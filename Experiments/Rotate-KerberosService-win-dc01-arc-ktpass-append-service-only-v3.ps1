<# 
.SYNOPSIS
    Rotate a Kerberos SERVICE keytab for FrostyLabs ad-lab from win-dc01,
    using an Arc-style ktpass append workflow on the domain controller.

.DESCRIPTION
    This script manages only the SERVICE account and service keytab.
    It does not manage any client principal or client-side keytab workflow.

    The service-side flow is:
      Bootstrap
        - Create the AD service account
        - Register the HTTP SPN
        - Export the first/current keytab
        - Deploy it to Apache on the Linux host

      Rotate
        - Read current KVNO from AD/manifest
        - Predict next KVNO as current + 1
        - Export a new current-only keytab for the new password / predicted KVNO
        - Create a transition keytab on win-dc01 by copying the old keytab and appending
          the new generation into that same file with ktpass /in ... /out ...
        - Deploy the transition keytab to Apache
        - Reset the AD password
        - Verify actual AD KVNO matches the prediction
        - Persist new manifest state

      Commit
        - Verify AD current KVNO still matches manifest current KVNO
        - Replace the active Apache keytab with the new current-only keytab
        - Remove tracked old/transition local artifacts
        - Rewrite the manifest so only the current generation remains tracked

.NOTES
    This follows the append pattern used by Microsoft's Azure Arc rotation script:
    ktpass is used to append the new generation into an existing keytab file using
    /in <file> /out <same file>.

    IMPORTANT CAVEAT:
    This still relies on the pre-reset "future keytab" assumption around ktpass.
    Validate this sequencing in your lab before treating it as production-safe.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Bootstrap','Rotate','Commit')]
    [string]$Action,

    [string]$DomainFqdn       = 'frostylabs.local',
    [string]$DomainController = 'win-dc01.frostylabs.local',
    [string]$OuDn             = 'CN=Users,DC=frostylabs,DC=local',

    [string]$ServiceAccountName = 'svc_http_linux',
    [string]$ServiceHost        = 'linux-srv01.frostylabs.local',

    [string]$LinuxHost          = '192.168.139.14',
    [int]   $LinuxPort          = 22,
    [string]$LinuxAdminUser     = 'vagrant',
    [string]$LinuxSshPrivateKeyPath = 'C:\Keys\vagrant-linux-srv01',

    [string]$RemoteKeytabPath   = '/etc/apache2/http_linux-srv01.keytab',
    [string]$RemoteMetaPath     = '/etc/apache2/http_linux-srv01.keytab.meta',
    [string]$RemoteApacheConf   = '/etc/apache2/conf-available/kerberos-demo.conf',
    [string]$RemoteApacheDocDir = '/var/www/frostylabs/kerberos',

    [string]$WorkDir = 'C:\Kerberos-Rotation-Service-Arc'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function New-StrongPassword {
    param([int]$Length = 32)
    if ($Length -lt 20) { throw "Password length must be at least 20." }

    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = 'abcdefghijkmnopqrstuvwxyz'
    $digit   = '23456789'
    $special = '!@#$%^&*()-_=+[]{}:,.?'
    $all     = ($upper + $lower + $digit + $special).ToCharArray()

    $chars = New-Object System.Collections.Generic.List[char]
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    function Get-RandomChar([char[]]$set, $rngObj) {
        $bytes = New-Object byte[] 4
        $rngObj.GetBytes($bytes)
        $idx = [BitConverter]::ToUInt32($bytes, 0) % $set.Length
        return $set[$idx]
    }

    $chars.Add((Get-RandomChar $upper.ToCharArray()   $rng))
    $chars.Add((Get-RandomChar $lower.ToCharArray()   $rng))
    $chars.Add((Get-RandomChar $digit.ToCharArray()   $rng))
    $chars.Add((Get-RandomChar $special.ToCharArray() $rng))

    for ($i = $chars.Count; $i -lt $Length; $i++) {
        $chars.Add((Get-RandomChar $all $rng))
    }

    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $bytes = New-Object byte[] 4
        $rng.GetBytes($bytes)
        $j = [BitConverter]::ToUInt32($bytes, 0) % ($i + 1)
        $tmp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }

    return -join $chars
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Save-Manifest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Data
    )
    Ensure-Directory -Path (Split-Path -Parent $Path)
    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Load-Manifest {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Manifest not found: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$Description = $FilePath,
        [switch]$CaptureOutput
    )

    Write-Host "==> $Description" -ForegroundColor Cyan

    if ($CaptureOutput) {
        $output = & $FilePath @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            $joined = ($output | Out-String)
            throw "$FilePath failed with exit code $LASTEXITCODE.`n$joined"
        }
        return ($output | Out-String)
    }

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Get-CommonSshArgs {
    return @(
        '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-i', $LinuxSshPrivateKeyPath,
        '-p', "$LinuxPort"
    )
}

function Invoke-SSH {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteCommand,
        [switch]$CaptureOutput
    )

    $args = @()
    $args += Get-CommonSshArgs
    $args += "$LinuxAdminUser@$LinuxHost"
    $args += $RemoteCommand

    return Invoke-External -FilePath 'ssh.exe' -Arguments $args -Description "ssh $LinuxAdminUser@$LinuxHost" -CaptureOutput:$CaptureOutput
}

function Copy-ToLinux {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$RemotePath
    )

    if (-not (Test-Path -LiteralPath $LocalPath)) {
        throw "Local file not found: $LocalPath"
    }

    $args = @()
    $args += Get-CommonSshArgs
    $args += $LocalPath
    $args += "$LinuxAdminUser@$LinuxHost`:$RemotePath"

    Invoke-External -FilePath 'scp.exe' -Arguments $args -Description "scp $(Split-Path $LocalPath -Leaf) -> $LinuxHost"
}

function Invoke-RemoteScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [string]$LocalBaseName = 'remote-helper.sh',
        [switch]$CaptureOutput
    )

    $rotationSafeId = [guid]::NewGuid().ToString()
    $remotePath = "/tmp/$($ServiceAccountName)-$rotationSafeId.sh"
    $localScript = Join-Path $script:AccountDir $LocalBaseName

    $ScriptText | Out-File -LiteralPath $localScript -Encoding ascii -Force
    Copy-ToLinux -LocalPath $localScript -RemotePath $remotePath

    try {
        return Invoke-SSH -RemoteCommand "bash $remotePath" -CaptureOutput:$CaptureOutput
    }
    finally {
        try {
            Invoke-SSH -RemoteCommand "rm -f '$remotePath'" | Out-Null
        }
        catch {
        }
    }
}

function Test-LinuxAdminAccess {
    Write-Host "Testing Linux admin SSH access..." -ForegroundColor Yellow

    $probe = @(
        'set -euo pipefail',
        'echo "HOST=$(hostname -f 2>/dev/null || hostname)"',
        'echo "USER=$(id -un)"',
        'sudo -n true',
        'command -v klist >/dev/null',
        'command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1 || true',
        'echo "SUDO=ok"'
    ) -join '; '

    $out = Invoke-SSH -RemoteCommand "bash -lc '$probe'" -CaptureOutput
    Write-Host $out.Trim()

    if ($out -notmatch 'SUDO=ok') {
        throw "Linux admin access test did not confirm passwordless sudo."
    }
}

function Get-ServiceAccount {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    return Get-ADUser -Identity $SamAccountName -Server $DomainController -Properties ServicePrincipalName, msDS-KeyVersionNumber -ErrorAction SilentlyContinue
}

function Get-CurrentKvno {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    $obj = Get-ADUser -Identity $SamAccountName -Server $DomainController -Properties msDS-KeyVersionNumber
    return [int]$obj.'msDS-KeyVersionNumber'
}

function Set-ServiceAccountAes256 {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    Set-ADUser -Identity $SamAccountName -Server $DomainController -KerberosEncryptionType AES256
}

function Add-ServiceSpn {
    param(
        [Parameter(Mandatory = $true)][string]$Spn,
        [Parameter(Mandatory = $true)][string]$SamAccountName
    )
    Invoke-External -FilePath 'setspn.exe' -Arguments @('-U', '-S', $Spn, $SamAccountName) -Description "Register SPN $Spn"
}

function New-KeytabFileName {
    param(
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$GenerationLabel,
        [Parameter(Mandatory = $true)][string]$RotationId
    )
    return Join-Path $script:AccountDir "$($ServiceAccountName).$GenerationLabel.kvno$Kvno.$RotationId.keytab"
}

function Show-KeytabEntries {
    param([Parameter(Mandatory = $true)][string]$KeytabPath)

    if (-not (Test-Path -LiteralPath $KeytabPath)) {
        throw "Keytab file not found: $KeytabPath"
    }

    Write-Host ""
    Write-Host "Keytab details" -ForegroundColor Yellow
    Write-Host "--------------"
    Write-Host "Path: $KeytabPath"
    $item = Get-Item -LiteralPath $KeytabPath
    Write-Host "Size: $($item.Length) bytes"
    Write-Host ""

    Invoke-External -FilePath 'ktpass.exe' -Arguments @('/in', $KeytabPath) -Description "Inspect keytab"
    Write-Host ""
}

function Export-Keytab {
    param(
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][string]$MapUser,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$OutFile
    )

    if (Test-Path -LiteralPath $OutFile) {
        Remove-Item -LiteralPath $OutFile -Force
    }

    $args = @(
        '/out', $OutFile,
        '/princ', $Principal,
        '/mapuser', $MapUser,
        '/pass', $Password,
        '/crypto', 'AES256-SHA1',
        '/ptype', 'KRB5_NT_PRINCIPAL',
        '/mapop', 'set',
        '/kvno', "$Kvno",
        '/target', $DomainController,
        '+setupn',
        '-setpass', $Password
    )

    Invoke-External -FilePath 'ktpass.exe' -Arguments $args -Description "Export keytab KVNO $Kvno"
}

function Append-KeytabEntryOnDomainController {
    param(
        [Parameter(Mandatory = $true)][string]$BaseKeytabPath,
        [Parameter(Mandatory = $true)][string]$TransitionKeytabPath,
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][string]$MapUser,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][int]$Kvno
    )

    if (-not (Test-Path -LiteralPath $BaseKeytabPath)) {
        throw "Base keytab not found: $BaseKeytabPath"
    }

    Copy-Item -LiteralPath $BaseKeytabPath -Destination $TransitionKeytabPath -Force

    $args = @(
        '/in', $TransitionKeytabPath,
        '/out', $TransitionKeytabPath,
        '/princ', $Principal,
        '/mapuser', $MapUser,
        '-setupn',
        '-setpass',
        '/pass', $Password,
        '/crypto', 'AES256-SHA1',
        '/ptype', 'KRB5_NT_PRINCIPAL',
        '/mapop', 'set',
        '/kvno', "$Kvno",
        '/target', $DomainController
    )

    Invoke-External -FilePath 'ktpass.exe' -Arguments $args -Description "Append keytab entry KVNO $Kvno into transition keytab"
}

function New-ApacheConfigContent {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteKeytab,
        [Parameter(Mandatory = $true)][string]$DocDir
    )

@"
Alias /kerberos $DocDir

<Location /kerberos>
    AuthType GSSAPI
    AuthName "Kerberos Test"
    GssapiCredStore keytab:$RemoteKeytab
    GssapiAllowedMech krb5
    Require valid-user
</Location>
"@
}

function Ensure-ApacheKerberosBase {
    $localApacheConf = Join-Path $script:AccountDir 'kerberos-demo.conf'
    $apacheConf = New-ApacheConfigContent -RemoteKeytab $RemoteKeytabPath -DocDir $RemoteApacheDocDir
    $apacheConf | Set-Content -LiteralPath $localApacheConf -Encoding ascii -Force
    Copy-ToLinux -LocalPath $localApacheConf -RemotePath '/tmp/kerberos-demo.conf'

    $remoteScript = @"
set -euo pipefail

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 krb5-user libapache2-mod-auth-gssapi

sudo install -d -o root -g root -m 755 '$RemoteApacheDocDir'

cat <<'HTML' | sudo tee '$RemoteApacheDocDir/index.html' >/dev/null
<!doctype html>
<html>
<head><title>Kerberos Demo</title></head>
<body>
  <h1>Kerberos demo page</h1>
  <p>This page is protected by Apache GSSAPI using a keytab.</p>
</body>
</html>
HTML

sudo install -o root -g root -m 644 /tmp/kerberos-demo.conf '$RemoteApacheConf'
sudo a2enmod auth_gssapi >/dev/null || true
sudo a2enconf $(basename '$RemoteApacheConf' .conf) >/dev/null || true
sudo systemctl enable apache2 >/dev/null
"@
    Invoke-RemoteScript -ScriptText $remoteScript -LocalBaseName 'ensure-apache-base.sh' | Out-Null
}

function Deploy-ServiceKeytabToApache {
    param(
        [Parameter(Mandatory = $true)][string]$LocalKeytabPath,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][int]$CurrentKvno,
        [Parameter(Mandatory = $true)][string]$CurrentRotationId,
        [string]$PreviousKvno = '',
        [string]$PreviousRotationId = ''
    )

    Ensure-ApacheKerberosBase
    Copy-ToLinux -LocalPath $LocalKeytabPath -RemotePath '/tmp/service.keytab.upload'

    $metaBody = @("MODE=$Mode")
    if ($PreviousKvno -ne '') { $metaBody += "PREVIOUS_KVNO=$PreviousKvno" }
    $metaBody += "CURRENT_KVNO=$CurrentKvno"
    if ($PreviousRotationId -ne '') { $metaBody += "PREVIOUS_ROTATION_ID=$PreviousRotationId" }
    $metaBody += "CURRENT_ROTATION_ID=$CurrentRotationId"
    $metaBody += "SERVICE_PRINCIPAL=$($script:ServicePrincipal)"
    $metaText = ($metaBody -join "`n")

    $remoteScript = @"
set -euo pipefail

sudo install -o root -g www-data -m 640 /tmp/service.keytab.upload '$RemoteKeytabPath'

cat <<'META' | sudo tee '$RemoteMetaPath' >/dev/null
$metaText
META

sudo systemctl restart apache2

echo '--- active service keytab ---'
sudo klist -k -e '$RemoteKeytabPath' || true
echo '--- service keytab metadata ---'
sudo cat '$RemoteMetaPath' || true
echo '--- kerberos endpoint ---'
echo 'http://$ServiceHost/kerberos/'
"@
    $out = Invoke-RemoteScript -ScriptText $remoteScript -LocalBaseName 'deploy-service-keytab.sh' -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ""
}

function Remove-TrackedLocalArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
}

Assert-Command -Name 'Get-ADUser'
Assert-Command -Name 'ktpass.exe'
Assert-Command -Name 'setspn.exe'
Assert-Command -Name 'ssh.exe'
Assert-Command -Name 'scp.exe'

if (-not (Test-Path -LiteralPath $LinuxSshPrivateKeyPath)) {
    throw "Linux SSH private key not found: $LinuxSshPrivateKeyPath"
}

$domain = Get-ADDomain -Identity $DomainFqdn -Server $DomainController
$Realm = $domain.DNSRoot.ToUpperInvariant()
$Netbios = $domain.NetBIOSName

$Spn             = "HTTP/$ServiceHost"
$ServicePrincipal = "$Spn@$Realm"
$MapUser         = "$Netbios\$ServiceAccountName"

$AccountDir   = Join-Path $WorkDir $ServiceAccountName
$ManifestPath = Join-Path $AccountDir 'rotation-manifest.json'

Ensure-Directory -Path $AccountDir

Write-Host "Run host:             $env:COMPUTERNAME"
Write-Host "Domain:               $DomainFqdn"
Write-Host "Controller:           $DomainController"
Write-Host "Service account:      $ServiceAccountName"
Write-Host "Service principal:    $ServicePrincipal"
Write-Host "Linux service target: $LinuxAdminUser@$LinuxHost`:$LinuxPort"
Write-Host "Remote keytab path:   $RemoteKeytabPath"
Write-Host "Action:               $Action"
Write-Host ""

Test-LinuxAdminAccess

switch ($Action) {
    'Bootstrap' {
        $existing = Get-ServiceAccount -SamAccountName $ServiceAccountName
        if ($existing) {
            throw "Service account '$ServiceAccountName' already exists. Use -Action Rotate or remove the account first."
        }

        $rotationId      = [guid]::NewGuid().ToString()
        $initialPassword = New-StrongPassword
        $securePassword  = ConvertTo-SecureString $initialPassword -AsPlainText -Force

        if ($PSCmdlet.ShouldProcess($ServiceAccountName, 'Create AD service account')) {
            New-ADUser `
                -Name $ServiceAccountName `
                -SamAccountName $ServiceAccountName `
                -UserPrincipalName "$ServiceAccountName@$DomainFqdn" `
                -Path $OuDn `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -CannotChangePassword $true `
                -Description "Kerberos HTTP service account for $ServiceHost" `
                -Server $DomainController
        }

        Set-ServiceAccountAes256 -SamAccountName $ServiceAccountName
        Add-ServiceSpn -Spn $Spn -SamAccountName $ServiceAccountName

        $currentKvno = Get-CurrentKvno -SamAccountName $ServiceAccountName
        $keytabPath  = New-KeytabFileName -Kvno $currentKvno -GenerationLabel 'gen0' -RotationId $rotationId

        Export-Keytab `
            -Principal $ServicePrincipal `
            -MapUser $MapUser `
            -Password $initialPassword `
            -Kvno $currentKvno `
            -OutFile $keytabPath

        Show-KeytabEntries -KeytabPath $keytabPath

        Deploy-ServiceKeytabToApache `
            -LocalKeytabPath $keytabPath `
            -Mode 'current-only' `
            -CurrentKvno $currentKvno `
            -CurrentRotationId $rotationId

        $manifest = @{
            domain            = $DomainFqdn
            realm             = $Realm
            domainController  = $DomainController
            serviceAccount    = $ServiceAccountName
            spn               = $Spn
            servicePrincipal  = $ServicePrincipal
            linuxHost         = $LinuxHost
            linuxPort         = $LinuxPort
            linuxAdminUser    = $LinuxAdminUser
            linuxSshKey       = $LinuxSshPrivateKeyPath
            remoteKeytabPath  = $RemoteKeytabPath
            remoteMetaPath    = $RemoteMetaPath
            serviceUrl        = "http://$ServiceHost/kerberos/"
            createdAt         = (Get-Date).ToString('o')
            current           = @{
                kvno        = $currentKvno
                localKeytab = $keytabPath
                label       = 'gen0'
                rotationId  = $rotationId
            }
            previous          = $null
            transition        = $null
        }

        Save-Manifest -Path $ManifestPath -Data $manifest

        Write-Host ""
        Write-Host "Bootstrap complete." -ForegroundColor Green
        Write-Host "Current AD KVNO: $currentKvno"
        Write-Host "Current service keytab: $keytabPath"
        Write-Host ""
    }

    'Rotate' {
        $manifest = Load-Manifest -Path $ManifestPath

        $svc = Get-ServiceAccount -SamAccountName $ServiceAccountName
        if (-not $svc) {
            throw "Service account '$ServiceAccountName' not found."
        }

        $oldKvno       = [int]$manifest.current.kvno
        $oldKeytab     = [string]$manifest.current.localKeytab
        $oldRotationId = [string]$manifest.current.rotationId

        if (-not (Test-Path -LiteralPath $oldKeytab)) {
            throw "Current local service keytab not found: $oldKeytab"
        }

        $predictedNewKvno = $oldKvno + 1
        $newRotationId    = [guid]::NewGuid().ToString()
        $newPassword      = New-StrongPassword
        $futureKeytab     = New-KeytabFileName -Kvno $predictedNewKvno -GenerationLabel 'gen1' -RotationId $newRotationId
        $transitionKeytab = Join-Path $script:AccountDir "$($ServiceAccountName).transition.kvno$oldKvno-$predictedNewKvno.$newRotationId.keytab"

        Export-Keytab `
            -Principal $ServicePrincipal `
            -MapUser $MapUser `
            -Password $newPassword `
            -Kvno $predictedNewKvno `
            -OutFile $futureKeytab

        Show-KeytabEntries -KeytabPath $futureKeytab

        Append-KeytabEntryOnDomainController `
            -BaseKeytabPath $oldKeytab `
            -TransitionKeytabPath $transitionKeytab `
            -Principal $ServicePrincipal `
            -MapUser $MapUser `
            -Password $newPassword `
            -Kvno $predictedNewKvno

        Show-KeytabEntries -KeytabPath $transitionKeytab

        Deploy-ServiceKeytabToApache `
            -LocalKeytabPath $transitionKeytab `
            -Mode 'transition' `
            -CurrentKvno $predictedNewKvno `
            -PreviousKvno "$oldKvno" `
            -CurrentRotationId $newRotationId `
            -PreviousRotationId $oldRotationId

        if ($PSCmdlet.ShouldProcess($ServiceAccountName, 'Rotate AD service account password')) {
            Set-ADAccountPassword `
                -Identity $ServiceAccountName `
                -Reset `
                -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) `
                -Server $DomainController
        }

        Set-ServiceAccountAes256 -SamAccountName $ServiceAccountName

        $actualNewKvno = Get-CurrentKvno -SamAccountName $ServiceAccountName
        if ($actualNewKvno -ne $predictedNewKvno) {
            throw "Predicted next KVNO ($predictedNewKvno) does not match actual AD KVNO after password reset ($actualNewKvno)."
        }

        $updatedManifest = @{
            domain            = $manifest.domain
            realm             = $manifest.realm
            domainController  = $manifest.domainController
            serviceAccount    = $manifest.serviceAccount
            spn               = $manifest.spn
            servicePrincipal  = $manifest.servicePrincipal
            linuxHost         = $manifest.linuxHost
            linuxPort         = $manifest.linuxPort
            linuxAdminUser    = $manifest.linuxAdminUser
            linuxSshKey       = $manifest.linuxSshKey
            remoteKeytabPath  = $manifest.remoteKeytabPath
            remoteMetaPath    = $manifest.remoteMetaPath
            serviceUrl        = $manifest.serviceUrl
            createdAt         = $manifest.createdAt
            rotatedAt         = (Get-Date).ToString('o')
            current           = @{
                kvno        = $actualNewKvno
                localKeytab = $futureKeytab
                label       = 'gen1'
                rotationId  = $newRotationId
            }
            previous          = @{
                kvno        = $oldKvno
                localKeytab = $oldKeytab
                label       = [string]$manifest.current.label
                rotationId  = $oldRotationId
            }
            transition        = @{
                localKeytab = $transitionKeytab
                mode        = 'transition'
            }
        }

        Save-Manifest -Path $ManifestPath -Data $updatedManifest

        Write-Host ""
        Write-Host "Rotation complete." -ForegroundColor Green
        Write-Host "Previous KVNO:              $oldKvno"
        Write-Host "Predicted/actual new KVNO:  $actualNewKvno"
        Write-Host "Future/current keytab:      $futureKeytab"
        Write-Host "Transition keytab:          $transitionKeytab"
        Write-Host ""
    }

    'Commit' {
        $manifest = Load-Manifest -Path $ManifestPath

        if (-not $manifest.previous) {
            throw "Nothing to commit. Rotate first."
        }

        $currentKvno = Get-CurrentKvno -SamAccountName $ServiceAccountName
        if ($currentKvno -ne [int]$manifest.current.kvno) {
            throw "AD current KVNO ($currentKvno) does not match manifest current KVNO ($($manifest.current.kvno))."
        }

        Deploy-ServiceKeytabToApache `
            -LocalKeytabPath ([string]$manifest.current.localKeytab) `
            -Mode 'current-only' `
            -CurrentKvno ([int]$manifest.current.kvno) `
            -CurrentRotationId ([string]$manifest.current.rotationId)

        Remove-TrackedLocalArtifact -Path ([string]$manifest.previous.localKeytab)

        if ($manifest.transition -and $manifest.transition.localKeytab) {
            Remove-TrackedLocalArtifact -Path ([string]$manifest.transition.localKeytab)
        }

        $finalManifest = @{
            domain            = $manifest.domain
            realm             = $manifest.realm
            domainController  = $manifest.domainController
            serviceAccount    = $manifest.serviceAccount
            spn               = $manifest.spn
            servicePrincipal  = $manifest.servicePrincipal
            linuxHost         = $manifest.linuxHost
            linuxPort         = $manifest.linuxPort
            linuxAdminUser    = $manifest.linuxAdminUser
            linuxSshKey       = $manifest.linuxSshKey
            remoteKeytabPath  = $manifest.remoteKeytabPath
            remoteMetaPath    = $manifest.remoteMetaPath
            serviceUrl        = $manifest.serviceUrl
            createdAt         = $manifest.createdAt
            rotatedAt         = $manifest.rotatedAt
            committedAt       = (Get-Date).ToString('o')
            current           = @{
                kvno        = [int]$manifest.current.kvno
                localKeytab = [string]$manifest.current.localKeytab
                label       = [string]$manifest.current.label
                rotationId  = [string]$manifest.current.rotationId
            }
            previous          = $null
            transition        = $null
        }

        Save-Manifest -Path $ManifestPath -Data $finalManifest

        Write-Host ""
        Write-Host "Commit complete." -ForegroundColor Green
        Write-Host "Service active keytab is now current-only."
        Write-Host "Old generation removed from active service keytab."
        Write-Host "Current KVNO:   $($finalManifest.current.kvno)"
        Write-Host "Current keytab: $($finalManifest.current.localKeytab)"
        Write-Host ""
    }
}
