
<# 
.SYNOPSIS
    Rotate an AD-backed Kerberos SERVICE keytab for Apache on linux-srv01 from win-dc01,
    using a Windows-side append workflow modeled after Microsoft's Azure Arc rotate-sql-keytab.ps1.

.DESCRIPTION
    This script focuses ONLY on the service-account / service-keytab workflow.

    It follows an append-style pattern:
      Bootstrap
        - Create the AD service account
        - Register the HTTP SPN
        - Export the current-only keytab
        - Deploy the current-only keytab to Apache

      Rotate
        - Build a TRANSITION keytab on WIN-DC01 using ktpass /in /out append style
          (current KVNO/current password entry, then next KVNO/new password entry)
        - Verify AD current KVNO advanced to the appended next KVNO
        - Export a NEW current-only keytab for the now-current password/KVNO
        - Deploy the transition keytab to Apache

      Commit
        - Verify AD current KVNO still matches the manifest current KVNO
        - Replace the active transition keytab with the current-only keytab
        - Delete the previous and transition local keytab artifacts
        - Rewrite the manifest so only the current generation remains tracked

    IMPORTANT
      - This script intentionally mirrors the Azure Arc append pattern on Windows DC.
      - It relies on ktpass /in /out append semantics plus password-setting behavior,
        just like the Azure Arc rotate-sql-keytab.ps1 script.
      - Because of that, Rotate REQUIRES both the CURRENT and NEW passwords to be provided.

.NOTES
    Before running this script on win-dc01:
      1. Copy the Vagrant/private SSH key for linux-srv01 onto win-dc01
      2. Pass its path with -LinuxSshPrivateKeyPath, or place it at the default path
      3. Ensure ssh.exe and scp.exe are available on win-dc01
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Bootstrap','Rotate','Commit')]
    [string]$Action,

    [SecureString]$InitialPassword,
    [SecureString]$CurrentPassword,
    [SecureString]$NewPassword,

    [string]$DomainFqdn       = 'frostylabs.local',
    [string]$DomainController = 'win-dc01.frostylabs.local',
    [string]$OuDn             = 'CN=Users,DC=frostylabs,DC=local',

    [string]$ServiceAccountName = 'svc_http_linux',
    [string]$ServiceHost        = 'linux-srv01.frostylabs.local',

    [string]$LinuxHost              = '192.168.139.14',
    [int]   $LinuxPort              = 22,
    [string]$LinuxAdminUser         = 'vagrant',
    [string]$LinuxSshPrivateKeyPath = 'C:\Keys\vagrant-linux-srv01',

    [string]$RemoteKeytabPath   = '/etc/apache2/http_linux-srv01.keytab',
    [string]$RemoteMetaPath     = '/etc/apache2/http_linux-srv01.keytab.meta',
    [string]$RemoteApacheConf   = '/etc/apache2/conf-available/kerberos-demo.conf',
    [string]$RemoteApacheDocDir = '/var/www/frostylabs/kerberos',

    [string]$WorkDir = 'C:\Kerberos-Rotation-Service',

    [switch]$ForceImmediateCommit
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

function ConvertTo-PlainText {
    param([Parameter(Mandatory = $true)][Security.SecureString]$SecureString)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
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
        [string]$LocalBaseName = 'remote-helper.sh'
    )

    $remoteId    = [guid]::NewGuid().ToString()
    $remotePath  = "/tmp/$($ServiceAccountName)-$remoteId.sh"
    $localScript = Join-Path $script:AccountDir $LocalBaseName

    $ScriptText | Out-File -LiteralPath $localScript -Encoding ascii -Force
    Copy-ToLinux -LocalPath $localScript -RemotePath $remotePath

    try {
        Invoke-SSH -RemoteCommand "bash $remotePath"
    }
    finally {
        try {
            Invoke-SSH -RemoteCommand "rm -f $remotePath" | Out-Null
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
    Invoke-External -FilePath 'setspn.exe' -Arguments @('-S', $Spn, $SamAccountName) -Description "Register SPN $Spn"
}

function New-KeytabFileName {
    param(
        [Parameter(Mandatory = $true)][string]$BaseName
    )
    return Join-Path $script:AccountDir $BaseName
}

function Show-KeytabEntries {
    param(
        [Parameter(Mandatory = $true)][string]$KeytabPath
    )

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

    Write-Host "Key information from keytab:" -ForegroundColor Yellow
    Invoke-External -FilePath 'ktpass.exe' -Arguments @('/in', $KeytabPath) -Description "Inspect keytab"
    Write-Host ""
}

function Invoke-KtpassWriteOrAppend {
    param(
        [Parameter(Mandatory = $true)][string]$PrincipalToWrite,
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$PasswordPlain,
        [Parameter(Mandatory = $true)][string]$KeytabPath,
        [Parameter(Mandatory = $true)][bool]$Append
    )

    $args = @(
        '/princ',  $PrincipalToWrite,
        '/ptype',  'KRB5_NT_PRINCIPAL',
        '/kvno',   "$Kvno",
        '/crypto', 'AES256-SHA1',
        '/mapuser',$MapUser
    )

    if ($Append) {
        $args += @('/in', $KeytabPath, '/out', $KeytabPath)
    }
    else {
        if (Test-Path -LiteralPath $KeytabPath) {
            Remove-Item -LiteralPath $KeytabPath -Force
        }
        $args += @('/out', $KeytabPath)
    }

    $args += @('-setpass', '/pass', $PasswordPlain)

    Invoke-External -FilePath 'ktpass.exe' -Arguments $args -Description ("ktpass " + ($(if ($Append) { "append" } else { "create" })) + " KVNO $Kvno")
}

function Build-AppendedTransitionKeytab {
    param(
        [Parameter(Mandatory = $true)][string]$TransitionKeytabPath,
        [Parameter(Mandatory = $true)][int]$CurrentKvno,
        [Parameter(Mandatory = $true)][int]$NextKvno,
        [Parameter(Mandatory = $true)][string]$CurrentPasswordPlain,
        [Parameter(Mandatory = $true)][string]$NewPasswordPlain
    )

    Invoke-KtpassWriteOrAppend `
        -PrincipalToWrite $Principal `
        -Kvno $CurrentKvno `
        -PasswordPlain $CurrentPasswordPlain `
        -KeytabPath $TransitionKeytabPath `
        -Append:$false

    Invoke-KtpassWriteOrAppend `
        -PrincipalToWrite $Principal `
        -Kvno $NextKvno `
        -PasswordPlain $NewPasswordPlain `
        -KeytabPath $TransitionKeytabPath `
        -Append:$true
}

function Export-CurrentOnlyKeytab {
    param(
        [Parameter(Mandatory = $true)][string]$KeytabPath,
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$PasswordPlain
    )

    if (Test-Path -LiteralPath $KeytabPath) {
        Remove-Item -LiteralPath $KeytabPath -Force
    }

    $args = @(
        '/out',    $KeytabPath,
        '/princ',  $Principal,
        '/mapuser',$MapUser,
        '/pass',   $PasswordPlain,
        '/crypto', 'AES256-SHA1',
        '/ptype',  'KRB5_NT_PRINCIPAL',
        '/mapop',  'set',
        '/kvno',   "$Kvno",
        '/target', $DomainController,
        '/answer', '-'
    )

    Invoke-External -FilePath 'ktpass.exe' -Arguments $args -Description "Export current-only keytab KVNO $Kvno"
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

sudo systemctl enable apache2 >/dev/null || true
"@
    Invoke-RemoteScript -ScriptText $remoteScript -LocalBaseName 'ensure-apache-base.sh'
}

function Deploy-KeytabToApache {
    param(
        [Parameter(Mandatory = $true)][string]$LocalKeytabPath,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][int]$CurrentKvno,
        [string]$PreviousKvno = '',
        [Parameter(Mandatory = $true)][string]$CurrentRotationId,
        [string]$PreviousRotationId = ''
    )

    Ensure-ApacheKerberosBase
    Copy-ToLinux -LocalPath $LocalKeytabPath -RemotePath '/tmp/http_linux-srv01.active.keytab'

    $metaBody = @("MODE=$Mode")
    if ($PreviousKvno -ne '') { $metaBody += "PREVIOUS_KVNO=$PreviousKvno" }
    $metaBody += "CURRENT_KVNO=$CurrentKvno"
    if ($PreviousRotationId -ne '') { $metaBody += "PREVIOUS_ROTATION_ID=$PreviousRotationId" }
    $metaBody += "CURRENT_ROTATION_ID=$CurrentRotationId"
    $metaBody += "PRINCIPAL=$($script:Principal)"
    $metaText = ($metaBody -join "`n")

    $remoteScript = @"
set -euo pipefail

sudo install -o root -g www-data -m 640 /tmp/http_linux-srv01.active.keytab '$RemoteKeytabPath'

cat <<'META' | sudo tee '$RemoteMetaPath' >/dev/null
$metaText
META

sudo systemctl restart apache2

echo '--- active keytab ---'
sudo klist -k -e '$RemoteKeytabPath' || true
echo '--- metadata ---'
sudo cat '$RemoteMetaPath' || true
echo '--- kerberos endpoint ---'
echo 'http://$ServiceHost/kerberos/'
"@
    Invoke-RemoteScript -ScriptText $remoteScript -LocalBaseName 'deploy-keytab.sh'
}

function Remove-TrackedLocalArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
}

function Show-ImmediateCommitNotes {
    Write-Host ''
    Write-Host 'Immediate cutover notes:' -ForegroundColor Yellow
    Write-Host '  Windows clients:  klist purge'
    Write-Host '  Linux clients:    kdestroy -A'
    Write-Host '  Browser / curl retest after acquiring a fresh service ticket.'
    Write-Host ''
}

Assert-Command -Name 'ktpass.exe'
Assert-Command -Name 'setspn.exe'
Assert-Command -Name 'ssh.exe'
Assert-Command -Name 'scp.exe'

if (-not (Test-Path -LiteralPath $LinuxSshPrivateKeyPath)) {
    throw "Linux SSH private key not found: $LinuxSshPrivateKeyPath"
}

switch ($Action) {
    'Bootstrap' {
        if (-not $InitialPassword) {
            throw "Bootstrap requires -InitialPassword."
        }
    }
    'Rotate' {
        if ((-not $CurrentPassword) -or (-not $NewPassword)) {
            throw "Rotate requires both -CurrentPassword and -NewPassword."
        }
    }
}

$domain = Get-ADDomain -Identity $DomainFqdn -Server $DomainController
$Realm   = $domain.DNSRoot.ToUpperInvariant()
$Netbios = $domain.NetBIOSName

$Spn       = "HTTP/$ServiceHost"
$Principal = "$Spn@$Realm"
$MapUser   = "$Netbios\$ServiceAccountName"

$AccountDir   = Join-Path $WorkDir $ServiceAccountName
$ManifestPath = Join-Path $AccountDir 'rotation-manifest.json'

Ensure-Directory -Path $AccountDir

Write-Host "Run host:            $env:COMPUTERNAME"
Write-Host "Domain:              $DomainFqdn"
Write-Host "Controller:          $DomainController"
Write-Host "SPN:                 $Spn"
Write-Host "Principal:           $Principal"
Write-Host "Linux admin target:  $LinuxAdminUser@$LinuxHost`:$LinuxPort"
Write-Host "Linux SSH key:       $LinuxSshPrivateKeyPath"
Write-Host "Action:              $Action"
Write-Host ""

Test-LinuxAdminAccess

switch ($Action) {
    'Bootstrap' {
        $existing = Get-ServiceAccount -SamAccountName $ServiceAccountName
        if ($existing) {
            throw "Service account '$ServiceAccountName' already exists. Use -Action Rotate or remove the account first."
        }

        $rotationId = [guid]::NewGuid().ToString()
        $initialPasswordPlain = ConvertTo-PlainText -SecureString $InitialPassword
        $securePassword = ConvertTo-SecureString $initialPasswordPlain -AsPlainText -Force

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
        $keytabPath  = New-KeytabFileName -BaseName "$($ServiceAccountName).gen0.kvno$currentKvno.$rotationId.keytab"

        Export-CurrentOnlyKeytab `
            -KeytabPath $keytabPath `
            -Kvno $currentKvno `
            -PasswordPlain $initialPasswordPlain

        Show-KeytabEntries -KeytabPath $keytabPath

        Deploy-KeytabToApache `
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
            principal         = $Principal
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

        Write-Host ''
        Write-Host 'Bootstrap complete.' -ForegroundColor Green
        Write-Host "Current AD KVNO: $currentKvno"
        Write-Host "Current keytab:  $keytabPath"
        Write-Host "Service URL:     http://$ServiceHost/kerberos/"
        Write-Host ''
    }

    'Rotate' {
        $manifest = Load-Manifest -Path $ManifestPath

        $svc = Get-ServiceAccount -SamAccountName $ServiceAccountName
        if (-not $svc) {
            throw "Service account '$ServiceAccountName' not found."
        }

        $oldKvno       = Get-CurrentKvno -SamAccountName $ServiceAccountName
        $oldKeytab     = [string]$manifest.current.localKeytab
        $oldRotationId = [string]$manifest.current.rotationId

        if ($oldKvno -ne [int]$manifest.current.kvno) {
            throw "AD current KVNO ($oldKvno) does not match manifest current KVNO ($($manifest.current.kvno)) before append-rotate."
        }

        $currentPasswordPlain = ConvertTo-PlainText -SecureString $CurrentPassword
        $newPasswordPlain     = ConvertTo-PlainText -SecureString $NewPassword

        $newRotationId     = [guid]::NewGuid().ToString()
        $predictedNewKvno  = $oldKvno + 1
        $transitionKeytab  = New-KeytabFileName -BaseName "$($ServiceAccountName).transition.kvno$oldKvno-$predictedNewKvno.$newRotationId.keytab"

        Build-AppendedTransitionKeytab `
            -TransitionKeytabPath $transitionKeytab `
            -CurrentKvno $oldKvno `
            -NextKvno $predictedNewKvno `
            -CurrentPasswordPlain $currentPasswordPlain `
            -NewPasswordPlain $newPasswordPlain

        Show-KeytabEntries -KeytabPath $transitionKeytab

        $actualNewKvno = Get-CurrentKvno -SamAccountName $ServiceAccountName
        if ($actualNewKvno -ne $predictedNewKvno) {
            throw "AD current KVNO after append-style build ($actualNewKvno) does not match predicted next KVNO ($predictedNewKvno)."
        }

        Set-ServiceAccountAes256 -SamAccountName $ServiceAccountName

        $newKeytab = New-KeytabFileName -BaseName "$($ServiceAccountName).gen1.kvno$actualNewKvno.$newRotationId.keytab"

        Export-CurrentOnlyKeytab `
            -KeytabPath $newKeytab `
            -Kvno $actualNewKvno `
            -PasswordPlain $newPasswordPlain

        Show-KeytabEntries -KeytabPath $newKeytab

        Deploy-KeytabToApache `
            -LocalKeytabPath $transitionKeytab `
            -Mode 'transition' `
            -CurrentKvno $actualNewKvno `
            -PreviousKvno "$oldKvno" `
            -CurrentRotationId $newRotationId `
            -PreviousRotationId $oldRotationId

        $updatedManifest = @{
            domain            = $manifest.domain
            realm             = $manifest.realm
            domainController  = $manifest.domainController
            serviceAccount    = $manifest.serviceAccount
            spn               = $manifest.spn
            principal         = $manifest.principal
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
                localKeytab = $newKeytab
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

        Write-Host ''
        Write-Host 'Rotate complete.' -ForegroundColor Green
        Write-Host "Previous KVNO:              $oldKvno"
        Write-Host "New AD current KVNO:        $actualNewKvno"
        Write-Host "Current-only keytab:        $newKeytab"
        Write-Host "Transition keytab:          $transitionKeytab"
        Write-Host "Apache active keytab mode:  transition"
        Write-Host ''
    }

    'Commit' {
        $manifest = Load-Manifest -Path $ManifestPath

        if (-not $manifest.previous) {
            throw 'Nothing to commit. Rotate first.'
        }

        $currentKvno = Get-CurrentKvno -SamAccountName $ServiceAccountName
        if ($currentKvno -ne [int]$manifest.current.kvno) {
            throw "AD current KVNO ($currentKvno) does not match manifest current KVNO ($($manifest.current.kvno))."
        }

        Deploy-KeytabToApache `
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
            principal         = $manifest.principal
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

        Write-Host ''
        Write-Host 'Commit complete.' -ForegroundColor Green
        Write-Host "Active Apache keytab is now current-only."
        Write-Host "Old generation removed from active service keytab."
        Write-Host "Current KVNO:   $($finalManifest.current.kvno)"
        Write-Host "Current keytab: $($finalManifest.current.localKeytab)"
        Write-Host "Service URL:    $($finalManifest.serviceUrl)"

        if ($ForceImmediateCommit) {
            Show-ImmediateCommitNotes
        }
    }
}
