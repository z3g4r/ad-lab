
<# 
.SYNOPSIS
    Rotate a Kerberos HTTP service account for FrostyLabs ad-lab, intended to run from win-dc01.

.DESCRIPTION
    This version is tailored for the FrostyLabs ad-lab layout:
      - Run it on win-dc01
      - Reach linux-srv01 directly on the private lab network (192.168.139.14:22)
      - Use the lab's vagrant/vagrant Linux admin credentials over SSH
      - Use PuTTY tools (plink.exe / pscp.exe) for deterministic password-based SSH from Windows

    Actions:
      Bootstrap - Create account, SPN, first keytab, deploy to Apache on linux-srv01
      Rotate    - Reset password, export new keytab, deploy it, keep a uniquely named backup
      Commit    - Delete previous keytab artifacts tracked in the manifest

    LAB ONLY:
      This script defaults to the lab's vagrant/vagrant credentials for Linux admin access.
      Do not use that pattern in production.

.EXAMPLE
    .\Rotate-KerberosService-win-dc01.ps1 -Action Bootstrap

.EXAMPLE
    .\Rotate-KerberosService-win-dc01.ps1 -Action Rotate

.EXAMPLE
    .\Rotate-KerberosService-win-dc01.ps1 -Action Commit
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
    [string]$LinuxAdminPassword = 'vagrant',

    [string]$RemoteKeytabPath   = '/etc/apache2/http_linux-srv01.keytab',
    [string]$RemoteMetaPath     = '/etc/apache2/http_linux-srv01.keytab.meta',
    [string]$RemoteApacheConf   = '/etc/apache2/conf-available/kerberos-demo.conf',
    [string]$RemoteApacheDocDir = '/var/www/frostylabs/kerberos',

    [string]$WorkDir = 'C:\Kerberos-Rotation',

    [switch]$ForceImmediateCommit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

# -----------------------------
# Helpers
# -----------------------------
function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Get-PuTTYBinary {
    param([Parameter(Mandatory = $true)][string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        "C:\Program Files\PuTTY\$Name",
        "C:\Program Files (x86)\PuTTY\$Name",
        "C:\Tools\PuTTY\$Name"
    )

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw "Required PuTTY binary not found: $Name"
}

function New-StrongPassword {
    param([int]$Length = 32)

    if ($Length -lt 20) {
        throw "Password length must be at least 20."
    }

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
        [string]$Description = $FilePath
    )

    Write-Host "==> $Description" -ForegroundColor Cyan
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Invoke-PLink {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteCommand,
        [switch]$CaptureOutput
    )

    $args = @(
        '-batch',
        '-ssh',
        '-P', "$LinuxPort",
        '-pw', $LinuxAdminPassword,
        "$LinuxAdminUser@$LinuxHost",
        $RemoteCommand
    )

    if ($CaptureOutput) {
        $output = & $script:PlinkPath @args 2>&1
        if ($LASTEXITCODE -ne 0) {
            $joined = ($output | Out-String)
            throw "plink failed with exit code $LASTEXITCODE.`n$joined"
        }
        return ($output | Out-String)
    }

    Invoke-External -FilePath $script:PlinkPath -Arguments $args -Description "plink $LinuxAdminUser@$LinuxHost"
}

function Copy-ToLinux {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$RemotePath
    )

    if (-not (Test-Path -LiteralPath $LocalPath)) {
        throw "Local file not found: $LocalPath"
    }

    $args = @(
        '-batch',
        '-P', "$LinuxPort",
        '-pw', $LinuxAdminPassword,
        $LocalPath,
        "$LinuxAdminUser@$LinuxHost`:$RemotePath"
    )

    Invoke-External -FilePath $script:PscpPath -Arguments $args -Description "pscp $(Split-Path $LocalPath -Leaf) -> $LinuxHost"
}

function Test-LinuxAdminAccess {
    Write-Host "Testing Linux admin SSH access..." -ForegroundColor Yellow

    $probe = @(
        'set -euo pipefail',
        'echo "HOST=$(hostname -f 2>/dev/null || hostname)"',
        'echo "USER=$(id -un)"',
        'sudo -n true',
        'echo "SUDO=ok"'
    ) -join '; '

    $out = Invoke-PLink -RemoteCommand "bash -lc '$probe'" -CaptureOutput
    Write-Host $out.Trim()

    if ($out -notmatch 'SUDO=ok') {
        throw "Linux admin access test did not confirm passwordless sudo."
    }
}

function Invoke-RemoteScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [string]$LocalBaseName = 'remote-helper.sh'
    )

    $rotationSafeId = [guid]::NewGuid().ToString()
    $remotePath = "/tmp/$($ServiceAccountName)-$rotationSafeId.sh"
    $localScript = Join-Path $script:AccountDir $LocalBaseName

    $ScriptText | Out-File -LiteralPath $localScript -Encoding ascii -Force
    Copy-ToLinux -LocalPath $localScript -RemotePath $remotePath

    try {
        Invoke-PLink -RemoteCommand "bash $remotePath"
    }
    finally {
        try {
            Invoke-PLink -RemoteCommand "rm -f $remotePath" | Out-Null
        }
        catch {
        }
    }
}

function Get-CurrentKvno {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    $obj = Get-ADUser -Identity $SamAccountName -Server $DomainController -Properties msDS-KeyVersionNumber
    return [int]$obj.'msDS-KeyVersionNumber'
}

function Get-ServiceAccount {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    return Get-ADUser -Identity $SamAccountName -Server $DomainController -Properties ServicePrincipalName, msDS-KeyVersionNumber -ErrorAction SilentlyContinue
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
        '/target', $DomainController
    )

    Invoke-External -FilePath 'ktpass.exe' -Arguments $args -Description "Export keytab KVNO $Kvno"
}

function New-ApacheConfigContent {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteKeytab,
        [Parameter(Mandatory = $true)][string]$DocDir
    )

@"
Alias /kerberos $DocDir

<Directory $DocDir>
    Options Indexes FollowSymLinks
    AllowOverride None

    AuthType GSSAPI
    AuthName "Kerberos SSO"
    GssapiCredStore keytab:$RemoteKeytab
    GssapiAllowedMech krb5
    GssapiUseSessions On
    Session On
    SessionCookieName gssapi_session path=/kerberos;httponly;

    Require valid-user
</Directory>
"@
}

function Deploy-KeytabToApache {
    param(
        [Parameter(Mandatory = $true)][string]$LocalKeytabPath,
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$RotationId,
        [string]$RemoteBackupPath = ''
    )

    $localApacheConf = Join-Path $script:AccountDir 'kerberos-demo.conf'
    $apacheConf = New-ApacheConfigContent -RemoteKeytab $RemoteKeytabPath -DocDir $RemoteApacheDocDir
    $apacheConf | Set-Content -LiteralPath $localApacheConf -Encoding ascii -Force

    Copy-ToLinux -LocalPath $LocalKeytabPath -RemotePath '/tmp/http_linux-srv01.keytab'
    Copy-ToLinux -LocalPath $localApacheConf -RemotePath '/tmp/kerberos-demo.conf'

    $backupClause = 'true'
    if (-not [string]::IsNullOrWhiteSpace($RemoteBackupPath)) {
        $backupClause = @"
if [ -f '$RemoteKeytabPath' ]; then
  sudo cp '$RemoteKeytabPath' '$RemoteBackupPath'
fi
"@
    }

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
  <p>Current deployed keytab KVNO: $Kvno</p>
  <p>Principal: $($script:Principal)</p>
  <p>Rotation ID: $RotationId</p>
</body>
</html>
HTML

$backupClause

sudo install -o root -g www-data -m 640 /tmp/http_linux-srv01.keytab '$RemoteKeytabPath'
sudo install -o root -g root -m 644 /tmp/kerberos-demo.conf '$RemoteApacheConf'

cat <<'META' | sudo tee '$RemoteMetaPath' >/dev/null
KVNO=$Kvno
ROTATION_ID=$RotationId
PRINCIPAL=$($script:Principal)
META

sudo a2enmod auth_gssapi session session_cookie headers >/dev/null || true
sudo a2enconf $(basename '$RemoteApacheConf' .conf) >/dev/null || true

sudo systemctl enable apache2 >/dev/null
sudo systemctl restart apache2

echo '--- active keytab ---'
sudo klist -k -e '$RemoteKeytabPath' || true
echo '--- metadata ---'
sudo cat '$RemoteMetaPath' || true
echo '--- kerberos endpoint ---'
echo 'http://$ServiceHost/kerberos/'
"@

    Invoke-RemoteScript -ScriptText $remoteScript -LocalBaseName 'deploy-apache.sh'
}

function Remove-PreviousKeyMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$PreviousLocalKeytabPath,
        [string]$RemoteBackupPath = ''
    )

    if (Test-Path -LiteralPath $PreviousLocalKeytabPath) {
        Remove-Item -LiteralPath $PreviousLocalKeytabPath -Force
    }

    $remoteDelete = 'true'
    if (-not [string]::IsNullOrWhiteSpace($RemoteBackupPath)) {
        $remoteDelete = "sudo rm -f '$RemoteBackupPath'"
    }

    $remoteScript = @"
set -euo pipefail
$remoteDelete
sudo rm -f /tmp/http_linux-srv01.keytab /tmp/kerberos-demo.conf || true
echo 'Previous remote keytab backup removed.'
echo '--- active keytab after commit ---'
sudo klist -k -e '$RemoteKeytabPath' || true
echo '--- metadata after commit ---'
sudo cat '$RemoteMetaPath' || true
"@
    Invoke-RemoteScript -ScriptText $remoteScript -LocalBaseName 'commit-cleanup.sh'
}

function Show-ImmediateCommitNotes {
    Write-Host ''
    Write-Host 'Immediate cutover notes:' -ForegroundColor Yellow
    Write-Host '  Windows clients:  klist purge'
    Write-Host '  Linux clients:    kdestroy -A'
    Write-Host '  Browser retest after acquiring a fresh service ticket.'
    Write-Host ''
}

# -----------------------------
# Preflight
# -----------------------------
Assert-Command -Name 'Get-ADUser'
Assert-Command -Name 'ktpass.exe'
Assert-Command -Name 'setspn.exe'

$script:PlinkPath = Get-PuTTYBinary -Name 'plink.exe'
$script:PscpPath  = Get-PuTTYBinary -Name 'pscp.exe'

$domain = Get-ADDomain -Identity $DomainFqdn -Server $DomainController
$Realm = $domain.DNSRoot.ToUpperInvariant()
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
Write-Host "PuTTY plink:         $script:PlinkPath"
Write-Host "PuTTY pscp:          $script:PscpPath"
Write-Host "Action:              $Action"
Write-Host ""

Test-LinuxAdminAccess

# -----------------------------
# Actions
# -----------------------------
switch ($Action) {
    'Bootstrap' {
        $existing = Get-ServiceAccount -SamAccountName $ServiceAccountName
        if ($existing) {
            throw "Service account '$ServiceAccountName' already exists. Use -Action Rotate or remove the account first."
        }

        $rotationId = [guid]::NewGuid().ToString()
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
            -Principal $Principal `
            -MapUser $MapUser `
            -Password $initialPassword `
            -Kvno $currentKvno `
            -OutFile $keytabPath

        Deploy-KeytabToApache -LocalKeytabPath $keytabPath -Kvno $currentKvno -RotationId $rotationId

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

        $newRotationId = [guid]::NewGuid().ToString()
        $newPassword = New-StrongPassword
        $secureNew   = ConvertTo-SecureString $newPassword -AsPlainText -Force

        if ($PSCmdlet.ShouldProcess($ServiceAccountName, 'Rotate service account password')) {
            Set-ADAccountPassword `
                -Identity $ServiceAccountName `
                -Reset `
                -NewPassword $secureNew `
                -Server $DomainController
        }

        Set-ServiceAccountAes256 -SamAccountName $ServiceAccountName

        $newKvno       = Get-CurrentKvno -SamAccountName $ServiceAccountName
        $newKeytab     = New-KeytabFileName -Kvno $newKvno -GenerationLabel 'gen1' -RotationId $newRotationId
        $remoteBackup  = "$RemoteKeytabPath.previous.$newRotationId"

        Export-Keytab `
            -Principal $Principal `
            -MapUser $MapUser `
            -Password $newPassword `
            -Kvno $newKvno `
            -OutFile $newKeytab

        Deploy-KeytabToApache -LocalKeytabPath $newKeytab -Kvno $newKvno -RotationId $newRotationId -RemoteBackupPath $remoteBackup

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
            remoteKeytabPath  = $manifest.remoteKeytabPath
            remoteMetaPath    = $manifest.remoteMetaPath
            serviceUrl        = $manifest.serviceUrl
            createdAt         = $manifest.createdAt
            rotatedAt         = (Get-Date).ToString('o')
            current           = @{
                kvno        = $newKvno
                localKeytab = $newKeytab
                label       = 'gen1'
                rotationId  = $newRotationId
            }
            previous          = @{
                kvno         = [int]$manifest.current.kvno
                localKeytab  = [string]$manifest.current.localKeytab
                label        = [string]$manifest.current.label
                rotationId   = [string]$manifest.current.rotationId
                remoteBackup = $remoteBackup
            }
        }

        Save-Manifest -Path $ManifestPath -Data $updatedManifest

        Write-Host ''
        Write-Host 'Rotation complete.' -ForegroundColor Green
        Write-Host "Old KVNO:       $($updatedManifest.previous.kvno)"
        Write-Host "New AD KVNO:    $newKvno"
        Write-Host "New keytab:     $newKeytab"
        Write-Host "Remote backup:  $remoteBackup"
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

        Remove-PreviousKeyMaterial `
            -PreviousLocalKeytabPath ([string]$manifest.previous.localKeytab) `
            -RemoteBackupPath ([string]$manifest.previous.remoteBackup)

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
        }

        Save-Manifest -Path $ManifestPath -Data $finalManifest

        Write-Host ''
        Write-Host 'Commit complete.' -ForegroundColor Green
        Write-Host "Only current key material remains tracked and deployed."
        Write-Host "Current KVNO:   $($finalManifest.current.kvno)"
        Write-Host "Current keytab: $($finalManifest.current.localKeytab)"
        Write-Host "Service URL:    $($finalManifest.serviceUrl)"

        if ($ForceImmediateCommit) {
            Show-ImmediateCommitNotes
        }
    }
}
