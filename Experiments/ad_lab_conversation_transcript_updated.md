# Conversation Transcript

This file contains the visible user/assistant conversation from this chat session in Markdown form.

---

## User
prepare a powershell script to be run in an active directory network based on this lab: https://github.com/FrostyLabs/ad-lab to perform the following:

register new service account, take a kerberos keytab for this account with one key kvno 0, set this key on an exemplary service (program) so that it can be authenticated to with it and then request another keytab with another key kvno 1, and set kvno 1 in the service replacing key kvno 0 and then prepare "commit" procedure that would make sure that when kvno 1 key is set in the service kvno 0 is invalidated and will no longer be present in the keytabs for given service accounts

## Assistant
I'm checking the lab and current Kerberos/AD behavior first, because the exact handling of keytabs and KVNOs in AD is the tricky part here. I'll give you a runnable PowerShell script, but I want to make sure it matches how AD actually rotates keys rather than encoding a lab-only assumption that will fail in practice.

## Assistant
I've confirmed the important part: in AD, KVNO follows the account's current Kerberos key, so the safe way to model "0 -> 1 -> commit" is via controlled password rotation and keytab regeneration, not by treating keytabs as independent version stores. I'm now shaping the script so it both demonstrates the lab flow and clearly separates "staged rotation" from the final cutover that invalidates the old key.

## Assistant
I'd build this as a **working AD rotation flow**, not as a literal hard-coded "KVNO 0 then KVNO 1" flow. In Active Directory, the usable KVNO is the account's current `msDS-KeyVersionNumber`, and the practical way to rotate is: create the service account, export a keytab for the current key, rotate the account password, export a new keytab for the new KVNO, deploy it, then commit by deleting the old keytab material. The `ad-lab` repo gives you exactly the pieces for that example: `frostylabs.local`, `win-dc01`, and an AD-joined `linux-srv01` running Apache/LAMP, so I used `HTTP/linux-srv01.frostylabs.local@FROSTYLABS.LOCAL` as the sample service principal. ([github.com](https://github.com/FrostyLabs/ad-lab))

I also made the sample service **Apache on `linux-srv01`** because that host is already part of the lab and `mod_auth_gssapi` supports a keytab-backed Kerberos setup through `GssapiCredStore keytab:...`. I set the service account to **AES256** rather than RC4, which matches current Microsoft guidance to move away from RC4 and is directly supported by `Set-ADUser -KerberosEncryptionType`. ([github.com](https://github.com/FrostyLabs/ad-lab))

```powershell
<# 
.SYNOPSIS
    Create and rotate an AD Kerberos service account + keytab for the FrostyLabs ad-lab.

.DESCRIPTION
    This script implements three phases:

    1) Bootstrap
       - Create a new AD user service account
       - Register SPN HTTP/linux-srv01.frostylabs.local
       - Force AES256 for the account
       - Read current AD KVNO (msDS-KeyVersionNumber)
       - Export a keytab for that KVNO
       - Deploy it to Apache on linux-srv01

    2) Rotate
       - Reset the service account password
       - Read the new AD KVNO
       - Export a new keytab for the new KVNO
       - Replace the service keytab on linux-srv01
       - Keep only a single backup copy remotely for commit-time deletion

    3) Commit
       - Delete the previous keytab locally and on the service host
       - Verify the deployed keytab contains only the current key material
       - Optionally print cache-purge commands for immediate cutover testing

    IMPORTANT:
    - This uses the REAL AD KVNO, not a forced literal 0/1.
    - Think of "Bootstrap" as your requested "kvno 0 generation"
      and "Rotate" as your requested "kvno 1 generation".
    - For a real AD deployment, that is the reliable approach.

.REQUIREMENTS
    - Run from a DC or management host with:
        * ActiveDirectory PowerShell module
        * ktpass.exe
        * setspn.exe
        * ssh.exe
        * scp.exe
    - SSH access from Windows host to linux-srv01
    - sudo rights on linux-srv01 for the chosen LinuxAdminUser

.EXAMPLE
    .\Rotate-KerberosService.ps1 -Action Bootstrap

.EXAMPLE
    .\Rotate-KerberosService.ps1 -Action Rotate

.EXAMPLE
    .\Rotate-KerberosService.ps1 -Action Commit -ForceImmediateCommit
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

    [string]$LinuxHost      = 'linux-srv01.frostylabs.local',
    [int]   $LinuxPort      = 22,
    [string]$LinuxAdminUser = 'vagrant',

    [string]$RemoteKeytabPath   = '/etc/apache2/http_linux-srv01.keytab',
    [string]$RemoteApacheConf   = '/etc/apache2/conf-available/kerberos-demo.conf',
    [string]$RemoteApacheDocDir = '/var/www/frostylabs/kerberos',

    [string]$WorkDir = 'C:\Kerberos-Rotation',

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

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$Description = $FilePath
    )

    Write-Host "==> $Description" -ForegroundColor Cyan
    $proc = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -NoNewWindow -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "$FilePath failed with exit code $($proc.ExitCode)."
    }
}

function Invoke-SSH {
    param([Parameter(Mandatory = $true)][string]$RemoteCommand)
    $args = @(
        '-p', "$LinuxPort",
        "$LinuxAdminUser@$LinuxHost",
        $RemoteCommand
    )
    Invoke-Native -FilePath 'ssh.exe' -Arguments $args -Description "SSH $LinuxHost"
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
        '-P', "$LinuxPort",
        $LocalPath,
        "$LinuxAdminUser@$LinuxHost`:$RemotePath"
    )
    Invoke-Native -FilePath 'scp.exe' -Arguments $args -Description "SCP $(Split-Path $LocalPath -Leaf) -> $LinuxHost"
}

function Invoke-RemoteScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [string]$RemotePath = '/tmp/kerberos-rotation.sh',
        [string]$LocalBaseName = 'kerberos-rotation.sh'
    )

    $localScript = Join-Path $script:AccountDir $LocalBaseName
    $ScriptText | Out-File -LiteralPath $localScript -Encoding ascii -Force
    Copy-ToLinux -LocalPath $localScript -RemotePath $RemotePath
    Invoke-SSH -RemoteCommand "bash $RemotePath"
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
    Invoke-Native -FilePath 'setspn.exe' -Arguments @('-U', '-S', $Spn, $SamAccountName) -Description "Register SPN $Spn"
}

function New-KeytabFileName {
    param(
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$GenerationLabel
    )
    return Join-Path $script:AccountDir "$($ServiceAccountName).$GenerationLabel.kvno$Kvno.keytab"
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

    Invoke-Native -FilePath 'ktpass.exe' -Arguments $args -Description "Export keytab KVNO $Kvno"
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
        [Parameter(Mandatory = $true)][int]$Kvno
    )

    $localApacheConf = Join-Path $script:AccountDir 'kerberos-demo.conf'
    $apacheConf = New-ApacheConfigContent -RemoteKeytab $RemoteKeytabPath -DocDir $RemoteApacheDocDir
    $apacheConf | Set-Content -LiteralPath $localApacheConf -Encoding ascii -Force

    Copy-ToLinux -LocalPath $LocalKeytabPath -RemotePath '/tmp/http_linux-srv01.keytab'
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
  <p>Current deployed keytab KVNO: $Kvno</p>
  <p>Principal: $($script:Principal)</p>
</body>
</html>
HTML

if [ -f '$RemoteKeytabPath' ]; then
  sudo cp '$RemoteKeytabPath' '$RemoteKeytabPath.previous'
fi

sudo install -o root -g www-data -m 640 /tmp/http_linux-srv01.keytab '$RemoteKeytabPath'
sudo install -o root -g root -m 644 /tmp/kerberos-demo.conf '$RemoteApacheConf'

sudo a2enmod auth_gssapi session session_cookie headers >/dev/null || true
sudo a2enconf $(basename '$RemoteApacheConf' .conf) >/dev/null || true

sudo systemctl enable apache2 >/dev/null
sudo systemctl restart apache2

echo '--- keytab on service host ---'
sudo klist -k -e '$RemoteKeytabPath' || true
echo '--- kerberos endpoint ---'
echo 'http://$ServiceHost/kerberos/'
"@

    Invoke-RemoteScript -ScriptText $remoteScript -LocalBaseName 'deploy-apache.sh'
}

function Remove-PreviousKeyMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$PreviousLocalKeytabPath
    )

    if (Test-Path -LiteralPath $PreviousLocalKeytabPath) {
        Remove-Item -LiteralPath $PreviousLocalKeytabPath -Force
    }

    $remoteScript = @"
set -euo pipefail
sudo rm -f '$RemoteKeytabPath.previous'
sudo rm -f /tmp/http_linux-srv01.keytab /tmp/kerberos-demo.conf /tmp/kerberos-rotation.sh || true
echo 'Previous remote keytab backup removed.'
sudo klist -k -e '$RemoteKeytabPath' || true
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

Assert-Command -Name 'ktpass.exe'
Assert-Command -Name 'setspn.exe'
Assert-Command -Name 'ssh.exe'
Assert-Command -Name 'scp.exe'

$domain = Get-ADDomain -Identity $DomainFqdn -Server $DomainController
$Realm = $domain.DNSRoot.ToUpperInvariant()
$Netbios = $domain.NetBIOSName

$Spn       = "HTTP/$ServiceHost"
$Principal = "$Spn@$Realm"
$MapUser   = "$Netbios\$ServiceAccountName"

$AccountDir   = Join-Path $WorkDir $ServiceAccountName
$ManifestPath = Join-Path $AccountDir 'rotation-manifest.json'

Ensure-Directory -Path $AccountDir

Write-Host "Domain:      $DomainFqdn"
Write-Host "Realm:       $Realm"
Write-Host "Controller:  $DomainController"
Write-Host "SPN:         $Spn"
Write-Host "Principal:   $Principal"
Write-Host "Linux host:  $LinuxHost"
Write-Host "Action:      $Action"
Write-Host ''

switch ($Action) {
    'Bootstrap' {
        $existing = Get-ServiceAccount -SamAccountName $ServiceAccountName
        if ($existing) {
            throw "Service account '$ServiceAccountName' already exists. Use -Action Rotate or remove the account first."
        }

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
        $keytabPath  = New-KeytabFileName -Kvno $currentKvno -GenerationLabel 'gen0'

        Export-Keytab `
            -Principal $Principal `
            -MapUser $MapUser `
            -Password $initialPassword `
            -Kvno $currentKvno `
            -OutFile $keytabPath

        Deploy-KeytabToApache -LocalKeytabPath $keytabPath -Kvno $currentKvno

        $manifest = @{
            domain            = $DomainFqdn
            realm             = $Realm
            domainController  = $DomainController
            serviceAccount    = $ServiceAccountName
            spn               = $Spn
            principal         = $Principal
            linuxHost         = $LinuxHost
            remoteKeytabPath  = $RemoteKeytabPath
            serviceUrl        = "http://$ServiceHost/kerberos/"
            createdAt         = (Get-Date).ToString('o')
            current           = @{
                kvno      = $currentKvno
                localKeytab= $keytabPath
                label     = 'gen0'
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
        Write-Host 'Treat this as your requested "first key / kvno-0 generation", but using the real AD KVNO.'
    }

    'Rotate' {
        $manifest = Load-Manifest -Path $ManifestPath

        $svc = Get-ServiceAccount -SamAccountName $ServiceAccountName
        if (-not $svc) {
            throw "Service account '$ServiceAccountName' not found."
        }

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

        $newKvno    = Get-CurrentKvno -SamAccountName $ServiceAccountName
        $newKeytab  = New-KeytabFileName -Kvno $newKvno -GenerationLabel 'gen1'

        Export-Keytab `
            -Principal $Principal `
            -MapUser $MapUser `
            -Password $newPassword `
            -Kvno $newKvno `
            -OutFile $newKeytab

        Deploy-KeytabToApache -LocalKeytabPath $newKeytab -Kvno $newKvno

        $updatedManifest = @{
            domain            = $manifest.domain
            realm             = $manifest.realm
            domainController  = $manifest.domainController
            serviceAccount    = $manifest.serviceAccount
            spn               = $manifest.spn
            principal         = $manifest.principal
            linuxHost         = $manifest.linuxHost
            remoteKeytabPath  = $manifest.remoteKeytabPath
            serviceUrl        = $manifest.serviceUrl
            createdAt         = $manifest.createdAt
            rotatedAt         = (Get-Date).ToString('o')
            current           = @{
                kvno       = $newKvno
                localKeytab = $newKeytab
                label      = 'gen1'
            }
            previous          = @{
                kvno       = [int]$manifest.current.kvno
                localKeytab = [string]$manifest.current.localKeytab
                label      = [string]$manifest.current.label
                remoteBackup = "$RemoteKeytabPath.previous"
            }
        }

        Save-Manifest -Path $ManifestPath -Data $updatedManifest

        Write-Host ''
        Write-Host 'Rotation complete.' -ForegroundColor Green
        Write-Host "Old KVNO:       $($updatedManifest.previous.kvno)"
        Write-Host "New AD KVNO:    $newKvno"
        Write-Host "New keytab:     $newKeytab"
        Write-Host "Remote backup:  $RemoteKeytabPath.previous"
        Write-Host ''
        Write-Host 'At this point, the service is using only the new keytab.'
        Write-Host 'Treat this as your requested "second key / kvno-1 generation", but using the real AD KVNO.'
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

        Remove-PreviousKeyMaterial -PreviousLocalKeytabPath ([string]$manifest.previous.localKeytab)

        $finalManifest = @{
            domain            = $manifest.domain
            realm             = $manifest.realm
            domainController  = $manifest.domainController
            serviceAccount    = $manifest.serviceAccount
            spn               = $manifest.spn
            principal         = $manifest.principal
            linuxHost         = $manifest.linuxHost
            remoteKeytabPath  = $manifest.remoteKeytabPath
            serviceUrl        = $manifest.serviceUrl
            createdAt         = $manifest.createdAt
            rotatedAt         = $manifest.rotatedAt
            committedAt       = (Get-Date).ToString('o')
            current           = @{
                kvno       = [int]$manifest.current.kvno
                localKeytab = [string]$manifest.current.localKeytab
                label      = [string]$manifest.current.label
            }
            previous          = $null
        }

        Save-Manifest -Path $ManifestPath -Data $finalManifest

        Write-Host ''
        Write-Host 'Commit complete.' -ForegroundColor Green
        Write-Host "Only current key material remains deployed for $ServiceAccountName."
        Write-Host "Current KVNO: $($finalManifest.current.kvno)"
        Write-Host "Current keytab: $($finalManifest.current.localKeytab)"
        Write-Host "Service URL: $($finalManifest.serviceUrl)"

        if ($ForceImmediateCommit) {
            Show-ImmediateCommitNotes
        }
    }
}
```

Run it like this:

```powershell
# First export / your requested "kvno 0" generation
.\Rotate-KerberosService.ps1 -Action Bootstrap

# Second export / your requested "kvno 1" generation
.\Rotate-KerberosService.ps1 -Action Rotate

# Finalize the cutover and delete the old keytab artifacts
.\Rotate-KerberosService.ps1 -Action Commit -ForceImmediateCommit
```

Two important notes:

1. The script does **immediate replacement**, because your requirement says that once the new key is set on the service, the old one should be invalidated and disappear from the service account's keytabs. That is exactly what the `Rotate` + `Commit` split does: `Rotate` deploys the new keytab and leaves only a single removable backup; `Commit` deletes the old backup and previous local keytab artifact. The working KVNO always follows the AD account's current key version. ([learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-keyversionnumber?utm_source=chatgpt.com))

2. Even after you commit, clients that already cached an older **service ticket** may need to re-acquire one. Microsoft documents the Kerberos service-ticket lifetime policy separately, and the common default is 600 minutes, so for lab testing you usually purge caches (`klist purge` on Windows, `kdestroy -A` on Linux) instead of waiting. ([learn.microsoft.com](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-lifetime-for-service-ticket?utm_source=chatgpt.com))

This can also be refit for SQL Server, IIS, or a non-Apache Linux service.

## User
is this apache already on linux server or should i put it there?

## Assistant
I'm checking the lab definition directly so I can answer based on the repo rather than assumption.

## Assistant
If you ran the lab setup fully, **Apache should already be on `linux-srv01`**.

The repo describes `linux-srv01` as **"Ubuntu 24.04 with LAMP stack and domain integration"** and says the `playbooks/linux-srv01.yml` playbook applies the `lamp_server` role, which **installs and configures the LAMP stack**. The `lamp_server` role explicitly includes **"Install Apache2 web server"** and creates a virtual host at `/var/www/frostylabs`. ([github.com](https://github.com/FrostyLabs/ad-lab))

What that means in practice:
- If you did `ansible-playbook labsetup.yml`, Apache should already be there. ([github.com](https://github.com/FrostyLabs/ad-lab))
- If you only did `vagrant up linux-srv01` and **did not** run the Ansible playbooks, then do **not** assume Apache is installed yet. The repo's quick start separates VM provisioning from running the Ansible playbooks. ([github.com](https://github.com/FrostyLabs/ad-lab))

Quick check on the VM:

```bash
systemctl status apache2
apache2 -v
ls /etc/apache2/sites-available
```

So for my earlier script:
- in a **fully configured ad-lab**, you likely only need to add `mod_auth_gssapi` and the Kerberos-specific Apache config.
- in a **partially built lab**, you may need to install Apache first.

I can rewrite the script to assume "Apache already present" and make it only configure Kerberos on top.

## User
what is running on that lamp server

## Assistant
I'm pulling the repo details so I can answer from the lab definition itself, not from a generic "LAMP usually means..." assumption.

## Assistant
On `linux-srv01`, the lab is meant to run more than just "plain LAMP."

By design, `linux-srv01` is the **Ubuntu 24.04 Linux server integrated with the AD domain**, and the architecture labels it as **"LAMP + SSSD."** ([github.com](https://github.com/FrostyLabs/ad-lab))

If you ran the Linux playbook, it applies three roles to that host: `linux_server_basic`, `linux_server_domain`, and `lamp_server`. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/playbooks/linux-srv01.yml))

So the box should be running these pieces:

- **Apache2** as the web server, enabled and started via systemd. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/roles/lamp_server/tasks/main.yml))
- **MySQL server** as the database component. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/roles/lamp_server/tasks/main.yml))
- **PHP** with `libapache2-mod-php` and `php-mysql`. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/roles/lamp_server/tasks/main.yml))
- A configured Apache **virtual host** for `frostylabs`, with web root at **`/var/www/frostylabs`**. ([github.com](https://github.com/FrostyLabs/ad-lab))
- Two example web files deployed there: **`index.html`** and **`info.php`**. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/roles/lamp_server/tasks/main.yml))
- **AD integration components**: `krb5-user`, `realmd`, `sssd`, `sssd-tools`, `adcli`, PAM/NSS integration, and a domain join to `frostylabs.local`. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/roles/linux_server_domain/tasks/main.yml))

So, in plain terms, that server is running:
**Apache + MySQL + PHP + AD login/domain integration**. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/roles/lamp_server/tasks/main.yml))

One important detail for your Kerberos idea: the repo does **not** appear to configure Apache for Kerberos/GSSAPI by default. It installs normal LAMP components and AD client integration, but not `mod_auth_gssapi` or an HTTP service keytab out of the box. ([raw.githubusercontent.com](https://raw.githubusercontent.com/FrostyLabs/ad-lab/main/roles/lamp_server/tasks/main.yml))

A quick verification on the VM would be:

```bash
systemctl status apache2
systemctl status mysql
ls -la /var/www/frostylabs
realm list
```

If you want, I can now trim the earlier PowerShell flow so it targets exactly what's already there and only adds the **Kerberos/GSSAPI layer** on top of this existing Apache setup.

## User
so can i authenticate to that apache with service account?

## Assistant
I'm checking both sides of this: what the lab already gives you, and how Apache Kerberos auth actually works, because "authenticate *to* Apache with a service account" can mean two different things.

## Assistant
Yes - **Apache on that lab host can be made to use a service account for Kerberos**, but the role of that account is usually **the server's identity**, not the human user's login identity. In this lab, `linux-srv01` is documented as an Ubuntu server with a **LAMP stack and domain integration**, so it is a good target for adding HTTP Kerberos on top. To enable that, you need an `HTTP/<host>@REALM` service principal mapped to an AD account and a keytab the web server can read. ([github.com](https://github.com/FrostyLabs/ad-lab))

So there are two meanings of your question:

- **"Can Apache use the service account to accept Kerberos auth?"**  
  **Yes.** That is the normal setup. You register an SPN on the AD account, export a keytab, and point Apache's GSSAPI module at that keytab, for example with `GssapiCredStore keytab:/etc/httpd.keytab`. Microsoft's SPN docs describe the SPN-to-account mapping, and `mod_auth_gssapi` shows the Apache side of using the keytab. ([learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-spn))

- **"Can I log into the website as the service account?"**  
  **Technically yes for testing, but that is usually not the intended design.** In a normal Kerberos web setup, the **client authenticates as an AD user**, while Apache proves/accepts the `HTTP/...` service identity using the service account's keytab. If you really want to test with the service account, you can acquire Kerberos credentials for that service account yourself and then make a request to Apache, but that is more of a lab validation step than a real user-login pattern. `mod_auth_gssapi` also supports a fallback Basic-auth-to-GSSAPI mode, but again that is different from standard browser SSO. ([github.com](https://github.com/gssapi/mod_auth_gssapi))

For your lab, the practical answer is: **yes, use the service account as the identity behind `HTTP/linux-srv01.frostylabs.local` and let Apache validate incoming Kerberos tickets with that keytab**. Then access the site from a domain-joined client as a normal domain user. That is the cleanest demonstration of the rotation flow you asked for earlier. ([github.com](https://github.com/FrostyLabs/ad-lab))

A simple test split would be:

1. Create `svc_http_linux` in AD.
2. Register `HTTP/linux-srv01.frostylabs.local` on that account.
3. Export keytab with `ktpass`.
4. Configure Apache `mod_auth_gssapi` to use that keytab.
5. Browse from `win-client01` as a domain user to confirm SSO.
6. Optionally do a separate CLI test where you authenticate as the service account just to prove the ticket path works. ([learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-spn))

I can turn that into the exact Apache config and a corrected PowerShell flow for the lab so it uses the service account in the right way.

## User
i wan to perform experiment to check if the old password is still working for the service account after rotate action is called

## Assistant
I'm verifying the AD behavior before I tell you how to test it, because the result depends on whether you mean "old cleartext password still gets a TGT" versus "old Kerberos key in an old keytab still works for already-issued tickets."

## Assistant
I've got the key distinction: to answer your experiment cleanly, you should use a **Kerberos-only TGT test** for the old password, not an NTLM-style network logon, because NTLM can intentionally allow the old password briefly after a change.

## Assistant
Yes - and the clean experiment is:

1. **rotate the service account password**,
2. **immediately try to get a fresh Kerberos TGT using the old password**,
3. **then try again with the new password**.

That tests exactly whether the **old password still works for Kerberos**, which is different from two easy-to-confuse cases:
- **NTLM network access**, where Microsoft documents that an old password can still work for a short period by default after a password change, and
- **old service tickets / old keytabs**, where a service may still decrypt tickets if it still has old key material. Microsoft explicitly says the NTLM grace behavior does **not** apply to components using Kerberos, and resetting a service account password increments KVNO so the old keytab breaks until you generate a new one. ([learn.microsoft.com](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/new-setting-modifies-ntlm-network-authentication))

The expected result for your experiment is:

- **Old password + fresh Kerberos TGT request:** should **fail** after `Rotate`, once you are talking to the updated DC state.  
- **New password + fresh Kerberos TGT request:** should **succeed**.  
- If you see inconsistent results in a multi-DC environment, that can be replication/PDC conflict-resolution behavior, because DCs may consult the PDC emulator during password-change propagation. In your lab, with a single DC, that ambiguity should be minimal. ([learn.microsoft.com](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/password-change-processing-conflict-resolution-function))

## Best test: Kerberos-only password check

Run this from a Linux machine that can talk Kerberos to the domain. `kinit` is ideal because it asks the KDC for a **new** TGT, so it tests the password directly instead of reusing an existing ticket.

### Test with the old password
```bash
kdestroy -A 2>/dev/null || true
kinit svc_http_linux@FROSTYLABS.LOCAL
# enter the OLD password here
klist
```

What to look for:
- **Fail**: `kinit: Preauthentication failed while getting initial credentials`
- **Pass**: `klist` shows a TGT for `svc_http_linux@FROSTYLABS.LOCAL`

### Test with the new password
```bash
kdestroy -A 2>/dev/null || true
kinit svc_http_linux@FROSTYLABS.LOCAL
# enter the NEW password here
klist
```

What to look for:
- This one should succeed after `Rotate`.

## Make the experiment stricter

Do these before each test so you do not get a false positive from cached tickets:

```bash
kdestroy -A 2>/dev/null || true
unset KRB5CCNAME
```

And on Windows clients, if you test from Windows rather than Linux:

```powershell
klist purge
```

## Recommended experiment sequence in your lab

Use this order:

1. Run `Bootstrap`
2. Confirm the **initial** password works:
   ```bash
   kdestroy -A 2>/dev/null || true
   kinit svc_http_linux@FROSTYLABS.LOCAL
   klist
   ```
3. Run `Rotate`
4. Test **old** password:
   ```bash
   kdestroy -A 2>/dev/null || true
   kinit svc_http_linux@FROSTYLABS.LOCAL
   ```
   Expected: **preauth failure**
5. Test **new** password:
   ```bash
   kdestroy -A 2>/dev/null || true
   kinit svc_http_linux@FROSTYLABS.LOCAL
   klist
   ```
   Expected: **success**
6. Run `Commit`
7. Optionally also test the web service itself as a separate check

## Important interpretation

If the **old password still succeeds in `kinit`**, that means one of these is true:
- you are not really testing Kerberos against fresh state,
- you hit a different DC than the one holding the updated password data in a larger environment,
- or the rotation step did not reset the account password the way you expected. Microsoft documents that writable DCs and the PDC emulator participate in password conflict resolution during propagation. ([learn.microsoft.com](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/password-change-processing-conflict-resolution-function))

If the **old password fails in `kinit`** but the website still works with old sessions, that does **not** mean the old password is still valid. It usually means you are seeing cached client tickets or lingering old key material on the service host, which is a different experiment from password validity. Resetting the service account password changes the effective Kerberos key version, so you must regenerate/deploy the new keytab for the service. ([learn.microsoft.com](https://learn.microsoft.com/en-us/answers/questions/185640/reset-service-account-password))

## What not to use for this experiment

Do **not** use SMB share access, WinRM, or generic "can I still log in over the network?" tests as your primary check, because NTLM has a documented old-password grace period for network access after a password change, defaulting to five minutes unless configured otherwise. Microsoft also notes that this grace behavior does not affect Kerberos-based components. ([learn.microsoft.com](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/new-setting-modifies-ntlm-network-authentication))

## Small addition to your PowerShell flow

Add a post-rotate note like this to the script output:

```powershell
Write-Host ""
Write-Host "Password validity test after rotation:"
Write-Host "  1. On a Kerberos-capable client, run: kdestroy -A"
Write-Host "  2. Then run: kinit $ServiceAccountName@$($DomainFqdn.ToUpper())"
Write-Host "  3. Enter OLD password -> should fail"
Write-Host "  4. Repeat with NEW password -> should succeed"
Write-Host ""
```

And if you want a truly controlled lab experiment, keep the **old password only in memory** just long enough to run the old-password `kinit` test, then discard it immediately.

I can also modify the earlier script so `Rotate` prints a ready-to-run SSH command that performs both the old-password and new-password Kerberos checks on `linux-srv01`.

## User
prepare me a separate script performing that pwd test, we need to be sure that after rotation the old pwd is no longer working

## Assistant
I'm shaping this as a **Kerberos-only verifier**, not a generic login test, so it checks the exact thing you care about: whether the KDC still accepts the old password after rotation.

## Assistant
Yes - here is a **separate PowerShell verifier** that tests exactly this:

- **old password** after `Rotate` -> must **fail** to get a fresh Kerberos TGT
- **new password** after `Rotate` -> must **succeed**

It does that by:
- prompting you for the **old** and **new** passwords,
- copying a tiny helper script to `linux-srv01`,
- running `kinit` there with an isolated Kerberos cache for each test,
- and returning a clear **PASS / FAIL** verdict.

Run it **after `Rotate`** and ideally **before `Commit`**.

```powershell
<# 
.SYNOPSIS
    Verify that the OLD password for an AD service account no longer works
    for Kerberos after rotation, while the NEW password does.

.DESCRIPTION
    This script performs a Kerberos-only test from a Linux host (default: linux-srv01)
    using kinit with isolated credential caches.

    Expected result after rotation:
      - OLD password  => FAIL
      - NEW password  => SUCCESS

    The script exits with:
      0 = expected behavior confirmed
      1 = verification failed
      2 = execution / environment error

.PARAMETER ServiceAccountName
    SamAccountName / UPN prefix of the service account, e.g. svc_http_linux

.PARAMETER Realm
    Kerberos realm, e.g. FROSTYLABS.LOCAL

.PARAMETER LinuxHost
    Host on which kinit will be executed.

.PARAMETER LinuxAdminUser
    SSH user for the Linux host.

.PARAMETER Principal
    Optional override for the Kerberos principal to test.
    Default: <ServiceAccountName>@<Realm>

.PARAMETER LinuxPort
    SSH port.

.PARAMETER RemoteHelperPath
    Temporary helper script path on Linux.

.PARAMETER KeepRemoteHelper
    Do not delete the helper script after the test.

.EXAMPLE
    .\Test-ServiceAccountPasswordAfterRotate.ps1

.EXAMPLE
    .\Test-ServiceAccountPasswordAfterRotate.ps1 `
      -ServiceAccountName svc_http_linux `
      -Realm FROSTYLABS.LOCAL `
      -LinuxHost linux-srv01.frostylabs.local `
      -LinuxAdminUser vagrant
#>

[CmdletBinding()]
param(
    [string]$ServiceAccountName = 'svc_http_linux',
    [string]$Realm              = 'FROSTYLABS.LOCAL',
    [string]$LinuxHost          = 'linux-srv01.frostylabs.local',
    [string]$LinuxAdminUser     = 'vagrant',
    [int]$LinuxPort             = 22,
    [string]$Principal          = '',
    [string]$RemoteHelperPath   = '/tmp/kerberos_pwd_verify.py',
    [switch]$KeepRemoteHelper
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Invoke-SCP {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$RemotePath
    )

    & scp.exe -P $LinuxPort $LocalPath "$LinuxAdminUser@$LinuxHost`:$RemotePath"
    if ($LASTEXITCODE -ne 0) {
        throw "scp failed with exit code $LASTEXITCODE"
    }
}

function Invoke-SSH {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteCommand
    )

    & ssh.exe -p $LinuxPort "$LinuxAdminUser@$LinuxHost" $RemoteCommand
    if ($LASTEXITCODE -ne 0) {
        throw "ssh failed with exit code $LASTEXITCODE"
    }
}

function Invoke-SSHWithJsonInput {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteCommand,
        [Parameter(Mandatory = $true)][string]$JsonInput
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'ssh.exe'
    $psi.Arguments = "-p $LinuxPort $LinuxAdminUser@$LinuxHost $RemoteCommand"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    if (-not $proc.Start()) {
        throw 'Failed to start ssh process.'
    }

    $proc.StandardInput.Write($JsonInput)
    $proc.StandardInput.Close()

    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    $proc.WaitForExit()

    return [pscustomobject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

Assert-Command -Name 'ssh.exe'
Assert-Command -Name 'scp.exe'

if ([string]::IsNullOrWhiteSpace($Principal)) {
    $Principal = "$ServiceAccountName@$($Realm.ToUpperInvariant())"
}

Write-Host "Linux host:  $LinuxHost"
Write-Host "Principal:   $Principal"
Write-Host ""

$oldSecure = Read-Host "Enter OLD password for $Principal" -AsSecureString
$newSecure = Read-Host "Enter NEW password for $Principal" -AsSecureString

$oldPassword = ConvertTo-PlainText -SecureString $oldSecure
$newPassword = ConvertTo-PlainText -SecureString $newSecure

$helperPy = @'
import json
import os
import subprocess
import sys
import tempfile

def run_test(principal, password, label):
    fd, cache_path = tempfile.mkstemp(prefix=f"krb5cc_{label}_")
    os.close(fd)

    try:
        env = os.environ.copy()
        env["KRB5CCNAME"] = f"FILE:{cache_path}"

        kinit = subprocess.run(
            ["kinit", principal],
            input=password + "\n",
            text=True,
            capture_output=True,
            env=env,
        )

        result = {
            "label": label,
            "principal": principal,
            "exit_code": kinit.returncode,
            "success": kinit.returncode == 0,
            "stdout": (kinit.stdout or "").strip(),
            "stderr": (kinit.stderr or "").strip(),
            "cache": env["KRB5CCNAME"],
            "tgt_present": False,
            "klist_stdout": "",
            "klist_stderr": "",
        }

        if kinit.returncode == 0:
            klist = subprocess.run(
                ["klist", "-c", env["KRB5CCNAME"]],
                text=True,
                capture_output=True,
                env=env,
            )
            result["tgt_present"] = (klist.returncode == 0)
            result["klist_stdout"] = (klist.stdout or "").strip()
            result["klist_stderr"] = (klist.stderr or "").strip()

        subprocess.run(
            ["kdestroy", "-c", env["KRB5CCNAME"]],
            text=True,
            capture_output=True,
            env=env,
        )

        return result
    finally:
        try:
            os.remove(cache_path)
        except FileNotFoundError:
            pass
        except Exception:
            pass

def main():
    payload = json.load(sys.stdin)

    principal = payload["principal"]
    old_password = payload["old_password"]
    new_password = payload["new_password"]

    out = {
        "principal": principal,
        "old_password_test": run_test(principal, old_password, "old"),
        "new_password_test": run_test(principal, new_password, "new"),
    }

    old_ok = out["old_password_test"]["success"]
    new_ok = out["new_password_test"]["success"]

    out["expected"] = {
        "old_password_should_work": False,
        "new_password_should_work": True,
    }

    out["verdict"] = {
        "pass": (old_ok is False) and (new_ok is True),
        "old_password_rejected": (old_ok is False),
        "new_password_accepted": (new_ok is True),
    }

    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
'@

$localHelper = Join-Path $env:TEMP 'kerberos_pwd_verify.py'
$helperPy | Set-Content -LiteralPath $localHelper -Encoding ascii -Force

try {
    Write-Host "Copying helper to Linux host..." -ForegroundColor Cyan
    Invoke-SCP -LocalPath $localHelper -RemotePath $RemoteHelperPath

    Write-Host "Checking remote prerequisites..." -ForegroundColor Cyan
    Invoke-SSH -RemoteCommand "bash -lc 'command -v python3 >/dev/null && command -v kinit >/dev/null && command -v klist >/dev/null && command -v kdestroy >/dev/null'"

    $payload = [ordered]@{
        principal    = $Principal
        old_password = $oldPassword
        new_password = $newPassword
    } | ConvertTo-Json -Compress

    Write-Host "Running Kerberos password verification..." -ForegroundColor Cyan
    $result = Invoke-SSHWithJsonInput -RemoteCommand "python3 $RemoteHelperPath" -JsonInput $payload

    if ($result.ExitCode -ne 0) {
        Write-Host ""
        Write-Host "Remote execution failed." -ForegroundColor Red
        if ($result.StdErr) {
            Write-Host $result.StdErr
        }
        exit 2
    }

    $parsed = $result.StdOut | ConvertFrom-Json

    Write-Host ""
    Write-Host "Result summary" -ForegroundColor Yellow
    Write-Host "--------------"
    Write-Host "Principal: $($parsed.principal)"
    Write-Host "Old password accepted: $($parsed.old_password_test.success)"
    Write-Host "New password accepted: $($parsed.new_password_test.success)"
    Write-Host ""

    Write-Host "Old password stderr:"
    Write-Host ($parsed.old_password_test.stderr | ForEach-Object { if ($_ -eq '') { '<empty>' } else { $_ } })
    Write-Host ""

    Write-Host "New password stderr:"
    Write-Host ($parsed.new_password_test.stderr | ForEach-Object { if ($_ -eq '') { '<empty>' } else { $_ } })
    Write-Host ""

    if ($parsed.new_password_test.tgt_present) {
        Write-Host "New password TGT check:" -ForegroundColor Green
        Write-Host $parsed.new_password_test.klist_stdout
        Write-Host ""
    }

    if ($parsed.verdict.pass) {
        Write-Host "PASS: old password is no longer working, new password is working." -ForegroundColor Green
        exit 0
    }
    else {
        Write-Host "FAIL: rotation verification did not produce the expected result." -ForegroundColor Red

        if (-not $parsed.verdict.old_password_rejected) {
            Write-Host "  - Old password was still accepted." -ForegroundColor Red
        }
        if (-not $parsed.verdict.new_password_accepted) {
            Write-Host "  - New password was not accepted." -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "Full JSON result:"
        Write-Host $result.StdOut

        exit 1
    }
}
finally {
    $oldPassword = $null
    $newPassword = $null

    if (-not $KeepRemoteHelper) {
        try {
            & ssh.exe -p $LinuxPort "$LinuxAdminUser@$LinuxHost" "rm -f $RemoteHelperPath" | Out-Null
        }
        catch {
        }
    }

    if (Test-Path -LiteralPath $localHelper) {
        Remove-Item -LiteralPath $localHelper -Force -ErrorAction SilentlyContinue
    }
}
```

Use it like this:

```powershell
.\Test-ServiceAccountPasswordAfterRotate.ps1
```

Or with explicit values:

```powershell
.\Test-ServiceAccountPasswordAfterRotate.ps1 `
  -ServiceAccountName svc_http_linux `
  -Realm FROSTYLABS.LOCAL `
  -LinuxHost linux-srv01.frostylabs.local `
  -LinuxAdminUser vagrant
```

What success looks like:
- **OLD password**: rejected
- **NEW password**: accepted
- script exits with **0**

What failure looks like:
- old password still accepted, or
- new password rejected
- script exits with **1**

A good sequence is:

```powershell
# 1. Run your Rotate action first
.\Rotate-KerberosService.ps1 -Action Rotate

# 2. Immediately run the verifier
.\Test-ServiceAccountPasswordAfterRotate.ps1
```

If you want, I can also give you a second version that **reads the old/new passwords from the rotation manifest automatically**, so you do not have to type them manually during the experiment.

## User
i want a bash script drop whis whole convo to md file and prepare for download

## User
drop whis whole convo to md file and prepare for download

---

End of transcript.

---

# Current context snapshot

_Last updated: 2026-04-15 23:01:08 UTC_

## Goal
Prepare and validate a Kerberos service-account rotation experiment in the FrostyLabs `ad-lab`, focused on:
- creating an HTTP service account for Apache on `linux-srv01`
- generating and deploying keytabs
- rotating the service account password and keytab
- verifying that old credentials and old key material stop working
- keeping a reusable transcript/context file for future chats

## Lab assumptions confirmed
- `win-dc01` is the preferred machine to run the rotation PowerShell script from.
- `linux-srv01` is the Ubuntu LAMP + AD-integrated server in the lab.
- Apache should already exist on `linux-srv01` if the Ansible playbooks were fully applied.
- The lab repo does not clearly prove that SSH password auth is enabled on `linux-srv01`.
- The safer SSH approach is to use the Vagrant private key copied onto `win-dc01`.
- The Vagrant private key path is not defined in the repo; the correct discovery method is:
  - `vagrant ssh-config linux-srv01`
  - then copy the `IdentityFile` key onto `win-dc01`

## Important Kerberos model decisions
- In AD, practical keytab rotation should follow the account's real `msDS-KeyVersionNumber` (KVNO), not assume a literal hard-coded `0 -> 1`.
- `Rotate` is the step that changes the AD password and invalidates the old password in AD.
- `Commit` is a cleanup/finalization step that deletes old tracked keytab artifacts and backup files; it does not change AD.
- Normal Apache Kerberos SSO means:
  - the user authenticates as themselves
  - Apache uses the service account keytab as the HTTP service identity

## Main files prepared
### 1. Transcript markdown
- `ad_lab_conversation_transcript.md`

### 2. Rotation script for `win-dc01` using Vagrant SSH key
- `Rotate-KerberosService-win-dc01-vagrantkey.ps1`

Purpose:
- run on `win-dc01`
- use Windows AD tooling (`Get-ADUser`, `Set-ADAccountPassword`, `setspn`, `ktpass`)
- SSH to `linux-srv01` with:
  - `ssh.exe`
  - `scp.exe`
  - `-i <Vagrant private key>`
- deploy Apache Kerberos config and keytab
- support actions:
  - `Bootstrap`
  - `Rotate`
  - `Commit`

## Current script behavior summary
### Bootstrap
- creates `svc_http_linux`
- registers `HTTP/linux-srv01.frostylabs.local`
- exports first keytab
- deploys it to Apache on `linux-srv01`

### Rotate
- resets the AD service-account password
- reads the new KVNO from AD
- exports a new keytab
- deploys the new keytab to Apache
- stores the previous generation in the manifest as cleanup state

### Commit
- loads the manifest
- checks that `manifest.previous` exists
- checks that AD current KVNO still matches `manifest.current.kvno`
- deletes previous tracked local and remote keytab artifacts
- rewrites the manifest with `previous = null`

## Manifest meaning
The rotation manifest is a local JSON state file used by the script, typically:
- `C:\Kerberos-Rotation\svc_http_linux\rotation-manifest.json`

It stores:
- domain / realm / principal
- current keytab generation
- previous keytab generation
- remote paths
- timestamps

It is only script bookkeeping; it is not an AD or Kerberos-native object.

## Concurrency caveat already identified
The original manifest-only approach is not fully safe if a separate process rotates the same service account concurrently.
Safer design ideas already noted:
- per-rotation GUID / rotation ID
- unique backup file names
- a locking mechanism
- stronger verification before commit

The newer script version already moved toward safer behavior by using:
- unique rotation IDs
- unique remote helper-script names
- per-rotation remote backup filenames

## Apache and keytab authentication setup
Recommended Apache GSSAPI pattern in the lab:
- install `libapache2-mod-auth-gssapi`
- configure Apache with:
  - `AuthType GSSAPI`
  - `GssapiCredStore keytab:/etc/apache2/http_linux-srv01.active.keytab`
  - `Require valid-user`
- for stale-vs-current keytab testing, avoid `GssapiUseSessions On` during the experiment to reduce false positives from cookie-backed sessions

## Best validation experiments agreed
### A. Old password should no longer work after rotation
Best test method:
- perform a fresh Kerberos TGT acquisition
- old password should fail
- new password should succeed

Recommended commands:
- `kdestroy -A`
- `kinit svc_http_linux@FROSTYLABS.LOCAL`

### B. Old keytab should fail, current keytab should succeed
Best test design:
- keep two server-side keytabs:
  - old
  - current
- Apache reads a single active path such as:
  - `/etc/apache2/http_linux-srv01.active.keytab`
- copy the old keytab into the active path and restart Apache
- get fresh client Kerberos tickets
- call Apache with SPNEGO using curl
- expected:
  - old keytab active -> HTTP 401
  - current keytab active -> HTTP 200

Recommended client command:
- `curl --negotiate -u : http://linux-srv01.frostylabs.local/kerberos/`

## Outstanding practical requirement
Before running the key-based rotation script on `win-dc01`, the Vagrant SSH private key for `linux-srv01` must be copied from the Vagrant host to `win-dc01`.

Best discovery command on the Vagrant host:
- `vagrant ssh-config linux-srv01`

Then copy the `IdentityFile` shown there onto `win-dc01`, for example to:
- `C:\Keys\vagrant-linux-srv01`

## Example script usage
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

.\Rotate-KerberosService-win-dc01-vagrantkey.ps1 `
  -Action Bootstrap `
  -LinuxSshPrivateKeyPath C:\Keys\vagrant-linux-srv01

.\Rotate-KerberosService-win-dc01-vagrantkey.ps1 `
  -Action Rotate `
  -LinuxSshPrivateKeyPath C:\Keys\vagrant-linux-srv01

.\Rotate-KerberosService-win-dc01-vagrantkey.ps1 `
  -Action Commit `
  -LinuxSshPrivateKeyPath C:\Keys\vagrant-linux-srv01
```

## Suggested next steps for a new chat
If this file is used as context in a new chat, the best continuation points are:
1. prepare a matching password-verification script using the same Vagrant-key SSH path
2. prepare a server-side helper to switch Apache between old and current keytabs for the A/B test
3. tighten the rotation workflow with lock handling and stronger commit verification
