
<# 
.SYNOPSIS
    Rotate a CLIENT Kerberos keytab from win-dc01 using Windows-side keytab appending.

.DESCRIPTION
    This version mirrors the Azure Arc "append new generation into the keytab before the
    password change" idea, but performs the append on win-dc01 using ktpass.exe with
    /in and /out against the same keytab file, instead of Linux-side merge tooling.

    Model:
      - win-dc01 exports a new current-only keytab for the predicted next KVNO
      - win-dc01 copies the current keytab to a transition keytab path
      - win-dc01 appends the new generation into that transition keytab using ktpass.exe
      - only the ready transition keytab is copied to the Linux client host
      - later Commit switches the Linux client back to the current-only keytab

    Important caveat:
      - This script follows the Arc-style ktpass append pattern on the DC.
      - It still uses ktpass.exe to produce the future/current-only keytab.
      - Validate the "future keytab before explicit Set-ADAccountPassword" sequencing in
        your lab before treating it as production-safe.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Bootstrap','Rotate','Commit')]
    [string]$Action,

    [string]$DomainFqdn       = 'frostylabs.local',
    [string]$DomainController = 'win-dc01.frostylabs.local',
    [string]$OuDn             = 'CN=Users,DC=frostylabs,DC=local',

    [string]$ClientAccountName = 'cli_http_demo',

    [string]$ClientLinuxHost   = '192.168.139.14',
    [int]   $ClientLinuxPort   = 22,
    [string]$ClientLinuxUser   = 'vagrant',
    [string]$ClientLinuxSshPrivateKeyPath = 'C:\Keys\vagrant-linux-srv01',

    [string]$ClientRemoteKeytabDir  = '/home/vagrant/krb-client',
    [string]$ClientRemoteKeytabPath = '/home/vagrant/krb-client/client.keytab',
    [string]$ClientRemoteMetaPath   = '/home/vagrant/krb-client/client.keytab.meta',

    [string]$ServiceHost = 'linux-srv01.frostylabs.local',
    [string]$ServiceUrl  = 'http://linux-srv01.frostylabs.local/kerberos/',

    [string]$WorkDir = 'C:\Kerberos-Rotation-Client-append'
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
            throw "$FilePath failed with exit code $LASTEXITCODE.`n$($output | Out-String)"
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
        '-i', $ClientLinuxSshPrivateKeyPath,
        '-p', "$ClientLinuxPort"
    )
}

function Invoke-SSH {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteCommand,
        [switch]$CaptureOutput
    )

    $args = @()
    $args += Get-CommonSshArgs
    $args += "$ClientLinuxUser@$ClientLinuxHost"
    $args += $RemoteCommand

    return Invoke-External -FilePath 'ssh.exe' -Arguments $args -Description "ssh $ClientLinuxUser@$ClientLinuxHost" -CaptureOutput:$CaptureOutput
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
    $args += "$ClientLinuxUser@$ClientLinuxHost`:$RemotePath"

    Invoke-External -FilePath 'scp.exe' -Arguments $args -Description "scp $(Split-Path $LocalPath -Leaf) -> $ClientLinuxHost"
}

function Invoke-RemoteScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [string]$LocalBaseName = 'remote-helper.sh',
        [switch]$CaptureOutput
    )

    $rotationSafeId = [guid]::NewGuid().ToString()
    $remotePath = "/tmp/$($ClientAccountName)-$rotationSafeId.sh"
    $localScript = Join-Path $script:AccountDir $LocalBaseName

    $ScriptText | Out-File -LiteralPath $localScript -Encoding ascii -Force
    Copy-ToLinux -LocalPath $localScript -RemotePath $remotePath

    try {
        return Invoke-SSH -RemoteCommand "bash $remotePath" -CaptureOutput:$CaptureOutput
    }
    finally {
        try { Invoke-SSH -RemoteCommand "rm -f '$remotePath'" | Out-Null } catch {}
    }
}

function Test-ClientLinuxAccess {
    Write-Host "Testing Linux client SSH access..." -ForegroundColor Yellow

    $probe = @(
        'set -euo pipefail',
        'echo "HOST=$(hostname -f 2>/dev/null || hostname)"',
        'echo "USER=$(id -un)"',
        'command -v kinit >/dev/null',
        'command -v klist >/dev/null',
        'command -v kdestroy >/dev/null',
        'command -v kvno >/dev/null',
        'command -v curl >/dev/null',
        'echo "CLIENT_OK=1"'
    ) -join '; '

    $out = Invoke-SSH -RemoteCommand "bash -lc '$probe'" -CaptureOutput
    Write-Host $out.Trim()
    if ($out -notmatch 'CLIENT_OK=1') {
        throw "Linux client access test did not complete successfully."
    }
}

function Get-ClientAccount {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    return Get-ADUser -Identity $SamAccountName -Server $DomainController -Properties msDS-KeyVersionNumber -ErrorAction SilentlyContinue
}

function Get-CurrentKvno {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    $obj = Get-ADUser -Identity $SamAccountName -Server $DomainController -Properties msDS-KeyVersionNumber
    return [int]$obj.'msDS-KeyVersionNumber'
}

function Set-ClientAccountAes256 {
    param([Parameter(Mandatory = $true)][string]$SamAccountName)
    Set-ADUser -Identity $SamAccountName -Server $DomainController -KerberosEncryptionType AES256
}

function New-KeytabFileName {
    param(
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$GenerationLabel,
        [Parameter(Mandatory = $true)][string]$RotationId
    )
    return Join-Path $script:AccountDir "$($ClientAccountName).$GenerationLabel.kvno$Kvno.$RotationId.keytab"
}

function Show-KeytabEntries {
    param([Parameter(Mandatory = $true)][string]$KeytabPath)

    if (-not (Test-Path -LiteralPath $KeytabPath)) {
        throw "Keytab file not found: $KeytabPath"
    }

    $item = Get-Item -LiteralPath $KeytabPath
    Write-Host ''
    Write-Host "Keytab path: $($item.FullName)" -ForegroundColor Yellow
    Write-Host "Keytab size: $($item.Length) bytes"
    Invoke-External -FilePath 'ktpass.exe' -Arguments @('/in', $KeytabPath) -Description 'Inspect keytab'
    Write-Host ''
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

function Append-KeytabEntriesOnDomainController {
    param(
        [Parameter(Mandatory = $true)][string]$BaseKeytabPath,
        [Parameter(Mandatory = $true)][string]$Principal,
        [Parameter(Mandatory = $true)][string]$MapUser,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$OutKeytabPath
    )

    if (-not (Test-Path -LiteralPath $BaseKeytabPath)) {
        throw "Base keytab not found: $BaseKeytabPath"
    }

    if (Test-Path -LiteralPath $OutKeytabPath) {
        Remove-Item -LiteralPath $OutKeytabPath -Force
    }

    Copy-Item -LiteralPath $BaseKeytabPath -Destination $OutKeytabPath -Force

    Write-Host ''
    Write-Host 'Appending new generation into transition keytab on win-dc01 with ktpass.exe' -ForegroundColor Yellow
    Write-Host "Base keytab:   $BaseKeytabPath"
    Write-Host "Output keytab: $OutKeytabPath"
    Write-Host "Principal:     $Principal"
    Write-Host "KVNO:          $Kvno"
    Write-Host ''

    $args = @(
        '/princ', $Principal,
        '/ptype', 'KRB5_NT_PRINCIPAL',
        '/kvno', "$Kvno",
        '/crypto', 'AES256-SHA1',
        '/mapuser', $MapUser,
        '/in', $OutKeytabPath,
        '/out', $OutKeytabPath,
        '-setpass',
        '/pass', $Password,
        '/target', $DomainController
    )

    Invoke-External -FilePath 'ktpass.exe' -Arguments $args -Description "Append keytab KVNO $Kvno into transition file"

    if (-not (Test-Path -LiteralPath $OutKeytabPath)) {
        throw "Transition keytab was not created: $OutKeytabPath"
    }
}

function Ensure-ClientRemoteDir {
    $cmd = @"
set -euo pipefail
install -d -m 700 '$ClientRemoteKeytabDir'
"@
    Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'init-client-dir.sh' | Out-Null
}

function Deploy-ClientKeytab {
    param(
        [Parameter(Mandatory = $true)][string]$LocalKeytabPath,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][int]$CurrentKvno,
        [string]$PreviousKvno = '',
        [Parameter(Mandatory = $true)][string]$CurrentRotationId,
        [string]$PreviousRotationId = ''
    )

    Ensure-ClientRemoteDir
    Copy-ToLinux -LocalPath $LocalKeytabPath -RemotePath '/tmp/client.keytab.upload'

    $metaBody = @("MODE=$Mode")
    if ($PreviousKvno -ne '') { $metaBody += "PREVIOUS_KVNO=$PreviousKvno" }
    $metaBody += "CURRENT_KVNO=$CurrentKvno"
    if ($PreviousRotationId -ne '') { $metaBody += "PREVIOUS_ROTATION_ID=$PreviousRotationId" }
    $metaBody += "CURRENT_ROTATION_ID=$CurrentRotationId"
    $metaBody += "CLIENT_PRINCIPAL=$($script:ClientPrincipal)"
    $metaBody += "SERVICE_PRINCIPAL=$($script:ServicePrincipal)"
    $metaText = ($metaBody -join "`n")

    $cmd = @"
set -euo pipefail
install -m 600 /tmp/client.keytab.upload '$ClientRemoteKeytabPath'
cat <<'META' > '$ClientRemoteMetaPath'
$metaText
META
echo '--- active client keytab ---'
klist -kte '$ClientRemoteKeytabPath' || true
echo '--- client keytab metadata ---'
cat '$ClientRemoteMetaPath' || true
"@
    $out = Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'deploy-client-keytab.sh' -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ''
}

function New-ClientRemoteCachePath {
    return "/tmp/$($ClientAccountName)-$([guid]::NewGuid().ToString())"
}

function Acquire-ClientTgtFromKeytab {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)

    $cmd = @"
set -euo pipefail
export KRB5CCNAME=FILE:$RemoteCachePath
kdestroy -A >/dev/null 2>&1 || true
kinit -k -t '$ClientRemoteKeytabPath' '$ClientPrincipal'
echo '--- klist after kinit ---'
klist
"@
    return Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'client-kinit.sh' -CaptureOutput
}

function Acquire-ServiceTicketFromClient {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)

    $cmd = @"
set -euo pipefail
export KRB5CCNAME=FILE:$RemoteCachePath
kvno '$ServicePrincipal'
echo '--- klist after kvno ---'
klist
"@
    return Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'client-kvno.sh' -CaptureOutput
}

function Invoke-ClientServiceRequest {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)

    $cmd = @"
set -euo pipefail
export KRB5CCNAME=FILE:$RemoteCachePath
http_code=`curl --negotiate -u : -s -o /dev/null -w "%{http_code}" '$ServiceUrl'`
echo "HTTP_CODE=$http_code"
"@
    return Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'client-curl.sh' -CaptureOutput
}

function Remove-ClientRemoteCache {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)
    try { Invoke-SSH -RemoteCommand "rm -f '$RemoteCachePath'" | Out-Null } catch {}
}

function Test-ClientAuthPath {
    param([Parameter(Mandatory = $true)][string]$Label)

    Write-Host ''
    Write-Host "Client validation: $Label" -ForegroundColor Yellow
    Write-Host '---------------------------'

    $cachePath = New-ClientRemoteCachePath
    try {
        $tgtOut = Acquire-ClientTgtFromKeytab -RemoteCachePath $cachePath
        Write-Host $tgtOut.Trim()
        Write-Host ''

        $svcOut = Acquire-ServiceTicketFromClient -RemoteCachePath $cachePath
        Write-Host $svcOut.Trim()
        Write-Host ''

        $httpOut = Invoke-ClientServiceRequest -RemoteCachePath $cachePath
        Write-Host $httpOut.Trim()
        Write-Host ''

        if ($httpOut -notmatch 'HTTP_CODE=200') {
            throw 'Client HTTP check did not return 200.'
        }
    }
    finally {
        Remove-ClientRemoteCache -RemoteCachePath $cachePath
    }
}

function Remove-TrackedLocalArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
}

Assert-Command -Name 'Get-ADUser'
Assert-Command -Name 'ktpass.exe'
Assert-Command -Name 'ssh.exe'
Assert-Command -Name 'scp.exe'

if (-not (Test-Path -LiteralPath $ClientLinuxSshPrivateKeyPath)) {
    throw "Linux SSH private key not found: $ClientLinuxSshPrivateKeyPath"
}

$domain = Get-ADDomain -Identity $DomainFqdn -Server $DomainController
$Realm = $domain.DNSRoot.ToUpperInvariant()
$Netbios = $domain.NetBIOSName

$ClientPrincipal = "$ClientAccountName@$Realm"
$MapUser         = "$Netbios\$ClientAccountName"
$ServicePrincipal = "HTTP/$ServiceHost@$Realm"

$AccountDir   = Join-Path $WorkDir $ClientAccountName
$ManifestPath = Join-Path $AccountDir 'rotation-manifest.json'
Ensure-Directory -Path $AccountDir

Write-Host "Run host:              $env:COMPUTERNAME"
Write-Host "Client principal:      $ClientPrincipal"
Write-Host "Service principal:     $ServicePrincipal"
Write-Host "Client linux target:   $ClientLinuxUser@$ClientLinuxHost`:$ClientLinuxPort"
Write-Host "Action:                $Action"
Write-Host ''

Test-ClientLinuxAccess

switch ($Action) {
    'Bootstrap' {
        $existing = Get-ClientAccount -SamAccountName $ClientAccountName
        if ($existing) {
            throw "Client account '$ClientAccountName' already exists. Use -Action Rotate or remove the account first."
        }

        $rotationId = [guid]::NewGuid().ToString()
        $initialPassword = New-StrongPassword
        $securePassword  = ConvertTo-SecureString $initialPassword -AsPlainText -Force

        if ($PSCmdlet.ShouldProcess($ClientAccountName, 'Create AD client principal')) {
            New-ADUser `
                -Name $ClientAccountName `
                -SamAccountName $ClientAccountName `
                -UserPrincipalName "$ClientAccountName@$DomainFqdn" `
                -Path $OuDn `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $true `
                -CannotChangePassword $true `
                -Description "Kerberos keytab client principal for $ServiceHost" `
                -Server $DomainController
        }

        Set-ClientAccountAes256 -SamAccountName $ClientAccountName

        $currentKvno = Get-CurrentKvno -SamAccountName $ClientAccountName
        $keytabPath  = New-KeytabFileName -Kvno $currentKvno -GenerationLabel 'gen0' -RotationId $rotationId

        Export-Keytab -Principal $ClientPrincipal -MapUser $MapUser -Password $initialPassword -Kvno $currentKvno -OutFile $keytabPath
        Show-KeytabEntries -KeytabPath $keytabPath

        Deploy-ClientKeytab -LocalKeytabPath $keytabPath -Mode 'current-only' -CurrentKvno $currentKvno -CurrentRotationId $rotationId
        Test-ClientAuthPath -Label 'bootstrap / current-only keytab'

        $manifest = @{
            domain            = $DomainFqdn
            realm             = $Realm
            domainController  = $DomainController
            clientAccount     = $ClientAccountName
            clientPrincipal   = $ClientPrincipal
            servicePrincipal  = $ServicePrincipal
            serviceUrl        = $ServiceUrl
            clientLinuxHost   = $ClientLinuxHost
            clientLinuxPort   = $ClientLinuxPort
            clientLinuxUser   = $ClientLinuxUser
            clientLinuxSshKey = $ClientLinuxSshPrivateKeyPath
            clientRemoteKeytabPath = $ClientRemoteKeytabPath
            clientRemoteMetaPath   = $ClientRemoteMetaPath
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
        Write-Host "Current client keytab: $keytabPath"
        Write-Host ''
    }

    'Rotate' {
        $manifest = Load-Manifest -Path $ManifestPath

        $acct = Get-ClientAccount -SamAccountName $ClientAccountName
        if (-not $acct) {
            throw "Client account '$ClientAccountName' not found."
        }

        $oldKvno       = [int]$manifest.current.kvno
        $oldKeytab     = [string]$manifest.current.localKeytab
        $oldRotationId = [string]$manifest.current.rotationId

        if (-not (Test-Path -LiteralPath $oldKeytab)) {
            throw "Current local client keytab not found: $oldKeytab"
        }

        $predictedNewKvno = $oldKvno + 1
        $newRotationId    = [guid]::NewGuid().ToString()
        $newPassword      = New-StrongPassword
        $futureKeytab     = New-KeytabFileName -Kvno $predictedNewKvno -GenerationLabel 'gen1' -RotationId $newRotationId
        $transitionKeytab = Join-Path $script:AccountDir "$($ClientAccountName).transition.kvno$oldKvno-$predictedNewKvno.$newRotationId.keytab"

        Export-Keytab -Principal $ClientPrincipal -MapUser $MapUser -Password $newPassword -Kvno $predictedNewKvno -OutFile $futureKeytab
        Show-KeytabEntries -KeytabPath $futureKeytab

        Append-KeytabEntriesOnDomainController -BaseKeytabPath $oldKeytab -Principal $ClientPrincipal -MapUser $MapUser -Password $newPassword -Kvno $predictedNewKvno -OutKeytabPath $transitionKeytab
        Show-KeytabEntries -KeytabPath $transitionKeytab

        Deploy-ClientKeytab `
            -LocalKeytabPath $transitionKeytab `
            -Mode 'transition' `
            -CurrentKvno $predictedNewKvno `
            -PreviousKvno "$oldKvno" `
            -CurrentRotationId $newRotationId `
            -PreviousRotationId $oldRotationId

        Test-ClientAuthPath -Label 'before password reset / appended transition keytab'

        if ($PSCmdlet.ShouldProcess($ClientAccountName, 'Rotate AD client account password')) {
            Set-ADAccountPassword `
                -Identity $ClientAccountName `
                -Reset `
                -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) `
                -Server $DomainController
        }

        Set-ClientAccountAes256 -SamAccountName $ClientAccountName

        $actualNewKvno = Get-CurrentKvno -SamAccountName $ClientAccountName
        if ($actualNewKvno -ne $predictedNewKvno) {
            throw "Predicted next KVNO ($predictedNewKvno) does not match actual AD KVNO after password reset ($actualNewKvno)."
        }

        Test-ClientAuthPath -Label 'after password reset / appended transition keytab'

        $updatedManifest = @{
            domain            = $manifest.domain
            realm             = $manifest.realm
            domainController  = $manifest.domainController
            clientAccount     = $manifest.clientAccount
            clientPrincipal   = $manifest.clientPrincipal
            servicePrincipal  = $manifest.servicePrincipal
            serviceUrl        = $manifest.serviceUrl
            clientLinuxHost   = $manifest.clientLinuxHost
            clientLinuxPort   = $manifest.clientLinuxPort
            clientLinuxUser   = $manifest.clientLinuxUser
            clientLinuxSshKey = $manifest.clientLinuxSshKey
            clientRemoteKeytabPath = $manifest.clientRemoteKeytabPath
            clientRemoteMetaPath   = $manifest.clientRemoteMetaPath
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

        Write-Host ''
        Write-Host 'Rotation complete.' -ForegroundColor Green
        Write-Host "Previous KVNO:              $oldKvno"
        Write-Host "Predicted/actual new KVNO:  $actualNewKvno"
        Write-Host "Future/current keytab:      $futureKeytab"
        Write-Host "Transition/appended keytab: $transitionKeytab"
        Write-Host ''
    }

    'Commit' {
        $manifest = Load-Manifest -Path $ManifestPath
        if (-not $manifest.previous) {
            throw 'Nothing to commit. Rotate first.'
        }

        $currentKvno = Get-CurrentKvno -SamAccountName $ClientAccountName
        if ($currentKvno -ne [int]$manifest.current.kvno) {
            throw "AD current KVNO ($currentKvno) does not match manifest current KVNO ($($manifest.current.kvno))."
        }

        Deploy-ClientKeytab `
            -LocalKeytabPath ([string]$manifest.current.localKeytab) `
            -Mode 'current-only' `
            -CurrentKvno ([int]$manifest.current.kvno) `
            -CurrentRotationId ([string]$manifest.current.rotationId)

        Test-ClientAuthPath -Label 'commit / current-only keytab'

        Remove-TrackedLocalArtifact -Path ([string]$manifest.previous.localKeytab)
        if ($manifest.transition -and $manifest.transition.localKeytab) {
            Remove-TrackedLocalArtifact -Path ([string]$manifest.transition.localKeytab)
        }

        $finalManifest = @{
            domain            = $manifest.domain
            realm             = $manifest.realm
            domainController  = $manifest.domainController
            clientAccount     = $manifest.clientAccount
            clientPrincipal   = $manifest.clientPrincipal
            servicePrincipal  = $manifest.servicePrincipal
            serviceUrl        = $manifest.serviceUrl
            clientLinuxHost   = $manifest.clientLinuxHost
            clientLinuxPort   = $manifest.clientLinuxPort
            clientLinuxUser   = $manifest.clientLinuxUser
            clientLinuxSshKey = $manifest.clientLinuxSshKey
            clientRemoteKeytabPath = $manifest.clientRemoteKeytabPath
            clientRemoteMetaPath   = $manifest.clientRemoteMetaPath
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
        Write-Host 'Client active keytab is now current-only.'
        Write-Host 'Old generation removed from active client keytab.'
        Write-Host "Current KVNO:   $($finalManifest.current.kvno)"
        Write-Host "Current keytab: $($finalManifest.current.localKeytab)"
        Write-Host ''
    }
}
