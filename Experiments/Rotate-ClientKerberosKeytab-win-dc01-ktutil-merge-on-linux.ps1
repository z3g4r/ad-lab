
<# 
.SYNOPSIS
    Rotate a CLIENT Kerberos keytab from win-dc01 using Linux-side ktutil merge.

.DESCRIPTION
    This version keeps orchestration on win-dc01 and performs only the KEYTAB MERGE on
    the Linux host with ktutil.

    Flow:
      Bootstrap
        - create AD client user
        - export current-only client keytab on win-dc01
        - upload current-only keytab to the Linux client
        - activate it as the client's active keytab
        - validate kinit/kvno/curl

      Rotate
        - read current KVNO from AD
        - predict next KVNO as current+1
        - export a future current-only keytab on win-dc01
        - upload the future current-only keytab to the Linux client
        - merge OLD + NEW keytabs on the Linux host with ktutil
        - activate the merged transition keytab
        - validate before AD password reset
        - reset the AD password on win-dc01
        - validate after AD password reset
        - save manifest

      Commit
        - switch the active client keytab back to the new current-only keytab
        - validate
        - remove tracked old artifacts
        - rewrite manifest

    IMPORTANT CAVEAT
      - In this design, ktutil only merges keytab files. It does NOT generate the new
        keytab. The new keytab is still exported on win-dc01 using ktpass.exe.
      - Therefore the "future keytab before the explicit AD password reset" assumption
        still depends on how ktpass behaves in your lab. Treat that part as a lab
        workflow to verify carefully.
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

    [string]$ClientRemoteWorkDir       = '/home/vagrant/krb-client',
    [string]$ClientRemoteActiveKeytab  = '/home/vagrant/krb-client/client.keytab',
    [string]$ClientRemoteMetaPath      = '/home/vagrant/krb-client/client.keytab.meta',

    [string]$ServiceHost = 'linux-srv01.frostylabs.local',
    [string]$ServiceUrl  = 'http://linux-srv01.frostylabs.local/kerberos/',

    [string]$WorkDir = 'C:\Kerberos-Rotation-Client-ktutil'
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
        try {
            Invoke-SSH -RemoteCommand "rm -f '$remotePath'" | Out-Null
        }
        catch {
        }
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

function Get-RemoteCurrentOnlyKeytabPath {
    param([Parameter(Mandatory = $true)][string]$RotationId)
    return "$ClientRemoteWorkDir/client.current.$RotationId.keytab"
}

function Get-RemoteTransitionKeytabPath {
    param(
        [Parameter(Mandatory = $true)][int]$OldKvno,
        [Parameter(Mandatory = $true)][int]$NewKvno,
        [Parameter(Mandatory = $true)][string]$RotationId
    )
    return "$ClientRemoteWorkDir/client.transition.kvno$OldKvno-$NewKvno.$RotationId.keytab"
}

function Test-ClientLinuxPrereqs {
    Write-Host "Testing Linux client access and prerequisites..." -ForegroundColor Yellow
    $probe = @(
        'set -euo pipefail',
        'echo "HOST=$(hostname -f 2>/dev/null || hostname)"',
        'echo "USER=$(id -un)"',
        'command -v ktutil >/dev/null',
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
        throw "Linux client did not satisfy ktutil/Kerberos prerequisites."
    }
}

function Initialize-RemoteClientDirectory {
    $cmd = @"
set -euo pipefail
install -d -m 700 '$ClientRemoteWorkDir'
"@
    Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'init-client-dir.sh' | Out-Null
}

function Show-KeytabEntries {
    param([Parameter(Mandatory = $true)][string]$KeytabPath)

    if (-not (Test-Path -LiteralPath $KeytabPath)) {
        throw "Keytab file not found: $KeytabPath"
    }

    Write-Host ""
    Write-Host "Retrieved keytab details" -ForegroundColor Yellow
    Write-Host "------------------------"
    Write-Host "Path: $KeytabPath"

    $item = Get-Item -LiteralPath $KeytabPath
    Write-Host "Size: $($item.Length) bytes"
    Write-Host ""

    Write-Host "Key information from keytab:" -ForegroundColor Yellow
    Invoke-External -FilePath 'ktpass.exe' -Arguments @('/in', $KeytabPath) -Description "Inspect keytab"
    Write-Host ""
}

function Show-RemoteKeytabEntries {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteKeytabPath,
        [string]$Label = 'remote keytab'
    )

    $cmd = @"
set -euo pipefail
echo '--- $Label ---'
klist -kte '$RemoteKeytabPath' || true
"@
    $out = Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'show-remote-keytab.sh' -CaptureOutput
    Write-Host $out.Trim()
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
        '/target', $DomainController
    )

    Invoke-External -FilePath 'ktpass.exe' -Arguments $args -Description "Export keytab KVNO $Kvno"
}

function Upload-RemoteClientKeytabArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$LocalKeytabPath,
        [Parameter(Mandatory = $true)][string]$RemoteKeytabPath
    )

    Copy-ToLinux -LocalPath $LocalKeytabPath -RemotePath $RemoteKeytabPath
}

function Merge-RemoteClientKeytabs {
    param(
        [Parameter(Mandatory = $true)][string]$OldRemoteKeytabPath,
        [Parameter(Mandatory = $true)][string]$NewRemoteKeytabPath,
        [Parameter(Mandatory = $true)][string]$TransitionRemoteKeytabPath
    )

    $tempMerged = "$TransitionRemoteKeytabPath.tmp"

    $cmd = @"
set -euo pipefail
rm -f '$tempMerged'

cat <<'KTUTIL' | ktutil >/dev/null
read_kt '$OldRemoteKeytabPath'
read_kt '$NewRemoteKeytabPath'
write_kt '$tempMerged'
quit
KTUTIL

install -m 600 '$tempMerged' '$TransitionRemoteKeytabPath'
rm -f '$tempMerged'

echo '--- merged transition keytab ---'
klist -kte '$TransitionRemoteKeytabPath' || true
"@
    $out = Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'merge-client-keytabs.sh' -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ""
}

function Activate-RemoteClientKeytab {
    param([Parameter(Mandatory = $true)][string]$RemoteSourceKeytabPath)

    $cmd = @"
set -euo pipefail
install -m 600 '$RemoteSourceKeytabPath' '$ClientRemoteActiveKeytab'
echo '--- active client keytab ---'
klist -kte '$ClientRemoteActiveKeytab' || true
"@
    $out = Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'activate-client-keytab.sh' -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ""
}

function Write-RemoteClientMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][int]$CurrentKvno,
        [Parameter(Mandatory = $true)][string]$CurrentRotationId,
        [string]$PreviousKvno = '',
        [string]$PreviousRotationId = ''
    )

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
cat <<'META' > '$ClientRemoteMetaPath'
$metaText
META

echo '--- client keytab metadata ---'
cat '$ClientRemoteMetaPath'
"@
    $out = Invoke-RemoteScript -ScriptText $cmd -LocalBaseName 'write-client-meta.sh' -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ""
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
kinit -k -t '$ClientRemoteActiveKeytab' '$ClientPrincipal'
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
    try {
        Invoke-SSH -RemoteCommand "rm -f '$RemoteCachePath'" | Out-Null
    }
    catch {
    }
}

function Test-ClientAuthPath {
    param([Parameter(Mandatory = $true)][string]$Label)

    Write-Host ""
    Write-Host "Client validation: $Label" -ForegroundColor Yellow
    Write-Host "---------------------------"

    $cachePath = New-ClientRemoteCachePath
    try {
        $tgtOut = Acquire-ClientTgtFromKeytab -RemoteCachePath $cachePath
        Write-Host $tgtOut.Trim()
        Write-Host ""

        $svcOut = Acquire-ServiceTicketFromClient -RemoteCachePath $cachePath
        Write-Host $svcOut.Trim()
        Write-Host ""

        $httpOut = Invoke-ClientServiceRequest -RemoteCachePath $cachePath
        Write-Host $httpOut.Trim()
        Write-Host ""

        if ($httpOut -notmatch 'HTTP_CODE=200') {
            throw "Client HTTP check did not return 200."
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

function Remove-TrackedRemoteArtifact {
    param([Parameter(Mandatory = $true)][string]$RemotePath)
    try {
        Invoke-SSH -RemoteCommand "rm -f '$RemotePath'" | Out-Null
    }
    catch {
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
Write-Host "Domain:                $DomainFqdn"
Write-Host "Controller:            $DomainController"
Write-Host "Client principal:      $ClientPrincipal"
Write-Host "Service principal:     $ServicePrincipal"
Write-Host "Client linux target:   $ClientLinuxUser@$ClientLinuxHost`:$ClientLinuxPort"
Write-Host "Client keytab path:    $ClientRemoteActiveKeytab"
Write-Host "Service URL:           $ServiceUrl"
Write-Host "Action:                $Action"
Write-Host ""

Test-ClientLinuxPrereqs
Initialize-RemoteClientDirectory

switch ($Action) {
    'Bootstrap' {
        $existing = Get-ClientAccount -SamAccountName $ClientAccountName
        if ($existing) {
            throw "Client account '$ClientAccountName' already exists. Use -Action Rotate or remove the account first."
        }

        $rotationId = [guid]::NewGuid().ToString()
        $initialPassword = New-StrongPassword
        $securePassword  = ConvertTo-SecureString $initialPassword -AsPlainText -Force
        $localCurrentOnly = New-KeytabFileName -Kvno 0 -GenerationLabel 'gen0' -RotationId $rotationId

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
        $localCurrentOnly = New-KeytabFileName -Kvno $currentKvno -GenerationLabel 'gen0' -RotationId $rotationId
        $remoteCurrentOnly = Get-RemoteCurrentOnlyKeytabPath -RotationId $rotationId

        Export-Keytab `
            -Principal $ClientPrincipal `
            -MapUser $MapUser `
            -Password $initialPassword `
            -Kvno $currentKvno `
            -OutFile $localCurrentOnly

        Show-KeytabEntries -KeytabPath $localCurrentOnly

        Upload-RemoteClientKeytabArtifact -LocalKeytabPath $localCurrentOnly -RemoteKeytabPath $remoteCurrentOnly
        Show-RemoteKeytabEntries -RemoteKeytabPath $remoteCurrentOnly -Label 'remote current-only keytab'
        Activate-RemoteClientKeytab -RemoteSourceKeytabPath $remoteCurrentOnly
        Write-RemoteClientMetadata -Mode 'current-only' -CurrentKvno $currentKvno -CurrentRotationId $rotationId
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
            clientRemoteActiveKeytab = $ClientRemoteActiveKeytab
            clientRemoteMetaPath     = $ClientRemoteMetaPath
            createdAt         = (Get-Date).ToString('o')
            current           = @{
                kvno             = $currentKvno
                localCurrentOnly = $localCurrentOnly
                remoteCurrentOnly = $remoteCurrentOnly
                rotationId       = $rotationId
            }
            previous          = $null
            transition        = $null
        }

        Save-Manifest -Path $ManifestPath -Data $manifest

        Write-Host ""
        Write-Host "Bootstrap complete." -ForegroundColor Green
        Write-Host "Current AD KVNO: $currentKvno"
        Write-Host "Local current-only keytab:  $localCurrentOnly"
        Write-Host "Remote current-only keytab: $remoteCurrentOnly"
        Write-Host ""
    }

    'Rotate' {
        $manifest = Load-Manifest -Path $ManifestPath

        $acct = Get-ClientAccount -SamAccountName $ClientAccountName
        if (-not $acct) {
            throw "Client account '$ClientAccountName' not found."
        }

        $oldKvno         = [int]$manifest.current.kvno
        $oldLocalCurrent = [string]$manifest.current.localCurrentOnly
        $oldRemoteCurrent = [string]$manifest.current.remoteCurrentOnly
        $oldRotationId   = [string]$manifest.current.rotationId

        if (-not (Test-Path -LiteralPath $oldLocalCurrent)) {
            throw "Current local client keytab not found: $oldLocalCurrent"
        }

        $predictedNewKvno = $oldKvno + 1
        $newRotationId    = [guid]::NewGuid().ToString()
        $newPassword      = New-StrongPassword
        $newLocalCurrent  = New-KeytabFileName -Kvno $predictedNewKvno -GenerationLabel 'gen1' -RotationId $newRotationId
        $newRemoteCurrent = Get-RemoteCurrentOnlyKeytabPath -RotationId $newRotationId
        $transitionRemote = Get-RemoteTransitionKeytabPath -OldKvno $oldKvno -NewKvno $predictedNewKvno -RotationId $newRotationId

        Export-Keytab `
            -Principal $ClientPrincipal `
            -MapUser $MapUser `
            -Password $newPassword `
            -Kvno $predictedNewKvno `
            -OutFile $newLocalCurrent

        Show-KeytabEntries -KeytabPath $newLocalCurrent

        Upload-RemoteClientKeytabArtifact -LocalKeytabPath $newLocalCurrent -RemoteKeytabPath $newRemoteCurrent
        Show-RemoteKeytabEntries -RemoteKeytabPath $newRemoteCurrent -Label 'remote future current-only keytab'

        Merge-RemoteClientKeytabs `
            -OldRemoteKeytabPath $oldRemoteCurrent `
            -NewRemoteKeytabPath $newRemoteCurrent `
            -TransitionRemoteKeytabPath $transitionRemote

        Activate-RemoteClientKeytab -RemoteSourceKeytabPath $transitionRemote

        Write-RemoteClientMetadata `
            -Mode 'transition' `
            -CurrentKvno $predictedNewKvno `
            -CurrentRotationId $newRotationId `
            -PreviousKvno "$oldKvno" `
            -PreviousRotationId $oldRotationId

        Test-ClientAuthPath -Label 'before AD password reset / transition keytab'

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

        Test-ClientAuthPath -Label 'after AD password reset / transition keytab'

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
            clientRemoteActiveKeytab = $manifest.clientRemoteActiveKeytab
            clientRemoteMetaPath     = $manifest.clientRemoteMetaPath
            createdAt         = $manifest.createdAt
            rotatedAt         = (Get-Date).ToString('o')
            current           = @{
                kvno              = $actualNewKvno
                localCurrentOnly  = $newLocalCurrent
                remoteCurrentOnly = $newRemoteCurrent
                rotationId        = $newRotationId
            }
            previous          = @{
                kvno              = $oldKvno
                localCurrentOnly  = $oldLocalCurrent
                remoteCurrentOnly = $oldRemoteCurrent
                rotationId        = $oldRotationId
            }
            transition        = @{
                remotePath        = $transitionRemote
                mode              = 'transition'
            }
        }

        Save-Manifest -Path $ManifestPath -Data $updatedManifest

        Write-Host ""
        Write-Host "Rotation complete." -ForegroundColor Green
        Write-Host "Previous KVNO:              $oldKvno"
        Write-Host "Predicted/actual new KVNO:  $actualNewKvno"
        Write-Host "Local current-only keytab:  $newLocalCurrent"
        Write-Host "Remote current-only keytab: $newRemoteCurrent"
        Write-Host "Remote transition keytab:   $transitionRemote"
        Write-Host ""
    }

    'Commit' {
        $manifest = Load-Manifest -Path $ManifestPath

        if (-not $manifest.previous) {
            throw "Nothing to commit. Rotate first."
        }

        $currentKvno = Get-CurrentKvno -SamAccountName $ClientAccountName
        if ($currentKvno -ne [int]$manifest.current.kvno) {
            throw "AD current KVNO ($currentKvno) does not match manifest current KVNO ($($manifest.current.kvno))."
        }

        Activate-RemoteClientKeytab -RemoteSourceKeytabPath ([string]$manifest.current.remoteCurrentOnly)
        Write-RemoteClientMetadata `
            -Mode 'current-only' `
            -CurrentKvno ([int]$manifest.current.kvno) `
            -CurrentRotationId ([string]$manifest.current.rotationId)

        Test-ClientAuthPath -Label 'commit / current-only keytab'

        Remove-TrackedLocalArtifact -Path ([string]$manifest.previous.localCurrentOnly)
        Remove-TrackedRemoteArtifact -RemotePath ([string]$manifest.previous.remoteCurrentOnly)

        if ($manifest.transition -and $manifest.transition.remotePath) {
            Remove-TrackedRemoteArtifact -RemotePath ([string]$manifest.transition.remotePath)
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
            clientRemoteActiveKeytab = $manifest.clientRemoteActiveKeytab
            clientRemoteMetaPath     = $manifest.clientRemoteMetaPath
            createdAt         = $manifest.createdAt
            rotatedAt         = $manifest.rotatedAt
            committedAt       = (Get-Date).ToString('o')
            current           = @{
                kvno              = [int]$manifest.current.kvno
                localCurrentOnly  = [string]$manifest.current.localCurrentOnly
                remoteCurrentOnly = [string]$manifest.current.remoteCurrentOnly
                rotationId        = [string]$manifest.current.rotationId
            }
            previous          = $null
            transition        = $null
        }

        Save-Manifest -Path $ManifestPath -Data $finalManifest

        Write-Host ""
        Write-Host "Commit complete." -ForegroundColor Green
        Write-Host "Client active keytab is now current-only."
        Write-Host "Old generation removed from the active client keytab."
        Write-Host "Current KVNO:   $($finalManifest.current.kvno)"
        Write-Host "Local keytab:   $($finalManifest.current.localCurrentOnly)"
        Write-Host "Remote keytab:  $($finalManifest.current.remoteCurrentOnly)"
        Write-Host ""
    }
}
