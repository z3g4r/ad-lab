
<# 
.SYNOPSIS
    Rotate a CLIENT Kerberos keytab from win-dc01 using the adutil-style next-KVNO workflow.

.DESCRIPTION
    This is a lab adaptation of Microsoft's documented adutil rotation sequence:
      1. obtain/renew a privileged Kerberos TGT on a domain-joined Linux machine
      2. determine current KVNO
      3. add/build next-KVNO keytab entries BEFORE changing the AD password
      4. then reset the AD password in Active Directory
      5. validate access continues to work

    IMPORTANT
      - Microsoft documents adutil for SQL Server on Linux use cases. This script adapts
        the same workflow pattern for a generic client principal in a lab.
      - Because adutil must run on a domain-joined machine, this script SSHes to the Linux
        client host and runs adutil there.
      - The old cached TGT lives in the credentials cache, not in the keytab.

    ACTIONS
      Bootstrap:
        - create AD client user
        - build a current-only client keytab on the Linux client using adutil
        - activate it
        - validate kinit/kvno/curl

      Rotate:
        - build a future current-only keytab with next KVNO on the Linux client
        - append the next-KVNO entry to the active keytab so it becomes a transition keytab
        - validate before AD password reset
        - reset the AD password on win-dc01
        - validate after AD password reset
        - save manifest

      Commit:
        - switch the active client keytab back to the staged current-only keytab
        - validate
        - remove tracked old artifacts
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

    [Parameter(Mandatory = $true)]
    [string]$PrivilegedAdPrincipal,

    [string]$ClientLinuxHost   = '192.168.139.14',
    [int]   $ClientLinuxPort   = 22,
    [string]$ClientLinuxUser   = 'vagrant',
    [string]$ClientLinuxSshPrivateKeyPath = 'C:\Keys\vagrant-linux-srv01',

    [string]$ClientRemoteWorkDir       = '/home/vagrant/krb-client',
    [string]$ClientRemoteActiveKeytab  = '/home/vagrant/krb-client/client.keytab',
    [string]$ClientRemoteMetaPath      = '/home/vagrant/krb-client/client.keytab.meta',

    [string]$ServiceHost = 'linux-srv01.frostylabs.local',
    [string]$ServiceUrl  = 'http://linux-srv01.frostylabs.local/kerberos/',

    [string]$WorkDir = 'C:\Kerberos-Rotation-Client-adutil'
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

function Convert-SecureStringToPlainText {
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

function Convert-TextToBase64 {
    param([Parameter(Mandatory = $true)][string]$Text)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Text))
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

function Get-RemoteCurrentOnlyKeytabPath {
    param([Parameter(Mandatory = $true)][string]$RotationId)
    return "$ClientRemoteWorkDir/client.current.$RotationId.keytab"
}

function Test-ClientLinuxPrereqs {
    Write-Host "Testing Linux client access and prerequisites..." -ForegroundColor Yellow
    $probe = @(
        'set -euo pipefail',
        'echo "HOST=$(hostname -f 2>/dev/null || hostname)"',
        'echo "USER=$(id -un)"',
        'command -v adutil >/dev/null',
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
        throw "Linux client did not satisfy adutil/Kerberos prerequisites."
    }
}

function Initialize-RemoteClientDirectory {
    $cmd = @"
set -euo pipefail
install -d -m 700 '$ClientRemoteWorkDir'
"@
    Invoke-SSH -RemoteCommand "bash -lc \"$($cmd.Replace('"','\"'))\""
}

function Show-RemoteKeytabEntries {
    param([Parameter(Mandatory = $true)][string]$RemoteKeytabPath)

    $cmd = @"
set -euo pipefail
echo '--- remote keytab ---'
klist -kte '$RemoteKeytabPath'
"@
    $out = Invoke-SSH -RemoteCommand "bash -lc \"$($cmd.Replace('"','\"'))\"" -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ""
}

function Invoke-RemoteAdutilCreateKeytab {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteKeytabPath,
        [Parameter(Mandatory = $true)][string]$PrincipalNameForAdutil,
        [Parameter(Mandatory = $true)][string]$PrincipalPassword,
        [Parameter(Mandatory = $true)][int]$Kvno,
        [Parameter(Mandatory = $true)][string]$PrivilegedPrincipal,
        [Parameter(Mandatory = $true)][string]$PrivilegedPassword,
        [switch]$Append
    )

    $privB64 = Convert-TextToBase64 -Text $PrivilegedPassword
    $acctB64 = Convert-TextToBase64 -Text $PrincipalPassword

    $removeLine = ""
    if (-not $Append) {
        $removeLine = "rm -f '$RemoteKeytabPath'"
    }

    $cmd = @"
set -euo pipefail
export KRB5CCNAME=FILE:/tmp/adutil-$([guid]::NewGuid().ToString()).ccache
priv_pass=`printf '%s' '$privB64' | base64 -d`
acct_pass=`printf '%s' '$acctB64' | base64 -d`
printf '%s\n' "\$priv_pass" | kinit '$PrivilegedPrincipal'
$removeLine
adutil keytab create -k '$RemoteKeytabPath' -p '$PrincipalNameForAdutil' --password "\$acct_pass" --kvno $Kvno
klist -kte '$RemoteKeytabPath'
rm -f "\${KRB5CCNAME#FILE:}"
"@
    $out = Invoke-SSH -RemoteCommand "bash -lc \"$($cmd.Replace('"','\"'))\"" -CaptureOutput
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
    $meta = ($metaBody -join "`n")

    $cmd = @"
set -euo pipefail
cat <<'META' > '$ClientRemoteMetaPath'
$meta
META
echo '--- client keytab metadata ---'
cat '$ClientRemoteMetaPath'
"@
    $out = Invoke-SSH -RemoteCommand "bash -lc \"$($cmd.Replace('"','\"'))\"" -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ""
}

function Promote-RemoteCurrentOnlyKeytab {
    param([Parameter(Mandatory = $true)][string]$RemoteCurrentOnlyKeytabPath)

    $cmd = @"
set -euo pipefail
install -d -m 700 '$ClientRemoteWorkDir'
install -m 600 '$RemoteCurrentOnlyKeytabPath' '$ClientRemoteActiveKeytab'
echo '--- active client keytab ---'
klist -kte '$ClientRemoteActiveKeytab'
"@
    $out = Invoke-SSH -RemoteCommand "bash -lc \"$($cmd.Replace('"','\"'))\"" -CaptureOutput
    Write-Host $out.Trim()
    Write-Host ""
}

function New-ClientRemoteCachePath {
    return "/tmp/$($ClientAccountName)-$([guid]::NewGuid().ToString())"
}

function Acquire-ClientTgtFromKeytab {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)
    $remoteScript = @"
set -euo pipefail
export KRB5CCNAME=FILE:$RemoteCachePath
kdestroy -A >/dev/null 2>&1 || true
kinit -k -t '$ClientRemoteActiveKeytab' '$ClientPrincipal'
echo '--- klist after kinit ---'
klist
"@
    return Invoke-SSH -RemoteCommand "bash -lc \"$($remoteScript.Replace('"','\"'))\"" -CaptureOutput
}

function Acquire-ServiceTicketFromClient {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)
    $remoteScript = @"
set -euo pipefail
export KRB5CCNAME=FILE:$RemoteCachePath
kvno '$ServicePrincipal'
echo '--- klist after kvno ---'
klist
"@
    return Invoke-SSH -RemoteCommand "bash -lc \"$($remoteScript.Replace('"','\"'))\"" -CaptureOutput
}

function Invoke-ClientServiceRequest {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)
    $remoteScript = @"
set -euo pipefail
export KRB5CCNAME=FILE:$RemoteCachePath
http_code=`curl --negotiate -u : -s -o /dev/null -w "%{http_code}" '$ServiceUrl'`
echo "HTTP_CODE=$http_code"
"@
    return Invoke-SSH -RemoteCommand "bash -lc \"$($remoteScript.Replace('"','\"'))\"" -CaptureOutput
}

function Remove-ClientRemoteCache {
    param([Parameter(Mandatory = $true)][string]$RemoteCachePath)
    try {
        Invoke-SSH -RemoteCommand "rm -f '$RemoteCachePath'" | Out-Null
    }
    catch {}
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

function Remove-TrackedRemoteArtifact {
    param([Parameter(Mandatory = $true)][string]$RemotePath)
    try {
        Invoke-SSH -RemoteCommand "rm -f '$RemotePath'" | Out-Null
    }
    catch {}
}

function Get-PrivilegedPassword {
    $secure = Read-Host "Enter password for $PrivilegedAdPrincipal" -AsSecureString
    return Convert-SecureStringToPlainText -SecureString $secure
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

$ClientPrincipal  = "$ClientAccountName@$Realm"
$ServicePrincipal = "HTTP/$ServiceHost@$Realm"

$AccountDir   = Join-Path $WorkDir $ClientAccountName
$ManifestPath = Join-Path $AccountDir 'rotation-manifest.json'

Ensure-Directory -Path $AccountDir

Write-Host "Run host:              $env:COMPUTERNAME"
Write-Host "Domain:                $DomainFqdn"
Write-Host "Controller:            $DomainController"
Write-Host "Client principal:      $ClientPrincipal"
Write-Host "Privileged principal:  $PrivilegedAdPrincipal"
Write-Host "Service principal:     $ServicePrincipal"
Write-Host "Linux client target:   $ClientLinuxUser@$ClientLinuxHost`:$ClientLinuxPort"
Write-Host "Active keytab path:    $ClientRemoteActiveKeytab"
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
        $currentOnlyPath = Get-RemoteCurrentOnlyKeytabPath -RotationId $rotationId

        $privPass = Get-PrivilegedPassword

        Invoke-RemoteAdutilCreateKeytab `
            -RemoteKeytabPath $currentOnlyPath `
            -PrincipalNameForAdutil $ClientAccountName `
            -PrincipalPassword $initialPassword `
            -Kvno $currentKvno `
            -PrivilegedPrincipal $PrivilegedAdPrincipal `
            -PrivilegedPassword $privPass

        Promote-RemoteCurrentOnlyKeytab -RemoteCurrentOnlyKeytabPath $currentOnlyPath
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
                kvno              = $currentKvno
                remoteCurrentOnly = $currentOnlyPath
                rotationId        = $rotationId
            }
            previous          = $null
        }

        Save-Manifest -Path $ManifestPath -Data $manifest

        Write-Host ""
        Write-Host "Bootstrap complete." -ForegroundColor Green
        Write-Host "Current AD KVNO: $currentKvno"
        Write-Host "Remote current-only keytab: $currentOnlyPath"
        Write-Host ""
    }

    'Rotate' {
        $manifest = Load-Manifest -Path $ManifestPath

        $acct = Get-ClientAccount -SamAccountName $ClientAccountName
        if (-not $acct) {
            throw "Client account '$ClientAccountName' not found."
        }

        $oldKvno       = [int]$manifest.current.kvno
        $oldCurrentOnlyPath = [string]$manifest.current.remoteCurrentOnly
        $oldRotationId = [string]$manifest.current.rotationId

        $predictedNewKvno = $oldKvno + 1
        $newRotationId    = [guid]::NewGuid().ToString()
        $newPassword      = New-StrongPassword
        $newCurrentOnlyPath = Get-RemoteCurrentOnlyKeytabPath -RotationId $newRotationId

        $privPass = Get-PrivilegedPassword

        # Build the future current-only keytab first, using current KVNO + 1.
        Invoke-RemoteAdutilCreateKeytab `
            -RemoteKeytabPath $newCurrentOnlyPath `
            -PrincipalNameForAdutil $ClientAccountName `
            -PrincipalPassword $newPassword `
            -Kvno $predictedNewKvno `
            -PrivilegedPrincipal $PrivilegedAdPrincipal `
            -PrivilegedPassword $privPass

        # Append the same next-KVNO entry into the active keytab so it becomes a transition keytab.
        Invoke-RemoteAdutilCreateKeytab `
            -RemoteKeytabPath $ClientRemoteActiveKeytab `
            -PrincipalNameForAdutil $ClientAccountName `
            -PrincipalPassword $newPassword `
            -Kvno $predictedNewKvno `
            -PrivilegedPrincipal $PrivilegedAdPrincipal `
            -PrivilegedPassword $privPass `
            -Append

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
                remoteCurrentOnly = $newCurrentOnlyPath
                rotationId        = $newRotationId
            }
            previous          = @{
                kvno              = $oldKvno
                remoteCurrentOnly = $oldCurrentOnlyPath
                rotationId        = $oldRotationId
            }
        }

        Save-Manifest -Path $ManifestPath -Data $updatedManifest

        Write-Host ""
        Write-Host "Rotation complete." -ForegroundColor Green
        Write-Host "Previous KVNO:              $oldKvno"
        Write-Host "Predicted/actual new KVNO:  $actualNewKvno"
        Write-Host "Remote current-only keytab: $newCurrentOnlyPath"
        Write-Host "Remote active keytab mode:  transition"
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

        Promote-RemoteCurrentOnlyKeytab -RemoteCurrentOnlyKeytabPath ([string]$manifest.current.remoteCurrentOnly)
        Write-RemoteClientMetadata -Mode 'current-only' -CurrentKvno ([int]$manifest.current.kvno) -CurrentRotationId ([string]$manifest.current.rotationId)
        Test-ClientAuthPath -Label 'commit / current-only keytab'

        Remove-TrackedRemoteArtifact -RemotePath ([string]$manifest.previous.remoteCurrentOnly)

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
                remoteCurrentOnly = [string]$manifest.current.remoteCurrentOnly
                rotationId        = [string]$manifest.current.rotationId
            }
            previous          = $null
        }

        Save-Manifest -Path $ManifestPath -Data $finalManifest

        Write-Host ""
        Write-Host "Commit complete." -ForegroundColor Green
        Write-Host "Client active keytab is now current-only."
        Write-Host "Old generation removed from the active client keytab."
        Write-Host "Current KVNO:   $($finalManifest.current.kvno)"
        Write-Host "Remote keytab:  $($finalManifest.current.remoteCurrentOnly)"
        Write-Host ""
    }
}
