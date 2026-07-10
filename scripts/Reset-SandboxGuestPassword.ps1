<#
.SYNOPSIS
Resets the KSwordSandbox Windows guest account password without knowing the old password.

.DESCRIPTION
This host-side script works against an offline Hyper-V Windows 10 guest disk. It
restores the configured clean checkpoint, mounts the active VHDX/AVHDX, injects a
one-shot LocalSystem service into the offline SYSTEM hive, boots the VM so the
service resets the guest user password, validates PowerShell Direct with the new
secret, stores the same secret in the host user environment/DPAPI backup, and
optionally refreshes the clean checkpoint so future sandbox runs keep working.

The generated password is never printed.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$VmName = 'KSwordSandbox-Win10-Golden',
    [string]$CheckpointName = 'Clean',
    [string]$GuestUserName = 'SandboxUser',
    [string]$SecretName = 'KSWORDBOX_GUEST_PASSWORD',
    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox',
    [string]$GuestWorkingDirectory = 'C:\KSwordSandbox',
    [string]$NewPassword = '',
    [switch]$PromptPassword,
    [switch]$SkipCheckpointRefresh,
    [switch]$SkipCheckpointRestore,
    [switch]$Force,
    [int]$BootTimeoutSeconds = 240,
    [int]$PowerShellDirectTimeoutSeconds = 240
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:StateDirectory = Join-Path $env:ProgramData 'KSwordSandbox'
$script:InstallStatePath = Join-Path $script:StateDirectory 'install-state.json'
$script:SecretBackupPath = Join-Path $script:StateDirectory 'guest-password.dpapi'
$script:ServiceName = 'KSwordSandboxPasswordReset'
$script:OfflineHiveName = 'KSwordSandboxOfflineSYSTEM'

function Write-ResetInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[guest-password-reset] $Message"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RandomPassword {
    param([int]$Length = 28)

    $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower = 'abcdefghijkmnopqrstuvwxyz'
    $digit = '23456789'
    $symbol = '!@#%_-+=' 
    $alphabet = $upper + $lower + $digit + $symbol
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = [byte[]]::new($Length)
        $rng.GetBytes($bytes)
        $chars = New-Object System.Collections.Generic.List[char]
        [void]$chars.Add($upper[$bytes[0] % $upper.Length])
        [void]$chars.Add($lower[$bytes[1] % $lower.Length])
        [void]$chars.Add($digit[$bytes[2] % $digit.Length])
        [void]$chars.Add($symbol[$bytes[3] % $symbol.Length])
        for ($index = 4; $index -lt $Length; $index++) {
            [void]$chars.Add($alphabet[$bytes[$index] % $alphabet.Length])
        }

        for ($index = 0; $index -lt $chars.Count; $index++) {
            $swapIndex = $bytes[$index % $bytes.Length] % $chars.Count
            $tmp = $chars[$index]
            $chars[$index] = $chars[$swapIndex]
            $chars[$swapIndex] = $tmp
        }

        return -join $chars.ToArray()
    }
    finally {
        $rng.Dispose()
    }
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory)][securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Get-NewGuestPassword {
    if (-not [string]::IsNullOrEmpty($NewPassword)) {
        return [pscustomobject]@{ Password = $NewPassword; Source = 'provided' }
    }

    if ($PromptPassword) {
        $secure = Read-Host "New password for guest user '$GuestUserName'" -AsSecureString
        return [pscustomobject]@{ Password = (ConvertFrom-SecureStringToPlainText -SecureString $secure); Source = 'prompt' }
    }

    return [pscustomobject]@{ Password = (New-RandomPassword); Source = 'generated' }
}

function Save-HostSecret {
    param(
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$PasswordSource
    )

    New-Item -ItemType Directory -Path $script:StateDirectory -Force | Out-Null
    [Environment]::SetEnvironmentVariable($SecretName, $Password, 'Process')
    [Environment]::SetEnvironmentVariable($SecretName, $Password, 'User')

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $secure | ConvertFrom-SecureString | Set-Content -LiteralPath $script:SecretBackupPath -Encoding ASCII

    $state = [ordered]@{
        installStateVersion = 2
        action = 'guest-vm-password-reset'
        updatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        guestUserName = $GuestUserName
        secretName = $SecretName
        runtimeRoot = $RuntimeRoot
        guestPayloadRoot = Join-Path $RuntimeRoot 'payload\guest-tools'
        passwordSource = "guest-vm-reset-$PasswordSource"
        persistedToUserEnvironment = $true
        persistedToCurrentProcess = $true
        dpapiBackupPath = $script:SecretBackupPath
        secretValuePrinted = $false
        vmName = $VmName
        checkpointName = $CheckpointName
        guestWorkingDirectory = $GuestWorkingDirectory
        localConfigPath = Join-Path $RuntimeRoot 'config\sandbox.local.json'
        webConfigPathEnvironmentName = 'Sandbox__ConfigPath'
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:InstallStatePath -Encoding UTF8
}

function Get-AvailableDriveLetter {
    $used = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object { [string]$_.DriveLetter })
    foreach ($letter in 'Z','Y','X','W','V','U','T','S','R','Q','P','O','N','M','L','K','J') {
        if ($used -notcontains $letter) {
            return $letter
        }
    }

    throw 'No available drive letter was found for mounting the guest Windows volume.'
}

function Get-DiskForVhd {
    param([Parameter(Mandatory)][string]$VhdPath)

    try {
        $mounted = Mount-VHD -Path $VhdPath -PassThru -ErrorAction Stop
        $script:MountedVhdHere = $true
        return ($mounted | Get-Disk)
    }
    catch {
        $message = $_.Exception.Message
        if ($message -notmatch 'already' -and $message -notmatch '正在使用' -and $message -notmatch 'attached') {
            throw
        }

        $image = Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
        return ($image | Get-Disk)
    }
}

function Mount-GuestWindowsVolume {
    param([Parameter(Mandatory)][string]$VhdPath)

    $script:MountedVhdHere = $false
    $script:TemporaryAccessPaths = New-Object System.Collections.Generic.List[object]
    $disk = Get-DiskForVhd -VhdPath $VhdPath
    if ($null -eq $disk) {
        throw "Could not resolve mounted disk for VHD: $VhdPath"
    }

    foreach ($partition in @(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Type -ne 'Reserved' })) {
        $letter = $partition.DriveLetter
        $letterText = [string]$letter
        $hasUsableLetter = (-not [string]::IsNullOrWhiteSpace($letterText)) -and ($letterText[0] -ne [char]0)
        if (-not $hasUsableLetter) {
            $letter = Get-AvailableDriveLetter
            $accessPath = "$letter`:"
            Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $accessPath -ErrorAction Stop
            [void]$script:TemporaryAccessPaths.Add([pscustomobject]@{
                DiskNumber = $disk.Number
                PartitionNumber = $partition.PartitionNumber
                AccessPath = $accessPath
            })
        }

        $root = "$letter`:"
        $systemHive = Join-Path $root 'Windows\System32\Config\SYSTEM'
        if (Test-Path -LiteralPath $systemHive -PathType Leaf) {
            return [pscustomobject]@{
                DiskNumber = $disk.Number
                Root = $root
                SystemHive = $systemHive
            }
        }
    }

    throw "Mounted VHD did not contain a Windows SYSTEM hive: $VhdPath"
}

function Dismount-GuestWindowsVolume {
    param([Parameter(Mandatory)][string]$VhdPath)

    if ($script:TemporaryAccessPaths) {
        foreach ($entry in @($script:TemporaryAccessPaths)) {
            Remove-PartitionAccessPath -DiskNumber $entry.DiskNumber -PartitionNumber $entry.PartitionNumber -AccessPath $entry.AccessPath -ErrorAction SilentlyContinue
        }
    }

    if ($script:MountedVhdHere) {
        Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue
    }
}

function ConvertTo-PowerShellSingleQuotedLiteral {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { $Text = '' }
    return "'" + $Text.Replace("'", "''") + "'"
}

function New-GuestResetScriptText {
    param([Parameter(Mandatory)][string]$Password)

    $quotedUser = ConvertTo-PowerShellSingleQuotedLiteral -Text $GuestUserName
    $quotedPassword = ConvertTo-PowerShellSingleQuotedLiteral -Text $Password
    $quotedService = ConvertTo-PowerShellSingleQuotedLiteral -Text $script:ServiceName

    return @"
`$ErrorActionPreference = 'Continue'
`$resultPath = 'C:\KSwordSandbox\HostInjected\password-reset-result.json'
New-Item -ItemType Directory -Path (Split-Path -Parent `$resultPath) -Force | Out-Null
`$result = [ordered]@{
    kind = 'KSwordSandbox.GuestPasswordResetResult'
    userName = $quotedUser
    startedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    success = `$false
    message = ''
    secretValuePrinted = `$false
}
try {
    `$userName = $quotedUser
    `$password = $quotedPassword
    `$secure = ConvertTo-SecureString `$password -AsPlainText -Force
    `$existing = Get-LocalUser -Name `$userName -ErrorAction SilentlyContinue
    if (`$null -eq `$existing) {
        New-LocalUser -Name `$userName -Password `$secure -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
    }
    else {
        Set-LocalUser -Name `$userName -Password `$secure -ErrorAction Stop
        Enable-LocalUser -Name `$userName -ErrorAction SilentlyContinue
    }

    `$adminGroup = Get-LocalGroup | Where-Object { `$_.SID -eq 'S-1-5-32-544' } | Select-Object -First 1
    if (`$null -ne `$adminGroup) {
        try { Add-LocalGroupMember -Group `$adminGroup.Name -Member `$userName -ErrorAction Stop } catch { }
    }

    try { Set-LocalUser -Name `$userName -PasswordNeverExpires `$true -ErrorAction SilentlyContinue } catch { }
    `$result.success = `$true
    `$result.message = 'Guest account password reset and account enabled.'
}
catch {
    `$result.success = `$false
    `$result.message = `$_.Exception.Message
}
finally {
    `$result.completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    `$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath `$resultPath -Encoding UTF8
    try { sc.exe delete $quotedService | Out-Null } catch { }
    try { Remove-Item -LiteralPath `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue } catch { }
}
"@
}

function Inject-PasswordResetService {
    param(
        [Parameter(Mandatory)][string]$WindowsRoot,
        [Parameter(Mandatory)][string]$SystemHive,
        [Parameter(Mandatory)][string]$Password
    )

    $guestRelativeDirectory = 'KSwordSandbox\HostInjected'
    $hostInjectedDirectory = Join-Path $WindowsRoot $guestRelativeDirectory
    New-Item -ItemType Directory -Path $hostInjectedDirectory -Force | Out-Null
    $hostScriptPath = Join-Path $hostInjectedDirectory 'ResetSandboxUser.ps1'
    New-GuestResetScriptText -Password $Password | Set-Content -LiteralPath $hostScriptPath -Encoding UTF8

    $offlineHivePath = "HKLM:\$script:OfflineHiveName"
    try {
        & reg.exe unload "HKLM\$script:OfflineHiveName" *> $null
    }
    catch {
    }
    $loaded = $false
    try {
        $load = & reg.exe load "HKLM\$script:OfflineHiveName" $SystemHive 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "reg load failed: $load"
        }
        $loaded = $true

        $select = Get-ItemProperty -LiteralPath (Join-Path $offlineHivePath 'Select')
        $controlSet = 'ControlSet{0:D3}' -f [int]$select.Current
        $servicePath = Join-Path $offlineHivePath "$controlSet\Services\$script:ServiceName"
        New-Item -Path $servicePath -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'Type' -PropertyType DWord -Value 16 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'Start' -PropertyType DWord -Value 2 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'ErrorControl' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'DelayedAutoStart' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'DisplayName' -PropertyType String -Value 'KSwordSandbox one-shot password reset' -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'ObjectName' -PropertyType String -Value 'LocalSystem' -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'ImagePath' -PropertyType ExpandString -Value '%SystemRoot%\System32\cmd.exe /c ""%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\KSwordSandbox\HostInjected\ResetSandboxUser.ps1" >> "C:\KSwordSandbox\HostInjected\reset-service.log" 2>&1"' -Force | Out-Null
    }
    finally {
        if ($loaded) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            reg.exe unload "HKLM\$script:OfflineHiveName" | Out-Null
        }
    }
}

function Wait-VMRunning {
    param([int]$TimeoutSeconds)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $vm = Get-VM -Name $VmName -ErrorAction Stop
        if ($vm.State -eq 'Running') {
            return
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "VM '$VmName' did not reach Running state within $TimeoutSeconds seconds."
}

function Wait-PowerShellDirectCredential {
    param([Parameter(Mandatory)][string]$Password)

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $credential = [pscredential]::new($GuestUserName, $secure)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($PowerShellDirectTimeoutSeconds)
    $lastError = ''
    do {
        try {
            $probe = Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
                [pscustomobject]@{
                    computerName = $env:COMPUTERNAME
                    userName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    resetMarkerExists = Test-Path -LiteralPath 'C:\KSwordSandbox\HostInjected\password-reset-result.json'
                }
            } -ErrorAction Stop
            return $probe
        }
        catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds 3
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "PowerShell Direct did not accept the reset credential within $PowerShellDirectTimeoutSeconds seconds. Last error: $lastError"
}

function Update-CleanCheckpoint {
    $existing = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $backupName = '{0}-before-password-reset-{1}' -f $CheckpointName, (Get-Date -Format 'yyyyMMdd-HHmmss')
        Rename-VMSnapshot -VMName $VmName -Name $CheckpointName -NewName $backupName -ErrorAction Stop
        Write-ResetInfo "Renamed old checkpoint '$CheckpointName' to '$backupName'."
    }

    Checkpoint-VM -Name $VmName -SnapshotName $CheckpointName | Out-Null
    Write-ResetInfo "Created refreshed checkpoint '$CheckpointName'."
}

try {
    if (-not (Test-IsAdministrator)) {
        throw 'Resetting a Hyper-V guest password requires an elevated host PowerShell session.'
    }

    $credentialInput = Get-NewGuestPassword
    if ([string]::IsNullOrEmpty($credentialInput.Password)) {
        throw 'New guest password must not be empty.'
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne 'Off') {
        if (-not $Force -and -not $PSCmdlet.ShouldProcess($VmName, 'Turn off VM before password reset')) { return }
        Stop-VM -Name $VmName -TurnOff -Force -ErrorAction Stop
    }

    if (-not $SkipCheckpointRestore) {
        $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction Stop
        if ($Force -or $PSCmdlet.ShouldProcess($VmName, "Restore checkpoint '$CheckpointName' before injecting password reset")) {
            Restore-VMSnapshot -VMName $VmName -Name $CheckpointName -Confirm:$false -ErrorAction Stop
            Write-ResetInfo "Restored checkpoint '$CheckpointName'."
        }
    }

    $drive = Get-VMHardDiskDrive -VMName $VmName | Select-Object -First 1
    if ($null -eq $drive -or [string]::IsNullOrWhiteSpace($drive.Path)) {
        throw "VM '$VmName' does not have a resolvable hard disk path."
    }

    $vhdPath = $drive.Path
    Write-ResetInfo "Injecting one-shot reset service into: $vhdPath"
    try {
        $mountedVolume = Mount-GuestWindowsVolume -VhdPath $vhdPath
        Inject-PasswordResetService -WindowsRoot $mountedVolume.Root -SystemHive $mountedVolume.SystemHive -Password $credentialInput.Password
    }
    finally {
        Dismount-GuestWindowsVolume -VhdPath $vhdPath
    }

    if ($Force -or $PSCmdlet.ShouldProcess($VmName, 'Boot VM to run one-shot password reset service')) {
        Start-VM -Name $VmName -ErrorAction Stop
        Wait-VMRunning -TimeoutSeconds $BootTimeoutSeconds
        Write-ResetInfo 'VM is running; waiting for PowerShell Direct with the reset credential.'
        $probe = Wait-PowerShellDirectCredential -Password $credentialInput.Password
        Write-ResetInfo "PowerShell Direct validated with reset credential. Guest identity: $($probe.userName)"

        Save-HostSecret -Password $credentialInput.Password -PasswordSource $credentialInput.Source
        Write-ResetInfo "Stored '$SecretName' in current process/User environment and DPAPI backup. Secret value was not printed."

        $secure = ConvertTo-SecureString $credentialInput.Password -AsPlainText -Force
        $credential = [pscredential]::new($GuestUserName, $secure)
        Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
            sc.exe delete KSwordSandboxPasswordReset | Out-Null
            Remove-Item -LiteralPath 'C:\KSwordSandbox\HostInjected\ResetSandboxUser.ps1' -Force -ErrorAction SilentlyContinue
        } -ErrorAction SilentlyContinue | Out-Null

        Stop-VM -Name $VmName -TurnOff -Force -ErrorAction Stop
        Write-ResetInfo 'VM stopped after credential validation.'

        if (-not $SkipCheckpointRefresh) {
            if ($Force -or $PSCmdlet.ShouldProcess($VmName, "Refresh checkpoint '$CheckpointName' with the reset password")) {
                Update-CleanCheckpoint
            }
        }
    }

    Write-ResetInfo 'Guest password reset completed. Secret value was not printed.'
    Write-Output ([pscustomobject][ordered]@{
        VmName = $VmName
        CheckpointName = $CheckpointName
        GuestUserName = $GuestUserName
        SecretName = $SecretName
        SecretStored = $true
        SecretValuePrinted = $false
        CheckpointRefreshed = (-not [bool]$SkipCheckpointRefresh)
    })
}
catch {
    Write-Error "FAIL: guest password reset failed. $($_.Exception.Message) $($_.ScriptStackTrace)"
    exit 1
}
