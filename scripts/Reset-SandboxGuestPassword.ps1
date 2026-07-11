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
        $secure = Read-Host "请输入来宾用户 '$GuestUserName' 的新密码（不会回显） / New password for guest user" -AsSecureString
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

    throw '错误：没有可用盘符可挂载来宾 Windows 卷。下一步：请释放一个盘符后重试，或手动检查已挂载 VHD。'
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
        throw "错误：无法解析已挂载 VHD 对应磁盘：$VhdPath。下一步：确认 VHD/AVHDX 路径有效且 Hyper-V 管理模块可用。"
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

    throw "错误：已挂载 VHD 中未找到 Windows SYSTEM hive：$VhdPath。下一步：确认选择的是 Windows 系统盘而不是数据盘。"
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
    `$result.message = '来宾账户密码已重置并启用。 / Guest account password reset and account enabled.'
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
            throw "错误：reg load 加载离线 SYSTEM hive 失败。下一步：确认 VHD 未被占用，并以管理员身份运行。英文输出：$load"
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

    throw "错误：VM '$VmName' 未在 $TimeoutSeconds 秒内进入 Running 状态。下一步：在 Hyper-V 管理器检查 VM 启动错误后重试。"
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

    throw "错误：PowerShell Direct 未在 $PowerShellDirectTimeoutSeconds 秒内接受重置后的凭据。下一步：确认 VM 已启动、用户 '$GuestUserName' 已启用、Hyper-V PowerShell Direct 可用。英文详情：$lastError"
}

function Update-CleanCheckpoint {
    $existing = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        $backupName = '{0}-before-password-reset-{1}' -f $CheckpointName, (Get-Date -Format 'yyyyMMdd-HHmmss')
        Rename-VMSnapshot -VMName $VmName -Name $CheckpointName -NewName $backupName -ErrorAction Stop
        Write-ResetInfo "已将旧 checkpoint '$CheckpointName' 重命名为 '$backupName'。 / Renamed old checkpoint."
    }

    Checkpoint-VM -Name $VmName -SnapshotName $CheckpointName | Out-Null
    Write-ResetInfo "已创建刷新后的 checkpoint '$CheckpointName'。 / Created refreshed checkpoint."
}

try {
    if (-not (Test-IsAdministrator)) {
        throw '错误：重置 Hyper-V 来宾密码需要宿主机管理员 PowerShell。下一步：以管理员身份打开 PowerShell 后重试。'
    }

    $credentialInput = Get-NewGuestPassword
    if ([string]::IsNullOrEmpty($credentialInput.Password)) {
        throw '错误：新来宾密码不能为空。下一步：重新运行并输入有效密码，或去掉 -PromptPassword 让脚本生成随机密码。'
    }

    $vm = Get-VM -Name $VmName -ErrorAction Stop
    if ($vm.State -ne 'Off') {
        if (-not $Force -and -not $PSCmdlet.ShouldProcess($VmName, '密码重置前关闭 VM / Turn off VM before password reset')) { return }
        Stop-VM -Name $VmName -TurnOff -Force -ErrorAction Stop
    }

    if (-not $SkipCheckpointRestore) {
        $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction Stop
        if ($Force -or $PSCmdlet.ShouldProcess($VmName, "注入密码重置前还原 checkpoint '$CheckpointName' / Restore checkpoint before password reset")) {
            Restore-VMSnapshot -VMName $VmName -Name $CheckpointName -Confirm:$false -ErrorAction Stop
            Write-ResetInfo "已还原 checkpoint '$CheckpointName'。 / Restored checkpoint."
        }
    }

    $drive = Get-VMHardDiskDrive -VMName $VmName | Select-Object -First 1
    if ($null -eq $drive -or [string]::IsNullOrWhiteSpace($drive.Path)) {
        throw "错误：VM '$VmName' 没有可解析的硬盘路径。下一步：在 Hyper-V 中确认 VM 已连接 Windows 系统盘。"
    }

    $vhdPath = $drive.Path
    Write-ResetInfo "正在向 VHD 注入一次性密码重置服务：$vhdPath / Injecting one-shot reset service."
    try {
        $mountedVolume = Mount-GuestWindowsVolume -VhdPath $vhdPath
        Inject-PasswordResetService -WindowsRoot $mountedVolume.Root -SystemHive $mountedVolume.SystemHive -Password $credentialInput.Password
    }
    finally {
        Dismount-GuestWindowsVolume -VhdPath $vhdPath
    }

    if ($Force -or $PSCmdlet.ShouldProcess($VmName, '启动 VM 运行一次性密码重置服务 / Boot VM to run reset service')) {
        Start-VM -Name $VmName -ErrorAction Stop
        Wait-VMRunning -TimeoutSeconds $BootTimeoutSeconds
        Write-ResetInfo 'VM 已运行；正在等待 PowerShell Direct 使用重置后的凭据连通。 / Waiting for PowerShell Direct.'
        $probe = Wait-PowerShellDirectCredential -Password $credentialInput.Password
        Write-ResetInfo "PowerShell Direct 已用重置后的凭据验证通过。来宾身份：$($probe.userName) / PowerShell Direct validated."

        Save-HostSecret -Password $credentialInput.Password -PasswordSource $credentialInput.Source
        Write-ResetInfo "已把 '$SecretName' 保存到当前 Process/User 环境和 DPAPI 备份；secret 值未打印。 / Secret stored; value was not printed."

        $secure = ConvertTo-SecureString $credentialInput.Password -AsPlainText -Force
        $credential = [pscredential]::new($GuestUserName, $secure)
        Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock {
            sc.exe delete KSwordSandboxPasswordReset | Out-Null
            Remove-Item -LiteralPath 'C:\KSwordSandbox\HostInjected\ResetSandboxUser.ps1' -Force -ErrorAction SilentlyContinue
        } -ErrorAction SilentlyContinue | Out-Null

        Stop-VM -Name $VmName -TurnOff -Force -ErrorAction Stop
        Write-ResetInfo '凭据验证后已停止 VM。 / VM stopped after credential validation.'

        if (-not $SkipCheckpointRefresh) {
            if ($Force -or $PSCmdlet.ShouldProcess($VmName, "用重置后的密码刷新 checkpoint '$CheckpointName' / Refresh checkpoint with reset password")) {
                Update-CleanCheckpoint
            }
        }
    }

    Write-ResetInfo '来宾密码重置完成；secret 值未打印。 / Guest password reset completed.'
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
    Write-Error "失败：guest password reset 失败。下一步：查看错误，确认管理员权限、VM/Checkpoint 名称、VHD 路径和 PowerShell Direct 后重试。英文详情：$($_.Exception.Message) $($_.ScriptStackTrace)"
    exit 1
}
