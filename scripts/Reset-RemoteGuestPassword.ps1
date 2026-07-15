<#
.SYNOPSIS
Rotates or recovers the configured VMware/QEMU guest password and creates a new clean baseline.

.DESCRIPTION
The current and replacement passwords are read only from inherited Process/User/Machine
environment variables. QEMU can also recover an unknown current password by converting the
selected clean baseline to a temporary VHDX and injecting a one-shot LocalSystem reset
service. Password values are never accepted as command-line parameters or written to output.
The old snapshot or disk image is preserved; a successful run returns the replacement
snapshot or disk path for the parent installer to commit to local config.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('VMware', 'Qemu')]
    [string]$VirtualizationProvider,

    [Parameter(Mandatory)][string]$VmName,
    [Parameter(Mandatory)][string]$CheckpointName,
    [Parameter(Mandatory)][string]$GuestUserName,
    [string]$CurrentPasswordSecretName = '',
    [Parameter(Mandatory)][string]$NewPasswordSecretName,
    [switch]$OfflineRecovery,
    [string]$GuestRemotingAddress = '',
    [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')][string]$GuestRemotingAddressMode = 'Configured',
    [ValidateRange(0, 65535)][int]$GuestRemotingPort = 0,
    [switch]$GuestRemotingUseSsl,
    [switch]$GuestRemotingSkipCertificateChecks,
    [ValidateSet('Negotiate', 'Basic', 'CredSSP')][string]$GuestRemotingAuthentication = 'Negotiate',
    [ValidateRange(1, 7200)][int]$GuestReadyTimeoutSeconds = 240,

    [string]$VMwareVmxPath = '',
    [string]$VMwareVmrunPath = 'vmrun.exe',
    [ValidateSet('ws')][string]$VMwareVmType = 'ws',
    [switch]$VMwareHeadless,

    [string]$QemuDiskImagePath = '',
    [string]$QemuSystemPath = 'qemu-system-x86_64.exe',
    [string]$QemuImgPath = 'qemu-img.exe',
    [ValidateSet('qcow2', 'raw', 'vhdx', 'vmdk')][string]$QemuDiskFormat = 'qcow2',
    [ValidateSet('virtio', 'ide', 'scsi')][string]$QemuDiskInterface = 'virtio',
    [switch]$QemuUseOverlayDisk,
    [ValidateRange(256, 1048576)][int]$QemuMemoryMegabytes = 4096,
    [switch]$QemuHeadless,
    [string]$QemuAdditionalArgumentsBase64 = '',
    [Parameter(Mandatory)][string]$RuntimeRoot,

    [switch]$Force,
    [switch]$Json
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:ValidatedQemuAdditionalArguments = @()
$script:EffectiveGuestRemotingAddress = $GuestRemotingAddress
$script:EffectiveGuestRemotingPort = $GuestRemotingPort
$script:GuestRemotingAddressSource = 'configured'

function Get-SecretValue {
    param([Parameter(Mandatory)][string]$Name)

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    throw "未找到密码环境变量 '$Name'；值不会从命令行读取。 / Password environment variable was not found."
}

function New-PasswordCredential {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$Password
    )

    $securePassword = [System.Security.SecureString]::new()
    foreach ($character in $Password.ToCharArray()) {
        $securePassword.AppendChar($character)
    }
    $securePassword.MakeReadOnly()
    return [pscredential]::new($UserName, $securePassword)
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Executable {
    param(
        [Parameter(Mandatory)][string]$ConfiguredPath,
        [Parameter(Mandatory)][string]$DisplayName
    )

    $command = Get-Command -Name $ConfiguredPath -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        return [string]$command.Source
    }
    if (Test-Path -LiteralPath $ConfiguredPath -PathType Leaf) {
        return (Resolve-Path -LiteralPath $ConfiguredPath).ProviderPath
    }

    throw "$DisplayName executable was not found: $ConfiguredPath"
}

function Select-VMwareGuestAddress {
    param([AllowEmptyCollection()][object[]]$Output = @())

    $candidates = @($Output | ForEach-Object {
            $candidateText = ([string]$_).Trim()
            $candidateAddress = $null
            if (-not [string]::IsNullOrWhiteSpace($candidateText) -and
                [Net.IPAddress]::TryParse($candidateText, [ref]$candidateAddress) -and
                -not [Net.IPAddress]::IsLoopback($candidateAddress) -and
                -not $candidateAddress.IsIPv6LinkLocal -and
                -not $candidateText.StartsWith('169.254.', [StringComparison]::Ordinal)) {
                [pscustomobject]@{ Text = $candidateText; Address = $candidateAddress }
            }
        })
    $preferred = $candidates | Where-Object {
        $_.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
    } | Select-Object -First 1
    if ($null -eq $preferred) { $preferred = $candidates | Select-Object -First 1 }
    return if ($null -eq $preferred) { '' } else { [string]$preferred.Text }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Operation
    )

    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Operation failed with exit code $exitCode. $($output -join ' ')"
    }
    return @($output)
}

function New-RemoteSession {
    param([Parameter(Mandatory)][pscredential]$Credential)

    $parameters = @{
        ComputerName = $script:EffectiveGuestRemotingAddress
        Credential = $Credential
        Authentication = $GuestRemotingAuthentication
        ErrorAction = 'Stop'
    }
    if ($script:EffectiveGuestRemotingPort -gt 0) { $parameters['Port'] = $script:EffectiveGuestRemotingPort }
    if ($GuestRemotingUseSsl) { $parameters['UseSSL'] = $true }
    if ($GuestRemotingSkipCertificateChecks) {
        $parameters['SessionOption'] = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    }
    return New-PSSession @parameters
}

function Wait-RemoteCredential {
    param([Parameter(Mandatory)][pscredential]$Credential)

    $deadline = (Get-Date).AddSeconds($GuestReadyTimeoutSeconds)
    $lastError = ''
    do {
        $session = $null
        try {
            $session = New-RemoteSession -Credential $Credential
            Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop | Out-Null
            return
        }
        catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds 3
        }
        finally {
            if ($null -ne $session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
    } while ((Get-Date) -lt $deadline)

    throw "WinRM did not accept the credential within $GuestReadyTimeoutSeconds seconds. Last error: $lastError"
}

function Confirm-RemoteOfflinePasswordResetCleanup {
    param([Parameter(Mandatory)][pscredential]$Credential)

    $deadline = (Get-Date).AddSeconds($GuestReadyTimeoutSeconds)
    $lastError = ''
    do {
        $session = $null
        try {
            $session = New-RemoteSession -Credential $Credential
            $probe = Invoke-Command -Session $session -ScriptBlock {
                $resultPath = 'C:\KSwordSandbox\HostInjected\password-reset-result.json'
                $scriptPath = 'C:\KSwordSandbox\HostInjected\ResetSandboxUser.ps1'
                if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
                    return [pscustomobject]@{ Ready = $false; Success = $false; Message = 'The one-shot password-reset result is not present yet.'; ScriptRemoved = $false }
                }

                try {
                    $resetResult = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    return [pscustomobject]@{ Ready = $false; Success = $false; Message = "The one-shot password-reset result is not readable yet: $($_.Exception.Message)"; ScriptRemoved = $false }
                }
                if (-not [bool]$resetResult.success) {
                    return [pscustomobject]@{ Ready = $true; Success = $false; Message = [string]$resetResult.message; ScriptRemoved = $false }
                }

                sc.exe delete KSwordSandboxPasswordReset | Out-Null
                Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
                return [pscustomobject]@{
                    Ready = $true
                    Success = $true
                    Message = [string]$resetResult.message
                    ScriptRemoved = -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)
                }
            } -ErrorAction Stop

            if ([bool]$probe.Ready -and -not [bool]$probe.Success) {
                $lastError = "The one-shot guest password-reset service reported failure: $($probe.Message)"
                break
            }
            if ([bool]$probe.Ready -and [bool]$probe.Success -and [bool]$probe.ScriptRemoved) {
                return
            }
            $lastError = [string]$probe.Message
        }
        catch {
            $lastError = $_.Exception.Message
        }
        finally {
            if ($null -ne $session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "The offline guest password-reset service cleanup was not confirmed within $GuestReadyTimeoutSeconds seconds. Last error: $lastError"
}

function Set-RemoteLocalPassword {
    param(
        [Parameter(Mandatory)][pscredential]$CurrentCredential,
        [Parameter(Mandatory)][string]$NewPassword
    )

    $session = New-RemoteSession -Credential $CurrentCredential
    try {
        Invoke-Command -Session $session -ScriptBlock {
            param([string]$RequestedUserName, [string]$ReplacementPassword)

            $localUserName = ($RequestedUserName -split '\\')[-1]
            if ([string]::IsNullOrWhiteSpace($localUserName)) {
                throw 'Guest local user name is empty.'
            }
            $account = [ADSI]("WinNT://./{0},user" -f $localUserName)
            $account.SetPassword($ReplacementPassword)
            $account.SetInfo()
        } -ArgumentList $GuestUserName, $NewPassword -ErrorAction Stop | Out-Null
    }
    finally {
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
}

function Get-QemuAdditionalArguments {
    if ([string]::IsNullOrWhiteSpace($QemuAdditionalArgumentsBase64)) { return @() }

    try {
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($QemuAdditionalArgumentsBase64))
        return @($json | ConvertFrom-Json | ForEach-Object { [string]$_ })
    }
    catch {
        throw "QEMU additional arguments metadata is invalid: $($_.Exception.Message)"
    }
}

function Assert-QemuManagedAdditionalArguments {
    param(
        [AllowEmptyCollection()][string[]]$Arguments = @(),
        [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')][string]$GuestAddressMode = 'Configured'
    )

    for ($index = 0; $index -lt @($Arguments).Count; $index++) {
        $argument = ([string]$Arguments[$index]).Trim()
        $option = @($argument -split '=', 2)[0].Trim()
        if ($option -cin @('-name', '-m', '-memory', '-pidfile', '-display')) {
            throw "QEMU additional arguments cannot set '$option'; VM identity, memory, PID ownership, and display mode are provider-managed."
        }
        if ($argument -cin @('-daemonize', '-snapshot', '-nographic', '-curses', '-S')) {
            throw "QEMU additional arguments cannot contain '$argument' because it bypasses lifecycle, baseline, or console guarantees."
        }

        $driveValue = $null
        if ($argument -ceq '-drive') {
            if ($index + 1 -ge @($Arguments).Count -or [string]::IsNullOrWhiteSpace([string]$Arguments[$index + 1])) {
                throw "QEMU additional arguments '-drive' requires a non-empty drive value."
            }
            $driveValue = [string]$Arguments[$index + 1]
        }
        elseif ($argument.StartsWith('-drive=', [StringComparison]::Ordinal)) {
            $driveValue = $argument.Substring('-drive='.Length)
        }
        if ($null -ne $driveValue -and @($driveValue -split ',' | Where-Object {
                    ([string]$_).Trim().Equals('id=ksword-disk', [StringComparison]::OrdinalIgnoreCase)
                }).Count -gt 0) {
            throw 'QEMU additional arguments cannot define a second drive with id=ksword-disk.'
        }
        if ($argument.IndexOf('id=ksword-scsi', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $argument.IndexOf('bus=ksword-scsi.0', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $argument.IndexOf('drive=ksword-disk', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'QEMU additional arguments cannot reuse id=ksword-scsi, bus=ksword-scsi.0, or drive=ksword-disk; the provider owns the managed SCSI topology.'
        }
        if ($GuestAddressMode -eq 'QemuUserNat' -and
            ($argument.IndexOf('id=ksword-net', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
             $argument.IndexOf('netdev=ksword-net', [StringComparison]::OrdinalIgnoreCase) -ge 0)) {
            throw 'QemuUserNat cannot reuse id/netdev=ksword-net; the provider owns that adapter and its WinRM forwarding.'
        }
    }
}

function Test-QemuWhpxAdditionalArguments {
    param(
        [AllowEmptyCollection()][string[]]$Arguments = @(),
        [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')][string]$GuestAddressMode = 'Configured'
    )

    Assert-QemuManagedAdditionalArguments -Arguments $Arguments -GuestAddressMode $GuestAddressMode
    $acceleratorConfigured = $false
    for ($index = 0; $index -lt @($Arguments).Count; $index++) {
        $argument = ([string]$Arguments[$index]).Trim()
        $acceleratorValue = $null
        if ($argument.Equals('-accel', [StringComparison]::OrdinalIgnoreCase)) {
            $index++
            if ($index -ge @($Arguments).Count) {
                throw "QEMU additional arguments '-accel' requires 'whpx'."
            }
            $acceleratorValue = [string]$Arguments[$index]
        }
        elseif ($argument.StartsWith('-accel=', [StringComparison]::OrdinalIgnoreCase)) {
            $acceleratorValue = $argument.Substring('-accel='.Length)
        }
        else {
            $machineValue = $null
            if ($argument.Equals('-machine', [StringComparison]::OrdinalIgnoreCase) -or
                $argument.Equals('-M', [StringComparison]::Ordinal)) {
                if ($index + 1 -ge @($Arguments).Count) {
                    throw "QEMU additional arguments '$argument' requires a machine value."
                }
                $machineValue = [string]$Arguments[$index + 1]
            }
            elseif ($argument.StartsWith('-machine=', [StringComparison]::OrdinalIgnoreCase)) {
                $machineValue = $argument.Substring('-machine='.Length)
            }
            elseif ($argument.StartsWith('-M=', [StringComparison]::Ordinal)) {
                $machineValue = $argument.Substring('-M='.Length)
            }
            if (-not [string]::IsNullOrWhiteSpace($machineValue)) {
                $acceleratorPart = @($machineValue -split ',' | Where-Object {
                        ([string]$_).Trim().StartsWith('accel=', [StringComparison]::OrdinalIgnoreCase)
                    } | Select-Object -First 1)
                if ($acceleratorPart.Count -gt 0) {
                    $acceleratorValue = ([string]$acceleratorPart[0]).Trim().Substring('accel='.Length)
                }
            }
            elseif ($argument.StartsWith('-machine=', [StringComparison]::OrdinalIgnoreCase) -or
                $argument.StartsWith('-M=', [StringComparison]::Ordinal)) {
                throw "QEMU additional arguments '$argument' requires a machine value."
            }
        }

        if ($null -eq $acceleratorValue) { continue }
        $accelerator = @(([string]$acceleratorValue) -split ',', 2)[0].Trim()
        if (-not $accelerator.Equals('whpx', [StringComparison]::OrdinalIgnoreCase)) {
            throw "QEMU accelerator '$accelerator' is not supported for Hyper-V-equivalent Windows password reset; use '-accel whpx'."
        }
        $acceleratorConfigured = $true
    }

    return $acceleratorConfigured
}

function Escape-QemuDriveOptionValue {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Replace(',', ',,')
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)

    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Stop-ProcessBounded {
    param([AllowNull()][System.Diagnostics.Process]$Process)

    if ($null -eq $Process) { return }
    try { $Process.Refresh() } catch { return }
    if ($Process.HasExited) { return }

    Stop-Process -Id $Process.Id -Force -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Process -Id $Process.Id -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    if (Get-Process -Id $Process.Id -ErrorAction SilentlyContinue) {
        throw "Process $($Process.Id) did not exit within 30 seconds."
    }
}

function Stop-QemuUsingDisk {
    param(
        [Parameter(Mandatory)][string]$QemuSystem,
        [Parameter(Mandatory)][string]$DiskPath
    )

    $resolvedDisk = [IO.Path]::GetFullPath($DiskPath)
    $resolvedDiskArgument = Escape-QemuDriveOptionValue -Value $resolvedDisk
    $expectedName = [IO.Path]::GetFileName($QemuSystem)
    $expectedExecutablePath = [IO.Path]::GetFullPath($QemuSystem)
    $qemuProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            ([string]$_.Name).Equals($expectedName, [StringComparison]::OrdinalIgnoreCase)
        })
    $stoppedPids = [System.Collections.Generic.HashSet[int]]::new()
    $vmsRoot = [IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'vms'))

    if (Test-Path -LiteralPath $vmsRoot -PathType Container) {
        foreach ($pidFile in @(Get-ChildItem -LiteralPath $vmsRoot -Filter 'qemu.pid' -File -Recurse -ErrorAction SilentlyContinue)) {
            $pidText = ([string](Get-Content -LiteralPath $pidFile.FullName -Raw -ErrorAction SilentlyContinue)).Trim()
            $candidatePid = 0
            if (-not [int]::TryParse($pidText, [ref]$candidatePid) -or $candidatePid -le 0) {
                throw "Invalid QEMU pid marker '$($pidFile.FullName)'; password reset stopped before changing the baseline."
            }

            $candidate = $qemuProcesses | Where-Object { [int]$_.ProcessId -eq $candidatePid } | Select-Object -First 1
            if ($null -eq $candidate) {
                Remove-Item -LiteralPath (Split-Path -Parent $pidFile.FullName) -Recurse -Force -ErrorAction SilentlyContinue
                continue
            }

            $markerWrittenUtc = (Get-Item -LiteralPath $pidFile.FullName -ErrorAction Stop).LastWriteTimeUtc
            $processStartedUtc = ([datetime]$candidate.CreationDate).ToUniversalTime()
            if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or
                $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) {
                throw "QEMU pid marker '$($pidFile.FullName)' points to reused pid $candidatePid; password reset stopped because the process instance start time does not match the marker."
            }

            $jobRoot = Split-Path -Parent $pidFile.FullName
            $commandLine = [string]$candidate.CommandLine
            if ([string]::IsNullOrWhiteSpace($commandLine)) {
                throw "Cannot inspect QEMU process $candidatePid from pid marker '$($pidFile.FullName)'; password reset stopped before changing the baseline."
            }
            $candidateExecutablePath = [string]$candidate.ExecutablePath
            $owned = -not [string]::IsNullOrWhiteSpace($candidateExecutablePath) -and
                $candidateExecutablePath.Equals($expectedExecutablePath, [StringComparison]::OrdinalIgnoreCase) -and
                $commandLine.IndexOf($pidFile.FullName, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                $commandLine.IndexOf($jobRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
            if (-not $owned) {
                throw "QEMU pid marker '$($pidFile.FullName)' points to process $candidatePid, but its executable/pidfile/runtime identity does not match a provider-managed job; password reset stopped before changing the baseline."
            }

            Stop-Process -Id $candidatePid -Force -ErrorAction Stop
            $deadline = (Get-Date).AddSeconds(30)
            while ((Get-Process -Id $candidatePid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 200
            }
            if (Get-Process -Id $candidatePid -ErrorAction SilentlyContinue) {
                throw "QEMU process $candidatePid did not exit within 30 seconds; password reset stopped before changing the disk."
            }
            [void]$stoppedPids.Add($candidatePid)
            Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($candidate in $qemuProcesses) {
        $candidatePid = [int]$candidate.ProcessId
        if ($stoppedPids.Contains($candidatePid)) { continue }
        $commandLine = [string]$candidate.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            throw "Cannot inspect QEMU process $candidatePid; password reset stopped before changing the baseline."
        }
        $usesRuntimeRoot = $commandLine.IndexOf($vmsRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
        $usesDisk = $commandLine.IndexOf($resolvedDisk, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $commandLine.IndexOf($resolvedDiskArgument, [StringComparison]::OrdinalIgnoreCase) -ge 0
        if (-not $usesRuntimeRoot -and -not $usesDisk) { continue }
        throw "QEMU password reset found an unowned process $candidatePid using the managed runtime/disk without a valid native qemu.pid ownership marker and refused to stop it. Close that process manually before retrying."
    }
}

function Start-QemuForPasswordReset {
    param(
        [Parameter(Mandatory)][string]$QemuSystem,
        [Parameter(Mandatory)][string]$DiskPath,
        [Parameter(Mandatory)][string]$DiskFormat,
        [Parameter(Mandatory)][string]$PidPath
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    $drivePath = Escape-QemuDriveOptionValue -Value $DiskPath
    foreach ($argument in @('-name', "$VmName-PasswordReset", '-m', ([string]$QemuMemoryMegabytes), '-pidfile', $PidPath)) {
        [void]$arguments.Add($argument)
    }
    if ($QemuDiskInterface -eq 'scsi') {
        foreach ($argument in @(
                '-drive', "file=$drivePath,if=none,format=$DiskFormat,id=ksword-disk",
                '-device', 'virtio-scsi-pci,id=ksword-scsi',
                '-device', 'scsi-hd,drive=ksword-disk,bus=ksword-scsi.0')) {
            [void]$arguments.Add($argument)
        }
    }
    else {
        [void]$arguments.Add('-drive')
        [void]$arguments.Add("file=$drivePath,if=$QemuDiskInterface,format=$DiskFormat,id=ksword-disk")
    }
    if ($QemuHeadless) {
        [void]$arguments.Add('-display')
        [void]$arguments.Add('none')
    }
    if ($GuestRemotingAddressMode -eq 'QemuUserNat') {
        $guestPort = if ($GuestRemotingUseSsl) { 5986 } else { 5985 }
        [void]$arguments.Add('-netdev')
        [void]$arguments.Add("user,id=ksword-net,hostfwd=tcp:127.0.0.1:$($script:EffectiveGuestRemotingPort)-:$guestPort")
        [void]$arguments.Add('-device')
        [void]$arguments.Add('e1000,netdev=ksword-net')
    }
    foreach ($argument in @($script:ValidatedQemuAdditionalArguments)) { [void]$arguments.Add($argument) }

    if ($GuestRemotingAddressMode -eq 'QemuUserNat') {
        $portProbe = $null
        try {
            $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $script:EffectiveGuestRemotingPort)
            $portProbe.ExclusiveAddressUse = $true
            $portProbe.Start()
        }
        catch {
            throw "QEMU password-reset WinRM host-forward port $($script:EffectiveGuestRemotingPort) on 127.0.0.1 is unavailable. Stop the conflicting listener or configure another GuestRemotingPort; no QEMU process was started. $($_.Exception.Message)"
        }
        finally {
            if ($null -ne $portProbe) { $portProbe.Stop() }
        }
    }

    $argumentLine = ($arguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join ' '
    Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
    $process = Start-Process -FilePath $QemuSystem -ArgumentList $argumentLine -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 2
    $process.Refresh()
    if ($process.HasExited) {
        throw "QEMU exited during password-reset startup with code $($process.ExitCode)."
    }

    $nativePidDeadline = (Get-Date).AddSeconds(10)
    while (-not (Test-Path -LiteralPath $PidPath -PathType Leaf) -and
        -not $process.HasExited -and
        (Get-Date) -lt $nativePidDeadline) {
        Start-Sleep -Milliseconds 100
        $process.Refresh()
    }
    if (-not (Test-Path -LiteralPath $PidPath -PathType Leaf)) {
        $markerError = "QEMU did not publish its native -pidfile marker within 10 seconds: $PidPath"
        try { Stop-ProcessBounded -Process $process }
        catch { throw "$markerError; the new process could not be stopped: $($_.Exception.Message)" }
        throw "$markerError; the new process was stopped."
    }

    try {
        $nativePidText = (Get-Content -LiteralPath $PidPath -Raw -ErrorAction Stop).Trim()
        $nativePid = 0
        if (-not [int]::TryParse($nativePidText, [ref]$nativePid) -or
            $nativePid -le 0 -or
            $nativePid -ne $process.Id) {
            throw "QEMU native -pidfile marker contains '$nativePidText', which does not match newly started process $($process.Id)."
        }
        $markerWrittenUtc = (Get-Item -LiteralPath $PidPath -ErrorAction Stop).LastWriteTimeUtc
        $processStartedUtc = $process.StartTime.ToUniversalTime()
        if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or
            $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) {
            throw "QEMU native -pidfile marker does not match the newly started process time."
        }
    }
    catch {
        $markerError = $_.Exception.Message
        Stop-ProcessBounded -Process $process
        Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
        throw "QEMU password-reset native pid marker validation failed; the new process was stopped: $markerError"
    }
    return $process
}

function Wait-VMwareVmPowerStateChecked {
    param(
        [Parameter(Mandatory)][string]$Vmrun,
        [Parameter(Mandatory)][string]$Vmx,
        [Parameter(Mandatory)][bool]$ExpectedRunning,
        [Parameter(Mandatory)][string]$Operation
    )

    $deadline = (Get-Date).AddSeconds(60)
    $lastOutput = @()
    $listExitCode = $null
    do {
        $lastOutput = @(& $Vmrun -T $VMwareVmType list 2>&1)
        $listExitCode = $LASTEXITCODE
        if ($listExitCode -eq 0) {
            $running = @($lastOutput | ForEach-Object { ([string]$_).Trim() }) -contains $Vmx
            if ($running -eq $ExpectedRunning) { return }
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    $expectedState = if ($ExpectedRunning) { 'running' } else { 'stopped' }
    throw "$Operation did not reach $expectedState state within 60 seconds. Last vmrun list exit code: $listExitCode. $($lastOutput -join ' ')"
}

function Stop-VMwareVmChecked {
    param(
        [Parameter(Mandatory)][string]$Vmrun,
        [Parameter(Mandatory)][string]$Vmx,
        [Parameter(Mandatory)][string]$Operation
    )

    $running = Invoke-NativeChecked -FilePath $Vmrun -Arguments @('-T', $VMwareVmType, 'list') -Operation "$Operation list"
    if (@($running | ForEach-Object { ([string]$_).Trim() }) -notcontains $Vmx) {
        return
    }

    $null = Invoke-NativeChecked -FilePath $Vmrun -Arguments @('-T', $VMwareVmType, 'stop', $Vmx, 'hard') -Operation "$Operation stop"
    Wait-VMwareVmPowerStateChecked -Vmrun $Vmrun -Vmx $Vmx -ExpectedRunning $false -Operation $Operation
}

function Resolve-VMwareToolsGuestAddress {
    param(
        [Parameter(Mandatory)][string]$Vmrun,
        [Parameter(Mandatory)][string]$Vmx
    )

    $deadline = (Get-Date).AddSeconds($GuestReadyTimeoutSeconds)
    $lastOutput = @()
    do {
        $lastOutput = @(& $Vmrun -T $VMwareVmType getGuestIPAddress $Vmx 2>&1)
        $exitCode = $LASTEXITCODE
        $address = Select-VMwareGuestAddress -Output $lastOutput
        if ($exitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($address)) {
            $script:EffectiveGuestRemotingAddress = $address
            $script:GuestRemotingAddressSource = 'vmware-tools-auto-discovery'
            return
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)

    throw "VMware Tools did not return a valid guest IP address within $GuestReadyTimeoutSeconds seconds. Last output: $($lastOutput -join ' ')"
}

function Invoke-VMwarePasswordReset {
    param(
        [Parameter(Mandatory)][pscredential]$CurrentCredential,
        [Parameter(Mandatory)][pscredential]$NewCredential,
        [Parameter(Mandatory)][string]$NewPassword
    )

    $vmrun = Resolve-Executable -ConfiguredPath $VMwareVmrunPath -DisplayName 'VMware vmrun'
    if (-not (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf)) {
        throw "VMware VMX was not found: $VMwareVmxPath"
    }
    $vmx = (Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath
    $snapshots = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'listSnapshots', $vmx) -Operation 'vmrun listSnapshots'
    if (@($snapshots | ForEach-Object { ([string]$_).Trim() }) -notcontains $CheckpointName) {
        throw "VMware snapshot '$CheckpointName' was not found; no password was changed."
    }

    $passwordChanged = $false
    $newSnapshotCreated = $false
    $startMode = if ($VMwareHeadless) { 'nogui' } else { 'gui' }
    $baselineSuffix = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    $newSnapshotName = "$CheckpointName-password-reset-$baselineSuffix"
    try {
        Stop-VMwareVmChecked -Vmrun $vmrun -Vmx $vmx -Operation 'vmrun pre-reset'
        $null = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'revertToSnapshot', $vmx, $CheckpointName) -Operation 'vmrun revertToSnapshot'
        $null = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'start', $vmx, $startMode) -Operation 'vmrun start'
        Wait-VMwareVmPowerStateChecked -Vmrun $vmrun -Vmx $vmx -ExpectedRunning $true -Operation 'vmrun start'
        if ($GuestRemotingAddressMode -eq 'VMwareTools') {
            Resolve-VMwareToolsGuestAddress -Vmrun $vmrun -Vmx $vmx
        }
        Wait-RemoteCredential -Credential $CurrentCredential
        Set-RemoteLocalPassword -CurrentCredential $CurrentCredential -NewPassword $NewPassword
        $passwordChanged = $true
        Wait-RemoteCredential -Credential $NewCredential
        Stop-VMwareVmChecked -Vmrun $vmrun -Vmx $vmx -Operation 'vmrun post-reset'
        $null = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'snapshot', $vmx, $newSnapshotName) -Operation 'vmrun create replacement snapshot'
        $newSnapshotCreated = $true
        return [pscustomobject][ordered]@{
            NewSnapshotName = $newSnapshotName
            NewDiskImagePath = $null
            NewVmxPath = $null
            NewVmName = $null
            UseOverlayDisk = $null
        }
    }
    catch {
        $primaryError = $_
        $cleanupErrors = [System.Collections.Generic.List[string]]::new()
        try {
            Stop-VMwareVmChecked -Vmrun $vmrun -Vmx $vmx -Operation 'vmrun failure rollback stop'
        }
        catch { [void]$cleanupErrors.Add("VM stop: $($_.Exception.Message)") }
        if ($passwordChanged -and -not $newSnapshotCreated -and $cleanupErrors.Count -eq 0) {
            try {
                $null = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'revertToSnapshot', $vmx, $CheckpointName) -Operation 'vmrun rollback to original snapshot'
            }
            catch { [void]$cleanupErrors.Add("snapshot rollback: $($_.Exception.Message)") }
        }
        if ($cleanupErrors.Count -gt 0) {
            throw "VMware password reset failed: $($primaryError.Exception.Message) Cleanup is incomplete: $($cleanupErrors -join ' | '). Inspect the VM before retrying."
        }
        throw $primaryError
    }
}

function Get-SingleVMwareCloneDiskReference {
    param([Parameter(Mandatory)][string]$VmxPath)

    $vmxText = [IO.File]::ReadAllText($VmxPath)
    if ($vmxText -match '(?im)^\s*checkpoint\.vmState\s*=\s*"[^"\r\n]+"\s*$') {
        throw 'VMware offline recovery requires a powered-off clean snapshot; the full clone contains checkpoint.vmState and cannot safely accept a replacement disk.'
    }
    $pattern = '(?im)^(?<prefix>\s*(?:scsi|sata|ide|nvme)\d+:\d+\.fileName\s*=\s*)"(?<path>[^"\r\n]+\.vmdk)"\s*$'
    $matches = [Text.RegularExpressions.Regex]::Matches($vmxText, $pattern)
    if ($matches.Count -ne 1) {
        throw "VMware offline recovery requires exactly one VMDK disk reference in the full-clone VMX; found $($matches.Count). Configure a single-system-disk recovery VM before retrying."
    }

    $match = $matches[0]
    $cloneDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $VmxPath))
    $configuredDiskPath = [string]$match.Groups['path'].Value
    $resolvedDiskPath = if ([IO.Path]::IsPathRooted($configuredDiskPath)) {
        [IO.Path]::GetFullPath($configuredDiskPath)
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $cloneDirectory $configuredDiskPath))
    }
    $pathSeparators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $clonePrefix = $cloneDirectory.TrimEnd($pathSeparators) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedDiskPath.StartsWith($clonePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The cloned VMX disk reference escapes the replacement clone directory: $configuredDiskPath"
    }
    if (-not (Test-Path -LiteralPath $resolvedDiskPath -PathType Leaf)) {
        throw "The cloned VMware disk was not found: $resolvedDiskPath"
    }

    return [pscustomobject][ordered]@{
        VmxText = $vmxText
        MatchIndex = $match.Index
        MatchLength = $match.Length
        Prefix = [string]$match.Groups['prefix'].Value
        DiskPath = $resolvedDiskPath
    }
}

function Set-VMwareCloneDiskReference {
    param(
        [Parameter(Mandatory)][string]$VmxPath,
        [Parameter(Mandatory)]$Reference,
        [Parameter(Mandatory)][string]$ReplacementDiskPath
    )

    $vmxDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $VmxPath))
    $replacementFullPath = [IO.Path]::GetFullPath($ReplacementDiskPath)
    $pathSeparators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $vmxPrefix = $vmxDirectory.TrimEnd($pathSeparators) + [IO.Path]::DirectorySeparatorChar
    if (-not $replacementFullPath.StartsWith($vmxPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Replacement VMware disk must remain in the replacement VMX directory.'
    }
    $replacementFileName = [IO.Path]::GetFileName($replacementFullPath)
    $replacementLine = $Reference.Prefix + '"' + $replacementFileName + '"'
    $updatedText = $Reference.VmxText.Remove([int]$Reference.MatchIndex, [int]$Reference.MatchLength).Insert([int]$Reference.MatchIndex, $replacementLine)
    $temporaryVmx = "$VmxPath.ksword-update-$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText($temporaryVmx, $updatedText, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporaryVmx -Destination $VmxPath -Force
    }
    finally {
        Remove-Item -LiteralPath $temporaryVmx -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-VMwareOfflinePasswordRecovery {
    param(
        [Parameter(Mandatory)][pscredential]$NewCredential,
        [Parameter(Mandatory)][string]$NewPassword
    )

    if ($VMwareVmType -ne 'ws') {
        throw 'VMware unknown-password recovery requires Workstation Pro vmrun full-clone support; vmrun -T player cannot create the isolated replacement VMX required by this safety contract.'
    }
    if (-not (Test-IsAdministrator)) {
        throw 'VMware offline password recovery requires an elevated Windows PowerShell session for detached VHDX mounting.'
    }

    $vmrun = Resolve-Executable -ConfiguredPath $VMwareVmrunPath -DisplayName 'VMware vmrun'
    $qemuImg = Resolve-Executable -ConfiguredPath $QemuImgPath -DisplayName 'qemu-img for VMware offline disk conversion'
    $powerShell = Resolve-Executable -ConfiguredPath 'powershell.exe' -DisplayName 'Windows PowerShell'
    $injector = Join-Path $PSScriptRoot 'Inject-OfflineGuestPasswordService.ps1'
    if (-not (Test-Path -LiteralPath $injector -PathType Leaf)) { throw "Offline guest password injector was not found: $injector" }
    if (-not (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf)) { throw "VMware VMX was not found: $VMwareVmxPath" }

    $sourceVmx = (Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath
    $snapshots = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'listSnapshots', $sourceVmx) -Operation 'vmrun listSnapshots offline-recovery source'
    if (@($snapshots | ForEach-Object { ([string]$_).Trim() }) -notcontains $CheckpointName) {
        throw "VMware snapshot '$CheckpointName' was not found; offline recovery did not modify the source VM."
    }
    Stop-VMwareVmChecked -Vmrun $vmrun -Vmx $sourceVmx -Operation 'vmrun offline-recovery source stop'

    $baselineSuffix = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    $cloneName = "$VmName-PasswordRecovery-$baselineSuffix"
    $cloneDirectory = Join-Path (Join-Path $RuntimeRoot 'provider-baselines\vmware') $baselineSuffix
    $cloneVmx = Join-Path $cloneDirectory 'KSwordSandbox-Recovered.vmx'
    $workingRoot = Join-Path $RuntimeRoot ("password-recovery\{0}" -f [Guid]::NewGuid().ToString('N'))
    $workingVhdx = Join-Path $workingRoot 'offline-recovery.vhdx'
    $replacementVmdk = Join-Path $cloneDirectory 'KSwordSandbox-Recovered-Disk.vmdk'
    $newSnapshotName = "$CheckpointName-password-recovery-$baselineSuffix"
    $startMode = if ($VMwareHeadless) { 'nogui' } else { 'gui' }
    $cloneCreated = $false
    $baselineCreated = $false

    try {
        New-Item -ItemType Directory -Path $cloneDirectory -Force | Out-Null
        New-Item -ItemType Directory -Path $workingRoot -Force | Out-Null
        $null = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'clone', $sourceVmx, $cloneVmx, 'full', "-snapshot=$CheckpointName", "-cloneName=$cloneName") -Operation 'vmrun create offline-recovery full clone'
        $cloneCreated = $true
        if (-not (Test-Path -LiteralPath $cloneVmx -PathType Leaf)) { throw "vmrun clone did not create the expected replacement VMX: $cloneVmx" }

        $diskReference = Get-SingleVMwareCloneDiskReference -VmxPath $cloneVmx
        $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('convert', '-f', 'vmdk', '-O', 'vhdx', $diskReference.DiskPath, $workingVhdx) -Operation 'qemu-img convert VMware clone disk to temporary VHDX'

        [Environment]::SetEnvironmentVariable($NewPasswordSecretName, $NewPassword, 'Process')
        try {
            $injectOutput = @(& $powerShell -NoProfile -ExecutionPolicy Bypass -File $injector `
                    -VhdxPath $workingVhdx `
                    -GuestUserName $GuestUserName `
                    -PasswordSecretName $NewPasswordSecretName `
                    -Force -Json -Confirm:$false 2>&1 | ForEach-Object { [string]$_ })
            $injectExitCode = $LASTEXITCODE
        }
        finally {
            [Environment]::SetEnvironmentVariable($NewPasswordSecretName, $null, 'Process')
        }
        if ($injectExitCode -ne 0) { throw "Offline guest password injection failed with exit code $injectExitCode: $($injectOutput -join ' ')" }
        try { $injectResult = ($injectOutput -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Offline guest password injection returned invalid JSON: $($_.Exception.Message)" }
        if (-not [bool]$injectResult.Injected -or -not [bool]$injectResult.ProviderChildSecretEnvironmentCleared -or [bool]$injectResult.SecretValuePrinted) {
            throw 'Offline guest password injection did not satisfy its mutation and secret-safety contract.'
        }

        $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('convert', '-f', 'vhdx', '-O', 'vmdk', '-o', 'subformat=monolithicSparse', $workingVhdx, $replacementVmdk) -Operation 'qemu-img create VMware offline-recovery replacement VMDK'
        $replacementInfoOutput = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('info', '--output=json', $replacementVmdk) -Operation 'qemu-img verify VMware offline-recovery replacement VMDK'
        $replacementInfo = ($replacementInfoOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
        if (-not ([string]$replacementInfo.format).Equals('vmdk', [StringComparison]::OrdinalIgnoreCase)) { throw 'VMware replacement disk format verification failed.' }
        Set-VMwareCloneDiskReference -VmxPath $cloneVmx -Reference $diskReference -ReplacementDiskPath $replacementVmdk

        $null = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'start', $cloneVmx, $startMode) -Operation 'vmrun start offline-recovery replacement VM'
        Wait-VMwareVmPowerStateChecked -Vmrun $vmrun -Vmx $cloneVmx -ExpectedRunning $true -Operation 'vmrun start offline-recovery replacement VM'
        if ($GuestRemotingAddressMode -eq 'VMwareTools') { Resolve-VMwareToolsGuestAddress -Vmrun $vmrun -Vmx $cloneVmx }
        Wait-RemoteCredential -Credential $NewCredential
        Confirm-RemoteOfflinePasswordResetCleanup -Credential $NewCredential
        Stop-VMwareVmChecked -Vmrun $vmrun -Vmx $cloneVmx -Operation 'vmrun stop verified offline-recovery replacement VM'
        $null = Invoke-NativeChecked -FilePath $vmrun -Arguments @('-T', $VMwareVmType, 'snapshot', $cloneVmx, $newSnapshotName) -Operation 'vmrun create offline-recovery replacement snapshot'
        $baselineCreated = $true

        return [pscustomobject][ordered]@{
            NewSnapshotName = $newSnapshotName
            NewDiskImagePath = $null
            NewVmxPath = $cloneVmx
            NewVmName = $cloneName
            UseOverlayDisk = $null
            OfflineRecovery = $true
        }
    }
    catch {
        $primaryError = $_
        $cleanupErrors = [System.Collections.Generic.List[string]]::new()
        if ($cloneCreated) {
            try { Stop-VMwareVmChecked -Vmrun $vmrun -Vmx $cloneVmx -Operation 'vmrun cleanup failed offline-recovery clone' }
            catch { [void]$cleanupErrors.Add("replacement VM stop: $($_.Exception.Message)") }
        }
        if (-not $baselineCreated -and $cleanupErrors.Count -eq 0 -and (Test-Path -LiteralPath $cloneDirectory -PathType Container)) {
            Remove-Item -LiteralPath $cloneDirectory -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $cloneDirectory -PathType Container) {
                [void]$cleanupErrors.Add("replacement clone directory could not be removed: $cloneDirectory")
            }
        }
        if ($cleanupErrors.Count -gt 0) {
            throw "VMware offline recovery failed: $($primaryError.Exception.Message) Cleanup is incomplete: $($cleanupErrors -join ' | '). The source VM and snapshot were not modified; inspect the replacement clone before retrying."
        }
        throw $primaryError
    }
    finally {
        [Environment]::SetEnvironmentVariable($NewPasswordSecretName, $null, 'Process')
        if (Test-Path -LiteralPath $workingRoot -PathType Container) {
            Remove-Item -LiteralPath $workingRoot -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $workingRoot -PathType Container) {
                throw "Secret-bearing VMware offline recovery workspace could not be removed: $workingRoot"
            }
        }
    }
}

function Invoke-QemuPasswordReset {
    param(
        [Parameter(Mandatory)][pscredential]$CurrentCredential,
        [Parameter(Mandatory)][pscredential]$NewCredential,
        [Parameter(Mandatory)][string]$NewPassword
    )

    $qemuSystem = Resolve-Executable -ConfiguredPath $QemuSystemPath -DisplayName 'qemu-system'
    $qemuImg = Resolve-Executable -ConfiguredPath $QemuImgPath -DisplayName 'qemu-img'
    if (-not (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf)) {
        throw "QEMU disk image was not found: $QemuDiskImagePath"
    }
    $baseDisk = (Resolve-Path -LiteralPath $QemuDiskImagePath).ProviderPath
    $imageInfoOutput = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('info', '--output=json', $baseDisk) -Operation 'qemu-img info'
    $imageInfo = ($imageInfoOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
    $actualFormat = [string]$imageInfo.format
    if (-not $actualFormat.Equals($QemuDiskFormat, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Configured QEMU format '$QemuDiskFormat' does not match '$actualFormat'."
    }
    if (-not $QemuUseOverlayDisk -and -not $actualFormat.Equals('qcow2', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'QEMU internal snapshot password reset requires qcow2.'
    }

    Stop-QemuUsingDisk -QemuSystem $qemuSystem -DiskPath $baseDisk
    $resetRoot = Join-Path $RuntimeRoot ("vms\password-reset-{0}" -f [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $resetRoot -Force | Out-Null
    $pidPath = Join-Path $resetRoot 'qemu.pid'
    $workingDisk = $baseDisk
    $workingFormat = $QemuDiskFormat
    $process = $null
    $passwordChanged = $false
    $newBaselineCreated = $false
    $newSnapshotName = $null
    $newDiskPath = $null
    $failureCleanupHandled = $false
    try {
        if ($QemuUseOverlayDisk) {
            $workingDisk = Join-Path $resetRoot 'password-reset-overlay.qcow2'
            $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('create', '-f', 'qcow2', '-F', $QemuDiskFormat, '-b', $baseDisk, $workingDisk) -Operation 'qemu-img create password-reset overlay'
            $workingFormat = 'qcow2'
        }
        else {
            $snapshotProperty = $imageInfo.PSObject.Properties['snapshots']
            $snapshotNames = if ($null -eq $snapshotProperty) { @() } else { @($snapshotProperty.Value | ForEach-Object { [string]$_.name }) }
            if ($snapshotNames -cnotcontains $CheckpointName) {
                throw "QEMU internal snapshot '$CheckpointName' was not found; no password was changed."
            }
            $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('snapshot', '-a', $CheckpointName, $baseDisk) -Operation 'qemu-img restore password-reset baseline'
        }

        $process = Start-QemuForPasswordReset -QemuSystem $qemuSystem -DiskPath $workingDisk -DiskFormat $workingFormat -PidPath $pidPath
        Wait-RemoteCredential -Credential $CurrentCredential
        Set-RemoteLocalPassword -CurrentCredential $CurrentCredential -NewPassword $NewPassword
        $passwordChanged = $true
        Wait-RemoteCredential -Credential $NewCredential
        Stop-ProcessBounded -Process $process
        $process = $null

        if ($QemuUseOverlayDisk) {
            $directory = Split-Path -Parent $baseDisk
            $stem = [IO.Path]::GetFileNameWithoutExtension($baseDisk)
            $extension = [IO.Path]::GetExtension($baseDisk)
            if ([string]::IsNullOrWhiteSpace($extension)) { $extension = ".$QemuDiskFormat" }
            $baselineSuffix = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
            $newDiskPath = Join-Path $directory ("{0}-password-reset-{1}{2}" -f $stem, $baselineSuffix, $extension)
            if (Test-Path -LiteralPath $newDiskPath) { throw "Replacement QEMU disk already exists: $newDiskPath" }
            $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('convert', '-f', 'qcow2', '-O', $QemuDiskFormat, $workingDisk, $newDiskPath) -Operation 'qemu-img create replacement baseline'
            $newInfoOutput = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('info', '--output=json', $newDiskPath) -Operation 'qemu-img verify replacement baseline'
            $newInfo = ($newInfoOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
            if (-not ([string]$newInfo.format).Equals($QemuDiskFormat, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Replacement QEMU disk format verification failed.'
            }
        }
        else {
            $baselineSuffix = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
            $newSnapshotName = "$CheckpointName-password-reset-$baselineSuffix"
            $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('snapshot', '-c', $newSnapshotName, $baseDisk) -Operation 'qemu-img create replacement snapshot'
        }
        $newBaselineCreated = $true

        return [pscustomobject][ordered]@{
            NewSnapshotName = $newSnapshotName
            NewDiskImagePath = $newDiskPath
            NewVmxPath = $null
            NewVmName = $null
            UseOverlayDisk = [bool]$QemuUseOverlayDisk
        }
    }
    catch {
        $primaryError = $_
        $cleanupErrors = [System.Collections.Generic.List[string]]::new()
        try { Stop-ProcessBounded -Process $process }
        catch { [void]$cleanupErrors.Add("QEMU stop: $($_.Exception.Message)") }
        if ($passwordChanged -and -not $newBaselineCreated -and -not $QemuUseOverlayDisk -and $cleanupErrors.Count -eq 0) {
            try {
                $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('snapshot', '-a', $CheckpointName, $baseDisk) -Operation 'qemu-img rollback to original snapshot'
            }
            catch { [void]$cleanupErrors.Add("snapshot rollback: $($_.Exception.Message)") }
        }
        if ($newDiskPath -and -not $newBaselineCreated -and $cleanupErrors.Count -eq 0) {
            Remove-Item -LiteralPath $newDiskPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $newDiskPath -PathType Leaf) {
                [void]$cleanupErrors.Add("replacement disk could not be removed: $newDiskPath")
            }
        }
        if ($cleanupErrors.Count -eq 0 -and (Test-Path -LiteralPath $resetRoot -PathType Container)) {
            Remove-Item -LiteralPath $resetRoot -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $resetRoot -PathType Container) {
                [void]$cleanupErrors.Add("secret-bearing password-reset workspace could not be removed: $resetRoot")
            }
        }
        $failureCleanupHandled = $true
        if ($cleanupErrors.Count -gt 0) {
            throw "QEMU password reset failed: $($primaryError.Exception.Message) Cleanup is incomplete: $($cleanupErrors -join ' | '). Inspect the QEMU process and replacement artifacts before retrying."
        }
        throw $primaryError
    }
    finally {
        if (-not $failureCleanupHandled -and (Test-Path -LiteralPath $resetRoot -PathType Container)) {
            Remove-Item -LiteralPath $resetRoot -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $resetRoot -PathType Container) {
                throw "Secret-bearing QEMU password-reset workspace could not be removed: $resetRoot"
            }
        }
    }
}

function Invoke-QemuOfflinePasswordRecovery {
    param(
        [Parameter(Mandatory)][pscredential]$NewCredential,
        [Parameter(Mandatory)][string]$NewPassword
    )

    if (-not (Test-IsAdministrator)) {
        throw 'QEMU offline password recovery requires an elevated Windows PowerShell session for detached VHDX mounting.'
    }

    $qemuSystem = Resolve-Executable -ConfiguredPath $QemuSystemPath -DisplayName 'qemu-system'
    $qemuImg = Resolve-Executable -ConfiguredPath $QemuImgPath -DisplayName 'qemu-img'
    $powerShell = Resolve-Executable -ConfiguredPath 'powershell.exe' -DisplayName 'Windows PowerShell'
    $injector = Join-Path $PSScriptRoot 'Inject-OfflineGuestPasswordService.ps1'
    if (-not (Test-Path -LiteralPath $injector -PathType Leaf)) {
        throw "Offline guest password injector was not found: $injector"
    }
    if (-not (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf)) {
        throw "QEMU disk image was not found: $QemuDiskImagePath"
    }

    $baseDisk = (Resolve-Path -LiteralPath $QemuDiskImagePath).ProviderPath
    $imageInfoOutput = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('info', '--output=json', $baseDisk) -Operation 'qemu-img info offline-recovery source'
    $imageInfo = ($imageInfoOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
    $actualFormat = [string]$imageInfo.format
    if (-not $actualFormat.Equals($QemuDiskFormat, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Configured QEMU format '$QemuDiskFormat' does not match '$actualFormat'."
    }
    if (-not $QemuUseOverlayDisk) {
        if (-not $actualFormat.Equals('qcow2', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'QEMU internal-snapshot offline recovery requires qcow2.'
        }
        $snapshotProperty = $imageInfo.PSObject.Properties['snapshots']
        $snapshotNames = if ($null -eq $snapshotProperty) { @() } else { @($snapshotProperty.Value | ForEach-Object { [string]$_.name }) }
        if ($snapshotNames -cnotcontains $CheckpointName) {
            throw "QEMU internal snapshot '$CheckpointName' was not found; offline recovery did not modify any disk."
        }
    }

    Stop-QemuUsingDisk -QemuSystem $qemuSystem -DiskPath $baseDisk
    $recoveryRoot = Join-Path $RuntimeRoot ("vms\password-recovery-{0}" -f [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $recoveryRoot -Force | Out-Null
    $pidPath = Join-Path $recoveryRoot 'qemu.pid'
    $workingVhdx = Join-Path $recoveryRoot 'offline-recovery.vhdx'
    $directory = Split-Path -Parent $baseDisk
    $stem = [IO.Path]::GetFileNameWithoutExtension($baseDisk)
    $extension = [IO.Path]::GetExtension($baseDisk)
    if ([string]::IsNullOrWhiteSpace($extension)) { $extension = ".$QemuDiskFormat" }
    $baselineSuffix = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    $newDiskPath = Join-Path $directory ("{0}-offline-password-recovery-{1}{2}" -f $stem, $baselineSuffix, $extension)
    $newSnapshotName = if ($QemuUseOverlayDisk) { $null } else { "$CheckpointName-password-recovery-$baselineSuffix" }
    $process = $null
    $newBaselineCreated = $false
    $failureCleanupHandled = $false

    try {
        $convertSourceArguments = @('convert', '-f', $QemuDiskFormat, '-O', 'vhdx')
        if (-not $QemuUseOverlayDisk) {
            $convertSourceArguments += @('-l', "snapshot.name=$CheckpointName")
        }
        $convertSourceArguments += @($baseDisk, $workingVhdx)
        $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments $convertSourceArguments -Operation 'qemu-img materialize clean baseline as temporary VHDX'

        [Environment]::SetEnvironmentVariable($NewPasswordSecretName, $NewPassword, 'Process')
        try {
            $injectOutput = @(& $powerShell -NoProfile -ExecutionPolicy Bypass -File $injector `
                    -VhdxPath $workingVhdx `
                    -GuestUserName $GuestUserName `
                    -PasswordSecretName $NewPasswordSecretName `
                    -Force -Json -Confirm:$false 2>&1 | ForEach-Object { [string]$_ })
            $injectExitCode = $LASTEXITCODE
        }
        finally {
            [Environment]::SetEnvironmentVariable($NewPasswordSecretName, $null, 'Process')
        }
        if ($injectExitCode -ne 0) {
            throw "Offline guest password injection failed with exit code $injectExitCode: $($injectOutput -join ' ')"
        }
        try {
            $injectResult = ($injectOutput -join [Environment]::NewLine) | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Offline guest password injection returned invalid JSON: $($_.Exception.Message)"
        }
        if (-not [bool]$injectResult.Injected -or
            -not [bool]$injectResult.ProviderChildSecretEnvironmentCleared -or
            [bool]$injectResult.SecretValuePrinted) {
            throw 'Offline guest password injection did not satisfy its mutation and secret-safety contract.'
        }

        if (Test-Path -LiteralPath $newDiskPath) {
            throw "Replacement QEMU disk already exists: $newDiskPath"
        }
        $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('convert', '-f', 'vhdx', '-O', $QemuDiskFormat, $workingVhdx, $newDiskPath) -Operation 'qemu-img create offline-recovery replacement baseline'
        $newInfoOutput = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('info', '--output=json', $newDiskPath) -Operation 'qemu-img verify offline-recovery replacement baseline'
        $newInfo = ($newInfoOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
        if (-not ([string]$newInfo.format).Equals($QemuDiskFormat, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Offline-recovery replacement QEMU disk format verification failed.'
        }

        $process = Start-QemuForPasswordReset -QemuSystem $qemuSystem -DiskPath $newDiskPath -DiskFormat $QemuDiskFormat -PidPath $pidPath
        Wait-RemoteCredential -Credential $NewCredential
        Confirm-RemoteOfflinePasswordResetCleanup -Credential $NewCredential
        Stop-ProcessBounded -Process $process
        $process = $null

        if (-not $QemuUseOverlayDisk) {
            $null = Invoke-NativeChecked -FilePath $qemuImg -Arguments @('snapshot', '-c', $newSnapshotName, $newDiskPath) -Operation 'qemu-img create offline-recovery replacement snapshot'
        }
        $newBaselineCreated = $true
        return [pscustomobject][ordered]@{
            NewSnapshotName = $newSnapshotName
            NewDiskImagePath = $newDiskPath
            NewVmxPath = $null
            NewVmName = $null
            UseOverlayDisk = [bool]$QemuUseOverlayDisk
            OfflineRecovery = $true
        }
    }
    catch {
        $primaryError = $_
        $cleanupErrors = [System.Collections.Generic.List[string]]::new()
        try { Stop-ProcessBounded -Process $process }
        catch { [void]$cleanupErrors.Add("replacement QEMU stop: $($_.Exception.Message)") }
        if (-not $newBaselineCreated -and $cleanupErrors.Count -eq 0 -and (Test-Path -LiteralPath $newDiskPath -PathType Leaf)) {
            Remove-Item -LiteralPath $newDiskPath -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $newDiskPath -PathType Leaf) {
                [void]$cleanupErrors.Add("replacement disk could not be removed: $newDiskPath")
            }
        }
        if ($cleanupErrors.Count -eq 0 -and (Test-Path -LiteralPath $recoveryRoot -PathType Container)) {
            Remove-Item -LiteralPath $recoveryRoot -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $recoveryRoot -PathType Container) {
                [void]$cleanupErrors.Add("secret-bearing QEMU offline-recovery workspace could not be removed: $recoveryRoot")
            }
        }
        $failureCleanupHandled = $true
        if ($cleanupErrors.Count -gt 0) {
            throw "QEMU offline recovery failed: $($primaryError.Exception.Message) Cleanup is incomplete: $($cleanupErrors -join ' | '). The source baseline was not modified; inspect the replacement disk before retrying."
        }
        throw $primaryError
    }
    finally {
        [Environment]::SetEnvironmentVariable($NewPasswordSecretName, $null, 'Process')
        if (-not $failureCleanupHandled -and (Test-Path -LiteralPath $recoveryRoot -PathType Container)) {
            Remove-Item -LiteralPath $recoveryRoot -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $recoveryRoot -PathType Container) {
                throw "Secret-bearing QEMU offline recovery workspace could not be removed: $recoveryRoot"
            }
        }
    }
}

if ($VirtualizationProvider -eq 'VMware' -and $GuestRemotingAddressMode -notin @('Configured', 'VMwareTools')) {
    throw "VMware GuestRemotingAddressMode '$GuestRemotingAddressMode' is invalid; use Configured or VMwareTools."
}
if ($VirtualizationProvider -eq 'Qemu' -and $GuestRemotingAddressMode -notin @('Configured', 'QemuUserNat')) {
    throw "QEMU GuestRemotingAddressMode '$GuestRemotingAddressMode' is invalid; use Configured or QemuUserNat."
}
if ($GuestRemotingAddressMode -eq 'Configured' -and [string]::IsNullOrWhiteSpace($GuestRemotingAddress)) {
    throw 'GuestRemotingAddress is required in Configured mode for VMware/QEMU password reset.'
}
if ($GuestRemotingAddressMode -in @('VMwareTools', 'QemuUserNat') -and -not $GuestRemotingUseSsl) {
    throw "$GuestRemotingAddressMode automatic endpoint mode requires GuestRemotingUseSsl so IP/loopback WinRM does not depend on host-wide TrustedHosts."
}
if ($GuestRemotingAddressMode -eq 'VMwareTools') {
    $script:EffectiveGuestRemotingAddress = ''
    $script:GuestRemotingAddressSource = 'vmware-tools-auto-discovery'
}
elseif ($GuestRemotingAddressMode -eq 'QemuUserNat') {
    $script:EffectiveGuestRemotingAddress = '127.0.0.1'
    $script:EffectiveGuestRemotingPort = if ($GuestRemotingPort -gt 0) { $GuestRemotingPort } elseif ($GuestRemotingUseSsl) { 55986 } else { 55985 }
    $script:GuestRemotingAddressSource = 'provider-managed-user-nat'
}
if ($GuestRemotingAuthentication -eq 'Basic' -and -not $GuestRemotingUseSsl) {
    throw 'Basic WinRM over HTTP is refused for password rotation; configure HTTPS or use Negotiate/CredSSP.'
}
if ($GuestRemotingSkipCertificateChecks -and -not $GuestRemotingUseSsl) {
    throw 'GuestRemotingSkipCertificateChecks is valid only with GuestRemotingUseSsl.'
}
if (-not $Force) {
    throw 'Remote guest password reset requires -Force after the parent installer confirms this isolated VM mutation.'
}
if ($OfflineRecovery -and $VirtualizationProvider -eq 'VMware' -and $VMwareVmType -ne 'ws') {
    throw 'VMware offline recovery requires Workstation Pro vmrun full-clone support; VMware Player cannot create the isolated replacement VMX.'
}
if (-not $OfflineRecovery -and [string]::IsNullOrWhiteSpace($CurrentPasswordSecretName)) {
    throw 'CurrentPasswordSecretName is required for WinRM password rotation.'
}
if (-not $OfflineRecovery -and $CurrentPasswordSecretName.Equals($NewPasswordSecretName, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'CurrentPasswordSecretName and NewPasswordSecretName must be different.'
}
if ($VirtualizationProvider -eq 'Qemu') {
    $configuredQemuArguments = @(Get-QemuAdditionalArguments)
    if (-not (Test-QemuWhpxAdditionalArguments -Arguments $configuredQemuArguments -GuestAddressMode $GuestRemotingAddressMode)) {
        $configuredQemuArguments = @('-accel', 'whpx') + $configuredQemuArguments
    }
    $script:ValidatedQemuAdditionalArguments = $configuredQemuArguments
}

$target = "${VirtualizationProvider}::${VmName}::${CheckpointName}"
$operation = if ($OfflineRecovery) {
    'Recover unknown guest password through offline VHDX injection, verify the new WinRM credential, and create a replacement clean baseline'
}
else {
    'Rotate guest password, verify new WinRM credential, and create a replacement clean baseline'
}
if (-not $PSCmdlet.ShouldProcess($target, $operation)) {
    $preview = [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.RemoteGuestPasswordReset'
        Provider = $VirtualizationProvider
        VmName = $VmName
        GuestRemotingAddressMode = $GuestRemotingAddressMode
        GuestRemotingAddressSource = $script:GuestRemotingAddressSource
        OfflineRecovery = [bool]$OfflineRecovery
        PasswordChanged = $false
        BaselineRefreshed = $false
        WhatIf = $true
        SecretValuePrinted = $false
    }
    if ($Json) { $preview | ConvertTo-Json -Depth 6 } else { $preview }
    exit 0
}

$currentPassword = if ($OfflineRecovery) { $null } else { Get-SecretValue -Name $CurrentPasswordSecretName }
$newPassword = Get-SecretValue -Name $NewPasswordSecretName
if (-not [string]::IsNullOrWhiteSpace($CurrentPasswordSecretName)) {
    [Environment]::SetEnvironmentVariable($CurrentPasswordSecretName, $null, 'Process')
}
[Environment]::SetEnvironmentVariable($NewPasswordSecretName, $null, 'Process')
$providerEnvironment = [Environment]::GetEnvironmentVariables('Process')
foreach ($providerEnvironmentKey in @($providerEnvironment.Keys)) {
    $providerEnvironmentName = [string]$providerEnvironmentKey
    if ($providerEnvironmentName.StartsWith('KSWORDBOX_', [StringComparison]::OrdinalIgnoreCase) -or
        $providerEnvironmentName -match '(?i)(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)') {
        [Environment]::SetEnvironmentVariable($providerEnvironmentName, $null, 'Process')
    }
}
if (-not $OfflineRecovery -and $currentPassword -ceq $newPassword) {
    throw 'The replacement guest password must differ from the current password.'
}
$currentCredential = if ($OfflineRecovery) { $null } else { New-PasswordCredential -UserName $GuestUserName -Password $currentPassword }
$newCredential = New-PasswordCredential -UserName $GuestUserName -Password $newPassword

$providerResult = if ($OfflineRecovery -and $VirtualizationProvider -eq 'VMware') {
    Invoke-VMwareOfflinePasswordRecovery -NewCredential $newCredential -NewPassword $newPassword
}
elseif ($OfflineRecovery) {
    Invoke-QemuOfflinePasswordRecovery -NewCredential $newCredential -NewPassword $newPassword
}
elseif ($VirtualizationProvider -eq 'VMware') {
    Invoke-VMwarePasswordReset -CurrentCredential $currentCredential -NewCredential $newCredential -NewPassword $newPassword
}
else {
    Invoke-QemuPasswordReset -CurrentCredential $currentCredential -NewCredential $newCredential -NewPassword $newPassword
}

$result = [pscustomobject][ordered]@{
    Kind = 'KSwordSandbox.RemoteGuestPasswordReset'
    Provider = $VirtualizationProvider
    VmName = $VmName
    GuestRemotingAddressMode = $GuestRemotingAddressMode
    GuestRemotingAddressSource = $script:GuestRemotingAddressSource
    OfflineRecovery = [bool]$OfflineRecovery
    PasswordChanged = $true
    CredentialVerified = $true
    BaselineRefreshed = $true
    OldBaselinePreserved = $true
    NewSnapshotName = $providerResult.NewSnapshotName
    NewDiskImagePath = $providerResult.NewDiskImagePath
    NewVmxPath = $providerResult.NewVmxPath
    NewVmName = $providerResult.NewVmName
    UseOverlayDisk = $providerResult.UseOverlayDisk
    OfflineTemporaryWorkspaceRemoved = if ($OfflineRecovery) { $true } else { $null }
    OfflineGuestServiceCleanupConfirmed = if ($OfflineRecovery) { $true } else { $null }
    ProviderChildSecretEnvironmentCleared = $true
    SecretValuePrinted = $false
}

if ($Json) { $result | ConvertTo-Json -Depth 6 } else { $result }
