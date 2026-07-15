<#
.SYNOPSIS
Enables or disables Windows test-signing inside the configured guest VM.

.DESCRIPTION
Inputs are a virtualization provider, guest user, and host environment secret
containing the guest password. Hyper-V uses PowerShell Direct; VMware and QEMU
use the provider WinRM endpoint. The script is non-interactive and never
invokes driver-signing tools.

Use this only for isolated analysis VMs/checkpoints that need a test-signed R0
driver. A reboot is required after changing test-signing state.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('HyperV', 'VMware', 'Qemu')]
    [string]$VirtualizationProvider = 'HyperV',

    [string]$VmName = 'KSwordSandbox-Win10-Golden',

    [string]$GuestRemotingAddress = '',

    [ValidateSet('Configured', 'VMwareTools', 'QemuUserNat')]
    [string]$GuestRemotingAddressMode = 'Configured',

    [ValidateRange(0, 65535)]
    [int]$GuestRemotingPort = 0,

    [switch]$GuestRemotingUseSsl,

    [switch]$GuestRemotingSkipCertificateChecks,

    [ValidateSet('Negotiate', 'Basic', 'CredSSP')]
    [string]$GuestRemotingAuthentication = 'Negotiate',

    [string]$VMwareVmxPath = '',

    [string]$VMwareVmrunPath = 'vmrun.exe',

    [ValidateSet('ws')]
    [string]$VMwareVmType = 'ws',

    [string]$QemuSystemPath = 'qemu-system-x86_64.exe',

    [string]$QemuDiskImagePath = '',

    [switch]$QemuInternalSnapshot,

    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox',

    [ValidateRange(1, 7200)]
    [int]$GuestReadyTimeoutSeconds = 240,

    [string]$GuestUserName = 'SandboxUser',

    [string]$SecretName = 'KSWORDBOX_GUEST_PASSWORD',

    [ValidateSet('Enable', 'Disable', 'Query')]
    [string]$Mode = 'Enable',

    [switch]$RestartGuest,

    [switch]$Force,

    [switch]$Json
)

if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAuthentication -eq 'Basic' -and -not $GuestRemotingUseSsl) {
    throw 'Basic WinRM over HTTP is refused for guest test-signing operations; configure HTTPS or use Negotiate/CredSSP.'
}
if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingSkipCertificateChecks -and -not $GuestRemotingUseSsl) {
    throw 'GuestRemotingSkipCertificateChecks is valid only with GuestRemotingUseSsl.'
}
if ($VirtualizationProvider -eq 'VMware' -and $GuestRemotingAddressMode -notin @('Configured', 'VMwareTools')) {
    throw "VMware GuestRemotingAddressMode '$GuestRemotingAddressMode' is invalid; use Configured or VMwareTools."
}
if ($VirtualizationProvider -eq 'Qemu' -and $GuestRemotingAddressMode -notin @('Configured', 'QemuUserNat')) {
    throw "QEMU GuestRemotingAddressMode '$GuestRemotingAddressMode' is invalid; use Configured or QemuUserNat."
}
if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAddressMode -in @('VMwareTools', 'QemuUserNat') -and -not $GuestRemotingUseSsl) {
    throw "$GuestRemotingAddressMode automatic endpoint mode requires GuestRemotingUseSsl so IP/loopback WinRM does not depend on host-wide TrustedHosts."
}
if ($VirtualizationProvider -eq 'Qemu' -and $GuestRemotingAddressMode -eq 'QemuUserNat' -and [string]::IsNullOrWhiteSpace($QemuDiskImagePath)) {
    throw 'QemuUserNat guest test-signing requires QemuDiskImagePath so the loopback endpoint can be tied to the configured provider profile.'
}

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-GuestPasswordSecretValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    throw "错误：未在 Process/User/Machine 环境中找到 guest password secret '$Name'。下一步：普通用户请运行 .\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword；如果使用 -GeneratePassword，请确保 VM 内密码也同步。"
}

function New-GuestCredential {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $securePassword = [System.Security.SecureString]::new()
    foreach ($passwordCharacter in $Password.ToCharArray()) {
        $securePassword.AppendChar($passwordCharacter)
    }
    $securePassword.MakeReadOnly()
    return [pscredential]::new($UserName, $securePassword)
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($VirtualizationProvider -eq 'HyperV' -and -not (Test-IsAdministrator)) {
    throw '错误：Hyper-V PowerShell Direct guest test-signing 需要宿主机管理员 PowerShell。下一步：以管理员身份重新打开 PowerShell 后重试；VMware/QEMU WinRM 路径只要求来宾账号具备管理员权限。'
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

function Get-QemuExpectedProcessVmNameFromPidFile {
    param([Parameter(Mandatory)][string]$PidFilePath)

    $normalizedPrefix = $VmName.Trim()
    if ($QemuInternalSnapshot) {
        return $normalizedPrefix
    }

    $jobIdentity = Split-Path -Leaf (Split-Path -Parent $PidFilePath)
    if ($jobIdentity -notmatch '^[0-9a-fA-F]{32}$') {
        return ''
    }

    $suffix = "-$($jobIdentity.ToLowerInvariant())"
    $maximumPrefixLength = 64 - $suffix.Length
    if ($normalizedPrefix.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
        $normalizedPrefix = $normalizedPrefix.Substring(0, $normalizedPrefix.Length - $suffix.Length).TrimEnd('-')
    }
    if ($normalizedPrefix.Length -gt $maximumPrefixLength) {
        $normalizedPrefix = $normalizedPrefix.Substring(0, $maximumPrefixLength)
    }

    return "$normalizedPrefix$suffix"
}

function Test-QemuCommandLineVmName {
    param(
        [Parameter(Mandatory)][string]$CommandLine,
        [Parameter(Mandatory)][string]$ExpectedVmName
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedVmName)) { return $false }
    $escapedVmName = [Text.RegularExpressions.Regex]::Escape($ExpectedVmName)
    $pattern = '(?i)(?:^|\s)-name(?:\s+|=)(?:"' + $escapedVmName + '"|' + $escapedVmName + ')(?=\s|$)'
    return [Text.RegularExpressions.Regex]::IsMatch(
        $CommandLine,
        $pattern,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function Resolve-QemuUserNatOwner {
    param([Parameter(Mandatory)][int]$HostPort)

    $qemuSystem = Resolve-Executable -ConfiguredPath $QemuSystemPath -DisplayName 'QEMU system'
    if (-not (Test-Path -LiteralPath $QemuDiskImagePath -PathType Leaf)) {
        throw "Configured QEMU disk image was not found: $QemuDiskImagePath"
    }

    $expectedProcessName = [IO.Path]::GetFileName($qemuSystem)
    $vmsRoot = Join-Path $RuntimeRoot 'vms'
    if (-not (Test-Path -LiteralPath $vmsRoot -PathType Container)) {
        throw "QemuUserNat endpoint ownership could not be verified because runtime VM directory '$vmsRoot' does not exist. Start the selected QEMU VM through KSword WebUI/CLI, then retry."
    }

    $hostForwardIdentity = "hostfwd=tcp:127.0.0.1:$HostPort-:"
    $owned = [System.Collections.Generic.List[object]]::new()
    foreach ($pidFile in @(Get-ChildItem -LiteralPath $vmsRoot -Filter 'qemu.pid' -File -Recurse -ErrorAction SilentlyContinue)) {
        $candidatePid = 0
        $pidText = ([string](Get-Content -LiteralPath $pidFile.FullName -Raw -ErrorAction SilentlyContinue)).Trim()
        if (-not [int]::TryParse($pidText, [ref]$candidatePid) -or $candidatePid -le 0) { continue }

        $candidate = Get-CimInstance Win32_Process -Filter "ProcessId = $candidatePid" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $candidate -or -not ([string]$candidate.Name).Equals($expectedProcessName, [StringComparison]::OrdinalIgnoreCase)) { continue }
        $candidateExecutable = [string]$candidate.ExecutablePath
        if ([string]::IsNullOrWhiteSpace($candidateExecutable)) {
            throw "QEMU process $candidatePid is referenced by '$($pidFile.FullName)', but its executable path cannot be inspected. Retry with permission to query Win32_Process.ExecutablePath."
        }
        if (-not ([IO.Path]::GetFullPath($candidateExecutable)).Equals([IO.Path]::GetFullPath($qemuSystem), [StringComparison]::OrdinalIgnoreCase)) { continue }

        $markerItem = Get-Item -LiteralPath $pidFile.FullName -ErrorAction SilentlyContinue
        if ($null -eq $markerItem) { continue }
        $markerWrittenUtc = $markerItem.LastWriteTimeUtc
        $processStartedUtc = ([datetime]$candidate.CreationDate).ToUniversalTime()
        if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or
            $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) { continue }

        $commandLine = [string]$candidate.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) {
            throw "QEMU process $candidatePid is referenced by '$($pidFile.FullName)', but its command line cannot be inspected. Retry with permission to query Win32_Process.CommandLine."
        }

        $jobRoot = Split-Path -Parent $pidFile.FullName
        $matchesProviderPidFile = $commandLine.IndexOf($pidFile.FullName, [StringComparison]::OrdinalIgnoreCase) -ge 0
        $matchesProviderRuntime = $commandLine.IndexOf($jobRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
        $expectedProcessVmName = Get-QemuExpectedProcessVmNameFromPidFile -PidFilePath $pidFile.FullName
        $matchesVm = Test-QemuCommandLineVmName -CommandLine $commandLine -ExpectedVmName $expectedProcessVmName
        $matchesForward = $commandLine.IndexOf($hostForwardIdentity, [StringComparison]::OrdinalIgnoreCase) -ge 0
        if ($matchesProviderPidFile -and $matchesProviderRuntime -and $matchesVm -and $matchesForward) {
            [void]$owned.Add([pscustomobject][ordered]@{
                ProcessId = $candidatePid
                PidMarkerPath = $pidFile.FullName
            })
        }
    }

    if ($owned.Count -eq 0) {
        throw "No active KSword-owned QEMU process matches VM '$VmName' and QemuUserNat port $HostPort. Start this configured QEMU VM through KSword WebUI/CLI, or use an explicit Configured endpoint, then retry."
    }
    if ($owned.Count -gt 1) {
        throw "QemuUserNat endpoint ownership is ambiguous: $($owned.Count) KSword QEMU processes match VM '$VmName' and port $HostPort. Stop duplicate runs before changing guest test-signing."
    }

    return $owned[0]
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

function Resolve-GuestRemotingEndpoint {
    if ($GuestRemotingAddressMode -eq 'Configured') {
        return [pscustomobject][ordered]@{
            Address = $GuestRemotingAddress.Trim()
            Port = [int]$GuestRemotingPort
            Source = 'configured'
            OwnerProcessId = $null
            OwnerPidMarkerPath = $null
        }
    }
    if ($GuestRemotingAddressMode -eq 'QemuUserNat') {
        $effectivePort = if ($GuestRemotingPort -gt 0) { [int]$GuestRemotingPort } elseif ($GuestRemotingUseSsl) { 55986 } else { 55985 }
        $owner = Resolve-QemuUserNatOwner -HostPort $effectivePort
        return [pscustomobject][ordered]@{
            Address = '127.0.0.1'
            Port = $effectivePort
            Source = 'provider-managed-user-nat-verified'
            OwnerProcessId = [int]$owner.ProcessId
            OwnerPidMarkerPath = [string]$owner.PidMarkerPath
        }
    }

    $vmrun = Resolve-Executable -ConfiguredPath $VMwareVmrunPath -DisplayName 'VMware vmrun'
    if (-not (Test-Path -LiteralPath $VMwareVmxPath -PathType Leaf)) {
        throw "VMware VMX was not found: $VMwareVmxPath"
    }
    $vmx = (Resolve-Path -LiteralPath $VMwareVmxPath).ProviderPath
    $deadline = (Get-Date).AddSeconds($GuestReadyTimeoutSeconds)
    $lastOutput = @()
    do {
        $lastOutput = @(& $vmrun -T $VMwareVmType getGuestIPAddress $vmx 2>&1)
        $exitCode = $LASTEXITCODE
        $address = Select-VMwareGuestAddress -Output $lastOutput
        if ($exitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($address)) {
            return [pscustomobject][ordered]@{
                Address = $address
                Port = [int]$GuestRemotingPort
                Source = 'vmware-tools-auto-discovery'
                OwnerProcessId = $null
                OwnerPidMarkerPath = $null
            }
        }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)

    throw "VMware Tools did not return a valid guest IP address within $GuestReadyTimeoutSeconds seconds. Last output: $($lastOutput -join ' ')"
}

if (-not (Get-Command Invoke-Command -ErrorAction SilentlyContinue)) {
    throw '错误：Invoke-Command 不可用。下一步：请确认当前是完整 PowerShell/Windows 环境，并启用了所选 provider 所需的 PowerShell 来宾传输。'
}

if ($VirtualizationProvider -ne 'HyperV' -and $GuestRemotingAddressMode -eq 'Configured' -and [string]::IsNullOrWhiteSpace($GuestRemotingAddress)) {
    throw "错误：$VirtualizationProvider 在 Configured 模式下需要 -GuestRemotingAddress；也可使用 provider 自动端点模式。"
}

$password = Get-GuestPasswordSecretValue -Name $SecretName
[Environment]::SetEnvironmentVariable($SecretName, $null, 'Process')
$credential = New-GuestCredential -UserName $GuestUserName -Password $password
$password = $null
$providerEnvironment = [Environment]::GetEnvironmentVariables('Process')
foreach ($providerEnvironmentKey in @($providerEnvironment.Keys)) {
    $providerEnvironmentName = [string]$providerEnvironmentKey
    if ($providerEnvironmentName.StartsWith('KSWORDBOX_', [StringComparison]::OrdinalIgnoreCase) -or
        $providerEnvironmentName -match '(?i)(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)') {
        [Environment]::SetEnvironmentVariable($providerEnvironmentName, $null, 'Process')
    }
}

$scriptBlock = {
    param(
        [string]$RequestedMode,
        [bool]$ShouldRestart,
        [string]$GuestProvider,
        [string]$GuestEndpointMode,
        [string]$GuestEndpointSource
    )

    $before = @(& bcdedit.exe /enum 2>&1)
    $beforeText = $before -join "`n"
    $beforeEnabled = $beforeText -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$'
    $bootTimeUtc = try {
        (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('O')
    }
    catch {
        ''
    }
    $changed = $false
    $commandOutput = @()

    if ($RequestedMode -eq 'Enable' -and -not $beforeEnabled) {
        $commandOutput = @(& bcdedit.exe /set testsigning on 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "错误：来宾内 bcdedit /set testsigning on 失败，退出码 $LASTEXITCODE。下一步：确认来宾系统允许修改启动配置，并以管理员上下文执行。英文输出：$($commandOutput -join ' ')"
        }
        $changed = $true
    }
    elseif ($RequestedMode -eq 'Disable' -and $beforeEnabled) {
        $commandOutput = @(& bcdedit.exe /set testsigning off 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "错误：来宾内 bcdedit /set testsigning off 失败，退出码 $LASTEXITCODE。下一步：确认来宾系统允许修改启动配置，并以管理员上下文执行。英文输出：$($commandOutput -join ' ')"
        }
        $changed = $true
    }

    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.GuestTestSigning'
        Provider = $GuestProvider
        ComputerName = $env:COMPUTERNAME
        RequestedMode = $RequestedMode
        TestSigningWasEnabled = $beforeEnabled
        Changed = $changed
        RestartRequired = $changed
        RestartRequested = $ShouldRestart
        RestartAttempted = $false
        RestartCompleted = $false
        BootTimeUtc = $bootTimeUtc
        PostRestartBootTimeUtc = $null
        PostRestartTestSigningEnabled = $null
        PostRestartProbeAttempts = 0
        GuestRemotingAddressMode = $GuestEndpointMode
        GuestRemotingAddressSource = $GuestEndpointSource
        CommandOutput = $commandOutput
        CSignToolUsed = $false
        GuestSecretEnvironmentCleared = $true
        ProviderChildSecretEnvironmentCleared = $true
        SecretValuePrinted = $false
    }
}

if (-not $Force -and $Mode -ne 'Query' -and $RestartGuest) {
    throw '错误：已请求 -RestartGuest，但未提供 -Force。下一步：确认允许来宾重启后，追加 -Force；只查询状态请使用 -Mode Query。'
}

function New-GuestInvokeParameterTable {
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$GuestCredential,
        [Parameter(Mandatory)][scriptblock]$GuestScriptBlock,
        [object[]]$GuestArgumentList = @(),
        [AllowNull()][object]$Endpoint
    )

    $parameters = @{
        Credential = $GuestCredential
        ScriptBlock = $GuestScriptBlock
        ErrorAction = 'Stop'
    }
    if (@($GuestArgumentList).Count -gt 0) {
        $parameters['ArgumentList'] = @($GuestArgumentList)
    }

    if ($VirtualizationProvider -eq 'HyperV') {
        $parameters['VMName'] = $VmName
    }
    else {
        if ($null -eq $Endpoint -or [string]::IsNullOrWhiteSpace([string]$Endpoint.Address)) {
            throw "$VirtualizationProvider guest endpoint is unavailable."
        }
        $parameters['ComputerName'] = [string]$Endpoint.Address
        $parameters['Authentication'] = $GuestRemotingAuthentication
        if ([int]$Endpoint.Port -gt 0) {
            $parameters['Port'] = [int]$Endpoint.Port
        }
        if ($GuestRemotingUseSsl) {
            $parameters['UseSSL'] = $true
        }
        if ($GuestRemotingSkipCertificateChecks) {
            $parameters['SessionOption'] = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        }
    }

    return $parameters
}

$target = if ($VirtualizationProvider -eq 'HyperV') { $VmName } elseif ($GuestRemotingAddressMode -eq 'Configured') { $GuestRemotingAddress } else { "${VirtualizationProvider}::${GuestRemotingAddressMode}::${VmName}" }
$result = if ($PSCmdlet.ShouldProcess($target, "在 $VirtualizationProvider 来宾中运行 bcdedit test-signing 模式 '$Mode' / Run guest bcdedit test-signing mode")) {
    $guestEndpoint = if ($VirtualizationProvider -eq 'HyperV') {
        [pscustomobject][ordered]@{ Address = ''; Port = 0; Source = 'vm-name'; OwnerProcessId = $null; OwnerPidMarkerPath = $null }
    }
    else {
        Resolve-GuestRemotingEndpoint
    }
    $invokeParameters = @{
        Credential = $credential
        ScriptBlock = $scriptBlock
        ArgumentList = @($Mode, ([bool]$RestartGuest), $VirtualizationProvider, $(if ($VirtualizationProvider -eq 'HyperV') { 'PowerShellDirect' } else { $GuestRemotingAddressMode }), $guestEndpoint.Source)
        ErrorAction = 'Stop'
    }

    if ($VirtualizationProvider -eq 'HyperV') {
        $invokeParameters['VMName'] = $VmName
    }
    else {
        $invokeParameters['ComputerName'] = $guestEndpoint.Address
        $invokeParameters['Authentication'] = $GuestRemotingAuthentication
        if ($guestEndpoint.Port -gt 0) {
            $invokeParameters['Port'] = $guestEndpoint.Port
        }
        if ($GuestRemotingUseSsl) {
            $invokeParameters['UseSSL'] = $true
        }
        if ($GuestRemotingSkipCertificateChecks) {
            $invokeParameters['SessionOption'] = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        }
    }

    $changeResults = @(Invoke-Command @invokeParameters)
    if ($changeResults.Count -ne 1) {
        throw "Guest test-signing change returned $($changeResults.Count) result objects; expected exactly one."
    }
    $changeResult = $changeResults[0]
    $changeResult | Add-Member -NotePropertyName GuestRemotingOwnerProcessId -NotePropertyValue $guestEndpoint.OwnerProcessId -Force
    $changeResult | Add-Member -NotePropertyName GuestRemotingOwnerPidMarkerPath -NotePropertyValue $guestEndpoint.OwnerPidMarkerPath -Force

    if ([bool]$changeResult.Changed -and [bool]$RestartGuest) {
        $restartScriptBlock = {
            $shutdownOutput = @(& shutdown.exe /r /t 0 /f 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Guest shutdown.exe restart failed with exit code $LASTEXITCODE. $($shutdownOutput -join ' ')"
            }
        }
        $restartParameters = New-GuestInvokeParameterTable `
            -GuestCredential $credential `
            -GuestScriptBlock $restartScriptBlock `
            -Endpoint $guestEndpoint
        $restartDispatchMessage = ''
        try {
            Invoke-Command @restartParameters | Out-Null
        }
        catch {
            # A successful guest restart commonly closes PowerShell Direct/WinRM
            # before Invoke-Command can return. The boot-time probe below is the
            # authoritative completion check.
            $restartDispatchMessage = $_.Exception.Message
        }

        $expectedEnabled = $Mode -eq 'Enable'
        $restartDeadline = (Get-Date).AddSeconds($GuestReadyTimeoutSeconds)
        $probeAttempts = 0
        $postRestartProbe = $null
        $lastProbeError = ''
        $probeScriptBlock = {
            $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('O')
            $bcdOutput = @(& bcdedit.exe /enum 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Guest bcdedit query failed with exit code $LASTEXITCODE. $($bcdOutput -join ' ')"
            }
            [pscustomobject][ordered]@{
                ComputerName = $env:COMPUTERNAME
                BootTimeUtc = $bootTime
                TestSigningEnabled = (($bcdOutput -join "`n") -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$')
            }
        }

        do {
            $probeAttempts++
            Start-Sleep -Seconds 2
            try {
                $probeEndpoint = if ($VirtualizationProvider -eq 'HyperV') {
                    [pscustomobject][ordered]@{ Address = ''; Port = 0; Source = 'vm-name'; OwnerProcessId = $null; OwnerPidMarkerPath = $null }
                }
                else {
                    Resolve-GuestRemotingEndpoint
                }
                $probeParameters = New-GuestInvokeParameterTable `
                    -GuestCredential $credential `
                    -GuestScriptBlock $probeScriptBlock `
                    -Endpoint $probeEndpoint
                $probeResults = @(Invoke-Command @probeParameters)
                if ($probeResults.Count -ne 1) {
                    throw "Post-restart probe returned $($probeResults.Count) result objects; expected exactly one."
                }
                $candidate = $probeResults[0]
                $bootChanged = -not [string]::IsNullOrWhiteSpace([string]$changeResult.BootTimeUtc) -and
                    -not [string]::IsNullOrWhiteSpace([string]$candidate.BootTimeUtc) -and
                    -not ([string]$candidate.BootTimeUtc).Equals([string]$changeResult.BootTimeUtc, [StringComparison]::OrdinalIgnoreCase)
                $stateMatches = [bool]$candidate.TestSigningEnabled -eq $expectedEnabled
                if ($bootChanged -and $stateMatches) {
                    $postRestartProbe = $candidate
                    break
                }
                $lastProbeError = "Guest is reachable but restart completion is not proven: bootChanged=$bootChanged, testSigningEnabled=$($candidate.TestSigningEnabled), expected=$expectedEnabled."
            }
            catch {
                $lastProbeError = $_.Exception.Message
            }
        } while ((Get-Date) -lt $restartDeadline)

        if ($null -eq $postRestartProbe) {
            $dispatchDetail = if ([string]::IsNullOrWhiteSpace($restartDispatchMessage)) { 'restart command returned without a transport error' } else { "restart transport closed: $restartDispatchMessage" }
            throw "Guest restart was requested for $VirtualizationProvider but was not verified within $GuestReadyTimeoutSeconds seconds. $dispatchDetail. Last probe: $lastProbeError. Confirm the VM restarted, the provider endpoint is reachable, and rerun -Mode Query."
        }

        $changeResult | Add-Member -NotePropertyName RestartAttempted -NotePropertyValue $true -Force
        $changeResult | Add-Member -NotePropertyName RestartCompleted -NotePropertyValue $true -Force
        $changeResult | Add-Member -NotePropertyName PostRestartBootTimeUtc -NotePropertyValue ([string]$postRestartProbe.BootTimeUtc) -Force
        $changeResult | Add-Member -NotePropertyName PostRestartTestSigningEnabled -NotePropertyValue ([bool]$postRestartProbe.TestSigningEnabled) -Force
        $changeResult | Add-Member -NotePropertyName PostRestartProbeAttempts -NotePropertyValue $probeAttempts -Force
        $changeResult | Add-Member -NotePropertyName ComputerName -NotePropertyValue ([string]$postRestartProbe.ComputerName) -Force
    }
    elseif ([bool]$RestartGuest -and -not [bool]$changeResult.RestartRequired) {
        $changeResult | Add-Member -NotePropertyName RestartCompleted -NotePropertyValue $true -Force
        $changeResult | Add-Member -NotePropertyName PostRestartBootTimeUtc -NotePropertyValue ([string]$changeResult.BootTimeUtc) -Force
        $changeResult | Add-Member -NotePropertyName PostRestartTestSigningEnabled -NotePropertyValue ([bool]$changeResult.TestSigningWasEnabled) -Force
    }

    $changeResult
}
else {
    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.GuestTestSigning'
        Provider = $VirtualizationProvider
        ComputerName = $null
        RequestedMode = $Mode
        TestSigningWasEnabled = $null
        Changed = $false
        RestartRequired = $false
        RestartRequested = [bool]$RestartGuest
        RestartAttempted = $false
        RestartCompleted = $false
        BootTimeUtc = $null
        PostRestartBootTimeUtc = $null
        PostRestartTestSigningEnabled = $null
        PostRestartProbeAttempts = 0
        GuestRemotingAddressMode = if ($VirtualizationProvider -eq 'HyperV') { 'PowerShellDirect' } else { $GuestRemotingAddressMode }
        GuestRemotingAddressSource = if ($VirtualizationProvider -eq 'HyperV') { 'vm-name' } elseif ($GuestRemotingAddressMode -eq 'VMwareTools') { 'vmware-tools-auto-discovery' } elseif ($GuestRemotingAddressMode -eq 'QemuUserNat') { 'provider-managed-user-nat' } else { 'configured' }
        GuestRemotingOwnerProcessId = $null
        GuestRemotingOwnerPidMarkerPath = $null
        WhatIf = [bool]$WhatIfPreference
        CommandOutput = @()
        CSignToolUsed = $false
        GuestSecretEnvironmentCleared = $true
        ProviderChildSecretEnvironmentCleared = $true
        SecretValuePrinted = $false
    }
}

if ($Json) {
    $result | ConvertTo-Json -Depth 8
}
else {
    $result
}
