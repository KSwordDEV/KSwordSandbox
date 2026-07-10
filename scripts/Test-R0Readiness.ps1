<#
.SYNOPSIS
Runs non-destructive R0 driver readiness checks before a real VM validation.

.DESCRIPTION
Default mode checks only local files, public R0 IOCTL contract text, read
permissions, Authenticode signing metadata, Administrator status, test-signing
boot configuration, and read-only SCM service state. It never loads, unloads,
installs, deletes, or opens the driver device unless the caller supplies
explicit parameters.

Service mutation requires both the operation switch and -AllowServiceMutation.
Device health and R0Collector drain checks are opt-in and assume the caller has
already loaded the driver in an isolated test VM.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = '',
    [string]$DriverSysPath,
    [string]$R0CollectorPath,
    [string]$ServiceName = 'KSwordSandboxDriver',
    [string]$DevicePath = '\\.\KSwordSandboxDriver',
    [switch]$SkipTestSigningRequirement,
    [switch]$AllowServiceMutation,
    [switch]$InstallService,
    [switch]$StartService,
    [switch]$StopService,
    [switch]$DeleteService,
    [switch]$CheckDeviceHealth,
    [switch]$CheckCollectorHealth,
    [switch]$DrainWithCollector,
    [string]$CollectorHealthOutputPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'KSwordSandbox-r0collector-health-readiness.jsonl'),
    [string]$CollectorOutputPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'KSwordSandbox-r0collector-readiness.jsonl')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$testSigningRequired = -not [bool]$SkipTestSigningRequirement

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

if (-not $PSBoundParameters.ContainsKey('DriverSysPath')) {
    $DriverSysPath = Join-Path $RepositoryRoot 'driver\KSword.Sandbox.Driver\x64\Debug\KSword.Sandbox.Driver.sys'
}

if (-not $PSBoundParameters.ContainsKey('R0CollectorPath')) {
    $R0CollectorPath = Join-Path $RepositoryRoot 'guest\KSword.Sandbox.R0Collector\bin\x64\Debug\KSword.Sandbox.R0Collector.exe'
}

# New-R0ReadinessResult builds a structured result row.
# Inputs are check name, status, required flag, message, and optional details.
# Processing copies details to an ordered object for JSON friendliness. Return
# behavior is a PSCustomObject with no side effects.
function New-R0ReadinessResult {
    param(
        [string]$Name,
        [ValidateSet('Passed', 'Warning', 'Failed')]
        [string]$Status,
        [bool]$Required,
        [string]$Message,
        [System.Collections.IDictionary]$Details = @{}
    )

    $orderedDetails = [ordered]@{}
    foreach ($key in $Details.Keys) {
        $orderedDetails[$key] = $Details[$key]
    }

    return [pscustomobject][ordered]@{
        ResultType = 'R0ReadinessCheck'
        Name       = $Name
        Status     = $Status
        Required   = $Required
        Message    = $Message
        Details    = [pscustomobject]$orderedDetails
    }
}

# Test-AdministratorPrivilege checks whether this shell can perform later
# explicit service-control operations. It never changes system state.
function Test-AdministratorPrivilege {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $isAdministrator = $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdministrator) {
            return New-R0ReadinessResult `
                -Name 'Administrator privilege' `
                -Status 'Passed' `
                -Required $true `
                -Message 'Current PowerShell process is elevated.' `
                -Details @{
                    UserName        = $identity.Name
                    IsAdministrator = $true
                }
        }

        return New-R0ReadinessResult `
            -Name 'Administrator privilege' `
            -Status 'Failed' `
            -Required $true `
            -Message 'Current PowerShell process is not elevated; service install/start/stop/delete and loaded-driver IOCTL checks usually require Administrator rights.' `
            -Details @{
                UserName        = $identity.Name
                IsAdministrator = $false
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'Administrator privilege' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to determine Administrator status: $($_.Exception.Message)" `
            -Details @{
                ErrorType = $_.Exception.GetType().FullName
            }
    }
}

# Test-RepositoryFile checks that a required source-side file exists.
# Inputs are label and path. Processing uses Test-Path/Get-Item only. Return
# behavior is a readiness object.
function Test-RepositoryFile {
    param(
        [string]$Name,
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $item = Get-Item -LiteralPath $Path
        return New-R0ReadinessResult `
            -Name $Name `
            -Status 'Passed' `
            -Required $true `
            -Message "Required repository file exists: $($item.FullName)" `
            -Details @{
                Path   = $item.FullName
                Length = $item.Length
            }
    }

    return New-R0ReadinessResult `
        -Name $Name `
        -Status 'Failed' `
        -Required $true `
        -Message "Required repository file is missing: $Path" `
        -Details @{
            Path = $Path
        }
}

# Test-TextContractFragments checks that a repository text file contains all
# required fragments for a static contract. It is read-only and never treats
# kernel/collector runtime availability as evidence.
function Test-TextContractFragments {
    param(
        [string]$Label,
        [string]$Path,
        [string[]]$Fragments,
        [System.Collections.Generic.List[string]]$MissingFragments,
        [System.Collections.Generic.List[string]]$CheckedFiles
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        [void]$MissingFragments.Add(('{0}: missing file ''{1}''' -f $Label, $Path))
        return
    }

    [void]$CheckedFiles.Add($Path)
    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    foreach ($fragment in $Fragments) {
        if (-not $content.Contains($fragment)) {
            [void]$MissingFragments.Add(('{0}: missing ''{1}''' -f $Label, $fragment))
        }
    }
}

# Test-R0CapabilityIoctlStaticContract verifies that the new negotiated R0
# runtime ABI is represented consistently across the public header, driver
# dispatch source, collector source, and operator docs. This is a static,
# non-destructive check: it does not load the service or open the device.
function Test-R0CapabilityIoctlStaticContract {
    param(
        [string]$DriverHeaderPath,
        [string]$DriverDispatchPath,
        [string]$DriverEventQueuePath,
        [string]$CollectorIoctlClientPath,
        [string]$CollectorEventParserPath,
        [string]$CollectorRuntimeLoopPath,
        [string]$DriverSigningDocPath,
        [string]$R0CollectorDocPath
    )

    $missing = New-Object System.Collections.Generic.List[string]
    $checkedFiles = New-Object System.Collections.Generic.List[string]

    Test-TextContractFragments `
        -Label 'Driver public IOCTL header' `
        -Path $DriverHeaderPath `
        -Fragments @(
            'IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES',
            'IOCTL_KSWORD_SANDBOX_GET_STATUS',
            'IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK',
            'KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES',
            'KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS',
            'KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK',
            'KSWORD_SANDBOX_CAPABILITIES_REPLY',
            'KSWORD_SANDBOX_STATUS_REPLY',
            'KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST',
            'KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY',
            'SupportedProducerMask',
            'ProducerEnableMask',
            'TotalEventsSuppressed',
            'SetProducerEnableMaskRequestSize'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    Test-TextContractFragments `
        -Label 'Driver IOCTL dispatch' `
        -Path $DriverDispatchPath `
        -Fragments @(
            'case IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES',
            'case IOCTL_KSWORD_SANDBOX_GET_STATUS',
            'case IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK',
            'KswHandleGetCapabilities',
            'KswHandleGetStatus',
            'KswHandleSetProducerEnableMask',
            'KswSetProducerEnableMask',
            'STATUS_INVALID_PARAMETER'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    Test-TextContractFragments `
        -Label 'Driver event queue producer mask' `
        -Path $DriverEventQueuePath `
        -Fragments @(
            'KswSetProducerEnableMask',
            'KswGetProducerMaskForEventType',
            'ProducerEnableMask',
            'EventsSuppressed'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    Test-TextContractFragments `
        -Label 'R0Collector IOCTL client' `
        -Path $CollectorIoctlClientPath `
        -Fragments @(
            'EmitDriverCapabilities',
            'EmitDriverStatus',
            'EmitDriverSetProducerEnableMask',
            'IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES',
            'IOCTL_KSWORD_SANDBOX_GET_STATUS',
            'IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK',
            'r0collector.driverCapabilities',
            'r0collector.driverStatus',
            'r0collector.driverProducerMask',
            'options.enableMaskSpecified'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    Test-TextContractFragments `
        -Label 'R0Collector event parser' `
        -Path $CollectorEventParserPath `
        -Fragments @(
            'BuildCapabilitiesData',
            'BuildStatusData',
            'BuildSetProducerEnableMaskData',
            'supportedProducerMask',
            'producerEnableMask',
            'effectiveEnableMask',
            'requestedEnableMask'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    Test-TextContractFragments `
        -Label 'R0Collector runtime loop' `
        -Path $CollectorRuntimeLoopPath `
        -Fragments @(
            'EmitDriverCapabilities',
            'EmitDriverSetProducerEnableMask',
            'EmitDriverStatus'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    Test-TextContractFragments `
        -Label 'Driver signing runbook' `
        -Path $DriverSigningDocPath `
        -Fragments @(
            'IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES',
            'IOCTL_KSWORD_SANDBOX_GET_STATUS',
            'IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK',
            'r0collector.driverCapabilities',
            'r0collector.driverStatus',
            'r0collector.driverProducerMask',
            'non-fatal diagnostics'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    Test-TextContractFragments `
        -Label 'R0Collector runbook' `
        -Path $R0CollectorDocPath `
        -Fragments @(
            'Capability/status/producer-mask negotiation',
            'IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES',
            'IOCTL_KSWORD_SANDBOX_GET_STATUS',
            'IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK',
            'r0collector.driverCapabilities',
            'r0collector.driverStatus',
            'r0collector.driverProducerMask',
            'non-fatal diagnostics'
        ) `
        -MissingFragments $missing `
        -CheckedFiles $checkedFiles

    $passed = $missing.Count -eq 0
    return New-R0ReadinessResult `
        -Name 'R0 capability/status IOCTL static contract' `
        -Status ($(if ($passed) { 'Passed' } else { 'Failed' })) `
        -Required $true `
        -Message ($(if ($passed) { 'Static contract references for GET_CAPABILITIES, GET_STATUS, and SET_PRODUCER_ENABLE_MASK are present.' } else { 'One or more static contract references for negotiated R0 IOCTL readiness are missing.' })) `
        -Details @{
            StaticOnly       = $true
            OpensDevice      = $false
            MutatesDriver    = $false
            CheckedFiles     = @($checkedFiles.ToArray())
            MissingFragments = @($missing.ToArray())
            Ioctls           = @(
                'IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES',
                'IOCTL_KSWORD_SANDBOX_GET_STATUS',
                'IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK'
            )
            CollectorRows    = @(
                'r0collector.driverCapabilities',
                'r0collector.driverStatus',
                'r0collector.driverProducerMask'
            )
        }
}

# Test-DriverSysGitHygiene verifies that kernel-driver binaries are not tracked,
# staged, or otherwise visible to git as commit candidates. Ignored local .sys
# files are not enumerated; the preferred path is to keep signed drivers outside
# the repository entirely.
function Test-DriverSysGitHygiene {
    param([string]$Root)

    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) {
        return New-R0ReadinessResult `
            -Name 'Driver .sys git hygiene' `
            -Status 'Failed' `
            -Required $true `
            -Message 'git.exe was not found, so the script cannot verify that driver .sys files are excluded from commits.' `
            -Details @{
                RepositoryRoot = $Root
                GitAvailable   = $false
            }
    }

    try {
        $repoOutput = @(& git -C $Root rev-parse --is-inside-work-tree 2>&1)
        $repoExitCode = $LASTEXITCODE
        if ($repoExitCode -ne 0 -or (($repoOutput | Select-Object -First 1) -ne 'true')) {
            return New-R0ReadinessResult `
                -Name 'Driver .sys git hygiene' `
                -Status 'Failed' `
                -Required $true `
                -Message "Repository root '$Root' is not inside a git work tree; cannot prove driver .sys files are excluded from commits." `
                -Details @{
                    RepositoryRoot = $Root
                    GitAvailable   = $true
                    ExitCode       = $repoExitCode
                    Output         = (($repoOutput | Out-String).Trim())
                }
        }

        $trackedOutput = @(& git -C $Root ls-files -- '*.sys' 2>&1)
        $trackedExitCode = $LASTEXITCODE
        $statusOutput = @(& git -C $Root status --porcelain=v1 -- '*.sys' 2>&1)
        $statusExitCode = $LASTEXITCODE

        if ($trackedExitCode -ne 0 -or $statusExitCode -ne 0) {
            return New-R0ReadinessResult `
                -Name 'Driver .sys git hygiene' `
                -Status 'Failed' `
                -Required $true `
                -Message 'git returned an error while checking .sys tracking/status.' `
                -Details @{
                    RepositoryRoot  = $Root
                    GitAvailable    = $true
                    TrackedExitCode = $trackedExitCode
                    TrackedOutput   = (($trackedOutput | Out-String).Trim())
                    StatusExitCode  = $statusExitCode
                    StatusOutput    = (($statusOutput | Out-String).Trim())
                }
        }

        $trackedSys = @($trackedOutput | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $statusSys = @($statusOutput | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $gitIgnorePath = Join-Path $Root '.gitignore'
        $gitIgnoreHasSysRule = $false
        if (Test-Path -LiteralPath $gitIgnorePath -PathType Leaf) {
            $gitIgnoreHasSysRule = [bool](Select-String -LiteralPath $gitIgnorePath -Pattern '^\s*\*\.sys\s*$' -Quiet)
        }

        if ($trackedSys.Count -gt 0 -or $statusSys.Count -gt 0) {
            return New-R0ReadinessResult `
                -Name 'Driver .sys git hygiene' `
                -Status 'Failed' `
                -Required $true `
                -Message 'One or more .sys files are tracked, staged, modified, or unignored by git. Remove them from the commit path and keep signed driver binaries outside git.' `
                -Details @{
                    RepositoryRoot      = $Root
                    GitAvailable        = $true
                    TrackedSysPaths     = @($trackedSys)
                    PorcelainSysEntries = @($statusSys)
                    GitIgnoreHasSysRule = $gitIgnoreHasSysRule
                }
        }

        return New-R0ReadinessResult `
            -Name 'Driver .sys git hygiene' `
            -Status 'Passed' `
            -Required $true `
            -Message 'No .sys files are tracked, staged, modified, or unignored by git for this repository.' `
            -Details @{
                RepositoryRoot      = $Root
                GitAvailable        = $true
                TrackedSysCount     = 0
                PorcelainSysCount   = 0
                GitIgnoreHasSysRule = $gitIgnoreHasSysRule
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'Driver .sys git hygiene' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to verify .sys git hygiene: $($_.Exception.Message)" `
            -Details @{
                RepositoryRoot = $Root
                GitAvailable   = $true
                ErrorType      = $_.Exception.GetType().FullName
            }
    }
}

# Test-ReadableFile checks that a runtime artifact exists and can be opened for
# reading. It does not write or execute the file.
function Test-ReadableFile {
    param(
        [string]$Name,
        [string]$Path,
        [bool]$Required
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return New-R0ReadinessResult `
            -Name $Name `
            -Status ($(if ($Required) { 'Failed' } else { 'Warning' })) `
            -Required $Required `
            -Message "File was not found: $Path" `
            -Details @{
                Path   = $Path
                Exists = $false
            }
    }

    $stream = $null
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $stream = [System.IO.File]::Open(
            $item.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite)

        return New-R0ReadinessResult `
            -Name $Name `
            -Status 'Passed' `
            -Required $Required `
            -Message "File exists and can be opened for read: $($item.FullName)" `
            -Details @{
                Path   = $item.FullName
                Exists = $true
                Length = $item.Length
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name $Name `
            -Status ($(if ($Required) { 'Failed' } else { 'Warning' })) `
            -Required $Required `
            -Message "File exists but cannot be opened for read: $($_.Exception.Message)" `
            -Details @{
                Path      = $Path
                Exists    = $true
                ErrorType = $_.Exception.GetType().FullName
            }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

# Test-DriverSignature reads Authenticode metadata for the .sys file. It does
# not trust or install certificates.
function Test-DriverSignature {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return New-R0ReadinessResult `
            -Name 'Driver Authenticode signature' `
            -Status 'Failed' `
            -Required $true `
            -Message "Driver binary is missing, so signature metadata cannot be inspected: $Path" `
            -Details @{
                DriverSysPath = $Path
            }
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $statusText = $signature.Status.ToString()
        $isSigned = $statusText -ne 'NotSigned'
        $isUsable = $statusText -eq 'Valid'

        if ($isUsable) {
            return New-R0ReadinessResult `
                -Name 'Driver Authenticode signature' `
                -Status 'Passed' `
                -Required $true `
                -Message "Driver signature status is Valid for '$Path'." `
                -Details @{
                    DriverSysPath = $Path
                    Status        = $statusText
                    Subject       = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
                    Thumbprint    = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
                }
        }

        return New-R0ReadinessResult `
            -Name 'Driver Authenticode signature' `
            -Status ($(if ($isSigned) { 'Warning' } else { 'Failed' })) `
            -Required $true `
            -Message "Driver signature status is '$statusText'. Test VMs must trust the signer and enable test-signing for non-production certs." `
            -Details @{
                DriverSysPath = $Path
                Status        = $statusText
                Subject       = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
                Thumbprint    = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'Driver Authenticode signature' `
            -Status 'Failed' `
            -Required $true `
            -Message "Unable to inspect driver signature: $($_.Exception.Message)" `
            -Details @{
                DriverSysPath = $Path
                ErrorType     = $_.Exception.GetType().FullName
            }
    }
}

# Test-TestSigningState reads BCDEdit state. It does not modify boot settings.
function Test-TestSigningState {
    param([bool]$Required)

    try {
        $output = @(& bcdedit.exe /enum 2>&1)
        $exitCode = $LASTEXITCODE
        $text = ($output | Out-String)
        if ($exitCode -ne 0) {
            return New-R0ReadinessResult `
                -Name 'Windows test-signing boot option' `
                -Status ($(if ($Required) { 'Failed' } else { 'Warning' })) `
                -Required $Required `
                -Message "bcdedit.exe returned exit code $exitCode while reading test-signing state." `
                -Details @{
                    ExitCode = $exitCode
                    Output   = $text.Trim()
                }
        }

        $enabled = $text -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$'
        if ($enabled) {
            return New-R0ReadinessResult `
                -Name 'Windows test-signing boot option' `
                -Status 'Passed' `
                -Required $Required `
                -Message 'BCDEdit reports testsigning enabled for the current boot entry.' `
                -Details @{
                    TestSigningEnabled = $true
                    MutatedBootConfig  = $false
                }
        }

        return New-R0ReadinessResult `
            -Name 'Windows test-signing boot option' `
            -Status ($(if ($Required) { 'Failed' } else { 'Warning' })) `
            -Required $Required `
            -Message 'BCDEdit did not report testsigning enabled. Run "bcdedit /set testsigning on" and reboot inside an isolated test VM before loading a test-signed driver.' `
            -Details @{
                TestSigningEnabled = $false
                MutatedBootConfig  = $false
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'Windows test-signing boot option' `
            -Status ($(if ($Required) { 'Failed' } else { 'Warning' })) `
            -Required $Required `
            -Message "Unable to query BCDEdit test-signing state: $($_.Exception.Message)" `
            -Details @{
                ErrorType = $_.Exception.GetType().FullName
            }
    }
}

# Test-ServiceState performs read-only SCM inspection for the configured kernel
# service name. It never creates, starts, stops, or deletes services.
function Test-ServiceState {
    param([string]$Name)

    try {
        $output = @(& sc.exe query $Name 2>&1)
        $exitCode = $LASTEXITCODE
        $text = ($output | Out-String).Trim()
        if ($exitCode -ne 0) {
            return New-R0ReadinessResult `
                -Name 'Kernel service state' `
                -Status 'Warning' `
                -Required $false `
                -Message "Service '$Name' is not queryable yet. Install it only in a test VM when ready to load the driver." `
                -Details @{
                    ServiceName = $Name
                    ExitCode    = $exitCode
                    Output      = $text
                    MutatedScm  = $false
                }
        }

        $stateLine = @($output | Where-Object { $_ -match '^\s*STATE\s*:' } | Select-Object -First 1)
        return New-R0ReadinessResult `
            -Name 'Kernel service state' `
            -Status 'Passed' `
            -Required $false `
            -Message "Service '$Name' is queryable. $($stateLine -join '')" `
            -Details @{
                ServiceName = $Name
                ExitCode    = $exitCode
                StateLine   = ($stateLine -join '')
                MutatedScm  = $false
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'Kernel service state' `
            -Status 'Warning' `
            -Required $false `
            -Message "Unable to query service '$Name': $($_.Exception.Message)" `
            -Details @{
                ServiceName = $Name
                ErrorType   = $_.Exception.GetType().FullName
                MutatedScm  = $false
            }
    }
}

# Invoke-ServiceMutation performs explicit SCM operations only when gated by
# -AllowServiceMutation and a specific operation switch.
function Invoke-ServiceMutation {
    param(
        [ValidateSet('install', 'start', 'stop', 'delete')]
        [string]$Operation
    )

    if (-not $AllowServiceMutation) {
        return New-R0ReadinessResult `
            -Name "Service $Operation" `
            -Status 'Failed' `
            -Required $true `
            -Message "Skipped service $Operation because -AllowServiceMutation was not supplied." `
            -Details @{
                ServiceName          = $ServiceName
                DriverSysPath        = $DriverSysPath
                RequestedOperation   = $Operation
                ServiceStateMutated  = $false
                RequiresExplicitGate = $true
            }
    }

    try {
        switch ($Operation) {
            'install' {
                $output = @(& sc.exe create $ServiceName type= kernel start= demand binPath= $DriverSysPath 2>&1)
                break
            }
            'start' {
                $output = @(& sc.exe start $ServiceName 2>&1)
                break
            }
            'stop' {
                $output = @(& sc.exe stop $ServiceName 2>&1)
                break
            }
            'delete' {
                $output = @(& sc.exe delete $ServiceName 2>&1)
                break
            }
        }

        $exitCode = $LASTEXITCODE
        $status = if ($exitCode -eq 0) { 'Passed' } else { 'Failed' }
        return New-R0ReadinessResult `
            -Name "Service $Operation" `
            -Status $status `
            -Required $true `
            -Message "sc.exe $Operation for '$ServiceName' returned exit code $exitCode." `
            -Details @{
                ServiceName         = $ServiceName
                DriverSysPath       = $DriverSysPath
                RequestedOperation  = $Operation
                ExitCode            = $exitCode
                Output              = (($output | Out-String).Trim())
                ServiceStateMutated = $true
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name "Service $Operation" `
            -Status 'Failed' `
            -Required $true `
            -Message "Service $Operation failed: $($_.Exception.Message)" `
            -Details @{
                ServiceName        = $ServiceName
                DriverSysPath      = $DriverSysPath
                RequestedOperation = $Operation
                ErrorType          = $_.Exception.GetType().FullName
            }
    }
}

# Add-KswNativeIoctlType defines P/Invoke wrappers only when the caller asks for
# device health. This check opens the already-loaded device and issues the
# public GET_HEALTH IOCTL; it never loads the driver.
function Add-KswNativeIoctlType {
    if ('KswSandbox.R0Readiness.NativeIoctl' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace KswSandbox.R0Readiness
{
    public static class NativeIoctl
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
            SafeFileHandle device,
            uint ioControlCode,
            byte[] inBuffer,
            int inBufferSize,
            byte[] outBuffer,
            int outBufferSize,
            out int bytesReturned,
            IntPtr overlapped);
    }
}
'@
}

# Invoke-DeviceHealthCheck opens the existing Win32 device and sends
# IOCTL_KSWORD_SANDBOX_GET_HEALTH. It is opt-in and does not load the service.
function Invoke-DeviceHealthCheck {
    param([string]$Path)

    try {
        Add-KswNativeIoctlType
        $genericRead = [uint32]0x80000000
        $shareReadWrite = [uint32]3
        $openExisting = [uint32]3
        $ioctlGetHealth = [uint32]0x80006000
        $outBuffer = New-Object byte[] 80
        $bytesReturned = 0

        $handle = [KswSandbox.R0Readiness.NativeIoctl]::CreateFile(
            $Path,
            $genericRead,
            $shareReadWrite,
            [IntPtr]::Zero,
            $openExisting,
            [uint32]0,
            [IntPtr]::Zero)

        if ($handle.IsInvalid) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            return New-R0ReadinessResult `
                -Name 'Device IOCTL health' `
                -Status 'Failed' `
                -Required $true `
                -Message "Unable to open driver device '$Path'. Win32 error $errorCode." `
            -Details @{
                DevicePath = $Path
                Win32Error = $errorCode
                DeviceOpened = $false
                DriverLoadedByScript = $false
            }
        }

        try {
            $ok = [KswSandbox.R0Readiness.NativeIoctl]::DeviceIoControl(
                $handle,
                $ioctlGetHealth,
                $null,
                0,
                $outBuffer,
                $outBuffer.Length,
                [ref]$bytesReturned,
                [IntPtr]::Zero)

            if (-not $ok) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                return New-R0ReadinessResult `
                    -Name 'Device IOCTL health' `
                    -Status 'Failed' `
                    -Required $true `
                    -Message "IOCTL_KSWORD_SANDBOX_GET_HEALTH failed. Win32 error $errorCode." `
                    -Details @{
                        DevicePath = $Path
                        IoctlCode  = ('0x{0:X8}' -f $ioctlGetHealth)
                        Win32Error = $errorCode
                    }
            }

            $version = [BitConverter]::ToUInt32($outBuffer, 0)
            $size = [BitConverter]::ToUInt32($outBuffer, 4)
            $driverState = [BitConverter]::ToUInt32($outBuffer, 8)
            $eventsQueued = [BitConverter]::ToUInt64($outBuffer, 16)
            $eventsDropped = [BitConverter]::ToUInt64($outBuffer, 24)
            $nextSequence = [BitConverter]::ToUInt64($outBuffer, 32)
            $lastNtStatus = [BitConverter]::ToInt32($outBuffer, 40)

            return New-R0ReadinessResult `
                -Name 'Device IOCTL health' `
                -Status 'Passed' `
                -Required $true `
                -Message "IOCTL_KSWORD_SANDBOX_GET_HEALTH succeeded with $bytesReturned bytes." `
                -Details @{
                    DevicePath    = $Path
                    IoctlCode     = ('0x{0:X8}' -f $ioctlGetHealth)
                    BytesReturned = $bytesReturned
                    DeviceOpened  = $true
                    Version       = ('0x{0:X8}' -f $version)
                    Size          = $size
                    DriverState   = $driverState
                    EventsQueued  = $eventsQueued
                    EventsDropped = $eventsDropped
                    NextSequence  = $nextSequence
                    LastNtStatus  = ('0x{0:X8}' -f ([uint32]$lastNtStatus))
                }
        }
        finally {
            $handle.Dispose()
        }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'Device IOCTL health' `
            -Status 'Failed' `
            -Required $true `
            -Message "Device health check failed: $($_.Exception.Message)" `
            -Details @{
                DevicePath = $Path
                ErrorType  = $_.Exception.GetType().FullName
            }
    }
}

# Get-JsonLineEventSummary parses a collector JSONL output file enough to prove
# that the expected lifecycle rows were written. It is read-only and keeps only
# event type names plus a small parse-error sample for diagnostics.
function Get-JsonLineEventSummary {
    param([string]$Path)

    $summary = [ordered]@{
        OutputExists     = $false
        OutputLength     = 0
        LineCount        = 0
        EventTypes       = @()
        ParseErrorCount  = 0
        ParseErrorSample = @()
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $summary
    }

    $item = Get-Item -LiteralPath $Path
    $summary.OutputExists = $true
    $summary.OutputLength = $item.Length

    $eventTypes = New-Object System.Collections.Generic.List[string]
    $parseErrors = New-Object System.Collections.Generic.List[string]
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $summary.LineCount = [int]$summary.LineCount + 1
        try {
            $row = $line | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $row.eventType -and -not [string]::IsNullOrWhiteSpace([string]$row.eventType)) {
                [void]$eventTypes.Add([string]$row.eventType)
            }
            else {
                [void]$parseErrors.Add("Line $($summary.LineCount): missing eventType")
            }
        }
        catch {
            [void]$parseErrors.Add("Line $($summary.LineCount): $($_.Exception.Message)")
        }
    }

    $summary.EventTypes = @($eventTypes.ToArray())
    $summary.ParseErrorCount = $parseErrors.Count
    $summary.ParseErrorSample = @($parseErrors.ToArray() | Select-Object -First 5)
    return $summary
}

# Invoke-R0CollectorHealth runs the collector's health-only path using the
# documented --health and --out options. It opens the already-loaded device,
# writes JSONL to the explicit output path, and does not drain queued events.
function Invoke-R0CollectorHealth {
    if (-not (Test-Path -LiteralPath $R0CollectorPath -PathType Leaf)) {
        return New-R0ReadinessResult `
            -Name 'R0Collector health' `
            -Status 'Failed' `
            -Required $true `
            -Message "R0Collector executable was not found: $R0CollectorPath" `
            -Details @{
                R0CollectorPath = $R0CollectorPath
                DevicePath      = $DevicePath
                OutputPath      = $CollectorHealthOutputPath
                OutputWritten   = $false
                HealthOnly      = $true
            }
    }

    try {
        $collectorArgs = @(
            '--device', $DevicePath,
            '--health',
            '--out', $CollectorHealthOutputPath
        )
        $output = @(& $R0CollectorPath @collectorArgs 2>&1)
        $exitCode = $LASTEXITCODE
        $summary = Get-JsonLineEventSummary -Path $CollectorHealthOutputPath
        $eventTypes = @($summary.EventTypes)
        $hasDeviceOpened = $eventTypes -contains 'r0collector.deviceOpened'
        $hasDriverHealth = $eventTypes -contains 'r0collector.driverHealth'
        $parseErrorCount = [int]$summary.ParseErrorCount
        $passed = $exitCode -eq 0 -and [bool]$summary.OutputExists -and [int64]$summary.OutputLength -gt 0 -and $parseErrorCount -eq 0 -and $hasDeviceOpened -and $hasDriverHealth

        return New-R0ReadinessResult `
            -Name 'R0Collector health' `
            -Status ($(if ($passed) { 'Passed' } else { 'Failed' })) `
            -Required $true `
            -Message "R0Collector --health --out returned exit code $exitCode." `
            -Details @{
                R0CollectorPath = $R0CollectorPath
                DevicePath      = $DevicePath
                OutputPath      = $CollectorHealthOutputPath
                HealthOnly      = $true
                ExitCode        = $exitCode
                OutputWritten   = [bool]$summary.OutputExists
                OutputLength    = [int64]$summary.OutputLength
                LineCount       = [int]$summary.LineCount
                EventTypes      = @($eventTypes)
                HasDeviceOpened = $hasDeviceOpened
                HasDriverHealth = $hasDriverHealth
                ParseErrorCount = $parseErrorCount
                ParseErrors     = @($summary.ParseErrorSample)
                ConsoleOutput   = (($output | Out-String).Trim())
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'R0Collector health' `
            -Status 'Failed' `
            -Required $true `
            -Message "R0Collector health check failed: $($_.Exception.Message)" `
            -Details @{
                R0CollectorPath = $R0CollectorPath
                DevicePath      = $DevicePath
                OutputPath      = $CollectorHealthOutputPath
                HealthOnly      = $true
                ErrorType       = $_.Exception.GetType().FullName
            }
    }
}

# Invoke-R0CollectorDrain runs R0Collector in one-shot mode. It is opt-in and
# writes only to the explicit collector output path.
function Invoke-R0CollectorDrain {
    if (-not (Test-Path -LiteralPath $R0CollectorPath -PathType Leaf)) {
        return New-R0ReadinessResult `
            -Name 'R0Collector drain' `
            -Status 'Failed' `
            -Required $true `
            -Message "R0Collector executable was not found: $R0CollectorPath" `
            -Details @{
                R0CollectorPath = $R0CollectorPath
                DevicePath      = $DevicePath
                OutputPath      = $CollectorOutputPath
                OutputWritten   = $false
            }
    }

    try {
        $collectorArgs = @(
            '--device', $DevicePath,
            '--out', $CollectorOutputPath,
            '--duration', '0'
        )
        $output = @(& $R0CollectorPath @collectorArgs 2>&1)
        $exitCode = $LASTEXITCODE
        $summary = Get-JsonLineEventSummary -Path $CollectorOutputPath
        $eventTypes = @($summary.EventTypes)
        $hasDriverHealth = $eventTypes -contains 'r0collector.driverHealth'
        $hasDriverCapabilities = $eventTypes -contains 'r0collector.driverCapabilities'
        $driverStatusCount = @($eventTypes | Where-Object { $_ -eq 'r0collector.driverStatus' }).Count
        $hasDriverStatus = $driverStatusCount -ge 1
        $hasDriverPoll = $eventTypes -contains 'r0collector.driverPoll'
        $hasDriverReadEvents = $eventTypes -contains 'r0collector.driverReadEvents'
        $parseErrorCount = [int]$summary.ParseErrorCount
        $passed = $exitCode -eq 0 -and [bool]$summary.OutputExists -and [int64]$summary.OutputLength -gt 0 -and $parseErrorCount -eq 0 -and $hasDriverHealth -and $hasDriverCapabilities -and $hasDriverStatus -and $hasDriverPoll -and $hasDriverReadEvents

        return New-R0ReadinessResult `
            -Name 'R0Collector drain' `
            -Status ($(if ($passed) { 'Passed' } else { 'Failed' })) `
            -Required $true `
            -Message "R0Collector --out one-shot drain returned exit code $exitCode and is expected to emit health/capabilities/status/poll/read-events rows." `
            -Details @{
                R0CollectorPath    = $R0CollectorPath
                DevicePath         = $DevicePath
                OutputPath         = $CollectorOutputPath
                OutputWritten      = [bool]$summary.OutputExists
                OutputLength       = [int64]$summary.OutputLength
                LineCount          = [int]$summary.LineCount
                EventTypes         = @($eventTypes)
                HasDriverHealth    = $hasDriverHealth
                HasDriverCapabilities = $hasDriverCapabilities
                HasDriverStatus    = $hasDriverStatus
                DriverStatusCount  = $driverStatusCount
                HasDriverPoll      = $hasDriverPoll
                HasDriverReadEvents = $hasDriverReadEvents
                ParseErrorCount    = $parseErrorCount
                ParseErrors        = @($summary.ParseErrorSample)
                ExitCode           = $exitCode
                ConsoleOutput      = (($output | Out-String).Trim())
            }
    }
    catch {
        return New-R0ReadinessResult `
            -Name 'R0Collector drain' `
            -Status 'Failed' `
            -Required $true `
            -Message "R0Collector drain failed: $($_.Exception.Message)" `
            -Details @{
                R0CollectorPath = $R0CollectorPath
                DevicePath      = $DevicePath
                OutputPath      = $CollectorOutputPath
                ErrorType       = $_.Exception.GetType().FullName
            }
    }
}

$results = New-Object System.Collections.Generic.List[object]

$driverProject = Join-Path $RepositoryRoot 'driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj'
$driverHeader = Join-Path $RepositoryRoot 'driver\KSword.Sandbox.Driver\include\KSwordSandboxDriverIoctl.h'
$driverDispatch = Join-Path $RepositoryRoot 'driver\KSword.Sandbox.Driver\src\Device\ControlDevice.c'
$driverEventQueue = Join-Path $RepositoryRoot 'driver\KSword.Sandbox.Driver\src\Eventing\EventQueue.c'
$collectorProject = Join-Path $RepositoryRoot 'guest\KSword.Sandbox.R0Collector\KSword.Sandbox.R0Collector.vcxproj'
$collectorIoctlClient = Join-Path $RepositoryRoot 'guest\KSword.Sandbox.R0Collector\src\IoctlClient.cpp'
$collectorEventParser = Join-Path $RepositoryRoot 'guest\KSword.Sandbox.R0Collector\src\EventParser.cpp'
$collectorRuntimeLoop = Join-Path $RepositoryRoot 'guest\KSword.Sandbox.R0Collector\src\RuntimeLoop.cpp'
$driverSigningDoc = Join-Path $RepositoryRoot 'docs\driver-signing.md'
$r0CollectorDoc = Join-Path $RepositoryRoot 'docs\r0-collector.md'

[void]$results.Add((Test-RepositoryFile -Name 'Driver project file' -Path $driverProject))
[void]$results.Add((Test-RepositoryFile -Name 'Driver public IOCTL header' -Path $driverHeader))
[void]$results.Add((Test-RepositoryFile -Name 'R0Collector project file' -Path $collectorProject))
[void]$results.Add((Test-R0CapabilityIoctlStaticContract `
            -DriverHeaderPath $driverHeader `
            -DriverDispatchPath $driverDispatch `
            -DriverEventQueuePath $driverEventQueue `
            -CollectorIoctlClientPath $collectorIoctlClient `
            -CollectorEventParserPath $collectorEventParser `
            -CollectorRuntimeLoopPath $collectorRuntimeLoop `
            -DriverSigningDocPath $driverSigningDoc `
            -R0CollectorDocPath $r0CollectorDoc))
[void]$results.Add((Test-DriverSysGitHygiene -Root $RepositoryRoot))
[void]$results.Add((Test-ReadableFile -Name 'Driver binary readable' -Path $DriverSysPath -Required $true))
[void]$results.Add((Test-ReadableFile -Name 'R0Collector executable readable' -Path $R0CollectorPath -Required $false))
[void]$results.Add((Test-DriverSignature -Path $DriverSysPath))
[void]$results.Add((Test-AdministratorPrivilege))
[void]$results.Add((Test-TestSigningState -Required $testSigningRequired))
[void]$results.Add((Test-ServiceState -Name $ServiceName))

if ($InstallService) {
    [void]$results.Add((Invoke-ServiceMutation -Operation install))
}
if ($StartService) {
    [void]$results.Add((Invoke-ServiceMutation -Operation start))
}
if ($CheckDeviceHealth) {
    [void]$results.Add((Invoke-DeviceHealthCheck -Path $DevicePath))
}
if ($CheckCollectorHealth) {
    [void]$results.Add((Invoke-R0CollectorHealth))
}
if ($DrainWithCollector) {
    [void]$results.Add((Invoke-R0CollectorDrain))
}
if ($StopService) {
    [void]$results.Add((Invoke-ServiceMutation -Operation stop))
}
if ($DeleteService) {
    [void]$results.Add((Invoke-ServiceMutation -Operation delete))
}

$failedCount = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
$warningCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
$passedCount = @($results | Where-Object { $_.Status -eq 'Passed' }).Count
$exitCode = if ($failedCount -gt 0) { 1 } else { 0 }
$overallStatus = if ($failedCount -gt 0) {
    'Failed'
}
elseif ($warningCount -gt 0) {
    'Warning'
}
else {
    'Passed'
}

foreach ($result in $results) {
    Write-Output $result
}

Write-Output ([pscustomobject][ordered]@{
        ResultType             = 'R0ReadinessSummary'
        OverallStatus          = $overallStatus
        ExitCode               = $exitCode
        PassedCount            = $passedCount
        WarningCount           = $warningCount
        FailedCount            = $failedCount
        RepositoryRoot         = $RepositoryRoot
        DriverSysPath          = $DriverSysPath
        R0CollectorPath        = $R0CollectorPath
        ServiceName            = $ServiceName
        DevicePath             = $DevicePath
        RequireTestSigning     = $testSigningRequired
        ServiceMutationAllowed = [bool]$AllowServiceMutation
        CollectorHealthOutputPath = $CollectorHealthOutputPath
        CollectorOutputPath     = $CollectorOutputPath
        DefaultModeSafe        = -not ($InstallService -or $StartService -or $StopService -or $DeleteService -or $CheckDeviceHealth -or $CheckCollectorHealth -or $DrainWithCollector)
        Note                   = 'Default mode performs static negotiated-IOCTL contract checks but does not load/unload the driver, mutate SCM state, open the device, or write collector output.'
    })

exit $exitCode
