<#
.SYNOPSIS
Runs non-destructive R0 driver readiness checks before a real VM validation.

.DESCRIPTION
Default mode checks only local files, read permissions, Authenticode signing
metadata, Administrator status, test-signing boot configuration, and read-only
SCM service state. It never loads, unloads, installs, deletes, or opens the
driver device unless the caller supplies explicit parameters.

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
    [switch]$DrainWithCollector,
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
            '--output', $CollectorOutputPath,
            '--duration', '0'
        )
        $output = @(& $R0CollectorPath @collectorArgs 2>&1)
        $exitCode = $LASTEXITCODE
        $outputExists = Test-Path -LiteralPath $CollectorOutputPath -PathType Leaf
        $outputLength = if ($outputExists) { (Get-Item -LiteralPath $CollectorOutputPath).Length } else { 0 }

        return New-R0ReadinessResult `
            -Name 'R0Collector drain' `
            -Status ($(if ($exitCode -eq 0) { 'Passed' } else { 'Failed' })) `
            -Required $true `
            -Message "R0Collector one-shot drain returned exit code $exitCode." `
            -Details @{
                R0CollectorPath = $R0CollectorPath
                DevicePath      = $DevicePath
                OutputPath      = $CollectorOutputPath
                OutputWritten   = $outputExists
                OutputLength    = $outputLength
                ExitCode        = $exitCode
                ConsoleOutput   = (($output | Out-String).Trim())
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
$collectorProject = Join-Path $RepositoryRoot 'guest\KSword.Sandbox.R0Collector\KSword.Sandbox.R0Collector.vcxproj'

[void]$results.Add((Test-RepositoryFile -Name 'Driver project file' -Path $driverProject))
[void]$results.Add((Test-RepositoryFile -Name 'Driver public IOCTL header' -Path $driverHeader))
[void]$results.Add((Test-RepositoryFile -Name 'R0Collector project file' -Path $collectorProject))
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
        DefaultModeSafe        = -not ($InstallService -or $StartService -or $StopService -or $DeleteService -or $CheckDeviceHealth -or $DrainWithCollector)
        Note                   = 'Default mode does not load/unload the driver, mutate SCM state, open the device, or write collector output.'
    })

exit $exitCode
