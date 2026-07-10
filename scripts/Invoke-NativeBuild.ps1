<#
.SYNOPSIS
Builds native KSwordSandbox projects through MSBuild with a sanitized PATH.

.DESCRIPTION
Inputs are solution/project path, configuration, platform, and verbosity.
Processing starts MSBuild in a child process after normalizing environment
variables so Windows sessions that contain both PATH and Path do not break
Visual C++ ToolTask environment creation. The default path is compile-only:
MSBuild driver signing and post-build events are disabled. Optional driver
signing is an explicit opt-in and is performed only with signtool.exe after a
successful build. The script returns the build/signing exit code and writes
captured stdout/stderr to the console.
#>
[CmdletBinding()]
param(
    [string]$Project = "KSwordSandbox.sln",
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [string]$Verbosity = "minimal",
    [string]$MSBuildPath = "D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe",
    [switch]$SignDriver,
    [string]$DriverOutputPath,
    [string]$SignToolPath,
    [string]$SigningCertificatePath,
    [string]$SigningCertificatePassword,
    [string]$SigningCertificateThumbprint,
    [string]$SigningCertificateSubjectName,
    [string]$TimestampUrl,
    [string]$FileDigestAlgorithm = "SHA256",
    [string]$TimestampDigestAlgorithm = "SHA256"
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

# ConvertTo-ProcessArgument quotes an argument for ProcessStartInfo.Arguments.
# Inputs are a single argument value; processing escapes embedded quotes; the
# function returns a command-line-safe argument string.
function ConvertTo-ProcessArgument {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return '""'
    }

    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    return '"' + ($Value -replace '"', '\"') + '"'
}

# Join-ProcessArguments quotes and joins process arguments.
# Inputs are an argument array; processing applies Windows command-line quoting;
# the function returns a single ProcessStartInfo.Arguments string.
function Join-ProcessArguments {
    param(
        [string[]]$Arguments
    )

    return (($Arguments | ForEach-Object { ConvertTo-ProcessArgument -Value $_ }) -join ' ')
}

# Resolve-RepositoryPath resolves a script input path against the current
# working directory first and the repository root second.
# Inputs are the path and a label; processing requires an existing file; the
# function returns the resolved provider path.
function Resolve-RepositoryPath {
    param(
        [string]$Path,
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Description path is required."
    }

    $candidatePaths = if ([System.IO.Path]::IsPathRooted($Path)) {
        @($Path)
    }
    else {
        @(
            (Join-Path (Get-Location).Path $Path),
            (Join-Path $repoRoot $Path)
        )
    }

    foreach ($candidate in $candidatePaths) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "$Description was not found: $Path"
}

# Start-NormalizedMSBuild starts MSBuild without duplicate PATH/Path variables.
# Inputs are MSBuild path and command-line arguments; processing copies the
# current environment, removes case-insensitive PATH duplicates, and writes one
# canonical Path entry; the function returns the child process exit code.
function Start-NormalizedMSBuild {
    param(
        [string]$FileName,
        [string]$Arguments
    )

    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = $FileName
    $processInfo.Arguments = $Arguments
    $processInfo.UseShellExecute = $false
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.CreateNoWindow = $true

    $pathValue = [Environment]::GetEnvironmentVariable('PATH')
    foreach ($key in @($processInfo.EnvironmentVariables.Keys)) {
        if ($key -ieq 'PATH') {
            $processInfo.EnvironmentVariables.Remove($key)
        }
    }

    $processInfo.EnvironmentVariables['Path'] = $pathValue

    $process = [System.Diagnostics.Process]::Start($processInfo)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if (-not [string]::IsNullOrWhiteSpace($stdout)) {
        Write-Host $stdout
    }

    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        Write-Host $stderr -ForegroundColor Red
    }

    return $process.ExitCode
}

# Get-WindowsKitSignToolCandidates returns known Windows Kit signtool.exe
# locations, newest kit first.
function Get-WindowsKitSignToolCandidates {
    $roots = @()
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $roots += (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin')
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $roots += (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    }

    foreach ($root in ($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }

        Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Sort-Object -Property Name -Descending |
            ForEach-Object {
                foreach ($architecture in @('x64', 'x86')) {
                    Join-Path $_.FullName (Join-Path $architecture 'signtool.exe')
                }
            }
    }
}

# Resolve-SignTool resolves signtool.exe and rejects other executables.
# Inputs are an optional explicit path; processing checks the Windows Kit,
# environment, and PATH fallbacks; the function returns an existing signtool.exe.
function Resolve-SignTool {
    param(
        [string]$ExplicitPath
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        [void]$candidates.Add($ExplicitPath)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:KSWORDBOX_SIGNTOOL)) {
        [void]$candidates.Add($env:KSWORDBOX_SIGNTOOL)
    }
    else {
        foreach ($candidate in (Get-WindowsKitSignToolCandidates)) {
            [void]$candidates.Add($candidate)
        }

        $pathTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($pathTool) {
            [void]$candidates.Add($pathTool.Source)
        }
    }

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $resolvedCandidate = if ([System.IO.Path]::IsPathRooted($candidate)) {
            $candidate
        }
        else {
            $command = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($command) {
                $command.Source
            }
            else {
                $candidate
            }
        }

        if (([System.IO.Path]::GetFileName($resolvedCandidate)) -ine 'signtool.exe') {
            throw "Driver signing requires signtool.exe. Received: $resolvedCandidate"
        }

        if (Test-Path -LiteralPath $resolvedCandidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $resolvedCandidate).Path
        }
    }

    throw 'signtool.exe was not found. Provide -SignToolPath when using -SignDriver.'
}

# Resolve-DriverOutput resolves the built driver .sys for optional signing.
# Inputs are an optional explicit path and build dimensions; processing checks
# common solution and project output layouts; the function returns one .sys path.
function Resolve-DriverOutput {
    param(
        [string]$ExplicitPath,
        [string]$BuildConfiguration,
        [string]$BuildPlatform
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return Resolve-RepositoryPath -Path $ExplicitPath -Description 'Driver output'
    }

    $candidatePaths = @(
        (Join-Path $repoRoot (Join-Path $BuildPlatform (Join-Path $BuildConfiguration 'KSword.Sandbox.Driver.sys'))),
        (Join-Path $repoRoot (Join-Path 'driver\KSword.Sandbox.Driver' (Join-Path $BuildPlatform (Join-Path $BuildConfiguration 'KSword.Sandbox.Driver.sys'))))
    )

    $existing = @(
        $candidatePaths |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            ForEach-Object { Get-Item -LiteralPath $_ }
    )

    if ($existing.Count -eq 0) {
        throw "Driver output was not found. Provide -DriverOutputPath when using -SignDriver."
    }

    return ($existing | Sort-Object -Property LastWriteTimeUtc -Descending | Select-Object -First 1).FullName
}

# Invoke-DriverSigning signs the compiled driver with signtool.exe.
# Inputs are signing selector parameters and target driver path; processing
# validates that signing is explicit and non-interactive; the function throws on
# signtool failure.
function Invoke-DriverSigning {
    param(
        [string]$DriverPath,
        [string]$ResolvedSignTool
    )

    $selectors = @()
    if (-not [string]::IsNullOrWhiteSpace($SigningCertificatePath)) {
        $selectors += 'path'
    }

    if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        $selectors += 'thumbprint'
    }

    if (-not [string]::IsNullOrWhiteSpace($SigningCertificateSubjectName)) {
        $selectors += 'subject'
    }

    if ($selectors.Count -ne 1) {
        throw 'Signing was requested; provide exactly one of -SigningCertificatePath, -SigningCertificateThumbprint, or -SigningCertificateSubjectName.'
    }

    if (-not [string]::IsNullOrWhiteSpace($SigningCertificatePassword) -and
        [string]::IsNullOrWhiteSpace($SigningCertificatePath)) {
        throw '-SigningCertificatePassword can only be used with -SigningCertificatePath.'
    }

    $signArguments = @('sign', '/fd', $FileDigestAlgorithm)
    if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
        $signArguments += @('/tr', $TimestampUrl, '/td', $TimestampDigestAlgorithm)
    }

    if (-not [string]::IsNullOrWhiteSpace($SigningCertificatePath)) {
        $resolvedCertificate = Resolve-RepositoryPath -Path $SigningCertificatePath -Description 'Signing certificate'
        $signArguments += @('/f', $resolvedCertificate)
        if (-not [string]::IsNullOrWhiteSpace($SigningCertificatePassword)) {
            $signArguments += @('/p', $SigningCertificatePassword)
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        $signArguments += @('/sha1', $SigningCertificateThumbprint)
    }
    else {
        $signArguments += @('/n', $SigningCertificateSubjectName)
    }

    $signArguments += $DriverPath

    Write-Host "==> signing native driver with signtool.exe: $DriverPath" -ForegroundColor Cyan
    & $ResolvedSignTool @signArguments
    $signExitCode = if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 }
    if ($signExitCode -ne 0) {
        throw "signtool.exe failed with exit code $signExitCode"
    }

    $global:LASTEXITCODE = 0
}

$signingParametersSupplied = -not [string]::IsNullOrWhiteSpace($DriverOutputPath) -or
    -not [string]::IsNullOrWhiteSpace($SignToolPath) -or
    -not [string]::IsNullOrWhiteSpace($SigningCertificatePath) -or
    -not [string]::IsNullOrWhiteSpace($SigningCertificatePassword) -or
    -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint) -or
    -not [string]::IsNullOrWhiteSpace($SigningCertificateSubjectName) -or
    -not [string]::IsNullOrWhiteSpace($TimestampUrl)

if (-not $SignDriver -and $signingParametersSupplied) {
    throw 'Signing parameters were supplied, but -SignDriver was not set. The default native build path is compile-only.'
}

$resolvedMSBuildPath = Resolve-RepositoryPath -Path $MSBuildPath -Description 'MSBuild'
$resolvedProject = Resolve-RepositoryPath -Path $Project -Description 'MSBuild project/solution'
$arguments = Join-ProcessArguments -Arguments @(
    $resolvedProject,
    '/m:1',
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    '/p:SignMode=Off',
    '/p:PostBuildEventUseInBuild=false',
    "/v:$Verbosity"
)

Write-Host "==> building native project without driver signing: $resolvedProject" -ForegroundColor Cyan
$exitCode = Start-NormalizedMSBuild -FileName $resolvedMSBuildPath -Arguments $arguments
if ($exitCode -ne 0) {
    exit $exitCode
}

if ($SignDriver) {
    $resolvedSignTool = Resolve-SignTool -ExplicitPath $SignToolPath
    $resolvedDriverOutput = Resolve-DriverOutput -ExplicitPath $DriverOutputPath -BuildConfiguration $Configuration -BuildPlatform $Platform
    Invoke-DriverSigning -DriverPath $resolvedDriverOutput -ResolvedSignTool $resolvedSignTool
}

exit $exitCode
