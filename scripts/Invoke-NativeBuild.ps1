<#
.SYNOPSIS
Builds native KSwordSandbox projects through MSBuild with a sanitized PATH.

.DESCRIPTION
Inputs are solution/project path, configuration, platform, and verbosity.
Processing starts MSBuild in a child process after normalizing environment
variables so Windows sessions that contain both PATH and Path do not break
Visual C++ ToolTask environment creation. The script returns MSBuild's exit
code and writes captured stdout/stderr to the console.
#>
[CmdletBinding()]
param(
    [string]$Project = "KSwordSandbox.sln",
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [string]$Verbosity = "minimal",
    [string]$MSBuildPath = "D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe"
)

$ErrorActionPreference = 'Stop'

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
        Write-Error $stderr
    }

    return $process.ExitCode
}

if (-not (Test-Path -LiteralPath $MSBuildPath -PathType Leaf)) {
    throw "MSBuild was not found: $MSBuildPath"
}

$arguments = "`"$Project`" /m:1 /p:Configuration=$Configuration /p:Platform=$Platform /v:$Verbosity"
$exitCode = Start-NormalizedMSBuild -FileName $MSBuildPath -Arguments $arguments
exit $exitCode
