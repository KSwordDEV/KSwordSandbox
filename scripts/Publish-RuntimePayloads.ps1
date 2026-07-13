<#
.SYNOPSIS
Publishes KSwordSandbox runtime payloads into an external RuntimePublishRoot.

.DESCRIPTION
Inputs are the repository root, an external publish root, build configuration,
and optional guest payload/toolchain switches. Processing publishes host Web,
JobTool, and PostProcess with dotnet publish, then delegates Guest Agent and
R0Collector staging to scripts\Prepare-GuestPayload.ps1 so the guest layout
matches live Hyper-V expectations.

The output layout matches packaging/runtime-package.manifest.json:

  host-web/
  guest-tools/
  tools/job-tool/
  tools/postprocess/

This script is local-only. It does not run smoke tests, start or restore VMs,
push, sign drivers, call CSignTool.exe, or copy from repository bin/obj/x64.
All generated payloads must stay under RuntimePublishRoot outside the git
repository and must not be committed.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RepositoryRoot,

    [string]$RuntimePublishRoot = 'D:\Temp\KSwordSandbox\publish',

    [string]$BuildRoot = 'D:\Temp\KSwordSandbox\publish-build',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$RuntimeIdentifier = 'win-x64',

    # Managed host tools are self-contained by default so a runtime package can
    # start on a clean operator host without a preinstalled .NET runtime. This
    # switch is retained for explicitness/backward compatibility.
    [switch]$SelfContainedManaged,

    # Opt into smaller host-web/job-tool/postprocess payloads when the target
    # operator host is known to have the matching .NET runtime installed.
    [switch]$FrameworkDependentManaged,

    [switch]$FrameworkDependentGuest,

    [switch]$SkipGuestPayload,

    [switch]$NoRestore,

    [switch]$Clean,

    [string]$MSBuildPath = 'D:\Software\VS\MSBuild\Current\Bin\MSBuild.exe',

    [string]$GuestWorkingDirectory = 'C:\KSwordSandbox'
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$scriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot
}
elseif (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    Split-Path -Parent $PSCommandPath
}
else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $scriptRoot '..'
}

function Write-PublishStep {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[publish-runtime] $Message"
}

function Get-FullPathNoRequire {
    param([Parameter(Mandatory)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
}

function Assert-OutsideRepository {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    $repoFull = (Get-FullPathNoRequire -Path $RepoRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $pathFull = (Get-FullPathNoRequire -Path $Path).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($pathFull.StartsWith($repoFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "错误：$Name 位于仓库内，拒绝写入 runtime payload：$Path。下一步：改用 D:\Temp\KSwordSandbox 下的仓库外目录。"
    }
}

function Clear-DirectorySafe {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Name
    )

    Assert-OutsideRepository -RepoRoot $RepoRoot -Path $Directory -Name $Name
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return
    }

    $resolved = (Resolve-Path -LiteralPath $Directory).Path
    if ([string]::IsNullOrWhiteSpace($resolved) -or $resolved.Length -lt 10) {
        throw "拒绝清理异常短路径：$Directory"
    }

    Write-PublishStep "Cleaning $Name at $resolved"
    Get-ChildItem -LiteralPath $resolved -Force | Remove-Item -Recurse -Force
}

function Clear-PayloadDirectory {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Name
    )

    Assert-OutsideRepository -RepoRoot $RepoRoot -Path $Directory -Name $Name
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
        return
    }

    $resolved = (Resolve-Path -LiteralPath $Directory).Path
    if ([string]::IsNullOrWhiteSpace($resolved) -or $resolved.Length -lt 10) {
        throw "拒绝清理异常短 runtime payload 路径：$Directory"
    }

    if ($PSCmdlet.ShouldProcess($resolved, "Clean runtime payload directory $Name")) {
        Write-PublishStep "Cleaning runtime payload directory $Name at $resolved"
        Get-ChildItem -LiteralPath $resolved -Force | Remove-Item -Recurse -Force
    }
}

function Invoke-DotNetPublish {
    param(
        [Parameter(Mandatory)][string]$ProjectPath,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string]$DisplayName
    )

    if (-not (Test-Path -LiteralPath $ProjectPath -PathType Leaf)) {
        throw "错误：找不到项目：$ProjectPath"
    }

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $arguments = @(
        'publish',
        $ProjectPath,
        '-c', $Configuration,
        '-o', $OutputDirectory,
        '-r', $RuntimeIdentifier,
        '--self-contained', $script:ManagedSelfContained.ToString().ToLowerInvariant(),
        '/p:UseAppHost=true',
        '/p:DebugType=None',
        '/p:DebugSymbols=false'
    )
    if ($NoRestore) {
        $arguments += '--no-restore'
    }

    Write-PublishStep "dotnet $($arguments -join ' ')"
    if ($PSCmdlet.ShouldProcess($OutputDirectory, "Publish $DisplayName")) {
        & dotnet @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "错误：$DisplayName publish 失败，退出码 $LASTEXITCODE。"
        }
    }
}

function Test-AnyExpectedLeaf {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$DisplayName
    )

    foreach ($name in $Names) {
        if (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf) {
            return
        }
    }

    throw "错误：$DisplayName 缺少预期入口文件：$($Names -join ' 或 ')。目录：$Directory"
}

function Get-DirectoryFileCount {
    param([Parameter(Mandatory)][string]$Directory)

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return 0
    }

    return @(Get-ChildItem -LiteralPath $Directory -Recurse -File -Force).Count
}

try {
    $repoRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
    $publishRoot = Get-FullPathNoRequire -Path $RuntimePublishRoot
    $buildRootFull = Get-FullPathNoRequire -Path $BuildRoot
    if ($SelfContainedManaged -and $FrameworkDependentManaged) {
        throw '错误：-SelfContainedManaged 和 -FrameworkDependentManaged 不能同时指定。默认已发布 self-contained managed payload；只有明确接受目标机 .NET runtime 依赖时才使用 -FrameworkDependentManaged。'
    }
    $script:ManagedSelfContained = -not [bool]$FrameworkDependentManaged

    Assert-OutsideRepository -RepoRoot $repoRoot -Path $publishRoot -Name 'RuntimePublishRoot'
    Assert-OutsideRepository -RepoRoot $repoRoot -Path $buildRootFull -Name 'BuildRoot'

    if ($Clean) {
        Clear-DirectorySafe -Directory $publishRoot -RepoRoot $repoRoot -Name 'RuntimePublishRoot'
        Clear-DirectorySafe -Directory $buildRootFull -RepoRoot $repoRoot -Name 'BuildRoot'
    }

    $hostWeb = Join-Path $publishRoot 'host-web'
    $guestTools = Join-Path $publishRoot 'guest-tools'
    $jobTool = Join-Path $publishRoot 'tools\job-tool'
    $postProcess = Join-Path $publishRoot 'tools\postprocess'
    $guestBuild = Join-Path $buildRootFull 'guest-tools'

    New-Item -ItemType Directory -Path $hostWeb, $guestTools, $jobTool, $postProcess, $guestBuild -Force | Out-Null
    Clear-PayloadDirectory -Directory $hostWeb -RepoRoot $repoRoot -Name 'host-web'
    Clear-PayloadDirectory -Directory $jobTool -RepoRoot $repoRoot -Name 'tools/job-tool'
    Clear-PayloadDirectory -Directory $postProcess -RepoRoot $repoRoot -Name 'tools/postprocess'

    Invoke-DotNetPublish `
        -ProjectPath (Join-Path $repoRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj') `
        -OutputDirectory $hostWeb `
        -DisplayName 'host-web'
    Invoke-DotNetPublish `
        -ProjectPath (Join-Path $repoRoot 'tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj') `
        -OutputDirectory $jobTool `
        -DisplayName 'tools/job-tool'
    Invoke-DotNetPublish `
        -ProjectPath (Join-Path $repoRoot 'tools\KSword.Sandbox.PostProcess\KSword.Sandbox.PostProcess.csproj') `
        -OutputDirectory $postProcess `
        -DisplayName 'tools/postprocess'

    if (-not $SkipGuestPayload) {
        $prepareGuest = Join-Path $repoRoot 'scripts\Prepare-GuestPayload.ps1'
        if (-not (Test-Path -LiteralPath $prepareGuest -PathType Leaf)) {
            throw "错误：找不到 guest payload 脚本：$prepareGuest"
        }

        $guestArguments = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $prepareGuest,
            '-RepoRoot', $repoRoot,
            '-MSBuildPath', $MSBuildPath,
            '-PayloadRoot', $guestTools,
            '-BuildRoot', $guestBuild,
            '-Configuration', $Configuration,
            '-RuntimeIdentifier', $RuntimeIdentifier,
            '-GuestWorkingDirectory', $GuestWorkingDirectory
        )
        if ($FrameworkDependentGuest) {
            $guestArguments += '-FrameworkDependent'
        }
        else {
            $guestArguments += '-SelfContained'
        }

        Write-PublishStep "powershell $($guestArguments -join ' ')"
        if ($PSCmdlet.ShouldProcess($guestTools, 'Publish guest-tools payload')) {
            & powershell @guestArguments
            if ($LASTEXITCODE -ne 0) {
                throw "错误：guest-tools publish 失败，退出码 $LASTEXITCODE。"
            }
        }
    }
    else {
        Write-PublishStep 'Skipping guest-tools payload by request; runtime handoff will remain incomplete until guest-tools is supplied.'
    }

    if ($WhatIfPreference) {
        Write-PublishStep "WhatIf preview complete. No runtime payload validation was performed because publish actions were not executed."
        return
    }

    Test-AnyExpectedLeaf -Directory $hostWeb -Names @('KSword.Sandbox.Web.exe', 'KSword.Sandbox.Web.dll') -DisplayName 'host-web'
    Test-AnyExpectedLeaf -Directory $jobTool -Names @('KSword.Sandbox.JobTool.exe', 'KSword.Sandbox.JobTool.dll') -DisplayName 'tools/job-tool'
    Test-AnyExpectedLeaf -Directory $postProcess -Names @('KSword.Sandbox.PostProcess.exe', 'KSword.Sandbox.PostProcess.dll') -DisplayName 'tools/postprocess'
    if (-not $SkipGuestPayload) {
        Test-AnyExpectedLeaf -Directory $guestTools -Names @('payload-manifest.json') -DisplayName 'guest-tools'
        Test-AnyExpectedLeaf -Directory (Join-Path $guestTools 'agent') -Names @('KSword.Sandbox.Agent.exe', 'KSword.Sandbox.Agent.dll') -DisplayName 'guest-tools/agent'
        Test-AnyExpectedLeaf -Directory (Join-Path $guestTools 'r0collector') -Names @('KSword.Sandbox.R0Collector.exe') -DisplayName 'guest-tools/r0collector'
    }

    $manifest = [pscustomobject][ordered]@{
        schema                  = 'ksword.runtime-publish.v1'
        generatedAtUtc          = [DateTimeOffset]::UtcNow.ToString('O')
        repositoryRoot          = $repoRoot
        runtimePublishRoot      = $publishRoot
        configuration           = $Configuration
        runtimeIdentifier       = $RuntimeIdentifier
        selfContainedManaged    = $script:ManagedSelfContained
        frameworkDependentManaged = -not $script:ManagedSelfContained
        frameworkDependentGuest = [bool]$FrameworkDependentGuest
        skipGuestPayload        = [bool]$SkipGuestPayload
        noVmMutation            = $true
        noDriverSigning         = $true
        noCSignTool             = $true
        expectedPackageEntries  = @('host-web', 'guest-tools', 'tools/job-tool', 'tools/postprocess')
        entries                 = [ordered]@{
            'host-web'          = @{ path = $hostWeb; fileCount = Get-DirectoryFileCount -Directory $hostWeb }
            'guest-tools'       = @{ path = $guestTools; fileCount = Get-DirectoryFileCount -Directory $guestTools }
            'tools/job-tool'    = @{ path = $jobTool; fileCount = Get-DirectoryFileCount -Directory $jobTool }
            'tools/postprocess' = @{ path = $postProcess; fileCount = Get-DirectoryFileCount -Directory $postProcess }
        }
        nextChecks              = @(
            ".\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -RuntimePublishRoot '$publishRoot' -RequireCompleteRuntimePackage",
            ".\scripts\package-portable.ps1 -PackageKind runtime -RuntimePublishRoot '$publishRoot' -RequireCompleteRuntimePayloads -OutputRoot 'D:\Temp\KSwordSandbox\packages'"
        )
    }

    $manifestPath = Join-Path $publishRoot 'runtime-publish-manifest.json'
    if ($PSCmdlet.ShouldProcess($manifestPath, 'Write runtime publish manifest')) {
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    }

    Write-PublishStep "RuntimePublishRoot ready: $publishRoot"
    Write-PublishStep "Next readiness: .\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -RuntimePublishRoot '$publishRoot' -RequireCompleteRuntimePackage"
}
catch {
    Write-Error "失败：runtime payload publish 未完成。下一步：确认 .NET SDK、MSBuild/WDK、RuntimePublishRoot 在仓库外，且不要提交生成目录。英文详情：$($_.Exception.Message)"
    exit 1
}
