<#
.SYNOPSIS
Resolves KSwordSandbox CLI tools from either a source checkout or a runtime package.

.DESCRIPTION
Wrappers use this helper to prefer published portable executables under the
package layout (`tools/job-tool`, `tools/postprocess`) and fall back to source
projects when running from a full repository. It does not build, sign, touch VM
state, or copy files; it only resolves and invokes local tools.
#>

function Resolve-KSwordPortableTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepoRoot,

        [Parameter(Mandatory)]
        [ValidateSet('JobTool', 'PostProcess')]
        [string]$Tool,

        [switch]$ThrowIfMissing
    )

    $root = [System.IO.Path]::GetFullPath($RepoRoot)
    switch ($Tool) {
        'JobTool' {
            $publishedRoot = Join-Path $root 'tools\job-tool'
            $exeName = 'KSword.Sandbox.JobTool.exe'
            $dllName = 'KSword.Sandbox.JobTool.dll'
            $project = Join-Path $root 'tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj'
        }
        'PostProcess' {
            $publishedRoot = Join-Path $root 'tools\postprocess'
            $exeName = 'KSword.Sandbox.PostProcess.exe'
            $dllName = 'KSword.Sandbox.PostProcess.dll'
            $project = Join-Path $root 'tools\KSword.Sandbox.PostProcess\KSword.Sandbox.PostProcess.csproj'
        }
    }

    $exe = Join-Path $publishedRoot $exeName
    $dll = Join-Path $publishedRoot $dllName

    if (Test-Path -LiteralPath $exe -PathType Leaf) {
        return [pscustomobject][ordered]@{
            Tool = $Tool
            Kind = 'PublishedExe'
            Path = (Resolve-Path -LiteralPath $exe).Path
            PublishedRoot = $publishedRoot
            SourceProjectPath = $project
            RequiresDotNet = $false
            SupportsNoBuild = $false
            RecommendedAction = ''
        }
    }

    if (Test-Path -LiteralPath $dll -PathType Leaf) {
        return [pscustomobject][ordered]@{
            Tool = $Tool
            Kind = 'PublishedDll'
            Path = (Resolve-Path -LiteralPath $dll).Path
            PublishedRoot = $publishedRoot
            SourceProjectPath = $project
            RequiresDotNet = $true
            SupportsNoBuild = $false
            RecommendedAction = '安装 .NET runtime，或使用包含 self-contained exe 的 runtime package。'
        }
    }

    if (Test-Path -LiteralPath $project -PathType Leaf) {
        return [pscustomobject][ordered]@{
            Tool = $Tool
            Kind = 'SourceProject'
            Path = (Resolve-Path -LiteralPath $project).Path
            PublishedRoot = $publishedRoot
            SourceProjectPath = $project
            RequiresDotNet = $true
            SupportsNoBuild = $true
            RecommendedAction = ''
        }
    }

    $missing = [pscustomobject][ordered]@{
        Tool = $Tool
        Kind = 'Missing'
        Path = $null
        PublishedRoot = $publishedRoot
        SourceProjectPath = $project
        RequiresDotNet = $null
        SupportsNoBuild = $false
        RecommendedAction = "便携包请确认 '$publishedRoot' 存在；源码仓库请确认 '$project' 存在。"
    }

    if ($ThrowIfMissing) {
        throw "错误：找不到 $Tool 启动目标。$($missing.RecommendedAction)"
    }

    return $missing
}

function Invoke-KSwordPortableTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Target,

        [Parameter(Mandatory)][string[]]$Arguments,

        [switch]$NoBuild
    )

    if ($Target.RequiresDotNet -and $null -eq (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "错误：$($Target.Tool) 启动目标 '$($Target.Kind)' 需要 dotnet，但当前 PATH 找不到 dotnet。$($Target.RecommendedAction)"
    }

    if ($Target.Kind -eq 'SourceProject') {
        $dotnetArgs = @('run')
        if ($NoBuild) {
            $dotnetArgs += '--no-build'
        }

        $dotnetArgs += @('--project', [string]$Target.Path, '--')
        $dotnetArgs += $Arguments
        & dotnet @dotnetArgs
        return $LASTEXITCODE
    }

    if ($NoBuild -and -not $Target.SupportsNoBuild) {
        Write-Verbose "Ignoring -NoBuild for published $($Target.Tool) target."
    }

    if ($Target.Kind -eq 'PublishedDll') {
        & dotnet ([string]$Target.Path) @Arguments
        return $LASTEXITCODE
    }

    if ($Target.Kind -eq 'PublishedExe') {
        & ([string]$Target.Path) @Arguments
        return $LASTEXITCODE
    }

    throw "错误：无法启动 $($Target.Tool)：目标类型为 $($Target.Kind)。"
}
