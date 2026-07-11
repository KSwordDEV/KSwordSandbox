<#
.SYNOPSIS
Runs lightweight release-readiness gates for KSwordSandbox.

.DESCRIPTION
This script is intentionally source/release oriented. It does not start,
restore, stop, or mutate Hyper-V VMs; it does not sign drivers; it does not
call CSignTool.exe; it does not use GUI signing fallback; it does not create
fresh live evidence; and it does not run heavyweight smoke suites by default.

Inputs are the repository root plus opt-in switches for build, source-package
staging, and complete runtime-payload handoff checks. Processing checks git
hygiene, repository policy, package manifest shape, runtime publish-root
completeness when requested, PowerShell syntax for operational scripts, and
accidental CSignTool/GUI-signing fallback references in normal release paths.
Return behavior is exit code 0 when all required checks pass, otherwise exit
code 1. Warnings are printed but do not fail unless -TreatWarningsAsErrors is
supplied.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot,

    [string]$OutputRoot = 'D:\Temp\KSwordSandbox\release-readiness',

    [switch]$AllowDirtySource,

    [switch]$StageSourcePackage,

    [switch]$SkipSourcePackageDryRun,

    [string]$RuntimePublishRoot,

    [switch]$RequireCompleteRuntimePackage,

    [switch]$IncludeBuild,

    [switch]$TreatWarningsAsErrors
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

$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$script:Results = New-Object System.Collections.Generic.List[object]

function Add-ReleaseCheckResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Passed', 'Warning', 'Failed', 'Skipped')]
        [string]$Status,
        [string]$Message = '',
        [string[]]$Remediation = @(),
        [hashtable]$Details = @{}
    )

    [void]$script:Results.Add([pscustomobject][ordered]@{
            id          = $Id
            title       = $Title
            status      = $Status
            message     = $Message
            remediation = @($Remediation)
            details     = $Details
        })
}

function Invoke-ReleaseCommand {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string[]]$Remediation = @()
    )

    $stdoutPath = Join-Path $OutputRoot "$Id.stdout.log"
    $stderrPath = Join-Path $OutputRoot "$Id.stderr.log"
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $RepositoryRoot `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    if ($process.ExitCode -eq 0) {
        Add-ReleaseCheckResult `
            -Id $Id `
            -Title $Title `
            -Status Passed `
            -Message "命令成功 / Command completed successfully. Logs: $stdoutPath ; $stderrPath" `
            -Details @{ exitCode = $process.ExitCode; stdout = $stdoutPath; stderr = $stderrPath }
        return
    }

    Add-ReleaseCheckResult `
        -Id $Id `
        -Title $Title `
        -Status Failed `
        -Message "命令失败，退出码 $($process.ExitCode) / Command failed. Logs: $stdoutPath ; $stderrPath" `
        -Remediation $Remediation `
        -Details @{ exitCode = $process.ExitCode; stdout = $stdoutPath; stderr = $stderrPath }
}

function Test-GitAvailable {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $git) {
        Add-ReleaseCheckResult `
            -Id 'git-available' `
            -Title 'Git available / Git 可用' `
            -Status Failed `
            -Message 'git was not found in PATH.' `
            -Remediation @('Install Git or run release readiness from a shell where git is available.')
        return $false
    }

    Add-ReleaseCheckResult `
        -Id 'git-available' `
        -Title 'Git available / Git 可用' `
        -Status Passed `
        -Message "git found at $($git.Source)."
    return $true
}

function Test-GitClean {
    $status = @(git -C $RepositoryRoot status --porcelain)
    if ($status.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'git-clean' `
            -Title 'Clean worktree / 工作树干净' `
            -Status Passed `
            -Message 'Worktree has no uncommitted tracked/untracked candidate changes.'
        return
    }

    $preview = @($status | Select-Object -First 20)
    $message = "Worktree has $($status.Count) changed/untracked item(s)."
    if ($AllowDirtySource) {
        Add-ReleaseCheckResult `
            -Id 'git-clean' `
            -Title 'Clean worktree / 工作树干净' `
            -Status Warning `
            -Message "$message AllowDirtySource is set." `
            -Remediation @('Do not cut a public source package from dirty source unless release notes explicitly document it.') `
            -Details @{ preview = $preview }
        return
    }

    Add-ReleaseCheckResult `
        -Id 'git-clean' `
        -Title 'Clean worktree / 工作树干净' `
        -Status Failed `
        -Message $message `
        -Remediation @('Commit or stash intended source changes before release packaging, or rerun with -AllowDirtySource for a documented internal draft.') `
        -Details @{ preview = $preview }
}

function Test-PowerShellScriptSyntax {
    $scriptPaths = New-Object System.Collections.Generic.List[string]
    foreach ($relative in @('run.ps1', 'install.ps1')) {
        [void]$scriptPaths.Add((Join-Path $RepositoryRoot $relative))
    }

    $scriptsRoot = Join-Path $RepositoryRoot 'scripts'
    if (Test-Path -LiteralPath $scriptsRoot -PathType Container) {
        foreach ($scriptFile in @(Get-ChildItem -LiteralPath $scriptsRoot -Filter '*.ps1' -File |
                Where-Object { $_.Name -notlike 'Sign-SandboxDriver*.ps1' } |
                Sort-Object FullName)) {
            [void]$scriptPaths.Add($scriptFile.FullName)
        }
    }

    $errors = New-Object System.Collections.Generic.List[object]
    $repoPrefix = $RepositoryRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $parsedCount = 0
    foreach ($path in @($scriptPaths.ToArray() | Sort-Object -Unique)) {
        $displayPath = if ($path.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $path.Substring($repoPrefix.Length)
        }
        else {
            $path
        }

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$errors.Add([pscustomobject]@{ script = $displayPath; error = 'missing' })
            continue
        }

        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
        $parsedCount++
        foreach ($parseError in @($parseErrors)) {
            [void]$errors.Add([pscustomobject]@{
                    script  = $displayPath
                    message = $parseError.Message
                    extent  = [string]$parseError.Extent
                })
        }
    }

    if ($errors.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'powershell-syntax' `
            -Title 'PowerShell syntax / PowerShell 语法' `
            -Status Passed `
            -Message "Parsed $parsedCount PowerShell script(s): root wrappers plus scripts/*.ps1 excluding signing helpers."
        return
    }

    Add-ReleaseCheckResult `
        -Id 'powershell-syntax' `
        -Title 'PowerShell syntax / PowerShell 语法' `
        -Status Failed `
        -Message "PowerShell parser found $($errors.Count) issue(s)." `
        -Remediation @('Fix parser errors before packaging or tagging a release.') `
        -Details @{ errors = @($errors.ToArray()) }
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [object]$DefaultValue = $null
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function Get-ScriptParameterNames {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return @()
    }

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0 -or $null -eq $ast.ParamBlock) {
        return @()
    }

    return @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
}

function Test-ScriptWrapperParameterSurface {
    $contracts = @(
        [pscustomobject]@{
            root = 'run.ps1'
            wrapper = 'scripts/run.ps1'
            allowedExtra = @()
        },
        [pscustomobject]@{
            root = 'install.ps1'
            wrapper = 'scripts/install.ps1'
            allowedExtra = @(
                'DriverAction',
                'DriverServiceName',
                'DriverPath',
                'DriverInfPath',
                'DriverKind',
                'MiniFilterAltitude',
                'MiniFilterInstanceName',
                'DriverPublishedName',
                'SkipDriverTestSigningCheck',
                'PreparePayload'
            )
        }
    )

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($contract in $contracts) {
        $rootParameters = @(Get-ScriptParameterNames -RelativePath $contract.root)
        $wrapperParameters = @(Get-ScriptParameterNames -RelativePath $contract.wrapper)
        if ($rootParameters.Count -eq 0) {
            [void]$issues.Add("Unable to inspect root parameters: $($contract.root)")
            continue
        }

        if ($wrapperParameters.Count -eq 0) {
            [void]$issues.Add("Unable to inspect wrapper parameters: $($contract.wrapper)")
            continue
        }

        foreach ($parameterName in $rootParameters) {
            if ($wrapperParameters -notcontains $parameterName) {
                [void]$issues.Add("Wrapper $($contract.wrapper) is missing root parameter -$parameterName from $($contract.root)")
            }
        }

        foreach ($parameterName in $wrapperParameters) {
            if (($rootParameters -notcontains $parameterName) -and ($contract.allowedExtra -notcontains $parameterName)) {
                [void]$issues.Add("Wrapper $($contract.wrapper) has unexpected parameter -$parameterName that is not documented as wrapper-only.")
            }
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'script-wrapper-parameter-surface' `
            -Title 'Script wrapper parameter surface / scripts 包装器参数面' `
            -Status Passed `
            -Message 'scripts/run.ps1 and scripts/install.ps1 expose root wrapper parameters, with only documented script-folder extras.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'script-wrapper-parameter-surface' `
        -Title 'Script wrapper parameter surface / scripts 包装器参数面' `
        -Status Failed `
        -Message "Script wrapper parameter contract found $($issues.Count) issue(s)." `
        -Remediation @('Keep scripts/ wrappers in sync with root run.ps1/install.ps1 so portable package operators can use the same documented commands.') `
        -Details @{ issues = @($issues.ToArray()) }
}

function Test-PackageManifests {
    $manifestPaths = @(
        'packaging/source-package.manifest.json',
        'packaging/runtime-package.manifest.json'
    )

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $manifestPaths) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$issues.Add("Missing manifest: $relative")
            continue
        }

        try {
            $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
            if ([int]$manifest.manifestVersion -lt 1) {
                [void]$issues.Add("manifestVersion is invalid: $relative")
            }

            if ([string]::IsNullOrWhiteSpace([string]$manifest.packageKind)) {
                [void]$issues.Add("packageKind is missing: $relative")
            }

            $raw = Get-Content -LiteralPath $path -Raw
            foreach ($requiredExclusion in @('*.vhd', '*.vhdx', '*.vhdset', '*.vmcx', '*.sys', '*.pdb', '*.pcap', '*.pcapng', '*.dmp', '*.mdmp', '*.png', '*.jpg', '*.jsonl', '*.sqlite', '*.sqlite3', '*.db', '*.har', '*.trace', 'jobs/**', 'dumps/**', 'screenshots/**', 'memory-dumps/**', 'packet-captures/**', 'sandbox.local.json', 'guest-password.dpapi')) {
                if ($raw.IndexOf($requiredExclusion, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$issues.Add("Manifest does not mention required exclusion '$requiredExclusion': $relative")
                }
            }

            if ($null -eq $manifest.PSObject.Properties['releaseContract']) {
                [void]$issues.Add("releaseContract is missing: $relative")
            }
            else {
                $releaseContract = Get-ObjectPropertyValue -InputObject $manifest -Name 'releaseContract' -DefaultValue $null
                $guiSigningFallback = [string](Get-ObjectPropertyValue -InputObject $releaseContract -Name 'guiSigningFallback' -DefaultValue '')
                if ($guiSigningFallback -ine 'forbidden') {
                    [void]$issues.Add("releaseContract.guiSigningFallback must be forbidden: $relative")
                }
            }

            if ($null -eq $manifest.PSObject.Properties['stagedMetadata']) {
                [void]$issues.Add("stagedMetadata contract is missing: $relative")
            }

            if ([string]$manifest.packageKind -eq 'source' -and @(Get-ObjectPropertyValue -InputObject $manifest -Name 'includePatterns' -DefaultValue @()).Count -eq 0) {
                [void]$issues.Add("source includePatterns are empty: $relative")
            }

            if ([string]$manifest.packageKind -eq 'runtime') {
                $includeEntries = @(Get-ObjectPropertyValue -InputObject $manifest -Name 'include' -DefaultValue @())
                if ($includeEntries.Count -eq 0) {
                    [void]$issues.Add("runtime include entries are empty: $relative")
                }

                if ($raw.IndexOf('"sourceType": "runtimePublish"', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$issues.Add("runtime manifest does not declare runtimePublish inputs: $relative")
                }

                $releaseContract = Get-ObjectPropertyValue -InputObject $manifest -Name 'releaseContract' -DefaultValue $null
                if ($null -ne $releaseContract) {
                    $requiresCompletePayloads = [bool](Get-ObjectPropertyValue -InputObject $releaseContract -Name 'completeRuntimePayloadsRequiredForHandoff' -DefaultValue $false)
                    if (-not $requiresCompletePayloads) {
                        [void]$issues.Add("runtime releaseContract must require complete runtime payloads for handoff: $relative")
                    }
                }

                foreach ($entry in $includeEntries) {
                    $entrySource = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'source' -DefaultValue '')
                    if ($entrySource -like 'scripts/Sign-SandboxDriverWithKsword*') {
                        [void]$issues.Add("runtime manifest must not include legacy KSword signing wrapper: $entrySource")
                    }
                }
            }
        }
        catch {
            [void]$issues.Add("Invalid JSON in ${relative}: $($_.Exception.Message)")
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'package-manifests' `
            -Title 'Package manifests / 打包清单' `
            -Status Passed `
            -Message 'Source and runtime manifests parsed and include high-risk exclusions.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'package-manifests' `
        -Title 'Package manifests / 打包清单' `
        -Status Failed `
        -Message "Package manifest checks found $($issues.Count) issue(s)." `
        -Remediation @('Update packaging manifests before release packaging.') `
        -Details @{ issues = @($issues.ToArray()) }
}

function Test-RuntimePublishCompleteness {
    $manifestPath = Join-Path $RepositoryRoot 'packaging\runtime-package.manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Failed `
            -Message 'Runtime package manifest is missing.' `
            -Remediation @('Restore packaging/runtime-package.manifest.json before release handoff.')
        return
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $runtimeEntries = @((Get-ObjectPropertyValue -InputObject $manifest -Name 'include' -DefaultValue @()) |
        Where-Object { [string](Get-ObjectPropertyValue -InputObject $_ -Name 'sourceType' -DefaultValue 'repository') -eq 'runtimePublish' })

    if ($runtimeEntries.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Failed `
            -Message 'Runtime manifest does not declare runtimePublish entries.' `
            -Remediation @('Declare host-web, guest-tools, tools/job-tool, and tools/postprocess runtimePublish entries.')
        return
    }

    $expectedSources = @($runtimeEntries | ForEach-Object { [string](Get-ObjectPropertyValue -InputObject $_ -Name 'source' -DefaultValue '') })
    $operatorHints = @(
        'Runtime payload completeness is a handoff gate only when -RuntimePublishRoot and -RequireCompleteRuntimePackage are supplied.',
        'Expected external payload folders: host-web, guest-tools, tools/job-tool, tools/postprocess.',
        'Read-only environment hints: run .\scripts\install.ps1 -Mode CheckEnvironment and .\scripts\run.ps1 -Mode CheckEnvironment for Hyper-V prerequisites, VM profile, guest payload freshness, and optional VT key status.',
        'This readiness script does not build payloads, copy from repository bin/obj/x64, start/restore/stop VMs, sign drivers, or generate fresh live evidence.'
    )

    if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
        if ($RequireCompleteRuntimePackage) {
            Add-ReleaseCheckResult `
                -Id 'runtime-publish-completeness' `
                -Title 'Runtime publish completeness / runtime payload 完整性' `
                -Status Failed `
                -Message '完整 runtime 便携包要求 -RuntimePublishRoot；当前未提供。' `
                -Remediation @('先把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到仓库外目录，再重跑：.\scripts\Test-ReleaseReadiness.ps1 -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage。') `
                -Details @{ expectedSources = $expectedSources; operatorHints = $operatorHints; dryRunOnly = $true }
            return
        }

        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Skipped `
            -Message 'Skipped complete runtime payload gate. This is acceptable for source/layout readiness only; use -RuntimePublishRoot with -RequireCompleteRuntimePackage before runtime handoff.' `
            -Details @{ expectedSources = $expectedSources; operatorHints = $operatorHints; dryRunOnly = $true; handoffAllowed = $false }
        return
    }

    $issues = New-Object System.Collections.Generic.List[string]
    $entryDiagnostics = New-Object System.Collections.Generic.List[object]
    $rootFull = [System.IO.Path]::GetFullPath($RuntimePublishRoot)
    $repoPrefix = ([System.IO.Path]::GetFullPath($RepositoryRoot)).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $rootPrefix = $rootFull.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($rootFull.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        [void]$issues.Add("RuntimePublishRoot must be outside the repository: $RuntimePublishRoot")
    }

    if (-not (Test-Path -LiteralPath $rootFull -PathType Container)) {
        [void]$issues.Add("RuntimePublishRoot does not exist or is not a directory: $RuntimePublishRoot")
    }
    else {
        foreach ($entry in $runtimeEntries) {
            $source = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'source' -DefaultValue '')
            if ([string]::IsNullOrWhiteSpace($source)) {
                [void]$issues.Add('Runtime publish entry is missing source.')
                continue
            }

            $sourcePath = [System.IO.Path]::GetFullPath((Join-Path $rootFull $source))
            if (($sourcePath -ne $rootFull) -and (-not $sourcePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase))) {
                [void]$issues.Add("Runtime publish entry escapes RuntimePublishRoot: $source")
                [void]$entryDiagnostics.Add([pscustomobject][ordered]@{
                        source = $source
                        sourcePath = $sourcePath
                        exists = $false
                        fileCount = 0
                        totalBytes = 0
                        error = 'path escapes RuntimePublishRoot'
                    })
                continue
            }

            if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
                [void]$issues.Add("Missing runtime publish payload directory: $source")
                [void]$entryDiagnostics.Add([pscustomobject][ordered]@{
                        source = $source
                        sourcePath = $sourcePath
                        exists = $false
                        fileCount = 0
                        totalBytes = 0
                        error = 'missing directory'
                    })
                continue
            }

            $files = @(Get-ChildItem -LiteralPath $sourcePath -Recurse -File -Force)
            $totalBytes = [Int64](($files | ForEach-Object { $_.Length } | Measure-Object -Sum).Sum)
            if ($files.Count -eq 0) {
                [void]$issues.Add("Runtime publish payload directory is empty: $source")
            }

            [void]$entryDiagnostics.Add([pscustomobject][ordered]@{
                    source = $source
                    sourcePath = $sourcePath
                    exists = $true
                    fileCount = $files.Count
                    totalBytes = $totalBytes
                    error = if ($files.Count -eq 0) { 'empty directory' } else { '' }
                })
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Passed `
            -Message 'RuntimePublishRoot is outside the repository and contains non-empty expected runtime payload directories.' `
            -Details @{ runtimePublishRoot = $RuntimePublishRoot; expectedSources = $expectedSources; entries = @($entryDiagnostics.ToArray()); operatorHints = $operatorHints; handoffAllowed = [bool]$RequireCompleteRuntimePackage }
        return
    }

    $status = if ($RequireCompleteRuntimePackage) { 'Failed' } else { 'Warning' }
    Add-ReleaseCheckResult `
        -Id 'runtime-publish-completeness' `
        -Title 'Runtime publish completeness / runtime payload 完整性' `
        -Status $status `
        -Message "Runtime publish completeness found $($issues.Count) issue(s)." `
        -Remediation @('完整 runtime handoff 前必须补齐仓库外 RuntimePublishRoot；package/readiness 不会从仓库 bin/obj/x64 回退复制，也不会构建、签名或操作 VM。') `
        -Details @{ issues = @($issues.ToArray()); runtimePublishRoot = $RuntimePublishRoot; expectedSources = $expectedSources; entries = @($entryDiagnostics.ToArray()); operatorHints = $operatorHints; requireCompleteRuntimePackage = [bool]$RequireCompleteRuntimePackage; handoffAllowed = $false }
}

function Test-CSignToolNotInReleasePath {
    $legacyInvocations = New-Object System.Collections.Generic.List[object]
    $files = @(Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -File -Filter '*.ps1' |
        Where-Object {
            $_.FullName -notmatch '\\\.git\\' -and
            $_.FullName -notmatch '\\bin\\|\\obj\\|\\x64\\' -and
            $_.Name -notlike 'Sign-SandboxDriverWithKswordCSignTool.ps1'
        })

    foreach ($file in $files) {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
        if (@($parseErrors).Count -gt 0) {
            continue
        }

        $commandAsts = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst]
                }, $true))

        foreach ($commandAst in $commandAsts) {
            $commandName = $commandAst.GetCommandName()
            $leaf = if ([string]::IsNullOrWhiteSpace($commandName)) { '' } else { Split-Path -Leaf $commandName }
            $text = $commandAst.Extent.Text
            $isDirectLegacyInvocation = $leaf -ieq 'CSignTool.exe' -or $leaf -ieq 'Sign-SandboxDriverWithKswordCSignTool.ps1'
            $isStartProcessLegacyInvocation = $commandName -ieq 'Start-Process' -and $text -match '(?i)-FilePath\s+["'']?[^"`''\r\n]*(CSignTool\.exe|Sign-SandboxDriverWithKswordCSignTool)'
            $isPowerShellLegacyInvocation = $commandName -match '^(powershell|powershell\.exe|pwsh|pwsh\.exe)$' -and $text -match '(?i)-File\s+["'']?[^"`''\r\n]*Sign-SandboxDriverWithKswordCSignTool'
            if ($isDirectLegacyInvocation -or $isStartProcessLegacyInvocation -or $isPowerShellLegacyInvocation) {
                [void]$legacyInvocations.Add([pscustomobject]@{
                        Path       = $file.FullName
                        LineNumber = $commandAst.Extent.StartLineNumber
                        Line       = $text
                    })
            }
        }
    }

    if ($legacyInvocations.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'no-csigntool-release-path' `
            -Title 'No CSignTool in release path / 发布链路不调用 CSignTool' `
            -Status Passed `
            -Message 'Operational PowerShell scripts do not call CSignTool.exe or the legacy KSword signing wrapper.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'no-csigntool-release-path' `
        -Title 'No CSignTool in release path / 发布链路不调用 CSignTool' `
        -Status Failed `
        -Message "Found $($legacyInvocations.Count) CSignTool invocation(s) in normal release scripts." `
        -Remediation @('Keep CSignTool usage out of normal install/run/package/readiness paths; use ordinary signtool/test-signing docs only when explicitly requested.') `
        -Details @{ matches = @($legacyInvocations.ToArray()) }
}

function Test-NoGuiSigningFallback {
    $guiIndicators = New-Object System.Collections.Generic.List[object]
    $files = @(Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -File -Filter '*.ps1' |
        Where-Object {
            $_.FullName -notmatch '\\\.git\\' -and
            $_.FullName -notmatch '\\bin\\|\\obj\\|\\x64\\' -and
            $_.Name -notlike 'Sign-SandboxDriverWithKswordCSignTool.ps1'
        })

    foreach ($file in $files) {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
        if (@($parseErrors).Count -gt 0) {
            continue
        }

        $commandAsts = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst]
                }, $true))

        foreach ($commandAst in $commandAsts) {
            $commandName = $commandAst.GetCommandName()
            $leaf = if ([string]::IsNullOrWhiteSpace($commandName)) { '' } else { Split-Path -Leaf $commandName }
            $text = $commandAst.Extent.Text
            $isDirectGuiCommand = $leaf -in @('Out-GridView', 'AuthenticodeVariantGUI.exe')
            $isGuiTypeOrAssembly = $text -match '(?i)(System\.Windows\.Forms|Microsoft\.Win32\.(OpenFileDialog|SaveFileDialog)|FolderBrowserDialog|OpenFileDialog|SaveFileDialog|PresentationFramework)'
            $isGuiSignerProcess = $commandName -ieq 'Start-Process' -and $text -match '(?i)AuthenticodeVariantGUI\.exe'
            if ($isDirectGuiCommand -or $isGuiTypeOrAssembly -or $isGuiSignerProcess) {
                [void]$guiIndicators.Add([pscustomobject]@{
                        Path       = $file.FullName
                        LineNumber = $commandAst.Extent.StartLineNumber
                        Line       = $text
                    })
            }
        }

        $typeAsts = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.TypeExpressionAst]
                }, $true))

        foreach ($typeAst in $typeAsts) {
            $typeName = [string]$typeAst.TypeName.FullName
            if ($typeName -match '(?i)(System\.Windows\.Forms|Microsoft\.Win32\.(OpenFileDialog|SaveFileDialog)|FolderBrowserDialog|OpenFileDialog|SaveFileDialog)') {
                [void]$guiIndicators.Add([pscustomobject]@{
                        Path       = $file.FullName
                        LineNumber = $typeAst.Extent.StartLineNumber
                        Line       = $typeAst.Extent.Text
                    })
            }
        }
    }

    if ($guiIndicators.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'no-gui-signing-fallback' `
            -Title 'No GUI signing fallback / 无 GUI 签名回退' `
            -Status Passed `
            -Message 'Operational PowerShell scripts do not use GUI dialog APIs, Out-GridView, or AuthenticodeVariantGUI.exe as a signing fallback.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'no-gui-signing-fallback' `
        -Title 'No GUI signing fallback / 无 GUI 签名回退' `
        -Status Failed `
        -Message "Found $($guiIndicators.Count) GUI fallback indicator(s) in operational PowerShell scripts." `
        -Remediation @('Keep signing out of normal release paths. Lab-only signing must be explicit, non-interactive, and must fail or skip clearly instead of launching dialogs.') `
        -Details @{ matches = @($guiIndicators.ToArray()) }
}

function Test-ReadinessNoVmMutationCommands {
    $forbiddenCommands = @(
        'Start-VM',
        'Stop-VM',
        'Restart-VM',
        'Restore-VMSnapshot',
        'Checkpoint-VM',
        'Remove-VMSnapshot',
        'Set-VM',
        'Set-VMMemory',
        'Set-VMProcessor',
        'Enable-VMIntegrationService',
        'Disable-VMIntegrationService',
        'Copy-VMFile',
        'Set-GuestTestSigning.ps1',
        'Start-SandboxHyperVJob.ps1'
    )

    $checkedScripts = @(
        'scripts\Test-ReleaseReadiness.ps1',
        'scripts\Test-RepositoryPolicy.ps1',
        'scripts\package-portable.ps1'
    )

    $issues = New-Object System.Collections.Generic.List[object]
    foreach ($relative in $checkedScripts) {
        $path = Join-Path $RepositoryRoot $relative
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
        if (@($parseErrors).Count -gt 0) {
            [void]$issues.Add([pscustomobject]@{ path = $relative; command = 'parse-error'; line = 0; text = 'Unable to parse script for safety command audit.' })
            continue
        }

        $commandAsts = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst]
                }, $true))

        foreach ($commandAst in $commandAsts) {
            $commandName = $commandAst.GetCommandName()
            if ([string]::IsNullOrWhiteSpace($commandName)) {
                continue
            }

            $leaf = Split-Path -Leaf $commandName
            if ($forbiddenCommands -contains $leaf) {
                [void]$issues.Add([pscustomobject]@{
                        path    = $relative
                        command = $leaf
                        line    = $commandAst.Extent.StartLineNumber
                        text    = $commandAst.Extent.Text
                    })
            }

            if ($leaf -ieq 'git') {
                $commandText = $commandAst.Extent.Text
                if ($commandText -match '(?i)\bpush\b') {
                    [void]$issues.Add([pscustomobject]@{
                            path    = $relative
                            command = 'git push'
                            line    = $commandAst.Extent.StartLineNumber
                            text    = $commandText
                        })
                }
            }
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'readiness-non-mutating' `
            -Title 'Readiness/package scripts are non-mutating / readiness 和打包不操作 VM' `
            -Status Passed `
            -Message 'Release readiness and portable packaging scripts do not invoke VM mutation, driver signing, git push, or Hyper-V live scripts.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'readiness-non-mutating' `
        -Title 'Readiness/package scripts are non-mutating / readiness 和打包不操作 VM' `
        -Status Failed `
        -Message "Found $($issues.Count) forbidden command invocation(s) in release readiness/package scripts." `
        -Remediation @('Keep readiness/package scripts limited to parsing, repository policy, source staging, and optional light builds; move VM/live/signing actions to explicit operator runbooks.') `
        -Details @{ issues = @($issues.ToArray()) }
}

function Test-DeploymentOperatorDiagnosticsContract {
    $requiredMarkers = [ordered]@{
        'install.ps1' = @(
            'Get-InstallHyperVPrerequisiteStatus',
            'Get-InstallGuestPayloadStatus',
            'Get-InstallVirusTotalStatus',
            'RuntimeRootUnderRepository',
            'StartsOrMutatesVm = $false'
        )
        'run.ps1' = @(
            'Get-RunHyperVPrerequisiteStatus',
            'GuestPayloadFreshnessReasons',
            'VirusTotalMissingKeyBehavior',
            'RuntimeRootUnderRepository',
            'StartsOrMutatesVm = $false'
        )
        'scripts/package-portable.ps1' = @(
            'Assert-RuntimePackageArchiveRequiresCompletePayloads',
            'operatorDiagnostics',
            'runtimePublishEntries',
            'runtimePublishSummary',
            'runtimeDryRunGuardrail',
            'runtimeArchiveRequiresCompleteRuntimePayloads',
            'runtimePublishRootMissingRecommendedActions',
            'externalStateDiagnostics',
            'freshLiveEvidenceGuardrail',
            'runtimePublishRootMustBeOutsideRepository',
            'no VM mutation, no driver signing, no GUI signing fallback',
            'no CSignTool'
        )
        'scripts/install.ps1' = @(
            'ShowTestSigningGuidance',
            'PreparePayload',
            'ConfigureVTKey',
            'CheckEnvironment'
        )
        'scripts/run.ps1' = @(
            'CheckEnvironment',
            'RequirePayloadForWebUI',
            'Live Hyper-V execution is',
            'root runtime wrapper'
        )
    }

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $requiredMarkers.Keys) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$issues.Add("Missing diagnostic file: $relative")
            continue
        }

        $raw = Get-Content -LiteralPath $path -Raw
        foreach ($marker in $requiredMarkers[$relative]) {
            if ($raw.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$issues.Add("Missing deployment diagnostic marker '$marker' in $relative")
            }
        }
    }

    foreach ($relative in @('packaging/source-package.manifest.json', 'packaging/runtime-package.manifest.json')) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$issues.Add("Missing packaging manifest for diagnostics contract: $relative")
            continue
        }

        $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
        $releaseContract = Get-ObjectPropertyValue -InputObject $manifest -Name 'releaseContract' -DefaultValue $null
        if ($null -eq $releaseContract) {
            [void]$issues.Add("releaseContract missing in $relative")
            continue
        }

        $operatorDiagnostics = [string](Get-ObjectPropertyValue -InputObject $releaseContract -Name 'operatorDiagnostics' -DefaultValue '')
        if ($operatorDiagnostics.IndexOf('Hyper-V', [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            $operatorDiagnostics.IndexOf('RuntimePublishRoot', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            [void]$issues.Add("releaseContract.operatorDiagnostics should mention Hyper-V and RuntimePublishRoot in $relative")
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'deployment-operator-diagnostics' `
            -Title 'Deployment operator diagnostics / 部署诊断契约' `
            -Status Passed `
            -Message 'Install/run/package paths expose non-mutating diagnostics for Hyper-V prerequisites, VM profile, guest payload, VT key, RuntimePublishRoot, and package safety.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'deployment-operator-diagnostics' `
        -Title 'Deployment operator diagnostics / 部署诊断契约' `
        -Status Failed `
        -Message "Deployment diagnostic contract found $($issues.Count) issue(s)." `
        -Remediation @('Keep install/run/readiness/package diagnostics explicit, bilingual, and non-mutating before release handoff.') `
        -Details @{ issues = @($issues.ToArray()) }
}

function Test-DeploymentDocsOperatorHints {
    $requiredMarkers = [ordered]@{
        'docs/install.md' = @(
            'ShowTestSigningGuidance',
            'GuestPayloadStatus',
            'VirusTotalStatus',
            'RuntimeRootUnderRepository',
            '不会启动、还原或停止 VM'
        )
        'docs/run.md' = @(
            'CheckEnvironment',
            'GuestPayloadFreshnessReasons',
            'VirusTotalMissingKeyBehavior',
            'RequirePayloadForWebUI',
            '不会启动、还原或停止 Hyper-V VM'
        )
        'docs/release.md' = @(
            'runtimePublishSummary',
            'runtimeDryRunGuardrail',
            'runtimeArchiveRequiresCompleteRuntimePayloads',
            'runtimePublishRootMissingRecommendedActions',
            'externalStateDiagnostics',
            'freshLiveEvidenceGuardrail',
            'no VM mutation',
            'no GUI signing fallback',
            'CSignTool'
        )
    }

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $requiredMarkers.Keys) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$issues.Add("Missing deployment doc: $relative")
            continue
        }

        $raw = Get-Content -LiteralPath $path -Raw
        foreach ($marker in $requiredMarkers[$relative]) {
            if ($raw.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$issues.Add("Missing operator hint marker '$marker' in $relative")
            }
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'deployment-docs-operator-hints' `
            -Title 'Deployment docs operator hints / 部署文档操作者提示' `
            -Status Passed `
            -Message 'Install/run/release docs describe non-mutating checks and repair hints for Hyper-V, guest payload, VT key, and RuntimePublishRoot gaps.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'deployment-docs-operator-hints' `
        -Title 'Deployment docs operator hints / 部署文档操作者提示' `
        -Status Failed `
        -Message "Deployment docs operator hints found $($issues.Count) issue(s)." `
        -Remediation @('Update docs/install.md, docs/run.md, and docs/release.md before release handoff so reviewers see concrete next-step commands for common deployment gaps.') `
        -Details @{ issues = @($issues.ToArray()) }
}

function Test-NoFreshLiveEvidenceGuardrail {
    $requiredMarkers = [ordered]@{
        'docs/release.md' = @(
            'fresh live evidence',
            'job id',
            '本候选未刷新 fresh live evidence'
        )
        'docs/run.md' = @(
            'fresh live evidence',
            '不会替 release notes 自动生成 fresh live evidence',
            'job id'
        )
        'docs/v1-release-gap-audit.md' = @(
            '本次不调整百分比',
            'fresh live evidence',
            'job id'
        )
        'docs/progress.md' = @(
            '本次不调整百分比',
            'fresh live evidence',
            'job id'
        )
        'scripts/package-portable.ps1' = @(
            'freshLiveEvidenceGuardrail',
            'packagingCreatesFreshLiveEvidence = $false',
            'releaseReadinessCreatesFreshLiveEvidence = $false'
        )
    }

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $requiredMarkers.Keys) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$issues.Add("Missing no-fresh-live guardrail file: $relative")
            continue
        }

        $raw = Get-Content -LiteralPath $path -Raw
        foreach ($marker in $requiredMarkers[$relative]) {
            if ($raw.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$issues.Add("Missing no-fresh-live marker '$marker' in $relative")
            }
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'no-fresh-live-evidence-guardrail' `
            -Title 'No fresh live evidence claims / 不冒充 fresh live 证据' `
            -Status Passed `
            -Message '中文：readiness/package/docs 明确说明低成本发布检查不会启动 live，也不会生成 fresh live evidence；release notes 必须记录实验室 job id 后才能声明当前候选已刷新 live 证据。'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'no-fresh-live-evidence-guardrail' `
        -Title 'No fresh live evidence claims / 不冒充 fresh live 证据' `
        -Status Failed `
        -Message "No-fresh-live guardrail found $($issues.Count) issue(s)." `
        -Remediation @('在 release/run/progress/gap 文档和 package metadata 中写清楚：readiness/package 不运行 Hyper-V live；没有当前候选 job id 时，release notes 必须声明未刷新 fresh live evidence。') `
        -Details @{ issues = @($issues.ToArray()) }
}

function Invoke-RepositoryPolicy {
    $scriptPath = Join-Path $RepositoryRoot 'scripts\Test-RepositoryPolicy.ps1'
    Invoke-ReleaseCommand `
        -Id 'repository-policy' `
        -Title 'Repository policy / 仓库策略' `
        -FilePath 'powershell.exe' `
        -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath, '-RepositoryRoot', $RepositoryRoot) `
        -Remediation @('Remove generated binaries, samples, VM artifacts, reports, captures, signing material, or secrets from the repository candidate set.')
}

function Invoke-SourcePackageStage {
    if ($SkipSourcePackageDryRun) {
        Add-ReleaseCheckResult `
            -Id 'source-package-stage' `
            -Title 'Source package stage / 源码包预暂存' `
            -Status Skipped `
            -Message 'Skipped by explicit -SkipSourcePackageDryRun. Default readiness performs a local StageOnly source-package dry run because it is non-mutating and catches exclusion regressions.'
        return
    }

    $packageScript = Join-Path $RepositoryRoot 'scripts\package-portable.ps1'
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $packageScript,
        '-PackageKind',
        'source',
        '-RepositoryRoot',
        $RepositoryRoot,
        '-OutputRoot',
        (Join-Path $OutputRoot 'packages'),
        '-StageOnly',
        '-Force'
    )

    if ($AllowDirtySource) {
        $arguments += '-AllowDirtySource'
    }

    Invoke-ReleaseCommand `
        -Id 'source-package-stage' `
        -Title 'Source package stage / 源码包预暂存' `
        -FilePath 'powershell.exe' `
        -Arguments $arguments `
        -Remediation @('Inspect package-manifest.generated.json and remove any unintended runtime/build artifacts, secrets, reports, samples, VM state, signing material, or repository binaries.')
}

function Invoke-LightBuild {
    if (-not $IncludeBuild) {
        Add-ReleaseCheckResult `
            -Id 'light-build' `
            -Title 'Light build / 轻量构建' `
            -Status Skipped `
            -Message 'Skipped by default to keep release-readiness cheap. Rerun with -IncludeBuild before final tag or handoff.'
        return
    }

    $buildOutput = Join-Path $OutputRoot 'verify\web'
    Invoke-ReleaseCommand `
        -Id 'light-build' `
        -Title 'Light build / 轻量构建' `
        -FilePath 'dotnet' `
        -Arguments @('build', (Join-Path $RepositoryRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'), '-c', 'Verify', '-p:UseSharedCompilation=false', "-p:OutDir=$buildOutput\") `
        -Remediation @('Fix compile errors before release handoff.')
}

if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) {
    [void](New-Item -ItemType Directory -Force -Path $OutputRoot)
}

$gitAvailable = Test-GitAvailable
if ($gitAvailable) {
    Test-GitClean
}

Test-PackageManifests
Test-RuntimePublishCompleteness
Test-PowerShellScriptSyntax
Test-ScriptWrapperParameterSurface
Test-CSignToolNotInReleasePath
Test-NoGuiSigningFallback
Test-ReadinessNoVmMutationCommands
Test-DeploymentOperatorDiagnosticsContract
Test-DeploymentDocsOperatorHints
Test-NoFreshLiveEvidenceGuardrail
Invoke-RepositoryPolicy
Invoke-SourcePackageStage
Invoke-LightBuild

$failed = @($script:Results | Where-Object { $_.status -eq 'Failed' })
$warnings = @($script:Results | Where-Object { $_.status -eq 'Warning' })
$exitCode = if ($failed.Count -gt 0 -or ($TreatWarningsAsErrors -and $warnings.Count -gt 0)) { 1 } else { 0 }

$summary = [pscustomobject][ordered]@{
    contractVersion       = 1
    kind                  = 'KSwordSandbox.ReleaseReadiness'
    generatedAtUtc        = [DateTimeOffset]::UtcNow.ToString('O')
    repositoryRoot        = $RepositoryRoot
    outputRoot            = $OutputRoot
    exitCode              = $exitCode
    failedCount           = $failed.Count
    warningCount          = $warnings.Count
    skippedCount          = @($script:Results | Where-Object { $_.status -eq 'Skipped' }).Count
    passedCount           = @($script:Results | Where-Object { $_.status -eq 'Passed' }).Count
    allowDirtySource      = [bool]$AllowDirtySource
    stageSourcePackage    = [bool]$StageSourcePackage
    sourcePackageDryRun   = -not [bool]$SkipSourcePackageDryRun
    skipSourcePackageDryRun = [bool]$SkipSourcePackageDryRun
    runtimePublishRoot    = if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) { $null } else { $RuntimePublishRoot }
    requireCompleteRuntimePackage = [bool]$RequireCompleteRuntimePackage
    includeBuild          = [bool]$IncludeBuild
    noVmMutation          = $true
    noDriverSigning       = $true
    noGuiSigningFallback  = $true
    csignToolNotCalled    = $true
    freshLiveEvidenceGenerated = $false
    freshLiveEvidenceRequiresExplicitLabRun = $true
    freshLiveEvidenceLabCommand = '.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live'
    releaseNotesFreshLiveFallback = '本候选未刷新 fresh live evidence'
    operatorReadinessHints = @(
        'Runtime handoff requires a complete external RuntimePublishRoot; source/package dry-runs do not prove runtime payload completeness.',
        'Use install/run CheckEnvironment for read-only VT key, Hyper-V prerequisite, VM profile, guest payload freshness, runtime-root-under-repository, and driver-path hints.',
        'No readiness/package command creates a job id; release notes need an explicit lab live run before claiming fresh live evidence.'
    )
    results               = @($script:Results.ToArray())
}

$summaryPath = Join-Path $OutputRoot 'release-readiness.json'
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8

function ConvertTo-ChineseFirstLabel {
    param([string]$Text)

    $parts = @($Text -split '\s+/\s+', 2)
    if ($parts.Count -eq 2) {
        return "$($parts[1]) / $($parts[0])"
    }

    return $Text
}

Write-Host "发布就绪检查结果：通过=$($summary.passedCount)，警告=$($summary.warningCount)，失败=$($summary.failedCount)，跳过=$($summary.skippedCount)。"
foreach ($result in $script:Results) {
    $prefix = switch ($result.status) {
        'Passed' { '通过 [pass]' }
        'Warning' { '警告 [warn]' }
        'Failed' { '失败 [fail]' }
        default { '跳过 [skip]' }
    }

    $displayTitle = ConvertTo-ChineseFirstLabel -Text $result.title
    Write-Host "$prefix $($result.id): $displayTitle"
    Write-Host "  说明：$($result.message)"
    if (@($result.remediation).Count -gt 0) {
        Write-Host "  下一步：$(@($result.remediation) -join '；')"
    }
}

Write-Host "发布就绪摘要已写入：$summaryPath"
Write-Host '安全护栏：未启动/还原/停止 VM，未签名，未调用 CSignTool/GUI signing fallback，未生成 fresh live evidence。'
exit $exitCode
