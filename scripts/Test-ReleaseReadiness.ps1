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
    $scriptPaths = New-Object System.Collections.Generic.List[object]
    foreach ($relative in @('run.ps1', 'install.ps1')) {
        [void]$scriptPaths.Add([pscustomobject]@{
                Path     = (Join-Path $RepositoryRoot $relative)
                Critical = $true
                Scope    = 'release-wrapper'
            })
    }

    $scriptsRoot = Join-Path $RepositoryRoot 'scripts'
    $auxiliarySyntaxWarningScripts = @(
        'Test-R0Readiness.ps1'
    )
    if (Test-Path -LiteralPath $scriptsRoot -PathType Container) {
        foreach ($scriptFile in @(Get-ChildItem -LiteralPath $scriptsRoot -Filter '*.ps1' -File |
                Where-Object { $_.Name -notlike 'Sign-SandboxDriver*.ps1' } |
                Sort-Object FullName)) {
            $isAuxiliaryWarning = $auxiliarySyntaxWarningScripts -contains $scriptFile.Name
            [void]$scriptPaths.Add([pscustomobject]@{
                    Path     = $scriptFile.FullName
                    Critical = -not $isAuxiliaryWarning
                    Scope    = if ($isAuxiliaryWarning) { 'auxiliary-lab-readiness-warning' } else { 'release-script' }
                })
        }
    }

    $errors = New-Object System.Collections.Generic.List[object]
    $warningErrors = New-Object System.Collections.Generic.List[object]
    $repoPrefix = $RepositoryRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $parsedCount = 0
    foreach ($scriptPathEntry in @($scriptPaths.ToArray() | Sort-Object Path -Unique)) {
        $path = [string]$scriptPathEntry.Path
        $critical = [bool]$scriptPathEntry.Critical
        $scope = [string]$scriptPathEntry.Scope
        $displayPath = if ($path.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $path.Substring($repoPrefix.Length)
        }
        else {
            $path
        }

        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $issue = [pscustomobject]@{ script = $displayPath; error = 'missing'; scope = $scope; critical = $critical }
            if ($critical) {
                [void]$errors.Add($issue)
            }
            else {
                [void]$warningErrors.Add($issue)
            }
            continue
        }

        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
        $parsedCount++
        foreach ($parseError in @($parseErrors)) {
            $issue = [pscustomobject]@{
                    script  = $displayPath
                    message = $parseError.Message
                    extent  = [string]$parseError.Extent
                    scope   = $scope
                    critical = $critical
                }
            if ($critical) {
                [void]$errors.Add($issue)
            }
            else {
                [void]$warningErrors.Add($issue)
            }
        }
    }

    if ($errors.Count -eq 0 -and $warningErrors.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'powershell-syntax' `
            -Title 'PowerShell syntax / PowerShell 语法' `
            -Status Passed `
            -Message "Parsed $parsedCount PowerShell script(s): root wrappers plus scripts/*.ps1 excluding signing helpers."
        return
    }

    if ($errors.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'powershell-syntax' `
            -Title 'PowerShell syntax / PowerShell 语法' `
            -Status Warning `
            -Message "Release-critical PowerShell parsed successfully, but auxiliary lab/readiness scripts reported $($warningErrors.Count) parser issue(s)." `
            -Remediation @('Do not block release packaging on auxiliary lab script parser issues introduced by concurrent work, but route these warnings to the owning implementation area before final lab validation.') `
            -Details @{ warnings = @($warningErrors.ToArray()); parsedCount = $parsedCount }
        return
    }

    Add-ReleaseCheckResult `
        -Id 'powershell-syntax' `
        -Title 'PowerShell syntax / PowerShell 语法' `
        -Status Failed `
        -Message "PowerShell parser found $($errors.Count) issue(s)." `
        -Remediation @('Fix parser errors before packaging or tagging a release.') `
        -Details @{ errors = @($errors.ToArray()); warnings = @($warningErrors.ToArray()) }
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

function New-RuntimePublishCompletenessSummary {
    param(
        [string[]]$ExpectedSources = @(),

        [object[]]$Entries = @(),

        [bool]$RootProvided = $false,

        [bool]$RootExists = $false,

        [bool]$RootOutsideRepository = $false,

        [bool]$RequireCompleteRuntimePackageValue = $false
    )

    $entryArray = @($Entries)
    $presentEntries = @($entryArray | Where-Object { [bool]$_.exists })
    $missingEntries = @($entryArray | Where-Object { -not [bool]$_.exists })
    $emptyEntries = @($entryArray | Where-Object { [bool]$_.exists -and [int]$_.fileCount -eq 0 })
    $incompleteEntries = @($entryArray | Where-Object {
            [bool]$_.exists -and (
                [int]$_.fileCount -eq 0 -or
                @($_.missingExpectedLeaves).Count -gt 0 -or
                @($_.forbiddenFilePreview).Count -gt 0
            )
        })

    $knownEntrySources = @($entryArray | ForEach-Object { [string]$_.source } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $missingSources = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $missingEntries) {
        if (-not [string]::IsNullOrWhiteSpace([string]$entry.source)) {
            [void]$missingSources.Add([string]$entry.source)
        }
    }

    foreach ($expectedSource in @($ExpectedSources)) {
        if ([string]::IsNullOrWhiteSpace($expectedSource)) {
            continue
        }

        if (-not $RootProvided -or -not $RootExists -or ($knownEntrySources -notcontains $expectedSource)) {
            [void]$missingSources.Add($expectedSource)
        }
    }

    $totalPayloadBytes = [Int64]0
    $missingExpectedLeafCount = 0
    $forbiddenFileCount = 0
    foreach ($entry in $entryArray) {
        if ($null -ne $entry.PSObject.Properties['totalBytes']) {
            $totalPayloadBytes += [Int64]$entry.totalBytes
        }

        $missingExpectedLeafCount += @($entry.missingExpectedLeaves).Count
        $forbiddenFileCount += @($entry.forbiddenFilePreview).Count
    }

    $uniqueMissingSources = @($missingSources.ToArray() | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $failureMode = if (-not $RootProvided) {
        'runtimePublishRootNotProvided'
    }
    elseif (-not $RootOutsideRepository) {
        'runtimePublishRootInsideRepository'
    }
    elseif (-not $RootExists) {
        'runtimePublishRootMissing'
    }
    elseif ($uniqueMissingSources.Count -gt 0) {
        'missingRuntimePayload'
    }
    elseif ($forbiddenFileCount -gt 0) {
        'forbiddenRuntimePayloadFile'
    }
    elseif ($missingExpectedLeafCount -gt 0 -or $emptyEntries.Count -gt 0) {
        'incompleteRuntimePayloadContents'
    }
    else {
        'ready'
    }

    return [ordered]@{
        schema = 'ksword.release.runtime-publish-completeness.v28'
        expectedCount = @($ExpectedSources).Count
        presentCount = $presentEntries.Count
        missingCount = $uniqueMissingSources.Count
        emptyCount = $emptyEntries.Count
        incompleteCount = $incompleteEntries.Count
        missingExpectedLeafCount = $missingExpectedLeafCount
        forbiddenFileCount = $forbiddenFileCount
        totalPayloadBytes = $totalPayloadBytes
        expectedSources = @($ExpectedSources)
        presentSources = @($presentEntries | ForEach-Object { $_.source })
        missingSources = @($uniqueMissingSources)
        emptySources = @($emptyEntries | ForEach-Object { $_.source })
        incompleteSources = @($incompleteEntries | ForEach-Object { $_.source })
        forbiddenSources = @($entryArray | Where-Object { @($_.forbiddenFilePreview).Count -gt 0 } | ForEach-Object { $_.source })
        rootProvided = $RootProvided
        rootExists = $RootExists
        rootOutsideRepository = $RootOutsideRepository
        requireCompleteRuntimePackage = $RequireCompleteRuntimePackageValue
        completeRuntimePackageReady = ($RootProvided -and $RootExists -and $RootOutsideRepository -and $uniqueMissingSources.Count -eq 0 -and $incompleteEntries.Count -eq 0)
        handoffAllowed = ($RootProvided -and $RootExists -and $RootOutsideRepository -and $RequireCompleteRuntimePackageValue -and $uniqueMissingSources.Count -eq 0 -and $incompleteEntries.Count -eq 0)
        failureMode = $failureMode
    }
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

    $expectedSources = @($runtimeEntries | ForEach-Object { [string](Get-ObjectPropertyValue -InputObject $_ -Name 'source' -DefaultValue '') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique)
    $expectedRuntimePayloadLeaves = @{
        'host-web' = @('KSword.Sandbox.Web.exe|KSword.Sandbox.Web.dll')
        'guest-tools' = @('payload-manifest.json', 'agent/KSword.Sandbox.Agent.exe|agent/KSword.Sandbox.Agent.dll', 'r0collector/KSword.Sandbox.R0Collector.exe')
        'tools/job-tool' = @('KSword.Sandbox.JobTool.exe|KSword.Sandbox.JobTool.dll')
        'tools/postprocess' = @('KSword.Sandbox.PostProcess.exe|KSword.Sandbox.PostProcess.dll')
    }
    $forbiddenRuntimePublishExtensions = @('.pdb', '.sys', '.pcap', '.pcapng', '.dmp', '.mdmp', '.vhd', '.vhdx', '.avhd', '.avhdx', '.pfx', '.pem', '.key', '.dpapi', '.jsonl', '.sqlite', '.db', '.zip')
    $forbiddenRuntimePublishNames = @('sandbox.local.json', 'install-state.json', 'guest-password.dpapi', '.env', 'CSignTool.exe', 'AuthenticodeVariantGUI.exe', 'signtool.exe')
    $operatorHints = @(
        'Runtime payload completeness is a handoff gate only when -RuntimePublishRoot and -RequireCompleteRuntimePackage are supplied.',
        'Expected external payload folders: host-web, guest-tools, tools/job-tool, tools/postprocess.',
        'Expected payload leaves include host-web KSword.Sandbox.Web exe/dll, guest payload manifest plus Agent/R0Collector, JobTool exe/dll, and PostProcess exe/dll; missing leaves are diagnostics for incomplete publish output.',
        'Read-only environment hints: run .\scripts\install.ps1 -Mode CheckEnvironment and .\scripts\run.ps1 -Mode CheckEnvironment for Hyper-V prerequisites, VM profile, guest payload freshness, and optional VT key status.',
        'This readiness script does not build payloads, copy from repository bin/obj/x64, start/restore/stop VMs, sign drivers, or generate fresh live evidence.'
    )

    if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
        $runtimePublishSummary = New-RuntimePublishCompletenessSummary `
            -ExpectedSources $expectedSources `
            -Entries @() `
            -RootProvided $false `
            -RootExists $false `
            -RootOutsideRepository $false `
            -RequireCompleteRuntimePackageValue ([bool]$RequireCompleteRuntimePackage)
        $rootDiagnostics = [ordered]@{
            provided = $false
            resolvedPath = $null
            exists = $false
            outsideRepository = $false
            repositoryBinaryFallbackAllowed = $false
            gateMode = if ($RequireCompleteRuntimePackage) { 'blocked-missing-runtime-publish-root' } else { 'source-layout-readiness-only' }
        }

        if ($RequireCompleteRuntimePackage) {
            Add-ReleaseCheckResult `
                -Id 'runtime-publish-completeness' `
                -Title 'Runtime publish completeness / runtime payload 完整性' `
                -Status Failed `
                -Message '完整 runtime 便携包要求 -RuntimePublishRoot；当前未提供。' `
                -Remediation @('先把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到仓库外目录，再重跑：.\scripts\Test-ReleaseReadiness.ps1 -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage。') `
                -Details @{ expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; operatorHints = $operatorHints; dryRunOnly = $true; handoffAllowed = $false }
            return
        }

        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Skipped `
            -Message 'Skipped complete runtime payload gate. This is acceptable for source/layout readiness only; use -RuntimePublishRoot with -RequireCompleteRuntimePackage before runtime handoff.' `
            -Details @{ expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; operatorHints = $operatorHints; dryRunOnly = $true; handoffAllowed = $false }
        return
    }

    $issues = New-Object System.Collections.Generic.List[string]
    $entryDiagnostics = New-Object System.Collections.Generic.List[object]
    $rootFull = [System.IO.Path]::GetFullPath($RuntimePublishRoot)
    $repoPrefix = ([System.IO.Path]::GetFullPath($RepositoryRoot)).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $rootPrefix = $rootFull.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $repoFull = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
    $rootExists = Test-Path -LiteralPath $rootFull -PathType Container
    $rootOutsideRepository = $true
    if ($rootFull.TrimEnd('\', '/') -ieq $repoFull -or $rootFull.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        [void]$issues.Add("RuntimePublishRoot must be outside the repository: $RuntimePublishRoot")
        $rootOutsideRepository = $false
    }

    if (-not $rootExists) {
        [void]$issues.Add("RuntimePublishRoot does not exist or is not a directory: $RuntimePublishRoot")
    }
    else {
        foreach ($entry in $runtimeEntries) {
            $source = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'source' -DefaultValue '')
            $target = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'target' -DefaultValue $source)
            $required = [bool](Get-ObjectPropertyValue -InputObject $entry -Name 'required' -DefaultValue $false)
            $handoffRequired = [bool](Get-ObjectPropertyValue -InputObject $entry -Name 'handoffRequired' -DefaultValue $true)
            $note = [string](Get-ObjectPropertyValue -InputObject $entry -Name 'note' -DefaultValue '')
            if ([string]::IsNullOrWhiteSpace($source)) {
                [void]$issues.Add('Runtime publish entry is missing source.')
                continue
            }

            $sourcePath = [System.IO.Path]::GetFullPath((Join-Path $rootFull $source))
            if (($sourcePath -ne $rootFull) -and (-not $sourcePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase))) {
                [void]$issues.Add("Runtime publish entry escapes RuntimePublishRoot: $source")
                [void]$entryDiagnostics.Add([pscustomobject][ordered]@{
                        source = $source
                        target = $target
                        required = $required
                        handoffRequired = $handoffRequired
                        note = $note
                        sourcePath = $sourcePath
                        exists = $false
                        fileCount = 0
                        totalBytes = 0
                        expectedLeaves = @($expectedRuntimePayloadLeaves[$source])
                        missingExpectedLeaves = @($expectedRuntimePayloadLeaves[$source])
                        forbiddenFilePreview = @()
                        error = 'path escapes RuntimePublishRoot'
                    })
                continue
            }

            if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
                [void]$issues.Add("Missing runtime publish payload directory: $source")
                [void]$entryDiagnostics.Add([pscustomobject][ordered]@{
                        source = $source
                        target = $target
                        required = $required
                        handoffRequired = $handoffRequired
                        note = $note
                        sourcePath = $sourcePath
                        exists = $false
                        fileCount = 0
                        totalBytes = 0
                        expectedLeaves = @($expectedRuntimePayloadLeaves[$source])
                        missingExpectedLeaves = @($expectedRuntimePayloadLeaves[$source])
                        forbiddenFilePreview = @()
                        error = 'missing directory'
                    })
                continue
            }

            $files = @(Get-ChildItem -LiteralPath $sourcePath -Recurse -File -Force)
            $totalBytes = [Int64](($files | ForEach-Object { $_.Length } | Measure-Object -Sum).Sum)
            $relativeFiles = @($files | ForEach-Object {
                    $fullName = [System.IO.Path]::GetFullPath($_.FullName)
                    $fullName.Substring($sourcePath.TrimEnd('\', '/').Length + 1).Replace('\', '/')
                })
            $missingExpectedLeaves = New-Object System.Collections.Generic.List[string]
            foreach ($expectedLeaf in @($expectedRuntimePayloadLeaves[$source])) {
                $leafAlternatives = @($expectedLeaf -split '\|' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                $hasExpectedLeaf = $false
                foreach ($leafAlternative in $leafAlternatives) {
                    if ($relativeFiles -contains $leafAlternative) {
                        $hasExpectedLeaf = $true
                        break
                    }
                }

                if (-not $hasExpectedLeaf) {
                    [void]$missingExpectedLeaves.Add($expectedLeaf)
                }
            }

            $forbiddenFiles = @($files | Where-Object {
                    $name = $_.Name
                    $extension = $_.Extension.ToLowerInvariant()
                    ($forbiddenRuntimePublishExtensions -contains $extension) -or ($forbiddenRuntimePublishNames -contains $name)
                } | ForEach-Object {
                    $_.FullName.Substring($sourcePath.TrimEnd('\', '/').Length + 1).Replace('\', '/')
                } | Select-Object -First 20)

            if ($files.Count -eq 0) {
                [void]$issues.Add("Runtime publish payload directory is empty: $source")
            }
            if ($missingExpectedLeaves.Count -gt 0) {
                [void]$issues.Add("Runtime publish payload '$source' is missing expected leaf file(s): $($missingExpectedLeaves -join ', ')")
            }
            if ($forbiddenFiles.Count -gt 0) {
                [void]$issues.Add("Runtime publish payload '$source' contains forbidden/sensitive file(s): $($forbiddenFiles -join ', ')")
            }

            [void]$entryDiagnostics.Add([pscustomobject][ordered]@{
                    source = $source
                    target = $target
                    required = $required
                    handoffRequired = $handoffRequired
                    note = $note
                    sourcePath = $sourcePath
                    exists = $true
                    fileCount = $files.Count
                    totalBytes = $totalBytes
                    expectedLeaves = @($expectedRuntimePayloadLeaves[$source])
                    missingExpectedLeaves = @($missingExpectedLeaves.ToArray())
                    forbiddenFilePreview = @($forbiddenFiles)
                    error = if ($files.Count -eq 0) { 'empty directory' } elseif ($missingExpectedLeaves.Count -gt 0) { 'missing expected leaves' } elseif ($forbiddenFiles.Count -gt 0) { 'forbidden files present' } else { '' }
                })
        }
    }

    $runtimePublishSummary = New-RuntimePublishCompletenessSummary `
        -ExpectedSources $expectedSources `
        -Entries @($entryDiagnostics.ToArray()) `
        -RootProvided $true `
        -RootExists $rootExists `
        -RootOutsideRepository $rootOutsideRepository `
        -RequireCompleteRuntimePackageValue ([bool]$RequireCompleteRuntimePackage)
    $rootDiagnostics = [ordered]@{
        provided = $true
        requestedPath = $RuntimePublishRoot
        resolvedPath = $rootFull
        exists = $rootExists
        outsideRepository = $rootOutsideRepository
        repositoryRoot = $RepositoryRoot
        repositoryBinaryFallbackAllowed = $false
        gateMode = if ([bool]$runtimePublishSummary.handoffAllowed) { 'complete-runtime-handoff-verified' } elseif ($RequireCompleteRuntimePackage) { 'blocked-complete-runtime-handoff' } else { 'diagnostic-only-rerun-with-require-complete' }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Passed `
            -Message 'RuntimePublishRoot is outside the repository and contains non-empty expected runtime payload directories.' `
            -Details @{ runtimePublishRoot = $RuntimePublishRoot; expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; entries = @($entryDiagnostics.ToArray()); operatorHints = $operatorHints; handoffAllowed = [bool]$runtimePublishSummary.handoffAllowed }
        return
    }

    $status = if ($RequireCompleteRuntimePackage) { 'Failed' } else { 'Warning' }
    Add-ReleaseCheckResult `
        -Id 'runtime-publish-completeness' `
        -Title 'Runtime publish completeness / runtime payload 完整性' `
        -Status $status `
        -Message "Runtime publish completeness found $($issues.Count) issue(s)." `
        -Remediation @('完整 runtime handoff 前必须补齐仓库外 RuntimePublishRoot，并确认每个 payload 含预期 exe/dll/manifest 且不含 .pdb/.sys/pcap/dump/VM/secret/signing 文件；package/readiness 不会从仓库 bin/obj/x64 回退复制，也不会构建、签名或操作 VM。') `
        -Details @{ issues = @($issues.ToArray()); runtimePublishRoot = $RuntimePublishRoot; expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; entries = @($entryDiagnostics.ToArray()); operatorHints = $operatorHints; requireCompleteRuntimePackage = [bool]$RequireCompleteRuntimePackage; handoffAllowed = $false }
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
            'runtimePublishRootDiagnostics',
            'runtimeCompletenessDiagnostics',
            'runtimeDryRunGuardrail',
            'runtimeArchiveRequiresCompleteRuntimePayloads',
            'runtimePublishRootMissingRecommendedActions',
            'externalStateDiagnostics',
            'freshLiveEvidenceGuardrail',
            'freshLiveEvidenceGenerated = $false',
            'gap-audit.v28',
            'reviewerChecklist',
            'componentProgress',
            'gapAudit',
            'self-noise-guard-readiness',
            'sourceRuntimeSafetyMetadata',
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
            'runtimePublishRootDiagnostics',
            'runtimeCompletenessDiagnostics',
            'runtimeDryRunGuardrail',
            'runtimeArchiveRequiresCompleteRuntimePayloads',
            'runtimePublishRootMissingRecommendedActions',
            'externalStateDiagnostics',
            'freshLiveEvidenceGuardrail',
            'freshLiveEvidenceGenerated',
            'gap-audit.v28',
            'reviewerChecklist',
            'componentProgress',
            'gapAudit',
            'self-noise-guard-readiness',
            'sourceRuntimeSafetyMetadata',
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
            'fresh live evidence',
            'job id',
            'RuntimePublishRoot'
        )
        'docs/progress.md' = @(
            'fresh live evidence',
            'job id',
            'RuntimePublishRoot'
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

function Test-SelfNoiseGuardReadiness {
    $issues = New-Object System.Collections.Generic.List[string]
    $docEvidence = New-Object System.Collections.Generic.List[object]
    $evidence = [ordered]@{
        rulesPath = 'rules/behavior-rules.json'
        rulesVersion = $null
        totalRules = 0
        guardedRuleCount = 0
        requiredMarkers = @('self-noise', 'noise', 'behaviorCounted', 'collection-health')
        docs = $docEvidence
    }

    $rulesPath = Join-Path $RepositoryRoot 'rules\behavior-rules.json'
    if (-not (Test-Path -LiteralPath $rulesPath -PathType Leaf)) {
        [void]$issues.Add('Missing rules/behavior-rules.json for static self-noise guard audit.')
    }
    else {
        try {
            $rules = Get-Content -LiteralPath $rulesPath -Raw | ConvertFrom-Json -ErrorAction Stop
            $evidence.rulesVersion = [string](Get-ObjectPropertyValue -InputObject $rules -Name 'version' -DefaultValue '')
            $ruleItems = @(Get-ObjectPropertyValue -InputObject $rules -Name 'rules' -DefaultValue @())
            $evidence.totalRules = $ruleItems.Count
            if ($evidence.rulesVersion.IndexOf('self-noise', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                $evidence.rulesVersion.IndexOf('v27', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                $evidence.rulesVersion.IndexOf('v28', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$issues.Add("rules/behavior-rules.json version does not advertise self-noise guard hardening or v27/v28 expansion: $($evidence.rulesVersion)")
            }

            $guardedRuleCount = 0
            foreach ($rule in $ruleItems) {
                $guardText = @(
                    (Get-ObjectPropertyValue -InputObject $rule -Name 'excludeDataContains' -DefaultValue $null),
                    (Get-ObjectPropertyValue -InputObject $rule -Name 'excludeDataEquals' -DefaultValue $null),
                    (Get-ObjectPropertyValue -InputObject $rule -Name 'excludeProcessNames' -DefaultValue $null),
                    (Get-ObjectPropertyValue -InputObject $rule -Name 'tags' -DefaultValue $null),
                    (Get-ObjectPropertyValue -InputObject $rule -Name 'summary' -DefaultValue ''),
                    (Get-ObjectPropertyValue -InputObject $rule -Name 'summaryZh' -DefaultValue '')
                ) | ConvertTo-Json -Depth 8 -Compress
                if ($guardText -match '(?i)selfNoise|self-noise|collectorSelfNoise|collector-self-noise|behaviorCounted|collection-health|virustotal|r0collector|noise') {
                    $guardedRuleCount++
                }
            }
            $evidence.guardedRuleCount = $guardedRuleCount
            if ($guardedRuleCount -le 0) {
                [void]$issues.Add('rules/behavior-rules.json has no statically detectable self-noise/collection-health guard markers.')
            }
        }
        catch {
            [void]$issues.Add("Unable to parse rules/behavior-rules.json for self-noise guard audit: $($_.Exception.Message)")
        }
    }

    foreach ($relative in @('docs/release.md', 'docs/run.md')) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$issues.Add("Missing self-noise readiness doc: $relative")
            continue
        }

        $raw = Get-Content -LiteralPath $path -Raw
        $hasSelfNoise = $raw.IndexOf('self-noise', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $raw.IndexOf('自噪声', [StringComparison]::OrdinalIgnoreCase) -ge 0
        $hasNoLiveBoundary = $raw.IndexOf('fresh live evidence', [StringComparison]::OrdinalIgnoreCase) -ge 0
        [void]$docEvidence.Add([ordered]@{
                path = $relative
                hasSelfNoiseMarker = $hasSelfNoise
                hasFreshLiveBoundary = $hasNoLiveBoundary
            })
        if (-not $hasSelfNoise) {
            [void]$issues.Add("Missing self-noise operator marker in $relative")
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'self-noise-guard-readiness' `
            -Title 'Self-noise guard readiness / 自噪声护栏就绪' `
            -Status Passed `
            -Message 'Static rules/docs audit found self-noise, collection-health, behaviorCounted, and no-fresh-live boundaries without running smoke tests or live Hyper-V.' `
            -Details @{ evidence = $evidence }
        return
    }

    Add-ReleaseCheckResult `
        -Id 'self-noise-guard-readiness' `
        -Title 'Self-noise guard readiness / 自噪声护栏就绪' `
        -Status Failed `
        -Message "Self-noise guard readiness found $($issues.Count) issue(s)." `
        -Remediation @('中文修复：确认 rules/behavior-rules.json 仍是 v26/v27/v28 self-noise hardening 规则，并在 docs/release.md/docs/run.md 写明采集器自噪声、collection-health、VT quiet state 和 behaviorCounted=false 不可计入样本行为；本检查只做静态审计，不运行 smoke/live。') `
        -Details @{ issues = @($issues.ToArray()); evidence = $evidence }
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

function Get-GitReleaseMetadata {
    $metadata = [ordered]@{
        available = $false
        branch = $null
        commit = $null
        shortCommit = $null
        statusCount = $null
        statusPreview = @()
    }

    if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
        return [pscustomobject]$metadata
    }

    try {
        $metadata.available = $true
        $metadata.branch = [string](& git -C $RepositoryRoot rev-parse --abbrev-ref HEAD 2>$null)
        $metadata.commit = [string](& git -C $RepositoryRoot rev-parse HEAD 2>$null)
        $metadata.shortCommit = [string](& git -C $RepositoryRoot rev-parse --short HEAD 2>$null)
        $statusLines = @(& git -C $RepositoryRoot status --porcelain 2>$null)
        $metadata.statusCount = $statusLines.Count
        $metadata.statusPreview = @($statusLines | Select-Object -First 20)
    }
    catch {
        $metadata.available = $false
        $metadata.statusPreview = @("Unable to collect git metadata: $($_.Exception.Message)")
    }

    return [pscustomobject]$metadata
}


function Get-ReleaseComponentProgressSnapshot {
    param([int]$ExitCode = 0)

    $runtimeRootProvided = -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)
    $completeRuntimeRequested = [bool]$RequireCompleteRuntimePackage
    return [ordered]@{
        schema = 'ksword.release.component-progress.v1'
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        purpose = 'Machine-readable component progress for release reviewers; readiness is non-mutating and does not create fresh live evidence; gapAudit uses ksword.release.gap-audit.v28.'
        noFreshLiveEvidenceGenerated = $true
        freshLiveEvidenceGenerated = $false
        gapAuditSchema = 'ksword.release.gap-audit.v28'
        releaseNotesFallbackZh = '本候选未刷新 fresh live evidence'
        components = @(
            [ordered]@{
                id = 'runtime-publish-root'
                titleZh = 'RuntimePublishRoot publish checklist'
                state = if ($runtimeRootProvided -and $completeRuntimeRequested -and $ExitCode -eq 0) { 'ready-for-runtime-handoff' } elseif ($runtimeRootProvided) { 'diagnosed-needs-complete-runtime-gate' } else { 'blocked-missing-external-runtime-publish-root' }
                handoffGate = 'Run readiness with -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage, then package runtime with -RequireCompleteRuntimePayloads.'
                reviewerChecklist = @('outside repository', 'host-web present', 'guest-tools present', 'tools/job-tool present', 'tools/postprocess present', 'no forbidden generated/secret/VM/signing files')
                remediationZh = '把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到仓库外 RuntimePublishRoot；不要从仓库 bin/obj/x64 兜底复制。'
            },
            [ordered]@{
                id = 'package-safety-contract'
                titleZh = '包安全边界'
                state = 'guarded'
                handoffGate = 'No samples, reports, VM state, generated artifacts, secrets, signing material, CSignTool, or GUI signing fallback in source/runtime packages.'
                reviewerChecklist = @('manifest high-risk exclusions present', 'sourceRuntimeSafetyMetadata excludes runtime evidence and signing material', 'rejectIfPresent absent from staged package')
                remediationZh = '如果发现样本、报告、PCAP/dump/trace、VM 文件、secret、证书私钥、driver binary 或 CSignTool，丢弃包并修正 manifest/exclude。'
            },
            [ordered]@{
                id = 'release-smoke-scenarios'
                titleZh = '发布 smoke 场景'
                state = 'documented-low-cost-only'
                handoffGate = 'PowerShell parse, repository policy, source package StageOnly dry-run; no Hyper-V/live/heavy E2E.'
                reviewerChecklist = @('release-readiness.json failedCount=0', 'source package dry-run metadata reviewed', 'complete runtime gate rerun before runtime handoff')
                remediationZh = '低成本 smoke 失败先看 release-readiness.md 的 Next；live smoke 只能由 release manager 在 lab host 显式运行。'
            },
            [ordered]@{
                id = 'fresh-live-guardrail'
                titleZh = 'No-fresh-live guardrail'
                state = 'guarded-not-generated'
                handoffGate = 'Fresh live claim requires lab job id, commit, runtime root, timestamp, and report paths.'
                reviewerChecklist = @('no job id means release notes says 本候选未刷新 fresh live evidence', 'readiness/package outputs are not fresh live evidence')
                remediationZh = '没有当前候选实验室 job id，不得在 release notes 声称 fresh Notepad 5s 或真实 R0 证据。'
            },
            [ordered]@{
                id = 'self-noise-guard-readiness'
                titleZh = '自噪声护栏就绪'
                state = 'static-audit-only'
                handoffGate = 'Rules/docs must show self-noise, collection-health, VT quiet state, and behaviorCounted=false boundaries; no smoke/live execution in readiness.'
                reviewerChecklist = @('rules version advertises self-noise hardening', 'docs explain self-noise stays out of behavior conclusions', 'readiness result self-noise-guard-readiness is Passed')
                remediationZh = '先修复 rules/behavior-rules.json 的 self-noise/collection-health/behaviorCounted guard，再补 docs/release.md/docs/run.md；本 readiness 步骤不运行 smoke/live。'
            },
            [ordered]@{
                id = 'operator-remediation-zh'
                titleZh = '中文操作者修复提示'
                state = 'documented'
                handoffGate = 'install/run CheckEnvironment exposes Chinese next-step commands for deployment gaps.'
                reviewerChecklist = @('Hyper-V prerequisites', 'VM profile/checkpoint', 'guest payload freshness', 'VT key optional state', 'runtime root outside repository')
                remediationZh = '先运行 .\\scripts\\install.ps1 -Mode CheckEnvironment 和 .\\scripts\\run.ps1 -Mode CheckEnvironment，再按 RecommendedActions 修复。'
            }
        )
    }
}

function Get-ReleaseGapAuditSnapshot {
    param([int]$ExitCode = 0)

    $resultById = @{}
    foreach ($result in @($script:Results.ToArray())) {
        $resultById[[string]$result.id] = $result
    }

    $runtimeResult = $resultById['runtime-publish-completeness']
    $freshLiveResult = $resultById['no-fresh-live-evidence-guardrail']
    $selfNoiseResult = $resultById['self-noise-guard-readiness']
    $noVmMutationResult = $resultById['readiness-non-mutating']
    $noCSignToolResult = $resultById['no-csigntool-release-path']
    $noGuiSigningResult = $resultById['no-gui-signing-fallback']
    $manifestResult = $resultById['package-manifests']
    $componentProgress = Get-ReleaseComponentProgressSnapshot -ExitCode $ExitCode
    $runtimeRootProvided = -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)
    $runtimeHandoffVerified = ($runtimeRootProvided -and [bool]$RequireCompleteRuntimePackage -and $null -ne $runtimeResult -and $runtimeResult.status -eq 'Passed' -and $ExitCode -eq 0)
    $runtimeSummary = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('runtimePublishSummary')) { $runtimeResult.details.runtimePublishSummary } else { $null }
    $runtimeEntries = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('entries')) { @($runtimeResult.details.entries) } else { @() }
    $rootDiagnostics = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('rootDiagnostics')) { $runtimeResult.details.rootDiagnostics } else { $null }

    return [ordered]@{
        schema = 'ksword.release.gap-audit.v28'
        contractVersion = 28
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        purpose = 'Machine-readable release/productization gap audit; produced by non-mutating readiness only.'
        validationProfile = 'release-readiness-no-smoke-no-live'
        generatedBy = 'scripts/Test-ReleaseReadiness.ps1'
        nonMutating = [ordered]@{
            hyperVLive = $false
            smokeTests = $false
            vmStartRestoreStop = $false
            vmMutation = $false
            driverSigning = $false
            csignTool = $false
            guiSigningFallback = $false
            gitPush = $false
        }
        guardrailResults = [ordered]@{
            packageManifests = if ($null -eq $manifestResult) { 'not-run' } else { [string]$manifestResult.status }
            noVmMutationOrLive = if ($null -eq $noVmMutationResult) { 'not-run' } else { [string]$noVmMutationResult.status }
            noCSignToolInvocation = if ($null -eq $noCSignToolResult) { 'not-run' } else { [string]$noCSignToolResult.status }
            noGuiSigningFallback = if ($null -eq $noGuiSigningResult) { 'not-run' } else { [string]$noGuiSigningResult.status }
        }
        noFreshLiveEvidence = [ordered]@{
            generated = $false
            claimAllowedWithoutLabJob = $false
            releaseNotesMustUseFallbackWhenNoJobId = $true
            status = if ($null -eq $freshLiveResult) { 'not-run' } else { [string]$freshLiveResult.status }
            releaseNotesFallbackZh = '本候选未刷新 fresh live evidence'
            requiredForClaim = @('commit', 'job id', 'RuntimePublishRoot/runtime root', 'generated time', 'report.json', 'report.zh.html', 'report.en.html')
            rejectedSubstitutes = @('release-readiness.json', 'package-manifest.generated.json', 'source package StageOnly dry-run', 'PowerShell parse output')
            remediationZh = '没有实验室 live job id 时，发布说明必须写“本候选未刷新 fresh live evidence”；不要把 readiness/package JSON 当作 fresh live 证据。'
        }
        runtimePublishRootCompleteness = [ordered]@{
            runtimePublishRoot = if ($runtimeRootProvided) { $RuntimePublishRoot } else { $null }
            requireCompleteRuntimePackage = [bool]$RequireCompleteRuntimePackage
            handoffVerified = $runtimeHandoffVerified
            handoffGateStatus = if ($runtimeHandoffVerified) { 'verified' } elseif ($runtimeRootProvided -and [bool]$RequireCompleteRuntimePackage) { 'blocked-or-failed' } elseif ($runtimeRootProvided) { 'diagnostic-only' } else { 'not-verified-missing-runtime-publish-root' }
            status = if ($null -eq $runtimeResult) { 'not-run' } else { [string]$runtimeResult.status }
            rootDiagnostics = $rootDiagnostics
            summary = $runtimeSummary
            entries = @($runtimeEntries)
            issues = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('issues')) { @($runtimeResult.details.issues) } else { @() }
            expectedSources = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('expectedSources')) { @($runtimeResult.details.expectedSources) } else { @('host-web', 'guest-tools', 'tools/job-tool', 'tools/postprocess') }
            remediationZh = '完整 runtime handoff 前，先把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到仓库外 RuntimePublishRoot，再用 -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage 重跑 readiness；不要从仓库 bin/obj/x64 兜底。'
        }
        selfNoiseGuardReadiness = [ordered]@{
            status = if ($null -eq $selfNoiseResult) { 'not-run' } else { [string]$selfNoiseResult.status }
            smokeExecuted = $false
            staticAuditOnly = $true
            behaviorConclusionAllowed = $false
            requiredBoundaries = @('self-noise excluded from sample behavior', 'collection-health remains evidence-quality only', 'VT quiet state is not behavior', 'behaviorCounted=false rows remain non-behavioral')
            evidence = if ($null -ne $selfNoiseResult -and $null -ne $selfNoiseResult.details -and $selfNoiseResult.details.ContainsKey('evidence')) { $selfNoiseResult.details.evidence } else { $null }
            remediationZh = '若静态审计失败，先恢复 rules/behavior-rules.json 的 self-noise/collection-health/behaviorCounted guard，再补 docs/run.md 和 docs/release.md；不要在本 release-readiness 步骤中运行 smoke/live。'
        }
        componentProgress = $componentProgress
        componentProgressStatus = [ordered]@{
            present = $true
            schema = $componentProgress.schema
            componentIds = @($componentProgress.components | ForEach-Object { $_.id })
            remediationZh = '若 componentProgress 缺组件，请同步更新 package-portable.ps1、Test-ReleaseReadiness.ps1 和 packaging/*.json 的 componentProgressTemplate。'
        }
    }
}

function ConvertTo-ReleaseReadinessMarkdown {
    param(
        [Parameter(Mandatory)]
        [object]$Summary
    )

    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('# KSwordSandbox release-readiness handoff')
    [void]$lines.Add('')
    [void]$lines.Add("Generated: ``$($Summary.generatedAtUtc)``")
    [void]$lines.Add("Repository: ``$($Summary.repositoryRoot)``")
    [void]$lines.Add("Branch/commit: ``$($Summary.gitBranch)`` / ``$($Summary.gitShortCommit)``")
    [void]$lines.Add("Changed items at check time: ``$($Summary.gitStatusCount)``")
    [void]$lines.Add('')
    [void]$lines.Add('## Summary')
    [void]$lines.Add('')
    [void]$lines.Add("- Passed: ``$($Summary.passedCount)``")
    [void]$lines.Add("- Warnings: ``$($Summary.warningCount)``")
    [void]$lines.Add("- Failed: ``$($Summary.failedCount)``")
    [void]$lines.Add("- Skipped: ``$($Summary.skippedCount)``")
    [void]$lines.Add("- Exit code: ``$($Summary.exitCode)``")
    [void]$lines.Add('')
    [void]$lines.Add('## Non-mutating release boundaries')
    [void]$lines.Add('')
    [void]$lines.Add("- VM mutation: ``$($Summary.noVmMutation)``")
    [void]$lines.Add("- Driver signing: ``$($Summary.noDriverSigning)``")
    [void]$lines.Add("- GUI signing fallback: ``$($Summary.noGuiSigningFallback)``")
    [void]$lines.Add("- CSignTool not called: ``$($Summary.csignToolNotCalled)``")
    [void]$lines.Add("- Fresh live evidence generated: ``$($Summary.freshLiveEvidenceGenerated)``")
    [void]$lines.Add("- Release-note fallback without a lab job id: ``$($Summary.releaseNotesFreshLiveFallback)``")
    [void]$lines.Add('')
    [void]$lines.Add('## Runtime handoff status')
    [void]$lines.Add('')
    if ([string]::IsNullOrWhiteSpace([string]$Summary.runtimePublishRoot)) {
        [void]$lines.Add('- RuntimePublishRoot: not supplied. Complete runtime handoff is **not verified** by this run.')
    }
    else {
        [void]$lines.Add("- RuntimePublishRoot: ``$($Summary.runtimePublishRoot)``")
        [void]$lines.Add("- Require complete runtime package: ``$($Summary.requireCompleteRuntimePackage)``")
    }

    [void]$lines.Add('- Required final evidence before claiming a fresh live release: commit, job id, runtime root, generated time, report JSON path, zh/en HTML report paths.')
    [void]$lines.Add('')
    [void]$lines.Add('## Reviewer checklist / 审阅清单')
    [void]$lines.Add('')
    foreach ($item in @($Summary.reviewerChecklist.mustPassBeforeSourceHandoff)) {
        [void]$lines.Add("- Source: $item")
    }
    foreach ($item in @($Summary.reviewerChecklist.mustPassBeforeRuntimeHandoff)) {
        [void]$lines.Add("- Runtime: $item")
    }
    foreach ($item in @($Summary.reviewerChecklist.releaseNotesMustState)) {
        [void]$lines.Add("- Release notes: $item")
    }
    [void]$lines.Add('')
    [void]$lines.Add('## Warnings and failures')
    [void]$lines.Add('')
    $interestingResults = @($Summary.results | Where-Object { $_.status -in @('Failed', 'Warning') })
    if ($interestingResults.Count -eq 0) {
        [void]$lines.Add('- No warning or failed checks were reported.')
    }
    else {
        foreach ($result in @($interestingResults | Select-Object -First 12)) {
            [void]$lines.Add("- **$($result.status)** ``$($result.id)``: $($result.message)")
            $remediation = @($result.remediation)
            if ($remediation.Count -gt 0) {
                [void]$lines.Add("  - Next: $($remediation -join '；')")
            }
        }
    }

    [void]$lines.Add('')
    [void]$lines.Add('## Reviewer commands')
    [void]$lines.Add('')
    [void]$lines.Add('```powershell')
    [void]$lines.Add('.\scripts\Test-RepositoryPolicy.ps1')
    [void]$lines.Add('.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource')
    [void]$lines.Add('.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage')
    [void]$lines.Add('```')
    [void]$lines.Add('')
    [void]$lines.Add('This handoff summary is generated by the non-mutating readiness script; it is not a substitute for a lab Hyper-V live run.')

    return $lines -join [Environment]::NewLine
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
Test-SelfNoiseGuardReadiness
Invoke-RepositoryPolicy
Invoke-SourcePackageStage
Invoke-LightBuild

$failed = @($script:Results | Where-Object { $_.status -eq 'Failed' })
$warnings = @($script:Results | Where-Object { $_.status -eq 'Warning' })
$exitCode = if ($failed.Count -gt 0 -or ($TreatWarningsAsErrors -and $warnings.Count -gt 0)) { 1 } else { 0 }
$gitMetadata = Get-GitReleaseMetadata

$summary = [pscustomobject][ordered]@{
    contractVersion       = 1
    kind                  = 'KSwordSandbox.ReleaseReadiness'
    generatedAtUtc        = [DateTimeOffset]::UtcNow.ToString('O')
    repositoryRoot        = $RepositoryRoot
    outputRoot            = $OutputRoot
    gitAvailable          = [bool]$gitMetadata.available
    gitBranch             = $gitMetadata.branch
    gitCommit             = $gitMetadata.commit
    gitShortCommit        = $gitMetadata.shortCommit
    gitStatusCount        = $gitMetadata.statusCount
    gitStatusPreview      = @($gitMetadata.statusPreview)
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
    reviewerChecklist     = [ordered]@{
        chinese = '中文审阅速查：readiness 只证明低副作用门禁；runtime handoff 还必须补齐仓库外 RuntimePublishRoot；fresh live 声明必须有实验室 job id。'
        mustPassBeforeSourceHandoff = @(
            'release-readiness.json failedCount = 0',
            'source package StageOnly dry-run 已生成 package-manifest.generated.json',
            'generated metadata 的 sourceRuntimeSafetyMetadata/source package safety 未显示 runtime payload、VM state、secret、签名材料或 build output',
            'dirty source 只能作为内部 draft，并在 release notes 说明 AllowDirtySource'
        )
        mustPassBeforeRuntimeHandoff = @(
            '使用 -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage 重新运行 readiness',
            'RuntimePublishRoot 在仓库外，且 host-web、guest-tools、tools/job-tool、tools/postprocess 都存在',
            '每个 runtime publish entry 含预期 exe/dll/payload-manifest，且不含 .pdb/.sys/pcap/dump/VM/secret/signing 文件',
            'package-portable.ps1 runtime zip 使用 -RequireCompleteRuntimePayloads，且不是 -StageOnly layout dry-run'
        )
        releaseNotesMustState = @(
            '如果没有 fresh lab job id，写“本候选未刷新 fresh live evidence”',
            '若声明 fresh live，记录 commit、job id、runtime root、生成时间、report.json/report.zh.html/report.en.html 路径',
            '默认包不签名、不加载真实 R0 driver；真实 R0 仍是隔离 lab 高级路径'
        )
        rejectIfPresent = @(
            'CSignTool.exe 或 GUI signing fallback',
            '仓库内 RuntimePublishRoot/bin/obj/x64 runtime fallback',
            '样本、报告、PCAP/dump/trace、VM 磁盘/快照、secret、证书私钥或 driver binary'
        )
    }
    componentProgress     = Get-ReleaseComponentProgressSnapshot -ExitCode $exitCode
    gapAudit              = Get-ReleaseGapAuditSnapshot -ExitCode $exitCode
    sourceRuntimeSafetyMetadata = [ordered]@{
        sourcePackage = [ordered]@{
            dryRunEnabledByDefault = -not [bool]$SkipSourcePackageDryRun
            sourceOnly = $true
            excludesRuntimePayloads = $true
            excludesSecretsVmStateSamplesReportsBuildOutputAndSigningMaterial = $true
        }
        runtimePackage = [ordered]@{
            runtimePublishRoot = if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) { $null } else { $RuntimePublishRoot }
            runtimePublishRootMustBeOutsideRepository = $true
            repositoryBinaryFallbackAllowed = $false
            completeRuntimePackageRequired = [bool]$RequireCompleteRuntimePackage
            completeRuntimeHandoffVerified = (-not [string]::IsNullOrWhiteSpace($RuntimePublishRoot) -and [bool]$RequireCompleteRuntimePackage -and $exitCode -eq 0)
        }
        nonMutating = [ordered]@{
            vmMutation = $false
            driverSigning = $false
            guiSigningFallback = $false
            csignTool = $false
            gitPush = $false
            networkPublish = $false
        }
    }
    results               = @($script:Results.ToArray())
}

$summaryPath = Join-Path $OutputRoot 'release-readiness.json'
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
$markdownPath = Join-Path $OutputRoot 'release-readiness.md'
ConvertTo-ReleaseReadinessMarkdown -Summary $summary | Set-Content -LiteralPath $markdownPath -Encoding UTF8

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
Write-Host "审阅交接摘要已写入：$markdownPath"
Write-Host '安全护栏：未启动/还原/停止 VM，未签名，未调用 CSignTool/GUI signing fallback，未生成 fresh live evidence。'
exit $exitCode
