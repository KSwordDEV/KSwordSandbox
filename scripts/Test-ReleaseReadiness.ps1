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

function Get-InstallEntrypointRequiredValues {
    return @('UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')
}

function Compare-StringSet {
    param(
        [string[]]$Actual = @(),
        [string[]]$Expected = @()
    )

    $actualValues = @($Actual | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    $expectedValues = @($Expected | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ } | Select-Object -Unique)

    return [pscustomobject][ordered]@{
        matches = (@($actualValues | Sort-Object) -join "`n") -eq (@($expectedValues | Sort-Object) -join "`n")
        missing = @($expectedValues | Where-Object { $actualValues -notcontains $_ })
        extra   = @($actualValues | Where-Object { $expectedValues -notcontains $_ })
        actual  = @($actualValues)
        expected = @($expectedValues)
    }
}

function Get-PowerShellAst {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{
            Ast = $null
            ParseErrors = @([pscustomobject]@{ Message = 'missing'; Extent = '' })
            Path = $path
            RelativePath = $RelativePath
        }
    }

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    return [pscustomobject]@{
        Ast = $ast
        ParseErrors = @($parseErrors)
        Path = $path
        RelativePath = $RelativePath
    }
}

function Get-ValidateSetValuesFromParameterAst {
    param([Parameter(Mandatory)][System.Management.Automation.Language.ParameterAst]$ParameterAst)

    foreach ($attribute in @($ParameterAst.Attributes)) {
        if ($attribute -isnot [System.Management.Automation.Language.AttributeAst]) {
            continue
        }

        $typeName = [string]$attribute.TypeName.FullName
        if ($typeName -notmatch '(?i)(^|\.|Automation\.)ValidateSet(Attribute)?$') {
            continue
        }

        return @($attribute.PositionalArguments | ForEach-Object {
                try {
                    [string]$_.SafeGetValue()
                }
                catch {
                    [string]$_.Extent.Text.Trim("'`"")
                }
            })
    }

    return @()
}

function Get-ParameterAstsByName {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory)][string[]]$Names
    )

    return @($Ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.ParameterAst] -and
                $Names -contains [string]$node.Name.VariablePath.UserPath
            }, $true))
}

function Get-FunctionDefinitionAst {
    param(
        [Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory)][string]$Name
    )

    return @($Ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                [string]$node.Name -eq $Name
            }, $true) | Select-Object -First 1)
}

function Get-CommandAsts {
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)

    return @($Ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true))
}

function Get-CommandAstLeafName {
    param([Parameter(Mandatory)][System.Management.Automation.Language.CommandAst]$CommandAst)

    $commandName = [string]$CommandAst.GetCommandName()
    if ([string]::IsNullOrWhiteSpace($commandName)) {
        return ''
    }

    return Split-Path -Leaf $commandName
}

function Get-ContainingFunctionName {
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Node)

    $parent = $Node.Parent
    while ($null -ne $parent) {
        if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            return [string]$parent.Name
        }

        $parent = $parent.Parent
    }

    return '<script>'
}

function Test-ScriptCmdletBindingSupportsShouldProcess {
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)

    if ($null -eq $Ast.ParamBlock) {
        return $false
    }

    foreach ($attribute in @($Ast.ParamBlock.Attributes)) {
        if ($attribute -isnot [System.Management.Automation.Language.AttributeAst]) {
            continue
        }

        $typeName = [string]$attribute.TypeName.FullName
        if ($typeName -notmatch '(?i)(^|\.|Automation\.)CmdletBinding(Attribute)?$') {
            continue
        }

        foreach ($namedArgument in @($attribute.NamedArguments)) {
            if ([string]$namedArgument.ArgumentName -ne 'SupportsShouldProcess') {
                continue
            }

            try {
                return [bool]$namedArgument.Argument.SafeGetValue()
            }
            catch {
                return ($namedArgument.Argument.Extent.Text -match '(?i)\$true|true')
            }
        }
    }

    return $false
}

function Normalize-ContractCommand {
    param([AllowNull()][string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) {
        return ''
    }

    return ([string]$Command).Trim().Replace('/', '\')
}

function Get-OperatorModeMatrixContractIssues {
    param(
        [AllowNull()][object]$OperatorModeMatrix,
        [Parameter(Mandatory)][string]$Context
    )

    $issues = New-Object System.Collections.Generic.List[string]
    if ($null -eq $OperatorModeMatrix) {
        [void]$issues.Add("operatorModeMatrix is missing: $Context")
        return @($issues.ToArray())
    }

    $operatorModes = @(Get-ObjectPropertyValue -InputObject $OperatorModeMatrix -Name 'modes' -DefaultValue @())
    $operatorModeIds = @($operatorModes |
        ForEach-Object { [string](Get-ObjectPropertyValue -InputObject $_ -Name 'modeId' -DefaultValue '') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    $expectedOperatorModeIds = @(Get-CanonicalOperatorModeRequiredIds)
    $modeIdComparison = Compare-StringSet -Actual $operatorModeIds -Expected $expectedOperatorModeIds
    foreach ($missingModeId in @($modeIdComparison.missing)) {
        [void]$issues.Add("operatorModeMatrix missing canonical mode '$missingModeId': $Context")
    }
    foreach ($extraModeId in @($modeIdComparison.extra)) {
        [void]$issues.Add("operatorModeMatrix has unexpected mode '$extraModeId': $Context")
    }

    foreach ($canonical in @(Get-CanonicalOperatorModeMatrix)) {
        $modeId = [string]$canonical.modeId
        $matchingModes = @($operatorModes | Where-Object { [string](Get-ObjectPropertyValue -InputObject $_ -Name 'modeId' -DefaultValue '') -eq $modeId })
        if ($matchingModes.Count -eq 0) {
            continue
        }

        if ($matchingModes.Count -gt 1) {
            [void]$issues.Add("operatorModeMatrix contains duplicate mode '$modeId': $Context")
        }

        $mode = $matchingModes[0]
        $entrypoint = [string](Get-ObjectPropertyValue -InputObject $mode -Name 'entrypoint' -DefaultValue '')
        if ($entrypoint -cne [string]$canonical.entrypoint) {
            [void]$issues.Add("operatorModeMatrix mode '$modeId' entrypoint '$entrypoint' must match '$($canonical.entrypoint)': $Context")
        }

        $defaultCommand = Normalize-ContractCommand -Command ([string](Get-ObjectPropertyValue -InputObject $mode -Name 'defaultCommand' -DefaultValue ''))
        $expectedDefaultCommand = Normalize-ContractCommand -Command ([string]$canonical.defaultCommand)
        if ($defaultCommand -ine $expectedDefaultCommand) {
            [void]$issues.Add("operatorModeMatrix mode '$modeId' defaultCommand '$defaultCommand' must match '$expectedDefaultCommand': $Context")
        }

        $mutatingCommand = Normalize-ContractCommand -Command ([string](Get-ObjectPropertyValue -InputObject $mode -Name 'mutatingCommand' -DefaultValue ''))
        $expectedMutatingCommand = Normalize-ContractCommand -Command ([string](Get-ObjectPropertyValue -InputObject ([pscustomobject]$canonical) -Name 'mutatingCommand' -DefaultValue ''))
        if ([string]::IsNullOrWhiteSpace($expectedMutatingCommand)) {
            if (-not [string]::IsNullOrWhiteSpace($mutatingCommand)) {
                [void]$issues.Add("operatorModeMatrix mode '$modeId' must not advertise a mutatingCommand: $Context")
            }
        }
        elseif ($mutatingCommand -ine $expectedMutatingCommand) {
            [void]$issues.Add("operatorModeMatrix mode '$modeId' mutatingCommand '$mutatingCommand' must match '$expectedMutatingCommand': $Context")
        }

        if ($modeId -eq 'rollback-restore-snapshot') {
            if ($mutatingCommand -notmatch '(?i)-AllowVmMutation' -or $mutatingCommand -notmatch '(?i)-(Confirm|Force)') {
                [void]$issues.Add("operatorModeMatrix restore mode mutatingCommand must include -AllowVmMutation plus -Confirm or -Force: $Context")
            }

            $packageReadinessMutation = [string](Get-ObjectPropertyValue -InputObject $mode -Name 'packageReadinessMutation' -DefaultValue '')
            if ($packageReadinessMutation -notmatch '(?i)forbidden') {
                [void]$issues.Add("operatorModeMatrix restore mode must mark package/readiness mutation as forbidden: $Context")
            }
        }
    }

    return @($issues.ToArray())
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

function Test-InstallerEntrypointStaticContract {
    $issues = New-Object System.Collections.Generic.List[object]
    $requiredEntrypoints = @(Get-InstallEntrypointRequiredValues)
    $rootParse = Get-PowerShellAst -RelativePath 'install.ps1'
    $wrapperParse = Get-PowerShellAst -RelativePath 'scripts\install.ps1'

    foreach ($parseResult in @($rootParse, $wrapperParse)) {
        foreach ($parseError in @($parseResult.ParseErrors)) {
            [void]$issues.Add([pscustomobject]@{
                    path = $parseResult.RelativePath
                    check = 'parse'
                    message = $parseError.Message
                    line = if ($null -ne $parseError.Extent) { $parseError.Extent.StartLineNumber } else { 0 }
                })
        }
    }

    if ($null -ne $rootParse.Ast -and $null -ne $wrapperParse.Ast) {
        foreach ($entry in @(
                [pscustomobject]@{ Relative = 'install.ps1'; Ast = $rootParse.Ast },
                [pscustomobject]@{ Relative = 'scripts\install.ps1'; Ast = $wrapperParse.Ast }
            )) {
            if (-not (Test-ScriptCmdletBindingSupportsShouldProcess -Ast $entry.Ast)) {
                [void]$issues.Add([pscustomobject]@{
                        path = $entry.Relative
                        check = 'supports-should-process'
                        message = 'script-level CmdletBinding must keep SupportsShouldProcess = true'
                        line = 1
                    })
            }

            $scriptEntrypointParameter = @($entry.Ast.ParamBlock.Parameters | Where-Object { [string]$_.Name.VariablePath.UserPath -eq 'InstallEntrypoint' } | Select-Object -First 1)
            if ($scriptEntrypointParameter.Count -eq 0) {
                [void]$issues.Add([pscustomobject]@{
                        path = $entry.Relative
                        check = 'script-install-entrypoint-param'
                        message = 'script param block must expose -InstallEntrypoint'
                        line = 1
                    })
            }

            foreach ($parameterAst in @(Get-ParameterAstsByName -Ast $entry.Ast -Names @('InstallEntrypoint', 'SelectedEntrypoint'))) {
                $validateSetValues = @(Get-ValidateSetValuesFromParameterAst -ParameterAst $parameterAst)
                $comparison = Compare-StringSet -Actual $validateSetValues -Expected $requiredEntrypoints
                if (-not [bool]$comparison.matches) {
                    [void]$issues.Add([pscustomobject]@{
                            path = $entry.Relative
                            check = 'entrypoint-validateset'
                            parameter = [string]$parameterAst.Name.VariablePath.UserPath
                            line = $parameterAst.Extent.StartLineNumber
                            message = "ValidateSet must exactly be: $($requiredEntrypoints -join ', ')"
                            missing = @($comparison.missing)
                            extra = @($comparison.extra)
                            actual = @($comparison.actual)
                        })
                }
            }
        }

        $requiredRootFunctions = @(
            'Invoke-UseConfiguredEnvironmentEntrypoint',
            'Invoke-RestoreCleanCheckpointEntrypoint',
            'Invoke-CreateOrPreparePathEntrypoint',
            'Assert-InstallEntrypointContract',
            'Invoke-InstallEntrypoint',
            'Get-InstallOperatorModeMatrix'
        )

        foreach ($functionName in $requiredRootFunctions) {
            if ($null -eq (Get-FunctionDefinitionAst -Ast $rootParse.Ast -Name $functionName)) {
                [void]$issues.Add([pscustomobject]@{
                        path = 'install.ps1'
                        check = 'required-root-function'
                        message = "Missing required installer function: $functionName"
                        line = 0
                    })
            }
        }

        $invokeEntrypointFunction = Get-FunctionDefinitionAst -Ast $rootParse.Ast -Name 'Invoke-InstallEntrypoint'
        if ($null -ne $invokeEntrypointFunction) {
            $invokeText = $invokeEntrypointFunction.Extent.Text
            $entrypointFunctionMap = [ordered]@{
                UseConfiguredEnvironment = 'Invoke-UseConfiguredEnvironmentEntrypoint'
                RestoreCleanCheckpoint = 'Invoke-RestoreCleanCheckpointEntrypoint'
                CreateOrPreparePath = 'Invoke-CreateOrPreparePathEntrypoint'
            }

            foreach ($entrypointName in $entrypointFunctionMap.Keys) {
                $targetFunction = $entrypointFunctionMap[$entrypointName]
                if ($invokeText -notmatch [regex]::Escape("'$entrypointName'") -or $invokeText -notmatch [regex]::Escape($targetFunction)) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'install.ps1'
                            check = 'entrypoint-switch-dispatch'
                            message = "Invoke-InstallEntrypoint must dispatch '$entrypointName' to $targetFunction"
                            line = $invokeEntrypointFunction.Extent.StartLineNumber
                        })
                }
            }
        }

        $assertEntrypointFunction = Get-FunctionDefinitionAst -Ast $rootParse.Ast -Name 'Assert-InstallEntrypointContract'
        if ($null -ne $assertEntrypointFunction) {
            $assertText = $assertEntrypointFunction.Extent.Text
            foreach ($marker in @('modeActionSwitches', 'UseConfiguredEnvironment', 'RestoreCleanCheckpoint', 'CreateOrPreparePath')) {
                if ($assertText.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'install.ps1'
                            check = 'entrypoint-switch-closure'
                            message = "Assert-InstallEntrypointContract is missing marker '$marker'"
                            line = $assertEntrypointFunction.Extent.StartLineNumber
                        })
                }
            }

            if ($assertText -notmatch "'UseConfiguredEnvironment'\s*\{[^\}]*AllowVmMutation") {
                [void]$issues.Add([pscustomobject]@{
                        path = 'install.ps1'
                        check = 'entrypoint-switch-closure'
                        message = 'UseConfiguredEnvironment must reject -AllowVmMutation to keep read-only semantics closed.'
                        line = $assertEntrypointFunction.Extent.StartLineNumber
                    })
            }
            if ($assertText -match "'RestoreCleanCheckpoint'\s*\{[^\}]*AllowVmMutation") {
                [void]$issues.Add([pscustomobject]@{
                        path = 'install.ps1'
                        check = 'entrypoint-switch-closure'
                        message = 'RestoreCleanCheckpoint must allow -AllowVmMutation so the later explicit restore gate can inspect it.'
                        line = $assertEntrypointFunction.Extent.StartLineNumber
                    })
            }
            if ($assertText -notmatch "'CreateOrPreparePath'\s*\{[^\}]*AllowVmMutation") {
                [void]$issues.Add([pscustomobject]@{
                        path = 'install.ps1'
                        check = 'entrypoint-switch-closure'
                        message = 'CreateOrPreparePath must reject -AllowVmMutation because it is local prepare only.'
                        line = $assertEntrypointFunction.Extent.StartLineNumber
                    })
            }
        }

        $restoreFunction = Get-FunctionDefinitionAst -Ast $rootParse.Ast -Name 'Invoke-RestoreCleanCheckpointEntrypoint'
        if ($null -ne $restoreFunction) {
            $restoreFunctionText = $restoreFunction.Extent.Text
            foreach ($marker in @('$AllowVmMutation', 'ShouldProcess', 'Confirm', '$Force', 'Test-IsAdministrator')) {
                if ($restoreFunctionText.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'install.ps1'
                            check = 'restore-gate'
                            message = "RestoreCleanCheckpoint implementation is missing required gate marker '$marker'"
                            line = $restoreFunction.Extent.StartLineNumber
                        })
                }
            }

            $restoreCommands = @(Get-CommandAsts -Ast $restoreFunction | Where-Object { (Get-CommandAstLeafName -CommandAst $_) -ieq 'Restore-VMSnapshot' })
            if ($restoreCommands.Count -ne 1) {
                [void]$issues.Add([pscustomobject]@{
                        path = 'install.ps1'
                        check = 'restore-command-count'
                        message = "RestoreCleanCheckpoint must contain exactly one Restore-VMSnapshot command; found $($restoreCommands.Count)."
                        line = $restoreFunction.Extent.StartLineNumber
                    })
            }
            else {
                $restoreLine = $restoreCommands[0].Extent.StartLineNumber
                $allowVmMutationLines = @($restoreFunction.FindAll({
                            param($node)
                            $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
                            [string]$node.VariablePath.UserPath -eq 'AllowVmMutation'
                        }, $true) | ForEach-Object { $_.Extent.StartLineNumber })
                $shouldProcessLines = @($restoreFunction.FindAll({
                            param($node)
                            $node -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and
                            $node.Extent.Text -match 'ShouldProcess'
                        }, $true) | ForEach-Object { $_.Extent.StartLineNumber })

                if ($allowVmMutationLines.Count -eq 0 -or [int]($allowVmMutationLines | Measure-Object -Minimum).Minimum -ge $restoreLine) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'install.ps1'
                            check = 'restore-gate-order'
                            message = 'Restore-VMSnapshot must be preceded by an AllowVmMutation gate.'
                            line = $restoreLine
                        })
                }
                if ($shouldProcessLines.Count -eq 0 -or [int]($shouldProcessLines | Measure-Object -Minimum).Minimum -ge $restoreLine) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'install.ps1'
                            check = 'restore-gate-order'
                            message = 'Restore-VMSnapshot must be preceded by a ShouldProcess gate.'
                            line = $restoreLine
                        })
                }
            }
        }

        foreach ($commandAst in @(Get-CommandAsts -Ast $rootParse.Ast | Where-Object { (Get-CommandAstLeafName -CommandAst $_) -ieq 'Restore-VMSnapshot' })) {
            $functionName = Get-ContainingFunctionName -Node $commandAst
            if ($functionName -ne 'Invoke-RestoreCleanCheckpointEntrypoint') {
                [void]$issues.Add([pscustomobject]@{
                        path = 'install.ps1'
                        check = 'restore-command-location'
                        message = "Restore-VMSnapshot must stay inside Invoke-RestoreCleanCheckpointEntrypoint, found in $functionName."
                        line = $commandAst.Extent.StartLineNumber
                    })
            }
        }

        foreach ($commandAst in @(Get-CommandAsts -Ast $wrapperParse.Ast | Where-Object { (Get-CommandAstLeafName -CommandAst $_) -ieq 'Restore-VMSnapshot' })) {
            [void]$issues.Add([pscustomobject]@{
                    path = 'scripts\install.ps1'
                    check = 'wrapper-no-direct-restore'
                    message = 'scripts/install.ps1 must forward restore requests to root install.ps1 and must not call Restore-VMSnapshot directly.'
                    line = $commandAst.Extent.StartLineNumber
                })
        }

        $operatorMatrixFunction = Get-FunctionDefinitionAst -Ast $rootParse.Ast -Name 'Get-InstallOperatorModeMatrix'
        if ($null -ne $operatorMatrixFunction) {
            $operatorMatrixText = $operatorMatrixFunction.Extent.Text
            foreach ($canonical in @(Get-CanonicalOperatorModeMatrix)) {
                foreach ($marker in @([string]$canonical.modeId, [string]$canonical.entrypoint, [string]$canonical.defaultCommand)) {
                    if ($operatorMatrixText.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                        [void]$issues.Add([pscustomobject]@{
                                path = 'install.ps1'
                                check = 'implementation-operator-mode-matrix'
                                message = "Get-InstallOperatorModeMatrix is missing canonical marker '$marker'."
                                line = $operatorMatrixFunction.Extent.StartLineNumber
                            })
                    }
                }
            }

            foreach ($marker in @('MutatingCommand = $restoreCommand', 'RestoresCheckpoint = $true', 'CreatesLocalConfig = $true', 'CreatesVm = $false')) {
                if ($operatorMatrixText.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'install.ps1'
                            check = 'implementation-operator-mode-matrix'
                            message = "Get-InstallOperatorModeMatrix is missing semantic marker '$marker'."
                            line = $operatorMatrixFunction.Extent.StartLineNumber
                        })
                }
            }
        }

        $wrapperForwardFunction = Get-FunctionDefinitionAst -Ast $wrapperParse.Ast -Name 'New-RootInstallerParameterTable'
        if ($null -eq $wrapperForwardFunction) {
            [void]$issues.Add([pscustomobject]@{
                    path = 'scripts\install.ps1'
                    check = 'wrapper-forwarding'
                    message = 'Missing New-RootInstallerParameterTable forwarding helper.'
                    line = 0
                })
        }
        else {
            $forwardText = $wrapperForwardFunction.Extent.Text
            foreach ($marker in @('$script:InitialWrapperBoundParameters.Keys', '$parameters[$key]', 'DriverWrapperParameterNames', 'PreparePayload')) {
                if ($forwardText.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'scripts\install.ps1'
                            check = 'wrapper-forwarding'
                            message = "New-RootInstallerParameterTable is missing forwarding marker '$marker'."
                            line = $wrapperForwardFunction.Extent.StartLineNumber
                        })
                }
            }

            foreach ($forbiddenDrop in @('InstallEntrypoint', 'AllowVmMutation', 'PlanOnly', 'Force', 'PrepareGuestPayload')) {
                $explicitDropPattern = '(?i)\$key\s+-eq\s+[''"]' + [regex]::Escape($forbiddenDrop) + '[''"]'
                $continueDropPattern = '(?i)' + [regex]::Escape($forbiddenDrop) + '.*continue'
                if ($forwardText -match $explicitDropPattern -or $forwardText -match $continueDropPattern) {
                    [void]$issues.Add([pscustomobject]@{
                            path = 'scripts\install.ps1'
                            check = 'wrapper-forwarding'
                            message = "Wrapper forwarding must not drop -$forbiddenDrop."
                            line = $wrapperForwardFunction.Extent.StartLineNumber
                        })
                }
            }
        }

        $wrapperRaw = Get-Content -LiteralPath $wrapperParse.Path -Raw
        foreach ($marker in @(
                "PSBoundParameters.ContainsKey('InstallEntrypoint')",
                "Invoke-RootInstaller -Parameters (New-RootInstallerParameterTable -RootMode 'Interactive')",
                "InstallEntrypoint = 'CreateOrPreparePath'",
                'PrepareGuestPayload = $true'
            )) {
            if ($wrapperRaw.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$issues.Add([pscustomobject]@{
                        path = 'scripts\install.ps1'
                        check = 'wrapper-forwarding'
                        message = "scripts/install.ps1 is missing wrapper forwarding marker '$marker'."
                        line = 0
                    })
            }
        }
    }

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'installer-entrypoint-static-contract' `
            -Title 'Installer entrypoint static contract / 安装三入口静态契约' `
            -Status Passed `
            -Message 'InstallEntrypoint ValidateSet, wrapper forwarding, root dispatch, RestoreCleanCheckpoint gates, and implementation operator-mode markers are statically consistent.'
        return
    }

    Add-ReleaseCheckResult `
        -Id 'installer-entrypoint-static-contract' `
        -Title 'Installer entrypoint static contract / 安装三入口静态契约' `
        -Status Failed `
        -Message "Installer entrypoint static contract found $($issues.Count) issue(s)." `
        -Remediation @('Keep UseConfiguredEnvironment, RestoreCleanCheckpoint, and CreateOrPreparePath closed across root/wrapper ValidateSet values, wrapper forwarding, root dispatch, RestoreCleanCheckpoint AllowVmMutation+ShouldProcess gates, and manifest operatorModeMatrix metadata.') `
        -Details @{ issues = @($issues.ToArray()); requiredEntrypoints = @($requiredEntrypoints) }
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

                $installModeContract = Get-ObjectPropertyValue -InputObject $releaseContract -Name 'installModeContract' -DefaultValue $null
                if ($null -eq $installModeContract) {
                    [void]$issues.Add("releaseContract.installModeContract is missing: $relative")
                }
                else {
                    $operatorModeMatrix = Get-ObjectPropertyValue -InputObject $installModeContract -Name 'operatorModeMatrix' -DefaultValue $null
                    foreach ($matrixIssue in @(Get-OperatorModeMatrixContractIssues -OperatorModeMatrix $operatorModeMatrix -Context $relative)) {
                        [void]$issues.Add($matrixIssue)
                    }

                    $operatorModes = if ($null -eq $operatorModeMatrix) { @() } else { @(Get-ObjectPropertyValue -InputObject $operatorModeMatrix -Name 'modes' -DefaultValue @()) }
                    foreach ($requiredEntrypoint in @(Get-InstallEntrypointRequiredValues)) {
                        $entrypointFound = $false
                        foreach ($operatorMode in $operatorModes) {
                            if ([string](Get-ObjectPropertyValue -InputObject $operatorMode -Name 'entrypoint' -DefaultValue '') -eq $requiredEntrypoint) {
                                $entrypointFound = $true
                                break
                            }
                        }
                        if (-not $entrypointFound) {
                            [void]$issues.Add("operatorModeMatrix missing entrypoint '$requiredEntrypoint': $relative")
                        }
                    }
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
        $nextActionsZh = Get-RuntimeHandoffNextActionsZh -RuntimeSummary $runtimePublishSummary -RootDiagnostics $rootDiagnostics

        if ($RequireCompleteRuntimePackage) {
            Add-ReleaseCheckResult `
                -Id 'runtime-publish-completeness' `
                -Title 'Runtime publish completeness / runtime payload 完整性' `
                -Status Failed `
                -Message '完整 runtime 便携包要求 -RuntimePublishRoot；当前未提供。' `
                -Remediation @($nextActionsZh) `
                -Details @{ expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; operatorHints = $operatorHints; nextActionsZh = @($nextActionsZh); dryRunOnly = $true; handoffAllowed = $false }
            return
        }

        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Skipped `
            -Message 'Skipped complete runtime payload gate. This is acceptable for source/layout readiness only; use -RuntimePublishRoot with -RequireCompleteRuntimePackage before runtime handoff.' `
            -Details @{ expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; operatorHints = $operatorHints; nextActionsZh = @($nextActionsZh); dryRunOnly = $true; handoffAllowed = $false }
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
    $nextActionsZh = Get-RuntimeHandoffNextActionsZh -RuntimeSummary $runtimePublishSummary -RootDiagnostics $rootDiagnostics -Entries @($entryDiagnostics.ToArray())

    if ($issues.Count -eq 0) {
        Add-ReleaseCheckResult `
            -Id 'runtime-publish-completeness' `
            -Title 'Runtime publish completeness / runtime payload 完整性' `
            -Status Passed `
            -Message 'RuntimePublishRoot is outside the repository and contains non-empty expected runtime payload directories.' `
            -Details @{ runtimePublishRoot = $RuntimePublishRoot; expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; entries = @($entryDiagnostics.ToArray()); operatorHints = $operatorHints; nextActionsZh = @($nextActionsZh); handoffAllowed = [bool]$runtimePublishSummary.handoffAllowed }
        return
    }

    $status = if ($RequireCompleteRuntimePackage) { 'Failed' } else { 'Warning' }
    Add-ReleaseCheckResult `
        -Id 'runtime-publish-completeness' `
        -Title 'Runtime publish completeness / runtime payload 完整性' `
        -Status $status `
        -Message "Runtime publish completeness found $($issues.Count) issue(s)." `
        -Remediation @($nextActionsZh) `
        -Details @{ issues = @($issues.ToArray()); runtimePublishRoot = $RuntimePublishRoot; expectedSources = $expectedSources; runtimePublishSummary = $runtimePublishSummary; rootDiagnostics = $rootDiagnostics; entries = @($entryDiagnostics.ToArray()); operatorHints = $operatorHints; nextActionsZh = @($nextActionsZh); requireCompleteRuntimePackage = [bool]$RequireCompleteRuntimePackage; handoffAllowed = $false }
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
                $evidence.rulesVersion.IndexOf('guard', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                $evidence.rulesVersion.IndexOf('v27', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                $evidence.rulesVersion.IndexOf('v28', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                $evidence.rulesVersion.IndexOf('v29', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$issues.Add("rules/behavior-rules.json version does not advertise self-noise guard hardening or v27/v28/v29 expansion: $($evidence.rulesVersion)")
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
        -Remediation @('中文修复：确认 rules/behavior-rules.json 仍是 v26/v27/v28/v29 self-noise hardening 规则，并在 docs/release.md/docs/run.md 写明采集器自噪声、collection-health、VT quiet state、R0/ETW health/capability 行和 behaviorCounted=false 不可计入样本行为；本检查只做静态审计，不运行 smoke/live。') `
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
        dirty = $null
        isDirty = $null
        dirtyStatus = 'unknown'
        statusCount = $null
        statusPreview = @()
        statusPorcelainPreview = @()
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
        $dirty = ($statusLines.Count -gt 0)
        $metadata.dirty = $dirty
        $metadata.isDirty = $dirty
        $metadata.dirtyStatus = if ($dirty) { 'dirty' } else { 'clean' }
        $metadata.statusCount = $statusLines.Count
        $metadata.statusPreview = @($statusLines | Select-Object -First 20)
        $metadata.statusPorcelainPreview = @($statusLines | Select-Object -First 20)
    }
    catch {
        $metadata.available = $false
        $metadata.dirtyStatus = 'unknown-git-status-failed'
        $metadata.statusPreview = @("Unable to collect git metadata: $($_.Exception.Message)")
        $metadata.statusPorcelainPreview = @("Unable to collect git metadata: $($_.Exception.Message)")
    }

    return [pscustomobject]$metadata
}

function Get-ReleaseExecutionBoundaries {
    return [ordered]@{
        schema = 'ksword.release.execution-boundaries.v1'
        generatedBy = 'scripts/Test-ReleaseReadiness.ps1'
        validationProfile = 'release-readiness-no-smoke-no-live'
        smokeTestsExecuted = $false
        hyperVLiveExecuted = $false
        vmStartRestoreStopExecuted = $false
        vmMutationExecuted = $false
        driverSigningExecuted = $false
        guiSigningFallbackInvoked = $false
        csignToolInvoked = $false
        gitPushExecuted = $false
        networkPublishExecuted = $false
        payloadBuildExecuted = [bool]$IncludeBuild
        sourcePackageStageOnlyDryRun = -not [bool]$SkipSourcePackageDryRun
        installerModesExecuted = @()
        installCheckEnvironmentExecuted = $false
        installStatusExecuted = $false
        installChangeExecuted = $false
        resetGuestVmPasswordExecuted = $false
        allowedActions = @('git metadata read', 'repository policy', 'PowerShell parse', 'package manifest parse', 'source package StageOnly dry-run', 'optional compile build when -IncludeBuild is explicitly supplied')
        forbiddenActions = @('installer mode execution', 'install CheckEnvironment execution', 'smoke test execution', 'Hyper-V live execution', 'VM start/restore/stop/mutation', 'driver signing', 'GUI signing fallback', 'CSignTool.exe invocation', 'git push', 'network publish', 'fresh live evidence generation')
        chinese = '中文：Test-ReleaseReadiness.ps1 不运行安装模式、不跑 smoke、不跑 Hyper-V live、不签名、不调用 CSignTool.exe、不 push/publish、不生成 fresh live evidence。'
    }
}

function Get-ReleaseRequiredEvidenceFields {
    return [ordered]@{
        schema = 'ksword.release.required-evidence-fields.v1'
        provenance = @('gitMetadata.branch', 'gitMetadata.commit', 'gitMetadata.shortCommit', 'gitMetadata.dirtyStatus', 'gitMetadata.statusCount', 'generatedAtUtc', 'repositoryRoot')
        sourceHandoff = @('release-readiness.json.failedCount=0', 'gitMetadata.branch', 'gitMetadata.commit', 'gitMetadata.dirtyStatus', 'sourceRuntimeSafetyMetadata', 'executionBoundaries', 'results[].id/status')
        runtimeHandoff = @('RuntimePublishRoot', 'RequireCompleteRuntimePackage=true', 'gapAudit.runtimePublishRootCompleteness.handoffVerified=true', 'summary.missingCount=0', 'summary.incompleteCount=0', 'summary.forbiddenFileCount=0', 'entries[].sourcePath')
        installModeHandoff = @('installModeContract.schema', 'installModeContract.operatorModeMatrix.modes[].entrypoint', 'installModeContract.modes[].id', 'installModeContract.readinessPackageNonMutation', 'installContractGaps', 'installContractGapNextActionsZh', 'results[install-mode-contract].status', 'results[installer-entrypoint-static-contract].status')
        freshLiveClaim = @('gitMetadata.commit', 'gitMetadata.branch', 'gitMetadata.dirtyStatus', 'job id', 'runtime root', 'generatedAtUtc/local time', 'report.json path', 'report.zh.html path', 'report.en.html path')
        fallbackWhenMissingFreshLiveJobZh = '没有实验室 live job id 时，release notes 必须写“本候选未刷新 fresh live evidence”。'
    }
}

function Get-InstallModeRequiredIds {
    return @(
        'existing-environment',
        'restore-checkpoint-snapshot',
        'fresh-create-flow',
        'first-computer-prerequisites',
        'compatibility-boundaries',
        'readiness-package-non-mutation'
    )
}

function Get-CanonicalOperatorModeRequiredIds {
    return @(
        'use-configured-environment',
        'rollback-restore-snapshot',
        'fresh-create-new-computer'
    )
}

function Get-CanonicalOperatorModeMatrix {
    return @(
        [ordered]@{
            modeId = 'use-configured-environment'
            entrypoint = 'UseConfiguredEnvironment'
            titleZh = '使用已配置环境'
            defaultCommand = '.\install.ps1 -InstallEntrypoint UseConfiguredEnvironment -PlanOnly'
            packageReadinessMutation = 'none'
            nextActionsZh = @('下一步：先跑 Status/CheckEnvironment；若 RecommendedActions 为空，再启动 WebUI 或 PlanOnly。')
        },
        [ordered]@{
            modeId = 'rollback-restore-snapshot'
            entrypoint = 'RestoreCleanCheckpoint'
            titleZh = '回退/恢复已有干净快照'
            defaultCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly'
            mutatingCommand = '.\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm'
            packageReadinessMutation = 'forbidden; package/readiness only records metadata and diagnostics'
            nextActionsZh = @('下一步：readiness/package 不恢复快照；只有隔离 lab 操作者显式 -AllowVmMutation -Confirm/-Force 才能恢复已有 checkpoint。')
        },
        [ordered]@{
            modeId = 'fresh-create-new-computer'
            entrypoint = 'CreateOrPreparePath'
            titleZh = '全新创建/新电脑准备'
            defaultCommand = '.\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword'
            packageReadinessMutation = 'none; installer may write local config/secret only when operator runs it directly'
            nextActionsZh = @('下一步：首机先确认 Hyper-V/BIOS/SLAT/管理员 shell，手工创建/导入 VM 和 clean checkpoint，再写本机 config/secret/payload。')
        }
    )
}

function Get-InstallContractGapNextActionsZh {
    param([string[]]$Gaps = @())

    if (@($Gaps).Count -eq 0) {
        return @()
    }

    $actions = New-Object System.Collections.Generic.List[string]
    [void]$actions.Add("检测到 install contract 缺口：$(@($Gaps) -join '；')。")
    [void]$actions.Add('下一步：只在允许的 install/run/readiness 脚本、packaging/*.manifest.json 和文档中补齐机器可读 contract；不要运行 install、smoke、Hyper-V live、签名或 VM mutation 来“证明” contract。')
    [void]$actions.Add("下一步：在 packaging/*.manifest.json 的 releaseContract.installModeContract.modeIds 中补齐：$((Get-InstallModeRequiredIds) -join ', ')。")
    [void]$actions.Add("下一步：在 releaseContract.installModeContract.operatorModeMatrix.modes 中补齐三种 canonical operator mode：$((Get-CanonicalOperatorModeRequiredIds) -join ', ')。")
    [void]$actions.Add('下一步：重新运行允许的 parse/JSON/readiness 检查，确认 installModeContract、installContractGaps、installContractGapNextActionsZh 和 executionBoundaries 同时存在。')
    return @($actions.ToArray())
}

function Get-InstallModeContractSnapshot {
    param([string]$GeneratedBy = 'scripts/Test-ReleaseReadiness.ps1')

    $requiredModeIds = @(Get-InstallModeRequiredIds)
    $gaps = New-Object System.Collections.Generic.List[string]
    $manifestContractsPresent = New-Object System.Collections.Generic.List[string]
    $manifestModeIds = New-Object System.Collections.Generic.List[string]
    $manifestOperatorModeMatrices = New-Object System.Collections.Generic.List[object]

    foreach ($relative in @('packaging/source-package.manifest.json', 'packaging/runtime-package.manifest.json')) {
        $path = Join-Path $RepositoryRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$gaps.Add("Missing package manifest: $relative")
            continue
        }

        try {
            $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop
            $releaseContract = Get-ObjectPropertyValue -InputObject $manifest -Name 'releaseContract' -DefaultValue $null
            if ($null -eq $releaseContract) {
                [void]$gaps.Add("releaseContract missing in $relative")
                continue
            }

            $installModeContract = Get-ObjectPropertyValue -InputObject $releaseContract -Name 'installModeContract' -DefaultValue $null
            if ($null -eq $installModeContract) {
                [void]$gaps.Add("releaseContract.installModeContract missing in $relative")
            }
            else {
                [void]$manifestContractsPresent.Add($relative)
                foreach ($modeId in @((Get-ObjectPropertyValue -InputObject $installModeContract -Name 'modeIds' -DefaultValue @()) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
                    [void]$manifestModeIds.Add([string]$modeId)
                }

                $operatorModeMatrix = Get-ObjectPropertyValue -InputObject $installModeContract -Name 'operatorModeMatrix' -DefaultValue $null
                foreach ($matrixIssue in @(Get-OperatorModeMatrixContractIssues -OperatorModeMatrix $operatorModeMatrix -Context $relative)) {
                    [void]$gaps.Add($matrixIssue)
                }

                if ($null -ne $operatorModeMatrix) {
                    [void]$manifestOperatorModeMatrices.Add([pscustomobject][ordered]@{
                            manifest = $relative
                            modeIds = @((Get-ObjectPropertyValue -InputObject $operatorModeMatrix -Name 'modes' -DefaultValue @()) |
                                ForEach-Object { [string](Get-ObjectPropertyValue -InputObject $_ -Name 'modeId' -DefaultValue '') } |
                                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                        })
                }
            }

            foreach ($flagName in @('noVmMutationByPackageScript', 'noSmokeByPackageOrReadiness', 'noHyperVLiveByPackageOrReadiness', 'noDriverSigningByPackageScript', 'noCSignToolInvocationByPackageOrReadiness')) {
                if (-not [bool](Get-ObjectPropertyValue -InputObject $releaseContract -Name $flagName -DefaultValue $false)) {
                    [void]$gaps.Add("releaseContract.$flagName must be true in $relative")
                }
            }

            $stagedMetadata = Get-ObjectPropertyValue -InputObject $manifest -Name 'stagedMetadata' -DefaultValue $null
            $machineOutputContract = if ($null -eq $stagedMetadata) { $null } else { Get-ObjectPropertyValue -InputObject $stagedMetadata -Name 'machineOutputContract' -DefaultValue $null }
            if ($null -eq $machineOutputContract -or -not [bool](Get-ObjectPropertyValue -InputObject $machineOutputContract -Name 'installModeContractRequired' -DefaultValue $false)) {
                [void]$gaps.Add("stagedMetadata.machineOutputContract.installModeContractRequired must be true in $relative")
            }
        }
        catch {
            [void]$gaps.Add("Invalid install contract JSON in ${relative}: $($_.Exception.Message)")
        }
    }

    $uniqueManifestModeIds = @($manifestModeIds.ToArray() | Select-Object -Unique)
    foreach ($modeId in $requiredModeIds) {
        if ($uniqueManifestModeIds -notcontains $modeId) {
            [void]$gaps.Add("packaging manifests missing install mode id '$modeId'")
        }
    }

    $packageScriptPath = Join-Path $RepositoryRoot 'scripts\package-portable.ps1'
    if (Test-Path -LiteralPath $packageScriptPath -PathType Leaf) {
        $packageRaw = Get-Content -LiteralPath $packageScriptPath -Raw
        foreach ($marker in @('installModeContract', 'installContractGaps', 'installContractGapNextActionsZh', 'existing-environment', 'restore-checkpoint-snapshot', 'fresh-create-flow', 'first-computer-prerequisites', 'compatibility-boundaries', 'readiness-package-non-mutation')) {
            if ($packageRaw.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$gaps.Add("Missing install contract marker '$marker' in scripts/package-portable.ps1")
            }
        }
    }
    else {
        [void]$gaps.Add('Missing scripts/package-portable.ps1 for install contract generation.')
    }

    foreach ($contractFile in @(
            [pscustomobject]@{ Relative = 'install.ps1'; Markers = @('Get-InstallHyperVPrerequisiteStatus', 'Get-InstallVmProfileStatus', 'ConfigureHyperVCommand', 'ResetGuestPasswordCommand', 'CheckEnvironmentStartsVm = $false') },
            [pscustomobject]@{ Relative = 'scripts/install.ps1'; Markers = @('CheckEnvironment', 'PreparePayload', '仅配置本机 Hyper-V 元数据；不会启动或还原 VM', 'ResetGuestVmPassword') }
        )) {
        $path = Join-Path $RepositoryRoot $contractFile.Relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$gaps.Add("Missing installer compatibility contract file: $($contractFile.Relative)")
            continue
        }

        $raw = Get-Content -LiteralPath $path -Raw
        foreach ($marker in @($contractFile.Markers)) {
            if ($raw.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                [void]$gaps.Add("Missing installer mode marker '$marker' in $($contractFile.Relative)")
            }
        }
    }

    $gapArray = @($gaps.ToArray() | Select-Object -Unique)
    $gapDetected = $gapArray.Count -gt 0

    return [pscustomobject][ordered]@{
        schema = 'ksword.release.install-mode-contract.v1'
        generatedBy = $GeneratedBy
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        purpose = 'Machine-readable installer UX/compatibility contract for release reviewers; generated by readiness without executing install modes.'
        manifestContractsPresent = @($manifestContractsPresent.ToArray())
        requiredModeIds = @($requiredModeIds)
        manifestModeIds = @($uniqueManifestModeIds)
        requiredEntrypoints = @(Get-InstallEntrypointRequiredValues)
        operatorModeMatrix = [ordered]@{
            schema = 'ksword.release.operator-mode-matrix.v1'
            modes = @(Get-CanonicalOperatorModeMatrix)
        }
        manifestOperatorModeMatrices = @($manifestOperatorModeMatrices.ToArray())
        gapDetected = $gapDetected
        gaps = @($gapArray)
        gapNextActionsZh = @(Get-InstallContractGapNextActionsZh -Gaps $gapArray)
        modes = @(
            [ordered]@{
                id = 'existing-environment'
                titleZh = '已有环境接入'
                primaryCommands = @('.\scripts\install.ps1 -Mode CheckEnvironment', '.\scripts\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>', '.\scripts\run.ps1 -Mode CheckEnvironment')
                evidenceFields = @('InstallStatus.VmExists', 'InstallStatus.CheckpointExists', 'InstallStatus.VmProfile', 'InstallStatus.GuestPayloadStatus', 'InstallStatus.RecommendedActions')
                readinessExecutesCommand = $false
                startsOrMutatesVm = $false
                nextActionsZh = @('下一步：已有 VM 时先用 CheckEnvironment 读取缺口，再用 -UpdateHyperVConfig 记录本机 VM/checkpoint profile。')
            },
            [ordered]@{
                id = 'restore-checkpoint-snapshot'
                titleZh = '还原 checkpoint/snapshot 边界'
                primaryCommands = @('.\scripts\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -PlanOnly', '.\scripts\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -WhatIf', '.\scripts\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -AllowVmMutation -Confirm')
                evidenceFields = @('InstallStatus.CheckpointExists', 'InstallStatus.CheckpointGuidance', 'VmProfile.ExpectedCheckpointName')
                readinessExecutesCommand = $false
                packageExecutesCommand = $false
                mayRestoreCheckpointOnlyWhenExplicit = $true
                nextActionsZh = @('下一步：先用 RestoreCleanCheckpoint -PlanOnly/-WhatIf 查看 rollback 计划；只有隔离 lab 操作者显式 -AllowVmMutation -Confirm/-Force 才可真实还原快照。')
            },
            [ordered]@{
                id = 'fresh-create-flow'
                titleZh = '首次/新机器本机配置流程'
                primaryCommands = @('.\scripts\install.ps1 -InstallEntrypoint CreateOrPreparePath -PromptPassword', '.\scripts\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>', '.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <external-payload-root> -SelfContained')
                evidenceFields = @('InstallStatus.RuntimeRootExists', 'InstallStatus.LocalConfigExists', 'InstallStatus.SecretValuePrinted=false', 'InstallStatus.GuestPayloadReadyForLiveCopy')
                createsLocalRuntimeFolders = $true
                createsVm = $false
                createsCheckpoint = $false
                nextActionsZh = @('下一步：新机器先运行 CreateOrPreparePath -PromptPassword 创建本机目录/配置/secret；payload 和 RuntimeRoot 放仓库外。')
            },
            [ordered]@{
                id = 'first-computer-prerequisites'
                titleZh = '首台电脑前置条件'
                evidenceFields = @('HyperVPrerequisites.OsIsWindows', 'HyperVPrerequisites.PowerShellModuleAvailable', 'HyperVPrerequisites.VirtualizationFirmwareEnabled', 'HyperVPrerequisites.SecondLevelAddressTranslationSupported', 'InstallStatus.IsAdministrator', 'InstallStatus.RuntimeRootUnderRepository', 'InstallStatus.VirusTotalStatus')
                evaluatedBy = @('.\scripts\install.ps1 -Mode CheckEnvironment', '.\scripts\run.ps1 -Mode CheckEnvironment')
                evaluatedByReadinessPackage = $false
                nextActionsZh = @('下一步：首机先跑 CheckEnvironment；按 RecommendedActions 修复 Hyper-V、BIOS 虚拟化、VM/checkpoint、payload、secret 和 runtime root。')
            },
            [ordered]@{
                id = 'compatibility-boundaries'
                titleZh = '兼容性边界'
                boundaries = @('Non-Windows hosts are source/package/readiness only; Hyper-V live requires Windows_NT.', 'Status/CheckEnvironment are read-only and do not print secrets.', 'StartWebUI does not start a VM; live VM execution requires explicit run.ps1 -Live.', 'Runtime packages require external RuntimePublishRoot.', 'VirusTotal is optional hash-only enrichment, not virtualization.')
                evidenceFields = @('executionBoundaries', 'operatorReadinessHints', 'freshLiveEvidenceGuardrail', 'requiredEvidenceFields.installModeHandoff')
                nextActionsZh = @('下一步：目标机器不满足 Hyper-V live 条件时，不要声称 fresh live；release notes 使用 no-fresh-live fallback。')
            },
            [ordered]@{
                id = 'readiness-package-non-mutation'
                titleZh = 'readiness/package 明确不变更'
                evidenceFields = @('executionBoundaries.smokeTestsExecuted=false', 'executionBoundaries.hyperVLiveExecuted=false', 'executionBoundaries.vmMutationExecuted=false', 'executionBoundaries.driverSigningExecuted=false', 'executionBoundaries.csignToolInvoked=false')
                installerModesExecutedByReadinessPackage = @()
                nonMutating = $true
                nextActionsZh = @('下一步：审阅 executionBoundaries；readiness/package 不能启动/还原/停止 VM、签名、push/publish 或生成 fresh live evidence。')
            }
        )
        readinessPackageNonMutation = [ordered]@{
            installerModesExecuted = @()
            checkEnvironmentExecuted = $false
            statusExecuted = $false
            installExecuted = $false
            changeExecuted = $false
            resetGuestVmPasswordExecuted = $false
            vmStartRestoreStopExecuted = $false
            vmMutationExecuted = $false
            driverSigningExecuted = $false
            csignToolInvoked = $false
            gitPushOrNetworkPublishExecuted = $false
            chinese = '中文：readiness/package 只做静态/本地低副作用检查，不运行安装模式、不启动/还原/停止 VM、不签名、不 push/publish。'
        }
        machineReadableEvidenceFields = @('installModeContract.modes[].id', 'installModeContract.readinessPackageNonMutation', 'installContractGaps', 'installContractGapNextActionsZh', 'executionBoundaries', 'requiredEvidenceFields.installModeHandoff')
    }
}

function Test-InstallModeMachineReadableContract {
    $contract = Get-InstallModeContractSnapshot
    if (-not [bool]$contract.gapDetected) {
        Add-ReleaseCheckResult `
            -Id 'install-mode-contract' `
            -Title 'Install mode contract / 安装模式契约' `
            -Status Passed `
            -Message 'Machine-readable install mode contract covers existing environment, checkpoint/snapshot restore boundary, fresh/create flow, first-computer prerequisites, compatibility boundaries, and readiness/package non-mutation.' `
            -Details @{ installModeContract = $contract }
        return
    }

    Add-ReleaseCheckResult `
        -Id 'install-mode-contract' `
        -Title 'Install mode contract / 安装模式契约' `
        -Status Failed `
        -Message "Install mode machine-readable contract found $(@($contract.gaps).Count) gap(s)." `
        -Remediation @($contract.gapNextActionsZh) `
        -Details @{ installModeContract = $contract; issues = @($contract.gaps); nextActionsZh = @($contract.gapNextActionsZh) }
}

function Get-RuntimeHandoffNextActionsZh {
    param(
        [object]$RuntimeSummary = $null,
        [object]$RootDiagnostics = $null,
        [object[]]$Entries = @()
    )

    $actions = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($RuntimePublishRoot)) {
        [void]$actions.Add('下一步：先把 host-web、guest-tools、tools/job-tool、tools/postprocess 发布到 D:\Temp\KSwordSandbox\publish 或其他仓库外 RuntimePublishRoot。')
        [void]$actions.Add('下一步：重跑 .\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePackage。')
    }
    elseif ($null -ne $RootDiagnostics -and -not [bool]$RootDiagnostics.outsideRepository) {
        [void]$actions.Add('下一步：RuntimePublishRoot 必须移到仓库外；不要从仓库 bin/obj/x64 或源码树兜底复制 runtime payload。')
    }
    elseif ($null -ne $RootDiagnostics -and -not [bool]$RootDiagnostics.exists) {
        [void]$actions.Add("下一步：创建并填充仓库外 RuntimePublishRoot：$($RootDiagnostics.resolvedPath)。")
    }

    if ($null -ne $RuntimeSummary) {
        if ([int]$RuntimeSummary.missingCount -gt 0) {
            [void]$actions.Add("下一步：补齐缺失 runtime payload：$(([string[]]@($RuntimeSummary.missingSources)) -join ', ')。")
        }
        if ([int]$RuntimeSummary.incompleteCount -gt 0) {
            [void]$actions.Add("下一步：重新发布不完整 payload：$(([string[]]@($RuntimeSummary.incompleteSources)) -join ', ')；确认预期 exe/dll/payload-manifest 存在。")
        }
        if ([int]$RuntimeSummary.forbiddenFileCount -gt 0) {
            [void]$actions.Add('下一步：删除 RuntimePublishRoot 内的 .pdb/.sys/pcap/dump/VM/secret/signing/CSignTool/signtool/GUI signing fallback 文件。')
        }
        if (-not [bool]$RuntimeSummary.handoffAllowed) {
            [void]$actions.Add('下一步：确认 RuntimePublishRoot 在仓库外、missingCount/incompleteCount/forbiddenFileCount 均为 0，并且本次使用 -RequireCompleteRuntimePackage。')
        }
    }

    if ($actions.Count -eq 0) {
        [void]$actions.Add('下一步：runtime handoff gate 已满足；生成 runtime zip 时仍需 package-portable.ps1 -PackageKind runtime -RuntimePublishRoot <external-publish-root> -RequireCompleteRuntimePayloads。')
    }

    [void]$actions.Add('边界提醒：readiness/package 不跑 smoke、不跑 live、不签名、不调用 CSignTool；fresh live evidence 只能由 release manager 在 lab host 显式运行并记录 job id。')
    return @($actions.ToArray())
}


function Get-ReleaseComponentProgressSnapshot {
    param([int]$ExitCode = 0)

    $runtimeRootProvided = -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)
    $completeRuntimeRequested = [bool]$RequireCompleteRuntimePackage
    $installContractResult = @($script:Results | Where-Object { $_.id -eq 'install-mode-contract' } | Select-Object -First 1)
    $installContractStatus = if ($installContractResult.Count -eq 0) { 'not-run' } else { [string]$installContractResult[0].status }
    return [ordered]@{
        schema = 'ksword.release.component-progress.v1'
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        purpose = 'Machine-readable component progress for release reviewers; readiness is non-mutating and does not create fresh live evidence; gapAudit uses ksword.release.gap-audit.v28.'
        noFreshLiveEvidenceGenerated = $true
        freshLiveEvidenceGenerated = $false
        executionBoundarySummary = 'no smoke, no Hyper-V live, no driver signing, no CSignTool, no git push/publish'
        requiredEvidenceFieldsSchema = 'ksword.release.required-evidence-fields.v1'
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
            },
            [ordered]@{
                id = 'install-mode-contract'
                titleZh = '安装模式机器可读契约'
                state = if ($installContractStatus -eq 'Passed') { 'documented' } elseif ($installContractStatus -eq 'not-run') { 'not-run' } else { 'blocked-contract-gap' }
                handoffGate = 'Machine-readable contract covers existing environment, restore checkpoint/snapshot boundary, fresh/create flow, first-computer prerequisites, compatibility boundaries, and readiness/package non-mutation.'
                reviewerChecklist = @('installModeContract.schema', 'required mode ids present', 'installContractGaps empty', 'installContractGapNextActionsZh present when gaps exist', 'executionBoundaries show no installer/live/VM mutation')
                remediationZh = '若 install-mode-contract 失败，按 release-readiness.json 的 installContractGapNextActionsZh 补齐 package/readiness/manifest metadata；不要改 install scripts/docs 或运行 live。'
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
    $installContractResult = $resultById['install-mode-contract']
    $installModeContract = Get-InstallModeContractSnapshot
    $componentProgress = Get-ReleaseComponentProgressSnapshot -ExitCode $ExitCode
    $runtimeRootProvided = -not [string]::IsNullOrWhiteSpace($RuntimePublishRoot)
    $runtimeHandoffVerified = ($runtimeRootProvided -and [bool]$RequireCompleteRuntimePackage -and $null -ne $runtimeResult -and $runtimeResult.status -eq 'Passed' -and $ExitCode -eq 0)
    $runtimeSummary = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('runtimePublishSummary')) { $runtimeResult.details.runtimePublishSummary } else { $null }
    $runtimeEntries = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('entries')) { @($runtimeResult.details.entries) } else { @() }
    $rootDiagnostics = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('rootDiagnostics')) { $runtimeResult.details.rootDiagnostics } else { $null }
    $runtimeNextActionsZh = if ($null -ne $runtimeResult -and $null -ne $runtimeResult.details -and $runtimeResult.details.ContainsKey('nextActionsZh')) { @($runtimeResult.details.nextActionsZh) } else { @(Get-RuntimeHandoffNextActionsZh -RuntimeSummary $runtimeSummary -RootDiagnostics $rootDiagnostics -Entries $runtimeEntries) }

    return [ordered]@{
        schema = 'ksword.release.gap-audit.v28'
        contractVersion = 28
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        purpose = 'Machine-readable release/productization gap audit; produced by non-mutating readiness only.'
        validationProfile = 'release-readiness-no-smoke-no-live'
        generatedBy = 'scripts/Test-ReleaseReadiness.ps1'
        gitMetadata = Get-GitReleaseMetadata
        executionBoundaries = Get-ReleaseExecutionBoundaries
        requiredEvidenceFields = Get-ReleaseRequiredEvidenceFields
        nonMutating = [ordered]@{
            hyperVLive = $false
            smokeTests = $false
            vmStartRestoreStop = $false
            vmMutation = $false
            installerModes = $false
            installCheckEnvironment = $false
            installStatus = $false
            installChange = $false
            resetGuestVmPassword = $false
            driverSigning = $false
            csignTool = $false
            csignToolInvoked = $false
            guiSigningFallback = $false
            gitPush = $false
            networkPublish = $false
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
            nextActionsZh = @($runtimeNextActionsZh)
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
        installModeContract = [ordered]@{
            schema = $installModeContract.schema
            status = if ($null -eq $installContractResult) { 'not-run' } else { [string]$installContractResult.status }
            gapDetected = [bool]$installModeContract.gapDetected
            gaps = @($installModeContract.gaps)
            nextActionsZh = @($installModeContract.gapNextActionsZh)
            requiredModeIds = @($installModeContract.requiredModeIds)
            modeIds = @($installModeContract.modes | ForEach-Object { $_.id })
            operatorModeEntrypoints = @($installModeContract.operatorModeMatrix.modes | ForEach-Object { $_.entrypoint })
            readinessPackageNonMutation = $installModeContract.readinessPackageNonMutation
            remediationZh = 'install mode contract 必须覆盖已有环境、checkpoint/snapshot 边界、首次/新机器流程、首机前置条件、兼容性边界，以及 package/readiness 明确不变更。'
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
    [void]$lines.Add("Dirty status: ``$($Summary.gitDirtyStatus)``")
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
    [void]$lines.Add("- Smoke tests executed: ``$($Summary.executionBoundaries.smokeTestsExecuted)``")
    [void]$lines.Add("- Hyper-V live executed: ``$($Summary.executionBoundaries.hyperVLiveExecuted)``")
    [void]$lines.Add("- VM mutation: ``$($Summary.noVmMutation)``")
    [void]$lines.Add("- Driver signing: ``$($Summary.noDriverSigning)``")
    [void]$lines.Add("- GUI signing fallback: ``$($Summary.noGuiSigningFallback)``")
    [void]$lines.Add("- CSignTool not called: ``$($Summary.csignToolNotCalled)``")
    [void]$lines.Add("- Fresh live evidence generated: ``$($Summary.freshLiveEvidenceGenerated)``")
    [void]$lines.Add("- Release-note fallback without a lab job id: ``$($Summary.releaseNotesFreshLiveFallback)``")
    [void]$lines.Add('')
    [void]$lines.Add('## Install mode contract')
    [void]$lines.Add('')
    [void]$lines.Add("- Gap detected: ``$($Summary.installContractGapDetected)``")
    foreach ($item in @($Summary.installContractGapNextActionsZh | Select-Object -First 6)) {
        [void]$lines.Add("- Install contract next: $item")
    }
    [void]$lines.Add('- The machine-readable `installModeContract` covers existing environment, checkpoint/snapshot restore boundary, fresh/create flow, first-computer prerequisites, compatibility boundaries, and readiness/package non-mutation.')
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
    foreach ($item in @($Summary.runtimeHandoffMissingNextActionsZh | Select-Object -First 6)) {
        [void]$lines.Add("- Runtime next: $item")
    }

    [void]$lines.Add('- Required final evidence before claiming a fresh live release: commit, job id, runtime root, generated time, report JSON path, zh/en HTML report paths.')
    [void]$lines.Add('- Machine-readable evidence fields are listed in `requiredEvidenceFields` and include branch, commit, dirty status, runtime handoff fields, and fresh-live claim fields.')
    [void]$lines.Add('')
    [void]$lines.Add('### Required evidence fields')
    [void]$lines.Add('')
    foreach ($item in @($Summary.requiredEvidenceFields.provenance)) {
        [void]$lines.Add("- Provenance: ``$item``")
    }
    foreach ($item in @($Summary.requiredEvidenceFields.runtimeHandoff)) {
        [void]$lines.Add("- Runtime handoff: ``$item``")
    }
    foreach ($item in @($Summary.requiredEvidenceFields.installModeHandoff)) {
        [void]$lines.Add("- Install mode handoff: ``$item``")
    }
    foreach ($item in @($Summary.requiredEvidenceFields.freshLiveClaim)) {
        [void]$lines.Add("- Fresh live claim: ``$item``")
    }
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
Test-InstallerEntrypointStaticContract
Test-CSignToolNotInReleasePath
Test-NoGuiSigningFallback
Test-ReadinessNoVmMutationCommands
Test-DeploymentOperatorDiagnosticsContract
Test-InstallModeMachineReadableContract
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
$runtimeResultForSummary = @($script:Results | Where-Object { $_.id -eq 'runtime-publish-completeness' } | Select-Object -First 1)
$runtimeHandoffMissingNextActionsZh = if ($runtimeResultForSummary.Count -gt 0 -and $null -ne $runtimeResultForSummary[0].details -and $runtimeResultForSummary[0].details.ContainsKey('nextActionsZh')) {
    @($runtimeResultForSummary[0].details.nextActionsZh)
}
else {
    @(Get-RuntimeHandoffNextActionsZh)
}
$installModeContractSummary = Get-InstallModeContractSnapshot

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
    gitDirty              = $gitMetadata.dirty
    gitDirtyStatus        = $gitMetadata.dirtyStatus
    gitStatusCount        = $gitMetadata.statusCount
    gitStatusPreview      = @($gitMetadata.statusPreview)
    gitMetadata           = [ordered]@{
        schema = 'ksword.release.git-provenance.v1'
        available = [bool]$gitMetadata.available
        branch = $gitMetadata.branch
        commit = $gitMetadata.commit
        shortCommit = $gitMetadata.shortCommit
        dirty = $gitMetadata.dirty
        isDirty = $gitMetadata.isDirty
        dirtyStatus = $gitMetadata.dirtyStatus
        statusCount = $gitMetadata.statusCount
        statusPreview = @($gitMetadata.statusPreview)
        statusPorcelainPreview = @($gitMetadata.statusPorcelainPreview)
    }
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
    executionBoundaries   = Get-ReleaseExecutionBoundaries
    requiredEvidenceFields = Get-ReleaseRequiredEvidenceFields
    installModeContract   = $installModeContractSummary
    installContractGapDetected = [bool]$installModeContractSummary.gapDetected
    installContractGaps   = @($installModeContractSummary.gaps)
    installContractGapNextActionsZh = @($installModeContractSummary.gapNextActionsZh)
    runtimeHandoffMissingNextActionsZh = @($runtimeHandoffMissingNextActionsZh)
    noSmokeTests          = $true
    noHyperVLive          = $true
    smokeTestsExecuted    = $false
    hyperVLiveExecuted    = $false
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
        'installModeContract machine-readably separates existing environment, restore checkpoint/snapshot, fresh/create setup, first-computer prerequisites, compatibility boundaries, and package/readiness non-mutation.',
        'No readiness/package command creates a job id; release notes need an explicit lab live run before claiming fresh live evidence.'
    )
    reviewerChecklist     = [ordered]@{
        chinese = '中文审阅速查：readiness 只证明低副作用门禁；runtime handoff 还必须补齐仓库外 RuntimePublishRoot；fresh live 声明必须有实验室 job id。'
        mustPassBeforeSourceHandoff = @(
            'release-readiness.json failedCount = 0',
            'source package StageOnly dry-run 已生成 package-manifest.generated.json',
            'installModeContract.gapDetected = false，installContractGaps 为空；若不为空按 installContractGapNextActionsZh 修复',
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
        installModeContract = [ordered]@{
            gapDetected = [bool]$installModeContractSummary.gapDetected
            gaps = @($installModeContractSummary.gaps)
            nextActionsZh = @($installModeContractSummary.gapNextActionsZh)
            modeIds = @($installModeContractSummary.modes | ForEach-Object { $_.id })
            operatorModeEntrypoints = @($installModeContractSummary.operatorModeMatrix.modes | ForEach-Object { $_.entrypoint })
            packageReadinessExecutesInstallerModes = $false
        }
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
            smokeTests = $false
            hyperVLive = $false
            vmMutation = $false
            installerModes = $false
            checkEnvironment = $false
            installModeInstall = $false
            installModeChange = $false
            resetGuestVmPassword = $false
            driverSigning = $false
            guiSigningFallback = $false
            csignTool = $false
            csignToolInvoked = $false
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
Write-Host "Git：branch=$($summary.gitBranch)，commit=$($summary.gitShortCommit)，dirty=$($summary.gitDirtyStatus)，changes=$($summary.gitStatusCount)。"
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
Write-Host '安全护栏：未跑 smoke，未跑 Hyper-V live，未启动/还原/停止 VM，未签名，未调用 CSignTool/GUI signing fallback，未 push/publish，未生成 fresh live evidence。'
exit $exitCode
