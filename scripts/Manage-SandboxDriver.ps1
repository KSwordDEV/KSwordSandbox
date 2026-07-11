<#
.SYNOPSIS
Installs, starts, stops, uninstalls, or reports status for the KSword Sandbox driver.

.DESCRIPTION
This helper is the explicit lab-only driver load/unload entry point. It never
calls CSignTool. It prefers an INF/pnputil install path when an INF is supplied
or auto-detected, and otherwise falls back to sc.exe plus the minimal
minifilter registry instance keys required for local test VMs.

All output is a single machine-readable JSON document. Mutating actions require
an elevated PowerShell session and, by default, Windows test-signing enabled
for the current boot entry. Use -SkipTestSigningCheck only when intentionally
validating a production-signed driver.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Status', 'Install', 'Start', 'Stop', 'Restart', 'Uninstall')]
    [string]$Action = 'Status',

    [string]$ServiceName = 'KSwordSandboxDriver',

    [string]$DriverPath = '',

    [string]$InfPath = '',

    [ValidateSet('Auto', 'Kernel', 'MiniFilter')]
    [string]$DriverKind = 'MiniFilter',

    [ValidateSet('Demand', 'Boot', 'System', 'Auto', 'Disabled')]
    [string]$StartType = 'Demand',

    [ValidatePattern('^\d+(\.\d+)?$')]
    [string]$MiniFilterAltitude = '385201',

    [string]$MiniFilterInstanceName = '',

    [string]$PublishedName = '',

    [switch]$SkipTestSigningCheck,

    [switch]$Force,

    [ValidateRange(4, 32)]
    [int]$JsonDepth = 12
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Steps = [System.Collections.Generic.List[object]]::new()
$script:Warnings = [System.Collections.Generic.List[string]]::new()

function Add-DriverWarning {
    param([Parameter(Mandatory)][string]$Message)

    if (-not $script:Warnings.Contains($Message)) {
        [void]$script:Warnings.Add($Message)
    }
}

function Get-RepositoryRoot {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
    }

    return (Get-Location).ProviderPath
}

function Resolve-OptionalPath {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    if (Test-Path -LiteralPath $Path) {
        return (Resolve-Path -LiteralPath $Path).ProviderPath
    }

    return [System.IO.Path]::GetFullPath($Path)
}

function Find-DefaultDriverPath {
    param([Parameter(Mandatory)][string]$RepositoryRoot)

    $candidates = @(
        (Join-Path $RepositoryRoot 'driver\KSword.Sandbox.Driver\x64\Debug\KSword.Sandbox.Driver.sys'),
        (Join-Path $RepositoryRoot 'driver\KSword.Sandbox.Driver\x64\Release\KSword.Sandbox.Driver.sys'),
        (Join-Path $RepositoryRoot 'x64\Debug\KSword.Sandbox.Driver.sys'),
        (Join-Path $RepositoryRoot 'x64\Release\KSword.Sandbox.Driver.sys')
    )

    $existing = foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Get-Item -LiteralPath $candidate
        }
    }

    $selected = $existing | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
    if ($selected) {
        return $selected.FullName
    }

    return ''
}

function Find-DefaultInfPath {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [AllowNull()][string]$ResolvedDriverPath
    )

    $searchRoots = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($ResolvedDriverPath) -and (Test-Path -LiteralPath $ResolvedDriverPath -PathType Leaf)) {
        [void]$searchRoots.Add((Split-Path -Parent $ResolvedDriverPath))
    }

    $driverRoot = Join-Path $RepositoryRoot 'driver'
    if (Test-Path -LiteralPath $driverRoot -PathType Container) {
        [void]$searchRoots.Add($driverRoot)
    }

    $infFiles = foreach ($root in ($searchRoots | Select-Object -Unique)) {
        Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.inf' -ErrorAction SilentlyContinue
    }

    $selected = $infFiles |
        Sort-Object @{ Expression = { if ($_.Name -like '*KSword*' -or $_.Name -like '*Sandbox*') { 0 } else { 1 } } }, LastWriteTime -Descending |
        Select-Object -First 1

    if ($selected) {
        return $selected.FullName
    }

    return ''
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)

    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList
    )

    if (-not (Test-CommandAvailable -Name $FilePath)) {
        return [pscustomobject][ordered]@{
            ExitCode = $null
            Output = @()
            Error = "错误：找不到命令：$FilePath。下一步：请确认该工具已安装并在 PATH 中。 / Command not found."
        }
    }

    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE

    return [pscustomobject][ordered]@{
        ExitCode = $exitCode
        Output = $output
        Error = $null
    }
}

function Add-CommandStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Verb,
        [int[]]$SuccessExitCodes = @(0),
        [switch]$NonFatal
    )

    $step = [ordered]@{
        Name = $Name
        Tool = $Tool
        Arguments = $Arguments
        Target = $Target
        Verb = $Verb
        Executed = $false
        SkippedByWhatIf = $false
        ExitCode = $null
        Success = $false
        NonFatal = [bool]$NonFatal
        Output = @()
        Error = $null
    }

    if (-not $PSCmdlet.ShouldProcess($Target, $Verb)) {
        $step.SkippedByWhatIf = $true
        $step.Success = $true
        [void]$script:Steps.Add([pscustomobject]$step)
        return [pscustomobject]$step
    }

    $commandResult = Invoke-CapturedCommand -FilePath $Tool -ArgumentList $Arguments
    $step.Executed = $true
    $step.ExitCode = $commandResult.ExitCode
    $step.Output = @($commandResult.Output)
    $step.Error = $commandResult.Error
    $step.Success = ($null -ne $commandResult.ExitCode -and $SuccessExitCodes -contains [int]$commandResult.ExitCode)

    if ($null -eq $commandResult.ExitCode -and -not [string]::IsNullOrWhiteSpace($commandResult.Error)) {
        $step.Success = $false
    }

    [void]$script:Steps.Add([pscustomobject]$step)

    if (-not $step.Success -and -not $NonFatal) {
        $message = if (-not [string]::IsNullOrWhiteSpace($step.Error)) {
            $step.Error
        }
        else {
            "错误：命令失败：$Tool $($Arguments -join ' ')，退出码 $($step.ExitCode)。下一步：查看 Output 字段，按 Hints 修复后重试。英文输出：$($step.Output -join ' ')"
        }

        throw $message
    }

    return [pscustomobject]$step
}

function Add-RegistryStep {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [switch]$NonFatal
    )

    $step = [ordered]@{
        Name = $Name
        Tool = 'PowerShell.Registry'
        Arguments = @()
        Target = $Target
        Verb = '写入注册表配置 / Write registry configuration'
        Executed = $false
        SkippedByWhatIf = $false
        ExitCode = 0
        Success = $false
        NonFatal = [bool]$NonFatal
        Output = @()
        Error = $null
    }

    if (-not $PSCmdlet.ShouldProcess($Target, '写入注册表配置 / Write registry configuration')) {
        $step.SkippedByWhatIf = $true
        $step.Success = $true
        [void]$script:Steps.Add([pscustomobject]$step)
        return [pscustomobject]$step
    }

    try {
        & $ScriptBlock
        $step.Executed = $true
        $step.Success = $true
    }
    catch {
        $step.Executed = $true
        $step.ExitCode = 1
        $step.Error = $_.Exception.Message
        $step.Success = $false
    }

    [void]$script:Steps.Add([pscustomobject]$step)

    if (-not $step.Success -and -not $NonFatal) {
        throw $step.Error
    }

    return [pscustomobject]$step
}

function Get-TestSigningStatus {
    if (-not (Test-CommandAvailable -Name 'bcdedit.exe')) {
        return [pscustomobject][ordered]@{
            ToolAvailable = $false
            Enabled = $null
            Value = $null
            ExitCode = $null
            Output = @()
            Error = '错误：找不到 bcdedit.exe。下一步：请在 Windows 管理员 PowerShell 中运行，确认系统工具可用。 / bcdedit.exe was not found.'
        }
    }

    $result = Invoke-CapturedCommand -FilePath 'bcdedit.exe' -ArgumentList @('/enum')
    $text = @($result.Output) -join "`n"
    $value = $null
    $enabled = $null
    if ($text -match '(?im)^\s*testsigning\s+(?<value>\S+)\s*$') {
        $value = $Matches['value']
        $enabled = $value -match '^(Yes|On|True)$'
    }
    elseif ($result.ExitCode -eq 0) {
        $value = 'AbsentOrOff'
        $enabled = $false
    }

    return [pscustomobject][ordered]@{
        ToolAvailable = $true
        Enabled = $enabled
        Value = $value
        ExitCode = $result.ExitCode
        Output = @($result.Output)
        Error = $result.Error
    }
}

function Get-DriverSignatureStatus {
    param([AllowNull()][string]$ResolvedDriverPath)

    if ([string]::IsNullOrWhiteSpace($ResolvedDriverPath) -or -not (Test-Path -LiteralPath $ResolvedDriverPath -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            DriverPath = $ResolvedDriverPath
            Exists = $false
            Status = $null
            StatusMessage = $null
            SignerSubject = $null
            SignerThumbprint = $null
        }
    }

    try {
        $signature = Get-AuthenticodeSignature -FilePath $ResolvedDriverPath
        return [pscustomobject][ordered]@{
            DriverPath = $ResolvedDriverPath
            Exists = $true
            Status = [string]$signature.Status
            StatusMessage = [string]$signature.StatusMessage
            SignerSubject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
            SignerThumbprint = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Thumbprint } else { $null }
        }
    }
    catch {
        return [pscustomobject][ordered]@{
            DriverPath = $ResolvedDriverPath
            Exists = $true
            Status = 'Unknown'
            StatusMessage = ConvertTo-DriverUserMessage -Message $_.Exception.Message
            SignerSubject = $null
            SignerThumbprint = $null
        }
    }
}

function Parse-ScColonValue {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Output,
        [Parameter(Mandatory)][string]$Name
    )

    $pattern = '^\s*' + [regex]::Escape($Name) + '\s*:\s*(?<value>.+?)\s*$'
    foreach ($line in $Output) {
        if ($line -match $pattern) {
            return $Matches['value']
        }
    }

    return $null
}

function Get-ServiceStatus {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Test-CommandAvailable -Name 'sc.exe')) {
        return [pscustomobject][ordered]@{
            ToolAvailable = $false
            Exists = $false
            ServiceName = $Name
            QueryExitCode = $null
            State = $null
            StateCode = $null
            Type = $null
            StartType = $null
            BinaryPath = $null
            RawQuery = @()
            RawConfig = @()
            Error = '错误：找不到 sc.exe。下一步：请在 Windows 环境/管理员 PowerShell 中运行。 / sc.exe was not found.'
        }
    }

    $query = Invoke-CapturedCommand -FilePath 'sc.exe' -ArgumentList @('queryex', $Name)
    $config = Invoke-CapturedCommand -FilePath 'sc.exe' -ArgumentList @('qc', $Name)
    $exists = $query.ExitCode -eq 0

    $stateText = Parse-ScColonValue -Output @($query.Output) -Name 'STATE'
    $stateCode = $null
    $stateName = $null
    if (-not [string]::IsNullOrWhiteSpace($stateText) -and $stateText -match '^(?<code>\d+)\s+(?<name>\S+)') {
        $stateCode = [int]$Matches['code']
        $stateName = $Matches['name']
    }

    return [pscustomobject][ordered]@{
        ToolAvailable = $true
        Exists = $exists
        ServiceName = $Name
        QueryExitCode = $query.ExitCode
        State = $stateName
        StateCode = $stateCode
        Type = Parse-ScColonValue -Output @($query.Output + $config.Output) -Name 'TYPE'
        StartType = Parse-ScColonValue -Output @($config.Output) -Name 'START_TYPE'
        BinaryPath = Parse-ScColonValue -Output @($config.Output) -Name 'BINARY_PATH_NAME'
        RawQuery = @($query.Output)
        RawConfig = @($config.Output)
        Error = if ($exists) { $null } else { ($query.Output -join ' ') }
    }
}

function Get-MiniFilterStatus {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Test-CommandAvailable -Name 'fltmc.exe')) {
        return [pscustomobject][ordered]@{
            ToolAvailable = $false
            Loaded = $null
            MatchingLines = @()
            RawFilters = @()
            Error = '错误：找不到 fltmc.exe。下一步：请在支持 Filter Manager 的 Windows VM 中运行。 / fltmc.exe was not found.'
        }
    }

    $filters = Invoke-CapturedCommand -FilePath 'fltmc.exe' -ArgumentList @('filters')
    $matches = @($filters.Output | Where-Object { $_ -match "(?i)\b$([regex]::Escape($Name))\b" })

    return [pscustomobject][ordered]@{
        ToolAvailable = $true
        Loaded = [bool]($matches.Count -gt 0)
        MatchingLines = $matches
        RawFilters = @($filters.Output)
        Error = $filters.Error
    }
}

function Get-CurrentStatus {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedDriverPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedInfPath,
        [Parameter(Mandatory)][string]$EffectiveDriverKind
    )

    $service = Get-ServiceStatus -Name $ServiceName
    $filter = Get-MiniFilterStatus -Name $ServiceName
    $signature = Get-DriverSignatureStatus -ResolvedDriverPath $ResolvedDriverPath
    $testSigning = Get-TestSigningStatus

    return [pscustomobject][ordered]@{
        Service = $service
        MiniFilter = $filter
        DriverFile = [pscustomobject][ordered]@{
            Path = $ResolvedDriverPath
            Exists = (-not [string]::IsNullOrWhiteSpace($ResolvedDriverPath) -and (Test-Path -LiteralPath $ResolvedDriverPath -PathType Leaf))
            Signature = $signature
        }
        Inf = [pscustomobject][ordered]@{
            Path = $ResolvedInfPath
            Exists = (-not [string]::IsNullOrWhiteSpace($ResolvedInfPath) -and (Test-Path -LiteralPath $ResolvedInfPath -PathType Leaf))
            PublishedName = if ([string]::IsNullOrWhiteSpace($PublishedName)) { $null } else { $PublishedName }
        }
        TestSigning = $testSigning
        EffectiveDriverKind = $EffectiveDriverKind
    }
}

function Get-ScDriverType {
    param([Parameter(Mandatory)][string]$EffectiveDriverKind)

    if ($EffectiveDriverKind -eq 'MiniFilter') {
        return 'filesys'
    }

    return 'kernel'
}

function Get-ScStartType {
    switch ($StartType) {
        'Boot' { return 'boot' }
        'System' { return 'system' }
        'Auto' { return 'auto' }
        'Disabled' { return 'disabled' }
        default { return 'demand' }
    }
}

function Write-MiniFilterRegistryFallback {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$InstanceName,
        [Parameter(Mandatory)][string]$Altitude
    )

    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $instancesKey = Join-Path $serviceKey 'Instances'
    $instanceKey = Join-Path $instancesKey $InstanceName

    New-Item -Path $serviceKey -Force | Out-Null
    New-ItemProperty -Path $serviceKey -Name 'Group' -PropertyType String -Value 'FSFilter Activity Monitor' -Force | Out-Null
    New-Item -Path $instancesKey -Force | Out-Null
    New-ItemProperty -Path $instancesKey -Name 'DefaultInstance' -PropertyType String -Value $InstanceName -Force | Out-Null
    New-Item -Path $instanceKey -Force | Out-Null
    New-ItemProperty -Path $instanceKey -Name 'Altitude' -PropertyType String -Value $Altitude -Force | Out-Null
    New-ItemProperty -Path $instanceKey -Name 'Flags' -PropertyType DWord -Value 0 -Force | Out-Null
}

function Assert-MutatingPreconditions {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedDriverPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedInfPath,
        [Parameter(Mandatory)]$Status
    )

    if (-not (Test-IsAdministrator)) {
        if ($WhatIfPreference) {
            Add-DriverWarning '需要管理员 PowerShell 才能修改 driver service；当前为 -WhatIf 预览，已在未提权状态下继续。 / Elevated PowerShell required for real mutations.'
        }
        else {
            throw '错误：安装/启动/停止/卸载 driver service 需要管理员 PowerShell。下一步：请以管理员身份打开隔离 VM 内的 PowerShell 后重试；只看状态可运行 -Action Status。'
        }
    }

    if ($Action -eq 'Install' -and
        [string]::IsNullOrWhiteSpace($ResolvedInfPath) -and
        ([string]::IsNullOrWhiteSpace($ResolvedDriverPath) -or -not (Test-Path -LiteralPath $ResolvedDriverPath -PathType Leaf))) {
        throw '错误：Install 需要 -InfPath，或可读取的 .sys -DriverPath。下一步：请先构建/复制测试签名 KSword.Sandbox.Driver.sys，然后传入 -DriverPath <path>。'
    }

    if ($Action -in @('Install', 'Start', 'Restart') -and -not $SkipTestSigningCheck) {
        if ($Status.TestSigning.Enabled -eq $false) {
            if ($WhatIfPreference) {
                Add-DriverWarning 'Windows test-signing 当前关闭。下一步：在隔离 VM 管理员 PowerShell 中运行 bcdedit /set testsigning on，重启，并信任测试证书后再真实加载。 / Windows test-signing is disabled.'
            }
            else {
                throw '错误：当前启动项未启用 Windows test-signing。下一步：在隔离 VM 管理员 PowerShell 中运行 bcdedit /set testsigning on，重启，信任测试证书后重试；只有生产签名 driver 才使用 -SkipTestSigningCheck。'
            }
        }

        if ($null -eq $Status.TestSigning.Enabled) {
            Add-DriverWarning '无法确认 Windows test-signing 状态。下一步：先检查 bcdedit /enum，确认 testsigning on 且已重启；否则测试签名 driver 可能加载失败。 / Could not confirm test-signing state.'
        }
    }
}

function Invoke-InstallAction {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedDriverPath,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedInfPath,
        [Parameter(Mandatory)][string]$EffectiveDriverKind,
        [Parameter(Mandatory)]$BeforeStatus
    )

    if (-not [string]::IsNullOrWhiteSpace($ResolvedInfPath) -and (Test-Path -LiteralPath $ResolvedInfPath -PathType Leaf)) {
        [void](Add-CommandStep `
            -Name 'pnputil.add-driver' `
            -Tool 'pnputil.exe' `
            -Arguments @('/add-driver', $ResolvedInfPath, '/install') `
            -Target $ResolvedInfPath `
            -Verb '用 pnputil 安装 driver package / Install driver package with pnputil')
        return
    }

    Add-DriverWarning '未找到 INF，将使用 sc.exe fallback。下一步：生产/正式 minifilter 包装请使用声明 class、instances、altitude 的签名 INF。 / No INF was found.'

    $scType = Get-ScDriverType -EffectiveDriverKind $EffectiveDriverKind
    $scStart = Get-ScStartType
    $operation = if ($BeforeStatus.Service.Exists) { 'config' } else { 'create' }
    $verb = if ($operation -eq 'create') { '用 sc.exe fallback 创建 driver service / Create driver service with sc.exe fallback' } else { '用 sc.exe fallback 更新现有 driver service / Update existing driver service with sc.exe fallback' }

    [void](Add-CommandStep `
        -Name "sc.$operation" `
        -Tool 'sc.exe' `
        -Arguments @($operation, $ServiceName, 'type=', $scType, 'start=', $scStart, 'binPath=', $ResolvedDriverPath) `
        -Target $ServiceName `
        -Verb $verb)

    if ($EffectiveDriverKind -eq 'MiniFilter') {
        $instance = if ([string]::IsNullOrWhiteSpace($MiniFilterInstanceName)) { "$ServiceName Instance" } else { $MiniFilterInstanceName }
        Add-DriverWarning "sc.exe fallback 已写入 minifilter instance '$instance'，实验 altitude '$MiniFilterAltitude'。下一步：生产包装请使用分配的 altitude 和 INF。 / sc.exe fallback wrote minifilter instance."
        [void](Add-RegistryStep `
            -Name 'registry.minifilter-instance' `
            -Target "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Instances" `
            -ScriptBlock { Write-MiniFilterRegistryFallback -Name $ServiceName -InstanceName $instance -Altitude $MiniFilterAltitude })
    }
}

function Invoke-StartAction {
    param([Parameter(Mandatory)][string]$EffectiveDriverKind)

    if ($EffectiveDriverKind -eq 'MiniFilter') {
        [void](Add-CommandStep `
            -Name 'fltmc.load' `
            -Tool 'fltmc.exe' `
            -Arguments @('load', $ServiceName) `
            -Target $ServiceName `
            -Verb '用 fltmc 加载 minifilter / Load minifilter with fltmc')
        return
    }

    [void](Add-CommandStep `
        -Name 'sc.start' `
        -Tool 'sc.exe' `
        -Arguments @('start', $ServiceName) `
        -Target $ServiceName `
        -Verb '启动 kernel driver service / Start kernel driver service' `
        -SuccessExitCodes @(0, 1056))
}

function Invoke-StopAction {
    param([Parameter(Mandatory)][string]$EffectiveDriverKind)

    if ($EffectiveDriverKind -eq 'MiniFilter') {
        [void](Add-CommandStep `
            -Name 'fltmc.unload' `
            -Tool 'fltmc.exe' `
            -Arguments @('unload', $ServiceName) `
            -Target $ServiceName `
            -Verb '用 fltmc 卸载 minifilter / Unload minifilter with fltmc' `
            -NonFatal)
    }

    [void](Add-CommandStep `
        -Name 'sc.stop' `
        -Tool 'sc.exe' `
        -Arguments @('stop', $ServiceName) `
        -Target $ServiceName `
        -Verb '停止 driver service / Stop driver service' `
        -SuccessExitCodes @(0, 1060, 1062) `
        -NonFatal)
}

function Invoke-UninstallAction {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedInfPath,
        [Parameter(Mandatory)][string]$EffectiveDriverKind
    )

    Invoke-StopAction -EffectiveDriverKind $EffectiveDriverKind

    if (-not [string]::IsNullOrWhiteSpace($ResolvedInfPath) -and -not [string]::IsNullOrWhiteSpace($PublishedName)) {
        [void](Add-CommandStep `
            -Name 'pnputil.delete-driver' `
            -Tool 'pnputil.exe' `
            -Arguments @('/delete-driver', $PublishedName, '/uninstall', '/force') `
            -Target $PublishedName `
            -Verb '用 pnputil 卸载 driver package / Uninstall driver package with pnputil' `
            -NonFatal)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($ResolvedInfPath)) {
        Add-DriverWarning '已知 INF 路径，但 pnputil 卸载需要发布后的 oem*.inf 名称。下一步：运行 pnputil /enum-drivers 查到名称后传 -PublishedName，或仅用 sc.exe fallback 移除 service。 / PublishedName is required for pnputil uninstall.'
    }

    [void](Add-CommandStep `
        -Name 'sc.delete' `
        -Tool 'sc.exe' `
        -Arguments @('delete', $ServiceName) `
        -Target $ServiceName `
        -Verb '删除 driver service / Delete driver service' `
        -SuccessExitCodes @(0, 1060))
}

function New-DriverHints {
    param(
        [Parameter(Mandatory)]$Status,
        [Parameter(Mandatory)][AllowEmptyString()][string]$ResolvedInfPath,
        [Parameter(Mandatory)][string]$EffectiveDriverKind
    )

    $hints = [System.Collections.Generic.List[string]]::new()

    foreach ($warning in $script:Warnings) {
        if (-not $hints.Contains($warning)) {
            [void]$hints.Add($warning)
        }
    }

    if ($Status.DriverFile.Exists -and $Status.DriverFile.Signature.Status -ne 'Valid') {
        [void]$hints.Add('下一步：Driver Authenticode 状态不是 Valid。请在一次性 VM 中运行 scripts\Sign-SandboxDriverWithTestCertificate.ps1 测试签名，把公钥证书信任到 Root 和 TrustedPublisher，并且不要使用 CSignTool。 / Driver signature is not Valid.')
    }

    if ($Status.TestSigning.Enabled -eq $false -and -not $SkipTestSigningCheck) {
        [void]$hints.Add('下一步：Windows test-signing 关闭。请在管理员 PowerShell 运行 bcdedit /set testsigning on 并重启，再加载测试签名 driver。 / Windows test-signing is off.')
    }

    if ($null -eq $Status.TestSigning.Enabled -and -not $SkipTestSigningCheck) {
        [void]$hints.Add('下一步：无法确认 Windows test-signing。请先检查 bcdedit /enum 输出，再加载测试签名 driver。 / Could not confirm test-signing.')
    }

    if ([string]::IsNullOrWhiteSpace($ResolvedInfPath)) {
        [void]$hints.Add('下一步：未自动发现 INF，脚本会用 sc.exe fallback；验证 minifilter 包装时请使用 INF/pnputil 路径。 / No INF auto-detected.')
    }

    if ($EffectiveDriverKind -eq 'MiniFilter') {
        [void]$hints.Add('下一步：MiniFilter 加载/卸载使用 fltmc。若 fltmc load 失败，请检查 service Type=FILE_SYSTEM_DRIVER、Instances 注册表键、altitude、签名信任和 test mode。 / MiniFilter uses fltmc.')
    }

    [void]$hints.Add('安全提示：CSignToolUsed=false；此流程禁止调用 .cert\CSignTool.exe 或 scripts\Sign-SandboxDriverWithKswordCSignTool.ps1。 / This workflow must never call CSignTool.')

    return @($hints | Select-Object -Unique)
}


function ConvertTo-DriverUserMessage {
    param([AllowNull()][string]$Message)

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return '错误：驱动管理操作失败，但没有返回详细错误。下一步：查看 Steps/Output/Hints 字段后重试。'
    }

    if ($Message -match '^(错误|下一步|安全提示)[:：]') {
        return $Message
    }

    return "错误：驱动管理操作失败。下一步：查看 JSON 的 Hints、Steps.Output 和管理员/test-signing 状态后重试。英文详情：$Message"
}

$repositoryRoot = Get-RepositoryRoot
$resolvedDriverPath = Resolve-OptionalPath -Path $DriverPath
if ([string]::IsNullOrWhiteSpace($resolvedDriverPath)) {
    $resolvedDriverPath = Find-DefaultDriverPath -RepositoryRoot $repositoryRoot
}

$resolvedInfPath = Resolve-OptionalPath -Path $InfPath
if ([string]::IsNullOrWhiteSpace($resolvedInfPath)) {
    $resolvedInfPath = Find-DefaultInfPath -RepositoryRoot $repositoryRoot -ResolvedDriverPath $resolvedDriverPath
}

$effectiveDriverKind = if ($DriverKind -eq 'Auto') {
    if (-not [string]::IsNullOrWhiteSpace($resolvedInfPath)) { 'MiniFilter' } else { 'MiniFilter' }
}
else {
    $DriverKind
}

$before = Get-CurrentStatus -ResolvedDriverPath $resolvedDriverPath -ResolvedInfPath $resolvedInfPath -EffectiveDriverKind $effectiveDriverKind
$result = [ordered]@{
    Kind = 'KSwordSandbox.DriverServiceOperation'
    Action = $Action
    ServiceName = $ServiceName
    RepositoryRoot = $repositoryRoot
    DriverPath = if ([string]::IsNullOrWhiteSpace($resolvedDriverPath)) { $null } else { $resolvedDriverPath }
    InfPath = if ([string]::IsNullOrWhiteSpace($resolvedInfPath)) { $null } else { $resolvedInfPath }
    DriverKind = $effectiveDriverKind
    StartType = $StartType
    MiniFilterAltitude = if ($effectiveDriverKind -eq 'MiniFilter') { $MiniFilterAltitude } else { $null }
    IsAdministrator = Test-IsAdministrator
    WhatIf = [bool]$WhatIfPreference
    CSignToolUsed = $false
    SkipTestSigningCheck = [bool]$SkipTestSigningCheck
    RequiresReboot = ($before.TestSigning.Enabled -eq $false -and -not $SkipTestSigningCheck)
    Before = $before
    Steps = @()
    After = $null
    Success = $false
    Error = $null
    Hints = @()
}

try {
    if ($Action -ne 'Status') {
        Assert-MutatingPreconditions -ResolvedDriverPath $resolvedDriverPath -ResolvedInfPath $resolvedInfPath -Status $before
    }

    switch ($Action) {
        'Status' { }
        'Install' { Invoke-InstallAction -ResolvedDriverPath $resolvedDriverPath -ResolvedInfPath $resolvedInfPath -EffectiveDriverKind $effectiveDriverKind -BeforeStatus $before }
        'Start' { Invoke-StartAction -EffectiveDriverKind $effectiveDriverKind }
        'Stop' { Invoke-StopAction -EffectiveDriverKind $effectiveDriverKind }
        'Restart' {
            Invoke-StopAction -EffectiveDriverKind $effectiveDriverKind
            Invoke-StartAction -EffectiveDriverKind $effectiveDriverKind
        }
        'Uninstall' { Invoke-UninstallAction -ResolvedInfPath $resolvedInfPath -EffectiveDriverKind $effectiveDriverKind }
    }

    $result.Success = $true
}
catch {
    $result.Success = $false
    $result.Error = [pscustomobject][ordered]@{
        Message = ConvertTo-DriverUserMessage -Message $_.Exception.Message
        FullyQualifiedErrorId = $_.FullyQualifiedErrorId
    }
}
finally {
    $after = Get-CurrentStatus -ResolvedDriverPath $resolvedDriverPath -ResolvedInfPath $resolvedInfPath -EffectiveDriverKind $effectiveDriverKind
    $result.Steps = @($script:Steps)
    $result.After = $after
    $result.RequiresReboot = ($after.TestSigning.Enabled -eq $false -and -not $SkipTestSigningCheck)
    $result.Hints = New-DriverHints -Status $after -ResolvedInfPath $resolvedInfPath -EffectiveDriverKind $effectiveDriverKind

    $json = ([pscustomobject]$result | ConvertTo-Json -Depth $JsonDepth)
    Write-Output $json

    if (-not $result.Success -and -not $Force) {
        exit 1
    }
}
