<#
.SYNOPSIS
Enables or disables Windows test-signing inside the configured Hyper-V guest VM.

.DESCRIPTION
Inputs are a VM name, guest user, and host environment secret containing the
guest password. Processing uses PowerShell Direct to run bcdedit inside the
guest. The script is non-interactive and never invokes driver-signing tools.

Use this only for isolated analysis VMs/checkpoints that need a test-signed R0
driver. A reboot is required after changing test-signing state.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$VmName = 'KSwordSandbox-Win10-Golden',

    [string]$GuestUserName = 'SandboxUser',

    [string]$SecretName = 'KSWORDBOX_GUEST_PASSWORD',

    [ValidateSet('Enable', 'Disable', 'Query')]
    [string]$Mode = 'Enable',

    [switch]$RestartGuest,

    [switch]$Force,

    [switch]$Json
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-GuestPasswordSecretValue {
    param([Parameter(Mandatory = $true)][string]$Name)

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    throw "错误：未在 Process/User/Machine 环境中找到 guest password secret '$Name'。下一步：普通用户请运行 .\install.ps1 -Mode Install -PromptPassword；如果使用 -GeneratePassword，请确保 VM 内密码也同步。"
}

function New-GuestCredential {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $securePassword = [System.Security.SecureString]::new()
    foreach ($passwordCharacter in $Password.ToCharArray()) {
        $securePassword.AppendChar($passwordCharacter)
    }
    $securePassword.MakeReadOnly()
    return [pscredential]::new($UserName, $securePassword)
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw '错误：Set-GuestTestSigning.ps1 需要在宿主机管理员 PowerShell 中运行，才能使用 Hyper-V PowerShell Direct。下一步：以管理员身份重新打开 PowerShell 后重试。'
}

if (-not (Get-Command Invoke-Command -ErrorAction SilentlyContinue)) {
    throw '错误：Invoke-Command 不可用。下一步：请确认当前是完整 PowerShell/Windows 环境，并启用了 Hyper-V/PowerShell Direct 所需组件。'
}

$password = Get-GuestPasswordSecretValue -Name $SecretName
$credential = New-GuestCredential -UserName $GuestUserName -Password $password

$scriptBlock = {
    param(
        [string]$RequestedMode,
        [bool]$ShouldRestart
    )

    $before = @(& bcdedit.exe /enum 2>&1)
    $beforeText = $before -join "`n"
    $beforeEnabled = $beforeText -match '(?im)^\s*testsigning\s+(Yes|On|True)\s*$'
    $changed = $false
    $commandOutput = @()

    if ($RequestedMode -eq 'Enable' -and -not $beforeEnabled) {
        $commandOutput = @(& bcdedit.exe /set testsigning on 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "错误：来宾内 bcdedit /set testsigning on 失败，退出码 $LASTEXITCODE。下一步：确认来宾系统允许修改启动配置，并以管理员上下文执行。英文输出：$($commandOutput -join ' ')"
        }
        $changed = $true
    }
    elseif ($RequestedMode -eq 'Disable' -and $beforeEnabled) {
        $commandOutput = @(& bcdedit.exe /set testsigning off 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "错误：来宾内 bcdedit /set testsigning off 失败，退出码 $LASTEXITCODE。下一步：确认来宾系统允许修改启动配置，并以管理员上下文执行。英文输出：$($commandOutput -join ' ')"
        }
        $changed = $true
    }

    if ($changed -and $ShouldRestart) {
        Restart-Computer -Force
    }

    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.GuestTestSigning'
        ComputerName = $env:COMPUTERNAME
        RequestedMode = $RequestedMode
        TestSigningWasEnabled = $beforeEnabled
        Changed = $changed
        RestartRequired = $changed
        RestartRequested = $ShouldRestart
        CommandOutput = $commandOutput
        CSignToolUsed = $false
    }
}

if (-not $Force -and $Mode -ne 'Query' -and $RestartGuest) {
    throw '错误：已请求 -RestartGuest，但未提供 -Force。下一步：确认允许来宾重启后，追加 -Force；只查询状态请使用 -Mode Query。'
}

$result = if ($PSCmdlet.ShouldProcess($VmName, "在来宾中运行 bcdedit test-signing 模式 '$Mode' / Run guest bcdedit test-signing mode")) {
    Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock $scriptBlock -ArgumentList $Mode, ([bool]$RestartGuest)
}
else {
    [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.GuestTestSigning'
        ComputerName = $null
        RequestedMode = $Mode
        TestSigningWasEnabled = $null
        Changed = $false
        RestartRequired = $false
        RestartRequested = [bool]$RestartGuest
        WhatIf = [bool]$WhatIfPreference
        CommandOutput = @()
        CSignToolUsed = $false
    }
}

if ($Json) {
    $result | ConvertTo-Json -Depth 8
}
else {
    $result
}
