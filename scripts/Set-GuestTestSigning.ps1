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

    [switch]$Force
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

    throw "Guest password environment variable '$Name' is not set in Process, User, or Machine scope. Run .\install.ps1 -Mode Install -PromptPassword or -GeneratePassword."
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
    throw 'Set-GuestTestSigning.ps1 must run from an elevated host PowerShell session for Hyper-V PowerShell Direct.'
}

if (-not (Get-Command Invoke-Command -ErrorAction SilentlyContinue)) {
    throw 'Invoke-Command is unavailable.'
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
            throw "bcdedit /set testsigning on failed with exit code $LASTEXITCODE. $($commandOutput -join ' ')"
        }
        $changed = $true
    }
    elseif ($RequestedMode -eq 'Disable' -and $beforeEnabled) {
        $commandOutput = @(& bcdedit.exe /set testsigning off 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "bcdedit /set testsigning off failed with exit code $LASTEXITCODE. $($commandOutput -join ' ')"
        }
        $changed = $true
    }

    if ($changed -and $ShouldRestart) {
        Restart-Computer -Force
    }

    [pscustomobject][ordered]@{
        ComputerName = $env:COMPUTERNAME
        RequestedMode = $RequestedMode
        TestSigningWasEnabled = $beforeEnabled
        Changed = $changed
        RestartRequested = $ShouldRestart
        CommandOutput = $commandOutput
    }
}

if (-not $Force -and $Mode -ne 'Query' -and $RestartGuest) {
    throw 'RestartGuest was requested. Pass -Force to make the reboot non-interactive and explicit.'
}

if ($PSCmdlet.ShouldProcess($VmName, "Run guest bcdedit test-signing mode '$Mode'")) {
    Invoke-Command -VMName $VmName -Credential $credential -ScriptBlock $scriptBlock -ArgumentList $Mode, ([bool]$RestartGuest)
}
