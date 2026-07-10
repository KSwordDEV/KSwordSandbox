<#
.SYNOPSIS
Installs, changes, or uninstalls local KSwordSandbox operator settings.

.DESCRIPTION
The installer is intentionally local-only. It prepares runtime folders and
stores the guest credential secret outside git so Hyper-V live scripts can read
KSWORDBOX_GUEST_PASSWORD without embedding passwords in config files.

Default mode is interactive:

  .\install.ps1

Automation examples:

  .\install.ps1 -Mode Install -GeneratePassword
  .\install.ps1 -Mode Change -ResetPassword -PromptPassword
  .\install.ps1 -Mode Uninstall

The script never prints the password value. By default it writes the configured
secret to the current user's environment and mirrors it into the current process
so commands launched from this PowerShell session can run immediately.
#>
[CmdletBinding()]
param(
    [ValidateSet('Interactive', 'Install', 'Change', 'Uninstall', 'Status')]
    [string]$Mode = 'Interactive',

    [string]$GuestUserName = 'SandboxUser',

    [string]$SecretName = 'KSWORDBOX_GUEST_PASSWORD',

    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox',

    [string]$GuestPayloadRoot = 'D:\Temp\KSwordSandbox\payload\guest-tools',

    [switch]$GeneratePassword,

    [switch]$PromptPassword,

    [switch]$ResetPassword,

    [switch]$CurrentProcessOnly,

    [switch]$SkipDpapiBackup,

    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:InstallStateDirectory = Join-Path $env:ProgramData 'KSwordSandbox'
$script:InstallStatePath = Join-Path $script:InstallStateDirectory 'install-state.json'
$script:SecretBackupPath = Join-Path $script:InstallStateDirectory 'guest-password.dpapi'

function Write-InstallInfo {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[install] $Message"
}

function Read-MenuChoice {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string[]]$Allowed
    )

    do {
        $choice = (Read-Host $Prompt).Trim()
    } while ($Allowed -notcontains $choice)

    return $choice
}

function New-RandomPassword {
    param([int]$Length = 24)

    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-+='
    $bytes = [byte[]]::new($Length)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        if ($null -ne $rng) {
            $rng.Dispose()
        }
    }
    $chars = for ($index = 0; $index -lt $Length; $index++) {
        $alphabet[$bytes[$index] % $alphabet.Length]
    }

    return -join $chars
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory)][securestring]$SecureString)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Read-GuestPassword {
    param(
        [bool]$UseGenerated,
        [bool]$UsePrompt,
        [string]$ExistingSecretName
    )

    if ($UseGenerated) {
        return [pscustomobject]@{
            Password = New-RandomPassword
            Source = 'generated'
        }
    }

    if ($UsePrompt) {
        $secure = Read-Host "Enter guest password for $ExistingSecretName" -AsSecureString
        return [pscustomobject]@{
            Password = ConvertFrom-SecureStringToPlainText -SecureString $secure
            Source = 'prompt'
        }
    }

    if ($Mode -ne 'Interactive') {
        throw 'Non-interactive install/change requires -GeneratePassword or -PromptPassword when setting/resetting the password.'
    }

    Write-Host ''
    Write-Host 'Guest password option:'
    Write-Host '  1) Generate a new random password and store it locally'
    Write-Host '  2) Type the existing VM SandboxUser password'
    $choice = Read-MenuChoice -Prompt 'Choose [1-2]' -Allowed @('1', '2')
    if ($choice -eq '1') {
        return [pscustomobject]@{
            Password = New-RandomPassword
            Source = 'generated'
        }
    }

    $secure = Read-Host "Enter guest password for $ExistingSecretName" -AsSecureString
    return [pscustomobject]@{
        Password = ConvertFrom-SecureStringToPlainText -SecureString $secure
        Source = 'prompt'
    }
}

function Save-DpapiSecretBackup {
    param(
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Path
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $secure | ConvertFrom-SecureString | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Save-InstallState {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$GuestUser,
        [Parameter(Mandatory)][string]$Secret,
        [Parameter(Mandatory)][string]$Runtime,
        [Parameter(Mandatory)][string]$PayloadRoot,
        [Parameter(Mandatory)][string]$PasswordSource,
        [bool]$PersistedToUser,
        [bool]$PersistedToProcess,
        [bool]$DpapiBackup
    )

    New-Item -ItemType Directory -Path $script:InstallStateDirectory -Force | Out-Null
    $state = [ordered]@{
        installStateVersion = 1
        action = $Action
        updatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        guestUserName = $GuestUser
        secretName = $Secret
        runtimeRoot = $Runtime
        guestPayloadRoot = $PayloadRoot
        passwordSource = $PasswordSource
        persistedToUserEnvironment = $PersistedToUser
        persistedToCurrentProcess = $PersistedToProcess
        dpapiBackupPath = if ($DpapiBackup) { $script:SecretBackupPath } else { $null }
        secretValuePrinted = $false
    }

    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:InstallStatePath -Encoding UTF8
}

function Set-GuestPasswordSecret {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Password,
        [string]$PasswordSource = 'unknown'
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw 'Secret name must not be empty.'
    }

    if ([string]::IsNullOrEmpty($Password)) {
        throw 'Guest password must not be empty.'
    }

    [Environment]::SetEnvironmentVariable($Name, $Password, 'Process')
    $persistedUser = $false
    if (-not $CurrentProcessOnly) {
        [Environment]::SetEnvironmentVariable($Name, $Password, 'User')
        $persistedUser = $true
    }

    $dpapiBackup = $false
    if (-not $SkipDpapiBackup) {
        Save-DpapiSecretBackup -Password $Password -Path $script:SecretBackupPath
        $dpapiBackup = $true
    }

    Save-InstallState `
        -Action 'credential-set' `
        -GuestUser $GuestUserName `
        -Secret $Name `
        -Runtime $RuntimeRoot `
        -PayloadRoot $GuestPayloadRoot `
        -PasswordSource $PasswordSource `
        -PersistedToUser $persistedUser `
        -PersistedToProcess $true `
        -DpapiBackup $dpapiBackup

    Write-InstallInfo "Guest password secret '$Name' stored. Value was not printed."
    if ($persistedUser) {
        Write-InstallInfo 'Stored in current User environment; new shells/Codex sessions can inherit it.'
    }
    else {
        Write-InstallInfo 'Stored only in the current PowerShell process.'
    }

    if ($dpapiBackup) {
        Write-InstallInfo "DPAPI backup written for this Windows account: $script:SecretBackupPath"
    }
}

function Install-KSwordSandboxLocal {
    param([bool]$SetPassword)

    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'jobs') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'plans') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'uploads') -Force | Out-Null
    New-Item -ItemType Directory -Path $GuestPayloadRoot -Force | Out-Null

    Write-InstallInfo "Runtime root ready: $RuntimeRoot"
    Write-InstallInfo "Guest payload root ready: $GuestPayloadRoot"

    if ($SetPassword) {
        $credential = Read-GuestPassword -UseGenerated ([bool]$GeneratePassword) -UsePrompt ([bool]$PromptPassword) -ExistingSecretName $SecretName
        Set-GuestPasswordSecret -Name $SecretName -Password $credential.Password -PasswordSource $credential.Source
    }
    else {
        Save-InstallState `
            -Action 'install-no-credential-change' `
            -GuestUser $GuestUserName `
            -Secret $SecretName `
            -Runtime $RuntimeRoot `
            -PayloadRoot $GuestPayloadRoot `
            -PasswordSource 'unchanged' `
            -PersistedToUser (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'User'))) `
            -PersistedToProcess (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'Process'))) `
            -DpapiBackup (Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf)
    }
}

function Reset-GuestPasswordSecret {
    $credential = Read-GuestPassword -UseGenerated ([bool]$GeneratePassword) -UsePrompt ([bool]$PromptPassword) -ExistingSecretName $SecretName
    Set-GuestPasswordSecret -Name $SecretName -Password $credential.Password -PasswordSource "reset-$($credential.Source)"
    Write-InstallInfo 'Password secret reset locally. If you generated a new password, make sure the VM SandboxUser account is changed to the same value before live Hyper-V runs.'
}

function Set-GuestUserNameState {
    param([string]$NewGuestUserName)

    if ([string]::IsNullOrWhiteSpace($NewGuestUserName)) {
        throw 'Guest user name must not be empty.'
    }

    Save-InstallState `
        -Action 'guest-user-changed' `
        -GuestUser $NewGuestUserName `
        -Secret $SecretName `
        -Runtime $RuntimeRoot `
        -PayloadRoot $GuestPayloadRoot `
        -PasswordSource 'unchanged' `
        -PersistedToUser (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'User'))) `
        -PersistedToProcess (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'Process'))) `
        -DpapiBackup (Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf)

    Write-InstallInfo "Recorded guest user name in install state: $NewGuestUserName"
    Write-InstallInfo 'If you need scripts to use a non-default guest user, also pass -GuestUserName or update the local sandbox config.'
}

function Show-KSwordSandboxInstallStatus {
    $processValue = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    $userValue = [Environment]::GetEnvironmentVariable($SecretName, 'User')
    $machineValue = [Environment]::GetEnvironmentVariable($SecretName, 'Machine')

    [pscustomobject][ordered]@{
        SecretName = $SecretName
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace($processValue)
        UserSecretSet = -not [string]::IsNullOrWhiteSpace($userValue)
        MachineSecretSet = -not [string]::IsNullOrWhiteSpace($machineValue)
        RuntimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot)
        RuntimeRootExists = Test-Path -LiteralPath $RuntimeRoot -PathType Container
        GuestPayloadRoot = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
        GuestPayloadRootExists = Test-Path -LiteralPath $GuestPayloadRoot -PathType Container
        InstallStatePath = $script:InstallStatePath
        InstallStateExists = Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf
        DpapiBackupPath = $script:SecretBackupPath
        DpapiBackupExists = Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf
        SecretValuePrinted = $false
    }
}

function Uninstall-KSwordSandboxLocal {
    if (-not $Force -and $Mode -eq 'Interactive') {
        Write-Host ''
        Write-Host "This removes local credential metadata for '$SecretName'. Runtime job outputs under '$RuntimeRoot' are not deleted."
        $choice = Read-MenuChoice -Prompt 'Continue uninstall? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        if ($choice -in @('n', 'N')) {
            Write-InstallInfo 'Uninstall cancelled.'
            return
        }
    }

    [Environment]::SetEnvironmentVariable($SecretName, $null, 'Process')
    [Environment]::SetEnvironmentVariable($SecretName, $null, 'User')
    Remove-Item -LiteralPath $script:SecretBackupPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:InstallStatePath -Force -ErrorAction SilentlyContinue
    Write-InstallInfo "Removed current process/User environment secret '$SecretName' and local DPAPI backup if present."
    Write-InstallInfo 'Runtime output folders were left intact.'
}

function Invoke-ChangeMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Change options:'
        Write-Host '  1) Reset password secret'
        Write-Host '  2) Change recorded guest username'
        Write-Host '  3) Recreate runtime folders'
        Write-Host '  4) Show status'
        Write-Host '  5) Back'
        $choice = Read-MenuChoice -Prompt 'Choose [1-5]' -Allowed @('1', '2', '3', '4', '5')
        switch ($choice) {
            '1' { Reset-GuestPasswordSecret }
            '2' {
                $name = Read-Host 'Guest username'
                Set-GuestUserNameState -NewGuestUserName $name
            }
            '3' { Install-KSwordSandboxLocal -SetPassword:$false }
            '4' { Show-KSwordSandboxInstallStatus | Format-List }
            '5' { return }
        }
    }
}

function Invoke-InteractiveInstaller {
    while ($true) {
        Write-Host ''
        Write-Host 'KSwordSandbox local installer'
        Write-Host '  1) Install / prepare local settings'
        Write-Host '  2) Change settings'
        Write-Host '  3) Uninstall local settings'
        Write-Host '  4) Status'
        Write-Host '  5) Exit'
        $choice = Read-MenuChoice -Prompt 'Choose [1-5]' -Allowed @('1', '2', '3', '4', '5')
        switch ($choice) {
            '1' {
                Write-Host ''
                Write-Host 'Install password handling:'
                Write-Host '  1) Set/reset password now'
                Write-Host '  2) Prepare folders only'
                $installChoice = Read-MenuChoice -Prompt 'Choose [1-2]' -Allowed @('1', '2')
                Install-KSwordSandboxLocal -SetPassword:($installChoice -eq '1')
            }
            '2' { Invoke-ChangeMenu }
            '3' { Uninstall-KSwordSandboxLocal }
            '4' { Show-KSwordSandboxInstallStatus | Format-List }
            '5' { return }
        }
    }
}

switch ($Mode) {
    'Interactive' {
        Invoke-InteractiveInstaller
    }
    'Install' {
        $shouldSetPassword = [bool]$GeneratePassword -or [bool]$PromptPassword -or [bool]$ResetPassword
        Install-KSwordSandboxLocal -SetPassword:$shouldSetPassword
    }
    'Change' {
        if ($ResetPassword -or $GeneratePassword -or $PromptPassword) {
            Reset-GuestPasswordSecret
        }
        else {
            Invoke-ChangeMenu
        }
    }
    'Uninstall' {
        Uninstall-KSwordSandboxLocal
    }
    'Status' {
        Show-KSwordSandboxInstallStatus | Format-List
    }
}
