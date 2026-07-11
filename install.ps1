<#
.SYNOPSIS
Installs, changes, or uninstalls local KSwordSandbox operator settings.

.DESCRIPTION
The installer is intentionally local-only. It prepares runtime folders and
stores the guest credential secret outside git so Hyper-V live scripts can read
KSWORDBOX_GUEST_PASSWORD without embedding passwords in config files.
It can also record the optional VirusTotal API key in the current user's
environment so the WebUI can perform hash-only lookups without committing a key.

Default mode is interactive:

  .\install.ps1

Automation examples:

  .\install.ps1 -Mode Install -GeneratePassword
  .\install.ps1 -Mode Change -ResetPassword -PromptPassword
  .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName KSwordSandbox-Win10-Golden -CheckpointName Clean
  .\install.ps1 -Mode ConfigureVTKey -PromptVTKey
  .\install.ps1 -Mode CheckEnvironment
  .\install.ps1 -Mode StartWebUI
  .\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
  .\install.ps1 -Mode Change -EnableGuestTestSigning -Force
  .\install.ps1 -Mode Uninstall

The script never prints the password value. By default it writes the configured
secret to the current user's environment and mirrors it into the current process
so commands launched from this PowerShell session can run immediately.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Interactive', 'Install', 'Change', 'Uninstall', 'Status', 'CheckEnvironment', 'ConfigureVTKey', 'StartWebUI')]
    [string]$Mode = 'Interactive',

    [string]$GuestUserName = 'SandboxUser',

    [string]$SecretName = 'KSWORDBOX_GUEST_PASSWORD',

    [string]$VirusTotalSecretName = 'KSWORDBOX_VIRUSTOTAL_API_KEY',

    [string]$RuntimeRoot = 'D:\Temp\KSwordSandbox',

    [string]$GuestPayloadRoot = 'D:\Temp\KSwordSandbox\payload\guest-tools',

    [string]$VmName = 'KSwordSandbox-Win10-Golden',

    [string]$CheckpointName = 'Clean',

    [string]$GuestWorkingDirectory = 'C:\KSwordSandbox',

    [string]$LocalConfigPath = '',

    [string]$VirusTotalSettingsPath = '',

    [string]$WebUiUrl = 'http://127.0.0.1:18080',

    [switch]$GeneratePassword,

    [switch]$PromptPassword,

    [switch]$ResetPassword,

    [switch]$ResetGuestVmPassword,

    [switch]$UpdateHyperVConfig,

    [switch]$ConfigureVTKey,

    [switch]$PromptVTKey,

    [switch]$ClearVTKey,

    [switch]$CheckEnvironment,

    [switch]$StartWebUI,

    [switch]$RunHyperVReadiness,

    [switch]$EnableGuestTestSigning,

    [switch]$DisableGuestTestSigning,

    [switch]$QueryGuestTestSigning,

    [switch]$RestartGuestAfterTestSigning,

    [switch]$CurrentProcessOnly,

    [switch]$SkipDpapiBackup,

    [switch]$SkipWebConfigEnvironment,

    [switch]$SkipCheckpointRefresh,

    [switch]$SkipCheckpointRestore,

    [int]$BootTimeoutSeconds = 240,

    [int]$PowerShellDirectTimeoutSeconds = 240,

    [switch]$OpenBrowser,

    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:InstallStateDirectory = Join-Path $env:ProgramData 'KSwordSandbox'
$script:InstallStatePath = Join-Path $script:InstallStateDirectory 'install-state.json'
$script:SecretBackupPath = Join-Path $script:InstallStateDirectory 'guest-password.dpapi'
$script:WebConfigPathEnvironmentName = 'Sandbox__ConfigPath'

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

function Read-InstallState {
    if (-not (Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf)) {
        return $null
    }

    try {
        return Get-Content -LiteralPath $script:InstallStatePath -Raw | ConvertFrom-Json
    }
    catch {
        Write-InstallInfo "Ignoring unreadable install state '$script:InstallStatePath': $($_.Exception.Message)"
        return $null
    }
}

function Get-StateString {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][string]$DefaultValue
    )

    if ($null -ne $State) {
        $property = $State.PSObject.Properties[$Name]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            return [string]$property.Value
        }
    }

    return $DefaultValue
}

function Initialize-EffectiveParameters {
    param(
        [AllowNull()]$State,
        [Parameter(Mandatory)][System.Collections.IDictionary]$BoundParameters
    )

    $bindings = @{
        GuestUserName = 'guestUserName'
        SecretName = 'secretName'
        VirusTotalSecretName = 'virusTotalSecretName'
        RuntimeRoot = 'runtimeRoot'
        GuestPayloadRoot = 'guestPayloadRoot'
        VmName = 'vmName'
        CheckpointName = 'checkpointName'
        GuestWorkingDirectory = 'guestWorkingDirectory'
        LocalConfigPath = 'localConfigPath'
    }

    foreach ($entry in $bindings.GetEnumerator()) {
        if ($BoundParameters.ContainsKey($entry.Key)) {
            continue
        }

        $current = (Get-Variable -Name $entry.Key -Scope Script -ValueOnly)
        $value = Get-StateString -State $State -Name $entry.Value -DefaultValue $current
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            Set-Variable -Name $entry.Key -Value $value -Scope Script
        }
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write DPAPI-protected guest password backup')) {
        Write-InstallInfo "WhatIf: DPAPI backup would be written for this Windows account: $Path"
        return
    }

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $secure | ConvertFrom-SecureString | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Get-LocalSandboxConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($LocalConfigPath)) {
        return [System.IO.Path]::GetFullPath($LocalConfigPath)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RuntimeRoot 'config\sandbox.local.json'))
}

function Write-LocalSandboxConfig {
    $targetPath = Get-LocalSandboxConfigPath
    $templatePath = Join-Path $PSScriptRoot 'config\sandbox.example.json'
    if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
        throw "Sandbox config template is missing: $templatePath"
    }

    $config = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
    $config.hyperV.goldenVmName = $VmName
    $config.hyperV.goldenSnapshotName = $CheckpointName
    $config.guest.userName = $GuestUserName
    $config.guest.passwordSecretName = $SecretName
    $config.guest.workingDirectory = $GuestWorkingDirectory
    $config.paths.runtimeRoot = $RuntimeRoot
    $config.paths.guestPayloadRoot = $GuestPayloadRoot

    $driverEventsFileName = Split-Path -Leaf $config.driver.eventJsonLinesPath
    $r0CollectorFileName = Split-Path -Leaf $config.driver.r0CollectorPathInGuest
    $driverFileName = Split-Path -Leaf $config.driver.driverPathInGuest
    if (-not [string]::IsNullOrWhiteSpace($driverEventsFileName)) {
        $config.driver.eventJsonLinesPath = Join-Path (Join-Path $GuestWorkingDirectory 'out') $driverEventsFileName
    }
    if (-not [string]::IsNullOrWhiteSpace($r0CollectorFileName)) {
        $config.driver.r0CollectorPathInGuest = Join-Path (Join-Path $GuestWorkingDirectory 'r0collector') $r0CollectorFileName
    }
    if (-not [string]::IsNullOrWhiteSpace($driverFileName)) {
        $config.driver.driverPathInGuest = Join-Path (Join-Path $GuestWorkingDirectory 'driver') $driverFileName
    }

    if ($PSCmdlet.ShouldProcess($targetPath, 'Write local sandbox config')) {
        $parent = Split-Path -Parent $targetPath
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }

        $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $targetPath -Encoding UTF8
        Write-InstallInfo "Local sandbox config written: $targetPath"
    }
    else {
        Write-InstallInfo "WhatIf: local sandbox config would be written: $targetPath"
    }

    return $targetPath
}

function Set-WebConfigPathEnvironment {
    param([Parameter(Mandatory)][string]$ConfigPath)

    if ($SkipWebConfigEnvironment) {
        Write-InstallInfo "Skipped '$script:WebConfigPathEnvironmentName' environment update."
        return
    }

    if (-not $PSCmdlet.ShouldProcess($script:WebConfigPathEnvironmentName, "Set Web/API config path environment variable to '$ConfigPath'")) {
        Write-InstallInfo "WhatIf: '$script:WebConfigPathEnvironmentName' would point at '$ConfigPath'."
        return
    }

    [Environment]::SetEnvironmentVariable($script:WebConfigPathEnvironmentName, $ConfigPath, 'Process')
    if (-not $CurrentProcessOnly) {
        [Environment]::SetEnvironmentVariable($script:WebConfigPathEnvironmentName, $ConfigPath, 'User')
        Write-InstallInfo "Set User environment '$script:WebConfigPathEnvironmentName' to the local sandbox config."
    }
    else {
        Write-InstallInfo "Set current process '$script:WebConfigPathEnvironmentName' to the local sandbox config."
    }
}

function Read-VirusTotalApiKey {
    if ($ClearVTKey) {
        return ''
    }

    if (-not $PromptVTKey -and $Mode -notin @('Interactive', 'ConfigureVTKey') -and -not $ConfigureVTKey) {
        throw 'Non-interactive VirusTotal key configuration requires -PromptVTKey or -ClearVTKey.'
    }

    $secure = Read-Host "Enter optional VirusTotal API key for $VirusTotalSecretName" -AsSecureString
    return ConvertFrom-SecureStringToPlainText -SecureString $secure
}

function Set-VirusTotalApiKeySecret {
    param([AllowNull()][string]$ApiKey)

    if ([string]::IsNullOrWhiteSpace($VirusTotalSecretName)) {
        throw 'VirusTotal secret environment variable name must not be empty.'
    }

    if ($ClearVTKey) {
        if (-not $PSCmdlet.ShouldProcess($VirusTotalSecretName, 'Clear optional VirusTotal API key from process/User environment')) {
            Write-InstallInfo "WhatIf: optional VirusTotal API key '$VirusTotalSecretName' would be cleared from process/User environment."
            return
        }

        [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $null, 'Process')
        [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $null, 'User')
        Write-InstallInfo "Optional VirusTotal API key '$VirusTotalSecretName' cleared from process/User environment."
        return
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        throw 'VirusTotal API key must not be empty. Use -ClearVTKey to remove the local setting.'
    }

    if (-not $PSCmdlet.ShouldProcess($VirusTotalSecretName, 'Store optional VirusTotal API key in local environment without printing it')) {
        Write-InstallInfo "WhatIf: optional VirusTotal API key '$VirusTotalSecretName' would be stored locally. Value was not printed."
        return
    }

    $trimmed = $ApiKey.Trim()
    [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $trimmed, 'Process')
    if (-not $CurrentProcessOnly) {
        [Environment]::SetEnvironmentVariable($VirusTotalSecretName, $trimmed, 'User')
        Write-InstallInfo "Optional VirusTotal API key '$VirusTotalSecretName' stored in current User environment. Value was not printed."
    }
    else {
        Write-InstallInfo "Optional VirusTotal API key '$VirusTotalSecretName' stored only in current process. Value was not printed."
    }
}

function Invoke-VirusTotalKeyConfiguration {
    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($VirusTotalSecretName, 'Configure optional VirusTotal API key')
        Write-InstallInfo "WhatIf: optional VirusTotal API key '$VirusTotalSecretName' would be configured or cleared. Value was not printed."
        return
    }

    $effectiveClear = [bool]$ClearVTKey
    if ($Mode -eq 'Interactive' -and -not $PromptVTKey -and -not $ClearVTKey) {
        Write-Host ''
        Write-Host 'VirusTotal API key option:'
        Write-Host '  1) Prompt and store optional key in the local environment'
        Write-Host '  2) Clear local key from process/User environment'
        Write-Host '  3) Back'
        $choice = Read-MenuChoice -Prompt 'Choose [1-3]' -Allowed @('1', '2', '3')
        if ($choice -eq '3') {
            Write-InstallInfo 'VirusTotal key configuration cancelled.'
            return
        }

        $effectiveClear = ($choice -eq '2')
        $script:ClearVTKey = $effectiveClear
    }

    if ($effectiveClear) {
        Set-VirusTotalApiKeySecret -ApiKey ''
        return
    }

    $apiKey = Read-VirusTotalApiKey
    Set-VirusTotalApiKeySecret -ApiKey $apiKey
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
        [bool]$DpapiBackup,
        [string]$Vm = $VmName,
        [string]$Checkpoint = $CheckpointName,
        [string]$GuestWorking = $GuestWorkingDirectory,
        [string]$LocalConfig = ''
    )

    if ([string]::IsNullOrWhiteSpace($LocalConfig)) {
        $LocalConfig = Get-LocalSandboxConfigPath
    }

    $state = [ordered]@{
        installStateVersion = 2
        action = $Action
        updatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        guestUserName = $GuestUser
        secretName = $Secret
        virusTotalSecretName = $VirusTotalSecretName
        runtimeRoot = $Runtime
        guestPayloadRoot = $PayloadRoot
        passwordSource = $PasswordSource
        persistedToUserEnvironment = $PersistedToUser
        persistedToCurrentProcess = $PersistedToProcess
        dpapiBackupPath = if ($DpapiBackup) { $script:SecretBackupPath } else { $null }
        vmName = $Vm
        checkpointName = $Checkpoint
        guestWorkingDirectory = $GuestWorking
        localConfigPath = $LocalConfig
        webConfigPathEnvironmentName = $script:WebConfigPathEnvironmentName
        secretValuePrinted = $false
    }

    if (-not $PSCmdlet.ShouldProcess($script:InstallStatePath, "Write install state for action '$Action'")) {
        Write-InstallInfo "WhatIf: install state would be written: $script:InstallStatePath"
        return
    }

    New-Item -ItemType Directory -Path $script:InstallStateDirectory -Force | Out-Null
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

    if (-not $PSCmdlet.ShouldProcess($Name, "Store guest password secret from source '$PasswordSource'")) {
        Write-InstallInfo "WhatIf: guest password secret '$Name' would be stored locally. Value was not printed."
        return
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

function Initialize-KSwordSandboxRuntimeFolders {
    $directories = @(
        $RuntimeRoot,
        (Join-Path $RuntimeRoot 'jobs'),
        (Join-Path $RuntimeRoot 'plans'),
        (Join-Path $RuntimeRoot 'uploads'),
        (Join-Path $RuntimeRoot 'config'),
        $GuestPayloadRoot
    )

    foreach ($directory in $directories) {
        if ($PSCmdlet.ShouldProcess($directory, 'Create or verify local runtime directory')) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }
}

function Set-HyperVConfigState {
    param([string]$Action = 'hyperv-config-updated')

    if ([string]::IsNullOrWhiteSpace($VmName)) {
        throw 'Hyper-V VM name must not be empty.'
    }
    if ([string]::IsNullOrWhiteSpace($CheckpointName)) {
        throw 'Hyper-V checkpoint name must not be empty.'
    }
    if ([string]::IsNullOrWhiteSpace($GuestWorkingDirectory)) {
        throw 'Guest working directory must not be empty.'
    }

    Initialize-KSwordSandboxRuntimeFolders
    $configPath = Write-LocalSandboxConfig
    Set-WebConfigPathEnvironment -ConfigPath $configPath

    Save-InstallState `
        -Action $Action `
        -GuestUser $GuestUserName `
        -Secret $SecretName `
        -Runtime $RuntimeRoot `
        -PayloadRoot $GuestPayloadRoot `
        -PasswordSource 'unchanged' `
        -PersistedToUser (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'User'))) `
        -PersistedToProcess (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($SecretName, 'Process'))) `
        -DpapiBackup (Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf) `
        -LocalConfig $configPath

    Write-InstallInfo "Hyper-V VM config recorded: VM='$VmName', checkpoint='$CheckpointName', guestRoot='$GuestWorkingDirectory'."
    Write-InstallInfo "Web/API can use it via '$script:WebConfigPathEnvironmentName=$configPath'."
}

function Install-KSwordSandboxLocal {
    param([bool]$SetPassword)

    Initialize-KSwordSandboxRuntimeFolders

    Write-InstallInfo "Runtime root ready: $RuntimeRoot"
    Write-InstallInfo "Guest payload root ready: $GuestPayloadRoot"
    $configPath = Write-LocalSandboxConfig
    Set-WebConfigPathEnvironment -ConfigPath $configPath

    if ($SetPassword) {
        if ($WhatIfPreference) {
            [void]$PSCmdlet.ShouldProcess($SecretName, 'Store guest password secret')
            Write-InstallInfo "WhatIf: guest password secret '$SecretName' would be set without printing the value."
            return
        }

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
            -DpapiBackup (Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf) `
            -LocalConfig $configPath
    }
}

function Reset-GuestPasswordSecret {
    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($SecretName, 'Reset host-side guest password secret')
        Write-InstallInfo "WhatIf: host-side guest password secret '$SecretName' would be reset locally. Value was not printed."
        return
    }

    $credential = Read-GuestPassword -UseGenerated ([bool]$GeneratePassword) -UsePrompt ([bool]$PromptPassword) -ExistingSecretName $SecretName
    Set-GuestPasswordSecret -Name $SecretName -Password $credential.Password -PasswordSource "reset-$($credential.Source)"
    Write-InstallInfo 'Password secret reset locally. If you generated a new password, make sure the VM SandboxUser account is changed to the same value before live Hyper-V runs.'
}

function Read-OptionalText {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [AllowNull()][string]$CurrentValue
    )

    $answer = Read-Host "$Prompt [$CurrentValue]"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $CurrentValue
    }

    return $answer.Trim()
}

function Invoke-HyperVConfigPrompt {
    $script:VmName = Read-OptionalText -Prompt 'Hyper-V golden VM name' -CurrentValue $VmName
    $script:CheckpointName = Read-OptionalText -Prompt 'Clean checkpoint name' -CurrentValue $CheckpointName
    $script:GuestUserName = Read-OptionalText -Prompt 'Guest username' -CurrentValue $GuestUserName
    $script:GuestWorkingDirectory = Read-OptionalText -Prompt 'Guest working directory' -CurrentValue $GuestWorkingDirectory
    $script:RuntimeRoot = Read-OptionalText -Prompt 'Host runtime root' -CurrentValue $RuntimeRoot
    $script:GuestPayloadRoot = Read-OptionalText -Prompt 'Host guest payload root' -CurrentValue $GuestPayloadRoot
    $script:LocalConfigPath = Read-OptionalText -Prompt 'Local sandbox config path' -CurrentValue (Get-LocalSandboxConfigPath)
    Set-HyperVConfigState
}

function Invoke-GuestVmPasswordReset {
    $resetScript = Join-Path $PSScriptRoot 'scripts\Reset-SandboxGuestPassword.ps1'
    if (-not (Test-Path -LiteralPath $resetScript -PathType Leaf)) {
        throw "Guest VM password reset script is missing: $resetScript"
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($VmName, "Reset actual VM guest password for '$GuestUserName'")
        Write-InstallInfo "WhatIf: actual VM guest password reset would be delegated to '$resetScript'. No checkpoint restore, disk mount, VM boot, or checkpoint refresh was executed."
        return
    }

    if (-not (Test-IsAdministrator)) {
        throw 'Resetting the actual VM guest password requires an elevated PowerShell session because it restores checkpoints and mounts the VM disk.'
    }

    $usePromptPassword = [bool]$PromptPassword
    if ($Mode -eq 'Interactive') {
        Write-Host ''
        Write-Host "This will restore checkpoint '$CheckpointName', mount the VM disk, boot '$VmName', reset '$GuestUserName', validate PowerShell Direct, and refresh the checkpoint."
        $continue = Read-MenuChoice -Prompt 'Continue actual VM password reset? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        if ($continue -in @('n', 'N')) {
            Write-InstallInfo 'Actual VM password reset cancelled.'
            return
        }

        Write-Host ''
        Write-Host 'Actual VM password option:'
        Write-Host '  1) Generate a new random password inside the reset script'
        Write-Host '  2) Prompt for a new VM password inside the reset script'
        $passwordChoice = Read-MenuChoice -Prompt 'Choose [1-2]' -Allowed @('1', '2')
        $usePromptPassword = ($passwordChoice -eq '2')
    }
    elseif (-not $Force) {
        throw 'Non-interactive actual VM password reset requires -Force to avoid hanging on Hyper-V confirmation prompts.'
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $resetScript,
        '-VmName', $VmName,
        '-CheckpointName', $CheckpointName,
        '-GuestUserName', $GuestUserName,
        '-SecretName', $SecretName,
        '-RuntimeRoot', $RuntimeRoot,
        '-GuestWorkingDirectory', $GuestWorkingDirectory,
        '-BootTimeoutSeconds', ([string]$BootTimeoutSeconds),
        '-PowerShellDirectTimeoutSeconds', ([string]$PowerShellDirectTimeoutSeconds),
        '-Force'
    )
    if ($usePromptPassword) {
        $arguments += '-PromptPassword'
    }
    if ($SkipCheckpointRefresh) {
        $arguments += '-SkipCheckpointRefresh'
    }
    if ($SkipCheckpointRestore) {
        $arguments += '-SkipCheckpointRestore'
    }

    if (-not $PSCmdlet.ShouldProcess($VmName, "Launch actual VM password reset for '$GuestUserName'")) {
        Write-InstallInfo 'Actual VM password reset declined by ShouldProcess/Confirm.'
        return
    }

    Write-InstallInfo "Launching actual VM password reset for '$VmName'. Secret value will not be printed."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Actual VM password reset failed with exit code $LASTEXITCODE."
    }

    $userSecret = [Environment]::GetEnvironmentVariable($SecretName, 'User')
    if (-not [string]::IsNullOrWhiteSpace($userSecret)) {
        [Environment]::SetEnvironmentVariable($SecretName, $userSecret, 'Process')
    }

    $configPath = Write-LocalSandboxConfig
    Set-WebConfigPathEnvironment -ConfigPath $configPath
    Write-InstallInfo 'Actual VM password reset completed. Host secret and local sandbox config are synchronized.'
}

function Set-GuestUserNameState {
    param([string]$NewGuestUserName)

    if ([string]::IsNullOrWhiteSpace($NewGuestUserName)) {
        throw 'Guest user name must not be empty.'
    }

    $script:GuestUserName = $NewGuestUserName

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
    Set-HyperVConfigState -Action 'guest-user-changed'
}

function Show-KSwordSandboxInstallStatus {
    $processValue = [Environment]::GetEnvironmentVariable($SecretName, 'Process')
    $userValue = [Environment]::GetEnvironmentVariable($SecretName, 'User')
    $machineValue = [Environment]::GetEnvironmentVariable($SecretName, 'Machine')
    $vtProcessValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'Process')
    $vtUserValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'User')
    $vtMachineValue = [Environment]::GetEnvironmentVariable($VirusTotalSecretName, 'Machine')
    $localConfig = Get-LocalSandboxConfigPath
    $hyperVModuleAvailable = $null -ne (Get-Command Get-VM -ErrorAction SilentlyContinue)
    $vmExists = $false
    $vmState = $null
    $checkpointExists = $false
    $hyperVStatusError = $null

    if ($hyperVModuleAvailable) {
        try {
            $vm = Get-VM -Name $VmName -ErrorAction Stop
            $vmExists = $true
            $vmState = [string]$vm.State
            $snapshot = Get-VMSnapshot -VMName $VmName -Name $CheckpointName -ErrorAction SilentlyContinue
            $checkpointExists = $null -ne $snapshot
        }
        catch {
            $hyperVStatusError = $_.Exception.Message
        }
    }

    [pscustomobject][ordered]@{
        SecretName = $SecretName
        ProcessSecretSet = -not [string]::IsNullOrWhiteSpace($processValue)
        UserSecretSet = -not [string]::IsNullOrWhiteSpace($userValue)
        MachineSecretSet = -not [string]::IsNullOrWhiteSpace($machineValue)
        VirusTotalSecretName = $VirusTotalSecretName
        VirusTotalProcessSecretSet = -not [string]::IsNullOrWhiteSpace($vtProcessValue)
        VirusTotalUserSecretSet = -not [string]::IsNullOrWhiteSpace($vtUserValue)
        VirusTotalMachineSecretSet = -not [string]::IsNullOrWhiteSpace($vtMachineValue)
        GuestUserName = $GuestUserName
        RuntimeRoot = [System.IO.Path]::GetFullPath($RuntimeRoot)
        RuntimeRootExists = Test-Path -LiteralPath $RuntimeRoot -PathType Container
        GuestPayloadRoot = [System.IO.Path]::GetFullPath($GuestPayloadRoot)
        GuestPayloadRootExists = Test-Path -LiteralPath $GuestPayloadRoot -PathType Container
        VmName = $VmName
        CheckpointName = $CheckpointName
        GuestWorkingDirectory = $GuestWorkingDirectory
        HyperVModuleAvailable = $hyperVModuleAvailable
        IsAdministrator = Test-IsAdministrator
        VmExists = $vmExists
        VmState = $vmState
        CheckpointExists = $checkpointExists
        HyperVStatusError = $hyperVStatusError
        LocalConfigPath = $localConfig
        LocalConfigExists = Test-Path -LiteralPath $localConfig -PathType Leaf
        WebConfigPathProcess = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'Process')
        WebConfigPathUser = [Environment]::GetEnvironmentVariable($script:WebConfigPathEnvironmentName, 'User')
        InstallStatePath = $script:InstallStatePath
        InstallStateExists = Test-Path -LiteralPath $script:InstallStatePath -PathType Leaf
        DpapiBackupPath = $script:SecretBackupPath
        DpapiBackupExists = Test-Path -LiteralPath $script:SecretBackupPath -PathType Leaf
        SecretValuePrinted = $false
    }
}

function Test-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return $null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Show-KSwordSandboxEnvironmentCheck {
    $runScript = Join-Path $PSScriptRoot 'run.ps1'
    $readinessScript = Join-Path $PSScriptRoot 'scripts\Test-HyperVReadiness.ps1'
    $webProject = Join-Path $PSScriptRoot 'src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj'
    $installStatus = Show-KSwordSandboxInstallStatus

    [pscustomobject][ordered]@{
        StartupCommand = '.\run.ps1'
        InstallCommand = '.\install.ps1'
        ConfigureHyperVCommand = '.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <VM> -CheckpointName <Checkpoint>'
        ConfigureGuestPasswordCommand = '.\install.ps1 -Mode Install -PromptPassword'
        ResetGuestPasswordCommand = '.\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force'
        ConfigureVTKeyCommand = '.\install.ps1 -Mode ConfigureVTKey -PromptVTKey'
        CheckEnvironmentCommand = '.\install.ps1 -Mode CheckEnvironment'
        WebUiUrl = $WebUiUrl
        RunScriptExists = Test-Path -LiteralPath $runScript -PathType Leaf
        ReadinessScriptExists = Test-Path -LiteralPath $readinessScript -PathType Leaf
        WebProjectExists = Test-Path -LiteralPath $webProject -PathType Leaf
        DotNetAvailable = Test-CommandAvailable -Name 'dotnet'
        PowerShellAvailable = Test-CommandAvailable -Name 'powershell'
        HyperVGetVmAvailable = Test-CommandAvailable -Name 'Get-VM'
        HyperVGetVmSnapshotAvailable = Test-CommandAvailable -Name 'Get-VMSnapshot'
        WhatIfSupported = $true
        DefaultStartsVm = $false
        StartWebUiStartsVm = $false
        LiveVmExecutionRequiresExplicitLive = $true
        SecretValuePrinted = $false
        InstallStatus = $installStatus
    }
}

function Invoke-KSwordSandboxEnvironmentCheck {
    Show-KSwordSandboxEnvironmentCheck | Format-List

    if ($RunHyperVReadiness) {
        $readinessScript = Join-Path $PSScriptRoot 'scripts\Test-HyperVReadiness.ps1'
        if (-not (Test-Path -LiteralPath $readinessScript -PathType Leaf)) {
            throw "Hyper-V readiness script is missing: $readinessScript"
        }

        if (-not $PSCmdlet.ShouldProcess($readinessScript, 'Run read-only Hyper-V readiness preflight')) {
            Write-InstallInfo "WhatIf: read-only Hyper-V readiness preflight would run: $readinessScript"
            return
        }

        Write-InstallInfo 'Running read-only Hyper-V readiness preflight. It must not restore/start/stop a VM.'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $readinessScript
        if ($LASTEXITCODE -ne 0) {
            throw "Hyper-V readiness preflight failed with exit code $LASTEXITCODE."
        }
    }
}

function Invoke-KSwordSandboxWebUi {
    $runScript = Join-Path $PSScriptRoot 'run.ps1'
    if (-not (Test-Path -LiteralPath $runScript -PathType Leaf)) {
        throw "run.ps1 was not found: $runScript"
    }

    if (-not $PSCmdlet.ShouldProcess($WebUiUrl, 'Start KSwordSandbox WebUI without starting or restoring a VM')) {
        Write-InstallInfo "WhatIf: WebUI would be started via '$runScript -Mode WebUI -Url $WebUiUrl'. No VM would be started by this wrapper."
        return
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $runScript,
        '-Mode', 'WebUI',
        '-Url', $WebUiUrl
    )

    if ($OpenBrowser) {
        $arguments += '-OpenBrowser'
    }

    Write-InstallInfo "Starting WebUI through run.ps1 at $WebUiUrl. This wrapper does not start or restore a VM."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "run.ps1 WebUI launch failed with exit code $LASTEXITCODE."
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

    if (-not $PSCmdlet.ShouldProcess($script:InstallStateDirectory, "Uninstall local KSwordSandbox settings and clear '$SecretName' from process/User environment")) {
        Write-InstallInfo "WhatIf: local installer metadata and '$SecretName' process/User environment entries would be removed."
        Write-InstallInfo 'Runtime output folders would be left intact.'
        return
    }

    [Environment]::SetEnvironmentVariable($SecretName, $null, 'Process')
    [Environment]::SetEnvironmentVariable($SecretName, $null, 'User')
    Remove-Item -LiteralPath $script:SecretBackupPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:InstallStatePath -Force -ErrorAction SilentlyContinue
    Write-InstallInfo "Removed current process/User environment secret '$SecretName' and local DPAPI backup if present."
    Write-InstallInfo 'Runtime output folders were left intact.'
}

function Invoke-GuestTestSigningMode {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable', 'Query')]
        [string]$TestSigningMode,

        [bool]$RestartAfterChange = $false
    )

    $testSigningScript = Join-Path $PSScriptRoot 'scripts\Set-GuestTestSigning.ps1'
    if (-not (Test-Path -LiteralPath $testSigningScript -PathType Leaf)) {
        throw "Guest test-signing script is missing: $testSigningScript"
    }

    if ($WhatIfPreference) {
        [void]$PSCmdlet.ShouldProcess($VmName, "Run guest test-signing '$TestSigningMode'")
        Write-InstallInfo "WhatIf: guest test-signing '$TestSigningMode' would be delegated to '$testSigningScript'. No guest command or reboot was executed."
        return
    }

    if ($TestSigningMode -ne 'Query' -and -not $Force -and $Mode -ne 'Interactive') {
        throw 'Non-interactive guest test-signing changes require -Force.'
    }

    if ($TestSigningMode -ne 'Query' -and $Mode -eq 'Interactive') {
        Write-Host ''
        Write-Host "This will run bcdedit /set testsigning $($TestSigningMode.ToLowerInvariant()) inside '$VmName'."
        if ($RestartAfterChange) {
            Write-Host 'The guest may reboot if the state changes.'
        }

        $continue = Read-MenuChoice -Prompt 'Continue guest test-signing change? [y/n]' -Allowed @('y', 'Y', 'n', 'N')
        if ($continue -in @('n', 'N')) {
            Write-InstallInfo 'Guest test-signing change cancelled.'
            return
        }
    }

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $testSigningScript,
        '-VmName', $VmName,
        '-GuestUserName', $GuestUserName,
        '-SecretName', $SecretName,
        '-Mode', $TestSigningMode
    )

    if ($RestartAfterChange) {
        $arguments += '-RestartGuest'
    }

    if ($Force -or $Mode -eq 'Interactive') {
        $arguments += '-Force'
    }

    if (-not $PSCmdlet.ShouldProcess($VmName, "Run guest test-signing '$TestSigningMode'")) {
        Write-InstallInfo "Guest test-signing '$TestSigningMode' declined by ShouldProcess/Confirm."
        return
    }

    Write-InstallInfo "Running guest test-signing '$TestSigningMode' for VM '$VmName'."
    & powershell @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Guest test-signing '$TestSigningMode' failed with exit code $LASTEXITCODE."
    }
}

function Invoke-GuestTestSigningMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Guest test-signing options:'
        Write-Host '  1) Query current guest test-signing state'
        Write-Host '  2) Enable guest test-signing'
        Write-Host '  3) Enable guest test-signing and reboot guest if changed'
        Write-Host '  4) Disable guest test-signing'
        Write-Host '  5) Back'
        $choice = Read-MenuChoice -Prompt 'Choose [1-5]' -Allowed @('1', '2', '3', '4', '5')
        switch ($choice) {
            '1' { Invoke-GuestTestSigningMode -TestSigningMode Query }
            '2' { Invoke-GuestTestSigningMode -TestSigningMode Enable }
            '3' { Invoke-GuestTestSigningMode -TestSigningMode Enable -RestartAfterChange $true }
            '4' { Invoke-GuestTestSigningMode -TestSigningMode Disable }
            '5' { return }
        }
    }
}

function Invoke-GuestPasswordMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Guest password options:'
        Write-Host '  1) Reset host-side password secret only'
        Write-Host '  2) Reset actual VM guest password (elevated, explicit confirmation)'
        Write-Host '  3) Back'
        $choice = Read-MenuChoice -Prompt 'Choose [1-3]' -Allowed @('1', '2', '3')
        switch ($choice) {
            '1' { Reset-GuestPasswordSecret }
            '2' { Invoke-GuestVmPasswordReset }
            '3' { return }
        }
    }
}

function Invoke-ChangeMenu {
    while ($true) {
        Write-Host ''
        Write-Host 'Change options:'
        Write-Host '  1) Reset password secret'
        Write-Host '  2) Reset actual VM guest password'
        Write-Host '  3) Change Hyper-V VM/checkpoint/guest paths'
        Write-Host '  4) Change recorded guest username'
        Write-Host '  5) Recreate runtime folders and local config'
        Write-Host '  6) Show Hyper-V readiness/status'
        Write-Host '  7) Manage guest test-signing'
        Write-Host '  8) Configure optional VirusTotal API key'
        Write-Host '  9) Check local environment'
        Write-Host '  10) Back'
        $choice = Read-MenuChoice -Prompt 'Choose [1-10]' -Allowed @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10')
        switch ($choice) {
            '1' { Reset-GuestPasswordSecret }
            '2' { Invoke-GuestVmPasswordReset }
            '3' { Invoke-HyperVConfigPrompt }
            '4' {
                $name = Read-Host 'Guest username'
                Set-GuestUserNameState -NewGuestUserName $name
            }
            '5' { Set-HyperVConfigState -Action 'runtime-folders-and-config-refreshed' }
            '6' { Show-KSwordSandboxInstallStatus | Format-List }
            '7' { Invoke-GuestTestSigningMenu }
            '8' { Invoke-VirusTotalKeyConfiguration }
            '9' { Invoke-KSwordSandboxEnvironmentCheck }
            '10' { return }
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
        Write-Host '  4) Reset Guest password'
        Write-Host '  5) Configure Hyper-V'
        Write-Host '  6) Configure VT key'
        Write-Host '  7) Check environment'
        Write-Host '  8) Start WebUI'
        Write-Host '  9) Status'
        Write-Host '  10) Exit'
        $choice = Read-MenuChoice -Prompt 'Choose [1-10]' -Allowed @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10')
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
            '4' { Invoke-GuestPasswordMenu }
            '5' { Invoke-HyperVConfigPrompt }
            '6' { Invoke-VirusTotalKeyConfiguration }
            '7' { Invoke-KSwordSandboxEnvironmentCheck }
            '8' { Invoke-KSwordSandboxWebUi }
            '9' { Show-KSwordSandboxInstallStatus | Format-List }
            '10' { return }
        }
    }
}

$script:InitialInstallState = Read-InstallState
Initialize-EffectiveParameters -State $script:InitialInstallState -BoundParameters $PSBoundParameters

switch ($Mode) {
    'Interactive' {
        Invoke-InteractiveInstaller
    }
    'Install' {
        $shouldSetPassword = [bool]$GeneratePassword -or [bool]$PromptPassword -or [bool]$ResetPassword
        Install-KSwordSandboxLocal -SetPassword:$shouldSetPassword
    }
    'Change' {
        if ($StartWebUI) {
            Invoke-KSwordSandboxWebUi
        }
        elseif ($CheckEnvironment) {
            Invoke-KSwordSandboxEnvironmentCheck
        }
        elseif ($ConfigureVTKey -or $PromptVTKey -or $ClearVTKey) {
            Invoke-VirusTotalKeyConfiguration
        }
        elseif ($ResetGuestVmPassword) {
            Invoke-GuestVmPasswordReset
        }
        elseif ($EnableGuestTestSigning) {
            Invoke-GuestTestSigningMode -TestSigningMode Enable -RestartAfterChange ([bool]$RestartGuestAfterTestSigning)
        }
        elseif ($DisableGuestTestSigning) {
            Invoke-GuestTestSigningMode -TestSigningMode Disable -RestartAfterChange ([bool]$RestartGuestAfterTestSigning)
        }
        elseif ($QueryGuestTestSigning) {
            Invoke-GuestTestSigningMode -TestSigningMode Query
        }
        elseif ($UpdateHyperVConfig) {
            Set-HyperVConfigState
        }
        elseif ($ResetPassword -or $GeneratePassword -or $PromptPassword) {
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
    'CheckEnvironment' {
        Invoke-KSwordSandboxEnvironmentCheck
    }
    'ConfigureVTKey' {
        Invoke-VirusTotalKeyConfiguration
    }
    'StartWebUI' {
        Invoke-KSwordSandboxWebUi
    }
}
