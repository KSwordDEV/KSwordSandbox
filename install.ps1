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
  .\install.ps1 -Mode Change -UpdateHyperVConfig -VmName KSwordSandbox-Win10-Golden -CheckpointName Clean
  .\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force
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

    [string]$VmName = 'KSwordSandbox-Win10-Golden',

    [string]$CheckpointName = 'Clean',

    [string]$GuestWorkingDirectory = 'C:\KSwordSandbox',

    [string]$LocalConfigPath = '',

    [switch]$GeneratePassword,

    [switch]$PromptPassword,

    [switch]$ResetPassword,

    [switch]$ResetGuestVmPassword,

    [switch]$UpdateHyperVConfig,

    [switch]$CurrentProcessOnly,

    [switch]$SkipDpapiBackup,

    [switch]$SkipWebConfigEnvironment,

    [switch]$SkipCheckpointRefresh,

    [switch]$SkipCheckpointRestore,

    [int]$BootTimeoutSeconds = 240,

    [int]$PowerShellDirectTimeoutSeconds = 240,

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

    $parent = Split-Path -Parent $targetPath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $targetPath -Encoding UTF8
    Write-InstallInfo "Local sandbox config written: $targetPath"
    return $targetPath
}

function Set-WebConfigPathEnvironment {
    param([Parameter(Mandatory)][string]$ConfigPath)

    if ($SkipWebConfigEnvironment) {
        Write-InstallInfo "Skipped '$script:WebConfigPathEnvironmentName' environment update."
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

    New-Item -ItemType Directory -Path $script:InstallStateDirectory -Force | Out-Null
    if ([string]::IsNullOrWhiteSpace($LocalConfig)) {
        $LocalConfig = Get-LocalSandboxConfigPath
    }

    $state = [ordered]@{
        installStateVersion = 2
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
        vmName = $Vm
        checkpointName = $Checkpoint
        guestWorkingDirectory = $GuestWorking
        localConfigPath = $LocalConfig
        webConfigPathEnvironmentName = $script:WebConfigPathEnvironmentName
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

function Initialize-KSwordSandboxRuntimeFolders {
    New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'jobs') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'plans') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'uploads') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $RuntimeRoot 'config') -Force | Out-Null
    New-Item -ItemType Directory -Path $GuestPayloadRoot -Force | Out-Null
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
        Write-Host '  2) Reset actual VM guest password'
        Write-Host '  3) Change Hyper-V VM/checkpoint/guest paths'
        Write-Host '  4) Change recorded guest username'
        Write-Host '  5) Recreate runtime folders and local config'
        Write-Host '  6) Show Hyper-V readiness/status'
        Write-Host '  7) Back'
        $choice = Read-MenuChoice -Prompt 'Choose [1-7]' -Allowed @('1', '2', '3', '4', '5', '6', '7')
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
            '7' { return }
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
        if ($ResetGuestVmPassword) {
            Invoke-GuestVmPasswordReset
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
}
