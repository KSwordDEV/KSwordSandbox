<#
.SYNOPSIS
Injects a one-shot LocalSystem password-reset service into an offline Windows VHDX.

.DESCRIPTION
This internal provider helper reads the replacement password from an environment
secret, mounts a detached VHDX through the Windows Storage module, writes a
self-deleting guest script, and registers a one-shot service in the offline
SYSTEM hive. It never starts a VM or commits provider configuration.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$VhdxPath,
    [Parameter(Mandatory)][string]$GuestUserName,
    [Parameter(Mandatory)][string]$PasswordSecretName,
    [string]$ServiceName = 'KSwordSandboxPasswordReset',
    [switch]$Force,
    [switch]$Json
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$script:MountedDiskImageHere = $false
$script:TemporaryAccessPaths = [System.Collections.Generic.List[object]]::new()
$script:OfflineHiveName = "KSwordOfflinePasswordReset_$PID"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SecretValue {
    param([Parameter(Mandatory)][string]$Name)

    foreach ($scope in @('Process', 'User', 'Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }
    throw "Password environment variable '$Name' was not found; offline injection never accepts a password on the command line."
}

function Clear-ProviderSecretEnvironment {
    [Environment]::SetEnvironmentVariable($PasswordSecretName, $null, 'Process')
    $environment = [Environment]::GetEnvironmentVariables('Process')
    foreach ($keyValue in @($environment.Keys)) {
        $name = [string]$keyValue
        if ($name.StartsWith('KSWORDBOX_', [StringComparison]::OrdinalIgnoreCase) -or
            $name -match '(?i)(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)') {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
}

function Get-AvailableDriveLetter {
    $used = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object { [string]$_.DriveLetter })
    foreach ($letter in 'Z','Y','X','W','V','U','T','S','R','Q','P','O','N','M','L','K','J') {
        if ($used -notcontains $letter) { return $letter }
    }
    throw 'No drive letter is available for the offline Windows volume.'
}

function Get-DiskForVhdx {
    param([Parameter(Mandatory)][string]$Path)

    $existingImage = Get-DiskImage -ImagePath $Path -ErrorAction SilentlyContinue
    if ($null -ne $existingImage -and [bool]$existingImage.Attached) {
        throw "Offline injection refuses an already attached VHDX: $Path"
    }

    $image = Mount-DiskImage -ImagePath $Path -NoDriveLetter -PassThru -ErrorAction Stop
    $script:MountedDiskImageHere = $true
    $disks = @($image | Get-Disk -ErrorAction Stop)
    if ($disks.Count -ne 1) { throw "The mounted VHDX resolved to $($disks.Count) disks; exactly one is required." }
    return $disks[0]
}

function Mount-GuestWindowsVolume {
    param([Parameter(Mandatory)][string]$Path)

    $disk = Get-DiskForVhdx -Path $Path
    if ($null -eq $disk) { throw "The mounted VHDX could not be resolved to a disk: $Path" }

    foreach ($partition in @(Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Type -ne 'Reserved' })) {
        $letterText = [string]$partition.DriveLetter
        $hasLetter = -not [string]::IsNullOrWhiteSpace($letterText) -and $letterText[0] -ne [char]0
        $letter = $partition.DriveLetter
        if (-not $hasLetter) {
            $letter = Get-AvailableDriveLetter
            $accessPath = "$letter`:\"
            Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $accessPath -ErrorAction Stop
            [void]$script:TemporaryAccessPaths.Add([pscustomobject]@{
                DiskNumber = $disk.Number
                PartitionNumber = $partition.PartitionNumber
                AccessPath = $accessPath
            })
        }

        $root = "$letter`:\"
        $systemHive = Join-Path $root 'Windows\System32\Config\SYSTEM'
        if (Test-Path -LiteralPath $systemHive -PathType Leaf) {
            return [pscustomobject][ordered]@{ Root = $root; SystemHive = $systemHive }
        }
    }

    throw "The mounted VHDX does not contain a Windows SYSTEM hive: $Path"
}

function Dismount-GuestWindowsVolume {
    param([Parameter(Mandatory)][string]$Path)

    $cleanupErrors = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($script:TemporaryAccessPaths)) {
        try {
            Remove-PartitionAccessPath -DiskNumber $entry.DiskNumber -PartitionNumber $entry.PartitionNumber -AccessPath $entry.AccessPath -ErrorAction Stop
        }
        catch {
            [void]$cleanupErrors.Add("temporary access path '$($entry.AccessPath)': $($_.Exception.Message)")
        }
    }
    if ($script:MountedDiskImageHere) {
        try { Dismount-DiskImage -ImagePath $Path -ErrorAction Stop }
        catch { [void]$cleanupErrors.Add("VHDX dismount: $($_.Exception.Message)") }
    }
    if ($cleanupErrors.Count -gt 0) {
        throw "Offline VHDX cleanup failed: $($cleanupErrors -join ' | ')"
    }
}

function ConvertTo-PowerShellSingleQuotedLiteral {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { $Text = '' }
    return "'" + $Text.Replace("'", "''") + "'"
}

function New-GuestResetScriptText {
    param([Parameter(Mandatory)][string]$Password)

    $quotedUser = ConvertTo-PowerShellSingleQuotedLiteral -Text $GuestUserName
    $quotedPassword = ConvertTo-PowerShellSingleQuotedLiteral -Text $Password
    $quotedService = ConvertTo-PowerShellSingleQuotedLiteral -Text $ServiceName
    return @"
`$ErrorActionPreference = 'Continue'
`$resultPath = 'C:\KSwordSandbox\HostInjected\password-reset-result.json'
New-Item -ItemType Directory -Path (Split-Path -Parent `$resultPath) -Force | Out-Null
`$result = [ordered]@{
    kind = 'KSwordSandbox.GuestPasswordResetResult'
    userName = $quotedUser
    startedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    success = `$false
    message = ''
    secretValuePrinted = `$false
}
try {
    `$userName = $quotedUser
    `$password = $quotedPassword
    `$secure = ConvertTo-SecureString `$password -AsPlainText -Force
    `$existing = Get-LocalUser -Name `$userName -ErrorAction SilentlyContinue
    if (`$null -eq `$existing) {
        New-LocalUser -Name `$userName -Password `$secure -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
    }
    else {
        Set-LocalUser -Name `$userName -Password `$secure -ErrorAction Stop
        Enable-LocalUser -Name `$userName -ErrorAction SilentlyContinue
    }
    `$adminGroup = Get-LocalGroup | Where-Object { `$_.SID -eq 'S-1-5-32-544' } | Select-Object -First 1
    if (`$null -ne `$adminGroup) {
        try { Add-LocalGroupMember -Group `$adminGroup.Name -Member `$userName -ErrorAction Stop } catch { }
    }
    try { Set-LocalUser -Name `$userName -PasswordNeverExpires `$true -ErrorAction SilentlyContinue } catch { }
    `$result.success = `$true
    `$result.message = 'Guest account password was reset and the account was enabled.'
}
catch {
    `$result.success = `$false
    `$result.message = `$_.Exception.Message
}
finally {
    `$result.completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    `$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath `$resultPath -Encoding UTF8
    try { sc.exe delete $quotedService | Out-Null } catch { }
    try { Remove-Item -LiteralPath `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue } catch { }
}
"@
}

function Inject-PasswordResetService {
    param(
        [Parameter(Mandatory)][string]$WindowsRoot,
        [Parameter(Mandatory)][string]$SystemHive,
        [Parameter(Mandatory)][string]$Password
    )

    $hostInjectedDirectory = Join-Path $WindowsRoot 'KSwordSandbox\HostInjected'
    New-Item -ItemType Directory -Path $hostInjectedDirectory -Force | Out-Null
    foreach ($staleArtifact in @('password-reset-result.json', 'reset-service.log')) {
        $staleArtifactPath = Join-Path $hostInjectedDirectory $staleArtifact
        Remove-Item -LiteralPath $staleArtifactPath -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $staleArtifactPath -PathType Leaf) {
            throw "A stale guest password-reset artifact could not be removed before injection: $staleArtifactPath"
        }
    }
    New-GuestResetScriptText -Password $Password | Set-Content -LiteralPath (Join-Path $hostInjectedDirectory 'ResetSandboxUser.ps1') -Encoding UTF8

    $offlineHivePath = "HKLM:\$script:OfflineHiveName"
    try { & reg.exe unload "HKLM\$script:OfflineHiveName" *> $null } catch { }
    $loaded = $false
    try {
        $loadOutput = @(& reg.exe load "HKLM\$script:OfflineHiveName" $SystemHive 2>&1)
        if ($LASTEXITCODE -ne 0) { throw "reg load failed for the offline SYSTEM hive: $($loadOutput -join ' ')" }
        $loaded = $true
        $select = Get-ItemProperty -LiteralPath (Join-Path $offlineHivePath 'Select')
        $controlSet = 'ControlSet{0:D3}' -f [int]$select.Current
        $servicePath = Join-Path $offlineHivePath "$controlSet\Services\$ServiceName"
        New-Item -Path $servicePath -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'Type' -PropertyType DWord -Value 16 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'Start' -PropertyType DWord -Value 2 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'ErrorControl' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'DelayedAutoStart' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'DisplayName' -PropertyType String -Value 'KSwordSandbox one-shot password reset' -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'ObjectName' -PropertyType String -Value 'LocalSystem' -Force | Out-Null
        New-ItemProperty -Path $servicePath -Name 'ImagePath' -PropertyType ExpandString -Value '%SystemRoot%\System32\cmd.exe /c ""%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\KSwordSandbox\HostInjected\ResetSandboxUser.ps1" >> "C:\KSwordSandbox\HostInjected\reset-service.log" 2>&1"' -Force | Out-Null
    }
    finally {
        if ($loaded) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            & reg.exe unload "HKLM\$script:OfflineHiveName" | Out-Null
        }
    }
}

$resolvedVhdx = [IO.Path]::GetFullPath($VhdxPath)
if (-not (Test-Path -LiteralPath $resolvedVhdx -PathType Leaf)) { throw "Offline VHDX was not found: $resolvedVhdx" }
if (-not $Force) { throw 'Offline guest password injection requires -Force from the confirmed parent recovery workflow.' }
if (-not $PSCmdlet.ShouldProcess($resolvedVhdx, "Inject one-shot guest password reset service for '$GuestUserName'")) {
    $preview = [pscustomobject][ordered]@{
        Kind = 'KSwordSandbox.OfflineGuestPasswordInjection'
        VhdxPath = $resolvedVhdx
        GuestUserName = $GuestUserName
        Injected = $false
        WhatIf = $true
        SecretValuePrinted = $false
    }
    if ($Json) { $preview | ConvertTo-Json -Depth 5 } else { $preview }
    exit 0
}
if (-not (Test-IsAdministrator)) { throw 'Offline VHDX password injection requires an elevated Windows PowerShell session.' }

$password = Get-SecretValue -Name $PasswordSecretName
Clear-ProviderSecretEnvironment
try {
    $mountedVolume = Mount-GuestWindowsVolume -Path $resolvedVhdx
    Inject-PasswordResetService -WindowsRoot $mountedVolume.Root -SystemHive $mountedVolume.SystemHive -Password $password
}
finally {
    Dismount-GuestWindowsVolume -Path $resolvedVhdx
    $password = $null
}

$result = [pscustomobject][ordered]@{
    Kind = 'KSwordSandbox.OfflineGuestPasswordInjection'
    VhdxPath = $resolvedVhdx
    GuestUserName = $GuestUserName
    Injected = $true
    ProviderChildSecretEnvironmentCleared = $true
    SecretValuePrinted = $false
}
if ($Json) { $result | ConvertTo-Json -Depth 5 } else { $result }
