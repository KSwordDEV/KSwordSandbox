#requires -RunAsAdministrator
<#
.SYNOPSIS
Prepare a Windows 10 VMware guest for KSwordSandbox WinRM HTTPS access.

.DESCRIPTION
Run once from an elevated Windows PowerShell prompt inside the guest. The script is
safe to run again: it updates the local account when requested, reuses a usable
machine certificate, and reconciles the WinRM HTTPS listener and firewall rule.
Passwords are read as SecureString and are never written to output or command-line
arguments.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[^\\/:*?"<>|]{1,20}$')]
    [string]$GuestUserName = 'SandboxUser',
    [string]$WorkingDirectory = 'C:\KSwordSandbox',
    [ValidateRange(1, 65535)]
    [int]$Port = 5986,
    [switch]$DisableDefenderForLab,
    [switch]$SkipPasswordSet
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ruleName = 'KSwordSandbox-WinRM-HTTPS'
$certificateFriendlyName = 'KSwordSandbox WinRM HTTPS'

function Write-Bilingual {
    param([Parameter(Mandatory)][string]$Chinese, [Parameter(Mandatory)][string]$English)
    Write-Host "$Chinese / $English"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '请用管理员身份运行此脚本。 / Run this script from an elevated Administrator PowerShell.'
    }
}

function Get-OrCreateGuestUser {
    $existing = Get-LocalUser -Name $GuestUserName -ErrorAction SilentlyContinue
    if ($SkipPasswordSet) {
        if ($null -eq $existing) {
            throw "找不到本地账户 '$GuestUserName'，不能使用 -SkipPasswordSet。 / Local account '$GuestUserName' was not found; omit -SkipPasswordSet to create it."
        }
        Enable-LocalUser -Name $GuestUserName -ErrorAction SilentlyContinue
        return $existing
    }

    $securePassword = Read-Host -Prompt "为 $GuestUserName 输入密码（不会显示） / Enter the password for $GuestUserName (hidden)" -AsSecureString
    if ($null -eq $securePassword -or $securePassword.Length -eq 0) {
        throw '密码不能为空。 / The password cannot be empty.'
    }

    if ($null -eq $existing) {
        New-LocalUser -Name $GuestUserName -Password $securePassword -Description 'KSwordSandbox VMware guest operator' -PasswordNeverExpires:$true -AccountNeverExpires:$true | Out-Null
        $existing = Get-LocalUser -Name $GuestUserName -ErrorAction Stop
        Write-Bilingual -Chinese "已创建本地账户 $GuestUserName" -English "Created local account $GuestUserName"
    }
    else {
        Set-LocalUser -Name $GuestUserName -Password $securePassword -PasswordNeverExpires:$true
        Enable-LocalUser -Name $GuestUserName -ErrorAction SilentlyContinue
        Write-Bilingual -Chinese "已更新本地账户密码 $GuestUserName" -English "Updated the local account password for $GuestUserName"
    }
    return $existing
}

function Ensure-LocalAdministrator {
    param([Parameter(Mandatory)]$User)
    $administratorsGroup = @(Get-LocalGroup -ErrorAction Stop | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' } | Select-Object -First 1)
    if ($administratorsGroup.Count -eq 0) {
        throw '找不到本地 Administrators 组。 / The built-in local Administrators group was not found.'
    }

    $groupName = [string]$administratorsGroup[0].Name
    $members = @(Get-LocalGroupMember -Group $groupName -ErrorAction Stop)
    $isMember = $members | Where-Object { $_.SID.Value -eq $User.SID.Value }
    if ($null -eq $isMember) {
        $memberName = "$env:COMPUTERNAME\$($User.Name)"
        Add-LocalGroupMember -Group $groupName -Member $memberName -ErrorAction Stop
        Write-Bilingual -Chinese "已将 $GuestUserName 加入 Administrators" -English "Added $GuestUserName to the Administrators group"
    }
    else {
        Write-Bilingual -Chinese "$GuestUserName 已经是 Administrators 成员" -English "$GuestUserName is already a member of Administrators"
    }
}

function Get-UsableWinRmCertificate {
    $computerName = [Environment]::MachineName
    $ekuServerAuth = '1.3.6.1.5.5.7.3.1'
    $certificates = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop | Where-Object {
        $ekuValues = foreach ($eku in @($_.EnhancedKeyUsageList)) {
            # Windows PowerShell and newer certificate providers expose EKU
            # entries with different shapes: some are Oid objects with Value,
            # others wrap the Oid in ObjectId. Read both without assuming one
            # provider-specific shape.
            $valueProperty = $eku.PSObject.Properties['Value']
            if ($null -ne $valueProperty) {
                [string]$valueProperty.Value
                continue
            }

            $objectIdProperty = $eku.PSObject.Properties['ObjectId']
            if ($null -ne $objectIdProperty -and $null -ne $eku.ObjectId) {
                $nestedValue = $eku.ObjectId.PSObject.Properties['Value']
                if ($null -ne $nestedValue) {
                    [string]$nestedValue.Value
                }
            }
        }
        $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) -and
        $_.Subject -eq "CN=$computerName" -and
        (@($ekuValues) -contains $ekuServerAuth)
    } | Sort-Object NotAfter -Descending)
    if ($certificates.Count -gt 0) { return $certificates[0] }

    Write-Bilingual -Chinese '正在创建来宾自签名 HTTPS 证书' -English 'Creating a self-signed HTTPS certificate in the guest'
    return New-SelfSignedCertificate -DnsName @($computerName, 'localhost') -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName $certificateFriendlyName -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(3) -Type SSLServerAuthentication
}

function Get-HttpsListeners {
    @(Get-ChildItem -Path 'WSMan:\localhost\Listener' -ErrorAction SilentlyContinue | Where-Object {
        $transport = @($_.Keys | Where-Object { [string]$_ -like 'Transport=*' }) -join ''
        $transport -eq 'Transport=HTTPS'
    })
}

function Get-WsManListenerProperty {
    param(
        [Parameter(Mandatory)]$Listener,
        [Parameter(Mandatory)][string]$Name
    )

    $directProperty = $Listener.PSObject.Properties[$Name]
    if ($null -ne $directProperty) {
        return [string]$directProperty.Value
    }

    try {
        $propertyItem = Get-Item -LiteralPath (Join-Path $Listener.PSPath $Name) -ErrorAction Stop
        $valueProperty = $propertyItem.PSObject.Properties['Value']
        if ($null -ne $valueProperty) {
            return [string]$valueProperty.Value
        }
    }
    catch {
        return $null
    }

    return $null
}

function Ensure-WinRmHttpsListener {
    param([Parameter(Mandatory)]$Certificate)
    $listeners = @(Get-HttpsListeners)
    $matching = @($listeners | Where-Object {
        $item = Get-Item -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $item) { return $false }
        $thumbprint = Get-WsManListenerProperty -Listener $item -Name 'CertificateThumbprint'
        $listenerPort = Get-WsManListenerProperty -Listener $item -Name 'Port'
        $thumbprint -eq $Certificate.Thumbprint -and
        (-not [string]::IsNullOrWhiteSpace($listenerPort)) -and
        ([int]$listenerPort -eq $Port)
    })
    if ($matching.Count -eq 0) {
        foreach ($listener in $listeners) {
            Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
        }
        $created = New-Item -Path 'WSMan:\localhost\Listener' -Transport HTTPS -Address '*' -Hostname ([Environment]::MachineName) -CertificateThumbprint $Certificate.Thumbprint -Enabled $true -Force
        if ($null -eq $created) { $created = Get-HttpsListeners | Select-Object -Last 1 }
        Set-Item -LiteralPath "$($created.PSPath)\Port" -Value $Port -Force
        Write-Bilingual -Chinese "已创建 WinRM HTTPS 监听器（端口 $Port）" -English "Created the WinRM HTTPS listener on port $Port"
    }
    else {
        Write-Bilingual -Chinese "WinRM HTTPS 监听器已就绪（端口 $Port）" -English "WinRM HTTPS listener is already configured on port $Port"
    }
}

function Ensure-FirewallRule {
    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -eq $rule) {
        New-NetFirewallRule -Name $ruleName -DisplayName 'KSwordSandbox WinRM HTTPS' -Description 'Allow KSwordSandbox host remoting to this VMware guest' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
        Write-Bilingual -Chinese "已开放防火墙 TCP $Port" -English "Opened TCP $Port in Windows Firewall"
        return
    }
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    if ($null -ne $portFilter -and [string]$portFilter.LocalPort -ne [string]$Port) {
        Set-NetFirewallRule -Name $ruleName -Enabled False -ErrorAction Stop
        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
        New-NetFirewallRule -Name $ruleName -DisplayName 'KSwordSandbox WinRM HTTPS' -Description 'Allow KSwordSandbox host remoting to this VMware guest' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Any | Out-Null
    }
    Write-Bilingual -Chinese "防火墙规则已就绪" -English 'Windows Firewall rule is ready'
}

function Ensure-WorkingDirectory {
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory) -or $WorkingDirectory -notmatch '^[A-Za-z]:\\') {
        throw '来宾工作目录必须是本地磁盘上的绝对路径。 / Guest working directory must be an absolute local drive path.'
    }
    $full = [IO.Path]::GetFullPath($WorkingDirectory).TrimEnd('\')
    $drive = [IO.Path]::GetPathRoot($full)
    if ($full.Equals($drive.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw '来宾工作目录不能是磁盘根目录。 / Guest working directory cannot be a drive root.'
    }
    $relative = $full.Substring($drive.Length)
    if (@($relative.Split('\') | Where-Object { $_ -match '^(?i:Windows|Users|Program Files(?: \(x86\))?|ProgramData|Recovery|System Volume Information|\$Recycle\.Bin)$' }).Count -gt 0) {
        throw '来宾工作目录不能位于系统目录或用户目录中。 / Guest working directory cannot be inside a system or user profile tree.'
    }
    $walk = $full
    while ($true) {
        if (Test-Path -LiteralPath $walk) {
            if (((Get-Item -LiteralPath $walk -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw '来宾工作目录含有重解析点。 / Guest working directory contains a reparse point.'
            }
        }
        if ($walk.Equals($drive.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or $walk.Equals($drive, [StringComparison]::OrdinalIgnoreCase)) { break }
        $walk = Split-Path -Parent $walk
        if ([string]::IsNullOrWhiteSpace($walk)) { throw 'Guest working directory ancestry could not be verified.' }
    }
    $marker = Join-Path $full '.ksword-sandbox-guest-root'
    if (-not $full.Equals('C:\KSwordSandbox', [StringComparison]::OrdinalIgnoreCase) -and
        -not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        foreach ($reserved in @('incoming', 'out', 'agent')) {
            if (Test-Path -LiteralPath (Join-Path $full $reserved)) {
                throw "Custom guest working directory already contains '$reserved'; choose an empty directory or a previously bootstrapped KSwordSandbox directory."
            }
        }
    }
    if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
        New-Item -Path $WorkingDirectory -ItemType Directory -Force | Out-Null
    }
    if (Test-Path -LiteralPath $marker) {
        if (((Get-Item -LiteralPath $marker -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-Content -LiteralPath $marker -Raw -ErrorAction Stop).Trim() -ne 'KSwordSandbox guest working directory v1') {
            throw 'Guest working directory marker is invalid.'
        }
    }
    else {
        [IO.File]::WriteAllText($marker, "KSwordSandbox guest working directory v1`n", [Text.UTF8Encoding]::new($false))
    }
    Write-Bilingual -Chinese "工作目录已就绪：$WorkingDirectory" -English "Working directory is ready: $WorkingDirectory"
}

function Ensure-LabDefenderPolicy {
    if (-not $DisableDefenderForLab) {
        return
    }

    $setMpPreference = Get-Command Set-MpPreference -ErrorAction SilentlyContinue
    $addMpPreference = Get-Command Add-MpPreference -ErrorAction SilentlyContinue
    if ($null -eq $setMpPreference -or $null -eq $addMpPreference) {
        throw '未找到 Defender PowerShell cmdlet，无法为实验 VM 关闭阻断。 / Defender PowerShell cmdlets were not found; cannot disable blocking for this lab VM.'
    }

    $preference = @{
        DisableRealtimeMonitoring = $true
        DisableBehaviorMonitoring = $true
        DisableIOAVProtection = $true
        DisableScriptScanning = $true
        DisableArchiveScanning = $true
        PUAProtection = 'Disabled'
    }
    Set-MpPreference @preference
    foreach ($path in @($WorkingDirectory, (Join-Path $WorkingDirectory 'incoming'), (Join-Path $WorkingDirectory 'out'))) {
        Add-MpPreference -ExclusionPath $path
    }

    Write-Bilingual -Chinese '已为此一次性实验 VM 关闭 Defender 实时阻断，并排除 KSwordSandbox 工作目录' -English 'Disabled Defender real-time blocking and excluded the KSwordSandbox working tree for this disposable lab VM'
}

function Ensure-LocalWinRmAccessPolicy {
    $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    New-Item -Path $policyPath -Force | Out-Null
    New-ItemProperty -Path $policyPath -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Bilingual -Chinese '已允许本地管理员通过 WinRM 使用完整令牌（仅限此实验 VM）' -English 'Enabled full-token WinRM access for local administrators (this disposable lab VM only)'
}

Assert-Administrator
$user = Get-OrCreateGuestUser
Ensure-LocalAdministrator -User $user
Ensure-LocalWinRmAccessPolicy
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM
$certificate = Get-UsableWinRmCertificate
Ensure-WinRmHttpsListener -Certificate $certificate
Ensure-FirewallRule
Ensure-WorkingDirectory
Ensure-LabDefenderPolicy

$addresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
    $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'
} | ForEach-Object { $_.IPAddress } | Select-Object -Unique)
Write-Host ''
Write-Bilingual -Chinese '来宾 bootstrap 完成。请在宿主 WebUI 中选择 VMware、填入来宾用户名和密码，然后运行只读预检。' -English 'Guest bootstrap completed. In the host WebUI, choose VMware, enter the guest username and password, then run the read-only preflight.'
Write-Bilingual -Chinese "WinRM HTTPS 端口：$Port；证书指纹：$($certificate.Thumbprint)" -English "WinRM HTTPS port: $Port; certificate thumbprint: $($certificate.Thumbprint)"
Write-Bilingual -Chinese ("来宾 IPv4：" + ($(if ($addresses.Count -gt 0) { $addresses -join ', ' } else { '未发现，请稍后查看 ipconfig' }))) -English ("Guest IPv4: " + ($(if ($addresses.Count -gt 0) { $addresses -join ', ' } else { 'not found; check ipconfig later' })))
Write-Bilingual -Chinese '如果这是基线虚拟机，请现在关机并在 VMware 中创建 powered-off 的 Clean 快照。' -English 'If this is the baseline VM, power it off now and create a powered-off Clean snapshot in VMware.'
