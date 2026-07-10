rule KSwordSandbox_Placeholder_Static_Executable
{
    meta:
        description = "Placeholder static rule file for future host-side YARA scanning"
        scope = "benign scaffold"
    condition:
        uint16(0) == 0x5A4D
}

rule KSwordSandbox_Static_Packer_Hints
{
    meta:
        description = "Lightweight packer markers aligned with StaticAnalyzer packer tags"
        scope = "triage"
        mitre = "T1027.002"
    strings:
        $upx_magic = "UPX!" ascii
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $aspack = "ASPack" ascii nocase
        $mpress = "MPRESS" ascii nocase
        $themida = "Themida" ascii nocase
        $vmprotect = "VMProtect" ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule KSwordSandbox_Static_Suspicious_Windows_Apis
{
    meta:
        description = "API strings mirrored by StaticAnalyzer suspicious import tags"
        scope = "triage"
        mitre = "T1106"
    strings:
        $inject1 = "VirtualAllocEx" ascii wide
        $inject2 = "WriteProcessMemory" ascii wide
        $inject3 = "CreateRemoteThread" ascii wide
        $inject4 = "QueueUserAPC" ascii wide
        $dyn1 = "GetProcAddress" ascii wide
        $dyn2 = "LoadLibrary" ascii wide
        $persist1 = "RegSetValue" ascii wide
        $persist2 = "CreateService" ascii wide
        $net1 = "InternetOpen" ascii wide
        $net2 = "WinHttpOpen" ascii wide
        $anti1 = "IsDebuggerPresent" ascii wide
        $anti2 = "NtQueryInformationProcess" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule KSwordSandbox_Static_Registration_Exports
{
    meta:
        description = "COM registration export names useful for regsvr32 triage"
        scope = "triage"
        mitre = "T1218.010"
    strings:
        $register = "DllRegisterServer" ascii
        $unregister = "DllUnregisterServer" ascii
        $install = "DllInstall" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule KSwordSandbox_Static_Network_Indicators
{
    meta:
        description = "URL and IPv4 strings mirrored by StaticAnalyzer network indicator tags"
        scope = "triage"
        mitre = "T1105"
    strings:
        $url_http = "http://" ascii wide nocase
        $url_https = "https://" ascii wide nocase
        $api_urlmon = "URLDownloadToFile" ascii wide
        $api_winhttp = "WinHttpSendRequest" ascii wide
        $api_wininet = "HttpSendRequest" ascii wide
        $ipv4 = /(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/ ascii
    condition:
        any of them
}

rule KSwordSandbox_Static_Script_Execution_Strings
{
    meta:
        description = "Script interpreter and encoded-command strings mirrored by StaticAnalyzer script tags"
        scope = "triage"
        mitre = "T1059"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $ps_enc1 = "-EncodedCommand" ascii wide nocase
        $ps_enc2 = "FromBase64String" ascii wide nocase
        $cmd = "cmd.exe" ascii wide nocase
        $wscript = "wscript" ascii wide nocase
        $cscript = "cscript" ascii wide nocase
        $mshta = "mshta" ascii wide nocase
        $rundll32 = "rundll32" ascii wide nocase
        $regsvr32 = "regsvr32" ascii wide nocase
        $certutil = "certutil" ascii wide nocase
        $bitsadmin = "bitsadmin" ascii wide nocase
    condition:
        any of them
}

rule KSwordSandbox_Static_FileDrop_And_Resource_Apis
{
    meta:
        description = "File creation and PE resource extraction APIs mirrored by StaticAnalyzer dropper/resource tags"
        scope = "triage"
        mitre = "T1027.009"
    strings:
        $file1 = "CreateFileW" ascii wide
        $file2 = "WriteFile" ascii wide
        $file3 = "CopyFile" ascii wide
        $file4 = "MoveFileEx" ascii wide
        $res1 = "FindResource" ascii wide
        $res2 = "LoadResource" ascii wide
        $res3 = "LockResource" ascii wide
        $res4 = "SizeofResource" ascii wide
        $mz = "MZ" ascii
    condition:
        uint16(0) == 0x5A4D and (any of ($file*) or (2 of ($res*) and $mz))
}

rule KSwordSandbox_Static_Persistence_Strings
{
    meta:
        description = "Run key, Startup folder, scheduled task, and service strings mirrored by StaticAnalyzer persistence tags"
        scope = "triage"
        mitre = "T1547.001"
    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $run2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $startup = "Start Menu\\Programs\\Startup" ascii wide nocase
        $services = "CurrentControlSet\\Services" ascii wide nocase
        $schtasks = "schtasks /create" ascii wide nocase
        $api_reg = "RegSetValue" ascii wide
        $api_svc = "CreateService" ascii wide
    condition:
        any of them
}

rule KSwordSandbox_Static_AntiAnalysis_Strings
{
    meta:
        description = "Debugger, sandbox, and VM strings mirrored by StaticAnalyzer anti-analysis tags"
        scope = "triage"
        mitre = "T1497"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $dbg3 = "NtQueryInformationProcess" ascii wide
        $dbg4 = "NtSetInformationThread" ascii wide
        $vm1 = "VirtualBox" ascii wide nocase
        $vm2 = "VMware" ascii wide nocase
        $vm3 = "sandboxie" ascii wide nocase
        $tool1 = "wireshark" ascii wide nocase
        $tool2 = "procmon" ascii wide nocase
        $tool3 = "x64dbg" ascii wide nocase
    condition:
        any of them
}

rule KSwordSandbox_Static_Discovery_And_AntiAnalysis_Apis
{
    meta:
        description = "System discovery, debugger, delay, and VM artifact APIs mirrored by StaticAnalyzer anti-analysis/discovery tags"
        scope = "triage"
        mitre = "T1497"
    strings:
        $sys1 = "GetSystemInfo" ascii wide
        $sys2 = "GlobalMemoryStatusEx" ascii wide
        $sys3 = "GetComputerName" ascii wide
        $sys4 = "GetUserName" ascii wide
        $proc1 = "CreateToolhelp32Snapshot" ascii wide
        $proc2 = "Process32First" ascii wide
        $proc3 = "EnumProcesses" ascii wide
        $delay1 = "NtDelayExecution" ascii wide
        $delay2 = "WaitForSingleObject" ascii wide
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $vm1 = "VirtualBox" ascii wide nocase
        $vm2 = "VMware" ascii wide nocase
        $tool1 = "procmon" ascii wide nocase
        $tool2 = "x64dbg" ascii wide nocase
    condition:
        any of them
}

rule KSwordSandbox_Static_IFEO_WMI_Winlogon_Persistence
{
    meta:
        description = "Persistence strings for IFEO debugger, WMI event subscriptions, and Winlogon helper paths"
        scope = "triage"
        mitre = "T1546"
    strings:
        $ifeo1 = "Image File Execution Options" ascii wide nocase
        $ifeo2 = "\\Debugger" ascii wide nocase
        $wmi1 = "__EventFilter" ascii wide
        $wmi2 = "CommandLineEventConsumer" ascii wide
        $wmi3 = "FilterToConsumerBinding" ascii wide
        $winlogon1 = "Winlogon\\Shell" ascii wide nocase
        $winlogon2 = "Winlogon\\Userinit" ascii wide nocase
        $winlogon3 = "Winlogon\\Notify" ascii wide nocase
        $com1 = "InprocServer32" ascii wide nocase
        $com2 = "LocalServer32" ascii wide nocase
    condition:
        any of them
}

rule KSwordSandbox_Static_Dropper_Network_Indicator_Depth
{
    meta:
        description = "Additional dropper and network indicator strings for report grouping"
        scope = "triage"
        mitre = "T1105"
    strings:
        $drop1 = "\\System32\\Tasks\\" ascii wide nocase
        $drop2 = "\\Windows\\System32\\" ascii wide nocase
        $drop3 = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $drop4 = "WriteFile" ascii wide
        $drop5 = "MoveFileEx" ascii wide
        $net1 = "InternetConnect" ascii wide
        $net2 = "HttpSendRequest" ascii wide
        $net3 = "WinHttpSendRequest" ascii wide
        $net4 = "WSAStartup" ascii wide
        $net5 = "getaddrinfo" ascii wide
    condition:
        any of them
}
