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
