using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.StaticAnalysis;

/// <summary>
/// Performs lightweight host-side static analysis without external tooling.
/// Inputs are local sample paths, processing parses PE headers and extracts
/// bounded strings/URLs, and Analyze returns a StaticAnalysisResult for reports.
/// </summary>
public sealed class StaticAnalyzer
{
    private const int SectionHeaderSize = 40;
    private const int MinimumStringLength = 5;
    private const int MaxStrings = 160;
    private const int MaxUrls = 80;
    private const int MaxStringScanBytes = 32 * 1024 * 1024;
    private const int MaxImportDescriptors = 256;
    private const int MaxImportThunksPerDescriptor = 512;
    private const int MaxImportEvidence = 96;
    private const int MaxImportSummaryModules = 24;
    private const int MaxImportApiClusterEvidence = 12;
    private const int MaxExportNames = 64;
    private const int MaxTlsCallbacks = 32;
    private const int MaxCertificateEntries = 16;
    private const int MaxDebugEntries = 64;
    private const int MaxResourceEntries = 160;
    private const int MaxResourceEvidence = 96;
    private const int MaxResourceDepth = 4;
    private const int MaxPeStringLength = 180;
    private const int MaxResourceStringBytes = 64 * 1024;
    private const int MaxVersionStringEvidence = 16;
    private const int MaxStructuredPeEntries = 128;
    private const int MaxStructuredStringIndicators = 160;
    private const int MaxStaticYaraRuleFileBytes = 1024 * 1024;
    private const int MaxStaticYaraRuleMatches = 32;
    private const int MaxStaticYaraMatchedStringIds = 24;
    private const int MaxStaticAnalysisEvents = 256;
    private const int MaxStaticEventDataValueLength = 640;

    private static readonly Regex UrlPattern = new(
        @"https?://[^\s""'<>]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex Ipv4Pattern = new(
        @"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex EmailPattern = new(
        @"(?<![A-Z0-9._%+\-])(?:[A-Z0-9._%+\-]{1,64})@(?:[A-Z0-9\-]{1,63}\.)+[A-Z]{2,63}(?![A-Z0-9._%+\-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex DomainPattern = new(
        @"(?<![A-Z0-9_\-@])(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,63}|XN--[A-Z0-9\-]{2,59})(?![A-Z0-9_\-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex WindowsPathPattern = new(
        @"(?<![A-Za-z0-9])(?:[A-Za-z]:\\|\\\\)[^""'<>|\r\n]{3,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex RegistryPathPattern = new(
        @"\b(?:HKCU|HKLM|HKCR|HKU|HKCC|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^""'<>|\r\n]{3,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex ManifestRequestedExecutionLevelPattern = new(
        @"requestedExecutionLevel\b[^>]*\blevel\s*=\s*[""'](?<level>[^""']{1,64})[""']",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex StaticYaraRulePattern = new(
        @"(?ms)^\s*rule\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{(?<body>.*?)^\s*\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] ProcessInjectionApis =
    [
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtMapViewOfSection",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "SetThreadContext",
        "GetThreadContext",
        "ResumeThread"
    ];

    private static readonly string[] DynamicCodeApis =
    [
        "VirtualAlloc",
        "VirtualProtect",
        "NtProtectVirtualMemory",
        "LoadLibrary",
        "GetProcAddress",
        "MapViewOfFile",
        "CreateFileMapping"
    ];

    private static readonly string[] PersistenceApis =
    [
        "RegCreateKey",
        "RegSetValue",
        "RegOpenKey",
        "CreateService",
        "OpenSCManager",
        "StartService",
        "ChangeServiceConfig",
        "ShellExecute"
    ];

    private static readonly string[] RegistryPersistenceApis =
    [
        "RegCreateKey",
        "RegCreateKeyEx",
        "RegSetValue",
        "RegSetValueEx",
        "RegOpenKey",
        "RegOpenKeyEx",
        "RegDeleteValue"
    ];

    private static readonly string[] ServicePersistenceApis =
    [
        "CreateService",
        "OpenSCManager",
        "StartService",
        "ChangeServiceConfig",
        "ChangeServiceConfig2"
    ];

    private static readonly string[] NetworkApis =
    [
        "InternetOpen",
        "InternetConnect",
        "HttpOpenRequest",
        "HttpSendRequest",
        "InternetReadFile",
        "InternetWriteFile",
        "InternetCrackUrl",
        "URLDownloadToFile",
        "URLDownloadToCacheFile",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpReadData",
        "WinHttpWriteData",
        "WSAStartup",
        "WSASend",
        "WSARecv",
        "socket",
        "getaddrinfo",
        "connect",
        "send",
        "recv"
    ];

    private static readonly string[] DownloadApis =
    [
        "URLDownloadToFile",
        "URLDownloadToCacheFile",
        "InternetReadFile",
        "WinHttpReadData",
        "HttpSendRequest",
        "WinHttpSendRequest",
        "URLOpenBlockingStream",
        "URLOpenStream",
        "CoInternetCombineUrl"
    ];

    private static readonly string[] ExfiltrationApis =
    [
        "InternetWriteFile",
        "WinHttpWriteData",
        "send",
        "WSASend",
        "FtpPutFile"
    ];

    private static readonly string[] FileDropApis =
    [
        "CreateFileA",
        "CreateFileW",
        "CreateFile2",
        "WriteFile",
        "CopyFile",
        "MoveFile",
        "MoveFileEx",
        "ReplaceFile",
        "DeleteFile",
        "GetTempPath",
        "GetTempFileName",
        "ExpandEnvironmentStrings",
        "SHGetFolderPath",
        "SHGetKnownFolderPath"
    ];

    private static readonly string[] ScriptExecutionApis =
    [
        "CreateProcess",
        "ShellExecute",
        "WinExec",
        "system",
        "_wsystem",
        "CreateProcessAsUser",
        "CreateProcessWithLogon",
        "CreateProcessWithToken"
    ];

    private static readonly string[] ResourceApis =
    [
        "FindResource",
        "FindResourceEx",
        "LoadResource",
        "LockResource",
        "SizeofResource",
        "BeginUpdateResource",
        "UpdateResource",
        "EndUpdateResource"
    ];

    private static readonly string[] AntiAnalysisApis =
    [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
        "NtSetInformationThread",
        "OutputDebugString",
        "FindWindow",
        "EnumWindows",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "GetAdaptersInfo",
        "GetAdaptersAddresses",
        "GetComputerName",
        "GetUserName",
        "GetLastInputInfo",
        "GlobalMemoryStatusEx",
        "GetDiskFreeSpaceEx",
        "GetSystemInfo",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "NtDelayExecution",
        "Sleep"
    ];

    private static readonly string[] AntiDebugApis =
    [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
        "NtSetInformationThread",
        "OutputDebugString",
        "DebugActiveProcess",
        "DebugBreak",
        "ContinueDebugEvent",
        "WaitForDebugEvent"
    ];

    private static readonly string[] CredentialAccessApis =
    [
        "MiniDumpWriteDump",
        "CredEnumerate",
        "CredRead",
        "CredWrite",
        "CryptUnprotectData",
        "PStoreCreateInstance",
        "VaultEnumerateVaults",
        "VaultEnumerateItems",
        "VaultGetItem",
        "LsaEnumerateLogonSessions",
        "LsaGetLogonSessionData",
        "LsaOpenPolicy",
        "SamConnect",
        "SamOpenDomain",
        "OpenProcessToken",
        "DuplicateTokenEx",
        "ImpersonateLoggedOnUser",
        "LogonUser"
    ];

    private static readonly string[] DefenseEvasionApis =
    [
        "AmsiScanBuffer",
        "AmsiInitialize",
        "EtwEventWrite",
        "EventRegister",
        "OpenEventLog",
        "ClearEventLog",
        "ControlService",
        "DeleteService",
        "SetFileAttributes",
        "Wow64DisableWow64FsRedirection"
    ];

    private static readonly string[] SuspiciousApiStrings =
        ProcessInjectionApis
            .Concat(DynamicCodeApis)
            .Concat(PersistenceApis)
            .Concat(NetworkApis)
            .Concat(DownloadApis)
            .Concat(ExfiltrationApis)
            .Concat(FileDropApis)
            .Concat(ScriptExecutionApis)
            .Concat(ResourceApis)
            .Concat(AntiAnalysisApis)
            .Concat(AntiDebugApis)
            .Concat(CredentialAccessApis)
            .Concat(DefenseEvasionApis)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static readonly string[] SuspiciousApiStringMarkers =
        SuspiciousApiStrings
            .Where(api => !string.Equals(api, "connect", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "send", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "recv", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "Sleep", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "system", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "_wsystem", StringComparison.OrdinalIgnoreCase))
            .ToArray();

    private static readonly string[] CommonDomainTlds =
    [
        "com", "net", "org", "info", "biz", "ru", "cn", "top", "xyz", "online",
        "site", "club", "cc", "tk", "ml", "ga", "cf", "gq", "co", "io",
        "me", "dev", "app", "cloud", "tech", "win", "work", "live", "link",
        "click", "stream", "shop", "store", "pw", "su", "ws", "pro", "us",
        "uk", "de", "fr", "nl", "br", "jp", "kr", "in", "au", "ca",
        "eu", "pl", "tr", "it", "es", "ch", "se", "no", "fi", "dk",
        "cz", "ro", "ua", "by", "ir", "vn", "tw", "hk", "sg", "th",
        "id", "my", "ph", "nz", "za", "mx", "ar", "cl", "be", "at",
        "pt", "gr", "il", "ae", "sa", "onion"
    ];

    private static readonly string[] ReferenceDomainSuffixes =
    [
        "microsoft.com",
        "windows.com",
        "w3.org",
        "schemas.xmlsoap.org",
        "ietf.org"
    ];

    private static readonly string[] DynamicDnsDomainMarkers =
    [
        "duckdns.org",
        "no-ip.",
        "noip.",
        "ddns.",
        "dynu.",
        "hopto.org",
        "serveftp.",
        "sytes.net",
        "myqnapcloud.com"
    ];

    private static readonly string[] PackerStringMarkers =
    [
        "UPX!",
        "UPX0",
        "UPX1",
        "UPX2",
        "ASPack",
        "ASProtect",
        "MPRESS",
        "Themida",
        "VMProtect",
        "Enigma Protector",
        "PECompact",
        "FSG!",
        "Petite",
        "Obsidium",
        "Armadillo",
        "MoleBox"
    ];

    private static readonly string[] PackerSectionNames =
    [
        "UPX",
        ".aspack",
        ".adata",
        "MPRESS",
        ".mpress",
        ".petite",
        ".vmp",
        ".vmp0",
        ".vmp1",
        ".packed",
        ".themida",
        ".enigma",
        ".fsg",
        ".mew",
        ".asprotect",
        ".boom"
    ];

    private static readonly string[] ScriptInterpreterMarkers =
    [
        "powershell",
        "pwsh",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "wmic",
        "schtasks",
        "reg.exe",
        "installutil",
        "msiexec",
        "msbuild",
        "regasm",
        "regsvcs",
        "cmstp",
        "odbcconf",
        "forfiles",
        "hh.exe",
        "xwizard",
        "msxsl"
    ];

    private static readonly string[] LolbinCommandMarkers =
    [
        "rundll32",
        "regsvr32",
        "mshta",
        "certutil",
        "bitsadmin",
        "wmic",
        "schtasks",
        "reg.exe",
        "installutil",
        "msiexec",
        "msbuild",
        "regasm",
        "regsvcs",
        "cmstp",
        "odbcconf",
        "forfiles",
        "hh.exe",
        "xwizard",
        "msxsl"
    ];

    private static readonly string[] ServiceStringMarkers =
    [
        "CurrentControlSet\\Services\\",
        "ControlSet001\\Services\\",
        "ControlSet002\\Services\\",
        "CreateService",
        "ChangeServiceConfig",
        "OpenSCManager",
        "ServiceMain",
        "SvchostPushServiceGlobals",
        "ServiceDll",
        "New-Service",
        "Set-Service",
        "Start-Service",
        "Stop-Service",
        "sc.exe create",
        "sc.exe config",
        "sc.exe failure"
    ];

    private static readonly string[] ScheduledTaskStringMarkers =
    [
        "\\System32\\Tasks\\",
        "\\SysWOW64\\Tasks\\",
        "Schedule\\TaskCache\\Tree\\",
        "Schedule\\TaskCache\\Tasks\\",
        "Windows NT\\CurrentVersion\\Schedule\\TaskCache\\",
        "Register-ScheduledTask",
        "New-ScheduledTask",
        "New-ScheduledTaskAction",
        "Set-ScheduledTask",
        "Schedule.Service",
        "IRegisteredTask",
        "ITaskService",
        "schtasks /create",
        "schtasks.exe /create",
        "schtasks /change",
        "schtasks.exe /change"
    ];

    private static readonly string[] VersionStringKeys =
    [
        "CompanyName",
        "FileDescription",
        "FileVersion",
        "InternalName",
        "OriginalFilename",
        "ProductName",
        "ProductVersion",
        "LegalCopyright"
    ];

    private static readonly string[] EncodedCommandMarkers =
    [
        "-enc",
        "-encodedcommand",
        "frombase64string",
        "iex ",
        "invoke-expression"
    ];

    private static readonly string[] DownloadCommandMarkers =
    [
        "invoke-webrequest",
        "invoke-restmethod",
        "start-bitstransfer",
        "bitsadmin",
        "certutil -urlcache",
        "certutil.exe -urlcache",
        "curl ",
        "curl.exe",
        "wget ",
        "wget.exe",
        "msiexec /i http",
        "msiexec.exe /i http"
    ];

    private static readonly string[] ExfilCommandMarkers =
    [
        "--upload-file",
        "-F file=",
        "curl -F",
        "curl.exe -F",
        "ftp -s:",
        "WinHttpWriteData",
        "InternetWriteFile"
    ];

    private static readonly string[] DownloadExecuteCommandMarkers =
    [
        ".exe",
        ".dll",
        ".scr",
        ".com",
        ".msi",
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".hta",
        "Start-Process",
        "Invoke-Expression",
        "iex ",
        "cmd /c",
        "powershell -",
        "pwsh -",
        "rundll32",
        "regsvr32",
        "mshta",
        "CreateProcess",
        "ShellExecute",
        "WinExec"
    ];

    private static readonly string[] CredentialStringMarkers =
    [
        "mimikatz",
        "sekurlsa",
        "lsadump",
        "MiniDumpWriteDump",
        "procdump",
        "lsass.exe",
        "\\SAM",
        "\\SECURITY",
        "\\NTDS.dit",
        "CryptUnprotectData",
        "VaultEnumerate",
        "CredEnumerate"
    ];

    private static readonly string[] DefenseEvasionStringMarkers =
    [
        "Set-MpPreference",
        "Add-MpPreference",
        "DisableRealtimeMonitoring",
        "AMSI",
        "EtwEventWrite",
        "wevtutil cl",
        "Clear-EventLog",
        "sc stop WinDefend",
        "taskkill /im MsMpEng",
        "netsh advfirewall set"
    ];

    private static readonly string[] AntiDebugStringMarkers =
    [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "ProcessDebugPort",
        "ProcessDebugFlags",
        "ProcessDebugObjectHandle",
        "BeingDebugged",
        "KdDebuggerEnabled",
        "OutputDebugString",
        "x64dbg",
        "ollydbg",
        "windbg",
        "idaq",
        "ida64"
    ];

    private static readonly string[] AntiSandboxStringMarkers =
    [
        "sandboxie",
        "virtualbox",
        "vbox",
        "vmware",
        "qemu",
        "xen",
        "wireshark",
        "procmon",
        "process monitor",
        "ollydbg",
        "x64dbg",
        "idaq",
        "ida64"
    ];

    /// <summary>
    /// Analyzes one local file.
    /// The input is a full or relative path, processing parses metadata and
    /// extracts bounded strings, and the method returns a static-analysis model.
    /// </summary>
    public StaticAnalysisResult Analyze(string samplePath)
    {
        var fullPath = Path.GetFullPath(samplePath);
        var warnings = new List<string>();
        var tags = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var urls = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var interestingStrings = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var stringEvidence = new StaticStringEvidence();

        using var stream = File.OpenRead(fullPath);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var header = ParsePe(reader, stream.Length, tags, interestingStrings, warnings);
        ExtractStrings(fullPath, tags, urls, interestingStrings, warnings, stringEvidence);

        return header with
        {
            NetworkIndicators = stringEvidence.NetworkIndicators,
            PathIndicators = stringEvidence.PathIndicators,
            CommandIndicators = stringEvidence.CommandIndicators,
            SuspiciousStrings = stringEvidence.SuspiciousStrings,
            Tags = tags.ToList(),
            Urls = urls.Take(MaxUrls).ToList(),
            InterestingStrings = interestingStrings.Take(MaxStrings).ToList(),
            Warnings = warnings
        };
    }

    /// <summary>
    /// Runs static analysis and projects the result into normalized events.
    /// Inputs are a local sample path; processing reuses Analyze so no external
    /// tools or binary dependencies are required; the method returns bounded
    /// host-side events for rules, live views, or diagnostics.
    /// </summary>
    public IReadOnlyList<SandboxEvent> AnalyzeToEvents(string samplePath)
    {
        var result = Analyze(samplePath);
        return CreateEvents(samplePath, result);
    }

    /// <summary>
    /// Projects a StaticAnalysisResult into normalized SandboxEvent rows.
    /// Inputs are a sample path plus an already computed static-analysis model;
    /// processing emits bounded PE import/export/TLS/section, string, packer,
    /// overlay, and built-in YARA-like match events; the method returns a
    /// backward-compatible event view without mutating the model.
    /// </summary>
    public static IReadOnlyList<SandboxEvent> CreateEvents(string samplePath, StaticAnalysisResult result)
    {
        var fullPath = Path.GetFullPath(samplePath);
        var events = new List<SandboxEvent>();

        AddStaticSummaryEvent(fullPath, result, events);
        AddStaticSectionEvents(fullPath, result, events);
        AddStaticImportEvents(fullPath, result, events);
        AddStaticExportEvents(fullPath, result, events);
        AddStaticTlsEvents(fullPath, result, events);
        AddStaticResourceEvents(fullPath, result, events);
        AddStaticOverlayEvent(fullPath, result, events);
        AddStaticStringEvents(fullPath, result, events);
        AddStaticPackerEvent(fullPath, result, events);
        AddStaticYaraEvents(fullPath, result, events);

        return events;
    }

    /// <summary>
    /// Parses the DOS and PE headers when present.
    /// Inputs are a BinaryReader, file size, tag set, and warning list;
    /// processing reads PE header fields and section metadata; the method
    /// returns a partially populated StaticAnalysisResult and static evidence.
    /// </summary>
    private static StaticAnalysisResult ParsePe(BinaryReader reader, long fileLength, SortedSet<string> tags, SortedSet<string> interestingStrings, List<string> warnings)
    {
        if (fileLength < 64)
        {
            warnings.Add("File is too small to contain a complete PE header.");
            tags.Add("too_small");
            return new StaticAnalysisResult { FileFormat = "unknown", Magic = "short file" };
        }

        var mz = reader.ReadUInt16();
        if (mz != 0x5a4d)
        {
            tags.Add("not_pe");
            return new StaticAnalysisResult { FileFormat = "unknown", Magic = $"0x{mz:X4}" };
        }

        reader.BaseStream.Position = 0x3c;
        var peOffset = reader.ReadUInt32();
        if (peOffset > fileLength - 24)
        {
            warnings.Add("MZ header points outside the file.");
            tags.Add("invalid_pe_offset");
            return new StaticAnalysisResult { FileFormat = "MZ", Magic = "MZ" };
        }

        reader.BaseStream.Position = peOffset;
        var peSignature = reader.ReadUInt32();
        if (peSignature != 0x00004550)
        {
            warnings.Add("PE signature was not found at the DOS header offset.");
            tags.Add("invalid_pe_signature");
            return new StaticAnalysisResult { FileFormat = "MZ", Magic = "MZ" };
        }

        var machine = reader.ReadUInt16();
        var sectionCount = reader.ReadUInt16();
        reader.BaseStream.Position += 12;
        var optionalHeaderSize = reader.ReadUInt16();
        reader.BaseStream.Position += 2;

        var optionalHeaderOffset = reader.BaseStream.Position;
        var optionalMagic = reader.ReadUInt16();
        var entryPoint = ReadUInt32At(reader, optionalHeaderOffset + 16, fileLength, warnings);
        var subsystem = ReadUInt16At(reader, optionalHeaderOffset + 68, fileLength, warnings);
        var imageBase = ReadImageBase(reader, optionalHeaderOffset, optionalMagic, fileLength, warnings);
        var dataDirectories = ReadDataDirectories(reader, optionalHeaderOffset, optionalHeaderSize, optionalMagic, fileLength, warnings);
        var sectionHeadersOffset = optionalHeaderOffset + optionalHeaderSize;

        var sectionLayouts = new List<PeSectionLayout>();
        var peEvidence = new PeAnalysisEvidence();
        var sections = ReadSections(reader, sectionHeadersOffset, sectionCount, fileLength, tags, warnings, sectionLayouts, interestingStrings);
        var architecture = DescribeArchitecture(machine, optionalMagic);
        var subsystemText = DescribeSubsystem(subsystem);
        AddPeTags(optionalMagic, subsystemText, sections, tags);
        AnalyzePeDataDirectories(reader, dataDirectories, sectionLayouts, optionalMagic, imageBase, fileLength, tags, interestingStrings, warnings, peEvidence);
        AnalyzePeOverlayAndSignature(reader, dataDirectories, sectionLayouts, fileLength, tags, interestingStrings, warnings, peEvidence);

        return new StaticAnalysisResult
        {
            FileFormat = optionalMagic == 0x20b ? "PE32+" : optionalMagic == 0x10b ? "PE32" : "PE",
            Magic = "MZ/PE",
            IsPe = true,
            Architecture = architecture,
            Machine = $"0x{machine:X4}",
            Subsystem = subsystemText,
            EntryPointRva = $"0x{entryPoint:X8}",
            SectionCount = sectionCount,
            Sections = sections,
            Imports = peEvidence.Imports,
            ImportApiClusters = peEvidence.ImportApiClusters,
            ExportModuleName = peEvidence.ExportModuleName,
            ExportNames = peEvidence.ExportNames,
            Tls = peEvidence.Tls,
            Overlay = peEvidence.Overlay,
            Resources = peEvidence.Resources
        };
    }

    /// <summary>
    /// Reads PE section headers and calculates raw-data entropy.
    /// Inputs are reader, section offset, count, file length, tag set, and
    /// warnings; processing validates bounds defensively; the method returns
    /// section summaries.
    /// </summary>
    private static List<PeSectionInfo> ReadSections(
        BinaryReader reader,
        long sectionHeadersOffset,
        int sectionCount,
        long fileLength,
        SortedSet<string> tags,
        List<string> warnings,
        List<PeSectionLayout> layouts,
        SortedSet<string> interestingStrings)
    {
        var sections = new List<PeSectionInfo>();
        if (sectionCount <= 0 || sectionCount > 96)
        {
            warnings.Add($"Unusual PE section count: {sectionCount}.");
            tags.Add("section_count_exception");
            return sections;
        }

        for (var index = 0; index < sectionCount; index++)
        {
            var offset = sectionHeadersOffset + index * SectionHeaderSize;
            if (offset < 0 || offset > fileLength - SectionHeaderSize)
            {
                warnings.Add($"Section header {index} is outside the file.");
                break;
            }

            reader.BaseStream.Position = offset;
            var name = ReadSectionName(reader.ReadBytes(8));
            var virtualSize = reader.ReadUInt32();
            var virtualAddress = reader.ReadUInt32();
            var rawSize = reader.ReadUInt32();
            var rawPointer = reader.ReadUInt32();
            reader.BaseStream.Position += 12;
            var characteristics = reader.ReadUInt32();
            var entropy = CalculateEntropy(reader, rawPointer, rawSize, fileLength, warnings);
            AddSectionTags(name, entropy, virtualSize, rawSize, characteristics, tags);
            layouts.Add(new PeSectionLayout(name, virtualAddress, virtualSize, rawSize, rawPointer));
            AddInterestingString(
                interestingStrings,
                $"section:{name},va=0x{virtualAddress:X8},vsize={virtualSize},raw={rawSize},entropy={Math.Round(entropy, 3):F3}");

            sections.Add(new PeSectionInfo
            {
                Name = name,
                VirtualAddress = $"0x{virtualAddress:X8}",
                RawDataOffset = $"0x{rawPointer:X8}",
                VirtualSize = virtualSize,
                RawDataSize = rawSize,
                Entropy = Math.Round(entropy, 3),
                EntropyLabel = DescribeEntropy(entropy, rawSize),
                Characteristics = $"0x{characteristics:X8}",
                IsExecutable = (characteristics & 0x20000000) != 0,
                IsWritable = (characteristics & 0x80000000) != 0
            });
        }

        return sections;
    }

    /// <summary>
    /// Extracts bounded ASCII and UTF-16 strings and URL-like values.
    /// Inputs are a file path and output collections, processing scans up to a
    /// fixed byte limit, and the method returns no value.
    /// </summary>
    private static void ExtractStrings(
        string fullPath,
        SortedSet<string> tags,
        SortedSet<string> urls,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        StaticStringEvidence stringEvidence)
    {
        var fileInfo = new FileInfo(fullPath);
        var readLength = (int)Math.Min(fileInfo.Length, MaxStringScanBytes);
        if (fileInfo.Length > MaxStringScanBytes)
        {
            warnings.Add($"String scan truncated at {MaxStringScanBytes} bytes.");
            tags.Add("string_scan_truncated");
        }

        var buffer = new byte[readLength];
        using (var stream = File.OpenRead(fullPath))
        {
            var totalRead = 0;
            while (totalRead < readLength)
            {
                var read = stream.Read(buffer, totalRead, readLength - totalRead);
                if (read == 0)
                {
                    break;
                }

                totalRead += read;
            }
        }

        foreach (var text in EnumerateAsciiStrings(buffer).Concat(EnumerateUtf16Strings(buffer)))
        {
            AddStringClassifications(text, tags, urls, interestingStrings, stringEvidence);
            if (urls.Count >= MaxUrls && interestingStrings.Count >= MaxStrings)
            {
                break;
            }
        }

        ApplyStaticNotesYaraRules(fullPath, buffer, tags, interestingStrings);
    }

    /// <summary>
    /// Applies optional static-notes YARA rules with a tiny built-in matcher.
    /// Inputs are the existing static scan buffer and tag/evidence outputs;
    /// processing finds rules/static-notes.yar and matches the small supported
    /// subset; the method silently returns when rules or matcher support are
    /// unavailable.
    /// </summary>
    private static void ApplyStaticNotesYaraRules(
        string fullPath,
        byte[] buffer,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings)
    {
        try
        {
            var rulesPath = ResolveStaticNotesYaraPath(fullPath);
            if (rulesPath is null)
            {
                return;
            }

            var rulesText = TryReadStaticYaraRules(rulesPath);
            if (string.IsNullOrWhiteSpace(rulesText))
            {
                return;
            }

            var rules = ParseStaticYaraRules(rulesText);
            if (rules.Count == 0)
            {
                return;
            }

            var context = new StaticYaraScanContext(buffer);
            var matchCount = 0;
            foreach (var rule in rules)
            {
                var match = MatchStaticYaraRule(rule, context);
                if (match is null)
                {
                    continue;
                }

                AddStaticYaraMatch(rule, match, tags, interestingStrings);
                matchCount++;
                if (matchCount >= MaxStaticYaraRuleMatches)
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (IsStaticYaraDowngradeException(ex))
        {
            // Optional YARA support must never make static analysis fail.
        }
    }

    /// <summary>
    /// Locates rules/static-notes.yar from likely repo or app roots.
    /// </summary>
    private static string? ResolveStaticNotesYaraPath(string samplePath)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in CandidateStaticYaraSearchRoots(samplePath))
        {
            foreach (var directory in EnumerateSelfAndParents(root))
            {
                if (!seen.Add(directory))
                {
                    continue;
                }

                var candidate = Path.Combine(directory, "rules", "static-notes.yar");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Returns directory roots used to resolve optional static YARA rules.
    /// </summary>
    private static IEnumerable<string> CandidateStaticYaraSearchRoots(string samplePath)
    {
        yield return Environment.CurrentDirectory;
        yield return AppContext.BaseDirectory;

        var sampleDirectory = Path.GetDirectoryName(samplePath);
        if (!string.IsNullOrWhiteSpace(sampleDirectory))
        {
            yield return sampleDirectory;
        }
    }

    /// <summary>
    /// Enumerates a directory and its parents.
    /// </summary>
    private static IEnumerable<string> EnumerateSelfAndParents(string startDirectory)
    {
        var directory = new DirectoryInfo(Path.GetFullPath(startDirectory));
        while (directory is not null)
        {
            yield return directory.FullName;
            directory = directory.Parent;
        }
    }

    /// <summary>
    /// Reads the optional YARA rule file only when it stays lightweight.
    /// </summary>
    private static string? TryReadStaticYaraRules(string rulesPath)
    {
        var fileInfo = new FileInfo(rulesPath);
        if (!fileInfo.Exists ||
            fileInfo.Length <= 0 ||
            fileInfo.Length > MaxStaticYaraRuleFileBytes)
        {
            return null;
        }

        using var stream = File.OpenRead(rulesPath);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    /// <summary>
    /// Parses the subset of YARA used by rules/static-notes.yar.
    /// </summary>
    private static List<StaticYaraRule> ParseStaticYaraRules(string rulesText)
    {
        var rules = new List<StaticYaraRule>();
        foreach (Match match in StaticYaraRulePattern.Matches(rulesText))
        {
            var name = match.Groups["name"].Value.Trim();
            var body = match.Groups["body"].Value;
            var rule = ParseStaticYaraRule(name, body);
            if (!string.IsNullOrWhiteSpace(rule.Condition))
            {
                rules.Add(rule);
            }
        }

        return rules;
    }

    /// <summary>
    /// Parses one rule body into meta, string, and condition sections.
    /// </summary>
    private static StaticYaraRule ParseStaticYaraRule(string name, string body)
    {
        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var strings = new List<StaticYaraString>();
        var condition = new StringBuilder();
        var section = string.Empty;

        foreach (var rawLine in body.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var line = StripStaticYaraLineComment(rawLine).Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.Equals("meta:", StringComparison.OrdinalIgnoreCase))
            {
                section = "meta";
                continue;
            }

            if (line.Equals("strings:", StringComparison.OrdinalIgnoreCase))
            {
                section = "strings";
                continue;
            }

            if (line.Equals("condition:", StringComparison.OrdinalIgnoreCase))
            {
                section = "condition";
                continue;
            }

            if (section.Equals("meta", StringComparison.OrdinalIgnoreCase))
            {
                TryParseStaticYaraMeta(line, meta);
            }
            else if (section.Equals("strings", StringComparison.OrdinalIgnoreCase))
            {
                var yaraString = TryParseStaticYaraString(line);
                if (yaraString is not null)
                {
                    strings.Add(yaraString);
                }
            }
            else if (section.Equals("condition", StringComparison.OrdinalIgnoreCase))
            {
                condition.Append(' ').Append(line);
            }
        }

        return new StaticYaraRule(name, meta, strings, condition.ToString().Trim());
    }

    /// <summary>
    /// Removes // comments while preserving quoted string and regex content.
    /// </summary>
    private static string StripStaticYaraLineComment(string line)
    {
        var inQuote = false;
        var inRegex = false;
        var escaped = false;
        for (var index = 0; index + 1 < line.Length; index++)
        {
            var current = line[index];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if ((inQuote || inRegex) && current == '\\')
            {
                escaped = true;
                continue;
            }

            if (!inRegex && current == '"')
            {
                inQuote = !inQuote;
                continue;
            }

            if (!inQuote && current == '/')
            {
                if (line[index + 1] == '/')
                {
                    return line[..index];
                }

                inRegex = !inRegex;
            }
        }

        return line;
    }

    /// <summary>
    /// Parses one YARA meta assignment.
    /// </summary>
    private static void TryParseStaticYaraMeta(string line, Dictionary<string, string> meta)
    {
        var equalsIndex = line.IndexOf('=');
        if (equalsIndex <= 0)
        {
            return;
        }

        var key = line[..equalsIndex].Trim();
        var valueText = line[(equalsIndex + 1)..].Trim().TrimEnd(',');
        if (key.Length == 0)
        {
            return;
        }

        if (valueText.StartsWith('"') &&
            TryReadStaticYaraQuotedString(valueText, out var quoted, out _))
        {
            meta[key] = quoted;
            return;
        }

        if (valueText.Length > 0)
        {
            meta[key] = valueText;
        }
    }

    /// <summary>
    /// Parses one YARA string definition.
    /// </summary>
    private static StaticYaraString? TryParseStaticYaraString(string line)
    {
        if (!line.StartsWith('$'))
        {
            return null;
        }

        var equalsIndex = line.IndexOf('=');
        if (equalsIndex <= 1)
        {
            return null;
        }

        var identifier = line[1..equalsIndex].Trim();
        if (!IsStaticYaraIdentifier(identifier))
        {
            return null;
        }

        var valueAndModifiers = line[(equalsIndex + 1)..].Trim();
        if (valueAndModifiers.StartsWith('"') &&
            TryReadStaticYaraQuotedString(valueAndModifiers, out var literal, out var literalLength))
        {
            return new StaticYaraString(
                identifier,
                StaticYaraStringKind.Literal,
                literal,
                null,
                ParseStaticYaraModifiers(valueAndModifiers[literalLength..]));
        }

        if (valueAndModifiers.StartsWith('/') &&
            TryReadStaticYaraRegex(valueAndModifiers, out var pattern, out var regexLength))
        {
            return new StaticYaraString(
                identifier,
                StaticYaraStringKind.Regex,
                null,
                pattern,
                ParseStaticYaraModifiers(valueAndModifiers[regexLength..]));
        }

        return null;
    }

    /// <summary>
    /// Reads a quoted YARA string literal and decodes common escapes.
    /// </summary>
    private static bool TryReadStaticYaraQuotedString(string text, out string value, out int consumed)
    {
        var builder = new StringBuilder();
        value = string.Empty;
        consumed = 0;

        for (var index = 1; index < text.Length; index++)
        {
            var current = text[index];
            if (current == '"')
            {
                value = builder.ToString();
                consumed = index + 1;
                return true;
            }

            if (current != '\\' || index + 1 >= text.Length)
            {
                builder.Append(current);
                continue;
            }

            var next = text[++index];
            switch (next)
            {
                case 'n':
                    builder.Append('\n');
                    break;
                case 'r':
                    builder.Append('\r');
                    break;
                case 't':
                    builder.Append('\t');
                    break;
                case 'x' when index + 2 < text.Length &&
                              byte.TryParse(text.Substring(index + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexValue):
                    builder.Append((char)hexValue);
                    index += 2;
                    break;
                default:
                    builder.Append(next);
                    break;
            }
        }

        return false;
    }

    /// <summary>
    /// Reads a slash-delimited YARA regex pattern.
    /// </summary>
    private static bool TryReadStaticYaraRegex(string text, out string pattern, out int consumed)
    {
        var builder = new StringBuilder();
        pattern = string.Empty;
        consumed = 0;
        var escaped = false;

        for (var index = 1; index < text.Length; index++)
        {
            var current = text[index];
            if (escaped)
            {
                builder.Append('\\').Append(current);
                escaped = false;
                continue;
            }

            if (current == '\\')
            {
                escaped = true;
                continue;
            }

            if (current == '/')
            {
                pattern = builder.ToString();
                consumed = index + 1;
                return true;
            }

            builder.Append(current);
        }

        if (escaped)
        {
            builder.Append('\\');
        }

        return false;
    }

    /// <summary>
    /// Parses supported YARA string modifiers.
    /// </summary>
    private static HashSet<string> ParseStaticYaraModifiers(string text)
    {
        return text
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(token => token.Trim().TrimEnd(',').ToLowerInvariant())
            .Where(token => token.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Tests whether a token is a simple YARA identifier.
    /// </summary>
    private static bool IsStaticYaraIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !(char.IsLetter(value[0]) || value[0] == '_'))
        {
            return false;
        }

        return value.All(character => char.IsLetterOrDigit(character) || character == '_');
    }

    /// <summary>
    /// Matches one parsed static YARA rule against the scan buffer.
    /// </summary>
    private static StaticYaraRuleMatch? MatchStaticYaraRule(StaticYaraRule rule, StaticYaraScanContext context)
    {
        var matchedStringIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var yaraString in rule.Strings)
        {
            if (MatchesStaticYaraString(yaraString, context))
            {
                matchedStringIds.Add(yaraString.Identifier);
            }
        }

        if (!EvaluateStaticYaraCondition(rule.Condition, rule.Strings, matchedStringIds, context.Buffer))
        {
            return null;
        }

        return new StaticYaraRuleMatch(
            rule.Name,
            matchedStringIds
                .OrderBy(identifier => identifier, StringComparer.OrdinalIgnoreCase)
                .Take(MaxStaticYaraMatchedStringIds)
                .ToList());
    }

    /// <summary>
    /// Matches one YARA string definition using supported modifiers.
    /// </summary>
    private static bool MatchesStaticYaraString(StaticYaraString yaraString, StaticYaraScanContext context)
    {
        var ignoreCase = yaraString.Modifiers.Contains("nocase");
        if (yaraString.Kind == StaticYaraStringKind.Regex)
        {
            return MatchesStaticYaraRegex(yaraString, context, ignoreCase);
        }

        if (string.IsNullOrEmpty(yaraString.Literal))
        {
            return false;
        }

        var ascii = yaraString.Modifiers.Contains("ascii") || !yaraString.Modifiers.Contains("wide");
        var wide = yaraString.Modifiers.Contains("wide");
        return ascii && ContainsBytes(context.Buffer, Encoding.ASCII.GetBytes(yaraString.Literal), ignoreCase) ||
               wide && ContainsWideLiteral(context.Buffer, yaraString.Literal, ignoreCase);
    }

    /// <summary>
    /// Matches one YARA regex string against a Latin-1 projection of the bytes.
    /// </summary>
    private static bool MatchesStaticYaraRegex(StaticYaraString yaraString, StaticYaraScanContext context, bool ignoreCase)
    {
        if (string.IsNullOrWhiteSpace(yaraString.Pattern))
        {
            return false;
        }

        var options = RegexOptions.CultureInvariant;
        if (ignoreCase)
        {
            options |= RegexOptions.IgnoreCase;
        }

        try
        {
            return Regex.IsMatch(context.AsciiText, yaraString.Pattern, options, TimeSpan.FromMilliseconds(200));
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// Evaluates the lightweight YARA condition subset used by static notes.
    /// </summary>
    private static bool EvaluateStaticYaraCondition(
        string condition,
        IReadOnlyList<StaticYaraString> strings,
        HashSet<string> matchedStringIds,
        byte[] buffer)
    {
        if (string.IsNullOrWhiteSpace(condition))
        {
            return false;
        }

        var tokens = TokenizeStaticYaraCondition(condition);
        if (tokens.Count == 0)
        {
            return false;
        }

        var parser = new StaticYaraConditionParser(tokens, strings, matchedStringIds, buffer);
        return parser.Parse();
    }

    /// <summary>
    /// Tokenizes the condition syntax needed by rules/static-notes.yar.
    /// </summary>
    private static List<StaticYaraConditionToken> TokenizeStaticYaraCondition(string condition)
    {
        var tokens = new List<StaticYaraConditionToken>();
        var index = 0;
        while (index < condition.Length)
        {
            var current = condition[index];
            if (char.IsWhiteSpace(current))
            {
                index++;
                continue;
            }

            if (current == '$')
            {
                var start = index++;
                while (index < condition.Length && (char.IsLetterOrDigit(condition[index]) || condition[index] == '_'))
                {
                    index++;
                }

                if (index < condition.Length && condition[index] == '*')
                {
                    index++;
                }

                tokens.Add(new StaticYaraConditionToken(StaticYaraConditionTokenKind.StringIdentifier, condition[start..index]));
                continue;
            }

            if (current == '(')
            {
                tokens.Add(new StaticYaraConditionToken(StaticYaraConditionTokenKind.OpenParen, current.ToString()));
                index++;
                continue;
            }

            if (current == ')')
            {
                tokens.Add(new StaticYaraConditionToken(StaticYaraConditionTokenKind.CloseParen, current.ToString()));
                index++;
                continue;
            }

            if (current == ',')
            {
                tokens.Add(new StaticYaraConditionToken(StaticYaraConditionTokenKind.Comma, current.ToString()));
                index++;
                continue;
            }

            if (current == '=' && index + 1 < condition.Length && condition[index + 1] == '=')
            {
                tokens.Add(new StaticYaraConditionToken(StaticYaraConditionTokenKind.Equals, "=="));
                index += 2;
                continue;
            }

            if (char.IsLetter(current) || current == '_')
            {
                var start = index++;
                while (index < condition.Length && (char.IsLetterOrDigit(condition[index]) || condition[index] == '_'))
                {
                    index++;
                }

                tokens.Add(new StaticYaraConditionToken(StaticYaraConditionTokenKind.Identifier, condition[start..index]));
                continue;
            }

            if (char.IsDigit(current))
            {
                var start = index++;
                if (current == '0' && index < condition.Length && condition[index] is 'x' or 'X')
                {
                    index++;
                    while (index < condition.Length && Uri.IsHexDigit(condition[index]))
                    {
                        index++;
                    }
                }
                else
                {
                    while (index < condition.Length && char.IsDigit(condition[index]))
                    {
                        index++;
                    }
                }

                tokens.Add(new StaticYaraConditionToken(StaticYaraConditionTokenKind.Number, condition[start..index]));
                continue;
            }

            index++;
        }

        return tokens;
    }

    /// <summary>
    /// Adds stable rule-facing tags and copyable evidence for a YARA match.
    /// </summary>
    private static void AddStaticYaraMatch(
        StaticYaraRule rule,
        StaticYaraRuleMatch match,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings)
    {
        tags.Add("static.yara.match");
        tags.Add("static.yara.engine.builtin");
        tags.Add($"static.yara.rule.{NormalizeStaticYaraTag(rule.Name)}");

        if (rule.Meta.TryGetValue("scope", out var scope))
        {
            tags.Add($"static.yara.scope.{NormalizeStaticYaraTag(scope)}");
        }

        if (rule.Meta.TryGetValue("mitre", out var mitre))
        {
            foreach (var technique in SplitStaticYaraMetaList(mitre))
            {
                tags.Add($"static.yara.mitre.{NormalizeStaticYaraTag(technique)}");
            }
        }

        AddInterestingString(interestingStrings, $"static.yara.match:{match.RuleName}");
        if (match.MatchedStringIds.Count > 0)
        {
            AddInterestingString(interestingStrings, $"static.yara.strings:{match.RuleName}:{string.Join(",", match.MatchedStringIds)}");
        }

        var metadata = new List<string>();
        if (rule.Meta.TryGetValue("scope", out var metaScope))
        {
            metadata.Add($"scope={metaScope}");
        }

        if (rule.Meta.TryGetValue("mitre", out var metaMitre))
        {
            metadata.Add($"mitre={metaMitre}");
        }

        if (metadata.Count > 0)
        {
            AddInterestingString(interestingStrings, $"static.yara.meta:{match.RuleName}:{string.Join(";", metadata)}");
        }
    }

    /// <summary>
    /// Splits comma/semicolon/space separated YARA metadata lists.
    /// </summary>
    private static IEnumerable<string> SplitStaticYaraMetaList(string value)
    {
        return value
            .Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => item.Length > 0);
    }

    /// <summary>
    /// Normalizes YARA metadata into comma-safe static tag suffixes.
    /// </summary>
    private static string NormalizeStaticYaraTag(string value)
    {
        var builder = new StringBuilder(value.Length);
        var lastWasSeparator = false;
        foreach (var character in value.Trim())
        {
            if (char.IsLetterOrDigit(character))
            {
                builder.Append(char.ToLowerInvariant(character));
                lastWasSeparator = false;
                continue;
            }

            if (character == '.')
            {
                builder.Append('.');
                lastWasSeparator = false;
                continue;
            }

            if (!lastWasSeparator)
            {
                builder.Append('_');
                lastWasSeparator = true;
            }
        }

        var normalized = builder.ToString().Trim('_');
        return normalized.Length == 0 ? "unknown" : normalized;
    }

    /// <summary>
    /// Returns whether one exception should silently disable optional YARA.
    /// </summary>
    private static bool IsStaticYaraDowngradeException(Exception ex)
    {
        return ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or FormatException or OverflowException or RegexMatchTimeoutException or NotSupportedException or PathTooLongException;
    }

    /// <summary>
    /// Searches for one byte pattern with optional ASCII-only nocase matching.
    /// </summary>
    private static bool ContainsBytes(byte[] data, byte[] pattern, bool ignoreCase)
    {
        if (pattern.Length == 0 || data.Length < pattern.Length)
        {
            return false;
        }

        if (!ignoreCase)
        {
            return data.AsSpan().IndexOf(pattern) >= 0;
        }

        for (var offset = 0; offset <= data.Length - pattern.Length; offset++)
        {
            var matched = true;
            for (var index = 0; index < pattern.Length; index++)
            {
                if (!AsciiBytesEqualIgnoreCase(data[offset + index], pattern[index]))
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Searches for a UTF-16LE YARA wide literal.
    /// </summary>
    private static bool ContainsWideLiteral(byte[] data, string literal, bool ignoreCase)
    {
        if (literal.Length == 0 || data.Length < literal.Length * 2)
        {
            return false;
        }

        for (var offset = 0; offset <= data.Length - literal.Length * 2; offset++)
        {
            var matched = true;
            for (var index = 0; index < literal.Length; index++)
            {
                var low = data[offset + index * 2];
                var high = data[offset + index * 2 + 1];
                if (high != 0 || !CharsEqual((char)low, literal[index], ignoreCase))
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Compares two ASCII bytes with ordinal case folding.
    /// </summary>
    private static bool AsciiBytesEqualIgnoreCase(byte left, byte right)
    {
        if (left == right)
        {
            return true;
        }

        return ToAsciiUpper(left) == ToAsciiUpper(right);
    }

    /// <summary>
    /// Converts one lowercase ASCII byte to uppercase.
    /// </summary>
    private static byte ToAsciiUpper(byte value)
    {
        return value is >= (byte)'a' and <= (byte)'z' ? (byte)(value - 32) : value;
    }

    /// <summary>
    /// Compares two literal characters with optional ordinal ignore-case.
    /// </summary>
    private static bool CharsEqual(char left, char right, bool ignoreCase)
    {
        return ignoreCase
            ? char.ToUpperInvariant(left) == char.ToUpperInvariant(right)
            : left == right;
    }

    /// <summary>
    /// Enumerates printable ASCII strings.
    /// The input is a byte buffer, processing groups printable characters, and
    /// the method yields strings that meet the minimum length.
    /// </summary>
    private static IEnumerable<string> EnumerateAsciiStrings(byte[] buffer)
    {
        var builder = new StringBuilder();
        foreach (var value in buffer)
        {
            if (value is >= 0x20 and <= 0x7e)
            {
                builder.Append((char)value);
                continue;
            }

            if (builder.Length >= MinimumStringLength)
            {
                yield return builder.ToString();
            }

            builder.Clear();
        }

        if (builder.Length >= MinimumStringLength)
        {
            yield return builder.ToString();
        }
    }

    /// <summary>
    /// Enumerates simple UTF-16LE strings.
    /// The input is a byte buffer, processing checks printable low bytes with
    /// zero high bytes, and the method yields strings that meet the minimum
    /// length.
    /// </summary>
    private static IEnumerable<string> EnumerateUtf16Strings(byte[] buffer)
    {
        var builder = new StringBuilder();
        for (var index = 0; index + 1 < buffer.Length; index += 2)
        {
            var low = buffer[index];
            var high = buffer[index + 1];
            if (high == 0 && low is >= 0x20 and <= 0x7e)
            {
                builder.Append((char)low);
                continue;
            }

            if (builder.Length >= MinimumStringLength)
            {
                yield return builder.ToString();
            }

            builder.Clear();
        }

        if (builder.Length >= MinimumStringLength)
        {
            yield return builder.ToString();
        }
    }

    /// <summary>
    /// Classifies one extracted string into URL or interesting static evidence.
    /// Inputs are text and output collections, processing applies token-bounded
    /// heuristics and benign manifest suppression, and the method returns no value.
    /// </summary>
    private static void AddStringClassifications(
        string text,
        SortedSet<string> tags,
        SortedSet<string> urls,
        SortedSet<string> interestingStrings,
        StaticStringEvidence stringEvidence)
    {
        var trimmed = text.Trim();
        if (trimmed.Length > 240)
        {
            trimmed = trimmed[..240];
        }

        var isInteresting = false;
        if (AddUrlClassifications(trimmed, tags, urls, interestingStrings, stringEvidence))
        {
            if (!IsBenignManifestOrMicrosoftReference(trimmed))
            {
                tags.Add("network_indicator_string");
            }
        }

        if (AddIpClassifications(trimmed, tags, interestingStrings, stringEvidence))
        {
            isInteresting = true;
        }

        if (AddEmailClassifications(trimmed, tags, interestingStrings, stringEvidence))
        {
            isInteresting = true;
        }

        if (AddDomainClassifications(trimmed, tags, interestingStrings, stringEvidence))
        {
            isInteresting = true;
        }

        if (AddPathClassifications(trimmed, tags, interestingStrings, stringEvidence))
        {
            isInteresting = true;
        }

        if (ContainsAny(trimmed, ScriptInterpreterMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("script_execution_string");
            if (ContainsAny(trimmed, "powershell", "pwsh"))
            {
                tags.Add("powershell_string");
            }

            AddCommandIndicator(
                stringEvidence,
                "script-interpreter",
                FindFirstMarker(trimmed, ScriptInterpreterMarkers),
                trimmed,
                "script_execution_string");

            if (ContainsAny(trimmed, LolbinCommandMarkers))
            {
                tags.Add("lolbin_string");
                AddCommandIndicator(
                    stringEvidence,
                    "lolbin",
                    FindFirstMarker(trimmed, LolbinCommandMarkers),
                    trimmed,
                    "script_execution_string",
                    "lolbin_string");
            }
        }

        if (ContainsAny(trimmed, EncodedCommandMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("encoded_command_string");
            AddCommandIndicator(
                stringEvidence,
                "encoded-command",
                FindFirstMarker(trimmed, ScriptInterpreterMarkers),
                trimmed,
                "script_execution_string",
                "encoded_command_string");
        }

        if (ContainsAny(trimmed, DownloadCommandMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("download_command_string");
            AddCommandIndicator(
                stringEvidence,
                "download-command",
                FindFirstMarker(trimmed, DownloadCommandMarkers),
                trimmed,
                "download_command_string");
        }

        if (IsDownloadExecuteString(trimmed))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("download_command_string");
            tags.Add("download_execute_string");
            tags.Add("download_exec_candidate");
            AddCommandIndicator(
                stringEvidence,
                "download-execute",
                FindFirstMarker(trimmed, DownloadCommandMarkers) ?? FindFirstMarker(trimmed, ScriptInterpreterMarkers),
                trimmed,
                "download_command_string",
                "download_execute_string",
                "download_exec_candidate");
        }

        if (ContainsAny(trimmed, ExfilCommandMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("exfil_command_string");
            AddCommandIndicator(
                stringEvidence,
                "exfil-command",
                FindFirstMarker(trimmed, ExfilCommandMarkers),
                trimmed,
                "exfil_command_string");
        }

        if (ContainsAny(trimmed, CredentialStringMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("credential_access_string");
            AddStringFinding(stringEvidence, "credential-access-string", trimmed, "credential_access_string");
        }

        if (ContainsAny(trimmed, DefenseEvasionStringMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("defense_evasion_string");
            AddStringFinding(stringEvidence, "defense-evasion-string", trimmed, "defense_evasion_string");
        }

        if (ContainsAny(trimmed, "Run\\", "RunOnce\\", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("persistence_string");
            AddStringFinding(stringEvidence, "persistence-string", trimmed, "persistence_string");
        }

        if (ContainsServicePersistenceString(trimmed))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("persistence_string");
            tags.Add("service_string");
            AddStringFinding(stringEvidence, "service-string", trimmed, "persistence_string", "service_string");
            if (ContainsAny(trimmed, "sc.exe", "New-Service", "Set-Service", "Start-Service", "Stop-Service", "CreateService", "ChangeServiceConfig"))
            {
                AddCommandIndicator(
                    stringEvidence,
                    "service-control",
                    FindFirstMarker(trimmed, ServiceStringMarkers),
                    trimmed,
                    "persistence_string",
                    "service_string");
            }
        }

        if (ContainsScheduledTaskString(trimmed))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("persistence_string");
            tags.Add("scheduled_task_string");
            tags.Add("task_string");
            AddStringFinding(stringEvidence, "scheduled-task-string", trimmed, "persistence_string", "scheduled_task_string", "task_string");
            AddCommandIndicator(
                stringEvidence,
                "scheduled-task",
                FindFirstMarker(trimmed, ScheduledTaskStringMarkers) ?? FindFirstMarker(trimmed, LolbinCommandMarkers),
                trimmed,
                "persistence_string",
                "scheduled_task_string",
                "task_string");
        }

        if (ContainsAnyApiToken(trimmed, SuspiciousApiStringMarkers))
        {
            isInteresting = true;
            tags.Add("suspicious_api_string");
            AddSuspiciousApiTags(trimmed, tags);
            AddStringFinding(stringEvidence, "suspicious-api-string", trimmed, "suspicious_api_string");
        }

        if (ContainsAny(trimmed, AntiSandboxStringMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("anti_analysis_string");
            tags.Add("sandbox_evasion_string");
            AddStringFinding(stringEvidence, "anti-analysis-string", trimmed, "anti_analysis_string", "sandbox_evasion_string");
        }

        if (ContainsAnyApiToken(trimmed, AntiDebugApis) || ContainsAny(trimmed, AntiDebugStringMarkers))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("anti_analysis_string");
            tags.Add("debugger_evasion_string");
            tags.Add("anti_debug_string");
            AddStringFinding(
                stringEvidence,
                "anti-debug-string",
                trimmed,
                "anti_analysis_string",
                "debugger_evasion_string",
                "anti_debug_string");
        }

        if (ContainsAny(trimmed, PackerStringMarkers))
        {
            isInteresting = true;
            tags.Add("packer_hint");
            tags.Add("packer_string_hint");
            if (ContainsAny(trimmed, "UPX!", "UPX0", "UPX1", "UPX2"))
            {
                tags.Add("packer_upx");
            }

            AddStringFinding(stringEvidence, "packer-string", trimmed, "packer_string_hint");
        }

        if (isInteresting)
        {
            AddInterestingString(interestingStrings, trimmed);
        }
    }

    /// <summary>
    /// Extracts URL-like substrings from one static string.
    /// Inputs are text plus output tag and URL collections, processing trims
    /// common delimiters, and the method returns whether any URL was found.
    /// </summary>
    private static bool AddUrlClassifications(
        string text,
        SortedSet<string> tags,
        SortedSet<string> urls,
        SortedSet<string> interestingStrings,
        StaticStringEvidence stringEvidence)
    {
        var found = false;
        foreach (Match match in UrlPattern.Matches(text))
        {
            var url = TrimEvidence(match.Value).TrimEnd('.', ',', ';', ')', ']', '}', '!');
            if (string.IsNullOrWhiteSpace(url))
            {
                continue;
            }

            urls.Add(url);
            if (IsBenignManifestOrMicrosoftReference(url))
            {
                AddInterestingString(interestingStrings, $"url-reference:{url}");
                AddNetworkIndicator(stringEvidence, "url", url, "reference");
            }
            else
            {
                AddInterestingString(interestingStrings, $"url:{url}");
                AddNetworkIndicator(stringEvidence, "url", url, "embedded");
                found = true;
            }

            continue;
        }

        if (found)
        {
            tags.Add("url");
            tags.Add("embedded_url");
        }

        return found;
    }

    /// <summary>
    /// Returns whether a URL/string is a benign Windows manifest or Microsoft
    /// framework reference that should remain visible but not score as network
    /// IOC evidence.
    /// </summary>
    private static bool IsBenignManifestOrMicrosoftReference(string value)
    {
        return value.Contains("schemas.microsoft.com/", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("go.microsoft.com/fwlink", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("go.microsoft.com/fwlink/p/", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("asm.v1", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("compatibility.v1", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Extracts IPv4 indicators and coarse routability labels.
    /// Inputs are text plus output collections, processing validates octets,
    /// suppresses version-like manifest values, and returns whether an IOC hit.
    /// </summary>
    private static bool AddIpClassifications(
        string text,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        StaticStringEvidence stringEvidence)
    {
        var found = false;
        foreach (Match match in Ipv4Pattern.Matches(text))
        {
            var ip = match.Value;
            if (!TryParseIpv4(ip, out var octets) ||
                IsVersionLikeIpv4(ip, text) ||
                IsBenignManifestOrMicrosoftReference(text))
            {
                continue;
            }

            tags.Add("ip_address");
            var classification = IsPrivateOrReservedIpv4(octets) ? "private_or_reserved" : "public";
            tags.Add(classification == "private_or_reserved" ? "private_or_reserved_ip_address" : "public_ip_address");
            tags.Add("network_indicator_string");
            AddInterestingString(interestingStrings, $"ip:{ip}");
            AddNetworkIndicator(stringEvidence, "ipv4", ip, classification);
            found = true;
        }

        return found;
    }

    /// <summary>
    /// Extracts email-like static indicators while suppressing common manifest
    /// references. Inputs are one string and output collections; processing
    /// emits both legacy evidence and structured network indicators.
    /// </summary>
    private static bool AddEmailClassifications(
        string text,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        StaticStringEvidence stringEvidence)
    {
        if (IsBenignManifestOrMicrosoftReference(text))
        {
            return false;
        }

        var found = false;
        foreach (Match match in EmailPattern.Matches(text))
        {
            var email = TrimEvidence(match.Value).TrimEnd('.', ',', ';', ')', ']', '}', '!');
            if (string.IsNullOrWhiteSpace(email))
            {
                continue;
            }

            tags.Add("email_address");
            tags.Add("network_indicator_string");
            AddInterestingString(interestingStrings, $"email:{email}");
            AddNetworkIndicator(stringEvidence, "email", email, "embedded");
            found = true;
        }

        return found;
    }

    /// <summary>
    /// Extracts bare domain indicators with conservative TLD filtering.
    /// Inputs are one string and output collections, processing suppresses PE
    /// file-extension and framework-reference false positives, and the method
    /// returns true when a reportable domain indicator is found.
    /// </summary>
    private static bool AddDomainClassifications(
        string text,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        StaticStringEvidence stringEvidence)
    {
        if (IsBenignManifestOrMicrosoftReference(text))
        {
            return false;
        }

        var found = false;
        foreach (Match match in DomainPattern.Matches(text))
        {
            var domain = TrimEvidence(match.Value).TrimEnd('.', ',', ';', ')', ']', '}', '!');
            if (!IsLikelyDomainIndicator(domain))
            {
                continue;
            }

            var normalizedDomain = domain.ToLowerInvariant();
            var isReference = IsReferenceDomain(normalizedDomain);
            var isOnion = normalizedDomain.EndsWith(".onion", StringComparison.OrdinalIgnoreCase);
            var isDynamicDns = ContainsAny(normalizedDomain, DynamicDnsDomainMarkers);
            var classification = isReference
                ? "reference"
                : isOnion
                    ? "onion"
                    : isDynamicDns
                        ? "dynamic_dns"
                        : "public";

            AddNetworkIndicator(stringEvidence, "domain", normalizedDomain, classification);
            if (isReference)
            {
                AddInterestingString(interestingStrings, $"domain-reference:{normalizedDomain}");
                continue;
            }

            tags.Add("domain_name");
            tags.Add("domain_indicator_string");
            tags.Add("network_indicator_string");
            if (isOnion)
            {
                tags.Add("tor_domain_string");
            }

            if (isDynamicDns)
            {
                tags.Add("dynamic_dns_domain_string");
            }

            AddInterestingString(interestingStrings, $"domain:{normalizedDomain}");
            found = true;
        }

        return found;
    }

    /// <summary>
    /// Applies conservative shape and TLD checks for static domain strings.
    /// </summary>
    private static bool IsLikelyDomainIndicator(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253)
        {
            return false;
        }

        var labels = domain.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length < 2 || labels.Any(label => label.Length is 0 or > 63))
        {
            return false;
        }

        var tld = labels[^1].TrimEnd('.').ToLowerInvariant();
        return CommonDomainTlds.Contains(tld, StringComparer.OrdinalIgnoreCase) ||
            tld.StartsWith("xn--", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns whether a domain is a common framework/documentation reference.
    /// </summary>
    private static bool IsReferenceDomain(string normalizedDomain)
    {
        return ReferenceDomainSuffixes.Any(suffix =>
            string.Equals(normalizedDomain, suffix, StringComparison.OrdinalIgnoreCase) ||
            normalizedDomain.EndsWith($".{suffix}", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Identifies Windows/manifest version tuples such as 5.1.0.0 or 6.0.0.0
    /// that look like IPv4 literals but are not network indicators.
    /// </summary>
    private static bool IsVersionLikeIpv4(string ip, string context)
    {
        if (!TryParseIpv4(ip, out var octets))
        {
            return false;
        }

        if (octets[2] == 0 && octets[3] == 0 && octets[0] <= 10 && octets[1] <= 30)
        {
            return true;
        }

        var index = context.IndexOf(ip, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return false;
        }

        var start = Math.Max(0, index - 32);
        var length = Math.Min(context.Length - start, ip.Length + 64);
        var localContext = context.Substring(start, length);
        return localContext.Contains("version", StringComparison.OrdinalIgnoreCase) ||
            localContext.Contains("supportedOS", StringComparison.OrdinalIgnoreCase) ||
            localContext.Contains("compatibility", StringComparison.OrdinalIgnoreCase) ||
            localContext.Contains("manifest", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Extracts Windows filesystem and registry path labels from a string.
    /// Inputs are text plus output collections, processing applies bounded
    /// regex matches and path marker checks, and the method returns true on hit.
    /// </summary>
    private static bool AddPathClassifications(
        string text,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        StaticStringEvidence stringEvidence)
    {
        var found = false;
        foreach (Match match in RegistryPathPattern.Matches(text))
        {
            var path = TrimEvidence(match.Value);
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            tags.Add("registry_path_string");
            var pathTags = new SortedSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "registry_path_string"
            };
            if (ContainsAny(path, "CurrentVersion\\Run", "CurrentVersion\\RunOnce", "Policies\\Explorer\\Run"))
            {
                tags.Add("run_key_path_string");
                tags.Add("persistence_string");
                pathTags.Add("run_key_path_string");
                pathTags.Add("persistence_string");
            }

            if (ContainsAny(path, "CurrentControlSet\\Services", "\\Services\\"))
            {
                tags.Add("service_registry_path_string");
                tags.Add("persistence_string");
                tags.Add("service_string");
                pathTags.Add("service_registry_path_string");
                pathTags.Add("persistence_string");
                pathTags.Add("service_string");
            }

            if (ContainsAny(path, "Schedule\\TaskCache\\Tree", "Schedule\\TaskCache\\Tasks", "Windows NT\\CurrentVersion\\Schedule\\TaskCache"))
            {
                tags.Add("scheduled_task_registry_path_string");
                tags.Add("scheduled_task_string");
                tags.Add("task_string");
                tags.Add("persistence_string");
                pathTags.Add("scheduled_task_registry_path_string");
                pathTags.Add("scheduled_task_string");
                pathTags.Add("task_string");
                pathTags.Add("persistence_string");
            }

            AddInterestingString(interestingStrings, $"registry-path:{path}");
            AddPathIndicator(stringEvidence, "registry", path, pathTags);
            found = true;
        }

        foreach (Match match in WindowsPathPattern.Matches(text))
        {
            var path = TrimEvidence(match.Value);
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            tags.Add("windows_path_string");
            tags.Add("file_path_string");
            var pathTags = new SortedSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "windows_path_string",
                "file_path_string"
            };
            if (ContainsAny(path, "\\Temp\\", "\\Windows\\Temp\\", "%TEMP%", "%TMP%"))
            {
                tags.Add("temp_path_string");
                pathTags.Add("temp_path_string");
            }

            if (ContainsAny(path, "\\AppData\\", "%APPDATA%", "%LOCALAPPDATA%"))
            {
                tags.Add("appdata_path_string");
                pathTags.Add("appdata_path_string");
            }

            if (ContainsAny(path, "\\Startup\\", "\\Start Menu\\Programs\\Startup", "Microsoft\\Windows\\Start Menu\\Programs\\Startup"))
            {
                tags.Add("startup_folder_path_string");
                tags.Add("persistence_string");
                pathTags.Add("startup_folder_path_string");
                pathTags.Add("persistence_string");
            }

            if (ContainsAny(path, "\\System32\\Tasks\\", "\\SysWOW64\\Tasks\\", "\\Windows\\Tasks\\"))
            {
                tags.Add("scheduled_task_path_string");
                tags.Add("scheduled_task_string");
                tags.Add("task_string");
                tags.Add("persistence_string");
                pathTags.Add("scheduled_task_path_string");
                pathTags.Add("scheduled_task_string");
                pathTags.Add("task_string");
                pathTags.Add("persistence_string");
            }

            if (ContainsAny(path, ".exe", ".dll", ".sys", ".scr", ".com"))
            {
                tags.Add("executable_path_string");
                pathTags.Add("executable_path_string");
            }

            if (ContainsAny(path, ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta", ".wsf"))
            {
                tags.Add("script_path_string");
                tags.Add("script_execution_string");
                pathTags.Add("script_path_string");
                pathTags.Add("script_execution_string");
            }

            AddInterestingString(interestingStrings, $"path:{path}");
            AddPathIndicator(stringEvidence, "filesystem", path, pathTags);
            found = true;
        }

        if (ContainsAny(text, "%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%", "%PROGRAMDATA%", "%USERPROFILE%"))
        {
            tags.Add("environment_path_string");
            var pathTags = new SortedSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "environment_path_string"
            };
            if (ContainsAny(text, "%TEMP%", "%TMP%"))
            {
                tags.Add("temp_path_string");
                pathTags.Add("temp_path_string");
            }

            if (ContainsAny(text, "%APPDATA%", "%LOCALAPPDATA%"))
            {
                tags.Add("appdata_path_string");
                pathTags.Add("appdata_path_string");
            }

            AddPathIndicator(stringEvidence, "environment", text, pathTags);
            found = true;
        }

        return found;
    }

    /// <summary>
    /// Matches service-persistence strings with conservative command/context
    /// checks so a generic word such as "service" does not become evidence.
    /// </summary>
    private static bool ContainsServicePersistenceString(string text)
    {
        if (ContainsAny(text, ServiceStringMarkers))
        {
            return true;
        }

        return ContainsToken(text, "sc") &&
            ContainsAny(text, " create ", " config ", " failure ", " sdset ", " start ", " stop ", " delete ");
    }

    /// <summary>
    /// Matches Scheduled Task strings, requiring either specific API/registry
    /// artifacts or schtasks.exe paired with task-management switches.
    /// </summary>
    private static bool ContainsScheduledTaskString(string text)
    {
        if (ContainsAny(text, ScheduledTaskStringMarkers))
        {
            return true;
        }

        return ContainsAny(text, "schtasks", "schtasks.exe") &&
            ContainsAny(text, "/create", "/change", "/run", "/tn ", "/tr ", "/sc ");
    }

    /// <summary>
    /// Detects static command strings that combine retrieval and execution
    /// clues. Inputs are one extracted string; processing requires both a
    /// download marker/URL and an executable/script or process-launch clue; the
    /// method returns true for low-confidence download-execute triage.
    /// </summary>
    private static bool IsDownloadExecuteString(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var hasDownload = ContainsAny(text, DownloadCommandMarkers) ||
            (UrlPattern.IsMatch(text) && ContainsAny(text, "http://", "https://"));
        var hasExecution = ContainsAny(text, DownloadExecuteCommandMarkers) ||
            ContainsAny(text, ScriptInterpreterMarkers) ||
            ContainsScriptExecutionApi(text);
        return hasDownload && hasExecution;
    }

    /// <summary>
    /// Adds high-level PE tags based on optional-header and section metadata.
    /// Inputs are optional-header magic, subsystem, sections, and tag set;
    /// processing adds report-friendly labels, and the method returns no value.
    /// </summary>
    private static void AddPeTags(ushort optionalMagic, string subsystem, List<PeSectionInfo> sections, SortedSet<string> tags)
    {
        tags.Add(optionalMagic == 0x20b ? "pe32_plus" : optionalMagic == 0x10b ? "pe32" : "pe_unknown_optional_header");
        if (subsystem.Contains("GUI", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("gui");
        }

        if (subsystem.Contains("Console", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("console");
        }

        if (sections.Any(section => section.Name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)))
        {
            tags.Add("packer_hint");
            tags.Add("packer_upx");
        }

        if (sections.Any(section => IsKnownPackerSectionName(section.Name)))
        {
            tags.Add("packer_hint");
            tags.Add("packer_section_name");
        }
    }

    /// <summary>
    /// Adds section-level anomaly tags.
    /// Inputs are section name, entropy, virtual size, raw size, and tag set;
    /// processing checks common packer/anomaly hints, and the method returns no
    /// value.
    /// </summary>
    private static void AddSectionTags(string name, double entropy, uint virtualSize, uint rawSize, uint characteristics, SortedSet<string> tags)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Any(ch => ch < 0x20 || ch > 0x7e))
        {
            tags.Add("section_name_exception");
        }

        if (name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("packer_hint");
            tags.Add("packer_upx");
        }

        if (IsKnownPackerSectionName(name))
        {
            tags.Add("packer_hint");
            tags.Add("packer_section_name");
        }

        if (entropy >= 7.2)
        {
            tags.Add("high_entropy_section");
        }

        if (entropy >= 7.8)
        {
            tags.Add("very_high_entropy_section");
        }

        if (rawSize >= 512 && entropy <= 1.0)
        {
            tags.Add("low_entropy_section");
        }

        if (rawSize == 0 && virtualSize > 0)
        {
            tags.Add("virtual_only_section");
        }

        if (rawSize > 0 && virtualSize > rawSize * 4UL && virtualSize >= 0x2000)
        {
            tags.Add("oversized_virtual_section");
        }

        var isExecutable = (characteristics & 0x20000000) != 0;
        var isWritable = (characteristics & 0x80000000) != 0;
        if (isExecutable)
        {
            tags.Add("executable_section");
        }

        if (isWritable)
        {
            tags.Add("writable_section");
        }

        if (isExecutable && isWritable)
        {
            tags.Add("writable_executable_section");
        }
    }

    /// <summary>
    /// Reads the PE image base used for VA-to-RVA conversion.
    /// Inputs are optional-header metadata, processing reads PE32 or PE32+
    /// image-base fields, and the method returns zero when unavailable.
    /// </summary>
    private static ulong ReadImageBase(BinaryReader reader, long optionalHeaderOffset, ushort optionalMagic, long fileLength, List<string> warnings)
    {
        return optionalMagic switch
        {
            0x20b => ReadUInt64At(reader, optionalHeaderOffset + 24, fileLength, warnings),
            0x10b => ReadUInt32At(reader, optionalHeaderOffset + 28, fileLength, warnings),
            _ => 0
        };
    }

    /// <summary>
    /// Reads bounded PE data-directory entries from the optional header.
    /// Inputs are optional-header offsets and sizes, processing respects the
    /// declared directory count and optional-header bounds, and the method
    /// returns directory RVA/size pairs.
    /// </summary>
    private static List<PeDataDirectory> ReadDataDirectories(BinaryReader reader, long optionalHeaderOffset, ushort optionalHeaderSize, ushort optionalMagic, long fileLength, List<string> warnings)
    {
        var directoryOffset = optionalMagic switch
        {
            0x20b => optionalHeaderOffset + 112,
            0x10b => optionalHeaderOffset + 96,
            _ => -1
        };

        if (directoryOffset < 0)
        {
            return [];
        }

        var directoryCountOffset = directoryOffset - sizeof(uint);
        if (directoryCountOffset < optionalHeaderOffset || directoryCountOffset > fileLength - sizeof(uint))
        {
            warnings.Add("PE optional header is too small to read data-directory count.");
            return [];
        }

        var declaredCount = ReadUInt32At(reader, directoryCountOffset, fileLength, warnings);
        var availableBytes = optionalHeaderOffset + optionalHeaderSize - directoryOffset;
        if (availableBytes < 0)
        {
            warnings.Add("PE data directories start outside the optional header.");
            return [];
        }

        var count = (int)Math.Min(Math.Min(declaredCount, 16), availableBytes / 8);
        var directories = new List<PeDataDirectory>(count);
        for (var index = 0; index < count; index++)
        {
            var offset = directoryOffset + index * 8;
            directories.Add(new PeDataDirectory(
                ReadUInt32At(reader, offset, fileLength, warnings),
                ReadUInt32At(reader, offset + sizeof(uint), fileLength, warnings)));
        }

        return directories;
    }

    /// <summary>
    /// Extracts lightweight import/export/TLS evidence from PE data directories.
    /// Inputs are parsed directories, section layouts, architecture metadata,
    /// and output collections; processing is bounded and best-effort; the
    /// method returns no value.
    /// </summary>
    private static void AnalyzePeDataDirectories(
        BinaryReader reader,
        IReadOnlyList<PeDataDirectory> directories,
        IReadOnlyList<PeSectionLayout> sections,
        ushort optionalMagic,
        ulong imageBase,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence)
    {
        if (directories.Count > 0)
        {
            ReadExports(reader, directories[0], sections, fileLength, tags, interestingStrings, warnings, peEvidence);
        }

        if (directories.Count > 1)
        {
            ReadImports(reader, directories[1], sections, optionalMagic, fileLength, tags, interestingStrings, warnings, peEvidence);
        }

        if (directories.Count > 2)
        {
            ReadResources(reader, directories[2], sections, fileLength, tags, interestingStrings, warnings, peEvidence);
        }

        if (directories.Count > 6)
        {
            ReadDebugDirectory(reader, directories[6], sections, fileLength, tags, interestingStrings, warnings);
        }

        if (directories.Count > 9)
        {
            ReadTlsDirectory(reader, directories[9], sections, optionalMagic, imageBase, fileLength, tags, interestingStrings, warnings, peEvidence);
        }
    }

    /// <summary>
    /// Extracts PE overlay and Authenticode certificate-table evidence.
    /// Inputs are parsed data directories and section layouts; processing keeps
    /// certificate-table parsing bounded and treats the PE security directory
    /// as a raw file offset per the PE format; the method records tags and
    /// human-readable evidence strings.
    /// </summary>
    private static void AnalyzePeOverlayAndSignature(
        BinaryReader reader,
        IReadOnlyList<PeDataDirectory> directories,
        IReadOnlyList<PeSectionLayout> sections,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence)
    {
        var securityDirectory = directories.Count > 4 ? directories[4] : new PeDataDirectory(0, 0);
        var certificateTable = ReadCertificateTable(reader, securityDirectory, fileLength, tags, interestingStrings, warnings);
        ReadOverlayEvidence(reader, sections, fileLength, certificateTable, tags, interestingStrings, warnings, peEvidence);
    }

    /// <summary>
    /// Reads the IMAGE_DIRECTORY_ENTRY_SECURITY certificate table.
    /// Inputs are the PE security directory, which stores a raw file offset
    /// rather than an RVA; processing walks bounded WIN_CERTIFICATE entries;
    /// the method returns the valid certificate interval when available.
    /// </summary>
    private static FileInterval? ReadCertificateTable(
        BinaryReader reader,
        PeDataDirectory securityDirectory,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings)
    {
        if (!securityDirectory.IsPresent || securityDirectory.Size == 0)
        {
            return null;
        }

        tags.Add("security_directory_present");
        var offset = (long)securityDirectory.Rva;
        var size = (long)securityDirectory.Size;
        AddInterestingString(interestingStrings, $"signature:certificate-table@0x{offset:X},size={size}");
        if (offset < 0 || size < 8 || offset > fileLength - size)
        {
            tags.Add("invalid_security_directory");
            warnings.Add($"PE security directory at 0x{offset:X} with size {size} is outside the file.");
            return null;
        }

        tags.Add("digital_signature_present");
        tags.Add("authenticode_signature_present");
        var endOffset = offset + size;
        var cursor = offset;
        var entryCount = 0;
        while (cursor <= endOffset - 8 && entryCount < MaxCertificateEntries)
        {
            if (!TryReadUInt32At(reader, cursor, fileLength, out var certificateLength) ||
                !TryReadUInt16At(reader, cursor + sizeof(uint), fileLength, out var revision) ||
                !TryReadUInt16At(reader, cursor + sizeof(uint) + sizeof(ushort), fileLength, out var certificateType))
            {
                break;
            }

            if (certificateLength < 8 || cursor + certificateLength > endOffset)
            {
                tags.Add("invalid_certificate_table");
                warnings.Add($"WIN_CERTIFICATE entry at 0x{cursor:X} has invalid length {certificateLength}.");
                break;
            }

            entryCount++;
            var certificateTypeText = DescribeCertificateType(certificateType);
            if (certificateType == 0x0002)
            {
                tags.Add("signature_pkcs_signed_data");
            }

            AddInterestingString(
                interestingStrings,
                $"signature:certificate[{entryCount}],type={certificateTypeText},revision=0x{revision:X4},size={certificateLength}");

            var alignedLength = AlignToEight(certificateLength);
            if (alignedLength <= 0)
            {
                break;
            }

            cursor += alignedLength;
        }

        if (cursor <= endOffset - 8 && entryCount >= MaxCertificateEntries)
        {
            warnings.Add($"Certificate-table scan truncated at {MaxCertificateEntries} entries.");
        }

        if (entryCount == 0)
        {
            tags.Add("certificate_table_unparsed");
        }

        return new FileInterval(offset, endOffset);
    }

    /// <summary>
    /// Records bytes after the last section raw-data end as PE overlay.
    /// Inputs are section layouts, file length, and optional certificate-table
    /// interval; processing distinguishes certificate-only overlay from
    /// non-certificate appended data and calculates bounded entropy evidence.
    /// </summary>
    private static void ReadOverlayEvidence(
        BinaryReader reader,
        IReadOnlyList<PeSectionLayout> sections,
        long fileLength,
        FileInterval? certificateTable,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence)
    {
        if (!TryGetRawImageEnd(sections, fileLength, out var rawImageEnd) || rawImageEnd >= fileLength)
        {
            return;
        }

        var overlay = new FileInterval(rawImageEnd, fileLength);
        var overlaySize = overlay.Length;
        tags.Add("overlay_present");
        tags.Add("pe_overlay");
        AddInterestingString(interestingStrings, $"overlay:start=0x{overlay.Start:X},size={overlaySize}");

        FileInterval? certificateOverlay = null;
        var containsCertificateTable = false;
        long certificateTableSize = 0;
        string? certificateTableOffset = null;
        if (certificateTable is { } certificate && certificate.Overlaps(overlay))
        {
            certificateOverlay = certificate.Intersect(overlay);
            containsCertificateTable = true;
            certificateTableOffset = $"0x{certificateOverlay.Value.Start:X}";
            certificateTableSize = certificateOverlay.Value.Length;
            tags.Add("overlay_contains_certificate_table");
            AddInterestingString(
                interestingStrings,
                $"overlay:certificate-table@0x{certificateOverlay.Value.Start:X},size={certificateOverlay.Value.Length}");
        }

        var nonCertificateSegments = SubtractInterval(overlay, certificateOverlay).ToList();
        var nonCertificateSize = nonCertificateSegments.Sum(segment => segment.Length);
        if (nonCertificateSize == 0)
        {
            tags.Add("overlay_certificate_table_only");
            peEvidence.Overlay = new PeOverlayInfo
            {
                Present = true,
                StartOffset = $"0x{overlay.Start:X}",
                Size = overlaySize,
                ContainsCertificateTable = containsCertificateTable,
                CertificateTableOffset = certificateTableOffset,
                CertificateTableSize = certificateTableSize,
                IsCertificateTableOnly = true,
                NonCertificateSize = 0
            };
            return;
        }

        tags.Add("overlay_non_certificate_data");
        AddInterestingString(interestingStrings, $"overlay:non-certificate-size={nonCertificateSize}");
        if (nonCertificateSize >= 1024 * 1024)
        {
            tags.Add("overlay_large_data");
        }

        var largestSegment = nonCertificateSegments
            .OrderByDescending(segment => segment.Length)
            .First();
        if (largestSegment.Length <= 0)
        {
            peEvidence.Overlay = new PeOverlayInfo
            {
                Present = true,
                StartOffset = $"0x{overlay.Start:X}",
                Size = overlaySize,
                ContainsCertificateTable = containsCertificateTable,
                CertificateTableOffset = certificateTableOffset,
                CertificateTableSize = certificateTableSize,
                IsCertificateTableOnly = false,
                NonCertificateSize = nonCertificateSize
            };
            return;
        }

        var entropy = CalculateEntropy(reader, largestSegment.Start, (uint)Math.Min(largestSegment.Length, uint.MaxValue), fileLength, warnings);
        if (entropy >= 7.2)
        {
            tags.Add("overlay_high_entropy");
        }

        AddInterestingString(
            interestingStrings,
            $"overlay:non-certificate@0x{largestSegment.Start:X},size={largestSegment.Length},entropy={Math.Round(entropy, 3):F3}");
        peEvidence.Overlay = new PeOverlayInfo
        {
            Present = true,
            StartOffset = $"0x{overlay.Start:X}",
            Size = overlaySize,
            ContainsCertificateTable = containsCertificateTable,
            CertificateTableOffset = certificateTableOffset,
            CertificateTableSize = certificateTableSize,
            IsCertificateTableOnly = false,
            NonCertificateSize = nonCertificateSize,
            LargestNonCertificateOffset = $"0x{largestSegment.Start:X}",
            LargestNonCertificateSize = largestSegment.Length,
            NonCertificateEntropy = Math.Round(entropy, 3)
        };
    }

    /// <summary>
    /// Reads PE import descriptors and selected thunk names.
    /// Inputs are the import data directory and section layouts, processing
    /// maps RVAs to raw offsets and records bounded API evidence, and the
    /// method returns no value.
    /// </summary>
    private static void ReadImports(
        BinaryReader reader,
        PeDataDirectory importDirectory,
        IReadOnlyList<PeSectionLayout> sections,
        ushort optionalMagic,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence)
    {
        if (!importDirectory.IsPresent)
        {
            return;
        }

        tags.Add("imports_present");
        if (!TryRvaToFileOffset(importDirectory.Rva, sections, fileLength, out var importOffset))
        {
            warnings.Add($"Import directory RVA 0x{importDirectory.Rva:X8} could not be mapped to a file offset.");
            return;
        }

        var descriptorLimit = importDirectory.Size > 0
            ? Math.Min(MaxImportDescriptors, Math.Max(1, (int)(importDirectory.Size / 20)))
            : MaxImportDescriptors;
        var evidenceCount = 0;
        var moduleSummaries = new List<ImportModuleSummary>();
        var suspiciousApiClusters = new SortedDictionary<string, ImportApiClusterSummary>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < descriptorLimit; index++)
        {
            var descriptorOffset = importOffset + index * 20;
            if (descriptorOffset < 0 || descriptorOffset > fileLength - 20)
            {
                break;
            }

            if (!TryReadUInt32At(reader, descriptorOffset, fileLength, out var originalFirstThunk) ||
                !TryReadUInt32At(reader, descriptorOffset + 12, fileLength, out var nameRva) ||
                !TryReadUInt32At(reader, descriptorOffset + 16, fileLength, out var firstThunk))
            {
                break;
            }

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
            {
                break;
            }

            var dllName = TryReadRvaAsciiString(reader, nameRva, sections, fileLength) ?? $"dll@0x{nameRva:X8}";
            AddImportModuleTags(dllName, tags);
            AddPeEvidence(interestingStrings, $"import:{dllName}", ref evidenceCount, MaxImportEvidence);
            var moduleSummary = new ImportModuleSummary(dllName);
            moduleSummaries.Add(moduleSummary);
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (thunkRva != 0)
            {
                ReadImportThunks(
                    reader,
                    dllName,
                    thunkRva,
                    sections,
                    optionalMagic,
                    fileLength,
                    tags,
                    interestingStrings,
                    moduleSummary,
                    suspiciousApiClusters,
                    ref evidenceCount);
            }
        }

        AddImportSummaryEvidence(moduleSummaries, suspiciousApiClusters, tags, interestingStrings, peEvidence);
    }

    /// <summary>
    /// Reads PE import thunk names for one imported module.
    /// Inputs are module name and thunk RVA, processing handles PE32/PE32+
    /// pointer sizes and ordinal imports, and the method records evidence.
    /// </summary>
    private static void ReadImportThunks(
        BinaryReader reader,
        string dllName,
        uint thunkRva,
        IReadOnlyList<PeSectionLayout> sections,
        ushort optionalMagic,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        ImportModuleSummary moduleSummary,
        SortedDictionary<string, ImportApiClusterSummary> suspiciousApiClusters,
        ref int evidenceCount)
    {
        if (!TryRvaToFileOffset(thunkRva, sections, fileLength, out var thunkOffset))
        {
            return;
        }

        var isPe32Plus = optionalMagic == 0x20b;
        var pointerSize = isPe32Plus ? sizeof(ulong) : sizeof(uint);
        var ordinalMask = isPe32Plus ? 0x8000000000000000UL : 0x80000000UL;
        for (var index = 0; index < MaxImportThunksPerDescriptor; index++)
        {
            var entryOffset = thunkOffset + (long)index * pointerSize;
            if (entryOffset < 0 || entryOffset > fileLength - pointerSize)
            {
                break;
            }

            var rawEntry = isPe32Plus
                ? TryReadUInt64At(reader, entryOffset, fileLength, out var value64) ? value64 : 0
                : TryReadUInt32At(reader, entryOffset, fileLength, out var value32) ? value32 : 0UL;
            if (rawEntry == 0)
            {
                break;
            }

            if ((rawEntry & ordinalMask) != 0)
            {
                moduleSummary.OrdinalImportCount++;
                var ordinalName = $"#ordinal{rawEntry & 0xffff}";
                AddBounded(moduleSummary.OrdinalImports, ordinalName, MaxStructuredPeEntries);
                AddPeEvidence(interestingStrings, $"import:{dllName}!{ordinalName}", ref evidenceCount, MaxImportEvidence);
                continue;
            }

            if (rawEntry > uint.MaxValue)
            {
                continue;
            }

            var apiName = TryReadImportByName(reader, (uint)rawEntry, sections, fileLength);
            if (string.IsNullOrWhiteSpace(apiName))
            {
                continue;
            }

            moduleSummary.NamedApiCount++;
            AddBounded(moduleSummary.ApiNames, apiName, MaxStructuredPeEntries);
            AddPeEvidence(interestingStrings, $"import:{dllName}!{apiName}", ref evidenceCount, MaxImportEvidence);
            AddSuspiciousApiTags(apiName, tags);
            foreach (var cluster in GetSuspiciousApiClusters(apiName))
            {
                if (!suspiciousApiClusters.TryGetValue(cluster, out var summary))
                {
                    summary = new ImportApiClusterSummary(cluster);
                    suspiciousApiClusters[cluster] = summary;
                }

                summary.HitCount++;
                summary.ApiNames.Add(apiName);
                moduleSummary.SuspiciousApiNames.Add(apiName);
                moduleSummary.SuspiciousApiClusters.Add(cluster);
            }
        }
    }

    /// <summary>
    /// Emits import-table aggregate evidence after descriptor/thunk walking.
    /// Inputs are bounded module summaries and suspicious API cluster counts;
    /// processing adds compact report strings and coarse multi-cluster tags.
    /// </summary>
    private static void AddImportSummaryEvidence(
        IReadOnlyList<ImportModuleSummary> moduleSummaries,
        IReadOnlyDictionary<string, ImportApiClusterSummary> suspiciousApiClusters,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        PeAnalysisEvidence peEvidence)
    {
        if (moduleSummaries.Count == 0)
        {
            return;
        }

        var namedApiCount = moduleSummaries.Sum(summary => summary.NamedApiCount);
        var ordinalImportCount = moduleSummaries.Sum(summary => summary.OrdinalImportCount);
        AddInterestingString(
            interestingStrings,
            $"import-summary:modules={moduleSummaries.Count},namedApis={namedApiCount},ordinals={ordinalImportCount}");

        foreach (var summary in moduleSummaries.Take(MaxImportSummaryModules))
        {
            AddInterestingString(
                interestingStrings,
                $"import-module:{summary.DllName},namedApis={summary.NamedApiCount},ordinals={summary.OrdinalImportCount}");
        }

        peEvidence.Imports = moduleSummaries
            .Take(MaxStructuredPeEntries)
            .Select(summary => new PeImportModuleInfo
            {
                ModuleName = summary.DllName,
                NamedApiCount = summary.NamedApiCount,
                OrdinalImportCount = summary.OrdinalImportCount,
                ApiNames = summary.ApiNames
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(MaxStructuredPeEntries)
                    .ToList(),
                OrdinalImports = summary.OrdinalImports
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(MaxStructuredPeEntries)
                    .ToList(),
                SuspiciousApiNames = summary.SuspiciousApiNames
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(MaxStructuredPeEntries)
                    .ToList(),
                SuspiciousApiClusters = summary.SuspiciousApiClusters
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(MaxStructuredPeEntries)
                    .ToList()
            })
            .ToList();

        if (suspiciousApiClusters.Count == 0)
        {
            return;
        }

        tags.Add("import_suspicious_api_cluster");
        if (suspiciousApiClusters.Count > 1)
        {
            tags.Add("import_multi_suspicious_api_cluster");
        }

        foreach (var cluster in suspiciousApiClusters
            .OrderByDescending(cluster => cluster.Value.HitCount)
            .ThenBy(cluster => cluster.Key, StringComparer.OrdinalIgnoreCase)
            .Take(MaxImportApiClusterEvidence))
        {
            AddInterestingString(interestingStrings, $"import-api-cluster:{cluster.Key},hits={cluster.Value.HitCount}");
        }

        peEvidence.ImportApiClusters = suspiciousApiClusters
            .Values
            .OrderByDescending(cluster => cluster.HitCount)
            .ThenBy(cluster => cluster.Name, StringComparer.OrdinalIgnoreCase)
            .Take(MaxStructuredPeEntries)
            .Select(cluster => new PeImportApiClusterInfo
            {
                Name = cluster.Name,
                HitCount = cluster.HitCount,
                ApiNames = cluster.ApiNames
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(MaxStructuredPeEntries)
                    .ToList()
            })
            .ToList();
    }

    /// <summary>
    /// Reads IMAGE_DEBUG_DIRECTORY entries and selected CodeView metadata.
    /// Inputs are the PE debug data directory and section layouts; processing
    /// keeps entry and string parsing bounded; the method records debug/PDB
    /// evidence without treating it as malicious by itself.
    /// </summary>
    private static void ReadDebugDirectory(
        BinaryReader reader,
        PeDataDirectory debugDirectory,
        IReadOnlyList<PeSectionLayout> sections,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings)
    {
        if (!debugDirectory.IsPresent || debugDirectory.Size == 0)
        {
            return;
        }

        tags.Add("debug_directory_present");
        if (!TryRvaToFileOffset(debugDirectory.Rva, sections, fileLength, out var debugOffset))
        {
            warnings.Add($"Debug directory RVA 0x{debugDirectory.Rva:X8} could not be mapped to a file offset.");
            return;
        }

        const int debugDirectoryEntrySize = 28;
        if (debugOffset < 0 || debugOffset > fileLength - debugDirectoryEntrySize)
        {
            warnings.Add("Debug directory is truncated.");
            return;
        }

        var entryLimit = Math.Min(MaxDebugEntries, Math.Max(1, (int)(debugDirectory.Size / debugDirectoryEntrySize)));
        if (debugDirectory.Size / debugDirectoryEntrySize > MaxDebugEntries)
        {
            warnings.Add($"Debug-directory scan truncated at {MaxDebugEntries} entries.");
        }

        var evidenceCount = 0;
        AddPeEvidence(interestingStrings, $"debug:directory@rva=0x{debugDirectory.Rva:X8},size={debugDirectory.Size}", ref evidenceCount, MaxDebugEntries);
        for (var index = 0; index < entryLimit; index++)
        {
            var entryOffset = debugOffset + index * debugDirectoryEntrySize;
            if (entryOffset < 0 || entryOffset > fileLength - debugDirectoryEntrySize)
            {
                break;
            }

            var type = ReadUInt32At(reader, entryOffset + 12, fileLength, warnings);
            var sizeOfData = ReadUInt32At(reader, entryOffset + 16, fileLength, warnings);
            var addressOfRawData = ReadUInt32At(reader, entryOffset + 20, fileLength, warnings);
            var pointerToRawData = ReadUInt32At(reader, entryOffset + 24, fileLength, warnings);
            var typeText = DescribeDebugType(type);
            tags.Add($"debug_type_{NormalizeTagComponent(typeText)}");

            if (type == 2)
            {
                tags.Add("debug_codeview_present");
            }

            if (type == 16)
            {
                tags.Add("debug_reproducible_build");
            }

            var dataOffsetText = "unmapped";
            long? dataOffset = null;
            if (pointerToRawData > 0 && pointerToRawData < fileLength)
            {
                dataOffset = pointerToRawData;
                dataOffsetText = $"0x{pointerToRawData:X}";
            }
            else if (addressOfRawData > 0 && TryRvaToFileOffset(addressOfRawData, sections, fileLength, out var mappedOffset))
            {
                dataOffset = mappedOffset;
                dataOffsetText = $"0x{mappedOffset:X}";
            }

            AddPeEvidence(
                interestingStrings,
                $"debug:entry[{index + 1}],type={typeText},size={sizeOfData},rva=0x{addressOfRawData:X8},file={dataOffsetText}",
                ref evidenceCount,
                MaxDebugEntries);

            if (type == 2 && dataOffset is { } codeViewOffset && sizeOfData >= 4)
            {
                ReadCodeViewDebugEvidence(reader, codeViewOffset, sizeOfData, fileLength, tags, interestingStrings, warnings, ref evidenceCount);
            }
        }
    }

    /// <summary>
    /// Reads CodeView RSDS/NB10 records for PDB-path evidence.
    /// </summary>
    private static void ReadCodeViewDebugEvidence(
        BinaryReader reader,
        long dataOffset,
        uint dataSize,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        ref int evidenceCount)
    {
        if (dataOffset < 0 || dataOffset > fileLength - 4)
        {
            warnings.Add("CodeView debug data is truncated.");
            return;
        }

        var dataEnd = Math.Min(fileLength, dataOffset + dataSize);
        reader.BaseStream.Position = dataOffset;
        var signature = Encoding.ASCII.GetString(reader.ReadBytes(4));
        if (string.Equals(signature, "RSDS", StringComparison.Ordinal))
        {
            tags.Add("debug_rsds_present");
            if (dataEnd - dataOffset < 24)
            {
                return;
            }

            var guidBytes = reader.ReadBytes(16);
            var pdbGuid = new Guid(guidBytes);
            var age = TryReadUInt32At(reader, dataOffset + 20, fileLength, out var ageValue) ? ageValue : 0;
            var pdbPath = ReadAsciiStringAt(reader, dataOffset + 24, fileLength);
            AddPeEvidence(
                interestingStrings,
                string.IsNullOrWhiteSpace(pdbPath)
                    ? $"debug:codeview=RSDS,guid={pdbGuid:N},age={age}"
                    : $"debug:codeview=RSDS,guid={pdbGuid:N},age={age},pdb={TrimEvidence(pdbPath)}",
                ref evidenceCount,
                MaxDebugEntries);
            AddPdbPathEvidence(pdbPath, tags, interestingStrings, ref evidenceCount);
            return;
        }

        if (string.Equals(signature, "NB10", StringComparison.Ordinal))
        {
            tags.Add("debug_nb10_present");
            if (dataEnd - dataOffset < 16)
            {
                return;
            }

            var timestamp = TryReadUInt32At(reader, dataOffset + 8, fileLength, out var timestampValue) ? timestampValue : 0;
            var age = TryReadUInt32At(reader, dataOffset + 12, fileLength, out var ageValue) ? ageValue : 0;
            var pdbPath = ReadAsciiStringAt(reader, dataOffset + 16, fileLength);
            AddPeEvidence(
                interestingStrings,
                string.IsNullOrWhiteSpace(pdbPath)
                    ? $"debug:codeview=NB10,timestamp=0x{timestamp:X8},age={age}"
                    : $"debug:codeview=NB10,timestamp=0x{timestamp:X8},age={age},pdb={TrimEvidence(pdbPath)}",
                ref evidenceCount,
                MaxDebugEntries);
            AddPdbPathEvidence(pdbPath, tags, interestingStrings, ref evidenceCount);
            return;
        }

        AddPeEvidence(interestingStrings, $"debug:codeview-signature={signature}", ref evidenceCount, MaxDebugEntries);
    }

    /// <summary>
    /// Adds bounded PDB-path evidence and coarse path-shape tags.
    /// </summary>
    private static void AddPdbPathEvidence(string? pdbPath, SortedSet<string> tags, SortedSet<string> interestingStrings, ref int evidenceCount)
    {
        if (string.IsNullOrWhiteSpace(pdbPath))
        {
            return;
        }

        var trimmed = TrimEvidence(pdbPath);
        tags.Add("debug_pdb_path");
        if (WindowsPathPattern.IsMatch(trimmed))
        {
            tags.Add("debug_pdb_path_absolute");
        }

        if (ContainsAny(trimmed, "\\Users\\", "\\Documents\\", "\\source\\", "\\src\\", "\\build\\", "\\agent\\_work\\"))
        {
            tags.Add("debug_pdb_build_path");
        }

        AddPeEvidence(interestingStrings, $"debug:pdb-path:{trimmed}", ref evidenceCount, MaxDebugEntries);
    }

    /// <summary>
    /// Reads the PE resource tree and records type/data-level triage tags.
    /// Inputs are the resource data directory and section layouts, processing
    /// walks bounded IMAGE_RESOURCE_DIRECTORY nodes, and the method records
    /// payload, manifest, icon, high-entropy, and embedded-PE evidence.
    /// </summary>
    private static void ReadResources(
        BinaryReader reader,
        PeDataDirectory resourceDirectory,
        IReadOnlyList<PeSectionLayout> sections,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence)
    {
        if (!resourceDirectory.IsPresent)
        {
            return;
        }

        tags.Add("resources_present");
        if (!TryRvaToFileOffset(resourceDirectory.Rva, sections, fileLength, out var resourceRootOffset))
        {
            warnings.Add($"Resource directory RVA 0x{resourceDirectory.Rva:X8} could not be mapped to a file offset.");
            return;
        }

        var evidenceCount = 0;
        var visitedDirectories = new HashSet<long>();
        WalkResourceDirectory(
            reader,
            resourceRootOffset,
            resourceRootOffset,
            depth: 0,
            resourceType: null,
            sections,
            fileLength,
            tags,
            interestingStrings,
            warnings,
            peEvidence,
            visitedDirectories,
            ref evidenceCount);
    }

    /// <summary>
    /// Walks one IMAGE_RESOURCE_DIRECTORY node.
    /// Inputs are resource-root and current-directory offsets, processing keeps
    /// recursion and entry counts bounded, and the method emits tags/evidence.
    /// </summary>
    private static void WalkResourceDirectory(
        BinaryReader reader,
        long resourceRootOffset,
        long directoryOffset,
        int depth,
        string? resourceType,
        IReadOnlyList<PeSectionLayout> sections,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence,
        HashSet<long> visitedDirectories,
        ref int evidenceCount)
    {
        if (depth > MaxResourceDepth)
        {
            warnings.Add("Resource-directory recursion depth limit reached.");
            return;
        }

        if (!visitedDirectories.Add(directoryOffset))
        {
            return;
        }

        if (directoryOffset < 0 || directoryOffset > fileLength - 16)
        {
            warnings.Add("Resource directory is truncated.");
            return;
        }

        var numberOfNamedEntries = ReadUInt16At(reader, directoryOffset + 12, fileLength, warnings);
        var numberOfIdEntries = ReadUInt16At(reader, directoryOffset + 14, fileLength, warnings);
        var totalEntries = numberOfNamedEntries + numberOfIdEntries;
        if (totalEntries > MaxResourceEntries)
        {
            warnings.Add($"Resource-directory scan truncated at {MaxResourceEntries} of {totalEntries} entries.");
        }

        for (var index = 0; index < Math.Min(totalEntries, MaxResourceEntries); index++)
        {
            var entryOffset = directoryOffset + 16 + index * 8L;
            if (entryOffset < 0 || entryOffset > fileLength - 8)
            {
                break;
            }

            var nameOrId = ReadUInt32At(reader, entryOffset, fileLength, warnings);
            var dataOrDirectory = ReadUInt32At(reader, entryOffset + sizeof(uint), fileLength, warnings);
            var entryName = ReadResourceEntryName(reader, resourceRootOffset, nameOrId, fileLength, tags);
            var currentType = depth == 0 ? DescribeResourceType(nameOrId, entryName) : resourceType;
            if (depth == 0)
            {
                AddResourceTypeTags(currentType, tags, interestingStrings, ref evidenceCount);
            }

            var isDirectory = (dataOrDirectory & 0x80000000) != 0;
            var relativeOffset = dataOrDirectory & 0x7fffffff;
            var childOffset = resourceRootOffset + relativeOffset;
            if (isDirectory)
            {
                WalkResourceDirectory(
                    reader,
                    resourceRootOffset,
                    childOffset,
                    depth + 1,
                    currentType,
                    sections,
                    fileLength,
                    tags,
                    interestingStrings,
                    warnings,
                    peEvidence,
                    visitedDirectories,
                    ref evidenceCount);
                continue;
            }

            ReadResourceDataEntry(
                reader,
                childOffset,
                currentType ?? "unknown",
                sections,
                fileLength,
                tags,
                interestingStrings,
                warnings,
                peEvidence,
                ref evidenceCount);
        }
    }

    /// <summary>
    /// Reads one IMAGE_RESOURCE_DATA_ENTRY and classifies payload traits.
    /// Inputs are the data-entry offset and resource type, processing maps the
    /// data RVA when possible, and the method records resource evidence.
    /// </summary>
    private static void ReadResourceDataEntry(
        BinaryReader reader,
        long dataEntryOffset,
        string resourceType,
        IReadOnlyList<PeSectionLayout> sections,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence,
        ref int evidenceCount)
    {
        if (dataEntryOffset < 0 || dataEntryOffset > fileLength - 16)
        {
            warnings.Add("Resource data entry is truncated.");
            return;
        }

        var dataRva = ReadUInt32At(reader, dataEntryOffset, fileLength, warnings);
        var size = ReadUInt32At(reader, dataEntryOffset + sizeof(uint), fileLength, warnings);
        var resourceTags = new SortedSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "resources_present",
            "resource_data_entry",
            $"resource_type_{NormalizeStaticYaraTag(resourceType)}"
        };
        AddPeEvidence(interestingStrings, $"resource:{resourceType},rva=0x{dataRva:X8},size={size}", ref evidenceCount, MaxResourceEvidence);
        if (size >= 1024 * 1024)
        {
            tags.Add("resource_large_data");
            resourceTags.Add("resource_large_data");
        }

        if (IsPayloadResourceType(resourceType))
        {
            tags.Add("resource_payload_candidate");
            resourceTags.Add("resource_payload_candidate");
        }

        var mapped = TryRvaToFileOffset(dataRva, sections, fileLength, out var dataOffset);
        double? entropy = null;
        var embeddedPe = false;
        if (mapped)
        {
            if (size >= 256)
            {
                entropy = CalculateEntropy(reader, dataOffset, size, fileLength, warnings);
                if (entropy >= 7.2)
                {
                    tags.Add("resource_high_entropy_data");
                    resourceTags.Add("resource_high_entropy_data");
                }

                if (entropy >= 7.8)
                {
                    tags.Add("resource_very_high_entropy_data");
                    resourceTags.Add("resource_very_high_entropy_data");
                }
            }

            AddPeEvidence(
                interestingStrings,
                entropy.HasValue
                    ? $"resource:{resourceType}@file=0x{dataOffset:X},rva=0x{dataRva:X8},size={size},entropy={Math.Round(entropy.Value, 3):F3},entropyLabel={DescribeEntropy(entropy.Value, size)}"
                    : $"resource:{resourceType}@file=0x{dataOffset:X},rva=0x{dataRva:X8},size={size}",
                ref evidenceCount,
                MaxResourceEvidence);

            if (TryReadUInt16At(reader, dataOffset, fileLength, out var magic) && magic == 0x5a4d)
            {
                embeddedPe = true;
                tags.Add("resource_embedded_pe");
                tags.Add("resource_payload_candidate");
                resourceTags.Add("resource_embedded_pe");
                resourceTags.Add("resource_payload_candidate");
                AddPeEvidence(interestingStrings, $"resource:{resourceType}:embedded-pe@0x{dataRva:X8}", ref evidenceCount, MaxResourceEvidence);
            }

            if (string.Equals(resourceType, "version", StringComparison.OrdinalIgnoreCase))
            {
                ReadVersionResourceEvidence(reader, dataOffset, size, fileLength, tags, interestingStrings, warnings, ref evidenceCount);
            }

            if (string.Equals(resourceType, "manifest", StringComparison.OrdinalIgnoreCase))
            {
                ReadManifestResourceEvidence(reader, dataOffset, size, fileLength, tags, interestingStrings, warnings, ref evidenceCount);
            }
        }
        else
        {
            resourceTags.Add("resource_unmapped_rva");
        }

        AddPeResourceInfo(
            peEvidence,
            resourceType,
            dataRva,
            mapped ? dataOffset : null,
            size,
            entropy,
            embeddedPe,
            resourceTags);
    }

    /// <summary>
    /// Adds one structured PE resource data-entry record for reports and rules.
    /// </summary>
    private static void AddPeResourceInfo(
        PeAnalysisEvidence peEvidence,
        string resourceType,
        uint dataRva,
        long? dataOffset,
        uint size,
        double? entropy,
        bool embeddedPe,
        IEnumerable<string> resourceTags)
    {
        if (peEvidence.Resources.Count >= MaxStructuredPeEntries)
        {
            return;
        }

        var tags = resourceTags
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var payloadCandidate = tags.Contains("resource_payload_candidate", StringComparer.OrdinalIgnoreCase);
        peEvidence.Resources.Add(new PeResourceInfo
        {
            ResourceType = resourceType,
            DataRva = $"0x{dataRva:X8}",
            DataFileOffset = dataOffset.HasValue ? $"0x{dataOffset.Value:X}" : null,
            Size = size,
            Entropy = entropy,
            EntropyLabel = entropy.HasValue ? DescribeEntropy(entropy.Value, size) : "unknown",
            IsPayloadCandidate = payloadCandidate,
            IsEmbeddedPe = embeddedPe,
            IsLarge = size >= 1024 * 1024,
            Tags = tags
        });
    }

    /// <summary>
    /// Identifies resource types that often carry staged payloads.
    /// </summary>
    private static bool IsPayloadResourceType(string resourceType)
    {
        return string.Equals(resourceType, "rcdata", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "html", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "unknown", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "named", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Extracts bounded VERSIONINFO key/value strings from an RT_VERSION
    /// resource. The parser is intentionally heuristic and emits only low-risk
    /// metadata tags plus copyable evidence strings.
    /// </summary>
    private static void ReadVersionResourceEvidence(
        BinaryReader reader,
        long dataOffset,
        uint size,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        ref int evidenceCount)
    {
        var data = ReadBoundedBytes(reader, dataOffset, size, fileLength, MaxResourceStringBytes, warnings);
        if (data.Length == 0)
        {
            return;
        }

        tags.Add("version_info_present");
        var strings = EnumerateUtf16ResourceStrings(data, minimumLength: 2)
            .Select(TrimEvidence)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Take(256)
            .ToList();
        if (strings.Count == 0)
        {
            return;
        }

        var emitted = 0;
        for (var index = 0; index < strings.Count && emitted < MaxVersionStringEvidence; index++)
        {
            var key = VersionStringKeys.FirstOrDefault(candidate =>
                string.Equals(strings[index], candidate, StringComparison.OrdinalIgnoreCase));
            if (key is null)
            {
                continue;
            }

            var value = FindVersionValue(strings, index + 1);
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            tags.Add("version_info_string");
            tags.Add($"version_{NormalizeTagComponent(key)}");
            AddPeEvidence(interestingStrings, $"version:{key}={value}", ref evidenceCount, MaxResourceEvidence);
            emitted++;
        }
    }

    /// <summary>
    /// Extracts selected RT_MANIFEST traits such as requested execution level.
    /// These are metadata indicators only and are not treated as malicious.
    /// </summary>
    private static void ReadManifestResourceEvidence(
        BinaryReader reader,
        long dataOffset,
        uint size,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        ref int evidenceCount)
    {
        var data = ReadBoundedBytes(reader, dataOffset, size, fileLength, MaxResourceStringBytes, warnings);
        if (data.Length == 0)
        {
            return;
        }

        var utf8 = Encoding.UTF8.GetString(data);
        var unicode = data.Length >= 2 ? Encoding.Unicode.GetString(data) : string.Empty;
        var text = utf8.Contains("assembly", StringComparison.OrdinalIgnoreCase) ||
            utf8.Contains("requestedExecutionLevel", StringComparison.OrdinalIgnoreCase)
                ? utf8
                : unicode;

        if (!text.Contains("assembly", StringComparison.OrdinalIgnoreCase) &&
            !text.Contains("requestedExecutionLevel", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        tags.Add("manifest_resource_string");
        if (ManifestRequestedExecutionLevelPattern.Match(text) is { Success: true } levelMatch)
        {
            var level = TrimEvidence(levelMatch.Groups["level"].Value);
            tags.Add("manifest_requested_execution_level");
            if (level.Contains("requireAdministrator", StringComparison.OrdinalIgnoreCase))
            {
                tags.Add("manifest_require_administrator");
            }

            if (level.Contains("highestAvailable", StringComparison.OrdinalIgnoreCase))
            {
                tags.Add("manifest_highest_available");
            }

            AddPeEvidence(interestingStrings, $"manifest:requestedExecutionLevel={level}", ref evidenceCount, MaxResourceEvidence);
        }

        if (text.Contains("<autoElevate>true</autoElevate>", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("<autoElevate>true", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("manifest_auto_elevate");
            AddPeEvidence(interestingStrings, "manifest:autoElevate=true", ref evidenceCount, MaxResourceEvidence);
        }

        if (text.Contains("uiAccess=\"true\"", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("uiAccess='true'", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("manifest_ui_access");
            AddPeEvidence(interestingStrings, "manifest:uiAccess=true", ref evidenceCount, MaxResourceEvidence);
        }
    }

    /// <summary>
    /// Reads a bounded resource-data byte slice without seeking outside the file.
    /// </summary>
    private static byte[] ReadBoundedBytes(
        BinaryReader reader,
        long offset,
        uint declaredSize,
        long fileLength,
        int maxBytes,
        List<string> warnings)
    {
        if (offset < 0 || offset >= fileLength || maxBytes <= 0)
        {
            return [];
        }

        var available = Math.Max(0, fileLength - offset);
        var readLength = (int)Math.Min(Math.Min(declaredSize, (ulong)available), (ulong)maxBytes);
        if (readLength <= 0)
        {
            return [];
        }

        if (declaredSize > maxBytes)
        {
            warnings.Add($"Resource string scan truncated at {maxBytes} bytes.");
        }

        reader.BaseStream.Position = offset;
        return reader.ReadBytes(readLength);
    }

    /// <summary>
    /// Enumerates printable UTF-16LE strings with a caller-supplied minimum
    /// length for resource metadata where values may be shorter than general
    /// executable strings.
    /// </summary>
    private static IEnumerable<string> EnumerateUtf16ResourceStrings(byte[] buffer, int minimumLength)
    {
        var builder = new StringBuilder();
        for (var index = 0; index + 1 < buffer.Length; index += 2)
        {
            var low = buffer[index];
            var high = buffer[index + 1];
            if (high == 0 && low is >= 0x20 and <= 0x7e)
            {
                builder.Append((char)low);
                continue;
            }

            if (builder.Length >= minimumLength)
            {
                yield return builder.ToString();
            }

            builder.Clear();
        }

        if (builder.Length >= minimumLength)
        {
            yield return builder.ToString();
        }
    }

    /// <summary>
    /// Finds the next plausible VERSIONINFO value after a known key.
    /// </summary>
    private static string? FindVersionValue(IReadOnlyList<string> strings, int startIndex)
    {
        for (var index = startIndex; index < strings.Count && index < startIndex + 8; index++)
        {
            var candidate = TrimEvidence(strings[index]);
            if (string.IsNullOrWhiteSpace(candidate) ||
                IsVersionStructuralString(candidate) ||
                VersionStringKeys.Contains(candidate, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            return candidate.Length > 120 ? candidate[..120] : candidate;
        }

        return null;
    }

    /// <summary>
    /// Suppresses VERSIONINFO container/language keys when choosing values.
    /// </summary>
    private static bool IsVersionStructuralString(string value)
    {
        return string.Equals(value, "VS_VERSION_INFO", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "StringFileInfo", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "VarFileInfo", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "Translation", StringComparison.OrdinalIgnoreCase) ||
            Regex.IsMatch(value, "^[0-9A-Fa-f]{8}$", RegexOptions.CultureInvariant);
    }

    /// <summary>
    /// Reads a resource entry name or numeric ID.
    /// Inputs are the raw name/id field and resource-root offset, processing
    /// resolves bounded UTF-16 names, and the method returns a display token.
    /// </summary>
    private static string ReadResourceEntryName(BinaryReader reader, long resourceRootOffset, uint nameOrId, long fileLength, SortedSet<string> tags)
    {
        if ((nameOrId & 0x80000000) == 0)
        {
            return (nameOrId & 0xffff).ToString();
        }

        tags.Add("resource_named_entry");
        var nameOffset = resourceRootOffset + (nameOrId & 0x7fffffff);
        if (nameOffset < 0 || nameOffset > fileLength - sizeof(ushort))
        {
            return "named";
        }

        reader.BaseStream.Position = nameOffset;
        var length = reader.ReadUInt16();
        var maxChars = Math.Min(length, (ushort)64);
        if (nameOffset + sizeof(ushort) + maxChars * 2L > fileLength)
        {
            return "named";
        }

        var bytes = reader.ReadBytes(maxChars * 2);
        var name = Encoding.Unicode.GetString(bytes).Trim('\0').Trim();
        return string.IsNullOrWhiteSpace(name) ? "named" : name;
    }

    /// <summary>
    /// Maps a root-level resource type ID/name to a stable token.
    /// Inputs are the resource ID/name field, processing recognizes common PE
    /// resource IDs, and the method returns a lower-case tag component.
    /// </summary>
    private static string DescribeResourceType(uint nameOrId, string entryName)
    {
        if ((nameOrId & 0x80000000) != 0)
        {
            return "named";
        }

        return (nameOrId & 0xffff) switch
        {
            1 => "cursor",
            2 => "bitmap",
            3 => "icon",
            4 => "menu",
            5 => "dialog",
            6 => "string",
            7 => "fontdir",
            8 => "font",
            9 => "accelerator",
            10 => "rcdata",
            11 => "message_table",
            12 => "group_cursor",
            14 => "group_icon",
            16 => "version",
            17 => "dlginclude",
            19 => "plugplay",
            20 => "vxd",
            21 => "animated_cursor",
            22 => "animated_icon",
            23 => "html",
            24 => "manifest",
            _ => string.IsNullOrWhiteSpace(entryName) ? "unknown" : "unknown"
        };
    }

    /// <summary>
    /// Adds high-level resource type tags and bounded evidence.
    /// Inputs are the resource type token and output collections, processing
    /// highlights payload-bearing types, and the method returns no value.
    /// </summary>
    private static void AddResourceTypeTags(string? resourceType, SortedSet<string> tags, SortedSet<string> interestingStrings, ref int evidenceCount)
    {
        if (string.IsNullOrWhiteSpace(resourceType))
        {
            return;
        }

        tags.Add($"resource_type_{resourceType}");
        AddPeEvidence(interestingStrings, $"resource-type:{resourceType}", ref evidenceCount, MaxResourceEvidence);
        if (string.Equals(resourceType, "manifest", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("resource_manifest");
        }

        if (string.Equals(resourceType, "version", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("resource_version_info");
        }

        if (resourceType.Contains("icon", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("resource_icon");
        }

        if (string.Equals(resourceType, "rcdata", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "html", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "named", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("resource_payload_candidate");
        }
    }

    /// <summary>
    /// Reads PE export names and classifies registration-style entry points.
    /// Inputs are the export data directory and section layouts, processing
    /// reads bounded export-name RVAs, and the method records static evidence.
    /// </summary>
    private static void ReadExports(
        BinaryReader reader,
        PeDataDirectory exportDirectory,
        IReadOnlyList<PeSectionLayout> sections,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence)
    {
        if (!exportDirectory.IsPresent)
        {
            return;
        }

        tags.Add("exports_present");
        if (!TryRvaToFileOffset(exportDirectory.Rva, sections, fileLength, out var exportOffset))
        {
            warnings.Add($"Export directory RVA 0x{exportDirectory.Rva:X8} could not be mapped to a file offset.");
            return;
        }

        if (exportOffset < 0 || exportOffset > fileLength - 40)
        {
            warnings.Add("Export directory is truncated.");
            return;
        }

        var evidenceCount = 0;
        var dllNameRva = ReadUInt32At(reader, exportOffset + 12, fileLength, warnings);
        var dllName = TryReadRvaAsciiString(reader, dllNameRva, sections, fileLength);
        if (!string.IsNullOrWhiteSpace(dllName))
        {
            AddPeEvidence(interestingStrings, $"export-module:{dllName}", ref evidenceCount, MaxExportNames);
            peEvidence.ExportModuleName = dllName;
        }

        var numberOfNames = ReadUInt32At(reader, exportOffset + 24, fileLength, warnings);
        var addressOfNames = ReadUInt32At(reader, exportOffset + 32, fileLength, warnings);
        if (numberOfNames > MaxExportNames)
        {
            warnings.Add($"Export-name scan truncated at {MaxExportNames} of {numberOfNames} names.");
        }

        if (!TryRvaToFileOffset(addressOfNames, sections, fileLength, out var namesOffset))
        {
            return;
        }

        for (var index = 0; index < Math.Min(numberOfNames, MaxExportNames); index++)
        {
            var namePointerOffset = namesOffset + index * sizeof(uint);
            if (!TryReadUInt32At(reader, namePointerOffset, fileLength, out var nameRva))
            {
                break;
            }

            var name = TryReadRvaAsciiString(reader, nameRva, sections, fileLength);
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            AddPeEvidence(interestingStrings, $"export:{name}", ref evidenceCount, MaxExportNames);
            AddBounded(peEvidence.ExportNames, name, MaxStructuredPeEntries);
            AddExportTags(name, tags);
        }
    }

    /// <summary>
    /// Reads the PE TLS directory and optional callback pointer array.
    /// Inputs are the TLS data directory and PE image base, processing maps VA
    /// callback arrays when possible, and the method records static tags.
    /// </summary>
    private static void ReadTlsDirectory(
        BinaryReader reader,
        PeDataDirectory tlsDirectory,
        IReadOnlyList<PeSectionLayout> sections,
        ushort optionalMagic,
        ulong imageBase,
        long fileLength,
        SortedSet<string> tags,
        SortedSet<string> interestingStrings,
        List<string> warnings,
        PeAnalysisEvidence peEvidence)
    {
        if (!tlsDirectory.IsPresent)
        {
            return;
        }

        tags.Add("tls_directory_present");
        var evidenceCount = 0;
        string? callbackTableText = null;
        string? callbackTableFileOffset = null;
        var callbacks = new List<PeTlsCallbackInfo>();
        AddPeEvidence(interestingStrings, "tls:directory", ref evidenceCount, MaxTlsCallbacks);
        if (!TryRvaToFileOffset(tlsDirectory.Rva, sections, fileLength, out var tlsOffset))
        {
            warnings.Add($"TLS directory RVA 0x{tlsDirectory.Rva:X8} could not be mapped to a file offset.");
            peEvidence.Tls = new PeTlsInfo { DirectoryPresent = true };
            return;
        }

        var isPe32Plus = optionalMagic == 0x20b;
        var callbackVaOffset = tlsOffset + (isPe32Plus ? 24 : 12);
        var callbacksVa = isPe32Plus
            ? ReadUInt64At(reader, callbackVaOffset, fileLength, warnings)
            : ReadUInt32At(reader, callbackVaOffset, fileLength, warnings);
        if (callbacksVa == 0)
        {
            peEvidence.Tls = new PeTlsInfo { DirectoryPresent = true };
            return;
        }

        tags.Add("tls_callback_pointer");
        callbackTableText = $"0x{callbacksVa:X}";
        if (!TryVaToFileOffset(callbacksVa, imageBase, sections, fileLength, out var callbacksOffset))
        {
            AddPeEvidence(interestingStrings, $"tls:callback-table@0x{callbacksVa:X}", ref evidenceCount, MaxTlsCallbacks);
            peEvidence.Tls = new PeTlsInfo
            {
                DirectoryPresent = true,
                CallbackTableVa = callbackTableText
            };
            return;
        }

        callbackTableFileOffset = $"0x{callbacksOffset:X}";
        AddPeEvidence(
            interestingStrings,
            $"tls:callback-table@0x{callbacksVa:X},file=0x{callbacksOffset:X}",
            ref evidenceCount,
            MaxTlsCallbacks);
        var pointerSize = isPe32Plus ? sizeof(ulong) : sizeof(uint);
        for (var index = 0; index < MaxTlsCallbacks; index++)
        {
            var callbackEntryOffset = callbacksOffset + (long)index * pointerSize;
            if (callbackEntryOffset < 0 || callbackEntryOffset > fileLength - pointerSize)
            {
                break;
            }

            var callbackVa = isPe32Plus
                ? TryReadUInt64At(reader, callbackEntryOffset, fileLength, out var value64) ? value64 : 0
                : TryReadUInt32At(reader, callbackEntryOffset, fileLength, out var value32) ? value32 : 0UL;
            if (callbackVa == 0)
            {
                break;
            }

            tags.Add("tls_callbacks");
            var relativeVirtualAddress = TryVaToRva(callbackVa, imageBase, out var callbackRva)
                ? $"0x{callbackRva:X8}"
                : null;
            var targetOffsetText = TryVaToFileOffset(callbackVa, imageBase, sections, fileLength, out var callbackTargetOffset)
                ? $"0x{callbackTargetOffset:X}"
                : "unmapped";
            if (string.Equals(targetOffsetText, "unmapped", StringComparison.OrdinalIgnoreCase))
            {
                tags.Add("tls_callback_target_unmapped");
            }

            AddPeEvidence(
                interestingStrings,
                relativeVirtualAddress is null
                    ? $"tls:callback@0x{callbackVa:X},file={targetOffsetText}"
                    : $"tls:callback@0x{callbackVa:X},rva={relativeVirtualAddress},file={targetOffsetText}",
                ref evidenceCount,
                MaxTlsCallbacks);
            callbacks.Add(new PeTlsCallbackInfo
            {
                VirtualAddress = $"0x{callbackVa:X}",
                RelativeVirtualAddress = relativeVirtualAddress
            });
        }

        peEvidence.Tls = new PeTlsInfo
        {
            DirectoryPresent = true,
            CallbackTableVa = callbackTableText,
            CallbackTableFileOffset = callbackTableFileOffset,
            Callbacks = callbacks
        };
    }

    /// <summary>
    /// Adds grouped tags for suspicious Windows API imports or strings.
    /// Inputs are one API-like text value and tag set, processing matches
    /// curated API tokens instead of raw substrings, and the method returns no value.
    /// </summary>
    private static void AddSuspiciousApiTags(string apiName, SortedSet<string> tags)
    {
        if (ContainsAnyApiToken(apiName, ProcessInjectionApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_process_injection_api");
        }

        if (ContainsAnyApiToken(apiName, DynamicCodeApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_dynamic_code_api");
        }

        if (ContainsAnyApiToken(apiName, RegistryPersistenceApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_persistence_api");
            tags.Add("import_registry_persistence_api");
        }

        if (ContainsAnyApiToken(apiName, ServicePersistenceApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_persistence_api");
            tags.Add("import_service_persistence_api");
        }

        if (ContainsAnyApiToken(apiName, PersistenceApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_persistence_api");
        }

        if (ContainsAnyApiToken(apiName, NetworkApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_network_api");
        }

        if (ContainsAnyApiToken(apiName, DownloadApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_network_api");
            tags.Add("import_download_api");
        }

        if (ContainsAnyApiToken(apiName, ExfiltrationApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_network_api");
            tags.Add("import_exfil_api");
        }

        if (ContainsAnyApiToken(apiName, FileDropApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_file_drop_api");
        }

        if (ContainsScriptExecutionApi(apiName))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_script_execution_api");
        }

        if (ContainsAnyApiToken(apiName, ResourceApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_resource_api");
        }

        if (ContainsAnyApiToken(apiName, AntiAnalysisApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_anti_analysis_api");
            tags.Add("anti_analysis_string");
            tags.Add("debugger_evasion_string");
        }

        if (ContainsAnyApiToken(apiName, AntiDebugApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_anti_analysis_api");
            tags.Add("import_anti_debug_api");
            tags.Add("anti_analysis_string");
            tags.Add("debugger_evasion_string");
            tags.Add("anti_debug_string");
        }

        if (ContainsAnyApiToken(apiName, CredentialAccessApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_credential_access_api");
        }

        if (ContainsAnyApiToken(apiName, DefenseEvasionApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_defense_evasion_api");
        }
    }

    /// <summary>
    /// Maps a suspicious API-like token to report-friendly behavior clusters.
    /// Inputs are one imported or embedded API name; processing reuses the
    /// same curated groups as tag classification; the method yields stable
    /// cluster names for aggregate import-table evidence.
    /// </summary>
    private static IEnumerable<string> GetSuspiciousApiClusters(string apiName)
    {
        if (ContainsAnyApiToken(apiName, ProcessInjectionApis))
        {
            yield return "process-injection";
        }

        if (ContainsAnyApiToken(apiName, DynamicCodeApis))
        {
            yield return "dynamic-code";
        }

        if (ContainsAnyApiToken(apiName, RegistryPersistenceApis))
        {
            yield return "registry-persistence";
        }

        if (ContainsAnyApiToken(apiName, ServicePersistenceApis))
        {
            yield return "service-persistence";
        }

        if (ContainsAnyApiToken(apiName, PersistenceApis))
        {
            yield return "persistence";
        }

        if (ContainsAnyApiToken(apiName, NetworkApis))
        {
            yield return "network";
        }

        if (ContainsAnyApiToken(apiName, DownloadApis))
        {
            yield return "download";
        }

        if (ContainsAnyApiToken(apiName, ExfiltrationApis))
        {
            yield return "exfiltration";
        }

        if (ContainsAnyApiToken(apiName, FileDropApis))
        {
            yield return "file-drop";
        }

        if (ContainsScriptExecutionApi(apiName))
        {
            yield return "script-execution";
        }

        if (ContainsAnyApiToken(apiName, ResourceApis))
        {
            yield return "resource";
        }

        if (ContainsAnyApiToken(apiName, AntiAnalysisApis))
        {
            yield return "anti-analysis";
        }

        if (ContainsAnyApiToken(apiName, AntiDebugApis))
        {
            yield return "anti-debug";
        }

        if (ContainsAnyApiToken(apiName, CredentialAccessApis))
        {
            yield return "credential-access";
        }

        if (ContainsAnyApiToken(apiName, DefenseEvasionApis))
        {
            yield return "defense-evasion";
        }
    }

    /// <summary>
    /// Adds coarse tags for imported DLL families.
    /// Inputs are a module name and tag set, processing checks common Windows
    /// networking/script/crypto modules, and the method returns no value.
    /// </summary>
    private static void AddImportModuleTags(string dllName, SortedSet<string> tags)
    {
        if (ContainsAny(dllName, "wininet", "winhttp", "urlmon", "ws2_32", "wsock32", "dnsapi"))
        {
            tags.Add("import_network_library");
        }

        if (ContainsAny(dllName, "advapi32"))
        {
            tags.Add("import_registry_or_service_library");
        }

        if (ContainsAny(dllName, "shell32"))
        {
            tags.Add("import_shell_execution_library");
        }

        if (ContainsAny(dllName, "wincrypt", "bcrypt", "crypt32", "ncrypt"))
        {
            tags.Add("import_crypto_library");
        }

        if (ContainsAny(dllName, "dbghelp", "vaultcli", "credui", "samlib", "ntdsapi"))
        {
            tags.Add("import_credential_access_library");
        }

        if (ContainsAny(dllName, "amsi", "wevtapi", "wscapi"))
        {
            tags.Add("import_defense_evasion_library");
        }
    }

    /// <summary>
    /// Adds tags for export names that imply special loader entry points.
    /// The input is one export name, processing checks common registration and
    /// service callbacks, and the method returns no value.
    /// </summary>
    private static void AddExportTags(string exportName, SortedSet<string> tags)
    {
        if (ContainsAny(exportName, "DllRegisterServer", "DllUnregisterServer", "DllInstall"))
        {
            tags.Add("export_registration_entrypoint");
        }

        if (ContainsAny(exportName, "ServiceMain", "SvchostPushServiceGlobals"))
        {
            tags.Add("export_service_entrypoint");
        }
    }

    /// <summary>
    /// Records bounded static PE evidence in the interesting-string list.
    /// Inputs are evidence text, output set, count, and limit; processing avoids
    /// unbounded import/export growth, and the method returns no value.
    /// </summary>
    private static void AddPeEvidence(SortedSet<string> interestingStrings, string evidence, ref int evidenceCount, int limit)
    {
        if (evidenceCount >= limit || string.IsNullOrWhiteSpace(evidence))
        {
            return;
        }

        interestingStrings.Add(evidence.Length > 240 ? evidence[..240] : evidence);
        evidenceCount++;
    }

    /// <summary>
    /// Checks a PE section name against common packer section markers.
    /// The input is a section name, processing performs case-insensitive prefix
    /// and exact matching, and the method returns true on a known marker.
    /// </summary>
    private static bool IsKnownPackerSectionName(string name)
    {
        return PackerSectionNames.Any(marker =>
            name.StartsWith(marker, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(name, marker, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Calculates the end offset of mapped PE section raw data.
    /// Inputs are section layouts and file length; processing ignores clearly
    /// invalid raw ranges; the method returns false when no raw section exists.
    /// </summary>
    private static bool TryGetRawImageEnd(IReadOnlyList<PeSectionLayout> sections, long fileLength, out long rawImageEnd)
    {
        rawImageEnd = 0;
        foreach (var section in sections)
        {
            if (section.RawSize == 0 || section.RawPointer >= fileLength)
            {
                continue;
            }

            var sectionEnd = Math.Min(fileLength, (long)section.RawPointer + section.RawSize);
            if (sectionEnd > rawImageEnd)
            {
                rawImageEnd = sectionEnd;
            }
        }

        return rawImageEnd > 0;
    }

    /// <summary>
    /// Subtracts one optional interval from another.
    /// Inputs are file intervals, processing returns the remaining left/right
    /// segments, and the method yields only positive-length intervals.
    /// </summary>
    private static IEnumerable<FileInterval> SubtractInterval(FileInterval interval, FileInterval? excluded)
    {
        if (excluded is not { } value || !value.Overlaps(interval))
        {
            yield return interval;
            yield break;
        }

        var overlap = value.Intersect(interval);
        if (interval.Start < overlap.Start)
        {
            yield return new FileInterval(interval.Start, overlap.Start);
        }

        if (overlap.End < interval.End)
        {
            yield return new FileInterval(overlap.End, interval.End);
        }
    }

    /// <summary>
    /// Aligns a certificate-entry length to the PE eight-byte boundary.
    /// </summary>
    private static long AlignToEight(uint value)
    {
        return ((long)value + 7L) & ~7L;
    }

    /// <summary>
    /// Describes WIN_CERTIFICATE type values for static evidence.
    /// </summary>
    private static string DescribeCertificateType(ushort certificateType)
    {
        return certificateType switch
        {
            0x0001 => "x509",
            0x0002 => "pkcs-signed-data",
            0x0003 => "reserved1",
            0x0004 => "ts-stack-signed",
            _ => $"0x{certificateType:X4}"
        };
    }

    /// <summary>
    /// Describes IMAGE_DEBUG_TYPE values for report tags and evidence.
    /// Inputs are numeric PE debug directory type values; processing maps common
    /// constants and returns a stable lowercase token for unknown values.
    /// </summary>
    private static string DescribeDebugType(uint debugType)
    {
        return debugType switch
        {
            0 => "unknown",
            1 => "coff",
            2 => "codeview",
            3 => "fpo",
            4 => "misc",
            5 => "exception",
            6 => "fixup",
            7 => "omap-to-src",
            8 => "omap-from-src",
            9 => "borland",
            10 => "reserved10",
            11 => "clsid",
            12 => "vc-feature",
            13 => "pogo",
            14 => "iltcg",
            15 => "mpx",
            16 => "repro",
            17 => "embedded-portable-pdb",
            18 => "pdb-checksum",
            19 => "ex-dllcharacteristics",
            _ => $"type-{debugType}"
        };
    }

    /// <summary>
    /// Normalizes arbitrary evidence labels into conservative tag components.
    /// Inputs are short labels; processing keeps alphanumeric runs and replaces
    /// other characters with single underscores; the method returns a stable
    /// lowercase token safe for tag names.
    /// </summary>
    private static string NormalizeTagComponent(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "unknown";
        }

        var builder = new StringBuilder(value.Length);
        var previousWasSeparator = false;
        foreach (var ch in value.Trim())
        {
            if (char.IsLetterOrDigit(ch))
            {
                builder.Append(char.ToLowerInvariant(ch));
                previousWasSeparator = false;
            }
            else if (!previousWasSeparator)
            {
                builder.Append('_');
                previousWasSeparator = true;
            }
        }

        var normalized = builder.ToString().Trim('_');
        return string.IsNullOrWhiteSpace(normalized) ? "unknown" : normalized;
    }

    /// <summary>
    /// Converts an RVA to a raw file offset by using section layout metadata.
    /// Inputs are RVA, sections, and file length; processing checks section
    /// ranges and header RVAs, and the method returns whether mapping worked.
    /// </summary>
    private static bool TryRvaToFileOffset(uint rva, IReadOnlyList<PeSectionLayout> sections, long fileLength, out long offset)
    {
        foreach (var section in sections)
        {
            var mappedSize = Math.Max(section.VirtualSize, section.RawSize);
            if (mappedSize == 0)
            {
                continue;
            }

            var start = (ulong)section.VirtualAddress;
            var end = start + mappedSize;
            if (rva < start || rva >= end)
            {
                continue;
            }

            var candidate = (long)section.RawPointer + (rva - section.VirtualAddress);
            if (candidate >= 0 && candidate < fileLength)
            {
                offset = candidate;
                return true;
            }
        }

        if (rva < fileLength)
        {
            offset = rva;
            return true;
        }

        offset = 0;
        return false;
    }

    /// <summary>
    /// Converts a PE virtual address to a raw file offset.
    /// Inputs are VA, image base, section layouts, and file length; processing
    /// subtracts image base when available, and the method returns true on map.
    /// </summary>
    private static bool TryVaToFileOffset(ulong va, ulong imageBase, IReadOnlyList<PeSectionLayout> sections, long fileLength, out long offset)
    {
        if (imageBase != 0 && va >= imageBase && va - imageBase <= uint.MaxValue)
        {
            return TryRvaToFileOffset((uint)(va - imageBase), sections, fileLength, out offset);
        }

        if (va <= uint.MaxValue)
        {
            return TryRvaToFileOffset((uint)va, sections, fileLength, out offset);
        }

        offset = 0;
        return false;
    }

    /// <summary>
    /// Converts a PE virtual address to an RVA without checking file mapping.
    /// </summary>
    private static bool TryVaToRva(ulong va, ulong imageBase, out uint rva)
    {
        if (imageBase != 0 && va >= imageBase && va - imageBase <= uint.MaxValue)
        {
            rva = (uint)(va - imageBase);
            return true;
        }

        if (va <= uint.MaxValue)
        {
            rva = (uint)va;
            return true;
        }

        rva = 0;
        return false;
    }

    /// <summary>
    /// Reads an import-by-name value.
    /// Inputs are the IMAGE_IMPORT_BY_NAME RVA and section layouts, processing
    /// skips the hint field and reads a bounded ASCII name; the method returns
    /// null when the name cannot be read.
    /// </summary>
    private static string? TryReadImportByName(BinaryReader reader, uint importByNameRva, IReadOnlyList<PeSectionLayout> sections, long fileLength)
    {
        return TryRvaToFileOffset(importByNameRva, sections, fileLength, out var offset)
            ? ReadAsciiStringAt(reader, offset + sizeof(ushort), fileLength)
            : null;
    }

    /// <summary>
    /// Reads a bounded null-terminated ASCII string from an RVA.
    /// Inputs are RVA, section layouts, and file length; processing maps to raw
    /// offset and reads printable ASCII; the method returns null on failure.
    /// </summary>
    private static string? TryReadRvaAsciiString(BinaryReader reader, uint rva, IReadOnlyList<PeSectionLayout> sections, long fileLength)
    {
        return TryRvaToFileOffset(rva, sections, fileLength, out var offset)
            ? ReadAsciiStringAt(reader, offset, fileLength)
            : null;
    }

    /// <summary>
    /// Reads a bounded null-terminated ASCII string from a raw file offset.
    /// Inputs are reader, offset, and file length; processing stops at null,
    /// non-printable bytes, or a length limit; the method returns text or null.
    /// </summary>
    private static string? ReadAsciiStringAt(BinaryReader reader, long offset, long fileLength)
    {
        if (offset < 0 || offset >= fileLength)
        {
            return null;
        }

        var maxLength = (int)Math.Min(MaxPeStringLength, fileLength - offset);
        var bytes = new List<byte>(Math.Min(maxLength, 64));
        reader.BaseStream.Position = offset;
        for (var index = 0; index < maxLength; index++)
        {
            var value = reader.ReadByte();
            if (value == 0)
            {
                break;
            }

            if (value is < 0x20 or > 0x7e)
            {
                break;
            }

            bytes.Add(value);
        }

        return bytes.Count == 0 ? null : Encoding.ASCII.GetString(bytes.ToArray());
    }

    /// <summary>
    /// Tries to read a UInt32 at an absolute offset without emitting warnings.
    /// Inputs are reader, offset, and file length; processing checks bounds,
    /// and the method returns false when the value is unavailable.
    /// </summary>
    private static bool TryReadUInt32At(BinaryReader reader, long offset, long fileLength, out uint value)
    {
        if (offset < 0 || offset > fileLength - sizeof(uint))
        {
            value = 0;
            return false;
        }

        reader.BaseStream.Position = offset;
        value = reader.ReadUInt32();
        return true;
    }

    /// <summary>
    /// Tries to read a UInt64 at an absolute offset without emitting warnings.
    /// Inputs are reader, offset, and file length; processing checks bounds,
    /// and the method returns false when the value is unavailable.
    /// </summary>
    private static bool TryReadUInt64At(BinaryReader reader, long offset, long fileLength, out ulong value)
    {
        if (offset < 0 || offset > fileLength - sizeof(ulong))
        {
            value = 0;
            return false;
        }

        reader.BaseStream.Position = offset;
        value = reader.ReadUInt64();
        return true;
    }

    /// <summary>
    /// Tries to read a UInt16 at an absolute offset without emitting warnings.
    /// Inputs are reader, offset, and file length; processing checks bounds,
    /// and the method returns false when the value is unavailable.
    /// </summary>
    private static bool TryReadUInt16At(BinaryReader reader, long offset, long fileLength, out ushort value)
    {
        if (offset < 0 || offset > fileLength - sizeof(ushort))
        {
            value = 0;
            return false;
        }

        reader.BaseStream.Position = offset;
        value = reader.ReadUInt16();
        return true;
    }

    /// <summary>
    /// Calculates Shannon entropy for section raw bytes.
    /// Inputs are a reader, raw pointer, raw size, file size, and warnings;
    /// processing reads bounded section bytes, and the method returns entropy.
    /// </summary>
    private static double CalculateEntropy(BinaryReader reader, uint rawPointer, uint rawSize, long fileLength, List<string> warnings)
    {
        return CalculateEntropy(reader, (long)rawPointer, rawSize, fileLength, warnings);
    }

    /// <summary>
    /// Calculates Shannon entropy for raw bytes at a long file offset.
    /// Inputs are a reader, raw pointer, raw size, file size, and warnings;
    /// processing reads bounded bytes, and the method returns entropy.
    /// </summary>
    private static double CalculateEntropy(BinaryReader reader, long rawPointer, uint rawSize, long fileLength, List<string> warnings)
    {
        if (rawSize == 0)
        {
            return 0;
        }

        if (rawPointer > fileLength || (long)rawPointer + rawSize > fileLength)
        {
            warnings.Add($"Section raw data at 0x{rawPointer:X} with size {rawSize} is outside the file.");
            return 0;
        }

        reader.BaseStream.Position = rawPointer;
        var data = reader.ReadBytes((int)Math.Min(rawSize, 4 * 1024 * 1024));
        if (data.Length == 0)
        {
            return 0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (var value in data)
        {
            counts[value]++;
        }

        var entropy = 0.0;
        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            var probability = count / (double)data.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    /// <summary>
    /// Adds one bounded human-readable evidence string.
    /// Inputs are an output set and value, processing trims report-unfriendly
    /// length, and the method returns no value.
    /// </summary>
    private static void AddInterestingString(SortedSet<string> interestingStrings, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var trimmed = TrimEvidence(value);
        interestingStrings.Add(trimmed.Length > 240 ? trimmed[..240] : trimmed);
    }

    /// <summary>
    /// Trims evidence delimiters commonly attached to extracted strings.
    /// Inputs are raw evidence, processing removes quotes and trailing
    /// punctuation, and the method returns a bounded display string.
    /// </summary>
    private static string TrimEvidence(string value)
    {
        var trimmed = value.Trim().Trim('"', '\'', '`');
        trimmed = trimmed.TrimEnd('\0', '.', ',', ';', ')', ']', '}', '"', '\'', '`');
        return trimmed.Length > 240 ? trimmed[..240] : trimmed;
    }

    /// <summary>
    /// Parses a dotted IPv4 literal into four octets.
    /// Inputs are a candidate string, processing validates each numeric octet,
    /// and the method returns true when parsing succeeds.
    /// </summary>
    private static bool TryParseIpv4(string value, out byte[] octets)
    {
        octets = new byte[4];
        var parts = value.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        for (var index = 0; index < parts.Length; index++)
        {
            if (!byte.TryParse(parts[index], out octets[index]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Checks whether an IPv4 address belongs to private, loopback, link-local,
    /// documentation, multicast, or otherwise reserved ranges.
    /// </summary>
    private static bool IsPrivateOrReservedIpv4(IReadOnlyList<byte> octets)
    {
        return
            octets[0] == 0 ||
            octets[0] == 10 ||
            octets[0] == 127 ||
            octets[0] >= 224 ||
            octets[0] == 169 && octets[1] == 254 ||
            octets[0] == 172 && octets[1] is >= 16 and <= 31 ||
            octets[0] == 192 && octets[1] == 168 ||
            octets[0] == 100 && octets[1] is >= 64 and <= 127 ||
            octets[0] == 192 && octets[1] == 0 && octets[2] == 2 ||
            octets[0] == 198 && octets[1] == 51 && octets[2] == 100 ||
            octets[0] == 203 && octets[1] == 0 && octets[2] == 113;
    }

    /// <summary>
    /// Reads a section name from an eight-byte fixed field.
    /// Inputs are raw section-name bytes, processing trims null terminators,
    /// and the method returns a printable name or placeholder.
    /// </summary>
    private static string ReadSectionName(byte[] nameBytes)
    {
        var zero = Array.IndexOf(nameBytes, (byte)0);
        var length = zero >= 0 ? zero : nameBytes.Length;
        var name = Encoding.ASCII.GetString(nameBytes, 0, length).Trim();
        return string.IsNullOrWhiteSpace(name) ? "<empty>" : name;
    }

    /// <summary>
    /// Reads a UInt32 at an absolute offset with bounds checking.
    /// Inputs are reader, offset, file length, and warnings, processing seeks
    /// only when safe, and the method returns zero when unavailable.
    /// </summary>
    private static uint ReadUInt32At(BinaryReader reader, long offset, long fileLength, List<string> warnings)
    {
        if (offset < 0 || offset > fileLength - sizeof(uint))
        {
            warnings.Add($"UInt32 read at 0x{offset:X} is outside the file.");
            return 0;
        }

        reader.BaseStream.Position = offset;
        return reader.ReadUInt32();
    }

    /// <summary>
    /// Reads a UInt64 at an absolute offset with bounds checking.
    /// Inputs are reader, offset, file length, and warnings, processing seeks
    /// only when safe, and the method returns zero when unavailable.
    /// </summary>
    private static ulong ReadUInt64At(BinaryReader reader, long offset, long fileLength, List<string> warnings)
    {
        if (offset < 0 || offset > fileLength - sizeof(ulong))
        {
            warnings.Add($"UInt64 read at 0x{offset:X} is outside the file.");
            return 0;
        }

        reader.BaseStream.Position = offset;
        return reader.ReadUInt64();
    }

    /// <summary>
    /// Reads a UInt16 at an absolute offset with bounds checking.
    /// Inputs are reader, offset, file length, and warnings, processing seeks
    /// only when safe, and the method returns zero when unavailable.
    /// </summary>
    private static ushort ReadUInt16At(BinaryReader reader, long offset, long fileLength, List<string> warnings)
    {
        if (offset < 0 || offset > fileLength - sizeof(ushort))
        {
            warnings.Add($"UInt16 read at 0x{offset:X} is outside the file.");
            return 0;
        }

        reader.BaseStream.Position = offset;
        return reader.ReadUInt16();
    }

    /// <summary>
    /// Describes PE machine and optional-header architecture.
    /// Inputs are numeric machine and optional-header magic values, processing
    /// maps common constants, and the method returns display text.
    /// </summary>
    private static string DescribeArchitecture(ushort machine, ushort optionalMagic)
    {
        return machine switch
        {
            0x014c => "x86",
            0x8664 => "x86-64",
            0xaa64 => "ARM64",
            _ => optionalMagic == 0x20b ? "PE32+ unknown machine" : "PE unknown machine"
        };
    }

    /// <summary>
    /// Describes PE subsystem values for report display.
    /// The input is a numeric subsystem, processing maps common Windows values,
    /// and the method returns display text.
    /// </summary>
    private static string DescribeSubsystem(ushort subsystem)
    {
        return subsystem switch
        {
            2 => "Windows GUI",
            3 => "Windows Console",
            9 => "Windows CE GUI",
            10 => "EFI Application",
            11 => "EFI Boot Service Driver",
            12 => "EFI Runtime Driver",
            14 => "Xbox",
            16 => "Windows Boot Application",
            _ => $"Unknown ({subsystem})"
        };
    }

    /// <summary>
    /// Checks whether a string contains any configured fragment.
    /// Inputs are text and fragments, processing uses ordinal ignore-case
    /// matching, and the method returns true on the first match.
    /// </summary>
    private static bool ContainsAny(string text, params string[] fragments)
    {
        return fragments.Any(fragment => text.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Matches imported API names exactly and extracted strings with identifier
    /// boundaries. This avoids `OpenProcess` matching `OpenProcessToken`.
    /// </summary>
    private static bool ContainsAnyApiToken(string text, params string[] fragments)
    {
        return fragments.Any(fragment =>
            string.Equals(text, fragment, StringComparison.OrdinalIgnoreCase) ||
            ContainsApiToken(text, fragment));
    }

    /// <summary>
    /// Checks script/process execution API markers while keeping broad CRT
    /// names such as `system` token-bounded.
    /// </summary>
    private static bool ContainsScriptExecutionApi(string text)
    {
        foreach (var fragment in ScriptExecutionApis)
        {
            if (string.Equals(fragment, "system", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fragment, "_wsystem", StringComparison.OrdinalIgnoreCase))
            {
                if (ContainsToken(text, fragment))
                {
                    return true;
                }

                continue;
            }

            if (string.Equals(text, fragment, StringComparison.OrdinalIgnoreCase) ||
                ContainsApiToken(text, fragment))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks a case-insensitive token with non-identifier boundaries.
    /// </summary>
    private static bool ContainsToken(string text, string token)
    {
        var start = 0;
        while (start < text.Length)
        {
            var index = text.IndexOf(token, start, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return false;
            }

            var before = index == 0 ? '\0' : text[index - 1];
            var afterIndex = index + token.Length;
            var after = afterIndex >= text.Length ? '\0' : text[afterIndex];
            if (!IsIdentifierChar(before) && !IsIdentifierChar(after))
            {
                return true;
            }

            start = index + token.Length;
        }

        return false;
    }

    /// <summary>
    /// Checks a Windows API token with identifier boundaries and optional
    /// ANSI/Unicode A/W suffixes. This keeps `InternetOpenA` matched to
    /// `InternetOpen` while preventing `OpenProcessToken` from matching
    /// `OpenProcess`.
    /// </summary>
    private static bool ContainsApiToken(string text, string token)
    {
        var start = 0;
        while (start < text.Length)
        {
            var index = text.IndexOf(token, start, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return false;
            }

            var before = index == 0 ? '\0' : text[index - 1];
            var afterIndex = index + token.Length;
            var after = afterIndex >= text.Length ? '\0' : text[afterIndex];
            if (!IsIdentifierChar(before) && !IsIdentifierChar(after))
            {
                return true;
            }

            if (!IsIdentifierChar(before) &&
                (after is 'A' or 'a' or 'W' or 'w') &&
                (afterIndex + 1 >= text.Length || !IsIdentifierChar(text[afterIndex + 1])))
            {
                return true;
            }

            start = index + token.Length;
        }

        return false;
    }

    /// <summary>
    /// Returns whether a character is part of a common API identifier token.
    /// </summary>
    private static bool IsIdentifierChar(char value)
    {
        return char.IsLetterOrDigit(value) || value == '_';
    }

    /// <summary>
    /// Adds a deduplicated structured network indicator.
    /// </summary>
    private static void AddNetworkIndicator(StaticStringEvidence evidence, string kind, string value, string? classification)
    {
        if (evidence.NetworkIndicators.Count >= MaxStructuredStringIndicators || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var trimmed = TrimEvidence(value);
        var key = $"{kind}\0{trimmed}\0{classification}";
        if (!evidence.NetworkIndicatorKeys.Add(key))
        {
            return;
        }

        evidence.NetworkIndicators.Add(new StaticNetworkIndicator
        {
            Kind = kind,
            Value = trimmed,
            Classification = classification
        });
    }

    /// <summary>
    /// Adds a deduplicated structured path indicator.
    /// </summary>
    private static void AddPathIndicator(StaticStringEvidence evidence, string kind, string value, IEnumerable<string> tags)
    {
        if (evidence.PathIndicators.Count >= MaxStructuredStringIndicators || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var trimmed = TrimEvidence(value);
        var key = $"{kind}\0{trimmed}";
        if (!evidence.PathIndicatorKeys.Add(key))
        {
            return;
        }

        evidence.PathIndicators.Add(new StaticPathIndicator
        {
            Kind = kind,
            Value = trimmed,
            Tags = tags.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        });
    }

    /// <summary>
    /// Adds a deduplicated structured command indicator.
    /// </summary>
    private static void AddCommandIndicator(StaticStringEvidence evidence, string category, string? tool, string value, params string[] tags)
    {
        if (evidence.CommandIndicators.Count >= MaxStructuredStringIndicators || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var trimmed = TrimEvidence(value);
        var key = $"{category}\0{tool}\0{trimmed}";
        if (!evidence.CommandIndicatorKeys.Add(key))
        {
            return;
        }

        evidence.CommandIndicators.Add(new StaticCommandIndicator
        {
            Category = category,
            Tool = tool,
            Value = trimmed,
            Tags = tags
                .Where(tag => !string.IsNullOrWhiteSpace(tag))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList()
        });
    }

    /// <summary>
    /// Adds a deduplicated suspicious-string finding.
    /// </summary>
    private static void AddStringFinding(StaticStringEvidence evidence, string category, string value, params string[] tags)
    {
        if (evidence.SuspiciousStrings.Count >= MaxStructuredStringIndicators || string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var trimmed = TrimEvidence(value);
        var key = $"{category}\0{trimmed}";
        if (!evidence.SuspiciousStringKeys.Add(key))
        {
            return;
        }

        evidence.SuspiciousStrings.Add(new StaticStringFinding
        {
            Category = category,
            Value = trimmed,
            Tags = tags
                .Where(tag => !string.IsNullOrWhiteSpace(tag))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList()
        });
    }

    /// <summary>
    /// Returns the first configured marker contained in a string.
    /// </summary>
    private static string? FindFirstMarker(string text, IEnumerable<string> markers)
    {
        return markers.FirstOrDefault(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Adds a value to a bounded list when not already present.
    /// </summary>
    private static void AddBounded(List<string> values, string value, int limit)
    {
        if (values.Count >= limit ||
            string.IsNullOrWhiteSpace(value) ||
            values.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        values.Add(value);
    }

    /// <summary>
    /// Converts entropy into a stable coarse label for report/rule consumers.
    /// </summary>
    private static string DescribeEntropy(double entropy, uint rawSize)
    {
        if (rawSize == 0)
        {
            return "empty";
        }

        return entropy switch
        {
            >= 7.2 => "very_high",
            >= 6.8 => "high",
            <= 1.0 => "low",
            _ => "normal"
        };
    }

    /// <summary>
    /// Adds the backward-compatible static.analysis.completed summary event.
    /// </summary>
    private static void AddStaticSummaryEvent(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        var yaraMatchCount = result.InterestingStrings.Count(value => value.StartsWith("static.yara.match:", StringComparison.OrdinalIgnoreCase));
        var tlsCallbackCount = result.Tls?.Callbacks.Count ?? 0;
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["fileFormat"] = result.FileFormat,
            ["magic"] = result.Magic,
            ["isPe"] = result.IsPe.ToString(),
            ["sectionCount"] = result.SectionCount.ToString(CultureInfo.InvariantCulture),
            ["importModuleCount"] = result.Imports.Count.ToString(CultureInfo.InvariantCulture),
            ["importApiClusterCount"] = result.ImportApiClusters.Count.ToString(CultureInfo.InvariantCulture),
            ["exportCount"] = result.ExportNames.Count.ToString(CultureInfo.InvariantCulture),
            ["tlsCallbackCount"] = tlsCallbackCount.ToString(CultureInfo.InvariantCulture),
            ["resourceCount"] = result.Resources.Count.ToString(CultureInfo.InvariantCulture),
            ["networkIndicatorCount"] = result.NetworkIndicators.Count.ToString(CultureInfo.InvariantCulture),
            ["pathIndicatorCount"] = result.PathIndicators.Count.ToString(CultureInfo.InvariantCulture),
            ["commandIndicatorCount"] = result.CommandIndicators.Count.ToString(CultureInfo.InvariantCulture),
            ["suspiciousStringCount"] = result.SuspiciousStrings.Count.ToString(CultureInfo.InvariantCulture),
            ["yaraMatchCount"] = yaraMatchCount.ToString(CultureInfo.InvariantCulture),
            ["tagCount"] = result.Tags.Count.ToString(CultureInfo.InvariantCulture),
            ["urlCount"] = result.Urls.Count.ToString(CultureInfo.InvariantCulture),
            ["interestingStringCount"] = result.InterestingStrings.Count.ToString(CultureInfo.InvariantCulture),
            ["warningCount"] = result.Warnings.Count.ToString(CultureInfo.InvariantCulture)
        };

        AddDataIfNotBlank(data, "architecture", result.Architecture);
        AddDataIfNotBlank(data, "machine", result.Machine);
        AddDataIfNotBlank(data, "subsystem", result.Subsystem);
        AddDataIfNotBlank(data, "entryPointRva", result.EntryPointRva);
        AddDataList(data, "tags", result.Tags);
        AddDataList(data, "warnings", result.Warnings);
        AddStaticRuleFacingFields(
            data,
            "static-analysis-summary",
            "static.analysis.completed",
            "static.summary",
            "static-summary",
            result.Tags.Count > 0 ? "info" : "none");

        TryAddStaticEvent(
            events,
            "static.analysis.completed",
            fullPath,
            "Static analysis completed.",
            "静态分析完成。",
            "该事件汇总主机侧静态分析结果；单个 PE、字符串和 YARA-like 命中会拆成后续事件。",
            data);
    }

    /// <summary>
    /// Adds one event per parsed PE section with entropy and flag metadata.
    /// </summary>
    private static void AddStaticSectionEvents(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        foreach (var section in result.Sections.Take(MaxStructuredPeEntries))
        {
            var sectionTags = GetSectionEventTags(section).ToList();
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["name"] = section.Name,
                ["virtualAddress"] = section.VirtualAddress,
                ["rawDataOffset"] = section.RawDataOffset,
                ["virtualSize"] = section.VirtualSize.ToString(CultureInfo.InvariantCulture),
                ["rawDataSize"] = section.RawDataSize.ToString(CultureInfo.InvariantCulture),
                ["entropy"] = section.Entropy.ToString("F3", CultureInfo.InvariantCulture),
                ["entropyLabel"] = section.EntropyLabel,
                ["characteristics"] = section.Characteristics,
                ["isExecutable"] = section.IsExecutable.ToString(),
                ["isWritable"] = section.IsWritable.ToString()
            };
            AddDataList(data, "tags", sectionTags);
            AddStaticRuleFacingFields(
                data,
                "pe-section",
                "static.pe.section",
                $"section.{NormalizeStaticYaraTag(section.Name)}",
                section.IsExecutable && section.IsWritable ? "memory-permissions" : "pe-section-layout",
                section.Entropy >= 7.2 || (section.IsExecutable && section.IsWritable) ? "medium" : "info");
            data["sectionRole"] = section.IsExecutable && section.IsWritable
                ? "writable-executable"
                : section.Entropy >= 7.2
                    ? "high-entropy"
                    : IsKnownPackerSectionName(section.Name)
                        ? "packer-section"
                        : "normal";
            data["packedCandidate"] = sectionTags.Contains("packer_hint", StringComparer.OrdinalIgnoreCase).ToString();

            TryAddStaticEvent(
                events,
                "static.pe.section",
                fullPath,
                $"PE section {section.Name} entropy {section.Entropy:F3}.",
                $"PE 节 {section.Name} 熵值 {section.Entropy:F3}。",
                "高熵、可写且可执行、虚拟大小异常或壳相关节名只是静态线索，需要结合运行时行为判断。",
                data);
        }
    }

    /// <summary>
    /// Adds import-module and suspicious API cluster events.
    /// </summary>
    private static void AddStaticImportEvents(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        foreach (var module in result.Imports.Take(MaxStructuredPeEntries))
        {
            var moduleTags = GetImportModuleEventTags(module).ToList();
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["moduleName"] = module.ModuleName,
                ["namedApiCount"] = module.NamedApiCount.ToString(CultureInfo.InvariantCulture),
                ["ordinalImportCount"] = module.OrdinalImportCount.ToString(CultureInfo.InvariantCulture)
            };
            AddDataList(data, "apiNames", module.ApiNames);
            AddDataList(data, "ordinalImports", module.OrdinalImports);
            AddDataList(data, "suspiciousApiNames", module.SuspiciousApiNames);
            AddDataList(data, "suspiciousApiClusters", module.SuspiciousApiClusters);
            AddDataList(data, "tags", moduleTags);
            AddImportModuleRuleFacingFields(data, module);

            TryAddStaticEvent(
                events,
                "static.pe.import.module",
                fullPath,
                $"PE import module {module.ModuleName} with {module.NamedApiCount} named APIs.",
                $"PE 导入模块 {module.ModuleName}，命名 API 数 {module.NamedApiCount}。",
                "导入表代表静态能力面，不等同于运行时调用；优先查看可疑 API 聚类和运行时证据。",
                data);
        }

        foreach (var cluster in result.ImportApiClusters.Take(MaxImportApiClusterEvidence))
        {
            var clusterTags = TagsForImportCluster(cluster.Name).ToList();
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["cluster"] = cluster.Name,
                ["hitCount"] = cluster.HitCount.ToString(CultureInfo.InvariantCulture)
            };
            AddDataList(data, "apiNames", cluster.ApiNames);
            AddDataList(data, "tags", clusterTags);
            AddImportClusterRuleFacingFields(data, cluster);

            TryAddStaticEvent(
                events,
                "static.pe.import.cluster",
                fullPath,
                $"Suspicious PE import API cluster {cluster.Name} observed.",
                $"发现静态 API 能力聚类：{cluster.Name}。",
                DescribeImportClusterZhHint(cluster.Name),
                data);
        }
    }

    /// <summary>
    /// Adds export-name events for DLL registration/service-style triage.
    /// </summary>
    private static void AddStaticExportEvents(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        foreach (var exportName in result.ExportNames.Take(MaxExportNames))
        {
            var exportTags = new SortedSet<string>(StringComparer.OrdinalIgnoreCase) { "exports_present" };
            AddExportTags(exportName, exportTags);
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["exportName"] = exportName
            };
            AddDataIfNotBlank(data, "moduleName", result.ExportModuleName);
            AddDataList(data, "tags", exportTags);
            var exportRole = DescribeExportRole(exportName);
            AddStaticRuleFacingFields(
                data,
                "pe-export",
                "static.pe.export",
                $"export.{NormalizeStaticYaraTag(exportRole)}",
                exportRole == "generic-export" ? "pe-export" : "persistence-or-loader-entrypoint",
                exportRole == "generic-export" ? "info" : "low");
            data["exportRole"] = exportRole;
            data["loaderEntryCandidate"] = (exportRole != "generic-export").ToString();
            data["persistenceCandidate"] = (exportRole is "com-registration-entrypoint" or "service-entrypoint").ToString();
            AddDataList(
                data,
                "mitreCandidates",
                exportRole switch
                {
                    "com-registration-entrypoint" => ["T1117", "T1218.010"],
                    "service-entrypoint" => ["T1543.003"],
                    _ => []
                });

            TryAddStaticEvent(
                events,
                "static.pe.export",
                fullPath,
                $"PE export {exportName} observed.",
                $"发现 PE 导出：{exportName}。",
                "DllRegisterServer、DllInstall、ServiceMain 等导出可用于加载器或服务入口 triage。",
                data);
        }
    }

    /// <summary>
    /// Adds TLS directory and callback events.
    /// </summary>
    private static void AddStaticTlsEvents(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        if (result.Tls is not { DirectoryPresent: true } tls)
        {
            return;
        }

        var directoryData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["directoryPresent"] = "True",
            ["callbackCount"] = tls.Callbacks.Count.ToString(CultureInfo.InvariantCulture),
            ["tags"] = tls.Callbacks.Count > 0 ? "tls_directory_present,tls_callbacks" : "tls_directory_present"
        };
        AddDataIfNotBlank(directoryData, "callbackTableVa", tls.CallbackTableVa);
        AddDataIfNotBlank(directoryData, "callbackTableFileOffset", tls.CallbackTableFileOffset);
        AddStaticRuleFacingFields(
            directoryData,
            "pe-tls-directory",
            "static.pe.tls.directory",
            "tls.directory",
            "early-execution",
            tls.Callbacks.Count > 0 ? "medium" : "info");
        directoryData["executionPhase"] = "pre-entrypoint";
        directoryData["earlyExecutionCandidate"] = (tls.Callbacks.Count > 0).ToString();
        directoryData["antiAnalysisCandidate"] = (tls.Callbacks.Count > 0).ToString();
        AddDataList(directoryData, "mitreCandidates", tls.Callbacks.Count > 0 ? ["T1497", "T1622"] : []);

        TryAddStaticEvent(
            events,
            "static.pe.tls.directory",
            fullPath,
            "PE TLS directory observed.",
            "发现 PE TLS 目录。",
            "TLS callback 可早于入口点执行，是静态 triage 线索；需要结合动态行为确认。",
            directoryData);

        for (var index = 0; index < tls.Callbacks.Count && index < MaxTlsCallbacks; index++)
        {
            var callback = tls.Callbacks[index];
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["index"] = index.ToString(CultureInfo.InvariantCulture),
                ["virtualAddress"] = callback.VirtualAddress,
                ["tags"] = "tls_directory_present,tls_callback_pointer,tls_callbacks"
            };
            AddDataIfNotBlank(data, "relativeVirtualAddress", callback.RelativeVirtualAddress);
            AddDataIfNotBlank(data, "callbackTableVa", tls.CallbackTableVa);
            AddDataIfNotBlank(data, "callbackTableFileOffset", tls.CallbackTableFileOffset);
            AddStaticRuleFacingFields(
                data,
                "pe-tls-callback",
                "static.pe.tls.callback",
                "tls.callback",
                "early-execution",
                "medium");
            data["executionPhase"] = "pre-entrypoint";
            data["earlyExecutionCandidate"] = "True";
            data["antiAnalysisCandidate"] = "True";
            AddDataList(data, "mitreCandidates", ["T1497", "T1622"]);

            TryAddStaticEvent(
                events,
                "static.pe.tls.callback",
                fullPath,
                $"PE TLS callback {callback.VirtualAddress} observed.",
                $"发现 PE TLS 回调：{callback.VirtualAddress}。",
                "TLS 回调可能在程序入口点前运行；这是优先复核的静态线索。",
                data);
        }
    }

    /// <summary>
    /// Adds one event per parsed PE resource data entry with payload/entropy hints.
    /// </summary>
    private static void AddStaticResourceEvents(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        foreach (var resource in result.Resources.Take(MaxStructuredPeEntries))
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["resourceType"] = resource.ResourceType,
                ["dataRva"] = resource.DataRva,
                ["size"] = resource.Size.ToString(CultureInfo.InvariantCulture),
                ["entropyLabel"] = resource.EntropyLabel,
                ["isPayloadCandidate"] = resource.IsPayloadCandidate.ToString(),
                ["isEmbeddedPe"] = resource.IsEmbeddedPe.ToString(),
                ["isLarge"] = resource.IsLarge.ToString()
            };
            AddDataIfNotBlank(data, "dataFileOffset", resource.DataFileOffset);
            if (resource.Entropy.HasValue)
            {
                data["entropy"] = resource.Entropy.Value.ToString("F3", CultureInfo.InvariantCulture);
            }

            AddDataList(data, "tags", resource.Tags);
            var resourceRole = DescribeResourceRole(resource);
            AddStaticRuleFacingFields(
                data,
                "pe-resource-data-entry",
                "static.pe.resource",
                $"resource.{NormalizeStaticYaraTag(resourceRole)}",
                resourceRole is "embedded-pe" or "payload-candidate" ? "embedded-payload" : "pe-resource",
                resource.IsEmbeddedPe || resource.Entropy >= 7.2 || resource.IsLarge ? "medium" : resource.IsPayloadCandidate ? "low" : "info");
            data["resourceRole"] = resourceRole;
            data["payloadCandidate"] = resource.IsPayloadCandidate.ToString();
            AddDataList(
                data,
                "mitreCandidates",
                resource.IsEmbeddedPe || resource.IsPayloadCandidate
                    ? ["T1027.009"]
                    : resource.Entropy >= 7.2
                        ? ["T1027"]
                        : []);

            TryAddStaticEvent(
                events,
                "static.pe.resource",
                fullPath,
                $"PE resource {resource.ResourceType} data entry observed.",
                $"发现 PE 资源数据项：{resource.ResourceType}。",
                "资源数据项是静态载荷线索；RCDATA/HTML/命名资源、高熵或嵌入 MZ 需要与 dropped files 和运行时行为交叉验证。",
                data);
        }
    }

    /// <summary>
    /// Adds PE overlay and certificate-table event metadata.
    /// </summary>
    private static void AddStaticOverlayEvent(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        if (result.Overlay is not { Present: true } overlay)
        {
            return;
        }

        var overlayTags = new List<string> { "overlay_present", "pe_overlay" };
        if (overlay.ContainsCertificateTable)
        {
            overlayTags.Add("overlay_contains_certificate_table");
        }

        if (overlay.IsCertificateTableOnly)
        {
            overlayTags.Add("overlay_certificate_table_only");
        }
        else if (overlay.NonCertificateSize > 0)
        {
            overlayTags.Add("overlay_non_certificate_data");
        }

        if (overlay.NonCertificateEntropy >= 7.2)
        {
            overlayTags.Add("overlay_high_entropy");
        }

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["present"] = overlay.Present.ToString(),
            ["startOffset"] = overlay.StartOffset,
            ["size"] = overlay.Size.ToString(CultureInfo.InvariantCulture),
            ["containsCertificateTable"] = overlay.ContainsCertificateTable.ToString(),
            ["certificateTableSize"] = overlay.CertificateTableSize.ToString(CultureInfo.InvariantCulture),
            ["isCertificateTableOnly"] = overlay.IsCertificateTableOnly.ToString(),
            ["nonCertificateSize"] = overlay.NonCertificateSize.ToString(CultureInfo.InvariantCulture)
        };
        AddDataIfNotBlank(data, "certificateTableOffset", overlay.CertificateTableOffset);
        AddDataIfNotBlank(data, "largestNonCertificateOffset", overlay.LargestNonCertificateOffset);
        if (overlay.LargestNonCertificateSize > 0)
        {
            data["largestNonCertificateSize"] = overlay.LargestNonCertificateSize.ToString(CultureInfo.InvariantCulture);
        }

        if (overlay.NonCertificateEntropy.HasValue)
        {
            data["nonCertificateEntropy"] = overlay.NonCertificateEntropy.Value.ToString("F3", CultureInfo.InvariantCulture);
        }

        AddDataList(data, "tags", overlayTags);
        var overlayRole = DescribeOverlayRole(overlay);
        AddStaticRuleFacingFields(
            data,
            "pe-overlay",
            "static.pe.overlay",
            $"overlay.{NormalizeStaticYaraTag(overlayRole)}",
            overlay.NonCertificateSize > 0 ? "packed-or-embedded-payload" : "pe-signature-metadata",
            overlay.NonCertificateEntropy >= 7.2 || overlay.NonCertificateSize >= 1024 * 1024 ? "medium" : "info");
        data["overlayRole"] = overlayRole;
        data["payloadCandidate"] = (overlay.NonCertificateSize > 0).ToString();
        data["certificateOnly"] = overlay.IsCertificateTableOnly.ToString();
        data["nonCertificateEntropyLabel"] = overlay.NonCertificateEntropy.HasValue
            ? DescribeEntropy(overlay.NonCertificateEntropy.Value, (uint)Math.Min(uint.MaxValue, overlay.NonCertificateSize))
            : "unknown";
        AddDataList(data, "mitreCandidates", overlay.NonCertificateSize > 0 ? ["T1027", "T1027.009"] : []);

        TryAddStaticEvent(
            events,
            "static.pe.overlay",
            fullPath,
            "PE overlay data observed.",
            "发现 PE overlay 附加数据。",
            "证书表 overlay 通常是签名结构；非证书高熵 overlay 更适合作为打包或附加载荷线索。",
            data);
    }

    /// <summary>
    /// Adds network/path/command/suspicious-string evidence events.
    /// </summary>
    private static void AddStaticStringEvents(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        foreach (var indicator in result.NetworkIndicators.Take(MaxStructuredStringIndicators))
        {
            var indicatorTags = GetNetworkIndicatorEventTags(indicator).ToList();
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["kind"] = indicator.Kind,
                ["value"] = indicator.Value,
            };
            AddDataList(data, "tags", indicatorTags);
            AddDataIfNotBlank(data, "classification", indicator.Classification);
            var indicatorRole = DescribeNetworkIndicatorRole(indicator);
            AddStaticRuleFacingFields(
                data,
                "static-network-indicator",
                "static.string.indicator",
                $"network.{NormalizeStaticYaraTag(indicator.Kind)}.{NormalizeStaticYaraTag(indicator.Classification ?? "unclassified")}",
                indicatorRole == "reference" ? "reference-metadata" : "network-indicator",
                indicatorRole is "download-url-candidate" or "tor-hidden-service" or "dynamic-dns" ? "low" : "info");
            data["indicatorRole"] = indicatorRole;
            data["iocConfidence"] = indicatorRole == "reference" ? "reference" : indicatorRole is "download-url-candidate" or "tor-hidden-service" or "dynamic-dns" ? "medium" : "low";
            data["isReference"] = string.Equals(indicator.Classification, "reference", StringComparison.OrdinalIgnoreCase).ToString();
            data["downloadPayloadCandidate"] = IsPotentialExecutableDownloadValue(indicator.Value).ToString();
            AddDataList(data, "mitreCandidates", IsPotentialExecutableDownloadValue(indicator.Value) ? ["T1105"] : []);

            TryAddStaticEvent(
                events,
                "static.string.indicator",
                fullPath,
                $"Static network/string indicator {indicator.Kind} observed.",
                $"发现静态网络/字符串指标：{indicator.Kind}。",
                "字符串指标可能来自配置、文档或资源；需结合上下文和网络行为确认。",
                data);
        }

        foreach (var path in result.PathIndicators.Take(MaxStructuredStringIndicators))
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["kind"] = path.Kind,
                ["value"] = path.Value
            };
            AddDataList(data, "tags", path.Tags);
            var pathRole = DescribePathRole(path);
            var persistenceCandidate = path.Tags.Contains("persistence_string", StringComparer.OrdinalIgnoreCase);
            var dropLocationCandidate = path.Tags.Contains("temp_path_string", StringComparer.OrdinalIgnoreCase) ||
                path.Tags.Contains("appdata_path_string", StringComparer.OrdinalIgnoreCase) ||
                path.Tags.Contains("executable_path_string", StringComparer.OrdinalIgnoreCase);
            AddStaticRuleFacingFields(
                data,
                "static-path-string",
                "static.string.path",
                $"path.{NormalizeStaticYaraTag(pathRole)}",
                persistenceCandidate ? "persistence" : dropLocationCandidate ? "dropped-file" : "path-indicator",
                persistenceCandidate || dropLocationCandidate ? "low" : "info");
            data["pathRole"] = pathRole;
            data["persistenceCandidate"] = persistenceCandidate.ToString();
            data["dropLocationCandidate"] = dropLocationCandidate.ToString();
            data["executionCandidate"] = (path.Tags.Contains("executable_path_string", StringComparer.OrdinalIgnoreCase) ||
                path.Tags.Contains("script_path_string", StringComparer.OrdinalIgnoreCase)).ToString();
            AddDataList(
                data,
                "mitreCandidates",
                persistenceCandidate
                    ? ["T1547.001", "T1053.005", "T1543.003"]
                    : dropLocationCandidate
                        ? ["T1105"]
                        : []);

            TryAddStaticEvent(
                events,
                "static.string.path",
                fullPath,
                $"Static path indicator {path.Kind} observed.",
                $"发现静态路径指标：{path.Kind}。",
                "注册表、启动目录或可执行路径字符串是能力线索，不代表已修改系统。",
                data);
        }

        foreach (var command in result.CommandIndicators.Take(MaxStructuredStringIndicators))
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["category"] = command.Category,
                ["value"] = command.Value
            };
            AddDataIfNotBlank(data, "tool", command.Tool);
            AddDataList(data, "tags", command.Tags);
            var commandBehaviorFamily = DescribeCommandBehaviorFamily(command);
            var downloadExecuteCandidate = string.Equals(command.Category, "download-execute", StringComparison.OrdinalIgnoreCase) ||
                IsDownloadExecuteString(command.Value);
            AddStaticRuleFacingFields(
                data,
                "static-command-string",
                "static.string.command",
                $"command.{NormalizeStaticYaraTag(command.Category)}",
                commandBehaviorFamily,
                downloadExecuteCandidate || command.Tags.Contains("encoded_command_string", StringComparer.OrdinalIgnoreCase) ? "medium" : "low");
            data["commandRole"] = command.Category;
            data["downloadExecCandidate"] = downloadExecuteCandidate.ToString();
            data["antiDebugCandidate"] = (ContainsAnyApiToken(command.Value, AntiDebugApis) ||
                ContainsAny(command.Value, AntiDebugStringMarkers)).ToString();
            AddDataList(
                data,
                "mitreCandidates",
                commandBehaviorFamily switch
                {
                    "download-execute" => ["T1105", "T1059"],
                    "script-obfuscation" => ["T1059", "T1027"],
                    "living-off-the-land" => ["T1218", "T1059"],
                    "persistence" => ["T1547", "T1053"],
                    "exfiltration" => ["T1041"],
                    _ => ["T1059"]
                });

            TryAddStaticEvent(
                events,
                "static.string.command",
                fullPath,
                $"Static command-like string {command.Category} observed.",
                $"发现静态命令类字符串：{command.Category}。",
                "LOLBIN、脚本或下载命令字符串需要结合命令行/进程事件确认是否执行。",
                data);
        }

        foreach (var finding in result.SuspiciousStrings.Take(MaxStructuredStringIndicators))
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["category"] = finding.Category,
                ["value"] = finding.Value
            };
            AddDataList(data, "tags", finding.Tags);
            var suspiciousFamily = DescribeSuspiciousStringBehaviorFamily(finding);
            var antiDebugCandidate = string.Equals(finding.Category, "anti-debug-string", StringComparison.OrdinalIgnoreCase) ||
                finding.Tags.Contains("anti_debug_string", StringComparer.OrdinalIgnoreCase) ||
                ContainsAnyApiToken(finding.Value, AntiDebugApis) ||
                ContainsAny(finding.Value, AntiDebugStringMarkers);
            AddStaticRuleFacingFields(
                data,
                "static-suspicious-string",
                "static.string.suspicious",
                $"string.{NormalizeStaticYaraTag(finding.Category)}",
                suspiciousFamily,
                suspiciousFamily is "credential-access" or "defense-evasion" or "anti-analysis" ? "low" : "info");
            data["stringRole"] = finding.Category;
            data["antiDebugCandidate"] = antiDebugCandidate.ToString();
            data["downloadExecCandidate"] = IsDownloadExecuteString(finding.Value).ToString();
            AddDataList(
                data,
                "mitreCandidates",
                suspiciousFamily switch
                {
                    "anti-analysis" => antiDebugCandidate ? ["T1622", "T1497.001"] : ["T1497"],
                    "credential-access" => ["T1003", "T1555"],
                    "defense-evasion" => ["T1562"],
                    "persistence" => ["TA0003"],
                    "packer" => ["T1027"],
                    _ => []
                });

            TryAddStaticEvent(
                events,
                "static.string.suspicious",
                fullPath,
                $"Suspicious static string {finding.Category} observed.",
                $"发现可疑静态字符串：{finding.Category}。",
                "该事件是静态字符串 triage 线索；优先与导入表、资源、运行时事件交叉验证。",
                data);
        }
    }

    /// <summary>
    /// Adds a compact packer-hint rollup event.
    /// </summary>
    private static void AddStaticPackerEvent(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        var packerTags = result.Tags
            .Where(tag => tag.Contains("packer", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (packerTags.Count == 0)
        {
            return;
        }

        var evidence = result.InterestingStrings
            .Where(value =>
                value.Contains("packer", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("UPX", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("section:", StringComparison.OrdinalIgnoreCase))
            .Take(12)
            .ToList();
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["tags"] = JoinBounded(packerTags)
        };
        AddDataList(data, "evidence", evidence, " | ");
        AddStaticRuleFacingFields(
            data,
            "static-packer-hint",
            "static.packer.hint",
            "packer.hint",
            "packing-or-obfuscation",
            packerTags.Contains("packer_upx", StringComparer.OrdinalIgnoreCase) ? "medium" : "low");
        data["packedCandidate"] = "True";
        AddDataList(data, "mitreCandidates", ["T1027", "T1027.002"]);

        TryAddStaticEvent(
            events,
            "static.packer.hint",
            fullPath,
            "Static packer hint observed.",
            "发现静态壳/打包线索。",
            "壳特征应与高熵节、异常节名、TLS callback、overlay 和导入表组合研判；单独命中不代表恶意。",
            data);
    }

    /// <summary>
    /// Adds one event for each built-in lightweight YARA-like rule hit.
    /// </summary>
    private static void AddStaticYaraEvents(string fullPath, StaticAnalysisResult result, List<SandboxEvent> events)
    {
        var ruleNames = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var stringsByRule = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var metaByRule = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var evidence in result.InterestingStrings)
        {
            if (evidence.StartsWith("static.yara.match:", StringComparison.OrdinalIgnoreCase))
            {
                var ruleName = evidence["static.yara.match:".Length..].Trim();
                if (ruleName.Length > 0)
                {
                    ruleNames.Add(ruleName);
                }

                continue;
            }

            if (TrySplitStaticYaraEvidence(evidence, "static.yara.strings:", out var stringRuleName, out var matchedStrings))
            {
                stringsByRule[stringRuleName] = matchedStrings;
                continue;
            }

            if (TrySplitStaticYaraEvidence(evidence, "static.yara.meta:", out var metaRuleName, out var metadata))
            {
                var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var pair in metadata.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var equals = pair.IndexOf('=');
                    if (equals <= 0)
                    {
                        continue;
                    }

                    meta[pair[..equals].Trim()] = pair[(equals + 1)..].Trim();
                }

                metaByRule[metaRuleName] = meta;
            }
        }

        foreach (var ruleName in ruleNames.Take(MaxStaticYaraRuleMatches))
        {
            var tags = new List<string>
            {
                "static.yara.match",
                "static.yara.engine.builtin",
                $"static.yara.rule.{NormalizeStaticYaraTag(ruleName)}"
            };
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ruleName"] = ruleName,
                ["engine"] = "builtin",
                ["tags"] = JoinBounded(tags)
            };
            AddStaticRuleFacingFields(
                data,
                "static-yara-like-match",
                "static.yara.match",
                $"yara.{NormalizeStaticYaraTag(ruleName)}",
                "static-signature",
                "low");

            if (stringsByRule.TryGetValue(ruleName, out var matchedStrings))
            {
                data["matchedStringIds"] = matchedStrings;
            }

            if (metaByRule.TryGetValue(ruleName, out var meta))
            {
                if (meta.TryGetValue("scope", out var scope))
                {
                    data["scope"] = scope;
                }

                if (meta.TryGetValue("mitre", out var mitre))
                {
                    data["mitre"] = mitre;
                }
            }

            TryAddStaticEvent(
                events,
                "static.yara.match",
                fullPath,
                $"Built-in static YARA-like rule {ruleName} matched.",
                $"内置轻量 YARA-like 规则命中：{ruleName}。",
                "该匹配由内置轻量解析器完成，不依赖外部 yara 二进制；仅支持项目规则使用的安全子集语法。",
                data);
        }
    }

    /// <summary>
    /// Builds section anomaly tags for event consumers.
    /// </summary>
    private static IEnumerable<string> GetSectionEventTags(PeSectionInfo section)
    {
        yield return "pe_section";
        if (section.Entropy >= 7.2)
        {
            yield return "high_entropy_section";
        }

        if (section.Entropy >= 7.8)
        {
            yield return "very_high_entropy_section";
        }

        if (section.RawDataSize >= 512 && section.Entropy <= 1.0)
        {
            yield return "low_entropy_section";
        }

        if (section.RawDataSize == 0 && section.VirtualSize > 0)
        {
            yield return "virtual_only_section";
        }

        if (section.RawDataSize > 0 && section.VirtualSize > section.RawDataSize * 4 && section.VirtualSize >= 0x2000)
        {
            yield return "oversized_virtual_section";
        }

        if (section.IsExecutable)
        {
            yield return "executable_section";
        }

        if (section.IsWritable)
        {
            yield return "writable_section";
        }

        if (section.IsExecutable && section.IsWritable)
        {
            yield return "writable_executable_section";
        }

        if (section.Name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase))
        {
            yield return "packer_hint";
            yield return "packer_upx";
        }

        if (IsKnownPackerSectionName(section.Name))
        {
            yield return "packer_hint";
            yield return "packer_section_name";
        }
    }

    /// <summary>
    /// Builds import module tags for event consumers.
    /// </summary>
    private static IEnumerable<string> GetImportModuleEventTags(PeImportModuleInfo module)
    {
        yield return "imports_present";
        if (module.SuspiciousApiNames.Count > 0 || module.SuspiciousApiClusters.Count > 0)
        {
            yield return "import_suspicious_api";
        }

        foreach (var cluster in module.SuspiciousApiClusters.SelectMany(TagsForImportCluster))
        {
            yield return cluster;
        }
    }

    /// <summary>
    /// Builds stable static network/string indicator tags used by behavior
    /// rules. Inputs are one structured URL/IP/email/domain indicator;
    /// processing mirrors the legacy summary tags where possible, and the
    /// method returns report/rule-friendly tag names for granular events.
    /// </summary>
    private static IEnumerable<string> GetNetworkIndicatorEventTags(StaticNetworkIndicator indicator)
    {
        yield return "network_indicator_string";
        switch (indicator.Kind)
        {
            case "url":
                yield return "url";
                if (!string.Equals(indicator.Classification, "reference", StringComparison.OrdinalIgnoreCase))
                {
                    yield return "embedded_url";
                }

                break;
            case "ipv4":
                yield return "ip_address";
                if (string.Equals(indicator.Classification, "public", StringComparison.OrdinalIgnoreCase))
                {
                    yield return "public_ip_address";
                }
                else if (string.Equals(indicator.Classification, "private_or_reserved", StringComparison.OrdinalIgnoreCase))
                {
                    yield return "private_or_reserved_ip_address";
                }

                break;
            case "email":
                yield return "email_address";
                break;
            case "domain":
                yield return "domain_name";
                yield return "domain_indicator_string";
                yield return "domain_string";
                if (string.Equals(indicator.Classification, "onion", StringComparison.OrdinalIgnoreCase))
                {
                    yield return "tor_domain_string";
                }
                else if (string.Equals(indicator.Classification, "dynamic_dns", StringComparison.OrdinalIgnoreCase))
                {
                    yield return "dynamic_dns_domain_string";
                }

                break;
            default:
                yield return $"{NormalizeStaticYaraTag(indicator.Kind)}_indicator_string";
                break;
        }
    }

    /// <summary>
    /// Maps import cluster names to stable tags used by behavior rules.
    /// </summary>
    private static IEnumerable<string> TagsForImportCluster(string cluster)
    {
        yield return "import_suspicious_api_cluster";
        switch (cluster)
        {
            case "process-injection":
                yield return "import_process_injection_api";
                break;
            case "dynamic-code":
                yield return "import_dynamic_code_api";
                break;
            case "registry-persistence":
                yield return "import_persistence_api";
                yield return "import_registry_persistence_api";
                break;
            case "service-persistence":
                yield return "import_persistence_api";
                yield return "import_service_persistence_api";
                break;
            case "persistence":
                yield return "import_persistence_api";
                break;
            case "network":
                yield return "import_network_api";
                break;
            case "download":
                yield return "import_network_api";
                yield return "import_download_api";
                break;
            case "exfiltration":
                yield return "import_network_api";
                yield return "import_exfil_api";
                break;
            case "file-drop":
                yield return "import_file_drop_api";
                break;
            case "script-execution":
                yield return "import_script_execution_api";
                break;
            case "resource":
                yield return "import_resource_api";
                break;
            case "anti-analysis":
                yield return "import_anti_analysis_api";
                break;
            case "anti-debug":
                yield return "import_anti_analysis_api";
                yield return "import_anti_debug_api";
                yield return "debugger_evasion_string";
                yield return "anti_debug_string";
                break;
            case "credential-access":
                yield return "import_credential_access_api";
                break;
            case "defense-evasion":
                yield return "import_defense_evasion_api";
                break;
        }
    }

    /// <summary>
    /// Adds common rule-consumer metadata to every granular static event.
    /// </summary>
    private static void AddStaticRuleFacingFields(
        Dictionary<string, string> data,
        string evidenceKind,
        string ruleScope,
        string ruleKey,
        string behaviorFamily,
        string triageLevel)
    {
        data["staticOnly"] = "True";
        data["evidenceOrigin"] = "host-static-analysis";
        data["evidenceKind"] = evidenceKind;
        data["ruleScope"] = ruleScope;
        data["ruleKey"] = ruleKey;
        data["behaviorFamily"] = behaviorFamily;
        data["triageLevel"] = triageLevel;
        data["reportLane"] = DescribeStaticReportLane(behaviorFamily);
        data["evidenceStrength"] = DescribeStaticEvidenceStrength(triageLevel);
        data["runtimeCorrelationRequired"] = "True";
        data["staticEvidenceBoundary"] = "does-not-prove-runtime-execution";
        data["zhBehaviorFamily"] = DescribeStaticBehaviorFamilyZh(behaviorFamily);
        data["zhTriageLevel"] = DescribeStaticTriageLevelZh(triageLevel);
        data["zhEvidenceBoundary"] = "静态证据只说明样本具备相关能力、字符串或文件结构特征，不能单独证明行为已发生。";
        data["zhNextEvidenceHint"] = DescribeStaticNextEvidenceHintZh(behaviorFamily);
    }

    /// <summary>
    /// Maps static behavior families to report lanes that can be grouped without
    /// parsing localized text.
    /// </summary>
    private static string DescribeStaticReportLane(string behaviorFamily)
    {
        return behaviorFamily switch
        {
            "process-injection" or "code-injection-or-unpack" or "packing-or-obfuscation" or "packer" => "injection-and-obfuscation",
            "persistence" => "persistence",
            "network" or "download-execute" or "exfiltration" => "network-and-download",
            "dropped-file" or "embedded-resource" or "embedded-payload" => "payload-and-artifacts",
            "execution-chain" or "script-execution" or "command-string" or "living-off-the-land" => "execution-chain",
            "anti-analysis" or "defense-evasion" => "anti-analysis-and-evasion",
            "credential-access" => "credential-access",
            "pe-section-layout" or "pe-resource" or "pe-export" or "pe-imports" or "pe-signature-metadata" => "pe-structure",
            "static-analysis-summary" or "static-summary" => "static-summary",
            _ => "static-triage"
        };
    }

    /// <summary>
    /// Converts static triage levels into a stable evidence-strength label for
    /// reports and rules.
    /// </summary>
    private static string DescribeStaticEvidenceStrength(string triageLevel)
    {
        return triageLevel switch
        {
            "medium" => "static-medium-needs-runtime-correlation",
            "low" => "static-low-needs-corroboration",
            "info" => "static-context-only",
            "none" => "static-no-signal",
            _ => "static-triage-only"
        };
    }

    /// <summary>
    /// Localizes broad static behavior families for compact report cards.
    /// </summary>
    private static string DescribeStaticBehaviorFamilyZh(string behaviorFamily)
    {
        return behaviorFamily switch
        {
            "process-injection" => "进程注入能力",
            "code-injection-or-unpack" => "动态代码/解包能力",
            "persistence" => "持久化能力",
            "network" => "网络能力",
            "download-execute" => "下载执行链",
            "exfiltration" => "外传能力",
            "dropped-file" => "落地文件能力",
            "embedded-resource" or "embedded-payload" => "内嵌资源/载荷",
            "execution-chain" or "script-execution" or "command-string" => "命令/脚本执行链",
            "living-off-the-land" => "系统自带工具执行",
            "anti-analysis" => "反分析/反沙箱",
            "defense-evasion" => "防御规避",
            "credential-access" => "凭据访问",
            "packing-or-obfuscation" or "packer" => "壳/混淆",
            "capability-imports" => "导入表能力面",
            "pe-imports" => "PE 导入表",
            "pe-section-layout" => "PE 节布局",
            "pe-resource" => "PE 资源",
            "pe-export" => "PE 导出",
            "pe-signature-metadata" => "PE 签名/证书元数据",
            "static-signature" => "静态规则命中",
            "static-analysis-summary" or "static-summary" => "静态分析摘要",
            _ => "静态 triage 线索"
        };
    }

    /// <summary>
    /// Localizes static triage levels without changing the canonical level.
    /// </summary>
    private static string DescribeStaticTriageLevelZh(string triageLevel)
    {
        return triageLevel switch
        {
            "medium" => "中等静态线索，需要运行时证据确认",
            "low" => "低强度静态线索，需要交叉验证",
            "info" => "上下文信息，默认不提升风险",
            "none" => "未见有效静态信号",
            _ => "静态 triage 线索"
        };
    }

    /// <summary>
    /// Suggests the next dynamic evidence lane for a static behavior family.
    /// </summary>
    private static string DescribeStaticNextEvidenceHintZh(string behaviorFamily)
    {
        return behaviorFamily switch
        {
            "process-injection" or "code-injection-or-unpack" =>
                "下一步查看 R0 进程/线程/映像加载事件、完整进程树和内存转储，确认是否真的写入或执行远程代码。",
            "persistence" =>
                "下一步查看 registry/service/scheduled task/startup folder 事件，确认是否真的写入持久化位置。",
            "network" or "download-execute" =>
                "下一步查看 DNS/HTTP/TLS/PCAP、dropped files 和子进程启动，确认是否发生下载、落地和执行。",
            "exfiltration" =>
                "下一步查看文件读取、凭据访问和出站连接流量，确认是否存在外传链路。",
            "dropped-file" or "embedded-resource" or "embedded-payload" =>
                "下一步查看 dropped files、artifact hash、资源释放路径和后续子进程，确认内嵌载荷是否被释放/运行。",
            "execution-chain" or "script-execution" or "command-string" or "living-off-the-land" =>
                "下一步查看 command line、子进程树和 LOLBIN 关联事件，确认字符串是否真的执行。",
            "anti-analysis" or "defense-evasion" =>
                "下一步查看早退、Sleep/时间加速、调试器/VM 检测和安全工具修改事件，区分正常兼容性检查与规避行为。",
            "credential-access" =>
                "下一步查看 LSASS/浏览器/凭据文件访问、dump 文件和可疑句柄事件。",
            "packing-or-obfuscation" or "packer" =>
                "下一步结合高熵节、overlay、TLS callback、运行时解包和内存转储判断是否只是打包或存在恶意载荷。",
            _ =>
                "下一步结合动态事件、规则命中、网络、进程树和 artifacts 判断该静态线索是否被执行。"
        };
    }

    /// <summary>
    /// Adds PE import-module capability fields for rules and reports.
    /// </summary>
    private static void AddImportModuleRuleFacingFields(Dictionary<string, string> data, PeImportModuleInfo module)
    {
        var clusters = module.SuspiciousApiClusters
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var hasDownload = HasImportCluster(module, "download");
        var hasExecution = HasAnyImportCluster(module, "script-execution", "dynamic-code", "file-drop");
        var hasAntiDebug = HasImportCluster(module, "anti-debug") ||
            module.SuspiciousApiNames.Any(api => ContainsAnyApiToken(api, AntiDebugApis));

        AddStaticRuleFacingFields(
            data,
            "pe-import-module",
            "static.pe.import.module",
            $"import.module.{NormalizeStaticYaraTag(module.ModuleName)}",
            clusters.Count > 0 ? "capability-imports" : "pe-imports",
            clusters.Count >= 2 ? "medium" : clusters.Count == 1 ? "low" : "info");
        data["hasSuspiciousApis"] = (module.SuspiciousApiNames.Count > 0 || clusters.Count > 0).ToString();
        data["hasProcessInjectionApi"] = HasImportCluster(module, "process-injection").ToString();
        data["hasDynamicCodeApi"] = HasImportCluster(module, "dynamic-code").ToString();
        data["hasNetworkApi"] = HasImportCluster(module, "network").ToString();
        data["hasDownloadApi"] = hasDownload.ToString();
        data["hasExfiltrationApi"] = HasImportCluster(module, "exfiltration").ToString();
        data["hasPersistenceApi"] = HasAnyImportCluster(module, "persistence", "registry-persistence", "service-persistence").ToString();
        data["hasAntiAnalysisApi"] = HasImportCluster(module, "anti-analysis").ToString();
        data["hasAntiDebugApi"] = hasAntiDebug.ToString();
        data["hasCredentialAccessApi"] = HasImportCluster(module, "credential-access").ToString();
        data["hasDefenseEvasionApi"] = HasImportCluster(module, "defense-evasion").ToString();
        data["downloadExecCandidate"] = (hasDownload && hasExecution).ToString();
        AddDataList(data, "behaviorFamilies", clusters.Select(DescribeImportClusterFamily));
        AddDataList(data, "mitreCandidates", clusters.SelectMany(GetImportClusterMitreCandidates));
        AddDataIfNotBlank(data, "primaryCapability", clusters.Select(DescribeImportClusterCapability).FirstOrDefault());
    }

    /// <summary>
    /// Adds suspicious import-cluster fields for rules and reports.
    /// </summary>
    private static void AddImportClusterRuleFacingFields(Dictionary<string, string> data, PeImportApiClusterInfo cluster)
    {
        AddStaticRuleFacingFields(
            data,
            "pe-import-capability-cluster",
            "static.pe.import.cluster",
            $"import.cluster.{NormalizeStaticYaraTag(cluster.Name)}",
            DescribeImportClusterFamily(cluster.Name),
            cluster.HitCount >= 3 ? "medium" : "low");
        data["behaviorLane"] = DescribeImportClusterLane(cluster.Name);
        data["primaryCapability"] = DescribeImportClusterCapability(cluster.Name);
        data["antiDebugCandidate"] = string.Equals(cluster.Name, "anti-debug", StringComparison.OrdinalIgnoreCase).ToString();
        data["downloadExecCandidate"] = string.Equals(cluster.Name, "download", StringComparison.OrdinalIgnoreCase).ToString();
        AddDataList(data, "mitreCandidates", GetImportClusterMitreCandidates(cluster.Name));
    }

    /// <summary>
    /// Tests whether an import module has a named suspicious cluster.
    /// </summary>
    private static bool HasImportCluster(PeImportModuleInfo module, string cluster)
    {
        return module.SuspiciousApiClusters.Contains(cluster, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Tests whether an import module has any of the named clusters.
    /// </summary>
    private static bool HasAnyImportCluster(PeImportModuleInfo module, params string[] clusters)
    {
        return clusters.Any(cluster => HasImportCluster(module, cluster));
    }

    /// <summary>
    /// Maps static import clusters to broad behavior families.
    /// </summary>
    private static string DescribeImportClusterFamily(string cluster)
    {
        return cluster switch
        {
            "process-injection" => "process-injection",
            "dynamic-code" => "code-injection-or-unpack",
            "registry-persistence" or "service-persistence" or "persistence" => "persistence",
            "network" or "download" or "exfiltration" => "network",
            "file-drop" => "dropped-file",
            "script-execution" => "execution-chain",
            "resource" => "embedded-resource",
            "anti-analysis" or "anti-debug" => "anti-analysis",
            "credential-access" => "credential-access",
            "defense-evasion" => "defense-evasion",
            _ => "static-capability"
        };
    }

    /// <summary>
    /// Maps import clusters to report lanes used by evidence story sections.
    /// </summary>
    private static string DescribeImportClusterLane(string cluster)
    {
        return cluster switch
        {
            "process-injection" or "dynamic-code" => "code-injection",
            "registry-persistence" or "service-persistence" or "persistence" => "persistence",
            "network" or "download" or "exfiltration" => "network",
            "file-drop" or "resource" => "payload-and-artifacts",
            "script-execution" => "execution-chain",
            "anti-analysis" or "anti-debug" => "anti-analysis",
            "credential-access" => "credential-access",
            "defense-evasion" => "defense-evasion",
            _ => "static-triage"
        };
    }

    /// <summary>
    /// Maps import clusters to concise analyst capability labels.
    /// </summary>
    private static string DescribeImportClusterCapability(string cluster)
    {
        return cluster switch
        {
            "process-injection" => "remote-process-memory/thread primitives",
            "dynamic-code" => "dynamic memory protection/loading",
            "registry-persistence" => "registry persistence primitives",
            "service-persistence" => "service-control persistence primitives",
            "persistence" => "generic persistence primitives",
            "network" => "network client primitives",
            "download" => "download/read-from-network primitives",
            "exfiltration" => "upload/write-to-network primitives",
            "file-drop" => "file creation/drop primitives",
            "script-execution" => "process or script launch primitives",
            "resource" => "resource extraction/update primitives",
            "anti-analysis" => "sandbox/debug/time/environment checks",
            "anti-debug" => "debugger detection or hiding primitives",
            "credential-access" => "credential or LSASS access primitives",
            "defense-evasion" => "security tooling or logging interaction",
            _ => "static capability cluster"
        };
    }

    /// <summary>
    /// Maps import clusters to ATT&CK candidates for downstream rules.
    /// </summary>
    private static IEnumerable<string> GetImportClusterMitreCandidates(string cluster)
    {
        return cluster switch
        {
            "process-injection" => ["T1055"],
            "dynamic-code" => ["T1027", "T1106"],
            "registry-persistence" => ["T1112", "T1547.001"],
            "service-persistence" => ["T1543.003"],
            "persistence" => ["TA0003"],
            "network" => ["T1105", "T1071"],
            "download" => ["T1105"],
            "exfiltration" => ["T1041"],
            "file-drop" => ["T1105"],
            "script-execution" => ["T1059"],
            "resource" => ["T1027.009"],
            "anti-analysis" => ["T1497", "T1622"],
            "anti-debug" => ["T1622", "T1497.001"],
            "credential-access" => ["T1003", "T1555"],
            "defense-evasion" => ["T1562"],
            _ => []
        };
    }

    /// <summary>
    /// Returns a Chinese triage hint for a suspicious import cluster.
    /// </summary>
    private static string DescribeImportClusterZhHint(string cluster)
    {
        return cluster switch
        {
            "process-injection" => "导入表包含远程进程内存/线程原语；请在动态事件里确认是否真的写入或创建远程线程。",
            "dynamic-code" => "导入表包含动态内存保护或加载原语；可能用于 unpack、shellcode 或插件加载。",
            "registry-persistence" => "导入表包含注册表写入原语；需要结合 Run/Service/Task 路径或运行时 registry.set 判断。",
            "service-persistence" => "导入表包含服务控制原语；请关注后续是否创建/修改服务。",
            "network" => "导入表包含网络客户端原语；静态能力不代表已联网，优先结合 DNS/HTTP/TLS/PCAP。",
            "download" => "导入表包含下载/读取网络数据原语；若同时有进程启动或落地路径，可作为下载执行候选。",
            "exfiltration" => "导入表包含上传/发送数据原语；需结合网络流量、文件读取或凭据访问证据确认。",
            "file-drop" => "导入表包含创建/写入文件原语；请关注 dropped files 和 artifact hash。",
            "script-execution" => "导入表包含进程/脚本启动原语；请结合命令行和子进程树确认执行链。",
            "resource" => "导入表包含资源提取/更新原语；可能释放内嵌 payload，需结合资源和 dropped files。",
            "anti-analysis" => "导入表包含环境、时间或调试检测原语；需要区分正常兼容性检查和沙箱规避。",
            "anti-debug" => "导入表包含明确反调试原语；请优先关联早期退出、异常延迟或调试器探测事件。",
            "credential-access" => "导入表包含凭据或 LSASS 访问相关原语；需结合进程句柄、dump 或文件访问证据确认。",
            "defense-evasion" => "导入表包含安全工具/日志/AMSI/ETW 相关原语；需结合配置修改或命令执行确认。",
            _ => "该导入聚类是静态能力线索，不等同于已发生行为。"
        };
    }

    /// <summary>
    /// Classifies an export name for rule-facing metadata.
    /// </summary>
    private static string DescribeExportRole(string exportName)
    {
        if (ContainsAny(exportName, "DllRegisterServer", "DllUnregisterServer", "DllInstall"))
        {
            return "com-registration-entrypoint";
        }

        if (ContainsAny(exportName, "ServiceMain", "SvchostPushServiceGlobals"))
        {
            return "service-entrypoint";
        }

        return "generic-export";
    }

    /// <summary>
    /// Classifies PE resource data entries for rule-facing metadata.
    /// </summary>
    private static string DescribeResourceRole(PeResourceInfo resource)
    {
        if (resource.IsEmbeddedPe)
        {
            return "embedded-pe";
        }

        if (resource.IsPayloadCandidate)
        {
            return "payload-candidate";
        }

        if (resource.Entropy >= 7.2)
        {
            return "high-entropy-resource";
        }

        if (resource.IsLarge)
        {
            return "large-resource";
        }

        if (string.Equals(resource.ResourceType, "manifest", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resource.ResourceType, "version", StringComparison.OrdinalIgnoreCase) ||
            resource.ResourceType.Contains("icon", StringComparison.OrdinalIgnoreCase))
        {
            return "metadata-resource";
        }

        return "resource-data";
    }

    /// <summary>
    /// Classifies overlay evidence for rule-facing metadata.
    /// </summary>
    private static string DescribeOverlayRole(PeOverlayInfo overlay)
    {
        if (overlay.IsCertificateTableOnly)
        {
            return "certificate-table-only";
        }

        if (overlay.ContainsCertificateTable && overlay.NonCertificateSize > 0)
        {
            return "certificate-plus-appended-data";
        }

        return overlay.NonCertificateSize > 0 ? "appended-non-certificate-data" : "overlay-metadata";
    }

    /// <summary>
    /// Maps static network indicators to a concise role.
    /// </summary>
    private static string DescribeNetworkIndicatorRole(StaticNetworkIndicator indicator)
    {
        if (string.Equals(indicator.Classification, "reference", StringComparison.OrdinalIgnoreCase))
        {
            return "reference";
        }

        if (string.Equals(indicator.Classification, "onion", StringComparison.OrdinalIgnoreCase))
        {
            return "tor-hidden-service";
        }

        if (string.Equals(indicator.Classification, "dynamic_dns", StringComparison.OrdinalIgnoreCase))
        {
            return "dynamic-dns";
        }

        if (string.Equals(indicator.Kind, "url", StringComparison.OrdinalIgnoreCase) &&
            IsPotentialExecutableDownloadValue(indicator.Value))
        {
            return "download-url-candidate";
        }

        return string.Equals(indicator.Kind, "ipv4", StringComparison.OrdinalIgnoreCase) ? "ip-literal" : $"{indicator.Kind}-indicator";
    }

    /// <summary>
    /// Tests whether a URL/string looks like a retrievable executable payload.
    /// </summary>
    private static bool IsPotentialExecutableDownloadValue(string value)
    {
        return ContainsAny(value, ".exe", ".dll", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".zip", ".rar", ".7z");
    }

    /// <summary>
    /// Maps static path tags to a concise role.
    /// </summary>
    private static string DescribePathRole(StaticPathIndicator path)
    {
        if (path.Tags.Contains("run_key_path_string", StringComparer.OrdinalIgnoreCase))
        {
            return "run-key";
        }

        if (path.Tags.Contains("service_registry_path_string", StringComparer.OrdinalIgnoreCase))
        {
            return "service-registry";
        }

        if (path.Tags.Contains("scheduled_task_registry_path_string", StringComparer.OrdinalIgnoreCase) ||
            path.Tags.Contains("scheduled_task_path_string", StringComparer.OrdinalIgnoreCase))
        {
            return "scheduled-task";
        }

        if (path.Tags.Contains("startup_folder_path_string", StringComparer.OrdinalIgnoreCase))
        {
            return "startup-folder";
        }

        if (path.Tags.Contains("script_path_string", StringComparer.OrdinalIgnoreCase))
        {
            return "script-path";
        }

        if (path.Tags.Contains("executable_path_string", StringComparer.OrdinalIgnoreCase))
        {
            return "executable-path";
        }

        if (path.Tags.Contains("temp_path_string", StringComparer.OrdinalIgnoreCase) ||
            path.Tags.Contains("appdata_path_string", StringComparer.OrdinalIgnoreCase))
        {
            return "user-writable-location";
        }

        return path.Kind;
    }

    /// <summary>
    /// Maps command indicator categories to broad behavior families.
    /// </summary>
    private static string DescribeCommandBehaviorFamily(StaticCommandIndicator command)
    {
        return command.Category switch
        {
            "download-command" or "download-execute" => "download-execute",
            "exfil-command" => "exfiltration",
            "encoded-command" => "script-obfuscation",
            "lolbin" => "living-off-the-land",
            "service-control" or "scheduled-task" => "persistence",
            "script-interpreter" => "script-execution",
            _ => "command-string"
        };
    }

    /// <summary>
    /// Maps suspicious string categories to broad behavior families.
    /// </summary>
    private static string DescribeSuspiciousStringBehaviorFamily(StaticStringFinding finding)
    {
        return finding.Category switch
        {
            "anti-debug-string" or "anti-analysis-string" => "anti-analysis",
            "credential-access-string" => "credential-access",
            "defense-evasion-string" => "defense-evasion",
            "persistence-string" or "service-string" or "scheduled-task-string" => "persistence",
            "packer-string" => "packer",
            "suspicious-api-string" => "api-capability",
            _ => "suspicious-string"
        };
    }

    /// <summary>
    /// Adds one normalized static event while respecting the event cap.
    /// </summary>
    private static void TryAddStaticEvent(
        List<SandboxEvent> events,
        string eventType,
        string fullPath,
        string message,
        string zhMessage,
        string zhHint,
        Dictionary<string, string> data)
    {
        if (events.Count >= MaxStaticAnalysisEvents)
        {
            return;
        }

        data["message"] = message;
        data["zhMessage"] = zhMessage;
        data["zhHint"] = zhHint;

        events.Add(new SandboxEvent
        {
            EventType = eventType,
            Source = "host",
            Path = fullPath,
            Data = TrimStaticEventData(data)
        });
    }

    /// <summary>
    /// Adds a non-empty data field with bounded value length.
    /// </summary>
    private static void AddDataIfNotBlank(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Adds a comma-separated data list when it contains values.
    /// </summary>
    private static void AddDataList(Dictionary<string, string> data, string key, IEnumerable<string> values, string separator = ",")
    {
        var joined = JoinBounded(values, separator);
        if (!string.IsNullOrWhiteSpace(joined))
        {
            data[key] = joined;
        }
    }

    /// <summary>
    /// Joins values into a bounded event-data string.
    /// </summary>
    private static string JoinBounded(IEnumerable<string> values, string separator = ",")
    {
        var builder = new StringBuilder();
        foreach (var value in values.Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var trimmed = TrimStaticEventValue(value);
            if (trimmed.Length == 0)
            {
                continue;
            }

            var prefixLength = builder.Length == 0 ? 0 : separator.Length;
            if (builder.Length + prefixLength + trimmed.Length > MaxStaticEventDataValueLength)
            {
                if (builder.Length + prefixLength + 3 <= MaxStaticEventDataValueLength)
                {
                    if (builder.Length > 0)
                    {
                        builder.Append(separator);
                    }

                    builder.Append("...");
                }

                break;
            }

            if (builder.Length > 0)
            {
                builder.Append(separator);
            }

            builder.Append(trimmed);
        }

        return builder.ToString();
    }

    /// <summary>
    /// Trims all event data values to a safe single-line representation.
    /// </summary>
    private static Dictionary<string, string> TrimStaticEventData(Dictionary<string, string> data)
    {
        var trimmed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in data)
        {
            if (string.IsNullOrWhiteSpace(pair.Key) || string.IsNullOrWhiteSpace(pair.Value))
            {
                continue;
            }

            trimmed[pair.Key] = TrimStaticEventValue(pair.Value);
        }

        return trimmed;
    }

    /// <summary>
    /// Trims one event data value and removes line breaks.
    /// </summary>
    private static string TrimStaticEventValue(string value)
    {
        var normalized = value
            .Replace("\r\n", " ", StringComparison.Ordinal)
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Trim();
        return normalized.Length <= MaxStaticEventDataValueLength
            ? normalized
            : normalized[..MaxStaticEventDataValueLength];
    }

    /// <summary>
    /// Splits static.yara.* evidence into rule name and payload.
    /// </summary>
    private static bool TrySplitStaticYaraEvidence(string evidence, string prefix, out string ruleName, out string payload)
    {
        ruleName = string.Empty;
        payload = string.Empty;
        if (!evidence.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rest = evidence[prefix.Length..];
        var separator = rest.IndexOf(':');
        if (separator <= 0)
        {
            return false;
        }

        ruleName = rest[..separator].Trim();
        payload = rest[(separator + 1)..].Trim();
        return ruleName.Length > 0;
    }

    /// <summary>
    /// Byte buffer plus lazily materialized text used by the YARA subset
    /// matcher.
    /// </summary>
    private sealed class StaticYaraScanContext
    {
        private string? asciiText;

        public StaticYaraScanContext(byte[] buffer)
        {
            Buffer = buffer;
        }

        public byte[] Buffer { get; }

        public string AsciiText => asciiText ??= Encoding.Latin1.GetString(Buffer);
    }

    /// <summary>
    /// Parsed lightweight YARA rule.
    /// </summary>
    private sealed record StaticYaraRule(
        string Name,
        Dictionary<string, string> Meta,
        List<StaticYaraString> Strings,
        string Condition);

    /// <summary>
    /// Parsed YARA string definition.
    /// </summary>
    private sealed record StaticYaraString(
        string Identifier,
        StaticYaraStringKind Kind,
        string? Literal,
        string? Pattern,
        HashSet<string> Modifiers);

    /// <summary>
    /// Supported YARA string definition kind.
    /// </summary>
    private enum StaticYaraStringKind
    {
        Literal,
        Regex
    }

    /// <summary>
    /// Matched YARA rule and bounded matched string identifiers.
    /// </summary>
    private sealed record StaticYaraRuleMatch(string RuleName, List<string> MatchedStringIds);

    /// <summary>
    /// Token kind for the tiny YARA condition parser.
    /// </summary>
    private enum StaticYaraConditionTokenKind
    {
        Identifier,
        StringIdentifier,
        Number,
        Equals,
        OpenParen,
        CloseParen,
        Comma
    }

    /// <summary>
    /// Token value for the tiny YARA condition parser.
    /// </summary>
    private readonly record struct StaticYaraConditionToken(StaticYaraConditionTokenKind Kind, string Text);

    /// <summary>
    /// Evaluates the simple condition grammar used by rules/static-notes.yar.
    /// </summary>
    private sealed class StaticYaraConditionParser
    {
        private readonly IReadOnlyList<StaticYaraConditionToken> tokens;
        private readonly IReadOnlyList<StaticYaraString> strings;
        private readonly HashSet<string> matchedStringIds;
        private readonly byte[] buffer;
        private int position;

        public StaticYaraConditionParser(
            IReadOnlyList<StaticYaraConditionToken> tokens,
            IReadOnlyList<StaticYaraString> strings,
            HashSet<string> matchedStringIds,
            byte[] buffer)
        {
            this.tokens = tokens;
            this.strings = strings;
            this.matchedStringIds = matchedStringIds;
            this.buffer = buffer;
        }

        public bool Parse()
        {
            return ParseOr();
        }

        private bool ParseOr()
        {
            var value = ParseAnd();
            while (MatchIdentifier("or"))
            {
                var right = ParseAnd();
                value = value || right;
            }

            return value;
        }

        private bool ParseAnd()
        {
            var value = ParseUnary();
            while (MatchIdentifier("and"))
            {
                var right = ParseUnary();
                value = value && right;
            }

            return value;
        }

        private bool ParseUnary()
        {
            if (MatchIdentifier("not"))
            {
                return !ParseUnary();
            }

            return ParsePrimary();
        }

        private bool ParsePrimary()
        {
            if (Match(StaticYaraConditionTokenKind.OpenParen))
            {
                var value = ParseOr();
                Match(StaticYaraConditionTokenKind.CloseParen);
                return value;
            }

            if (IsIdentifier("uint16"))
            {
                return ParseUInt16Comparison();
            }

            if (IsIdentifier("any") || IsIdentifier("all") || Current.Kind == StaticYaraConditionTokenKind.Number)
            {
                return ParseOfExpression();
            }

            if (Current.Kind == StaticYaraConditionTokenKind.StringIdentifier)
            {
                var identifier = Current.Text.TrimStart('$');
                position++;
                return matchedStringIds.Contains(identifier);
            }

            if (!IsAtEnd)
            {
                position++;
            }

            return false;
        }

        private bool ParseUInt16Comparison()
        {
            position++;
            if (!Match(StaticYaraConditionTokenKind.OpenParen) ||
                !TryReadNumber(out var offset) ||
                !Match(StaticYaraConditionTokenKind.CloseParen) ||
                !Match(StaticYaraConditionTokenKind.Equals) ||
                !TryReadNumber(out var expected))
            {
                return false;
            }

            if (offset < 0 || offset > int.MaxValue || expected < 0)
            {
                return false;
            }

            var actual = ReadUInt16LittleEndian(buffer, (int)offset);
            return actual.HasValue && actual.Value == expected;
        }

        private bool ParseOfExpression()
        {
            var mode = string.Empty;
            var requiredCount = 0L;
            if (MatchIdentifier("any"))
            {
                mode = "any";
            }
            else if (MatchIdentifier("all"))
            {
                mode = "all";
            }
            else if (TryReadNumber(out requiredCount))
            {
                mode = "count";
            }

            if (mode.Length == 0 || !MatchIdentifier("of"))
            {
                return false;
            }

            var candidateIds = ParseStringSet();
            if (candidateIds.Count == 0)
            {
                return false;
            }

            var matchedCount = candidateIds.Count(identifier => matchedStringIds.Contains(identifier));
            return mode switch
            {
                "any" => matchedCount > 0,
                "all" => matchedCount == candidateIds.Count,
                _ => matchedCount >= requiredCount
            };
        }

        private List<string> ParseStringSet()
        {
            if (MatchIdentifier("them"))
            {
                return strings
                    .Select(yaraString => yaraString.Identifier)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            var identifiers = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            if (Match(StaticYaraConditionTokenKind.OpenParen))
            {
                while (!IsAtEnd)
                {
                    if (Match(StaticYaraConditionTokenKind.CloseParen))
                    {
                        break;
                    }

                    if (Current.Kind == StaticYaraConditionTokenKind.StringIdentifier)
                    {
                        AddStringReference(identifiers, Current.Text);
                        position++;
                        Match(StaticYaraConditionTokenKind.Comma);
                        continue;
                    }

                    position++;
                }

                return identifiers.ToList();
            }

            if (Current.Kind == StaticYaraConditionTokenKind.StringIdentifier)
            {
                AddStringReference(identifiers, Current.Text);
                position++;
            }

            return identifiers.ToList();
        }

        private void AddStringReference(SortedSet<string> identifiers, string token)
        {
            var reference = token.TrimStart('$');
            if (reference.EndsWith('*'))
            {
                var prefix = reference[..^1];
                foreach (var yaraString in strings.Where(yaraString => yaraString.Identifier.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                {
                    identifiers.Add(yaraString.Identifier);
                }

                return;
            }

            if (strings.Any(yaraString => string.Equals(yaraString.Identifier, reference, StringComparison.OrdinalIgnoreCase)))
            {
                identifiers.Add(reference);
            }
        }

        private bool TryReadNumber(out long value)
        {
            value = 0;
            if (Current.Kind != StaticYaraConditionTokenKind.Number)
            {
                return false;
            }

            var token = Current.Text;
            position++;
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                return long.TryParse(token[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
            }

            return long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        private bool MatchIdentifier(string value)
        {
            if (!IsIdentifier(value))
            {
                return false;
            }

            position++;
            return true;
        }

        private bool IsIdentifier(string value)
        {
            return Current.Kind == StaticYaraConditionTokenKind.Identifier &&
                   string.Equals(Current.Text, value, StringComparison.OrdinalIgnoreCase);
        }

        private bool Match(StaticYaraConditionTokenKind kind)
        {
            if (Current.Kind != kind)
            {
                return false;
            }

            position++;
            return true;
        }

        private bool IsAtEnd => position >= tokens.Count;

        private StaticYaraConditionToken Current => IsAtEnd
            ? new StaticYaraConditionToken(StaticYaraConditionTokenKind.Identifier, string.Empty)
            : tokens[position];

        private static int? ReadUInt16LittleEndian(byte[] data, int offset)
        {
            if (offset < 0 || offset > data.Length - sizeof(ushort))
            {
                return null;
            }

            return data[offset] | data[offset + 1] << 8;
        }
    }

    /// <summary>
    /// Internal PE data-directory pointer used by lightweight parsing.
    /// Inputs are parsed RVA and size values; processing is simple storage; the
    /// value returns whether a directory is present.
    /// </summary>
    private readonly record struct PeDataDirectory(uint Rva, uint Size)
    {
        public bool IsPresent => Rva != 0;
    }

    /// <summary>
    /// Internal aggregate for one IMAGE_IMPORT_DESCRIPTOR.
    /// Inputs are a DLL name plus bounded thunk-walk counters; processing is
    /// simple storage for report evidence, and the type is not exposed.
    /// </summary>
    private sealed class ImportModuleSummary
    {
        public ImportModuleSummary(string dllName)
        {
            DllName = dllName;
        }

        public string DllName { get; }

        public int NamedApiCount { get; set; }

        public int OrdinalImportCount { get; set; }

        public List<string> ApiNames { get; } = [];

        public List<string> OrdinalImports { get; } = [];

        public List<string> SuspiciousApiNames { get; } = [];

        public List<string> SuspiciousApiClusters { get; } = [];
    }

    /// <summary>
    /// Mutable PE parse evidence accumulated before creating the public model.
    /// </summary>
    private sealed class PeAnalysisEvidence
    {
        public List<PeImportModuleInfo> Imports { get; set; } = [];

        public List<PeImportApiClusterInfo> ImportApiClusters { get; set; } = [];

        public string? ExportModuleName { get; set; }

        public List<string> ExportNames { get; } = [];

        public PeTlsInfo? Tls { get; set; }

        public PeOverlayInfo? Overlay { get; set; }

        public List<PeResourceInfo> Resources { get; } = [];
    }

    /// <summary>
    /// Mutable suspicious import API cluster rollup.
    /// </summary>
    private sealed class ImportApiClusterSummary
    {
        public ImportApiClusterSummary(string name)
        {
            Name = name;
        }

        public string Name { get; }

        public int HitCount { get; set; }

        public SortedSet<string> ApiNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Mutable string-indicator evidence accumulated before creating the public model.
    /// </summary>
    private sealed class StaticStringEvidence
    {
        public List<StaticNetworkIndicator> NetworkIndicators { get; } = [];

        public HashSet<string> NetworkIndicatorKeys { get; } = new(StringComparer.OrdinalIgnoreCase);

        public List<StaticPathIndicator> PathIndicators { get; } = [];

        public HashSet<string> PathIndicatorKeys { get; } = new(StringComparer.OrdinalIgnoreCase);

        public List<StaticCommandIndicator> CommandIndicators { get; } = [];

        public HashSet<string> CommandIndicatorKeys { get; } = new(StringComparer.OrdinalIgnoreCase);

        public List<StaticStringFinding> SuspiciousStrings { get; } = [];

        public HashSet<string> SuspiciousStringKeys { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Internal PE section layout used for RVA mapping.
    /// Inputs are parsed section header values; processing is simple storage;
    /// the value is not exposed in report models.
    /// </summary>
    private sealed record PeSectionLayout(string Name, uint VirtualAddress, uint VirtualSize, uint RawSize, uint RawPointer);

    /// <summary>
    /// Internal raw-file interval used for overlay/certificate-table parsing.
    /// Inputs are start and exclusive end offsets; processing is simple storage
    /// plus overlap helpers; the value is not exposed in report models.
    /// </summary>
    private readonly record struct FileInterval(long Start, long End)
    {
        public long Length => Math.Max(0, End - Start);

        public bool Overlaps(FileInterval other) => Start < other.End && other.Start < End;

        public FileInterval Intersect(FileInterval other) => new(Math.Max(Start, other.Start), Math.Min(End, other.End));
    }
}
