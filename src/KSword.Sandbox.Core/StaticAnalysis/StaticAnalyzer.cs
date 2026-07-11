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
    private const int MaxResourceEntries = 160;
    private const int MaxResourceEvidence = 96;
    private const int MaxResourceDepth = 4;
    private const int MaxPeStringLength = 180;
    private const int MaxStructuredPeEntries = 128;
    private const int MaxStructuredStringIndicators = 160;

    private static readonly Regex UrlPattern = new(
        @"https?://[^\s""'<>]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex Ipv4Pattern = new(
        @"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex EmailPattern = new(
        @"(?<![A-Z0-9._%+\-])(?:[A-Z0-9._%+\-]{1,64})@(?:[A-Z0-9\-]{1,63}\.)+[A-Z]{2,63}(?![A-Z0-9._%+\-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex WindowsPathPattern = new(
        @"(?<![A-Za-z0-9])(?:[A-Za-z]:\\|\\\\)[^""'<>|\r\n]{3,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex RegistryPathPattern = new(
        @"\b(?:HKCU|HKLM|HKCR|HKU|HKCC|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^""'<>|\r\n]{3,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

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
        "InternetCrackUrl",
        "URLDownloadToFile",
        "URLDownloadToCacheFile",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpReadData",
        "WSAStartup",
        "socket",
        "getaddrinfo",
        "connect",
        "send",
        "recv"
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
        "GetComputerName",
        "GetUserName",
        "GlobalMemoryStatusEx",
        "GetSystemInfo",
        "GetTickCount",
        "QueryPerformanceCounter",
        "Sleep"
    ];

    private static readonly string[] SuspiciousApiStrings =
        ProcessInjectionApis
            .Concat(DynamicCodeApis)
            .Concat(PersistenceApis)
            .Concat(NetworkApis)
            .Concat(FileDropApis)
            .Concat(ScriptExecutionApis)
            .Concat(ResourceApis)
            .Concat(AntiAnalysisApis)
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

    private static readonly string[] PackerStringMarkers =
    [
        "UPX!",
        "UPX0",
        "UPX1",
        "UPX2",
        "ASPack",
        "MPRESS",
        "Themida",
        "VMProtect",
        "Enigma Protector",
        "PECompact"
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
        ".packed",
        ".themida",
        ".enigma"
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
        "installutil"
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
        "installutil"
    ];

    private static readonly string[] EncodedCommandMarkers =
    [
        "-enc",
        "-encodedcommand",
        "frombase64string",
        "iex ",
        "invoke-expression"
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
            Overlay = peEvidence.Overlay
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

        if (ContainsAny(trimmed, "Run\\", "RunOnce\\", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
        {
            isInteresting = true;
            tags.Add("interesting_string");
            tags.Add("persistence_string");
            AddStringFinding(stringEvidence, "persistence-string", trimmed, "persistence_string");
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

        if (ContainsAny(trimmed, PackerStringMarkers))
        {
            isInteresting = true;
            tags.Add("packer_string_hint");
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
                pathTags.Add("service_registry_path_string");
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
            tags.Add("packer_upx");
        }

        if (sections.Any(section => IsKnownPackerSectionName(section.Name)))
        {
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
            tags.Add("packer_upx");
        }

        if (IsKnownPackerSectionName(name))
        {
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
            ReadResources(reader, directories[2], sections, fileLength, tags, interestingStrings, warnings);
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
        List<string> warnings)
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
        ref int evidenceCount)
    {
        if (dataEntryOffset < 0 || dataEntryOffset > fileLength - 16)
        {
            warnings.Add("Resource data entry is truncated.");
            return;
        }

        var dataRva = ReadUInt32At(reader, dataEntryOffset, fileLength, warnings);
        var size = ReadUInt32At(reader, dataEntryOffset + sizeof(uint), fileLength, warnings);
        AddPeEvidence(interestingStrings, $"resource:{resourceType},size={size}", ref evidenceCount, MaxResourceEvidence);
        if (size >= 1024 * 1024)
        {
            tags.Add("resource_large_data");
        }

        if (string.Equals(resourceType, "rcdata", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "html", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "unknown", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(resourceType, "named", StringComparison.OrdinalIgnoreCase))
        {
            tags.Add("resource_payload_candidate");
        }

        if (!TryRvaToFileOffset(dataRva, sections, fileLength, out var dataOffset))
        {
            return;
        }

        if (size >= 256)
        {
            var entropy = CalculateEntropy(reader, dataOffset, size, fileLength, warnings);
            if (entropy >= 7.2)
            {
                tags.Add("resource_high_entropy_data");
            }
        }

        if (TryReadUInt16At(reader, dataOffset, fileLength, out var magic) && magic == 0x5a4d)
        {
            tags.Add("resource_embedded_pe");
            tags.Add("resource_payload_candidate");
            AddPeEvidence(interestingStrings, $"resource:{resourceType}:embedded-pe@0x{dataRva:X8}", ref evidenceCount, MaxResourceEvidence);
        }
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
            AddPeEvidence(interestingStrings, $"tls:callback@0x{callbackVa:X}", ref evidenceCount, MaxTlsCallbacks);
            callbacks.Add(new PeTlsCallbackInfo
            {
                VirtualAddress = $"0x{callbackVa:X}",
                RelativeVirtualAddress = imageBase != 0 && callbackVa >= imageBase
                    ? $"0x{callbackVa - imageBase:X}"
                    : null
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
