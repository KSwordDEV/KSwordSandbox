using System.Text;
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
    private const int MaxExportNames = 64;
    private const int MaxTlsCallbacks = 32;
    private const int MaxPeStringLength = 180;

    private static readonly string[] ProcessInjectionApis =
    [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "SetThreadContext",
        "GetThreadContext",
        "OpenProcess",
        "ResumeThread",
        "CreateToolhelp32Snapshot"
    ];

    private static readonly string[] DynamicCodeApis =
    [
        "VirtualAlloc",
        "VirtualProtect",
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

    private static readonly string[] NetworkApis =
    [
        "InternetOpen",
        "InternetConnect",
        "HttpOpenRequest",
        "HttpSendRequest",
        "URLDownloadToFile",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpSendRequest",
        "WSAStartup",
        "connect",
        "send",
        "recv"
    ];

    private static readonly string[] AntiAnalysisApis =
    [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "GetTickCount",
        "QueryPerformanceCounter",
        "Sleep"
    ];

    private static readonly string[] SuspiciousApiStrings =
        ProcessInjectionApis
            .Concat(DynamicCodeApis)
            .Concat(PersistenceApis)
            .Concat(NetworkApis)
            .Concat(AntiAnalysisApis)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static readonly string[] SuspiciousApiStringMarkers =
        SuspiciousApiStrings
            .Where(api => !string.Equals(api, "connect", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "send", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "recv", StringComparison.OrdinalIgnoreCase))
            .Where(api => !string.Equals(api, "Sleep", StringComparison.OrdinalIgnoreCase))
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

        using var stream = File.OpenRead(fullPath);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var header = ParsePe(reader, stream.Length, tags, interestingStrings, warnings);
        ExtractStrings(fullPath, tags, urls, interestingStrings, warnings);

        return header with
        {
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
        var sections = ReadSections(reader, sectionHeadersOffset, sectionCount, fileLength, tags, warnings, sectionLayouts);
        var architecture = DescribeArchitecture(machine, optionalMagic);
        var subsystemText = DescribeSubsystem(subsystem);
        AddPeTags(optionalMagic, subsystemText, sections, tags);
        AnalyzePeDataDirectories(reader, dataDirectories, sectionLayouts, optionalMagic, imageBase, fileLength, tags, interestingStrings, warnings);

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
            Sections = sections
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
        List<PeSectionLayout> layouts)
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
            var entropy = CalculateEntropy(reader, rawPointer, rawSize, fileLength, warnings);
            AddSectionTags(name, entropy, virtualSize, rawSize, tags);
            layouts.Add(new PeSectionLayout(name, virtualAddress, virtualSize, rawSize, rawPointer));

            sections.Add(new PeSectionInfo
            {
                Name = name,
                VirtualAddress = $"0x{virtualAddress:X8}",
                VirtualSize = virtualSize,
                RawDataSize = rawSize,
                Entropy = Math.Round(entropy, 3)
            });
        }

        return sections;
    }

    /// <summary>
    /// Extracts bounded ASCII and UTF-16 strings and URL-like values.
    /// Inputs are a file path and output collections, processing scans up to a
    /// fixed byte limit, and the method returns no value.
    /// </summary>
    private static void ExtractStrings(string fullPath, SortedSet<string> tags, SortedSet<string> urls, SortedSet<string> interestingStrings, List<string> warnings)
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
            AddStringClassifications(text, tags, urls, interestingStrings);
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
    /// Inputs are text and output collections, processing applies simple
    /// substring heuristics, and the method returns no value.
    /// </summary>
    private static void AddStringClassifications(string text, SortedSet<string> tags, SortedSet<string> urls, SortedSet<string> interestingStrings)
    {
        var trimmed = text.Trim();
        if (trimmed.Length > 240)
        {
            trimmed = trimmed[..240];
        }

        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            urls.Add(trimmed);
            tags.Add("url");
            return;
        }

        var isInteresting = false;
        if (ContainsAny(trimmed, "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "reg.exe", "schtasks", "Run\\", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
        {
            isInteresting = true;
            tags.Add("interesting_string");
        }

        if (ContainsAny(trimmed, SuspiciousApiStringMarkers))
        {
            isInteresting = true;
            tags.Add("suspicious_api_string");
            AddSuspiciousApiTags(trimmed, tags);
        }

        if (ContainsAny(trimmed, PackerStringMarkers))
        {
            isInteresting = true;
            tags.Add("packer_string_hint");
        }

        if (isInteresting)
        {
            interestingStrings.Add(trimmed);
        }
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
    private static void AddSectionTags(string name, double entropy, uint virtualSize, uint rawSize, SortedSet<string> tags)
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

        if (rawSize == 0 && virtualSize > 0)
        {
            tags.Add("virtual_only_section");
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
        List<string> warnings)
    {
        if (directories.Count > 0)
        {
            ReadExports(reader, directories[0], sections, fileLength, tags, interestingStrings, warnings);
        }

        if (directories.Count > 1)
        {
            ReadImports(reader, directories[1], sections, optionalMagic, fileLength, tags, interestingStrings, warnings);
        }

        if (directories.Count > 9)
        {
            ReadTlsDirectory(reader, directories[9], sections, optionalMagic, imageBase, fileLength, tags, interestingStrings, warnings);
        }
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
        List<string> warnings)
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
            AddPeEvidence(interestingStrings, $"import:{dllName}", ref evidenceCount, MaxImportEvidence);
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (thunkRva != 0)
            {
                ReadImportThunks(reader, dllName, thunkRva, sections, optionalMagic, fileLength, tags, interestingStrings, ref evidenceCount);
            }
        }
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
                AddPeEvidence(interestingStrings, $"import:{dllName}!#ordinal{rawEntry & 0xffff}", ref evidenceCount, MaxImportEvidence);
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

            AddPeEvidence(interestingStrings, $"import:{dllName}!{apiName}", ref evidenceCount, MaxImportEvidence);
            AddSuspiciousApiTags(apiName, tags);
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
        List<string> warnings)
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
        List<string> warnings)
    {
        if (!tlsDirectory.IsPresent)
        {
            return;
        }

        tags.Add("tls_directory_present");
        var evidenceCount = 0;
        AddPeEvidence(interestingStrings, "tls:directory", ref evidenceCount, MaxTlsCallbacks);
        if (!TryRvaToFileOffset(tlsDirectory.Rva, sections, fileLength, out var tlsOffset))
        {
            warnings.Add($"TLS directory RVA 0x{tlsDirectory.Rva:X8} could not be mapped to a file offset.");
            return;
        }

        var isPe32Plus = optionalMagic == 0x20b;
        var callbackVaOffset = tlsOffset + (isPe32Plus ? 24 : 12);
        var callbacksVa = isPe32Plus
            ? ReadUInt64At(reader, callbackVaOffset, fileLength, warnings)
            : ReadUInt32At(reader, callbackVaOffset, fileLength, warnings);
        if (callbacksVa == 0)
        {
            return;
        }

        tags.Add("tls_callback_pointer");
        if (!TryVaToFileOffset(callbacksVa, imageBase, sections, fileLength, out var callbacksOffset))
        {
            AddPeEvidence(interestingStrings, $"tls:callback-table@0x{callbacksVa:X}", ref evidenceCount, MaxTlsCallbacks);
            return;
        }

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
        }
    }

    /// <summary>
    /// Adds grouped tags for suspicious Windows API imports or strings.
    /// Inputs are one API-like text value and tag set, processing matches
    /// curated substring groups, and the method returns no value.
    /// </summary>
    private static void AddSuspiciousApiTags(string apiName, SortedSet<string> tags)
    {
        if (ContainsAny(apiName, ProcessInjectionApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_process_injection_api");
        }

        if (ContainsAny(apiName, DynamicCodeApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_dynamic_code_api");
        }

        if (ContainsAny(apiName, PersistenceApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_persistence_api");
        }

        if (ContainsAny(apiName, NetworkApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_network_api");
        }

        if (ContainsAny(apiName, AntiAnalysisApis))
        {
            tags.Add("import_suspicious_api");
            tags.Add("import_anti_analysis_api");
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
    /// Calculates Shannon entropy for section raw bytes.
    /// Inputs are a reader, raw pointer, raw size, file size, and warnings;
    /// processing reads bounded section bytes, and the method returns entropy.
    /// </summary>
    private static double CalculateEntropy(BinaryReader reader, uint rawPointer, uint rawSize, long fileLength, List<string> warnings)
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
    /// Internal PE data-directory pointer used by lightweight parsing.
    /// Inputs are parsed RVA and size values; processing is simple storage; the
    /// value returns whether a directory is present.
    /// </summary>
    private readonly record struct PeDataDirectory(uint Rva, uint Size)
    {
        public bool IsPresent => Rva != 0;
    }

    /// <summary>
    /// Internal PE section layout used for RVA mapping.
    /// Inputs are parsed section header values; processing is simple storage;
    /// the value is not exposed in report models.
    /// </summary>
    private sealed record PeSectionLayout(string Name, uint VirtualAddress, uint VirtualSize, uint RawSize, uint RawPointer);
}
