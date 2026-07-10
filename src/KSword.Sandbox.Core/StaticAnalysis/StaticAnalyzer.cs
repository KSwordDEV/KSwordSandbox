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
        var header = ParsePe(reader, stream.Length, tags, warnings);
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
    /// returns a partially populated StaticAnalysisResult.
    /// </summary>
    private static StaticAnalysisResult ParsePe(BinaryReader reader, long fileLength, SortedSet<string> tags, List<string> warnings)
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
        var sectionHeadersOffset = optionalHeaderOffset + optionalHeaderSize;

        var sections = ReadSections(reader, sectionHeadersOffset, sectionCount, fileLength, tags, warnings);
        var architecture = DescribeArchitecture(machine, optionalMagic);
        var subsystemText = DescribeSubsystem(subsystem);
        AddPeTags(optionalMagic, subsystemText, sections, tags);

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
    private static List<PeSectionInfo> ReadSections(BinaryReader reader, long sectionHeadersOffset, int sectionCount, long fileLength, SortedSet<string> tags, List<string> warnings)
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

        if (ContainsAny(trimmed, "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "reg.exe", "schtasks", "Run\\", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
        {
            interestingStrings.Add(trimmed);
            tags.Add("interesting_string");
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
}
