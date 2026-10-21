using System;
using System.Buffers.Binary;
using System.Text;

namespace KSword.Sandbox.Core.Reporting;

/// <summary>
/// Minimal self-contained PE (Portable Executable) parser used by the report
/// pipeline to describe dropped executables and the analyzed sample. Inputs
/// are file bytes or a path; processing reads DOS/PE headers, the section
/// table, the import directory, and the security directory without any
/// third-party library; the record is returned for report rendering and
/// artifact-index enrichment.
/// </summary>
public sealed record PeFileSectionInfo
{
    public string Name { get; init; } = string.Empty;
    public long VirtualSize { get; init; }
    public long RawSize { get; init; }
    public double Entropy { get; init; }
}

public sealed record PeFileInfo
{
    public bool IsPe { get; init; }
    public string Error { get; init; } = string.Empty;
    public string Machine { get; init; } = string.Empty;
    public string Subsystem { get; init; } = string.Empty;
    public DateTimeOffset? CompileTimestampUtc { get; init; }
    public long EntryPointRva { get; init; }
    public long ImageBase { get; init; }
    public bool Is64Bit { get; init; }
    public bool HasSignature { get; init; }
    public IReadOnlyList<PeFileSectionInfo> Sections { get; init; } = [];
    public IReadOnlyList<string> ImportDlls { get; init; } = [];
}

public static class PeFileInfoParser
{
    private const ushort DosMagic = 0x5A4D; // "MZ"
    private const uint PeMagic = 0x00004550; // "PE\0\0"
    private const int MaxFileBytes = 64 * 1024 * 1024;

    public static bool LooksLikePe(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (stream.Length < 0x40)
            {
                return false;
            }

            Span<byte> buffer = stackalloc byte[2];
            return stream.Read(buffer) == 2 && BinaryPrimitives.ReadUInt16LittleEndian(buffer) == DosMagic;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    public static PeFileInfo Parse(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
            {
                return new PeFileInfo { Error = "file-not-found" };
            }

            if (file.Length > MaxFileBytes)
            {
                return new PeFileInfo { Error = "file-too-large" };
            }

            return Parse(File.ReadAllBytes(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return new PeFileInfo { Error = ex.GetType().Name };
        }
    }

    public static PeFileInfo Parse(byte[] bytes)
    {
        try
        {
            return ParseCore(bytes);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException)
        {
            return new PeFileInfo { Error = ex.GetType().Name };
        }
    }

    private static PeFileInfo ParseCore(byte[] bytes)
    {
        if (bytes.Length < 0x40 || BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(0, 2)) != DosMagic)
        {
            return new PeFileInfo { Error = "not-pe" };
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C, 4));
        if (peOffset < 0 || peOffset + 24 > bytes.Length ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(peOffset, 4)) != PeMagic)
        {
            return new PeFileInfo { Error = "bad-pe-signature" };
        }

        var coff = peOffset + 4;
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff, 2));
        var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 2, 2));
        var timestamp = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(coff + 4, 4));
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 16, 2));

        var optional = coff + 20;
        if (optional + optionalSize > bytes.Length || optionalSize < 96)
        {
            return new PeFileInfo { Error = "bad-optional-header", Machine = MachineName(machine) };
        }

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optional, 2));
        var is64 = magic == 0x20B;
        if (magic != 0x10B && !is64)
        {
            return new PeFileInfo { Error = "unknown-optional-magic", Machine = MachineName(machine) };
        }

        var entryPoint = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(optional + 16, 4));
        long imageBase = is64
            ? BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(optional + 24, 8))
            : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(optional + 28, 4));
        var subsystem = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optional + 68, 2));

        // Data directories: 16 entries; index 1 = import, index 4 = security.
        var directoryCountOffset = optional + (is64 ? 108 : 92);
        var directoryOffset = optional + (is64 ? 112 : 96);
        var dirCount = directoryCountOffset + 4 <= bytes.Length
            ? BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(directoryCountOffset, 4))
            : 0;
        (long importRva, long importSize) = Directory(dirCount, 1);
        (long securityRva, long securitySize) = Directory(dirCount, 4);

        var sections = new List<PeFileSectionInfo>(Math.Min((int)sectionCount, 96));
        var sectionTable = optional + optionalSize;
        long imageSize = 0;
        for (var i = 0; i < sectionCount && sectionTable + 40 <= bytes.Length; i++, sectionTable += 40)
        {
            var nameBytes = bytes.AsSpan(sectionTable, 8);
            var nul = nameBytes.IndexOf((byte)0);
            var name = Encoding.ASCII.GetString(nul >= 0 ? nameBytes[..nul] : nameBytes);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(sectionTable + 8, 4));
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(sectionTable + 16, 4));
            var rawOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(sectionTable + 20, 4));
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(sectionTable + 12, 4));
            imageSize = Math.Max(imageSize, (long)virtualAddress + virtualSize);
            double entropy = 0;
            if (rawSize > 0 && rawOffset >= 0 && rawOffset + rawSize <= bytes.Length)
            {
                entropy = ShannonEntropy(bytes, rawOffset, (int)Math.Min(rawSize, int.MaxValue));
            }

            sections.Add(new PeFileSectionInfo
            {
                Name = name,
                VirtualSize = virtualSize,
                RawSize = rawSize,
                Entropy = entropy,
            });
        }

        var importDlls = ReadImportDlls(bytes, importRva, importSize, sections);

        DateTimeOffset? compiled = null;
        if (timestamp > 0)
        {
            try
            {
                compiled = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero).AddSeconds(timestamp);
            }
            catch (ArgumentOutOfRangeException)
            {
                compiled = null;
            }
        }

        // Security directory (file offset, not RVA) present => signed.
        var hasCertificateTable = securitySize > 0 && securityRva > 0 &&
                                  securityRva + securitySize <= bytes.Length;
        return new PeFileInfo
        {
            IsPe = true,
            Machine = MachineName(machine),
            Subsystem = SubsystemName(subsystem),
            CompileTimestampUtc = compiled,
            EntryPointRva = entryPoint,
            ImageBase = imageBase,
            Is64Bit = is64,
            HasSignature = hasCertificateTable,
            Sections = sections,
            ImportDlls = importDlls,
        };

        (long Rva, long Size) Directory(int count, int index)
        {
            if (index >= count)
            {
                return (0, 0);
            }

            var offset = directoryOffset + index * 8;
            if (offset + 8 > bytes.Length)
            {
                return (0, 0);
            }

            return (
                BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4)),
                BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset + 4, 4)));
        }
    }

    private static IReadOnlyList<string> ReadImportDlls(
        byte[] bytes,
        long importRva,
        long importSize,
        IReadOnlyList<PeFileSectionInfo> sections)
    {
        var names = new List<string>();
        if (importRva <= 0 || importSize < 20)
        {
            return names;
        }

        // The descriptor loop needs RVA→file-offset translation via sections.
        // Sections record raw addresses only in the full header pass, so do a
        // cheap re-walk of the section table here using stored values.
        // To keep this parser minimal we re-derive offsets from the PE header.
        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C, 4));
        var coff = peOffset + 4;
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 16, 2));
        var optional = coff + 20;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optional, 2));
        var is64 = magic == 0x20B;
        var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 2, 2));
        var sectionTable = optional + optionalSize;
        var ranges = new List<(long Va, long VSize, long RawOffset, long RawSize)>();
        for (var i = 0; i < sectionCount && sectionTable + 40 <= bytes.Length; i++, sectionTable += 40)
        {
            var vsize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(sectionTable + 8, 4));
            var va = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(sectionTable + 12, 4));
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(sectionTable + 16, 4));
            var rawOffset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(sectionTable + 20, 4));
            ranges.Add((va, vsize, rawOffset, rawSize));
        }

        long RvaToOffset(long rva)
        {
            foreach (var (va, vsize, rawOffset, rawSize) in ranges)
            {
                var span = Math.Max(vsize, rawSize);
                if (rva >= va && rva < va + span)
                {
                    return rawOffset + (rva - va);
                }
            }

            return rva < bytes.Length ? rva : -1;
        }

        try
        {
            var descriptorOffset = RvaToOffset(importRva);
            if (descriptorOffset < 0)
            {
                return names;
            }

            const int descriptorSize = 20;
            for (var d = 0; d < 512; d++)
            {
                var offset = descriptorOffset + d * descriptorSize;
                if (offset + descriptorSize > bytes.Length)
                {
                    break;
                }

                var originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)offset, 4));
                var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)offset + 12, 4));
                if (originalFirstThunk == 0 && nameRva == 0)
                {
                    break;
                }

                if (nameRva == 0)
                {
                    continue;
                }

                var nameOffset = RvaToOffset(nameRva);
                if (nameOffset < 0 || nameOffset >= bytes.Length)
                {
                    continue;
                }

                var end = Array.IndexOf(bytes, (byte)0, (int)nameOffset);
                if (end < 0 || end - nameOffset > 260)
                {
                    continue;
                }

                names.Add(Encoding.ASCII.GetString(bytes, (int)nameOffset, end - (int)nameOffset));
            }
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException)
        {
            // Partial imports still beat none; keep whatever was read.
        }

        return names;
    }

    private static double ShannonEntropy(byte[] bytes, int offset, int length)
    {
        var counts = new int[256];
        var end = Math.Min(bytes.Length, offset + length);
        for (var i = offset; i < end; i++)
        {
            counts[bytes[i]]++;
        }

        var total = (double)(end - offset);
        if (total <= 0)
        {
            return 0;
        }

        var entropy = 0.0;
        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            var p = count / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static string MachineName(ushort machine) => machine switch
    {
        0x014C => "x86 (I386)",
        0x0200 => "IA64",
        0x8664 => "x64 (AMD64)",
        0x01C0 => "ARM",
        0x01C4 => "ARMv7",
        0xAA64 => "ARM64",
        _ => $"0x{machine:X4}",
    };

    private static string SubsystemName(ushort subsystem) => subsystem switch
    {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows Console",
        5 => "OS/2 Console",
        7 => "POSIX Console",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service",
        12 => "EFI Runtime",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows Boot Application",
        _ => $"0x{subsystem:X4}",
    };
}
