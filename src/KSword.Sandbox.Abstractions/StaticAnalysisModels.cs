namespace KSword.Sandbox.Abstractions;

/// <summary>
/// Static-analysis metadata for one submitted file.
/// Inputs are collected from the host filesystem before VM execution,
/// processing parses lightweight PE metadata and strings, and the record is
/// returned in JSON and HTML reports.
/// </summary>
public sealed record StaticAnalysisResult
{
    public string FileFormat { get; init; } = "unknown";

    public string Magic { get; init; } = "unknown";

    public bool IsPe { get; init; }

    public string? Architecture { get; init; }

    public string? Machine { get; init; }

    public string? Subsystem { get; init; }

    public string? EntryPointRva { get; init; }

    public int SectionCount { get; init; }

    public List<PeSectionInfo> Sections { get; init; } = [];

    public List<string> Tags { get; init; } = [];

    public List<string> Urls { get; init; } = [];

    public List<string> InterestingStrings { get; init; } = [];

    public List<string> Warnings { get; init; } = [];
}

/// <summary>
/// PE section summary used by static analysis reports.
/// Inputs are parsed from IMAGE_SECTION_HEADER entries, processing calculates
/// entropy when raw bytes are available, and the record is returned as report
/// evidence.
/// </summary>
public sealed record PeSectionInfo
{
    public required string Name { get; init; }

    public string VirtualAddress { get; init; } = "0x0";

    public long VirtualSize { get; init; }

    public long RawDataSize { get; init; }

    public double Entropy { get; init; }
}
