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

    public List<PeImportModuleInfo> Imports { get; init; } = [];

    public List<PeImportApiClusterInfo> ImportApiClusters { get; init; } = [];

    public string? ExportModuleName { get; init; }

    public List<string> ExportNames { get; init; } = [];

    public PeTlsInfo? Tls { get; init; }

    public PeOverlayInfo? Overlay { get; init; }

    public List<StaticNetworkIndicator> NetworkIndicators { get; init; } = [];

    public List<StaticPathIndicator> PathIndicators { get; init; } = [];

    public List<StaticCommandIndicator> CommandIndicators { get; init; } = [];

    public List<StaticStringFinding> SuspiciousStrings { get; init; } = [];

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

    public string RawDataOffset { get; init; } = "0x0";

    public long VirtualSize { get; init; }

    public long RawDataSize { get; init; }

    public double Entropy { get; init; }

    public string EntropyLabel { get; init; } = "empty";

    public string Characteristics { get; init; } = "0x0";

    public bool IsExecutable { get; init; }

    public bool IsWritable { get; init; }
}

/// <summary>
/// Structured import-table module summary.
/// Inputs are parsed from IMAGE_IMPORT_DESCRIPTOR and thunk entries,
/// processing keeps bounded API/ordinal samples, and the record is returned
/// alongside legacy string evidence for reports and rule enrichment.
/// </summary>
public sealed record PeImportModuleInfo
{
    public required string ModuleName { get; init; }

    public int NamedApiCount { get; init; }

    public int OrdinalImportCount { get; init; }

    public List<string> ApiNames { get; init; } = [];

    public List<string> OrdinalImports { get; init; } = [];

    public List<string> SuspiciousApiNames { get; init; } = [];

    public List<string> SuspiciousApiClusters { get; init; } = [];
}

/// <summary>
/// Rollup for suspicious API families observed in the import table.
/// </summary>
public sealed record PeImportApiClusterInfo
{
    public required string Name { get; init; }

    public int HitCount { get; init; }

    public List<string> ApiNames { get; init; } = [];
}

/// <summary>
/// Structured TLS directory and callback-table evidence.
/// </summary>
public sealed record PeTlsInfo
{
    public bool DirectoryPresent { get; init; }

    public string? CallbackTableVa { get; init; }

    public string? CallbackTableFileOffset { get; init; }

    public List<PeTlsCallbackInfo> Callbacks { get; init; } = [];
}

/// <summary>
/// One TLS callback pointer decoded from IMAGE_TLS_DIRECTORY.
/// </summary>
public sealed record PeTlsCallbackInfo
{
    public required string VirtualAddress { get; init; }

    public string? RelativeVirtualAddress { get; init; }
}

/// <summary>
/// Structured PE overlay summary.
/// </summary>
public sealed record PeOverlayInfo
{
    public bool Present { get; init; }

    public string StartOffset { get; init; } = "0x0";

    public long Size { get; init; }

    public bool ContainsCertificateTable { get; init; }

    public string? CertificateTableOffset { get; init; }

    public long CertificateTableSize { get; init; }

    public bool IsCertificateTableOnly { get; init; }

    public long NonCertificateSize { get; init; }

    public string? LargestNonCertificateOffset { get; init; }

    public long LargestNonCertificateSize { get; init; }

    public double? NonCertificateEntropy { get; init; }
}

/// <summary>
/// Structured URL/IP/email indicator extracted from bounded strings.
/// </summary>
public sealed record StaticNetworkIndicator
{
    public required string Kind { get; init; }

    public required string Value { get; init; }

    public string? Classification { get; init; }
}

/// <summary>
/// Structured filesystem, registry, or environment path indicator.
/// </summary>
public sealed record StaticPathIndicator
{
    public required string Kind { get; init; }

    public required string Value { get; init; }

    public List<string> Tags { get; init; } = [];
}

/// <summary>
/// Structured command-like string, including LOLBIN and script-interpreter
/// evidence suitable for report grouping.
/// </summary>
public sealed record StaticCommandIndicator
{
    public required string Category { get; init; }

    public string? Tool { get; init; }

    public required string Value { get; init; }

    public List<string> Tags { get; init; } = [];
}

/// <summary>
/// Structured suspicious string finding with a stable category name.
/// </summary>
public sealed record StaticStringFinding
{
    public required string Category { get; init; }

    public required string Value { get; init; }

    public List<string> Tags { get; init; } = [];
}
