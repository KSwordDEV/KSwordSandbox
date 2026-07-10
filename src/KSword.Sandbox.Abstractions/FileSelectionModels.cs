namespace KSword.Sandbox.Abstractions;

/// <summary>
/// Request model for scanning one host file or directory for executable targets.
/// Inputs are supplied by the local WebUI, processing bounds recursion and
/// result count on the host, and the response returns candidate executables.
/// </summary>
public sealed record ExecutableScanRequest
{
    public required string Path { get; init; }

    public int MaxDepth { get; init; } = 4;

    public int MaxResults { get; init; } = 200;
}

/// <summary>
/// Describes one executable candidate discovered on the host filesystem.
/// Inputs are file metadata from a scan, processing normalizes the absolute
/// path, and the record is returned to the WebUI for user selection.
/// </summary>
public sealed record ExecutableCandidate
{
    public required string FileName { get; init; }

    public required string FullPath { get; init; }

    public long SizeBytes { get; init; }

    public DateTimeOffset LastWriteTimeUtc { get; init; }
}

/// <summary>
/// Response model for executable target scanning.
/// Inputs are scan results and warning messages, processing sorts candidates
/// deterministically, and the record is returned by the scan API.
/// </summary>
public sealed record ExecutableScanResult
{
    public required string RootPath { get; init; }

    public bool RootIsFile { get; init; }

    public List<ExecutableCandidate> Candidates { get; init; } = [];

    public List<string> Warnings { get; init; } = [];
}
