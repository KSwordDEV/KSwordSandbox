using KSword.Sandbox.Abstractions;

internal sealed class JobToolOptions
{
    public Dictionary<string, string> Values { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> Flags { get; } = new(StringComparer.OrdinalIgnoreCase);
}

internal sealed record ToolContext(
    string RepositoryRoot,
    string ConfigPath,
    SandboxConfig Config);

internal sealed record JobLocator(
    Guid JobId,
    string JobRoot);

internal sealed class JobSummary
{
    public bool IsCandidate { get; init; }

    public Guid? JobId { get; init; }

    public string JobRoot { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public string SampleName { get; init; } = string.Empty;

    public string? SamplePath { get; init; }

    public string? SampleSha256 { get; init; }

    public string? JsonReportPath { get; init; }

    public string? HtmlReportPath { get; init; }

    public string? GuestEventsPath { get; init; }

    public string? RunbookExecutionPath { get; init; }

    public string? RunbookProgressPath { get; init; }

    public string? GuestOutputSkeletonPath { get; init; }

    public string? StartResultPath { get; init; }

    public string? CollectResultPath { get; init; }

    public string? ReportRebuildDiagnosticsPath { get; init; }

    public int? ReportEventCount { get; init; }

    public int? FindingCount { get; init; }

    public int? ArtifactCount { get; init; }

    public int? CollectionCount { get; init; }

    public DateTimeOffset? LastWriteUtc { get; init; }

    public List<string> MissingKeyArtifacts { get; init; } = [];

    public Dictionary<string, int> Metrics { get; init; } = [];
}

internal sealed class EventInputResolution
{
    public string Path { get; init; } = string.Empty;

    public string Source { get; init; } = string.Empty;

    public bool CreatedFailureSkeleton { get; init; }

    public int CandidateCount { get; init; }

    public List<string> CandidatePaths { get; init; } = [];

    public string Message { get; init; } = string.Empty;

    public List<string> RemediationHints { get; init; } = [];
}

internal sealed class ReadinessCheck
{
    public string CheckId { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public bool Required { get; init; }

    public string Message { get; init; } = string.Empty;

    public Dictionary<string, object?> Details { get; init; } = [];

    public List<string> RemediationHints { get; init; } = [];

    public static ReadinessCheck Passed(string checkId, string name, bool required, string message, Dictionary<string, object?>? details = null)
    {
        return new ReadinessCheck
        {
            CheckId = checkId,
            Name = name,
            Status = "Passed",
            Required = required,
            Message = message,
            Details = details ?? []
        };
    }

    public static ReadinessCheck Warning(string checkId, string name, bool required, string message, Dictionary<string, object?>? details = null, IEnumerable<string>? remediationHints = null)
    {
        return new ReadinessCheck
        {
            CheckId = checkId,
            Name = name,
            Status = "Warning",
            Required = required,
            Message = message,
            Details = details ?? [],
            RemediationHints = remediationHints?.ToList() ?? []
        };
    }

    public static ReadinessCheck Failed(string checkId, string name, bool required, string message, Dictionary<string, object?>? details = null, IEnumerable<string>? remediationHints = null)
    {
        return new ReadinessCheck
        {
            CheckId = checkId,
            Name = name,
            Status = "Failed",
            Required = required,
            Message = message,
            Details = details ?? [],
            RemediationHints = remediationHints?.ToList() ?? []
        };
    }
}

internal sealed class RecoveryResultFile
{
    public string Name { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public bool Exists { get; init; }

    public bool? Success { get; init; }

    public string State { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string FailureReason { get; init; } = string.Empty;

    public List<string> RemediationHints { get; init; } = [];
}

internal sealed class RecoveryAssessment
{
    public string State { get; init; } = string.Empty;

    public bool HasBlockingFailure { get; init; }

    public string FailureReason { get; init; } = string.Empty;

    public List<string> RecommendedActions { get; init; } = [];
}
