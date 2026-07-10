namespace KSword.Sandbox.Abstractions;

/// <summary>
/// Describes the lifecycle state of a sandbox job.
/// Inputs are state transitions from the host scheduler, processing is simple
/// enum storage, and the value is returned to API clients and reports.
/// </summary>
public enum AnalysisStatus
{
    Queued,
    Planning,
    Planned,
    Running,
    Completed,
    Failed
}

/// <summary>
/// Captures a user request to analyze one executable inside the guest VM.
/// Inputs are supplied by the Web API, processing validates the local path and
/// duration, and the record is returned as part of each planned job.
/// </summary>
public sealed record SandboxSubmission
{
    public required string SamplePath { get; init; }

    public string? DisplayName { get; init; }

    public int DurationSeconds { get; init; } = 120;

    public bool DryRun { get; init; } = true;
}

/// <summary>
/// Stores stable file identity for the submitted sample.
/// Inputs are read from the host filesystem, processing hashes the file with
/// SHA-256, and the record is returned in job metadata and reports.
/// </summary>
public sealed record SampleIdentity
{
    public required string FileName { get; init; }

    public required string FullPath { get; init; }

    public required string Sha256 { get; init; }

    public long SizeBytes { get; init; }
}

/// <summary>
/// Represents one normalized behavior event collected by the guest agent or
/// host orchestration layer. Inputs are raw driver, agent, or host events;
/// processing normalizes common fields; the record is returned to the rule
/// engine, JSON output, and HTML report renderer.
/// </summary>
public sealed record SandboxEvent
{
    public required string EventType { get; init; }

    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    public string Source { get; init; } = "host";

    public string? ProcessName { get; init; }

    public int? ProcessId { get; init; }

    public int? ParentProcessId { get; init; }

    public string? Path { get; init; }

    public string? CommandLine { get; init; }

    public Dictionary<string, string> Data { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Describes one rule hit after event classification.
/// Inputs are normalized sandbox events and behavior rules, processing keeps
/// matching evidence, and the record is returned to JSON and HTML reports.
/// </summary>
public sealed record BehaviorFinding
{
    public required string RuleId { get; init; }

    public required string Title { get; init; }

    public string Severity { get; init; } = "info";

    public string? MitreTechniqueId { get; init; }

    public string? MitreTechniqueName { get; init; }

    public string Summary { get; init; } = string.Empty;

    public List<SandboxEvent> Evidence { get; init; } = [];
}

/// <summary>
/// Contains the final report model for one analysis job.
/// Inputs are job metadata, normalized events, and behavior findings;
/// processing calculates simple counts; the record is returned to the report
/// store and Web API.
/// </summary>
public sealed record AnalysisReport
{
    public required Guid JobId { get; init; }

    public required SampleIdentity Sample { get; init; }

    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    public AnalysisStatus Status { get; init; } = AnalysisStatus.Planned;

    public List<SandboxEvent> Events { get; init; } = [];

    public List<BehaviorFinding> Findings { get; init; } = [];

    public Dictionary<string, int> Metrics { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Tracks host-side job metadata and generated artifacts.
/// Inputs are produced by the job service, processing appends messages and
/// artifacts as planning advances, and the record is returned by the API.
/// </summary>
public sealed record AnalysisJob
{
    public required Guid JobId { get; init; }

    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    public required SandboxSubmission Submission { get; init; }

    public AnalysisStatus Status { get; init; } = AnalysisStatus.Queued;

    public SampleIdentity? Sample { get; init; }

    public SandboxRunbook? Runbook { get; init; }

    public string? JsonReportPath { get; init; }

    public string? HtmlReportPath { get; init; }

    public List<string> Messages { get; init; } = [];
}
