using System.Text.Json.Serialization;

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

    /// <summary>
    /// Requested bounded analysis window in seconds. A value of 0 is allowed
    /// only when <see cref="DurationUnlimited"/> is true and represents the
    /// Web/API "no runtime limit" intent.
    /// </summary>
    public int DurationSeconds { get; init; } = 120;

    /// <summary>
    /// True when the operator explicitly requested no Web/API runtime cap for
    /// this sample. The host still may require an external cancellation path or
    /// infrastructure-level guard; this flag preserves the request semantics.
    /// </summary>
    public bool DurationUnlimited { get; init; }

    /// <summary>
    /// Optional per-job timeout for establishing the guest PowerShell session
    /// after VM startup. Applies equally to PowerShell Direct and WinRM.
    /// </summary>
    public int? GuestReadyTimeoutSeconds { get; init; }

    public bool DryRun { get; init; } = true;

    public VirtualizationProvider? Provider { get; init; }

    public string? GoldenVmName { get; init; }

    public string? GoldenSnapshotName { get; init; }

    /// <summary>
    /// Optional provider machine definition for this job. VMware interprets
    /// this as a VMX path and QEMU as a disk image path; Hyper-V continues to
    /// identify the target through <see cref="GoldenVmName"/>.
    /// </summary>
    public string? MachineDefinitionPath { get; init; }

    /// <summary>
    /// Optional QEMU disk format paired with <see cref="MachineDefinitionPath"/>.
    /// Ignored by the Hyper-V and VMware providers.
    /// </summary>
    public string? QemuDiskFormat { get; init; }

    public string? GuestUserName { get; init; }

    public string? GuestWorkingDirectory { get; init; }

    public string? GuestPayloadRoot { get; init; }

    public bool? UseMockCollector { get; init; }

    public bool? CollectDroppedFiles { get; init; }

    public bool? CaptureScreenshots { get; init; }

    public bool? CaptureMemoryDumps { get; init; }

    public bool? CapturePacketCapture { get; init; }
}

/// <summary>
/// Stores stable file identity for the submitted sample.
/// Inputs are read from the host filesystem, processing hashes the file with
/// common malware-analysis digests, and the record is returned in job metadata
/// and reports.
/// </summary>
public sealed record SampleIdentity
{
    public required string FileName { get; init; }

    public required string FullPath { get; init; }

    public required string Sha256 { get; init; }

    public required string Sha1 { get; init; }

    public required string Md5 { get; init; }

    public required string Crc32 { get; init; }

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
/// Carries unclassified events for the WebUI live monitor.
/// Inputs are already-normalized SandboxEvent records from host reports or
/// guest JSON/JSONL files, processing applies only ordering and paging, and the
/// record is returned to browsers without running behavior rules.
/// </summary>
public sealed record LiveEventSnapshot
{
    public required Guid JobId { get; init; }

    public DateTimeOffset RetrievedAt { get; init; } = DateTimeOffset.UtcNow;

    public int TotalEvents { get; init; }

    public int NextOffset { get; init; }

    public bool HasMore { get; init; }

    public List<string> Sources { get; init; } = [];

    public List<SandboxEvent> Events { get; init; } = [];
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

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TitleZh { get; init; }

    public string Severity { get; init; } = "info";

    public string Confidence { get; init; } = "medium";

    public string? MitreTechniqueId { get; init; }

    public string? MitreTechniqueName { get; init; }

    public string Summary { get; init; } = string.Empty;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SummaryZh { get; init; }

    public List<string> Tags { get; init; } = [];

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

    public VirtualizationProvider? Provider { get; init; }

    /// <summary>
    /// Effective provider VM target used for this analysis. Older reports leave
    /// this null because they predate provider resource identity persistence.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetVmName { get; init; }

    /// <summary>
    /// Effective clean checkpoint, snapshot, or overlay baseline selected by the
    /// provider for this analysis.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BaselineName { get; init; }

    /// <summary>
    /// Effective VMware VMX or QEMU base-disk path. Hyper-V reports normally
    /// leave this null because the VM name identifies the managed resource.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MachineDefinitionPath { get; init; }

    /// <summary>
    /// Effective QEMU base-disk format, or null for other providers.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? QemuDiskFormat { get; init; }

    public required SampleIdentity Sample { get; init; }

    public DateTimeOffset GeneratedAt { get; init; } = DateTimeOffset.UtcNow;

    public AnalysisStatus Status { get; init; } = AnalysisStatus.Planned;

    public StaticAnalysisResult? StaticAnalysis { get; init; }

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

    public string? HtmlReportZhPath { get; init; }

    public string? HtmlReportEnPath { get; init; }

    public string? RunbookExecutionResultPath { get; init; }

    public string? GuestEventsPath { get; init; }

    public List<string> Messages { get; init; } = [];
}
