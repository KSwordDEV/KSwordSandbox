namespace KSword.Sandbox.Abstractions.Artifacts;

/// <summary>
/// Classifies durable files produced by one sandbox job.
/// Inputs are selected by artifact writers, processing uses enum values instead
/// of fragile strings, and the value is returned in manifests and APIs.
/// </summary>
public enum ArtifactKind
{
    Unknown = 0,
    ArtifactManifest,
    ReportJson,
    ReportHtml,
    RunbookJson,
    RunbookExecutionJson,
    GuestEventsJson,
    GuestSummaryJson,
    DroppedFile,
    DriverEventsJsonLines,
    StaticAnalysisJson,
    Screenshot,
    Log,
    Bundle,
    ArtifactIndex
}
