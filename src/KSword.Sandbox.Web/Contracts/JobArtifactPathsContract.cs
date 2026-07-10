namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: report, runbook, guest, and driver artifact paths associated with a
/// sandbox job.
/// Processing: keeps operator-facing path names stable for dashboard and API
/// clients without exposing arbitrary host path selection.
/// Return behavior: instances are serialized as the copyable artifact path
/// block for a job experience view.
/// </summary>
/// <param name="ReportJsonPath">Path to report.json.</param>
/// <param name="ReportHtmlPath">Path to report.html.</param>
/// <param name="EventsJsonPath">Expected or recorded guest events.json path.</param>
/// <param name="DriverEventsJsonlPath">Expected or recorded driver-events.jsonl path.</param>
/// <param name="RunbookExecutionResultPath">Path to runbook-execution.json.</param>
/// <param name="GuestImportSourcePath">Actual source path used by guest import when known.</param>
public sealed record JobArtifactPathsContract(
    string? ReportJsonPath,
    string? ReportHtmlPath,
    string? EventsJsonPath,
    string? DriverEventsJsonlPath,
    string? RunbookExecutionResultPath,
    string? GuestImportSourcePath);
