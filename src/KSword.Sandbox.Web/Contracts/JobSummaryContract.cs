namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: job identity, display fields, state, optional report path, and lifecycle timestamps.
/// Processing: flattens job data for list and detail views without exposing internal job entities.
/// Return behavior: instances are serialized as job summary payloads.
/// </summary>
/// <param name="JobId">Unique job identifier supplied by the job service.</param>
/// <param name="DisplayName">Caller-facing job name or executable name.</param>
/// <param name="State">Machine-readable job state.</param>
/// <param name="HtmlReportPath">Optional HTML report path recorded for the job.</param>
/// <param name="CreatedAtUtc">Optional UTC timestamp when the job was created.</param>
/// <param name="CompletedAtUtc">Optional UTC timestamp when the job completed.</param>
public sealed record JobSummaryContract(
    Guid JobId,
    string DisplayName,
    string State,
    string? HtmlReportPath,
    DateTimeOffset? CreatedAtUtc,
    DateTimeOffset? CompletedAtUtc)
{
    /// <summary>
    /// Full artifact path set used by the dashboard when the summary is shown
    /// as the latest job card.
    /// </summary>
    public JobArtifactPathsContract? ArtifactPaths { get; init; }

    /// <summary>
    /// Guest event import status shown beside report and telemetry paths.
    /// </summary>
    public GuestImportStatusContract? GuestImportStatus { get; init; }
}
