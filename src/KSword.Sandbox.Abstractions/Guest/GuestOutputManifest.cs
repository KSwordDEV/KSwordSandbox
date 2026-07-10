namespace KSword.Sandbox.Abstractions.Guest;

/// <summary>
/// Maps guest output paths to their host-side collection directory.
/// Inputs are produced by host path planning, processing keeps job-specific
/// output paths, and the record is returned to runbook builders and importers.
/// </summary>
public sealed record GuestOutputManifest
{
    public Guid JobId { get; init; }

    public string GuestOutputDirectory { get; init; } = string.Empty;

    public string HostOutputDirectory { get; init; } = string.Empty;

    public string EventsJsonPath { get; init; } = string.Empty;

    public string? DriverJsonLinesPath { get; init; }
}
