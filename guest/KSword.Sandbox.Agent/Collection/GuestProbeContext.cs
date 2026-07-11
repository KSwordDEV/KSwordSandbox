namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Carries run-specific context into guest probes.
/// Inputs are parsed agent options and sample execution state; processing stores
/// immutable paths, phase metadata, and optional root process identifiers; the
/// record is returned to probe implementations through GuestProbeRunner.
/// </summary>
internal sealed record GuestProbeContext
{
    public required string SamplePath { get; init; }

    public required string WorkingDirectory { get; init; }

    public required string OutputDirectory { get; init; }

    public int? RootProcessId { get; init; }

    public int? RootParentProcessId { get; init; }

    public string? RootProcessName { get; init; }

    public string? RootProcessPath { get; init; }

    public string? RootCommandLine { get; init; }

    public DateTime? RootProcessStartTimeUtc { get; init; }

    public bool CaptureScreenshots { get; init; }

    public bool CaptureMemoryDump { get; init; }

    public bool CapturePacketCapture { get; init; }
}
