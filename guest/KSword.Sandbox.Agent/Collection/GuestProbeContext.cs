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

    /// <summary>
    /// Indicates that the agent has observed the launched root process exit.
    /// This lets process-tree probes distinguish an exited process that raced
    /// the first snapshot from a live process that the snapshot failed to
    /// capture.
    /// </summary>
    public bool RootProcessExitObserved { get; init; }

    public bool CaptureScreenshots { get; init; }

    public bool CollectDroppedFiles { get; init; }

    public bool CaptureMemoryDump { get; init; }

    public bool CapturePacketCapture { get; init; }

    /// <summary>
    /// Enables the explicit opt-in Windows logman kernel ETW trace.  The
    /// resulting ETL is raw evidence and must be decoded before behavior
    /// counting; false means the probe emits an explicit disabled row.
    /// </summary>
    public bool CaptureEtwLiveTrace { get; init; }
}
