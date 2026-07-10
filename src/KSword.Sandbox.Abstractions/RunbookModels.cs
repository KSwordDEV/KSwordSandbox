namespace KSword.Sandbox.Abstractions;

/// <summary>
/// A single host operation needed to prepare, run, or clean a VM analysis.
/// Inputs are generated from typed configuration, processing formats a
/// PowerShell command, and the step is returned in the runbook plan.
/// </summary>
public sealed record SandboxRunbookStep
{
    public required string Id { get; init; }

    public required string Title { get; init; }

    public required string PowerShell { get; init; }

    public bool RequiresElevation { get; init; } = true;

    public bool MutatesVmState { get; init; } = true;
}

/// <summary>
/// Ordered command plan for one analysis job.
/// Inputs are job, sample, and configuration data; processing emits a
/// deterministic sequence of Hyper-V and PowerShell Direct operations; the
/// runbook is returned to the Web API and report artifacts.
/// </summary>
public sealed record SandboxRunbook
{
    public required Guid JobId { get; init; }

    public required string TargetVmName { get; init; }

    public bool UsesTemporaryVm { get; init; }

    public List<SandboxRunbookStep> Steps { get; init; } = [];
}
