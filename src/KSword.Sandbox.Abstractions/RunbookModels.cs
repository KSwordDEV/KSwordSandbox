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
/// deterministic sequence of provider lifecycle and guest-session operations;
/// the runbook is returned to the Web API and report artifacts.
/// </summary>
public sealed record SandboxRunbook
{
    public required Guid JobId { get; init; }

    public VirtualizationProvider Provider { get; init; } = VirtualizationProvider.HyperV;

    public required string TargetVmName { get; init; }

    /// <summary>
    /// Effective clean baseline selected by the provider. QEMU overlay mode
    /// reports per-job-overlay because no internal snapshot is restored.
    /// </summary>
    public string? BaselineName { get; init; }

    /// <summary>
    /// Effective provider resource selected for this runbook. VMware stores the
    /// VMX path and QEMU stores the base disk path; Hyper-V leaves it empty.
    /// </summary>
    public string? MachineDefinitionPath { get; init; }

    /// <summary>
    /// Effective QEMU base-disk format, or null for other providers.
    /// </summary>
    public string? QemuDiskFormat { get; init; }

    /// <summary>
    /// Cross-process lease file used to serialize live VM execution within one
    /// runtime root. Dry-run execution never acquires this lease.
    /// </summary>
    public string? LiveExecutionLeasePath { get; init; }

    public bool UsesTemporaryVm { get; init; }

    public List<SandboxRunbookStep> Steps { get; init; } = [];
}
