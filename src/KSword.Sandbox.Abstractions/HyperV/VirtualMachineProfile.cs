namespace KSword.Sandbox.Abstractions.HyperV;

/// <summary>
/// Describes the golden or temporary VM used by an analysis job.
/// Inputs are resolved from configuration and job planning, processing stores
/// VM identity and disk mode, and the record is returned to orchestration code.
/// </summary>
public sealed record VirtualMachineProfile
{
    public string VmName { get; init; } = string.Empty;

    public string? SnapshotName { get; init; }

    public string? SwitchName { get; init; }

    public bool UsesDifferencingDisk { get; init; }

    public string? VhdxPath { get; init; }
}
