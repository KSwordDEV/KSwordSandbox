namespace KSword.Sandbox.Abstractions.HyperV;

/// <summary>
/// Describes one guest command before it is translated into runbook steps.
/// Inputs are VM and command metadata, processing preserves intent and state
/// mutation flags, and the record is returned to runbook composition layers.
/// </summary>
public sealed record GuestCommandPlan
{
    public string VmName { get; init; } = string.Empty;

    public string GuestWorkingDirectory { get; init; } = string.Empty;

    public string PowerShell { get; init; } = string.Empty;

    public bool MutatesState { get; init; } = true;
}
