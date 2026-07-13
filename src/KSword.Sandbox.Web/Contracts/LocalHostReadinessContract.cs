namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Read-only local host facts shown by the WebUI before a VM job is submitted.
/// Inputs come from the active sandbox config, host filesystem, environment,
/// and a bounded Hyper-V inventory query; processing never mutates a VM or
/// writes probe files; the contract returns only non-secret readiness data.
/// </summary>
public sealed record LocalHostReadinessContract(
    DateTimeOffset DetectedAtUtc,
    string MachineName,
    string OperatingSystem,
    bool IsElevated,
    bool ReadOnly,
    LocalHyperVReadinessContract HyperV,
    LocalGuestReadinessContract Guest,
    LocalPathReadinessContract Paths);

/// <summary>
/// Read-only Hyper-V inventory and safe automatic selection result.
/// Configured names are included only as comparison metadata and are never
/// returned as detected values unless the local Hyper-V query confirms them.
/// </summary>
public sealed record LocalHyperVReadinessContract(
    bool ManagementAvailable,
    bool QuerySucceeded,
    bool AccessDenied,
    string ConfiguredVmName,
    string? VmName,
    string VmSource,
    string? VmState,
    bool VmExists,
    string ConfiguredCheckpointName,
    string? CheckpointName,
    string CheckpointSource,
    bool CheckpointExists,
    IReadOnlyList<LocalVmCandidateContract> VmCandidates,
    string DiagnosticCode,
    string DiagnosticMessage);

/// <summary>
/// One locally enumerated VM and its read-only checkpoint inventory.
/// </summary>
public sealed record LocalVmCandidateContract(
    string Name,
    string State,
    IReadOnlyList<string> Checkpoints,
    string? CheckpointDiagnostic);

/// <summary>
/// Guest metadata that cannot be inferred safely from an offline host VM.
/// Values are therefore explicitly labeled as config-derived, while secret
/// readiness checks only presence and never returns the secret value.
/// </summary>
public sealed record LocalGuestReadinessContract(
    string UserName,
    string UserNameSource,
    string WorkingDirectory,
    string WorkingDirectorySource,
    string PasswordSecretName,
    bool PasswordSecretAvailable,
    string PasswordSecretSource);

/// <summary>
/// Local filesystem facts used by VM job staging.
/// </summary>
public sealed record LocalPathReadinessContract(
    LocalPathFactContract RuntimeRoot,
    LocalPathFactContract GuestPayloadRoot,
    LocalPathFactContract PayloadManifest,
    LocalPathFactContract AgentExecutable,
    LocalPathFactContract CollectorExecutable,
    LocalPathFactContract BaseVhdx);

/// <summary>
/// One configured host path plus its actual read-only existence result.
/// </summary>
public sealed record LocalPathFactContract(
    string? Path,
    bool Configured,
    bool Exists,
    string Kind,
    string Source);
