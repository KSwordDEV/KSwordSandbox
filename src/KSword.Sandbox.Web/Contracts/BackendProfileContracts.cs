using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Local-only provider profile submitted by the first-run setup page. Passwords
/// are intentionally excluded; the existing guest secret environment variable
/// remains the only credential source.
/// </summary>
public sealed record BackendProfileUpdateRequest
{
    public VirtualizationProvider Provider { get; init; } = VirtualizationProvider.VMware;

    public string VmName { get; init; } = string.Empty;

    public string VmxPath { get; init; } = string.Empty;

    public string SnapshotName { get; init; } = "Clean";

    public string VmrunPath { get; init; } = "vmrun.exe";

    public GuestRemotingAddressMode AddressMode { get; init; } = GuestRemotingAddressMode.VMwareTools;

    public string? Address { get; init; }

    public string Authentication { get; init; } = "Negotiate";

    public int Port { get; init; } = 5986;

    public bool UseSsl { get; init; } = true;

    public bool SkipCertificateChecks { get; init; } = true;
}

public sealed record BackendProfileResponse
(
    string ConfigPath,
    bool ConfigExists,
    SandboxConfig Config,
    bool RestartRequired);

public sealed record GuestSecretUpdateRequest
{
    public string? Password { get; init; }

    public bool Clear { get; init; }
}
