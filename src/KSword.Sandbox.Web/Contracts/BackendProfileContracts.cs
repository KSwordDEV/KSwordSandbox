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

    public string GuestUserName { get; init; } = "SandboxUser";

    public string GuestWorkingDirectory { get; init; } = "C:\\KSwordSandbox";

    public string QemuSystemPath { get; init; } = "qemu-system-x86_64.exe";
    public string QemuImgPath { get; init; } = "qemu-img.exe";
    public string DiskImagePath { get; init; } = string.Empty;
    public string DiskFormat { get; init; } = "qcow2";
    public string DiskInterface { get; init; } = "virtio";
    public bool UseOverlayDisk { get; init; } = true;
    public int MemoryMegabytes { get; init; } = 4096;
    public List<string> AdditionalArguments { get; init; } = ["-accel", "whpx"];
    public bool Headless { get; init; }
    public bool DriverEnabled { get; init; } = true;
    public bool UseMockCollector { get; init; }
    public string? HostDriverPath { get; init; }
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
