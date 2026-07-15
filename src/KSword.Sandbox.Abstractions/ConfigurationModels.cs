using System.Text.Json.Serialization;

namespace KSword.Sandbox.Abstractions;

/// <summary>
/// Host hypervisor used to execute sandbox runbooks.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<VirtualizationProvider>))]
public enum VirtualizationProvider
{
    HyperV,
    VMware,
    Qemu
}

/// <summary>
/// Resolves the Windows guest endpoint used by VMware and QEMU runbooks.
/// Configured preserves explicit DNS/IP behavior, VMwareTools discovers the
/// restored guest IP through vmrun, and QemuUserNat uses a provider-owned
/// localhost WinRM forwarding rule.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<GuestRemotingAddressMode>))]
public enum GuestRemotingAddressMode
{
    Configured,
    VMwareTools,
    QemuUserNat
}

/// <summary>
/// Root configuration for the sandbox host.
/// Inputs come from config/sandbox.example.json or a local copy, processing
/// binds JSON to typed records, and the model is returned to services that
/// build runbooks and reports.
/// </summary>
public sealed record SandboxConfig
{
    public VirtualizationConfig Virtualization { get; init; } = new();

    public HyperVConfig HyperV { get; init; } = new();

    public VMwareConfig VMware { get; init; } = new();

    public QemuConfig Qemu { get; init; } = new();

    public GuestConfig Guest { get; init; } = new();

    public AnalysisConfig Analysis { get; init; } = new();

    public ArtifactCollectionConfig ArtifactCollection { get; init; } = new();

    public SandboxPaths Paths { get; init; } = new();

    public DriverConfig Driver { get; init; } = new();
}

/// <summary>
/// Selects the host virtualization implementation. Hyper-V remains the default
/// so existing local configuration files keep their original behavior.
/// </summary>
public sealed record VirtualizationConfig
{
    public VirtualizationProvider Provider { get; init; } = VirtualizationProvider.HyperV;
}

/// <summary>
/// Hyper-V settings for either checkpoint restore or differencing-disk mode.
/// Inputs are local host names and paths, processing only creates a command
/// plan in v1, and the values are returned to the runbook builder.
/// </summary>
public sealed record HyperVConfig
{
    public string GoldenVmName { get; init; } = "KSwordSandbox-Win10-Golden";

    public string GoldenSnapshotName { get; init; } = "Clean";

    public string TempVmPrefix { get; init; } = "KSwordSandbox-Run";

    public string? SwitchName { get; init; }

    public bool UseDifferencingDisk { get; init; }

    public string? BaseVhdxPath { get; init; }

    // Backward-compatible status/config surface. Live Web/Core runbooks still
    // require an interactive VM desktop; only the CLI -NoOpenVmConsole switch
    // may explicitly permit headless execution.
    public bool OpenVmConsoleOnLiveStart { get; init; } = true;

    public string VmConsoleServerName { get; init; } = "localhost";

    public bool RdpFallbackEnabled { get; init; } = true;

    public string? RdpTarget { get; init; }

    public long MemoryStartupBytes { get; init; } = 4L * 1024 * 1024 * 1024;
}

/// <summary>
/// VMware Workstation Pro vmrun settings on a Windows host. Guest operations
/// use the provider remoting profile with legacy <see cref="GuestConfig"/> fallback.
/// </summary>
public sealed record VMwareConfig
{
    public string VmName { get; init; } = "KSwordSandbox-Win10-Golden";

    public string VmxPath { get; init; } = string.Empty;

    public string SnapshotName { get; init; } = "Clean";

    public string VmrunPath { get; init; } = "vmrun.exe";

    public string VmType { get; init; } = "ws";

    public bool Headless { get; init; }

    public GuestRemotingConfig GuestRemoting { get; init; } = new()
    {
        AddressMode = GuestRemotingAddressMode.VMwareTools,
        UseSsl = true,
        SkipCertificateChecks = true
    };
}

/// <summary>
/// QEMU settings for a Windows guest backed by a qcow2/raw/vhdx/vmdk disk. Overlay mode
/// creates one disposable qcow2 disk per job; snapshot mode restores an
/// existing internal snapshot before boot.
/// </summary>
public sealed record QemuConfig
{
    public string VmName { get; init; } = "KSwordSandbox-Win10-Golden";

    public string QemuSystemPath { get; init; } = "qemu-system-x86_64.exe";

    public string QemuImgPath { get; init; } = "qemu-img.exe";

    public string DiskImagePath { get; init; } = string.Empty;

    public string DiskFormat { get; init; } = "qcow2";

    public string DiskInterface { get; init; } = "virtio";

    public string SnapshotName { get; init; } = "Clean";

    public bool UseOverlayDisk { get; init; } = true;

    public int MemoryMegabytes { get; init; } = 4096;

    public bool Headless { get; init; }

    public List<string> AdditionalArguments { get; init; } = ["-accel", "whpx"];

    public GuestRemotingConfig GuestRemoting { get; init; } = new()
    {
        AddressMode = GuestRemotingAddressMode.QemuUserNat,
        UseSsl = true,
        SkipCertificateChecks = true
    };
}

/// <summary>
/// Provider-specific Windows PowerShell remoting endpoint. Configured mode can
/// fall back to the legacy shared fields in <see cref="GuestConfig"/>.
/// </summary>
public sealed record GuestRemotingConfig
{
    public GuestRemotingAddressMode AddressMode { get; init; } = GuestRemotingAddressMode.Configured;

    public string? Address { get; init; }

    public string Authentication { get; init; } = "Negotiate";

    public bool UseSsl { get; init; }

    public int Port { get; init; }

    public bool SkipCertificateChecks { get; init; }
}

/// <summary>
/// Guest operating system settings used by PowerShell Direct and the agent.
/// Inputs intentionally reference a secret name instead of a password,
/// processing avoids storing credentials in git, and the values are returned
/// to host orchestration.
/// </summary>
public sealed record GuestConfig
{
    public string UserName { get; init; } = "SandboxUser";

    public string PasswordSecretName { get; init; } = "KSWORDBOX_GUEST_PASSWORD";

    public string WorkingDirectory { get; init; } = "C:\\KSwordSandbox";

    public string AgentExecutableName { get; init; } = "KSword.Sandbox.Agent.exe";

    public bool EnablePowerShellDirect { get; init; } = true;

    /// <summary>
    /// DNS name or IP used by VMware and QEMU guests for Windows PowerShell
    /// remoting. Hyper-V ignores this field and uses PowerShell Direct.
    /// </summary>
    public string? PowerShellRemotingAddress { get; init; }

    public string PowerShellRemotingAuthentication { get; init; } = "Negotiate";

    public bool PowerShellRemotingUseSsl { get; init; }

    public int PowerShellRemotingPort { get; init; }

    public bool PowerShellRemotingSkipCertificateChecks { get; init; }
}

/// <summary>
/// Analysis timing and safety limits.
/// Inputs are API requests and defaults, processing clamps dangerous values,
/// and the values are returned to job planning.
/// </summary>
public sealed record AnalysisConfig
{
    public int DefaultDurationSeconds { get; init; } = 120;

    public int MaxDurationSeconds { get; init; } = 900;

    public int GuestReadyTimeoutSeconds { get; init; } = 180;

    public bool DurationUnlimited { get; init; }

    public long MaxSampleBytes { get; init; } = 200L * 1024 * 1024;
}

/// <summary>
/// Opt-in guest artifact collection settings.
/// Inputs are config defaults or per-job WebUI overrides, processing forwards
/// enabled lanes to the Guest Agent CLI, and the values are returned to
/// runbook builders without collecting sensitive artifacts by default.
/// </summary>
public sealed record ArtifactCollectionConfig
{
    public bool CollectDroppedFiles { get; init; }

    public bool CaptureScreenshots { get; init; }

    public bool CaptureMemoryDumps { get; init; }

    public bool CapturePacketCapture { get; init; }
}

/// <summary>
/// Host paths for runtime artifacts and rule files.
/// Inputs are local filesystem paths, processing expands relative paths from
/// the repository root, and the values are returned to storage services.
/// </summary>
public sealed record SandboxPaths
{
    public string RuntimeRoot { get; init; } = "D:\\Temp\\KSwordSandbox";

    public string RulesDirectory { get; init; } = "rules";

    public string GuestPayloadRoot { get; init; } = "D:\\Temp\\KSwordSandbox\\payload\\guest-tools";
}

/// <summary>
/// Optional R0 driver integration settings for the guest VM.
/// Inputs point at signed driver artifacts outside git, processing forwards
/// only paths and service names, and the record is returned to the runbook.
/// </summary>
public sealed record DriverConfig
{
    public bool Enabled { get; init; } = true;

    public string ServiceName { get; init; } = "KSwordSandboxDriver";

    public string? HostDriverPath { get; init; }

    public string DriverPathInGuest { get; init; } = "C:\\KSwordSandbox\\driver\\KSword.Sandbox.Driver.sys";

    public string EventJsonLinesPath { get; init; } = "C:\\KSwordSandbox\\out\\driver-events.jsonl";

    public string R0CollectorPathInGuest { get; init; } = "C:\\KSwordSandbox\\r0collector\\KSword.Sandbox.R0Collector.exe";

    public string DevicePath { get; init; } = "\\\\.\\KSwordSandboxDriver";

    public bool UseMockCollector { get; init; }
}
