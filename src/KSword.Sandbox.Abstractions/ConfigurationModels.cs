namespace KSword.Sandbox.Abstractions;

/// <summary>
/// Root configuration for the sandbox host.
/// Inputs come from config/sandbox.example.json or a local copy, processing
/// binds JSON to typed records, and the model is returned to services that
/// build runbooks and reports.
/// </summary>
public sealed record SandboxConfig
{
    public HyperVConfig HyperV { get; init; } = new();

    public GuestConfig Guest { get; init; } = new();

    public AnalysisConfig Analysis { get; init; } = new();

    public SandboxPaths Paths { get; init; } = new();

    public DriverConfig Driver { get; init; } = new();
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

    public long MemoryStartupBytes { get; init; } = 4L * 1024 * 1024 * 1024;
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

    public long MaxSampleBytes { get; init; } = 200L * 1024 * 1024;
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
}

/// <summary>
/// Optional R0 driver integration settings for the guest VM.
/// Inputs point at signed driver artifacts outside git, processing forwards
/// only paths and service names, and the record is returned to the runbook.
/// </summary>
public sealed record DriverConfig
{
    public bool Enabled { get; init; } = true;

    public string ServiceName { get; init; } = "KSwordARK";

    public string DriverPathInGuest { get; init; } = "C:\\KSwordSandbox\\driver\\KSwordARKDriver.sys";

    public string EventJsonLinesPath { get; init; } = "C:\\KSwordSandbox\\out\\driver-events.jsonl";
}
