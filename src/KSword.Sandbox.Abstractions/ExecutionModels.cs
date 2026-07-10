namespace KSword.Sandbox.Abstractions;

/// <summary>
/// Selects whether a runbook is only inspected or actually executed.
/// Inputs are supplied through <see cref="SandboxRunbookExecutionOptions"/>;
/// processing branches the executor into safe planning or live PowerShell
/// launch behavior; the selected value is returned on execution results.
/// </summary>
public enum SandboxRunbookExecutionMode
{
    /// <summary>
    /// Records each runbook step without launching PowerShell or mutating VM state.
    /// </summary>
    DryRun = 0,

    /// <summary>
    /// Launches PowerShell for each step in order and stops on the first failure.
    /// </summary>
    Live = 1
}

/// <summary>
/// Options that control one runbook execution attempt.
/// Inputs are mode, PowerShell host settings, timeout, and environment
/// overrides; processing uses these values for each step launch; the record is
/// returned to callers only through the copied fields in execution results.
/// </summary>
public sealed record SandboxRunbookExecutionOptions
{
    /// <summary>
    /// Chooses dry-run or live execution. Dry-run is the default so constructing
    /// this record never executes Hyper-V commands by accident.
    /// </summary>
    public SandboxRunbookExecutionMode Mode { get; init; } = SandboxRunbookExecutionMode.DryRun;

    /// <summary>
    /// PowerShell host to launch in live mode. Hyper-V cmdlets are normally
    /// available from elevated Windows PowerShell, so the default is powershell.exe.
    /// </summary>
    public string PowerShellExecutablePath { get; init; } = "powershell.exe";

    /// <summary>
    /// Maximum runtime for each live PowerShell step. A zero or negative value
    /// disables the per-step timeout and leaves cancellation to the caller.
    /// </summary>
    public TimeSpan StepTimeout { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Optional working directory for the live PowerShell process. Null keeps
    /// the current process working directory.
    /// </summary>
    public string? WorkingDirectory { get; init; }

    /// <summary>
    /// Requires the hosting process to be elevated before live steps that need
    /// elevation are launched. Keep this enabled for Hyper-V runbooks.
    /// </summary>
    public bool RequireElevatedPowerShell { get; init; } = true;

    /// <summary>
    /// Environment variable overrides for live PowerShell. A null value removes
    /// the variable from the child process environment.
    /// </summary>
    public IReadOnlyDictionary<string, string?> EnvironmentVariables { get; init; } = new Dictionary<string, string?>();
}

/// <summary>
/// Captured output and status for one runbook step.
/// Inputs are produced by <c>SandboxRunbookStep.PowerShell</c> execution or by
/// dry-run planning; processing stores stdout, stderr, exit code, timing, and
/// failure data; the record is returned as part of the aggregate result.
/// </summary>
public sealed record SandboxRunbookStepExecutionResult
{
    /// <summary>
    /// Zero-based position of this step in the source runbook.
    /// </summary>
    public required int StepIndex { get; init; }

    /// <summary>
    /// Stable runbook step identifier.
    /// </summary>
    public required string StepId { get; init; }

    /// <summary>
    /// Human-readable runbook step title.
    /// </summary>
    public required string Title { get; init; }

    /// <summary>
    /// PowerShell command text that was planned or executed.
    /// </summary>
    public required string PowerShell { get; init; }

    /// <summary>
    /// True when the step was recorded without launching PowerShell.
    /// </summary>
    public bool Skipped { get; init; }

    /// <summary>
    /// True when the step succeeded or was safely skipped in dry-run mode.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// Exit code returned by PowerShell. Null means the process was not started
    /// or did not reach a normal exit.
    /// </summary>
    public int? ExitCode { get; init; }

    /// <summary>
    /// Captured standard output from PowerShell. Dry-run steps use an empty string.
    /// </summary>
    public string StandardOutput { get; init; } = string.Empty;

    /// <summary>
    /// Captured standard error from PowerShell. Dry-run steps use an empty string.
    /// </summary>
    public string StandardError { get; init; } = string.Empty;

    /// <summary>
    /// UTC time when the step was recorded or launched.
    /// </summary>
    public DateTimeOffset StartedAtUtc { get; init; }

    /// <summary>
    /// Elapsed time spent recording or executing this step.
    /// </summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// True when the source step declares an elevated PowerShell requirement.
    /// </summary>
    public bool RequiresElevation { get; init; }

    /// <summary>
    /// True when the source step is expected to mutate VM state.
    /// </summary>
    public bool MutatesVmState { get; init; }

    /// <summary>
    /// Failure or skip detail for callers and reports. Null means no additional
    /// message is needed.
    /// </summary>
    public string? Message { get; init; }
}

/// <summary>
/// Aggregate result for one runbook execution attempt.
/// Inputs are all source runbook steps and the executor options; processing
/// records each dry-run or live step until completion or first failure; the
/// record is returned to the caller for persistence, reporting, or UI display.
/// </summary>
public sealed record SandboxRunbookExecutionResult
{
    /// <summary>
    /// Job identifier copied from the source runbook.
    /// </summary>
    public required Guid JobId { get; init; }

    /// <summary>
    /// Target VM name copied from the source runbook.
    /// </summary>
    public required string TargetVmName { get; init; }

    /// <summary>
    /// Mode used for this attempt.
    /// </summary>
    public required SandboxRunbookExecutionMode Mode { get; init; }

    /// <summary>
    /// True when every planned step was recorded or every live step exited with
    /// code 0.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// Total number of source runbook steps.
    /// </summary>
    public int TotalSteps { get; init; }

    /// <summary>
    /// Number of PowerShell processes actually launched. Dry-run steps do not
    /// count as executed.
    /// </summary>
    public int ExecutedSteps { get; init; }

    /// <summary>
    /// Zero-based failed source step index. Null means no source step failed or
    /// the failure happened before step execution.
    /// </summary>
    public int? FailedStepIndex { get; init; }

    /// <summary>
    /// UTC time when the attempt started.
    /// </summary>
    public DateTimeOffset StartedAtUtc { get; init; }

    /// <summary>
    /// Total elapsed time for the attempt.
    /// </summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// True when at least one source step declares an elevated PowerShell
    /// requirement.
    /// </summary>
    public bool RequiresElevation { get; init; }

    /// <summary>
    /// Captured per-step results. Live mode stops adding source step results
    /// after the first failure.
    /// </summary>
    public IReadOnlyList<SandboxRunbookStepExecutionResult> StepResults { get; init; } = [];

    /// <summary>
    /// Aggregate failure detail. Null means no aggregate failure occurred.
    /// </summary>
    public string? Message { get; init; }
}
