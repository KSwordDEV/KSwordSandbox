using System.Collections.Concurrent;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// In-memory background execution registry for WebUI-started runbooks.
/// Inputs are job ids and deferred runbook execution delegates; processing
/// starts work on the server side so browser requests can return immediately;
/// callers poll compact snapshots for terminal result/report navigation.
/// </summary>
internal sealed class RunbookBackgroundExecutionStore
{
    public const string NotStarted = "not_started";
    public const string Queued = "queued";
    public const string Running = "running";
    public const string Completed = "completed";
    public const string Failed = "failed";

    private readonly ConcurrentDictionary<Guid, RunbookBackgroundExecutionSnapshot> snapshots = new();

    /// <summary>
    /// Starts one background run unless the same job is already queued/running.
    /// Inputs are job id, mode flags, and a delegate that owns the real executor
    /// work; processing records queued/running/terminal snapshots; return value
    /// indicates whether a new task was accepted.
    /// </summary>
    public bool TryStart(
        Guid jobId,
        bool live,
        bool importGuestEvents,
        Func<Task<RunbookExecutionOutcome>> executeAsync,
        out RunbookBackgroundExecutionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(executeAsync);

        if (snapshots.TryGetValue(jobId, out var existing) && IsActive(existing.State))
        {
            snapshot = existing with
            {
                Accepted = false,
                Message = "该任务的分析流程已经在排队或运行中；下一步：打开监控页或进度页查看当前状态，不要重复提交 / Runbook execution is already queued or running for this job. Next step: open the monitor or progress page to view the current state instead of submitting again.",
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        var queuedSnapshot = new RunbookBackgroundExecutionSnapshot
        {
            JobId = jobId,
            Live = live,
            ImportGuestEvents = importGuestEvents,
            Accepted = true,
            State = Queued,
            Message = "WebUI 已接收后台分析任务；下一步：进入监控页查看安全进度 / Runbook execution has been accepted by the WebUI background runner. Next step: open the monitor page for UI-safe progress.",
            StartedAtUtc = now,
            UpdatedAtUtc = now
        };
        snapshot = queuedSnapshot;
        snapshots[jobId] = snapshot;

        _ = Task.Run(async () =>
        {
            Update(queuedSnapshot with
            {
                State = Running,
                Message = "后台正在执行虚拟机分析流程；下一步：保持监控页打开等待报告入口 / Runbook execution is running in the WebUI background runner. Next step: keep the monitor page open until report links appear.",
                UpdatedAtUtc = DateTimeOffset.UtcNow
            });

            try
            {
                var outcome = await executeAsync().ConfigureAwait(false);
                var importFailed = !string.IsNullOrWhiteSpace(outcome.GuestImportMessage) &&
                    !outcome.GuestImportSucceeded;
                var success = outcome.Execution.Success && !importFailed;
                Update(new RunbookBackgroundExecutionSnapshot
                {
                    JobId = jobId,
                    Live = live,
                    ImportGuestEvents = importGuestEvents,
                    Accepted = true,
                    State = success ? Completed : Failed,
                    Success = success,
                    Execution = outcome.Execution,
                    Job = outcome.Job,
                    GuestImportSucceeded = outcome.GuestImportSucceeded,
                    GuestImportMessage = outcome.GuestImportMessage,
                    Message = success
                        ? "分析流程已完成；下一步：打开中文或英文报告 / Runbook execution completed. Next step: open the Chinese or English report."
                        : outcome.Execution.Message ?? outcome.GuestImportMessage ?? "分析流程失败；下一步：打开进度页查看失败阶段并保留本条状态 / Runbook execution failed. Next step: open the progress page for the failed stage and keep this status text.",
                    StartedAtUtc = now,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
            }
            catch (Exception ex)
            {
                Update(new RunbookBackgroundExecutionSnapshot
                {
                    JobId = jobId,
                    Live = live,
                    ImportGuestEvents = importGuestEvents,
                    Accepted = true,
                    State = Failed,
                    Success = false,
                    Message = $"后台分析执行失败；下一步：打开进度页查看失败阶段并检查 Web Host 日志 / Runbook background execution failed. Next step: open the progress page for the failed stage and check Web Host logs: {ex.Message}",
                    StartedAtUtc = now,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
            }
        });

        return true;
    }

    /// <summary>
    /// Reads a current snapshot or returns a stable not-started marker.
    /// </summary>
    public RunbookBackgroundExecutionSnapshot Get(Guid jobId)
    {
        return snapshots.TryGetValue(jobId, out var snapshot)
            ? snapshot
            : new RunbookBackgroundExecutionSnapshot
            {
                JobId = jobId,
                State = NotStarted,
                Message = "此任务尚未启动 WebUI 后台分析；下一步：在主界面点击启动虚拟机分析 / No WebUI background runbook execution has started for this job. Next step: start VM analysis from the dashboard.",
                StartedAtUtc = DateTimeOffset.UtcNow,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
    }

    private static bool IsActive(string state)
    {
        return string.Equals(state, Queued, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(state, Running, StringComparison.OrdinalIgnoreCase);
    }

    private void Update(RunbookBackgroundExecutionSnapshot snapshot)
    {
        snapshots[snapshot.JobId] = snapshot;
    }
}

/// <summary>
/// JSON-serializable background execution status for a job.
/// </summary>
internal sealed record RunbookBackgroundExecutionSnapshot
{
    public required Guid JobId { get; init; }

    public bool Live { get; init; }

    public bool ImportGuestEvents { get; init; }

    public bool Accepted { get; init; }

    public required string State { get; init; }

    public bool? Success { get; init; }

    public string? Message { get; init; }

    public DateTimeOffset StartedAtUtc { get; init; }

    public DateTimeOffset UpdatedAtUtc { get; init; }

    public TimeSpan Duration => UpdatedAtUtc >= StartedAtUtc
        ? UpdatedAtUtc - StartedAtUtc
        : TimeSpan.Zero;

    public SandboxRunbookExecutionResult? Execution { get; init; }

    public AnalysisJob? Job { get; init; }

    public bool GuestImportSucceeded { get; init; }

    public string? GuestImportMessage { get; init; }
}

/// <summary>
/// Terminal result from one runbook execution plus optional guest import.
/// </summary>
internal sealed record RunbookExecutionOutcome(
    SandboxRunbookExecutionResult Execution,
    AnalysisJob Job,
    bool GuestImportSucceeded,
    string? GuestImportMessage);
