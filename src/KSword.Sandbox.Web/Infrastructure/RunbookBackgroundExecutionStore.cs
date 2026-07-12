using System.Collections.Concurrent;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Web.Contracts;

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
                var importFailed = outcome.GuestImportFailed ||
                    (outcome.Execution.Success && outcome.Job.Status == AnalysisStatus.Failed);
                var terminalFailed = !outcome.Execution.Success || importFailed || outcome.Job.Status == AnalysisStatus.Failed;
                var success = outcome.Execution.Success && !terminalFailed;
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
                    GuestImportSkipped = outcome.GuestImportSkipped,
                    GuestImportFailed = importFailed,
                    GuestImportMessage = outcome.GuestImportMessage,
                    Message = ResolveTerminalMessage(success, outcome),
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

    private static string ResolveTerminalMessage(bool success, RunbookExecutionOutcome outcome)
    {
        if (success)
        {
            return !string.IsNullOrWhiteSpace(outcome.GuestImportMessage)
                ? outcome.GuestImportMessage!
                : "分析流程已完成；下一步：打开中文或英文报告 / Runbook execution completed. Next step: open the Chinese or English report.";
        }

        if (outcome.GuestImportFailed && !string.IsNullOrWhiteSpace(outcome.GuestImportMessage))
        {
            return outcome.GuestImportMessage!;
        }

        if (!outcome.Execution.Success && !string.IsNullOrWhiteSpace(outcome.Execution.Message))
        {
            return $"分析流程失败：{outcome.Execution.Message} / Runbook execution failed.";
        }

        return !string.IsNullOrWhiteSpace(outcome.GuestImportMessage)
            ? outcome.GuestImportMessage!
            : "分析流程失败；下一步：打开进度页查看失败阶段并保留本条状态 / Runbook execution failed. Next step: open the progress page for the failed stage and keep this status text.";
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
    private static readonly TimeSpan BackgroundStaleThreshold = TimeSpan.FromSeconds(15);

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

    public bool GuestImportSkipped { get; init; }

    public bool GuestImportFailed { get; init; }

    public string? GuestImportMessage { get; init; }

    public string? DurableSourcePath => DurableProgressSourcePath ?? DurableExecutionSourcePath;

    public string? DurableProgressSourcePath => ResolveSiblingPath(Job?.RunbookExecutionResultPath, "runbook-progress.json");

    public string? DurableExecutionSourcePath => Job?.RunbookExecutionResultPath;

    public DateTimeOffset SnapshotGeneratedAtUtc => DateTimeOffset.UtcNow;

    public TimeSpan SnapshotAge
    {
        get
        {
            var now = DateTimeOffset.UtcNow;
            return now >= UpdatedAtUtc ? now - UpdatedAtUtc : TimeSpan.Zero;
        }
    }

    public TimeSpan StaleThreshold => BackgroundStaleThreshold;

    public bool IsStale => IsBackgroundActive(State) && SnapshotAge > StaleThreshold;

    public int CompletedStepCount => Execution?.StepResults.Count(step => step.Success || step.Skipped) ?? 0;

    public int FailedStepCount => Execution?.StepResults.Count(step => !step.Success && !step.Skipped) ?? 0;

    public int RunningStepCount => IsBackgroundActive(State) && Execution is null ? 1 : 0;

    public RunbookStepProgressSummaryContract? LatestStepSummary => BuildLatestStepSummary(Execution);

    public IReadOnlyList<string> OperatorHintsZh => BuildOperatorHintsZh();

    private static bool IsBackgroundActive(string? state)
    {
        return string.Equals(state, RunbookBackgroundExecutionStore.Queued, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(state, RunbookBackgroundExecutionStore.Running, StringComparison.OrdinalIgnoreCase);
    }

    private static RunbookStepProgressSummaryContract? BuildLatestStepSummary(SandboxRunbookExecutionResult? execution)
    {
        if (execution is null || execution.StepResults.Count == 0)
        {
            return null;
        }

        var latest = execution.StepResults
            .OrderBy(step => step.StepIndex)
            .ThenBy(step => step.StartedAtUtc)
            .Last();
        var state = latest.Success
            ? latest.Skipped ? SandboxRunbookProgressStates.Skipped : SandboxRunbookProgressStates.Completed
            : SandboxRunbookProgressStates.Failed;
        var progressStep = new SandboxRunbookStepProgressSnapshot
        {
            StepIndex = latest.StepIndex,
            StepId = latest.StepId,
            Title = latest.Title,
            State = state,
            RequiresElevation = latest.RequiresElevation,
            MutatesVmState = latest.MutatesVmState,
            StartedAtUtc = latest.StartedAtUtc,
            Duration = latest.Duration,
            ExitCode = latest.ExitCode,
            Message = latest.Message,
            RemediationHintZh = latest.Success
                ? "该步骤已完成；继续观察后续步骤或报告入口。"
                : "该步骤失败；打开执行流程页查看 stdout/stderr，并保留 job 目录用于排障。"
        };

        return RunbookStepProgressSummaryContract.FromStep(progressStep, execution.TotalSteps);
    }

    private IReadOnlyList<string> BuildOperatorHintsZh()
    {
        var hints = new List<string>();
        if (string.IsNullOrWhiteSpace(DurableSourcePath))
        {
            hints.Add("后台状态暂未包含持久化执行记录路径；等待 runbook-execution.json 写入或检查 job 元数据。");
        }
        else
        {
            hints.Add($"持久化执行记录：{DurableSourcePath}");
        }

        hints.Add($"后台快照年龄：{FormatAge(SnapshotAge)}；超过 {FormatAge(StaleThreshold)} 且仍在排队/运行时视为可能陈旧。");

        if (LatestStepSummary is not null)
        {
            hints.Add($"最新步骤：{LatestStepSummary.Ordinal} {LatestStepSummary.Title}（{LatestStepSummary.State}）。");
        }

        if (GuestImportFailed)
        {
            hints.Add(string.IsNullOrWhiteSpace(GuestImportMessage)
                ? "来宾事件导入失败：报告已收敛为 Failed；先查看任务消息和 report.json 中的 guest.events.import_failed 标记。"
                : $"来宾事件导入失败：{GuestImportMessage}");
        }
        else if (GuestImportSkipped)
        {
            hints.Add(string.IsNullOrWhiteSpace(GuestImportMessage)
                ? "来宾事件导入已按请求跳过：报告已收敛为 Completed，并写入 guest.events.import_skipped 标记。"
                : $"来宾事件导入已跳过：{GuestImportMessage}");
        }
        else if (GuestImportSucceeded)
        {
            hints.Add(string.IsNullOrWhiteSpace(GuestImportMessage)
                ? "来宾事件已导入：打开报告查看样本行为。"
                : $"来宾事件导入完成：{GuestImportMessage}");
        }

        if (IsStale)
        {
            hints.Add("后台状态可能陈旧：刷新 /runbook/background；若仍无变化，查看进度页和 Web Host 日志。");
        }
        else if (string.Equals(State, RunbookBackgroundExecutionStore.Completed, StringComparison.OrdinalIgnoreCase))
        {
            hints.Add("后台执行已完成：打开中文或英文报告，并确认 guest events 是否已导入。");
        }
        else if (string.Equals(State, RunbookBackgroundExecutionStore.Failed, StringComparison.OrdinalIgnoreCase))
        {
            hints.Add("后台执行失败：不要重复提交；先打开进度页/执行流程页定位失败步骤。");
        }
        else if (IsBackgroundActive(State))
        {
            hints.Add("后台执行仍在进行：保持监控页打开，避免重复启动同一 job。");
        }

        return hints;
    }

    private static string FormatAge(TimeSpan value)
    {
        return value.TotalMinutes >= 1
            ? $"{value.TotalMinutes:0.#} 分钟"
            : $"{value.TotalSeconds:0.#} 秒";
    }

    private static string? ResolveSiblingPath(string? path, string fileName)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            var directory = Path.GetDirectoryName(path);
            return string.IsNullOrWhiteSpace(directory)
                ? null
                : Path.Combine(directory, fileName);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }
}

/// <summary>
/// Terminal result from one runbook execution plus optional guest import.
/// </summary>
internal sealed record RunbookExecutionOutcome(
    SandboxRunbookExecutionResult Execution,
    AnalysisJob Job,
    bool GuestImportSucceeded,
    bool GuestImportSkipped,
    bool GuestImportFailed,
    string? GuestImportMessage);
