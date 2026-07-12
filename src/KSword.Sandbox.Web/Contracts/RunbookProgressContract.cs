using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// API-safe durability and freshness metadata for true runbook progress.
/// Inputs are the selected progress snapshot, its durable source path, and the
/// freshness policy; processing derives counts and the latest safe step summary
/// without exposing PowerShell, stdout, or stderr; return behavior is JSON
/// serialization beside progress/background payloads.
/// </summary>
public sealed record RunbookProgressContract(
    Guid JobId,
    string State,
    string? DurableSourcePath,
    DateTimeOffset SnapshotUpdatedAtUtc,
    TimeSpan SnapshotAge,
    TimeSpan StaleThreshold,
    bool IsStale,
    RunbookStepProgressSummaryContract? LatestStepSummary,
    int CompletedStepCount,
    int FailedStepCount,
    int RunningStepCount,
    IReadOnlyList<string> OperatorHintsZh)
{
    public static readonly TimeSpan DefaultStaleThreshold = TimeSpan.FromSeconds(15);

    public static RunbookProgressContract FromSnapshot(
        SandboxRunbookProgressSnapshot snapshot,
        string? durableSourcePath,
        DateTimeOffset generatedAtUtc,
        TimeSpan? staleThreshold = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var threshold = staleThreshold ?? DefaultStaleThreshold;
        var age = generatedAtUtc >= snapshot.UpdatedAtUtc
            ? generatedAtUtc - snapshot.UpdatedAtUtc
            : TimeSpan.Zero;
        var latestStep = SelectLatestStep(snapshot);

        return new RunbookProgressContract(
            snapshot.JobId,
            snapshot.State,
            string.IsNullOrWhiteSpace(durableSourcePath) ? null : durableSourcePath,
            snapshot.UpdatedAtUtc,
            age,
            threshold,
            IsSnapshotStale(snapshot, age, threshold),
            latestStep is null ? null : RunbookStepProgressSummaryContract.FromStep(latestStep, snapshot.TotalSteps),
            snapshot.Steps.Count(step => IsState(step.State, SandboxRunbookProgressStates.Completed) || IsState(step.State, SandboxRunbookProgressStates.Skipped)),
            snapshot.Steps.Count(step => IsState(step.State, SandboxRunbookProgressStates.Failed) || IsState(step.State, SandboxRunbookProgressStates.Canceled)),
            snapshot.Steps.Count(step => IsState(step.State, SandboxRunbookProgressStates.Running)),
            BuildOperatorHintsZh(snapshot, durableSourcePath, age, threshold, latestStep));
    }

    private static SandboxRunbookStepProgressSnapshot? SelectLatestStep(SandboxRunbookProgressSnapshot snapshot)
    {
        var running = snapshot.Steps.LastOrDefault(step => IsState(step.State, SandboxRunbookProgressStates.Running));
        if (running is not null)
        {
            return running;
        }

        var indexed = snapshot.CurrentStepIndex is >= 0
            ? snapshot.Steps.LastOrDefault(step => step.StepIndex == snapshot.CurrentStepIndex.Value)
            : null;
        if (indexed is not null)
        {
            return indexed;
        }

        return snapshot.Steps.LastOrDefault(step => !IsState(step.State, SandboxRunbookProgressStates.Pending)) ??
            snapshot.Steps.FirstOrDefault();
    }

    private static bool IsSnapshotStale(SandboxRunbookProgressSnapshot snapshot, TimeSpan age, TimeSpan threshold)
    {
        if (IsState(snapshot.State, SandboxRunbookProgressStates.Completed) ||
            IsState(snapshot.State, SandboxRunbookProgressStates.Failed) ||
            IsState(snapshot.State, SandboxRunbookProgressStates.Canceled) ||
            snapshot.Success.HasValue)
        {
            return false;
        }

        return age > threshold;
    }

    private static IReadOnlyList<string> BuildOperatorHintsZh(
        SandboxRunbookProgressSnapshot snapshot,
        string? durableSourcePath,
        TimeSpan age,
        TimeSpan threshold,
        SandboxRunbookStepProgressSnapshot? latestStep)
    {
        var hints = new List<string>
        {
            string.IsNullOrWhiteSpace(durableSourcePath)
                ? "当前快照尚未标注持久化来源；请确认 runbook-progress.json 或 runbook-execution.json 是否已经写入。"
                : $"持久化来源：{durableSourcePath}",
            $"快照年龄：{FormatAge(age)}；超过 {FormatAge(threshold)} 且任务未终止时视为可能陈旧。"
        };

        if (latestStep is not null)
        {
            hints.Add($"最新步骤：{latestStep.StepIndex + 1}/{Math.Max(snapshot.TotalSteps, latestStep.StepIndex + 1)} {latestStep.Title}（{latestStep.State}）。");
            if (!string.IsNullOrWhiteSpace(latestStep.RemediationHintZh))
            {
                hints.Add(latestStep.RemediationHintZh);
            }
        }

        if (IsSnapshotStale(snapshot, age, threshold))
        {
            hints.Add("进度流可能陈旧：优先刷新进度接口；如仍不更新，检查 Web Host 日志与后台执行状态。");
        }
        else if (IsState(snapshot.State, SandboxRunbookProgressStates.Running))
        {
            hints.Add("进度仍在更新：保持监控页打开，避免重复启动同一 job。");
        }
        else if (IsState(snapshot.State, SandboxRunbookProgressStates.Failed) || snapshot.Success == false)
        {
            hints.Add("执行失败：保留当前页面和 job 目录，打开执行流程页定位失败步骤。");
        }

        return hints;
    }

    private static string FormatAge(TimeSpan value)
    {
        return value.TotalMinutes >= 1
            ? $"{value.TotalMinutes:0.#} 分钟"
            : $"{value.TotalSeconds:0.#} 秒";
    }

    private static bool IsState(string? actual, string expected)
    {
        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// UI-safe summary for the latest/current runbook step.
/// </summary>
public sealed record RunbookStepProgressSummaryContract(
    int StepIndex,
    int StepNumber,
    int TotalSteps,
    string Ordinal,
    string StepId,
    string Title,
    string State,
    string? Phase,
    string? Category,
    DateTimeOffset? StartedAtUtc,
    TimeSpan? Duration,
    int? ExitCode,
    string? Message,
    string? RemediationHintZh)
{
    public static RunbookStepProgressSummaryContract FromStep(
        SandboxRunbookStepProgressSnapshot step,
        int totalSteps)
    {
        ArgumentNullException.ThrowIfNull(step);
        var boundedTotal = Math.Max(totalSteps, step.StepIndex + 1);
        return new RunbookStepProgressSummaryContract(
            step.StepIndex,
            step.StepIndex + 1,
            boundedTotal,
            string.IsNullOrWhiteSpace(step.Ordinal) ? $"{step.StepIndex + 1}/{boundedTotal}" : step.Ordinal,
            step.StepId,
            step.Title,
            step.State,
            step.Phase,
            step.Category,
            step.StartedAtUtc,
            step.Duration,
            step.ExitCode,
            step.Message,
            step.RemediationHintZh);
    }
}
