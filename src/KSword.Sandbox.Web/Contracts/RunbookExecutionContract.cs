using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: execution mode, success flag, summary message, executed step labels, and completion time.
/// Processing: summarizes runbook execution without leaking executor implementation details.
/// Return behavior: instances are serialized as runbook execution payloads.
/// </summary>
/// <param name="Live">Indicates whether the runbook was executed in live mode.</param>
/// <param name="Succeeded">Indicates whether every required runbook step succeeded.</param>
/// <param name="Message">Caller-facing summary of the runbook result.</param>
/// <param name="Steps">Ordered labels for steps included in the execution response.</param>
/// <param name="CompletedAtUtc">UTC timestamp captured after the execution result was produced.</param>
public sealed record RunbookExecutionContract(
    bool Live,
    bool Succeeded,
    string Message,
    IReadOnlyList<string> Steps,
    DateTimeOffset CompletedAtUtc)
{
    public VirtualizationProvider Provider { get; init; } = VirtualizationProvider.HyperV;

    public string? TargetVmName { get; init; }

    public string? BaselineName { get; init; }

    public string? MachineDefinitionPath { get; init; }

    public string? QemuDiskFormat { get; init; }

    public bool WasCanceled { get; init; }

    public string State { get; init; } = "not_started";

    /// <summary>
    /// Copyable per-step execution rows for the WebUI. Values include stdout,
    /// stderr, exit code, duration, and step status when an endpoint has moved
    /// from the legacy label-only list to the richer experience contract.
    /// </summary>
    public IReadOnlyList<RunbookStepExecutionContract> StepResults { get; init; } = [];

    public string? DurableSourcePath { get; init; }

    public TimeSpan SnapshotAge { get; init; } = TimeSpan.Zero;

    public TimeSpan StaleThreshold { get; init; } = RunbookProgressContract.DefaultStaleThreshold;

    public RunbookStepProgressSummaryContract? LatestStepSummary { get; init; }

    public int CompletedStepCount { get; init; }

    public int FailedStepCount { get; init; }

    public int RunningStepCount { get; init; }

    public IReadOnlyList<string> OperatorHintsZh { get; init; } = [];

    public static RunbookExecutionContract FromResult(
        SandboxRunbookExecutionResult result,
        string? durableSourcePath,
        DateTimeOffset generatedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(result);

        var completedAtUtc = result.StartedAtUtc + result.Duration;
        if (completedAtUtc < result.StartedAtUtc)
        {
            completedAtUtc = generatedAtUtc;
        }

        var stepResults = result.StepResults
            .Select(step => new RunbookStepExecutionContract(
                step.StepIndex,
                step.StepId,
                step.Title,
                step.Success,
                step.Skipped,
                step.ExitCode,
                step.Duration,
                step.StandardOutput,
                step.StandardError,
                step.Message))
            .ToList();
        var latest = result.StepResults
            .OrderBy(step => step.StepIndex)
            .ThenBy(step => step.StartedAtUtc)
            .LastOrDefault();

        return new RunbookExecutionContract(
            result.Mode == SandboxRunbookExecutionMode.Live,
            result.Success,
            result.Message ?? (result.Success
                ? "Runbook execution completed."
                : result.WasCanceled
                    ? "Runbook execution was canceled."
                    : "Runbook execution failed."),
            result.StepResults.Select(step => step.Title).ToList(),
            completedAtUtc)
        {
            Provider = result.Provider,
            TargetVmName = result.TargetVmName,
            BaselineName = result.BaselineName,
            MachineDefinitionPath = result.MachineDefinitionPath,
            QemuDiskFormat = result.QemuDiskFormat,
            WasCanceled = result.WasCanceled,
            State = result.Success ? "completed" : result.WasCanceled ? "canceled" : "failed",
            StepResults = stepResults,
            DurableSourcePath = string.IsNullOrWhiteSpace(durableSourcePath) ? null : durableSourcePath,
            SnapshotAge = TimeSpan.Zero,
            StaleThreshold = RunbookProgressContract.DefaultStaleThreshold,
            LatestStepSummary = latest is null ? null : RunbookStepProgressSummaryContract.FromStep(new SandboxRunbookStepProgressSnapshot
            {
                StepIndex = latest.StepIndex,
                Ordinal = latest.StepIndex < 0 ? "preflight" : null,
                StepId = latest.StepId,
                Title = latest.Title,
                State = latest.Success
                    ? latest.Skipped ? SandboxRunbookProgressStates.Skipped : SandboxRunbookProgressStates.Completed
                    : IsCanceledStep(latest)
                        ? SandboxRunbookProgressStates.Canceled
                        : SandboxRunbookProgressStates.Failed,
                RequiresElevation = latest.RequiresElevation,
                MutatesVmState = latest.MutatesVmState,
                StartedAtUtc = latest.StartedAtUtc,
                Duration = latest.Duration,
                ExitCode = latest.ExitCode,
                Message = latest.Message,
                RemediationHintZh = BuildLatestStepRemediationHintZh(latest)
            }, result.TotalSteps),
            CompletedStepCount = result.StepResults.Count(step => step.Success || step.Skipped),
            FailedStepCount = result.StepResults.Count(step => !step.Success && !step.Skipped),
            RunningStepCount = 0,
            OperatorHintsZh = BuildOperatorHintsZh(result, durableSourcePath)
        };
    }

    /// <summary>
    /// Inputs: a reason string and a UTC timestamp from the caller.
    /// Processing: creates a non-live, non-successful result that still uses the normal contract shape.
    /// Return behavior: returns a skipped execution payload with an empty step list.
    /// </summary>
    public static RunbookExecutionContract Skipped(string reason, DateTimeOffset completedAtUtc)
    {
        return new RunbookExecutionContract(false, false, reason, Array.Empty<string>(), completedAtUtc)
        {
            State = "skipped"
        };
    }

    private static IReadOnlyList<string> BuildOperatorHintsZh(
        SandboxRunbookExecutionResult result,
        string? durableSourcePath)
    {
        var hints = new List<string>
        {
            string.IsNullOrWhiteSpace(durableSourcePath)
                ? "执行记录尚未写入持久化路径；请确认 job 目录是否可写。"
                : $"持久化执行记录：{durableSourcePath}"
        };

        if (result.Success)
        {
            hints.Add("执行已完成：打开中文或英文报告，并确认 guest events 导入状态。");
        }
        else if (result.WasCanceled)
        {
            hints.Add("执行已取消：检查 stop/cleanup 步骤结果和 VM 状态后再决定是否重跑。");
        }
        else if (result.StepResults.Any(step => step.StepId.Equals("live-execution-lease", StringComparison.OrdinalIgnoreCase)))
        {
            hints.Add(result.StepResults.Any(IsLegacyLeaseRunbookFailure)
                ? "旧 runbook 缺少 live execution lease：为该样本重新创建 plan 后再执行 live。"
                : "live execution lease 获取失败：等待当前 live job 完成；若确认没有任务运行，检查 runtime root 的 locks 目录权限后重试。");
        }
        else
        {
            hints.Add("执行失败：保留 job 目录，打开执行流程页定位失败步骤。");
        }

        return hints;
    }

    private static string BuildLatestStepRemediationHintZh(SandboxRunbookStepExecutionResult step)
    {
        if (step.StepId.Equals("live-execution-lease", StringComparison.OrdinalIgnoreCase))
        {
            return IsLegacyLeaseRunbookFailure(step)
                ? "该任务的旧 runbook 缺少 lease 路径；为样本重新创建 plan 后再执行 live。"
                : "等待当前 live job 完成；若确认没有任务运行，检查 runtime root 的 locks 目录权限后重试。";
        }

        if (step.StepId.Equals("elevation-check", StringComparison.OrdinalIgnoreCase))
        {
            return "以管理员身份重新启动承载进程后再执行 live 模式。";
        }

        return step.Success
            ? "该步骤已完成；继续查看最终报告。"
            : "该步骤失败；请先在执行流程页查看安全诊断，再按记录路径在宿主机本地检查 runbook-execution.json。";
    }

    private static bool IsLegacyLeaseRunbookFailure(SandboxRunbookStepExecutionResult step) =>
        step.Message?.Contains("predates the live execution lease contract", StringComparison.OrdinalIgnoreCase) == true;

    private static bool IsCanceledStep(SandboxRunbookStepExecutionResult step)
    {
        return !step.Success &&
            ((step.Message?.Contains("canceled", StringComparison.OrdinalIgnoreCase) ?? false) ||
             (step.Message?.Contains("cancelled", StringComparison.OrdinalIgnoreCase) ?? false));
    }
}
