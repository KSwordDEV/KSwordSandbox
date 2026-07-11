using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Execution;

/// <summary>
/// Shared helpers for UI-safe runbook progress. Inputs are source runbook
/// metadata, compact progress rows, and execution results; processing derives
/// display-only phase/category/ordinal facts and messages that never copy
/// PowerShell command text or captured stdout/stderr; returned values are safe
/// for WebUI progress snapshots and durable sidecars.
/// </summary>
internal static class RunbookProgressFacts
{
    private const string HiddenStreamsNotice = "UI progress omits command text/stdout/stderr; use runbook-execution.json for raw execution evidence.";
    private const string HiddenStreamsNoticeZh = "UI 进度不会写入命令文本/stdout/stderr；需要原始执行证据时请查看 runbook-execution.json。";

    /// <summary>
    /// Builds stable display facts for one step.
    /// Inputs are source step metadata and zero-based position; processing maps
    /// known step ids to coarse phases/categories and returns an ordinal that
    /// callers can use without inspecting command text.
    /// </summary>
    public static RunbookStepProgressDescriptor DescribeStep(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps)
    {
        ArgumentNullException.ThrowIfNull(step);
        var normalizedId = (step.Id ?? string.Empty).Trim();
        var category = ResolveCategory(normalizedId);
        return new RunbookStepProgressDescriptor(
            StepIndex: stepIndex,
            StepNumber: stepIndex + 1,
            TotalSteps: Math.Max(totalSteps, stepIndex + 1),
            Ordinal: FormatOrdinal(stepIndex, totalSteps),
            Phase: ResolvePhase(normalizedId),
            Category: category,
            RemediationHintZh: BuildChineseRemediationHint(normalizedId, category),
            IsCleanup: IsCleanupStepId(normalizedId));
    }

    /// <summary>
    /// Formats the human ordinal used by progress messages.
    /// </summary>
    public static string FormatOrdinal(int stepIndex, int totalSteps)
    {
        return $"{stepIndex + 1}/{Math.Max(totalSteps, stepIndex + 1)}";
    }

    /// <summary>
    /// Builds a compact prefix with ordinal, phase, and category.
    /// </summary>
    public static string BuildStepPrefix(SandboxRunbookStep step, int stepIndex, int totalSteps)
    {
        var facts = DescribeStep(step, stepIndex, totalSteps);
        return $"Step {facts.Ordinal} [phase={facts.Phase}; category={facts.Category}]";
    }

    /// <summary>
    /// Resolves the progress state for a source step.
    /// Inputs are optional execution result and aggregate failed index;
    /// processing distinguishes skipped, canceled, failed, and pending rows;
    /// the returned string is one of SandboxRunbookProgressStates.
    /// </summary>
    public static string ResolveStepState(
        int stepIndex,
        SandboxRunbookStepExecutionResult? stepResult,
        int? failedIndex)
    {
        if (stepResult is not null)
        {
            if (stepResult.Skipped)
            {
                return SandboxRunbookProgressStates.Skipped;
            }

            if (stepResult.Success)
            {
                return SandboxRunbookProgressStates.Completed;
            }

            return IsCanceledStepResult(stepResult)
                ? SandboxRunbookProgressStates.Canceled
                : SandboxRunbookProgressStates.Failed;
        }

        if (failedIndex.HasValue && stepIndex > failedIndex.Value)
        {
            return SandboxRunbookProgressStates.Skipped;
        }

        return SandboxRunbookProgressStates.Pending;
    }

    /// <summary>
    /// Picks the current step when recovering from durable state.
    /// Inputs are UI-safe step rows plus any explicit current-step index;
    /// processing prefers running/failed rows and falls back to the next
    /// actionable step so the UI does not lose current-step context after a
    /// process restart.
    /// </summary>
    public static int? ResolveCurrentStepIndex(
        IReadOnlyList<SandboxRunbookStepProgressSnapshot> steps,
        int? explicitCurrentStepIndex,
        string? aggregateState,
        bool? success)
    {
        if (steps.Count == 0)
        {
            return null;
        }

        if (explicitCurrentStepIndex is >= 0 && explicitCurrentStepIndex.Value < steps.Count)
        {
            return explicitCurrentStepIndex.Value;
        }

        var normalizedState = (aggregateState ?? string.Empty).Trim().ToLowerInvariant();
        var running = steps.FirstOrDefault(step => StateEquals(step.State, SandboxRunbookProgressStates.Running));
        if (running is not null)
        {
            return running.StepIndex;
        }

        if (normalizedState is SandboxRunbookProgressStates.Failed ||
            normalizedState is SandboxRunbookProgressStates.Canceled ||
            success == false)
        {
            var failed = steps.FirstOrDefault(step =>
                StateEquals(step.State, SandboxRunbookProgressStates.Failed) ||
                StateEquals(step.State, SandboxRunbookProgressStates.Canceled));
            if (failed is not null)
            {
                return failed.StepIndex;
            }

            var lastStarted = steps.LastOrDefault(step => !StateEquals(step.State, SandboxRunbookProgressStates.Pending));
            if (lastStarted is not null)
            {
                return lastStarted.StepIndex;
            }

            return steps[0].StepIndex;
        }

        if (normalizedState is SandboxRunbookProgressStates.Completed || success == true)
        {
            return steps.LastOrDefault(step =>
                StateEquals(step.State, SandboxRunbookProgressStates.Completed) ||
                StateEquals(step.State, SandboxRunbookProgressStates.Skipped))?.StepIndex ?? steps[^1].StepIndex;
        }

        return steps.FirstOrDefault(step => StateEquals(step.State, SandboxRunbookProgressStates.Pending))?.StepIndex ??
            steps.Last().StepIndex;
    }

    /// <summary>
    /// Returns true when a row state should count as complete for progress
    /// accounting. Skipped steps are included because no more work remains for
    /// that source step.
    /// </summary>
    public static bool CountsAsCompletedStep(string? state)
    {
        return StateEquals(state, SandboxRunbookProgressStates.Completed) ||
            StateEquals(state, SandboxRunbookProgressStates.Skipped);
    }

    /// <summary>
    /// Builds a UI-safe step row message from source metadata and result facts.
    /// The method intentionally ignores captured stdout/stderr and raw
    /// PowerShell text even when the execution result contains them.
    /// </summary>
    public static string? BuildStepProgressMessage(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        string state,
        SandboxRunbookStepExecutionResult? result,
        bool isCurrent)
    {
        var prefix = BuildStepPrefix(step, stepIndex, totalSteps);
        var facts = DescribeStep(step, stepIndex, totalSteps);
        if (result is not null)
        {
            if (StateEquals(state, SandboxRunbookProgressStates.Skipped))
            {
                return result.Success
                    ? $"{prefix} recorded/skipped without launching a live PowerShell step. {HiddenStreamsNoticeZh}"
                    : $"{prefix} skipped after an earlier failure. {HiddenStreamsNoticeZh}";
            }

            if (StateEquals(state, SandboxRunbookProgressStates.Completed))
            {
                return $"{prefix} completed in {FormatDuration(result.Duration)}.";
            }

            if (StateEquals(state, SandboxRunbookProgressStates.Canceled))
            {
                return $"{prefix} was canceled before completion. 修复建议：确认是否为操作者主动取消；如需重跑，请先检查 VM 是否已清理干净。 {HiddenStreamsNoticeZh}";
            }

            if (StateEquals(state, SandboxRunbookProgressStates.Failed))
            {
                return $"{prefix} failed; {BuildExitCodeSummary(result)}. 修复建议：{facts.RemediationHintZh} {HiddenStreamsNoticeZh}";
            }
        }

        if (isCurrent && StateEquals(state, SandboxRunbookProgressStates.Running))
        {
            return $"{prefix} is running. {HiddenStreamsNotice}";
        }

        return null;
    }

    /// <summary>
    /// Builds a UI-safe aggregate message from an execution result.
    /// Inputs include the source runbook and optional freshness diagnostic;
    /// processing summarizes the failing/current step without copying any
    /// command or captured stream content.
    /// </summary>
    public static string BuildAggregateProgressMessage(
        SandboxRunbook runbook,
        SandboxRunbookExecutionResult result,
        string? freshnessDiagnostic = null)
    {
        ArgumentNullException.ThrowIfNull(runbook);
        ArgumentNullException.ThrowIfNull(result);

        string message;
        if (result.Success)
        {
            var completed = Math.Max(result.TotalSteps, runbook.Steps.Count);
            message = $"Runbook execution completed; {completed} step(s) reached terminal progress. 分析步骤已完成。";
        }
        else
        {
            var canceled = result.StepResults.Any(IsCanceledStepResult);
            var failedIndex = result.FailedStepIndex;
            if (failedIndex is >= 0 && failedIndex.Value < runbook.Steps.Count)
            {
                var step = runbook.Steps[failedIndex.Value];
                var facts = DescribeStep(step, failedIndex.Value, runbook.Steps.Count);
                var failedResult = result.StepResults.LastOrDefault(candidate => candidate.StepIndex == failedIndex.Value);
                var verb = canceled ? "was canceled" : "failed";
                message = $"Runbook execution {verb} at step {facts.Ordinal} [phase={facts.Phase}; category={facts.Category}]: {step.Title}. {BuildExitCodeSummary(failedResult)} 修复建议：{facts.RemediationHintZh} {HiddenStreamsNoticeZh}";
            }
            else
            {
                var firstFailure = result.StepResults.FirstOrDefault(candidate => !candidate.Success);
                var reason = firstFailure is null ? "No source step reported a normal success result." : BuildExitCodeSummary(firstFailure);
                message = $"Runbook execution failed before a recoverable source step was identified. {reason} 修复建议：确认宿主 PowerShell 已以管理员权限启动、配置项完整，并重新启动分析。 {HiddenStreamsNoticeZh}";
            }
        }

        return AppendFreshnessDiagnostic(message, freshnessDiagnostic);
    }

    /// <summary>
    /// Creates a sanitized copy of a persisted progress snapshot.
    /// Inputs are the optional source runbook and an existing UI snapshot;
    /// processing rebuilds current-step identity and replaces row/aggregate
    /// messages with safe text so historical sidecars cannot leak stdout,
    /// stderr, or command strings.
    /// </summary>
    public static SandboxRunbookProgressSnapshot SanitizeSnapshot(
        SandboxRunbook? runbook,
        SandboxRunbookProgressSnapshot snapshot,
        string? freshnessDiagnostic = null,
        bool bumpUpdatedAt = false)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var totalSteps = Math.Max(snapshot.TotalSteps, Math.Max(snapshot.Steps.Count, runbook?.Steps.Count ?? 0));
        var explicitCurrent = ResolveCurrentStepIndex(snapshot.Steps, snapshot.CurrentStepIndex, snapshot.State, snapshot.Success);
        var steps = snapshot.Steps.Select(step =>
        {
            var sourceStep = ResolveSourceStep(runbook, step);
            var facts = DescribePersistedStep(sourceStep, step, totalSteps);
            var isCurrent = explicitCurrent == step.StepIndex;
            var safeMessage = sourceStep is null
                ? BuildFallbackStepMessage(step, totalSteps, isCurrent)
                : BuildSnapshotStepMessage(sourceStep, step, totalSteps, isCurrent);
            if (string.IsNullOrWhiteSpace(safeMessage) && !string.IsNullOrWhiteSpace(step.Message))
            {
                safeMessage = BuildFallbackStepMessage(step, totalSteps, isCurrent);
            }

            return step with
            {
                Ordinal = facts.Ordinal,
                Phase = facts.Phase,
                Category = facts.Category,
                RemediationHintZh = facts.RemediationHintZh,
                IsCleanup = facts.IsCleanup,
                Message = safeMessage
            };
        }).ToList();

        var currentIndex = ResolveCurrentStepIndex(steps, explicitCurrent, snapshot.State, snapshot.Success);
        var currentStep = currentIndex is >= 0
            ? steps.FirstOrDefault(step => step.StepIndex == currentIndex.Value)
            : null;
        var message = BuildSnapshotAggregateMessage(runbook, snapshot, currentStep);
        message = AppendFreshnessDiagnostic(message, freshnessDiagnostic);

        return snapshot with
        {
            TotalSteps = totalSteps,
            CompletedSteps = steps.Count(step => CountsAsCompletedStep(step.State)),
            CurrentStepIndex = currentStep?.StepIndex,
            CurrentStepId = currentStep?.StepId,
            CurrentStepTitle = currentStep?.Title,
            CurrentPhase = currentStep?.Phase,
            CurrentCategory = currentStep?.Category,
            ProgressPercent = ComputeProgressPercent(steps, snapshot.State, snapshot.Success, totalSteps),
            Message = message,
            UpdatedAtUtc = bumpUpdatedAt ? DateTimeOffset.UtcNow : snapshot.UpdatedAtUtc,
            Steps = steps
        };
    }

    /// <summary>
    /// Computes a bounded display percentage for a UI progress snapshot.
    /// Completed/skipped steps count as full units, a running current step earns
    /// a half unit so operators can see forward motion, and terminal states are
    /// pinned to 100/0 as appropriate.
    /// </summary>
    public static int ComputeProgressPercent(
        IReadOnlyList<SandboxRunbookStepProgressSnapshot> steps,
        string? aggregateState,
        bool? success,
        int totalSteps)
    {
        if (success == true || StateEquals(aggregateState, SandboxRunbookProgressStates.Completed))
        {
            return 100;
        }

        var denominator = Math.Max(totalSteps, steps.Count);
        if (denominator <= 0)
        {
            return 0;
        }

        var completed = steps.Count(step => CountsAsCompletedStep(step.State));
        var runningCredit = steps.Any(step => StateEquals(step.State, SandboxRunbookProgressStates.Running)) ? 0.5d : 0d;
        var percent = (int)Math.Floor(((completed + runningCredit) / denominator) * 100d);
        if (success == false || StateEquals(aggregateState, SandboxRunbookProgressStates.Failed) || StateEquals(aggregateState, SandboxRunbookProgressStates.Canceled))
        {
            return Math.Clamp(percent, 0, 99);
        }

        return Math.Clamp(percent, 0, 99);
    }

    /// <summary>
    /// Adds a freshness diagnostic to an existing progress message.
    /// </summary>
    public static string AppendFreshnessDiagnostic(string? message, string? freshnessDiagnostic)
    {
        if (string.IsNullOrWhiteSpace(freshnessDiagnostic))
        {
            return string.IsNullOrWhiteSpace(message) ? string.Empty : message;
        }

        var prefix = string.IsNullOrWhiteSpace(message) ? string.Empty : message.Trim() + " ";
        return $"{prefix}Snapshot freshness diagnostic: {freshnessDiagnostic} 快照新鲜度诊断：{freshnessDiagnostic}";
    }

    /// <summary>
    /// Determines whether a failed step result represents cancellation.
    /// </summary>
    public static bool IsCanceledStepResult(SandboxRunbookStepExecutionResult result)
    {
        return result.Message is not null &&
            (result.Message.Contains("canceled", StringComparison.OrdinalIgnoreCase) ||
             result.Message.Contains("cancelled", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Identifies cleanup steps by stable runbook identifiers.
    /// </summary>
    public static bool IsCleanupStepId(string? stepId)
    {
        return stepId is not null &&
            (stepId.Equals("stop-vm", StringComparison.OrdinalIgnoreCase) ||
             stepId.Equals("remove-temp-vm", StringComparison.OrdinalIgnoreCase) ||
             stepId.Equals("stop-vm-after-run", StringComparison.OrdinalIgnoreCase) ||
             stepId.Equals("restore-checkpoint-after-run", StringComparison.OrdinalIgnoreCase) ||
             stepId.StartsWith("cleanup-", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Formats a duration for operator-facing progress.
    /// </summary>
    public static string FormatDuration(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
        {
            duration = TimeSpan.Zero;
        }

        if (duration.TotalHours >= 1)
        {
            return $"{(int)duration.TotalHours}h {duration.Minutes}m {duration.Seconds}s";
        }

        if (duration.TotalMinutes >= 1)
        {
            return $"{(int)duration.TotalMinutes}m {duration.Seconds}s";
        }

        return $"{Math.Max(0, (int)Math.Round(duration.TotalSeconds))}s";
    }

    private static string ResolvePhase(string stepId)
    {
        if (IsCleanupStepId(stepId))
        {
            return "cleanup";
        }

        return stepId switch
        {
            "check-hyperv" or "check-golden-vm" or "check-r0-driver-config" or "check-guest-credential" => "preflight",
            "make-vm-root" or "make-diff-disk" or "create-temp-vm" or "stop-golden" or "restore-golden" or
                "enable-guest-service" or "start-temp-vm" or "start-golden" or "start-vm" or "wait-powershell-direct" => "vm-prepare",
            "stage-guest-payload" or "copy-sample" or "make-host-output" or "record-artifact-policy" or "prepare-guest-output" => "guest-prepare",
            "install-driver-service" => "r0-driver",
            "run-agent" => "analysis",
            "sync-live-output" or "collect-output" => "collection",
            _ => stepId.Contains("driver", StringComparison.OrdinalIgnoreCase) ? "r0-driver" : "runbook"
        };
    }

    private static string ResolveCategory(string stepId)
    {
        return stepId switch
        {
            "check-hyperv" or "check-golden-vm" => "host-readiness",
            "check-r0-driver-config" => "driver-readiness",
            "check-guest-credential" => "credential",
            "make-vm-root" or "make-diff-disk" or "create-temp-vm" or "stop-golden" or "restore-golden" or
                "start-temp-vm" or "start-golden" or "start-vm" => "hyperv-vm",
            "enable-guest-service" => "guest-service",
            "wait-powershell-direct" => "powershell-direct",
            "stage-guest-payload" => "payload",
            "copy-sample" => "sample",
            "make-host-output" or "record-artifact-policy" or "prepare-guest-output" => "artifact-output",
            "install-driver-service" => "driver-service",
            "run-agent" => "guest-agent",
            "sync-live-output" or "collect-output" => "guest-output",
            "stop-vm" or "remove-temp-vm" or "stop-vm-after-run" or "restore-checkpoint-after-run" => "cleanup",
            _ => stepId.Contains("driver", StringComparison.OrdinalIgnoreCase) ? "driver" : "operation"
        };
    }

    private static string BuildChineseRemediationHint(string stepId, string category)
    {
        return stepId switch
        {
            "check-hyperv" => "确认宿主机已安装 Hyper-V 模块，并从管理员 PowerShell 启动服务进程。",
            "check-golden-vm" => "确认 golden VM 名称与配置一致，且当前用户可读取该 VM。",
            "check-r0-driver-config" => "确认 driver.hostDriverPath 指向已构建并测试签名的 .sys；如只验证流程，可启用 mock R0。",
            "check-guest-credential" => "确认来宾密码环境变量在 Process/User/Machine 作用域可见，且用户名与 VM 内账号一致。",
            "start-temp-vm" or "start-golden" or "start-vm" => "检查 VM 当前状态、检查点/差分盘是否可用，以及 Hyper-V 服务是否正常。",
            "wait-powershell-direct" => "确认 VM 已启动、Guest Service Interface 已启用、来宾账号密码正确，并等待系统完成登录初始化。",
            "stage-guest-payload" => "确认 Guest Agent/R0Collector payload 目录存在，Copy-VMFile/PowerShell Direct 可用，来宾目标目录可写。",
            "copy-sample" => "确认样本文件仍在宿主机路径中，且来宾 incoming 目录可由 Guest Service 写入。",
            "install-driver-service" => "确认来宾处于测试签名模式，驱动已可信签名，服务名未被占用，驱动路径已正确 staging。",
            "run-agent" => "确认 Guest Agent 可执行文件存在，样本路径和输出目录有效，采集参数与来宾权限匹配。",
            "sync-live-output" => "确认 agent.pid/agent.exit 标记文件可读，PowerShell Direct session 稳定，宿主输出目录可写。",
            "collect-output" => "确认 guest 输出目录存在，events.json、agent.pid、agent.exit 已生成，并重新执行最终复制。",
            "stop-vm" or "remove-temp-vm" or "stop-vm-after-run" or "restore-checkpoint-after-run" => "检查 VM 是否仍存在/可访问；必要时手动关闭或恢复快照后再重试。",
            _ => category switch
            {
                "credential" => "检查凭据配置和环境变量作用域。",
                "powershell-direct" => "检查 PowerShell Direct、Guest Service Interface 和来宾账号可用性。",
                "driver" or "driver-service" or "driver-readiness" => "检查驱动路径、签名、测试签名模式和服务状态。",
                "guest-output" or "artifact-output" => "检查来宾/宿主输出目录、标记文件和复制权限。",
                _ => "查看对应步骤配置、宿主权限、VM 状态和完整执行记录中的原始输出。"
            }
        };
    }

    private static string BuildExitCodeSummary(SandboxRunbookStepExecutionResult? result)
    {
        if (result is null)
        {
            return "No per-step result was available.";
        }

        if (IsCanceledStepResult(result))
        {
            return "The step was canceled before completion.";
        }

        return result.ExitCode.HasValue
            ? $"PowerShell exited with code {result.ExitCode.Value}"
            : "PowerShell did not return a normal exit code";
    }

    private static SandboxRunbookStep? ResolveSourceStep(
        SandboxRunbook? runbook,
        SandboxRunbookStepProgressSnapshot step)
    {
        if (runbook is null)
        {
            return null;
        }

        if (step.StepIndex >= 0 && step.StepIndex < runbook.Steps.Count)
        {
            return runbook.Steps[step.StepIndex];
        }

        return runbook.Steps.FirstOrDefault(candidate =>
            string.Equals(candidate.Id, step.StepId, StringComparison.OrdinalIgnoreCase));
    }

    private static RunbookStepProgressDescriptor DescribePersistedStep(
        SandboxRunbookStep? sourceStep,
        SandboxRunbookStepProgressSnapshot step,
        int totalSteps)
    {
        if (sourceStep is not null)
        {
            return DescribeStep(sourceStep, step.StepIndex, totalSteps);
        }

        var fallback = new SandboxRunbookStep
        {
            Id = string.IsNullOrWhiteSpace(step.StepId) ? $"step-{step.StepIndex + 1}" : step.StepId,
            Title = string.IsNullOrWhiteSpace(step.Title) ? $"Step {step.StepIndex + 1}" : step.Title,
            PowerShell = string.Empty,
            RequiresElevation = step.RequiresElevation,
            MutatesVmState = step.MutatesVmState
        };
        return DescribeStep(fallback, step.StepIndex, totalSteps);
    }

    private static string BuildFallbackStepMessage(
        SandboxRunbookStepProgressSnapshot step,
        int totalSteps,
        bool isCurrent)
    {
        var ordinal = FormatOrdinal(step.StepIndex, totalSteps);
        var state = string.IsNullOrWhiteSpace(step.State) ? "unknown" : step.State;
        if (isCurrent && StateEquals(state, SandboxRunbookProgressStates.Running))
        {
            return $"Step {ordinal} [{step.StepId}] is running. {HiddenStreamsNotice}";
        }

        return $"Step {ordinal} [{step.StepId}] progress state is {state}. {HiddenStreamsNoticeZh}";
    }

    private static string? BuildSnapshotStepMessage(
        SandboxRunbookStep sourceStep,
        SandboxRunbookStepProgressSnapshot step,
        int totalSteps,
        bool isCurrent)
    {
        var prefix = BuildStepPrefix(sourceStep, step.StepIndex, totalSteps);
        var facts = DescribeStep(sourceStep, step.StepIndex, totalSteps);
        if (StateEquals(step.State, SandboxRunbookProgressStates.Pending))
        {
            return isCurrent
                ? $"{prefix} is the next pending step after recovery. {HiddenStreamsNoticeZh}"
                : null;
        }

        if (StateEquals(step.State, SandboxRunbookProgressStates.Running))
        {
            return $"{prefix} is running. {HiddenStreamsNotice}";
        }

        if (StateEquals(step.State, SandboxRunbookProgressStates.Completed))
        {
            var duration = step.Duration.HasValue ? $" in {FormatDuration(step.Duration.Value)}" : string.Empty;
            return $"{prefix} completed{duration}.";
        }

        if (StateEquals(step.State, SandboxRunbookProgressStates.Skipped))
        {
            return $"{prefix} was skipped/recorded without launching a live PowerShell step. {HiddenStreamsNoticeZh}";
        }

        if (StateEquals(step.State, SandboxRunbookProgressStates.Canceled))
        {
            return $"{prefix} was canceled. 修复建议：确认是否为操作者主动取消；如需重跑，请先检查 VM 是否已清理干净。 {HiddenStreamsNoticeZh}";
        }

        if (StateEquals(step.State, SandboxRunbookProgressStates.Failed))
        {
            var exit = step.ExitCode.HasValue
                ? $"PowerShell exited with code {step.ExitCode.Value}"
                : "PowerShell did not return a normal exit code";
            return $"{prefix} failed; {exit}. 修复建议：{facts.RemediationHintZh} {HiddenStreamsNoticeZh}";
        }

        return $"{prefix} progress state is {step.State}. {HiddenStreamsNoticeZh}";
    }

    private static string BuildSnapshotAggregateMessage(
        SandboxRunbook? runbook,
        SandboxRunbookProgressSnapshot snapshot,
        SandboxRunbookStepProgressSnapshot? currentStep)
    {
        var state = (snapshot.State ?? string.Empty).Trim().ToLowerInvariant();
        if (state == SandboxRunbookProgressStates.Completed || snapshot.Success == true)
        {
            return "Runbook progress is complete. 分析步骤已完成。";
        }

        if (state == SandboxRunbookProgressStates.Failed || state == SandboxRunbookProgressStates.Canceled || snapshot.Success == false)
        {
            var canceled = state == SandboxRunbookProgressStates.Canceled;
            if (currentStep is not null)
            {
                var sourceStep = ResolveSourceStep(runbook, currentStep);
                if (sourceStep is not null)
                {
                    var facts = DescribeStep(sourceStep, currentStep.StepIndex, Math.Max(snapshot.TotalSteps, snapshot.Steps.Count));
                    return $"Runbook progress {(canceled ? "was canceled" : "failed")} at step {facts.Ordinal} [phase={facts.Phase}; category={facts.Category}]: {currentStep.Title}. 修复建议：{facts.RemediationHintZh} {HiddenStreamsNoticeZh}";
                }

                return $"Runbook progress {(canceled ? "was canceled" : "failed")} at step {FormatOrdinal(currentStep.StepIndex, Math.Max(snapshot.TotalSteps, snapshot.Steps.Count))}: {currentStep.Title}. {HiddenStreamsNoticeZh}";
            }

            return $"Runbook progress {(canceled ? "was canceled" : "failed")} before a current step could be identified. {HiddenStreamsNoticeZh}";
        }

        if (currentStep is not null)
        {
            return $"Runbook progress is {snapshot.State}; current step is {FormatOrdinal(currentStep.StepIndex, Math.Max(snapshot.TotalSteps, snapshot.Steps.Count))}: {currentStep.Title}. {HiddenStreamsNoticeZh}";
        }

        return $"Runbook progress is {snapshot.State}. {HiddenStreamsNoticeZh}";
    }

    private static bool StateEquals(string? actual, string expected)
    {
        return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// UI-safe derived step facts used by progress message builders.
/// </summary>
internal sealed record RunbookStepProgressDescriptor(
    int StepIndex,
    int StepNumber,
    int TotalSteps,
    string Ordinal,
    string Phase,
    string Category,
    string RemediationHintZh,
    bool IsCleanup);
