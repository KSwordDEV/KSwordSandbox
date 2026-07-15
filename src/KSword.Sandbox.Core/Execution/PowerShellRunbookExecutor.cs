using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Execution;

/// <summary>
/// Executes sandbox runbook steps by launching PowerShell.
/// Inputs are a prepared provider runbook and execution options; processing
/// records every step in dry-run mode or starts one elevated PowerShell child
/// process per step in live mode; the returned result captures stdout, stderr,
/// exit code, duration, and first-failure status.
/// </summary>
public sealed class PowerShellRunbookExecutor : IRunbookExecutor
{
    private const string DryRunMessage = "Dry-run mode recorded the command without launching PowerShell.";
    private const string ElevationFailureMessage = "This live runbook contains host operations that require an elevated PowerShell session. 修复建议：请使用“以管理员身份运行”的 PowerShell/服务进程重新启动后再执行 live 模式。";
    private const string LiveExecutionLeaseFailureMessage = "The exclusive live execution lease could not be acquired. Another live job may be running, or the runtime lock directory is unavailable. No provider command was executed. 修复建议：等待当前 live job 完成；若没有任务运行，请检查 runtime root 的 locks 目录权限后重试。";
    private static readonly TimeSpan StepHeartbeatInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan StreamReadTimeout = TimeSpan.FromSeconds(5);
    private static readonly System.Text.RegularExpressions.Regex SensitiveEnvironmentNamePattern = new(
        "(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase |
        System.Text.RegularExpressions.RegexOptions.CultureInvariant |
        System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>
    /// Executes or records the supplied runbook.
    /// Inputs are the runbook plan, execution options, and cancellation token;
    /// processing defaults to dry-run safety, validates elevation for live
    /// steps that require it, then executes each PowerShell command in order; the method
    /// returns aggregate status and per-step captured output.
    /// </summary>
    public async Task<SandboxRunbookExecutionResult> ExecuteAsync(
        SandboxRunbook runbook,
        SandboxRunbookExecutionOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(runbook);
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.PowerShellExecutablePath))
        {
            throw new ArgumentException("PowerShell executable path must not be empty.", nameof(options));
        }

        var startedAtUtc = DateTimeOffset.UtcNow;
        var attemptTimer = Stopwatch.StartNew();
        var requiresElevation = runbook.Steps.Any(step => step.RequiresElevation);

        if (options.Mode == SandboxRunbookExecutionMode.DryRun)
        {
            PublishProgress(
                runbook,
                options,
                SandboxRunbookProgressStates.Running,
                startedAtUtc,
                attemptTimer.Elapsed,
                [],
                currentStepIndex: null,
                success: null,
                message: "Dry-run runbook recording started.");

            var dryRunResults = runbook.Steps
                .Select((step, index) => CreateDryRunStepResult(step, index, startedAtUtc))
                .ToList();

            attemptTimer.Stop();
            PublishProgress(
                runbook,
                options,
                SandboxRunbookProgressStates.Completed,
                startedAtUtc,
                attemptTimer.Elapsed,
                dryRunResults,
                currentStepIndex: runbook.Steps.Count > 0 ? runbook.Steps.Count - 1 : null,
                success: true,
                message: "Dry-run runbook recording completed.");

            return CreateAggregateResult(
                runbook,
                options,
                dryRunResults,
                success: true,
                failedStepIndex: null,
                startedAtUtc: startedAtUtc,
                duration: attemptTimer.Elapsed,
                message: null,
                requiresElevation: requiresElevation);
        }

        if (options.Mode != SandboxRunbookExecutionMode.Live)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.Mode, "Unsupported runbook execution mode.");
        }

        PublishProgress(
            runbook,
            options,
            SandboxRunbookProgressStates.Running,
            startedAtUtc,
            attemptTimer.Elapsed,
            [],
            currentStepIndex: null,
            success: null,
            message: $"Starting live {runbook.Provider} runbook for VM '{runbook.TargetVmName}'.");

        if (options.RequireElevatedPowerShell && requiresElevation && !IsCurrentProcessElevated())
        {
            var elevationFailure = CreateElevationFailureStepResult(startedAtUtc);

            attemptTimer.Stop();
            PublishProgress(
                runbook,
                options,
                SandboxRunbookProgressStates.Failed,
                startedAtUtc,
                attemptTimer.Elapsed,
                [elevationFailure],
                currentStepIndex: null,
                success: false,
                message: ElevationFailureMessage);

            return CreateAggregateResult(
                runbook,
                options,
                [elevationFailure],
                success: false,
                failedStepIndex: null,
                startedAtUtc: startedAtUtc,
                duration: attemptTimer.Elapsed,
                message: ElevationFailureMessage,
                requiresElevation: requiresElevation);
        }

        FileStream liveExecutionLease;
        try
        {
            liveExecutionLease = AcquireLiveExecutionLease(runbook);
        }
        catch (Exception ex) when (IsLiveExecutionLeaseFailure(ex))
        {
            var leaseFailure = CreateLiveExecutionLeaseFailureStepResult(startedAtUtc, ex);

            attemptTimer.Stop();
            PublishProgress(
                runbook,
                options,
                SandboxRunbookProgressStates.Failed,
                startedAtUtc,
                attemptTimer.Elapsed,
                [leaseFailure],
                currentStepIndex: null,
                success: false,
                message: leaseFailure.Message ?? LiveExecutionLeaseFailureMessage);

            return CreateAggregateResult(
                runbook,
                options,
                [leaseFailure],
                success: false,
                failedStepIndex: null,
                startedAtUtc: startedAtUtc,
                duration: attemptTimer.Elapsed,
                message: leaseFailure.Message ?? LiveExecutionLeaseFailureMessage,
                requiresElevation: requiresElevation);
        }

        using var ownedLiveExecutionLease = liveExecutionLease;

        var liveResults = new List<SandboxRunbookStepExecutionResult>();
        int? failedStepIndex = null;
        SandboxRunbookStepExecutionResult? primaryFailureResult = null;
        var wasCanceled = false;
        var cleanupMode = false;
        var vmMutationAttempted = false;

        for (var index = 0; index < runbook.Steps.Count; index++)
        {
            var step = runbook.Steps[index];

            if (failedStepIndex is not null && !IsCleanupStep(step))
            {
                liveResults.Add(CreateSkippedAfterFailureStepResult(step, index, primaryFailureResult));
                continue;
            }

            if (!cleanupMode && cancellationToken.IsCancellationRequested)
            {
                failedStepIndex = index;
                wasCanceled = true;
                var currentStepIsCleanup = IsCleanupStep(step);
                var cleanupAvailable = vmMutationAttempted &&
                    (currentStepIsCleanup || HasRemainingCleanupSteps(runbook, index + 1));
                var canceledResult = currentStepIsCleanup && cleanupAvailable
                    ? CreateCancellationBeforeCleanupStepResult(step, DateTimeOffset.UtcNow)
                    : CreateCanceledStepResult(step, index, DateTimeOffset.UtcNow, TimeSpan.Zero);
                primaryFailureResult = canceledResult;
                liveResults.Add(canceledResult);

                if (cleanupAvailable)
                {
                    cleanupMode = true;
                    PublishProgress(
                        runbook,
                        options,
                        SandboxRunbookProgressStates.Running,
                        startedAtUtc,
                        attemptTimer.Elapsed,
                        liveResults,
                        index,
                        success: null,
                        message: "Runbook cancellation was recorded; attempting VM cleanup before returning the canceled result.");
                    if (!currentStepIsCleanup)
                    {
                        continue;
                    }
                }
                else
                {
                    PublishProgress(
                        runbook,
                        options,
                        SandboxRunbookProgressStates.Canceled,
                        startedAtUtc,
                        attemptTimer.Elapsed,
                        liveResults,
                        index,
                        success: false,
                        message: "Runbook execution was canceled before this step started.");
                    break;
                }
            }

            PublishProgress(
                runbook,
                options,
                SandboxRunbookProgressStates.Running,
                startedAtUtc,
                attemptTimer.Elapsed,
                liveResults,
                index,
                success: null,
                message: cleanupMode
                    ? BuildRunningCleanupStepMessage(step, index, runbook.Steps.Count, primaryFailureResult)
                    : BuildRunningStepMessage(step, index, runbook.Steps.Count, options.StepTimeout));

            if (step.MutatesVmState)
            {
                vmMutationAttempted = true;
            }

            var stepResult = await ExecutePowerShellStepAsync(
                step,
                index,
                runbook.Steps.Count,
                options,
                heartbeatMessage => PublishProgress(
                    runbook,
                    options,
                    SandboxRunbookProgressStates.Running,
                    startedAtUtc,
                    attemptTimer.Elapsed,
                    liveResults,
                    index,
                    success: null,
                    message: heartbeatMessage),
                cleanupMode ? CancellationToken.None : cancellationToken).ConfigureAwait(false);
            liveResults.Add(stepResult);

            if (!stepResult.Success)
            {
                if (failedStepIndex is null)
                {
                    failedStepIndex = index;
                    primaryFailureResult = stepResult;
                    wasCanceled = RunbookProgressFacts.IsCanceledStepResult(stepResult);

                    if (!IsCleanupStep(step) &&
                        vmMutationAttempted &&
                        HasRemainingCleanupSteps(runbook, index + 1))
                    {
                        cleanupMode = true;
                        PublishProgress(
                            runbook,
                            options,
                            SandboxRunbookProgressStates.Running,
                            startedAtUtc,
                            attemptTimer.Elapsed,
                            liveResults,
                            index,
                            success: null,
                            message: $"Step {index + 1} failed; attempting VM cleanup now. Primary failure remains: {stepResult.Message ?? step.Title}");
                        continue;
                    }
                }
                else if (cleanupMode)
                {
                    PublishProgress(
                        runbook,
                        options,
                        SandboxRunbookProgressStates.Running,
                        startedAtUtc,
                        attemptTimer.Elapsed,
                        liveResults,
                        index,
                        success: null,
                        message: $"Cleanup step '{step.Title}' failed after the primary failure and was recorded separately: {stepResult.Message}");
                    continue;
                }

                PublishProgress(
                    runbook,
                    options,
                    SandboxRunbookProgressStates.Failed,
                    startedAtUtc,
                    attemptTimer.Elapsed,
                    liveResults,
                    index,
                    success: false,
                    message: stepResult.Message ?? $"Runbook step {index + 1} failed.");
                break;
            }

            PublishProgress(
                runbook,
                options,
                SandboxRunbookProgressStates.Running,
                startedAtUtc,
                attemptTimer.Elapsed,
                liveResults,
                index,
                success: null,
                message: BuildCompletedStepMessage(step, index, runbook.Steps.Count, stepResult.Duration));
        }

        attemptTimer.Stop();
        var success = failedStepIndex is null && liveResults.Count == runbook.Steps.Count;
        var message = success ? null : BuildLiveFailureMessage(runbook, liveResults, failedStepIndex, wasCanceled);
        var terminalState = success
            ? SandboxRunbookProgressStates.Completed
            : wasCanceled
                ? SandboxRunbookProgressStates.Canceled
                : SandboxRunbookProgressStates.Failed;

        PublishProgress(
            runbook,
            options,
            terminalState,
            startedAtUtc,
            attemptTimer.Elapsed,
            liveResults,
            failedStepIndex ?? (runbook.Steps.Count > 0 ? Math.Min(liveResults.Count, runbook.Steps.Count) - 1 : null),
            success,
            message ?? (success ? "Live runbook execution completed." : "Live runbook execution failed."));

        return CreateAggregateResult(
            runbook,
            options,
            liveResults,
            success,
            failedStepIndex,
            startedAtUtc,
            attemptTimer.Elapsed,
            message,
            requiresElevation);
    }

    /// <summary>
    /// Launches PowerShell for one runbook step and captures its result.
    /// Inputs are one step, its index, live execution options, and cancellation;
    /// processing starts a redirected PowerShell process with an encoded script,
    /// waits for completion or timeout, and kills the process tree on timeout or
    /// cancellation; the method returns stdout, stderr, exit code, and duration.
    /// </summary>
    private static async Task<SandboxRunbookStepExecutionResult> ExecutePowerShellStepAsync(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        SandboxRunbookExecutionOptions options,
        Action<string>? heartbeat,
        CancellationToken cancellationToken)
    {
        var startedAtUtc = DateTimeOffset.UtcNow;
        var stepTimer = Stopwatch.StartNew();
        using var process = new Process
        {
            StartInfo = CreatePowerShellStartInfo(step.PowerShell, options)
        };

        Task<string>? stdoutTask = null;
        Task<string>? stderrTask = null;

        try
        {
            if (!process.Start())
            {
                stepTimer.Stop();
                var facts = RunbookProgressFacts.DescribeStep(step, stepIndex, totalSteps);
                return CreateStepResult(
                    step,
                    stepIndex,
                    skipped: false,
                    success: false,
                    exitCode: null,
                    stdout: string.Empty,
                    stderr: string.Empty,
                    startedAtUtc: startedAtUtc,
                    duration: stepTimer.Elapsed,
                    message: $"PowerShell process did not start for step {facts.Ordinal}. 修复建议：确认 PowerShell 可执行文件路径有效、宿主权限满足要求。");
            }

            stdoutTask = process.StandardOutput.ReadToEndAsync();
            stderrTask = process.StandardError.ReadToEndAsync();

            if (options.StepTimeout > TimeSpan.Zero)
            {
                var exitedBeforeTimeout = await WaitForProcessExitWithHeartbeatAsync(
                    process,
                    step,
                    stepIndex,
                    totalSteps,
                    options.StepTimeout,
                    stepTimer,
                    heartbeat,
                    cancellationToken).ConfigureAwait(false);

                if (!exitedBeforeTimeout)
                {
                    TryKillProcessTree(process);
                    await WaitForExitAfterKillAsync(process).ConfigureAwait(false);
                    var timedOutOutput = await CollectOutputAsync(stdoutTask, stderrTask).ConfigureAwait(false);

                    stepTimer.Stop();
                    var facts = RunbookProgressFacts.DescribeStep(step, stepIndex, totalSteps);
                    var timedOutMessage = cancellationToken.IsCancellationRequested
                        ? $"PowerShell step {facts.Ordinal} was canceled before completion. 修复建议：确认是否为操作者主动取消；如需重跑，请先检查 VM 清理状态。"
                        : $"{RunbookProgressFacts.BuildStepPrefix(step, stepIndex, totalSteps)} exceeded the per-step timeout of {FormatDuration(options.StepTimeout)}. 修复建议：{facts.RemediationHintZh}";

                    return CreateStepResult(
                        step,
                        stepIndex,
                        skipped: false,
                        success: false,
                        exitCode: SafeExitCode(process),
                        stdout: timedOutOutput.StandardOutput,
                        stderr: timedOutOutput.StandardError,
                        startedAtUtc: startedAtUtc,
                        duration: stepTimer.Elapsed,
                        message: timedOutMessage);
                }

            }
            else
            {
                await WaitForProcessExitWithoutTimeoutAsync(
                    process,
                    step,
                    stepIndex,
                    totalSteps,
                    stepTimer,
                    heartbeat,
                    cancellationToken).ConfigureAwait(false);
            }

            var output = await CollectOutputAsync(stdoutTask, stderrTask).ConfigureAwait(false);
            var exitCode = SafeExitCode(process);
            var success = exitCode == 0;

            stepTimer.Stop();
            return CreateStepResult(
                step,
                stepIndex,
                skipped: false,
                success: success,
                exitCode: exitCode,
                stdout: output.StandardOutput,
                stderr: output.StandardError,
                startedAtUtc: startedAtUtc,
                duration: stepTimer.Elapsed,
                message: success ? null : BuildStepFailureMessage(step, stepIndex, totalSteps, exitCode));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryKillProcessTree(process);
            await WaitForExitAfterKillAsync(process).ConfigureAwait(false);
            var canceledOutput = await CollectOutputAsync(stdoutTask, stderrTask).ConfigureAwait(false);

            stepTimer.Stop();
            return CreateStepResult(
                step,
                stepIndex,
                skipped: false,
                success: false,
                exitCode: SafeExitCode(process),
                stdout: canceledOutput.StandardOutput,
                stderr: canceledOutput.StandardError,
                startedAtUtc: startedAtUtc,
                duration: stepTimer.Elapsed,
                message: $"PowerShell step {RunbookProgressFacts.FormatOrdinal(stepIndex, totalSteps)} was canceled before completion. 修复建议：确认是否为操作者主动取消；如需重跑，请先检查 VM 清理状态。");
        }
        catch (Exception ex)
        {
            TryKillProcessTree(process);
            await WaitForExitAfterKillAsync(process).ConfigureAwait(false);
            var failedOutput = await CollectOutputAsync(stdoutTask, stderrTask).ConfigureAwait(false);

            stepTimer.Stop();
            return CreateStepResult(
                step,
                stepIndex,
                skipped: false,
                success: false,
                exitCode: SafeExitCode(process),
                stdout: failedOutput.StandardOutput,
                stderr: failedOutput.StandardError,
                startedAtUtc: startedAtUtc,
                duration: stepTimer.Elapsed,
                message: $"{RunbookProgressFacts.BuildStepPrefix(step, stepIndex, totalSteps)} failed before or during PowerShell launch: {ex.Message}. 修复建议：确认 PowerShell 可执行文件路径、工作目录和宿主权限。");
        }
    }

    /// <summary>
    /// Waits for a launched PowerShell process and emits low-frequency progress
    /// heartbeats while the step is still active. Inputs are the process, step,
    /// timeout, elapsed timer, heartbeat callback, and cancellation token;
    /// processing polls at a bounded cadence without reading stdout/stderr; the
    /// return value is false only when the configured timeout elapsed.
    /// </summary>
    private static async Task<bool> WaitForProcessExitWithHeartbeatAsync(
        Process process,
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        TimeSpan timeout,
        Stopwatch stepTimer,
        Action<string>? heartbeat,
        CancellationToken cancellationToken)
    {
        var waitTask = process.WaitForExitAsync(cancellationToken);
        while (true)
        {
            var remaining = timeout - stepTimer.Elapsed;
            if (remaining <= TimeSpan.Zero)
            {
                return false;
            }

            var delay = Min(StepHeartbeatInterval, remaining);
            var delayTask = Task.Delay(delay, cancellationToken);
            var completedTask = await Task.WhenAny(waitTask, delayTask).ConfigureAwait(false);
            if (completedTask == waitTask)
            {
                await waitTask.ConfigureAwait(false);
                return true;
            }

            await delayTask.ConfigureAwait(false);
            if (stepTimer.Elapsed < timeout)
            {
                heartbeat?.Invoke(BuildStepHeartbeatMessage(step, stepIndex, totalSteps, stepTimer.Elapsed, timeout));
            }
        }
    }

    /// <summary>
    /// Waits for a launched PowerShell process when the caller disabled the
    /// per-step timeout. Inputs are the process, step, elapsed timer, heartbeat
    /// callback, and cancellation token; processing emits sparse progress so
    /// long VM operations do not look hung; return value is a completed task.
    /// </summary>
    private static async Task WaitForProcessExitWithoutTimeoutAsync(
        Process process,
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        Stopwatch stepTimer,
        Action<string>? heartbeat,
        CancellationToken cancellationToken)
    {
        var waitTask = process.WaitForExitAsync(cancellationToken);
        while (true)
        {
            var delayTask = Task.Delay(StepHeartbeatInterval, cancellationToken);
            var completedTask = await Task.WhenAny(waitTask, delayTask).ConfigureAwait(false);
            if (completedTask == waitTask)
            {
                await waitTask.ConfigureAwait(false);
                return;
            }

            await delayTask.ConfigureAwait(false);
            heartbeat?.Invoke(BuildStepHeartbeatMessage(step, stepIndex, totalSteps, stepTimer.Elapsed, timeout: null));
        }
    }

    /// <summary>
    /// Builds the first live-progress sentence for a step.
    /// Inputs are step metadata, position, total count, and timeout; processing
    /// adds short operator context for long provider startup and guest-session phases;
    /// the returned message is safe for dashboard progress.
    /// </summary>
    private static string BuildRunningStepMessage(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        TimeSpan stepTimeout)
    {
        var timeoutText = stepTimeout > TimeSpan.Zero
            ? $" Timeout: {FormatDuration(stepTimeout)}."
            : " No per-step timeout is configured.";
        return $"{RunbookProgressFacts.BuildStepPrefix(step, stepIndex, totalSteps)}: {DescribeStepForOperator(step)}{timeoutText}";
    }

    /// <summary>
    /// Builds the first progress sentence for a cleanup step that runs after a
    /// primary failure. Inputs are step metadata, position, total count, and the
    /// primary failure; processing keeps the original failure visible; the
    /// returned text is safe for dashboard progress.
    /// </summary>
    private static string BuildRunningCleanupStepMessage(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        SandboxRunbookStepExecutionResult? primaryFailure)
    {
        var failureText = primaryFailure is null
            ? "the earlier failure"
            : $"step {primaryFailure.StepIndex + 1} ({primaryFailure.Title})";
        return $"Cleanup {RunbookProgressFacts.BuildStepPrefix(step, stepIndex, totalSteps)}: {DescribeStepForOperator(step)}. Preserving primary failure from {failureText}.";
    }

    /// <summary>
    /// Builds a sparse heartbeat message for a still-running step.
    /// Inputs are the step, elapsed time, and optional timeout; processing
    /// describes the current wait without dumping command text or streams; the
    /// returned message is safe for WebUI and CLI summaries.
    /// </summary>
    private static string BuildStepHeartbeatMessage(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        TimeSpan elapsed,
        TimeSpan? timeout)
    {
        var timeoutText = timeout is { } value
            ? $", timeout {FormatDuration(value)}"
            : ", no per-step timeout";
        return $"Still working on {RunbookProgressFacts.BuildStepPrefix(step, stepIndex, totalSteps)}: {step.Title} ({FormatDuration(elapsed)} elapsed{timeoutText}). {BuildLongStepHint(step)}";
    }

    /// <summary>
    /// Builds the successful completion progress sentence for one step.
    /// Inputs are step metadata, position, total count, and elapsed duration;
    /// processing avoids command text and returns a compact status line.
    /// </summary>
    private static string BuildCompletedStepMessage(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        TimeSpan duration)
    {
        return $"Finished {RunbookProgressFacts.BuildStepPrefix(step, stepIndex, totalSteps)}: {step.Title} ({FormatDuration(duration)}).";
    }

    /// <summary>
    /// Converts known runbook step identifiers into human-readable operator
    /// intent. Inputs are source step metadata; processing keeps unknown steps
    /// on their title; the returned text avoids PowerShell command details.
    /// </summary>
    private static string DescribeStepForOperator(SandboxRunbookStep step)
    {
        return step.Id switch
        {
            "start-temp-vm" or "start-golden" or "start-vm" =>
                $"{step.Title}; waiting for the selected virtualization provider to finish VM startup",
            "wait-powershell-direct" =>
                $"{step.Title}; waiting for the guest OS to accept PowerShell Direct logon",
            "wait-guest-remoting" =>
                $"{step.Title}; waiting for the guest OS to accept WinRM logon",
            "sync-live-output" =>
                $"{step.Title}; copying partial guest output while the Guest Agent runs",
            "collect-output" =>
                $"{step.Title}; copying the final guest output tree to the host",
            "stop-vm" or "remove-temp-vm" =>
                $"{step.Title}; cleanup is best-effort and any cleanup error will be reported separately",
            _ => step.Title
        };
    }

    /// <summary>
    /// Builds context shown in heartbeat messages for slow phases.
    /// Input is a runbook step; processing maps known provider waits to practical
    /// operator expectations; the method returns a short sentence.
    /// </summary>
    private static string BuildLongStepHint(SandboxRunbookStep step)
    {
        return step.Id switch
        {
            "start-temp-vm" or "start-golden" or "start-vm" =>
                "VM boot can take a few minutes after baseline restore. 修复建议：若持续超时，请检查所选 provider 管理工具、VM 状态、干净基线和启动参数。",
            "wait-powershell-direct" =>
                "The VM may already be running while the guest service and credentials are still becoming ready. 修复建议：检查来宾服务接口、账号密码和系统登录初始化。",
            "wait-guest-remoting" =>
                "The VM may already be running while WinRM is still becoming ready. 修复建议：检查地址、端口、SSL、认证、TrustedHosts/证书和来宾账号密码；VMwareTools/QemuUserNat 自动端点要求 baseline 已配置 HTTPS listener。",
            "sync-live-output" =>
                "Output copy failures are throttled; the final copy will report the first actionable error. 修复建议：检查 agent 标记文件、会话稳定性和宿主输出目录权限。",
            "collect-output" =>
                "If this fails, check the guest output directory, guest PowerShell session, and required marker files. 修复建议：确认 events.json、agent.pid、agent.exit 均已生成。",
            _ => "No command output is streamed here; full stdout/stderr remains in the execution record. 修复建议：如步骤卡住，请检查宿主权限、VM 状态和完整执行记录。"
        };
    }

    /// <summary>
    /// Determines whether later steps include VM cleanup work.
    /// Inputs are a runbook and start index; processing scans stable cleanup
    /// step identifiers; return value decides whether to continue after a
    /// primary failure.
    /// </summary>
    private static bool HasRemainingCleanupSteps(SandboxRunbook runbook, int startIndex)
    {
        for (var index = Math.Max(0, startIndex); index < runbook.Steps.Count; index++)
        {
            if (IsCleanupStep(runbook.Steps[index]))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Identifies cleanup steps by stable runbook identifiers.
    /// Input is one planned step; processing avoids relying on localized title
    /// text; the returned value is true for stop/remove/restore cleanup steps.
    /// </summary>
    private static bool IsCleanupStep(SandboxRunbookStep step)
    {
        return IsCleanupStepId(step.Id);
    }

    /// <summary>
    /// Identifies cleanup steps by result step id.
    /// Input is a step id; processing handles both C# and script E2E naming;
    /// the returned value is true for cleanup/stop/remove/restore tail steps.
    /// </summary>
    private static bool IsCleanupStepId(string? stepId)
    {
        return RunbookProgressFacts.IsCleanupStepId(stepId);
    }

    /// <summary>
    /// Formats a duration for operator-facing progress.
    /// Input is a TimeSpan; processing rounds to seconds and keeps the value
    /// compact; the returned string is culture-invariant enough for logs.
    /// </summary>
    private static string FormatDuration(TimeSpan duration)
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

    private static TimeSpan Min(TimeSpan left, TimeSpan right)
    {
        return left <= right ? left : right;
    }

    /// <summary>
    /// Builds ProcessStartInfo for a single PowerShell step.
    /// Inputs are command text and executor options; processing wraps the command
    /// in a fail-fast script, encodes it for PowerShell, and applies environment
    /// overrides; the configured start info is returned to the caller.
    /// </summary>
    private static ProcessStartInfo CreatePowerShellStartInfo(string powerShell, SandboxRunbookExecutionOptions options)
    {
        var encodedCommand = BuildEncodedCommand(powerShell);
        var startInfo = new ProcessStartInfo
        {
            FileName = options.PowerShellExecutablePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        if (!string.IsNullOrWhiteSpace(options.WorkingDirectory))
        {
            startInfo.WorkingDirectory = options.WorkingDirectory;
        }

        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encodedCommand);

        SanitizeInheritedSecretEnvironment(startInfo);
        foreach (var item in options.EnvironmentVariables)
        {
            if (string.IsNullOrWhiteSpace(item.Key))
            {
                continue;
            }

            if (item.Value is null)
            {
                startInfo.Environment.Remove(item.Key);
            }
            else
            {
                startInfo.Environment[item.Key] = item.Value;
            }
        }

        return startInfo;
    }

    private static void SanitizeInheritedSecretEnvironment(ProcessStartInfo startInfo)
    {
        foreach (var name in startInfo.Environment.Keys.ToArray())
        {
            if (name.StartsWith("KSWORDBOX_", StringComparison.OrdinalIgnoreCase) ||
                SensitiveEnvironmentNamePattern.IsMatch(name))
            {
                startInfo.Environment.Remove(name);
            }
        }
    }

    /// <summary>
    /// Encodes a PowerShell command using the UTF-16 format required by
    /// -EncodedCommand.
    /// Input is raw step PowerShell; processing wraps it with error handling and
    /// Base64 encodes it; the returned string is safe to pass as one argument.
    /// </summary>
    private static string BuildEncodedCommand(string powerShell)
    {
        var script = BuildFailFastScript(powerShell);
        return Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
    }

    /// <summary>
    /// Wraps step PowerShell in a script that produces deterministic exit codes.
    /// Input is the runbook command; processing sets ErrorActionPreference,
    /// executes the command, maps native LASTEXITCODE failures, and catches
    /// terminating PowerShell errors; the returned script is executed by the
    /// child PowerShell process.
    /// </summary>
    private static string BuildFailFastScript(string powerShell)
    {
        const string newLine = "\r\n";
        var command = IndentPowerShell(powerShell, newLine);

        return string.Join(
            newLine,
            new[]
            {
                "$ErrorActionPreference = 'Stop'",
                "$global:LASTEXITCODE = 0",
                "try {",
                command,
                "    if ($global:LASTEXITCODE -is [int] -and $global:LASTEXITCODE -ne 0) {",
                "        exit $global:LASTEXITCODE",
                "    }",
                "    exit 0",
                "}",
                "catch {",
                "    Write-Error -ErrorRecord $_",
                "    exit 1",
                "}"
            });
    }

    /// <summary>
    /// Indents raw PowerShell so it can be placed inside a try block.
    /// Input is command text and the desired newline; processing normalizes
    /// line endings and prefixes each line; the returned text preserves command
    /// content while improving generated script readability.
    /// </summary>
    private static string IndentPowerShell(string powerShell, string newLine)
    {
        var normalized = powerShell
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');

        var lines = normalized.Split('\n');
        return string.Join(newLine, lines.Select(line => $"    {line}"));
    }

    /// <summary>
    /// Creates a dry-run result for one source step.
    /// Inputs are the source step, index, and attempt start time; processing
    /// records the command without execution; the returned result is successful,
    /// skipped, and has no stdout, stderr, or exit code.
    /// </summary>
    private static SandboxRunbookStepExecutionResult CreateDryRunStepResult(
        SandboxRunbookStep step,
        int stepIndex,
        DateTimeOffset startedAtUtc)
    {
        return CreateStepResult(
            step,
            stepIndex,
            skipped: true,
            success: true,
            exitCode: null,
            stdout: string.Empty,
            stderr: string.Empty,
            startedAtUtc: startedAtUtc,
            duration: TimeSpan.Zero,
            message: DryRunMessage);
    }

    /// <summary>
    /// Creates a cancellation result before launching a source step.
    /// Inputs are the source step, index, start time, and elapsed duration;
    /// processing marks the step as failed but not skipped because live execution
    /// was requested; the returned result stops aggregate execution.
    /// </summary>
    private static SandboxRunbookStepExecutionResult CreateCanceledStepResult(
        SandboxRunbookStep step,
        int stepIndex,
        DateTimeOffset startedAtUtc,
        TimeSpan duration)
    {
        return CreateStepResult(
            step,
            stepIndex,
            skipped: false,
            success: false,
            exitCode: null,
            stdout: string.Empty,
            stderr: string.Empty,
            startedAtUtc: startedAtUtc,
            duration: duration,
            message: "Runbook execution was canceled before this step started.");
    }

    /// <summary>
    /// Records cancellation observed exactly at the cleanup boundary without
    /// consuming the cleanup step's source index. The current cleanup step can
    /// then execute with a non-cancelable token while aggregate state remains
    /// canceled.
    /// </summary>
    private static SandboxRunbookStepExecutionResult CreateCancellationBeforeCleanupStepResult(
        SandboxRunbookStep cleanupStep,
        DateTimeOffset startedAtUtc)
    {
        return new SandboxRunbookStepExecutionResult
        {
            StepIndex = -1,
            StepId = "cancellation-before-cleanup",
            Title = $"Cancellation before cleanup: {cleanupStep.Title}",
            PowerShell = string.Empty,
            Skipped = false,
            Success = false,
            ExitCode = null,
            StandardOutput = string.Empty,
            StandardError = string.Empty,
            StartedAtUtc = startedAtUtc,
            Duration = TimeSpan.Zero,
            RequiresElevation = false,
            MutatesVmState = false,
            Message = "Runbook execution was canceled at the cleanup boundary; the current and remaining cleanup steps continue without cancellation."
        };
    }

    /// <summary>
    /// Creates a skipped result for a non-cleanup step after a primary failure.
    /// Inputs are the source step, index, and primary failure; processing keeps
    /// the skipped step visible in progress without converting it into another
    /// failure; the returned result does not mask the primary failed step.
    /// </summary>
    private static SandboxRunbookStepExecutionResult CreateSkippedAfterFailureStepResult(
        SandboxRunbookStep step,
        int stepIndex,
        SandboxRunbookStepExecutionResult? primaryFailure)
    {
        var message = primaryFailure is null
            ? "Skipped because an earlier runbook step failed."
            : $"Skipped because step {primaryFailure.StepIndex + 1} failed: {primaryFailure.Title}.";
        return CreateStepResult(
            step,
            stepIndex,
            skipped: true,
            success: true,
            exitCode: null,
            stdout: string.Empty,
            stderr: string.Empty,
            startedAtUtc: DateTimeOffset.UtcNow,
            duration: TimeSpan.Zero,
            message: message);
    }

    /// <summary>
    /// Creates a synthetic result when live execution is blocked by elevation.
    /// Inputs are the attempt start time; processing records the missing
    /// elevated PowerShell requirement without running any VM command; the
    /// returned failed result explains the preflight stop.
    /// </summary>
    private static SandboxRunbookStepExecutionResult CreateElevationFailureStepResult(DateTimeOffset startedAtUtc)
    {
        return new SandboxRunbookStepExecutionResult
        {
            StepIndex = -1,
            StepId = "elevation-check",
            Title = "Verify elevated PowerShell host",
            PowerShell = "Start the host process from an elevated PowerShell session before selecting live mode.",
            Skipped = true,
            Success = false,
            ExitCode = null,
            StandardOutput = string.Empty,
            StandardError = string.Empty,
            StartedAtUtc = startedAtUtc,
            Duration = TimeSpan.Zero,
            RequiresElevation = true,
            MutatesVmState = false,
            Message = ElevationFailureMessage
        };
    }

    /// <summary>
    /// Acquires the runtime-root-wide live execution lease. The returned stream
    /// remains open for the complete provider run, including failure cleanup;
    /// FileShare.None supplies cross-process exclusion and process termination
    /// releases the operating-system handle automatically.
    /// </summary>
    private static FileStream AcquireLiveExecutionLease(SandboxRunbook runbook)
    {
        if (string.IsNullOrWhiteSpace(runbook.LiveExecutionLeasePath))
        {
            throw new InvalidOperationException("The persisted runbook does not contain a live execution lease path.");
        }

        var leasePath = runbook.LiveExecutionLeasePath;
        leasePath = Path.GetFullPath(leasePath);
        var leaseDirectory = Path.GetDirectoryName(leasePath);
        if (string.IsNullOrWhiteSpace(leaseDirectory))
        {
            throw new IOException("The live execution lease path does not have a parent directory.");
        }

        Directory.CreateDirectory(leaseDirectory);
        return new FileStream(
            leasePath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            bufferSize: 1,
            FileOptions.None);
    }

    private static bool IsLiveExecutionLeaseFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException or InvalidOperationException;

    /// <summary>
    /// Records a live preflight failure without exposing host exception details
    /// or pretending that a source runbook step was launched.
    /// </summary>
    private static SandboxRunbookStepExecutionResult CreateLiveExecutionLeaseFailureStepResult(
        DateTimeOffset startedAtUtc,
        Exception exception)
    {
        var message = exception is InvalidOperationException
            ? "This persisted runbook predates the live execution lease contract. No provider command was executed. 修复建议：为该样本重新创建 plan 后再执行 live；旧任务仍可用于 status、report 和 artifact recovery。"
            : $"{LiveExecutionLeaseFailureMessage} {(exception is IOException ? "The lease is already held or the lock file cannot be opened." : "The runtime lock path is not accessible.")}";
        return new SandboxRunbookStepExecutionResult
        {
            StepIndex = -1,
            StepId = "live-execution-lease",
            Title = "Acquire exclusive live execution lease",
            PowerShell = string.Empty,
            Skipped = false,
            Success = false,
            ExitCode = null,
            StandardOutput = string.Empty,
            StandardError = string.Empty,
            StartedAtUtc = startedAtUtc,
            Duration = TimeSpan.Zero,
            RequiresElevation = false,
            MutatesVmState = false,
            Message = message
        };
    }

    /// <summary>
    /// Creates a normalized result for a source runbook step.
    /// Inputs are source step metadata, execution status, output, timing, and
    /// message; processing copies stable fields from the step and status values
    /// from execution; the returned record is safe for reports or persistence.
    /// </summary>
    private static SandboxRunbookStepExecutionResult CreateStepResult(
        SandboxRunbookStep step,
        int stepIndex,
        bool skipped,
        bool success,
        int? exitCode,
        string stdout,
        string stderr,
        DateTimeOffset startedAtUtc,
        TimeSpan duration,
        string? message)
    {
        return new SandboxRunbookStepExecutionResult
        {
            StepIndex = stepIndex,
            StepId = step.Id,
            Title = step.Title,
            PowerShell = step.PowerShell,
            Skipped = skipped,
            Success = success,
            ExitCode = exitCode,
            StandardOutput = stdout,
            StandardError = stderr,
            StartedAtUtc = startedAtUtc,
            Duration = duration,
            RequiresElevation = step.RequiresElevation,
            MutatesVmState = step.MutatesVmState,
            Message = message
        };
    }

    /// <summary>
    /// Creates the aggregate result returned to callers.
    /// Inputs are the runbook, options, captured step results, status, timing,
    /// and elevation flag; processing counts launched steps and copies stable
    /// runbook identity; the returned result summarizes the execution attempt.
    /// </summary>
    private static SandboxRunbookExecutionResult CreateAggregateResult(
        SandboxRunbook runbook,
        SandboxRunbookExecutionOptions options,
        IReadOnlyList<SandboxRunbookStepExecutionResult> stepResults,
        bool success,
        int? failedStepIndex,
        DateTimeOffset startedAtUtc,
        TimeSpan duration,
        string? message,
        bool requiresElevation)
    {
        return new SandboxRunbookExecutionResult
        {
            JobId = runbook.JobId,
            Provider = runbook.Provider,
            TargetVmName = runbook.TargetVmName,
            BaselineName = runbook.BaselineName,
            MachineDefinitionPath = runbook.MachineDefinitionPath,
            QemuDiskFormat = runbook.QemuDiskFormat,
            Mode = options.Mode,
            Success = success,
            TotalSteps = runbook.Steps.Count,
            ExecutedSteps = stepResults.Count(step => !step.Skipped && step.StepIndex >= 0),
            FailedStepIndex = failedStepIndex,
            StartedAtUtc = startedAtUtc,
            Duration = duration,
            RequiresElevation = requiresElevation,
            StepResults = stepResults,
            Message = message
        };
    }

    /// <summary>
    /// Builds a concise per-step failure message for reports and progress.
    /// Inputs are step metadata and exit status; processing deliberately avoids
    /// copying stdout/stderr or command text, while pointing operators to the
    /// full execution record when they need raw evidence.
    /// </summary>
    private static string BuildStepFailureMessage(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        int? exitCode)
    {
        var facts = RunbookProgressFacts.DescribeStep(step, stepIndex, totalSteps);
        var exitText = exitCode is null
            ? "PowerShell failed before a process exit code was available"
            : $"PowerShell exited with code {exitCode.Value}";
        return $"{exitText} at step {facts.Ordinal} [phase={facts.Phase}; category={facts.Category}]. 修复建议：{facts.RemediationHintZh} UI 进度不会包含 stdout/stderr；完整输出保留在 runbook-execution.json。";
    }

    /// <summary>
    /// Builds the aggregate live-mode failure message.
    /// Inputs are the source runbook, collected results, failure index, and
    /// cancellation flag; processing includes the failed step title and concise
    /// reason without exposing long commands; the returned string is stored on
    /// the aggregate result and terminal progress snapshot.
    /// </summary>
    private static string? BuildLiveFailureMessage(
        SandboxRunbook runbook,
        IReadOnlyList<SandboxRunbookStepExecutionResult> results,
        int? failedStepIndex,
        bool wasCanceled)
    {
        if (failedStepIndex is null)
        {
            return wasCanceled ? "Live runbook execution was canceled." : null;
        }

        var failedResult = wasCanceled
            ? results.FirstOrDefault(RunbookProgressFacts.IsCanceledStepResult)
            : results.LastOrDefault(result => result.StepIndex == failedStepIndex.Value);
        var stepTitle = failedResult?.Title;
        if (string.IsNullOrWhiteSpace(stepTitle) &&
            failedStepIndex.Value >= 0 &&
            failedStepIndex.Value < runbook.Steps.Count)
        {
            stepTitle = runbook.Steps[failedStepIndex.Value].Title;
        }

        var reason = failedResult is null ? null : BuildSafeFailureReason(failedResult);
        var prefix = wasCanceled
            ? $"Live runbook execution was canceled at step {failedStepIndex.Value + 1}"
            : $"Live runbook execution stopped at step {failedStepIndex.Value + 1}";
        if (!string.IsNullOrWhiteSpace(stepTitle))
        {
            prefix += $": {stepTitle}";
        }

        var primaryMessage = string.IsNullOrWhiteSpace(reason)
            ? $"{prefix}."
            : $"{prefix}. Failure reason: {reason}";
        var cleanupFailures = results
            .Where(result => !result.Success &&
                IsCleanupStepId(result.StepId) &&
                (wasCanceled || result.StepIndex != failedStepIndex.Value))
            .Select(result => $"{result.Title}: {BuildSafeFailureReason(result)}")
            .Take(3)
            .ToList();

        return cleanupFailures.Count == 0
            ? primaryMessage
            : $"{primaryMessage} Cleanup also reported {cleanupFailures.Count} failure(s), recorded separately: {string.Join("; ", cleanupFailures)}";
    }

    private static string BuildSafeFailureReason(SandboxRunbookStepExecutionResult result)
    {
        if (RunbookProgressFacts.IsCanceledStepResult(result))
        {
            return "The step was canceled before completion.";
        }

        return result.ExitCode.HasValue
            ? $"PowerShell exited with code {result.ExitCode.Value}; stdout/stderr are omitted from progress and retained in runbook-execution.json."
            : "PowerShell did not return a normal exit code; stdout/stderr are omitted from progress and retained in runbook-execution.json.";
    }

    /// <summary>
    /// Emits one UI-safe progress snapshot when a caller supplied a progress
    /// sink. Inputs are the runbook, execution state, current result list, and
    /// optional message; processing builds compact per-step status without
    /// PowerShell/stdout/stderr; the method returns no value.
    /// </summary>
    private static void PublishProgress(
        SandboxRunbook runbook,
        SandboxRunbookExecutionOptions options,
        string state,
        DateTimeOffset startedAtUtc,
        TimeSpan duration,
        IReadOnlyList<SandboxRunbookStepExecutionResult> results,
        int? currentStepIndex,
        bool? success,
        string? message)
    {
        var sink = options.ProgressSink;
        if (sink is null)
        {
            return;
        }

        var snapshot = CreateProgressSnapshot(
            runbook,
            options,
            state,
            startedAtUtc,
            duration,
            results,
            currentStepIndex,
            success,
            message);
        sink.Report(snapshot);
    }

    /// <summary>
    /// Builds a UI-safe progress snapshot. Inputs are the source runbook and
    /// result list produced so far; processing derives pending/running/
    /// completed/failed state for every step; the snapshot is returned to the
    /// caller for storage or streaming.
    /// </summary>
    private static SandboxRunbookProgressSnapshot CreateProgressSnapshot(
        SandboxRunbook runbook,
        SandboxRunbookExecutionOptions options,
        string state,
        DateTimeOffset startedAtUtc,
        TimeSpan duration,
        IReadOnlyList<SandboxRunbookStepExecutionResult> results,
        int? currentStepIndex,
        bool? success,
        string? message)
    {
        var resultByIndex = results
            .Where(result => result.StepIndex >= 0)
            .GroupBy(result => result.StepIndex)
            .ToDictionary(group => group.Key, group => group.Last());
        var steps = runbook.Steps
            .Select((step, index) => CreateStepProgressSnapshot(step, index, runbook.Steps.Count, resultByIndex, state, currentStepIndex))
            .ToList();
        var preflightFailure = results.LastOrDefault(RunbookProgressFacts.IsPreflightFailureResult);
        var resolvedCurrentStepIndex = preflightFailure is null
            ? RunbookProgressFacts.ResolveCurrentStepIndex(steps, currentStepIndex, state, success)
            : null;
        var currentStep = resolvedCurrentStepIndex is >= 0
            ? steps.FirstOrDefault(step => step.StepIndex == resolvedCurrentStepIndex.Value)
            : null;

        return new SandboxRunbookProgressSnapshot
        {
            JobId = runbook.JobId,
            Provider = runbook.Provider,
            TargetVmName = runbook.TargetVmName,
            BaselineName = runbook.BaselineName,
            MachineDefinitionPath = runbook.MachineDefinitionPath,
            QemuDiskFormat = runbook.QemuDiskFormat,
            Mode = options.Mode,
            State = state,
            TotalSteps = runbook.Steps.Count,
            CompletedSteps = steps.Count(step => RunbookProgressFacts.CountsAsCompletedStep(step.State)),
            ExecutedSteps = results.Count(step => !step.Skipped && step.StepIndex >= 0),
            CurrentStepIndex = currentStep is null ? null : resolvedCurrentStepIndex,
            CurrentStepId = preflightFailure?.StepId ?? currentStep?.StepId,
            CurrentStepTitle = preflightFailure?.Title ?? currentStep?.Title,
            CurrentPhase = preflightFailure is null ? currentStep?.Phase : "preflight",
            CurrentCategory = preflightFailure is null ? currentStep?.Category : RunbookProgressFacts.GetPreflightFailureCategory(preflightFailure.StepId),
            ProgressPercent = RunbookProgressFacts.ComputeProgressPercent(steps, state, success, runbook.Steps.Count),
            Success = success,
            Message = message,
            StartedAtUtc = startedAtUtc,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            Duration = duration,
            Steps = steps
        };
    }

    /// <summary>
    /// Builds one progress row for the dashboard. Inputs are source step
    /// metadata, result lookup, aggregate state, and current index; processing
    /// never copies PowerShell or captured output; the returned row is safe for
    /// the main WebUI.
    /// </summary>
    private static SandboxRunbookStepProgressSnapshot CreateStepProgressSnapshot(
        SandboxRunbookStep step,
        int stepIndex,
        int totalSteps,
        IReadOnlyDictionary<int, SandboxRunbookStepExecutionResult> resultByIndex,
        string aggregateState,
        int? currentStepIndex)
    {
        var facts = RunbookProgressFacts.DescribeStep(step, stepIndex, totalSteps);
        if (resultByIndex.TryGetValue(stepIndex, out var result))
        {
            var resultState = RunbookProgressFacts.ResolveStepState(stepIndex, result, failedIndex: null);
            return new SandboxRunbookStepProgressSnapshot
            {
                StepIndex = stepIndex,
                Ordinal = facts.Ordinal,
                StepId = step.Id,
                Title = step.Title,
                State = resultState,
                Phase = facts.Phase,
                Category = facts.Category,
                RemediationHintZh = facts.RemediationHintZh,
                IsCleanup = facts.IsCleanup,
                RequiresElevation = step.RequiresElevation,
                MutatesVmState = step.MutatesVmState,
                StartedAtUtc = result.StartedAtUtc,
                Duration = result.Duration,
                ExitCode = result.ExitCode,
                Message = RunbookProgressFacts.BuildStepProgressMessage(step, stepIndex, totalSteps, resultState, result, isCurrent: currentStepIndex == stepIndex)
            };
        }

        var isCurrent = currentStepIndex == stepIndex &&
            aggregateState is SandboxRunbookProgressStates.Running;

        return new SandboxRunbookStepProgressSnapshot
        {
            StepIndex = stepIndex,
            Ordinal = facts.Ordinal,
            StepId = step.Id,
            Title = step.Title,
            State = isCurrent ? SandboxRunbookProgressStates.Running : SandboxRunbookProgressStates.Pending,
            Phase = facts.Phase,
            Category = facts.Category,
            RemediationHintZh = facts.RemediationHintZh,
            IsCleanup = facts.IsCleanup,
            RequiresElevation = step.RequiresElevation,
            MutatesVmState = step.MutatesVmState,
            Message = isCurrent
                ? RunbookProgressFacts.BuildStepProgressMessage(step, stepIndex, totalSteps, SandboxRunbookProgressStates.Running, result: null, isCurrent: true)
                : null
        };
    }

    /// <summary>
    /// Captures stdout and stderr after a PowerShell process exits or is killed.
    /// Inputs are the asynchronous reader tasks, which can be null if the process
    /// never started; processing awaits each safely; the returned tuple contains
    /// empty strings when streams were unavailable.
    /// </summary>
    private static async Task<(string StandardOutput, string StandardError)> CollectOutputAsync(
        Task<string>? stdoutTask,
        Task<string>? stderrTask)
    {
        var stdout = await ReadStreamTaskAsync(stdoutTask, "stdout").ConfigureAwait(false);
        var stderr = await ReadStreamTaskAsync(stderrTask, "stderr").ConfigureAwait(false);
        var diagnostics = new[]
            {
                stdout.Diagnostic,
                stderr.Diagnostic
            }
            .Where(item => !string.IsNullOrWhiteSpace(item));
        var standardError = string.Join(
            Environment.NewLine,
            new[] { stderr.Text }.Concat(diagnostics).Where(item => !string.IsNullOrWhiteSpace(item)));
        return (stdout.Text, standardError);
    }

    /// <summary>
    /// Reads one redirected process stream task.
    /// Input is a nullable text task; processing awaits it and converts stream
    /// read failures to a short diagnostic instead of hiding the reason; the
    /// returned tuple is suitable for inclusion in the step result.
    /// </summary>
    private static async Task<(string Text, string? Diagnostic)> ReadStreamTaskAsync(
        Task<string>? streamTask,
        string streamName)
    {
        if (streamTask is null)
        {
            return (string.Empty, null);
        }

        try
        {
            var completedTask = await Task.WhenAny(streamTask, Task.Delay(StreamReadTimeout)).ConfigureAwait(false);
            if (completedTask != streamTask)
            {
                return (string.Empty, $"Timed out while reading PowerShell {streamName} after {FormatDuration(StreamReadTimeout)}.");
            }

            return (await streamTask.ConfigureAwait(false), null);
        }
        catch (Exception ex)
        {
            return (string.Empty, $"Unable to read PowerShell {streamName}: {ex.Message}");
        }
    }

    /// <summary>
    /// Terminates a still-running PowerShell process.
    /// Input is a process instance; processing kills the full process tree when
    /// supported and ignores races where the process already exited; the method
    /// returns no value.
    /// </summary>
    private static void TryKillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
            // The process was never started or has already exited.
        }
        catch (NotSupportedException)
        {
            TryKillSingleProcess(process);
        }
        catch (Exception)
        {
            // Killing is a best-effort cleanup path; the original step failure
            // remains the actionable result.
        }
    }

    /// <summary>
    /// Terminates only the direct PowerShell child process.
    /// Input is a process instance; processing calls the portable Kill overload
    /// as a fallback; the method returns no value.
    /// </summary>
    private static void TryKillSingleProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill();
            }
        }
        catch (Exception)
        {
            // Best-effort fallback only.
        }
    }

    /// <summary>
    /// Waits for a killed process to finish releasing redirected streams.
    /// Input is a process instance; processing waits without caller cancellation
    /// and ignores races around non-started processes; the method returns no
    /// value when cleanup has completed or cannot proceed.
    /// </summary>
    private static async Task WaitForExitAfterKillAsync(Process process)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            // Process was never started.
        }
        catch (OperationCanceledException)
        {
            // The kill path is best-effort. Do not let a stuck process obscure
            // the timeout/cancellation/failure that triggered cleanup.
        }
    }

    /// <summary>
    /// Reads a process exit code only when it is available.
    /// Input is a process instance; processing guards against non-started or
    /// still-running states; the returned value is null when no exit code exists.
    /// </summary>
    private static int? SafeExitCode(Process process)
    {
        try
        {
            return process.HasExited ? process.ExitCode : null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Detects whether the current host process is elevated on Windows.
    /// There is no input; processing checks the current Windows identity and
    /// Administrator role when the OS supports it; the method returns false on
    /// non-Windows platforms or when the check cannot be completed.
    /// </summary>
    private static bool IsCurrentProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
