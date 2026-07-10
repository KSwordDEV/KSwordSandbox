using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Execution;

/// <summary>
/// Executes sandbox runbook steps by launching PowerShell.
/// Inputs are a prepared Hyper-V runbook and execution options; processing
/// records every step in dry-run mode or starts one elevated PowerShell child
/// process per step in live mode; the returned result captures stdout, stderr,
/// exit code, duration, and first-failure status.
/// </summary>
public sealed class PowerShellRunbookExecutor : IRunbookExecutor
{
    private const string DryRunMessage = "Dry-run mode recorded the command without launching PowerShell.";
    private const string ElevationFailureMessage = "Live Hyper-V runbook execution requires the host process to run from an elevated PowerShell session.";

    /// <summary>
    /// Executes or records the supplied runbook.
    /// Inputs are the runbook plan, execution options, and cancellation token;
    /// processing defaults to dry-run safety, validates elevation for live
    /// Hyper-V steps, then executes each PowerShell command in order; the method
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
            message: "Live runbook execution started.");

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

        var liveResults = new List<SandboxRunbookStepExecutionResult>();
        int? failedStepIndex = null;

        for (var index = 0; index < runbook.Steps.Count; index++)
        {
            var step = runbook.Steps[index];

            if (cancellationToken.IsCancellationRequested)
            {
                failedStepIndex = index;
                liveResults.Add(CreateCanceledStepResult(step, index, DateTimeOffset.UtcNow, TimeSpan.Zero));
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

            PublishProgress(
                runbook,
                options,
                SandboxRunbookProgressStates.Running,
                startedAtUtc,
                attemptTimer.Elapsed,
                liveResults,
                index,
                success: null,
                message: $"Running step {index + 1} of {runbook.Steps.Count}: {step.Title}");

            var stepResult = await ExecutePowerShellStepAsync(step, index, options, cancellationToken).ConfigureAwait(false);
            liveResults.Add(stepResult);

            if (!stepResult.Success)
            {
                failedStepIndex = index;
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
                message: $"Completed step {index + 1} of {runbook.Steps.Count}: {step.Title}");
        }

        attemptTimer.Stop();
        var success = failedStepIndex is null && liveResults.Count == runbook.Steps.Count;
        var message = success ? null : BuildLiveFailureMessage(failedStepIndex);

        PublishProgress(
            runbook,
            options,
            success ? SandboxRunbookProgressStates.Completed : SandboxRunbookProgressStates.Failed,
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
        SandboxRunbookExecutionOptions options,
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
                    message: "PowerShell process did not start.");
            }

            stdoutTask = process.StandardOutput.ReadToEndAsync();
            stderrTask = process.StandardError.ReadToEndAsync();

            if (options.StepTimeout > TimeSpan.Zero)
            {
                var waitTask = process.WaitForExitAsync(cancellationToken);
                var timeoutTask = Task.Delay(options.StepTimeout, cancellationToken);
                var completedTask = await Task.WhenAny(waitTask, timeoutTask).ConfigureAwait(false);

                if (completedTask != waitTask)
                {
                    TryKillProcessTree(process);
                    await WaitForExitAfterKillAsync(process).ConfigureAwait(false);
                    var timedOutOutput = await CollectOutputAsync(stdoutTask, stderrTask).ConfigureAwait(false);

                    stepTimer.Stop();
                    var timedOutMessage = cancellationToken.IsCancellationRequested
                        ? "PowerShell step was canceled before completion."
                        : $"PowerShell step exceeded timeout {options.StepTimeout}.";

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

                await waitTask.ConfigureAwait(false);
            }
            else
            {
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
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
                message: success ? null : $"PowerShell exited with code {exitCode}.");
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
                message: "PowerShell step was canceled before completion.");
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
                message: $"PowerShell launch failed: {ex.Message}");
        }
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
            TargetVmName = runbook.TargetVmName,
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
    /// Builds the aggregate live-mode failure message.
    /// Input is the failed source step index; processing distinguishes pre-step
    /// failures from step failures; the returned string is stored on the result.
    /// </summary>
    private static string? BuildLiveFailureMessage(int? failedStepIndex)
    {
        return failedStepIndex is null
            ? null
            : $"Live runbook execution stopped after step index {failedStepIndex.Value} failed.";
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
            .Select((step, index) => CreateStepProgressSnapshot(step, index, resultByIndex, state, currentStepIndex))
            .ToList();
        var currentStep = currentStepIndex is >= 0 && currentStepIndex.Value < runbook.Steps.Count
            ? runbook.Steps[currentStepIndex.Value]
            : null;

        return new SandboxRunbookProgressSnapshot
        {
            JobId = runbook.JobId,
            TargetVmName = runbook.TargetVmName,
            Mode = options.Mode,
            State = state,
            TotalSteps = runbook.Steps.Count,
            CompletedSteps = steps.Count(step => step.State is SandboxRunbookProgressStates.Completed or SandboxRunbookProgressStates.Skipped),
            ExecutedSteps = results.Count(step => !step.Skipped && step.StepIndex >= 0),
            CurrentStepIndex = currentStep is null ? null : currentStepIndex,
            CurrentStepId = currentStep?.Id,
            CurrentStepTitle = currentStep?.Title,
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
        IReadOnlyDictionary<int, SandboxRunbookStepExecutionResult> resultByIndex,
        string aggregateState,
        int? currentStepIndex)
    {
        if (resultByIndex.TryGetValue(stepIndex, out var result))
        {
            return new SandboxRunbookStepProgressSnapshot
            {
                StepIndex = stepIndex,
                StepId = step.Id,
                Title = step.Title,
                State = result.Skipped
                    ? SandboxRunbookProgressStates.Skipped
                    : result.Success
                        ? SandboxRunbookProgressStates.Completed
                        : SandboxRunbookProgressStates.Failed,
                RequiresElevation = step.RequiresElevation,
                MutatesVmState = step.MutatesVmState,
                StartedAtUtc = result.StartedAtUtc,
                Duration = result.Duration,
                ExitCode = result.ExitCode,
                Message = result.Message
            };
        }

        var isCurrent = currentStepIndex == stepIndex &&
            aggregateState is SandboxRunbookProgressStates.Running;

        return new SandboxRunbookStepProgressSnapshot
        {
            StepIndex = stepIndex,
            StepId = step.Id,
            Title = step.Title,
            State = isCurrent ? SandboxRunbookProgressStates.Running : SandboxRunbookProgressStates.Pending,
            RequiresElevation = step.RequiresElevation,
            MutatesVmState = step.MutatesVmState
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
        var stdout = await ReadStreamTaskAsync(stdoutTask).ConfigureAwait(false);
        var stderr = await ReadStreamTaskAsync(stderrTask).ConfigureAwait(false);
        return (stdout, stderr);
    }

    /// <summary>
    /// Reads one redirected process stream task.
    /// Input is a nullable text task; processing awaits it and converts stream
    /// read failures to an empty string; the returned string is suitable for
    /// inclusion in the step result.
    /// </summary>
    private static async Task<string> ReadStreamTaskAsync(Task<string>? streamTask)
    {
        if (streamTask is null)
        {
            return string.Empty;
        }

        try
        {
            return await streamTask.ConfigureAwait(false);
        }
        catch (Exception)
        {
            return string.Empty;
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
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            // Process was never started.
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
