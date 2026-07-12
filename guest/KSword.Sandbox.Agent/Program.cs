using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using KSword.Sandbox.Agent.Collection;
using KSword.Sandbox.Agent.Output;
using KSword.Sandbox.Abstractions;

return await AgentProgram.RunAsync(args);

/// <summary>
/// Guest-side collector that runs inside the disposable Windows VM.
/// Inputs are command-line arguments for sample path, output path, duration,
/// optional driver event path, optional R0Collector sidecar path, and optional
/// screenshot stage/count, dropped-file extraction, memory-dump, and opt-in
/// packet-capture flags; processing can
/// start the sidecar, starts the sample, runs dynamic guest probes, merges
/// driver JSONL, and writes JSON artifacts; RunAsync returns a process exit
/// code.
/// </summary>
internal static class AgentProgram
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private static readonly TimeSpan R0CollectorGracefulStopTimeout = TimeSpan.FromSeconds(5);

    private static readonly TimeSpan R0CollectorDiagnosticDrainTimeout = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan R0CollectorJsonLinesDrainTimeout = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan R0CollectorJsonLinesPollInterval = TimeSpan.FromMilliseconds(100);

    private const string R0CollectorStandardOutputFileName = "r0collector.stdout.log";

    private const string R0CollectorStandardErrorFileName = "r0collector.stderr.log";

    private const string DroppedFilesArtifactDirectoryName = "dropped-files";

    private const string DroppedFileReasonTaxonomy = "guest-artifact.dropped-file.reason.v1";

    private const string DroppedFileSelectorVersion = "artifact-selectors-v1";

    internal const int DefaultR0CollectorMaxEventsPerRead = 1024;

    internal const int DefaultR0CollectorMaxReadBatches = 0;

    internal const int DefaultR0CollectorDriverEventSampleStride = 16;

    /// <summary>
    /// Main async entry point for the guest collector.
    /// Inputs are raw command-line arguments, processing parses options and
    /// executes the collection workflow, and the method returns zero on success.
    /// </summary>
    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            var options = AgentOptions.Parse(args);
            Directory.CreateDirectory(options.OutputDirectory);
            var events = await CollectAsync(options);
            WriteArtifacts(options, events);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine($"zhMessage: {AgentCliZhHint(ex)}");
            return 1;
        }
    }

    /// <summary>
    /// Runs the sample and collects normalized behavior events.
    /// Inputs are parsed options, processing snapshots process tree, file, TCP,
    /// optional screenshot cadence, and optional after-start memory dump state
    /// before, during, and after execution, and the method returns collected
    /// events.
    /// </summary>
    private static async Task<List<SandboxEvent>> CollectAsync(AgentOptions options)
    {
        var workingDirectory = Path.GetDirectoryName(options.SamplePath) ?? Environment.CurrentDirectory;
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "agent.start",
                Source = "guest",
                Path = options.SamplePath,
                Data =
                {
                    ["durationSeconds"] = options.DurationSeconds.ToString(CultureInfo.InvariantCulture),
                    ["captureScreenshots"] = options.CaptureScreenshots.ToString(),
                    ["screenshotPhases"] = options.ScreenshotOptions.FormatStages(),
                    ["screenshotCount"] = options.ScreenshotOptions.CaptureCount.ToString(CultureInfo.InvariantCulture)
                }
            }
        };

        AddEnvironmentSnapshotEvent(events, options, workingDirectory);
        var probePipeline = CreateProbePipeline(options);
        var probeRunner = probePipeline.Runner;
        var probeContext = CreateGuestProbeContext(options, workingDirectory, rootProcessId: null);
        events.AddRange(await probeRunner.CollectAsync(ProbePhase.BeforeStart, probeContext));
        var r0Collector = StartR0Collector(options, events);
        var analysisDeadline = DateTimeOffset.UtcNow.AddSeconds(options.DurationSeconds);

        var executionStage = "start";
        int? executionProcessId = null;
        int? executionParentProcessId = null;
        string? executionProcessName = null;
        DateTime? executionProcessStartTimeUtc = null;
        var executionCommandLine = options.SamplePath;
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = options.SamplePath,
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start sample process.");
            executionProcessId = process.Id;
            executionParentProcessId = Environment.ProcessId;
            executionProcessName = SafeProcessName(process);
            executionProcessStartTimeUtc = SafeProcessStartTimeUtc(process);
            events.Add(new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = executionProcessName,
                ProcessId = process.Id,
                ParentProcessId = executionParentProcessId,
                Path = options.SamplePath,
                CommandLine = executionCommandLine,
                Data =
                {
                    ["imagePath"] = options.SamplePath,
                    ["processImagePath"] = options.SamplePath,
                    ["commandLine"] = executionCommandLine,
                    ["parentProcessId"] = executionParentProcessId.Value.ToString(CultureInfo.InvariantCulture)
                }
            });
            if (executionProcessStartTimeUtc is not null)
            {
                events[^1].Data["startTimeUtc"] = executionProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            }

            executionStage = "after-start-probes";
            var runningProbeContext = CreateGuestProbeContext(
                options,
                workingDirectory,
                process.Id,
                executionParentProcessId,
                executionProcessName,
                options.SamplePath,
                executionCommandLine,
                executionProcessStartTimeUtc);
            events.AddRange(await probeRunner.CollectAsync(ProbePhase.AfterStart, runningProbeContext));

            executionStage = "wait";
            var exited = await WaitForExitAsync(process, TimeSpan.FromSeconds(options.DurationSeconds));
            if (!exited)
            {
                events.Add(new SandboxEvent
                {
                    EventType = "process.timeout",
                    Source = "guest",
                    ProcessName = SafeProcessName(process),
                    ProcessId = process.Id,
                    ParentProcessId = executionParentProcessId,
                    Path = options.SamplePath,
                    CommandLine = executionCommandLine,
                    Data =
                    {
                        ["imagePath"] = options.SamplePath,
                        ["processImagePath"] = options.SamplePath,
                        ["commandLine"] = executionCommandLine,
                        ["parentProcessId"] = executionParentProcessId?.ToString() ?? string.Empty,
                        ["zhMessage"] = "样本进程超过配置的分析时长未退出，Guest Agent 将终止进程树并继续收集剩余证据。",
                        ["zhHint"] = "如果这是预期的长驻样本，请调大 --duration；否则重点查看超时前后的进程树、文件和网络事件。"
                    }
                });
                if (executionProcessStartTimeUtc is not null)
                {
                    events[^1].Data["startTimeUtc"] = executionProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
                }

                if (options.CaptureMemoryDump)
                {
                    executionStage = "timeout-memory-dump";
                    events.AddRange(await probePipeline.MemoryDumpRunner.CollectAsync(ProbePhase.Cleanup, runningProbeContext));
                }

                executionStage = "kill-timeout";
                try
                {
                    if (!HasProcessExited(process))
                    {
                        process.Kill(entireProcessTree: true);
                    }

                    await process.WaitForExitAsync();
                }
                catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                {
                    events.Add(CreateSampleExecutionFailureEvent("process.kill_failed", options.SamplePath, process.Id, executionStage, ex));
                }
            }

            executionStage = "exit";
            events.Add(new SandboxEvent
            {
                EventType = "process.exit",
                Source = "guest",
                ProcessName = SafeProcessName(process),
                ProcessId = process.Id,
                ParentProcessId = executionParentProcessId,
                Path = options.SamplePath,
                CommandLine = executionCommandLine,
                Data =
                {
                    ["exitCode"] = SafeExitCode(process),
                    ["imagePath"] = options.SamplePath,
                    ["processImagePath"] = options.SamplePath,
                    ["commandLine"] = executionCommandLine,
                    ["parentProcessId"] = executionParentProcessId?.ToString() ?? string.Empty
                }
            });
            if (executionProcessStartTimeUtc is not null)
            {
                events[^1].Data["startTimeUtc"] = executionProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            }

            var remainingAnalysisWindow = analysisDeadline - DateTimeOffset.UtcNow;
            if (remainingAnalysisWindow > TimeSpan.Zero)
            {
                events.Add(new SandboxEvent
                {
                    EventType = "analysis.wait_remaining",
                    Source = "guest",
                    ProcessName = SafeProcessName(process),
                    ProcessId = process.Id,
                    ParentProcessId = executionParentProcessId,
                    Path = options.SamplePath,
                    CommandLine = executionCommandLine,
                    Data =
                    {
                        ["remainingSeconds"] = Math.Ceiling(remainingAnalysisWindow.TotalSeconds).ToString(CultureInfo.InvariantCulture),
                        ["reason"] = "sampleExitedBeforeAnalysisDuration",
                        ["durationSeconds"] = options.DurationSeconds.ToString(CultureInfo.InvariantCulture),
                        ["imagePath"] = options.SamplePath,
                        ["processImagePath"] = options.SamplePath,
                        ["commandLine"] = executionCommandLine,
                        ["parentProcessId"] = executionParentProcessId?.ToString() ?? string.Empty,
                        ["zhMessage"] = "样本早于配置的分析窗口退出，Guest Agent 会等待剩余时间继续观察后续行为。"
                    }
                });
                if (executionProcessStartTimeUtc is not null)
                {
                    events[^1].Data["startTimeUtc"] = executionProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
                }

                await Task.Delay(remainingAnalysisWindow);
            }

            executionStage = "after-run-probes";
            events.AddRange(await probeRunner.CollectAsync(ProbePhase.AfterRun, runningProbeContext));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var diagnosticContext = CreateGuestProbeContext(
                options,
                workingDirectory,
                executionProcessId,
                executionParentProcessId,
                executionProcessName,
                options.SamplePath,
                executionCommandLine,
                executionProcessStartTimeUtc);
            var eventType = string.Equals(executionStage, "start", StringComparison.OrdinalIgnoreCase)
                ? "process.start_failed"
                : "process.execution_failed";
            events.Add(CreateSampleExecutionFailureEvent(eventType, options.SamplePath, executionProcessId, executionStage, ex));
            events.AddRange(await probeRunner.CollectAsync(ProbePhase.AfterRun, diagnosticContext));
        }
        finally
        {
            await StopR0CollectorAsync(r0Collector, events);
        }

        events.AddRange(ReadDriverEvents(options.DriverEventsPath));
        events.Add(new SandboxEvent { EventType = "agent.stop", Source = "guest", Path = options.OutputDirectory });
        return events;
    }

    /// <summary>
    /// Creates the dynamic guest probe pipeline.
    /// Inputs are none; processing constructs the process tree, file diff, TCP
    /// diff, configurable optional screenshot, packet capture, and opt-in
    /// memory dump probes in deterministic order; the method returns shared
    /// runners for one agent run.
    /// </summary>
    private sealed record GuestProbePipeline(GuestProbeRunner Runner, GuestProbeRunner MemoryDumpRunner);

    private static GuestProbePipeline CreateProbePipeline(AgentOptions options)
    {
        var memoryDumpProbe = new MemoryDumpProbe();
        return new GuestProbePipeline(
            new GuestProbeRunner(
            [
                new ProcessTreeProbe(),
                new SecurityEventLogProbe(),
                new FileDiffProbe(),
                new TcpConnectionDiffProbe(),
                new PacketCaptureProbe(),
                new ScreenshotProbe(options.ScreenshotOptions),
                memoryDumpProbe
            ]),
            new GuestProbeRunner([memoryDumpProbe]));
    }

    /// <summary>
    /// Builds a probe context from current agent options and execution state.
    /// Inputs are parsed options, working directory, and optional root process
    /// id; processing copies values into an immutable context; the method
    /// returns the context consumed by guest probes.
    /// </summary>
    private static GuestProbeContext CreateGuestProbeContext(
        AgentOptions options,
        string workingDirectory,
        int? rootProcessId,
        int? rootParentProcessId = null,
        string? rootProcessName = null,
        string? rootProcessPath = null,
        string? rootCommandLine = null,
        DateTime? rootProcessStartTimeUtc = null)
    {
        return new GuestProbeContext
        {
            SamplePath = options.SamplePath,
            WorkingDirectory = workingDirectory,
            OutputDirectory = options.OutputDirectory,
            RootProcessId = rootProcessId,
            RootParentProcessId = rootParentProcessId,
            RootProcessName = rootProcessName,
            RootProcessPath = rootProcessPath,
            RootCommandLine = rootCommandLine,
            RootProcessStartTimeUtc = rootProcessStartTimeUtc,
            CaptureScreenshots = options.CaptureScreenshots,
            CollectDroppedFiles = options.CollectDroppedFiles,
            CaptureMemoryDump = options.CaptureMemoryDump,
            CapturePacketCapture = options.CapturePacketCapture
        };
    }

    /// <summary>
    /// Starts the optional R0Collector sidecar before sample execution.
    /// Inputs are parsed agent options and the event output list; processing
    /// requires both --r0collector and --driver-events, creates the JSONL parent
    /// directory, redirects stdout/stderr into guest diagnostics, forwards
    /// --device/--output/--duration plus optional --mock, and records
    /// r0collector.failed on configuration or startup errors; the method
    /// returns a process handle when the sidecar starts or null when disabled or
    /// failed.
    /// </summary>
    private static R0CollectorProcess? StartR0Collector(AgentOptions options, List<SandboxEvent> events)
    {
        var sidecarRequested = !string.IsNullOrWhiteSpace(options.R0CollectorPath) || options.R0Mock;
        if (!sidecarRequested)
        {
            return null;
        }

        var standardOutputPath = Path.Combine(options.OutputDirectory, R0CollectorStandardOutputFileName);
        var standardErrorPath = Path.Combine(options.OutputDirectory, R0CollectorStandardErrorFileName);

        if (string.IsNullOrWhiteSpace(options.R0CollectorPath))
        {
            var reason = "collectorPathMissing";
            WriteR0CollectorStartupDiagnostic(standardOutputPath, standardErrorPath, reason, null);
            events.Add(CreateLegacyR0CollectorStartFailedEvent(options, reason, null, standardOutputPath, standardErrorPath));
            events.Add(CreateR0CollectorFailedEvent(
                options,
                phase: "start",
                reason: reason,
                standardOutputPath: standardOutputPath,
                standardErrorPath: standardErrorPath));
            return null;
        }

        if (string.IsNullOrWhiteSpace(options.DriverEventsPath))
        {
            var reason = "driverEventsPathMissing";
            WriteR0CollectorStartupDiagnostic(standardOutputPath, standardErrorPath, reason, null);
            events.Add(CreateLegacyR0CollectorStartFailedEvent(options, reason, null, standardOutputPath, standardErrorPath));
            events.Add(CreateR0CollectorFailedEvent(
                options,
                phase: "start",
                reason: reason,
                standardOutputPath: standardOutputPath,
                standardErrorPath: standardErrorPath));
            return null;
        }

        if (!File.Exists(options.R0CollectorPath))
        {
            var reason = "collectorMissing";
            WriteR0CollectorStartupDiagnostic(standardOutputPath, standardErrorPath, reason, null);
            events.Add(CreateLegacyR0CollectorStartFailedEvent(options, reason, null, standardOutputPath, standardErrorPath));
            events.Add(CreateR0CollectorFailedEvent(
                options,
                phase: "start",
                reason: reason,
                standardOutputPath: standardOutputPath,
                standardErrorPath: standardErrorPath));
            return null;
        }

        FileStream? standardOutputFile = null;
        FileStream? standardErrorFile = null;
        Process? startedProcess = null;
        try
        {
            EnsureParentDirectory(options.DriverEventsPath);
            standardOutputFile = OpenR0CollectorDiagnosticFile(standardOutputPath);
            standardErrorFile = OpenR0CollectorDiagnosticFile(standardErrorPath);

            var startInfo = new ProcessStartInfo
            {
                FileName = options.R0CollectorPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            startInfo.ArgumentList.Add("--device");
            startInfo.ArgumentList.Add(options.DriverDevicePath);
            startInfo.ArgumentList.Add("--output");
            startInfo.ArgumentList.Add(options.DriverEventsPath);
            startInfo.ArgumentList.Add("--duration");
            startInfo.ArgumentList.Add(options.DurationSeconds.ToString(CultureInfo.InvariantCulture));
            startInfo.ArgumentList.Add("--max-events");
            startInfo.ArgumentList.Add(options.R0CollectorMaxEventsPerRead.ToString(CultureInfo.InvariantCulture));
            startInfo.ArgumentList.Add("--max-read-batches");
            startInfo.ArgumentList.Add(options.R0CollectorMaxReadBatches.ToString(CultureInfo.InvariantCulture));
            startInfo.ArgumentList.Add("--driver-event-sample-stride");
            startInfo.ArgumentList.Add(options.R0CollectorDriverEventSampleStride.ToString(CultureInfo.InvariantCulture));
            if (options.R0Mock)
            {
                startInfo.ArgumentList.Add("--mock");
            }

            startedProcess = Process.Start(startInfo) ?? throw new InvalidOperationException("R0Collector process start returned null.");
            var standardOutputTask = CopyR0CollectorDiagnosticStreamAsync(startedProcess.StandardOutput.BaseStream, standardOutputFile);
            standardOutputFile = null;
            var standardErrorTask = CopyR0CollectorDiagnosticStreamAsync(startedProcess.StandardError.BaseStream, standardErrorFile);
            standardErrorFile = null;
            var commandLine = BuildR0CollectorCommandLine(options);
            events.Add(CreateR0CollectorStartedEvent(options, startedProcess.Id, standardOutputPath, standardErrorPath, commandLine));
            return new R0CollectorProcess(
                startedProcess,
                options.R0CollectorPath,
                options.DriverEventsPath,
                standardOutputPath,
                standardErrorPath,
                standardOutputTask,
                standardErrorTask,
                commandLine);
        }
        catch (Exception ex)
        {
            standardOutputFile?.Dispose();
            standardErrorFile?.Dispose();
            DisposePartiallyStartedR0Collector(startedProcess);
            var reason = "startException";
            WriteR0CollectorStartupDiagnostic(standardOutputPath, standardErrorPath, reason, ex);
            events.Add(CreateLegacyR0CollectorStartFailedEvent(options, reason, ex, standardOutputPath, standardErrorPath));
            events.Add(CreateR0CollectorFailedEvent(
                options,
                phase: "start",
                reason: reason,
                exception: ex,
                standardOutputPath: standardOutputPath,
                standardErrorPath: standardErrorPath));
            return null;
        }
    }

    /// <summary>
    /// Best-effort cleanup for rare failures after Process.Start succeeds but
    /// before the sidecar record can be returned to normal shutdown handling.
    /// </summary>
    private static void DisposePartiallyStartedR0Collector(Process? process)
    {
        if (process is null)
        {
            return;
        }

        try
        {
            if (!HasProcessExited(process))
            {
                process.Kill(entireProcessTree: true);
            }

            process.WaitForExit(milliseconds: 1000);
        }
        catch
        {
            // Startup failure reporting must not be replaced by cleanup noise.
        }
        finally
        {
            process.Dispose();
        }
    }

    /// <summary>
    /// Waits briefly for the optional R0Collector sidecar and terminates it if
    /// needed after sample execution. The input is the nullable sidecar process
    /// record plus the event output list; processing gives the collector a
    /// short graceful-exit window, then kills the process tree if needed,
    /// drains redirected diagnostics and the JSONL file, and records
    /// r0collector.exited or r0collector.failed details; the method returns no
    /// value.
    /// </summary>
    private static async Task StopR0CollectorAsync(R0CollectorProcess? collector, List<SandboxEvent> events)
    {
        if (collector is null)
        {
            return;
        }

        var forcedStop = false;
        var stopFailed = false;
        var stopFailureReason = string.Empty;
        Exception? stopException = null;
        var processId = SafeProcessId(collector.Process);
        try
        {
            if (!await WaitForExitAsync(collector.Process, R0CollectorGracefulStopTimeout))
            {
                forcedStop = true;
                var forcedStopEvent = new SandboxEvent
                {
                    EventType = "r0collector.stop_forced",
                    Source = "guest",
                    Path = collector.CollectorPath,
                    ProcessId = processId,
                    ProcessName = Path.GetFileName(collector.CollectorPath),
                    CommandLine = collector.CommandLine,
                    Data =
                    {
                        ["driverEventsPath"] = collector.DriverEventsPath,
                        ["processId"] = processId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                        ["stdoutPath"] = collector.StandardOutputPath,
                        ["stderrPath"] = collector.StandardErrorPath,
                        ["gracefulStopTimeoutSeconds"] = R0CollectorGracefulStopTimeout.TotalSeconds.ToString(CultureInfo.InvariantCulture),
                        ["capturePolicy"] = "explicit-opt-in-r0collector-sidecar",
                        ["zhMessage"] = "R0Collector 未在宽限期内退出，Guest Agent 将强制终止 sidecar 进程树。",
                        ["zhHint"] = "该事件说明采集 sidecar 的关闭路径异常；请结合后续 r0collector.failed/exited、stdout/stderr 和 driver-events JSONL 判断证据完整性。"
                    }
                };
                AddR0ArtifactReferenceData(
                    forcedStopEvent,
                    InferR0OutputDirectory(collector),
                    collector.DriverEventsPath,
                    collector.StandardOutputPath,
                    collector.StandardErrorPath);
                events.Add(forcedStopEvent);

                if (!HasProcessExited(collector.Process))
                {
                    collector.Process.Kill(entireProcessTree: true);
                }

                await collector.Process.WaitForExitAsync();
            }
        }
        catch (Exception ex)
        {
            stopFailed = true;
            stopFailureReason = "stopException";
            stopException = ex;
            events.Add(CreateLegacyR0CollectorStopFailedEvent(collector, ex, processId));
        }
        finally
        {
            var diagnosticDrainStatus = await DrainR0CollectorDiagnosticsAsync(collector);
            var jsonLinesDrainStatus = await DrainR0CollectorJsonLinesAsync(collector.DriverEventsPath);
            var exitCode = SafeExitCode(collector.Process);

            if (stopFailed)
            {
                events.Add(CreateR0CollectorFailedEvent(
                    collector,
                    phase: "stop",
                    reason: stopFailureReason,
                    exception: stopException,
                    processId: processId,
                    exitCode: exitCode,
                    forcedStop: forcedStop,
                    diagnosticDrainStatus: diagnosticDrainStatus,
                    jsonLinesDrainStatus: jsonLinesDrainStatus));
            }
            else if (forcedStop || !string.Equals(exitCode, "0", StringComparison.Ordinal))
            {
                events.Add(CreateR0CollectorFailedEvent(
                    collector,
                    phase: forcedStop ? "stop" : "runtime",
                    reason: forcedStop ? "forcedStop" : "nonZeroExit",
                    exception: null,
                    processId: processId,
                    exitCode: exitCode,
                    forcedStop: forcedStop,
                    diagnosticDrainStatus: diagnosticDrainStatus,
                    jsonLinesDrainStatus: jsonLinesDrainStatus));
            }
            else
            {
                events.Add(CreateR0CollectorExitedEvent(
                    collector,
                    processId,
                    exitCode,
                    forcedStop,
                    diagnosticDrainStatus,
                    jsonLinesDrainStatus));
            }

            collector.Process.Dispose();
        }
    }

    /// <summary>
    /// Opens a sidecar diagnostic log with sharing so host copy/import tools can
    /// read it while the guest agent is still draining process output.
    /// </summary>
    private static FileStream OpenR0CollectorDiagnosticFile(string path)
    {
        EnsureParentDirectory(path);
        return new FileStream(
            path,
            FileMode.Create,
            FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
    }

    /// <summary>
    /// Copies one redirected sidecar stream to its diagnostic file and closes
    /// the destination when the process pipe reaches EOF.
    /// </summary>
    private static async Task CopyR0CollectorDiagnosticStreamAsync(Stream source, FileStream destination)
    {
        await using var diagnosticFile = destination;
        await source.CopyToAsync(diagnosticFile);
        await diagnosticFile.FlushAsync();
    }

    /// <summary>
    /// Writes best-effort diagnostic files for failures that happen before a
    /// sidecar process exists and therefore before stdout/stderr redirection
    /// can start.
    /// </summary>
    private static void WriteR0CollectorStartupDiagnostic(
        string standardOutputPath,
        string standardErrorPath,
        string reason,
        Exception? exception)
    {
        try
        {
            EnsureParentDirectory(standardOutputPath);
            File.WriteAllText(standardOutputPath, string.Empty);
            var lines = new List<string>
            {
                $"R0Collector did not start: {reason}",
                $"zhMessage: R0Collector 未启动：{R0CollectorReasonZhMessage(reason)}",
                $"zhHint: {R0CollectorReasonZhHint(reason)}"
            };

            if (exception is not null)
            {
                lines.Add($"{exception.GetType().FullName ?? exception.GetType().Name}: {exception.Message}");
            }

            File.WriteAllLines(standardErrorPath, lines);
        }
        catch
        {
            // Startup diagnostics must never mask the structured events that
            // explain why the optional sidecar did not run.
        }
    }

    /// <summary>
    /// Waits briefly for redirected sidecar stdout/stderr copy tasks to finish.
    /// </summary>
    private static async Task<string> DrainR0CollectorDiagnosticsAsync(R0CollectorProcess collector)
    {
        var stdoutStatus = await DrainR0CollectorDiagnosticTaskAsync("stdout", collector.StandardOutputTask);
        var stderrStatus = await DrainR0CollectorDiagnosticTaskAsync("stderr", collector.StandardErrorTask);
        return $"{stdoutStatus};{stderrStatus}";
    }

    /// <summary>
    /// Waits for one diagnostic copy task and converts completion, timeout, or
    /// failure into compact event metadata.
    /// </summary>
    private static async Task<string> DrainR0CollectorDiagnosticTaskAsync(string name, Task task)
    {
        try
        {
            var completedTask = await Task.WhenAny(task, Task.Delay(R0CollectorDiagnosticDrainTimeout));
            if (completedTask != task)
            {
                return $"{name}=timeout";
            }

            await task;
            return $"{name}=completed";
        }
        catch (Exception ex)
        {
            return $"{name}=failed:{ex.GetType().Name}:{ex.Message}";
        }
    }

    /// <summary>
    /// Gives the sidecar JSONL artifact a short best-effort drain window after
    /// process exit/kill so the final read sees flushed rows whenever possible.
    /// </summary>
    private static async Task<string> DrainR0CollectorJsonLinesAsync(string path)
    {
        var deadline = DateTimeOffset.UtcNow + R0CollectorJsonLinesDrainTimeout;
        long? previousLength = null;
        DateTime? previousLastWriteUtc = null;
        var stableObservations = 0;
        var observed = false;
        Exception? lastException = null;

        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                var info = new FileInfo(path);
                info.Refresh();
                if (!info.Exists)
                {
                    await Task.Delay(R0CollectorJsonLinesPollInterval);
                    continue;
                }

                observed = true;
                using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                }

                if (previousLength == info.Length && previousLastWriteUtc == info.LastWriteTimeUtc)
                {
                    stableObservations++;
                    if (stableObservations >= 2)
                    {
                        return "stable";
                    }
                }
                else
                {
                    previousLength = info.Length;
                    previousLastWriteUtc = info.LastWriteTimeUtc;
                    stableObservations = 0;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                lastException = ex;
            }

            await Task.Delay(R0CollectorJsonLinesPollInterval);
        }

        if (!observed)
        {
            return "missing";
        }

        if (lastException is not null)
        {
            return $"timeoutAfterReadError:{lastException.GetType().Name}:{lastException.Message}";
        }

        return "timeout";
    }

    /// <summary>
    /// Creates the sidecar supervision event written immediately after a
    /// process handle is obtained.
    /// </summary>
    private static SandboxEvent CreateR0CollectorStartedEvent(
        AgentOptions options,
        int processId,
        string standardOutputPath,
        string standardErrorPath,
        string commandLine)
    {
        var evt = new SandboxEvent
        {
            EventType = "r0collector.started",
            Source = "guest",
            ProcessName = Path.GetFileName(options.R0CollectorPath),
            ProcessId = processId,
            Path = options.R0CollectorPath,
            CommandLine = commandLine,
            Data =
            {
                ["collectorPath"] = options.R0CollectorPath ?? string.Empty,
                ["driverDevicePath"] = options.DriverDevicePath,
                ["driverEventsPath"] = options.DriverEventsPath ?? string.Empty,
                ["durationSeconds"] = options.DurationSeconds.ToString(CultureInfo.InvariantCulture),
                ["r0MaxEventsPerRead"] = options.R0CollectorMaxEventsPerRead.ToString(CultureInfo.InvariantCulture),
                ["r0MaxReadBatches"] = options.R0CollectorMaxReadBatches.ToString(CultureInfo.InvariantCulture),
                ["r0DriverEventSampleStride"] = options.R0CollectorDriverEventSampleStride.ToString(CultureInfo.InvariantCulture),
                ["r0BackpressureMitigation"] = "unlimited-read-batches-with-stride-sampling",
                ["r0Mock"] = options.R0Mock.ToString(),
                ["stdoutPath"] = standardOutputPath,
                ["stderrPath"] = standardErrorPath,
                ["processId"] = processId.ToString(CultureInfo.InvariantCulture),
                ["supervisor"] = "guest-agent",
                ["capturePolicy"] = "explicit-opt-in-r0collector-sidecar",
                ["zhMessage"] = "R0Collector sidecar 已由 Guest Agent 启动，驱动 JSONL 和诊断日志会作为证据保留。",
                ["zhHint"] = "started 事件表示 sidecar 已启动；最终 JSONL/log 文件完整性请以 r0collector.exited/failed 和 manifest 中的 sizeBytes/sha256 为准。"
            }
        };
        AddR0ArtifactReferenceData(
            evt,
            options.OutputDirectory,
            options.DriverEventsPath,
            standardOutputPath,
            standardErrorPath);
        return evt;
    }

    /// <summary>
    /// Creates the sidecar supervision event for a clean collector process exit.
    /// </summary>
    private static SandboxEvent CreateR0CollectorExitedEvent(
        R0CollectorProcess collector,
        int? processId,
        string exitCode,
        bool forcedStop,
        string diagnosticDrainStatus,
        string jsonLinesDrainStatus)
    {
        var evt = new SandboxEvent
        {
            EventType = "r0collector.exited",
            Source = "guest",
            ProcessName = Path.GetFileName(collector.CollectorPath),
            ProcessId = processId,
            Path = collector.CollectorPath,
            CommandLine = collector.CommandLine,
            Data =
            {
                ["collectorPath"] = collector.CollectorPath,
                ["driverEventsPath"] = collector.DriverEventsPath,
                ["stdoutPath"] = collector.StandardOutputPath,
                ["stderrPath"] = collector.StandardErrorPath,
                ["processId"] = processId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["exitCode"] = exitCode,
                ["forcedStop"] = forcedStop.ToString(),
                ["diagnosticDrainStatus"] = diagnosticDrainStatus,
                ["jsonlDrainStatus"] = jsonLinesDrainStatus,
                ["supervisor"] = "guest-agent",
                ["capturePolicy"] = "explicit-opt-in-r0collector-sidecar",
                ["zhMessage"] = "R0Collector sidecar 已正常退出，Guest Agent 已尝试冲刷 stdout/stderr 和 driver-events JSONL。",
                ["zhHint"] = "请使用 artifactRelativePath 下载 driver-events JSONL；stdoutRelativePath/stderrRelativePath 可用于诊断 sidecar 输出。"
            }
        };
        AddR0ArtifactReferenceData(
            evt,
            InferR0OutputDirectory(collector),
            collector.DriverEventsPath,
            collector.StandardOutputPath,
            collector.StandardErrorPath);
        return evt;
    }

    /// <summary>
    /// Creates a sidecar failure event when no process handle is available.
    /// </summary>
    private static SandboxEvent CreateR0CollectorFailedEvent(
        AgentOptions options,
        string phase,
        string reason,
        Exception? exception = null,
        string? standardOutputPath = null,
        string? standardErrorPath = null)
    {
        var evt = new SandboxEvent
        {
            EventType = "r0collector.failed",
            Source = "guest",
            ProcessName = string.IsNullOrWhiteSpace(options.R0CollectorPath) ? null : Path.GetFileName(options.R0CollectorPath),
            Path = options.R0CollectorPath,
            Data =
            {
                ["collectorPath"] = options.R0CollectorPath ?? string.Empty,
                ["driverDevicePath"] = options.DriverDevicePath,
                ["driverEventsPath"] = options.DriverEventsPath ?? string.Empty,
                ["durationSeconds"] = options.DurationSeconds.ToString(CultureInfo.InvariantCulture),
                ["r0Mock"] = options.R0Mock.ToString(),
                ["phase"] = phase,
                ["reason"] = reason,
                ["stdoutPath"] = standardOutputPath ?? string.Empty,
                ["stderrPath"] = standardErrorPath ?? string.Empty,
                ["supervisor"] = "guest-agent"
            }
        };

        AddR0ArtifactReferenceData(
            evt,
            options.OutputDirectory,
            options.DriverEventsPath,
            standardOutputPath,
            standardErrorPath);
        AddExceptionData(evt, exception);
        AddR0CollectorLocalizationData(evt, reason, phase);
        return evt;
    }

    /// <summary>
    /// Creates a sidecar failure event for a process that started but did not
    /// complete cleanly.
    /// </summary>
    private static SandboxEvent CreateR0CollectorFailedEvent(
        R0CollectorProcess collector,
        string phase,
        string reason,
        Exception? exception,
        int? processId,
        string exitCode,
        bool forcedStop,
        string diagnosticDrainStatus,
        string jsonLinesDrainStatus)
    {
        var evt = new SandboxEvent
        {
            EventType = "r0collector.failed",
            Source = "guest",
            ProcessName = Path.GetFileName(collector.CollectorPath),
            ProcessId = processId,
            Path = collector.CollectorPath,
            CommandLine = collector.CommandLine,
            Data =
            {
                ["collectorPath"] = collector.CollectorPath,
                ["driverEventsPath"] = collector.DriverEventsPath,
                ["stdoutPath"] = collector.StandardOutputPath,
                ["stderrPath"] = collector.StandardErrorPath,
                ["processId"] = processId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["exitCode"] = exitCode,
                ["forcedStop"] = forcedStop.ToString(),
                ["phase"] = phase,
                ["reason"] = reason,
                ["diagnosticDrainStatus"] = diagnosticDrainStatus,
                ["jsonlDrainStatus"] = jsonLinesDrainStatus,
                ["supervisor"] = "guest-agent"
            }
        };

        AddR0ArtifactReferenceData(
            evt,
            InferR0OutputDirectory(collector),
            collector.DriverEventsPath,
            collector.StandardOutputPath,
            collector.StandardErrorPath);
        AddExceptionData(evt, exception);
        AddR0CollectorLocalizationData(evt, reason, phase);
        return evt;
    }

    /// <summary>
    /// Preserves the older startup failure event name for downstream consumers
    /// while the canonical sidecar outcome is r0collector.failed.
    /// </summary>
    private static SandboxEvent CreateLegacyR0CollectorStartFailedEvent(
        AgentOptions options,
        string reason,
        Exception? exception,
        string standardOutputPath,
        string standardErrorPath)
    {
        var evt = new SandboxEvent
        {
            EventType = "r0collector.start_failed",
            Source = "guest",
            Path = options.R0CollectorPath,
            Data =
            {
                ["collectorPath"] = options.R0CollectorPath ?? string.Empty,
                ["driverDevicePath"] = options.DriverDevicePath,
                ["driverEventsPath"] = options.DriverEventsPath ?? string.Empty,
                ["durationSeconds"] = options.DurationSeconds.ToString(CultureInfo.InvariantCulture),
                ["r0Mock"] = options.R0Mock.ToString(),
                ["reason"] = reason,
                ["stdoutPath"] = standardOutputPath,
                ["stderrPath"] = standardErrorPath
            }
        };

        AddR0ArtifactReferenceData(
            evt,
            options.OutputDirectory,
            options.DriverEventsPath,
            standardOutputPath,
            standardErrorPath);
        AddExceptionData(evt, exception);
        AddR0CollectorLocalizationData(evt, reason, "start");
        return evt;
    }

    /// <summary>
    /// Preserves the older stop failure event name while the canonical sidecar
    /// outcome is r0collector.failed.
    /// </summary>
    private static SandboxEvent CreateLegacyR0CollectorStopFailedEvent(R0CollectorProcess collector, Exception exception, int? processId)
    {
        var evt = new SandboxEvent
        {
            EventType = "r0collector.stop_failed",
            Source = "guest",
            ProcessName = Path.GetFileName(collector.CollectorPath),
            ProcessId = processId,
            Path = collector.CollectorPath,
            CommandLine = collector.CommandLine,
            Data =
            {
                ["driverEventsPath"] = collector.DriverEventsPath,
                ["stdoutPath"] = collector.StandardOutputPath,
                ["stderrPath"] = collector.StandardErrorPath,
                ["processId"] = processId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty
            }
        };

        AddR0ArtifactReferenceData(
            evt,
            InferR0OutputDirectory(collector),
            collector.DriverEventsPath,
            collector.StandardOutputPath,
            collector.StandardErrorPath);
        AddExceptionData(evt, exception);
        AddR0CollectorLocalizationData(evt, "stopException", "stop");
        return evt;
    }

    /// <summary>
    /// Adds exception metadata to a diagnostic event when an exception exists.
    /// </summary>
    private static void AddExceptionData(SandboxEvent evt, Exception? exception)
    {
        if (exception is null)
        {
            return;
        }

        evt.Data["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name;
        evt.Data["message"] = exception.Message;
        evt.Data.TryAdd("zhMessage", "操作失败；请结合 exceptionType/message、phase/reason 和相关路径判断是采集诊断问题还是样本行为。");
    }

    /// <summary>
    /// Adds Chinese operator-facing text for R0 sidecar supervision events while
    /// preserving stable machine-readable reason/phase keys.
    /// </summary>
    private static void AddR0CollectorLocalizationData(SandboxEvent evt, string reason, string phase)
    {
        evt.Data["zhMessage"] = $"R0Collector 在 {phase} 阶段未完成正常路径：{R0CollectorReasonZhMessage(reason)}";
        evt.Data["zhHint"] = R0CollectorReasonZhHint(reason);
    }

    private static string R0CollectorReasonZhMessage(string reason)
    {
        return reason switch
        {
            "collectorPathMissing" => "未提供 R0Collector 可执行文件路径。",
            "driverEventsPathMissing" => "未提供 driver-events JSONL 输出路径。",
            "collectorMissing" => "配置的 R0Collector 可执行文件不存在。",
            "startException" => "启动 R0Collector 进程时发生异常。",
            "forcedStop" => "R0Collector 未在宽限期内退出，已被 Guest Agent 强制终止。",
            "nonZeroExit" => "R0Collector 以非零退出码结束。",
            "stopException" => "停止或回收 R0Collector 进程时发生异常。",
            _ => "请查看同一事件中的 reason、exitCode、stdout/stderr 和 JSONL drain 状态。"
        };
    }

    private static string R0CollectorReasonZhHint(string reason)
    {
        return reason switch
        {
            "collectorPathMissing" => "请在 Guest Agent 参数中提供 --r0collector/--r0-collector，或关闭 R0 sidecar 采集。",
            "driverEventsPathMissing" => "请同时提供 --driver-events，确保该路径位于 Guest 输出目录或可被后续拷贝。",
            "collectorMissing" => "请确认 R0Collector exe 已部署到 guest，路径拼写正确且未被清理。",
            "startException" => "请查看 r0collector.stderr.log、异常类型和权限/依赖问题；这通常是采集环境问题，不代表样本行为。",
            "forcedStop" => "如果 JSONL 末尾缺失，请查看 jsonlDrainStatus 和 stdout/stderr；必要时缩短 Collector duration 或增大停止宽限期。",
            "nonZeroExit" => "请优先查看 r0collector.deviceUnavailable/readinessDiagnostic/ioctlFailure 等行以及 stderr 日志。",
            "stopException" => "请检查进程权限、句柄状态和诊断日志是否仍可读取。",
            _ => "请把该事件视为采集诊断信号，并结合 r0collector.*.log 与 driver-events.jsonl 判断根因。"
        };
    }

    private static string AgentCliZhHint(Exception exception)
    {
        if (exception is ArgumentException && exception.Message.Contains("--sample", StringComparison.OrdinalIgnoreCase))
        {
            return "请使用 --sample 指向 guest 内存在的可执行样本文件。";
        }

        if (exception is ArgumentException && exception.Message.Contains("--out", StringComparison.OrdinalIgnoreCase))
        {
            return "请使用 --out 指定 Guest Agent 输出目录。";
        }

        return "Guest Agent 启动失败；请检查命令行参数、样本路径、输出目录和当前用户权限。";
    }

    /// <summary>
    /// Adds output-relative artifact selectors for R0 sidecar JSONL and logs.
    /// Inputs are a sidecar event, output root, and known artifact paths;
    /// processing records relative selectors that the guest manifest and host
    /// index can later resolve without exposing absolute paths as href values.
    /// </summary>
    private static void AddR0ArtifactReferenceData(
        SandboxEvent evt,
        string? outputDirectory,
        string? driverEventsPath,
        string? standardOutputPath,
        string? standardErrorPath)
    {
        var driverEventsRelativePath = TryGetOutputRelativePath(outputDirectory, driverEventsPath);
        var stdoutRelativePath = TryGetOutputRelativePath(outputDirectory, standardOutputPath);
        var stderrRelativePath = TryGetOutputRelativePath(outputDirectory, standardErrorPath);

        evt.Data.TryAdd("capturePolicy", "explicit-opt-in-r0collector-sidecar");
        evt.Data["artifactRelativePathStatus"] = string.IsNullOrWhiteSpace(driverEventsRelativePath) ? "not-available" : "expected-or-captured";
        AddDataIfNotEmpty(evt.Data, "driverEventsRelativePath", driverEventsRelativePath);
        AddDataIfNotEmpty(evt.Data, "jsonlRelativePath", driverEventsRelativePath);
        AddDataIfNotEmpty(evt.Data, "stdoutRelativePath", stdoutRelativePath);
        AddDataIfNotEmpty(evt.Data, "stderrRelativePath", stderrRelativePath);
        AddDataIfNotEmpty(evt.Data, "artifactRelativePath", driverEventsRelativePath);
        AddDataIfNotEmpty(evt.Data, "diagnosticRelativePath", FirstNonEmpty(stdoutRelativePath, stderrRelativePath));
    }

    private static string InferR0OutputDirectory(R0CollectorProcess collector)
    {
        return FirstNonEmpty(
            SafeDirectoryName(collector.DriverEventsPath),
            SafeDirectoryName(collector.StandardOutputPath),
            SafeDirectoryName(collector.StandardErrorPath));
    }

    private static string TryGetOutputRelativePath(string? outputDirectory, string? path)
    {
        if (string.IsNullOrWhiteSpace(outputDirectory) || string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        try
        {
            var fullOutputDirectory = Path.GetFullPath(outputDirectory);
            var fullPath = Path.GetFullPath(path);
            if (!IsSameOrUnderDirectory(fullPath, fullOutputDirectory))
            {
                return string.Empty;
            }

            return NormalizeArtifactRelativePath(Path.GetRelativePath(fullOutputDirectory, fullPath));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    private static string SafeDirectoryName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        try
        {
            return Path.GetDirectoryName(path) ?? string.Empty;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static void AddDataIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Reads Process.Id defensively for shutdown paths.
    /// </summary>
    private static int? SafeProcessId(Process process)
    {
        try
        {
            return process.Id;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Checks whether a process has exited without throwing if state changed.
    /// </summary>
    private static bool HasProcessExited(Process process)
    {
        try
        {
            return process.HasExited;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    /// <summary>
    /// Builds a diagnostic command line string matching the arguments supplied
    /// to ProcessStartInfo.
    /// </summary>
    private static string BuildR0CollectorCommandLine(AgentOptions options)
    {
        var arguments = new List<string>
        {
            QuoteCommandLineArgument(options.R0CollectorPath ?? string.Empty),
            "--device",
            QuoteCommandLineArgument(options.DriverDevicePath),
            "--output",
            QuoteCommandLineArgument(options.DriverEventsPath ?? string.Empty),
            "--duration",
            options.DurationSeconds.ToString(CultureInfo.InvariantCulture),
            "--max-events",
            options.R0CollectorMaxEventsPerRead.ToString(CultureInfo.InvariantCulture),
            "--max-read-batches",
            options.R0CollectorMaxReadBatches.ToString(CultureInfo.InvariantCulture),
            "--driver-event-sample-stride",
            options.R0CollectorDriverEventSampleStride.ToString(CultureInfo.InvariantCulture)
        };

        if (options.R0Mock)
        {
            arguments.Add("--mock");
        }

        return string.Join(" ", arguments);
    }

    /// <summary>
    /// Quotes command-line arguments for diagnostic display.
    /// </summary>
    private static string QuoteCommandLineArgument(string value)
    {
        if (value.Length == 0)
        {
            return "\"\"";
        }

        if (!value.Any(char.IsWhiteSpace) && !value.Contains('"', StringComparison.Ordinal))
        {
            return value;
        }

        return $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\"";
    }

    /// <summary>
    /// Creates the parent directory for a sidecar JSONL file when needed.
    /// The input is an output file path; processing extracts its directory and
    /// creates it if non-empty; the method returns no value.
    /// </summary>
    private static void EnsureParentDirectory(string path)
    {
        var parentDirectory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(parentDirectory))
        {
            Directory.CreateDirectory(parentDirectory);
        }
    }

    /// <summary>
    /// Waits for a process with timeout support.
    /// Inputs are a Process and timeout, processing races process exit against
    /// a delay, and the method returns true when the process exits in time.
    /// </summary>
    private static async Task<bool> WaitForExitAsync(Process process, TimeSpan timeout)
    {
        var exitTask = process.WaitForExitAsync();
        var delayTask = Task.Delay(timeout);
        return await Task.WhenAny(exitTask, delayTask) == exitTask;
    }

    /// <summary>
    /// Adds a single guest environment snapshot event before the sample starts.
    /// Inputs are the event output list, parsed options, and selected sample
    /// working directory; processing reads stable operating-system, user, host,
    /// architecture, and directory values; the method returns no value.
    /// </summary>
    private static void AddEnvironmentSnapshotEvent(List<SandboxEvent> events, AgentOptions options, string workingDirectory)
    {
        events.Add(new SandboxEvent
        {
            EventType = "environment.snapshot",
            Source = "guest",
            Path = options.SamplePath,
            Data =
            {
                ["osDescription"] = RuntimeInformation.OSDescription,
                ["osArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
                ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                ["is64BitOperatingSystem"] = Environment.Is64BitOperatingSystem.ToString(),
                ["userName"] = Environment.UserName,
                ["userDomainName"] = Environment.UserDomainName,
                ["machineName"] = Environment.MachineName,
                ["currentDirectory"] = Environment.CurrentDirectory,
                ["workingDirectory"] = workingDirectory,
                ["systemDirectory"] = Environment.SystemDirectory
            }
        });
    }

    /// <summary>
    /// Creates a non-fatal sample execution diagnostic event.
    /// Inputs are event type, sample path, optional process id, execution stage,
    /// and exception; processing stores all error detail in Data so artifact
    /// writing can continue; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateSampleExecutionFailureEvent(
        string eventType,
        string samplePath,
        int? processId,
        string stage,
        Exception exception)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessName = SafeFileName(samplePath),
            ProcessId = processId,
            Path = samplePath,
            Data =
            {
                ["stage"] = stage,
                ["nonfatal"] = "true",
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message,
                ["zhMessage"] = $"样本执行在 {stage} 阶段失败；Guest Agent 会尽量继续写出已收集证据。",
                ["zhHint"] = "请查看 exceptionType/message、样本路径、权限以及后续 process/file/network 事件来定位原因。"
            }
        };
    }

    /// <summary>
    /// Reads a filename for diagnostics without throwing on malformed paths.
    /// </summary>
    private static string? SafeFileName(string path)
    {
        try
        {
            return string.IsNullOrWhiteSpace(path) ? null : Path.GetFileName(path);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Captures visible process metadata for before/after comparison.
    /// There are no inputs; processing enumerates Process.GetProcesses and
    /// reads names, executable paths, and start times defensively because some
    /// system processes deny access; the method returns a keyed snapshot.
    /// </summary>
    private static Dictionary<string, ProcessSnapshot> SnapshotProcesses()
    {
        var snapshot = new Dictionary<string, ProcessSnapshot>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    var processName = TryReadProcessValue(process, static p => p.ProcessName, "unknown");
                    var path = TryReadProcessValue<string?>(process, static p => p.MainModule?.FileName, null);
                    var startTimeUtc = TryReadProcessValue<DateTime?>(process, static p => p.StartTime.ToUniversalTime(), null);
                    var current = new ProcessSnapshot(process.Id, processName, path, startTimeUtc);
                    snapshot[current.Key] = current;
                }
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Win32Exception)
        {
        }

        return snapshot;
    }

    /// <summary>
    /// Adds baseline process observation events from a process snapshot.
    /// Inputs are the event output list, a process snapshot, and a phase label;
    /// processing emits process.observed events with stable metadata; the method
    /// returns no value.
    /// </summary>
    private static void AddProcessObservationEvents(List<SandboxEvent> events, Dictionary<string, ProcessSnapshot> snapshot, string phase)
    {
        foreach (var process in snapshot.Values.OrderBy(process => process.ProcessId).ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase))
        {
            events.Add(CreateProcessSnapshotEvent("process.observed", process, phase));
        }
    }

    /// <summary>
    /// Adds process list delta events for processes not present in the baseline.
    /// Inputs are the event output list, before and after process snapshots, a
    /// phase label, and emitted keys; processing compares snapshot keys and
    /// emits each new process once; the method returns no value.
    /// </summary>
    private static void AddProcessDeltaEvents(
        List<SandboxEvent> events,
        Dictionary<string, ProcessSnapshot> before,
        Dictionary<string, ProcessSnapshot> after,
        string phase,
        HashSet<string> emittedKeys)
    {
        foreach (var (key, process) in after.OrderBy(pair => pair.Value.ProcessId).ThenBy(pair => pair.Value.ProcessName, StringComparer.OrdinalIgnoreCase))
        {
            if (before.ContainsKey(key) || !emittedKeys.Add(key))
            {
                continue;
            }

            events.Add(CreateProcessSnapshotEvent("process.new", process, phase));
        }
    }

    /// <summary>
    /// Creates a normalized SandboxEvent from one process snapshot.
    /// Inputs are the event type, captured process data, and a phase label;
    /// processing copies common fields and adds snapshot metadata to Data; the
    /// method returns the event to append to the output stream.
    /// </summary>
    private static SandboxEvent CreateProcessSnapshotEvent(string eventType, ProcessSnapshot process, string phase)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessName = process.ProcessName,
            ProcessId = process.ProcessId,
            Path = process.Path,
            Data =
            {
                ["phase"] = phase,
                ["snapshotKey"] = process.Key
            }
        };

        if (process.StartTimeUtc is not null)
        {
            evt.Data["startTimeUtc"] = process.StartTimeUtc.Value.ToString("O");
        }

        return evt;
    }

    /// <summary>
    /// Reads one Process property while tolerating protected or exited targets.
    /// Inputs are the Process instance, a value selector, and a fallback value;
    /// processing catches expected process-access exceptions; the method
    /// returns the selected value or the fallback.
    /// </summary>
    private static T TryReadProcessValue<T>(Process process, Func<Process, T> read, T fallback)
    {
        try
        {
            return read(process);
        }
        catch (InvalidOperationException)
        {
            return fallback;
        }
        catch (Win32Exception)
        {
            return fallback;
        }
        catch (NotSupportedException)
        {
            return fallback;
        }
    }

    /// <summary>
    /// Captures file timestamps and sizes for one directory tree.
    /// Inputs are a root directory, processing enumerates files defensively,
    /// and the method returns a path-to-metadata dictionary.
    /// </summary>
    private static Dictionary<string, FileSnapshot> SnapshotFiles(string root)
    {
        var files = new Dictionary<string, FileSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            try
            {
                var info = new FileInfo(path);
                files[path] = new FileSnapshot(info.Length, info.LastWriteTimeUtc);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return files;
    }

    /// <summary>
    /// Captures active TCP connections visible to the guest user.
    /// There are no inputs; processing queries IPGlobalProperties; the method
    /// returns keyed connection snapshots with parsed local/remote/state fields.
    /// </summary>
    private static Dictionary<string, TcpConnectionSnapshot> SnapshotTcpConnections()
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpConnections()
                .Select(connection => new TcpConnectionSnapshot(connection.LocalEndPoint, connection.RemoteEndPoint, connection.State.ToString()))
                .ToDictionary(connection => connection.Key, StringComparer.OrdinalIgnoreCase);
        }
        catch (NetworkInformationException)
        {
            return new Dictionary<string, TcpConnectionSnapshot>(StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Adds events for files created or modified during execution.
    /// Inputs are event output, root path, and before/after snapshots;
    /// processing compares size and timestamp metadata; the method returns no
    /// value.
    /// </summary>
    private static void AddFileDeltaEvents(List<SandboxEvent> events, string root, Dictionary<string, FileSnapshot> before, Dictionary<string, FileSnapshot> after)
    {
        foreach (var (path, current) in after)
        {
            if (!before.TryGetValue(path, out var previous))
            {
                events.Add(new SandboxEvent { EventType = "file.created", Source = "guest", Path = path });
            }
            else if (previous != current)
            {
                events.Add(new SandboxEvent { EventType = "file.modified", Source = "guest", Path = path });
            }
        }

        foreach (var path in before.Keys.Except(after.Keys, StringComparer.OrdinalIgnoreCase))
        {
            events.Add(new SandboxEvent { EventType = "file.deleted", Source = "guest", Path = path });
        }
    }

    /// <summary>
    /// Adds events for new TCP connections observed after execution.
    /// Inputs are event output and before/after connection sets; processing
    /// computes the set difference; the method returns no value.
    /// </summary>
    private static void AddTcpDeltaEvents(List<SandboxEvent> events, Dictionary<string, TcpConnectionSnapshot> before, Dictionary<string, TcpConnectionSnapshot> after)
    {
        foreach (var (key, connection) in after)
        {
            if (before.ContainsKey(key))
            {
                continue;
            }

            events.Add(new SandboxEvent
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["connection"] = connection.Key,
                    ["local"] = connection.Local,
                    ["remote"] = connection.Remote,
                    ["state"] = connection.State,
                    ["localAddress"] = connection.LocalEndPoint.Address.ToString(),
                    ["localPort"] = connection.LocalEndPoint.Port.ToString(),
                    ["remoteAddress"] = connection.RemoteEndPoint.Address.ToString(),
                    ["remotePort"] = connection.RemoteEndPoint.Port.ToString()
                }
            });
        }
    }

    /// <summary>
    /// Reads optional driver JSONL events produced by the R0Collector sidecar.
    /// The input is the --driver-events path, processing delegates parsing to
    /// DriverJsonLinesReader so malformed lines and read errors remain visible
    /// as guest evidence, and the method returns normalized events for
    /// inclusion in events.json.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> ReadDriverEvents(string? path)
    {
        var driverJsonLinesReader = new DriverJsonLinesReader();
        return driverJsonLinesReader.Read(path);
    }

    /// <summary>
    /// Writes events, optional dropped-file artifacts, optional screenshot and
    /// memory-dump paths, and a compact summary into the output directory.
    /// Inputs are agent options and event list; processing copies opt-in
    /// dropped files before serializing final event and summary JSON files; the
    /// method returns no value.
    /// </summary>
    private static void WriteArtifacts(AgentOptions options, List<SandboxEvent> events)
    {
        var artifactWriter = new GuestArtifactWriter();
        var droppedFileMetadataByRelativePath = options.CollectDroppedFiles
            ? CopyDroppedFileArtifacts(options, events)
            : new Dictionary<string, DroppedFileArtifactMetadata>(StringComparer.OrdinalIgnoreCase);
        if (!options.CollectDroppedFiles)
        {
            events.Add(CreateDroppedFilesDisabledEvent(options, events));
        }

        GuestSelfNoiseMetadata.Apply(events);
        TryWriteArtifactManifest(options, events, artifactWriter, droppedFileMetadataByRelativePath);
        GuestSelfNoiseMetadata.Apply(events);

        artifactWriter.WriteEvents(options.OutputDirectory, events);
        artifactWriter.WriteSummary(options.OutputDirectory, options.SamplePath, events.Count);
    }

    /// <summary>
    /// Copies newly-created files from the sample working directory into the
    /// guest output artifact tree when explicitly enabled.
    /// Inputs are parsed options and collected file events; processing copies
    /// file.created paths outside --out into artifacts/dropped-files and emits
    /// copy/skip events; the method returns metadata keyed by manifest-relative
    /// copied artifact path.
    /// </summary>
    private static Dictionary<string, DroppedFileArtifactMetadata> CopyDroppedFileArtifacts(AgentOptions options, List<SandboxEvent> events)
    {
        var metadataByRelativePath = new Dictionary<string, DroppedFileArtifactMetadata>(StringComparer.OrdinalIgnoreCase);
        var usedArtifactRelativePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var candidates = events
            .Where(static evt =>
                string.Equals(evt.EventType, "file.created", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(evt.EventType, "file.modified", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var processContext = CreateDroppedFileProcessContext(options, events);
        var candidateCreatedFileCount = candidates.Count(static evt => string.Equals(evt.EventType, "file.created", StringComparison.OrdinalIgnoreCase));
        var candidateModifiedFileCount = candidates.Count(static evt => string.Equals(evt.EventType, "file.modified", StringComparison.OrdinalIgnoreCase));

        if (candidates.Count == 0)
        {
            events.Add(CreateDroppedFileSummaryEvent(
                processContext,
                candidateCreatedFileCount,
                candidateModifiedFileCount,
                copiedCount: 0,
                skippedCount: 0,
                artifactCount: 0));
            return metadataByRelativePath;
        }

        var workingDirectory = Path.GetFullPath(Path.GetDirectoryName(options.SamplePath) ?? Environment.CurrentDirectory);
        var outputDirectory = Path.GetFullPath(options.OutputDirectory);
        var artifactsRoot = Path.Combine(outputDirectory, GuestArtifactWriter.ArtifactsDirectoryName);
        var droppedFilesRoot = Path.Combine(artifactsRoot, DroppedFilesArtifactDirectoryName);
        var copyOutcomeStartIndex = events.Count;

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate.Path))
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "sourcePathMissing", processContext: processContext));
                continue;
            }

            string sourcePath;
            try
            {
                sourcePath = Path.GetFullPath(candidate.Path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "sourcePathInvalid", exception: ex, processContext: processContext));
                continue;
            }

            if (!IsSameOrUnderDirectory(sourcePath, workingDirectory))
            {
                events.Add(CreateDroppedFileSkippedEvent(
                    candidate,
                    reason: "outsideWorkingDirectory",
                    sourcePath: sourcePath,
                    sourceEvidence: ReadDroppedFileSourceEvidence(sourcePath, computeHash: false),
                    processContext: processContext));
                continue;
            }

            if (IsSameOrUnderDirectory(sourcePath, outputDirectory))
            {
                events.Add(CreateDroppedFileSkippedEvent(
                    candidate,
                    reason: "underOutputDirectory",
                    sourcePath: sourcePath,
                    sourceEvidence: ReadDroppedFileSourceEvidence(sourcePath, computeHash: false),
                    processContext: processContext));
                continue;
            }

            if (!File.Exists(sourcePath))
            {
                events.Add(CreateDroppedFileSkippedEvent(
                    candidate,
                    reason: "sourceFileMissing",
                    sourcePath: sourcePath,
                    sourceEvidence: ReadDroppedFileSourceEvidence(sourcePath, computeHash: false),
                    processContext: processContext));
                continue;
            }

            var originalRelativePath = GetOriginalRelativePath(candidate, workingDirectory, sourcePath);
            var safeRelativePath = BuildSafeDroppedFileRelativePath(originalRelativePath, sourcePath);
            var destination = CreateDroppedFileDestination(
                droppedFilesRoot,
                outputDirectory,
                safeRelativePath,
                sourcePath,
                usedArtifactRelativePaths);
            if (destination is null)
            {
                events.Add(CreateDroppedFileSkippedEvent(
                    candidate,
                    reason: "destinationPathInvalid",
                    sourcePath: sourcePath,
                    sourceEvidence: ReadDroppedFileSourceEvidence(sourcePath, computeHash: false),
                    processContext: processContext));
                continue;
            }

            try
            {
                var sourceEvidence = ReadDroppedFileSourceEvidence(sourcePath, computeHash: true);
                if (sourceEvidence.Exists == false)
                {
                    events.Add(CreateDroppedFileSkippedEvent(
                        candidate,
                        reason: "sourceFileMissing",
                        sourcePath: sourcePath,
                        sourceEvidence: sourceEvidence,
                        processContext: processContext));
                    continue;
                }

                var sourceInfo = new FileInfo(sourcePath);
                Directory.CreateDirectory(Path.GetDirectoryName(destination.FullPath) ?? droppedFilesRoot);
                CopyFileSharedRead(sourcePath, destination.FullPath);
                var copiedInfo = new FileInfo(destination.FullPath);
                var copiedHash = ComputeSha256BestEffort(destination.FullPath);
                var copiedAtUtc = DateTimeOffset.UtcNow;
                usedArtifactRelativePaths.Add(destination.ArtifactRelativePath);
                metadataByRelativePath[destination.ArtifactRelativePath] = new DroppedFileArtifactMetadata(
                    sourcePath,
                    originalRelativePath,
                    candidate.EventType,
                    sourceInfo.Length,
                    sourceInfo.CreationTimeUtc,
                    sourceInfo.LastWriteTimeUtc,
                    candidate.Timestamp,
                    copiedAtUtc,
                    sourceEvidence.Sha256,
                    copiedHash.Sha256);
                events.Add(CreateDroppedFileCopiedEvent(
                    candidate,
                    sourcePath,
                    originalRelativePath,
                    destination.FullPath,
                    destination.ArtifactRelativePath,
                    sourceInfo,
                    copiedInfo,
                    copiedAtUtc,
                    processContext,
                    sourceEvidence,
                    copiedHash));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
            {
                events.Add(CreateDroppedFileSkippedEvent(
                    candidate,
                    reason: "copyFailed",
                    sourcePath: sourcePath,
                    sourceEvidence: ReadDroppedFileSourceEvidence(sourcePath, computeHash: true),
                    exception: ex,
                    processContext: processContext));
            }
        }

        var copyOutcomeEvents = events.Skip(copyOutcomeStartIndex).ToList();
        events.Add(CreateDroppedFileSummaryEvent(
            processContext,
            candidateCreatedFileCount,
            candidateModifiedFileCount,
            copyOutcomeEvents.Count(static evt => string.Equals(evt.EventType, "artifact.dropped_file.copied", StringComparison.OrdinalIgnoreCase)),
            copyOutcomeEvents.Count(static evt => string.Equals(evt.EventType, "artifact.dropped_file.skipped", StringComparison.OrdinalIgnoreCase)),
            metadataByRelativePath.Count,
            copyOutcomeEvents));
        return metadataByRelativePath;
    }

    /// <summary>
    /// Writes the guest artifact manifest and records the outcome as a guest
    /// event. Inputs are options, event list, writer, and copied artifact
    /// metadata; processing writes artifacts/manifest.json best-effort with
    /// collection-lane status for screenshots, dropped files, memory dumps,
    /// driver events, R0 logs, and future packet captures; the method returns
    /// no value.
    /// </summary>
    private static void TryWriteArtifactManifest(
        AgentOptions options,
        List<SandboxEvent> events,
        GuestArtifactWriter artifactWriter,
        IReadOnlyDictionary<string, DroppedFileArtifactMetadata> droppedFileMetadataByRelativePath)
    {
        try
        {
            var manifestResult = artifactWriter.WriteArtifactManifest(
                options.OutputDirectory,
                droppedFileMetadataByRelativePath,
                events,
                new GuestArtifactCollectionOptions
                {
                    CaptureScreenshots = options.CaptureScreenshots,
                    CollectDroppedFiles = options.CollectDroppedFiles,
                    CaptureMemoryDump = options.CaptureMemoryDump,
                    CapturePacketCapture = options.CapturePacketCapture,
                    DriverEventsRequested = !string.IsNullOrWhiteSpace(options.DriverEventsPath),
                    R0CollectorRequested = !string.IsNullOrWhiteSpace(options.R0CollectorPath) || options.R0Mock
                });
            var manifestRelativePath = NormalizeArtifactRelativePath(Path.GetRelativePath(options.OutputDirectory, manifestResult.ManifestPath));
            var manifestEvent = new SandboxEvent
            {
                EventType = "artifact.manifest.written",
                Source = "guest",
                Path = manifestResult.ManifestPath,
                Data =
                {
                    ["artifactCount"] = manifestResult.ArtifactCount.ToString(CultureInfo.InvariantCulture),
                    ["collectionCount"] = manifestResult.CollectionCount.ToString(CultureInfo.InvariantCulture),
                    ["copiedDroppedFileCount"] = droppedFileMetadataByRelativePath.Count.ToString(CultureInfo.InvariantCulture),
                    ["collectDroppedFiles"] = options.CollectDroppedFiles.ToString(),
                    ["captureScreenshots"] = options.CaptureScreenshots.ToString(),
                    ["capturePolicy"] = "manifest-summary-of-guest-artifact-lanes",
                    ["screenshotPhases"] = options.ScreenshotOptions.FormatStages(),
                    ["screenshotCount"] = options.ScreenshotOptions.CaptureCount.ToString(CultureInfo.InvariantCulture),
                    ["captureMemoryDump"] = options.CaptureMemoryDump.ToString(),
                    ["capturePacketCapture"] = options.CapturePacketCapture.ToString(),
                    ["relativePath"] = manifestRelativePath,
                    ["artifactRelativePath"] = manifestRelativePath,
                    ["importPath"] = manifestRelativePath,
                    ["artifactRoot"] = Path.Combine(options.OutputDirectory, GuestArtifactWriter.ArtifactsDirectoryName),
                    ["captureState"] = "captured",
                    ["status"] = "captured",
                    ["nonfatal"] = "false",
                    ["artifactEvent"] = "false",
                    ["behaviorCounted"] = "false",
                    ["nonbehavior"] = "true",
                    ["collectionHealth"] = "true",
                    ["zhMessage"] = "Guest artifact manifest 已写入，证据集合摘要可用。",
                    ["zhHint"] = "请使用 artifactRelativePath 下载 manifest；其中 collections metadata 汇总每个证据通道的 captured/skipped/failed/disabled 状态。"
                }
            };
            AddManifestFileEvidence(manifestEvent, manifestResult.ManifestPath);
            events.Add(manifestEvent);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            var evt = new SandboxEvent
            {
                EventType = "artifact.manifest.failed",
                Source = "guest",
                Path = Path.Combine(options.OutputDirectory, GuestArtifactWriter.ArtifactsDirectoryName, GuestArtifactWriter.ManifestFileName),
                Data =
                {
                    ["collectDroppedFiles"] = options.CollectDroppedFiles.ToString(),
                    ["captureScreenshots"] = options.CaptureScreenshots.ToString(),
                    ["capturePolicy"] = "manifest-summary-of-guest-artifact-lanes",
                    ["screenshotPhases"] = options.ScreenshotOptions.FormatStages(),
                    ["screenshotCount"] = options.ScreenshotOptions.CaptureCount.ToString(CultureInfo.InvariantCulture),
                    ["captureMemoryDump"] = options.CaptureMemoryDump.ToString(),
                    ["capturePacketCapture"] = options.CapturePacketCapture.ToString(),
                    ["reason"] = "writeFailed",
                    ["reasonCode"] = "writeFailed",
                    ["reasonCategory"] = "manifest-io",
                    ["artifactEvent"] = "false",
                    ["behaviorCounted"] = "false",
                    ["nonbehavior"] = "true",
                    ["collectionHealth"] = "true",
                    ["nonfatal"] = "true",
                    ["zhMessage"] = "Guest artifact manifest 写入失败，但事件 JSON 仍会尽量写出。",
                    ["zhHint"] = "请检查 --out 目录权限、磁盘空间、路径长度，以及 artifacts/manifest.json 是否被其他进程占用。"
                }
            };
            AddExceptionData(evt, ex);
            events.Add(evt);
        }
    }

    /// <summary>
    /// Adds manifest file size/hash metadata to artifact.manifest.written.
    /// </summary>
    private static void AddManifestFileEvidence(SandboxEvent evt, string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                evt.Data["artifactHashStatus"] = "missing";
                evt.Data["artifactExists"] = "false";
                evt.Data["artifactIntegrityState"] = "missing";
                evt.Data["sizeBytesStatus"] = "missing";
                evt.Data["sha256Status"] = "missing";
                return;
            }

            evt.Data["artifactExists"] = "true";
            evt.Data["sizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactSizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["sizeBytesStatus"] = "computed";
            evt.Data["artifactLastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            var hash = ComputeSha256BestEffort(path);
            if (!string.IsNullOrWhiteSpace(hash.Sha256))
            {
                evt.Data["sha256"] = hash.Sha256;
                evt.Data["artifactSha256"] = hash.Sha256;
                evt.Data["hashAlgorithm"] = "sha256";
                evt.Data["sha256Status"] = "computed";
            }

            evt.Data["artifactHashStatus"] = hash.Status;
            evt.Data.TryAdd("sha256Status", hash.Status);
            evt.Data["artifactIntegrityState"] = hash.Status == "computed" ? "verified" : "hash-failed";
            AddDataIfNotEmpty(evt.Data, "artifactHashExceptionType", hash.ExceptionType);
            AddDataIfNotEmpty(evt.Data, "artifactHashMessage", hash.Message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data["artifactHashStatus"] = "failed";
            evt.Data["artifactIntegrityState"] = "hash-failed";
            evt.Data["sha256Status"] = "failed";
            evt.Data["artifactHashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["artifactHashMessage"] = ex.Message;
        }
    }

    /// <summary>
    /// Creates an event for a copied dropped-file artifact.
    /// Inputs are source and destination paths plus metadata; processing stores
    /// paths and sizes as strings; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateDroppedFileCopiedEvent(
        SandboxEvent sourceEvent,
        string sourcePath,
        string originalRelativePath,
        string destinationPath,
        string artifactRelativePath,
        FileInfo sourceInfo,
        FileInfo copiedInfo,
        DateTimeOffset copiedAtUtc,
        DroppedFileProcessContext processContext,
        DroppedFileSourceEvidence sourceEvidence,
        DroppedFileHashResult copiedHash)
    {
        var evt = new SandboxEvent
        {
            EventType = "artifact.dropped_file.copied",
            Source = "guest",
            Path = destinationPath,
            ProcessName = processContext.ProcessName,
            ProcessId = processContext.RootProcessId,
            ParentProcessId = processContext.ParentProcessId,
            CommandLine = processContext.CommandLine,
            Data =
            {
                ["phase"] = "after-run",
                ["capturePhase"] = "after-run",
                ["sourcePath"] = sourcePath,
                ["guestFullPath"] = sourcePath,
                ["guestRelativePath"] = originalRelativePath,
                ["dropCandidateType"] = DroppedFileCandidateType(sourceEvent),
                ["copyMethod"] = "shared-read-stream-copy",
                ["artifactRelativePath"] = artifactRelativePath,
                ["relativePath"] = artifactRelativePath,
                ["importPath"] = artifactRelativePath,
                ["artifactFullPath"] = destinationPath,
                ["sizeBytes"] = copiedInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["artifactSizeBytes"] = copiedInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["copiedSizeBytes"] = copiedInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["sourceSizeBytes"] = sourceInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["sourceCreatedUtc"] = sourceInfo.CreationTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["sourceLastWriteUtc"] = sourceInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["sourceMtimeUtc"] = sourceInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["copiedCreatedUtc"] = copiedInfo.CreationTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["copiedLastWriteUtc"] = copiedInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["artifactLastWriteUtc"] = copiedInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["mtimeUtc"] = copiedInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["copiedAtUtc"] = copiedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["collectionName"] = "dropped-files",
                ["evidenceRole"] = "dropped-file",
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-copy-working-directory-new-files",
                ["artifactRelativePathStatus"] = "captured",
                ["captureState"] = "captured",
                ["status"] = "captured",
                ["reason"] = "artifactCopied",
                ["reasonCode"] = "artifactCopied",
                ["reasonCategory"] = "captured",
                ["reasonTaxonomy"] = DroppedFileReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["nonfatal"] = "false",
                ["artifactEvent"] = "true",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["artifactExists"] = copiedInfo.Exists.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["artifactIntegrityState"] = DroppedFileArtifactIntegrityState(copiedHash),
                ["sizeBytesStatus"] = "computed",
                ["sha256Status"] = copiedHash.Status,
                ["artifactSelector"] = artifactRelativePath,
                ["stableArtifactSelector"] = artifactRelativePath,
                ["canonicalArtifactSelector"] = artifactRelativePath,
                ["downloadSelector"] = artifactRelativePath,
                ["artifactSafeLink"] = BuildArtifactSafeLink(artifactRelativePath),
                ["artifactSelectorKind"] = "safe-output-relative-path",
                ["artifactSelectorVersion"] = DroppedFileSelectorVersion,
                ["artifactSelectionReason"] = "copied-dropped-file",
                ["processRole"] = processContext.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["zhMessage"] = "掉落文件已复制为可下载证据文件。",
                ["zhHint"] = "请使用 artifactRelativePath 下载复制后的文件；sourceSha256/copiedSha256 可用于比对源文件与证据文件。",
                ["expectedRelativePath"] = "artifacts/dropped-files/**",
                ["collectDroppedFiles"] = "true"
            }
        };

        AddDroppedFileProcessContext(evt, processContext);
        AddDroppedFileSourceEventData(evt, sourceEvent);
        AddDroppedFileSourceEvidenceData(evt, sourceEvidence);
        AddDroppedFileHashData(evt, copiedHash, prefix: "copied");
        if (!string.IsNullOrWhiteSpace(copiedHash.Sha256))
        {
            evt.Data["sha256"] = copiedHash.Sha256;
            evt.Data["artifactSha256"] = copiedHash.Sha256;
            evt.Data["hashAlgorithm"] = "sha256";
            evt.Data["artifactHashAlgorithm"] = "sha256";
        }

        if (!string.IsNullOrWhiteSpace(copiedHash.Status))
        {
            evt.Data["hashStatus"] = copiedHash.Status;
            evt.Data["artifactHashStatus"] = copiedHash.Status;
        }

        if (!string.IsNullOrWhiteSpace(sourceEvidence.Sha256) && !string.IsNullOrWhiteSpace(copiedHash.Sha256))
        {
            evt.Data["sourceCopiedSha256Match"] = string.Equals(sourceEvidence.Sha256, copiedHash.Sha256, StringComparison.OrdinalIgnoreCase)
                .ToString(CultureInfo.InvariantCulture)
                .ToLowerInvariant();
            evt.Data["artifactIntegrityState"] = string.Equals(sourceEvidence.Sha256, copiedHash.Sha256, StringComparison.OrdinalIgnoreCase)
                ? "verified-source-copy-match"
                : "hash-mismatch";
        }

        return evt;
    }

    /// <summary>
    /// Creates an event for a skipped dropped-file copy attempt.
    /// Inputs are the source file event, reason, optional normalized path, and
    /// exception; processing records diagnostics in Data; the method returns a
    /// SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateDroppedFileSkippedEvent(
        SandboxEvent sourceEvent,
        string reason,
        string? sourcePath = null,
        DroppedFileSourceEvidence? sourceEvidence = null,
        Exception? exception = null,
        DroppedFileProcessContext? processContext = null)
    {
        var evt = new SandboxEvent
        {
            EventType = "artifact.dropped_file.skipped",
            Source = "guest",
            Path = sourcePath ?? sourceEvent.Path,
            ProcessName = processContext?.ProcessName,
            ProcessId = processContext?.RootProcessId,
            ParentProcessId = processContext?.ParentProcessId,
            CommandLine = processContext?.CommandLine,
            Data =
            {
                ["phase"] = "after-run",
                ["capturePhase"] = "after-run",
                ["reason"] = reason,
                ["skipReason"] = reason,
                ["reasonCode"] = reason,
                ["reasonCategory"] = DroppedFileReasonCategory(reason),
                ["reasonTaxonomy"] = DroppedFileReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhReason"] = DroppedFileReasonZhReason(reason),
                ["zhMessage"] = "掉落文件复制被跳过；该事件说明证据缺口，不会中断整体分析。",
                ["zhHint"] = DroppedFileReasonZhHint(reason),
                ["sourceEventType"] = sourceEvent.EventType,
                ["dropCandidateType"] = DroppedFileCandidateType(sourceEvent),
                ["copyMethod"] = "shared-read-stream-copy",
                ["sourcePath"] = sourcePath ?? sourceEvent.Path ?? string.Empty,
                ["guestFullPath"] = sourcePath ?? sourceEvent.Path ?? string.Empty,
                ["collectionName"] = "dropped-files",
                ["evidenceRole"] = "dropped-file",
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-copy-working-directory-new-files",
                ["captureState"] = "skipped",
                ["status"] = "skipped",
                ["nonfatal"] = "true",
                ["artifactEvent"] = "false",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["processRole"] = processContext?.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["expectedRelativePath"] = "artifacts/dropped-files/**",
                ["artifactRelativePathStatus"] = "not-created",
                ["artifactExists"] = "false",
                ["artifactIntegrityState"] = "skipped",
                ["sizeBytesStatus"] = "not-created",
                ["sha256Status"] = "not-created",
                ["collectDroppedFiles"] = "true"
            }
        };

        AddDroppedFileProcessContext(evt, processContext);
        if (sourceEvent.Data.TryGetValue("relativePath", out var relativePath))
        {
            evt.Data["guestRelativePath"] = relativePath;
        }

        AddDroppedFileSourceEventData(evt, sourceEvent);
        if (sourceEvidence is not null)
        {
            AddDroppedFileSourceEvidenceData(evt, sourceEvidence);
        }

        AddExceptionData(evt, exception);
        return evt;
    }

    /// <summary>
    /// Creates a dropped-file collection summary for copied/skipped outcomes.
    /// </summary>
    private static SandboxEvent CreateDroppedFileSummaryEvent(
        DroppedFileProcessContext processContext,
        int candidateCreatedFileCount,
        int candidateModifiedFileCount,
        int copiedCount,
        int skippedCount,
        int artifactCount,
        IReadOnlyList<SandboxEvent>? copyOutcomeEvents = null)
    {
        var candidateFileCount = candidateCreatedFileCount + candidateModifiedFileCount;
        var status = copiedCount > 0
            ? "captured"
            : skippedCount > 0
                ? "skipped"
                : "enabled-empty";
        var outcomeEvents = copyOutcomeEvents ?? Array.Empty<SandboxEvent>();
        var reason = DroppedFileSummaryReason(candidateFileCount, copiedCount, skippedCount);
        var evt = new SandboxEvent
        {
            EventType = "artifact.dropped_file.summary",
            Source = "guest",
            ProcessName = processContext.ProcessName,
            ProcessId = processContext.RootProcessId,
            ParentProcessId = processContext.ParentProcessId,
            CommandLine = processContext.CommandLine,
            Data =
            {
                ["phase"] = "after-run",
                ["capturePhase"] = "after-run",
                ["collectionName"] = "dropped-files",
                ["evidenceRole"] = "dropped-file",
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-copy-working-directory-new-files",
                ["captureState"] = status,
                ["status"] = status,
                ["reason"] = reason,
                ["reasonCode"] = reason,
                ["reasonCategory"] = copiedCount > 0 ? "captured" : skippedCount > 0 ? "skipped" : "empty",
                ["reasonTaxonomy"] = DroppedFileReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhReason"] = DroppedFileSummaryZhReason(reason),
                ["summaryEvent"] = "true",
                ["nonfatal"] = "true",
                ["artifactEvent"] = "false",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["processRole"] = processContext.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["expectedRelativePath"] = "artifacts/dropped-files/**",
                ["artifactRelativePathStatus"] = copiedCount > 0 ? "some-captured" : "not-created",
                ["artifactIntegrityState"] = DroppedFileSummaryIntegrityState(outcomeEvents, copiedCount),
                ["collectDroppedFiles"] = "true",
                ["candidateFileCount"] = candidateFileCount.ToString(CultureInfo.InvariantCulture),
                ["candidateCreatedFileCount"] = candidateCreatedFileCount.ToString(CultureInfo.InvariantCulture),
                ["candidateModifiedFileCount"] = candidateModifiedFileCount.ToString(CultureInfo.InvariantCulture),
                ["copyOutcomeEventCount"] = (copiedCount + skippedCount).ToString(CultureInfo.InvariantCulture),
                ["copiedCount"] = copiedCount.ToString(CultureInfo.InvariantCulture),
                ["copiedDroppedFileCount"] = copiedCount.ToString(CultureInfo.InvariantCulture),
                ["skippedCount"] = skippedCount.ToString(CultureInfo.InvariantCulture),
                ["copiedHashComputedCount"] = CountOutcomeDataValue(outcomeEvents, "copiedHashStatus", "computed").ToString(CultureInfo.InvariantCulture),
                ["copiedHashFailedCount"] = CountOutcomeDataValue(outcomeEvents, "copiedHashStatus", "failed").ToString(CultureInfo.InvariantCulture),
                ["sourceHashComputedCount"] = CountOutcomeDataValue(outcomeEvents, "sourceHashStatus", "computed").ToString(CultureInfo.InvariantCulture),
                ["sourceHashFailedCount"] = CountOutcomeDataValue(outcomeEvents, "sourceHashStatus", "failed").ToString(CultureInfo.InvariantCulture),
                ["artifactCount"] = artifactCount.ToString(CultureInfo.InvariantCulture),
                ["artifactSelectorVersion"] = DroppedFileSelectorVersion,
                ["copyMethod"] = "shared-read-stream-copy",
                ["zhMessage"] = copiedCount > 0
                    ? "掉落文件复制 sweep 已完成，并已产出可下载证据文件。"
                    : "掉落文件复制 sweep 已完成，但没有产出可下载证据文件。",
                ["zhHint"] = "请结合 candidateCreatedFileCount/candidateModifiedFileCount、copiedCount/skippedCount 以及 artifact.dropped_file.* 事件判断掉落文件覆盖情况。"
            }
        };
        AddDroppedFileProcessContext(evt, processContext);
        AddDroppedFileSummaryReasonCounts(evt, outcomeEvents);
        AddDroppedFileSummaryArtifactSelectors(evt, outcomeEvents);
        return evt;
    }

    /// <summary>
    /// Creates a dropped-file lane disabled event when artifact copying was not
    /// explicitly requested.
    /// </summary>
    private static SandboxEvent CreateDroppedFilesDisabledEvent(AgentOptions options, IReadOnlyList<SandboxEvent> events)
    {
        var createdFileEventCount = events.Count(static evt => string.Equals(evt.EventType, "file.created", StringComparison.OrdinalIgnoreCase));
        var processContext = CreateDroppedFileProcessContext(options, events);
        var evt = new SandboxEvent
        {
            EventType = "artifact.dropped_file.disabled",
            Source = "guest",
            ProcessName = processContext.ProcessName,
            ProcessId = processContext.RootProcessId,
            ParentProcessId = processContext.ParentProcessId,
            CommandLine = processContext.CommandLine,
            Data =
            {
                ["phase"] = "after-run",
                ["capturePhase"] = "after-run",
                ["reason"] = "collectDroppedFilesNotRequested",
                ["reasonCode"] = "collectDroppedFilesNotRequested",
                ["reasonCategory"] = "disabled",
                ["reasonTaxonomy"] = DroppedFileReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhReason"] = "未请求掉落文件复制。",
                ["zhMessage"] = "掉落文件复制采集未启用。",
                ["zhHint"] = "未启用 --collect-dropped-files/--dropped-files，Guest Agent 只记录文件事件，不复制新建文件内容。",
                ["collectionName"] = "dropped-files",
                ["evidenceRole"] = "dropped-file",
                ["captureEnabled"] = "false",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-copy-working-directory-new-files",
                ["captureState"] = "disabled",
                ["status"] = "disabled",
                ["nonfatal"] = "true",
                ["artifactEvent"] = "false",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["processRole"] = processContext.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["expectedRelativePath"] = "artifacts/dropped-files/**",
                ["artifactRelativePathStatus"] = "disabled",
                ["artifactExists"] = "false",
                ["artifactIntegrityState"] = "disabled",
                ["sizeBytesStatus"] = "disabled",
                ["sha256Status"] = "disabled",
                ["collectDroppedFiles"] = "false",
                ["candidateCreatedFileCount"] = createdFileEventCount.ToString(CultureInfo.InvariantCulture),
                ["outputDirectory"] = options.OutputDirectory
            }
        };
        AddDroppedFileProcessContext(evt, processContext);
        return evt;
    }

    /// <summary>
    /// Builds best-effort sample-root identity for dropped-file artifact
    /// events. Inputs are agent options and already-collected events; processing
    /// prefers process.start and falls back to later root process events; the
    /// method returns context used only for report attribution.
    /// </summary>
    private static DroppedFileProcessContext CreateDroppedFileProcessContext(AgentOptions options, IReadOnlyList<SandboxEvent> events)
    {
        var rootEvent = events.FirstOrDefault(static evt => string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase)) ??
            events.LastOrDefault(static evt =>
                string.Equals(evt.EventType, "process.exit", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(evt.EventType, "process.timeout", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(evt.EventType, "process.execution_failed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(evt.EventType, "process.start_failed", StringComparison.OrdinalIgnoreCase));
        var rootProcessId = rootEvent?.ProcessId ?? ParseNullableInt(FirstEventData(rootEvent, "rootProcessId", "processId"));
        var parentProcessId = rootEvent?.ParentProcessId ?? ParseNullableInt(FirstEventData(rootEvent, "parentProcessId"));
        var processName = FirstNonEmpty(
            rootEvent?.ProcessName,
            FirstEventData(rootEvent, "processName", "targetProcessName"),
            SafeFileName(options.SamplePath));
        var processPath = FirstNonEmpty(
            rootEvent?.Path,
            FirstEventData(rootEvent, "processImagePath", "imagePath", "targetProcessPath"),
            options.SamplePath);
        var commandLine = FirstNonEmpty(
            rootEvent?.CommandLine,
            FirstEventData(rootEvent, "commandLine"),
            options.SamplePath);
        var startTimeUtc = ParseNullableDateTimeUtc(FirstEventData(rootEvent, "startTimeUtc", "rootProcessStartTimeUtc"));
        return new DroppedFileProcessContext(
            rootProcessId,
            parentProcessId,
            string.IsNullOrWhiteSpace(processName) ? null : processName,
            string.IsNullOrWhiteSpace(processPath) ? null : processPath,
            string.IsNullOrWhiteSpace(commandLine) ? null : commandLine,
            startTimeUtc);
    }

    /// <summary>
    /// Applies sample-root attribution fields to dropped-file artifact events.
    /// Inputs are an event and optional process context; processing adds root
    /// PID, parent PID, root-only lineage, and process-role fields.
    /// </summary>
    private static void AddDroppedFileProcessContext(SandboxEvent evt, DroppedFileProcessContext? processContext)
    {
        if (processContext is null)
        {
            evt.Data.TryAdd("processRole", "sample-context");
            return;
        }

        evt.Data["processRole"] = processContext.RootProcessId is null ? "sample-context" : "sample-root-context";
        if (processContext.RootProcessId is not null)
        {
            var rootPid = processContext.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["rootProcessId"] = rootPid;
            evt.Data["rootProcessIdStatus"] = "available";
            evt.Data.TryAdd("processId", rootPid);
            evt.Data.TryAdd("treeDepth", "0");
            evt.Data.TryAdd("treeLineage", rootPid);
            evt.Data.TryAdd("treeLineageStatus", "stable");
        }
        else
        {
            evt.Data["rootProcessIdStatus"] = "unavailable";
            evt.Data["treeLineageStatus"] = "unavailable";
        }

        if (processContext.ParentProcessId is not null)
        {
            evt.Data["parentProcessId"] = processContext.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddDataIfNotEmpty(evt.Data, "processName", processContext.ProcessName);
        AddDataIfNotEmpty(evt.Data, "targetProcessName", processContext.ProcessName);
        AddDataIfNotEmpty(evt.Data, "processImagePath", processContext.ProcessPath);
        AddDataIfNotEmpty(evt.Data, "targetProcessPath", processContext.ProcessPath);
        AddDataIfNotEmpty(evt.Data, "commandLine", processContext.CommandLine);
        if (processContext.StartTimeUtc is not null)
        {
            evt.Data["rootProcessStartTimeUtc"] = processContext.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }
    }

    private static string? FirstEventData(SandboxEvent? evt, params string[] keys)
    {
        if (evt is null)
        {
            return null;
        }

        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static int? ParseNullableInt(string? value)
    {
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private static DateTime? ParseNullableDateTimeUtc(string? value)
    {
        return DateTime.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    private static string DroppedFileReasonZhHint(string reason)
    {
        return reason switch
        {
            "sourcePathMissing" => "源事件没有可复制路径；请查看原始 file.created 事件。",
            "sourcePathInvalid" => "源路径无法规范化，可能包含非法路径字符或过长路径。",
            "sourceFileMissing" => "复制时源文件已经不存在，可能被样本删除或移动。",
            "outsideWorkingDirectory" => "为避免越界采集，默认只复制样本工作目录下的新建文件。",
            "underOutputDirectory" => "源文件位于输出目录下，跳过以避免把采集产物再次作为样本掉落物复制。",
            "destinationPathInvalid" => "无法在 artifacts/dropped-files 下生成安全目标路径。",
            "copyFailed" => "复制失败；请检查文件锁、权限、路径长度和磁盘空间。",
            _ => "该掉落文件复制尝试被跳过；请结合 reason、sourcePath 和 exceptionType/message 判断。"
        };
    }

    private static string DroppedFileReasonZhReason(string reason)
    {
        return reason switch
        {
            "sourcePathMissing" => "源事件缺少路径。",
            "sourcePathInvalid" => "源路径无效。",
            "sourceFileMissing" => "源文件已不存在。",
            "outsideWorkingDirectory" => "源文件不在样本工作目录内。",
            "underOutputDirectory" => "源文件位于输出目录内。",
            "destinationPathInvalid" => "目标证据路径无效。",
            "copyFailed" => "复制失败。",
            "collectDroppedFilesNotRequested" => "未请求掉落文件复制。",
            _ => "复制尝试被跳过。"
        };
    }

    private static string DroppedFileReasonCategory(string reason)
    {
        return reason switch
        {
            "sourcePathMissing" or "sourcePathInvalid" => "source-path",
            "sourceFileMissing" => "source-missing",
            "outsideWorkingDirectory" or "underOutputDirectory" => "policy",
            "destinationPathInvalid" => "destination-path",
            "copyFailed" => "copy-io",
            "collectDroppedFilesNotRequested" => "disabled",
            _ => "unknown"
        };
    }

    private static string DroppedFileArtifactIntegrityState(DroppedFileHashResult copiedHash)
    {
        return copiedHash.Status switch
        {
            "computed" => "verified",
            "missing" => "missing",
            "failed" => "hash-failed",
            _ => "unknown"
        };
    }

    private static string DroppedFileSummaryReason(int candidateFileCount, int copiedCount, int skippedCount)
    {
        if (copiedCount > 0)
        {
            return skippedCount > 0 ? "someCandidatesCopied" : "allCandidatesCopied";
        }

        if (skippedCount > 0)
        {
            return "allCandidatesSkipped";
        }

        return candidateFileCount == 0 ? "noFileCandidates" : "noCopyOutcomes";
    }

    private static string DroppedFileSummaryZhReason(string reason)
    {
        return reason switch
        {
            "allCandidatesCopied" => "所有候选文件均已复制。",
            "someCandidatesCopied" => "部分候选文件已复制，部分被跳过。",
            "allCandidatesSkipped" => "所有候选文件均被跳过。",
            "noFileCandidates" => "没有发现可复制的文件候选。",
            "noCopyOutcomes" => "没有复制结果事件。",
            _ => "掉落文件复制 sweep 已记录。"
        };
    }

    private static string DroppedFileSummaryIntegrityState(IReadOnlyList<SandboxEvent> outcomeEvents, int copiedCount)
    {
        if (copiedCount == 0)
        {
            return outcomeEvents.Count == 0 ? "not-applicable-empty" : "skipped";
        }

        var copiedEvents = outcomeEvents
            .Where(static evt => string.Equals(evt.EventType, "artifact.dropped_file.copied", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (copiedEvents.Count == 0)
        {
            return "unknown";
        }

        if (copiedEvents.All(static evt =>
            evt.Data.TryGetValue("artifactIntegrityState", out var state) &&
            (string.Equals(state, "verified", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(state, "verified-source-copy-match", StringComparison.OrdinalIgnoreCase))))
        {
            return "verified";
        }

        if (copiedEvents.Any(static evt =>
            evt.Data.TryGetValue("artifactIntegrityState", out var state) &&
            string.Equals(state, "hash-mismatch", StringComparison.OrdinalIgnoreCase)))
        {
            return "hash-mismatch";
        }

        return "partial-integrity";
    }

    private static int CountOutcomeDataValue(IReadOnlyList<SandboxEvent> outcomeEvents, string key, string expected)
    {
        return outcomeEvents.Count(evt =>
            evt.Data.TryGetValue(key, out var value) &&
            string.Equals(value, expected, StringComparison.OrdinalIgnoreCase));
    }

    private static void AddDroppedFileSummaryReasonCounts(SandboxEvent evt, IReadOnlyList<SandboxEvent> outcomeEvents)
    {
        var outcomeReasonCounts = outcomeEvents
            .Select(static item => item.Data.TryGetValue("reason", out var reason) ? reason : string.Empty)
            .Where(static reason => !string.IsNullOrWhiteSpace(reason))
            .GroupBy(static reason => reason, StringComparer.OrdinalIgnoreCase)
            .OrderBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.OrdinalIgnoreCase);
        var skippedReasonCounts = outcomeEvents
            .Where(static item => string.Equals(item.EventType, "artifact.dropped_file.skipped", StringComparison.OrdinalIgnoreCase))
            .Select(static item => item.Data.TryGetValue("reason", out var reason) ? reason : string.Empty)
            .Where(static reason => !string.IsNullOrWhiteSpace(reason))
            .GroupBy(static reason => reason, StringComparer.OrdinalIgnoreCase)
            .OrderBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.OrdinalIgnoreCase);

        evt.Data["reasonCount"] = outcomeReasonCounts.Count.ToString(CultureInfo.InvariantCulture);
        if (outcomeReasonCounts.Count > 0)
        {
            evt.Data["reasons"] = string.Join(",", outcomeReasonCounts.Keys);
            evt.Data["reasonCounts"] = string.Join(
                ";",
                outcomeReasonCounts.Select(pair => $"{pair.Key}={pair.Value.ToString(CultureInfo.InvariantCulture)}"));
            evt.Data["reasonCountsJson"] = JsonSerializer.Serialize(outcomeReasonCounts);
        }

        if (skippedReasonCounts.Count == 0)
        {
            evt.Data["skippedReasonCount"] = "0";
            return;
        }

        evt.Data["skippedReasonCount"] = skippedReasonCounts.Count.ToString(CultureInfo.InvariantCulture);
        evt.Data["skippedReasons"] = string.Join(",", skippedReasonCounts.Keys);
        evt.Data["skippedReasonCounts"] = string.Join(
            ";",
            skippedReasonCounts.Select(pair => $"{pair.Key}={pair.Value.ToString(CultureInfo.InvariantCulture)}"));
        evt.Data["skippedReasonCountsJson"] = JsonSerializer.Serialize(skippedReasonCounts);
        var lastSkipped = outcomeEvents.LastOrDefault(static item => string.Equals(item.EventType, "artifact.dropped_file.skipped", StringComparison.OrdinalIgnoreCase));
        if (lastSkipped is not null)
        {
            AddDataIfNotEmpty(evt.Data, "lastSkippedReason", FirstEventData(lastSkipped, "reason"));
            AddDataIfNotEmpty(evt.Data, "lastSkippedReasonCategory", FirstEventData(lastSkipped, "reasonCategory"));
            AddDataIfNotEmpty(evt.Data, "lastSkippedZhHint", FirstEventData(lastSkipped, "zhHint"));
        }
    }

    private static void AddDroppedFileSummaryArtifactSelectors(SandboxEvent evt, IReadOnlyList<SandboxEvent> outcomeEvents)
    {
        var copiedArtifacts = outcomeEvents
            .Where(static item => string.Equals(item.EventType, "artifact.dropped_file.copied", StringComparison.OrdinalIgnoreCase))
            .Select(static item => new DroppedFileArtifactSummary(
                FirstEventData(item, "artifactRelativePath", "relativePath", "importPath") ?? string.Empty,
                ParseNullableLong(FirstEventData(item, "artifactSizeBytes", "copiedSizeBytes", "sizeBytes")) ?? 0,
                FirstEventData(item, "artifactSha256", "copiedSha256", "sha256"),
                FirstEventData(item, "guestFullPath", "sourcePath")))
            .Where(static artifact => !string.IsNullOrWhiteSpace(artifact.RelativePath))
            .ToList();

        if (copiedArtifacts.Count == 0)
        {
            evt.Data["artifactSelectorState"] = "none-copied";
            return;
        }

        evt.Data["artifactSelectorState"] = "available";
        evt.Data["artifactSelectorMode"] = "copy-event-order-and-size";
        AddDroppedFileArtifactSelector(evt.Data, "first", copiedArtifacts.First(), "first-copied-event");
        AddDroppedFileArtifactSelector(evt.Data, "last", copiedArtifacts.Last(), "last-copied-event");
        AddDroppedFileArtifactSelector(
            evt.Data,
            "largest",
            copiedArtifacts
                .OrderByDescending(static artifact => artifact.SizeBytes)
                .ThenBy(static artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
                .First(),
            "largest-size-bytes");
    }

    private static void AddDroppedFileArtifactSelector(
        Dictionary<string, string> data,
        string prefix,
        DroppedFileArtifactSummary artifact,
        string selectionReason)
    {
        var titlePrefix = char.ToUpperInvariant(prefix[0]) + prefix[1..];
        data[DroppedFileArtifactSelectorKey(prefix)] = artifact.RelativePath;
        data[$"{prefix}ArtifactRelativePath"] = artifact.RelativePath;
        data[$"{prefix}ArtifactSafeLink"] = BuildArtifactSafeLink(artifact.RelativePath);
        data[$"{prefix}ArtifactSizeBytes"] = artifact.SizeBytes.ToString(CultureInfo.InvariantCulture);
        AddDataIfNotEmpty(data, $"{prefix}ArtifactSha256", artifact.Sha256);
        AddDataIfNotEmpty(data, $"{prefix}ArtifactGuestFullPath", artifact.GuestFullPath);
        data[$"{prefix}ArtifactSelectionReason"] = selectionReason;
        data[$"has{titlePrefix}ArtifactSelector"] = "true";
    }

    private static string DroppedFileArtifactSelectorKey(string prefix)
    {
        return prefix switch
        {
            "first" => "firstArtifactSelector",
            "last" => "lastArtifactSelector",
            "largest" => "largestArtifactSelector",
            _ => $"{prefix}ArtifactSelector"
        };
    }

    private static long? ParseNullableLong(string? value)
    {
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private static string BuildArtifactSafeLink(string relativePath)
    {
        return string.Join(
            "/",
            NormalizeArtifactRelativePath(relativePath)
                .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(Uri.EscapeDataString));
    }

    /// <summary>
    /// Copies a possibly locked dropped-file candidate using permissive source sharing.
    /// </summary>
    private static void CopyFileSharedRead(string sourcePath, string destinationPath)
    {
        using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var destination = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        source.CopyTo(destination);
        destination.Flush(flushToDisk: true);
    }

    private static string DroppedFileCandidateType(SandboxEvent sourceEvent)
    {
        return sourceEvent.EventType switch
        {
            "file.created" => "created",
            "file.modified" => "modified",
            _ => sourceEvent.EventType
        };
    }

    /// <summary>
    /// Reads source-file evidence for a dropped-file copy or skip event without
    /// throwing when the file disappears, is locked, or is inaccessible.
    /// </summary>
    private static DroppedFileSourceEvidence ReadDroppedFileSourceEvidence(string sourcePath, bool computeHash)
    {
        var evidence = new DroppedFileSourceEvidence(sourcePath);
        try
        {
            if (!File.Exists(sourcePath))
            {
                return evidence with
                {
                    Exists = false,
                    MetadataStatus = "missing",
                    HashStatus = computeHash ? "missing" : null
                };
            }

            var info = new FileInfo(sourcePath);
            evidence = evidence with
            {
                Exists = true,
                SizeBytes = info.Length,
                CreationTimeUtc = info.CreationTimeUtc,
                LastWriteTimeUtc = info.LastWriteTimeUtc,
                LastAccessTimeUtc = info.LastAccessTimeUtc
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            return evidence with
            {
                Exists = null,
                MetadataStatus = "failed",
                MetadataExceptionType = ex.GetType().FullName ?? ex.GetType().Name,
                MetadataMessage = ex.Message
            };
        }

        if (!computeHash)
        {
            return evidence;
        }

        var hash = ComputeSha256BestEffort(sourcePath);
        return evidence with
        {
            Sha256 = hash.Sha256,
            HashStatus = hash.Status,
            HashExceptionType = hash.ExceptionType,
            HashMessage = hash.Message
        };
    }

    /// <summary>
    /// Hashes a file for evidence metadata while tolerating write/delete sharing
    /// races common during malware execution.
    /// </summary>
    private static DroppedFileHashResult ComputeSha256BestEffort(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var hash = System.Security.Cryptography.SHA256.HashData(stream);
            return new DroppedFileHashResult(Convert.ToHexString(hash).ToLowerInvariant(), "computed", null, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            return new DroppedFileHashResult(null, "failed", ex.GetType().FullName ?? ex.GetType().Name, ex.Message);
        }
    }

    /// <summary>
    /// Chooses a non-overwriting destination under artifacts/dropped-files.
    /// </summary>
    private static DroppedFileDestination? CreateDroppedFileDestination(
        string droppedFilesRoot,
        string outputDirectory,
        string safeRelativePath,
        string sourcePath,
        HashSet<string> usedArtifactRelativePaths)
    {
        foreach (var candidateRelativePath in EnumerateDroppedFileDestinationCandidates(safeRelativePath, sourcePath))
        {
            string destinationPath;
            string artifactRelativePath;
            try
            {
                destinationPath = Path.GetFullPath(Path.Combine(droppedFilesRoot, candidateRelativePath));
                if (!IsSameOrUnderDirectory(destinationPath, droppedFilesRoot))
                {
                    continue;
                }

                artifactRelativePath = NormalizeArtifactRelativePath(Path.GetRelativePath(outputDirectory, destinationPath));
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException or PathTooLongException)
            {
                continue;
            }

            if (usedArtifactRelativePaths.Contains(artifactRelativePath) || File.Exists(destinationPath))
            {
                continue;
            }

            return new DroppedFileDestination(destinationPath, artifactRelativePath);
        }

        return null;
    }

    /// <summary>
    /// Generates deterministic collision-avoidance names for copied drops.
    /// </summary>
    private static IEnumerable<string> EnumerateDroppedFileDestinationCandidates(string safeRelativePath, string sourcePath)
    {
        yield return safeRelativePath;

        var directory = Path.GetDirectoryName(safeRelativePath);
        var fileName = Path.GetFileName(safeRelativePath);
        var stem = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        if (string.IsNullOrWhiteSpace(stem))
        {
            stem = "_";
        }

        var suffix = ShortStableId(sourcePath);
        for (var index = 1; index <= 1000; index++)
        {
            var numberedSuffix = index == 1
                ? suffix
                : $"{suffix}.{index.ToString(CultureInfo.InvariantCulture)}";
            var candidateFileName = $"{stem}.{numberedSuffix}{extension}";
            yield return string.IsNullOrWhiteSpace(directory)
                ? candidateFileName
                : Path.Combine(directory, candidateFileName);
        }
    }

    /// <summary>
    /// Creates a short stable identifier from source path text for name
    /// collision avoidance without reading source contents.
    /// </summary>
    private static string ShortStableId(string value)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(value);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash.AsSpan(0, 4)).ToLowerInvariant();
    }

    /// <summary>
    /// Copies file.created source-event size/time diagnostics onto copy
    /// outcome events so skips can be explained even if the source vanished.
    /// </summary>
    private static void AddDroppedFileSourceEventData(SandboxEvent evt, SandboxEvent sourceEvent)
    {
        if (sourceEvent.Data.TryGetValue("relativePath", out var relativePath) && !string.IsNullOrWhiteSpace(relativePath))
        {
            evt.Data["sourceEventRelativePath"] = relativePath;
            evt.Data.TryAdd("guestRelativePath", relativePath);
        }

        if (sourceEvent.Data.TryGetValue("sizeBytes", out var sizeBytes) && !string.IsNullOrWhiteSpace(sizeBytes))
        {
            evt.Data["sourceEventSizeBytes"] = sizeBytes;
        }

        if (sourceEvent.Data.TryGetValue("lastWriteUtc", out var lastWriteUtc) && !string.IsNullOrWhiteSpace(lastWriteUtc))
        {
            evt.Data["sourceEventLastWriteUtc"] = lastWriteUtc;
        }

        if (sourceEvent.Data.TryGetValue("sha256", out var sha256) && !string.IsNullOrWhiteSpace(sha256))
        {
            evt.Data["sourceEventSha256"] = sha256;
        }

        if (sourceEvent.Data.TryGetValue("hashAlgorithm", out var hashAlgorithm) && !string.IsNullOrWhiteSpace(hashAlgorithm))
        {
            evt.Data["sourceEventHashAlgorithm"] = hashAlgorithm;
        }

        if (sourceEvent.Data.TryGetValue("hashStatus", out var hashStatus) && !string.IsNullOrWhiteSpace(hashStatus))
        {
            evt.Data["sourceEventHashStatus"] = hashStatus;
        }

        AddDataIfNotEmpty(evt.Data, "sourceEventProcessId", FirstEventData(sourceEvent, "processId", "targetProcessId"));
        AddDataIfNotEmpty(evt.Data, "sourceEventParentProcessId", FirstEventData(sourceEvent, "parentProcessId", "targetParentProcessId"));
        AddDataIfNotEmpty(evt.Data, "sourceEventRootProcessId", FirstEventData(sourceEvent, "rootProcessId"));
        AddDataIfNotEmpty(evt.Data, "sourceEventTreeLineage", FirstEventData(sourceEvent, "treeLineage", "targetTreeLineage"));
        AddDataIfNotEmpty(evt.Data, "sourceEventProcessRole", FirstEventData(sourceEvent, "processRole", "targetProcessRole"));
        if (!evt.Data.ContainsKey("treeLineage") &&
            sourceEvent.Data.TryGetValue("treeLineage", out var sourceLineage) &&
            !string.IsNullOrWhiteSpace(sourceLineage))
        {
            evt.Data["treeLineage"] = sourceLineage;
            evt.Data["treeLineageStatus"] = "source-event";
        }
    }

    /// <summary>
    /// Copies best-effort live source-file evidence onto dropped-file copy or
    /// skip events.
    /// </summary>
    private static void AddDroppedFileSourceEvidenceData(SandboxEvent evt, DroppedFileSourceEvidence evidence)
    {
        if (!string.IsNullOrWhiteSpace(evidence.SourcePath))
        {
            evt.Data["sourcePath"] = evidence.SourcePath;
            evt.Data["guestFullPath"] = evidence.SourcePath;
        }

        if (evidence.Exists is not null)
        {
            evt.Data["sourceExists"] = evidence.Exists.Value.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["sourceMissing"] = (!evidence.Exists.Value).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        }

        if (evidence.SizeBytes is not null)
        {
            evt.Data["sourceSizeBytes"] = evidence.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (evidence.CreationTimeUtc is not null)
        {
            evt.Data["sourceCreatedUtc"] = evidence.CreationTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (evidence.LastWriteTimeUtc is not null)
        {
            evt.Data["sourceLastWriteUtc"] = evidence.LastWriteTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["sourceMtimeUtc"] = evidence.LastWriteTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (evidence.LastAccessTimeUtc is not null)
        {
            evt.Data["sourceLastAccessUtc"] = evidence.LastAccessTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(evidence.MetadataStatus))
        {
            evt.Data["sourceMetadataStatus"] = evidence.MetadataStatus;
        }

        if (!string.IsNullOrWhiteSpace(evidence.MetadataExceptionType))
        {
            evt.Data["sourceMetadataExceptionType"] = evidence.MetadataExceptionType;
        }

        if (!string.IsNullOrWhiteSpace(evidence.MetadataMessage))
        {
            evt.Data["sourceMetadataMessage"] = evidence.MetadataMessage;
        }

        if (!string.IsNullOrWhiteSpace(evidence.Sha256))
        {
            evt.Data["sourceSha256"] = evidence.Sha256;
            evt.Data["sourceHashAlgorithm"] = "sha256";
        }

        if (!string.IsNullOrWhiteSpace(evidence.HashStatus))
        {
            evt.Data["sourceHashStatus"] = evidence.HashStatus;
        }

        if (!string.IsNullOrWhiteSpace(evidence.HashExceptionType))
        {
            evt.Data["sourceHashExceptionType"] = evidence.HashExceptionType;
        }

        if (!string.IsNullOrWhiteSpace(evidence.HashMessage))
        {
            evt.Data["sourceHashMessage"] = evidence.HashMessage;
        }
    }

    /// <summary>
    /// Copies hash status metadata with the requested prefix.
    /// </summary>
    private static void AddDroppedFileHashData(SandboxEvent evt, DroppedFileHashResult hash, string prefix)
    {
        if (!string.IsNullOrWhiteSpace(hash.Sha256))
        {
            evt.Data[$"{prefix}Sha256"] = hash.Sha256;
            evt.Data[$"{prefix}HashAlgorithm"] = "sha256";
        }

        if (!string.IsNullOrWhiteSpace(hash.Status))
        {
            evt.Data[$"{prefix}HashStatus"] = hash.Status;
        }

        if (!string.IsNullOrWhiteSpace(hash.ExceptionType))
        {
            evt.Data[$"{prefix}HashExceptionType"] = hash.ExceptionType;
        }

        if (!string.IsNullOrWhiteSpace(hash.Message))
        {
            evt.Data[$"{prefix}HashMessage"] = hash.Message;
        }
    }

    /// <summary>
    /// Reads the original file relative path from a source event or computes a
    /// fallback under the working directory.
    /// </summary>
    private static string GetOriginalRelativePath(SandboxEvent sourceEvent, string workingDirectory, string sourcePath)
    {
        if (sourceEvent.Data.TryGetValue("relativePath", out var relativePath) && !string.IsNullOrWhiteSpace(relativePath))
        {
            return NormalizeArtifactRelativePath(relativePath);
        }

        return NormalizeArtifactRelativePath(Path.GetRelativePath(workingDirectory, sourcePath));
    }

    /// <summary>
    /// Converts a guest relative path to a safe file-system relative path below
    /// artifacts/dropped-files.
    /// </summary>
    private static string BuildSafeDroppedFileRelativePath(string originalRelativePath, string sourcePath)
    {
        var candidate = string.IsNullOrWhiteSpace(originalRelativePath)
            ? Path.GetFileName(sourcePath)
            : originalRelativePath;

        var segments = candidate
            .Replace('\\', '/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(segment => !string.Equals(segment, ".", StringComparison.Ordinal) && !string.Equals(segment, "..", StringComparison.Ordinal))
            .Select(SanitizeFileNameSegment)
            .Where(segment => !string.IsNullOrWhiteSpace(segment))
            .ToList();

        if (segments.Count == 0)
        {
            segments.Add(SanitizeFileNameSegment(Path.GetFileName(sourcePath)));
        }

        return Path.Combine(segments.ToArray());
    }

    /// <summary>
    /// Replaces invalid filename characters in a copied artifact path segment.
    /// </summary>
    private static string SanitizeFileNameSegment(string segment)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sanitized = new string(segment.Select(ch => invalid.Contains(ch) || ch == ':' ? '_' : ch).ToArray()).Trim();
        return string.IsNullOrWhiteSpace(sanitized) ? "_" : sanitized;
    }

    /// <summary>
    /// Normalizes an artifact-relative path to slash-separated display text.
    /// </summary>
    private static string NormalizeArtifactRelativePath(string path)
    {
        return path.Replace('\\', '/');
    }

    /// <summary>
    /// Tests whether a path is equal to or below a directory root.
    /// Inputs are a file path and directory path; processing normalizes both;
    /// the method returns true only for same-root descendants.
    /// </summary>
    private static bool IsSameOrUnderDirectory(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path);
        var fullDirectory = Path.GetFullPath(directory);
        if (string.Equals(
            Path.TrimEndingDirectorySeparator(fullPath),
            Path.TrimEndingDirectorySeparator(fullDirectory),
            StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var directoryWithSeparator = Path.EndsInDirectorySeparator(fullDirectory)
            ? fullDirectory
            : fullDirectory + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(directoryWithSeparator, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Reads a process name without failing if the process already exited.
    /// The input is a Process object, processing catches InvalidOperation,
    /// and the method returns a name or a fallback.
    /// </summary>
    private static string SafeProcessName(Process process)
    {
        try
        {
            return process.ProcessName;
        }
        catch (InvalidOperationException)
        {
            return "unknown";
        }
    }

    /// <summary>
    /// Reads a process start time without failing if the process exits quickly
    /// or denies metadata access.
    /// </summary>
    private static DateTime? SafeProcessStartTimeUtc(Process process)
    {
        try
        {
            return process.StartTime.ToUniversalTime();
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads a process exit code defensively.
    /// The input is a Process object, processing catches invalid state, and the
    /// method returns the exit code as text or "unknown".
    /// </summary>
    private static string SafeExitCode(Process process)
    {
        try
        {
            return process.ExitCode.ToString();
        }
        catch (InvalidOperationException)
        {
            return "unknown";
        }
    }

    /// <summary>
    /// Tracks a started R0Collector sidecar so shutdown can happen reliably.
    /// Inputs are the started Process plus collector executable, JSONL,
    /// diagnostic paths, redirect tasks, and the displayed command line;
    /// processing is simple storage; the record is returned from
    /// StartR0Collector and consumed by StopR0CollectorAsync.
    /// </summary>
    private sealed record R0CollectorProcess(
        Process Process,
        string CollectorPath,
        string DriverEventsPath,
        string StandardOutputPath,
        string StandardErrorPath,
        Task StandardOutputTask,
        Task StandardErrorTask,
        string CommandLine);

    private sealed record DroppedFileDestination(string FullPath, string ArtifactRelativePath);

    private sealed record DroppedFileProcessContext(
        int? RootProcessId,
        int? ParentProcessId,
        string? ProcessName,
        string? ProcessPath,
        string? CommandLine,
        DateTime? StartTimeUtc);

    private sealed record DroppedFileHashResult(
        string? Sha256,
        string Status,
        string? ExceptionType,
        string? Message);

    private sealed record DroppedFileArtifactSummary(
        string RelativePath,
        long SizeBytes,
        string? Sha256,
        string? GuestFullPath);

    private sealed record DroppedFileSourceEvidence(string SourcePath)
    {
        public bool? Exists { get; init; }

        public long? SizeBytes { get; init; }

        public DateTime? CreationTimeUtc { get; init; }

        public DateTime? LastWriteTimeUtc { get; init; }

        public DateTime? LastAccessTimeUtc { get; init; }

        public string? Sha256 { get; init; }

        public string? HashStatus { get; init; }

        public string? HashExceptionType { get; init; }

        public string? HashMessage { get; init; }

        public string? MetadataStatus { get; init; }

        public string? MetadataExceptionType { get; init; }

        public string? MetadataMessage { get; init; }
    }

    private sealed record FileSnapshot(long SizeBytes, DateTime LastWriteUtc);

    private sealed record ProcessSnapshot(int ProcessId, string ProcessName, string? Path, DateTime? StartTimeUtc)
    {
        public string Key => StartTimeUtc is null
            ? $"{ProcessId}:{ProcessName}"
            : $"{ProcessId}:{StartTimeUtc.Value.Ticks}:{ProcessName}";
    }

    private sealed record TcpConnectionSnapshot(IPEndPoint LocalEndPoint, IPEndPoint RemoteEndPoint, string State)
    {
        public string Local => FormatEndPoint(LocalEndPoint);

        public string Remote => FormatEndPoint(RemoteEndPoint);

        public string Key => $"{Local}->{Remote}:{State}";

        private static string FormatEndPoint(IPEndPoint endpoint)
        {
            return endpoint.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? $"[{endpoint.Address}]:{endpoint.Port}"
                : $"{endpoint.Address}:{endpoint.Port}";
        }
    }
}

/// <summary>
/// Parsed command-line options for the guest agent.
/// Inputs are raw CLI tokens, processing maps known switches and boolean flags
/// to properties, and Parse returns a validated AgentOptions instance.
/// </summary>
internal sealed record AgentOptions
{
    private const string DefaultDriverDevicePath = @"\\.\KSwordSandboxDriver";

    public required string SamplePath { get; init; }

    public required string OutputDirectory { get; init; }

    public int DurationSeconds { get; init; }

    public string? DriverEventsPath { get; init; }

    public string? R0CollectorPath { get; init; }

    public string DriverDevicePath { get; init; } = DefaultDriverDevicePath;

    public bool R0Mock { get; init; }

    public int R0CollectorMaxEventsPerRead { get; init; } = AgentProgram.DefaultR0CollectorMaxEventsPerRead;

    public int R0CollectorMaxReadBatches { get; init; } = AgentProgram.DefaultR0CollectorMaxReadBatches;

    public int R0CollectorDriverEventSampleStride { get; init; } = AgentProgram.DefaultR0CollectorDriverEventSampleStride;

    public bool CaptureScreenshots { get; init; }

    public ScreenshotProbeOptions ScreenshotOptions { get; init; } = ScreenshotProbeOptions.Default;

    public bool CollectDroppedFiles { get; init; }

    public bool CaptureMemoryDump { get; init; }

    public bool CapturePacketCapture { get; init; }

    /// <summary>
    /// Parses command-line switches for the guest agent.
    /// Inputs are string arguments, processing consumes --sample, --out,
    /// --duration, --driver-events, optional R0Collector sidecar switches, and
    /// boolean --r0-mock/--screenshot/--collect-dropped-files/--memory-dump,
    /// optional --screenshot-phases/--screenshot-count, plus opt-in
    /// --packet-capture/--pcap network capture flags without breaking existing
    /// value switches; the method returns
    /// validated and normalized options.
    /// </summary>
    public static AgentOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var optionName = args[index][2..];
            if (string.Equals(optionName, "r0-mock", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "screenshot", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "screenshots", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "collect-dropped-files", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "dropped-files", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "memory-dump", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "memory-dumps", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "packet-capture", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "pcap", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(optionName, "network-capture", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add(optionName);
                continue;
            }

            if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            values[optionName] = args[++index];
        }

        if (!values.TryGetValue("sample", out var samplePath) || !File.Exists(samplePath))
        {
            throw new ArgumentException("--sample must point to an existing executable. / --sample 必须指向 guest 内存在的可执行样本文件。");
        }

        if (!values.TryGetValue("out", out var outputDirectory) || string.IsNullOrWhiteSpace(outputDirectory))
        {
            throw new ArgumentException("--out is required. / 必须使用 --out 指定 Guest Agent 输出目录。");
        }

        var duration = values.TryGetValue("duration", out var rawDuration) && int.TryParse(rawDuration, out var parsedDuration)
            ? Math.Clamp(parsedDuration, 1, 3600)
            : 120;

        values.TryGetValue("driver-events", out var driverEventsPath);
        values.TryGetValue("driver-device", out var driverDevicePath);
        values.TryGetValue("r0collector", out var r0CollectorPath);
        if (string.IsNullOrWhiteSpace(r0CollectorPath))
        {
            values.TryGetValue("r0-collector", out r0CollectorPath);
        }

        var captureScreenshots = flags.Contains("screenshot") || flags.Contains("screenshots");
        var r0MaxEventsPerRead = ParseBoundedOption(values, 1, 1024, AgentProgram.DefaultR0CollectorMaxEventsPerRead, "r0-max-events", "r0-read-events-max-events", "driver-max-events");
        var r0MaxReadBatches = ParseBoundedOption(values, 0, 1_000_000, AgentProgram.DefaultR0CollectorMaxReadBatches, "r0-max-read-batches", "driver-max-read-batches");
        var r0DriverEventSampleStride = ParseBoundedOption(values, 1, 1_000_000, AgentProgram.DefaultR0CollectorDriverEventSampleStride, "r0-driver-event-sample-stride", "driver-event-sample-stride", "r0-event-sample-stride");
        var screenshotOptions = ScreenshotProbeOptions.Parse(
            FirstValue(values, "screenshot-phases", "screenshot-stages", "screenshots-phases", "screenshots-stages"),
            FirstValue(values, "screenshot-count", "screenshots-count"));

        return new AgentOptions
        {
            SamplePath = Path.GetFullPath(samplePath),
            OutputDirectory = Path.GetFullPath(outputDirectory),
            DurationSeconds = duration,
            DriverEventsPath = string.IsNullOrWhiteSpace(driverEventsPath) ? null : Path.GetFullPath(driverEventsPath),
            R0CollectorPath = string.IsNullOrWhiteSpace(r0CollectorPath) ? null : Path.GetFullPath(r0CollectorPath),
            DriverDevicePath = string.IsNullOrWhiteSpace(driverDevicePath) ? DefaultDriverDevicePath : driverDevicePath,
            R0Mock = flags.Contains("r0-mock"),
            R0CollectorMaxEventsPerRead = r0MaxEventsPerRead,
            R0CollectorMaxReadBatches = r0MaxReadBatches,
            R0CollectorDriverEventSampleStride = r0DriverEventSampleStride,
            CaptureScreenshots = captureScreenshots,
            ScreenshotOptions = screenshotOptions,
            CollectDroppedFiles = flags.Contains("collect-dropped-files") || flags.Contains("dropped-files"),
            CaptureMemoryDump = flags.Contains("memory-dump") || flags.Contains("memory-dumps"),
            CapturePacketCapture = flags.Contains("packet-capture") || flags.Contains("pcap") || flags.Contains("network-capture")
        };
    }

    /// <summary>
    /// Finds the first populated option value across aliases.
    /// Inputs are parsed value switches and candidate names; processing returns
    /// the first non-empty value; the method returns null when none are set.
    /// </summary>
    private static string? FirstValue(IReadOnlyDictionary<string, string> values, params string[] names)
    {
        foreach (var name in names)
        {
            if (values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static int ParseBoundedOption(IReadOnlyDictionary<string, string> values, int minValue, int maxValue, int defaultValue, params string[] names)
    {
        var raw = FirstValue(values, names);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return defaultValue;
        }

        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return defaultValue;
        }

        return Math.Clamp(parsed, minValue, maxValue);
    }
}
