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
/// screenshot, dropped-file extraction, memory-dump, and future PCAP flags; processing can
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
            return 1;
        }
    }

    /// <summary>
    /// Runs the sample and collects normalized behavior events.
    /// Inputs are parsed options, processing snapshots process tree, file, TCP,
    /// optional screenshot state, and optional after-start memory dump state
    /// before and after execution, and the method returns collected events.
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
                    ["durationSeconds"] = options.DurationSeconds.ToString(CultureInfo.InvariantCulture)
                }
            }
        };

        AddEnvironmentSnapshotEvent(events, options, workingDirectory);
        var probeRunner = CreateProbeRunner();
        var probeContext = CreateGuestProbeContext(options, workingDirectory, rootProcessId: null);
        events.AddRange(await probeRunner.CollectAsync(ProbePhase.BeforeStart, probeContext));
        var r0Collector = StartR0Collector(options, events);
        var analysisDeadline = DateTimeOffset.UtcNow.AddSeconds(options.DurationSeconds);

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
            events.Add(new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = process.ProcessName,
                ProcessId = process.Id,
                Path = options.SamplePath,
                CommandLine = options.SamplePath
            });
            var runningProbeContext = CreateGuestProbeContext(options, workingDirectory, process.Id);
            events.AddRange(await probeRunner.CollectAsync(ProbePhase.AfterStart, runningProbeContext));

            var exited = await WaitForExitAsync(process, TimeSpan.FromSeconds(options.DurationSeconds));
            if (!exited)
            {
                events.Add(new SandboxEvent
                {
                    EventType = "process.timeout",
                    Source = "guest",
                    ProcessName = SafeProcessName(process),
                    ProcessId = process.Id,
                    Path = options.SamplePath
                });
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }

            events.Add(new SandboxEvent
            {
                EventType = "process.exit",
                Source = "guest",
                ProcessName = SafeProcessName(process),
                ProcessId = process.Id,
                Path = options.SamplePath,
                Data =
                {
                    ["exitCode"] = SafeExitCode(process)
                }
            });

            var remainingAnalysisWindow = analysisDeadline - DateTimeOffset.UtcNow;
            if (remainingAnalysisWindow > TimeSpan.Zero)
            {
                events.Add(new SandboxEvent
                {
                    EventType = "analysis.wait_remaining",
                    Source = "guest",
                    ProcessName = SafeProcessName(process),
                    ProcessId = process.Id,
                    Path = options.SamplePath,
                    Data =
                    {
                        ["remainingSeconds"] = Math.Ceiling(remainingAnalysisWindow.TotalSeconds).ToString(CultureInfo.InvariantCulture),
                        ["reason"] = "sampleExitedBeforeAnalysisDuration",
                        ["durationSeconds"] = options.DurationSeconds.ToString(CultureInfo.InvariantCulture)
                    }
                });
                await Task.Delay(remainingAnalysisWindow);
            }

            events.AddRange(await probeRunner.CollectAsync(ProbePhase.AfterRun, runningProbeContext));
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
    /// diff, optional screenshot, and opt-in memory dump probes in deterministic
    /// order; the method returns a reusable GuestProbeRunner for one agent run.
    /// </summary>
    private static GuestProbeRunner CreateProbeRunner()
    {
        return new GuestProbeRunner(
        [
            new ProcessTreeProbe(),
            new FileDiffProbe(),
            new TcpConnectionDiffProbe(),
            new PacketCaptureProbe(),
            new ScreenshotProbe(),
            new MemoryDumpProbe()
        ]);
    }

    /// <summary>
    /// Builds a probe context from current agent options and execution state.
    /// Inputs are parsed options, working directory, and optional root process
    /// id; processing copies values into an immutable context; the method
    /// returns the context consumed by guest probes.
    /// </summary>
    private static GuestProbeContext CreateGuestProbeContext(AgentOptions options, string workingDirectory, int? rootProcessId)
    {
        return new GuestProbeContext
        {
            SamplePath = options.SamplePath,
            WorkingDirectory = workingDirectory,
            OutputDirectory = options.OutputDirectory,
            RootProcessId = rootProcessId,
            CaptureScreenshots = options.CaptureScreenshots,
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
                events.Add(new SandboxEvent
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
                        ["gracefulStopTimeoutSeconds"] = R0CollectorGracefulStopTimeout.TotalSeconds.ToString(CultureInfo.InvariantCulture)
                    }
                });

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
                $"R0Collector did not start: {reason}"
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
        return new SandboxEvent
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
                ["r0Mock"] = options.R0Mock.ToString(),
                ["stdoutPath"] = standardOutputPath,
                ["stderrPath"] = standardErrorPath,
                ["processId"] = processId.ToString(CultureInfo.InvariantCulture),
                ["supervisor"] = "guest-agent"
            }
        };
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
        return new SandboxEvent
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
                ["supervisor"] = "guest-agent"
            }
        };
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

        AddExceptionData(evt, exception);
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

        AddExceptionData(evt, exception);
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

        AddExceptionData(evt, exception);
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

        AddExceptionData(evt, exception);
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
            options.DurationSeconds.ToString(CultureInfo.InvariantCulture)
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

        TryWriteArtifactManifest(options, events, artifactWriter, droppedFileMetadataByRelativePath);

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
        var candidates = events
            .Where(static evt => string.Equals(evt.EventType, "file.created", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (candidates.Count == 0)
        {
            return metadataByRelativePath;
        }

        var workingDirectory = Path.GetFullPath(Path.GetDirectoryName(options.SamplePath) ?? Environment.CurrentDirectory);
        var outputDirectory = Path.GetFullPath(options.OutputDirectory);
        var artifactsRoot = Path.Combine(outputDirectory, GuestArtifactWriter.ArtifactsDirectoryName);
        var droppedFilesRoot = Path.Combine(artifactsRoot, DroppedFilesArtifactDirectoryName);

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate.Path))
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "sourcePathMissing"));
                continue;
            }

            string sourcePath;
            try
            {
                sourcePath = Path.GetFullPath(candidate.Path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "sourcePathInvalid", exception: ex));
                continue;
            }

            if (!IsSameOrUnderDirectory(sourcePath, workingDirectory))
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "outsideWorkingDirectory", sourcePath: sourcePath));
                continue;
            }

            if (IsSameOrUnderDirectory(sourcePath, outputDirectory))
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "underOutputDirectory", sourcePath: sourcePath));
                continue;
            }

            if (!File.Exists(sourcePath))
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "sourceFileMissing", sourcePath: sourcePath));
                continue;
            }

            var originalRelativePath = GetOriginalRelativePath(candidate, workingDirectory, sourcePath);
            var safeRelativePath = BuildSafeDroppedFileRelativePath(originalRelativePath, sourcePath);
            var destinationPath = Path.GetFullPath(Path.Combine(droppedFilesRoot, safeRelativePath));
            if (!IsSameOrUnderDirectory(destinationPath, droppedFilesRoot))
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "destinationPathInvalid", sourcePath: sourcePath));
                continue;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(destinationPath) ?? droppedFilesRoot);
                File.Copy(sourcePath, destinationPath, overwrite: true);
                var artifactRelativePath = NormalizeArtifactRelativePath(Path.GetRelativePath(outputDirectory, destinationPath));
                var copiedInfo = new FileInfo(destinationPath);
                metadataByRelativePath[artifactRelativePath] = new DroppedFileArtifactMetadata(
                    sourcePath,
                    originalRelativePath,
                    candidate.EventType);
                events.Add(CreateDroppedFileCopiedEvent(
                    sourcePath,
                    originalRelativePath,
                    destinationPath,
                    artifactRelativePath,
                    copiedInfo.Length));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
            {
                events.Add(CreateDroppedFileSkippedEvent(candidate, reason: "copyFailed", sourcePath: sourcePath, exception: ex));
            }
        }

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
            events.Add(new SandboxEvent
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
                    ["captureMemoryDump"] = options.CaptureMemoryDump.ToString(),
                    ["capturePacketCapture"] = options.CapturePacketCapture.ToString(),
                    ["relativePath"] = NormalizeArtifactRelativePath(Path.GetRelativePath(options.OutputDirectory, manifestResult.ManifestPath)),
                    ["importPath"] = NormalizeArtifactRelativePath(Path.GetRelativePath(options.OutputDirectory, manifestResult.ManifestPath)),
                    ["artifactRoot"] = Path.Combine(options.OutputDirectory, GuestArtifactWriter.ArtifactsDirectoryName)
                }
            });
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
                    ["captureMemoryDump"] = options.CaptureMemoryDump.ToString(),
                    ["capturePacketCapture"] = options.CapturePacketCapture.ToString(),
                    ["reason"] = "writeFailed"
                }
            };
            AddExceptionData(evt, ex);
            events.Add(evt);
        }
    }

    /// <summary>
    /// Creates an event for a copied dropped-file artifact.
    /// Inputs are source and destination paths plus metadata; processing stores
    /// paths and sizes as strings; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateDroppedFileCopiedEvent(
        string sourcePath,
        string originalRelativePath,
        string destinationPath,
        string artifactRelativePath,
        long sizeBytes)
    {
        return new SandboxEvent
        {
            EventType = "artifact.dropped_file.copied",
            Source = "guest",
            Path = destinationPath,
            Data =
            {
                ["sourcePath"] = sourcePath,
                ["guestFullPath"] = sourcePath,
                ["guestRelativePath"] = originalRelativePath,
                ["artifactRelativePath"] = artifactRelativePath,
                ["relativePath"] = artifactRelativePath,
                ["sizeBytes"] = sizeBytes.ToString(CultureInfo.InvariantCulture),
                ["evidenceRole"] = "dropped-file",
                ["collectDroppedFiles"] = "true"
            }
        };
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
        Exception? exception = null)
    {
        var evt = new SandboxEvent
        {
            EventType = "artifact.dropped_file.skipped",
            Source = "guest",
            Path = sourcePath ?? sourceEvent.Path,
            Data =
            {
                ["reason"] = reason,
                ["sourceEventType"] = sourceEvent.EventType,
                ["sourcePath"] = sourcePath ?? sourceEvent.Path ?? string.Empty,
                ["collectDroppedFiles"] = "true"
            }
        };

        if (sourceEvent.Data.TryGetValue("relativePath", out var relativePath))
        {
            evt.Data["guestRelativePath"] = relativePath;
        }

        AddExceptionData(evt, exception);
        return evt;
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

    public bool CaptureScreenshots { get; init; }

    public bool CollectDroppedFiles { get; init; }

    public bool CaptureMemoryDump { get; init; }

    public bool CapturePacketCapture { get; init; }

    /// <summary>
    /// Parses command-line switches for the guest agent.
    /// Inputs are string arguments, processing consumes --sample, --out,
    /// --duration, --driver-events, optional R0Collector sidecar switches, and
    /// boolean --r0-mock/--screenshot/--collect-dropped-files/--memory-dump
    /// plus future --packet-capture/--pcap placeholder flags without breaking
    /// existing value switches; the method returns
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
            throw new ArgumentException("--sample must point to an existing executable.");
        }

        if (!values.TryGetValue("out", out var outputDirectory) || string.IsNullOrWhiteSpace(outputDirectory))
        {
            throw new ArgumentException("--out is required.");
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

        return new AgentOptions
        {
            SamplePath = Path.GetFullPath(samplePath),
            OutputDirectory = Path.GetFullPath(outputDirectory),
            DurationSeconds = duration,
            DriverEventsPath = string.IsNullOrWhiteSpace(driverEventsPath) ? null : Path.GetFullPath(driverEventsPath),
            R0CollectorPath = string.IsNullOrWhiteSpace(r0CollectorPath) ? null : Path.GetFullPath(r0CollectorPath),
            DriverDevicePath = string.IsNullOrWhiteSpace(driverDevicePath) ? DefaultDriverDevicePath : driverDevicePath,
            R0Mock = flags.Contains("r0-mock"),
            CaptureScreenshots = flags.Contains("screenshot") || flags.Contains("screenshots"),
            CollectDroppedFiles = flags.Contains("collect-dropped-files") || flags.Contains("dropped-files"),
            CaptureMemoryDump = flags.Contains("memory-dump") || flags.Contains("memory-dumps"),
            CapturePacketCapture = flags.Contains("packet-capture") || flags.Contains("pcap") || flags.Contains("network-capture")
        };
    }
}
