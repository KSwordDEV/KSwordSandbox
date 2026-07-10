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
/// screenshot capture flag; processing can start the sidecar, starts the sample,
/// runs dynamic guest probes, merges driver JSONL, and writes JSON artifacts;
/// RunAsync returns a process exit code.
/// </summary>
internal static class AgentProgram
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

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
    /// and optional screenshot state before and after execution, and the method
    /// returns collected events.
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
    /// diff, and optional screenshot probes in deterministic order; the method
    /// returns a reusable GuestProbeRunner for one agent run.
    /// </summary>
    private static GuestProbeRunner CreateProbeRunner()
    {
        return new GuestProbeRunner(
        [
            new ProcessTreeProbe(),
            new FileDiffProbe(),
            new TcpConnectionDiffProbe(),
            new ScreenshotProbe()
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
            CaptureScreenshots = options.CaptureScreenshots
        };
    }

    /// <summary>
    /// Starts the optional R0Collector sidecar before sample execution.
    /// Inputs are parsed agent options and the event output list; processing
    /// requires both --r0collector and --driver-events, creates the JSONL parent
    /// directory, forwards --device/--output/--duration plus optional --mock,
    /// and records r0collector.start_failed on startup errors; the method
    /// returns a process handle when the sidecar starts or null when disabled or
    /// failed.
    /// </summary>
    private static R0CollectorProcess? StartR0Collector(AgentOptions options, List<SandboxEvent> events)
    {
        if (string.IsNullOrWhiteSpace(options.R0CollectorPath) || string.IsNullOrWhiteSpace(options.DriverEventsPath))
        {
            return null;
        }

        try
        {
            EnsureParentDirectory(options.DriverEventsPath);

            var startInfo = new ProcessStartInfo
            {
                FileName = options.R0CollectorPath,
                UseShellExecute = false,
                CreateNoWindow = true
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

            var process = Process.Start(startInfo) ?? throw new InvalidOperationException("R0Collector process start returned null.");
            return new R0CollectorProcess(process, options.R0CollectorPath, options.DriverEventsPath);
        }
        catch (Exception ex)
        {
            events.Add(new SandboxEvent
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
                    ["exceptionType"] = ex.GetType().FullName ?? ex.GetType().Name,
                    ["message"] = ex.Message
                }
            });
            return null;
        }
    }

    /// <summary>
    /// Waits briefly for the optional R0Collector sidecar and terminates it if
    /// needed after sample execution. The input is the nullable sidecar process
    /// record plus the event output list; processing gives the collector a
    /// short graceful-exit window, then kills the process tree and records
    /// stop_forced or stop_failed details; the method returns no value.
    /// </summary>
    private static async Task StopR0CollectorAsync(R0CollectorProcess? collector, List<SandboxEvent> events)
    {
        if (collector is null)
        {
            return;
        }

        try
        {
            if (!await WaitForExitAsync(collector.Process, TimeSpan.FromSeconds(5)))
            {
                events.Add(new SandboxEvent
                {
                    EventType = "r0collector.stop_forced",
                    Source = "guest",
                    Path = collector.CollectorPath,
                    Data =
                    {
                        ["driverEventsPath"] = collector.DriverEventsPath,
                        ["processId"] = collector.Process.Id.ToString(CultureInfo.InvariantCulture)
                    }
                });
                collector.Process.Kill(entireProcessTree: true);
                await collector.Process.WaitForExitAsync();
            }
        }
        catch (Exception ex)
        {
            events.Add(new SandboxEvent
            {
                EventType = "r0collector.stop_failed",
                Source = "guest",
                Path = collector.CollectorPath,
                Data =
                {
                    ["driverEventsPath"] = collector.DriverEventsPath,
                    ["exceptionType"] = ex.GetType().FullName ?? ex.GetType().Name,
                    ["message"] = ex.Message
                }
            });
        }
        finally
        {
            collector.Process.Dispose();
        }
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
    /// Writes events and a compact summary into the output directory.
    /// Inputs are agent options and event list, processing serializes JSON
    /// files, and the method returns no value.
    /// </summary>
    private static void WriteArtifacts(AgentOptions options, List<SandboxEvent> events)
    {
        var eventsPath = Path.Combine(options.OutputDirectory, "events.json");
        var summaryPath = Path.Combine(options.OutputDirectory, "agent-summary.json");
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(events, JsonOptions));
        File.WriteAllText(summaryPath, JsonSerializer.Serialize(new
        {
            sample = options.SamplePath,
            eventCount = events.Count,
            generatedAt = DateTimeOffset.UtcNow
        }, JsonOptions));
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
    /// Inputs are the started Process plus the collector executable and JSONL
    /// paths; processing is simple storage; the record is returned from
    /// StartR0Collector and consumed by StopR0CollectorAsync.
    /// </summary>
    private sealed record R0CollectorProcess(Process Process, string CollectorPath, string DriverEventsPath);

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

    /// <summary>
    /// Parses command-line switches for the guest agent.
    /// Inputs are string arguments, processing consumes --sample, --out,
    /// --duration, --driver-events, optional R0Collector sidecar switches, and
    /// boolean --r0-mock/--screenshot flags without breaking existing value
    /// switches; the method returns validated and normalized options.
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
                string.Equals(optionName, "screenshots", StringComparison.OrdinalIgnoreCase))
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
            CaptureScreenshots = flags.Contains("screenshot") || flags.Contains("screenshots")
        };
    }
}
