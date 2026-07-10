using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json;
using KSword.Sandbox.Abstractions;

return await AgentProgram.RunAsync(args);

/// <summary>
/// Guest-side collector that runs inside the disposable Windows VM.
/// Inputs are command-line arguments for sample path, output path, duration,
/// and optional driver event path; processing starts the sample, records process
/// and environment events, and writes JSON artifacts; RunAsync returns a
/// process exit code.
/// </summary>
internal static class AgentProgram
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
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
    /// Inputs are parsed options, processing snapshots network and files before
    /// and after execution, and the method returns collected events.
    /// </summary>
    private static async Task<List<SandboxEvent>> CollectAsync(AgentOptions options)
    {
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "agent.start",
                Source = "guest",
                Path = options.SamplePath,
                Data =
                {
                    ["durationSeconds"] = options.DurationSeconds.ToString()
                }
            }
        };

        var workingDirectory = Path.GetDirectoryName(options.SamplePath) ?? Environment.CurrentDirectory;
        var filesBefore = SnapshotFiles(workingDirectory);
        var tcpBefore = SnapshotTcpConnections();
        events.AddRange(ReadDriverEvents(options.DriverEventsPath));

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

        AddFileDeltaEvents(events, workingDirectory, filesBefore, SnapshotFiles(workingDirectory));
        AddTcpDeltaEvents(events, tcpBefore, SnapshotTcpConnections());
        events.Add(new SandboxEvent { EventType = "agent.stop", Source = "guest", Path = options.OutputDirectory });
        return events;
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
    /// returns string keys for current connections.
    /// </summary>
    private static HashSet<string> SnapshotTcpConnections()
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpConnections()
                .Select(connection => $"{connection.LocalEndPoint}->{connection.RemoteEndPoint}:{connection.State}")
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch (NetworkInformationException)
        {
            return [];
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
    private static void AddTcpDeltaEvents(List<SandboxEvent> events, HashSet<string> before, HashSet<string> after)
    {
        foreach (var connection in after.Except(before, StringComparer.OrdinalIgnoreCase))
        {
            events.Add(new SandboxEvent
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["connection"] = connection
                }
            });
        }
    }

    /// <summary>
    /// Reads optional driver JSONL events produced by the R0 collector.
    /// The input is an optional file path, processing deserializes each JSON
    /// line independently, and the method returns normalized events.
    /// </summary>
    private static List<SandboxEvent> ReadDriverEvents(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        var events = new List<SandboxEvent>();
        foreach (var line in File.ReadLines(path))
        {
            try
            {
                var evt = JsonSerializer.Deserialize<SandboxEvent>(line, JsonOptions);
                if (evt is not null)
                {
                    events.Add(evt with { Source = string.IsNullOrWhiteSpace(evt.Source) ? "driver" : evt.Source });
                }
            }
            catch (JsonException)
            {
                events.Add(new SandboxEvent { EventType = "driver.parse_error", Source = "guest", Data = { ["line"] = line } });
            }
        }

        return events;
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

    private sealed record FileSnapshot(long SizeBytes, DateTime LastWriteUtc);
}

/// <summary>
/// Parsed command-line options for the guest agent.
/// Inputs are raw CLI tokens, processing maps known switches to properties,
/// and Parse returns a validated AgentOptions instance.
/// </summary>
internal sealed record AgentOptions
{
    public required string SamplePath { get; init; }

    public required string OutputDirectory { get; init; }

    public int DurationSeconds { get; init; }

    public string? DriverEventsPath { get; init; }

    /// <summary>
    /// Parses command-line switches for the guest agent.
    /// Inputs are string arguments, processing consumes --sample, --out,
    /// --duration, and --driver-events, and the method returns options.
    /// </summary>
    public static AgentOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal) || index + 1 >= args.Length)
            {
                continue;
            }

            values[args[index][2..]] = args[++index];
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
        return new AgentOptions
        {
            SamplePath = Path.GetFullPath(samplePath),
            OutputDirectory = Path.GetFullPath(outputDirectory),
            DurationSeconds = duration,
            DriverEventsPath = driverEventsPath
        };
    }
}
