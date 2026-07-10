using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace KSword.Sandbox.HarmlessSample;

/// <summary>
/// Provides a harmless Windows smoke-test executable for end-to-end sandbox validation.
/// Inputs: command-line arguments accepted by <see cref="ParseOptions"/>, primarily an
/// optional output directory and an optional network-probe flag.
/// Processing: creates a marker text file, starts one short-lived child process, and can
/// optionally make short TCP connection attempts only to loopback and TEST-NET addresses.
/// Return behavior: returns 0 when the visible actions complete, or 1 when argument parsing
/// or file/process execution fails.
/// </summary>
internal static class Program
{
    private const string MarkerFileName = "ksword-sandbox-smoke.txt";
    private const int ChildTimeoutSeconds = 10;

    /// <summary>
    /// Entry point for the smoke sample.
    /// Inputs: command-line arguments documented by <see cref="PrintUsage"/>.
    /// Processing: resolves the output directory, runs the visible child process, optionally
    /// performs safe network probes, then writes a marker file containing deterministic
    /// metadata that a sandbox report can collect.
    /// Return behavior: returns 0 for a successful smoke run, 1 for a handled error, and 0 for
    /// help output because no smoke action was requested.
    /// </summary>
    public static async Task<int> Main(string[] args)
    {
        try
        {
            SampleOptions options = ParseOptions(args);

            if (options.ShowHelp)
            {
                PrintUsage();
                return 0;
            }

            Directory.CreateDirectory(options.OutputDirectory);

            ChildProcessResult childResult = await RunChildProcessAsync(options.OutputDirectory);
            IReadOnlyList<NetworkProbeResult> probeResults = options.EnableNetworkProbe
                ? await RunOptionalNetworkProbesAsync()
                : Array.Empty<NetworkProbeResult>();

            string markerPath = Path.Combine(options.OutputDirectory, MarkerFileName);
            string markerText = BuildMarkerText(args, options, childResult, probeResults);
            await File.WriteAllTextAsync(markerPath, markerText, Encoding.UTF8);

            Console.WriteLine("KSword sandbox smoke sample completed.");
            Console.WriteLine($"Marker file: {markerPath}");
            Console.WriteLine($"Child exit code: {childResult.ExitCode}");
            Console.WriteLine(options.EnableNetworkProbe
                ? "Optional network probes were attempted against loopback and TEST-NET only."
                : "Optional network probes were skipped.");

            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine("KSword sandbox smoke sample failed.");
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    /// <summary>
    /// Parses the small command-line surface for this test sample.
    /// Inputs: raw command-line arguments from <see cref="Main"/>.
    /// Processing: accepts "--output-dir &lt;path&gt;", "--output-dir=&lt;path&gt;",
    /// "--network-probe", and help switches; the output path is normalized to a full path.
    /// Return behavior: returns immutable sample options, or throws <see cref="ArgumentException"/>
    /// when an unknown option or missing option value is supplied.
    /// </summary>
    private static SampleOptions ParseOptions(string[] args)
    {
        string outputDirectory = Environment.CurrentDirectory;
        bool enableNetworkProbe = false;
        bool showHelp = false;

        for (int index = 0; index < args.Length; index++)
        {
            string argument = args[index];

            if (IsHelpSwitch(argument))
            {
                showHelp = true;
                continue;
            }

            if (argument.Equals("--network-probe", StringComparison.OrdinalIgnoreCase))
            {
                enableNetworkProbe = true;
                continue;
            }

            if (argument.StartsWith("--output-dir=", StringComparison.OrdinalIgnoreCase))
            {
                outputDirectory = argument["--output-dir=".Length..];
                continue;
            }

            if (argument.Equals("--output-dir", StringComparison.OrdinalIgnoreCase))
            {
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException("Missing value for --output-dir.");
                }

                outputDirectory = args[++index];
                continue;
            }

            throw new ArgumentException($"Unknown argument: {argument}");
        }

        if (string.IsNullOrWhiteSpace(outputDirectory))
        {
            throw new ArgumentException("The output directory cannot be empty.");
        }

        return new SampleOptions(Path.GetFullPath(outputDirectory), enableNetworkProbe, showHelp);
    }

    /// <summary>
    /// Determines whether a command-line argument requests usage text.
    /// Inputs: one raw command-line argument.
    /// Processing: compares the argument with common help switches using ordinal
    /// case-insensitive matching.
    /// Return behavior: returns true for a help switch, otherwise false.
    /// </summary>
    private static bool IsHelpSwitch(string argument)
    {
        return argument.Equals("--help", StringComparison.OrdinalIgnoreCase)
            || argument.Equals("-h", StringComparison.OrdinalIgnoreCase)
            || argument.Equals("/?", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Starts a short-lived Windows child process that produces a benign, visible process event.
    /// Inputs: the output directory used as the child process working directory.
    /// Processing: launches "cmd.exe /d /c echo ..." without a shell window, captures standard
    /// output and standard error, and enforces a short timeout to avoid a lingering process.
    /// Return behavior: returns the child process exit code and captured streams, or throws
    /// <see cref="InvalidOperationException"/> if the process cannot start or times out.
    /// </summary>
    private static async Task<ChildProcessResult> RunChildProcessAsync(string outputDirectory)
    {
        string commandProcessor = Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe";
        var startInfo = new ProcessStartInfo
        {
            FileName = commandProcessor,
            Arguments = "/d /c echo KSwordSandbox smoke child process completed",
            WorkingDirectory = outputDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        using var process = new Process
        {
            StartInfo = startInfo
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("Failed to start the smoke child process.");
        }

        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(ChildTimeoutSeconds));

        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException ex)
        {
            TryKillProcessTree(process);
            throw new InvalidOperationException($"The smoke child process exceeded {ChildTimeoutSeconds} seconds.", ex);
        }

        string stdout = await stdoutTask;
        string stderr = await stderrTask;

        return new ChildProcessResult(
            Path.GetFileName(commandProcessor),
            process.Id,
            process.ExitCode,
            stdout.Trim(),
            stderr.Trim());
    }

    /// <summary>
    /// Attempts to terminate the child process and descendants after a timeout.
    /// Inputs: a <see cref="Process"/> instance that may still be running.
    /// Processing: checks process state and requests whole-tree termination while suppressing
    /// best-effort cleanup errors because the primary failure is already the timeout.
    /// Return behavior: no return value.
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
            // The process may exit between the HasExited check and Kill call.
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or NotSupportedException)
        {
            // Cleanup is best effort; the timeout exception remains the actionable failure.
        }
    }

    /// <summary>
    /// Runs optional TCP probes against addresses that are safe for documentation and loopback tests.
    /// Inputs: no user-controlled addresses; targets are hard-coded to 127.0.0.1 and 192.0.2.1.
    /// Processing: performs short connection attempts that can produce network telemetry without
    /// contacting an arbitrary external service.
    /// Return behavior: returns one result per probe, including timeout or socket-error status.
    /// </summary>
    private static async Task<IReadOnlyList<NetworkProbeResult>> RunOptionalNetworkProbesAsync()
    {
        var results = new List<NetworkProbeResult>
        {
            await ProbeTcpEndpointAsync("loopback-discard", "127.0.0.1", 9, TimeSpan.FromMilliseconds(300)),
            await ProbeTcpEndpointAsync("test-net-documentation", "192.0.2.1", 80, TimeSpan.FromMilliseconds(300))
        };

        return results;
    }

    /// <summary>
    /// Attempts one short TCP connection and records the observable outcome.
    /// Inputs: a probe name, numeric host address, TCP port, and timeout.
    /// Processing: creates a disposable <see cref="TcpClient"/>, attempts to connect, and converts
    /// normal refusal, timeout, and other socket failures into text statuses instead of failing
    /// the whole sample.
    /// Return behavior: returns a probe result with elapsed milliseconds and a status string.
    /// </summary>
    private static async Task<NetworkProbeResult> ProbeTcpEndpointAsync(
        string name,
        string host,
        int port,
        TimeSpan timeout)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

        using var client = new TcpClient();

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            await client.ConnectAsync(host, port, cancellation.Token);
            return new NetworkProbeResult(name, host, port, "connected", stopwatch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            return new NetworkProbeResult(name, host, port, "timeout", stopwatch.ElapsedMilliseconds);
        }
        catch (SocketException ex)
        {
            return new NetworkProbeResult(name, host, port, $"socket-error:{ex.SocketErrorCode}", stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            return new NetworkProbeResult(name, host, port, $"error:{ex.GetType().Name}", stopwatch.ElapsedMilliseconds);
        }
    }

    /// <summary>
    /// Builds the marker file content consumed by end-to-end smoke reports.
    /// Inputs: original arguments, parsed options, child process telemetry, and optional network
    /// probe results.
    /// Processing: writes stable key-value lines with environment and action summaries so a
    /// collector can verify file creation, child-process execution, and optional network telemetry.
    /// Return behavior: returns the complete UTF-8 text that should be written to the marker file.
    /// </summary>
    private static string BuildMarkerText(
        string[] args,
        SampleOptions options,
        ChildProcessResult childResult,
        IReadOnlyList<NetworkProbeResult> probeResults)
    {
        var builder = new StringBuilder();

        builder.AppendLine("KSword Sandbox Smoke Sample");
        builder.AppendLine($"UtcTimestamp={DateTimeOffset.UtcNow:O}");
        builder.AppendLine($"MachineName={Environment.MachineName}");
        builder.AppendLine($"UserName={Environment.UserName}");
        builder.AppendLine($"ProcessId={Environment.ProcessId}");
        builder.AppendLine($"WorkingDirectory={Environment.CurrentDirectory}");
        builder.AppendLine($"OutputDirectory={options.OutputDirectory}");
        builder.AppendLine($"Arguments={string.Join(' ', args)}");
        builder.AppendLine($"ChildImage={childResult.ImageName}");
        builder.AppendLine($"ChildProcessId={childResult.ProcessId}");
        builder.AppendLine($"ChildExitCode={childResult.ExitCode}");
        builder.AppendLine($"ChildStdout={childResult.StandardOutput}");
        builder.AppendLine($"ChildStderr={childResult.StandardError}");
        builder.AppendLine($"NetworkProbeEnabled={options.EnableNetworkProbe}");

        if (probeResults.Count == 0)
        {
            builder.AppendLine("NetworkProbeResult=skipped");
        }
        else
        {
            foreach (NetworkProbeResult result in probeResults)
            {
                builder.AppendLine(
                    $"NetworkProbeResult={result.Name},{result.Host}:{result.Port},{result.Status},{result.ElapsedMilliseconds}ms");
            }
        }

        return builder.ToString();
    }

    /// <summary>
    /// Prints usage information for operators running the sample manually.
    /// Inputs: none.
    /// Processing: writes concise command help and safety notes to standard output.
    /// Return behavior: no return value.
    /// </summary>
    private static void PrintUsage()
    {
        Console.WriteLine("KSword.Sandbox.HarmlessSample");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  KSword.Sandbox.HarmlessSample.exe [--output-dir <path>] [--network-probe]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  --output-dir <path>   Directory that receives ksword-sandbox-smoke.txt.");
        Console.WriteLine("  --network-probe       Also attempt short TCP probes to 127.0.0.1 and 192.0.2.1.");
        Console.WriteLine("  --help, -h, /?        Show this help text.");
    }
}

/// <summary>
/// Stores parsed command-line settings for the sample.
/// Inputs: constructed from normalized parser output.
/// Processing: immutable record values are passed between helper methods instead of rereading
/// command-line state.
/// Return behavior: record construction returns a value object with no side effects.
/// </summary>
internal sealed record SampleOptions(string OutputDirectory, bool EnableNetworkProbe, bool ShowHelp);

/// <summary>
/// Stores observable child-process telemetry for the marker file.
/// Inputs: populated from the completed "cmd.exe" child process.
/// Processing: immutable record values preserve the process image name, process id, exit code,
/// and captured output streams.
/// Return behavior: record construction returns a value object with no side effects.
/// </summary>
internal sealed record ChildProcessResult(
    string ImageName,
    int ProcessId,
    int ExitCode,
    string StandardOutput,
    string StandardError);

/// <summary>
/// Stores the result of a safe optional TCP probe.
/// Inputs: populated by <see cref="Program"/> after probing a hard-coded loopback or TEST-NET endpoint.
/// Processing: immutable record values keep the target and status for report assertions.
/// Return behavior: record construction returns a value object with no side effects.
/// </summary>
internal sealed record NetworkProbeResult(
    string Name,
    string Host,
    int Port,
    string Status,
    long ElapsedMilliseconds);
