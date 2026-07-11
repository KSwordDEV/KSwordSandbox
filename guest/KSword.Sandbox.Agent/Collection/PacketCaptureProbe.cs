using System.Globalization;
using System.Runtime.InteropServices;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures opt-in packet evidence with Windows pktmon and converts ETL to
/// PCAPNG. Inputs are probe phase and guest output paths; processing starts
/// pktmon before sample launch, stops it after the run, converts to PCAPNG, and
/// emits non-fatal diagnostic events; CollectAsync returns packet-capture
/// lifecycle events.
/// </summary>
internal sealed class PacketCaptureProbe : IGuestProbe
{
    private const string CollectionName = "packet-captures";
    private const string PktmonExecutable = "pktmon.exe";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);
    private PacketCaptureSession? activeSession;

    public string ProbeId => "packet-capture";

    /// <summary>
    /// Starts or stops the packet capture according to the probe phase.
    /// Inputs are phase, context, and cancellation token; processing uses
    /// pktmon only when explicitly enabled; the method returns normalized
    /// packet_capture.* events without throwing for missing tools or rights.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!context.CapturePacketCapture)
        {
            return [];
        }

        return phase switch
        {
            ProbePhase.BeforeStart => await StartCaptureAsync(context, cancellationToken).ConfigureAwait(false),
            ProbePhase.AfterRun => await StopAndConvertCaptureAsync(context, cancellationToken).ConfigureAwait(false),
            _ => []
        };
    }

    /// <summary>
    /// Starts pktmon capture and records the target ETL/PCAPNG paths.
    /// Inputs are guest context and cancellation token; processing creates the
    /// output folder and runs pktmon start; the method returns started,
    /// skipped, or failed events.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> StartCaptureAsync(
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return [CreateSkippedEvent("before-start", context, "notWindows", implemented: true)];
        }

        if (activeSession is not null)
        {
            return [CreateSkippedEvent("before-start", context, "captureAlreadyActive", implemented: true, session: activeSession)];
        }

        var captureDirectory = Path.Combine(context.OutputDirectory, CollectionName);
        var diagnosticDirectory = Path.Combine(context.OutputDirectory, "packet-capture-diagnostics");
        Directory.CreateDirectory(captureDirectory);
        Directory.CreateDirectory(diagnosticDirectory);
        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture);
        var session = new PacketCaptureSession(
            captureDirectory,
            diagnosticDirectory,
            Path.Combine(diagnosticDirectory, $"pktmon-{stamp}.etl"),
            Path.Combine(captureDirectory, $"pktmon-{stamp}.pcapng"),
            DateTimeOffset.UtcNow);

        var result = await BoundedProcessRunner.RunAsync(
            PktmonExecutable,
            [
                "start",
                "--capture",
                "--pkt-size",
                "0",
                "--file-name",
                session.EtlPath,
                "--file-size",
                "128"
            ],
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            return [CreateCommandFailureEvent("packet_capture.failed", "before-start", context, "pktmonStartFailed", result, session)];
        }

        activeSession = session;
        var started = new SandboxEvent
        {
            EventType = "packet_capture.started",
            Source = "guest",
            Path = session.EtlPath,
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "before-start",
                ["capturePhase"] = "before-start",
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["collector"] = "pktmon",
                ["collectionName"] = CollectionName,
                ["evidenceRole"] = "packet-capture",
                ["captureState"] = "started",
                ["status"] = "started",
                ["nonfatal"] = "false",
                ["etlPath"] = session.EtlPath,
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["commandExitCode"] = FormatExitCode(result.ExitCode),
                ["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["commandOutputSuppressed"] = "true"
            }
        };
        AddRootProcessData(started, context);
        return [started];
    }

    /// <summary>
    /// Stops pktmon and converts the captured ETL to PCAPNG.
    /// Inputs are context and cancellation token; processing always attempts a
    /// stop when a session started; the method returns stopped, converted,
    /// captured, skipped, or failed events.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> StopAndConvertCaptureAsync(
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        if (activeSession is null)
        {
            return [CreateSkippedEvent("after-run", context, "captureWasNotStarted", implemented: true)];
        }

        var session = activeSession;
        activeSession = null;
        var events = new List<SandboxEvent>();
        var stopResult = await BoundedProcessRunner.RunAsync(
            PktmonExecutable,
            ["stop"],
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!stopResult.Succeeded)
        {
            events.Add(CreateCommandFailureEvent("packet_capture.failed", "after-run", context, "pktmonStopFailed", stopResult, session));
            return events;
        }

        var stopped = new SandboxEvent
        {
            EventType = "packet_capture.stopped",
            Source = "guest",
            Path = session.EtlPath,
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "after-run",
                ["capturePhase"] = "after-run",
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["collector"] = "pktmon",
                ["collectionName"] = CollectionName,
                ["evidenceRole"] = "packet-capture",
                ["captureState"] = "stopped",
                ["status"] = "stopped",
                ["nonfatal"] = "false",
                ["etlPath"] = session.EtlPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["commandExitCode"] = FormatExitCode(stopResult.ExitCode),
                ["commandTimedOut"] = stopResult.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["durationMilliseconds"] = (DateTimeOffset.UtcNow - session.StartedAtUtc).TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["commandOutputSuppressed"] = "true"
            }
        };
        AddRootProcessData(stopped, context);
        events.Add(stopped);

        var convertResult = await BoundedProcessRunner.RunAsync(
            PktmonExecutable,
            [
                "etl2pcap",
                session.EtlPath,
                "--out",
                session.PcapngPath
            ],
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!convertResult.Succeeded || !File.Exists(session.PcapngPath))
        {
            events.Add(CreateCommandFailureEvent("packet_capture.failed", "after-run", context, "pktmonConvertFailed", convertResult, session));
            return events;
        }

        var pcapInfo = new FileInfo(session.PcapngPath);
        var captured = new SandboxEvent
        {
            EventType = "packet_capture.captured",
            Source = "guest",
            Path = session.PcapngPath,
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "after-run",
                ["capturePhase"] = "after-run",
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["collector"] = "pktmon",
                ["collectionName"] = CollectionName,
                ["evidenceRole"] = "packet-capture",
                ["captureState"] = "captured",
                ["status"] = "captured",
                ["nonfatal"] = "false",
                ["pcapFormat"] = "pcapng",
                ["etlPath"] = session.EtlPath,
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["sizeBytes"] = pcapInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["durationMilliseconds"] = (DateTimeOffset.UtcNow - session.StartedAtUtc).TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["commandExitCode"] = FormatExitCode(convertResult.ExitCode),
                ["commandTimedOut"] = convertResult.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["commandOutputSuppressed"] = "true"
            }
        };
        AddRootProcessData(captured, context);
        events.Add(captured);
        return events;
    }

    /// <summary>
    /// Creates a non-fatal packet-capture skip event.
    /// Inputs are phase, reason, implementation flag, and optional paths;
    /// processing stores stable manifest metadata; the method returns an event.
    /// </summary>
    private static SandboxEvent CreateSkippedEvent(
        string phase,
        GuestProbeContext context,
        string reason,
        bool implemented,
        PacketCaptureSession? session = null)
    {
        var artifactRelativePath = session is null
            ? string.Empty
            : RelativeToOutput(context.OutputDirectory, session.PcapngPath);
        var evt = new SandboxEvent
        {
            EventType = "packet_capture.skipped",
            Source = "guest",
            Path = session?.PcapngPath,
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = phase,
                ["capturePhase"] = phase,
                ["captureEnabled"] = "true",
                ["implemented"] = implemented.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["reason"] = reason,
                ["collector"] = "pktmon",
                ["evidenceRole"] = "packet-capture",
                ["collectionName"] = CollectionName,
                ["captureState"] = "skipped",
                ["status"] = "skipped",
                ["nonfatal"] = "true",
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng"
            }
        };
        AddIfNotEmpty(evt.Data, "artifactRelativePath", artifactRelativePath);
        AddRootProcessData(evt, context);
        if (session is not null)
        {
            evt.Data["etlPath"] = session.EtlPath;
            evt.Data["pcapngPath"] = session.PcapngPath;
            evt.Data["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            evt.Data["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
        }

        return evt;
    }

    /// <summary>
    /// Converts a failed pktmon command into a packet_capture diagnostic event.
    /// Inputs are event type, phase, reason, command result, and session; the
    /// method suppresses stdout/stderr while preserving exit and timeout data.
    /// </summary>
    private static SandboxEvent CreateCommandFailureEvent(
        string eventType,
        string phase,
        GuestProbeContext context,
        string reason,
        BoundedCommandResult result,
        PacketCaptureSession session)
    {
        var failed = eventType.EndsWith(".failed", StringComparison.OrdinalIgnoreCase);
        var captureState = failed ? "failed" : "skipped";
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = session.PcapngPath,
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = phase,
                ["capturePhase"] = phase,
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["reason"] = reason,
                ["collector"] = "pktmon",
                ["evidenceRole"] = "packet-capture",
                ["collectionName"] = CollectionName,
                ["captureState"] = captureState,
                ["status"] = captureState,
                ["nonfatal"] = "true",
                ["etlPath"] = session.EtlPath,
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["commandFileName"] = result.FileName,
                ["commandArguments"] = result.Arguments,
                ["commandExitCode"] = FormatExitCode(result.ExitCode),
                ["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["commandTimeoutMilliseconds"] = result.Timeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["commandExceptionType"] = result.ExceptionType ?? string.Empty,
                ["commandMessage"] = result.Message ?? string.Empty,
                ["commandOutputSuppressed"] = "true"
            }
        };

        AddRootProcessData(evt, context);
        return evt;
    }

    /// <summary>
    /// Reads a display process name for sample-scoped packet-capture events.
    /// </summary>
    private static string? SampleProcessName(string samplePath)
    {
        try
        {
            return string.IsNullOrWhiteSpace(samplePath) ? null : Path.GetFileName(samplePath);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Copies root process identity into event Data when available.
    /// </summary>
    private static void AddRootProcessData(SandboxEvent evt, GuestProbeContext context)
    {
        if (context.RootProcessId is not null)
        {
            evt.Data["rootProcessId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["processId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "processName", evt.ProcessName);
        AddIfNotEmpty(evt.Data, "samplePath", context.SamplePath);
    }

    /// <summary>
    /// Adds non-empty event Data values.
    /// </summary>
    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Formats nullable command exit codes for event data.
    /// </summary>
    private static string FormatExitCode(int? exitCode)
    {
        return exitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
    }

    /// <summary>
    /// Converts an absolute artifact path into a safe output-relative path.
    /// Inputs are output directory and path; processing guards against paths
    /// outside the output root; the method returns slash-separated relative
    /// text.
    /// </summary>
    private static string RelativeToOutput(string outputDirectory, string path)
    {
        try
        {
            var outputRoot = Path.GetFullPath(outputDirectory);
            var fullPath = Path.GetFullPath(path);
            var outputRootWithSeparator = Path.EndsInDirectorySeparator(outputRoot)
                ? outputRoot
                : outputRoot + Path.DirectorySeparatorChar;
            if (!fullPath.StartsWith(outputRootWithSeparator, StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty;
            }

            return Path.GetRelativePath(outputRoot, fullPath).Replace('\\', '/');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    private sealed record PacketCaptureSession(
        string CaptureDirectory,
        string DiagnosticDirectory,
        string EtlPath,
        string PcapngPath,
        DateTimeOffset StartedAtUtc);
}
