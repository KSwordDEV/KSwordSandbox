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
            return phase == ProbePhase.BeforeStart
                ? [CreateDisabledEvent(context)]
                : [];
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
                ["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["sourceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["packetCaptureRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["commandExitCode"] = FormatExitCode(result.ExitCode),
                ["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["commandOutputSuppressed"] = "true",
                ["zhMessage"] = "网络抓包已启动，PCAPNG 会在 after-run 阶段转换后写出。",
                ["zhHint"] = "started 事件保留预期 artifactRelativePath；最终完整性请以 packet_capture.captured 的 sizeBytes/sha256 为准。"
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
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["sourceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["packetCaptureRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["commandExitCode"] = FormatExitCode(stopResult.ExitCode),
                ["commandTimedOut"] = stopResult.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["durationMilliseconds"] = (DateTimeOffset.UtcNow - session.StartedAtUtc).TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["commandOutputSuppressed"] = "true",
                ["zhMessage"] = "网络抓包已停止，正在/即将转换为 PCAPNG 证据文件。",
                ["zhHint"] = "stopped 事件保留 ETL 诊断路径；最终 artifactRelativePath、sizeBytes、sha256 以 captured 事件为准。"
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
                ["zhMessage"] = "网络抓包已采集为 PCAPNG 证据文件。",
                ["zhHint"] = "请使用 artifactRelativePath 下载 PCAPNG；sizeBytes/sha256 可用于校验抓包文件完整性。",
                ["pcapFormat"] = "pcapng",
                ["etlPath"] = session.EtlPath,
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["sourceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["packetCaptureRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["sizeBytes"] = pcapInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["pcapLastWriteUtc"] = pcapInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["durationMilliseconds"] = (DateTimeOffset.UtcNow - session.StartedAtUtc).TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
                ["commandExitCode"] = FormatExitCode(convertResult.ExitCode),
                ["commandTimedOut"] = convertResult.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["commandOutputSuppressed"] = "true"
            }
        };
        AddArtifactFileEvidence(captured, session.PcapngPath);
        AddRootProcessData(captured, context);
        events.Add(captured);
        events.Add(CreateProtocolSummaryPlaceholderEvent(context, session, pcapInfo));
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
                ["zhMessage"] = "网络抓包采集被跳过；该事件说明证据缺口，不会中断整体分析。",
                ["zhHint"] = PacketCaptureReasonZhHint(reason),
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
            evt.Data["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath);
            evt.Data["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            evt.Data["sourceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath);
            evt.Data["packetCaptureRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath);
        }

        return evt;
    }

    /// <summary>
    /// Creates a single disabled event for the opt-in packet-capture lane.
    /// </summary>
    private static SandboxEvent CreateDisabledEvent(GuestProbeContext context)
    {
        var evt = new SandboxEvent
        {
            EventType = "packet_capture.disabled",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "before-start",
                ["capturePhase"] = "before-start",
                ["captureEnabled"] = "false",
                ["implemented"] = "true",
                ["reason"] = "packetCaptureNotRequested",
                ["zhMessage"] = "网络抓包采集未启用。",
                ["zhHint"] = "未启用 --packet-capture/--pcap/--network-capture，Guest Agent 不会启动 pktmon 抓包。",
                ["collector"] = "pktmon",
                ["collectionName"] = CollectionName,
                ["evidenceRole"] = "packet-capture",
                ["captureState"] = "disabled",
                ["status"] = "disabled",
                ["nonfatal"] = "true",
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["samplePath"] = context.SamplePath
            }
        };

        AddRootProcessData(evt, context);
        return evt;
    }

    /// <summary>
    /// Emits a protocol-summary placeholder tied to the captured PCAPNG.
    /// </summary>
    private static SandboxEvent CreateProtocolSummaryPlaceholderEvent(
        GuestProbeContext context,
        PacketCaptureSession session,
        FileInfo pcapInfo)
    {
        var evt = new SandboxEvent
        {
            EventType = "packet_capture.protocol_summary",
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
                ["nonfatal"] = "true",
                ["reason"] = "protocolParserNotImplemented",
                ["zhMessage"] = "PCAPNG 已采集，但协议摘要解析器尚未实现；该 placeholder 不会改变 packet-captures 的 captured 状态。",
                ["zhHint"] = "请直接下载/分析 packet-captures/*.pcapng；后续实现协议解析后会填充摘要字段。",
                ["pcapFormat"] = "pcapng",
                ["etlPath"] = session.EtlPath,
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["sourceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["packetCaptureRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["sizeBytes"] = pcapInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["pcapLastWriteUtc"] = pcapInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["protocolSummaryAvailable"] = "false",
                ["protocolSummaryState"] = "placeholder",
                ["protocolSummaryStatus"] = "skipped",
                ["protocolSummaryReason"] = "protocolParserNotImplemented",
                ["protocolSummaryFormat"] = "placeholder",
                ["protocolSummary"] = "{}",
                ["protocolsObserved"] = "unknown"
            }
        };

        AddArtifactFileEvidence(evt, session.PcapngPath);
        AddRootProcessData(evt, context);
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
                ["zhMessage"] = "pktmon 命令失败，网络抓包通道未完整产出。",
                ["zhHint"] = PacketCaptureReasonZhHint(reason),
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
                ["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["sourceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["packetCaptureRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
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
        AddArtifactFileEvidence(evt, session.PcapngPath);
        return evt;
    }

    private static string PacketCaptureReasonZhHint(string reason)
    {
        return reason switch
        {
            "notWindows" => "pktmon 抓包仅支持 Windows guest；非 Windows 环境会跳过。",
            "captureAlreadyActive" => "已有抓包会话处于活动状态，本次不会重复启动。",
            "captureWasNotStarted" => "after-run 阶段没有可停止/转换的 pktmon 会话，通常表示 before-start 未成功启动。",
            "pktmonStartFailed" => "pktmon start 失败；请检查管理员权限、pktmon 是否存在，以及系统是否已有冲突抓包。",
            "pktmonStopFailed" => "pktmon stop 失败；请检查命令输出和 ETL 诊断文件，确认是否有活动 pktmon 会话。",
            "pktmonConvertFailed" => "pktmon etl2pcap 转换失败；请查看 commandExitCode/commandMessage 和 ETL 诊断路径。",
            "packetCaptureNotRequested" => "未请求网络抓包；如需 PCAPNG，请显式传入 --packet-capture、--pcap 或 --network-capture。",
            "protocolParserNotImplemented" => "协议摘要尚未实现；原始 PCAPNG 仍可作为证据下载分析。",
            _ => "请结合 reason、commandExitCode、commandTimedOut、commandMessage 和 diagnosticRelativePath 判断 pktmon 失败原因。"
        };
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
        evt.Data["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context";
        if (context.RootProcessId is not null)
        {
            evt.Data["rootProcessId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["processId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["treeDepth"] = "0";
            evt.Data["treeLineage"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "processName", evt.ProcessName);
        AddIfNotEmpty(evt.Data, "samplePath", context.SamplePath);
    }

    /// <summary>
    /// Adds event-level size and SHA-256 metadata for a captured PCAPNG file.
    /// Inputs are an event and artifact path; processing reads the file
    /// best-effort with sharing flags and records compact diagnostics on error.
    /// </summary>
    private static void AddArtifactFileEvidence(SandboxEvent evt, string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                evt.Data["artifactHashStatus"] = "missing";
                evt.Data["artifactExists"] = "false";
                return;
            }

            evt.Data["artifactExists"] = "true";
            evt.Data["sizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactSizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactLastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            evt.Data["sha256"] = sha256;
            evt.Data["artifactSha256"] = sha256;
            evt.Data["hashAlgorithm"] = "sha256";
            evt.Data["artifactHashStatus"] = "computed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data["artifactHashStatus"] = "failed";
            evt.Data["artifactHashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["artifactHashMessage"] = ex.Message;
        }
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
