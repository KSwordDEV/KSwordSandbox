using System.Buffers.Binary;
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
    private const string ArtifactSelectorVersion = "artifact-selectors-v1";
    private const string ReasonTaxonomy = "guest-artifact.packet-capture.reason.v1";
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
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--packet-capture/--pcap/--network-capture",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-network-packet-capture",
                ["collector"] = "pktmon",
                ["captureTool"] = PktmonExecutable,
                ["captureToolMode"] = "windows-pktmon-etw",
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
                ["captureStartedUtc"] = session.StartedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["captureToolCommand"] = "pktmon start --capture --pkt-size 0 --file-name <etl> --file-size 128",
                ["conversionTool"] = PktmonExecutable,
                ["conversionCommand"] = "pktmon etl2pcap <etl> --out <pcapng>",
                ["conversionStatus"] = "pending",
                ["conversionSourceFormat"] = "etl",
                ["conversionTargetFormat"] = "pcapng",
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["artifactRelativePathStatus"] = "expected-pending-conversion",
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
        AddCaptureSourceToolData(started.Data);
        AddPacketCaptureSelectorAliases(started.Data);
        AddExpectedArtifactEvidence(started.Data, "conversion-pending");
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
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--packet-capture/--pcap/--network-capture",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-network-packet-capture",
                ["collector"] = "pktmon",
                ["captureTool"] = PktmonExecutable,
                ["captureToolMode"] = "windows-pktmon-etw",
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
                ["captureStartedUtc"] = session.StartedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["captureStoppedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                ["captureToolCommand"] = "pktmon stop",
                ["conversionTool"] = PktmonExecutable,
                ["conversionCommand"] = "pktmon etl2pcap <etl> --out <pcapng>",
                ["conversionStatus"] = "pending",
                ["conversionSourceFormat"] = "etl",
                ["conversionTargetFormat"] = "pcapng",
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["artifactRelativePathStatus"] = "expected-pending-conversion",
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
        AddCaptureSourceToolData(stopped.Data);
        AddPacketCaptureSelectorAliases(stopped.Data);
        AddExpectedArtifactEvidence(stopped.Data, "conversion-pending");
        AddNamedFileEvidence(stopped.Data, "etl", session.EtlPath);
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
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--packet-capture/--pcap/--network-capture",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-network-packet-capture",
                ["collector"] = "pktmon",
                ["captureTool"] = PktmonExecutable,
                ["captureToolMode"] = "windows-pktmon-etw",
                ["collectionName"] = CollectionName,
                ["evidenceRole"] = "packet-capture",
                ["captureState"] = "captured",
                ["status"] = "captured",
                ["nonfatal"] = "false",
                ["zhMessage"] = "网络抓包已采集为 PCAPNG 证据文件。",
                ["zhHint"] = "请使用 artifactRelativePath 下载 PCAPNG；sizeBytes/sha256 可用于校验抓包文件完整性。",
                ["pcapFormat"] = "pcapng",
                ["packetCaptureFileCount"] = "1",
                ["fileCount"] = "1",
                ["conversionStatus"] = "succeeded",
                ["conversionTool"] = PktmonExecutable,
                ["conversionCommand"] = "pktmon etl2pcap <etl> --out <pcapng>",
                ["conversionSourceFormat"] = "etl",
                ["conversionTargetFormat"] = "pcapng",
                ["etlPath"] = session.EtlPath,
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["captureStartedUtc"] = session.StartedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["captureStoppedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["artifactRelativePathStatus"] = "captured",
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
        AddCaptureSourceToolData(captured.Data);
        AddPacketCaptureSelectorAliases(captured.Data);
        AddArtifactFileEvidence(captured, session.PcapngPath);
        AddNamedFileEvidence(captured.Data, "pcapng", session.PcapngPath);
        AddNamedFileEvidence(captured.Data, "etl", session.EtlPath);
        AddPcapngPacketSummary(captured.Data, session.PcapngPath);
        AddProtocolDiagnosticDefaults(captured.Data);
        AddPktmonConversionOutputSummary(captured.Data, convertResult);
        AddRootProcessData(captured, context);
        events.Add(captured);
        events.Add(CreateProtocolSummaryMetadataEvent(context, session, pcapInfo));
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
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--packet-capture/--pcap/--network-capture",
                ["implemented"] = implemented.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["capturePolicy"] = "explicit-opt-in-network-packet-capture",
                ["reason"] = reason,
                ["reasonCode"] = reason,
                ["reasonCategory"] = PacketCaptureReasonCategory(reason),
                ["reasonTaxonomy"] = ReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhMessage"] = "网络抓包采集被跳过；该事件说明证据缺口，不会中断整体分析。",
                ["zhHint"] = PacketCaptureReasonZhHint(reason),
                ["collector"] = "pktmon",
                ["captureTool"] = PktmonExecutable,
                ["captureToolMode"] = "windows-pktmon-etw",
                ["conversionTool"] = PktmonExecutable,
                ["conversionStatus"] = reason == "pktmonConvertFailed" ? "failed" : "not-attempted",
                ["conversionSourceFormat"] = "etl",
                ["conversionTargetFormat"] = "pcapng",
                ["evidenceRole"] = "packet-capture",
                ["collectionName"] = CollectionName,
                ["captureState"] = "skipped",
                ["status"] = "skipped",
                ["nonfatal"] = "true",
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["artifactExists"] = "false",
                ["artifactIntegrityState"] = "skipped",
                ["artifactRelativePathStatus"] = session is null ? "not-created" : "expected-not-created",
                ["sizeBytesStatus"] = "not-created",
                ["sha256Status"] = "not-created"
            }
        };
        AddCaptureSourceToolData(evt.Data);
        AddIfNotEmpty(evt.Data, "artifactRelativePath", artifactRelativePath);
        AddPacketCaptureSelectorAliases(evt.Data);
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
                ["captureRequested"] = "false",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--packet-capture/--pcap/--network-capture",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-network-packet-capture",
                ["reason"] = "packetCaptureNotRequested",
                ["reasonCode"] = "packetCaptureNotRequested",
                ["reasonCategory"] = "disabled",
                ["reasonTaxonomy"] = ReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhMessage"] = "网络抓包采集未启用。",
                ["zhHint"] = "未启用 --packet-capture/--pcap/--network-capture，Guest Agent 不会启动 pktmon 抓包。",
                ["collector"] = "pktmon",
                ["collectionName"] = CollectionName,
                ["evidenceRole"] = "packet-capture",
                ["captureState"] = "disabled",
                ["status"] = "disabled",
                ["nonfatal"] = "true",
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["artifactExists"] = "false",
                ["artifactIntegrityState"] = "disabled",
                ["artifactRelativePathStatus"] = "disabled",
                ["sizeBytesStatus"] = "disabled",
                ["sha256Status"] = "disabled",
                ["samplePath"] = context.SamplePath
            }
        };

        AddCaptureSourceToolData(evt.Data);
        AddRootProcessData(evt, context);
        return evt;
    }

    /// <summary>
    /// Emits protocol diagnostics tied to the captured PCAPNG.
    /// </summary>
    private static SandboxEvent CreateProtocolSummaryMetadataEvent(
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
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--packet-capture/--pcap/--network-capture",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-network-packet-capture",
                ["collector"] = "pktmon",
                ["captureTool"] = PktmonExecutable,
                ["captureToolMode"] = "windows-pktmon-etw",
                ["collectionName"] = CollectionName,
                ["evidenceRole"] = "packet-capture",
                ["captureState"] = "captured",
                ["status"] = "captured",
                ["nonfatal"] = "true",
                ["reason"] = "protocolParserNotImplemented",
                ["zhMessage"] = "PCAPNG 已采集；当前事件提供协议解析前的抓包诊断摘要。",
                ["zhHint"] = "请先查看 pcapng*、packetCount*、etl* 字段判断抓包是否有效；需要 DNS/HTTP/TLS 明细时下载 artifactRelativePath 进行协议分析。",
                ["pcapFormat"] = "pcapng",
                ["etlPath"] = session.EtlPath,
                ["pcapngPath"] = session.PcapngPath,
                ["relativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["etlRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["pcapngRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["diagnosticRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["artifactRelativePathStatus"] = "captured",
                ["sourceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["packetCaptureRelativePath"] = RelativeToOutput(context.OutputDirectory, session.PcapngPath),
                ["expectedRelativePath"] = $"{CollectionName}/*.pcapng",
                ["sizeBytes"] = pcapInfo.Length.ToString(CultureInfo.InvariantCulture),
                ["pcapLastWriteUtc"] = pcapInfo.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                ["protocolSummaryAvailable"] = "false",
                ["protocolSummaryState"] = "capture-metadata-only",
                ["protocolSummaryStatus"] = "skipped",
                ["protocolSummaryReason"] = "protocolParserNotImplemented",
                ["protocolSummaryFormat"] = "capture-metadata",
                ["protocolSummary"] = "{\"state\":\"capture-metadata-only\"}",
                ["protocolsObserved"] = "not-parsed",
                ["protocolDiagnosticsAvailable"] = "true",
                ["protocolDiagnostics"] = "pcapng-block-counters",
                ["protocolFamiliesExpected"] = "dns,http,tls",
                ["dnsSummaryState"] = "not-parsed",
                ["httpSummaryState"] = "not-parsed",
                ["tlsSummaryState"] = "not-parsed",
                ["packetCaptureFileCount"] = "1",
                ["fileCount"] = "1",
                ["conversionStatus"] = "succeeded",
                ["conversionTool"] = PktmonExecutable,
                ["conversionSourceFormat"] = "etl",
                ["conversionTargetFormat"] = "pcapng"
            }
        };

        AddCaptureSourceToolData(evt.Data);
        AddPacketCaptureSelectorAliases(evt.Data);
        AddArtifactFileEvidence(evt, session.PcapngPath);
        AddNamedFileEvidence(evt.Data, "pcapng", session.PcapngPath);
        AddNamedFileEvidence(evt.Data, "etl", session.EtlPath);
        AddPcapngPacketSummary(evt.Data, session.PcapngPath);
        AddProtocolDiagnosticDefaults(evt.Data);
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
                ["captureRequested"] = "true",
                ["explicitOptInRequired"] = "true",
                ["explicitOptInOption"] = "--packet-capture/--pcap/--network-capture",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-network-packet-capture",
                ["reason"] = reason,
                ["reasonCode"] = reason,
                ["reasonCategory"] = PacketCaptureReasonCategory(reason),
                ["reasonTaxonomy"] = ReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhMessage"] = "pktmon 命令失败，网络抓包通道未完整产出。",
                ["zhHint"] = PacketCaptureReasonZhHint(reason),
                ["collector"] = "pktmon",
                ["captureTool"] = PktmonExecutable,
                ["captureToolMode"] = "windows-pktmon-etw",
                ["conversionTool"] = PktmonExecutable,
                ["conversionStatus"] = reason == "pktmonConvertFailed" ? "failed" : "not-attempted",
                ["conversionSourceFormat"] = "etl",
                ["conversionTargetFormat"] = "pcapng",
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
                ["artifactRelativePathStatus"] = "expected-not-created",
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

        AddCaptureSourceToolData(evt.Data);
        AddPacketCaptureSelectorAliases(evt.Data);
        AddNamedFileEvidence(evt.Data, "etl", session.EtlPath);
        AddRootProcessData(evt, context);
        AddArtifactFileEvidence(evt, session.PcapngPath);
        AddNamedFileEvidence(evt.Data, "pcapng", session.PcapngPath);
        AddProtocolDiagnosticDefaults(evt.Data);
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

    private static string PacketCaptureReasonCategory(string reason)
    {
        return reason switch
        {
            "packetCaptureNotRequested" => "disabled",
            "notWindows" => "platform",
            "captureAlreadyActive" => "state",
            "captureWasNotStarted" => "state",
            "pktmonStartFailed" or "pktmonStopFailed" or "pktmonConvertFailed" => "tool",
            "protocolParserNotImplemented" => "protocol-summary",
            _ => "unknown"
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
    /// Adds stable source-tool aliases so reports can identify the artifact
    /// producer even when pktmon is missing, conversion fails, or only a
    /// lifecycle event is available.
    /// </summary>
    private static void AddCaptureSourceToolData(Dictionary<string, string> data)
    {
        AddIfNotEmpty(data, "captureTool", PktmonExecutable);
        AddIfNotEmpty(data, "sourceTool", PktmonExecutable);
        AddIfNotEmpty(data, "artifactSourceTool", PktmonExecutable);
        AddIfNotEmpty(data, "packetCaptureSourceTool", PktmonExecutable);
        AddIfNotEmpty(data, "sourceToolMode", "windows-pktmon-etw");
        AddIfNotEmpty(data, "packetCaptureSource", "guest-pktmon");
    }

    /// <summary>
    /// Adds stable selector aliases for the PCAPNG artifact path when present.
    /// </summary>
    private static void AddPacketCaptureSelectorAliases(Dictionary<string, string> data)
    {
        if (!data.TryGetValue("artifactRelativePath", out var artifactRelativePath) ||
            string.IsNullOrWhiteSpace(artifactRelativePath))
        {
            return;
        }

        AddIfNotEmpty(data, "artifactSelector", artifactRelativePath);
        AddIfNotEmpty(data, "stableArtifactSelector", artifactRelativePath);
        AddIfNotEmpty(data, "canonicalArtifactSelector", artifactRelativePath);
        AddIfNotEmpty(data, "downloadSelector", artifactRelativePath);
        AddIfNotEmpty(data, "artifactSafeLink", BuildSafeLink(artifactRelativePath));
        AddIfNotEmpty(data, "artifactSelectorKind", "safe-output-relative-path");
        AddIfNotEmpty(data, "artifactSelectorVersion", ArtifactSelectorVersion);
        AddIfNotEmpty(data, "artifactSelectionReason", "packet-capture-pcapng");
    }

    /// <summary>
    /// Marks expected-but-not-yet-created PCAPNG evidence without treating the
    /// pending file as a capture failure.
    /// </summary>
    private static void AddExpectedArtifactEvidence(Dictionary<string, string> data, string status)
    {
        AddIfNotEmpty(data, "artifactIntegrityState", status);
        AddIfNotEmpty(data, "artifactRelativePathStatus", status);
        AddIfNotEmpty(data, "hashStatus", status);
        AddIfNotEmpty(data, "artifactHashStatus", status);
        AddIfNotEmpty(data, "sizeBytesStatus", status);
        AddIfNotEmpty(data, "artifactSizeStatus", status);
    }

    /// <summary>
    /// Copies root process identity into event Data when available.
    /// </summary>
    private static void AddRootProcessData(SandboxEvent evt, GuestProbeContext context)
    {
        evt.Data["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context";
        if (context.RootProcessId is not null)
        {
            var rootProcessId = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["rootProcessId"] = rootProcessId;
            evt.Data["processId"] = rootProcessId;
            evt.Data["treeDepth"] = "0";
            evt.Data["treeLineage"] = rootProcessId;
            evt.Data["rootProcessIdStatus"] = "available";
            evt.Data["treeLineageStatus"] = "stable";
            evt.Data["lineageIncludesRoot"] = "true";
        }
        else
        {
            evt.Data["rootProcessIdStatus"] = "unavailable";
            evt.Data["treeLineageStatus"] = "unavailable";
            evt.Data["lineageIncludesRoot"] = "false";
        }

        if (context.RootParentProcessId is not null)
        {
            var parentProcessId = context.RootParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["rootParentProcessId"] = parentProcessId;
            evt.Data.TryAdd("parentProcessId", parentProcessId);
        }

        if (context.RootProcessStartTimeUtc is not null)
        {
            evt.Data["rootProcessStartTimeUtc"] = context.RootProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "processName", context.RootProcessName ?? evt.ProcessName);
        AddIfNotEmpty(evt.Data, "rootProcessName", context.RootProcessName);
        AddIfNotEmpty(evt.Data, "processImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "commandLine", context.RootCommandLine);
        AddIfNotEmpty(evt.Data, "rootCommandLine", context.RootCommandLine);
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
                evt.Data["hashStatus"] = "missing";
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
            evt.Data["artifactLastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            evt.Data["sha256"] = sha256;
            evt.Data["artifactSha256"] = sha256;
            evt.Data["hashAlgorithm"] = "sha256";
            evt.Data["hashStatus"] = "computed";
            evt.Data["artifactHashAlgorithm"] = "sha256";
            evt.Data["artifactHashStatus"] = "computed";
            evt.Data["artifactIntegrityState"] = "verified";
            evt.Data["sizeBytesStatus"] = "computed";
            evt.Data["sha256Status"] = "computed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data["hashStatus"] = "failed";
            evt.Data["artifactHashStatus"] = "failed";
            evt.Data["artifactIntegrityState"] = "hash-failed";
            evt.Data["sha256Status"] = "failed";
            evt.Data["artifactHashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["artifactHashMessage"] = ex.Message;
        }
    }


    /// <summary>
    /// Adds prefixed existence, size, timestamp, and SHA-256 evidence for a related capture file.
    /// </summary>
    private static void AddNamedFileEvidence(Dictionary<string, string> data, string prefix, string path)
    {
        try
        {
            var info = new FileInfo(path);
            data[$"{prefix}Path"] = path;
            if (!info.Exists)
            {
                data[$"{prefix}Exists"] = "false";
                data[$"{prefix}HashStatus"] = "missing";
                return;
            }

            data[$"{prefix}Exists"] = "true";
            data[$"{prefix}SizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            data[$"{prefix}LastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            data[$"{prefix}Sha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            data[$"{prefix}HashAlgorithm"] = "sha256";
            data[$"{prefix}HashStatus"] = "computed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            data[$"{prefix}HashStatus"] = "failed";
            data[$"{prefix}HashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            data[$"{prefix}HashMessage"] = ex.Message;
        }
    }

    /// <summary>
    /// Counts common PCAPNG packet blocks without requiring tshark or other external dependencies.
    /// </summary>
    private static void AddPcapngPacketSummary(Dictionary<string, string> data, string path)
    {
        try
        {
            var summary = CountPcapngPacketBlocks(path);
            data["packetCountStatus"] = summary.Status;
            data["packetCountConfidence"] = summary.Status == "computed" ? "pcapng-block-scan" : "diagnostic";
            data["pcapngDiagnosticsAvailable"] = "true";
            data["pcapngValidationStatus"] = summary.Status;
            data["pcapngTruncated"] = (summary.Status == "partial-or-invalid").ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            data["pcapngByteOrder"] = summary.ByteOrder;
            if (summary.PacketCount is not null)
            {
                data["packetCount"] = summary.PacketCount.Value.ToString(CultureInfo.InvariantCulture);
                data["pcapngPacketBlockCount"] = summary.PacketCount.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (summary.BlockCount is not null)
            {
                data["pcapngBlockCount"] = summary.BlockCount.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (summary.SectionHeaderBlockCount is not null)
            {
                data["pcapngSectionHeaderCount"] = summary.SectionHeaderBlockCount.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (summary.InterfaceDescriptionBlockCount is not null)
            {
                data["pcapngInterfaceDescriptionBlockCount"] = summary.InterfaceDescriptionBlockCount.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (summary.EnhancedPacketBlockCount is not null)
            {
                data["pcapngEnhancedPacketBlockCount"] = summary.EnhancedPacketBlockCount.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (summary.SimplePacketBlockCount is not null)
            {
                data["pcapngSimplePacketBlockCount"] = summary.SimplePacketBlockCount.Value.ToString(CultureInfo.InvariantCulture);
            }

            var trafficObserved = summary.PacketCount is > 0;
            data["trafficObserved"] = trafficObserved.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            data["emptyCapture"] = (summary.PacketCount == 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            data["packetCaptureQuality"] = summary.Status == "computed"
                ? trafficObserved ? "packets-observed" : "valid-empty-pcapng"
                : summary.Status;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            data["packetCountStatus"] = "failed";
            data["packetCountConfidence"] = "failed";
            data["pcapngDiagnosticsAvailable"] = "false";
            data["packetCountExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            data["packetCountMessage"] = ex.Message;
        }
    }

    private static PcapngPacketSummary CountPcapngPacketBlocks(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        Span<byte> header = stackalloc byte[12];
        if (stream.Read(header) != header.Length)
        {
            return new PcapngPacketSummary(null, null, null, null, null, null, "unknown", "too-small");
        }

        var littleEndian = true;
        var firstBlockType = BinaryPrimitives.ReadUInt32LittleEndian(header[..4]);
        if (firstBlockType != 0x0A0D0D0A)
        {
            return new PcapngPacketSummary(null, null, null, null, null, null, "unknown", "not-pcapng");
        }

        var byteOrderMagic = BinaryPrimitives.ReadUInt32LittleEndian(header[8..12]);
        var byteOrder = "little-endian";
        if (byteOrderMagic == 0x4D3C2B1A)
        {
            littleEndian = false;
            byteOrder = "big-endian";
        }
        else if (byteOrderMagic != 0x1A2B3C4D)
        {
            return new PcapngPacketSummary(null, null, null, null, null, null, "unknown", "unknown-byte-order");
        }

        stream.Position = 0;
        var blockCount = 0L;
        var sectionHeaderBlocks = 0L;
        var interfaceDescriptionBlocks = 0L;
        var enhancedPacketBlocks = 0L;
        var simplePacketBlocks = 0L;
        Span<byte> blockHeader = stackalloc byte[8];
        while (stream.Position + blockHeader.Length <= stream.Length && stream.Read(blockHeader) == blockHeader.Length)
        {
            var blockType = ReadUInt32(blockHeader[..4], littleEndian);
            var blockLength = ReadUInt32(blockHeader[4..8], littleEndian);
            if (blockLength < 12 || blockLength > int.MaxValue || stream.Position - 8 + blockLength > stream.Length)
            {
                return new PcapngPacketSummary(enhancedPacketBlocks + simplePacketBlocks, blockCount, sectionHeaderBlocks, interfaceDescriptionBlocks, enhancedPacketBlocks, simplePacketBlocks, byteOrder, "partial-or-invalid");
            }

            blockCount++;
            if (blockType == 0x0A0D0D0A)
            {
                sectionHeaderBlocks++;
            }
            else if (blockType == 0x00000001)
            {
                interfaceDescriptionBlocks++;
            }
            else if (blockType == 0x00000006)
            {
                enhancedPacketBlocks++;
            }
            else if (blockType == 0x00000003)
            {
                simplePacketBlocks++;
            }

            stream.Position += blockLength - 8;
        }

        return new PcapngPacketSummary(enhancedPacketBlocks + simplePacketBlocks, blockCount, sectionHeaderBlocks, interfaceDescriptionBlocks, enhancedPacketBlocks, simplePacketBlocks, byteOrder, "computed");
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> value, bool littleEndian)
    {
        return littleEndian
            ? BinaryPrimitives.ReadUInt32LittleEndian(value)
            : BinaryPrimitives.ReadUInt32BigEndian(value);
    }

    /// <summary>
    /// Extracts bounded pktmon conversion counters from stdout/stderr when pktmon prints them.
    /// </summary>
    private static void AddPktmonConversionOutputSummary(Dictionary<string, string> data, BoundedCommandResult result)
    {
        var output = string.Join('\n', new[] { result.StandardOutput, result.StandardError }.Where(text => !string.IsNullOrWhiteSpace(text)));
        if (string.IsNullOrWhiteSpace(output))
        {
            data["conversionOutputSummaryAvailable"] = "false";
            return;
        }

        data["conversionOutputSummaryAvailable"] = "true";
        var convertedPackets = FindFirstNumberAfterLabel(output, "packet");
        if (convertedPackets is not null)
        {
            data["pktmonReportedPacketCount"] = convertedPackets.Value.ToString(CultureInfo.InvariantCulture);
            AddIfNotEmpty(data, "packetCount", data.TryGetValue("packetCount", out var existing) && !string.IsNullOrWhiteSpace(existing) ? existing : convertedPackets.Value.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static void AddProtocolDiagnosticDefaults(Dictionary<string, string> data)
    {
        AddIfNotEmpty(data, "protocolDiagnosticsAvailable", data.TryGetValue("protocolDiagnosticsAvailable", out var existing) ? existing : "true");
        AddIfNotEmpty(data, "protocolDiagnostics", data.TryGetValue("protocolDiagnostics", out var diagnostics) ? diagnostics : "pcapng-block-counters");
        AddIfNotEmpty(data, "protocolFamiliesExpected", data.TryGetValue("protocolFamiliesExpected", out var families) ? families : "dns,http,tls");
        AddIfNotEmpty(data, "dnsSummaryState", data.TryGetValue("dnsSummaryState", out var dns) ? dns : "not-parsed");
        AddIfNotEmpty(data, "httpSummaryState", data.TryGetValue("httpSummaryState", out var http) ? http : "not-parsed");
        AddIfNotEmpty(data, "tlsSummaryState", data.TryGetValue("tlsSummaryState", out var tls) ? tls : "not-parsed");
        AddIfNotEmpty(data, "protocolSummaryAvailable", data.TryGetValue("protocolSummaryAvailable", out var available) ? available : "false");
        AddIfNotEmpty(data, "protocolSummaryState", data.TryGetValue("protocolSummaryState", out var state) ? state : "capture-metadata-only");
        AddIfNotEmpty(data, "protocolSummaryStatus", data.TryGetValue("protocolSummaryStatus", out var status) ? status : "skipped");
        AddIfNotEmpty(data, "protocolSummaryReason", data.TryGetValue("protocolSummaryReason", out var reason) ? reason : "protocolParserNotImplemented");
    }

    private static long? FindFirstNumberAfterLabel(string text, string label)
    {
        var labelIndex = text.IndexOf(label, StringComparison.OrdinalIgnoreCase);
        if (labelIndex < 0)
        {
            return null;
        }

        var digits = new string(text[(labelIndex + label.Length)..].SkipWhile(ch => !char.IsDigit(ch)).TakeWhile(char.IsDigit).ToArray());
        return long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
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

    private static string BuildSafeLink(string relativePath)
    {
        return string.Join(
            "/",
            relativePath
                .Replace('\\', '/')
                .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(Uri.EscapeDataString));
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

    private sealed record PcapngPacketSummary(
        long? PacketCount,
        long? BlockCount,
        long? SectionHeaderBlockCount,
        long? InterfaceDescriptionBlockCount,
        long? EnhancedPacketBlockCount,
        long? SimplePacketBlockCount,
        string ByteOrder,
        string Status);

    private sealed record PacketCaptureSession(
        string CaptureDirectory,
        string DiagnosticDirectory,
        string EtlPath,
        string PcapngPath,
        DateTimeOffset StartedAtUtc);
}
