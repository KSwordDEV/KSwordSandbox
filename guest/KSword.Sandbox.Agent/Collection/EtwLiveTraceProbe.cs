using System.Globalization;
using System.Text;
using System.Xml.Linq;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures a real Windows ETW kernel trace for the lifetime of a sample.
/// This probe intentionally stores the ETL as an evidence artifact; it does
/// not claim that an ETL file is already parsed behavior.  A successful
/// start/stop pair is required before an event is marked captured.  Missing
/// logman, insufficient privilege, an existing session, or a missing/empty
/// ETL all produce explicit failed rows so reports cannot confuse readiness
/// with live collection.
/// </summary>
internal sealed class EtwLiveTraceProbe : IGuestProbe
{
    private const string CollectorSource = "etwLive";
    private const string CollectionName = "etw-traces";
    private const string LogmanExecutable = "logman.exe";
    private const string TracerptExecutable = "tracerpt.exe";
    // Windows Kernel Trace is a system logger provider.  Windows rejects an
    // arbitrary session name with "provided session name is invalid"; the
    // supported logger name is NT Kernel Logger.  Keep the ETL filename unique
    // per run while reusing this required session identity.
    private const string KernelLoggerSessionName = "NT Kernel Logger";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan DecodeTimeout = TimeSpan.FromSeconds(30);
    private EtwTraceSession? activeSession;

    public string ProbeId => "etw-live-trace";

    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!context.CaptureEtwLiveTrace)
        {
            return phase == ProbePhase.BeforeStart ? [CreateDisabledEvent(context)] : [];
        }

        if (!OperatingSystem.IsWindows())
        {
            return phase == ProbePhase.BeforeStart
                ? [CreateFailureEvent("platformUnsupported", "before-start", context, null, null, null)]
                : [];
        }

        return phase switch
        {
            ProbePhase.BeforeStart => await StartAsync(context, cancellationToken).ConfigureAwait(false),
            ProbePhase.AfterRun => await StopAsync(context, cancellationToken).ConfigureAwait(false),
            _ => []
        };
    }

    private async Task<IReadOnlyList<SandboxEvent>> StartAsync(
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        if (activeSession is not null)
        {
            return [CreateFailureEvent("captureAlreadyActive", "before-start", context, activeSession, null, null)];
        }

        var traceDirectory = Path.Combine(context.OutputDirectory, CollectionName);
        Directory.CreateDirectory(traceDirectory);
        var etlPath = Path.Combine(traceDirectory, "KSEtw_" + Guid.NewGuid().ToString("N") + ".etl");
        var session = new EtwTraceSession(KernelLoggerSessionName, etlPath, DateTimeOffset.UtcNow);
        var activeLogger = await BoundedProcessRunner.RunAsync(
            LogmanExecutable,
            ["query", KernelLoggerSessionName, "-ets"],
            TimeSpan.FromSeconds(5),
            cancellationToken).ConfigureAwait(false);
        if (activeLogger.Succeeded)
        {
            return [CreateFailureEvent("captureAlreadyActive", "before-start", context, session, activeLogger, null)];
        }

        var result = await BoundedProcessRunner.RunAsync(
            LogmanExecutable,
            BuildStartArguments(session),
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            // `start ... -ets` does not persist a data-collector definition.
            // Do not issue a best-effort stop here: if the query above was
            // denied or raced another controller, stopping could terminate a
            // trace session that this job did not own.
            return [CreateFailureEvent(
                result.TimedOut ? "logmanStartTimedOut" : "logmanStartFailed",
                "before-start",
                context,
                session,
                result,
                null)];
        }

        activeSession = session;
        var evt = CreateBaseEvent("etw_live.started", "before-start", context, session);
        evt.Data["captureState"] = "started";
        evt.Data["status"] = "started";
        evt.Data["commandExitCode"] = FormatExitCode(result.ExitCode);
        evt.Data["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture);
        evt.Data["startCommand"] = FormatCommand(LogmanExecutable, BuildStartArguments(session));
        evt.Data["semanticRowsAvailable"] = "false";
        evt.Data["etlDecodeRequired"] = "true";
        evt.Data["zhMessage"] = "ETW 内核实时会话已启动，结束后将保存 ETL 原始证据。";
        evt.Data["zhHint"] = "started 只表示 logman 已创建会话；必须同时看到 etw_live.captured 和 ETL 文件校验字段，才能认为实时证据可用。ETL 尚未解析为行为行。";
        return [evt];
    }

    private async Task<IReadOnlyList<SandboxEvent>> StopAsync(
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        if (activeSession is null)
        {
            return [CreateFailureEvent("captureWasNotStarted", "after-run", context, null, null, null)];
        }

        var session = activeSession;
        activeSession = null;
        var result = await BoundedProcessRunner.RunAsync(
            LogmanExecutable,
            ["stop", session.SessionName, "-ets"],
            CommandTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return [CreateFailureEvent(
                result.TimedOut ? "logmanStopTimedOut" : "logmanStopFailed",
                "after-run",
                context,
                session,
                result,
                null)];
        }

        if (!File.Exists(session.EtlPath))
        {
            return [CreateFailureEvent("etlMissingAfterStop", "after-run", context, session, result, null)];
        }

        var info = new FileInfo(session.EtlPath);
        if (info.Length <= 0)
        {
            return [CreateFailureEvent("etlEmptyAfterStop", "after-run", context, session, result, info)];
        }

        var decode = await DecodeAsync(session, context, cancellationToken).ConfigureAwait(false);
        var evt = CreateBaseEvent("etw_live.captured", "after-run", context, session);
        evt.Data["captureState"] = "captured";
        evt.Data["status"] = "captured";
        evt.Data["commandExitCode"] = FormatExitCode(result.ExitCode);
        evt.Data["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture);
        evt.Data["stopCommand"] = $"{LogmanExecutable} stop {session.SessionName} -ets";
        evt.Data["captureStoppedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["sizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
        evt.Data["lastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["artifactRelativePathStatus"] = "captured";
        evt.Data["semanticRowsAvailable"] = decode.Rows.Count > 0 ? "true" : "false";
        evt.Data["etlDecodeRequired"] = decode.Succeeded ? "false" : "true";
        evt.Data["decodeAttempted"] = "true";
        evt.Data["decodeTool"] = TracerptExecutable;
        evt.Data["decodeCommandExitCode"] = FormatExitCode(decode.CommandResult?.ExitCode);
        evt.Data["decodeCommandTimedOut"] = (decode.CommandResult?.TimedOut ?? false).ToString(CultureInfo.InvariantCulture);
        evt.Data["parsedEventCount"] = decode.Rows.Count.ToString(CultureInfo.InvariantCulture);
        evt.Data["decodedEventCount"] = decode.Rows.Count.ToString(CultureInfo.InvariantCulture);
        evt.Data["decodedEventTypes"] = string.Join(",", decode.Rows
            .Select(static row => row.EventType)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(decode.DecodedPath))
        {
            var decodedRelativePath = RelativeToOutput(context.OutputDirectory, decode.DecodedPath);
            evt.Data["decodedArtifactRelativePath"] = decodedRelativePath;
            evt.Data["decodedArtifactSelector"] = decodedRelativePath;
            evt.Data["decodedArtifactExists"] = "true";
        }

        if (decode.Succeeded)
        {
            evt.Data["zhMessage"] = "ETW 内核实时会话已停止，并已通过 Windows tracerpt 解码为行为行。";
            evt.Data["zhHint"] = "该事件包含 ETL 原始证据及其 CSV 解码结果；process/thread/image/file/registry 行仍需结合样本进程树进行归因。";
            return [evt, ..decode.Rows];
        }

        evt.Data["decodeFailureReason"] = decode.FailureReason;
        evt.Data["zhMessage"] = "ETW 内核实时会话已停止，但解码未完成；原始 ETL 仍已保存。";
        evt.Data["zhHint"] = "tracerpt 解码失败或没有产生可解析行；不能把原始 ETL 当作已解析行为，报告会保留该采集缺口。";
        var failure = CreateDecodeFailureEvent(context, session, decode);
        return [evt, failure];
    }

    private static async Task<EtwDecodeResult> DecodeAsync(
        EtwTraceSession session,
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        var xmlPath = Path.ChangeExtension(session.EtlPath, ".xml");
        try
        {
            if (File.Exists(xmlPath))
            {
                File.Delete(xmlPath);
            }

            var result = await BoundedProcessRunner.RunAsync(
                TracerptExecutable,
                [session.EtlPath, "-o", xmlPath, "-of", "XML", "-y", "-lr"],
                DecodeTimeout,
                cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return new EtwDecodeResult(false, xmlPath, [], "tracerptFailed", result);
            }

            if (!File.Exists(xmlPath))
            {
                return new EtwDecodeResult(false, xmlPath, [], "decodedXmlMissing", result);
            }

            var info = new FileInfo(xmlPath);
            if (info.Length <= 0)
            {
                return new EtwDecodeResult(false, xmlPath, [], "decodedXmlEmpty", result);
            }

            var rows = ParseTracerptXml(xmlPath, session, context);
            if (rows.Count == 0)
            {
                return new EtwDecodeResult(false, xmlPath, [], "decodedXmlHasNoEventRows", result);
            }

            return new EtwDecodeResult(true, xmlPath, rows, string.Empty, result);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or FormatException or System.Xml.XmlException)
        {
            return new EtwDecodeResult(false, xmlPath, [], "decoderException:" + ex.GetType().Name, null);
        }
    }

    private static IReadOnlyList<SandboxEvent> ParseTracerptXml(
        string xmlPath,
        EtwTraceSession session,
        GuestProbeContext context)
    {
        var document = XDocument.Load(xmlPath, LoadOptions.PreserveWhitespace);
        var rows = new List<SandboxEvent>();
        foreach (var eventElement in document.Descendants().Where(static element => element.Name.LocalName.Equals("Event", StringComparison.OrdinalIgnoreCase)))
        {
            var system = eventElement.Elements().FirstOrDefault(static element => element.Name.LocalName.Equals("System", StringComparison.OrdinalIgnoreCase));
            if (system is null)
            {
                continue;
            }

            var providerElement = system.Elements().FirstOrDefault(static element => element.Name.LocalName.Equals("Provider", StringComparison.OrdinalIgnoreCase));
            var renderingInfo = eventElement.Elements().FirstOrDefault(static element => element.Name.LocalName.Equals("RenderingInfo", StringComparison.OrdinalIgnoreCase));
            var provider = FirstNonEmpty(
                providerElement?.Attribute("Name")?.Value,
                providerElement?.Attribute("name")?.Value,
                ChildValue(renderingInfo, "Provider"));
            var eventId = ChildValue(system, "EventID", "EventId", "Id");
            var opcode = FirstNonEmpty(ChildValue(system, "Opcode", "Operation"), ChildValue(renderingInfo, "Opcode", "Operation"));
            var task = ChildValue(system, "Task");
            var timestampElement = system.Elements().FirstOrDefault(static element => element.Name.LocalName.Equals("TimeCreated", StringComparison.OrdinalIgnoreCase));
            var timestampText = FirstNonEmpty(timestampElement?.Attribute("SystemTime")?.Value, timestampElement?.Attribute("systemTime")?.Value);
            var timestamp = ParseTimestamp(timestampText) ?? DateTimeOffset.UtcNow;
            var execution = system.Elements().FirstOrDefault(static element => element.Name.LocalName.Equals("Execution", StringComparison.OrdinalIgnoreCase));
            var processId = ParseProcessId(FirstNonEmpty(execution?.Attribute("ProcessID")?.Value, execution?.Attribute("ProcessId")?.Value));
            var threadId = FirstNonEmpty(execution?.Attribute("ThreadID")?.Value, execution?.Attribute("ThreadId")?.Value);
            var eventName = FirstNonEmpty(
                ChildValue(renderingInfo, "EventName", "Name"),
                ChildValue(system, "EventName", "Name"),
                task,
                opcode,
                provider + ":" + eventId);
            var payload = eventElement.Descendants().Where(static element => element.Name.LocalName.Equals("Data", StringComparison.OrdinalIgnoreCase));
            var payloadValues = payload
                .Select(element =>
                {
                    var name = FirstNonEmpty(element.Attribute("Name")?.Value, element.Attribute("name")?.Value);
                    return string.IsNullOrWhiteSpace(name) ? element.Value : name + "=" + element.Value;
                })
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .ToList();
            var payloadByName = payload
                .Select(element => (Name: NormalizeColumnName(FirstNonEmpty(element.Attribute("Name")?.Value, element.Attribute("name")?.Value)), Value: element.Value.Trim()))
                .Where(static pair => !string.IsNullOrWhiteSpace(pair.Name))
                .GroupBy(static pair => pair.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(static group => group.Key, static group => group.First().Value, StringComparer.OrdinalIgnoreCase);
            var payloadProcessId = ParseProcessId(ValueOrEmpty(payloadByName, "processid", "pid"));
            processId = payloadProcessId ?? processId;
            var parentProcessId = ParseProcessId(ValueOrEmpty(payloadByName, "parentprocessid", "parentpid", "parentid"));
            threadId = FirstNonEmpty(threadId, ValueOrEmpty(payloadByName, "threadid", "tthreadid"));
            var image = ValueOrEmpty(payloadByName, "imagename", "imagefilename", "image", "processname", "process");
            var path = ValueOrEmpty(payloadByName, "filename", "file", "path", "imagepath");
            var commandLine = ValueOrEmpty(payloadByName, "commandline", "command");
            var eventType = MapEventType(eventName, provider + " " + opcode + " " + task + " " + eventId);
            var data = CreateDecodedData(eventType, eventName, provider, eventId, opcode, threadId, session, context, string.Join("; ", payloadValues));
            rows.Add(new SandboxEvent
            {
                EventType = eventType,
                Timestamp = timestamp,
                Source = CollectorSource,
                ProcessName = image,
                ProcessId = processId,
                ParentProcessId = parentProcessId,
                Path = path,
                CommandLine = commandLine,
                Data = data
            });
        }

        return rows;
    }

    private static Dictionary<string, string> CreateDecodedData(
        string eventType,
        string eventName,
        string provider,
        string eventId,
        string opcode,
        string threadId,
        EtwTraceSession session,
        GuestProbeContext context,
        string payload)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["collectorSource"] = CollectorSource,
            ["captureSource"] = "etw-live-tracerpt",
            ["eventName"] = eventName,
            ["providerName"] = provider,
            ["eventId"] = eventId,
            ["opcode"] = opcode,
            ["threadId"] = threadId,
            ["traceSessionName"] = session.SessionName,
            ["traceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
            ["semanticEventClass"] = EventClassForType(eventType),
            ["semanticEventTags"] = "etw,windows-kernel," + EventClassForType(eventType),
            ["rawDecoded"] = "true"
        };
        AddIfNotEmpty(data, "payload", payload);
        AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "samplePath", context.SamplePath);
        return data;
    }

    private static string ChildValue(XElement? parent, params string[] names)
    {
        if (parent is null)
        {
            return string.Empty;
        }

        foreach (var child in parent.Elements())
        {
            if (names.Any(name => child.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase)))
            {
                return child.Value.Trim();
            }
        }

        return string.Empty;
    }

    private static string ValueOrEmpty(IReadOnlyDictionary<string, string> values, params string[] names)
    {
        foreach (var name in names)
        {
            if (values.TryGetValue(NormalizeColumnName(name), out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;

    private static IReadOnlyList<SandboxEvent> ParseTracerptCsv(
        string csvPath,
        EtwTraceSession session,
        GuestProbeContext context)
    {
        var lines = File.ReadLines(csvPath).Where(static line => !string.IsNullOrWhiteSpace(line));
        using var enumerator = lines.GetEnumerator();
        if (!enumerator.MoveNext())
        {
            return [];
        }

        var header = ParseCsvLine(enumerator.Current);
        if (!LooksLikeTracerptHeader(header))
        {
            return [];
        }

        var columns = header
            .Select((value, index) => (Name: NormalizeColumnName(value), Index: index))
            .Where(static item => !string.IsNullOrWhiteSpace(item.Name))
            .GroupBy(static item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static group => group.Key, static group => group.First().Index, StringComparer.OrdinalIgnoreCase);
        var rows = new List<SandboxEvent>();
        while (enumerator.MoveNext())
        {
            var fields = ParseCsvLine(enumerator.Current);
            if (fields.Count == 0 || fields.All(static field => string.IsNullOrWhiteSpace(field)))
            {
                continue;
            }

            var eventName = GetField(fields, columns, "eventname", "event", "name");
            var provider = GetField(fields, columns, "providername", "provider");
            var eventId = GetField(fields, columns, "eventid", "id");
            if (string.IsNullOrWhiteSpace(eventName) && string.IsNullOrWhiteSpace(provider))
            {
                continue;
            }

            var eventType = MapEventType(eventName, provider);
            var processId = ParseProcessId(GetField(fields, columns, "processid", "pid"));
            var parentProcessId = ParseProcessId(GetField(fields, columns, "parentprocessid", "parentpid"));
            var threadId = GetField(fields, columns, "threadid", "tid");
            var timestamp = ParseTimestamp(GetField(fields, columns, "timestamp", "timestamputc", "time")) ?? DateTimeOffset.UtcNow;
            var image = GetField(fields, columns, "imagename", "image", "processname", "process");
            var path = GetField(fields, columns, "filename", "file", "path", "imagepath");
            var opcode = GetField(fields, columns, "opcode", "operation");
            var payload = BuildPayload(fields, columns, "payload", "data", "userdata");
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectorSource"] = CollectorSource,
                ["captureSource"] = "etw-live-tracerpt",
                ["eventName"] = eventName,
                ["providerName"] = provider,
                ["eventId"] = eventId,
                ["opcode"] = opcode,
                ["threadId"] = threadId,
                ["traceSessionName"] = session.SessionName,
                ["traceArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath),
                ["semanticEventClass"] = EventClassForType(eventType),
                ["semanticEventTags"] = "etw,windows-kernel," + EventClassForType(eventType),
                ["rawDecoded"] = "true"
            };
            AddIfNotEmpty(data, "payload", payload);
            AddIfNotEmpty(data, "processorNumber", GetField(fields, columns, "processornumber", "cpu"));
            AddIfNotEmpty(data, "kernelTime", GetField(fields, columns, "kerneltime"));
            AddIfNotEmpty(data, "userTime", GetField(fields, columns, "usertime"));
            AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
            AddIfNotEmpty(data, "samplePath", context.SamplePath);

            rows.Add(new SandboxEvent
            {
                EventType = eventType,
                Timestamp = timestamp,
                Source = CollectorSource,
                ProcessName = image,
                ProcessId = processId,
                ParentProcessId = parentProcessId,
                Path = path,
                CommandLine = GetField(fields, columns, "commandline", "command"),
                Data = data
            });
        }

        return rows;
    }

    private static SandboxEvent CreateDecodeFailureEvent(
        GuestProbeContext context,
        EtwTraceSession session,
        EtwDecodeResult decode)
    {
        var evt = CreateBaseEvent("etw_live.decode_failed", "after-run", context, session);
        evt.Data["captureState"] = "failed";
        evt.Data["status"] = "failed";
        evt.Data["decodeAttempted"] = "true";
        evt.Data["decodeTool"] = TracerptExecutable;
        evt.Data["decodeFailureReason"] = decode.FailureReason;
        evt.Data["nonfatal"] = "true";
        evt.Data["semanticRowsAvailable"] = "false";
        evt.Data["etlDecodeRequired"] = "true";
        evt.Data["decodedArtifactRelativePath"] = RelativeToOutput(context.OutputDirectory, decode.DecodedPath);
        evt.Data["zhMessage"] = "ETW 原始证据已保存，但 Windows tracerpt 解码失败。";
        evt.Data["zhHint"] = "这是明确的 ETW 解码缺口；请保留 ETL 与 tracerpt 诊断，不要把它标记成未检出。";
        AddIfNotEmpty(evt.Data, "decodeCommandExitCode", FormatExitCode(decode.CommandResult?.ExitCode));
        AddIfNotEmpty(evt.Data, "decodeStderr", Truncate(decode.CommandResult?.StandardError));
        return evt;
    }

    private static IReadOnlyList<string> BuildStartArguments(EtwTraceSession session)
    {
        // Kernel-Process/Thread/Image are built-in providers.  The broad mask
        // keeps short-lived process and image edges visible; ETL is bounded by
        // the per-run duration and the OS logger buffer policy.
        return
        [
            // The reserved kernel logger is started directly; `create trace`
            // treats the reserved name as a normal data collector and can
            // return the same invalid-session error seen in the field.
            "start", session.SessionName,
            // Use the provider GUID so localized Windows builds do not depend
            // on the display name of Windows Kernel Trace.  The keyword group
            // names are the documented process/thread/image/file/registry
            // kernel flags.  These cover short-lived process edges and the
            // file/registry providers without pretending ETL is decoded.
            "-p", "{9e814aad-3204-11d2-9a82-006008a86939}", "(process,thread,img,file,fileio,registry)",
            "-o", session.EtlPath,
            "-ets"
        ];
    }

    private static bool LooksLikeTracerptHeader(IReadOnlyList<string> fields)
    {
        var normalized = fields.Select(NormalizeColumnName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return normalized.Contains("eventname") ||
               normalized.Contains("event") ||
               normalized.Contains("eventid") ||
               normalized.Contains("timestamp") ||
               normalized.Contains("providername");
    }

    private static string NormalizeColumnName(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value.Trim().Trim('\uFEFF').ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(character))
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
    }

    private static string GetField(
        IReadOnlyList<string> fields,
        IReadOnlyDictionary<string, int> columns,
        params string[] names)
    {
        foreach (var name in names)
        {
            if (columns.TryGetValue(name, out var index) && index < fields.Count)
            {
                return fields[index].Trim();
            }
        }

        return string.Empty;
    }

    private static int? ParseProcessId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(normalized[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
        {
            return hex;
        }

        return int.TryParse(normalized, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid)
            ? pid
            : null;
    }

    private static DateTimeOffset? ParseTimestamp(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return DateTimeOffset.TryParse(
            value.Trim(),
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var timestamp)
            ? timestamp
            : null;
    }

    private static string BuildPayload(
        IReadOnlyList<string> fields,
        IReadOnlyDictionary<string, int> columns,
        params string[] names)
    {
        var payload = GetField(fields, columns, names);
        if (!string.IsNullOrWhiteSpace(payload))
        {
            return payload;
        }

        var knownIndexes = columns.Values.ToHashSet();
        return string.Join(",", fields
            .Select((value, index) => (value, index))
            .Where(item => !knownIndexes.Contains(item.index) && !string.IsNullOrWhiteSpace(item.value))
            .Select(item => item.value.Trim()));
    }

    private static string MapEventType(string eventName, string provider)
    {
        var value = (eventName + " " + provider).Trim();
        if (ContainsAny(value, "processstart", "process/start", "process start", "processcreate") ||
            (ContainsAny(value, "process") && ContainsAny(value, "start", "dcstart")) ||
            (ContainsAny(value, "kernel-process", "kernel process", "kernelprocess") &&
             ContainsAny(value, "start", "dcstart")))
        {
            return "process.start";
        }

        if (ContainsAny(value, "processstop", "process/stop", "process stop", "processexit") ||
            (ContainsAny(value, "process") && ContainsAny(value, "stop", "dcstop", "exit")) ||
            (ContainsAny(value, "kernel-process", "kernel process", "kernelprocess") &&
             ContainsAny(value, "stop", "dcstop", "exit")))
        {
            return "process.exit";
        }

        if (ContainsAny(value, "threadstart", "thread/start", "thread start") ||
            (ContainsAny(value, "thread") && ContainsAny(value, "start", "dcstart")) ||
            (ContainsAny(value, "kernel-thread", "kernel thread", "kernelthread") &&
             ContainsAny(value, "start", "dcstart")))
        {
            return "thread.start";
        }

        if (ContainsAny(value, "threadstop", "thread/stop", "thread stop", "threadexit") ||
            (ContainsAny(value, "thread") && ContainsAny(value, "stop", "dcstop", "exit")) ||
            (ContainsAny(value, "kernel-thread", "kernel thread", "kernelthread") &&
             ContainsAny(value, "stop", "dcstop", "exit")))
        {
            return "thread.exit";
        }

        if (ContainsAny(value, "imageload", "image/load", "image load", "imageunload") ||
            (ContainsAny(value, "image") && ContainsAny(value, "start", "dcstart", "load")))
        {
            return "image.load";
        }

        if (ContainsAny(value, "fileio", "file/io", "file io", "filecreate", "filedelete", "filerename"))
        {
            return "file.etw.io";
        }

        if (ContainsAny(value, "registry", "regkcb", "regset", "regdelete"))
        {
            return "registry.etw";
        }

        return "etw.kernel.event";
    }

    private static string EventClassForType(string eventType) => eventType switch
    {
        "process.start" or "process.exit" => "process",
        "thread.start" or "thread.exit" => "thread",
        "image.load" => "image",
        "file.etw.io" => "file",
        "registry.etw" => "registry",
        _ => "kernel"
    };

    private static bool ContainsAny(string value, params string[] candidates) =>
        candidates.Any(candidate => value.Contains(candidate, StringComparison.OrdinalIgnoreCase));

    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        for (var index = 0; index < line.Length; index++)
        {
            var character = line[index];
            if (character == '"')
            {
                if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                {
                    field.Append('"');
                    index++;
                }
                else
                {
                    quoted = !quoted;
                }

                continue;
            }

            if (character == ',' && !quoted)
            {
                fields.Add(field.ToString());
                field.Clear();
                continue;
            }

            field.Append(character);
        }

        fields.Add(field.ToString());
        return fields;
    }

    private static SandboxEvent CreateDisabledEvent(GuestProbeContext context)
    {
        var evt = CreateBaseEvent("etw_live.disabled", "before-start", context, null);
        evt.Data["captureState"] = "disabled";
        evt.Data["status"] = "disabled";
        evt.Data["captureEnabled"] = "false";
        evt.Data["reason"] = "etwLiveNotRequested";
        evt.Data["zhMessage"] = "ETW 内核实时采集未启用。";
        evt.Data["zhHint"] = "当前报告没有 ETW live 原始证据；如需覆盖短命进程、线程和镜像边沿，请显式传入 --etw-live，并在结果中检查 etw_live.captured。";
        return evt;
    }

    private static SandboxEvent CreateFailureEvent(
        string reason,
        string phase,
        GuestProbeContext context,
        EtwTraceSession? session,
        BoundedCommandResult? result,
        FileInfo? file)
    {
        var evt = CreateBaseEvent("etw_live.failed", phase, context, session);
        evt.Data["captureState"] = "failed";
        evt.Data["status"] = "failed";
        evt.Data["reason"] = reason;
        evt.Data["reasonCode"] = reason;
        evt.Data["captureEnabled"] = "true";
        evt.Data["nonfatal"] = "true";
        evt.Data["commandExitCode"] = FormatExitCode(result?.ExitCode);
        evt.Data["commandTimedOut"] = (result?.TimedOut ?? false).ToString(CultureInfo.InvariantCulture);
        AddIfNotEmpty(evt.Data, "exceptionType", result?.ExceptionType);
        AddIfNotEmpty(evt.Data, "message", result?.Message);
        AddIfNotEmpty(evt.Data, "stderr", Truncate(result?.StandardError));
        AddIfNotEmpty(evt.Data, "stdout", Truncate(result?.StandardOutput));
        if (file is not null)
        {
            evt.Data["sizeBytes"] = file.Length.ToString(CultureInfo.InvariantCulture);
        }

        evt.Data["zhMessage"] = "ETW 内核实时采集未完成，已明确记录证据缺口。";
        evt.Data["zhHint"] = reason switch
        {
            "platformUnsupported" => "当前 guest 不是 Windows，无法启动 logman ETW 会话。",
            "captureAlreadyActive" => "上一 ETW 会话仍处于活动状态；请检查 logman query -ets 后清理残留会话。",
            "captureWasNotStarted" => "after-run 没有对应的 started 事件，不能把本次运行称为 ETW live captured。",
            _ => "请检查 guest 管理员权限、logman 输出、ETW 会话名称和 trace 文件；本次运行的 ETW 证据不可用。"
        };
        return evt;
    }

    private static SandboxEvent CreateBaseEvent(
        string eventType,
        string phase,
        GuestProbeContext context,
        EtwTraceSession? session)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = CollectorSource,
            ["collectorSource"] = CollectorSource,
            ["collectionName"] = CollectionName,
            ["evidenceRole"] = "etw-kernel-trace",
            ["phase"] = phase,
            ["capturePhase"] = phase,
            ["capturePolicy"] = "explicit-opt-in-etw-kernel-trace",
            ["captureTool"] = LogmanExecutable,
            ["captureToolMode"] = "windows-logman-kernel-etw",
            ["traceProviders"] = "Windows Kernel Trace(flags=process|thread|image-load|file-io|registry)",
            ["etwLiveCaptureEnabled"] = "true",
            ["etwSessionStarted"] = string.Equals(eventType, "etw_live.started", StringComparison.OrdinalIgnoreCase) ? "true" : "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["behaviorCounted"] = "false",
            ["sampleBehaviorCandidate"] = "false",
            ["semanticRowsAvailable"] = "false",
            ["etlDecodeRequired"] = "true",
            ["implemented"] = "true",
            ["reasonTaxonomy"] = "guest-artifact.etw-live.reason.v1"
        };
        if (session is not null)
        {
            data["traceSessionName"] = session.SessionName;
            data["traceFilePath"] = session.EtlPath;
            data["artifactRelativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["relativePath"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["stableArtifactSelector"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["canonicalArtifactSelector"] = RelativeToOutput(context.OutputDirectory, session.EtlPath);
            data["captureStartedUtc"] = session.StartedAtUtc.ToString("O", CultureInfo.InvariantCulture);
            data["expectedRelativePath"] = $"{CollectionName}/*.etl";
        }

        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = CollectorSource,
            ProcessName = SafeFileName(context.RootProcessPath ?? context.SamplePath),
            ProcessId = context.RootProcessId,
            Path = session?.EtlPath ?? context.SamplePath,
            CommandLine = context.RootCommandLine,
            Data = data
        };
        AddIfNotEmpty(data, "samplePath", context.SamplePath);
        AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        return evt;
    }

    private static string RelativeToOutput(string outputDirectory, string path)
    {
        return NormalizeRelativePath(Path.GetRelativePath(outputDirectory, path));
    }

    private static string NormalizeRelativePath(string path) => path.Replace('\\', '/');

    private static string FormatExitCode(int? exitCode) => exitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;

    private static string? Truncate(string? value) => string.IsNullOrWhiteSpace(value)
        ? null
        : value.Length <= 512 ? value : value[..512];

    private static void AddIfNotEmpty(IDictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path); }
        catch { return string.Empty; }
    }

    private static string FormatCommand(string fileName, IEnumerable<string> args) =>
        fileName + " " + string.Join(" ", args.Select(static arg => arg.Any(char.IsWhiteSpace) ? $"\"{arg}\"" : arg));

    private sealed record EtwTraceSession(string SessionName, string EtlPath, DateTimeOffset StartedAtUtc);

    private sealed record EtwDecodeResult(
        bool Succeeded,
        string DecodedPath,
        IReadOnlyList<SandboxEvent> Rows,
        string FailureReason,
        BoundedCommandResult? CommandResult);
}
