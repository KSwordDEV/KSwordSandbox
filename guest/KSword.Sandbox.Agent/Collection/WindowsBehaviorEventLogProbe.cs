using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Collects targeted Windows operational Event Log rows that complement R0 and
/// Security-audit coverage without starting a live ETW trace session. Inputs
/// are probe phases and sample context; processing runs bounded wevtutil
/// queries against low-volume service/task/PowerShell channels; output rows
/// carry stable correlation, severity, and noise-boundary fields.
/// </summary>
internal sealed class WindowsBehaviorEventLogProbe : IGuestProbe
{
    private const string CollectorSource = "windowsBehaviorEventLog";
    private const string CollectionName = "windows-behavior-event-log";
    private const string EvidenceRole = "targeted-windows-eventlog-behavior";
    private const int MaxEventsPerChannelRead = 128;
    private const int MaxFieldValueLength = 2048;
    private const int MaxRenderedMessageLength = 1024;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan QueryOverlap = TimeSpan.FromSeconds(2);

    private static readonly TargetChannel[] TargetChannels =
    [
        new(
            "system-service-control-manager",
            "System",
            ["Service Control Manager"],
            [7035, 7040, 7045],
            "service-control-manager",
            "service,persistence,service-control",
            "Service Control Manager System log records service installation, start-type mutation, and service control events that may not be attributed by R0 callbacks."),
        new(
            "task-scheduler-operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            ["Microsoft-Windows-TaskScheduler"],
            [106, 140, 141, 142, 200, 201],
            "scheduled-task-operational",
            "scheduled-task,persistence,execution",
            "Task Scheduler Operational records task registration/update/delete and task action start/complete events outside the R0 registry view."),
        new(
            "powershell-operational",
            "Microsoft-Windows-PowerShell/Operational",
            ["Microsoft-Windows-PowerShell"],
            [4103, 4104],
            "powershell-operational",
            "powershell,command,script-block,credential,registry,network",
            "PowerShell Operational module/script-block logs can expose user-mode credential, registry, service, task, file, and network commands when logging is enabled.")
    ];

    private readonly HashSet<string> seenEventKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> unavailableChannels = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset? collectionStartUtc;
    private DateTimeOffset? lastQueryUtc;

    public string ProbeId => "windows-behavior-event-log";

    /// <summary>
    /// Collects bounded Windows Event Log records. BeforeStart only records the
    /// query watermark and a non-behavior start row; later phases query recent
    /// target records and convert expected failures into diagnostics.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return phase == ProbePhase.BeforeStart
                ? [CreateSkippedEvent(phase, context, "nonWindowsGuest", null, null, null)]
                : [];
        }

        if (phase == ProbePhase.BeforeStart)
        {
            collectionStartUtc = DateTimeOffset.UtcNow.Subtract(QueryOverlap);
            lastQueryUtc = null;
            seenEventKeys.Clear();
            unavailableChannels.Clear();
            return [CreateStartedEvent(phase, context)];
        }

        if (phase != ProbePhase.AfterStart && phase != ProbePhase.AfterRun && phase != ProbePhase.Cleanup)
        {
            return [];
        }

        collectionStartUtc ??= DateTimeOffset.UtcNow.Subtract(QueryOverlap);
        var querySinceUtc = (lastQueryUtc ?? collectionStartUtc.Value).Subtract(QueryOverlap);
        var queryStartedUtc = DateTimeOffset.UtcNow;
        var events = new List<SandboxEvent>();
        var emittedCount = 0;
        var correlatedCount = 0;
        var skippedChannelCount = 0;
        var failedChannelCount = 0;
        var possiblyTruncated = false;

        foreach (var channel in TargetChannels)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (unavailableChannels.Contains(channel.ChannelName))
            {
                skippedChannelCount++;
                continue;
            }

            var result = await QueryChannelAsync(channel, querySinceUtc, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                var reason = ClassifyQueryFailure(result);
                events.Add(CreateSkippedEvent(phase, context, reason, channel, result, querySinceUtc));
                failedChannelCount++;
                if (IsPermanentUnavailableReason(reason))
                {
                    unavailableChannels.Add(channel.ChannelName);
                }

                continue;
            }

            var rawEvents = ParseEventLogEvents(result.StandardOutput, channel, phase, context, events)
                .Where(IsTargetEvent)
                .Where(ShouldEmit)
                .OrderBy(rawEvent => rawEvent.TimestampUtc)
                .ThenBy(rawEvent => rawEvent.RecordId ?? long.MaxValue)
                .ToList();

            possiblyTruncated |= rawEvents.Count >= MaxEventsPerChannelRead;
            foreach (var rawEvent in rawEvents)
            {
                var normalized = CreateBehaviorEvent(rawEvent, phase, context);
                if (IsBehaviorCounted(normalized))
                {
                    correlatedCount++;
                }

                events.Add(normalized);
                emittedCount++;
            }
        }

        lastQueryUtc = queryStartedUtc;
        events.Add(CreateQuerySummaryEvent(
            phase,
            context,
            querySinceUtc,
            queryStartedUtc,
            emittedCount,
            correlatedCount,
            skippedChannelCount,
            failedChannelCount,
            possiblyTruncated));
        return events;
    }

    private static Task<BoundedCommandResult> QueryChannelAsync(
        TargetChannel channel,
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken)
    {
        var wevtutilPath = ResolveWevtutilPath();
        var systemTime = sinceUtc.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        var eventIdPredicate = string.Join(
            " or ",
            channel.EventIds.Select(static id => $"EventID={id.ToString(CultureInfo.InvariantCulture)}"));
        var query = $"*[System[({eventIdPredicate}) and TimeCreated[@SystemTime >= '{systemTime}']]]";
        var arguments = new[]
        {
            "qe",
            channel.ChannelName,
            $"/q:{query}",
            "/f:RenderedXml",
            "/rd:true",
            $"/c:{MaxEventsPerChannelRead.ToString(CultureInfo.InvariantCulture)}"
        };

        return BoundedProcessRunner.RunAsync(wevtutilPath, arguments, CommandTimeout, cancellationToken);
    }

    private static string ResolveWevtutilPath()
    {
        var systemDirectory = Environment.SystemDirectory;
        if (!string.IsNullOrWhiteSpace(systemDirectory))
        {
            var candidate = Path.Combine(systemDirectory, "wevtutil.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return "wevtutil.exe";
    }

    private static IReadOnlyList<RawWindowsEvent> ParseEventLogEvents(
        string xml,
        TargetChannel channel,
        ProbePhase phase,
        GuestProbeContext context,
        List<SandboxEvent> diagnostics)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return [];
        }

        var events = new List<RawWindowsEvent>();
        var settings = new XmlReaderSettings
        {
            ConformanceLevel = ConformanceLevel.Fragment,
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element ||
                    !string.Equals(reader.LocalName, "Event", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (XElement.ReadFrom(reader) is XElement element && TryParseEvent(element, channel, out var rawEvent))
                {
                    events.Add(rawEvent);
                }
            }
        }
        catch (XmlException ex)
        {
            diagnostics.Add(CreateParseFailedEvent(phase, context, channel, ex, xml));
        }

        return events;
    }

    private static bool TryParseEvent(XElement element, TargetChannel targetChannel, out RawWindowsEvent rawEvent)
    {
        var ns = element.Name.Namespace;
        var system = element.Element(ns + "System");
        if (system is null)
        {
            rawEvent = default!;
            return false;
        }

        var eventIdText = system.Element(ns + "EventID")?.Value;
        if (!int.TryParse(eventIdText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
        {
            rawEvent = default!;
            return false;
        }

        var timestampText = system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value;
        var timestampUtc = DateTimeOffset.TryParse(
            timestampText,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsedTimestamp)
            ? parsedTimestamp
            : DateTimeOffset.UtcNow;

        var recordIdText = system.Element(ns + "EventRecordID")?.Value;
        var recordId = long.TryParse(recordIdText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedRecordId)
            ? parsedRecordId
            : (long?)null;

        var execution = system.Element(ns + "Execution");
        var eventData = ReadEventData(element, ns);
        var renderedMessage = element
            .Element(ns + "RenderingInfo")
            ?.Element(ns + "Message")
            ?.Value ?? string.Empty;

        rawEvent = new RawWindowsEvent(
            targetChannel,
            eventId,
            NormalizedEventName(targetChannel.SurfaceKey, eventId),
            recordId,
            timestampUtc,
            system.Element(ns + "Provider")?.Attribute("Name")?.Value ?? string.Empty,
            system.Element(ns + "Computer")?.Value ?? string.Empty,
            system.Element(ns + "Channel")?.Value ?? targetChannel.ChannelName,
            system.Element(ns + "Task")?.Value ?? string.Empty,
            system.Element(ns + "Opcode")?.Value ?? string.Empty,
            system.Element(ns + "Keywords")?.Value ?? string.Empty,
            execution?.Attribute("ProcessID")?.Value ?? string.Empty,
            execution?.Attribute("ThreadID")?.Value ?? string.Empty,
            eventData,
            Truncate(renderedMessage, MaxRenderedMessageLength));
        return true;
    }

    private static Dictionary<string, string> ReadEventData(XElement element, XNamespace ns)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var ordinal = 0;
        foreach (var dataElement in element
            .Descendants(ns + "Data")
            .Where(static item => item.Parent is not null &&
                (string.Equals(item.Parent.Name.LocalName, "EventData", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(item.Parent.Name.LocalName, "UserData", StringComparison.OrdinalIgnoreCase))))
        {
            ordinal++;
            var name = dataElement.Attribute("Name")?.Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                name = $"Data{ordinal.ToString(CultureInfo.InvariantCulture)}";
            }

            var key = name;
            var duplicate = 2;
            while (data.ContainsKey(key))
            {
                key = $"{name}{duplicate.ToString(CultureInfo.InvariantCulture)}";
                duplicate++;
            }

            data[key] = Truncate(dataElement.Value, MaxFieldValueLength);
        }

        return data;
    }

    private bool ShouldEmit(RawWindowsEvent rawEvent)
    {
        var key = rawEvent.RecordId is not null
            ? $"{rawEvent.Channel}:record:{rawEvent.RecordId.Value.ToString(CultureInfo.InvariantCulture)}"
            : $"{rawEvent.Channel}:synthetic:{rawEvent.EventId}:{rawEvent.TimestampUtc:O}:{Field(rawEvent.EventData, "ProcessID")}:{Field(rawEvent.EventData, "ServiceName")}:{Field(rawEvent.EventData, "TaskName")}:{Field(rawEvent.EventData, "ScriptBlockId")}:{Field(rawEvent.EventData, "ImagePath")}:{Field(rawEvent.EventData, "HostApplication")}";
        return seenEventKeys.Add(key);
    }

    private static bool IsTargetEvent(RawWindowsEvent rawEvent)
    {
        return rawEvent.TargetChannel.EventIds.Contains(rawEvent.EventId) &&
            rawEvent.TargetChannel.ProviderNames.Any(providerName =>
                string.Equals(providerName, rawEvent.ProviderName, StringComparison.OrdinalIgnoreCase));
    }

    private static SandboxEvent CreateBehaviorEvent(
        RawWindowsEvent rawEvent,
        ProbePhase phase,
        GuestProbeContext context)
    {
        var correlation = EvaluateCorrelation(rawEvent, context);
        var behaviorCounted = correlation.IsStrongSampleCorrelation;
        var processId = PrimaryProcessId(rawEvent);
        var path = PrimaryPath(rawEvent);
        var commandLine = PrimaryCommandLine(rawEvent);
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = CollectorSource,
            ["collectorSource"] = CollectorSource,
            ["collectorMode"] = "bounded-windows-event-log-query",
            ["channelKey"] = rawEvent.TargetChannel.Key,
            ["channel"] = rawEvent.Channel,
            ["windowsEventLogChannel"] = rawEvent.Channel,
            ["providerName"] = rawEvent.ProviderName,
            ["providerNamesExpected"] = JoinDistinct(rawEvent.TargetChannel.ProviderNames),
            ["eventId"] = rawEvent.EventId.ToString(CultureInfo.InvariantCulture),
            ["windowsEventId"] = rawEvent.EventId.ToString(CultureInfo.InvariantCulture),
            ["eventName"] = rawEvent.EventName,
            ["eventRecordId"] = rawEvent.RecordId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            ["computer"] = rawEvent.Computer,
            ["phase"] = ToPhaseLabel(phase),
            ["capturePhase"] = ToPhaseLabel(phase),
            ["collectionName"] = CollectionName,
            ["evidenceRole"] = EvidenceRole,
            ["eventOrigin"] = "windows-event-log",
            ["surfaceKey"] = rawEvent.TargetChannel.SurfaceKey,
            ["fallbackSurfaceKey"] = rawEvent.TargetChannel.SurfaceKey,
            ["semanticEventTags"] = rawEvent.TargetChannel.SemanticTags,
            ["fallbackOwner"] = "WindowsBehaviorEventLogProbe",
            ["r0CoverageGap"] = rawEvent.TargetChannel.R0CoverageGap,
            ["behaviorBoundary"] = BehaviorBoundary(rawEvent.TargetChannel.SurfaceKey),
            ["noiseBoundary"] = NoiseBoundary(rawEvent.TargetChannel.SurfaceKey),
            ["noiseClass"] = NoiseClass(rawEvent.TargetChannel.SurfaceKey),
            ["severity"] = EventSeverity(rawEvent, behaviorCounted),
            ["severityMeaning"] = "operator triage priority for this evidence row, not a standalone malicious verdict",
            ["behaviorCounted"] = behaviorCounted.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["sampleBehaviorCandidate"] = behaviorCounted.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["sampleBehaviorCandidateReason"] = behaviorCounted ? "strong-eventlog-sample-correlation" : "not-strongly-correlated-to-sample-process",
            ["sampleCorrelationStatus"] = correlation.Status,
            ["sampleCorrelationReason"] = correlation.Reason,
            ["sampleCorrelationField"] = correlation.FieldName,
            ["sampleCorrelationStrength"] = behaviorCounted ? "strong" : "none",
            ["strongSampleCorrelation"] = behaviorCounted.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["targetEventIds"] = string.Join(",", rawEvent.TargetChannel.EventIds.Select(static id => id.ToString(CultureInfo.InvariantCulture))),
            ["maxEventsPerChannelRead"] = MaxEventsPerChannelRead.ToString(CultureInfo.InvariantCulture),
            ["wevtutilTimeoutMilliseconds"] = CommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
            ["task"] = rawEvent.Task,
            ["opcode"] = rawEvent.Opcode,
            ["keywords"] = rawEvent.Keywords,
            ["providerExecutionProcessId"] = rawEvent.ProviderExecutionProcessId,
            ["providerExecutionThreadId"] = rawEvent.ProviderExecutionThreadId,
            ["renderedMessage"] = rawEvent.RenderedMessage,
            ["zhMessage"] = EventZhMessage(rawEvent),
            ["zhHint"] = EventZhHint(rawEvent, correlation)
        };

        if (!behaviorCounted)
        {
            data["nonbehavior"] = "true";
            data["notSampleBehavior"] = "true";
        }

        AddIfNotEmpty(data, "processImagePath", path);
        AddIfNotEmpty(data, "imagePath", path);
        AddIfNotEmpty(data, "commandLine", commandLine);
        AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(data, "rootCommandLine", context.RootCommandLine);
        AddCommonAliases(data, rawEvent);
        AddRawEventData(data, rawEvent.EventData);

        return new SandboxEvent
        {
            EventType = NormalizedEventType(rawEvent.TargetChannel.SurfaceKey, rawEvent.EventId),
            Timestamp = rawEvent.TimestampUtc,
            Source = CollectorSource,
            ProcessName = SafeFileName(path),
            ProcessId = processId,
            Path = path,
            CommandLine = string.IsNullOrWhiteSpace(commandLine) ? null : commandLine,
            Data = data
        };
    }

    private static SampleCorrelation EvaluateCorrelation(RawWindowsEvent rawEvent, GuestProbeContext context)
    {
        if (context.RootProcessId is not null && CandidateProcessIds(rawEvent).Contains(context.RootProcessId.Value))
        {
            return new SampleCorrelation(true, "correlated", "pid-matched-root-process", "processId");
        }

        foreach (var field in CandidateTextFields(rawEvent))
        {
            if (TextReferencesSample(field.Value, context.SamplePath))
            {
                return new SampleCorrelation(true, "correlated", "text-referenced-sample-path", field.Key);
            }
        }

        return new SampleCorrelation(false, "uncorrelated", "no-strong-sample-pid-or-path-match", string.Empty);
    }

    private static IEnumerable<int> CandidateProcessIds(RawWindowsEvent rawEvent)
    {
        foreach (var name in new[] { "ProcessID", "ProcessId", "EnginePID", "ExecutionProcessID", "NewProcessId" })
        {
            var parsed = ParseProcessId(Field(rawEvent.EventData, name));
            if (parsed is not null)
            {
                yield return parsed.Value;
            }
        }

        var executionPid = ParseProcessId(rawEvent.ProviderExecutionProcessId);
        if (executionPid is not null)
        {
            yield return executionPid.Value;
        }
    }

    private static IEnumerable<KeyValuePair<string, string>> CandidateTextFields(RawWindowsEvent rawEvent)
    {
        foreach (var name in new[] { "ImagePath", "ServiceFileName", "ActionName", "HostApplication", "ContextInfo", "CommandLine", "ScriptBlockText", "Path" })
        {
            var value = Field(rawEvent.EventData, name);
            if (!string.IsNullOrWhiteSpace(value))
            {
                yield return new KeyValuePair<string, string>(name, value);
            }
        }

        if (!string.IsNullOrWhiteSpace(rawEvent.RenderedMessage))
        {
            yield return new KeyValuePair<string, string>("renderedMessage", rawEvent.RenderedMessage);
        }
    }

    private static int? PrimaryProcessId(RawWindowsEvent rawEvent)
    {
        return ParseProcessId(FirstNonEmpty(
            Field(rawEvent.EventData, "ProcessID"),
            Field(rawEvent.EventData, "ProcessId"),
            Field(rawEvent.EventData, "EnginePID"),
            rawEvent.ProviderExecutionProcessId));
    }

    private static string PrimaryPath(RawWindowsEvent rawEvent)
    {
        return FirstNonEmpty(
            Field(rawEvent.EventData, "ImagePath"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Image Path", "Service File Name"),
            Field(rawEvent.EventData, "Path"),
            Field(rawEvent.EventData, "ActionName"));
    }

    private static string PrimaryCommandLine(RawWindowsEvent rawEvent)
    {
        return FirstNonEmpty(
            Field(rawEvent.EventData, "HostApplication"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Host Application", "Command Line"),
            Field(rawEvent.EventData, "ContextInfo"),
            Field(rawEvent.EventData, "ScriptBlockText"));
    }

    private static int? ParseProcessId(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value, "-", StringComparison.Ordinal))
        {
            return null;
        }

        var text = value.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexValue)
                ? hexValue
                : null;
        }

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var decimalValue)
            ? decimalValue
            : null;
    }

    private static bool TextReferencesSample(string value, string samplePath)
    {
        if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(samplePath))
        {
            return false;
        }

        if (value.Contains(samplePath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var fileName = SafeFileName(samplePath);
        var directory = SafeDirectoryName(samplePath);
        return !string.IsNullOrWhiteSpace(fileName) &&
            !string.IsNullOrWhiteSpace(directory) &&
            value.Contains(fileName, StringComparison.OrdinalIgnoreCase) &&
            value.Contains(directory, StringComparison.OrdinalIgnoreCase);
    }

    private static void AddCommonAliases(Dictionary<string, string> data, RawWindowsEvent rawEvent)
    {
        AddIfNotEmpty(data, "serviceName", FirstNonEmpty(
            Field(rawEvent.EventData, "ServiceName"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Service Name")));
        AddIfNotEmpty(data, "serviceImagePath", FirstNonEmpty(
            Field(rawEvent.EventData, "ImagePath"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Image Path")));
        AddIfNotEmpty(data, "serviceStartType", FirstNonEmpty(
            Field(rawEvent.EventData, "StartType"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Start Type")));
        AddIfNotEmpty(data, "serviceAccount", FirstNonEmpty(
            Field(rawEvent.EventData, "AccountName"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Service Account", "Account Name")));
        AddIfNotEmpty(data, "serviceControl", FirstNonEmpty(
            Field(rawEvent.EventData, "param2"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Control")));
        AddIfNotEmpty(data, "taskName", FirstNonEmpty(
            Field(rawEvent.EventData, "TaskName"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Task Name")));
        AddIfNotEmpty(data, "taskActionName", Field(rawEvent.EventData, "ActionName"));
        AddIfNotEmpty(data, "taskUserName", Field(rawEvent.EventData, "UserName"));
        AddIfNotEmpty(data, "taskInstanceId", Field(rawEvent.EventData, "InstanceId"));
        AddIfNotEmpty(data, "powerShellCommandName", Field(rawEvent.EventData, "CommandName"));
        AddIfNotEmpty(data, "powerShellCommandType", Field(rawEvent.EventData, "CommandType"));
        AddIfNotEmpty(data, "powerShellScriptBlockId", Field(rawEvent.EventData, "ScriptBlockId"));
        AddIfNotEmpty(data, "powerShellScriptBlockText", Field(rawEvent.EventData, "ScriptBlockText"));
        AddIfNotEmpty(data, "powerShellHostApplication", Field(rawEvent.EventData, "HostApplication"));
        AddIfNotEmpty(data, "powerShellContextInfo", Field(rawEvent.EventData, "ContextInfo"));
    }

    private static void AddRawEventData(Dictionary<string, string> data, Dictionary<string, string> rawData)
    {
        foreach (var (key, value) in rawData.OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            AddIfNotEmpty(data, $"eventData.{key}", value);
        }
    }

    private static bool IsBehaviorCounted(SandboxEvent evt)
    {
        return evt.Data.TryGetValue("behaviorCounted", out var value) &&
            string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
    }

    private static string ClassifyQueryFailure(BoundedCommandResult result)
    {
        if (result.TimedOut)
        {
            return "queryTimedOut";
        }

        if (!string.IsNullOrWhiteSpace(result.ExceptionType))
        {
            return "collectorLaunchFailed";
        }

        var text = $"{result.StandardError}\n{result.StandardOutput}\n{result.Message}";
        if (ContainsAny(text, "Access is denied", "拒绝访问", "0x5"))
        {
            return "eventLogAccessDenied";
        }

        if (ContainsAny(text, "The specified channel could not be found", "channel could not be found", "The channel", "找不到指定"))
        {
            return "eventLogChannelUnavailable";
        }

        if (ContainsAny(text, "The specified query is invalid", "query is invalid"))
        {
            return "eventLogQueryInvalid";
        }

        return "eventLogQueryFailed";
    }

    private static bool IsPermanentUnavailableReason(string reason)
    {
        return string.Equals(reason, "eventLogAccessDenied", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(reason, "eventLogChannelUnavailable", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(reason, "collectorLaunchFailed", StringComparison.OrdinalIgnoreCase);
    }

    private static SandboxEvent CreateStartedEvent(ProbePhase phase, GuestProbeContext context)
    {
        var evt = CreateDiagnosticEvent("eventlog.behavior.collection.started", phase, context, null, "started");
        evt.Data["collectorMode"] = "bounded-windows-event-log-query";
        evt.Data["targetChannelKeys"] = JoinDistinct(TargetChannels.Select(static channel => channel.Key));
        evt.Data["targetChannels"] = JoinDistinct(TargetChannels.Select(static channel => channel.ChannelName));
        evt.Data["targetEventIdsByChannel"] = JoinDistinct(TargetChannels.Select(static channel => $"{channel.ChannelName}={string.Join('/', channel.EventIds)}"));
        evt.Data["maxEventsPerChannelRead"] = MaxEventsPerChannelRead.ToString(CultureInfo.InvariantCulture);
        evt.Data["wevtutilTimeoutMilliseconds"] = CommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        evt.Data["behaviorBoundary"] = "collection start/readiness rows are nonbehavior; target event rows require strong sample PID/path/text correlation before behaviorCounted=true";
        evt.Data["noiseBoundary"] = "service/task/powershell operational logs can contain benign OS or administrator activity inside the time window; uncorrelated rows remain context";
        evt.Data["severity"] = "info";
        evt.Data["zhMessage"] = "Windows 定向行为事件日志补采已启用，将有界读取服务、计划任务和 PowerShell Operational 事件。";
        evt.Data["zhHint"] = "该 started 行是采集健康信息，不代表样本行为；实际事件仍需强 PID、路径或命令文本关联才会 behaviorCounted=true。";
        return evt;
    }

    private static SandboxEvent CreateSkippedEvent(
        ProbePhase phase,
        GuestProbeContext context,
        string reason,
        TargetChannel? channel,
        BoundedCommandResult? result,
        DateTimeOffset? querySinceUtc)
    {
        var evt = CreateDiagnosticEvent("eventlog.behavior.skipped", phase, context, channel, reason);
        AddCommandResultData(evt.Data, result);
        AddIfNotEmpty(evt.Data, "querySinceUtc", querySinceUtc?.ToString("O", CultureInfo.InvariantCulture));
        evt.Data["severity"] = "info";
        evt.Data["zhMessage"] = "Windows 定向行为事件日志补采不可用或本通道查询失败，Guest Agent 已记录诊断并继续其它采集。";
        evt.Data["zhHint"] = EventLogFailureZhHint(reason);
        return evt;
    }

    private static SandboxEvent CreateParseFailedEvent(
        ProbePhase phase,
        GuestProbeContext context,
        TargetChannel channel,
        XmlException exception,
        string output)
    {
        var evt = CreateDiagnosticEvent("eventlog.behavior.parse_failed", phase, context, channel, "renderedXmlParseFailed");
        evt.Data["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name;
        evt.Data["message"] = exception.Message;
        evt.Data["outputSnippet"] = Truncate(output, 2048);
        evt.Data["severity"] = "info";
        evt.Data["zhMessage"] = "Windows 定向事件日志查询返回的 XML 片段无法完全解析，已保留诊断信息。";
        evt.Data["zhHint"] = "该问题只影响对应 Event Log 补采通道；样本执行、R0 JSONL 和其它 guest 探针会继续运行。";
        return evt;
    }

    private static SandboxEvent CreateQuerySummaryEvent(
        ProbePhase phase,
        GuestProbeContext context,
        DateTimeOffset querySinceUtc,
        DateTimeOffset queryStartedUtc,
        int emittedEventCount,
        int correlatedEventCount,
        int skippedChannelCount,
        int failedChannelCount,
        bool possiblyTruncated)
    {
        var evt = CreateDiagnosticEvent("eventlog.behavior.query.summary", phase, context, null, "queryCompleted");
        evt.Data["querySinceUtc"] = querySinceUtc.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["queryStartedUtc"] = queryStartedUtc.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["emittedEventCount"] = emittedEventCount.ToString(CultureInfo.InvariantCulture);
        evt.Data["sampleCorrelatedEventCount"] = correlatedEventCount.ToString(CultureInfo.InvariantCulture);
        evt.Data["uncorrelatedEventCount"] = Math.Max(0, emittedEventCount - correlatedEventCount).ToString(CultureInfo.InvariantCulture);
        evt.Data["skippedChannelCount"] = skippedChannelCount.ToString(CultureInfo.InvariantCulture);
        evt.Data["failedChannelCount"] = failedChannelCount.ToString(CultureInfo.InvariantCulture);
        evt.Data["possiblyTruncated"] = possiblyTruncated.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["targetChannels"] = JoinDistinct(TargetChannels.Select(static channel => channel.ChannelName));
        evt.Data["severity"] = "info";
        evt.Data["zhMessage"] = emittedEventCount == 0
            ? "本阶段未读取到目标 Windows 行为事件日志记录；这可能表示没有相关行为、通道未启用或日志不可读。"
            : "本阶段 Windows 定向行为事件日志补采查询完成。";
        evt.Data["zhHint"] = "summary 不代表样本行为；只有 sampleCorrelationStatus=correlated 且 behaviorCounted=true 的 eventlog.* 行才计入行为候选。";
        return evt;
    }

    private static SandboxEvent CreateDiagnosticEvent(
        string eventType,
        ProbePhase phase,
        GuestProbeContext context,
        TargetChannel? channel,
        string reason)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = CollectorSource,
            ["collectorSource"] = CollectorSource,
            ["phase"] = ToPhaseLabel(phase),
            ["capturePhase"] = ToPhaseLabel(phase),
            ["collectionName"] = CollectionName,
            ["evidenceRole"] = EvidenceRole,
            ["collectionHealth"] = "true",
            ["nonfatal"] = "true",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["sampleBehaviorCandidate"] = "false",
            ["behaviorCounted"] = "false",
            ["reason"] = reason
        };

        if (channel is not null)
        {
            data["channelKey"] = channel.Key;
            data["channel"] = channel.ChannelName;
            data["windowsEventLogChannel"] = channel.ChannelName;
            data["providerNamesExpected"] = JoinDistinct(channel.ProviderNames);
            data["surfaceKey"] = channel.SurfaceKey;
            data["semanticEventTags"] = channel.SemanticTags;
            data["targetEventIds"] = string.Join(",", channel.EventIds.Select(static id => id.ToString(CultureInfo.InvariantCulture)));
        }

        AddIfNotEmpty(data, "samplePath", context.SamplePath);
        AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);

        return new SandboxEvent
        {
            EventType = eventType,
            Source = CollectorSource,
            ProcessName = SafeFileName(context.RootProcessPath ?? context.SamplePath),
            ProcessId = context.RootProcessId,
            Path = context.SamplePath,
            CommandLine = context.RootCommandLine,
            Data = data
        };
    }

    private static void AddCommandResultData(Dictionary<string, string> data, BoundedCommandResult? result)
    {
        if (result is null)
        {
            return;
        }

        data["command"] = result.FileName;
        data["arguments"] = result.Arguments;
        data["exitCode"] = result.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        data["timedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        data["timeoutMilliseconds"] = result.Timeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        AddIfNotEmpty(data, "exceptionType", result.ExceptionType);
        AddIfNotEmpty(data, "message", result.Message);
        AddIfNotEmpty(data, "stderr", Truncate(result.StandardError, 2048));
        AddIfNotEmpty(data, "stdout", Truncate(result.StandardOutput, 2048));
    }

    private static string EventLogFailureZhHint(string reason)
    {
        return reason switch
        {
            "nonWindowsGuest" => "Windows Event Log 补采仅在 Windows guest 中可用；其它平台会跳过该通道。",
            "eventLogAccessDenied" => "读取该 Event Log 通道需要权限；这是可降级采集问题，不代表样本行为。",
            "eventLogChannelUnavailable" => "当前系统未启用或未暴露该 Event Log 通道；Guest Agent 会继续其它采集。",
            "queryTimedOut" => "Event Log 查询超过内部超时；已中止该次查询以避免阻塞其它探针。",
            "collectorLaunchFailed" => "无法启动 wevtutil；请检查 Windows 系统工具路径和执行权限。",
            "eventLogQueryInvalid" => "Event Log XPath 查询被系统拒绝；请检查目标事件 ID 查询兼容性。",
            _ => "该诊断只影响定向 Windows Event Log 补采；样本执行、R0 JSONL 和其它 guest 探针会继续运行。"
        };
    }

    private static string NormalizedEventType(string surfaceKey, int eventId)
    {
        return surfaceKey switch
        {
            "service-control-manager" => eventId switch
            {
                7045 => "eventlog.service.installed",
                7040 => "eventlog.service.start_type_changed",
                7035 => "eventlog.service.control_sent",
                _ => "eventlog.service.event"
            },
            "scheduled-task-operational" => eventId switch
            {
                106 => "eventlog.scheduled_task.registered",
                140 => "eventlog.scheduled_task.updated",
                141 => "eventlog.scheduled_task.deleted",
                142 => "eventlog.scheduled_task.disabled",
                200 => "eventlog.scheduled_task.action_started",
                201 => "eventlog.scheduled_task.action_completed",
                _ => "eventlog.scheduled_task.event"
            },
            "powershell-operational" => eventId switch
            {
                4103 => "eventlog.powershell.module_command",
                4104 => "eventlog.powershell.script_block",
                _ => "eventlog.powershell.event"
            },
            _ => "eventlog.behavior.event"
        };
    }

    private static string NormalizedEventName(string surfaceKey, int eventId)
    {
        return surfaceKey switch
        {
            "service-control-manager" => eventId switch
            {
                7045 => "service-installed",
                7040 => "service-start-type-changed",
                7035 => "service-control-sent",
                _ => "service-control-manager-event"
            },
            "scheduled-task-operational" => eventId switch
            {
                106 => "scheduled-task-registered",
                140 => "scheduled-task-updated",
                141 => "scheduled-task-deleted",
                142 => "scheduled-task-disabled",
                200 => "scheduled-task-action-started",
                201 => "scheduled-task-action-completed",
                _ => "scheduled-task-event"
            },
            "powershell-operational" => eventId switch
            {
                4103 => "powershell-module-command",
                4104 => "powershell-script-block",
                _ => "powershell-operational-event"
            },
            _ => "windows-eventlog-event"
        };
    }

    private static string EventSeverity(RawWindowsEvent rawEvent, bool behaviorCounted)
    {
        if (!behaviorCounted)
        {
            return "info";
        }

        return rawEvent.EventId switch
        {
            7045 or 106 or 140 or 4104 => "medium",
            _ => "low"
        };
    }

    private static string BehaviorBoundary(string surfaceKey)
    {
        return surfaceKey switch
        {
            "service-control-manager" => "SCM rows are behavior candidates only when service image/path text references the sample; otherwise service inventory diffs provide stronger attribution.",
            "scheduled-task-operational" => "Task Scheduler rows are noisy temporal context unless task action/name text is sample-correlated or paired with scheduled_task.* inventory diffs.",
            "powershell-operational" => "PowerShell rows are behavior candidates only when ProcessID, HostApplication, ContextInfo, or script text strongly references the sample.",
            _ => "Event Log rows require strong sample PID/path/text correlation before behaviorCounted=true."
        };
    }

    private static string NoiseBoundary(string surfaceKey)
    {
        return surfaceKey switch
        {
            "service-control-manager" => "Benign installers and OS maintenance can create or reconfigure services; uncorrelated rows remain nonbehavior context.",
            "scheduled-task-operational" => "Windows and application maintenance tasks can emit frequent action start/complete rows; registration/update/delete are higher signal than execution-only rows.",
            "powershell-operational" => "PowerShell Operational logging can include administrator or management activity in the same session; strong sample correlation is required before counting.",
            _ => "Time-window Event Log records can include unrelated guest activity and must be correlated before counting."
        };
    }

    private static string NoiseClass(string surfaceKey)
    {
        return surfaceKey switch
        {
            "scheduled-task-operational" => "medium-noise-operational-log",
            "powershell-operational" => "policy-dependent-command-log",
            "service-control-manager" => "low-volume-system-log",
            _ => "bounded-eventlog-context"
        };
    }

    private static string EventZhMessage(RawWindowsEvent rawEvent)
    {
        return rawEvent.EventId switch
        {
            7045 => "System 日志记录了服务安装事件，可补充 R0/注册表对服务持久化的观测。",
            7040 => "System 日志记录了服务启动类型变更事件。",
            7035 => "System 日志记录了向服务发送控制请求的事件。",
            106 => "TaskScheduler Operational 日志记录了计划任务注册事件。",
            140 => "TaskScheduler Operational 日志记录了计划任务更新事件。",
            141 => "TaskScheduler Operational 日志记录了计划任务删除事件。",
            142 => "TaskScheduler Operational 日志记录了计划任务禁用事件。",
            200 => "TaskScheduler Operational 日志记录了计划任务动作开始执行事件。",
            201 => "TaskScheduler Operational 日志记录了计划任务动作执行完成事件。",
            4103 => "PowerShell Operational 日志记录了模块命令调用，可补充脚本执行、注册表、服务、任务或网络命令上下文。",
            4104 => "PowerShell Operational 日志记录了脚本块文本，可补充凭据、注册表、文件和网络相关命令上下文。",
            _ => "Windows 定向行为事件日志记录了一条目标事件。"
        };
    }

    private static string EventZhHint(RawWindowsEvent rawEvent, SampleCorrelation correlation)
    {
        if (correlation.IsStrongSampleCorrelation)
        {
            return "该 Event Log 行已通过 PID、路径或命令文本与样本强关联，behaviorCounted=true；仍建议结合 process.tree、service/scheduled_task/registry diff 和 R0 JSONL 复核归因。";
        }

        return rawEvent.TargetChannel.SurfaceKey switch
        {
            "scheduled-task-operational" => "计划任务 Operational 日志可能包含系统维护任务；该行未强关联样本，默认 behaviorCounted=false，可与 scheduled_task.* diff 互证。",
            "service-control-manager" => "服务控制日志缺少可靠发起进程字段时容易只有时间窗口关联；该行未强关联样本，默认 behaviorCounted=false，可与 service.* diff 互证。",
            "powershell-operational" => "PowerShell 行未与样本 PID/路径/宿主命令强关联，默认 behaviorCounted=false；可用于解释脚本日志覆盖情况。",
            _ => "该 Event Log 行未与样本强关联，默认 behaviorCounted=false；可作为补充上下文。"
        };
    }

    private static string ExtractRenderedFieldValue(string renderedMessage, params string[] labels)
    {
        if (string.IsNullOrWhiteSpace(renderedMessage))
        {
            return string.Empty;
        }

        var lines = renderedMessage.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n');
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            foreach (var label in labels)
            {
                if (!trimmed.StartsWith(label, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var colon = trimmed.IndexOf(':', StringComparison.Ordinal);
                if (colon >= 0 && colon + 1 < trimmed.Length)
                {
                    return trimmed[(colon + 1)..].Trim();
                }
            }
        }

        return string.Empty;
    }

    private static string Field(Dictionary<string, string> data, string key)
    {
        return data.TryGetValue(key, out var value) ? value : string.Empty;
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

    private static string JoinDistinct(IEnumerable<string> values)
    {
        return string.Join(
            "; ",
            values
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    private static bool ContainsAny(string value, params string[] needles)
    {
        return needles.Any(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    private static string Truncate(string value, int maxLength)
    {
        return string.IsNullOrEmpty(value) || value.Length <= maxLength ? value : value[..maxLength];
    }

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

    private static string? SafeDirectoryName(string path)
    {
        try
        {
            return string.IsNullOrWhiteSpace(path) ? null : Path.GetDirectoryName(path);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static string ToPhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.AfterStart => "after-start",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString()
        };
    }

    private sealed record TargetChannel(
        string Key,
        string ChannelName,
        string[] ProviderNames,
        int[] EventIds,
        string SurfaceKey,
        string SemanticTags,
        string R0CoverageGap);

    private sealed record RawWindowsEvent(
        TargetChannel TargetChannel,
        int EventId,
        string EventName,
        long? RecordId,
        DateTimeOffset TimestampUtc,
        string ProviderName,
        string Computer,
        string Channel,
        string Task,
        string Opcode,
        string Keywords,
        string ProviderExecutionProcessId,
        string ProviderExecutionThreadId,
        Dictionary<string, string> EventData,
        string RenderedMessage);

    private readonly record struct SampleCorrelation(
        bool IsStrongSampleCorrelation,
        string Status,
        string Reason,
        string FieldName);
}
