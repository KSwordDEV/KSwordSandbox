using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Best-effort Windows Security log collector for privilege/security audit
/// events that are not directly observable from the R0 callback stream.
/// Inputs are the probe phase and sample context; processing queries the
/// Security channel through wevtutil with a bounded result count; the method
/// returns normalized Windows Event Log events and non-fatal diagnostics.
/// </summary>
internal sealed class SecurityEventLogProbe : IGuestProbe
{
    private const string ChannelName = "Security";
    private const string ProviderName = "Microsoft-Windows-Security-Auditing";
    private const string CollectorSource = "windowsEventLog";
    private const string CollectionName = "security-event-log";
    private const string EvidenceRole = "privilege-security-audit-event";
    private const int MaxEventsPerRead = 512;
    private const int MaxFieldValueLength = 2048;
    private const int MaxRenderedMessageLength = 1024;
    private const int MaxAuditPolicySnippetLength = 4096;
    private const int MaxProviderManifestSnippetLength = 2048;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan AuditPolicyCommandTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan ProviderManifestCommandTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan QueryOverlap = TimeSpan.FromSeconds(2);
    private static readonly int[] ProcessAccessEventIds = [4656, 4663, 4690];

    private static readonly int[] TargetEventIds =
    [
        4656, // A handle to an object was requested; filtered to Process objects after parsing.
        4663, // An attempt was made to access an object; filtered to Process objects after parsing.
        4672, // Special privileges assigned to new logon.
        4673, // A privileged service was called.
        4674, // An operation was attempted on a privileged object.
        4688, // A new process has been created.
        4689, // A process has exited.
        4690, // An attempt was made to duplicate a handle to an object; filtered to Process objects after parsing.
        4696, // A primary token was assigned to process.
        4697, // A service was installed in the system.
        4698, // A scheduled task was created.
        4699, // A scheduled task was deleted.
        4700, // A scheduled task was enabled.
        4701, // A scheduled task was disabled.
        4702, // A scheduled task was updated.
        4703, // A token right was adjusted.
        4704, // A user right was assigned.
        4705, // A user right was removed.
        4717, // System security access was granted to an account.
        4718, // System security access was removed from an account.
        4719, // System audit policy was changed.
        4720, // A user account was created.
        4722, // A user account was enabled.
        4723, // An attempt was made to change an account password.
        4724, // An attempt was made to reset an account password.
        4725, // A user account was disabled.
        4726, // A user account was deleted.
        4728, // A member was added to a security-enabled global group.
        4729, // A member was removed from a security-enabled global group.
        4732, // A member was added to a security-enabled local group.
        4733, // A member was removed from a security-enabled local group.
        4738, // A user account was changed.
        4739 // Domain policy was changed.
    ];

    private readonly HashSet<string> seenEventKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> correlatedProcessIds = [];
    private readonly HashSet<string> observedLogonIds = new(StringComparer.OrdinalIgnoreCase);

    private static readonly (uint Mask, string Name)[] ProcessAccessRights =
    [
        (0x0001u, "PROCESS_TERMINATE"),
        (0x0002u, "PROCESS_CREATE_THREAD"),
        (0x0004u, "PROCESS_SET_SESSIONID"),
        (0x0008u, "PROCESS_VM_OPERATION"),
        (0x0010u, "PROCESS_VM_READ"),
        (0x0020u, "PROCESS_VM_WRITE"),
        (0x0040u, "PROCESS_DUP_HANDLE"),
        (0x0080u, "PROCESS_CREATE_PROCESS"),
        (0x0100u, "PROCESS_SET_QUOTA"),
        (0x0200u, "PROCESS_SET_INFORMATION"),
        (0x0400u, "PROCESS_QUERY_INFORMATION"),
        (0x0800u, "PROCESS_SUSPEND_RESUME"),
        (0x1000u, "PROCESS_QUERY_LIMITED_INFORMATION"),
        (0x2000u, "PROCESS_SET_LIMITED_INFORMATION"),
        (0x00010000u, "DELETE"),
        (0x00020000u, "READ_CONTROL"),
        (0x00040000u, "WRITE_DAC"),
        (0x00080000u, "WRITE_OWNER"),
        (0x00100000u, "SYNCHRONIZE")
    ];

    private static readonly AuditPolicyExpectation[] AuditPolicyExpectations =
    [
        new("0cce9211-69ae-11d9-bed3-505054503030", "Security System Extension", "安全系统扩展", "4697", "Service installation auditing; useful when service persistence is not visible in R0 callbacks."),
        new("0cce921b-69ae-11d9-bed3-505054503030", "Special Logon", "特殊登录", "4672", "Special privilege assignment at logon; helps explain later privilege/token context."),
        new("0cce9223-69ae-11d9-bed3-505054503030", "Handle Manipulation", "句柄操作", "4656,4663,4690", "Process/object handle requests, accesses, and duplicate-handle attempts; requires object auditing/SACL for many targets."),
        new("0cce9228-69ae-11d9-bed3-505054503030", "Sensitive Privilege Use", "敏感权限使用", "4673,4674", "Privileged service/object operations; complements R0 process and registry callbacks."),
        new("0cce922b-69ae-11d9-bed3-505054503030", "Process Creation", "进程创建", "4688", "Process command line and token elevation context."),
        new("0cce922c-69ae-11d9-bed3-505054503030", "Process Termination", "进程终止", "4689", "Process exit context for short-lived children."),
        new("0cce922f-69ae-11d9-bed3-505054503030", "Audit Policy Change", "审核策略更改", "4719", "Audit policy tampering and readiness drift."),
        new("0cce9231-69ae-11d9-bed3-505054503030", "Authorization Policy Change", "授权策略更改", "4703,4704,4705,4717,4718", "Token/user-right adjustment evidence, including AdjustTokenPrivileges-style gaps."),
        new("0cce9227-69ae-11d9-bed3-505054503030", "Other Object Access Events", "其它对象访问事件", "4698,4699,4700,4701,4702", "Scheduled-task changes and other object-access events.")
    ];

    private static readonly FallbackSurfaceExpectation[] FallbackSurfaceExpectations =
    [
        new(
            "process-handle-access",
            "Process handle/object access",
            "4656,4663,4690",
            "Microsoft-Windows-Security-Auditing",
            "Handle Manipulation success auditing plus a process object SACL are normally required; useful for PROCESS_VM_*, DUP_HANDLE, and DuplicateHandle gaps."),
        new(
            "privilege-use",
            "Privilege use/logon privileges",
            "4672,4673,4674",
            "Microsoft-Windows-Security-Auditing",
            "Special Logon and Sensitive Privilege Use success auditing explain Se*Privilege context not decoded by R0 callbacks."),
        new(
            "token-adjustment",
            "Token assignment/right adjustment",
            "4696,4703,4704,4705,4717,4718",
            "Microsoft-Windows-Security-Auditing",
            "Authorization Policy Change and related Security events provide low-rate token/right mutation context."),
        new(
            "process-create-exit",
            "Process create/exit",
            "4688,4689; Kernel-Process start/stop",
            "Microsoft-Windows-Security-Auditing; Microsoft-Windows-Kernel-Process",
            "Security events add command line/token elevation when audit policy is enabled; Kernel-Process ETW provider presence is an alternate live-capture surface."),
    ];

    private static readonly Regex PrivilegeNameRegex = new(
        @"\bSe[A-Za-z0-9]+Privilege\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private DateTimeOffset? collectionStartUtc;
    private DateTimeOffset? lastQueryUtc;
    private bool permanentlyUnavailable;

    public string ProbeId => "security-event-log";

    /// <summary>
    /// Collects Windows Security audit events for the current phase.
    /// BeforeStart establishes the query watermark; after-start and after-run
    /// query recent events. Expected access/audit-policy failures become
    /// windowsEventLog diagnostics instead of throwing.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return phase == ProbePhase.BeforeStart
                ? [CreateSkippedEvent(phase, context, "nonWindowsGuest", null, null)]
                : [];
        }

        if (permanentlyUnavailable)
        {
            return [];
        }

        TrackRootProcess(context);
        if (phase == ProbePhase.BeforeStart)
        {
            collectionStartUtc = DateTimeOffset.UtcNow.Subtract(QueryOverlap);
            lastQueryUtc = null;
            seenEventKeys.Clear();
            observedLogonIds.Clear();
            return
            [
                CreateStartedEvent(phase, context),
                await CreateAuditPolicySummaryEventAsync(phase, context, cancellationToken).ConfigureAwait(false),
                await CreateFallbackSurfaceReadinessEventAsync(phase, context, cancellationToken).ConfigureAwait(false)
            ];
        }

        if (phase != ProbePhase.AfterStart && phase != ProbePhase.AfterRun && phase != ProbePhase.Cleanup)
        {
            return [];
        }

        collectionStartUtc ??= DateTimeOffset.UtcNow.Subtract(QueryOverlap);
        var querySinceUtc = (lastQueryUtc ?? collectionStartUtc.Value).Subtract(QueryOverlap);
        var queryStartedUtc = DateTimeOffset.UtcNow;
        var result = await QuerySecurityLogAsync(querySinceUtc, cancellationToken).ConfigureAwait(false);
        var events = new List<SandboxEvent>();

        if (!result.Succeeded)
        {
            var reason = ClassifyQueryFailure(result);
            var diagnostic = IsPermanentUnavailableReason(reason)
                ? CreateSkippedEvent(phase, context, reason, result, querySinceUtc)
                : CreateQueryFailedEvent(phase, context, reason, result, querySinceUtc);
            events.Add(diagnostic);
            if (IsPermanentUnavailableReason(reason))
            {
                permanentlyUnavailable = true;
            }

            return events;
        }

        var rawEvents = ParseSecurityEvents(result.StandardOutput, phase, context, events)
            .Where(IsTargetSecurityEvent)
            .Where(rawEvent => ShouldEmit(rawEvent))
            .OrderBy(rawEvent => rawEvent.TimestampUtc)
            .ThenBy(rawEvent => rawEvent.RecordId ?? long.MaxValue)
            .ToList();

        var correlatedCount = 0;
        foreach (var rawEvent in rawEvents)
        {
            var normalized = CreateSecurityEvent(rawEvent, phase, context);
            if (IsBehaviorCounted(normalized))
            {
                correlatedCount++;
            }

            events.Add(normalized);
            TrackCorrelatedEvent(rawEvent, normalized);
        }

        lastQueryUtc = queryStartedUtc;
        events.Add(CreateQuerySummaryEvent(
            phase,
            context,
            querySinceUtc,
            queryStartedUtc,
            rawEvents.Count,
            correlatedCount,
            rawEvents.Count >= MaxEventsPerRead));
        return events;
    }

    /// <summary>
    /// Runs wevtutil against the Security channel with bounded XPath queries.
    /// Inputs are the lower time bound and cancellation token; processing avoids
    /// EventData predicates because wevtutil supports only a subset of XPath,
    /// caps records, and returns a combined command result.
    /// </summary>
    private static async Task<BoundedCommandResult> QuerySecurityLogAsync(
        DateTimeOffset sinceUtc,
        CancellationToken cancellationToken)
    {
        var wevtutilPath = ResolveWevtutilPath();
        var queries = BuildSecurityXPathQueries(sinceUtc);
        var outputs = new List<string>(queries.Count);
        var displayedArguments = new List<string>(queries.Count);

        foreach (var query in queries)
        {
            var arguments = BuildWevtutilQueryArguments(query);
            var result = await BoundedProcessRunner
                .RunAsync(wevtutilPath, arguments, CommandTimeout, cancellationToken)
                .ConfigureAwait(false);
            displayedArguments.Add(result.Arguments);

            if (!result.Succeeded)
            {
                return result;
            }

            if (!string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                outputs.Add(result.StandardOutput);
            }
        }

        return new BoundedCommandResult(
            wevtutilPath,
            string.Join(" ; ", displayedArguments),
            ExitCode: 0,
            string.Join(Environment.NewLine, outputs),
            StandardError: string.Empty,
            TimedOut: false,
            ExceptionType: null,
            Message: null,
            Timeout: CommandTimeout);
    }

    /// <summary>
    /// Queries the local Advanced Audit Policy table. Inputs are the caller
    /// cancellation token; processing uses auditpol in report mode and returns
    /// a bounded command result for a collection-health event.
    /// </summary>
    private static Task<BoundedCommandResult> QueryAuditPolicyAsync(CancellationToken cancellationToken)
    {
        var auditpolPath = ResolveAuditpolPath();
        var arguments = new[]
        {
            "/get",
            "/category:*",
            "/r"
        };

        return BoundedProcessRunner.RunAsync(auditpolPath, arguments, AuditPolicyCommandTimeout, cancellationToken);
    }

    /// <summary>
    /// Queries ETW provider metadata without starting a live trace session.
    /// Inputs are a provider name and cancellation token; processing uses
    /// wevtutil provider manifest inspection; the method returns command
    /// metadata for non-behavior readiness events.
    /// </summary>
    private static Task<BoundedCommandResult> QueryProviderManifestAsync(
        string providerName,
        CancellationToken cancellationToken)
    {
        var wevtutilPath = ResolveWevtutilPath();
        var arguments = new[]
        {
            "gp",
            providerName,
            "/ge:true",
            "/gm:false"
        };

        return BoundedProcessRunner.RunAsync(wevtutilPath, arguments, ProviderManifestCommandTimeout, cancellationToken);
    }

    /// <summary>
    /// Resolves the event log command path. The input is implicit process
    /// environment state; processing prefers System32 and falls back to PATH.
    /// </summary>
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

    /// <summary>
    /// Resolves auditpol.exe. The input is implicit process environment state;
    /// processing prefers System32 and falls back to PATH.
    /// </summary>
    private static string ResolveAuditpolPath()
    {
        var systemDirectory = Environment.SystemDirectory;
        if (!string.IsNullOrWhiteSpace(systemDirectory))
        {
            var candidate = Path.Combine(systemDirectory, "auditpol.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return "auditpol.exe";
    }

    /// <summary>
    /// Builds Security channel XPath queries for targeted privilege/security
    /// event IDs. The input is a UTC lower bound; processing formats Event Log
    /// time and EventID-only System predicates so the XPath remains accepted by
    /// wevtutil; process-object filtering is performed after XML parsing.
    /// </summary>
    private static IReadOnlyList<string> BuildSecurityXPathQueries(DateTimeOffset sinceUtc)
    {
        var systemTime = sinceUtc.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        return TargetEventIds
            .Chunk(8)
            .Select(chunk =>
            {
                var eventIdPredicate = string.Join(
                    " or ",
                    chunk.Select(static id => $"EventID={id.ToString(CultureInfo.InvariantCulture)}"));
                return $"*[System[({eventIdPredicate}) and TimeCreated[@SystemTime >= '{systemTime}']]]";
            })
            .ToList();
    }

    /// <summary>
    /// Builds wevtutil qe arguments for a single XPath query.
    /// </summary>
    private static string[] BuildWevtutilQueryArguments(string query)
    {
        return
        [
            "qe",
            ChannelName,
            $"/q:{query}",
            "/f:RenderedXml",
            "/rd:true",
            $"/c:{MaxEventsPerRead.ToString(CultureInfo.InvariantCulture)}"
        ];
    }

    /// <summary>
    /// Parses the RenderedXml stream returned by wevtutil. Inputs are stdout and
    /// current phase/context; processing tolerates malformed fragments by
    /// appending a parse diagnostic; parsed raw events are returned.
    /// </summary>
    private static IReadOnlyList<RawSecurityEvent> ParseSecurityEvents(
        string xml,
        ProbePhase phase,
        GuestProbeContext context,
        List<SandboxEvent> diagnostics)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return [];
        }

        var events = new List<RawSecurityEvent>();
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

                if (XElement.ReadFrom(reader) is XElement element &&
                    TryParseSecurityEvent(element, out var rawEvent))
                {
                    events.Add(rawEvent);
                }
            }
        }
        catch (XmlException ex)
        {
            diagnostics.Add(CreateParseFailedEvent(phase, context, ex, xml));
        }

        return events;
    }

    /// <summary>
    /// Parses one Event XML element into a compact raw record.
    /// Inputs are an XElement; processing reads System/EventData/RenderingInfo
    /// with namespace-aware access; the method returns false for unsupported
    /// records.
    /// </summary>
    private static bool TryParseSecurityEvent(XElement element, out RawSecurityEvent rawEvent)
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

        var providerName = system.Element(ns + "Provider")?.Attribute("Name")?.Value ?? string.Empty;
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

        rawEvent = new RawSecurityEvent(
            eventId,
            EventName(eventId),
            recordId,
            timestampUtc,
            providerName,
            system.Element(ns + "Computer")?.Value ?? string.Empty,
            system.Element(ns + "Channel")?.Value ?? ChannelName,
            system.Element(ns + "Task")?.Value ?? string.Empty,
            system.Element(ns + "Opcode")?.Value ?? string.Empty,
            system.Element(ns + "Keywords")?.Value ?? string.Empty,
            execution?.Attribute("ProcessID")?.Value ?? string.Empty,
            execution?.Attribute("ThreadID")?.Value ?? string.Empty,
            eventData,
            Truncate(renderedMessage, MaxRenderedMessageLength));
        return true;
    }

    /// <summary>
    /// Reads named EventData/UserData fields from an event XML element.
    /// Duplicate or unnamed fields receive stable synthetic suffixes.
    /// </summary>
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

    /// <summary>
    /// Deduplicates records across overlapping phase queries. Inputs are a raw
    /// event; processing builds a record-ID key when available, otherwise a
    /// stable content signature; the method returns true once per event.
    /// </summary>
    private bool ShouldEmit(RawSecurityEvent rawEvent)
    {
        var key = rawEvent.RecordId is not null
            ? $"record:{rawEvent.RecordId.Value.ToString(CultureInfo.InvariantCulture)}"
            : $"synthetic:{rawEvent.EventId}:{rawEvent.TimestampUtc:O}:{Field(rawEvent.EventData, "ProcessId")}:{Field(rawEvent.EventData, "NewProcessId")}:{Field(rawEvent.EventData, "ProcessName")}:{Field(rawEvent.EventData, "NewProcessName")}:{Field(rawEvent.EventData, "ObjectName")}:{Field(rawEvent.EventData, "HandleId")}:{Field(rawEvent.EventData, "AccessMask")}:{Field(rawEvent.EventData, "PrivilegeList")}:{Field(rawEvent.EventData, "EnabledPrivilegeList")}:{Field(rawEvent.EventData, "DisabledPrivilegeList")}";
        return seenEventKeys.Add(key);
    }

    /// <summary>
    /// Applies filters that are intentionally not encoded in the wevtutil XPath.
    /// Inputs are parsed Security events; processing keeps all target IDs except
    /// 4656/4663/4690, which are only emitted for Process object audit rows.
    /// </summary>
    private static bool IsTargetSecurityEvent(RawSecurityEvent rawEvent)
    {
        if (!TargetEventIds.Contains(rawEvent.EventId))
        {
            return false;
        }

        if (!ProcessAccessEventIds.Contains(rawEvent.EventId))
        {
            return true;
        }

        var objectType = FirstNonEmpty(
            Field(rawEvent.EventData, "ObjectType"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Object Type"));
        return IsProcessObjectType(objectType);
    }

    /// <summary>
    /// Converts one raw Security audit record into the shared SandboxEvent
    /// schema. Inputs are raw event, phase, and sample context; processing adds
    /// event log metadata, normalized process fields, and sample-correlation
    /// flags; the method returns one event.
    /// </summary>
    private SandboxEvent CreateSecurityEvent(
        RawSecurityEvent rawEvent,
        ProbePhase phase,
        GuestProbeContext context)
    {
        var correlation = EvaluateCorrelation(rawEvent, context);
        var processId = PrimaryProcessId(rawEvent);
        var parentProcessId = ParentProcessId(rawEvent);
        var processPath = PrimaryProcessPath(rawEvent);
        var commandLine = Field(rawEvent.EventData, "CommandLine");
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = CollectorSource,
            ["collectorSource"] = CollectorSource,
            ["collectorMode"] = "windows-event-log-query",
            ["backingProvider"] = ProviderName,
            ["channel"] = rawEvent.Channel,
            ["windowsEventLogChannel"] = rawEvent.Channel,
            ["providerName"] = rawEvent.ProviderName,
            ["eventId"] = rawEvent.EventId.ToString(CultureInfo.InvariantCulture),
            ["windowsEventId"] = rawEvent.EventId.ToString(CultureInfo.InvariantCulture),
            ["securityEventName"] = rawEvent.EventName,
            ["eventRecordId"] = rawEvent.RecordId?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
            ["computer"] = rawEvent.Computer,
            ["phase"] = ToPhaseLabel(phase),
            ["capturePhase"] = ToPhaseLabel(phase),
            ["collectionName"] = CollectionName,
            ["evidenceRole"] = EvidenceRole,
            ["eventOrigin"] = "windows-security-auditing",
            ["r0CoverageGap"] = "privilege/security audit events are supplied by Windows Security auditing rather than R0 callbacks",
            ["auditDependency"] = "Requires Security log access and relevant Windows audit policy; absence is not fatal.",
            ["behaviorCounted"] = correlation.IsStrongSampleCorrelation.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["sampleBehaviorCandidate"] = correlation.IsStrongSampleCorrelation.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["sampleCorrelationStatus"] = correlation.Status,
            ["sampleCorrelationReason"] = correlation.Reason,
            ["sampleCorrelationField"] = correlation.FieldName,
            ["sampleCorrelationStrength"] = correlation.IsStrongSampleCorrelation ? "strong" : "none",
            ["strongSampleCorrelation"] = correlation.IsStrongSampleCorrelation.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["targetEventIds"] = FormatTargetEventIds(),
            ["maxEventsPerRead"] = MaxEventsPerRead.ToString(CultureInfo.InvariantCulture),
            ["wevtutilTimeoutMilliseconds"] = CommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture),
            ["task"] = rawEvent.Task,
            ["opcode"] = rawEvent.Opcode,
            ["keywords"] = rawEvent.Keywords,
            ["providerExecutionProcessId"] = rawEvent.ProviderExecutionProcessId,
            ["providerExecutionThreadId"] = rawEvent.ProviderExecutionThreadId,
            ["renderedMessage"] = rawEvent.RenderedMessage,
            ["zhMessage"] = SecurityEventZhMessage(rawEvent.EventId),
            ["zhHint"] = SecurityEventZhHint(correlation)
        };

        if (!correlation.IsStrongSampleCorrelation)
        {
            if (string.Equals(correlation.Status, "session-related", StringComparison.OrdinalIgnoreCase))
            {
                data["sampleCorrelationStrength"] = "session-only";
            }

            data["nonbehavior"] = "true";
            data["notSampleBehavior"] = "true";
            data["sampleBehaviorCandidateReason"] = "not-strongly-correlated-to-sample-process";
        }
        else
        {
            data["sampleBehaviorCandidateReason"] = "strong-security-eventlog-sample-correlation";
        }

        AddIfNotEmpty(data, "processImagePath", processPath);
        AddIfNotEmpty(data, "imagePath", processPath);
        AddIfNotEmpty(data, "commandLine", commandLine);
        AddIfNotEmpty(data, "parentProcessId", parentProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(data, "rootCommandLine", context.RootCommandLine);
        AddCommonSecurityAliases(data, rawEvent);
        AddRawEventData(data, rawEvent.EventData);

        return new SandboxEvent
        {
            EventType = NormalizedEventType(rawEvent.EventId),
            Timestamp = rawEvent.TimestampUtc,
            Source = CollectorSource,
            ProcessName = SafeFileName(processPath),
            ProcessId = processId,
            ParentProcessId = parentProcessId,
            Path = processPath,
            CommandLine = string.IsNullOrWhiteSpace(commandLine) ? null : commandLine,
            Data = data
        };
    }

    /// <summary>
    /// Adds common account, logon, privilege, service, and task aliases while
    /// retaining the raw eventData.* fields separately.
    /// </summary>
    private static void AddCommonSecurityAliases(Dictionary<string, string> data, RawSecurityEvent rawEvent)
    {
        AddIfNotEmpty(data, "subjectUserSid", Field(rawEvent.EventData, "SubjectUserSid"));
        AddIfNotEmpty(data, "subjectUserName", Field(rawEvent.EventData, "SubjectUserName"));
        AddIfNotEmpty(data, "subjectDomainName", Field(rawEvent.EventData, "SubjectDomainName"));
        AddIfNotEmpty(data, "subjectLogonId", Field(rawEvent.EventData, "SubjectLogonId"));
        AddIfNotEmpty(data, "targetUserSid", Field(rawEvent.EventData, "TargetUserSid"));
        AddIfNotEmpty(data, "targetUserName", Field(rawEvent.EventData, "TargetUserName"));
        AddIfNotEmpty(data, "targetDomainName", Field(rawEvent.EventData, "TargetDomainName"));
        AddIfNotEmpty(data, "targetLogonId", Field(rawEvent.EventData, "TargetLogonId"));
        AddIfNotEmpty(data, "privilegeList", FirstNonEmpty(
            Field(rawEvent.EventData, "PrivilegeList"),
            Field(rawEvent.EventData, "EnabledPrivilegeList"),
            Field(rawEvent.EventData, "DisabledPrivilegeList")));
        AddIfNotEmpty(data, "enabledPrivilegeList", Field(rawEvent.EventData, "EnabledPrivilegeList"));
        AddIfNotEmpty(data, "disabledPrivilegeList", Field(rawEvent.EventData, "DisabledPrivilegeList"));
        AddPrivilegeAliases(data, rawEvent);
        AddObjectAccessAliases(data, rawEvent);
        AddIfNotEmpty(data, "serviceName", Field(rawEvent.EventData, "ServiceName"));
        AddIfNotEmpty(data, "serviceFileName", Field(rawEvent.EventData, "ServiceFileName"));
        AddIfNotEmpty(data, "taskName", Field(rawEvent.EventData, "TaskName"));
        AddIfNotEmpty(data, "memberName", Field(rawEvent.EventData, "MemberName"));
        AddIfNotEmpty(data, "memberSid", Field(rawEvent.EventData, "MemberSid"));
        AddIfNotEmpty(data, "groupName", Field(rawEvent.EventData, "TargetUserName"));
    }

    /// <summary>
    /// Normalizes privilege names from structured EventData and rendered text.
    /// Event 4703 can expose enabled/disabled privilege fields with slightly
    /// different names across Windows builds; this keeps rule-facing aliases
    /// stable without relying on localized message labels.
    /// </summary>
    private static void AddPrivilegeAliases(Dictionary<string, string> data, RawSecurityEvent rawEvent)
    {
        var enabledPrivileges = ExtractPrivilegeNames(
            Field(rawEvent.EventData, "EnabledPrivilegeList"),
            Field(rawEvent.EventData, "EnabledPrivileges"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Enabled Privileges", "EnabledPrivilegeList"));
        var disabledPrivileges = ExtractPrivilegeNames(
            Field(rawEvent.EventData, "DisabledPrivilegeList"),
            Field(rawEvent.EventData, "DisabledPrivileges"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Disabled Privileges", "DisabledPrivilegeList"));
        var privilegeNames = ExtractPrivilegeNames(
                Field(rawEvent.EventData, "PrivilegeList"),
                Field(rawEvent.EventData, "PrivilegeName"),
                Field(rawEvent.EventData, "Privileges"),
                rawEvent.RenderedMessage)
            .Concat(enabledPrivileges)
            .Concat(disabledPrivileges)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (privilegeNames.Count == 0)
        {
            return;
        }

        var joinedPrivileges = string.Join("; ", privilegeNames);
        data["privilege"] = joinedPrivileges;
        data["privilegeName"] = joinedPrivileges;
        data["privilegeNames"] = joinedPrivileges;
        data["primaryPrivilegeName"] = privilegeNames[0];
        data["privilegeDisplayName"] = joinedPrivileges;
        AddIfNotEmpty(data, "enabledPrivilegeNames", JoinDistinct(enabledPrivileges));
        AddIfNotEmpty(data, "disabledPrivilegeNames", JoinDistinct(disabledPrivileges));

        if (rawEvent.EventId == 4703)
        {
            data["api"] = "AdjustTokenPrivileges";
            data["operation"] = TokenPrivilegeOperation(enabledPrivileges.Count > 0, disabledPrivileges.Count > 0);
            data["tokenPrivilegeAdjustment"] = "true";
            data["tokenPrivilegeAdjustmentSource"] = "windows-security-event-4703";
        }
    }

    /// <summary>
    /// Adds process/object access aliases that match rule and report field
    /// expectations. Access masks are decoded for Process objects so Security
    /// 4656/4663 fallback rows can expose PROCESS_VM_WRITE and related rights.
    /// </summary>
    private static void AddObjectAccessAliases(Dictionary<string, string> data, RawSecurityEvent rawEvent)
    {
        var objectType = FirstNonEmpty(
            Field(rawEvent.EventData, "ObjectType"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Object Type"));
        var objectName = FirstNonEmpty(
            Field(rawEvent.EventData, "ObjectName"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Object Name"));
        var handleId = FirstNonEmpty(
            Field(rawEvent.EventData, "HandleId"),
            Field(rawEvent.EventData, "SourceHandleId"),
            Field(rawEvent.EventData, "TargetHandleId"),
            Field(rawEvent.EventData, "NewHandleId"));
        var accessMask = FirstNonEmpty(
            Field(rawEvent.EventData, "AccessMask"),
            Field(rawEvent.EventData, "DesiredAccess"),
            Field(rawEvent.EventData, "RequestedAccess"),
            Field(rawEvent.EventData, "GrantedAccess"));
        var rawAccesses = FirstNonEmpty(
            Field(rawEvent.EventData, "AccessList"),
            Field(rawEvent.EventData, "Accesses"),
            Field(rawEvent.EventData, "AccessReason"),
            ExtractRenderedFieldValue(rawEvent.RenderedMessage, "Accesses", "Requested Accesses"));
        var decodedAccesses = IsProcessObjectType(objectType)
            ? DecodeProcessAccessMask(accessMask)
            : [];
        var accesses = JoinDistinct(
            SplitSecurityList(rawAccesses)
                .Concat(decodedAccesses)
                .Concat(string.IsNullOrWhiteSpace(accessMask) ? [] : [NormalizeAccessMask(accessMask)]));

        AddIfNotEmpty(data, "objectType", objectType);
        AddIfNotEmpty(data, "objectName", objectName);
        AddIfNotEmpty(data, "objectPath", objectName);
        AddIfNotEmpty(data, "targetObject", objectName);
        AddIfNotEmpty(data, "handleId", handleId);
        AddIfNotEmpty(data, "sourceHandleId", Field(rawEvent.EventData, "SourceHandleId"));
        AddIfNotEmpty(data, "targetHandleId", FirstNonEmpty(
            Field(rawEvent.EventData, "TargetHandleId"),
            Field(rawEvent.EventData, "NewHandleId")));
        AddIfNotEmpty(data, "sourceProcessId", Field(rawEvent.EventData, "SourceProcessId"));
        AddIfNotEmpty(data, "targetProcessId", Field(rawEvent.EventData, "TargetProcessId"));
        AddIfNotEmpty(data, "accessMask", accessMask);
        AddIfNotEmpty(data, "accesses", accesses);

        if (IsProcessObjectType(objectType))
        {
            AddIfNotEmpty(data, "targetProcess", objectName);
            AddIfNotEmpty(data, "targetProcessName", SafeFileName(objectName));
            AddIfNotEmpty(data, "targetImage", objectName);
            AddIfNotEmpty(data, "targetImagePath", objectName);
            AddIfNotEmpty(data, "requestedAccess", accesses);
            AddIfNotEmpty(data, "desiredAccess", accesses);
            AddIfNotEmpty(data, "grantedAccess", rawEvent.EventId == 4663 ? accesses : string.Empty);
            data["processAccessTelemetry"] = "true";
            data["processAccessTelemetrySource"] = rawEvent.EventId == 4656
                ? "windows-security-event-4656"
                : rawEvent.EventId == 4663
                    ? "windows-security-event-4663"
                    : rawEvent.EventId == 4690
                        ? "windows-security-event-4690"
                        : "windows-security-auditing";

            if (rawEvent.EventId == 4656)
            {
                data["operation"] = AppendOperation(data, "OpenProcess; process handle requested");
            }
            else if (rawEvent.EventId == 4663)
            {
                data["operation"] = AppendOperation(data, "OpenProcess; process object accessed");
            }
            else if (rawEvent.EventId == 4690)
            {
                data["api"] = "DuplicateHandle";
                data["operation"] = AppendOperation(data, "DuplicateHandle; process handle duplicated");
            }
        }
    }

    /// <summary>
    /// Preserves original EventData fields under eventData.* keys.
    /// </summary>
    private static void AddRawEventData(Dictionary<string, string> data, Dictionary<string, string> eventData)
    {
        foreach (var (key, value) in eventData.OrderBy(static item => item.Key, StringComparer.OrdinalIgnoreCase))
        {
            AddIfNotEmpty(data, $"eventData.{key}", value);
        }
    }

    /// <summary>
    /// Evaluates whether a Security event has a strong sample correlation.
    /// PID/image-path matches count as behavior candidates; logon-session-only
    /// matches are retained as context but do not become behaviorCounted.
    /// </summary>
    private SampleCorrelation EvaluateCorrelation(RawSecurityEvent rawEvent, GuestProbeContext context)
    {
        var processIds = CandidateProcessIds(rawEvent).ToList();
        if (context.RootProcessId is not null)
        {
            var rootPid = context.RootProcessId.Value;
            if (processIds.Contains(rootPid))
            {
                return new SampleCorrelation(true, "correlated", "pid-matched-root-process", "processId");
            }
        }

        foreach (var processId in processIds)
        {
            if (correlatedProcessIds.Contains(processId))
            {
                return new SampleCorrelation(true, "correlated", "pid-matched-known-sample-process-tree", "processId");
            }
        }

        var creatorPid = ParseProcessId(Field(rawEvent.EventData, "CreatorProcessId"));
        if (creatorPid is not null && correlatedProcessIds.Contains(creatorPid.Value))
        {
            return new SampleCorrelation(true, "correlated", "creator-pid-matched-known-sample-process-tree", "creatorProcessId");
        }

        var path = PrimaryProcessPath(rawEvent);
        if (PathMatchesSample(path, context.SamplePath) ||
            PathMatchesSample(Field(rawEvent.EventData, "NewProcessName"), context.SamplePath) ||
            PathMatchesSample(Field(rawEvent.EventData, "ProcessName"), context.SamplePath))
        {
            return new SampleCorrelation(true, "correlated", "image-path-matched-sample", "processImagePath");
        }

        var commandLine = Field(rawEvent.EventData, "CommandLine");
        if (!string.IsNullOrWhiteSpace(commandLine) &&
            commandLine.Contains(Path.GetFileName(context.SamplePath), StringComparison.OrdinalIgnoreCase) &&
            commandLine.Contains(Path.GetDirectoryName(context.SamplePath) ?? context.SamplePath, StringComparison.OrdinalIgnoreCase))
        {
            return new SampleCorrelation(true, "correlated", "command-line-contained-sample-path", "commandLine");
        }

        var logonId = FirstNonEmpty(
            Field(rawEvent.EventData, "SubjectLogonId"),
            Field(rawEvent.EventData, "TargetLogonId"));
        if (!string.IsNullOrWhiteSpace(logonId) && observedLogonIds.Contains(logonId))
        {
            return new SampleCorrelation(false, "session-related", "logon-id-seen-on-sample-correlated-event-only", "logonId");
        }

        return new SampleCorrelation(false, "uncorrelated", "no-strong-sample-pid-or-path-match", string.Empty);
    }

    /// <summary>
    /// Tracks root PID from context so later Security records can be correlated.
    /// </summary>
    private void TrackRootProcess(GuestProbeContext context)
    {
        if (context.RootProcessId is not null)
        {
            correlatedProcessIds.Add(context.RootProcessId.Value);
        }
    }

    /// <summary>
    /// Extends process/logon correlation state after a normalized event has a
    /// strong sample match.
    /// </summary>
    private void TrackCorrelatedEvent(RawSecurityEvent rawEvent, SandboxEvent normalized)
    {
        if (!IsBehaviorCounted(normalized))
        {
            return;
        }

        foreach (var processId in CandidateProcessIds(rawEvent))
        {
            correlatedProcessIds.Add(processId);
        }

        AddObservedLogonId(Field(rawEvent.EventData, "SubjectLogonId"));
        AddObservedLogonId(Field(rawEvent.EventData, "TargetLogonId"));
    }

    private void AddObservedLogonId(string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            observedLogonIds.Add(value);
        }
    }

    /// <summary>
    /// Returns all process IDs that may represent the actor or subject process.
    /// </summary>
    private static IEnumerable<int> CandidateProcessIds(RawSecurityEvent rawEvent)
    {
        foreach (var name in new[] { "NewProcessId", "ProcessId", "SourceProcessId", "TargetProcessId", "ClientProcessId" })
        {
            var parsed = ParseProcessId(Field(rawEvent.EventData, name));
            if (parsed is not null)
            {
                yield return parsed.Value;
            }
        }
    }

    private static int? PrimaryProcessId(RawSecurityEvent rawEvent)
    {
        return ParseProcessId(FirstNonEmpty(
            Field(rawEvent.EventData, "NewProcessId"),
            Field(rawEvent.EventData, "ProcessId"),
            Field(rawEvent.EventData, "SourceProcessId"),
            Field(rawEvent.EventData, "TargetProcessId"),
            Field(rawEvent.EventData, "ClientProcessId")));
    }

    private static int? ParentProcessId(RawSecurityEvent rawEvent)
    {
        return ParseProcessId(FirstNonEmpty(
            Field(rawEvent.EventData, "CreatorProcessId"),
            Field(rawEvent.EventData, "ParentProcessId")));
    }

    private static string PrimaryProcessPath(RawSecurityEvent rawEvent)
    {
        return FirstNonEmpty(
            Field(rawEvent.EventData, "NewProcessName"),
            Field(rawEvent.EventData, "ProcessName"),
            Field(rawEvent.EventData, "Application"),
            Field(rawEvent.EventData, "ServiceFileName"));
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

    private static bool PathMatchesSample(string candidate, string samplePath)
    {
        if (string.IsNullOrWhiteSpace(candidate) || string.IsNullOrWhiteSpace(samplePath))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(candidate),
                Path.GetFullPath(samplePath),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Equals(candidate, samplePath, StringComparison.OrdinalIgnoreCase);
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
            return "securityLogAccessDenied";
        }

        if (ContainsAny(text, "The specified channel could not be found", "channel could not be found", "找不到指定"))
        {
            return "securityLogChannelUnavailable";
        }

        if (ContainsAny(text, "The specified query is invalid", "query is invalid"))
        {
            return "securityLogQueryInvalid";
        }

        return "securityLogQueryFailed";
    }

    private static bool IsPermanentUnavailableReason(string reason)
    {
        return string.Equals(reason, "securityLogAccessDenied", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(reason, "securityLogChannelUnavailable", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(reason, "collectorLaunchFailed", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Creates a non-behavior readiness row for Security audit policy coverage.
    /// Inputs are phase/context; processing queries auditpol and matches
    /// target subcategory GUIDs; the method returns a health event.
    /// </summary>
    private static async Task<SandboxEvent> CreateAuditPolicySummaryEventAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        var result = await QueryAuditPolicyAsync(cancellationToken).ConfigureAwait(false);
        var evt = CreateCollectionDiagnosticEvent("security_eventlog.audit_policy.summary", phase, context, "auditPolicyReadiness");
        evt.Data["collectorMode"] = "auditpol-readiness-query";
        evt.Data["auditPolicyCommandTimeoutMilliseconds"] = AuditPolicyCommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        evt.Data["targetAuditPolicySubcategories"] = JoinDistinct(AuditPolicyExpectations.Select(static item => item.EnglishName));
        evt.Data["targetAuditPolicyGuids"] = JoinDistinct(AuditPolicyExpectations.Select(static item => item.Guid));
        evt.Data["targetSecurityEventIds"] = FormatTargetEventIds();
        evt.Data["auditPolicyReadinessRole"] = "explains whether Windows can emit Security Event Log fallback rows for R0 gaps";
        evt.Data["r0CoverageGap"] = "Privilege and token adjustment semantics are not fully decoded by R0 callbacks; Security audit policy controls the fallback evidence surface.";
        evt.Data["zhMessage"] = "已记录 Windows 高级审核策略就绪度，用于解释 Security 日志补充通道是否可能覆盖权限、令牌、进程和对象访问事件。";

        AddCommandResultData(evt.Data, result);

        if (!result.Succeeded)
        {
            evt.Data["captureState"] = "partial";
            evt.Data["status"] = "partial";
            evt.Data["reason"] = result.TimedOut ? "auditPolicyQueryTimedOut" : "auditPolicyQueryFailed";
            evt.Data["auditPolicyStatus"] = result.TimedOut ? "queryTimedOut" : "queryFailed";
            evt.Data["auditPolicyRawCsvSnippet"] = Truncate(result.StandardOutput, MaxAuditPolicySnippetLength);
            evt.Data["zhHint"] = "auditpol 查询失败不会中断采集；如果报告缺少 4656/4663/4673/4674/4703 等 Security 行，请在 guest 中手工检查高级审核策略和进程对象 SACL。";
            return evt;
        }

        var policyRows = ParseAuditPolicyRows(result.StandardOutput);
        var rowsByGuid = policyRows
            .Where(static row => !string.IsNullOrWhiteSpace(row.Guid))
            .GroupBy(static row => NormalizeGuid(row.Guid), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.OrdinalIgnoreCase);

        var observed = new List<string>();
        var enabled = new List<string>();
        var disabled = new List<string>();
        var missing = new List<string>();
        var notes = new List<string>();

        foreach (var expectation in AuditPolicyExpectations)
        {
            if (!rowsByGuid.TryGetValue(NormalizeGuid(expectation.Guid), out var row))
            {
                missing.Add($"{expectation.EnglishName} ({expectation.SecurityEventIds})");
                continue;
            }

            var label = $"{FirstNonEmpty(row.Subcategory, expectation.EnglishName)}={FirstNonEmpty(row.InclusionSetting, "unknown")}";
            observed.Add(label);
            if (LooksSuccessAuditEnabled(row.InclusionSetting))
            {
                enabled.Add($"{expectation.EnglishName} ({expectation.SecurityEventIds})");
            }
            else
            {
                disabled.Add($"{expectation.EnglishName} ({expectation.SecurityEventIds})");
                notes.Add($"{expectation.EnglishName}: {expectation.Rationale}");
            }
        }

        evt.Data["auditPolicyParsedRowCount"] = policyRows.Count.ToString(CultureInfo.InvariantCulture);
        evt.Data["auditPolicyObservedTargets"] = JoinDistinct(observed);
        evt.Data["auditPolicySuccessEnabledTargets"] = JoinDistinct(enabled);
        evt.Data["auditPolicyDisabledOrFailureOnlyTargets"] = JoinDistinct(disabled);
        evt.Data["auditPolicyMissingTargets"] = JoinDistinct(missing);
        evt.Data["auditPolicyGapNotes"] = JoinDistinct(notes);
        evt.Data["auditPolicyRawCsvSnippet"] = Truncate(result.StandardOutput, MaxAuditPolicySnippetLength);
        evt.Data["auditPolicyLocalizationNote"] = "Rows are matched by stable subcategory GUIDs; inclusion-setting text can be localized.";

        if (missing.Count == 0 && disabled.Count == 0)
        {
            evt.Data["auditPolicyStatus"] = "targetPoliciesSuccessEnabled";
            evt.Data["zhHint"] = "目标 Security 事件相关审核策略看起来已开启成功审核；仍需注意 4656/4663 进程对象访问通常还依赖对象 SACL，缺失事件不一定代表样本未访问。";
        }
        else
        {
            evt.Data["captureState"] = "partial";
            evt.Data["status"] = "partial";
            evt.Data["reason"] = "auditPolicyCoverageGap";
            evt.Data["auditPolicyStatus"] = missing.Count > 0 ? "targetPoliciesMissingOrLocalized" : "targetPoliciesNotFullySuccessEnabled";
            evt.Data["zhHint"] = "部分目标审核策略未确认开启成功审核；若需要补足 R0 无法解释的令牌/权限/句柄语义，请在快照中启用对应 Advanced Audit Policy，并对敏感进程对象配置必要 SACL。";
        }

        return evt;
    }

    private static SandboxEvent CreateStartedEvent(ProbePhase phase, GuestProbeContext context)
    {
        var evt = CreateCollectionDiagnosticEvent("security_eventlog.collection.started", phase, context, "started");
        evt.Data["targetEventIds"] = FormatTargetEventIds();
        evt.Data["maxEventsPerRead"] = MaxEventsPerRead.ToString(CultureInfo.InvariantCulture);
        evt.Data["wevtutilTimeoutMilliseconds"] = CommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        evt.Data["collectorMode"] = "windows-event-log-query";
        evt.Data["backingProvider"] = ProviderName;
        evt.Data["auditDependency"] = "Security log access plus enabled audit policy; missing access/events are non-fatal.";
        evt.Data["zhMessage"] = "Windows 安全日志补充采集已启用，将尽量读取权限、令牌、进程和安全策略相关审计事件。";
        evt.Data["zhHint"] = "该通道用于补足 R0 不直接覆盖的 4672/4703 令牌权限和 4656/4663 进程访问审计信息；若 Security 日志不可读或审计策略未开启，会记录 skipped/summary 而不中断分析。";
        return evt;
    }

    /// <summary>
    /// Creates a non-behavior readiness row describing Security/ETW fallback
    /// surfaces for known R0 semantic gaps. Inputs are phase/context; processing
    /// performs only bounded provider-manifest probes and does not start any
    /// live ETW session; the method returns one coverage-health event.
    /// </summary>
    private static async Task<SandboxEvent> CreateFallbackSurfaceReadinessEventAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        var securityProviderResult = await QueryProviderManifestAsync(ProviderName, cancellationToken).ConfigureAwait(false);
        var kernelProcessProviderResult = await QueryProviderManifestAsync("Microsoft-Windows-Kernel-Process", cancellationToken).ConfigureAwait(false);

        var evt = CreateCollectionDiagnosticEvent("security_eventlog.fallback_surface.readiness", phase, context, "fallbackSurfaceReadiness");
        evt.Data["collectorMode"] = "security-etw-readiness-query";
        evt.Data["r0CoverageGap"] = "Readiness map for process handle access, privilege use, token adjustment, and process create/exit semantics not always represented by R0 callback JSONL.";
        evt.Data["fallbackSurfaceCount"] = FallbackSurfaceExpectations.Length.ToString(CultureInfo.InvariantCulture);
        evt.Data["fallbackSurfaceKeys"] = JoinDistinct(FallbackSurfaceExpectations.Select(static item => item.SurfaceKey));
        evt.Data["fallbackSurfaceNames"] = JoinDistinct(FallbackSurfaceExpectations.Select(static item => item.SurfaceName));
        evt.Data["fallbackSecurityEventIds"] = JoinDistinct(FallbackSurfaceExpectations.Select(static item => item.SecurityEventIds));
        evt.Data["fallbackProviders"] = JoinDistinct(FallbackSurfaceExpectations.Select(static item => item.ProviderSurface));
        evt.Data["fallbackSurfaceNotes"] = JoinDistinct(FallbackSurfaceExpectations.Select(static item => $"{item.SurfaceName}: {item.ReadinessNote}"));
        evt.Data["etwLiveCaptureEnabled"] = "false";
        evt.Data["etwLiveCaptureReason"] = "readiness-only probe; no trace session is started";
        evt.Data["manifestQueryTimeoutMilliseconds"] = ProviderManifestCommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        evt.Data["securityProviderManifestStatus"] = ProviderManifestStatus(securityProviderResult);
        evt.Data["kernelProcessProviderManifestStatus"] = ProviderManifestStatus(kernelProcessProviderResult);
        evt.Data["securityProviderManifestSnippet"] = Truncate(securityProviderResult.StandardOutput, MaxProviderManifestSnippetLength);
        evt.Data["kernelProcessProviderManifestSnippet"] = Truncate(kernelProcessProviderResult.StandardOutput, MaxProviderManifestSnippetLength);
        evt.Data["securityProviderCommand"] = $"{securityProviderResult.FileName} {securityProviderResult.Arguments}";
        evt.Data["kernelProcessProviderCommand"] = $"{kernelProcessProviderResult.FileName} {kernelProcessProviderResult.Arguments}";
        evt.Data["surface.processHandleAccess"] = "Security 4656/4663/4690; requires Handle Manipulation success auditing and target process SACL; emitted rows remain nonbehavior unless sample-correlated.";
        evt.Data["surface.privilegeUse"] = "Security 4672/4673/4674; requires Special Logon/Sensitive Privilege Use success auditing; emitted rows remain nonbehavior unless sample-correlated.";
        evt.Data["surface.tokenAdjustment"] = "Security 4696/4703/4704/4705/4717/4718; requires Authorization Policy Change or related policy auditing; emitted rows remain nonbehavior unless sample-correlated.";
        evt.Data["surface.processCreateExit"] = "Security 4688/4689 and Kernel-Process ETW provider metadata; current implementation reads Security log only and records ETW provider readiness.";
        evt.Data["sampleBehaviorCandidateReason"] = "readiness-only-fallback-surface-map";
        evt.Data["zhMessage"] = "已记录 Security/ETW 补充面就绪度，用于说明 R0 未完全覆盖的进程句柄、权限、令牌和进程生命周期语义可由哪些低风险通道补足。";

        AddCommandResultSummary(evt.Data, "securityProvider", securityProviderResult);
        AddCommandResultSummary(evt.Data, "kernelProcessProvider", kernelProcessProviderResult);

        if (!securityProviderResult.Succeeded || !kernelProcessProviderResult.Succeeded)
        {
            evt.Data["captureState"] = "partial";
            evt.Data["status"] = "partial";
            evt.Data["reason"] = "fallbackSurfacePartiallyUnavailable";
            evt.Data["zhHint"] = "一个或多个 ETW/EventLog provider manifest 查询失败；这只影响就绪度说明，不会启动 ETW 抓取，也不代表样本行为。Security 事件是否真正出现仍取决于日志权限、审核策略和样本强关联。";
        }
        else
        {
            evt.Data["zhHint"] = "Provider manifest 可查询仅说明补充面存在；实时 ETW 抓取未启用，Security 事件仍只有在强样本关联时才 behaviorCounted=true。";
        }

        return evt;
    }

    private static SandboxEvent CreateSkippedEvent(
        ProbePhase phase,
        GuestProbeContext context,
        string reason,
        BoundedCommandResult? result,
        DateTimeOffset? querySinceUtc)
    {
        var evt = CreateCollectionDiagnosticEvent("security_eventlog.skipped", phase, context, reason);
        AddCommandResultData(evt.Data, result);
        AddIfNotEmpty(evt.Data, "querySinceUtc", querySinceUtc?.ToString("O", CultureInfo.InvariantCulture));
        evt.Data["zhMessage"] = "Windows 安全日志补充采集不可用，Guest Agent 已跳过该通道且不会中断分析。";
        evt.Data["zhHint"] = SecurityEventLogFailureZhHint(reason);
        return evt;
    }

    private static SandboxEvent CreateQueryFailedEvent(
        ProbePhase phase,
        GuestProbeContext context,
        string reason,
        BoundedCommandResult result,
        DateTimeOffset querySinceUtc)
    {
        var evt = CreateCollectionDiagnosticEvent("security_eventlog.query_failed", phase, context, reason);
        AddCommandResultData(evt.Data, result);
        evt.Data["querySinceUtc"] = querySinceUtc.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["zhMessage"] = "Windows 安全日志查询失败；该错误会作为采集诊断保留，不会中断样本分析。";
        evt.Data["zhHint"] = SecurityEventLogFailureZhHint(reason);
        return evt;
    }

    private static SandboxEvent CreateParseFailedEvent(
        ProbePhase phase,
        GuestProbeContext context,
        XmlException exception,
        string output)
    {
        var evt = CreateCollectionDiagnosticEvent("security_eventlog.parse_failed", phase, context, "renderedXmlParseFailed");
        evt.Data["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name;
        evt.Data["message"] = exception.Message;
        evt.Data["outputSnippet"] = Truncate(output, 2048);
        evt.Data["zhMessage"] = "Windows 安全日志查询返回的 XML 片段无法完全解析，已保留诊断信息。";
        evt.Data["zhHint"] = "请查看 outputSnippet/exceptionType/message；该问题只影响安全日志补充通道，不会阻止其它 Guest/R0 事件写出。";
        return evt;
    }

    private static SandboxEvent CreateQuerySummaryEvent(
        ProbePhase phase,
        GuestProbeContext context,
        DateTimeOffset querySinceUtc,
        DateTimeOffset queryStartedUtc,
        int emittedEventCount,
        int correlatedEventCount,
        bool possiblyTruncated)
    {
        var evt = CreateCollectionDiagnosticEvent("security_eventlog.query.summary", phase, context, "queryCompleted");
        evt.Data["querySinceUtc"] = querySinceUtc.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["queryStartedUtc"] = queryStartedUtc.ToString("O", CultureInfo.InvariantCulture);
        evt.Data["emittedEventCount"] = emittedEventCount.ToString(CultureInfo.InvariantCulture);
        evt.Data["sampleCorrelatedEventCount"] = correlatedEventCount.ToString(CultureInfo.InvariantCulture);
        evt.Data["uncorrelatedEventCount"] = Math.Max(0, emittedEventCount - correlatedEventCount).ToString(CultureInfo.InvariantCulture);
        evt.Data["maxEventsPerRead"] = MaxEventsPerRead.ToString(CultureInfo.InvariantCulture);
        evt.Data["possiblyTruncated"] = possiblyTruncated.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["targetEventIds"] = FormatTargetEventIds();
        evt.Data["zhMessage"] = emittedEventCount == 0
            ? "本阶段未读取到目标 Windows 安全日志事件；这可能表示没有相关行为、审计策略未开启或日志不可读。"
            : "本阶段 Windows 安全日志补充查询完成。";
        evt.Data["zhHint"] = "summary 不代表样本行为；只有 sampleCorrelationStatus=correlated 且 behaviorCounted=true 的安全日志事件才计入样本行为候选。";
        return evt;
    }

    private static SandboxEvent CreateCollectionDiagnosticEvent(
        string eventType,
        ProbePhase phase,
        GuestProbeContext context,
        string reason)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = CollectorSource,
            ["collectorSource"] = CollectorSource,
            ["channel"] = ChannelName,
            ["windowsEventLogChannel"] = ChannelName,
            ["providerName"] = ProviderName,
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

    private static void AddCommandResultSummary(Dictionary<string, string> data, string prefix, BoundedCommandResult result)
    {
        data[$"{prefix}.exitCode"] = result.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        data[$"{prefix}.timedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        data[$"{prefix}.succeeded"] = result.Succeeded.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        data[$"{prefix}.timeoutMilliseconds"] = result.Timeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        AddIfNotEmpty(data, $"{prefix}.exceptionType", result.ExceptionType);
        AddIfNotEmpty(data, $"{prefix}.message", result.Message);
        AddIfNotEmpty(data, $"{prefix}.stderr", Truncate(result.StandardError, 1024));
    }

    private static string ProviderManifestStatus(BoundedCommandResult result)
    {
        if (result.Succeeded)
        {
            return "manifestQueryable";
        }

        if (result.TimedOut)
        {
            return "manifestQueryTimedOut";
        }

        if (!string.IsNullOrWhiteSpace(result.ExceptionType))
        {
            return "manifestCollectorLaunchFailed";
        }

        var text = $"{result.StandardError}\n{result.StandardOutput}\n{result.Message}";
        if (ContainsAny(text, "not found", "could not find", "cannot find", "找不到指定"))
        {
            return "manifestProviderMissing";
        }

        if (ContainsAny(text, "Access is denied", "拒绝访问", "0x5"))
        {
            return "manifestAccessDenied";
        }

        return "manifestQueryFailed";
    }

    private static string NormalizedEventType(int eventId)
    {
        return eventId switch
        {
            4672 => "security.privilege.special_logon",
            4656 => "security.process.access_requested",
            4663 => "security.process.accessed",
            4673 => "security.privilege.service_called",
            4674 => "security.privilege.object_operation",
            4688 => "security.process.created",
            4689 => "security.process.exited",
            4690 => "security.process.handle_duplicated",
            4696 => "security.token.assigned",
            4697 => "security.service.installed",
            4698 => "security.scheduled_task.created",
            4699 => "security.scheduled_task.deleted",
            4700 => "security.scheduled_task.enabled",
            4701 => "security.scheduled_task.disabled",
            4702 => "security.scheduled_task.updated",
            4703 => "security.privilege.token_adjusted",
            4704 => "security.user_right.assigned",
            4705 => "security.user_right.removed",
            4717 => "security.system_security_access.granted",
            4718 => "security.system_security_access.removed",
            4719 => "security.audit_policy.changed",
            4720 => "security.account.created",
            4722 => "security.account.enabled",
            4723 => "security.account.password_change_attempted",
            4724 => "security.account.password_reset_attempted",
            4725 => "security.account.disabled",
            4726 => "security.account.deleted",
            4728 => "security.group_member.added",
            4729 => "security.group_member.removed",
            4732 => "security.local_group_member.added",
            4733 => "security.local_group_member.removed",
            4738 => "security.account.changed",
            4739 => "security.domain_policy.changed",
            _ => "security.audit.event"
        };
    }

    private static string EventName(int eventId)
    {
        return eventId switch
        {
            4672 => "special-privileges-assigned-to-new-logon",
            4656 => "process-handle-requested",
            4663 => "process-object-accessed",
            4673 => "privileged-service-called",
            4674 => "privileged-object-operation-attempted",
            4688 => "process-created",
            4689 => "process-exited",
            4690 => "process-handle-duplicated",
            4696 => "primary-token-assigned",
            4697 => "service-installed",
            4698 => "scheduled-task-created",
            4699 => "scheduled-task-deleted",
            4700 => "scheduled-task-enabled",
            4701 => "scheduled-task-disabled",
            4702 => "scheduled-task-updated",
            4703 => "token-right-adjusted",
            4704 => "user-right-assigned",
            4705 => "user-right-removed",
            4717 => "system-security-access-granted",
            4718 => "system-security-access-removed",
            4719 => "audit-policy-changed",
            4720 => "account-created",
            4722 => "account-enabled",
            4723 => "account-password-change-attempted",
            4724 => "account-password-reset-attempted",
            4725 => "account-disabled",
            4726 => "account-deleted",
            4728 => "global-group-member-added",
            4729 => "global-group-member-removed",
            4732 => "local-group-member-added",
            4733 => "local-group-member-removed",
            4738 => "account-changed",
            4739 => "domain-policy-changed",
            _ => "security-audit-event"
        };
    }

    private static string SecurityEventZhMessage(int eventId)
    {
        return eventId switch
        {
            4672 => "Windows 安全日志记录了新登录会话获得特殊权限的事件。",
            4656 => "Windows 安全日志记录了进程对象句柄请求事件，可作为 R0 进程访问权限观测的补充。",
            4663 => "Windows 安全日志记录了进程对象访问事件，可作为 R0 进程访问权限观测的补充。",
            4688 => "Windows 安全日志记录了进程创建事件，可补充命令行、令牌提升类型等审计字段。",
            4689 => "Windows 安全日志记录了进程退出事件，可补充用户态/R0 进程生命周期证据。",
            4690 => "Windows 安全日志记录了进程对象句柄复制事件，可补充 DuplicateHandle/跨进程句柄语义。",
            4703 => "Windows 安全日志记录了令牌权限调整事件，这是 R0 回调通常无法直接解释的权限行为。",
            4673 or 4674 => "Windows 安全日志记录了特权服务或特权对象访问事件。",
            4696 => "Windows 安全日志记录了主令牌分配到进程的事件。",
            4697 => "Windows 安全日志记录了服务安装事件。",
            >= 4698 and <= 4702 => "Windows 安全日志记录了计划任务变更事件。",
            4704 or 4705 or 4717 or 4718 or 4719 => "Windows 安全日志记录了用户权限或审计策略变更事件。",
            >= 4720 and <= 4739 => "Windows 安全日志记录了账户或安全组变更事件。",
            _ => "Windows 安全日志记录了权限/安全相关审计事件。"
        };
    }

    private static string SecurityEventZhHint(SampleCorrelation correlation)
    {
        return correlation.IsStrongSampleCorrelation
            ? "该安全日志事件已通过样本 PID、子进程 PID 或镜像路径强关联，behaviorCounted=true；仍建议结合 process.tree、R0 JSONL 与 eventData.* 字段复核归因。"
            : "该安全日志事件未与样本 PID/路径强关联，默认 behaviorCounted=false；可用于解释权限审计背景或判断 Security 日志覆盖情况。";
    }

    private static string SecurityEventLogFailureZhHint(string reason)
    {
        return reason switch
        {
            "nonWindowsGuest" => "Windows Security Event Log 仅在 Windows guest 中可用；其它平台会跳过该补充通道。",
            "securityLogAccessDenied" => "读取 Security 日志通常需要管理员权限或事件日志读取权限；这属于预期的可降级情况，请不要视为样本行为。",
            "securityLogChannelUnavailable" => "当前系统未暴露 Security 事件通道；Guest Agent 会继续保留其它采集结果。",
            "queryTimedOut" => "Security 日志查询超过内部超时；已中止该次查询以避免阻塞其它探针。",
            "collectorLaunchFailed" => "无法启动 wevtutil；请检查 Windows 系统工具路径和执行权限。",
            "securityLogQueryInvalid" => "Security 日志 XPath 查询被系统拒绝；请检查目标事件 ID 查询兼容性。",
            _ => "该诊断只影响 Windows 安全日志补充通道；样本执行、R0 JSONL 和其它 guest 探针会继续运行。"
        };
    }

    private static string TokenPrivilegeOperation(bool hasEnabledPrivileges, bool hasDisabledPrivileges)
    {
        if (hasEnabledPrivileges && hasDisabledPrivileges)
        {
            return "AdjustTokenPrivileges; privilege enabled; privilege disabled";
        }

        if (hasEnabledPrivileges)
        {
            return "AdjustTokenPrivileges; privilege enabled; enable privilege";
        }

        if (hasDisabledPrivileges)
        {
            return "AdjustTokenPrivileges; privilege disabled; disable privilege";
        }

        return "AdjustTokenPrivileges; privilege adjusted";
    }

    private static string AppendOperation(Dictionary<string, string> data, string operation)
    {
        return data.TryGetValue("operation", out var existing) && !string.IsNullOrWhiteSpace(existing)
            ? JoinDistinct([existing, operation])
            : operation;
    }

    private static IReadOnlyList<string> ExtractPrivilegeNames(params string?[] values)
    {
        var privileges = new List<string>();
        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            foreach (Match match in PrivilegeNameRegex.Matches(value))
            {
                if (match.Success && !string.IsNullOrWhiteSpace(match.Value))
                {
                    privileges.Add(match.Value);
                }
            }

            foreach (var token in SplitSecurityList(value))
            {
                if (token.StartsWith("Se", StringComparison.OrdinalIgnoreCase) &&
                    token.EndsWith("Privilege", StringComparison.OrdinalIgnoreCase))
                {
                    privileges.Add(token);
                }
            }
        }

        return privileges
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IReadOnlyList<string> SplitSecurityList(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return value
            .Replace("\r", "\n", StringComparison.Ordinal)
            .Split(['\n', '\t', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static item => item.Trim())
            .Where(static item => !string.IsNullOrWhiteSpace(item) && !string.Equals(item, "-", StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
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

    private static IReadOnlyList<AuditPolicyRow> ParseAuditPolicyRows(string csv)
    {
        if (string.IsNullOrWhiteSpace(csv))
        {
            return [];
        }

        var lines = csv
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(static line => !string.IsNullOrWhiteSpace(line))
            .ToList();
        if (lines.Count == 0)
        {
            return [];
        }

        var header = ParseCsvLine(lines[0]);
        var subcategoryIndex = HeaderIndex(header, "Subcategory", fallback: 2);
        var guidIndex = HeaderIndex(header, "Subcategory GUID", fallback: 3);
        var inclusionIndex = HeaderIndex(header, "Inclusion Setting", fallback: 4);
        var exclusionIndex = HeaderIndex(header, "Exclusion Setting", fallback: 5);
        var maxIndex = Math.Max(Math.Max(subcategoryIndex, guidIndex), Math.Max(inclusionIndex, exclusionIndex));
        var rows = new List<AuditPolicyRow>();

        foreach (var line in lines.Skip(1))
        {
            var fields = ParseCsvLine(line);
            if (fields.Count <= maxIndex)
            {
                continue;
            }

            var guid = NormalizeGuid(fields[guidIndex]);
            if (string.IsNullOrWhiteSpace(guid) || !LooksLikeGuid(guid))
            {
                continue;
            }

            rows.Add(new AuditPolicyRow(
                fields[subcategoryIndex].Trim(),
                guid,
                fields[inclusionIndex].Trim(),
                exclusionIndex < fields.Count ? fields[exclusionIndex].Trim() : string.Empty));
        }

        return rows;
    }

    private static int HeaderIndex(IReadOnlyList<string> header, string name, int fallback)
    {
        for (var index = 0; index < header.Count; index++)
        {
            if (string.Equals(header[index].Trim(), name, StringComparison.OrdinalIgnoreCase))
            {
                return index;
            }
        }

        return fallback;
    }

    private static IReadOnlyList<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new System.Text.StringBuilder();
        var quoted = false;

        for (var index = 0; index < line.Length; index++)
        {
            var ch = line[index];
            if (ch == '"')
            {
                if (quoted && index + 1 < line.Length && line[index + 1] == '"')
                {
                    current.Append('"');
                    index++;
                }
                else
                {
                    quoted = !quoted;
                }

                continue;
            }

            if (ch == ',' && !quoted)
            {
                fields.Add(current.ToString());
                current.Clear();
                continue;
            }

            current.Append(ch);
        }

        fields.Add(current.ToString());
        return fields;
    }

    private static bool LooksSuccessAuditEnabled(string inclusionSetting)
    {
        if (string.IsNullOrWhiteSpace(inclusionSetting))
        {
            return false;
        }

        var value = inclusionSetting.Trim();
        return value.Contains("Success", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("成功", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeGuid(string value)
    {
        return value
            .Trim()
            .Trim('{', '}')
            .ToLowerInvariant();
    }

    private static bool LooksLikeGuid(string value)
    {
        return Guid.TryParse(value, out _);
    }

    private static string ExtractRenderedFieldValue(string renderedMessage, params string[] labels)
    {
        if (string.IsNullOrWhiteSpace(renderedMessage))
        {
            return string.Empty;
        }

        var lines = renderedMessage.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            var trimmed = lines[index].Trim();
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

                var collected = new List<string>();
                for (var next = index + 1; next < lines.Length; next++)
                {
                    var candidate = lines[next].Trim();
                    if (string.IsNullOrWhiteSpace(candidate))
                    {
                        if (collected.Count > 0)
                        {
                            break;
                        }

                        continue;
                    }

                    if (candidate.Contains(':', StringComparison.Ordinal) && !candidate.StartsWith("Se", StringComparison.OrdinalIgnoreCase))
                    {
                        break;
                    }

                    collected.Add(candidate);
                }

                return JoinDistinct(collected);
            }
        }

        return string.Empty;
    }

    private static bool IsProcessObjectType(string value)
    {
        return string.Equals(value, "Process", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "Process Object", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<string> DecodeProcessAccessMask(string accessMask)
    {
        if (!TryParseUInt32(accessMask, out var mask))
        {
            return [];
        }

        var names = new List<string> { NormalizeAccessMask(accessMask) };
        if ((mask & 0x001F0FFFu) == 0x001F0FFFu || (mask & 0x001FFFFFu) == 0x001FFFFFu)
        {
            names.Add("PROCESS_ALL_ACCESS");
        }

        foreach (var (rightMask, name) in ProcessAccessRights)
        {
            if ((mask & rightMask) == rightMask)
            {
                names.Add(name);
            }
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string NormalizeAccessMask(string accessMask)
    {
        return TryParseUInt32(accessMask, out var mask)
            ? $"0x{mask:x}"
            : accessMask;
    }

    private static bool TryParseUInt32(string value, out uint parsed)
    {
        parsed = 0;
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value.Trim(), "-", StringComparison.Ordinal))
        {
            return false;
        }

        var text = value.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed);
        }

        return uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed);
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

    private static string FormatTargetEventIds()
    {
        return string.Join(",", TargetEventIds.Select(static id => id.ToString(CultureInfo.InvariantCulture)));
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
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value[..maxLength];
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

    private sealed record RawSecurityEvent(
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

    private sealed record SampleCorrelation(
        bool IsStrongSampleCorrelation,
        string Status,
        string Reason,
        string FieldName);

    private readonly record struct AuditPolicyExpectation(
        string Guid,
        string EnglishName,
        string ZhName,
        string SecurityEventIds,
        string Rationale);

    private readonly record struct FallbackSurfaceExpectation(
        string SurfaceKey,
        string SurfaceName,
        string SecurityEventIds,
        string ProviderSurface,
        string ReadinessNote);

    private readonly record struct AuditPolicyRow(
        string Subcategory,
        string Guid,
        string InclusionSetting,
        string ExclusionSetting);
}
