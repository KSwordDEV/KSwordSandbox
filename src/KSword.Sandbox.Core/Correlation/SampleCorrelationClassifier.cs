using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Correlation;

/// <summary>
/// Adds conservative sample-attribution metadata to normalized sandbox events.
/// Inputs are the complete event stream and submitted sample path; processing
/// builds a small process/network context and labels events as confirmed,
/// probable, environment, or unknown; the returned events preserve raw evidence
/// while downgrading uncorrelated noise out of the behavior lane.
/// </summary>
public static class SampleCorrelationClassifier
{
    private static readonly TimeSpan PcapAttributionGrace = TimeSpan.FromSeconds(2);

    private static readonly string[] CollectionEventTypePrefixes =
    [
        "agent.",
        "probe.",
        "r0collector.",
        "artifact.",
        "guest.events.",
        "live.events.",
        "report.",
        "hyperv.runbook.",
        "vmware.runbook.",
        "qemu.runbook.",
        "environment.",
        "security_eventlog.audit_policy.",
        "collection-health."
    ];

    private static readonly string[] SystemProcessNames =
    [
        "system",
        "idle",
        "registry",
        "secure system",
        "memory compression",
        "smss",
        "csrss",
        "wininit",
        "winlogon",
        "services",
        "lsass",
        "lsaiso",
        "svchost",
        "fontdrvhost",
        "dwm",
        "spoolsv",
        "taskhostw",
        "runtimebroker",
        "sihost",
        "ctfmon",
        "audiodg",
        "wmiprvse",
        "wmiapsrv",
        "dllhost",
        "conhost",
        "msmpeng",
        "nissrv",
        "securityhealthservice",
        "searchindexer",
        "searchhost",
        "startmenuexperiencehost",
        "textinputhost",
        "shellexperiencehost",
        "applicationframehost",
        "sppsvc"
    ];

    private static readonly string[] KnownWindowsServiceNames =
    [
        "bits",
        "cdpsvc",
        "dps",
        "eventlog",
        "ssdpsrv",
        "wpdbusenum",
        "semgrsvc",
        "dosvc",
        "wsearch",
        "windefend",
        "wuauserv",
        "schedule",
        "lmhosts",
        "dnscache",
        "nlasvc",
        "netprofm"
    ];

    private static readonly string[] DefenderProcessNames =
    [
        "msmpeng",
        "nissrv",
        "securityhealthservice",
        "mpcmdrun",
        "smartscreen",
        "sense",
        "sgrmbroker"
    ];

    // These Windows-native commands are routinely launched by the guest
    // probes and shell setup.  A System32 image/known signed binary doing
    // local discovery is retained as evidence, but it must not become sample
    // behavior merely because its PID or command line appears in the sample
    // process tree.  Higher-signal semantics (persistence, injection,
    // defense evasion, download/execute, or explicit malicious network data)
    // bypass this baseline guard below.
    private static readonly string[] BenignWindowsDiscoveryUtilityNames =
    [
        "arp",
        "getmac",
        "hostname",
        "ipconfig",
        "nbtstat",
        "netstat",
        "nslookup",
        "pathping",
        "route",
        "systeminfo",
        "tasklist",
        "whoami"
    ];

    private static readonly string[] NormalInteractiveGuiProcessNamePrefixes =
    [
        "notepad"
    ];

    private static readonly string[] UserWritablePathHints =
    [
        @"\users\",
        @"\appdata\",
        @"\temp\",
        @"\downloads\",
        @"\desktop\",
        @"\programdata\",
        @"\public\",
        @"\perflogs\",
        @"\windows\temp\",
        @"\windows\tasks\",
        @"\windows\system32\tasks\",
        @"\kswordsandbox\incoming\",
        @"\kswordsandbox\out\",
        "%temp%",
        "%appdata%",
        "%localappdata%",
        "%programdata%",
        "%public%"
    ];

    private static readonly string[] SystemPathHints =
    [
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
        @"\windows\servicing\",
        @"\windows\systemresources\",
        @"\program files\windows defender\",
        @"\programdata\microsoft\windows defender\",
        @"\programdata\microsoft\windows defender advanced threat protection\"
    ];

    /// <summary>
    /// Applies sample-correlation metadata to a complete event batch.
    /// </summary>
    public static List<SandboxEvent> Apply(IEnumerable<SandboxEvent> events, string? samplePath)
    {
        // Classification only reads the incoming event and creates a new
        // Data dictionary when it adds correlation fields.  Cloning every
        // input dictionary here before that second copy doubled the peak
        // memory footprint for large R0 JSONL imports (hundreds of thousands
        // of rows) without changing the caller-visible result.  Keep the
        // source events immutable by contract and retain the one copy made by
        // ClassifyEvent for enriched rows.
        var eventList = events as IReadOnlyList<SandboxEvent> ?? events.ToList();
        var context = BuildContext(eventList, samplePath);
        var classified = new List<SandboxEvent>(eventList.Count);

        foreach (var evt in eventList)
        {
            classified.Add(ClassifyEvent(evt, context));
        }

        return classified;
    }

    private static SandboxEvent ClassifyEvent(SandboxEvent evt, CorrelationContext context)
    {
        if (ShouldSkipCorrelation(evt))
        {
            return evt;
        }

        var data = new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase);
        var enriched = EnrichWithKnownProcess(evt, data, context);
        var disposition = DetermineDisposition(enriched, data, context);
        ApplyDisposition(data, disposition);
        return enriched with { Data = data };
    }

    private static CorrelationDisposition DetermineDisposition(
        SandboxEvent evt,
        Dictionary<string, string> data,
        CorrelationContext context)
    {
        // Guest event-log probes conservatively mark rows as nonbehavior when
        // they cannot see the full process tree in real time.  Once the host
        // has reconstructed a child PID under the submitted sample, that
        // stale marker must not block the stronger host-side correlation.
        if (IsSampleCorrelatedWindowsEventLogEvidence(evt, data, context))
        {
            return CorrelationDisposition.Confirmed(
                "eventlog-process-id-matched-sample-process-tree",
                "processId",
                NormalBehaviorBoundary(evt, data, context),
                true);
        }

        // A PCAP packet has no owning PID.  Keep the ownerless row eligible
        // only when an independent ETW/R0/guest runtime row joins the same
        // target to the submitted sample process.  Lifecycle/static-IOC
        // overlap alone remains retained evidence, not sample behavior.
        if (IsNetworkEvidence(evt) && TryClassifyPcapCorrelation(evt, data, context, out var pcapDisposition))
        {
            return pcapDisposition;
        }

        if (IsExplicitNonBehaviorOrCollectionNoise(evt, data))
        {
            return CorrelationDisposition.Environment("explicit-nonbehavior-or-collection-noise", "behaviorCounted/nonbehavior");
        }

        if (IsCollectorOrAgentProcess(evt, data, context))
        {
            return CorrelationDisposition.Environment("row-belongs-to-sandbox-collector-or-agent", "processName");
        }

        if (IsBenignWindowsDiscoveryUtility(evt, data, context))
        {
            return CorrelationDisposition.Environment(
                "system32-signed-or-known-discovery-utility-without-high-signal-behavior",
                "processImagePath/commandLine");
        }

        if (!HasExistingStrongCorrelation(data) && IsKnownUntaintedServiceHostProcess(evt, data, context))
        {
            return CorrelationDisposition.Environment("process-row-belongs-to-untainted-windows-service-host", "processName");
        }

        if (HasExistingStrongCorrelation(data))
        {
            return CorrelationDisposition.Confirmed(
                "existing-strong-sample-correlation",
                "strongSampleCorrelation",
                NormalBehaviorBoundary(evt, data, context));
        }

        if (MatchesSampleProcess(evt, data, context))
        {
            return CorrelationDisposition.Confirmed(
                "pid-or-lineage-matched-sample-process-tree",
                "processId",
                NormalBehaviorBoundary(evt, data, context));
        }

        // A filesystem watcher has no actor PID.  Its path remains useful
        // evidence, but a common file name under AppData/ProgramData must not
        // be promoted to confirmed sample behavior merely because it contains
        // the submitted sample's basename.
        if (!IsUnattributedFileWatcherEvent(evt, data) && AnyFieldMatchesSamplePath(evt, data, context))
        {
            return CorrelationDisposition.Confirmed(
                "path-or-command-matched-submitted-sample",
                "path",
                NormalBehaviorBoundary(evt, data, context));
        }

        if (IsNetworkEvidence(evt))
        {
            return ClassifyNetworkEvidence(evt, data, context);
        }

        if (IsFileEvidence(evt))
        {
            return ClassifyFileEvidence(evt, data, context);
        }

        if (IsDriverEvidence(evt))
        {
            return ClassifyDriverEvidence(evt, data, context);
        }

        if (IsServiceOrScheduledTaskEvidence(evt))
        {
            return ClassifyServiceOrScheduledTaskEvidence(evt, data, context);
        }

        if (IsProcessEvidence(evt))
        {
            return ClassifyProcessEvidence(evt, data, context);
        }

        return CorrelationDisposition.Unchanged();
    }

    private static CorrelationDisposition ClassifyDriverEvidence(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        if (IsCollectorOrAgentProcess(evt, data, context))
        {
            return CorrelationDisposition.Environment("driver-row-belongs-to-sandbox-collector-or-agent", "processName");
        }

        var processFacts = TryGetEventProcessFacts(evt, data, context);
        var targetPath = FirstNonEmpty(
            evt.Path,
            Value(data, "path"),
            Value(data, "filePath"),
            Value(data, "imagePath"),
            Value(data, "keyPath"),
            Value(data, "objectPath"));
        var isHighSignalMutation = IsHighSignalMutation(evt, data);
        var targetsUserWritableOrPersistence = LooksUserWritableOrPersistenceTarget(targetPath, context);
        var targetsSystemOnly = LooksSystemOnlyPath(targetPath);

        if (processFacts is not null && IsDefenderOrSecurityProcess(processFacts))
        {
            return CorrelationDisposition.Environment("driver-row-belongs-to-defender-or-security-service", "processName");
        }

        if (processFacts is not null && IsKernelOrCoreSystemProcess(processFacts))
        {
            return CorrelationDisposition.Environment("driver-row-belongs-to-kernel-or-core-system-process", "processName");
        }

        if (processFacts is not null && IsKnownSystemProcess(processFacts))
        {
            return CorrelationDisposition.Environment(
                targetsSystemOnly
                    ? "driver-row-joined-known-system-process-and-system-target"
                    : "driver-row-joined-known-system-process-without-prior-sample-taint",
                "processId");
        }

        // A path alone is insufficient for R0 file/registry telemetry when
        // the Agent failed before exporting a sample PID/process tree. Keep
        // the raw row as unknown evidence rather than upgrading ambient
        // machine mutations to probable sample behavior.
        if (isHighSignalMutation && targetsUserWritableOrPersistence)
        {
            if (HasIndependentSampleEvidence(evt, targetPath, context, "mutation"))
            {
                return CorrelationDisposition.Probable("driver-mutation-targets-user-writable-or-persistence-location-with-cross-source-sample-evidence", "path", "probable-cross-source-mutation-boundary");
            }

            return CorrelationDisposition.Unknown("driver-mutation-targets-user-writable-or-persistence-location-without-cross-source-evidence", "path");
        }

        if (isHighSignalMutation && !targetsSystemOnly && !IsPathTruncated(data))
        {
            if (HasIndependentSampleEvidence(evt, targetPath, context, "mutation"))
            {
                return CorrelationDisposition.Probable("driver-mutation-has-non-system-target-with-cross-source-sample-evidence", "path", "probable-cross-source-mutation-boundary");
            }

            return CorrelationDisposition.Unknown("driver-mutation-has-non-system-target-without-cross-source-evidence", "path");
        }

        return CorrelationDisposition.Unknown("driver-row-has-no-sample-pid-path-lineage-match", "processId");
    }

    private static CorrelationDisposition ClassifyNetworkEvidence(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var ownerPid = EventProcessId(evt, data);
        if (ownerPid is null && TryGetJoinedNetworkOwnerPid(data, context, out var joinedOwner))
        {
            ownerPid = joinedOwner;
        }

        if (ownerPid is not null && context.SampleProcessIds.Contains(ownerPid.Value))
        {
            return CorrelationDisposition.Confirmed("network-owner-pid-matched-sample-process-tree", "owningProcessId");
        }

        var ownerImageOrCommand = FirstNonEmpty(
            Value(data, "ownerImagePath"),
            Value(data, "owningProcessImagePath"),
            Value(data, "processImagePath"),
            Value(data, "imagePath"),
            Value(data, "ownerCommandLine"),
            Value(data, "commandLine"));
        if (PathOrCommandMatchesSample(ownerImageOrCommand, context))
        {
            return CorrelationDisposition.Confirmed("network-owner-image-or-command-matched-submitted-sample", "owningProcessImagePath");
        }

        if (ownerPid is not null &&
            context.Processes.TryGetValue(ownerPid.Value, out var processFacts) &&
            IsKnownSystemProcess(processFacts))
        {
            return CorrelationDisposition.Environment("network-owner-pid-joined-known-system-service-process", "owningProcessId");
        }

        if (IsListenerEvent(evt))
        {
            return CorrelationDisposition.Unknown("listener-delta-has-no-sample-owner-pid-join", "owningProcessId");
        }

        return CorrelationDisposition.Unknown("network-row-has-no-sample-owner-pid-join", "owningProcessId");
    }

    private static bool TryClassifyPcapCorrelation(
        SandboxEvent evt,
        Dictionary<string, string> data,
        CorrelationContext context,
        out CorrelationDisposition disposition)
    {
        disposition = CorrelationDisposition.Unchanged();
        if (!IsPcapProtocolEvidence(evt, data) || IsRawPcapCompatibilityRow(data) ||
            IsPcapSummaryOrCollectionRow(evt, data) || IsCollectionNetworkEvidence(evt, data))
        {
            return false;
        }

        // A real owner PID or an already strong disposition is more precise
        // than timestamp/IOC corroboration. Let the normal network classifier
        // keep confirmed owner attribution instead of downgrading it.
        if (HasExistingStrongCorrelation(data) ||
            (EventProcessId(evt, data) is int ownerPid && context.SampleProcessIds.Contains(ownerPid)) ||
            (ParsePid(Value(data, "owningProcessId")) is int owningPid && context.SampleProcessIds.Contains(owningPid)))
        {
            return false;
        }

        data["pcapCorrelationAttempted"] = "true";
        data["pcapCorrelationOwnerPidAvailable"] = EventProcessId(evt, data) is not null ? "true" : "false";
        var lifecycle = context.SampleLifecycles.FirstOrDefault(window =>
            evt.Timestamp >= window.StartUtc && evt.Timestamp <= window.EndUtc);
        data["pcapCorrelationWindowMatched"] = (lifecycle is not null).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        if (lifecycle is null)
        {
            data["pcapCorrelationUncertainty"] = "capture-timestamp-outside-sample-lifecycle";
            return false;
        }

        data["pcapCorrelationWindowStartUtc"] = lifecycle.StartUtc.ToString("O", CultureInfo.InvariantCulture);
        data["pcapCorrelationWindowEndUtc"] = lifecycle.EndUtc.ToString("O", CultureInfo.InvariantCulture);

        var targets = NetworkTargets(data).ToList();
        var staticMatch = targets
            .Select(target => (Target: target, Match: FindStaticIocMatch(target, context.StaticNetworkIndicators)))
            .FirstOrDefault(pair => !string.IsNullOrWhiteSpace(pair.Match));
        var matchedIoc = staticMatch.Match;
        var dnsCorroborated = string.IsNullOrWhiteSpace(matchedIoc) && targets.Any(target => context.DnsCorroboratedTargets.Contains(target));
        if (dnsCorroborated)
        {
            matchedIoc = "dns-answer-corroboration";
        }
        data["pcapCorrelationStaticIocMatched"] = (!string.IsNullOrWhiteSpace(matchedIoc)).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        data["pcapCorrelationDnsCorroborated"] = dnsCorroborated.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        var crossSourceSampleEvidence = targets.Any(target => HasIndependentSampleEvidence(evt, target, context, "network"));
        data["pcapCorrelationCrossSourceEvidence"] = crossSourceSampleEvidence.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(matchedIoc))
        {
            data["pcapCorrelationStaticIoc"] = matchedIoc;
            if (!crossSourceSampleEvidence)
            {
                data["pcapCorrelationUncertainty"] = dnsCorroborated
                    ? "owner-pid-unavailable; lifecycle-overlap; dns-answer-corroboration-without-etw-or-r0-sample-owner"
                    : "owner-pid-unavailable; lifecycle-overlap; static-ioc-without-etw-or-r0-sample-owner";
                return false;
            }

            data["pcapCorrelationUncertainty"] = dnsCorroborated
                ? "owner-pid-unavailable; lifecycle-overlap; dns-answer-corroboration"
                : "owner-pid-unavailable; lifecycle-overlap; static-ioc-corroboration";
            disposition = CorrelationDisposition.Probable(
                dnsCorroborated
                    ? "pcap-lifecycle-overlap-dns-answer-corroboration"
                    : "pcap-lifecycle-overlap-static-ioc-corroboration",
                dnsCorroborated ? "timestamp+dnsAnswer" : "timestamp+staticIoc",
                "probable-pcap-static-ioc-boundary",
                true);
            return true;
        }

        // An ownerless DNS query is retained with an explicit uncertainty
        // marker, but it can enter the probable lane only after the same
        // target is independently joined to a sample-owned runtime row.
        if (IsPcapDnsEvidence(evt, data))
        {
            data["pcapCorrelationUncertainty"] = crossSourceSampleEvidence
                ? "owner-pid-unavailable; lifecycle-overlap; unattributed-dns-query-with-etw-or-r0-sample-corroboration"
                : "owner-pid-unavailable; lifecycle-overlap; unattributed-dns-query-without-etw-or-r0-sample-corroboration";
            data["pcapCorrelationDnsLifecycleMatched"] = "true";
            if (!crossSourceSampleEvidence)
            {
                return false;
            }

            disposition = CorrelationDisposition.Probable(
                "pcap-lifecycle-overlap-unattributed-dns",
                "timestamp+dnsLifecycle",
                "probable-pcap-dns-boundary",
                true);
            return true;
        }

        data["pcapCorrelationUncertainty"] = "owner-pid-unavailable; lifecycle-overlap; no-static-ioc-corroboration";
        return false;
    }

    private static bool IsPcapDnsEvidence(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        return evt.EventType.Equals("dns.query", StringComparison.OrdinalIgnoreCase) && !IsRawPcapCompatibilityRow(data);
    }

    private static bool IsPcapProtocolEvidence(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        return evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Value(data, "importSource"), "pcap-native", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Value(data, "sourceArtifactKind"), "PacketCapture", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Value(data, "importArtifactKind"), "PacketCapture", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRawPcapCompatibilityRow(IReadOnlyDictionary<string, string> data)
    {
        return IsTruthy(Value(data, "rawPcapCompatibilityRow")) ||
            string.Equals(Value(data, "duplicateRole"), "raw-pcap-compatibility", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPcapSummaryOrCollectionRow(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        return evt.EventType.EndsWith(".summary", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains(".parse_error", StringComparison.OrdinalIgnoreCase) ||
            TextEqualsAny(Value(data, "eventKind"), "summary", "health", "parse_error");
    }

    private static bool IsCollectionNetworkEvidence(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        if (IsTruthy(Value(data, "collectorSelfNoise")) || IsTruthy(Value(data, "collectionHealth")) ||
            ContainsAny(Value(data, "sourceComponent"), "collector", "winrm", "ksword.sandbox.agent"))
        {
            return true;
        }

        var destinationPort = ParsePort(FirstNonEmpty(
            Value(data, "destinationPort"),
            Value(data, "destPort"),
            Value(data, "serverPort"),
            Value(data, "remotePort")));
        if (destinationPort is 5985 or 5986)
        {
            return true;
        }

        var endpoint = FirstNonEmpty(
            Value(data, "destinationEndpoint"),
            Value(data, "remoteEndpoint"),
            Value(data, "destinationIp"),
            Value(data, "remoteAddress"));
        return IsLoopbackAddress(endpoint) &&
            (destinationPort is 5985 or 5986 || ContainsAny(Value(data, "serviceHint"), "winrm", "wsman"));
    }

    private static IEnumerable<string> NetworkTargets(IReadOnlyDictionary<string, string> data)
    {
        var values = new[]
        {
            Value(data, "queryName"), Value(data, "qname"), Value(data, "domain"), Value(data, "dnsQueryName"),
            Value(data, "sni"), Value(data, "serverName"), Value(data, "tlsSni"), Value(data, "tls.server_name"),
            Value(data, "host"), Value(data, "hostname"), Value(data, "httpHost"), Value(data, "authority"),
            Value(data, "url"), Value(data, "requestUrl"), Value(data, "httpUrl"),
            Value(data, "destinationIp"), Value(data, "destIp"), Value(data, "dstIp"), Value(data, "serverIp"), Value(data, "remoteAddress"),
            Value(data, "answerAddress"), Value(data, "dnsAnswerIps"), Value(data, "answersNormalized"), Value(data, "networkTarget")
        };

        foreach (var value in values.Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            foreach (var candidate in value!.Split(new[] { ',', ';', '|', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var normalized = NormalizeNetworkTarget(candidate);
                if (!string.IsNullOrWhiteSpace(normalized) && !IsLoopbackAddress(normalized))
                {
                    yield return normalized;
                }
            }
        }
    }

    private static string FindStaticIocMatch(string target, IReadOnlySet<string> indicators)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return string.Empty;
        }

        foreach (var indicator in indicators)
        {
            if (string.Equals(target, indicator, StringComparison.OrdinalIgnoreCase) ||
                (!IsIpLiteral(target) && target.EndsWith("." + indicator, StringComparison.OrdinalIgnoreCase)))
            {
                return indicator;
            }
        }

        return string.Empty;
    }

    private static string NormalizeNetworkTarget(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var candidate = value.Trim().Trim('"', '\'', '[', ']', '(', ')', ',', ';');
        if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            candidate = uri.Host;
        }
        else if (candidate.Contains('/', StringComparison.Ordinal) && Uri.TryCreate("http://" + candidate, UriKind.Absolute, out var authority))
        {
            candidate = authority.Host;
        }

        return candidate.TrimEnd('.').ToLowerInvariant();
    }

    private static bool IsIpLiteral(string value) => System.Net.IPAddress.TryParse(value.Trim('[', ']'), out _);

    private static bool IsLoopbackAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var candidate = NormalizeNetworkTarget(value);
        return candidate is "localhost" or "127.0.0.1" or "::1";
    }

    private static bool IsCollectionNetworkTarget(string value)
    {
        return IsLoopbackAddress(value) || value is "0.0.0.0" or "::";
    }

    private static bool IsKnownCollectionNetworkTarget(string value)
    {
        var normalized = value.TrimEnd('.').ToLowerInvariant();
        return normalized is "wpad" or "wpad.localdomain" ||
            normalized.EndsWith(".microsoft.com", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".windowsupdate.com", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".msftncsi.com", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".microsoftonline.com", StringComparison.OrdinalIgnoreCase);
    }

    private static CorrelationDisposition ClassifyServiceOrScheduledTaskEvidence(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var target = FirstNonEmpty(
            Value(data, "target"),
            Value(data, "value"),
            Value(data, "imagePath"),
            Value(data, "serviceDll"),
            Value(data, "taskToRun"),
            Value(data, "registryKeyPath"),
            Value(data, "keyPath"),
            Value(data, "commandLine"),
            evt.CommandLine,
            evt.Path);

        var persistenceSurface = string.Join("|", new[]
        {
            target,
            Value(data, "keyPath"),
            Value(data, "registryKeyPath"),
            Value(data, "location"),
            Value(data, "taskName"),
            Value(data, "serviceName")
        }.Where(value => !string.IsNullOrWhiteSpace(value)));

        if (PathOrCommandMatchesSample(persistenceSurface, context))
        {
            return CorrelationDisposition.Confirmed("service-or-task-target-points-to-submitted-sample", "imagePath/taskToRun");
        }

        var actorPid = EventProcessId(evt, data);
        if (actorPid is not null && context.SampleProcessIds.Contains(actorPid.Value))
        {
            return CorrelationDisposition.Confirmed("service-or-task-actor-pid-matched-sample-process-tree", "actorProcessId");
        }

        if (LooksUserWritableOrPersistenceTarget(persistenceSurface, context))
        {
            if (HasIndependentSampleEvidence(evt, target, context, "mutation"))
            {
                return CorrelationDisposition.Probable("service-or-task-target-points-to-user-writable-location-with-cross-source-sample-evidence", "imagePath/taskToRun", "probable-cross-source-mutation-boundary");
            }

            return CorrelationDisposition.Unknown("service-or-task-target-points-to-user-writable-location-without-cross-source-evidence", "imagePath/taskToRun");
        }

        if (IsKnownWindowsServiceChange(data, persistenceSurface) || IsKnownWindowsTaskChange(data, persistenceSurface))
        {
            return CorrelationDisposition.Environment("standard-windows-service-or-task-state-drift", "serviceName/taskName");
        }

        return CorrelationDisposition.Unknown("service-or-task-diff-has-no-sample-target-or-actor-correlation", "imagePath/taskToRun");
    }

    private static CorrelationDisposition ClassifyFileEvidence(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var target = FirstNonEmpty(
            evt.Path,
            Value(data, "path"),
            Value(data, "filePath"),
            Value(data, "target"),
            Value(data, "destinationPath"),
            Value(data, "sourcePath"));
        var operation = FirstNonEmpty(
            Value(data, "operation"),
            Value(data, "operationName"),
            Value(data, "fileOperationName"),
            evt.EventType);

        var targetMatchesSample = IsUnattributedFileWatcherEvent(evt, data)
            ? ExactSamplePathMatches(target, context)
            : PathOrCommandMatchesSample(target, context);
        if (targetMatchesSample)
        {
            return CorrelationDisposition.Confirmed("file-target-points-to-submitted-sample", "path");
        }

        if (IsUnattributedFileWatcherEvent(evt, data) && IsKnownCollectorFilesystemNoise(target))
        {
            return CorrelationDisposition.Environment("filesystem-watcher-row-matches-powerShell-or-windows-collection-noise", "path");
        }

        if (LooksUserWritableOrPersistenceTarget(target, context) && IsHighSignalMutation(evt, data))
        {
            if (HasIndependentSampleEvidence(evt, target, context, "mutation"))
            {
                return CorrelationDisposition.Probable("file-mutation-targets-user-writable-location-with-cross-source-sample-evidence", "path", "probable-cross-source-mutation-boundary");
            }

            return CorrelationDisposition.Unknown("file-mutation-targets-user-writable-location-without-cross-source-evidence", "path");
        }

        if (IsHighSignalMutation(evt, data) && !LooksSystemOnlyPath(target) && !string.IsNullOrWhiteSpace(operation))
        {
            if (HasIndependentSampleEvidence(evt, target, context, "mutation"))
            {
                return CorrelationDisposition.Probable("file-mutation-has-non-system-target-with-cross-source-sample-evidence", "path", "probable-cross-source-mutation-boundary");
            }

            return CorrelationDisposition.Unknown("file-mutation-has-non-system-target-without-cross-source-evidence", "path");
        }

        return CorrelationDisposition.Unknown("file-row-has-no-sample-path-or-lineage-match", "path");
    }

    private static CorrelationDisposition ClassifyProcessEvidence(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        if (IsCollectorOrAgentProcess(evt, data, context))
        {
            return CorrelationDisposition.Environment("process-row-belongs-to-sandbox-collector-or-agent", "processName");
        }

        if (IsKnownUntaintedServiceHostProcess(evt, data, context))
        {
            return CorrelationDisposition.Environment("process-row-belongs-to-untainted-windows-service-host", "processName");
        }

        // PsiXBot-style WMI CopyEx reinvocations can start after the submitted
        // root exits and therefore lack a surviving parent-chain snapshot.
        // Preserve this narrow, high-signal candidate instead of dropping it
        // as ambient WmiPrvSE noise; it remains probable until ETW/R0 proves
        // the caller and is never promoted solely by the path.
        if (IsLikelyWmiSecondaryPayload(evt, data, context))
        {
            return CorrelationDisposition.Probable("post-exit-wmi-child-under-user-appdata-microsoft", "path/parentProcessName");
        }

        var processFacts = TryGetEventProcessFacts(evt, data, context);
        if (processFacts is not null && IsKnownSystemProcess(processFacts))
        {
            return CorrelationDisposition.Environment("process-row-joined-known-system-process-without-sample-parentage", "processId");
        }

        if (TryGetRootProcessId(data, out var rootPid) && context.SampleProcessIds.Contains(rootPid))
        {
            return CorrelationDisposition.Unknown("process-row-has-root-process-id-only-without-parent-lineage-or-path-match", "rootProcessId");
        }

        return CorrelationDisposition.Unchanged();
    }

    private static bool IsLikelyWmiSecondaryPayload(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        if (!TextEqualsAny(evt.EventType, "process.new", "process.snapshot", "process.observed"))
        {
            return false;
        }

        if (!TryGetRootProcessId(data, out var rootPid) || !context.SampleProcessIds.Contains(rootPid))
        {
            return false;
        }

        var path = FirstNonEmpty(evt.Path, Value(data, "processImagePath"), Value(data, "imagePath"));
        var parentName = FirstNonEmpty(
            Value(data, "parentProcessName"),
            Value(data, "parentImageName"),
            Value(data, "parentProcessPath"));
        return ContainsAny(path, "\\AppData\\Local\\Microsoft\\", "%APPDATA%\\Local\\Microsoft\\") &&
            ContainsAny(parentName, "WmiPrvSE", "WMIPrvSE");
    }

    private static SandboxEvent EnrichWithKnownProcess(
        SandboxEvent evt,
        Dictionary<string, string> data,
        CorrelationContext context)
    {
        var pid = EventProcessId(evt, data);
        if (pid is null || !context.Processes.TryGetValue(pid.Value, out var facts))
        {
            return evt;
        }

        AddIfMissing(data, "actorProcessId", pid.Value.ToString(CultureInfo.InvariantCulture));
        AddIfMissing(data, "actorProcessName", facts.Name);
        AddIfMissing(data, "actorProcessImagePath", facts.ImagePath);
        AddIfMissing(data, "actorCommandLine", facts.CommandLine);
        AddIfMissing(data, "actorParentProcessId", facts.ParentProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfMissing(data, "processImagePath", facts.ImagePath);
        AddIfMissing(data, "processName", facts.Name);

        return evt with
        {
            ProcessName = string.IsNullOrWhiteSpace(evt.ProcessName) ? facts.Name : evt.ProcessName,
            ParentProcessId = evt.ParentProcessId ?? facts.ParentProcessId
        };
    }

    private static CorrelationContext BuildContext(IReadOnlyList<SandboxEvent> events, string? samplePath)
    {
        var sampleFullPath = NormalizePath(samplePath);
        var sampleFileName = string.IsNullOrWhiteSpace(samplePath) ? string.Empty : Path.GetFileName(samplePath);
        var sampleDirectory = string.IsNullOrWhiteSpace(sampleFullPath) ? string.Empty : Path.GetDirectoryName(sampleFullPath) ?? string.Empty;
        var processes = BuildProcessFacts(events);
        var rootPids = ResolveRootProcessIds(events, sampleFullPath, sampleFileName);
        var samplePids = ExpandSampleProcessTree(rootPids, processes);
        var networkOwners = BuildNetworkEndpointOwnerMap(events);
        var lifecycles = BuildSampleLifecycles(events, rootPids, samplePids);
        var staticIocs = BuildStaticNetworkIndicators(events);
        var dnsCorroboratedTargets = BuildDnsCorroboratedTargets(events, staticIocs);
        var crossSourceEvidence = BuildCrossSourceSampleEvidence(events, samplePids, rootPids);
        return new CorrelationContext(sampleFullPath, sampleFileName, sampleDirectory, processes, samplePids, networkOwners, lifecycles, staticIocs, dnsCorroboratedTargets, crossSourceEvidence);
    }

    private static IReadOnlyList<CrossSourceEvidence> BuildCrossSourceSampleEvidence(
        IEnumerable<SandboxEvent> events,
        IReadOnlySet<int> samplePids,
        IReadOnlySet<int> rootPids)
    {
        var evidence = new List<CrossSourceEvidence>();
        foreach (var evt in events)
        {
            if (!IsIndependentRuntimeSource(evt) || IsExplicitNonBehaviorOrCollectionNoise(evt, evt.Data))
            {
                continue;
            }

            var pid = EventProcessId(evt, evt.Data);
            var parentPid = evt.ParentProcessId ??
                ParsePid(Value(evt.Data, "parentProcessId")) ??
                ParsePid(Value(evt.Data, "actorParentProcessId"));
            var rooted = pid is not null && samplePids.Contains(pid.Value) ||
                parentPid is not null && samplePids.Contains(parentPid.Value) ||
                rootPids.Any(root => LineageContainsPid(Value(evt.Data, "treeLineage"), root)) ||
                rootPids.Any(root => ParsePid(Value(evt.Data, "rootProcessId")) == root);
            if (!rooted)
            {
                continue;
            }

            var source = IsDriverEvidence(evt) ? "r0" : IsEtwEvidence(evt) ? "etw" : "guest";
            foreach (var target in MutationTargets(evt))
            {
                var normalizedTarget = NormalizeEvidenceTarget(target);
                if (!string.IsNullOrWhiteSpace(normalizedTarget))
                {
                    evidence.Add(new CrossSourceEvidence(source, "mutation", normalizedTarget, evt.Timestamp));
                }
            }

            foreach (var target in NetworkTargets(evt.Data))
            {
                var normalizedTarget = NormalizeEvidenceTarget(target);
                if (!string.IsNullOrWhiteSpace(normalizedTarget))
                {
                    evidence.Add(new CrossSourceEvidence(source, "network", normalizedTarget, evt.Timestamp));
                }
            }
        }

        return evidence;
    }

    private static bool HasIndependentSampleEvidence(
        SandboxEvent evt,
        string? target,
        CorrelationContext context,
        string family)
    {
        var targets = family.Equals("network", StringComparison.OrdinalIgnoreCase)
            ? NetworkTargets(evt.Data)
            : MutationTargets(evt);
        if (!string.IsNullOrWhiteSpace(target))
        {
            targets = targets.Append(target);
        }

        var normalizedTargets = targets
            .Select(NormalizeEvidenceTarget)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (normalizedTargets.Count == 0)
        {
            return false;
        }

        var currentSource = IsDriverEvidence(evt) ? "r0" :
            IsPcapProtocolEvidence(evt, evt.Data) ? "pcap" :
            IsEtwEvidence(evt) ? "etw" : "guest";
        return context.CrossSourceEvidence.Any(evidence =>
            evidence.Family.Equals(family, StringComparison.OrdinalIgnoreCase) &&
            !evidence.Source.Equals(currentSource, StringComparison.OrdinalIgnoreCase) &&
            normalizedTargets.Contains(evidence.Target) &&
            (evidence.Timestamp - evt.Timestamp).Duration() <= TimeSpan.FromSeconds(10));
    }

    private static IEnumerable<string> MutationTargets(SandboxEvent evt)
    {
        return new[]
        {
            evt.Path,
            Value(evt.Data, "path"),
            Value(evt.Data, "filePath"),
            Value(evt.Data, "target"),
            Value(evt.Data, "destinationPath"),
            Value(evt.Data, "sourcePath"),
            Value(evt.Data, "keyPath"),
            Value(evt.Data, "registryKeyPath"),
            Value(evt.Data, "objectPath"),
            Value(evt.Data, "imagePath"),
            Value(evt.Data, "serviceDll"),
            Value(evt.Data, "taskToRun")
        }.Where(value => !string.IsNullOrWhiteSpace(value))!;
    }

    private static string NormalizeEvidenceTarget(string value)
    {
        var normalized = NormalizeSlashes(value.Trim().Trim('"', '\''));
        return normalized.TrimEnd('\\', '/').ToLowerInvariant();
    }

    private static bool IsIndependentRuntimeSource(SandboxEvent evt)
    {
        return IsDriverEvidence(evt) || IsEtwEvidence(evt) ||
            (string.Equals(evt.Source, "guest", StringComparison.OrdinalIgnoreCase) &&
             (IsFileEvidence(evt) || IsNetworkEvidence(evt) || IsServiceOrScheduledTaskEvidence(evt)));
    }

    private static bool IsEtwEvidence(SandboxEvent evt)
    {
        return evt.Source.Contains("etw", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("etw.", StringComparison.OrdinalIgnoreCase) ||
            ContainsAny(Value(evt.Data, "captureSource"), "etw") ||
            ContainsAny(Value(evt.Data, "collectorSource"), "etw");
    }

    private static IReadOnlyList<SampleLifecycleWindow> BuildSampleLifecycles(
        IEnumerable<SandboxEvent> events,
        IReadOnlySet<int> rootPids,
        IReadOnlySet<int> samplePids)
    {
        var eventList = events.ToList();
        var windows = new List<SampleLifecycleWindow>();
        foreach (var rootPid in rootPids)
        {
            var related = eventList
                .Where(evt => EventProcessId(evt, evt.Data) == rootPid ||
                    TryGetRootProcessId(evt.Data, out var eventRootPid) && eventRootPid == rootPid)
                .OrderBy(evt => evt.Timestamp)
                .ToList();
            if (related.Count == 0)
            {
                continue;
            }

            var start = related
                .Where(evt => evt.EventType.Equals("process.start", StringComparison.OrdinalIgnoreCase) ||
                    evt.EventType.Equals("process.tree.summary", StringComparison.OrdinalIgnoreCase) ||
                    evt.EventType.Equals("process.snapshot", StringComparison.OrdinalIgnoreCase))
                .Select(evt => evt.Timestamp)
                .DefaultIfEmpty(related[0].Timestamp)
                .Min();
            var end = related.Max(evt => evt.Timestamp);
            // A root exit event is authoritative, but process-tree summaries
            // can continue while the 30-second guest collection window drains.
            // Keep that observed tail so packets from a short-lived child are
            // still within the same sample execution window.
            var exit = eventList
                .Where(evt => EventProcessId(evt, evt.Data) is int pid && samplePids.Contains(pid) &&
                    evt.EventType.Equals("process.exit", StringComparison.OrdinalIgnoreCase))
                .Select(evt => evt.Timestamp)
                .Where(timestamp => timestamp >= start)
                .DefaultIfEmpty(end)
                .Max();
            end = end > exit ? end : exit;
            if (end >= start)
            {
                windows.Add(new SampleLifecycleWindow(start - PcapAttributionGrace, end + PcapAttributionGrace));
            }
        }

        return windows;
    }

    private static HashSet<string> BuildStaticNetworkIndicators(IEnumerable<SandboxEvent> events)
    {
        var indicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events)
        {
            if (!evt.EventType.StartsWith("static.string.indicator", StringComparison.OrdinalIgnoreCase) ||
                IsTruthy(Value(evt.Data, "isReference")) ||
                string.Equals(Value(evt.Data, "classification"), "reference", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var kind = Value(evt.Data, "kind");
            if (!TextEqualsAny(kind, "domain", "url", "ipv4", "ip", "host", "hostname"))
            {
                continue;
            }

            AddStaticNetworkIndicator(indicators, Value(evt.Data, "value"));
        }

        return indicators;
    }

    private static void AddStaticNetworkIndicator(ISet<string> indicators, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var normalized = NormalizeNetworkTarget(value);
        if (!string.IsNullOrWhiteSpace(normalized) && !IsCollectionNetworkTarget(normalized) && !IsKnownCollectionNetworkTarget(normalized))
        {
            indicators.Add(normalized);
        }

        if (Uri.TryCreate(value.Trim().Trim('"', '\''), UriKind.Absolute, out var uri) &&
            !string.IsNullOrWhiteSpace(uri.Host))
        {
            var host = NormalizeNetworkTarget(uri.Host);
            if (!string.IsNullOrWhiteSpace(host) && !IsCollectionNetworkTarget(host) && !IsKnownCollectionNetworkTarget(host))
            {
                indicators.Add(host);
            }
        }
    }

    private static HashSet<string> BuildDnsCorroboratedTargets(
        IEnumerable<SandboxEvent> events,
        IReadOnlySet<string> staticIndicators)
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events)
        {
            var eventKind = Value(evt.Data, "eventKind");
            if (!(evt.EventType.StartsWith("dns.", StringComparison.OrdinalIgnoreCase) ||
                  evt.EventType.Equals("pcap.dns", StringComparison.OrdinalIgnoreCase) ||
                  string.Equals(eventKind, "dns", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var query = NormalizeNetworkTarget(FirstNonEmpty(
                Value(evt.Data, "queryName"), Value(evt.Data, "qname"), Value(evt.Data, "domain"), Value(evt.Data, "dnsQueryName")));
            if (string.IsNullOrWhiteSpace(query) || string.IsNullOrWhiteSpace(FindStaticIocMatch(query, staticIndicators)))
            {
                continue;
            }

            foreach (var answer in new[]
            {
                Value(evt.Data, "answerAddress"),
                Value(evt.Data, "dnsAnswerIps"),
                Value(evt.Data, "answersNormalized"),
                Value(evt.Data, "answers")
            }.Where(value => !string.IsNullOrWhiteSpace(value)))
            {
                foreach (var token in answer!.Split(new[] { ',', ';', '|', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var normalized = NormalizeNetworkTarget(token);
                    if (!string.IsNullOrWhiteSpace(normalized) && !IsCollectionNetworkTarget(normalized))
                    {
                        targets.Add(normalized);
                    }
                }
            }
        }

        return targets;
    }

    private static Dictionary<int, ProcessFacts> BuildProcessFacts(IEnumerable<SandboxEvent> events)
    {
        var processes = new Dictionary<int, ProcessFacts>();
        foreach (var evt in events)
        {
            var pid = EventProcessId(evt, evt.Data);
            if (pid is null)
            {
                continue;
            }

            processes.TryGetValue(pid.Value, out var existing);
            var name = FirstNonEmpty(
                evt.ProcessName,
                Value(evt.Data, "processName"),
                Value(evt.Data, "imageName"),
                existing?.Name);
            var imagePath = FirstNonEmpty(
                Value(evt.Data, "processImagePath"),
                Value(evt.Data, "imagePath"),
                IsProcessSnapshot(evt) ? evt.Path : null,
                existing?.ImagePath);
            var commandLine = FirstNonEmpty(evt.CommandLine, Value(evt.Data, "commandLine"), existing?.CommandLine);
            var parentPid = evt.ParentProcessId ?? ParsePid(Value(evt.Data, "parentProcessId")) ?? existing?.ParentProcessId;
            var rootPid = ParsePid(Value(evt.Data, "rootProcessId")) ?? existing?.RootProcessId;
            var lineage = FirstNonEmpty(Value(evt.Data, "treeLineage"), existing?.TreeLineage);

            processes[pid.Value] = new ProcessFacts(pid.Value, name, imagePath, commandLine, parentPid, rootPid, lineage);
        }

        return processes;
    }

    private static HashSet<int> ResolveRootProcessIds(
        IEnumerable<SandboxEvent> events,
        string sampleFullPath,
        string sampleFileName)
    {
        var rootPids = new HashSet<int>();
        foreach (var evt in events)
        {
            var eventType = evt.EventType ?? string.Empty;
            if (eventType.Equals("process.start", StringComparison.OrdinalIgnoreCase) &&
                EventLooksLikeSubmittedSample(evt, sampleFullPath, sampleFileName) &&
                evt.ProcessId is not null)
            {
                rootPids.Add(evt.ProcessId.Value);
            }

            if ((eventType.Equals("process.tree.summary", StringComparison.OrdinalIgnoreCase) ||
                 eventType.Equals("process.snapshot", StringComparison.OrdinalIgnoreCase)) &&
                TryGetRootProcessId(evt.Data, out var rootPid))
            {
                if (EventLooksLikeSubmittedSample(evt, sampleFullPath, sampleFileName) ||
                    PathOrCommandMatchesSample(Value(evt.Data, "rootImagePath"), sampleFullPath, sampleFileName))
                {
                    rootPids.Add(rootPid);
                }
            }
        }

        return rootPids;
    }

    private static HashSet<int> ExpandSampleProcessTree(
        HashSet<int> rootPids,
        IReadOnlyDictionary<int, ProcessFacts> processes)
    {
        var samplePids = new HashSet<int>(rootPids);
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var process in processes.Values)
            {
                if (samplePids.Contains(process.ProcessId))
                {
                    continue;
                }

                if (process.ParentProcessId is not null && samplePids.Contains(process.ParentProcessId.Value) ||
                    rootPids.Any(root => LineageContainsPid(process.TreeLineage, root)))
                {
                    samplePids.Add(process.ProcessId);
                    changed = true;
                }
            }
        }

        return samplePids;
    }

    private static Dictionary<string, int> BuildNetworkEndpointOwnerMap(IEnumerable<SandboxEvent> events)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in events)
        {
            if (!evt.EventType.StartsWith("network.netstat", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var pid = EventProcessId(evt, evt.Data);
            if (pid is null)
            {
                continue;
            }

            AddEndpointOwner(map, Value(evt.Data, "protocol"), Value(evt.Data, "local"), pid.Value);
            AddEndpointOwner(map, Value(evt.Data, "protocol"), FormatLocalEndpoint(evt.Data), pid.Value);
            AddEndpointOwner(map, Value(evt.Data, "transport"), Value(evt.Data, "localEndpoint"), pid.Value);
            AddEndpointOwner(map, Value(evt.Data, "protocol"), Value(evt.Data, "localEndpoint"), pid.Value);
        }

        return map;
    }

    private static void AddEndpointOwner(IDictionary<string, int> map, string? protocol, string? local, int pid)
    {
        var key = EndpointKey(protocol, local);
        if (!string.IsNullOrWhiteSpace(key))
        {
            map[key] = pid;
        }
    }

    private static bool TryGetJoinedNetworkOwnerPid(
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context,
        out int ownerPid)
    {
        foreach (var key in CandidateEndpointKeys(data))
        {
            if (context.NetworkEndpointOwners.TryGetValue(key, out ownerPid))
            {
                return true;
            }
        }

        ownerPid = 0;
        return false;
    }

    private static IEnumerable<string> CandidateEndpointKeys(IReadOnlyDictionary<string, string> data)
    {
        var protocols = new[]
        {
            Value(data, "protocol"),
            Value(data, "transport")
        };
        var locals = new[]
        {
            Value(data, "local"),
            Value(data, "localEndpoint"),
            FormatLocalEndpoint(data)
        };

        foreach (var protocol in protocols)
        {
            foreach (var local in locals)
            {
                var key = EndpointKey(protocol, local);
                if (!string.IsNullOrWhiteSpace(key))
                {
                    yield return key;
                }
            }
        }
    }

    private static void ApplyDisposition(Dictionary<string, string> data, CorrelationDisposition disposition)
    {
        if (disposition.Kind == CorrelationKind.Unchanged)
        {
            return;
        }

        data["sampleCorrelation"] = disposition.Label;
        AddIfMissing(data, "sampleCorrelationStatus", disposition.Status);
        data["sampleCorrelationReason"] = disposition.Reason;
        data["sampleCorrelationField"] = disposition.Field;
        data["sampleCorrelationStrength"] = disposition.Strength;
        data["strongSampleCorrelation"] = disposition.Strong.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        data["sampleCorrelationClassifier"] = "core-sample-correlation-v1";
        data["sampleCorrelationPolicy"] = "confirmed/probable events may enter behavior findings; environment/unknown rows are retained as evidence but excluded from primary behavior conclusions; trusted benign GUI presets such as Notepad require additional file, registry, network, persistence, injection, or privilege evidence before becoming a suspicious sample conclusion";
        data["sampleCorrelationBoundary"] = disposition.Boundary;

        if (disposition.Kind is CorrelationKind.Environment or CorrelationKind.Unknown)
        {
            data["evidenceDisposition"] = "retained-not-promoted";
            data["sampleConclusionPromoted"] = "false";
            data["sampleConclusionPolicy"] = "insufficient-sample-correlation-retain-evidence-only";
            data["behaviorCounted"] = "false";
            data["nonbehavior"] = "true";
            data["notSampleBehavior"] = "true";
            data["sampleBehaviorCandidate"] = "false";
            data["sampleBehaviorCandidateReason"] = disposition.Kind == CorrelationKind.Environment
                ? "environment-or-collection-noise-not-sample-behavior"
                : "unknown-attribution-not-promoted-to-sample-behavior";
            data["nonbehaviorReason"] = disposition.Reason;
            data["behaviorCountingPolicy"] = "weak-or-environment-sample-correlation-is-not-counted-as-sample-behavior";
            data["zhBehaviorHint"] = disposition.Kind == CorrelationKind.Environment
                ? "该事件被归因为环境/系统或采集噪声：保留证据，但不计入样本恶意行为结论。"
                : "该事件缺少样本 PID、路径或血缘关联：保留为未归因证据，默认不升级为样本行为。";
        }
        else if (disposition.Kind is CorrelationKind.Confirmed or CorrelationKind.Probable)
        {
            if (disposition.Kind == CorrelationKind.Confirmed &&
                disposition.Boundary == "normal-interactive-gui-baseline")
            {
                data["evidenceDisposition"] = "retained-not-promoted";
                data["sampleConclusionPromoted"] = "false";
                data["sampleConclusionPolicy"] = "normal-interactive-gui-baseline-extra-evidence-required";
                data["baselineSampleEvidence"] = "true";
                data["sampleBehaviorCandidate"] = "false";
                data["behaviorCounted"] = "false";
                data["nonbehavior"] = "true";
                data["notSampleBehavior"] = "true";
                data["sampleBehaviorCandidateReason"] = "normal-interactive-gui-baseline-extra-evidence-required";
                data["behaviorCountingPolicy"] = "normal-interactive-gui-baseline-retained-not-counted-as-suspicious-behavior";
                data["normalBehaviorBoundary"] = disposition.Boundary;
                data["zhBehaviorHint"] = "该事件属于 Notepad 等受信 benign preset 的交互式 GUI 基线活动：保留为样本相关证据，但需要额外文件、注册表、网络、持久化、注入或权限证据才升级为可疑结论。";
                return;
            }

            AddIfMissing(data, "evidenceDisposition", "behavior-candidate");
            AddIfMissing(data, "sampleConclusionPromoted", disposition.Kind == CorrelationKind.Confirmed ? "true" : "candidate");
            AddIfMissing(data, "sampleConclusionPolicy", disposition.Kind == CorrelationKind.Confirmed ? "strong-sample-correlation" : "probable-sample-correlation-review-required");
            if (disposition.OverrideExistingNonBehavior)
            {
                data["evidenceDisposition"] = "behavior-candidate";
                data["sampleConclusionPromoted"] = "true";
                data["sampleConclusionPolicy"] = "strong-sample-correlation";
                data["sampleBehaviorCandidate"] = "true";
                data["behaviorCounted"] = "true";
                data["nonbehavior"] = "false";
                data["notSampleBehavior"] = "false";
                data.Remove("nonbehaviorReason");
                data["sampleBehaviorCandidateReason"] = disposition.Reason;
                data["behaviorCountingPolicy"] = "strong-sample-correlation-is-counted-as-sample-behavior";
                data["zhBehaviorHint"] = "该事件的进程 PID 已通过主机进程树关联到样本，升级为样本行为证据。";
                data["zhHint"] = "该事件的进程 PID 已通过主机进程树关联到样本，升级为样本行为证据。";
            }
            else
            {
                if (disposition.OverrideExistingNonBehavior)
                {
                    data["sampleBehaviorCandidate"] = "true";
                    data["behaviorCounted"] = "true";
                    data["nonbehavior"] = "false";
                    data["notSampleBehavior"] = "false";
                    data.Remove("nonbehaviorReason");
                    data["behaviorCountingPolicy"] = "probable-pcap-correlation-is-counted-as-sample-candidate";
                }
                else
                {
                    AddIfMissing(data, "sampleBehaviorCandidate", "true");
                    AddIfMissing(data, "behaviorCounted", "true");
                }
            }
            AddIfMissing(data, "sampleBehaviorCandidateReason", disposition.Reason);
            AddIfMissing(data, "normalBehaviorBoundary", disposition.Boundary);
            AddIfMissing(data, "zhBehaviorHint", disposition.Kind == CorrelationKind.Confirmed
                ? (disposition.Boundary == "normal-interactive-gui-baseline"
                    ? "该事件属于 Notepad 等受信 benign preset 的交互式 GUI 基线活动：保留为样本相关证据，但需要额外文件、注册表、网络、持久化、注入或权限证据才升级为可疑结论。"
                    : "该事件已通过样本 PID、路径或进程血缘关联到样本。")
                : "该事件没有直接样本 PID，但目标路径/语义较强，作为疑似样本相关行为保留。");
        }
    }

    private static bool ShouldSkipCorrelation(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("static.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsExplicitNonBehaviorOrCollectionNoise(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        return IsFalsy(Value(data, "behaviorCounted")) ||
            IsFalsy(Value(data, "sampleBehaviorCandidate")) ||
            IsTruthy(Value(data, "nonbehavior")) ||
            IsTruthy(Value(data, "notSampleBehavior")) ||
            IsTruthy(Value(data, "collectionHealth")) ||
            IsTruthy(Value(data, "collectionNoise")) ||
            IsTruthy(Value(data, "collectorNoise")) ||
            IsTruthy(Value(data, "collectorSelfNoise")) ||
            IsTruthy(Value(data, "selfNoise")) ||
            IsTruthy(Value(data, "selfProcess")) ||
            CollectionEventTypePrefixes.Any(prefix => evt.EventType.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSampleCorrelatedWindowsEventLogEvidence(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var eventType = evt.EventType ?? string.Empty;
        var evidenceRole = Value(data, "evidenceRole");
        if (eventType.EndsWith(".summary", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains(".collection.", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains(".readiness.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var isTargetedEventLog = eventType.StartsWith("eventlog.", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(evidenceRole, "targeted-windows-eventlog-behavior", StringComparison.OrdinalIgnoreCase);
        var isSecurityAuditEvent = eventType.StartsWith("security.", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(evidenceRole, "privilege-security-audit-event", StringComparison.OrdinalIgnoreCase);

        // Collection/readiness summaries use the same evidence role on some
        // guest versions but are never behavior rows.  Their event type is
        // deliberately kept outside the eventlog./security. namespaces.
        if (!isTargetedEventLog && !isSecurityAuditEvent)
        {
            return false;
        }

        var processId = EventProcessId(evt, data);
        return processId is not null && context.SampleProcessIds.Contains(processId.Value);
    }

    private static string NormalBehaviorBoundary(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var processName = TrimExe(FirstNonEmpty(
            evt.ProcessName,
            Value(data, "processName"),
            Value(data, "actorProcessName"),
            Value(data, "imageName"),
            Path.GetFileName(Value(data, "processImagePath")),
            Path.GetFileName(Value(data, "imagePath")),
            context.SampleFileName));

        if (TextEqualsOrStartsWithAny(processName, NormalInteractiveGuiProcessNamePrefixes) && IsNormalInteractiveGuiBaselineEvent(evt, data, context))
        {
            return "normal-interactive-gui-baseline";
        }

        return "sample-attribution-boundary";
    }

    private static bool IsNormalInteractiveGuiBaselineEvent(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        if (IsHighSignalMutation(evt, data) || IsNetworkEvidence(evt) || IsServiceOrScheduledTaskEvidence(evt))
        {
            return false;
        }

        // Kernel ETW emits ordinary module and thread lifecycle edges for a
        // GUI process. Keep those rows in the evidence stream, but do not
        // turn every System32 DLL or routine thread edge into a suspicious
        // behavior finding. A user-writable image, the submitted sample
        // image, or an explicit remote-thread/injection marker remains a
        // sample candidate and is handled by the normal correlation path.
        if (IsEtwGuiLifecycleBaseline(evt, data, context))
        {
            return true;
        }

        if (IsProcessEvidence(evt))
        {
            return true;
        }

        var eventKind = Value(data, "eventKind");
        var eventFamily = Value(data, "eventFamily");
        return TextEqualsAny(eventKind, "summary", "status", "metadata") ||
            TextEqualsAny(eventFamily, "process", "window", "ui", "screenshot");
    }

    private static bool IsEtwGuiLifecycleBaseline(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        if (!IsEtwEvidence(evt) ||
            !TextEqualsAny(Value(data, "captureSource"), "etw-live-tracerpt") &&
            !TextEqualsAny(Value(data, "collectorSource"), "etwLive"))
        {
            return false;
        }

        if (TextEqualsAny(evt.EventType, "image.load", "image.unload"))
        {
            var imagePath = FirstNonEmpty(
                evt.Path,
                Value(data, "fileName"),
                Value(data, "path"),
                Value(data, "imagePath"));
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                return false;
            }

            var imageName = imagePath.Replace('/', '\\').TrimEnd('\\').Split('\\').LastOrDefault();
            var isSubmittedSampleImage = !string.IsNullOrWhiteSpace(imageName) &&
                string.Equals(imageName, context.SampleFileName, StringComparison.OrdinalIgnoreCase);
            return isSubmittedSampleImage || LooksSystemOnlyPath(imagePath);
        }

        if (TextEqualsAny(evt.EventType, "thread.start", "thread.exit"))
        {
            return !HasRemoteThreadSignal(data);
        }

        return false;
    }

    private static bool HasRemoteThreadSignal(IReadOnlyDictionary<string, string> data)
    {
        return IsTruthy(Value(data, "remoteThread")) ||
            IsTruthy(Value(data, "remoteThreadCandidate")) ||
            IsTruthy(Value(data, "injectionCandidate")) ||
            IsTruthy(Value(data, "remoteInjection")) ||
            !string.IsNullOrWhiteSpace(Value(data, "creatorProcessId")) ||
            !string.IsNullOrWhiteSpace(Value(data, "sourceProcessId")) ||
            ContainsAny(Value(data, "semanticEventTags"), "remote-thread", "injection");
    }

    private static bool HasExistingStrongCorrelation(IReadOnlyDictionary<string, string> data)
    {
        return IsTruthy(Value(data, "strongSampleCorrelation")) ||
            TextEqualsAny(Value(data, "sampleCorrelation"), "confirmed") ||
            TextEqualsAny(Value(data, "sampleCorrelationStatus"), "correlated", "confirmed") ||
            TextEqualsAny(Value(data, "sampleCorrelationStrength"), "strong");
    }

    private static bool MatchesSampleProcess(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var pid = EventProcessId(evt, data);
        if (pid is not null && context.SampleProcessIds.Contains(pid.Value))
        {
            return true;
        }

        var parentPid = evt.ParentProcessId ??
            ParsePid(Value(data, "parentProcessId")) ??
            ParsePid(Value(data, "actorParentProcessId"));
        if (parentPid is not null && context.SampleProcessIds.Contains(parentPid.Value))
        {
            return true;
        }

        if (context.SampleProcessIds.Any(root => LineageContainsPid(Value(data, "treeLineage"), root)))
        {
            return true;
        }

        return !IsProcessEvidence(evt) &&
            TryGetRootProcessId(data, out var rootPid) &&
            context.SampleProcessIds.Contains(rootPid);
    }

    private static bool AnyFieldMatchesSamplePath(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        return PathOrCommandMatchesSample(evt.Path, context) ||
            PathOrCommandMatchesSample(evt.CommandLine, context) ||
            PathOrCommandMatchesSample(Value(data, "path"), context) ||
            PathOrCommandMatchesSample(Value(data, "filePath"), context) ||
            PathOrCommandMatchesSample(Value(data, "imagePath"), context) ||
            PathOrCommandMatchesSample(Value(data, "processImagePath"), context) ||
            PathOrCommandMatchesSample(Value(data, "rootImagePath"), context) ||
            PathOrCommandMatchesSample(Value(data, "commandLine"), context) ||
            PathOrCommandMatchesSample(Value(data, "target"), context) ||
            PathOrCommandMatchesSample(Value(data, "value"), context) ||
            PathOrCommandMatchesSample(Value(data, "taskToRun"), context) ||
            PathOrCommandMatchesSample(Value(data, "serviceDll"), context) ||
            PathOrCommandMatchesSample(Value(data, "registryKeyPath"), context) ||
            PathOrCommandMatchesSample(Value(data, "keyPath"), context);
    }

    private static bool EventLooksLikeSubmittedSample(SandboxEvent evt, string sampleFullPath, string sampleFileName)
    {
        return PathOrCommandMatchesSample(evt.Path, sampleFullPath, sampleFileName) ||
            PathOrCommandMatchesSample(evt.CommandLine, sampleFullPath, sampleFileName) ||
            PathOrCommandMatchesSample(Value(evt.Data, "imagePath"), sampleFullPath, sampleFileName) ||
            PathOrCommandMatchesSample(Value(evt.Data, "processImagePath"), sampleFullPath, sampleFileName) ||
            PathOrCommandMatchesSample(Value(evt.Data, "rootImagePath"), sampleFullPath, sampleFileName);
    }

    private static bool PathOrCommandMatchesSample(string? value, CorrelationContext context) =>
        PathOrCommandMatchesSample(value, context.SampleFullPath, context.SampleFileName);

    private static bool PathOrCommandMatchesSample(string? value, string sampleFullPath, string sampleFileName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = NormalizePath(value);
        if (!string.IsNullOrWhiteSpace(sampleFullPath) &&
            (string.Equals(normalized, sampleFullPath, StringComparison.OrdinalIgnoreCase) ||
             value.Contains(sampleFullPath, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(sampleFileName) &&
            value.Contains(sampleFileName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDriverEvidence(SandboxEvent evt)
    {
        return string.Equals(evt.Source, "driver", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "image.load", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsNetworkEvidence(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("network.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("dns.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("http.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("tls.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("driver.network", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsFileEvidence(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("file.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("filesystem.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("dropped_file.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUnattributedFileWatcherEvent(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data)
    {
        return IsFileEvidence(evt) &&
            string.Equals(Value(data, "actorPidStatus"), "unavailable-filesystem-watcher", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsKnownCollectorFilesystemNoise(string? target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        var normalized = NormalizeSlashes(target);
        return normalized.Contains("__PSScriptPolicyTest_", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\DeviceMetadataCache\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\Diagnosis\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("EventStore.db-wal", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\PowerShell\\StartupProfileData", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\EdgeUpdate\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\AppRepository\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("RPTA", StringComparison.OrdinalIgnoreCase) &&
            normalized.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBenignWindowsDiscoveryUtility(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        if (!IsProcessEvidence(evt))
        {
            return false;
        }

        var processName = TrimExe(FirstNonEmpty(
            evt.ProcessName,
            Value(data, "processName"),
            Value(data, "actorProcessName"),
            Path.GetFileName(FirstNonEmpty(
                Value(data, "processImagePath"),
                Value(data, "imagePath"),
                evt.Path))));
        if (!TextEqualsAny(processName, BenignWindowsDiscoveryUtilityNames))
        {
            return false;
        }

        var imageOrPath = FirstNonEmpty(
            evt.Path,
            Value(data, "processImagePath"),
            Value(data, "imagePath"),
            Value(data, "actorProcessImagePath"));
        var submittedKnownSystemUtility =
            TextEqualsAny(TrimExe(Path.GetFileName(context.SampleFullPath)), BenignWindowsDiscoveryUtilityNames) &&
            LooksSystemOnlyPath(context.SampleFullPath);
        var signedOrKnownSystemImage = LooksSystemOnlyPath(imageOrPath) ||
            submittedKnownSystemUtility ||
            IsTruthy(Value(data, "signed")) ||
            IsTruthy(Value(data, "isSigned")) ||
            IsTruthy(Value(data, "signatureTrusted")) ||
            IsTruthy(Value(data, "signedBinary")) ||
            IsTruthy(Value(data, "knownWindowsBinary")) ||
            IsTruthy(Value(data, "windowsNativeBinary")) ||
            IsTruthy(Value(data, "isSystemBinary")) ||
            TextEqualsAny(Value(data, "signatureStatus"), "valid", "trusted", "signed");
        if (!signedOrKnownSystemImage)
        {
            return false;
        }

        return !HasHighSignalDiscoveryOverride(evt, data);
    }

    private static bool HasHighSignalDiscoveryOverride(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data)
    {
        if (IsHighSignalMutation(evt, data))
        {
            return true;
        }

        foreach (var key in new[]
        {
            "persistenceCandidate", "servicePersistenceCandidate", "startupRegistryCandidate",
            "injectionCandidate", "remoteInjection", "remoteThread", "defenseEvasionCandidate",
            "downloadCandidate", "downloadExecute", "maliciousNetwork", "maliciousNetworkCandidate"
        })
        {
            if (IsTruthy(Value(data, key)))
            {
                return true;
            }
        }

        var commandLine = FirstNonEmpty(evt.CommandLine, Value(data, "commandLine"));
        return ContainsAny(
            commandLine,
            "-enc", "-encodedcommand", "invoke-webrequest", "downloadstring", "start-bitstransfer",
            "rundll32", "regsvr32", "mshta", "schtasks /create", "sc create", "reg add");
    }

    private static bool ExactSamplePathMatches(string? value, CorrelationContext context)
    {
        if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(context.SampleFullPath))
        {
            return false;
        }

        return string.Equals(NormalizePath(value), context.SampleFullPath, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsListenerEvent(SandboxEvent evt)
    {
        return evt.EventType.Contains(".listener.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsServiceOrScheduledTaskEvidence(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("service.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("scheduled_task.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("startup.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("startup_item.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("registry.run.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsProcessEvidence(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("driver.process", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCollectorOrAgentProcess(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var processName = FirstNonEmpty(evt.ProcessName, Value(data, "processName"), Value(data, "actorProcessName"));
        if (TextEqualsAny(TrimExe(processName), "ksword.sandbox.agent", "ksword.sandbox.r0collector"))
        {
            return true;
        }

        var processFacts = TryGetEventProcessFacts(evt, data, context);
        return processFacts is not null &&
            TextEqualsAny(TrimExe(processFacts.Name), "ksword.sandbox.agent", "ksword.sandbox.r0collector");
    }

    private static ProcessFacts? TryGetEventProcessFacts(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        var pid = EventProcessId(evt, data);
        return pid is not null && context.Processes.TryGetValue(pid.Value, out var facts) ? facts : null;
    }

    private static bool IsKnownSystemProcess(ProcessFacts process)
    {
        var processName = TrimExe(process.Name);
        return TextEqualsAny(processName, SystemProcessNames) ||
            TextEqualsAny(processName, DefenderProcessNames) ||
            LooksSystemOnlyPath(process.ImagePath) ||
            LooksWindowsServiceHost(process);
    }

    private static bool IsDefenderOrSecurityProcess(ProcessFacts process)
    {
        var processName = TrimExe(process.Name);
        return TextEqualsAny(processName, DefenderProcessNames) ||
            ContainsAny(process.ImagePath, @"\program files\windows defender\", @"\programdata\microsoft\windows defender\") ||
            ContainsAny(process.CommandLine, @"\program files\windows defender\", @"\programdata\microsoft\windows defender\");
    }

    private static bool IsKernelOrCoreSystemProcess(ProcessFacts process)
    {
        return process.ProcessId is 0 or 4 ||
            TextEqualsAny(TrimExe(process.Name), "system", "idle", "registry", "smss", "csrss", "wininit", "services", "lsass", "lsaiso");
    }

    private static bool LooksWindowsServiceHost(ProcessFacts process)
    {
        return TextEqualsAny(TrimExe(process.Name), "svchost") &&
            !string.IsNullOrWhiteSpace(process.CommandLine) &&
            process.CommandLine.Contains(@"\windows\system32\svchost.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsKnownUntaintedServiceHostProcess(
        SandboxEvent evt,
        IReadOnlyDictionary<string, string> data,
        CorrelationContext context)
    {
        if (!IsProcessEvidence(evt) || AnyFieldMatchesSamplePath(evt, data, context))
        {
            return false;
        }

        var processName = FirstNonEmpty(evt.ProcessName, Value(data, "processName"), Value(data, "actorProcessName"));
        if (!TextEqualsAny(TrimExe(processName), "svchost"))
        {
            return false;
        }

        var imageOrPath = FirstNonEmpty(
            evt.Path,
            Value(data, "path"),
            Value(data, "processImagePath"),
            Value(data, "imagePath"),
            Value(data, "actorProcessImagePath"));
        var commandLine = FirstNonEmpty(evt.CommandLine, Value(data, "commandLine"), Value(data, "actorCommandLine"));
        if (!LooksSystemOnlyPath(imageOrPath) &&
            !ContainsAny(commandLine, @"\windows\system32\svchost.exe", "svchost.exe -k"))
        {
            return false;
        }

        var parentPid = evt.ParentProcessId ??
            ParsePid(Value(data, "parentProcessId")) ??
            ParsePid(Value(data, "actorParentProcessId"));
        var parentIsServices = parentPid is not null &&
            context.Processes.TryGetValue(parentPid.Value, out var parentFacts) &&
            TextEqualsAny(TrimExe(parentFacts.Name), "services");
        var parentName = FirstNonEmpty(Value(data, "parentProcessName"), Value(data, "actorParentProcessName"));
        var serviceName = FirstNonEmpty(Value(data, "serviceName"), Value(data, "service"));
        var commandLooksLikeServiceHost = ContainsAny(commandLine, " -k ", " -s ");

        return parentIsServices ||
            TextEqualsAny(TrimExe(parentName), "services") ||
            TextEqualsAny(serviceName, KnownWindowsServiceNames) ||
            commandLooksLikeServiceHost;
    }

    private static bool IsKnownWindowsServiceChange(IReadOnlyDictionary<string, string> data, string target)
    {
        var serviceName = Value(data, "serviceName");
        return TextEqualsAny(serviceName, KnownWindowsServiceNames) ||
            (LooksSystemOnlyPath(target) && !LooksUserWritableOrPersistenceTarget(target));
    }

    private static bool IsKnownWindowsTaskChange(IReadOnlyDictionary<string, string> data, string target)
    {
        var taskName = Value(data, "taskName");
        return taskName.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase) ||
            (LooksSystemOnlyPath(target) && !LooksUserWritableOrPersistenceTarget(target));
    }

    private static bool LooksSystemOnlyPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = NormalizeSlashes(value).ToLowerInvariant();
        return SystemPathHints.Any(normalized.Contains) ||
            normalized.StartsWith(@"\device\harddiskvolume", StringComparison.OrdinalIgnoreCase) &&
            (normalized.Contains(@"\windows\", StringComparison.OrdinalIgnoreCase) ||
             normalized.Contains(@"\program files\", StringComparison.OrdinalIgnoreCase));
    }

    private static bool LooksUserWritableOrPersistenceTarget(string? value, CorrelationContext? context = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = NormalizeSlashes(value).ToLowerInvariant();
        return UserWritablePathHints.Any(normalized.Contains) ||
            (context is not null &&
             !string.IsNullOrWhiteSpace(context.SampleDirectory) &&
             normalized.Contains(NormalizeSlashes(context.SampleDirectory).ToLowerInvariant(), StringComparison.OrdinalIgnoreCase)) ||
            normalized.Contains(@"\currentversion\run", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\currentversion\runonce", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\taskcache\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\startup\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\services\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHighSignalMutation(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        var operation = FirstNonEmpty(
            Value(data, "operationName"),
            Value(data, "fileOperationName"),
            Value(data, "registryOperationName"),
            Value(data, "operation"),
            evt.EventType);
        return ContainsAny(operation, "write", "create", "set", "rename", "delete", "setValue", "createKey", "setinfo") ||
            IsTruthy(Value(data, "deleteIntent")) ||
            IsTruthy(Value(data, "renameIntent")) ||
            IsTruthy(Value(data, "droppedFileCandidate")) ||
            IsTruthy(Value(data, "startupRegistryCandidate")) ||
            IsTruthy(Value(data, "servicePersistenceCandidate")) ||
            IsTruthy(Value(data, "persistenceCandidate"));
    }

    private static bool IsPathTruncated(IReadOnlyDictionary<string, string> data)
    {
        return IsTruthy(Value(data, "pathTruncated")) ||
            IsTruthy(Value(data, "filePathTruncated")) ||
            IsTruthy(Value(data, "keyPathTruncated"));
    }

    private static int? EventProcessId(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        return evt.ProcessId is > 0 ? evt.ProcessId :
            ParsePid(Value(data, "processId")) ??
            ParsePid(Value(data, "pid")) ??
            ParsePid(Value(data, "driverProcessId")) ??
            ParsePid(Value(data, "owningProcessId")) ??
            ParsePid(Value(data, "ownerPid")) ??
            ParsePid(Value(data, "ownerProcessId")) ??
            ParsePid(Value(data, "sourceProcessId")) ??
            ParsePid(Value(data, "targetProcessId")) ??
            ParsePid(Value(data, "eventHeaderPid")) ??
            ParsePid(Value(data, "serviceProcessId")) ??
            ParsePid(Value(data, "actorProcessId")) ??
            ParsePid(Value(data, "parentPid")) ??
            ParsePid(Value(data, "ppid"));
    }

    private static bool TryGetRootProcessId(IReadOnlyDictionary<string, string> data, out int rootPid)
    {
        var parsed = ParsePid(Value(data, "rootProcessId"));
        if (parsed is null)
        {
            rootPid = 0;
            return false;
        }

        rootPid = parsed.Value;
        return true;
    }

    private static int? ParsePid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value, "null", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var text = value.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex) && hex > 0
                ? hex
                : null;
        }

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? parsed
            : null;
    }

    private static int? ParsePort(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        var separator = text.LastIndexOf(':');
        if (separator >= 0 && separator + 1 < text.Length)
        {
            text = text[(separator + 1)..];
        }

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) && port is > 0 and <= 65535
            ? port
            : null;
    }

    private static bool LineageContainsPid(string? lineage, int pid)
    {
        if (string.IsNullOrWhiteSpace(lineage))
        {
            return false;
        }

        var needle = pid.ToString(CultureInfo.InvariantCulture);
        return lineage.Split(['>', '|', ',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(part => string.Equals(part, needle, StringComparison.OrdinalIgnoreCase));
    }

    private static string EndpointKey(string? protocol, string? local)
    {
        if (string.IsNullOrWhiteSpace(protocol) || string.IsNullOrWhiteSpace(local))
        {
            return string.Empty;
        }

        return $"{protocol.Trim().ToUpperInvariant()}|{local.Trim()}";
    }

    private static string FormatLocalEndpoint(IReadOnlyDictionary<string, string> data)
    {
        var address = Value(data, "localAddress");
        var port = Value(data, "localPort");
        return string.IsNullOrWhiteSpace(address) || string.IsNullOrWhiteSpace(port)
            ? string.Empty
            : $"{address}:{port}";
    }

    private static bool ContainsAny(string? value, params string[] fragments)
    {
        return !string.IsNullOrWhiteSpace(value) &&
            fragments.Any(fragment => value.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TextEqualsAny(string? value, params string[] candidates)
    {
        return !string.IsNullOrWhiteSpace(value) &&
            candidates.Any(candidate => string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TextEqualsOrStartsWithAny(string? value, params string[] candidates)
    {
        return !string.IsNullOrWhiteSpace(value) &&
            candidates.Any(candidate =>
                string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(candidate + "-", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(candidate + "_", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith(candidate + ".", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsTruthy(string? value)
    {
        return TextEqualsAny(value, "true", "1", "yes", "y");
    }

    private static bool IsFalsy(string? value)
    {
        return TextEqualsAny(value, "false", "0", "no", "n");
    }

    private static string Value(IReadOnlyDictionary<string, string> data, string key)
    {
        return data.TryGetValue(key, out var value) ? value ?? string.Empty : string.Empty;
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

    private static void AddIfMissing(IDictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value) &&
            (!data.TryGetValue(key, out var existing) || string.IsNullOrWhiteSpace(existing)))
        {
            data[key] = value;
        }
    }

    private static SandboxEvent CloneEvent(SandboxEvent evt)
    {
        return evt with
        {
            Data = new Dictionary<string, string>(evt.Data ?? [], StringComparer.OrdinalIgnoreCase)
        };
    }

    private static bool IsProcessSnapshot(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        try
        {
            return Path.GetFullPath(value.Trim().Trim('"'));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return value.Trim().Trim('"');
        }
    }

    private static string NormalizeSlashes(string value)
    {
        return value.Replace('/', '\\');
    }

    private static string TrimExe(string? value)
    {
        var fileName = string.IsNullOrWhiteSpace(value) ? string.Empty : Path.GetFileName(value.Trim());
        return fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? fileName[..^4]
            : fileName;
    }

    private sealed record CorrelationContext(
        string SampleFullPath,
        string SampleFileName,
        string SampleDirectory,
        IReadOnlyDictionary<int, ProcessFacts> Processes,
        HashSet<int> SampleProcessIds,
        IReadOnlyDictionary<string, int> NetworkEndpointOwners,
        IReadOnlyList<SampleLifecycleWindow> SampleLifecycles,
        IReadOnlySet<string> StaticNetworkIndicators,
        IReadOnlySet<string> DnsCorroboratedTargets,
        IReadOnlyList<CrossSourceEvidence> CrossSourceEvidence);

    private sealed record SampleLifecycleWindow(DateTimeOffset StartUtc, DateTimeOffset EndUtc);

    private sealed record ProcessFacts(
        int ProcessId,
        string Name,
        string ImagePath,
        string CommandLine,
        int? ParentProcessId,
        int? RootProcessId,
        string TreeLineage);

    private sealed record CrossSourceEvidence(
        string Source,
        string Family,
        string Target,
        DateTimeOffset Timestamp);

    private enum CorrelationKind
    {
        Unchanged,
        Confirmed,
        Probable,
        Environment,
        Unknown
    }

    private sealed record CorrelationDisposition(
        CorrelationKind Kind,
        string Label,
        string Status,
        string Reason,
        string Field,
        string Strength,
        bool Strong,
        string Boundary,
        bool OverrideExistingNonBehavior = false)
    {
        public static CorrelationDisposition Unchanged() => new(CorrelationKind.Unchanged, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, false, string.Empty);

        public static CorrelationDisposition Confirmed(string reason, string field, string boundary = "sample-attribution-boundary", bool overrideExistingNonBehavior = false) => new(CorrelationKind.Confirmed, "confirmed", "correlated", reason, field, "strong", true, boundary, overrideExistingNonBehavior);

        public static CorrelationDisposition Probable(string reason, string field, string boundary = "probable-behavior-boundary", bool overrideExistingNonBehavior = false) => new(CorrelationKind.Probable, "probable", "probable", reason, field, "medium", false, boundary, overrideExistingNonBehavior);

        public static CorrelationDisposition Environment(string reason, string field) => new(CorrelationKind.Environment, "environment", "environment", reason, field, "none", false, "environment-system-collector-boundary");

        public static CorrelationDisposition Unknown(string reason, string field) => new(CorrelationKind.Unknown, "unknown", "unknown", reason, field, "none", false, "unknown-attribution-boundary");
    }
}
