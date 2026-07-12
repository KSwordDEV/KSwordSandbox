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
        var eventList = events
            .Select(CloneEvent)
            .ToList();
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
        if (IsExplicitNonBehaviorOrCollectionNoise(evt, data))
        {
            return CorrelationDisposition.Environment("explicit-nonbehavior-or-collection-noise", "behaviorCounted/nonbehavior");
        }

        if (IsCollectorOrAgentProcess(evt, data, context))
        {
            return CorrelationDisposition.Environment("row-belongs-to-sandbox-collector-or-agent", "processName");
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

        if (AnyFieldMatchesSamplePath(evt, data, context))
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

        if (isHighSignalMutation && targetsUserWritableOrPersistence)
        {
            return CorrelationDisposition.Probable("driver-mutation-targets-user-writable-or-persistence-location-without-sample-pid", "path");
        }

        if (isHighSignalMutation && !targetsSystemOnly && !IsPathTruncated(data))
        {
            return CorrelationDisposition.Probable("driver-mutation-has-non-system-target-but-no-lineage-join", "path");
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

        if (PathOrCommandMatchesSample(target, context))
        {
            return CorrelationDisposition.Confirmed("service-or-task-target-points-to-submitted-sample", "imagePath/taskToRun");
        }

        var actorPid = EventProcessId(evt, data);
        if (actorPid is not null && context.SampleProcessIds.Contains(actorPid.Value))
        {
            return CorrelationDisposition.Confirmed("service-or-task-actor-pid-matched-sample-process-tree", "actorProcessId");
        }

        if (LooksUserWritableOrPersistenceTarget(target, context))
        {
            return CorrelationDisposition.Probable("service-or-task-target-points-to-user-writable-location", "imagePath/taskToRun");
        }

        if (IsKnownWindowsServiceChange(data, target) || IsKnownWindowsTaskChange(data, target))
        {
            return CorrelationDisposition.Environment("standard-windows-service-or-task-state-drift", "serviceName/taskName");
        }

        return CorrelationDisposition.Unknown("service-or-task-diff-has-no-sample-target-or-actor-correlation", "imagePath/taskToRun");
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
        return new CorrelationContext(sampleFullPath, sampleFileName, sampleDirectory, processes, samplePids, networkOwners);
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
                    PathOrCommandMatchesSample(Value(evt.Data, "rootImagePath"), sampleFullPath, sampleFileName) ||
                    eventType.Equals("process.tree.summary", StringComparison.OrdinalIgnoreCase))
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
            AddIfMissing(data, "sampleBehaviorCandidate", "true");
            AddIfMissing(data, "behaviorCounted", "true");
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

        if (TextEqualsOrStartsWithAny(processName, NormalInteractiveGuiProcessNamePrefixes) && IsNormalInteractiveGuiBaselineEvent(evt, data))
        {
            return "normal-interactive-gui-baseline";
        }

        return "sample-attribution-boundary";
    }

    private static bool IsNormalInteractiveGuiBaselineEvent(SandboxEvent evt, IReadOnlyDictionary<string, string> data)
    {
        if (IsHighSignalMutation(evt, data) || IsNetworkEvidence(evt) || IsServiceOrScheduledTaskEvidence(evt))
        {
            return false;
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
        return evt.ProcessId ??
            ParsePid(Value(data, "processId")) ??
            ParsePid(Value(data, "driverProcessId")) ??
            ParsePid(Value(data, "owningProcessId")) ??
            ParsePid(Value(data, "serviceProcessId")) ??
            ParsePid(Value(data, "actorProcessId"));
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
            return int.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex)
                ? hex
                : null;
        }

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
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
        IReadOnlyDictionary<string, int> NetworkEndpointOwners);

    private sealed record ProcessFacts(
        int ProcessId,
        string Name,
        string ImagePath,
        string CommandLine,
        int? ParentProcessId,
        int? RootProcessId,
        string TreeLineage);

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
        string Boundary)
    {
        public static CorrelationDisposition Unchanged() => new(CorrelationKind.Unchanged, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, false, string.Empty);

        public static CorrelationDisposition Confirmed(string reason, string field, string boundary = "sample-attribution-boundary") => new(CorrelationKind.Confirmed, "confirmed", "correlated", reason, field, "strong", true, boundary);

        public static CorrelationDisposition Probable(string reason, string field, string boundary = "probable-behavior-boundary") => new(CorrelationKind.Probable, "probable", "probable", reason, field, "medium", false, boundary);

        public static CorrelationDisposition Environment(string reason, string field) => new(CorrelationKind.Environment, "environment", "environment", reason, field, "none", false, "environment-system-collector-boundary");

        public static CorrelationDisposition Unknown(string reason, string field) => new(CorrelationKind.Unknown, "unknown", "unknown", reason, field, "none", false, "unknown-attribution-boundary");
    }
}
