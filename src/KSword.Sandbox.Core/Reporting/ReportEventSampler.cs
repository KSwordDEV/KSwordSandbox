using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Reporting;

/// <summary>
/// Controls how many normalized events are embedded directly into HTML/report
/// payloads. Inputs are raw guest/driver/host events; processing keeps high
/// value progress/process/network rows plus a bounded sample of noisy types;
/// the output is a compact, sanitized event list and an omitted-event count.
/// </summary>
public sealed record ReportEventSamplingOptions
{
    public int MaxInlineEvents { get; init; } = 220;

    public int MaxEventsPerType { get; init; } = 30;

    public int MaxHighValueEventsPerType { get; init; } = 80;

    public int MaxEvidenceEventsPerFinding { get; init; } = 8;

    public int MaxEventDataPairs { get; init; } = 24;

    public int MaxEventDataValueCharacters { get; init; } = 512;

    public int MaxPathCharacters { get; init; } = 4096;
}

/// <summary>
/// Describes the outcome of report-event sampling. Inputs are the raw count and
/// sanitized selected rows; processing computes omitted row metadata; callers
/// embed Events in report.json/report.html while keeping raw artifacts on disk.
/// </summary>
public sealed record ReportEventSamplingResult
{
    public required List<SandboxEvent> Events { get; init; }

    public int RawEventCount { get; init; }

    public int SelectedRawEventCount { get; init; }

    public int OmittedEventCount => Math.Max(0, RawEventCount - SelectedRawEventCount);

    public bool WasSampled => OmittedEventCount > 0;
}

/// <summary>
/// Shared report sampler used by WebUI regeneration and the post-process tool.
/// It prevents R0-heavy runs from producing giant HTML while preserving enough
/// representative evidence for operator review and keeping all raw files on
/// disk for deep analysis.
/// </summary>
public static class ReportEventSampler
{
    public static readonly ReportEventSamplingOptions DefaultOptions = new();

    private static readonly string[] PriorityDataKeys =
    [
        "collectionName",
        "evidenceRole",
        "capturePhase",
        "captureState",
        "importMode",
        "behaviorCounted",
        "nonbehavior",
        "notSampleBehavior",
        "sampleBehaviorCandidate",
        "sampleBehaviorCandidateReason",
        "sampleCorrelation",
        "sampleCorrelationStatus",
        "sampleCorrelationReason",
        "sampleCorrelationField",
        "sampleCorrelationStrength",
        "strongSampleCorrelation",
        "sampleCorrelationClassifier",
        "sampleCorrelationPolicy",
        "sampleCorrelationBoundary",
        "normalBehaviorBoundary",
        "evidenceDisposition",
        "sampleConclusionPromoted",
        "sampleConclusionPolicy",
        "baselineSampleEvidence",
        "actorProcessId",
        "actorProcessName",
        "actorProcessImagePath",
        "actorCommandLine",
        "behaviorCountingPolicy",
        "nonbehaviorReason",
        "behaviorScope",
        "semanticLane",
        "sampleBehaviorBoundary",
        "collectionDiagnostic",
        "collectionNoise",
        "collectorSelfNoise",
        "collectorNoise",
        "selfNoise",
        "selfProcess",
        "noisePolicy",
        "collectorNoisePolicy",
        "collectorNoiseScope",
        "noiseClass",
        "noiseScope",
        "hostOperationalKind",
        "guestImportOutcome",
        "guestImportMarker",
        "operatorHint",
        "zhBehaviorHint",
        "zhNoiseHint",
        "zhNoiseClassificationHint",
        "zhOperatorHint",
        "uid",
        "protocol",
        "sourceIp",
        "sourcePort",
        "destinationIp",
        "destinationPort",
        "flowKey",
        "method",
        "host",
        "uri",
        "queryName",
        "sni",
        "sourceArtifactKind",
        "sourceArtifactRelativePath",
        "sourceArtifactSha256",
        "sourceArtifactSizeBytes",
        "downloadSelector",
        "downloadSafeLink",
        "safeLink",
        "safeRelativeSelector",
        "importPath",
        "downloadRejectionPolicy",
        "artifactEvidenceMatrix",
        "artifactEvidenceSummaryZh",
        "artifactEvidenceCollectionsReady",
        "artifactEvidenceCollectionsMissing",
        "primaryArtifactSelectors",
        "hasDroppedFileArtifacts",
        "hasScreenshotArtifacts",
        "hasMemoryDumpArtifacts",
        "hasPacketCaptureArtifacts",
        "droppedFileArtifactCount",
        "screenshotArtifactCount",
        "memoryDumpArtifactCount",
        "packetCaptureArtifactCount",
        "droppedFileBytes",
        "screenshotBytes",
        "memoryDumpBytes",
        "packetCaptureBytes",
        "rejectionDiagnosticsAvailable",
        "rejectedArtifactCount",
        "lastRejectedArtifactSelector",
        "artifactRejectionReasons",
        "isDuplicate",
        "duplicateGroupKey",
        "duplicateGroupId",
        "duplicateGroupCount",
        "duplicateOrdinal",
        "duplicatePrimarySelector",
        "duplicatePrimarySafeLink",
        "duplicateOfArtifactRelativePath",
        "artifactRelativePath",
        "artifactCategory",
        "artifactKind",
        "screenshotRelativePath",
        "memoryDumpRelativePath",
        "packetCaptureRelativePath",
        "pcapRelativePath",
        "pcapngRelativePath",
        "etlRelativePath",
        "relativePath",
        "sizeBytes",
        "sha256",
        "hash.sha256",
        "hashStatus",
        "artifactHashStatus",
        "rootProcessId",
        "processKey",
        "processGuid",
        "processUniqueId",
        "snapshotKey",
        "processSnapshotKey",
        "parentProcessId",
        "parentPid",
        "ppid",
        "parentProcessKey",
        "parentProcessGuid",
        "parentProcessName",
        "parentImageName",
        "treeDepth",
        "depth",
        "treeLineage",
        "driverEventPath",
        "rawEventsPath",
        "driverEventsPath",
        "phase",
        "screenshotStage",
        "memoryDumpPhase",
        "packetCapturePhase",
        "captureStatus",
        "status",
        "tool",
        "conversionTool",
        "conversionStatus",
        "pcapngFileCount",
        "pcapngPacketCount",
        "pcapngBlockCount",
        "packetCount",
        "blockCount",
        "fileCount",
        "totalBytes",
        "protocolSummaryState",
        "childProcessDumpEnabled",
        "childProcessDumpMode",
        "childProcessDumpTarget",
        "driverStateName",
        "flags",
        "flagNames",
        "queueCapacity",
        "queueDepth",
        "queueHighWatermark",
        "lostCount",
        "highWatermark",
        "lastEnqueueFailureStatus",
        "lastEnqueueFailureStatusHex",
        "sequence",
        "sequenceMeaning",
        "totalEventsDropped",
        "totalEventsSuppressed",
        "totalEventsBackpressured",
        "producerDroppedMaskHex",
        "producerSuppressedMaskHex",
        "producerBackpressureMaskHex",
        "nextSequence",
        "processName",
        "imageName",
        "operationName",
        "operation",
        "queryName",
        "qname",
        "domain",
        "queryType",
        "recordType",
        "rcode",
        "isResponse",
        "protocol",
        "transportProtocol",
        "protocolName",
        "sourceIp",
        "sourcePort",
        "sourceEndpoint",
        "destinationIp",
        "destinationPort",
        "destinationEndpoint",
        "flowKey",
        "direction",
        "method",
        "uri",
        "requestUri",
        "host",
        "url",
        "userAgent",
        "contentType",
        "statusCode",
        "payloadMagic",
        "sni",
        "serverName",
        "tlsVersion",
        "ja3",
        "ja3s",
        "alpn",
        "cipherSuite",
        "remoteAddress",
        "remotePort",
        "state",
        "durationSeconds",
        "packetCount",
        "byteCount",
        "uid",
        "fileFormat",
        "magic",
        "isPe",
        "architecture",
        "machine",
        "subsystem",
        "sectionCount",
        "sectionName",
        "entropy",
        "entropyLabel",
        "moduleName",
        "apiCount",
        "clusterName",
        "exportName",
        "tlsCallback",
        "resourceType",
        "resourceRole",
        "dataRva",
        "dataFileOffset",
        "size",
        "isPayloadCandidate",
        "payloadCandidate",
        "isEmbeddedPe",
        "isLarge",
        "yaraRule",
        "matchedStrings",
        "tags",
        "networkStatusAvailable",
        "diagnosticStage",
        "diagnosticCode",
        "readinessState",
        "lastDegradeReasonName",
        "supportedLayerMask",
        "supportedLayerMaskHex",
        "supportedLayerMaskSummary",
        "activeLayerMask",
        "activeLayerMaskHex",
        "activeLayerMaskSummary",
        "lastRegisteredCalloutMask",
        "lastRegisteredCalloutMaskHex",
        "lastAddedFilterMask",
        "lastAddedFilterMaskHex",
        "todoMask",
        "todoMaskHex",
        "classifyCount",
        "eventCount",
        "queueFailureCount",
        "classifyPayloadFailureCount",
        "registerNtStatusHex",
        "engineNtStatusHex",
        "lastQueueFailureNtStatusHex",
        "vtStatus",
        "vtEventName",
        "vtVerdict",
        "verdict",
        "vtMalicious",
        "vtSuspicious",
        "vtHarmless",
        "vtUndetected",
        "vtTimeout",
        "vtScore",
        "vtDetectionCount",
        "vtEngineCount",
        "engineCount",
        "vtReputation",
        "reputation",
        "vtCommunityScore",
        "communityScore",
        "communityScoreSource",
        "vtCommunityHarmlessVotes",
        "vtCommunityMaliciousVotes",
        "vtCommunityVoteCount",
        "lastAnalysisDateUtc",
        "meaningfulName",
        "permalink",
        "detectionPermalink",
        "officialApiSelfLink",
        "collectionHealth",
        "nonbehavior",
        "zhMessage",
        "zhHint"
    ];

    private static readonly string[] StaticPriorityDataKeys =
    [
        "staticOnly",
        "evidenceOrigin",
        "evidenceKind",
        "ruleScope",
        "ruleKey",
        "behaviorFamily",
        "triageLevel",
        "reportLane",
        "evidenceStrength",
        "runtimeCorrelationRequired",
        "staticEvidenceBoundary",
        "zhBehaviorFamily",
        "zhTriageLevel",
        "zhEvidenceBoundary",
        "zhNextEvidenceHint",
        "fileFormat",
        "magic",
        "isPe",
        "architecture",
        "machine",
        "subsystem",
        "sectionCount",
        "sectionName",
        "entropy",
        "entropyLabel",
        "moduleName",
        "apiCount",
        "clusterName",
        "exportName",
        "tlsCallback",
        "resourceType",
        "resourceName",
        "resourceLanguage",
        "resourceRole",
        "dataRva",
        "dataFileOffset",
        "size",
        "isPayloadCandidate",
        "payloadCandidate",
        "isEmbeddedPe",
        "isLarge",
        "overlaySize",
        "overlayEntropy",
        "indicatorKind",
        "indicatorValue",
        "category",
        "value",
        "tool",
        "commandRole",
        "cluster",
        "clusterName",
        "hitCount",
        "apiNames",
        "suspiciousApiNames",
        "suspiciousApiClusters",
        "stringKind",
        "stringValue",
        "yaraRule",
        "matchedStrings",
        "tags"
    ];

    private static readonly string[] NetworkCommonPriorityDataKeys =
    [
        "collectionName",
        "evidenceRole",
        "behaviorCounted",
        "nonbehavior",
        "notSampleBehavior",
        "sampleBehaviorCandidate",
        "sampleBehaviorCandidateReason",
        "sampleCorrelation",
        "sampleCorrelationStatus",
        "sampleCorrelationReason",
        "sampleCorrelationField",
        "sampleCorrelationStrength",
        "strongSampleCorrelation",
        "behaviorScope",
        "sourceArtifactKind",
        "sourceArtifactRelativePath",
        "sourceArtifactSha256",
        "sourceArtifactSizeBytes",
        "importMode",
        "uid",
        "protocol",
        "sourceIp",
        "sourcePort",
        "destinationIp",
        "destinationPort",
        "flowKey"
    ];

    private static readonly string[] ArtifactImportPriorityDataKeys =
    [
        "collectionName",
        "evidenceRole",
        "behaviorCounted",
        "nonbehavior",
        "notSampleBehavior",
        "sampleBehaviorCandidate",
        "sampleBehaviorCandidateReason",
        "behaviorScope",
        "nonbehaviorReason",
        "zhMessage",
        "zhHint",
        "sourceArtifactKind",
        "sourceArtifactRelativePath",
        "sourceArtifactSha256",
        "sourceArtifactSizeBytes",
        "downloadSelector",
        "downloadSafeLink",
        "safeLink",
        "artifactRelativePath",
        "artifactKind",
        "artifactEvidenceMatrix",
        "artifactEvidenceSummaryZh",
        "artifactEvidenceCollectionsReady",
        "artifactEvidenceCollectionsMissing",
        "primaryArtifactSelectors",
        "hasDroppedFileArtifacts",
        "hasScreenshotArtifacts",
        "hasMemoryDumpArtifacts",
        "hasPacketCaptureArtifacts",
        "droppedFileArtifactCount",
        "screenshotArtifactCount",
        "memoryDumpArtifactCount",
        "packetCaptureArtifactCount",
        "importMode"
    ];

    private static readonly string[] ArtifactImportSummaryPriorityDataKeys =
    [
        "behaviorCounted",
        "nonbehavior",
        "notSampleBehavior",
        "sampleBehaviorCandidate",
        "sampleBehaviorCandidateReason",
        "behaviorCountingPolicy",
        "nonbehaviorReason",
        "downloadPolicy",
        "artifactEvidenceMatrix",
        "artifactEvidenceSummaryZh",
        "primaryArtifactSelectors",
        "hasDroppedFileArtifacts",
        "hasScreenshotArtifacts",
        "hasMemoryDumpArtifacts",
        "hasPacketCaptureArtifacts",
        "droppedFileArtifactCount",
        "screenshotArtifactCount",
        "memoryDumpArtifactCount",
        "packetCaptureArtifactCount",
        "importedSensitiveArtifactCount",
        "downloadableArtifactCount",
        "sensitiveArtifactCount"
    ];

    private static readonly string[] DnsPriorityDataKeys =
    [
        "queryName",
        "queryType",
        "rcode",
        "isResponse",
        "qname",
        "domain",
        "recordType"
    ];

    private static readonly string[] HttpPriorityDataKeys =
    [
        "method",
        "host",
        "uri",
        "requestUri",
        "url",
        "userAgent",
        "contentType",
        "statusCode",
        "payloadMagic"
    ];

    private static readonly string[] TlsPriorityDataKeys =
    [
        "sni",
        "serverName",
        "tlsVersion",
        "ja3",
        "ja3s",
        "alpn",
        "cipherSuite"
    ];

    private static readonly string[] FlowPriorityDataKeys =
    [
        "state",
        "durationSeconds",
        "byteCount",
        "packetCount",
        "pcapngPacketCount",
        "pcapngBlockCount",
        "fileCount",
        "totalBytes",
        "protocolSummaryState",
        "sourceEndpoint",
        "destinationEndpoint",
        "direction"
    ];

    /// <summary>
    /// Samples and sanitizes normalized events for report embedding. Inputs are
    /// ordered or unordered raw events plus optional source-path hints;
    /// processing orders by timestamp, applies per-type caps, adds a sampling
    /// marker when rows were omitted, and returns compact report events.
    /// </summary>
    public static ReportEventSamplingResult SampleForReport(
        IReadOnlyCollection<SandboxEvent> rawEvents,
        ReportEventSamplingOptions? options = null,
        string? jobRoot = null,
        string? eventsPath = null,
        string? driverEventsPath = null)
    {
        var resolvedOptions = options ?? DefaultOptions;
        var orderedEvents = rawEvents.OrderBy(evt => evt.Timestamp).ToList();
        var selected = SelectEvents(orderedEvents, resolvedOptions)
            .Select(evt => SanitizeEvent(evt, resolvedOptions))
            .ToList();

        var result = new ReportEventSamplingResult
        {
            Events = selected,
            RawEventCount = orderedEvents.Count,
            SelectedRawEventCount = selected.Count
        };

        if (result.WasSampled)
        {
            result.Events.Insert(0, BuildSamplingMarker(result, resolvedOptions, jobRoot, eventsPath, driverEventsPath));
        }

        return result;
    }

    /// <summary>
    /// Caps evidence rows per finding and sanitizes large fields. Inputs are raw
    /// findings from the rule engine; processing preserves rule metadata and a
    /// bounded evidence prefix; the method returns report-safe findings.
    /// </summary>
    public static List<BehaviorFinding> SanitizeFindings(IEnumerable<BehaviorFinding> findings, ReportEventSamplingOptions? options = null)
    {
        var resolvedOptions = options ?? DefaultOptions;
        return findings.Select(finding => finding with
        {
            Evidence = finding.Evidence
                .Take(resolvedOptions.MaxEvidenceEventsPerFinding)
                .Select(evt => SanitizeEvent(evt, resolvedOptions))
                .ToList()
        }).ToList();
    }

    /// <summary>
    /// Truncates one event's unbounded fields for safe HTML/JSON embedding.
    /// Inputs are a normalized event and sampling options; processing preserves
    /// common fields while bounding path, command line, and data payloads.
    /// </summary>
    public static SandboxEvent SanitizeEvent(SandboxEvent evt, ReportEventSamplingOptions? options = null)
    {
        var resolvedOptions = options ?? DefaultOptions;
        return evt with
        {
            EventType = string.IsNullOrWhiteSpace(evt.EventType) ? "unknown" : evt.EventType,
            Source = string.IsNullOrWhiteSpace(evt.Source) ? "guest" : evt.Source,
            Path = Truncate(evt.Path, resolvedOptions.MaxPathCharacters),
            CommandLine = Truncate(evt.CommandLine, resolvedOptions.MaxPathCharacters),
            Data = SanitizeData(evt, resolvedOptions)
        };
    }

    private static IEnumerable<SandboxEvent> SelectEvents(IReadOnlyList<SandboxEvent> orderedEvents, ReportEventSamplingOptions options)
    {
        var inlineCandidates = orderedEvents
            .Where(static evt => !IsLowValueOperationalInlineEvent(evt))
            .ToList();

        if (inlineCandidates.Count <= options.MaxInlineEvents)
        {
            return inlineCandidates;
        }

        var selected = new bool[inlineCandidates.Count];
        var perType = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var selectedCount = 0;

        for (var index = 0; index < inlineCandidates.Count && selectedCount < options.MaxInlineEvents; index++)
        {
            var evt = inlineCandidates[index];
            var eventType = NormalizeEventType(evt.EventType);
            var typeLimit = IsHighValueReportEvent(evt)
                ? options.MaxHighValueEventsPerType
                : options.MaxEventsPerType;

            perType.TryGetValue(eventType, out var currentForType);
            if (currentForType >= typeLimit)
            {
                continue;
            }

            selected[index] = true;
            selectedCount++;
            perType[eventType] = currentForType + 1;
        }

        // If the first pass did not reach the requested max because most events
        // were one noisy type, keep the report intentionally smaller. Raw JSONL
        // remains the authority; avoiding a fill pass prevents driver.file or
        // registry noise from overwhelming user-facing reports.
        var result = new List<SandboxEvent>(selectedCount);
        for (var index = 0; index < inlineCandidates.Count; index++)
        {
            if (selected[index])
            {
                result.Add(inlineCandidates[index]);
            }
        }

        return result;
    }

    private static bool IsLowValueOperationalInlineEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        if (TextEqualsAny(
                eventType,
                "agent.start",
                "environment.snapshot",
                "environment.detail",
                "service.snapshot",
                "scheduled_task.snapshot",
                "startup_item.snapshot",
                "registry.run.snapshot",
                "dns.cache.snapshot",
                "network.hosts.snapshot",
                "network.proxy.snapshot",
                "network.netstat.snapshot",
                "network.tcp.listener.snapshot",
                "network.udp.listener.snapshot"))
        {
            return true;
        }

        return EventDataBoolTrue(
                evt,
                "baselineSnapshot",
                "inventorySnapshot",
                "operationalEvent",
                "hostControlPlane",
                "hostGenerated") &&
            !EventDataBoolTrue(evt, "behaviorCounted", "sampleBehaviorCandidate", "strongSampleCorrelation");
    }

    private static SandboxEvent BuildSamplingMarker(
        ReportEventSamplingResult result,
        ReportEventSamplingOptions options,
        string? jobRoot,
        string? eventsPath,
        string? driverEventsPath)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["reason"] = "raw event volume exceeded report inline limit",
            ["zhMessage"] = "报告内联事件数量超过上限，已保留代表性事件并保留原始事件文件路径。",
            ["zhHint"] = "该行是 Host 报告采样标记，behaviorCounted=false；完整事件仍在 rawEventsPath/driverEventsPath 或 report.json 中。",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["sampleBehaviorCandidate"] = "false",
            ["sampleBehaviorCandidateReason"] = "report-event-sampling-marker-not-sample-behavior",
            ["behaviorScope"] = "host-operational",
            ["eventKind"] = "diagnostic",
            ["hostGenerated"] = "true",
            ["behaviorCountingPolicy"] = "report-sampling-markers-are-not-sample-behavior",
            ["rawEventCount"] = result.RawEventCount.ToString(),
            ["selectedRawEventCount"] = result.SelectedRawEventCount.ToString(),
            ["reportEventCount"] = (result.SelectedRawEventCount + 1).ToString(),
            ["omittedEventCount"] = result.OmittedEventCount.ToString(),
            ["maxInlineEvents"] = options.MaxInlineEvents.ToString(),
            ["maxEventsPerType"] = options.MaxEventsPerType.ToString(),
            ["maxHighValueEventsPerType"] = options.MaxHighValueEventsPerType.ToString()
        };

        if (!string.IsNullOrWhiteSpace(eventsPath))
        {
            data["rawEventsPath"] = eventsPath;
        }

        if (!string.IsNullOrWhiteSpace(driverEventsPath))
        {
            data["driverEventsPath"] = driverEventsPath;
        }

        return new SandboxEvent
        {
            EventType = "report.events.sampled",
            Timestamp = DateTimeOffset.UtcNow,
            Source = "host",
            Path = jobRoot,
            Data = data
        };
    }

    private static bool IsHighValueReportEvent(SandboxEvent evt)
    {
        var eventType = evt.EventType ?? string.Empty;
        return eventType.Contains("process", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("static.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("probe.", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("artifact", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("network", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("tcp", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("dns", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("r0collector", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("agent.", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("report.", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("guest.events", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeEventType(string? eventType) =>
        string.IsNullOrWhiteSpace(eventType) ? "unknown" : eventType.Trim();

    private static Dictionary<string, string> SanitizeData(SandboxEvent evt, ReportEventSamplingOptions options)
    {
        var sanitized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var data = evt.Data;
        if (data is null || data.Count == 0)
        {
            return sanitized;
        }

        var prioritySeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in BuildPriorityDataKeys(evt))
        {
            if (!prioritySeen.Add(key))
            {
                continue;
            }

            if (sanitized.Count >= options.MaxEventDataPairs)
            {
                break;
            }

            if (data.TryGetValue(key, out var value))
            {
                sanitized[key] = Truncate(value, options.MaxEventDataValueCharacters) ?? string.Empty;
            }
        }

        foreach (var pair in data)
        {
            if (sanitized.Count >= options.MaxEventDataPairs)
            {
                break;
            }

            if (sanitized.ContainsKey(pair.Key))
            {
                continue;
            }

            sanitized[pair.Key] = Truncate(pair.Value, options.MaxEventDataValueCharacters) ?? string.Empty;
        }

        if (data.Count > sanitized.Count)
        {
            sanitized["__omittedDataPairs"] = (data.Count - sanitized.Count).ToString();
        }

        return sanitized;
    }

    private static IEnumerable<string> BuildPriorityDataKeys(SandboxEvent evt)
    {
        if ((evt.EventType ?? string.Empty).StartsWith("static.", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in StaticPriorityDataKeys)
            {
                yield return key;
            }
        }

        if (string.Equals(evt.EventType, "artifact.import_summary", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in ArtifactImportSummaryPriorityDataKeys)
            {
                yield return key;
            }
        }
        else if (string.Equals(evt.EventType, "artifact.host_imported", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in ArtifactImportPriorityDataKeys)
            {
                yield return key;
            }
        }

        if (IsNetworkReportDataEvent(evt))
        {
            foreach (var key in NetworkCommonPriorityDataKeys)
            {
                yield return key;
            }

            var eventKind = DataValue(evt.Data, "eventKind");
            var serviceHint = DataValue(evt.Data, "serviceHint");
            var eventType = evt.EventType ?? string.Empty;
            foreach (var key in NetworkKindPriorityKeys(eventType, eventKind, serviceHint))
            {
                yield return key;
            }
        }

        foreach (var key in PriorityDataKeys)
        {
            yield return key;
        }
    }

    private static IEnumerable<string> NetworkKindPriorityKeys(string eventType, string eventKind, string serviceHint)
    {
        if (IsNetworkKind(eventType, eventKind, serviceHint, "dns"))
        {
            return DnsPriorityDataKeys;
        }

        if (IsNetworkKind(eventType, eventKind, serviceHint, "http"))
        {
            return HttpPriorityDataKeys;
        }

        if (IsNetworkKind(eventType, eventKind, serviceHint, "tls") ||
            eventType.Contains("ssl", StringComparison.OrdinalIgnoreCase))
        {
            return TlsPriorityDataKeys;
        }

        return FlowPriorityDataKeys;
    }

    private static bool IsNetworkReportDataEvent(SandboxEvent evt)
    {
        var eventType = evt.EventType ?? string.Empty;
        return eventType.StartsWith("network.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("dns.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("http.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("tls.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(DataValue(evt.Data, "eventFamily"), "network", StringComparison.OrdinalIgnoreCase) ||
            IsNetworkKind(eventType, DataValue(evt.Data, "eventKind"), DataValue(evt.Data, "serviceHint"), "dns") ||
            IsNetworkKind(eventType, DataValue(evt.Data, "eventKind"), DataValue(evt.Data, "serviceHint"), "http") ||
            IsNetworkKind(eventType, DataValue(evt.Data, "eventKind"), DataValue(evt.Data, "serviceHint"), "tls") ||
            IsNetworkKind(eventType, DataValue(evt.Data, "eventKind"), DataValue(evt.Data, "serviceHint"), "connection");
    }

    private static bool IsNetworkKind(string eventType, string eventKind, string serviceHint, string expected)
    {
        return eventType.Contains(expected, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(eventKind, expected, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(serviceHint, expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string DataValue(IReadOnlyDictionary<string, string> data, string key)
    {
        return data.TryGetValue(key, out var value) ? value : string.Empty;
    }

    private static bool EventDataBoolTrue(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && IsTruthy(value))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsTruthy(string value)
    {
        return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TextEqualsAny(string value, params string[] candidates)
    {
        return candidates.Any(candidate => string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase));
    }

    private static string? Truncate(string? value, int maxCharacters)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxCharacters)
        {
            return value;
        }

        return value[..maxCharacters] + $"…<truncated {value.Length - maxCharacters} chars>";
    }
}
