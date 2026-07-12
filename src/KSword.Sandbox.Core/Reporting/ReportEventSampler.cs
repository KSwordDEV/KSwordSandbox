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

    public int MaxDiagnosticEvents { get; init; } = 12;

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

    private enum ReportSamplingBucket
    {
        StrongSampleBehavior,
        FindingEvidence,
        ProbableSampleEvidence,
        GeneralBehaviorEvidence,
        Diagnostics,
        Excluded
    }

    private sealed record ReportSamplingCandidate(SandboxEvent Event, int Index, ReportSamplingBucket Bucket);

    private static readonly ReportSamplingBucket[] ReportSamplingBucketPriority =
    [
        ReportSamplingBucket.StrongSampleBehavior,
        ReportSamplingBucket.FindingEvidence,
        ReportSamplingBucket.ProbableSampleEvidence,
        ReportSamplingBucket.GeneralBehaviorEvidence,
        ReportSamplingBucket.Diagnostics
    ];

    private static readonly string[] PriorityDataKeys =
    [
        "collectionName",
        "evidenceRole",
        "startupSurface",
        "startupCategory",
        "startupSource",
        "autostartKind",
        "target",
        "registryKeyPath",
        "serviceName",
        "serviceType",
        "serviceDll",
        "taskName",
        "taskToRun",
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
        string? driverEventsPath = null,
        IEnumerable<BehaviorFinding>? findings = null)
    {
        var resolvedOptions = options ?? DefaultOptions;
        var orderedEvents = rawEvents.OrderBy(evt => evt.Timestamp).ToList();
        var findingEvidenceKeys = BuildFindingEvidenceKeys(findings);
        var selected = SelectEvents(orderedEvents, resolvedOptions, findingEvidenceKeys)
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

    private static IEnumerable<SandboxEvent> SelectEvents(
        IReadOnlyList<SandboxEvent> orderedEvents,
        ReportEventSamplingOptions options,
        IReadOnlySet<string> findingEvidenceKeys)
    {
        var inlineCandidates = orderedEvents
            .Select((evt, index) => new ReportSamplingCandidate(evt, index, ClassifyReportSamplingBucket(evt, findingEvidenceKeys)))
            .Where(static candidate => candidate.Bucket != ReportSamplingBucket.Excluded)
            .ToList();

        if (inlineCandidates.Count == 0)
        {
            return [];
        }

        var diagnosticQuota = Math.Max(0, Math.Min(options.MaxDiagnosticEvents, options.MaxInlineEvents));
        var diagnosticCount = inlineCandidates.Count(static candidate => candidate.Bucket == ReportSamplingBucket.Diagnostics);
        if (inlineCandidates.Count <= options.MaxInlineEvents && diagnosticCount <= diagnosticQuota)
        {
            return inlineCandidates.Select(static candidate => candidate.Event);
        }

        var selectedIndexes = new HashSet<int>();
        var perType = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var bucket in ReportSamplingBucketPriority)
        {
            var bucketQuota = bucket == ReportSamplingBucket.Diagnostics
                ? diagnosticQuota
                : options.MaxInlineEvents;
            var selectedForBucket = 0;

            foreach (var candidate in inlineCandidates.Where(candidate => candidate.Bucket == bucket))
            {
                if (selectedIndexes.Count >= options.MaxInlineEvents || selectedForBucket >= bucketQuota)
                {
                    break;
                }

                var eventType = NormalizeEventType(candidate.Event.EventType);
                var typeLimit = TypeLimitForBucket(candidate.Event, bucket, options);

                perType.TryGetValue(eventType, out var currentForType);
                if (currentForType >= typeLimit)
                {
                    continue;
                }

                selectedIndexes.Add(candidate.Index);
                selectedForBucket++;
                perType[eventType] = currentForType + 1;
            }
        }

        // If the first pass did not reach the requested max because most events
        // were one noisy type, keep the report intentionally smaller. Raw JSONL
        // remains the authority; avoiding a fill pass prevents driver.file or
        // registry noise from overwhelming user-facing reports.
        return inlineCandidates
            .Where(candidate => selectedIndexes.Contains(candidate.Index))
            .OrderBy(static candidate => candidate.Index)
            .Select(static candidate => candidate.Event)
            .ToList();
    }

    private static HashSet<string> BuildFindingEvidenceKeys(IEnumerable<BehaviorFinding>? findings)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        if (findings is null)
        {
            return keys;
        }

        foreach (var finding in findings)
        {
            foreach (var evidence in finding.Evidence)
            {
                keys.Add(BuildEventEvidenceKey(evidence));
            }
        }

        return keys;
    }

    private static ReportSamplingBucket ClassifyReportSamplingBucket(
        SandboxEvent evt,
        IReadOnlySet<string> findingEvidenceKeys)
    {
        if (IsReportSamplingMarkerEvent(evt))
        {
            return ReportSamplingBucket.Excluded;
        }

        if (IsDiagnosticReportEvent(evt))
        {
            return ReportSamplingBucket.Diagnostics;
        }

        if (IsStrongSampleBehaviorEvent(evt))
        {
            return ReportSamplingBucket.StrongSampleBehavior;
        }

        if (findingEvidenceKeys.Contains(BuildEventEvidenceKey(evt)))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        if (IsProbableSampleEvidenceEvent(evt))
        {
            return ReportSamplingBucket.ProbableSampleEvidence;
        }

        return IsHighValueReportEvent(evt)
            ? ReportSamplingBucket.GeneralBehaviorEvidence
            : ReportSamplingBucket.Diagnostics;
    }

    private static int TypeLimitForBucket(
        SandboxEvent evt,
        ReportSamplingBucket bucket,
        ReportEventSamplingOptions options)
    {
        if (bucket == ReportSamplingBucket.Diagnostics)
        {
            return Math.Max(1, Math.Min(2, options.MaxEventsPerType));
        }

        return IsHighValueReportEvent(evt)
            ? options.MaxHighValueEventsPerType
            : options.MaxEventsPerType;
    }

    private static bool IsStrongSampleBehaviorEvent(SandboxEvent evt)
    {
        return EventDataBoolTrue(evt, "behaviorCounted", "countsAsBehavior", "countedAsBehavior") &&
            (EventDataBoolTrue(evt, "strongSampleCorrelation") ||
             EventDataEqualsAny(evt, "sampleCorrelation", "confirmed") ||
             EventDataEqualsAny(evt, "sampleCorrelationStatus", "correlated", "confirmed") ||
             EventDataEqualsAny(evt, "sampleCorrelationStrength", "strong"));
    }

    private static bool IsProbableSampleEvidenceEvent(SandboxEvent evt)
    {
        if (!EventDataBoolTrue(evt, "behaviorCounted", "countsAsBehavior", "countedAsBehavior") &&
            !EventDataBoolTrue(evt, "sampleBehaviorCandidate", "sample_behavior_candidate"))
        {
            return false;
        }

        return EventDataBoolTrue(evt, "sampleBehaviorCandidate", "sample_behavior_candidate") ||
            EventDataEqualsAny(evt, "sampleCorrelation", "probable", "candidate") ||
            EventDataEqualsAny(evt, "sampleCorrelationStatus", "probable", "candidate") ||
            EventDataEqualsAny(evt, "sampleCorrelationStrength", "medium", "probable") ||
            EventDataEqualsAny(evt, "evidenceDisposition", "behavior-candidate");
    }

    private static bool IsDiagnosticReportEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        if (IsLowValueOperationalInlineEvent(evt) ||
            IsDisabledArtifactCollectionEvent(evt) ||
            eventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("collection-health.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("etw_security.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("report.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("guest.events.", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("artifact.import", StringComparison.OrdinalIgnoreCase) ||
            eventType.StartsWith("artifact.manifest.", StringComparison.OrdinalIgnoreCase) ||
            TextEqualsAny(eventType, "artifact.host_imported", "network.health", "pcap.parse_error", "driver.parse_error", "driver.read_error"))
        {
            return true;
        }

        if (eventType.StartsWith("security_eventlog.", StringComparison.OrdinalIgnoreCase) &&
            (IsReadinessOrStatusEvent(evt) ||
             eventType.Contains(".audit_policy.", StringComparison.OrdinalIgnoreCase) ||
             eventType.Contains(".collection.", StringComparison.OrdinalIgnoreCase) ||
             eventType.Contains(".fallback_surface.", StringComparison.OrdinalIgnoreCase) ||
             eventType.EndsWith(".skipped", StringComparison.OrdinalIgnoreCase) ||
             eventType.EndsWith(".query_failed", StringComparison.OrdinalIgnoreCase) ||
             eventType.EndsWith(".parse_failed", StringComparison.OrdinalIgnoreCase) ||
             eventType.EndsWith(".query.summary", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (EventDataBoolFalse(evt, "behaviorCounted", "behavior_counted", "countsAsBehavior", "countedAsBehavior") ||
            EventDataBoolFalse(evt, "sampleBehaviorCandidate", "sample_behavior_candidate", "sampleBehavior", "sample_behavior") ||
            EventDataBoolTrue(
                evt,
                "nonbehavior",
                "nonBehavior",
                "non_behavior",
                "notSampleBehavior",
                "not_sample_behavior",
                "metadataOnly",
                "metadata_only",
                "collectionHealth",
                "collectionStatus",
                "collectionDiagnostic",
                "collectionNoise",
                "collectorSelfNoise",
                "collectorNoise",
                "selfNoise",
                "selfProcess",
                "readinessOnly",
                "statusOnly",
                "healthEvent",
                "diagnosticEvent",
                "qualityEvent",
                "telemetryHealth",
                "telemetryDegraded",
                "telemetry_degraded",
                "backpressure",
                "backpressureObserved",
                "lossObserved",
                "vtQuietState",
                "operationalEvent",
                "hostGenerated",
                "hostControlPlane"))
        {
            return true;
        }

        return IsReadinessOrStatusEvent(evt);
    }

    private static bool IsReadinessOrStatusEvent(SandboxEvent evt)
    {
        return EventDataEqualsAny(
                evt,
                "eventKind",
                "nonbehavior",
                "metadata",
                "diagnostic",
                "health",
                "status",
                "summary",
                "readiness",
                "collection-status",
                "evidence-quality",
                "quiet-state",
                "enrichment-status") ||
            EventDataEqualsAny(
                evt,
                "behaviorScope",
                "collection-health",
                "network-collection-health",
                "network-import-summary",
                "raw-pcap-compatibility",
                "diagnostic",
                "status",
                "collection-status",
                "evidence-quality",
                "host-operational",
                "host-control-plane",
                "collector-diagnostic",
                "collector-lifecycle",
                "driver-health",
                "driver-readiness",
                "readiness-only",
                "setup",
                "import",
                "health",
                "readiness") ||
            EventDataEqualsAny(evt, "semanticLane", "nonbehavior", "non-behavior", "diagnostic", "collection-health") ||
            EventDataEqualsAny(evt, "sampleBehaviorBoundary", "nonbehavior-separated", "not-sample-behavior", "nonbehavior-evidence-quality") ||
            EventDataEqualsAny(evt, "collectorNoiseScope", "nonbehavior-evidence-quality", "collector-diagnostic", "collector-self-noise");
    }

    private static bool IsDisabledArtifactCollectionEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        return TextEqualsAny(
                eventType,
                "packet_capture.disabled",
                "packet-capture.disabled",
                "screenshot.disabled",
                "memory_dump.disabled",
                "memory-dump.disabled",
                "dropped_file.disabled",
                "dropped-file.disabled") ||
            eventType.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase) &&
            TextContainsAny(eventType, "packet_capture", "packet-capture", "screenshot", "memory_dump", "memory-dump", "dropped_file", "dropped-file");
    }

    private static bool IsReportSamplingMarkerEvent(SandboxEvent evt)
    {
        return string.Equals(NormalizeEventType(evt.EventType), "report.events.sampled", StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildEventEvidenceKey(SandboxEvent evt)
    {
        return string.Join(
            '\u001f',
            evt.Timestamp.UtcTicks.ToString(),
            NormalizeEventType(evt.EventType),
            evt.Source ?? string.Empty,
            evt.ProcessName ?? string.Empty,
            evt.ProcessId?.ToString() ?? string.Empty,
            evt.ParentProcessId?.ToString() ?? string.Empty,
            evt.Path ?? string.Empty,
            evt.CommandLine ?? string.Empty,
            FirstDataValue(
                evt,
                "uid",
                "eventId",
                "eventRecordId",
                "sequence",
                "flowKey",
                "processKey",
                "processGuid",
                "snapshotKey",
                "imagePath",
                "filePath",
                "keyPath",
                "queryName",
                "host",
                "uri") ?? string.Empty);
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
                "process.snapshot",
                "process.observed",
                "probe.summary",
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
            ["maxHighValueEventsPerType"] = options.MaxHighValueEventsPerType.ToString(),
            ["maxDiagnosticEvents"] = options.MaxDiagnosticEvents.ToString()
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

    private static bool EventDataBoolFalse(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && IsFalsy(value))
            {
                return true;
            }
        }

        return false;
    }

    private static bool EventDataEqualsAny(SandboxEvent evt, string key, params string[] values)
    {
        return evt.Data.TryGetValue(key, out var value) && TextEqualsAny(value, values);
    }

    private static string? FirstDataValue(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static bool IsTruthy(string value)
    {
        return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsFalsy(string value)
    {
        return string.Equals(value, "false", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "0", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "no", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TextEqualsAny(string value, params string[] candidates)
    {
        return candidates.Any(candidate => string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TextContainsAny(string value, params string[] fragments)
    {
        return fragments.Any(fragment => value.Contains(fragment, StringComparison.OrdinalIgnoreCase));
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
