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

    public int MaxEvidenceEventsPerFinding { get; init; } = 50;

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

    /// <summary>
    /// Number of rows intentionally kept out of the inline report because they
    /// are host/agent lifecycle noise. These rows remain available in the raw
    /// guest/driver event files and do not make the report claim that volume
    /// sampling occurred.
    /// </summary>
    public int ExcludedEventCount { get; init; }

    /// <summary>
    /// Number of behavior or diagnostic rows omitted by the bounded inline
    /// quota. Policy-excluded lifecycle rows are not counted as sampled rows.
    /// </summary>
    public int OmittedEventCount => Math.Max(0, RawEventCount - SelectedRawEventCount - ExcludedEventCount);

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
        DynamicActionEvidence,
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
        ReportSamplingBucket.DynamicActionEvidence,
        ReportSamplingBucket.ProbableSampleEvidence,
        ReportSamplingBucket.GeneralBehaviorEvidence,
        ReportSamplingBucket.Diagnostics
    ];

    // Failure summaries are operator-facing evidence. Keep their diagnosis
    // visible even when the rest of a host-control-plane event is compacted.
    private static readonly string[] OperationalFailurePriorityDataKeys =
    [
        "success",
        "failedStepIndex",
        "failedStepId",
        "message",
        "error",
        "failureReason",
        "reason",
        "cleanupFailures",
        "totalSteps",
        "executedSteps",
        "duration",
        "resultPath",
        "failureHint"
    ];

    // Guest import markers are operator-facing collection outcomes. Keep the
    // count and terminal state visible when the host metadata envelope is
    // larger than the bounded event-data budget.
    private static readonly string[] GuestImportPriorityDataKeys =
    [
        "eventCount",
        "guestImportOutcome",
        "guestImportMarker",
        "guestImportMessage",
        "terminalStatus",
        "importMode",
        "resultPath"
    ];

    private static readonly string[] CollectionHealthPriorityDataKeys =
    [
        "healthStatus",
        "artifactMissing",
        "sourceEventType",
        "collectionName",
        "status",
        "captureState",
        "reason",
        "zhMessage",
        "zhHint"
    ];

    private static readonly string[] PcapImportPriorityDataKeys =
    [
        "collectionName",
        "importMode",
        // Artifact selectors/hashes keep the evidence row downloadable and
        // verifiable even when the bounded payload is full of endpoint data.
        "sourceArtifactRelativePath",
        "sourceArtifactSha256",
        "sourceArtifactSizeBytes",
        "pcapSourceArtifactRelativePath",
        "pcapDownloadSelector",
        "behaviorCounted",
        "nonbehavior",
        "notSampleBehavior",
        "sampleBehaviorCandidate",
        "sampleCorrelation",
        "sampleCorrelationStatus",
        "sampleCorrelationReason",
        // Endpoint identity is the primary user-facing value for PCAP rows.
        // Keep it before correlation/diagnostic metadata so the bounded data
        // payload cannot hide the remote IP/port behind policy fields.
        "sourceIp",
        "sourcePort",
        "sourceAddress",
        "sourceEndpoint",
        "localAddress",
        "localPort",
        "destinationIp",
        "destinationPort",
        "destinationAddress",
        "destinationEndpoint",
        "remoteAddress",
        "remotePort",
        "remoteEndpoint",
        "serverIp",
        "serverPort",
        "flowKey",
        "endpointPair",
        "owningProcessId",
        "processId",
        "pcapCorrelationAttempted",
        "pcapCorrelationOwnerPidAvailable",
        "pcapCorrelationWindowMatched",
        "pcapCorrelationWindowStartUtc",
        "pcapCorrelationWindowEndUtc",
        "pcapCorrelationStaticIocMatched",
        "pcapCorrelationStaticIoc",
        "pcapCorrelationDnsCorroborated",
        "pcapCorrelationDnsLifecycleMatched",
        "pcapCorrelationUncertainty",
        "protocolSummaryAvailable",
        "protocolSummaryState",
        "protocolSummaryStatus",
        "protocolSummaryReason",
        "protocolSummaryParser",
        "sourcePcapArtifactSha256",
        "eventFamily",
        "eventKind",
        "protocol",
        "serviceHint",
        "queryName",
        "qname",
        "domain",
        "answerAddress",
        "dnsAnswerIps",
        "answersNormalized",
        "answers",
        "host",
        "url",
        "sni",
        "serverName",
        "tls.sni",
        "tls.server_name",
        "networkTarget"
    ];

    // Synthetic R0 rows are plumbing evidence used to verify JSONL import and
    // must retain their source marker even when host metadata is verbose.
    private static readonly string[] R0MockPriorityDataKeys =
    [
        "mock",
        "stress",
        "driverEventPath",
        "typedPayloadStatus",
        "collectorAbiVersion",
        "syntheticSampleProcessId",
        "selfNoiseFilterMatched"
    ];

    // Keep malformed JSONL content available to the operator. The original
    // line identifies the producer/parser boundary and is required for repair.
    private static readonly string[] DriverParseErrorPriorityDataKeys =
    [
        "line",
        "driverEventPath",
        "parseError",
        "error",
        "reason"
    ];

    private static readonly string[] R0CapabilitiesPriorityDataKeys =
    [
        "abiVersionMajor",
        "abiVersionMinor",
        "eventHeaderVersion",
        "supportedProducerMaskHex",
        "eventSchemaName"
    ];

    private static readonly string[] R0ProducerMaskPriorityDataKeys =
    [
        "requestedEnableMaskHex",
        "effectiveEnableMaskHex",
        "supportedProducerMaskHex"
    ];

    private static readonly string[] R0StatusPriorityDataKeys =
    [
        "phase",
        "queueCapacity",
        "queueDepth",
        "queueHighWatermark",
        "highWatermark",
        "nextSequence",
        "sequence",
        "sequenceMeaning",
        "totalEventsDropped",
        "lostCount",
        "totalEventsSuppressed",
        "totalEventsBackpressured",
        "producerDroppedMaskHex",
        "producerSuppressedMaskHex",
        "producerBackpressureMaskHex",
        "lastEnqueueFailureStatus",
        "lastEnqueueFailureStatusHex",
        "effectiveProducerMaskHex"
    ];

    private static readonly string[] R0ReadEventsPriorityDataKeys =
    [
        "recordsProcessed",
        "eventsWritten",
        "lostCount",
        "highWatermark",
        "lastEnqueueFailureStatusHex",
        "sequence",
        "sequenceMeaning",
        "processed",
        "eligible",
        "eligibleEvents",
        "emitted",
        "suppressed",
        "skipped",
        "head",
        "tail",
        "eventsDropped",
        "loss",
        "lossObserved",
        "backpressure",
        "backpressureObserved",
        "backpressureReason",
        "sampling"
    ];

    private static readonly string[] R0StartedPriorityDataKeys =
    [
        "mockMode",
        "syntheticMode",
        "injectJsonlNoise",
        "stressCount",
        "StressJsonlExpectedDriverRows",
        "StressJsonlSequenceStart",
        "StressJsonlSequenceEnd",
        "StressJsonlSequenceGapCount",
        "StressJsonlLossEvidence",
        "StressJsonlBackpressureEvidence"
    ];

    private static readonly string[] R0StoppedPriorityDataKeys =
    [
        "reason",
        "ioctlIssued",
        "stressCount",
        "injectJsonlNoise",
        "driverEvents",
        "driverRecordsProcessed",
        "collectorSuppressedEvents",
        "collectorSkippedEvents"
    ];

    private static readonly string[] R0DriverEventPriorityDataKeys =
    [
        "producer",
        "schema",
        "sequence",
        "stress",
        "collectorAbiVersion",
        "syntheticSampleProcessId",
        "selfNoiseFilterMatched"
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
        "healthStatus",
        "artifactMissing",
        "sourceEventType",
        "status",
        "captureState",
        "reason",
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
        "flowKey",
        "connection",
        "local",
        "remote",
        "localAddress",
        "localPort",
        "remoteAddress",
        "remotePort",
        "owningPid",
        "owningProcessId",
        "processId",
        "rootProcessId"
    ];

    private static readonly string[] FilePriorityDataKeys =
    [
        "artifactRelativePath",
        "relativePath",
        "sourcePath",
        "guestFullPath",
        "path",
        "filePath",
        "rootProcessPath",
        "operation",
        "status",
        "captureState",
        "captureSource",
        "sizeBytes",
        "previousSizeBytes",
        "lastWriteUtc",
        "previousLastWriteUtc",
        "sha256",
        "hash",
        "hashStatus",
        "artifactSelector",
        "processId",
        "rootProcessId",
        "parentProcessId",
        "treeLineage"
    ];

    // Import summaries are the only network evidence left in many reports
    // when raw netstat/sidecar rows are omitted by the inline quota. Preserve
    // their counters so the report can say "environment network observed; no
    // sample attribution" instead of incorrectly presenting the lane as
    // uncollected.
    private static readonly string[] NetworkImportSummaryPriorityDataKeys =
    [
        "status",
        "eventCount",
        "connectionEventCount",
        "dnsEventCount",
        "httpEventCount",
        "tlsEventCount",
        "flowEventCount",
        "parseErrorCount",
        "nonbehaviorEventCount",
        "behaviorCountedEventCount",
        "canonicalBehaviorEventCount",
        "canonicalDnsEventCount",
        "canonicalHttpEventCount",
        "canonicalTlsEventCount",
        "canonicalFlowEventCount",
        "compatibilityEventCount",
        "rawPcapCompatibilityEventCount",
        "artifactCount",
        "pcapArtifactCount",
        "sidecarArtifactCount",
        "manifestPresent",
        "collectionHealthSummary",
        "protocols",
        "protocolHealthSummary"
    ];

    private static readonly string[] NetworkSnapshotPriorityDataKeys =
    [
        "phase",
        "rowCount",
        "emittedRows",
        "entryCount",
        "listenerCount",
        "settingCount",
        "addedCount",
        "removedCount",
        "sourceTool",
        "change"
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
        var selection = SelectEvents(orderedEvents, resolvedOptions, findingEvidenceKeys);
        var selected = selection.Events
            .Select(evt => SanitizeEvent(evt, resolvedOptions))
            .ToList();

        var result = new ReportEventSamplingResult
        {
            Events = selected,
            RawEventCount = orderedEvents.Count,
            SelectedRawEventCount = selected.Count,
            ExcludedEventCount = selection.ExcludedEventCount
        };

        if (result.WasSampled)
        {
            result.Events.Insert(0, BuildSamplingMarker(result, resolvedOptions, jobRoot, eventsPath, driverEventsPath, orderedEvents));
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

    private sealed record ReportSamplingSelection(
        IReadOnlyList<SandboxEvent> Events,
        int ExcludedEventCount);

    private static ReportSamplingSelection SelectEvents(
        IReadOnlyList<SandboxEvent> orderedEvents,
        ReportEventSamplingOptions options,
        IReadOnlySet<string> findingEvidenceKeys)
    {
        var inlineCandidates = orderedEvents
            .Select((evt, index) => new ReportSamplingCandidate(evt, index, ClassifyReportSamplingBucket(evt, findingEvidenceKeys)))
            .Where(static candidate => candidate.Bucket != ReportSamplingBucket.Excluded)
            .ToList();

        var excludedEventCount = orderedEvents.Count - inlineCandidates.Count;
        if (inlineCandidates.Count == 0)
        {
            return new ReportSamplingSelection([], excludedEventCount);
        }

        var diagnosticQuota = Math.Max(0, Math.Min(options.MaxDiagnosticEvents, options.MaxInlineEvents));
        var selectedIndexes = new HashSet<int>();
        var perType = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var boundedSelectedCount = 0;

        foreach (var bucket in ReportSamplingBucketPriority)
        {
            var bucketQuota = bucket == ReportSamplingBucket.Diagnostics
                ? diagnosticQuota
                : options.MaxInlineEvents;
            var selectedForBucket = 0;

            foreach (var candidate in inlineCandidates.Where(candidate => candidate.Bucket == bucket))
            {
                var completeDynamicEvidence = bucket == ReportSamplingBucket.DynamicActionEvidence;
                if ((!completeDynamicEvidence && boundedSelectedCount >= options.MaxInlineEvents) ||
                    (!completeDynamicEvidence && selectedForBucket >= bucketQuota))
                {
                    break;
                }

                var eventType = NormalizeEventType(candidate.Event.EventType);
                var typeLimit = completeDynamicEvidence
                    ? int.MaxValue
                    : TypeLimitForBucket(candidate.Event, bucket, options);

                perType.TryGetValue(eventType, out var currentForType);
                if (currentForType >= typeLimit)
                {
                    continue;
                }

                selectedIndexes.Add(candidate.Index);
                selectedForBucket++;
                if (!completeDynamicEvidence)
                {
                    boundedSelectedCount++;
                }
                perType[eventType] = currentForType + 1;
            }
        }

        // If the first pass did not reach the requested max because most events
        // were one noisy type, keep the report intentionally smaller. Raw JSONL
        // remains the authority; avoiding a fill pass prevents driver.file or
        // registry noise from overwhelming user-facing reports.
        return new ReportSamplingSelection(
            inlineCandidates
                .Where(candidate => selectedIndexes.Contains(candidate.Index))
                .OrderBy(static candidate => candidate.Index)
                .Select(static candidate => candidate.Event)
                .ToList(),
            excludedEventCount);
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
        var eventType = NormalizeEventType(evt.EventType);
        if (IsReportSamplingMarkerEvent(evt))
        {
            return ReportSamplingBucket.Excluded;
        }

        // Every indexed sensitive artifact needs a visible download/evidence
        // row; treating these rows as diagnostics would cap one collection
        // type at two and silently hide screenshots or packet captures.
        if (string.Equals(evt.EventType, "artifact.host_imported", StringComparison.OrdinalIgnoreCase))
        {
            return ReportSamplingBucket.GeneralBehaviorEvidence;
        }

        if (string.Equals(evt.EventType, "artifact.import_summary", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "artifact.import_rejected", StringComparison.OrdinalIgnoreCase))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        // Agent lifecycle is collection plumbing, not a sample event. Keep it
        // out of the inline report entirely; the original guest/driver files
        // remain the audit source for startup/stop timing.
        if (IsAgentLifecycleEvent(evt))
        {
            return ReportSamplingBucket.Excluded;
        }

        if (evt.EventType.StartsWith("guest.events.", StringComparison.OrdinalIgnoreCase))
        {
            return ReportSamplingBucket.GeneralBehaviorEvidence;
        }

        // A sample launch failure is operator-facing evidence even when the
        // correlation policy classifies benign GUI startup as nonbehavior. Keep
        // it ahead of the diagnostic quota so a report cannot hide the one row
        // explaining why process.start/process.exit are absent.
        if (IsSampleExecutionFailureEvent(evt))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        // Preserve any terminal analysis/import/runbook failure ahead of the
        // diagnostic quota so the report always explains a Failed status.
        if (IsAnalysisFailureEvent(evt))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        // Missing/failed artifact collection is a user-facing evidence gap.
        // Keep the health row ahead of the diagnostic quota so an empty dump,
        // screenshot, or PCAP lane is never silently mistaken for success.
        if (IsArtifactCollectionFailureEvent(evt))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        // WMI startup inventory failures explain a persistence-coverage gap.
        // Keep both before-start and after-run class/query failures visible so
        // a single sampled row cannot make the probe look healthy.
        if (IsWmiCaptureFailureEvent(evt))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        // The submitted process lifecycle is the minimum proof of what ran.
        // Keep start/exit rows ahead of bounded diagnostic and dynamic quotas
        // so a zero or nonzero exit code can never disappear from report.json.
        if (IsSampleExecutionLifecycleEvent(evt))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        // Keep a compact R0 readiness/coverage proof in report.json. These
        // rows remain explicitly nonbehavior diagnostics, but hiding every
        // collector row behind the small diagnostic quota makes a successful
        // live driver run indistinguishable from an unconfigured one.
        if (IsR0CoverageEvidenceEvent(evt))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        if (string.Equals(evt.EventType, "pcap.summary", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "pcap.import.summary", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "network.import.summary", StringComparison.OrdinalIgnoreCase))
        {
            return ReportSamplingBucket.GeneralBehaviorEvidence;
        }

        if (eventType.StartsWith("packet_capture.", StringComparison.OrdinalIgnoreCase) &&
            (eventType.Contains("summary", StringComparison.OrdinalIgnoreCase) ||
             eventType.EndsWith(".captured", StringComparison.OrdinalIgnoreCase) ||
             eventType.EndsWith(".failed", StringComparison.OrdinalIgnoreCase)))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        // Environment network snapshots are still important coverage proof;
        // keep representative rows out of the small diagnostics quota so the
        // report can distinguish observed environment traffic from no capture.
        if (IsNetworkSnapshotOrDiffEvent(evt))
        {
            return ReportSamplingBucket.GeneralBehaviorEvidence;
        }

        // Every normalized dynamic action is evidence, including rows that
        // remain environment/unknown after correlation. Route all of them
        // through the complete dynamic-evidence bucket so the report cannot
        // lose TCP edges, rename/delete rows, registry writes, startup/task
        // changes, or PowerShell children merely because attribution is weak.
        // Correlation fields still decide whether a row contributes to a
        // sample verdict; retention and attribution are separate concerns.
        if (IsDynamicActionEvidenceEvent(evt))
        {
            return ReportSamplingBucket.DynamicActionEvidence;
        }

        // Findings may deliberately reference nonbehavior/diagnostic rows
        // (for example artifact manifest and collection-gap evidence). Resolve
        // that explicit reference before the diagnostic gate so evidence cannot
        // disappear behind the small diagnostics quota.
        if (findingEvidenceKeys.Contains(BuildEventEvidenceKey(evt)))
        {
            return ReportSamplingBucket.FindingEvidence;
        }

        if (IsDiagnosticReportEvent(evt))
        {
            return ReportSamplingBucket.Diagnostics;
        }

        if (IsStrongSampleBehaviorEvent(evt))
        {
            return ReportSamplingBucket.StrongSampleBehavior;
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

    private static bool IsDynamicActionEvidenceEvent(SandboxEvent evt)
    {
        var type = NormalizeEventType(evt.EventType);
        if (type.Contains(".snapshot", StringComparison.OrdinalIgnoreCase) ||
            type.Contains(".observed", StringComparison.OrdinalIgnoreCase) ||
            type.Contains(".diff", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (EventDataEqualsAny(evt, "captureSource", "etw-live-tracerpt"))
        {
            return true;
        }

        // R0 rows retain every driver-originated class in the Guest Agent;
        // keep all typed driver activity in the dynamic evidence lane while
        // dropping explicit collector or synthetic stress noise.  This keeps
        // image/load and future driver producers visible instead of silently
        // reducing the report to process/file/registry/network rows.
        if (IsDriverSampleActivityEvent(evt))
        {
            return true;
        }

        if (type.StartsWith("process.", StringComparison.OrdinalIgnoreCase))
        {
            return type.Equals("process.start", StringComparison.OrdinalIgnoreCase) ||
                type.Equals("process.exit", StringComparison.OrdinalIgnoreCase) ||
                type.Equals("process.new", StringComparison.OrdinalIgnoreCase) ||
                type.Equals("process.tree", StringComparison.OrdinalIgnoreCase) ||
                type.Equals("process.tree_unavailable", StringComparison.OrdinalIgnoreCase);
        }

        return type.StartsWith("network.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("dns.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("http.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("tls.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("pcap.dns", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("pcap.http", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("pcap.tls", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("pcap.flow", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("eventlog.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("security.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("etw.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("file.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("registry.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("startup.", StringComparison.OrdinalIgnoreCase) ||
            type.StartsWith("scheduled_task.", StringComparison.OrdinalIgnoreCase) ||
            (type.StartsWith("service.", StringComparison.OrdinalIgnoreCase) &&
                !type.Contains("snapshot", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsDriverSampleActivityEvent(SandboxEvent evt)
    {
        var type = NormalizeEventType(evt.EventType);
        if ((evt.ProcessName?.Contains("r0collector", StringComparison.OrdinalIgnoreCase) ?? false) ||
            EventDataBoolTrue(evt, "selfProcess", "collectorSelfNoise", "collectorNoise", "selfNoise"))
        {
            return false;
        }

        if (EventDataBoolTrue(evt, "stress") ||
            !(type.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) ||
              type.StartsWith("image.", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return !EventDataBoolTrue(
            evt,
            "noise",
            "nonbehavior",
            "collectionNoise",
            "collectorNoise",
            "collectorSelfNoise",
            "selfNoise",
            "metadataOnly",
            "collectionDiagnostic");
    }

    private static bool IsStrongSampleBehaviorEvent(SandboxEvent evt)
    {
        return EventDataBoolTrue(evt, "behaviorCounted", "countsAsBehavior", "countedAsBehavior") &&
            (EventDataBoolTrue(evt, "strongSampleCorrelation") ||
             EventDataEqualsAny(evt, "sampleCorrelation", "confirmed") ||
             EventDataEqualsAny(evt, "sampleCorrelationStatus", "correlated", "confirmed") ||
             EventDataEqualsAny(evt, "sampleCorrelationStrength", "strong"));
    }

    private static bool IsSampleExecutionFailureEvent(SandboxEvent evt)
    {
        if (!string.Equals(NormalizeEventType(evt.EventType), "process.start_failed", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // The Guest Agent emits this event only for the submitted sample. The
        // path/process guard keeps malformed generic diagnostic rows out of the
        // priority lane while allowing baseline GUI failures to remain visible.
        return EventDataEqualsAny(evt, "sampleCorrelationStatus", "correlated", "confirmed", "probable", "candidate") ||
            EventDataBoolTrue(evt, "sampleBehaviorCandidate", "baselineSampleEvidence") ||
            (evt.Path?.Contains("\\incoming\\", StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private static bool IsAnalysisFailureEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        if (eventType.Contains("failure_skeleton", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("analysis.failed", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".import_failed", StringComparison.OrdinalIgnoreCase) ||
            eventType.EndsWith(".runbook.execution_result_error", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return eventType.EndsWith(".runbook.executed", StringComparison.OrdinalIgnoreCase) &&
            EventDataBoolFalse(evt, "success", "succeeded");
    }

    private static bool IsSampleExecutionLifecycleEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        if (eventType is not ("process.start" or "process.exit" or "process.timeout"))
        {
            return false;
        }

        return evt.Path?.Contains("\\incoming\\", StringComparison.OrdinalIgnoreCase) == true ||
            EventDataBoolTrue(evt, "strongSampleCorrelation", "sampleBehaviorCandidate");
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

    private static bool IsArtifactCollectionFailureEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        return (string.Equals(eventType, "collection.health", StringComparison.OrdinalIgnoreCase) ||
                eventType.StartsWith("collection-health.", StringComparison.OrdinalIgnoreCase)) &&
            (EventDataBoolTrue(evt, "artifactMissing", "captureFailed", "collectionFailed") ||
             EventDataEqualsAny(evt, "healthStatus", "failed", "missing", "rejected") ||
             EventDataEqualsAny(evt, "captureState", "failed", "missing", "rejected"));
    }

    private static bool IsWmiCaptureFailureEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        return eventType.Contains("wmi.capture_failed", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("wmi.capture-failed", StringComparison.OrdinalIgnoreCase) ||
            eventType.Contains("wmi.query_failed", StringComparison.OrdinalIgnoreCase);
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

    private static bool IsR0CoverageEvidenceEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        if (!eventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return TextEqualsAny(
            eventType,
            "r0collector.started",
            "r0collector.deviceOpened",
            "r0collector.driverHealth",
            "r0collector.driverCapabilities",
            "r0collector.driverProducerMask",
            "r0collector.driverStatus",
            "r0collector.driverReadEvents",
            "r0collector.exited");
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

    private static bool IsAgentLifecycleEvent(SandboxEvent evt)
    {
        var eventType = NormalizeEventType(evt.EventType);
        return TextEqualsAny(
            eventType,
            "agent.start",
            "agent.stop",
            "agent.ready",
            "agent.exit",
            "agent.heartbeat",
            "agent.status",
            "agent.initialized",
            "agent.shutdown");
    }

    private static SandboxEvent BuildSamplingMarker(
        ReportEventSamplingResult result,
        ReportEventSamplingOptions options,
        string? jobRoot,
        string? eventsPath,
        string? driverEventsPath,
        IReadOnlyList<SandboxEvent> orderedEvents)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["reason"] = "raw event volume exceeded report inline limit",
            ["zhMessage"] = "报告内联事件数量超过上限，已保留全部动态动作和代表性其他证据，并保留原始事件文件路径。",
            ["zhHint"] = "该行是 Host 报告采样标记，behaviorCounted=false；report.json 保留全部规范化动态动作（包括未归因行），普通静态/诊断行按配额采样；完整原始来源请查看 rawEventsPath/driverEventsPath 或已索引源文件。",
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
            ["excludedEventCount"] = result.ExcludedEventCount.ToString(),
            ["reportEventCount"] = (result.SelectedRawEventCount + 1).ToString(),
            ["omittedEventCount"] = result.OmittedEventCount.ToString(),
            ["maxInlineEvents"] = options.MaxInlineEvents.ToString(),
            ["maxEventsPerType"] = options.MaxEventsPerType.ToString(),
            ["maxHighValueEventsPerType"] = options.MaxHighValueEventsPerType.ToString(),
            ["maxDiagnosticEvents"] = options.MaxDiagnosticEvents.ToString(),
            ["dynamicActionEventsAlwaysRetained"] = "true",
            ["maxInlineEventsExcludesDynamicActions"] = "true"
        };

        var wmiFailures = orderedEvents
            .Where(evt => TextContainsAny(evt.EventType, "wmi.capture_failed", "wmi.capture-failed"))
            .ToList();
        if (wmiFailures.Count > 0)
        {
            data["wmiCaptureFailedCount"] = wmiFailures.Count.ToString();
            data["wmiCaptureFailedPhases"] = string.Join(", ", wmiFailures
                .Select(evt => FirstDataValue(evt, "phase", "capturePhase", "diagnosticStage") ?? "unknown")
                .Distinct(StringComparer.OrdinalIgnoreCase));
        }

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
        // Exit and launch diagnostics drive the runtime verdict. Keep the
        // actual code/reason even when the event also carries verbose helper
        // metadata; otherwise CLR/AV/timeout outcomes are silently erased.
        if (TextEqualsAny(evt.EventType, "process.exit", "process.start_failed", "process.execution_failed", "process.wait_failed", "process.timeout"))
        {
            foreach (var key in new[]
            {
                "exitCode", "processExitCode", "code", "timedOut", "analysisFailure",
                "failureReason", "reason", "exceptionType", "message", "stage",
                "win32Error", "win32ErrorCode", "stderr", "stdout"
            })
            {
                yield return key;
            }
        }

        if (evt.EventType.StartsWith("registry.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("startup.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("scheduled_task.", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in new[]
            {
                "operation", "operationName", "operationType", "action", "keyPath", "registryPath",
                "valueName", "value", "expandedValue", "previousValue", "taskName", "taskPath",
                "taskToRun", "commandLine", "author", "status", "nextRunTime", "lastRunTime"
            })
            {
                yield return key;
            }
        }

        if (evt.EventType.StartsWith("service.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("startup.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("scheduled_task.", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in new[]
            {
                "imagePath", "objectName", "displayName", "name", "previousImagePath",
                "previousValue", "startType", "rawSummary", "signature", "target", "value"
            })
            {
                yield return key;
            }
        }

        if (evt.EventType.StartsWith("file.", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in FilePriorityDataKeys)
            {
                yield return key;
            }
        }

        if (evt.EventType.EndsWith(".runbook.executed", StringComparison.OrdinalIgnoreCase) &&
            TextEqualsAny(DataValue(evt.Data, "success"), "false", "0", "no", "failed"))
        {
            foreach (var key in OperationalFailurePriorityDataKeys)
            {
                yield return key;
            }
        }

        if (string.Equals(evt.EventType, "collection.health", StringComparison.OrdinalIgnoreCase) ||
            (evt.EventType ?? string.Empty).StartsWith("collection-health.", StringComparison.OrdinalIgnoreCase) ||
            evt.Data.Keys.Any(key => string.Equals(key, "artifactMissing", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(key, "healthStatus", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(key, "sourceEventType", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var key in CollectionHealthPriorityDataKeys)
            {
                yield return key;
            }
        }

        if ((evt.EventType ?? string.Empty).StartsWith("guest.events.", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in GuestImportPriorityDataKeys)
            {
                yield return key;
            }
        }

        if ((evt.EventType ?? string.Empty).StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
            TextEqualsAny(DataValue(evt.Data, "sourceArtifactKind"), "PacketCapture") ||
            TextEqualsAny(DataValue(evt.Data, "evidenceRole"), "packet-capture"))
        {
            foreach (var key in PcapImportPriorityDataKeys)
            {
                yield return key;
            }
        }

        if (string.Equals(evt.EventType, "r0collector.mockDriverEvent", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in R0MockPriorityDataKeys)
            {
                yield return key;
            }
        }

        if (string.Equals(evt.EventType, "driver.parse_error", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var key in DriverParseErrorPriorityDataKeys)
            {
                yield return key;
            }
        }

        var r0EventType = evt.EventType ?? string.Empty;
        var r0Keys = r0EventType switch
        {
            "r0collector.driverCapabilities" => R0CapabilitiesPriorityDataKeys,
            "r0collector.driverProducerMask" => R0ProducerMaskPriorityDataKeys,
            "r0collector.driverStatus" => R0StatusPriorityDataKeys,
            "r0collector.driverReadEvents" => R0ReadEventsPriorityDataKeys,
            "r0collector.started" => R0StartedPriorityDataKeys,
            "r0collector.stopped" => R0StoppedPriorityDataKeys,
            _ when r0EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase) ||
                    r0EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase)
                => R0DriverEventPriorityDataKeys,
            _ => Array.Empty<string>()
        };
        foreach (var key in r0Keys)
        {
            yield return key;
        }

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
            if (IsNetworkSnapshotOrDiffEvent(evt))
            {
                foreach (var key in NetworkSnapshotPriorityDataKeys)
                {
                    yield return key;
                }
            }

            foreach (var key in NetworkCommonPriorityDataKeys)
            {
                yield return key;
            }

            if (string.Equals(evt.EventType, "network.import.summary", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(evt.EventType, "pcap.summary", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(evt.EventType, "pcap.import.summary", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var key in NetworkImportSummaryPriorityDataKeys)
                {
                    yield return key;
                }
            }

            var eventKind = DataValue(evt.Data, "eventKind");
            var serviceHint = DataValue(evt.Data, "serviceHint");
            foreach (var key in NetworkKindPriorityKeys(evt.EventType ?? string.Empty, eventKind, serviceHint))
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

    private static bool IsNetworkSnapshotOrDiffEvent(SandboxEvent evt)
    {
        var eventType = evt.EventType ?? string.Empty;
        return IsNetworkReportDataEvent(evt) &&
            (eventType.Contains(".snapshot", StringComparison.OrdinalIgnoreCase) ||
             eventType.Contains(".diff", StringComparison.OrdinalIgnoreCase));
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
