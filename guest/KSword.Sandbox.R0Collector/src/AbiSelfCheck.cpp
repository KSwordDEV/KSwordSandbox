#include "AbiSelfCheck.h"

namespace KSword::Sandbox::R0Collector {
namespace {

// Input: One or more KSWORD_SANDBOX_CAPABILITY_FLAG_* bits.
// Processing: Produces a stable, pipe-delimited capability-name list for
// contract diagnostics without depending on a live driver reply.
// Return: Named capabilities or "none" when no known bits are present.
std::string CurrentCapabilityFlagNames(const unsigned long long flags) {
    std::string names;
    const auto appendName = [&](const unsigned long long bit, const char* name) {
        if ((flags & bit) == 0) {
            return;
        }

        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH, "GetHealth");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_POLL, "Poll");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS, "ReadEvents");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES, "GetCapabilities");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS, "GetStatus");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK, "SetProducerEnableMask");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS, "QueueStatusCounters");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS, "ProducerEnableBits");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS, "TypedEventPayloads");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES, "EventSchemaNames");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT, "ProcessCreateExit");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD, "ImageLoad");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER, "FileMinifilter");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK, "RegistryCallback");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE, "NetworkWfpAle");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_COMMON_METADATA, "EventCommonMetadata");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_METADATA, "ProducerMetadata");
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_SELF_NOISE_METADATA, "SelfNoiseMetadata");

    return names.empty() ? "none" : names;
}

// Input: One or more KSWORD_SANDBOX_PRODUCER_FLAG_* bits.
// Processing: Produces the public producer family names used by capabilities,
// status, producer-mask negotiation, and event-quality smoke tests.
// Return: Named producers or "none" when no known bits are present.
std::string CurrentProducerMaskNames(const unsigned long mask) {
    std::string names;
    const auto appendName = [&](const unsigned long bit, const char* name) {
        if ((mask & bit) == 0) {
            return;
        }

        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    appendName(KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER, "driver");
    appendName(KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS, "process");
    appendName(KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE, "image");
    appendName(KSWORD_SANDBOX_PRODUCER_FLAG_FILE, "file");
    appendName(KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY, "registry");
    appendName(KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK, "network");

    return names.empty() ? "none" : names;
}

// Input: Collector options from the current invocation.
// Processing: Builds a self-contained ABI/event-quality data object that can be
// emitted without opening \\.\KSwordSandboxDriver. This lets CI and operators
// verify the collector was compiled against the expected public driver header,
// CLI backpressure knobs, and JSONL noise policy before attempting a live load.
// Return: JSON object text suitable for SandboxEvent.data.
std::string BuildAbiSelfCheckData(const Options& options) {
    JsonDataObjectBuilder data;

    data.AddBool("selfCheckPassed", true);
    data.AddBool("opensDriverDevice", false);
    data.AddBool("ioctlIssued", false);
    data.AddBool("mockMode", options.mockMode);
    data.AddBool("healthOnly", options.healthOnly);
    data.AddBool("heartbeat", options.heartbeat);
    data.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("outputPath", options.outputPath);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "collector-abi-self-check", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUnsigned("highWatermark", 0);

    data.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUnsigned("abiVersionMajor", KSWORD_SANDBOX_ABI_VERSION_MAJOR);
    data.AddUnsigned("abiVersionMinor", KSWORD_SANDBOX_ABI_VERSION_MINOR);
    data.AddUnsigned("eventHeaderVersion", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    data.AddUtf8("eventHeaderVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8));
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));

    data.AddUnsigned("capabilityFlagsCurrent", KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT);
    data.AddUtf8("capabilityFlagsCurrentHex", HexUnsignedLongLong(KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT, 16));
    data.AddUtf8("capabilityFlagNames", CurrentCapabilityFlagNames(KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT));
    data.AddUnsigned("producerMaskCurrent", KSWORD_SANDBOX_PRODUCER_MASK_CURRENT);
    data.AddUtf8("producerMaskCurrentHex", HexUnsignedLongLong(KSWORD_SANDBOX_PRODUCER_MASK_CURRENT, 8));
    data.AddUtf8("producerMaskCurrentNames", CurrentProducerMaskNames(KSWORD_SANDBOX_PRODUCER_MASK_CURRENT));
    data.AddUnsigned("producerMaskDefault", KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT);
    data.AddUtf8("producerMaskDefaultHex", HexUnsignedLongLong(KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT, 8));
    data.AddUtf8("producerMaskDefaultNames", CurrentProducerMaskNames(KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT));

    data.AddUnsigned("eventHeaderSize", sizeof(KSWORD_SANDBOX_EVENT_HEADER));
    data.AddUnsigned("healthReplySize", sizeof(KSWORD_SANDBOX_HEALTH_REPLY));
    data.AddUnsigned("healthReplyLegacyMinimumBytes", kHealthReplyLegacyMinimumBytes);
    data.AddUnsigned("healthReplyProducerMaskBytes", kHealthReplyProducerMaskBytes);
    data.AddUnsigned("healthProducerMasksAvailableFlag", KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE);
    data.AddUtf8("healthProducerMasksAvailableFlagHex", HexUnsignedLongLong(KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE, 8));
    data.AddUtf8(
        "healthProducerMasksCompatibilityPolicy",
        "GET_HEALTH accepts legacy-sized replies; producer masks require KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE and returned field bytes");
    data.AddUnsigned("pollReplySize", sizeof(KSWORD_SANDBOX_POLL_REPLY));
    data.AddUnsigned("capabilitiesReplySize", sizeof(KSWORD_SANDBOX_CAPABILITIES_REPLY));
    data.AddUnsigned("statusReplySize", sizeof(KSWORD_SANDBOX_STATUS_REPLY));
    data.AddUnsigned("setProducerEnableMaskRequestSize", sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST));
    data.AddUnsigned("setProducerEnableMaskReplySize", sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY));
    data.AddUnsigned("readEventsRequestSize", sizeof(KSWORD_SANDBOX_READ_EVENTS_REQUEST));
    data.AddUnsigned("readEventsReplyHeaderSize", KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);
    data.AddUnsigned("driverLoadPayloadSize", sizeof(KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD));
    data.AddUnsigned("processPayloadSize", sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD));
    data.AddUnsigned("imagePayloadSize", sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD));
    data.AddUnsigned("filePayloadSize", sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD));
    data.AddUnsigned("registryPayloadSize", sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD));
    data.AddUnsigned("networkPayloadSize", sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD));
    data.AddUnsigned("eventMaxPayloadSize", KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
    data.AddUtf8("eventRingCapacitySource", "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES.EventRingCapacity");

    data.AddUnsigned("readEventsBufferBytes", kReadEventsBufferBytes);
    data.AddUnsigned("defaultReadEventsMaxEvents", kReadEventsMaxEvents);
    data.AddUnsigned("requestedMaxEvents", options.readEventsMaxEvents);
    data.AddUnsigned("readEventsMaxEvents", options.readEventsMaxEvents);
    data.AddUtf8("maxEventsBounds", "1..1024");
    data.AddSigned("maxReadBatches", options.maxReadBatches);
    data.AddUtf8("maxReadBatchesMode", "0=unbounded;n=stop-after-n-successful-READ_EVENTS-batches");
    data.AddUnsigned("driverEventSampleStride", options.driverEventSampleStride);
    data.AddUtf8(
        "driverEventSamplingPolicy",
        options.driverEventSampleStride <= 1
            ? "none; every eligible driver row is emitted unless self-noise suppression applies"
            : "stride; emit the first eligible driver row and every nth eligible row, with skipped rows counted in r0collector.driverReadEvents");
    data.AddWide(
        "zhDriverEventSamplingPolicy",
        options.driverEventSampleStride <= 1
            ? L"\u65e0\u91c7\u6837\uff1b\u9664\u81ea\u8eab\u566a\u58f0\u6291\u5236\u5916\uff0c\u6bcf\u6761\u7b26\u5408\u6761\u4ef6\u7684 driver \u884c\u90fd\u4f1a\u5199\u51fa\u3002"
            : L"\u542f\u7528\u6b65\u957f\u91c7\u6837\uff1b\u5199\u51fa\u7b2c\u4e00\u6761\u7b26\u5408\u6761\u4ef6\u7684 driver \u884c\u548c\u6bcf\u7b2c n \u6761\uff0c\u8df3\u8fc7\u6570\u91cf\u8bb0\u5f55\u5728 r0collector.driverReadEvents\u3002");
    data.AddBool("enableMaskSpecified", options.enableMaskSpecified);
    data.AddUnsigned("enableMask", options.enableMask);
    data.AddUtf8("enableMaskHex", HexUnsignedLongLong(options.enableMask, 8));

    data.AddUtf8("readEventsRequestFlagsPolicy", "always-zero");
    data.AddUtf8("producerSelectionPolicy", "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK only");
    data.AddUtf8(
        "collectorSelfNoisePolicy",
        options.suppressSelfNoise
            ? "default live READ_EVENTS import suppresses collector PID, collector output JSONL, and known KSword infrastructure paths; --emit-self-noise emits those rows with selfNoise=true"
            : "--emit-self-noise active; collector and KSword infrastructure rows are emitted with selfNoise=true instead of being suppressed");
    data.AddWide(
        "zhCollectorSelfNoisePolicy",
        options.suppressSelfNoise
            ? L"\u9ed8\u8ba4\u6291\u5236 Collector PID\u3001Collector \u8f93\u51fa JSONL \u548c\u5df2\u77e5 KSword \u57fa\u7840\u8bbe\u65bd\u8def\u5f84\uff1b\u9700\u8981\u8bca\u65ad\u6291\u5236\u51b3\u7b56\u65f6\u53ef\u4f7f\u7528 --emit-self-noise\u3002"
            : L"\u5df2\u542f\u7528 --emit-self-noise\uff1bCollector/KSword \u57fa\u7840\u8bbe\u65bd\u884c\u4f1a\u5199\u51fa\uff0c\u5e76\u6807\u8bb0 selfNoise=true\u3002");
    data.AddUtf8("jsonlNoisePolicy", "blank lines ignored by live reader; malformed lines preserved by host import as driver.parse_error; valid rows with extra fields tolerated");
    data.AddWide("zhJsonlNoisePolicy", L"\u5b9e\u65f6\u8bfb\u53d6\u5668\u5ffd\u7565\u7a7a\u884c\uff1b\u7578\u5f62 JSONL \u7531 Host import \u4fdd\u7559\u4e3a driver.parse_error\uff1b\u5305\u542b\u989d\u5916\u5b57\u6bb5\u7684\u5408\u6cd5\u884c\u4f1a\u88ab\u5bb9\u5fcd\u3002");
    data.AddUtf8("jsonlMalformedPolicy", "collector never emits malformed rows except when --inject-jsonl-noise is explicitly requested; live readers skip malformed rows and host import preserves them as driver.parse_error evidence");
    data.AddWide("zhJsonlMalformedPolicy", L"Collector \u4ec5\u5728\u663e\u5f0f --inject-jsonl-noise \u65f6\u53d1\u51fa\u7578\u5f62\u884c\uff1b\u5b9e\u65f6\u8bfb\u53d6\u5668\u8df3\u8fc7\u7578\u5f62\u884c\uff0cHost import \u5c06\u5176\u4fdd\u7559\u4e3a driver.parse_error \u8bc1\u636e\u3002");
    data.AddUtf8("kernelBackpressurePolicy", "nonblocking producers; fixed ring overwrites oldest unread record on overflow");
    data.AddWide("zhKernelBackpressurePolicy", L"\u5185\u6838 producer \u975e\u963b\u585e\uff1b\u56fa\u5b9a\u73af\u5f62\u7f13\u51b2\u533a\u6ea2\u51fa\u65f6\u8986\u76d6\u6700\u65e7\u672a\u8bfb\u8bb0\u5f55\u3002");
    data.AddUtf8("queueLossEvidence", "lostCount|TotalEventsDropped|EventsDropped|TotalEventsSuppressed|TotalEventsBackpressured|ProducerDroppedMask|ProducerSuppressedMask|ProducerBackpressureMask|NextSequence|sequence|queueHighWatermark|highWatermark");
    data.AddUtf8("stableJsonlFields", "sequence|sequenceMeaning|lost|lostCount|loss|lossObserved|backpressure|backpressureObserved|backpressureReason|highWatermark|lastEnqueueFailureStatus|noise|collectorNoise|collectorSelfNoise|selfProcess|selfNoise|selfNoiseReason|selfNoiseAction|collectorSuppressed|producer|producerCategory|eventOrigin|subjectKind|actorRole|subjectRole|processIdSource|operationName|status|pathTruncated|schema|eventSchemaName|eventSchemaVersion|eligible|processed|emitted|suppressed|skipped|head|tail|sampling|producerDroppedMask|producerSuppressedMask|producerBackpressureMask|effectiveProducerMask|lastFailureNtStatus");
    data.AddUtf8("collectorSelfCheckContract", "--abi-self-check emits this row and exits before CreateFileW/DeviceIoControl");
    data.AddWide("zhCollectorSelfCheckContract", L"--abi-self-check \u4f1a\u53d1\u51fa\u8be5\u884c\uff0c\u5e76\u5728 CreateFileW/DeviceIoControl \u4e4b\u524d\u9000\u51fa\u3002");

    return data.Build();
}

} // namespace

// Input: Event sink and current collector options.
// Processing: Emits one r0collector.abiSelfCheck row with compile-time ABI,
// capability, producer-mask, backpressure, and JSONL noise-policy evidence.
// Return: true if the event was written successfully.
bool EmitAbiSelfCheck(EventWriter& writer, const Options& options) {
    SandboxEventFields event;
    event.eventType = "r0collector.abiSelfCheck";
    event.path = options.devicePath;
    event.dataJson = BuildAbiSelfCheckData(options);
    return EmitEvent(writer, event);
}

// Input: Collector options and already-open JSONL sink.
// Processing: Runs the no-device ABI self-check mode and records a stopped row.
// Return: Process exit code.
int RunAbiSelfCheckMode(const Options& options, EventWriter& writer) {
    if (!EmitAbiSelfCheck(writer, options)) {
        return kExitRuntimeFailure;
    }

    SandboxEventFields stoppedEvent;
    stoppedEvent.eventType = "r0collector.stopped";
    stoppedEvent.path = options.devicePath;

    JsonDataObjectBuilder data;
    data.AddUtf8("reason", "abiSelfCheckComplete");
    data.AddBool("ioctlIssued", false);
    data.AddBool("opensDriverDevice", false);
    data.AddBool("abiSelfCheck", true);
    data.AddBool("healthOnly", options.healthOnly);
    data.AddBool("heartbeat", options.heartbeat);
    data.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "collector-stopped", "collector-lifecycle");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUnsigned("highWatermark", 0);
    stoppedEvent.dataJson = data.Build();

    return EmitEvent(writer, stoppedEvent) ? kExitSuccess : kExitRuntimeFailure;
}

} // namespace KSword::Sandbox::R0Collector
