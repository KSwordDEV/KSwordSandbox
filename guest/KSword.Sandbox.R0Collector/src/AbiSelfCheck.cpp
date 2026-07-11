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
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("outputPath", options.outputPath);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);

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
    data.AddBool("enableMaskSpecified", options.enableMaskSpecified);
    data.AddUnsigned("enableMask", options.enableMask);
    data.AddUtf8("enableMaskHex", HexUnsignedLongLong(options.enableMask, 8));

    data.AddUtf8("readEventsRequestFlagsPolicy", "always-zero");
    data.AddUtf8("producerSelectionPolicy", "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK only");
    data.AddUtf8("jsonlNoisePolicy", "blank lines ignored by live reader; malformed lines preserved by host import as driver.parse_error; valid rows with extra fields tolerated");
    data.AddUtf8("jsonlMalformedPolicy", "collector never emits malformed rows except when --inject-jsonl-noise is explicitly requested; live readers skip malformed rows and host import preserves them as driver.parse_error evidence");
    data.AddUtf8("kernelBackpressurePolicy", "nonblocking producers; fixed ring overwrites oldest unread record on overflow");
    data.AddUtf8("queueLossEvidence", "TotalEventsDropped|EventsDropped|TotalEventsSuppressed|NextSequence|sequence|queueHighWatermark");
    data.AddUtf8("stableJsonlFields", "sequence|lost|backpressure|noise|producer|schema|eventSchemaName|eventSchemaVersion");
    data.AddUtf8("collectorSelfCheckContract", "--abi-self-check emits this row and exits before CreateFileW/DeviceIoControl");

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
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);
    stoppedEvent.dataJson = data.Build();

    return EmitEvent(writer, stoppedEvent) ? kExitSuccess : kExitRuntimeFailure;
}

} // namespace KSword::Sandbox::R0Collector
