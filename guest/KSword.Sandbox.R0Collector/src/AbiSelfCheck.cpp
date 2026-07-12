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
    appendName(KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS, "GetNetworkStatus");

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
    data.AddUnsigned("abiSelfCheckDiagnosticsVersion", kAbiSelfCheckDiagnosticsVersion);
    data.AddUtf8("abiSelfCheckDiagnosticLevel", "abi-layout-plus-event-quality-boundaries");
    data.AddUtf8("abiSelfCheckMode", "no-device-no-ioctl-no-driver-open");
    data.AddWide(
        "zhAbiSelfCheckMode",
        L"该自检只验证 Collector 编译期 ABI、字段质量和边界声明；不会打开驱动或调用 IOCTL。");
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
    AddCollectorNonBehaviorFields(data, "collector-abi-self-check", "emit-abi-self-check-not-sample-behavior");
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
    data.AddUtf8("noiseScope", "none");
    data.AddUtf8("noiseKind", "none");
    data.AddUtf8("noiseSource", "not-noise");
    data.AddUtf8("noiseClass", "collector-diagnostic");
    data.AddUtf8("selfNoiseClass", "none");
    data.AddUtf8("collectorNoiseClass", "none");
    data.AddUtf8("noiseAction", "emit");
    data.AddUtf8("noiseDisposition", "emitted-as-collector-diagnostic");
    data.AddUtf8("noiseReasons", "none");
    data.AddUtf8("noiseFieldSet", kJsonlNoiseFieldSet);
    data.AddUtf8("noiseClassificationFieldSet", kJsonlNoiseClassificationFields);
    data.AddUtf8("noiseTaxonomyVersion", "1");
    data.AddUtf8("noiseDecision", "collector-diagnostic");
    data.AddUtf8("noiseDecisionSource", "abi-self-check-mode");
    data.AddUtf8("noiseClassificationConfidence", "high");
    data.AddUtf8("noiseProbeKind", "none");
    data.AddBool("sampleBehaviorCandidate", false);
    data.AddUtf8("sampleBehaviorCandidateReason", "abi-self-check-is-collection-diagnostic");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("collectionNoise", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddWide(
        "zhNoiseHint",
        L"ABI 自检行是采集诊断，不是样本行为；noise=false 表示它不是 JSONL 噪声注入行。");
    data.AddWide(
        "zhNoiseClassificationHint",
        L"噪声分类为 collector-diagnostic；该行用于 ABI/字段合同验证，不应进入样本行为图。");
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUnsigned("highWatermark", 0);

    data.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUtf8("abiCompatibilityDiagnosticLevel", "compile-time-no-device-contract");
    data.AddBool("abiCompatible", true);
    data.AddUtf8("abiCompatibility", "compile-time-compatible");
    data.AddUtf8("abiMismatchReasons", "none");
    data.AddUnsigned("expectedInterfaceVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("expectedInterfaceVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUnsigned("driverInterfaceVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("driverInterfaceVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddBool("interfaceVersionCompatible", true);
    data.AddUnsigned("expectedAbiVersionMajor", KSWORD_SANDBOX_ABI_VERSION_MAJOR);
    data.AddUnsigned("expectedAbiVersionMinor", KSWORD_SANDBOX_ABI_VERSION_MINOR);
    data.AddUnsigned("driverAbiVersionMajor", KSWORD_SANDBOX_ABI_VERSION_MAJOR);
    data.AddUnsigned("driverAbiVersionMinor", KSWORD_SANDBOX_ABI_VERSION_MINOR);
    data.AddBool("abiMajorMatch", true);
    data.AddBool("abiMinorForwardCompatible", true);
    data.AddUnsigned("expectedEventHeaderVersion", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    data.AddUnsigned("driverEventHeaderVersion", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    data.AddBool("eventHeaderVersionCompatible", true);
    data.AddUnsigned("expectedEventMaxPayloadSize", KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
    data.AddUnsigned("driverEventMaxPayloadSize", KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
    data.AddBool("eventMaxPayloadSizeCompatible", true);
    data.AddUtf8(
        "abiCompatibilityPolicy",
        "no-device self-check emits expected/driver aliases with compile-time values; live --diagnose and driverCapabilities rows compare returned driver bytes");
    data.AddWide(
        "zhAbiCompatibilityHint",
        L"无设备 ABI 自检使用编译期 expected/driver 别名证明 Collector 合同；live diagnose/capabilities 会比较真实驱动返回值。");
    data.AddUnsigned("abiVersionMajor", KSWORD_SANDBOX_ABI_VERSION_MAJOR);
    data.AddUnsigned("abiVersionMinor", KSWORD_SANDBOX_ABI_VERSION_MINOR);
    data.AddUnsigned("eventHeaderVersion", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    data.AddUtf8("eventHeaderVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8));
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUtf8("stableAbiVersionFields", kStableAbiVersionFields);

    data.AddUnsigned("capabilityFlagsCurrent", KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT);
    data.AddUtf8("capabilityFlagsCurrentHex", HexUnsignedLongLong(KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT, 16));
    data.AddUtf8("capabilityFlagNames", CurrentCapabilityFlagNames(KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT));
    data.AddUnsigned("producerMaskCurrent", KSWORD_SANDBOX_PRODUCER_MASK_CURRENT);
    data.AddUtf8("producerMaskCurrentHex", HexUnsignedLongLong(KSWORD_SANDBOX_PRODUCER_MASK_CURRENT, 8));
    data.AddUtf8("producerMaskCurrentNames", CurrentProducerMaskNames(KSWORD_SANDBOX_PRODUCER_MASK_CURRENT));
    data.AddUnsigned("producerMaskDefault", KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT);
    data.AddUtf8("producerMaskDefaultHex", HexUnsignedLongLong(KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT, 8));
    data.AddUtf8("producerMaskDefaultNames", CurrentProducerMaskNames(KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT));

    data.AddBool("abiGuardPassed", true);
    data.AddUtf8("abiGuardPolicy", "compile-time static_asserts plus emitted size/offset evidence for release readiness");
    data.AddWide("zhAbiGuardPolicy", L"Collector 在编译期校验关键 ABI 大小/偏移，并在 --abi-self-check 中输出证据。");
    data.AddUtf8(
        "abiGuardDiagnosticSummary",
        "event-header/status/read-events/network-status sizes and offsets match collector compile-time expectations");
    data.AddUtf8(
        "abiGuardDriftAction",
        "if any size/offset evidence changes, update public header, collector parser, docs, and smoke tests together before release");
    data.AddWide(
        "zhAbiGuardDriftAction",
        L"如果 size/offset 证据变化，请同时更新 public header、Collector parser、文档和 smoke tests 后再发布。");
    data.AddUtf8(
        "abiGuardFieldSet",
        "eventHeaderSize|eventHeaderSequenceOffset|eventHeaderLostEventsOffset|eventHeaderBackpressureEventsOffset|statusQueueHighWatermarkOffset|statusTotalEventsDroppedOffset|capabilitiesReplySize|capabilitiesCapabilityFlagsOffset|capabilitiesEventHeaderVersionOffset|setProducerEnableMaskReplySize|readEventsRequestSize|readEventsBytesWrittenOffset|readEventsEventsDroppedOffset|readEventsNextSequenceOffset|readEventsEventsOffset|networkStatusReplySize|networkStatusTodoMaskOffset|networkStatusLastDegradeReasonOffset|producerPayloadVersionFieldSet|processPayloadVersion|imagePayloadVersion|filePayloadVersion|registryPayloadVersion|networkPayloadVersion");
    data.AddUnsigned("eventHeaderSize", sizeof(KSWORD_SANDBOX_EVENT_HEADER));
    data.AddUnsigned("eventHeaderSequenceOffset", kAbiGuardEventHeaderSequenceOffset);
    data.AddUnsigned("eventHeaderLostEventsOffset", kAbiGuardEventHeaderLostEventsOffset);
    data.AddUnsigned("eventHeaderBackpressureEventsOffset", kAbiGuardEventHeaderBackpressureEventsOffset);
    data.AddUnsigned("eventHeaderOperationOffset", kAbiGuardEventHeaderOperationOffset);
    data.AddUnsigned("eventHeaderStatusOffset", kAbiGuardEventHeaderStatusOffset);
    data.AddUnsigned("eventHeaderProducerMetadataFlagsOffset", kAbiGuardEventHeaderProducerMetadataFlagsOffset);
    data.AddUnsigned("statusQueueHighWatermarkOffset", kAbiGuardStatusQueueHighWatermarkOffset);
    data.AddUnsigned("statusTotalEventsDroppedOffset", kAbiGuardStatusTotalEventsDroppedOffset);
    data.AddUnsigned("statusTotalEventsBackpressuredOffset", kAbiGuardStatusTotalEventsBackpressuredOffset);
    data.AddUnsigned("statusLastEnqueueFailureOffset", kAbiGuardStatusLastEnqueueFailureOffset);
    data.AddUnsigned("capabilitiesCapabilityFlagsOffset", kAbiGuardCapabilitiesCapabilityFlagsOffset);
    data.AddUnsigned("capabilitiesEventHeaderVersionOffset", kAbiGuardCapabilitiesEventHeaderVersionOffset);
    data.AddUnsigned("capabilitiesReadEventsReplyHeaderSizeOffset", kAbiGuardCapabilitiesReadEventsReplyHeaderSizeOffset);
    data.AddUnsigned("setProducerEnableMaskReplyEffectiveMaskOffset", kAbiGuardSetProducerEnableMaskReplyEffectiveMaskOffset);
    data.AddUnsigned("setProducerEnableMaskReplySupportedMaskOffset", kAbiGuardSetProducerEnableMaskReplySupportedMaskOffset);
    data.AddUnsigned("readEventsBytesWrittenOffset", kAbiGuardReadEventsBytesWrittenOffset);
    data.AddUnsigned("readEventsEventsDroppedOffset", kAbiGuardReadEventsEventsDroppedOffset);
    data.AddUnsigned("readEventsNextSequenceOffset", kAbiGuardReadEventsNextSequenceOffset);
    data.AddUnsigned("readEventsEventsOffset", kAbiGuardReadEventsEventsOffset);
    data.AddUnsigned("networkStatusReplySize", sizeof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY));
    data.AddUnsigned("networkStatusTodoMaskOffset", kAbiGuardNetworkStatusTodoMaskOffset);
    data.AddUnsigned("networkStatusPayloadVersionOffset", kAbiGuardNetworkStatusPayloadVersionOffset);
    data.AddUnsigned("networkStatusLastDegradeReasonOffset", kAbiGuardNetworkStatusLastDegradeReasonOffset);
    data.AddUnsigned("networkStatusClassifyCountOffset", kAbiGuardNetworkStatusClassifyCountOffset);
    data.AddUnsigned("networkStatusEventCountOffset", kAbiGuardNetworkStatusEventCountOffset);
    data.AddUnsigned("networkStatusQueueFailureCountOffset", kAbiGuardNetworkStatusQueueFailureCountOffset);
    data.AddUnsigned("networkStatusLastQueueFailureOffset", kAbiGuardNetworkStatusLastQueueFailureOffset);
    data.AddUtf8("networkStatusIoctlPolicy", "IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS is optional read-only WFP/ALE diagnostics; unavailable drivers emit r0collector.driverNetworkStatus with readinessState=degraded and collection continues");
    data.AddWide("zhNetworkStatusIoctlPolicy", L"GET_NETWORK_STATUS 是可选只读 WFP/ALE 诊断；驱动不支持时输出降级状态行并继续采集。");
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
    data.AddUtf8("producerPayloadVersionPolicy", "all v1 typed producer payloads stamp Version=0x00010000 and Size=sizeof(payload); version/size prefixes are static_assert-guarded at offsets 0/4");
    data.AddUtf8("producerPayloadVersionFieldSet", kTypedPayloadVersionFieldSet);
    data.AddUtf8("payloadVersionPolicy", "typed payload parsers accept only the fixed v1 version/size pair for the known schema and retain opaque evidence on mismatch");
    data.AddUnsigned("driverLoadPayloadVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("driverLoadPayloadVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUnsigned("processPayloadVersion", KSWORD_SANDBOX_PROCESS_EVENT_VERSION);
    data.AddUtf8("processPayloadVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_PROCESS_EVENT_VERSION, 8));
    data.AddUnsigned("imagePayloadVersion", KSWORD_SANDBOX_IMAGE_EVENT_VERSION);
    data.AddUtf8("imagePayloadVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_IMAGE_EVENT_VERSION, 8));
    data.AddUnsigned("filePayloadVersion", KSWORD_SANDBOX_FILE_EVENT_VERSION);
    data.AddUtf8("filePayloadVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_FILE_EVENT_VERSION, 8));
    data.AddUnsigned("registryPayloadVersion", KSWORD_SANDBOX_REGISTRY_EVENT_VERSION);
    data.AddUtf8("registryPayloadVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_REGISTRY_EVENT_VERSION, 8));
    data.AddUnsigned("networkPayloadVersion", KSWORD_SANDBOX_NETWORK_EVENT_VERSION);
    data.AddUtf8("networkPayloadVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_NETWORK_EVENT_VERSION, 8));
    data.AddUnsigned("driverLoadPayloadVersionOffset", kAbiGuardDriverLoadPayloadVersionOffset);
    data.AddUnsigned("driverLoadPayloadSizeOffset", kAbiGuardDriverLoadPayloadSizeOffset);
    data.AddUnsigned("processPayloadVersionOffset", kAbiGuardProcessPayloadVersionOffset);
    data.AddUnsigned("processPayloadSizeOffset", kAbiGuardProcessPayloadSizeOffset);
    data.AddUnsigned("imagePayloadVersionOffset", kAbiGuardImagePayloadVersionOffset);
    data.AddUnsigned("imagePayloadSizeOffset", kAbiGuardImagePayloadSizeOffset);
    data.AddUnsigned("filePayloadVersionOffset", kAbiGuardFilePayloadVersionOffset);
    data.AddUnsigned("filePayloadSizeOffset", kAbiGuardFilePayloadSizeOffset);
    data.AddUnsigned("registryPayloadVersionOffset", kAbiGuardRegistryPayloadVersionOffset);
    data.AddUnsigned("registryPayloadSizeOffset", kAbiGuardRegistryPayloadSizeOffset);
    data.AddUnsigned("networkPayloadVersionOffset", kAbiGuardNetworkPayloadVersionOffset);
    data.AddUnsigned("networkPayloadSizeOffset", kAbiGuardNetworkPayloadSizeOffset);
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
    data.AddUtf8(
        "selfNoiseFilterPolicy",
        "synthetic/no-device rows use kSyntheticSampleProcessId with collectorSelfNoise=false; live rows classify collector PID, collector output JSONL, and KSword infrastructure paths before emission");
    data.AddUtf8(
        "selfNoiseFilterFields",
        "selfNoiseFilterMode|selfNoiseFilterPolicy|selfNoiseFilterMatched|selfNoiseFilterAction|syntheticSampleProcessId|collectorSelfNoise|selfProcess|collectorSuppressed");
    data.AddWide(
        "zhCollectorSelfNoisePolicy",
        options.suppressSelfNoise
            ? L"\u9ed8\u8ba4\u6291\u5236 Collector PID\u3001Collector \u8f93\u51fa JSONL \u548c\u5df2\u77e5 KSword \u57fa\u7840\u8bbe\u65bd\u8def\u5f84\uff1b\u9700\u8981\u8bca\u65ad\u6291\u5236\u51b3\u7b56\u65f6\u53ef\u4f7f\u7528 --emit-self-noise\u3002"
            : L"\u5df2\u542f\u7528 --emit-self-noise\uff1bCollector/KSword \u57fa\u7840\u8bbe\u65bd\u884c\u4f1a\u5199\u51fa\uff0c\u5e76\u6807\u8bb0 selfNoise=true\u3002");
    data.AddUtf8("jsonlNoisePolicy", "blank lines ignored by live reader; malformed lines preserved by host import as driver.parse_error; valid rows with extra fields tolerated");
    data.AddWide("zhJsonlNoisePolicy", L"\u5b9e\u65f6\u8bfb\u53d6\u5668\u5ffd\u7565\u7a7a\u884c\uff1b\u7578\u5f62 JSONL \u7531 Host import \u4fdd\u7559\u4e3a driver.parse_error\uff1b\u5305\u542b\u989d\u5916\u5b57\u6bb5\u7684\u5408\u6cd5\u884c\u4f1a\u88ab\u5bb9\u5fcd\u3002");
    data.AddUtf8("jsonlMalformedPolicy", "collector never emits malformed rows except when --inject-jsonl-noise is explicitly requested in mock/stress mode; abi/diagnose/health/live modes reject noise injection before opening output/device paths");
    data.AddWide("zhJsonlMalformedPolicy", L"Collector \u4ec5\u5728 mock/stress \u6a21\u5f0f\u663e\u5f0f --inject-jsonl-noise \u65f6\u53d1\u51fa\u7578\u5f62\u884c\uff1bABI/\u5c31\u7eea/\u5065\u5eb7/\u5b9e\u65f6\u6a21\u5f0f\u4f1a\u5728\u6253\u5f00\u8f93\u51fa\u6216\u8bbe\u5907\u524d\u62d2\u7edd\u566a\u58f0\u6ce8\u5165\u3002");
    data.AddUtf8("jsonlNoiseInjectionGuard", "--inject-jsonl-noise requires mock/stress and is rejected with --abi-self-check/--diagnose/--health/live collection");
    data.AddWide("zhJsonlNoiseInjectionGuard", L"--inject-jsonl-noise \u53ea\u5141\u8bb8\u5728 mock/stress \u4e2d\u4f7f\u7528\uff1b\u4e0e ABI \u81ea\u68c0\u3001\u5c31\u7eea\u8bca\u65ad\u3001\u5065\u5eb7\u68c0\u67e5\u6216\u5b9e\u65f6\u91c7\u96c6\u51b2\u7a81\u65f6\u4f1a\u88ab\u62d2\u7edd\u3002");
    data.AddUtf8("kernelBackpressurePolicy", "nonblocking producers; fixed ring overwrites oldest unread record on overflow; backpressure=true is evidence/diagnostic, not producer blocking");
    data.AddWide("zhKernelBackpressurePolicy", L"\u5185\u6838 producer \u975e\u963b\u585e\uff1b\u56fa\u5b9a\u73af\u5f62\u7f13\u51b2\u533a\u6ea2\u51fa\u65f6\u8986\u76d6\u6700\u65e7\u672a\u8bfb\u8bb0\u5f55\uff1bbackpressure=true \u662f\u8bc1\u636e/\u8bca\u65ad\uff0c\u4e0d\u8868\u793a producer \u88ab\u963b\u585e\u3002");
    data.AddUtf8("sequenceSemantics", "event rows use concrete event Sequence; health/poll/status/readEvents summary rows use NextSequence with sequenceMeaning=nextSequence; head/tail are consumed batch sequence bounds");
    data.AddWide("zhSequenceSemantics", L"\u4e8b\u4ef6\u884c\u7684 sequence \u662f\u5177\u4f53\u4e8b\u4ef6 Sequence\uff1bhealth/poll/status/readEvents \u6458\u8981\u884c\u7684 sequence \u662f NextSequence\uff0c\u5e76\u4ee5 sequenceMeaning=nextSequence \u6807\u8bb0\uff1bhead/tail \u662f\u6279\u6b21\u5df2\u6d88\u8d39\u8bb0\u5f55\u7684 sequence \u8fb9\u754c\u3002");
    data.AddUtf8("batchSummaryFieldSet", "batchSummaryVersion|batchKind|batchCounterScope|sequenceScope|sequenceCountScope|noiseObservedCount|lossObservedCount|backpressureObservedCount|StressJsonlNoiseEvidence");
    data.AddUtf8("sequenceScopePolicy", "driver rows use sequenceScope=driver-event; live READ_EVENTS summaries use consumed-driver-event-records; synthetic stress summaries use counted-stress-driver-file-rows");
    data.AddUtf8("noiseLossCounterPolicy", "summary rows carry explicit noiseObservedCount/lossObservedCount/backpressureObservedCount plus StressJsonlNoiseEvidence so no-device and live evidence can be compared without scanning every driver row");
    data.AddUtf8("StressJsonlNoiseEvidence", kStressJsonlNoiseEvidence);
    data.AddWide("zhSequenceScopePolicy", L"driver 行、live 批次摘要和 synthetic stress 摘要使用不同 sequenceScope，避免把 nextSequence 摘要值当成具体事件序列。");
    data.AddUtf8("driverEventSequenceMeaning", "eventSequence");
    data.AddUtf8("driverEventSequenceScope", "driver-event");
    data.AddUtf8("driverEventSequencePolicy", "driver rows emit sequenceMeaning=eventSequence and sequenceConcrete=true; summaries emit sequenceMeaning=nextSequence");
    data.AddWide("zhDriverEventSequencePolicy", L"driver \u4e8b\u4ef6\u884c\u4f7f\u7528 sequenceMeaning=eventSequence \u548c sequenceConcrete=true\uff1b\u6458\u8981\u884c\u4f7f\u7528 sequenceMeaning=nextSequence\u3002");
    data.AddUtf8("driverEventStressFieldSet", "stress|stressOrdinal|stressCount|stressCorpusRole|StressJsonlExpectedDriverRows|StressJsonlSequenceStart|StressJsonlSequenceEnd|StressJsonlSequenceGapCount");
    data.AddUtf8("driverEventStressPolicy", "live driver rows emit stress=false with stable stress keys; synthetic counted stress rows override stress=true and carry contiguous sequence evidence");
    data.AddUtf8("driverEventPayloadVersionPolicy", "all live and synthetic driver rows emit payloadVersion, payloadVersionHex, payloadSchemaVersion, expectedPayloadVersion, payloadVersionStatus, and producerPayloadVersionFieldSet");
    data.AddWide("zhDriverEventQualityPolicy", L"live driver 行和 synthetic/stress 行都必须保留 ABI、payload version、stress 与 noise 字段，便于无设备与真实采集对齐。");
    data.AddUtf8("networkServiceHintPolicy", "port-protocol heuristic: 53=dns, 80/8080/8000=http, 443/8443=tls; fields include serviceHintSource/serviceHintConfidence/serviceHintDns/serviceHintHttp/serviceHintTls");
    data.AddUnsigned("networkCorrelationContractVersion", KSWORD_SANDBOX_NETWORK_CORRELATION_CONTRACT_VERSION);
    data.AddUnsigned("networkFlowKeyVersion", KSWORD_SANDBOX_NETWORK_FLOW_KEY_VERSION);
    data.AddUnsigned("networkProtocolBoundaryVersion", KSWORD_SANDBOX_NETWORK_PROTOCOL_BOUNDARY_VERSION);
    data.AddUtf8("networkFlowKeyPolicy", "flowKeyVersion is the public constant KSWORD_SANDBOX_NETWORK_FLOW_KEY_VERSION; flowKey uses protocol|sourceEndpoint|destinationEndpoint with direction-aware endpoints plus endpointPair/source/destination aliases");
    data.AddUtf8("networkWfpEventNamingPolicy", "driver.network rows emit wfpEventFamily/wfpEventName/wfpLayerSemanticName so reports can identify WFP ALE connect/recv-accept IPv4/IPv6 without WDK constants");
    data.AddUtf8("networkWfpEventNameFields", kNetworkWfpEventNameFields);
    data.AddUtf8("kernelNetworkProducerScope", "wfp-ale-endpoint-metadata-no-payload");
    data.AddBool("rawPacketPayloadAvailable", false);
    data.AddBool("kernelPayloadParserEnabled", false);
    data.AddUtf8("networkProtocolParserBoundary", "R0 WFP/ALE rows are endpoint/port/layer evidence only; raw packets, dnsQueryName, httpHost/httpUri/httpMethod, tlsSni/certificates require PCAP/browser/sidecar correlation and are marked unavailable in mock rows");
    data.AddUtf8("networkProtocolBoundaryFields", kNetworkProtocolBoundaryFields);
    data.AddUtf8("networkCorrelationStableFields", kNetworkCorrelationStableFields);
    data.AddUtf8("networkCorrelationPolicy", "R0 rows are join candidates only: networkCorrelationRole=r0-endpoint-candidate, pcapCorrelationRole=join-candidate-not-l7-owner, and pcapCorrelationJoinFields names flowKey/endpoints/protocol/ports/processId");
    data.AddUtf8("pcapCorrelationPolicy", "R0 driver.network rows emit pcapCorrelationRequired=true and flowKey candidates; PCAP import rows own DNS names, HTTP Host/URI/method, TLS SNI/certificate details");
    data.AddUtf8("pcapCorrelationJoinFieldsPolicy", "stable join fields are flowKey|sourceEndpoint|destinationEndpoint|protocolName|sourcePort|destinationPort|processId; missing L7 fields remain unavailable on R0 rows");
    data.AddUtf8("pcapExpectedRecordTypes", "pcap.flow|pcap.dns|pcap.http|pcap.tls");
    data.AddUtf8("dnsBoundaryPolicy", "dnsCandidate/serviceHintDns is a port/protocol candidate only; dnsQueryNameAvailable=false until pcap.dns or sidecar evidence supplies the name");
    data.AddUtf8("httpBoundaryPolicy", "httpCandidate/serviceHintHttp is a port/protocol candidate only; httpHostAvailable/httpUriAvailable/httpMethodAvailable remain false on R0 rows");
    data.AddUtf8("tlsBoundaryPolicy", "tlsCandidate/serviceHintTls is a port/protocol candidate only; tlsSniAvailable/tlsCertificateAvailable remain false on R0 rows");
    data.AddUtf8("l7ProtocolDetailsPolicy", "l7ProtocolDetailsAvailable=false and l7ProtocolDetailsOwner=pcap-browser-sidecar-not-r0 for R0 WFP/ALE rows");
    data.AddWide("zhNetworkProtocolParserBoundary", L"R0 WFP/ALE 行只证明端点、端口和层信息；DNS 查询名、HTTP Host/URI、TLS SNI 必须来自 PCAP/浏览器/sidecar 证据。");
    data.AddWide("zhPcapCorrelationPolicy", L"R0 网络行会给出 flowKey/端点候选；DNS/HTTP/TLS 细节归 PCAP import、浏览器或 sidecar 行所有。");
    data.AddWide("zhDnsCorrelationPolicy", L"DNS 候选字段只说明 53/UDP 等端点；查询名、响应码和答案必须来自 pcap.dns 或 sidecar 行。");
    data.AddWide("zhHttpCorrelationPolicy", L"HTTP 候选字段只说明 80/8080 等端点；Host、URI、Method 和状态码必须来自 pcap.http、浏览器或代理 sidecar 行。");
    data.AddWide("zhTlsCorrelationPolicy", L"TLS 候选字段只说明 443/8443 等端点；SNI、证书、JA3/JA3S 必须来自 pcap.tls 或 TLS sidecar 行。");
    data.AddUtf8("semanticSelfCheckScenarios", kSyntheticSemanticSelfCheckScenarios);
    data.AddUnsigned("semanticSelfCheckRows", kSyntheticSemanticSelfCheckRows);
    data.AddUnsigned("semanticSelfCheckSequenceStart", kSyntheticSemanticSequenceStart);
    data.AddUnsigned(
        "semanticSelfCheckSequenceEnd",
        kSyntheticSemanticSequenceStart + kSyntheticSemanticSelfCheckRows - 1);
    data.AddUtf8(
        "semanticSelfCheckPolicy",
        "mock/stress runs emit dedicated no-device rows for process-lineage, DNS, HTTP, TLS, lateral movement, and download-execute without changing the counted StressJsonlExpectedDriverRows file corpus");
    data.AddUtf8(
        "semanticStressCountPreservationPolicy",
        "semantic companion rows keep semanticRowCountedInStress=false and semanticStressCountImpact=none; only counted driver.file stress rows contribute to StressJsonlExpectedDriverRows");
    data.AddWide(
        "zhSemanticSelfCheckPolicy",
        L"mock/stress 会输出进程血缘、DNS、HTTP、TLS、横向移动和下载执行语义自检行；不会改变 StressJsonlExpectedDriverRows 计数的 driver.file 压测语料。");
    data.AddWide(
        "zhSemanticStressCountPreservationPolicy",
        L"语义 companion 行不计入 StressJsonlExpectedDriverRows；只有带 stress=true 的 driver.file 压测行参与行数合同。");
    data.AddUtf8("selfNoiseClassificationFields", "noiseClass|noiseScope|noiseKind|noiseSource|selfNoiseClass|collectorNoiseClass|noiseAction|noiseDisposition|noiseReasons|noiseFieldSet|noiseTaxonomyVersion|noiseDecision|noiseDecisionSource|noiseClassificationConfidence|noiseProbeKind|sampleBehaviorCandidate|sampleBehaviorCandidateReason|collectionNoise|operatorInterpretation|zhNoiseHint|zhNoiseClassificationHint|zhOperatorHint");
    data.AddUtf8("typedPayloadSemanticFields", "semanticFamily|behaviorLane|activityKind|evidenceReady|zhMessage|zhHint|zhSemanticHint|semanticScenario|artifactCandidateKind|dropLocationFamily|persistenceFamily|imageLoadFamily|networkEvidenceKind plus process/file/registry/network family-specific hints");
    data.AddUtf8("stressBackpressureDiagnostics", "observedSequenceSpan|expectedContiguousEvents|sequenceGapReason|lossDiagnostic|backpressureSeverity|backpressureDiagnostics|zhBackpressureHint");
    data.AddUtf8("queueLossEvidence", "lostCount|TotalEventsDropped|EventsDropped|TotalEventsSuppressed|TotalEventsBackpressured|ProducerDroppedMask|ProducerSuppressedMask|ProducerBackpressureMask|NextSequence|sequence|sequenceGapObserved|sequenceGapEstimate|queueHighWatermark|highWatermark");
    data.AddUtf8("stableJsonlFields", "sequence|sequenceMeaning|sequenceScope|sequenceConcrete|lost|lostCount|loss|lossObserved|backpressure|backpressureObserved|backpressureReason|backpressureSeverity|highWatermark|lastEnqueueFailureStatus|noise|noiseScope|noiseKind|noiseSource|noiseClass|selfNoiseClass|collectorNoiseClass|noiseAction|noiseDisposition|noiseReasons|noiseFieldSet|noiseTaxonomyVersion|noiseDecision|noiseDecisionSource|noiseClassificationConfidence|noiseProbeKind|sampleBehaviorCandidate|sampleBehaviorCandidateReason|collectorNoise|collectorSelfNoise|selfProcess|selfNoise|selfNoiseReason|selfNoiseAction|collectorSuppressed|producer|producerCategory|eventOrigin|subjectKind|actorRole|subjectRole|processIdSource|semanticFamily|behaviorLane|activityKind|semanticContractVersion|semanticRowKind|semanticCompanionRow|semanticCompanionCount|semanticCompanionContract|semanticRowCountedInStress|semanticScenario|semanticSelfCheck|semanticSelfCheckScenarios|semanticSelfCheckRows|semanticEvidenceKind|zhSemanticHint|zhOperatorHint|zhCompanionHint|artifactCandidateKind|dropLocationFamily|droppedFileCandidate|startupFolderCandidate|downloadedFileCandidate|executableFileCandidate|persistenceFamily|servicePersistenceCandidate|ifeoPersistenceCandidate|imageLoadFamily|injectionCandidate|processLineageScenario|lineageConfidence|parentProcessId|creatingProcessId|capturedCommandLine|networkEvidenceKind|externalAddressCandidate|lateralMovementCandidate|downloadExecuteCandidate|serviceHint|serviceHintDns|serviceHintHttp|serviceHintTls|dnsQueryNameAvailable|dnsQueryNameSource|dnsCorrelationRecordType|dnsDetailsOwner|httpHostAvailable|httpUriAvailable|httpMethodAvailable|httpCorrelationRecordType|httpDetailsOwner|tlsSniAvailable|tlsCertificateAvailable|tlsCorrelationRecordType|tlsDetailsOwner|protocolPayloadParsed|protocolParserSource|protocolPayloadSource|networkCorrelationContractVersion|networkCorrelationRole|pcapCorrelationRole|pcapCorrelationJoinFields|pcapCorrelationMissingFields|pcapCorrelationConfidence|l7ProtocolDetailsAvailable|l7ProtocolDetailsOwner|r0ProtocolParserGuarantee|protocolBoundaryVerdict|pcapCorrelationRequired|pcapCorrelationStatus|pcapFlowKeyCandidate|pcapCorrelationKey|networkProtocolBoundaryFields|networkCorrelationStableFields|flowKey|sourceEndpoint|destinationEndpoint|zhMessage|zhHint|zhPcapCorrelationHint|zhNetworkBoundaryHint|zhDnsCorrelationHint|zhHttpCorrelationHint|zhTlsCorrelationHint|zhNoiseClassificationHint|operationName|status|pathTruncated|schema|eventSchemaName|eventSchemaVersion|eligible|processed|emitted|suppressed|skipped|head|tail|sampling|sequenceGapReason|observedSequenceSpan|producerDroppedMask|producerSuppressedMask|producerBackpressureMask|effectiveProducerMask|lastFailureNtStatus|networkStatusAvailable|networkStatusCapability|supportedLayerMask|activeLayerMask|todoMask|classifyCount|eventCount|queueFailureCount|classifyPayloadFailureCount|lastDegradeReasonName|payloadVersion|payloadVersionHex|payloadSchemaVersion|payloadVersionStatus|expectedPayloadVersion|expectedPayloadVersionHex|producerPayloadVersionFieldSet|stress|stressOrdinal|stressCount|stressCorpusRole|driverEventStressFieldSet|StressJsonlNoiseEvidence");
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
    AddCollectorNonBehaviorFields(data, "collector-stopped", "emit-collector-stopped-not-sample-behavior");
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
