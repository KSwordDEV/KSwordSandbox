#include "SyntheticMode.h"

#include <string>
#include <utility>
#include <vector>

namespace KSword::Sandbox::R0Collector {

// Input: Mock driver event type name.
// Processing: Maps synthetic category rows to the same public event type values
// and payload schema names that live READ_EVENTS parser rows emit.
// Return: Public payload schema name for the category, or a mock fallback.
std::string MockPayloadSchemaForDriverType(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "process") {
        return "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "image") {
        return "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "file") {
        return "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "registry") {
        return "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "network") {
        return "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD";
    }
    return "mock-forward-compatible";
}

// Input: Mock driver event type name.
// Processing: Maps mock categories to public KswSandboxEventType* values so
// mock/live JSONL rows share comparable diagnostic fields.
// Return: Numeric public event type or KswSandboxEventTypeReserved fallback.
ULONG MockDriverEventTypeValue(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "process") {
        return KswSandboxEventTypeProcess;
    }
    if (driverEventTypeName == "image") {
        return KswSandboxEventTypeImage;
    }
    if (driverEventTypeName == "file") {
        return KswSandboxEventTypeFile;
    }
    if (driverEventTypeName == "registry") {
        return KswSandboxEventTypeRegistry;
    }
    if (driverEventTypeName == "network") {
        return KswSandboxEventTypeNetwork;
    }
    return KswSandboxEventTypeReserved;
}

// Input: Mock driver event type name.
// Processing: Uses the same subject-kind vocabulary as live driver rows.
// Return: Stable subject kind label for attribution smoke tests.
std::string MockSubjectKind(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "network") {
        return "network-flow";
    }
    if (driverEventTypeName == "process" ||
        driverEventTypeName == "image" ||
        driverEventTypeName == "file" ||
        driverEventTypeName == "registry") {
        return driverEventTypeName;
    }
    return "unknown";
}

// Input: Mock category metadata, collector options, and the JSONL sink.
// Processing: Emits one synthetic driver-originated row that uses the same
// stable eventType values as drained R0 events while clearly marking the data as
// mock-only and not sourced from a real kernel payload.
// Return: true if the JSONL sink accepted the mock row; false on write failure.
bool EmitMockDriverCategoryEvent(
    EventWriter& writer,
    const Options& options,
    const std::string& eventType,
    const std::wstring& path,
    const std::wstring& commandLine,
    const std::string& driverEventTypeName,
    const std::string& operation,
    const std::vector<std::pair<std::string, std::string>>& extraData) {
    SandboxEventFields event;
    event.eventType = eventType;
    event.source = "driver";
    event.processId = GetCurrentProcessId();
    event.processName = L"notepad.exe";
    event.path = path;
    event.commandLine = commandLine;

    JsonDataObjectBuilder data;
    data.AddBool("mock", true);
    data.AddWide("devicePath", options.devicePath);
    data.AddBool("healthOnly", options.healthOnly);
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("driverEventType", MockDriverEventTypeValue(driverEventTypeName));
    data.AddUtf8("driverEventTypeName", driverEventTypeName);
    data.AddUtf8("producer", driverEventTypeName);
    data.AddUtf8("producerCategory", driverEventTypeName);
    data.AddUtf8("eventOrigin", "synthetic-r0collector");
    data.AddUtf8("subjectKind", MockSubjectKind(driverEventTypeName));
    data.AddUtf8("actorRole", "synthetic-sample-process");
    data.AddUtf8("subjectRole", "synthetic-sample-or-system");
    data.AddUtf8("processIdSource", "synthetic");
    data.AddUtf8("operationName", operation);
    data.AddSigned("status", 0);
    data.AddUtf8("statusHex", "0x00000000");
    data.AddBool("statusPresent", true);
    data.AddBool("pathTruncated", false);
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddUtf8("operation", operation);
    data.AddUtf8("typedPayloadStatus", "mock");
    data.AddBool("typedPayloadParsed", true);
    data.AddUtf8("payloadSchema", MockPayloadSchemaForDriverType(driverEventTypeName));
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddBool("noise", false);
    data.AddUtf8(
        "note",
        "Synthetic driver-category row for Guest Agent and host import plumbing.");
    data.AddWide(
        "zhNote",
        L"\u4f9b Guest Agent \u548c Host import \u7ba1\u7ebf\u6d4b\u8bd5\u4f7f\u7528\u7684\u5408\u6210 driver \u5206\u7c7b\u884c\u3002");

    for (const auto& item : extraData) {
        data.AddUtf8(item.first, item.second);
    }

    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Event sink for synthetic mode.
// Processing: Appends a deterministic blank line, malformed row, and valid
// extra-field row so host readers prove JSONL noise tolerance without needing
// stress rows or a live device.
// Return: true when every noise line is accepted by the sink.
bool EmitSyntheticJsonlNoiseRows(EventWriter& writer) {
    if (!writer.WriteLine("   ")) {
        return false;
    }

    if (!writer.WriteLine("{\"eventType\":\"driver.file\",\"source\":\"driver\",\"data\":{\"sequence\":\"broken\"")) {
        return false;
    }

    JsonDataObjectBuilder data;
    data.AddUtf8("sequence", "9999");
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "network");
    data.AddUtf8("producerCategory", "network");
    data.AddUtf8("eventOrigin", "synthetic-r0collector");
    data.AddUtf8("subjectKind", "network-flow");
    data.AddUtf8("actorRole", "synthetic-sample-process");
    data.AddUtf8("subjectRole", "synthetic-jsonl-noise");
    data.AddUtf8("processIdSource", "synthetic");
    data.AddUtf8("operationName", "aleAuthorize");
    data.AddSigned("status", 0);
    data.AddUtf8("statusHex", "0x00000000");
    data.AddBool("statusPresent", true);
    data.AddBool("pathTruncated", false);
    data.AddUtf8("collectorNoisePolicy", "synthetic-noise-injector");
    data.AddBool("noise", true);
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);
    data.AddUtf8("protocolName", "tcp");
    data.AddUtf8("transportProtocol", "tcp");
    data.AddUtf8("directionName", "outbound");
    data.AddUtf8("addressFamilyName", "ipv4");
    data.AddUtf8("localAddress", "192.0.2.10");
    data.AddUtf8("remoteAddress", "203.0.113.10");
    data.AddUtf8("localPort", "51515");
    data.AddUtf8("remotePort", "443");
    data.AddUtf8("localEndpoint", "192.0.2.10:51515");
    data.AddUtf8("remoteEndpoint", "203.0.113.10:443");
    data.AddUtf8("sourceEndpoint", "192.0.2.10:51515");
    data.AddUtf8("destinationEndpoint", "203.0.113.10:443");
    data.AddUtf8("flowKey", "tcp|192.0.2.10:51515|203.0.113.10:443");

    std::string line =
        "{\"eventType\":\"driver.network\",\"source\":\"driver\",\"extraTopLevel\":\"ignored\",\"data\":";
    line += data.Build();
    line += "}";
    return writer.WriteLine(line);
}

// Input: Collector options and the JSONL sink.
// Processing: Emits a deterministic contiguous driver.file corpus that is large
// enough for host/live readers to prove ordering, loss markers, and bounded
// backpressure fields without opening the kernel device.
// Return: true when all requested synthetic stress rows were written; false on
// output failure.
bool EmitSyntheticStressEvents(EventWriter& writer, const Options& options, const std::wstring& commandLine) {
    if (options.stressCount <= 0) {
        return true;
    }

    const DWORD currentProcessId = GetCurrentProcessId();
    const std::string currentProcessIdText = std::to_string(currentProcessId);
    const std::string stressSequenceStartText = std::to_string(kSyntheticStressSequenceStart);
    const std::string stressSequenceEndText = std::to_string(kSyntheticStressSequenceStart + options.stressCount - 1);

    for (int index = 0; index < options.stressCount; ++index) {
        const int sequence = kSyntheticStressSequenceStart + index;
        std::wstring path = LR"(C:\Users\Public\ksword-r0collector-stress-)";
        path += std::to_wstring(index);
        path += L".tmp";
        const std::string pathUtf8 = Utf8FromWide(path);

        if (!EmitMockDriverCategoryEvent(
                writer,
                options,
                "driver.file",
                path,
                commandLine,
                "file",
                "create",
                {
                    {"stress", "true"},
                    {"stressOrdinal", std::to_string(index)},
                    {"stressCount", std::to_string(options.stressCount)},
                    {"StressJsonlExpectedDriverRows", std::to_string(options.stressCount)},
                    {"StressJsonlSequenceStart", stressSequenceStartText},
                    {"StressJsonlSequenceEnd", stressSequenceEndText},
                    {"StressJsonlSequenceGapCount", "0"},
                    {"sequenceGapObserved", "false"},
                    {"sequenceGapEstimate", "0"},
                    {"sequenceRangeMeaning", "synthetic contiguous concrete event sequence"},
                    {"StressJsonlLossEvidence", kStressJsonlLossEvidence},
                    {"StressJsonlBackpressureEvidence", kStressJsonlBackpressureEvidence},
                    {"version", std::to_string(KSWORD_SANDBOX_EVENT_HEADER_VERSION)},
                    {"versionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8)},
                    {"recordSize", std::to_string(sizeof(KSWORD_SANDBOX_EVENT_HEADER))},
                    {"sequence", std::to_string(sequence)},
                    {"payloadSize", std::to_string(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD))},
                    {"filePath", pathUtf8},
                    {"desiredAccessHex", "0x0012019F"},
                    {"disposition", "create"},
                    {"processId", currentProcessIdText},
                    {"queueCapacity", "0"},
                    {"queueHighWatermark", "0"},
                    {"totalEventsDropped", "0"},
                    {"totalEventsBackpressured", "0"},
                    {"producerDroppedMask", "0"},
                    {"producerDroppedMaskHex", "0x00000000"},
                    {"producerBackpressureMask", "0"},
                    {"producerBackpressureMaskHex", "0x00000000"},
                    {"requestedMaxEvents", std::to_string(options.readEventsMaxEvents)},
                    {"readEventsMaxEvents", std::to_string(options.readEventsMaxEvents)},
                    {"maxReadBatches", std::to_string(options.maxReadBatches)},
                    {"drainStoppedAtBatchLimit", "false"},
                    {"sampling", options.driverEventSampleStride <= 1 ? "none" : "stride:not-applied-in-synthetic-stress"}
                })) {
            return false;
        }
    }

    return true;
}

// Input: Collector options and JSONL sink after synthetic stress rows.
// Processing: Emits a compact READ_EVENTS-shaped summary so no-device stress
// output exposes the same processed/emitted/backpressure aliases as live drains.
// Return: true when no summary is needed or the sink accepted the summary row.
bool EmitSyntheticStressSummary(EventWriter& writer, const Options& options) {
    if (options.stressCount <= 0) {
        return true;
    }

    const std::string stressSequenceStartText = std::to_string(kSyntheticStressSequenceStart);
    const std::string stressSequenceEndText =
        std::to_string(kSyntheticStressSequenceStart + options.stressCount - 1);
    const std::string stressNextSequenceText =
        std::to_string(kSyntheticStressSequenceStart + options.stressCount);

    SandboxEventFields event;
    event.eventType = "r0collector.driverReadEvents";
    event.path = options.devicePath;

    JsonDataObjectBuilder data;
    data.AddBool("mock", true);
    data.AddBool("syntheticStress", true);
    data.AddUtf8("ioctlProtocol", "not-issued");
    data.AddUnsigned("requestedMaxEvents", options.readEventsMaxEvents);
    data.AddUnsigned("readEventsMaxEvents", options.readEventsMaxEvents);
    data.AddSigned("maxReadBatches", options.maxReadBatches);
    data.AddBool("drainStoppedAtBatchLimit", false);
    data.AddUnsigned("recordsProcessed", options.stressCount);
    data.AddUnsigned("eventsEmitted", options.stressCount);
    data.AddUnsigned("collectorSuppressedEvents", 0);
    data.AddUnsigned("collectorSkippedEvents", 0);
    data.AddUnsigned("processed", options.stressCount);
    data.AddUnsigned("eligible", options.stressCount);
    data.AddUnsigned("eligibleEvents", options.stressCount);
    data.AddUnsigned("emitted", options.stressCount);
    data.AddUnsigned("suppressed", 0);
    data.AddUnsigned("skipped", 0);
    data.AddUtf8("head", stressSequenceStartText);
    data.AddUtf8("tail", stressSequenceEndText);
    data.AddBool("sequenceGapObserved", false);
    data.AddUnsigned("sequenceGapEstimate", 0);
    data.AddUtf8("sequenceRangeMeaning", "synthetic stress rows are contiguous concrete event sequences");
    data.AddWide("zhSequenceRangeMeaning", L"合成压测行使用连续的具体事件 sequence，用于验证丢失/缺口检测。");
    data.AddUtf8("sampling", options.driverEventSampleStride <= 1 ? "none" : "stride:not-applied-in-synthetic-stress");
    data.AddUtf8("loss", "none");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "synthetic-stress-summary", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("lost", false);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureReason", "none");
    data.AddUnsigned("eventsDropped", 0);
    data.AddUnsigned("lostCount", 0);
    data.AddUnsigned("totalEventsDropped", 0);
    data.AddUnsigned("totalEventsBackpressured", 0);
    data.AddUnsigned("queueCapacity", 0);
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddUtf8("nextSequence", stressNextSequenceText);
    data.AddUtf8("sequence", stressNextSequenceText);
    data.AddUtf8("sequenceMeaning", "nextSequence");
    data.AddUtf8("sequencePolicy", "summary sequence is the next synthetic sequence after the contiguous stress corpus");
    data.AddWide("zhSequencePolicy", L"摘要行的 sequence 是连续合成压测集后的下一个 sequence。");
    data.AddUtf8("producerDroppedMaskHex", "0x00000000");
    data.AddUtf8("producerBackpressureMaskHex", "0x00000000");
    data.AddUtf8("StressJsonlExpectedDriverRows", std::to_string(options.stressCount));
    data.AddUtf8("StressJsonlSequenceStart", stressSequenceStartText);
    data.AddUtf8("StressJsonlSequenceEnd", stressSequenceEndText);
    data.AddUtf8("StressJsonlSequenceGapCount", "0");
    data.AddUtf8("StressJsonlLossEvidence", kStressJsonlLossEvidence);
    data.AddUtf8("StressJsonlBackpressureEvidence", kStressJsonlBackpressureEvidence);
    event.dataJson = data.Build();

    return EmitEvent(writer, event);
}

// Input: User options and event writer.
// Processing: Emits deterministic mock driver-like rows, then exits without
// opening the device path. This keeps CI and Guest Agent wiring testable before
// a signed kernel driver is installed in the guest VM.
// Return: Process exit code.
int RunSyntheticMode(const Options& options, EventWriter& writer) {
    const DWORD currentProcessId = GetCurrentProcessId();
    const std::string currentProcessIdText = std::to_string(currentProcessId);
    const std::wstring mockProcessPath = LR"(C:\Windows\System32\notepad.exe)";
    const std::wstring mockCommandLine = LR"("C:\Windows\System32\notepad.exe" --ksword-mock)";
    const bool stressMode = options.stressCount > 0;
    const std::string stressSequenceStartText = std::to_string(kSyntheticStressSequenceStart);
    const std::string stressSequenceEndText = stressMode
        ? std::to_string(kSyntheticStressSequenceStart + options.stressCount - 1)
        : "";

    SandboxEventFields mockEvent;
    mockEvent.eventType = "r0collector.mockDriverEvent";
    mockEvent.processId = currentProcessId;
    mockEvent.processName = L"notepad.exe";
    mockEvent.path = mockProcessPath;
    mockEvent.commandLine = mockCommandLine;
    JsonDataObjectBuilder mockData;
    mockData.AddBool("mock", true);
    mockData.AddWide("devicePath", options.devicePath);
    mockData.AddBool("healthOnly", options.healthOnly);
    mockData.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    mockData.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    mockData.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    mockData.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(mockData, "synthetic-mock-marker", "collector-diagnostic");
    mockData.AddBool("collectorNoise", false);
    mockData.AddBool("collectorSelfNoise", false);
    mockData.AddBool("selfProcess", false);
    mockData.AddUtf8("collectorNoiseReason", "none");
    mockData.AddUtf8("collectorNoiseAction", "emit");
    mockData.AddBool("collectorSuppressed", false);
    mockData.AddBool("selfNoise", false);
    mockData.AddUtf8("selfNoiseReason", "none");
    mockData.AddUtf8("selfNoiseAction", "emit");
    mockData.AddBool("noise", false);
    mockData.AddBool("lost", false);
    mockData.AddUnsigned("lostCount", 0);
    mockData.AddBool("lossObserved", false);
    mockData.AddBool("backpressure", false);
    mockData.AddBool("backpressureObserved", false);
    mockData.AddUnsigned("highWatermark", 0);
    mockData.AddUnsigned("queueHighWatermark", 0);
    mockData.AddSigned("lastEnqueueFailureStatus", 0);
    mockData.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    mockData.AddBool("stress", stressMode);
    mockData.AddSigned("stressCount", options.stressCount);
    if (stressMode) {
        mockData.AddSigned("StressJsonlExpectedDriverRows", options.stressCount);
        mockData.AddUtf8("StressJsonlSequenceStart", stressSequenceStartText);
        mockData.AddUtf8("StressJsonlSequenceEnd", stressSequenceEndText);
        mockData.AddSigned("StressJsonlSequenceGapCount", 0);
        mockData.AddBool("sequenceGapObserved", false);
        mockData.AddUnsigned("sequenceGapEstimate", 0);
        mockData.AddUtf8("StressJsonlLossEvidence", kStressJsonlLossEvidence);
        mockData.AddUtf8("StressJsonlBackpressureEvidence", kStressJsonlBackpressureEvidence);
    }
    mockData.AddUtf8("ioctlProtocol", "not-issued");
    mockData.AddUtf8("note", "Synthetic marker; driver category mock rows follow.");
    mockData.AddWide("zhNote", L"\u5408\u6210\u6807\u8bb0\u884c\uff1b\u540e\u7eed\u4f1a\u5199\u51fa driver \u5206\u7c7b mock \u884c\u3002");
    mockEvent.dataJson = mockData.Build();

    if (!EmitEvent(writer, mockEvent)) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.process",
            mockProcessPath,
            mockCommandLine,
            "process",
            "create",
            {
                {"imagePath", "C:\\Windows\\System32\\notepad.exe"},
                {"processId", currentProcessIdText},
                {"parentProcessId", currentProcessIdText}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "image.load",
            LR"(C:\Windows\System32\kernel32.dll)",
            mockCommandLine,
            "image",
            "load",
            {
                {"imagePath", "C:\\Windows\\System32\\kernel32.dll"},
                {"imageBase", "0x0000000180000000"},
                {"imageSize", "1048576"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.file",
            LR"(C:\Users\Public\ksword-r0collector-mock.tmp)",
            mockCommandLine,
            "file",
            "create",
            {
                {"filePath", "C:\\Users\\Public\\ksword-r0collector-mock.tmp"},
                {"desiredAccessHex", "0x0012019F"},
                {"disposition", "create"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.registry",
            LR"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KSwordMock)",
            mockCommandLine,
            "registry",
            "setValue",
            {
                {"keyPath", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
                {"valueName", "KSwordMock"},
                {"valueType", "REG_SZ"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.network",
            LR"(tcp://203.0.113.10:443)",
            mockCommandLine,
            "network",
            "connect",
            {
                {"protocolName", "tcp"},
                {"directionName", "outbound"},
                {"addressFamilyName", "ipv4"},
                {"localAddress", "192.0.2.10"},
                {"localPort", "51515"},
                {"remoteAddress", "203.0.113.10"},
                {"remotePort", "443"},
                {"localEndpoint", "192.0.2.10:51515"},
                {"remoteEndpoint", "203.0.113.10:443"},
                {"sourceEndpoint", "192.0.2.10:51515"},
                {"destinationEndpoint", "203.0.113.10:443"},
                {"flowKey", "tcp|192.0.2.10:51515|203.0.113.10:443"},
                {"servicePort", "443"},
                {"serviceHint", "tls"},
                {"semanticCandidate", "tls"},
                {"dnsCandidate", "false"},
                {"httpCandidate", "false"},
                {"tlsCandidate", "true"},
                {"processId", currentProcessIdText}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitSyntheticStressEvents(writer, options, mockCommandLine)) {
        return kExitRuntimeFailure;
    }

    if (!EmitSyntheticStressSummary(writer, options)) {
        return kExitRuntimeFailure;
    }

    if (options.injectJsonlNoise && !EmitSyntheticJsonlNoiseRows(writer)) {
        return kExitRuntimeFailure;
    }

    return kExitSuccess;
}

} // namespace KSword::Sandbox::R0Collector
