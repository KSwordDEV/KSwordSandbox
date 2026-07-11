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
    data.AddUtf8("operation", operation);
    data.AddUtf8("operationName", operation);
    data.AddUtf8("typedPayloadStatus", "mock");
    data.AddBool("typedPayloadParsed", true);
    data.AddUtf8("payloadSchema", MockPayloadSchemaForDriverType(driverEventTypeName));
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);
    data.AddBool("noise", false);
    data.AddUtf8(
        "note",
        "Synthetic driver-category row for Guest Agent and host import plumbing.");

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
    data.AddBool("noise", true);
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

    static constexpr int kStressSequenceStart = 1200;
    const DWORD currentProcessId = GetCurrentProcessId();
    const std::string currentProcessIdText = std::to_string(currentProcessId);
    const std::string stressSequenceStartText = std::to_string(kStressSequenceStart);
    const std::string stressSequenceEndText = std::to_string(kStressSequenceStart + options.stressCount - 1);

    for (int index = 0; index < options.stressCount; ++index) {
        const int sequence = kStressSequenceStart + index;
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
                    {"StressJsonlLossEvidence", "TotalEventsDropped|totalEventsDropped|EventsDropped|eventsDropped|NextSequence|nextSequence|sequence"},
                    {"StressJsonlBackpressureEvidence", "QueueCapacity|queueCapacity|QueueHighWatermark|queueHighWatermark|drainStoppedAtBatchLimit|requestedMaxEvents|readEventsMaxEvents|maxReadBatches"},
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
                    {"readEventsMaxEvents", std::to_string(options.readEventsMaxEvents)},
                    {"maxReadBatches", std::to_string(options.maxReadBatches)}
                })) {
            return false;
        }
    }

    return true;
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
    mockData.AddUtf8("ioctlProtocol", "not-issued");
    mockData.AddUtf8("note", "Synthetic marker; driver category mock rows follow.");
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

    if (options.injectJsonlNoise && !EmitSyntheticJsonlNoiseRows(writer)) {
        return kExitRuntimeFailure;
    }

    return kExitSuccess;
}

} // namespace KSword::Sandbox::R0Collector
