#include "RuntimeLoop.h"

#include "AbiSelfCheck.h"
#include "IoctlClient.h"
#include "JsonWriter.h"
#include "Options.h"
#include "ReadinessDiagnostics.h"
#include "SyntheticMode.h"

#include <chrono>
#include <thread>

namespace KSword::Sandbox::R0Collector {

// Input: Collector options used for this run.
// Processing: Serializes the configuration into the data object of lifecycle events.
// Return: JSON object text for SandboxEvent.data.
std::string BuildConfigData(const Options& options) {
    JsonDataObjectBuilder data;
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("serviceName", options.serviceName);
    data.AddWide("outputPath", options.outputPath);
    data.AddSigned("durationSeconds", options.durationSeconds);
    data.AddSigned("pollIntervalMs", options.pollIntervalMs);
    data.AddSigned("diagnoseReadTimeoutMs", options.diagnoseReadTimeoutMs);
    data.AddSigned("maxReadBatches", options.maxReadBatches);
    data.AddUnsigned("readEventsMaxEvents", options.readEventsMaxEvents);
    data.AddUnsigned("driverEventSampleStride", options.driverEventSampleStride);
    data.AddUtf8(
        "driverEventSampling",
        options.driverEventSampleStride <= 1 ? "none" : "stride");
    data.AddSigned("stressCount", options.stressCount);
    data.AddBool("mockMode", options.mockMode);
    data.AddBool("syntheticMode", options.mockMode);
    data.AddBool("injectJsonlNoise", options.injectJsonlNoise);
    data.AddBool("abiSelfCheck", options.abiSelfCheck);
    data.AddBool("diagnose", options.diagnose);
    data.AddBool("healthOnly", options.healthOnly);
    data.AddBool("heartbeat", options.heartbeat);
    data.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddBool("enableMaskSpecified", options.enableMaskSpecified);
    data.AddUnsigned("enableMask", options.enableMask);
    data.AddUtf8("enableMaskHex", HexUnsignedLongLong(options.enableMask, 8));
    data.AddUtf8("ioctlProtocol", "KSwordSandboxDriverIoctl.h");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);
    return data.Build();
}

// Input: CLI parse or output-open failure details.
// Processing: Builds a structured error object while keeping top-level fields
// compatible with SandboxEvent.
// Return: JSON object text for SandboxEvent.data.
std::string BuildErrorData(const std::wstring& message, const DWORD errorCode, const std::wstring& hint) {
    JsonDataObjectBuilder data;
    data.AddWide("message", message);
    data.AddUnsigned("win32Error", errorCode);
    data.AddWide("hint", hint);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);
    return data.Build();
}

// Input: Collector runtime counters and a reason label.
// Processing: Emits an optional lifecycle heartbeat row so timed runs provide
// progress evidence even when the driver queue is empty.
// Return: true if heartbeat output was disabled or the JSONL sink accepted the row.
bool EmitCollectorHeartbeat(
    EventWriter& writer,
    const Options& options,
    const std::string& reason,
    const unsigned long long polls,
    const unsigned long long readBatches,
    const unsigned long long driverEvents,
    const unsigned long long driverRecordsProcessed,
    const unsigned long long collectorSuppressedEvents,
    const unsigned long long collectorSkippedEvents) {
    if (!options.heartbeat) {
        return true;
    }

    SandboxEventFields event;
    event.eventType = "r0collector.heartbeat";
    event.path = options.devicePath;

    JsonDataObjectBuilder data;
    data.AddUtf8("reason", reason);
    data.AddUnsigned("polls", polls);
    data.AddUnsigned("readBatches", readBatches);
    data.AddUnsigned("driverEvents", driverEvents);
    data.AddUnsigned("driverRecordsProcessed", driverRecordsProcessed);
    data.AddUnsigned("collectorSuppressedEvents", collectorSuppressedEvents);
    data.AddUnsigned("collectorSkippedEvents", collectorSkippedEvents);
    data.AddUnsigned("driverEventSampleStride", options.driverEventSampleStride);
    data.AddUtf8(
        "driverEventSampling",
        options.driverEventSampleStride <= 1 ? "none" : "stride");
    data.AddSigned("durationSeconds", options.durationSeconds);
    data.AddSigned("pollIntervalMs", options.pollIntervalMs);
    data.AddBool("mockMode", options.mockMode);
    data.AddBool("syntheticMode", options.mockMode);
    data.AddBool("abiSelfCheck", options.abiSelfCheck);
    data.AddBool("healthOnly", options.healthOnly);
    data.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddBool("enableMaskSpecified", options.enableMaskSpecified);
    data.AddUnsigned("enableMask", options.enableMask);
    data.AddUtf8("enableMaskHex", HexUnsignedLongLong(options.enableMask, 8));
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);
    event.dataJson = data.Build();

    return EmitEvent(writer, event);
}

// Input: Open driver handle, collector options, and event sink.
// Processing: Runs only the public GET_HEALTH IOCTL and emits a stopped row
// without polling or draining the event queue.  This is useful for service
// readiness checks that must not consume queued telemetry.
// Return: Process exit code.
int RunDriverHealthOnly(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    if (!device.IsValid()) {
        return kExitDeviceUnavailable;
    }

    if (!EmitDriverHealth(device, options, writer)) {
        return kExitRuntimeFailure;
    }

    if (!EmitCollectorHeartbeat(writer, options, "healthComplete", 0, 0, 0, 0, 0, 0)) {
        return kExitRuntimeFailure;
    }

    JsonDataObjectBuilder data;
    data.AddUtf8("reason", "healthComplete");
    data.AddUnsigned("polls", 0);
    data.AddUnsigned("readBatches", 0);
    data.AddUnsigned("driverEvents", 0);
    data.AddUnsigned("driverRecordsProcessed", 0);
    data.AddUnsigned("collectorSuppressedEvents", 0);
    data.AddUnsigned("collectorSkippedEvents", 0);
    data.AddBool("ioctlIssued", true);
    data.AddBool("healthOnly", true);
    data.AddBool("heartbeat", options.heartbeat);
    data.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    data.AddUnsigned("driverEventSampleStride", options.driverEventSampleStride);
    data.AddUtf8(
        "driverEventSampling",
        options.driverEventSampleStride <= 1 ? "none" : "stride");
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);

    SandboxEventFields stoppedEvent;
    stoppedEvent.eventType = "r0collector.stopped";
    stoppedEvent.path = options.devicePath;
    stoppedEvent.dataJson = data.Build();

    return EmitEvent(writer, stoppedEvent) ? kExitSuccess : kExitRuntimeFailure;
}

// Input: Open driver handle, collector options, and event sink.
// Processing: Calls the public driver skeleton IOCTLs. Health is read once;
// POLL is called once per loop and READ_EVENTS is drained in batches until the
// batch is smaller than the request cap. Duration 0 performs one poll/drain pass.
// Return: Process exit code describing write or IOCTL failure versus success.
int RunDriverIoctlLoop(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    if (!device.IsValid()) {
        return kExitDeviceUnavailable;
    }

    if (!EmitDriverHealth(device, options, writer)) {
        return kExitRuntimeFailure;
    }

    if (!EmitDriverCapabilities(device, options, writer)) {
        return kExitRuntimeFailure;
    }

    if (!EmitDriverSetProducerEnableMask(device, options, writer)) {
        return kExitRuntimeFailure;
    }

    if (!EmitDriverStatus(device, options, writer)) {
        return kExitRuntimeFailure;
    }

    unsigned long long polls = 0;
    unsigned long long readBatches = 0;
    unsigned long long driverEvents = 0;
    unsigned long long driverRecordsProcessed = 0;
    unsigned long long collectorSuppressedEvents = 0;
    unsigned long long collectorSkippedEvents = 0;
    bool drainStoppedAtDeadline = false;
    bool drainStoppedAtBatchLimit = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(options.durationSeconds);

    do {
        if (!EmitDriverPoll(device, options, writer)) {
            return kExitRuntimeFailure;
        }
        ++polls;

        for (;;) {
            if (options.maxReadBatches > 0 &&
                readBatches >= static_cast<unsigned long long>(options.maxReadBatches)) {
                drainStoppedAtBatchLimit = true;
                break;
            }

            unsigned long long eventsEmitted = 0;
            unsigned long long recordsProcessed = 0;
            unsigned long long suppressedEvents = 0;
            if (!EmitDriverReadEvents(
                    device,
                    options,
                    readBatches + 1,
                    writer,
                    &eventsEmitted,
                    &recordsProcessed,
                    &suppressedEvents)) {
                return kExitRuntimeFailure;
            }
            ++readBatches;
            driverEvents += eventsEmitted;
            driverRecordsProcessed += recordsProcessed;
            collectorSuppressedEvents += suppressedEvents;
            const unsigned long long accountedEvents = eventsEmitted + suppressedEvents;
            if (recordsProcessed > accountedEvents) {
                collectorSkippedEvents += recordsProcessed - accountedEvents;
            }

            if (recordsProcessed < options.readEventsMaxEvents) {
                break;
            }

            if (options.durationSeconds > 0 && std::chrono::steady_clock::now() >= deadline) {
                drainStoppedAtDeadline = true;
                break;
            }
        }

        if (!EmitCollectorHeartbeat(
                writer,
                options,
                "pollComplete",
                polls,
                readBatches,
                driverEvents,
                driverRecordsProcessed,
                collectorSuppressedEvents,
                collectorSkippedEvents)) {
            return kExitRuntimeFailure;
        }

        if (options.durationSeconds <= 0 || std::chrono::steady_clock::now() >= deadline) {
            break;
        }

        if (drainStoppedAtBatchLimit) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(options.pollIntervalMs));
    } while (std::chrono::steady_clock::now() < deadline);

    JsonDataObjectBuilder data;
    data.AddUtf8("reason", options.durationSeconds > 0 ? "durationElapsed" : "oneShotComplete");
    data.AddUnsigned("polls", polls);
    data.AddUnsigned("readBatches", readBatches);
    data.AddUnsigned("driverEvents", driverEvents);
    data.AddUnsigned("driverRecordsProcessed", driverRecordsProcessed);
    data.AddUnsigned("collectorSuppressedEvents", collectorSuppressedEvents);
    data.AddUnsigned("collectorSkippedEvents", collectorSkippedEvents);
    data.AddBool("ioctlIssued", true);
    data.AddBool("healthOnly", false);
    data.AddUtf8("drainMode", "batchUntilEmpty");
    data.AddBool("drainStoppedAtDeadline", drainStoppedAtDeadline);
    data.AddBool("drainStoppedAtBatchLimit", drainStoppedAtBatchLimit);
    data.AddSigned("maxReadBatches", options.maxReadBatches);
    data.AddUnsigned("readEventsMaxEvents", options.readEventsMaxEvents);
    data.AddUnsigned("driverEventSampleStride", options.driverEventSampleStride);
    data.AddUtf8(
        "driverEventSampling",
        options.driverEventSampleStride <= 1 ? "none" : "stride");
    data.AddBool("heartbeat", options.heartbeat);
    data.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", drainStoppedAtBatchLimit);

    SandboxEventFields stoppedEvent;
    stoppedEvent.eventType = "r0collector.stopped";
    stoppedEvent.path = options.devicePath;
    stoppedEvent.dataJson = data.Build();

    if (!EmitDriverStatus(device, options, writer)) {
        return kExitRuntimeFailure;
    }

    return EmitEvent(writer, stoppedEvent) ? kExitSuccess : kExitRuntimeFailure;
}

// Input: Windows Unicode process arguments.
// Processing: Parses collector options, opens the output JSONL sink, optionally
// opens the driver device, and emits SandboxEvent-compatible lifecycle/error rows.
// Return: Conventional process exit code; nonzero values distinguish argument,
// output, device-open, and runtime failures.
int RunCollector(int argc, wchar_t* argv[]) {
    Options options;
    std::wstring parseError;
    if (!ParseArguments(argc, argv, &options, &parseError)) {
        PrintUsage(argc > 0 ? argv[0] : L"KSword.Sandbox.R0Collector.exe");
        SandboxEventFields parseEvent;
        parseEvent.eventType = "r0collector.argumentError";
        parseEvent.path = L"";
        parseEvent.dataJson = BuildErrorData(parseError, ERROR_INVALID_PARAMETER, L"Run with --help for supported options.");
        EmitFallbackEventToStderr(parseEvent);
        return kExitInvalidArguments;
    }

    if (options.showHelp) {
        PrintUsage(argc > 0 ? argv[0] : L"KSword.Sandbox.R0Collector.exe");
        return kExitSuccess;
    }

    EventWriter writer;
    std::wstring outputError;
    if (!writer.Open(options.outputPath, &outputError)) {
        SandboxEventFields outputEvent;
        outputEvent.eventType = "r0collector.outputUnavailable";
        outputEvent.path = options.outputPath;
        outputEvent.dataJson = BuildErrorData(outputError, ERROR_OPEN_FAILED, L"Create the parent directory or use --output -.");
        EmitFallbackEventToStderr(outputEvent);
        return kExitOutputUnavailable;
    }

    SandboxEventFields startedEvent;
    startedEvent.eventType = "r0collector.started";
    startedEvent.path = options.devicePath;
    startedEvent.dataJson = BuildConfigData(options);
    if (!EmitEvent(writer, startedEvent)) {
        return kExitRuntimeFailure;
    }

    if (!EmitCollectorHeartbeat(writer, options, "collectorStarted", 0, 0, 0, 0, 0, 0)) {
        return kExitRuntimeFailure;
    }

    if (options.abiSelfCheck) {
        return RunAbiSelfCheckMode(options, writer);
    }

    if (options.diagnose) {
        return RunReadinessDiagnoseMode(options, writer);
    }

    if (options.mockMode) {
        const int mockExitCode = RunSyntheticMode(options, writer);
        if (mockExitCode != kExitSuccess) {
            return mockExitCode;
        }

        if (!EmitCollectorHeartbeat(writer, options, "syntheticComplete", 0, 0, 0, 0, 0, 0)) {
            return kExitRuntimeFailure;
        }

        SandboxEventFields stoppedEvent;
        stoppedEvent.eventType = "r0collector.stopped";
        stoppedEvent.path = options.devicePath;
        JsonDataObjectBuilder stoppedData;
        stoppedData.AddUtf8("reason", "mockComplete");
        stoppedData.AddBool("ioctlIssued", false);
        stoppedData.AddBool("healthOnly", options.healthOnly);
        stoppedData.AddBool("heartbeat", options.heartbeat);
        stoppedData.AddBool("suppressSelfNoise", options.suppressSelfNoise);
        stoppedData.AddUtf8(
            "collectorNoisePolicy",
            options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
        stoppedData.AddUnsigned("driverEventSampleStride", options.driverEventSampleStride);
        stoppedData.AddUtf8(
            "driverEventSampling",
            options.driverEventSampleStride <= 1 ? "none" : "stride");
        stoppedData.AddSigned("stressCount", options.stressCount);
        stoppedData.AddBool("injectJsonlNoise", options.injectJsonlNoise);
        stoppedData.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
        stoppedData.AddUtf8("producer", "r0collector");
        stoppedData.AddBool("noise", false);
        stoppedData.AddBool("lost", false);
        stoppedData.AddBool("backpressure", false);
        stoppedEvent.dataJson = stoppedData.Build();
        return EmitEvent(writer, stoppedEvent) ? kExitSuccess : kExitRuntimeFailure;
    }

    DWORD openError = ERROR_SUCCESS;
    UniqueHandle device = OpenDriverDevice(options.devicePath, &openError);
    if (!device.IsValid()) {
        EmitDeviceUnavailableDiagnostic(writer, options, openError, "openDevice");
        return kExitDeviceUnavailable;
    }

    SandboxEventFields openedEvent;
    openedEvent.eventType = "r0collector.deviceOpened";
    openedEvent.path = options.devicePath;
    JsonDataObjectBuilder openedData;
    openedData.AddWide("devicePath", options.devicePath);
    openedData.AddWide("serviceName", options.serviceName);
    openedData.AddBool("ioctlIssued", false);
    openedData.AddBool("healthOnly", options.healthOnly);
    openedData.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    openedData.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    openedData.AddBool("enableMaskSpecified", options.enableMaskSpecified);
    openedData.AddUnsigned("enableMask", options.enableMask);
    openedData.AddUtf8("enableMaskHex", HexUnsignedLongLong(options.enableMask, 8));
    openedData.AddUnsigned("driverEventSampleStride", options.driverEventSampleStride);
    openedData.AddUtf8(
        "driverEventSampling",
        options.driverEventSampleStride <= 1 ? "none" : "stride");
    openedData.AddUtf8("ioctlProtocol", "KSwordSandboxDriverIoctl.h");
    openedData.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    openedData.AddUtf8("producer", "r0collector");
    openedData.AddBool("noise", false);
    openedData.AddBool("lost", false);
    openedData.AddBool("backpressure", false);
    openedEvent.dataJson = openedData.Build();
    if (!EmitEvent(writer, openedEvent)) {
        return kExitRuntimeFailure;
    }

    if (options.healthOnly) {
        return RunDriverHealthOnly(device, options, writer);
    }

    return RunDriverIoctlLoop(device, options, writer);
}

} // namespace KSword::Sandbox::R0Collector
