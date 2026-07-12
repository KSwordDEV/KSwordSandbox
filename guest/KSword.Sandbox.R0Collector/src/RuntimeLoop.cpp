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
    data.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUnsigned("abiVersionMajor", KSWORD_SANDBOX_ABI_VERSION_MAJOR);
    data.AddUnsigned("abiVersionMinor", KSWORD_SANDBOX_ABI_VERSION_MINOR);
    data.AddUnsigned("eventHeaderVersion", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    data.AddUtf8("eventHeaderVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8));
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUtf8("stableAbiVersionFields", kStableAbiVersionFields);
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
    if (options.stressCount > 0) {
        data.AddSigned("StressJsonlExpectedDriverRows", options.stressCount);
        data.AddSigned("StressJsonlSequenceStart", kSyntheticStressSequenceStart);
        data.AddSigned("StressJsonlSequenceEnd", kSyntheticStressSequenceStart + options.stressCount - 1);
        data.AddSigned("StressJsonlSequenceGapCount", 0);
        data.AddUtf8("StressJsonlLossEvidence", kStressJsonlLossEvidence);
        data.AddUtf8("StressJsonlBackpressureEvidence", kStressJsonlBackpressureEvidence);
        data.AddUtf8("stressBackpressureMode", "synthetic-no-device-evidence");
    }
    data.AddBool("mockMode", options.mockMode);
    data.AddBool("syntheticMode", options.mockMode);
    if (options.mockMode == true) {
        data.AddUtf8("semanticSelfCheckScenarios", kSyntheticSemanticSelfCheckScenarios);
        data.AddSigned("semanticContractVersion", kAbiSelfCheckDiagnosticsVersion);
        data.AddSigned("semanticSelfCheckRows", kSyntheticSemanticSelfCheckRows);
        data.AddSigned("semanticSelfCheckSequenceStart", kSyntheticSemanticSequenceStart);
        data.AddSigned(
            "semanticSelfCheckSequenceEnd",
            kSyntheticSemanticSequenceStart + kSyntheticSemanticSelfCheckRows - 1);
        data.AddBool("semanticCompanionRowsExcludedFromStress", true);
        data.AddUtf8("semanticStressCountPreservationPolicy", "semantic companion rows are not counted in StressJsonlExpectedDriverRows");
        data.AddWide(
            "zhSemanticSelfCheckHint",
            L"mock/stress 模式会附加 DNS/HTTP/TLS/横向移动/下载执行/进程血缘语义自检行；这些行不来自真实驱动。");
        data.AddUtf8("networkProtocolBoundaryFields", kNetworkProtocolBoundaryFields);
        data.AddUtf8("networkCorrelationStableFields", kNetworkCorrelationStableFields);
        data.AddUtf8("jsonlNoiseFieldSet", kJsonlNoiseFieldSet);
        data.AddUtf8("jsonlNoiseClassificationFields", kJsonlNoiseClassificationFields);
    }
    data.AddBool("injectJsonlNoise", options.injectJsonlNoise);
    data.AddUtf8("jsonlNoiseInjectionGuard", "noise injection is accepted only in mock/stress mode and rejected for abi/diagnose/health/live collection");
    data.AddWide("zhJsonlNoiseInjectionGuard", L"JSONL 噪声注入仅在 mock/stress 模式允许，ABI/就绪/健康/实时采集会拒绝。");
    data.AddBool("abiSelfCheck", options.abiSelfCheck);
    data.AddBool("diagnose", options.diagnose);
    data.AddBool("healthOnly", options.healthOnly);
    data.AddBool("heartbeat", options.heartbeat);
    data.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    data.AddUtf8(
        "selfNoiseFilterPolicy",
        options.mockMode
            ? "synthetic/no-device rows use kSyntheticSampleProcessId and explicit collectorSelfNoise=false"
            : "live READ_EVENTS rows classify collector PID/output-path/KSword infrastructure before emission");
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddBool("enableMaskSpecified", options.enableMaskSpecified);
    data.AddUnsigned("enableMask", options.enableMask);
    data.AddUtf8("enableMaskHex", HexUnsignedLongLong(options.enableMask, 8));
    data.AddUtf8("ioctlProtocol", "KSwordSandboxDriverIoctl.h");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "collector-lifecycle", "collector-lifecycle");
    AddCollectorNonBehaviorFields(data, "collector-lifecycle", "emit-collector-lifecycle-not-sample-behavior");
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
    data.AddUtf8("noiseClass", "collector-lifecycle");
    data.AddUtf8("selfNoiseClass", "none");
    data.AddUtf8("collectorNoiseClass", "none");
    data.AddUtf8("noiseAction", "emit");
    data.AddUtf8("noiseDisposition", "emitted-as-collector-lifecycle");
    data.AddUtf8("noiseReasons", "none");
    data.AddUtf8("noiseFieldSet", kJsonlNoiseFieldSet);
    data.AddUtf8("noiseTaxonomyVersion", "1");
    data.AddUtf8("noiseDecision", "collector-lifecycle");
    data.AddUtf8("noiseDecisionSource", "collector-run-configuration");
    data.AddUtf8("noiseClassificationConfidence", "high");
    data.AddUtf8("noiseProbeKind", "none");
    data.AddBool("sampleBehaviorCandidate", false);
    data.AddUtf8("sampleBehaviorCandidateReason", "collector-lifecycle-not-sample-behavior");
    data.AddWide("zhNoiseClassificationHint", L"噪声分类为 collector-lifecycle；该行描述采集器运行配置，不是样本行为。");
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUnsigned("highWatermark", 0);
    return data.Build();
}

// Input: CLI parse or output-open failure details.
// Processing: Builds a structured error object while keeping top-level fields
// compatible with SandboxEvent.
// Return: JSON object text for SandboxEvent.data.
std::wstring BuildZhErrorMessage(const DWORD errorCode) {
    if (errorCode == ERROR_INVALID_PARAMETER) {
        return L"\u547d\u4ee4\u884c\u53c2\u6570\u65e0\u6548\u3002";
    }

    if (errorCode == ERROR_OPEN_FAILED) {
        return L"\u8f93\u51fa JSONL \u6587\u4ef6\u65e0\u6cd5\u6253\u5f00\u3002";
    }

    return L"Collector \u8fd0\u884c\u65f6\u9519\u8bef\u3002";
}

std::wstring BuildZhErrorHint(const DWORD errorCode) {
    if (errorCode == ERROR_INVALID_PARAMETER) {
        return L"\u8bf7\u4f7f\u7528 --help \u67e5\u770b\u652f\u6301\u7684\u53c2\u6570\uff1b"
            L"\u786e\u8ba4\u9700\u8981\u503c\u7684\u9009\u9879\u540e\u9762\u8ddf\u4e86\u503c\uff0c"
            L"\u6570\u503c\u5728\u5141\u8bb8\u8303\u56f4\u5185\u3002";
    }

    if (errorCode == ERROR_OPEN_FAILED) {
        return L"\u8bf7\u521b\u5efa\u8f93\u51fa\u6587\u4ef6\u7236\u76ee\u5f55\u3001\u786e\u8ba4\u5199\u6743\u9650\uff0c"
            L"\u6216\u4f7f\u7528 --output - \u8f93\u51fa\u5230\u6807\u51c6\u8f93\u51fa\u3002";
    }

    return L"\u8bf7\u68c0\u67e5\u547d\u4ee4\u884c\u53c2\u6570\u6216\u8f93\u51fa\u8def\u5f84\u3002";
}

std::string BuildErrorData(const std::wstring& message, const DWORD errorCode, const std::wstring& hint) {
    JsonDataObjectBuilder data;
    data.AddWide("message", message);
    data.AddWide("zhMessage", BuildZhErrorMessage(errorCode));
    data.AddUnsigned("win32Error", errorCode);
    data.AddWide("hint", hint);
    data.AddWide("zhHint", BuildZhErrorHint(errorCode));
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "collector-error", "collector-diagnostic");
    AddCollectorNonBehaviorFields(data, "collector-error", "emit-collector-error-not-sample-behavior");
    data.AddBool("collectorNoise", true);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "collectionDiagnostic");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddUtf8("loss", "none");
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureReason", "none");
    data.AddUnsigned("highWatermark", 0);
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
    AddCollectorAttributionFields(data, "collector-heartbeat", "collector-lifecycle");
    AddCollectorNonBehaviorFields(data, "collector-heartbeat", "emit-collector-heartbeat-not-sample-behavior");
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

    if (!EmitDriverNetworkStatus(device, options, writer)) {
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
    data.AddBool("backpressure", drainStoppedAtBatchLimit);
    data.AddBool("backpressureObserved", drainStoppedAtBatchLimit);
    data.AddUnsigned("highWatermark", 0);

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
        stoppedData.AddUnsigned("driverEvents", options.stressCount > 0 ? options.stressCount : 0);
        stoppedData.AddUnsigned("driverRecordsProcessed", options.stressCount > 0 ? options.stressCount : 0);
        stoppedData.AddUnsigned("collectorSuppressedEvents", 0);
        stoppedData.AddUnsigned("collectorSkippedEvents", 0);
        stoppedData.AddUnsigned("readBatches", options.stressCount > 0 ? 1 : 0);
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
        AddCollectorAttributionFields(stoppedData, "collector-stopped", "collector-lifecycle");
        AddCollectorNonBehaviorFields(stoppedData, "collector-stopped", "emit-collector-stopped-not-sample-behavior");
        stoppedData.AddBool("collectorNoise", false);
        stoppedData.AddBool("collectorSelfNoise", false);
        stoppedData.AddBool("selfProcess", false);
        stoppedData.AddUtf8("collectorNoiseReason", "none");
        stoppedData.AddUtf8("collectorNoiseAction", "emit");
        stoppedData.AddBool("collectorSuppressed", false);
        stoppedData.AddBool("selfNoise", false);
        stoppedData.AddUtf8("selfNoiseReason", "none");
        stoppedData.AddUtf8("selfNoiseAction", "emit");
        stoppedData.AddBool("noise", false);
        stoppedData.AddBool("lost", false);
        stoppedData.AddUnsigned("lostCount", 0);
        stoppedData.AddBool("lossObserved", false);
        stoppedData.AddBool("backpressure", false);
        stoppedData.AddBool("backpressureObserved", false);
        stoppedData.AddUnsigned("highWatermark", 0);
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
    AddCollectorAttributionFields(openedData, "collector-device-open", "collector-diagnostic");
    AddCollectorNonBehaviorFields(openedData, "collector-device-open", "emit-collector-device-open-not-sample-behavior");
    openedData.AddBool("collectorNoise", false);
    openedData.AddBool("collectorSelfNoise", false);
    openedData.AddBool("selfProcess", false);
    openedData.AddUtf8("collectorNoiseReason", "none");
    openedData.AddUtf8("collectorNoiseAction", "emit");
    openedData.AddBool("collectorSuppressed", false);
    openedData.AddBool("selfNoise", false);
    openedData.AddUtf8("selfNoiseReason", "none");
    openedData.AddUtf8("selfNoiseAction", "emit");
    openedData.AddBool("noise", false);
    openedData.AddBool("lost", false);
    openedData.AddUnsigned("lostCount", 0);
    openedData.AddBool("lossObserved", false);
    openedData.AddBool("backpressure", false);
    openedData.AddBool("backpressureObserved", false);
    openedData.AddUnsigned("highWatermark", 0);
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
