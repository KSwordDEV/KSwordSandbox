#include "IoctlClient.h"

#include "EventParser.h"

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <string>
#include <vector>

namespace KSword::Sandbox::R0Collector {

// Input: Device path supplied by the user.
// Processing: Opens the KSword driver control device with read/write access so
// the caller can issue GET_HEALTH, POLL, and READ_EVENTS IOCTLs.
// Return: A valid UniqueHandle on success; invalid handle and error code on failure.
UniqueHandle OpenDriverDeviceWithFlags(
    const std::wstring& devicePath,
    const DWORD flagsAndAttributes,
    DWORD* errorCode) {
    const HANDLE handle = CreateFileW(
        devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        flagsAndAttributes,
        nullptr);

    if (handle == INVALID_HANDLE_VALUE && errorCode != nullptr) {
        *errorCode = GetLastError();
    }

    return UniqueHandle(handle);
}

// Input: Device path supplied by the user.
// Processing: Opens the KSword driver control device with synchronous IOCTL
// semantics used by the normal collector loop.
// Return: A valid UniqueHandle on success; invalid handle and error code on failure.
UniqueHandle OpenDriverDevice(const std::wstring& devicePath, DWORD* errorCode) {
    return OpenDriverDeviceWithFlags(devicePath, FILE_ATTRIBUTE_NORMAL, errorCode);
}

// Input: Device handle, IOCTL code, optional input buffer, and output buffer.
// Processing: Calls DeviceIoControl and captures both byte count and Win32 error
// without throwing exceptions.
// Return: true on DeviceIoControl success; false with errorCode set otherwise.
bool CallDriverIoctl(
    const UniqueHandle& device,
    const DWORD ioctlCode,
    void* inputBuffer,
    const DWORD inputBytes,
    void* outputBuffer,
    const DWORD outputBytes,
    DWORD* bytesReturned,
    DWORD* errorCode) {
    DWORD localBytesReturned = 0;
    const BOOL ok = DeviceIoControl(
        device.Get(),
        ioctlCode,
        inputBuffer,
        inputBytes,
        outputBuffer,
        outputBytes,
        &localBytesReturned,
        nullptr);

    if (bytesReturned != nullptr) {
        *bytesReturned = localBytesReturned;
    }

    if (!ok) {
        if (errorCode != nullptr) {
            *errorCode = GetLastError();
        }
        return false;
    }

    if (errorCode != nullptr) {
        *errorCode = ERROR_SUCCESS;
    }
    return true;
}

// Input: Failed DeviceIoControl details plus collector options.
// Processing: Emits one structured error row while keeping the device-unavailable
// path separate for CreateFile failures.
// Return: true if the JSONL sink accepted the error event.
bool EmitIoctlFailure(
    EventWriter& writer,
    const Options& options,
    const std::string& ioctlName,
    const DWORD ioctlCode,
    const DWORD errorCode,
    const DWORD bytesReturned,
    const std::wstring& hint) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", ioctlName);
    data.AddUnsigned("ioctlCode", ioctlCode);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("win32Error", errorCode);
    data.AddWide("win32Message", Win32ErrorMessage(errorCode));
    data.AddWide("hint", hint);
    data.AddWide(
        "zhMessage",
        L"\u9a71\u52a8 IOCTL \u8c03\u7528\u5931\u8d25\uff1b"
        L"\u8fd9\u662f\u91c7\u96c6\u5065\u5eb7/\u5c31\u7eea\u8bca\u65ad\uff0c\u4e0d\u4ee3\u8868\u6837\u672c\u884c\u4e3a\u3002");
    data.AddWide(
        "zhHint",
        L"\u9a71\u52a8 IOCTL \u8c03\u7528\u5931\u8d25\uff1b"
        L"\u8bf7\u786e\u8ba4\u9a71\u52a8\u5df2\u52a0\u8f7d\u3001"
        L"\u6743\u9650\u8db3\u591f\u4e14\u9a71\u52a8/Collector ABI \u5339\u914d\u3002");
    data.AddUtf8("severity", "error");
    data.AddUtf8("readinessState", "blocked");
    data.AddUtf8("diagnosticCode", "ioctl_failure");
    data.AddUtf8("diagnosticStage", "ioctl");
    data.AddUtf8("collectionScope", "r0collector-ioctl");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddUtf8("eventOrigin", "collector-sidecar");
    data.AddUtf8("producerCategory", "r0collector");
    data.AddUtf8("subjectKind", "collector-diagnostic");
    data.AddUtf8("actorRole", "collector-infrastructure");
    data.AddUtf8("subjectRole", "collector-diagnostic");
    data.AddUtf8("processIdSource", "top-level");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("collectionNoise", true);
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

    SandboxEventFields event;
    event.eventType = "r0collector.ioctlFailure";
    event.path = options.devicePath;
    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Protocol validation failure details discovered after DeviceIoControl
// returned success.
// Processing: Emits a collector-owned error row with string-valued data so the
// malformed batch can be diagnosed without crashing the collector.
// Return: true if the JSONL sink accepted the protocol error event.
bool EmitProtocolError(
    EventWriter& writer,
    const Options& options,
    const std::string& ioctlName,
    const std::wstring& message,
    const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", ioctlName);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddWide("message", message);
    data.AddWide(
        "zhMessage",
        L"\u9a71\u52a8\u8fd4\u56de\u7684\u6570\u636e\u4e0e Collector \u671f\u671b\u7684 ABI \u4e0d\u517c\u5bb9\u3002");
    data.AddWide(
        "zhHint",
        L"\u8bf7\u91cd\u5efa\u5e76\u91cd\u65b0\u52a0\u8f7d\u5339\u914d\u7248\u672c\u7684\u9a71\u52a8\u548c Collector\u3002");
    data.AddUtf8("expectedInterfaceVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUtf8("severity", "error");
    data.AddUtf8("readinessState", "blocked");
    data.AddUtf8("diagnosticCode", "abi_mismatch");
    data.AddUtf8("diagnosticStage", "abiNegotiation");
    data.AddUtf8("collectionScope", "r0collector-abi");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddUtf8("eventOrigin", "collector-sidecar");
    data.AddUtf8("producerCategory", "r0collector");
    data.AddUtf8("subjectKind", "collector-diagnostic");
    data.AddUtf8("actorRole", "collector-infrastructure");
    data.AddUtf8("subjectRole", "collector-diagnostic");
    data.AddUtf8("processIdSource", "top-level");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("collectionNoise", true);
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

    SandboxEventFields event;
    event.eventType = "r0collector.driverProtocolError";
    event.path = options.devicePath;
    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Win32 error code from a failed optional DeviceIoControl call.
// Processing: Recognizes the common mappings for STATUS_INVALID_DEVICE_REQUEST
// and STATUS_NOT_SUPPORTED so newer collectors can keep draining older v1
// health/poll/read-events drivers.
// Return: true when the error means the optional IOCTL is unavailable.
bool IsOptionalIoctlUnavailable(const DWORD errorCode) {
    return errorCode == ERROR_INVALID_FUNCTION ||
           errorCode == ERROR_NOT_SUPPORTED;
}

// Input: Optional IOCTL failure details plus collector options.
// Processing: Emits a non-fatal diagnostic row for ABI negotiation paths that
// older live drivers may not implement while preserving the normal error fields.
// Return: true if the JSONL sink accepted the diagnostic event.
bool EmitOptionalIoctlUnavailable(
    EventWriter& writer,
    const Options& options,
    const std::string& ioctlName,
    const DWORD ioctlCode,
    const DWORD errorCode,
    const DWORD bytesReturned,
    const std::wstring& compatibilityAction) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", ioctlName);
    data.AddUnsigned("ioctlCode", ioctlCode);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("win32Error", errorCode);
    data.AddWide("win32Message", Win32ErrorMessage(errorCode));
    data.AddWide("compatibilityAction", compatibilityAction);
    data.AddWide(
        "zhMessage",
        L"\u53ef\u9009 IOCTL \u5728\u5f53\u524d\u9a71\u52a8\u4e0a\u4e0d\u53ef\u7528\uff1b"
        L"Collector \u5c06\u7ee7\u7eed\u517c\u5bb9\u8def\u5f84\u3002");
    data.AddWide(
        "zhCompatibilityAction",
        L"\u8be5\u53ef\u9009 IOCTL \u4e0d\u53ef\u7528\uff0cCollector \u4f1a\u7ee7\u7eed\u4f7f\u7528\u517c\u5bb9\u8def\u5f84\uff1b"
        L"\u5982\u679c\u9700\u8981\u5b8c\u6574\u961f\u5217/producer-mask \u8bca\u65ad\uff0c\u8bf7\u66f4\u65b0\u9a71\u52a8\u3002");
    data.AddWide(
        "zhHint",
        L"\u53ef\u9009 IOCTL \u4e0d\u53ef\u7528\u65f6 Collector \u4f1a\u5c1d\u8bd5\u7ee7\u7eed\uff1b"
        L"\u82e5\u9700\u8981\u5b8c\u6574\u961f\u5217\u3001\u80cc\u538b\u548c producer-mask \u5b57\u6bb5\uff0c"
        L"\u8bf7\u66f4\u65b0\u5230\u5339\u914d\u7684\u9a71\u52a8\u548c Collector\u3002");
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUtf8("severity", "warning");
    data.AddUtf8("readinessState", "degraded");
    data.AddUtf8("diagnosticCode", "optional_ioctl_unavailable");
    data.AddUtf8("diagnosticStage", "abiNegotiation");
    data.AddUtf8("collectionScope", "r0collector-abi");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddUtf8("eventOrigin", "collector-sidecar");
    data.AddUtf8("producerCategory", "r0collector");
    data.AddUtf8("subjectKind", "collector-diagnostic");
    data.AddUtf8("actorRole", "collector-infrastructure");
    data.AddUtf8("subjectRole", "collector-diagnostic");
    data.AddUtf8("processIdSource", "top-level");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("collectionNoise", true);
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

    SandboxEventFields event;
    event.eventType = "r0collector.optionalIoctlUnavailable";
    event.path = options.devicePath;
    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Failed GET_NETWORK_STATUS details from an otherwise opened device.
// Processing: Emits a network-specific degraded diagnostic with the same mask
// and counter keys used by successful replies so reports can render one stable
// shape even when older drivers do not implement the optional IOCTL.
// Return: true if the JSONL sink accepted the unavailable status event.
bool EmitNetworkStatusUnavailable(
    EventWriter& writer,
    const Options& options,
    const DWORD errorCode,
    const DWORD bytesReturned,
    const bool optionalUnavailable) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("win32Error", errorCode);
    data.AddWide("win32Message", Win32ErrorMessage(errorCode));
    data.AddUtf8("diagnosticStage", "networkStatus");
    data.AddUtf8(
        "diagnosticCode",
        optionalUnavailable ? "network_status_ioctl_unavailable" : "network_status_ioctl_failed");
    data.AddUtf8("severity", optionalUnavailable ? "warning" : "error");
    data.AddUtf8("readinessState", "degraded");
    data.AddUtf8("availabilityState", "unavailable");
    data.AddUtf8("collectionScope", "r0collector-network-status");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddWide(
        "hint",
        optionalUnavailable
            ? L"Loaded driver does not expose the optional GET_NETWORK_STATUS diagnostics IOCTL; continuing without WFP/ALE runtime status."
            : L"GET_NETWORK_STATUS failed. Continue collecting other driver evidence, then verify the loaded driver/collector ABI if network status is required.");
    data.AddWide(
        "zhMessage",
        L"R0 网络状态诊断 IOCTL 当前不可用；Collector 会继续采集其他 R0 证据。");
    data.AddWide(
        "zhHint",
        optionalUnavailable
            ? L"当前驱动可能是旧 ABI 或未包含 GET_NETWORK_STATUS；如需 WFP/ALE mask、counter 和错误字段，请使用同一构建产物的驱动与 Collector。"
            : L"GET_NETWORK_STATUS 调用失败；请检查驱动/Collector ABI、权限和驱动日志。该失败不会中断其他 producer 采集。");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-network-status", "collector-diagnostic");
    data.AddBool("collectionNoise", true);
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
    data.AddBool("networkStatusAvailable", false);
    data.AddBool("getNetworkStatusCapable", false);
    data.AddBool("networkWfpAleCapable", false);
    data.AddBool("networkWfpAleActive", false);
    data.AddBool("networkWfpAleDegraded", true);
    data.AddBool("networkWfpAleInspectOnly", false);
    data.AddBool("networkTodoRemaining", false);
    data.AddUtf8("networkStatusCapability", optionalUnavailable ? "ioctl-unavailable" : "ioctl-failed");
    data.AddUtf8("networkStatusKind", "wfp-ale-runtime-diagnostics");
    data.AddUtf8("networkStatusInterpretation", "collector_readiness_not_sample_behavior");
    data.AddUnsigned("flags", 0);
    data.AddUtf8("flagsHex", "0x00000000");
    data.AddUtf8("flagNames", "none");
    data.AddUnsigned("implementationLevel", KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_NONE);
    data.AddUtf8("implementationLevelName", "none");
    data.AddUnsigned("supportedLayerMask", 0);
    data.AddUtf8("supportedLayerMaskHex", "0x00000000");
    data.AddUtf8("supportedLayerMaskNames", "none");
    data.AddUnsigned("lastRegisteredCalloutMask", 0);
    data.AddUtf8("lastRegisteredCalloutMaskHex", "0x00000000");
    data.AddUtf8("lastRegisteredCalloutMaskNames", "none");
    data.AddUnsigned("lastAddedFilterMask", 0);
    data.AddUtf8("lastAddedFilterMaskHex", "0x00000000");
    data.AddUtf8("lastAddedFilterMaskNames", "none");
    data.AddUnsigned("activeLayerMask", 0);
    data.AddUtf8("activeLayerMaskHex", "0x00000000");
    data.AddUtf8("activeLayerMaskNames", "none");
    data.AddUnsigned("todoMask", 0);
    data.AddUtf8("todoMaskHex", "0x00000000");
    data.AddUtf8("todoMaskNames", "none");
    data.AddUnsigned("payloadVersion", 0);
    data.AddUtf8("payloadVersionHex", "0x00000000");
    data.AddSigned("lastDegradeReason", optionalUnavailable ? KswSandboxNetworkStatusDegradeNone : KswSandboxNetworkStatusDegradeQueuePush);
    data.AddUtf8("lastDegradeReasonName", optionalUnavailable ? "none" : "queue-push");
    data.AddSigned("lastDegradeNtStatus", 0);
    data.AddUtf8("lastDegradeNtStatusHex", "0x00000000");
    data.AddSigned("registerNtStatus", 0);
    data.AddUtf8("registerNtStatusHex", "0x00000000");
    data.AddSigned("engineNtStatus", 0);
    data.AddUtf8("engineNtStatusHex", "0x00000000");
    data.AddUnsigned("classifyCount", 0);
    data.AddUnsigned("eventCount", 0);
    data.AddUnsigned("queueFailureCount", 0);
    data.AddUnsigned("classifyPayloadFailureCount", 0);
    data.AddUnsigned("lastClassifyLayerId", 0);
    data.AddUtf8("lastClassifyLayerIdHex", "0x00000000");
    data.AddSigned("lastQueueFailureNtStatus", 0);
    data.AddUtf8("lastQueueFailureNtStatusHex", "0x00000000");
    data.AddUnsigned("lastQueueFailureLayerId", 0);
    data.AddUtf8("lastQueueFailureLayerIdHex", "0x00000000");
    data.AddUnsigned("lastClassifyPayloadFailureLayerId", 0);
    data.AddUtf8("lastClassifyPayloadFailureLayerIdHex", "0x00000000");

    SandboxEventFields event;
    event.eventType = "r0collector.driverNetworkStatus";
    event.path = options.devicePath;
    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Open driver handle, collector options, and JSONL sink.
// Processing: Issues IOCTL_KSWORD_SANDBOX_GET_HEALTH and writes a
// r0collector.driverHealth row with the public health reply fields.
// Return: true if the IOCTL succeeded, the reply was structurally valid, and the
// event sink accepted the health row.
bool EmitDriverHealth(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    KSWORD_SANDBOX_HEALTH_REPLY reply {};
    DWORD bytesReturned = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (!CallDriverIoctl(
            device,
            IOCTL_KSWORD_SANDBOX_GET_HEALTH,
            nullptr,
            0,
            &reply,
            static_cast<DWORD>(sizeof(reply)),
            &bytesReturned,
            &errorCode)) {
        return EmitIoctlFailure(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_HEALTH",
            IOCTL_KSWORD_SANDBOX_GET_HEALTH,
            errorCode,
            bytesReturned,
            L"Verify that the loaded driver matches the collector public ABI header.");
    }

    const bool producerMasksAdvertised =
        (reply.Flags & KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE) != 0;
    const bool producerMaskBytesReturned =
        bytesReturned >= static_cast<DWORD>(kHealthReplyProducerMaskBytes) &&
        reply.Size >= kHealthReplyProducerMaskBytes;

    if (bytesReturned < static_cast<DWORD>(kHealthReplyLegacyMinimumBytes) ||
        reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        reply.Size < kHealthReplyLegacyMinimumBytes) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_HEALTH",
            L"GET_HEALTH returned an incompatible KSWORD_SANDBOX_HEALTH_REPLY prefix.",
            bytesReturned);
    }

    if (producerMasksAdvertised && !producerMaskBytesReturned) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_HEALTH",
            L"GET_HEALTH advertised producer masks without returning the producer-mask fields.",
            bytesReturned);
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverHealth";
    event.path = options.devicePath;
    event.dataJson = BuildHealthData(reply, bytesReturned);
    return EmitEvent(writer, event);
}

// Input: Open driver handle, collector options, and JSONL sink.
// Processing: Issues IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES before normal event
// draining so the collector negotiates ABI limits, optional IOCTLs, and producer
// masks instead of assuming a matching driver.
// Return: true if the IOCTL succeeded, the reply was structurally valid, and
// the event sink accepted the capabilities row.
bool EmitDriverCapabilities(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    KSWORD_SANDBOX_CAPABILITIES_REPLY reply {};
    DWORD bytesReturned = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (!CallDriverIoctl(
            device,
            IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES,
            nullptr,
            0,
            &reply,
            static_cast<DWORD>(sizeof(reply)),
            &bytesReturned,
            &errorCode)) {
        if (IsOptionalIoctlUnavailable(errorCode)) {
            return EmitOptionalIoctlUnavailable(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES",
                IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES,
                errorCode,
                bytesReturned,
                L"Continuing with legacy health/poll/read-events behavior.");
        }
        return EmitIoctlFailure(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES",
            IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES,
            errorCode,
            bytesReturned,
            L"Verify that the loaded driver supports the public capabilities IOCTL.");
    }

    if (bytesReturned < static_cast<DWORD>(sizeof(reply)) ||
        reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        reply.Size < sizeof(reply) ||
        reply.AbiVersionMajor != KSWORD_SANDBOX_ABI_VERSION_MAJOR ||
        reply.EventHeaderVersion != KSWORD_SANDBOX_EVENT_HEADER_VERSION ||
        reply.EventMaxPayloadSize > KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES",
            L"GET_CAPABILITIES returned an incompatible KSWORD_SANDBOX_CAPABILITIES_REPLY.",
            bytesReturned);
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverCapabilities";
    event.path = options.devicePath;
    event.dataJson = BuildCapabilitiesData(reply, bytesReturned);
    return EmitEvent(writer, event);
}

// Input: Open driver handle, collector options, and JSONL sink.
// Processing: Issues IOCTL_KSWORD_SANDBOX_GET_STATUS and writes queue,
// producer-mask, and counter metadata before/after capture operations.
// Return: true if the IOCTL/reply/sink are valid.
bool EmitDriverStatus(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    KSWORD_SANDBOX_STATUS_REPLY reply {};
    DWORD bytesReturned = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (!CallDriverIoctl(
            device,
            IOCTL_KSWORD_SANDBOX_GET_STATUS,
            nullptr,
            0,
            &reply,
            static_cast<DWORD>(sizeof(reply)),
            &bytesReturned,
            &errorCode)) {
        if (IsOptionalIoctlUnavailable(errorCode)) {
            return EmitOptionalIoctlUnavailable(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_GET_STATUS",
                IOCTL_KSWORD_SANDBOX_GET_STATUS,
                errorCode,
                bytesReturned,
                L"Continuing without queue/status counter snapshots.");
        }
        return EmitIoctlFailure(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_STATUS",
            IOCTL_KSWORD_SANDBOX_GET_STATUS,
            errorCode,
            bytesReturned,
            L"Verify that the loaded driver supports the public status IOCTL.");
    }

    if (bytesReturned < static_cast<DWORD>(sizeof(reply)) ||
        reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        reply.Size < sizeof(reply)) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_STATUS",
            L"GET_STATUS returned an incompatible KSWORD_SANDBOX_STATUS_REPLY.",
            bytesReturned);
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverStatus";
    event.path = options.devicePath;
    event.dataJson = BuildStatusData(reply, bytesReturned);
    return EmitEvent(writer, event);
}

// Input: Open driver handle, collector options, and JSONL sink.
// Processing: Issues optional IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS and
// writes a r0collector.driverNetworkStatus row with WFP/ALE masks, counters,
// capability state, and last error fields. Older drivers that do not implement
// this IOCTL produce a degraded unavailable row and normal collection continues.
// Return: true when a success/unavailable diagnostic row was emitted.
bool EmitDriverNetworkStatus(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    KSWORD_SANDBOX_NETWORK_STATUS_REPLY reply {};
    DWORD bytesReturned = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (!CallDriverIoctl(
            device,
            IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS,
            nullptr,
            0,
            &reply,
            static_cast<DWORD>(sizeof(reply)),
            &bytesReturned,
            &errorCode)) {
        return EmitNetworkStatusUnavailable(
            writer,
            options,
            errorCode,
            bytesReturned,
            IsOptionalIoctlUnavailable(errorCode));
    }

    if (bytesReturned < static_cast<DWORD>(sizeof(reply)) ||
        reply.Version != KSWORD_SANDBOX_NETWORK_STATUS_REPLY_VERSION ||
        reply.Size < sizeof(reply)) {
        return EmitNetworkStatusUnavailable(
            writer,
            options,
            ERROR_REVISION_MISMATCH,
            bytesReturned,
            false);
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverNetworkStatus";
    event.path = options.devicePath;
    event.dataJson = BuildNetworkStatusData(reply, bytesReturned);
    return EmitEvent(writer, event);
}

// Input: Open driver handle and collector options carrying --enable-mask.
// Processing: Issues IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK only when
// requested by the operator, then records requested/previous/effective masks.
// Return: true if no mask was requested or the IOCTL/reply/sink are valid.
bool EmitDriverSetProducerEnableMask(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    if (!options.enableMaskSpecified) {
        return true;
    }

    std::vector<unsigned char> buffer(sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY));
    auto* request = reinterpret_cast<PKSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST>(buffer.data());
    request->Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    request->Size = sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST);
    request->EnableMask = options.enableMask;
    request->Flags = 0;

    DWORD bytesReturned = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (!CallDriverIoctl(
            device,
            IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK,
            request,
            static_cast<DWORD>(sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST)),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytesReturned,
            &errorCode)) {
        if (IsOptionalIoctlUnavailable(errorCode)) {
            return EmitOptionalIoctlUnavailable(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK",
                IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK,
                errorCode,
                bytesReturned,
                L"Continuing with the driver default producer mask.");
        }
        return EmitIoctlFailure(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK",
            IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK,
            errorCode,
            bytesReturned,
            L"Ensure the requested producer mask is a subset of the supported mask.");
    }

    if (bytesReturned < static_cast<DWORD>(sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY))) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK",
            L"SET_PRODUCER_ENABLE_MASK returned fewer bytes than the public reply.",
            bytesReturned);
    }

    KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY reply {};
    std::memcpy(&reply, buffer.data(), sizeof(reply));
    if (reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        reply.Size < sizeof(reply)) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK",
            L"SET_PRODUCER_ENABLE_MASK returned an incompatible reply.",
            bytesReturned);
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverProducerMask";
    event.path = options.devicePath;
    event.dataJson = BuildSetProducerEnableMaskData(reply, bytesReturned, options.enableMask);
    return EmitEvent(writer, event);
}

// Input: Open driver handle, collector options, and JSONL sink.
// Processing: Issues IOCTL_KSWORD_SANDBOX_POLL and writes a
// r0collector.driverPoll row with the queue snapshot.
// Return: true if the IOCTL succeeded, the reply was structurally valid, and the
// event sink accepted the poll row.
bool EmitDriverPoll(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    KSWORD_SANDBOX_POLL_REPLY reply {};
    DWORD bytesReturned = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (!CallDriverIoctl(
            device,
            IOCTL_KSWORD_SANDBOX_POLL,
            nullptr,
            0,
            &reply,
            static_cast<DWORD>(sizeof(reply)),
            &bytesReturned,
            &errorCode)) {
        return EmitIoctlFailure(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_POLL",
            IOCTL_KSWORD_SANDBOX_POLL,
            errorCode,
            bytesReturned,
            L"Verify that the loaded driver supports the skeleton POLL IOCTL.");
    }

    if (bytesReturned < static_cast<DWORD>(sizeof(reply)) ||
        reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        reply.Size < sizeof(reply)) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_POLL",
            L"POLL returned an incompatible KSWORD_SANDBOX_POLL_REPLY.",
            bytesReturned);
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverPoll";
    event.path = options.devicePath;
    event.dataJson = BuildPollData(reply, bytesReturned);
    return EmitEvent(writer, event);
}

// Input: UTF-16 text from driver payloads or collector options.
// Processing: Normalizes slashes and ASCII/Unicode casing for conservative
// infrastructure path matching without touching the filesystem.
// Return: Lowercase path-like text used only for comparisons.
std::wstring NormalizedCompareText(std::wstring value) {
    std::replace(value.begin(), value.end(), L'/', L'\\');
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(ch)));
        });
    return value;
}

// Input: Two UTF-16 values.
// Processing: Compares with the same normalization used for self-noise path
// fragments so equivalent slash/case variants are treated consistently.
// Return: true when the normalized values are identical and non-empty.
bool EqualsNormalized(const std::wstring& left, const std::wstring& right) {
    return !left.empty() && !right.empty() &&
        NormalizedCompareText(left) == NormalizedCompareText(right);
}

// Input: A path-like value and a literal lowercase/uppercase fragment.
// Processing: Performs a case-insensitive contains check after slash
// normalization. The fragment is not treated as a glob or regular expression.
// Return: true when the normalized value contains the normalized fragment.
bool ContainsNormalized(const std::wstring& value, const wchar_t* fragment) {
    if (value.empty() || fragment == nullptr || fragment[0] == L'\0') {
        return false;
    }

    return NormalizedCompareText(value).find(NormalizedCompareText(fragment)) != std::wstring::npos;
}

// Input: Mutable reason string plus a short reason token.
// Processing: Appends pipe-delimited reason tokens so suppressed event batches
// remain diagnosable without emitting each noisy row.
// Return: No return value.
void AppendSelfNoiseReason(std::string* reasons, const char* reason) {
    if (reasons == nullptr || reason == nullptr || reason[0] == '\0') {
        return;
    }

    if (!reasons->empty()) {
        *reasons += "|";
    }
    *reasons += reason;
}

// Input: Driver event type plus bounded payload bytes.
// Processing: Detects whether the top-level SandboxEvent.processId was derived
// from a typed payload subject PID or fell back to the callback/header PID.
// Return: Stable data.processIdSource value.
std::string DriverProcessIdSource(
    const ULONG eventType,
    const unsigned char* payload,
    const size_t payloadBytes) {
    if (payload == nullptr) {
        return "eventHeader";
    }

    switch (eventType) {
    case KswSandboxEventTypeProcess:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)) {
            const auto* processPayload =
                reinterpret_cast<const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD*>(payload);
            return processPayload->ProcessId != 0 ? "typedPayload.processId" : "eventHeader";
        }
        break;

    case KswSandboxEventTypeImage:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)) {
            const auto* imagePayload =
                reinterpret_cast<const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD*>(payload);
            const bool processIdPresent =
                (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT) != 0;
            return (processIdPresent && imagePayload->ProcessId != 0)
                ? "typedPayload.processId"
                : "eventHeader";
        }
        break;

    case KswSandboxEventTypeFile:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)) {
            const auto* filePayload =
                reinterpret_cast<const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD*>(payload);
            return filePayload->ProcessId != 0 ? "typedPayload.processId" : "eventHeader";
        }
        break;

    case KswSandboxEventTypeRegistry:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)) {
            const auto* registryPayload =
                reinterpret_cast<const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD*>(payload);
            return registryPayload->ProcessId != 0 ? "typedPayload.processId" : "eventHeader";
        }
        break;

    case KswSandboxEventTypeNetwork:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)) {
            const auto* networkPayload =
                reinterpret_cast<const KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD*>(payload);
            const bool processIdPresent =
                (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT) != 0;
            return (processIdPresent && networkPayload->ProcessId != 0)
                ? "typedPayload.processId"
                : "eventHeader";
        }
        break;

    default:
        break;
    }

    return "eventHeader";
}

// Input: Public driver event type.
// Processing: Names the subject kind independently from eventType so reports and
// raw JSONL can explain what object the row is about.
// Return: Stable subject kind label.
std::string DriverSubjectKind(const ULONG eventType) {
    switch (eventType) {
    case KswSandboxEventTypeDriverLoad:
        return "driver";
    case KswSandboxEventTypeProcess:
        return "process";
    case KswSandboxEventTypeImage:
        return "image";
    case KswSandboxEventTypeFile:
        return "file";
    case KswSandboxEventTypeRegistry:
        return "registry";
    case KswSandboxEventTypeNetwork:
        return "network-flow";
    case KswSandboxEventTypeReserved:
        return "reserved";
    case KswSandboxEventTypeNone:
        return "none";
    default:
        return "unknown";
    }
}

// Input: One decoded driver event plus collector options.
// Processing: Classifies collector/guest-agent infrastructure rows by PID and
// known KSword paths.  The policy is deliberately narrow: exact collector output
// file, collector PID, and documented KSword infrastructure directories/files.
// Return: Attribution metadata consumed by JSONL serialization and suppression.
DriverEventAttribution BuildDriverEventAttribution(
    const Options& options,
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    const unsigned char* payload,
    const size_t payloadBytes,
    const SandboxEventFields& event,
    const bool hasTypedSubjectPath) {
    DriverEventAttribution attribution;
    attribution.producerCategory =
        header.Type == KswSandboxEventTypeDriverLoad ? "driver" : DriverEventTypeName(header.Type);
    attribution.subjectKind = DriverSubjectKind(header.Type);
    attribution.processIdSource = DriverProcessIdSource(header.Type, payload, payloadBytes);
    attribution.collectorNoisePolicy = options.suppressSelfNoise
        ? "suppress-self-noise"
        : "emit-self-noise";
    attribution.eventOrigin =
        header.Type == KswSandboxEventTypeDriverLoad ? "kernel-driver-control-plane" : "kernel-driver";
    attribution.actorRole =
        attribution.processIdSource == "eventHeader" ? "callback-current-process" : "payload-subject-process";
    attribution.subjectRole =
        header.Type == KswSandboxEventTypeDriverLoad ? "driver-control-plane" : "sample-or-system";

    std::string selfNoiseReasons;
    std::string collectorNoiseReasons;
    const auto appendCollectorNoise = [&](const char* reason) {
        AppendSelfNoiseReason(&collectorNoiseReasons, reason);
        AppendSelfNoiseReason(&selfNoiseReasons, reason);
    };

    if ((header.Flags & KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE) != 0 ||
        (header.ProducerMetadataFlags & KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE) != 0) {
        AppendSelfNoiseReason(&selfNoiseReasons, "producerSelfNoiseFlag");
    }

    const bool isCurrentCollectorProcessId = event.processId == GetCurrentProcessId();
    if (isCurrentCollectorProcessId) {
        attribution.selfProcess = true;
        appendCollectorNoise("collectorProcessId");
    }

    const std::wstring eventPathBaseName = BaseNameFromPath(event.path);
    if (EqualsNormalized(event.processName, L"KSword.Sandbox.R0Collector.exe") ||
        EqualsNormalized(eventPathBaseName, L"KSword.Sandbox.R0Collector.exe") ||
        ContainsNormalized(event.commandLine, L"ksword.sandbox.r0collector.exe")) {
        attribution.selfProcess = true;
        appendCollectorNoise("collectorExecutable");
    }

    if (hasTypedSubjectPath) {
        if (EqualsNormalized(event.path, options.outputPath)) {
            appendCollectorNoise("collectorOutputPath");
        }

        static constexpr const wchar_t* kInfrastructurePathFragments[] = {
            L"\\kswordsandbox\\agent\\",
            L"\\kswordsandbox\\r0collector\\",
            L"\\kswordsandbox\\driver\\",
            L"\\kswordsandbox\\out\\"
        };
        for (const wchar_t* fragment : kInfrastructurePathFragments) {
            if (ContainsNormalized(event.path, fragment)) {
                appendCollectorNoise("kswordInfrastructurePath");
                break;
            }
        }

        if (EqualsNormalized(eventPathBaseName, L"driver-events.jsonl") ||
            EqualsNormalized(eventPathBaseName, L"r0collector.stdout.log") ||
            EqualsNormalized(eventPathBaseName, L"r0collector.stderr.log") ||
            EqualsNormalized(eventPathBaseName, L"events.json") ||
            EqualsNormalized(eventPathBaseName, L"agent-summary.json")) {
            appendCollectorNoise("kswordOutputArtifact");
        }
    }

    if (header.Type == KswSandboxEventTypeProcess) {
        if (ContainsNormalized(event.path, L"\\ksword.sandbox.r0collector.exe") ||
            ContainsNormalized(event.commandLine, L"ksword.sandbox.r0collector.exe") ||
            ContainsNormalized(event.path, L"\\ksword.sandbox.agent.exe") ||
            ContainsNormalized(event.commandLine, L"ksword.sandbox.agent.exe")) {
            appendCollectorNoise("kswordToolProcess");
        }
    }

    if (!collectorNoiseReasons.empty()) {
        attribution.collectorNoise = true;
        attribution.collectorNoiseReason = collectorNoiseReasons;
        attribution.collectorNoiseAction = options.suppressSelfNoise ? "suppress" : "emit";
    }

    if (!selfNoiseReasons.empty()) {
        attribution.selfNoise = true;
        attribution.suppressed = options.suppressSelfNoise;
        attribution.selfNoiseReason = selfNoiseReasons;
        attribution.selfNoiseAction = options.suppressSelfNoise ? "suppress" : "emit";
        if (attribution.collectorNoise) {
            attribution.actorRole = "collector-infrastructure";
            attribution.subjectRole = "collector-infrastructure";
        }
    }

    return attribution;
}

// Input: Output counter pointers from the caller.
// Processing: Writes all available READ_EVENTS accounting counters defensively.
// Return: No return value.
void SetDriverEventRecordCounts(
    unsigned long long* eventsEmitted,
    unsigned long long* recordsProcessed,
    unsigned long long* collectorSuppressedEvents,
    const unsigned long long emitted,
    const unsigned long long processed,
    const unsigned long long suppressed) {
    if (eventsEmitted != nullptr) {
        *eventsEmitted = emitted;
    }
    if (recordsProcessed != nullptr) {
        *recordsProcessed = processed;
    }
    if (collectorSuppressedEvents != nullptr) {
        *collectorSuppressedEvents = suppressed;
    }
}

// Input: Output pointers from the caller plus the richer batch counter object.
// Processing: Preserves the legacy three-counter outputs while making the full
// batch telemetry available to the JSON summary builder.
// Return: No return value.
void SetDriverEventBatchCounters(
    unsigned long long* eventsEmitted,
    unsigned long long* recordsProcessed,
    unsigned long long* collectorSuppressedEvents,
    DriverReadEventsBatchCounters* batchCounters,
    const DriverReadEventsBatchCounters& counters) {
    SetDriverEventRecordCounts(
        eventsEmitted,
        recordsProcessed,
        collectorSuppressedEvents,
        counters.eventsEmitted,
        counters.recordsProcessed,
        counters.collectorSuppressedEvents);

    if (batchCounters != nullptr) {
        *batchCounters = counters;
    }
}

// Input: Mutable batch counters and one driver event sequence value.
// Processing: Tracks the first and last consumed record sequence values without
// assuming the stream is contiguous.
// Return: No return value.
void ObserveProcessedSequence(
    DriverReadEventsBatchCounters* counters,
    const unsigned long long sequence) {
    if (counters == nullptr) {
        return;
    }

    if (!counters->hasSequenceRange) {
        counters->hasSequenceRange = true;
        counters->headSequence = sequence;
    }
    counters->tailSequence = sequence;
}

// Input: Mutable batch counters and one emitted driver event sequence value.
// Processing: Tracks the first and last JSONL-emitted sequence values so
// optional collector sampling remains diagnosable.
// Return: No return value.
void ObserveEmittedSequence(
    DriverReadEventsBatchCounters* counters,
    const unsigned long long sequence) {
    if (counters == nullptr) {
        return;
    }

    if (!counters->hasEmittedSequenceRange) {
        counters->hasEmittedSequenceRange = true;
        counters->emittedHeadSequence = sequence;
    }
    counters->emittedTailSequence = sequence;
}

// Input: Collector options and the 1-based eligible-record ordinal.
// Processing: Implements the opt-in stride sampler.  The first eligible record
// is always emitted, then every nth eligible record is emitted.
// Return: true when the eligible record should be skipped by collector sampling.
bool ShouldSkipEligibleDriverEvent(
    const Options& options,
    const unsigned long long eligibleOrdinal) {
    return options.driverEventSampleStride > 1 &&
        eligibleOrdinal > 1 &&
        ((eligibleOrdinal - 1ULL) % options.driverEventSampleStride) != 0ULL;
}

// Input: READ_EVENTS output bytes and public reply header metadata.
// Processing: Walks the byte stream after the fixed reply header, validates each
// KSWORD_SANDBOX_EVENT_HEADER, and emits one driver-originated JSONL row per
// event header unless the row is classified as collector/guest self-noise.
// Return: true when all advertised event records were processed; false when the
// stream is malformed or the sink fails. Counter outputs distinguish emitted
// rows, consumed records, rows suppressed by policy, and rows skipped by optional
// collector sampling.
bool EmitDriverEventRecords(
    EventWriter& writer,
    const Options& options,
    const unsigned long long batchIndex,
    const unsigned char* eventBytes,
    const size_t eventByteCount,
    const ULONG eventsWritten,
    unsigned long long* eventsEmitted,
    unsigned long long* recordsProcessed,
    unsigned long long* collectorSuppressedEvents,
    DriverReadEventsBatchCounters* batchCounters) {
    size_t offset = 0;
    DriverReadEventsBatchCounters counters;

    while (counters.recordsProcessed < eventsWritten) {
        if (eventByteCount - offset < sizeof(KSWORD_SANDBOX_EVENT_HEADER)) {
            SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, batchCounters, counters);
            return EmitProtocolError(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
                L"READ_EVENTS ended before the next KSWORD_SANDBOX_EVENT_HEADER.",
                static_cast<DWORD>(eventByteCount));
        }

        KSWORD_SANDBOX_EVENT_HEADER header {};
        std::memcpy(&header, eventBytes + offset, sizeof(header));

        if (header.Version != KSWORD_SANDBOX_EVENT_HEADER_VERSION ||
            header.Size < sizeof(header) ||
            static_cast<size_t>(header.Size) > eventByteCount - offset) {
            SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, batchCounters, counters);
            return EmitProtocolError(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
                L"READ_EVENTS returned an event record with an incompatible header.",
                static_cast<DWORD>(eventByteCount));
        }

        const size_t payloadCapacity = static_cast<size_t>(header.Size) - sizeof(header);
        if (static_cast<size_t>(header.PayloadSize) > payloadCapacity) {
            SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, batchCounters, counters);
            return EmitProtocolError(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
                L"READ_EVENTS returned an event record whose PayloadSize exceeds record Size.",
                static_cast<DWORD>(eventByteCount));
        }

        const unsigned char* payload = eventBytes + offset + sizeof(header);
        SandboxEventFields event;
        event.eventType = DriverEventJsonType(header.Type);
        event.source = "driver";
        event.processName.clear();
        event.commandLine.clear();
        event.processId = ExtractTypedPayloadProcessId(
            header.Type,
            payload,
            header.PayloadSize,
            header.ProcessId);
        event.path = options.devicePath;
        const std::wstring subjectPath =
            ExtractTypedPayloadPath(header.Type, payload, header.PayloadSize);
        const bool hasTypedSubjectPath = !subjectPath.empty();
        if (hasTypedSubjectPath) {
            event.path = subjectPath;
        }
        const std::wstring processName =
            ExtractTypedPayloadProcessName(header.Type, payload, header.PayloadSize);
        if (!processName.empty()) {
            event.processName = processName;
        }
        const std::wstring commandLine =
            ExtractTypedPayloadCommandLine(header.Type, payload, header.PayloadSize);
        if (!commandLine.empty()) {
            event.commandLine = commandLine;
        }

        const DriverEventAttribution attribution = BuildDriverEventAttribution(
            options,
            header,
            payload,
            header.PayloadSize,
            event,
            hasTypedSubjectPath);

        if (attribution.suppressed) {
            ObserveProcessedSequence(&counters, header.Sequence);
            offset += header.Size;
            ++counters.recordsProcessed;
            ++counters.collectorSuppressedEvents;
            continue;
        }

        ++counters.eligibleEvents;
        if (ShouldSkipEligibleDriverEvent(options, counters.eligibleEvents)) {
            ObserveProcessedSequence(&counters, header.Sequence);
            offset += header.Size;
            ++counters.recordsProcessed;
            ++counters.collectorSkippedEvents;
            continue;
        }

        event.dataJson = BuildDriverEventData(
            header,
            batchIndex,
            static_cast<unsigned long long>(offset),
            payload,
            header.PayloadSize,
            attribution);

        if (!EmitEvent(writer, event)) {
            SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, batchCounters, counters);
            return false;
        }

        ObserveProcessedSequence(&counters, header.Sequence);
        ObserveEmittedSequence(&counters, header.Sequence);
        offset += header.Size;
        ++counters.eventsEmitted;
        ++counters.recordsProcessed;
    }

    if (offset != eventByteCount) {
        SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, batchCounters, counters);
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            L"READ_EVENTS returned extra bytes after the advertised event records.",
            static_cast<DWORD>(eventByteCount));
    }

    SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, batchCounters, counters);
    return true;
}

// Input: Open driver handle, collector options, batch index, and JSONL sink.
// Processing: Issues IOCTL_KSWORD_SANDBOX_READ_EVENTS with a public request
// header, emits one row per returned event header, then emits a batch summary.
// Return: true if the IOCTL, event parsing, and JSONL writes all succeeded.
bool EmitDriverReadEvents(
    const UniqueHandle& device,
    const Options& options,
    const unsigned long long batchIndex,
    EventWriter& writer,
    unsigned long long* eventsEmitted,
    unsigned long long* recordsProcessed,
    unsigned long long* collectorSuppressedEvents) {
    KSWORD_SANDBOX_READ_EVENTS_REQUEST request {};
    request.Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    request.Size = sizeof(request);
    request.MaxEvents = options.readEventsMaxEvents;
    /*
     * READ_EVENTS currently reserves Flags and the kernel validates that the
     * field is zero.  Producer selection is negotiated exclusively through
     * IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK before draining.
     */
    request.Flags = 0;
    request.StartingSequence = 0;

    std::vector<unsigned char> buffer(kReadEventsBufferBytes);
    DWORD bytesReturned = 0;
    DWORD errorCode = ERROR_SUCCESS;

    if (!CallDriverIoctl(
            device,
            IOCTL_KSWORD_SANDBOX_READ_EVENTS,
            &request,
            static_cast<DWORD>(sizeof(request)),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytesReturned,
            &errorCode)) {
        return EmitIoctlFailure(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            IOCTL_KSWORD_SANDBOX_READ_EVENTS,
            errorCode,
            bytesReturned,
            L"Verify that the loaded driver supports the skeleton READ_EVENTS IOCTL.");
    }

    if (bytesReturned < KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            L"READ_EVENTS returned fewer bytes than KSWORD_SANDBOX_READ_EVENTS_REPLY header.",
            bytesReturned);
    }

    KSWORD_SANDBOX_READ_EVENTS_REPLY reply {};
    std::memcpy(&reply, buffer.data(), KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);

    if (reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        reply.Size < KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE ||
        reply.Size > bytesReturned) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            L"READ_EVENTS returned an incompatible fixed reply header.",
            bytesReturned);
    }

    const unsigned long long availableEventBytes = bytesReturned - reply.Size;
    if (reply.BytesWritten > availableEventBytes) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            L"READ_EVENTS BytesWritten exceeds the returned output buffer size.",
            bytesReturned);
    }

    DriverReadEventsBatchCounters counters;
    const size_t eventByteCount = static_cast<size_t>(reply.BytesWritten);
    const unsigned char* eventBytes = buffer.data() + reply.Size;
    if (!EmitDriverEventRecords(
            writer,
            options,
            batchIndex,
            eventBytes,
            eventByteCount,
            reply.EventsWritten,
            nullptr,
            nullptr,
            nullptr,
            &counters)) {
        SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, nullptr, counters);
        return false;
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverReadEvents";
    event.path = options.devicePath;
    event.dataJson = BuildReadEventsBatchData(
        reply,
        bytesReturned,
        options.readEventsMaxEvents,
        counters,
        options.driverEventSampleStride,
        options.suppressSelfNoise);
    if (!EmitEvent(writer, event)) {
        SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, nullptr, counters);
        return false;
    }

    SetDriverEventBatchCounters(eventsEmitted, recordsProcessed, collectorSuppressedEvents, nullptr, counters);
    return true;
}

} // namespace KSword::Sandbox::R0Collector
