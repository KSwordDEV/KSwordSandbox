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
UniqueHandle OpenDriverDevice(const std::wstring& devicePath, DWORD* errorCode) {
    const HANDLE handle = CreateFileW(
        devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (handle == INVALID_HANDLE_VALUE && errorCode != nullptr) {
        *errorCode = GetLastError();
    }

    return UniqueHandle(handle);
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
    data.AddUtf8("expectedInterfaceVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));

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
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));

    SandboxEventFields event;
    event.eventType = "r0collector.optionalIoctlUnavailable";
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
            return imagePayload->ProcessId != 0 ? "typedPayload.processId" : "eventHeader";
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

    std::string reasons;
    if (event.processId == GetCurrentProcessId()) {
        AppendSelfNoiseReason(&reasons, "collectorProcessId");
    }

    if (hasTypedSubjectPath) {
        if (EqualsNormalized(event.path, options.outputPath)) {
            AppendSelfNoiseReason(&reasons, "collectorOutputPath");
        }

        static constexpr const wchar_t* kInfrastructurePathFragments[] = {
            L"\\kswordsandbox\\agent\\",
            L"\\kswordsandbox\\r0collector\\",
            L"\\kswordsandbox\\driver\\",
            L"\\kswordsandbox\\out\\"
        };
        for (const wchar_t* fragment : kInfrastructurePathFragments) {
            if (ContainsNormalized(event.path, fragment)) {
                AppendSelfNoiseReason(&reasons, "kswordInfrastructurePath");
                break;
            }
        }

        const std::wstring fileName = BaseNameFromPath(event.path);
        if (EqualsNormalized(fileName, L"driver-events.jsonl") ||
            EqualsNormalized(fileName, L"r0collector.stdout.log") ||
            EqualsNormalized(fileName, L"r0collector.stderr.log") ||
            EqualsNormalized(fileName, L"events.json") ||
            EqualsNormalized(fileName, L"agent-summary.json")) {
            AppendSelfNoiseReason(&reasons, "kswordOutputArtifact");
        }
    }

    if (header.Type == KswSandboxEventTypeProcess) {
        if (ContainsNormalized(event.path, L"\\ksword.sandbox.r0collector.exe") ||
            ContainsNormalized(event.commandLine, L"ksword.sandbox.r0collector.exe") ||
            ContainsNormalized(event.path, L"\\ksword.sandbox.agent.exe") ||
            ContainsNormalized(event.commandLine, L"ksword.sandbox.agent.exe")) {
            AppendSelfNoiseReason(&reasons, "kswordToolProcess");
        }
    }

    if (!reasons.empty()) {
        attribution.selfNoise = true;
        attribution.suppressed = options.suppressSelfNoise;
        attribution.selfNoiseReason = reasons;
        attribution.selfNoiseAction = options.suppressSelfNoise ? "suppress" : "emit";
        attribution.actorRole = "collector-infrastructure";
        attribution.subjectRole = "collector-infrastructure";
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

// Input: READ_EVENTS output bytes and public reply header metadata.
// Processing: Walks the byte stream after the fixed reply header, validates each
// KSWORD_SANDBOX_EVENT_HEADER, and emits one driver-originated JSONL row per
// event header unless the row is classified as collector/guest self-noise.
// Return: true when all advertised event records were processed; false when the
// stream is malformed or the sink fails. Counter outputs distinguish emitted
// rows, consumed records, and rows suppressed by the collector policy.
bool EmitDriverEventRecords(
    EventWriter& writer,
    const Options& options,
    const unsigned long long batchIndex,
    const unsigned char* eventBytes,
    const size_t eventByteCount,
    const ULONG eventsWritten,
    unsigned long long* eventsEmitted,
    unsigned long long* recordsProcessed,
    unsigned long long* collectorSuppressedEvents) {
    size_t offset = 0;
    unsigned long long emitted = 0;
    unsigned long long processed = 0;
    unsigned long long suppressed = 0;

    while (processed < eventsWritten) {
        if (eventByteCount - offset < sizeof(KSWORD_SANDBOX_EVENT_HEADER)) {
            SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
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
            SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
            return EmitProtocolError(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
                L"READ_EVENTS returned an event record with an incompatible header.",
                static_cast<DWORD>(eventByteCount));
        }

        const size_t payloadCapacity = static_cast<size_t>(header.Size) - sizeof(header);
        if (static_cast<size_t>(header.PayloadSize) > payloadCapacity) {
            SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
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
            offset += header.Size;
            ++processed;
            ++suppressed;
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
            SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
            return false;
        }

        offset += header.Size;
        ++emitted;
        ++processed;
    }

    if (offset != eventByteCount) {
        SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            L"READ_EVENTS returned extra bytes after the advertised event records.",
            static_cast<DWORD>(eventByteCount));
    }

    SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
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

    unsigned long long emitted = 0;
    unsigned long long processed = 0;
    unsigned long long suppressed = 0;
    const size_t eventByteCount = static_cast<size_t>(reply.BytesWritten);
    const unsigned char* eventBytes = buffer.data() + reply.Size;
    if (!EmitDriverEventRecords(
            writer,
            options,
            batchIndex,
            eventBytes,
            eventByteCount,
            reply.EventsWritten,
            &emitted,
            &processed,
            &suppressed)) {
        SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
        return false;
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverReadEvents";
    event.path = options.devicePath;
    event.dataJson = BuildReadEventsBatchData(
        reply,
        bytesReturned,
        options.readEventsMaxEvents,
        emitted,
        processed,
        suppressed,
        options.suppressSelfNoise);
    if (!EmitEvent(writer, event)) {
        SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
        return false;
    }

    SetDriverEventRecordCounts(eventsEmitted, recordsProcessed, collectorSuppressedEvents, emitted, processed, suppressed);
    return true;
}

} // namespace KSword::Sandbox::R0Collector
