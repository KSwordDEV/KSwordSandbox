#include "ReadinessDiagnostics.h"

#include "EventParser.h"
#include "IoctlClient.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace KSword::Sandbox::R0Collector {
namespace {

struct ReadinessSummary {
    bool blocked = false;
    bool degraded = false;
    std::string highestSeverity = "info";
    std::string readinessState = "ready";
    std::string failedStage = "none";
    std::string serviceDiagnosticCode = "not_checked";
    std::string openDeviceDiagnosticCode = "not_checked";
    std::string abiDiagnosticCode = "not_checked";
    std::string readEventsDiagnosticCode = "not_checked";
};

class UniqueServiceHandle {
public:
    UniqueServiceHandle() = default;
    explicit UniqueServiceHandle(SC_HANDLE handle) : handle_(handle) {}

    UniqueServiceHandle(const UniqueServiceHandle&) = delete;
    UniqueServiceHandle& operator=(const UniqueServiceHandle&) = delete;

    UniqueServiceHandle(UniqueServiceHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    UniqueServiceHandle& operator=(UniqueServiceHandle&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~UniqueServiceHandle() {
        Close();
    }

    bool IsValid() const {
        return handle_ != nullptr;
    }

    SC_HANDLE Get() const {
        return handle_;
    }

private:
    void Close() {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
            handle_ = nullptr;
        }
    }

    SC_HANDLE handle_ = nullptr;
};

// Input: Severity label produced by readiness probes.
// Processing: Maps the label to an ordering so summary can preserve the highest
// observed severity without introducing a logging dependency.
// Return: Numeric rank where larger values are more severe.
int SeverityRank(const std::string& severity) {
    if (severity == "error") {
        return 3;
    }
    if (severity == "warning") {
        return 2;
    }
    return 1;
}

// Input: Mutable readiness summary and one probe result.
// Processing: Updates highest severity, stage-specific code, and final state
// using the machine-readable diagnostic fields emitted to JSONL.
// Return: No return value.
void RecordProbe(
    ReadinessSummary* summary,
    const std::string& stage,
    const std::string& code,
    const std::string& severity,
    const std::string& state) {
    if (summary == nullptr) {
        return;
    }

    if (SeverityRank(severity) > SeverityRank(summary->highestSeverity)) {
        summary->highestSeverity = severity;
    }

    if (stage == "service") {
        summary->serviceDiagnosticCode = code;
    } else if (stage == "openDevice") {
        summary->openDeviceDiagnosticCode = code;
    } else if (stage == "abiNegotiation") {
        summary->abiDiagnosticCode = code;
    } else if (stage == "readEvents") {
        summary->readEventsDiagnosticCode = code;
    }

    if (state == "blocked") {
        summary->blocked = true;
        if (summary->failedStage == "none") {
            summary->failedStage = stage;
        }
    } else if (state == "degraded") {
        summary->degraded = true;
    }

    summary->readinessState = summary->blocked
        ? "blocked"
        : (summary->degraded ? "degraded" : "ready");
}

// Input: Win32 service state code returned by QueryServiceStatusEx.
// Processing: Converts SCM constants into stable JSONL text.
// Return: Service state name, preserving unrecognized values.
std::string ServiceStateName(const DWORD state) {
    switch (state) {
    case SERVICE_STOPPED:
        return "stopped";
    case SERVICE_START_PENDING:
        return "start_pending";
    case SERVICE_STOP_PENDING:
        return "stop_pending";
    case SERVICE_RUNNING:
        return "running";
    case SERVICE_CONTINUE_PENDING:
        return "continue_pending";
    case SERVICE_PAUSE_PENDING:
        return "pause_pending";
    case SERVICE_PAUSED:
        return "paused";
    default:
        return "unrecognized";
    }
}

// Input: Win32 service start type from QueryServiceConfigW.
// Processing: Converts SCM constants into stable JSONL text.
// Return: Start type name.
std::string ServiceStartTypeName(const DWORD startType) {
    switch (startType) {
    case SERVICE_BOOT_START:
        return "boot";
    case SERVICE_SYSTEM_START:
        return "system";
    case SERVICE_AUTO_START:
        return "auto";
    case SERVICE_DEMAND_START:
        return "demand";
    case SERVICE_DISABLED:
        return "disabled";
    default:
        return "unrecognized";
    }
}

// Input: Win32 service type bitmask.
// Processing: Names kernel-driver service types separately from user-mode
// service types so operator output points at the right readiness lane.
// Return: Service type name.
std::string ServiceTypeName(const DWORD serviceType) {
    if ((serviceType & SERVICE_KERNEL_DRIVER) != 0) {
        return "kernel_driver";
    }
    if ((serviceType & SERVICE_FILE_SYSTEM_DRIVER) != 0) {
        return "file_system_driver";
    }
    if ((serviceType & SERVICE_WIN32_OWN_PROCESS) != 0) {
        return "win32_own_process";
    }
    if ((serviceType & SERVICE_WIN32_SHARE_PROCESS) != 0) {
        return "win32_share_process";
    }
    return "unrecognized";
}

// Input: Win32 error returned by CreateFileW for \\.\KSwordSandboxDriver.
// Processing: Buckets common readiness failures into stable diagnostic codes.
// Return: Machine-readable open-device failure code.
std::string DeviceOpenDiagnosticCode(const DWORD errorCode) {
    switch (errorCode) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_PATHNAME:
        return "open_device_not_found";
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
        return "open_device_denied";
    case ERROR_SHARING_VIOLATION:
        return "open_device_sharing_violation";
    default:
        return "open_device_failed";
    }
}

// Input: CreateFileW error code and service name.
// Processing: Returns actionable operator hints without mutating SCM, BCD, or
// driver state.  Test-signing is a hint because this collector must not change
// boot configuration or invoke signing tools.
// Return: Human-readable hint.
std::wstring DeviceOpenHint(const DWORD errorCode, const std::wstring& serviceName) {
    const std::wstring serviceText = serviceName.empty() ? L"KSwordSandboxDriver" : serviceName;
    switch (errorCode) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_PATHNAME:
        return L"Check that kernel service '" + serviceText +
            L"' exists, is running, and created the \\DosDevices\\KSwordSandboxDriver symbolic link; if start failed, check driver signing/test-signing and Code Integrity logs.";
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
        return L"Open was denied. Run the collector from an elevated guest context or adjust the driver control-device security descriptor.";
    case ERROR_SHARING_VIOLATION:
        return L"The control device is present but another handle rejected sharing; close competing collectors and retry.";
    default:
        return L"Inspect SCM state, driver load events, device symbolic-link creation, and the loaded driver's public IOCTL ABI.";
    }
}

// Input: Common readiness event metadata.
// Processing: Emits a string-valued JSONL diagnostic row that can be consumed by
// host import/reporting without schema migration.
// Return: true when the sink accepted the row.
bool EmitReadinessDiagnostic(
    EventWriter& writer,
    const Options& options,
    const std::string& stage,
    const std::string& code,
    const std::string& severity,
    const std::string& state,
    const std::wstring& hint,
    JsonDataObjectBuilder* extraData) {
    JsonDataObjectBuilder data;
    data.AddUtf8("diagnosticStage", stage);
    data.AddUtf8("diagnosticCode", code);
    data.AddUtf8("severity", severity);
    data.AddUtf8("readinessState", state);
    data.AddWide("hint", hint);
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("serviceName", options.serviceName);
    data.AddSigned("diagnoseReadTimeoutMs", options.diagnoseReadTimeoutMs);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);

    if (extraData != nullptr) {
        const std::string extraJson = extraData->Build();
        if (extraJson.size() > 2) {
            std::string withoutBraces = extraJson.substr(1, extraJson.size() - 2);
            if (!withoutBraces.empty()) {
                // JsonDataObjectBuilder intentionally has no merge primitive.
                // Add the extra fields through a raw splice while preserving
                // the builder's escaping for all values already serialized.
                std::string merged = data.Build();
                merged.pop_back();
                merged += ",";
                merged += withoutBraces;
                merged += "}";
                SandboxEventFields event;
                event.eventType = "r0collector.readinessDiagnostic";
                event.path = options.devicePath;
                event.dataJson = merged;
                return EmitEvent(writer, event);
            }
        }
    }

    SandboxEventFields event;
    event.eventType = "r0collector.readinessDiagnostic";
    event.path = options.devicePath;
    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Service manager/query metadata from the local guest.
// Processing: Emits a service readiness diagnostic without starting, stopping,
// installing, or deleting the service.
// Return: true if the probe completed far enough to emit one JSONL row.
bool ProbeServiceReadiness(
    EventWriter& writer,
    const Options& options,
    ReadinessSummary* summary) {
    DWORD scmError = ERROR_SUCCESS;
    UniqueServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.IsValid()) {
        scmError = GetLastError();
        JsonDataObjectBuilder extra;
        extra.AddUnsigned("win32Error", scmError);
        extra.AddWide("win32Message", Win32ErrorMessage(scmError));
        const std::string severity = scmError == ERROR_ACCESS_DENIED ? "warning" : "error";
        const std::string state = scmError == ERROR_ACCESS_DENIED ? "degraded" : "blocked";
        const std::string code = scmError == ERROR_ACCESS_DENIED ? "service_manager_denied" : "service_manager_unavailable";
        RecordProbe(summary, "service", code, severity, state);
        return EmitReadinessDiagnostic(
            writer,
            options,
            "service",
            code,
            severity,
            state,
            L"Unable to query SCM. Device-open and ABI probes still provide direct readiness evidence.",
            &extra);
    }

    DWORD serviceError = ERROR_SUCCESS;
    UniqueServiceHandle service(OpenServiceW(
        scm.Get(),
        options.serviceName.c_str(),
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    if (!service.IsValid()) {
        serviceError = GetLastError();
        JsonDataObjectBuilder extra;
        extra.AddUnsigned("win32Error", serviceError);
        extra.AddWide("win32Message", Win32ErrorMessage(serviceError));
        std::string code = "service_open_failed";
        std::string severity = "error";
        std::string state = "blocked";
        std::wstring hint = L"Verify the configured --service-name and install the driver service before live R0 collection.";
        if (serviceError == ERROR_SERVICE_DOES_NOT_EXIST) {
            code = "missing_service";
            hint = L"Driver service is missing. Install/register the KSwordSandboxDriver service before live R0 collection.";
        } else if (serviceError == ERROR_ACCESS_DENIED) {
            code = "service_query_denied";
            severity = "warning";
            state = "degraded";
            hint = L"SCM access was denied. Re-run elevated for service details; device-open/ABI probes remain authoritative.";
        }

        RecordProbe(summary, "service", code, severity, state);
        return EmitReadinessDiagnostic(
            writer,
            options,
            "service",
            code,
            severity,
            state,
            hint,
            &extra);
    }

    SERVICE_STATUS_PROCESS status {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(
            service.Get(),
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded)) {
        const DWORD queryError = GetLastError();
        JsonDataObjectBuilder extra;
        extra.AddUnsigned("win32Error", queryError);
        extra.AddWide("win32Message", Win32ErrorMessage(queryError));
        RecordProbe(summary, "service", "service_status_query_failed", "warning", "degraded");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "service",
            "service_status_query_failed",
            "warning",
            "degraded",
            L"OpenService succeeded but QueryServiceStatusEx failed; continue with direct device-open/ABI probes.",
            &extra);
    }

    DWORD configBytesNeeded = 0;
    QueryServiceConfigW(service.Get(), nullptr, 0, &configBytesNeeded);
    std::vector<unsigned char> configBuffer(configBytesNeeded);
    QUERY_SERVICE_CONFIGW* config = nullptr;
    if (!configBuffer.empty() &&
        QueryServiceConfigW(
            service.Get(),
            reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data()),
            static_cast<DWORD>(configBuffer.size()),
            &configBytesNeeded)) {
        config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
    }

    const bool running = status.dwCurrentState == SERVICE_RUNNING;
    const bool startPending = status.dwCurrentState == SERVICE_START_PENDING;
    const std::string code = running
        ? "service_running"
        : (startPending ? "service_start_pending" : "service_not_running");
    const std::string severity = running ? "info" : "error";
    const std::string state = running ? "ready" : "blocked";
    const std::wstring hint = running
        ? L"Driver service is running; continue with device-open and ABI probes."
        : L"Driver service exists but is not running. Start it in an isolated VM and check driver signing/test-signing, SCM failure code, and Code Integrity logs if start fails.";

    JsonDataObjectBuilder extra;
    extra.AddUnsigned("serviceState", status.dwCurrentState);
    extra.AddUtf8("serviceStateName", ServiceStateName(status.dwCurrentState));
    extra.AddUnsigned("serviceProcessId", status.dwProcessId);
    extra.AddUnsigned("serviceControlsAccepted", status.dwControlsAccepted);
    extra.AddUnsigned("serviceWin32ExitCode", status.dwWin32ExitCode);
    extra.AddUnsigned("serviceSpecificExitCode", status.dwServiceSpecificExitCode);
    extra.AddBool("serviceRunning", running);
    if (config != nullptr) {
        extra.AddUnsigned("serviceType", config->dwServiceType);
        extra.AddUtf8("serviceTypeName", ServiceTypeName(config->dwServiceType));
        extra.AddUnsigned("serviceStartType", config->dwStartType);
        extra.AddUtf8("serviceStartTypeName", ServiceStartTypeName(config->dwStartType));
        extra.AddUnsigned("serviceErrorControl", config->dwErrorControl);
        if (config->lpBinaryPathName != nullptr) {
            extra.AddWide("serviceBinaryPath", config->lpBinaryPathName);
        }
    }

    RecordProbe(summary, "service", code, severity, state);
    return EmitReadinessDiagnostic(
        writer,
        options,
        "service",
        code,
        severity,
        state,
        hint,
        &extra);
}

// Input: Opened device handle.
// Processing: Issues GET_CAPABILITIES directly so diagnose mode can classify
// ABI mismatch separately from generic IOCTL failures.
// Return: true when the loaded driver satisfies the collector ABI contract.
bool ProbeCapabilitiesReadiness(
    const UniqueHandle& device,
    EventWriter& writer,
    const Options& options,
    ReadinessSummary* summary) {
    KSWORD_SANDBOX_CAPABILITIES_REPLY reply {};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        device.Get(),
        IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES,
        nullptr,
        0,
        &reply,
        static_cast<DWORD>(sizeof(reply)),
        &bytesReturned,
        nullptr);
    if (!ok) {
        const DWORD errorCode = GetLastError();
        JsonDataObjectBuilder extra;
        extra.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES");
        extra.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES);
        extra.AddUnsigned("bytesReturned", bytesReturned);
        extra.AddUnsigned("win32Error", errorCode);
        extra.AddWide("win32Message", Win32ErrorMessage(errorCode));
        const std::string code =
            errorCode == ERROR_INVALID_FUNCTION || errorCode == ERROR_NOT_SUPPORTED
                ? "abi_capabilities_unavailable"
                : "abi_ioctl_failed";
        RecordProbe(summary, "abiNegotiation", code, "error", "blocked");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "abiNegotiation",
            code,
            "error",
            "blocked",
            L"Loaded driver did not satisfy GET_CAPABILITIES; rebuild/reload matching driver and collector binaries.",
            &extra) && false;
    }

    const bool compatible =
        bytesReturned >= static_cast<DWORD>(sizeof(reply)) &&
        reply.Version == KSWORD_SANDBOX_INTERFACE_VERSION &&
        reply.Size >= sizeof(reply) &&
        reply.AbiVersionMajor == KSWORD_SANDBOX_ABI_VERSION_MAJOR &&
        reply.EventHeaderVersion == KSWORD_SANDBOX_EVENT_HEADER_VERSION &&
        reply.EventMaxPayloadSize <= KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE;

    SandboxEventFields capabilitiesEvent;
    capabilitiesEvent.eventType = "r0collector.driverCapabilities";
    capabilitiesEvent.path = options.devicePath;
    capabilitiesEvent.dataJson = BuildCapabilitiesData(reply, bytesReturned);
    if (!EmitEvent(writer, capabilitiesEvent)) {
        return false;
    }

    JsonDataObjectBuilder extra;
    extra.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES");
    extra.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES);
    extra.AddUnsigned("bytesReturned", bytesReturned);
    extra.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    extra.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    extra.AddUnsigned("driverAbiVersionMajor", reply.AbiVersionMajor);
    extra.AddUnsigned("driverAbiVersionMinor", reply.AbiVersionMinor);
    extra.AddUnsigned("driverEventHeaderVersion", reply.EventHeaderVersion);
    extra.AddUnsigned("driverEventMaxPayloadSize", reply.EventMaxPayloadSize);
    extra.AddBool("abiCompatible", compatible);

    if (!compatible) {
        RecordProbe(summary, "abiNegotiation", "abi_mismatch", "error", "blocked");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "abiNegotiation",
            "abi_mismatch",
            "error",
            "blocked",
            L"Driver capabilities reply does not match the collector ABI; use a matching driver/collector build.",
            &extra) && false;
    }

    RecordProbe(summary, "abiNegotiation", "abi_compatible", "info", "ready");
    return EmitReadinessDiagnostic(
        writer,
        options,
        "abiNegotiation",
        "abi_compatible",
        "info",
        "ready",
        L"Driver capabilities match the collector ABI.",
        &extra);
}

// Input: Opened device handle and timeout from diagnose options.
// Processing: Issues one overlapped READ_EVENTS request on a separate handle so
// diagnose mode can fail fast with read_timeout instead of hanging forever on a
// broken driver.
// Return: true when the read path completed and the JSONL diagnostics were
// emitted; false on sink/runtime failure.
bool ProbeReadEventsReadiness(
    EventWriter& writer,
    const Options& options,
    ReadinessSummary* summary) {
    DWORD openError = ERROR_SUCCESS;
    UniqueHandle device = OpenDriverDeviceWithFlags(
        options.devicePath,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        &openError);
    if (!device.IsValid()) {
        JsonDataObjectBuilder extra;
        extra.AddUnsigned("win32Error", openError);
        extra.AddWide("win32Message", Win32ErrorMessage(openError));
        RecordProbe(summary, "readEvents", "read_probe_open_failed", "error", "blocked");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "readEvents",
            "read_probe_open_failed",
            "error",
            "blocked",
            DeviceOpenHint(openError, options.serviceName),
            &extra);
    }

    UniqueHandle eventHandle(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!eventHandle.IsValid()) {
        const DWORD eventError = GetLastError();
        JsonDataObjectBuilder extra;
        extra.AddUnsigned("win32Error", eventError);
        extra.AddWide("win32Message", Win32ErrorMessage(eventError));
        RecordProbe(summary, "readEvents", "read_probe_event_create_failed", "error", "blocked");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "readEvents",
            "read_probe_event_create_failed",
            "error",
            "blocked",
            L"CreateEventW failed before READ_EVENTS probe could run.",
            &extra);
    }

    KSWORD_SANDBOX_READ_EVENTS_REQUEST request {};
    request.Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    request.Size = sizeof(request);
    request.MaxEvents = std::min<unsigned long>(options.readEventsMaxEvents, 1UL);
    request.Flags = 0;
    request.StartingSequence = 0;

    std::vector<unsigned char> buffer(kReadEventsBufferBytes);
    OVERLAPPED overlapped {};
    overlapped.hEvent = eventHandle.Get();
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        device.Get(),
        IOCTL_KSWORD_SANDBOX_READ_EVENTS,
        &request,
        static_cast<DWORD>(sizeof(request)),
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &bytesReturned,
        &overlapped);

    DWORD errorCode = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && errorCode == ERROR_IO_PENDING) {
        const DWORD waitResult = WaitForSingleObject(
            eventHandle.Get(),
            static_cast<DWORD>(options.diagnoseReadTimeoutMs));
        if (waitResult == WAIT_TIMEOUT) {
            CancelIoEx(device.Get(), &overlapped);
            JsonDataObjectBuilder extra;
            extra.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
            extra.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
            extra.AddSigned("timeoutMs", options.diagnoseReadTimeoutMs);
            extra.AddUnsigned("requestedMaxEvents", request.MaxEvents);
            RecordProbe(summary, "readEvents", "read_timeout", "error", "blocked");
            return EmitReadinessDiagnostic(
                writer,
                options,
                "readEvents",
                "read_timeout",
                "error",
                "blocked",
                L"READ_EVENTS did not complete within the diagnose timeout; investigate driver dispatch hangs or stuck synchronization.",
                &extra);
        }

        if (waitResult != WAIT_OBJECT_0) {
            errorCode = GetLastError();
            ok = FALSE;
        } else {
            ok = GetOverlappedResult(device.Get(), &overlapped, &bytesReturned, FALSE);
            errorCode = ok ? ERROR_SUCCESS : GetLastError();
        }
    }

    if (!ok) {
        JsonDataObjectBuilder extra;
        extra.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
        extra.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
        extra.AddUnsigned("bytesReturned", bytesReturned);
        extra.AddUnsigned("win32Error", errorCode);
        extra.AddWide("win32Message", Win32ErrorMessage(errorCode));
        RecordProbe(summary, "readEvents", "read_ioctl_failed", "error", "blocked");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "readEvents",
            "read_ioctl_failed",
            "error",
            "blocked",
            L"READ_EVENTS IOCTL failed; verify loaded driver dispatch table and public IOCTL number.",
            &extra);
    }

    if (bytesReturned < KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE) {
        JsonDataObjectBuilder extra;
        extra.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
        extra.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
        extra.AddUnsigned("bytesReturned", bytesReturned);
        extra.AddUnsigned("expectedReplyHeaderSize", KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);
        RecordProbe(summary, "readEvents", "read_protocol_error", "error", "blocked");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "readEvents",
            "read_protocol_error",
            "error",
            "blocked",
            L"READ_EVENTS returned too few bytes for the public reply header.",
            &extra);
    }

    KSWORD_SANDBOX_READ_EVENTS_REPLY reply {};
    std::memcpy(&reply, buffer.data(), KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);
    const bool compatible =
        reply.Version == KSWORD_SANDBOX_INTERFACE_VERSION &&
        reply.Size >= KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE &&
        reply.Size <= bytesReturned;
    const unsigned long long availableEventBytes = compatible
        ? static_cast<unsigned long long>(bytesReturned - reply.Size)
        : 0ULL;
    const bool byteCountsCompatible =
        compatible &&
        reply.BytesWritten <= availableEventBytes;
    if (!byteCountsCompatible) {
        JsonDataObjectBuilder extra;
        extra.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
        extra.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
        extra.AddUnsigned("bytesReturned", bytesReturned);
        extra.AddUnsigned("replyVersion", reply.Version);
        extra.AddUnsigned("replySize", reply.Size);
        extra.AddUnsigned("replyBytesWritten", reply.BytesWritten);
        extra.AddUnsigned("availableEventBytes", availableEventBytes);
        RecordProbe(summary, "readEvents", "abi_mismatch", "error", "blocked");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "readEvents",
            "abi_mismatch",
            "error",
            "blocked",
            L"READ_EVENTS reply header is incompatible with the collector ABI.",
            &extra);
    }

    JsonDataObjectBuilder extra;
    extra.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
    extra.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
    extra.AddUnsigned("bytesReturned", bytesReturned);
    extra.AddUnsigned("requestedMaxEvents", request.MaxEvents);
    extra.AddUnsigned("eventsWritten", reply.EventsWritten);
    extra.AddUnsigned("bytesWritten", reply.BytesWritten);
    extra.AddUnsigned("eventsDropped", reply.EventsDropped);
    extra.AddUnsigned("nextSequence", reply.NextSequence);

    if (reply.EventsWritten == 0 || reply.BytesWritten == 0) {
        RecordProbe(summary, "readEvents", "driver_no_events", "warning", "degraded");
        return EmitReadinessDiagnostic(
            writer,
            options,
            "readEvents",
            "driver_no_events",
            "warning",
            "degraded",
            L"READ_EVENTS completed but returned no driver records; verify producers are enabled or generate controlled sample activity in the VM.",
            &extra);
    }

    RecordProbe(summary, "readEvents", "read_events_ready", "info", "ready");
    return EmitReadinessDiagnostic(
        writer,
        options,
        "readEvents",
        "read_events_ready",
        "info",
        "ready",
        L"READ_EVENTS completed and returned at least one driver record.",
        &extra);
}

// Input: Accumulated readiness state after all non-mutating probes.
// Processing: Emits a single machine-readable summary row for orchestration and
// WebUI/report consumption.
// Return: true when the summary row was written.
bool EmitReadinessSummary(
    EventWriter& writer,
    const Options& options,
    const ReadinessSummary& summary) {
    JsonDataObjectBuilder data;
    data.AddUtf8("severity", summary.highestSeverity);
    data.AddUtf8("readinessState", summary.readinessState);
    data.AddBool("ready", !summary.blocked);
    data.AddBool("degraded", summary.degraded);
    data.AddUtf8("failedStage", summary.failedStage);
    data.AddUtf8("serviceDiagnosticCode", summary.serviceDiagnosticCode);
    data.AddUtf8("openDeviceDiagnosticCode", summary.openDeviceDiagnosticCode);
    data.AddUtf8("abiDiagnosticCode", summary.abiDiagnosticCode);
    data.AddUtf8("readEventsDiagnosticCode", summary.readEventsDiagnosticCode);
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("serviceName", options.serviceName);
    data.AddSigned("diagnoseReadTimeoutMs", options.diagnoseReadTimeoutMs);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);

    SandboxEventFields event;
    event.eventType = "r0collector.readinessSummary";
    event.path = options.devicePath;
    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

} // namespace

// Input: Failed CreateFileW state for the R0 control device.
// Processing: Emits the legacy event type with explicit severity, readiness
// state, diagnostic code, and operator hint so failures are no longer plain
// informational rows.
// Return: true when the JSONL sink accepted the row.
bool EmitDeviceUnavailableDiagnostic(
    EventWriter& writer,
    const Options& options,
    const DWORD openError,
    const std::string& diagnosticStage) {
    JsonDataObjectBuilder data;
    const std::string code = DeviceOpenDiagnosticCode(openError);
    data.AddUtf8("diagnosticStage", diagnosticStage);
    data.AddUtf8("diagnosticCode", code);
    data.AddUtf8("severity", "error");
    data.AddUtf8("readinessState", "blocked");
    data.AddUtf8("availabilityState", code);
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("serviceName", options.serviceName);
    data.AddUnsigned("win32Error", openError);
    data.AddWide("win32Message", Win32ErrorMessage(openError));
    data.AddWide(
        "message",
        L"Unable to open driver device " + options.devicePath + L": " + Win32ErrorMessage(openError));
    data.AddWide("hint", DeviceOpenHint(openError, options.serviceName));
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddBool("backpressure", false);

    SandboxEventFields event;
    event.eventType = "r0collector.deviceUnavailable";
    event.path = options.devicePath;
    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Collector options and open JSONL sink.
// Processing: Runs a non-mutating readiness diagnostic pass: SCM query,
// CreateFileW device open classification, ABI capabilities negotiation,
// health/status rows, and bounded READ_EVENTS probe.
// Return: Exit code suitable for automation; blocked readiness is nonzero.
int RunReadinessDiagnoseMode(const Options& options, EventWriter& writer) {
    ReadinessSummary summary;

    if (!ProbeServiceReadiness(writer, options, &summary)) {
        return kExitRuntimeFailure;
    }

    DWORD openError = ERROR_SUCCESS;
    UniqueHandle device = OpenDriverDevice(options.devicePath, &openError);
    if (!device.IsValid()) {
        const std::string code = DeviceOpenDiagnosticCode(openError);
        RecordProbe(&summary, "openDevice", code, "error", "blocked");
        if (!EmitDeviceUnavailableDiagnostic(writer, options, openError, "openDevice") ||
            !EmitReadinessSummary(writer, options, summary)) {
            return kExitRuntimeFailure;
        }
        return kExitDeviceUnavailable;
    }

    RecordProbe(&summary, "openDevice", "device_opened", "info", "ready");
    JsonDataObjectBuilder openExtra;
    openExtra.AddBool("ioctlIssued", false);
    if (!EmitReadinessDiagnostic(
            writer,
            options,
            "openDevice",
            "device_opened",
            "info",
            "ready",
            L"Control device opened successfully; continue with ABI and READ_EVENTS probes.",
            &openExtra)) {
        return kExitRuntimeFailure;
    }

    SandboxEventFields openedEvent;
    openedEvent.eventType = "r0collector.deviceOpened";
    openedEvent.path = options.devicePath;
    JsonDataObjectBuilder openedData;
    openedData.AddWide("devicePath", options.devicePath);
    openedData.AddWide("serviceName", options.serviceName);
    openedData.AddBool("ioctlIssued", false);
    openedData.AddBool("diagnose", true);
    openedData.AddUtf8("diagnosticStage", "openDevice");
    openedData.AddUtf8("diagnosticCode", "device_opened");
    openedData.AddUtf8("severity", "info");
    openedData.AddUtf8("readinessState", "ready");
    openedData.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    openedData.AddUtf8("producer", "r0collector");
    openedData.AddBool("noise", false);
    openedData.AddBool("lost", false);
    openedData.AddBool("backpressure", false);
    openedEvent.dataJson = openedData.Build();
    if (!EmitEvent(writer, openedEvent)) {
        return kExitRuntimeFailure;
    }

    if (!EmitDriverHealth(device, options, writer)) {
        RecordProbe(&summary, "abiNegotiation", "health_ioctl_failed", "error", "blocked");
        EmitReadinessSummary(writer, options, summary);
        return kExitRuntimeFailure;
    }

    if (!ProbeCapabilitiesReadiness(device, writer, options, &summary)) {
        EmitReadinessSummary(writer, options, summary);
        return kExitRuntimeFailure;
    }

    if (!EmitDriverStatus(device, options, writer)) {
        RecordProbe(&summary, "abiNegotiation", "status_ioctl_failed", "error", "blocked");
        EmitReadinessSummary(writer, options, summary);
        return kExitRuntimeFailure;
    }

    if (!ProbeReadEventsReadiness(writer, options, &summary)) {
        EmitReadinessSummary(writer, options, summary);
        return kExitRuntimeFailure;
    }

    if (!EmitReadinessSummary(writer, options, summary)) {
        return kExitRuntimeFailure;
    }

    return summary.blocked ? kExitRuntimeFailure : kExitSuccess;
}

} // namespace KSword::Sandbox::R0Collector
