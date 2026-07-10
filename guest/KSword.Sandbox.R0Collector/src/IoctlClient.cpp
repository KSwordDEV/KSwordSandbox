#include "IoctlClient.h"

#include "EventParser.h"

#include <cstring>
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

    if (bytesReturned < static_cast<DWORD>(sizeof(reply)) ||
        reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        reply.Size < sizeof(reply)) {
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_GET_HEALTH",
            L"GET_HEALTH returned an incompatible KSWORD_SANDBOX_HEALTH_REPLY.",
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

// Input: READ_EVENTS output bytes and public reply header metadata.
// Processing: Walks the byte stream after the fixed reply header, validates each
// KSWORD_SANDBOX_EVENT_HEADER, and emits one driver-originated JSONL row per
// event header.
// Return: true when all advertised event records were emitted; false when the
// stream is malformed or the sink fails. eventsEmitted receives the row count.
bool EmitDriverEventRecords(
    EventWriter& writer,
    const Options& options,
    const unsigned long long batchIndex,
    const unsigned char* eventBytes,
    const size_t eventByteCount,
    const ULONG eventsWritten,
    unsigned long long* eventsEmitted) {
    size_t offset = 0;
    unsigned long long emitted = 0;

    while (emitted < eventsWritten) {
        if (eventByteCount - offset < sizeof(KSWORD_SANDBOX_EVENT_HEADER)) {
            if (eventsEmitted != nullptr) {
                *eventsEmitted = emitted;
            }
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
            if (eventsEmitted != nullptr) {
                *eventsEmitted = emitted;
            }
            return EmitProtocolError(
                writer,
                options,
                "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
                L"READ_EVENTS returned an event record with an incompatible header.",
                static_cast<DWORD>(eventByteCount));
        }

        const size_t payloadCapacity = static_cast<size_t>(header.Size) - sizeof(header);
        if (static_cast<size_t>(header.PayloadSize) > payloadCapacity) {
            if (eventsEmitted != nullptr) {
                *eventsEmitted = emitted;
            }
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
        event.processId = ExtractTypedPayloadProcessId(
            header.Type,
            payload,
            header.PayloadSize,
            header.ProcessId);
        event.path = options.devicePath;
        const std::wstring subjectPath =
            ExtractTypedPayloadPath(header.Type, payload, header.PayloadSize);
        if (!subjectPath.empty()) {
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
        event.dataJson = BuildDriverEventData(
            header,
            batchIndex,
            static_cast<unsigned long long>(offset),
            payload,
            header.PayloadSize);

        if (!EmitEvent(writer, event)) {
            if (eventsEmitted != nullptr) {
                *eventsEmitted = emitted;
            }
            return false;
        }

        offset += header.Size;
        ++emitted;
    }

    if (offset != eventByteCount) {
        if (eventsEmitted != nullptr) {
            *eventsEmitted = emitted;
        }
        return EmitProtocolError(
            writer,
            options,
            "IOCTL_KSWORD_SANDBOX_READ_EVENTS",
            L"READ_EVENTS returned extra bytes after the advertised event records.",
            static_cast<DWORD>(eventByteCount));
    }

    if (eventsEmitted != nullptr) {
        *eventsEmitted = emitted;
    }
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
    unsigned long long* eventsEmitted) {
    KSWORD_SANDBOX_READ_EVENTS_REQUEST request {};
    request.Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    request.Size = sizeof(request);
    request.MaxEvents = kReadEventsMaxEvents;
    request.Flags = options.enableMaskSpecified ? options.enableMask : 0;
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
    const size_t eventByteCount = static_cast<size_t>(reply.BytesWritten);
    const unsigned char* eventBytes = buffer.data() + reply.Size;
    if (!EmitDriverEventRecords(
            writer,
            options,
            batchIndex,
            eventBytes,
            eventByteCount,
            reply.EventsWritten,
            &emitted)) {
        if (eventsEmitted != nullptr) {
            *eventsEmitted = emitted;
        }
        return false;
    }

    SandboxEventFields event;
    event.eventType = "r0collector.driverReadEvents";
    event.path = options.devicePath;
    event.dataJson = BuildReadEventsBatchData(reply, bytesReturned, emitted);
    if (!EmitEvent(writer, event)) {
        if (eventsEmitted != nullptr) {
            *eventsEmitted = emitted;
        }
        return false;
    }

    if (eventsEmitted != nullptr) {
        *eventsEmitted = emitted;
    }
    return true;
}

} // namespace KSword::Sandbox::R0Collector
