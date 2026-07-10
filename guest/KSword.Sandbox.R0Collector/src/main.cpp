#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winioctl.h>
#include <KSwordSandboxDriverIoctl.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr const char* kCollectorSource = "r0collector";
constexpr int kExitSuccess = 0;
constexpr int kExitInvalidArguments = 64;
constexpr int kExitOutputUnavailable = 65;
constexpr int kExitDeviceUnavailable = 66;
constexpr int kExitRuntimeFailure = 70;
constexpr DWORD kReadEventsBufferBytes = 64U * 1024U;
constexpr ULONG kReadEventsMaxEvents = 64U;
constexpr size_t kMaxPayloadHexBytes = 256U;

// Input: UTF-16 text from Windows APIs or command-line arguments.
// Processing: Converts the full input string to UTF-8 with WideCharToMultiByte.
// Return: UTF-8 text; an empty string is returned for empty input or conversion failure.
std::string Utf8FromWide(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int requiredBytes = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);

    if (requiredBytes <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(requiredBytes), '\0');
    const int writtenBytes = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        requiredBytes,
        nullptr,
        nullptr);

    if (writtenBytes <= 0) {
        return {};
    }

    return result;
}

// Input: Arbitrary UTF-8 text.
// Processing: Escapes characters that have special meaning in JSON strings and
// emits control characters as \u00XX sequences so every JSONL row stays valid.
// Return: Escaped UTF-8 text without surrounding quotation marks.
std::string JsonEscapeUtf8(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');

    for (const unsigned char ch : value) {
        switch (ch) {
        case '\"':
            escaped << "\\\"";
            break;
        case '\\':
            escaped << "\\\\";
            break;
        case '\b':
            escaped << "\\b";
            break;
        case '\f':
            escaped << "\\f";
            break;
        case '\n':
            escaped << "\\n";
            break;
        case '\r':
            escaped << "\\r";
            break;
        case '\t':
            escaped << "\\t";
            break;
        default:
            if (ch < 0x20) {
                static constexpr char kHex[] = "0123456789abcdef";
                escaped << "\\u00" << kHex[(ch >> 4) & 0x0F] << kHex[ch & 0x0F];
            } else {
                escaped << static_cast<char>(ch);
            }
            break;
        }
    }

    return escaped.str();
}

// Input: UTF-8 text that should become a JSON string value.
// Processing: Escapes the text and adds the surrounding quotation marks.
// Return: A complete JSON string token.
std::string JsonStringFromUtf8(const std::string& value) {
    return "\"" + JsonEscapeUtf8(value) + "\"";
}

// Input: UTF-16 text that should become a JSON string value.
// Processing: Converts to UTF-8, escapes JSON metacharacters, and quotes it.
// Return: A complete JSON string token.
std::string JsonStringFromWide(const std::wstring& value) {
    return JsonStringFromUtf8(Utf8FromWide(value));
}

// Input: Ordered key/value pairs that must be serialized under SandboxEvent.data.
// Processing: Appends each value as a JSON string regardless of its semantic
// type so the output remains compatible with Dictionary<string,string>.
// Return: Build returns a complete JSON object string; Add* methods return no
// value and mutate the builder.
class JsonDataObjectBuilder {
public:
    void AddUtf8(const std::string& key, const std::string& value) {
        AddPrefixAndKey(key);
        json_ += JsonStringFromUtf8(value);
    }

    void AddWide(const std::string& key, const std::wstring& value) {
        AddPrefixAndKey(key);
        json_ += JsonStringFromWide(value);
    }

    void AddUnsigned(const std::string& key, const unsigned long long value) {
        AddUtf8(key, std::to_string(value));
    }

    void AddSigned(const std::string& key, const long long value) {
        AddUtf8(key, std::to_string(value));
    }

    void AddBool(const std::string& key, const bool value) {
        AddUtf8(key, value ? "true" : "false");
    }

    std::string Build() const {
        return json_ + "}";
    }

private:
    void AddPrefixAndKey(const std::string& key) {
        if (!first_) {
            json_ += ",";
        }

        first_ = false;
        json_ += JsonStringFromUtf8(key);
        json_ += ":";
    }

    bool first_ = true;
    std::string json_ = "{";
};

// Input: Unsigned integer value plus a minimum hexadecimal digit width.
// Processing: Formats the value with a 0x prefix and zero-padding for stable
// diagnostic output in JSONL data fields.
// Return: ASCII hexadecimal text.
std::string HexUnsignedLongLong(const unsigned long long value, const int width = 0) {
    std::ostringstream hex;
    hex << "0x" << std::uppercase << std::hex << std::setfill('0');
    if (width > 0) {
        hex << std::setw(width);
    }
    hex << value;
    return hex.str();
}

// Input: Raw payload bytes returned after a driver event header.
// Processing: Converts at most maxBytes to uppercase hexadecimal without spaces
// so opaque payloads can be inspected while preserving JSON string data values.
// Return: Hex text for the emitted preview bytes; callers record truncation
// separately so this field stays valid hexadecimal.
std::string HexBytes(const unsigned char* bytes, const size_t byteCount, const size_t maxBytes) {
    if (bytes == nullptr || byteCount == 0 || maxBytes == 0) {
        return {};
    }

    const size_t bytesToFormat = byteCount < maxBytes ? byteCount : maxBytes;
    std::ostringstream hex;
    hex << std::uppercase << std::hex << std::setfill('0');

    for (size_t index = 0; index < bytesToFormat; ++index) {
        hex << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }

    return hex.str();
}

// Input: No explicit input; uses the current system clock.
// Processing: Produces a UTC timestamp with millisecond precision.
// Return: ISO-8601/RFC3339-style timestamp suitable for SandboxEvent.timestamp.
std::string UtcTimestampIso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto wholeSeconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now - wholeSeconds).count();
    const std::time_t timeValue = std::chrono::system_clock::to_time_t(now);

    std::tm utc {};
    if (gmtime_s(&utc, &timeValue) != 0) {
        return "1970-01-01T00:00:00.000Z";
    }

    char buffer[32] {};
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        static_cast<long long>(milliseconds));

    return buffer;
}

// Input: Win32 error code returned by GetLastError or an equivalent API.
// Processing: Uses FormatMessageW and trims trailing CR/LF/dot-like spacing.
// Return: Human-readable UTF-16 error text; includes the numeric code if lookup fails.
std::wstring Win32ErrorMessage(const DWORD errorCode) {
    wchar_t* rawMessage = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;

    const DWORD length = FormatMessageW(
        flags,
        nullptr,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&rawMessage),
        0,
        nullptr);

    std::wstring message;
    if (length != 0 && rawMessage != nullptr) {
        message.assign(rawMessage, length);
        LocalFree(rawMessage);
    } else {
        message = L"Win32 error " + std::to_wstring(errorCode);
    }

    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ' || message.back() == L'\t')) {
        message.pop_back();
    }

    return message;
}

// Input: No explicit input; reads the current process command line from Windows.
// Processing: Copies the raw command-line string so every event can record how
// the collector was invoked.
// Return: The current process command line, or an empty string if unavailable.
std::wstring CurrentCommandLine() {
    const wchar_t* commandLine = GetCommandLineW();
    return commandLine == nullptr ? std::wstring() : std::wstring(commandLine);
}

struct Options {
    std::wstring devicePath = LR"(\\.\KSwordSandboxDriver)";
    std::wstring outputPath = L"-";
    int durationSeconds = 0;
    int pollIntervalMs = 500;
    bool mockMode = false;
    bool showHelp = false;
};

struct SandboxEventFields {
    std::string eventType;
    std::string source = kCollectorSource;
    std::wstring timestampOverride;
    unsigned long long processId = GetCurrentProcessId();
    std::wstring path;
    std::wstring commandLine = CurrentCommandLine();
    std::string dataJson = "{}";
};

// Input: Fully populated event fields.
// Processing: Serializes fields in the SandboxEvent-compatible order requested
// by the repo: eventType/source/timestamp/processId/path/commandLine/data.
// Return: One complete JSON object without a trailing newline.
std::string BuildSandboxEventJsonLine(const SandboxEventFields& fields) {
    const std::string timestamp = fields.timestampOverride.empty()
        ? UtcTimestampIso8601()
        : Utf8FromWide(fields.timestampOverride);
    const std::string data = fields.dataJson.empty() ? "{}" : fields.dataJson;

    std::string line;
    line.reserve(512 + data.size());
    line += "{\"eventType\":";
    line += JsonStringFromUtf8(fields.eventType);
    line += ",\"source\":";
    line += JsonStringFromUtf8(fields.source);
    line += ",\"timestamp\":";
    line += JsonStringFromUtf8(timestamp);
    line += ",\"processId\":";
    line += std::to_string(fields.processId);
    line += ",\"path\":";
    line += JsonStringFromWide(fields.path);
    line += ",\"commandLine\":";
    line += JsonStringFromWide(fields.commandLine);
    line += ",\"data\":";
    line += data;
    line += "}";
    return line;
}

// Input: Output path from CLI options; "-" means stdout.
// Processing: Opens a UTF-8 JSONL sink in truncate mode for files, or attaches
// to stdout without taking ownership.
// Return: true when future writes can proceed; false with an explanatory error.
class EventWriter {
public:
    bool Open(const std::wstring& outputPath, std::wstring* error) {
        outputPath_ = outputPath;
        if (outputPath == L"-") {
            stream_ = &std::cout;
            return true;
        }

        file_.open(std::filesystem::path(outputPath), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!file_.is_open()) {
            if (error != nullptr) {
                *error = L"Unable to open output JSONL file: " + outputPath;
            }
            return false;
        }

        stream_ = &file_;
        return true;
    }

    bool WriteLine(const std::string& line) {
        if (stream_ == nullptr) {
            return false;
        }

        (*stream_) << line << '\n';
        stream_->flush();
        return stream_->good();
    }

    const std::wstring& OutputPath() const {
        return outputPath_;
    }

private:
    std::wstring outputPath_;
    std::ofstream file_;
    std::ostream* stream_ = nullptr;
};

// Input: Native HANDLE returned by CreateFileW.
// Processing: Owns the handle and closes it on destruction unless released.
// Return: No direct return value; IsValid/Get expose handle state to callers.
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : handle_(handle) {}

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    ~UniqueHandle() {
        Close();
    }

    bool IsValid() const {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HANDLE Get() const {
        return handle_;
    }

private:
    void Close() {
        if (IsValid()) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

// Input: CLI numeric value plus accepted inclusive bounds.
// Processing: Parses a base-10 integer and validates the full string was used.
// Return: true with parsed output, or false with a user-facing parse error.
bool ParseBoundedInt(
    const std::wstring& value,
    const int minValue,
    const int maxValue,
    const std::wstring& optionName,
    int* parsedValue,
    std::wstring* error) {
    if (value.empty()) {
        if (error != nullptr) {
            *error = optionName + L" requires a numeric value.";
        }
        return false;
    }

    errno = 0;
    wchar_t* end = nullptr;
    const long number = std::wcstol(value.c_str(), &end, 10);
    if (errno == ERANGE || end == value.c_str() || *end != L'\0' || number < minValue || number > maxValue) {
        if (error != nullptr) {
            *error = optionName + L" must be a base-10 integer between " +
                std::to_wstring(minValue) + L" and " + std::to_wstring(maxValue) + L".";
        }
        return false;
    }

    *parsedValue = static_cast<int>(number);
    return true;
}

// Input: Process argc/argv from wmain.
// Processing: Handles long and short collector options and validates bounded
// numeric values before any driver handle or output sink is opened.
// Return: true with Options populated, or false with an error string.
bool ParseArguments(int argc, wchar_t* argv[], Options* options, std::wstring* error) {
    for (int index = 1; index < argc; ++index) {
        const std::wstring arg = argv[index];
        const auto readValue = [&](const std::wstring& optionName, std::wstring* value) -> bool {
            if (index + 1 >= argc) {
                if (error != nullptr) {
                    *error = optionName + L" requires a value.";
                }
                return false;
            }
            *value = argv[++index];
            return true;
        };

        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            options->showHelp = true;
            return true;
        }

        if (arg == L"--mock") {
            options->mockMode = true;
            continue;
        }

        std::wstring value;
        if (arg == L"--device" || arg == L"-d") {
            if (!readValue(arg, &value)) {
                return false;
            }
            options->devicePath = value;
        } else if (arg == L"--output" || arg == L"-o") {
            if (!readValue(arg, &value)) {
                return false;
            }
            options->outputPath = value;
        } else if (arg == L"--duration" || arg == L"-t") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 0, 86400, arg, &options->durationSeconds, error)) {
                return false;
            }
        } else if (arg == L"--poll-interval" || arg == L"--poll-interval-ms" || arg == L"--poll-ms" || arg == L"-p") {
            if (!readValue(arg, &value)) {
                return false;
            }
            if (!ParseBoundedInt(value, 1, 600000, arg, &options->pollIntervalMs, error)) {
                return false;
            }
        } else {
            if (error != nullptr) {
                *error = L"Unknown argument: " + arg;
            }
            return false;
        }
    }

    return true;
}

// Input: Program name as printed by the shell.
// Processing: Writes supported arguments and defaults to stderr.
// Return: No return value.
void PrintUsage(const wchar_t* programName) {
    std::wcerr
        << L"Usage: " << programName << L" [options]\n"
        << L"\n"
        << L"Options:\n"
        << L"  -d, --device <path>          Win32 device path (default: \\\\.\\KSwordSandboxDriver)\n"
        << L"  -o, --output <jsonl|->       JSON Lines output path, or '-' for stdout (default: -)\n"
        << L"  -t, --duration <seconds>     Poll duration; 0 opens once and exits (default: 0)\n"
        << L"  -p, --poll-ms <ms>           Poll interval in milliseconds (default: 500)\n"
        << L"      --poll-interval-ms <ms>  Alias for --poll-ms\n"
        << L"      --mock                   Emit a mock driver event without opening a device\n"
        << L"  -h, --help                   Show this help text\n";
}

// Input: Collector options used for this run.
// Processing: Serializes the configuration into the data object of lifecycle events.
// Return: JSON object text for SandboxEvent.data.
std::string BuildConfigData(const Options& options) {
    JsonDataObjectBuilder data;
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("outputPath", options.outputPath);
    data.AddSigned("durationSeconds", options.durationSeconds);
    data.AddSigned("pollIntervalMs", options.pollIntervalMs);
    data.AddBool("mockMode", options.mockMode);
    data.AddUtf8("ioctlProtocol", "KSwordSandboxDriverIoctl.h");
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
    return data.Build();
}

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

// Input: DriverState value returned by GET_HEALTH or POLL.
// Processing: Maps the public ABI enum to stable text while preserving unknown
// values for forward-compatible collectors.
// Return: ASCII state name.
std::string DriverStateName(const ULONG driverState) {
    switch (driverState) {
    case KswSandboxDriverStateUnknown:
        return "unknown";
    case KswSandboxDriverStateRunning:
        return "running";
    case KswSandboxDriverStateStopping:
        return "stopping";
    default:
        return "unrecognized";
    }
}

// Input: Driver event type from KSWORD_SANDBOX_EVENT_HEADER.Type.
// Processing: Maps currently public skeleton values to names. Future driver
// payload types still flow through as raw numeric metadata.
// Return: ASCII type name.
std::string DriverEventTypeName(const ULONG eventType) {
    switch (eventType) {
    case KswSandboxEventTypeNone:
        return "none";
    case KswSandboxEventTypeDriverLoad:
        return "driverLoad";
    case KswSandboxEventTypeProcess:
        return "process";
    case KswSandboxEventTypeImage:
        return "image";
    case KswSandboxEventTypeFile:
        return "file";
    case KswSandboxEventTypeRegistry:
        return "registry";
    case KswSandboxEventTypeNetwork:
        return "network";
    case KswSandboxEventTypeReserved:
        return "reserved";
    default:
        return "unrecognized";
    }
}

// Input: Driver event type from KSWORD_SANDBOX_EVENT_HEADER.Type.
// Processing: Uses known public types to choose an eventType string while
// falling back to driver.event for forward-compatible unknown records.
// Return: SandboxEvent.eventType value for one driver-originated event.
std::string DriverEventJsonType(const ULONG eventType) {
    switch (eventType) {
    case KswSandboxEventTypeNone:
        return "driver.event.none";
    case KswSandboxEventTypeDriverLoad:
        return "driver.load";
    case KswSandboxEventTypeProcess:
        return "driver.process";
    case KswSandboxEventTypeImage:
        return "image.load";
    case KswSandboxEventTypeFile:
        return "driver.file";
    case KswSandboxEventTypeRegistry:
        return "driver.registry";
    case KswSandboxEventTypeNetwork:
        return "driver.network";
    case KswSandboxEventTypeReserved:
        return "driver.event.reserved";
    default:
        return "driver.event";
    }
}

// Input: Bounded ANSI character array from a driver payload.
// Processing: Copies bytes until NUL or capacity is reached, preserving only the
// supplied bounded range so malformed payloads cannot over-read collector memory.
// Return: ASCII/UTF-8-compatible string.
std::string BoundedAsciiString(const CHAR* value, const size_t capacity) {
    if (value == nullptr || capacity == 0) {
        return {};
    }

    size_t length = 0;
    while (length < capacity && value[length] != '\0') {
        ++length;
    }

    return std::string(value, value + length);
}

// Input: GET_HEALTH reply plus the byte count returned by DeviceIoControl.
// Processing: Copies every public field into string-valued data entries.
// Return: JSON object text for SandboxEvent.data.
std::string BuildHealthData(const KSWORD_SANDBOX_HEALTH_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_HEALTH");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_HEALTH);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("driverState", reply.DriverState);
    data.AddUtf8("driverStateName", DriverStateName(reply.DriverState));
    data.AddUnsigned("flags", reply.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(reply.Flags, 8));
    data.AddUnsigned("eventsQueued", reply.EventsQueued);
    data.AddUnsigned("eventsDropped", reply.EventsDropped);
    data.AddUnsigned("nextSequence", reply.NextSequence);
    data.AddSigned("lastNtStatus", reply.LastNtStatus);
    data.AddUtf8("lastNtStatusHex", HexUnsignedLongLong(static_cast<unsigned long>(reply.LastNtStatus), 8));
    return data.Build();
}

// Input: POLL reply plus the byte count returned by DeviceIoControl.
// Processing: Copies queue snapshot fields into string-valued data entries.
// Return: JSON object text for SandboxEvent.data.
std::string BuildPollData(const KSWORD_SANDBOX_POLL_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_POLL");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_POLL);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("driverState", reply.DriverState);
    data.AddUtf8("driverStateName", DriverStateName(reply.DriverState));
    data.AddBool("hasEvents", reply.HasEvents != 0);
    data.AddUnsigned("eventsQueued", reply.EventsQueued);
    data.AddUnsigned("eventsDropped", reply.EventsDropped);
    data.AddUnsigned("nextSequence", reply.NextSequence);
    return data.Build();
}

// Input: READ_EVENTS reply header, byte count, and the number of event records
// actually emitted by this collector.
// Processing: Records the batch-level metadata with string values so zero-event
// skeleton replies still leave evidence that the IOCTL was called.
// Return: JSON object text for SandboxEvent.data.
std::string BuildReadEventsBatchData(
    const KSWORD_SANDBOX_READ_EVENTS_REPLY& reply,
    const DWORD bytesReturned,
    const unsigned long long eventsEmitted) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("eventsWritten", reply.EventsWritten);
    data.AddUnsigned("eventsEmitted", eventsEmitted);
    data.AddUnsigned("flags", reply.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(reply.Flags, 8));
    data.AddUnsigned("bytesWritten", reply.BytesWritten);
    data.AddUnsigned("eventsDropped", reply.EventsDropped);
    data.AddUnsigned("nextSequence", reply.NextSequence);
    return data.Build();
}

// Input: One driver event header plus optional opaque payload bytes.
// Processing: Serializes framing metadata and a bounded payload hex preview as
// string-valued data entries.
// Return: JSON object text for SandboxEvent.data.
std::string BuildDriverEventData(
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    const unsigned long long batchIndex,
    const unsigned long long recordOffset,
    const unsigned char* payload,
    const size_t payloadBytes) {
    const size_t payloadPreviewBytes = payloadBytes < kMaxPayloadHexBytes ? payloadBytes : kMaxPayloadHexBytes;

    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
    data.AddUnsigned("batchIndex", batchIndex);
    data.AddUnsigned("recordOffset", recordOffset);
    data.AddUnsigned("version", header.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(header.Version, 8));
    data.AddUnsigned("recordSize", header.Size);
    data.AddUnsigned("driverEventType", header.Type);
    data.AddUtf8("driverEventTypeName", DriverEventTypeName(header.Type));
    data.AddUnsigned("flags", header.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(header.Flags, 8));
    data.AddUnsigned("sequence", header.Sequence);
    data.AddSigned("timestampQpc", header.TimestampQpc.QuadPart);
    data.AddUnsigned("driverProcessId", header.ProcessId);
    data.AddUnsigned("driverThreadId", header.ThreadId);
    data.AddUnsigned("payloadSize", header.PayloadSize);
    data.AddUnsigned("payloadHexBytes", payloadPreviewBytes);
    data.AddBool("payloadTruncated", payloadPreviewBytes < payloadBytes);
    data.AddUtf8("payloadHex", HexBytes(payload, payloadBytes, kMaxPayloadHexBytes));

    if (header.Type == KswSandboxEventTypeDriverLoad &&
        payload != nullptr &&
        payloadBytes >= sizeof(KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD)) {
        const auto* driverLoad =
            reinterpret_cast<const KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD*>(payload);
        data.AddUnsigned("driverLoadVersion", driverLoad->Version);
        data.AddUnsigned("driverLoadSize", driverLoad->Size);
        data.AddUnsigned("bootId", driverLoad->BootId);
        data.AddUtf8(
            "buildTag",
            BoundedAsciiString(driverLoad->BuildTag, sizeof(driverLoad->BuildTag)));
    }

    return data.Build();
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

// Input: Event sink and fields to emit.
// Processing: Serializes one SandboxEvent-compatible object and appends a JSONL newline.
// Return: true if the sink accepted the event; false if serialization or writing failed.
bool EmitEvent(EventWriter& writer, const SandboxEventFields& fields) {
    return writer.WriteLine(BuildSandboxEventJsonLine(fields));
}

// Input: Event sink plus a fully built event for stderr fallback.
// Processing: Writes JSONL to stderr when the normal output sink cannot be opened.
// Return: No return value.
void EmitFallbackEventToStderr(const SandboxEventFields& fields) {
    std::cerr << BuildSandboxEventJsonLine(fields) << '\n';
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
        event.processId = header.ProcessId;
        event.path = options.devicePath;
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

// Input: User options and event writer.
// Processing: Emits deterministic mock driver-like rows, then exits without
// opening the device path. This keeps CI and Guest Agent wiring testable before
// a signed kernel driver is installed in the guest VM.
// Return: Process exit code.
int RunMockMode(const Options& options, EventWriter& writer) {
    SandboxEventFields mockEvent;
    mockEvent.eventType = "r0collector.mockDriverEvent";
    mockEvent.processId = GetCurrentProcessId();
    mockEvent.path = LR"(C:\Windows\System32\notepad.exe)";
    mockEvent.commandLine = LR"("C:\Windows\System32\notepad.exe" --ksword-mock)";
    JsonDataObjectBuilder mockData;
    mockData.AddBool("mock", true);
    mockData.AddWide("devicePath", options.devicePath);
    mockData.AddUtf8("ioctlProtocol", "not-issued");
    mockData.AddUtf8("note", "Synthetic event for JSONL and Guest Agent plumbing.");
    mockEvent.dataJson = mockData.Build();

    if (!EmitEvent(writer, mockEvent)) {
        return kExitRuntimeFailure;
    }

    SandboxEventFields fileEvent;
    fileEvent.eventType = "file.created";
    fileEvent.processId = GetCurrentProcessId();
    fileEvent.path = LR"(C:\Users\Public\ksword-r0collector-mock.tmp)";
    fileEvent.commandLine = LR"("C:\Windows\System32\notepad.exe" --ksword-mock)";
    JsonDataObjectBuilder fileData;
    fileData.AddBool("mock", true);
    fileData.AddUtf8("driverEventType", "file");
    fileData.AddUtf8("operation", "create");
    fileData.AddWide("devicePath", options.devicePath);
    fileEvent.dataJson = fileData.Build();
    if (!EmitEvent(writer, fileEvent)) {
        return kExitRuntimeFailure;
    }

    SandboxEventFields registryEvent;
    registryEvent.eventType = "registry.set";
    registryEvent.processId = GetCurrentProcessId();
    registryEvent.path = LR"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KSwordMock)";
    registryEvent.commandLine = LR"("C:\Windows\System32\notepad.exe" --ksword-mock)";
    JsonDataObjectBuilder registryData;
    registryData.AddBool("mock", true);
    registryData.AddUtf8("driverEventType", "registry");
    registryData.AddUtf8("operation", "setValue");
    registryData.AddUtf8("valueName", "KSwordMock");
    registryEvent.dataJson = registryData.Build();
    if (!EmitEvent(writer, registryEvent)) {
        return kExitRuntimeFailure;
    }

    return kExitSuccess;
}

// Input: Open driver handle, collector options, and event sink.
// Processing: Calls the public driver skeleton IOCTLs. Health is read once;
// POLL and READ_EVENTS are called once for duration 0, or repeatedly until the
// requested duration elapses.
// Return: Process exit code describing write or IOCTL failure versus success.
int RunDriverIoctlLoop(const UniqueHandle& device, const Options& options, EventWriter& writer) {
    if (!device.IsValid()) {
        return kExitDeviceUnavailable;
    }

    if (!EmitDriverHealth(device, options, writer)) {
        return kExitRuntimeFailure;
    }

    unsigned long long polls = 0;
    unsigned long long readBatches = 0;
    unsigned long long driverEvents = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(options.durationSeconds);

    do {
        if (!EmitDriverPoll(device, options, writer)) {
            return kExitRuntimeFailure;
        }
        ++polls;

        unsigned long long eventsEmitted = 0;
        if (!EmitDriverReadEvents(device, options, readBatches + 1, writer, &eventsEmitted)) {
            return kExitRuntimeFailure;
        }
        ++readBatches;
        driverEvents += eventsEmitted;

        if (options.durationSeconds <= 0 || std::chrono::steady_clock::now() >= deadline) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(options.pollIntervalMs));
    } while (std::chrono::steady_clock::now() < deadline);

    JsonDataObjectBuilder data;
    data.AddUtf8("reason", options.durationSeconds > 0 ? "durationElapsed" : "oneShotComplete");
    data.AddUnsigned("polls", polls);
    data.AddUnsigned("readBatches", readBatches);
    data.AddUnsigned("driverEvents", driverEvents);
    data.AddBool("ioctlIssued", true);

    SandboxEventFields stoppedEvent;
    stoppedEvent.eventType = "r0collector.stopped";
    stoppedEvent.path = options.devicePath;
    stoppedEvent.dataJson = data.Build();

    return EmitEvent(writer, stoppedEvent) ? kExitSuccess : kExitRuntimeFailure;
}

} // namespace

// Input: Windows Unicode process arguments.
// Processing: Parses collector options, opens the output JSONL sink, optionally
// opens the driver device, and emits SandboxEvent-compatible lifecycle/error rows.
// Return: Conventional process exit code; nonzero values distinguish argument,
// output, device-open, and runtime failures.
int wmain(int argc, wchar_t* argv[]) {
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

    if (options.mockMode) {
        const int mockExitCode = RunMockMode(options, writer);
        if (mockExitCode != kExitSuccess) {
            return mockExitCode;
        }

        SandboxEventFields stoppedEvent;
        stoppedEvent.eventType = "r0collector.stopped";
        stoppedEvent.path = options.devicePath;
        JsonDataObjectBuilder stoppedData;
        stoppedData.AddUtf8("reason", "mockComplete");
        stoppedData.AddBool("ioctlIssued", false);
        stoppedEvent.dataJson = stoppedData.Build();
        return EmitEvent(writer, stoppedEvent) ? kExitSuccess : kExitRuntimeFailure;
    }

    DWORD openError = ERROR_SUCCESS;
    UniqueHandle device = OpenDriverDevice(options.devicePath, &openError);
    if (!device.IsValid()) {
        const std::wstring message = L"Unable to open driver device " + options.devicePath + L": " + Win32ErrorMessage(openError);
        SandboxEventFields deviceEvent;
        deviceEvent.eventType = "r0collector.deviceUnavailable";
        deviceEvent.path = options.devicePath;
        deviceEvent.dataJson = BuildErrorData(
            message,
            openError,
            L"Install/start the KSword driver, verify the symbolic link, or run with --mock for plumbing tests.");
        EmitEvent(writer, deviceEvent);
        return kExitDeviceUnavailable;
    }

    SandboxEventFields openedEvent;
    openedEvent.eventType = "r0collector.deviceOpened";
    openedEvent.path = options.devicePath;
    JsonDataObjectBuilder openedData;
    openedData.AddWide("devicePath", options.devicePath);
    openedData.AddBool("ioctlIssued", false);
    openedData.AddUtf8("ioctlProtocol", "KSwordSandboxDriverIoctl.h");
    openedEvent.dataJson = openedData.Build();
    if (!EmitEvent(writer, openedEvent)) {
        return kExitRuntimeFailure;
    }

    return RunDriverIoctlLoop(device, options, writer);
}
