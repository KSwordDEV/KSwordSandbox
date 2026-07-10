#include "JsonWriter.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace KSword::Sandbox::R0Collector {

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

// Input: Unsigned integer value plus a minimum hexadecimal digit width.
// Processing: Formats the value with a 0x prefix and zero-padding for stable
// diagnostic output in JSONL data fields.
// Return: ASCII hexadecimal text.
std::string HexUnsignedLongLong(const unsigned long long value, const int width) {
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

// Input: Address family and raw address bytes from a network payload.
// Processing: Formats IPv4 as dotted decimal and IPv6 as eight hexadecimal
// hextets without compression so the output stays deterministic and dependency-free.
// Return: Presentation-style address text, or an empty string for unknown inputs.
std::string NetworkAddressText(const ULONG addressFamily, const unsigned char* addressBytes) {
    if (addressBytes == nullptr) {
        return {};
    }

    std::ostringstream text;
    if (addressFamily == KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV4) {
        text << static_cast<unsigned int>(addressBytes[0]) << "."
             << static_cast<unsigned int>(addressBytes[1]) << "."
             << static_cast<unsigned int>(addressBytes[2]) << "."
             << static_cast<unsigned int>(addressBytes[3]);
        return text.str();
    }

    if (addressFamily == KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV6) {
        text << std::hex << std::nouppercase;
        for (size_t index = 0; index < KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES; index += 2U) {
            if (index != 0) {
                text << ":";
            }
            const unsigned int hextet =
                (static_cast<unsigned int>(addressBytes[index]) << 8U) |
                static_cast<unsigned int>(addressBytes[index + 1U]);
            text << hextet;
        }
        return text.str();
    }

    return {};
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

} // namespace KSword::Sandbox::R0Collector
