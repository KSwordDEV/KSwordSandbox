#pragma once

#include "Common.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <ostream>
#include <sstream>
#include <string>

namespace KSword::Sandbox::R0Collector {

std::string Utf8FromWide(const std::wstring& value);
std::string JsonEscapeUtf8(const std::string& value);
std::string JsonStringFromUtf8(const std::string& value);
std::string JsonStringFromWide(const std::wstring& value);
std::string HexUnsignedLongLong(unsigned long long value, int width = 0);
std::string HexBytes(const unsigned char* bytes, size_t byteCount, size_t maxBytes);
std::string NetworkAddressText(ULONG addressFamily, const unsigned char* addressBytes);
std::string UtcTimestampIso8601();
std::wstring Win32ErrorMessage(DWORD errorCode);
std::wstring CurrentCommandLine();
std::wstring CurrentProcessName();
std::wstring BaseNameFromPath(const std::wstring& path);

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

void AddCollectorAttributionFields(
    JsonDataObjectBuilder& data,
    const std::string& subjectKind,
    const std::string& subjectRole);
void AddCollectorNonBehaviorFields(
    JsonDataObjectBuilder& data,
    const std::string& evidenceKind,
    const std::string& noisePolicy);

struct SandboxEventFields {
    std::string eventType;
    std::string source = kCollectorSource;
    std::wstring timestampOverride;
    unsigned long long processId = GetCurrentProcessId();
    std::wstring processName = CurrentProcessName();
    std::wstring path;
    std::wstring commandLine = CurrentCommandLine();
    std::string dataJson = "{}";
};

std::string BuildSandboxEventJsonLine(const SandboxEventFields& fields);

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
                *error = L"Unable to open output JSONL file: " + outputPath +
                    L" / \u65e0\u6cd5\u6253\u5f00\u8f93\u51fa JSONL \u6587\u4ef6\uff1a" + outputPath;
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

bool EmitEvent(EventWriter& writer, const SandboxEventFields& fields);
void EmitFallbackEventToStderr(const SandboxEventFields& fields);

} // namespace KSword::Sandbox::R0Collector
