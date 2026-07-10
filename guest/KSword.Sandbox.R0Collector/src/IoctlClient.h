#pragma once

#include "Common.h"
#include "JsonWriter.h"
#include "Options.h"

namespace KSword::Sandbox::R0Collector {

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

UniqueHandle OpenDriverDevice(const std::wstring& devicePath, DWORD* errorCode);
bool EmitDriverHealth(const UniqueHandle& device, const Options& options, EventWriter& writer);
bool EmitDriverCapabilities(const UniqueHandle& device, const Options& options, EventWriter& writer);
bool EmitDriverPoll(const UniqueHandle& device, const Options& options, EventWriter& writer);
bool EmitDriverReadEvents(
    const UniqueHandle& device,
    const Options& options,
    unsigned long long batchIndex,
    EventWriter& writer,
    unsigned long long* eventsEmitted);

} // namespace KSword::Sandbox::R0Collector
