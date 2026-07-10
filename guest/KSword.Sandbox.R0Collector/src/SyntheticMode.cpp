#include "SyntheticMode.h"

#include <string>
#include <utility>
#include <vector>

namespace KSword::Sandbox::R0Collector {

// Input: Mock category metadata, collector options, and the JSONL sink.
// Processing: Emits one synthetic driver-originated row that uses the same
// stable eventType values as drained R0 events while clearly marking the data as
// mock-only and not sourced from a real kernel payload.
// Return: true if the JSONL sink accepted the mock row; false on write failure.
bool EmitMockDriverCategoryEvent(
    EventWriter& writer,
    const Options& options,
    const std::string& eventType,
    const std::wstring& path,
    const std::wstring& commandLine,
    const std::string& driverEventTypeName,
    const std::string& operation,
    const std::vector<std::pair<std::string, std::string>>& extraData) {
    SandboxEventFields event;
    event.eventType = eventType;
    event.source = "driver";
    event.processId = GetCurrentProcessId();
    event.path = path;
    event.commandLine = commandLine;

    JsonDataObjectBuilder data;
    data.AddBool("mock", true);
    data.AddWide("devicePath", options.devicePath);
    data.AddUtf8("driverEventTypeName", driverEventTypeName);
    data.AddUtf8("operation", operation);
    data.AddUtf8("typedPayloadStatus", "mock");
    data.AddUtf8("payloadSchema", "mock-forward-compatible");
    data.AddUtf8(
        "note",
        "Synthetic driver-category row for Guest Agent and host import plumbing.");

    for (const auto& item : extraData) {
        data.AddUtf8(item.first, item.second);
    }

    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: User options and event writer.
// Processing: Emits deterministic mock driver-like rows, then exits without
// opening the device path. This keeps CI and Guest Agent wiring testable before
// a signed kernel driver is installed in the guest VM.
// Return: Process exit code.
int RunSyntheticMode(const Options& options, EventWriter& writer) {
    const DWORD currentProcessId = GetCurrentProcessId();
    const std::string currentProcessIdText = std::to_string(currentProcessId);
    const std::wstring mockProcessPath = LR"(C:\Windows\System32\notepad.exe)";
    const std::wstring mockCommandLine = LR"("C:\Windows\System32\notepad.exe" --ksword-mock)";

    SandboxEventFields mockEvent;
    mockEvent.eventType = "r0collector.mockDriverEvent";
    mockEvent.processId = currentProcessId;
    mockEvent.path = mockProcessPath;
    mockEvent.commandLine = mockCommandLine;
    JsonDataObjectBuilder mockData;
    mockData.AddBool("mock", true);
    mockData.AddWide("devicePath", options.devicePath);
    mockData.AddUtf8("ioctlProtocol", "not-issued");
    mockData.AddUtf8("note", "Synthetic marker; driver category mock rows follow.");
    mockEvent.dataJson = mockData.Build();

    if (!EmitEvent(writer, mockEvent)) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.process",
            mockProcessPath,
            mockCommandLine,
            "process",
            "create",
            {
                {"imagePath", "C:\\Windows\\System32\\notepad.exe"},
                {"processId", currentProcessIdText},
                {"parentProcessId", currentProcessIdText}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "image.load",
            LR"(C:\Windows\System32\kernel32.dll)",
            mockCommandLine,
            "image",
            "load",
            {
                {"imagePath", "C:\\Windows\\System32\\kernel32.dll"},
                {"imageBase", "0x0000000180000000"},
                {"imageSize", "1048576"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.file",
            LR"(C:\Users\Public\ksword-r0collector-mock.tmp)",
            mockCommandLine,
            "file",
            "create",
            {
                {"filePath", "C:\\Users\\Public\\ksword-r0collector-mock.tmp"},
                {"desiredAccessHex", "0x0012019F"},
                {"disposition", "create"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.registry",
            LR"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KSwordMock)",
            mockCommandLine,
            "registry",
            "setValue",
            {
                {"keyPath", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
                {"valueName", "KSwordMock"},
                {"valueType", "REG_SZ"}
            })) {
        return kExitRuntimeFailure;
    }

    return kExitSuccess;
}

} // namespace KSword::Sandbox::R0Collector
