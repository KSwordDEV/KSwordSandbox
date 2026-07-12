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

std::wstring DeviceOpenZhHint(const DWORD errorCode, const std::wstring& serviceName) {
    const std::wstring serviceText = serviceName.empty() ? L"KSwordSandboxDriver" : serviceName;
    switch (errorCode) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_PATHNAME:
        return L"\u8bf7\u786e\u8ba4\u5185\u6838\u670d\u52a1 '" + serviceText +
            L"' \u5df2\u5b58\u5728\u5e76\u6b63\u5728\u8fd0\u884c\uff0c"
            L"\u4e14\u5df2\u521b\u5efa \\\\DosDevices\\\\KSwordSandboxDriver \u7b26\u53f7\u94fe\u63a5\uff1b"
            L"\u5982\u679c\u542f\u52a8\u5931\u8d25\uff0c\u8bf7\u68c0\u67e5\u9a71\u52a8\u7b7e\u540d/"
            L"\u6d4b\u8bd5\u7b7e\u540d\u548c Code Integrity \u65e5\u5fd7\u3002";
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
        return L"\u6253\u5f00\u88ab\u62d2\u7edd\u3002\u8bf7\u5728\u63d0\u6743\u7684 guest \u73af\u5883\u4e2d\u8fd0\u884c Collector\uff0c"
            L"\u6216\u8c03\u6574\u9a71\u52a8\u63a7\u5236\u8bbe\u5907\u7684\u5b89\u5168\u63cf\u8ff0\u7b26\u3002";
    case ERROR_SHARING_VIOLATION:
        return L"\u63a7\u5236\u8bbe\u5907\u5b58\u5728\uff0c\u4f46\u53e6\u4e00\u4e2a\u53e5\u67c4\u62d2\u7edd\u5171\u4eab\uff1b"
            L"\u8bf7\u5173\u95ed\u5176\u4ed6 Collector \u540e\u91cd\u8bd5\u3002";
    default:
        return L"\u8bf7\u68c0\u67e5 SCM \u72b6\u6001\u3001\u9a71\u52a8\u52a0\u8f7d\u4e8b\u4ef6\u3001"
            L"\u8bbe\u5907\u7b26\u53f7\u94fe\u63a5\u521b\u5efa\uff0c"
            L"\u4ee5\u53ca\u5df2\u52a0\u8f7d\u9a71\u52a8\u7684 public IOCTL ABI\u3002";
    }
}

std::wstring ReadinessZhMessage(const std::string& state) {
    if (state == "blocked") {
        return L"R0Collector \u5c31\u7eea\u8bca\u65ad\u53d1\u73b0\u963b\u585e\u9879\uff1b"
            L"\u8fd9\u662f\u91c7\u96c6\u8bca\u65ad\uff0c\u4e0d\u4ee3\u8868\u6837\u672c\u884c\u4e3a\u3002";
    }

    if (state == "degraded") {
        return L"R0Collector \u5c31\u7eea\u8bca\u65ad\u53d1\u73b0\u964d\u7ea7\u9879\uff1b"
            L"\u53ef\u7ee7\u7eed\u67e5\u770b\u5176\u4ed6\u63a2\u9488\u7ed3\u679c\u3002";
    }

    return L"R0Collector \u5c31\u7eea\u63a2\u9488\u901a\u8fc7\u3002";
}

std::wstring ReadinessZhHint(const std::string& stage, const std::string& code) {
    if (stage == "service") {
        if (code == "missing_service") {
            return L"未找到驱动服务。请先在隔离 VM 中注册 KSwordSandboxDriver 服务；Collector 不会自动安装、启动或签名驱动。";
        }

        if (code == "service_not_running" || code == "service_start_pending") {
            return L"驱动服务存在但尚未运行。请在 VM 中检查 SCM 失败代码、驱动签名/测试签名状态和 Code Integrity 日志。";
        }

        if (code == "service_query_denied" || code == "service_manager_denied") {
            return L"SCM 查询权限不足。请以提升权限运行 Collector；后续设备打开和 ABI 探针仍可作为直接证据。";
        }

        return L"\u8bf7\u786e\u8ba4\u9a71\u52a8\u670d\u52a1\u540d\u3001\u5b89\u88c5\u72b6\u6001\u548c\u8fd0\u884c\u72b6\u6001\uff1b"
            L"Collector \u4e0d\u4f1a\u5b89\u88c5\u3001\u542f\u52a8\u3001\u505c\u6b62\u6216\u7b7e\u540d\u9a71\u52a8\u3002";
    }

    if (stage == "openDevice") {
        if (code == "open_device_not_found" || code == "read_probe_open_failed") {
            return L"无法找到控制设备。请确认服务已运行并创建 \\\\DosDevices\\\\KSwordSandboxDriver 符号链接；若启动失败，请检查签名/测试签名和 Code Integrity。";
        }

        if (code == "open_device_denied") {
            return L"打开控制设备被拒绝。请以提升权限运行 Collector，或检查驱动控制设备的安全描述符。";
        }

        if (code == "open_device_sharing_violation") {
            return L"控制设备存在但共享冲突。请关闭其他 Collector 或占用该设备的句柄后重试。";
        }

        return L"\u8bf7\u786e\u8ba4\u9a71\u52a8\u670d\u52a1\u5df2\u8fd0\u884c\u3001"
            L"\u63a7\u5236\u8bbe\u5907\u7b26\u53f7\u94fe\u63a5\u5b58\u5728\uff0c"
            L"\u5e76\u4e14 Collector \u4ee5\u8db3\u591f\u6743\u9650\u8fd0\u884c\u3002";
    }

    if (stage == "abiNegotiation" || code == "abi_mismatch") {
        if (code == "optional_ioctl_unavailable" || code == "abi_capabilities_unavailable") {
            return L"当前驱动缺少可选 ABI 探针。Collector 会尽量兼容旧路径；如需完整队列、背压和 producer-mask 诊断，请使用同一构建产物的驱动和 Collector。";
        }

        return L"\u8bf7\u786e\u8ba4\u9a71\u52a8\u548c Collector \u6765\u81ea\u540c\u4e00\u6784\u5efa\uff0c"
            L"public IOCTL ABI \u5934\u6587\u4ef6\u5339\u914d\u3002";
    }

    if (stage == "readEvents") {
        if (code == "read_timeout") {
            return L"READ_EVENTS 在诊断超时内未返回。请检查驱动分发函数是否挂起、锁是否卡住，以及队列同步路径。";
        }

        if (code == "driver_no_events") {
            return L"READ_EVENTS 已完成但没有返回驱动记录。请确认 producer enable mask 未禁用目标 producer，并在 VM 内产生受控样本活动；若只想验证无驱动字段质量，可先运行 --abi-self-check 或 --stress-count 32 --inject-jsonl-noise。";
        }

        if (code == "read_protocol_error" || code == "abi_mismatch") {
            return L"READ_EVENTS 回复头与 Collector 期望不匹配。请重新构建并加载匹配版本的驱动和 Collector。";
        }

        return L"\u8bf7\u786e\u8ba4 READ_EVENTS \u5206\u53d1\u4e0d\u4f1a\u6302\u8d77\u3001"
            L"producer \u5df2\u542f\u7528\uff0c\u5e76\u5728 VM \u5185\u4ea7\u751f\u53d7\u63a7\u6837\u672c\u6d3b\u52a8\u3002";
    }

    return L"\u8bf7\u7ed3\u5408 diagnosticStage/diagnosticCode \u548c hint \u5b57\u6bb5\u5b9a\u4f4d\u5c31\u7eea\u95ee\u9898\u3002";
}

std::wstring ReadinessSummaryZhMessage(const ReadinessSummary& summary) {
    if (summary.blocked) {
        return L"\u5c31\u7eea\u8bca\u65ad\u53d1\u73b0\u963b\u585e\u9879\uff1b"
            L"\u8bf7\u4f18\u5148\u67e5\u770b failedStage \u548c\u5404 *DiagnosticCode \u5b57\u6bb5\u3002";
    }

    if (summary.degraded) {
        return L"\u5c31\u7eea\u8bca\u65ad\u53d1\u73b0\u964d\u7ea7\u9879\uff1b"
            L"\u8bf7\u67e5\u770b warning \u884c\u5e76\u786e\u8ba4\u662f\u5426\u5f71\u54cd\u672c\u6b21\u91c7\u96c6\u76ee\u6807\u3002";
    }

    return L"\u5c31\u7eea\u8bca\u65ad\u901a\u8fc7\uff1bR0Collector \u53ef\u7ee7\u7eed\u8fdb\u5165\u91c7\u96c6\u8def\u5f84\u3002";
}

// Input: Collector-diagnostic JSON builder plus row disposition label.
// Processing: Adds the same rich noise taxonomy used by driver/mock rows while
// keeping readiness diagnostics out of sample behavior.
// Return: No return value; builder is mutated.
void AddReadinessNoiseFields(
    JsonDataObjectBuilder& data,
    const std::string& disposition) {
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
    data.AddUtf8("noiseScope", "collector-diagnostic");
    data.AddUtf8("noiseKind", "readiness-diagnostic");
    data.AddUtf8("noiseSource", "r0collector-readiness");
    data.AddUtf8("noiseClass", "collector-diagnostic");
    data.AddUtf8("selfNoiseClass", "none");
    data.AddUtf8("collectorNoiseClass", "collector-diagnostic");
    data.AddUtf8("noiseAction", "emit");
    data.AddUtf8("noiseDisposition", disposition);
    data.AddUtf8("noiseReasons", "collectionDiagnostic");
    data.AddUtf8("noiseFieldSet", kJsonlNoiseFieldSet);
    AddCollectorNonBehaviorFields(data, "readiness-diagnostic", "emit-readiness-diagnostic-not-sample-behavior");
    data.AddBool("sampleBehaviorCandidate", false);
    data.AddWide(
        "zhNoiseHint",
        L"该 readiness 行是 Collector 采集健康/配置诊断，不是样本行为；报告应作为采集状态处理。");
    data.AddWide(
        "zhNoisePolicyHint",
        L"readiness 噪声策略是写出诊断但不计入行为；Host 应按 collector health 处理。");
    data.AddWide(
        "zhOperatorHint",
        L"运营提示：先修复 readiness 的阻塞/降级项，再解读样本行为；可用 --abi-self-check 或 --stress-count 32 --inject-jsonl-noise 做无驱动验证。");
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
    data.AddUtf8("collectionScope", "r0collector-readiness");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddUtf8("eventOrigin", "collector-sidecar");
    data.AddUtf8("producerCategory", "r0collector");
    data.AddUtf8("subjectKind", "collector-diagnostic");
    data.AddUtf8("actorRole", "collector-infrastructure");
    data.AddUtf8("subjectRole", "collector-diagnostic");
    data.AddUtf8("processIdSource", "top-level");
    data.AddWide("hint", hint);
    data.AddWide("zhMessage", ReadinessZhMessage(state));
    data.AddWide("zhHint", ReadinessZhHint(stage, code));
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("serviceName", options.serviceName);
    data.AddSigned("diagnoseReadTimeoutMs", options.diagnoseReadTimeoutMs);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddReadinessNoiseFields(data, "emitted-as-readiness-diagnostic");
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddUtf8("loss", "none");
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureReason", "none");
    data.AddUnsigned("highWatermark", 0);

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

    const bool bytesReturnedMatch = bytesReturned >= static_cast<DWORD>(sizeof(reply));
    const bool interfaceVersionMatch = reply.Version == KSWORD_SANDBOX_INTERFACE_VERSION;
    const bool replySizeCompatible = reply.Size >= sizeof(reply);
    const bool abiMajorMatch = reply.AbiVersionMajor == KSWORD_SANDBOX_ABI_VERSION_MAJOR;
    const bool abiMinorForwardCompatible = reply.AbiVersionMinor >= KSWORD_SANDBOX_ABI_VERSION_MINOR;
    const bool eventHeaderVersionMatch = reply.EventHeaderVersion == KSWORD_SANDBOX_EVENT_HEADER_VERSION;
    const bool maxPayloadSizeCompatible = reply.EventMaxPayloadSize <= KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE;
    const bool readEventsHeaderSizeMatch =
        reply.ReadEventsReplyHeaderSize == KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE;
    const bool capabilitiesReplySizeCompatible = reply.CapabilitiesReplySize >= sizeof(reply);
    const bool statusReplySizeCompatible = reply.StatusReplySize >= sizeof(KSWORD_SANDBOX_STATUS_REPLY);
    const bool compatible =
        bytesReturnedMatch &&
        interfaceVersionMatch &&
        replySizeCompatible &&
        abiMajorMatch &&
        abiMinorForwardCompatible &&
        eventHeaderVersionMatch &&
        maxPayloadSizeCompatible &&
        readEventsHeaderSizeMatch &&
        capabilitiesReplySizeCompatible &&
        statusReplySizeCompatible;

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
    extra.AddUnsigned("expectedBytesReturnedAtLeast", sizeof(reply));
    extra.AddBool("bytesReturnedMatch", bytesReturnedMatch);
    extra.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    extra.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    extra.AddUnsigned("driverInterfaceVersion", reply.Version);
    extra.AddUtf8("driverInterfaceVersionHex", HexUnsignedLongLong(reply.Version, 8));
    extra.AddBool("interfaceVersionMatch", interfaceVersionMatch);
    extra.AddUnsigned("expectedAbiVersionMajor", KSWORD_SANDBOX_ABI_VERSION_MAJOR);
    extra.AddUnsigned("expectedAbiVersionMinor", KSWORD_SANDBOX_ABI_VERSION_MINOR);
    extra.AddUnsigned("driverAbiVersionMajor", reply.AbiVersionMajor);
    extra.AddUnsigned("driverAbiVersionMinor", reply.AbiVersionMinor);
    extra.AddBool("abiMajorMatch", abiMajorMatch);
    extra.AddBool("abiMinorForwardCompatible", abiMinorForwardCompatible);
    extra.AddUnsigned("expectedEventHeaderVersion", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    extra.AddUnsigned("driverEventHeaderVersion", reply.EventHeaderVersion);
    extra.AddUtf8("driverEventHeaderVersionHex", HexUnsignedLongLong(reply.EventHeaderVersion, 8));
    extra.AddBool("eventHeaderVersionMatch", eventHeaderVersionMatch);
    extra.AddUnsigned("expectedEventMaxPayloadSize", KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
    extra.AddUnsigned("driverEventMaxPayloadSize", reply.EventMaxPayloadSize);
    extra.AddBool("maxPayloadSizeCompatible", maxPayloadSizeCompatible);
    extra.AddUnsigned("expectedCapabilitiesReplySize", sizeof(KSWORD_SANDBOX_CAPABILITIES_REPLY));
    extra.AddUnsigned("driverCapabilitiesReplySize", reply.CapabilitiesReplySize);
    extra.AddBool("capabilitiesReplySizeCompatible", capabilitiesReplySizeCompatible);
    extra.AddUnsigned("expectedStatusReplySize", sizeof(KSWORD_SANDBOX_STATUS_REPLY));
    extra.AddUnsigned("driverStatusReplySize", reply.StatusReplySize);
    extra.AddBool("statusReplySizeCompatible", statusReplySizeCompatible);
    extra.AddUnsigned("expectedReadEventsReplyHeaderSize", KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);
    extra.AddUnsigned("driverReadEventsReplyHeaderSize", reply.ReadEventsReplyHeaderSize);
    extra.AddBool("readEventsReplyHeaderSizeMatch", readEventsHeaderSizeMatch);
    extra.AddBool("abiCompatible", compatible);
    std::string mismatchReasons;
    const auto appendMismatch = [&mismatchReasons](const bool ok, const char* reason) {
        if (ok) {
            return;
        }
        if (!mismatchReasons.empty()) {
            mismatchReasons += "|";
        }
        mismatchReasons += reason;
    };
    appendMismatch(bytesReturnedMatch, "bytesReturnedTooSmall");
    appendMismatch(interfaceVersionMatch, "interfaceVersion");
    appendMismatch(replySizeCompatible, "capabilitiesReplySizeField");
    appendMismatch(abiMajorMatch, "abiMajor");
    appendMismatch(abiMinorForwardCompatible, "abiMinorTooOld");
    appendMismatch(eventHeaderVersionMatch, "eventHeaderVersion");
    appendMismatch(maxPayloadSizeCompatible, "eventMaxPayloadSize");
    appendMismatch(readEventsHeaderSizeMatch, "readEventsReplyHeaderSize");
    appendMismatch(capabilitiesReplySizeCompatible, "capabilitiesReplySize");
    appendMismatch(statusReplySizeCompatible, "statusReplySize");
    extra.AddUtf8("abiMismatchReasons", mismatchReasons.empty() ? "none" : mismatchReasons);
    extra.AddWide(
        "zhAbiDiagnosticHint",
        compatible
            ? L"驱动 capabilities 与 Collector 期望 ABI 匹配。"
            : L"ABI 不匹配；请对照 abiMismatchReasons 以及 expected*/driver* 字段，使用同一构建产物重新部署驱动和 Collector。");

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
        extra.AddUnsigned("expectedReplyHeaderSize", KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);
        extra.AddUnsigned("expectedReplyVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
        extra.AddUnsigned("replyVersion", reply.Version);
        extra.AddUnsigned("replySize", reply.Size);
        extra.AddUnsigned("replyBytesWritten", reply.BytesWritten);
        extra.AddUnsigned("availableEventBytes", availableEventBytes);
        extra.AddBool("replyVersionMatch", reply.Version == KSWORD_SANDBOX_INTERFACE_VERSION);
        extra.AddBool("replySizeAtLeastHeader", reply.Size >= KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);
        extra.AddBool("replySizeWithinBytesReturned", reply.Size <= bytesReturned);
        extra.AddBool("replyBytesWrittenWithinAvailableBytes", reply.BytesWritten <= availableEventBytes);
        extra.AddUtf8(
            "abiMismatchReasons",
            reply.Version != KSWORD_SANDBOX_INTERFACE_VERSION
                ? "readEventsReplyVersion"
                : (reply.Size < KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE
                    ? "readEventsReplyHeaderTooSmall"
                    : (reply.Size > bytesReturned
                        ? "readEventsReplySizeExceedsBytesReturned"
                        : "readEventsReplyBytesWrittenExceedsAvailable")));
        extra.AddWide(
            "zhAbiDiagnosticHint",
            L"READ_EVENTS 回复头与 Collector 期望不匹配；请对照 expected*/reply* 字段重新部署匹配版本。");
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
    extra.AddUnsigned("lostCount", reply.EventsDropped);
    extra.AddUnsigned("nextSequence", reply.NextSequence);
    extra.AddUnsigned("sequence", reply.NextSequence);
    extra.AddUtf8("sequenceMeaning", "nextSequence");

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
    data.AddWide("zhMessage", ReadinessSummaryZhMessage(summary));
    data.AddWide(
        "zhHint",
        L"\u8bf7\u628a readinessSummary \u89c6\u4e3a\u91c7\u96c6\u5065\u5eb7\u72b6\u6001\uff0c"
        L"\u4e0d\u8981\u5f52\u7c7b\u4e3a\u6837\u672c\u884c\u4e3a\u3002");
    data.AddBool("ready", !summary.blocked);
    data.AddBool("degraded", summary.degraded);
    data.AddUtf8("collectionScope", "r0collector-readiness-summary");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddUtf8("eventOrigin", "collector-sidecar");
    data.AddUtf8("producerCategory", "r0collector");
    data.AddUtf8("subjectKind", "collector-diagnostic");
    data.AddUtf8("actorRole", "collector-infrastructure");
    data.AddUtf8("subjectRole", "collector-diagnostic");
    data.AddUtf8("processIdSource", "top-level");
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
    AddReadinessNoiseFields(data, "emitted-as-readiness-summary");
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddUtf8("loss", "none");
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureReason", "none");
    data.AddUnsigned("highWatermark", 0);

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
    data.AddUtf8("deviceAvailability", "unavailable");
    data.AddBool("deviceOpenAttempted", true);
    data.AddBool("ioctlIssued", false);
    data.AddBool("driverLoadedByCollector", false);
    data.AddBool("mutatesDriver", false);
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("collectionScope", "r0collector-device-open");
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddUtf8("eventOrigin", "collector-sidecar");
    data.AddUtf8("producerCategory", "r0collector");
    data.AddUtf8("subjectKind", "collector-diagnostic");
    data.AddUtf8("actorRole", "collector-infrastructure");
    data.AddUtf8("subjectRole", "collector-diagnostic");
    data.AddUtf8("processIdSource", "top-level");
    data.AddUtf8("sideEffectPolicy", "read-only-open-no-driver-load-no-scm-mutation-no-signing");
    data.AddWide("devicePath", options.devicePath);
    data.AddWide("serviceName", options.serviceName);
    data.AddUnsigned("win32Error", openError);
    data.AddWide("win32Message", Win32ErrorMessage(openError));
    data.AddWide(
        "message",
        L"Unable to open driver device " + options.devicePath + L": " + Win32ErrorMessage(openError));
    data.AddWide("hint", DeviceOpenHint(openError, options.serviceName));
    data.AddWide(
        "zhMessage",
        L"\u65e0\u6cd5\u6253\u5f00\u9a71\u52a8\u8bbe\u5907 " + options.devicePath + L": " + Win32ErrorMessage(openError));
    data.AddWide("zhHint", DeviceOpenZhHint(openError, options.serviceName));
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddReadinessNoiseFields(data, "emitted-as-device-unavailable-diagnostic");
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddUtf8("loss", "none");
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureReason", "none");
    data.AddUnsigned("highWatermark", 0);

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
    openedData.AddWide(
        "zhMessage",
        L"\u9a71\u52a8\u63a7\u5236\u8bbe\u5907\u5df2\u6253\u5f00\uff1b"
        L"Collector \u5c06\u7ee7\u7eed\u6267\u884c ABI \u548c READ_EVENTS \u5c31\u7eea\u63a2\u9488\u3002");
    openedData.AddWide(
        "zhHint",
        L"\u8bf7\u7ee7\u7eed\u67e5\u770b\u540e\u7eed r0collector.readinessDiagnostic \u884c\uff0c"
        L"\u786e\u8ba4 ABI\u3001\u961f\u5217\u8bfb\u53d6\u548c\u5065\u5eb7\u72b6\u6001\u5747\u4e3a ready\u3002");
    openedData.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    openedData.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(openedData, "collector-device-open", "collector-diagnostic");
    AddCollectorNonBehaviorFields(openedData, "readiness-device-open", "emit-readiness-device-open-not-sample-behavior");
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

    if (!EmitDriverNetworkStatus(device, options, writer)) {
        RecordProbe(&summary, "abiNegotiation", "network_status_emit_failed", "error", "blocked");
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
