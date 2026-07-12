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

// Input: Mutable JSON data builder and optional process-handle capability state.
// Processing: Emits explicit negative/availability fields for telemetry that
// process lifecycle rows do not provide, preventing reports from treating
// create/exit evidence as AdjustTokenPrivileges, SeDebugPrivilege, or process
// handle requested/granted-access evidence.
// Return: No return value; builder is mutated.
inline void AddR0PrivilegeProcessAccessCoverageFields(
    JsonDataObjectBuilder& data,
    const bool processHandleAccessTelemetryAvailable = false,
    const bool tokenPrivilegeTelemetryAvailable = false) {
    data.AddBool("r0PrivilegeTelemetryAvailable", tokenPrivilegeTelemetryAvailable);
    data.AddBool("r0AdjustTokenPrivilegesTelemetryAvailable", tokenPrivilegeTelemetryAvailable);
    data.AddBool("r0SeDebugPrivilegeTelemetryAvailable", tokenPrivilegeTelemetryAvailable);
    data.AddUtf8(
        "r0PrivilegeTelemetrySource",
        tokenPrivilegeTelemetryAvailable
            ? kR0PrivilegeTelemetrySourceDraft
            : kR0PrivilegeTelemetrySourceUnavailable);
    data.AddUtf8(
        "r0PrivilegeTelemetryStatus",
        tokenPrivilegeTelemetryAvailable ? "draft-capability-advertised" : "not-implemented");
    data.AddBool("tokenPrivilegeAdjustmentR0Direct", tokenPrivilegeTelemetryAvailable);
    data.AddBool("tokenPrivilegeAdjustmentEtwFallbackRequired", !tokenPrivilegeTelemetryAvailable);
    data.AddUtf8(
        "tokenPrivilegeAdjustmentObservation",
        tokenPrivilegeTelemetryAvailable ? "r0-direct-draft" : "etw-fallback-required");
    data.AddUtf8(
        "tokenPrivilegeAdjustmentObservationSource",
        tokenPrivilegeTelemetryAvailable ? kR0PrivilegeTelemetrySourceDraft : "etw-security-audit-or-kernel-provider");
    data.AddUtf8(
        "tokenPrivilegeAdjustmentEtwFallbackReason",
        tokenPrivilegeTelemetryAvailable ? "none" : "not-implemented-no-token-privilege-producer");
    data.AddUtf8(
        "tokenPrivilegeAdjustmentFallbackOwner",
        tokenPrivilegeTelemetryAvailable ? "none" : "etw-security-audit-or-kernel-token-provider");
    data.AddBool("r0ProcessHandleAccessTelemetryAvailable", processHandleAccessTelemetryAvailable);
    data.AddBool("r0ProcessHandleRightsTelemetryAvailable", processHandleAccessTelemetryAvailable);
    data.AddBool("r0ProcessHandleRequestedAccessAvailable", processHandleAccessTelemetryAvailable);
    data.AddBool("r0ProcessHandleGrantedAccessAvailable", processHandleAccessTelemetryAvailable);
    data.AddUtf8(
        "r0ProcessHandleAccessTelemetrySource",
        processHandleAccessTelemetryAvailable
            ? kR0ProcessHandleAccessTelemetrySourceDraft
            : kR0ProcessHandleAccessTelemetrySourceUnavailable);
    data.AddUtf8(
        "r0ProcessHandleAccessTelemetryStatus",
        processHandleAccessTelemetryAvailable ? "draft-capability-advertised" : "not-implemented");
    data.AddBool("handleAccessR0Direct", processHandleAccessTelemetryAvailable);
    data.AddBool("handleAccessEtwFallbackRequired", !processHandleAccessTelemetryAvailable);
    data.AddUtf8(
        "handleAccessObservation",
        processHandleAccessTelemetryAvailable ? "r0-direct-draft" : "etw-fallback-required");
    data.AddUtf8(
        "handleAccessObservationSource",
        processHandleAccessTelemetryAvailable
            ? kR0ProcessHandleAccessTelemetrySourceDraft
            : "etw-object-access-or-kernel-provider");
    data.AddUtf8(
        "handleAccessEtwFallbackReason",
        processHandleAccessTelemetryAvailable ? "none" : "not-implemented-no-obcallback-handle-access-producer");
    data.AddUtf8(
        "processHandleAccessFallbackOwner",
        processHandleAccessTelemetryAvailable ? "none" : "etw-object-access-or-kernel-obhandle-provider");
    data.AddBool("r0ThreadHandleAccessTelemetryAvailable", processHandleAccessTelemetryAvailable);
    data.AddBool("threadHandleAccessR0Direct", processHandleAccessTelemetryAvailable);
    data.AddBool("threadHandleAccessEtwFallbackRequired", !processHandleAccessTelemetryAvailable);
    data.AddUtf8(
        "threadHandleAccessObservation",
        processHandleAccessTelemetryAvailable ? "r0-direct-draft" : "etw-fallback-required");
    data.AddUtf8(
        "threadHandleAccessObservationSource",
        processHandleAccessTelemetryAvailable
            ? kR0ProcessHandleAccessTelemetrySourceDraft
            : "etw-object-access-or-kernel-obhandle-provider");
    data.AddUtf8(
        "threadHandleAccessFallbackOwner",
        processHandleAccessTelemetryAvailable ? "none" : "etw-object-access-or-kernel-obhandle-provider");
    data.AddBool("threadLifecycleR0Direct", false);
    data.AddBool("threadLifecycleFallbackRequired", true);
    data.AddUtf8("threadLifecycleFallbackOwner", "etw-kernel-thread-or-guest-api-trace");
    data.AddBool("remoteThreadCreationR0Direct", false);
    data.AddBool("remoteThreadCreationFallbackRequired", true);
    data.AddUtf8("remoteThreadCreationFallbackOwner", "etw-kernel-thread-or-guest-api-trace");
    data.AddUtf8("r0ProcessPrivilegeCoveragePolicy", kR0ProcessPrivilegeCoveragePolicy);
    data.AddUtf8("r0PrivilegeTelemetryFieldSet", kR0PrivilegeTelemetryFieldSet);
}

// Input: R0 direct-observation booleans for the producer families and draft
// handle/token telemetry surfaces.
// Processing: Emits a stable machine-readable contract that separates what the
// current R0 path observes directly from lanes that must be filled by ETW (or
// another explicitly documented side channel) instead of inferred from nearby
// process lifecycle evidence.
// Return: No return value; builder is mutated.
inline void AddR0EtwCapabilityContractFields(
    JsonDataObjectBuilder& data,
    const std::string& contractSource,
    const std::string& evidenceSource,
    const bool processCreateExitR0Direct,
    const bool imageLoadR0Direct,
    const bool fileActivityR0Direct,
    const bool registryActivityR0Direct,
    const bool networkActivityR0Direct,
    const bool processHandleAccessTelemetryAvailable = false,
    const bool tokenPrivilegeTelemetryAvailable = false) {
    std::string directScope;
    std::string fallbackScope;
    const auto appendScope = [](std::string& scope, const char* name) {
        if (!scope.empty()) {
            scope += "|";
        }
        scope += name;
    };
    const auto classifyScope = [&](const bool r0Direct, const char* name) {
        if (r0Direct) {
            appendScope(directScope, name);
        } else {
            appendScope(fallbackScope, name);
        }
    };

    classifyScope(processCreateExitR0Direct, "processCreateExit");
    classifyScope(imageLoadR0Direct, "imageLoad");
    classifyScope(fileActivityR0Direct, "fileActivity");
    classifyScope(registryActivityR0Direct, "registryActivity");
    classifyScope(networkActivityR0Direct, "networkActivity");
    classifyScope(processHandleAccessTelemetryAvailable, "handleAccess");
    classifyScope(tokenPrivilegeTelemetryAvailable, "tokenPrivilegeAdjustment");

    std::string gapCategories;
    const auto appendGap = [](std::string& gaps, const char* name) {
        if (!gaps.empty()) {
            gaps += "|";
        }
        gaps += name;
    };
    if (!processHandleAccessTelemetryAvailable) {
        appendGap(gapCategories, "process.handleAccess");
    }
    if (!tokenPrivilegeTelemetryAvailable) {
        appendGap(gapCategories, "token.privilegeAdjustment");
    }
    appendGap(gapCategories, "thread.lifecycle");
    appendGap(gapCategories, "thread.remoteCreation");
    appendGap(gapCategories, "token.objectHandles");
    appendGap(gapCategories, "service.control");
    appendGap(gapCategories, "driver.serviceLoadSemantics");
    appendGap(gapCategories, "network.rawPacketPayload");
    appendGap(gapCategories, "network.dnsPayload");
    appendGap(gapCategories, "network.httpPayload");
    appendGap(gapCategories, "network.tlsPayload");
    appendGap(gapCategories, "file.contentBytesAndHash");
    appendGap(gapCategories, "file.securityDescriptorBytes");
    appendGap(gapCategories, "registry.valueDataBytes");
    appendGap(gapCategories, "registry.securityDescriptorBytes");
    appendGap(gapCategories, "userModeCallStack");

    data.AddUnsigned("r0EtwCapabilityContractVersion", 1);
    data.AddUtf8("r0EtwCapabilityContractSource", contractSource);
    data.AddUtf8("r0EtwCapabilityContractEvidence", evidenceSource);
    data.AddUtf8("r0EtwCapabilityContractFieldSet", kR0EtwCapabilityContractFieldSet);
    data.AddUtf8("r0DirectObservationScope", directScope.empty() ? "none" : directScope);
    data.AddUtf8("etwFallbackRequiredScope", fallbackScope.empty() ? "none" : fallbackScope);
    data.AddBool("etwFallbackRequiredForR0Gaps", !fallbackScope.empty());
    data.AddUtf8("r0FallbackRequiredCategories", gapCategories.empty() ? "none" : gapCategories);
    data.AddUtf8(
        "r0FallbackOwners",
        "process.handleAccess=ETW/object-access;"
        "thread.lifecycle=ETW/kernel-thread-or-Guest/API-trace;"
        "thread.remoteCreation=ETW/kernel-thread-or-Guest/API-trace;"
        "token.privilegeAdjustment=ETW/security-audit;"
        "token.objectHandles=ETW/object-access;"
        "service.control=Guest/SCM-or-ETW;"
        "driver.serviceLoadSemantics=Guest/SCM-or-ETW;"
        "network.rawPacketPayload=PCAP/sidecar;"
        "network.dnsPayload=PCAP/DNS-sidecar;"
        "network.httpPayload=PCAP/HTTP-sidecar-or-browser;"
        "network.tlsPayload=PCAP/TLS-sidecar;"
        "file.contentBytesAndHash=Guest/artifact-hashing;"
        "file.securityDescriptorBytes=ETW/security-audit-or-Guest/artifact;"
        "registry.valueDataBytes=Guest/registry-snapshot-or-ETW;"
        "registry.securityDescriptorBytes=ETW/security-audit-or-Guest/registry-snapshot;"
        "userModeCallStack=ETW-or-Guest-instrumentation");
    data.AddUtf8(
        "r0ReadinessGapInterpretation",
        "coverage-gap-and-readiness-evidence-not-sample-verdict");
    data.AddUtf8(
        "r0EtwFallbackPolicy",
        "R0 emits advertised direct producer lanes; ETW fallback owns missing, disabled, or unimplemented lanes including handle access and token privilege adjustment unless draft R0 capability bits are advertised");

    const auto addDirectLane = [&data](const char* prefix, const bool r0Direct, const char* r0Source) {
        data.AddBool(std::string(prefix) + "R0Direct", r0Direct);
        data.AddUtf8(
            std::string(prefix) + "Observation",
            r0Direct ? "r0-direct" : "etw-fallback-required");
        data.AddUtf8(
            std::string(prefix) + "ObservationSource",
            r0Direct ? r0Source : "etw-fallback-required");
        data.AddBool(std::string(prefix) + "EtwFallbackRequired", !r0Direct);
        data.AddUtf8(
            std::string(prefix) + "EtwFallbackReason",
            r0Direct ? "none" : "r0-direct-capability-not-advertised-or-not-active");
    };

    addDirectLane("processCreateExit", processCreateExitR0Direct, "ps-process-create-notify");
    addDirectLane("imageLoad", imageLoadR0Direct, "ps-image-load-notify");
    data.AddBool("driverImageLoadMetadataR0Direct", imageLoadR0Direct);
    data.AddBool("driverServiceLoadSemanticsR0Direct", false);
    data.AddUtf8("driverServiceLoadFallbackOwner", "guest-service-control-manager-or-etw");
    addDirectLane("fileActivity", fileActivityR0Direct, "fltmgr-minifilter");
    data.AddBool("fileContentHashR0Direct", false);
    data.AddUtf8("fileContentHashFallbackOwner", "guest-artifact-hashing");
    addDirectLane("registryActivity", registryActivityR0Direct, "cm-registry-callback");
    data.AddBool("registryValueDataBytesR0Direct", false);
    data.AddUtf8("registryValueDataBytesFallbackOwner", "guest-registry-snapshot-or-etw");
    data.AddBool("serviceControlR0Direct", false);
    data.AddUtf8("serviceControlFallbackOwner", "guest-service-control-manager-or-etw");
    addDirectLane("networkActivity", networkActivityR0Direct, "wfp-ale-inspect-only");
    data.AddUtf8(
        "networkActivityR0Scope",
        networkActivityR0Direct ? "endpoint-metadata-only" : "none");
    data.AddBool("networkProtocolPayloadR0Direct", false);
    data.AddBool("networkProtocolPayloadFallbackRequired", true);
    data.AddUtf8("networkProtocolPayloadFallbackOwner", "pcap-sidecar-or-etw");
    data.AddBool("dnsPayloadR0Direct", false);
    data.AddUtf8("dnsPayloadFallbackOwner", "pcap-dns-or-sidecar");
    data.AddBool("httpPayloadR0Direct", false);
    data.AddUtf8("httpPayloadFallbackOwner", "pcap-http-browser-or-sidecar");
    data.AddBool("tlsPayloadR0Direct", false);
    data.AddUtf8("tlsPayloadFallbackOwner", "pcap-tls-or-sidecar");

    AddR0PrivilegeProcessAccessCoverageFields(
        data,
        processHandleAccessTelemetryAvailable,
        tokenPrivilegeTelemetryAvailable);
}

inline void AddCurrentR0EtwCapabilityContractFields(
    JsonDataObjectBuilder& data,
    const std::string& contractSource,
    const std::string& evidenceSource) {
    AddR0EtwCapabilityContractFields(
        data,
        contractSource,
        evidenceSource,
        (KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT & KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT) != 0 &&
            (KSWORD_SANDBOX_PRODUCER_MASK_CURRENT & KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS) != 0,
        (KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT & KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD) != 0 &&
            (KSWORD_SANDBOX_PRODUCER_MASK_CURRENT & KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE) != 0,
        (KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT & KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER) != 0 &&
            (KSWORD_SANDBOX_PRODUCER_MASK_CURRENT & KSWORD_SANDBOX_PRODUCER_FLAG_FILE) != 0,
        (KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT & KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK) != 0 &&
            (KSWORD_SANDBOX_PRODUCER_MASK_CURRENT & KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY) != 0,
        (KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT & KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE) != 0 &&
            (KSWORD_SANDBOX_PRODUCER_MASK_CURRENT & KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK) != 0,
        (KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT & KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_HANDLE_ACCESS_DRAFT) != 0,
        (KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT & KSWORD_SANDBOX_CAPABILITY_FLAG_TOKEN_PRIVILEGE_DRAFT) != 0);
}

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
