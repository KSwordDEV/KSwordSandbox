#pragma once

#include "Common.h"
#include "JsonWriter.h"

#include <string>

namespace KSword::Sandbox::R0Collector {

struct DriverEventAttribution {
    std::string eventOrigin = "kernel-driver";
    std::string producerCategory = "unknown";
    std::string subjectKind = "unknown";
    std::string actorRole = "sample-or-system";
    std::string subjectRole = "sample-or-system";
    std::string processIdSource = "eventHeader";
    std::string collectorNoisePolicy = "suppress-self-noise";
    std::string selfNoiseReason = "none";
    std::string selfNoiseAction = "emit";
    bool selfNoise = false;
    bool suppressed = false;
};

std::string DriverEventJsonType(ULONG eventType);
std::string DriverEventTypeName(ULONG eventType);
std::wstring ExtractTypedPayloadPath(ULONG eventType, const unsigned char* payload, size_t payloadBytes);
std::wstring ExtractTypedPayloadCommandLine(ULONG eventType, const unsigned char* payload, size_t payloadBytes);
std::wstring ExtractTypedPayloadProcessName(ULONG eventType, const unsigned char* payload, size_t payloadBytes);
unsigned long long ExtractTypedPayloadProcessId(
    ULONG eventType,
    const unsigned char* payload,
    size_t payloadBytes,
    unsigned long long fallbackProcessId);
std::string BuildHealthData(const KSWORD_SANDBOX_HEALTH_REPLY& reply, DWORD bytesReturned);
std::string BuildCapabilitiesData(const KSWORD_SANDBOX_CAPABILITIES_REPLY& reply, DWORD bytesReturned);
std::string BuildStatusData(const KSWORD_SANDBOX_STATUS_REPLY& reply, DWORD bytesReturned);
std::string BuildSetProducerEnableMaskData(
    const KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY& reply,
    DWORD bytesReturned,
    ULONG requestedEnableMask);
std::string BuildPollData(const KSWORD_SANDBOX_POLL_REPLY& reply, DWORD bytesReturned);
std::string BuildReadEventsBatchData(
    const KSWORD_SANDBOX_READ_EVENTS_REPLY& reply,
    DWORD bytesReturned,
    unsigned long requestedMaxEvents,
    unsigned long long eventsEmitted,
    unsigned long long recordsProcessed,
    unsigned long long collectorSuppressedEvents,
    bool suppressSelfNoise);
std::string BuildDriverEventData(
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    unsigned long long batchIndex,
    unsigned long long batchOffset,
    const unsigned char* payload,
    size_t payloadBytes,
    const DriverEventAttribution& attribution);

} // namespace KSword::Sandbox::R0Collector
