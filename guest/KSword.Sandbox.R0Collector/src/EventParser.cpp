#include "EventParser.h"

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <sstream>
#include <string>

namespace KSword::Sandbox::R0Collector {

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

// Input: Flag bits from KSWORD_SANDBOX_EVENT_HEADER.Flags.
// Processing: Decodes currently public flag bits and preserves unknown bits as a
// hexadecimal suffix so newer drivers remain diagnosable by older collectors.
// Return: Human-readable ASCII flag names, or "none" when no bits are set.
std::string DriverEventFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;

    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST) != 0) {
        appendName("SelfTest");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED) != 0) {
        appendName("DriverStarted");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT) != 0) {
        appendName("OperationPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT) != 0) {
        appendName("StatusPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT) != 0) {
        appendName("TargetPidPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_PARENT_PID_PRESENT) != 0) {
        appendName("ParentPidPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_PARENT_PID_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT) != 0) {
        appendName("SubjectPathPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT) != 0) {
        appendName("LostCountPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT) != 0) {
        appendName("BackpressureCountPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_PRODUCER_METADATA_PRESENT) != 0) {
        appendName("ProducerMetadataPresent");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_PRODUCER_METADATA_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE) != 0) {
        appendName("SelfNoise");
        knownFlags |= KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE;
    }

    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }

    return names.empty() ? "none" : names;
}

// Input: GET_HEALTH flag bits.
// Processing: Names the optional IOCTL and queue-state bits exposed by the
// public health reply while preserving unknown bits for forward compatibility.
// Return: Pipe-delimited flag names, or "none".
std::string HealthFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_HEALTH_FLAG_HAS_EVENTS) != 0) {
        appendName("HasEvents");
        knownFlags |= KSWORD_SANDBOX_HEALTH_FLAG_HAS_EVENTS;
    }
    if ((flags & KSWORD_SANDBOX_HEALTH_FLAG_CAPABILITIES_AVAILABLE) != 0) {
        appendName("CapabilitiesAvailable");
        knownFlags |= KSWORD_SANDBOX_HEALTH_FLAG_CAPABILITIES_AVAILABLE;
    }
    if ((flags & KSWORD_SANDBOX_HEALTH_FLAG_STATUS_AVAILABLE) != 0) {
        appendName("StatusAvailable");
        knownFlags |= KSWORD_SANDBOX_HEALTH_FLAG_STATUS_AVAILABLE;
    }
    if ((flags & KSWORD_SANDBOX_HEALTH_FLAG_ENABLE_MASK_AVAILABLE) != 0) {
        appendName("EnableMaskAvailable");
        knownFlags |= KSWORD_SANDBOX_HEALTH_FLAG_ENABLE_MASK_AVAILABLE;
    }
    if ((flags & KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE) != 0) {
        appendName("ProducerMasksAvailable");
        knownFlags |= KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE;
    }

    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: GET_STATUS flag bits.
// Processing: Names queue/producers/last-status bits from the status reply.
// Return: Pipe-delimited flag names, or "none".
std::string StatusFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_HAS_EVENTS) != 0) {
        appendName("HasEvents");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_HAS_EVENTS;
    }
    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_PARTIAL) != 0) {
        appendName("ProducersPartial");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_PARTIAL;
    }
    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_ALL_DISABLED) != 0) {
        appendName("ProducersAllDisabled");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_ALL_DISABLED;
    }
    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_LAST_STATUS_FAILURE) != 0) {
        appendName("LastStatusFailure");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_LAST_STATUS_FAILURE;
    }
    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE) != 0) {
        appendName("QueueBackpressure");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE;
    }
    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_EVENTS_DROPPED) != 0) {
        appendName("EventsDropped");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_EVENTS_DROPPED;
    }
    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_EVENTS_SUPPRESSED) != 0) {
        appendName("EventsSuppressed");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_EVENTS_SUPPRESSED;
    }
    if ((flags & KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_DEGRADED) != 0) {
        appendName("ProducersDegraded");
        knownFlags |= KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_DEGRADED;
    }

    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: Capability flag mask returned by GET_CAPABILITIES.
// Processing: Names public optional IOCTL/schema flags and preserves unknowns.
// Return: Pipe-delimited flag names, or "none".
std::string CapabilityFlagNames(const ULONGLONG flags) {
    std::string names;
    ULONGLONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH) != 0) {
        appendName("GetHealth");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_POLL) != 0) {
        appendName("Poll");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_POLL;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS) != 0) {
        appendName("ReadEvents");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES) != 0) {
        appendName("GetCapabilities");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS) != 0) {
        appendName("GetStatus");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK) != 0) {
        appendName("SetProducerEnableMask");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS) != 0) {
        appendName("QueueStatusCounters");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS) != 0) {
        appendName("ProducerEnableBits");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS) != 0) {
        appendName("TypedEventPayloads");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES) != 0) {
        appendName("EventSchemaNames");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT) != 0) {
        appendName("ProcessCreateExit");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD) != 0) {
        appendName("ImageLoad");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER) != 0) {
        appendName("FileMinifilter");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK) != 0) {
        appendName("RegistryCallback");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE) != 0) {
        appendName("NetworkWfpAle");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_COMMON_METADATA) != 0) {
        appendName("EventCommonMetadata");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_COMMON_METADATA;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_METADATA) != 0) {
        appendName("ProducerMetadata");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_METADATA;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_SELF_NOISE_METADATA) != 0) {
        appendName("SelfNoiseMetadata");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_SELF_NOISE_METADATA;
    }
    if ((flags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS) != 0) {
        appendName("GetNetworkStatus");
        knownFlags |= KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS;
    }

    const ULONGLONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 16) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: Implementation level from KSWORD_SANDBOX_NETWORK_STATUS_REPLY.
// Processing: Names the current network/WFP implementation tier without
// implying packet-layer or protocol parser support.
// Return: Stable ASCII implementation name.
std::string NetworkImplementationLevelName(const ULONG implementationLevel) {
    switch (implementationLevel) {
    case KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_NONE:
        return "none";
    case KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_ALE_INSPECT_ONLY:
        return "ale-inspect-only";
    default:
        return "unrecognized";
    }
}

// Input: GET_NETWORK_STATUS flag bits.
// Processing: Names public WFP/ALE readiness bits and preserves unknown bits
// for forward-compatible diagnostics.
// Return: Pipe-delimited flag names, or "none".
std::string NetworkStatusFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_COMPILED) != 0) {
        appendName("Compiled");
        knownFlags |= KSWORD_SANDBOX_NETWORK_STATUS_FLAG_COMPILED;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_ACTIVE) != 0) {
        appendName("Active");
        knownFlags |= KSWORD_SANDBOX_NETWORK_STATUS_FLAG_ACTIVE;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_DEGRADED) != 0) {
        appendName("Degraded");
        knownFlags |= KSWORD_SANDBOX_NETWORK_STATUS_FLAG_DEGRADED;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_INSPECT_ONLY) != 0) {
        appendName("InspectOnly");
        knownFlags |= KSWORD_SANDBOX_NETWORK_STATUS_FLAG_INSPECT_ONLY;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_QUEUE_FAILURE) != 0) {
        appendName("QueueFailure");
        knownFlags |= KSWORD_SANDBOX_NETWORK_STATUS_FLAG_QUEUE_FAILURE;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_CLASSIFY_PAYLOAD_FAILURE) != 0) {
        appendName("ClassifyPayloadFailure");
        knownFlags |= KSWORD_SANDBOX_NETWORK_STATUS_FLAG_CLASSIFY_PAYLOAD_FAILURE;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_COMPILE_TIME_DISABLED) != 0) {
        appendName("CompileTimeDisabled");
        knownFlags |= KSWORD_SANDBOX_NETWORK_STATUS_FLAG_COMPILE_TIME_DISABLED;
    }

    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: WFP/ALE layer mask returned by GET_NETWORK_STATUS.
// Processing: Names the public ALE v4/v6 connect/recv-accept bits and keeps
// unknown future layers visible.
// Return: Pipe-delimited layer names, or "none".
std::string NetworkLayerMaskNames(const ULONG mask) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V4) != 0) {
        appendName("AleConnectV4");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V4;
    }
    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V4) != 0) {
        appendName("AleRecvAcceptV4");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V4;
    }
    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V6) != 0) {
        appendName("AleConnectV6");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V6;
    }
    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V6) != 0) {
        appendName("AleRecvAcceptV6");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V6;
    }

    const ULONG unknownFlags = mask & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: WFP/ALE TODO mask returned by GET_NETWORK_STATUS.
// Processing: Names intentional capability gaps so report/readiness consumers
// can distinguish ALE inspect-only telemetry from missing runtime state.
// Return: Pipe-delimited gap names, or "none".
std::string NetworkTodoMaskNames(const ULONG mask) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PACKET_STREAM_LAYERS) != 0) {
        appendName("PacketStreamLayers");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PACKET_STREAM_LAYERS;
    }
    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FLOW_CONTEXTS) != 0) {
        appendName("FlowContexts");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FLOW_CONTEXTS;
    }
    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FILTER_CONDITIONS) != 0) {
        appendName("FilterConditions");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FILTER_CONDITIONS;
    }
    if ((mask & KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PROTOCOL_PAYLOADS) != 0) {
        appendName("ProtocolPayloads");
        knownFlags |= KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PROTOCOL_PAYLOADS;
    }

    const ULONG unknownFlags = mask & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: KSWORD_SANDBOX_NETWORK_STATUS_DEGRADE_REASON value.
// Processing: Maps public degradation reasons to stable text for diagnostics.
// Return: Stable ASCII reason name.
std::string NetworkDegradeReasonName(const LONG reason) {
    switch (reason) {
    case KswSandboxNetworkStatusDegradeNone:
        return "none";
    case KswSandboxNetworkStatusDegradeCompileTimeDisabled:
        return "compile-time-disabled";
    case KswSandboxNetworkStatusDegradeFwpsCalloutRegister:
        return "fwps-callout-register";
    case KswSandboxNetworkStatusDegradeFwpmEngineOpen:
        return "fwpm-engine-open";
    case KswSandboxNetworkStatusDegradeFwpmTransaction:
        return "fwpm-transaction";
    case KswSandboxNetworkStatusDegradeFwpmSublayer:
        return "fwpm-sublayer";
    case KswSandboxNetworkStatusDegradeFwpmManagementCallout:
        return "fwpm-management-callout";
    case KswSandboxNetworkStatusDegradeFwpmInspectionFilter:
        return "fwpm-inspection-filter";
    case KswSandboxNetworkStatusDegradeClassifyPayload:
        return "classify-payload";
    case KswSandboxNetworkStatusDegradeQueuePush:
        return "queue-push";
    default:
        return "unrecognized";
    }
}

// Input: Derived network readiness state.
// Processing: Provides Chinese operator wording while keeping stable machine
// fields English.
// Return: UTF-16 Chinese message suitable for zhMessage.
std::wstring NetworkStatusZhMessage(const bool active, const bool degraded, const bool compileTimeDisabled) {
    if (compileTimeDisabled) {
        return L"R0 网络 WFP/ALE producer 在当前驱动构建中被编译期禁用；该行是采集能力诊断，不代表样本行为。";
    }

    if (degraded) {
        return L"R0 网络 WFP/ALE producer 可诊断但处于降级状态；请查看 mask、计数器和 NTSTATUS 字段。";
    }

    if (active) {
        return L"R0 网络 WFP/ALE producer 已处于活动状态；当前仍是 ALE inspect-only 诊断能力。";
    }

    return L"R0 网络 WFP/ALE producer 已编译但当前未处于活动状态；该行用于 readiness 诊断。";
}

// Input: GET_NETWORK_STATUS TODO mask and readiness bits.
// Processing: Provides concrete Chinese remediation guidance for operators.
// Return: UTF-16 Chinese hint.
std::wstring NetworkStatusZhHint(const bool active, const bool degraded, const bool compileTimeDisabled, const ULONG todoMask) {
    if (compileTimeDisabled) {
        return L"请使用启用 WFP/ALE producer 的驱动构建，并确认 WDK/WFP 依赖可用；Collector 会继续采集其他 R0 producer。";
    }

    if (degraded) {
        return L"请优先检查 lastDegradeReasonName、registerNtStatusHex、engineNtStatusHex、lastQueueFailureNtStatusHex，以及 active/registered/filter layer mask。";
    }

    if (todoMask != 0) {
        return L"TodoMask 表示当前仅覆盖 ALE inspect-only；packet/stream、flow context、filter condition 和协议 payload 解析仍由 sidecar/PCAP 路径补足。";
    }

    if (!active) {
        return L"若需要网络 R0 事件，请确认 network producer 已启用、驱动初始化 WFP 成功，并在 VM 内产生连接活动。";
    }

    return L"请结合 driver.network 事件、PCAP/sidecar 归一化和该状态行的计数器判断网络证据覆盖面。";
}

// Input: Producer enable/support mask bits.
// Processing: Names public producer categories and keeps unknown bits visible.
// Return: Pipe-delimited producer names, or "none".
std::string ProducerMaskNames(const ULONG mask) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((mask & KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER) != 0) {
        appendName("driver");
        knownFlags |= KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER;
    }
    if ((mask & KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS) != 0) {
        appendName("process");
        knownFlags |= KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS;
    }
    if ((mask & KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE) != 0) {
        appendName("image");
        knownFlags |= KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE;
    }
    if ((mask & KSWORD_SANDBOX_PRODUCER_FLAG_FILE) != 0) {
        appendName("file");
        knownFlags |= KSWORD_SANDBOX_PRODUCER_FLAG_FILE;
    }
    if ((mask & KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY) != 0) {
        appendName("registry");
        knownFlags |= KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY;
    }
    if ((mask & KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK) != 0) {
        appendName("network");
        knownFlags |= KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK;
    }

    const ULONG unknownFlags = mask & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: Supported/enabled/active/failed producer masks from driver replies.
// Processing: Classifies the runtime producer lane without hiding the raw masks.
// Return: Stable readiness label for producer runtime diagnostics.
std::string ProducerRuntimeState(
    const ULONG supportedMask,
    const ULONG enabledMask,
    const ULONG activeMask,
    const ULONG failedMask) {
    const ULONG supportedEnabledMask = supportedMask & enabledMask;
    const ULONG activeEnabledMask = activeMask & supportedEnabledMask;
    const ULONG failedEnabledMask = failedMask & supportedEnabledMask;

    if (supportedMask == 0) {
        return "unsupported";
    }

    if (supportedEnabledMask == 0) {
        return "all-disabled";
    }

    if (failedEnabledMask != 0) {
        return activeEnabledMask == 0 ? "failed" : "degraded";
    }

    if (activeEnabledMask != supportedEnabledMask) {
        return "degraded";
    }

    return "ready";
}

// Input: A producer runtime state label.
// Processing: Provides a compact Chinese operator hint while keeping the
// machine-readable state English and stable.
// Return: UTF-16 Chinese text suitable for JSONL zh* fields.
std::wstring ProducerRuntimeZhHint(const std::string& state) {
    if (state == "ready") {
        return L"已启用的 R0 producer 均处于活动状态。";
    }

    if (state == "degraded") {
        return L"部分已启用的 R0 producer 未处于活动状态或曾经初始化失败；请查看 active/failed/effective producer mask。";
    }

    if (state == "failed") {
        return L"已启用的 R0 producer 没有活动项或初始化失败；请查看 failedProducerMask 和 lastFailureNtStatus。";
    }

    if (state == "all-disabled") {
        return L"当前 producer enable mask 禁用了所有受支持 producer；不会产生新的驱动事件。";
    }

    if (state == "legacy-unavailable") {
        return L"当前驱动/回复未提供 producer runtime mask 字段；请升级到匹配的驱动和 Collector 以获得完整诊断。";
    }

    return L"当前构建未报告受支持的 R0 producer。";
}

// Input: Producer masks and a flag indicating whether the reply actually
// returned those fields.
// Processing: Adds derived runtime-state diagnostics beside the raw masks so
// operators do not have to infer active/failed/effective state by hand.
// Return: No return value; the JSON builder is mutated.
void AddProducerRuntimeStateData(
    JsonDataObjectBuilder& data,
    const bool masksAvailable,
    const ULONG supportedMask,
    const ULONG enabledMask,
    const ULONG activeMask,
    const ULONG failedMask) {
    if (!masksAvailable) {
        data.AddUtf8("producerRuntimeState", "legacy-unavailable");
        data.AddWide("zhProducerRuntimeHint", ProducerRuntimeZhHint("legacy-unavailable"));
        data.AddUnsigned("producerRuntimeEffectiveMask", 0);
        data.AddUtf8("producerRuntimeEffectiveMaskHex", HexUnsignedLongLong(0, 8));
        data.AddUtf8("producerRuntimeEffectiveMaskNames", ProducerMaskNames(0));
        return;
    }

    const ULONG supportedEnabledMask = supportedMask & enabledMask;
    const ULONG activeEnabledMask = activeMask & supportedEnabledMask;
    const ULONG failedEnabledMask = failedMask & supportedEnabledMask;
    const std::string state =
        ProducerRuntimeState(supportedMask, enabledMask, activeMask, failedMask);

    data.AddUtf8("producerRuntimeState", state);
    data.AddWide("zhProducerRuntimeHint", ProducerRuntimeZhHint(state));
    data.AddUnsigned("enabledSupportedProducerMask", supportedEnabledMask);
    data.AddUtf8("enabledSupportedProducerMaskHex", HexUnsignedLongLong(supportedEnabledMask, 8));
    data.AddUtf8("enabledSupportedProducerMaskNames", ProducerMaskNames(supportedEnabledMask));
    data.AddUnsigned("activeEnabledProducerMask", activeEnabledMask);
    data.AddUtf8("activeEnabledProducerMaskHex", HexUnsignedLongLong(activeEnabledMask, 8));
    data.AddUtf8("activeEnabledProducerMaskNames", ProducerMaskNames(activeEnabledMask));
    data.AddUnsigned("failedEnabledProducerMask", failedEnabledMask);
    data.AddUtf8("failedEnabledProducerMaskHex", HexUnsignedLongLong(failedEnabledMask, 8));
    data.AddUtf8("failedEnabledProducerMaskNames", ProducerMaskNames(failedEnabledMask));
    data.AddUnsigned("producerRuntimeEffectiveMask", activeEnabledMask);
    data.AddUtf8("producerRuntimeEffectiveMaskHex", HexUnsignedLongLong(activeEnabledMask, 8));
    data.AddUtf8("producerRuntimeEffectiveMaskNames", ProducerMaskNames(activeEnabledMask));
    data.AddBool("producerRuntimeDegraded", state == "degraded" || state == "failed");
}

// Input: KSWORD_SANDBOX_EVENT_HEADER.ProducerMetadataFlags.
// Processing: Decodes public producer metadata flags and preserves unknown bits.
// Return: Pipe-delimited flag names, or "none".
std::string ProducerMetadataFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;

    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE) != 0) {
        appendName("SelfNoise");
        knownFlags |= KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE;
    }

    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }

    return names.empty() ? "none" : names;
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

// Input: File operation value from KSWORD_SANDBOX_FILE_EVENT_PAYLOAD.Operation.
// Processing: Converts the stable ABI enum into a compact lowercase label for
// WebUI live event display, rule diagnostics, and raw report inspection.
// Return: ASCII operation name; unknown numeric values are preserved elsewhere
// by the caller and represented here as "unrecognized".
std::string FileOperationName(const ULONG operation) {
    switch (operation) {
    case KswSandboxFileOperationNone:
        return "none";
    case KswSandboxFileOperationCreate:
        return "create";
    case KswSandboxFileOperationWrite:
        return "write";
    case KswSandboxFileOperationSetInformation:
        return "setInformation";
    case KswSandboxFileOperationDelete:
        return "delete";
    case KswSandboxFileOperationCleanup:
        return "cleanup";
    case KswSandboxFileOperationClose:
        return "close";
    case KswSandboxFileOperationRead:
        return "read";
    case KswSandboxFileOperationRename:
        return "rename";
    default:
        return "unrecognized";
    }
}

// Input: File event flag bits from KSWORD_SANDBOX_FILE_EVENT_PAYLOAD.Flags.
// Processing: Decodes public bits and keeps any newer unknown bits visible as a
// hexadecimal suffix so older collectors remain useful with newer drivers.
// Return: Human-readable ASCII flag names, or "none" when no bits are set.
std::string FileEventFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;

    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT) != 0) {
        appendName("PathPresent");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED) != 0) {
        appendName("PathTruncated");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT) != 0) {
        appendName("StatusPresent");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_POST_OPERATION) != 0) {
        appendName("PostOperation");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_POST_OPERATION;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED) != 0) {
        appendName("PathNormalized");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK) != 0) {
        appendName("PathFallback");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_OPERATION_FAILED) != 0) {
        appendName("OperationFailed");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_OPERATION_FAILED;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_DELETE_INTENT) != 0) {
        appendName("DeleteIntent");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_DELETE_INTENT;
    }

    if ((flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_RENAME_INTENT) != 0) {
        appendName("RenameIntent");
        knownFlags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_RENAME_INTENT;
    }

    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }

    return names.empty() ? "none" : names;
}

// Input: Fixed UTF-16 file path buffer and a byte length supplied by the driver.
// Processing: Clamps the byte length to the public fixed buffer, rounds down to
// whole WCHARs, and stops at the first embedded NUL to avoid over-reading stale
// stack bytes from malformed or future payloads.
// Return: Decoded UTF-16 string; empty means no bounded path could be decoded.
std::wstring BoundedWideStringFromUtf16Bytes(
    const WCHAR* value,
    const ULONG lengthBytes,
    const size_t capacityChars) {
    if (value == nullptr || lengthBytes == 0 || capacityChars == 0) {
        return {};
    }

    const size_t capacityBytes = capacityChars * sizeof(WCHAR);
    const size_t clampedBytes =
        std::min(static_cast<size_t>(lengthBytes), capacityBytes);
    const size_t clampedChars = clampedBytes / sizeof(WCHAR);

    size_t lengthChars = 0;
    while (lengthChars < clampedChars && value[lengthChars] != L'\0') {
        ++lengthChars;
    }

    return std::wstring(value, value + lengthChars);
}

// Input: File payload bytes from a KswSandboxEventTypeFile record.
// Processing: Validates the public payload size and decodes the bounded path
// only when the PathPresent flag is set.
// Return: File path for top-level SandboxEvent.path, or empty on malformed /
// path-less records.
std::wstring ExtractFilePayloadPath(
    const unsigned char* payload,
    const size_t payloadBytes) {
    if (payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)) {
        return {};
    }

    const auto* filePayload =
        reinterpret_cast<const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD*>(payload);
    if ((filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT) == 0) {
        return {};
    }

    return BoundedWideStringFromUtf16Bytes(
        filePayload->Path,
        filePayload->PathLengthBytes,
        KSWORD_SANDBOX_FILE_EVENT_PATH_CHARS);
}

// Input: Process operation value from KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD.
// Processing: Converts the stable ABI enum into a compact lowercase label.
// Return: ASCII operation name for data.operationName.
std::string ProcessOperationName(const ULONG operation) {
    switch (operation) {
    case KswSandboxProcessOperationNone:
        return "none";
    case KswSandboxProcessOperationCreate:
        return "create";
    case KswSandboxProcessOperationExit:
        return "exit";
    default:
        return "unrecognized";
    }
}

// Input: Registry operation value from KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD.
// Processing: Converts public enum values into report-friendly names.
// Return: ASCII operation name for registry data.
std::string RegistryOperationName(const ULONG operation) {
    switch (operation) {
    case KswSandboxRegistryOperationNone:
        return "none";
    case KswSandboxRegistryOperationCreateKey:
        return "createKey";
    case KswSandboxRegistryOperationOpenKey:
        return "openKey";
    case KswSandboxRegistryOperationSetValue:
        return "setValue";
    case KswSandboxRegistryOperationDeleteValue:
        return "deleteValue";
    case KswSandboxRegistryOperationDeleteKey:
        return "deleteKey";
    case KswSandboxRegistryOperationRenameKey:
        return "renameKey";
    default:
        return "unrecognized";
    }
}

// Input: Network direction value from KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD.
// Processing: Converts the compact numeric ABI value into a stable label.
// Return: ASCII direction name.
std::string NetworkDirectionName(const ULONG direction) {
    switch (direction) {
    case KswSandboxNetworkDirectionUnknown:
        return "unknown";
    case KswSandboxNetworkDirectionOutbound:
        return "outbound";
    case KswSandboxNetworkDirectionInbound:
        return "inbound";
    default:
        return "unrecognized";
    }
}

// Input: Network address family value from KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD.
// Processing: Converts public address-family constants into stable labels.
// Return: ASCII family name.
std::string NetworkAddressFamilyName(const ULONG addressFamily) {
    switch (addressFamily) {
    case KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_UNKNOWN:
        return "unknown";
    case KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV4:
        return "ipv4";
    case KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV6:
        return "ipv6";
    default:
        return "unrecognized";
    }
}

// Input: IP protocol number from a network payload.
// Processing: Names common protocols while preserving the numeric field.
// Return: ASCII protocol name.
std::string NetworkProtocolName(const ULONG protocol) {
    switch (protocol) {
    case KSWORD_SANDBOX_NETWORK_PROTOCOL_ANY:
        return "any";
    case KSWORD_SANDBOX_NETWORK_PROTOCOL_ICMP:
        return "icmp";
    case KSWORD_SANDBOX_NETWORK_PROTOCOL_TCP:
        return "tcp";
    case KSWORD_SANDBOX_NETWORK_PROTOCOL_UDP:
        return "udp";
    case KSWORD_SANDBOX_NETWORK_PROTOCOL_ICMPV6:
        return "icmpv6";
    default:
        return "unrecognized";
    }
}

// Input: Image operation value from KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD.
// Processing: Converts the compact public enum into a report-friendly label.
// Return: ASCII operation name for image data.
std::string ImageOperationName(const ULONG operation) {
    switch (operation) {
    case KswSandboxImageOperationNone:
        return "none";
    case KswSandboxImageOperationLoad:
        return "load";
    default:
        return "unrecognized";
    }
}

// Input: Network operation value from KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD.
// Processing: Converts the compact public enum into a report-friendly label.
// Return: ASCII operation name for network data.
std::string NetworkOperationName(const ULONG operation) {
    switch (operation) {
    case KswSandboxNetworkOperationNone:
        return "none";
    case KswSandboxNetworkOperationAleAuthorize:
        return "aleAuthorize";
    default:
        return "unrecognized";
    }
}

// Input: Driver event type and common-header operation value.
// Processing: Applies the typed operation enum for known producer families so
// short/future payloads can still expose a stable operationName from the header.
// Return: Operation label, or "unrecognized" for unknown families/values.
std::string DriverOperationName(const ULONG eventType, const ULONG operation) {
    switch (eventType) {
    case KswSandboxEventTypeDriverLoad:
        return operation == KswSandboxEventTypeDriverLoad ? "load" : "unrecognized";
    case KswSandboxEventTypeProcess:
        return ProcessOperationName(operation);
    case KswSandboxEventTypeImage:
        return ImageOperationName(operation);
    case KswSandboxEventTypeFile:
        return FileOperationName(operation);
    case KswSandboxEventTypeRegistry:
        return RegistryOperationName(operation);
    case KswSandboxEventTypeNetwork:
        return NetworkOperationName(operation);
    default:
        return "unrecognized";
    }
}

// Input: UTF-16 text and a UTF-16 fragment.
// Processing: Performs a case-insensitive containment check without filesystem
// access so event semantics can be derived from bounded payload text safely.
// Return: true when the fragment appears in the value.
bool ContainsWideInsensitive(std::wstring value, std::wstring fragment) {
    if (value.empty() || fragment.empty()) {
        return false;
    }

    std::replace(value.begin(), value.end(), L'/', L'\\');
    std::replace(fragment.begin(), fragment.end(), L'/', L'\\');
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(ch)));
        });
    std::transform(
        fragment.begin(),
        fragment.end(),
        fragment.begin(),
        [](const wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(ch)));
        });

    return value.find(fragment) != std::wstring::npos;
}

// Input: Registry key path decoded from the public payload.
// Processing: Labels common Windows autorun locations as persistence candidates
// for report/storytelling evidence without treating them as a final verdict.
// Return: true when the key path resembles a common autostart location.
bool RegistryPersistenceCandidate(const std::wstring& keyPath) {
    return ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\run") ||
        ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\runonce") ||
        ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run") ||
        ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows nt\\currentversion\\winlogon") ||
        ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows nt\\currentversion\\image file execution options") ||
        ContainsWideInsensitive(keyPath, L"\\system\\currentcontrolset\\services") ||
        ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\explorer\\startupapproved");
}

// Input: Registry key path already decoded from a compact payload.
// Processing: Names the persistence family without turning the row into a
// verdict. Rules and reports can explain why the key deserves attention.
// Return: Stable family label or "none".
std::string RegistryPersistenceFamily(const std::wstring& keyPath) {
    if (ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\run") ||
        ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\runonce") ||
        ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run")) {
        return "autorun-run-key";
    }

    if (ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows nt\\currentversion\\winlogon")) {
        return "winlogon-shell-userinit";
    }

    if (ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows nt\\currentversion\\image file execution options")) {
        return "ifeo-debugger";
    }

    if (ContainsWideInsensitive(keyPath, L"\\system\\currentcontrolset\\services")) {
        return "service-configuration";
    }

    if (ContainsWideInsensitive(keyPath, L"\\software\\microsoft\\windows\\currentversion\\explorer\\startupapproved")) {
        return "startup-approved";
    }

    return "none";
}

// Input: Decoded file path.
// Processing: Tags common dropper locations for report cards/rules while
// keeping the event evidence-level, not a maliciousness verdict.
// Return: Stable family label.
std::string FileDropLocationFamily(const std::wstring& filePath) {
    if (filePath.empty()) {
        return "unknown";
    }

    if (ContainsWideInsensitive(filePath, L"\\appdata\\local\\temp\\") ||
        ContainsWideInsensitive(filePath, L"\\windows\\temp\\") ||
        ContainsWideInsensitive(filePath, L"\\temp\\")) {
        return "temp-directory";
    }

    if (ContainsWideInsensitive(filePath, L"\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup")) {
        return "startup-folder";
    }

    if (ContainsWideInsensitive(filePath, L"\\users\\public\\") ||
        ContainsWideInsensitive(filePath, L"\\programdata\\")) {
        return "shared-writable-directory";
    }

    if (ContainsWideInsensitive(filePath, L"\\windows\\system32\\") ||
        ContainsWideInsensitive(filePath, L"\\windows\\syswow64\\")) {
        return "system-directory";
    }

    return "other";
}

// Input: Decoded image path.
// Processing: Flags suspicious DLL/image loading contexts that are useful in a
// report process tree and behavior rules without claiming injection by itself.
// Return: Stable family label.
std::string ImageLoadFamily(const std::wstring& imagePath, const bool systemModeImage) {
    if (systemModeImage) {
        return "kernel-or-driver-image";
    }

    if (ContainsWideInsensitive(imagePath, L"\\appdata\\") ||
        ContainsWideInsensitive(imagePath, L"\\temp\\") ||
        ContainsWideInsensitive(imagePath, L"\\programdata\\")) {
        return "user-writable-image";
    }

    if (ContainsWideInsensitive(imagePath, L"\\windows\\system32\\") ||
        ContainsWideInsensitive(imagePath, L"\\windows\\syswow64\\")) {
        return "windows-system-image";
    }

    return imagePath.empty() ? "unknown" : "other";
}

// Input: A typed operation name.
// Processing: Normalizes the semantic family and operation into a compact
// report/rule field.
// Return: family.operation when operation is known, otherwise family.unknown.
std::string ActivityKind(const std::string& family, const std::string& operationName) {
    return family + "." + (operationName.empty() ? "unknown" : operationName);
}

// Input: Driver event sequence and JSON builder.
// Processing: Emits stable concrete-event sequence semantics before verbose ABI
// fields so report sampling keeps the meaning beside the sequence value.
// Return: No return value; builder is mutated.
void AddConcreteEventSequenceSemantics(
    JsonDataObjectBuilder& data,
    const unsigned long long sequence) {
    data.AddUnsigned("sequence", sequence);
    data.AddUtf8("sequenceMeaning", "eventSequence");
    data.AddUtf8("sequenceScope", "driver-event");
    data.AddBool("sequenceConcrete", true);
    data.AddUtf8(
        "sequencePolicy",
        "Concrete driver rows use KSWORD_SANDBOX_EVENT_HEADER.Sequence; summary rows use NextSequence with sequenceMeaning=nextSequence");
    data.AddWide(
        "zhSequencePolicy",
        L"具体 driver 事件行的 sequence 来自 KSWORD_SANDBOX_EVENT_HEADER.Sequence；"
        L"摘要行使用 NextSequence，并以 sequenceMeaning=nextSequence 标记。");
}

// Input: Attribution returned by self-noise classification.
// Processing: Emits stable noise-class fields used by reports to hide collector
// plumbing from sample behavior while preserving an audit trail.
// Return: No return value; builder is mutated.
void AddDriverNoiseClassificationFields(
    JsonDataObjectBuilder& data,
    const DriverEventAttribution& attribution) {
    const std::string selfNoiseClass = attribution.collectorNoise
        ? "collector-self-noise"
        : (attribution.selfNoise ? "producer-self-noise" : "none");
    const std::string noiseClass = attribution.collectorNoise
        ? "collector-infrastructure"
        : (attribution.selfNoise ? "producer-self-noise" : "sample-or-system");
    const bool sampleBehaviorCandidate = !attribution.collectorNoise && !attribution.selfNoise;

    data.AddUtf8("noiseClass", noiseClass);
    data.AddUtf8(
        "noiseScope",
        attribution.collectorNoise
            ? "collector-infrastructure"
            : (attribution.selfNoise ? "producer-self-noise" : "none"));
    data.AddUtf8(
        "noiseKind",
        attribution.collectorNoise
            ? "collector-self-noise"
            : (attribution.selfNoise ? "producer-self-noise" : "none"));
    data.AddUtf8(
        "noiseSource",
        attribution.collectorNoise
            ? "collector-path-or-pid"
            : (attribution.selfNoise ? "driver-producer-flag" : "not-noise"));
    data.AddUtf8("selfNoiseClass", selfNoiseClass);
    data.AddUtf8(
        "collectorNoiseClass",
        attribution.collectorNoise ? "collector-infrastructure" : "none");
    data.AddUtf8(
        "noiseAction",
        attribution.suppressed ? "suppress" : "emit");
    data.AddUtf8(
        "noiseDisposition",
        attribution.suppressed
            ? "suppressed-before-jsonl"
            : (sampleBehaviorCandidate ? "emitted-as-sample-or-system-candidate" : "emitted-for-audit-only"));
    data.AddUtf8(
        "noiseReasons",
        attribution.selfNoiseReason.empty() ? "none" : attribution.selfNoiseReason);
    data.AddUtf8("noiseFieldSet", kJsonlNoiseFieldSet);
    data.AddUtf8("noiseTaxonomyVersion", "1");
    data.AddUtf8(
        "noiseDecision",
        attribution.collectorNoise
            ? "collector-self-noise"
            : (attribution.selfNoise ? "producer-self-noise" : "not-noise"));
    data.AddUtf8(
        "noiseDecisionSource",
        attribution.collectorNoise
            ? "collector-path-or-pid"
            : (attribution.selfNoise ? "driver-producer-flag" : "driver-attribution-default"));
    data.AddUtf8("noiseClassificationConfidence", "high");
    data.AddUtf8("noiseProbeKind", "none");
    data.AddBool("sampleBehaviorCandidate", sampleBehaviorCandidate);
    data.AddUtf8(
        "sampleBehaviorCandidateReason",
        sampleBehaviorCandidate
            ? "not-collector-or-producer-self-noise"
            : "noise-classification-excludes-sample-behavior");
    data.AddBool("collectionDiagnostic", false);
    data.AddBool("collectionNoise", attribution.collectorNoise);
    data.AddUtf8(
        "operatorInterpretation",
        attribution.collectorNoise
            ? "collector_self_noise_not_sample_behavior"
            : (attribution.selfNoise ? "producer_self_noise_not_sample_behavior" : "candidate_sample_or_system_behavior"));
    data.AddWide(
        "zhNoiseHint",
        attribution.collectorNoise
            ? (attribution.suppressed
                ? L"该行被判定为 Collector/KSword 基础设施自噪声，默认已从样本行为中抑制。"
                : L"该行被判定为 Collector/KSword 基础设施自噪声；当前配置选择写出以便审计。")
            : (attribution.selfNoise
                ? L"该行由 producer 标记为自噪声，不应直接计入样本行为。"
                : L"该行未命中 Collector 自噪声规则，可作为样本或系统行为候选证据。"));
    data.AddWide(
        "zhNoiseClassificationHint",
        attribution.collectorNoise
            ? L"噪声分类为 Collector/KSword 基础设施；用于审计采集链路，不应计入样本行为。"
            : (attribution.selfNoise
                ? L"噪声分类为 producer 自噪声；请与 sampleBehaviorCandidate=false 一起处理。"
                : L"噪声分类为 not-noise；该行可作为样本/系统行为候选，但仍需上下文确认。"));
    data.AddWide(
        "zhOperatorHint",
        attribution.collectorNoise
            ? L"运营提示：Collector/KSword 基础设施噪声只用于审计采集链路，不要作为样本行为结论。"
            : (attribution.selfNoise
                ? L"运营提示：producer 自噪声需要和 sampleBehaviorCandidate=false 一起处理，避免误报。"
                : L"运营提示：该行可进入样本/系统行为候选，但仍需结合进程树、文件、注册表和网络上下文判断。"));
}

// Input: Process payload flags.
// Processing: Decodes public bits and preserves unknown bits for diagnostics.
// Return: Pipe-delimited flag names, or "none".
std::string ProcessEventFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT) != 0) {
        appendName("ImagePathPresent");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED) != 0) {
        appendName("ImagePathTruncated");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT) != 0) {
        appendName("CommandPresent");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED) != 0) {
        appendName("CommandTruncated");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT) != 0) {
        appendName("StatusPresent");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_EX_CALLBACK) != 0) {
        appendName("ExCallback");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_EX_CALLBACK;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LEGACY_CALLBACK) != 0) {
        appendName("LegacyCallback");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LEGACY_CALLBACK;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT) != 0) {
        appendName("ParentIdPresent");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT) != 0) {
        appendName("CreatorIdPresent");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_CACHE_HIT) != 0) {
        appendName("LineageCacheHit");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_CACHE_HIT;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_STRINGS_REPLAYED) != 0) {
        appendName("LineageStringsReplayed");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_STRINGS_REPLAYED;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_FILE_OPEN_NAME_AVAILABLE) != 0) {
        appendName("FileOpenNameAvailable");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_FILE_OPEN_NAME_AVAILABLE;
    }
    if ((flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_OPERATION_FAILED) != 0) {
        appendName("OperationFailed");
        knownFlags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_OPERATION_FAILED;
    }

    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: Image payload flags.
// Processing: Decodes public image-load bits.
// Return: Pipe-delimited flag names, or "none".
std::string ImageEventFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT) != 0) {
        appendName("PathPresent");
        knownFlags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED) != 0) {
        appendName("PathTruncated");
        knownFlags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED;
    }
    if ((flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE) != 0) {
        appendName("SystemModeImage");
        knownFlags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE;
    }
    if ((flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT) != 0) {
        appendName("ProcessIdPresent");
        knownFlags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROPERTIES_PRESENT) != 0) {
        appendName("PropertiesPresent");
        knownFlags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROPERTIES_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_MAPPED_TO_ALL_PIDS) != 0) {
        appendName("MappedToAllPids");
        knownFlags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_MAPPED_TO_ALL_PIDS;
    }
    if ((flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_EXTENDED_INFO_PRESENT) != 0) {
        appendName("ExtendedInfoPresent");
        knownFlags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_EXTENDED_INFO_PRESENT;
    }
    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: Registry payload flags.
// Processing: Decodes public registry bits.
// Return: Pipe-delimited flag names, or "none".
std::string RegistryEventFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT) != 0) {
        appendName("KeyPresent");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED) != 0) {
        appendName("KeyTruncated");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT) != 0) {
        appendName("ValuePresent");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TRUNCATED) != 0) {
        appendName("ValueTruncated");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TRUNCATED;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_STATUS_PRESENT) != 0) {
        appendName("StatusPresent");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_STATUS_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_POST_OPERATION) != 0) {
        appendName("PostOperation");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_POST_OPERATION;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_CALLBACK) != 0) {
        appendName("KeyFromCallback");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_CALLBACK;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_OBJECT) != 0) {
        appendName("KeyFromObject");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_OBJECT;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TYPE_PRESENT) != 0) {
        appendName("ValueTypePresent");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TYPE_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_SIZE_PRESENT) != 0) {
        appendName("ValueSizePresent");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_SIZE_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_OPERATION_FAILED) != 0) {
        appendName("OperationFailed");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_OPERATION_FAILED;
    }
    if ((flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_DATA_EMPTY) != 0) {
        appendName("ValueDataEmpty");
        knownFlags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_DATA_EMPTY;
    }
    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: Network payload flags.
// Processing: Decodes public network bits.
// Return: Pipe-delimited flag names, or "none".
std::string NetworkEventFlagNames(const ULONG flags) {
    std::string names;
    ULONG knownFlags = 0;
    const auto appendName = [&names](const std::string& name) {
        if (!names.empty()) {
            names += "|";
        }
        names += name;
    };

    if ((flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT) != 0) {
        appendName("LocalAddressPresent");
        knownFlags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT) != 0) {
        appendName("RemoteAddressPresent");
        knownFlags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT) != 0) {
        appendName("ProcessIdPresent");
        knownFlags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_FLOW_HANDLE_PRESENT) != 0) {
        appendName("FlowHandlePresent");
        knownFlags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_FLOW_HANDLE_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_ENDPOINT_HANDLE_PRESENT) != 0) {
        appendName("EndpointHandlePresent");
        knownFlags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_ENDPOINT_HANDLE_PRESENT;
    }
    if ((flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_INSPECTION_ONLY) != 0) {
        appendName("InspectionOnly");
        knownFlags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_INSPECTION_ONLY;
    }
    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
}

// Input: Network protocol plus the most meaningful peer port.
// Processing: Applies light service hints without inspecting packet payloads.
// Return: dns/http/tls/web/unknown label used by rules and reports.
std::string NetworkServiceHint(const ULONG protocol, const USHORT remotePort) {
    if (remotePort == 53 && (protocol == KSWORD_SANDBOX_NETWORK_PROTOCOL_UDP ||
                             protocol == KSWORD_SANDBOX_NETWORK_PROTOCOL_TCP)) {
        return "dns";
    }

    if ((remotePort == 80 || remotePort == 8080 || remotePort == 8000) &&
        protocol == KSWORD_SANDBOX_NETWORK_PROTOCOL_TCP) {
        return "http";
    }

    if ((remotePort == 443 || remotePort == 8443) &&
        protocol == KSWORD_SANDBOX_NETWORK_PROTOCOL_TCP) {
        return "tls";
    }

    if (remotePort == 80 || remotePort == 443 || remotePort == 8080 || remotePort == 8443) {
        return "web";
    }

    return "unknown";
}

// Input: Address and port strings.
// Processing: Joins decoded address/port into a stable endpoint token.
// Return: endpoint text, or empty when no address was decoded.
std::string NetworkEndpoint(const std::string& address, const USHORT port) {
    if (address.empty()) {
        return {};
    }

    return address + ":" + std::to_string(port);
}

// Input: transport, endpoints, and direction.
// Processing: Produces a deterministic correlation key shared with PCAP/import
// events so reports can group R0 and packet-capture evidence.
// Return: flow key text.
std::string NetworkFlowKey(
    const std::string& protocolName,
    const std::string& localEndpoint,
    const std::string& remoteEndpoint,
    const ULONG direction) {
    const std::string source = direction == KswSandboxNetworkDirectionInbound ? remoteEndpoint : localEndpoint;
    const std::string destination = direction == KswSandboxNetworkDirectionInbound ? localEndpoint : remoteEndpoint;
    return protocolName + "|" + source + "|" + destination;
}

// Input: Network flow key and service-hint label already derived from endpoint
// metadata.
// Processing: Emits explicit L7/PCAP boundary fields so DNS/HTTP/TLS candidates
// remain endpoint/port evidence and do not look like payload parsing verdicts.
// Return: No return value; builder is mutated.
void AddNetworkProtocolBoundaryData(
    JsonDataObjectBuilder& data,
    const std::string& flowKey,
    const std::string& serviceHint) {
    const bool dnsCandidate = serviceHint == "dns";
    const bool httpCandidate = serviceHint == "http";
    const bool tlsCandidate = serviceHint == "tls";

    data.AddBool("protocolPayloadParsed", false);
    data.AddUtf8("protocolParserSource", "r0-ale-endpoint-only");
    data.AddUtf8("protocolPayloadSource", "none-r0-endpoint-metadata-only");
    data.AddUnsigned("networkCorrelationContractVersion", 1);
    data.AddUtf8("networkCorrelationRole", "r0-endpoint-candidate");
    data.AddUtf8("pcapCorrelationRole", "join-candidate-not-l7-owner");
    data.AddUtf8("pcapCorrelationJoinFields", "flowKey|sourceEndpoint|destinationEndpoint|protocolName|sourcePort|destinationPort|processId");
    data.AddUtf8("pcapCorrelationMissingFields", "dnsQueryName|httpHost|httpUri|httpMethod|tlsSni|tlsCertificate");
    data.AddUtf8("pcapCorrelationConfidence", serviceHint == "unknown" ? "low" : "medium");
    data.AddUtf8("networkCorrelationStableFields", kNetworkCorrelationStableFields);
    data.AddBool("pcapCorrelationRequired", true);
    data.AddUtf8("pcapCorrelationStatus", "required-unmatched-in-r0-row");
    data.AddUtf8("pcapFlowKeyCandidate", flowKey);
    data.AddUtf8("pcapCorrelationKey", flowKey);
    data.AddUtf8("pcapCorrelationKeySource", "flowKey");
    data.AddUtf8("pcapExpectedRecordTypes", "pcap.flow|pcap.dns|pcap.http|pcap.tls");
    data.AddBool("pcapDnsDetailsAvailable", false);
    data.AddBool("pcapHttpDetailsAvailable", false);
    data.AddBool("pcapTlsDetailsAvailable", false);
    data.AddUtf8(
        "pcapBoundaryPolicy",
        "R0 rows provide endpoint/port/PID/layer evidence; L7 names and URLs require PCAP/browser/sidecar rows");
    data.AddUtf8("networkProtocolBoundaryFields", kNetworkProtocolBoundaryFields);
    data.AddUtf8(
        "networkProtocolParserBoundary",
        "R0 WFP/ALE rows do not parse DNS names, HTTP Host/URI, or TLS SNI; correlate PCAP/browser/sidecar rows");
    data.AddUtf8("r0ProtocolParserGuarantee", "endpoint-port-pid-layer-only");
    data.AddUtf8("protocolBoundaryVerdict", "l7-unavailable-r0-endpoint-only");
    data.AddBool("l7ProtocolDetailsAvailable", false);
    data.AddUtf8("l7ProtocolDetailsOwner", "pcap-browser-sidecar-not-r0");
    data.AddUtf8("dnsQueryName", "");
    data.AddBool("dnsQueryNameAvailable", false);
    data.AddUtf8("dnsQueryNameSource", "pcap-required-not-r0");
    data.AddUtf8("dnsCorrelationRecordType", dnsCandidate ? "pcap.dns-required" : "not-applicable");
    data.AddUtf8("dnsDetailsOwner", "pcap.dns-or-sidecar");
    data.AddUtf8(
        "dnsBoundary",
        dnsCandidate ? "candidate-port-only-name-required-from-pcap" : "not-dns-candidate");
    data.AddUtf8("httpHost", "");
    data.AddUtf8("httpUri", "");
    data.AddUtf8("httpMethod", "");
    data.AddBool("httpHostAvailable", false);
    data.AddBool("httpUriAvailable", false);
    data.AddBool("httpMethodAvailable", false);
    data.AddUtf8("httpMetadataSource", "pcap-or-browser-required-not-r0");
    data.AddUtf8("httpCorrelationRecordType", httpCandidate ? "pcap.http-required" : "not-applicable");
    data.AddUtf8("httpDetailsOwner", "pcap.http-browser-or-sidecar");
    data.AddUtf8(
        "httpBoundary",
        httpCandidate ? "candidate-port-only-host-uri-required-from-pcap" : "not-http-candidate");
    data.AddUtf8("tlsSni", "");
    data.AddBool("tlsSniAvailable", false);
    data.AddBool("tlsCertificateAvailable", false);
    data.AddUtf8("tlsMetadataSource", "pcap-required-not-r0");
    data.AddUtf8("tlsCorrelationRecordType", tlsCandidate ? "pcap.tls-required" : "not-applicable");
    data.AddUtf8("tlsDetailsOwner", "pcap.tls-or-sidecar");
    data.AddUtf8(
        "tlsBoundary",
        tlsCandidate ? "candidate-port-only-sni-cert-required-from-pcap" : "not-tls-candidate");
    data.AddWide(
        "zhPcapCorrelationHint",
        L"该 R0 网络行只提供端点/端口/PID/layer 证据；DNS 名称、HTTP Host/URI、TLS SNI/证书需查看 PCAP、浏览器或 sidecar 行。");
    data.AddWide(
        "zhNetworkBoundaryHint",
        L"不要把 serviceHint 或 candidate 布尔值解读为协议载荷已解析；它们只是端口/协议候选标签。");
    data.AddWide(
        "zhDnsCorrelationHint",
        dnsCandidate
            ? L"DNS 候选只说明 53/UDP 端点；查询名、响应码和答案应由 pcap.dns 或 sidecar 行补齐。"
            : L"该行不是 DNS 候选；如需域名证据请查看 pcap.dns 或 sidecar 行。");
    data.AddWide(
        "zhHttpCorrelationHint",
        httpCandidate
            ? L"HTTP 候选只说明 80/TCP 等端点；Host、URI、Method 和状态码应由 pcap.http、浏览器或代理 sidecar 行补齐。"
            : L"该行不是 HTTP 候选；不要从 R0 端点字段推断 Host、URI 或 Method。");
    data.AddWide(
        "zhTlsCorrelationHint",
        tlsCandidate
            ? L"TLS 候选只说明 443/TCP 等端点；SNI、证书、JA3/JA3S 应由 pcap.tls 或 TLS sidecar 行补齐。"
            : L"该行不是 TLS 候选；不要从 R0 端点字段推断 SNI 或证书。");
}

// Input: ASCII text already produced from numeric network metadata.
// Processing: Widens byte-for-byte for top-level SandboxEvent.path construction.
// Return: UTF-16 string safe for ASCII URI-like paths.
std::wstring WideFromAscii(const std::string& value) {
    return std::wstring(value.begin(), value.end());
}

// Input: Payload bytes and driver event type.
// Processing: Decodes the best available subject path for top-level event.path.
// Return: UTF-16 subject path or an empty string when the payload has no path.
std::wstring ExtractTypedPayloadPath(
    const ULONG eventType,
    const unsigned char* payload,
    const size_t payloadBytes) {
    if (payload == nullptr) {
        return {};
    }

    if (eventType == KswSandboxEventTypeFile) {
        return ExtractFilePayloadPath(payload, payloadBytes);
    }

    if (eventType == KswSandboxEventTypeProcess &&
        payloadBytes >= sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)) {
        const auto* processPayload =
            reinterpret_cast<const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD*>(payload);
        if ((processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT) != 0) {
            return BoundedWideStringFromUtf16Bytes(
                processPayload->ImagePath,
                processPayload->ImagePathLengthBytes,
                KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS);
        }
    }

    if (eventType == KswSandboxEventTypeImage &&
        payloadBytes >= sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)) {
        const auto* imagePayload =
            reinterpret_cast<const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD*>(payload);
        if ((imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT) != 0) {
            return BoundedWideStringFromUtf16Bytes(
                imagePayload->ImagePath,
                imagePayload->PathLengthBytes,
                KSWORD_SANDBOX_IMAGE_PATH_CHARS);
        }
    }

    if (eventType == KswSandboxEventTypeRegistry &&
        payloadBytes >= sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)) {
        const auto* registryPayload =
            reinterpret_cast<const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD*>(payload);
        if ((registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT) != 0) {
            return BoundedWideStringFromUtf16Bytes(
                registryPayload->KeyPath,
                registryPayload->KeyPathLengthBytes,
                KSWORD_SANDBOX_REGISTRY_KEY_PATH_CHARS);
        }
    }

    if (eventType == KswSandboxEventTypeNetwork &&
        payloadBytes >= sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)) {
        const auto* networkPayload =
            reinterpret_cast<const KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD*>(payload);
        if ((networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT) != 0) {
            const std::string remoteAddress =
                NetworkAddressText(networkPayload->AddressFamily, networkPayload->RemoteAddress);
            if (!remoteAddress.empty()) {
                return WideFromAscii(
                    NetworkProtocolName(networkPayload->Protocol) + "://" +
                    remoteAddress + ":" + std::to_string(networkPayload->RemotePort));
            }
        }
    }

    return {};
}

// Input: Payload bytes and driver event type.
// Processing: Extracts the captured process command-line prefix when the public
// process payload says it is present.
// Return: UTF-16 command-line text, or empty for non-process/absent payloads.
std::wstring ExtractTypedPayloadCommandLine(
    const ULONG eventType,
    const unsigned char* payload,
    const size_t payloadBytes) {
    if (eventType != KswSandboxEventTypeProcess ||
        payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)) {
        return {};
    }

    const auto* processPayload =
        reinterpret_cast<const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD*>(payload);
    if ((processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT) == 0) {
        return {};
    }

    return BoundedWideStringFromUtf16Bytes(
        processPayload->CommandLine,
        processPayload->CommandLineLengthBytes,
        KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS);
}

// Input: Payload bytes and driver event type.
// Processing: Derives a top-level SandboxEvent.processName from the public
// process image path when present.  Non-process events keep the collector
// default or an explicitly supplied value because their subject path is not
// necessarily the owning process image.
// Return: Process image basename, or empty when unavailable.
std::wstring ExtractTypedPayloadProcessName(
    const ULONG eventType,
    const unsigned char* payload,
    const size_t payloadBytes) {
    if (eventType != KswSandboxEventTypeProcess) {
        return {};
    }

    const std::wstring imagePath = ExtractTypedPayloadPath(eventType, payload, payloadBytes);
    return BaseNameFromPath(imagePath);
}

// Input: Payload bytes, driver event type, and the header PID fallback.
// Processing: Uses the typed payload PID when the public ABI supplies the
// observed/target process ID, because the event header records only the kernel
// callback's current process context.
// Return: Best-effort SandboxEvent.processId value.
unsigned long long ExtractTypedPayloadProcessId(
    const ULONG eventType,
    const unsigned char* payload,
    const size_t payloadBytes,
    const unsigned long long fallbackProcessId) {
    if (payload == nullptr) {
        return fallbackProcessId;
    }

    switch (eventType) {
    case KswSandboxEventTypeProcess:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)) {
            const auto* processPayload =
                reinterpret_cast<const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD*>(payload);
            return processPayload->ProcessId != 0 ? processPayload->ProcessId : fallbackProcessId;
        }
        break;

    case KswSandboxEventTypeImage:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)) {
            const auto* imagePayload =
                reinterpret_cast<const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD*>(payload);
            const bool processIdPresent =
                (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT) != 0;
            return (processIdPresent && imagePayload->ProcessId != 0)
                ? imagePayload->ProcessId
                : fallbackProcessId;
        }
        break;

    case KswSandboxEventTypeFile:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)) {
            const auto* filePayload =
                reinterpret_cast<const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD*>(payload);
            return filePayload->ProcessId != 0 ? filePayload->ProcessId : fallbackProcessId;
        }
        break;

    case KswSandboxEventTypeRegistry:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)) {
            const auto* registryPayload =
                reinterpret_cast<const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD*>(payload);
            return registryPayload->ProcessId != 0 ? registryPayload->ProcessId : fallbackProcessId;
        }
        break;

    case KswSandboxEventTypeNetwork:
        if (payloadBytes >= sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)) {
            const auto* networkPayload =
                reinterpret_cast<const KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD*>(payload);
            const bool processIdPresent =
                (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT) != 0;
            return (processIdPresent && networkPayload->ProcessId != 0)
                ? networkPayload->ProcessId
                : fallbackProcessId;
        }
        break;

    default:
        break;
    }

    return fallbackProcessId;
}

// Input: One public driver event header and the JSON data builder being filled.
// Processing: Adds string-valued flag diagnostics and names DriverEntry startup
// heartbeat semantics for both the current typed driver-load event and legacy
// reserved/header-only rows.
// Return: No return value; the builder is mutated when it is non-null.
void AddDriverEventFlagData(
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return;
    }

    const ULONG knownFlags =
        KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST |
        KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED |
        KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_PARENT_PID_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_PRODUCER_METADATA_PRESENT |
        KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE;
    const ULONG unknownFlags = header.Flags & ~knownFlags;
    const bool isSelfTest =
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST) != 0;
    const bool isDriverStarted =
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED) != 0;

    data->AddUtf8("flagNames", DriverEventFlagNames(header.Flags));
    data->AddBool("flagSelfTest", isSelfTest);
    data->AddBool("flagDriverStarted", isDriverStarted);
    data->AddBool(
        "flagOperationPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT) != 0);
    data->AddBool(
        "flagStatusPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT) != 0);
    data->AddBool(
        "flagTargetPidPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT) != 0);
    data->AddBool(
        "flagParentPidPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_PARENT_PID_PRESENT) != 0);
    data->AddBool(
        "flagSubjectPathPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT) != 0);
    data->AddBool(
        "flagLostCountPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT) != 0);
    data->AddBool(
        "flagBackpressureCountPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT) != 0);
    data->AddBool(
        "flagProducerMetadataPresent",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_PRODUCER_METADATA_PRESENT) != 0);
    data->AddBool(
        "flagSelfNoise",
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE) != 0);
    data->AddUnsigned("unknownFlags", unknownFlags);
    data->AddUtf8("unknownFlagsHex", HexUnsignedLongLong(unknownFlags, 8));

    if (header.Type == KswSandboxEventTypeDriverLoad && isDriverStarted) {
        data->AddUtf8("driverLoadEventName", "driver.load");
        data->AddUtf8(
            "driverLoadEventDescription",
            "Typed DriverEntry startup heartbeat emitted by the KSword sandbox driver.");
        data->AddWide(
            "zhDriverLoadEventDescription",
            L"KSword sandbox driver \u5728 DriverEntry \u542f\u52a8\u65f6\u53d1\u51fa\u7684 typed \u5fc3\u8df3\u4e8b\u4ef6\u3002");
    } else if (header.Type == KswSandboxEventTypeReserved && isDriverStarted) {
        data->AddUtf8("reservedEventName", "driver.started");
        data->AddUtf8(
            "reservedEventDescription",
            "Legacy header-only DriverEntry startup heartbeat emitted with reserved event type.");
        data->AddWide(
            "zhReservedEventDescription",
            L"\u517c\u5bb9\u65e7\u683c\u5f0f\u7684 DriverEntry \u542f\u52a8\u5fc3\u8df3\uff0c"
            L"\u4ec5\u5305\u542b header\uff0c\u4e8b\u4ef6\u7c7b\u578b\u4e3a reserved\u3002");
    }
}

// Input: Driver event header, optional typed payload, and JSON builder.
// Processing: Emits the report-critical compatibility aliases before verbose
// payload fields so sampled reports keep operation/status/truncation evidence.
// Return: No return value; fields are additive and string-valued.
void AddTypedReportCompatibilityData(
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return;
    }

    const auto addHeaderFallback = [&]() {
        if ((header.Flags & KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT) != 0) {
            data->AddUtf8("operationName", DriverOperationName(header.Type, header.Operation));
        }
        if ((header.Flags & KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT) != 0) {
            data->AddSigned("status", header.Status);
        }
    };

    switch (header.Type) {
    case KswSandboxEventTypeFile:
        if (payload != nullptr && payloadBytes >= sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)) {
            const auto* filePayload =
                reinterpret_cast<const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD*>(payload);
            data->AddUtf8("operationName", FileOperationName(filePayload->Operation));
            data->AddSigned("status", filePayload->Status);
            data->AddBool(
                "pathTruncated",
                (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED) != 0);
        } else {
            addHeaderFallback();
            data->AddBool("pathTruncated", false);
        }
        break;

    case KswSandboxEventTypeProcess:
        if (payload != nullptr && payloadBytes >= sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)) {
            const auto* processPayload =
                reinterpret_cast<const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD*>(payload);
            data->AddUtf8("operationName", ProcessOperationName(processPayload->Operation));
            data->AddSigned("status", processPayload->Status);
            data->AddBool(
                "pathTruncated",
                (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED) != 0);
        } else {
            addHeaderFallback();
            data->AddBool("pathTruncated", false);
        }
        break;

    case KswSandboxEventTypeImage:
        if (payload != nullptr && payloadBytes >= sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)) {
            const auto* imagePayload =
                reinterpret_cast<const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD*>(payload);
            const ULONG operation = imagePayload->Operation != 0
                ? imagePayload->Operation
                : header.Operation;
            data->AddUtf8("operationName", ImageOperationName(operation));
            data->AddBool(
                "pathTruncated",
                (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED) != 0);
        } else {
            addHeaderFallback();
            data->AddBool("pathTruncated", false);
        }
        break;

    case KswSandboxEventTypeRegistry:
        if (payload != nullptr && payloadBytes >= sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)) {
            const auto* registryPayload =
                reinterpret_cast<const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD*>(payload);
            data->AddUtf8("operationName", RegistryOperationName(registryPayload->Operation));
            data->AddSigned("status", registryPayload->Status);
            data->AddBool(
                "pathTruncated",
                (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED) != 0);
        } else {
            addHeaderFallback();
            data->AddBool("pathTruncated", false);
        }
        break;

    case KswSandboxEventTypeNetwork:
        if (payload != nullptr && payloadBytes >= sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)) {
            const auto* networkPayload =
                reinterpret_cast<const KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD*>(payload);
            const ULONG operation = networkPayload->Operation != 0
                ? networkPayload->Operation
                : header.Operation;
            data->AddUtf8("operationName", NetworkOperationName(operation));
            data->AddSigned("status", networkPayload->Status);
        } else {
            addHeaderFallback();
        }
        data->AddBool("pathTruncated", false);
        break;

    case KswSandboxEventTypeDriverLoad:
        data->AddUtf8("operationName", "load");
        if ((header.Flags & KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT) != 0) {
            data->AddSigned("status", header.Status);
        }
        data->AddBool("pathTruncated", false);
        break;

    default:
        addHeaderFallback();
        data->AddBool("pathTruncated", false);
        break;
    }
}

// Input: One driver event header and the JSON data builder being filled.
// Processing: Exposes the common ABI metadata appended to
// KSWORD_SANDBOX_EVENT_HEADER so consumers can diagnose operation/status/loss
// hints even if a typed payload is short or from a newer producer.
// Return: No return value; the builder is mutated when it is non-null.
void AddDriverEventCommonMetadata(
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return;
    }

    data->AddUnsigned("headerParentProcessId", header.ParentProcessId);
    data->AddUnsigned("lostEvents", header.LostEvents);
    data->AddUnsigned("lostCount", header.LostEvents);
    data->AddUnsigned("backpressureEvents", header.BackpressureEvents);
    data->AddUnsigned("headerOperation", header.Operation);
    data->AddUtf8("headerOperationName", DriverOperationName(header.Type, header.Operation));
    data->AddSigned("headerStatus", header.Status);
    data->AddUtf8("headerStatusHex", HexUnsignedLongLong(static_cast<unsigned long>(header.Status), 8));
    data->AddUnsigned("producerId", header.ProducerId);
    data->AddUtf8("producerIdHex", HexUnsignedLongLong(header.ProducerId, 8));
    data->AddUtf8("producerIdNames", ProducerMaskNames(header.ProducerId));
    data->AddUnsigned("producerMetadataFlags", header.ProducerMetadataFlags);
    data->AddUtf8("producerMetadataFlagsHex", HexUnsignedLongLong(header.ProducerMetadataFlags, 8));
    data->AddUtf8("producerMetadataFlagNames", ProducerMetadataFlagNames(header.ProducerMetadataFlags));
    data->AddBool(
        "producerSelfNoise",
        (header.ProducerMetadataFlags & KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE) != 0);
    data->AddSigned("timestampSystemTime", header.TimestampSystemTime.QuadPart);
}

// Input: Payload bytes for KswSandboxEventTypeDriverLoad and the JSON builder.
// Processing: Validates that the public driver-load payload is present before
// copying its fixed fields.  Malformed or short payloads keep the common
// payloadHex fallback emitted by the caller.
// Return: true when the public driver-load payload was parsed; false otherwise.
bool AddDriverLoadPayloadData(
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    data->AddUtf8("typedPayloadKind", "driver.load");
    data->AddUtf8("payloadSchema", "KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD");
    data->AddUnsigned(
        "typedPayloadMinimumSize",
        static_cast<unsigned long long>(sizeof(KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD)));

    if (payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD)) {
        data->AddUtf8("typedPayloadStatus", "payload-too-small");
        return false;
    }

    const auto* driverLoad =
        reinterpret_cast<const KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD*>(payload);
    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUnsigned("driverLoadVersion", driverLoad->Version);
    data->AddUtf8("driverLoadVersionHex", HexUnsignedLongLong(driverLoad->Version, 8));
    data->AddUnsigned("driverLoadSize", driverLoad->Size);
    data->AddBool(
        "driverLoadSizeMatchesPublicAbi",
        driverLoad->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD)));
    data->AddUnsigned("bootId", driverLoad->BootId);
    data->AddUtf8(
        "buildTag",
        BoundedAsciiString(driverLoad->BuildTag, sizeof(driverLoad->BuildTag)));
    return true;
}

// Input: Payload bytes for KswSandboxEventTypeFile and the JSON builder.
// Processing: Parses the public compact minifilter payload and emits only
// string-valued data fields so the host import path can keep using
// Dictionary<string,string>. The common payloadHex fallback remains present for
// byte-level diagnosis even when parsing succeeds.
// Return: true when the public file payload was parsed; false for short or
// missing payloads.
bool AddFilePayloadData(
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    data->AddUtf8("typedPayloadKind", "file");
    data->AddUtf8("payloadSchema", "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD");
    data->AddUnsigned(
        "typedPayloadMinimumSize",
        static_cast<unsigned long long>(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)));
    data->AddUnsigned("typedPayloadObservedBytes", static_cast<unsigned long long>(payloadBytes));

    if (payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)) {
        data->AddUtf8("typedPayloadStatus", "payload-too-small");
        return false;
    }

    const auto* filePayload =
        reinterpret_cast<const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD*>(payload);
    const bool pathPresent =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT) != 0;
    const bool pathTruncated =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED) != 0;
    const bool statusPresent =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT) != 0;
    const bool postOperation =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_POST_OPERATION) != 0;
    const bool pathNormalized =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED) != 0;
    const bool pathFallback =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK) != 0;
    const bool operationFailed =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_OPERATION_FAILED) != 0;
    const bool deleteIntent =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_DELETE_INTENT) != 0;
    const bool renameIntent =
        (filePayload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_RENAME_INTENT) != 0;
    const std::wstring filePath = ExtractFilePayloadPath(payload, payloadBytes);
    const std::string fileOperationName = FileOperationName(filePayload->Operation);
    const std::string fileIntent = deleteIntent
        ? "delete"
        : (renameIntent ? "rename" : (operationFailed ? "failed-access" : fileOperationName));
    const std::string dropLocationFamily = FileDropLocationFamily(filePath);
    const bool startupFolderCandidate = dropLocationFamily == "startup-folder";
    const bool droppedFileCandidate =
        fileIntent == "create" ||
        fileIntent == "set-information" ||
        fileIntent == "rename" ||
        dropLocationFamily == "temp-directory" ||
        dropLocationFamily == "startup-folder" ||
        dropLocationFamily == "shared-writable-directory";

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUtf8("semanticFamily", "file");
    data->AddUtf8("behaviorLane", "filesystem");
    data->AddUtf8("fileOperationName", fileOperationName);
    data->AddUtf8("activityKind", ActivityKind("file", fileOperationName));
    data->AddUtf8("fileIntent", fileIntent);
    data->AddUtf8("artifactCandidateKind", droppedFileCandidate ? "dropped-file-or-file-change" : "file-activity");
    data->AddUtf8("dropLocationFamily", dropLocationFamily);
    data->AddBool("droppedFileCandidate", droppedFileCandidate);
    data->AddBool("startupFolderCandidate", startupFolderCandidate);
    data->AddBool("downloadExecuteCandidate", false);
    data->AddBool("evidenceReady", true);
    data->AddWide(
        "zhMessage",
        startupFolderCandidate
            ? L"R0 捕获到启动目录文件行为。"
            : (droppedFileCandidate ? L"R0 捕获到疑似释放文件/落地文件行为。" : L"R0 捕获到文件系统行为。"));
    data->AddWide(
        "zhHint",
        startupFolderCandidate
            ? L"文件位于用户启动目录，是持久化重点证据；建议在报告中与进程树和 dropped files 一起展开。"
            : (deleteIntent
                ? L"该文件事件带有删除意图，可结合 dropped files/artifact 目录判断样本释放或清理行为。"
                : (renameIntent
                    ? L"该文件事件带有重命名意图，可关注释放文件是否被移动或伪装。"
                    : L"该文件事件来自内核 minifilter，适合与 Guest dropped files、PCAP 和报告证据展开联动。")));
    data->AddUnsigned("fileVersion", filePayload->Version);
    data->AddUtf8("fileVersionHex", HexUnsignedLongLong(filePayload->Version, 8));
    data->AddUnsigned("filePayloadSize", filePayload->Size);
    data->AddBool(
        "filePayloadSizeMatchesPublicAbi",
        filePayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", filePayload->Operation);
    data->AddUnsigned("flags", filePayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(filePayload->Flags, 8));
    data->AddUtf8("flagNames", FileEventFlagNames(filePayload->Flags));
    data->AddBool("pathPresent", pathPresent);
    data->AddBool("filePathTruncated", pathTruncated);
    data->AddBool("pathNormalized", pathNormalized);
    data->AddBool("pathFallback", pathFallback);
    data->AddBool("statusPresent", statusPresent);
    data->AddBool("postOperation", postOperation);
    data->AddBool("operationFailed", operationFailed);
    data->AddBool("deleteIntent", deleteIntent);
    data->AddBool("renameIntent", renameIntent);
    data->AddUtf8(
        "statusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(filePayload->Status), 8));
    data->AddUnsigned("processId", filePayload->ProcessId);
    data->AddUnsigned("pathLengthBytes", filePayload->PathLengthBytes);
    data->AddUnsigned(
        "pathLengthBytesClamped",
        static_cast<unsigned long long>(std::min(
            static_cast<size_t>(filePayload->PathLengthBytes),
            sizeof(filePayload->Path))));
    data->AddUnsigned("majorFunction", filePayload->MajorFunction);
    data->AddUtf8("majorFunctionHex", HexUnsignedLongLong(filePayload->MajorFunction, 2));
    data->AddUnsigned("minorFunction", filePayload->MinorFunction);
    data->AddUtf8("minorFunctionHex", HexUnsignedLongLong(filePayload->MinorFunction, 2));
    data->AddBool("pathDecoded", !filePath.empty());
    if (!filePath.empty()) {
        data->AddWide("path", filePath);
        data->AddWide("filePath", filePath);
    }

    return true;
}

// Input: Payload bytes for KswSandboxEventTypeProcess and JSON builder.
// Processing: Parses process create/exit payload fields into string-valued data.
// Return: true when the public process payload was parsed; false otherwise.
bool AddProcessPayloadData(
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    data->AddUtf8("typedPayloadKind", "process");
    data->AddUtf8("payloadSchema", "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD");
    data->AddUnsigned(
        "typedPayloadMinimumSize",
        static_cast<unsigned long long>(sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)));
    data->AddUnsigned("typedPayloadObservedBytes", static_cast<unsigned long long>(payloadBytes));
    if (payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)) {
        data->AddUtf8("typedPayloadStatus", "payload-too-small");
        return false;
    }

    const auto* processPayload =
        reinterpret_cast<const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD*>(payload);
    const bool imagePathPresent =
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT) != 0;
    const bool commandLinePresent =
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT) != 0;
    const std::wstring imagePath = ExtractTypedPayloadPath(
        KswSandboxEventTypeProcess,
        payload,
        payloadBytes);
    const std::wstring commandLine = commandLinePresent
        ? BoundedWideStringFromUtf16Bytes(
            processPayload->CommandLine,
            processPayload->CommandLineLengthBytes,
            KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS)
        : std::wstring();
    const std::string processOperationName = ProcessOperationName(processPayload->Operation);
    const bool parentProcessIdPresent =
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT) != 0;
    const bool creatingProcessIdPresent =
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT) != 0;

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUtf8("semanticFamily", "process");
    data->AddUtf8("behaviorLane", "process-tree");
    data->AddUtf8("processOperationName", processOperationName);
    data->AddUtf8("activityKind", ActivityKind("process", processOperationName));
    data->AddUtf8(
        "processLifecycle",
        processOperationName == "create" ? "start" : (processOperationName == "exit" ? "exit" : "unknown"));
    data->AddUtf8(
        "lineageConfidence",
        parentProcessIdPresent || creatingProcessIdPresent ? "payload-lineage" : "header-only");
    data->AddBool("evidenceReady", true);
    data->AddWide(
        "zhMessage",
        processOperationName == "exit" ? L"R0 捕获到进程退出事件。" : L"R0 捕获到进程创建/生命周期事件。");
    data->AddWide(
        "zhHint",
        parentProcessIdPresent || creatingProcessIdPresent
            ? L"该进程事件包含父进程/创建者 PID，可用于恢复完整进程树。"
            : L"该进程事件缺少显式父进程字段，可与 Guest 进程快照和命令行证据交叉验证。");
    data->AddUnsigned("processVersion", processPayload->Version);
    data->AddUtf8("processVersionHex", HexUnsignedLongLong(processPayload->Version, 8));
    data->AddUnsigned("processPayloadSize", processPayload->Size);
    data->AddBool(
        "processPayloadSizeMatchesPublicAbi",
        processPayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", processPayload->Operation);
    data->AddUnsigned("flags", processPayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(processPayload->Flags, 8));
    data->AddUtf8("flagNames", ProcessEventFlagNames(processPayload->Flags));
    data->AddBool("pathPresent", imagePathPresent);
    data->AddBool("imagePathPresent", imagePathPresent);
    data->AddBool("commandLinePresent", commandLinePresent);
    data->AddBool(
        "statusPresent",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT) != 0);
    data->AddBool(
        "exCallback",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_EX_CALLBACK) != 0);
    data->AddBool(
        "legacyCallback",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LEGACY_CALLBACK) != 0);
    data->AddBool("parentProcessIdPresent", parentProcessIdPresent);
    data->AddBool("creatingProcessIdPresent", creatingProcessIdPresent);
    data->AddBool(
        "lineageCacheHit",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_CACHE_HIT) != 0);
    data->AddBool(
        "lineageStringsReplayed",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_STRINGS_REPLAYED) != 0);
    data->AddBool(
        "fileOpenNameAvailable",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_FILE_OPEN_NAME_AVAILABLE) != 0);
    data->AddBool(
        "operationFailed",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_OPERATION_FAILED) != 0);
    data->AddBool(
        "imagePathTruncated",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED) != 0);
    data->AddBool(
        "commandLineTruncated",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED) != 0);
    data->AddUnsigned("processId", processPayload->ProcessId);
    data->AddUnsigned("parentProcessId", processPayload->ParentProcessId);
    data->AddUnsigned("creatingProcessId", processPayload->CreatingProcessId);
    data->AddUtf8(
        "statusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(processPayload->Status), 8));
    data->AddUnsigned("imagePathLengthBytes", processPayload->ImagePathLengthBytes);
    data->AddUnsigned(
        "imagePathLengthBytesClamped",
        static_cast<unsigned long long>(std::min(
            static_cast<size_t>(processPayload->ImagePathLengthBytes),
            sizeof(processPayload->ImagePath))));
    data->AddUnsigned("commandLineLengthBytes", processPayload->CommandLineLengthBytes);
    data->AddUnsigned(
        "commandLineLengthBytesClamped",
        static_cast<unsigned long long>(std::min(
            static_cast<size_t>(processPayload->CommandLineLengthBytes),
            sizeof(processPayload->CommandLine))));
    data->AddBool("imagePathDecoded", !imagePath.empty());
    data->AddBool("commandLineDecoded", !commandLine.empty());
    if (!imagePath.empty()) {
        data->AddWide("imagePath", imagePath);
        data->AddWide("path", imagePath);
    }
    if (!commandLine.empty()) {
        data->AddWide("capturedCommandLine", commandLine);
    }

    return true;
}

// Input: Payload bytes for KswSandboxEventTypeImage and JSON builder.
// Processing: Parses image-load callback payload fields for live display.
// Return: true when the public image payload was parsed; false otherwise.
bool AddImagePayloadData(
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    data->AddUtf8("typedPayloadKind", "image");
    data->AddUtf8("payloadSchema", "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD");
    data->AddUnsigned(
        "typedPayloadMinimumSize",
        static_cast<unsigned long long>(sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)));
    data->AddUnsigned("typedPayloadObservedBytes", static_cast<unsigned long long>(payloadBytes));
    if (payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)) {
        data->AddUtf8("typedPayloadStatus", "payload-too-small");
        return false;
    }

    const auto* imagePayload =
        reinterpret_cast<const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD*>(payload);
    const std::wstring imagePath = ExtractTypedPayloadPath(
        KswSandboxEventTypeImage,
        payload,
        payloadBytes);
    const bool systemModeImage =
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE) != 0;
    const bool mappedToAllPids =
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_MAPPED_TO_ALL_PIDS) != 0;
    const std::string imageOperationName = ImageOperationName(imagePayload->Operation);
    const std::string imageLoadFamily = ImageLoadFamily(imagePath, systemModeImage);
    const bool injectionCandidate =
        !systemModeImage &&
        (imageLoadFamily == "user-writable-image" || mappedToAllPids);

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUtf8("semanticFamily", "image");
    data->AddUtf8("behaviorLane", "module-load");
    data->AddUtf8("activityKind", ActivityKind("image", imageOperationName));
    data->AddUtf8("imageLoadFamily", imageLoadFamily);
    data->AddBool("injectionCandidate", injectionCandidate);
    data->AddBool("userWritableImageCandidate", imageLoadFamily == "user-writable-image");
    data->AddBool("evidenceReady", true);
    data->AddWide(
        "zhMessage",
        injectionCandidate ? L"R0 捕获到可疑模块加载候选。" : L"R0 捕获到镜像/模块加载事件。");
    data->AddWide(
        "zhHint",
        injectionCandidate
            ? L"模块来自用户可写位置或映射范围异常，可与进程树、命令行和后续网络行为组合判断注入/侧载。"
            : L"该镜像加载事件用于还原进程模块时间线，不单独构成恶意结论。");
    data->AddUnsigned("imageVersion", imagePayload->Version);
    data->AddUtf8("imageVersionHex", HexUnsignedLongLong(imagePayload->Version, 8));
    data->AddUnsigned("imagePayloadSize", imagePayload->Size);
    data->AddBool(
        "imagePayloadSizeMatchesPublicAbi",
        imagePayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", imagePayload->Operation);
    data->AddUtf8("imageOperationName", imageOperationName);
    data->AddUnsigned("flags", imagePayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(imagePayload->Flags, 8));
    data->AddUtf8("flagNames", ImageEventFlagNames(imagePayload->Flags));
    data->AddBool(
        "pathPresent",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT) != 0);
    data->AddBool("systemModeImage", systemModeImage);
    data->AddBool(
        "processIdPresent",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT) != 0);
    data->AddBool(
        "propertiesPresent",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROPERTIES_PRESENT) != 0);
    data->AddBool(
        "imagePathTruncated",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED) != 0);
    data->AddBool("mappedToAllPids", mappedToAllPids);
    data->AddBool(
        "extendedInfoPresent",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_EXTENDED_INFO_PRESENT) != 0);
    data->AddUnsigned("processId", imagePayload->ProcessId);
    data->AddUtf8("imageBaseHex", HexUnsignedLongLong(imagePayload->ImageBase, 16));
    data->AddUnsigned("imageBase", imagePayload->ImageBase);
    data->AddUnsigned("imageSize", imagePayload->ImageSize);
    data->AddUnsigned("imageProperties", imagePayload->ImageProperties);
    data->AddUtf8("imagePropertiesHex", HexUnsignedLongLong(imagePayload->ImageProperties, 8));
    data->AddUnsigned("pathLengthBytes", imagePayload->PathLengthBytes);
    data->AddUnsigned(
        "pathLengthBytesClamped",
        static_cast<unsigned long long>(std::min(
            static_cast<size_t>(imagePayload->PathLengthBytes),
            sizeof(imagePayload->ImagePath))));
    data->AddBool("pathDecoded", !imagePath.empty());
    if (!imagePath.empty()) {
        data->AddWide("imagePath", imagePath);
        data->AddWide("path", imagePath);
    }

    return true;
}

// Input: Payload bytes for KswSandboxEventTypeRegistry and JSON builder.
// Processing: Parses registry callback payload fields.
// Return: true when the public registry payload was parsed; false otherwise.
bool AddRegistryPayloadData(
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    data->AddUtf8("typedPayloadKind", "registry");
    data->AddUtf8("payloadSchema", "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD");
    data->AddUnsigned(
        "typedPayloadMinimumSize",
        static_cast<unsigned long long>(sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)));
    data->AddUnsigned("typedPayloadObservedBytes", static_cast<unsigned long long>(payloadBytes));
    if (payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)) {
        data->AddUtf8("typedPayloadStatus", "payload-too-small");
        return false;
    }

    const auto* registryPayload =
        reinterpret_cast<const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD*>(payload);
    const std::wstring keyPath = ExtractTypedPayloadPath(
        KswSandboxEventTypeRegistry,
        payload,
        payloadBytes);
    const std::wstring valueName = BoundedWideStringFromUtf16Bytes(
        registryPayload->ValueName,
        registryPayload->ValueNameLengthBytes,
        KSWORD_SANDBOX_REGISTRY_VALUE_NAME_CHARS);
    const std::string registryOperationName = RegistryOperationName(registryPayload->Operation);
    const bool persistenceCandidate = RegistryPersistenceCandidate(keyPath);
    const std::string persistenceFamily = RegistryPersistenceFamily(keyPath);
    const bool servicePersistenceCandidate = persistenceFamily == "service-configuration";
    const bool ifeoPersistenceCandidate = persistenceFamily == "ifeo-debugger";

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUtf8("semanticFamily", "registry");
    data->AddUtf8("behaviorLane", "registry");
    data->AddUtf8("registryOperationName", registryOperationName);
    data->AddUtf8("activityKind", ActivityKind("registry", registryOperationName));
    data->AddBool("persistenceCandidate", persistenceCandidate);
    data->AddUtf8(
        "registryPersistenceSignal",
        persistenceCandidate ? "common-windows-persistence-key" : "none");
    data->AddUtf8("persistenceFamily", persistenceFamily);
    data->AddBool("servicePersistenceCandidate", servicePersistenceCandidate);
    data->AddBool("ifeoPersistenceCandidate", ifeoPersistenceCandidate);
    data->AddBool("startupRegistryCandidate", persistenceCandidate && !servicePersistenceCandidate && !ifeoPersistenceCandidate);
    data->AddBool("evidenceReady", true);
    data->AddWide(
        "zhMessage",
        persistenceCandidate ? L"R0 捕获到疑似持久化相关注册表行为。" : L"R0 捕获到注册表行为。");
    data->AddWide(
        "zhHint",
        persistenceCandidate
            ? L"该注册表路径匹配常见自启动/服务/IFEO 等持久化位置，应在报告中作为重点证据展开。"
            : L"该注册表事件来自内核回调，可结合行为规则和原始事件判断影响。");
    data->AddUnsigned("registryVersion", registryPayload->Version);
    data->AddUtf8("registryVersionHex", HexUnsignedLongLong(registryPayload->Version, 8));
    data->AddUnsigned("registryPayloadSize", registryPayload->Size);
    data->AddBool(
        "registryPayloadSizeMatchesPublicAbi",
        registryPayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", registryPayload->Operation);
    data->AddUnsigned("flags", registryPayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(registryPayload->Flags, 8));
    data->AddUtf8("flagNames", RegistryEventFlagNames(registryPayload->Flags));
    data->AddBool(
        "pathPresent",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT) != 0);
    data->AddBool(
        "keyPathPresent",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT) != 0);
    data->AddBool(
        "keyPathTruncated",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED) != 0);
    data->AddBool(
        "valueNamePresent",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT) != 0);
    data->AddBool(
        "valueNameTruncated",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TRUNCATED) != 0);
    data->AddBool(
        "statusPresent",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_STATUS_PRESENT) != 0);
    data->AddBool(
        "postOperation",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_POST_OPERATION) != 0);
    data->AddBool(
        "keyFromCallback",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_CALLBACK) != 0);
    data->AddBool(
        "keyFromObject",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_OBJECT) != 0);
    data->AddBool(
        "valueTypePresent",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TYPE_PRESENT) != 0);
    data->AddBool(
        "valueSizePresent",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_SIZE_PRESENT) != 0);
    data->AddBool(
        "operationFailed",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_OPERATION_FAILED) != 0);
    data->AddBool(
        "valueDataEmpty",
        (registryPayload->Flags & KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_DATA_EMPTY) != 0);
    data->AddUtf8(
        "statusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(registryPayload->Status), 8));
    data->AddUnsigned("processId", registryPayload->ProcessId);
    data->AddUnsigned("valueDataType", registryPayload->ValueDataType);
    data->AddUtf8("valueDataTypeHex", HexUnsignedLongLong(registryPayload->ValueDataType, 8));
    data->AddUnsigned("valueDataSizeBytes", registryPayload->ValueDataSizeBytes);
    data->AddUnsigned("keyPathLengthBytes", registryPayload->KeyPathLengthBytes);
    data->AddUnsigned(
        "keyPathLengthBytesClamped",
        static_cast<unsigned long long>(std::min(
            static_cast<size_t>(registryPayload->KeyPathLengthBytes),
            sizeof(registryPayload->KeyPath))));
    data->AddUnsigned("valueNameLengthBytes", registryPayload->ValueNameLengthBytes);
    data->AddUnsigned(
        "valueNameLengthBytesClamped",
        static_cast<unsigned long long>(std::min(
            static_cast<size_t>(registryPayload->ValueNameLengthBytes),
            sizeof(registryPayload->ValueName))));
    data->AddBool("keyPathDecoded", !keyPath.empty());
    data->AddBool("valueNameDecoded", !valueName.empty());
    if (!keyPath.empty()) {
        data->AddWide("keyPath", keyPath);
        data->AddWide("path", keyPath);
    }
    if (!valueName.empty()) {
        data->AddWide("valueName", valueName);
    }

    return true;
}

// Input: Payload bytes for KswSandboxEventTypeNetwork and JSON builder.
// Processing: Parses the compact network ABI for future WFP producers.
// Return: true when the public network payload was parsed; false otherwise.
bool AddNetworkPayloadData(
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    data->AddUtf8("typedPayloadKind", "network");
    data->AddUtf8("payloadSchema", "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD");
    data->AddUnsigned(
        "typedPayloadMinimumSize",
        static_cast<unsigned long long>(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)));
    data->AddUnsigned("typedPayloadObservedBytes", static_cast<unsigned long long>(payloadBytes));
    if (payload == nullptr ||
        payloadBytes < sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)) {
        data->AddUtf8("typedPayloadStatus", "payload-too-small");
        return false;
    }

    const auto* networkPayload =
        reinterpret_cast<const KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD*>(payload);
    const bool localAddressPresent =
        (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT) != 0;
    const bool remoteAddressPresent =
        (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT) != 0;
    const bool processIdPresent =
        (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT) != 0;
    const bool flowHandlePresent =
        (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_FLOW_HANDLE_PRESENT) != 0;
    const bool endpointHandlePresent =
        (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_ENDPOINT_HANDLE_PRESENT) != 0;
    const std::string localAddress = localAddressPresent
        ? NetworkAddressText(networkPayload->AddressFamily, networkPayload->LocalAddress)
        : std::string();
    const std::string remoteAddress = remoteAddressPresent
        ? NetworkAddressText(networkPayload->AddressFamily, networkPayload->RemoteAddress)
        : std::string();
    const std::string protocolName = NetworkProtocolName(networkPayload->Protocol);
    const std::string directionName = NetworkDirectionName(networkPayload->Direction);
    const std::string localEndpoint = NetworkEndpoint(localAddress, networkPayload->LocalPort);
    const std::string remoteEndpoint = NetworkEndpoint(remoteAddress, networkPayload->RemotePort);
    const std::string sourceEndpoint =
        networkPayload->Direction == KswSandboxNetworkDirectionInbound ? remoteEndpoint : localEndpoint;
    const std::string destinationEndpoint =
        networkPayload->Direction == KswSandboxNetworkDirectionInbound ? localEndpoint : remoteEndpoint;
    const std::string sourceAddress =
        networkPayload->Direction == KswSandboxNetworkDirectionInbound ? remoteAddress : localAddress;
    const std::string destinationAddress =
        networkPayload->Direction == KswSandboxNetworkDirectionInbound ? localAddress : remoteAddress;
    const USHORT sourcePort =
        networkPayload->Direction == KswSandboxNetworkDirectionInbound ? networkPayload->RemotePort : networkPayload->LocalPort;
    const USHORT destinationPort =
        networkPayload->Direction == KswSandboxNetworkDirectionInbound ? networkPayload->LocalPort : networkPayload->RemotePort;
    const std::string flowKey = NetworkFlowKey(
        protocolName,
        localEndpoint,
        remoteEndpoint,
        networkPayload->Direction);
    const USHORT servicePort = networkPayload->Direction == KswSandboxNetworkDirectionInbound
        ? networkPayload->LocalPort
        : networkPayload->RemotePort;
    const std::string serviceHint = NetworkServiceHint(networkPayload->Protocol, servicePort);
    const bool dnsCandidate = serviceHint == "dns";
    const bool httpCandidate = serviceHint == "http";
    const bool tlsCandidate = serviceHint == "tls";
    const bool webCandidate = serviceHint == "http" || serviceHint == "tls" || serviceHint == "web";
    const std::string serviceHintSource = serviceHint == "unknown" ? "unclassified" : "port-protocol";
    const std::string serviceHintConfidence = serviceHint == "unknown" ? "none" : "medium";
    const bool externalAddressCandidate =
        remoteAddressPresent &&
        !remoteAddress.empty() &&
        remoteAddress.rfind("127.", 0) != 0 &&
        remoteAddress != "::1" &&
        remoteAddress != "0.0.0.0";
    const bool lateralMovementCandidate =
        externalAddressCandidate &&
        networkPayload->Protocol == KSWORD_SANDBOX_NETWORK_PROTOCOL_TCP &&
        (servicePort == 135 || servicePort == 139 || servicePort == 445 ||
            servicePort == 3389 || servicePort == 5985 || servicePort == 5986);
    const bool downloadExecuteCandidate = httpCandidate || tlsCandidate;
    const std::string networkEvidenceKind = dnsCandidate
        ? "dns-flow"
        : (httpCandidate
            ? "http-flow"
            : (tlsCandidate
                ? "tls-flow"
                : (lateralMovementCandidate ? "lateral-movement-flow" : "network-flow")));

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUtf8("semanticFamily", "network");
    data->AddUtf8("behaviorLane", "network-flow");
    data->AddUtf8("activityKind", ActivityKind("network", NetworkOperationName(networkPayload->Operation)));
    data->AddUtf8("networkEvidenceKind", networkEvidenceKind);
    data->AddBool("externalAddressCandidate", externalAddressCandidate);
    data->AddBool("lateralMovementCandidate", lateralMovementCandidate);
    data->AddBool("downloadExecuteCandidate", downloadExecuteCandidate);
    data->AddBool("evidenceReady", true);
    data->AddWide(
        "zhMessage",
        dnsCandidate
            ? L"R0 捕获到疑似 DNS 网络流。"
            : (httpCandidate
                ? L"R0 捕获到疑似 HTTP 网络流。"
                : (tlsCandidate
                    ? L"R0 捕获到疑似 TLS/HTTPS 网络流。"
                    : (lateralMovementCandidate ? L"R0 捕获到疑似横向移动端口连接。" : L"R0 捕获到网络连接/授权事件。"))));
    data->AddWide(
        "zhHint",
        lateralMovementCandidate
            ? L"远端端口命中 SMB/RPC/RDP/WinRM 等横向移动常见服务；请结合进程树、凭据/命令行和 PCAP 证据判断。"
            : (remoteAddressPresent
                ? L"该网络事件包含端点和 flowKey，可与 PCAP/DNS/HTTP/TLS sidecar 证据合并成网络关系图。"
                : L"该网络事件缺少远端地址，仍保留 WFP 层/过滤器信息供排障和 ABI 核对。"));
    data->AddUnsigned("networkVersion", networkPayload->Version);
    data->AddUtf8("networkVersionHex", HexUnsignedLongLong(networkPayload->Version, 8));
    data->AddUnsigned("networkPayloadSize", networkPayload->Size);
    data->AddBool(
        "networkPayloadSizeMatchesPublicAbi",
        networkPayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", networkPayload->Operation);
    data->AddUtf8("networkOperationName", NetworkOperationName(networkPayload->Operation));
    data->AddBool("statusPresent", true);
    data->AddUtf8(
        "statusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(networkPayload->Status), 8));
    data->AddUnsigned("protocol", networkPayload->Protocol);
    data->AddUtf8("protocolName", protocolName);
    data->AddUtf8("transportProtocol", protocolName);
    data->AddUnsigned("direction", networkPayload->Direction);
    data->AddUtf8("directionName", directionName);
    data->AddUnsigned("addressFamily", networkPayload->AddressFamily);
    data->AddUtf8("addressFamilyName", NetworkAddressFamilyName(networkPayload->AddressFamily));
    data->AddUnsigned("flags", networkPayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(networkPayload->Flags, 8));
    data->AddUtf8("flagNames", NetworkEventFlagNames(networkPayload->Flags));
    data->AddBool("localAddressPresent", localAddressPresent);
    data->AddBool("remoteAddressPresent", remoteAddressPresent);
    data->AddBool("processIdPresent", processIdPresent);
    data->AddBool("flowHandlePresent", flowHandlePresent);
    data->AddBool("endpointHandlePresent", endpointHandlePresent);
    data->AddBool(
        "inspectionOnly",
        (networkPayload->Flags & KSWORD_SANDBOX_NETWORK_EVENT_FLAG_INSPECTION_ONLY) != 0);
    data->AddUnsigned("processId", networkPayload->ProcessId);
    data->AddUtf8(
        "localAddressHex",
        HexBytes(networkPayload->LocalAddress, KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES, KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES));
    data->AddUtf8(
        "remoteAddressHex",
        HexBytes(networkPayload->RemoteAddress, KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES, KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES));
    data->AddBool("localAddressDecoded", !localAddress.empty());
    data->AddBool("remoteAddressDecoded", !remoteAddress.empty());
    if (!localAddress.empty()) {
        data->AddUtf8("localAddress", localAddress);
    }
    if (!remoteAddress.empty()) {
        data->AddUtf8("remoteAddress", remoteAddress);
    }
    data->AddUnsigned("localPort", networkPayload->LocalPort);
    data->AddUnsigned("remotePort", networkPayload->RemotePort);
    data->AddUtf8("localEndpoint", localEndpoint);
    data->AddUtf8("remoteEndpoint", remoteEndpoint);
    data->AddUtf8("sourceEndpoint", sourceEndpoint);
    data->AddUtf8("destinationEndpoint", destinationEndpoint);
    data->AddUtf8("sourceAddress", sourceAddress);
    data->AddUtf8("destinationAddress", destinationAddress);
    data->AddUnsigned("sourcePort", sourcePort);
    data->AddUnsigned("destinationPort", destinationPort);
    data->AddUtf8("endpointPair", sourceEndpoint + " -> " + destinationEndpoint);
    data->AddUtf8("flowKey", flowKey);
    data->AddUnsigned("flowKeyVersion", 1);
    data->AddUtf8("flowKeyDirection", directionName);
    data->AddUtf8("flowKeySource", "directional-source-destination-endpoints");
    data->AddUtf8("flowKeyScope", "transport-5tuple-lite");
    data->AddUnsigned("servicePort", servicePort);
    data->AddUtf8("serviceHint", serviceHint);
    data->AddUtf8("serviceHintSource", serviceHintSource);
    data->AddUtf8("serviceHintConfidence", serviceHintConfidence);
    data->AddUtf8("serviceHintPolicy", "port-protocol heuristic: 53=dns, 80/8080/8000=http, 443/8443=tls");
    data->AddUtf8("semanticCandidate", serviceHint);
    data->AddBool("dnsCandidate", dnsCandidate);
    data->AddBool("httpCandidate", httpCandidate);
    data->AddBool("tlsCandidate", tlsCandidate);
    data->AddBool("webCandidate", webCandidate);
    data->AddBool("remoteServiceCandidate", externalAddressCandidate && serviceHint != "unknown");
    data->AddBool("smbCandidate", servicePort == 445 || servicePort == 139);
    data->AddBool("rpcCandidate", servicePort == 135);
    data->AddBool("rdpCandidate", servicePort == 3389);
    data->AddBool("winrmCandidate", servicePort == 5985 || servicePort == 5986);
    data->AddBool("serviceHintDns", dnsCandidate);
    data->AddBool("serviceHintHttp", httpCandidate);
    data->AddBool("serviceHintTls", tlsCandidate);
    AddNetworkProtocolBoundaryData(*data, flowKey, serviceHint);
    data->AddUnsigned("layerId", networkPayload->LayerId);
    data->AddUtf8("layerIdHex", HexUnsignedLongLong(networkPayload->LayerId, 4));
    data->AddUnsigned("calloutId", networkPayload->CalloutId);
    data->AddUtf8("calloutIdHex", HexUnsignedLongLong(networkPayload->CalloutId, 8));
    data->AddUnsigned("filterId", networkPayload->FilterId);
    data->AddUtf8("filterIdHex", HexUnsignedLongLong(networkPayload->FilterId, 16));
    data->AddUnsigned("flowHandle", networkPayload->FlowHandle);
    data->AddUtf8("flowHandleHex", HexUnsignedLongLong(networkPayload->FlowHandle, 16));
    data->AddUnsigned("transportEndpointHandle", networkPayload->TransportEndpointHandle);
    data->AddUtf8(
        "transportEndpointHandleHex",
        HexUnsignedLongLong(networkPayload->TransportEndpointHandle, 16));

    return true;
}

// Input: Event category whose payload structure is not yet public, the observed
// payload bytes, and the JSON builder.
// Processing: Records an ABI-pending parser status without inventing field
// offsets.  The caller has already emitted payloadHex for any non-empty payload.
// Return: false because no typed public payload could be parsed.
bool AddAbiPendingPayloadData(
    const char* payloadKind,
    const char* expectedPublicAbiName,
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    data->AddUtf8("typedPayloadKind", payloadKind == nullptr ? "unknown" : payloadKind);
    data->AddUtf8(
        "payloadSchema",
        expectedPublicAbiName == nullptr ? "not-public" : expectedPublicAbiName);
    data->AddUtf8("typedPayloadStatus", "abi-not-public");
    data->AddUnsigned("typedPayloadObservedBytes", static_cast<unsigned long long>(payloadBytes));
    data->AddBool("typedPayloadHasBytes", payload != nullptr && payloadBytes != 0);
    data->AddUtf8(
        "typedPayloadNote",
        "No public payload struct exists in KSwordSandboxDriverIoctl.h; payloadHex is retained.");
    data->AddWide(
        "zhTypedPayloadNote",
        L"KSwordSandboxDriverIoctl.h \u4e2d\u5c1a\u65e0\u516c\u5f00 payload \u7ed3\u6784\uff1b"
        L"\u5df2\u4fdd\u7559 payloadHex \u4f9b\u8bca\u65ad\u3002");
    return false;
}

// Input: Reserved event header, optional payload bytes, and the JSON builder.
// Processing: Names legacy header-only driver-start events and treats any
// reserved payload bytes as opaque so forward compatibility is preserved.
// Return: true when the reserved event was fully represented by header flags;
// false when opaque reserved payload bytes remain unparsed.
bool AddReservedPayloadData(
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    if (data == nullptr) {
        return false;
    }

    const bool isDriverStarted =
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED) != 0;

    data->AddUtf8("typedPayloadKind", "reserved");
    data->AddUnsigned("typedPayloadObservedBytes", static_cast<unsigned long long>(payloadBytes));

    if (isDriverStarted && payloadBytes == 0) {
        data->AddUtf8("payloadSchema", "header-only");
        data->AddUtf8("typedPayloadStatus", "parsed-from-header-flags");
        return true;
    }

    if (payload != nullptr && payloadBytes != 0) {
        data->AddUtf8("payloadSchema", "reserved-opaque");
        data->AddUtf8("typedPayloadStatus", "reserved-payload-opaque");
        return false;
    }

    data->AddUtf8("payloadSchema", "none");
    data->AddUtf8("typedPayloadStatus", "no-payload");
    return true;
}

// Input: One public event header, its payload bytes, and the JSON builder.
// Processing: Dispatches to a typed parser only when the public header exposes a
// payload layout.  Unknown future payload categories keep the common payloadHex
// fallback instead of guessing offsets.
// Return: true when the payload or header-only semantic record was parsed;
// false when callers should rely on payloadHex as the opaque fallback.
bool AddTypedPayloadData(
    const KSWORD_SANDBOX_EVENT_HEADER& header,
    const unsigned char* payload,
    const size_t payloadBytes,
    JsonDataObjectBuilder* data) {
    switch (header.Type) {
    case KswSandboxEventTypeDriverLoad:
        return AddDriverLoadPayloadData(payload, payloadBytes, data);
    case KswSandboxEventTypeProcess:
        return AddProcessPayloadData(payload, payloadBytes, data);
    case KswSandboxEventTypeImage:
        return AddImagePayloadData(payload, payloadBytes, data);
    case KswSandboxEventTypeFile:
        return AddFilePayloadData(payload, payloadBytes, data);
    case KswSandboxEventTypeRegistry:
        return AddRegistryPayloadData(payload, payloadBytes, data);
    case KswSandboxEventTypeNetwork:
        return AddNetworkPayloadData(payload, payloadBytes, data);
    case KswSandboxEventTypeReserved:
        return AddReservedPayloadData(header, payload, payloadBytes, data);
    default:
        return AddAbiPendingPayloadData(
            "unknown",
            "unknown-public-payload",
            payload,
            payloadBytes,
            data);
    }
}

// Input: GET_HEALTH reply plus the byte count returned by DeviceIoControl.
// Processing: Copies every public field into string-valued data entries.
// Return: JSON object text for SandboxEvent.data.
std::string BuildHealthData(const KSWORD_SANDBOX_HEALTH_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    const bool lost = reply.EventsDropped != 0;
    const bool producerMaskFieldsReturned =
        bytesReturned >= static_cast<DWORD>(kHealthReplyProducerMaskBytes) &&
        reply.Size >= kHealthReplyProducerMaskBytes;
    const bool producerMasksAdvertised =
        (reply.Flags & KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE) != 0;
    const bool producerMasksAvailable = producerMasksAdvertised && producerMaskFieldsReturned;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_HEALTH");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_HEALTH);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-health", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", lost);
    data.AddBool("lossObserved", lost);
    data.AddUtf8("loss", lost ? "driver-events-dropped" : "none");
    data.AddBool("backpressure", lost);
    data.AddBool("backpressureObserved", lost);
    data.AddUtf8("backpressureReason", lost ? "events-dropped" : "none");
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("driverState", reply.DriverState);
    data.AddUtf8("driverStateName", DriverStateName(reply.DriverState));
    data.AddUnsigned("flags", reply.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(reply.Flags, 8));
    data.AddUtf8("flagNames", HealthFlagNames(reply.Flags));
    data.AddUnsigned("eventsQueued", reply.EventsQueued);
    data.AddUnsigned("eventsDropped", reply.EventsDropped);
    data.AddUnsigned("lostCount", reply.EventsDropped);
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddUnsigned("nextSequence", reply.NextSequence);
    data.AddUnsigned("sequence", reply.NextSequence);
    data.AddUtf8("sequenceMeaning", "nextSequence");
    data.AddUtf8("sequencePolicy", "NextSequence is a queue snapshot/summary value; event rows carry concrete Sequence values");
    data.AddWide("zhSequencePolicy", L"NextSequence 是队列快照/摘要值；事件行才携带具体事件 Sequence。");
    data.AddBool("producerMasksAdvertised", producerMasksAdvertised);
    data.AddBool("producerMaskFieldsReturned", producerMaskFieldsReturned);
    data.AddBool("producerMasksAvailable", producerMasksAvailable);
    data.AddUtf8(
        "producerMasksCompatibility",
        producerMasksAvailable ? "available" : "legacy-or-not-advertised");
    data.AddUnsigned("producerEnableMask", producerMasksAvailable ? reply.ProducerEnableMask : 0);
    data.AddUtf8("producerEnableMaskHex", HexUnsignedLongLong(producerMasksAvailable ? reply.ProducerEnableMask : 0, 8));
    data.AddUtf8("producerEnableMaskNames", ProducerMaskNames(producerMasksAvailable ? reply.ProducerEnableMask : 0));
    data.AddUnsigned("supportedProducerMask", producerMasksAvailable ? reply.SupportedProducerMask : 0);
    data.AddUtf8("supportedProducerMaskHex", HexUnsignedLongLong(producerMasksAvailable ? reply.SupportedProducerMask : 0, 8));
    data.AddUtf8("supportedProducerMaskNames", ProducerMaskNames(producerMasksAvailable ? reply.SupportedProducerMask : 0));
    data.AddUnsigned("activeProducerMask", producerMasksAvailable ? reply.ActiveProducerMask : 0);
    data.AddUtf8("activeProducerMaskHex", HexUnsignedLongLong(producerMasksAvailable ? reply.ActiveProducerMask : 0, 8));
    data.AddUtf8("activeProducerMaskNames", ProducerMaskNames(producerMasksAvailable ? reply.ActiveProducerMask : 0));
    data.AddUnsigned("failedProducerMask", producerMasksAvailable ? reply.FailedProducerMask : 0);
    data.AddUtf8("failedProducerMaskHex", HexUnsignedLongLong(producerMasksAvailable ? reply.FailedProducerMask : 0, 8));
    data.AddUtf8("failedProducerMaskNames", ProducerMaskNames(producerMasksAvailable ? reply.FailedProducerMask : 0));
    AddProducerRuntimeStateData(
        data,
        producerMasksAvailable,
        producerMasksAvailable ? reply.SupportedProducerMask : 0,
        producerMasksAvailable ? reply.ProducerEnableMask : 0,
        producerMasksAvailable ? reply.ActiveProducerMask : 0,
        producerMasksAvailable ? reply.FailedProducerMask : 0);
    data.AddSigned("lastNtStatus", reply.LastNtStatus);
    data.AddUtf8("lastNtStatusHex", HexUnsignedLongLong(static_cast<unsigned long>(reply.LastNtStatus), 8));
    return data.Build();
}

// Input: GET_CAPABILITIES reply plus byte count returned by DeviceIoControl.
// Processing: Copies the public ABI negotiation fields and producer masks into
// JSON string data entries so Host/WebUI can prove which driver contract was
// negotiated before draining events.
// Return: JSON object text for SandboxEvent.data.
std::string BuildCapabilitiesData(const KSWORD_SANDBOX_CAPABILITIES_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-capabilities", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddUtf8("loss", "none");
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureReason", "none");
    data.AddUnsigned("highWatermark", 0);
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("abiVersionMajor", reply.AbiVersionMajor);
    data.AddUnsigned("abiVersionMinor", reply.AbiVersionMinor);
    data.AddUnsigned("capabilityFlags", reply.CapabilityFlags);
    data.AddUtf8("capabilityFlagsHex", HexUnsignedLongLong(reply.CapabilityFlags, 16));
    data.AddUtf8("capabilityFlagNames", CapabilityFlagNames(reply.CapabilityFlags));
    data.AddBool("getHealthCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH) != 0);
    data.AddBool("pollCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_POLL) != 0);
    data.AddBool("readEventsCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS) != 0);
    data.AddBool("getCapabilitiesCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES) != 0);
    data.AddBool("getStatusCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS) != 0);
    data.AddBool(
        "setProducerEnableMaskCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK) != 0);
    data.AddBool(
        "queueStatusCountersCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS) != 0);
    data.AddBool(
        "producerEnableBitsCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS) != 0);
    data.AddBool(
        "typedEventPayloadsCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS) != 0);
    data.AddBool(
        "eventSchemaNamesCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES) != 0);
    data.AddBool(
        "processCreateExitCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT) != 0);
    data.AddBool("imageLoadCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD) != 0);
    data.AddBool("fileMinifilterCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER) != 0);
    data.AddBool(
        "registryCallbackCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK) != 0);
    data.AddBool("networkWfpAleCapable", (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE) != 0);
    data.AddBool(
        "getNetworkStatusCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS) != 0);
    data.AddBool(
        "eventCommonMetadataCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_COMMON_METADATA) != 0);
    data.AddBool(
        "producerMetadataCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_METADATA) != 0);
    data.AddBool(
        "selfNoiseMetadataCapable",
        (reply.CapabilityFlags & KSWORD_SANDBOX_CAPABILITY_FLAG_SELF_NOISE_METADATA) != 0);
    data.AddUnsigned("supportedProducerMask", reply.SupportedProducerMask);
    data.AddUtf8("supportedProducerMaskHex", HexUnsignedLongLong(reply.SupportedProducerMask, 8));
    data.AddUtf8("supportedProducerMaskNames", ProducerMaskNames(reply.SupportedProducerMask));
    data.AddUnsigned("defaultProducerMask", reply.DefaultProducerMask);
    data.AddUtf8("defaultProducerMaskHex", HexUnsignedLongLong(reply.DefaultProducerMask, 8));
    data.AddUtf8("defaultProducerMaskNames", ProducerMaskNames(reply.DefaultProducerMask));
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUnsigned("eventHeaderVersion", reply.EventHeaderVersion);
    data.AddUnsigned("eventMaxPayloadSize", reply.EventMaxPayloadSize);
    data.AddUnsigned("eventRingCapacity", reply.EventRingCapacity);
    data.AddUnsigned("readEventsReplyHeaderSize", reply.ReadEventsReplyHeaderSize);
    data.AddUnsigned("capabilitiesReplySize", reply.CapabilitiesReplySize);
    data.AddUnsigned("statusReplySize", reply.StatusReplySize);
    data.AddUnsigned("setProducerEnableMaskRequestSize", reply.SetProducerEnableMaskRequestSize);
    data.AddUnsigned("setProducerEnableMaskReplySize", reply.SetProducerEnableMaskReplySize);
    data.AddBool("driverProducerSupported", (reply.SupportedProducerMask & KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER) != 0);
    data.AddBool("processProducerSupported", (reply.SupportedProducerMask & KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS) != 0);
    data.AddBool("imageProducerSupported", (reply.SupportedProducerMask & KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE) != 0);
    data.AddBool("fileProducerSupported", (reply.SupportedProducerMask & KSWORD_SANDBOX_PRODUCER_FLAG_FILE) != 0);
    data.AddBool("registryProducerSupported", (reply.SupportedProducerMask & KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY) != 0);
    data.AddBool("networkProducerSupported", (reply.SupportedProducerMask & KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK) != 0);
    data.AddUtf8("producerRuntimeState", "capabilities-advertised");
    data.AddWide(
        "zhProducerRuntimeHint",
        L"该行仅说明驱动声明支持哪些 producer；实际运行状态请查看 r0collector.driverStatus。");
    return data.Build();
}

// Input: GET_STATUS reply plus byte count returned by DeviceIoControl.
// Processing: Copies current producer mask, queue depth, counters, and last
// driver status into JSON data for operator diagnostics before event draining.
// Return: JSON object text for SandboxEvent.data.
std::string BuildStatusData(const KSWORD_SANDBOX_STATUS_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    const bool lost = reply.TotalEventsDropped != 0 || reply.ProducerDroppedMask != 0;
    const bool atCapacity =
        reply.QueueCapacity != 0 &&
        (reply.QueueDepth >= reply.QueueCapacity || reply.QueueHighWatermark >= reply.QueueCapacity);
    const bool backpressure =
        lost ||
        atCapacity ||
        reply.TotalEventsBackpressured != 0 ||
        reply.ProducerBackpressureMask != 0 ||
        (reply.Flags & KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE) != 0;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_STATUS");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_STATUS);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-status", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", lost);
    data.AddBool("lossObserved", lost);
    data.AddUtf8("loss", lost ? "driver-events-dropped" : "none");
    data.AddBool("backpressure", backpressure);
    data.AddBool("backpressureObserved", backpressure);
    data.AddUtf8(
        "backpressureReason",
        lost
            ? "events-dropped"
            : (atCapacity
                ? "queue-at-capacity"
                : ((reply.TotalEventsBackpressured != 0 || reply.ProducerBackpressureMask != 0)
                    ? "producer-backpressure"
                    : (((reply.Flags & KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE) != 0)
                        ? "queue-backpressure-flag"
                        : "none"))));
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("driverState", reply.DriverState);
    data.AddUtf8("driverStateName", DriverStateName(reply.DriverState));
    data.AddUnsigned("flags", reply.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(reply.Flags, 8));
    data.AddUtf8("flagNames", StatusFlagNames(reply.Flags));
    data.AddUnsigned("queueCapacity", reply.QueueCapacity);
    data.AddUnsigned("queueDepth", reply.QueueDepth);
    data.AddUnsigned("queueHighWatermark", reply.QueueHighWatermark);
    data.AddUnsigned("highWatermark", reply.QueueHighWatermark);
    data.AddUnsigned("producerEnableMask", reply.ProducerEnableMask);
    data.AddUtf8("producerEnableMaskHex", HexUnsignedLongLong(reply.ProducerEnableMask, 8));
    data.AddUtf8("producerEnableMaskNames", ProducerMaskNames(reply.ProducerEnableMask));
    data.AddUnsigned("supportedProducerMask", reply.SupportedProducerMask);
    data.AddUtf8("supportedProducerMaskHex", HexUnsignedLongLong(reply.SupportedProducerMask, 8));
    data.AddUtf8("supportedProducerMaskNames", ProducerMaskNames(reply.SupportedProducerMask));
    data.AddSigned("lastNtStatus", reply.LastNtStatus);
    data.AddUtf8("lastNtStatusHex", HexUnsignedLongLong(static_cast<unsigned long>(reply.LastNtStatus), 8));
    data.AddUnsigned("activeProducerMask", reply.ActiveProducerMask);
    data.AddUtf8("activeProducerMaskHex", HexUnsignedLongLong(reply.ActiveProducerMask, 8));
    data.AddUtf8("activeProducerMaskNames", ProducerMaskNames(reply.ActiveProducerMask));
    data.AddUnsigned("failedProducerMask", reply.FailedProducerMask);
    data.AddUtf8("failedProducerMaskHex", HexUnsignedLongLong(reply.FailedProducerMask, 8));
    data.AddUtf8("failedProducerMaskNames", ProducerMaskNames(reply.FailedProducerMask));
    AddProducerRuntimeStateData(
        data,
        true,
        reply.SupportedProducerMask,
        reply.ProducerEnableMask,
        reply.ActiveProducerMask,
        reply.FailedProducerMask);
    data.AddUnsigned("totalEventsEnqueued", reply.TotalEventsEnqueued);
    data.AddUnsigned("totalEventsDropped", reply.TotalEventsDropped);
    data.AddUnsigned("lostCount", reply.TotalEventsDropped);
    data.AddUnsigned("totalEventsRead", reply.TotalEventsRead);
    data.AddUnsigned("totalEventsSuppressed", reply.TotalEventsSuppressed);
    data.AddUnsigned("nextSequence", reply.NextSequence);
    data.AddUnsigned("sequence", reply.NextSequence);
    data.AddUtf8("sequenceMeaning", "nextSequence");
    data.AddUtf8("sequencePolicy", "NextSequence is a queue snapshot/summary value; event rows carry concrete Sequence values");
    data.AddWide("zhSequencePolicy", L"NextSequence 是队列快照/摘要值；事件行才携带具体事件 Sequence。");
    data.AddUnsigned("totalEventsBackpressured", reply.TotalEventsBackpressured);
    data.AddUnsigned("producerDroppedMask", reply.ProducerDroppedMask);
    data.AddUtf8("producerDroppedMaskHex", HexUnsignedLongLong(reply.ProducerDroppedMask, 8));
    data.AddUtf8("producerDroppedMaskNames", ProducerMaskNames(reply.ProducerDroppedMask));
    data.AddUnsigned("producerSuppressedMask", reply.ProducerSuppressedMask);
    data.AddUtf8("producerSuppressedMaskHex", HexUnsignedLongLong(reply.ProducerSuppressedMask, 8));
    data.AddUtf8("producerSuppressedMaskNames", ProducerMaskNames(reply.ProducerSuppressedMask));
    data.AddUnsigned("producerBackpressureMask", reply.ProducerBackpressureMask);
    data.AddUtf8("producerBackpressureMaskHex", HexUnsignedLongLong(reply.ProducerBackpressureMask, 8));
    data.AddUtf8("producerBackpressureMaskNames", ProducerMaskNames(reply.ProducerBackpressureMask));
    data.AddUnsigned("effectiveProducerMask", reply.EffectiveProducerMask);
    data.AddUtf8("effectiveProducerMaskHex", HexUnsignedLongLong(reply.EffectiveProducerMask, 8));
    data.AddUtf8("effectiveProducerMaskNames", ProducerMaskNames(reply.EffectiveProducerMask));
    data.AddSigned("lastFailureNtStatus", reply.LastFailureNtStatus);
    data.AddUtf8(
        "lastFailureNtStatusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(reply.LastFailureNtStatus), 8));
    data.AddSigned("lastEnqueueFailureStatus", reply.LastEnqueueFailureNtStatus);
    data.AddUtf8(
        "lastEnqueueFailureStatusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(reply.LastEnqueueFailureNtStatus), 8));
    return data.Build();
}

// Input: GET_NETWORK_STATUS reply plus byte count returned by DeviceIoControl.
// Processing: Copies WFP/ALE readiness masks, implementation gaps, counters,
// and error/status fields into a collector-diagnostic JSON object.
// Return: JSON object text for SandboxEvent.data.
std::string BuildNetworkStatusData(const KSWORD_SANDBOX_NETWORK_STATUS_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    const bool active = (reply.Flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_ACTIVE) != 0;
    const bool compileTimeDisabled =
        (reply.Flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_COMPILE_TIME_DISABLED) != 0 ||
        reply.ImplementationLevel == KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_NONE;
    const bool degraded =
        compileTimeDisabled ||
        (reply.Flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_DEGRADED) != 0 ||
        (reply.Flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_QUEUE_FAILURE) != 0 ||
        (reply.Flags & KSWORD_SANDBOX_NETWORK_STATUS_FLAG_CLASSIFY_PAYLOAD_FAILURE) != 0 ||
        reply.LastDegradeReason != KswSandboxNetworkStatusDegradeNone ||
        reply.LastDegradeNtStatus != 0 ||
        reply.RegisterNtStatus != 0 ||
        reply.EngineNtStatus != 0 ||
        reply.QueueFailureCount != 0 ||
        reply.ClassifyPayloadFailureCount != 0;
    const std::string readinessState = degraded ? "degraded" : (active ? "ready" : "degraded");
    const std::string severity = degraded || !active ? "warning" : "info";
    const std::string diagnosticCode = compileTimeDisabled
        ? "network_status_compile_time_disabled"
        : (degraded
            ? "network_status_degraded"
            : (active ? "network_status_ready" : "network_status_inactive"));
    const bool todoRemaining = reply.TodoMask != 0;

    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-network-status", "collector-diagnostic");
    data.AddUtf8("diagnosticStage", "networkStatus");
    data.AddUtf8("diagnosticCode", diagnosticCode);
    data.AddUtf8("severity", severity);
    data.AddUtf8("readinessState", readinessState);
    data.AddUtf8("collectionScope", "r0collector-network-status");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("sampleBehavior", false);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddWide("zhMessage", NetworkStatusZhMessage(active, degraded, compileTimeDisabled));
    data.AddWide("zhHint", NetworkStatusZhHint(active, degraded, compileTimeDisabled, reply.TodoMask));
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", reply.QueueFailureCount != 0);
    data.AddUnsigned("lostCount", reply.QueueFailureCount);
    data.AddBool("lossObserved", reply.QueueFailureCount != 0);
    data.AddUtf8("loss", reply.QueueFailureCount != 0 ? "network-queue-failure" : "none");
    data.AddBool("backpressure", reply.QueueFailureCount != 0);
    data.AddBool("backpressureObserved", reply.QueueFailureCount != 0);
    data.AddUtf8("backpressureReason", reply.QueueFailureCount != 0 ? "network-queue-failure" : "none");
    data.AddUnsigned("highWatermark", 0);

    data.AddBool("networkStatusAvailable", true);
    data.AddBool("getNetworkStatusCapable", true);
    data.AddBool("networkWfpAleCapable", !compileTimeDisabled);
    data.AddBool("networkWfpAleActive", active);
    data.AddBool("networkWfpAleDegraded", degraded);
    data.AddBool("networkWfpAleInspectOnly", reply.ImplementationLevel == KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_ALE_INSPECT_ONLY);
    data.AddBool("networkTodoRemaining", todoRemaining);
    data.AddUtf8("networkStatusCapability", "ioctl-available");
    data.AddUtf8("networkStatusKind", "wfp-ale-runtime-diagnostics");
    data.AddUtf8("networkStatusInterpretation", "collector_readiness_not_sample_behavior");
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("flags", reply.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(reply.Flags, 8));
    data.AddUtf8("flagNames", NetworkStatusFlagNames(reply.Flags));
    data.AddUnsigned("implementationLevel", reply.ImplementationLevel);
    data.AddUtf8("implementationLevelName", NetworkImplementationLevelName(reply.ImplementationLevel));
    data.AddUnsigned("supportedLayerMask", reply.SupportedLayerMask);
    data.AddUtf8("supportedLayerMaskHex", HexUnsignedLongLong(reply.SupportedLayerMask, 8));
    data.AddUtf8("supportedLayerMaskNames", NetworkLayerMaskNames(reply.SupportedLayerMask));
    data.AddUnsigned("lastRegisteredCalloutMask", reply.LastRegisteredCalloutMask);
    data.AddUtf8("lastRegisteredCalloutMaskHex", HexUnsignedLongLong(reply.LastRegisteredCalloutMask, 8));
    data.AddUtf8("lastRegisteredCalloutMaskNames", NetworkLayerMaskNames(reply.LastRegisteredCalloutMask));
    data.AddUnsigned("lastAddedFilterMask", reply.LastAddedFilterMask);
    data.AddUtf8("lastAddedFilterMaskHex", HexUnsignedLongLong(reply.LastAddedFilterMask, 8));
    data.AddUtf8("lastAddedFilterMaskNames", NetworkLayerMaskNames(reply.LastAddedFilterMask));
    data.AddUnsigned("activeLayerMask", reply.ActiveLayerMask);
    data.AddUtf8("activeLayerMaskHex", HexUnsignedLongLong(reply.ActiveLayerMask, 8));
    data.AddUtf8("activeLayerMaskNames", NetworkLayerMaskNames(reply.ActiveLayerMask));
    data.AddUnsigned("todoMask", reply.TodoMask);
    data.AddUtf8("todoMaskHex", HexUnsignedLongLong(reply.TodoMask, 8));
    data.AddUtf8("todoMaskNames", NetworkTodoMaskNames(reply.TodoMask));
    data.AddUtf8("todoMaskMeaning", "remaining-gap-mask-for-ale-inspect-only-coverage");
    data.AddUnsigned("payloadVersion", reply.PayloadVersion);
    data.AddUtf8("payloadVersionHex", HexUnsignedLongLong(reply.PayloadVersion, 8));
    data.AddSigned("lastDegradeReason", reply.LastDegradeReason);
    data.AddUtf8("lastDegradeReasonName", NetworkDegradeReasonName(reply.LastDegradeReason));
    data.AddSigned("lastDegradeNtStatus", reply.LastDegradeNtStatus);
    data.AddUtf8("lastDegradeNtStatusHex", HexUnsignedLongLong(static_cast<unsigned long>(reply.LastDegradeNtStatus), 8));
    data.AddSigned("registerNtStatus", reply.RegisterNtStatus);
    data.AddUtf8("registerNtStatusHex", HexUnsignedLongLong(static_cast<unsigned long>(reply.RegisterNtStatus), 8));
    data.AddSigned("engineNtStatus", reply.EngineNtStatus);
    data.AddUtf8("engineNtStatusHex", HexUnsignedLongLong(static_cast<unsigned long>(reply.EngineNtStatus), 8));
    data.AddUnsigned("classifyCount", reply.ClassifyCount);
    data.AddUnsigned("eventCount", reply.EventCount);
    data.AddUnsigned("queueFailureCount", reply.QueueFailureCount);
    data.AddUnsigned("classifyPayloadFailureCount", reply.ClassifyPayloadFailureCount);
    data.AddUnsigned("lastClassifyLayerId", reply.LastClassifyLayerId);
    data.AddUtf8("lastClassifyLayerIdHex", HexUnsignedLongLong(reply.LastClassifyLayerId, 8));
    data.AddSigned("lastQueueFailureNtStatus", reply.LastQueueFailureNtStatus);
    data.AddUtf8(
        "lastQueueFailureNtStatusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(reply.LastQueueFailureNtStatus), 8));
    data.AddUnsigned("lastQueueFailureLayerId", reply.LastQueueFailureLayerId);
    data.AddUtf8("lastQueueFailureLayerIdHex", HexUnsignedLongLong(reply.LastQueueFailureLayerId, 8));
    data.AddUnsigned("lastClassifyPayloadFailureLayerId", reply.LastClassifyPayloadFailureLayerId);
    data.AddUtf8(
        "lastClassifyPayloadFailureLayerIdHex",
        HexUnsignedLongLong(reply.LastClassifyPayloadFailureLayerId, 8));
    return data.Build();
}

// Input: SET_PRODUCER_ENABLE_MASK reply, byte count, and requested mask.
// Processing: Records requested/previous/effective masks so the final report can
// prove exactly which kernel producers were enabled for this run.
// Return: JSON object text for SandboxEvent.data.
std::string BuildSetProducerEnableMaskData(
    const KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY& reply,
    const DWORD bytesReturned,
    const ULONG requestedEnableMask) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-producer-mask", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddUtf8("loss", "none");
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureReason", "none");
    data.AddUnsigned("highWatermark", 0);
    data.AddUnsigned("requestedEnableMask", requestedEnableMask);
    data.AddUtf8("requestedEnableMaskHex", HexUnsignedLongLong(requestedEnableMask, 8));
    data.AddUtf8("requestedEnableMaskNames", ProducerMaskNames(requestedEnableMask));
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("previousEnableMask", reply.PreviousEnableMask);
    data.AddUtf8("previousEnableMaskHex", HexUnsignedLongLong(reply.PreviousEnableMask, 8));
    data.AddUtf8("previousEnableMaskNames", ProducerMaskNames(reply.PreviousEnableMask));
    data.AddUnsigned("effectiveEnableMask", reply.EffectiveEnableMask);
    data.AddUtf8("effectiveEnableMaskHex", HexUnsignedLongLong(reply.EffectiveEnableMask, 8));
    data.AddUtf8("effectiveEnableMaskNames", ProducerMaskNames(reply.EffectiveEnableMask));
    data.AddUnsigned("supportedProducerMask", reply.SupportedProducerMask);
    data.AddUtf8("supportedProducerMaskHex", HexUnsignedLongLong(reply.SupportedProducerMask, 8));
    data.AddUtf8("supportedProducerMaskNames", ProducerMaskNames(reply.SupportedProducerMask));
    data.AddUnsigned("flags", reply.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(reply.Flags, 8));
    AddProducerRuntimeStateData(
        data,
        true,
        reply.SupportedProducerMask,
        reply.EffectiveEnableMask,
        reply.EffectiveEnableMask,
        0);
    return data.Build();
}

// Input: POLL reply plus the byte count returned by DeviceIoControl.
// Processing: Copies queue snapshot fields into string-valued data entries.
// Return: JSON object text for SandboxEvent.data.
std::string BuildPollData(const KSWORD_SANDBOX_POLL_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    const bool lost = reply.EventsDropped != 0;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_POLL");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_POLL);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-poll", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddBool("lost", lost);
    data.AddBool("lossObserved", lost);
    data.AddUtf8("loss", lost ? "driver-events-dropped" : "none");
    data.AddBool("backpressure", lost);
    data.AddBool("backpressureObserved", lost);
    data.AddUtf8("backpressureReason", lost ? "events-dropped" : "none");
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("driverState", reply.DriverState);
    data.AddUtf8("driverStateName", DriverStateName(reply.DriverState));
    data.AddBool("hasEvents", reply.HasEvents != 0);
    data.AddUnsigned("eventsQueued", reply.EventsQueued);
    data.AddUnsigned("eventsDropped", reply.EventsDropped);
    data.AddUnsigned("lostCount", reply.EventsDropped);
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddUnsigned("nextSequence", reply.NextSequence);
    data.AddUnsigned("sequence", reply.NextSequence);
    data.AddUtf8("sequenceMeaning", "nextSequence");
    data.AddUtf8("sequencePolicy", "NextSequence is a queue snapshot/summary value; event rows carry concrete Sequence values");
    data.AddWide("zhSequencePolicy", L"NextSequence 是队列快照/摘要值；事件行才携带具体事件 Sequence。");
    return data.Build();
}

// Input: READ_EVENTS reply header, byte count, and collector-side batch
// accounting produced while walking the returned event stream.
// Processing: Records batch metadata with the old field names plus concise
// aliases near the front of data so report sampling keeps the most useful
// counters even when many diagnostic fields are present.
// Return: JSON object text for SandboxEvent.data.
std::string BuildReadEventsBatchData(
    const KSWORD_SANDBOX_READ_EVENTS_REPLY& reply,
    const DWORD bytesReturned,
    const unsigned long requestedMaxEvents,
    const DriverReadEventsBatchCounters& counters,
    const unsigned long driverEventSampleStride,
    const bool suppressSelfNoise) {
    JsonDataObjectBuilder data;
    const bool lost = reply.EventsDropped != 0;
    const bool cappedByMaxEvents =
        requestedMaxEvents != 0 && counters.recordsProcessed >= requestedMaxEvents;
    const bool outputBufferFull = bytesReturned >= kReadEventsBufferBytes;
    const bool backpressure = lost || cappedByMaxEvents || outputBufferFull;
    const std::string loss = lost ? "driver-events-dropped" : "none";
    const std::string sampling =
        driverEventSampleStride <= 1
            ? "none"
            : (counters.collectorSkippedEvents == 0 ? "stride:no-skip-in-batch" : "stride:applied");
    const std::string head = counters.hasSequenceRange ? std::to_string(counters.headSequence) : "";
    const std::string tail = counters.hasSequenceRange ? std::to_string(counters.tailSequence) : "";
    const std::string emittedHead =
        counters.hasEmittedSequenceRange ? std::to_string(counters.emittedHeadSequence) : "";
    const std::string emittedTail =
        counters.hasEmittedSequenceRange ? std::to_string(counters.emittedTailSequence) : "";
    unsigned long long sequenceGapEstimate = 0;
    unsigned long long observedSequenceSpan = 0;
    if (counters.hasSequenceRange &&
        counters.recordsProcessed > 0 &&
        counters.tailSequence >= counters.headSequence) {
        observedSequenceSpan = counters.tailSequence - counters.headSequence + 1ULL;
        if (observedSequenceSpan > counters.recordsProcessed) {
            sequenceGapEstimate = observedSequenceSpan - counters.recordsProcessed;
        }
    }
    const bool sequenceGapObserved = sequenceGapEstimate != 0;
    const std::string sequenceGapReason =
        sequenceGapObserved ? "non-contiguous-consumed-driver-sequence" : "none";
    const std::string backpressureSeverity =
        lost ? "loss" : (sequenceGapObserved ? "sequence-gap" : (backpressure ? "bounded-drain" : "none"));

    data.AddUnsigned("requestedMaxEvents", requestedMaxEvents);
    data.AddUnsigned("recordsProcessed", counters.recordsProcessed);
    data.AddUnsigned("eventsEmitted", counters.eventsEmitted);
    data.AddUnsigned("collectorSuppressedEvents", counters.collectorSuppressedEvents);
    data.AddUnsigned("collectorSkippedEvents", counters.collectorSkippedEvents);
    data.AddUnsigned("processed", counters.recordsProcessed);
    data.AddUnsigned("eligible", counters.eligibleEvents);
    data.AddUnsigned("emitted", counters.eventsEmitted);
    data.AddUnsigned("suppressed", counters.collectorSuppressedEvents);
    data.AddUnsigned("skipped", counters.collectorSkippedEvents);
    data.AddUtf8("head", head);
    data.AddUtf8("tail", tail);
    data.AddUnsigned("observedSequenceSpan", observedSequenceSpan);
    data.AddUnsigned("expectedContiguousEvents", counters.recordsProcessed);
    data.AddBool("sequenceGapObserved", sequenceGapObserved);
    data.AddUnsigned("sequenceGapEstimate", sequenceGapEstimate);
    data.AddUtf8("sequenceGapReason", sequenceGapReason);
    data.AddUtf8("sequenceRangeMeaning", "head/tail are consumed event sequences before collector self-noise suppression or sampling accounting");
    data.AddWide("zhSequenceRangeMeaning", L"head/tail 表示本批次已消费的事件 sequence 范围，用于区分真实丢失与 Collector 自身噪声/采样跳过。");
    data.AddUtf8("sampling", sampling);
    data.AddUtf8("loss", sequenceGapObserved && !lost ? "sequence-gap" : loss);
    data.AddUtf8(
        "lossDiagnostic",
        lost ? "driver-drop-counter" : (sequenceGapObserved ? "sequence-gap-estimate" : "none"));
    data.AddUnsigned("eligibleEvents", counters.eligibleEvents);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "driver-read-events-batch", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("eventsWritten", reply.EventsWritten);
    data.AddUnsigned("driverEventSampleStride", driverEventSampleStride);
    data.AddBool("samplingApplied", counters.collectorSkippedEvents != 0);
    data.AddUtf8("headSequence", head);
    data.AddUtf8("tailSequence", tail);
    data.AddUtf8("emittedHeadSequence", emittedHead);
    data.AddUtf8("emittedTailSequence", emittedTail);
    data.AddBool("hasSequenceRange", counters.hasSequenceRange);
    data.AddUtf8(
        "collectorNoisePolicy",
        suppressSelfNoise
            ? (counters.collectorSuppressedEvents == 0 ? "suppress-self-noise" : "suppress-self-noise:applied")
            : "emit-self-noise");
    data.AddBool("noise", false);
    data.AddBool("lost", lost || sequenceGapObserved);
    data.AddBool("lossObserved", lost || sequenceGapObserved);
    data.AddBool("backpressure", backpressure);
    data.AddBool("backpressureObserved", backpressure);
    data.AddUtf8("backpressureSeverity", backpressureSeverity);
    data.AddUtf8(
        "backpressureReason",
        lost ? "events-dropped" : (cappedByMaxEvents ? "requested-max-events-reached" : (outputBufferFull ? "output-buffer-full" : (sequenceGapObserved ? "sequence-gap-without-drop-counter" : "none"))));
    data.AddUtf8(
        "backpressureDiagnostics",
        "lost counter, sequence gap estimate, requested max-events cap, and output-buffer-full are reported independently");
    data.AddWide(
        "zhBackpressureHint",
        backpressure
            ? L"本批次出现丢失、读取上限或输出缓冲区压力；请查看 lostCount、sequenceGapEstimate、requestedMaxEvents 和 highWatermark。"
            : L"本批次未观察到 R0 队列背压或丢失迹象。");
    data.AddBool("cappedByMaxEvents", cappedByMaxEvents);
    data.AddBool("outputBufferFull", outputBufferFull);
    data.AddUnsigned("flags", reply.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(reply.Flags, 8));
    data.AddUnsigned("bytesWritten", reply.BytesWritten);
    data.AddUnsigned("eventsDropped", reply.EventsDropped);
    data.AddUnsigned("lostCount", reply.EventsDropped);
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddUnsigned("nextSequence", reply.NextSequence);
    data.AddUnsigned("sequence", reply.NextSequence);
    data.AddUtf8("sequenceMeaning", "nextSequence");
    data.AddUtf8("sequencePolicy", "NextSequence is a queue snapshot/summary value; event rows carry concrete Sequence values");
    data.AddWide("zhSequencePolicy", L"NextSequence 是队列快照/摘要值；事件行才携带具体事件 Sequence。");
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
    const size_t payloadBytes,
    const DriverEventAttribution& attribution) {
    const size_t payloadPreviewBytes = payloadBytes < kMaxPayloadHexBytes ? payloadBytes : kMaxPayloadHexBytes;
    const std::string driverEventTypeName = DriverEventTypeName(header.Type);
    const bool lost = header.LostEvents != 0;
    const bool backpressure = header.BackpressureEvents != 0;

    JsonDataObjectBuilder data;
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", driverEventTypeName);
    data.AddUtf8("eventOrigin", attribution.eventOrigin);
    data.AddUtf8("producerCategory", attribution.producerCategory);
    data.AddUtf8("subjectKind", attribution.subjectKind);
    data.AddUtf8("actorRole", attribution.actorRole);
    data.AddUtf8("subjectRole", attribution.subjectRole);
    data.AddUtf8("processIdSource", attribution.processIdSource);
    AddConcreteEventSequenceSemantics(data, header.Sequence);
    AddDriverNoiseClassificationFields(data, attribution);
    AddTypedReportCompatibilityData(header, payload, payloadBytes, &data);
    data.AddUtf8("collectorNoisePolicy", attribution.collectorNoisePolicy);
    data.AddBool("noise", attribution.selfNoise);
    data.AddBool("collectorNoise", attribution.collectorNoise);
    data.AddBool("collectorSelfNoise", attribution.collectorNoise);
    data.AddBool("selfProcess", attribution.selfProcess);
    data.AddUtf8("collectorNoiseReason", attribution.collectorNoiseReason);
    data.AddUtf8("collectorNoiseAction", attribution.collectorNoiseAction);
    data.AddBool("selfNoise", attribution.selfNoise);
    data.AddUtf8("selfNoiseReason", attribution.selfNoiseReason);
    data.AddUtf8("selfNoiseAction", attribution.selfNoiseAction);
    data.AddBool("collectorSuppressed", attribution.suppressed);
    data.AddBool("lost", lost);
    data.AddBool("lossObserved", lost);
    data.AddUtf8("loss", lost ? "driver-record-lost-count" : "none");
    data.AddBool("backpressure", backpressure);
    data.AddBool("backpressureObserved", backpressure);
    data.AddUtf8("backpressureReason", backpressure ? "driver-record-backpressure-count" : "none");
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
    data.AddUnsigned("batchIndex", batchIndex);
    data.AddUnsigned("recordOffset", recordOffset);
    data.AddUnsigned("version", header.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(header.Version, 8));
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUnsigned("recordSize", header.Size);
    data.AddUnsigned("driverEventType", header.Type);
    data.AddUtf8("driverEventTypeName", driverEventTypeName);
    data.AddUnsigned("flags", header.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(header.Flags, 8));
    AddDriverEventFlagData(header, &data);
    AddDriverEventCommonMetadata(header, &data);
    data.AddSigned("timestampQpc", header.TimestampQpc.QuadPart);
    data.AddUnsigned("driverProcessId", header.ProcessId);
    data.AddUnsigned("driverThreadId", header.ThreadId);
    data.AddUnsigned("payloadSize", header.PayloadSize);
    data.AddUnsigned("payloadHexBytes", payloadPreviewBytes);
    data.AddBool("payloadTruncated", payloadPreviewBytes < payloadBytes);
    data.AddUtf8("payloadHex", HexBytes(payload, payloadBytes, kMaxPayloadHexBytes));
    const bool typedPayloadParsed = AddTypedPayloadData(header, payload, payloadBytes, &data);
    data.AddBool("typedPayloadParsed", typedPayloadParsed);

    return data.Build();
}

} // namespace KSword::Sandbox::R0Collector
