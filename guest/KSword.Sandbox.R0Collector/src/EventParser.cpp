#include "EventParser.h"

#include <algorithm>
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

    const ULONGLONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 16) + ")");
    }
    return names.empty() ? "none" : names;
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
    const ULONG unknownFlags = flags & ~knownFlags;
    if (unknownFlags != 0) {
        appendName("Unknown(" + HexUnsignedLongLong(unknownFlags, 8) + ")");
    }
    return names.empty() ? "none" : names;
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
            return imagePayload->ProcessId != 0 ? imagePayload->ProcessId : fallbackProcessId;
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
        KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED;
    const ULONG unknownFlags = header.Flags & ~knownFlags;
    const bool isSelfTest =
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST) != 0;
    const bool isDriverStarted =
        (header.Flags & KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED) != 0;

    data->AddUtf8("flagNames", DriverEventFlagNames(header.Flags));
    data->AddBool("flagSelfTest", isSelfTest);
    data->AddBool("flagDriverStarted", isDriverStarted);
    data->AddUnsigned("unknownFlags", unknownFlags);
    data->AddUtf8("unknownFlagsHex", HexUnsignedLongLong(unknownFlags, 8));

    if (header.Type == KswSandboxEventTypeDriverLoad && isDriverStarted) {
        data->AddUtf8("driverLoadEventName", "driver.load");
        data->AddUtf8(
            "driverLoadEventDescription",
            "Typed DriverEntry startup heartbeat emitted by the KSword sandbox driver.");
    } else if (header.Type == KswSandboxEventTypeReserved && isDriverStarted) {
        data->AddUtf8("reservedEventName", "driver.started");
        data->AddUtf8(
            "reservedEventDescription",
            "Legacy header-only DriverEntry startup heartbeat emitted with reserved event type.");
    }
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
    const std::wstring filePath = ExtractFilePayloadPath(payload, payloadBytes);

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUnsigned("fileVersion", filePayload->Version);
    data->AddUtf8("fileVersionHex", HexUnsignedLongLong(filePayload->Version, 8));
    data->AddUnsigned("filePayloadSize", filePayload->Size);
    data->AddBool(
        "filePayloadSizeMatchesPublicAbi",
        filePayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", filePayload->Operation);
    data->AddUtf8("operationName", FileOperationName(filePayload->Operation));
    data->AddUnsigned("flags", filePayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(filePayload->Flags, 8));
    data->AddUtf8("flagNames", FileEventFlagNames(filePayload->Flags));
    data->AddBool("pathPresent", pathPresent);
    data->AddBool("pathTruncated", pathTruncated);
    data->AddBool("pathNormalized", pathNormalized);
    data->AddBool("pathFallback", pathFallback);
    data->AddBool("statusPresent", statusPresent);
    data->AddBool("postOperation", postOperation);
    data->AddSigned("status", filePayload->Status);
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
    const std::wstring imagePath = ExtractTypedPayloadPath(
        KswSandboxEventTypeProcess,
        payload,
        payloadBytes);
    const std::wstring commandLine = BoundedWideStringFromUtf16Bytes(
        processPayload->CommandLine,
        processPayload->CommandLineLengthBytes,
        KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS);

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUnsigned("processVersion", processPayload->Version);
    data->AddUtf8("processVersionHex", HexUnsignedLongLong(processPayload->Version, 8));
    data->AddUnsigned("processPayloadSize", processPayload->Size);
    data->AddBool(
        "processPayloadSizeMatchesPublicAbi",
        processPayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", processPayload->Operation);
    data->AddUtf8("operationName", ProcessOperationName(processPayload->Operation));
    data->AddUnsigned("flags", processPayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(processPayload->Flags, 8));
    data->AddUtf8("flagNames", ProcessEventFlagNames(processPayload->Flags));
    data->AddBool(
        "statusPresent",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT) != 0);
    data->AddBool(
        "exCallback",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_EX_CALLBACK) != 0);
    data->AddBool(
        "legacyCallback",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LEGACY_CALLBACK) != 0);
    data->AddBool(
        "parentProcessIdPresent",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT) != 0);
    data->AddBool(
        "creatingProcessIdPresent",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT) != 0);
    data->AddBool(
        "lineageCacheHit",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_CACHE_HIT) != 0);
    data->AddBool(
        "lineageStringsReplayed",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_STRINGS_REPLAYED) != 0);
    data->AddBool(
        "imagePathTruncated",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED) != 0);
    data->AddBool(
        "commandLineTruncated",
        (processPayload->Flags & KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED) != 0);
    data->AddUnsigned("processId", processPayload->ProcessId);
    data->AddUnsigned("parentProcessId", processPayload->ParentProcessId);
    data->AddUnsigned("creatingProcessId", processPayload->CreatingProcessId);
    data->AddSigned("status", processPayload->Status);
    data->AddUtf8(
        "statusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(processPayload->Status), 8));
    data->AddUnsigned("imagePathLengthBytes", processPayload->ImagePathLengthBytes);
    data->AddUnsigned("commandLineLengthBytes", processPayload->CommandLineLengthBytes);
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

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUnsigned("imageVersion", imagePayload->Version);
    data->AddUtf8("imageVersionHex", HexUnsignedLongLong(imagePayload->Version, 8));
    data->AddUnsigned("imagePayloadSize", imagePayload->Size);
    data->AddBool(
        "imagePayloadSizeMatchesPublicAbi",
        imagePayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)));
    data->AddUnsigned("flags", imagePayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(imagePayload->Flags, 8));
    data->AddUtf8("flagNames", ImageEventFlagNames(imagePayload->Flags));
    data->AddBool(
        "systemModeImage",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE) != 0);
    data->AddBool(
        "processIdPresent",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT) != 0);
    data->AddBool(
        "propertiesPresent",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROPERTIES_PRESENT) != 0);
    data->AddBool(
        "imagePathTruncated",
        (imagePayload->Flags & KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED) != 0);
    data->AddUnsigned("processId", imagePayload->ProcessId);
    data->AddUtf8("imageBaseHex", HexUnsignedLongLong(imagePayload->ImageBase, 16));
    data->AddUnsigned("imageBase", imagePayload->ImageBase);
    data->AddUnsigned("imageSize", imagePayload->ImageSize);
    data->AddUnsigned("imageProperties", imagePayload->ImageProperties);
    data->AddUtf8("imagePropertiesHex", HexUnsignedLongLong(imagePayload->ImageProperties, 8));
    data->AddUnsigned("pathLengthBytes", imagePayload->PathLengthBytes);
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

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUnsigned("registryVersion", registryPayload->Version);
    data->AddUtf8("registryVersionHex", HexUnsignedLongLong(registryPayload->Version, 8));
    data->AddUnsigned("registryPayloadSize", registryPayload->Size);
    data->AddBool(
        "registryPayloadSizeMatchesPublicAbi",
        registryPayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)));
    data->AddUnsigned("operation", registryPayload->Operation);
    data->AddUtf8("operationName", RegistryOperationName(registryPayload->Operation));
    data->AddUnsigned("flags", registryPayload->Flags);
    data->AddUtf8("flagsHex", HexUnsignedLongLong(registryPayload->Flags, 8));
    data->AddUtf8("flagNames", RegistryEventFlagNames(registryPayload->Flags));
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
    data->AddSigned("status", registryPayload->Status);
    data->AddUtf8(
        "statusHex",
        HexUnsignedLongLong(static_cast<unsigned long>(registryPayload->Status), 8));
    data->AddUnsigned("processId", registryPayload->ProcessId);
    data->AddUnsigned("valueDataType", registryPayload->ValueDataType);
    data->AddUtf8("valueDataTypeHex", HexUnsignedLongLong(registryPayload->ValueDataType, 8));
    data->AddUnsigned("valueDataSizeBytes", registryPayload->ValueDataSizeBytes);
    data->AddUnsigned("keyPathLengthBytes", registryPayload->KeyPathLengthBytes);
    data->AddUnsigned("valueNameLengthBytes", registryPayload->ValueNameLengthBytes);
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

    data->AddUtf8("typedPayloadStatus", "parsed");
    data->AddUnsigned("networkVersion", networkPayload->Version);
    data->AddUtf8("networkVersionHex", HexUnsignedLongLong(networkPayload->Version, 8));
    data->AddUnsigned("networkPayloadSize", networkPayload->Size);
    data->AddBool(
        "networkPayloadSizeMatchesPublicAbi",
        networkPayload->Size == static_cast<ULONG>(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)));
    data->AddUnsigned("protocol", networkPayload->Protocol);
    data->AddUtf8("protocolName", NetworkProtocolName(networkPayload->Protocol));
    data->AddUnsigned("direction", networkPayload->Direction);
    data->AddUtf8("directionName", NetworkDirectionName(networkPayload->Direction));
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
    data.AddUtf8("flagNames", HealthFlagNames(reply.Flags));
    data.AddUnsigned("eventsQueued", reply.EventsQueued);
    data.AddUnsigned("eventsDropped", reply.EventsDropped);
    data.AddUnsigned("nextSequence", reply.NextSequence);
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
    data.AddUnsigned("version", reply.Version);
    data.AddUtf8("versionHex", HexUnsignedLongLong(reply.Version, 8));
    data.AddUnsigned("size", reply.Size);
    data.AddUnsigned("abiVersionMajor", reply.AbiVersionMajor);
    data.AddUnsigned("abiVersionMinor", reply.AbiVersionMinor);
    data.AddUnsigned("capabilityFlags", reply.CapabilityFlags);
    data.AddUtf8("capabilityFlagsHex", HexUnsignedLongLong(reply.CapabilityFlags, 16));
    data.AddUtf8("capabilityFlagNames", CapabilityFlagNames(reply.CapabilityFlags));
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
    return data.Build();
}

// Input: GET_STATUS reply plus byte count returned by DeviceIoControl.
// Processing: Copies current producer mask, queue depth, counters, and last
// driver status into JSON data for operator diagnostics before event draining.
// Return: JSON object text for SandboxEvent.data.
std::string BuildStatusData(const KSWORD_SANDBOX_STATUS_REPLY& reply, const DWORD bytesReturned) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_GET_STATUS");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_GET_STATUS);
    data.AddUnsigned("bytesReturned", bytesReturned);
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
    data.AddUnsigned("totalEventsEnqueued", reply.TotalEventsEnqueued);
    data.AddUnsigned("totalEventsDropped", reply.TotalEventsDropped);
    data.AddUnsigned("totalEventsRead", reply.TotalEventsRead);
    data.AddUnsigned("totalEventsSuppressed", reply.TotalEventsSuppressed);
    data.AddUnsigned("nextSequence", reply.NextSequence);
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
    const unsigned long requestedMaxEvents,
    const unsigned long long eventsEmitted) {
    JsonDataObjectBuilder data;
    data.AddUtf8("ioctl", "IOCTL_KSWORD_SANDBOX_READ_EVENTS");
    data.AddUnsigned("ioctlCode", IOCTL_KSWORD_SANDBOX_READ_EVENTS);
    data.AddUnsigned("bytesReturned", bytesReturned);
    data.AddUnsigned("requestedMaxEvents", requestedMaxEvents);
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
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUnsigned("recordSize", header.Size);
    data.AddUnsigned("driverEventType", header.Type);
    data.AddUtf8("driverEventTypeName", DriverEventTypeName(header.Type));
    data.AddUnsigned("flags", header.Flags);
    data.AddUtf8("flagsHex", HexUnsignedLongLong(header.Flags, 8));
    AddDriverEventFlagData(header, &data);
    data.AddUnsigned("sequence", header.Sequence);
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
