#pragma once

/*
 * Public ABI for the KSword sandbox kernel driver.
 *
 * This header is intentionally usable from both kernel-mode code and a
 * user-mode collector.  Kernel builds include ntddk.h for CTL_CODE and base
 * Windows types; user-mode builds include Windows.h so DeviceIoControl callers
 * can consume the same IOCTL numbers and structure layouts.
 */
#if defined(_KERNEL_MODE)
#if !defined(__FLTKERNEL__)
#include <ntddk.h>
#endif
#else
#include <Windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Device names.
 *
 * Kernel code creates \Device\KSwordSandboxDriver and publishes the DOS device
 * link \DosDevices\KSwordSandboxDriver.  User-mode collectors should open the
 * Win32 path \\.\KSwordSandboxDriver with CreateFileW before issuing IOCTLs.
 */
#define KSWORD_SANDBOX_NT_DEVICE_NAME      L"\\Device\\KSwordSandboxDriver"
#define KSWORD_SANDBOX_DOS_DEVICE_NAME     L"\\DosDevices\\KSwordSandboxDriver"
#define KSWORD_SANDBOX_WIN32_DEVICE_NAME   L"\\\\.\\KSwordSandboxDriver"

/*
 * The custom device type is in the vendor-defined range.  Function codes are
 * also in the vendor-defined 0x800-0xFFF range to avoid colliding with Windows
 * system IOCTL definitions.
 */
#define KSWORD_SANDBOX_DEVICE_TYPE         0x8000U
#define KSWORD_SANDBOX_IOCTL_BASE          0x800U

/*
 * Interface and structure versions.
 *
 * The high word is the major ABI version and the low word is the minor ABI
 * version.  All current skeleton structures use version 1.0.  Compatible
 * status additions may reuse reserved reply space without changing the minor
 * version or fixed reply size.  Collectors should first read capabilities,
 * compare the major version, and then gate optional IOCTL use on
 * CapabilityFlags and reply Size.
 *
 * Event payload version policy: every current process/image/registry/file/
 * network payload uses the v1 value 0x00010000.  Producers must continue to
 * stamp that exact value for the fixed v1 layouts below; future field growth
 * needs a new version/capability or an explicit *_DRAFT layout, not silent
 * reuse of the v1 structure with different semantics.
 *
 * Sequence/loss/backpressure policy: producers never block on collector
 * throughput.  Event Sequence, snapshot NextSequence, dropped counters, queue
 * high-watermark, producer loss/backpressure masks, and per-record
 * LostEvents/BackpressureEvents are the stable ABI evidence used by collectors
 * and JSONL smoke tests to diagnose overflow, gaps, and pressure.
 */
#define KSWORD_SANDBOX_ABI_VERSION_MAJOR   1U
#define KSWORD_SANDBOX_ABI_VERSION_MINOR   0U
#define KSWORD_SANDBOX_MAKE_ABI_VERSION(Major, Minor) \
    ((((ULONG)(Major)) << 16) | (((ULONG)(Minor)) & 0xFFFFU))
#define KSWORD_SANDBOX_ABI_VERSION \
    KSWORD_SANDBOX_MAKE_ABI_VERSION( \
        KSWORD_SANDBOX_ABI_VERSION_MAJOR, \
        KSWORD_SANDBOX_ABI_VERSION_MINOR)
#define KSWORD_SANDBOX_INTERFACE_VERSION   KSWORD_SANDBOX_ABI_VERSION
#define KSWORD_SANDBOX_EVENT_HEADER_VERSION KSWORD_SANDBOX_ABI_VERSION
#define KSWORD_SANDBOX_EVENT_SCHEMA_NAME   "ksword.sandbox.r0.event"
#define KSWORD_SANDBOX_EVENT_SCHEMA_VERSION_MAJOR \
    KSWORD_SANDBOX_ABI_VERSION_MAJOR
#define KSWORD_SANDBOX_EVENT_SCHEMA_VERSION_MINOR \
    KSWORD_SANDBOX_ABI_VERSION_MINOR
#define KSWORD_SANDBOX_EVENT_SCHEMA_VERSION \
    KSWORD_SANDBOX_ABI_VERSION

/*
 * IOCTL_KSWORD_SANDBOX_GET_HEALTH
 *   Input : none.
 *   Output: KSWORD_SANDBOX_HEALTH_REPLY.
 *   Return: STATUS_SUCCESS when the output buffer is large enough; otherwise
 *           STATUS_BUFFER_TOO_SMALL or another NTSTATUS failure.
 */
#define IOCTL_KSWORD_SANDBOX_GET_HEALTH \
    CTL_CODE(KSWORD_SANDBOX_DEVICE_TYPE, KSWORD_SANDBOX_IOCTL_BASE + 0x00U, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * IOCTL_KSWORD_SANDBOX_POLL
 *   Input : none.
 *   Output: KSWORD_SANDBOX_POLL_REPLY.
 *   Return: STATUS_SUCCESS with a lightweight queue snapshot.  This is intended
 *           for collector polling before the real event queue exists.
 */
#define IOCTL_KSWORD_SANDBOX_POLL \
    CTL_CODE(KSWORD_SANDBOX_DEVICE_TYPE, KSWORD_SANDBOX_IOCTL_BASE + 0x01U, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * IOCTL_KSWORD_SANDBOX_READ_EVENTS
 *   Input : optional KSWORD_SANDBOX_READ_EVENTS_REQUEST.
 *   Output: KSWORD_SANDBOX_READ_EVENTS_REPLY followed by zero or more event
 *           records, each beginning with KSWORD_SANDBOX_EVENT_HEADER.
 *   Return: STATUS_SUCCESS when the fixed reply header fits.  EventsWritten may
 *           be zero when the queue is empty or the trailing output capacity
 *           cannot hold a complete event record.
 */
#define IOCTL_KSWORD_SANDBOX_READ_EVENTS \
    CTL_CODE(KSWORD_SANDBOX_DEVICE_TYPE, KSWORD_SANDBOX_IOCTL_BASE + 0x02U, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES
 *   Input : none.
 *   Output: KSWORD_SANDBOX_CAPABILITIES_REPLY.
 *   Return: STATUS_SUCCESS when the output buffer is large enough.  Future
 *           collectors should use this as the first negotiated R0 driver ABI
 *           probe and fall back to GET_HEALTH only when an older driver returns
 *           STATUS_INVALID_DEVICE_REQUEST for this IOCTL.
 */
#define IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES \
    CTL_CODE(KSWORD_SANDBOX_DEVICE_TYPE, KSWORD_SANDBOX_IOCTL_BASE + 0x03U, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * IOCTL_KSWORD_SANDBOX_GET_STATUS
 *   Input : none.
 *   Output: KSWORD_SANDBOX_STATUS_REPLY.
 *   Return: STATUS_SUCCESS with lifecycle, enable-mask, active/failed producer
 *           masks, queue-capacity, and total counter state for collector
 *           diagnostics.
 */
#define IOCTL_KSWORD_SANDBOX_GET_STATUS \
    CTL_CODE(KSWORD_SANDBOX_DEVICE_TYPE, KSWORD_SANDBOX_IOCTL_BASE + 0x04U, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK
 *   Input : KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST.
 *   Output: KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY.
 *   Return: STATUS_SUCCESS after updating the producer emission mask, or
 *           STATUS_INVALID_PARAMETER when the request names unsupported bits.
 */
#define IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK \
    CTL_CODE(KSWORD_SANDBOX_DEVICE_TYPE, KSWORD_SANDBOX_IOCTL_BASE + 0x05U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_KSWORD_SANDBOX_SET_ENABLE_MASK \
    IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK

/*
 * IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS
 *   Input : none.
 *   Output: KSWORD_SANDBOX_NETWORK_STATUS_REPLY.
 *   Return: STATUS_SUCCESS with read-only WFP/ALE runtime diagnostics.  This
 *           does not load WFP state by itself and does not imply packet-layer
 *           or DNS/HTTP/TLS payload parsing support.
 */
#define IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS \
    CTL_CODE(KSWORD_SANDBOX_DEVICE_TYPE, KSWORD_SANDBOX_IOCTL_BASE + 0x06U, METHOD_BUFFERED, FILE_READ_DATA)

/*
 * Alias kept for local experiments that used the DrainEvents name.  The public
 * skeleton contract remains IOCTL_KSWORD_SANDBOX_READ_EVENTS.
 */
#define IOCTL_KSWORD_SANDBOX_DRAIN_EVENTS IOCTL_KSWORD_SANDBOX_READ_EVENTS

/*
 * Driver state values reported through health and poll replies.
 */
typedef enum _KSWORD_SANDBOX_DRIVER_STATE {
    KswSandboxDriverStateUnknown = 0,
    KswSandboxDriverStateRunning = 1,
    KswSandboxDriverStateStopping = 2
} KSWORD_SANDBOX_DRIVER_STATE;

/*
 * Health/status/capability flag bits.
 *
 * Inputs : returned by GET_HEALTH, GET_STATUS, and GET_CAPABILITIES replies.
 * Logic  : these bits let collectors detect optional IOCTLs and status meaning
 *          without depending on structure growth in older health/poll replies.
 * Return : not applicable; callers preserve unknown bits.
 */
#define KSWORD_SANDBOX_HEALTH_FLAG_HAS_EVENTS             0x00000001U
#define KSWORD_SANDBOX_HEALTH_FLAG_CAPABILITIES_AVAILABLE 0x00000002U
#define KSWORD_SANDBOX_HEALTH_FLAG_STATUS_AVAILABLE       0x00000004U
#define KSWORD_SANDBOX_HEALTH_FLAG_ENABLE_MASK_AVAILABLE  0x00000008U
#define KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE 0x00000010U

#define KSWORD_SANDBOX_STATUS_FLAG_HAS_EVENTS             0x00000001U
#define KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_PARTIAL      0x00000002U
#define KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_ALL_DISABLED 0x00000004U
#define KSWORD_SANDBOX_STATUS_FLAG_LAST_STATUS_FAILURE    0x00000008U
#define KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE     0x00000010U
#define KSWORD_SANDBOX_STATUS_FLAG_EVENTS_DROPPED         0x00000020U
#define KSWORD_SANDBOX_STATUS_FLAG_EVENTS_SUPPRESSED      0x00000040U
#define KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_DEGRADED     0x00000080U

#define KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH             0x0000000000000001ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_POLL                   0x0000000000000002ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS            0x0000000000000004ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES       0x0000000000000008ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS             0x0000000000000010ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK 0x0000000000000020ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS  0x0000000000000040ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS   0x0000000000000080ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS   0x0000000000000100ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES     0x0000000000000200ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT    0x0000000000000400ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD             0x0000000000000800ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER        0x0000000000001000ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK      0x0000000000002000ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE        0x0000000000004000ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_COMMON_METADATA  0x0000000000008000ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_METADATA      0x0000000000010000ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_SELF_NOISE_METADATA    0x0000000000020000ULL
#define KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS     0x0000000000040000ULL

#define KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT \
    (KSWORD_SANDBOX_CAPABILITY_FLAG_GET_HEALTH | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_POLL | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_READ_EVENTS | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_GET_CAPABILITIES | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_GET_STATUS | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_SET_PRODUCER_ENABLE_MASK | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_QUEUE_STATUS_COUNTERS | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_ENABLE_BITS | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_TYPED_EVENT_PAYLOADS | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_PROCESS_CREATE_EXIT | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_IMAGE_LOAD | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_FILE_MINIFILTER | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_REGISTRY_CALLBACK | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_NETWORK_WFP_ALE | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_COMMON_METADATA | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_PRODUCER_METADATA | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_SELF_NOISE_METADATA | \
     KSWORD_SANDBOX_CAPABILITY_FLAG_GET_NETWORK_STATUS)

/*
 * Producer enable bits.
 *
 * Inputs : used in GET_CAPABILITIES.SupportedProducerMask,
 *          GET_STATUS.ProducerEnableMask, and SET_PRODUCER_ENABLE_MASK input.
 * Logic  : one bit gates enqueue of one public event family.  Disabling a
 *          producer suppresses future KswPushEvent records for that family; it
 *          does not unregister kernel callbacks or clear already queued events.
 * Return : not applicable; collectors must mask requested bits with
 *          SupportedProducerMask before issuing SET_PRODUCER_ENABLE_MASK.
 */
#define KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER    0x00000001U
#define KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS   0x00000002U
#define KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE     0x00000004U
#define KSWORD_SANDBOX_PRODUCER_FLAG_FILE      0x00000008U
#define KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY  0x00000010U
#define KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK   0x00000020U

#define KSWORD_SANDBOX_PRODUCER_MASK_CURRENT \
    (KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER | \
     KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS | \
     KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE | \
     KSWORD_SANDBOX_PRODUCER_FLAG_FILE | \
     KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY | \
     KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK)

#define KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT \
    KSWORD_SANDBOX_PRODUCER_MASK_CURRENT

/*
 * Event type values.
 *
 * The minimal skeleton emits a Reserved event with SelfTest and DriverStarted
 * flags from DriverEntry.  The typed categories are reserved now so later
 * process, image, file, registry, and network producers can join the same
 * READ_EVENTS contract without renumbering.
 */
typedef enum _KSWORD_SANDBOX_EVENT_TYPE {
    KswSandboxEventTypeNone = 0,
    KswSandboxEventTypeDriverLoad = 1,
    KswSandboxEventTypeProcess = 2,
    KswSandboxEventTypeImage = 3,
    KswSandboxEventTypeFile = 4,
    KswSandboxEventTypeRegistry = 5,
    KswSandboxEventTypeNetwork = 6,
    KswSandboxEventTypeReserved = 0xFFFF
} KSWORD_SANDBOX_EVENT_TYPE;

/*
 * Event header flag bits.
 *
 * Inputs : written by the driver in KSWORD_SANDBOX_EVENT_HEADER.Flags.
 * Logic  : SelfTest marks synthetic records and DriverStarted identifies the
 *          reserved startup event queued during DriverEntry initialization.
 * Return : not applicable; collectors treat unknown flags as reserved.
 */
#define KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST       0x00000001U
#define KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED  0x00000002U
#define KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT 0x00000004U
#define KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT  0x00000008U
#define KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT 0x00000010U
#define KSWORD_SANDBOX_EVENT_FLAG_PARENT_PID_PRESENT 0x00000020U
#define KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT 0x00000040U
#define KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT 0x00000080U
#define KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT 0x00000100U
#define KSWORD_SANDBOX_EVENT_FLAG_PRODUCER_METADATA_PRESENT 0x00000200U
#define KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE       0x00000400U

/*
 * Producer metadata flag bits carried in
 * KSWORD_SANDBOX_EVENT_HEADER.ProducerMetadataFlags.
 *
 * Inputs : producers may set these bits through common event metadata.
 * Logic  : v1 reserves an explicit self-noise marker even when a producer elects
 *          to suppress those records before enqueue; collectors can preserve
 *          unknown bits for future producer-specific metadata.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE 0x00000001U

/*
 * File event payload version and operation values.
 *
 * Inputs : written by minifilter callbacks in
 *          KSWORD_SANDBOX_FILE_EVENT_PAYLOAD.Operation.
 * Logic  : operations are stable numeric values instead of IRP major codes so
 *          collectors can parse file telemetry without WDK headers.
 * Return : not applicable; unknown operation values are reserved for future
 *          producer expansion.
 */
#define KSWORD_SANDBOX_FILE_EVENT_VERSION 0x00010000U /* v1 file payload layout */

typedef enum _KSWORD_SANDBOX_FILE_OPERATION {
    KswSandboxFileOperationNone = 0,
    KswSandboxFileOperationCreate = 1,
    KswSandboxFileOperationWrite = 2,
    KswSandboxFileOperationSetInformation = 3,
    KswSandboxFileOperationDelete = 4,
    KswSandboxFileOperationCleanup = 5,
    KswSandboxFileOperationClose = 6,
    KswSandboxFileOperationRead = 7,
    KswSandboxFileOperationRename = 8
} KSWORD_SANDBOX_FILE_OPERATION;

/*
 * File payload flag bits.
 *
 * Inputs : written by the driver in KSWORD_SANDBOX_FILE_EVENT_PAYLOAD.Flags.
 * Logic  : PathPresent means PathLengthBytes and Path contain a bounded UTF-16
 *          string, PathTruncated means the original name did not fit,
 *          PathNormalized means FltMgr provided a normalized name, PathFallback
 *          means the producer fell back to FILE_OBJECT.FileName, and
 *          PostOperation identifies callbacks that captured the final status.
 * Return : not applicable; collectors should treat unknown bits as reserved.
 */
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT     0x00000001U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED   0x00000002U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT   0x00000004U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_POST_OPERATION   0x00000008U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED  0x00000010U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK    0x00000020U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_OPERATION_FAILED 0x00000040U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_DELETE_INTENT    0x00000080U
#define KSWORD_SANDBOX_FILE_EVENT_FLAG_RENAME_INTENT    0x00000100U

/*
 * Bounded UTF-16 path capacity for file payloads.
 *
 * Inputs : used by both driver callbacks and collectors.
 * Logic  : the value keeps KSWORD_SANDBOX_FILE_EVENT_PAYLOAD within the common
 *          KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE limit while still preserving a
 *          useful path prefix for early R0 telemetry.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_FILE_EVENT_PATH_CHARS 44U

/*
 * Process event payload version, operation values, and bounded string sizes.
 *
 * Inputs : process callback producers write Operation and flag fields.
 * Logic  : strings are bounded UTF-16 prefixes so callback paths never allocate
 *          variable-size output records and collectors can parse fixed layouts.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_PROCESS_EVENT_VERSION 0x00010000U /* v1 process payload layout */
#define KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS 24U
#define KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS 12U

typedef enum _KSWORD_SANDBOX_PROCESS_OPERATION {
    KswSandboxProcessOperationNone = 0,
    KswSandboxProcessOperationCreate = 1,
    KswSandboxProcessOperationExit = 2
} KSWORD_SANDBOX_PROCESS_OPERATION;

#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT      0x00000001U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED    0x00000002U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT         0x00000004U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED       0x00000008U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT          0x00000010U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_EX_CALLBACK             0x00000020U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LEGACY_CALLBACK         0x00000040U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT       0x00000080U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT      0x00000100U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_CACHE_HIT       0x00000200U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_STRINGS_REPLAYED 0x00000400U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_FILE_OPEN_NAME_AVAILABLE 0x00000800U
#define KSWORD_SANDBOX_PROCESS_EVENT_FLAG_OPERATION_FAILED        0x00001000U

/*
 * Image-load event payload version and bounded path size.
 *
 * Inputs : image-load callback producers write this fixed payload.
 * Logic  : image base and size are preserved as integer fields, while the image
 *          path is a bounded UTF-16 prefix compatible with READ_EVENTS.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_IMAGE_EVENT_VERSION 0x00010000U /* v1 image payload layout */
#define KSWORD_SANDBOX_IMAGE_PATH_CHARS 40U

typedef enum _KSWORD_SANDBOX_IMAGE_OPERATION {
    KswSandboxImageOperationNone = 0,
    KswSandboxImageOperationLoad = 1
} KSWORD_SANDBOX_IMAGE_OPERATION;

#define KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT       0x00000001U
#define KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED     0x00000002U
#define KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE  0x00000004U
#define KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT 0x00000008U
#define KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROPERTIES_PRESENT 0x00000010U
#define KSWORD_SANDBOX_IMAGE_EVENT_FLAG_MAPPED_TO_ALL_PIDS 0x00000020U
#define KSWORD_SANDBOX_IMAGE_EVENT_FLAG_EXTENDED_INFO_PRESENT 0x00000040U

/*
 * Registry event payload version, operation values, and bounded string sizes.
 *
 * Inputs : registry callback producers write operation, key, and value fields.
 * Logic  : the compact layout prioritizes set/delete persistence evidence while
 *          leaving enough fixed UTF-16 room for Run/Services path prefixes.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_REGISTRY_EVENT_VERSION 0x00010000U /* v1 registry payload layout */
#define KSWORD_SANDBOX_REGISTRY_KEY_PATH_CHARS 28U
#define KSWORD_SANDBOX_REGISTRY_VALUE_NAME_CHARS 14U

typedef enum _KSWORD_SANDBOX_REGISTRY_OPERATION {
    KswSandboxRegistryOperationNone = 0,
    KswSandboxRegistryOperationCreateKey = 1,
    KswSandboxRegistryOperationOpenKey = 2,
    KswSandboxRegistryOperationSetValue = 3,
    KswSandboxRegistryOperationDeleteValue = 4,
    KswSandboxRegistryOperationDeleteKey = 5,
    KswSandboxRegistryOperationRenameKey = 6
} KSWORD_SANDBOX_REGISTRY_OPERATION;

#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT       0x00000001U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED     0x00000002U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT     0x00000004U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TRUNCATED   0x00000008U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_STATUS_PRESENT    0x00000010U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_POST_OPERATION    0x00000020U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_CALLBACK 0x00000040U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_OBJECT   0x00000080U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TYPE_PRESENT 0x00000100U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_SIZE_PRESENT 0x00000200U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_OPERATION_FAILED  0x00000400U
#define KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_DATA_EMPTY  0x00000800U

/*
 * Network event payload version, protocol values, and compact address fields.
 *
 * Inputs : WFP/ALE producers write protocol, direction, addresses, ports, and
 *          optional WFP metadata into KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD.
 * Logic  : protocol values intentionally match IANA IP protocol numbers for
 *          common protocols.  Addresses are 16-byte slots: IPv4 uses bytes
 *          [0..3] and IPv6 uses all 16 bytes.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_NETWORK_EVENT_VERSION 0x00010000U /* v1 network payload layout */
#define KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES 16U

#define KSWORD_SANDBOX_NETWORK_PROTOCOL_ANY 0U
#define KSWORD_SANDBOX_NETWORK_PROTOCOL_ICMP 1U
#define KSWORD_SANDBOX_NETWORK_PROTOCOL_TCP 6U
#define KSWORD_SANDBOX_NETWORK_PROTOCOL_UDP 17U
#define KSWORD_SANDBOX_NETWORK_PROTOCOL_ICMPV6 58U

typedef enum _KSWORD_SANDBOX_NETWORK_DIRECTION {
    KswSandboxNetworkDirectionUnknown = 0,
    KswSandboxNetworkDirectionOutbound = 1,
    KswSandboxNetworkDirectionInbound = 2
} KSWORD_SANDBOX_NETWORK_DIRECTION;

typedef enum _KSWORD_SANDBOX_NETWORK_OPERATION {
    KswSandboxNetworkOperationNone = 0,
    KswSandboxNetworkOperationAleAuthorize = 1
} KSWORD_SANDBOX_NETWORK_OPERATION;

/*
 * Network producer degradation reasons.
 *
 * Inputs : reserved for future status/payload diagnostics around the WFP/ALE
 *          producer.  The current v1 payload does not carry this field, and
 *          GET_STATUS still exposes degradation through FailedProducerMask,
 *          LastNtStatus, and LastFailureNtStatus only.
 * Logic  : values are stable numeric draft labels for the reason a network
 *          producer was unavailable, partially initialized, or unable to emit a
 *          classify event.  A future ABI revision may surface one of these
 *          values explicitly; until then collectors must not infer this field
 *          from the v1 network event payload.
 * Return : not applicable; unknown values are reserved.
 */
typedef enum _KSWORD_SANDBOX_NETWORK_STATUS_DEGRADE_REASON {
    KswSandboxNetworkStatusDegradeNone = 0,
    KswSandboxNetworkStatusDegradeCompileTimeDisabled = 1,
    KswSandboxNetworkStatusDegradeFwpsCalloutRegister = 2,
    KswSandboxNetworkStatusDegradeFwpmEngineOpen = 3,
    KswSandboxNetworkStatusDegradeFwpmTransaction = 4,
    KswSandboxNetworkStatusDegradeFwpmSublayer = 5,
    KswSandboxNetworkStatusDegradeFwpmManagementCallout = 6,
    KswSandboxNetworkStatusDegradeFwpmInspectionFilter = 7,
    KswSandboxNetworkStatusDegradeClassifyPayload = 8,
    KswSandboxNetworkStatusDegradeQueuePush = 9
} KSWORD_SANDBOX_NETWORK_STATUS_DEGRADE_REASON;

#define KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD_DRAFT_VERSION 0x00010001U

/*
 * Network/WFP status IOCTL constants.
 *
 * Inputs : returned by IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS.
 * Logic  : the current implementation level is ALE inspect-only.  The TODO
 *          bits are intentionally machine-readable so readiness gates can show
 *          exactly which WFP/network gaps remain without implying the v1 event
 *          payload already contains packet, stream, flow-context, or protocol
 *          parser evidence.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_NETWORK_STATUS_REPLY_VERSION KSWORD_SANDBOX_ABI_VERSION
#define KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_NONE 0U
#define KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_ALE_INSPECT_ONLY 1U

#define KSWORD_SANDBOX_NETWORK_STATUS_FLAG_COMPILED              0x00000001U
#define KSWORD_SANDBOX_NETWORK_STATUS_FLAG_ACTIVE                0x00000002U
#define KSWORD_SANDBOX_NETWORK_STATUS_FLAG_DEGRADED              0x00000004U
#define KSWORD_SANDBOX_NETWORK_STATUS_FLAG_INSPECT_ONLY          0x00000008U
#define KSWORD_SANDBOX_NETWORK_STATUS_FLAG_QUEUE_FAILURE         0x00000010U
#define KSWORD_SANDBOX_NETWORK_STATUS_FLAG_CLASSIFY_PAYLOAD_FAILURE 0x00000020U
#define KSWORD_SANDBOX_NETWORK_STATUS_FLAG_COMPILE_TIME_DISABLED 0x00000040U

#define KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V4     0x00000001U
#define KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V4 0x00000002U
#define KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V6     0x00000004U
#define KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V6 0x00000008U
#define KSWORD_SANDBOX_NETWORK_WFP_LAYER_MASK_ALE_V1 \
    (KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V4 | \
     KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V4 | \
     KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_CONNECT_V6 | \
     KSWORD_SANDBOX_NETWORK_WFP_LAYER_FLAG_ALE_RECV_ACCEPT_V6)

#define KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PACKET_STREAM_LAYERS 0x00000001U
#define KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FLOW_CONTEXTS        0x00000002U
#define KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FILTER_CONDITIONS    0x00000004U
#define KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PROTOCOL_PAYLOADS    0x00000008U
#define KSWORD_SANDBOX_NETWORK_WFP_TODO_MASK_CURRENT \
    (KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PACKET_STREAM_LAYERS | \
     KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FLOW_CONTEXTS | \
     KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_FILTER_CONDITIONS | \
     KSWORD_SANDBOX_NETWORK_WFP_TODO_FLAG_PROTOCOL_PAYLOADS)

/*
 * Network address family values.
 *
 * Inputs : written before LocalAddress and RemoteAddress are interpreted.
 * Logic  : IPv4 uses the first four bytes of each address array in presentation
 *          order; IPv6 uses all 16 bytes.  Unknown means address bytes are
 *          diagnostic only.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_UNKNOWN 0U
#define KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV4 4U
#define KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV6 6U

/*
 * Network payload flag bits.
 *
 * Inputs : written by the WFP/ALE producer in the network payload Flags field.
 * Logic  : these bits distinguish absent metadata from zero-valued metadata,
 *          such as PID 0 or an unspecified address.
 * Return : not applicable; collectors should preserve unknown bits.
 */
#define KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT  0x00000001U
#define KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT 0x00000002U
#define KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT     0x00000004U
#define KSWORD_SANDBOX_NETWORK_EVENT_FLAG_FLOW_HANDLE_PRESENT    0x00000008U
#define KSWORD_SANDBOX_NETWORK_EVENT_FLAG_ENDPOINT_HANDLE_PRESENT 0x00000010U
#define KSWORD_SANDBOX_NETWORK_EVENT_FLAG_INSPECTION_ONLY        0x00000020U
#define KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PID_PRESENT \
    KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT

/*
 * Maximum payload size for one event returned by READ_EVENTS.
 *
 * Inputs : used by collectors to size stack or heap parsing buffers.
 * Logic  : the initial R0 driver stores compact fixed-size records in a ring,
 *          and this limit keeps the METHOD_BUFFERED drain path predictable.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE 128U

/*
 * Common header placed before every event record returned by READ_EVENTS.
 *
 * Inputs : none directly; this is an output record layout.
 * Logic  : Size describes the complete event record, PayloadSize describes the
 *          bytes after this header, and Sequence gives collectors a stable
 *          ordering key for loss detection.  Fields through Reserved preserve
 *          their v1.0 offsets; the appended common metadata mirrors key fields
 *          from typed payloads so collectors can index pid/ppid/tid,
 *          operation/status, producer, loss, and backpressure without parsing
 *          every payload first.  LostEvents and BackpressureEvents are
 *          per-record evidence aliases; collectors preserve them even when zero
 *          so sequence/lost/backpressure JSONL fields remain schema-stable.
 * Return : not applicable; callers validate Size before reading payload bytes.
 */
typedef struct _KSWORD_SANDBOX_EVENT_HEADER {
    ULONG Version;
    ULONG Size;
    ULONG Type;
    ULONG Flags;
    ULONGLONG Sequence;
    LARGE_INTEGER TimestampQpc;
    ULONGLONG ProcessId;
    ULONGLONG ThreadId;
    ULONG PayloadSize;
    ULONG Reserved;
    ULONGLONG ParentProcessId;
    ULONGLONG LostEvents;
    ULONGLONG BackpressureEvents;
    ULONG Operation;
    LONG Status;
    ULONG ProducerId;
    ULONG ProducerMetadataFlags;
    LARGE_INTEGER TimestampSystemTime;
} KSWORD_SANDBOX_EVENT_HEADER, *PKSWORD_SANDBOX_EVENT_HEADER;

/*
 * Health reply returned by GET_HEALTH.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : The driver fills ABI metadata, current state, queue counters,
 *          producer masks, and the most recent internal status field known to
 *          the skeleton.  Producer mask fields occupy ABI 1.0 reserved space,
 *          so sizeof(KSWORD_SANDBOX_HEALTH_REPLY) remains stable for older
 *          collectors.
 * Return : sizeof(KSWORD_SANDBOX_HEALTH_REPLY) bytes on success.
 */
typedef struct _KSWORD_SANDBOX_HEALTH_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG DriverState;
    ULONG Flags;
    ULONGLONG EventsQueued;
    ULONGLONG EventsDropped;
    ULONGLONG NextSequence;
    LONG LastNtStatus;
    ULONG ProducerEnableMask;
    ULONG SupportedProducerMask;
    ULONG ActiveProducerMask;
    ULONG FailedProducerMask;
    ULONGLONG Reserved[2];
} KSWORD_SANDBOX_HEALTH_REPLY, *PKSWORD_SANDBOX_HEALTH_REPLY;

/*
 * Poll reply returned by POLL.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : The driver returns a cheap queue snapshot so a collector can decide
 *          whether to call READ_EVENTS.
 * Return : sizeof(KSWORD_SANDBOX_POLL_REPLY) bytes on success.
 */
typedef struct _KSWORD_SANDBOX_POLL_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG DriverState;
    ULONG HasEvents;
    ULONGLONG EventsQueued;
    ULONGLONG EventsDropped;
    ULONGLONG NextSequence;
    ULONGLONG Reserved[4];
} KSWORD_SANDBOX_POLL_REPLY, *PKSWORD_SANDBOX_POLL_REPLY;

/*
 * Capabilities reply returned by GET_CAPABILITIES.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : The driver publishes ABI version numbers, supported optional IOCTLs,
 *          producer enable bits, and fixed queue/event layout limits before a
 *          collector commits to newer status or enable-mask calls.
 * Return : sizeof(KSWORD_SANDBOX_CAPABILITIES_REPLY) bytes on success.
 */
typedef struct _KSWORD_SANDBOX_CAPABILITIES_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG AbiVersionMajor;
    ULONG AbiVersionMinor;
    ULONGLONG CapabilityFlags;
    ULONG SupportedProducerMask;
    ULONG DefaultProducerMask;
    ULONG EventHeaderVersion;
    ULONG EventMaxPayloadSize;
    ULONG EventRingCapacity;
    ULONG ReadEventsReplyHeaderSize;
    ULONG CapabilitiesReplySize;
    ULONG StatusReplySize;
    ULONG SetProducerEnableMaskRequestSize;
    ULONG SetProducerEnableMaskReplySize;
    ULONG Reserved0;
    ULONGLONG Reserved[4];
} KSWORD_SANDBOX_CAPABILITIES_REPLY, *PKSWORD_SANDBOX_CAPABILITIES_REPLY;

/*
 * Status reply returned by GET_STATUS.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : The driver returns a stable lifecycle snapshot, current producer
 *          enable mask, active/failed producer registration masks, ring
 *          capacity/depth, and monotonic total counters for enqueued, read,
 *          dropped, suppressed, and queue-backpressure events.  Queue stress
 *          fields are appended only by reusing v1.0 reserved/alignment space:
 *          QueueHighWatermark reports the maximum observed depth, TotalEventsLost
 *          aliases the cumulative dropped/lost count, and
 *          LastEnqueueFailureNtStatus aliases
 *          the sticky LastFailureNtStatus slot for collectors that want enqueue
 *          failure wording without a fixed-size ABI change.  QueueHighWatermark
 *          is the ABI source for collector JSONL `queueHighWatermark` and
 *          `highWatermark`; TotalEventsDropped and ProducerDroppedMask are the
 *          durable loss contract.
 * Return : sizeof(KSWORD_SANDBOX_STATUS_REPLY) bytes on success.
 */
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4201)
#endif
typedef struct _KSWORD_SANDBOX_STATUS_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG DriverState;
    ULONG Flags;
    ULONG QueueCapacity;
    ULONG QueueDepth;
    ULONG QueueHighWatermark;
    ULONG ProducerEnableMask;
    ULONG SupportedProducerMask;
    LONG LastNtStatus;
    ULONG ActiveProducerMask;
    ULONG FailedProducerMask;
    ULONGLONG TotalEventsEnqueued;
    union {
        ULONGLONG TotalEventsDropped;
        ULONGLONG TotalEventsLost;
    };
    ULONGLONG TotalEventsRead;
    ULONGLONG TotalEventsSuppressed;
    ULONGLONG NextSequence;
    ULONGLONG TotalEventsBackpressured;
    ULONG ProducerDroppedMask;
    ULONG ProducerSuppressedMask;
    ULONG ProducerBackpressureMask;
    ULONG EffectiveProducerMask;
    union {
        LONG LastFailureNtStatus;
        LONG LastEnqueueFailureNtStatus;
    };
    ULONG Reserved0;
} KSWORD_SANDBOX_STATUS_REPLY, *PKSWORD_SANDBOX_STATUS_REPLY;
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

/*
 * Read-only WFP/ALE runtime diagnostics returned by
 * IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : exposes machine-readable network readiness evidence without
 *          changing the v1 network event payload.  LastRegisteredCalloutMask
 *          and LastAddedFilterMask preserve partial setup progress after a
 *          non-fatal registration failure; ActiveLayerMask is non-zero only
 *          while the WFP classify path is currently active.  TodoMask is not an
 *          error by itself; it distinguishes ALE inspect-only telemetry from a
 *          full packet/protocol sensor.
 * Return : sizeof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY) bytes on success.
 */
typedef struct _KSWORD_SANDBOX_NETWORK_STATUS_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG ImplementationLevel;
    ULONG SupportedLayerMask;
    ULONG LastRegisteredCalloutMask;
    ULONG LastAddedFilterMask;
    ULONG ActiveLayerMask;
    ULONG TodoMask;
    ULONG PayloadVersion;
    LONG LastDegradeReason;
    LONG LastDegradeNtStatus;
    LONG RegisterNtStatus;
    LONG EngineNtStatus;
    ULONGLONG ClassifyCount;
    ULONGLONG EventCount;
    ULONGLONG QueueFailureCount;
    ULONGLONG ClassifyPayloadFailureCount;
    ULONG LastClassifyLayerId;
    LONG LastQueueFailureNtStatus;
    ULONG LastQueueFailureLayerId;
    ULONG LastClassifyPayloadFailureLayerId;
    ULONGLONG Reserved[3];
} KSWORD_SANDBOX_NETWORK_STATUS_REPLY,
    *PKSWORD_SANDBOX_NETWORK_STATUS_REPLY;

/*
 * Request for SET_PRODUCER_ENABLE_MASK.
 *
 * Inputs : collectors write the Version, Size, and requested EnableMask.
 * Logic  : EnableMask must be a subset of SupportedProducerMask returned by
 *          GET_CAPABILITIES/GET_STATUS.  Flags is reserved and must be zero.
 * Return : not returned directly; the same METHOD_BUFFERED buffer receives
 *          KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY on success.
 */
typedef struct _KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST {
    ULONG Version;
    ULONG Size;
    ULONG EnableMask;
    ULONG Flags;
    ULONGLONG Reserved[4];
} KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST,
    *PKSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST;

/*
 * Reply for SET_PRODUCER_ENABLE_MASK.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : reports the previous and effective masks so collectors can log the
 *          exact transition used for the capture session.
 * Return : sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY) bytes on
 *          success.
 */
typedef struct _KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG PreviousEnableMask;
    ULONG EffectiveEnableMask;
    ULONG SupportedProducerMask;
    ULONG Flags;
    ULONGLONG Reserved[4];
} KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY,
    *PKSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY;

/*
 * Optional request for READ_EVENTS.
 *
 * Inputs : collectors may pass this at the start of the METHOD_BUFFERED system
 *          buffer.  A zero-length input is also valid for the current skeleton.
 * Logic  : MaxEvents limits the number of records when non-zero.  A zero value
 *          means the driver may return as many complete records as fit.  Flags
 *          is reserved and must be zero; producer selection belongs only to
 *          IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK.  The current skeleton
 *          validates but otherwise ignores StartingSequence.
 * Return : not returned directly; the same METHOD_BUFFERED buffer receives
 *          KSWORD_SANDBOX_READ_EVENTS_REPLY on success.
 */
typedef struct _KSWORD_SANDBOX_READ_EVENTS_REQUEST {
    ULONG Version;
    ULONG Size;
    ULONG MaxEvents;
    ULONG Flags;
    ULONGLONG StartingSequence;
    ULONGLONG Reserved[4];
} KSWORD_SANDBOX_READ_EVENTS_REQUEST, *PKSWORD_SANDBOX_READ_EVENTS_REQUEST;

/*
 * Payload layout for the KswSandboxEventTypeDriverLoad startup heartbeat.
 *
 * Inputs : output-only payload that follows KSWORD_SANDBOX_EVENT_HEADER.
 * Logic  : BootId is reserved for a later boot/session identifier and BuildTag
 *          is an ASCII, NUL-terminated driver heartbeat marker emitted from
 *          DriverEntry so collectors can validate typed payload parsing.
 * Return : not applicable.
 */
typedef struct _KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONGLONG BootId;
    CHAR BuildTag[32];
} KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD, *PKSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD;

/*
 * Bounded payload for KswSandboxEventTypeFile.
 *
 * Inputs : output-only payload following KSWORD_SANDBOX_EVENT_HEADER.
 * Logic  : carries a compact file operation, requestor PID, final NTSTATUS when
 *          known, the original IRP major/minor function numbers, and a bounded
 *          UTF-16 path copied from the file object without dynamic allocation.
 *          Version must equal KSWORD_SANDBOX_FILE_EVENT_VERSION and Size must
 *          equal sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD) for this v1 layout.
 * Return : not applicable; Size describes this payload and PathLengthBytes does
 *          not include a trailing NUL terminator.
 */
typedef struct _KSWORD_SANDBOX_FILE_EVENT_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONG Operation;
    ULONG Flags;
    ULONGLONG ProcessId;
    LONG Status;
    ULONG PathLengthBytes;
    ULONG MajorFunction;
    ULONG MinorFunction;
    WCHAR Path[KSWORD_SANDBOX_FILE_EVENT_PATH_CHARS];
} KSWORD_SANDBOX_FILE_EVENT_PAYLOAD, *PKSWORD_SANDBOX_FILE_EVENT_PAYLOAD;

/*
 * Bounded payload for KswSandboxEventTypeProcess.
 *
 * Inputs : output-only payload following KSWORD_SANDBOX_EVENT_HEADER.
 * Logic  : process callbacks preserve key lineage identifiers, optional exit
 *          status, and bounded image/command prefixes without dynamic output.
 *          Version must equal KSWORD_SANDBOX_PROCESS_EVENT_VERSION and Size
 *          must equal sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD) for v1.
 * Return : not applicable.
 */
typedef struct _KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONG Operation;
    ULONG Flags;
    ULONGLONG ProcessId;
    ULONGLONG ParentProcessId;
    ULONGLONG CreatingProcessId;
    LONG Status;
    ULONG ImagePathLengthBytes;
    ULONG CommandLineLengthBytes;
    WCHAR ImagePath[KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS];
    WCHAR CommandLine[KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS];
} KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD, *PKSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD;

/*
 * Bounded payload for KswSandboxEventTypeImage.
 *
 * Inputs : output-only payload following KSWORD_SANDBOX_EVENT_HEADER.
 * Logic  : carries image load address/size/properties, process id, and a
 *          bounded full image name prefix from the image-load callback.
 *          Version must equal KSWORD_SANDBOX_IMAGE_EVENT_VERSION and Size must
 *          equal sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD) for this v1 layout.
 * Return : not applicable.
 */
typedef struct _KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG PathLengthBytes;
    ULONGLONG ProcessId;
    ULONGLONG ImageBase;
    ULONGLONG ImageSize;
    ULONG ImageProperties;
    ULONG Operation;
    WCHAR ImagePath[KSWORD_SANDBOX_IMAGE_PATH_CHARS];
} KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD, *PKSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD;

/*
 * Bounded payload for KswSandboxEventTypeRegistry.
 *
 * Inputs : output-only payload following KSWORD_SANDBOX_EVENT_HEADER.
 * Logic  : registry callbacks preserve operation, status, process id, bounded
 *          key/value names, and set-value type/size metadata for behavior rules
 *          and report evidence.  Version must equal
 *          KSWORD_SANDBOX_REGISTRY_EVENT_VERSION and Size must equal
 *          sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD) for this v1 layout.
 * Return : not applicable.
 */
typedef struct _KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONG Operation;
    ULONG Flags;
    ULONGLONG ProcessId;
    LONG Status;
    ULONG KeyPathLengthBytes;
    ULONG ValueNameLengthBytes;
    ULONG ValueDataType;
    ULONG ValueDataSizeBytes;
    WCHAR KeyPath[KSWORD_SANDBOX_REGISTRY_KEY_PATH_CHARS];
    WCHAR ValueName[KSWORD_SANDBOX_REGISTRY_VALUE_NAME_CHARS];
} KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD, *PKSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD;

/*
 * Bounded payload for KswSandboxEventTypeNetwork.
 *
 * Inputs : output-only payload following KSWORD_SANDBOX_EVENT_HEADER.
 * Logic  : carries a normalized ALE authorization event from the WFP callout
 *          producer.  AddressFamily selects how LocalAddress and RemoteAddress
 *          are interpreted; layer, callout, and filter identifiers are
 *          diagnostic hints for WFP registration correlation.  Version must equal KSWORD_SANDBOX_NETWORK_EVENT_VERSION and Size must equal
 *          sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD) for this v1 layout.
 * Return : not applicable; Size describes this payload and remains bounded by
 *          KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE for READ_EVENTS.
 */
typedef struct _KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONG Protocol;
    ULONG Direction;
    ULONG AddressFamily;
    ULONG Flags;
    ULONGLONG ProcessId;
    ULONG LayerId;
    ULONG CalloutId;
    USHORT LocalPort;
    USHORT RemotePort;
    UCHAR LocalAddress[KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES];
    UCHAR RemoteAddress[KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES];
    ULONGLONG FlowHandle;
    ULONGLONG TransportEndpointHandle;
    ULONGLONG FilterId;
    ULONG Operation;
    LONG Status;
} KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD, *PKSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD;

/*
 * Draft extension for a future network payload revision.
 *
 * Inputs : not emitted by the current driver.  This draft composes the current
 *          v1 payload and appends a machine-readable StatusDegradeReason.
 * Logic  : keeping this as a separate *_DRAFT structure prevents the current
 *          WFP/ALE producer from pretending it already exposes degrade reasons
 *          in event records, while giving collectors and tests a typed layout
 *          target for the next ABI negotiation step.
 * Return : not applicable; parse only when a future capability explicitly
 *          advertises this draft or a promoted successor.
 */
typedef struct _KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD_V2_DRAFT {
    KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD V1;
    ULONG StatusDegradeReason;
    ULONG Reserved0;
} KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD_V2_DRAFT,
    *PKSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD_V2_DRAFT;

/*
 * Reply header for READ_EVENTS.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : The fixed header is followed by an Events byte stream.  Each record
 *          in that stream starts with KSWORD_SANDBOX_EVENT_HEADER.
 *          EventsDropped and NextSequence are the batch-level loss/sequence
 *          summary that lets collectors detect gaps even when no record payload
 *          survives for an overwritten event.
 * Return : At least KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE bytes on
 *          success.  BytesWritten counts only bytes in the trailing Events
 *          stream; IoStatus.Information includes this fixed header plus those
 *          trailing event bytes.
 */
typedef struct _KSWORD_SANDBOX_READ_EVENTS_REPLY {
    ULONG Version;
    ULONG Size;
    ULONG EventsWritten;
    ULONG Flags;
    ULONGLONG BytesWritten;
    ULONGLONG EventsDropped;
    ULONGLONG NextSequence;
    UCHAR Events[ANYSIZE_ARRAY];
} KSWORD_SANDBOX_READ_EVENTS_REPLY, *PKSWORD_SANDBOX_READ_EVENTS_REPLY;

#define KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE \
    ((ULONG)FIELD_OFFSET(KSWORD_SANDBOX_READ_EVENTS_REPLY, Events))

#ifdef __cplusplus
}
#endif
