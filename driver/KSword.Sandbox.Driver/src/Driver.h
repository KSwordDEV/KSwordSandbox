#pragma once

/*
 * Internal driver declarations for the KSword sandbox kernel skeleton.
 *
 * This file is not part of the user-mode collector ABI.  Public IOCTL numbers
 * and record layouts live in include/KSwordSandboxDriverIoctl.h.
 */
#include <fltKernel.h>
#include <KSwordSandboxDriverIoctl.h>

/*
 * Fixed extension signature used as a cheap sanity check before handling IOCTLs.
 * The value is "KSWD" in hexadecimal byte order and is not used for security.
 */
#define KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE 0x4B535744UL

/*
 * READ_EVENTS ring sizing.
 *
 * Inputs : KSWORD_SANDBOX_EVENT_RING_CAPACITY may be overridden at build time
 *          for stress runs; the default is sized for bursty file/registry/image
 *          telemetry without materially increasing non-paged pool pressure.
 * Logic  : keeping the array inside the IoCreateDevice extension places it in
 *          non-paged kernel memory and avoids dynamic allocation in callbacks.
 *          At the current 232-byte event record size, 4096 slots consume about
 *          928 KiB of non-paged memory; the guard rails below prevent accidental
 *          multi-megabyte lab builds.
 * Return : not applicable.
 */
#if !defined(KSWORD_SANDBOX_EVENT_RING_CAPACITY)
#define KSWORD_SANDBOX_EVENT_RING_CAPACITY 4096UL
#endif

#define KSWORD_SANDBOX_EVENT_RING_CAPACITY_MINIMUM 64UL
#define KSWORD_SANDBOX_EVENT_RING_CAPACITY_MAXIMUM 4096UL
#define KSWORD_SANDBOX_EVENT_RING_BACKPRESSURE_PERCENT 75UL
#define KSWORD_SANDBOX_EVENT_RING_BACKPRESSURE_THRESHOLD \
    ((KSWORD_SANDBOX_EVENT_RING_CAPACITY * \
      KSWORD_SANDBOX_EVENT_RING_BACKPRESSURE_PERCENT) / 100UL)

#if KSWORD_SANDBOX_EVENT_RING_CAPACITY < KSWORD_SANDBOX_EVENT_RING_CAPACITY_MINIMUM
#error KSWORD_SANDBOX_EVENT_RING_CAPACITY is below the supported minimum.
#endif

#if KSWORD_SANDBOX_EVENT_RING_CAPACITY > KSWORD_SANDBOX_EVENT_RING_CAPACITY_MAXIMUM
#error KSWORD_SANDBOX_EVENT_RING_CAPACITY is above the supported maximum.
#endif

/*
 * Local minifilter instance metadata.
 *
 * Inputs : used when DriverEntry self-heals the service key before calling
 *          FltRegisterFilter.
 * Logic  : FltMgr requires an Instances key and altitude for non-INF lab
 *          loading; these values keep the minimal driver load path predictable.
 * Return : not applicable.
 */
#define KSWORD_SANDBOX_FILE_FILTER_INSTANCE_KEY_NAME L"Instances"
#define KSWORD_SANDBOX_FILE_FILTER_DEFAULT_INSTANCE_NAME L"KSword Sandbox File Instance"
#define KSWORD_SANDBOX_FILE_FILTER_ALTITUDE_TEXT L"385240"

/*
 * Compile-time producer capability switches.
 *
 * Inputs : build definitions may set individual KSWORD_SANDBOX_ENABLE_* values
 *          to 0 when a lab image wants an explicit "not supported" producer
 *          instead of registering that callback family.
 * Logic  : SupportedProducerMask and GET_CAPABILITIES are derived from the
 *          compiled producer set, so a disabled producer is not advertised as
 *          active or supported.  Runtime registration failures still appear in
 *          FailedProducerMask and LastNtStatus.
 * Return : not applicable.
 */
#if !defined(KSWORD_SANDBOX_ENABLE_PROCESS_CREATE)
#define KSWORD_SANDBOX_ENABLE_PROCESS_CREATE 1
#endif

#if !defined(KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS)
#define KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS 1
#endif

#if !defined(KSWORD_SANDBOX_ENABLE_IMAGE_LOAD)
#define KSWORD_SANDBOX_ENABLE_IMAGE_LOAD 1
#endif

#if !defined(KSWORD_SANDBOX_ENABLE_FILE_MINIFILTER)
#define KSWORD_SANDBOX_ENABLE_FILE_MINIFILTER 1
#endif

#if !defined(KSWORD_SANDBOX_ENABLE_REGISTRY_CALLBACK)
#define KSWORD_SANDBOX_ENABLE_REGISTRY_CALLBACK 1
#endif

#if !defined(KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE)
#define KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE 1
#endif

#define KSWORD_SANDBOX_COMPILED_PRODUCER_MASK \
    (KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER | \
     (KSWORD_SANDBOX_ENABLE_PROCESS_CREATE ? \
        KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS : 0U) | \
     (KSWORD_SANDBOX_ENABLE_PROCESS_CREATE && \
      KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS ? \
        KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS_HANDLE_ACCESS : 0U) | \
     (KSWORD_SANDBOX_ENABLE_IMAGE_LOAD ? \
        KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE : 0U) | \
     (KSWORD_SANDBOX_ENABLE_FILE_MINIFILTER ? \
        KSWORD_SANDBOX_PRODUCER_FLAG_FILE : 0U) | \
     (KSWORD_SANDBOX_ENABLE_REGISTRY_CALLBACK ? \
        KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY : 0U) | \
     (KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE ? \
        KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK : 0U))

/*
 * Internal event record stored in the fixed non-paged ring.
 *
 * Inputs : filled by KswPushEvent from a typed event id, flags, and an optional
 *          payload buffer.
 * Logic  : stores the public header plus bounded inline payload bytes so the
 *          drain path can copy complete records without touching paged memory or
 *          following external pointers.
 * Return : no direct return value; records are dequeued by READ_EVENTS.
 */
typedef struct _KSWORD_SANDBOX_EVENT_RECORD {
    KSWORD_SANDBOX_EVENT_HEADER Header;
    UCHAR Payload[KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE];
} KSWORD_SANDBOX_EVENT_RECORD, *PKSWORD_SANDBOX_EVENT_RECORD;

/*
 * Per-device state.
 *
 * Inputs : allocated by IoCreateDevice as the device extension.
 * Logic  : stores the current lifecycle state, queue counters, and a fixed
 *          event ring under a spin lock so future event producers can update it
 *          safely without allocating paged memory.
 * Return : no direct return value; dispatch handlers copy snapshots into IOCTL
 *          reply structures.
 */
typedef struct _KSWORD_SANDBOX_DEVICE_EXTENSION {
    ULONG Signature;
    ULONG DriverState;
    KSPIN_LOCK StateLock;
    ULONGLONG EventsQueued;
    ULONGLONG TotalEventsQueued;
    ULONGLONG EventsDropped;
    ULONGLONG EventsRead;
    ULONGLONG EventsSuppressed;
    ULONGLONG EventsBackpressured;
    ULONGLONG NextSequence;
    NTSTATUS LastStatus;
    NTSTATUS LastFailureStatus;
    ULONG ProducerEnableMask;
    ULONG SupportedProducerMask;
    ULONG ActiveProducerMask;
    ULONG FailedProducerMask;
    ULONG ProducerDroppedMask;
    ULONG ProducerSuppressedMask;
    ULONG ProducerBackpressureMask;
    ULONG Reserved0;
    ULONG EventReadIndex;
    ULONG EventWriteIndex;
    ULONG EventCount;
    ULONG QueueHighWatermark;
    KSWORD_SANDBOX_EVENT_RECORD EventRing[KSWORD_SANDBOX_EVENT_RING_CAPACITY];
} KSWORD_SANDBOX_DEVICE_EXTENSION, *PKSWORD_SANDBOX_DEVICE_EXTENSION;

/*
 * Immutable snapshot copied from the device extension while holding StateLock.
 *
 * Inputs : populated by KswSnapshotState.
 * Logic  : prevents IOCTL output writers from holding the spin lock while
 *          touching user request buffers.
 * Return : no direct return value.
 */
typedef struct _KSWORD_SANDBOX_STATE_SNAPSHOT {
    ULONG DriverState;
    ULONGLONG EventsQueued;
    ULONGLONG TotalEventsQueued;
    ULONGLONG EventsDropped;
    ULONGLONG EventsRead;
    ULONGLONG EventsSuppressed;
    ULONGLONG EventsBackpressured;
    ULONGLONG NextSequence;
    NTSTATUS LastStatus;
    NTSTATUS LastFailureStatus;
    ULONG ProducerEnableMask;
    ULONG SupportedProducerMask;
    ULONG ActiveProducerMask;
    ULONG FailedProducerMask;
    ULONG ProducerDroppedMask;
    ULONG ProducerSuppressedMask;
    ULONG ProducerBackpressureMask;
    ULONG QueueCapacity;
    ULONG EventCount;
    ULONG QueueHighWatermark;
} KSWORD_SANDBOX_STATE_SNAPSHOT, *PKSWORD_SANDBOX_STATE_SNAPSHOT;

VOID
KswSetLastStatus(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS Status
    );

VOID
KswRecordProducerStatus(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG ProducerMask,
    _In_ NTSTATUS Status
    );

VOID
KswClearProducerActiveMask(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG ProducerMask
    );

VOID
KswInitializeDeviceExtension(
    _Out_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

PKSWORD_SANDBOX_DEVICE_EXTENSION
KswGetDeviceExtension(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    );

VOID
KswSnapshotState(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _Out_ PKSWORD_SANDBOX_STATE_SNAPSHOT Snapshot
    );

NTSTATUS
KswSetProducerEnableMask(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG EnableMask,
    _Out_ PULONG PreviousEnableMask,
    _Out_ PULONG EffectiveEnableMask
    );

NTSTATUS
KswPushEvent(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG EventType,
    _In_ ULONG Flags,
    _In_reads_bytes_opt_(PayloadSize) const VOID* Payload,
    _In_ ULONG PayloadSize
    );

ULONG
KswAdvanceEventRingIndex(
    _In_ ULONG Index
    );

ULONGLONG
KswGetNextReadableSequenceLocked(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

VOID
KswDrainEventHeaders(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _Out_writes_bytes_(EventCapacityBytes) PUCHAR EventBuffer,
    _In_ ULONG EventCapacityBytes,
    _In_ ULONG MaxEvents,
    _In_ ULONGLONG StartingSequence,
    _Out_ PULONG EventsWritten,
    _Out_ PULONG BytesWritten,
    _Out_ PULONGLONG EventsDropped,
    _Out_ PULONGLONG NextSequence
    );

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD KswDriverUnload;
DRIVER_DISPATCH KswDispatchCreateClose;
DRIVER_DISPATCH KswDispatchDeviceControl;
DRIVER_DISPATCH KswDispatchUnsupported;
