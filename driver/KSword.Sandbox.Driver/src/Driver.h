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
 * Fixed ring capacity for the initial READ_EVENTS skeleton.
 *
 * Inputs : used by the per-device extension's static EventRing array.
 * Logic  : keeping the array inside the IoCreateDevice extension places it in
 *          non-paged kernel memory and avoids dynamic allocation in dispatch.
 * Return : not applicable; future event producers can raise this cautiously.
 */
#define KSWORD_SANDBOX_EVENT_RING_CAPACITY 64UL

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
    ULONGLONG EventsDropped;
    ULONGLONG NextSequence;
    NTSTATUS LastStatus;
    ULONG EventReadIndex;
    ULONG EventWriteIndex;
    ULONG EventCount;
    ULONG EventReserved;
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
    ULONGLONG EventsDropped;
    ULONGLONG NextSequence;
    NTSTATUS LastStatus;
    ULONG EventCount;
} KSWORD_SANDBOX_STATE_SNAPSHOT, *PKSWORD_SANDBOX_STATE_SNAPSHOT;

/*
 * Runtime state for the minimal file minifilter producer.
 *
 * Inputs : initialized from DriverEntry and read by minifilter callbacks.
 * Logic  : stores the FltMgr filter handle, the existing READ_EVENTS device
 *          extension, and registration/start statuses.  Active gates callback
 *          event emission before the filter is unregistered during unload.
 * Return : no direct return value; failures are summarized through the device
 *          extension LastStatus field exposed by health.
 */
typedef struct _KSWORD_SANDBOX_FILE_FILTER_RUNTIME {
    PFLT_FILTER Filter;
    PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension;
    volatile LONG Active;
    NTSTATUS RegisterStatus;
    NTSTATUS StartStatus;
} KSWORD_SANDBOX_FILE_FILTER_RUNTIME, *PKSWORD_SANDBOX_FILE_FILTER_RUNTIME;

NTSTATUS
KswPushEvent(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG EventType,
    _In_ ULONG Flags,
    _In_reads_bytes_opt_(PayloadSize) const VOID* Payload,
    _In_ ULONG PayloadSize
    );

NTSTATUS
KswInitializeFileFilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

VOID
KswUninitializeFileFilter(
    VOID
    );

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD KswDriverUnload;
DRIVER_DISPATCH KswDispatchCreateClose;
DRIVER_DISPATCH KswDispatchDeviceControl;
DRIVER_DISPATCH KswDispatchUnsupported;
