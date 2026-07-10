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
#include <ntddk.h>
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
 * version.  All current skeleton structures use version 1.0.
 */
#define KSWORD_SANDBOX_INTERFACE_VERSION   0x00010000U
#define KSWORD_SANDBOX_EVENT_HEADER_VERSION 0x00010000U

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
 *          ordering key for loss detection.
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
} KSWORD_SANDBOX_EVENT_HEADER, *PKSWORD_SANDBOX_EVENT_HEADER;

/*
 * Health reply returned by GET_HEALTH.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : The driver fills ABI metadata, current state, queue counters, and the
 *          most recent internal status field known to the skeleton.
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
    ULONG Reserved0;
    ULONGLONG Reserved[4];
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
 * Optional request for READ_EVENTS.
 *
 * Inputs : collectors may pass this at the start of the METHOD_BUFFERED system
 *          buffer.  A zero-length input is also valid for the current skeleton.
 * Logic  : MaxEvents limits the number of records when non-zero.  A zero value
 *          means the driver may return as many complete records as fit.  The
 *          current skeleton validates but otherwise ignores StartingSequence.
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
 * Reserved payload layout for a future KswSandboxEventTypeDriverLoad record.
 *
 * Inputs : output-only payload that follows KSWORD_SANDBOX_EVENT_HEADER.
 * Logic  : BootId is reserved for a later boot/session identifier and BuildTag
 *          is an ASCII, NUL-terminated driver heartbeat marker.  The current
 *          DriverEntry self-test event is header-only and does not emit this
 *          payload yet.
 * Return : not applicable.
 */
typedef struct _KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD {
    ULONG Version;
    ULONG Size;
    ULONGLONG BootId;
    CHAR BuildTag[32];
} KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD, *PKSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD;

/*
 * Reply header for READ_EVENTS.
 *
 * Inputs : output buffer supplied by DeviceIoControl.
 * Logic  : The fixed header is followed by an Events byte stream.  Each record
 *          in that stream starts with KSWORD_SANDBOX_EVENT_HEADER.
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
