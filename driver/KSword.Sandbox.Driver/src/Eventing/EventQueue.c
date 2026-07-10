#include "Driver.h"

/*
 * Advances a fixed-size ring index by one slot.
 *
 * Inputs : Index is a current EventRing array index.
 * Logic  : increments the index and wraps it to zero when it reaches the fixed
 *          non-paged ring capacity.
 * Return : the next valid EventRing array index.
 */
static
ULONG
KswAdvanceRingIndex(
    _In_ ULONG Index
    )
{
    Index++;
    if (Index >= KSWORD_SANDBOX_EVENT_RING_CAPACITY) {
        Index = 0;
    }

    return Index;
}

/*
 * Reports the sequence a collector should read next.
 *
 * Inputs : DeviceExtension is protected by StateLock, which must already be
 *          held by the caller.
 * Logic  : when the ring has unread events, returns the oldest unread event
 *          sequence; otherwise returns the next sequence that will be assigned
 *          to a future event.
 * Return : the next readable or future sequence number.
 */
static
ULONGLONG
KswGetNextReadableSequenceLocked(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    if (DeviceExtension->EventCount != 0) {
        return DeviceExtension->EventRing[DeviceExtension->EventReadIndex].Header.Sequence;
    }

    return DeviceExtension->NextSequence;
}

/*
 * Updates the last internal status reported through GET_HEALTH.
 *
 * Inputs : DeviceExtension owns the status field; Status is the newest internal
 *          initialization or producer status to expose to collectors.
 * Logic  : acquires StateLock, updates LastStatus, and releases the lock before
 *          returning so callers do not hold state locks across FltMgr calls.
 * Return : no return value.
 */
VOID
KswSetLastStatus(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS Status
    )
{
    KIRQL oldIrql;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);
    DeviceExtension->LastStatus = Status;
    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
}

/*
 * Queues one bounded event record in the device ring.
 *
 * Inputs : DeviceExtension owns the ring; EventType and Flags describe the
 *          event; Payload is optional caller-owned bytes with PayloadSize.
 * Logic  : validates the bounded payload, prepares the public event header and
 *          inline payload outside the spin lock, then inserts the record under
 *          StateLock.  If the ring is full, the oldest unread event is
 *          overwritten and EventsDropped is incremented.
 * Return : STATUS_SUCCESS on enqueue, STATUS_INVALID_PARAMETER for invalid
 *          inputs, or STATUS_BUFFER_TOO_SMALL for oversized payloads.
 */
NTSTATUS
KswPushEvent(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG EventType,
    _In_ ULONG Flags,
    _In_reads_bytes_opt_(PayloadSize) const VOID* Payload,
    _In_ ULONG PayloadSize
    )
{
    KIRQL oldIrql;
    KSWORD_SANDBOX_EVENT_RECORD eventRecord;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PayloadSize > KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (PayloadSize != 0 && Payload == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&eventRecord, sizeof(eventRecord));
    eventRecord.Header.Version = KSWORD_SANDBOX_EVENT_HEADER_VERSION;
    eventRecord.Header.Size =
        (ULONG)sizeof(KSWORD_SANDBOX_EVENT_HEADER) + PayloadSize;
    eventRecord.Header.Type = EventType;
    eventRecord.Header.Flags = Flags;
    eventRecord.Header.TimestampQpc = KeQueryPerformanceCounter(NULL);
    eventRecord.Header.ProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    eventRecord.Header.ThreadId = (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
    eventRecord.Header.PayloadSize = PayloadSize;
    eventRecord.Header.Reserved = 0;

    if (PayloadSize != 0) {
        RtlCopyMemory(eventRecord.Payload, Payload, PayloadSize);
    }

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);

    eventRecord.Header.Sequence = DeviceExtension->NextSequence;
    DeviceExtension->NextSequence++;

    if (DeviceExtension->EventCount == KSWORD_SANDBOX_EVENT_RING_CAPACITY) {
        DeviceExtension->EventReadIndex =
            KswAdvanceRingIndex(DeviceExtension->EventReadIndex);
        DeviceExtension->EventCount--;
        DeviceExtension->EventsDropped++;
    }

    DeviceExtension->EventRing[DeviceExtension->EventWriteIndex] = eventRecord;
    DeviceExtension->EventWriteIndex =
        KswAdvanceRingIndex(DeviceExtension->EventWriteIndex);
    DeviceExtension->EventCount++;
    DeviceExtension->EventsQueued = DeviceExtension->EventCount;
    DeviceExtension->LastStatus = STATUS_SUCCESS;

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);

    return STATUS_SUCCESS;
}

/*
 * Queues the DriverEntry startup self-test event.
 *
 * Inputs : DeviceExtension owns the fixed non-paged ring.
 * Logic  : writes a header-only Reserved event with SelfTest and DriverStarted
 *          flags.  This is the minimal "driver.started" heartbeat that lets
 *          collectors validate IOCTL framing without requiring a payload parser.
 * Return : no return value.
 */
static
VOID
KswQueueDriverStartedEvent(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    (VOID)KswPushEvent(
        DeviceExtension,
        KswSandboxEventTypeReserved,
        KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST |
            KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED,
        NULL,
        0);
}

/*
 * Drains up to MaxEvents complete records from the ring.
 *
 * Inputs : DeviceExtension owns the ring; EventBuffer points to the trailing
 *          METHOD_BUFFERED output area; EventCapacityBytes is that trailing
 *          capacity; MaxEvents is bounded by output capacity and collector input.
 * Logic  : acquires StateLock, copies complete event records from the oldest
 *          unread slot forward, advances the read index, and updates queue
 *          counters before releasing the lock.  Every record copy is checked
 *          against EventCapacityBytes before touching the output stream.
 * Return : no direct return value; EventsWritten, BytesWritten, EventsDropped,
 *          and NextSequence receive the values that READ_EVENTS reports.
 */
VOID
KswDrainEventHeaders(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _Out_writes_bytes_(EventCapacityBytes) PUCHAR EventBuffer,
    _In_ ULONG EventCapacityBytes,
    _In_ ULONG MaxEvents,
    _Out_ PULONG EventsWritten,
    _Out_ PULONG BytesWritten,
    _Out_ PULONGLONG EventsDropped,
    _Out_ PULONGLONG NextSequence
    )
{
    KIRQL oldIrql;
    ULONG eventLimit;
    ULONG eventIndex;
    PKSWORD_SANDBOX_EVENT_RECORD sourceRecord;

    *EventsWritten = 0;
    *BytesWritten = 0;
    *EventsDropped = 0;
    *NextSequence = 0;

    if (MaxEvents > KSWORD_SANDBOX_EVENT_RING_CAPACITY) {
        MaxEvents = KSWORD_SANDBOX_EVENT_RING_CAPACITY;
    }

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);

    eventLimit = DeviceExtension->EventCount;
    if (eventLimit > MaxEvents) {
        eventLimit = MaxEvents;
    }

    for (eventIndex = 0; eventIndex < eventLimit; eventIndex++) {
        sourceRecord =
            &DeviceExtension->EventRing[DeviceExtension->EventReadIndex];
        if (sourceRecord->Header.Size > EventCapacityBytes - *BytesWritten) {
            break;
        }

        RtlCopyMemory(
            EventBuffer + *BytesWritten,
            &sourceRecord->Header,
            sizeof(sourceRecord->Header));
        *BytesWritten += (ULONG)sizeof(sourceRecord->Header);

        if (sourceRecord->Header.PayloadSize != 0) {
            RtlCopyMemory(
                EventBuffer + *BytesWritten,
                sourceRecord->Payload,
                sourceRecord->Header.PayloadSize);
            *BytesWritten += sourceRecord->Header.PayloadSize;
        }

        DeviceExtension->EventReadIndex =
            KswAdvanceRingIndex(DeviceExtension->EventReadIndex);
        (*EventsWritten)++;
    }

    DeviceExtension->EventCount -= *EventsWritten;
    DeviceExtension->EventsQueued = DeviceExtension->EventCount;

    *EventsDropped = DeviceExtension->EventsDropped;
    *NextSequence = KswGetNextReadableSequenceLocked(DeviceExtension);

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
}

/*
 * Initializes the driver-owned per-device extension.
 *
 * Inputs : DeviceExtension points to the memory allocated by IoCreateDevice.
 * Logic  : zeroes the extension, writes a signature, initializes the spin lock,
 *          marks the skeleton as running, and seeds the event sequence.  The
 *          ring itself lives inside this non-paged device extension.
 * Return : no return value.
 */
VOID
KswInitializeDeviceExtension(
    _Out_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    RtlZeroMemory(DeviceExtension, sizeof(*DeviceExtension));

    DeviceExtension->Signature = KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE;
    DeviceExtension->DriverState = KswSandboxDriverStateRunning;
    DeviceExtension->EventsQueued = 0;
    DeviceExtension->EventsDropped = 0;
    DeviceExtension->NextSequence = 1;
    DeviceExtension->LastStatus = STATUS_SUCCESS;

    KeInitializeSpinLock(&DeviceExtension->StateLock);
    KswQueueDriverStartedEvent(DeviceExtension);
}

/*
 * Copies queue and lifecycle fields into a stable snapshot.
 *
 * Inputs : DeviceExtension supplies current state; Snapshot receives the copy.
 * Logic  : acquires StateLock briefly, copies only primitive fields, and then
 *          releases the lock before any IOCTL output buffer is touched.
 * Return : no return value.
 */
VOID
KswSnapshotState(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _Out_ PKSWORD_SANDBOX_STATE_SNAPSHOT Snapshot
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);

    Snapshot->DriverState = DeviceExtension->DriverState;
    Snapshot->EventsQueued = DeviceExtension->EventsQueued;
    Snapshot->EventsDropped = DeviceExtension->EventsDropped;
    Snapshot->NextSequence = KswGetNextReadableSequenceLocked(DeviceExtension);
    Snapshot->LastStatus = DeviceExtension->LastStatus;
    Snapshot->EventCount = DeviceExtension->EventCount;

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
}
