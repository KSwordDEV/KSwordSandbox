#include "Driver.h"

/*
 * Advances a fixed-size event ring index by one slot.
 *
 * Inputs : Index is a current EventRing array index.
 * Logic  : increments the index and wraps it to zero when it reaches the fixed
 *          non-paged ring capacity.
 * Return : the next valid EventRing array index.
 */
ULONG
KswAdvanceEventRingIndex(
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

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

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
            KswAdvanceEventRingIndex(DeviceExtension->EventReadIndex);
        (*EventsWritten)++;
    }

    DeviceExtension->EventCount -= *EventsWritten;
    DeviceExtension->EventsQueued = DeviceExtension->EventCount;
    DeviceExtension->EventsRead += *EventsWritten;

    *EventsDropped = DeviceExtension->EventsDropped;
    *NextSequence = KswGetNextReadableSequenceLocked(DeviceExtension);

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
}
