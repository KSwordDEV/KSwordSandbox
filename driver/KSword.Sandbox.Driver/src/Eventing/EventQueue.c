#include "Driver.h"

/*
 * Maps a public event type to the producer enable bit that controls it.
 *
 * Inputs : EventType is the KSWORD_SANDBOX_EVENT_TYPE value passed to
 *          KswPushEvent.
 * Logic  : centralizes producer gating so existing producer modules do not need
 *          separate enable-mask checks in callback hot paths.
 * Return : one KSWORD_SANDBOX_PRODUCER_FLAG_* bit, or DRIVER for reserved and
 *          driver-lifecycle records.
 */
static
ULONG
KswGetProducerMaskForEventType(
    _In_ ULONG EventType
    )
{
    switch (EventType) {
    case KswSandboxEventTypeProcess:
        return KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS;

    case KswSandboxEventTypeImage:
        return KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE;

    case KswSandboxEventTypeFile:
        return KSWORD_SANDBOX_PRODUCER_FLAG_FILE;

    case KswSandboxEventTypeRegistry:
        return KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY;

    case KswSandboxEventTypeNetwork:
        return KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK;

    case KswSandboxEventTypeDriverLoad:
    case KswSandboxEventTypeReserved:
    default:
        return KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER;
    }
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
    if (NT_SUCCESS(Status)) {
        if (NT_SUCCESS(DeviceExtension->LastStatus)) {
            DeviceExtension->LastStatus = Status;
        }
    } else {
        DeviceExtension->LastStatus = Status;
        DeviceExtension->LastFailureStatus = Status;
    }
    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
}

/*
 * Records whether a producer family reached an active or failed state.
 *
 * Inputs : DeviceExtension owns the producer bitmaps; ProducerMask names one or
 *          more KSWORD_SANDBOX_PRODUCER_FLAG_* bits; Status is that producer's
 *          initialization result.
 * Logic  : success marks producer bits active and clears their failure bits,
 *          while failure marks them failed and stores sticky LastStatus data so
 *          a later successful producer cannot hide an earlier bring-up problem.
 * Return : no return value.
 */
VOID
KswRecordProducerStatus(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG ProducerMask,
    _In_ NTSTATUS Status
    )
{
    KIRQL oldIrql;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE ||
        ProducerMask == 0) {
        return;
    }

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);

    ProducerMask &= DeviceExtension->SupportedProducerMask;
    if (ProducerMask != 0) {
        if (NT_SUCCESS(Status)) {
            DeviceExtension->ActiveProducerMask |= ProducerMask;
            DeviceExtension->FailedProducerMask &= ~ProducerMask;
            if (NT_SUCCESS(DeviceExtension->LastStatus)) {
                DeviceExtension->LastStatus = STATUS_SUCCESS;
            }
        } else {
            DeviceExtension->FailedProducerMask |= ProducerMask;
            DeviceExtension->ActiveProducerMask &= ~ProducerMask;
            DeviceExtension->LastStatus = Status;
            DeviceExtension->LastFailureStatus = Status;
        }
    }

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
}

/*
 * Updates the producer event emission mask.
 *
 * Inputs : DeviceExtension owns the shared mask; EnableMask is the collector's
 *          requested subset; PreviousEnableMask and EffectiveEnableMask receive
 *          the before/after values.
 * Logic  : rejects unsupported bits before taking the spin lock, then updates
 *          the mask atomically with respect to KswPushEvent enqueue checks.
 * Return : STATUS_SUCCESS or STATUS_INVALID_PARAMETER for unsupported bits.
 */
NTSTATUS
KswSetProducerEnableMask(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG EnableMask,
    _Out_ PULONG PreviousEnableMask,
    _Out_ PULONG EffectiveEnableMask
    )
{
    KIRQL oldIrql;

    if (PreviousEnableMask == NULL || EffectiveEnableMask == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *PreviousEnableMask = 0;
    *EffectiveEnableMask = 0;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((EnableMask & ~DeviceExtension->SupportedProducerMask) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);

    *PreviousEnableMask = DeviceExtension->ProducerEnableMask;
    DeviceExtension->ProducerEnableMask = EnableMask;
    *EffectiveEnableMask = DeviceExtension->ProducerEnableMask;
    if (NT_SUCCESS(DeviceExtension->LastStatus)) {
        DeviceExtension->LastStatus = STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);

    return STATUS_SUCCESS;
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
    ULONG producerMask;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (PayloadSize > KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE) {
        KswSetLastStatus(DeviceExtension, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (PayloadSize != 0 && Payload == NULL) {
        KswSetLastStatus(DeviceExtension, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    producerMask = KswGetProducerMaskForEventType(EventType);

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

    if ((DeviceExtension->ProducerEnableMask & producerMask) == 0) {
        DeviceExtension->EventsSuppressed++;
        DeviceExtension->ProducerSuppressedMask |= producerMask;
        KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
        return STATUS_CANCELLED;
    }

    eventRecord.Header.Sequence = DeviceExtension->NextSequence;
    DeviceExtension->NextSequence++;

    if (DeviceExtension->EventCount == KSWORD_SANDBOX_EVENT_RING_CAPACITY) {
        DeviceExtension->EventReadIndex =
            KswAdvanceEventRingIndex(DeviceExtension->EventReadIndex);
        DeviceExtension->EventCount--;
        DeviceExtension->EventsDropped++;
        DeviceExtension->ProducerDroppedMask |= producerMask;
    }

    DeviceExtension->EventRing[DeviceExtension->EventWriteIndex] = eventRecord;
    DeviceExtension->EventWriteIndex =
        KswAdvanceEventRingIndex(DeviceExtension->EventWriteIndex);
    DeviceExtension->EventCount++;
    DeviceExtension->EventsQueued = DeviceExtension->EventCount;
    DeviceExtension->TotalEventsQueued++;
    if (DeviceExtension->EventCount > DeviceExtension->QueueHighWatermark) {
        DeviceExtension->QueueHighWatermark = DeviceExtension->EventCount;
    }
    if (DeviceExtension->EventCount >=
        KSWORD_SANDBOX_EVENT_RING_BACKPRESSURE_THRESHOLD) {
        DeviceExtension->EventsBackpressured++;
        DeviceExtension->ProducerBackpressureMask |= producerMask;
    }
    if (NT_SUCCESS(DeviceExtension->LastStatus)) {
        DeviceExtension->LastStatus = STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);

    return STATUS_SUCCESS;
}

/*
 * Queues the DriverEntry startup self-test event.
 *
 * Inputs : DeviceExtension owns the fixed non-paged ring.
 * Logic  : writes a typed DriverLoad event with SelfTest and DriverStarted
 *          flags.  This is the minimal "driver.started" heartbeat that lets
 *          collectors validate IOCTL framing while preserving a stable payload
 *          layout for ABI tests.
 * Return : no return value.
 */
static
VOID
KswQueueDriverStartedEvent(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD payload;
    static const CHAR buildTag[] = "ksword-r0-v1";

    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    payload.Size = sizeof(payload);
    payload.BootId = 0;
    RtlCopyMemory(payload.BuildTag, buildTag, sizeof(buildTag));

    (VOID)KswPushEvent(
        DeviceExtension,
        KswSandboxEventTypeDriverLoad,
        KSWORD_SANDBOX_EVENT_FLAG_SELF_TEST |
            KSWORD_SANDBOX_EVENT_FLAG_DRIVER_STARTED,
        &payload,
        (ULONG)sizeof(payload));
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
    DeviceExtension->TotalEventsQueued = 0;
    DeviceExtension->EventsDropped = 0;
    DeviceExtension->EventsRead = 0;
    DeviceExtension->EventsSuppressed = 0;
    DeviceExtension->EventsBackpressured = 0;
    DeviceExtension->NextSequence = 1;
    DeviceExtension->LastStatus = STATUS_SUCCESS;
    DeviceExtension->LastFailureStatus = STATUS_SUCCESS;
    DeviceExtension->ProducerEnableMask = KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT;
    DeviceExtension->SupportedProducerMask = KSWORD_SANDBOX_PRODUCER_MASK_CURRENT;
    DeviceExtension->ActiveProducerMask = KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER;
    DeviceExtension->FailedProducerMask = 0;
    DeviceExtension->ProducerDroppedMask = 0;
    DeviceExtension->ProducerSuppressedMask = 0;
    DeviceExtension->ProducerBackpressureMask = 0;
    DeviceExtension->QueueHighWatermark = 0;

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
    Snapshot->TotalEventsQueued = DeviceExtension->TotalEventsQueued;
    Snapshot->EventsDropped = DeviceExtension->EventsDropped;
    Snapshot->EventsRead = DeviceExtension->EventsRead;
    Snapshot->EventsSuppressed = DeviceExtension->EventsSuppressed;
    Snapshot->EventsBackpressured = DeviceExtension->EventsBackpressured;
    Snapshot->NextSequence = KswGetNextReadableSequenceLocked(DeviceExtension);
    Snapshot->LastStatus = DeviceExtension->LastStatus;
    Snapshot->LastFailureStatus = DeviceExtension->LastFailureStatus;
    Snapshot->ProducerEnableMask = DeviceExtension->ProducerEnableMask;
    Snapshot->SupportedProducerMask = DeviceExtension->SupportedProducerMask;
    Snapshot->ActiveProducerMask = DeviceExtension->ActiveProducerMask;
    Snapshot->FailedProducerMask = DeviceExtension->FailedProducerMask;
    Snapshot->ProducerDroppedMask = DeviceExtension->ProducerDroppedMask;
    Snapshot->ProducerSuppressedMask = DeviceExtension->ProducerSuppressedMask;
    Snapshot->ProducerBackpressureMask = DeviceExtension->ProducerBackpressureMask;
    Snapshot->QueueCapacity = KSWORD_SANDBOX_EVENT_RING_CAPACITY;
    Snapshot->EventCount = DeviceExtension->EventCount;
    Snapshot->QueueHighWatermark = DeviceExtension->QueueHighWatermark;

    KeReleaseSpinLock(&DeviceExtension->StateLock, oldIrql);
}
