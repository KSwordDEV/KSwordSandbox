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
 * Detects the explicit draft process-handle access payload shape.
 *
 * Inputs : EventType and bounded payload bytes supplied to KswPushEvent.
 * Logic  : checks the public draft Version/Size/Operation prefix so ordinary
 *          process create/exit rows remain gated by the process producer bit.
 * Return : TRUE only for process/thread handle-access draft records.
 */
static
BOOLEAN
KswIsProcessHandleAccessPayload(
    _In_ ULONG EventType,
    _In_reads_bytes_opt_(PayloadSize) const VOID* Payload,
    _In_ ULONG PayloadSize
    )
{
    const KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT*
        accessPayload;

    if (EventType != KswSandboxEventTypeProcess ||
        Payload == NULL ||
        PayloadSize <
            (ULONG)sizeof(KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT)) {
        return FALSE;
    }

    accessPayload =
        (const KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT*)Payload;
    return accessPayload->Version ==
            KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_VERSION &&
        accessPayload->Size ==
            (ULONG)sizeof(KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT) &&
        (accessPayload->Operation ==
                KswSandboxProcessOperationHandleCreateDraft ||
            accessPayload->Operation ==
                KswSandboxProcessOperationHandleDuplicateDraft);
}

/*
 * Maps an event plus optional payload to its producer enable/status bit.
 *
 * Inputs : EventType and payload bytes supplied by a producer.
 * Logic  : process lifecycle and process-handle-access records share the public
 *          event type but use separate producer bits so registration failures
 *          and operator enable masks remain machine-readable.
 * Return : one KSWORD_SANDBOX_PRODUCER_FLAG_* bit.
 */
static
ULONG
KswGetProducerMaskForEvent(
    _In_ ULONG EventType,
    _In_reads_bytes_opt_(PayloadSize) const VOID* Payload,
    _In_ ULONG PayloadSize
    )
{
    if (KswIsProcessHandleAccessPayload(EventType, Payload, PayloadSize)) {
        return KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS_HANDLE_ACCESS;
    }

    return KswGetProducerMaskForEventType(EventType);
}

/*
 * Mirrors typed payload metadata into the common event header.
 *
 * Inputs : Header is the record header being prepared; EventType identifies the
 *          typed payload layout; Payload/PayloadSize are the bounded producer
 *          bytes supplied to KswPushEvent.
 * Logic  : keeps producer modules focused on their native payloads while giving
 *          collectors stable top-level pid/ppid/operation/status/path-presence
 *          hints for indexing, loss accounting, and future self-noise metadata.
 * Return : no return value; unsupported or short payloads leave zero/defaults.
 */
static
VOID
KswPopulateCommonEventMetadata(
    _Inout_ PKSWORD_SANDBOX_EVENT_HEADER Header,
    _In_ ULONG EventType,
    _In_reads_bytes_opt_(PayloadSize) const VOID* Payload,
    _In_ ULONG PayloadSize
    )
{
    ULONG producerMask;

    if (Header == NULL) {
        return;
    }

    producerMask = KswGetProducerMaskForEvent(EventType, Payload, PayloadSize);
    Header->ProducerId = producerMask;
    if (producerMask != 0) {
        Header->Flags |=
            KSWORD_SANDBOX_EVENT_FLAG_PRODUCER_METADATA_PRESENT;
    }
    if ((Header->Flags & KSWORD_SANDBOX_EVENT_FLAG_SELF_NOISE) != 0) {
        Header->ProducerMetadataFlags |=
            KSWORD_SANDBOX_EVENT_METADATA_FLAG_SELF_NOISE;
        Header->Flags |=
            KSWORD_SANDBOX_EVENT_FLAG_PRODUCER_METADATA_PRESENT;
    }

    switch (EventType) {
    case KswSandboxEventTypeDriverLoad:
        Header->Operation = KswSandboxEventTypeDriverLoad;
        Header->Status = STATUS_SUCCESS;
        Header->Flags |=
            KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT |
            KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
        break;

    case KswSandboxEventTypeProcess:
        if (Payload != NULL &&
            PayloadSize >= (ULONG)sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD)) {
            const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD* processPayload;

            processPayload =
                (const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD*)Payload;
            if (KswIsProcessHandleAccessPayload(
                    EventType,
                    Payload,
                    PayloadSize)) {
                const KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT*
                    accessPayload;

                accessPayload =
                    (const KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT*)Payload;
                Header->ProcessId = accessPayload->TargetProcessId;
                Header->Operation = accessPayload->Operation;
                Header->Status = accessPayload->Status;
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT;
                if ((accessPayload->Flags &
                        KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_TARGET_PID_PRESENT) != 0 ||
                    accessPayload->TargetProcessId != 0) {
                    Header->Flags |=
                        KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT;
                }
                if ((accessPayload->Flags &
                        (KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_POST_OPERATION |
                         KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_OPERATION_FAILED)) != 0) {
                    Header->Flags |= KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
                }
                break;
            }

            Header->ProcessId = processPayload->ProcessId;
            Header->ParentProcessId = processPayload->ParentProcessId;
            Header->Operation = processPayload->Operation;
            Header->Status = processPayload->Status;
            Header->Flags |=
                KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT |
                KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT;
            if ((processPayload->Flags &
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT) != 0 ||
                processPayload->ParentProcessId != 0) {
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_PARENT_PID_PRESENT;
            }
            if ((processPayload->Flags &
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT) != 0) {
                Header->Flags |= KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
            }
            if ((processPayload->Flags &
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT) != 0) {
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT;
            }
        }
        break;

    case KswSandboxEventTypeImage:
        if (Payload != NULL &&
            PayloadSize >= (ULONG)sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD)) {
            const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD* imagePayload;

            imagePayload = (const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD*)Payload;
            Header->ProcessId = imagePayload->ProcessId;
            Header->Operation = imagePayload->Operation != 0 ?
                imagePayload->Operation :
                KswSandboxImageOperationLoad;
            Header->Status = STATUS_SUCCESS;
            Header->Flags |=
                KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT |
                KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
            if ((imagePayload->Flags &
                    KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT) != 0 ||
                imagePayload->ProcessId != 0) {
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT;
            }
            if ((imagePayload->Flags &
                    KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT) != 0) {
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT;
            }
        }
        break;

    case KswSandboxEventTypeFile:
        if (Payload != NULL &&
            PayloadSize >= (ULONG)sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD)) {
            const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD* filePayload;

            filePayload = (const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD*)Payload;
            Header->ProcessId = filePayload->ProcessId;
            Header->Operation = filePayload->Operation;
            Header->Status = filePayload->Status;
            Header->Flags |=
                KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT |
                KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT;
            if ((filePayload->Flags &
                    KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT) != 0) {
                Header->Flags |= KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
            }
            if ((filePayload->Flags &
                    KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT) != 0) {
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT;
            }
        }
        break;

    case KswSandboxEventTypeRegistry:
        if (Payload != NULL &&
            PayloadSize >= (ULONG)sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD)) {
            const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD* registryPayload;

            registryPayload =
                (const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD*)Payload;
            Header->ProcessId = registryPayload->ProcessId;
            Header->Operation = registryPayload->Operation;
            Header->Status = registryPayload->Status;
            Header->Flags |=
                KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT |
                KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT;
            if ((registryPayload->Flags &
                    KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_STATUS_PRESENT) != 0) {
                Header->Flags |= KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
            }
            if ((registryPayload->Flags &
                    KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT) != 0) {
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_SUBJECT_PATH_PRESENT;
            }
        }
        break;

    case KswSandboxEventTypeNetwork:
        if (Payload != NULL &&
            PayloadSize >= (ULONG)sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD)) {
            const KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD* networkPayload;

            networkPayload =
                (const KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD*)Payload;
            Header->ProcessId = networkPayload->ProcessId;
            Header->Operation = networkPayload->Operation != 0 ?
                networkPayload->Operation :
                KswSandboxNetworkOperationAleAuthorize;
            Header->Status = networkPayload->Status;
            Header->Flags |=
                KSWORD_SANDBOX_EVENT_FLAG_OPERATION_PRESENT |
                KSWORD_SANDBOX_EVENT_FLAG_STATUS_PRESENT;
            if ((networkPayload->Flags &
                    KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT) != 0 ||
                networkPayload->ProcessId != 0) {
                Header->Flags |=
                    KSWORD_SANDBOX_EVENT_FLAG_TARGET_PID_PRESENT;
            }
        }
        break;

    default:
        break;
    }
}

/*
 * Updates the last internal status reported through GET_HEALTH/GET_STATUS.
 *
 * Inputs : DeviceExtension owns the status field; Status is the newest internal
 *          initialization, producer, or enqueue status to expose to collectors.
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
 * Clears producer active bits without turning a normal stop into a failure.
 *
 * Inputs : DeviceExtension owns the producer bitmaps; ProducerMask names the
 *          producer families being stopped.
 * Logic  : removes the bits from ActiveProducerMask while preserving
 *          FailedProducerMask and LastFailureStatus.  Driver unload uses this
 *          before unregistering callbacks so a concurrent status reader sees a
 *          stopping/deactivated producer instead of a false failure.
 * Return : no return value.
 */
VOID
KswClearProducerActiveMask(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ ULONG ProducerMask
    )
{
    KIRQL oldIrql;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE ||
        ProducerMask == 0) {
        return;
    }

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);
    DeviceExtension->ActiveProducerMask &=
        ~(ProducerMask & DeviceExtension->SupportedProducerMask);
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
 *          overwritten and EventsDropped is incremented.  Validation failures
 *          and producer-mask suppression update the sticky failure status that
 *          GET_STATUS exposes as LastFailureNtStatus/LastEnqueueFailureNtStatus.
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
    ULONG writeIndex;

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

    producerMask = KswGetProducerMaskForEvent(EventType, Payload, PayloadSize);

    RtlZeroMemory(&eventRecord, sizeof(eventRecord));
    eventRecord.Header.Version = KSWORD_SANDBOX_EVENT_HEADER_VERSION;
    eventRecord.Header.Size =
        (ULONG)sizeof(KSWORD_SANDBOX_EVENT_HEADER) + PayloadSize;
    eventRecord.Header.Type = EventType;
    eventRecord.Header.Flags = Flags;
    eventRecord.Header.TimestampQpc = KeQueryPerformanceCounter(NULL);
    KeQuerySystemTime(&eventRecord.Header.TimestampSystemTime);
    eventRecord.Header.ProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    eventRecord.Header.ThreadId = (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
    eventRecord.Header.PayloadSize = PayloadSize;
    eventRecord.Header.Reserved = 0;
    KswPopulateCommonEventMetadata(
        &eventRecord.Header,
        EventType,
        Payload,
        PayloadSize);

    if (PayloadSize != 0) {
        RtlCopyMemory(eventRecord.Payload, Payload, PayloadSize);
    }

    KeAcquireSpinLock(&DeviceExtension->StateLock, &oldIrql);

    if ((DeviceExtension->ProducerEnableMask & producerMask) == 0) {
        DeviceExtension->EventsSuppressed++;
        DeviceExtension->ProducerSuppressedMask |= producerMask;
        DeviceExtension->LastStatus = STATUS_CANCELLED;
        DeviceExtension->LastFailureStatus = STATUS_CANCELLED;
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
        DeviceExtension->LastStatus = STATUS_BUFFER_OVERFLOW;
        DeviceExtension->LastFailureStatus = STATUS_BUFFER_OVERFLOW;
    }

    eventRecord.Header.LostEvents = DeviceExtension->EventsDropped;
    if (eventRecord.Header.LostEvents != 0) {
        eventRecord.Header.Flags |=
            KSWORD_SANDBOX_EVENT_FLAG_LOST_COUNT_PRESENT;
    }

    writeIndex = DeviceExtension->EventWriteIndex;
    DeviceExtension->EventWriteIndex = KswAdvanceEventRingIndex(writeIndex);
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
    eventRecord.Header.BackpressureEvents = DeviceExtension->EventsBackpressured;
    if (DeviceExtension->EventsBackpressured != 0) {
        eventRecord.Header.Flags |=
            KSWORD_SANDBOX_EVENT_FLAG_BACKPRESSURE_COUNT_PRESENT;
    }
    DeviceExtension->EventRing[writeIndex] = eventRecord;
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
    DeviceExtension->SupportedProducerMask = KSWORD_SANDBOX_COMPILED_PRODUCER_MASK;
    DeviceExtension->ProducerEnableMask =
        DeviceExtension->SupportedProducerMask & KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT;
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
