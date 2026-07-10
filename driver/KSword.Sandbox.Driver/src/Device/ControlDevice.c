#include "Driver.h"

/*
 * Completes an IRP with the supplied status and byte count.
 *
 * Inputs : Irp is the request to complete; Status is the final NTSTATUS;
 *          Information is the number of bytes returned to the caller.
 * Logic  : writes IoStatus, completes the request with IO_NO_INCREMENT, and
 *          returns the same NTSTATUS so dispatch paths can tail-call it.
 * Return : Status.
 */
static
NTSTATUS
KswCompleteIrp(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
    )
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

/*
 * Validates and returns the device extension for an incoming request.
 *
 * Inputs : DeviceObject is the device object supplied to the dispatch routine.
 * Logic  : checks that the object and extension exist and that the extension has
 *          the expected skeleton signature.
 * Return : device extension on success; NULL when the request should fail.
 */
PKSWORD_SANDBOX_DEVICE_EXTENSION
KswGetDeviceExtension(
    _In_opt_ PDEVICE_OBJECT DeviceObject
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;

    if (DeviceObject == NULL || DeviceObject->DeviceExtension == NULL) {
        return NULL;
    }

    deviceExtension =
        (PKSWORD_SANDBOX_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    if (deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return NULL;
    }

    return deviceExtension;
}

/*
 * Builds health flag bits from a state snapshot.
 *
 * Inputs : Snapshot is a stable copy of driver state.
 * Logic  : exposes optional negotiation IOCTL availability without changing the
 *          legacy health reply size that existing collectors may already use.
 * Return : KSWORD_SANDBOX_HEALTH_FLAG_* bits.
 */
static
ULONG
KswBuildHealthFlags(
    _In_ const KSWORD_SANDBOX_STATE_SNAPSHOT* Snapshot
    )
{
    ULONG flags;

    flags =
        KSWORD_SANDBOX_HEALTH_FLAG_CAPABILITIES_AVAILABLE |
        KSWORD_SANDBOX_HEALTH_FLAG_STATUS_AVAILABLE |
        KSWORD_SANDBOX_HEALTH_FLAG_ENABLE_MASK_AVAILABLE;

    if (Snapshot->EventCount != 0) {
        flags |= KSWORD_SANDBOX_HEALTH_FLAG_HAS_EVENTS;
    }

    return flags;
}

/*
 * Builds status flag bits from a state snapshot.
 *
 * Inputs : Snapshot is a stable copy of driver state.
 * Logic  : summarizes queue depth, producer-mask coverage, and whether the most
 *          recent internal NTSTATUS represents a failure.
 * Return : KSWORD_SANDBOX_STATUS_FLAG_* bits.
 */
static
ULONG
KswBuildStatusFlags(
    _In_ const KSWORD_SANDBOX_STATE_SNAPSHOT* Snapshot
    )
{
    ULONG flags;

    flags = 0;

    if (Snapshot->EventCount != 0) {
        flags |= KSWORD_SANDBOX_STATUS_FLAG_HAS_EVENTS;
    }

    if (Snapshot->ProducerEnableMask == 0) {
        flags |= KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_ALL_DISABLED;
    } else if (Snapshot->ProducerEnableMask != Snapshot->SupportedProducerMask) {
        flags |= KSWORD_SANDBOX_STATUS_FLAG_PRODUCERS_PARTIAL;
    }

    if (!NT_SUCCESS(Snapshot->LastStatus) ||
        !NT_SUCCESS(Snapshot->LastFailureStatus) ||
        Snapshot->FailedProducerMask != 0) {
        flags |= KSWORD_SANDBOX_STATUS_FLAG_LAST_STATUS_FAILURE;
    }

    return flags;
}

/*
 * Fills a GET_CAPABILITIES reply.
 *
 * Inputs : Reply points to a caller-sized output buffer already validated by
 *          the IOCTL handler.
 * Logic  : writes only compile-time ABI constants and fixed structure sizes, so
 *          callers can negotiate with the driver before using newer contracts.
 * Return : no return value.
 */
static
VOID
KswFillCapabilitiesReply(
    _Out_ PKSWORD_SANDBOX_CAPABILITIES_REPLY Reply
    )
{
    RtlZeroMemory(Reply, sizeof(*Reply));
    Reply->Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    Reply->Size = sizeof(*Reply);
    Reply->AbiVersionMajor = KSWORD_SANDBOX_ABI_VERSION_MAJOR;
    Reply->AbiVersionMinor = KSWORD_SANDBOX_ABI_VERSION_MINOR;
    Reply->CapabilityFlags = KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT;
    Reply->SupportedProducerMask = KSWORD_SANDBOX_PRODUCER_MASK_CURRENT;
    Reply->DefaultProducerMask = KSWORD_SANDBOX_PRODUCER_MASK_DEFAULT;
    Reply->EventHeaderVersion = KSWORD_SANDBOX_EVENT_HEADER_VERSION;
    Reply->EventMaxPayloadSize = KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE;
    Reply->EventRingCapacity = KSWORD_SANDBOX_EVENT_RING_CAPACITY;
    Reply->ReadEventsReplyHeaderSize =
        KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE;
    Reply->CapabilitiesReplySize = sizeof(KSWORD_SANDBOX_CAPABILITIES_REPLY);
    Reply->StatusReplySize = sizeof(KSWORD_SANDBOX_STATUS_REPLY);
    Reply->SetProducerEnableMaskRequestSize =
        sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST);
    Reply->SetProducerEnableMaskReplySize =
        sizeof(KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY);
}

/*
 * Handles IOCTL_KSWORD_SANDBOX_GET_HEALTH.
 *
 * Inputs : DeviceObject identifies the skeleton device; Irp carries a buffered
 *          output buffer; OutputBufferLength is the caller's output size.
 * Logic  : validates the output buffer, snapshots internal state, and fills a
 *          KSWORD_SANDBOX_HEALTH_REPLY for the collector.
 * Return : STATUS_SUCCESS with sizeof(KSWORD_SANDBOX_HEALTH_REPLY) bytes, or a
 *          failure status when the request cannot be satisfied.
 */
static
NTSTATUS
KswHandleGetHealth(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    PKSWORD_SANDBOX_HEALTH_REPLY reply;
    KSWORD_SANDBOX_STATE_SNAPSHOT snapshot;

    if (OutputBufferLength < sizeof(*reply)) {
        return KswCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    reply = (PKSWORD_SANDBOX_HEALTH_REPLY)Irp->AssociatedIrp.SystemBuffer;
    if (reply == NULL) {
        return KswCompleteIrp(Irp, STATUS_INVALID_USER_BUFFER, 0);
    }

    deviceExtension = KswGetDeviceExtension(DeviceObject);
    if (deviceExtension == NULL) {
        return KswCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    KswSnapshotState(deviceExtension, &snapshot);

    RtlZeroMemory(reply, sizeof(*reply));
    reply->Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    reply->Size = sizeof(*reply);
    reply->DriverState = snapshot.DriverState;
    reply->Flags = KswBuildHealthFlags(&snapshot);
    reply->EventsQueued = snapshot.EventsQueued;
    reply->EventsDropped = snapshot.EventsDropped;
    reply->NextSequence = snapshot.NextSequence;
    reply->LastNtStatus = snapshot.LastStatus;

    return KswCompleteIrp(Irp, STATUS_SUCCESS, sizeof(*reply));
}

/*
 * Handles IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES.
 *
 * Inputs : Irp carries a buffered output buffer; OutputBufferLength is the
 *          caller's output size.
 * Logic  : validates the output buffer and returns static ABI/capability data
 *          for collector negotiation.
 * Return : STATUS_SUCCESS with sizeof(KSWORD_SANDBOX_CAPABILITIES_REPLY) bytes,
 *          or a failure status.
 */
static
NTSTATUS
KswHandleGetCapabilities(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    PKSWORD_SANDBOX_CAPABILITIES_REPLY reply;

    if (OutputBufferLength < sizeof(*reply)) {
        return KswCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    reply = (PKSWORD_SANDBOX_CAPABILITIES_REPLY)Irp->AssociatedIrp.SystemBuffer;
    if (reply == NULL) {
        return KswCompleteIrp(Irp, STATUS_INVALID_USER_BUFFER, 0);
    }

    deviceExtension = KswGetDeviceExtension(DeviceObject);
    if (deviceExtension == NULL) {
        return KswCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    KswFillCapabilitiesReply(reply);

    return KswCompleteIrp(Irp, STATUS_SUCCESS, sizeof(*reply));
}

/*
 * Handles IOCTL_KSWORD_SANDBOX_GET_STATUS.
 *
 * Inputs : DeviceObject identifies the skeleton device; Irp carries a buffered
 *          output buffer; OutputBufferLength is the caller's output size.
 * Logic  : validates the output buffer, snapshots shared state, and returns
 *          lifecycle, producer-mask, queue-capacity, and total counter fields.
 * Return : STATUS_SUCCESS with sizeof(KSWORD_SANDBOX_STATUS_REPLY) bytes, or a
 *          failure status.
 */
static
NTSTATUS
KswHandleGetStatus(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    PKSWORD_SANDBOX_STATUS_REPLY reply;
    KSWORD_SANDBOX_STATE_SNAPSHOT snapshot;

    if (OutputBufferLength < sizeof(*reply)) {
        return KswCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    reply = (PKSWORD_SANDBOX_STATUS_REPLY)Irp->AssociatedIrp.SystemBuffer;
    if (reply == NULL) {
        return KswCompleteIrp(Irp, STATUS_INVALID_USER_BUFFER, 0);
    }

    deviceExtension = KswGetDeviceExtension(DeviceObject);
    if (deviceExtension == NULL) {
        return KswCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    KswSnapshotState(deviceExtension, &snapshot);

    RtlZeroMemory(reply, sizeof(*reply));
    reply->Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    reply->Size = sizeof(*reply);
    reply->DriverState = snapshot.DriverState;
    reply->Flags = KswBuildStatusFlags(&snapshot);
    reply->QueueCapacity = snapshot.QueueCapacity;
    reply->QueueDepth = snapshot.EventCount;
    reply->QueueHighWatermark = snapshot.QueueHighWatermark;
    reply->ProducerEnableMask = snapshot.ProducerEnableMask;
    reply->SupportedProducerMask = snapshot.SupportedProducerMask;
    reply->LastNtStatus = snapshot.LastStatus;
    reply->ActiveProducerMask = snapshot.ActiveProducerMask;
    reply->FailedProducerMask = snapshot.FailedProducerMask;
    reply->TotalEventsEnqueued = snapshot.TotalEventsQueued;
    reply->TotalEventsDropped = snapshot.EventsDropped;
    reply->TotalEventsRead = snapshot.EventsRead;
    reply->TotalEventsSuppressed = snapshot.EventsSuppressed;
    reply->NextSequence = snapshot.NextSequence;

    return KswCompleteIrp(Irp, STATUS_SUCCESS, sizeof(*reply));
}

/*
 * Handles IOCTL_KSWORD_SANDBOX_POLL.
 *
 * Inputs : DeviceObject identifies the skeleton device; Irp carries a buffered
 *          output buffer; OutputBufferLength is the caller's output size.
 * Logic  : validates the output buffer, snapshots the shared event queue, and
 *          reports whether any startup or file telemetry events are queued.
 * Return : STATUS_SUCCESS with sizeof(KSWORD_SANDBOX_POLL_REPLY) bytes, or a
 *          failure status.
 */
static
NTSTATUS
KswHandlePoll(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    PKSWORD_SANDBOX_POLL_REPLY reply;
    KSWORD_SANDBOX_STATE_SNAPSHOT snapshot;

    if (OutputBufferLength < sizeof(*reply)) {
        return KswCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    reply = (PKSWORD_SANDBOX_POLL_REPLY)Irp->AssociatedIrp.SystemBuffer;
    if (reply == NULL) {
        return KswCompleteIrp(Irp, STATUS_INVALID_USER_BUFFER, 0);
    }

    deviceExtension = KswGetDeviceExtension(DeviceObject);
    if (deviceExtension == NULL) {
        return KswCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    KswSnapshotState(deviceExtension, &snapshot);

    RtlZeroMemory(reply, sizeof(*reply));
    reply->Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    reply->Size = sizeof(*reply);
    reply->DriverState = snapshot.DriverState;
    reply->HasEvents = snapshot.EventsQueued > 0 ? 1 : 0;
    reply->EventsQueued = snapshot.EventsQueued;
    reply->EventsDropped = snapshot.EventsDropped;
    reply->NextSequence = snapshot.NextSequence;

    return KswCompleteIrp(Irp, STATUS_SUCCESS, sizeof(*reply));
}

/*
 * Validates the optional READ_EVENTS request header.
 *
 * Inputs : Buffer points to the METHOD_BUFFERED system buffer; InputBufferLength
 *          is the number of input bytes supplied by the collector.
 * Logic  : accepts a zero-length request for the current skeleton; otherwise
 *          requires the full request structure and matching ABI metadata.
 * Return : STATUS_SUCCESS when the request can be accepted; otherwise a failure
 *          NTSTATUS that the caller should complete back to user mode.
 */
static
NTSTATUS
KswValidateReadEventsRequest(
    _In_opt_ PVOID Buffer,
    _In_ ULONG InputBufferLength,
    _Out_ PULONG RequestedMaxEvents,
    _Out_ PULONGLONG RequestedStartingSequence
    )
{
    PKSWORD_SANDBOX_READ_EVENTS_REQUEST request;

    *RequestedMaxEvents = 0;
    *RequestedStartingSequence = 0;

    if (InputBufferLength == 0) {
        return STATUS_SUCCESS;
    }

    if (Buffer == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }

    if (InputBufferLength < sizeof(*request)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PKSWORD_SANDBOX_READ_EVENTS_REQUEST)Buffer;
    if (request->Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        request->Size < sizeof(*request) ||
        request->Size > InputBufferLength ||
        request->Flags != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *RequestedMaxEvents = request->MaxEvents;
    *RequestedStartingSequence = request->StartingSequence;

    return STATUS_SUCCESS;
}

/*
 * Validates a SET_PRODUCER_ENABLE_MASK request header.
 *
 * Inputs : Buffer points to the METHOD_BUFFERED system buffer; InputBufferLength
 *          is the number of input bytes supplied by the collector.
 * Logic  : requires the current ABI version, a known-size prefix, and reserved
 *          flags set to zero.  Unsupported bits are checked later against the
 *          live device extension.
 * Return : STATUS_SUCCESS with EnableMask copied out, otherwise a failure
 *          NTSTATUS that is completed back to user mode.
 */
static
NTSTATUS
KswValidateSetProducerEnableMaskRequest(
    _In_opt_ PVOID Buffer,
    _In_ ULONG InputBufferLength,
    _Out_ PULONG EnableMask
    )
{
    PKSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST request;

    *EnableMask = 0;

    if (Buffer == NULL) {
        return STATUS_INVALID_USER_BUFFER;
    }

    if (InputBufferLength < sizeof(*request)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PKSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST)Buffer;
    if (request->Version != KSWORD_SANDBOX_INTERFACE_VERSION ||
        request->Size < sizeof(*request) ||
        request->Size > InputBufferLength ||
        request->Flags != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *EnableMask = request->EnableMask;

    return STATUS_SUCCESS;
}

/*
 * Handles IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK.
 *
 * Inputs : DeviceObject identifies the skeleton device; Irp carries a buffered
 *          request/reply buffer; InputBufferLength and OutputBufferLength are
 *          the caller-provided METHOD_BUFFERED sizes.
 * Logic  : validates the request and reply capacity, applies the new producer
 *          mask under the shared state lock, and returns the before/after masks.
 * Return : STATUS_SUCCESS with a
 *          KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY, or a failure status.
 */
static
NTSTATUS
KswHandleSetProducerEnableMask(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
    )
{
    NTSTATUS status;
    PVOID systemBuffer;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    PKSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY reply;
    ULONG requestedEnableMask;
    ULONG previousEnableMask;
    ULONG effectiveEnableMask;

    if (OutputBufferLength < sizeof(*reply)) {
        return KswCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    status = KswValidateSetProducerEnableMaskRequest(
        systemBuffer,
        InputBufferLength,
        &requestedEnableMask);
    if (!NT_SUCCESS(status)) {
        return KswCompleteIrp(Irp, status, 0);
    }

    deviceExtension = KswGetDeviceExtension(DeviceObject);
    if (deviceExtension == NULL) {
        return KswCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    status = KswSetProducerEnableMask(
        deviceExtension,
        requestedEnableMask,
        &previousEnableMask,
        &effectiveEnableMask);
    if (!NT_SUCCESS(status)) {
        return KswCompleteIrp(Irp, status, 0);
    }

    reply = (PKSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY)systemBuffer;
    RtlZeroMemory(reply, sizeof(*reply));
    reply->Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    reply->Size = sizeof(*reply);
    reply->PreviousEnableMask = previousEnableMask;
    reply->EffectiveEnableMask = effectiveEnableMask;
    reply->SupportedProducerMask = KSWORD_SANDBOX_PRODUCER_MASK_CURRENT;
    reply->Flags = 0;

    return KswCompleteIrp(Irp, STATUS_SUCCESS, sizeof(*reply));
}

/*
 * Handles IOCTL_KSWORD_SANDBOX_READ_EVENTS.
 *
 * Inputs : DeviceObject identifies the skeleton device; Irp carries the shared
 *          METHOD_BUFFERED input/output buffer; InputBufferLength may describe
 *          an optional read request; OutputBufferLength is the output capacity.
 * Logic  : validates the optional request, validates the fixed output header
 *          capacity, computes how many complete event headers fit, drains that
 *          many records from the non-paged ring, and writes a bounded event
 *          stream after the reply header.
 * Return : STATUS_SUCCESS with a KSWORD_SANDBOX_READ_EVENTS_REPLY header and
 *          zero or more KSWORD_SANDBOX_EVENT_HEADER records.  IoStatus bytes
 *          equals the fixed reply header plus BytesWritten from the event stream.
 */
static
NTSTATUS
KswHandleReadEvents(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
    )
{
    NTSTATUS status;
    PVOID systemBuffer;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    PKSWORD_SANDBOX_READ_EVENTS_REPLY reply;
    ULONG requestedMaxEvents;
    ULONGLONG requestedStartingSequence;
    ULONG maxEvents;
    ULONG eventCapacityBytes;
    ULONG eventsWritten;
    ULONG bytesWritten;
    ULONGLONG eventsDropped;
    ULONGLONG nextSequence;
    ULONG_PTR information;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    status = KswValidateReadEventsRequest(
        systemBuffer,
        InputBufferLength,
        &requestedMaxEvents,
        &requestedStartingSequence);
    if (!NT_SUCCESS(status)) {
        return KswCompleteIrp(Irp, status, 0);
    }

    if (OutputBufferLength < KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE) {
        return KswCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    if (systemBuffer == NULL) {
        return KswCompleteIrp(Irp, STATUS_INVALID_USER_BUFFER, 0);
    }

    deviceExtension = KswGetDeviceExtension(DeviceObject);
    if (deviceExtension == NULL) {
        return KswCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    reply = (PKSWORD_SANDBOX_READ_EVENTS_REPLY)systemBuffer;
    RtlZeroMemory(reply, KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE);

    eventCapacityBytes =
        OutputBufferLength - KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE;
    maxEvents =
        eventCapacityBytes / (ULONG)sizeof(KSWORD_SANDBOX_EVENT_HEADER);
    if (requestedMaxEvents != 0 && requestedMaxEvents < maxEvents) {
        maxEvents = requestedMaxEvents;
    }

    KswDrainEventHeaders(
        deviceExtension,
        reply->Events,
        eventCapacityBytes,
        maxEvents,
        requestedStartingSequence,
        &eventsWritten,
        &bytesWritten,
        &eventsDropped,
        &nextSequence);

    reply->Version = KSWORD_SANDBOX_INTERFACE_VERSION;
    reply->Size = KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE;
    reply->EventsWritten = eventsWritten;
    reply->Flags = 0;
    reply->BytesWritten = bytesWritten;
    reply->EventsDropped = eventsDropped;
    reply->NextSequence = nextSequence;

    information =
        KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE + (ULONG_PTR)bytesWritten;

    return KswCompleteIrp(
        Irp,
        STATUS_SUCCESS,
        information);
}

/*
 * Handles IRP_MJ_CREATE and IRP_MJ_CLOSE.
 *
 * Inputs : DeviceObject identifies the control device; Irp is the create or
 *          close request generated by CreateFile/CloseHandle.
 * Logic  : validates that the request targets this skeleton device and performs
 *          no per-handle allocation in the initial implementation.
 * Return : STATUS_SUCCESS with zero output bytes, or STATUS_DEVICE_NOT_READY if
 *          the device extension is invalid.
 */
_Use_decl_annotations_
NTSTATUS
KswDispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )
{
    if (KswGetDeviceExtension(DeviceObject) == NULL) {
        return KswCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    return KswCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

/*
 * Handles unsupported major functions.
 *
 * Inputs : DeviceObject identifies the device; Irp is any unsupported request.
 * Logic  : ignores the device object because no unsupported IRP is valid for the
 *          skeleton and completes the request with a stable failure code.
 * Return : STATUS_INVALID_DEVICE_REQUEST with zero output bytes.
 */
_Use_decl_annotations_
NTSTATUS
KswDispatchUnsupported(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return KswCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

/*
 * Handles IRP_MJ_DEVICE_CONTROL.
 *
 * Inputs : DeviceObject identifies the control device; Irp contains the IOCTL
 *          code plus METHOD_BUFFERED input/output lengths.
 * Logic  : routes public collector IOCTLs to dedicated handlers and rejects
 *          unknown control codes.
 * Return : handler-specific NTSTATUS and byte count.
 */
_Use_decl_annotations_
NTSTATUS
KswDispatchDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )
{
    PIO_STACK_LOCATION irpStack;
    ULONG ioControlCode;
    ULONG inputBufferLength;
    ULONG outputBufferLength;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioControlCode) {
    case IOCTL_KSWORD_SANDBOX_GET_HEALTH:
        return KswHandleGetHealth(DeviceObject, Irp, outputBufferLength);

    case IOCTL_KSWORD_SANDBOX_POLL:
        return KswHandlePoll(DeviceObject, Irp, outputBufferLength);

    case IOCTL_KSWORD_SANDBOX_READ_EVENTS:
        return KswHandleReadEvents(
            DeviceObject,
            Irp,
            inputBufferLength,
            outputBufferLength);

    case IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES:
        return KswHandleGetCapabilities(
            DeviceObject,
            Irp,
            outputBufferLength);

    case IOCTL_KSWORD_SANDBOX_GET_STATUS:
        return KswHandleGetStatus(DeviceObject, Irp, outputBufferLength);

    case IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK:
        return KswHandleSetProducerEnableMask(
            DeviceObject,
            Irp,
            inputBufferLength,
            outputBufferLength);

    default:
        return KswCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
}
