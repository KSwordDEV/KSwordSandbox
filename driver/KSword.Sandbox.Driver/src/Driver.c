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
static
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
static
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
 * Validates and returns the device extension for an incoming request.
 *
 * Inputs : DeviceObject is the device object supplied to the dispatch routine.
 * Logic  : checks that the object and extension exist and that the extension has
 *          the expected skeleton signature.
 * Return : device extension on success; NULL when the request should fail.
 */
static
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
 * Copies queue and lifecycle fields into a stable snapshot.
 *
 * Inputs : DeviceExtension supplies current state; Snapshot receives the copy.
 * Logic  : acquires StateLock briefly, copies only primitive fields, and then
 *          releases the lock before any IOCTL output buffer is touched.
 * Return : no return value.
 */
static
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
    reply->Flags = 0;
    reply->EventsQueued = snapshot.EventsQueued;
    reply->EventsDropped = snapshot.EventsDropped;
    reply->NextSequence = snapshot.NextSequence;
    reply->LastNtStatus = snapshot.LastStatus;

    return KswCompleteIrp(Irp, STATUS_SUCCESS, sizeof(*reply));
}

/*
 * Handles IOCTL_KSWORD_SANDBOX_POLL.
 *
 * Inputs : DeviceObject identifies the skeleton device; Irp carries a buffered
 *          output buffer; OutputBufferLength is the caller's output size.
 * Logic  : validates the output buffer, snapshots the placeholder event queue,
 *          and reports whether any reserved events are currently queued.
 * Return : STATUS_SUCCESS with sizeof(KSWORD_SANDBOX_POLL_REPLY) bytes, or a
 *          failure status.  The current skeleton always reports no events.
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
    _Out_ PULONG RequestedMaxEvents
    )
{
    PKSWORD_SANDBOX_READ_EVENTS_REQUEST request;

    *RequestedMaxEvents = 0;

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
        request->Size > InputBufferLength) {
        return STATUS_INVALID_PARAMETER;
    }

    *RequestedMaxEvents = request->MaxEvents;

    return STATUS_SUCCESS;
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
        &requestedMaxEvents);
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
 * Driver entry point called by the I/O manager when the service is loaded.
 *
 * Inputs : DriverObject is owned by the I/O manager; RegistryPath identifies the
 *          service key for future configuration reads.
 * Logic  : installs dispatch routines, creates one control device object,
 *          initializes its extension, creates the Win32-visible symbolic link,
 *          and clears DO_DEVICE_INITIALIZING only after setup succeeds.
 * Return : STATUS_SUCCESS when the control device is ready; otherwise the
 *          failing NTSTATUS from device or symbolic-link creation.
 */
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    PDEVICE_OBJECT deviceObject;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    ULONG majorFunctionIndex;

    UNREFERENCED_PARAMETER(RegistryPath);

    deviceObject = NULL;

    DriverObject->DriverUnload = KswDriverUnload;
    for (majorFunctionIndex = 0;
         majorFunctionIndex <= IRP_MJ_MAXIMUM_FUNCTION;
         majorFunctionIndex++) {
        DriverObject->MajorFunction[majorFunctionIndex] = KswDispatchUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = KswDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KswDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KswDispatchDeviceControl;

    RtlInitUnicodeString(&deviceName, KSWORD_SANDBOX_NT_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        sizeof(KSWORD_SANDBOX_DEVICE_EXTENSION),
        &deviceName,
        KSWORD_SANDBOX_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;

    deviceExtension =
        (PKSWORD_SANDBOX_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    KswInitializeDeviceExtension(deviceExtension);

    RtlInitUnicodeString(&symbolicLinkName, KSWORD_SANDBOX_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

/*
 * Driver unload routine called when the driver service is stopped.
 *
 * Inputs : DriverObject identifies the loaded driver instance.
 * Logic  : marks the device as stopping, deletes the DOS symbolic link, and
 *          deletes the single control device object created by DriverEntry.
 * Return : no return value.
 */
_Use_decl_annotations_
VOID
KswDriverUnload(
    PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symbolicLinkName;
    PDEVICE_OBJECT deviceObject;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;

    RtlInitUnicodeString(&symbolicLinkName, KSWORD_SANDBOX_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);

    deviceObject = DriverObject->DeviceObject;
    if (deviceObject != NULL) {
        deviceExtension = KswGetDeviceExtension(deviceObject);
        if (deviceExtension != NULL) {
            KIRQL oldIrql;

            KeAcquireSpinLock(&deviceExtension->StateLock, &oldIrql);
            deviceExtension->DriverState = KswSandboxDriverStateStopping;
            KeReleaseSpinLock(&deviceExtension->StateLock, oldIrql);
        }

        IoDeleteDevice(deviceObject);
    }
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
 * Logic  : routes the three initial collector IOCTLs to dedicated handlers and
 *          rejects unknown control codes.
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

    default:
        return KswCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
}
