#include "Driver.h"

C_ASSERT(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);

static KSWORD_SANDBOX_FILE_FILTER_RUNTIME g_KswFileFilterRuntime;

static NTSTATUS FLTAPI
KswFileFilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

static FLT_PREOP_CALLBACK_STATUS FLTAPI
KswFileFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    );

static FLT_POSTOP_CALLBACK_STATUS FLTAPI
KswFileFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

/*
 * Minifilter operation table for the first file telemetry slice.
 *
 * Inputs : consumed by FltRegisterFilter during DriverEntry.
 * Logic  : CREATE, WRITE, and SET_INFORMATION are registered; the callback maps
 *          SET_INFORMATION to Delete only for disposition information classes.
 * Return : not applicable; FltMgr reads this static registration table.
 */
static const FLT_OPERATION_REGISTRATION g_KswFileFilterOperations[] = {
    { IRP_MJ_CREATE, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_WRITE, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_SET_INFORMATION, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_OPERATION_END }
};

/*
 * Minifilter registration block.
 *
 * Inputs : consumed by FltRegisterFilter.
 * Logic  : no contexts or name-provider callbacks are registered because the
 *          minimal producer only observes selected file operations and forwards
 *          compact events into the existing READ_EVENTS ring.
 * Return : not applicable.
 */
static const FLT_REGISTRATION g_KswFileFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_KswFileFilterOperations,
    KswFileFilterUnloadCallback,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

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
 * Updates the last internal status reported through GET_HEALTH.
 *
 * Inputs : DeviceExtension owns the status field; Status is the newest internal
 *          initialization or producer status to expose to collectors.
 * Logic  : acquires StateLock, updates LastStatus, and releases the lock before
 *          returning so callers do not hold state locks across FltMgr calls.
 * Return : no return value.
 */
static
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
 * Creates or opens a registry key for minifilter instance metadata.
 *
 * Inputs : RootHandle is an optional parent key, KeyName is the relative or
 *          absolute key name, and KeyHandleOut receives the opened key.
 * Logic  : wraps ZwCreateKey with kernel-handle attributes and read/write
 *          access so DriverEntry can build the small FltMgr Instances tree.
 * Return : ZwCreateKey NTSTATUS.
 */
static
NTSTATUS
KswCreateOrOpenRegistryKey(
    _In_opt_ HANDLE RootHandle,
    _In_ PUNICODE_STRING KeyName,
    _Out_ PHANDLE KeyHandleOut
    )
{
    OBJECT_ATTRIBUTES objectAttributes;
    ULONG disposition;

    if (KeyName == NULL ||
        KeyName->Buffer == NULL ||
        KeyHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *KeyHandleOut = NULL;
    disposition = 0;

    InitializeObjectAttributes(
        &objectAttributes,
        KeyName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        RootHandle,
        NULL);

    return ZwCreateKey(
        KeyHandleOut,
        KEY_READ | KEY_WRITE,
        &objectAttributes,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition);
}

/*
 * Writes a REG_SZ value under an already-open service registry key.
 *
 * Inputs : KeyHandle is an open registry key, ValueNameText names the value, and
 *          ValueDataText is the NUL-terminated UTF-16 payload.
 * Logic  : builds transient UNICODE_STRING wrappers and writes the value,
 *          including the trailing NUL expected for REG_SZ.
 * Return : ZwSetValueKey NTSTATUS.
 */
static
NTSTATUS
KswWriteRegistryStringValue(
    _In_ HANDLE KeyHandle,
    _In_z_ PCWSTR ValueNameText,
    _In_z_ PCWSTR ValueDataText
    )
{
    UNICODE_STRING valueName;
    UNICODE_STRING valueData;

    if (KeyHandle == NULL ||
        ValueNameText == NULL ||
        ValueDataText == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&valueName, ValueNameText);
    RtlInitUnicodeString(&valueData, ValueDataText);

    return ZwSetValueKey(
        KeyHandle,
        &valueName,
        0,
        REG_SZ,
        valueData.Buffer,
        (ULONG)valueData.Length + sizeof(WCHAR));
}

/*
 * Writes a REG_DWORD value under an already-open service registry key.
 *
 * Inputs : KeyHandle is an open registry key, ValueNameText names the value, and
 *          ValueData is the DWORD payload.
 * Logic  : builds a transient UNICODE_STRING wrapper and stores the fixed-size
 *          DWORD used by FltMgr instance flags.
 * Return : ZwSetValueKey NTSTATUS.
 */
static
NTSTATUS
KswWriteRegistryDwordValue(
    _In_ HANDLE KeyHandle,
    _In_z_ PCWSTR ValueNameText,
    _In_ ULONG ValueData
    )
{
    UNICODE_STRING valueName;

    if (KeyHandle == NULL || ValueNameText == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&valueName, ValueNameText);

    return ZwSetValueKey(
        KeyHandle,
        &valueName,
        0,
        REG_DWORD,
        &ValueData,
        sizeof(ValueData));
}

/*
 * Closes an optional kernel registry handle.
 *
 * Inputs : KeyHandle is either NULL or a handle returned by ZwCreateKey.
 * Logic  : skips NULL handles and otherwise delegates to ZwClose.
 * Return : ZwClose status for real handles or STATUS_SUCCESS for NULL.
 */
static
NTSTATUS
KswCloseOptionalRegistryHandle(
    _In_opt_ HANDLE KeyHandle
    )
{
    if (KeyHandle == NULL) {
        return STATUS_SUCCESS;
    }

    return ZwClose(KeyHandle);
}

/*
 * Ensures the service key contains the minimal FltMgr Instances metadata.
 *
 * Inputs : RegistryPath is the DriverEntry service key path.
 * Logic  : creates/open the service key, Instances subkey, and default instance
 *          subkey, then writes DefaultInstance, Altitude, and Flags values.
 * Return : STATUS_SUCCESS when all writes and closes succeed; otherwise the
 *          first registry failure observed.
 */
static
NTSTATUS
KswEnsureFileFilterRegistryInstances(
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNICODE_STRING instancesKeyName;
    UNICODE_STRING instanceKeyName;
    HANDLE serviceKeyHandle;
    HANDLE instancesKeyHandle;
    HANDLE instanceKeyHandle;
    NTSTATUS status;
    NTSTATUS closeStatus;

    if (RegistryPath == NULL ||
        RegistryPath->Buffer == NULL ||
        RegistryPath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    serviceKeyHandle = NULL;
    instancesKeyHandle = NULL;
    instanceKeyHandle = NULL;

    status = KswCreateOrOpenRegistryKey(
        NULL,
        RegistryPath,
        &serviceKeyHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    RtlInitUnicodeString(
        &instancesKeyName,
        KSWORD_SANDBOX_FILE_FILTER_INSTANCE_KEY_NAME);
    status = KswCreateOrOpenRegistryKey(
        serviceKeyHandle,
        &instancesKeyName,
        &instancesKeyHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = KswWriteRegistryStringValue(
        instancesKeyHandle,
        L"DefaultInstance",
        KSWORD_SANDBOX_FILE_FILTER_DEFAULT_INSTANCE_NAME);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    RtlInitUnicodeString(
        &instanceKeyName,
        KSWORD_SANDBOX_FILE_FILTER_DEFAULT_INSTANCE_NAME);
    status = KswCreateOrOpenRegistryKey(
        instancesKeyHandle,
        &instanceKeyName,
        &instanceKeyHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = KswWriteRegistryStringValue(
        instanceKeyHandle,
        L"Altitude",
        KSWORD_SANDBOX_FILE_FILTER_ALTITUDE_TEXT);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = KswWriteRegistryDwordValue(instanceKeyHandle, L"Flags", 0);

Exit:
    closeStatus = KswCloseOptionalRegistryHandle(instanceKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }

    closeStatus = KswCloseOptionalRegistryHandle(instancesKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }

    closeStatus = KswCloseOptionalRegistryHandle(serviceKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }

    return status;
}

/*
 * Maps a minifilter callback to the public file operation ABI.
 *
 * Inputs : Data is the FltMgr callback data for one file-system operation.
 * Logic  : CREATE and WRITE map directly; SET_INFORMATION is emitted only when
 *          it represents file disposition, which is the first delete signal the
 *          minimal collector needs.
 * Return : KSWORD_SANDBOX_FILE_OPERATION value or None for ignored callbacks.
 */
static
ULONG
KswMapFileOperation(
    _In_ PFLT_CALLBACK_DATA Data
    )
{
    FILE_INFORMATION_CLASS informationClass;

    if (Data == NULL || Data->Iopb == NULL) {
        return KswSandboxFileOperationNone;
    }

    switch (Data->Iopb->MajorFunction) {
    case IRP_MJ_CREATE:
        return KswSandboxFileOperationCreate;

    case IRP_MJ_WRITE:
        return KswSandboxFileOperationWrite;

    case IRP_MJ_SET_INFORMATION:
        informationClass =
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (informationClass == FileDispositionInformation ||
            informationClass == FileDispositionInformationEx) {
            return KswSandboxFileOperationDelete;
        }
        return KswSandboxFileOperationNone;

    default:
        return KswSandboxFileOperationNone;
    }
}

/*
 * Copies a bounded UTF-16 file name into a file event payload.
 *
 * Inputs : Payload receives the copied name; FileName is an optional source
 *          UNICODE_STRING from FILE_OBJECT.FileName.
 * Logic  : copies at most PATH_CHARS - 1 WCHARs, stores a NUL terminator, and
 *          marks truncation when the original path exceeds the fixed payload.
 * Return : no return value.
 */
static
VOID
KswCopyFilePathToPayload(
    _Inout_ PKSWORD_SANDBOX_FILE_EVENT_PAYLOAD Payload,
    _In_opt_ PCUNICODE_STRING FileName
    )
{
    ULONG maxBytes;
    ULONG bytesToCopy;
    ULONG sourceBytes;
    ULONG copiedChars;

    if (Payload == NULL ||
        FileName == NULL ||
        FileName->Buffer == NULL ||
        FileName->Length == 0) {
        return;
    }

    sourceBytes = FileName->Length;
    maxBytes =
        (KSWORD_SANDBOX_FILE_EVENT_PATH_CHARS - 1U) * (ULONG)sizeof(WCHAR);
    bytesToCopy = sourceBytes;
    if (bytesToCopy > maxBytes) {
        bytesToCopy = maxBytes;
        Payload->Flags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_TRUNCATED;
    }

    bytesToCopy -= bytesToCopy % (ULONG)sizeof(WCHAR);
    if (bytesToCopy == 0) {
        return;
    }

    RtlCopyMemory(Payload->Path, FileName->Buffer, bytesToCopy);
    copiedChars = bytesToCopy / (ULONG)sizeof(WCHAR);
    Payload->Path[copiedChars] = L'\0';
    Payload->PathLengthBytes = bytesToCopy;
    Payload->Flags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT;
}

/*
 * Builds and queues one file event into the existing READ_EVENTS ring.
 *
 * Inputs : Data and FltObjects describe the completed file operation;
 *          Operation is the public file operation; IsPostOperation indicates
 *          whether Data->IoStatus.Status is final.
 * Logic  : fills a stack payload, performs only bounded path copying, avoids
 *          path access above APC_LEVEL, and calls the existing KswPushEvent
 *          producer to preserve READ_EVENTS framing and drop accounting.
 * Return : no return value.
 */
static
VOID
KswPushFileEvent(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Operation,
    _In_ BOOLEAN IsPostOperation
    )
{
    KSWORD_SANDBOX_FILE_EVENT_PAYLOAD payload;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;

    if (Operation == KswSandboxFileOperationNone ||
        InterlockedCompareExchange(&g_KswFileFilterRuntime.Active, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswFileFilterRuntime.DeviceExtension;
    if (deviceExtension == NULL) {
        return;
    }

    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = KSWORD_SANDBOX_FILE_EVENT_VERSION;
    payload.Size = sizeof(payload);
    payload.Operation = Operation;
    payload.ProcessId = (ULONGLONG)(ULONG_PTR)FltGetRequestorProcessId(Data);

    if (Data != NULL && Data->Iopb != NULL) {
        payload.MajorFunction = Data->Iopb->MajorFunction;
        payload.MinorFunction = Data->Iopb->MinorFunction;
    }

    if (IsPostOperation) {
        payload.Status = Data->IoStatus.Status;
        payload.Flags |=
            KSWORD_SANDBOX_FILE_EVENT_FLAG_STATUS_PRESENT |
            KSWORD_SANDBOX_FILE_EVENT_FLAG_POST_OPERATION;
    }

    if (KeGetCurrentIrql() <= APC_LEVEL &&
        FltObjects != NULL &&
        FltObjects->FileObject != NULL) {
        KswCopyFilePathToPayload(&payload, &FltObjects->FileObject->FileName);
    }

    (VOID)KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeFile,
        0,
        &payload,
        sizeof(payload));
}

/*
 * Handles FltMgr pre-operation callbacks for selected file operations.
 *
 * Inputs : Data and FltObjects describe the current file-system request;
 *          CompletionContext is unused and always cleared.
 * Logic  : maps the operation and requests a post-operation callback only for
 *          create/write/delete events that the minimal collector understands.
 * Return : FLT_PREOP_SUCCESS_WITH_CALLBACK when a final-status event should be
 *          emitted later; otherwise FLT_PREOP_SUCCESS_NO_CALLBACK.
 */
static
FLT_PREOP_CALLBACK_STATUS
FLTAPI
KswFileFilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    )
{
    ULONG operation;

    UNREFERENCED_PARAMETER(FltObjects);

    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    operation = KswMapFileOperation(Data);
    if (operation == KswSandboxFileOperationNone ||
        InterlockedCompareExchange(&g_KswFileFilterRuntime.Active, 0, 0) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/*
 * Handles FltMgr post-operation callbacks for selected file operations.
 *
 * Inputs : Data and FltObjects describe the completed operation;
 *          CompletionContext is unused; Flags describes post-operation state.
 * Logic  : ignores draining callbacks, remaps the operation, and queues one
 *          bounded file payload with the final NTSTATUS.
 * Return : FLT_POSTOP_FINISHED_PROCESSING.
 */
static
FLT_POSTOP_CALLBACK_STATUS
FLTAPI
KswFileFilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    ULONG operation;

    UNREFERENCED_PARAMETER(CompletionContext);

    if ((Flags & FLTFL_POST_OPERATION_DRAINING) != 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    operation = KswMapFileOperation(Data);
    if (operation != KswSandboxFileOperationNone) {
        KswPushFileEvent(Data, FltObjects, operation, TRUE);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/*
 * Allows FltMgr-initiated unload for the registered minifilter.
 *
 * Inputs : Flags describes the unload request type from FltMgr.
 * Logic  : no per-instance state is allocated, so the driver permits unload;
 *          DriverUnload still owns the explicit unregister path.
 * Return : STATUS_SUCCESS.
 */
static
NTSTATUS
FLTAPI
KswFileFilterUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}

/*
 * Registers and starts the minimal file minifilter producer.
 *
 * Inputs : DriverObject and RegistryPath come from DriverEntry;
 *          DeviceExtension is the existing READ_EVENTS ring owner.
 * Logic  : prepares FltMgr instance registry values for lab loading, registers
 *          the callback table, starts filtering, and marks callbacks active only
 *          after FltStartFiltering succeeds.
 * Return : STATUS_SUCCESS when file callbacks are active, otherwise the FltMgr
 *          or registry NTSTATUS.  The caller may keep the control device alive.
 */
NTSTATUS
KswInitializeFileFilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    NTSTATUS status;
    NTSTATUS registryStatus;

    if (DriverObject == NULL || DeviceExtension == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&g_KswFileFilterRuntime, sizeof(g_KswFileFilterRuntime));
    g_KswFileFilterRuntime.DeviceExtension = DeviceExtension;
    g_KswFileFilterRuntime.RegisterStatus = STATUS_NOT_SUPPORTED;
    g_KswFileFilterRuntime.StartStatus = STATUS_NOT_SUPPORTED;

    registryStatus = KswEnsureFileFilterRegistryInstances(RegistryPath);
    if (!NT_SUCCESS(registryStatus)) {
        KswSetLastStatus(DeviceExtension, registryStatus);
    }

    status = FltRegisterFilter(
        DriverObject,
        &g_KswFileFilterRegistration,
        &g_KswFileFilterRuntime.Filter);
    g_KswFileFilterRuntime.RegisterStatus = status;
    if (!NT_SUCCESS(status)) {
        g_KswFileFilterRuntime.Filter = NULL;
        g_KswFileFilterRuntime.DeviceExtension = NULL;
        KswSetLastStatus(DeviceExtension, status);
        return status;
    }

    status = FltStartFiltering(g_KswFileFilterRuntime.Filter);
    g_KswFileFilterRuntime.StartStatus = status;
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_KswFileFilterRuntime.Filter);
        g_KswFileFilterRuntime.Filter = NULL;
        g_KswFileFilterRuntime.DeviceExtension = NULL;
        KswSetLastStatus(DeviceExtension, status);
        return status;
    }

    InterlockedExchange(&g_KswFileFilterRuntime.Active, 1);
    KswSetLastStatus(DeviceExtension, STATUS_SUCCESS);

    return STATUS_SUCCESS;
}

/*
 * Stops callback emission and unregisters the minifilter producer.
 *
 * Inputs : none; uses the single static runtime initialized by DriverEntry.
 * Logic  : clears Active so new callbacks skip emission, unregisters the
 *          FltMgr filter handle, and clears the device-extension pointer before
 *          the WDM control device is deleted.
 * Return : no return value.
 */
VOID
KswUninitializeFileFilter(
    VOID
    )
{
    PFLT_FILTER filter;

    InterlockedExchange(&g_KswFileFilterRuntime.Active, 0);

    filter = g_KswFileFilterRuntime.Filter;
    g_KswFileFilterRuntime.Filter = NULL;
    g_KswFileFilterRuntime.DeviceExtension = NULL;

    if (filter != NULL) {
        FltUnregisterFilter(filter);
    }

    g_KswFileFilterRuntime.RegisterStatus = STATUS_NOT_SUPPORTED;
    g_KswFileFilterRuntime.StartStatus = STATUS_NOT_SUPPORTED;
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

    /*
     * The file minifilter is an event producer layered on the existing control
     * device.  If FltMgr registration is unavailable in a lab environment, keep
     * the original IOCTL and READ_EVENTS path alive and expose the failure
     * through GET_HEALTH.LastNtStatus.
     */
    status = KswInitializeFileFilter(
        DriverObject,
        RegistryPath,
        deviceExtension);
    if (!NT_SUCCESS(status)) {
        KswSetLastStatus(deviceExtension, status);
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

    KswUninitializeFileFilter();

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
