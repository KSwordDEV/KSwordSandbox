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
