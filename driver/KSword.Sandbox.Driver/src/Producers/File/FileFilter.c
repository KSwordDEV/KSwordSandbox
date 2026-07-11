#include "Driver.h"

C_ASSERT(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);

static KSWORD_SANDBOX_FILE_FILTER_RUNTIME g_KswFileFilterRuntime;
static volatile LONG g_KswFileFilterUninitializing;

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
 * Minifilter operation table for the file telemetry producer.
 *
 * Inputs : consumed by FltRegisterFilter during DriverEntry.
 * Logic  : CREATE, READ, WRITE, SET_INFORMATION, CLEANUP, and CLOSE are
 *          registered.  CLOSE is pre-only because there is no useful final
 *          status at that point; other operations use post callbacks when
 *          available so collectors see result status.  The callback maps
 *          SET_INFORMATION to Rename/Delete for those information classes and
 *          otherwise preserves SetInformation.
 * Return : not applicable; FltMgr reads this static registration table.
 */
static const FLT_OPERATION_REGISTRATION g_KswFileFilterOperations[] = {
    { IRP_MJ_CREATE, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_READ, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_WRITE, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_SET_INFORMATION, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_CLEANUP, 0, KswFileFilterPreOperation, KswFileFilterPostOperation },
    { IRP_MJ_CLOSE, 0, KswFileFilterPreOperation, NULL },
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
 * Tests whether a SET_INFORMATION request represents delete intent.
 *
 * Inputs : InformationClass is the WDK file-information class from the I/O
 *          parameter block.
 * Logic  : disposition classes are normalized to the public Delete operation so
 *          collectors do not need WDK-specific class values for common file
 *          removal evidence.
 * Return : TRUE for delete/disposition classes; FALSE otherwise.
 */
static
BOOLEAN
KswIsDeleteInformationClass(
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    return InformationClass == FileDispositionInformation ||
        InformationClass == FileDispositionInformationEx;
}

/*
 * Tests whether a SET_INFORMATION request represents rename intent.
 *
 * Inputs : InformationClass is the WDK file-information class from the I/O
 *          parameter block.
 * Logic  : rename classes are normalized to the public Rename operation while
 *          all other metadata changes remain SetInformation events.
 * Return : TRUE for rename classes; FALSE otherwise.
 */
static
BOOLEAN
KswIsRenameInformationClass(
    _In_ FILE_INFORMATION_CLASS InformationClass
    )
{
    return InformationClass == FileRenameInformation ||
        InformationClass == FileRenameInformationEx ||
        InformationClass == FileLinkInformation ||
        InformationClass == FileLinkInformationEx;
}

/*
 * Performs bounded, case-insensitive substring matching on a UNICODE_STRING.
 *
 * Inputs : Value is the bounded string to scan, NeedleText is a NUL-terminated
 *          UTF-16 substring.
 * Logic  : compares WCHARs using RtlUpcaseUnicodeChar and never reads beyond
 *          Value->Length or NeedleText's initialized UNICODE_STRING length.
 * Return : TRUE when NeedleText is present in Value; FALSE otherwise.
 */
static
BOOLEAN
KswUnicodeStringContainsInsensitive(
    _In_opt_ PCUNICODE_STRING Value,
    _In_z_ PCWSTR NeedleText
    )
{
    UNICODE_STRING needle;
    ULONG valueChars;
    ULONG needleChars;
    ULONG startIndex;
    ULONG needleIndex;

    if (Value == NULL ||
        Value->Buffer == NULL ||
        Value->Length == 0 ||
        NeedleText == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&needle, NeedleText);
    if (needle.Buffer == NULL || needle.Length == 0) {
        return FALSE;
    }

    valueChars = Value->Length / (ULONG)sizeof(WCHAR);
    needleChars = needle.Length / (ULONG)sizeof(WCHAR);
    if (needleChars == 0 || valueChars < needleChars) {
        return FALSE;
    }

    for (startIndex = 0;
         startIndex <= valueChars - needleChars;
         ++startIndex) {
        for (needleIndex = 0;
             needleIndex < needleChars;
             ++needleIndex) {
            if (RtlUpcaseUnicodeChar(Value->Buffer[startIndex + needleIndex]) !=
                RtlUpcaseUnicodeChar(needle.Buffer[needleIndex])) {
                break;
            }
        }

        if (needleIndex == needleChars) {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Applies the built-in sandbox self-noise path filter.
 *
 * Inputs : FileName is a normalized or fallback subject path.
 * Logic  : suppresses known KSword infrastructure locations that are produced
 *          by the guest agent, R0Collector, driver staging, and telemetry output
 *          while leaving sample paths such as \KSwordSandbox\incoming\*
 *          observable.
 * Return : TRUE when the event should not be queued.
 */
static
BOOLEAN
KswIsSandboxSelfPath(
    _In_opt_ PCUNICODE_STRING FileName
    )
{
    if (FileName == NULL ||
        FileName->Buffer == NULL ||
        FileName->Length == 0) {
        return FALSE;
    }

    if (KswUnicodeStringContainsInsensitive(
            FileName,
            L"\\KSwordSandbox\\agent\\") ||
        KswUnicodeStringContainsInsensitive(
            FileName,
            L"\\KSwordSandbox\\r0collector\\") ||
        KswUnicodeStringContainsInsensitive(
            FileName,
            L"\\KSwordSandbox\\driver\\") ||
        KswUnicodeStringContainsInsensitive(
            FileName,
            L"\\KSwordSandbox\\out\\") ||
        KswUnicodeStringContainsInsensitive(
            FileName,
            L"\\KSwordSandboxDriver")) {
        return TRUE;
    }

    return FALSE;
}

/*
 * Maps a minifilter callback to the public file operation ABI.
 *
 * Inputs : Data is the FltMgr callback data for one file-system operation.
 * Logic  : common create/read/write/lifetime operations map directly; selected
 *          SET_INFORMATION classes are normalized to Rename/Delete and all
 *          remaining metadata updates are preserved as SetInformation.
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

    case IRP_MJ_READ:
        return KswSandboxFileOperationRead;

    case IRP_MJ_WRITE:
        return KswSandboxFileOperationWrite;

    case IRP_MJ_SET_INFORMATION:
        informationClass =
            Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (KswIsDeleteInformationClass(informationClass)) {
            return KswSandboxFileOperationDelete;
        }
        if (KswIsRenameInformationClass(informationClass)) {
            return KswSandboxFileOperationRename;
        }
        return KswSandboxFileOperationSetInformation;

    case IRP_MJ_CLEANUP:
        return KswSandboxFileOperationCleanup;

    case IRP_MJ_CLOSE:
        return KswSandboxFileOperationClose;

    default:
        return KswSandboxFileOperationNone;
    }
}

/*
 * Copies a bounded UTF-16 file name into a file event payload.
 *
 * Inputs : Payload receives the copied name; FileName is an optional source
 *          UNICODE_STRING; SourceFlag identifies normalized vs fallback names.
 * Logic  : copies at most PATH_CHARS - 1 WCHARs, stores a NUL terminator, and
 *          marks truncation when the original path exceeds the fixed payload.
 * Return : TRUE when a non-empty bounded path was copied; FALSE otherwise.
 */
static
BOOLEAN
KswCopyFilePathToPayload(
    _Inout_ PKSWORD_SANDBOX_FILE_EVENT_PAYLOAD Payload,
    _In_opt_ PCUNICODE_STRING FileName,
    _In_ ULONG SourceFlag
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
        return FALSE;
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
        return FALSE;
    }

    RtlCopyMemory(Payload->Path, FileName->Buffer, bytesToCopy);
    copiedChars = bytesToCopy / (ULONG)sizeof(WCHAR);
    Payload->Path[copiedChars] = L'\0';
    Payload->PathLengthBytes = bytesToCopy;
    Payload->Flags |=
        KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT |
        SourceFlag;

    return TRUE;
}

/*
 * Attempts to capture a normalized FltMgr path into the file payload.
 *
 * Inputs : Data is the callback data, Payload receives the bounded path, and
 *          SuppressEvent receives whether the full source path matched the
 *          sandbox self-noise policy.
 * Logic  : first asks FltMgr for a normalized name using the default query
 *          policy, then falls back to cache-only lookup for close/cleanup or
 *          other contexts where a file-system name query is unsafe.  Filtering
 *          is evaluated on the full FltMgr name before payload truncation.
 * Return : TRUE when a normalized path was copied; FALSE otherwise.
 */
static
BOOLEAN
KswCopyNormalizedFilePathToPayload(
    _In_ PFLT_CALLBACK_DATA Data,
    _Inout_ PKSWORD_SANDBOX_FILE_EVENT_PAYLOAD Payload,
    _Out_ PBOOLEAN SuppressEvent
    )
{
    PFLT_FILE_NAME_INFORMATION nameInformation;
    NTSTATUS status;
    BOOLEAN copied;

    if (SuppressEvent != NULL) {
        *SuppressEvent = FALSE;
    }

    if (Data == NULL ||
        Payload == NULL ||
        SuppressEvent == NULL ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    nameInformation = NULL;
    copied = FALSE;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInformation);
    if (!NT_SUCCESS(status)) {
        nameInformation = NULL;
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED |
                FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
            &nameInformation);
    }

    if (NT_SUCCESS(status) && nameInformation != NULL) {
        if (KswIsSandboxSelfPath(&nameInformation->Name)) {
            *SuppressEvent = TRUE;
        } else {
            copied = KswCopyFilePathToPayload(
                Payload,
                &nameInformation->Name,
                KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_NORMALIZED);
        }
    }

    if (nameInformation != NULL) {
        FltReleaseFileNameInformation(nameInformation);
    }

    return copied;
}

/*
 * Captures the best available path for a file callback.
 *
 * Inputs : Data and FltObjects identify the file operation; Payload receives a
 *          normalized name when available or a bounded FILE_OBJECT fallback;
 *          SuppressEvent receives sandbox self-filter matches.
 * Logic  : avoids name work above APC_LEVEL, prefers FltMgr-normalized names,
 *          filters full source paths before truncation, and only falls back to
 *          FILE_OBJECT.FileName when normalization fails.
 * Return : TRUE when a path was copied; FALSE otherwise.
 */
static
BOOLEAN
KswCopyBestFilePathToPayload(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PKSWORD_SANDBOX_FILE_EVENT_PAYLOAD Payload,
    _Out_ PBOOLEAN SuppressEvent
    )
{
    if (SuppressEvent != NULL) {
        *SuppressEvent = FALSE;
    }

    if (Payload == NULL ||
        SuppressEvent == NULL ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    if (KswCopyNormalizedFilePathToPayload(Data, Payload, SuppressEvent)) {
        return TRUE;
    }

    if (*SuppressEvent) {
        return FALSE;
    }

    if (FltObjects == NULL || FltObjects->FileObject == NULL) {
        return FALSE;
    }

    if (KswIsSandboxSelfPath(&FltObjects->FileObject->FileName)) {
        *SuppressEvent = TRUE;
        return FALSE;
    }

    return KswCopyFilePathToPayload(
        Payload,
        &FltObjects->FileObject->FileName,
        KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_FALLBACK);
}

/*
 * Tests whether a completed payload should be suppressed as sandbox self-noise.
 *
 * Inputs : Payload is the bounded file event payload after path capture.
 * Logic  : reconstructs a bounded UNICODE_STRING over the inline path and
 *          applies the static KSword infrastructure path rules.
 * Return : TRUE when the caller should skip KswPushEvent.
 */
static
BOOLEAN
KswShouldSuppressFilePayload(
    _In_ const KSWORD_SANDBOX_FILE_EVENT_PAYLOAD* Payload
    )
{
    UNICODE_STRING path;

    if (Payload == NULL ||
        (Payload->Flags & KSWORD_SANDBOX_FILE_EVENT_FLAG_PATH_PRESENT) == 0 ||
        Payload->PathLengthBytes == 0) {
        return FALSE;
    }

    RtlZeroMemory(&path, sizeof(path));
    path.Buffer = (PWCH)Payload->Path;
    path.Length = (USHORT)Payload->PathLengthBytes;
    path.MaximumLength =
        (USHORT)(Payload->PathLengthBytes + (ULONG)sizeof(WCHAR));

    return KswIsSandboxSelfPath(&path);
}

/*
 * Records unexpected shared-ring enqueue failures for health diagnostics.
 *
 * Inputs : DeviceExtension owns LastStatus; PushStatus is the KswPushEvent
 *          result.
 * Logic  : producer-disabled STATUS_CANCELLED is expected operator policy and
 *          already increments EventsSuppressed in EventQueue, so only true
 *          write/format failures are promoted to LastStatus.
 * Return : no return value.
 */
static
VOID
KswRecordFileEventPushStatus(
    _Inout_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension,
    _In_ NTSTATUS PushStatus
    )
{
    if (NT_SUCCESS(PushStatus) || PushStatus == STATUS_CANCELLED) {
        return;
    }

    KswSetLastStatus(DeviceExtension, PushStatus);
}

/*
 * Builds and queues one file event into the existing READ_EVENTS ring.
 *
 * Inputs : Data and FltObjects describe the completed file operation;
 *          Operation is the public file operation; IsPostOperation indicates
 *          whether Data->IoStatus.Status is final.
 * Logic  : fills a stack payload, prefers normalized FltMgr names, marks
 *          fallback/truncation flags, suppresses known sandbox self paths, and
 *          calls the existing KswPushEvent producer to preserve READ_EVENTS
 *          framing and drop accounting.
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
    NTSTATUS pushStatus;
    BOOLEAN suppressEvent;

    if (Data == NULL ||
        Operation == KswSandboxFileOperationNone ||
        InterlockedCompareExchange(&g_KswFileFilterRuntime.Active, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswFileFilterRuntime.DeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    RtlZeroMemory(&payload, sizeof(payload));
    suppressEvent = FALSE;
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
        if (!NT_SUCCESS(payload.Status)) {
            payload.Flags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_OPERATION_FAILED;
        }
    }

    if (Operation == KswSandboxFileOperationDelete) {
        payload.Flags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_DELETE_INTENT;
    } else if (Operation == KswSandboxFileOperationRename) {
        payload.Flags |= KSWORD_SANDBOX_FILE_EVENT_FLAG_RENAME_INTENT;
    }

    (VOID)KswCopyBestFilePathToPayload(
        Data,
        FltObjects,
        &payload,
        &suppressEvent);
    if (suppressEvent || KswShouldSuppressFilePayload(&payload)) {
        return;
    }

    pushStatus = KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeFile,
        0,
        &payload,
        (ULONG)sizeof(payload));
    KswRecordFileEventPushStatus(deviceExtension, pushStatus);
}

/*
 * Handles FltMgr pre-operation callbacks for selected file operations.
 *
 * Inputs : Data and FltObjects describe the current file-system request;
 *          CompletionContext is unused and always cleared.
 * Logic  : maps the operation, emits CLOSE immediately because it is registered
 *          without a post callback, and requests a post-operation callback for
 *          the remaining supported telemetry events so final status is
 *          preserved.
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

    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    operation = KswMapFileOperation(Data);
    if (operation == KswSandboxFileOperationNone ||
        InterlockedCompareExchange(&g_KswFileFilterRuntime.Active, 0, 0) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data != NULL &&
        Data->Iopb != NULL &&
        Data->Iopb->MajorFunction == IRP_MJ_CLOSE) {
        KswPushFileEvent(Data, FltObjects, operation, FALSE);
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
 * Logic  : delegates to the same cleanup path used by DriverUnload.  The shared
 *          cleanup routine is guarded so direct DriverUnload and FltMgr unload
 *          paths unregister the filter at most once.
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

    KswUninitializeFileFilter();

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
    InterlockedExchange(&g_KswFileFilterUninitializing, 0);
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
 * Logic  : runs once, clears Active so new callbacks skip emission, unregisters
 *          the FltMgr filter handle, and clears the device-extension pointer
 *          before the WDM control device is deleted.
 * Return : no return value.
 */
VOID
KswUninitializeFileFilter(
    VOID
    )
{
    PFLT_FILTER filter;

    if (InterlockedExchange(&g_KswFileFilterUninitializing, 1) != 0) {
        return;
    }

    InterlockedExchange(&g_KswFileFilterRuntime.Active, 0);

    filter = g_KswFileFilterRuntime.Filter;
    g_KswFileFilterRuntime.Filter = NULL;

    if (filter != NULL) {
        FltUnregisterFilter(filter);
    }

    g_KswFileFilterRuntime.DeviceExtension = NULL;
    g_KswFileFilterRuntime.RegisterStatus = STATUS_NOT_SUPPORTED;
    g_KswFileFilterRuntime.StartStatus = STATUS_NOT_SUPPORTED;
}
