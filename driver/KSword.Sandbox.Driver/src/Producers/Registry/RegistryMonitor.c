#include "Producers/Registry/RegistryMonitor.h"
#include "Common/KernelString.h"

/*
 * Registry callback altitude for local KSword sandbox research builds.
 *
 * Inputs : consumed by CmRegisterCallbackEx during DriverEntry.
 * Logic  : Configuration Manager callbacks require a unique altitude string.
 *          This test altitude is intentionally separate from the minifilter
 *          altitude and can be replaced by an assigned production value later.
 * Return : not applicable; duplicate altitude registration fails and is
 *          surfaced through GET_HEALTH.LastNtStatus.
 */
#define KSWORD_SANDBOX_REGISTRY_CALLBACK_ALTITUDE L"385201.7337"

static PKSWORD_SANDBOX_DEVICE_EXTENSION g_KswRegistryMonitorDeviceExtension;
static LARGE_INTEGER g_KswRegistryCallbackCookie;
static volatile LONG g_KswRegistryMonitorActive;
static volatile LONG g_KswRegistryCallbackRegistered;

/*
 * Builds a bounded, read-only UNICODE_STRING view for registry callback text.
 * Inputs : Source is callback-owned optional UTF-16 text; SafeSource receives a
 *          clamped view whose Length never exceeds MaximumLength.
 * Logic  : registry names are copied only at IRQL <= APC_LEVEL, odd byte counts
 *          are rounded down to full WCHARs, and no allocation is performed.
 * Return : TRUE when SafeSource can be passed to KswCopyUnicodePrefix.
 */
static
BOOLEAN
KswPrepareRegistryCallbackString(
    _In_opt_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING SafeSource
    )
{
    USHORT safeLength;

    if (SafeSource == NULL) {
        return FALSE;
    }

    RtlZeroMemory(SafeSource, sizeof(*SafeSource));
    if (Source == NULL ||
        Source->Buffer == NULL ||
        Source->Length == 0 ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    safeLength = Source->Length;
    if (Source->MaximumLength != 0 && safeLength > Source->MaximumLength) {
        safeLength = Source->MaximumLength;
    }

    safeLength = (USHORT)(safeLength - (safeLength % (USHORT)sizeof(WCHAR)));
    if (safeLength == 0) {
        return FALSE;
    }

    SafeSource->Buffer = Source->Buffer;
    SafeSource->Length = safeLength;
    SafeSource->MaximumLength = safeLength;
    return TRUE;
}

/*
 * Copies optional UTF-16 registry metadata into a compact payload field.
 * Inputs : Destination is a fixed WCHAR field, DestinationChars is the capacity,
 *          Source may be NULL, PresentFlag and TruncatedFlag are payload bits,
 *          Flags and LengthBytes belong to the target payload.
 * Logic  : validates IRQL and UNICODE_STRING bounds before delegating to the
 *          shared kernel string helper.
 * Return : TRUE when text was copied; FALSE when the field is absent. Flags and
 *          LengthBytes are updated in place.
 */
static
BOOLEAN
KswCopyRegistryPayloadString(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source,
    _In_ ULONG PresentFlag,
    _In_ ULONG TruncatedFlag,
    _Inout_ PULONG Flags,
    _Out_ PULONG LengthBytes
    )
{
    BOOLEAN truncated;
    BOOLEAN copied;
    ULONG bytesCopied;
    UNICODE_STRING safeSource;

    if (Destination == NULL ||
        DestinationChars == 0 ||
        Flags == NULL ||
        LengthBytes == NULL) {
        return FALSE;
    }

    Destination[0] = L'\0';
    *LengthBytes = 0;
    truncated = FALSE;
    copied = FALSE;
    bytesCopied = 0;

    if (KswPrepareRegistryCallbackString(Source, &safeSource) &&
        KswCopyUnicodePrefix(
            Destination,
            DestinationChars,
            &safeSource,
            &bytesCopied,
            &truncated)) {
        *Flags |= PresentFlag;
        *LengthBytes = bytesCopied;
        copied = TRUE;
    }

    if (truncated) {
        *Flags |= TruncatedFlag;
    }

    return copied;
}

/*
 * Resolves a registry key object to a bounded key path in a payload.
 * Inputs : KeyObject is a Configuration Manager registry object pointer and
 *          Payload receives compact key metadata.
 * Logic  : uses CmCallbackGetKeyObjectIDEx only when the callback cookie and
 *          IRQL allow name lookup, copies a bounded prefix, then releases the
 *          name buffer through CmCallbackReleaseKeyObjectIDEx.
 * Return : TRUE when a key name was copied; missing names simply leave
 *          key-present unset.
 */
static
BOOLEAN
KswCopyRegistryKeyObjectPath(
    _In_opt_ PVOID KeyObject,
    _Inout_ PKSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD Payload
    )
{
    NTSTATUS status;
    PCUNICODE_STRING keyName;
    BOOLEAN copied;

    if (Payload == NULL ||
        KeyObject == NULL ||
        g_KswRegistryCallbackCookie.QuadPart == 0 ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    keyName = NULL;
    status = CmCallbackGetKeyObjectIDEx(
        &g_KswRegistryCallbackCookie,
        KeyObject,
        NULL,
        &keyName,
        0);
    if (!NT_SUCCESS(status) || keyName == NULL) {
        return FALSE;
    }

    copied = KswCopyRegistryPayloadString(
        Payload->KeyPath,
        KSWORD_SANDBOX_REGISTRY_KEY_PATH_CHARS,
        keyName,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED,
        &Payload->Flags,
        &Payload->KeyPathLengthBytes);
    if (copied) {
        Payload->Flags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_OBJECT;
    }
    CmCallbackReleaseKeyObjectIDEx(keyName);
    return copied;
}

/*
 * Initializes registry payload fields common to all operations.
 * Inputs : Payload receives the fixed record; Operation is the public operation
 *          value and Status is the post-operation NTSTATUS.
 * Logic  : stamps ABI metadata, captures current PID, records status, and marks
 *          the status-present bit for collector diagnostics.
 * Return : no return value; Payload is ready for optional key/value copies.
 */
static
VOID
KswInitializeRegistryPayload(
    _Out_ PKSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD Payload,
    _In_ ULONG Operation,
    _In_ NTSTATUS Status
    )
{
    RtlZeroMemory(Payload, sizeof(*Payload));
    Payload->Version = KSWORD_SANDBOX_REGISTRY_EVENT_VERSION;
    Payload->Size = sizeof(*Payload);
    Payload->Operation = Operation;
    Payload->Flags =
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_STATUS_PRESENT |
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_POST_OPERATION;
    Payload->ProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    Payload->Status = Status;
}

/*
 * Queues one registry event through the shared event ring.
 * Inputs : Payload is a fully initialized compact registry record.
 * Logic  : validates active state and the shared device extension, then uses
 *          KswPushEvent so collectors read registry events through READ_EVENTS.
 * Return : no return value; enqueue failures are intentionally ignored so the
 *          observed registry operation is never modified by telemetry.
 */
static
VOID
KswQueueRegistryEvent(
    _In_ const KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD* Payload
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    NTSTATUS status;

    if (Payload == NULL ||
        InterlockedCompareExchange(&g_KswRegistryMonitorActive, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswRegistryMonitorDeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    status = KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeRegistry,
        0,
        Payload,
        (ULONG)sizeof(*Payload));
    if (!NT_SUCCESS(status) && status != STATUS_CANCELLED) {
        /*
         * Producer enable masks intentionally surface disabled registry events
         * as STATUS_CANCELLED from KswPushEvent.  Any other failure is an
         * unexpected ABI/state problem worth exposing through health telemetry.
         */
        KswSetLastStatus(deviceExtension, status);
    }
}

/*
 * Captures a completed create-key or open-key registry operation.
 * Inputs : PostInfo is the Configuration Manager post-operation record;
 *          Operation identifies create versus open.
 * Logic  : extracts CompleteName from the pre-operation information, records
 *          final status, copies a bounded key prefix, and queues one event.
 * Return : no return value.
 */
static
VOID
KswCapturePostCreateOrOpenKey(
    _In_opt_ PREG_POST_OPERATION_INFORMATION PostInfo,
    _In_ ULONG Operation
    )
{
    KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD payload;
    PCUNICODE_STRING keyName;
    BOOLEAN copied;

    if (PostInfo == NULL || PostInfo->PreInformation == NULL) {
        return;
    }

    keyName = Operation == KswSandboxRegistryOperationCreateKey
        ? ((PREG_CREATE_KEY_INFORMATION)PostInfo->PreInformation)->CompleteName
        : ((PREG_OPEN_KEY_INFORMATION)PostInfo->PreInformation)->CompleteName;

    KswInitializeRegistryPayload(&payload, Operation, PostInfo->Status);
    copied = KswCopyRegistryPayloadString(
        payload.KeyPath,
        KSWORD_SANDBOX_REGISTRY_KEY_PATH_CHARS,
        keyName,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED,
        &payload.Flags,
        &payload.KeyPathLengthBytes);
    if (copied) {
        payload.Flags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_CALLBACK;
    }
    if (!copied && PostInfo->Object != NULL) {
        (VOID)KswCopyRegistryKeyObjectPath(PostInfo->Object, &payload);
    }
    KswQueueRegistryEvent(&payload);
}

/*
 * Captures legacy completed create-key or open-key registry operations.
 * Inputs : PostInfo is the XP-style post-operation record for RegNtPostCreateKey
 *          or RegNtPostOpenKey; Operation identifies create versus open.
 * Logic  : preserves compatibility with non-Ex create/open notifications by
 *          copying CompleteName directly, falling back to the returned object
 *          path when available, then queueing the same public registry payload.
 * Return : no return value.
 */
static
VOID
KswCaptureLegacyPostCreateOrOpenKey(
    _In_opt_ PREG_POST_CREATE_KEY_INFORMATION PostInfo,
    _In_ ULONG Operation
    )
{
    KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD payload;
    BOOLEAN copied;

    if (PostInfo == NULL) {
        return;
    }

    KswInitializeRegistryPayload(&payload, Operation, PostInfo->Status);
    copied = KswCopyRegistryPayloadString(
        payload.KeyPath,
        KSWORD_SANDBOX_REGISTRY_KEY_PATH_CHARS,
        PostInfo->CompleteName,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_PRESENT,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_TRUNCATED,
        &payload.Flags,
        &payload.KeyPathLengthBytes);
    if (copied) {
        payload.Flags |= KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_KEY_FROM_CALLBACK;
    }
    if (!copied && PostInfo->Object != NULL) {
        (VOID)KswCopyRegistryKeyObjectPath(PostInfo->Object, &payload);
    }
    KswQueueRegistryEvent(&payload);
}

/*
 * Captures a completed set-value registry operation.
 * Inputs : PostInfo is the post-operation record for RegNtPostSetValueKey.
 * Logic  : resolves the key object path, copies the value name prefix, records
 *          final status, and queues a compact event without copying value data.
 * Return : no return value.
 */
static
VOID
KswCapturePostSetValue(
    _In_opt_ PREG_POST_OPERATION_INFORMATION PostInfo
    )
{
    PREG_SET_VALUE_KEY_INFORMATION preInfo;
    KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD payload;
    PVOID keyObject;

    if (PostInfo == NULL || PostInfo->PreInformation == NULL) {
        return;
    }

    preInfo = (PREG_SET_VALUE_KEY_INFORMATION)PostInfo->PreInformation;
    keyObject = preInfo->Object != NULL ? preInfo->Object : PostInfo->Object;

    KswInitializeRegistryPayload(
        &payload,
        KswSandboxRegistryOperationSetValue,
        PostInfo->Status);
    payload.ValueDataType = preInfo->Type;
    payload.ValueDataSizeBytes = preInfo->DataSize;
    payload.Flags |=
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TYPE_PRESENT |
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_SIZE_PRESENT;
    KswCopyRegistryKeyObjectPath(keyObject, &payload);
    KswCopyRegistryPayloadString(
        payload.ValueName,
        KSWORD_SANDBOX_REGISTRY_VALUE_NAME_CHARS,
        preInfo->ValueName,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TRUNCATED,
        &payload.Flags,
        &payload.ValueNameLengthBytes);
    KswQueueRegistryEvent(&payload);
}

/*
 * Captures a completed delete-key registry operation.
 * Inputs : PostInfo is the post-operation record for RegNtPostDeleteKey.
 * Logic  : resolves the deleted key object name when possible, records final
 *          status, and queues one compact event.
 * Return : no return value.
 */
static
VOID
KswCapturePostDeleteKey(
    _In_opt_ PREG_POST_OPERATION_INFORMATION PostInfo
    )
{
    PREG_DELETE_KEY_INFORMATION preInfo;
    KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD payload;
    PVOID keyObject;

    if (PostInfo == NULL || PostInfo->PreInformation == NULL) {
        return;
    }

    preInfo = (PREG_DELETE_KEY_INFORMATION)PostInfo->PreInformation;
    keyObject = preInfo->Object != NULL ? preInfo->Object : PostInfo->Object;

    KswInitializeRegistryPayload(
        &payload,
        KswSandboxRegistryOperationDeleteKey,
        PostInfo->Status);
    KswCopyRegistryKeyObjectPath(keyObject, &payload);
    KswQueueRegistryEvent(&payload);
}

/*
 * Captures a completed delete-value registry operation.
 * Inputs : PostInfo is the post-operation record for RegNtPostDeleteValueKey.
 * Logic  : resolves the key path, copies the deleted value name prefix, records
 *          final status, and queues one compact event.
 * Return : no return value.
 */
static
VOID
KswCapturePostDeleteValue(
    _In_opt_ PREG_POST_OPERATION_INFORMATION PostInfo
    )
{
    PREG_DELETE_VALUE_KEY_INFORMATION preInfo;
    KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD payload;
    PVOID keyObject;

    if (PostInfo == NULL || PostInfo->PreInformation == NULL) {
        return;
    }

    preInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)PostInfo->PreInformation;
    keyObject = preInfo->Object != NULL ? preInfo->Object : PostInfo->Object;

    KswInitializeRegistryPayload(
        &payload,
        KswSandboxRegistryOperationDeleteValue,
        PostInfo->Status);
    KswCopyRegistryKeyObjectPath(keyObject, &payload);
    KswCopyRegistryPayloadString(
        payload.ValueName,
        KSWORD_SANDBOX_REGISTRY_VALUE_NAME_CHARS,
        preInfo->ValueName,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TRUNCATED,
        &payload.Flags,
        &payload.ValueNameLengthBytes);
    KswQueueRegistryEvent(&payload);
}

/*
 * Captures a completed rename-key registry operation.
 * Inputs : PostInfo is the post-operation record for RegNtPostRenameKey.
 * Logic  : resolves the original key path, stores the new key name in the value
 *          field for compact reporting, records final status, and queues event.
 * Return : no return value.
 */
static
VOID
KswCapturePostRenameKey(
    _In_opt_ PREG_POST_OPERATION_INFORMATION PostInfo
    )
{
    PREG_RENAME_KEY_INFORMATION preInfo;
    KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD payload;
    PVOID keyObject;

    if (PostInfo == NULL || PostInfo->PreInformation == NULL) {
        return;
    }

    preInfo = (PREG_RENAME_KEY_INFORMATION)PostInfo->PreInformation;
    keyObject = preInfo->Object != NULL ? preInfo->Object : PostInfo->Object;

    KswInitializeRegistryPayload(
        &payload,
        KswSandboxRegistryOperationRenameKey,
        PostInfo->Status);
    KswCopyRegistryKeyObjectPath(keyObject, &payload);
    KswCopyRegistryPayloadString(
        payload.ValueName,
        KSWORD_SANDBOX_REGISTRY_VALUE_NAME_CHARS,
        preInfo->NewName,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_PRESENT,
        KSWORD_SANDBOX_REGISTRY_EVENT_FLAG_VALUE_TRUNCATED,
        &payload.Flags,
        &payload.ValueNameLengthBytes);
    KswQueueRegistryEvent(&payload);
}

/*
 * Configuration Manager registry callback.
 * Inputs : CallbackContext is unused because module-local state owns the device
 *          extension; Argument1 is REG_NOTIFY_CLASS and Argument2 is the typed
 *          post-operation structure.
 * Logic  : observes selected post-operation notifications and queues compact
 *          registry records while always preserving the original operation.
 * Return : STATUS_SUCCESS so the registry operation is never blocked.
 */
static
NTSTATUS
KswRegistryCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (InterlockedCompareExchange(&g_KswRegistryMonitorActive, 0, 0) == 0) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    switch (notifyClass) {
    case RegNtPostCreateKey:
        KswCaptureLegacyPostCreateOrOpenKey(
            (PREG_POST_CREATE_KEY_INFORMATION)Argument2,
            KswSandboxRegistryOperationCreateKey);
        break;

    case RegNtPostCreateKeyEx:
        KswCapturePostCreateOrOpenKey(
            (PREG_POST_OPERATION_INFORMATION)Argument2,
            KswSandboxRegistryOperationCreateKey);
        break;

    case RegNtPostOpenKey:
        KswCaptureLegacyPostCreateOrOpenKey(
            (PREG_POST_OPEN_KEY_INFORMATION)Argument2,
            KswSandboxRegistryOperationOpenKey);
        break;

    case RegNtPostOpenKeyEx:
        KswCapturePostCreateOrOpenKey(
            (PREG_POST_OPERATION_INFORMATION)Argument2,
            KswSandboxRegistryOperationOpenKey);
        break;

    case RegNtPostSetValueKey:
        KswCapturePostSetValue((PREG_POST_OPERATION_INFORMATION)Argument2);
        break;

    case RegNtPostDeleteKey:
        KswCapturePostDeleteKey((PREG_POST_OPERATION_INFORMATION)Argument2);
        break;

    case RegNtPostDeleteValueKey:
        KswCapturePostDeleteValue((PREG_POST_OPERATION_INFORMATION)Argument2);
        break;

    case RegNtPostRenameKey:
        KswCapturePostRenameKey((PREG_POST_OPERATION_INFORMATION)Argument2);
        break;

    default:
        break;
    }

    return STATUS_SUCCESS;
}

/*
 * Initializes registry telemetry callbacks.
 * Inputs : DriverObject identifies this driver for CmRegisterCallbackEx;
 *          DeviceExtension owns the READ_EVENTS ring.
 * Logic  : registers the callback at the local altitude, stores the cookie, and
 *          enables event emission only after registration succeeds.
 * Return : STATUS_SUCCESS when active or the registration failure NTSTATUS.
 */
NTSTATUS
KswInitializeRegistryMonitor(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (DriverObject == NULL ||
        DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    g_KswRegistryMonitorDeviceExtension = DeviceExtension;
    g_KswRegistryCallbackCookie.QuadPart = 0;
    InterlockedExchange(&g_KswRegistryCallbackRegistered, 0);
    InterlockedExchange(&g_KswRegistryMonitorActive, 0);

    RtlInitUnicodeString(&altitude, KSWORD_SANDBOX_REGISTRY_CALLBACK_ALTITUDE);
    status = CmRegisterCallbackEx(
        KswRegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_KswRegistryCallbackCookie,
        NULL);
    if (!NT_SUCCESS(status)) {
        g_KswRegistryMonitorDeviceExtension = NULL;
        return status;
    }

    InterlockedExchange(&g_KswRegistryCallbackRegistered, 1);
    InterlockedExchange(&g_KswRegistryMonitorActive, 1);
    return STATUS_SUCCESS;
}

/*
 * Stops registry telemetry callbacks.
 * Inputs : none; callback cookie storage is module-local.
 * Logic  : disables event emission, unregisters the Configuration Manager
 *          callback if it was registered, and clears stale pointers before the
 *          control device extension can be deleted.
 * Return : no return value.
 */
VOID
KswUninitializeRegistryMonitor(
    VOID
    )
{
    LARGE_INTEGER callbackCookie;
    LONG callbackRegistered;

    InterlockedExchange(&g_KswRegistryMonitorActive, 0);
    callbackRegistered = InterlockedExchange(&g_KswRegistryCallbackRegistered, 0);
    callbackCookie = g_KswRegistryCallbackCookie;

    if (callbackRegistered != 0 ||
        callbackCookie.QuadPart != 0) {
        (VOID)CmUnRegisterCallback(callbackCookie);
    }

    g_KswRegistryCallbackCookie.QuadPart = 0;
    g_KswRegistryMonitorDeviceExtension = NULL;
}
