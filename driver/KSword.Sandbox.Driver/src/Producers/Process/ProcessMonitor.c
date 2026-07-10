#include "Producers/Process/ProcessMonitor.h"
#include "Common/KernelString.h"

/*
 * Process notify registration mode.
 *
 * Inputs : written after process callback registration.
 * Logic  : unload must remove the same callback form that was registered.
 * Return : not applicable.
 */
typedef enum _KSWORD_SANDBOX_PROCESS_NOTIFY_MODE {
    KswProcessNotifyModeNone = 0,
    KswProcessNotifyModeEx = 1,
    KswProcessNotifyModeLegacy = 2
} KSWORD_SANDBOX_PROCESS_NOTIFY_MODE;

static PKSWORD_SANDBOX_DEVICE_EXTENSION g_KswProcessMonitorDeviceExtension;
static volatile LONG g_KswProcessMonitorActive;
static volatile LONG g_KswProcessCallbackRegistered;
static volatile LONG g_KswImageCallbackRegistered;
static ULONG g_KswProcessNotifyMode;

static VOID
KswProcessCreateNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

static VOID
KswProcessCreateNotifyLegacy(
    _In_opt_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    );

static VOID
KswLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

/*
 * Copies an optional callback string into a process payload field.
 * Inputs : Destination is fixed payload storage; Source may be NULL; PresentFlag
 *          and TruncatedFlag identify the payload bits to update.
 * Logic  : uses the shared bounded UTF-16 helper and stores byte counts without
 *          allocating or touching pageable buffers above the callback contract.
 * Return : no return value; flags and length are updated in place.
 */
static
VOID
KswCopyProcessPayloadString(
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
    ULONG bytesCopied;

    if (Flags == NULL || LengthBytes == NULL) {
        return;
    }

    *LengthBytes = 0;
    truncated = FALSE;
    bytesCopied = 0;

    if (KswCopyUnicodePrefix(
            Destination,
            DestinationChars,
            Source,
            &bytesCopied,
            &truncated)) {
        *Flags |= PresentFlag;
        *LengthBytes = bytesCopied;
    }

    if (truncated) {
        *Flags |= TruncatedFlag;
    }
}

/*
 * Queues one process event through the shared READ_EVENTS ring.
 * Inputs : Payload is a fully initialized fixed process record.
 * Logic  : checks active state and shared device-extension validity, then uses
 *          KswPushEvent so collectors read process events through existing IOCTLs.
 * Return : no return value; enqueue failures are ignored by callback paths.
 */
static
VOID
KswQueueProcessEvent(
    _In_ const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD* Payload
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;

    if (Payload == NULL ||
        InterlockedCompareExchange(&g_KswProcessMonitorActive, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswProcessMonitorDeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    (VOID)KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeProcess,
        0,
        Payload,
        (ULONG)sizeof(*Payload));
}

/*
 * Queues one image-load event through the shared READ_EVENTS ring.
 * Inputs : Payload is a fully initialized fixed image record.
 * Logic  : checks active state and shared device-extension validity, then uses
 *          KswPushEvent with KswSandboxEventTypeImage.
 * Return : no return value; enqueue failures are ignored by callback paths.
 */
static
VOID
KswQueueImageEvent(
    _In_ const KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD* Payload
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;

    if (Payload == NULL ||
        InterlockedCompareExchange(&g_KswProcessMonitorActive, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswProcessMonitorDeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    (VOID)KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeImage,
        0,
        Payload,
        (ULONG)sizeof(*Payload));
}

/*
 * Emits a process create or exit event from the Ex callback.
 * Inputs : Process and ProcessId identify the target process; CreateInfo is
 *          present for create and NULL for exit.
 * Logic  : captures lineage, create status, image/command prefixes, and exit
 *          status when available, then queues a compact fixed payload.
 * Return : no return value.
 */
static
VOID
KswProcessCreateNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD payload;

    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = KSWORD_SANDBOX_PROCESS_EVENT_VERSION;
    payload.Size = sizeof(payload);
    payload.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    payload.Flags = KSWORD_SANDBOX_PROCESS_EVENT_FLAG_EX_CALLBACK;

    if (CreateInfo != NULL) {
        payload.Operation = KswSandboxProcessOperationCreate;
        payload.ParentProcessId = (ULONGLONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
        payload.Status = CreateInfo->CreationStatus;
        payload.Flags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT;
        KswCopyProcessPayloadString(
            payload.ImagePath,
            KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS,
            CreateInfo->ImageFileName,
            KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT,
            KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED,
            &payload.Flags,
            &payload.ImagePathLengthBytes);
        KswCopyProcessPayloadString(
            payload.CommandLine,
            KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS,
            CreateInfo->CommandLine,
            KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT,
            KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED,
            &payload.Flags,
            &payload.CommandLineLengthBytes);
    } else {
        payload.Operation = KswSandboxProcessOperationExit;
        if (Process != NULL && KeGetCurrentIrql() <= APC_LEVEL) {
            payload.Status = PsGetProcessExitStatus(Process);
            payload.Flags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT;
        }
    }

    KswQueueProcessEvent(&payload);
}

/*
 * Emits a process create or exit event from the legacy callback fallback.
 * Inputs : ParentId and ProcessId come from the legacy notify API; Create marks
 *          create versus exit.
 * Logic  : captures only IDs because the legacy API does not expose image path,
 *          command line, or operation status.
 * Return : no return value.
 */
static
VOID
KswProcessCreateNotifyLegacy(
    _In_opt_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
    )
{
    KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD payload;

    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = KSWORD_SANDBOX_PROCESS_EVENT_VERSION;
    payload.Size = sizeof(payload);
    payload.Operation = Create ?
        KswSandboxProcessOperationCreate :
        KswSandboxProcessOperationExit;
    payload.Flags = KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LEGACY_CALLBACK;
    payload.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    payload.ParentProcessId = (ULONGLONG)(ULONG_PTR)ParentId;
    KswQueueProcessEvent(&payload);
}

/*
 * Emits an image-load event from PsSetLoadImageNotifyRoutine.
 * Inputs : FullImageName is optional path text; ProcessId identifies the target
 *          process for user images; ImageInfo supplies base, size, and mode.
 * Logic  : copies fixed numeric fields and a bounded UTF-16 path prefix, then
 *          queues the record through the shared event ring.
 * Return : no return value.
 */
static
VOID
KswLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD payload;
    BOOLEAN truncated;
    ULONG bytesCopied;

    if (ImageInfo == NULL) {
        return;
    }

    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = KSWORD_SANDBOX_IMAGE_EVENT_VERSION;
    payload.Size = sizeof(payload);
    payload.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    payload.ImageBase = (ULONGLONG)(ULONG_PTR)ImageInfo->ImageBase;
    payload.ImageSize = (ULONGLONG)ImageInfo->ImageSize;
    if (ImageInfo->SystemModeImage != 0) {
        payload.Flags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE;
    }

    truncated = FALSE;
    bytesCopied = 0;
    if (KswCopyUnicodePrefix(
            payload.ImagePath,
            KSWORD_SANDBOX_IMAGE_PATH_CHARS,
            FullImageName,
            &bytesCopied,
            &truncated)) {
        payload.Flags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT;
        payload.PathLengthBytes = bytesCopied;
    }
    if (truncated) {
        payload.Flags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED;
    }

    KswQueueImageEvent(&payload);
}

/*
 * Initializes process create/exit and image-load telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring that callbacks write into.
 * Logic  : registers Ex process callback first, falls back to legacy callback,
 *          registers image callback, and activates emission for any successful
 *          registration while returning the first failure for health reporting.
 * Return : STATUS_SUCCESS when both producers are active; otherwise first
 *          registration failure while leaving successful producers active.
 */
NTSTATUS
KswInitializeProcessMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    NTSTATUS processStatus;
    NTSTATUS imageStatus;
    NTSTATUS returnStatus;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    g_KswProcessMonitorDeviceExtension = DeviceExtension;
    g_KswProcessNotifyMode = KswProcessNotifyModeNone;
    InterlockedExchange(&g_KswProcessMonitorActive, 0);
    InterlockedExchange(&g_KswProcessCallbackRegistered, 0);
    InterlockedExchange(&g_KswImageCallbackRegistered, 0);

    processStatus = PsSetCreateProcessNotifyRoutineEx(
        KswProcessCreateNotifyEx,
        FALSE);
    if (NT_SUCCESS(processStatus)) {
        g_KswProcessNotifyMode = KswProcessNotifyModeEx;
        InterlockedExchange(&g_KswProcessCallbackRegistered, 1);
    } else {
        processStatus = PsSetCreateProcessNotifyRoutine(
            KswProcessCreateNotifyLegacy,
            FALSE);
        if (NT_SUCCESS(processStatus)) {
            g_KswProcessNotifyMode = KswProcessNotifyModeLegacy;
            InterlockedExchange(&g_KswProcessCallbackRegistered, 1);
        }
    }

    imageStatus = PsSetLoadImageNotifyRoutine(KswLoadImageNotify);
    if (NT_SUCCESS(imageStatus)) {
        InterlockedExchange(&g_KswImageCallbackRegistered, 1);
    }

    if (InterlockedCompareExchange(&g_KswProcessCallbackRegistered, 0, 0) != 0 ||
        InterlockedCompareExchange(&g_KswImageCallbackRegistered, 0, 0) != 0) {
        InterlockedExchange(&g_KswProcessMonitorActive, 1);
    }

    returnStatus = STATUS_SUCCESS;
    if (!NT_SUCCESS(processStatus)) {
        returnStatus = processStatus;
    }
    if (!NT_SUCCESS(imageStatus) && NT_SUCCESS(returnStatus)) {
        returnStatus = imageStatus;
    }

    return returnStatus;
}

/*
 * Stops process create/exit and image-load telemetry callbacks.
 * Inputs : none; callback registration state is module-local.
 * Logic  : disables emission first, unregisters whichever callback APIs were
 *          registered, then clears all module-local pointers and mode fields.
 * Return : no return value.
 */
VOID
KswUninitializeProcessMonitor(
    VOID
    )
{
    LONG processRegistered;
    LONG imageRegistered;
    ULONG processNotifyMode;

    InterlockedExchange(&g_KswProcessMonitorActive, 0);
    processRegistered = InterlockedCompareExchange(&g_KswProcessCallbackRegistered, 0, 0);
    imageRegistered = InterlockedCompareExchange(&g_KswImageCallbackRegistered, 0, 0);
    processNotifyMode = g_KswProcessNotifyMode;

    if (processRegistered != 0) {
        if (processNotifyMode == KswProcessNotifyModeEx) {
            (VOID)PsSetCreateProcessNotifyRoutineEx(KswProcessCreateNotifyEx, TRUE);
        } else if (processNotifyMode == KswProcessNotifyModeLegacy) {
            (VOID)PsSetCreateProcessNotifyRoutine(KswProcessCreateNotifyLegacy, TRUE);
        }
        InterlockedExchange(&g_KswProcessCallbackRegistered, 0);
    }

    if (imageRegistered != 0) {
        (VOID)PsRemoveLoadImageNotifyRoutine(KswLoadImageNotify);
        InterlockedExchange(&g_KswImageCallbackRegistered, 0);
    }

    g_KswProcessNotifyMode = KswProcessNotifyModeNone;
    g_KswProcessMonitorDeviceExtension = NULL;
}
