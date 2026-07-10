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

#define KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY 128UL

typedef struct _KSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY {
    ULONGLONG ProcessId;
    ULONGLONG ParentProcessId;
    ULONGLONG CreatingProcessId;
} KSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY, *PKSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY;

static PKSWORD_SANDBOX_DEVICE_EXTENSION g_KswProcessMonitorDeviceExtension;
static volatile LONG g_KswProcessMonitorActive;
static volatile LONG g_KswProcessCallbackRegistered;
static volatile LONG g_KswImageCallbackRegistered;
static ULONG g_KswProcessNotifyMode;
static KSPIN_LOCK g_KswProcessLineageLock;
static ULONG g_KswProcessLineageNextIndex;
static KSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY
    g_KswProcessLineage[KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY];

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
 * Clears the fixed process lineage cache.
 * Inputs : none; the module-local spin lock must already be initialized.
 * Logic  : used during initialize/uninitialize so stale PID reuse never leaks
 *          parent/creator IDs across driver reloads.
 * Return : no return value.
 */
static
VOID
KswClearProcessLineage(
    VOID
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_KswProcessLineageLock, &oldIrql);
    RtlZeroMemory(g_KswProcessLineage, sizeof(g_KswProcessLineage));
    g_KswProcessLineageNextIndex = 0;
    KeReleaseSpinLock(&g_KswProcessLineageLock, oldIrql);
}

/*
 * Remembers process lineage from a create callback for the later exit callback.
 * Inputs : ProcessId is the child PID; ParentProcessId and CreatingProcessId
 *          describe lineage captured by Ps callbacks.
 * Logic  : keeps a bounded non-paged cache under a spin lock; when full it
 *          replaces entries round-robin instead of allocating in callbacks.
 * Return : no return value.
 */
static
VOID
KswRememberProcessLineage(
    _In_ ULONGLONG ProcessId,
    _In_ ULONGLONG ParentProcessId,
    _In_ ULONGLONG CreatingProcessId
    )
{
    ULONG index;
    ULONG selectedIndex;
    KIRQL oldIrql;

    if (ProcessId == 0) {
        return;
    }

    selectedIndex = KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY;
    KeAcquireSpinLock(&g_KswProcessLineageLock, &oldIrql);
    for (index = 0; index < KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY; index++) {
        if (g_KswProcessLineage[index].ProcessId == ProcessId) {
            selectedIndex = index;
            break;
        }

        if (g_KswProcessLineage[index].ProcessId == 0 &&
            selectedIndex == KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY) {
            selectedIndex = index;
        }
    }

    if (selectedIndex == KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY) {
        selectedIndex =
            g_KswProcessLineageNextIndex % KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY;
        g_KswProcessLineageNextIndex =
            (selectedIndex + 1U) % KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY;
    }

    g_KswProcessLineage[selectedIndex].ProcessId = ProcessId;
    g_KswProcessLineage[selectedIndex].ParentProcessId = ParentProcessId;
    g_KswProcessLineage[selectedIndex].CreatingProcessId = CreatingProcessId;
    KeReleaseSpinLock(&g_KswProcessLineageLock, oldIrql);
}

/*
 * Removes and returns cached process lineage for an exit callback.
 * Inputs : ProcessId identifies the exiting process; ParentProcessId and
 *          CreatingProcessId receive cached values when present.
 * Logic  : bounded lookup under the lineage spin lock; the entry is cleared so
 *          PID reuse does not inherit old parent IDs.
 * Return : TRUE when cached lineage was found.
 */
static
BOOLEAN
KswTakeProcessLineage(
    _In_ ULONGLONG ProcessId,
    _Out_ PULONGLONG ParentProcessId,
    _Out_ PULONGLONG CreatingProcessId
    )
{
    ULONG index;
    BOOLEAN found;
    KIRQL oldIrql;

    if (ParentProcessId != NULL) {
        *ParentProcessId = 0;
    }
    if (CreatingProcessId != NULL) {
        *CreatingProcessId = 0;
    }
    if (ProcessId == 0) {
        return FALSE;
    }

    found = FALSE;
    KeAcquireSpinLock(&g_KswProcessLineageLock, &oldIrql);
    for (index = 0; index < KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY; index++) {
        if (g_KswProcessLineage[index].ProcessId == ProcessId) {
            if (ParentProcessId != NULL) {
                *ParentProcessId = g_KswProcessLineage[index].ParentProcessId;
            }
            if (CreatingProcessId != NULL) {
                *CreatingProcessId = g_KswProcessLineage[index].CreatingProcessId;
            }
            RtlZeroMemory(
                &g_KswProcessLineage[index],
                sizeof(g_KswProcessLineage[index]));
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_KswProcessLineageLock, oldIrql);
    return found;
}

/*
 * Builds a bounded, read-only UNICODE_STRING view that is safe for the common
 * copy helper.
 * Inputs : Source is callback-owned optional UTF-16 text; SafeSource receives a
 *          clamped view that never has Length greater than MaximumLength.
 * Logic  : avoids touching pageable callback strings above APC_LEVEL and rounds
 *          odd byte lengths down to full WCHARs before any copy is attempted.
 * Return : TRUE when SafeSource references useful UTF-16 text, FALSE otherwise.
 */
static
BOOLEAN
KswPrepareProcessCallbackString(
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
 * Copies an optional callback string into a process payload field.
 * Inputs : Destination is fixed payload storage; Source may be NULL; PresentFlag
 *          and TruncatedFlag identify the payload bits to update.
 * Logic  : validates IRQL and UNICODE_STRING bounds before delegating to the
 *          shared bounded UTF-16 helper; no allocation or blocking occurs.
 * Return : TRUE when text was copied; FALSE when the field is intentionally
 *          absent. Flags and length are updated in place.
 */
static
BOOLEAN
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
    BOOLEAN copied;
    ULONG bytesCopied;
    UNICODE_STRING safeSource;

    if (Destination != NULL && DestinationChars != 0) {
        Destination[0] = L'\0';
    }

    if (Flags == NULL || LengthBytes == NULL) {
        return FALSE;
    }

    *LengthBytes = 0;
    truncated = FALSE;
    copied = FALSE;
    bytesCopied = 0;

    if (KswPrepareProcessCallbackString(Source, &safeSource) &&
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
        KswRememberProcessLineage(
            payload.ProcessId,
            payload.ParentProcessId,
            payload.CreatingProcessId);
    } else {
        payload.Operation = KswSandboxProcessOperationExit;
        if (!KswTakeProcessLineage(
                payload.ProcessId,
                &payload.ParentProcessId,
                &payload.CreatingProcessId)) {
            payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
        }
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
    payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (Create) {
        KswRememberProcessLineage(
            payload.ProcessId,
            payload.ParentProcessId,
            payload.CreatingProcessId);
    } else if (!KswTakeProcessLineage(
            payload.ProcessId,
            &payload.ParentProcessId,
            &payload.CreatingProcessId)) {
        payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    }
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

    (VOID)KswCopyProcessPayloadString(
        payload.ImagePath,
        KSWORD_SANDBOX_IMAGE_PATH_CHARS,
        FullImageName,
        KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_PRESENT,
        KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PATH_TRUNCATED,
        &payload.Flags,
        &payload.PathLengthBytes);

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
    KeInitializeSpinLock(&g_KswProcessLineageLock);
    KswClearProcessLineage();

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
    processRegistered = InterlockedExchange(&g_KswProcessCallbackRegistered, 0);
    imageRegistered = InterlockedExchange(&g_KswImageCallbackRegistered, 0);
    processNotifyMode = g_KswProcessNotifyMode;

    if (processRegistered != 0) {
        if (processNotifyMode == KswProcessNotifyModeEx) {
            (VOID)PsSetCreateProcessNotifyRoutineEx(KswProcessCreateNotifyEx, TRUE);
        } else if (processNotifyMode == KswProcessNotifyModeLegacy) {
            (VOID)PsSetCreateProcessNotifyRoutine(KswProcessCreateNotifyLegacy, TRUE);
        }
    }

    if (imageRegistered != 0) {
        (VOID)PsRemoveLoadImageNotifyRoutine(KswLoadImageNotify);
    }

    g_KswProcessNotifyMode = KswProcessNotifyModeNone;
    KswClearProcessLineage();
    g_KswProcessMonitorDeviceExtension = NULL;
}
