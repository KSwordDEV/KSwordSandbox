#include "Producers/Process/ProcessMonitor.h"
#include "Common/KernelString.h"

C_ASSERT(sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
C_ASSERT(sizeof(KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);

#define KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_ALTITUDE L"385201.7338"

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
#define KSWORD_SANDBOX_PROCESS_LINEAGE_STRING_FLAGS \
    (KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT | \
     KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED | \
     KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT | \
     KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED)

typedef struct _KSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY {
    ULONGLONG ProcessId;
    ULONGLONG ParentProcessId;
    ULONGLONG CreatingProcessId;
    ULONG Flags;
    ULONG ImagePathLengthBytes;
    ULONG CommandLineLengthBytes;
    WCHAR ImagePath[KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS];
    WCHAR CommandLine[KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS];
} KSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY, *PKSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY;

/*
 * Runtime state for the process create/exit event producer.
 *
 * Inputs : initialized by KswInitializeProcessMonitor after the control device
 *          extension and READ_EVENTS ring exist.
 * Logic  : keeps callback registration state, active/uninitializing gates, the
 *          v1 payload version stamped on emitted records, and the bounded
 *          lineage replay cache in one non-paged module-local structure.
 * Return : no direct return value; initialization returns the registration
 *          NTSTATUS and teardown clears these fields before driver unload.
 */
typedef struct _KSWORD_SANDBOX_PROCESS_MONITOR_RUNTIME {
    PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension;
    volatile LONG Active;
    volatile LONG CallbackRegistered;
    volatile LONG ObjectCallbackRegistered;
    volatile LONG Initialized;
    volatile LONG Uninitializing;
    PVOID ObjectCallbackRegistrationHandle;
    ULONG NotifyMode;
    ULONG PayloadVersion;
    ULONG HandleAccessPayloadVersion;
    KSPIN_LOCK LineageLock;
    ULONG LineageNextIndex;
    KSWORD_SANDBOX_PROCESS_LINEAGE_ENTRY
        Lineage[KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY];
} KSWORD_SANDBOX_PROCESS_MONITOR_RUNTIME,
    *PKSWORD_SANDBOX_PROCESS_MONITOR_RUNTIME;

static KSWORD_SANDBOX_PROCESS_MONITOR_RUNTIME g_KswProcessMonitorRuntime;

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

#if KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS
static OB_PREOP_CALLBACK_STATUS
KswProcessHandlePreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );
#endif

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

    if (InterlockedCompareExchange(
            &g_KswProcessMonitorRuntime.Initialized,
            0,
            0) == 0) {
        RtlZeroMemory(
            g_KswProcessMonitorRuntime.Lineage,
            sizeof(g_KswProcessMonitorRuntime.Lineage));
        g_KswProcessMonitorRuntime.LineageNextIndex = 0;
        return;
    }

    KeAcquireSpinLock(&g_KswProcessMonitorRuntime.LineageLock, &oldIrql);
    RtlZeroMemory(
        g_KswProcessMonitorRuntime.Lineage,
        sizeof(g_KswProcessMonitorRuntime.Lineage));
    g_KswProcessMonitorRuntime.LineageNextIndex = 0;
    KeReleaseSpinLock(&g_KswProcessMonitorRuntime.LineageLock, oldIrql);
}

/*
 * Returns the process payload version stamped on emitted records.
 * Inputs : none; reads module-local runtime state.
 * Logic  : callbacks may race with teardown, so fall back to the ABI v1 value
 *          instead of emitting a zero Version if runtime state was already
 *          cleared after Active was observed.
 * Return : KSWORD_SANDBOX_PROCESS_EVENT_VERSION for v1 records.
 */
static
ULONG
KswProcessPayloadVersion(
    VOID
    )
{
    ULONG version;

    version = g_KswProcessMonitorRuntime.PayloadVersion;
    return version == 0 ? KSWORD_SANDBOX_PROCESS_EVENT_VERSION : version;
}

#if KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS
/*
 * Returns the draft process/thread handle-access payload version.
 * Inputs : none; reads module-local runtime state.
 * Logic  : callbacks may race with teardown, so fall back to the public draft
 *          version rather than emitting zero if runtime cleanup has started.
 * Return : KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_VERSION.
 */
static
ULONG
KswProcessHandleAccessPayloadVersion(
    VOID
    )
{
    ULONG version;

    version = g_KswProcessMonitorRuntime.HandleAccessPayloadVersion;
    return version == 0 ?
        KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_VERSION :
        version;
}
#endif

/*
 * Remembers process lineage from a create callback for the later exit callback.
 * Inputs : Payload is the already bounded process-create payload.
 * Logic  : keeps a bounded non-paged cache under a spin lock; when full it
 *          replaces entries round-robin instead of allocating in callbacks.
 *          Bounded image/command prefixes are replayed on exit so R0Collector
 *          can map both create and exit records to a useful SandboxEvent path.
 * Return : no return value.
 */
static
VOID
KswRememberProcessLineage(
    _In_ const KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD* Payload
    )
{
    ULONG index;
    ULONG selectedIndex;
    ULONG bytesToCopy;
    ULONG charsToCopy;
    KIRQL oldIrql;

    if (Payload == NULL || Payload->ProcessId == 0) {
        return;
    }

    selectedIndex = KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY;
    KeAcquireSpinLock(&g_KswProcessMonitorRuntime.LineageLock, &oldIrql);
    for (index = 0; index < KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY; index++) {
        if (g_KswProcessMonitorRuntime.Lineage[index].ProcessId == Payload->ProcessId) {
            selectedIndex = index;
            break;
        }

        if (g_KswProcessMonitorRuntime.Lineage[index].ProcessId == 0 &&
            selectedIndex == KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY) {
            selectedIndex = index;
        }
    }

    if (selectedIndex == KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY) {
        selectedIndex =
            g_KswProcessMonitorRuntime.LineageNextIndex % KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY;
        g_KswProcessMonitorRuntime.LineageNextIndex =
            (selectedIndex + 1U) % KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY;
    }

    RtlZeroMemory(
        &g_KswProcessMonitorRuntime.Lineage[selectedIndex],
        sizeof(g_KswProcessMonitorRuntime.Lineage[selectedIndex]));
    g_KswProcessMonitorRuntime.Lineage[selectedIndex].ProcessId = Payload->ProcessId;
    g_KswProcessMonitorRuntime.Lineage[selectedIndex].ParentProcessId = Payload->ParentProcessId;
    g_KswProcessMonitorRuntime.Lineage[selectedIndex].CreatingProcessId = Payload->CreatingProcessId;
    g_KswProcessMonitorRuntime.Lineage[selectedIndex].Flags =
        Payload->Flags & KSWORD_SANDBOX_PROCESS_LINEAGE_STRING_FLAGS;

    if ((Payload->Flags &
            KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT) != 0) {
        bytesToCopy = Payload->ImagePathLengthBytes;
        if (bytesToCopy >
            (KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS - 1U) *
                (ULONG)sizeof(WCHAR)) {
            bytesToCopy =
                (KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS - 1U) *
                (ULONG)sizeof(WCHAR);
        }
        bytesToCopy -= bytesToCopy % (ULONG)sizeof(WCHAR);
        if (bytesToCopy != 0) {
            RtlCopyMemory(
                g_KswProcessMonitorRuntime.Lineage[selectedIndex].ImagePath,
                Payload->ImagePath,
                bytesToCopy);
            charsToCopy = bytesToCopy / (ULONG)sizeof(WCHAR);
            g_KswProcessMonitorRuntime.Lineage[selectedIndex].ImagePath[charsToCopy] = L'\0';
            g_KswProcessMonitorRuntime.Lineage[selectedIndex].ImagePathLengthBytes = bytesToCopy;
        }
    }

    if ((Payload->Flags &
            KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT) != 0) {
        bytesToCopy = Payload->CommandLineLengthBytes;
        if (bytesToCopy >
            (KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS - 1U) *
                (ULONG)sizeof(WCHAR)) {
            bytesToCopy =
                (KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS - 1U) *
                (ULONG)sizeof(WCHAR);
        }
        bytesToCopy -= bytesToCopy % (ULONG)sizeof(WCHAR);
        if (bytesToCopy != 0) {
            RtlCopyMemory(
                g_KswProcessMonitorRuntime.Lineage[selectedIndex].CommandLine,
                Payload->CommandLine,
                bytesToCopy);
            charsToCopy = bytesToCopy / (ULONG)sizeof(WCHAR);
            g_KswProcessMonitorRuntime.Lineage[selectedIndex].CommandLine[charsToCopy] = L'\0';
            g_KswProcessMonitorRuntime.Lineage[selectedIndex].CommandLineLengthBytes = bytesToCopy;
        }
    }

    KeReleaseSpinLock(&g_KswProcessMonitorRuntime.LineageLock, oldIrql);
}

/*
 * Removes and returns cached process lineage for an exit callback.
 * Inputs : ProcessId identifies the exiting process; Payload receives cached
 *          lineage and bounded create-time strings when present.
 * Logic  : bounded lookup under the lineage spin lock; the entry is cleared so
 *          PID reuse does not inherit old parent IDs.
 * Return : TRUE when cached lineage was found.
 */
static
BOOLEAN
KswTakeProcessLineage(
    _In_ ULONGLONG ProcessId,
    _Inout_ PKSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD Payload
    )
{
    ULONG index;
    BOOLEAN found;
    ULONG bytesToCopy;
    ULONG charsToCopy;
    KIRQL oldIrql;

    if (ProcessId == 0 || Payload == NULL) {
        return FALSE;
    }

    found = FALSE;
    KeAcquireSpinLock(&g_KswProcessMonitorRuntime.LineageLock, &oldIrql);
    for (index = 0; index < KSWORD_SANDBOX_PROCESS_LINEAGE_CAPACITY; index++) {
        if (g_KswProcessMonitorRuntime.Lineage[index].ProcessId == ProcessId) {
            Payload->ParentProcessId = g_KswProcessMonitorRuntime.Lineage[index].ParentProcessId;
            Payload->CreatingProcessId =
                g_KswProcessMonitorRuntime.Lineage[index].CreatingProcessId;
            Payload->Flags |=
                KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_CACHE_HIT;
            if (Payload->ParentProcessId != 0) {
                Payload->Flags |=
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT;
            }
            if (Payload->CreatingProcessId != 0) {
                Payload->Flags |=
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT;
            }

            if ((g_KswProcessMonitorRuntime.Lineage[index].Flags &
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT) != 0 &&
                g_KswProcessMonitorRuntime.Lineage[index].ImagePathLengthBytes != 0) {
                bytesToCopy = g_KswProcessMonitorRuntime.Lineage[index].ImagePathLengthBytes;
                if (bytesToCopy >
                    (KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS - 1U) *
                        (ULONG)sizeof(WCHAR)) {
                    bytesToCopy =
                        (KSWORD_SANDBOX_PROCESS_IMAGE_PATH_CHARS - 1U) *
                        (ULONG)sizeof(WCHAR);
                }
                bytesToCopy -= bytesToCopy % (ULONG)sizeof(WCHAR);
                if (bytesToCopy != 0) {
                    RtlCopyMemory(
                        Payload->ImagePath,
                        g_KswProcessMonitorRuntime.Lineage[index].ImagePath,
                        bytesToCopy);
                    charsToCopy = bytesToCopy / (ULONG)sizeof(WCHAR);
                    Payload->ImagePath[charsToCopy] = L'\0';
                    Payload->ImagePathLengthBytes = bytesToCopy;
                    Payload->Flags |=
                        g_KswProcessMonitorRuntime.Lineage[index].Flags &
                        (KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_PRESENT |
                         KSWORD_SANDBOX_PROCESS_EVENT_FLAG_IMAGE_PATH_TRUNCATED);
                    Payload->Flags |=
                        KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_STRINGS_REPLAYED;
                }
            }

            if ((g_KswProcessMonitorRuntime.Lineage[index].Flags &
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT) != 0 &&
                g_KswProcessMonitorRuntime.Lineage[index].CommandLineLengthBytes != 0) {
                bytesToCopy = g_KswProcessMonitorRuntime.Lineage[index].CommandLineLengthBytes;
                if (bytesToCopy >
                    (KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS - 1U) *
                        (ULONG)sizeof(WCHAR)) {
                    bytesToCopy =
                        (KSWORD_SANDBOX_PROCESS_COMMAND_LINE_CHARS - 1U) *
                        (ULONG)sizeof(WCHAR);
                }
                bytesToCopy -= bytesToCopy % (ULONG)sizeof(WCHAR);
                if (bytesToCopy != 0) {
                    RtlCopyMemory(
                        Payload->CommandLine,
                        g_KswProcessMonitorRuntime.Lineage[index].CommandLine,
                        bytesToCopy);
                    charsToCopy = bytesToCopy / (ULONG)sizeof(WCHAR);
                    Payload->CommandLine[charsToCopy] = L'\0';
                    Payload->CommandLineLengthBytes = bytesToCopy;
                    Payload->Flags |=
                        g_KswProcessMonitorRuntime.Lineage[index].Flags &
                        (KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_PRESENT |
                         KSWORD_SANDBOX_PROCESS_EVENT_FLAG_COMMAND_TRUNCATED);
                    Payload->Flags |=
                        KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LINEAGE_STRINGS_REPLAYED;
                }
            }

            RtlZeroMemory(
                &g_KswProcessMonitorRuntime.Lineage[index],
                sizeof(g_KswProcessMonitorRuntime.Lineage[index]));
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_KswProcessMonitorRuntime.LineageLock, oldIrql);
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
    NTSTATUS status;

    if (Payload == NULL ||
        InterlockedCompareExchange(&g_KswProcessMonitorRuntime.Active, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswProcessMonitorRuntime.DeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    status = KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeProcess,
        0,
        Payload,
        (ULONG)sizeof(*Payload));
    if (!NT_SUCCESS(status) && status != STATUS_CANCELLED) {
        /*
         * STATUS_CANCELLED is the expected producer-disabled path and was
         * already counted by the shared queue.  Other failures indicate an ABI
         * or state bug that should be visible through GET_HEALTH.LastNtStatus.
         */
        KswSetLastStatus(deviceExtension, status);
    }
}

#if KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS
/*
 * Queues one guarded process/thread handle-access event.
 * Inputs : Payload is a fixed draft handle-access record produced by
 *          ObRegisterCallbacks pre-operation notification.
 * Logic  : shares the process producer enable bit and READ_EVENTS ring; no
 *          allocation, blocking, or access-mask mutation occurs in the callback
 *          hot path.
 * Return : no return value; enqueue failures are reported through shared
 *          status/loss counters where possible.
 */
static
VOID
KswQueueProcessHandleAccessEvent(
    _In_ const KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT* Payload
    )
{
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    NTSTATUS status;

    if (Payload == NULL ||
        InterlockedCompareExchange(&g_KswProcessMonitorRuntime.Active, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswProcessMonitorRuntime.DeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    status = KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeProcess,
        0,
        Payload,
        (ULONG)sizeof(*Payload));
    if (!NT_SUCCESS(status) && status != STATUS_CANCELLED) {
        KswSetLastStatus(deviceExtension, status);
    }
}
/*
 * Adds target identity fields for a process or thread object.
 * Inputs : OperationInformation is supplied by ObRegisterCallbacks; Payload is
 *          the fixed draft record being built on the callback stack.
 * Logic  : supports PsProcessType and PsThreadType only.  Thread handle events
 *          include both the owning process id and target thread id so consumers
 *          do not need to infer a TID from process-only fields.
 * Return : TRUE when the object type is supported and identity was captured.
 */
static
BOOLEAN
KswPopulateHandleAccessObjectIdentity(
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation,
    _Inout_ PKSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT Payload
    )
{
    if (OperationInformation == NULL ||
        Payload == NULL ||
        OperationInformation->Object == NULL ||
        OperationInformation->ObjectType == NULL) {
        return FALSE;
    }

    if (OperationInformation->ObjectType == *PsProcessType) {
        Payload->ObjectType = KswSandboxProcessAccessObjectTypeProcess;
        Payload->TargetProcessId =
            (ULONGLONG)(ULONG_PTR)PsGetProcessId(
                (PEPROCESS)OperationInformation->Object);
        Payload->Flags |=
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_PROCESS_OBJECT;
        if (Payload->TargetProcessId != 0) {
            Payload->Flags |=
                KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_TARGET_PID_PRESENT;
        }
        return TRUE;
    }

    if (OperationInformation->ObjectType == *PsThreadType) {
        Payload->ObjectType = KswSandboxProcessAccessObjectTypeThread;
        Payload->TargetProcessId =
            (ULONGLONG)(ULONG_PTR)PsGetThreadProcessId(
                (PETHREAD)OperationInformation->Object);
        Payload->TargetThreadId =
            (ULONGLONG)(ULONG_PTR)PsGetThreadId(
                (PETHREAD)OperationInformation->Object);
        Payload->Flags |=
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_THREAD_OBJECT;
        if (Payload->TargetProcessId != 0) {
            Payload->Flags |=
                KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_TARGET_PID_PRESENT;
        }
        if (Payload->TargetThreadId != 0) {
            Payload->Flags |=
                KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_TARGET_TID_PRESENT;
        }
        return TRUE;
    }

    return FALSE;
}

/*
 * Emits non-mutating handle create/duplicate telemetry from Ob callbacks.
 * Inputs : OperationInformation describes the process/thread object handle
 *          operation before the kernel grants access.
 * Logic  : captures actor pid, target pid/tid, source/target duplicate pids,
 *          requested access masks, callback operation, previous mode, and
 *          kernel-handle state.  It never changes DesiredAccess and always
 *          returns OB_PREOP_SUCCESS.
 * Return : OB_PREOP_SUCCESS so object-manager processing continues normally.
 */
static
OB_PREOP_CALLBACK_STATUS
KswProcessHandlePreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_PAYLOAD_V1_DRAFT payload;
    POB_PRE_CREATE_HANDLE_INFORMATION createInfo;
    POB_PRE_DUPLICATE_HANDLE_INFORMATION duplicateInfo;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation == NULL ||
        OperationInformation->Parameters == NULL ||
        InterlockedCompareExchange(
            &g_KswProcessMonitorRuntime.ObjectCallbackRegistered,
            0,
            0) == 0) {
        return OB_PREOP_SUCCESS;
    }

    RtlZeroMemory(&payload, sizeof(payload));
    payload.Version = KswProcessHandleAccessPayloadVersion();
    payload.Size = sizeof(payload);
    payload.ActorProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    payload.CallbackOperation = (ULONG)OperationInformation->Operation;
    payload.PreviousMode = (ULONG)ExGetPreviousMode();
    payload.Status = STATUS_SUCCESS;
    payload.Flags =
        KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_PRE_OPERATION;

    if (OperationInformation->KernelHandle != 0) {
        payload.Flags |=
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_KERNEL_HANDLE;
    }
    if (payload.PreviousMode == UserMode) {
        payload.Flags |=
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_USER_MODE_REQUEST;
    }

    if (!KswPopulateHandleAccessObjectIdentity(
            OperationInformation,
            &payload)) {
        return OB_PREOP_SUCCESS;
    }

    switch (OperationInformation->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        createInfo = &OperationInformation->Parameters->CreateHandleInformation;
        payload.Operation = KswSandboxProcessOperationHandleCreateDraft;
        payload.OriginalDesiredAccess = createInfo->OriginalDesiredAccess;
        payload.DesiredAccess = createInfo->DesiredAccess;
        payload.Flags |=
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_ORIGINAL_DESIRED_ACCESS_PRESENT |
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_DESIRED_ACCESS_PRESENT;
        if (payload.DesiredAccess != payload.OriginalDesiredAccess) {
            payload.Flags |=
                KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_ACCESS_REDUCED;
        }
        break;

    case OB_OPERATION_HANDLE_DUPLICATE:
        duplicateInfo =
            &OperationInformation->Parameters->DuplicateHandleInformation;
        payload.Operation = KswSandboxProcessOperationHandleDuplicateDraft;
        payload.OriginalDesiredAccess = duplicateInfo->OriginalDesiredAccess;
        payload.DesiredAccess = duplicateInfo->DesiredAccess;
        if (duplicateInfo->SourceProcess != NULL) {
            payload.SourceProcessId =
                (ULONGLONG)(ULONG_PTR)PsGetProcessId(
                    duplicateInfo->SourceProcess);
            if (payload.SourceProcessId != 0) {
                payload.Flags |=
                    KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_SOURCE_PID_PRESENT;
            }
        }
        if (duplicateInfo->TargetProcess != NULL) {
            payload.DuplicateTargetProcessId =
                (ULONGLONG)(ULONG_PTR)PsGetProcessId(
                    duplicateInfo->TargetProcess);
            if (payload.DuplicateTargetProcessId != 0) {
                payload.Flags |=
                    KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_DUPLICATE_TARGET_PID_PRESENT;
            }
        }
        payload.Flags |=
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_ORIGINAL_DESIRED_ACCESS_PRESENT |
            KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_DESIRED_ACCESS_PRESENT;
        if (payload.DesiredAccess != payload.OriginalDesiredAccess) {
            payload.Flags |=
                KSWORD_SANDBOX_PROCESS_ACCESS_EVENT_FLAG_ACCESS_REDUCED;
        }
        break;

    default:
        return OB_PREOP_SUCCESS;
    }

    KswQueueProcessHandleAccessEvent(&payload);
    return OB_PREOP_SUCCESS;
}

/*
 * Registers process/thread object-manager handle telemetry callbacks.
 * Inputs : DeviceExtension owns the shared event ring.
 * Logic  : registers one non-mutating pre-operation callback for PsProcessType
 *          and PsThreadType handle create/duplicate operations.  Registration
 *          failure is non-fatal to process create/exit telemetry and is exposed
 *          through LastNtStatus.
 * Return : STATUS_SUCCESS when Ob callbacks registered; otherwise the object
 *          manager registration failure.
 */
static
NTSTATUS
KswInitializeProcessHandleAccessCallbacks(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    NTSTATUS status;
    UNICODE_STRING altitude;
    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistrations[2];

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(
            &g_KswProcessMonitorRuntime.ObjectCallbackRegistered,
            0,
            0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    RtlZeroMemory(operationRegistrations, sizeof(operationRegistrations));
    RtlInitUnicodeString(
        &altitude,
        KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_ALTITUDE);

    operationRegistrations[0].ObjectType = PsProcessType;
    operationRegistrations[0].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistrations[0].PreOperation =
        KswProcessHandlePreOperationCallback;
    operationRegistrations[0].PostOperation = NULL;

    operationRegistrations[1].ObjectType = PsThreadType;
    operationRegistrations[1].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistrations[1].PreOperation =
        KswProcessHandlePreOperationCallback;
    operationRegistrations[1].PostOperation = NULL;

    callbackRegistration.Version = ObGetFilterVersion();
    callbackRegistration.OperationRegistrationCount =
        (USHORT)RTL_NUMBER_OF(operationRegistrations);
    callbackRegistration.Altitude = altitude;
    callbackRegistration.RegistrationContext = DeviceExtension;
    callbackRegistration.OperationRegistration = operationRegistrations;

    status = ObRegisterCallbacks(
        &callbackRegistration,
        &g_KswProcessMonitorRuntime.ObjectCallbackRegistrationHandle);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(
            &g_KswProcessMonitorRuntime.ObjectCallbackRegistered,
            1);
    }
    KswRecordProducerStatus(
        DeviceExtension,
        KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS_HANDLE_ACCESS,
        status);

    return status;
}

/*
 * Unregisters object-manager handle telemetry callbacks.
 * Inputs : none; callback registration handle is module-local.
 * Logic  : clears the registered gate before calling ObUnRegisterCallbacks so
 *          any concurrent callback returns without queuing new events.
 * Return : no return value.
 */
static
VOID
KswUninitializeProcessHandleAccessCallbacks(
    VOID
    )
{
    PVOID callbackRegistrationHandle;

    callbackRegistrationHandle =
        g_KswProcessMonitorRuntime.ObjectCallbackRegistrationHandle;
    if (InterlockedExchange(
            &g_KswProcessMonitorRuntime.ObjectCallbackRegistered,
            0) != 0 &&
        callbackRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(callbackRegistrationHandle);
    }

    g_KswProcessMonitorRuntime.ObjectCallbackRegistrationHandle = NULL;
}
#endif

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
    payload.Version = KswProcessPayloadVersion();
    payload.Size = sizeof(payload);
    payload.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    payload.Flags = KSWORD_SANDBOX_PROCESS_EVENT_FLAG_EX_CALLBACK;

    if (CreateInfo != NULL) {
        payload.Operation = KswSandboxProcessOperationCreate;
        payload.ParentProcessId = (ULONGLONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
        payload.Status = CreateInfo->CreationStatus;
        payload.Flags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_STATUS_PRESENT;
        if (!NT_SUCCESS(payload.Status)) {
            payload.Flags |=
                KSWORD_SANDBOX_PROCESS_EVENT_FLAG_OPERATION_FAILED;
        }
        if (CreateInfo->FileOpenNameAvailable != 0) {
            payload.Flags |=
                KSWORD_SANDBOX_PROCESS_EVENT_FLAG_FILE_OPEN_NAME_AVAILABLE;
        }
        if (payload.ParentProcessId != 0) {
            payload.Flags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT;
        }
        if (payload.CreatingProcessId != 0) {
            payload.Flags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT;
        }
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
        KswRememberProcessLineage(&payload);
    } else {
        payload.Operation = KswSandboxProcessOperationExit;
        if (!KswTakeProcessLineage(payload.ProcessId, &payload)) {
            payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (payload.CreatingProcessId != 0) {
                payload.Flags |=
                    KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT;
            }
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
    payload.Version = KswProcessPayloadVersion();
    payload.Size = sizeof(payload);
    payload.Operation = Create ?
        KswSandboxProcessOperationCreate :
        KswSandboxProcessOperationExit;
    payload.Flags = KSWORD_SANDBOX_PROCESS_EVENT_FLAG_LEGACY_CALLBACK;
    payload.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    payload.ParentProcessId = (ULONGLONG)(ULONG_PTR)ParentId;
    payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (Create) {
        if (payload.ParentProcessId != 0) {
            payload.Flags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_PARENT_ID_PRESENT;
        }
        if (payload.CreatingProcessId != 0) {
            payload.Flags |= KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT;
        }
        KswRememberProcessLineage(&payload);
    } else if (!KswTakeProcessLineage(payload.ProcessId, &payload)) {
        payload.CreatingProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
        if (payload.CreatingProcessId != 0) {
            payload.Flags |=
                KSWORD_SANDBOX_PROCESS_EVENT_FLAG_CREATOR_ID_PRESENT;
        }
    }
    KswQueueProcessEvent(&payload);
}

/*
 * Initializes process create/exit telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring that callbacks write into.
 * Logic  : registers Ex process callback first, falls back to legacy callback,
 *          and activates emission after either callback form registers.
 * Return : STATUS_SUCCESS when process callbacks are active; otherwise the
 *          registration failure NTSTATUS.
 */
NTSTATUS
KswInitializeProcessMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    NTSTATUS processStatus;
#if KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS
    NTSTATUS handleAccessStatus;
#endif

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(
            &g_KswProcessMonitorRuntime.CallbackRegistered,
            0,
            0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(
        &g_KswProcessMonitorRuntime,
        sizeof(g_KswProcessMonitorRuntime));
    g_KswProcessMonitorRuntime.DeviceExtension = DeviceExtension;
    g_KswProcessMonitorRuntime.NotifyMode = KswProcessNotifyModeNone;
    g_KswProcessMonitorRuntime.PayloadVersion =
        KSWORD_SANDBOX_PROCESS_EVENT_VERSION;
    g_KswProcessMonitorRuntime.HandleAccessPayloadVersion =
        KSWORD_SANDBOX_PROCESS_HANDLE_ACCESS_EVENT_VERSION;
    InterlockedExchange(&g_KswProcessMonitorRuntime.Active, 0);
    InterlockedExchange(&g_KswProcessMonitorRuntime.CallbackRegistered, 0);
    InterlockedExchange(&g_KswProcessMonitorRuntime.ObjectCallbackRegistered, 0);
    InterlockedExchange(&g_KswProcessMonitorRuntime.Uninitializing, 0);
    KeInitializeSpinLock(&g_KswProcessMonitorRuntime.LineageLock);
    InterlockedExchange(&g_KswProcessMonitorRuntime.Initialized, 1);
    KswClearProcessLineage();

    processStatus = PsSetCreateProcessNotifyRoutineEx(
        KswProcessCreateNotifyEx,
        FALSE);
    if (NT_SUCCESS(processStatus)) {
        g_KswProcessMonitorRuntime.NotifyMode = KswProcessNotifyModeEx;
        InterlockedExchange(&g_KswProcessMonitorRuntime.CallbackRegistered, 1);
    } else {
        processStatus = PsSetCreateProcessNotifyRoutine(
            KswProcessCreateNotifyLegacy,
            FALSE);
        if (NT_SUCCESS(processStatus)) {
            g_KswProcessMonitorRuntime.NotifyMode = KswProcessNotifyModeLegacy;
            InterlockedExchange(&g_KswProcessMonitorRuntime.CallbackRegistered, 1);
        }
    }

    KswRecordProducerStatus(
        DeviceExtension,
        KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS,
        processStatus);

    if (InterlockedCompareExchange(&g_KswProcessMonitorRuntime.CallbackRegistered, 0, 0) != 0) {
        InterlockedExchange(&g_KswProcessMonitorRuntime.Active, 1);
    }

#if KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS
    if (NT_SUCCESS(processStatus)) {
        handleAccessStatus =
            KswInitializeProcessHandleAccessCallbacks(DeviceExtension);
        if (!NT_SUCCESS(handleAccessStatus)) {
            KswSetLastStatus(DeviceExtension, handleAccessStatus);
        }
    }
#endif

    return processStatus;
}

/*
 * Stops process create/exit telemetry callbacks.
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
    ULONG processNotifyMode;

    if (InterlockedExchange(
            &g_KswProcessMonitorRuntime.Uninitializing,
            1) != 0) {
        return;
    }

    InterlockedExchange(&g_KswProcessMonitorRuntime.Active, 0);
#if KSWORD_SANDBOX_ENABLE_PROCESS_HANDLE_ACCESS
    KswUninitializeProcessHandleAccessCallbacks();
#endif
    processRegistered = InterlockedExchange(
        &g_KswProcessMonitorRuntime.CallbackRegistered,
        0);
    processNotifyMode = g_KswProcessMonitorRuntime.NotifyMode;

    if (processRegistered != 0) {
        if (processNotifyMode == KswProcessNotifyModeEx) {
            (VOID)PsSetCreateProcessNotifyRoutineEx(KswProcessCreateNotifyEx, TRUE);
        } else if (processNotifyMode == KswProcessNotifyModeLegacy) {
            (VOID)PsSetCreateProcessNotifyRoutine(KswProcessCreateNotifyLegacy, TRUE);
        }
    }

    g_KswProcessMonitorRuntime.NotifyMode = KswProcessNotifyModeNone;
    KswClearProcessLineage();
    g_KswProcessMonitorRuntime.PayloadVersion = 0;
    g_KswProcessMonitorRuntime.HandleAccessPayloadVersion = 0;
    g_KswProcessMonitorRuntime.DeviceExtension = NULL;
    InterlockedExchange(&g_KswProcessMonitorRuntime.Initialized, 0);
}
