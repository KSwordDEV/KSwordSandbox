#include "Producers/Image/ImageMonitor.h"
#include "Common/KernelString.h"

C_ASSERT(sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);

/*
 * Runtime state for the image-load event producer.
 *
 * Inputs : initialized by KswInitializeImageMonitor before the load-image
 *          callback is registered.
 * Logic  : groups the shared event-ring owner, callback registration state,
 *          initialized/teardown guards, and v1 payload version stamped on every image
 *          payload so callback paths do not depend on loose globals.
 * Return : no direct return value; setup/teardown expose state through their
 *          NTSTATUS return and Active/CallbackRegistered gates.
 */
typedef struct _KSWORD_SANDBOX_IMAGE_MONITOR_RUNTIME {
    PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension;
    volatile LONG Active;
    volatile LONG CallbackRegistered;
    volatile LONG Initialized;
    volatile LONG Uninitializing;
    ULONG PayloadVersion;
} KSWORD_SANDBOX_IMAGE_MONITOR_RUNTIME,
    *PKSWORD_SANDBOX_IMAGE_MONITOR_RUNTIME;

static KSWORD_SANDBOX_IMAGE_MONITOR_RUNTIME g_KswImageMonitorRuntime;

static VOID
KswLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

/*
 * Returns the image payload version stamped on emitted records.
 * Inputs : none; reads module-local runtime state.
 * Logic  : in-flight callbacks can race with teardown after observing Active,
 *          so zeroed runtime state falls back to the stable ABI v1 version.
 * Return : KSWORD_SANDBOX_IMAGE_EVENT_VERSION for v1 records.
 */
static
ULONG
KswImagePayloadVersion(
    VOID
    )
{
    ULONG version;

    version = g_KswImageMonitorRuntime.PayloadVersion;
    return version == 0 ? KSWORD_SANDBOX_IMAGE_EVENT_VERSION : version;
}

/*
 * Builds a bounded, read-only UNICODE_STRING view that is safe for image
 * callback path capture.
 * Inputs : Source is callback-owned optional UTF-16 text; SafeSource receives a
 *          clamped view that never has Length greater than MaximumLength.
 * Logic  : avoids touching pageable callback strings above APC_LEVEL and rounds
 *          odd byte lengths down to full WCHARs before any copy is attempted.
 * Return : TRUE when SafeSource references useful UTF-16 text, FALSE otherwise.
 */
static
BOOLEAN
KswPrepareImageCallbackString(
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
 * Copies an optional image callback path into the image payload.
 * Inputs : Destination is fixed payload storage; Source may be NULL; PresentFlag
 *          and TruncatedFlag identify the payload bits to update.
 * Logic  : validates IRQL and UNICODE_STRING bounds before delegating to the
 *          shared bounded UTF-16 helper; no allocation or blocking occurs.
 * Return : TRUE when text was copied; FALSE when the field is intentionally
 *          absent. Flags and length are updated in place.
 */
static
BOOLEAN
KswCopyImagePayloadString(
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

    if (KswPrepareImageCallbackString(Source, &safeSource) &&
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
    NTSTATUS status;

    if (Payload == NULL ||
        InterlockedCompareExchange(&g_KswImageMonitorRuntime.Active, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswImageMonitorRuntime.DeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    status = KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeImage,
        0,
        Payload,
        (ULONG)sizeof(*Payload));
    if (!NT_SUCCESS(status) && status != STATUS_CANCELLED) {
        /*
         * Disabled image telemetry returns STATUS_CANCELLED by design. Preserve
         * unexpected enqueue failures for collector diagnostics instead.
         */
        KswSetLastStatus(deviceExtension, status);
    }
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
    payload.Version = KswImagePayloadVersion();
    payload.Size = sizeof(payload);
    payload.Operation = KswSandboxImageOperationLoad;
    payload.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
    payload.ImageBase = (ULONGLONG)(ULONG_PTR)ImageInfo->ImageBase;
    payload.ImageSize = (ULONGLONG)ImageInfo->ImageSize;
    payload.ImageProperties = ImageInfo->Properties;
    payload.Flags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROPERTIES_PRESENT;
    if (ProcessId != NULL) {
        payload.Flags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_PROCESS_ID_PRESENT;
    }
    if (ImageInfo->SystemModeImage != 0) {
        payload.Flags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_SYSTEM_MODE_IMAGE;
    }
    if (ImageInfo->ImageMappedToAllPids != 0) {
        payload.Flags |= KSWORD_SANDBOX_IMAGE_EVENT_FLAG_MAPPED_TO_ALL_PIDS;
    }
    if (ImageInfo->ExtendedInfoPresent != 0) {
        payload.Flags |=
            KSWORD_SANDBOX_IMAGE_EVENT_FLAG_EXTENDED_INFO_PRESENT;
    }

    (VOID)KswCopyImagePayloadString(
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
 * Initializes image-load telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring that callbacks write into.
 * Logic  : registers PsSetLoadImageNotifyRoutine and activates emission only
 *          after registration succeeds.
 * Return : STATUS_SUCCESS when active or the registration failure NTSTATUS.
 */
NTSTATUS
KswInitializeImageMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    NTSTATUS status;

    if (DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(
            &g_KswImageMonitorRuntime.CallbackRegistered,
            0,
            0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(
        &g_KswImageMonitorRuntime,
        sizeof(g_KswImageMonitorRuntime));
    g_KswImageMonitorRuntime.DeviceExtension = DeviceExtension;
    g_KswImageMonitorRuntime.PayloadVersion =
        KSWORD_SANDBOX_IMAGE_EVENT_VERSION;
    InterlockedExchange(&g_KswImageMonitorRuntime.Initialized, 1);
    InterlockedExchange(&g_KswImageMonitorRuntime.Active, 0);
    InterlockedExchange(&g_KswImageMonitorRuntime.CallbackRegistered, 0);
    InterlockedExchange(&g_KswImageMonitorRuntime.Uninitializing, 0);

    status = PsSetLoadImageNotifyRoutine(KswLoadImageNotify);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&g_KswImageMonitorRuntime.CallbackRegistered, 1);
        InterlockedExchange(&g_KswImageMonitorRuntime.Active, 1);
    } else {
        g_KswImageMonitorRuntime.PayloadVersion = 0;
        g_KswImageMonitorRuntime.DeviceExtension = NULL;
        InterlockedExchange(&g_KswImageMonitorRuntime.Initialized, 0);
    }

    KswRecordProducerStatus(
        DeviceExtension,
        KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE,
        status);

    return status;
}

/*
 * Stops image-load telemetry callbacks.
 * Inputs : none; callback registration state is module-local.
 * Logic  : disables emission first, unregisters the callback if it was
 *          registered, then clears all module-local pointers.
 * Return : no return value.
 */
VOID
KswUninitializeImageMonitor(
    VOID
    )
{
    LONG imageRegistered;

    if (InterlockedExchange(
            &g_KswImageMonitorRuntime.Uninitializing,
            1) != 0) {
        return;
    }

    InterlockedExchange(&g_KswImageMonitorRuntime.Active, 0);
    imageRegistered = InterlockedExchange(
        &g_KswImageMonitorRuntime.CallbackRegistered,
        0);

    if (imageRegistered != 0) {
        (VOID)PsRemoveLoadImageNotifyRoutine(KswLoadImageNotify);
    }

    g_KswImageMonitorRuntime.PayloadVersion = 0;
    g_KswImageMonitorRuntime.DeviceExtension = NULL;
    InterlockedExchange(&g_KswImageMonitorRuntime.Initialized, 0);
}
