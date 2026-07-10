#pragma once

#include "Driver.h"

/*
 * Initializes process create/exit and image-load telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring that callbacks write into.
 * Logic  : registers PsSetCreateProcessNotifyRoutineEx with a legacy fallback
 *          and PsSetLoadImageNotifyRoutine, then activates producers that
 *          registered successfully.
 * Return : STATUS_SUCCESS when both process and image producers are active;
 *          otherwise the first registration failure while keeping any producer
 *          that did register active.
 */
NTSTATUS
KswInitializeProcessMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops process create/exit and image-load telemetry callbacks.
 * Inputs : none; callback registration state is module-local.
 * Logic  : disables emission before removing registered callbacks and clearing
 *          the shared device-extension pointer.
 * Return : no return value.
 */
VOID
KswUninitializeProcessMonitor(
    VOID
    );
