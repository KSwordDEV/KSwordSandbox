#pragma once

#include "Driver.h"

/*
 * Initializes process create/exit and guarded handle-access telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring that callbacks write into.
 * Logic  : registers PsSetCreateProcessNotifyRoutineEx with a legacy fallback
 *          and, when compiled in, non-mutating ObRegisterCallbacks handle
 *          access telemetry.  The process producer activates when lifecycle
 *          callbacks register successfully.
 * Return : STATUS_SUCCESS when the process producer is active or the
 *          registration failure NTSTATUS.
 */
NTSTATUS
KswInitializeProcessMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops process create/exit and guarded handle-access telemetry callbacks.
 * Inputs : none; callback registration state is module-local.
 * Logic  : disables emission before removing registered callbacks and clearing
 *          the shared device-extension pointer.
 * Return : no return value.
 */
VOID
KswUninitializeProcessMonitor(
    VOID
    );
