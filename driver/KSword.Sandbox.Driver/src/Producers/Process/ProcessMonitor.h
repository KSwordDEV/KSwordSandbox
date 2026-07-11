#pragma once

#include "Driver.h"

/*
 * Initializes process create/exit telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring that callbacks write into.
 * Logic  : registers PsSetCreateProcessNotifyRoutineEx with a legacy fallback
 *          and activates the process producer when a callback registered.
 * Return : STATUS_SUCCESS when the process producer is active or the
 *          registration failure NTSTATUS.
 */
NTSTATUS
KswInitializeProcessMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops process create/exit telemetry callbacks.
 * Inputs : none; callback registration state is module-local.
 * Logic  : disables emission before removing registered callbacks and clearing
 *          the shared device-extension pointer.
 * Return : no return value.
 */
VOID
KswUninitializeProcessMonitor(
    VOID
    );
