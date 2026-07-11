#pragma once

#include "Driver.h"

/*
 * Initializes image-load telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring that callbacks write into.
 * Logic  : registers PsSetLoadImageNotifyRoutine and activates the image
 *          producer only after registration succeeds.
 * Return : STATUS_SUCCESS when active or the registration failure NTSTATUS.
 */
NTSTATUS
KswInitializeImageMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops image-load telemetry callbacks.
 * Inputs : none; callback registration state is module-local.
 * Logic  : disables emission before removing the registered callback and
 *          clearing the shared device-extension pointer.
 * Return : no return value.
 */
VOID
KswUninitializeImageMonitor(
    VOID
    );
