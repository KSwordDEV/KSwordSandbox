#pragma once

#include "Driver.h"

/*
 * Initializes registry telemetry callbacks.
 * Inputs : DriverObject identifies this driver for CmRegisterCallbackEx;
 *          DeviceExtension owns the READ_EVENTS ring.
 * Logic  : registers a Configuration Manager post-operation callback for
 *          create/open/set/delete/rename telemetry.
 * Return : STATUS_SUCCESS when active or the registration failure NTSTATUS.
 */
NTSTATUS
KswInitializeRegistryMonitor(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops registry telemetry callbacks.
 * Inputs : none; callback cookie storage is module-local.
 * Logic  : disables event emission and unregisters CmRegisterCallbackEx state
 *          before the control device is deleted.
 * Return : no return value.
 */
VOID
KswUninitializeRegistryMonitor(
    VOID
    );
