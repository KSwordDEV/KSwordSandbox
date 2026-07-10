#pragma once

#include "Driver.h"

/*
 * Initializes registry telemetry callbacks.
 * Inputs : DriverObject identifies this driver for CmRegisterCallbackEx;
 *          DeviceExtension owns the READ_EVENTS ring.
 * Logic  : this boundary isolates registry callback code from DriverEntry.
 * Return : STATUS_NOT_SUPPORTED until callback registration is implemented.
 */
NTSTATUS
KswInitializeRegistryMonitor(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops registry telemetry callbacks.
 * Inputs : none; callback cookie storage is module-local.
 * Logic  : no-op until CmRegisterCallbackEx support lands.
 * Return : no return value.
 */
VOID
KswUninitializeRegistryMonitor(
    VOID
    );
