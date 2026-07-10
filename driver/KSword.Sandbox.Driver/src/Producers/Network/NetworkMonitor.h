#pragma once

#include "Driver.h"

/*
 * Initializes network telemetry callbacks.
 * Inputs : DeviceExtension owns the READ_EVENTS ring for eventual WFP events.
 * Logic  : boundary is separated now so WFP callout registration can be added
 *          independently from process, registry, file, and IOCTL code.
 * Return : STATUS_NOT_SUPPORTED until WFP registration is implemented.
 */
NTSTATUS
KswInitializeNetworkMonitor(
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops network telemetry callbacks.
 * Inputs : none; WFP engine/callout state will be module-local.
 * Logic  : no-op until WFP support lands.
 * Return : no return value.
 */
VOID
KswUninitializeNetworkMonitor(
    VOID
    );
