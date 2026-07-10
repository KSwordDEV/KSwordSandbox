#pragma once

#include "Driver.h"

/*
 * Initializes network telemetry callbacks.
 * Inputs : DeviceObject owns the FWPS callback lifetime; DeviceExtension owns
 *          the READ_EVENTS ring that receives WFP/ALE events.
 * Logic  : registers inspect-only ALE connect and recv-accept callouts/filters
 *          for IPv4 and IPv6 without blocking or modifying network traffic.
 * Return : STATUS_SUCCESS when WFP registration succeeds; otherwise the first
 *          FWPS/FWPM NTSTATUS so DriverEntry can expose it through health.
 */
NTSTATUS
KswInitializeNetworkMonitor(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops network telemetry callbacks.
 * Inputs : none; WFP engine/callout state is module-local.
 * Logic  : disables classify emission, deletes FWPM objects, closes the dynamic
 *          engine session, unregisters FWPS callouts, and clears shared state.
 * Return : no return value.
 */
VOID
KswUninitializeNetworkMonitor(
    VOID
    );
