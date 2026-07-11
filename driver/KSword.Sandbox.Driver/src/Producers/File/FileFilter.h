#pragma once

#include "Driver.h"

/*
 * Runtime state for the file minifilter producer.
 *
 * Inputs : initialized from DriverEntry and read by minifilter callbacks.
 * Logic  : stores the FltMgr filter handle, the existing READ_EVENTS device
 *          extension, registration/start statuses, initialized/teardown guards,
 *          and the v1 payload version.  Active gates callback event emission before the
 *          filter is unregistered during unload.
 * Return : no direct return value; failures are summarized through the device
 *          extension LastStatus field exposed by health.
 */
typedef struct _KSWORD_SANDBOX_FILE_FILTER_RUNTIME {
    PFLT_FILTER Filter;
    PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension;
    volatile LONG Active;
    volatile LONG Initialized;
    volatile LONG Uninitializing;
    ULONG PayloadVersion;
    NTSTATUS RegisterStatus;
    NTSTATUS StartStatus;
} KSWORD_SANDBOX_FILE_FILTER_RUNTIME, *PKSWORD_SANDBOX_FILE_FILTER_RUNTIME;

/*
 * Initializes file-system telemetry callbacks.
 * Inputs : DriverObject and RegistryPath come from DriverEntry; DeviceExtension
 *          owns the READ_EVENTS ring.
 * Logic  : prepares FltMgr instance metadata, registers the minifilter, starts
 *          filtering, and marks the producer active only after start succeeds.
 * Return : STATUS_SUCCESS when active or the first FltMgr/registry NTSTATUS.
 */
NTSTATUS
KswInitializeFileFilter(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    );

/*
 * Stops file-system telemetry callbacks.
 * Inputs : none; runtime state is module-local.
 * Logic  : disables callback emission, unregisters the minifilter once, and
 *          clears stale pointers before the control device can be deleted.
 * Return : no return value.
 */
VOID
KswUninitializeFileFilter(
    VOID
    );
