#include "Driver.h"
#include "Producers/Network/NetworkMonitor.h"
#include "Producers/Process/ProcessMonitor.h"
#include "Producers/Registry/RegistryMonitor.h"

/*
 * Driver entry point called by the I/O manager when the service is loaded.
 *
 * Inputs : DriverObject is owned by the I/O manager; RegistryPath identifies the
 *          service key for future configuration reads.
 * Logic  : installs dispatch routines, creates one control device object,
 *          initializes its extension, creates the Win32-visible symbolic link,
 *          starts independent R0 producers, and clears DO_DEVICE_INITIALIZING
 *          only after the control device is usable.
 * Return : STATUS_SUCCESS when the control device is ready; otherwise the
 *          failing NTSTATUS from device or symbolic-link creation.
 */
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    PDEVICE_OBJECT deviceObject;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    ULONG majorFunctionIndex;

    deviceObject = NULL;

    DriverObject->DriverUnload = KswDriverUnload;
    for (majorFunctionIndex = 0;
         majorFunctionIndex <= IRP_MJ_MAXIMUM_FUNCTION;
         majorFunctionIndex++) {
        DriverObject->MajorFunction[majorFunctionIndex] = KswDispatchUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = KswDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KswDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KswDispatchDeviceControl;

    RtlInitUnicodeString(&deviceName, KSWORD_SANDBOX_NT_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        sizeof(KSWORD_SANDBOX_DEVICE_EXTENSION),
        &deviceName,
        KSWORD_SANDBOX_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;

    deviceExtension =
        (PKSWORD_SANDBOX_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    KswInitializeDeviceExtension(deviceExtension);

    RtlInitUnicodeString(&symbolicLinkName, KSWORD_SANDBOX_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    /*
     * The file minifilter is an event producer layered on the existing control
     * device.  If FltMgr registration is unavailable in a lab environment, keep
     * the original IOCTL and READ_EVENTS path alive and expose the failure
     * through GET_HEALTH.LastNtStatus.
     */
    status = KswInitializeFileFilter(
        DriverObject,
        RegistryPath,
        deviceExtension);
    if (!NT_SUCCESS(status)) {
        KswSetLastStatus(deviceExtension, status);
    }

    /*
     * Process and image callbacks are core R0 behavior producers.  Registration
     * failures are non-fatal because unsigned or improperly signed lab builds
     * may reject the Ex callback; the collector can still use health and other
     * producers.
     */
    status = KswInitializeProcessMonitor(deviceExtension);
    if (!NT_SUCCESS(status)) {
        KswSetLastStatus(deviceExtension, status);
    }

    /*
     * Registry telemetry is independent from the other producer modules.
     * Altitude collisions or policy failures are useful health data, but they
     * must not prevent the control device or other telemetry from loading.
     */
    status = KswInitializeRegistryMonitor(DriverObject, deviceExtension);
    if (!NT_SUCCESS(status)) {
        KswSetLastStatus(deviceExtension, status);
    }

    /*
     * Network telemetry registers inspect-only WFP/ALE callouts over the same
     * READ_EVENTS ring.  Registration failures are non-fatal because lab VMs
     * may lack usable WFP state during early driver bring-up.
     */
    status = KswInitializeNetworkMonitor(deviceObject, deviceExtension);
    if (!NT_SUCCESS(status)) {
        KswSetLastStatus(deviceExtension, status);
    }

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

/*
 * Driver unload routine called when the driver service is stopped.
 *
 * Inputs : DriverObject identifies the loaded driver instance.
 * Logic  : marks the device as stopping, stops producer modules, deletes the
 *          DOS symbolic link, and deletes the single control device object
 *          created by DriverEntry.
 * Return : no return value.
 */
_Use_decl_annotations_
VOID
KswDriverUnload(
    PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symbolicLinkName;
    PDEVICE_OBJECT deviceObject;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;

    deviceObject = DriverObject->DeviceObject;
    if (deviceObject != NULL) {
        deviceExtension = KswGetDeviceExtension(deviceObject);
        if (deviceExtension != NULL) {
            KIRQL oldIrql;

            KeAcquireSpinLock(&deviceExtension->StateLock, &oldIrql);
            deviceExtension->DriverState = KswSandboxDriverStateStopping;
            KeReleaseSpinLock(&deviceExtension->StateLock, oldIrql);
        }
    }

    KswUninitializeNetworkMonitor();
    KswUninitializeProcessMonitor();
    KswUninitializeRegistryMonitor();
    KswUninitializeFileFilter();

    RtlInitUnicodeString(&symbolicLinkName, KSWORD_SANDBOX_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);

    if (deviceObject != NULL) {
        IoDeleteDevice(deviceObject);
    }
}
