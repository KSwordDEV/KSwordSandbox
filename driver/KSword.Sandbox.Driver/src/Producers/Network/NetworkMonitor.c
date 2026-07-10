#include "Producers/Network/NetworkMonitor.h"

#if !defined(NDIS630)
#define NDIS630 1
#endif

/*
 * WFP kernel headers include NDIS definitions that intentionally use anonymous
 * unions.  Keep the warning scoped to WDK headers so /W4 /WX still applies to
 * this source file's own code.
 */
#pragma warning(push)
#pragma warning(disable: 4201)
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

/*
 * Runtime state for the WFP/ALE network event producer.
 *
 * Inputs : initialized by KswInitializeNetworkMonitor after the control device
 *          and event ring exist.
 * Logic  : stores dynamic FWPM engine state, FWPS callout ids, filter ids, and
 *          the shared READ_EVENTS ring owner.  Active gates classify callback
 *          emission during partial initialization and unload.
 * Return : no direct return value; KswInitializeNetworkMonitor exposes setup
 *          failures and KswPushEvent carries telemetry to user mode.
 */
typedef struct _KSWORD_SANDBOX_NETWORK_WFP_RUNTIME {
    PDEVICE_OBJECT DeviceObject;
    PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension;
    HANDLE EngineHandle;
    volatile LONG Active;
    UINT32 ConnectV4CalloutId;
    UINT32 RecvAcceptV4CalloutId;
    UINT32 ConnectV6CalloutId;
    UINT32 RecvAcceptV6CalloutId;
    UINT64 ConnectV4FilterId;
    UINT64 RecvAcceptV4FilterId;
    UINT64 ConnectV6FilterId;
    UINT64 RecvAcceptV6FilterId;
    NTSTATUS RegisterStatus;
    NTSTATUS EngineStatus;
    volatile LONG64 ClassifyCount;
    volatile LONG64 EventCount;
} KSWORD_SANDBOX_NETWORK_WFP_RUNTIME, *PKSWORD_SANDBOX_NETWORK_WFP_RUNTIME;

static KSWORD_SANDBOX_NETWORK_WFP_RUNTIME g_KswNetworkWfpRuntime;

static VOID NTAPI
KswNetworkClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    );

static NTSTATUS NTAPI
KswNetworkNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER0* Filter
    );

static VOID NTAPI
KswNetworkFlowDeleteFn(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
    );

/*
 * WFP layer and object GUIDs used by the dynamic ALE event producer.
 *
 * Inputs : consumed by FWPS/FWPM registration helpers.
 * Logic  : standard layer GUID values are stored locally to avoid relying on
 *          GUID object instantiation from WDK headers; KSword-owned GUIDs name
 *          this driver's dynamic sublayer, callouts, and filters.
 * Return : not applicable; WFP copies these values during registration.
 */
static const GUID g_KswFwpmLayerAleAuthConnectV4 = {
    0xc38d57d1, 0x05a7, 0x4c33,
    { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 }
};

static const GUID g_KswFwpmLayerAleAuthRecvAcceptV4 = {
    0xe1cd9fe7, 0xf4b5, 0x4273,
    { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 }
};

static const GUID g_KswFwpmLayerAleAuthConnectV6 = {
    0x4a72393b, 0x319f, 0x44bc,
    { 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4 }
};

static const GUID g_KswFwpmLayerAleAuthRecvAcceptV6 = {
    0xa3b42c97, 0x9f04, 0x4672,
    { 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f }
};

static const GUID g_KswNetworkWfpSublayer = {
    0x045d9f2c, 0xd8d7, 0x4e8a,
    { 0xa1, 0xe4, 0x05, 0x32, 0xfd, 0x03, 0xde, 0x69 }
};

static const GUID g_KswNetworkConnectV4Callout = {
    0x64f03ec7, 0x7b29, 0x453b,
    { 0x8c, 0xac, 0x34, 0xa8, 0xf5, 0x4e, 0xa4, 0xa1 }
};

static const GUID g_KswNetworkRecvAcceptV4Callout = {
    0xbcef729c, 0xf07a, 0x4db4,
    { 0x89, 0x31, 0x54, 0x99, 0xc0, 0xb8, 0x9e, 0x8f }
};

static const GUID g_KswNetworkConnectV6Callout = {
    0x633b5a9d, 0x14bd, 0x42b5,
    { 0xa3, 0x5d, 0x21, 0xa8, 0x7e, 0xeb, 0xb4, 0xa8 }
};

static const GUID g_KswNetworkRecvAcceptV6Callout = {
    0x1295009b, 0xb5b5, 0x4d9d,
    { 0xbd, 0x13, 0x14, 0x80, 0x91, 0xdd, 0x39, 0xf2 }
};

static const GUID g_KswNetworkConnectV4Filter = {
    0xf2b09803, 0x0c2c, 0x4269,
    { 0x9d, 0xc0, 0x16, 0xec, 0xc7, 0x9a, 0xb7, 0x21 }
};

static const GUID g_KswNetworkRecvAcceptV4Filter = {
    0xc32d15b2, 0xc38a, 0x4bd5,
    { 0xb0, 0xa6, 0xdf, 0x5a, 0x61, 0xce, 0x4b, 0xd4 }
};

static const GUID g_KswNetworkConnectV6Filter = {
    0x235ba9d5, 0xecb0, 0x441f,
    { 0xbe, 0x23, 0xe7, 0x96, 0xbe, 0xe0, 0x55, 0x71 }
};

static const GUID g_KswNetworkRecvAcceptV6Filter = {
    0xcbb030e9, 0x912f, 0x4b6e,
    { 0x89, 0x03, 0x1b, 0xd2, 0xca, 0x92, 0x13, 0x15 }
};

/*
 * Leaves WFP classification as a non-blocking inspection decision.
 *
 * Inputs : ClassifyOut is the WFP classify output supplied to the callout.
 * Logic  : inspection filters should not terminate policy evaluation.  When WFP
 *          grants action-write rights, return CONTINUE so later filters and the
 *          base firewall policy keep their normal behavior.
 * Return : no return value.
 */
static
VOID
KswNetworkSetInspectionAction(
    _Inout_opt_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    if (ClassifyOut != NULL &&
        (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

/*
 * Converts a network-order transport port to host order.
 *
 * Inputs : PortNetwork is the 16-bit ALE fixed-field value.
 * Logic  : WFP supplies transport ports in network byte order for these fields;
 *          swapping before enqueue keeps the user-mode ABI parser-friendly.
 * Return : host-order port value.
 */
static
USHORT
KswNetworkPortFromNetworkOrder(
    _In_ USHORT PortNetwork
    )
{
    return (USHORT)(((PortNetwork & 0x00ffU) << 8) |
        ((PortNetwork & 0xff00U) >> 8));
}

/*
 * Writes a 32-bit IPv4 address into the public address bytes.
 *
 * Inputs : AddressBytes is a 16-byte public address field; AddressValue is the
 *          WFP IPv4 value interpreted in presentation order.
 * Logic  : stores bytes [a,b,c,d] in indices [0..3] and leaves the remaining
 *          bytes untouched so the caller can preserve zero-initialization.
 * Return : no return value.
 */
static
VOID
KswNetworkWriteIpv4AddressBytes(
    _Out_writes_bytes_(KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES) UCHAR* AddressBytes,
    _In_ ULONG AddressValue
    )
{
    AddressBytes[0] = (UCHAR)((AddressValue >> 24) & 0xffU);
    AddressBytes[1] = (UCHAR)((AddressValue >> 16) & 0xffU);
    AddressBytes[2] = (UCHAR)((AddressValue >> 8) & 0xffU);
    AddressBytes[3] = (UCHAR)(AddressValue & 0xffU);
}

/*
 * Reads an integer-valued WFP fixed field into a ULONG.
 *
 * Inputs : Values is the WFP fixed-value array, Index is a layer-specific field
 *          enum, and ValueOut receives a normalized integer.
 * Logic  : validates bounds and accepts UINT8, UINT16, and UINT32 field types
 *          because WFP protocol/port/address fields vary by layer and WDK.
 * Return : TRUE when a supported integer was copied; otherwise FALSE.
 */
static
BOOLEAN
KswNetworkReadIntegerField(
    _In_opt_ const FWPS_INCOMING_VALUES0* Values,
    _In_ UINT32 Index,
    _Out_ PULONG ValueOut
    )
{
    const FWP_VALUE0* value;

    if (Values == NULL ||
        Values->incomingValue == NULL ||
        ValueOut == NULL ||
        Index >= Values->valueCount) {
        return FALSE;
    }

    value = &Values->incomingValue[Index].value;
    switch (value->type) {
    case FWP_UINT8:
        *ValueOut = value->uint8;
        return TRUE;

    case FWP_UINT16:
        *ValueOut = value->uint16;
        return TRUE;

    case FWP_UINT32:
        *ValueOut = value->uint32;
        return TRUE;

    default:
        return FALSE;
    }
}
