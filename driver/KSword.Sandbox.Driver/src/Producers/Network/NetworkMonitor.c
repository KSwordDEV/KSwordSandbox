#include "Producers/Network/NetworkInternal.h"

#if KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE

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

#include "Producers/Network/NetworkWfpBindings.h"

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

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
 * Returns the network payload version stamped on emitted ALE records.
 * Inputs : none; reads the WFP runtime state.
 * Logic  : classify callbacks can overlap teardown after observing Active, so a
 *          cleared runtime falls back to the stable ABI v1 payload version.
 * Return : KSWORD_SANDBOX_NETWORK_EVENT_VERSION for current network payloads.
 */
static
ULONG
KswNetworkPayloadVersion(
    VOID
    )
{
    ULONG version;

    version = g_KswNetworkWfpRuntime.PayloadVersion;
    return version == 0 ? KSWORD_SANDBOX_NETWORK_EVENT_VERSION : version;
}

/*
 * Records the most recent network-specific degradation reason.
 *
 * Inputs : Reason is a KSWORD_SANDBOX_NETWORK_STATUS_DEGRADE_REASON value and
 *          Status is the closest NTSTATUS for the failing WFP or queue step.
 * Logic  : this is intentionally internal-only today.  GET_STATUS exposes the
 *          coarse FailedProducerMask/LastNtStatus contract; the draft typed
 *          payload/status reason must not be treated as implemented until a
 *          future ABI advertises it.
 * Return : no return value.
 */
static
VOID
KswNetworkRecordDegradeStatus(
    _In_ ULONG Reason,
    _In_ NTSTATUS Status
    )
{
    (VOID)InterlockedExchange(
        &g_KswNetworkWfpRuntime.LastDegradeReason,
        (LONG)Reason);
    (VOID)InterlockedExchange(
        &g_KswNetworkWfpRuntime.LastDegradeStatus,
        (LONG)Status);
}

/*
 * Finds the descriptor row for a WFP ALE layer id.
 *
 * Inputs : LayerId is FWPS_INCOMING_VALUES0.layerId.
 * Logic  : the descriptor table is the single source of truth for the four ALE
 *          layers implemented in this inspect-only producer.
 * Return : descriptor pointer, or NULL for a layer outside the current scope.
 */
static
const KSWORD_SANDBOX_NETWORK_ALE_BINDING*
KswNetworkFindAleBindingByLayer(
    _In_ UINT16 LayerId
    )
{
    ULONG index;

    for (index = 0; index < KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT; index++) {
        if (g_KswNetworkAleBindings[index].LayerId == LayerId) {
            return &g_KswNetworkAleBindings[index];
        }
    }

    return NULL;
}

/*
 * Maps a descriptor row to the runtime FWPS callout-id slot.
 *
 * Inputs : BindingId identifies one row from g_KswNetworkAleBindings.
 * Logic  : keeps table-driven registration/cleanup in one compiled source file
 *          without using C++ member pointers or spreading globals across files.
 * Return : address of the runtime slot, or NULL for invalid input.
 */
static
PUINT32
KswNetworkCalloutIdSlot(
    _In_ KSWORD_SANDBOX_NETWORK_ALE_BINDING_ID BindingId
    )
{
    switch (BindingId) {
    case KswNetworkAleBindingConnectV4:
        return &g_KswNetworkWfpRuntime.ConnectV4CalloutId;

    case KswNetworkAleBindingRecvAcceptV4:
        return &g_KswNetworkWfpRuntime.RecvAcceptV4CalloutId;

    case KswNetworkAleBindingConnectV6:
        return &g_KswNetworkWfpRuntime.ConnectV6CalloutId;

    case KswNetworkAleBindingRecvAcceptV6:
        return &g_KswNetworkWfpRuntime.RecvAcceptV6CalloutId;

    default:
        return NULL;
    }
}

/*
 * Maps a descriptor row to the runtime FWPM filter-id slot.
 *
 * Inputs : BindingId identifies one row from g_KswNetworkAleBindings.
 * Logic  : mirrors KswNetworkCalloutIdSlot for filter cleanup and registration
 *          while preserving the single source descriptor table.
 * Return : address of the runtime slot, or NULL for invalid input.
 */
static
PUINT64
KswNetworkFilterIdSlot(
    _In_ KSWORD_SANDBOX_NETWORK_ALE_BINDING_ID BindingId
    )
{
    switch (BindingId) {
    case KswNetworkAleBindingConnectV4:
        return &g_KswNetworkWfpRuntime.ConnectV4FilterId;

    case KswNetworkAleBindingRecvAcceptV4:
        return &g_KswNetworkWfpRuntime.RecvAcceptV4FilterId;

    case KswNetworkAleBindingConnectV6:
        return &g_KswNetworkWfpRuntime.ConnectV6FilterId;

    case KswNetworkAleBindingRecvAcceptV6:
        return &g_KswNetworkWfpRuntime.RecvAcceptV6FilterId;

    default:
        return NULL;
    }
}

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

/*
 * Reads and converts a transport port from a WFP fixed field.
 *
 * Inputs : Values is the WFP fixed-value array, Index is a local or remote port
 *          field enum, and PortOut receives a host-order public ABI value.
 * Logic  : normalizes the source field as an integer, verifies it fits in 16
 *          bits, then swaps from network byte order.
 * Return : TRUE when a valid port was copied; otherwise FALSE.
 */
static
BOOLEAN
KswNetworkReadPortField(
    _In_opt_ const FWPS_INCOMING_VALUES0* Values,
    _In_ UINT32 Index,
    _Out_ PUSHORT PortOut
    )
{
    ULONG value;

    if (PortOut == NULL ||
        !KswNetworkReadIntegerField(Values, Index, &value) ||
        value > 0xffffU) {
        return FALSE;
    }

    *PortOut = KswNetworkPortFromNetworkOrder((USHORT)value);
    return TRUE;
}

/*
 * Reads an IPv4 fixed field into the public address byte array.
 *
 * Inputs : Values is the WFP fixed-value array, Index is the layer-specific IPv4
 *          address field, and AddressBytes receives a 16-byte public field.
 * Logic  : reads the WFP UINT32 address and stores only the first four bytes in
 *          presentation order; the caller controls payload flags.
 * Return : TRUE when an IPv4 address was copied; otherwise FALSE.
 */
static
BOOLEAN
KswNetworkReadIpv4AddressField(
    _In_opt_ const FWPS_INCOMING_VALUES0* Values,
    _In_ UINT32 Index,
    _Out_writes_bytes_(KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES) UCHAR* AddressBytes
    )
{
    ULONG addressValue;

    if (AddressBytes == NULL ||
        !KswNetworkReadIntegerField(Values, Index, &addressValue)) {
        return FALSE;
    }

    KswNetworkWriteIpv4AddressBytes(AddressBytes, addressValue);
    return TRUE;
}

/*
 * Reads an IPv6 fixed field into the public address byte array.
 *
 * Inputs : Values is the WFP fixed-value array, Index is the layer-specific IPv6
 *          address field, and AddressBytes receives all 16 bytes.
 * Logic  : validates that WFP supplied an FWP_BYTE_ARRAY16 pointer before doing
 *          a bounded copy into the fixed-size payload.
 * Return : TRUE when an IPv6 address was copied; otherwise FALSE.
 */
static
BOOLEAN
KswNetworkReadIpv6AddressField(
    _In_opt_ const FWPS_INCOMING_VALUES0* Values,
    _In_ UINT32 Index,
    _Out_writes_bytes_(KSWORD_SANDBOX_NETWORK_ADDRESS_BYTES) UCHAR* AddressBytes
    )
{
    const FWP_VALUE0* value;

    if (Values == NULL ||
        Values->incomingValue == NULL ||
        AddressBytes == NULL ||
        Index >= Values->valueCount) {
        return FALSE;
    }

    value = &Values->incomingValue[Index].value;
    if (value->type != FWP_BYTE_ARRAY16_TYPE ||
        value->byteArray16 == NULL) {
        return FALSE;
    }

    RtlCopyMemory(
        AddressBytes,
        value->byteArray16->byteArray16,
        sizeof(value->byteArray16->byteArray16));
    return TRUE;
}

/*
 * Maps a WFP ALE layer id to the public direction value.
 *
 * Inputs : LayerId is FWPS_INCOMING_VALUES0.layerId.
 * Logic  : connect authorization represents outbound initiation and recv-accept
 *          authorization represents inbound acceptance.
 * Return : KSWORD_SANDBOX_NETWORK_DIRECTION value.
 */
static
ULONG
KswNetworkDirectionFromLayer(
    _In_ UINT16 LayerId
    )
{
    switch (LayerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        return KswSandboxNetworkDirectionOutbound;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        return KswSandboxNetworkDirectionInbound;

    default:
        return KswSandboxNetworkDirectionUnknown;
    }
}

/*
 * Maps a WFP ALE layer id to the registered runtime callout id.
 *
 * Inputs : LayerId is FWPS_INCOMING_VALUES0.layerId.
 * Logic  : all four ALE callouts share one classify function, so layer id is a
 *          compact hint for the public payload when WFP's filter object does
 *          not expose a callout id.
 * Return : registered callout id or zero when the layer is unknown.
 */
static
ULONG
KswNetworkCalloutIdFromLayer(
    _In_ UINT16 LayerId
    )
{
    const KSWORD_SANDBOX_NETWORK_ALE_BINDING* binding;
    PUINT32 calloutIdSlot;

    binding = KswNetworkFindAleBindingByLayer(LayerId);
    if (binding == NULL) {
        return 0;
    }

    calloutIdSlot = KswNetworkCalloutIdSlot(binding->Id);
    return calloutIdSlot == NULL ? 0 : *calloutIdSlot;
}

typedef struct _KSWORD_SANDBOX_NETWORK_ALE_FIELD_LAYOUT {
    ULONG AddressFamily;
    UINT32 ProtocolIndex;
    UINT32 LocalPortIndex;
    UINT32 RemotePortIndex;
    UINT32 LocalAddressIndex;
    UINT32 RemoteAddressIndex;
    BOOLEAN IsIpv6;
} KSWORD_SANDBOX_NETWORK_ALE_FIELD_LAYOUT,
    *PKSWORD_SANDBOX_NETWORK_ALE_FIELD_LAYOUT;

/*
 * Selects fixed-field indices for one supported ALE layer.
 *
 * Inputs : LayerId is FWPS_INCOMING_VALUES0.layerId.
 * Logic  : isolates WFP enum fan-out from payload building so future packet,
 *          stream, or condition-filter TODOs can add new layouts without
 *          inflating the classify hot path.
 * Return : TRUE with Layout initialized for supported ALE layers; otherwise
 *          FALSE.
 */
static
BOOLEAN
KswNetworkGetAleFieldLayout(
    _In_ UINT16 LayerId,
    _Out_ PKSWORD_SANDBOX_NETWORK_ALE_FIELD_LAYOUT Layout
    )
{
    if (Layout == NULL) {
        return FALSE;
    }

    RtlZeroMemory(Layout, sizeof(*Layout));

    switch (LayerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        Layout->AddressFamily = KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV4;
        Layout->ProtocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
        Layout->LocalPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
        Layout->RemotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
        Layout->LocalAddressIndex =
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
        Layout->RemoteAddressIndex =
            FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        return TRUE;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        Layout->AddressFamily = KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV4;
        Layout->ProtocolIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
        Layout->LocalPortIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
        Layout->RemotePortIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
        Layout->LocalAddressIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
        Layout->RemoteAddressIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
        return TRUE;

    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        Layout->AddressFamily = KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV6;
        Layout->ProtocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
        Layout->LocalPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
        Layout->RemotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
        Layout->LocalAddressIndex =
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
        Layout->RemoteAddressIndex =
            FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
        Layout->IsIpv6 = TRUE;
        return TRUE;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        Layout->AddressFamily = KSWORD_SANDBOX_NETWORK_ADDRESS_FAMILY_IPV6;
        Layout->ProtocolIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
        Layout->LocalPortIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
        Layout->RemotePortIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
        Layout->LocalAddressIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
        Layout->RemoteAddressIndex =
            FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
        Layout->IsIpv6 = TRUE;
        return TRUE;

    default:
        return FALSE;
    }
}

/*
 * Copies optional WFP metadata into the public network payload.
 *
 * Inputs : MetaValues is the optional WFP metadata block and Payload is the
 *          stack payload being prepared for KswPushEvent.
 * Logic  : checks metadata presence bits before copying PID, flow handle, and
 *          transport endpoint handle so zero-valued metadata remains distinct
 *          from absent metadata in public ABI flags.
 * Return : no return value.
 */
static
VOID
KswNetworkCopyMetadataToPayload(
    _In_opt_ const FWPS_INCOMING_METADATA_VALUES0* MetaValues,
    _Inout_ PKSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD Payload
    )
{
    if (MetaValues == NULL || Payload == NULL) {
        return;
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(
            MetaValues,
            FWPS_METADATA_FIELD_PROCESS_ID)) {
        Payload->ProcessId = MetaValues->processId;
        Payload->Flags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_PROCESS_ID_PRESENT;
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(
            MetaValues,
            FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        Payload->FlowHandle = MetaValues->flowHandle;
        Payload->Flags |= KSWORD_SANDBOX_NETWORK_EVENT_FLAG_FLOW_HANDLE_PRESENT;
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(
            MetaValues,
            FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)) {
        Payload->TransportEndpointHandle = MetaValues->transportEndpointHandle;
        Payload->Flags |=
            KSWORD_SANDBOX_NETWORK_EVENT_FLAG_ENDPOINT_HANDLE_PRESENT;
    }
}

/*
 * Builds a compact public network payload from one ALE classify invocation.
 *
 * Inputs : FixedValues and MetaValues are supplied by WFP; Filter identifies the
 *          matching FWPM filter; Payload receives a fixed-size ABI record.
 * Logic  : maps the ALE layer to direction/family, reads protocol, ports, and
 *          address fields through bounded helpers, copies optional metadata,
 *          and stores layer/callout/filter hints for user-mode diagnostics.
 * Return : TRUE when the classify layer is one of the registered ALE layers;
 *          FALSE when no event should be emitted.
 */
static
BOOLEAN
KswNetworkBuildAlePayload(
    _In_opt_ const FWPS_INCOMING_VALUES0* FixedValues,
    _In_opt_ const FWPS_INCOMING_METADATA_VALUES0* MetaValues,
    _In_opt_ const FWPS_FILTER0* Filter,
    _Out_ PKSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD Payload
    )
{
    KSWORD_SANDBOX_NETWORK_ALE_FIELD_LAYOUT layout;
    ULONG protocol;

    if (FixedValues == NULL || Payload == NULL) {
        return FALSE;
    }

    if (!KswNetworkGetAleFieldLayout(FixedValues->layerId, &layout)) {
        return FALSE;
    }

    protocol = KSWORD_SANDBOX_NETWORK_PROTOCOL_ANY;

    RtlZeroMemory(Payload, sizeof(*Payload));
    Payload->Version = KswNetworkPayloadVersion();
    Payload->Size = sizeof(*Payload);
    Payload->LayerId = FixedValues->layerId;
    Payload->AddressFamily = layout.AddressFamily;
    Payload->Operation = KswSandboxNetworkOperationAleAuthorize;
    Payload->Status = STATUS_SUCCESS;
    Payload->Direction = KswNetworkDirectionFromLayer(FixedValues->layerId);
    Payload->Flags = KSWORD_SANDBOX_NETWORK_EVENT_FLAG_INSPECTION_ONLY;

    if (Filter != NULL) {
        Payload->FilterId = Filter->filterId;
        Payload->CalloutId = Filter->action.calloutId;
    }
    if (Payload->CalloutId == 0) {
        Payload->CalloutId = KswNetworkCalloutIdFromLayer(FixedValues->layerId);
    }

    if (KswNetworkReadIntegerField(
            FixedValues,
            layout.ProtocolIndex,
            &protocol)) {
        Payload->Protocol = protocol;
    }

    (VOID)KswNetworkReadPortField(
        FixedValues,
        layout.LocalPortIndex,
        &Payload->LocalPort);
    (VOID)KswNetworkReadPortField(
        FixedValues,
        layout.RemotePortIndex,
        &Payload->RemotePort);

    if (layout.IsIpv6) {
        if (KswNetworkReadIpv6AddressField(
                FixedValues,
                layout.LocalAddressIndex,
                Payload->LocalAddress)) {
            Payload->Flags |=
                KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT;
        }
        if (KswNetworkReadIpv6AddressField(
                FixedValues,
                layout.RemoteAddressIndex,
                Payload->RemoteAddress)) {
            Payload->Flags |=
                KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT;
        }
    } else {
        if (KswNetworkReadIpv4AddressField(
                FixedValues,
                layout.LocalAddressIndex,
                Payload->LocalAddress)) {
            Payload->Flags |=
                KSWORD_SANDBOX_NETWORK_EVENT_FLAG_LOCAL_ADDRESS_PRESENT;
        }
        if (KswNetworkReadIpv4AddressField(
                FixedValues,
                layout.RemoteAddressIndex,
                Payload->RemoteAddress)) {
            Payload->Flags |=
                KSWORD_SANDBOX_NETWORK_EVENT_FLAG_REMOTE_ADDRESS_PRESENT;
        }
    }

    KswNetworkCopyMetadataToPayload(MetaValues, Payload);

    return TRUE;
}

/*
 * WFP classify callback for the ALE network event producer.
 *
 * Inputs : WFP supplies fixed fields, metadata, layer data, the matching filter,
 *          flow context, and classify output for one authorization decision.
 * Logic  : returns CONTINUE for inspect-only behavior, skips emission while
 *          inactive, builds one compact payload from fixed fields, and queues it
 *          into the existing READ_EVENTS ring with KswPushEvent.
 * Return : no return value; WFP observes ClassifyOut and collectors observe the
 *          queued event stream.
 */
static
VOID
NTAPI
KswNetworkClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
{
    KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD payload;
    PKSWORD_SANDBOX_DEVICE_EXTENSION deviceExtension;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(FlowContext);

    KswNetworkSetInspectionAction(ClassifyOut);
    InterlockedIncrement64(&g_KswNetworkWfpRuntime.ClassifyCount);

    if (InterlockedCompareExchange(&g_KswNetworkWfpRuntime.Active, 0, 0) == 0) {
        return;
    }

    deviceExtension = g_KswNetworkWfpRuntime.DeviceExtension;
    if (deviceExtension == NULL ||
        deviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return;
    }

    if (!KswNetworkBuildAlePayload(
            InFixedValues,
            InMetaValues,
            Filter,
            &payload)) {
        KswNetworkRecordDegradeStatus(
            KswSandboxNetworkStatusDegradeClassifyPayload,
            STATUS_INVALID_PARAMETER);
        return;
    }

    status = KswPushEvent(
        deviceExtension,
        KswSandboxEventTypeNetwork,
        0,
        &payload,
        (ULONG)sizeof(payload));
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_KswNetworkWfpRuntime.EventCount);
    } else if (status != STATUS_CANCELLED) {
        KswNetworkRecordDegradeStatus(
            KswSandboxNetworkStatusDegradeQueuePush,
            status);
        KswSetLastStatus(deviceExtension, status);
    }
}

/*
 * WFP filter notification callback for the ALE network producer.
 *
 * Inputs : NotifyType describes filter add/delete, FilterKey identifies the
 *          filter, and Filter supplies WFP's filter object.
 * Logic  : this minimal producer keeps no per-filter state, so the callback
 *          validates the path and lets WFP continue.
 * Return : STATUS_SUCCESS.
 */
static
NTSTATUS
NTAPI
KswNetworkNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER0* Filter
    )
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);

    return STATUS_SUCCESS;
}

/*
 * WFP flow-delete callback for the ALE network producer.
 *
 * Inputs : LayerId, CalloutId, and FlowContext describe a flow context being
 *          removed by WFP.
 * Logic  : this v1 producer does not associate flow contexts, so the callback
 *          intentionally performs no work and only satisfies callout contract.
 * Return : no return value.
 */
static
VOID
NTAPI
KswNetworkFlowDeleteFn(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
    )
{
    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);
    UNREFERENCED_PARAMETER(FlowContext);
}

/*
 * Registers one runtime FWPS callout with the filtering engine.
 *
 * Inputs : DeviceObject owns callback lifetime, CalloutKey is the KSword-owned
 *          callout GUID, and CalloutIdOut receives WFP's runtime id.
 * Logic  : builds a version-0 callout descriptor that points at the shared ALE
 *          classify, notify, and flow-delete callbacks.
 * Return : FwpsCalloutRegister0 NTSTATUS.
 */
static
NTSTATUS
KswNetworkRegisterFwpsCallout(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ const GUID* CalloutKey,
    _Out_ PUINT32 CalloutIdOut
    )
{
    FWPS_CALLOUT0 callout;

    if (DeviceObject == NULL ||
        CalloutKey == NULL ||
        CalloutIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *CalloutIdOut = 0;
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *CalloutKey;
    callout.classifyFn = KswNetworkClassifyFn;
    callout.notifyFn = KswNetworkNotifyFn;
    callout.flowDeleteFn = KswNetworkFlowDeleteFn;

    return FwpsCalloutRegister0(DeviceObject, &callout, CalloutIdOut);
}

/*
 * Unregisters all FWPS callout ids stored in the network runtime.
 *
 * Inputs : none; uses g_KswNetworkWfpRuntime.
 * Logic  : unregisters non-zero callout ids and clears each field so repeated
 *          cleanup after partial initialization is safe.
 * Return : no return value; unregister failures are ignored during cleanup.
 */
static
VOID
KswNetworkUnregisterFwpsCallouts(
    VOID
    )
{
    ULONG index;

    for (index = 0; index < KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT; index++) {
        PUINT32 calloutIdSlot;

        calloutIdSlot = KswNetworkCalloutIdSlot(
            g_KswNetworkAleBindings[index].Id);
        if (calloutIdSlot != NULL && *calloutIdSlot != 0) {
            (VOID)FwpsCalloutUnregisterById0(*calloutIdSlot);
            *calloutIdSlot = 0;
        }
    }
}

/*
 * Adds the KSword dynamic WFP sublayer to the open engine session.
 *
 * Inputs : EngineHandle is an open FWPM engine handle.
 * Logic  : uses a driver-owned sublayer GUID and medium weight so the inspect
 *          filters are grouped and removable without touching host policy.
 * Return : FwpmSubLayerAdd0 NTSTATUS.
 */
static
NTSTATUS
KswNetworkAddSublayer(
    _In_ HANDLE EngineHandle
    )
{
    FWPM_SUBLAYER0 subLayer;

    if (EngineHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey = g_KswNetworkWfpSublayer;
    subLayer.displayData.name = L"KSword Sandbox Network Events";
    subLayer.displayData.description =
        L"Dynamic inspect sublayer for KSword sandbox ALE telemetry";
    subLayer.weight = 0x4000U;

    return FwpmSubLayerAdd0(EngineHandle, &subLayer, NULL);
}

/*
 * Adds one FWPM management callout object for an already-registered FWPS id.
 *
 * Inputs : EngineHandle is open, CalloutKey identifies the callout, LayerKey is
 *          the applicable ALE layer, and Name is a diagnostic display name.
 * Logic  : creates a dynamic FWPM callout that binds WFP policy to the runtime
 *          FWPS callback registered earlier in initialization.
 * Return : FwpmCalloutAdd0 NTSTATUS.
 */
static
NTSTATUS
KswNetworkAddManagementCallout(
    _In_ HANDLE EngineHandle,
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_z_ PWSTR Name
    )
{
    FWPM_CALLOUT0 callout;

    if (EngineHandle == NULL ||
        CalloutKey == NULL ||
        LayerKey == NULL ||
        Name == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *CalloutKey;
    callout.displayData.name = Name;
    callout.applicableLayer = *LayerKey;

    return FwpmCalloutAdd0(EngineHandle, &callout, NULL, NULL);
}

/*
 * Adds one inspect filter that invokes a KSword ALE callout.
 *
 * Inputs : EngineHandle is open; FilterKey, CalloutKey, and LayerKey identify
 *          the WFP objects; Name is a diagnostic label; FilterIdOut receives the
 *          WFP-assigned id for later cleanup.
 * Logic  : creates an inspect-only filter with no conditions so the classify
 *          callback sees the selected ALE authorization layer without blocking
 *          or modifying traffic.
 * Return : FwpmFilterAdd0 NTSTATUS.
 */
static
NTSTATUS
KswNetworkAddInspectionFilter(
    _In_ HANDLE EngineHandle,
    _In_ const GUID* FilterKey,
    _In_ const GUID* CalloutKey,
    _In_ const GUID* LayerKey,
    _In_z_ PWSTR Name,
    _Out_ PUINT64 FilterIdOut
    )
{
    FWPM_FILTER0 filter;

    if (EngineHandle == NULL ||
        FilterKey == NULL ||
        CalloutKey == NULL ||
        LayerKey == NULL ||
        Name == NULL ||
        FilterIdOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *FilterIdOut = 0;
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = *FilterKey;
    filter.displayData.name = Name;
    filter.layerKey = *LayerKey;
    filter.subLayerKey = g_KswNetworkWfpSublayer;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = *CalloutKey;

    return FwpmFilterAdd0(EngineHandle, &filter, NULL, FilterIdOut);
}

/*
 * Deletes FWPM filters, callouts, sublayer, and closes the engine handle.
 *
 * Inputs : none; uses g_KswNetworkWfpRuntime.
 * Logic  : removes objects in dependency order, tolerates partial
 *          initialization, clears ids, and closes the dynamic session handle.
 * Return : no return value; cleanup is best-effort during unload/failure.
 */
static
VOID
KswNetworkDeleteManagementObjects(
    VOID
    )
{
    HANDLE engineHandle;
    ULONG index;

    engineHandle = g_KswNetworkWfpRuntime.EngineHandle;
    if (engineHandle == NULL) {
        return;
    }

    for (index = KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT; index > 0; index--) {
        PUINT64 filterIdSlot;

        filterIdSlot = KswNetworkFilterIdSlot(
            g_KswNetworkAleBindings[index - 1U].Id);
        if (filterIdSlot != NULL && *filterIdSlot != 0) {
            (VOID)FwpmFilterDeleteById0(engineHandle, *filterIdSlot);
            *filterIdSlot = 0;
        }
    }

    for (index = KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT; index > 0; index--) {
        (VOID)FwpmCalloutDeleteByKey0(
            engineHandle,
            &g_KswNetworkAleBindings[index - 1U].CalloutKey);
    }
    (VOID)FwpmSubLayerDeleteByKey0(engineHandle, &g_KswNetworkWfpSublayer);

    FwpmEngineClose0(engineHandle);
    g_KswNetworkWfpRuntime.EngineHandle = NULL;
}

/*
 * Registers and starts the WFP/ALE network event producer.
 *
 * Inputs : DeviceObject is the control device used for FWPS callback lifetime;
 *          DeviceExtension owns the existing READ_EVENTS ring.
 * Logic  : registers four ALE FWPS callouts, opens a dynamic FWPM session,
 *          creates one sublayer, creates management callouts and inspect
 *          filters for connect/recv-accept on IPv4 and IPv6, then marks classify
 *          emission active only after the transaction commits.
 * Return : STATUS_SUCCESS when WFP callbacks are active; otherwise the first
 *          FWPS/FWPM failure.  DriverEntry may keep the IOCTL device online.
 */
NTSTATUS
KswInitializeNetworkMonitor(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    FWPM_SESSION0 session;
    NTSTATUS status;
    BOOLEAN transactionStarted;
    ULONG index;
    ULONG degradeReason;

    if (DeviceObject == NULL ||
        DeviceExtension == NULL ||
        DeviceExtension->Signature != KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_KswNetworkWfpRuntime.EngineHandle != NULL ||
        InterlockedCompareExchange(&g_KswNetworkWfpRuntime.Active, 0, 0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(&g_KswNetworkWfpRuntime, sizeof(g_KswNetworkWfpRuntime));
    g_KswNetworkWfpRuntime.DeviceObject = DeviceObject;
    g_KswNetworkWfpRuntime.DeviceExtension = DeviceExtension;
    g_KswNetworkWfpRuntime.PayloadVersion =
        KSWORD_SANDBOX_NETWORK_EVENT_VERSION;
    g_KswNetworkWfpRuntime.RegisterStatus = STATUS_NOT_SUPPORTED;
    g_KswNetworkWfpRuntime.EngineStatus = STATUS_NOT_SUPPORTED;
    InterlockedExchange(&g_KswNetworkWfpRuntime.Initialized, 1);
    InterlockedExchange(&g_KswNetworkWfpRuntime.Uninitializing, 0);
    KswNetworkRecordDegradeStatus(
        KswSandboxNetworkStatusDegradeNone,
        STATUS_SUCCESS);
    transactionStarted = FALSE;
    degradeReason = KswSandboxNetworkStatusDegradeNone;

    for (index = 0; index < KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT; index++) {
        PUINT32 calloutIdSlot;

        calloutIdSlot = KswNetworkCalloutIdSlot(
            g_KswNetworkAleBindings[index].Id);
        if (calloutIdSlot == NULL) {
            status = STATUS_INVALID_PARAMETER;
            degradeReason = KswSandboxNetworkStatusDegradeFwpsCalloutRegister;
            goto Failure;
        }

        status = KswNetworkRegisterFwpsCallout(
            DeviceObject,
            &g_KswNetworkAleBindings[index].CalloutKey,
            calloutIdSlot);
        if (!NT_SUCCESS(status)) {
            degradeReason = KswSandboxNetworkStatusDegradeFwpsCalloutRegister;
            goto Failure;
        }
    }
    g_KswNetworkWfpRuntime.RegisterStatus = STATUS_SUCCESS;

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = L"KSword Sandbox Network WFP Session";
    session.displayData.description =
        L"Dynamic WFP session for KSword sandbox network events";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.kernelMode = TRUE;

    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &g_KswNetworkWfpRuntime.EngineHandle);
    g_KswNetworkWfpRuntime.EngineStatus = status;
    if (!NT_SUCCESS(status)) {
        degradeReason = KswSandboxNetworkStatusDegradeFwpmEngineOpen;
        goto Failure;
    }

    status = FwpmTransactionBegin0(g_KswNetworkWfpRuntime.EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        degradeReason = KswSandboxNetworkStatusDegradeFwpmTransaction;
        goto Failure;
    }
    transactionStarted = TRUE;

    status = KswNetworkAddSublayer(g_KswNetworkWfpRuntime.EngineHandle);
    if (!NT_SUCCESS(status)) {
        degradeReason = KswSandboxNetworkStatusDegradeFwpmSublayer;
        goto Failure;
    }

    for (index = 0; index < KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT; index++) {
        status = KswNetworkAddManagementCallout(
            g_KswNetworkWfpRuntime.EngineHandle,
            &g_KswNetworkAleBindings[index].CalloutKey,
            &g_KswNetworkAleBindings[index].LayerKey,
            g_KswNetworkAleBindings[index].CalloutDisplayName);
        if (!NT_SUCCESS(status)) {
            degradeReason =
                KswSandboxNetworkStatusDegradeFwpmManagementCallout;
            goto Failure;
        }
    }

    for (index = 0; index < KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT; index++) {
        PUINT64 filterIdSlot;

        filterIdSlot = KswNetworkFilterIdSlot(
            g_KswNetworkAleBindings[index].Id);
        if (filterIdSlot == NULL) {
            status = STATUS_INVALID_PARAMETER;
            degradeReason =
                KswSandboxNetworkStatusDegradeFwpmInspectionFilter;
            goto Failure;
        }

        status = KswNetworkAddInspectionFilter(
            g_KswNetworkWfpRuntime.EngineHandle,
            &g_KswNetworkAleBindings[index].FilterKey,
            &g_KswNetworkAleBindings[index].CalloutKey,
            &g_KswNetworkAleBindings[index].LayerKey,
            g_KswNetworkAleBindings[index].FilterDisplayName,
            filterIdSlot);
        if (!NT_SUCCESS(status)) {
            degradeReason =
                KswSandboxNetworkStatusDegradeFwpmInspectionFilter;
            goto Failure;
        }
    }

    status = FwpmTransactionCommit0(g_KswNetworkWfpRuntime.EngineHandle);
    transactionStarted = FALSE;
    if (!NT_SUCCESS(status)) {
        degradeReason = KswSandboxNetworkStatusDegradeFwpmTransaction;
        goto Failure;
    }

    InterlockedExchange(&g_KswNetworkWfpRuntime.Active, 1);
    KswNetworkRecordDegradeStatus(
        KswSandboxNetworkStatusDegradeNone,
        STATUS_SUCCESS);
    KswSetLastStatus(DeviceExtension, STATUS_SUCCESS);

    return STATUS_SUCCESS;

Failure:
    if (degradeReason == KswSandboxNetworkStatusDegradeNone) {
        degradeReason = KswSandboxNetworkStatusDegradeFwpmTransaction;
    }
    KswNetworkRecordDegradeStatus(degradeReason, status);

    if (transactionStarted &&
        g_KswNetworkWfpRuntime.EngineHandle != NULL) {
        (VOID)FwpmTransactionAbort0(g_KswNetworkWfpRuntime.EngineHandle);
    }

    KswNetworkDeleteManagementObjects();
    KswNetworkUnregisterFwpsCallouts();
    g_KswNetworkWfpRuntime.PayloadVersion = 0;
    InterlockedExchange(&g_KswNetworkWfpRuntime.Initialized, 0);
    g_KswNetworkWfpRuntime.DeviceExtension = NULL;
    g_KswNetworkWfpRuntime.DeviceObject = NULL;
    KswSetLastStatus(DeviceExtension, status);

    return status;
}

/*
 * Stops and unregisters the WFP/ALE network event producer.
 *
 * Inputs : none; uses the single static runtime initialized by DriverEntry.
 * Logic  : clears Active before deleting filters, removes FWPM management
 *          objects and closes the dynamic engine session, unregisters FWPS
 *          callouts, then drops pointers to the control device and ring.
 * Return : no return value.
 */
VOID
KswUninitializeNetworkMonitor(
    VOID
    )
{
    if (InterlockedExchange(
            &g_KswNetworkWfpRuntime.Uninitializing,
            1) != 0) {
        return;
    }

    InterlockedExchange(&g_KswNetworkWfpRuntime.Active, 0);
    KswNetworkDeleteManagementObjects();
    KswNetworkUnregisterFwpsCallouts();
    g_KswNetworkWfpRuntime.PayloadVersion = 0;
    InterlockedExchange(&g_KswNetworkWfpRuntime.Initialized, 0);
    g_KswNetworkWfpRuntime.DeviceExtension = NULL;
    g_KswNetworkWfpRuntime.DeviceObject = NULL;
    g_KswNetworkWfpRuntime.RegisterStatus = STATUS_NOT_SUPPORTED;
    g_KswNetworkWfpRuntime.EngineStatus = STATUS_NOT_SUPPORTED;
}

#else

/*
 * Explicit unsupported network producer build.
 *
 * Inputs : build-time KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE=0.
 * Logic  : do not register any WFP state and return STATUS_NOT_SUPPORTED so the
 *          core driver can keep the control device online while capabilities do
 *          not advertise the NETWORK producer bit.
 * Return : STATUS_NOT_SUPPORTED after preserving diagnostics in LastNtStatus.
 */
NTSTATUS
KswInitializeNetworkMonitor(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (DeviceExtension != NULL &&
        DeviceExtension->Signature == KSWORD_SANDBOX_DEVICE_EXTENSION_SIGNATURE) {
        KswSetLastStatus(DeviceExtension, STATUS_NOT_SUPPORTED);
    }

    return STATUS_NOT_SUPPORTED;
}

/*
 * No-op cleanup for explicit unsupported network producer builds.
 */
VOID
KswUninitializeNetworkMonitor(
    VOID
    )
{
}

#endif
