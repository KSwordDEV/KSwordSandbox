#pragma once

#include "Producers/Network/NetworkMonitor.h"

/*
 * Network producer implementation switches and ABI guardrails.
 *
 * Inputs : Driver.h defines KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE before this
 *          header is included by the single NetworkMonitor.c translation unit.
 * Logic  : keep the compile-time switch explicitly boolean so lab builds can
 *          choose "unsupported" without accidentally compiling a partial WFP
 *          path, and pin the current v1 network payload size/field offsets
 *          separately from the future draft extension.
 * Return : no runtime value; invalid configurations fail the driver build.
 */
#if !defined(KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE)
#error KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE must be defined by Driver.h.
#endif

#if KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE != 0 && \
    KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE != 1
#error KSWORD_SANDBOX_ENABLE_NETWORK_WFP_ALE must be 0 or 1.
#endif

#define KSWORD_SANDBOX_NETWORK_WFP_IMPLEMENTATION_ALE_INSPECT_ONLY 1U
#define KSWORD_SANDBOX_NETWORK_WFP_TODO_FULL_PACKET_LAYERS 1U
#define KSWORD_SANDBOX_NETWORK_WFP_TODO_FLOW_CONTEXTS 1U
#define KSWORD_SANDBOX_NETWORK_WFP_TODO_FILTER_CONDITIONS 1U

C_ASSERT(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD) == 112U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD, FlowHandle) == 80U);
C_ASSERT(FIELD_OFFSET(
    KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD,
    TransportEndpointHandle) == 88U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD, FilterId) == 96U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD, Operation) == 104U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD, Status) == 108U);
C_ASSERT(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD_V2_DRAFT) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
C_ASSERT(FIELD_OFFSET(
    KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD_V2_DRAFT,
    StatusDegradeReason) == 112U);

/*
 * Runtime state for the WFP/ALE network event producer.
 *
 * Inputs : initialized by KswInitializeNetworkMonitor after the control device
 *          and event ring exist.
 * Logic  : stores dynamic FWPM engine state, FWPS callout ids, filter ids, the
 *          shared READ_EVENTS ring owner, initialized/teardown guards, and v1
 *          payload version.  LastDegradeReason/Status are internal diagnostics only;
 *          GET_STATUS still exposes only producer masks and NTSTATUS values
 *          until the draft payload/status ABI is promoted.
 * Return : no direct return value; KswInitializeNetworkMonitor exposes setup
 *          failures and KswPushEvent carries telemetry to user mode.
 */
typedef struct _KSWORD_SANDBOX_NETWORK_WFP_RUNTIME {
    PDEVICE_OBJECT DeviceObject;
    PKSWORD_SANDBOX_DEVICE_EXTENSION DeviceExtension;
    HANDLE EngineHandle;
    volatile LONG Active;
    volatile LONG Initialized;
    volatile LONG Uninitializing;
    ULONG PayloadVersion;
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
    volatile LONG LastDegradeReason;
    volatile LONG LastDegradeStatus;
    volatile LONG64 ClassifyCount;
    volatile LONG64 EventCount;
} KSWORD_SANDBOX_NETWORK_WFP_RUNTIME, *PKSWORD_SANDBOX_NETWORK_WFP_RUNTIME;
