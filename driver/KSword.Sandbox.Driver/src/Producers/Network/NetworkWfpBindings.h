#pragma once

#include "Producers/Network/NetworkInternal.h"

/*
 * Compile-time WFP contract checks for the current ALE-only producer.
 *
 * Inputs : WDK WFP headers must be included before this file.
 * Logic  : reference every ALE layer/field and WFP action used by the producer
 *          so unsupported header sets fail at build time instead of degrading
 *          into a runtime no-op that looks implemented.
 * Return : no runtime value.
 */
C_ASSERT(FWPS_LAYER_ALE_AUTH_CONNECT_V4 >= 0);
C_ASSERT(FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 >= 0);
C_ASSERT(FWPS_LAYER_ALE_AUTH_CONNECT_V6 >= 0);
C_ASSERT(FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6 >= 0);
C_ASSERT(FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL >= 0);
C_ASSERT(FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL >= 0);
C_ASSERT(FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL >= 0);
C_ASSERT(FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL >= 0);
C_ASSERT(FWP_ACTION_CALLOUT_INSPECTION != 0);
C_ASSERT(FWP_ACTION_CONTINUE >= 0);
C_ASSERT(FWPM_SESSION_FLAG_DYNAMIC != 0);

/*
 * Local binding identifiers for the four ALE layers implemented today.
 *
 * Inputs : used as stable keys when mapping descriptor table rows to runtime
 *          callout/filter id slots.
 * Logic  : avoids hand-written registration and cleanup blocks for every layer
 *          while keeping the implementation honest about its limited WFP scope.
 * Return : not applicable.
 */
typedef enum _KSWORD_SANDBOX_NETWORK_ALE_BINDING_ID {
    KswNetworkAleBindingConnectV4 = 0,
    KswNetworkAleBindingRecvAcceptV4 = 1,
    KswNetworkAleBindingConnectV6 = 2,
    KswNetworkAleBindingRecvAcceptV6 = 3
} KSWORD_SANDBOX_NETWORK_ALE_BINDING_ID;

typedef struct _KSWORD_SANDBOX_NETWORK_ALE_BINDING {
    KSWORD_SANDBOX_NETWORK_ALE_BINDING_ID Id;
    UINT16 LayerId;
    GUID LayerKey;
    GUID CalloutKey;
    GUID FilterKey;
    PWSTR CalloutDisplayName;
    PWSTR FilterDisplayName;
} KSWORD_SANDBOX_NETWORK_ALE_BINDING,
    *PKSWORD_SANDBOX_NETWORK_ALE_BINDING;

#define KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT 4U

/*
 * WFP layer and object GUIDs used by the dynamic ALE event producer.
 *
 * Inputs : consumed by FWPS/FWPM registration helpers.
 * Logic  : standard layer GUID values are stored locally to avoid relying on
 *          GUID object instantiation from WDK headers; KSword-owned GUIDs name
 *          this driver's dynamic sublayer, callouts, and filters.
 * Return : not applicable; WFP copies these values during registration.
 */
static const GUID g_KswNetworkWfpSublayer = {
    0x045d9f2c, 0xd8d7, 0x4e8a,
    { 0xa1, 0xe4, 0x05, 0x32, 0xfd, 0x03, 0xde, 0x69 }
};

static const KSWORD_SANDBOX_NETWORK_ALE_BINDING g_KswNetworkAleBindings[
    KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT] = {
    {
        KswNetworkAleBindingConnectV4,
        FWPS_LAYER_ALE_AUTH_CONNECT_V4,
        {
            0xc38d57d1, 0x05a7, 0x4c33,
            { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 }
        },
        {
            0x64f03ec7, 0x7b29, 0x453b,
            { 0x8c, 0xac, 0x34, 0xa8, 0xf5, 0x4e, 0xa4, 0xa1 }
        },
        {
            0xf2b09803, 0x0c2c, 0x4269,
            { 0x9d, 0xc0, 0x16, 0xec, 0xc7, 0x9a, 0xb7, 0x21 }
        },
        L"KSword Sandbox ALE connect IPv4 event callout",
        L"KSword Sandbox ALE connect IPv4 event filter"
    },
    {
        KswNetworkAleBindingRecvAcceptV4,
        FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        {
            0xe1cd9fe7, 0xf4b5, 0x4273,
            { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 }
        },
        {
            0xbcef729c, 0xf07a, 0x4db4,
            { 0x89, 0x31, 0x54, 0x99, 0xc0, 0xb8, 0x9e, 0x8f }
        },
        {
            0xc32d15b2, 0xc38a, 0x4bd5,
            { 0xb0, 0xa6, 0xdf, 0x5a, 0x61, 0xce, 0x4b, 0xd4 }
        },
        L"KSword Sandbox ALE recv-accept IPv4 event callout",
        L"KSword Sandbox ALE recv-accept IPv4 event filter"
    },
    {
        KswNetworkAleBindingConnectV6,
        FWPS_LAYER_ALE_AUTH_CONNECT_V6,
        {
            0x4a72393b, 0x319f, 0x44bc,
            { 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4 }
        },
        {
            0x633b5a9d, 0x14bd, 0x42b5,
            { 0xa3, 0x5d, 0x21, 0xa8, 0x7e, 0xeb, 0xb4, 0xa8 }
        },
        {
            0x235ba9d5, 0xecb0, 0x441f,
            { 0xbe, 0x23, 0xe7, 0x96, 0xbe, 0xe0, 0x55, 0x71 }
        },
        L"KSword Sandbox ALE connect IPv6 event callout",
        L"KSword Sandbox ALE connect IPv6 event filter"
    },
    {
        KswNetworkAleBindingRecvAcceptV6,
        FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        {
            0xa3b42c97, 0x9f04, 0x4672,
            { 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f }
        },
        {
            0x1295009b, 0xb5b5, 0x4d9d,
            { 0xbd, 0x13, 0x14, 0x80, 0x91, 0xdd, 0x39, 0xf2 }
        },
        {
            0xcbb030e9, 0x912f, 0x4b6e,
            { 0x89, 0x03, 0x1b, 0xd2, 0xca, 0x92, 0x13, 0x15 }
        },
        L"KSword Sandbox ALE recv-accept IPv6 event callout",
        L"KSword Sandbox ALE recv-accept IPv6 event filter"
    }
};

C_ASSERT(RTL_NUMBER_OF(g_KswNetworkAleBindings) ==
    KSWORD_SANDBOX_NETWORK_ALE_BINDING_COUNT);
