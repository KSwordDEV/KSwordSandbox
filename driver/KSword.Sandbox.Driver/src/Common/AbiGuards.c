#include "Driver.h"

/*
 * Verifies that every public producer payload fits the READ_EVENTS contract.
 * Inputs : compile-time structure definitions from KSwordSandboxDriverIoctl.h.
 * Logic  : C_ASSERT fails the WDK build if a future field expansion exceeds the
 *          fixed event payload capacity consumed by user-mode R0Collector.
 * Return : no runtime value; this translation unit exists for build-time ABI
 *          enforcement only.
 */
C_ASSERT(sizeof(KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
C_ASSERT(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
C_ASSERT(sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
C_ASSERT(sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
C_ASSERT(sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
C_ASSERT(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD) <=
    KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE);
