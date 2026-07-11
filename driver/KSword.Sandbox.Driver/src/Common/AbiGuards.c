#include "Driver.h"

/*
 * Guards fixed-size IOCTL replies that have historically been consumed by
 * user-mode collectors.
 * Inputs : public reply layouts from KSwordSandboxDriverIoctl.h.
 * Logic  : C_ASSERT pins the v1.0 GET_HEALTH size and producer-mask offsets so
 *          additions can safely reuse reserved space without silently changing
 *          the METHOD_BUFFERED ABI.
 * Return : no runtime value; build fails if the layout drifts.
 */
C_ASSERT(sizeof(KSWORD_SANDBOX_HEALTH_REPLY) == 80U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_HEALTH_REPLY, ProducerEnableMask) == 44U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_HEALTH_REPLY, SupportedProducerMask) == 48U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_HEALTH_REPLY, ActiveProducerMask) == 52U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_HEALTH_REPLY, FailedProducerMask) == 56U);
C_ASSERT(sizeof(KSWORD_SANDBOX_STATUS_REPLY) == 120U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, LastNtStatus) == 36U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, ActiveProducerMask) == 40U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, FailedProducerMask) == 44U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, ProducerDroppedMask) == 96U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, ProducerSuppressedMask) == 100U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, ProducerBackpressureMask) == 104U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, EffectiveProducerMask) == 108U);
C_ASSERT(FIELD_OFFSET(KSWORD_SANDBOX_STATUS_REPLY, LastFailureNtStatus) == 112U);

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

C_ASSERT(sizeof(KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD) == 48U);
C_ASSERT(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD) == 128U);
C_ASSERT(sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD) == 128U);
C_ASSERT(sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD) == 128U);
C_ASSERT(sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD) == 128U);
C_ASSERT(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD) == 112U);
