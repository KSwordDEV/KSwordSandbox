#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winioctl.h>
#include <KSwordSandboxDriverIoctl.h>

#include <cstddef>

namespace KSword::Sandbox::R0Collector {

inline constexpr const char* kCollectorSource = "r0collector";
inline constexpr int kExitSuccess = 0;
inline constexpr int kExitInvalidArguments = 64;
inline constexpr int kExitOutputUnavailable = 65;
inline constexpr int kExitDeviceUnavailable = 66;
inline constexpr int kExitRuntimeFailure = 70;
inline constexpr DWORD kReadEventsBufferBytes = 64U * 1024U;
inline constexpr ULONG kReadEventsMaxEvents = 64U;
inline constexpr size_t kMaxPayloadHexBytes = 256U;
inline constexpr int kSyntheticStressSequenceStart = 1200;
inline constexpr int kSyntheticSemanticSequenceStart = 1100;
inline constexpr int kSyntheticSemanticSelfCheckRows = 6;
inline constexpr const char* kSyntheticSemanticSelfCheckScenarios =
    "process-lineage|dns|http|tls|lateral-movement|download-execute";
inline constexpr unsigned long kAbiSelfCheckDiagnosticsVersion = 2U;
inline constexpr const char* kStressJsonlLossEvidence =
    "lost|lostCount|lossObserved|TotalEventsDropped|totalEventsDropped|EventsDropped|eventsDropped|ProducerDroppedMask|producerDroppedMask|NextSequence|nextSequence|sequence|sequenceGapObserved|sequenceGapEstimate|head|tail|loss";
inline constexpr const char* kStressJsonlBackpressureEvidence =
    "backpressure|backpressureObserved|highWatermark|QueueCapacity|queueCapacity|QueueHighWatermark|queueHighWatermark|TotalEventsBackpressured|totalEventsBackpressured|ProducerBackpressureMask|producerBackpressureMask|lastEnqueueFailureStatus|drainStoppedAtBatchLimit|requestedMaxEvents|readEventsMaxEvents|maxReadBatches|sampling";
inline constexpr const char* kNetworkProtocolBoundaryFields =
    "protocolPayloadParsed|protocolParserSource|protocolPayloadSource|networkProtocolParserBoundary|networkProtocolBoundaryFields|pcapCorrelationRequired|pcapCorrelationStatus|pcapFlowKeyCandidate|pcapCorrelationKey|pcapCorrelationKeySource|pcapExpectedRecordTypes|pcapBoundaryPolicy|pcapDnsDetailsAvailable|pcapHttpDetailsAvailable|pcapTlsDetailsAvailable|dnsQueryNameAvailable|dnsQueryNameSource|dnsBoundary|httpHostAvailable|httpUriAvailable|httpMethodAvailable|httpMetadataSource|httpBoundary|tlsSniAvailable|tlsCertificateAvailable|tlsMetadataSource|tlsBoundary|networkCorrelationContractVersion|networkCorrelationRole|pcapCorrelationRole|pcapCorrelationJoinFields|pcapCorrelationMissingFields|pcapCorrelationConfidence|dnsCorrelationRecordType|httpCorrelationRecordType|tlsCorrelationRecordType|dnsDetailsOwner|httpDetailsOwner|tlsDetailsOwner|l7ProtocolDetailsAvailable|l7ProtocolDetailsOwner|r0ProtocolParserGuarantee|protocolBoundaryVerdict|zhPcapCorrelationHint|zhNetworkBoundaryHint|zhDnsCorrelationHint|zhHttpCorrelationHint|zhTlsCorrelationHint";
inline constexpr const char* kNetworkCorrelationStableFields =
    "networkCorrelationContractVersion|networkCorrelationRole|pcapCorrelationRole|pcapCorrelationJoinFields|pcapCorrelationMissingFields|pcapCorrelationConfidence|dnsCorrelationRecordType|httpCorrelationRecordType|tlsCorrelationRecordType|dnsDetailsOwner|httpDetailsOwner|tlsDetailsOwner|l7ProtocolDetailsAvailable|l7ProtocolDetailsOwner|r0ProtocolParserGuarantee|protocolBoundaryVerdict|zhPcapCorrelationHint|zhNetworkBoundaryHint|zhDnsCorrelationHint|zhHttpCorrelationHint|zhTlsCorrelationHint";
inline constexpr const char* kJsonlNoiseFieldSet =
    "noise|noiseScope|noiseKind|noiseSource|noiseClass|selfNoiseClass|collectorNoiseClass|noiseAction|noiseDisposition|noiseReasons|noiseTaxonomyVersion|noiseDecision|noiseDecisionSource|noiseClassificationConfidence|noiseProbeKind|sampleBehaviorCandidate|sampleBehaviorCandidateReason|collectionDiagnostic|collectionNoise|operatorInterpretation|zhNoiseHint|zhNoiseClassificationHint|zhOperatorHint";
inline constexpr const char* kJsonlNoiseClassificationFields =
    "noiseTaxonomyVersion|noiseDecision|noiseDecisionSource|noiseClassificationConfidence|noiseProbeKind|sampleBehaviorCandidateReason|zhNoiseClassificationHint";

// Collector-side ABI guard constants. These mirror the public driver ABI offsets
// that release/readiness diagnostics depend on. Keep them in the collector so
// --abi-self-check can prove the binary was built against the expected header
// before any live driver handle is opened.
inline constexpr size_t kAbiGuardEventHeaderSequenceOffset = offsetof(KSWORD_SANDBOX_EVENT_HEADER, Sequence);
inline constexpr size_t kAbiGuardEventHeaderLostEventsOffset = offsetof(KSWORD_SANDBOX_EVENT_HEADER, LostEvents);
inline constexpr size_t kAbiGuardEventHeaderBackpressureEventsOffset = offsetof(KSWORD_SANDBOX_EVENT_HEADER, BackpressureEvents);
inline constexpr size_t kAbiGuardEventHeaderOperationOffset = offsetof(KSWORD_SANDBOX_EVENT_HEADER, Operation);
inline constexpr size_t kAbiGuardEventHeaderStatusOffset = offsetof(KSWORD_SANDBOX_EVENT_HEADER, Status);
inline constexpr size_t kAbiGuardEventHeaderProducerMetadataFlagsOffset = offsetof(KSWORD_SANDBOX_EVENT_HEADER, ProducerMetadataFlags);
inline constexpr size_t kAbiGuardStatusQueueHighWatermarkOffset = offsetof(KSWORD_SANDBOX_STATUS_REPLY, QueueHighWatermark);
inline constexpr size_t kAbiGuardStatusTotalEventsDroppedOffset = offsetof(KSWORD_SANDBOX_STATUS_REPLY, TotalEventsDropped);
inline constexpr size_t kAbiGuardStatusTotalEventsBackpressuredOffset = offsetof(KSWORD_SANDBOX_STATUS_REPLY, TotalEventsBackpressured);
inline constexpr size_t kAbiGuardStatusLastEnqueueFailureOffset = offsetof(KSWORD_SANDBOX_STATUS_REPLY, LastEnqueueFailureNtStatus);
inline constexpr size_t kAbiGuardReadEventsEventsDroppedOffset = offsetof(KSWORD_SANDBOX_READ_EVENTS_REPLY, EventsDropped);
inline constexpr size_t kAbiGuardReadEventsEventsOffset = offsetof(KSWORD_SANDBOX_READ_EVENTS_REPLY, Events);
inline constexpr size_t kAbiGuardNetworkStatusTodoMaskOffset = offsetof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY, TodoMask);
inline constexpr size_t kAbiGuardNetworkStatusPayloadVersionOffset = offsetof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY, PayloadVersion);
inline constexpr size_t kAbiGuardNetworkStatusLastDegradeReasonOffset = offsetof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY, LastDegradeReason);
inline constexpr size_t kAbiGuardNetworkStatusClassifyCountOffset = offsetof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY, ClassifyCount);
inline constexpr size_t kAbiGuardNetworkStatusEventCountOffset = offsetof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY, EventCount);
inline constexpr size_t kAbiGuardNetworkStatusQueueFailureCountOffset = offsetof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY, QueueFailureCount);
inline constexpr size_t kAbiGuardNetworkStatusLastQueueFailureOffset = offsetof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY, LastQueueFailureNtStatus);

static_assert(sizeof(KSWORD_SANDBOX_EVENT_HEADER) == 104U,
    "KSWORD_SANDBOX_EVENT_HEADER size changed; update R0Collector ABI diagnostics and tests.");
static_assert(kAbiGuardEventHeaderSequenceOffset == 16U,
    "KSWORD_SANDBOX_EVENT_HEADER.Sequence offset changed.");
static_assert(kAbiGuardEventHeaderLostEventsOffset == 64U,
    "KSWORD_SANDBOX_EVENT_HEADER.LostEvents offset changed.");
static_assert(kAbiGuardEventHeaderBackpressureEventsOffset == 72U,
    "KSWORD_SANDBOX_EVENT_HEADER.BackpressureEvents offset changed.");
static_assert(kAbiGuardEventHeaderOperationOffset == 80U,
    "KSWORD_SANDBOX_EVENT_HEADER.Operation offset changed.");
static_assert(kAbiGuardEventHeaderStatusOffset == 84U,
    "KSWORD_SANDBOX_EVENT_HEADER.Status offset changed.");
static_assert(kAbiGuardEventHeaderProducerMetadataFlagsOffset == 92U,
    "KSWORD_SANDBOX_EVENT_HEADER.ProducerMetadataFlags offset changed.");
static_assert(kAbiGuardStatusQueueHighWatermarkOffset == 24U,
    "KSWORD_SANDBOX_STATUS_REPLY.QueueHighWatermark offset changed.");
static_assert(kAbiGuardStatusTotalEventsDroppedOffset == 56U,
    "KSWORD_SANDBOX_STATUS_REPLY.TotalEventsDropped offset changed.");
static_assert(kAbiGuardStatusTotalEventsBackpressuredOffset == 88U,
    "KSWORD_SANDBOX_STATUS_REPLY.TotalEventsBackpressured offset changed.");
static_assert(kAbiGuardStatusLastEnqueueFailureOffset == 112U,
    "KSWORD_SANDBOX_STATUS_REPLY.LastEnqueueFailureNtStatus offset changed.");
static_assert(kAbiGuardReadEventsEventsDroppedOffset == 24U,
    "KSWORD_SANDBOX_READ_EVENTS_REPLY.EventsDropped offset changed.");
static_assert(kAbiGuardReadEventsEventsOffset == KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE,
    "KSWORD_SANDBOX_READ_EVENTS_REPLY_HEADER_SIZE must point at Events.");
static_assert(sizeof(KSWORD_SANDBOX_NETWORK_STATUS_REPLY) == 128U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY size changed; update R0Collector network diagnostics and tests.");
static_assert(kAbiGuardNetworkStatusTodoMaskOffset == 32U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY.TodoMask offset changed.");
static_assert(kAbiGuardNetworkStatusPayloadVersionOffset == 36U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY.PayloadVersion offset changed.");
static_assert(kAbiGuardNetworkStatusLastDegradeReasonOffset == 40U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY.LastDegradeReason offset changed.");
static_assert(kAbiGuardNetworkStatusClassifyCountOffset == 56U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY.ClassifyCount offset changed.");
static_assert(kAbiGuardNetworkStatusEventCountOffset == 64U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY.EventCount offset changed.");
static_assert(kAbiGuardNetworkStatusQueueFailureCountOffset == 72U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY.QueueFailureCount offset changed.");
static_assert(kAbiGuardNetworkStatusLastQueueFailureOffset == 92U,
    "KSWORD_SANDBOX_NETWORK_STATUS_REPLY.LastQueueFailureNtStatus offset changed.");

// GET_HEALTH producer masks were added in ABI-reserved space.  Keep accepting
// legacy replies that only contain the stable prefix through LastNtStatus, and
// treat producer mask values as available only when the driver advertises the
// health flag and returns the mask field bytes.
inline constexpr size_t kHealthReplyLegacyMinimumBytes = offsetof(KSWORD_SANDBOX_HEALTH_REPLY, ProducerEnableMask);
inline constexpr size_t kHealthReplyProducerMaskBytes =
    offsetof(KSWORD_SANDBOX_HEALTH_REPLY, FailedProducerMask) + sizeof(ULONG);

static_assert(kHealthReplyLegacyMinimumBytes >= offsetof(KSWORD_SANDBOX_HEALTH_REPLY, LastNtStatus) + sizeof(LONG),
    "GET_HEALTH legacy prefix must include LastNtStatus.");
static_assert(kHealthReplyProducerMaskBytes <= sizeof(KSWORD_SANDBOX_HEALTH_REPLY),
    "GET_HEALTH producer mask fields must fit in the public reply.");

} // namespace KSword::Sandbox::R0Collector
