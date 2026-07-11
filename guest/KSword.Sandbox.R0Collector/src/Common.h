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
