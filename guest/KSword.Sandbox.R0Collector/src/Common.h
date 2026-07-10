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

} // namespace KSword::Sandbox::R0Collector
