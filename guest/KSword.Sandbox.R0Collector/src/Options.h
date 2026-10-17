#pragma once

#include "Common.h"

#include <string>

namespace KSword::Sandbox::R0Collector {

struct Options {
    std::wstring devicePath = LR"(\\.\KSwordSandboxDriver)";
    std::wstring serviceName = L"KSwordSandboxDriver";
    std::wstring outputPath = L"-";
    int durationSeconds = 0;
    // Once a timed collection window ends, keep draining the kernel ring for
    // this bounded grace period. A finite grace period makes the end-of-run
    // loss observable instead of silently abandoning records already queued.
    // High-volume samples can leave hundreds of thousands of records queued
    // at the capture deadline. The default is intentionally long enough to
    // drain that backlog on the normal collector path; operators can lower it
    // explicitly when a hard run-time cap is preferred.
    int drainGraceMs = 120000;
    // Rotate high-volume JSONL before the file system/CRT write boundary.
    // Zero disables rotation for low-level diagnostics.
    unsigned long long maxOutputBytes = 256ULL * 1024ULL * 1024ULL;
    // Keep the live ring drain responsive during guest boot and sample launch.
    // The producer queue is finite; a 500 ms default lets file/registry
    // startup bursts overwrite records before the first drain. Operators can
    // still override this with --poll-ms for low-rate or stress runs.
    int pollIntervalMs = 10;
    int diagnoseReadTimeoutMs = 2000;
    int maxReadBatches = 0;
    unsigned long readEventsMaxEvents = kReadEventsMaxEvents;
    unsigned long driverEventSampleStride = 1;
    unsigned long enableMask = 0;
    int stressCount = 0;
    bool enableMaskSpecified = false;
    bool abiSelfCheck = false;
    bool diagnose = false;
    bool mockMode = false;
    bool injectJsonlNoise = false;
    bool healthOnly = false;
    bool heartbeat = false;
    bool suppressSelfNoise = true;
    bool showHelp = false;
};

bool ParseArguments(int argc, wchar_t* argv[], Options* options, std::wstring* error);
void PrintUsage(const wchar_t* programName);

} // namespace KSword::Sandbox::R0Collector
