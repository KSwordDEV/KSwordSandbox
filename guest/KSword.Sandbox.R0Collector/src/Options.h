#pragma once

#include "Common.h"

#include <string>

namespace KSword::Sandbox::R0Collector {

struct Options {
    std::wstring devicePath = LR"(\\.\KSwordSandboxDriver)";
    std::wstring serviceName = L"KSwordSandboxDriver";
    std::wstring outputPath = L"-";
    int durationSeconds = 0;
    int pollIntervalMs = 500;
    int diagnoseReadTimeoutMs = 2000;
    int maxReadBatches = 0;
    unsigned long readEventsMaxEvents = kReadEventsMaxEvents;
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
