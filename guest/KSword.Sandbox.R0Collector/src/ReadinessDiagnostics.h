#pragma once

#include "JsonWriter.h"
#include "Options.h"

namespace KSword::Sandbox::R0Collector {

bool EmitDeviceUnavailableDiagnostic(
    EventWriter& writer,
    const Options& options,
    DWORD openError,
    const std::string& diagnosticStage);

int RunReadinessDiagnoseMode(const Options& options, EventWriter& writer);

} // namespace KSword::Sandbox::R0Collector
