#pragma once

#include "JsonWriter.h"
#include "Options.h"

namespace KSword::Sandbox::R0Collector {

bool EmitAbiSelfCheck(EventWriter& writer, const Options& options);
int RunAbiSelfCheckMode(const Options& options, EventWriter& writer);

} // namespace KSword::Sandbox::R0Collector
