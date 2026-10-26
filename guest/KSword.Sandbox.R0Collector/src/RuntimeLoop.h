#pragma once

#include "IoctlClient.h"
#include "JsonWriter.h"
#include "Options.h"

namespace KSword::Sandbox::R0Collector {

int RunCollector(int argc, wchar_t* argv[]);

// Handles an intentional cumulative-output-budget stop: the JSONL sink is
// already finalized and closed, so this only issues one best-effort final
// GET_STATUS and records the authoritative remaining queue depth in the
// r0-status sidecar. Returns kExitSuccess so the supervisor sees a clean
// stop that is semantically distinct from an output-write failure.
int FinishBudgetStop(
    const UniqueHandle& device,
    const Options& options,
    EventWriter& writer);

} // namespace KSword::Sandbox::R0Collector
