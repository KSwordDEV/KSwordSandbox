#include "RuntimeLoop.h"

// Input: Windows Unicode process arguments.
// Processing: Parses collector options, opens the output JSONL sink, optionally
// opens the driver device, and emits SandboxEvent-compatible lifecycle/error rows.
// Return: Conventional process exit code; nonzero values distinguish argument,
// output, device-open, and runtime failures.
int wmain(int argc, wchar_t* argv[]) {
    return KSword::Sandbox::R0Collector::RunCollector(argc, argv);
}
