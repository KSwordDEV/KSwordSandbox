# KSwordSandbox project framework

This repository is being expanded as a multi-project Windows sandbox rather
than a single flat prototype. The intent is to keep each domain large enough to
accept parallel work without making later R0, Hyper-V, WebUI, and reporting
changes fight over the same files.

## Module ownership

- `src/KSword.Sandbox.Abstractions`: stable contracts shared by host, guest,
  tests, and report tooling.
- `src/KSword.Sandbox.Core`: host-side orchestration, artifact storage,
  telemetry import, rule classification, report generation, scheduling, and
  Hyper-V planning.
- `src/KSword.Sandbox.Web`: local WebUI and HTTP API. Large inline dashboard
  logic should be split into endpoint, contract, and dashboard modules.
- `guest/KSword.Sandbox.Agent`: guest-side sample execution and user-mode
  observations. The current single-file agent should be decomposed into
  collection, execution, output, options, and diagnostics modules.
- `guest/KSword.Sandbox.R0Collector`: user-mode bridge from the R0 driver to
  JSONL events.
- `driver/KSword.Sandbox.Driver`: kernel producer stack for process, image,
  file, registry, and network events.
- `tests/KSword.Sandbox.SmokeTests`: scenario-based verification for build,
  synthetic events, report content, and repository policy.

## Near-term expansion rules

1. Prefer new focused files over adding more responsibilities to existing
   large files.
2. Keep write ownership disjoint when multiple Codex threads run in parallel.
3. Do not commit runtime output, binaries, VM disks, reports, or samples.
4. Treat WebUI live telemetry as raw monitoring first; classification happens
   after final event import.
5. Keep the Hyper-V live path usable even when R0 driver signing or WDK setup
   is temporarily blocked.

## Suggested next split

- Web worker: endpoint groups, dashboard renderer, request/response contracts.
- Guest worker: modular probes and sidecar collector lifecycle.
- Hyper-V worker: live guest-output sync and job-specific guest output paths.
- R0 worker: WFP network producer integration and richer driver ABI.
- Reporting worker: section renderers and taxonomy-backed classification.
- Test worker: synthetic event fixtures and HTML/report assertions.
