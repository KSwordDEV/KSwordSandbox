# KSwordSandbox 项目框架 / project framework

本仓库正在从单一扁平 prototype 扩展为多项目 Windows sandbox。目标是让各领域有足够清晰的边界，支持并行工作，同时减少后续 R0、Hyper-V、WebUI 和 reporting 改动争抢同一批文件。

English summary: the repository is a multi-project Windows sandbox with boundaries for parallel R0, Hyper-V, WebUI, and reporting work.

## 模块归属 / Module ownership

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

## 近期扩展规则 / Near-term expansion rules

1. Prefer new focused files over adding more responsibilities to existing
   large files.
2. Keep write ownership disjoint when multiple Codex threads run in parallel.
3. Do not commit runtime output, binaries, VM disks, reports, or samples.
4. Treat WebUI live telemetry as raw monitoring first; classification happens
   after final event import.
5. Keep the Hyper-V live path usable even when R0 driver signing or WDK setup
   is temporarily blocked.

## 建议拆分方向 / Suggested next split

- Web worker: endpoint groups, dashboard renderer, request/response contracts.
- Guest worker: modular probes and sidecar collector lifecycle.
- Hyper-V worker: live guest-output sync and job-specific guest output paths.
- R0 worker: WFP network producer integration and richer driver ABI.
- Reporting worker: section renderers and taxonomy-backed classification.
- Test worker: synthetic event fixtures and HTML/report assertions.
