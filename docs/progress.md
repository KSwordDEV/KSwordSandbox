# KSwordSandbox progress snapshot

This snapshot is intentionally conservative. It measures distance to the
requested v1 deliverable: open WebUI, submit an EXE, run a Windows 10 Hyper-V
guest, see raw R0/guest events live, import events, classify behavior, and open
a final HTML report.

## Current estimated completion

- Overall v1 deliverable: **56%**
- Minimum usable E2E chain on this host: **72%**
- Repository architecture, docs, module boundaries, policy: **82%**
- Core job/event/rule/report models: **68%**
- Web/API/WebUI submission and job UX: **66%**
- Live raw telemetry contract: **70%**
- Hyper-V runbook generation and execution recording: **66%**
- Golden VM / payload staging / operator readiness: **58%**
- Guest Agent dynamic collection: **60%**
- R0 Driver + R0Collector: **56%**
- Static analysis and behavior rules: **48%**
- HTML report generation: **62%**
- Artifact manifest and dropped-file plumbing: **45%**
- Tests and quality gates: **62%**
- Install/operations/security hardening: **32%**

## Evidence already present

- Host Web project can plan jobs, execute dry-run/live runbooks, persist
  runbook execution records, import guest event files, and serve live event
  snapshots/SSE.
- Guest Agent can emit normalized events and can merge R0Collector JSONL into
  guest output.
- R0 driver project is in the main solution and has control-device, ring-buffer,
  health/poll/read-events, process/image, file, registry, and WFP source paths.
- R0Collector builds as a native x64 console application and emits
  `SandboxEvent`-compatible JSONL in mock and driver modes.
- Report renderer has cloud-sandbox-style sections for risk, behavior, MITRE,
  static, dynamic, process, file, registry, network, failures, and raw events.
- Repository policy blocks VM disks, binaries, samples, reports, keys, and build
  outputs.
- Smoke validation now has a P0/P1 gate that checks WebUI live endpoint shape,
  guest `events.json` plus `driver-events.jsonl` import, Hyper-V script safety,
  R0 driver/collector file and ABI strings, report sections, and repo policy.
- `Invoke-FullValidation.ps1` now runs the live-telemetry contract script and a
  non-mutating Hyper-V `PlanOnly`/`WhatIf` plan check before native/readiness
  gates.
- Smoke validation now enforces the harmless-sample contract for
  `KSword.Sandbox.HarmlessSample`: the source project and
  `Prepare-HarmlessSample.ps1` exist, generated `.exe`/`.dll`/`.bin` and
  `bin`/`obj` outputs must stay out of git, and the Hyper-V E2E runbook explains
  how to publish it outside the repository before `-Live`.
- `Invoke-LocalPipelineSmoke.ps1` now covers the host-side minimal chain:
  Web API health, directory scan, job plan, dry-run runbook execution,
  `runbook-execution.json`, synthetic guest `events.json`,
  synthetic `driver-events.jsonl`, live raw-event endpoint, guest import, and
  final `report.html`.
- `Invoke-FullValidation.ps1` includes the local WebUI/API pipeline smoke by
  default, so the runnable host-side MVP path is part of the standard gate.
- A real WebUI/API + Hyper-V + test-signed R0 validation has completed on the
  local prepared VM. Evidence is recorded in `docs/webui-real-r0-e2e.md`:
  `fe0db7cb-df74-444b-897e-50c9f5a27d4d` completed 17/17 runbook steps,
  imported guest events, served default/zh/en HTML reports, and exposed 522
  live raw events without calling `CSignTool.exe`.
- The reusable `scripts/Invoke-WebUIApiE2E.ps1` gate now covers the WebUI API
  path. Its default mode is dry-run and safe; `-Live` is required before any VM
  mutation.

## Remaining P0 gaps

1. Turn the currently single-job/single-golden-VM flow into an operator-safe
   packaged experience: clearer install/run checks, better failure recovery, and
   one-click defaults that do not require reading runbook internals.
2. Replace the estimated WebUI progress bar with exact per-step executor
   telemetry while the long live request is still running.
3. Harden the real R0 path beyond the successful smoke: ABI versioning,
   backpressure, producer-specific stress tests, unload/reload reliability, and
   better event filtering.
4. Reduce final report size and improve raw-event evidence pagination/collapse.
5. Add dropped-file extraction, hashing, artifact manifests, screenshots, and
   optional PCAP/memory artifacts to the report pipeline.
6. Move from single golden VM restore to safer temporary VM or differencing-disk
   isolation before any broader sample testing.

## Next best work

- Finish R0 ABI/capability negotiation and typed payload parsing.
- Run the Hyper-V E2E PlanOnly/full-validation gates on the target host after
  each script change, then run the live mode only from an elevated test session.
- Use `Prepare-HarmlessSample.ps1` and the runbook checklist to build the
  executable outside git for live Hyper-V validation.
- Add final report artifact links for `events.json`, `driver-events.jsonl`,
  screenshots, and dropped-file manifests.
- Run native build and full smoke after each R0/collector merge.
