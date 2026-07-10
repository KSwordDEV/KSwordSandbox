# KSwordSandbox progress snapshot

This snapshot is intentionally conservative. It measures distance to the
requested v1 deliverable: open WebUI, submit an EXE, run a Windows 10 Hyper-V
guest, see raw R0/guest events live, import events, classify behavior, and open
a final HTML report.

## Current estimated completion

- Overall v1 deliverable: **43%**
- Repository architecture, docs, module boundaries, policy: **82%**
- Core job/event/rule/report models: **68%**
- Web/API/WebUI submission and job UX: **60%**
- Live raw telemetry contract: **63%**
- Hyper-V runbook generation and execution recording: **55%**
- Golden VM / payload staging / operator readiness: **45%**
- Guest Agent dynamic collection: **52%**
- R0 Driver + R0Collector: **48%**
- Static analysis and behavior rules: **48%**
- HTML report generation: **58%**
- Artifact manifest and dropped-file plumbing: **45%**
- Tests and quality gates: **56%**
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

## Remaining P0 gaps

1. Run a real administrator Hyper-V end-to-end job against
   `KSwordSandbox-Win10-Golden` with checkpoint `Clean`.
2. Confirm guest credential flow via `KSWORDBOX_GUEST_PASSWORD` on the actual
   host session that runs the Web app.
3. Confirm PowerShell Direct / Guest Service copy latency is acceptable for live
   JSONL polling.
4. Load a signed or test-signed driver inside the guest and prove at least one
   real R0 event path, preferably process create or file minifilter.
5. Confirm WebUI live table remains responsive during a live run, then final
   import regenerates `report.json` and `report.html`.

## Next best work

- Finish R0 ABI/capability negotiation and typed payload parsing.
- Run the Hyper-V E2E PlanOnly/full-validation gates on the target host after
  each script change, then run the live mode only from an elevated test session.
- Add a harmless guest test executable and a repeatable live-run checklist.
- Add final report artifact links for `events.json`, `driver-events.jsonl`,
  screenshots, and dropped-file manifests.
- Run native build and full smoke after each R0/collector merge.
