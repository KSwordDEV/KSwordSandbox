# KSwordSandbox progress snapshot

This snapshot is intentionally conservative. It measures distance to the
requested v1 deliverable: open WebUI, submit an EXE, run a Windows 10 Hyper-V
guest, see raw R0/guest events live, import events, classify behavior, and open
a final HTML report.

## Current estimated completion

- Overall v1 deliverable: **60%**
- Minimum usable E2E chain on this host: **75%**
- Repository architecture, docs, module boundaries, policy: **82%**
- Core job/event/rule/report models: **70%**
- Web/API/WebUI submission and job UX: **73%**
- Live raw telemetry contract: **78%**
- Hyper-V runbook generation and execution recording: **69%**
- Golden VM / payload staging / operator readiness: **58%**
- Guest Agent dynamic collection: **67%**
- R0 Driver + R0Collector: **56%**
- Static analysis and behavior rules: **58%**
- HTML report generation: **70%**
- Artifact manifest and dropped-file plumbing: **58%**
- Tests and quality gates: **68%**
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
- WebUI runbook execution now emits real UI-safe
  `SandboxRunbookProgressSnapshot` updates through the executor `ProgressSink`.
  `GET /api/jobs/{jobId}/runbook/progress` exposes the latest per-step state
  while `/runbook/execute` is still running, without exposing PowerShell
  commands, stdout, or stderr on the main dashboard.
- The upload flow is now closer to one-click operation: after an `.exe` upload
  is stored and planned, the dashboard automatically starts live VM analysis
  and switches the progress panel to exact runbook step state.
- Final HTML reports no longer inline every raw event by default. Raw evidence
  is collapsed in a bounded scroll panel, capped to the first 200 inline rows,
  and the report shows complete source hints for `report.json`, `events.json`,
  `driver-events.jsonl`, and artifact manifests.
- Behavior rules have been expanded to 153 rules with added coverage for
  persistence, service/task abuse, PowerShell/script launch, download-execute,
  process injection signals, credential/LSASS/browser-store access, lateral
  movement, anti-sandbox checks, firewall/tool tampering, DNS/HTTP/TLS/C2
  placeholders, and MITRE map consistency.
- Guest Agent artifact collection now has an opt-in dropped-file manifest path
  and an opt-in memory dump path. Dropped files are copied under
  `artifacts/dropped-files/**` with manifest metadata; memory dumps are off by
  default and only written under `memory-dumps/**` when explicitly requested.
- Current validation evidence for this snapshot:
  `dotnet build .\KSwordSandbox.sln`, smoke tests, local pipeline smoke, and
  repository policy all pass.
- VirusTotal integration has a first WebUI pass: `/settings` stores or clears a
  local API key, `KSWORDBOX_VIRUSTOTAL_API_KEY` can override it, and
  `/api/jobs/{jobId}/virustotal` performs a hash-only official v3 file-report
  lookup without uploading samples. Missing keys or API failures return quiet
  status payloads and do not interrupt sandbox execution.

## Remaining P0 gaps

1. Turn the currently single-job/single-golden-VM flow into an operator-safe
   packaged experience: clearer install/run checks, better failure recovery, and
   one-click defaults that do not require reading runbook internals.
2. Harden the real R0 path beyond the successful smoke: ABI versioning,
   backpressure, producer-specific stress tests, unload/reload reliability, and
   better event filtering.
3. Continue report evidence polish beyond the new raw-event collapse: add
   graph/process-tree polish, IOC copy/export, and richer artifact cards.
4. Finish screenshots and PCAP/network-flow artifacts, then connect them to the
   artifact manifest and final report.
5. Move from single golden VM restore to safer temporary VM or differencing-disk
   isolation before any broader sample testing.
6. Add VirusTotal settings/hash lookup and keep failures silent unless the
   operator opens the settings/status page.

## Next best work

- Finish R0 ABI/capability negotiation and typed payload parsing.
- Run the Hyper-V E2E PlanOnly/full-validation gates on the target host after
  each script change, then run the live mode only from an elevated test session.
- Use `Prepare-HarmlessSample.ps1` and the runbook checklist to build the
  executable outside git for live Hyper-V validation.
- Add final report artifact links for `events.json`, `driver-events.jsonl`,
  screenshots, dropped-file manifests, memory dumps, and future PCAP files.
- Add VirusTotal settings storage plus hash lookup, with no noisy logs when the
  key is absent or the API call fails.
- Run native build and full smoke after each R0/collector merge.
