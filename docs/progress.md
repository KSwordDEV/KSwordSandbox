# KSwordSandbox progress snapshot

This snapshot is intentionally conservative. It measures distance to the
requested v1 deliverable: open WebUI, submit an EXE, run a Windows 10 Hyper-V
guest, see raw R0/guest events live, import events, classify behavior, and open
a final HTML report.

## Current estimated completion

- Overall v1 deliverable: **69%**
- Minimum usable E2E chain on this host: **81%**
- Repository architecture, docs, module boundaries, policy: **82%**
- Core job/event/rule/report models: **74%**
- Web/API/WebUI submission and job UX: **78%**
- Live raw telemetry contract: **82%**
- Hyper-V runbook generation and execution recording: **69%**
- Golden VM / payload staging / operator readiness: **58%**
- Guest Agent dynamic collection: **74%**
- R0 Driver + R0Collector: **63%**
- Static analysis and behavior rules: **66%**
- HTML report generation: **79%**
- Artifact manifest and dropped-file plumbing: **75%**
- Tests and quality gates: **75%**
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
  `SandboxEvent`-compatible JSONL in mock and driver modes. It also has a
  no-device `--abi-self-check` / `--contract-self-check` mode that records ABI
  version, capability flags, producer masks, structure sizes, JSONL noise
  policy, kernel backpressure policy, and queue-loss evidence without opening
  the driver device.
- R0Collector now has a shipped synthetic event-quality stress mode:
  `--stress-count <n>` emits contiguous `driver.file` rows with sequence,
  stress, loss, and backpressure evidence, and `--inject-jsonl-noise` appends
  blank/malformed/extra-field rows for parser tolerance checks without opening
  the driver device.
- R0 network parsing now adds lightweight semantic fields (`serviceHint`,
  `semanticCandidate`, `flowKey`, source/destination endpoints, and
  DNS/HTTP/TLS candidate booleans) and uses URI-like top-level network paths
  when remote endpoints decode.
- Report renderer has cloud-sandbox-style sections for risk, behavior, MITRE,
  static, dynamic, behavior graph / IOC summary, artifact links, process, file,
  registry, network, failures, and raw events.
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
- The dedicated dynamic monitor page also polls the real runbook progress
  endpoint and shows UI-safe step progress beside raw events and VirusTotal
  results. The upload flow opens a same-gesture blank monitor placeholder before
  asynchronous upload work, then navigates it to the job monitor after planning
  to reduce browser popup-blocker failures.
- The upload flow is now closer to one-click operation: after an `.exe` upload
  is stored and planned, the dashboard opens the standalone dynamic monitor,
  starts live VM analysis, keeps the main page on exact runbook step state, and
  falls back to a copyable monitor/progress/report link card if the browser
  blocks the new tab.
- Final HTML reports no longer inline every raw event by default. Raw evidence
  is collapsed in a bounded scroll panel, capped to the first 200 inline rows,
  and the report shows complete source hints for `report.json`, `events.json`,
  `driver-events.jsonl`, and artifact manifests.
- Behavior rules have been expanded to 206 rules with added coverage for
  persistence, service/task abuse, PowerShell/script launch, download-execute,
  process injection signals, credential/LSASS/browser-store access, lateral
  movement, anti-sandbox checks, firewall/tool tampering, DNS/HTTP/TLS/C2,
  PCAP evidence, screenshots, memory dumps, dropped-file artifacts, process
  trees, and MITRE map consistency.
- Guest Agent artifact collection now has opt-in dropped-file, screenshot,
  memory-dump, and packet-capture lanes. Dropped files are copied under
  `artifacts/dropped-files/**` with manifest metadata; screenshots and memory
  dumps remain off by default; packet capture is explicit opt-in and uses
  Windows `pktmon` to produce `packet-captures/*.pcapng` when the guest permits
  it.
- Artifact manifests now carry collection status metadata (`collections`,
  `evidenceRole`, `capturePhase`, `captureState`, `guestPath`, `importPath`,
  and `collectionName`), and host indexing recognizes memory dumps plus
  `.pcap` / `.pcapng` files.
- Screenshot collection remains opt-in but now supports a default
  `before,during,after` cadence, `--screenshot-phases` /
  `--screenshot-stages`, and bounded `--screenshot-count 1..5`; skipped
  screenshots stay non-fatal on headless or unsupported guests.
- Host artifact indexing now exposes collection summaries and can consume
  guest-generated or externally supplied `.pcap` / `.pcapng` artifacts; packet
  captures appear in report artifact links when present.
- PCAP artifacts are now parsed into bounded normalized `pcap.summary`,
  `pcap.flow`, `pcap.dns`, `pcap.http`, and `pcap.tls` events for Ethernet /
  IPv4 / TCP / UDP captures. Guest event import merges sibling PCAP files into
  report regeneration, and smoke coverage verifies DNS, HTTP, TLS/SNI, flow,
  protocol summary, and rule hits.
- The report now includes a static HTML/CSS weak-interaction behavior graph and
  IOC summary cards, deriving process-to-file, process-to-registry,
  process-to-network, and process-to-artifact edges from normalized events. It
  now also has bounded evidence summary cards, process relationship cards, and
  network relationship cards with folded evidence blocks and copy-friendly text.
- Current validation evidence for this snapshot:
  `dotnet build .\KSwordSandbox.sln`, native driver/collector compile-only
  build, smoke tests, local pipeline smoke, and repository policy all pass.
- VirusTotal integration has a first WebUI pass: `/settings` stores or clears a
  local API key, `KSWORDBOX_VIRUSTOTAL_API_KEY` can override it, and
  `/api/jobs/{jobId}/virustotal` performs a hash-only official v3 file-report
  lookup without uploading samples. Missing keys or API failures return quiet
  status payloads and do not interrupt sandbox execution.

## Remaining P0 gaps

1. Turn the currently single-job/single-golden-VM flow into an operator-safe
   packaged experience: clearer install/run checks, better failure recovery, and
   one-click defaults that do not require reading runbook internals.
2. Harden the real R0 path beyond the successful smoke: producer-specific
   stress tests, unload/reload reliability, tighter event filtering, and live
   ABI self-check execution in the guest image.
3. Continue report evidence polish beyond the new relationship cards: improve
   visual process-tree layout, timeline grouping, artifact cards, and screenshot
   evidence placement.
4. Finish real screenshot capture validation and repeated PCAP/network-flow
   validation. The guest now has an opt-in pktmon path, but it still needs live
   VM validation across privilege levels, existing-capture conflicts, and large
   trace conversion.
5. Move from single golden VM restore to safer temporary VM or differencing-disk
   isolation before any broader sample testing.
6. Broaden VirusTotal and external intelligence presentation beyond the first
   hash-only lookup while keeping missing keys and API failures quiet by default.

## Next best work

- Run the new R0Collector no-device ABI self-check inside the prepared guest
  image and wire its output into operator readiness checks.
- Finish deeper R0 typed payload parsing, producer-specific stress tests, and
  unload/reload reliability checks.
- Run the Hyper-V E2E PlanOnly/full-validation gates on the target host after
  each script change, then run the live mode only from an elevated test session.
- Use `Prepare-HarmlessSample.ps1` and the runbook checklist to build the
  executable outside git for live Hyper-V validation.
- Validate the new opt-in guest pktmon PCAP collection path inside the prepared
  VM and ensure generated `.pcapng` artifacts are imported into the final
  report during live Hyper-V runs.
- Add richer visual process-tree layout, timeline grouping, and artifact cards
  on top of the new process/network relationship cards.
- Run native build and full smoke after each R0/collector merge.
