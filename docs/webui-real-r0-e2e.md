# WebUI/API real R0 E2E validation

This document records the current local validation evidence for the requested
minimum usable chain:

```text
choose/upload EXE -> plan job -> start Hyper-V Win10 VM -> run sample ->
collect basic guest/R0 behavior -> import/classify -> open HTML report
```

Runtime files listed here are local lab artifacts under `D:\Temp\KSwordSandbox`
and must not be committed.

## Current local result

Observed from `D:\Projects\KswordSandbox` on 2026-07-11 local time.

Environment:

- WebUI URL: `http://127.0.0.1:18082`
- Config: `D:\Temp\KSwordSandbox\real-r0.live.json`
- VM: `KSwordSandbox-Win10-Golden`
- Checkpoint: `Clean-TestSigning`
- Guest user: `SandboxUser`
- Sample: `D:\Projects\KswordSandbox\tools\KSword.Sandbox.HarmlessSample\bin\Debug\net9.0\KSword.Sandbox.HarmlessSample.exe`
- Driver mode: real R0, `driver.useMockCollector=false`
- Driver signer: local Windows test certificate
- `CSignTool.exe`: not used

Scripted command:

```powershell
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900 `
  -SummaryPath 'D:\Temp\KSwordSandbox\webui-api-e2e\real-r0-live-summary.json'
```

Summary:

```text
jobId:                 fe0db7cb-df74-444b-897e-50c9f5a27d4d
runbook:               17/17 steps succeeded
duration:              78.009 seconds
guest import:          succeeded
live raw events:       522
report default:        HTTP 200, 11,933,268 bytes
report zh:             HTTP 200, 11,770,152 bytes
report en:             HTTP 200, 11,933,268 bytes
cSignToolUsed:         false
```

Key output paths:

```text
D:\Temp\KSwordSandbox\jobs\fe0db7cbdf74444b897e50c9f5a27d4d\runbook-execution.json
D:\Temp\KSwordSandbox\jobs\fe0db7cbdf74444b897e50c9f5a27d4d\guest\fe0db7cbdf74444b897e50c9f5a27d4d\events.json
D:\Temp\KSwordSandbox\jobs\fe0db7cbdf74444b897e50c9f5a27d4d\guest\fe0db7cbdf74444b897e50c9f5a27d4d\driver-events.jsonl
D:\Temp\KSwordSandbox\jobs\fe0db7cbdf74444b897e50c9f5a27d4d\report.json
D:\Temp\KSwordSandbox\jobs\fe0db7cbdf74444b897e50c9f5a27d4d\report.html
D:\Temp\KSwordSandbox\jobs\fe0db7cbdf74444b897e50c9f5a27d4d\report.zh.html
D:\Temp\KSwordSandbox\jobs\fe0db7cbdf74444b897e50c9f5a27d4d\report.en.html
```

Additional manual WebAPI run immediately before the scripted gate:

```text
jobId:           62932974-a1f8-49b3-b514-6157cd7fb3bb
runbook:         17/17 steps succeeded
duration:        00:01:19.3434848
live raw events: 700
report events:   705
findings:        29
driver JSONL:    558 lines
guest events:    700 rows
```

Top event groups in that run:

```text
driver.file                 383
driver.registry             135
process.observed             90
network.netstat              23
r0collector.driverReadEvents 17
r0collector.driverPoll       10
image.load                    5
process.new                   4
```

## What this proves

- The WebUI host can accept an executable path and create a job.
- The same WebAPI path used by the WebUI can execute a live Hyper-V runbook.
- The VM restore/start/stage/run/collect/shutdown sequence works on the local
  prepared Windows 10 golden VM.
- The Guest Agent waits for the requested analysis window even when the sample
  exits quickly, so R0Collector has time to drain events.
- The real R0 driver can be loaded in the test-signing VM and can emit file,
  registry, process/image, and network/status events through R0Collector JSONL.
- Host import merges `events.json` and `driver-events.jsonl`, reruns rules, and
  regenerates `report.json`, `report.html`, `report.zh.html`, and
  `report.en.html`.
- The live raw-event endpoint can read real guest/R0 artifacts before final
  classification.
- The driver build/sign validation path does not call `CSignTool.exe`; real R0
  validation used Windows test mode plus `Set-AuthenticodeSignature`.

## Safe dry-run script gate

For fast verification without VM mutation:

```powershell
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 120 `
  -SummaryPath 'D:\Temp\KSwordSandbox\webui-api-e2e\dryrun-summary.json'
```

Latest dry-run evidence:

```text
jobId:           e90a3caf-25ee-423c-8c44-0f46ab37d4dc
mode:            DryRun
runbook:         0/17 live steps executed, 17 steps recorded
report default:  HTTP 200
report zh:       HTTP 200
report en:       HTTP 200
cSignToolUsed:   false
```

## Known limitations after this pass

- The VM is still a single golden VM workflow; concurrent job scheduling and
  disposable temporary VM/differencing-disk isolation are not production-grade.
- The WebUI progress bar is estimated from the long HTTP request. It does not
  yet stream exact per-runbook-step state from the executor while the request is
  in flight.
- R0 coverage is useful but not final: file/registry/process/image/network
  events exist, but ABI hardening, stress tests, filtering, and dropped-file
  extraction still need work.
- Reports are large because raw events are included inline; the next UI/report
  pass should paginate or collapse raw evidence more aggressively.
- Real malicious sample testing has not been performed in this validation.
