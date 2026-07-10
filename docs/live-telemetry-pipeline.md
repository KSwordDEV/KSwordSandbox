# Live telemetry pipeline

The WebUI live monitor is intentionally raw-event focused. It should show what
the guest and driver are producing while the job is running, without waiting
for final rule classification.

## v1 data flow

1. Guest Agent writes `events.json` under a job-specific guest output folder,
   for example `C:\KSwordSandbox\out\<job-id-n>`.
2. R0Collector writes `driver-events.jsonl` beside `events.json`.
3. Host starts the Guest Agent asynchronously, then a runbook
   `sync-live-output` step periodically copies that guest output tree into
   `D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest`.
4. Core live telemetry services read JSON/JSONL with shared-read tolerance.
5. WebUI polls `/api/jobs/{jobId}/events/live` and appends unclassified rows.
6. After completion, Host imports events, runs rules, and regenerates reports.

## Important boundary

Live display is not a verdict. It is a visibility channel for process, file,
registry, image, and network events. Risk scoring and MITRE mapping belong to
the final report regeneration path.

## Current v1 implementation

The live path is still PowerShell Direct based, not a socket stream. The host
opens a PSSession, copies the guest output tree while the Guest Agent wrapper
process is running, and performs one final copy after the process exits. This
keeps v1 deployable in a default Hyper-V Windows 10 guest without installing a
guest TCP/WebSocket service.
