# Live telemetry pipeline

The WebUI live monitor is intentionally raw-event focused. It should show what
the guest and driver are producing while the job is running, without waiting
for final rule classification.

## v1 data flow

1. Guest Agent writes `events.json` under a job-specific guest output folder.
2. R0Collector writes `driver-events.jsonl` beside `events.json`.
3. Host copies or syncs those files into `D:\Temp\KSwordSandbox\jobs\<job>\guest`.
4. Core live telemetry services read JSON/JSONL with shared-read tolerance.
5. WebUI polls `/api/jobs/{jobId}/events/live` and appends unclassified rows.
6. After completion, Host imports events, runs rules, and regenerates reports.

## Important boundary

Live display is not a verdict. It is a visibility channel for process, file,
registry, image, and network events. Risk scoring and MITRE mapping belong to
the final report regeneration path.
