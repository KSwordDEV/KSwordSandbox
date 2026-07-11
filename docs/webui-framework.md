# Web UI framework staging

This document describes the staged Web project layout used to extract endpoint
and dashboard logic from `Program.cs`. Most endpoint modules remain passive
staging, but the root WebUI is now rendered by
`Dashboard/DashboardExperiencePage.cs` so the operator experience can evolve
inside the Dashboard layer without touching Core, Driver, or Guest code.

## Write boundary

Worker-Web changes are limited to:

- `src/KSword.Sandbox.Web/Contracts/**`
- `src/KSword.Sandbox.Web/Dashboard/**`
- `src/KSword.Sandbox.Web/Endpoints/**`
- `src/KSword.Sandbox.Web/Infrastructure/**`
- `src/KSword.Sandbox.Web/Program.cs` for route wiring and Web-only error text
- `docs/webui-framework.md`

No `driver/`, `guest/`, or `src/KSword.Sandbox.Core/` files should be modified
by WebUI/UX work.

## Layer responsibilities

- `Contracts`: named API payload records that can replace anonymous response
  objects as endpoint blocks move out of `Program.cs`.
- `Infrastructure`: small Web-only helpers for clocks, request correlation,
  problem responses, validation errors, route constants, content types, and file
  name normalization.
- `Endpoints`: route-module descriptors, collection ordering, DI registration
  helpers, and feature-area modules for Dashboard, Health, Files, Jobs, and
  Runbooks.
- `Dashboard`: server-rendered HTML component primitives, document composition,
  navigation, status badges, the root experience page, and a standard
  context-copy script for copyable dashboard values.

## WebUI experience contract

The root dashboard must keep these operator-facing areas visible and copyable:

- three tab-separated planning entry points for upload-and-plan, host-path
  planning, and directory scan plus first-candidate or selected-candidate
  planning; the upload tab is the default selected tab;
- VM configuration fields that are sent with every dry-run planning request:
  `goldenVmName`, `goldenSnapshotName`, `guestUserName`,
  `guestWorkingDirectory`, `guestPayloadRoot`, and `useMockCollector`;
- opt-in artifact collection fields that are sent with every dry-run planning
  request and preserved on the job submission: `collectDroppedFiles`,
  `captureScreenshots`, `captureMemoryDumps`, and `capturePacketCapture`. These
  are disabled by default unless explicitly enabled in config or checked in the
  WebUI, and the runbook forwards them to the Guest Agent as
  `--collect-dropped-files`, `--screenshot`, `--memory-dump`, and
  `--packet-capture`;
- explicit job status, job ID, sample path, recent job list, and guest import
  status;
- artifact paths for `report.json`, `report.html`, `events.json`,
  `driver-events.jsonl`, and `runbook-execution.json`;
- automatic report links after a plan is created, including the served
  `/api/jobs/{jobId}/report/html` link and the local-file fallback when a path
  is recorded. The primary report button follows the current Chinese/English
  dashboard language, while compact `zh` / `en` alternatives remain visible so
  operators never need to paste a report path;
- stage progress that shows ordered planning/execution/import/report steps with
  stable IDs and human-readable status;
- real executor progress from
  `GET /api/jobs/{jobId}/runbook/progress` while `/runbook/execute` is still
  running. The endpoint is backed by `RunbookProgressStore`, receives
  `SandboxRunbookProgressSnapshot` values through the executor `ProgressSink`,
  and intentionally omits PowerShell command text, `stdout`, and `stderr` from
  the main dashboard;
- upload flow should be one-click for operators: after an `.exe` upload is
  stored and a plan is created, the dashboard automatically opens the dedicated
  dynamic monitor page in a new tab, starts live VM analysis, and switches the
  progress panel from estimated stages to real runbook step status. The click
  handler opens a same-gesture `about:blank` monitor placeholder before the
  first asynchronous upload/plan `await`, then navigates that existing window to
  `/jobs/{jobId}/live-events` once the job exists; this reduces popup-blocker
  failures compared with opening the monitor only after upload completes. If
  the browser blocks the new tab, the current job card must show an explicit
  bilingual `Enter dynamic monitor` fallback link while keeping the dashboard
  alive for the long-running execute request;
- VirusTotal official result integration is optional and hash-only. Operators
  can open `/settings` to save or clear a local API key; the key is read from
  `KSWORDBOX_VIRUSTOTAL_API_KEY` first or from the runtime settings file under
  `D:\Temp\KSwordSandbox\settings`. The job page exposes
  `GET /api/jobs/{jobId}/virustotal`, which queries the official v3
  `files/{sha256}` endpoint with `x-apikey`, does not upload samples, and
  returns a quiet `not_configured` / `lookup_failed` state when missing or
  unavailable instead of interrupting analysis;
- a link to a dedicated live raw monitor page / dynamic monitor page that shows
  source files and unclassified raw event rows before final report
  classification. The page should explain that, when opened automatically from
  upload, the dashboard tab must stay open to continue the analysis request.
  The monitor page also polls `GET /api/jobs/{jobId}/runbook/progress` and shows
  UI-safe runbook step state, current step, and progress percentage without
  command lines, `stdout`, or `stderr`;
- a natural progress-page link to the dedicated execution-flow page for runbook
  step status, available both from the job actions and the progress summary.
  The root dashboard must not inline long runbook PowerShell commands,
  command-line details, `stdout`, or `stderr`.

All tables, path values, raw telemetry evidence, job messages, status text,
inputs, and section text must support either an
explicit `Copy` button or right-click copy through `data-copy`, `code`, `pre`,
`td`, `th`, `p`, `li`, heading, `label`, `span`, `a`, `button`, or `input`
elements. The WebUI should display a small toast after copy succeeds or fails so
operators know whether clipboard capture worked.

Guest import status should be specific:

- `waiting for import` when the job has report paths but no imported event
  source yet;
- `imported` when an `events.json` or JSONL source path is recorded;
- `imported empty` when import succeeded technically but no guest events were
  found;
- `import failed` when job messages indicate guest output was missing or could
  not be imported.

The import action should allow an optional explicit `events.json` / `.jsonl`
path. If the field is blank, the endpoint searches the deterministic job guest
folder. This keeps the one-click path short while still giving operators a
repair path when guest collection artifacts landed somewhere else.

Client-side errors should preserve the failing action, HTTP status, server
detail, and trace/request ID when present, for example:
`Create dry-run analysis plan failed (HTTP 400 Bad Request): Dry-run plan could
not be created: <specific path validation detail>`.

## Migration path

1. Add `builder.Services.AddSandboxWebEndpointModules()` after the Web project
   imports the endpoint namespace.
2. Replace the existing inline `app.MapGet` / `app.MapPost` blocks with
   `app.MapSandboxEndpointModules(app.Services.GetServices<IWebEndpointModule>())`.
3. Move one feature area at a time:
   - health and config responses,
   - file scan and upload endpoints,
   - job list/detail/live-event endpoints,
   - runbook execution and guest import endpoints,
   - dashboard HTML rendering.
4. Replace anonymous objects with `Contracts` records where response shape is
   stable.
5. Keep any endpoint that touches filesystem paths behind explicit
   Infrastructure helpers so browser input cannot select arbitrary host paths.

## Dashboard conventions

Dashboard components should render only locally owned HTML fragments. Plain text
must go through `DashboardHtml.Encode` or `DashboardHtml.Attribute`. When values
need to be copied from text, badges, cards, or future tables, render them with a
`data-copy` attribute so the standard context-copy script can handle right-click
copy behavior consistently.

Sensitive artifact collection controls must stay under an advanced/explicit
opt-in section. The UI may pre-check them from
`config.artifactCollection.collectDroppedFiles`,
`config.artifactCollection.captureScreenshots`,
`config.artifactCollection.captureMemoryDumps`, and
`config.artifactCollection.capturePacketCapture`, but operators must be able to
override them per job before planning. The job card should summarize which
lanes were requested without implying that artifacts already exist.

When JavaScript renders dynamic table rows, each path or evidence cell should
either call the local copy-button helper or set `data-copy` to the raw value.
For planned jobs, the UI may derive expected guest paths from the recorded job
root: `guest\<job-id-n>\events.json` and
`guest\<job-id-n>\driver-events.jsonl`. These derived paths are display hints;
the import endpoint still resolves actual files server-side.

The current root page also renders a recent job table from `/api/jobs`. That
table is intentionally read-only: the `Open` action fetches the selected job
detail and reuses the main job panel instead of duplicating artifact/runbook
rendering logic.

## Optional runtime WebUI smoke

The normal smoke path is a static gate: it checks source, script, and
documentation contracts without launching a browser or modifying runtime
artifacts. Use it when the Web host or a real browser cannot be started:

```powershell
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj
.\scripts\Test-LiveTelemetryFramework.ps1 -ContractOnly
```

When a Web host is already running and an existing planned/live job ID is
available, set both runtime variables before running the smoke project:

```powershell
$env:KSWORD_SMOKE_BASE_URL = 'http://127.0.0.1:5000'
$env:KSWORD_SMOKE_JOB_ID = '<existing-job-guid>'
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj
```

The runtime WebUI smoke contract is intentionally API-level so it can run on
headless workers. It probes:

- `GET /jobs/{jobId}/live-events` and requires a successful `text/html` page
  containing the live raw monitor title plus references to both raw event
  transports;
- `GET /api/jobs/{jobId}/events/live?offset=0&take=1` and requires the live raw
  telemetry JSON cursor fields: `jobId`, `retrievedAt`, `totalEvents`,
  `nextOffset`, `hasMore`, `sources`, and `events`;
- the root dashboard source must link to the dedicated live raw monitor page;
- `GET /api/jobs/{jobId}/report/html` and requires a successful `text/html`
  served report response, which is the same safe report link rendered by the
  dashboard;
- bilingual report endpoints: `GET /api/jobs/{jobId}/report/html?lang=zh` and
  `GET /api/jobs/{jobId}/report/html?lang=en` should both return `text/html`
  from the recorded job report paths, falling back to the compatibility
  `report.html` only when a localized report file is not recorded;
- `POST /api/jobs/{jobId}/guest-events/import` with an explicit missing
  `eventsPath` and requires a controlled HTTP 400 validation response. This
  proves the manual guest import endpoint and payload contract without importing
  or rewriting real guest artifacts during smoke.

The PowerShell gate also accepts the same environment variables when `-BaseUrl`
and `-JobId` are omitted:

```powershell
.\scripts\Test-LiveTelemetryFramework.ps1 -UsePollingFallback
```

For an end-to-end operator validation, create or select a job after starting the
Web host, open the dashboard in a browser manually, and confirm that the served
HTML report link opens, the live raw monitor page refreshes through SSE or
polling, the Chinese report endpoint
`/api/jobs/{jobId}/report/html?lang=zh` and English report endpoint
`/api/jobs/{jobId}/report/html?lang=en` both serve HTML, the root dashboard does
not show long runbook command/output blocks, and the manual guest import field
can be left blank or filled with a specific `events.json` / `.jsonl` path. Do
not commit generated reports, imported guest output, browser screenshots, or
build binaries from this validation.

## Verification guidance

To avoid modifying repository `bin/` or `obj/` directories during verification,
build the Web project with `BaseIntermediateOutputPath`, `BaseOutputPath`, and
`RestorePackagesPath` redirected to a temporary directory outside the
repository.
