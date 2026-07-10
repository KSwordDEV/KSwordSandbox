# Web UI framework staging

This document describes the staged Web project layout used to extract endpoint
and dashboard logic from `Program.cs`. Most endpoint modules remain passive
staging, but the root WebUI is now rendered by
`Dashboard/DashboardExperiencePage.cs` so the operator experience can evolve
inside the Dashboard layer.

## Write boundary

Worker-Web changes are limited to:

- `src/KSword.Sandbox.Web/Contracts/**`
- `src/KSword.Sandbox.Web/Dashboard/**`
- `src/KSword.Sandbox.Web/Endpoints/**`
- `src/KSword.Sandbox.Web/Infrastructure/**`
- `docs/webui-framework.md`

No `driver/`, `guest/`, `src/KSword.Sandbox.Core/`, or existing Web source file
was modified by this staging work.

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

- clearer one-click entry points for upload-and-plan, host-path planning, and
  directory scan plus first-candidate planning;
- explicit job status, job ID, sample path, and guest import status;
- artifact paths for `report.json`, `report.html`, `events.json`,
  `driver-events.jsonl`, and `runbook-execution.json`;
- a live raw telemetry area that shows source files and unclassified raw event
  rows before final report classification;
- runbook execution rows with step status, `stdout`, `stderr`, exit code,
  duration, and command text.

All tables, path values, raw telemetry evidence, runbook command/output blocks,
and job messages must support either an explicit `Copy` button or right-click
copy through `data-copy`, `code`, `pre`, `td`, or `th` elements.

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

When JavaScript renders dynamic table rows, each path or evidence cell should
either call the local copy-button helper or set `data-copy` to the raw value.
For planned jobs, the UI may derive expected guest paths from the recorded job
root: `guest\<job-id-n>\events.json` and
`guest\<job-id-n>\driver-events.jsonl`. These derived paths are display hints;
the import endpoint still resolves actual files server-side.

## Verification guidance

To avoid modifying repository `bin/` or `obj/` directories during verification,
build the Web project with `BaseIntermediateOutputPath`, `BaseOutputPath`, and
`RestorePackagesPath` redirected to a temporary directory outside the
repository.
