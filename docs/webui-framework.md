# Web UI framework staging

This document describes the staged Web project layout added for future
extraction of the current `Program.cs` endpoint and dashboard logic. The new
files are intentionally passive: they compile with the Web project, but
`Program.cs` has not been changed to call them yet.

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
  navigation, status badges, and a standard context-copy script for copyable
  dashboard values.

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

## Verification guidance

To avoid modifying repository `bin/` or `obj/` directories during verification,
build the Web project with `BaseIntermediateOutputPath`, `BaseOutputPath`, and
`RestorePackagesPath` redirected to a temporary directory outside the
repository.
