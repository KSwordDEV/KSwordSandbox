# Report schema

## JSON artifacts

The host writes `report.json` beside `report.html` for every planned job. The
JSON model is `AnalysisReport`:

- `jobId`
- `sample`
- `generatedAt`
- `status`
- `events`
- `findings`
- `metrics`

`staticAnalysis` currently uses the stable `StaticAnalysisResult` shape:

- PE identity fields: `fileFormat`, `magic`, `isPe`, `architecture`,
  `machine`, `subsystem`, `entryPointRva`, `sectionCount`, and `sections`.
- Static triage fields: `tags`, `urls`, `interestingStrings`, and `warnings`.
- Imports/exports/TLS are represented without changing the public schema:
  parsed import modules/APIs, export names, and TLS callback hints are emitted
  as bounded `interestingStrings`; rule-facing signals are emitted as `tags`
  such as `imports_present`, `exports_present`, `tls_directory_present`,
  `tls_callbacks`, `import_suspicious_api`, and
  `export_registration_entrypoint`.

The host also emits a normalized `static.analysis.completed` event. Its
`data.tags` value is the comma-joined static tag list consumed by
`rules/behavior-rules.json` via `dataContains.tags`.

Guest collection writes `events.json` and `agent-summary.json` under the guest
output directory before the host collects them. Driver/R0 telemetry may also be
present as sibling `driver-events.jsonl`. Guest dropped-file evidence may be
represented by `artifacts/manifest.json`, and screenshots may be present under
`screenshots/`.

## Artifact manifest evidence

Dropped files and other copied evidence use
`KSword.Sandbox.Abstractions.Artifacts.ArtifactManifest`. The schema is:

- `schemaVersion`: manifest contract version, currently `1`.
- `jobId`: host job ID when known; guest-side manifests may leave this empty.
- `runtimeRoot`: root directory used by the producer.
- `rootPath`: artifact root directory.
- `producer`: component that wrote the manifest, such as
  `KSword.Sandbox.Agent`.
- `generatedAtUtc`: manifest generation time.
- `artifacts`: `ArtifactDescriptor[]`.

Each `ArtifactDescriptor` records:

- `kind`: for dropped files, `DroppedFile`; manifest files use
  `ArtifactManifest`; event streams use `GuestEventsJson` or
  `DriverEventsJsonLines`; screenshots use `Screenshot`.
- `category`: stable report grouping such as `dropped-file`, `telemetry`,
  `screenshot`, or `artifact-manifest`.
- `name`: file name.
- `relativePath`: path relative to the collected output root, for example
  `artifacts/drop.bin`.
- `safeLink`: URL-encoded relative link derived from `relativePath`; rooted
  paths and `..` traversal are not emitted as links.
- `fullPath`: host-resolved path after collection, or producer-local path before
  host normalization.
- `mimeType`, `sizeBytes`, `sha256`, `hashes`, `createdAtUtc`.
- `metadata`: string fields such as `origin=guest`,
  `evidenceRole=dropped-file`, and `guestFullPath`.

Host-side code can load guest manifests with `GuestArtifactManifestReader`,
which resolves `relativePath` under the collected guest-output directory and
preserves original guest absolute paths in metadata.

The host writes `artifact-index.json` beside `report.json` and `report.html`.
This `HostArtifactIndex` scans the job root for report files, `events.json`,
`driver-events.jsonl`, `artifacts/manifest.json`, `screenshots/*`, and dropped
files under `artifacts/*`. The HTML report has an **Artifact links** section
that exposes those indexed artifacts with safe relative links when available,
and falls back to copyable paths from events when a link cannot be trusted.

## HTML sections

The v1 HTML report includes:

- summary and sample identity;
- behavior findings with MITRE seed mappings;
- normalized event table.

Static import/export/TLS details appear in the existing Static analysis section
under `Tags` and `Interesting strings`; no WebUI contract changes are required
for this depth increment.

Future sections should keep the same source model and add rendered sections for
table of contents, risk summary, behavior detections, multi-dimensional
detections, engine/rule hits, static analysis, dynamic analysis, process tree,
dropped files, network timeline, screenshots, driver health, and failure
reasons. The target structure is summarized in
`docs/microstep-report-benchmark.md`.
