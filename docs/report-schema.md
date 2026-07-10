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
output directory before the host collects them. Guest dropped-file evidence may
also be represented by `artifacts/manifest.json`.

## Artifact manifest evidence

Dropped files and other copied evidence use
`KSword.Sandbox.Abstractions.Artifacts.ArtifactManifest`. The current minimal
schema is:

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
  `ArtifactManifest`.
- `name`: file name.
- `relativePath`: path relative to the collected output root, for example
  `artifacts/drop.bin`.
- `fullPath`: host-resolved path after collection, or producer-local path before
  host normalization.
- `sizeBytes`, `sha256`, `createdAtUtc`.
- `metadata`: string fields such as `origin=guest`,
  `evidenceRole=dropped-file`, and `guestFullPath`.

Host-side code can load guest manifests with `GuestArtifactManifestReader`,
which resolves `relativePath` under the collected guest-output directory and
preserves original guest absolute paths in metadata. The main report import path
does not yet merge this manifest into `AnalysisReport`; until that integration
lands, `events.json` remains the behavior timeline and `artifacts/manifest.json`
is the evidence-chain sidecar.

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
