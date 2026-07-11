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
- Section and indicator depth also stays schema-compatible: section summaries
  remain in `sections`, while copyable evidence strings such as `section:...`,
  `url:...`, `ip:...`, `registry-path:...`, `path:...`, `resource:...`, and
  `tls:...` appear in `interestingStrings`.

The host also emits a normalized `static.analysis.completed` event. Its
`data.tags` value is the comma-joined static tag list consumed by
`rules/behavior-rules.json` via `dataContains.tags`.

Guest collection writes `events.json` and `agent-summary.json` under the guest
output directory before the host collects them. Driver/R0 telemetry may also be
present as sibling `driver-events.jsonl`. Guest dropped-file evidence may be
represented by `artifacts/manifest.json`, screenshots may be present under
`screenshots/`, and explicit `--packet-capture` / `--pcap` /
`--network-capture` runs may produce `packet-captures/*.pcapng` through Windows
`pktmon`. Externally generated `.pcap` or `.pcapng` files may also be present
under `packet-captures/` or elsewhere in the collected job folder.

When `events.json` is imported, sibling `*.jsonl` files under the same guest
output root are merged into the regenerated `report.json` and `report.html`.
This includes R0Collector mock JSONL rows such as
`r0collector.mockDriverEvent`; they remain raw events with
`source=r0collector`, keep `data.mock=true` / `data.driverEventPath`, and trigger the
`r0collector-mock-driver-event` informational rule. The host
`guest.events.imported` marker stores an `eventCount` that includes both
`events.json` rows and imported JSONL rows so a smoke run can prove the R0 mock
sidecar was included in the final report.

## Artifact manifest evidence

Dropped files and other copied evidence use
`KSword.Sandbox.Abstractions.Artifacts.ArtifactManifest`. The schema is:

- `schemaVersion`: manifest contract version, currently `1`.
- `jobId`: host job ID when known; guest-side manifests may leave this empty.
- `runtimeRoot`: root directory used by the producer.
- `rootPath`: artifact root directory.
- `importRoot`: root that host importers use to resolve descriptor import
  paths.
- `producer`: component that wrote the manifest, such as
  `KSword.Sandbox.Agent`.
- `generatedAtUtc`: manifest generation time.
- `collections`: `ArtifactCollectionDescriptor[]` lanes, including disabled,
  skipped/failed, and packet-capture lanes.
- `artifacts`: `ArtifactDescriptor[]`.

Each `ArtifactDescriptor` records:

- `kind`: for dropped files, `DroppedFile`; manifest files use
  `ArtifactManifest`; event streams use `GuestEventsJson` or
  `DriverEventsJsonLines`; screenshots use `Screenshot`; packet captures use
  `PacketCapture`.
- `category`: stable report grouping such as `dropped-file`, `telemetry`,
  `screenshot`, `packet-capture`, or `artifact-manifest`.
- `name`: file name.
- `relativePath`: path relative to the collected output root, for example
  `artifacts/drop.bin`.
- `safeLink`: URL-encoded relative link derived from `relativePath`; rooted
  paths and `..` traversal are not emitted as links.
- `fullPath`: host-resolved path after collection, or producer-local path before
  host normalization.
- `evidenceRole`, `capturePhase`, `captureState`, `guestPath`, `importPath`,
  and `collectionName`.
- `mimeType`, `sizeBytes`, `sha256`, `hashes`, `createdAtUtc`.
- `metadata`: string fields such as `origin=guest`,
  `evidenceRole=dropped-file`, `guestFullPath`, `captureSource=external`, and
  `hostCaptureStarted=false`.

Host-side code can load guest manifests with `GuestArtifactManifestReader`,
which resolves `relativePath` under the collected guest-output directory and
preserves original guest absolute paths in metadata. If a guest manifest points
at an existing `.pcap` or `.pcapng`, the reader can consume it as
`PacketCapture` evidence and fill MIME, size, SHA-256/hash map, safe import
path, and packet-capture collection metadata. Host import then parses bounded
PCAP/PCAPNG content into normalized `pcap.summary`, `pcap.flow`, `pcap.dns`,
`pcap.http`, and `pcap.tls` events when supported.

The host writes `artifact-index.json` beside `report.json` and `report.html`.
This `HostArtifactIndex` scans the job root for report files, `events.json`,
`driver-events.jsonl`, `artifacts/manifest.json`, `screenshots/*`,
`memory-dumps/*`, `.pcap` / `.pcapng`, and dropped files under `artifacts/*`.
Its `collections` list summarizes discovered lanes; for packet captures it
records `name=packet-captures`, `kind=PacketCapture`,
`status=captured`, `implemented=true` for import/report consumption,
`captureSource=external`, `hostCaptureStarted=false`,
`importMode=external-artifact`, artifact count, total bytes, and MIME types.
The HTML report has an **Artifact links** section that exposes indexed
artifacts with safe relative links when available, and falls back to copyable
paths from events when a link cannot be trusted.

## HTML sections

The HTML report is self-contained and renders the stable `AnalysisReport`
model into operator-facing sections:

- cover and table of contents;
- risk summary metrics for severities, rule hits, MITRE techniques, events,
  static tags, network, registry, dropped files, and R0/driver telemetry;
- behavior detections, MITRE detections, and engine/rule hits;
- static analysis with PE sections, grouped imports, exports, URL/IP
  indicators, registry/path indicators, resources/TLS, tags, warnings, and the
  complete bounded interesting-string list;
- dynamic analysis metrics;
- artifact links with safe relative links when available;
- timeline, process details/tree, dropped files, registry behavior, network
  behavior, R0/driver events, failure reasons, and raw normalized events.

Tables, chips, code fields, timeline entries, and evidence blocks expose
`data-copy` attributes. The local report script supports right-click copy and
explicit **Copy event** buttons without external dependencies.
