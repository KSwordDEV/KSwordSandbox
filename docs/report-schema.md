# Report schema

Canonical scope: this page owns the `AnalysisReport` JSON and rendered HTML
section contract. Artifact manifest/index schema details live in
`docs/artifact-manifest.md`; visual and interaction requirements live in
`docs/report-ux.md`; static-analysis evidence details live in
`docs/static-analysis.md`.

Generated `report.json`, `report.html`, `report.zh.html`, `report.en.html`,
raw events, artifact indexes, samples, payload binaries, VM outputs, packet
captures, and dumps are runtime outputs and must not be committed.

## JSON artifacts

The host writes `report.json` beside `report.html`, `report.zh.html`, and
`report.en.html` for every planned job. `report.html` is the compatibility
Simplified Chinese report, while `report.zh.html` and `report.en.html` are the
explicit localized report outputs. The JSON model is `AnalysisReport`:

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

导入 `events.json` 时，同一 guest 输出根目录下的相邻 `*.jsonl` 文件会合并进重新生成的
`report.json` 和 `report.html`。这包括 `r0collector.mockDriverEvent` 等 R0Collector
mock JSONL 行；它们保留为原始事件（raw events），带 `source=r0collector`，
保留 `data.mock=true` / `data.driverEventPath`，但不会触发行为规则 finding。
R0 mock/health/lifecycle 行只属于 R0 health/raw evidence lanes。Host 写出的
`guest.events.imported` 标记会把 `events.json` 行和导入的 JSONL 行都计入
`eventCount`，因此 smoke run 能证明最终报告确实包含 R0 mock sidecar。

R0Collector 自噪声是元数据，不是样本行为。若 driver-originated rows 的进程身份、
data 字段或路径指向 `KSword.Sandbox.R0Collector.exe`、
`KSword.Sandbox.Agent.exe`、collector staging directories 或 KSword driver
device，或事件显式标记 `behaviorCounted=false`、`nonbehavior`、
`notSampleBehavior`、`sampleBehavior=false` / `sampleBehaviorCandidate=false`，
这些行会保留在 `events` 和 raw HTML evidence 中，但会从 behavior counts、
behavior graphs 以及 file/registry/network/process behavior sections 中排除。
HTML R0 section 会单独报告 “Collector self-noise hidden / 已隐藏采集器自噪声”
计数并附示例，保证证据质量可审计，同时不会抬高行为数量。

## Artifact manifest evidence

Dropped files 和其他已复制证据使用
`KSword.Sandbox.Abstractions.Artifacts.ArtifactManifest`。Schema 如下：

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
artifacts with safe relative links when available. Safe `safeLink` /
`relativePath` values render as Open/Download buttons. Absolute host or guest
filesystem paths remain copyable evidence text only and are not emitted as
`href` values when a link cannot be trusted.

## HTML sections

The HTML report is self-contained and renders the stable `AnalysisReport`
model into operator-facing sections:

- cover and table of contents;
- risk summary metrics for severities, rule hits, MITRE techniques, events,
  static tags, network, registry, dropped files, and R0/driver telemetry,
  plus a compact collection/self-noise policy card that counts rows excluded
  from the behavior story (`behaviorCounted=false`, `nonbehavior`,
  collector self-noise, VT quiet states, and R0 health/readiness diagnostics)
  while keeping those rows visible in dedicated sections and raw events;
- behavior detections, MITRE detections, and engine/rule hits;
- static analysis with PE sections, grouped imports, exports, URL/IP
  indicators, registry/path indicators, resources/TLS, tags, warnings, and the
  complete bounded interesting-string list;
- dynamic analysis metrics;
- a behavior-story routing card that shows which normalized rows feed the
  sample-behavior graph/process/network/file/registry lanes and which rows stay
  in collection/VT/R0/raw evidence lanes because they are nonbehavior,
  `notSampleBehavior`, self-noise, or health/reputation metadata;
- artifact links with safe relative Open/Download buttons when available, with
  absolute local paths preserved only as copyable text, plus an artifact
  evidence-matrix narrative for dropped files, screenshots, memory dumps, and
  packet captures before the dense artifact table;
- timeline, process details/tree, dropped files, registry behavior, network
  behavior, R0/driver events, failure reasons, and raw normalized events;
- a bilingual entry bar linking sibling `report.zh.html`, `report.en.html`,
  and compatibility `report.html` files.

The behavior graph and process/network relationship cards are intentionally
weak-interaction/static. They separate collection metadata from sample behavior
with compact graph self-noise and behavior-routing cards: `behaviorCounted=false`,
`nonbehavior`, `notSampleBehavior`, collector self-noise, VT quiet states, and
R0 health/readiness rows remain in dedicated sections and raw normalized events,
but are not promoted into process tree or evidence-graph behavior. When the current
artifact index or normalized events already link evidence to a process,
endpoint, or edge, compact bilingual artifact badges are rendered on those
cards/edges; full descriptors, hashes, selectors, and safe Open/Download
actions remain in Artifact links and raw evidence.

Tables, chips, code fields, timeline entries, and evidence blocks expose
`data-copy` attributes. The local report script supports right-click copy and
explicit **Copy event** buttons without external dependencies.
The Simplified Chinese renderer localizes report chrome and operator guidance,
including headings, table headers, buttons, hints, section notes, empty states,
status labels, and evidence expander summaries. Normalized evidence remains in
its original form: `eventType`, API names, schema keys/values, hashes, paths,
command lines, stdout/stderr, and JSON/JSONL previews are preserved for
forensic copy/paste and schema compatibility.
Raw normalized events are collapsed by default; command/stdout/stderr/
PowerShell and similarly long technical fields are nested behind additional
copyable collapsed `<details>` blocks so the main report remains readable.
Evidence expanders include a bounded preview/summary before dense rows, and raw
event pagination remains capped (`75` inline rows, `25` rows per page) with
report.json/source artifacts as the complete record.
