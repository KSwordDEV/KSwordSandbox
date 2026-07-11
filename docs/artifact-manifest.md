# Artifact manifest and host index

Artifact evidence uses the shared
`KSword.Sandbox.Abstractions.Artifacts` contracts.

## Guest manifest

The guest can write `artifacts/manifest.json` under the collected output root.
The file is an `ArtifactManifest`:

- `schemaVersion`: contract version, currently `1`.
- `jobId`: host job ID when known; guest manifests may leave it empty.
- `runtimeRoot`: producer-local output root.
- `rootPath`: producer-local artifact root.
- `importRoot`: root that host importers use to resolve descriptor
  `importPath` values. Guest manifests set it to the guest output root; host
  readers normalize it to the collected guest-output directory.
- `producer`: writer component, for example `KSword.Sandbox.Agent`.
- `generatedAtUtc`: UTC generation timestamp.
- `collections`: `ArtifactCollectionDescriptor[]` entries for collection lanes,
  including disabled, skipped, failed, and optional lanes.
- `artifacts`: `ArtifactDescriptor[]`.

`ArtifactCollectionDescriptor` includes:

- `name`: stable lane name, for example `dropped-files`, `screenshots`,
  `memory-dumps`, `driver-events`, `r0-logs`, or `packet-captures`.
- `kind`: primary artifact kind for the lane.
- `category` and `evidenceRole`: stable grouping and evidence purpose.
- `relativePath`, `safeLink`, and `importPath`: safe paths under the collected
  guest output root.
- `enabled`: whether the operator requested the lane for this run.
- `implemented`: whether the collector can currently produce files. The current
  guest packet-capture lane is implemented but remains explicit opt-in.
- `status`: `disabled`, `enabled-empty`, `captured`, `skipped`, `failed`, or
  `not-implemented`.
- `reason`: compact diagnostic reason for disabled/skipped/future lanes.
- `metadata`: string diagnostics such as artifact and event counts.

Each `ArtifactDescriptor` includes:

- `kind`: enum such as `DroppedFile`, `Screenshot`, `MemoryDump`,
  `PacketCapture`, `GuestEventsJson`, `DriverEventsJsonLines`, or
  `ArtifactManifest`.
- `category`: stable lower-case grouping such as `dropped-file`,
  `screenshot`, `telemetry`, or `artifact-manifest`.
- `name`: file name only.
- `relativePath`: slash-separated path under the collected output root.
- `safeLink`: URL-encoded relative link derived only from safe relative path
  segments. Rooted paths and `..` traversal are not linkable.
- `evidenceRole`: stable purpose such as `dropped-file`, `screenshot`,
  `memory-dump`, `driver-events`, or `packet-capture`.
- `capturePhase`: phase such as `after-start` or `after-run` when applicable.
- `captureState`: `captured`, `skipped`, `available`, or `failed`.
- `guestPath`: producer-local path kept as evidence only.
- `importPath`: safe path that a host importer resolves under `importRoot`.
- `collectionName`: collection lane that produced or owns the descriptor.
- `fullPath`: producer-local path before host normalization, or host path after
  collection.
- `mimeType`: deterministic content type such as `application/json`,
  `application/x-ndjson`, `image/bmp`, or `application/octet-stream`.
- `sizeBytes`: byte length when the file is present.
- `sha256`: primary SHA-256 digest.
- `hashes`: hash map; currently includes `sha256`.
- `createdAtUtc`: filesystem creation time when available.
- `metadata`: string metadata such as `origin=guest`,
  `evidenceRole=dropped-file`, and `guestFullPath`.

Guest manifests intentionally use relative paths for durable links. The host
preserves original VM-local absolute paths in metadata instead of trusting them
as link targets.

The current guest manifest writes descriptors for files already present below
the guest output root, including `artifacts/dropped-files/**`, `screenshots/**`,
`memory-dumps/**`, `driver-events.jsonl`, R0 diagnostic logs, and
`packet-captures/**` files. When `--packet-capture`, `--pcap`, or
`--network-capture` is supplied, the guest can start Windows `pktmon`, convert
ETL to PCAPNG, and produce `PacketCapture` descriptors with
`kind=PacketCapture`, `category=packet-capture`, `mimeType`, `sizeBytes`,
`sha256` / `hashes.sha256`, `evidenceRole=packet-capture`, and
`collectionName=packet-captures`. Missing tools, access denied, active capture
conflicts, stop failures, or conversion failures are represented by skipped or
failed collection status rather than failing the run.

If another tool has already placed a `.pcap` or `.pcapng` under the guest output
root and the manifest references it, the host reader still treats that file as
packet-capture evidence using the same safe descriptor fields.

## Host artifact index

The host writes `artifact-index.json` in the job root. The file is a
`HostArtifactIndex` with:

- `schemaVersion`
- `jobId`
- `rootPath`
- `producer`
- `generatedAtUtc`
- `collections`
- `artifacts`

The host index scans known job artifacts under the job root and records safe
relative links for:

- `report.json` / `report.html`
- localized reports such as `report.en.html` / `report.zh.html`
- `runbook.json` / `runbook-execution.json`
- `events.json` / `agent-summary.json`
- `driver-events.jsonl`
- `artifacts/manifest.json`
- `screenshots/*`
- `memory-dumps/*`
- `packet-captures/*.pcap` / `packet-captures/*.pcapng` files produced by the
  guest capture probe or supplied by another tool
- dropped files under `artifacts/dropped-files/*`

During the scan, the host reads collected guest `artifacts/manifest.json`
files and overlays matching descriptors by host-resolved full path. Host
`relativePath`, `safeLink`, `fullPath`, `sizeBytes`, and `sha256` remain
host-derived. Guest fields such as `guestPath`, `importPath`, `capturePhase`,
`captureState`, `collectionName`, process identity, original VM-local paths,
and extra `metadata` are retained. Collection lanes from the guest manifest are
also retained, including `enabled`, `implemented`, `status`, `reason`, and
metadata copies named `guestCollectionStatus` / `guestCollectionReason`.

The host also summarizes nearby guest `events.json` rows into artifact and
collection metadata. This keeps nonfatal evidence explainable even when no file
was created: `screenshot.skipped` and `packet_capture.failed` contribute
concrete `lastReason`, `lastDiagnosticStage`, or command fields, and
`memory_dump.sweep` contributes `sweepVisibleTargetCount`,
`sweepAttemptedCount`, `sweepCapturedCount`, `sweepSkippedCount`, and
`sweepAlreadyCapturedCount`.

Artifact references in events may be relative or absolute. The stable relative
keys are `artifactRelativePath`, `relativePath`, `importPath`,
`sourceArtifactRelativePath`, `driverEventsRelativePath`, `jsonlRelativePath`,
`stdoutRelativePath`, `stderrRelativePath`, `screenshotRelativePath`,
`memoryDumpRelativePath`, `dumpRelativePath`, `pcapRelativePath`,
`pcapngRelativePath`, `etlRelativePath`, and `diagnosticRelativePath`.
Absolute evidence keys such as `artifactFullPath`, `sourceArtifactFullPath`,
`driverEventsPath`, `stdoutPath`, `stderrPath`, `screenshotPath`,
`memoryDumpPath`, `dumpPath`, `pcapPath`, `pcapngPath`, `packetCapturePath`,
and `etlPath` are used only when they resolve under the collected guest output
root. R0 sidecar events use those fields so `driver-events.jsonl` and
`r0collector.*.log` receive metadata and hashes in the host index.

The scan also classifies any discovered `.pcap` or `.pcapng` file as
`PacketCapture` even when only the file is available and the manifest metadata
is missing. Packet capture descriptors include deterministic MIME
(`application/vnd.tcpdump.pcap` or
`application/x-pcapng`), byte size, SHA-256, safe relative import path, and
metadata such as `captureSource=external`, `hostCaptureStarted=false`,
`importMode=external-artifact`, and `collectionName=packet-captures`.

`HostArtifactIndex.collections` summarizes discovered lanes. For a filesystem
PCAP collection the host records `name=packet-captures`, `kind=PacketCapture`,
`status=captured`, `implemented=true` for import/report consumption, and
metadata such as artifact count, total bytes, MIME types, and
`external-pcap-artifacts-indexed`. The host-side indexer itself still does not
run a packet sniffer; capture is performed by the explicit guest-side pktmon
probe when requested.

Downloadable descriptor selectors are always job-relative. `relativePath` is
the canonical selector, `safeLink` is the URL-encoded report-link form, and
`importPath` is accepted as a compatibility selector for importers. WebUI
download URLs pass one of these values to the guarded
`/api/jobs/{jobId}/artifacts/download?path=...` endpoint. `fullPath` remains a
server-side stream source only and must not be emitted as an href. Absolute
paths, `..` traversal, and descriptors that cannot be resolved under the job
root are not downloadable.

The HTML report consumes this index when available. If no index has been
provided, it still exposes artifact paths inferred from report events, but only
host-normalized relative paths receive clickable `safeLink` anchors.

## HTML report links and evidence

`report.html` renders an **Artifact links** section for durable evidence that
operators need to open from the local job folder:

- `events.json`
- `driver-events.jsonl`
- `artifacts/manifest.json`
- `screenshots/*`
- dropped files under `artifacts/dropped-files/*`

Memory dumps and packet captures are indexed by `artifact-index.json` with
`kind=MemoryDump` / `kind=PacketCapture`; the current
HTML artifact-link section focuses on events, driver JSONL, manifests,
screenshots, and dropped files.

Each artifact row includes the safe relative link, kind/category, size, MIME,
SHA-256, and a collapsible **Artifact evidence** block. Text evidence artifacts
(`events.json`, `driver-events.jsonl`, and artifact manifests) include a bounded
preview. Screenshot artifacts include an inline preview that links to the image.
Dropped files are not previewed as text; their evidence expansion shows hashes,
size, safe path, and metadata such as `guestFullPath`.

Event tables also back-link to related artifacts. File events can link to
dropped-file artifacts through exact paths or `relativePath` data, screenshot
events link to screenshots, R0/driver events link to `driver-events.jsonl`, and
guest import events link to `events.json`, driver JSONL, and the artifact
manifest. When a report is opened directly from the job folder, these remain
report-local `safeLink` anchors. When the same report is served by WebUI through
`/api/jobs/{jobId}/report/html`, relative links are handled by
`/api/jobs/{jobId}/report/{relativeArtifactPath}` and resolved against the
host-side artifact index, so the browser can download or preview evidence
without being allowed to request arbitrary absolute host paths. The dedicated
index endpoint `GET /api/jobs/{jobId}/artifacts` exposes the same descriptors
with guarded download URLs for the dynamic monitor page.
