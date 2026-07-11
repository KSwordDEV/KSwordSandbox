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
  including disabled or future-placeholder lanes.
- `artifacts`: `ArtifactDescriptor[]`.

`ArtifactCollectionDescriptor` includes:

- `name`: stable lane name, for example `dropped-files`, `screenshots`,
  `memory-dumps`, `driver-events`, `r0-logs`, or `packet-captures`.
- `kind`: primary artifact kind for the lane.
- `category` and `evidenceRole`: stable grouping and evidence purpose.
- `relativePath`, `safeLink`, and `importPath`: safe paths under the collected
  guest output root.
- `enabled`: whether the operator requested the lane for this run.
- `implemented`: whether the collector can currently produce files. Future
  PCAP lanes use `implemented=false`.
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
`memory-dumps/**`, `driver-events.jsonl`, R0 diagnostic logs, and future
`packet-captures/**` files if a later collector produces them. It does not
start a PCAP collector today; `PacketCapture` is represented by a collection
placeholder and optional future import path.

## Host artifact index

The host writes `artifact-index.json` in the job root. The file is a
`HostArtifactIndex` with:

- `schemaVersion`
- `jobId`
- `rootPath`
- `producer`
- `generatedAtUtc`
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
- future `packet-captures/*.pcap` / `packet-captures/*.pcapng`
- dropped files under `artifacts/dropped-files/*`

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

Memory dumps and future packet captures are indexed by `artifact-index.json`
with `kind=MemoryDump` / `kind=PacketCapture`; the current HTML artifact-link
section focuses on events, driver JSONL, manifests, screenshots, and dropped
files.

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
manifest. These links are report-local `safeLink` anchors; original VM-local
paths remain copyable evidence only.
