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
- `producer`: writer component, for example `KSword.Sandbox.Agent`.
- `generatedAtUtc`: UTC generation timestamp.
- `artifacts`: `ArtifactDescriptor[]`.

Each `ArtifactDescriptor` includes:

- `kind`: enum such as `DroppedFile`, `Screenshot`, `GuestEventsJson`,
  `DriverEventsJsonLines`, or `ArtifactManifest`.
- `category`: stable lower-case grouping such as `dropped-file`,
  `screenshot`, `telemetry`, or `artifact-manifest`.
- `name`: file name only.
- `relativePath`: slash-separated path under the collected output root.
- `safeLink`: URL-encoded relative link derived only from safe relative path
  segments. Rooted paths and `..` traversal are not linkable.
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
- `events.json`
- `driver-events.jsonl`
- `artifacts/manifest.json`
- `screenshots/*`
- dropped files under `artifacts/*`

The HTML report consumes this index when available. If no index has been
provided, it still exposes artifact paths inferred from report events, but only
host-normalized relative paths receive clickable `safeLink` anchors.
