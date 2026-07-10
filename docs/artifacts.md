# Guest artifacts

Guest artifact collection is intentionally opt-in for high-sensitivity evidence.
The stable guest output root is the directory passed with `--out`.

## Layout

- `events.json` and `agent-summary.json` are always written.
- `screenshots/*.bmp` is written only when `--screenshot` is supplied and the
  guest desktop can be captured.
- `memory-dumps/*.dmp` is written only when `--memory-dump` or
  `--memory-dumps` is supplied.
- `artifacts/dropped-files/**` and `artifacts/manifest.json` are written only
  when `--collect-dropped-files` or `--dropped-files` is supplied.

## Dropped-files manifest

When dropped-file collection is enabled, newly-created files under the sample
working directory are copied to `artifacts/dropped-files/**`. The guest then
writes `artifacts/manifest.json` using `ArtifactManifest` /
`ArtifactDescriptor` entries with `kind=DroppedFile`, `category=dropped-file`,
safe relative links, file size, MIME type, SHA-256, and metadata preserving the
original VM-local path.

The manifest never trusts VM-local absolute paths for links. The host resolves
`relativePath` under the collected guest-output directory and keeps original
paths as metadata only.

## Screenshot artifacts

Screenshots are best-effort BMP files captured during `after-start` and
`after-run`. Unsupported or headless sessions emit `screenshot.skipped` instead
of failing the run. The host artifact index classifies files under
`screenshots/` as `Screenshot` artifacts.

## Memory dump artifacts

Memory dump capture is **off by default** and requires explicit opt-in with
`--memory-dump` or `--memory-dumps`. The current implementation captures one
`MiniDumpNormal` for the launched sample process during `after-start` and writes
it under `memory-dumps/*.dmp`.

Dump files can contain credentials or document fragments. Host policy should
enable this option only for jobs where that evidence is required. Capture
failures emit `memory_dump.skipped`; they do not block event, screenshot, or
dropped-file artifact writing.

The host artifact index classifies `memory-dumps/**` files as
`kind=Bundle`, `category=memory-dump`, and `evidenceRole=memory-dump` so the
path remains discoverable without changing shared artifact enum contracts.
