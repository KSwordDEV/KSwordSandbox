# Guest artifacts

Guest artifact collection is intentionally opt-in for high-sensitivity evidence.
The stable guest output root is the directory passed with `--out`.

## Layout

- `events.json` and `agent-summary.json` are always written.
- `artifacts/manifest.json` is always written as a safe evidence index. It can
  contain zero file artifacts when every sensitive collection lane is disabled.
- `screenshots/*.bmp` is written only when `--screenshot` is supplied and the
  guest desktop can be captured.
- `memory-dumps/*.dmp` is written only when `--memory-dump` or
  `--memory-dumps` is supplied.
- `artifacts/dropped-files/**` is written only when `--collect-dropped-files`
  or `--dropped-files` is supplied.
- `packet-captures/*.pcapng` is reserved for future PCAP import. The current
  agent only writes a `PacketCapture` collection placeholder when
  `--packet-capture`, `--pcap`, or `--network-capture` is explicitly supplied;
  it does not start a packet sniffer.

## Dropped-files manifest

When dropped-file collection is enabled, newly-created files under the sample
working directory are copied to `artifacts/dropped-files/**`. The guest then
writes `artifacts/manifest.json` using `ArtifactManifest` /
`ArtifactDescriptor` entries with `kind=DroppedFile`, `category=dropped-file`,
`evidenceRole=dropped-file`, `collectionName=dropped-files`, safe relative
links, `importPath`, file size, MIME type, SHA-256, and metadata preserving the
original VM-local path.

The manifest never trusts VM-local absolute paths for links. The host resolves
`relativePath` under the collected guest-output directory and keeps original
paths as metadata only.

## Screenshot artifacts

Screenshots are opt-in because they can contain desktop contents unrelated to
the sample. They are best-effort BMP files captured during `after-start` and
`after-run`. Unsupported or headless sessions emit `screenshot.skipped` instead
of failing the run. The guest manifest and host artifact index classify files
under `screenshots/` as `kind=Screenshot`, `category=screenshot`,
`evidenceRole=screenshot`, and `collectionName=screenshots`.

## Memory dump artifacts

Memory dump capture is **off by default** and requires explicit opt-in with
`--memory-dump` or `--memory-dumps`. The current implementation captures one
`MiniDumpNormal` for the launched sample process during `after-start` and writes
it under `memory-dumps/*.dmp`.

Dump files can contain credentials or document fragments. Host policy should
enable this option only for jobs where that evidence is required. Capture
failures emit `memory_dump.skipped`; they do not block event, screenshot, or
dropped-file artifact writing.

The guest manifest and host artifact index classify `memory-dumps/**` files as
`kind=MemoryDump`, `category=memory-dump`, `evidenceRole=memory-dump`, and
`collectionName=memory-dumps`.

## Collection lanes and import paths

`artifacts/manifest.json` includes `collections` entries for:

- `dropped-files`
- `screenshots`
- `memory-dumps`
- `driver-events`
- `r0-logs`
- `packet-captures`

Each collection records `enabled`, `implemented`, `status`, `reason`,
`relativePath`, `safeLink`, and `importPath`. Disabled lanes are explicit, so a
host importer can distinguish "not requested" from "requested but unavailable."
`packet-captures` is currently `implemented=false` unless a future collector
writes a `.pcap` or `.pcapng` file.

Each file descriptor also carries `evidenceRole`, `capturePhase`,
`captureState`, `guestPath`, `importPath`, and `collectionName` alongside size,
MIME type, and hashes. `guestPath` is evidence only; clickable links and import
paths are derived from safe paths under the collected guest output root.

## Future packet capture placeholder

`--packet-capture`, `--pcap`, and `--network-capture` are safe placeholders.
They emit `packet_capture.skipped` with `implemented=false` and reserve the
`packet-captures/` import path in the manifest. No real network packet capture
is performed by default or by the current placeholder.
