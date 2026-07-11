# Guest artifacts

Guest artifact collection is intentionally opt-in for high-sensitivity evidence.
The stable guest output root is the directory passed with `--out`.

## Layout

- `events.json` and `agent-summary.json` are always written.
- `artifacts/manifest.json` is always written as a safe evidence index. It can
  contain zero file artifacts when every sensitive collection lane is disabled.
- `screenshots/*.bmp` is written only when `--screenshot` is supplied and the
  guest desktop can be captured. The default screenshot cadence is
  `before,during,after`; `--screenshot-phases` and `--screenshot-count` can
  narrow stages or capture multiple images per stage.
- `memory-dumps/*.dmp` is written only when `--memory-dump` or
  `--memory-dumps` is supplied. The current guest agent captures the sample
  root process early and then performs a final visible root/child process sweep
  so child processes can also produce dump artifacts.
- `artifacts/dropped-files/**` is written only when `--collect-dropped-files`
  or `--dropped-files` is supplied.
- `packet-captures/*.pcapng` is written only when `--packet-capture`, `--pcap`,
  or `--network-capture` is explicitly supplied and Windows `pktmon` can start
  capture inside the guest. Existing external `.pcap` / `.pcapng` files remain
  consumable by the host importer.

## Dropped-files manifest

When dropped-file collection is enabled, newly-created files under the sample
working directory are copied to `artifacts/dropped-files/**`. The guest then
writes `artifacts/manifest.json` using `ArtifactManifest` /
`ArtifactDescriptor` entries with `kind=DroppedFile`, `category=dropped-file`,
`evidenceRole=dropped-file`, `collectionName=dropped-files`, safe relative
links, `importPath`, file size, MIME type, SHA-256, and metadata preserving the
original VM-local path.

Copied dropped-file artifact descriptors always carry
`artifactRelativePath`, `relativePath`, `collectionName=dropped-files`,
`evidenceRole=dropped-file`, and `captureState=captured`. Skipped copy
attempts are nonfatal and keep a compact `reason` such as
`sourceFileMissing`, `outsideWorkingDirectory`, or `copyFailed`; collection
metadata keeps `lastReason` so a run with no copied files is diagnosable.

The manifest never trusts VM-local absolute paths for links. The host resolves
`relativePath` under the collected guest-output directory and keeps original
paths as metadata only.

## Screenshot artifacts

Screenshots are opt-in because they can contain desktop contents unrelated to
the sample. They are best-effort BMP files captured during the configured
`before,during,after` stages, which map to `before-start`, `after-start`, and
`after-run` probe phases. Unsupported or headless sessions emit
`screenshot.skipped` instead of failing the run. Screenshot events carry
`screenshotStage`, `screenshotIndex`, and `screenshotCount` metadata so the
manifest can preserve the configured cadence. The guest manifest and host
artifact index classify files under `screenshots/` as `kind=Screenshot`,
`category=screenshot`, `evidenceRole=screenshot`, and
`collectionName=screenshots`.

Screenshot events also carry `phase`/`capturePhase`, `captureState`,
`status`, `nonfatal`, `expectedRelativePath=screenshots/*.bmp`,
`artifactRelativePath` when a file is created, and `rootProcessId` /
`processId` when the sample process identity is known. Skipped screenshots
preserve `reason`, `diagnosticStage`, optional `exceptionType`, and optional
`win32Error` without failing the run.

## Memory dump artifacts

Memory dump capture is **off by default** and requires explicit opt-in with
`--memory-dump` or `--memory-dumps`. The current implementation captures a
`MiniDumpNormal` for the launched sample process during `after-start`, then
captures any still-visible child processes during an `after-run` process-tree
sweep. Dump attempts write under `memory-dumps/*.dmp`.

Dump files can contain credentials or document fragments. Host policy should
enable this option only for jobs where that evidence is required. Capture
failures emit `memory_dump.skipped`; they do not block event, screenshot,
packet-capture, or dropped-file artifact writing. The final
`memory_dump.sweep` event records visible/attempted/captured/skipped counts so
missing dump artifacts are explainable.

The guest manifest and host artifact index classify `memory-dumps/**` files as
`kind=MemoryDump`, `category=memory-dump`, `evidenceRole=memory-dump`, and
`collectionName=memory-dumps`.

Memory dump attempt events carry `phase`/`capturePhase`, `captureState`,
`status`, `nonfatal`, `artifactRelativePath` for captured dumps, and process
identity fields: `processId`, `rootProcessId`, `parentProcessId`,
`targetProcessName`, `targetProcessPath`, `processRole`, `treeDepth`,
`treeLineage`, `snapshotKey`, and `dumpType`. Skipped attempts preserve
`reason`, `diagnosticStage`, optional `exceptionType`, and optional
`win32Error`. Probe timeouts or exceptions are mapped to the `memory-dumps`
collection as nonfatal failed status instead of becoming `enabled-empty`.

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
`packet-captures` is an implemented opt-in lane for KSword's guest collector.
When capture is requested but `pktmon` is unavailable, access is denied, or ETL
conversion fails, the lane is marked `skipped` or `failed` and the run
continues. If a manifest or collected folder contains an externally supplied
`.pcap` or `.pcapng`, the host can still import and report it as
`kind=PacketCapture`.

When the host builds `artifact-index.json`, it merges the guest
`artifacts/manifest.json` and nearby `events.json` back into the filesystem
scan. The index keeps host-safe paths, host-computed size, and host-computed
SHA-256 as authoritative link fields, while preserving guest collection
`status`/`reason`, concrete skipped or failed reasons, command diagnostics,
original guest paths, process identity, and memory-dump root/child sweep
metadata in descriptor or collection `metadata`.

Collection metadata preserves nonfatal diagnostics consistently across
dropped files, screenshots, memory dumps, and packet captures. The guest
manifest records counts plus `lastReason`, `lastDiagnosticStage`,
`lastExceptionType`, `lastCommandMessage`, `lastArtifactRelativePath`,
`lastPhase` / `lastCapturePhase`, and `lastProcessId` / `lastRootProcessId`
when those values were present on related events. Host indexes also retain
guest status aliases such as `guestManifestStatus` / `guestManifestReason`
and `guestCollectionStatus` / `guestCollectionReason`.

Each file descriptor also carries `evidenceRole`, `capturePhase`,
`captureState`, `guestPath`, `importPath`, and `collectionName` alongside size,
MIME type, and hashes. `guestPath` is evidence only; clickable links and import
paths are derived from safe paths under the collected guest output root.

## Optional packet capture and external import

`--packet-capture`, `--pcap`, and `--network-capture` are explicit opt-in
switches. They start Windows `pktmon` before the sample runs, stop it after the
run, convert the ETL trace with `pktmon etl2pcap`, and write
`packet-captures/*.pcapng` when conversion succeeds. Raw ETL diagnostics stay
under `packet-capture-diagnostics/` and are not treated as packet-capture
artifacts.

Packet capture is still safe-by-default: no sniffer is started unless one of
the opt-in switches is present. Missing `pktmon`, insufficient rights, active
system capture conflicts, stop failures, or conversion failures emit
`packet_capture.skipped` or `packet_capture.failed`; they do not prevent
`events.json`, dropped files, screenshots, memory dumps, or the artifact
manifest from being written. Successful runs emit `packet_capture.started`,
`packet_capture.stopped`, and `packet_capture.captured`.

Packet capture lifecycle events carry `collectionName=packet-captures`,
`evidenceRole=packet-capture`, `phase`/`capturePhase`, `status`,
`captureState`, `nonfatal`, `expectedRelativePath=packet-captures/*.pcapng`,
and `artifactRelativePath` for the final PCAPNG path. ETL diagnostics are
separate from the packet artifact and use `etlRelativePath` /
`diagnosticRelativePath`. Start/stop/convert command failures retain
`reason`, command exit/timeout details, and `commandMessage`; a failed
`pktmon start` is reported as `packet_capture.failed`, while unavailable or
not-started cases remain `packet_capture.skipped`.

For import/report purposes, existing packet captures are regular artifacts:

- guest manifests can reference `packet-captures/*.pcap` or
  `packet-captures/*.pcapng` with `kind=PacketCapture`;
- host indexing also classifies any discovered `.pcap` or `.pcapng` file as
  packet-capture evidence, even when it was generated outside KSwordSandbox;
- descriptors expose MIME type (`application/vnd.tcpdump.pcap` or
  `application/x-pcapng`), `sizeBytes`, `sha256`, `hashes.sha256`,
  `collectionName=packet-captures`, and safe `importPath`;
- collection metadata records `captureSource=external`,
  `hostCaptureStarted=false`, `importMode=external-artifact`, artifact count,
  total bytes, and MIME types.

`ImportGuestEvents` parses discovered `.pcap` / `.pcapng` files into bounded
`pcap.*` events. Those imported events carry `collectionName=packet-captures`,
`importMode=external-artifact`, `sourceArtifactRelativePath`,
`sourceArtifactSizeBytes`, and `sourceArtifactSha256` so report findings remain
traceable back to the capture artifact.
