# Behavior rule matrix

This document describes the v1 behavior rules in `rules/behavior-rules.json`.
The matrix is intentionally conservative: rules classify normalized sandbox
events for reporting, but they do not by themselves prove malicious intent.

## Rule schema boundary

The current rule engine supports these stable predicates:

- `eventTypes`: exact, case-insensitive event type match.
- `containsPath`: case-insensitive substring match against `SandboxEvent.Path`.
- `containsCommandLine`: case-insensitive substring match against
  `SandboxEvent.CommandLine`.
- `dataKeys`: requires at least one configured key in `SandboxEvent.Data`.
- `dataContains`: case-insensitive substring match against configured data
  fields.

There is no source-specific predicate yet. Rows that mention driver or R0
events therefore rely on normalized event names and path/data evidence; report
readers should still inspect the event `source` field in the evidence table.

## Event sources

| Source | Producer | Current event examples | Report intent |
| --- | --- | --- | --- |
| `host` | Core planning and static analysis | `submission.accepted`, `hyperv.runbook.created`, `static.analysis.completed` | Show planning, sample identity, and static PE/string traits. |
| `guest` | `KSword.Sandbox.Agent` | `process.start`, `process.new`, `process.timeout`, `file.created`, `file.modified`, `file.deleted`, `driver.file`, `network.tcp` | Show behavior observed inside the VM during the analysis window. |
| `driver` | Guest-imported driver JSONL sidecar | `registry.set`, `file.created`, `file.modified`, future R0 events | Preserve kernel/driver evidence without changing Core/Web contracts. |
| `r0collector` | `KSword.Sandbox.R0Collector` lifecycle rows | `r0collector.deviceUnavailable`, `r0collector.driverHealth`, `r0collector.driverPoll`, `r0collector.driverReadEvents`, `r0collector.mockDriverEvent` | Distinguish collector health and synthetic plumbing events from sample behavior. |

## Rule groups

| Group | Rule IDs | Event types | Severity | MITRE mapping | Notes |
| --- | --- | --- | --- | --- | --- |
| Host planning | `host-submission`, `runbook-created` | `submission.accepted`, `hyperv.runbook.created` | `info` | None | Explains why a report exists and which execution plan was generated. |
| R0 collector health | `r0collector-device-unavailable`, `r0collector-driver-health`, `r0collector-ioctl-protocol-pending` | `r0collector.deviceUnavailable`, `r0collector.driverHealth`, `r0collector.driverPoll`, `r0collector.driverReadEvents`, `r0collector.ioctlProtocolPending` | `info` | None | Shows driver-open failures and successful health/poll/read IOCTL plumbing; the pending row is retained only for older local collector builds. |
| R0 synthetic plumbing | `r0collector-mock-driver-event` | `r0collector.mockDriverEvent` | `info` | None | Marks mock JSONL rows so report output stays clear during Guest Agent sidecar tests. |
| Process behavior | `script-interpreter`, `process-new`, `process-timeout-long-sleep` | `process.start`, `process.new`, `process.timeout` | `low` to `medium` | `T1059`, `T1497.003` | Separates generic new-process evidence from stronger scripting and timeout/evasion indicators. |
| Registry behavior | `registry-change`, `registry-run-key-persistence` | `registry.set`, `registry.create`, `registry.delete`, `driver.registry` | `medium` to `high` | `T1112`, `T1547.001` | Generic registry writes remain medium; Run/RunOnce autostart paths are high. |
| File behavior | `file-drop`, `file-deleted`, `executable-file-write` | `file.created`, `file.modified`, `file.deleted`, `driver.file` | `low` to `medium` | `T1070.004` where deletion applies | Executable/script extension matching makes driver and guest file-write rows easier to triage. |
| R0 driver heartbeat | `driver-load-heartbeat` | `driver.event.reserved`, `driver.load` | `info` | None | Shows that the R0 event drain path produced the driver startup self-test or future driver-load heartbeat. |
| Image-load placeholder | `image-load-placeholder` | `image.load`, `image.loaded`, `driver.imageLoad`, `driver.image.load` | `info` | None yet | Keeps future R0 image callback rows from appearing as unexplained raw events. |
| Network behavior | `network-connection` | `network.tcp` | `medium` | `T1105` | Records outbound TCP activity; richer DNS/HTTP/TLS rules should use structured data fields later. |
| Static PE traits | `static-pe-known-packer`, `static-pe-high-entropy-sections`, `static-embedded-url`, `static-pe-imports-present`, `static-pe-exports-present`, `static-pe-tls-callbacks` | `static.analysis.completed` | `info` to `medium` | `T1027.002`, `T1027`, `T1105` | Uses `dataContains.tags` emitted by static analysis for packers, entropy, URLs, import/export table presence, and TLS directory/callback hints. |
| Static import/API traits | `static-import-suspicious-api`, `static-import-process-injection`, `static-import-network-api`, `static-import-persistence-api`, `static-import-anti-analysis-api` | `static.analysis.completed` | `medium` to `high` | `T1106`, `T1055`, `T1105`, `T1112`, `T1622` | StaticAnalyzer maps parsed imports and fallback API strings into tags such as `import_suspicious_api`, `import_process_injection_api`, `import_network_api`, `import_persistence_api`, and `import_anti_analysis_api`. |
| Static export traits | `static-export-registration-entrypoint`, `static-export-service-entrypoint` | `static.analysis.completed` | `low` to `medium` | `T1218.010`, `T1543.003` | Export names are triage-only evidence; registration exports can indicate regsvr32-compatible DLL entry points, and service exports can support service DLL triage. |

## MITRE mapping notes

- `T1059` is used only when the command line references common Windows
  scripting interpreters.
- `T1112` covers generic registry modification. `T1547.001` is reserved for
  Run/RunOnce autostart paths because that evidence is more specific.
- `T1070.004` is used for file deletion because the current event does not yet
  prove cleanup intent, but it is still useful to surface in reports.
- `T1105` is retained for outbound TCP and embedded URL evidence as a seed
- `T1105` is retained for outbound TCP, embedded URL evidence, and static
  network/download API imports as a seed mapping until protocol-specific
  network rules exist.
- `T1055` is used only for static import groups that include process-injection
  primitives such as cross-process allocation/write/thread APIs.
- `T1106` covers broad native Windows API import/string evidence; more specific
  rules such as process injection, network transfer, persistence, and
  anti-analysis should take precedence in triage.
- `T1218.010` is used for static COM registration exports because those names
  are compatible with regsvr32-style execution, but the static rule does not
  prove that regsvr32 was actually used.
- `T1622` is used for debugger/timing import strings where static evidence
  suggests anti-analysis checks.
- Rules without MITRE IDs are intentionally unmapped because the current event
  is health, placeholder, or generic telemetry.

## Static-analysis tag contract

The current report model does not have first-class `imports`, `exports`, or
`tls` fields. StaticAnalyzer therefore records lightweight static depth through
existing fields:

- `Tags`: rule-facing tokens such as `imports_present`, `exports_present`,
  `tls_directory_present`, `tls_callbacks`, `import_suspicious_api`,
  `import_process_injection_api`, `import_network_api`,
  `export_registration_entrypoint`, `packer_section_name`, and
  `packer_string_hint`.
- `InterestingStrings`: bounded human-readable evidence such as
  `import:kernel32.dll!VirtualAllocEx`, `export:DllRegisterServer`, and
  `tls:callback@0x...`.
- `static.analysis.completed.Data["tags"]`: comma-joined `Tags` used by
  `dataContains.tags` predicates in `rules/behavior-rules.json`.

This keeps static coverage useful without changing public report contracts.
If a future Abstractions model adds structured `Imports`, `Exports`, or `Tls`
fields, keep these tags for backward-compatible rule matching and add structured
predicates separately.

## Future R0 expansion

When the driver event protocol is finalized, keep R0 events compatible with the
existing `SandboxEvent` model and add rules in small, auditable groups:

1. Normalize file callbacks to `file.created`, `file.modified`,
   `file.deleted`, and later `file.renamed`; include operation, status, and
   normalized path fields in `Data`.
2. Normalize registry callbacks to `registry.create`, `registry.set`, and
   `registry.delete`; add separate high-confidence rules for Run keys,
   services, IFEO, and shell extension persistence.
3. Normalize process/thread/image callbacks to `process.start`,
   `process.exit`, `thread.created`, and `image.load`; add image-load rules
   only after payload fields such as image path, signer, and process context are
   stable.
4. Normalize network/WFP evidence to protocol-specific events such as
   `network.tcp`, `network.udp`, `dns.query`, and `http.request` when those
   collectors exist.
5. Consider adding a source predicate to the rule schema before creating
   driver-only rules that cannot be safely distinguished by event type, path, or
   data fields alone.
