# Static analysis notes

These notes document the built-in `StaticAnalyzer` tag vocabulary. They are
reference material for rule authors and are not a production rule file.

For the analyzer contract, see `docs/static-analysis.md`; for behavior-rule
coverage and current counts, see `docs/behavior-rule-matrix.md`. Keep this file
focused on rule-author compatibility notes rather than duplicating analyzer or
report documentation.

## Compatibility contract

- Keep `Tags`, `Urls`, and `InterestingStrings` backward compatible.
- Add new tags as low-risk triage metadata unless there is strong static
  corroboration.
- Prefer prefixed evidence strings (`import:*`, `export:*`, `resource:*`,
  `tls:*`, `overlay:*`, `signature:*`, `debug:*`, `version:*`, `manifest:*`)
  so reports can group findings without schema changes.

## Low-risk metadata tags

The following tags should not be mapped to high severity by themselves:

- `debug_directory_present`, `debug_codeview_present`, `debug_rsds_present`,
  `debug_nb10_present`, `debug_pdb_path`, `debug_pdb_path_absolute`,
  `debug_pdb_build_path`, `debug_reproducible_build`, `debug_type_<type>`.
- `version_info_present`, `version_info_string`, `version_companyname`,
  `version_filedescription`, `version_fileversion`,
  `version_originalfilename`, `version_productname`.
- `manifest_resource_string`, `manifest_requested_execution_level`,
  `manifest_require_administrator`, `manifest_highest_available`,
  `manifest_auto_elevate`, `manifest_ui_access`.
- `security_directory_present`, `digital_signature_present`,
  `authenticode_signature_present`, `signature_pkcs_signed_data`.

## Packer and entropy guardrails

- `high_entropy_section`, `very_high_entropy_section`, and
  `overlay_high_entropy` are triage signals only.
- `packer_hint` is emitted only with packer section-name or known packer-string
  evidence. Keep it separate from high-entropy-only observations.
- Stronger packer review should look for multiple corroborating signals:
  unusual section names, high entropy, virtual-only/oversized sections,
  suspicious imports, TLS callbacks, and non-certificate overlay data.

## Static-analysis event projection

`StaticAnalyzer.AnalyzeToEvents()` and `StaticAnalyzer.CreateEvents()` expose a
bounded event view over the same `StaticAnalysisResult` without requiring any
external PE/YARA binaries. Event consumers should treat these as host-side
triage events, not as observed guest behavior.

- `static.analysis.completed` keeps the existing summary contract and adds
  counts for imports, exports, TLS callbacks, suspicious strings, packer hints,
  and YARA-like rule matches.
- `static.pe.section`, `static.pe.import.module`,
  `static.pe.import.cluster`, `static.pe.export`, `static.pe.tls.directory`,
  `static.pe.tls.callback`, and `static.pe.overlay` carry structured PE
  evidence such as entropy labels, API clusters, export names, callback VAs,
  and overlay entropy.
- `static.string.indicator`, `static.string.path`, `static.string.command`,
  and `static.string.suspicious` expose bounded URL/IP/domain/email, registry
  or filesystem paths, LOLBin/script strings, and suspicious string findings.
- `static.packer.hint` is a rollup event for `packer_*` tags.
- `static.yara.match` is emitted for each built-in lightweight YARA-like rule
  hit. Data fields include `ruleName`, `engine=builtin`, optional
  `matchedStringIds`, and optional metadata such as `scope`/`mitre`.
- Chinese diagnostics may be placed in `Data.zhMessage` and `Data.zhHint`; do
  not add new report schema fields for localization-only text.
- Rule-facing fields are string-valued and shared across static rows:
  `staticOnly`, `evidenceOrigin`, `evidenceKind`, `ruleScope`, `ruleKey`,
  `behaviorFamily`, and `triageLevel`. Rules should use these machine fields
  instead of parsing `message`/`zhMessage`.
- PE import rows may expose `hasProcessInjectionApi`, `hasDownloadApi`,
  `hasAntiDebugApi`, `hasCredentialAccessApi`, `hasDefenseEvasionApi`,
  `downloadExecCandidate`, `behaviorFamilies`, `primaryCapability`, and
  `mitreCandidates`.
- Export, TLS, overlay, and string rows may expose role fields such as
  `exportRole`, `executionPhase`, `overlayRole`, `indicatorRole`, `pathRole`,
  `commandRole`, `stringRole`, `antiDebugCandidate`, and
  `downloadExecCandidate`.

## Behavior-rule consumption guardrails

- Prefer concrete projection events (`static.pe.section`,
  `static.pe.import.*`, `static.pe.export`, `static.pe.tls.*`,
  `static.pe.overlay`, `static.string.*`, `static.packer.hint`, and
  `static.yara.match`) over broad `static.*` selectors.
- Keep `static.analysis.completed` as a backward-compatible summary/rollup.
  When a rule consumes both the summary and a granular event, report rendering
  should treat them as evidence for one rule finding rather than as separate
  findings.
- Resource-directory tags are available both in `static.analysis.completed`
  and granular `static.pe.resource` rows. Prefer `static.pe.resource` when the
  rule needs resource type, data RVA/file offset, size, entropy label,
  `resourceRole`, `isPayloadCandidate`, or `isEmbeddedPe`; keep the summary
  row only for backward-compatible rollups.
- YARA-like results should normally have one generic low-confidence consumer
  for `static.yara.match`. Add per-rule YARA behavior rules only when they are
  scoped by `Data.ruleName` and do not duplicate tag-based PE/string rules.
- Static-only rules should include explicit `confidence` and `evidenceFields`
  so analysts can distinguish host-side capability evidence from observed
  guest behavior.
- Do not promote `downloadExecCandidate` or `antiDebugCandidate` to high
  severity by itself. These fields mean the static string/import surface has
  enough structure for analyst attention; runtime command, process, file, R0,
  or network evidence should provide the confirming behavior.
- The release-prep rules `static-granular-download-exec-capability`,
  `static-granular-injection-capability`, and
  `static-granular-anti-debug-capability` consume structured `static.*` rows
  directly (`downloadExecCandidate`, `hasProcessInjectionApi`,
  `antiDebugCandidate`, `hasAntiDebugApi`, `primaryCapability`,
  `behaviorFamily`, and `ruleKey`). Keep these static-only rules at low or
  medium severity and low confidence; the corresponding high-confidence
  behavior rules require process, file, R0, HTTP/TLS/PCAP, or command-line
  evidence.

## R0 semantic field handoff

The R0Collector can emit parsed semantic fields that behavior rules should
prefer over brittle raw-string matches when available:

- Registry rows: `persistenceFamily`, `servicePersistenceCandidate`, and
  `ifeoPersistenceCandidate`.
- File rows: `dropLocationFamily` and `droppedFileCandidate`.
- Image rows: `imageLoadFamily` and `injectionCandidate`.
- Network rows: `networkEvidenceKind`, `lateralMovementCandidate`, and
  `downloadExecuteCandidate`.

These R0 fields are evidence shorthands, not final verdicts. R0-facing rules
should still include `evidenceFields` and explicit self-noise/health guards
such as `noise`, `selfNoise`, `collectorSelfNoise`, `collectorNoise`,
`healthStatus`, `vtStatus`, and sandbox-agent/collector process exclusions.
Do not globally exclude `source=r0collector` in rules whose purpose is to
consume parsed R0 rows; instead, require the semantic fields and suppress known
collector-health or self-noise markers.

For recent high-signal scoring rules, the v26 guard baseline is:
`behaviorCounted=false`, `nonbehavior=true`, `collectorSelfNoise=true`,
`collectorNoise=true`, `source=collection-health`, `source=virustotal`,
`source=r0collector`, and explicit `KSword.Sandbox.Agent.exe` /
`KSword.Sandbox.R0Collector.exe` process-name exclusions where those fields are
not the behavior being intentionally consumed. Treat open-source references
such as SigmaHQ, Elastic detection-rules, Splunk Security Content, and LOLBAS as
behavior-family inspiration only; keep KSword predicates expressed over local
event fields and add source-reference tags only through existing rule `tags`.

## Artifact-backed correlation handoff

Host artifact import can project safe, one-level fields onto
`artifact.host_imported` and imported `pcap.*` rows. Behavior rules should
prefer these fields when they need to prove that a finding can be traced back to
a concrete downloadable artifact:

- Artifact identity: `sourceArtifactKind`, `artifactKind`, `collectionName`,
  `evidenceRole`, `sourceEventType`, and `sourceEventPath`.
- Safe selectors: `sourceArtifactRelativePath`, `artifactRelativePath`,
  `downloadSelector`, `downloadSafeLink`, and `safeRelativeSelector`.
- Host-computed integrity and size: `sourceArtifactSha256`, `sha256`,
  `hash.sha256`, `sourceArtifactSizeBytes`, and `sizeBytes`.
- Correlation context: `processId`, `parentProcessId`, `rootProcessId`,
  `treeLineage`, `processName`, `commandLine`, and PCAP protocol/endpoint
  fields such as `protocol`, `host`, `uri`, `queryName`, `sni`,
  `destinationIp`, and `destinationPort`.

Rules that consume host-imported artifacts should not treat the mere presence of
`artifact.host_imported` as sample behavior. Require exact kind/collection/role,
path and hash fields, source event context, and explicit collection-health, VT
quiet-state, and R0 self-noise exclusions. Memory-dump and screenshot artifact
correlations are evidence metadata unless separate sample behavior proves
credential dumping or screen capture.

The built-in YARA-like matcher intentionally supports only the small subset
used by `rules/static-notes.yar`: literal/regex strings, `ascii`, `wide`,
`nocase`, `uint16(offset) == value`, `$id`, `any/all/N of (...)`, `of them`,
prefix string sets such as `$api*`, and boolean `and`/`or`/`not`. Unsupported
or malformed rules should downgrade silently so static analysis still returns.

## Persistence/string guardrails

- Service strings require concrete markers such as
  `CurrentControlSet\Services`, `ServiceDll`, `CreateService`,
  `ChangeServiceConfig`, `New-Service`, or `sc.exe create/config/failure`.
- Scheduled-task strings require Task Scheduler registry/path/API markers or
  `schtasks` with task-management switches such as `/create`, `/change`,
  `/tn`, `/tr`, or `/sc`.
- Generic words like `service` or `task` must not create static persistence
  findings.
- LOLBin strings should remain command/context evidence. Do not score a bare
  tool name as high-risk without command switches, URL/path evidence, or
  corroborating behavior.
