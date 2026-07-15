# Behavior rule matrix

This document describes the behavior rules in `rules/behavior-rules.json`.
The matrix is intentionally conservative: rules classify normalized sandbox
events for reporting, but they do not by themselves prove malicious intent.
As of the local v29 security/privilege coverage pass,
`rules/behavior-rules.json` contains 589 rules
with no duplicate IDs in the cheap JSON audit. The v29 pass confirms the new
security/process-access/token-privilege rules are consumable from current
normalized event types: Guest Security Event Log `security.*` rows such as
`security.privilege.token_adjusted`, `security.privilege.object_operation`, and
`security.process.created`, existing `process.access`/`process.open` rows, and
the existing R0-facing `r0.process`/`r0.thread` rule set. It also adds Chinese
operator text for the touched process-access rules and keeps self-noise and
nonbehavior boundaries intact. The v28 high/medium rules retain the host,
collection-health, VirusTotal quiet-state, R0 health/self-noise, and sandbox
plumbing process guards checked by the lightweight guard audit. The v28 batch adds 10 bounded
rules across WMI/COM persistence, hollowing and reflective-loader injection,
DCOM/WMI lateral movement, device/window anti-sandbox gates, and
Rundll32/InstallUtil download-execute chains. It uses public SigmaHQ, Elastic,
Splunk, and LOLBAS behavior families only as inspiration; the landed rules are
new KSword predicates over local fields, carry source-reference tags through
the existing `tags` metadata, and add explicit `sampleBehaviorCandidate=false`
exclusions alongside the v27/v26 self-noise baseline. The previous v27 batch
adds 10 bounded rules across IFEO/BITS persistence, DLL/APC injection,
SVCCTL/WinRM lateral movement, tool-enumeration and sleep-skew anti-sandbox
gates, and Certutil/Mshta download-execute chains. The earlier v26 self-noise
guard hardening kept rule volume unchanged and hardened recent high-signal
scoring rules against KSword collection/self-noise by adding explicit
`behaviorCounted=false`, `nonbehavior=true`, `collectorNoise=true`,
`collectorSelfNoise=true`, `source=r0collector`, `source=virustotal`,
`source=collection-health`, and sandbox agent/R0Collector process-name
exclusions where those guards reduce false positives without suppressing
positive sample events. The v29 handoff audit additionally confirms the v28
high/medium batch carries `source=host` and `r0SelfNoise=true` exclusions. The
v25 batch adds 8 constrained
rules over structured DNS answer scope, HTTP transfer hints, TLS certificate
CN/validity fields, host artifact evidence matrices and memory/screenshot/PCAP
selectors, and R0 backpressure/loss quality fields. The v23 batch adds 10 constrained
Windows sandbox rules across time-provider, Netsh helper, and screensaver
persistence; process doppelgänging/ghosting-style injection; DCOM and
PsExec-style SMB lateral movement; human-interaction and VM artifact
anti-sandbox gates; and Office remote-template download-execute chains. The
previous v22 defensive matrix adds 25 high-signal rules across
RunOnceEx/svchost/IFEO persistence, AtomBombing and remote-memory injection,
SMB/WinRM/WMI lateral movement, anti-sandbox gates, WebDAV/CAB/MSI/ADS
download-execute, CMSTP/MSBuild LOLBin execution, scheduled task/service
persistence, staging correlations, debugger-gated execution, and PowerShell
download-extract-launch chains. The v21/static readiness polish adds four
static PE metadata/parse/layout rules. The previous v20 high-signal
Windows behavior expansion raised coverage to 521 rules with 15 constrained
runtime and packet-derived rules across persistence, process injection, lateral
movement, anti-sandbox, download-execute, and C2/network behavior. New rules
require regex, same-field AND, all-field, exact, numeric, artifact/container,
process, network, or MITRE-specific protocol context instead of broad
substring-only matching, and every scoring rule carries explicit
collection-health, VirusTotal quiet state, sandbox-agent, and R0/self-noise
guards. The previous v19 artifact-correlation expansion raised coverage to 506
rules. It adds six
narrowly guarded rules for host-indexed memory dump,
dropped-file, screenshot, and PCAP artifact correlations, lineage-backed
process-tree execution, and exact `vtStatus=found` VirusTotal enrichment. These
rules require concrete artifact selectors, SHA-256/size metadata, process or
protocol context, and explicit collection-health, VT quiet-state, and R0
self-noise guards where they score behavior. The previous v18 release-prep
behavior expansion raised coverage to 500 rules. It added 22 guarded
rule/contract updates plus 10 direct R0 semantic-field consumers across
persistence, process injection, lateral movement, download-execute,
anti-sandbox gates, `static.*` consumption, and DNS/HTTP/TLS/PCAP semantics.
The R0-facing rules prefer stable parsed fields such as `persistenceFamily`,
`servicePersistenceCandidate`, `ifeoPersistenceCandidate`, `imageLoadFamily`,
`injectionCandidate`, `networkEvidenceKind`, `lateralMovementCandidate`,
`downloadExecuteCandidate`, `dropLocationFamily`, and `droppedFileCandidate`
before falling back to raw path or command text. The previous v17
release-facing behavior expansion raised
coverage to 468 rules. It added the original 38 runtime and packet-derived
behavior rules, 19 supplemental high-signal rules, and a 10-rule MVP gap-closure
batch across persistence, process injection, lateral movement, download-execute,
anti-sandbox gates, credential/exfil staging, and DNS/HTTP/TLS/PCAP triage. These rules are inspired
by public detection families such as SigmaHQ, Elastic detection rules, Splunk
Security Content, and MITRE ATT&CK technique semantics, but the KSword rules are
new sandbox predicates and do not copy upstream rule text. The previous
2026-07-11 v16 structured-static-event expansion raised coverage to 399 rules.
It keeps the existing `static.analysis.completed` tag contract and adds direct
rule consumption for `static.pe.import.module`, `static.pe.import.cluster`,
`static.string.*`, `static.packer.hint`, and `static.yara.match` rows as
low-confidence static triage. Reference-only static URL/domain rows stay
evidence-only, and static-only findings remain outside the primary runtime
behavior bucket. The previous v15 open-source-reference expansion raised
coverage to 398 rules. It landed a small set of Cuckoo/CAPE-style behavior
signatures, DRAKVUF/API-monitor dimensions, ATT&CK Windows mappings, and public
Sigma-style false-positive guards for Odbcconf, MMC, and named-pipe
impersonation evidence. These rules require command/API/path context and retain
explicit KSword/R0Collector/VirusTotal noise exclusions. The previous v14
combination-rule and MITRE-quality expansion raised coverage to 395 rules.
It added high-signal combinations for Run-key/dropper persistence, Defender
exclusion dropper evasion, security-tool discovery, credential-file search,
periodic C2 from user-writable payloads, anti-sandbox VM-check sleep gates,
and script-download dropped-file artifacts. It also maps hollowing and
LoadLibrary evidence to more specific process injection subtechniques. The
previous v13 advanced-predicate and
Windows-behavior expansion added regex, numeric-range, absent-field, and
same-field-AND predicates so rules can express command syntax, port/byte/count
thresholds, no-SNI/no-User-Agent cases, and high-signal field combinations
without broad substring fallbacks. The previous v12 targeted Windows behavior
and false-positive-control expansion added focused coverage for remote
script/proxy execution, NTDS/Kerberos/browser credential access,
Defender/UAC/PowerShell logging tamper, Office/browser persistence, WinRM
enablement, TLS dynamic-DNS/onion SNI, and authenticated HTTP exfil metadata.
New high-risk rules require runtime command, registry, file, HTTP, TLS, DNS,
or flow evidence and explicitly avoid collection health, R0 unavailable/self
noise, VirusTotal unset, and static-only weak signals. The previous v11
behavior expansion added all-of path, command-line, and data predicates so
high-risk behavior expansion can require concrete combinations instead of
promoting single weak fields. The previous v10 static/rule-quality expansion
added exact data-value predicates for status/verdict rules plus static domain,
download/upload, credential-access, and defense-evasion triage without
changing the public report model. The previous v9 rules/VT-quality expansion
added
targeted Windows persistence, privilege-escalation, process-injection,
PowerShell/LOLBin, DNS/HTTP/TLS/certificate, anti-analysis, and VirusTotal
enrichment-quality rules. The previous v8
report-semantic cleanup separated behavior findings from static triage and
collection diagnostics, and the v7 diagnostic-metadata reduction pass replaced
broad compatibility entries with concrete metadata, indicator, or
normalized-correlation rules for download/execute chains, process trees,
anti-analysis timing, DNS/TLS/PCAP evidence, and R0 image-load rows. Newer
rules may also carry metadata-only `confidence`, `tags`, `evidenceFields`,
`titleZh`, and `summaryZh` values to make report triage and rule reviews more
consistent.

## Rule schema boundary

The current rule engine supports these stable predicates:

- `eventTypes`: exact, case-insensitive event type match plus suffix-`*`
  prefix wildcards such as `security.*` and `etw.security.*`.
- `containsPath`: case-insensitive substring match against `SandboxEvent.Path`.
- `allContainsPath`: all configured substrings must appear in
  `SandboxEvent.Path`. This is used for constrained path pairs such as Startup
  folder plus executable/script extension.
- `pathRegex`: at least one timeout-bounded, case-insensitive regular
  expression must match `SandboxEvent.Path`.
- `containsCommandLine`: case-insensitive substring match against
  `SandboxEvent.CommandLine`.
- `allContainsCommandLine`: all configured substrings must appear in
  `SandboxEvent.CommandLine`. This is used for command patterns such as
  `net use` plus `/user:` plus an admin share.
- `commandLineRegex`: at least one timeout-bounded, case-insensitive regular
  expression must match `SandboxEvent.CommandLine`.
- `dataKeys`: requires at least one configured field. Fields first resolve
  against `SandboxEvent.Data`; stable top-level aliases such as `source`,
  `processName`, `path`, and `commandLine` are also available.
- `allDataKeys`: requires every configured field, for normalized correlation
  rows that need both source and target fields.
- `absentDataKeys`: requires every configured field to be absent. This is used
  for no-User-Agent, no-SNI, and no-referrer rules.
- `dataEquals`: case-insensitive exact match against configured data fields.
  This is used for status/verdict values where substring matching would be too
  broad, such as avoiding `not_malicious` matching a `malicious` verdict rule.
- `allDataEquals`: all configured data fields must exactly match one of their
  configured values.
- `dataContains`: case-insensitive substring match against configured data
  fields.
- `allDataContains`: all configured data fields must contain at least one of
  their configured substrings. This is used for combinations such as HTTP
  `POST` plus JSON content type before applying C2 URI labels.
- `dataContainsAll`: every configured field must contain every substring in
  that field's list. This is same-field AND for cases such as `wmic` plus
  `shadowcopy` plus `delete`.
- `dataRegex`: at least one configured field must match one timeout-bounded,
  case-insensitive regular expression.
- `allDataRegex`: every configured field must match one timeout-bounded,
  case-insensitive regular expression.
- `dataNumericRanges`: at least one configured field must parse as an
  invariant-culture finite number and fall within an inclusive range. Ranges
  can set `min`, `max`, `exclusiveMin`, and `exclusiveMax`.
- `allDataNumericRanges`: every configured numeric field must be present,
  parseable, and in range.
- `excludeProcessNames`: excludes matching process-image names after basename
  normalization and `.exe` trimming.
- `excludePathContains`: excludes path substrings.
- `excludeCommandLineContains`: excludes command-line substrings.
- `excludeDataEquals`: exact-match exclusion counterpart for `dataEquals`.
- `excludeDataContains`: substring exclusion counterpart for `dataContains`.

Predicate families are combined with AND. Non-`all*` lists and dictionaries are
still any-of within that family; `all*` predicates are the conservative
counterpart for rules that would otherwise be too broad.

Metadata-only fields do not affect matching:

- `confidence`: expected triage confidence (`low`, `medium`, or `high`) for
  the rule evidence shape.
- `titleZh` and `summaryZh`: Simplified Chinese operator text for new rule
  metadata. Older rules may not have these fields; the JSON stays compatible
  because the rule engine ignores unknown metadata fields.
- `tags`: report grouping hints such as `static`, `triage`, `collection`,
  `diagnostic`, and `metadata`; tags do not affect rule matching.
- `evidenceFields`: top-level or `data.*` fields analysts should inspect first
  when reviewing the finding.

There is still no dedicated source-only predicate, but data-style predicates
can resolve the top-level `source` alias for exclusions and constrained rules.
Rows that mention driver or R0 events still rely primarily on normalized event
names plus path/data evidence; report readers should inspect the event
`source` field in the evidence table.

## Event sources

| Source | Producer | Current event examples | Report intent |
| --- | --- | --- | --- |
| `host` | Core planning, provider execution persistence, static analysis, artifact import, and optional enrichment persistence | `submission.accepted`, `hyperv.runbook.*` / `vmware.runbook.*` / `qemu.runbook.*`, `static.analysis.completed`, `artifact.host_imported`, `enrichment.virustotal.lookup` | Show planning and provider execution outcomes, sample identity, static PE/string traits, host-indexed artifact correlation metadata, and external enrichment rows. |
| `guest` | `KSword.Sandbox.Agent` | `process.start`, `process.new`, `process.timeout`, `process.tree`, `process.tree_unavailable`, `service.*`, `scheduled_task.*`, `startup_item.*`, `file.created`, `file.modified`, `file.deleted`, `artifact.dropped_file.*`, `screenshot.*`, `memory_dump.*`, `dns.cache.*`, `network.tcp`, `network.netstat.*`, `network.udp.listener.*` | Show behavior and artifacts observed inside the VM during the analysis window. |
| `windowsEventLog` | Guest Security Event Log probe | `security.privilege.special_logon`, `security.privilege.service_called`, `security.privilege.object_operation`, `security.privilege.token_adjusted`, `security.process.created`, `security.token.assigned`, `security.service.installed`, `security.scheduled_task.*`, `security.account.*`, `security.group_member.*` | Preserve Windows Security audit context for sample-correlated process, privilege, token, service, scheduled-task, account, and group-change rows. Strongly correlated rows can support behavior rules; uncorrelated rows carry `behaviorCounted=false`/`nonbehavior=true` and stay context. |
| `driver` | Guest-imported driver JSONL sidecar | `driver.process`, `driver.file`, `driver.registry`, `driver.network`, `image.load`, legacy normalized `registry.set` / `file.created` | Preserve kernel/driver evidence without changing Core/Web contracts. |
| `pcap` / protocol importer | Future packet or flow post-processors | `pcap.summary`, `pcap.protocol.summary`, `pcap.flow`, `pcap.tcp`, `pcap.udp`, `pcap.http`, `pcap.dns`, `pcap.tls`, `network.pcap`, `pcap.packet`, `network.flow` | Reserve stable report buckets for packet-derived endpoint, DNS, HTTP, and TLS evidence before a first-class PCAP model exists. Rules key on normalized data fields rather than the `source` value, so imported PCAP-derived rows may still use host-side sources. |
| `r0collector` | `KSword.Sandbox.R0Collector` lifecycle rows | `r0collector.started`, `r0collector.deviceOpened`, `r0collector.heartbeat`, `r0collector.driverHealth`, `r0collector.driverPoll`, `r0collector.driverReadEvents`, `r0collector.ioctlFailure`, `r0collector.driverProtocolError`, `r0collector.stopped` | Distinguish collector health, failures, and synthetic plumbing events from sample behavior as collection/diagnostic metadata. |
| `virustotal` | Optional hash-only enrichment | `enrichment.virustotal.lookup`, `reputation.virustotal.file` | Preserve provider status/verdict/count/permalink metadata. Quiet states stay diagnostic; found/malicious/suspicious verdict rows remain external reputation, not local ATT&CK behavior. |

## PCAP importer field contract

The PCAP sidecar rules intentionally use the existing `SandboxEvent.Data`
dictionary rather than introducing a first-class packet model. The currently
reserved importer keys are covered by `dataKeys` or `dataContains` predicates:

- `pcap.summary`: `flowCount`, `packetCount`.
- `pcap.protocol.summary`: `protocol` or `protocols` when a sidecar emits
  aggregate protocol labels.
- `pcap.flow`: `sourceIp`, `sourcePort`, `destinationIp`,
  `destinationPort`, `protocol`.
- `pcap.dns`: `sourceIp`, `sourcePort`, `destinationIp`,
  `destinationPort`, `protocol`, `queryName`, `rcode`.
- `pcap.http`: `sourceIp`, `sourcePort`, `destinationIp`,
  `destinationPort`, `protocol`, `host`, `method`, `uri`, `contentType`,
  `payloadMagic`.
- `pcap.tls`: `sourceIp`, `sourcePort`, `destinationIp`,
  `destinationPort`, `protocol`, `sni`.
- Artifact-backed imported protocol rows can also carry
  `collectionName=packet-captures`, `sourceArtifactRelativePath`,
  `sourceArtifactSha256`, and `sourceArtifactSizeBytes`. Rules should require
  these fields before claiming a protocol row can be traced to a concrete
  PCAP/PCAPNG artifact.

Legacy aliases such as `srcIp`, `dstIp`, `url`, `requestUri`, `qname`, `ja3`,
and `tlsVersion` remain in the rule set for backward-compatible synthetic and
future parser rows.

## Rule groups

| Group | Rule IDs | Event types | Severity | MITRE mapping | Notes |
| --- | --- | --- | --- | --- | --- |
| Host planning and orchestration | `host-submission`, `runbook-created` | `submission.accepted`, `hyperv.runbook.created/executed/execution_result_error`, `vmware.runbook.created/executed/execution_result_error`, `qemu.runbook.created/executed/execution_result_error` | `info` | None | Explains why a report exists, which provider plan was generated, and whether provider execution evidence was imported successfully. |
| R0 collector health | none (not behavior-rule findings) | `r0collector.deviceUnavailable`, `r0collector.start_failed`, `r0collector.driverHealth`, `r0collector.driverPoll`, `r0collector.driverReadEvents`, `r0collector.started`, `r0collector.deviceOpened`, `r0collector.heartbeat`, `r0collector.stopped`, `r0collector.ioctlFailure`, `r0collector.driverProtocolError` | n/a | None | R0 health, lifecycle, mock, protocol, and backpressure rows are rendered in the R0 health/raw evidence lanes only. They are intentionally removed as behavior-rule finding sources so collection quality does not look like sample behavior. |
| VirusTotal enrichment | `virustotal-malicious-verdict`, `virustotal-suspicious-verdict`, `virustotal-found-result-enrichment`, `virustotal-not-found`, `virustotal-rate-limited`, `virustotal-not-configured` | `enrichment.virustotal.lookup`, `reputation.virustotal.file` | `info` to `high` | None | Consumes hash-only external reputation rows. `found` requires exact `vtStatus=found`, while not-found/rate-limited/not-configured remain quiet metadata and no VT rule receives an ATT&CK mapping. |
| Process behavior | `script-interpreter`, `process-new`, `process-timeout-long-sleep` | `process.start`, `process.new`, `process.timeout` | `low` to `medium` | `T1059`, `T1497.003` | Separates generic new-process evidence from stronger scripting and timeout/evasion indicators. |
| Security, privilege, and process-access telemetry | `security-privilege-telemetry-observed`, `process-access-debug-privilege`, `privilege-debug-backup-restore-enabled` | `security.*`, `security.privilege.*`, `security.token.*`, `etw.security`, `etw.security.*`, `etw.privilege`, `etw.privilege.*`, `process.access`, `process.token`, `privilege.enabled`, `api.call` | `info` to `high` | `T1055`, `T1134.001` where sensitive rights/privileges apply | Consumes current Security Event Log rows and ETW-style aliases. The context rule is info/low confidence; scoring rules require sensitive privilege names, token privilege lists, process access rights, API names, or Security `eventData.*` aliases such as `PrivilegeList`, `EnabledPrivilegeList`, `AccessMask`, and `ObjectName`. |
| Full process tree and launch context | `process-tree-observed`, `process-start-failed`, `process-tree-child-count-observed`, `lolbin-process-tree-node`, `execution-from-user-writable-tree-path`, `process-tree-lineage-user-writable-descendant` | `process.tree`, `process.start_failed`, `process.new`, `process.start` | `info` to `medium` | `T1204.002`, `T1218` where specific evidence applies | Surfaces root/depth/lineage/child-count rows, launch failures, LOLBin descendants, execution from user-writable staging paths, and lineage-backed user-writable descendants. `process.tree_unavailable` is retained as raw/probe diagnostic evidence only, not a behavior-rule finding. |
| Script execution behavior | `script-interpreter`, `script-file-executed` | `process.start` | `medium` | `T1059` | Matches interpreter names and script-like command-line extensions. |
| Script/LOLBin proxy expansion | `hh-compiled-help-remote-script-execution`, `msxsl-remote-xsl-script-execution`, `forfiles-script-proxy-execution` | `process.start` | `medium` to `high` | `T1202`, `T1218`, `T1220` | Adds constrained HH, MSXSL, and forfiles proxy-execution rules. Each rule requires the LOLBin plus remote/script or child-command evidence and excludes sandbox agent/R0 collector command self-noise. |
| Open-source reference LOLBin/API monitor expansion | `odbcconf-regsvr-user-writable-dll-proxy-execution`, `mmc-user-writable-msc-proxy-execution`, `named-pipe-impersonation-api-observed` | `process.start`, `process.new`, `api.call`, `named_pipe.impersonation`, `pipe.impersonation` | `high` | `T1218.008`, `T1218.014`, `T1134.001` | Lands public ATT&CK/Sigma-style ideas with sandbox-safe constraints: Odbcconf must use `REGSVR` plus a user-writable DLL, MMC must load a user-writable `.msc`, and named-pipe impersonation must include an impersonation API plus pipe name. |
| v28 behavior-rule expansion | `persistence-wmi-commandline-consumer-user-writable`, `persistence-com-scriptleturl-remote-clsid-hijack`, `injection-hollowing-unmap-write-setcontext-resume`, `injection-reflective-loader-user-writable-module`, `lateral-dcom-shellwindows-remote-script-launch`, `lateral-wmi-admin-share-payload-execution`, `anti-sandbox-device-object-probe-exit-gate`, `anti-sandbox-window-title-analysis-gate`, `download-execute-rundll32-mshtml-remote-script`, `download-execute-installutil-remote-assembly-launch` | `wmi.event_consumer`, `wmi.subscription`, `registry.*`, `driver.registry`, `api.sequence`, `process.hollowing`, `image.load`, `process.injection`, `dcom.activation`, `wmi.process_create`, `wmic.command`, `antiAnalysis.sandboxCheck`, `anti_sandbox.check`, `api.call`, `process.start`, `process.new`, `download.execute`, `behavior.download_execute` | `medium` to `high` | `T1546.003`, `T1546.015`, `T1055.012`, `T1055.001`, `T1021.003`, `T1047`, `T1497.001`, `T1218.011`, `T1218.004` | Adds a bounded SigmaHQ/Elastic/Splunk/LOLBAS-inspired batch without copying upstream rule text. Each rule requires multi-field regex, same-field AND, remote host, user-writable payload, device/window gate, or download/execution correlation evidence and carries v27 self-noise guards plus the v29 handoff aliases: `behaviorCounted=false`, `sampleBehaviorCandidate=false`, `nonbehavior=true`, host/collection/VT/R0 source exclusions, all four legacy noise markers, `r0SelfNoise=true`, and sandbox plumbing process exclusions. |
| v27 behavior-rule expansion | `persistence-ifeo-verifierdll-user-writable`, `persistence-bits-notifycmdline-user-writable`, `injection-createremotethread-loadlibrary-user-dll`, `injection-queueuserapc-loadlibrary-suspended-process`, `lateral-svcctl-remote-service-user-writable-binary`, `lateral-winrm-encoded-command-remote-target`, `anti-sandbox-tool-enumeration-gated-exit`, `anti-sandbox-sleep-skew-gated-execution`, `download-execute-certutil-urlcache-user-launch`, `download-execute-mshta-remote-scriptlet-user-payload` | `registry.set`, `registry.create`, `driver.registry`, `bits.job.*`, `api.call`, `api.sequence`, `process.injection`, `thread.remote`, `service.*`, `process.start`, `process.new`, `smb.pipe.open`, `pcap.smb`, `powershell.scriptblock`, `winrm.command`, `antiAnalysis.sandboxCheck`, `anti_sandbox.check`, `api.sleep`, `download.execute`, `behavior.download_execute` | `medium` to `high` | `T1546`, `T1197`, `T1055.001`, `T1055.004`, `T1569.002`, `T1021.006`, `T1497.001`, `T1497.003`, `T1105`, `T1218.005` | Adds a coherent SigmaHQ/Elastic/Splunk/LOLBAS-inspired batch without copying upstream rule text. Every rule requires multi-field regex, same-field AND, numeric threshold, remote-host, user-writable payload, or download/execution correlation evidence and carries v26 guards for collection-health, VT quiet states, R0/collector self-noise, and sandbox plumbing process names. |
| Advanced PowerShell and command syntax | `powershell-encoded-command-base64-regex`, `powershell-amsi-bypass-scriptblock-field-and`, `wmic-shadowcopy-delete-field-and`, `wevtutil-log-clear-command-regex`, `bcdedit-recovery-ignoreallfailures-command` | `process.start`, `process.new`, `powershell.scriptblock`, `scriptblock.text`, `api.call` | `high` | `T1059.001`, `T1070.001`, `T1490`, `T1562.001` | Uses regex and same-field-AND predicates for EncodedCommand base64 payloads, AMSI bypass script blocks, WMIC shadow-copy deletion, event-log clearing, and recovery-policy tamper. Agent/R0Collector command self-noise and collection-health metadata are excluded. |
| v23 high-signal Windows behavior expansion | `persistence-time-provider-user-writable-dll`, `persistence-netsh-helper-user-writable-dll`, `persistence-screensaver-executable-user-writable`, `injection-process-doppelganging-transaction-sequence`, `injection-process-ghosting-delete-pending-section`, `lateral-dcom-excel-application-remote-launch`, `lateral-smb-psexesvc-pipe-or-service`, `anti-sandbox-human-interaction-gated-exit`, `anti-sandbox-vm-service-registry-probe-gate`, `download-execute-office-remote-template-launch` | `registry.set`, `registry.create`, `driver.registry`, `api.call`, `api.sequence`, `behavior.injection`, `process.hollowing`, `process.image`, `process.start`, `process.new`, `smb.pipe.open`, `pcap.smb`, `antiAnalysis.sandboxCheck`, `anti_sandbox.check`, `behavior.anti_analysis`, `download.execute`, `behavior.download_execute` | `medium` to `high` | `T1547.003`, `T1546`, `T1546.002`, `T1055`, `T1021.003`, `T1021.002`, `T1497.001`, `T1105` | Adds a bounded MITRE/Sigma/Elastic/Splunk-inspired batch without copying upstream rule text. Each rule requires regex or same-field/all-field context on registry paths, user-writable payload paths, API sequences, remote host/COM metadata, SMB named-pipe fields, anti-sandbox gates, or Office remote-template launch correlation, with collection-health, VT quiet-state, sandbox-agent, and R0/self-noise exclusions. |
| v22 defensive matrix and static readiness | `static-section-virtual-layout-anomaly`, `static-pe-signature-metadata-present`, `static-pe-parse-warning-observed`, `static-pe-zero-entrypoint`, `persistence-runonceex-depend-dll-value`, `persistence-svchost-servicedll-user-writable`, `persistence-ifeo-globalflag-silentprocessexit`, `injection-atom-bombing-api-sequence`, `injection-writeprocessmemory-followed-by-protect-execute`, `injection-setthreadcontext-suspended-target`, `lateral-smb-admin-share-executable-write`, `lateral-winrm-wsman-create-shell-soap`, `lateral-smb-svcctl-pipe-open`, `anti-sandbox-low-interaction-count-gate`, `anti-sandbox-vm-mac-oui-check`, `anti-sandbox-resource-threshold-exit`, `download-execute-webdav-lolbin-url`, `download-execute-temp-cab-msi-chain`, `download-execute-ads-zoneidentifier-executable-launch`, `lolbin-cmstp-remote-inf-proxy-execution`, `lolbin-msbuild-inline-task-user-writable-project`, `persistence-service-failurecommand-user-writable`, `persistence-scheduled-task-comhandler-user-writable`, `lateral-wmi-win32-process-create-remote-host`, `lateral-winrm-invoke-command-remote-scriptblock`, `staging-archive-extract-script-user-writable`, `staging-hidden-script-then-lolbin-launch-correlation`, `anti-analysis-debugger-check-exit-gate`, `download-execute-iwr-expand-start-chain` | `static.pe.section`, `static.pe.signature`, `static.pe.parse_warning`, `static.analysis.completed`, `registry.set`, `registry.create`, `driver.registry`, `api.call`, `api.sequence`, `behavior.injection`, `file.created`, `file.modified`, `smb.file.write`, `http.request`, `pcap.http`, `network.http`, `smb.pipe.open`, `pcap.smb`, `anti_sandbox.check`, `process.start`, `process.new`, `download.execute`, `artifact.dropped_file.copied` | `low` to `high` | Static triage plus `T1546`, `T1547`, `T1055`, `T1021`, `T1047`, `T1053.005`, `T1497`, `T1105`, `T1197`, `T1218` where runtime evidence applies | Records the current v22 rule delta. Static PE rows remain low-confidence triage. Runtime rules require constrained command/path/data/artifact context and keep collection-health, VT quiet-state, sandbox-agent, and R0/self-noise exclusions. |
| v20 high-signal Windows behavior expansion | `persistence-silentprocessexit-monitorprocess-user-writable`, `persistence-print-processor-user-writable-dll`, `persistence-winsock-provider-user-writable-dll`, `injection-early-bird-apc-suspended-resume-sequence`, `injection-process-herpaderping-delete-pending-image`, `lateral-winrm-wsman-remote-shell-command`, `lateral-smb-atsvc-named-pipe-task-registration`, `lateral-rdp-tscon-system-session-hijack`, `anti-sandbox-firmware-wmi-vm-gate`, `anti-sandbox-short-uptime-exit-gate`, `download-execute-mounted-image-lnk-payload`, `download-execute-script-interpreter-motw`, `c2-websocket-upgrade-nonbrowser-user-agent`, `c2-doh-post-high-entropy-query`, `c2-mtls-client-cert-rare-ja3` | `registry.set`, `registry.create`, `driver.registry`, `api.call`, `process.image`, `thread.remote`, `driver.thread`, `http.request`, `network.http`, `pcap.http`, `pcap.smb`, `smb.pipe`, `network.flow`, `process.start`, `process.new`, `antiAnalysis.sandboxCheck`, `system.uptime`, `download.execute`, `network.tls`, `tls.connection`, `pcap.tls` | `high` | `T1546`, `T1546.012`, `T1547.012`, `T1055`, `T1055.004`, `T1021.001`, `T1021.006`, `T1053.005`, `T1497.001`, `T1497.003`, `T1204.002`, `T1071.001`, `T1071.004`, `T1573` | Adds high-signal Windows rules for SilentProcessExit, Print Processor, and Winsock provider persistence; early-bird APC and delete-pending image mutation injection; WSMan, ATSVC named-pipe, and TSCON lateral movement; firmware/uptime anti-sandbox gates; mounted-image/MOTW script download-execute; and WebSocket, DoH, and mTLS C2. Each rule requires regex/all-of/exact/numeric context and explicit collection, VT, sandbox-agent, and R0 self-noise exclusions. |
| Persistence behavior | `registry-run-key-persistence`, `service-registry-persistence`, `service-create-command`, `scheduled-task-persistence`, `tasks-folder-file-write`, `startup-folder-persistence`, `ifeo-debugger-persistence`, `winlogon-persistence`, `driver-registry-run-key-typed-persistence`, `driver-registry-service-typed-persistence`, `scheduled-task-registry-cache-persistence`, `driver-registry-taskcache-typed-persistence`, `wmi-event-subscription-persistence`, `wmi-event-subscription-command`, `com-hijack-persistence`, `appinit-dlls-persistence`, `lsa-security-provider-persistence` | `registry.set`, `registry.create`, `driver.registry`, `process.start`, `file.created`, `file.modified`, `driver.file` | `high` | `T1547.001`, `T1547.004`, `T1543.003`, `T1053.005`, `T1546.012`, `T1546`, `T1112` | Covers Run/RunOnce keys, service registry paths and service creation commands, scheduled-task command/folder evidence, Startup folder writes, IFEO and Winlogon helper values, WMI subscription artifacts, COM hijacks, AppInit DLLs, and LSA package paths. |
| Constrained persistence expansion | `persistence-startup-folder-lnk-or-script`, `persistence-service-script-lolbin-imagepath`, `persistence-shell-open-command-hijack`, `persistence-winlogon-user-writable-payload`, `persistence-scheduled-task-hidden-user-writable` | `file.created`, `file.modified`, `driver.file`, `registry.set`, `registry.create`, `driver.registry`, `service.created`, `service.modified`, `scheduled_task.created`, `scheduled_task.modified` | `high` | `T1547.001`, `T1547.004`, `T1543.003`, `T1053.005`, `T1546` | Uses all-of path/data predicates and query-operation exclusions so Startup, service, shell-open-command, Winlogon, and hidden scheduled-task persistence requires payload or user-writable context rather than a bare registry path. |
| Regex-constrained service and task persistence | `suspicious-service-imagepath-user-writable-regex`, `suspicious-scheduled-task-payload-regex` | `registry.set`, `registry.create`, `driver.registry`, `scheduled_task.created`, `scheduled_task.modified` | `high` | `T1543.003`, `T1053.005` | Adds regex-backed checks for service ImagePath and scheduled-task payloads under user-writable locations. Query/read registry operations and sandbox/collector metadata remain excluded. |
| 2026-07-12 persistence expansion | `persistence-lsa-authentication-package-registry`, `persistence-appinit-dlls-registry`, `persistence-appcert-dlls-registry`, `persistence-bootexecute-registry-autocheck`, `persistence-time-providers-registry-dll`, `persistence-wmi-event-subscription-registry-or-event`, `persistence-com-hijack-inprocserver-user-writable`, `persistence-print-monitor-registry-dll`, `persistence-active-setup-stubpath`, `persistence-powershell-profile-user-writable`, `persistence-logon-script-user-writable`, `persistence-screensaver-scr-user-writable` | `registry.set`, `registry.create`, `driver.registry`, `wmi.subscription`, `wmi.event_consumer`, `file.created`, `file.modified`, `driver.file` | `medium` to `high` | `T1547.002`, `T1546.010`, `T1546.009`, `T1547.001`, `T1547.003`, `T1546.003`, `T1546.015`, `T1547.010`, `T1547.014`, `T1546.013`, `T1037.001`, `T1546.002` | Adds release-facing autostart surfaces for LSA authentication packages, AppInit/AppCert DLLs, BootExecute, Time Providers, WMI event subscriptions, COM InprocServer hijacks, print monitors, Active Setup, PowerShell profiles, logon scripts, and screensaver payloads. |
| Cross-category combination rules | `combo-persistence-runkey-dropped-payload`, `combo-defense-evasion-defender-exclusion-dropped-payload`, `combo-discovery-security-tool-process-list`, `combo-credential-file-search-user-profile`, `combo-c2-user-writable-payload-periodic-flow`, `combo-anti-sandbox-vm-check-long-sleep`, `combo-dropped-file-script-download-artifact` | `registry.set`, `registry.create`, `driver.registry`, `process.start`, `process.new`, `network.flow`, `pcap.flow`, `antiAnalysis.sandboxCheck`, `api.sleep`, `artifact.dropped_file.copied` | `medium` to `high` | `T1547.001`, `T1562.001`, `T1518.001`, `T1552.001`, `T1071.001`, `T1497.003`, `T1105` | Requires paired path/data/regex/numeric/correlation evidence across persistence, defense evasion, discovery, credential access, C2, anti-sandbox, and dropped-file categories. Agent/R0Collector process names, command lines, collection-health fields, and VT unset rows are excluded. |
| Office and browser persistence expansion | `office-macro-security-weakened-registry`, `outlook-form-homepage-persistence`, `browser-extension-policy-persistence`, `browser-native-messaging-host-registry`, `browser-native-messaging-host-manifest-file`, `ie-browser-helper-object-user-writable` | `registry.set`, `registry.create`, `driver.registry`, `file.created`, `file.modified`, `driver.file` | `high` | `T1137`, `T1176` | Adds Office macro/Protected View weakening, Outlook forms/homepage persistence, browser extension policy force-install, native-messaging host registration/manifest files, and IE BHO/toolbar hooks. Registry rules exclude query-only operations; file rules exclude sandbox plumbing and normal browser process writes where appropriate. |
| System inventory diff persistence | `service-system-change-created`, `service-system-change-suspicious-command`, `scheduled-task-system-change-created`, `scheduled-task-suspicious-target`, `startup-item-system-change-created`, `startup-item-executable-value`, `persistence-system-item-deleted`, `system-diff-truncated` | `service.created`, `service.modified`, `service.deleted`, `scheduled_task.created`, `scheduled_task.modified`, `scheduled_task.deleted`, `startup_item.created`, `startup_item.modified`, `startup_item.deleted`, `*.diff_truncated` | `info` to `high` | `T1543.003`, `T1053.005`, `T1547.001`, `T1070.004` | Uses the current system-change probe’s service/task/startup diffs to catch persistence created or changed after launch, suspicious payload targets, deleted persistence entries, and truncation diagnostics. |
| Registry behavior | `registry-change`, `registry-run-key-persistence`, `service-registry-persistence`, `service-imagepath-or-dll-registry-change`, `scheduled-task-registry-cache-persistence`, `ifeo-debugger-persistence`, `winlogon-persistence`, `wmi-event-subscription-persistence`, `com-hijack-persistence`, `appinit-dlls-persistence`, `lsa-security-provider-persistence`, `r0-driver-registry-change-signal` | `registry.set`, `registry.create`, `registry.delete`, `driver.registry` | `medium` to `high` | `T1112`, `T1547.001`, `T1547.004`, `T1546.012`, `T1546`, `T1543.003` | Generic registry writes remain medium; Run/RunOnce, service, TaskCache, IFEO, Winlogon, WMI subscription, COM, AppInit, and LSA paths are high. |
| File behavior | `file-drop`, `file-deleted`, `executable-file-write`, `temp-executable-drop`, `script-file-drop`, `system-directory-executable-write`, `tasks-folder-file-write`, `startup-folder-persistence`, `downloaded-file-zone-identifier`, `browser-download-cache-write`, `download-archive-or-script-stage`, `r0-driver-file-write-signal` | `file.created`, `file.modified`, `file.deleted`, `driver.file`, `driver.file.*` | `low` to `high` | `T1070.004`, `T1105`, `T1059`, `T1053.005`, `T1547.001` where specific evidence applies | Executable/script extension, Temp/AppData/System32/Tasks/Startup paths, browser/download cache paths, Zone.Identifier metadata, staged archives/scripts, and driver file-operation metadata make guest and R0 file-write rows easier to triage. |
| Ransomware and recovery inhibition | `ransomware-shadow-copy-deletion-command`, `ransomware-recovery-configuration-disable-command`, `ransomware-ransom-note-file-created`, `ransomware-encrypted-extension-rename`, `ransomware-encryption-classified-file-event` | `process.start`, `file.created`, `file.modified`, `driver.file`, `driver.file.rename`, `driver.file.setinfo`, `driver.file.write`, `artifact.dropped_file.copied` | `high` | `T1486`, `T1490` | Adds ransomware-specific impact rules for shadow-copy/recovery deletion commands, ransom-note filenames, encrypted-extension rename operations, and explicit ransomware/encryption file classifications. These rules require command, path, operation, or classification evidence and exclude sandbox collection paths. |
| Numeric burst impact metadata | `ransomware-mass-file-write-burst-numeric`, `registry-mass-runkey-change-burst-numeric` | `file.activity`, `file.burst`, `driver.file.summary`, `registry.activity`, `registry.summary`, `driver.registry.summary` | `high` | `T1486`, `T1547.001` | Uses numeric thresholds plus classification/path-scope regex so high-volume file writes or registry sets are elevated only when paired with ransomware/encryption or Run-key persistence context. |
| Screenshot, memory, and dropped-file artifacts | `screenshot-captured-artifact`, `screenshot-capture-skipped`, `memory-dump-captured-artifact`, `memory-dump-capture-skipped`, `dropped-file-artifact-copied`, `dropped-file-artifact-skipped`, `dropped-executable-artifact-copied`, `artifact-manifest-written`, `artifact-memory-dump-process-correlation`, `artifact-dropped-file-source-correlation`, `artifact-screenshot-capture-correlation`, `file-masquerading-double-extension` | `screenshot.captured`, `screenshot.skipped`, `memory_dump.captured`, `memory_dump.skipped`, `artifact.dropped_file.copied`, `artifact.dropped_file.skipped`, `artifact.manifest.written`, `artifact.host_imported`, `file.created`, `file.modified`, `driver.file` | `info` to `medium` | `T1105`, `T1036` where payload or masquerading evidence applies | Keeps opt-in screenshots, minidumps, released dropped files, copied executable/script/archive artifacts, manifest rows, and double-extension masquerading visible. The v19 host-imported artifact rules require safe relative selectors, SHA-256/size fields, exact collection/kind/evidence role, and source event context before creating correlation findings. |
| Injection behavior | `remote-thread-injection-observed`, `process-injection-memory-primitive`, `process-injection-thread-or-apc-primitive`, `process-hollowing-signal`, `rwx-memory-protection-change`, `dll-injection-loadlibrary-signal` | `process.remote_thread`, `thread.remote`, `driver.thread`, `process.memory`, `process.write_memory`, `memory.protect`, `driver.process`, `api.call`, `image.load` | `medium` to `high` | `T1055`, `T1055.001`, `T1055.012` | Covers normalized remote-thread/APC events plus memory allocation/write, thread/APC, hollowing, RWX protection, and LoadLibrary-style DLL injection primitives. |
| Constrained injection context | `injection-remote-thread-into-sensitive-process`, `injection-early-bird-apc-primitive`, `injection-section-map-remote-execute`, `injection-loadlibrary-remote-thread-target`, `injection-all-access-sensitive-process-handle` | `security.privilege.object_operation`, `process.remote_thread`, `thread.remote`, `driver.thread`, `api.call`, `process.memory`, `driver.process`, `process.open`, `process.access` | `high` | `T1055`, `T1055.001`, `T1055.002` | Requires target-process, target function, section-map, APC, or sensitive-process handle context so static imports or bare API names do not become strong injection findings. Security object-operation rows use `eventData.ObjectName` and `eventData.AccessMask` aliases. |
| 2026-07-12 injection expansion | `injection-r0-cross-process-vm-write`, `injection-r0-remote-thread-create`, `injection-queue-user-apc-remote-process`, `injection-section-map-executable-remote`, `injection-suspended-process-hollowing-sequence`, `injection-lsass-cross-process-handle`, `injection-create-remote-thread-startaddress-rwx`, `injection-mapview-section-unbacked-execute`, `injection-setwindowshookex-user-writable-dll`, `injection-thread-context-hijack-sequence`, `injection-module-stomping-write-execute` | `security.privilege.object_operation`, `r0.process`, `driver.process`, `process.memory`, `process.write_memory`, `api.call`, `r0.thread`, `driver.thread`, `process.remote_thread`, `thread.remote`, `process.hollowing`, `process.start`, `process.open`, `process.access` | `high` | `T1055`, `T1055.001`, `T1055.002`, `T1055.003`, `T1055.004`, `T1055.012`, `T1003.001` | Adds kernel/driver, Security object-operation, and API monitor evidence for cross-process memory writes, remote threads, APC injection, executable section mapping, hollowing sequences, LSASS handle access, RWX remote-thread starts, unbacked executable section maps, hook DLL injection, thread context hijacking, and module stomping. |
| Lateral movement behavior | `psexec-or-remote-service-lateral-command`, `winrm-powershell-remoting-lateral-command`, `admin-share-or-remote-copy-command`, `wmi-remote-execution-command`, `remote-scheduled-task-command`, `smb-network-port-observed`, `winrm-network-port-observed` | `process.start`, `network.tcp`, `network.udp`, `driver.network`, `pcap.tcp`, `pcap.udp`, `network.flow` | `medium` to `high` | `T1021.002`, `T1021.006`, `T1047`, `T1053.005`, `T1569.002`, `T1570` | Covers PsExec/remote service, WinRM/PowerShell remoting, admin-share staging, WMI/CIM remote execution, remote scheduled tasks, SMB ports, and WinRM ports. |
| Constrained lateral movement commands | `lateral-net-use-admin-share-credentials`, `lateral-wmic-remote-process-create`, `lateral-remote-schtasks-create-or-run`, `lateral-psexec-service-drop-file`, `lateral-remote-registry-run-or-service-add`, `winrm-remote-management-enabled-command` | `process.start`, `file.created`, `file.modified`, `driver.file`, `artifact.dropped_file.copied` | `high` | `T1021.002`, `T1021.006`, `T1047`, `T1053.005`, `T1112`, `T1570` | Adds all-of command/path rules for admin-share credentials, WMIC remote process creation, remote scheduled tasks, PsExec service staging, remote registry persistence, and explicit WinRM/PowerShell remoting enablement. Port-only lateral rules remain triage. |
| 2026-07-12 lateral movement expansion | `lateral-admin-share-copy-executable`, `lateral-psexec-service-imagepath`, `lateral-winrm-process-with-remote-target`, `lateral-wmi-process-call-create-remote`, `lateral-rdp-shadow-or-restrictedadmin-command`, `lateral-dcom-mmc20-remote-execution-command`, `lateral-sc-remote-service-start-or-control`, `lateral-wmi-remote-process-create-with-credentials`, `lateral-schtasks-remote-run-with-credentials`, `lateral-rdp-restrictedadmin-registry-enable` | `file.created`, `file.modified`, `driver.file`, `artifact.dropped_file.copied`, `registry.set`, `registry.create`, `driver.registry`, `process.start`, `process.new` | `medium` to `high` | `T1021`, `T1021.001`, `T1021.002`, `T1021.003`, `T1021.006`, `T1047`, `T1053.005`, `T1569.002` | Adds release-facing coverage for admin-share executable staging, PsExec service ImagePath evidence, WinRM remote targets, WMI process creation against remote hosts, RDP shadow/RestrictedAdmin command evidence, DCOM MMC20 command execution, remote service control via sc.exe, credentialed WMIC/schtasks remoting, and RestrictedAdmin registry enablement. |
| Numeric remote-management ports | `network-smb-outbound-admin-port-numeric`, `network-rdp-outbound-port-numeric`, `network-winrm-outbound-port-numeric`, `network-tor-socks-listener-port-numeric` | `network.tcp`, `driver.network`, `pcap.flow`, `pcap.tcp`, `network.tcp.listener.opened`, `network.udp.listener.opened`, `network.netstat.added` | `medium` | `T1021.001`, `T1021.002`, `T1021.006`, `T1090` | Uses numeric ranges for SMB 445, RDP 3389, WinRM 5985/5986, and Tor/SOCKS 9050/9150 listener ports. These remain medium-confidence network behavior unless paired with command or file evidence. |
| Extended discovery and lateral movement | `rdp-network-port-observed`, `ssh-network-port-observed`, `ldap-kerberos-network-port-observed`, `tor-or-proxy-port-observed`, `admin-share-file-path-observed`, `remote-desktop-command-observed`, `network-share-discovery-command`, `system-discovery-command`, `process-discovery-command`, `network-discovery-command` | `process.start`, `file.created`, `file.modified`, `file.open`, `driver.file`, `network.tcp`, `network.udp`, `network.netstat`, `network.netstat.added`, `driver.network`, `pcap.tcp`, `pcap.udp`, `network.flow` | `medium` to `high` | `T1016`, `T1018`, `T1021.001`, `T1021.004`, `T1049`, `T1057`, `T1082`, `T1090`, `T1135`, `T1570` | Adds RDP/SSH/LDAP/Kerberos/domain-service ports, proxy/Tor ports, admin-share file paths, Remote Desktop commands, and common system/process/network/share discovery commands. |
| R0 driver callback signals | `r0-driver-process-event`, `r0-driver-file-write-signal`, `r0-driver-registry-change-signal`, `r0-driver-network-signal`, `image-load-metadata-observed` | `driver.process`, `driver.file`, `driver.registry`, `driver.network`, `image.load` | `info` to `medium` | `T1105`, `T1112` where specific evidence applies | Keeps typed R0 process/file/registry/network/image callback rows visible in findings when they carry sample-correlated behavior context. Driver startup heartbeat/reserved self-test rows are R0 health evidence only, not behavior-rule findings. |
| Image-load metadata | `image-load-metadata-observed` | `image.load`, `image.loaded`, `driver.imageLoad`, `driver.image.load` | `info` | None | Requires image/module path, process, base-address, or system-image metadata so R0 image callback rows are visible without matching every bare event-type stub. |
| Download-execute behavior | `powershell-evasion-download-abuse`, `script-interpreter-network-download`, `mshta-script-proxy-execution`, `regsvr32-scriptlet-proxy-execution`, `download-execute-chain-observed`, `execution-from-downloads-or-staging-path` | `process.start`, `behavior.download_execute`, `download.execute`, `file.downloaded.executed` | `high` | `T1059.001`, `T1218.005`, `T1218.010`, `T1105` | Covers script/LOLBin download primitives, mshta/regsvr32 URL/scriptlet execution, process starts from download/staging paths, and normalized correlation rows for downloaded artifacts executed in the same analysis window. |
| Constrained download-execute expansion | `download-powershell-outfile-user-writable`, `download-curl-to-user-writable-path`, `download-certutil-urlcache-user-writable`, `downloaded-file-executed-with-path-correlation`, `rundll32-remote-scriptlet-execution` | `process.start`, `behavior.download_execute`, `download.execute`, `file.downloaded.executed` | `high` | `T1105`, `T1218.011` | Requires downloader command tokens plus user-writable output paths, or both downloaded/executed path fields on normalized correlation rows. Static URL strings and standalone file writes remain lower-confidence triage. |
| 2026-07-12 download-execute expansion | `download-execute-certutil-urlcache-split`, `download-execute-bitsadmin-transfer`, `download-execute-powershell-webclient-to-user-writable`, `download-execute-mshta-or-regsvr32-remote-scriptlet`, `download-execute-rundll32-url-dll-entrypoint`, `download-execute-wscript-cscript-remote-script-url`, `download-execute-artifact-hash-launch-correlation`, `download-execute-msiexec-remote-package`, `download-execute-curl-wget-shell-chain`, `download-execute-http-response-mz-launch-correlation` | `process.start`, `process.new`, `behavior.download_execute`, `download.execute`, `file.downloaded.executed` | `high` | `T1105`, `T1197`, `T1218.005`, `T1218.007`, `T1218.011` | Adds concrete downloader/LOLBin command shapes for Certutil URL cache staging, BITS transfers, PowerShell WebClient downloads to user-writable paths, remote scriptlets, Rundll32 URL/DLL entrypoint execution, WSH remote script execution, hash-backed downloaded-artifact launch correlation, remote MSI execution, curl/wget shell chains, and HTTP MZ launch correlation. |
| Network behavior | `network-connection`, `http-network-activity`, `dns-query-observed`, `udp-network-activity`, `tls-or-https-network-activity`, `network-ip-literal-observed`, `driver-network-outbound-connect`, `driver-network-dns-traffic`, `driver-network-web-protocol-or-port`, `r0-driver-network-signal` | `network.tcp`, `network.udp`, `http.request`, `network.http`, `network.tls`, `tls.connection`, `dns.query`, `network.dns`, `driver.network` | `low` to `medium` | `T1105`, `T1071.001`, `T1071.004` | Records outbound TCP/UDP plus protocol-specific HTTP/DNS/TLS rows and driver network payloads when normalized collectors provide them. |
| Network probe depth | `dns-cache-added`, `dns-cache-txt-or-tunnel`, `dns-cache-dynamic-domain`, `netstat-connection-observed`, `netstat-added-connection`, `network-listener-opened`, `network-nonstandard-listener-port`, `network-connection-closed` | `dns.cache.added`, `network.netstat`, `network.netstat.added`, `network.netstat.removed`, `network.tcp.listener.opened`, `network.udp.listener.opened`, `network.tcp.closed` | `info` to `high` | `T1049`, `T1071.004`, `T1571` where specific evidence applies | Uses current TCP/DNS/netstat/listener probe output to report new DNS cache entries, tunnel-capable records, dynamic domains, opened listeners, suspicious listener ports, and short-lived closed connections. Generic `network.netstat` rows are collection metadata; only `network.netstat.added` carries the netstat discovery behavior mapping. |
| C2, DNS, TLS, and PCAP metadata | `network-c2-beacon-event`, `network-c2-indicator-fields`, `dns-tunnel-or-dga-indicator`, `http-c2-suspicious-user-agent`, `tls-sni-ja3-metadata-observed`, `pcap-artifact-imported`, `pcap-protocol-summary-placeholder`, `pcap-flow-observed`, `pcap-http-request-observed`, `pcap-dns-query-observed`, `pcap-tls-clienthello-observed`, `artifact-pcap-protocol-correlation`, `dns-dynamic-domain-pattern`, `http-direct-ip-or-nonstandard-port` | `network.c2`, `c2.beacon`, `beacon.observed`, `http.request`, `network.http`, `network.tls`, `tls.connection`, `dns.query`, `network.dns`, `dns.cache.added`, `driver.network`, `pcap.summary`, `pcap.protocol.summary`, `network.pcap`, `pcap.packet`, `pcap.flow`, `pcap.tcp`, `pcap.udp`, `pcap.http`, `pcap.dns`, `pcap.tls`, `network.flow` | `info` to `high` | `T1071.001`, `T1071.004`, `T1573` where protocol-specific evidence exists | Adds explicit C2/beacon event support, C2 indicator fields, DNS tunnel/DGA indicators, suspicious HTTP user agents, TLS SNI/JA3/certificate metadata, direct-IP/nonstandard web port triage, and PCAP artifact/flow/HTTP/DNS/TLS metadata without changing collectors. The artifact-backed PCAP rule requires source artifact path/hash/size and `collectionName=packet-captures`; compatibility IDs such as `pcap-protocol-summary-placeholder` are retained because existing report/smoke contracts reference them, but their titles, tags, and Chinese summaries now describe concrete diagnostic metadata. |
| Constrained C2 correlation | `c2-http-script-user-agent-beacon-uri`, `c2-http-post-json-tasking`, `c2-dns-txt-high-entropy-label`, `c2-tls-no-sni-with-risky-ja3`, `c2-network-flow-classified-periodic-checkin`, `c2-ja3-sni-domain-fronting-correlation`, `c2-beacon-sni-ja3-process-correlation` | `http.request`, `network.http`, `pcap.http`, `dns.query`, `network.dns`, `pcap.dns`, `network.tls`, `tls.connection`, `pcap.tls`, `network.flow`, `pcap.flow` | `high` | `T1071.001`, `T1071.004`, `T1090`, `T1573` | Uses all-of predicates for user-agent plus beacon URI, POST plus JSON content plus tasking URI, TXT/NULL plus high-entropy classification, no-SNI plus JA3 reputation, domain-fronting Host/SNI/JA3 correlation, and periodicity plus explicit C2 classification tied to a user-writable process path. Timing fields, user-agent strings, or packet counters alone are not enough. |
| Targeted HTTP/TLS exfil and infrastructure | `tls-sni-dynamic-dns-or-onion`, `http-post-auth-cookie-or-token-exfil` | `network.tls`, `tls.connection`, `pcap.tls`, `http.request`, `network.http`, `pcap.http` | `high` | `T1041`, `T1071.001` | Adds TLS SNI/serverName dynamic-DNS or `.onion` infrastructure triage and a constrained HTTP POST rule that requires credential/token material in headers, body, or classification fields. VT unset and collection-health rows are excluded through data exclusions. |
| Advanced HTTP/TLS/DNS predicates | `pcap-http-large-upload-numeric`, `dns-very-long-nxdomain-query-numeric`, `http-direct-ip-missing-user-agent`, `tls-ja3-without-sni`, `http-uri-api-gate-field-and` | `http.request`, `network.http`, `pcap.http`, `dns.query`, `network.dns`, `pcap.dns`, `dns.cache.added`, `network.tls`, `tls.connection`, `pcap.tls` | `medium` to `high` | `T1041`, `T1071.001`, `T1071.004` | Adds numeric upload/query-length thresholds, IPv4-literal host regex with absent User-Agent, JA3 regex with absent SNI/serverName, and same-field API gate URI matching. These rules exclude VT unset and collection-health metadata. |
| HTTP/TLS/PCAP deep triage | `http-executable-download`, `http-post-or-checkin-beacon`, `http-doh-request`, `http-proxy-or-tunnel-method`, `tls-invalid-certificate`, `tls-encrypted-clienthello-or-esni`, `pcap-executable-payload`, `pcap-dns-nxdomain-or-dga`, `pcap-upload-or-exfil-indicator`, `pcap-flow-count-metadata-observed` | `http.request`, `network.http`, `pcap.http`, `network.tls`, `tls.connection`, `pcap.tls`, `pcap.dns`, `dns.query`, `network.dns`, `pcap.flow`, `network.flow`, `pcap.packet`, `pcap.summary` | `low` to `high` | `T1041`, `T1071.001`, `T1071.004`, `T1090`, `T1105`, `T1573` where specific evidence applies | Adds executable/script/archive downloads, POST/check-in paths, DNS-over-HTTPS, HTTP tunnel/proxy methods, invalid/self-signed certificates, ECH/ESNI metadata, PE payload markers, NXDOMAIN/DGA DNS, upload/exfil labels, and packet/flow count metadata. |
| 2026-07-12 DNS/HTTP/TLS/PCAP expansion | `pcap-dns-txt-long-label-exfil`, `pcap-dns-nxdomain-burst-dga`, `pcap-http-executable-download-magic`, `pcap-http-post-beacon-small-periodic`, `pcap-http-host-header-ip-or-suspicious-tld`, `pcap-tls-self-signed-or-invalid-cert`, `pcap-tls-sni-ip-literal-or-dga`, `pcap-tls-no-sni-rare-ja3`, `network-pcap-smb-session-setup-admin-share` | `pcap.dns`, `dns.query`, `network.dns`, `dns.cache.added`, `pcap.http`, `http.response`, `http.request`, `network.http`, `pcap.tls`, `network.tls`, `tls.connection`, `pcap.smb`, `pcap.flow`, `network.flow`, `network.tcp`, `driver.network` | `medium` to `high` | `T1048.003`, `T1568.002`, `T1105`, `T1071.001`, `T1573.002`, `T1021.002` | Adds packet-derived release signals for DNS TXT/long-label exfil, NXDOMAIN/DGA bursts, HTTP executable payload magic, small periodic POST beacons, suspicious Host/SNI metadata, invalid/self-signed TLS, rare JA3/no-SNI combinations, and SMB admin-share session setup evidence. |
| Anti-analysis behavior | `process-timeout-long-sleep`, `anti-analysis-debugger-check`, `anti-analysis-vm-artifact-query`, `anti-analysis-delay-api-observed`, `anti-analysis-system-fingerprint-command`, `anti-analysis-process-enumeration-command`, `anti-analysis-hardware-registry-query`, `anti-analysis-timing-command`, `anti-analysis-sandbox-artifact-command`, `anti-analysis-user-activity-check`, `anti-analysis-cpuid-api-observed`, `anti-analysis-mac-disk-fingerprint-command`, `anti-analysis-sleep-duration-metadata`, `anti-analysis-window-or-tool-check-api`, `anti-analysis-low-resource-check`, `anti-analysis-accelerated-sleep-metadata` | `process.timeout`, `antiAnalysis.debuggerCheck`, `antiAnalysis.sandboxCheck`, `debugger.detected`, `sandbox.detected`, `registry.query`, `file.open`, `process.query`, `api.call`, `process.start`, `driver.registry`, `system.fingerprint`, `antiAnalysis.sleep`, `api.sleep` | `medium` to `high` | `T1497`, `T1497.001`, `T1497.003`, `T1622` | Covers timeout/sleep evasion, explicit debugger/sandbox check events, VM/tool artifact queries, hardware/process enumeration, CPU/hypervisor checks, MAC/disk fingerprinting, duration and sleep-acceleration metadata, user-activity checks, and low-resource telemetry keys. |
| Constrained anti-analysis expansion | `anti-analysis-sandbox-tool-process-enumeration`, `anti-analysis-debug-object-flags-query`, `anti-analysis-low-resource-classification`, `anti-analysis-sleep-skipped-or-fast-forwarded`, `anti-analysis-human-interaction-gate-api` | `process.query`, `api.call`, `driver.process`, `antiAnalysis.sandboxCheck`, `antiAnalysis.debuggerCheck`, `system.fingerprint`, `antiAnalysis.sleep`, `api.sleep` | `medium` | `T1497.001`, `T1497.003`, `T1622` | Requires runtime tool names, debug flag/object strings, explicit low-resource classifications, explicit sleep-skip/fast-forward fields, or user-interaction APIs. Plain `process.timeout` and generic inventory fields stay low-confidence or unmapped. |
| 2026-07-12 anti-sandbox expansion | `anti-sandbox-cpuid-hypervisor-check`, `anti-sandbox-vm-registry-key-query`, `anti-sandbox-analysis-tool-process-query`, `anti-sandbox-long-sleep-or-time-skew`, `anti-sandbox-low-resource-exit-gate`, `anti-sandbox-sleep-acceleration-ratio-mismatch` | `antiAnalysis.sandboxCheck`, `sandbox.detected`, `api.call`, `r0.cpu`, `driver.process`, `registry.query`, `registry.open`, `driver.registry`, `process.query`, `process.start`, `process.new`, `process.timeout`, `antiAnalysis.sleep`, `api.sleep`, `system.fingerprint` | `medium` | `T1497.001`, `T1497.003` | Adds CPUID/hypervisor, VM registry-key, analysis-tool process query, long-sleep/time-skew checks, low-resource exit gates, and sleep acceleration ratio mismatches as medium-confidence anti-sandbox indicators. |
| Numeric anti-analysis timing | `anti-analysis-long-sleep-duration-numeric`, `process-tree-high-child-count-numeric` | `api.sleep`, `antiAnalysis.sleep`, `process.timeout`, `process.tree` | `medium` | `T1497.003`, `T1059` | Uses numeric thresholds for long sleep durations and unusually large process-tree child counts. These rules are runtime metadata and do not depend on static strings. |
| Defense evasion and security tooling | `anti-analysis-security-tool-termination-command`, `defender-disable-command`, `defender-policy-registry-disable`, `security-tool-stop-or-kill-command`, `firewall-defense-disable-command`, `event-log-clearing-command`, `amsi-etw-bypass-command-string` | `process.start`, `registry.set`, `registry.create`, `driver.registry` | `high` | `T1562.001`, `T1562.004`, `T1070.001`, `T1497` | Flags Defender disable/exclusion commands, Defender policy registry writes, EDR/security-tool stop or kill tokens, firewall disablement, event-log clearing, and AMSI/ETW bypass strings. |
| Targeted Defender, UAC, and PowerShell logging controls | `defender-service-disabled-registry-start`, `defender-realtime-disable-registry-value`, `defender-exclusion-registry-user-writable`, `powershell-security-logging-disabled-registry`, `uac-policy-weakened-registry`, `uac-local-account-token-filter-policy`, `uac-silentcleanup-env-hijack` | `registry.set`, `registry.create`, `driver.registry` | `high` | `T1021`, `T1548.002`, `T1562.001` | Adds exact value-name/value constraints for Defender service disablement, Defender realtime-disable policy values, user-writable Defender exclusions, PowerShell logging policy disables, UAC policy weakening, remote UAC token-filter changes, and SilentCleanup windir hijack. Query-only registry operations and sandbox/collector metadata are excluded. |
| Collection and concealment extras | `screenshot-api-observed`, `hidden-file-attribute-command` | `api.call`, `process.start` | `medium` to `high` | `T1113`, `T1564.001` | Flags screen-capture API primitives and `attrib` hidden/system attribute commands separately from sandbox-generated screenshot artifacts. |
| Credential and LSASS behavior | `lsa-security-provider-persistence`, `lsass-memory-dump-command`, `lsass-process-access-observed`, `credential-store-access-observed`, `credential-dumping-tool-command`, `credential-lsass-process-access`, `credential-lsass-dump-command`, `credential-sam-system-hive-access`, `credential-hive-save-command`, `credential-browser-store-access`, `credential-vault-dpapi-access` | `registry.set`, `registry.create`, `driver.registry`, `process.start`, `security.privilege.object_operation`, `process.open`, `process.access`, `api.call`, `driver.process`, `file.open`, `file.read`, `file.created`, `file.modified`, `registry.query`, `driver.file` | `high` to `critical` | `T1003.001`, `T1003.002`, `T1112`, `T1555`, `T1555.003` | Covers LSA package persistence, LSASS dump commands/access, Security object-operation rows naming LSASS, SAM/SECURITY/SYSTEM/NTDS hive access, hive-save commands, browser credential databases, Vault/Credentials/DPAPI paths, and common credential dumping tool tokens. |
| Targeted credential access expansion | `credential-ntdsutil-ifm-command`, `credential-esentutl-ntds-copy-command`, `credential-kerberos-ticket-export-command`, `credential-browser-local-state-access`, `credential-chromium-cookie-db-access` | `process.start`, `file.open`, `file.read`, `file.created`, `file.modified`, `driver.file` | `high` to `critical` | `T1003.003`, `T1539`, `T1555.003`, `T1558` | Adds NTDS IFM and esentutl/copy command evidence, Kerberos ticket export tokens, and non-browser Chromium Local State/Cookie database access. Browser-process and sandbox plumbing exclusions keep normal browser startup and collector self-noise out of these findings. |
| Regex credential-file access | `credential-cookie-file-path-regex`, `credential-ntds-dit-path-access-regex`, `credential-lsass-dump-path-regex` | `file.open`, `file.read`, `file.created`, `file.modified`, `driver.file`, `artifact.dropped_file.copied` | `high` to `critical` | `T1003.001`, `T1003.003`, `T1555.003` | Adds path-regex coverage for Chromium cookie databases, NTDS.dit, and LSASS-like dump files. Normal browser processes, sandbox paths, and collector metadata are excluded. |
| Static PE traits | `static-pe-known-packer`, `static-pe-high-entropy-sections`, `static-section-writable-executable`, `static-embedded-url`, `static-pe-imports-present`, `static-pe-exports-present`, `static-pe-tls-callbacks`, `static-pe-resources-present` | `static.analysis.completed`, `static.pe.*` | `info` to `medium` | `T1027.002`, `T1027` where structural evidence applies | Uses `dataContains.tags` emitted by static analysis for packers, entropy, RWX/abnormal sections, URL strings, import/export/resource table presence, granular resource entries, and TLS directory/callback hints. URL strings are low-confidence static triage and do not imply transfer behavior. |
| Static resource traits | `static-resource-payload-candidate`, `static-resource-embedded-pe`, `static-resource-high-entropy` | `static.analysis.completed`, `static.pe.resource` | `medium` to `high` | `T1027.009`, `T1027` | Maps resource-directory parsing tags and granular resource DTO fields such as `resourceType`, `dataRva`, `size`, `entropyLabel`, `resourceRole`, `isPayloadCandidate`, and `isEmbeddedPe`. |
| Static import/API traits | `static-import-suspicious-api`, `static-import-process-injection`, `static-import-network-api`, `static-import-download-api`, `static-import-exfil-api`, `static-import-persistence-api`, `static-import-anti-analysis-api`, `static-import-credential-access-api`, `static-import-defense-evasion-api`, `static-import-dynamic-code`, `static-import-script-execution`, `static-import-file-drop`, `static-import-resource-api`, `static-import-registry-persistence`, `static-import-service-persistence` | `static.analysis.completed` | `low` to `medium` | Technique mappings remain only where import-only triage is specific enough; runtime rules carry primary behavior mappings. | StaticAnalyzer maps parsed imports and fallback API strings into tags such as `import_suspicious_api`, `import_process_injection_api`, `import_network_api`, `import_download_api`, `import_exfil_api`, `import_file_drop_api`, `import_resource_api`, `import_script_execution_api`, credential/defense-evasion groups, and persistence/anti-analysis subgroups. Static import-only evidence is low-confidence triage; runtime process/API/driver evidence is required for primary behavior. |
| Static export traits | `static-export-registration-entrypoint`, `static-export-service-entrypoint` | `static.analysis.completed` | `low` to `medium` | `T1218.010`, `T1543.003` | Export names are triage-only evidence; registration exports can indicate regsvr32-compatible DLL entry points, and service exports can support service DLL triage. |
| Static string indicators | `static-domain-indicator`, `static-tor-domain-string`, `static-dynamic-dns-domain-string`, `static-ip-address`, `static-windows-path-string`, `static-registry-path-string`, `static-persistence-string`, `static-script-command-string`, `static-encoded-command-string`, `static-lolbin-string`, `static-download-command-string`, `static-exfil-command-string`, `static-credential-access-string`, `static-defense-evasion-string`, `static-anti-sandbox-string` | `static.analysis.completed` | `info` to `medium` | `T1041`, `T1090`, `T1105`, `T1003`, `T1562.001`, `T1112`, `T1547.001`, `T1059`, `T1059.001`, `T1218`, `T1497` where specific string evidence applies | Covers bare domains (with conservative TLD/reference filtering), IP-like strings, Windows/registry paths, persistence paths, PowerShell encoded commands, living-off-the-land utility names, download/upload command strings, credential/defense-evasion strings, and VM/debugger/sandbox strings. Static indicators are triage metadata unless corroborated by runtime telemetry. |


## 2026-07-12 release-facing behavior expansion

This pass documents the release-facing rule expansion. The coverage is
organized for release notes and analyst triage rather than as a copy of any
upstream rule set: SigmaHQ, Elastic detection rules, Splunk Security Content,
and MITRE ATT&CK are used as inspiration families for technique vocabulary,
field hygiene, and false-positive thinking only.

| Release area | New rule IDs | Primary mapping |
| --- | --- | --- |
| Persistence | `persistence-lsa-authentication-package-registry`, `persistence-appinit-dlls-registry`, `persistence-appcert-dlls-registry`, `persistence-bootexecute-registry-autocheck`, `persistence-time-providers-registry-dll`, `persistence-wmi-event-subscription-registry-or-event`, `persistence-com-hijack-inprocserver-user-writable`, `persistence-print-monitor-registry-dll`, `persistence-active-setup-stubpath` | LSA, AppInit/AppCert, BootExecute, Time Providers, WMI events, COM hijack, Port Monitor, and Active Setup persistence surfaces. |
| Injection | `injection-r0-cross-process-vm-write`, `injection-r0-remote-thread-create`, `injection-queue-user-apc-remote-process`, `injection-section-map-executable-remote`, `injection-suspended-process-hollowing-sequence`, `injection-lsass-cross-process-handle` | Cross-process memory/thread/APC/section/hollowing evidence plus LSASS access. |
| Lateral movement | `lateral-admin-share-copy-executable`, `lateral-psexec-service-imagepath`, `lateral-winrm-process-with-remote-target`, `lateral-wmi-process-call-create-remote`, `lateral-rdp-shadow-or-restrictedadmin-command` | Admin-share staging, PsExec/service execution, WinRM, WMI remote create, and RDP command modes. |
| Anti-sandbox | `anti-sandbox-cpuid-hypervisor-check`, `anti-sandbox-vm-registry-key-query`, `anti-sandbox-analysis-tool-process-query`, `anti-sandbox-long-sleep-or-time-skew` | Hypervisor/system checks, VM registry keys, analysis-tool enumeration, and timing evasion. |
| Download-execute | `download-execute-certutil-urlcache-split`, `download-execute-bitsadmin-transfer`, `download-execute-powershell-webclient-to-user-writable`, `download-execute-mshta-or-regsvr32-remote-scriptlet`, `download-execute-rundll32-url-dll-entrypoint` | Tool transfer and LOLBin/proxy-execution download shapes. |
| DNS/HTTP/TLS/PCAP | `pcap-dns-txt-long-label-exfil`, `pcap-dns-nxdomain-burst-dga`, `pcap-http-executable-download-magic`, `pcap-http-post-beacon-small-periodic`, `pcap-http-host-header-ip-or-suspicious-tld`, `pcap-tls-self-signed-or-invalid-cert`, `pcap-tls-sni-ip-literal-or-dga`, `pcap-tls-no-sni-rare-ja3`, `network-pcap-smb-session-setup-admin-share` | Packet-derived exfil, DGA, executable transfer, HTTP beaconing, suspicious host/SNI, TLS certificate/JA3, and SMB admin-share evidence. |

## 2026-07-12 supplemental open-source-inspired batch

The supplemental batch adds 19 rules and raises the rule count from 439 to
458. It uses only KSwordSandbox event types and fields already present in the
guest, R0/API, network, and PCAP rule model. It does not copy upstream rule
text, SPL, KQL, EQL, Sigma YAML, or vendor test samples.

| Release area | New rule IDs | Primary mapping |
| --- | --- | --- |
| Scheduled-task and registry persistence | `scheduled-task-onlogon-user-writable-command`, `scheduled-task-runlevel-highest-user-writable`, `persistence-app-paths-user-writable-hijack`, `persistence-netsh-helper-dll-registry` | `T1053.005` scheduled tasks and broad `T1546` event-triggered registry persistence when the payload path is user-writable or DLL-based. |
| Injection and direct-syscall evidence | `injection-direct-syscall-or-ntdll-unhook`, `injection-process-doppelganging-transaction-primitive`, `injection-sensitive-process-virtual-memory-write` | `T1055`, `T1055.002`; API/R0/process rows must carry direct-syscall, NTDLL-unhook, transaction-section, or sensitive-target memory-write evidence. |
| Lateral movement over file shares and services | `lateral-admin-share-binary-copy-command`, `lateral-remote-service-admin-share-binpath`, `lateral-powershell-copyitem-admin-share`, `pcap-smb-svcctl-named-pipe-executable-service` | `T1570`, `T1569.002`; requires admin-share copy, remote service ImagePath, or svcctl named-pipe metadata rather than port-only evidence. |
| Download-execute | `download-execute-powershell-iwr-startprocess-chain`, `download-execute-bits-notifycmdline-payload` | `T1105`, `T1197`; requires web-transfer syntax, user-writable output or BITS notify command, and execution-oriented command context. |
| Credential access and exfil staging | `credential-browser-database-copy-command`, `credential-lsass-minidump-api-call`, `credential-file-archive-staging-command`, `http-large-authenticated-upload` | `T1555.003`, `T1003.001`, `T1552.001`, `T1041`; focuses on browser DB copy commands, LSASS dump APIs, credential-themed archive staging, and authenticated large HTTP uploads. |
| DNS/TLS network detections | `dns-base64-label-exfil-high-entropy`, `tls-risky-new-domain-or-c2-ja3` | `T1048.003`, `T1071.001`; requires long/high-entropy DNS labels or TLS reputation/JA3/new-domain metadata. |

The release-facing mapping keeps static and reputation-only signals out of the
primary runtime behavior bucket. High-risk findings still require concrete event
type plus path, command-line, API, registry, packet, or normalized data context.

## 2026-07-12 v26 self-noise guard hardening

This pass adds no new behavior rules. It hardens the existing v20, v22, v23,
and v25 recent/high-signal scoring rules after reviewing open-source detection
directions for inspiration only, including SigmaHQ process-creation patterns,
Elastic process-injection and lateral-movement concepts, Splunk Security
Content registry/service/lateral-movement topics, and LOLBAS LOLBin function
families. No upstream rule text, query syntax, or test data is copied into the
KSword rules.

The batch adds or completes the following guard families where missing:

- `excludeDataEquals.behaviorCounted = false`
- `excludeDataEquals.nonbehavior = true`
- `excludeDataContains.source = host`, `collection-health`, `virustotal`,
  `r0collector`
- `excludeDataContains.collectorSelfNoise = true`
- `excludeDataContains.r0SelfNoise = true`
- `excludeDataContains.collectorNoise = true`
- `excludeDataContains.healthStatus = collection-health` / `driver-health`
- `excludeProcessNames = KSword.Sandbox.Agent.exe` and
  `KSword.Sandbox.R0Collector.exe`

These are metadata/self-noise exclusions only. Positive predicates for sample
behavior remain unchanged, so a payload event with the same path, command-line,
registry, API, R0 semantic, DNS/HTTP/TLS, or artifact evidence still matches
unless it is explicitly marked as collection health or sandbox collector noise.

## 2026-07-12 v25 R0/file/network semantic-field batch

This pass adds 8 focused rules and raises the rule count from 560 to 568. It is
bounded to fields already emitted by the project and treats collection-only
artifact/R0 rows as evidence-quality metadata rather than sample behavior.

| Area | Rule IDs | Intent |
| --- | --- | --- |
| DNS answer scope | `dns-answer-private-or-loopback-scope`, `dns-answer-fastflux-public-scope-low-ttl` | Consumes `answerScope`, answer counts, TTL, ASN/country hints, and query names to flag private/loopback resolution and public fast-flux-style rotation. |
| HTTP transfer hints | `http-transfer-executable-download-hints`, `http-transfer-authenticated-upload-hints` | Uses `transferHint`, content disposition/type, transfer encoding, upload direction, auth/cookie presence, and body-size fields for download-execute or upload/exfil triage. |
| TLS certificate semantics | `tls-cert-common-name-ip-or-dynamic-host`, `tls-cert-invalid-validity-window` | Consumes `certificateCommonName`, issuer/subject, SNI, and validity-window status fields for encrypted-channel metadata review. |
| Artifact selector health | `artifact-evidence-matrix-selectors-ready` | Requires `artifact.import_summary` to carry `artifactEvidenceMatrix`, `primaryArtifactSelectors`, and positive screenshot/memory/PCAP counts. It is metadata-only. |
| R0 quality metadata | none (R0 health/raw evidence only) | Queue depth/capacity/high-watermark, dropped/lost counters, and backpressure/loss flags remain visible in R0 health/raw evidence lanes and are intentionally not behavior-rule findings. |

The cheap contract scenario is `behavior.rules-v25-semantic-fields`; it loads
repository JSON and matches synthetic DNS/HTTP/TLS/artifact rows without
Hyper-V, signing, live packet capture, or heavy E2E execution.

## 2026-07-12 v19 artifact correlation guards

This pass adds 6 focused rules and raises the rule count from 500 to 506. It
keeps the public-matrix inspiration at the behavior-family level only: artifact
and process lineage ideas are expressed as KSword-specific JSON predicates over
safe selectors, hashes, source events, and normalized process/PCAP fields rather
than copied upstream text or query syntax.

| Area | Rule IDs | Intent |
| --- | --- | --- |
| Artifact-backed memory, dropped-file, and screenshot correlation | `artifact-memory-dump-process-correlation`, `artifact-dropped-file-source-correlation`, `artifact-screenshot-capture-correlation` | Requires `artifact.host_imported`, exact `sourceArtifactKind`/`collectionName`/`evidenceRole`, `sourceArtifactRelativePath`, `sourceArtifactSha256`, `sourceArtifactSizeBytes`, and source event context. Memory dumps and screenshots remain metadata; executable/script/archive dropped files map to `T1105`. |
| Artifact-backed PCAP protocol rows | `artifact-pcap-protocol-correlation` | Requires packet-derived `pcap.*` rows to carry `collectionName=packet-captures`, source artifact path, SHA-256, size, and protocol/endpoint fields before reporting a capture-backed protocol correlation. |
| Process-tree lineage | `process-tree-lineage-user-writable-descendant` | Requires `process.tree` lineage (`rootProcessId`, `parentProcessId`, `treeLineage`, numeric `treeDepth`) plus a user-writable executable/script path, with collection-health/VT/R0 self-noise exclusions. |
| VirusTotal found enrichment | `virustotal-found-result-enrichment` | Requires exact `vtStatus=found`, SHA-256 shape, permalink, and provider verdict/count fields. It is metadata-only and does not carry ATT&CK mapping; malicious/suspicious scoring remains in verdict-specific rules. |

The cheap contract scenario is `behavior.rules-artifact-correlation-guards`; it
loads repository JSON, checks the narrow rule contracts, classifies synthetic
positive rows, and verifies collection-health, VT quiet, and R0 self-noise rows
do not match the new rules.

## 2026-07-12 v18 release-prep guards and R0 semantic fields

This pass adds 32 focused rules and raises the rule count from 468 to 500.
It uses the supplied MITRE/Sigma references as design evidence for constrained
predicates: Run-key/Startup-folder persistence and process injection remain tied
to ATT&CK technique semantics, while PowerShell/web-download ideas are expressed
as KSword-specific command, path, and correlation predicates rather than copied
Sigma text.

| Area | Rule IDs | Intent |
| --- | --- | --- |
| Persistence | `persistence-powershell-profile-user-writable`, `persistence-logon-script-user-writable`, `persistence-screensaver-scr-user-writable` | Adds PowerShell profile, Windows logon-script, and screensaver autostart surfaces with user-writable payload guards. |
| Injection | `injection-setwindowshookex-user-writable-dll`, `injection-thread-context-hijack-sequence`, `injection-module-stomping-write-execute` | Adds hook DLL, thread-context hijack, and module-stomping predicates requiring target/module/context evidence. |
| Lateral movement | `lateral-wmi-remote-process-create-with-credentials`, `lateral-schtasks-remote-run-with-credentials`, `lateral-rdp-restrictedadmin-registry-enable` | Adds credentialed WMIC/schtasks remote execution and RestrictedAdmin registry enablement. |
| Anti-sandbox | `anti-sandbox-debugger-present-exit-gate`, `anti-sandbox-user-idle-exit-gate`, `anti-sandbox-vm-artifact-sleep-gate` | Requires debugger/user/VM checks plus exit, delay, or long-sleep gate evidence. |
| Download-execute | `download-execute-msiexec-remote-package`, `download-execute-curl-wget-shell-chain`, `download-execute-http-response-mz-launch-correlation` | Adds remote MSI execution, curl/wget-to-user-writable shell chains, and HTTP MZ launch correlation. |
| Structured static | `static-granular-download-exec-capability`, `static-granular-injection-capability`, `static-granular-anti-debug-capability` | Consumes granular `static.pe.import.*`, `static.string.*`, and `static.yara.match` fields as low-confidence static triage only. |
| DNS/HTTP/TLS/PCAP | `dns-doh-query-with-high-entropy-name`, `pcap-dns-fastflux-low-ttl-many-answers`, `http-connect-c2-tunnel`, `tls-ech-or-esni-risky-ja3-no-sni` | Adds DoH, fast-flux, HTTP CONNECT, and ECH/ESNI + JA3 semantics with concrete fields. |
| R0 semantic fields | `r0-semantic-runkey-persistence-family`, `r0-semantic-service-persistence-candidate`, `r0-semantic-ifeo-debugger-persistence-candidate`, `r0-semantic-startup-folder-dropped-file`, `r0-semantic-user-writable-dropped-file-candidate`, `r0-semantic-user-writable-image-injection-candidate`, `r0-semantic-network-lateral-movement-flow`, `r0-semantic-network-download-execute-flow`, `r0-semantic-network-dns-flow`, `r0-semantic-file-drop-download-correlation-hint` | Prefers parsed R0 fields (`persistenceFamily`, `imageLoadFamily`, `networkEvidenceKind`, `dropLocationFamily`, and candidate booleans) over brittle raw text. |

All v18 primary behavior rules carry explicit collection-health, VirusTotal quiet
state, and R0 self-noise exclusions. R0 semantic rules intentionally do not
blanket-exclude `source=r0collector`, because parsed driver rows may be emitted
by the collector; instead they require stable semantic fields and exclude
`noise`, `selfNoise`, `collectorSelfNoise`, health/status rows, and sandbox
agent/collector process names. The cheap contract scenario is
`behavior.rules-release-prep-r0-semantics`.

## 2026-07-12 MVP gap-closure behavior batch

This pass adds 10 focused rules and raises the rule count from 458 to 468.
It targets gaps that are still valuable for the MVP report without promoting
static-only strings or collection-health rows into primary malicious findings.
Each rule uses runtime command, API/R0, normalized correlation, or network/PCAP
fields plus explicit collection-health/VT/R0 self-noise exclusions.

| Release area | New rule IDs | Primary mapping |
| --- | --- | --- |
| Lateral movement and remote service admin | `lateral-dcom-mmc20-remote-execution-command`, `lateral-sc-remote-service-start-or-control` | DCOM MMC20/ShellWindows remote execution (`T1021.003`) and sc.exe remote service control (`T1021`). |
| Download-execute correlation | `download-execute-wscript-cscript-remote-script-url`, `download-execute-artifact-hash-launch-correlation` | WSH remote script execution and hash-backed downloaded-artifact launch correlation (`T1105`). |
| Anti-sandbox gates | `anti-sandbox-low-resource-exit-gate`, `anti-sandbox-sleep-acceleration-ratio-mismatch` | Low-resource exit/delay gates and accelerated sleep mismatch evidence (`T1497.001`, `T1497.003`). |
| Injection and memory mapping | `injection-create-remote-thread-startaddress-rwx`, `injection-mapview-section-unbacked-execute` | Remote thread starts in RWX memory (`T1055.004`) and executable unbacked section maps (`T1055.002`). |
| C2 beacon, JA3/SNI, and domain fronting | `c2-ja3-sni-domain-fronting-correlation`, `c2-beacon-sni-ja3-process-correlation` | Host/SNI/domain-fronting plus risky JA3 correlation (`T1090`) and beacon timing tied to SNI/JA3/user-writable process context (`T1071.001`). |

The cheap contract scenario is `behavior.rules-mvp-gap-closure`; it loads the
repository rule files, checks rule ID uniqueness and MITRE map coverage,
classifies synthetic positive events, and verifies static/VT/collector noise
rows do not trigger these new primary findings.

## 2026-07-11 v15 open-source reference rules

The v15 pass adds 3 rules plus two MITRE seed-map entries
(`T1218.008` and `T1218.014`) based on Cuckoo/CAPE signature-style behavior,
DRAKVUF API/plugin dimensions, ATT&CK Windows technique names, and public
Sigma-style detection hygiene:

- `odbcconf-regsvr-user-writable-dll-proxy-execution` maps to
  `T1218.008 Odbcconf`. It requires `odbcconf`, `REGSVR`, and a DLL path under
  a user-writable location in the same command line.
- `mmc-user-writable-msc-proxy-execution` maps to `T1218.014 MMC`. It requires
  `mmc`, `.msc`, and a user-writable `.msc` path, so normal control-panel or
  system snap-in launches do not match.
- `named-pipe-impersonation-api-observed` maps to `T1134.001 Token
  Impersonation/Theft`. It requires an impersonation API/operation and a
  `pipeName` field, with common browser and KSword pipe names excluded.
- All three rules include `evidenceFields`, bilingual operator metadata,
  `sigma-style`/`open-source-reference` tags, and collection-health/VT/R0
  exclusions. They are smoke-tested by `behavior.rules-open-source-reference`.

## 2026-07-11 v14 combination rules and MITRE map quality

The v14 pass adds 7 high-signal combination rules and four MITRE seed-map
entries (`T1518`, `T1518.001`, `T1552`, and `T1552.001`):

- Persistence plus dropped-file context: Run/RunOnce writes are elevated only
  when the value points to a user-writable executable/script payload and the
  same event carries dropped-file or download-execute correlation evidence.
- Defense evasion plus dropped-file context: Defender exclusion writes require
  both a Defender exclusion path and a user-writable dropped/staged payload
  value.
- Discovery and credential access: process-listing security-tool discovery maps
  to `T1518.001`, while user-profile credential-themed file searches map to
  `T1552.001`.
- Network C2 and anti-sandbox combinations: periodic C2 flow rules require a
  user-writable process path, destination IP, interval, jitter, and C2/beacon
  classification; anti-sandbox sleep gates require VM/sandbox check text plus a
  long sleep duration.
- Dropped-file artifact quality: script/LOLBin downloaded dropped-file
  artifacts require source path, downloader process, and HTTP(S) source URL
  metadata. Collection output paths alone are not enough.
- MITRE precision: process hollowing now maps to `T1055.012` and
  LoadLibrary-style DLL injection to `T1055.001` instead of broad `T1055`.
- False-positive boundary: each primary combination rule excludes
  Agent/R0Collector process names, command self-noise, collection-health data,
  and VirusTotal unset/status metadata where applicable.

## 2026-07-11 v13 advanced predicates and Windows behavior

The v13 pass adds 24 rules plus minimal stable predicate support for regex,
numeric ranges, explicit absent-field checks, and same-field AND:

- Predicate support: `pathRegex`, `commandLineRegex`, `dataRegex`,
  `allDataRegex`, `dataNumericRanges`, `allDataNumericRanges`,
  `absentDataKeys`, and `dataContainsAll` let rules express syntax,
  thresholds, missing telemetry fields, and multiple tokens in one field.
  Regex matching is case-insensitive, culture-invariant, and timeout-bounded.
  Numeric parsing uses invariant-culture finite numbers and inclusive bounds by
  default.
- Command and script behavior: PowerShell EncodedCommand base64 syntax, AMSI
  bypass script-block text, WMIC shadow-copy deletion, wevtutil log clearing,
  and bcdedit recovery-policy tamper move from broad substring checks to regex
  or same-field-AND constraints.
- Numeric network and telemetry: SMB/RDP/WinRM/Tor-SOCKS ports, HTTP upload
  size, DNS query length, long sleep duration, high child-process counts, mass
  file-write bursts, and registry Run-key set bursts use numeric thresholds
  rather than string fragments.
- Exists/not-exists guards: direct-IP HTTP without User-Agent, TLS JA3 without
  SNI/serverName, and download-execute rows without referrer/browser context
  use `absentDataKeys` so missing context is explicit and reviewable.
- Regex file and persistence rules: Chromium Cookie DB access, NTDS.dit access,
  LSASS-like dump paths, service ImagePath, and scheduled-task payloads use
  path/data regex while excluding normal browser processes, query-only registry
  operations, sandbox collection paths, R0Collector self-noise, and VT unset or
  collection-health rows.

## 2026-07-11 v12 targeted Windows behavior and false-positive controls

The v12 pass adds 24 rules focused on requested high-signal Windows behavior
gaps without changing collectors or report contracts:

- Download/script execution: HH remote script/CHM, MSXSL remote XSL/script,
  and forfiles `/c` proxy execution require LOLBin plus remote/script or child
  command evidence.
- Credential access: NTDS IFM, esentutl/copy of `ntds.dit`, Kerberos ticket
  export tokens, and non-browser access to Chromium Local State and Cookie DBs
  are split from generic credential-store access.
- Defender, UAC, and logging evasion: Defender service `Start=4`, Defender
  disable policy values, user-writable Defender exclusions, PowerShell logging
  disables, UAC policy weakening, `LocalAccountTokenFilterPolicy`, and
  SilentCleanup `windir` hijacks use exact value-name/value or path-plus-payload
  constraints.
- Office/browser persistence: Office macro/Protected View weakening, Outlook
  forms/homepage, browser extension policy force-install, native-messaging
  host registry/manifest writes, and IE BHO/toolbar hooks require Office or
  browser-specific paths plus payload/update URL/user-writable evidence.
- Lateral/C2/TLS/HTTP: explicit WinRM enablement, TLS SNI dynamic-DNS or
  `.onion` domains, and HTTP POST with credential/token material add targeted
  rules without treating port-only, timing-only, or static-only evidence as
  primary malicious behavior.
- False-positive boundary: every new registry rule excludes query-only
  operations; file/browser-credential rules exclude sandbox paths and normal
  browser processes where appropriate; command rules exclude Agent/R0Collector
  command self-noise; network rules exclude VT unset and collection-health
  metadata via data-field exclusions.

## 2026-07-11 v11 behavior expansion and false-positive guards

The v11 pass adds 35 behavior rules, two MITRE impact mappings, and all-of
predicate families:

- Predicate quality: `allContainsPath`, `allContainsCommandLine`,
  `allDataKeys`, `allDataEquals`, and `allDataContains` allow conservative
  high-risk rules that require combined evidence such as downloader command plus
  user-writable output path, HTTP method plus content type, or both downloaded
  and executed path fields.
- Ransomware/impact: shadow-copy deletion, recovery disablement, ransom-note
  paths, encrypted-extension rename operations, and explicit ransomware file
  classifications are mapped to `T1490` or `T1486`. Generic file deletion and
  driver file-write signals are not promoted to ransomware by themselves.
- Injection and lateral movement: added target-process, target-function,
  section-map, APC, and sensitive-process handle context for injection; lateral
  rules now cover admin-share credentials, WMIC remote create, remote
  scheduled-task actions, PsExec service-file staging, and remote registry
  persistence using all-of command/path checks.
- Anti-analysis, download, persistence, and C2: new rules require explicit
  runtime checks, output paths, correlation fields, payload paths, or C2 labels.
  Broad single-field rules were tightened: script/library HTTP user agents,
  generic POST/PUT methods, query-length DNS fields, and PCAP beacon interval
  metadata no longer act as high-confidence C2 by themselves.
- False-positive boundary: collection health, R0 unavailable, R0 collector
  plumbing, VirusTotal `not_configured`/`not_found`/`rate_limited`, and
  `static.analysis.completed` import/string/domain/IP rules remain metadata or
  triage. New high-risk rules use runtime event types plus command/path/data
  evidence and sandbox-agent exclusions where applicable.

## 2026-07-11 v10 static and rule-quality expansion

The v10 pass adds 11 rules and one exact-match predicate family:

- Static network strings: bare domain indicators, `.onion` domains, and common
  dynamic-DNS markers are emitted as low-confidence static triage. Runtime DNS,
  HTTP, TLS, or PCAP evidence remains required for primary network behavior.
- Static import clusters: download-capable APIs, upload/exfil-capable APIs,
  credential-access APIs/libraries, and defense-evasion APIs/libraries now map
  to dedicated low-confidence static rules instead of only the broad
  `import_suspicious_api` bucket.
- Static command/string indicators: download command strings, upload/exfil
  command strings, credential-access strings, and defense-evasion strings have
  separate rules so reports can explain why the static triage fired.
- `dataEquals` / `excludeDataEquals` were added to the rule engine for exact
  status/verdict predicates. VirusTotal verdict/status rules now use
  `dataEquals` so strings such as `not_malicious` cannot satisfy the
  `malicious` verdict rule through substring matching.

## 2026-07-11 v9 rules and VT quality expansion

The v9 pass adds 37 rules:

- Persistence/autostart: user-writable and script/LOLBin Run-key payloads,
  `StartupApproved` state changes, service binary/failure-command/driver
  installs, weak service ACL metadata, TaskCache COM handlers, and scheduled
  task XML targets pointing at user-writable paths.
- Execution/injection/privilege: user-writable payload launch, archive or
  installer process-tree launch chains, DLL image loads from user-writable
  paths, debug/all-access process opens, token impersonation APIs,
  auto-elevate UAC registry/LOLBin evidence, sensitive privilege enablement,
  PowerShell in-memory reflection loaders, PowerShell-to-LOLBin child
  processes, CMSTP, and Control Panel proxy execution.
- Network/certificate/anti-analysis: periodic beacon metadata, DNS reputation
  and high-entropy metadata, HTTP JSON tasking/gate URI and host-header
  mismatch labels, TLS certificate reputation, root certificate store
  modification command/registry evidence, debug-register checks, and host
  identity sandbox checks.
- VirusTotal enrichment quality: explicit `malicious`, `suspicious`,
  `not_found`, `rate_limited`, and `not_configured` rules consume
  `enrichment.virustotal.lookup`/`reputation.virustotal.file` rows when a
  caller converts lookup results to normalized events. These rules are tagged
  as enrichment metadata and intentionally have no ATT&CK technique ID because
  external reputation is not local adversary behavior.

## 2026-07-11 v6 quality expansion

The v6 quality expansion added 21 high-value detections that only use fields
already represented by `SandboxEvent`, the guest probes, typed R0 JSONL rows, or
the PCAP importer:

- Persistence: Office add-in/startup paths, accessibility IFEO debugger
  hijacks, and logon-script file paths.
- Injection and proxy execution: Mavinject, InstallUtil, MSBuild inline tasks,
  and Regasm/Regsvcs command evidence.
- Collection and credentials: LSASS dump file creation, clipboard APIs, and
  screenshot-like sample-created files.
- Anti-analysis: uptime/boot-time checks and parent-process/PEB inspection
  API evidence.
- Lateral movement and discovery: `cmdkey` credential staging and domain trust
  or domain-controller discovery commands.
- DNS/HTTP/TLS/PCAP: `.onion` domains, long or encoded HTTP URI labels,
  domain-fronting indicators, and TLS C2 classification fields.
- Process trees: Office-to-script/LOLBin and browser-to-script/LOLBin lineage
  patterns emitted by `process.tree` rows.

## 2026-07-11 v7 diagnostic metadata reduction

The v7 pass replaced 15 broad compatibility rules with concrete names and
metadata boundaries while staying within current `RuleEngine` predicates:

- R0/image and process context: `image-load-metadata-observed` requires
  image/module/process/base-address fields instead of matching every bare image
  callback row.
- Normalized correlation: `download-execute-chain-observed` and
  `archive-extracted-execute-chain-observed` require download/archive/executed
  path metadata on higher-level correlation events.
- DNS/TLS/PCAP: `dns-tunnel-or-dga-indicator`,
  `tls-sni-ja3-metadata-observed`, `pcap-artifact-imported`,
  `pcap-flow-observed`, `pcap-upload-or-exfil-indicator`,
  `pcap-flow-count-metadata-observed`, and
  `tls-no-sni-or-rare-ja3-indicator` document the exact data fields analysts
  should inspect.
- Anti-analysis timing: `anti-analysis-sleep-duration-metadata` and
  `anti-analysis-accelerated-sleep-metadata` make clear that numeric duration
  fields are metadata until threshold predicates exist.

The remaining broad compatibility IDs are deliberately low-confidence
diagnostic lanes: the legacy R0 IOCTL protocol row, PCAP protocol-summary
rollup, HTTP direct-IP/nonstandard-port triage, and PCAP beacon-interval
metadata. They keep older identifiers only for report/smoke-test
compatibility; titles, summaries, tags, and `evidenceFields` now point to the
具体证据字段（协议、端口、packet/flow 计数、资源盘点和分类字段）that analysts
should inspect. v11 added constrained companion rules for low-resource and
periodic C2 evidence so weak metadata fields are not promoted without explicit
classification.

## MITRE mapping notes

- `T1016`, `T1049`, `T1057`, `T1082`, and `T1135` cover command-line or
  probe-derived discovery signals for local network configuration, active
  connections, running processes, system identity, and network shares.
- `T1518` and `T1518.001` cover software and security-software discovery;
  KSword rules use `T1518.001` only when process-listing commands are paired
  with security/EDR, packet-capture, VM, or analysis-tool process names.
- `T1134.001` covers token duplication, impersonation, and sensitive privilege
  enablement telemetry such as `DuplicateTokenEx`, `CreateProcessWithTokenW`,
  `AdjustTokenPrivileges`, and `SeDebugPrivilege`/backup/restore privilege
  enablement.
- `T1018` is used for LDAP/Kerberos/domain-service port evidence as remote
  system/domain discovery triage; port evidence alone does not prove domain
  compromise.
- `T1021` is used for broader remote-service enablement or policy changes, such
  as `LocalAccountTokenFilterPolicy`, when a subtechnique is too narrow for the
  current event shape.
- `T1021.001` and `T1021.004` cover RDP/SSH port or command evidence.
  Existing SMB and WinRM mappings remain `T1021.002` and `T1021.006`.
- `T1036` covers double-extension file names that masquerade as documents,
  images, archives, or text files while ending in executable/script suffixes.
- `T1041` is reserved for packet/HTTP metadata labeled as upload or
  exfiltration until byte-threshold correlation exists.
- `T1048.003` is used for DNS TXT/long-label packet metadata that indicates
  exfiltration over an unencrypted non-C2 protocol.
- `T1090` covers HTTP CONNECT/WebSocket/proxy tunnel metadata and common
  proxy/Tor port evidence.
- `T1059` is used only when the command line references common Windows
  scripting interpreters.
- `T1003.001` is reserved for LSASS process access or dump evidence, while
  `T1003.002` is used for SAM/SECURITY/SYSTEM hive access and hive-save
  commands.
- `T1003.003` is used only for NTDS-specific IFM, `ntds.dit`, esentutl,
  diskshadow, or shadow-copy copy evidence.
- `T1021.002` and `T1021.006` cover SMB/admin-share and WinRM/PowerShell
  remoting evidence respectively; network-port rules are triage signals, not
  proof of successful lateral movement.
- `T1047` covers WMI/CIM remote execution command evidence.
- `T1112` covers generic registry modification. `T1547.001` is reserved for
  Run/RunOnce autostart paths because that evidence is more specific.
- `T1070.001` is used only for event-log clearing command evidence; generic
  file deletion remains `T1070.004`.
- `T1070.004` is used for file deletion because the current event does not yet
  prove cleanup intent, but it is still useful to surface in reports.
- `T1053.005` is used only when a command line shows scheduled-task creation
  or registration evidence.
- `T1059` covers interpreter and script-file execution evidence. `T1059.001`
  is used when static strings specifically show PowerShell encoded-command
  markers.
- `T1071.001` and `T1071.004` are reserved for normalized HTTP and DNS events.
- `T1105` is retained for outbound TCP, embedded URL/IP evidence, and static
  network/download API imports, download staging paths, and normalized
  download-execute correlation rows until more precise seed mappings are
  available.
- `T1197` is used for BITS transfer download-execute command evidence when
  `bitsadmin` or BITS job semantics are visible.
- `T1113` covers runtime screen-capture API calls from sample telemetry. The
  sandbox's own `screenshot.captured` artifact rows are intentionally unmapped
  collection evidence.
- `T1176` covers browser extension persistence surfaces such as forced
  extension policy, native messaging host manifests, and Browser Helper Object
  registry hooks.
- `T1204.002` is used for execution from download/staging paths because the
  rule observes launch context, not the preceding transfer by itself.
- `T1055` is used only for static import groups that include process-injection
  primitives such as cross-process allocation/write/thread APIs, or dynamic
  events that explicitly report remote-thread/APC, hollowing, RWX memory, or
  LoadLibrary-style injection operations.
- `T1055.001` is used when LoadLibrary/LdrLoadDll-style DLL injection evidence
  is present; `T1055.012` is used for hollowing or suspended-process
  replacement signals.
- `T1055.004` is used for QueueUserAPC/APC-style remote process injection
  evidence. Generic R0 cross-process memory writes and remote-thread rows stay
  under broad `T1055` until a more specific subtechnique is explicit.
- `T1106` covers broad native Windows API import/string evidence; more specific
  rules such as process injection, network transfer, persistence, and
  anti-analysis should take precedence in triage.
- `T1027.009` is used for resource payload candidates and embedded PE resource
  evidence. `T1027` remains the broader entropy/obfuscation fallback.
- `T1218` is used for generic living-off-the-land binary strings; specific
  export evidence still uses `T1218.010` for regsvr32-compatible DLL exports.
- `T1218.010` is used for static COM registration exports because those names
  are compatible with regsvr32-style execution, but the static rule does not
  prove that regsvr32 was actually used.
- `T1218.002` and `T1218.003` cover Control Panel and CMSTP proxy-execution
  command lines respectively.
- `T1218.008` covers Odbcconf proxy execution only when `REGSVR` style
  command evidence points at a user-writable DLL. Generic ODBC configuration
  usage is not enough.
- `T1218.014` covers MMC proxy execution only when `mmc.exe` loads a
  user-writable `.msc` snap-in path. Normal system snap-ins remain outside the
  rule.
- `T1202` covers indirect command execution through `forfiles /c` only when a
  script interpreter, shell, or proxy-execution child command is present.
- `T1220` covers MSXSL/XSL script processing when the command references a
  remote or script-capable XSL source.
- `T1115` covers clipboard API evidence when runtime telemetry explicitly
  records clipboard access primitives.
- `T1127.001`, `T1218.004`, and `T1218.009` cover MSBuild inline-task,
  InstallUtil, and Regasm/Regsvcs proxy-execution command lines.
- `T1137` covers Office add-in/startup registry and filesystem evidence.
- `T1482` covers domain trust, domain-controller, and domain group discovery
  commands used before lateral movement.
- `T1486` is used only for runtime ransomware/encryption artifacts such as
  ransom-note paths, encrypted-extension rename operations, or explicit
  ransomware/encryption file classifications; generic file writes/deletes do
  not qualify.
- `T1497` covers static VM/sandbox/tool strings; `T1497.003` remains specific
  to time-based evasion and delay/sleep telemetry. Dynamic anti-analysis
  command rules also use `T1497` for VM/tool lookup, user-activity checks, and
  analysis-tool termination evidence.
- `T1497.001` is used for CPU, hypervisor, hardware, user-activity, and
  low-resource system checks.
- `T1490` covers recovery-inhibition command evidence such as shadow-copy
  deletion, backup-catalog deletion, `reagentc /disable`, or boot recovery
  disablement. It is not used for collection failures or unavailable R0
  telemetry.
- `T1546` is used as the broad event-triggered execution mapping for WMI
  event subscriptions, COM hijacks, and AppInit DLL registry evidence because
  the current seed map intentionally does not include every subtechnique.
- `T1546.003`, `T1546.009`, `T1546.010`, and `T1546.015` are used when
  the new release-facing persistence rules have enough registry, file, or WMI
  event context for WMI event subscriptions, AppCert DLLs, AppInit DLLs, or COM
  InprocServer hijacking instead of the broad `T1546` fallback.
- `T1546.012` is used for Image File Execution Options debugger registry paths.
- `T1547.004` is used for Winlogon Shell/Userinit/Notify/GinaDLL persistence
  paths.
- `T1547.002`, `T1547.003`, `T1547.010`, and `T1547.014` are used for
  LSA authentication package, Time Provider, Port Monitor, and Active Setup
  persistence surfaces when the corresponding registry/value evidence is
  present.
- `T1548.002` covers auto-elevate UAC bypass registry paths and LOLBin
  launches such as `fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe`, and
  `eventvwr.exe` when observed in sandbox telemetry.
- `T1539` covers browser cookie database access or HTTP metadata that contains
  session-cookie/token material.
- `T1555` and `T1555.003` cover credential stores broadly and browser
  credential databases specifically.
- `T1552` and `T1552.001` cover unsecured credentials and credential-themed
  file searches; the current runtime rule requires user-profile scope plus
  password/secret/token/key-store filename terms in the same command line.
- `T1558` covers Kerberos ticket dump/export command evidence such as
  `sekurlsa::tickets`, `kerberos::list /export`, and Rubeus ticket operations.
- `T1553.004` covers certificate-root-store modification commands and registry
  paths. TLS certificate reputation remains mapped to encrypted-channel
  network evidence instead of trust-store modification.
- `T1562.001` covers attempts to disable or modify security tools, Defender,
  AMSI, or ETW; `T1562.004` covers firewall disablement.
- `T1564.001` is used for `attrib +h/+s` command-line evidence that attempts
  to hide staged files or persistence artifacts.
- `T1569.002` covers remote service execution command evidence; `T1570` covers
  lateral tool transfer over UNC/admin-share style paths.
- `T1573` is used for TLS/SNI/JA3 metadata indicators where encrypted-channel
  metadata is available but content is not inspected.
- `T1573.002` is used when TLS certificate metadata specifically indicates
  self-signed or invalid asymmetric-certificate behavior.
- `T1571` covers listener or endpoint metadata that uses non-standard ports
  often associated with reverse shells, proxies, Tor, or custom C2 channels.
- `T1568.002` is used for DNS/PCAP metadata that explicitly indicates
  NXDOMAIN bursts or DGA-like generated-domain behavior.
- `T1574.009` covers service ImagePath values that need unquoted-space hijack
  review. `T1574.011` covers weak service permissions or service registry ACL
  metadata that can permit service hijacking.
- `T1620` is used for dynamic code loading and memory-protection import groups
  as a triage hint, not as proof of reflective loading at runtime.
- `T1622` is used for debugger/timing import strings where static evidence
  suggests anti-analysis checks.
- Rules without MITRE IDs are intentionally unmapped because the current event
  is health, generic telemetry, parser metadata, or intentionally too broad for
  a stable technique assignment.

## Static-analysis tag contract

`StaticAnalysisResult` now carries structured imports, suspicious API clusters,
exports, TLS, overlay, and string-indicator fields, but rule matching still uses
the stable `static.analysis.completed.Data["tags"]` contract so older reports
and rules remain compatible. StaticAnalyzer therefore records lightweight static
depth through both structured fields and existing tag/evidence fields:

- `Tags`: rule-facing tokens such as `imports_present`, `exports_present`,
  `resources_present`, `tls_directory_present`, `tls_callbacks`,
  `resource_payload_candidate`, `resource_embedded_pe`,
  `writable_executable_section`, `import_suspicious_api`,
  `import_process_injection_api`, `import_network_api`,
  `import_download_api`, `import_exfil_api`, `import_file_drop_api`,
  `import_resource_api`, `import_credential_access_api`,
  `import_defense_evasion_api`,
  `import_script_execution_api`, `registry_path_string`,
  `script_execution_string`, `domain_name`, `ip_address`,
  `export_registration_entrypoint`, `packer_section_name`, and
  `packer_string_hint`.
- `InterestingStrings`: bounded human-readable evidence such as
  `section:.text,va=...`, `import:kernel32.dll!VirtualAllocEx`,
  `export:DllRegisterServer`, `resource:rcdata,size=...`,
  `url:https://...`, `domain:example.com`, `path:C:\...`, `ip:8.8.8.8`, and
  `tls:callback@0x...`.
- `static.analysis.completed.Data["tags"]`: comma-joined `Tags` used by
  `dataContains.tags` predicates in `rules/behavior-rules.json`.

This keeps static coverage useful without requiring new rule predicates.
If future rules consume structured static fields directly, keep these tags for
backward-compatible matching and add structured predicates separately.

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
   `process.exit`, `thread.created`, and `image.load`; keep the generic
   image-load metadata rule constrained by path/process/base-address fields,
   and add more specific signer/path-context rules after those fields are
   stable.
4. Normalize network/WFP evidence to protocol-specific events such as
   `network.tcp`, `network.udp`, `dns.query`, and `http.request` when those
   collectors exist.
5. Consider adding a source predicate to the rule schema before creating
   driver-only rules that cannot be safely distinguished by event type, path, or
   data fields alone.
