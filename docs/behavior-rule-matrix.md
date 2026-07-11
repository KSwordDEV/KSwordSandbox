# Behavior rule matrix

This document describes the behavior rules in `rules/behavior-rules.json`.
The matrix is intentionally conservative: rules classify normalized sandbox
events for reporting, but they do not by themselves prove malicious intent.
The 2026-07-11 v4 expansion keeps the same schema while broadening coverage to
206 rules for download/execute chains, injection, credential access, full
process trees, screenshot/memory/drop artifacts, lateral movement,
anti-analysis, defense evasion, and DNS/HTTP/TLS/PCAP evidence.

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
| `guest` | `KSword.Sandbox.Agent` | `process.start`, `process.new`, `process.timeout`, `process.tree`, `process.tree_unavailable`, `service.*`, `scheduled_task.*`, `startup_item.*`, `file.created`, `file.modified`, `file.deleted`, `artifact.dropped_file.*`, `screenshot.*`, `memory_dump.*`, `dns.cache.*`, `network.tcp`, `network.netstat.*`, `network.udp.listener.*` | Show behavior and artifacts observed inside the VM during the analysis window. |
| `driver` | Guest-imported driver JSONL sidecar | `driver.process`, `driver.file`, `driver.registry`, `driver.network`, `image.load`, legacy normalized `registry.set` / `file.created` | Preserve kernel/driver evidence without changing Core/Web contracts. |
| `pcap` / protocol importer | Future packet or flow post-processors | `pcap.summary`, `pcap.protocol.summary`, `pcap.flow`, `pcap.tcp`, `pcap.udp`, `pcap.http`, `pcap.dns`, `pcap.tls`, `network.pcap`, `pcap.packet`, `network.flow` | Reserve stable report buckets for packet-derived endpoint, DNS, HTTP, and TLS evidence before a first-class PCAP model exists. Rules key on normalized data fields rather than the `source` value, so imported PCAP-derived rows may still use host-side sources. |
| `r0collector` | `KSword.Sandbox.R0Collector` lifecycle rows | `r0collector.started`, `r0collector.deviceOpened`, `r0collector.heartbeat`, `r0collector.driverHealth`, `r0collector.driverPoll`, `r0collector.driverReadEvents`, `r0collector.ioctlFailure`, `r0collector.driverProtocolError`, `r0collector.stopped` | Distinguish collector health, failures, and synthetic plumbing events from sample behavior. |

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

Legacy aliases such as `srcIp`, `dstIp`, `url`, `requestUri`, `qname`, `ja3`,
and `tlsVersion` remain in the rule set for backward-compatible synthetic and
future parser rows.

## Rule groups

| Group | Rule IDs | Event types | Severity | MITRE mapping | Notes |
| --- | --- | --- | --- | --- | --- |
| Host planning | `host-submission`, `runbook-created` | `submission.accepted`, `hyperv.runbook.created` | `info` | None | Explains why a report exists and which execution plan was generated. |
| R0 collector health | `r0collector-device-unavailable`, `r0collector-start-failed`, `r0collector-driver-health`, `r0collector-ioctl-protocol-pending`, `r0collector-lifecycle`, `r0collector-ioctl-failure` | `r0collector.deviceUnavailable`, `r0collector.start_failed`, `r0collector.driverHealth`, `r0collector.driverPoll`, `r0collector.driverReadEvents`, `r0collector.ioctlProtocolPending`, `r0collector.started`, `r0collector.deviceOpened`, `r0collector.heartbeat`, `r0collector.stopped`, `r0collector.ioctlFailure`, `r0collector.driverProtocolError` | `info` | None | Shows driver-open failures, lifecycle rows, successful health/poll/read IOCTL plumbing, and collection/protocol errors; the pending row is retained only for older local collector builds. |
| R0 synthetic plumbing | `r0collector-mock-driver-event` | `r0collector.mockDriverEvent` | `info` | None | Marks mock JSONL rows so report output stays clear during Guest Agent sidecar tests. |
| Process behavior | `script-interpreter`, `process-new`, `process-timeout-long-sleep` | `process.start`, `process.new`, `process.timeout` | `low` to `medium` | `T1059`, `T1497.003` | Separates generic new-process evidence from stronger scripting and timeout/evasion indicators. |
| Full process tree and launch context | `process-tree-observed`, `process-tree-root-unavailable`, `process-start-failed`, `process-tree-large-fanout-placeholder`, `lolbin-process-tree-node`, `execution-from-user-writable-tree-path` | `process.tree`, `process.tree_unavailable`, `process.start_failed`, `process.new`, `process.start` | `info` to `medium` | `T1204.002`, `T1218` where specific evidence applies | Surfaces root/depth/lineage/child-count rows from the process-tree probe, rapid-exit collection gaps, launch failures, LOLBin descendants, and execution from user-writable staging paths. |
| Script execution behavior | `script-interpreter`, `script-file-executed` | `process.start` | `medium` | `T1059` | Matches interpreter names and script-like command-line extensions. |
| Persistence behavior | `registry-run-key-persistence`, `service-registry-persistence`, `service-create-command`, `scheduled-task-persistence`, `tasks-folder-file-write`, `startup-folder-persistence`, `ifeo-debugger-persistence`, `winlogon-persistence`, `driver-registry-run-key-typed-persistence`, `driver-registry-service-typed-persistence`, `scheduled-task-registry-cache-persistence`, `driver-registry-taskcache-typed-persistence`, `wmi-event-subscription-persistence`, `wmi-event-subscription-command`, `com-hijack-persistence`, `appinit-dlls-persistence`, `lsa-security-provider-persistence` | `registry.set`, `registry.create`, `driver.registry`, `process.start`, `file.created`, `file.modified`, `driver.file` | `high` | `T1547.001`, `T1547.004`, `T1543.003`, `T1053.005`, `T1546.012`, `T1546`, `T1112` | Covers Run/RunOnce keys, service registry paths and service creation commands, scheduled-task command/folder evidence, Startup folder writes, IFEO and Winlogon helper values, WMI subscription artifacts, COM hijacks, AppInit DLLs, and LSA package paths. |
| System inventory diff persistence | `service-system-change-created`, `service-system-change-suspicious-command`, `scheduled-task-system-change-created`, `scheduled-task-suspicious-target`, `startup-item-system-change-created`, `startup-item-executable-value`, `persistence-system-item-deleted`, `system-diff-truncated` | `service.created`, `service.modified`, `service.deleted`, `scheduled_task.created`, `scheduled_task.modified`, `scheduled_task.deleted`, `startup_item.created`, `startup_item.modified`, `startup_item.deleted`, `*.diff_truncated` | `info` to `high` | `T1543.003`, `T1053.005`, `T1547.001`, `T1070.004` | Uses the current system-change probe’s service/task/startup diffs to catch persistence created or changed after launch, suspicious payload targets, deleted persistence entries, and truncation diagnostics. |
| Registry behavior | `registry-change`, `registry-run-key-persistence`, `service-registry-persistence`, `service-imagepath-or-dll-registry-change`, `scheduled-task-registry-cache-persistence`, `ifeo-debugger-persistence`, `winlogon-persistence`, `wmi-event-subscription-persistence`, `com-hijack-persistence`, `appinit-dlls-persistence`, `lsa-security-provider-persistence`, `r0-driver-registry-change-signal` | `registry.set`, `registry.create`, `registry.delete`, `driver.registry` | `medium` to `high` | `T1112`, `T1547.001`, `T1547.004`, `T1546.012`, `T1546`, `T1543.003` | Generic registry writes remain medium; Run/RunOnce, service, TaskCache, IFEO, Winlogon, WMI subscription, COM, AppInit, and LSA paths are high. |
| File behavior | `file-drop`, `file-deleted`, `executable-file-write`, `temp-executable-drop`, `script-file-drop`, `system-directory-executable-write`, `tasks-folder-file-write`, `startup-folder-persistence`, `downloaded-file-zone-identifier`, `browser-download-cache-write`, `download-archive-or-script-stage`, `r0-driver-file-write-signal` | `file.created`, `file.modified`, `file.deleted`, `driver.file`, `driver.file.*` | `low` to `high` | `T1070.004`, `T1105`, `T1059`, `T1053.005`, `T1547.001` where specific evidence applies | Executable/script extension, Temp/AppData/System32/Tasks/Startup paths, browser/download cache paths, Zone.Identifier metadata, staged archives/scripts, and driver file-operation metadata make guest and R0 file-write rows easier to triage. |
| Screenshot, memory, and dropped-file artifacts | `screenshot-captured-artifact`, `screenshot-capture-skipped`, `memory-dump-captured-artifact`, `memory-dump-capture-skipped`, `dropped-file-artifact-copied`, `dropped-file-artifact-skipped`, `dropped-executable-artifact-copied`, `artifact-manifest-written`, `file-masquerading-double-extension` | `screenshot.captured`, `screenshot.skipped`, `memory_dump.captured`, `memory_dump.skipped`, `artifact.dropped_file.copied`, `artifact.dropped_file.skipped`, `artifact.manifest.written`, `file.created`, `file.modified`, `driver.file` | `info` to `medium` | `T1105`, `T1036` where payload or masquerading evidence applies | Keeps opt-in screenshots, minidumps, released dropped files, copied executable/script/archive artifacts, manifest rows, and double-extension masquerading visible without adding new report fields. |
| Injection behavior | `remote-thread-injection-observed`, `process-injection-memory-primitive`, `process-injection-thread-or-apc-primitive`, `process-hollowing-signal`, `rwx-memory-protection-change`, `dll-injection-loadlibrary-signal` | `process.remote_thread`, `thread.remote`, `driver.thread`, `process.memory`, `process.write_memory`, `memory.protect`, `driver.process`, `api.call`, `image.load` | `medium` to `high` | `T1055`, `T1055.001`, `T1055.012` | Covers normalized remote-thread/APC events plus memory allocation/write, thread/APC, hollowing, RWX protection, and LoadLibrary-style DLL injection primitives. |
| Lateral movement behavior | `psexec-or-remote-service-lateral-command`, `winrm-powershell-remoting-lateral-command`, `admin-share-or-remote-copy-command`, `wmi-remote-execution-command`, `remote-scheduled-task-command`, `smb-network-port-observed`, `winrm-network-port-observed` | `process.start`, `network.tcp`, `network.udp`, `driver.network`, `pcap.tcp`, `pcap.udp`, `network.flow` | `medium` to `high` | `T1021.002`, `T1021.006`, `T1047`, `T1053.005`, `T1569.002`, `T1570` | Covers PsExec/remote service, WinRM/PowerShell remoting, admin-share staging, WMI/CIM remote execution, remote scheduled tasks, SMB ports, and WinRM ports. |
| Extended discovery and lateral movement | `rdp-network-port-observed`, `ssh-network-port-observed`, `ldap-kerberos-network-port-observed`, `tor-or-proxy-port-observed`, `admin-share-file-path-observed`, `remote-desktop-command-observed`, `network-share-discovery-command`, `system-discovery-command`, `process-discovery-command`, `network-discovery-command` | `process.start`, `file.created`, `file.modified`, `file.open`, `driver.file`, `network.tcp`, `network.udp`, `network.netstat`, `network.netstat.added`, `driver.network`, `pcap.tcp`, `pcap.udp`, `network.flow` | `medium` to `high` | `T1016`, `T1018`, `T1021.001`, `T1021.004`, `T1049`, `T1057`, `T1082`, `T1090`, `T1135`, `T1570` | Adds RDP/SSH/LDAP/Kerberos/domain-service ports, proxy/Tor ports, admin-share file paths, Remote Desktop commands, and common system/process/network/share discovery commands. |
| R0 driver callback signals | `r0-driver-process-event`, `r0-driver-file-write-signal`, `r0-driver-registry-change-signal`, `r0-driver-network-signal`, `driver-load-heartbeat`, `image-load-placeholder` | `driver.process`, `driver.file`, `driver.registry`, `driver.network`, `driver.event.reserved`, `driver.load`, `image.load` | `info` to `medium` | `T1105`, `T1112` where specific evidence applies | Keeps typed R0 process/file/registry/network callback rows visible in findings before richer source predicates or cross-event correlation exist. |
| R0 driver heartbeat | `driver-load-heartbeat` | `driver.event.reserved`, `driver.load` | `info` | None | Shows that the R0 event drain path produced the driver startup self-test or future driver-load heartbeat. |
| Image-load placeholder | `image-load-placeholder` | `image.load`, `image.loaded`, `driver.imageLoad`, `driver.image.load` | `info` | None yet | Keeps future R0 image callback rows from appearing as unexplained raw events. |
| Download-execute behavior | `powershell-evasion-download-abuse`, `script-interpreter-network-download`, `mshta-script-proxy-execution`, `regsvr32-scriptlet-proxy-execution`, `download-execute-chain-placeholder`, `execution-from-downloads-or-staging-path` | `process.start`, `behavior.download_execute`, `download.execute`, `file.downloaded.executed` | `high` | `T1059.001`, `T1218.005`, `T1218.010`, `T1105` | Covers script/LOLBin download primitives, mshta/regsvr32 URL/scriptlet execution, process starts from download/staging paths, and a future correlation placeholder for downloaded artifacts executed in the same analysis window. |
| Network behavior | `network-connection`, `http-network-activity`, `dns-query-observed`, `udp-network-activity`, `tls-or-https-network-activity`, `network-ip-literal-observed`, `driver-network-outbound-connect`, `driver-network-dns-traffic`, `driver-network-web-protocol-or-port`, `r0-driver-network-signal` | `network.tcp`, `network.udp`, `http.request`, `network.http`, `network.tls`, `tls.connection`, `dns.query`, `network.dns`, `driver.network` | `low` to `medium` | `T1105`, `T1071.001`, `T1071.004` | Records outbound TCP/UDP plus protocol-specific HTTP/DNS/TLS rows and driver network payloads when normalized collectors provide them. |
| Network probe depth | `dns-cache-added`, `dns-cache-txt-or-tunnel`, `dns-cache-dynamic-domain`, `netstat-connection-observed`, `netstat-added-connection`, `network-listener-opened`, `network-nonstandard-listener-port`, `network-connection-closed` | `dns.cache.added`, `network.netstat`, `network.netstat.added`, `network.netstat.removed`, `network.tcp.listener.opened`, `network.udp.listener.opened`, `network.tcp.closed` | `info` to `high` | `T1049`, `T1071.004`, `T1571` where specific evidence applies | Uses current TCP/DNS/netstat/listener probe output to report new DNS cache entries, tunnel-capable records, dynamic domains, netstat deltas, opened listeners, suspicious listener ports, and short-lived closed connections. |
| C2, DNS, TLS, and PCAP placeholders | `network-c2-beacon-event`, `network-c2-indicator-fields`, `dns-c2-tunnel-placeholder`, `http-c2-suspicious-user-agent`, `tls-sni-ja3-placeholder`, `pcap-artifact-placeholder`, `pcap-protocol-summary-placeholder`, `pcap-flow-observed-placeholder`, `pcap-http-request-observed`, `pcap-dns-query-observed`, `pcap-tls-clienthello-observed`, `dns-dynamic-domain-pattern`, `http-direct-ip-or-nonstandard-port` | `network.c2`, `c2.beacon`, `beacon.observed`, `http.request`, `network.http`, `network.tls`, `tls.connection`, `dns.query`, `network.dns`, `driver.network`, `pcap.summary`, `pcap.protocol.summary`, `network.pcap`, `pcap.packet`, `pcap.flow`, `pcap.tcp`, `pcap.udp`, `pcap.http`, `pcap.dns`, `pcap.tls`, `network.flow` | `info` to `high` | `T1071.001`, `T1071.004`, `T1573` where protocol-specific evidence exists | Adds explicit C2/beacon event support, C2 indicator fields, DNS tunnel/DGA placeholders, suspicious HTTP user agents, TLS SNI/JA3/certificate metadata placeholders, direct-IP/nonstandard web port triage, and PCAP flow/HTTP/DNS/TLS placeholders without changing collectors. |
| HTTP/TLS/PCAP deep triage | `http-executable-download`, `http-post-or-checkin-beacon`, `http-doh-request`, `http-proxy-or-tunnel-method`, `tls-invalid-certificate`, `tls-encrypted-clienthello-or-esni`, `pcap-executable-payload`, `pcap-dns-nxdomain-or-dga`, `pcap-flow-upload-exfil-placeholder`, `pcap-high-fanout-flow-placeholder` | `http.request`, `network.http`, `pcap.http`, `network.tls`, `tls.connection`, `pcap.tls`, `pcap.dns`, `dns.query`, `network.dns`, `pcap.flow`, `network.flow`, `pcap.packet`, `pcap.summary` | `low` to `high` | `T1041`, `T1071.001`, `T1071.004`, `T1090`, `T1105`, `T1573` where specific evidence applies | Adds executable/script/archive downloads, POST/check-in paths, DNS-over-HTTPS, HTTP tunnel/proxy methods, invalid/self-signed certificates, ECH/ESNI metadata, PE payload markers, NXDOMAIN/DGA DNS, upload/exfil placeholders, and high-fan-out packet summary fields. |
| Anti-analysis behavior | `process-timeout-long-sleep`, `anti-analysis-debugger-check`, `anti-analysis-vm-artifact-query`, `anti-analysis-delay-api-observed`, `anti-analysis-system-fingerprint-command`, `anti-analysis-process-enumeration-command`, `anti-analysis-hardware-registry-query`, `anti-analysis-timing-command`, `anti-analysis-sandbox-artifact-command`, `anti-analysis-user-activity-check`, `anti-analysis-cpuid-api-observed`, `anti-analysis-mac-disk-fingerprint-command`, `anti-analysis-sleep-duration-placeholder`, `anti-analysis-window-or-tool-check-api`, `anti-analysis-low-resource-check` | `process.timeout`, `antiAnalysis.debuggerCheck`, `antiAnalysis.sandboxCheck`, `debugger.detected`, `sandbox.detected`, `registry.query`, `file.open`, `process.query`, `api.call`, `process.start`, `driver.registry`, `system.fingerprint` | `medium` to `high` | `T1497`, `T1497.001`, `T1497.003`, `T1622` | Covers timeout/sleep evasion, explicit debugger/sandbox check events, VM/tool artifact queries, hardware/process enumeration, CPU/hypervisor checks, MAC/disk fingerprinting, duration-field placeholders, user-activity checks, and low-resource telemetry keys. |
| Defense evasion and security tooling | `anti-analysis-security-tool-termination-command`, `defender-disable-command`, `defender-policy-registry-disable`, `security-tool-stop-or-kill-command`, `firewall-defense-disable-command`, `event-log-clearing-command`, `amsi-etw-bypass-command-string` | `process.start`, `registry.set`, `registry.create`, `driver.registry` | `high` | `T1562.001`, `T1562.004`, `T1070.001`, `T1497` | Flags Defender disable/exclusion commands, Defender policy registry writes, EDR/security-tool stop or kill tokens, firewall disablement, event-log clearing, and AMSI/ETW bypass strings. |
| Collection and concealment extras | `screenshot-api-observed`, `hidden-file-attribute-command` | `api.call`, `process.start` | `medium` to `high` | `T1113`, `T1564.001` | Flags screen-capture API primitives and `attrib` hidden/system attribute commands separately from sandbox-generated screenshot artifacts. |
| Credential and LSASS behavior | `lsa-security-provider-persistence`, `lsass-memory-dump-command`, `lsass-process-access-observed`, `credential-store-access-observed`, `credential-dumping-tool-command`, `credential-lsass-process-access`, `credential-lsass-dump-command`, `credential-sam-system-hive-access`, `credential-hive-save-command`, `credential-browser-store-access`, `credential-vault-dpapi-access` | `registry.set`, `registry.create`, `driver.registry`, `process.start`, `process.open`, `process.access`, `api.call`, `driver.process`, `file.open`, `file.read`, `file.created`, `file.modified`, `registry.query`, `driver.file` | `high` to `critical` | `T1003.001`, `T1003.002`, `T1112`, `T1555`, `T1555.003` | Covers LSA package persistence, LSASS dump commands/access, SAM/SECURITY/SYSTEM/NTDS hive access, hive-save commands, browser credential databases, Vault/Credentials/DPAPI paths, and common credential dumping tool tokens. |
| Static PE traits | `static-pe-known-packer`, `static-pe-high-entropy-sections`, `static-section-writable-executable`, `static-embedded-url`, `static-pe-imports-present`, `static-pe-exports-present`, `static-pe-tls-callbacks`, `static-pe-resources-present` | `static.analysis.completed` | `info` to `medium` | `T1027.002`, `T1027`, `T1105` | Uses `dataContains.tags` emitted by static analysis for packers, entropy, RWX/abnormal sections, URLs, import/export/resource table presence, and TLS directory/callback hints. |
| Static resource traits | `static-resource-payload-candidate`, `static-resource-embedded-pe`, `static-resource-high-entropy` | `static.analysis.completed` | `medium` to `high` | `T1027.009`, `T1027` | Maps resource-directory parsing tags such as `resource_payload_candidate`, `resource_embedded_pe`, and `resource_high_entropy_data`. |
| Static import/API traits | `static-import-suspicious-api`, `static-import-process-injection`, `static-import-network-api`, `static-import-persistence-api`, `static-import-anti-analysis-api`, `static-import-dynamic-code`, `static-import-script-execution`, `static-import-file-drop`, `static-import-resource-api`, `static-import-registry-persistence`, `static-import-service-persistence` | `static.analysis.completed` | `medium` to `high` | `T1106`, `T1055`, `T1105`, `T1112`, `T1543.003`, `T1059`, `T1027.009`, `T1620`, `T1622` | StaticAnalyzer maps parsed imports and fallback API strings into tags such as `import_suspicious_api`, `import_process_injection_api`, `import_network_api`, `import_file_drop_api`, `import_resource_api`, `import_script_execution_api`, and persistence/anti-analysis subgroups. |
| Static export traits | `static-export-registration-entrypoint`, `static-export-service-entrypoint` | `static.analysis.completed` | `low` to `medium` | `T1218.010`, `T1543.003` | Export names are triage-only evidence; registration exports can indicate regsvr32-compatible DLL entry points, and service exports can support service DLL triage. |
| Static string indicators | `static-ip-address`, `static-windows-path-string`, `static-registry-path-string`, `static-persistence-string`, `static-script-command-string`, `static-encoded-command-string`, `static-lolbin-string`, `static-anti-sandbox-string` | `static.analysis.completed` | `low` to `medium` | `T1105`, `T1112`, `T1547.001`, `T1059`, `T1059.001`, `T1218`, `T1497` | Covers URL/IP/network indicators, Windows/registry paths, persistence paths, PowerShell encoded commands, living-off-the-land utility names, and VM/debugger/sandbox strings. |

## MITRE mapping notes

- `T1016`, `T1049`, `T1057`, `T1082`, and `T1135` cover command-line or
  probe-derived discovery signals for local network configuration, active
  connections, running processes, system identity, and network shares.
- `T1018` is used for LDAP/Kerberos/domain-service port evidence as remote
  system/domain discovery triage; port evidence alone does not prove domain
  compromise.
- `T1021.001` and `T1021.004` cover RDP/SSH port or command evidence.
  Existing SMB and WinRM mappings remain `T1021.002` and `T1021.006`.
- `T1036` covers double-extension file names that masquerade as documents,
  images, archives, or text files while ending in executable/script suffixes.
- `T1041` is reserved for packet/HTTP metadata labeled as upload or
  exfiltration until byte-threshold correlation exists.
- `T1090` covers HTTP CONNECT/WebSocket/proxy tunnel metadata and common
  proxy/Tor port evidence.
- `T1059` is used only when the command line references common Windows
  scripting interpreters.
- `T1003.001` is reserved for LSASS process access or dump evidence, while
  `T1003.002` is used for SAM/SECURITY/SYSTEM hive access and hive-save
  commands.
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
  network/download API imports, download staging paths, and download-execute
  placeholders until more precise seed mappings are available.
- `T1113` covers runtime screen-capture API calls from sample telemetry. The
  sandbox's own `screenshot.captured` artifact rows are intentionally unmapped
  collection evidence.
- `T1204.002` is used for execution from download/staging paths because the
  rule observes launch context, not the preceding transfer by itself.
- `T1055` is used only for static import groups that include process-injection
  primitives such as cross-process allocation/write/thread APIs, or dynamic
  events that explicitly report remote-thread/APC, hollowing, RWX memory, or
  LoadLibrary-style injection operations.
- `T1055.001` is used when LoadLibrary/LdrLoadDll-style DLL injection evidence
  is present; `T1055.012` is used for hollowing or suspended-process
  replacement signals.
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
- `T1497` covers static VM/sandbox/tool strings; `T1497.003` remains specific
  to time-based evasion and delay/sleep telemetry. Dynamic anti-analysis
  command rules also use `T1497` for VM/tool lookup, user-activity checks, and
  analysis-tool termination evidence.
- `T1497.001` is used for CPU, hypervisor, hardware, user-activity, and
  low-resource system checks.
- `T1546` is used as the broad event-triggered execution mapping for WMI
  event subscriptions, COM hijacks, and AppInit DLL registry evidence because
  the current seed map intentionally does not include every subtechnique.
- `T1546.012` is used for Image File Execution Options debugger registry paths.
- `T1547.004` is used for Winlogon Shell/Userinit/Notify/GinaDLL persistence
  paths.
- `T1555` and `T1555.003` cover credential stores broadly and browser
  credential databases specifically.
- `T1562.001` covers attempts to disable or modify security tools, Defender,
  AMSI, or ETW; `T1562.004` covers firewall disablement.
- `T1564.001` is used for `attrib +h/+s` command-line evidence that attempts
  to hide staged files or persistence artifacts.
- `T1569.002` covers remote service execution command evidence; `T1570` covers
  lateral tool transfer over UNC/admin-share style paths.
- `T1573` is used for TLS/SNI/JA3 placeholder evidence where encrypted-channel
  metadata is available but content is not inspected.
- `T1571` covers listener or endpoint metadata that uses non-standard ports
  often associated with reverse shells, proxies, Tor, or custom C2 channels.
- `T1620` is used for dynamic code loading and memory-protection import groups
  as a triage hint, not as proof of reflective loading at runtime.
- `T1622` is used for debugger/timing import strings where static evidence
  suggests anti-analysis checks.
- Rules without MITRE IDs are intentionally unmapped because the current event
  is health, placeholder, generic telemetry, or intentionally too broad for a
  stable technique assignment.

## Static-analysis tag contract

The current report model does not have first-class `imports`, `exports`, or
`tls` fields. StaticAnalyzer therefore records lightweight static depth through
existing fields:

- `Tags`: rule-facing tokens such as `imports_present`, `exports_present`,
  `resources_present`, `tls_directory_present`, `tls_callbacks`,
  `resource_payload_candidate`, `resource_embedded_pe`,
  `writable_executable_section`, `import_suspicious_api`,
  `import_process_injection_api`, `import_network_api`,
  `import_file_drop_api`, `import_resource_api`,
  `import_script_execution_api`, `registry_path_string`,
  `script_execution_string`, `ip_address`,
  `export_registration_entrypoint`, `packer_section_name`, and
  `packer_string_hint`.
- `InterestingStrings`: bounded human-readable evidence such as
  `section:.text,va=...`, `import:kernel32.dll!VirtualAllocEx`,
  `export:DllRegisterServer`, `resource:rcdata,size=...`,
  `url:https://...`, `path:C:\...`, `ip:8.8.8.8`, and
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
