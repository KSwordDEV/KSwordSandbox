# Windows sandbox behavior rules

This note summarizes the practical Windows sandbox rule expansion in
`rules/behavior-rules.json`.

The rule engine is intentionally simple: it matches event type, path
substrings, command-line substrings, data-key presence, and data-field
substrings. Rules therefore favor stable evidence already emitted by guest
events and typed R0 collector rows rather than requiring correlation that the
engine does not support yet.

The current rule set has 257 behavior rules. Newer high-value rules may include
metadata-only `confidence` and `evidenceFields` values; those fields do not
change matching, but they document expected triage confidence and the evidence
fields analysts should inspect first.

## Added coverage

- Probe/artifact evidence:
  - Screenshot capture and skip diagnostics through `screenshot.captured` /
    `screenshot.skipped`.
  - Opt-in sample minidump capture and skip diagnostics through
    `memory_dump.captured` / `memory_dump.skipped`.
  - Dropped-file artifact copy/skip rows, copied executable/script/archive
    payloads, and manifest write events.
- Full process tree:
  - `process.tree` root/depth/lineage/child-count rows and
    `process.tree_unavailable` diagnostics.
  - Process start failures, LOLBin nodes inside the tree, and execution from
    user-writable staging paths such as Temp, AppData, Downloads, ProgramData,
    and Public.
- Registry persistence:
  - Run, RunOnce, RunOnceEx, policy Run, and StartupApproved autostart paths.
  - Service configuration hives, including typed `driver.registry` `keyPath`
    / `path` fields.
  - Service `ImagePath`, `ServiceDll`, failure-command, and account/value
    changes when paired with a service registry path.
  - Scheduled TaskCache registry paths, including typed driver payload fields.
  - Office add-in/startup registry paths, accessibility IFEO debugger hijacks,
    and logon-script registry/file locations.
- System inventory diff persistence:
  - `service.created` / `service.modified` and suspicious service raw command
    metadata.
  - `scheduled_task.created` / `scheduled_task.modified` and task targets that
    launch scripts, shells, or user-writable payloads.
  - `startup_item.created` / `startup_item.modified`, executable startup-item
    values, deleted persistence items, and truncated service/task/startup diff
    diagnostics.
- Scheduled-task and service commands:
  - `schtasks.exe /create`, task changes, PowerShell ScheduledTasks cmdlets,
    legacy `at.exe`, `sc create/config/failure`, and service PowerShell cmdlets.
- Typed driver events:
  - `driver.registry` Run/service/TaskCache paths via top-level `path` and
    typed data fields.
  - `driver.network` outbound/connect, DNS, and HTTP/HTTPS/web-port evidence.
- Script abuse:
  - PowerShell encoded commands, execution-policy bypass, hidden windows,
    expression evaluation, Base64 decode, and web-download primitives.
  - Mshta and regsvr32 scriptlet proxy execution.
  - Mavinject, InstallUtil, MSBuild inline-task, and Regasm/Regsvcs
    proxy-execution command evidence.
  - Certutil, bitsadmin, curl/wget, BITS, and PowerShell web-request staging.
  - Windows Script Host script execution.
- DNS/HTTP/TLS/PCAP:
  - DNS cache additions, TXT/NULL/CNAME/tunnel-style entries, and dynamic DNS
    domain fragments from the current network probe.
  - HTTP executable/script/archive downloads, POST/check-in beacon paths,
    DNS-over-HTTPS requests, and CONNECT/WebSocket/proxy tunnel indicators.
  - TLS invalid/self-signed certificate evidence plus ECH/ESNI metadata
    placeholders.
  - Baseline PCAP import placeholders for `pcap.summary`,
    `pcap.protocol.summary`, `pcap.flow`, `pcap.tcp`, `pcap.udp`,
    `pcap.http`, `pcap.dns`, `pcap.tls`, `network.pcap`, `pcap.packet`, and
    `network.flow`.
  - PCAP importer field aliases for summary counts (`flowCount`,
    `packetCount`), flow endpoints (`sourceIp`, `sourcePort`,
    `destinationIp`, `destinationPort`, `protocol`), HTTP metadata (`host`,
    `method`, `uri`, `contentType`, `payloadMagic`), DNS metadata
    (`queryName`, `rcode`), and TLS SNI (`sni`).
  - PCAP executable payload, NXDOMAIN/DGA DNS, upload/exfiltration, and
    high-fan-out flow placeholders.
  - `.onion` domains, long/encoded HTTP URIs, domain-fronting labels, and TLS
    C2 classification fields when emitted by guest, PCAP, or enrichment rows.
- Network/lateral movement:
  - Netstat observed/added/removed rows, listener-opened deltas, suspicious
    non-standard listener ports, RDP/SSH/LDAP/Kerberos/domain ports, and
    Tor/proxy ports.
  - Admin-share file paths, Remote Desktop commands, network-share discovery,
    system/process/network discovery commands.
  - `cmdkey` credential staging and domain trust / domain controller discovery
    commands.
- Anti-analysis:
  - VM/tool artifact paths expanded for common VMware, VirtualBox, Hyper-V,
    QEMU, Xen, debugger, reverse-engineering, and traffic-analysis tools.
  - System/BIOS/hardware fingerprint commands.
  - Process/module/driver enumeration commands.
  - Hardware, BIOS, ACPI, PCI, and hypervisor-identifying registry paths.
  - Command-line delay primitives such as `timeout`, ping-delay, `Start-Sleep`,
    and wait APIs.
  - Uptime/boot-time checks and parent-process/PEB inspection API evidence.
- Collection/defense-evasion extras:
  - Screen-capture API calls (`BitBlt`, `GetDC`, `PrintWindow`, foreground or
    desktop window APIs).
  - Clipboard access APIs and screenshot-like files created by the sample.
  - Double-extension masquerading drops and `attrib` hidden/system file
    attribute commands.

## Triage notes

These rules are reporting aids, not verdicts. Some commands such as
`tasklist`, `systeminfo`, service configuration, or scheduled-task changes can
be legitimate installer/admin behavior. Treat high-severity persistence and
script-abuse hits as priority evidence and inspect the underlying event rows
before assigning malicious intent.
