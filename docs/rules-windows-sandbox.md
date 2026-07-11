# Windows sandbox behavior rules

This note summarizes the practical Windows sandbox rule expansion in
`rules/behavior-rules.json`.

For exact current rule count, schema details, and the full matrix, use
`docs/behavior-rule-matrix.md` as the source of truth. This page is the readable
operator/contributor summary and should avoid hard-coded counts that drift.

The rule engine is intentionally simple and deterministic: it matches event
type, path/command-line substrings, all-of path and command-line substrings,
timeout-bounded regexes, data-key presence or absence, exact data values,
data-field substrings, same-field AND predicates, and numeric ranges. Rules
therefore favor stable evidence already emitted by guest events, typed R0
collector rows, and normalized protocol/correlation rows rather than requiring
stateful joins in the engine.

The current rule set spans behavior, enrichment, static, and collection-health
signals. The recent open-source-reference pass adds sandbox-safe Odbcconf, MMC,
and named-pipe impersonation coverage using public ATT&CK/Sigma-style behavior
ideas and explicit false-positive guards. The previous v14 combination and
MITRE-quality pass built on the v13 advanced predicates with high-signal
coverage for
Run-key/dropper persistence, Defender exclusion dropper evasion,
security-tool discovery, credential-file search, periodic C2 from
user-writable payloads, anti-sandbox VM-check sleep gates, and script-download
dropped-file artifacts. The previous v13 pass added regex, numeric-range,
absent-field, and same-field-AND predicates; the v12 targeted Windows behavior
and false-positive-control pass added high-value coverage for remote
script/proxy execution, NTDS/Kerberos/browser credential access,
Defender/UAC/PowerShell logging tamper, Office/browser persistence, WinRM
enablement, TLS dynamic-DNS/onion SNI, and authenticated HTTP exfil metadata.
Newer rules may include metadata-only `confidence`, `tags`, `evidenceFields`,
`titleZh`, and `summaryZh` values; those fields do not change matching, but
they document expected triage confidence, bilingual operator text, report
grouping intent, and the evidence fields analysts should inspect first.

## Added coverage

- Open-source reference behavior rules:
  - Odbcconf `REGSVR` proxy execution with a user-writable DLL path, mapped to
    `T1218.008`.
  - MMC loading user-writable `.msc` files, mapped to `T1218.014`.
  - Named-pipe impersonation API/pipe metadata, mapped to `T1134.001`.
- Combination rules and MITRE quality:
  - Run/RunOnce persistence rules that require a user-writable payload value
    plus dropped-file or download-execute correlation context.
  - Defender exclusion tamper rules that require both Defender Exclusions paths
    and a dropped/staged user-writable payload value.
  - Security software discovery (`T1518.001`) through process-listing commands
    paired with EDR, Defender, packet-capture, VM, or analysis-tool names.
  - Credential-file search (`T1552.001`) in user-profile scopes with password,
    secret, token, wallet, private-key, or KeePass-like filename terms.
  - Periodic C2 flow rules that require user-writable process paths,
    destination IPs, beacon interval, jitter, and C2/beacon labels.
  - Anti-sandbox sleep-gate rules that require VM/sandbox check text plus a
    long numeric sleep duration.
  - Dropped-file artifact rules that require source path, script/LOLBin
    downloader process, and HTTP(S) source URL metadata rather than collection
    output paths alone.
  - Process hollowing and LoadLibrary-style DLL injection now map to
    `T1055.012` and `T1055.001` respectively.
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
  - Run/RunOnce values that point to user-writable payload paths or launch
    script interpreters/LOLBins, plus StartupApproved state changes.
  - Service configuration hives, including typed `driver.registry` `keyPath`
    / `path` fields.
  - Service `ImagePath`, `ServiceDll`, failure-command, and account/value
    changes when paired with a service registry path.
  - User-writable service binaries, service failure-command persistence,
    kernel-driver service installs, weak service ACL metadata, and unquoted
    Program Files style ImagePath values for hijack review.
  - Scheduled TaskCache registry paths, including typed driver payload fields.
  - Scheduled-task COM handlers and task XML/actions that target user-writable
    payload paths.
  - Office add-in/startup registry paths, accessibility IFEO debugger hijacks,
    and logon-script registry/file locations.
  - Office macro/Protected View policy weakening, Outlook forms/homepage
    persistence, browser extension force-install policies, browser native
    messaging host registry/manifest writes, and IE Browser Helper Object or
    toolbar hooks with payload/update URL/user-writable constraints.
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
  - PowerShell in-memory reflection/shellcode loaders and PowerShell process
    trees that spawn LOLBins such as rundll32, regsvr32, mshta, certutil,
    bitsadmin, or installutil.
  - CMSTP and Control Panel proxy-execution command lines.
  - HH/HTML Help remote script or CHM proxy execution, MSXSL remote XSL/script
    execution, and `forfiles /c` launches of shells, script interpreters, or
    proxy-execution LOLBins.
- DNS/HTTP/TLS/PCAP:
  - DNS cache additions, TXT/NULL/CNAME/tunnel-style entries, and dynamic DNS
    domain fragments from the current network probe.
  - HTTP executable/script/archive downloads, POST/check-in beacon paths,
    DNS-over-HTTPS requests, and CONNECT/WebSocket/proxy tunnel indicators.
  - TLS invalid/self-signed certificate evidence plus ECH/ESNI metadata
    indicators.
  - Baseline PCAP import metadata coverage for `pcap.summary`,
    `pcap.protocol.summary`, `pcap.flow`, `pcap.tcp`, `pcap.udp`,
    `pcap.http`, `pcap.dns`, `pcap.tls`, `network.pcap`, `pcap.packet`, and
    `network.flow`.
  - PCAP importer field aliases for summary counts (`flowCount`,
    `packetCount`), flow endpoints (`sourceIp`, `sourcePort`,
    `destinationIp`, `destinationPort`, `protocol`), HTTP metadata (`host`,
    `method`, `uri`, `contentType`, `payloadMagic`), DNS metadata
    (`queryName`, `rcode`), and TLS SNI (`sni`).
  - PCAP executable payload, NXDOMAIN/DGA DNS, upload/exfiltration
    indicators, and flow-count metadata.
  - `.onion` domains, long/encoded HTTP URIs, domain-fronting labels, and TLS
    C2 classification fields when emitted by guest, PCAP, or enrichment rows.
  - Periodic beacon interval/jitter metadata, DNS reputation-risk labels,
    high-entropy DNS metadata, HTTP JSON tasking/gate URIs, host-header
    mismatch labels, and TLS certificate reputation labels.
  - TLS SNI/serverName values that expose `.onion` or common dynamic-DNS
    domains, plus constrained HTTP POST rows carrying authorization, cookie,
    bearer-token, password, session, or explicit credential-exfil labels.
  - Root certificate store modification commands and registry/file paths.
  - DNS tunnel/DGA labels, TLS SNI/JA3/certificate metadata, PCAP artifact
    import rows, PCAP endpoint flows, upload/exfil labels, and PCAP flow-count
    metadata now use concrete rule names and documented evidence fields.
- Network/lateral movement:
  - Netstat observed/added/removed rows, listener-opened deltas, suspicious
    non-standard listener ports, RDP/SSH/LDAP/Kerberos/domain ports, and
    Tor/proxy ports.
  - Admin-share file paths, Remote Desktop commands, network-share discovery,
    system/process/network discovery commands.
  - `cmdkey` credential staging and domain trust / domain controller discovery
    commands.
  - Explicit WinRM / PowerShell Remoting enablement through `Enable-PSRemoting`,
    `winrm quickconfig`, WSMan quick-config, AllowUnencrypted, or TrustedHosts
    command evidence.
- Anti-analysis:
  - VM/tool artifact paths expanded for common VMware, VirtualBox, Hyper-V,
    QEMU, Xen, debugger, reverse-engineering, and traffic-analysis tools.
  - System/BIOS/hardware fingerprint commands.
  - Process/module/driver enumeration commands.
  - Hardware, BIOS, ACPI, PCI, and hypervisor-identifying registry paths.
  - Command-line delay primitives such as `timeout`, ping-delay, `Start-Sleep`,
    and wait APIs.
  - Uptime/boot-time checks and parent-process/PEB inspection API evidence.
  - Debug-register/hardware-breakpoint API checks and host identity
    hostname/username/domain sandbox checks.
  - Sleep-duration and accelerated/skipped-sleep telemetry fields carry
    explicit confidence and evidence-field metadata; v13/v14 numeric-range
    rules now elevate only bounded long-sleep or VM-check sleep-gate evidence.
- Collection/defense-evasion extras:
  - Screen-capture API calls (`BitBlt`, `GetDC`, `PrintWindow`, foreground or
    desktop window APIs).
  - Clipboard access APIs and screenshot-like files created by the sample.
  - Double-extension masquerading drops and `attrib` hidden/system file
    attribute commands.
  - Token impersonation, sensitive privilege enablement, auto-elevate UAC
    registry/LOLBin chains, debug/all-access process opens, and user-writable
    DLL image-load evidence.
  - Defender service `Start=4`, Defender realtime/security policy disable
    values, Defender exclusions that point at user-writable staging paths,
    PowerShell ScriptBlock/Module/Transcription logging disable values, UAC
    policy weakening, remote UAC `LocalAccountTokenFilterPolicy`, and
    SilentCleanup `windir` environment hijacks.
- Credential access:
  - NTDS extraction through `ntdsutil ifm`, esentutl/diskshadow/vssadmin or
    copy-style commands touching `ntds.dit`.
  - Kerberos ticket export/dump tokens such as `sekurlsa::tickets`,
    `kerberos::list /export`, and Rubeus ticket operations.
  - Non-browser access to Chromium `Local State` and Cookie databases, with
    normal browser process exclusions to control expected browser startup
    noise.

## VirusTotal enrichment quality

VirusTotal lookups remain optional and do not upload samples. The lookup model
now derives clear statuses/verdicts for report or rule use without requiring a
real API key during local builds:

- `not_configured` and `missing_hash` mean no lookup was attempted.
- `not_found` records HTTP 404 as coverage metadata.
- `rate_limited` records HTTP 429 and exposes `RetryAfterUtc` when available.
- `authentication_failed` distinguishes invalid keys from transport failures.
- successful reports derive `malicious`, `suspicious`, `clean`, or `unknown`
  from flattened engine counts.

If a caller converts `VirusTotalLookupResult.ToRuleEvent()` into normalized
events, VT rules consume one-level fields such as `vtVerdict`, `vtStatus`,
`vtMalicious`, `vtSuspicious`, `httpStatusCode`, and `retryAfterUtc`. These
rules are tagged as enrichment metadata and intentionally have no MITRE
technique because external reputation is not local sample behavior.

## Triage notes

These rules are reporting aids, not verdicts. Some commands such as
`tasklist`, `systeminfo`, service configuration, scheduled-task changes, WinRM
configuration, or browser/Office policy changes can be legitimate
installer/admin behavior. Treat high-severity persistence, credential,
defense-evasion, and script-abuse hits as priority evidence and inspect the
underlying event rows before assigning malicious intent. Collection-health
rows, R0 collector availability/plumbing, VirusTotal `not_configured` /
`not_found` / `rate_limited`, and sandbox Agent/R0Collector self-noise remain
metadata or exclusions rather than sample-malicious behavior. New combination
rules also require paired path/data/regex/numeric evidence before promoting
persistence, defense-evasion, C2, anti-sandbox, credential-search, or
dropped-file artifacts into primary behavior findings.
