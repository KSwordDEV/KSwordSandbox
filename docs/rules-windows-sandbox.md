# Windows sandbox behavior rules

This note summarizes the practical Windows sandbox rule expansion in
`rules/behavior-rules.json`.

The rule engine is intentionally simple: it matches event type, path
substrings, command-line substrings, data-key presence, and data-field
substrings. Rules therefore favor stable evidence already emitted by guest
events and typed R0 collector rows rather than requiring correlation that the
engine does not support yet.

## Added coverage

- Registry persistence:
  - Run, RunOnce, RunOnceEx, policy Run, and StartupApproved autostart paths.
  - Service configuration hives, including typed `driver.registry` `keyPath`
    / `path` fields.
  - Service `ImagePath`, `ServiceDll`, failure-command, and account/value
    changes when paired with a service registry path.
  - Scheduled TaskCache registry paths, including typed driver payload fields.
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
  - Certutil, bitsadmin, curl/wget, BITS, and PowerShell web-request staging.
  - Windows Script Host script execution.
- Anti-analysis:
  - VM/tool artifact paths expanded for common VMware, VirtualBox, Hyper-V,
    QEMU, Xen, debugger, reverse-engineering, and traffic-analysis tools.
  - System/BIOS/hardware fingerprint commands.
  - Process/module/driver enumeration commands.
  - Hardware, BIOS, ACPI, PCI, and hypervisor-identifying registry paths.
  - Command-line delay primitives such as `timeout`, ping-delay, `Start-Sleep`,
    and wait APIs.

## Triage notes

These rules are reporting aids, not verdicts. Some commands such as
`tasklist`, `systeminfo`, service configuration, or scheduled-task changes can
be legitimate installer/admin behavior. Treat high-severity persistence and
script-abuse hits as priority evidence and inspect the underlying event rows
before assigning malicious intent.
