# Research basis

This document records the external systems and platform documentation used to
shape the v1 KSwordSandbox design. The repository keeps these references as
design inputs only; it does not vendor third-party sandbox code or clone large
external repositories into git.

## Sandbox behavior model

- CAPE Sandbox documents a workflow for submitting samples, preparing guests,
  collecting analysis results, and enabling reporting modules. KSwordSandbox
  adopts the same broad separation of host orchestration, guest execution,
  processing, and reporting.
  - https://capev2.readthedocs.io/en/latest/
- Cuckoo Sandbox signatures classify analysis results into behavior matches
  with severity, categories, references, and matched data. KSwordSandbox uses a
  compact JSON rule model with equivalent concepts: rule ID, severity, summary,
  MITRE technique, tags, and evidence events.
  - https://cuckoo.readthedocs.io/en/latest/customization/signatures/
- DRAKVUF Sandbox is a useful long-term reference for web-driven task
  submission and low-agent/agentless analysis, but v1 intentionally starts with
  guest-side Windows collection because Hyper-V VMI on Windows hosts would add
  substantial platform risk.
  - https://drakvuf-sandbox.readthedocs.io/en/latest/

## Windows behavior matrix

- MITRE ATT&CK Windows Matrix is the baseline taxonomy for behavior mapping.
  v1 seeds map scripting, registry modification, and network activity to ATT&CK
  technique IDs and will expand as R0 telemetry arrives.
  - https://attack.mitre.org/matrices/enterprise/windows/

## Hyper-V host orchestration

- PowerShell Direct supports `Invoke-Command`, persistent sessions, and
  host/guest file copy for Windows 10 or newer guests running locally on a
  Hyper-V host. KSwordSandbox runbooks use this for guest command execution and
  artifact collection.
  - https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct
- `Copy-VMFile` copies files from the host into a VM and supports creating the
  guest destination path. KSwordSandbox uses it to stage submitted samples.
  - https://learn.microsoft.com/en-us/powershell/module/hyper-v/copy-vmfile

## R0 telemetry anchors

- `PsSetCreateProcessNotifyRoutineEx` registers process create/exit callbacks.
  This is the primary R0 process telemetry anchor.
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- `CmRegisterCallbackEx` registers registry callbacks and is the R0 anchor for
  registry create/set/delete behavior events.
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex
- `FltRegisterFilter` registers a file-system minifilter, which is the planned
  R0 file telemetry anchor for created, modified, deleted, and dropped files.
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltregisterfilter
- Windows Filtering Platform callout drivers are the planned R0 network
  telemetry anchor for outbound connection and flow metadata.
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-windows-filtering-platform-callout-drivers

## Microstep/TI-style report target

The referenced local report is treated as the visual benchmark. The local HTML
renderer should grow toward these sections:

- cover and sample identity;
- table of contents;
- risk summary;
- behavior detections;
- multi-dimensional detections;
- engine and rule hits;
- static analysis;
- dynamic analysis;
- process tree;
- dropped files;
- registry behavior;
- network behavior;
- screenshots and failure reasons.

The extracted page-by-page summary and implementation implications are recorded
in `docs/microstep-report-benchmark.md`.
