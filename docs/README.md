# Documentation map and canonical status

This page is the lightweight index for the current MVP documentation. It is
intended to reduce drift: when two documents cover the same topic, update the
canonical document below and keep the other document as a short pointer or
historical note.

## Current MVP in one paragraph

The current MVP is a local Hyper-V sandbox flow: an operator selects or locally
uploads an `.exe` in the WebUI/API, the host plans the job and hashes/static-
analyzes the sample, explicit live mode restores/starts the prepared Windows 10
golden VM, Guest Agent and optional R0Collector collect guest/R0 behavior,
WebUI shows live progress and raw events, optional VirusTotal enrichment performs
hash-only lookup, host import folds events/artifacts into findings, and the
renderer emits `report.json`, `report.html`, `report.zh.html`, and
`report.en.html` under the runtime root.

Recorded local evidence for this end-to-end path is in
[`webui-real-r0-e2e.md`](webui-real-r0-e2e.md). The default safe path remains
PlanOnly/dry-run and does not mutate a VM.

## Repository hygiene reminder

Commit only source, rules, config templates, and documentation. Do **not**
commit samples, VM disks/checkpoints/exports, runtime job folders, generated
reports, guest payload binaries, packet captures, memory dumps, `bin/`, `obj/`,
`x64/`, `.sys`, `.pdb`, `.obj`, certificates, private keys, API keys, guest
passwords, or local `sandbox.local.json` / install-state files.

## Canonical documents by task

| Task | Canonical document(s) | Notes |
| --- | --- | --- |
| Project overview and guardrails | [`../README.md`](../README.md), [`current-architecture-and-operations.md`](current-architecture-and-operations.md) | Root README is the entry point; current architecture/operations is the canonical MVP status and operator map. |
| Install, local config, secrets | [`install.md`](install.md) | Keeps guest password, VT key, and VM config guidance in one place. |
| Daily WebUI / CLI entry point | [`run.md`](run.md) | Covers WebUI startup, Analyze shortcuts, PlanOnly vs Live, report rebuild, and artifact inspection. |
| Hyper-V live operator flow | [`hyperv-e2e-runbook.md`](hyperv-e2e-runbook.md), [`hyperv-readiness.md`](hyperv-readiness.md) | Scripted PlanOnly/WhatIf/Live flow and read-only preflight checks. |
| Golden VM and payload staging | [`golden-vm.md`](golden-vm.md), [`guest-payload-staging.md`](guest-payload-staging.md) | VM baseline and guest tool publishing; outputs stay outside git. |
| WebUI/API validation evidence | [`webui-real-r0-e2e.md`](webui-real-r0-e2e.md), [`verification.md`](verification.md), [`testing.md`](testing.md) | Use `webui-real-r0-e2e.md` as the current local live evidence record; use verification/testing for repeatable gates. |
| Artifacts and reports | [`artifacts.md`](artifacts.md), [`artifact-manifest.md`](artifact-manifest.md), [`report-schema.md`](report-schema.md), [`report-ux.md`](report-ux.md) | Artifact storage/indexing, report JSON/HTML shape, bilingual report UX, and evidence links. |
| Guest collection | [`guest-agent.md`](guest-agent.md), [`guest-agent-framework.md`](guest-agent-framework.md) | Event/artifact coverage and probe framework notes. |
| R0 collection and driver ABI | [`r0-collector.md`](r0-collector.md), [`r0-jsonl-schema.md`](r0-jsonl-schema.md), [`r0-driver-core.md`](r0-driver-core.md), [`driver-install.md`](driver-install.md) | Collector JSONL and kernel/user ABI are canonical; driver install is the VM-only operator runbook. |
| R0 producer notes | [`r0-driver.md`](r0-driver.md), [`r0-file-monitor.md`](r0-file-monitor.md), [`r0-process-registry-image.md`](r0-process-registry-image.md), [`r0-network.md`](r0-network.md) | Producer-specific notes should link back to `r0-driver-core.md` instead of repeating ABI details. |
| Behavior rules and static analysis | [`behavior-rule-matrix.md`](behavior-rule-matrix.md), [`rules-windows-sandbox.md`](rules-windows-sandbox.md), [`static-analysis.md`](static-analysis.md), [`../rules/static-analysis-notes.md`](../rules/static-analysis-notes.md) | Matrix is exhaustive; rules-windows is the readable summary; static docs cover host-side evidence. |
| VirusTotal | [`virustotal.md`](virustotal.md) | Hash-only optional enrichment; no sample upload. |
| Packaging/release | [`release.md`](release.md) | Source/runtime package boundaries and artifact exclusions. |

## Historical or background notes

These files remain useful, but they should not be treated as the current status
source of truth without checking the canonical docs above:

- [`progress.md`](progress.md): historical progress snapshot and planning
  percentages.
- [`extracted-results-summary.md`](extracted-results-summary.md): research and
  narrative summary; current status has moved to
  `current-architecture-and-operations.md`.
- [`hyperv-vm-current-state.md`](hyperv-vm-current-state.md): dated read-only VM
  observation; rerun readiness before live work.
- [`microstep-report-benchmark.md`](microstep-report-benchmark.md),
  [`research-basis.md`](research-basis.md), and
  [`open-source-sandbox-references.md`](open-source-sandbox-references.md):
  design/reference material.
- [`r0-merge-review.md`](r0-merge-review.md) and
  [`r0-next-implementation-plan.md`](r0-next-implementation-plan.md): merge or
  implementation planning notes; verify against current source before acting.

## Overlap policy

- Prefer linking to the canonical document over copying long PowerShell blocks
  into multiple files.
- If a runbook must repeat a command, keep the guardrails with it: PlanOnly is
  safe, Live is explicit and mutates the configured VM, `CSignTool.exe` is not
  part of the default path, and generated outputs must remain outside git.
- Dated local evidence should include the date and should point back to the
  repeatable readiness or verification command.
