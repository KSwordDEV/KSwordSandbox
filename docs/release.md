# KSwordSandbox release packaging checklist

中文优先：本页描述本机打包闭环。`scripts/package-portable.ps1` 只在本机
staging/zip，不提交、不 push、不发布；清单和脚本会拒绝本机 secret、VM
磁盘/快照、样本、报告、仓库构建二进制、符号和签名材料。

This is the draft release wrapper for productized source and portable runtime
packages. It is intentionally conservative: packages are staged outside the
repository, release artifacts are not pushed by the packaging script, and
sensitive/runtime material is excluded by manifest policy.

## Package types

- Source package: repository source, rules, docs, tests, packaging metadata, and
  scripts needed to rebuild from source. It excludes VM state, submitted
  samples, local runtime roots, reports, captures, generated binaries, archives,
  signing material, local secrets, and private certificate files.
- Runtime portable package: operator-facing docs/config/rules/scripts plus
  pre-published runtime payloads copied from an external `RuntimePublishRoot`.
  It must not copy from repository `bin/`, `obj/`, or `x64/` folders. Published
  host/guest/tool payloads are expected under external folders such as
  `host-web`, `guest-tools`, `tools/job-tool`, and `tools/postprocess`.

## Manifests

- `packaging/source-package.manifest.json`
- `packaging/runtime-package.manifest.json`

The manifests are the package contract. Update them before changing what the
portable script copies. Keep exclusions broad enough to block:

- submitted samples and generated harmless-sample binaries;
- Hyper-V disks, checkpoints, snapshots, and other VM exports;
- local runtime roots, reports, event streams, captures, dumps, screenshots,
  packet captures, and extracted evidence;
- Hyper-V state files such as `.vmcx`, `.vmrs`, `.vmgs`, `.vsv`, `.vhdset`,
  `.vhdpmem`, `.vhd`, `.vhdx`, `.avhd`, and `.avhdx`;
- build intermediates and symbols from `bin/`, `obj/`, `x64/`, `.vs/`,
  `TestResults/`, and `coverage/`;
- signed driver binaries and private signing/certificate material;
- local config, environment files, DPAPI backups, and install state.

Both manifests also carry a `releaseContract` and `stagedMetadata` section.
These are operator-facing guardrails, not build inputs: they document that
packaging/readiness must not mutate Hyper-V, sign drivers, call `CSignTool.exe`,
push, or publish, and they define the generated metadata fields reviewers should
expect inside each staged package.

## Pre-release checklist

1. Coordinate with other workers before cutting a package. Do not revert their
   work and do not include unrelated local artifacts.
2. Confirm the intended release revision and package version.
3. Run repository policy:

   ```powershell
   .\scripts\Test-RepositoryPolicy.ps1
   ```

4. Verify PowerShell script syntax:

   ```powershell
   $tokens = $null
   $errors = $null
   [System.Management.Automation.Language.Parser]::ParseFile(
     (Resolve-Path .\scripts\package-portable.ps1),
     [ref]$tokens,
     [ref]$errors
   ) | Out-Null
   if ($errors.Count -gt 0) { $errors | Format-List *; exit 1 }
   ```

5. For source packages, use a clean worktree unless the release note explicitly
   documents why dirty source was packaged.
6. For runtime packages, publish host/guest/tool payloads into an external
   folder such as `D:\Temp\KSwordSandbox\publish`; do not stage payloads into
   the repository.
7. Build the package locally:

   ```powershell
   .\scripts\package-portable.ps1 `
     -PackageKind source `
     -OutputRoot 'D:\Temp\KSwordSandbox\packages'

   .\scripts\package-portable.ps1 `
     -PackageKind runtime `
     -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' `
     -OutputRoot 'D:\Temp\KSwordSandbox\packages'
   ```

8. Inspect the generated `package-manifest.generated.json` inside the staged
   package and verify that no forbidden path or extension was copied. Reviewers
   should check `fileInventory[].sha256`, `fileInventory[].sizeBytes`,
   `packageDiagnostics`, `safetyContract`, `runtimePublishRoot`, `gitStatus`,
   and `manifestRequiredChecks`.
9. Smoke-test the runtime package on a clean host or VM using only the portable
   package contents and local configuration.
10. Record hashes and release notes. Push/publish only when a release manager
    explicitly requests it; the package script does not push.

## Open-source MVP readiness checklist

Use this as the concise release manager gate before publishing the first public
MVP package.

- **Repository policy:** `.\scripts\Test-RepositoryPolicy.ps1` passes for the
  current tree and, before commit, `.\scripts\Test-RepositoryPolicy.ps1
  -StagedOnly` passes for staged files.
- **Artifact exclusion:** no samples, job folders, reports, event streams,
  captures, dumps, screenshots, VM exports, Hyper-V checkpoints, `bin/`, `obj/`,
  `x64/`, `.sys`, `.pdb`, archives, certificates, private keys, DPAPI backups,
  `sandbox.local.json`, or `install-state.json` are tracked or packaged.
- **Packaging locality:** package output root is outside the repository, for
  example `D:\Temp\KSwordSandbox\packages`; the packaging script only stages and
  zips locally.
- **No legacy signing tool:** build, smoke, package, and onboarding commands do
  not call `CSignTool.exe` or old KSword interactive signing wrappers.
- **Known R0 signing limitation:** real R0 remains an optional lab path, not a
  default release promise. The driver can be compiled, but loading it requires a
  test-signed `.sys`, guest Windows test-signing, and an isolated Hyper-V VM.
  Keep `.sys`, `.pdb`, certificates, and private signing material outside git
  and outside source packages.
- **Hyper-V live prerequisites documented:** the operator runbook states that
  Live mode requires an elevated Windows host with Hyper-V PowerShell tools,
  hardware virtualization enabled in BIOS/UEFI, an existing Windows golden VM,
  a clean checkpoint, Guest Service Interface / PowerShell Direct access, a
  guest password secret, and staged Guest Agent/R0Collector payloads.
- **VT terminology is explicit:** VirusTotal is optional hash-only enrichment
  configured with `.\install.ps1 -Mode ConfigureVTKey -PromptVTKey`; Intel VT-x
  / AMD-V is the BIOS/UEFI virtualization setting required by Hyper-V. These are
  unrelated settings despite sharing the letters "VT".
- **Default behavior is safe:** `.\run.ps1`, `.\run.ps1 -Mode Analyze
  -SamplePreset Notepad`, `Status`, `CheckEnvironment`, `Plan`, `WhatIf`, and
  package creation do not start, restore, stop, or mutate a VM. Live execution
  requires explicit `-Live` or the WebUI/API live action.
- **Real Notepad 5s report path is documented and tested on a lab machine:** see
  the command sequence below. The resulting job/report remains under the runtime
  root, not the repository.

## Real Notepad 5s report runbook

This is the shortest public-MVP live smoke for generating a real report with
the built-in Windows Notepad sample. Run it only on the prepared lab host/VM;
it can restore, start, stop, and modify the configured golden VM.

1. From an elevated PowerShell in the repository or portable package root, check
   read-only readiness:

   ```powershell
   .\install.ps1 -Mode CheckEnvironment
   .\run.ps1 -Mode CheckEnvironment
   ```

2. If readiness reports missing local state, configure it outside git:

   ```powershell
   .\install.ps1 -Mode Install -PromptPassword
   .\install.ps1 -Mode Change -UpdateHyperVConfig `
     -VmName 'KSwordSandbox-Win10-Golden' `
     -CheckpointName 'Clean' `
     -GuestWorkingDirectory 'C:\KSwordSandbox'
   .\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -SelfContained
   ```

3. Optional enrichment only: configure VirusTotal hash-only lookups if desired.
   This never uploads sample bytes.

   ```powershell
   .\install.ps1 -Mode ConfigureVTKey -PromptVTKey
   ```

4. Optional real R0 only: configure a repository-external test-signed driver
   path and enable guest test-signing in the isolated VM. Skip this step for
   the default MVP live smoke or use mock/disabled R0.

   ```powershell
   .\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath 'D:\Temp\KSwordSandbox\build\r0-driver\Release\KSword.Sandbox.Driver.sys'
   .\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force
   ```

5. Generate the real 5-second Notepad report:

   ```powershell
   .\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
   ```

6. Confirm the output job directory printed by `run.ps1` contains:

   ```text
   runbook-execution.json
   guest\<job-id>\events.json
   postprocess-result.json
   report.json
   report.html
   report.zh.html
   report.en.html
   ```

   If the job id is known later, reports can be regenerated without touching the
   VM:

   ```powershell
   .\scripts\Rebuild-JobReport.ps1 -JobId <job-guid>
   ```

## Portable zip script draft

`scripts/package-portable.ps1` reads the selected manifest, stages files under
`D:\Temp\KSwordSandbox\packages\staging` by default, writes generated package
metadata, and creates a zip next to the staging folder. Use `-StageOnly` to
inspect the tree without creating an archive. Use `-Force` to replace a prior
local staging folder/archive under the same output root.

The script validates output placement, path traversal, manifest exclusions, and
high-risk extensions before copying. Runtime package binaries are allowed only
when they come from the external runtime publish root; source packages remain
source-only.

Release-manager diagnostics are printed at the end of each package run:

- package kind/version, staging path, generated metadata path, copied file count
  and payload byte count;
- skipped optional runtime publish entries, for example when `guest-tools` or
  `tools/postprocess` has not yet been published into `RuntimePublishRoot`;
- archive path and SHA-256 when `-StageOnly` is not used;
- explicit safety line: no VM mutation, no driver signing, no `CSignTool`, no
  `git push`, and no network publish.

The generated metadata is intended to be committed only as part of a built
release artifact, never back into the source repository. Keep staged packages
under `D:\Temp\KSwordSandbox\packages` or another ignored external folder.

Runtime portable packages include both root-level `install.ps1`/`run.ps1` and
the `scripts/` wrappers (`scripts/run.ps1`, `scripts/install.ps1`,
`scripts/Manage-SandboxDriver.ps1`) so operators can run one-command WebUI
startup plus read-only Status/CheckEnvironment checks from either layout. The
published WebUI is expected at `app/host-web`; root `run.ps1` automatically uses
that directory when the source project is not present.
