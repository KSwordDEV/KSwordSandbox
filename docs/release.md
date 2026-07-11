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
   package and verify that no forbidden path or extension was copied.
9. Smoke-test the runtime package on a clean host or VM using only the portable
   package contents and local configuration.
10. Record hashes and release notes. Push/publish only when a release manager
    explicitly requests it; the package script does not push.

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

Runtime portable packages include both root-level `install.ps1`/`run.ps1` and
the `scripts/` wrappers (`scripts/run.ps1`, `scripts/install.ps1`,
`scripts/Manage-SandboxDriver.ps1`) so operators can run one-command WebUI
startup plus read-only Status/CheckEnvironment checks from either layout. The
published WebUI is expected at `app/host-web`; root `run.ps1` automatically uses
that directory when the source project is not present.
