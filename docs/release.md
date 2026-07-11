# KSwordSandbox 发布打包检查清单 / Release packaging checklist

中文优先：本页描述本机打包闭环。`scripts/package-portable.ps1` 只在本机
staging/zip，不提交、不 push、不发布；清单和脚本会拒绝本机 secret、VM
磁盘/快照、样本、报告、仓库构建二进制、符号和签名材料。

This is the draft release wrapper for productized source and portable runtime
packages. It is intentionally conservative: packages are staged outside the
repository, release artifacts are not pushed by the packaging script, and
sensitive/runtime material is excluded by manifest policy.

## 当前发布 handoff（本地 v22+ 发布准备批次，基线 77298d6 / v22）

面向审阅者的当前结论：源码层 MVP 主链路已经成形，但正式 tag 前仍应由
release manager 在候选提交上重新跑低副作用门禁。本轮发布准备批次没有重跑
Hyper-V live、重 smoke 或驱动签名。
v21/v22 已收敛 telemetry/product-readiness polish、defensive behavior matrix、artifact/download metadata、network address-scope metadata、live progress freshness 和 runtime guardrail。
本轮发布准备批次没有新的 live `job id`、报告 hash、实验室记录或完整 `RuntimePublishRoot` handoff 证据，
因此不能替 release notes 声明 `fresh live evidence` 或“runtime 包已完整交付”。若未补跑实验室 live，release notes 必须写：
“本候选未刷新 fresh live evidence”。

已落地并可在代码/文档中审阅的 release-ready 能力：

- WebUI 上传/选择 `.exe` 后进入 live monitor；真实进度优先走
  `/api/jobs/{jobId}/progress/stream`，fallback 到 durable
  `runbook-progress.json`，主视图不展示命令/stdout/stderr。
- Host 静态分析已输出 granular `static.*` 事件，行为规则消费
  `static.pe.*`、`static.string.*`、`static.packer.hint` 和
  `static.yara.match`；规则库当前 550 条且静态命中仍是 triage，不等同 guest 行为。
- Artifact index/download 走 job 内安全 selector，Web DTO 暴露
  duplicate/rejection/download 诊断；包策略继续拒绝 runtime 产物入库。
- VirusTotal 是 process-memory only 配置入口和 hash-only 查询；quiet
  status 不写成主行为噪音。
- 报告输出中英 HTML，区分本地行为、R0 health/noise、VT reputation 和
  artifacts，raw events 默认折叠/分页/限高。
- R0 driver/collector 只作为可选 lab 路径发布；默认 package/readiness
  不签名、不加载驱动、不使用 GUI signing fallback、不调用 `CSignTool.exe`。

审阅者优先看：

1. [`v1-release-gap-audit.md`](v1-release-gap-audit.md) 的组件百分比、更新规则和剩余差距。
2. 本页的 package/checklist；确认 staging 输出在仓库外。
3. `docs/README.md` 的 canonical 文档地图，避免引用历史 planning 文件作为当前事实。

## 包类型 / Package types

- Source package: repository source, rules, docs, tests, packaging metadata, and
  scripts needed to rebuild from source. It excludes VM state, submitted
  samples, local runtime roots, reports, captures, generated binaries, archives,
  signing material, local secrets, and private certificate files.
- Runtime portable package: operator-facing docs/config/rules/scripts plus
  pre-published runtime payloads copied from an external `RuntimePublishRoot`.
  It must not copy from repository `bin/`, `obj/`, or `x64/` folders. Published
  host/guest/tool payloads are expected under external folders such as
  `host-web`, `guest-tools`, `tools/job-tool`, and `tools/postprocess`.

## 清单 / Manifests

- `packaging/source-package.manifest.json`
- `packaging/runtime-package.manifest.json`

清单是 package contract。修改便携脚本复制内容前，先更新对应 manifest；排除项要足够宽，
至少阻止以下内容：

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

两个 manifest 都带有 `releaseContract` 和 `stagedMetadata`。它们是面向操作者的
guardrail，不是构建输入：用于声明 packaging/readiness 不得修改 Hyper-V、不得签名
driver、不得使用 GUI signing fallback、不得调用 `CSignTool.exe`、不得 push 或 publish，
并定义审阅者应在 staged package 内看到的 generated metadata 字段。

## 发布前检查清单 / Pre-release checklist

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
     -RequireCompleteRuntimePayloads `
     -OutputRoot 'D:\Temp\KSwordSandbox\packages'
   ```

   如果只是审阅 layout/safety，可以省略 `-RequireCompleteRuntimePayloads` 并使用
   `-StageOnly`；正式 runtime handoff 必须让 `host-web`、`guest-tools`、
   `tools/job-tool`、`tools/postprocess` 都来自仓库外 `RuntimePublishRoot`。

8. Inspect the generated `package-manifest.generated.json` inside the staged
   package and verify that no forbidden path or extension was copied. Reviewers
   should check `fileInventory[].sha256`, `fileInventory[].sizeBytes`,
   `packageDiagnostics`, `safetyContract`, `runtimePublishRoot`, `gitStatus`,
   and `manifestRequiredChecks`.
   `Test-ReleaseReadiness.ps1` 默认会执行一次仓库外 `source` package
   `-StageOnly -Force` dry-run，用来提前发现安全排除项、manifest 和 generated
   metadata 回归；它不会创建 zip、不会启动 Hyper-V、不会签名、不会发布。只有在极端低成本
   环境中才使用 `-SkipSourcePackageDryRun` 跳过。

   需要 runtime handoff gate 时运行：

   ```powershell
   .\scripts\Test-ReleaseReadiness.ps1 `
     -AllowDirtySource `
     -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' `
     -RequireCompleteRuntimePackage
   ```

9. Smoke-test the runtime package on a clean host or VM using only the portable
   package contents and local configuration.
10. Record hashes and release notes. Push/publish only when a release manager
    explicitly requests it; the package script does not push.

## 开源 MVP readiness 检查清单 / Open-source MVP readiness checklist

发布第一个公开 MVP 包前，release manager 用本节做精简 gate：

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
- **No legacy signing tool / no GUI signing fallback:** build, smoke, package,
  and onboarding commands do not call `CSignTool.exe`, old KSword interactive
  signing wrappers, or GUI signing fallback paths. Missing `signtool.exe` must
  fail/skip clearly, not open a dialog.
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
- **Operator diagnostics are explicit:** `install.ps1` and `run.ps1` expose
  read-only `HyperVPrerequisites`, `VmProfile`, `GuestPayloadStatus` /
  `GuestPayloadFreshnessReasons`, `VirusTotalMissingKeyBehavior`, and
  `RuntimeRootUnderRepository`. Reviewers should inspect `RecommendedActions`
  before live execution instead of discovering missing prerequisites during a
  sample run.
- **Real Notepad 5s report path is documented; fresh evidence is a lab action:**
  see the command sequence below. Historical live evidence is recorded in
  `docs/webui-real-r0-e2e.md`, but a release note must not claim a fresh Notepad
  run unless the release manager reruns it on the prepared lab host. The
  resulting job/report remains under the runtime root, not the repository.
- **No-fresh-live guardrail:** package/readiness 输出只能证明本地低副作用门禁；
  它不会启动 Hyper-V live，也不会替 release notes 自动生成 fresh live evidence。
  如果当前候选没有新的 `job id`、运行时间、runtime root 和报告路径，就必须写
  “本候选未刷新 fresh live evidence”。

## 真实 Notepad 5s 报告 runbook / Real Notepad 5s report runbook

这是用内置 Windows Notepad 样本生成真实报告的最短 public-MVP live smoke。
只在准备好的 lab host/VM 上运行；它可能还原、启动、停止并修改已配置的 golden VM。

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

4. 仅当需要真实 R0 时：配置仓库外 test-signed driver path，并在隔离 VM 中启用
   guest test-signing。默认 MVP live smoke 跳过这一步，或使用 mock/disabled R0。

   ```powershell
   .\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath 'D:\Temp\KSwordSandbox\build\r0-driver\Release\KSword.Sandbox.Driver.sys'
   .\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force
   ```

   启用真实 R0 后、live 前先跑只读 R0 readiness/status；不要在这一步签名或安装 driver：

   ```powershell
   .\scripts\Test-R0Readiness.ps1
   .\scripts\Manage-SandboxDriver.ps1 -Action Status
   ```

5. 生成真实 5 秒 Notepad 报告。只有 release manager 明确要求 fresh live evidence
   时才运行；这不是 package/readiness 的默认步骤：

   ```powershell
   .\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
   ```

6. 记录 release note 证据字段：commit、`job id`、运行时间（UTC 或本地时区）、
   runtime root、VM/checkpoint、是否启用真实 R0，以及报告路径。确认 `run.ps1`
   打印的输出 job 目录包含：

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

## 便携 zip 脚本草案 / Portable zip script draft

`scripts/package-portable.ps1` 读取选定 manifest，默认把文件暂存到
`D:\Temp\KSwordSandbox\packages\staging`，写出 generated package metadata，
并在 staging 旁边创建 zip。使用 `-StageOnly` 只审阅目录树、不创建 archive；
使用 `-Force` 替换同一 output root 下已有的本地 staging folder/archive。

脚本在复制前校验 output 位置、path traversal、manifest exclusions 和高风险扩展名。
runtime package binary 只允许来自仓库外 `RuntimePublishRoot`；source package 始终
保持 source-only。为避免把 layout dry-run 误交付成可运行包，非 `-StageOnly` 的
runtime zip 必须显式传入 `-RequireCompleteRuntimePayloads` 且 `RuntimePublishRoot`
中所有 runtime publish entries 都存在。generated metadata 中的
`operatorDiagnostics.runtimeArchiveRequiresCompleteRuntimePayloads` 会记录这一策略。

Release-manager diagnostics are printed at the end of each package run:

- package kind/version, staging path, generated metadata path, copied file count
  and payload byte count;
- `RuntimePublishRoot` state and each expected runtime publish entry
  (`host-web`, `guest-tools`, `tools/job-tool`, `tools/postprocess`) as
  present/missing; missing optional entries remain useful for layout dry-runs
  but must be resolved before a complete portable runtime handoff;
- skipped optional runtime publish entries, for example when `guest-tools` or
  `tools/postprocess` has not yet been published into `RuntimePublishRoot`;
- archive path and SHA-256 when `-StageOnly` is not used;
- explicit safety line: no VM mutation, no driver signing, no GUI signing
  fallback, no `CSignTool`, no `git push`, and no network publish.

`package-manifest.generated.json` now includes `operatorDiagnostics` with
runtime publish readiness, missing payload names, non-mutating guarantees, and
package safety guidance. Newer staging output should expose:

- `runtimePublishSummary`: present/missing counts, missing required vs optional
  runtime payloads, `incompleteCount`, expected leaf-file gaps, forbidden-file
  previews, and whether this is a layout dry-run or complete runtime handoff.
- `safeExclusionCategories`: operator-readable categories that must stay out of
  source/runtime packages: secrets, install state, samples, reports/events,
  captures/PCAP/dumps/traces, VM disks/checkpoints, build outputs, symbols,
  driver binaries, certificates, signing material, GUI signing fallback, and
  `CSignTool`.
- `runtimeDryRunGuardrail`: Chinese-first statement of whether this staging is
  only a layout/safety dry-run, whether runtime handoff is allowed, and which
  conditions must be true before a runtime zip is deliverable.
- `runtimePublishRootMissingRecommendedActions`: concise next commands when
  `RuntimePublishRoot` is absent, under the repository, or missing expected
  folders.
- `completeRuntimePayloadsRequired` / `runtimePublishSummary`: whether this is
  an explicit complete-runtime handoff or only a layout dry-run.
- `externalStateDiagnostics`: reminders that Hyper-V prerequisites, local VM
  profile, guest payload freshness, optional VT key state, and runtime job
  outputs are checked by read-only install/run status commands rather than by
  the package script. VT key means VirusTotal API key; Intel VT-x / AMD-V is
  the separate hardware virtualization prerequisite for Hyper-V.
- `freshLiveEvidenceGuardrail`: explicit `false` for package/readiness fresh-live
  creation, plus the lab `-Live` command and required release-note fields before
  claiming current fresh live evidence.

It is a reviewer-facing handoff artifact, not a file to commit back into the
source tree.

The generated metadata is intended to be committed only as part of a built
release artifact, never back into the source repository. Keep staged packages
under `D:\Temp\KSwordSandbox\packages` or another ignored external folder.

### RuntimePublishRoot 排障 / RuntimePublishRoot troubleshooting

`RuntimePublishRoot` 不是仓库目录，也不是 `bin/`、`obj/`、`x64/` 的兜底复制源。
完整 runtime handoff 前，readiness/package diagnostics 应同时满足：

- `host-web` contains `KSword.Sandbox.Web.exe` or `KSword.Sandbox.Web.dll`;
- `guest-tools` contains `payload-manifest.json`, Guest Agent exe/dll, and
  `r0collector/KSword.Sandbox.R0Collector.exe`;
- `tools/job-tool` contains JobTool exe/dll;
- `tools/postprocess` contains PostProcess exe/dll;
- none of the runtime publish folders contains `.pdb`, `.sys`, PCAP/dump/trace,
  VM disk/checkpoint/state, secret, certificate/private-key, `.jsonl`, SQLite,
  zip/archive, `CSignTool.exe`, `signtool.exe`, or GUI signing fallback files.

如果 `runtimePublishSummary.incompleteCount > 0`，不要把 zip 交付给操作者；
重新发布对应 payload 到仓库外目录，再运行：

```powershell
.\scripts\Test-ReleaseReadiness.ps1 `
  -AllowDirtySource `
  -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' `
  -RequireCompleteRuntimePackage
```

如果缺口是 VM profile、guest payload freshness、guest test-signing、硬件虚拟化
或可选 VirusTotal key，不要修改 package；先运行只读：

```powershell
.\scripts\install.ps1 -Mode CheckEnvironment
.\scripts\run.ps1 -Mode CheckEnvironment
```

Runtime portable packages include both root-level `install.ps1`/`run.ps1` and
the `scripts/` wrappers (`scripts/run.ps1`, `scripts/install.ps1`,
`scripts/Manage-SandboxDriver.ps1`) so operators can run one-command WebUI
startup plus read-only Status/CheckEnvironment checks from either layout. The
published WebUI is expected at `app/host-web`; root `run.ps1` automatically uses
that directory when the source project is not present.
