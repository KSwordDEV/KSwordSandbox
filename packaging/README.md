# KSwordSandbox packaging manifests

中文优先提示：便携打包只做本机 staging/zip，不发布、不推送；manifest 和
`scripts/package-portable.ps1` 的硬性规则会排除本机 secret、`install-state.json`、
DPAPI 备份、`.env`、样本、报告、VM 磁盘/快照、仓库二进制、符号和签名材料。

This directory contains the first productization-facing package manifests:

- `source-package.manifest.json` defines the source-release include roots and
  the hard exclusions for samples, VM state, generated build output, archives,
  runtime reports, local secrets, and signing material.
- `runtime-package.manifest.json` defines a portable runtime layout that copies
  operator scripts/docs/config/rules from the repository and copies published
  binaries only from an external `RuntimePublishRoot`. The runtime manifest
  includes both root wrappers and `scripts/` wrappers, including driver status
  management, but never copies repository `bin/`, `obj/`, `x64/`, VM, report,
  sample, or local secret files.

Use `scripts/package-portable.ps1` to stage a local package tree and optionally
create a `.zip` under an output directory outside the repository. The script is
local-only and intentionally has no push/publish step.

## 便携包成熟度约束 / Portable package contract

- `RuntimePublishRoot` 必须在仓库外，例如 `D:\Temp\KSwordSandbox\publish`。
  runtime 包只从该目录复制已发布的 Web/guest/tool payload；仓库内
  `bin/`、`obj/`、`x64/` 二进制会被拒绝。完整 handoff 需要显式传入
  `-RequireCompleteRuntimePayloads`；不传时只允许作为 layout/safety dry-run 审阅。
- `package-manifest.generated.json` 会写入 staged package 根目录，包含版本、
  git revision/branch、dirty-state preview、payload 文件列表、`sizeBytes`、
  `sha256`、可选 runtime payload 跳过原因、`completeRuntimePayloadsRequired`、
  安全合约、面向审阅者的 `operatorDiagnostics`、generated
  `reviewerChecklist` 和 `sourceRuntimeSafetyMetadata`。
- `operatorDiagnostics` 会列出 `RuntimePublishRoot` 是否提供、是否应在仓库外、
  runtime publish entry（`host-web`、`guest-tools`、`tools/job-tool`、
  `tools/postprocess`）是否存在，以及缺失 payload 的修复建议。
- `reviewerChecklist` 是中文优先 handoff 清单：source gate、runtime gate、
  release-note 必填字段和 reject-if-present 项分开列出，方便 reviewer 直接核对。
- `sourceRuntimeSafetyMetadata` 是机器可读安全元数据：source 包 source-only；
  runtime payload 只来自仓库外 `RuntimePublishRoot`；仓库二进制 fallback=false；
  readiness/package 不修改 VM、不签名、不调用 GUI signing fallback / `CSignTool.exe`。
- readiness/package 脚本不启动、不还原、不停止 VM，不签名 driver，不使用
  GUI signing fallback，不调用 `CSignTool.exe`，也不执行 `git push` 或发布网络动作。
- manifest 和脚本现在显式排除截图、PCAP/PCAPNG、JSONL 事件流、dump、
  SQLite/DB、HAR/trace、VM 状态、样本、报告、secret 和签名材料。

Before a review handoff or source package dry run, use the combined lightweight
gate from the repository root:

```powershell
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -StageSourcePackage
```

完整 runtime handoff 前再加一个不构建、不签名、不操作 Hyper-V 的 payload gate：

```powershell
.\scripts\Test-ReleaseReadiness.ps1 `
  -AllowDirtySource `
  -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' `
  -RequireCompleteRuntimePackage
```

The readiness wrapper calls repository policy, parses operational PowerShell
scripts, validates package manifests, and scans normal release paths for legacy
`CSignTool.exe` references and GUI signing fallback indicators. It also checks
that install/run/package scripts keep Hyper-V prerequisite、VM profile、guest
payload、VT key、runtime root 和 package safety diagnostics visible to
operators. It does not start Hyper-V, sign drivers, or publish artifacts.
