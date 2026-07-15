# KSwordSandbox 打包清单 / packaging manifests

中文优先提示：便携打包只做本机 staging/zip，不发布、不推送；manifest 和
`scripts/package-portable.ps1` 的硬性规则会排除本机 secret、`install-state.json`、
DPAPI 备份、`.env`、样本、报告、VM 磁盘/快照、仓库二进制、符号和签名材料。

本目录包含首批面向产品化的 package manifests：

- `source-package.manifest.json` 定义 source-release include roots，并硬性排除
  samples、VM state、generated build output、archives、runtime reports、本机
  secrets 和 signing material。
- `runtime-package.manifest.json` 定义 portable runtime layout：从仓库复制
  operator scripts/docs/config/rules，只从仓库外 `RuntimePublishRoot` 复制已发布
  binaries。runtime manifest 包含 root wrappers 和 `scripts/` wrappers（包括
  driver status management、三 provider Web API E2E 和只读聚合证据校验器），但绝不复制仓库内 `bin/`、`obj/`、`x64/`、VM、
  report、sample 或本机 secret files。
- runtime 便携包面向普通操作者的入口是包根 `install.ps1`：无参数运行会进入推荐安装向导，
  逐项询问 runtime root、已有 VM/checkpoint、guest 用户、guest 密码、可选 driver path、
  可选 VT key 和 WebUI 启动选择；显式参数主要保留给自动化/CI。

使用 `scripts/package-portable.ps1` staging 本地 package tree，并可选择在仓库外
output directory 创建 `.zip`。脚本只做 local-only 操作，故意没有 push/publish 步骤。

English summary: manifests define source/runtime portable package contents while
excluding generated binaries, VM state, reports, samples, secrets, and signing material.

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

源码仓库提供 `scripts\Publish-RuntimePayloads.ps1` 作为 runtime handoff 的本地发布入口。
该脚本面向 release manager/source checkout；便携 runtime 包只消费已发布 payload，
不要求操作者在包内重新构建：

```powershell
.\scripts\Publish-RuntimePayloads.ps1 -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish'
```

该脚本把 `host-web`、`guest-tools`、`tools/job-tool`、`tools/postprocess` 发布到仓库外
`RuntimePublishRoot`，managed host tools 默认是 self-contained 且不带 `.pdb`，并写入
`runtime-publish-manifest.json`。它不运行 smoke、不启动或还原任何 provider VM、不签名、不调用
`CSignTool.exe`，也不从仓库 `bin/obj/x64` 复制 runtime payload。只有明确接受目标机已安装
.NET runtime 依赖时，才用 `-FrameworkDependentManaged` 生成瘦包。

在 review handoff 或 source package dry run 前，从仓库根目录运行组合轻量门禁：

```powershell
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -StageSourcePackage
```

完整 runtime handoff 前再加一个不构建、不签名、不操作任何 provider VM 的 payload gate：

```powershell
.\scripts\Test-ReleaseReadiness.ps1 `
  -AllowDirtySource `
  -RuntimePublishRoot 'D:\Temp\KSwordSandbox\publish' `
  -RequireCompleteRuntimePackage
```

Readiness wrapper 会调用 repository policy、解析操作者 PowerShell scripts、校验 package manifests，并扫描常规 release path 中遗留的 `CSignTool.exe` 引用和 GUI signing fallback 指示。它还会确认 install/run/package scripts 保持所选 provider prerequisite、VM profile、guest transport、guest payload、VT key、runtime root 和 package safety diagnostics 对操作者可见。它不会启动任何 provider VM、签名 driver 或发布 artifacts。
