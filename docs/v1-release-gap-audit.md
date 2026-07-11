# KSwordSandbox v1 发布差距审计（截至 0068358）

更新时间：2026-07-12。本文是发布经理/审阅者 handoff，基于 `0068358 Advance v20 evidence and release readiness`
之后的源码与文档状态整理；本次文档刷新没有重跑 Hyper-V live、重 smoke 或签名链。

本页只回答发布前最重要的三件事：当前能交付什么、还差什么、审阅者用哪些低副作用命令验收。
百分比不包含测试覆盖占比；100% 指当前 open-source MVP 可务实做到的范围，不包含云端多租户、海量样本库、
完整恶意家族归因或默认真实 R0 驱动签名。
本次不调整百分比：这次只加强 release/deployment guardrail、runtime dry-run 诊断和
no-fresh-live 说明；没有新的 build 矩阵、真实样本报告、fresh live evidence `job id`
或签名链结果可支撑上调。

## 总体判断

当前 KSwordSandbox 已具备公开 MVP 的主链路形态：

- WebUI/API 可选择或上传 `.exe`，创建 job 并进入 live monitor；显式 live 才会操作 Hyper-V VM。
- Host 侧会做 hash/静态分析，`SandboxJobService` 已接入完整 `static.*` 事件而不是单条 summary。
- Guest Agent 可采集进程树、文件差异、网络快照，以及显式启用的 dropped files、截图、memory dump、PCAP artifact。
- Host 可导入 guest events、driver JSONL、PCAP/sidecar/artifacts，生成 `report.json`、`report.html`、`report.zh.html`、`report.en.html`。
- Web live progress 优先使用 `/api/jobs/{jobId}/progress/stream` 和 durable `runbook-progress.json`，命令/stdout/stderr 默认不在主视图展开。
- Artifact index/download 已有安全 selector、duplicate 信息和拒绝诊断；下载必须命中 job artifact index。
- VirusTotal 是可选 hash-only enrichment；缺 key、限速、未收录等 quiet/status 状态不应污染主行为判定。
- 报告已按 Process / Files / Network / R0 / VT / Artifacts 分区，raw events 默认折叠/分页/限高，并区分 R0 health/noise 与样本行为。
- R0Collector/R0 driver 有 ABI、lost/backpressure/highWatermark/sequence、readiness/diagnose 等 telemetry contract；真实驱动加载仍是隔离 lab 高级路径。
- 打包与仓库策略默认拒绝样本、VM、报告、dump、pcap、驱动二进制、签名材料和 secret；默认路径不应调用 `CSignTool.exe`。

不应对 v1 承诺“任意样本完整恶意判定”或“默认真实 R0 driver 可加载”。真实 R0 仍取决于隔离 guest 的 test-signing、
驱动测试签名、checkpoint 状态和本地实验室配置。

## 组件完成度估计（不含测试覆盖）

| 组件 | 估计 | 发布前还需补强 |
| --- | ---: | --- |
| WebUI 上传/选择、自动启动、live monitor | 95% | 做一次真实样本 UI 走查，确认失败态、artifact 卡片和报告按钮在 live 结束后可读。 |
| Hyper-V runbook / host orchestration | 90% | 继续收敛 checkpoint 偏差恢复、前置条件提示和失败诊断文案。 |
| Guest Agent R3 采集 | 91% | artifact manifest、截图/PCAP/dump 等 opt-in 证据 lane 更完整；仍需用更多样本校准 dropped file、child process、PCAP 和 opt-in artifact 质量。 |
| R0Collector 用户态采集链 | 88% | 已接入可选 `GET_NETWORK_STATUS` 诊断、sequence/backpressure/readiness/noise contract；仍需真实驱动输入和压力样本复验。 |
| R0 driver / kernel producer | 76% | driver 侧 telemetry/diagnostic 面更完整，Collector 已消费 `GET_NETWORK_STATUS`；默认发布仍不承诺未签名驱动加载，报告/UI 还可继续加强该状态叙事。 |
| 静态分析与行为规则 | 94% | `static.*` 结构化事件、resource projection 和规则消费已落地，规则库已扩展；后续按 corpus 校准误报/漏报、MITRE 映射和 YARA-like 规则噪音。 |
| 网络 sidecar / PCAP 元数据 | 86% | DNS/HTTP/TLS/flow/IPv6/sidecar 归一化已可用；深度协议字段和异常证书/JA3 质量还需样本校准。 |
| artifact import / host index / download | 92% | 安全下载、duplicate/rejection 诊断和 artifact evidence readiness 已增强；继续补非 ASCII、深目录、重复内容和路径穿越 synthetic 覆盖。 |
| 中英 HTML 报告 | 94% | 证据叙事和 artifact 证据呈现已可审阅；继续用真实样本报告校准首屏摘要、关系卡和 raw evidence 边界。 |
| VirusTotal hash-only enrichment | 90% | 官方 file object 字段、permalink/cache/quiet 状态已接入；继续补 rate-limit/错误分类的 UI 文案。 |
| 发布/打包/仓库策略 | 94% | readiness/package gate 已有；runtime zip 交付必须显式完整 payload，正式 tag 前仍需 release manager 跑 staged policy 和 source package dry run。 |
| 文档与操作者 onboarding | 89% | 中文优先索引和 release handoff 已收敛；随最终 release notes 再做一次去重。 |

## P0 发布门禁

当前没有必须先写代码才能发布的 P0 阻断；P0 是发布经理必须在候选提交上重新确认的门禁。

### 1. 仓库与包内不得含敏感/运行产物

已具备能力：

- `scripts/Test-RepositoryPolicy.ps1` 拒绝常见二进制、VM、report、sample、pcap、dump、secret 和大文件。
- `scripts/Test-ReleaseReadiness.ps1` 组合仓库策略、PowerShell 语法、package manifest、release path `CSignTool.exe` 检查。
- `package-manifest.generated.json` 暴露 `operatorDiagnostics`、`safetyContract`、`runtimePublishRoot`、`gitStatus` 和 required checks；
  runtime handoff 审阅还应看 `runtimePublishSummary.incompleteCount`、expected leaf gaps
  和 forbidden-file previews，确认仓库外 `RuntimePublishRoot` 不是 layout-only dry-run。

发布前验收：

```powershell
.\scripts\Test-RepositoryPolicy.ps1
.\scripts\Test-RepositoryPolicy.ps1 -StagedOnly
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -StageSourcePackage
```

通过证据：命令退出码为 0，且 `D:\Temp\KSwordSandbox\release-readiness\release-readiness.json` 中 `failedCount=0`。

### 2. 默认路径不得调用 CSignTool 或 GUI 签名链

已具备能力：

- release/readiness 路径会扫描 `CSignTool.exe` 和 legacy interactive signing wrapper。
- release/readiness 也会扫描 `AuthenticodeVariantGUI.exe`、`Out-GridView` 和常见
  Windows Forms/OpenFileDialog/SaveFileDialog 指标，防止 GUI signing fallback 混入默认路径。
- `install.ps1` / `run.ps1` / package/readiness 默认不签名、不加载真实 R0 driver。
- 真实 R0 文档应坚持 ordinary `signtool.exe` 或 guest test-signing 的人工 lab 路径，不自动回退 GUI 签名链。

通过证据：`Test-ReleaseReadiness.ps1` 的 `no-csigntool-release-path` 和
`no-gui-signing-fallback` 均为 `Passed`。

### 3. 最新 live 证据 / Fresh live evidence 由 release manager 在 lab 主机确认

已具备能力：

- 文档与脚本已有最短 Notepad 5s live runbook：

  ```powershell
  .\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
  ```

- `docs/webui-real-r0-e2e.md` 记录了本地 WebUI/API + real R0 live 验证历史证据（harmless sample，非本轮重跑）。

发布前验收建议：

- 若 release notes 要声称“本候选版本已生成真实 Notepad 5s 报告”，必须在准备好的实验室主机重新运行上面的 live 命令并记录 job id。
- 若真实 R0 未就绪，使用 disabled/mock R0 或记录 `-NoR0Collector`/等效配置，不把 R0 driver load 作为默认发布门槛。
- 若未重新运行 live，release notes 必须写“本候选未刷新 fresh live evidence”；
  `Test-ReleaseReadiness.ps1` / `package-portable.ps1` 的通过结果不能替代 live `job id`。

通过证据：runtime root 下的最新 job 包含 `runbook-execution.json`、`guest\<job-id>\events.json`、`report.json`、
`report.zh.html` 和 `report.en.html`，且 VM 已回到预期 checkpoint/state。

## P1 发布质量差距

### WebUI 实时监控页 / WebUI live monitor

已实现：SSE 真实进度流、durable progress fallback、上传后跳转 live page、stdout/stderr 默认折叠、artifact 卡片/下载入口、VT quiet 状态。

仍需：真实样本人工走查，确认当前 step、失败原因、报告入口和 artifact 入口不用打开命令墙也能理解。

### 报告证据叙事

已实现：方角蓝色主题、raw events 折叠/分页/限高、process tree、network 关系卡、evidence expansion、R0 health/noise、VT reputation 分区。

仍需：对 benign GUI、harmless sample、下载执行、文件释放、网络样本各生成报告，校准首屏是否能回答“做了什么、证据是什么、哪些是采集健康/外部信誉”。

### 行为规则与静态分析

已验证的轻量事实：`rules/behavior-rules.json` 当前 521 条规则、重复 ID 组为 0。

已实现：`static.analysis.completed` 保持兼容 summary；`static.pe.*`、`static.string.*`、`static.packer.hint`、`static.yara.match` 结构化事件进入规则消费；
`rules/static-notes.yar` 由内置轻量 YARA-like matcher 处理，不依赖外部 YARA。

仍需：按 corpus 校准 ATT&CK、误报/漏报和 YARA-like 噪音；任何 static-only 命中都保持 triage，不当作已观察到的 guest 行为。

### 网络与 artifact

已实现：PCAP/native import 与 sidecar 对 DNS/HTTP/TLS/flow、IPv6 TCP/UDP、NXDOMAIN、HTTP upload/status、TLS SNI/JA3/ALPN/证书字段做归一化；artifact index/download 提供 safe selectors、duplicate 信息和 rejection diagnostics。

仍需：补充 synthetic import/download 覆盖非 ASCII、深目录、重复内容、路径穿越拒绝，以及真实 sidecar/PCAP 样本字段质量。

### R0 遥测 / R0 telemetry

已实现：R0Collector/报告保留 lost/backpressure/highWatermark/lastEnqueueFailureStatusHex/sequence/sequenceMeaning、readiness/diagnose 中文提示和 self-noise 边界；driver 侧已有更完整 producer runtime state 与 network status ABI。

仍需：默认发布只承诺 telemetry contract，不承诺 driver load；driver network status 还需要更多 collector/report 闭环和真实压力复验。

## 低成本发布验证矩阵

默认低成本（不启动 VM、不签名）：

```powershell
.\scripts\Test-RepositoryPolicy.ps1
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource
dotnet build .\src\KSword.Sandbox.Core\KSword.Sandbox.Core.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\core-release\
dotnet build .\src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\web-release\
dotnet build .\guest\KSword.Sandbox.Agent\KSword.Sandbox.Agent.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\agent-release\
```

发布候选前增加：

```powershell
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -StageSourcePackage
dotnet build .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\jobtool-release\
```

实验室 live 只在 release manager 明确需要 fresh evidence 时运行：

```powershell
.\run.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
```

## 发布说明 / Release notes 必须写清楚

- 本项目是本地授权分析沙箱，不是云上传服务。
- VirusTotal 是 hash-only；Intel VT-x/AMD-V 是 Hyper-V 硬件虚拟化，两者不是同一个配置。
- VM profile、guest payload、guest test-signing、RuntimePublishRoot 完整性是不同故障域；
  先用 `install/run CheckEnvironment` 看本机 profile/payload/VT key，再用
  `Test-ReleaseReadiness -RuntimePublishRoot ... -RequireCompleteRuntimePackage`
  验证 runtime package handoff。
- 默认命令不会启动或修改 VM；Live 必须显式开启。
- 默认不签名、不加载真实 R0 driver；真实 R0 是隔离实验室高级路径。
- 不要提交或分享 runtime root、样本、报告、dump、pcap、VM、secret 或签名材料。
