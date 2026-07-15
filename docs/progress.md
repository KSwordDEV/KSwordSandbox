# KSwordSandbox 进度快照 / Progress snapshot

> 中文优先。本文只做当前工程进度和发布差距的轻量快照；权威操作链路见
> `docs/current-architecture-and-operations.md`，真实 live 历史证据见
> `docs/webui-real-r0-e2e.md`，规则清单见 `docs/behavior-rule-matrix.md`，发布差距审计见
> `docs/v1-release-gap-audit.md`。本文不声称本轮重新运行了 Hyper-V live、Notepad 5s 或真实样本测试。

## 当前完成度估计（不含测试覆盖）

这些百分比衡量“当前开源 MVP 可务实做到的范围”，不包含云端多租户、海量样本库、完整家族归因或默认真实 R0 驱动签名。
本轮快照反映本地 v28 发布准备提交 `dd33924`（`Advance v28 telemetry and release hardening`）的源码能力：
v28 已补强 Web durable progress contract、artifact host index/download、network sidecar/PCAP canonical lanes、
Guest artifact event quality、R0 ABI/event quality、报告叙事、自噪声边界和 release gap-audit 元数据。
当前仍**没有**新的 Hyper-V/VMware/QEMU live、真实 Notepad 5s、真实样本报告、fresh live evidence `job id`
或完整 `RuntimePublishRoot` handoff 证据；后续只有在记录新的完整 runtime handoff 或实验室 live `job id`
与报告路径后，才继续上调这些数字。

- 总体 v1 交付链路：**92%**
- WebUI 上传/选择、自动启动、实时监控页（live monitor）：**96%**
- 三 provider runbook / host orchestration：**91%**
- Guest Agent R3 采集：**93%**
- R0Collector 用户态采集链：**91%**
- R0 driver / kernel producer：**78%**
- 静态分析与行为规则：**97%**
- 网络 sidecar / PCAP 元数据：**91%**
- Artifact import / host index / download：**95%**
- 中英 HTML 报告：**96%**
- VirusTotal hash-only enrichment：**92%**
- 发布/打包/仓库策略：**96%**
- 文档与操作者 onboarding：**93%**

## 已具备的交付证据

- WebUI/API 可以选择或上传 `.exe`，为 Hyper-V、VMware 或 QEMU 创建 job 后进入独立实时监控页（live monitor）；显式 live 才会操作所选 provider VM。
- Live monitor 优先消费 `/api/jobs/{jobId}/progress/stream` 真实 runbook step SSE；SSE 不可用时回退 durable `runbook-progress.json` 和 `/runbook/progress` polling。
- 主视图默认不展开 runbook command、stdout、stderr；需要深度排障时再打开 execution-flow 或复制 `runbook-execution.json`。
- Web live artifact 面板展示 artifact index 总览、safe selector、download href、duplicate grouping 和 rejection diagnostics；下载解析必须命中 job artifact index。
- Web live monitor 已显示 progress snapshot freshness/updated-at，帮助审阅者区分实时进度、durable snapshot 和可能停滞的非终态快照。
- VirusTotal 是可选 hash-only reputation enrichment；设置页只影响当前 Web 进程，缺 key、未收录、限速、认证失败、timeout 等 quiet state 不写默认 job log，也不进入主要恶意行为列表。
- Host 静态分析输出 `static.analysis.completed` 兼容摘要，并投影 `static.pe.*`、`static.string.*`、`static.packer.hint`、`static.yara.match`、`static.pe.resource` 等结构化事件供规则和报告消费；行为规则当前 588 条（`2026-07-12-v28-behavior-rule-expansion`），重复 ID 组为 0。
- `static.pe.resource` 覆盖 PE resource type/name/language、size、RVA、entropy、embedded-PE/payload-candidate 等字段，规则侧可用于静态 resource payload triage。
- Guest Agent 具备进程树、文件差异、网络快照，以及显式 opt-in 的 dropped files、screenshots、memory dumps、packet captures lanes；artifact metadata 带 sha256、size、相对路径和中文提示。
- Host 可导入 `events.json`、`driver-events.jsonl`、artifact manifest、PCAP/PCAPNG 和 sidecar rows，生成 normalized events、findings、artifact index 与中英 HTML 报告；network rows 带 source/destination address-scope 和 HTTP literal-IP host metadata。
- PCAP/sidecar 归一化覆盖 DNS、HTTP、TLS、flow、IPv6 TCP/UDP、NXDOMAIN、HTTP upload/status、TLS SNI/JA3/ALPN/证书字段，并尽量保留 process/root lineage。
- R0Collector 支持 mock/driver 模式、ABI/contract self-check、sequence/lost/backpressure/highWatermark 质量字段，并接入只读 `IOCTL_KSWORD_SANDBOX_GET_NETWORK_STATUS`。
- `r0collector.driverNetworkStatus` 在成功时记录 WFP/ALE layer masks、producer counters、degrade reason 和 readiness state；IOCTL 不可用时输出 degraded 诊断行且继续采集。
- HTML 报告已按 Risk、Process、Files、Network、R0、VT、Artifacts、Raw events 分区；raw events 默认折叠、分页、限高，命令墙字段默认隐藏在可复制 details 中。
- 报告证据叙事包含 process relationship、network relationship、evidence story board、IOC/behavior graph、R0 health/noise 和 VT reputation 分区，避免把采集健康或外部信誉误算成样本行为。
- 仓库策略阻止样本、VM、报告、PCAP、dump、驱动二进制、symbols、证书、secret、`bin/`、`obj/`、`x64/` 等产物进入 git。

## v28 本地低成本验证记录

以下命令在提交 `dd33924` 前后用于 release-prep 审阅；它们不启动 VM、不签名、不联网、不运行重 smoke，也不调用 `CSignTool.exe`：

```powershell
dotnet build .\src\KSword.Sandbox.Core\KSword.Sandbox.Core.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\v28-core-final\
dotnet build .\src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\v28-web-final\
dotnet build .\guest\KSword.Sandbox.Agent\KSword.Sandbox.Agent.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\v28-agent-final\
dotnet build .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\v28-jobtool-final2\
dotnet build .\tools\KSword.Sandbox.PostProcess\KSword.Sandbox.PostProcess.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\v28-postprocess-final\
dotnet build .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\v28-testcompile-final\
```

```powershell
MSBuild .\guest\KSword.Sandbox.R0Collector\KSword.Sandbox.R0Collector.vcxproj /p:Configuration=Debug /p:Platform=x64 /m /v:minimal
MSBuild .\driver\KSword.Sandbox.Driver\KSword.Sandbox.Driver.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SignMode=Off /m /v:minimal
python -m json.tool .\rules\behavior-rules.json
python -m json.tool .\packaging\runtime-package.manifest.json
python -m json.tool .\packaging\source-package.manifest.json
git diff --check
.\scripts\Test-RepositoryPolicy.ps1
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -OutputRoot D:\Temp\KSwordSandbox\release-readiness-v28
```

`scripts/Test-ReleaseReadiness.ps1` 生成的 `release-readiness.json`/`.md` 是非破坏性审阅物料；它不是 fresh live evidence，也不证明 runtime payload 完整交付。

## 仍需发布经理确认的 P0/P1 差距

P0 当前不是“必须先写代码”，而是候选提交发布前必须重新确认的门禁：

1. 仓库和 source package 不含 runtime artifacts、样本、VM、dump、pcap、驱动二进制（driver binary）、证书或 secret。
2. 默认 install/run/readiness/package 路径不调用 `CSignTool.exe`，不加载真实 driver，不修改 VM。
3. 若 release notes 要声明“本候选已生成真实 Notepad 5s 报告”，必须在实验室主机重新运行 live 命令并记录 job id；历史证据、package/readiness 通过结果和本轮发布准备批次都不能替代新的 release evidence。
4. 完整 runtime handoff 仍未在本轮复验；正式交付前必须使用仓库外 `RuntimePublishRoot` 和 `-RequireCompleteRuntimePackage`/`-RequireCompleteRuntimePayloads` 证明 `host-web`、`guest-tools`、`tools/job-tool`、`tools/postprocess` payload 齐备。

P1 仍值得继续补强：

- 用真实样本人工走查实时监控页（live monitor），确认当前 step、失败态、artifact 卡片、VT quiet card 和报告入口无需打开命令墙也能理解。
- 用 benign GUI、harmless sample、下载执行、文件释放、网络样本生成报告，校准首屏摘要、关系卡、截图/PCAP/落地文件证据和原始证据（raw evidence）边界。
- 对 R0 driver path 做真实驱动输入、压力样本、unload/reload 和 guest 内 ABI self-check 复验；默认发布仍只承诺遥测契约（telemetry contract），不承诺任意主机都能加载未签名驱动。
- 用更多样本集（corpus）校准 behavior rules、MITRE 映射、static-only triage、YARA-like 噪音和 VT reputation 呈现。
- 补 synthetic 覆盖：非 ASCII artifact path、深目录、重复内容、路径穿越拒绝、真实 sidecar/PCAP 字段质量。

## 低成本下一步

默认低成本验证不启动 VM、不签名、不联网、不调用 `CSignTool.exe`：

```powershell
.\scripts\Test-RepositoryPolicy.ps1
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource
```

若只改文档，优先运行：

```powershell
git diff --check -- docs
```

Hyper-V live、真实 R0、VT 联网和重 smoke 只在 release manager（发布负责人）明确安排时运行。
