# KSwordSandbox v1 发布差距审计与弥补方向

本页是发布前收敛用的 current-state audit。它不替代各模块详细文档，
而是回答三个问题：

1. 现在距离可公开 MVP 还差什么。
2. 每个差距用什么证据证明已弥补。
3. 发布前哪些命令可以低成本验证，不触发 VM 或驱动签名副作用。

## 总体判断

KSwordSandbox 已经具备 open-source MVP 的主链路形态：

- 上传/选择 EXE 后可以进入 WebUI live monitor。
- CLI/Web/API 能规划 Hyper-V runbook；显式 live 模式能把样本送入 VM。
- Guest Agent 可采集进程、文件差异、网络快照、截图/PCAP/memory dump 的 opt-in
  事件与 artifact manifest。
- Host 可以导入 guest events、driver JSONL、PCAP/sidecar/artifacts 并生成中英 HTML 报告。
- VirusTotal 是 hash-only 可选富化，不上传样本。
- 发布脚本与仓库策略默认拒绝样本、VM、报告、dump、pcap、驱动二进制、签名材料和 secret。

v1 不应承诺“任意样本完整恶意判定”或“默认真实 R0 驱动可加载”。真实 R0
仍取决于隔离 guest 内 test-signing、驱动测试签名、checkpoint 状态和本地实验室配置。

## 组件完成度估计（不含测试覆盖）

以下百分比是以“当前 open-source MVP 可以做到的务实目标”为 100%，不把长期产品化、
云端多租户、大规模样本库、完整恶意家族归因或默认真实 R0 驱动签名纳入分母。

| 组件 | 估计 | 还需补强的发布方向 |
| --- | ---: | --- |
| WebUI 上传/选择、自动启动、live monitor | 92% | 真实样本 UI 走查、失败态和 artifact 下载提示继续抛光。 |
| Hyper-V runbook / host orchestration | 88% | 失败诊断文案、checkpoint 偏差恢复和 lab 前置条件提示继续收敛。 |
| Guest Agent R3 采集 | 86% | 更多样本类型下的 dropped file、child process dump、PCAP 质量校准。 |
| R0Collector 用户态采集链 | 78% | sequence/backpressure 已具备；仍需更多压力样本和真实驱动输入复验。 |
| R0 driver / kernel producer | 68% | 当前可作为高级 lab 路径；默认发布不承诺未签名驱动可加载。 |
| 静态分析与行为规则 | 84% | 新增规则已扩容；后续按 corpus 校准误报/漏报与 MITRE 映射。 |
| 网络 sidecar / PCAP 元数据 | 75% | 已减少 placeholder 感；深度 DNS/HTTP/TLS 协议解析仍是后续增强。 |
| artifact import / host index / download | 83% | 非 ASCII/深目录/重复内容/路径穿越拒绝需要更多 synthetic 覆盖。 |
| 中英 HTML 报告 | 88% | 首屏叙事已可用；继续用真实样本报告校准“证据讲故事”。 |
| VirusTotal hash-only enrichment | 82% | quiet state 已明确；后续补更多 rate-limit/错误分类展示。 |
| 发布/打包/仓库策略 | 90% | readiness gate 已有；正式 tag 前再跑 staged policy 和 source package dry run。 |
| 文档与操作者 onboarding | 84% | 中文优先索引已整理；仍需随真实 release notes 做最后一次去重。 |

## P0 发布阻断差距

### 1. 最小真实 live 样本路径需要稳定复验

当前证据：

- `.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live` 已能执行
  真实 Notepad guest run 并生成 `report.zh.html` / `report.en.html`。
- 当真实 R0 driver 未签名时，`sc.exe start` 可能返回 577；默认发布 smoke 应使用
  disabled/mock R0 或明确记录该限制。

弥补方向：

- 发布前在准备好的实验室主机跑一次 Notepad 5s live smoke。
- 如果真实 R0 未就绪，记录 `-NoR0Collector` 或 mock/disabled R0 的 smoke 结果，
  不把 R0 driver load 作为默认发布门槛。

完成证据：

- runtime root 下存在一个最新 job，含：
  - `runbook-execution.json`
  - `guest\<job-id>\events.json`
  - `report.json`
  - `report.zh.html`
  - `report.en.html`
- `runbook-execution.json` 的 `Success=true`。
- VM 运行后已恢复到预期 checkpoint/state。

### 2. 发布包必须证明不含敏感/运行产物

当前证据：

- `scripts/Test-RepositoryPolicy.ps1` 会拒绝常见二进制、VM、report、sample、pcap、
  dump、secret 和大文件。
- `scripts/Test-ReleaseReadiness.ps1` 组合仓库策略、PowerShell 语法、package manifest、
  release path CSignTool 检查。

弥补方向：

- 每次提交/打包前跑：

  ```powershell
  .\scripts\Test-RepositoryPolicy.ps1
  .\scripts\Test-RepositoryPolicy.ps1 -StagedOnly
  .\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource
  .\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -StageSourcePackage
  ```

完成证据：

- 上述命令退出码为 0。
- `D:\Temp\KSwordSandbox\release-readiness\release-readiness.json` 中
  `failedCount=0`。
- source package staging 目录在仓库外，生成 manifest 未列出 forbidden 扩展/路径。

### 3. 默认路径不得调用 CSignTool 或 GUI 签名链

当前证据：

- `Test-ReleaseReadiness.ps1` 对正常 release PowerShell 路径扫描
  `CSignTool.exe` / legacy KSword signing wrapper。
- README/release docs 明确默认 build/smoke/package 不签名驱动。

弥补方向：

- 只保留历史/手动签名脚本作为显式人工路径；正常 install/run/package/readiness 不引用。
- 真实 R0 文档坚持 ordinary `signtool.exe` 或 guest test-signing 说明，不自动回退 GUI。

完成证据：

- `Test-ReleaseReadiness.ps1` 的 `no-csigntool-release-path` 为 `Passed`。

## P1 发布质量差距

### 4. WebUI live monitor 仍需真实样本 UI 走查

当前能力：

- live monitor 展示真实 runbook step、进度百分比、当前步骤、VT quiet 状态、artifact 下载入口。
- stdout/stderr/命令墙不再默认展开。

弥补方向：

- 用 Notepad 5s live job 打开 live page，确认：
  - 当前 step 随 `runbook-progress.json` 更新。
  - VT 未配置时为 quiet state，不写 job message。
  - 报告按钮和 artifact 卡片在回收后可用。

完成证据：

- live page 截图或人工记录。
- Web build 通过。

### 5. 报告观感和证据讲故事能力需要持续扩样本校准

当前能力：

- 报告有中英输出、raw events 折叠/限高/分页、process/network/R0/VT/artifact 分区。
- evidence 展开、process tree、network endpoint grouping 已能降低 raw event 噪音。

弥补方向：

- 对 benign GUI、harmless sample、下载执行样本、文件释放样本、网络样本各跑一份报告。
- 手工检查报告首屏是否能回答：
  - 样本做了什么？
  - 证据是什么？
  - 哪些是采集健康/VT/R0 自噪声，不是样本行为？

完成证据：

- 每类样本至少一份 `report.zh.html`。
- 报告中高价值证据可以不打开 `report.json` 即读到。

### 6. 行为规则扩容需要 corpus 和 schema 质量门禁

当前能力：

- rules 已覆盖 static、process、file、registry、network、pcap、VT、R0 多类事件。
- 规则已有大量中文标题/摘要和 MITRE 映射。

弥补方向：

- 持续按 ATT&CK 家族补规则：持久化、注入、横向移动、反沙箱、下载执行、凭据访问、
  exfil、PCAP DNS/HTTP/TLS。
- 对新增规则跑 schema/contract smoke，而不是重 Hyper-V。

完成证据：

- `rules/behavior-rules.json` JSON/schema 有效。
- static/runtime synthetic scenario 能命中新增规则族。
- 无 placeholder 规则混入主要行为分区，除非它们代表真实采集健康/元数据。

### 7. R0 质量发布前只能承诺 telemetry contract，不承诺默认加载

当前能力：

- R0Collector 已有 ABI/self-check、lost/backpressure/highWatermark/sequence 诊断。
- 报告能分离 R0 health、自噪声和样本行为。

弥补方向：

- 发布前跑 R0Collector 纯用户态 contract/stress，不跑签名/driver load。
- 真实 R0 live 单独作为 lab appendix，要求隔离 VM test-signing。

完成证据：

- R0Collector build/contract/stress 通过。
- readiness 对未签名 driver 报 Warning 或明确失败原因，不污染样本判定。

### 8. Artifact 下载与索引需要跨路径稳定性

当前能力：

- host artifact index 记录 sha256、sizeBytes、artifactRelativePath，并对 duplicate group 做标记。
- dropped files、screenshots、memory dumps、PCAP 事件会带 artifact metadata。

弥补方向：

- 对路径包含空格、非 ASCII、深目录、重复内容的 artifact 做 synthetic import。
- 确保 Web download endpoint 只允许 job root/index 内文件，不允许路径穿越。

完成证据：

- artifact index 中每个可下载文件都有 `artifactRelativePath`、`sizeBytes`、`sha256`。
- 下载端点对非法相对路径返回拒绝。

## 低成本发布验证矩阵

默认低成本：

```powershell
.\scripts\Test-RepositoryPolicy.ps1
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource
dotnet build .\src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\web-release\
dotnet build .\src\KSword.Sandbox.Core\KSword.Sandbox.Core.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\core-release\
dotnet build .\guest\KSword.Sandbox.Agent\KSword.Sandbox.Agent.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\agent-release\
```

发布候选前增加：

```powershell
.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -StageSourcePackage
dotnet build .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -c Verify -p:UseSharedCompilation=false -p:OutDir=D:\Temp\KSwordSandbox\verify\jobtool-release\
```

实验室 live 只在需要时运行：

```powershell
.\run.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
```

## 发布说明建议

公开 MVP release notes 应明确：

- 项目是本地授权分析沙箱，不是云上传服务。
- VT 是 VirusTotal hash-only；Intel VT-x/AMD-V 是 Hyper-V 硬件虚拟化，两者不同。
- 默认命令不会启动或修改 VM；Live 必须显式开启。
- 默认不签名、不加载真实 R0 driver；真实 R0 是隔离实验室高级路径。
- 不要提交或分享 runtime root、样本、报告、dump、pcap、VM、secret 或签名材料。
