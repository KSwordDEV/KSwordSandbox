# 运行时与报告审计记录

更新时间：2026-10-15 18:41:01 +08:00（本机时间）  
工作树：`E:\Projects\KswordSandbox`  
审计范围：质量门禁、Web API 本地 pipeline、报告 smoke、源码包暂存和 release-readiness 静态门禁。只使用仓库内合成样本与临时目录；没有启动 Hyper-V、没有修改 VM、没有下载或执行真实恶意样本。

## 这一轮结论

| 检查 | 结果 | 说明 |
|---|---|---|
| `scripts/Test-QualityGates.ps1`（含 Debug build） | 通过 | 3 个默认场景全部通过；0 警告、0 错误。 |
| `scripts/Test-QualityGates.ps1 -NoBuild`（复跑） | 通过 | 第二轮复跑结果一致，未见质量门禁回归。 |
| `scripts/Invoke-LocalPipelineSmoke.ps1` | 通过 | Web `/health`、文件扫描、dry-run job、live raw-event、guest/driver 导入和 `report.html`/`report.zh.html`/`report.en.html` 均通过。运行产物在 `D:\Temp\KSwordSandbox\pipeline-smoke-audit\run-20261015-183143-9ee5d54a`。 |
| `report.evidence-story.contract` | 通过 | R0 网络、静态资源、artifact-index 和 VT evidence story 均通过。 |
| `report.event-sampler-priority.contract` | 通过 | static/network/probe/R0 优先级和噪声压缩契约通过。 |
| `webui.experience.contract` | 通过 | WebUI 上传、监控/报告/进度导航、状态/路径、telemetry、runbook 和 guest import 契约通过。 |
| `scripts/package-portable.ps1 -PackageKind source -StageOnly -AllowDirtySource` | 通过 | 421 个源码文件完成仓库外暂存；没有压缩、push、VM 或 signing 操作。 |
| `scripts/Test-ReleaseReadiness.ps1 -AllowDirtySource` | 失败（静态契约） | 13 通过、1 警告、3 失败、2 跳过；见下方逐项分析。 |
| `report.ux.contract` | 失败（代码回归） | 默认 `HtmlReportRenderer.Render()` 生成的 HTML 不含 `<html lang="zh-CN">`，与默认中文兼容报告契约不一致。其它报告 smoke 未受影响。 |

## 失败项与归因

### 需要修复的代码/契约问题

1. **默认报告语言回归**：`report.ux.contract` 在 `ReportUxContractScenario.RequireRenderedReportContract` 处失败，要求默认 `Render()` 产物是简体中文兼容报告，并链接 `report.zh.html`。当前返回内容未命中 `<html lang="zh-CN">`。这不是环境噪声；应检查 `HtmlReportRenderer.Render()` 的默认语言选择和对应测试，修复后重跑 `report.ux.contract` 与 pipeline smoke。
2. **安装入口静态契约缺两个语义标记**：`install.ps1` 的 `Get-InstallOperatorModeMatrix` 缺少 `MutatingCommand = $restoreCommand`、`RestoresCheckpoint = $true`。这是 readiness 静态检查与实现元数据不一致，属于真实契约缺口；不会由本机网络或 Hyper-V 状态造成。
3. **部署诊断标记缺失**：`scripts/run.ps1` 缺少 `Live Hyper-V execution is` marker，两个 package manifest 的 `releaseContract.operatorDiagnostics` 没有同时说明 Hyper-V 与 `RuntimePublishRoot`。属于发布说明/诊断契约缺口，需补齐后再做 handoff。

### 需要先判定是否误报的静态检查

- `readiness-non-mutating` 报告 `Test-ReleaseReadiness.ps1` 含 `Invoke-HyperVE2E.ps1`、`Start-SandboxHyperVJob.ps1` 两个禁用 provider 脚本字面量引用。当前脚本仍将这些名称用于“禁止调用”的扫描规则/允许声明计数；本轮没有执行 provider 命令，也没有修改 VM。该项是静态扫描规则与自身检查文本的边界问题，暂按**静态检查误报候选**记录；应让扫描器只分析可执行调用 AST，或明确排除自身声明文本，再复跑确认。

### 环境/工作树噪声

- `git-clean` 仅因当前协同开发工作树有 9 个已修改/未跟踪项而警告；命令使用了 `-AllowDirtySource`，源码暂存仍成功。这不代表运行时或报告回归。
- release-readiness 默认跳过 runtime payload 完整性和 light build；这是脚本参数选择，不是失败。pipeline smoke 已覆盖本地 Web build/启动和报告生成。
- smoke 使用 `.exe` 命名的纯文本合成文件，不能替代隔离环境中的真实样本校准；它只验证流程、归因边界和 UI 契约。

## 可复现命令

```powershell
.\scripts\Test-QualityGates.ps1
.\scripts\Test-QualityGates.ps1 -NoBuild
.\scripts\Invoke-LocalPipelineSmoke.ps1 -RuntimeRoot 'D:\Temp\KSwordSandbox\pipeline-smoke-audit' -StartupTimeoutSeconds 90
.\scripts\Invoke-SandboxSmokeTest.ps1 -NoBuild -Scenario report.evidence-story.contract
.\scripts\Invoke-SandboxSmokeTest.ps1 -NoBuild -Scenario report.event-sampler-priority.contract
.\scripts\Invoke-SandboxSmokeTest.ps1 -NoBuild -Scenario webui.experience.contract
.\scripts\Invoke-SandboxSmokeTest.ps1 -NoBuild -Scenario report.ux.contract
.\scripts\package-portable.ps1 -PackageKind source -OutputRoot 'D:\Temp\KSwordSandbox\packages-audit' -StageOnly -AllowDirtySource -Force
.\scripts\Test-ReleaseReadiness.ps1 -RepositoryRoot (Get-Location).Path -OutputRoot 'D:\Temp\KSwordSandbox\release-readiness-audit' -AllowDirtySource
```

## 下一轮入口

1. 修复默认中文报告契约和安装/发布诊断静态契约后，先运行 `report.ux.contract`、`Test-QualityGates.ps1 -NoBuild` 和 local pipeline smoke。
2. 若 `readiness-non-mutating` 仍失败，单独调整扫描器对自身禁用脚本名称的识别，再重跑 release-readiness；不要把 provider live 当作修复手段。
3. 任意真实样本测试必须在隔离 VM/快照中单独记录 job ID、网络策略和采集质量；本审计不会把合成 smoke 的通过结果当作恶意样本动态结论。

## 修复后复核（2026-10-15 18:45 +08:00）

主线修复默认中文报告、脚本/属性保护、`agent` 生命周期指标和扁平色块后，按相同路径复跑：

| 检查 | 结果 | 证据 |
|---|---|---|
| `report.ux.contract` | **通过** | `Report UX sections and copyable evidence contracts are present.`；默认 `Render()` 的 `zh-CN` 契约已恢复。 |
| `scripts/Test-QualityGates.ps1 -NoBuild` | **通过** | artifacts、R0 self-noise、rules collection-health 三个场景全部通过。 |
| `scripts/Invoke-LocalPipelineSmoke.ps1 -RuntimeRoot D:\Temp\KSwordSandbox\pipeline-smoke-audit2` | **通过** | `/health`、file scan、job dry-run、live events、报告导入和三份 HTML 报告全部通过；Job ID `b516f013-74a6-47b9-b63a-66919abd6f42`。 |

本轮未启动 Hyper-V、未执行真实样本，也没有发现环境基线噪声。第一轮记录的 `report.ux.contract` 代码回归已闭合；release-readiness 的安装/发布静态契约尚未在本轮复测，仍需单独处理并记录结果。

### Release-readiness 复测（2026-10-15 18:47 +08:00）

`Test-ReleaseReadiness.ps1 -AllowDirtySource` 仍为 **13 通过、1 警告、3 失败、2 跳过**，与首轮相同：

- `installer-entrypoint-static-contract`：仍缺 `MutatingCommand = $restoreCommand` 与 `RestoresCheckpoint = $true` 两个语义标记。
- `readiness-non-mutating`：仍把 `Test-ReleaseReadiness.ps1` 自身用于禁止调用扫描的 `Invoke-HyperVE2E.ps1`、`Start-SandboxHyperVJob.ps1` 字面量计为禁用 provider 调用，属于静态误报候选；本轮安全摘要确认没有执行 provider/VM。
- `deployment-operator-diagnostics`：`scripts/run.ps1` 和两个 package manifest 的诊断 marker 仍未满足要求。

因此报告 UX 和运行时 pipeline 已恢复通过，release handoff 的静态契约仍未闭合。

### Release-readiness 修复后复测（2026-10-15 18:55 +08:00）

补齐安装模式语义标记、`scripts/run.ps1` 的 Hyper-V/RuntimePublishRoot 诊断说明、两个 package manifest 的 provider 诊断文本，并收紧 readiness 自身禁用脚本字面量扫描后，复测结果为 **16 通过、1 警告、0 失败、2 跳过**。唯一警告是工作树有协同修改；未执行 VM、provider live、签名或 push。输出目录：`D:\Temp\KSwordSandbox\release-readiness-audit5`。

### 修复后含构建质量门禁（2026-10-15 18:49 +08:00）

`Test-QualityGates.ps1`（含 Debug build）重新生成 Abstractions/Core/SmokeTests，构建 **0 警告、0 错误**，3 个默认场景全部通过。说明前述 `report.ux.contract` 修复没有依赖旧二进制产物。

### 当前候选复测（2026-10-15 22:55 +08:00）

以下结果以当时已推送的 `7b400df` 为基线（复测开始时工作树干净），用于覆盖上文较早的历史快照；本段记录的监控脚本修复随后纳入最终提交：

| 检查 | 当前结果 | 证据 |
|---|---|---|
| `dotnet build tests/KSword.Sandbox.SmokeTests/KSword.Sandbox.SmokeTests.csproj -c Release --no-restore` + 全 smoke | **通过** | Release 构建 0 警告、0 错误；全部场景输出 `Smoke tests passed.` |
| `scripts/Test-QualityGates.ps1` | **通过** | 3 个默认离线质量门禁通过，构建 0 警告、0 错误。 |
| `scripts/Test-ReleaseReadiness.ps1` | **通过** | 17 pass、0 warning、0 fail、2 skip；跳过项仅为未提供外部 runtime publish root 和默认不执行 light build。 |
| `scripts/Invoke-LocalPipelineSmoke.ps1 -Configuration Release -NoBuild` | **通过** | `/health`、文件扫描、dry-run、live events、事件导入及中英文 HTML 报告均通过；Web stderr 为空。 |
| `scripts/Test-LiveTelemetryFramework.ps1 -ContractOnly -RequireImplementedStream` | **通过** | SSE/polling、报告入口、手工导入及 dashboard 当前 server-owned 报告标记全部通过，退出码 0。 |
| `run.ps1 -Mode CheckEnvironment -Json -NoBuild` | **通过（非 Live）** | `OverallStatus=ReadyForNonLive`、`WebUiReady=true`、`PlanOnlyReady=true`、`LiveReady=false`；明确报告硬件虚拟化未确认和 R0 host driver 缺失。 |

本轮还修复了 `Test-LiveTelemetryFramework.ps1` 的返回码污染：格式化对象曾覆盖 `exit (...)` 的数值返回，导致“检查失败”仍返回 0；现已通过 `Out-Host` 隔离格式化输出，并把过时的 dashboard 文案检查换成当前 `data-report-current="true"`/`Report not ready` 契约。
