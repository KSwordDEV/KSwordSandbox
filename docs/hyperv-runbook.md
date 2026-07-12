# Hyper-V 运行手册（runbook）

规范范围 / Canonical scope：本页只描述生成 runbook 的概念步骤和执行前提。当前只读
preflight 命令见 `docs/hyperv-readiness.md`；脚本化 PlanOnly / WhatIf / Live
操作者流程见 `docs/hyperv-e2e-runbook.md`。

宿主服务会为 sandbox job 生成 Hyper-V runbook。默认执行边界是 dry-run / PlanOnly，便于在没有
管理员权限或没有注册 golden VM 的机器上安全构建和审阅。当前脚本 live 路径使用同一个 golden VM：
还原 `Clean` checkpoint、启动 VM、运行样本、收集输出，然后停止并再次还原 checkpoint。
临时差分磁盘 VM（temporary differencing-disk VM）属于保留设计方向，不是当前默认脚本路径。

## 计划步骤组（planned step groups）

1. 验证 Hyper-V PowerShell cmdlets。
2. 验证配置的 golden VM 存在。
3. 从环境变量加载 guest credential。
4. 停止 VM（如需要）并还原 clean checkpoint。
5. 启用来宾服务接口（Guest Service Interface）。
6. 启动分析 VM，并等待 Hyper-V 报告 `Running`。
7. 等待 PowerShell Direct，可见 bounded retries 和 heartbeat。
8. 通过 PowerShell Direct 将 `paths.guestPayloadRoot` 下的 Guest Agent 与 R0Collector payload stage 到 guest。
9. 当配置了 `driver.hostDriverPath` 时，可选复制外部 `.sys` 到 `driver.driverPathInGuest`。
10. 将样本复制到 guest。
11. 创建 job 专属 guest 输出目录，例如 `C:\KSwordSandbox\out\<job-id-n>`。
12. 可选安装 driver service（`install-driver-service`），仅 real R0 且 `.sys` path 有效时生成。
13. 通过 PowerShell Direct 异步启动 `KSword.Sandbox.Agent.exe`。
14. driver collection 启用时传入 `--driver-events C:\KSwordSandbox\out\<job-id-n>\driver-events.jsonl`、
    `--r0collector`、`--driver-device`；mock mode 会额外加入 `--r0-mock` / R0Collector `--mock`。
15. Guest Agent 运行期间周期性将 guest output 复制回 `D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest`。
16. 最终复制 guest JSON/JSONL output，并验证 `events.json`、`agent.pid`、`agent.exit` 到达 host。
17. 停止 VM，并按配置再次还原 clean checkpoint。

长等待会输出低频值守心跳 / operator heartbeat：VM 启动报告状态变化（state change）；
PowerShell Direct 报告已用时间、尝试次数（attempt count）和最后连接错误；live-output
sync 抑制重复周期性 copy error，只保留首个 warning，最终 copy 失败时给出一个简洁原因。

## 环境路径与兼容性 / Environment path and compatibility

本页的 Live runbook 只适用于已经完成安装路径选择的操作者：

- 已配置环境：直接用 `Status` / `CheckEnvironment` 确认 VM profile、secret、
  payload 和 runtime root。
- 恢复已有 checkpoint/snapshot：先记录 VM/checkpoint 名称并准备 payload；实际
  `Restore-VMSnapshot` 是显式 lab mutation，不是低成本 readiness。
- 创建/准备新环境：先完成支持 Hyper-V 的 Windows host、Hyper-V PowerShell module、
  管理员 PowerShell、BIOS/UEFI Intel VT-x / AMD-V 和 SLAT、Windows guest、
  Guest Service Interface、PowerShell Direct、guest account/password secret 和 clean
  checkpoint/snapshot。

VirusTotal key 是可选 hash-only enrichment，缺失不阻止 Plan/WebUI；Intel VT-x /
AMD-V 是 Hyper-V live 前置条件。runbook 准备路径不签名 driver，不调用
`CSignTool.exe`，也不使用旧 GUI/interactive signing fallback。

## 执行前提（execution prerequisites）

- Elevated host PowerShell。
- Hyper-V feature 与 PowerShell module 已安装。
- Golden VM 已注册，例如 `KSwordSandbox-Win10-Golden`。
- Clean checkpoint 已存在，例如 `Clean`。
- Guest credential 可通过配置环境变量读取，默认 `KSWORDBOX_GUEST_PASSWORD`。
- Guest Service Interface 已启用；中文 Windows 可能显示为 `来宾服务接口`，组件 ID 为
  `6C09BB55-D683-4DA0-8931-C9BF705F6480`。
- PowerShell Direct 可用。
- Guest Agent 和 R0Collector host payload 已在 `paths.guestPayloadRoot` 下准备好，通常通过
  `scripts/Prepare-GuestPayload.ps1`。
- 可选 test-signed driver 保持在 git 外，仅 real R0 需要，并通过 `driver.hostDriverPath` 引用。

## Live 前只读门禁

运行 readiness preflight；它不会启动 VM、还原 checkpoint、复制文件或启用 integration service：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

完全显式形式：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestUserName 'SandboxUser' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -GuestPayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

Elevated PowerShell 中可做只读 Hyper-V 状态确认：

```powershell
Get-VM -Name 'KSwordSandbox-Win10-Golden'
Get-VMSnapshot -VMName 'KSwordSandbox-Win10-Golden' -Name 'Clean'
Get-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden'

$guestServiceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'
Get-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' |
  Where-Object {
    ([string]$_.Id).EndsWith('\' + $guestServiceComponentId, [System.StringComparison]::OrdinalIgnoreCase) -or
    $_.Name -eq 'Guest Service Interface' -or
    $_.Name -eq '来宾服务接口'
  } |
  Select-Object Name, Enabled, PrimaryStatusDescription
```

## 真实 R0 driver 预检 / Real R0 driver preflight（可选）

默认 E2E 不要求真实 kernel driver。只有三项配置一致时才启用真实 R0 collection：

- `driver.enabled=true`
- `driver.useMockCollector=false`
- `driver.hostDriverPath` 指向存在的、已本地 test-signed 的 `.sys`

如果 `driver.enabled=true` 且 `driver.useMockCollector=false`，但 `driver.hostDriverPath` 为空，runbook 无法把
driver 复制进 guest，也不会生成 `install-driver-service`。后续 R0Collector 可能因打开
`\\.\KSwordSandboxDriver` 失败而返回 `deviceUnavailable` / `win32Error=2`。

生成的 runbook 会先发出非变更 `check-r0-driver-config` preflight；脚本 E2E plan 也会在任何
VM mutation 前记录 `R0 driver host path configuration` 失败。修复方式：

```powershell
# 真实 R0：记录仓库外 test-signed .sys。
.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>

# 只验证通路：改用 mock collector。
# 在 local config 中设置 driver.useMockCollector=true。

# 临时关闭 R0Collector：
.\scripts\Invoke-HyperVE2E.ps1 -NoR0Collector -PlanOnly
```

不要把 `CSignTool.exe` 或旧签名 wrapper 加入 runbook/E2E 准备路径。测试证书
helper 只走普通 Windows SDK `signtool.exe`；找不到 `signtool.exe` 时会明确
报告跳过签名，而不是调用会弹窗的旧工具。

## 当前本地状态说明

宿主现在具备 dry-run 和 live execution wiring。非 elevated shell 仍无法可靠枚举 Hyper-V 状态；
`Get-VM`、`Get-WindowsOptionalFeature -Online` 等命令通常需要管理员权限。Live execution 必须从
elevated host process 启动，并满足 golden VM、checkpoint、guest credential 和 payload 前置条件。

如果 `Test-HyperVReadiness.ps1` 因 VM 为 `Off` 报告 `PowerShell Direct` 为 `Warning`，这表示 preflight
保持了只读；可以在 operator-controlled session 中手动启动 VM 后再复验，或在 live 前接受该只读限制。

## 进度耐久化与新鲜度字段 / Durable progress and freshness

真实 runbook 进度仍以 UI-safe 快照为准：实时内存流会同步写入 job 目录中的
`runbook-progress.json`，终端执行记录写入 `runbook-execution.json`。API/契约层的进度元数据不包含
PowerShell command、stdout 或 stderr，只暴露便于值守人员判断“当前显示是否可信”的字段：

- `durableSourcePath`：持久化来源路径，优先指向 `runbook-progress.json` 或终端
  `runbook-execution.json`。
- `snapshotAge`：本次 API 生成时间与快照 `updatedAtUtc` 的差值。
- `staleThreshold`：默认 `00:00:15`；非终止状态超过该阈值时可认为进度可能陈旧。
- `isStale`：仅 queued/running/pending 等非终止状态会置为 true；completed/failed/canceled 不因年龄变陈旧。
- `latestStepSummary`：最新/当前步骤的安全摘要，包含 `stepIndex`、`ordinal`、`title`、`state`、
  `phase/category`、`exitCode`、`message` 和中文修复提示。
- `completedStepCount`、`failedStepCount`、`runningStepCount`：供监控页或外部轮询快速判断进度。
- `operatorHintsZh`：中文优先的值守提示，说明持久化路径、快照年龄、最新步骤以及下一步处理建议。

如果进度看起来停住，先刷新 `/api/jobs/{jobId}/runbook/progress` 或
`/api/jobs/{jobId}/runbook/background`。若 `isStale=true` 且后台仍在 running，保留 job 目录并检查
Web Host 日志；不要重复启动同一 job，避免覆盖证据和执行上下文。
