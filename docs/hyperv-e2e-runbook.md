# Hyper-V 一键 E2E 运行手册（one-command E2E runbook）

本文覆盖已准备 KSword Sandbox Hyper-V golden VM 的脚本式 E2E 路径。默认安全：顶层命令只写 JSON
计划并退出；只有在 elevated host PowerShell 中显式传入 `-Live` 才会触碰 VM。

## 先确认操作者路径 / Confirm the operator path first

`Invoke-HyperVE2E.ps1` 假设你已经完成以下三条路径之一；它不是首台机器创建 VM 的向导：

- 使用已配置环境：本机 install state、`sandbox.local.json`、guest secret、VM/checkpoint
  profile、runtime root 和 staged payload 已存在。
- 恢复已有 checkpoint/snapshot：VM 和 clean snapshot 已存在；恢复 snapshot 是显式
  lab mutation，只能在操作者确认后执行。
- 创建/准备新环境：先完成 Hyper-V host 兼容性、BIOS/UEFI Intel VT-x / AMD-V、
  Hyper-V PowerShell module、管理员 PowerShell、Windows guest、`SandboxUser`、
  Guest Service Interface、PowerShell Direct 和 clean checkpoint。

低成本确认命令：

```powershell
.\install.ps1 -Mode Status
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Status
.\run.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode Analyze -SamplePreset Notepad
```

这些命令不启动、不还原、不停止 VM，不签名 driver，不调用 `CSignTool.exe`。
VirusTotal key 可选；Intel VT-x / AMD-V 才是 Hyper-V live 前置条件。

## 安全契约（safety contract）

`scripts/Invoke-HyperVE2E.ps1` 是 operator 的主要脚本入口；the default mode is `PlanOnly`：

- 写出可审阅 plan JSON；
- 不还原 checkpoint；
- 不启动、停止、创建、删除或还原任何 VM；
- 不向 guest 复制 host 文件；
- 不运行 Guest Agent、R0Collector、driver code 或样本；
- 不签名 driver，不调用 `CSignTool.exe`。

`-WhatIf` 即使与 `-Live` 同时使用，也保持 no-mutation。Live execution 需要同时满足：

1. 存在 `-Live`，且没有 `-PlanOnly`。
2. 当前 shell 是 Administrator。
3. 没有 `-WhatIf`。
4. guest password 环境变量在当前进程可见。
5. 样本和 staged guest payload 文件存在，并且位于仓库外。
6. 生成的 `preflightSummary.liveReady` 在任何 child script 启动前为 `true`。

Live 前还应运行只读 readiness 和仓库策略检查。默认 E2E 只验证 compile/mock R0 wiring，不签名、不调用
`CSignTool.exe` 或旧 KSword signing wrapper：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-RepositoryPolicy.ps1 -StagedOnly
```

## 推荐主路径

```powershell
# 1. 准备 Guest Agent/R0Collector payload，输出在仓库外。
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-GuestPayload.ps1 `
  -RepoRoot 'D:\Projects\KswordSandbox' `
  -PayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -Configuration Release `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -SelfContained

# 2. 准备 harmless sample，输出在仓库外。
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-HarmlessSample.ps1 `
  -RepositoryRoot 'D:\Projects\KswordSandbox' `
  -OutputRoot 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample'

# 3. 只读 readiness。
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1

# 4. PlanOnly：只写 plan/runbook-execution 记录。
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -PlanOnly

# 5. WhatIf：审阅 Live 意图但不修改 VM。
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -Live `
  -WhatIf

# 6. Live：必须在同一个 elevated PowerShell 进程内设置密码。
$env:KSWORDBOX_GUEST_PASSWORD = '<SandboxUser password>'
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -Live
```

`Prepare-GuestPayload.ps1`、`Prepare-HarmlessSample.ps1` 会生成 payload/sample/build 输出；这些都必须保持在
`D:\Temp\KSwordSandbox` 等仓库外路径，不要提交。

## 历史 go/no-go 快照

旧的本地 go/no-go 快照只可作为历史记录，不可作为当前 release 或当前机器 readiness。
在任何 `-Live` 前都必须从当前 elevated PowerShell 重新运行只读检查：

```powershell
.\install.ps1 -Mode CheckEnvironment
.\run.ps1 -Mode CheckEnvironment
.\scripts\Test-HyperVReadiness.ps1
```

如果这些检查缺少 guest password、VM/checkpoint、Guest Service Interface、PowerShell Direct
或 payload，先按 `RecommendedActions` 修复；不要用历史 snapshot 代替当前证据。

## Harmless behavior sample contract

首选 live smoke input 是 harmless behavior sample：
`tools/KSword.Sandbox.HarmlessSample/KSword.Sandbox.HarmlessSample.csproj`。如项目移动，仍应保留同名
`KSword.Sandbox.HarmlessSample.csproj`，便于 smoke tests 发现。

构建/发布使用 `Prepare-HarmlessSample.ps1`，输出必须在仓库外，例如：

```text
D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample
```

发布出的 `KSword.Sandbox.HarmlessSample.exe`、`bin`/`obj`、helper `.dll`/`.bin` 都是本地 lab artifacts，
不得入库。

## 生成 plan JSON

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe'
```

默认 plan path 在仓库外：

```text
D:\Temp\KSwordSandbox\plans\hyperv-e2e-<job-id-n>.json
```

显式 plan path：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -PlanPath 'D:\Temp\KSwordSandbox\plans\manual-review.json' `
  -PlanOnly
```

Plan JSON 包含：

- `safeDefault`、`requestedMode`、`effectiveMode`、`willMutateVm`；
- VM name 与 clean checkpoint name；
- host checks：Windows、Administrator、Hyper-V cmdlets、`Get-VM`、`Get-VMSnapshot`、Guest Service
  Interface、credential env var，以及 VM 已运行时的非变更 PowerShell Direct probes；
- host sample path 与 guest sample path；
- host payload root 与 Guest Agent/R0Collector payload 文件；
- R0 driver host-path readiness；当 `driver.enabled=true`、`driver.useMockCollector=false` 且
  `driver.hostDriverPath` 为空或 `.sys` 不存在时，live preflight 会失败；
- guest output paths：`events.json`、`driver-events.jsonl`、`agent.pid`、`agent.exit`；
- Guest Agent command line 与 R0Collector mock/live sidecar arguments；
- ordered `steps` 和 `mutatesVmState` flags；
- preflight summary 与 live-only failures；
- job root 下计划的 `runbook-execution.json` path。

PlanOnly 与 WhatIf 也会写出 `runbook-execution.json`，其中所有 steps 标记 skipped，证明没有 child script
或 VM command 被启动；脚本同时写出 UI-safe `runbook-progress.json`，主页面/恢复工具可直接读取，不需要解析
PowerShell command、stdout 或 stderr。

审阅 plan/progress 时请确认：

- safe review run 显示 `willMutateVm=false`；
- `runbook-progress.json` 中的 `ProgressPercent`、`FailureReason`、`RemediationHints`、phase result paths 和
  skipped/executed step records 可用于 UI/恢复视图；
- 如果不想把 guest password 持久化到 User scope，先用 `Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword`
  仅写入当前 Process scope。

## Mock R0 live flow

当要验证 live Guest Agent/R0Collector 通路但不加载 signed kernel driver 时，使用 Mock R0。这是 driver
signing 冻结时的首选 E2E 模式。配置必须留在仓库外：

```powershell
$mockConfigPath = 'D:\Temp\KSwordSandbox\mock-r0.live.json'
$config = Get-Content .\config\sandbox.example.json -Raw | ConvertFrom-Json
$config.driver.enabled = $true
$config.driver.useMockCollector = $true
$config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $mockConfigPath -Encoding UTF8
```

先审阅：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-HyperVE2E.ps1 `
  -ConfigPath $mockConfigPath `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -PlanOnly
```

确认 `driver.collectionMode` 为 `Mock`、`driver.useMockCollector=true`、Guest Agent 参数含 `--r0-mock`、
R0Collector 参数含 `--mock` 后，再在 elevated process 设置密码并 live。

Mock run 仍会还原 `Clean`、启动 VM、stage payload、复制样本、运行 Guest Agent/R0Collector、收集输出、
停止 VM 并再次还原 `Clean`。只 mock R0Collector device dependency。

English contract note: the live flow restores the clean checkpoint again before the VM is treated as golden.

## Optional real R0 driver flow

Real R0 loading 不属于默认 E2E path。不要把 `CSignTool.exe` 或
`scripts\Sign-SandboxDriverWithKswordCSignTool.ps1` 加入 E2E preparation。确需真实 driver load 时，先完成
compile-only validation，再按 `docs/driver-signing.md` 在 Windows test mode + local test certificate 下处理。

Real R0 需要：

- `driver.useMockCollector=false`；
- `driver.hostDriverPath` 指向 host-side `.sys`；
- test-signed `.sys` staged 到 `C:\KSwordSandbox\driver` 等 guest-only path；
- 签名材料、`.sys`、symbols 全部保持在 git 外；
- live 前运行 non-mutating R0 readiness。

## Live execution sequence

只在隔离 lab host 上运行 live。`-Live` 会修改配置 VM：restore/start/copy/run/collect/stop/restore。

Live mode 调用两个 child scripts：

1. `scripts/Start-SandboxHyperVJob.ps1`
   - 在首次 VM mutation 前验证 elevation、Hyper-V commands、VM、clean checkpoint、Guest Service Interface、
     sample、payload folders/files 和可选 payload manifest；
   - 从 `KSWORDBOX_GUEST_PASSWORD` 加载 credential，不打印 secret；
   - 必要时停止 golden VM；
   - 还原 clean checkpoint；
   - 启用 Guest Service Interface；
   - 启动 VM，并在等待 `Running` 时输出低频 heartbeat；
   - 等待 PowerShell Direct，bounded retry heartbeat 包括 elapsed time、attempt count、last connection error；
   - 使用 `Copy-Item -ToSession` 复制 Guest Agent 与 R0Collector payload；
   - 使用 `Copy-VMFile` 复制样本；
   - 创建干净 guest output folder；
   - 异步启动 Guest Agent。

2. `scripts/Collect-GuestOutputs.ps1`
   - 打开 PowerShell Direct session；
   - 读取 `agent.pid`；
   - 周期性使用 `Copy-Item -FromSession` 复制 guest output folder 到 host；
   - 要求 `agent.exit` 存在，并在 Guest Agent exit code 非 0 时失败；
   - 索引收集到的 events/artifacts，尽可能计算 size、kind、SHA-256；
   - 要求 host 侧存在 `events.json`、`agent.pid`、`agent.exit`；启用 driver collection 但缺少
     `driver-events.jsonl` 时 warning；
   - 停止 VM；
   - 默认再次还原 clean checkpoint。

顶层 orchestrator 为每个 child process 设置 phase timeout；约每 30 秒输出一次 heartbeat。timeout 时在 JSON
中记录 `timedOut=true` 和 `timeoutSeconds`，stdout/stderr 保存在 JSON record，不直接刷屏。

Live 成功后，`Invoke-HyperVE2E.ps1` 会自动调用 `Import-HyperVJobReport.ps1` 导入 guest events 并生成
`report.json` / `report.html` / 本地化 HTML。失败或需要重建时可手动使用该脚本导入。

## 失败诊断与可导入 skeleton

为让 install 后的单次 `run.ps1 -Mode Analyze -Live` 更容易恢复，所有脚本式 E2E 失败都会尽量留下两个
operator 可读 sidecar：

- `runbook-progress.json`：UI-safe 进度快照，包含每个 step 的 `state`、`message`、`FailureReason` 和
  `RemediationHints`；不包含 PowerShell command text、stdout/stderr 或 secret。
- `guest\<job-id-n>\guest-output-skeleton.json` 与同目录 `events.json`：当真实 guest output 缺失或为空时，
  写入 `hyperv.e2e.failure_skeleton` 事件、`agent.pid=0`、`agent.exit=-1`、stdout/stderr 占位文件。
  该 skeleton 是“可导入诊断证据”，不表示 Guest Agent 已成功运行。

脚本优先保留真实 guest `events.json`：如果 collection 已复制到非空 events，失败 skeleton 不覆盖真实事件，
只补充 metadata/marker 文件。手动导入命令：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Import-HyperVJobReport.ps1 `
  -JobId '<job-guid>' `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -EventsPath 'D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest\<job-id-n>\events.json' `
  -RunbookExecutionPath 'D:\Temp\KSwordSandbox\jobs\<job-id-n>\runbook-execution.json'
```

如果 `events.json` 已缺失但 `runbook-execution.json` 存在，`Import-HyperVJobReport.ps1` 会先生成同样的
failure skeleton 再调用 JobTool；整个 import 仍然只读 VM，不启动、停止或还原 VM。

常见失败的中文优先诊断：

- 凭据：检查 `guest.passwordSecretName`、Process/User/Machine scope、runner 是否与设置 secret 的
  PowerShell 是同一进程；脚本只记录 secret 名称/scope，永不打印值。
- VM：检查 golden VM 名称、Hyper-V PowerShell 工具、管理员权限；PlanOnly/WhatIf 只做只读查询。
- checkpoint：检查 `cleanCheckpointName`，失败时记录最多 20 个可见 checkpoint 名称帮助比对。
- Guest Service Interface：脚本按组件 ID `6C09BB55-D683-4DA0-8931-C9BF705F6480`、英文名和中文名
  `来宾服务接口` 匹配；Live start 可在 VM/checkpoint 预检成功后启用它。
- PowerShell Direct：heartbeat 会记录 elapsed、attempt count、最后 VM state 和首条连接错误；优先提示凭据不同步、
  VM 未 Running 或 Hyper-V/PowerShell Direct 不可用。

## 输出位置（output locations）

对于 job `<job-id-n>`：

```text
D:\Temp\KSwordSandbox\jobs\<job-id-n>\
  runbook-execution.json
  runbook-progress.json
  hyperv-e2e-start-result.json
  hyperv-e2e-collect-result.json
  report.json
  report.html
  report.zh.html
  report.en.html
  guest\<job-id-n>\events.json
  guest\<job-id-n>\guest-output-skeleton.json
  guest\<job-id-n>\driver-events.jsonl
  guest\<job-id-n>\agent.pid
  guest\<job-id-n>\agent.exit
```

这些 outputs、samples、payload binaries、driver files、VM disks、build products 都不得入库。

## 恢复说明（recovery notes）

如果 live 在 start phase 修改 VM 后失败，`Start-SandboxHyperVJob.ps1` 会尝试 stop/restore cleanup。如果进入
collection phase，`Collect-GuestOutputs.ps1` 仍会在 `finally` 中尝试 stop VM 并还原 clean checkpoint。
Cleanup errors 会记录在 `cleanupErrors` 和 warnings 中，但不应覆盖 primary failure reason。

修复 VM 后，从 elevated shell 重新运行只读 readiness，再尝试下一次 live。

## PowerShell Direct 手动确认

当 password secret 缺失或 VM 停止时，PowerShell Direct 不能完全确认。仅在 VM 已运行或你明确手动启动后执行：

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
$vmName = 'KSwordSandbox-Win10-Golden'
$guestPassword = ConvertTo-SecureString $env:KSWORDBOX_GUEST_PASSWORD -AsPlainText -Force
$guestCredential = [pscredential]::new('SandboxUser', $guestPassword)

Invoke-Command -VMName $vmName -Credential $guestCredential -ScriptBlock {
  [pscustomobject][ordered]@{
    ComputerName = $env:COMPUTERNAME
    UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    AgentExists = Test-Path 'C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe' -PathType Leaf
    R0CollectorExists = Test-Path 'C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe' -PathType Leaf
  }
}
```

手动验证后，在再次把 `KSwordSandbox-Win10-Golden` 视为 golden baseline 前，还原 `Clean` checkpoint。
