# 运行入口 / Runtime entry point

本页中文优先。命令参数名（如 `-Mode`、`-Live`、`-SamplePath`）和机器可读
JSON key（如 `RecommendedActions`、`SecretValuePrinted`）保持英文，不翻译。

日常使用最短路径：

```powershell
.\install.ps1 -Mode Install -PromptPassword   # 首次或配置变化时运行
.\run.ps1                                     # 日常启动 WebUI；不会启动/还原 VM
```

出错时先按输出中的“下一步”处理。常见路径：

- WebUI 端口不可用：去掉 `-StrictUrl` 让脚本自动换端口，或传
  `-Url http://127.0.0.1:<free-port>`。
- 找不到配置：普通启动会显示“本机配置未就绪”，请先打开安装向导完成
  `Install / prepare local settings`，再在 `Change settings` 里确认 VM/checkpoint/driver path。
- payload 缺失/过期：运行 `.\scripts\Prepare-GuestPayload.ps1 -SelfContained`。
- `Analyze` 没有样本：使用 `-SamplePreset Notepad` / `-SamplePreset HarmlessSample`
  或传入 `-SamplePath <sample.exe>`。
- 真实 R0 缺少 driver：配置 `-DriverHostPath <test-signed .sys>`，或仅做链路验证时
  设置 `driver.useMockCollector=true`。`run.ps1` 不签名 driver，不使用 GUI signing
  fallback，也不调用 `CSignTool.exe`。

中文摘要 / English summary：`.\run.ps1` 默认只启动 WebUI 或生成 PlanOnly-safe
计划；只有显式传入 `-Live` 才会修改 VM。

推荐操作者流程 / Intended operator flow：先用 `install.ps1` 准备一次性本机设置，
之后每次用 `run.ps1` 启动本地 WebUI。

最短流程：

```powershell
.\install.ps1   # one-time or when VM/password/config changes
.\run.ps1       # each time you want to use the local WebUI
```

`.\run.ps1 -Mode StartWebUI` 是一键 WebUI 入口：未显式传
`-OpenBrowser:$false` 时会自动打开浏览器。默认 `.\run.ps1` 仍只启动本地
WebUI 服务，不会启动、还原或停止 VM。

release bundle 也会在 `scripts\` 下暴露等价入口：

```powershell
.\scripts\install.ps1
.\scripts\run.ps1
```

`scripts\` 包装器会在同一个 PowerShell 进程中转发到仓库根 wrapper。它们只是
packaging convenience alias，不是第二套配置系统。同一个 session 中建议固定使用根目录或
`scripts\` 形式；两者都会读取 `%ProgramData%\KSwordSandbox\install-state.json`，
使用同一个 `Sandbox__ConfigPath`，并避免把 secret 打到命令输出。
因为根脚本仍是实现 owner，诊断输出和 `RecommendedActions` 仍可能显示
`.\run.ps1`、`.\install.ps1` 等 canonical 命令；这些命令是预期输出，且与 wrapper 形式等价。

## 启动 WebUI / Start the WebUI

默认模式会启动本地 WebUI，并加载已安装的本机配置：

```powershell
.\run.ps1
.\scripts\run.ps1
```

等价的显式形式：

```powershell
.\run.ps1 -Mode WebUI -Url 'http://127.0.0.1:18080' -OpenBrowser
```

`StartWebUI` 是给菜单和偏好 verb 的自动化使用的 alias：

```powershell
.\run.ps1 -Mode StartWebUI
.\scripts\run.ps1 -Mode StartWebUI
```

打包/交互场景 / interactive packaging：`StartWebUI` 默认自动打开浏览器，除非显式传入
`-OpenBrowser:$false`。

如果没有已安装本机配置，且解析器原本会回退到 `config\sandbox.example.json`，
普通 `WebUI` / `StartWebUI` / `Analyze` / `Plan` 启动会用中文
`本机配置未就绪` 停止，避免用占位 VM/checkpoint 值启动。开发者确实要使用示例或自定义
config 时，仍可显式传入 `-ConfigPath`。

预览启动 / Preview startup：不构建 payload、不启动 dotnet、不打开浏览器，也不触碰 VM：

```powershell
.\run.ps1 -Mode StartWebUI -WhatIf
```

启动 Web 项目前，`run.ps1` 会设置以下进程级环境值 / process-scoped values：

- `Sandbox__ConfigPath`：来自 `%ProgramData%\KSwordSandbox\install-state.json`、
  当前环境，或 `D:\Temp\KSwordSandbox\config\sandbox.local.json`；
- `ASPNETCORE_URLS`：来自 `-Url`；
- `KSWORDBOX_GUEST_PASSWORD`：若 User/Machine 环境变量存在，会镜像到子进程的
  process scope；
- 可选 `KSWORDBOX_VIRUSTOTAL_API_KEY`：若 User/Machine 环境变量存在，会镜像到子进程的
  process scope。

密码值永不打印；可选 VT key 值也永不打印 / never printed。
WebUI 启动路径只打印简短状态、选定 URL 和修复提示；不会向操作者输出一长串命令墙。

如果请求的 localhost 端口被 Windows/Hyper-V TCP port exclusion 或其他进程占用，
`run.ps1` 会自动 fallback 到附近可用安全端口，并打印最终 WebUI URL。需要端口绑定失败时
立即停止，请使用 `-StrictUrl`。

## 单个 EXE 计划或 Live 运行 / Single EXE plan or live run

只做不修改 VM 的 plan 检查：

```powershell
.\run.ps1 -Mode Plan -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30
```

内置样本的 release shortcut：

```powershell
# PlanOnly 分析 Notepad；不修改 VM。
.\run.ps1 -Mode Analyze -SamplePreset Notepad

# 等价短别名。
.\run.ps1 -Mode Analyze -SamplePath notepad

# 在 git 外发布 harmless sample，然后创建 PlanOnly runbook。
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample

# 等价短别名。
.\run.ps1 -Mode Analyze -SamplePath sample
```

中文提示：上面四条命令都是“一条命令 Analyze notepad/sample”的入口；未加
`-Live` 时只生成计划，不启动、不还原、不停止 Hyper-V VM，也不会执行样本。
`HarmlessSample` 会在 `D:\Temp\KSwordSandbox\samples\...` 或已配置的
`RuntimeRoot` 下发布测试 EXE，输出位于仓库外。

`-Mode Plan` 是 PlanOnly 且不修改 VM：不会启动、还原、停止 VM，也不会复制文件进 VM；
它还会跳过 guest payload preparation。生成的 Hyper-V plan 会记录 missing/stale payload
files，并给出修复建议，例如运行 `.\scripts\Prepare-GuestPayload.ps1 -SelfContained`。

在 elevated shell 中运行单次 live Hyper-V 分析：

```powershell
.\run.ps1 -Mode Analyze -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30 -Live
```

中文护栏：`-Live` 是显式实验室动作，会修改已配置 VM。它不会由
`Test-ReleaseReadiness.ps1`、`package-portable.ps1` 或普通 WebUI 启动自动触发，
也不会替 release notes 自动生成 fresh live evidence。若发布说明要声明当前候选已刷新
live，请先记录 commit、`job id`、运行时间、runtime root 和报告路径；否则写
“本候选未刷新 fresh live evidence”。

内置样本 live 形式：

```powershell
.\run.ps1 -Mode Analyze -SamplePreset Notepad -Live
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample -Live

# Public-MVP live smoke：真实 Notepad 5 秒。
.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
```

Live mode 可能还原/启动/停止已配置 VM，因此需要 installed golden VM/checkpoint、
guest password secret、prepared guest payload，以及你的 lab 所需的真实 R0
`driver.hostDriverPath` / guest test-signing 设置。宿主机必须具备 Hyper-V PowerShell
tools，并在 BIOS/UEFI 启用硬件虚拟化（Intel VT-x / AMD-V）。这与可选的 VirusTotal
hash-only enrichment 无关；VT key 需单独通过
`.\install.ps1 -Mode ConfigureVTKey -PromptVTKey`.

如果省略 `-Live`，`Analyze` 会回退到 PlanOnly 且不修改 VM。这样默认路径不会意外执行样本，
同时真实 live 命令仍保持简短。

`-Live` 成功后，`run.ps1` 会自动对已收集的 job 目录执行
`tools/KSword.Sandbox.PostProcess` 后处理 / post-process。单条命令结束时应得到：

- `runbook-execution.json`
- `guest\<job-id>\events.json`
- `postprocess-result.json`
- `report.json`
- `report.html`
- `report.zh.html`
- `report.en.html`

## 不重跑 VM 的报告重建与 artifact 检查 / Rebuild reports and inspect artifacts without rerunning the VM

live run 结束后，操作者可以重建报告或检查已收集 artifacts；这些命令不会启动、还原、
停止或修改 Hyper-V：

```powershell
# 列出 runtime jobs。
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- list-jobs

# 显示单个 job 摘要。
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- show-job --job-id <job-guid>

# 重建 report.json/report.html/report.zh.html/report.en.html 和 artifact-index.json。
.\scripts\Rebuild-JobReport.ps1 -JobId <job-guid>

# 仅在内存中检查 artifacts，不重写 artifact-index.json。
.\scripts\Inspect-JobArtifacts.ps1 -JobId <job-guid>

# 需要时显式刷新 artifact-index.json。
.\scripts\Inspect-JobArtifacts.ps1 -JobId <job-guid> -WriteIndex
```

中文提示：这些命令只读取已有 job 目录、`events.json`、`driver-events.jsonl`、
`runbook-execution.json`、PCAP 和其他产物；不会重跑样本，也不会操作 VM。
`Rebuild-JobReport.ps1` 会调用 JobTool 的 `rebuild-report`，可在已有
`report.json` 中推断原始样本路径；若样本无法推断，请追加 `-SamplePath`。

JobTool 自动化输出 / automation output：也支持 JSON：

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- inspect-artifacts --job-id <job-guid> --json
.\scripts\Rebuild-JobReport.ps1 -JobId <job-guid> -Json
```

JobTool 项目已构建且排障时想避免隐式 `dotnet run` build，可给 wrapper 传 `-NoBuild`。
所有 JobTool 与 wrapper 输出都应中英友好，并在打印前脱敏 password / API-key / token-like
字段。不要提交重建的 runtime artifacts；job、report、sample、payload binary、VM disk 和
本机 secret 应保留在 `D:\Temp\KSwordSandbox` 或其他 ignored runtime root。

Guest payload 自动准备 / payload readiness：调用 `scripts/Invoke-HyperVE2E.ps1` 前，
`run.ps1` 会检查配置的 `guestPayloadRoot` 下是否已有 Guest Agent/R0Collector payload。
缺失时会调用 `scripts/Prepare-GuestPayload.ps1 -SelfContained`，让新机器无需手工构建 guest
二进制也能走到 Hyper-V 路径。只有在故意测试 planner “缺 payload” 行为时才使用
`-SkipPayloadPreparation`。

真实 R0 配置提示 / R0 readiness：WebUI 或单次分析启动前，`run.ps1` 也会报告 real R0 driver
配置。如果 `driver.enabled=true`、`driver.useMockCollector=false`，但 `driver.hostDriverPath`
为空或不存在，会打印 `R0 warning`：live runbook 无法 stage `.sys`，也无法生成
`install-driver-service`；否则 R0Collector 稍后可能以 `deviceUnavailable` / `win32Error=2`
失败。修复方式是设置
`.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>`，
或仅做 payload-only R0 验证时设置 `driver.useMockCollector=true`，或设置
`driver.enabled=false`。

## 状态 / Status

```powershell
.\run.ps1 -Mode Status
```

`Status` 会报告 repository root、install state、local config、Web URL、runtime root、
secret 是否存在、可选 VirusTotal key 是否存在、VM/checkpoint 是否存在、host
Guest Agent/R0Collector payload 是否存在、R0 driver host-path readiness，以及是否打印
secret 值（应为 `False`）。它还会输出 `RecommendedActions`，用可读文本给出常见缺口修复：

- 缺少 VM：用以下命令记录真实 VM：
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>`;
- 缺少 checkpoint：创建或记录 clean checkpoint；
- 缺少 guest payload：运行
  `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -SelfContained`;
- 缺少 guest password secret：运行 `.\install.ps1 -Mode Install -PromptPassword`，
  或使用 `.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword`
  做 process-only check；
- 请求真实 R0 但没有 `driver.hostDriverPath`：设置 `-DriverHostPath`，
  启用 `driver.useMockCollector=true`，或禁用 `driver.enabled`。

需要更完整且不修改 VM 的 preflight summary：

```powershell
.\run.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` 会打印 daily startup command、`ReadinessCommand`，以及当前 host
是否可见 `dotnet`、Web project、payload-preparation script、Hyper-V E2E script、
local config、guest secret、可选 VirusTotal key、VM、checkpoint 和 payload files。
`CheckEnvironmentStartsVm=False` 且 `PlanOnlyStartsVm=False`；这些路径用于在另一台
developer 电脑尝试 `-Live` 前做安全检查。

release-readiness reviewer 还应在 `Status` / `CheckEnvironment` 输出中查看：

- `GuestPayloadFreshnessReasons`：说明准备好的 Guest Agent/R0Collector payload
  为什么是 fresh、stale 或 missing，并给出 `Prepare-GuestPayload.ps1` 修复命令。
- `VmProfile`：确认未来显式 `-Live` 会使用的本机 VM、checkpoint、guest working
  directory、runtime root、guest payload root 和 driver path。占位/示例值是配置缺口，
  不是 packaging 问题。
- `VirusTotalMissingKeyBehavior`：确认可选 VirusTotal hash-only enrichment 缺失或失败时会
  静默跳过，不污染 job log。这个可选 VirusTotal API key 与 Intel VT-x / AMD-V
  硬件虚拟化无关；后者才是 Hyper-V 宿主前置条件。
- `RequirePayloadForWebUI`：当 release candidate 必须在 payload 缺失时 fail fast，
  而不是继续启动 WebUI，请使用 `.\run.ps1 -RequirePayloadForWebUI`。

排障时按从外到内的顺序看 `RecommendedActions`：先确认宿主 Hyper-V capability
（管理员 PowerShell、Hyper-V module、BIOS/UEFI Intel VT-x / AMD-V、SLAT），再确认
`VmProfile`（VM、checkpoint、guest working directory、runtime root、payload root、
driver path），然后确认 `GuestPayloadFreshnessReasons`。VirusTotal API key 只是可选
hash-only enrichment；它不是 Intel VT-x / AMD-V，缺失不会阻止 Plan/WebUI。

`run.ps1` 支持 `-WhatIf`。在 WebUI 模式下会跳过 payload preparation 和 dotnet startup；
在 `Plan` / `Analyze` 模式下会在委托给 `scripts\Invoke-HyperVE2E.ps1` 之前停止，
因此不会启动 Hyper-V 子脚本。

## 与 install.ps1 的关系 / Relationship with install.ps1

- `install.ps1` 用于一次性本机准备 / one-time local preparation：目录、Hyper-V
  VM/checkpoint config、本地 config 文件、Web/API config 环境变量和 guest password sync。
- `run.ps1` 用于每次启动 / each launch：启动 WebUI，或使用已安装 config 运行/规划一个 EXE。
- `run.ps1` 不会要求你在命令行输入密码；它只把 Process/User/Machine 环境中的已配置 secret
  镜像到子 WebUI 或 Hyper-V 进程，并只报告值是否存在。

Runtime 输出保持在 `D:\Temp\KSwordSandbox`；不要提交生成的 report、sample、payload binary、
VM disk 或本机 secret。

## 便携包一键 WebUI 启动

中文优先：`run.ps1` 现在会自动选择 WebUI 启动目标。源码仓库中优先使用
`src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj`；便携包中如果没有源码项目，则使用
`app\host-web\KSword.Sandbox.Web.exe`，或退回到 `app\host-web\KSword.Sandbox.Web.dll` + `dotnet`。
日常入口仍然是一条命令：

```powershell
.\run.ps1
.\run.ps1 -Mode StartWebUI -OpenBrowser
.\run.ps1 -Mode Status
```

`Status`/`CheckEnvironment` 会展示 `WebUiLaunchKind`、`WebUiLaunchPath`、`PublishedWebAppExists`、
`PortableWebUiReady`、`VmProfile`、`HostTestSigningState`、guest password presence 和 R0 driver
配置状态。缺失本机配置、payload、VM profile、driver path 或 published WebUI 时，先看
`RecommendedActions`；这些检查不会启动、还原或停止 Hyper-V VM。

便携包运行要求：

- `install.ps1`/`run.ps1` 位于包根目录，`scripts\run.ps1` 只是等价 wrapper。
- `app\host-web` 来自外部发布目录，不从仓库 `bin/`、`obj/`、`x64/` 复制。
- `packaging\runtime-package.manifest.json` 和 `packaging\README.md` 会随 runtime
  包一起进入包内，便于审阅 portable layout 与禁止项；真实发布 payload 的
  来源仍只允许是仓库外 `RuntimePublishRoot`。完整 handoff 包应由
  `package-portable.ps1 -RequireCompleteRuntimePayloads` 生成；否则只视为
  layout/safety dry-run。
- 包根的 `package-manifest.generated.json` 是本次 staging 的审计索引，包含
  文件 hash/size、git revision、runtime publish root、跳过的可选 payload
  和安全合约。排障时先看这个文件里的 generated `reviewerChecklist`、
  `sourceRuntimeSafetyMetadata`、`gapAudit`、`runtimePublishSummary.incompleteCount`、
  expected leaf gaps、forbidden-file previews，再看 `Status`/`CheckEnvironment`。
- 本机 `sandbox.local.json`、guest password、VT key、样本、报告和 VM 输出继续保存在 runtime root
  或 Windows 环境/DPAPI 中，不进入 zip。
- 默认 WebUI 不执行 Live；Live Hyper-V 仍必须在 WebUI/API 或 CLI 中显式选择。

### 发布 smoke 场景边界 / Release smoke boundaries

发布 smoke 边界 / release smoke boundaries：默认只接受低副作用场景，例如 PowerShell parse、
repository policy、source package `-StageOnly` dry-run，以及带仓库外 `RuntimePublishRoot`
的完整性检查。`release-readiness.json.componentProgress` 会把这些场景标记为
`documented-low-cost-only`；`release-readiness.json.gapAudit` 使用
`ksword.release.gap-audit.v28`，会机器可读地列出 no fresh live evidence、
RuntimePublishRoot completeness、no VM mutation/no signing `guardrailResults`、
self-noise guard readiness 和 component progress。Runtime handoff 还要查看
`runtimePublishRootDiagnostics` / `runtimeCompletenessDiagnostics`：root 必须在仓库外，
`summary.missingCount = 0`、`summary.incompleteCount = 0`、`summary.forbiddenFileCount = 0`，
且 `handoffAllowed = true`。任何 `-Live` Notepad 5s、真实 R0、Hyper-V VM mutation
或 heavy E2E 都必须由 release manager 在 lab host 显式运行，并记录 `job id`、commit、runtime root、
生成时间和报告路径；否则 release notes 写“本候选未刷新 fresh live evidence”。

自噪声护栏 / self-noise guard 只做静态/readiness 审计：采集器自噪声、collection-health、
VT 静默状态 / VT quiet state、`behaviorCounted=false`、R0 health/noise 行必须留在证据质量通道，不得被写成样本行为。
如果 `gapAudit.selfNoiseGuardReadiness` 失败，先修复规则 guard 和报告/文档降噪说明；不要在
run/package/readiness 阶段临时补跑 smoke、Hyper-V live 或 CSignTool。
