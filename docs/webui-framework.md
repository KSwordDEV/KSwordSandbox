# WebUI 框架暂存 / WebUI framework staging

本文说明 Web 项目的暂存分层：目标是逐步把 endpoint 与 dashboard 逻辑从
`Program.cs` 拆出。多数 endpoint 模块仍是被动暂存，但根 WebUI 已由
`Dashboard/DashboardExperiencePage.cs` 渲染，因此操作者体验可以在
Dashboard 层迭代，而不触碰 Core、Driver 或 Guest 代码。

权威交叉链接：报告/UI 呈现看 `docs/report-ux.md`，报告数据结构看
`docs/report-schema.md`，artifact 下载 selector 看 `docs/artifact-manifest.md`，
VirusTotal hash-only 行为看 `docs/virustotal.md`，可重复验证命令看
`docs/verification.md`。测试 WebUI 时产生的 runtime 报告、原始事件、上传样本、
payload 二进制、浏览器截图、VM 输出或构建产物都不要提交。

## 写入边界 / Write boundary

Worker-Web 变更仅限：

- `src/KSword.Sandbox.Web/Contracts/**`
- `src/KSword.Sandbox.Web/Dashboard/**`
- `src/KSword.Sandbox.Web/Endpoints/**`
- `src/KSword.Sandbox.Web/Infrastructure/**`
- `src/KSword.Sandbox.Web/Program.cs`：路由接线和 Web-only 错误文案
- `docs/webui-framework.md`

WebUI/UX 工作不得修改 `driver/`、`guest/` 或
`src/KSword.Sandbox.Core/` 文件。

## 分层职责 / Layer responsibilities

- `Contracts`：命名 API payload records，用于在 endpoint 逐步移出
  `Program.cs` 时替代匿名响应对象。
- `Infrastructure`：Web 专属的小型 helper，包括时钟、请求关联、
  problem responses、validation errors、route constants、content types 和
  文件名规范化。
- `Endpoints`：route-module 描述、集合排序、DI 注册 helper，以及
  Dashboard、Health、Files、Jobs、Runbooks 等功能区模块。
- `Dashboard`：服务端渲染 HTML 组件原语、文档组合、导航、状态 badge、
  根体验页，以及用于可复制 dashboard 值的标准右键复制脚本。

## WebUI 体验契约 / WebUI experience contract

根 dashboard 默认中文（`zh-CN`），右上角保留醒目的语言切换。首次访问打开
中文体验；如果操作者切换到英文，浏览器本地选择会复用到下一次修改。

根 dashboard 是短路径操作者入口（operator launcher），只应保留以下可见且
可复制区域：

- 首屏必须像成熟云沙箱的 cockpit：顶部先说明“上传后自动进 VM”，再展示可复制的
  readiness chips。chips 至少覆盖样本选择状态、VM/checkpoint、Guest 密钥环境变量名、
  R0 real/mock/config 状态、VirusTotal hash-only quiet 状态，以及本次敏感产物采集摘要。
  chip 只表达“可见配置/等待后端预检”，不能伪造 Hyper-V live readiness。
- `上传 EXE` 默认面板应提供清晰 primary CTA：`开始分析：上传 → 进 VM → 打开实时监控`。
  选择样本前显示空态；选择后显示文件名、大小、分析时长、扩展名检查和 artifact 采集摘要。
  可选运行预设（例如快速观察、标准动态、证据优先、内存取证）只能修改当前表单字段，不写配置。
  拖拽上传区、样本摘要、预设按钮、状态文本和错误提示都必须支持右键复制。
  主按钮附近必须保留可复制的 one-click handoff 提示，明确
  `/api/files/upload/start` 会保存样本、创建 job、提交后台 VM 分析，并将当前浏览器页
  导航到 `/jobs/{jobId}/live-events`；英文契约必须明确写作 redirect the current browser page to
  `/jobs/{jobId}/live-events`，并说明 no popup or extra dashboard tab is required；上传中、启动接受或预检失败时，该提示应更新为
  可复制的 job/monitor/progress 摘要。
- 顶层工作区分为 `上传 / 配置`、`进度`、`报告` 三个 tab。上传/配置 tab
  是 default selected tab；上传/启动成功后按需切换到进度/报告区域；报告
  就绪通知必须在自动打开报告前显示。报告主链接必须跟随 current Chinese/English
  dashboard language，并保留中文/英文备用入口。
- 上传/配置工作区内部按用户输入方式再分为三种 submission tabs：
  `上传 EXE`、`选择已有路径`、`扫描目录`。上传 EXE 是默认选中的短路径，
  会在 `.exe` 保存后创建计划、提交后台 VM 分析，并把当前页面跳到 live
  monitor；host-path planning 和 directory scan 只生成可复核计划，不展示
  runbook 命令长列表。
- VM 配置字段（VM configuration fields）在上传前可见，并随每次 dry-run 或一键 upload/start planning request
  提交：`goldenVmName`、`goldenSnapshotName`、`durationSeconds`、
  `guestUserName`、`guestWorkingDirectory`、`guestPayloadRoot` 和
  `useMockCollector`。UI 只展示 Guest 凭据提示，不要求操作者输入密码；凭据仍由
  Web host 从配置的 secret 环境变量解析。R0 `driver.enabled` 仍是 Core 配置开关；
  WebUI 只读展示该状态，并保留每任务 real-vs-`useMockCollector` 覆盖，不改变 Core
  业务逻辑。
- 敏感产物采集字段为显式启用（opt-in），随每次 dry-run planning request
  提交并保存在 job submission 中：`collectDroppedFiles`、`captureScreenshots`、
  `captureMemoryDumps` 和 `capturePacketCapture`。默认禁用；只有配置显式启用或
  WebUI 勾选时才打开。runbook 转发给 Guest Agent 的参数为
  `--collect-dropped-files`、`--screenshot`、`--memory-dump` 和
  `--packet-capture`。
  Upload UI 必须先读取当前 `/api/config` 的 `artifactCollection` shape；
  当前配置/Runbook 未暴露的 lane 在页面中保持禁用和可复制说明，不向
  upload/start 表单提交 phantom 字段。截图、内存转储和 PCAP 仍是高级显式
  opt-in，内存转储文案需说明“样本进程，支持时包含子进程”。
- 明确展示任务状态、任务 ID、样本路径、近期任务列表、进度页入口、实时监控入口和报告入口。
- 可选高级手动 guest import input 只用于修复。根 dashboard 不再渲染
  artifact/download 路径表；报告与证据下载统一集中在 live monitor。
- 操作者可见结果文件使用证据索引（artifact index）和下载端点（download endpoints）：
  `GET /api/jobs/{jobId}/artifacts` 返回当前宿主侧 `artifact-index` 视图；
  `GET /api/jobs/{jobId}/artifacts/download?path=<relative>` 只流式返回该索引中存在的文件。
  下载 path 必须是规范化的 relative/safe-link 值，绝不能是任意宿主绝对路径。
  `GET /api/jobs/{jobId}/report/{relativeArtifactPath}` 复用同一个受保护 resolver，
  使 served HTML report 内的链接可以打开 `events.json`、`driver-events.jsonl`、
  落地文件、截图、内存转储或 PCAP 证据，而不把本地文件系统路径暴露给浏览器；
- 计划创建后自动给出报告链接，包括 served `/api/jobs/{jobId}/report/html` 链接。
  手动报告按钮必须跟随当前中文/英文 dashboard 语言，同时保留紧凑 `zh` / `en` 备选入口，
  避免操作者手动粘贴报告路径。完成后自动导航默认使用中文报告端点
  `/api/jobs/{jobId}/report/html?lang=zh`，解析到 `report.zh.html`。如果报告路径尚不可用，
  主按钮必须显示禁用/等待状态，而不是跳到可能的 404；
- 阶段进度（stage progress）必须展示有序且用户可理解的阶段：`启动 VM`、
  `部署 Payload`、`执行样本`、`收集结果`、`生成报告`，并保留稳定 ID 和
  人类可读状态。进度卡片还必须在主 dashboard 直接展示当前步骤、已耗时和失败原因
  （current step, elapsed time, and failure reason），
  让操作者无需展开高级详情也能判断运行是否推进。较长的 Hyper-V restore/start 阶段即使
  executor step 尚未前进，也应保持可见运行/脉冲状态。
- 真实 executor 进度来自 `GET /api/jobs/{jobId}/runbook/progress`：当
  `/runbook/start` 已接受后台运行，或工具仍使用 legacy executor path 时可读取。
  该端点由 `RunbookProgressStore` 支撑，通过 executor `ProgressSink` 接收
  `SandboxRunbookProgressSnapshot`，把同一份 UI-safe 快照写入持久化
  `runbook-progress.json`，并返回最新 durable/in-memory 快照，避免刷新或另一个
  Web worker 退回假进度。进度快照有意省略 PowerShell 命令文本、标准输出
  `stdout` 和标准错误 `stderr`；
- 实时 VM 分析应通过服务端后台路径启动：
  `POST /api/jobs/{jobId}/runbook/start` 接受任务后立即返回；
  `GET /api/jobs/{jobId}/runbook/background` 暴露 queued/running/completed/failed
  状态以及终端执行/导入结果。legacy blocking `/runbook/execute` endpoint 仍可供工具使用，
  但浏览器体验不得依赖一个长 fetch 持续存活；
- 上传流程应保持一键（one-click）：`.exe` 上传并保存后创建 plan，dashboard 必须把实时
  VM analysis 提交给 Web host background runner，并将当前浏览器页重定向到
  `/jobs/{jobId}/live-events`，不需要弹窗或额外 dashboard tab。动态监控页（dynamic monitor）
  是操作者查看真实 runbook 进度、原始事件、VirusTotal 状态和证据/下载卡片的主入口。
  首选 API 路径是
  `POST /api/files/upload/start`，它在一个服务端操作中保存上传、创建 job、提交后台
  runbook 执行，避免早期三段请求链（`upload` -> `plan` -> `runbook/start`）在浏览器
  fetch 中途失败时丢失上下文；
- VirusTotal 官方结果集成为可选、仅 hash 查询。操作者可以打开 `/settings` 保存或清除
  本地 API key，并管理浏览器本地 VM WebUI 预设（VM 名称、checkpoint、duration、
  Guest user hints、real/mock R0 collector mode 和 artifact opt-in toggles）。
  VM 预设只保存在浏览器 `localStorage`，在 upload page 上作为 per-job override；
  不会写入 `config/*.json`、Core、Driver 或 Guest 文件。Key 优先从
  `KSWORDBOX_VIRUSTOTAL_API_KEY` 读取，也可来自 settings 页的 process-local 更新；
  WebUI 不得把 API key 写入 repo、config 或 runtime 文件。Job 页提供
  `GET /api/jobs/{jobId}/virustotal`，使用 `x-apikey` 查询官方 v3 `files/{sha256}`
  endpoint，不上传样本；缺失或不可用时返回静默 `not_configured` / `lookup_failed`
  状态，而不是中断分析。缺失 API key 应保持为带设置链接的静默 UI 状态，
  不应成为重复 warning/noisy log 或自动 report-enrichment write；
  live monitor 的 VirusTotal 卡片必须中文优先地区分 `官方已收录 / found` 与
  `静默状态 / quiet state`：found 是官方信誉信号，仍以本地沙箱报告为准；quiet
  明确“不阻断分析、不写任务/行为日志”。这些状态必须可右键复制。
- 提供专用实时原始事件监控页（dedicated live raw monitor page / dynamic monitor page）
  链接，用于在最终报告 classification 前展示 source files 和未归类 raw event rows。若页面由 upload 自动打开，
  Web host 已经接受后台运行，原 dashboard 页不必继续打开。Monitor 页还应轮询
  `GET /api/jobs/{jobId}/runbook/progress`，只展示界面安全的 runbook step 状态、
  当前步骤和进度百分比，不内联命令行、`stdout` 或 `stderr`。
  如果 `/runbook/background` 上存在终端执行结果，per-step `stdout`/`stderr` 只能放在折叠的
  排障 `<details>` 中；命令行仍保持隐藏。页面也轮询
  `GET /api/jobs/{jobId}/runbook/background`，以便主 dashboard tab 在后台任务接受后关闭时，
  monitor 仍能显示终态 completed/failed 状态和报告链接。上传启动的 monitor
  会在完成后先显示短“报告已就绪”通知，再自动导航到中文报告
  `/api/jobs/{jobId}/report/html?lang=zh`（`report.zh.html`）。操作者仍可使用右上角语言切换
  和显式英文报告按钮进入英文报告；
- 动态监控页（dynamic monitor page）应优先服务真实产品使用，而不只服务 smoke 覆盖；页面展示
  **证据 / 下载** 卡片面板。面板列出
  `report.html`、`report.zh.html`、`report.en.html`、`report.json`、`events.json`、
  `driver-events.jsonl`、落地文件、截图、内存转储和 PCAP packet captures。
  如果存在安全 Web endpoint（包括 `/api/jobs/{jobId}/artifacts/download?path=<relative>`
  或 served report endpoint），卡片应渲染双语打开/下载按钮。没有下载 endpoint 的证据，
  应显示可复制 host path 或 derived expected path，并显示双语 `等待回收` / `waiting for collection`
  状态，而不是隐藏该 lane。同一 monitor 应突出展示 VirusTotal 结果，并清晰区分
  恶意/可疑/无害/缺失/未配置状态；后台运行进入 terminal state 后，
  仍保持显式中文和英文报告按钮可见；
  Monitor 还应提供“刷新证据/下载卡片”手动入口，并为每张卡片提供右键复制和显式
  `复制卡片摘要` / `复制 selector` / `复制下载链接` affordances，方便值守人员不打开
  host 路径即可传递安全 selector 或 endpoint。
  每张证据卡还应显示 copyable artifact lane readiness，例如“安全端点可用”、
  “索引已记录，可复制 selector/状态”或“等待回收”，让操作者不用展开详情也能判断该 lane
  是否可交付。
- 为 runbook step status 提供自然的进度页链接，指向 dedicated execution-flow page，
  并同时出现在任务操作与进度摘要中。该入口在 UI 文案中称为 progress-page link，
  让操作者自然进入 execution-flow 诊断页，而不是在 dashboard 内展开命令墙。
  根 dashboard 不得内联长 runbook PowerShell commands、command-line details、`stdout`、
  `stderr`、raw event rows 或 artifact/download lists。近期任务卡应保持紧凑，
  只展示状态、报告就绪度、`执行流程 / Execution flow` 链接，以及用于技术跟进的
  实时监控/下载入口。

所有表格、路径值、原始遥测证据、任务消息、状态文本、输入框
和 section text 都必须支持显式 `复制 / Copy` 按钮，或通过 `data-copy`、
`code`、`pre`、`td`、`th`、`p`、`li`、heading、`label`、`span`、`a`、
`button`、`input` 元素支持右键复制（right-click copy）。复制成功或失败后 WebUI 应显示小
toast，告知操作者剪贴板捕获是否成功。
`/settings` 的 VirusTotal、VM、Guest、R0/artifact 重要卡片也必须有卡片级复制摘要；
输入框、toggle card、source/mask/path/status 值既可右键复制，也应保留显式复制按钮或
可复制摘要按钮。

Guest 导入状态应具体且中文优先：

- `等待导入 / waiting for import`：job 已有 report paths，但尚无 imported
  event source。
- `已导入 / imported`：已记录 `events.json` 或 JSONL source path。
- `已导入（无事件） / imported empty`：导入技术上成功，但未发现 guest
  events。
- `导入失败 / import failed`：job messages 表明 guest output 缺失或无法导入。

导入操作应允许可选的显式 `events.json` / `.jsonl` path。字段留空时，endpoint
搜索确定性的 job guest folder。这样既保持 one-click 路径简短，又在 guest
collection artifacts 落在其他位置时给操作者修复路径。

客户端错误（client-side errors）应保留失败动作、HTTP status、server detail，以及存在
时的 trace/request ID。示例（中文优先，保留英文动作上下文）：
`生成 dry-run 分析计划失败 (HTTP 400 Bad Request，跟踪 ID <trace>): Dry-run plan could not be created: <specific path validation detail>`。

## 迁移路径 / Migration path

1. Web 项目导入 endpoint namespace 后，添加
   `builder.Services.AddSandboxWebEndpointModules()`。
2. 用下列模块映射替换现有内联 `app.MapGet` / `app.MapPost` blocks：
   `app.MapSandboxEndpointModules(app.Services.GetServices<IWebEndpointModule>())`。
3. 一次只迁移一个功能区：
   - health 和 config responses；
   - file scan 与 upload endpoints；
   - job list/detail/live-event endpoints；
   - runbook execution 与 guest import endpoints；
   - dashboard HTML rendering。
4. 响应 shape 稳定后，用 `Contracts` records 替代 anonymous objects。
5. 任何接触 filesystem paths 的 endpoint 都必须放在显式 Infrastructure helpers 后面，
   防止浏览器输入选择任意 host paths。

## Dashboard 约定 / Dashboard conventions

Dashboard components 只渲染本地拥有的 HTML fragments。普通文本必须经过
`DashboardHtml.Encode` 或 `DashboardHtml.Attribute`。当文本、徽章、卡片
或未来表格中的值需要复制时，使用 `data-copy` attribute 渲染，使标准
右键复制脚本（context-copy script）能一致处理复制行为。

敏感产物采集控制必须位于高级/显式启用（advanced/explicit opt-in）区域。UI
可从以下配置预勾选：
`config.artifactCollection.collectDroppedFiles`、
`config.artifactCollection.captureScreenshots`、
`config.artifactCollection.captureMemoryDumps` 和
`config.artifactCollection.capturePacketCapture`，但操作者必须能在规划前按 job 覆盖。
任务卡只汇总请求了哪些证据 lane，不暗示证据已经存在。

VM 控件（VM controls）应保持面向操作者但紧凑：VM 名称、checkpoint、分析时长、Guest
用户/工作目录提示、R0 配置状态、real/mock collector mode 和 artifact toggles
都在上传页以方角扁平卡片展示。`/settings` 可以把同一组值保存为浏览器本地预设，
减少重复输入，但该预设不是 Core configuration writer。主 dashboard 必须继续避免
命令墙：进度卡和任务卡汇总人类可读状态，并链接到专用 execution-flow page 做深入诊断，
而不是内联长命令或进程输出。

当 JavaScript 渲染动态表格行时，每个路径或证据单元格应调用本地
copy-button helper，或把 `data-copy` 设置为原始值。对于 planned jobs，UI
可从记录的 job root 推导预期 guest paths：`guest\<job-id-n>\events.json`
和
`guest\<job-id-n>\driver-events.jsonl`。这些派生路径只是显示提示；导入 endpoint
仍在服务端解析真实文件。

当前根页面也从 `/api/jobs` 渲染紧凑近期任务卡。这些卡片刻意只读：
`打开 / Open` action 获取所选 job detail 并复用主 job panel；证据/下载
渲染保留在 `/jobs/{jobId}/live-events`。

## 运行时 WebUI 可选 smoke / Optional runtime WebUI smoke

常规 smoke 路径是静态门禁（static gate）：检查 source、script 与
documentation contracts，不启动浏览器，也不修改 runtime artifacts。Web host
或真实浏览器无法启动时使用：

```powershell
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj
.\scripts\Test-LiveTelemetryFramework.ps1 -ContractOnly
```

当 Web host 已运行且已有 planned/live job ID 时，运行 smoke project 前设置：

```powershell
$env:KSWORD_SMOKE_BASE_URL = 'http://127.0.0.1:5000'
$env:KSWORD_SMOKE_JOB_ID = '<existing-job-guid>'
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj
```

运行时 WebUI smoke contract 刻意保持 API-level，便于 headless workers 运行。
它探测：

- `GET /jobs/{jobId}/live-events`：要求返回成功的 `text/html` 页面，页面包含实时原始监控标题，
  并引用两种 raw event transport；
- `GET /api/jobs/{jobId}/events/live?offset=0&take=1`：要求返回实时原始遥测 JSON cursor 字段：
  `jobId`、`retrievedAt`、`totalEvents`、
  `nextOffset`、`hasMore`、`sources` 和 `events`；
- root dashboard source 必须链接到专用实时原始监控页（live raw monitor page）；
- `GET /api/jobs/{jobId}/report/html`：要求返回成功的 `text/html` served report response，
  也就是 dashboard 渲染的同一个安全报告链接；
- 双语报告端点 `GET /api/jobs/{jobId}/report/html?lang=zh` 与
  `GET /api/jobs/{jobId}/report/html?lang=en` 都应从记录的 job report path 返回
  `text/html`；只有没有记录本地化报告文件时才回退到兼容 `report.html`；
- `POST /api/jobs/{jobId}/guest-events/import` 携带显式缺失的 `eventsPath` 时，
  要求返回受控 HTTP 400 validation response。这样可证明手动 guest import endpoint
  与 payload contract，而不在 smoke 中导入或重写真实 guest artifacts。

当省略 `-BaseUrl` 和 `-JobId` 时，PowerShell gate 也接受同一组环境变量：

```powershell
.\scripts\Test-LiveTelemetryFramework.ps1 -UsePollingFallback
```

端到端操作者验证：启动 Web host 后创建或选择一个 job，手动在浏览器打开
dashboard，并确认 served HTML report link 可打开、live raw monitor page 通过
SSE 或 polling 刷新、monitor 显示证据/下载卡片、中文报告 endpoint
`/api/jobs/{jobId}/report/html?lang=zh` 与英文报告 endpoint
`/api/jobs/{jobId}/report/html?lang=en` 都返回 HTML、upload 启动后的完成流程
会导航到中文报告（`report.zh.html`），并且根 dashboard 不展示长 runbook command/output blocks
或 artifact/download lists。可选手动 guest import 字段可以留空，也可以填写具体
`events.json` / `.jsonl` path。不要提交该验证生成的报告、导入的 guest output、
浏览器截图或构建二进制。

## 验证指引 / Verification guidance

为避免验证时修改仓库内 `bin/` 或 `obj/` 目录，构建 Web project 时请把
`BaseIntermediateOutputPath`、`BaseOutputPath`、`RestorePackagesPath` 重定向到
仓库外临时目录。
