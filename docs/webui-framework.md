# WebUI 框架暂存 / Web UI framework staging

本文说明 Web 项目的暂存分层：目标是逐步把 endpoint 与 dashboard 逻辑从
`Program.cs` 拆出。多数 endpoint 模块仍是被动暂存，但根 WebUI 已由
`Dashboard/DashboardExperiencePage.cs` 渲染，因此操作者体验可以在
Dashboard 层迭代，而不触碰 Core、Driver 或 Guest 代码。

中文说明：本文描述 Web 项目的 staged layout，用于逐步把 endpoint 和 dashboard
逻辑从 `Program.cs` 拆出。

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
- `src/KSword.Sandbox.Web/Program.cs` for route wiring and Web-only error text
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

- 顶层工作区分为 `上传 / 配置`、`进度`、`报告` 三个 tab。上传/配置 tab
  是 default selected tab；上传/启动成功后按需切换到进度/报告区域；报告
  就绪通知必须在自动打开报告前显示。
- 上传/配置工作区内部按用户输入方式再分为三种 submission tabs：
  `上传 EXE`、`选择已有路径`、`扫描目录`。上传 EXE 是默认选中的短路径，
  会在 `.exe` 保存后创建计划、提交后台 VM 分析，并把当前页面跳到 live
  monitor；host-path planning 和 directory scan 只生成可复核计划，不展示
  runbook 命令长列表。
- VM configuration fields 在上传前可见，并随每次 dry-run 或 one-click
  upload/start planning request 提交：`goldenVmName`,
  `goldenSnapshotName`, `durationSeconds`, `guestUserName`,
  `guestWorkingDirectory`, `guestPayloadRoot`, and `useMockCollector`. The UI
  shows a Guest credential hint instead of asking for a password: credentials
  are still resolved from the configured secret environment variable by the Web
  host. R0 `driver.enabled` remains a config-level Core switch; the WebUI shows
  that state read-only and exposes the existing per-job
  real-vs-`useMockCollector` override without changing Core business logic;
- 敏感产物采集字段为显式启用（opt-in），随每次 dry-run planning request
  提交并保存在 job submission 中：`collectDroppedFiles`,
  `captureScreenshots`, `captureMemoryDumps`, and `capturePacketCapture`. These
  are disabled by default unless explicitly enabled in config or checked in the
  WebUI, and the runbook forwards them to the Guest Agent as
  `--collect-dropped-files`, `--screenshot`, `--memory-dump`, and
  `--packet-capture`;
- 明确展示 job status、job ID、sample path、recent job list、progress-page
  entry、live-monitor entry 和 report entry。
- 可选高级手动 guest import input 只用于修复。根 dashboard 不再渲染
  artifact/download 路径表；报告与证据下载统一集中在 live monitor。
- 操作者可见结果文件使用 artifact index 和 download endpoints：
  `GET /api/jobs/{jobId}/artifacts` 返回当前宿主侧 `artifact-index` 视图；
  `GET /api/jobs/{jobId}/artifacts/download?path=<relative>` 只 stream 该索引中存在的文件。
  下载 path 必须是规范化的 relative/safe-link 值，绝不能是任意宿主绝对路径。
  `GET /api/jobs/{jobId}/report/{relativeArtifactPath}` 复用同一个受保护 resolver，
  使 served HTML report 内的链接可以打开 `events.json`、`driver-events.jsonl`、
  dropped files、screenshots、memory dumps 或 PCAP artifacts，而不把本地文件系统路径暴露给浏览器；
- 计划创建后自动给出报告链接，包括 served
  `/api/jobs/{jobId}/report/html` link. Manual report buttons follow the
  current Chinese/English dashboard language, while compact `zh` / `en` alternatives
  remain visible so operators never need to paste a report path. Automatic
  completion navigation defaults to the Chinese report endpoint
  `/api/jobs/{jobId}/report/html?lang=zh`, which resolves to `report.zh.html`.
  If no report path is available yet, the main button must be visibly
  disabled/pending instead of navigating to a likely 404;
- stage progress 必须展示有序且用户可理解的阶段：`启动 VM`、
  `部署 Payload`、`执行样本`、`收集结果`、`生成报告`，并保留稳定 ID 和
  human-readable status。进度卡片还必须在主 dashboard 直接展示
  current step, elapsed time, and failure reason，让操作者无需展开高级详情也能判断
  运行是否推进。较长的 Hyper-V restore/start 阶段即使 executor step 尚未
  前进，也应保持可见 running/pulse 状态。
- 真实 executor 进度来自
  `GET /api/jobs/{jobId}/runbook/progress` after `/runbook/start` accepts a
  background run or when tooling uses the legacy executor path. The endpoint is
  backed by `RunbookProgressStore`, receives `SandboxRunbookProgressSnapshot`
  values through the executor `ProgressSink`, writes the same UI-safe snapshot
  to durable `runbook-progress.json`, and returns the newest durable/in-memory
  snapshot so refreshes or another Web worker do not regress to fake progress.
  Progress snapshots intentionally omit PowerShell command text, `stdout`, and
  `stderr` from the main dashboard;
- live VM analysis 应通过服务端 background path 启动：
  `POST /api/jobs/{jobId}/runbook/start` returns immediately after accepting
  the job, and `GET /api/jobs/{jobId}/runbook/background` exposes queued,
  running, completed, or failed state plus the terminal execution/import result.
  The legacy blocking `/runbook/execute` endpoint remains available for tools,
  but the browser experience must not depend on one long fetch staying alive;
- 上传流程应保持 one-click：`.exe` 上传并保存后创建 plan，dashboard 必须把 live VM
  analysis 提交给 Web host background runner，并将当前浏览器页重定向到
  `/jobs/{jobId}/live-events`。动态监控页（dynamic monitor）是操作者查看真实
  runbook 进度、原始事件、VirusTotal 状态和 artifact/download 卡片的主入口；
  不需要 popup 或额外 dashboard tab。首选 API 路径是
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
  endpoint，不上传样本；缺失或不可用时返回 quiet `not_configured` / `lookup_failed`
  状态，而不是中断分析。缺失 API key 应保持为带 settings 链接的 quiet UI 状态，
  不应成为重复 warning/noisy log 或自动 report-enrichment write；
- 提供 dedicated live raw monitor page / dynamic monitor page 链接，用于在最终报告
  classification 前展示 source files 和未归类 raw event rows。若页面由 upload 自动打开，
  Web host 已经接受后台运行，原 dashboard 页不必继续打开。Monitor 页还应轮询
  `GET /api/jobs/{jobId}/runbook/progress`，只展示 UI-safe 的 runbook step state、
  current step 和 progress percentage，不内联 command lines、`stdout` 或 `stderr`。
  如果 `/runbook/background` 上存在终端执行结果，per-step `stdout`/`stderr` 只能放在折叠的
  troubleshooting `<details>` 中；command lines 仍保持隐藏。页面也轮询
  `GET /api/jobs/{jobId}/runbook/background`，以便主 dashboard tab 在后台任务接受后关闭时，
  monitor 仍能显示 terminal completed/failed state 和报告链接。Upload-launched monitor
  会在完成后先显示短 report-ready notice，再自动导航到中文报告
  `/api/jobs/{jobId}/report/html?lang=zh`（`report.zh.html`）。操作者仍可使用右上角语言切换
  和显式英文报告按钮进入英文报告；
- dynamic monitor page 应优先服务真实产品使用，而不只服务 smoke 覆盖；页面展示
  **证据 / 下载（Artifacts / downloads）** 卡片面板。面板列出
  `report.html`、`report.zh.html`、`report.en.html`、`report.json`、`events.json`、
  `driver-events.jsonl`、dropped files、screenshots、memory dumps 和 packet captures。
  如果存在安全 Web endpoint（包括 `/api/jobs/{jobId}/artifacts/download?path=<relative>`
  或 served report endpoint），卡片应渲染双语打开/下载按钮。没有 download endpoint 的证据，
  应显示可复制 host path 或 derived expected path，并显示双语 `等待回收` / `waiting for collection`
  状态，而不是隐藏该 lane。同一 monitor 应突出展示 VirusTotal 结果，并清晰区分
  malicious/suspicious/clean/missing/not-configured 状态；后台运行进入 terminal state 后，
  仍保持显式中文和英文报告按钮可见；
- 为 runbook step status 提供自然的 progress-page link，指向 dedicated
  execution-flow page，并同时出现在 job actions 与 progress summary 中。
  根 dashboard 不得内联长 runbook PowerShell commands、command-line details、`stdout`、
  `stderr`、raw event rows 或 artifact/download lists。Recent job cards 应保持紧凑，
  只展示 status、report readiness、`执行流程 / Execution flow` 链接，以及用于技术跟进的
  live monitor/download 入口。

所有表格、路径值、raw telemetry evidence、job messages、status text、inputs
和 section text 都必须支持显式 `复制 / Copy` 按钮，或通过 `data-copy`、
`code`、`pre`、`td`、`th`、`p`、`li`、heading、`label`、`span`、`a`、
`button`、`input` 元素支持右键复制（right-click copy）。复制成功或失败后 WebUI 应显示小
toast，告知操作者剪贴板捕获是否成功。

Guest import status 应具体且中文优先：

- `等待导入 / waiting for import`：job 已有 report paths，但尚无 imported
  event source。
- `已导入 / imported`：已记录 `events.json` 或 JSONL source path。
- `已导入（无事件） / imported empty`：导入技术上成功，但未发现 guest
  events。
- `导入失败 / import failed`：job messages 表明 guest output 缺失或无法导入。

导入操作应允许可选的显式 `events.json` / `.jsonl` path。字段留空时，endpoint
搜索确定性的 job guest folder。这样既保持 one-click 路径简短，又在 guest
collection artifacts 落在其他位置时给操作者修复路径。

Client-side errors 应保留 failing action、HTTP status、server detail，以及存在
时的 trace/request ID。示例（中文优先，保留英文动作上下文）：
`生成 dry-run 分析计划失败 (HTTP 400 Bad Request，跟踪 ID <trace>): Dry-run plan could not be created: <specific path validation detail>`。
English reference: `Create dry-run analysis plan failed (HTTP 400 Bad Request):
Dry-run plan could not be created: <specific path validation detail>`.

## 迁移路径 / Migration path

1. Add `builder.Services.AddSandboxWebEndpointModules()` after the Web project
   imports the endpoint namespace.
2. Replace the existing inline `app.MapGet` / `app.MapPost` blocks with
   `app.MapSandboxEndpointModules(app.Services.GetServices<IWebEndpointModule>())`.
3. Move one feature area at a time:
   - health and config responses,
   - file scan and upload endpoints,
   - job list/detail/live-event endpoints,
   - runbook execution and guest import endpoints,
   - dashboard HTML rendering.
4. Replace anonymous objects with `Contracts` records where response shape is
   stable.
5. Keep any endpoint that touches filesystem paths behind explicit
   Infrastructure helpers so browser input cannot select arbitrary host paths.

## Dashboard 约定 / Dashboard conventions

Dashboard components 只渲染本地拥有的 HTML fragments。普通文本必须经过
`DashboardHtml.Encode` 或 `DashboardHtml.Attribute`。当文本、badges、cards
或未来表格中的值需要复制时，使用 `data-copy` attribute 渲染，使标准
context-copy script 能一致处理右键复制（right-click copy）行为。

敏感产物采集控制必须位于高级/显式启用（advanced/explicit opt-in）区域。UI
可从以下配置预勾选：
`config.artifactCollection.collectDroppedFiles`,
`config.artifactCollection.captureScreenshots`,
`config.artifactCollection.captureMemoryDumps`, and
`config.artifactCollection.capturePacketCapture`, but operators must be able to
override them per job before planning. The job card should summarize which
lanes were requested without implying that artifacts already exist.

VM controls should remain operator-facing but compact: VM name, checkpoint,
analysis duration, Guest user/working-directory hints, R0 config state,
real/mock collector mode, and artifact toggles are shown in square, flat cards
on the upload page. `/settings` may save the same values as a local browser
preset so repeated jobs do not require retyping, but the preset is not a Core
configuration writer. The main dashboard must continue to avoid a command-line
wall: progress cards and job cards summarize human-readable state and link to
the dedicated execution-flow page for deeper diagnostics instead of inlining
long commands or process output.

当 JavaScript 渲染动态表格行时，每个 path 或 evidence cell 应调用本地
copy-button helper，或把 `data-copy` 设置为 raw value。对于 planned jobs，UI
可从 recorded job root 推导预期 guest paths：`guest\<job-id-n>\events.json`
和
`guest\<job-id-n>\driver-events.jsonl`. These derived paths are display hints;
the import endpoint still resolves actual files server-side.

当前根页面也从 `/api/jobs` 渲染紧凑 recent-job cards。这些卡片刻意只读：
`打开 / Open` action 获取所选 job detail 并复用主 job panel；artifact/download
渲染保留在 `/jobs/{jobId}/live-events`。

## 可选运行时 WebUI smoke / Optional runtime WebUI smoke

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

runtime WebUI smoke contract 刻意保持 API-level，便于 headless workers 运行。
它探测：

- `GET /jobs/{jobId}/live-events` and requires a successful `text/html` page
  containing the live raw monitor title plus references to both raw event
  transports;
- `GET /api/jobs/{jobId}/events/live?offset=0&take=1` and requires the live raw
  telemetry JSON cursor fields: `jobId`, `retrievedAt`, `totalEvents`,
  `nextOffset`, `hasMore`, `sources`, and `events`;
- the root dashboard source must link to the dedicated live raw monitor page;
- `GET /api/jobs/{jobId}/report/html` and requires a successful `text/html`
  served report response, which is the same safe report link rendered by the
  dashboard;
- bilingual report endpoints: `GET /api/jobs/{jobId}/report/html?lang=zh` and
  `GET /api/jobs/{jobId}/report/html?lang=en` should both return `text/html`
  from the recorded job report paths, falling back to the compatibility
  `report.html` only when a localized report file is not recorded;
- `POST /api/jobs/{jobId}/guest-events/import` with an explicit missing
  `eventsPath` and requires a controlled HTTP 400 validation response. This
  proves the manual guest import endpoint and payload contract without importing
  or rewriting real guest artifacts during smoke.

The PowerShell gate also accepts the same environment variables when `-BaseUrl`
and `-JobId` are omitted:

```powershell
.\scripts\Test-LiveTelemetryFramework.ps1 -UsePollingFallback
```

端到端操作者验证：启动 Web host 后创建或选择一个 job，手动在浏览器打开
dashboard，并确认 served HTML report link 可打开、live raw monitor page 通过
SSE 或 polling 刷新、monitor 显示 artifacts/download cards、中文报告 endpoint
`/api/jobs/{jobId}/report/html?lang=zh` 与英文报告 endpoint
`/api/jobs/{jobId}/report/html?lang=en` 都返回 HTML、upload-launched completion
会导航到中文报告（`report.zh.html`），并且根 dashboard 不展示长 runbook command/output blocks
或 artifact/download lists。 The optional manual guest import field can be left blank or filled with a
specific `events.json` / `.jsonl` path. Do not commit generated reports,
imported guest output, browser screenshots, or build binaries from this
validation.

## 验证指引 / Verification guidance

为避免验证时修改仓库内 `bin/` 或 `obj/` 目录，构建 Web project 时请把
`BaseIntermediateOutputPath`、`BaseOutputPath`、`RestorePackagesPath` 重定向到
仓库外临时目录。
