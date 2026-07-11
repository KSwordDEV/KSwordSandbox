# WebUI 框架暂存 / Web UI framework staging

本文说明 Web 项目的暂存分层：目标是逐步把 endpoint 与 dashboard 逻辑从
`Program.cs` 拆出。多数 endpoint 模块仍是被动暂存，但根 WebUI 已由
`Dashboard/DashboardExperiencePage.cs` 渲染，因此操作者体验可以在
Dashboard 层迭代，而不触碰 Core、Driver 或 Guest 代码。

English context: this document describes the staged Web project layout used to
extract endpoint and dashboard logic from `Program.cs`.

Canonical cross-links: use `docs/report-ux.md` for report/UI presentation,
`docs/report-schema.md` for report data shape, `docs/artifact-manifest.md` for
artifact download selectors, `docs/virustotal.md` for hash-only VT behavior,
and `docs/verification.md` for repeatable validation commands. Do not commit
runtime reports, raw events, uploaded samples, payload binaries, browser
screenshots, VM outputs, or build artifacts produced while testing WebUI work.

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
  `GET /api/jobs/{jobId}/artifacts` returns the current host-side
  `artifact-index` view, and
  `GET /api/jobs/{jobId}/artifacts/download?path=<relative>` streams only files
  present in that index. The download path is a normalized relative/safe-link
  value, never an arbitrary absolute host path. The same guarded resolver backs
  `GET /api/jobs/{jobId}/report/{relativeArtifactPath}` so links embedded in a
  served HTML report can open `events.json`, `driver-events.jsonl`, dropped
  files, screenshots, memory dumps, or PCAP artifacts without exposing local
  filesystem paths to the browser;
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
- 上传流程应保持 one-click：`.exe` 上传后，
  stored and a plan is created, the dashboard must submit live VM analysis to
  the Web host background runner and redirect the current browser page to
  `/jobs/{jobId}/live-events`. The dynamic monitor becomes the primary
  operator surface for real runbook progress, raw events, VirusTotal status,
  and artifact/download cards; no popup or extra dashboard tab is required. The
  preferred API path is
  `POST /api/files/upload/start`, which saves the upload, creates the job, and
  submits background runbook execution in one server-side operation. This avoids
  the earlier three-request chain (`upload` -> `plan` -> `runbook/start`) losing
  context if a browser fetch fails between steps;
- VirusTotal 官方结果集成为可选、仅 hash 查询。操作者
  can open `/settings` to save or clear a local API key and manage browser-local
  VM WebUI presets for VM name, checkpoint, duration, Guest user hints,
  real/mock R0 collector mode, and artifact opt-in toggles. VM presets are
  stored only in browser `localStorage` and become per-job overrides on the
  upload page; they do not write `config/*.json`, Core, Driver, or Guest files.
  The key is read from `KSWORDBOX_VIRUSTOTAL_API_KEY` first or from the
  process-local settings page update; WebUI must not write API keys to repo,
  config, or runtime files. The job page exposes
  `GET /api/jobs/{jobId}/virustotal`, which queries the official v3
  `files/{sha256}` endpoint with `x-apikey`, does not upload samples, and
  returns a quiet `not_configured` / `lookup_failed` state when missing or
  unavailable instead of interrupting analysis. A missing API key should remain
  a quiet UI state with a settings link, not a repeated warning/noisy log path
  or automatic report-enrichment write;
- 提供 dedicated live raw monitor page / dynamic monitor page 链接，用于展示
  source files and unclassified raw event rows before final report
  classification. When opened automatically from upload, the Web host has
  already accepted the background run, so the original dashboard page does not
  need to remain open. The monitor page also polls
  `GET /api/jobs/{jobId}/runbook/progress` and shows UI-safe runbook step state,
  current step, and progress percentage without command lines, `stdout`, or
  `stderr` inline. If terminal execution results are present on
  `/runbook/background`, per-step `stdout`/`stderr` may be available only under
  collapsed troubleshooting `<details>` blocks; command lines remain hidden.
  It also polls
  `GET /api/jobs/{jobId}/runbook/background` so the monitor can show terminal
  completed/failed state and report links even if the main dashboard tab is
  closed after the server accepted the background task. For upload-launched
  monitor sessions, a completed run should automatically navigate to
  `/api/jobs/{jobId}/report/html?lang=zh` (`report.zh.html`) after displaying a
  short report-ready notice. Operators can still use the top-right language
  switch and explicit English report button for manual English navigation;
- dynamic monitor page 应优先服务真实产品使用，而不只服务 smoke 覆盖；页面展示
  **证据 / 下载（Artifacts / downloads）** 卡片面板。面板列出
  `report.html`, `report.zh.html`, `report.en.html`, `report.json`,
  `events.json`, `driver-events.jsonl`, dropped files, screenshots, memory
  dumps, and packet captures. If a safe Web endpoint is available, including
  `/api/jobs/{jobId}/artifacts/download?path=<relative>` or the served report
  endpoint, the card should render bilingual open/download buttons. For evidence
  without a download endpoint, it should render the copyable host path or
  derived expected path plus a bilingual `等待回收` / `waiting for collection`
  state instead of hiding the lane. The same monitor should make VirusTotal
  results visually prominent with clear malicious/suspicious/clean/missing/
  not-configured states, and after a run reaches a terminal background state it
  should keep explicit Chinese and English report buttons visible;
- 为 runbook step status 提供自然的 progress-page link，指向 dedicated
  execution-flow page，并同时出现在 job actions 与 progress summary 中。
  The root dashboard must not inline long runbook PowerShell commands,
  command-line details, `stdout`, `stderr`, raw event rows, or artifact/download
  lists. Recent job cards should remain compact and show only status, report
  readiness, an `执行流程 / Execution flow` link, and a live monitor/download
  entry for technical follow-up.

所有表格、路径值、raw telemetry evidence、job messages、status text、inputs
和 section text 都必须支持显式 `复制 / Copy` 按钮，或通过 `data-copy`、
`code`、`pre`、`td`、`th`、`p`、`li`、heading、`label`、`span`、`a`、
`button`、`input` 元素 right-click copy。复制成功或失败后 WebUI 应显示小
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
context-copy script 能一致处理 right-click copy 行为。

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
SSE 或 polling 刷新、monitor 显示 artifacts/download cards、Chinese report endpoint
`/api/jobs/{jobId}/report/html?lang=zh` and English report endpoint
`/api/jobs/{jobId}/report/html?lang=en` both serve HTML, upload-launched
completion navigates to the Chinese report (`report.zh.html`), and the root
dashboard does not show long runbook command/output blocks or artifact/download
lists. The optional manual guest import field can be left blank or filled with a
specific `events.json` / `.jsonl` path. Do not commit generated reports,
imported guest output, browser screenshots, or build binaries from this
validation.

## 验证指引 / Verification guidance

为避免验证时修改仓库内 `bin/` 或 `obj/` 目录，构建 Web project 时请把
`BaseIntermediateOutputPath`、`BaseOutputPath`、`RestorePackagesPath` 重定向到
仓库外临时目录。
