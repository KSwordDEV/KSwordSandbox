# 实时遥测管线 / Live telemetry pipeline

WebUI 动态监控页以原始事件为核心：任务运行时先展示 Guest Agent 与驱动正在产生的进程、文件、注册表、截图和网络证据，不等待最终规则归类。英文术语仅作为接口名或排障参照保留。

## v1 数据流 / v1 data flow

1. Host 将准备好的 Guest Agent 与 R0Collector payload 从 `paths.guestPayloadRoot` 部署到来宾机。
2. Guest Agent 在任务专属输出目录写入 `events.json`，例如 `C:\KSwordSandbox\out\<job-id-n>`。
3. R0Collector 在 `events.json` 旁边写入 `driver-events.jsonl`。
4. Host 异步启动 Guest Agent，然后由 runbook 的 `sync-live-output` 步骤周期性把 guest 输出树复制到 `D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest`。
5. Core 实时遥测服务以共享读取（shared-read）容错方式读取 JSON/JSONL。
6. WebUI 优先消费 `/api/jobs/{jobId}/events/stream` 原始事件 SSE；不可用时轮询 `/api/jobs/{jobId}/events/live`，并追加未归类事件行。
7. WebUI 同时优先消费 `/api/jobs/{jobId}/progress/stream` 真实 runbook 进度 SSE；不可用、无快照或代理缓冲时退回 `/runbook/progress` 与 `/runbook/background` 安全轮询。
8. 任务结束后，Host 导入事件、执行行为规则，并重新生成 JSON/中文 HTML/英文 HTML 报告。

## 重要边界 / Important boundary

实时显示不是最终判定（verdict）。它只是运行中可见性通道，帮助操作者确认进程、文件、注册表、图像、R0 和网络事件是否正在回收。风险评分、MITRE 映射和最终结论仍属于报告再生成路径。

## 可见文案与术语约定 / Visible wording

页面文案中文优先，英文只作为接口名、排障参照或 `data-en` 备选：

- `实时原始事件` / `原始事件流`：对应 live raw events / raw event stream。
- `最终判定（verdict）`：只来自报告，不来自 live raw 表格。
- `降级为轮询 fallback`：SSE 不可用时的正常兜底路径。
- `事件游标（offset / nextOffset）`：浏览器分页读取服务端 snapshot 的唯一 cursor。
- `事件来源`：Host 侧 `events.json`、`driver-events.jsonl` 等 live source。
- 空状态使用 `暂无原始事件` 与 `尚未发现事件来源`，避免把“还没回收”误读成“无行为”。

## 当前 v1 实现 / Current v1 implementation

实时路径仍基于 PowerShell Direct，而不是 guest socket stream。Host 打开 PSSession，在 Guest Agent wrapper 运行期间复制 guest 输出树，并在进程退出后执行最后一次复制。这样 v1 可以在默认 Hyper-V Windows 10 guest 中部署，不要求额外安装 guest TCP/WebSocket 服务。

## 文件源容错与状态行 / File-source tolerance and status rows

实时读取使用共享文件访问（shared file access），因为 `events.json` 和 `driver-events.jsonl` 可能正在被复制或追加。文件源必须用可解释状态代替端点失败（endpoint failure）：

- 缺失或暂时被锁定的文件：事件读取器返回空结果；live monitor 读取器可生成 `live.events.source_status`，其中 `status=missing` 或 `status=pending`。
- 空文件：生成稳定的 `live.events.source_status`，其中 `status=empty`。
- 不完整的 `events.json` 数组：在 JSON 数组完整前保持 `status=pending`。
- JSONL 空行被忽略；完整但格式错误的行计入 `parseErrorCount`；末尾半行计入 `partialLineCount` 并保持 `status=pending`。
- 多个来源读取完成后再去重事件行。

`live.events.source_status` 是 Host 生成的 raw event。它使用固定时间戳 `1970-01-01T00:00:00Z` 与稳定排序，避免同一文件状态反复读取时 cursor 抖动。字段包括 `format`、`sourceFileName`、`eventCount`、`recordCount`、`blankLineCount`、`parseErrorCount`、`partialLineCount`、`sizeBytes`、`lastWriteTimeUtc` 和 `cursorStable=true`。该行可出现在原始事件表格中，并会被页面状态条汇总为“事件来源诊断”；它仅用于诊断，不是 verdict，也不触发报告分类。最终报告归类仍使用导入后的 durable events。

## 动态监控页 UX / Live monitor UX

`/jobs/{jobId}/live-events` 页面保持独立、中文优先，并按低噪音原则展示：

- 顶部任务概览、运营态势驾驶舱、采集选项、证据与下载、虚拟机分析进度、VirusTotal 官方结果、原始事件流。
- 原始事件流优先使用 `/events/stream` SSE；不可用时显示明确回退（fallback）状态，并轮询 `/events/live`。
- 原始事件表格只渲染有界页面：浏览器保留有限缓冲，提供首页、上一页、下一页、最新页和每页行数控制。
- 支持严重度、类型、来源三组快速筛选（quick filters）。严重度是页面诊断分组，不是最终风险等级。
- 点击事件行可选中一条事件；`复制选中事件摘要` 输出一条短摘要，右键行、单元格、状态条仍可复制。
- `data` 列默认隐藏 command/stdout/stderr/PowerShell 类字段，并截断过长值，避免 live 页变成巨大命令墙。

## 浏览器 API 面 / Browser API surface

动态监控页面面向浏览器提供以下入口：

- `GET /jobs/{jobId}/live-events`：独立 live raw event page。
- `GET /api/jobs/{jobId}/events/stream`：原始事件 Server-Sent Events (SSE)。
- `GET /api/jobs/{jobId}/events/live`：原始事件 JSON 轮询回退（fallback）。
- `GET /api/jobs/{jobId}/progress/stream`：真实 runbook step 进度 SSE。
- `GET /api/jobs/{jobId}/runbook/progress`：进度快照轮询回退（fallback）。
- `GET /api/jobs/{jobId}/runbook/background`：后台执行状态轮询回退（fallback）。

页面返回 `text/html`，必须包含中文优先标签和英文 `data-en` 参照，并引用 `/events/stream`、`/events/live`、`/progress/stream`，方便 headless smoke 不打开浏览器也能确认路由存在。

### 轮询快照 / Polling snapshot

```http
GET /api/jobs/{jobId}/events/live?offset=0&take=100
Accept: application/json
```

响应是 camelCase `LiveEventSnapshot`：

- `jobId`：请求的任务 ID。
- `retrievedAt`：Host 组装快照时的 UTC 时间。
- `totalEvents`：当前可见原始事件总数。
- `nextOffset`：下一次轮询应传入的 cursor。
- `hasMore`：当前页未包含所有可见事件时为 `true`。
- `sources`：本次快照使用的 Host 侧 JSON/JSONL 文件。
- `events`：未归类的 `SandboxEvent` 行。

查询约定：`offset` 是从 0 开始的事件 cursor；缺失或负数按 `0` 处理。`take` 默认 `100`，服务端限制在 `1..500`。`intervalMs` 不属于轮询 endpoint；轮询节奏由浏览器或 QA 脚本控制。

客户端只拥有 `nextOffset` 这一种 cursor。`hasMore=true` 时立即用 `offset=nextOffset` 再取一页；`hasMore=false` 且任务仍运行时，稍等后用同一个 `nextOffset` 继续轮询，runbook 复制 guest 输出树后会出现新行。

### 原始事件 SSE 流 / Raw-event SSE stream

`GET /api/jobs/{jobId}/events/stream` 保持 HTTP 响应打开，并推送与轮询相同 shape 的 `LiveEventSnapshot` 快照帧。

```http
GET /api/jobs/{jobId}/events/stream?offset=0&take=100&intervalMs=2000
Accept: text/event-stream
Cache-Control: no-cache
```

成功响应要求：

- HTTP `200`。
- `Content-Type: text/event-stream`。
- `Cache-Control: no-cache`。
- `X-Accel-Buffering: no`，减少代理缓冲。
- 流路径不做行为分类、风险评分或 verdict 计算。
- 事件排序与分页必须匹配当前轮询排序。
- 每个推送帧是 snapshot，不是单条 event。
- `event:` 固定为 `snapshot`。
- `data:` 包含一个 camelCase `LiveEventSnapshot` JSON。

查询约定：`offset` 是初始 cursor；缺失或负数按 `0` 处理。`take` 默认 `100` 并限制到 `1..500`。`intervalMs` 控制服务端每次读取间隔，默认 `2000`，限制到 `500..10000`。

示例帧：

```text
event: snapshot
data: {"jobId":"00000000-0000-0000-0000-000000000000","retrievedAt":"2026-07-10T08:00:00Z","totalEvents":7,"nextOffset":7,"hasMore":false,"sources":["D:\\Temp\\KSwordSandbox\\jobs\\...\\events.json"],"events":[{"eventType":"process.start","timestamp":"2026-07-10T08:00:00Z","source":"guest","processName":"sample.exe","processId":4242,"data":{}}]}
```

重连约定：从最近快照的 `nextOffset` 继续；客户端发送前把负数或格式错误的 offset 归零；有效 cursor 不得重放重复行；HTTP client 断开时服务端应尽快关闭。

### 真实进度流 / Real runbook progress stream

`GET /api/jobs/{jobId}/progress/stream` 用于 WebUI 进度卡片。它推送界面安全载荷（UI-safe payload）：真实 runbook step、后台（background）状态、终态/最终/失败（terminal/final/failed）状态和心跳（heartbeat）。该 payload 不应包含命令行、`stdout`、`stderr` 或完整 PowerShell 输出。

可见文案必须中文优先：

- 连接中：`正在连接真实进度流`。
- 已连接但未收到快照：`真实进度流已连接，等待 runbook step 快照`。
- heartbeat：`真实进度流心跳正常，等待下一条进度快照`。
- fallback：`进度 SSE 不可用，已切换为轮询` 或 `进度流暂未返回快照，已切换为安全轮询`。
- terminal：`真实进度流已结束，正在刷新证据索引`。
- failed terminal：`真实进度流已收到失败终态，正在刷新证据索引`。

页面可以把连接中状态扩展为 `正在连接真实进度流；如 6 秒内没有快照将自动切换到安全轮询。`，但仍不得展示命令行、`stdout`、`stderr` 或完整 PowerShell 输出。

## 轮询回退 / Polling fallback

当 SSE 不可用或不适合当前环境时，轮询仍是 WebUI 与 QA probe 的必备回退（fallback）。客户端应在以下情况回退到 `/api/jobs/{jobId}/events/live?offset=<lastOffset>&take=100` 或进度轮询 API：

- SSE 端点（endpoint）返回 `404`、`405` 或 `501`。
- 响应不是 `text/event-stream`。
- 连接在收到 response headers 前失败。
- 代理或本地测试 harness 缓冲 SSE，导致页面无法及时接收帧。
- 进度流在短时间内没有返回 snapshot。

回退（fallback）是容忍丢包/重连的：服务端 cursor 是当前 raw event snapshot 上的整数 offset。客户端保留最近的 `nextOffset`，直到 `hasMore=false`；任务仍运行时继续低频轮询。任务完成后，一次最终轮询加 guest-event import/report refresh 即可补齐 UI 状态。
