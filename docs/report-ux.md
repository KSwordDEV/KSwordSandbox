# 报告与 WebUI UX 契约 / Report and WebUI UX contract

权威范围：本页负责 report/WebUI 展示预期。JSON/HTML section 数据契约见
`docs/report-schema.md`，artifact selector/link schema 见 `docs/artifact-manifest.md`，
VirusTotal hash-only reputation 行为见 `docs/virustotal.md`。

验证这些 UX 要求时，不要提交生成报告、raw events、artifact indexes、screenshots、
dumps、packet captures、samples、payload binaries 或 VM outputs。

v1 报告必须在 live demo 中对操作者有用，而不只是技术上完整。页面应让操作者快速回答三件事：

1. 风险是什么？ / What is the risk?
2. 哪些行为证明该风险？ / What behavior proves that risk?
3. 原始 artifacts 和 original events 在哪里？ / Where are the raw artifacts and original events?

## 报告章节 / Report sections

`report.html`、`report.zh.html` 和 `report.en.html` 必须包含以下章节。
`report.html` 是默认简体中文兼容报告；显式英文入口仍是 `report.en.html`。

- Cover / 封面：包含 job id、生成时间、verdict、样本身份和 hashes。
- Table of contents / 目录.
- Quick navigation / 快速导航：面向高频章节的 sticky subnav：
  Risk、Process、Files、Network、R0、VT、Artifacts 和 Raw events。计数应代表当前嵌入证据，
  不得暗示 R0 health、collector self-noise 或 VT lookup status 是恶意行为。
- Risk summary / 风险摘要：方形摘要面板。
- Behavior detections / 行为命中.
  每个 finding 应显示 evidence count，并提供原生 `<details>` “Top evidence / 关键证据”块，
  其中包含可复制的高信号事件，便于分析员无需先打开完整 raw table 就理解规则命中。
  Primary behavior verdicts must exclude static-only triage, collection
  diagnostics, R0 unavailable/health rows, and VirusTotal/reputation findings.
  Those signals belong in their dedicated quality or reputation sections.
- MITRE mapping / MITRE 映射.
- Engine/rule hits / 引擎与规则命中。
- Static analysis / 静态分析：包含 PE sections、URLs、strings、warnings 和 tags。
- Dynamic summary / 动态分析.
- VirusTotal / reputation / VirusTotal / 信誉：VT 是可选 hash-only 信誉 enrichment。
  缺失 API key、限速、未收录响应或 lookup transport status 属于 enrichment 质量/状态，
  不是沙箱观察到的恶意行为。
- Behavior graph / IOC summary / 行为图谱与 IOC 摘要. This is a stable,
  weak-interaction graph view that derives process-to-file, process-to-registry,
  process-to-network, and process-to-artifact edges from normalized telemetry.
  It must include an Evidence story board, Top behavior chain, Evidence graph
  edges, and IOC summary panels so the final report feels like an
  analyst-facing sandbox report rather than only raw tables. The Evidence story
  board should keep dropped files, screenshots, memory dumps, PCAP/network,
  process lineage, and R0 health/noise boundaries visible as copyable,
  collapsible lanes before dense event tables.
- Timeline. The timeline must use timeline grouping so bursty telemetry is
  readable in chronological order: group by a stable time bucket, show event
  counts and event-family summaries, keep a bounded timeline inline, and point
  to raw events/report JSON for complete evidence.
- Process details / 进程, including the Process tree, process relationship
  tree, process relationship panels, and process event table. The tree should
  prefer a stable process key when present and fall back to PID/PPID so parent,
  child, and orphan relationships remain stable without JavaScript.
  This stable process relationship tree must remain readable without opening
  raw evidence first. A Process tree overview should show node/root/edge
  counts, high-signal default-expanded nodes, and self-noise excluded from the
  tree before the operator expands the lineage.
- File behavior / 文件, including dropped files.
  Dropped-file rows should be reinforced by the Evidence story board and
  Artifact collection status lanes so released files remain visible even when
  raw file activity is noisy.
- Artifact links / 证据文件链接：当 job 目录存在对应文件时，必须包含 `events.json`、
  `driver-events.jsonl`、artifact manifests、screenshots、dropped files、显式 opt-in 的
  memory dumps，以及导入的 `.pcap` / `.pcapng` packet captures。本章节还必须包含
  Artifact collection status panels，用于 dropped files、screenshots、memory dumps、
  packet captures 和 driver events。这些面板应从 indexed artifacts 与 normalized telemetry
  汇总 captured、failed、skipped、partial、observed 或 not-observed 状态，让操作者即使在
  没有 artifact 文件时也能判断证据是否实际采集。
- Registry behavior / 注册表.
- Network behavior / 网络. A Network category view should summarize endpoint
  groups plus DNS / HTTP / TLS / flow counts before raw network rows, so
  operators can read relationships without opening the full raw table. PCAP /
  pktmon collection metadata, packet counts, conversion status, and imported
  DNS/HTTP/TLS/flow rows should also appear in the Evidence story board and
  remain collapsible/copyable rather than being spread across raw rows only.
- R0 / driver events.
  R0 collection health status must be shown before driver telemetry evidence.
  Device unavailable, driver health, queue backpressure, and dropped-event
  counters describe telemetry quality and must not be counted as sample
  behavior. Health alerts may be highlighted as collection-quality warnings.
  The R0 availability summary should show available, unavailable/degraded,
  attention-needed, or absent-health-row states as evidence quality rather than
  malicious behavior.
  Driver rows attributed to `KSword.Sandbox.R0Collector.exe`, the sandbox
  agent, collector staging paths, or the KSword driver device are
  collection-side self-noise. They must be excluded from behavior counts,
  behavior graphs, and file/registry/network/process behavior sections, while
  remaining auditable in the R0 self-noise summary and Raw normalized events.
  R0 health/unavailable examples should be folded by default and capped to a
  small representative set, with complete evidence left in raw events and
  `report.json`.
- Failure reasons / 失败原因.
- Raw normalized events / 原始事件.
  This section should remain collapsed and capped, but before the collapsed
  table it should show a small "Raw event distribution" summary for top event
  types, sources, and event families. Raw evidence height limit should be
  explicit in the UI so operators know expanded evidence remains bounded.


## Report renderer visual contract

The final report renderer should use a modern sandbox report layout, not a
plain diagnostic dump. The visual contract is:

- Primary accent color: `#43A0FF`.
- Major report areas should render as square panels with clear spacing,
  readable typography, and an operator-focused summary-first flow. Corners
  should be square (`0` or `2px` radius) and shadows should be avoided.
- Visual nesting should stop at one obvious containment layer. Tables must not
  contain nested card stacks, rounded pills, or card-like evidence blocks; use
  inline actions and native flat `<details>` instead.
- Each major `section.card` panel should keep very large evidence sets bounded with a
  maximum height around `75vh` and `overflow:auto`, so risk, behavior, MITRE,
  static, dynamic, timeline, process, file, registry, network, R0, failure,
  and raw event evidence remain navigable during demos.
- Each bounded major panel should keep a sticky section header so the operator
  never loses the current chapter while scrolling dense evidence. The section
  chrome should follow the Microstep-style bright-blue rhythm with `#43A0FF`
  accents, compact square step markers, and summary-first spacing.
- Heavy event tables should also be bounded inside the section, not just by the
  whole page panel. The renderer should inline a representative window (currently
  80 rows for ordinary event tables), show hidden-row counts, and point to Raw
  normalized events or `report.json` for complete evidence.
- Large static strings/warnings lists should be capped in the default view
  (currently 200 entries) with a visible hidden-entry count and a pointer to
  `report.json`.
- 具有可信 `safeLink` 或安全相对路径的 Artifact evidence 应渲染为显式
  Open/Download（`打开 / Open`、`下载 / Download`）按钮。任意 host/guest 绝对文件系统路径只能作为可复制
  evidence text 展示 and must not be used as `href`。绝对路径不得用于 `href`。
- The Raw normalized events section should be slim by default: render a native
  collapsed `<details>` block, bound the expanded raw event panel height, and
  inline only the first 75 raw events. Expanded inline rows must be split into
  25-row native pages so analysts can open a small chunk instead of a long
  table. The section must show total events, inline-rendered events, inline
  page count, hidden raw events, a Raw evidence height limit (currently
  `58vh`), and clear `report.json` plus raw source artifact path hints for
  complete evidence.
- Raw normalized events should also include a static `Raw event page index /
  原始事件页索引` that covers every normalized event, including rows hidden from
  inline rendering. The index should group by event type, source, and event
  family, show first row / first inline page or `report.json only`, and provide
  copyable row ranges. This keeps large reports navigable without adding
  JavaScript or turning the final report into an app.
- Raw event details should keep command/stdout/stderr/PowerShell and similarly
  long technical payloads hidden by default behind deliberate, copyable native
  `<details>` entries. The main report must not directly spread full command
  lines, script blocks, stdout, or stderr across the page; they should stay
  copyable after deliberate expansion.
- Ordinary event rows must use the same long-field policy: command line,
  stdout/stderr, PowerShell/script-block payloads, encoded commands, and other
  large fields stay collapsed by default even outside the Raw normalized events
  section.
- Raw event expansion and layout stability must use native HTML/CSS rather than
  JavaScript. Copy affordances may enhance the static HTML but must not be
  required to reveal evidence.
- The Behavior graph / IOC summary section should remain static HTML/CSS. It
  should prefer stable weak interactions over fragile canvas/SVG rendering:
  an Evidence story board, process graph nodes, a bounded Top behavior chain,
  Evidence graph edges, and IOC summary panels for network, file/path,
  registry, and artifact indicators.
- The Evidence story board should be summary-first and weakly interactive:
  each lane must show a compact status badge, a short analyst narrative,
  3-8 metric chips, and a native collapsed evidence block. Required lanes are
  execution lineage, dropped-file evidence, screenshot evidence, memory dump
  evidence, network/PCAP evidence, and R0 health/noise boundary.
- Timeline and process relationship views should also prefer stable weak
  interactions: native HTML/CSS timeline group panels, a bounded process
  relationship tree, and copyable relationship panels rather than external graph
  JavaScript.
- The report must support Chinese and English rendering entrypoints, or
  equivalent core renderer support for `report.zh.html` and `report.en.html`.
- New report chrome must have Simplified Chinese mappings before release.
  Common operator text such as Quick navigation, VT lookups/status, collection
  health/status rows, health alerts, event-table caps, and hidden evidence
  counts should not remain as large English blocks in `report.zh.html`.
- The Simplified Chinese report should localize operator-facing chrome such as
  table headers, buttons, hints, section notes, empty states, status words, and
  evidence-expander summaries. Raw evidence must stay original: `eventType`,
  API names, schema keys/values, hashes, paths, command lines, stdout, stderr,
  and JSON/JSONL previews are not translated.
- Each generated HTML report should expose an in-report bilingual entry bar
  linking the sibling `report.zh.html`, `report.en.html`, and compatibility
  `report.html` files, so local file viewing and served WebUI viewing behave
  consistently. The entry bar should explain that `report.html` is the default Simplified Chinese compatibility report, `report.en.html` keeps English
  operator chrome, and evidence values stay original in both reports.
- Jobs should keep report path fields suitable for automatic WebUI links, so a
  completed plan can expose the default report plus localized report clues
  without asking the operator to paste a filesystem path.
- The WebUI report entry should be path-free for normal operators: one primary
  current-language report button, compact Chinese/English alternatives, and an
  automatic current-language report navigation after successful dynamic
  analysis or manual event import refresh.
- Validation should request the served bilingual endpoints
  `/api/jobs/{jobId}/report/html?lang=zh` and
  `/api/jobs/{jobId}/report/html?lang=en` and require `text/html` responses.
  The default `/api/jobs/{jobId}/report/html` endpoint remains the compatibility
  link for existing report consumers and should serve the Simplified Chinese
  report chrome by default.

## 证据交互 / Evidence interaction

Evidence rows 是操作者可见内容。Tables、timeline entries 和 raw evidence blocks
应支持快速复制：

- Right-click / 右键可复制单元格或 timeline item，复制其 evidence text。
- 点击 raw evidence 上的 `复制 / Copy` 按钮，复制完整 event block。
- Raw event fields should be sorted and rendered in a flat collapsible evidence
  block; command/output/script fields stay in nested copyable `<details>` so
  large driver payloads do not overwhelm the page.
- Raw normalized events should default to a closed summary, show only the first
  75 inline rows in 25-row native pages, and tell the operator exactly how
  many events are hidden.
- The raw section should point to `report.json`, `events.json`,
  `driver-events.jsonl`, and/or artifact manifests when indexed, so operators
  have raw source artifact path hints and can open or copy the full raw source
  instead of relying on an oversized HTML table.
- Indexed artifacts 应通过安全相对 report links 打开或下载。若只知道绝对 host/guest path，
  则显示为可复制 text evidence，而不是 clickable link。

## Live UI 预期 / Live UI expectations

WebUI live raw monitor 是独立 dynamic monitor page，由 main dashboard 链接；浏览器允许时，
upload flow 会自动打开它。该页刻意只显示 raw events only；在 analysis 完成并导入 guest output 前，
不运行 behavior classification。当页面由 upload 打开时，双语提示应告知操作者分析请求已由后台接管，
可在 monitor 页查看进度/下载。Live table 应显示：

- timestamp / 时间戳
- `eventType`
- source / 来源
- process id/name / 进程 ID/名称
- path / 路径
- data / 数据：command/output 字段隐藏在可复制 details 中

当 job 失败时，main dashboard 应保持 report links、artifact paths、progress stage status、
failed step title/message、exit code 和 duration 可见。它不应内联长 runbook command text、
stdout 或 stderr；操作者可打开 execution-flow page，并复制 `runbook-execution.json` 进行深度排障。

Main dashboard 的 report navigation 应保持低噪音：一个当前语言 primary report button、紧凑的
中文/英文替代入口、生成/导入成功后的稳定 automatic open notice、progress summary 旁自然的
progress-page（`execution-flow`）链接，以及作为独立页面而非 inline stream 的 live raw monitor。
