# Report and WebUI UX contract

The v1 report must be useful during a live demo, not merely technically
complete. The page should let an operator answer three questions quickly:

1. What is the risk?
2. What behavior proves that risk?
3. Where are the raw artifacts and original events?

## Report sections

Required `report.html`, `report.zh.html`, and `report.en.html` sections:

- Cover / 封面 with job id, generation time, verdict, sample identity, and hashes.
- Table of contents / 目录.
- Risk summary / 风险摘要 cards.
- Behavior detections / 行为命中.
  Each finding should show the evidence count plus a native `<details>` "Top
  evidence" block with copyable high-signal events so analysts can understand a
  rule hit without opening the full raw table first.
- MITRE mapping / MITRE 映射.
- Engine/rule hits.
- Static analysis / 静态分析 with PE sections, URLs, strings, warnings, and tags.
- Dynamic summary / 动态分析.
- Behavior graph / IOC summary / 行为图谱与 IOC 摘要. This is a stable,
  weak-interaction graph view that derives process-to-file, process-to-registry,
  process-to-network, and process-to-artifact edges from normalized telemetry.
  It must include a Top behavior chain, Evidence graph edges, and IOC summary
  cards so the final report feels like an analyst-facing sandbox report rather
  than only raw tables.
- Timeline. The timeline must use timeline grouping so bursty telemetry is
  readable in chronological order: group by a stable time bucket, show event
  counts and event-family summaries, keep a bounded timeline inline, and point
  to raw events/report JSON for complete evidence.
- Process details / 进程, including the Process tree, process relationship
  tree, process relationship cards, and process event table. The tree should
  prefer a stable process key when present and fall back to PID/PPID so parent,
  child, and orphan relationships remain stable without JavaScript.
  This stable process relationship tree must remain readable without opening
  raw evidence first.
- File behavior / 文件, including dropped files.
- Artifact links / 证据文件链接 must include `events.json`,
  `driver-events.jsonl`, artifact manifests, screenshots, dropped files,
  opt-in memory dumps, and imported `.pcap` / `.pcapng` packet captures when
  those files exist in the job directory. This section must also include
  Artifact collection status cards for dropped files, screenshots, memory
  dumps, packet captures, and driver events. These cards should summarize
  captured, failed, skipped, partial, observed, or not-observed collection state
  from both indexed artifacts and normalized telemetry, so operators can see
  whether evidence was actually collected even when no artifact file exists.
- Registry behavior / 注册表.
- Network behavior / 网络.
- R0 / driver events.
- Failure reasons / 失败原因.
- Raw normalized events / 原始事件.
  This section should remain collapsed and capped, but before the collapsed
  table it should show a small "Raw event distribution" summary for top event
  types, sources, and event families.


## Report renderer visual contract

The final report renderer should use a modern sandbox report layout, not a
plain diagnostic dump. The visual contract is:

- Primary accent color: `#43A0FF`.
- Major report areas should render as modern cards/panels with clear spacing,
  readable typography, and an operator-focused summary-first flow.
- Each major `section.card` should keep very large evidence sets bounded with a
  maximum height around `75vh` and `overflow:auto`, so risk, behavior, MITRE,
  static, dynamic, timeline, process, file, registry, network, R0, failure,
  and raw event evidence remain navigable during demos.
- Each bounded major card should keep a sticky section header so the operator
  never loses the current chapter while scrolling dense evidence. The section
  chrome should follow the Microstep-style bright-blue rhythm with `#43A0FF`
  accents, compact step markers, rounded cards, and summary-first spacing.
- Artifact evidence with a trusted `safeLink` or safe relative path should
  render as explicit Open/Download buttons. Arbitrary host or guest absolute
  filesystem paths must remain copyable evidence text only and must not be used
  as `href` values.
  Absolute paths must not be used as `href` values.
- The Raw normalized events section should be slim by default: render a native
  collapsed `<details>` block, bound the expanded raw event panel height, and
  inline only the first 200 raw events. Expanded inline rows must be split into
  50-row native pages so analysts can open a small chunk instead of a long
  table. The section must show total events, inline-rendered events, inline
  page count, hidden raw events, and clear `report.json` plus raw source
  artifact path hints for complete evidence.
- Raw event details should keep command/stdout/stderr/PowerShell and similarly
  long technical payloads inside nested collapsed details. The main report must
  not directly spread full command lines, script blocks, stdout, or stderr
  across the page; they should stay copyable after deliberate expansion.
- Raw event expansion and layout stability must use native HTML/CSS rather than
  JavaScript. Copy affordances may enhance the static HTML but must not be
  required to reveal evidence.
- The Behavior graph / IOC summary section should remain static HTML/CSS. It
  should prefer stable weak interactions over fragile canvas/SVG rendering:
  process graph nodes, a bounded Top behavior chain, Evidence graph edges, and
  IOC summary cards for network, file/path, registry, and artifact indicators.
- Timeline and process relationship views should also prefer stable weak
  interactions: native HTML/CSS timeline group panels, a bounded process
  relationship tree, and copyable relationship cards rather than external graph
  JavaScript.
- The report must support Chinese and English rendering entrypoints, or
  equivalent core renderer support for `report.zh.html` and `report.en.html`.
- Each generated HTML report should expose an in-report bilingual entry bar
  linking the sibling `report.zh.html`, `report.en.html`, and compatibility
  `report.html` files, so local file viewing and served WebUI viewing behave
  consistently.
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
  link for existing report consumers.

## Evidence interaction

Evidence rows are operator-facing. Tables, timeline entries, and raw evidence
blocks should support fast copying:

- Right-click a copyable cell or timeline item to copy its evidence text.
- Click a copy button on raw evidence to copy a complete event block.
- Raw event fields should be sorted and rendered in a collapsible evidence
  block so large driver payloads do not overwhelm the page.
- Raw normalized events should default to a closed summary, show only the first
  200 inline rows in 50-row native pages, and tell the operator exactly how
  many events are hidden.
- The raw section should point to `report.json`, `events.json`,
  `driver-events.jsonl`, and/or artifact manifests when indexed, so operators
  have raw source artifact path hints and can open or copy the full raw source
  instead of relying on an oversized HTML table.
- Indexed artifacts should be opened or downloaded through safe relative report
  links. If only an absolute host/guest path is known, show it as copyable text
  evidence rather than a clickable link.

## Live UI expectations

The WebUI live raw monitor is a dedicated dynamic monitor page linked from the
main dashboard and opened automatically by the upload flow when the browser
allows it. It intentionally shows raw events only. It does not run behavior
classification until the analysis is completed and guest output is imported.
When the page opens from upload, its bilingual hint should tell the operator to
leave the dashboard tab running the analysis request. The live table should
show:

- timestamp
- `eventType`
- source
- process id/name
- path
- command line
- data

When a job fails, the main dashboard should keep the report links, artifact
paths, progress stage status, failed step title/message, exit code, and duration
visible. It should not inline long runbook command text, stdout, or stderr; the
operator can open the execution-flow page and copy `runbook-execution.json` for
deep troubleshooting.

The main dashboard should keep report navigation low-noise: one current-language
primary report button, compact Chinese/English alternatives, a stable automatic
open notice after successful generation/import, a natural progress-page
(`execution-flow`) link beside the progress summary, and the live raw monitor as
a separate page rather than an inline stream.
