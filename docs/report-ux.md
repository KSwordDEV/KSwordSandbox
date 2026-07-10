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
- MITRE mapping / MITRE 映射.
- Engine/rule hits.
- Static analysis / 静态分析 with PE sections, URLs, strings, warnings, and tags.
- Dynamic summary / 动态分析.
- Timeline.
- Process details / 进程, including the Process tree and process event table.
- File behavior / 文件, including dropped files.
- Registry behavior / 注册表.
- Network behavior / 网络.
- R0 / driver events.
- Failure reasons / 失败原因.
- Raw normalized events / 原始事件.


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
- The report must support Chinese and English rendering entrypoints, or
  equivalent core renderer support for `report.zh.html` and `report.en.html`.
- Each generated HTML report should expose an in-report bilingual entry bar
  linking the sibling `report.zh.html`, `report.en.html`, and compatibility
  `report.html` files, so local file viewing and served WebUI viewing behave
  consistently.
- Jobs should keep report path fields suitable for automatic WebUI links, so a
  completed plan can expose the default report plus localized report clues
  without asking the operator to paste a filesystem path.
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

## Live UI expectations

The WebUI live raw monitor is a dedicated page linked from the main dashboard.
It intentionally shows raw events only. It does not run behavior classification
until the analysis is completed and guest output is imported. The live table
should show:

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
open notice after successful generation/import, and the live raw monitor as a
separate page rather than an inline stream.
