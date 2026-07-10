# Report and WebUI UX contract

The v1 report must be useful during a live demo, not merely technically
complete. The page should let an operator answer three questions quickly:

1. What is the risk?
2. What behavior proves that risk?
3. Where are the raw artifacts and original events?

## Report sections

Required `report.html` sections:

- Cover with job id, generation time, verdict, sample identity, and hashes.
- Table of contents.
- Risk summary cards.
- Behavior detections.
- MITRE mapping.
- Engine/rule hits.
- Static analysis with PE sections, URLs, strings, warnings, and tags.
- Dynamic summary.
- Timeline.
- Process tree and process event table.
- File behavior / dropped files.
- Registry behavior.
- Network behavior.
- Failure reasons.
- Raw normalized events.

## Evidence interaction

Evidence rows are operator-facing. Tables, timeline entries, and raw evidence
blocks should support fast copying:

- Right-click a copyable cell or timeline item to copy its evidence text.
- Click a copy button on raw evidence to copy a complete event block.
- Raw event fields should be sorted and rendered in a collapsible evidence
  block so large driver payloads do not overwhelm the page.

## Live UI expectations

The WebUI live monitor intentionally shows raw events only. It does not run
behavior classification until the analysis is completed and guest output is
imported. The live table should show:

- timestamp
- `eventType`
- source
- process id/name
- path
- command line
- data

When a job fails, the dashboard should keep the runbook stdout/stderr, exit
code, duration, and failure message visible next to the report/artifact paths.
