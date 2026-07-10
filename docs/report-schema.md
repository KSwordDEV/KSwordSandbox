# Report schema

## JSON artifacts

The host writes `report.json` beside `report.html` for every planned job. The
JSON model is `AnalysisReport`:

- `jobId`
- `sample`
- `generatedAt`
- `status`
- `events`
- `findings`
- `metrics`

Guest collection writes `events.json` and `agent-summary.json` under the guest
output directory before the host collects them.

## HTML sections

The v1 HTML report includes:

- summary and sample identity;
- behavior findings with MITRE seed mappings;
- normalized event table.

Future sections should keep the same source model and add rendered sections for
table of contents, risk summary, behavior detections, multi-dimensional
detections, engine/rule hits, static analysis, dynamic analysis, process tree,
dropped files, network timeline, screenshots, driver health, and failure
reasons. The target structure is summarized in
`docs/microstep-report-benchmark.md`.
