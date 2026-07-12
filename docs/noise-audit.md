# Noise audit and conclusion boundary

This note documents the current report/audit boundary for normal GUI samples and collector/system/readiness noise.

- `sampleCorrelation=confirmed|probable` may be shown as behavior candidates.
- `sampleCorrelation=environment|unknown`, `nonbehavior=true`, `behaviorCounted=false`, `notSampleBehavior=true`, collector self-noise, VT quiet states, and R0/readiness diagnostics are retained as evidence but are not promoted to primary sample conclusions.
- Normal interactive GUI baselines are reserved for trusted benign presets such as Notepad, and are tagged with `normalBehaviorBoundary=normal-interactive-gui-baseline` only when the row is limited to process/window/metadata activity. Do not add unknown sample family names to this allowlist; stealthy malware may intentionally look like a quiet GUI application.
- `JobTool audit --json` emits machine-readable correlation histograms, retained-not-promoted counts, system actor counts, and bounded weak-evidence examples for release review.
- HTML reports embed `ksword.report.behavior-routing-stats.v1` under the Collection/self-noise policy card so reviewers can copy routing statistics without parsing the page.

Calibration still requires real benign GUI and malicious samples; the boundary is conservative and intended to prevent environment/system/readiness evidence from contaminating the main conclusion.
