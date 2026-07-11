# Smoke test framework

Historical framework note. The current operator-facing smoke overview is
`docs/testing.md`, and the command source of truth is `docs/verification.md`.
Keep this page limited to smoke-test project structure; do not add duplicate
quality-gate command blocks here.

The smoke-test project is a console project, so the first framework layer uses
small scenario classes instead of adding a test framework dependency.

Current expansion points:

- `Framework`: scenario interface, context, suite, and result records.
- `Assertions`: dependency-free assertion helpers.
- `Scenarios`: focused checks such as repository layout, synthetic event import,
  report generation, and HTML section assertions.
- `scripts/Test-ProjectFramework.ps1`: quick path-level validation.

Current smoke coverage to keep lightweight:

1. Synthetic `events.json` import refreshes `report.json` and `report.html`.
2. Sibling `driver-events.jsonl` is imported with the guest events; the
   synthetic `r0collector.mockDriverEvent` row appears in `report.json`,
   `report.html`, findings, and live raw event snapshots without requiring a
   real Hyper-V VM or driver.
3. Repository policy rejects binaries, VM disks, PDFs, and build artifacts.
4. Report HTML contains process, file, network, MITRE, and raw event sections.
