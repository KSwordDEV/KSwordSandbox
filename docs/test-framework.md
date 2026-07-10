# Smoke test framework

The smoke-test project is a console project, so the first framework layer uses
small scenario classes instead of adding a test framework dependency.

Current expansion points:

- `Framework`: scenario interface, context, suite, and result records.
- `Assertions`: dependency-free assertion helpers.
- `Scenarios`: focused checks such as repository layout, synthetic event import,
  report generation, and HTML section assertions.
- `scripts/Test-ProjectFramework.ps1`: quick path-level validation.

Recommended next scenarios:

1. Synthetic `events.json` import refreshes `report.json` and `report.html`.
2. Report HTML contains process, file, network, MITRE, and raw event sections.
3. Repository policy rejects binaries, VM disks, PDFs, and build artifacts.
4. R0Collector mock JSONL can be imported as live telemetry.
