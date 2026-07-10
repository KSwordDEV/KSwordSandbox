# Guest Agent framework

The Guest Agent currently works as a compact executable, but the project now
has module boundaries for larger implementation:

- `Collection`: guest probes, probe phases, and event sink.
- `Execution`: sample launch plans and process execution results.
- `Output`: `events.json`, `agent-summary.json`, and driver JSONL import.
- `Options`: command-line switch constants and parsed option models.
- `Diagnostics`: normalized diagnostic event creation.

The current `Program.cs` can continue serving the MVP. Future refactors should
move logic into the framework files without changing CLI compatibility:

```text
--sample <path> --out <directory> --duration <seconds>
--driver-events <jsonl> --r0collector <path> --driver-device <path>
```

The driver sidecar remains optional so VM smoke tests can proceed without a
signed driver.
