# Guest Agent behavior events

The guest agent runs inside the analysis VM and keeps the existing command-line
contract:

```text
--sample <path> --out <directory> [--duration <seconds>] [--driver-events <path>]
```

It still writes two JSON artifacts under `--out`:

- `events.json` - ordered `SandboxEvent` entries collected in the guest.
- `agent-summary.json` - compact run metadata with sample path, event count, and
  generation time.

## Event coverage

The current guest collector emits these host-reportable event groups:

- `agent.start` / `agent.stop` for collector lifecycle.
- `environment.snapshot` before sample launch, including OS description, user,
  machine name, current directory, selected sample working directory, and
  process/OS architecture.
- `process.observed` for the pre-launch process list baseline.
- `process.start`, `process.timeout`, and `process.exit` for the launched
  sample process.
- `process.new` for processes visible after sample launch or after the run that
  were not present in the pre-launch baseline.
- `file.created`, `file.modified`, and `file.deleted` for files changed under
  the sample working directory.
- `network.tcp` for new TCP connections visible in the post-run TCP snapshot.
  Each event keeps the legacy `connection` string and also includes structured
  `local`, `remote`, `state`, `localAddress`, `localPort`, `remoteAddress`, and
  `remotePort` fields in `Data`.
- Driver JSONL events from `--driver-events`, preserving driver-provided fields
  and defaulting missing sources to `driver`.

The event model remains `KSword.Sandbox.Abstractions.SandboxEvent`; additional
details are carried in the existing string `Data` dictionary to avoid changing
shared Core/Web/Abstractions contracts.
