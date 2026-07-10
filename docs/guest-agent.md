# Guest Agent behavior events

The guest agent runs inside the analysis VM and keeps the existing command-line
contract:

```text
--sample <path> --out <directory> [--duration <seconds>] [--driver-events <path>]
```

Optional R0 sidecar flags extend the contract without changing the existing
arguments:

```text
[--r0collector <path>] [--driver-device <path>] [--r0-mock]
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
- `r0collector.start_failed` if the optional sidecar process could not be
  created. This event is emitted by the agent and does not fail the whole run.
- `r0collector.stop_forced` / `r0collector.stop_failed` only when the agent had
  to terminate the sidecar or could not finish sidecar shutdown cleanly.

The event model remains `KSword.Sandbox.Abstractions.SandboxEvent`; additional
details are carried in the existing string `Data` dictionary to avoid changing
shared Core/Web/Abstractions contracts.

## Optional R0Collector sidecar

When both `--r0collector <path>` and `--driver-events <jsonl>` are supplied, the
agent starts `KSword.Sandbox.R0Collector.exe` before launching the sample. The
sidecar is invoked with:

```text
--device <driver-device> --output <driver-events> --duration <duration>
```

`--driver-device` defaults to `\\.\KSwordSandboxDriver` when omitted. Supplying
`--r0-mock` makes the agent forward `--mock` to the sidecar, which allows local
or CI plumbing tests without an installed kernel driver.

After the sample exits or times out, the agent waits briefly for the sidecar to
exit. If it is still running, the agent terminates the sidecar process tree so
the JSONL file can be closed and read. The agent then reads `--driver-events`
and merges those JSONL rows into `events.json`.

If the sidecar executable is missing, cannot be started, or the JSONL parent
directory cannot be prepared, the agent adds `r0collector.start_failed` to the
guest events and continues with normal user-mode collection.

## Driver JSONL compatibility

Driver sidecars such as `KSword.Sandbox.R0Collector` should write one
`SandboxEvent`-compatible JSON object per line. The guest agent reads these
events case-insensitively, so both `eventType` and `EventType` are accepted.

The current shared model keeps `Data` as `Dictionary<string,string>`. Driver
JSONL producers must therefore serialize values inside `data` as strings, for
example:

```json
{"eventType":"registry.set","source":"driver","processId":4242,"path":"HKCU\\Software\\Run","data":{"value":"C:\\sample.exe","win32Error":"0"}}
```

Top-level numeric fields such as `processId` may remain JSON numbers.
