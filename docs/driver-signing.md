# Driver signing and R0 event export

## Scope

The sandbox repository does not store driver binaries, certificates, private
keys, PDB files, or WDK build outputs. It only documents the integration point
for the KSword driver family.

## Expected event bridge

The guest agent can ingest driver events from JSON Lines:

```json
{"eventType":"registry.set","source":"driver","processId":1234,"path":"HKCU\\Software\\Example","data":{"value":"Run"}}
{"eventType":"file.created","source":"driver","processId":1234,"path":"C:\\Users\\SandboxUser\\AppData\\Local\\drop.bin"}
```

Each line should deserialize to the shared `SandboxEvent` shape. Invalid lines
are preserved as `driver.parse_error` events so the report exposes integration
problems instead of silently losing data.

## Signing notes

- Use a test-signed driver only in an isolated test VM.
- Keep test certificates and private keys outside this repository.
- Record the driver service name in local config through `Driver.ServiceName`.
- Record the guest output path through `Driver.EventJsonLinesPath`.

## Reuse boundary from KSword5.1

Prefer reusing protocol definitions and driver-client boundaries from
`D:\Projects\Ksword5.1\shared\driver`, `KswordARKDriver`, and `ArkDriverClient`
as source references. Do not copy the full source tree, generated binaries,
certificates, or `APIMonitor_x64` into this repository.
