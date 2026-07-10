# Live telemetry pipeline

The WebUI live monitor is intentionally raw-event focused. It should show what
the guest and driver are producing while the job is running, without waiting
for final rule classification.

## v1 data flow

1. Host stages the prepared Guest Agent and R0Collector payload from
   `paths.guestPayloadRoot` into the guest.
2. Guest Agent writes `events.json` under a job-specific guest output folder,
   for example `C:\KSwordSandbox\out\<job-id-n>`.
3. R0Collector writes `driver-events.jsonl` beside `events.json`.
4. Host starts the Guest Agent asynchronously, then a runbook
   `sync-live-output` step periodically copies that guest output tree into
   `D:\Temp\KSwordSandbox\jobs\<job-id-n>\guest`.
5. Core live telemetry services read JSON/JSONL with shared-read tolerance.
6. WebUI consumes `/api/jobs/{jobId}/events/stream` when available, or polls
   `/api/jobs/{jobId}/events/live` as the fallback, and appends unclassified
   rows.
7. After completion, Host imports events, runs rules, and regenerates reports.

## Important boundary

Live display is not a verdict. It is a visibility channel for process, file,
registry, image, and network events. Risk scoring and MITRE mapping belong to
the final report regeneration path.

## Current v1 implementation

The live path is still PowerShell Direct based, not a socket stream. The host
opens a PSSession, copies the guest output tree while the Guest Agent wrapper
process is running, and performs one final copy after the process exits. This
keeps v1 deployable in a default Hyper-V Windows 10 guest without installing a
guest TCP/WebSocket service.

## API surface

The live monitor has two browser-facing surfaces:

- `GET /api/jobs/{jobId}/events/stream` for Server-Sent Events (SSE).
- `GET /api/jobs/{jobId}/events/live` for JSON polling fallback.

Both surfaces return raw, normalized telemetry. They do not classify behavior,
score risk, or regenerate reports.

### Polling snapshot

```http
GET /api/jobs/{jobId}/events/live?offset=0&take=100
Accept: application/json
```

The response is a camelCase `LiveEventSnapshot`:

- `jobId`: requested job identifier.
- `retrievedAt`: host UTC time when the snapshot was assembled.
- `totalEvents`: number of currently visible raw events.
- `nextOffset`: offset to pass to the next polling request.
- `hasMore`: `true` when the current page did not include every visible event.
- `sources`: host-side JSON or JSONL files used for the snapshot.
- `events`: unclassified `SandboxEvent` rows.

Query behavior:

- `offset` is a zero-based event cursor. Negative or missing values are treated
  as `0`.
- `take` is the requested page size. Missing values default to `100`; the
  service clamps values to the safe range `1..500`.
- `intervalMs` is not used by the polling endpoint. Polling cadence is owned by
  the browser or QA script.

Clients should treat `nextOffset` as the only cursor they own. When
`hasMore=true`, call the endpoint again immediately with `offset=nextOffset`.
When `hasMore=false` and the job is still running, wait briefly and poll again
with the same `nextOffset`; new rows will appear after the runbook copies the
guest output tree.

### SSE stream

`GET /api/jobs/{jobId}/events/stream` keeps an HTTP response open and emits
snapshot frames compatible with the same `LiveEventSnapshot` shape returned by
polling.

Request:

```http
GET /api/jobs/{jobId}/events/stream?offset=0&take=100&intervalMs=2000
Accept: text/event-stream
Cache-Control: no-cache
```

Successful response:

- HTTP `200`.
- `Content-Type: text/event-stream`.
- `Cache-Control: no-cache`.
- `X-Accel-Buffering: no` to discourage proxy buffering.
- No behavior classification or verdict calculation in the stream path.
- Event order and paging match the current polling ordering.
- Each pushed frame is a snapshot, not a single-row event.
- `event:` is `snapshot`.
- `data:` contains one camelCase JSON `LiveEventSnapshot`.

Query behavior:

- `offset` is the initial zero-based event cursor. Negative or missing values are
  treated as `0`.
- `take` is the requested per-frame page size. Missing values default to `100`;
  the service clamps values to `1..500`.
- `intervalMs` controls the server-side delay between snapshot reads. Missing
  values default to `2000`; the service clamps values to `500..10000`.

Example frame:

```text
event: snapshot
data: {"jobId":"00000000-0000-0000-0000-000000000000","retrievedAt":"2026-07-10T08:00:00Z","totalEvents":7,"nextOffset":7,"hasMore":false,"sources":["D:\\Temp\\KSwordSandbox\\jobs\\...\\events.json"],"events":[{"eventType":"process.start","timestamp":"2026-07-10T08:00:00Z","source":"guest","processName":"sample.exe","processId":4242,"data":{}}]}

```

Reconnect behavior:

- Reconnect with `offset=<last nextOffset>` from the most recent snapshot.
- Clamp negative or malformed offsets to `0` on the client side before sending
  the next request.
- Do not replay duplicate rows for a valid cursor.
- Close promptly when the HTTP client disconnects.

## Polling fallback

Polling remains the required fallback for the WebUI and QA probes when SSE is
unavailable or unsuitable. A client should fall back to
`/api/jobs/{jobId}/events/live?offset=<lastOffset>&take=100` when:

- `/api/jobs/{jobId}/events/stream` returns `404`, `405`, or `501`.
- The response is not `text/event-stream`.
- The connection fails before receiving response headers.
- A proxy or local test harness buffers SSE and makes it unusable.

The fallback is loss-tolerant because the server-side cursor is an integer
offset over the current raw event snapshot. The client keeps the most recent
`nextOffset`, polls until `hasMore=false`, then continues slower polling while
the job remains `Running`. After the job completes, one final poll followed by
guest-event import/report refresh is sufficient.
