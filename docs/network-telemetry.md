# Network telemetry import

KSwordSandbox host import treats network evidence as artifacts, not as a live
host sniffer. The current importer consumes collected guest outputs and emits a
stable string-valued event schema for DNS, HTTP, TLS, and connection telemetry.

## Inputs

Supported import inputs:

- Guest `artifacts/manifest.json` descriptors for `PacketCapture` artifacts.
- `.pcap` and `.pcapng` files under collected guest output, typically
  `packet-captures/**`.
- Packet-capture sidecar JSONL/log files beside captures, for example
  `*.dns.jsonl`, `*.http.jsonl`, `*.tls.jsonl`, `*.conn.jsonl`, `tshark*.jsonl`,
  Zeek-like JSONL, or KSword/R0 network JSONL rows.
- Weak sidecar log rows without strict JSON, including `key=value` or
  `key: value` tokens and loose flow text such as
  `10.0.0.4:50200 -> 198.51.100.77:8080`.

The host resolves manifest `relativePath` / `importPath` only under the
collected guest output root. Absolute VM-local paths remain evidence strings and
are not trusted as import targets.

## Tshark behavior

`PcapArtifactEventImporter` does not require `tshark`. It uses a bounded native
parser for Ethernet/IPv4/TCP/UDP plus lightweight DNS/HTTP/TLS metadata.

When `tshark` is not on `PATH`, import still succeeds and
`network.import.summary` records:

- `tsharkRequired=false`
- `tsharkAvailable=false`
- `tsharkStatus=not-found-native-parser-used`
- `parser=native-pcap`

Malformed or unsupported captures emit `pcap.parse_error` plus a
`network.import.summary` row with `status=parse_error`; they do not fail the
whole guest event import.

## Event types

Compatibility PCAP rows are still emitted:

- `pcap.summary`
- `pcap.flow`
- `pcap.dns`
- `pcap.http`
- `pcap.tls`

Standardized network rows are emitted alongside them:

- `network.import.summary`
- `network.flow`
- `dns.query`
- `http.request`
- `tls.connection`

Sidecar JSONL/log rows are normalized directly to the standardized event types.
Malformed JSON lines become `network.sidecar.parse_error` rows instead of
failing the whole PCAP import.

## Shared field schema

All imported network rows carry string-valued `data` fields:

- `schema=network.telemetry.v1`
- `eventFamily=network`
- `eventKind`: `summary`, `connection`, `dns`, `http`, `tls`, or `parse_error`
- `importSource`: `pcap-native`, `sidecar-jsonl`, or aggregate import metadata
- Collection and operator fields:
  - `collectionHealth`: `ok`, `partial`, `empty`, or `degraded`
  - `zhMessage`: concise Chinese operator-facing summary
  - `zhHint`: concise Chinese triage hint
- Endpoint aliases:
  - `protocol`, `transportProtocol`, `protocolName`
  - `sourceIp`, `sourcePort`, `srcIp`, `srcPort`, `localAddress`, `localPort`
  - `destinationIp`, `destinationPort`, `dstIp`, `dstPort`,
    `remoteAddress`, `remotePort`
  - `sourceEndpoint`, `destinationEndpoint`, `localEndpoint`,
    `remoteEndpoint`
  - `flowKey`
- Artifact traceability:
  - `sourceArtifactPath`
  - `sourceArtifactRelativePath`
  - `sourceArtifactSizeBytes`
  - `sourceArtifactSha256`
  - `collectionName`
  - `evidenceRole`
  - `importMode`

Protocol-specific fields:

- DNS: `queryName`, `qname`, `domain`, `queryType`, `recordType`, `rcode`,
  `isResponse`
- HTTP: `method`, `uri`, `requestUri`, `host`, `url`, `userAgent`,
  `contentType`, `statusCode`, `payloadMagic`
- TLS: `sni`, `serverName`, `tlsVersion`, `handshakeType`, `ja3`, `ja3s`,
  `alpn`, `cipherSuite`
- Connection: `state`, `durationSeconds`, `packetCount`, `byteCount`, `uid`

Sidecar-specific fields:

- `sidecarLineNumber`
- `sidecarFormat`: `jsonl` or `log`
- `parser=sidecar-jsonl`
- `originalEventType` when the input row exposed one

Log sidecars are intentionally weakly parsed. The importer recognizes quoted
and unquoted `key=value` / `key: value` tokens, endpoint arrows, HTTP request
lines, DNS query tokens, and TLS SNI tokens. Unrecognized plain log lines are
ignored to avoid false network evidence.

## Summary event

`network.import.summary` is generated for PCAP imports and for guest artifact
aggregate imports. It records counts and parser state, including:

- `artifactCount`, `pcapArtifactCount`, `sidecarArtifactCount`
- `eventCount`
- `connectionEventCount`, `dnsEventCount`, `httpEventCount`, `tlsEventCount`
- `parseErrorCount`
- `protocols`
- `manifestPresent` for guest-root aggregate imports
- `tsharkRequired`, `tsharkAvailable`, `tsharkStatus` for PCAP imports

This event is intended as the stable report/search anchor for network import
health, while protocol-specific rows remain the evidence used by behavior rules.

`collectionHealth` is derived from the imported rows:

- `ok`: row has enough endpoint/protocol context and no parse errors.
- `partial`: a protocol row was imported but endpoint context is incomplete.
- `empty`: an aggregate import found no network evidence rows.
- `degraded`: malformed PCAP/sidecar rows or parse errors were observed.
