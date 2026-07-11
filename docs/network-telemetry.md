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

## Guest capture diagnostics vs imported evidence

中文优先：guest 端的 `packet_capture.protocol_summary` 是抓包文件诊断摘要，
不是 DNS/HTTP/TLS 行为证据。若字段显示
`protocolSummaryState=capture-metadata-only`、
`protocolSummaryStatus=skipped`、
`protocolSummaryReason=protocolParserNotImplemented`，含义是 PCAP/PCAPNG
文件已经可追溯，但内置协议摘要解析尚未接入；请用
`artifactRelativePath` / `sourceArtifactRelativePath`、`sizeBytes` /
`sourceArtifactSizeBytes`、`sha256` / `sourceArtifactSha256`、`packetCount`、
`pcapngBlockCount`、`pcapngEnhancedPacketBlockCount`、
`pcapngSimplePacketBlockCount` 和 `pcapngSectionHeaderCount` 判断证据是否具体。

The capture diagnostic row remains as a stable report/search anchor until
inline protocol parsing is available. It should not be used as a substitute
for imported `dns.query`, `http.request`, `tls.connection`, `network.flow`, or
`pcap.*` rows. Concrete protocol evidence comes from the native PCAP importer
or sidecar importers described below, each carrying artifact traceability
fields back to the capture file.

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

- DNS: `queryName`, `qname`, `domain`, `dnsQueryName`, `queryType`,
  `recordType`, `dnsRecordType`, `rcode`, `rcodeName`, `responseCode`,
  `dnsRcode`, `isResponse`, `answer`, `answers`, `resolvedIps`,
  `answerCount`, `ttl`, `recordClass`, `dnsTransactionId`, `dnsOutcome`,
  `classification`, `isNxDomain`
- HTTP: `method`, `uri`, `requestUri`, `host`, `url`, `userAgent`,
  `contentType`, `statusCode`, `responseStatusCode`, `httpStatusCode`,
  `statusFamily`, `payloadMagic`, `referer`, `contentEncoding`,
  `requestBodyBytes`, `requestBytes`, `responseBodyBytes`, `responseBytes`,
  `requestContentLength`, `responseContentLength`, `uploadBytes`,
  `downloadBytes`, `uploadCandidate`, `transferDirection`,
  `authorizationHeaderPresent`, `cookiePresent`
- TLS: `sni`, `serverName`, `tlsVersion`, `handshakeType`, `ja3`, `ja3s`,
  `ja3Hash`, `ja3sHash`, `alpn`, `cipherSuite`, `certSubject`, `certIssuer`,
  `certSerial`, `certSha256`, `certificateSha256`,
  `certificateFingerprintSha256`, `certSha1`, `certNotBefore`,
  `certNotAfter`, `certificateStatus`, `validationStatus`,
  `certSelfSigned`, `certExpired`, `tlsCertificateRisk`
- Connection: `state`, `durationSeconds`, `packetCount`, `byteCount`,
  `packetsToServer`, `packetsToClient`, `bytesToServer`, `bytesToClient`,
  `uid`, `externalFlowKey`, `communityId`, `applicationProtocol`,
  `flowReason`

Sidecar process / lineage fields are propagated when the source row exposes
them:

- `processId`, `pid`, `parentProcessId`
- `rootProcessId`, `rootPid`, `processRootId`
- `treeLineage`, `processTreeLineage`
- `processName`, `imageName`, `processImage`, `processPath`,
  `commandLine`, `processRole`
- `rootProcessName`, `rootCommandLine`

中文：sidecar 归一化会尽量保留样本根进程和进程树 lineage。报告里若同时看到
`rootProcessId` / `treeLineage` 与 HTTP 上传、NXDOMAIN、TLS JA3/证书异常，
可以把网络行为直接挂到样本进程树，而不是只把它当作孤立网络流量。

Sidecar alias coverage intentionally accepts common Zeek/ECS/tshark/R0 field
families such as `id.orig_h`, `id.resp_h`, `orig_bytes`, `resp_bytes`,
`dns.rrname`, `dns.answers`, `http.response.status_code`,
`http.request.body.bytes`, `tls.ja3.hash`, `tls.cert.fingerprint.sha256`,
`network.community_id`, and `process.entry_leader.*`. Sensitive HTTP headers
are not copied verbatim; the importer records `authorizationHeaderPresent` and
`cookiePresent` booleans instead.

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
