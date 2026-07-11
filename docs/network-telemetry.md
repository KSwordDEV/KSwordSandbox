# 网络遥测导入 / Network telemetry import

KSwordSandbox 的宿主侧网络导入把网络证据当作回收 artifact，而不是 live host sniffer。
当前 importer 消费 guest 已收集输出，并生成稳定的字符串字段事件 schema，覆盖 DNS、HTTP、TLS
和 connection/flow telemetry。

## 输入 / Inputs

支持的导入输入：

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

## Tshark 行为 / Tshark behavior

`PcapArtifactEventImporter` 不要求安装 `tshark`。它内置有界 native parser，
覆盖 Ethernet/IPv4/IPv6、TCP/UDP，以及轻量 DNS/HTTP/TLS metadata。

当 `tshark` 不在 `PATH` 中时，导入仍然可以成功，`network.import.summary` 会记录：

- `tsharkRequired=false`
- `tsharkAvailable=false`
- `tsharkStatus=not-found-native-parser-used`
- `parser=native-pcap`

损坏或暂不支持的 capture 会生成 `pcap.parse_error` 和一条 `status=parse_error` 的
`network.import.summary`；这不会让整个 guest event import 失败。

## Guest capture diagnostics vs imported evidence

guest 端的 `packet_capture.protocol_summary` 是抓包文件诊断摘要，不是 DNS/HTTP/TLS
行为证据。若历史或降级字段显示
`protocolSummaryState=capture-metadata-only`、
`protocolSummaryStatus=skipped`、
`protocolSummaryReason=protocolParserNotImplemented`，含义只是 guest 采集行本身只提供
抓包文件可追溯性；不要把它当作“没有网络行为”。请用
`artifactRelativePath` / `sourceArtifactRelativePath`、`sizeBytes` /
`sourceArtifactSizeBytes`、`sha256` / `sourceArtifactSha256`、`packetCount`、
`pcapngBlockCount`、`pcapngEnhancedPacketBlockCount`、
`pcapngSimplePacketBlockCount` 和 `pcapngSectionHeaderCount` 判断证据是否具体。

Concrete protocol evidence 来自宿主 native PCAP importer 或 sidecar importer。报告/规则应优先消费
导入后的 `dns.query`、`http.request`、`tls.connection`、`network.flow` 或 `pcap.*` rows；
上述每一类行都应携带回指 capture 文件的 artifact traceability 字段。

## 事件类型 / Event types

兼容 PCAP rows 仍然输出：

- `pcap.summary`
- `pcap.flow`
- `pcap.dns`
- `pcap.http`
- `pcap.tls`

同时输出标准化 network rows：

- `network.import.summary`
- `network.flow`
- `dns.query`
- `http.request`
- `tls.connection`

Sidecar JSONL/log rows 会直接归一化到标准事件类型。损坏 JSON lines 变成
`network.sidecar.parse_error` rows，而不是让整个 PCAP import 失败。

## 共享字段 schema / Shared field schema

所有 imported network rows 都使用字符串值 `data` fields：

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
  - `ipFamily`: `ipv4` or `ipv6` when an endpoint is present
  - `sourceIp`, `sourcePort`, `srcIp`, `srcPort`, `localAddress`, `localPort`
  - `destinationIp`, `destinationPort`, `dstIp`, `dstPort`,
    `remoteAddress`, `remotePort`
  - `sourceEndpoint`, `destinationEndpoint`, `localEndpoint`,
    `remoteEndpoint`
  - `flowKey`
  - IPv6 endpoint normalization keeps bare addresses in `sourceIp` /
    `destinationIp` and uses brackets only in endpoint strings, for example
    `sourceEndpoint=[2001:db8::10]:5353`.
- Artifact traceability:
  - `sourceArtifactPath`
  - `sourceArtifactRelativePath`
  - `artifactRelativePath`, `downloadSelector`
  - `sourceArtifactSizeBytes`
  - `sourceArtifactSha256`
  - PCAP-native rows expose `pcapSourceArtifactRelativePath`,
    `pcapSourceArtifactName`, `pcapSourceArtifactSizeBytes`, and
    `pcapSourceArtifactSha256`. Adjacent sidecars keep their own
    `sourceArtifactRelativePath` while also preserving the parent capture in
    `pcapSourceArtifactRelativePath` / `sourcePcapArtifactRelativePath`.
  - `collectionName`
  - `evidenceRole`
  - `importMode`

协议字段：

- DNS: `queryName`, `qname`, `domain`, `dnsQueryName`, `queryType`,
  `recordType`, `dnsRecordType`, `rcode`, `rcodeName`, `responseCode`,
  `dnsRcode`, `isResponse`, `answer`, `answers`, `resolvedIps`,
  `answerCount`, `ttl`, `recordClass`, `dnsTransactionId`, `dnsOutcome`,
  `classification`, `isNxDomain`
- HTTP: `httpMessageType`, `method`, `uri`, `requestUri`, `host`, `url`, `userAgent`,
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
  `certSelfSigned`, `certExpired`, `tlsCertificateRisk`. Native PCAP TLS
  parsing derives client-hello SNI/ALPN/cipher hint/JA3, server-hello JA3S
  when present, and best-effort certificate subject/issuer/fingerprint
  metadata from TLS Certificate handshakes without requiring `tshark`.
- Connection: `state`, `durationSeconds`, `packetCount`, `byteCount`,
  `packetsToServer`, `packetsToClient`, `bytesToServer`, `bytesToClient`,
  `uid`, `externalFlowKey`, `communityId`, `applicationProtocol`,
  `flowReason`

如果 source row 暴露 process / lineage 字段，sidecar importer 会尽量保留：

- `processId`, `pid`, `parentProcessId`
- `rootProcessId`, `rootPid`, `processRootId`
- `treeLineage`, `processTreeLineage`
- `processName`, `imageName`, `processImage`, `processPath`,
  `commandLine`, `processRole`
- `rootProcessName`, `rootCommandLine`

中文：sidecar 归一化会尽量保留样本根进程和进程树 lineage。报告里若同时看到
`rootProcessId` / `treeLineage` 与 HTTP 上传、NXDOMAIN、TLS JA3/证书异常，
可以把网络行为直接挂到样本进程树，而不是只把它当作孤立网络流量。

Sidecar alias coverage 有意兼容常见 Zeek/ECS/tshark/R0 字段族，例如 `id.orig_h`、`id.resp_h`、
`orig_bytes`、`resp_bytes`、
`dns.rrname`, `dns.answers`, `http.response.status_code`,
`http.request.body.bytes`, `tls.ja3.hash`, `tls.cert.fingerprint.sha256`,
`network.community_id`, and `process.entry_leader.*`. Sensitive HTTP headers
are not copied verbatim; the importer records `authorizationHeaderPresent` and
`cookiePresent` booleans instead.

Sidecar 专属字段：

- `sidecarLineNumber`
- `sidecarFormat`: `jsonl` or `log`
- `parser=sidecar-jsonl`
- `originalEventType` when the input row exposed one

Log sidecar 是弱解析：importer 识别带引号或不带引号的 `key=value` / `key: value` token、
endpoint arrow、HTTP request line、DNS query token 和 TLS SNI token。无法识别的普通 log line
会被忽略，以避免制造虚假网络证据。

## R0 网络状态诊断 / R0 network status diagnostics

`r0collector.driverNetworkStatus` 不是样本网络行为，而是 R0/WFP/ALE 采集质量证据。报告和 WebUI
应把它放在 R0 health / readiness 区，而不是 DNS/HTTP/TLS 行为列表。

成功读取 driver IOCTL 时，该行可包含：

- `diagnosticStage=networkStatus`
- `networkStatusAvailable=true`
- `supportedLayerMask*`、`activeLayerMask*`、`lastRegisteredCalloutMask*`、`lastAddedFilterMask*`
- `todoMask*`
- `classifyCount`、`eventCount`、`queueFailureCount`、`classifyPayloadFailureCount`
- `lastDegradeReasonName`、`registerNtStatusHex`、`engineNtStatusHex`、`lastQueueFailureNtStatusHex`
- `readinessState`、`zhMessage`、`zhHint`

IOCTL 不可用、旧 driver 协议不匹配或 device 打不开时，Collector 应输出同一 event type 的 degraded
诊断行，例如 `networkStatusAvailable=false`、`diagnosticCode=network_status_ioctl_unavailable`。
这表示采集能力/版本边界，不表示样本规避或恶意网络行为。

## 汇总事件 / Summary event

`network.import.summary` 会在 PCAP import 和 guest artifact aggregate import 时生成。
它记录计数和 parser 状态，包括：

- `artifactCount`, `pcapArtifactCount`, `sidecarArtifactCount`
- `eventCount`
- `connectionEventCount`, `dnsEventCount`, `httpEventCount`, `tlsEventCount`
- `parseErrorCount`
- `protocols`
- `manifestPresent` for guest-root aggregate imports
- `tsharkRequired`, `tsharkAvailable`, `tsharkStatus` for PCAP imports

该事件是网络导入健康状态的稳定 report/search anchor；行为规则仍应使用协议级 rows 作为证据。

`collectionHealth` 从 imported rows 推导：

- `ok`: row has enough endpoint/protocol context and no parse errors.
- `partial`: a protocol row was imported but endpoint context is incomplete.
- `empty`: an aggregate import found no network evidence rows.
- `degraded`: malformed PCAP/sidecar rows or parse errors were observed.
