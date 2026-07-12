# 网络遥测导入 / Network telemetry import

KSwordSandbox 的宿主侧网络导入把网络证据当作已回收证据产物（artifact），而不是实时宿主抓包器（live host sniffer）。
当前导入器（importer）消费 guest 已收集输出，并生成稳定的字符串字段事件 schema，覆盖 DNS、HTTP、TLS
和连接/流量遥测（connection/flow telemetry）。

## 输入 / Inputs

支持的导入输入：

- Guest `artifacts/manifest.json` 中指向 `PacketCapture` artifacts 的 descriptors。
- Collected guest output 下的 `.pcap` 和 `.pcapng` 文件，通常位于
  `packet-captures/**`。
- Capture 文件旁边的 packet-capture sidecar JSONL/log 文件，例如
  `*.dns.jsonl`, `*.http.jsonl`, `*.tls.jsonl`, `*.conn.jsonl`, `tshark*.jsonl`,
  Zeek-like JSONL 或 KSword/R0 network JSONL rows。
- 非严格 JSON 的弱结构 sidecar log rows，包括 `key=value` 或
  `key: value` tokens，以及类似下方的 loose flow text：
  `10.0.0.4:50200 -> 198.51.100.77:8080`。

Host 只在已收集的 guest 输出根目录（collected guest output root）下解析 manifest `relativePath` / `importPath`。VM 内绝对路径（absolute VM-local paths）
只保留为 evidence strings，不能作为 import targets 信任。

## Tshark 行为 / Tshark behavior

`PcapArtifactEventImporter` 不要求安装 `tshark`。它内置有界原生解析器（native parser），
覆盖 Ethernet/IPv4/IPv6、TCP/UDP，以及轻量 DNS/HTTP/TLS 元数据。
PCAP 行会显式携带 bounded parser 元数据，包括 `parserInputKind=packet-capture`、
`parserBounded=true`、`parserMaxPackets`、`parserMaxPayloadBytes`、
`parserMaxProtocolEvents`、`parserMaxFlowEvents`、`parserPacketLimitHit` 和
`parserProtocolEventLimitHit`（适用时）。这些字段说明解析边界，不代表样本行为。

当 `tshark` 不在 `PATH` 中时，导入仍然可以成功，`network.import.summary` 会记录：

- `tsharkRequired=false`
- `tsharkAvailable=false`
- `tsharkStatus=not-found-native-parser-used`
- `parser=native-pcap`

损坏或暂不支持的 capture 会生成 `pcap.parse_error` 和一条 `status=parse_error` 的
`network.import.summary`；这不会让整个 guest event import 失败。
解析边界诊断会稳定携带 `diagnosticCode`、`parserBoundary`、`parseFailureStage`、
`byteOffset`、`expectedBytes`、`actualBytes`（可用时）和中文 `zhHint`，用于区分
PCAP global header、packet header/payload、PCAPNG block body/trailer 等截断或长度异常。

## Guest 抓包诊断与导入证据 / Guest capture diagnostics vs imported evidence

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

具体协议证据（protocol evidence）来自宿主原生 PCAP 导入器或 sidecar 导入器。报告/规则应优先消费
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

Sidecar JSONL/log 行会直接归一化到标准事件类型。损坏 JSON lines 变成
`network.sidecar.parse_error` rows，而不是让整个 PCAP import 失败。

## 共享字段 Schema / Shared field schema

所有导入后的网络行（network rows）都使用字符串值 `data` 字段：

- `schema=network.telemetry.v1`
- `eventFamily=network`
- `eventKind`: `summary`, `connection`, `dns`, `http`, `tls`, `health` 或 `parse_error`
- `importSource`: `pcap-native`, `sidecar-jsonl` 或 aggregate import metadata
- Provenance / behavior metadata:
  - `provenance=host-imported-guest-artifact`
  - `importProvenance=host-imported-network-artifact`
  - `importMode`: `pcap-artifact`, `sidecar-artifact`, `guest-artifact-aggregate` 等
  - `behaviorCounted`, `nonbehavior`, `behaviorScope`
  - `sourceComponent`, `collectorProcessName`, `noisePolicy`
  - `collectorSelfNoise`, `collectorNoiseScope`, `sampleBehaviorBoundary`
  - `network.import.summary`, `pcap.summary`, `network.health` 和
    `*.parse_error` rows 标记为 `behaviorCounted=false` / `nonbehavior=true`；
    实际 DNS/HTTP/TLS/connection packet facts 保持 `behaviorCounted=true`，
    以便规则继续把协议事实作为行为证据。
  - 当 sidecar process/telemetry 字段可识别
    `KSword.Sandbox.R0Collector.exe` / `r0collector.*` 时，导入器会补充
    `collectorProcessName`、`sourceComponent=ksword-r0collector` 和
    `noisePolicy=collector-self-noise-filterable`、
    `collectorSelfNoise=true`、`collectorNoiseScope=collector-self-noise`、
    `sampleBehaviorBoundary=collector-separated`，帮助规则过滤采集器自噪声；
    这不改变 DNS/HTTP/TLS packet facts 本身的行为可计数属性。
- Collection 与操作者字段：
  - `collectionHealth`: `ok`, `partial`, `empty` 或 `degraded`
  - `zhMessage`: 面向操作者的简短中文摘要
  - `zhHint`: 简短中文 triage 提示
- 端点别名（endpoint aliases）：
  - `protocol`, `transportProtocol`, `protocolName`
  - `ipFamily`: endpoint 存在时为 `ipv4` 或 `ipv6`
  - `sourceIp`, `sourcePort`, `srcIp`, `srcPort`, `localAddress`, `localPort`
  - `destinationIp`, `destinationPort`, `dstIp`, `dstPort`,
    `remoteAddress`, `remotePort`
  - `sourceEndpoint`, `destinationEndpoint`, `localEndpoint`,
    `remoteEndpoint`
  - `flowKey`
  - IPv6 endpoint normalization 会在 `sourceIp` / `destinationIp` 中保留裸地址，
    只在 endpoint strings 中使用方括号，例如
    `sourceEndpoint=[2001:db8::10]:5353`。
- Artifact traceability（证据回溯字段）：
  - `sourceArtifactPath`
  - `sourceArtifactRelativePath`
  - `artifactRelativePath`, `downloadSelector`
  - `sourceArtifactSelector`, `artifactSelector`, `sourceDownloadSelector`
  - `sourceArtifactSizeBytes`, `sizeBytes`, `artifactSizeBytes`
  - `sourceArtifactSha256`, `sha256`, `hash.sha256`, `artifactSha256`,
    `artifactHashSha256`
  - PCAP-native rows 暴露 `pcapSourceArtifactRelativePath`、
    `pcapSourceArtifactName`、`pcapSourceArtifactSelector`、`pcapDownloadSelector`、
    `pcapSourceArtifactSizeBytes` 和 `pcapSourceArtifactSha256`。相邻 sidecars
    保留自己的 `sourceArtifactRelativePath` / `sourceArtifactSha256`，同时用
    `pcapSourceArtifactRelativePath` / `sourcePcapArtifactRelativePath`、
    `pcapSourceArtifactSha256` / `sourcePcapArtifactSha256` 和
    `pcapDownloadSelector` / `sourcePcapDownloadSelector` 保留 parent capture。
    Guest-root aggregate import 会对同目录同 basename 的 sidecar 自动关联 sibling PCAP。
  - `collectionName`
  - `evidenceRole`
  - `importMode`
  - `importArtifactRole`, `importArtifactKind`, `importArtifactName`,
    `importArtifactRelativePath`, `importArtifactSelector`
  - `packetCaptureImportProvenance`, `sidecarImportProvenance`,
    `packetFactSource`

协议字段：

- DNS: `queryName`, `qname`, `domain`, `dnsQueryName`, `query`, `dnsQuery`,
  `rrname`, `dns.rrname`, `dns.qry.name`, `dns.question.name`,
  `dns.questions.name`, `dns.query.name`, `queryType`, `recordType`,
  `dnsRecordType`, `qtype`, `rrtype`, `dns.qry.type`, `dns.question.type`,
  `rcode`, `rcodeName`, `responseCode`, `dnsRcode`, `dnsResponseCode`,
  `dns.rcode`, `dns.flags.rcode`, `dns.response_code`, `isResponse`,
  `answer`, `answers`, `resolvedIp`, `resolvedIps`, `dnsAnswers`,
  `answerCount`, `ttl`, `recordClass`, `dnsTransactionId`, `dnsOutcome`,
  `classification`, `isNxDomain`, `answerTypeSummary`,
  `dnsAnswerTypeSummary`, `cnameChain`, `dnsCnameChain`, `cnameTarget`,
  `hasCname`, `dnsAnswerHasCname`
- HTTP: `httpMessageType`, `method`, `httpMethod`, `requestMethod`,
  `httpRequestMethod`, `http.request.method`, `uri`, `requestUri`, `host`,
  `url`, `userAgent`, `contentType`, `statusCode`, `responseStatusCode`,
  `httpStatusCode`, `httpStatus`, `responseCode`, `http.response.status_code`,
  `http.response.code`, `statusFamily`, `payloadMagic`, `referer`, `referrer`,
  `httpUserAgentFamily`, `contentDisposition`, `httpContentDisposition`,
  `downloadFilename`, `downloadFileName`, `downloadFilenameSource`,
  `contentEncoding`, `requestBodyBytes`, `requestBytes`,
  `httpRequestBodyBytes`, `requestBodySizeBytes`, `responseBodyBytes`,
  `responseBytes`, `httpResponseBodyBytes`, `responseBodySizeBytes`,
  `bodyBytes`, `bodySizeBytes`, `http.body.bytes`, `requestContentLength`,
  `responseContentLength`, `contentLength`, `uploadBytes`, `downloadBytes`,
  `uploadCandidate`, `transferDirection`, `authorizationHeaderPresent`,
  `cookiePresent`
- TLS: `sni`, `serverName`, `tlsServerName`, `tlsSni`, `server_name`,
  `tls.server_name`, `tlsVersion`, `handshakeType`, `tlsHandshakeType`,
  `ja3`, `ja3s`, `ja3Hash`, `ja3sHash`, `ja3Fingerprint`, `ja3sFingerprint`,
  `ja3.hash`, `tls.ja3.hash`, `alpn`, `cipherSuite`, `certSubject`,
  `certificateSubject`, `x509.subject`, `certIssuer`, `certificateIssuer`,
  `x509.issuer`, `certSerial`, `certificateSerial`, `certSha256`,
  `certificateSha256`, `certificateFingerprintSha256`,
  `x509.fingerprint.sha256`, `certSha1`, `certNotBefore`, `certNotAfter`,
  `certificateStatus`, `validationStatus`, `certSelfSigned`,
  `certificateSelfSigned`, `certExpired`, `certificateExpired`,
  `certificateValidityStatus`, `tlsCertificateValidityStatus`,
  `certificateIssuerSummary`, `tlsCertificateIssuerSummary`,
  `tlsCertificateRisk`, `tlsCertificateRiskReason`,
  `tlsCertificateRiskClassification`. Native PCAP TLS
  parsing 可在不要求 `tshark` 的情况下，从 client-hello 推导 SNI/ALPN/cipher hint/JA3，
  在存在 server-hello 时推导 JA3S，并从 TLS Certificate handshakes 尽力提取 certificate
  subject/issuer/fingerprint metadata。自签名、过期、尚未生效、invalid/untrusted 或
  certificate parse error 会将协议行的 `protocolHealth` 标记为 `warning`，同时保留
  `collectionHealth=ok`，表示“协议证据可解析，但证书风险需要复核”。
- Connection: `state`, `durationSeconds`, `packetCount`, `byteCount`,
  `packetsToServer`, `packetsToClient`, `bytesToServer`, `bytesToClient`,
  `uid`, `externalFlowKey`, `communityId`, `applicationProtocol`,
  `flowReason`

如果源行（source row）暴露 process / lineage 字段，sidecar 导入器会尽量保留：

- `processId`, `pid`, `parentProcessId`
- `rootProcessId`, `rootPid`, `processRootId`
- `treeLineage`, `processTreeLineage`
- `processName`, `imageName`, `processImage`, `processPath`,
  `commandLine`, `processRole`
- `rootProcessName`, `rootCommandLine`

中文：sidecar 归一化会尽量保留样本根进程和进程树 lineage。报告里若同时看到
`rootProcessId` / `treeLineage` 与 HTTP 上传、NXDOMAIN、TLS JA3/证书异常，
可以把网络行为直接挂到样本进程树，而不是只把它当作孤立网络流量。

Sidecar 别名覆盖（alias coverage）有意兼容常见 Zeek/ECS/tshark/R0 字段族，例如 `id.orig_h`、`id.resp_h`、
`orig_bytes`、`resp_bytes`、
`dns.rrname`, `dns.answers`, `http.response.status_code`,
`http.request.body.bytes`, `tls.ja3.hash`, `tls.cert.fingerprint.sha256`,
`network.community_id` 和 `process.entry_leader.*`。敏感 HTTP headers 不会原样复制；
导入器只记录 `authorizationHeaderPresent` 和 `cookiePresent` 布尔值。

Sidecar 专属字段：

- `sidecarLineNumber`
- `sidecarFormat`: `jsonl` 或 `log`
- `parser=sidecar-jsonl`
- `parserInputKind=network-sidecar`
- `parserBounded=true`
- `parserMaxLines`
- `sidecarImportProvenance=sidecar-artifact`
- `sidecarSourceArtifactRelativePath`, `sidecarSourceArtifactName`,
  `sidecarSourceArtifactSelector`
- `originalEventType`: 输入 row 暴露时记录
- R0/WFP health sidecar rows（例如 `r0collector.driverNetworkStatus`）会归入
  `eventKind=health`，保留 `originalEventType`，并带
  `behaviorCounted=false`、`nonbehavior=true`、`behaviorScope=network-collection-health`。
- Parse error rows 额外暴露 `diagnosticCode`、`parserBoundary`、`parseFailureStage`、
  `diagnosticStage`、`diagnosticMessage`、`parseErrorMessage`、`linePreview`
  和中文 `zhHint`。JSONL 行级错误通常是
  `diagnosticCode=sidecar_json_parse_error`、`parserBoundary=sidecar.line`。

Log sidecar（日志 sidecar）是弱解析：importer 识别带引号或不带引号的 `key=value` / `key: value` token、
endpoint arrow、HTTP request line、DNS query token 和 TLS SNI token。无法识别的普通 log line
会被忽略，以避免制造虚假网络证据。

## R0 网络状态诊断 / R0 network status diagnostics

`r0collector.driverNetworkStatus` 不是样本网络行为，而是 R0/WFP/ALE 采集质量证据。报告和 WebUI
应把它放在 R0 health / readiness 区，而不是 DNS/HTTP/TLS 行为列表。
宿主导入后该行保持 `originalEventType=r0collector.driverNetworkStatus`，并携带
`eventKind=health`、`behaviorCounted=false`、`nonbehavior=true`、
`behaviorScope=network-collection-health`、`noisePolicy=nonbehavior-evidence-quality`。

成功读取 driver IOCTL 时，该行可包含：

- `diagnosticStage=networkStatus`
- `networkStatusAvailable=true`
- `supportedLayerMask*`、`activeLayerMask*`、`lastRegisteredCalloutMask*`、`lastAddedFilterMask*`
- `todoMask*`
- `classifyCount`、`eventCount`、`queueFailureCount`、`classifyPayloadFailureCount`
- `lastDegradeReasonName`、`registerNtStatusHex`、`engineNtStatusHex`、`lastQueueFailureNtStatusHex`
- `readinessState`、`zhMessage`、`zhHint`

IOCTL 不可用、旧驱动协议不匹配或 device 打不开时，Collector 应输出同一 event type 的降级（degraded）
诊断行，例如 `networkStatusAvailable=false`、`diagnosticCode=network_status_ioctl_unavailable`。
这表示采集能力/版本边界，不表示样本规避或恶意网络行为。

## 汇总事件 / Summary event

`network.import.summary` 会在 PCAP 导入和 guest 证据聚合导入（artifact aggregate import）时生成。
它记录计数和解析器状态，包括：

- `artifactCount`, `pcapArtifactCount`, `sidecarArtifactCount`
- `eventCount`
- `connectionEventCount`, `dnsEventCount`, `httpEventCount`, `tlsEventCount`
- `parseErrorCount`
- `behaviorCountedEventCount`, `nonbehaviorEventCount`,
  `collectorSelfNoiseEventCount`
- `protocolHealthSummary`, `collectionHealthSummary`,
  `protocolHealthOkCount`, `protocolHealthWarningCount`,
  `protocolHealthDegradedCount`
- `protocols`
- guest-root aggregate imports 的 `manifestPresent`
- PCAP imports 的 `tsharkRequired`, `tsharkAvailable`, `tsharkStatus`

该事件是网络导入健康状态的稳定报告/搜索锚点（report/search anchor）；行为规则仍应使用协议级 rows 作为证据。

`collectionHealth` 从 imported rows 推导：

- `ok`: row 有足够 endpoint/protocol context，且没有 parse errors。
- `partial`: 已导入 protocol row，但 endpoint context 不完整。
- `empty`: aggregate import 没有找到 network evidence rows。
- `degraded`: 观察到 malformed PCAP/sidecar rows 或 parse errors。
