# 网络遥测导入 / Network telemetry import

KSwordSandbox 的宿主侧网络导入把网络证据当作已回收证据产物（artifact），而不是实时宿主抓包器（live host sniffer）。
当前导入器（importer）消费 guest 已收集输出，并生成稳定的字符串字段事件 schema，覆盖 DNS、HTTP、TLS
和连接/流量遥测（connection/flow telemetry）。

## 输入 / Inputs

支持的导入输入：

- Guest `artifacts/manifest.json` 中指向 `PacketCapture` artifacts 的 descriptors。
- Collected guest output 下的 `.pcap` 和 `.pcapng` 文件，通常位于
  `packet-captures/**`。
- Capture 文件旁边同 basename 的 packet-capture sidecar JSONL/log 文件，例如
  `sample.jsonl`, `sample.dns.jsonl`, `sample.http.jsonl`, `sample.tls.jsonl`,
  `sample.conn.jsonl`。`network-sidecars/**` 中也可导入 Zeek-like JSONL、
  `tshark*.jsonl` 或 KSword/R0 network JSONL rows；若文件名不是同 basename，
  只作为独立 sidecar 处理，除非 manifest/metadata 明确声明 parent PCAP。
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

## Parser bounds and non-inference rules

所有 parser 相关字段都描述导入覆盖范围，不描述样本行为本身。

Bounded PCAP parser：

- Per artifact packet cap: `parserMaxPackets=4096`
- Per packet payload cap: `parserMaxPayloadBytes=8192`
- Per artifact protocol event cap: `parserMaxProtocolEvents=256`
- Per artifact flow output cap: `parserMaxFlowEvents=256`
- Coverage flags: `parserPacketLimitHit`, `parserProtocolEventLimitHit`,
  `parserFlowEventLimitHit`
- Coverage counters on `pcap.summary`: `tcpPacketCount`, `udpPacketCount`,
  `ipv4PacketCount`, `ipv6PacketCount`, `transportProtocolSummary`,
  `ipFamilySummary`

Bounded sidecar parser：

- Per sidecar line cap: `parserMaxLines=4096`
- Per JSON/log flattened field cap: `parserMaxFlattenedFields=512`
- JSON depth cap: `parserMaxJsonDepth=16`
- String field value cap: `parserMaxFieldValueLength` /
  `parserMetadataValueMaxLength`（当前 4096 chars）
- JSONL parse previews use `linePreview` truncated to 160 chars。
- Coverage flags/counters: `parserLineLimitHit`, `sidecarLineLimitHit`,
  `parserFieldLimitHit`, `parserDepthLimitHit`, `parserFlattenedFieldCount`,
  `parserLinesRead`

Rows carrying parser metadata also carry `parserMetadataBounded=true` and
`parserMetadataPolicy=bounded-parser-metadata-nonbehavior-coverage-boundary`。
这些字段只说明“导入器在有界预算内看到了什么”；不要把 limit hit 解释成恶意规避、
不要把 parser failure 解释成良性，也不要把没有 protocol rows 解释成没有网络行为。
如果 sidecar 被成功读取但没有归一化出 DNS/HTTP/TLS/flow rows（例如全是未知 log、
深层 JSON 或字段/行数超限），导入器会输出一条 nonbehavior `network.health`
parser coverage row，带 `parserCoverageOnly=true`、`parserLinesRead`、
`parserLineLimitHit`、`parserDepthLimitHit`、`parserFieldLimitHit`、
`readinessState=parser_coverage_only`、`behaviorCounted=false` 和
`sampleBehaviorCandidate=false`。该 row 的中文 `zhMessage` / `zhHint`
会明确提示“已读取但没有归一化协议行”，这是 readiness/coverage 状态，不是样本行为。

## Coverage/readiness/nonbehavior quick map

Parser/import readiness rows should stay outside behavior scoring：

- `network.health` with `parserCoverageOnly=true`: sidecar was bounded-read, but no
  DNS/HTTP/TLS/flow row was normalized. It may be caused by unknown log format,
  depth/field/line limits, or sidecar content that is only health/readiness.
- `network.sidecar.parse_error` / `pcap.parse_error`: parser diagnostic rows.
  They explain malformed/truncated input and should not be converted into
  maliciousness or benignness.
- `network.import.summary` / `pcap.summary`: import accounting and readiness.
  Use their counters to understand coverage; use canonical protocol rows for
  sample behavior.
- 中文提示原则：`zhMessage` 是操作者摘要；`zhHint` 是 triage 提示。若提示中出现
  “解析覆盖状态”、“采集能力”或“readiness”，含义都是证据质量边界，而非样本网络行为。

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
导入后的标准化 canonical rows：`dns.query`、`http.request`、`tls.connection`、`network.flow`。
`pcap.*` rows 是 raw-derived compatibility rows，用于回溯/调试，不应作为额外独立行为重复计数。
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

## 语义泳道 / Behavior vs nonbehavior lanes

导入器显式区分 behavior lane 与 nonbehavior lane：

- Behavior lane（可作为样本网络行为计数）：`dns.query`、`http.request`、
  `tls.connection`、`network.flow`，且 `behaviorCounted=true`、`nonbehavior=false`。
- Nonbehavior lane（证据质量、导入状态或兼容视图）：`network.import.summary`、
  `pcap.summary`、`pcap.dns`、`pcap.http`、`pcap.tls`、`pcap.flow`、
  `*.parse_error`、`network.health`、`r0collector.driverNetworkStatus`。
- 所有 rows 都会尽量携带 `semanticLane`、`behaviorLane`、`behaviorCounted`、
  `nonbehavior`、`behaviorScope`、`behaviorCountingPolicy`。规则应优先用
  `behaviorCounted=true` 且 `nonbehavior!=true` 的 canonical rows 计数行为。
- Parser metadata、parser limits、import diagnostics、collection health、driver
  readiness、sidecar parse errors 都是 nonbehavior 证据质量字段；不要把它们转换成
  “样本规避”、“良性”或“没有网络行为”的结论。
- 缺失协议 rows、`capture-metadata-only`、`parser*LimitHit=true` 或 parse errors 只表示
  覆盖/解析边界；不证明样本没有 DNS/HTTP/TLS/连接行为。

## Raw PCAP rows and normalized event duplicate policy

PCAP native importer 会为同一个 packet/flow 同时输出兼容行和 canonical 行：

- `pcap.dns` -> canonical `dns.query`
- `pcap.http` -> canonical `http.request`
- `pcap.tls` -> canonical `tls.connection`
- `pcap.flow` -> canonical `network.flow`

Duplicate policy：

- Normalized canonical rows 是报告和规则的主输入。
- `pcap.*` rows 保留 raw PCAP 解码视图和 artifact 回溯，标记
  `rawPcapCompatibilityRow=true`、`duplicateRole=raw-pcap-compatibility`、
  `duplicateOfEventType=<canonical>`、`behaviorCounted=false`、`nonbehavior=true`。
- Canonical companion rows 标记 `duplicateRole=normalized-canonical`，并带相同
  `duplicateGroupKey` / `pcapProtocolEventKey`（协议 rows）或 flow duplicate key。
- `network.import.summary.eventCount` 仍是全部 imported rows；行为计数应使用
  `canonicalBehaviorEventCount` / `behaviorCountedEventCount`。`compatibilityEventCount`
  / `rawPcapCompatibilityEventCount` 说明 raw PCAP 兼容行数量。
- 协议族计数分两层：`protocolFamilyCounters` /
  `canonicalProtocolFamilyCounters` 的 scope 是
  `protocolFamilyCounterScope=behavior-counted-canonical-events`；`rawPcapCompatibilityProtocolFamilyCounters`
  的 scope 是 `raw-pcap-compatibility-nonbehavior-rows`。历史 `dnsEventCount` /
  `httpEventCount` / `tlsEventCount` / `flowEventCount` 可能包含 compatibility rows，
  不应用于样本行为去重计数。

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
  - `network.import.summary`, `pcap.summary`, `pcap.dns`, `pcap.http`,
    `pcap.tls`, `pcap.flow`, `network.health` 和
    `*.parse_error` rows 标记为 `behaviorCounted=false` / `nonbehavior=true`；
    标准化 canonical DNS/HTTP/TLS/connection rows 保持 `behaviorCounted=true`，
    以便规则继续把协议事实作为行为证据且避免 raw PCAP compatibility rows 重复计数。
  - 当 sidecar process/telemetry 字段可识别
    `KSword.Sandbox.R0Collector.exe` / `r0collector.*` 时，导入器会补充
    `collectorProcessName`、`sourceComponent=ksword-r0collector` 和
    `noisePolicy=collector-self-noise-filterable`、
    `collectorSelfNoise=true`、`collectorNoiseScope=collector-self-noise`、
    `sampleBehaviorBoundary=collector-separated`、`behaviorLane=collector-self-noise`，
    并将该 row 从样本行为计数中排除，帮助规则过滤采集器自噪声。
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
    Guest-root aggregate import 只会对同目录同 basename、且唯一匹配的 sidecar 自动关联
    sibling PCAP。
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
- `parserLinesRead`, `parserLineLimitHit`, `sidecarLineLimitHit`
- `parserMaxFlattenedFields`, `parserMaxJsonDepth`, `parserMaxFieldValueLength`
- `parserFieldLimitHit`, `parserDepthLimitHit`, `parserFlattenedFieldCount`
- `sidecarImportProvenance=sidecar-artifact`
- `sidecarProvenanceModel`
- `sidecarSourceArtifactPath`, `sidecarSourceArtifactRelativePath`,
  `sidecarSourceArtifactName`, `sidecarSourceArtifactSelector`,
  `sidecarSourceArtifactSha256`, `sidecarSourceArtifactSizeBytes`
- `originalEventType`: 输入 row 暴露时记录
- R0/WFP health sidecar rows（例如 `r0collector.driverNetworkStatus`）会归入
  `eventKind=health`，保留 `originalEventType`，并带
  `behaviorCounted=false`、`nonbehavior=true`、`behaviorScope=network-collection-health`。
- Parse error rows 额外暴露 `diagnosticCode`、`parserBoundary`、`parseFailureStage`、
  `diagnosticStage`、`diagnosticMessage`、`parseErrorMessage`、`linePreview`
  和中文 `zhHint`。JSONL 行级错误通常是
  `diagnosticCode=sidecar_json_parse_error`、`parserBoundary=sidecar.line`。

## Sidecar provenance model

Sidecar rows 使用两层 artifact identity，避免把 sidecar 本身和 parent capture 混在一起：

- `sourceArtifact*` 与 `sidecarSourceArtifact*` 指 sidecar 文件本身，例如 JSONL/log
  的 path、relative path、selector、size 和 hash。
- `pcapSourceArtifact*` / `sourcePcapArtifact*` / `parentArtifact*` 指相邻或 manifest
  指定的 parent/sibling PCAP。只有确实发现或 metadata 明确给出 parent PCAP 时才填充。
- 没有关联 PCAP 时，PCAP-specific parent fields 保持缺席；可见
  `sidecarParentPcapLinked=false`、`sidecarPcapLinkSource=none` 作为 provenance 状态。
- Direct PCAP import 读取相邻 sidecar 时，`sidecarPcapLinkSource=pcap-import-adjacent-sidecar`。
  该自动读取只接受与当前 PCAP 同 basename 的 sidecar，例如 `sample.pcap` 对应
  `sample.jsonl` / `sample.dns.jsonl`；`dns.jsonl`、`tshark.jsonl` 或
  `all-captures.dns.jsonl` 这类 global sidecar 不会被挂到某个 PCAP。
  Guest-root aggregate import 从同目录同 basename 推断时，
  `sidecarPcapLinkSource=adjacent-sibling-pcap`。
- 歧义策略：如果同目录存在多个 PCAP，或同一个 sidecar basename 可匹配多个 capture，
  importer 不会猜测 parent PCAP；PCAP-specific parent fields 保持缺席，并保留
  `sidecarParentPcapLinked=false`、`sidecarPcapLinkSource=none`。需要关联 global /
  ambiguous sidecar 时，应在 manifest/sidecar metadata 中显式声明 parent PCAP。
- 如果 manifest/sidecar metadata 已经声明 parent PCAP，而相邻推断结果不同，既有
  parent metadata 优先；导入器记录 `sidecarPcapLinkConflict=manifest-vs-adjacent`、
  `sidecarPcapLinkConflictPolicy=keep-existing-parent-metadata` 和 inferred path 字段，
  供人工复核。
- Sidecar parent PCAP provenance 是 evidence traceability，不是 behavior。`linked=false`
  或 `sidecarPcapLinkSource=none` 只表示没有安全、唯一的 parent capture 关联；不要因此推断
  “无 PCAP 行为”或“无网络行为”。
- `sidecarLineNumber`、`sidecarFormat`、`originalEventType`、sidecar hash/path、
  parser limit fields 都是 provenance/coverage metadata，不是样本行为。

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

## Protocol health semantics

`protocolHealth` 描述单条协议 evidence 的可解释性；`collectionHealth` 描述该 row 所在
导入/采集链路的完整性。二者不要混用。

- `protocolHealth=ok`: 协议 row 可解析，没有协议级 warning。
- `protocolHealth=warning`: 协议 row 可解析，但存在需复核的协议风险/异常，例如 TLS
  自签名、过期、尚未生效、invalid/untrusted 或 certificate parse warning。
- `protocolHealth=degraded`: 协议 evidence 因 malformed/truncated parser path 降级，
  通常会伴随 parse_error 或 diagnostic metadata。
- `collectionHealth=partial`: row 已导入但 endpoint/protocol context 不完整。
- `collectionHealth=degraded`: 导入链路观察到 parse errors 或采集健康降级。

Examples：

- DNS `NXDOMAIN` 是有效 DNS 响应和行为证据；它通常仍是 `protocolHealth=ok`，
  规则可基于 DGA/探测语义另行判断。
- TLS 证书风险会让对应 `tls.connection` 标记 `protocolHealth=warning`，但
  `collectionHealth` 可保持 `ok`，表示“证据可解析，但证书需复核”。
- PCAP/sidecar 截断、JSON parse error、packet boundary failure 属于 collection/parser
  diagnostic，进入 nonbehavior lane，并通过 `collectionHealth=degraded` 汇总。

Summary aggregation：

- `protocolHealthSummary`、`protocolHealthOkCount`、`protocolHealthWarningCount`、
  `protocolHealthDegradedCount` 只统计 `behaviorCounted=true` 的 canonical behavior rows，
  不重复统计 `pcap.*` compatibility rows。
- `collectionHealthSummary` 统计全部 imported rows，因为 parse errors、summary rows 和
  health rows 都属于采集/导入质量。
- Summary 格式稳定为 comma-separated `value:count`，例如 `ok:12,warning:1`。

## 汇总事件 / Summary event

`network.import.summary` 会在 PCAP 导入和 guest 证据聚合导入（artifact aggregate import）时生成。
它记录计数和解析器状态，包括：

- `artifactCount`, `pcapArtifactCount`, `sidecarArtifactCount`
- `eventCount`
- `connectionEventCount`, `dnsEventCount`, `httpEventCount`, `tlsEventCount`
- `parseErrorCount`
- `canonicalBehaviorEventCount`, `compatibilityEventCount`,
  `rawPcapCompatibilityEventCount`
- `canonicalDnsEventCount`, `canonicalHttpEventCount`, `canonicalTlsEventCount`,
  `canonicalFlowEventCount`
- `rawPcapDnsCompatibilityEventCount`, `rawPcapHttpCompatibilityEventCount`,
  `rawPcapTlsCompatibilityEventCount`, `rawPcapFlowCompatibilityEventCount`
- `behaviorCountedEventCount`, `nonbehaviorEventCount`,
  `collectorSelfNoiseEventCount`
- `protocolFamilyCounters`, `canonicalProtocolFamilyCounters`,
  `rawPcapCompatibilityProtocolFamilyCounters`
- PCAP summary 的 `tcpPacketCount`, `udpPacketCount`, `ipv4PacketCount`,
  `ipv6PacketCount`, `transportProtocolSummary`, `ipFamilySummary`
- `protocolHealthSummary`, `collectionHealthSummary`,
  `protocolHealthOkCount`, `protocolHealthWarningCount`,
  `protocolHealthDegradedCount`
- `protocolHealthSummaryScope`, `collectionHealthSummaryScope`,
  `eventCountPolicy`, `behaviorCountPolicy`, `duplicatePolicy`
- `protocols`
- guest-root aggregate imports 的 `manifestPresent`
- PCAP imports 的 `tsharkRequired`, `tsharkAvailable`, `tsharkStatus`

该事件是网络导入健康状态的稳定报告/搜索锚点（report/search anchor）；行为规则仍应使用协议级 rows 作为证据。

`collectionHealth` 从 imported rows 推导：

- `ok`: row 有足够 endpoint/protocol context，且没有 parse errors。
- `partial`: 已导入 protocol row，但 endpoint context 不完整。
- `empty`: aggregate import 没有找到 network evidence rows。
- `degraded`: 观察到 malformed PCAP/sidecar rows 或 parse errors。
