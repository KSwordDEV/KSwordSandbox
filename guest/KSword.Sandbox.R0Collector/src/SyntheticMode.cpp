#include "SyntheticMode.h"

#include <string>
#include <utility>
#include <vector>

namespace KSword::Sandbox::R0Collector {

using MockExtraData = std::vector<std::pair<std::string, std::string>>;

// Input: Boolean used in synthetic extra-data builders.
// Processing: Converts to the collector's string-valued JSONL data convention.
// Return: Stable lowercase boolean text.
std::string BoolText(const bool value) {
    return value ? "true" : "false";
}

void AddSyntheticAbiVersionFields(JsonDataObjectBuilder& data) {
    data.AddUnsigned("collectorAbiVersion", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("collectorAbiVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddUnsigned("abiVersionMajor", KSWORD_SANDBOX_ABI_VERSION_MAJOR);
    data.AddUnsigned("abiVersionMinor", KSWORD_SANDBOX_ABI_VERSION_MINOR);
    data.AddUnsigned("eventHeaderVersion", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    data.AddUtf8("eventHeaderVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8));
    data.AddUtf8("eventSchemaName", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("eventSchemaVersion", KSWORD_SANDBOX_EVENT_SCHEMA_VERSION);
    data.AddUtf8("eventSchemaVersionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_SCHEMA_VERSION, 8));
    data.AddUtf8("stableAbiVersionFields", kStableAbiVersionFields);
}

void AddSyntheticSelfNoiseFilterFields(JsonDataObjectBuilder& data) {
    data.AddUtf8("selfNoiseFilterMode", "synthetic-no-device-sample-pid");
    data.AddUtf8(
        "selfNoiseFilterPolicy",
        "synthetic driver rows use kSyntheticSampleProcessId and are not collector PID/path self-noise");
    data.AddBool("selfNoiseFilterMatched", false);
    data.AddUtf8("selfNoiseFilterAction", "emit-as-synthetic-sample-or-system");
    data.AddUnsigned("syntheticSampleProcessId", kSyntheticSampleProcessId);
}

// Input: Ordinal within the no-device semantic self-check corpus.
// Processing: Allocates a concrete sequence outside the stress range so mock
// semantic rows can be validated independently of StressJsonlExpectedDriverRows.
// Return: Stable sequence string.
std::string SemanticSequenceText(const int ordinal) {
    return std::to_string(kSyntheticSemanticSequenceStart + ordinal);
}

// Input: Scenario metadata for one synthetic semantic self-check row.
// Processing: Creates common no-device ABI/sequence/scenario fields shared by
// process-lineage, network, and download-execute mock rows.
// Return: Mutable extra-data vector for EmitMockDriverCategoryEvent.
MockExtraData BuildSemanticBaseExtra(
    const int ordinal,
    const std::string& scenario,
    const std::string& evidenceKind,
    const std::string& zhHint) {
    MockExtraData extra;
    extra.push_back({"semanticSelfCheck", "true"});
    extra.push_back({"semanticSelfCheckOrdinal", std::to_string(ordinal)});
    extra.push_back({"semanticSelfCheckRows", std::to_string(kSyntheticSemanticSelfCheckRows)});
    extra.push_back({"semanticSelfCheckScenarios", kSyntheticSemanticSelfCheckScenarios});
    extra.push_back({"semanticScenario", scenario});
    extra.push_back({"semanticEvidenceKind", evidenceKind});
    extra.push_back({"sequence", SemanticSequenceText(ordinal)});
    extra.push_back({"semanticSequenceScope", "synthetic-semantic-self-check"});
    extra.push_back({"semanticContractVersion", std::to_string(kAbiSelfCheckDiagnosticsVersion)});
    extra.push_back({"semanticRowKind", "no-device-companion"});
    extra.push_back({"semanticCompanionRow", "true"});
    extra.push_back({"semanticCompanionCount", std::to_string(kSyntheticSemanticSelfCheckRows)});
    extra.push_back({"semanticCompanionContract", "not-counted-in-StressJsonlExpectedDriverRows"});
    extra.push_back({"semanticRowCountedInStress", "false"});
    extra.push_back({"semanticStressCountImpact", "none"});
    extra.push_back({"stressRowCountPreserved", "true"});
    extra.push_back({"operatorHintLanguage", "zh-CN"});
    extra.push_back({"zhOperatorHint", zhHint});
    extra.push_back({"zhCompanionHint", u8"该语义 companion 行只补充 no-device 关联字段，不计入 StressJsonlExpectedDriverRows。"});
    extra.push_back({"version", std::to_string(KSWORD_SANDBOX_EVENT_HEADER_VERSION)});
    extra.push_back({"versionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8)});
    extra.push_back({"recordSize", std::to_string(sizeof(KSWORD_SANDBOX_EVENT_HEADER))});
    extra.push_back({"mockPayloadBoundary", "typed-payload-shape-only-no-live-driver-bytes"});
    extra.push_back({"zhSemanticHint", zhHint});
    return extra;
}

// Input: Mutable extra-data list for a synthetic network row.
// Processing: Adds protocol-parser boundary fields so DNS/HTTP/TLS candidates
// remain endpoint/port hints and do not claim packet payload parsing.
// Return: No return value; extra is appended in-place.
void AddNetworkParserBoundaryFields(
    MockExtraData& extra,
    const std::string& flowKey,
    const std::string& serviceHint) {
    const bool dnsCandidate = serviceHint == "dns";
    const bool httpCandidate = serviceHint == "http";
    const bool tlsCandidate = serviceHint == "tls";

    extra.push_back({"protocolBoundaryVersion", std::to_string(KSWORD_SANDBOX_NETWORK_PROTOCOL_BOUNDARY_VERSION)});
    extra.push_back({"protocolPayloadParsed", "false"});
    extra.push_back({"rawPacketPayloadAvailable", "false"});
    extra.push_back({"kernelPayloadParserEnabled", "false"});
    extra.push_back({"protocolParserSource", "r0-ale-endpoint-only"});
    extra.push_back({"protocolPayloadSource", "none-r0-endpoint-metadata-only"});
    extra.push_back({"networkCorrelationContractVersion", std::to_string(KSWORD_SANDBOX_NETWORK_CORRELATION_CONTRACT_VERSION)});
    extra.push_back({"networkCorrelationRole", "r0-endpoint-candidate"});
    extra.push_back({"pcapCorrelationRole", "join-candidate-not-l7-owner"});
    extra.push_back({"pcapCorrelationJoinFields", "flowKey|sourceEndpoint|destinationEndpoint|protocolName|sourcePort|destinationPort|processId"});
    extra.push_back({"pcapCorrelationMissingFields", "dnsQueryName|httpHost|httpUri|httpMethod|tlsSni|tlsCertificate"});
    extra.push_back({"pcapCorrelationConfidence", serviceHint == "unknown" ? "low" : "medium"});
    extra.push_back({"networkCorrelationStableFields", kNetworkCorrelationStableFields});
    extra.push_back({"pcapCorrelationRequired", "true"});
    extra.push_back({"pcapCorrelationStatus", "required-unmatched-in-r0-row"});
    extra.push_back({"pcapFlowKeyCandidate", flowKey});
    extra.push_back({"pcapCorrelationKey", flowKey});
    extra.push_back({"pcapCorrelationKeySource", "flowKey"});
    extra.push_back({"pcapExpectedRecordTypes", "pcap.flow|pcap.dns|pcap.http|pcap.tls"});
    extra.push_back({"pcapDnsDetailsAvailable", "false"});
    extra.push_back({"pcapHttpDetailsAvailable", "false"});
    extra.push_back({"pcapTlsDetailsAvailable", "false"});
    extra.push_back({"pcapBoundaryPolicy", "R0 rows provide endpoint/port/PID/layer evidence only; raw packets and L7 names/URLs require PCAP/browser/sidecar rows"});
    extra.push_back({"networkProtocolBoundaryFields", kNetworkProtocolBoundaryFields});
    extra.push_back({
        "networkProtocolParserBoundary",
        "R0 WFP/ALE rows do not parse raw payloads, DNS names, HTTP Host/URI/method, or TLS SNI/certificates; correlate PCAP/browser/sidecar rows"});
    extra.push_back({"r0ProtocolParserGuarantee", "endpoint-port-pid-layer-only"});
    extra.push_back({"protocolBoundaryVerdict", "l7-unavailable-r0-endpoint-only"});
    extra.push_back({"l7ProtocolDetailsAvailable", "false"});
    extra.push_back({"l7ProtocolDetailsOwner", "pcap-browser-sidecar-not-r0"});
    extra.push_back({"dnsQueryName", ""});
    extra.push_back({"dnsQueryNameAvailable", "false"});
    extra.push_back({"dnsQueryNameSource", "pcap-required-not-r0"});
    extra.push_back({"dnsCorrelationRecordType", dnsCandidate ? "pcap.dns-required" : "not-applicable"});
    extra.push_back({"dnsDetailsOwner", "pcap.dns-or-sidecar"});
    extra.push_back({"dnsBoundary", dnsCandidate ? "candidate-port-only-name-required-from-pcap" : "not-dns-candidate"});
    extra.push_back({"httpHost", ""});
    extra.push_back({"httpUri", ""});
    extra.push_back({"httpMethod", ""});
    extra.push_back({"httpHostAvailable", "false"});
    extra.push_back({"httpUriAvailable", "false"});
    extra.push_back({"httpMethodAvailable", "false"});
    extra.push_back({"httpMetadataSource", "pcap-or-browser-required-not-r0"});
    extra.push_back({"httpCorrelationRecordType", httpCandidate ? "pcap.http-required" : "not-applicable"});
    extra.push_back({"httpDetailsOwner", "pcap.http-browser-or-sidecar"});
    extra.push_back({"httpBoundary", httpCandidate ? "candidate-port-only-host-uri-required-from-pcap" : "not-http-candidate"});
    extra.push_back({"tlsSni", ""});
    extra.push_back({"tlsSniAvailable", "false"});
    extra.push_back({"tlsCertificateAvailable", "false"});
    extra.push_back({"tlsMetadataSource", "pcap-required-not-r0"});
    extra.push_back({"tlsCorrelationRecordType", tlsCandidate ? "pcap.tls-required" : "not-applicable"});
    extra.push_back({"tlsDetailsOwner", "pcap.tls-or-sidecar"});
    extra.push_back({"tlsBoundary", tlsCandidate ? "candidate-port-only-sni-cert-required-from-pcap" : "not-tls-candidate"});
    extra.push_back({"zhPcapCorrelationHint", u8"该 R0 网络行只提供端点/端口/PID/layer 证据；DNS 名称、HTTP Host/URI、TLS SNI/证书需查看 PCAP、浏览器或 sidecar 行。"});
    extra.push_back({"zhNetworkBoundaryHint", u8"不要把 serviceHint 或 candidate 布尔值解读为协议载荷已解析；它们只是端口/协议候选标签。"});
    extra.push_back({"zhDnsCorrelationHint", dnsCandidate
        ? u8"DNS 候选只说明 53/UDP 端点；查询名、响应码和答案应由 pcap.dns 或 sidecar 行补齐。"
        : u8"该行不是 DNS 候选；如需域名证据请查看 pcap.dns 或 sidecar 行。"});
    extra.push_back({"zhHttpCorrelationHint", httpCandidate
        ? u8"HTTP 候选只说明 80/TCP 等端点；Host、URI、Method 和状态码应由 pcap.http、浏览器或代理 sidecar 行补齐。"
        : u8"该行不是 HTTP 候选；不要从 R0 端点字段推断 Host、URI 或 Method。"});
    extra.push_back({"zhTlsCorrelationHint", tlsCandidate
        ? u8"TLS 候选只说明 443/TCP 等端点；SNI、证书、JA3/JA3S 应由 pcap.tls 或 TLS sidecar 行补齐。"
        : u8"该行不是 TLS 候选；不要从 R0 端点字段推断 SNI 或证书。"});
}

// Input: Network scenario fields that mirror AddNetworkPayloadData aliases.
// Processing: Builds a deterministic WFP/ALE-style endpoint row without packet
// payload claims, suitable for no-device DNS/HTTP/TLS/lateral smoke tests.
// Return: Mutable extra-data vector for EmitMockDriverCategoryEvent.
MockExtraData BuildNetworkSemanticExtra(
    const int ordinal,
    const std::string& scenario,
    const std::string& evidenceKind,
    const std::string& protocolName,
    const std::string& localAddress,
    const std::string& localPort,
    const std::string& remoteAddress,
    const std::string& remotePort,
    const std::string& serviceHint,
    const std::string& semanticCandidate,
    const bool dnsCandidate,
    const bool httpCandidate,
    const bool tlsCandidate,
    const bool webCandidate,
    const bool lateralMovementCandidate,
    const bool downloadExecuteCandidate,
    const bool smbCandidate,
    const bool rpcCandidate,
    const bool rdpCandidate,
    const bool winrmCandidate,
    const std::string& zhHint,
    const std::string& currentProcessIdText) {
    MockExtraData extra = BuildSemanticBaseExtra(ordinal, scenario, evidenceKind, zhHint);
    const std::string localEndpoint = localAddress + ":" + localPort;
    const std::string remoteEndpoint = remoteAddress + ":" + remotePort;
    const std::string flowKey = protocolName + "|" + localEndpoint + "|" + remoteEndpoint;

    extra.push_back({"payloadSize", std::to_string(sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD))});
    extra.push_back({"networkOperationName", "aleAuthorize"});
    extra.push_back({"wfpEventFamily", "wfp.ale.auth"});
    extra.push_back({"wfpEventName", "wfp.ale.auth.connect.ipv4"});
    extra.push_back({"wfpLayerSemanticName", "ale-auth-connect-ipv4"});
    extra.push_back({"wfpLayerDirection", "outbound"});
    extra.push_back({"wfpLayerAddressFamily", "ipv4"});
    extra.push_back({"wfpInspectionAction", "continue-inspection-only"});
    extra.push_back({"kernelNetworkProducerScope", "wfp-ale-endpoint-metadata-no-payload"});
    extra.push_back({"networkWfpEventNameFields", kNetworkWfpEventNameFields});
    extra.push_back({"protocol", protocolName == "udp" ? "17" : "6"});
    extra.push_back({"protocolName", protocolName});
    extra.push_back({"transportProtocol", protocolName});
    extra.push_back({"direction", "outbound"});
    extra.push_back({"directionName", "outbound"});
    extra.push_back({"addressFamily", "ipv4"});
    extra.push_back({"addressFamilyName", "ipv4"});
    extra.push_back({"localAddressPresent", "true"});
    extra.push_back({"remoteAddressPresent", "true"});
    extra.push_back({"processIdPresent", "true"});
    extra.push_back({"localAddress", localAddress});
    extra.push_back({"remoteAddress", remoteAddress});
    extra.push_back({"localPort", localPort});
    extra.push_back({"remotePort", remotePort});
    extra.push_back({"localEndpoint", localEndpoint});
    extra.push_back({"remoteEndpoint", remoteEndpoint});
    extra.push_back({"sourceEndpoint", localEndpoint});
    extra.push_back({"destinationEndpoint", remoteEndpoint});
    extra.push_back({"sourceAddress", localAddress});
    extra.push_back({"destinationAddress", remoteAddress});
    extra.push_back({"sourcePort", localPort});
    extra.push_back({"destinationPort", remotePort});
    extra.push_back({"endpointPair", localEndpoint + " -> " + remoteEndpoint});
    extra.push_back({"flowKey", flowKey});
    extra.push_back({"flowKeyVersion", std::to_string(KSWORD_SANDBOX_NETWORK_FLOW_KEY_VERSION)});
    extra.push_back({"flowKeyDirection", "outbound"});
    extra.push_back({"flowKeySource", "directional-source-destination-endpoints"});
    extra.push_back({"flowKeyScope", "transport-5tuple-lite"});
    extra.push_back({"servicePort", remotePort});
    extra.push_back({"serviceHint", serviceHint});
    extra.push_back({"serviceHintSource", serviceHint == "unknown" ? "unclassified" : "port-protocol"});
    extra.push_back({"serviceHintConfidence", serviceHint == "unknown" ? "none" : "medium"});
    extra.push_back({"serviceHintPolicy", "port-protocol heuristic: 53=dns, 80/8080/8000=http, 443/8443=tls"});
    extra.push_back({"semanticCandidate", semanticCandidate});
    extra.push_back({"networkEvidenceKind", evidenceKind});
    extra.push_back({"externalAddressCandidate", "true"});
    extra.push_back({"lateralMovementCandidate", BoolText(lateralMovementCandidate)});
    extra.push_back({"downloadExecuteCandidate", BoolText(downloadExecuteCandidate)});
    extra.push_back({"dnsCandidate", BoolText(dnsCandidate)});
    extra.push_back({"httpCandidate", BoolText(httpCandidate)});
    extra.push_back({"tlsCandidate", BoolText(tlsCandidate)});
    extra.push_back({"webCandidate", BoolText(webCandidate)});
    extra.push_back({"remoteServiceCandidate", BoolText(lateralMovementCandidate || serviceHint != "unknown")});
    extra.push_back({"smbCandidate", BoolText(smbCandidate)});
    extra.push_back({"rpcCandidate", BoolText(rpcCandidate)});
    extra.push_back({"rdpCandidate", BoolText(rdpCandidate)});
    extra.push_back({"winrmCandidate", BoolText(winrmCandidate)});
    extra.push_back({"serviceHintDns", BoolText(dnsCandidate)});
    extra.push_back({"serviceHintHttp", BoolText(httpCandidate)});
    extra.push_back({"serviceHintTls", BoolText(tlsCandidate)});
    extra.push_back({"processId", currentProcessIdText});
    extra.push_back({"flowHandlePresent", "false"});
    extra.push_back({"endpointHandlePresent", "false"});
    extra.push_back({"inspectionOnly", "true"});
    extra.push_back({"layerIdHex", "0x0000"});
    extra.push_back({"calloutIdHex", "0x00000000"});
    extra.push_back({"filterIdHex", "0x0000000000000000"});
    extra.push_back({"flowHandleHex", "0x0000000000000000"});
    extra.push_back({"transportEndpointHandleHex", "0x0000000000000000"});
    AddNetworkParserBoundaryFields(extra, flowKey, serviceHint);
    return extra;
}

// Input: Mock driver event type name.
// Processing: Maps synthetic category rows to the same public event type values
// and payload schema names that live READ_EVENTS parser rows emit.
// Return: Public payload schema name for the category, or a mock fallback.
std::string MockPayloadSchemaForDriverType(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "process") {
        return "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "image") {
        return "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "file") {
        return "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "registry") {
        return "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD";
    }
    if (driverEventTypeName == "network") {
        return "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD";
    }
    return "mock-forward-compatible";
}

// Input: Mock driver event type name.
// Processing: Maps mock categories to public KswSandboxEventType* values so
// mock/live JSONL rows share comparable diagnostic fields.
// Return: Numeric public event type or KswSandboxEventTypeReserved fallback.
ULONG MockDriverEventTypeValue(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "process") {
        return KswSandboxEventTypeProcess;
    }
    if (driverEventTypeName == "image") {
        return KswSandboxEventTypeImage;
    }
    if (driverEventTypeName == "file") {
        return KswSandboxEventTypeFile;
    }
    if (driverEventTypeName == "registry") {
        return KswSandboxEventTypeRegistry;
    }
    if (driverEventTypeName == "network") {
        return KswSandboxEventTypeNetwork;
    }
    return KswSandboxEventTypeReserved;
}

// Input: Mock driver event type name.
// Processing: Uses the same subject-kind vocabulary as live driver rows.
// Return: Stable subject kind label for attribution smoke tests.
std::string MockSubjectKind(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "network") {
        return "network-flow";
    }
    if (driverEventTypeName == "process" ||
        driverEventTypeName == "image" ||
        driverEventTypeName == "file" ||
        driverEventTypeName == "registry") {
        return driverEventTypeName;
    }
    return "unknown";
}

// Input: Mock driver category and operation.
// Processing: Builds the same semantic family.operation field used by live typed
// payload rows, but marks the row as synthetic elsewhere in data.
// Return: Stable activity-kind token.
std::string MockActivityKind(
    const std::string& driverEventTypeName,
    const std::string& operation) {
    return driverEventTypeName + "." + (operation.empty() ? "unknown" : operation);
}

// Input: Mock driver category.
// Processing: Provides a concise Chinese message for no-device smoke reports.
// Return: UTF-16 Chinese operator-facing message.
std::wstring MockZhMessage(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "process") {
        return L"合成 R0 进程事件，用于验证 JSONL 字段和报告进程树。";
    }
    if (driverEventTypeName == "file") {
        return L"合成 R0 文件事件，用于验证 dropped files/文件证据展示。";
    }
    if (driverEventTypeName == "registry") {
        return L"合成 R0 注册表事件，用于验证持久化证据字段。";
    }
    if (driverEventTypeName == "network") {
        return L"合成 R0 网络事件，用于验证 DNS/HTTP/TLS/flowKey 证据字段。";
    }
    if (driverEventTypeName == "image") {
        return L"合成 R0 镜像加载事件，用于验证进程模块证据。";
    }
    return L"合成 R0 事件，用于验证 Collector JSONL 合同。";
}

// Input: Mock driver category.
// Processing: Provides a Chinese hint that the row is not live kernel evidence.
// Return: UTF-16 Chinese operator-facing hint.
std::wstring MockZhHint(const std::string& driverEventTypeName) {
    if (driverEventTypeName == "network") {
        return L"该行为 mock/stress 输出，不来自真实驱动；字段形状应与 live 网络事件保持一致。";
    }
    return L"该行为 mock/stress 输出，不来自真实驱动；用于低成本验证字段、采样和报告合同。";
}

// Input: Mock category metadata, collector options, and the JSONL sink.
// Processing: Emits one synthetic driver-originated row that uses the same
// stable eventType values as drained R0 events while clearly marking the data as
// mock-only and not sourced from a real kernel payload.
// Return: true if the JSONL sink accepted the mock row; false on write failure.
bool EmitMockDriverCategoryEvent(
    EventWriter& writer,
    const Options& options,
    const std::string& eventType,
    const std::wstring& path,
    const std::wstring& commandLine,
    const std::string& driverEventTypeName,
    const std::string& operation,
    const std::vector<std::pair<std::string, std::string>>& extraData) {
    bool hasSequence = false;
    bool hasVersion = false;
    for (const auto& item : extraData) {
        if (item.first == "sequence") {
            hasSequence = true;
        }
        if (item.first == "version") {
            hasVersion = true;
        }
    }

    SandboxEventFields event;
    event.eventType = eventType;
    event.source = "driver";
    event.processId = kSyntheticSampleProcessId;
    event.processName = L"notepad.exe";
    event.path = path;
    event.commandLine = commandLine;

    JsonDataObjectBuilder data;
    data.AddBool("mock", true);
    data.AddWide("devicePath", options.devicePath);
    data.AddBool("healthOnly", options.healthOnly);
    AddSyntheticAbiVersionFields(data);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    if (!hasVersion) {
        data.AddUnsigned("version", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
        data.AddUtf8("versionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8));
    }
    data.AddUnsigned("driverEventType", MockDriverEventTypeValue(driverEventTypeName));
    data.AddUtf8("driverEventTypeName", driverEventTypeName);
    data.AddUtf8("producer", driverEventTypeName);
    data.AddUtf8("producerCategory", driverEventTypeName);
    data.AddUtf8("eventOrigin", "synthetic-r0collector");
    data.AddUtf8("subjectKind", MockSubjectKind(driverEventTypeName));
    data.AddUtf8("actorRole", "synthetic-sample-process");
    data.AddUtf8("subjectRole", "synthetic-sample-or-system");
    data.AddUtf8("processIdSource", "synthetic");
    AddSyntheticSelfNoiseFilterFields(data);
    data.AddUtf8("semanticFamily", driverEventTypeName);
    data.AddUtf8("behaviorLane", MockSubjectKind(driverEventTypeName));
    data.AddUtf8("activityKind", MockActivityKind(driverEventTypeName, operation));
    data.AddUtf8("operationName", operation);
    if (hasSequence) {
        data.AddUtf8("sequenceMeaning", "eventSequence");
        data.AddUtf8("sequenceScope", "synthetic-driver-event");
        data.AddBool("sequenceConcrete", true);
        data.AddUtf8(
            "sequencePolicy",
            "Synthetic driver rows use concrete event sequences; stress rows are contiguous and summaries use nextSequence");
        data.AddWide(
            "zhSequencePolicy",
            L"合成 driver 行使用具体事件 sequence；压测行保持连续，摘要行使用 nextSequence。");
    }
    data.AddSigned("status", 0);
    data.AddUtf8("statusHex", "0x00000000");
    data.AddBool("statusPresent", true);
    data.AddBool("pathTruncated", false);
    data.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("noiseClass", "sample-or-system");
    data.AddUtf8("noiseScope", "none");
    data.AddUtf8("noiseKind", "none");
    data.AddUtf8("noiseSource", "not-noise");
    data.AddUtf8("selfNoiseClass", "none");
    data.AddUtf8("collectorNoiseClass", "none");
    data.AddUtf8("noiseAction", "emit");
    data.AddUtf8("noiseDisposition", "emitted-as-sample-or-system-candidate");
    data.AddUtf8("noiseReasons", "none");
    data.AddUtf8("noiseFieldSet", kJsonlNoiseFieldSet);
    data.AddUtf8("noiseTaxonomyVersion", "1");
    data.AddUtf8("noiseDecision", "not-noise");
    data.AddUtf8("noiseDecisionSource", "synthetic-driver-category-default");
    data.AddUtf8("noiseClassificationConfidence", "high");
    data.AddUtf8("noiseProbeKind", "none");
    data.AddBool("sampleBehaviorCandidate", true);
    data.AddUtf8("sampleBehaviorCandidateReason", "synthetic-sample-or-system-candidate");
    data.AddBool("collectionDiagnostic", false);
    data.AddBool("collectionNoise", false);
    data.AddUtf8("operatorInterpretation", "candidate_sample_or_system_behavior");
    data.AddWide("zhNoiseHint", L"该合成事件未标记为 Collector 自噪声，用于验证样本行为候选字段。");
    data.AddWide("zhNoiseClassificationHint", L"噪声分类为 not-noise；该行可进入样本/系统行为候选，但仍需结合上下文判断。");
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddUtf8("operation", operation);
    data.AddUtf8("typedPayloadStatus", "mock");
    data.AddBool("typedPayloadParsed", true);
    data.AddUtf8("payloadSchema", MockPayloadSchemaForDriverType(driverEventTypeName));
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddBool("noise", false);
    data.AddUtf8(
        "note",
        "Synthetic driver-category row for Guest Agent and host import plumbing.");
    data.AddBool("evidenceReady", true);
    data.AddWide("zhMessage", MockZhMessage(driverEventTypeName));
    data.AddWide("zhHint", MockZhHint(driverEventTypeName));
    data.AddWide("zhOperatorHint", MockZhHint(driverEventTypeName));
    data.AddWide(
        "zhNote",
        L"\u4f9b Guest Agent \u548c Host import \u7ba1\u7ebf\u6d4b\u8bd5\u4f7f\u7528\u7684\u5408\u6210 driver \u5206\u7c7b\u884c\u3002");

    for (const auto& item : extraData) {
        data.AddUtf8(item.first, item.second);
    }

    event.dataJson = data.Build();
    return EmitEvent(writer, event);
}

// Input: Collector options, JSONL sink, mock command line, and current PID text.
// Processing: Emits no-device semantic rows that exercise report/rule fields
// for process-lineage, DNS, HTTP, TLS, lateral movement, and download-execute
// without changing the counted driver.file stress corpus.
// Return: true when all semantic rows were written; false on output failure.
bool EmitSyntheticSemanticSelfCheckEvents(
    EventWriter& writer,
    const Options& options,
    const std::wstring& mockCommandLine,
    const DWORD currentProcessId,
    const std::string& currentProcessIdText) {
    const std::string syntheticCmdProcessId =
        std::to_string(static_cast<unsigned long long>(currentProcessId) + 1000ULL);
    const std::string syntheticPowerShellProcessId =
        std::to_string(static_cast<unsigned long long>(currentProcessId) + 1001ULL);

    MockExtraData processLineage = BuildSemanticBaseExtra(
        0,
        "process-lineage",
        "process-lineage-edge",
        u8"合成进程血缘行，验证父进程/创建者 PID、命令行前缀和进程树展示字段。");
    processLineage.push_back({"payloadSize", std::to_string(sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD))});
    processLineage.push_back({"imagePath", "C:\\Windows\\System32\\cmd.exe"});
    processLineage.push_back({"processOperationName", "create"});
    processLineage.push_back({"processLifecycle", "start"});
    processLineage.push_back({"processLineageScenario", "true"});
    processLineage.push_back({"lineageConfidence", "synthetic-parent-child"});
    processLineage.push_back({"parentProcessIdPresent", "true"});
    processLineage.push_back({"creatingProcessIdPresent", "true"});
    processLineage.push_back({"commandLinePresent", "true"});
    processLineage.push_back({"imagePathPresent", "true"});
    processLineage.push_back({"processId", syntheticCmdProcessId});
    processLineage.push_back({"parentProcessId", currentProcessIdText});
    processLineage.push_back({"creatingProcessId", currentProcessIdText});
    processLineage.push_back({"parentImagePath", "C:\\Windows\\System32\\notepad.exe"});
    processLineage.push_back({"childImagePath", "C:\\Windows\\System32\\cmd.exe"});
    processLineage.push_back({"capturedCommandLine", "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\update.ps1"});
    processLineage.push_back({"parentChildEdge", "notepad.exe -> cmd.exe"});
    processLineage.push_back({"descendantProcessHint", "powershell.exe"});
    processLineage.push_back({"descendantProcessId", syntheticPowerShellProcessId});
    processLineage.push_back({"sampleCommandLineCandidate", "true"});
    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.process",
            LR"(C:\Windows\System32\cmd.exe)",
            LR"(cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1)",
            "process",
            "create",
            processLineage)) {
        return false;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.network",
            LR"(tcp://203.0.113.10:443)",
            mockCommandLine,
            "network",
            "connect",
            BuildNetworkSemanticExtra(
                3,
                "tls-egress-download",
                "tls-flow",
                "tcp",
                "192.0.2.10",
                "51515",
                "203.0.113.10",
                "443",
                "tls",
                "tls",
                false,
                false,
                true,
                true,
                false,
                true,
                false,
                false,
                false,
                false,
                u8"TLS 自检行只证明 443/TCP 端点；SNI/证书需要 PCAP/TLS sidecar 证据。",
                currentProcessIdText))) {
        return false;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.network",
            LR"(udp://198.51.100.53:53)",
            mockCommandLine,
            "network",
            "aleAuthorize",
            BuildNetworkSemanticExtra(
                1,
                "dns-egress",
                "dns-flow",
                "udp",
                "192.0.2.10",
                "53001",
                "198.51.100.53",
                "53",
                "dns",
                "dns",
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                u8"DNS 自检行只证明 53/UDP 端点和 flowKey；DNS 查询名需要 PCAP/sidecar 证据。",
                currentProcessIdText))) {
        return false;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.network",
            LR"(tcp://203.0.113.80:80)",
            mockCommandLine,
            "network",
            "aleAuthorize",
            BuildNetworkSemanticExtra(
                2,
                "http-egress-download",
                "http-flow",
                "tcp",
                "192.0.2.10",
                "51580",
                "203.0.113.80",
                "80",
                "http",
                "http",
                false,
                true,
                false,
                true,
                false,
                true,
                false,
                false,
                false,
                false,
                u8"HTTP 自检行只证明 80/TCP 端点；HTTP Host/URI/方法需要 PCAP、浏览器或代理 sidecar 证据。",
                currentProcessIdText))) {
        return false;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.network",
            LR"(tcp://10.0.2.25:445)",
            mockCommandLine,
            "network",
            "connect",
            BuildNetworkSemanticExtra(
                4,
                "lateral-smb-egress",
                "lateral-movement-flow",
                "tcp",
                "192.0.2.10",
                "51645",
                "10.0.2.25",
                "445",
                "unknown",
                "lateral-movement",
                false,
                false,
                false,
                false,
                true,
                false,
                true,
                false,
                false,
                false,
                u8"横向移动自检行命中 SMB/445 端口；需要结合进程树、凭据、命令行和文件复制证据判断。",
                currentProcessIdText))) {
        return false;
    }

    MockExtraData downloadExecute = BuildSemanticBaseExtra(
        5,
        "download-execute",
        "downloaded-executable-file",
        u8"下载执行自检行用于关联 HTTP/TLS 候选流和落地 EXE；真实 URL/哈希仍需浏览器、PCAP 或 dropped-file 证据。");
    downloadExecute.push_back({"payloadSize", std::to_string(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD))});
    downloadExecute.push_back({"filePath", "C:\\Users\\Public\\Downloads\\invoice-update.exe"});
    downloadExecute.push_back({"fileOperationName", "create"});
    downloadExecute.push_back({"fileIntent", "create"});
    downloadExecute.push_back({"artifactCandidateKind", "dropped-executable-from-web-flow"});
    downloadExecute.push_back({"dropLocationFamily", "downloads-directory"});
    downloadExecute.push_back({"droppedFileCandidate", "true"});
    downloadExecute.push_back({"downloadedFileCandidate", "true"});
    downloadExecute.push_back({"executableFileCandidate", "true"});
    downloadExecute.push_back({"downloadExecuteCandidate", "true"});
    downloadExecute.push_back({"startupFolderCandidate", "false"});
    downloadExecute.push_back({"fileExtension", ".exe"});
    downloadExecute.push_back({"correlatedNetworkScenario", "http-egress-download|tls-egress-download"});
    downloadExecute.push_back({"correlationKey", "synthetic-download-execute-1"});
    downloadExecute.push_back({"sourceUrlAvailable", "false"});
    downloadExecute.push_back({"sourceUrlSource", "pcap-browser-or-proxy-required-not-r0"});
    downloadExecute.push_back({"sha256Available", "false"});
    downloadExecute.push_back({"zoneIdentifierCandidate", "true"});
    downloadExecute.push_back({"motwCandidate", "true"});
    downloadExecute.push_back({"desiredAccessHex", "0x0012019F"});
    downloadExecute.push_back({"disposition", "create"});
    downloadExecute.push_back({"processId", syntheticPowerShellProcessId});
    return EmitMockDriverCategoryEvent(
        writer,
        options,
        "driver.file",
        LR"(C:\Users\Public\Downloads\invoice-update.exe)",
        LR"(powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1)",
        "file",
        "create",
        downloadExecute);
}

// Input: Event sink for synthetic mode.
// Processing: Appends a deterministic blank line, malformed row, and valid
// extra-field row so host readers prove JSONL noise tolerance without needing
// stress rows or a live device.
// Return: true when every noise line is accepted by the sink.
bool EmitSyntheticJsonlNoiseRows(EventWriter& writer) {
    if (!writer.WriteLine("   ")) {
        return false;
    }

    if (!writer.WriteLine("{\"eventType\":\"driver.file\",\"source\":\"driver\",\"data\":{\"sequence\":\"broken\"")) {
        return false;
    }

    JsonDataObjectBuilder data;
    data.AddUtf8("sequence", "9999");
    AddSyntheticAbiVersionFields(data);
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUnsigned("version", KSWORD_SANDBOX_EVENT_HEADER_VERSION);
    data.AddUtf8("versionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8));
    data.AddUtf8("producer", "network");
    data.AddUtf8("producerCategory", "network");
    data.AddUtf8("eventOrigin", "synthetic-r0collector");
    data.AddUtf8("subjectKind", "network-flow");
    data.AddUtf8("actorRole", "synthetic-sample-process");
    data.AddUtf8("subjectRole", "synthetic-jsonl-noise");
    data.AddUtf8("processIdSource", "synthetic");
    AddSyntheticSelfNoiseFilterFields(data);
    data.AddUtf8("semanticFamily", "network");
    data.AddUtf8("behaviorLane", "network-flow");
    data.AddUtf8("activityKind", "network.aleAuthorize");
    data.AddUtf8("operationName", "aleAuthorize");
    data.AddBool("semanticSelfCheck", true);
    data.AddUtf8("semanticScenario", "jsonl-extra-field-tls-noise");
    data.AddUtf8("semanticEvidenceKind", "tls-flow-extra-field-noise");
    data.AddUtf8("semanticSelfCheckScenarios", kSyntheticSemanticSelfCheckScenarios);
    data.AddUnsigned("semanticSelfCheckRows", kSyntheticSemanticSelfCheckRows);
    data.AddSigned("status", 0);
    data.AddUtf8("statusHex", "0x00000000");
    data.AddBool("statusPresent", true);
    data.AddBool("pathTruncated", false);
    data.AddUtf8("collectorNoisePolicy", "synthetic-noise-injector");
    data.AddBool("noise", true);
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("noiseClass", "jsonl-noise");
    data.AddUtf8("noiseScope", "synthetic-jsonl-noise");
    data.AddUtf8("noiseKind", "valid-extra-field-row");
    data.AddUtf8("noiseSource", "explicit---inject-jsonl-noise");
    data.AddUtf8("selfNoiseClass", "none");
    data.AddUtf8("collectorNoiseClass", "none");
    data.AddUtf8("noiseAction", "emit");
    data.AddUtf8("noiseDisposition", "emitted-for-importer-tolerance-probe");
    data.AddUtf8("noiseReasons", "synthetic-jsonl-noise-row");
    data.AddUtf8("noiseFieldSet", kJsonlNoiseFieldSet);
    data.AddUtf8("noiseTaxonomyVersion", "1");
    data.AddUtf8("noiseDecision", "jsonl-noise-probe");
    data.AddUtf8("noiseDecisionSource", "explicit---inject-jsonl-noise");
    data.AddUtf8("noiseClassificationConfidence", "high");
    data.AddUtf8("noiseProbeKind", "valid-extra-field-row");
    data.AddBool("sampleBehaviorCandidate", false);
    data.AddUtf8("sampleBehaviorCandidateReason", "explicit-jsonl-noise-probe-not-sample-behavior");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("collectionNoise", false);
    data.AddUtf8("operatorInterpretation", "jsonl_noise_tolerance_probe_not_sample_behavior");
    data.AddWide("zhNoiseHint", L"该行是显式 JSONL 噪声注入的合法额外字段行，用于验证导入器容错。");
    data.AddWide("zhNoiseClassificationHint", L"噪声分类为 JSONL 容错探针；用于导入器测试，不应进入样本行为图。");
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("lost", false);
    data.AddUnsigned("lostCount", 0);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddUtf8("protocolName", "tcp");
    data.AddUtf8("transportProtocol", "tcp");
    data.AddUtf8("directionName", "outbound");
    data.AddUtf8("addressFamilyName", "ipv4");
    data.AddUtf8("localAddress", "192.0.2.10");
    data.AddUtf8("remoteAddress", "203.0.113.10");
    data.AddUtf8("localPort", "51515");
    data.AddUtf8("remotePort", "443");
    data.AddUtf8("localEndpoint", "192.0.2.10:51515");
    data.AddUtf8("remoteEndpoint", "203.0.113.10:443");
    data.AddUtf8("sourceEndpoint", "192.0.2.10:51515");
    data.AddUtf8("destinationEndpoint", "203.0.113.10:443");
    data.AddUtf8("sourcePort", "51515");
    data.AddUtf8("destinationPort", "443");
    data.AddUnsigned("processId", kSyntheticSampleProcessId);
    data.AddUtf8("flowKey", "tcp|192.0.2.10:51515|203.0.113.10:443");
    data.AddUnsigned("flowKeyVersion", 1);
    data.AddUtf8("flowKeyDirection", "outbound");
    data.AddUtf8("flowKeySource", "directional-source-destination-endpoints");
    data.AddUtf8("flowKeyScope", "transport-5tuple-lite");
    data.AddUtf8("endpointPair", "192.0.2.10:51515 -> 203.0.113.10:443");
    data.AddUtf8("serviceHint", "tls");
    data.AddUtf8("serviceHintSource", "port-protocol");
    data.AddUtf8("serviceHintConfidence", "medium");
    data.AddBool("dnsCandidate", false);
    data.AddBool("httpCandidate", false);
    data.AddBool("tlsCandidate", true);
    data.AddBool("webCandidate", true);
    data.AddBool("serviceHintDns", false);
    data.AddBool("serviceHintHttp", false);
    data.AddBool("serviceHintTls", true);
    data.AddBool("protocolPayloadParsed", false);
    data.AddUtf8("protocolParserSource", "r0-ale-endpoint-only");
    data.AddUtf8("protocolPayloadSource", "none-r0-endpoint-metadata-only");
    data.AddUnsigned("networkCorrelationContractVersion", 1);
    data.AddUtf8("networkCorrelationRole", "r0-endpoint-candidate");
    data.AddUtf8("pcapCorrelationRole", "join-candidate-not-l7-owner");
    data.AddUtf8("pcapCorrelationJoinFields", "flowKey|sourceEndpoint|destinationEndpoint|protocolName|sourcePort|destinationPort|processId");
    data.AddUtf8("pcapCorrelationMissingFields", "dnsQueryName|httpHost|httpUri|httpMethod|tlsSni|tlsCertificate");
    data.AddUtf8("pcapCorrelationConfidence", "medium");
    data.AddUtf8("networkCorrelationStableFields", kNetworkCorrelationStableFields);
    data.AddBool("pcapCorrelationRequired", true);
    data.AddUtf8("pcapCorrelationStatus", "required-unmatched-in-r0-row");
    data.AddUtf8("pcapFlowKeyCandidate", "tcp|192.0.2.10:51515|203.0.113.10:443");
    data.AddUtf8("pcapCorrelationKey", "tcp|192.0.2.10:51515|203.0.113.10:443");
    data.AddUtf8("pcapCorrelationKeySource", "flowKey");
    data.AddUtf8("pcapExpectedRecordTypes", "pcap.flow|pcap.dns|pcap.http|pcap.tls");
    data.AddBool("pcapDnsDetailsAvailable", false);
    data.AddBool("pcapHttpDetailsAvailable", false);
    data.AddBool("pcapTlsDetailsAvailable", false);
    data.AddUtf8(
        "pcapBoundaryPolicy",
        "R0 rows provide endpoint/port/PID/layer evidence; L7 names and URLs require PCAP/browser/sidecar rows");
    data.AddUtf8("networkProtocolBoundaryFields", kNetworkProtocolBoundaryFields);
    data.AddUtf8("dnsQueryName", "");
    data.AddBool("dnsQueryNameAvailable", false);
    data.AddUtf8("dnsQueryNameSource", "pcap-required-not-r0");
    data.AddUtf8("dnsCorrelationRecordType", "not-applicable");
    data.AddUtf8("dnsDetailsOwner", "pcap.dns-or-sidecar");
    data.AddUtf8("dnsBoundary", "not-dns-candidate");
    data.AddUtf8("httpHost", "");
    data.AddUtf8("httpUri", "");
    data.AddUtf8("httpMethod", "");
    data.AddBool("httpHostAvailable", false);
    data.AddBool("httpUriAvailable", false);
    data.AddBool("httpMethodAvailable", false);
    data.AddUtf8("httpMetadataSource", "pcap-or-browser-required-not-r0");
    data.AddUtf8("httpCorrelationRecordType", "not-applicable");
    data.AddUtf8("httpDetailsOwner", "pcap.http-browser-or-sidecar");
    data.AddUtf8("httpBoundary", "not-http-candidate");
    data.AddUtf8("tlsSni", "");
    data.AddBool("tlsSniAvailable", false);
    data.AddBool("tlsCertificateAvailable", false);
    data.AddUtf8("tlsMetadataSource", "pcap-required-not-r0");
    data.AddUtf8("tlsCorrelationRecordType", "pcap.tls-required");
    data.AddUtf8("tlsDetailsOwner", "pcap.tls-or-sidecar");
    data.AddUtf8("tlsBoundary", "candidate-port-only-sni-cert-required-from-pcap");
    data.AddBool("l7ProtocolDetailsAvailable", false);
    data.AddUtf8("l7ProtocolDetailsOwner", "pcap-browser-sidecar-not-r0");
    data.AddUtf8("r0ProtocolParserGuarantee", "endpoint-port-pid-layer-only");
    data.AddUtf8("protocolBoundaryVerdict", "l7-unavailable-r0-endpoint-only");
    data.AddUtf8(
        "networkProtocolParserBoundary",
        "valid noise row keeps endpoint/TLS candidate fields but does not claim protocol payload parsing");
    data.AddWide(
        "zhPcapCorrelationHint",
        L"该合法噪声行保留 TLS flowKey 以测试导入容错；真实 SNI/证书仍需 PCAP/TLS sidecar。");
    data.AddWide(
        "zhNetworkBoundaryHint",
        L"这是额外字段容错探针，不是样本真实网络行为，也不是 TLS 载荷解析结果。");
    data.AddWide(
        "zhDnsCorrelationHint",
        L"该噪声行不是 DNS 候选；DNS 查询名必须来自 pcap.dns 或 sidecar 行。");
    data.AddWide(
        "zhHttpCorrelationHint",
        L"该噪声行不是 HTTP 候选；HTTP Host/URI/Method 必须来自 pcap.http、浏览器或代理 sidecar 行。");
    data.AddWide(
        "zhTlsCorrelationHint",
        L"该噪声行只保留 TLS flowKey 候选；SNI、证书、JA3/JA3S 必须来自 pcap.tls 或 TLS sidecar。");
    data.AddBool("evidenceReady", true);
    data.AddWide("zhMessage", L"合成 JSONL 噪声网络行，保留 TLS flowKey 字段用于容错测试。");
    data.AddWide("zhHint", L"该行不代表真实样本网络行为；用于验证合法额外字段不会破坏导入。");
    data.AddWide("zhOperatorHint", L"运营提示：将该行作为 JSONL 容错探针处理；不要计入样本网络关系图。");
    data.AddWide("zhSemanticHint", L"该合法噪声行只验证 TLS 候选字段和额外字段容错，不代表真实 SNI/证书解析。");

    std::string line =
        "{\"eventType\":\"driver.network\",\"source\":\"driver\",\"extraTopLevel\":\"ignored\",\"data\":";
    line += data.Build();
    line += "}";
    return writer.WriteLine(line);
}

// Input: Collector options and the JSONL sink.
// Processing: Emits a deterministic contiguous driver.file corpus that is large
// enough for host/live readers to prove ordering, loss markers, and bounded
// backpressure fields without opening the kernel device.
// Return: true when all requested synthetic stress rows were written; false on
// output failure.
bool EmitSyntheticStressEvents(EventWriter& writer, const Options& options, const std::wstring& commandLine) {
    if (options.stressCount <= 0) {
        return true;
    }

    const std::string currentProcessIdText = std::to_string(kSyntheticSampleProcessId);
    const std::string stressSequenceStartText = std::to_string(kSyntheticStressSequenceStart);
    const std::string stressSequenceEndText = std::to_string(kSyntheticStressSequenceStart + options.stressCount - 1);

    for (int index = 0; index < options.stressCount; ++index) {
        const int sequence = kSyntheticStressSequenceStart + index;
        std::wstring path = LR"(C:\Users\Public\ksword-r0collector-stress-)";
        path += std::to_wstring(index);
        path += L".tmp";
        const std::string pathUtf8 = Utf8FromWide(path);

        if (!EmitMockDriverCategoryEvent(
                writer,
                options,
                "driver.file",
                path,
                commandLine,
                "file",
                "create",
                {
                    {"stress", "true"},
                    {"stressOrdinal", std::to_string(index)},
                    {"stressCount", std::to_string(options.stressCount)},
                    {"stressCorpusRole", "counted-driver-file-row"},
                    {"semanticSelfCheck", "true"},
                    {"semanticContractVersion", std::to_string(kAbiSelfCheckDiagnosticsVersion)},
                    {"semanticRowKind", "counted-stress-driver-file"},
                    {"semanticRowCountedInStress", "true"},
                    {"semanticStressCountImpact", "counts-toward-StressJsonlExpectedDriverRows"},
                    {"semanticScenario", "stress-file-create"},
                    {"semanticEvidenceKind", "file-create-stress"},
                    {"semanticSelfCheckScenarios", kSyntheticSemanticSelfCheckScenarios},
                    {"semanticSelfCheckRows", std::to_string(kSyntheticSemanticSelfCheckRows)},
                    {"semanticCompanionRows", std::to_string(kSyntheticSemanticSelfCheckRows)},
                    {"zhSemanticHint", u8"该压测行是计数 driver.file 语料；DNS/HTTP/TLS/横向移动/下载执行/进程血缘由 companion mock 行覆盖。"},
                    {"StressJsonlExpectedDriverRows", std::to_string(options.stressCount)},
                    {"StressJsonlSequenceStart", stressSequenceStartText},
                    {"StressJsonlSequenceEnd", stressSequenceEndText},
                    {"StressJsonlSequenceGapCount", "0"},
                    {"sequenceGapObserved", "false"},
                    {"sequenceGapEstimate", "0"},
                    {"sequenceRangeMeaning", "synthetic contiguous concrete event sequence"},
                    {"StressJsonlLossEvidence", kStressJsonlLossEvidence},
                    {"StressJsonlBackpressureEvidence", kStressJsonlBackpressureEvidence},
                    {"version", std::to_string(KSWORD_SANDBOX_EVENT_HEADER_VERSION)},
                    {"versionHex", HexUnsignedLongLong(KSWORD_SANDBOX_EVENT_HEADER_VERSION, 8)},
                    {"recordSize", std::to_string(sizeof(KSWORD_SANDBOX_EVENT_HEADER))},
                    {"sequence", std::to_string(sequence)},
                    {"payloadSize", std::to_string(sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD))},
                    {"filePath", pathUtf8},
                    {"desiredAccessHex", "0x0012019F"},
                    {"disposition", "create"},
                    {"processId", currentProcessIdText},
                    {"queueCapacity", "0"},
                    {"queueHighWatermark", "0"},
                    {"totalEventsDropped", "0"},
                    {"totalEventsBackpressured", "0"},
                    {"producerDroppedMask", "0"},
                    {"producerDroppedMaskHex", "0x00000000"},
                    {"producerBackpressureMask", "0"},
                    {"producerBackpressureMaskHex", "0x00000000"},
                    {"requestedMaxEvents", std::to_string(options.readEventsMaxEvents)},
                    {"readEventsMaxEvents", std::to_string(options.readEventsMaxEvents)},
                    {"maxReadBatches", std::to_string(options.maxReadBatches)},
                    {"drainStoppedAtBatchLimit", "false"},
                    {"sampling", options.driverEventSampleStride <= 1 ? "none" : "stride:not-applied-in-synthetic-stress"}
                })) {
            return false;
        }
    }

    return true;
}

// Input: Collector options and JSONL sink after synthetic stress rows.
// Processing: Emits a compact READ_EVENTS-shaped summary so no-device stress
// output exposes the same processed/emitted/backpressure aliases as live drains.
// Return: true when no summary is needed or the sink accepted the summary row.
bool EmitSyntheticStressSummary(EventWriter& writer, const Options& options) {
    if (options.stressCount <= 0) {
        return true;
    }

    const std::string stressSequenceStartText = std::to_string(kSyntheticStressSequenceStart);
    const std::string stressSequenceEndText =
        std::to_string(kSyntheticStressSequenceStart + options.stressCount - 1);
    const std::string stressNextSequenceText =
        std::to_string(kSyntheticStressSequenceStart + options.stressCount);

    SandboxEventFields event;
    event.eventType = "r0collector.driverReadEvents";
    event.path = options.devicePath;

    JsonDataObjectBuilder data;
    AddSyntheticAbiVersionFields(data);
    data.AddUnsigned("version", KSWORD_SANDBOX_INTERFACE_VERSION);
    data.AddUtf8("versionHex", HexUnsignedLongLong(KSWORD_SANDBOX_INTERFACE_VERSION, 8));
    data.AddBool("mock", true);
    data.AddBool("syntheticStress", true);
    data.AddUtf8("semanticSelfCheckScenarios", kSyntheticSemanticSelfCheckScenarios);
    data.AddUnsigned("semanticSelfCheckRows", kSyntheticSemanticSelfCheckRows);
    data.AddUnsigned("semanticSelfCheckSequenceStart", kSyntheticSemanticSequenceStart);
    data.AddUnsigned(
        "semanticSelfCheckSequenceEnd",
        kSyntheticSemanticSequenceStart + kSyntheticSemanticSelfCheckRows - 1);
    data.AddUtf8(
        "semanticSelfCheckPolicy",
        "semantic companion rows are emitted outside the counted driver.file stress corpus");
    data.AddBool("semanticCompanionRowsExcludedFromStress", true);
    data.AddUtf8("semanticStressCountPreservationPolicy", "semantic companion rows are not counted in StressJsonlExpectedDriverRows");
    data.AddUtf8("countedStressRowEventType", "driver.file");
    data.AddUtf8("countedStressRowKind", "counted-stress-driver-file");
    data.AddWide(
        "zhSemanticSelfCheckHint",
        L"语义 companion 行覆盖 DNS/HTTP/TLS/横向移动/下载执行/进程血缘，不计入 driver.file 压测行数。");
    data.AddUtf8("ioctlProtocol", "not-issued");
    data.AddUnsigned("requestedMaxEvents", options.readEventsMaxEvents);
    data.AddUnsigned("readEventsMaxEvents", options.readEventsMaxEvents);
    data.AddSigned("maxReadBatches", options.maxReadBatches);
    data.AddBool("drainStoppedAtBatchLimit", false);
    data.AddUnsigned("recordsProcessed", options.stressCount);
    data.AddUnsigned("eventsEmitted", options.stressCount);
    data.AddUnsigned("collectorSuppressedEvents", 0);
    data.AddUnsigned("collectorSkippedEvents", 0);
    data.AddUnsigned("processed", options.stressCount);
    data.AddUnsigned("eligible", options.stressCount);
    data.AddUnsigned("eligibleEvents", options.stressCount);
    data.AddUnsigned("emitted", options.stressCount);
    data.AddUnsigned("suppressed", 0);
    data.AddUnsigned("skipped", 0);
    data.AddUtf8("head", stressSequenceStartText);
    data.AddUtf8("tail", stressSequenceEndText);
    data.AddUnsigned("observedSequenceSpan", options.stressCount);
    data.AddUnsigned("expectedContiguousEvents", options.stressCount);
    data.AddBool("sequenceGapObserved", false);
    data.AddUnsigned("sequenceGapEstimate", 0);
    data.AddUtf8("sequenceGapReason", "none");
    data.AddUtf8("sequenceRangeMeaning", "synthetic stress rows are contiguous concrete event sequences");
    data.AddWide("zhSequenceRangeMeaning", L"合成压测行使用连续的具体事件 sequence，用于验证丢失/缺口检测。");
    data.AddUtf8("sampling", options.driverEventSampleStride <= 1 ? "none" : "stride:not-applied-in-synthetic-stress");
    data.AddUtf8("loss", "none");
    data.AddUtf8("lossDiagnostic", "none");
    data.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    data.AddUtf8("producer", "r0collector");
    AddCollectorAttributionFields(data, "synthetic-stress-summary", "collector-diagnostic");
    data.AddBool("collectorNoise", false);
    data.AddBool("collectorSelfNoise", false);
    data.AddBool("selfProcess", false);
    data.AddUtf8("collectorNoiseReason", "none");
    data.AddUtf8("collectorNoiseAction", "emit");
    data.AddBool("collectorSuppressed", false);
    data.AddBool("selfNoise", false);
    data.AddUtf8("selfNoiseReason", "none");
    data.AddUtf8("selfNoiseAction", "emit");
    data.AddBool("noise", false);
    data.AddUtf8("noiseScope", "none");
    data.AddUtf8("noiseKind", "none");
    data.AddUtf8("noiseSource", "not-noise");
    data.AddUtf8("noiseClass", "collector-diagnostic");
    data.AddUtf8("selfNoiseClass", "none");
    data.AddUtf8("collectorNoiseClass", "none");
    data.AddUtf8("noiseAction", "emit");
    data.AddUtf8("noiseDisposition", "emitted-as-collector-diagnostic");
    data.AddUtf8("noiseReasons", "none");
    data.AddUtf8("noiseFieldSet", kJsonlNoiseFieldSet);
    data.AddUtf8("noiseTaxonomyVersion", "1");
    data.AddUtf8("noiseDecision", "synthetic-stress-summary");
    data.AddUtf8("noiseDecisionSource", "synthetic-stress-summary");
    data.AddUtf8("noiseClassificationConfidence", "high");
    data.AddUtf8("noiseProbeKind", "none");
    data.AddBool("sampleBehaviorCandidate", false);
    data.AddUtf8("sampleBehaviorCandidateReason", "collector-summary-not-sample-behavior");
    data.AddBool("collectionDiagnostic", true);
    data.AddBool("collectionNoise", false);
    AddSyntheticSelfNoiseFilterFields(data);
    data.AddUtf8("operatorInterpretation", "collection_diagnostic_not_sample_behavior");
    data.AddWide("zhNoiseHint", L"该行是合成压测摘要，不是样本行为。");
    data.AddWide("zhNoiseClassificationHint", L"噪声分类为 synthetic-stress-summary；仅用于核对行数、序列、丢失和背压合同。");
    data.AddBool("lost", false);
    data.AddBool("lossObserved", false);
    data.AddBool("backpressure", false);
    data.AddBool("backpressureObserved", false);
    data.AddUtf8("backpressureSeverity", "none");
    data.AddUtf8("backpressureReason", "none");
    data.AddUtf8(
        "backpressureDiagnostics",
        "synthetic stress corpus is contiguous and no-device; live batches add queue/high-watermark/drop evidence");
    data.AddWide("zhBackpressureHint", L"合成压测未观察到背压；真实驱动批次会补充队列水位、丢弃和读取上限证据。");
    data.AddUnsigned("eventsDropped", 0);
    data.AddUnsigned("lostCount", 0);
    data.AddUnsigned("totalEventsDropped", 0);
    data.AddUnsigned("totalEventsBackpressured", 0);
    data.AddUnsigned("queueCapacity", 0);
    data.AddUnsigned("queueHighWatermark", 0);
    data.AddUnsigned("highWatermark", 0);
    data.AddSigned("lastEnqueueFailureStatus", 0);
    data.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    data.AddUtf8("nextSequence", stressNextSequenceText);
    data.AddUtf8("sequence", stressNextSequenceText);
    data.AddUtf8("sequenceMeaning", "nextSequence");
    data.AddUtf8("sequencePolicy", "summary sequence is the next synthetic sequence after the contiguous stress corpus");
    data.AddWide("zhSequencePolicy", L"摘要行的 sequence 是连续合成压测集后的下一个 sequence。");
    data.AddUtf8("producerDroppedMaskHex", "0x00000000");
    data.AddUtf8("producerBackpressureMaskHex", "0x00000000");
    data.AddUtf8("StressJsonlExpectedDriverRows", std::to_string(options.stressCount));
    data.AddUtf8("StressJsonlSequenceStart", stressSequenceStartText);
    data.AddUtf8("StressJsonlSequenceEnd", stressSequenceEndText);
    data.AddUtf8("StressJsonlSequenceGapCount", "0");
    data.AddUtf8("StressJsonlLossEvidence", kStressJsonlLossEvidence);
    data.AddUtf8("StressJsonlBackpressureEvidence", kStressJsonlBackpressureEvidence);
    event.dataJson = data.Build();

    return EmitEvent(writer, event);
}

// Input: User options and event writer.
// Processing: Emits deterministic mock driver-like rows, then exits without
// opening the device path. This keeps CI and Guest Agent wiring testable before
// a signed kernel driver is installed in the guest VM.
// Return: Process exit code.
int RunSyntheticMode(const Options& options, EventWriter& writer) {
    const DWORD currentProcessId = kSyntheticSampleProcessId;
    const std::string currentProcessIdText = std::to_string(kSyntheticSampleProcessId);
    const std::wstring mockProcessPath = LR"(C:\Windows\System32\notepad.exe)";
    const std::wstring mockCommandLine = LR"("C:\Windows\System32\notepad.exe" --ksword-mock)";
    const bool stressMode = options.stressCount > 0;
    const std::string stressSequenceStartText = std::to_string(kSyntheticStressSequenceStart);
    const std::string stressSequenceEndText = stressMode
        ? std::to_string(kSyntheticStressSequenceStart + options.stressCount - 1)
        : "";

    SandboxEventFields mockEvent;
    mockEvent.eventType = "r0collector.mockDriverEvent";
    mockEvent.processId = currentProcessId;
    mockEvent.processName = L"notepad.exe";
    mockEvent.path = mockProcessPath;
    mockEvent.commandLine = mockCommandLine;
    JsonDataObjectBuilder mockData;
    AddSyntheticAbiVersionFields(mockData);
    mockData.AddBool("mock", true);
    mockData.AddWide("devicePath", options.devicePath);
    mockData.AddBool("healthOnly", options.healthOnly);
    mockData.AddBool("suppressSelfNoise", options.suppressSelfNoise);
    mockData.AddUtf8(
        "collectorNoisePolicy",
        options.suppressSelfNoise ? "suppress-self-noise" : "emit-self-noise");
    mockData.AddUtf8("schema", KSWORD_SANDBOX_EVENT_SCHEMA_NAME);
    mockData.AddUtf8("producer", "r0collector");
    AddSyntheticSelfNoiseFilterFields(mockData);
    AddCollectorAttributionFields(mockData, "synthetic-mock-marker", "collector-diagnostic");
    mockData.AddBool("collectorNoise", false);
    mockData.AddBool("collectorSelfNoise", false);
    mockData.AddBool("selfProcess", false);
    mockData.AddUtf8("collectorNoiseReason", "none");
    mockData.AddUtf8("collectorNoiseAction", "emit");
    mockData.AddBool("collectorSuppressed", false);
    mockData.AddBool("selfNoise", false);
    mockData.AddUtf8("selfNoiseReason", "none");
    mockData.AddUtf8("selfNoiseAction", "emit");
    mockData.AddBool("noise", false);
    mockData.AddBool("lost", false);
    mockData.AddUnsigned("lostCount", 0);
    mockData.AddBool("lossObserved", false);
    mockData.AddBool("backpressure", false);
    mockData.AddBool("backpressureObserved", false);
    mockData.AddUnsigned("highWatermark", 0);
    mockData.AddUnsigned("queueHighWatermark", 0);
    mockData.AddSigned("lastEnqueueFailureStatus", 0);
    mockData.AddUtf8("lastEnqueueFailureStatusHex", "0x00000000");
    mockData.AddBool("stress", stressMode);
    mockData.AddSigned("stressCount", options.stressCount);
    mockData.AddUtf8("semanticSelfCheckScenarios", kSyntheticSemanticSelfCheckScenarios);
    mockData.AddUnsigned("semanticContractVersion", kAbiSelfCheckDiagnosticsVersion);
    mockData.AddUnsigned("semanticSelfCheckRows", kSyntheticSemanticSelfCheckRows);
    mockData.AddUnsigned("semanticSelfCheckSequenceStart", kSyntheticSemanticSequenceStart);
    mockData.AddUnsigned(
        "semanticSelfCheckSequenceEnd",
        kSyntheticSemanticSequenceStart + kSyntheticSemanticSelfCheckRows - 1);
    mockData.AddUtf8(
        "semanticSelfCheckPolicy",
        "mock/stress emits semantic companion rows for process-lineage, DNS, HTTP, TLS, lateral movement, and download-execute without opening the driver");
    mockData.AddWide(
        "zhSemanticSelfCheckHint",
        L"mock/stress 会附加进程血缘、DNS、HTTP、TLS、横向移动和下载执行语义行；这些行不来自真实驱动。");
    if (stressMode) {
        mockData.AddSigned("StressJsonlExpectedDriverRows", options.stressCount);
        mockData.AddUtf8("StressJsonlSequenceStart", stressSequenceStartText);
        mockData.AddUtf8("StressJsonlSequenceEnd", stressSequenceEndText);
        mockData.AddSigned("StressJsonlSequenceGapCount", 0);
        mockData.AddBool("sequenceGapObserved", false);
        mockData.AddUnsigned("sequenceGapEstimate", 0);
        mockData.AddUtf8("StressJsonlLossEvidence", kStressJsonlLossEvidence);
        mockData.AddUtf8("StressJsonlBackpressureEvidence", kStressJsonlBackpressureEvidence);
    }
    mockData.AddUtf8("ioctlProtocol", "not-issued");
    mockData.AddUtf8("note", "Synthetic marker; driver category mock rows follow.");
    mockData.AddWide("zhNote", L"\u5408\u6210\u6807\u8bb0\u884c\uff1b\u540e\u7eed\u4f1a\u5199\u51fa driver \u5206\u7c7b mock \u884c\u3002");
    mockEvent.dataJson = mockData.Build();

    if (!EmitEvent(writer, mockEvent)) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.process",
            mockProcessPath,
            mockCommandLine,
            "process",
            "create",
            {
                {"imagePath", "C:\\Windows\\System32\\notepad.exe"},
                {"processId", currentProcessIdText},
                {"parentProcessId", currentProcessIdText}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "image.load",
            LR"(C:\Windows\System32\kernel32.dll)",
            mockCommandLine,
            "image",
            "load",
            {
                {"imagePath", "C:\\Windows\\System32\\kernel32.dll"},
                {"imageOperationName", "load"},
                {"imageLoadFamily", "windows-system-image"},
                {"injectionCandidate", "false"},
                {"userWritableImageCandidate", "false"},
                {"imageBase", "0x0000000180000000"},
                {"imageSize", "1048576"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.file",
            LR"(C:\Users\Public\ksword-r0collector-mock.tmp)",
            mockCommandLine,
            "file",
            "create",
            {
                {"filePath", "C:\\Users\\Public\\ksword-r0collector-mock.tmp"},
                {"artifactCandidateKind", "dropped-file-or-file-change"},
                {"dropLocationFamily", "shared-writable-directory"},
                {"droppedFileCandidate", "true"},
                {"startupFolderCandidate", "false"},
                {"downloadExecuteCandidate", "false"},
                {"desiredAccessHex", "0x0012019F"},
                {"disposition", "create"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitMockDriverCategoryEvent(
            writer,
            options,
            "driver.registry",
            LR"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KSwordMock)",
            mockCommandLine,
            "registry",
            "setValue",
            {
                {"keyPath", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
                {"valueName", "KSwordMock"},
                {"valueType", "REG_SZ"},
                {"persistenceCandidate", "true"},
                {"registryPersistenceSignal", "common-windows-persistence-key"},
                {"persistenceFamily", "autorun-run-key"},
                {"servicePersistenceCandidate", "false"},
                {"ifeoPersistenceCandidate", "false"},
                {"startupRegistryCandidate", "true"}
            })) {
        return kExitRuntimeFailure;
    }

    if (!EmitSyntheticSemanticSelfCheckEvents(
            writer,
            options,
            mockCommandLine,
            currentProcessId,
            currentProcessIdText)) {
        return kExitRuntimeFailure;
    }

    if (!EmitSyntheticStressEvents(writer, options, mockCommandLine)) {
        return kExitRuntimeFailure;
    }

    if (!EmitSyntheticStressSummary(writer, options)) {
        return kExitRuntimeFailure;
    }

    if (options.injectJsonlNoise && !EmitSyntheticJsonlNoiseRows(writer)) {
        return kExitRuntimeFailure;
    }

    return kExitSuccess;
}

} // namespace KSword::Sandbox::R0Collector
