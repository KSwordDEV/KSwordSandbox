using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Net;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Network;

/// <summary>
/// Imports network JSONL sidecars generated beside packet captures by tshark,
/// Zeek-like exporters, or KSword/R0 collectors. Inputs are line-delimited JSON
/// or weak text rows with key/value tokens or endpoint arrows; processing
/// best-effort maps DNS/HTTP/TLS and connection fields into the shared network
/// telemetry schema; methods return normalized SandboxEvent rows and never
/// require tshark to be installed.
/// </summary>
public sealed class NetworkSidecarEventImporter
{
    private const int MaxLines = 4096;

    private static readonly Regex KeyValueTokenRegex = new(
        "(?<key>[A-Za-z_@][A-Za-z0-9_.-]*)\\s*(?:=|:)\\s*(?:\"(?<quoted>[^\"]*)\"|'(?<single>[^']*)'|(?<value>\\S+))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex EndpointFlowRegex = new(
        "(?<src>(?:\\d{1,3}\\.){3}\\d{1,3}|\\[[0-9a-fA-F:.%]+\\]|[A-Za-z0-9_.-]+):(?<srcPort>\\d{1,5})\\s*(?:->|=>|to)\\s*(?<dst>(?:\\d{1,3}\\.){3}\\d{1,3}|\\[[0-9a-fA-F:.%]+\\]|[A-Za-z0-9_.-]+):(?<dstPort>\\d{1,5})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex HttpRequestLineRegex = new(
        "\"(?<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\s+(?<uri>\\S+)\\s+HTTP/[0-9.]+\"",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public IReadOnlyList<SandboxEvent> Import(string path)
    {
        var source = NetworkArtifactSource.FromPath(path);
        var events = ImportEvents(path, source);
        return
        [
            NetworkTelemetrySchema.CreateImportSummary(
                path,
                source,
                events,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["importer"] = nameof(NetworkSidecarEventImporter),
                    ["importSource"] = "sidecar-jsonl",
                    ["sidecarArtifactCount"] = "1",
                    ["pcapArtifactCount"] = "0",
                    ["parser"] = "jsonl-sidecar",
                    ["tsharkRequired"] = "false"
                }),
            .. events
        ];
    }

    internal IReadOnlyList<SandboxEvent> ImportEvents(string path, NetworkArtifactSource source)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        var events = new List<SandboxEvent>();
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            string? line;
            var lineNumber = 0;
            while (lineNumber < MaxLines && (line = reader.ReadLine()) is not null)
            {
                lineNumber++;
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var trimmed = line.Trim();
                if (trimmed.StartsWith('{'))
                {
                    TryImportJsonLine(trimmed, path, lineNumber, source, events);
                }
                else
                {
                    TryImportLogLine(trimmed, path, lineNumber, source, events);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            events.Add(CreateParseError(path, 0, ex.Message, source, "stream", "sidecar_stream_parse_error", "sidecar.stream"));
        }

        return events;
    }

    public static bool IsLikelyNetworkSidecarPath(string path)
    {
        var extension = Path.GetExtension(path);
        if (!string.Equals(extension, ".jsonl", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(extension, ".ndjson", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(extension, ".log", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(extension, ".txt", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var normalized = path.Replace('\\', '/');
        var fileName = Path.GetFileName(path);
        return normalized.Contains("/packet-captures/", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("/network-sidecars/", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("/network-telemetry/", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("pcap", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("tshark", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("zeek", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("dns", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("ssl", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("conn", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("flow", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains("network", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(fileName, "driver-events.jsonl", StringComparison.OrdinalIgnoreCase);
    }

    private static void TryImportJsonLine(
        string line,
        string path,
        int lineNumber,
        NetworkArtifactSource source,
        List<SandboxEvent> events)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            FlattenJson(document.RootElement, fields, prefix: string.Empty);
            if (TryCreateNetworkEvent(fields, path, lineNumber, source, "jsonl", out var evt))
            {
                events.Add(evt);
            }
        }
        catch (JsonException ex)
        {
            events.Add(CreateParseError(path, lineNumber, ex.Message, source, "jsonl", "sidecar_json_parse_error", "sidecar.line", line));
        }
    }

    private static void TryImportLogLine(
        string line,
        string path,
        int lineNumber,
        NetworkArtifactSource source,
        List<SandboxEvent> events)
    {
        var fields = ParseKeyValueLine(line);
        AddLooseLogHints(line, fields);
        if (fields.Count == 0)
        {
            return;
        }

        if (TryCreateNetworkEvent(fields, path, lineNumber, source, "log", out var evt))
        {
            events.Add(evt);
        }
    }

    private static bool TryCreateNetworkEvent(
        IReadOnlyDictionary<string, string> fields,
        string path,
        int lineNumber,
        NetworkArtifactSource source,
        string sidecarFormat,
        out SandboxEvent evt)
    {
        evt = default!;
        var originalEventType = FirstValue(
            fields,
            "eventType",
            "event_type",
            "event.type",
            "event.kind",
            "event.category",
            "event.action",
            "event.dataset",
            "type",
            "kind",
            "message_type",
            "_source.layers.frame.frame.protocols");
        var timestamp = NetworkTelemetrySchema.ParseTimestampOrDefault(
            FirstValue(fields, "timestamp", "@timestamp", "time", "ts", "start", "startTime", "event.start", "frame.time_epoch", "_source.layers.frame.frame.time_epoch"),
            DateTimeOffset.UtcNow);
        var rawSourceEndpoint = FirstValue(fields, "sourceEndpoint", "srcEndpoint", "src", "source", "clientEndpoint", "client.endpoint", "localEndpoint", "local.endpoint", "id.orig");
        var rawDestinationEndpoint = FirstValue(fields, "destinationEndpoint", "dstEndpoint", "destEndpoint", "dst", "dest", "destination", "serverEndpoint", "server.endpoint", "remoteEndpoint", "remote.endpoint", "id.resp");
        var sourceEndpoint = SplitEndpoint(rawSourceEndpoint);
        var destinationEndpoint = SplitEndpoint(rawDestinationEndpoint);
        var rawSourceIp = FirstValue(fields, "sourceIp", "sourceAddress", "srcIp", "src_ip", "src_addr", "orig_h", "id.orig_h", "client.ip", "client.address", "source.ip", "source.address", "source.addr", "localAddress", "local.address", "ip.src", "ipv6.src", "_source.layers.ip.ip.src", "_source.layers.ipv6.ipv6.src");
        var rawDestinationIp = FirstValue(fields, "destinationIp", "destinationAddress", "destIp", "dstIp", "dest_ip", "dst_ip", "dst_addr", "resp_h", "id.resp_h", "server.ip", "server.address", "destination.ip", "destination.address", "dest.ip", "dest.address", "remoteAddress", "remote.address", "ip.dst", "ipv6.dst", "_source.layers.ip.ip.dst", "_source.layers.ipv6.ipv6.dst");
        var sourceIpValue = SplitEndpoint(rawSourceIp);
        var destinationIpValue = SplitEndpoint(rawDestinationIp);
        var sourceIp = sourceIpValue.Address ?? sourceEndpoint.Address;
        var destinationIp = destinationIpValue.Address ?? destinationEndpoint.Address;
        var sourcePort = NetworkTelemetrySchema.ParsePort(FirstValue(fields, "sourcePort", "srcPort", "src_port", "sport", "orig_p", "id.orig_p", "client.port", "source.port", "localPort", "local.port", "tcp.srcport", "udp.srcport", "_source.layers.tcp.tcp.srcport", "_source.layers.udp.udp.srcport")) ?? sourceEndpoint.Port ?? sourceIpValue.Port;
        var destinationPort = NetworkTelemetrySchema.ParsePort(FirstValue(fields, "destinationPort", "destPort", "dstPort", "dest_port", "dst_port", "dport", "resp_p", "id.resp_p", "server.port", "destination.port", "dest.port", "remotePort", "remote.port", "tcp.dstport", "udp.dstport", "_source.layers.tcp.tcp.dstport", "_source.layers.udp.udp.dstport")) ?? destinationEndpoint.Port ?? destinationIpValue.Port;
        var protocol = FirstValue(fields, "protocol", "transportProtocol", "protocolName", "proto", "network.transport", "network.protocol", "transport", "ip_proto", "ip.protocol", "_source.layers.frame.frame.protocols");
        protocol = InferProtocol(protocol, sourcePort, destinationPort);

        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sidecarLineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sidecarFormat"] = sidecarFormat,
            ["importSource"] = "sidecar-jsonl",
            ["parser"] = "sidecar-jsonl"
        };
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "originalEventType", originalEventType);
        AddSidecarProcessFields(fields, extra);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "direction", FirstValue(fields, "direction", "flow.direction", "network.direction", "event.direction"));
        AddCommonSidecarFields(fields, extra);

        if (IsNetworkHealth(fields, originalEventType))
        {
            AddNetworkHealthFields(fields, extra);
            evt = ApplySidecarProcessContext(CreateNetworkHealthEvent(
                path,
                timestamp,
                source,
                originalEventType,
                extra), fields);
            return true;
        }

        if (IsDns(fields, originalEventType))
        {
            AddDnsFields(fields, extra);
            evt = ApplySidecarProcessContext(NetworkTelemetrySchema.CreateNetworkEvent(
                "dns.query",
                timestamp,
                null,
                "dns",
                "sidecar-jsonl",
                protocol,
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort,
                source,
                extra), fields);
            return true;
        }

        if (IsHttp(fields, originalEventType))
        {
            AddHttpFields(fields, extra);
            evt = ApplySidecarProcessContext(NetworkTelemetrySchema.CreateNetworkEvent(
                "http.request",
                timestamp,
                null,
                "http",
                "sidecar-jsonl",
                string.IsNullOrWhiteSpace(protocol) ? "tcp" : protocol,
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort,
                source,
                extra), fields);
            return true;
        }

        if (IsTls(fields, originalEventType))
        {
            AddTlsFields(fields, extra);
            evt = ApplySidecarProcessContext(NetworkTelemetrySchema.CreateNetworkEvent(
                "tls.connection",
                timestamp,
                null,
                "tls",
                "sidecar-jsonl",
                string.IsNullOrWhiteSpace(protocol) ? "tcp" : protocol,
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort,
                source,
                extra), fields);
            return true;
        }

        if (IsConnection(fields, originalEventType, sourceIp, destinationIp, sourcePort, destinationPort))
        {
            AddConnectionFields(fields, extra);
            evt = ApplySidecarProcessContext(NetworkTelemetrySchema.CreateNetworkEvent(
                "network.flow",
                timestamp,
                null,
                "connection",
                "sidecar-jsonl",
                protocol,
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort,
                source,
                extra), fields);
            return true;
        }

        return false;
    }

    private static SandboxEvent CreateNetworkHealthEvent(
        string path,
        DateTimeOffset timestamp,
        NetworkArtifactSource source,
        string? originalEventType,
        Dictionary<string, string> extra)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["schema"] = NetworkTelemetrySchema.SchemaVersion,
            ["eventFamily"] = "network",
            ["eventKind"] = "health",
            ["importSource"] = "sidecar-jsonl",
            ["parser"] = "sidecar-jsonl",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["behaviorScope"] = "network-collection-health",
            ["noisePolicy"] = "nonbehavior-evidence-quality"
        };

        NetworkTelemetrySchema.AddIfNotEmpty(data, "originalEventType", originalEventType);
        foreach (var pair in extra)
        {
            NetworkTelemetrySchema.AddIfNotEmpty(data, pair.Key, pair.Value);
        }

        NetworkTelemetrySchema.AddArtifactData(data, source);
        NetworkTelemetrySchema.ApplyHealthAndLocalization(data);
        return new SandboxEvent
        {
            EventType = !string.IsNullOrWhiteSpace(originalEventType) &&
                originalEventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase)
                    ? originalEventType
                    : "network.health",
            Timestamp = timestamp == default ? DateTimeOffset.UtcNow : timestamp,
            Source = "host",
            Path = path,
            Data = data
        };
    }

    private static bool IsNetworkHealth(IReadOnlyDictionary<string, string> fields, string? eventType)
    {
        return Contains(eventType, "driverNetworkStatus") ||
            Contains(eventType, "networkStatus") ||
            HasAny(
                fields,
                "networkStatusAvailable",
                "readinessState",
                "lastDegradeReasonName",
                "supportedLayerMask",
                "supportedLayerMaskHex",
                "activeLayerMask",
                "activeLayerMaskHex",
                "lastRegisteredCalloutMask",
                "lastAddedFilterMask",
                "todoMask",
                "queueFailureCount",
                "classifyPayloadFailureCount",
                "registerNtStatusHex",
                "engineNtStatusHex",
                "lastQueueFailureNtStatusHex");
    }

    private static void AddNetworkHealthFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "diagnosticStage", FirstValue(fields, "diagnosticStage", "stage", "event.stage") ?? "networkStatus");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "networkStatusAvailable", FirstValue(fields, "networkStatusAvailable", "available", "isAvailable"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "readinessState", FirstValue(fields, "readinessState", "state", "status"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "diagnosticCode", FirstValue(fields, "diagnosticCode", "code", "error.code"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "lastDegradeReasonName", FirstValue(fields, "lastDegradeReasonName", "degradeReason", "reason"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "supportedLayerMask", FirstValue(fields, "supportedLayerMask", "supportedLayerMaskHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "activeLayerMask", FirstValue(fields, "activeLayerMask", "activeLayerMaskHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "lastRegisteredCalloutMask", FirstValue(fields, "lastRegisteredCalloutMask", "lastRegisteredCalloutMaskHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "lastAddedFilterMask", FirstValue(fields, "lastAddedFilterMask", "lastAddedFilterMaskHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "todoMask", FirstValue(fields, "todoMask", "todoMaskHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "classifyCount", FirstValue(fields, "classifyCount"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "eventCount", FirstValue(fields, "eventCount"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "queueFailureCount", FirstValue(fields, "queueFailureCount"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "classifyPayloadFailureCount", FirstValue(fields, "classifyPayloadFailureCount"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "registerNtStatusHex", FirstValue(fields, "registerNtStatusHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "engineNtStatusHex", FirstValue(fields, "engineNtStatusHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "lastQueueFailureNtStatusHex", FirstValue(fields, "lastQueueFailureNtStatusHex"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "zhMessage", FirstValue(fields, "zhMessage"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "zhHint", FirstValue(fields, "zhHint"));
    }

    private static bool IsDns(IReadOnlyDictionary<string, string> fields, string? eventType)
    {
        return Contains(eventType, "dns") ||
            HasAny(
                fields,
                "queryName",
                "query",
                "dnsQuery",
                "qname",
                "query.name",
                "domain",
                "rrname",
                "dns.rrname",
                "dns.qry.name",
                "dns.question.name",
                "dns.questions.name",
                "dns.query.name",
                "dns.answers",
                "dns.answers.data",
                "rcode",
                "responseCode",
                "dnsRcode",
                "dns.rcode",
                "dns.flags.rcode",
                "_source.layers.dns.dns.qry.name");
    }

    private static bool IsHttp(IReadOnlyDictionary<string, string> fields, string? eventType)
    {
        return Contains(eventType, "http") ||
            HasAny(fields, "method", "httpMethod", "requestMethod", "httpRequestMethod", "http.method", "http.request.method", "request.method", "_source.layers.http.http.request.method") ||
            HasAny(fields, "host", "hostname", "httpHost", "http.host", "http.hostname", "server.domain", "url.domain", "_source.layers.http.http.host") ||
            HasAny(fields, "url", "http.url", "url.full", "url.original", "http.request.uri", "statusCode", "httpStatusCode", "responseStatusCode", "http.response.code", "http.response.status_code", "_source.layers.http.http.request.uri");
    }

    private static bool IsTls(IReadOnlyDictionary<string, string> fields, string? eventType)
    {
        return Contains(eventType, "tls") ||
            Contains(eventType, "ssl") ||
            HasAny(
                fields,
                "sni",
                "serverName",
                "tlsSni",
                "server_name",
                "tls.sni",
                "tls.server_name",
                "tls.handshake.extensions_server_name",
                "ssl.handshake.extensions_server_name",
                "ja3",
                "ja3.hash",
                "ja3Fingerprint",
                "tls.ja3.hash",
                "alpn",
                "tls.alpn",
                "cert.subject",
                "certificateSubject",
                "certSha256",
                "certificateSha256",
                "tls.cert.subject",
                "_source.layers.tls.tls.handshake.extensions_server_name");
    }

    private static bool IsConnection(
        IReadOnlyDictionary<string, string> fields,
        string? eventType,
        string? sourceIp,
        string? destinationIp,
        int? sourcePort,
        int? destinationPort)
    {
        return Contains(eventType, "connection") ||
            Contains(eventType, "flow") ||
            Contains(eventType, "network") ||
            Contains(eventType, "conn") ||
            HasAny(fields, "flowKey", "uid", "connection") ||
            (!string.IsNullOrWhiteSpace(sourceIp) &&
                !string.IsNullOrWhiteSpace(destinationIp) &&
                (sourcePort.HasValue || destinationPort.HasValue));
    }

    private static void AddDnsFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        var queryName = FirstValue(
            fields,
            "queryName",
            "query",
            "dnsQuery",
            "qname",
            "query.name",
            "domain",
            "rrname",
            "dns.rrname",
            "dns.qry.name",
            "dns.question.name",
            "dns.questions.name",
            "dns.query.name",
            "_source.layers.dns.dns.qry.name");
        var queryType = FirstValue(
            fields,
            "queryType",
            "recordType",
            "qtype",
            "typeName",
            "rrtype",
            "dns.rrtype",
            "dns.qry.type",
            "dns.qry.type_name",
            "dns.question.type",
            "dns.questions.type",
            "dns.query.type",
            "dns.answers.type",
            "_source.layers.dns.dns.qry.type");
        AddAliases(extra, queryName, "queryName", "qname", "domain", "dnsQueryName", "query", "dnsQuery", "rrname", "dns.rrname", "dns.qry.name", "dns.question.name", "dns.questions.name", "dns.query.name");
        AddAliases(extra, queryType, "queryType", "recordType", "dnsRecordType", "qtype", "rrtype", "dns.rrtype", "dns.qry.type", "dns.question.type", "dns.questions.type", "dns.query.type");

        var rcode = NetworkTelemetrySchema.NormalizeDnsRCode(FirstValue(fields, "rcode", "rcodeName", "responseCode", "dnsRcode", "dnsResponseCode", "dns.rcode", "dns.flags.rcode", "dns.response_code", "_source.layers.dns.dns.flags.rcode"));
        AddAliases(extra, rcode, "rcode", "rcodeName", "responseCode", "dnsRcode", "dnsResponseCode", "dns.rcode", "dns.flags.rcode", "dns.response_code");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "isResponse", NormalizeBoolean(FirstValue(fields, "isResponse", "dns.flags.response", "dns.response", "_source.layers.dns.dns.flags.response")));

        var answer = FirstValue(
            fields,
            "answer",
            "answers",
            "resolvedIp",
            "resolvedIps",
            "answerIp",
            "answerAddress",
            "dns.answer",
            "dns.answers",
            "dns.answers.data",
            "dns.a",
            "dns.aaaa",
            "dns.cname",
            "dns.resp.name",
            "_source.layers.dns.dns.a",
            "_source.layers.dns.dns.aaaa",
            "_source.layers.dns.dns.cname");
        AddAliases(extra, answer, "answer", "answers", "dnsAnswer", "dnsAnswers", "resolvedIp", "resolvedIps", "resolvedAddress", "resolvedAddresses", "answerIp", "answerAddress", "dns.answer", "dns.answers", "dns.answers.data", "dns.answers.name", "dns.resp.name", "dns.a", "dns.aaaa", "dns.cname");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "answerTypeSummary", FirstValue(fields, "answerTypeSummary", "dnsAnswerTypeSummary", "dns.answers.type", "dns.rrtype", "_source.layers.dns.dns.resp.type"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "dnsAnswerTypeSummary", FirstValue(fields, "answerTypeSummary", "dnsAnswerTypeSummary", "dns.answers.type", "dns.rrtype", "_source.layers.dns.dns.resp.type"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "cnameChain", FirstValue(fields, "cnameChain", "dnsCnameChain", "dns.cname.chain", "dns.cname", "_source.layers.dns.dns.cname"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "dnsCnameChain", FirstValue(fields, "cnameChain", "dnsCnameChain", "dns.cname.chain", "dns.cname", "_source.layers.dns.dns.cname"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "answerCount", FirstNonEmpty(FirstValue(fields, "answerCount", "answersCount", "dns.answers.count", "dns.count.answers"), CountDelimitedValues(answer)));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "ttl", FirstValue(fields, "ttl", "dns.ttl", "dns.resp.ttl", "dns.answers.ttl"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "recordClass", FirstValue(fields, "recordClass", "queryClass", "dns.qry.class", "dns.question.class"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "dnsTransactionId", FirstValue(fields, "dnsTransactionId", "transactionId", "dns.id"));

        if (string.Equals(rcode, "NXDOMAIN", StringComparison.OrdinalIgnoreCase))
        {
            extra["classification"] = "nxdomain";
            extra["dnsOutcome"] = "negative";
            extra["isNxDomain"] = "true";
            extra["zhHint"] = "DNS 返回 NXDOMAIN；若短时间大量出现，优先关联 DGA、探测域名或 C2 备用域。";
        }
        else if (!string.IsNullOrWhiteSpace(answer))
        {
            extra["dnsOutcome"] = "answered";
        }
    }

    private static void AddHttpFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        var uri = FirstValue(fields, "uri", "requestUri", "path", "url.path", "url.original", "http.url", "http.request.uri", "http.request.full_uri", "http.target", "cs-uri-stem", "_source.layers.http.http.request.uri");
        var host = FirstValue(fields, "host", "hostname", "httpHost", "authority", "url.host", "url.domain", "server.domain", "http.host", "http.hostname", "http.request.headers.host", "request.headers.host", "_source.layers.http.http.host");
        var url = FirstValue(fields, "url", "http.url", "url.full", "url.original", "_source.layers.http.http.url");
        var absoluteUrl = string.Empty;
        var scheme = FirstValue(fields, "scheme", "url.scheme", "http.scheme", "network.protocol");
        if (!string.IsNullOrWhiteSpace(url) && Uri.TryCreate(url, UriKind.Absolute, out var parsedUrl))
        {
            absoluteUrl = url;
            host ??= parsedUrl.Host;
            uri ??= string.IsNullOrWhiteSpace(parsedUrl.PathAndQuery) ? "/" : parsedUrl.PathAndQuery;
            scheme = parsedUrl.Scheme;
        }
        else if (!string.IsNullOrWhiteSpace(url) && string.IsNullOrWhiteSpace(uri))
        {
            uri = url;
        }

        scheme = InferHttpScheme(scheme, fields);
        var method = FirstValue(fields, "method", "httpMethod", "requestMethod", "httpRequestMethod", "http.method", "http.request.method", "request.method", "cs-method", "_source.layers.http.http.request.method");
        AddAliases(extra, method, "method", "httpMethod", "requestMethod", "httpRequestMethod", "http.method", "http.request.method");
        AddAliases(extra, uri, "uri", "requestUri", "path", "url.path", "http.request.uri", "http.target", "cs-uri-stem");
        AddAliases(extra, host, "host", "hostname", "httpHost", "authority", "url.host", "url.domain", "server.domain", "http.host", "http.hostname", "http.request.headers.host", "request.headers.host");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "scheme", scheme);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "httpScheme", scheme);
        if (!string.IsNullOrWhiteSpace(absoluteUrl))
        {
            NetworkTelemetrySchema.AddIfNotEmpty(extra, "url", absoluteUrl);
        }
        else if (!string.IsNullOrWhiteSpace(host))
        {
            NetworkTelemetrySchema.AddIfNotEmpty(extra, "url", $"{(string.IsNullOrWhiteSpace(scheme) ? "http" : scheme)}://{host}{(string.IsNullOrWhiteSpace(uri) ? "/" : uri)}");
        }

        var userAgent = FirstValue(fields, "userAgent", "user_agent", "httpUserAgent", "http.user_agent", "http.user_agent.original", "http.request.headers.user-agent", "request.headers.user-agent", "user-agent", "_source.layers.http.http.user_agent");
        AddAliases(extra, userAgent, "userAgent", "user_agent", "httpUserAgent", "http.user_agent", "http.user_agent.original", "http.request.headers.user-agent", "request.headers.user-agent", "user-agent");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "contentType", FirstValue(fields, "contentType", "mimeType", "http.content_type", "http.request.content_type", "http.response.mime_type", "http.response.content_type", "_source.layers.http.http.content_type"));
        var statusCode = FirstValue(fields, "statusCode", "httpStatusCode", "responseStatusCode", "httpStatus", "status", "status_code", "responseCode", "response.status_code", "http.status", "http.response.code", "http.response.status_code", "http.status_code", "sc-status", "_source.layers.http.http.response.code");
        AddAliases(extra, statusCode, "statusCode", "responseStatusCode", "httpStatusCode", "httpStatus", "status", "responseCode", "http.response.status_code", "http.response.code", "http.status_code", "http.status", "status_code", "response.status_code", "sc-status");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "statusFamily", StatusFamily(statusCode));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "payloadMagic", FirstValue(fields, "payloadMagic", "file.magic"));
        var referer = FirstValue(fields, "referer", "referrer", "http.referer", "http.request.referrer", "request.headers.referer", "request.headers.referrer");
        AddAliases(extra, referer, "referer", "referrer", "http.referer", "http.request.referrer", "request.headers.referer", "request.headers.referrer");
        var contentDisposition = FirstValue(fields, "contentDisposition", "httpContentDisposition", "http.content_disposition", "http.response.headers.content-disposition", "response.headers.content-disposition");
        AddAliases(extra, contentDisposition, "contentDisposition", "httpContentDisposition", "http.content_disposition", "http.response.headers.content-disposition", "response.headers.content-disposition");
        AddAliases(extra, FirstValue(fields, "downloadFilename", "downloadFileName", "filename", "file.name", "http.file_data.filename"), "downloadFilename", "downloadFileName", "filename", "file.name", "httpDownloadFilename");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "contentEncoding", FirstValue(fields, "contentEncoding", "http.content_encoding", "http.response.content_encoding"));

        var requestBytes = FirstValue(fields, "requestBodyBytes", "requestBytes", "http.request.body.bytes", "http.request.body.size", "http.request.bytes", "request.bytes", "requestContentLength", "http.request.headers.content_length", "bytes_toserver", "orig_bytes");
        var responseBytes = FirstValue(fields, "responseBodyBytes", "responseBytes", "http.response.body.bytes", "http.response.body.size", "http.response.bytes", "response.bytes", "responseContentLength", "http.response.headers.content_length", "bytes_toclient", "resp_bytes");
        var requestContentLength = FirstNonEmpty(FirstValue(fields, "requestContentLength", "http.request.headers.content_length", "request.headers.content-length"), requestBytes);
        var responseContentLength = FirstNonEmpty(FirstValue(fields, "responseContentLength", "http.response.headers.content_length", "response.headers.content-length"), responseBytes);
        AddAliases(extra, requestBytes, "requestBodyBytes", "requestBytes", "httpRequestBodyBytes", "requestBodySizeBytes", "requestBodySize", "http.request.body.bytes", "http.request.body.size", "request.body.bytes", "bytesToServer");
        AddAliases(extra, responseBytes, "responseBodyBytes", "responseBytes", "httpResponseBodyBytes", "responseBodySizeBytes", "responseBodySize", "http.response.body.bytes", "http.response.body.size", "response.body.bytes", "bytesToClient");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "requestContentLength", requestContentLength);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "responseContentLength", responseContentLength);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "uploadBytes", FirstNonEmpty(requestBytes, requestContentLength));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "downloadBytes", FirstNonEmpty(responseBytes, responseContentLength));

        if (IsUploadCandidate(method, FirstNonEmpty(requestBytes, requestContentLength)))
        {
            extra["uploadCandidate"] = "true";
            extra["transferDirection"] = "upload";
            extra["zhHint"] = "HTTP 请求包含上传/出站 body 元数据；优先关联释放文件、凭据或 C2 回传证据。";
        }

        if (!string.IsNullOrWhiteSpace(FirstValue(fields, "authorization", "authorizationHeader", "http.authorization", "http.request.headers.authorization", "request.headers.authorization")))
        {
            extra["authorizationHeaderPresent"] = "true";
        }

        if (!string.IsNullOrWhiteSpace(FirstValue(fields, "cookie", "http.cookie", "http.request.cookie", "http.request.headers.cookie", "request.headers.cookie")))
        {
            extra["cookiePresent"] = "true";
        }
    }

    private static void AddTlsFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        var sni = FirstValue(fields, "sni", "serverName", "server_name", "tls.sni", "tls.server_name", "ssl.server_name", "tls.handshake.extensions_server_name", "ssl.handshake.extensions_server_name", "_source.layers.tls.tls.handshake.extensions_server_name");
        AddAliases(extra, sni, "sni", "serverName", "tlsServerName", "tlsSni", "server_name", "tls.sni", "tls.server_name", "ssl.server_name", "tls.handshake.extensions_server_name", "ssl.handshake.extensions_server_name");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "tlsVersion", FirstValue(fields, "tlsVersion", "version", "ssl.version", "tls.version", "tls.version.name", "tls.record.version", "tls.handshake.version", "_source.layers.tls.tls.record.version"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "handshakeType", FirstValue(fields, "handshakeType", "tls.handshake.type", "tls.handshake.type_name", "_source.layers.tls.tls.handshake.type"));
        var ja3 = FirstValue(fields, "ja3", "ja3.hash", "tls.ja3", "tls.ja3.hash", "tls.handshake.ja3", "tls.handshake.ja3_hash", "ssl.ja3", "ssl.ja3_hash");
        var ja3s = FirstValue(fields, "ja3s", "ja3s.hash", "tls.ja3s", "tls.ja3s.hash", "tls.handshake.ja3s", "tls.handshake.ja3s_hash", "ssl.ja3s", "ssl.ja3s_hash");
        AddAliases(extra, ja3, "ja3", "ja3Hash", "tlsJa3", "ja3Fingerprint", "ja3Digest", "ja3Md5", "ja3.hash", "tls.ja3", "tls.ja3.hash", "tls.handshake.ja3", "tls.handshake.ja3_hash", "ssl.ja3", "ssl.ja3_hash");
        AddAliases(extra, ja3s, "ja3s", "ja3sHash", "tlsJa3s", "ja3sFingerprint", "ja3sDigest", "ja3sMd5", "ja3s.hash", "tls.ja3s", "tls.ja3s.hash", "tls.handshake.ja3s", "tls.handshake.ja3s_hash", "ssl.ja3s", "ssl.ja3s_hash");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "alpn", FirstValue(fields, "alpn", "applicationLayerProtocol", "tls.alpn", "tls.handshake.extensions_alpn", "tls.handshake.extensions_alpn_str", "ssl.alpn"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "cipherSuite", FirstValue(fields, "cipherSuite", "cipher", "tls.cipher", "tls.cipher_suite", "tls.handshake.ciphersuite", "ssl.cipher"));
        var certSubject = FirstValue(fields, "certSubject", "certificateSubject", "subject", "x509.subject", "cert.subject", "tls.cert.subject", "tls.certificate.subject", "tls.handshake.certificate.subject", "ssl.subject");
        AddAliases(extra, certSubject, "certSubject", "certificateSubject", "x509Subject", "x509.subject", "tls.cert.subject", "tls.certificate.subject");
        var certIssuer = FirstValue(fields, "certIssuer", "certificateIssuer", "issuer", "x509.issuer", "cert.issuer", "tls.cert.issuer", "tls.certificate.issuer", "tls.handshake.certificate.issuer", "ssl.issuer");
        AddAliases(extra, certIssuer, "certIssuer", "certificateIssuer", "x509Issuer", "x509.issuer", "tls.cert.issuer", "tls.certificate.issuer");
        var certSerial = FirstValue(fields, "certSerial", "certificateSerial", "x509.serial_number", "cert.serial", "tls.cert.serial", "tls.certificate.serial");
        AddAliases(extra, certSerial, "certSerial", "certificateSerial", "x509Serial", "x509.serial_number", "tls.cert.serial", "tls.certificate.serial");
        var certSha256 = FirstValue(fields, "certSha256", "certificateSha256", "certificateFingerprintSha256", "x509.fingerprint.sha256", "cert.sha256", "cert.fingerprint.sha256", "tls.cert.fingerprint.sha256", "tls.certificate.fingerprint.sha256");
        AddAliases(extra, certSha256, "certSha256", "certificateSha256", "certificateFingerprintSha256", "serverCertificateSha256", "x509.fingerprint.sha256", "cert.sha256", "cert.fingerprint.sha256", "tls.cert.sha256", "tls.cert.fingerprint.sha256", "tls.certificate.sha256", "tls.certificate.fingerprint.sha256");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "certSha1", FirstValue(fields, "certSha1", "certificateSha1", "x509.fingerprint.sha1", "cert.sha1", "cert.fingerprint.sha1", "tls.cert.fingerprint.sha1"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "certNotBefore", FirstValue(fields, "certNotBefore", "certificateNotBefore", "x509.not_before", "tls.cert.not_before"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "certNotAfter", FirstValue(fields, "certNotAfter", "certificateNotAfter", "x509.not_after", "tls.cert.not_after"));
        var validationStatus = FirstValue(fields, "validationStatus", "certificateStatus", "tls.validation_status", "ssl.validation_status", "cert.validation_status", "tls.cert.validation_status");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "certificateStatus", validationStatus);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "validationStatus", validationStatus);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "certSelfSigned", NormalizeBoolean(FirstValue(fields, "certSelfSigned", "selfSigned", "certificate.self_signed", "tls.cert.self_signed")));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "certExpired", NormalizeBoolean(FirstValue(fields, "certExpired", "certificate.expired", "tls.cert.expired")));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "certificateValidityStatus", FirstValue(fields, "certificateValidityStatus", "tlsCertificateValidityStatus", "x509.validity.status"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "tlsCertificateRiskReason", FirstValue(fields, "tlsCertificateRiskReason", "certificateRiskReason", "tls.cert.risk_reason"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "tlsCertificateRiskClassification", FirstValue(fields, "tlsCertificateRiskClassification", "certificateRiskClassification", "tls.cert.risk_classification"));
        if (Contains(validationStatus, "invalid") ||
            Contains(validationStatus, "self") ||
            string.Equals(FirstValue(fields, "certSelfSigned", "selfSigned", "certificate.self_signed", "tls.cert.self_signed"), "true", StringComparison.OrdinalIgnoreCase))
        {
            extra["tlsCertificateRisk"] = "suspicious";
            extra["protocolHealth"] = "warning";
            extra["zhHint"] = "TLS 证书状态异常或自签名；请结合 SNI、JA3/JA3S、目标 IP 和 VT/情报结果复核。";
        }
    }

    private static void AddConnectionFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "state", FirstValue(fields, "state", "conn_state", "connection.state", "event.outcome"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "durationSeconds", FirstValue(fields, "duration", "durationSeconds", "event.duration", "flow.duration"));
        var packetsToServer = FirstValue(fields, "packetsToServer", "sourcePackets", "orig_pkts", "pkts_toserver", "source.packets", "network.packets_toserver");
        var packetsToClient = FirstValue(fields, "packetsToClient", "destinationPackets", "resp_pkts", "pkts_toclient", "destination.packets", "network.packets_toclient");
        var bytesToServer = FirstValue(fields, "bytesToServer", "sourceBytes", "orig_bytes", "bytes_toserver", "source.bytes", "network.bytes_toserver");
        var bytesToClient = FirstValue(fields, "bytesToClient", "destinationBytes", "resp_bytes", "bytes_toclient", "destination.bytes", "network.bytes_toclient");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "packetCount", FirstNonEmpty(FirstValue(fields, "packetCount", "packets", "pkts", "packet_count", "network.packets"), SumNumericStrings(packetsToServer, packetsToClient)));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "byteCount", FirstNonEmpty(FirstValue(fields, "byteCount", "bytes", "byte_count", "network.bytes"), SumNumericStrings(bytesToServer, bytesToClient)));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "packetsToServer", packetsToServer);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "packetsToClient", packetsToClient);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "bytesToServer", bytesToServer);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "bytesToClient", bytesToClient);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "uid", FirstValue(fields, "uid", "flow_id", "flowId", "conn.uid", "community_id", "network.community_id"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "externalFlowKey", FirstValue(fields, "flowKey", "flow.key", "connectionId", "connection.id", "network.community_id", "community_id"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "applicationProtocol", FirstValue(fields, "applicationProtocol", "appProtocol", "service", "network.application", "network.protocol"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "flowReason", FirstValue(fields, "flowReason", "reason", "history", "conn.history"));
    }

    private static void AddCommonSidecarFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "observerName", FirstValue(fields, "observerName", "observer.name", "agent.name", "sensor", "sensorName"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "sidecarTool", FirstValue(fields, "sidecarTool", "tool", "parser.name", "observer.vendor", "event.module"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "ruleName", FirstValue(fields, "ruleName", "rule.name", "signature", "alert.signature"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "classification", FirstValue(fields, "classification", "event.classification", "alert.category", "threat.indicator.type"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "confidence", FirstValue(fields, "confidence", "event.confidence", "alert.severity"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "flowId", FirstValue(fields, "flowId", "flow_id", "uid", "conn.uid", "network.community_id", "community_id"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "communityId", FirstValue(fields, "communityId", "community_id", "network.community_id"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "vlanId", FirstValue(fields, "vlanId", "vlan.id", "vlan"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "interfaceName", FirstValue(fields, "interfaceName", "interface", "observer.ingress.interface.name", "observer.egress.interface.name"));
    }

    private static void AddSidecarProcessFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        var processId = FirstValue(fields, "processId", "pid", "proc.pid", "process.pid", "process_id", "process.entity_id");
        var parentProcessId = FirstValue(fields, "parentProcessId", "ppid", "process.parent.pid", "parent_pid");
        var rootProcessId = FirstValue(fields, "rootProcessId", "rootPid", "root.pid", "process.root.pid", "process.rootProcessId", "processRootId", "process.entry_leader.pid");
        var lineage = FirstValue(fields, "treeLineage", "lineage", "process.lineage", "process.treeLineage", "processTreeLineage", "process.parent.entity_id", "process.Ext.ancestry");
        var processName = FirstValue(fields, "processName", "imageName", "process.name", "process.executable", "proc.name", "application", "app", "image", "exe");
        var imageName = FirstValue(fields, "imageName", "processName", "process.name", "process.executable", "process.path", "proc.name", "image", "exe");
        var commandLine = FirstValue(fields, "commandLine", "cmdline", "process.command_line", "process.commandLine", "process.cmdline", "process.args");
        AddAliases(extra, processId, "processId", "pid");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "parentProcessId", parentProcessId);
        AddAliases(extra, rootProcessId, "rootProcessId", "rootPid", "processRootId");
        AddAliases(extra, lineage, "treeLineage", "processTreeLineage");
        AddAliases(extra, processName, "processName", "process.name");
        AddAliases(extra, imageName, "imageName", "processImage", "processPath");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "commandLine", commandLine);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "processRole", FirstValue(fields, "processRole", "process.role", "process.entry_leader.same_as_process"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "rootProcessName", FirstValue(fields, "rootProcessName", "rootProcessImage", "process.root.name", "process.entry_leader.name"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "rootCommandLine", FirstValue(fields, "rootCommandLine", "process.root.command_line", "process.entry_leader.command_line"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "collectorProcessName", FirstValue(fields, "collectorProcessName", "collector.processName", "collector.process.name"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "sourceComponent", FirstValue(fields, "sourceComponent", "source.component", "telemetrySource", "telemetry.source"));
    }

    private static SandboxEvent ApplySidecarProcessContext(SandboxEvent evt, IReadOnlyDictionary<string, string> fields)
    {
        var processName = FirstValue(fields, "processName", "imageName", "process.name", "process.executable", "proc.name", "application", "app", "image", "exe");
        var commandLine = FirstValue(fields, "commandLine", "cmdline", "process.command_line", "process.commandLine", "process.cmdline", "process.args");
        var processId = ParseNullableInt(FirstValue(fields, "processId", "pid", "proc.pid", "process.pid", "process_id"));
        var parentProcessId = ParseNullableInt(FirstValue(fields, "parentProcessId", "ppid", "process.parent.pid", "parent_pid"));
        return evt with
        {
            ProcessName = string.IsNullOrWhiteSpace(processName) ? evt.ProcessName : processName,
            ProcessId = processId ?? evt.ProcessId,
            ParentProcessId = parentProcessId ?? evt.ParentProcessId,
            CommandLine = string.IsNullOrWhiteSpace(commandLine) ? evt.CommandLine : commandLine
        };
    }

    private static int? ParseNullableInt(string? value)
    {
        return int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private static void AddAliases(Dictionary<string, string> data, string? value, params string[] keys)
    {
        foreach (var key in keys)
        {
            NetworkTelemetrySchema.AddIfNotEmpty(data, key, value);
        }
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static string NormalizeDnsRCode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(trimmed[2..], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var hexCode))
        {
            return DnsRCodeName(hexCode);
        }

        return int.TryParse(trimmed, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var code)
            ? DnsRCodeName(code)
            : trimmed.ToUpperInvariant();
    }

    private static string DnsRCodeName(int code)
    {
        return code switch
        {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            9 => "NOTAUTH",
            10 => "NOTZONE",
            _ => code.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
    }

    private static string NormalizeBoolean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim();
        if (string.Equals(trimmed, "1", StringComparison.Ordinal) ||
            string.Equals(trimmed, "yes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(trimmed, "y", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(trimmed, "true", StringComparison.OrdinalIgnoreCase))
        {
            return "true";
        }

        if (string.Equals(trimmed, "0", StringComparison.Ordinal) ||
            string.Equals(trimmed, "no", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(trimmed, "n", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(trimmed, "false", StringComparison.OrdinalIgnoreCase))
        {
            return "false";
        }

        return trimmed;
    }

    private static string? CountDelimitedValues(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var count = value.Split(new[] { ',', ';', '|', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length;
        return count > 0 ? count.ToString(System.Globalization.CultureInfo.InvariantCulture) : null;
    }

    private static string InferHttpScheme(string? scheme, IReadOnlyDictionary<string, string> fields)
    {
        if (!string.IsNullOrWhiteSpace(scheme))
        {
            return scheme.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
                scheme.Contains("ssl", StringComparison.OrdinalIgnoreCase)
                    ? "https"
                    : scheme.Trim().ToLowerInvariant();
        }

        var port = NetworkTelemetrySchema.ParsePort(FirstValue(fields, "destinationPort", "destPort", "dstPort", "dest_port", "dst_port", "dport", "resp_p", "id.resp_p", "server.port", "destination.port", "remotePort", "remote.port"));
        return port == 443 || port == 8443 ? "https" : "http";
    }

    private static string StatusFamily(string? statusCode)
    {
        if (int.TryParse(statusCode, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var status) &&
            status is >= 100 and <= 599)
        {
            return $"{status / 100}xx";
        }

        return string.Empty;
    }

    private static bool IsUploadCandidate(string? method, string? byteCount)
    {
        if (method is not null &&
            (string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(method, "PUT", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(method, "PATCH", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return TryPositiveLong(byteCount);
    }

    private static bool TryPositiveLong(string? value)
    {
        return long.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed) &&
            parsed > 0;
    }

    private static string? SumNumericStrings(params string?[] values)
    {
        long sum = 0;
        var any = false;
        foreach (var value in values)
        {
            if (long.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed))
            {
                sum += parsed;
                any = true;
            }
        }

        return any ? sum.ToString(System.Globalization.CultureInfo.InvariantCulture) : null;
    }

    private static string InferProtocol(string? value, int? sourcePort, int? destinationPort)
    {
        var protocolText = value ?? string.Empty;
        if (protocolText.Contains("tcp", StringComparison.OrdinalIgnoreCase))
        {
            return "tcp";
        }

        if (protocolText.Contains("udp", StringComparison.OrdinalIgnoreCase))
        {
            return "udp";
        }

        if (sourcePort == 53 || destinationPort == 53)
        {
            return "udp";
        }

        if (sourcePort.HasValue || destinationPort.HasValue)
        {
            return "tcp";
        }

        return NetworkTelemetrySchema.NormalizeProtocol(value);
    }

    private static void FlattenJson(JsonElement element, Dictionary<string, string> fields, string prefix)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    var key = string.IsNullOrWhiteSpace(prefix) ? property.Name : $"{prefix}.{property.Name}";
                    FlattenJson(property.Value, fields, key);
                    if (string.Equals(property.Name, "data", StringComparison.OrdinalIgnoreCase) &&
                        property.Value.ValueKind == JsonValueKind.Object)
                    {
                        FlattenJson(property.Value, fields, string.Empty);
                    }
                }

                break;
            case JsonValueKind.Array:
                var values = element.EnumerateArray()
                    .Select(ValueAsString)
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Take(16)
                    .ToArray();
                if (values.Length > 0)
                {
                    fields[prefix] = string.Join(",", values);
                }

                break;
            case JsonValueKind.String:
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                fields[prefix] = ValueAsString(element);
                break;
        }
    }

    private static string ValueAsString(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? string.Empty,
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => element.GetRawText()
        };
    }

    private static Dictionary<string, string> ParseKeyValueLine(string line)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in KeyValueTokenRegex.Matches(line))
        {
            var key = match.Groups["key"].Value;
            var value = match.Groups["quoted"].Success
                ? match.Groups["quoted"].Value
                : match.Groups["single"].Success
                    ? match.Groups["single"].Value
                    : match.Groups["value"].Value;
            if (!string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(value))
            {
                fields[key] = value.Trim('"', '\'');
            }
        }

        return fields;
    }

    private static void AddLooseLogHints(string line, Dictionary<string, string> fields)
    {
        if (!fields.ContainsKey("timestamp"))
        {
            var firstToken = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
            if (DateTimeOffset.TryParse(firstToken, out _) || double.TryParse(firstToken, out _))
            {
                fields["timestamp"] = firstToken;
            }
        }

        AddIfMissing(fields, "eventType", InferLooseEventType(line));
        if (line.Contains(" tcp ", StringComparison.OrdinalIgnoreCase) ||
            line.Contains(" proto=tcp", StringComparison.OrdinalIgnoreCase))
        {
            AddIfMissing(fields, "protocol", "tcp");
        }

        if (line.Contains(" udp ", StringComparison.OrdinalIgnoreCase) ||
            line.Contains(" proto=udp", StringComparison.OrdinalIgnoreCase))
        {
            AddIfMissing(fields, "protocol", "udp");
        }

        var endpointMatch = EndpointFlowRegex.Match(line);
        if (endpointMatch.Success)
        {
            AddIfMissing(
                fields,
                "src",
                NetworkTelemetrySchema.Endpoint(
                    TrimBrackets(endpointMatch.Groups["src"].Value),
                    NetworkTelemetrySchema.ParsePort(endpointMatch.Groups["srcPort"].Value)));
            AddIfMissing(
                fields,
                "dst",
                NetworkTelemetrySchema.Endpoint(
                    TrimBrackets(endpointMatch.Groups["dst"].Value),
                    NetworkTelemetrySchema.ParsePort(endpointMatch.Groups["dstPort"].Value)));
        }

        var httpMatch = HttpRequestLineRegex.Match(line);
        if (httpMatch.Success)
        {
            AddIfMissing(fields, "eventType", "http.request");
            AddIfMissing(fields, "method", httpMatch.Groups["method"].Value.ToUpperInvariant());
            AddIfMissing(fields, "uri", httpMatch.Groups["uri"].Value);
        }

        if (!fields.ContainsKey("queryName"))
        {
            AddIfMissing(fields, "queryName", FirstLooseTokenValue(line, "query", "qname", "domain", "rrname"));
        }

        if (!fields.ContainsKey("sni"))
        {
            AddIfMissing(fields, "sni", FirstLooseTokenValue(line, "sni", "server_name", "servername"));
        }
    }

    private static string? InferLooseEventType(string line)
    {
        if (line.Contains("dns", StringComparison.OrdinalIgnoreCase) ||
            line.Contains(" qname", StringComparison.OrdinalIgnoreCase) ||
            line.Contains(" query=", StringComparison.OrdinalIgnoreCase))
        {
            return "dns.query";
        }

        if (line.Contains("http", StringComparison.OrdinalIgnoreCase) ||
            HttpRequestLineRegex.IsMatch(line))
        {
            return "http.request";
        }

        if (line.Contains("tls", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("ssl", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("sni=", StringComparison.OrdinalIgnoreCase))
        {
            return "tls.connection";
        }

        if (line.Contains("->", StringComparison.OrdinalIgnoreCase) ||
            line.Contains(" conn", StringComparison.OrdinalIgnoreCase) ||
            line.Contains(" flow", StringComparison.OrdinalIgnoreCase))
        {
            return "network.flow";
        }

        return null;
    }

    private static string? FirstLooseTokenValue(string line, params string[] keys)
    {
        foreach (var key in keys)
        {
            var match = Regex.Match(
                line,
                $@"(?:^|\s){Regex.Escape(key)}\s*(?:=|:)\s*(?:""(?<value>[^""]*)""|'(?<value>[^']*)'|(?<value>\S+))",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (match.Success && !string.IsNullOrWhiteSpace(match.Groups["value"].Value))
            {
                return match.Groups["value"].Value.Trim('"', '\'');
            }
        }

        return null;
    }

    private static (string? Address, int? Port) SplitEndpoint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return (null, null);
        }

        var trimmed = value.Trim().Trim('"', '\'');
        if (trimmed.StartsWith("[", StringComparison.Ordinal))
        {
            var closing = trimmed.IndexOf(']');
            if (closing > 1)
            {
                var address = trimmed[1..closing];
                var port = closing + 2 <= trimmed.Length && trimmed[closing + 1] == ':'
                    ? NetworkTelemetrySchema.ParsePort(trimmed[(closing + 2)..])
                    : null;
                return (address, port);
            }
        }

        if (IPAddress.TryParse(trimmed, out _))
        {
            return (trimmed, null);
        }

        var lastColon = trimmed.LastIndexOf(':');
        if (lastColon > 0 &&
            trimmed.IndexOf(':') == lastColon &&
            NetworkTelemetrySchema.ParsePort(trimmed[(lastColon + 1)..]) is { } parsedPort)
        {
            return (trimmed[..lastColon], parsedPort);
        }

        if (lastColon > 0 &&
            trimmed.IndexOf(':') != lastColon &&
            NetworkTelemetrySchema.ParsePort(trimmed[(lastColon + 1)..]) is { } ipv6Port &&
            IPAddress.TryParse(trimmed[..lastColon], out var parsedAddress) &&
            parsedAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return (trimmed[..lastColon], ipv6Port);
        }

        return (trimmed, null);
    }

    private static void AddIfMissing(Dictionary<string, string> fields, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value) && !fields.ContainsKey(key))
        {
            fields[key] = value;
        }
    }

    private static string TrimBrackets(string value)
    {
        return value.Trim().TrimStart('[').TrimEnd(']');
    }

    private static SandboxEvent CreateParseError(
        string path,
        int lineNumber,
        string message,
        NetworkArtifactSource source,
        string sidecarFormat,
        string diagnosticCode,
        string parserBoundary,
        string? linePreview = null)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["schema"] = NetworkTelemetrySchema.SchemaVersion,
            ["eventFamily"] = "network",
            ["eventKind"] = "parse_error",
            ["lineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sidecarLineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sidecarFormat"] = sidecarFormat,
            ["message"] = message,
            ["diagnosticMessage"] = message,
            ["parseErrorMessage"] = message,
            ["parser"] = "sidecar-jsonl",
            ["diagnosticCode"] = diagnosticCode,
            ["parserBoundary"] = parserBoundary,
            ["parseFailureStage"] = sidecarFormat == "jsonl" ? "json-line" : "sidecar-stream",
            ["diagnosticStage"] = sidecarFormat == "jsonl" ? "json-line" : "sidecar-stream",
            ["zhHint"] = lineNumber > 0
                ? $"Sidecar 第 {lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture)} 行解析失败；请检查 JSON 引号、换行截断或 exporter 字段格式。"
                : "Sidecar 文件读取或解析失败；请检查文件是否仍在写入、被截断或编码异常。"
        };
        NetworkTelemetrySchema.AddIfNotEmpty(data, "linePreview", Truncate(linePreview, 160));
        NetworkTelemetrySchema.AddArtifactData(data, source);
        NetworkTelemetrySchema.ApplyHealthAndLocalization(data);
        return new SandboxEvent
        {
            EventType = "network.sidecar.parse_error",
            Source = "host",
            Path = path,
            Data = data
        };
    }

    private static bool HasAny(IReadOnlyDictionary<string, string> fields, params string[] keys)
    {
        return keys.Any(key => !string.IsNullOrWhiteSpace(FirstValue(fields, key)));
    }

    private static string? Truncate(string? value, int maxLength)
    {
        return string.IsNullOrWhiteSpace(value) || value.Length <= maxLength
            ? value
            : value[..maxLength];
    }

    private static bool Contains(string? value, string needle)
    {
        return value?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;
    }

    private static string? FirstValue(IReadOnlyDictionary<string, string> fields, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (fields.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }

            var suffixMatch = fields.FirstOrDefault(pair =>
                pair.Key.EndsWith($".{key}", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(pair.Value));
            if (!string.IsNullOrWhiteSpace(suffixMatch.Value))
            {
                return suffixMatch.Value;
            }
        }

        return null;
    }
}
