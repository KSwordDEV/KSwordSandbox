using System.Globalization;
using System.Security.Cryptography;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Network;

/// <summary>
/// Shared field schema for network events imported from PCAP, packet-capture
/// sidecars, and JSONL telemetry. Inputs are decoded endpoint/protocol values;
/// processing adds stable aliases used by reports/rules; methods return
/// string-valued SandboxEvent data dictionaries.
/// </summary>
public static class NetworkTelemetrySchema
{
    public const string SchemaVersion = "network.telemetry.v1";

    public const string ImportSummaryEventType = "network.import.summary";

    public static Dictionary<string, string> CreateEndpointData(
        string? protocol,
        string? sourceIp,
        int? sourcePort,
        string? destinationIp,
        int? destinationPort,
        string eventKind,
        string importSource,
        NetworkArtifactSource? source = null,
        IDictionary<string, string>? extra = null)
    {
        var normalizedProtocol = NormalizeProtocol(protocol);
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["schema"] = SchemaVersion,
            ["eventFamily"] = "network",
            ["eventKind"] = eventKind,
            ["importSource"] = importSource,
            ["protocol"] = normalizedProtocol,
            ["transportProtocol"] = normalizedProtocol,
            ["protocolName"] = normalizedProtocol
        };

        AddIfNotEmpty(data, "sourceIp", sourceIp);
        AddIfNotEmpty(data, "src", sourceIp);
        AddIfNotEmpty(data, "srcIp", sourceIp);
        AddIfNotEmpty(data, "localAddress", sourceIp);
        AddIfNotEmpty(data, "destinationIp", destinationIp);
        AddIfNotEmpty(data, "dst", destinationIp);
        AddIfNotEmpty(data, "dstIp", destinationIp);
        AddIfNotEmpty(data, "remoteAddress", destinationIp);
        AddPort(data, "sourcePort", sourcePort);
        AddPort(data, "srcPort", sourcePort);
        AddPort(data, "localPort", sourcePort);
        AddPort(data, "destinationPort", destinationPort);
        AddPort(data, "dstPort", destinationPort);
        AddPort(data, "remotePort", destinationPort);

        var sourceEndpoint = Endpoint(sourceIp, sourcePort);
        var destinationEndpoint = Endpoint(destinationIp, destinationPort);
        AddIfNotEmpty(data, "sourceEndpoint", sourceEndpoint);
        AddIfNotEmpty(data, "srcEndpoint", sourceEndpoint);
        AddIfNotEmpty(data, "localEndpoint", sourceEndpoint);
        AddIfNotEmpty(data, "destinationEndpoint", destinationEndpoint);
        AddIfNotEmpty(data, "dstEndpoint", destinationEndpoint);
        AddIfNotEmpty(data, "remoteEndpoint", destinationEndpoint);
        AddIfNotEmpty(data, "ports", Ports(sourcePort, destinationPort));
        if (!string.IsNullOrWhiteSpace(normalizedProtocol) &&
            !string.IsNullOrWhiteSpace(sourceEndpoint) &&
            !string.IsNullOrWhiteSpace(destinationEndpoint))
        {
            data["flowKey"] = $"{normalizedProtocol}|{sourceEndpoint}|{destinationEndpoint}";
        }

        AddIfNotEmpty(data, "direction", "outbound");
        AddIfNotEmpty(data, "serviceHint", ServiceHint(eventKind, normalizedProtocol, sourcePort, destinationPort));
        AddArtifactData(data, source);
        if (extra is not null)
        {
            foreach (var pair in extra)
            {
                AddIfNotEmpty(data, pair.Key, pair.Value);
            }
        }

        ApplyHealthAndLocalization(data);
        return data;
    }

    public static SandboxEvent CreateNetworkEvent(
        string eventType,
        DateTimeOffset timestamp,
        string? path,
        string eventKind,
        string importSource,
        string? protocol,
        string? sourceIp,
        int? sourcePort,
        string? destinationIp,
        int? destinationPort,
        NetworkArtifactSource? source = null,
        IDictionary<string, string>? extra = null)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Timestamp = timestamp == default ? DateTimeOffset.UtcNow : timestamp,
            Source = "host",
            Path = string.IsNullOrWhiteSpace(path)
                ? BuildPath(eventKind, protocol, destinationIp, destinationPort, extra)
                : path,
            Data = CreateEndpointData(
                protocol,
                sourceIp,
                sourcePort,
                destinationIp,
                destinationPort,
                eventKind,
                importSource,
                source,
                extra)
        };
    }

    public static SandboxEvent CreateImportSummary(
        string path,
        NetworkArtifactSource? source,
        IEnumerable<SandboxEvent> importedEvents,
        IDictionary<string, string>? extra = null)
    {
        var materialized = importedEvents.ToList();
        var protocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var evt in materialized)
        {
            AddProtocolFromEvent(protocols, evt);
        }

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["schema"] = SchemaVersion,
            ["eventFamily"] = "network",
            ["eventKind"] = "summary",
            ["status"] = materialized.Count == 0 ? "empty" : "imported",
            ["eventCount"] = materialized.Count.ToString(CultureInfo.InvariantCulture),
            ["connectionEventCount"] = CountEvents(materialized, "connection").ToString(CultureInfo.InvariantCulture),
            ["dnsEventCount"] = CountEvents(materialized, "dns").ToString(CultureInfo.InvariantCulture),
            ["httpEventCount"] = CountEvents(materialized, "http").ToString(CultureInfo.InvariantCulture),
            ["tlsEventCount"] = CountEvents(materialized, "tls").ToString(CultureInfo.InvariantCulture),
            ["flowEventCount"] = materialized.Count(evt => IsEventType(evt, "network.flow") || IsEventType(evt, "pcap.flow")).ToString(CultureInfo.InvariantCulture),
            ["parseErrorCount"] = CountEvents(materialized, "parse_error").ToString(CultureInfo.InvariantCulture),
            ["protocols"] = string.Join(",", protocols.OrderBy(value => value, StringComparer.OrdinalIgnoreCase)),
            ["protocol"] = string.Join(",", protocols.OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        };

        AddArtifactData(data, source);
        if (extra is not null)
        {
            foreach (var pair in extra)
            {
                AddIfNotEmpty(data, pair.Key, pair.Value);
            }
        }

        ApplyHealthAndLocalization(data);
        return new SandboxEvent
        {
            EventType = ImportSummaryEventType,
            Timestamp = DateTimeOffset.UtcNow,
            Source = "host",
            Path = path,
            Data = data
        };
    }

    public static void AddArtifactData(Dictionary<string, string> data, NetworkArtifactSource? source)
    {
        if (source is null)
        {
            return;
        }

        AddIfNotEmpty(data, "sourceArtifactPath", source.FullPath);
        AddIfNotEmpty(data, "sourceArtifactName", source.Name);
        AddIfNotEmpty(data, "sourceArtifactRelativePath", source.RelativePath);
        AddIfNotEmpty(data, "artifactRelativePath", source.RelativePath);
        AddIfNotEmpty(data, "downloadSelector", source.RelativePath);
        AddIfNotEmpty(data, "sourceImportRoot", source.ImportRoot);
        AddIfNotEmpty(data, "sourceArtifactKind", source.ArtifactKind);
        AddIfNotEmpty(data, "collectionName", source.CollectionName);
        AddIfNotEmpty(data, "evidenceRole", source.EvidenceRole);
        AddIfNotEmpty(data, "importMode", source.ImportMode);
        foreach (var pair in source.Metadata ?? EmptyMetadata)
        {
            if (pair.Key.StartsWith("network.", StringComparison.OrdinalIgnoreCase) ||
                pair.Key.StartsWith("pcap", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "captureState", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "capturePhase", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "sha256", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "sourceArtifactSha256", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "hash.sha256", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "sizeBytes", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "sourceArtifactSizeBytes", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "artifactRelativePath", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "sourceArtifactRelativePath", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "rootProcessId", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "treeLineage", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "processId", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "parentProcessId", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "processName", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "commandLine", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "duplicateGroupKey", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "duplicateGroupCount", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "duplicateOrdinal", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "isDuplicate", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pair.Key, "duplicateOfArtifactRelativePath", StringComparison.OrdinalIgnoreCase))
            {
                AddIfNotEmpty(data, pair.Key, pair.Value);
            }
        }

        try
        {
            var info = new FileInfo(source.FullPath);
            if (info.Exists)
            {
                var sizeText = info.Length.ToString(CultureInfo.InvariantCulture);
                var sha256 = ComputeSha256(info.FullName);
                data["sourceArtifactSizeBytes"] = sizeText;
                data["sizeBytes"] = sizeText;
                data["sourceArtifactSha256"] = sha256;
                data["sha256"] = sha256;
                data["hash.sha256"] = sha256;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            data["sourceArtifactHashSkipped"] = ex.GetType().Name;
        }
    }

    public static void ApplyHealthAndLocalization(Dictionary<string, string> data)
    {
        if (!data.ContainsKey("collectionHealth"))
        {
            data["collectionHealth"] = InferCollectionHealth(data);
        }

        if (!data.ContainsKey("zhMessage"))
        {
            AddIfNotEmpty(data, "zhMessage", BuildZhMessage(data));
        }

        if (!data.ContainsKey("zhHint"))
        {
            AddIfNotEmpty(data, "zhHint", BuildZhHint(data));
        }
    }

    public static string NormalizeProtocol(string? protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol))
        {
            return string.Empty;
        }

        var value = protocol.Trim().ToLowerInvariant();
        return value switch
        {
            "6" => "tcp",
            "17" => "udp",
            "tcp6" => "tcp",
            "udp6" => "udp",
            _ => value
        };
    }

    public static string ServiceHint(string eventKind, string protocol, int? sourcePort, int? destinationPort)
    {
        if (string.Equals(eventKind, "dns", StringComparison.OrdinalIgnoreCase) ||
            sourcePort == 53 ||
            destinationPort == 53)
        {
            return "dns";
        }

        if (string.Equals(eventKind, "http", StringComparison.OrdinalIgnoreCase) ||
            sourcePort == 80 ||
            destinationPort == 80 ||
            sourcePort == 8080 ||
            destinationPort == 8080)
        {
            return "http";
        }

        if (string.Equals(eventKind, "tls", StringComparison.OrdinalIgnoreCase) ||
            sourcePort == 443 ||
            destinationPort == 443 ||
            sourcePort == 8443 ||
            destinationPort == 8443)
        {
            return "tls";
        }

        return string.IsNullOrWhiteSpace(protocol) ? "unknown" : protocol;
    }

    public static string Endpoint(string? address, int? port)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return string.Empty;
        }

        if (!port.HasValue)
        {
            return address;
        }

        var normalizedAddress = address.Contains(':', StringComparison.Ordinal) &&
            !address.StartsWith("[", StringComparison.Ordinal) &&
            !address.EndsWith("]", StringComparison.Ordinal)
                ? $"[{address}]"
                : address;
        return $"{normalizedAddress}:{port.Value.ToString(CultureInfo.InvariantCulture)}";
    }

    public static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    public static int? ParsePort(string? value)
    {
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) &&
            port is >= 0 and <= 65535
            ? port
            : null;
    }

    public static DateTimeOffset ParseTimestampOrDefault(string? value, DateTimeOffset defaultValue)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
        {
            return parsed.ToUniversalTime();
        }

        if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var epochSeconds))
        {
            try
            {
                var seconds = Math.Truncate(epochSeconds);
                var fraction = epochSeconds - seconds;
                return DateTimeOffset.UnixEpoch
                    .AddSeconds(seconds)
                    .AddTicks((long)(fraction * TimeSpan.TicksPerSecond));
            }
            catch (ArgumentOutOfRangeException)
            {
                return defaultValue;
            }
        }

        return defaultValue;
    }

    private static void AddPort(Dictionary<string, string> data, string key, int? port)
    {
        if (port.HasValue)
        {
            data[key] = port.Value.ToString(CultureInfo.InvariantCulture);
        }
    }

    private static string Ports(int? sourcePort, int? destinationPort)
    {
        if (sourcePort.HasValue && destinationPort.HasValue)
        {
            return $"{sourcePort.Value.ToString(CultureInfo.InvariantCulture)}->{destinationPort.Value.ToString(CultureInfo.InvariantCulture)}";
        }

        if (sourcePort.HasValue)
        {
            return sourcePort.Value.ToString(CultureInfo.InvariantCulture);
        }

        return destinationPort.HasValue
            ? destinationPort.Value.ToString(CultureInfo.InvariantCulture)
            : string.Empty;
    }

    private static string BuildPath(
        string eventKind,
        string? protocol,
        string? destinationIp,
        int? destinationPort,
        IDictionary<string, string>? extra)
    {
        if (extra is not null)
        {
            if (string.Equals(eventKind, "dns", StringComparison.OrdinalIgnoreCase) &&
                extra.TryGetValue("queryName", out var queryName) &&
                !string.IsNullOrWhiteSpace(queryName))
            {
                return queryName;
            }

            if (string.Equals(eventKind, "http", StringComparison.OrdinalIgnoreCase))
            {
                var host = ValueOrEmpty(extra, "host");
                var uri = ValueOrEmpty(extra, "uri");
                if (string.IsNullOrWhiteSpace(uri))
                {
                    uri = ValueOrEmpty(extra, "requestUri");
                }
                if (!string.IsNullOrWhiteSpace(host))
                {
                    return $"http://{host}{(string.IsNullOrWhiteSpace(uri) ? "/" : uri)}";
                }
            }

            if (string.Equals(eventKind, "tls", StringComparison.OrdinalIgnoreCase))
            {
                var sni = ValueOrEmpty(extra, "sni");
                if (string.IsNullOrWhiteSpace(sni))
                {
                    sni = ValueOrEmpty(extra, "serverName");
                }
                if (!string.IsNullOrWhiteSpace(sni))
                {
                    return $"tls://{sni}";
                }
            }
        }

        var normalizedProtocol = NormalizeProtocol(protocol);
        var endpoint = Endpoint(destinationIp, destinationPort);
        return !string.IsNullOrWhiteSpace(endpoint) && !string.IsNullOrWhiteSpace(normalizedProtocol)
            ? $"{normalizedProtocol}://{endpoint}"
            : endpoint;
    }

    private static void AddProtocolFromEvent(HashSet<string> protocols, SandboxEvent evt)
    {
        if (evt.Data.TryGetValue("protocol", out var protocol))
        {
            AddProtocol(protocols, protocol);
        }

        if (evt.Data.TryGetValue("transportProtocol", out var transportProtocol))
        {
            AddProtocol(protocols, transportProtocol);
        }

        if (evt.EventType.Contains("dns", StringComparison.OrdinalIgnoreCase))
        {
            protocols.Add("dns");
        }

        if (evt.EventType.Contains("http", StringComparison.OrdinalIgnoreCase))
        {
            protocols.Add("http");
        }

        if (evt.EventType.Contains("tls", StringComparison.OrdinalIgnoreCase))
        {
            protocols.Add("tls");
        }
    }

    private static string ValueOrEmpty(IEnumerable<KeyValuePair<string, string>> data, string key)
    {
        foreach (var pair in data)
        {
            if (string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }

        return string.Empty;
    }

    private static void AddProtocol(HashSet<string> protocols, string value)
    {
        foreach (var protocol in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var normalized = NormalizeProtocol(protocol);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                protocols.Add(normalized);
            }
        }
    }

    private static int CountEvents(IReadOnlyCollection<SandboxEvent> events, string eventKind)
    {
        return events.Count(evt =>
            (evt.Data.TryGetValue("eventKind", out var kind) &&
                string.Equals(kind, eventKind, StringComparison.OrdinalIgnoreCase)) ||
            evt.EventType.Contains(eventKind, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsEventType(SandboxEvent evt, string eventType)
    {
        return string.Equals(evt.EventType, eventType, StringComparison.OrdinalIgnoreCase);
    }

    private static string InferCollectionHealth(IReadOnlyDictionary<string, string> data)
    {
        var eventKind = ValueOrEmpty(data, "eventKind");
        var status = ValueOrEmpty(data, "status");
        if (string.Equals(eventKind, "parse_error", StringComparison.OrdinalIgnoreCase) ||
            status.Contains("error", StringComparison.OrdinalIgnoreCase) ||
            HasPositiveCount(data, "parseErrorCount"))
        {
            return "degraded";
        }

        if (string.Equals(status, "empty", StringComparison.OrdinalIgnoreCase) ||
            (string.Equals(eventKind, "summary", StringComparison.OrdinalIgnoreCase) &&
                data.TryGetValue("eventCount", out var eventCount) &&
                string.Equals(eventCount, "0", StringComparison.Ordinal)))
        {
            return "empty";
        }

        if (!string.Equals(eventKind, "summary", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(eventKind, "parse_error", StringComparison.OrdinalIgnoreCase) &&
            (string.IsNullOrWhiteSpace(ValueOrEmpty(data, "sourceIp")) ||
                string.IsNullOrWhiteSpace(ValueOrEmpty(data, "destinationIp"))))
        {
            return "partial";
        }

        return "ok";
    }

    private static string BuildZhMessage(IReadOnlyDictionary<string, string> data)
    {
        var eventKind = ValueOrEmpty(data, "eventKind");
        if (string.Equals(eventKind, "summary", StringComparison.OrdinalIgnoreCase))
        {
            var health = ValueOrEmpty(data, "collectionHealth");
            var count = FirstDataValue(data, "eventCount", "packetCount", "parsedPacketCount");
            var protocols = ValueOrEmpty(data, "protocols");
            if (string.Equals(health, "empty", StringComparison.OrdinalIgnoreCase))
            {
                return "未发现可导入的网络证据。";
            }

            if (string.Equals(health, "degraded", StringComparison.OrdinalIgnoreCase))
            {
                return $"网络证据导入完成但存在解析异常：{DisplayCount(count)} 条事件。";
            }

            return $"网络证据导入完成：{DisplayCount(count)} 条事件，协议 {DisplayValue(protocols, "未知")}。";
        }

        if (string.Equals(eventKind, "parse_error", StringComparison.OrdinalIgnoreCase))
        {
            return $"网络证据解析失败：{DisplayValue(ValueOrEmpty(data, "message"), "原因未知")}。";
        }

        if (string.Equals(eventKind, "dns", StringComparison.OrdinalIgnoreCase))
        {
            return $"观察到 DNS 查询：{DisplayValue(FirstDataValue(data, "queryName", "qname", "domain"), "未知域名")}。";
        }

        if (string.Equals(eventKind, "http", StringComparison.OrdinalIgnoreCase))
        {
            var method = DisplayValue(ValueOrEmpty(data, "method"), "HTTP");
            var target = FirstDataValue(data, "url", "host", "uri", "requestUri");
            return $"观察到 HTTP 请求：{method} {DisplayValue(target, "未知目标")}。";
        }

        if (string.Equals(eventKind, "tls", StringComparison.OrdinalIgnoreCase))
        {
            return $"观察到 TLS 连接：{DisplayValue(FirstDataValue(data, "sni", "serverName", "destinationEndpoint"), "未知服务端")}。";
        }

        if (string.Equals(eventKind, "connection", StringComparison.OrdinalIgnoreCase))
        {
            return $"观察到网络连接：{DisplayValue(ValueOrEmpty(data, "sourceEndpoint"), "未知源")} -> {DisplayValue(ValueOrEmpty(data, "destinationEndpoint"), "未知目的")}。";
        }

        return "观察到网络证据。";
    }

    private static string BuildZhHint(IReadOnlyDictionary<string, string> data)
    {
        var eventKind = ValueOrEmpty(data, "eventKind");
        var health = ValueOrEmpty(data, "collectionHealth");
        if (string.Equals(health, "degraded", StringComparison.OrdinalIgnoreCase))
        {
            return "部分网络证据解析失败；请保留源 PCAP/sidecar 文件并查看 parse_error 事件。";
        }

        if (string.Equals(health, "empty", StringComparison.OrdinalIgnoreCase))
        {
            return "请检查 packet-captures 目录、sidecar JSONL/log 文件和采集权限。";
        }

        if (string.Equals(health, "partial", StringComparison.OrdinalIgnoreCase))
        {
            return "该行缺少完整端点信息；可结合 sourceArtifactPath 和原始 sidecar 行复核。";
        }

        if (string.Equals(eventKind, "summary", StringComparison.OrdinalIgnoreCase))
        {
            return "可筛选 dns.query、http.request、tls.connection、network.flow 查看标准化网络证据。";
        }

        if (string.Equals(eventKind, "dns", StringComparison.OrdinalIgnoreCase))
        {
            return "关注异常域名、NXDOMAIN、动态域名或与后续 HTTP/TLS 连接的关联。";
        }

        if (string.Equals(eventKind, "http", StringComparison.OrdinalIgnoreCase))
        {
            return "关注下载路径、Host、User-Agent、Content-Type 和 payloadMagic。";
        }

        if (string.Equals(eventKind, "tls", StringComparison.OrdinalIgnoreCase))
        {
            return "关注 SNI、TLS 版本、JA3/JA3S 和目标端口。";
        }

        if (string.Equals(eventKind, "connection", StringComparison.OrdinalIgnoreCase))
        {
            return "关注外连目的地址、端口、连接状态、流量字节数和持续时间。";
        }

        return "结合进程、文件、注册表和时间线证据进行关联分析。";
    }

    private static bool HasPositiveCount(IReadOnlyDictionary<string, string> data, string key)
    {
        return data.TryGetValue(key, out var value) &&
            int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count) &&
            count > 0;
    }

    private static string FirstDataValue(IReadOnlyDictionary<string, string> data, params string[] keys)
    {
        foreach (var key in keys)
        {
            var value = ValueOrEmpty(data, key);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string DisplayCount(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "0" : value;
    }

    private static string DisplayValue(string value, string fallback)
    {
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    private static string ComputeSha256(string fullPath)
    {
        using var stream = File.OpenRead(fullPath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static readonly IReadOnlyDictionary<string, string> EmptyMetadata =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
