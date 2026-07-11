using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
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
        "(?<src>(?:\\d{1,3}\\.){3}\\d{1,3}|\\[[0-9a-fA-F:.]+\\]):(?<srcPort>\\d{1,5})\\s*(?:->|=>|to)\\s*(?<dst>(?:\\d{1,3}\\.){3}\\d{1,3}|\\[[0-9a-fA-F:.]+\\]):(?<dstPort>\\d{1,5})",
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
            events.Add(CreateParseError(path, 0, ex.Message, source));
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
            events.Add(CreateParseError(path, lineNumber, ex.Message, source));
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
        var originalEventType = FirstValue(fields, "eventType", "event_type", "event.type", "event.kind", "event.category", "type", "_source.layers.frame.frame.protocols");
        var timestamp = NetworkTelemetrySchema.ParseTimestampOrDefault(
            FirstValue(fields, "timestamp", "@timestamp", "time", "ts", "frame.time_epoch", "_source.layers.frame.frame.time_epoch"),
            DateTimeOffset.UtcNow);
        var sourceEndpoint = SplitEndpoint(FirstValue(fields, "sourceEndpoint", "srcEndpoint", "src", "source", "localEndpoint", "local.endpoint"));
        var destinationEndpoint = SplitEndpoint(FirstValue(fields, "destinationEndpoint", "dstEndpoint", "destEndpoint", "dst", "dest", "destination", "remoteEndpoint", "remote.endpoint"));
        var sourceIp = FirstValue(fields, "sourceIp", "srcIp", "src_ip", "src_addr", "orig_h", "id.orig_h", "source.ip", "source.address", "source.addr", "localAddress", "local.address", "ip.src", "ipv6.src", "_source.layers.ip.ip.src") ?? sourceEndpoint.Address;
        var destinationIp = FirstValue(fields, "destinationIp", "destIp", "dstIp", "dest_ip", "dst_ip", "dst_addr", "resp_h", "id.resp_h", "destination.ip", "destination.address", "dest.ip", "dest.address", "remoteAddress", "remote.address", "ip.dst", "ipv6.dst", "_source.layers.ip.ip.dst") ?? destinationEndpoint.Address;
        var sourcePort = NetworkTelemetrySchema.ParsePort(FirstValue(fields, "sourcePort", "srcPort", "src_port", "orig_p", "id.orig_p", "source.port", "localPort", "local.port", "tcp.srcport", "udp.srcport", "_source.layers.tcp.tcp.srcport", "_source.layers.udp.udp.srcport")) ?? sourceEndpoint.Port;
        var destinationPort = NetworkTelemetrySchema.ParsePort(FirstValue(fields, "destinationPort", "destPort", "dstPort", "dest_port", "dst_port", "resp_p", "id.resp_p", "destination.port", "dest.port", "remotePort", "remote.port", "tcp.dstport", "udp.dstport", "_source.layers.tcp.tcp.dstport", "_source.layers.udp.udp.dstport")) ?? destinationEndpoint.Port;
        var protocol = FirstValue(fields, "protocol", "transportProtocol", "protocolName", "proto", "network.transport", "transport", "ip_proto", "ip.protocol", "_source.layers.frame.frame.protocols");
        protocol = InferProtocol(protocol, sourcePort, destinationPort);

        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sidecarLineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sidecarFormat"] = sidecarFormat,
            ["parser"] = "sidecar-jsonl"
        };
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "originalEventType", originalEventType);
        AddSidecarProcessFields(fields, extra);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "direction", FirstValue(fields, "direction", "flow.direction", "network.direction"));

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

    private static bool IsDns(IReadOnlyDictionary<string, string> fields, string? eventType)
    {
        return Contains(eventType, "dns") ||
            HasAny(fields, "queryName", "query", "qname", "domain", "rrname", "dns.qry.name", "_source.layers.dns.dns.qry.name");
    }

    private static bool IsHttp(IReadOnlyDictionary<string, string> fields, string? eventType)
    {
        return Contains(eventType, "http") ||
            HasAny(fields, "method", "httpMethod", "http.method", "http.request.method", "_source.layers.http.http.request.method") ||
            HasAny(fields, "host", "hostname", "httpHost", "http.host", "http.hostname", "_source.layers.http.http.host") ||
            HasAny(fields, "url", "http.url", "http.request.uri", "_source.layers.http.http.request.uri");
    }

    private static bool IsTls(IReadOnlyDictionary<string, string> fields, string? eventType)
    {
        return Contains(eventType, "tls") ||
            Contains(eventType, "ssl") ||
            HasAny(fields, "sni", "serverName", "tls.sni", "tls.server_name", "tls.handshake.extensions_server_name", "ssl.handshake.extensions_server_name", "_source.layers.tls.tls.handshake.extensions_server_name");
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
        var queryName = FirstValue(fields, "queryName", "query", "dnsQuery", "qname", "domain", "rrname", "dns.rrname", "dns.qry.name", "_source.layers.dns.dns.qry.name");
        var queryType = FirstValue(fields, "queryType", "recordType", "qtype", "typeName", "rrtype", "dns.rrtype", "dns.qry.type", "dns.qry.type_name", "_source.layers.dns.dns.qry.type");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "queryName", queryName);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "qname", queryName);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "domain", queryName);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "queryType", queryType);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "recordType", queryType);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "rcode", FirstValue(fields, "rcode", "dns.rcode", "dns.flags.rcode", "_source.layers.dns.dns.flags.rcode"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "isResponse", FirstValue(fields, "isResponse", "dns.flags.response", "_source.layers.dns.dns.flags.response"));
    }

    private static void AddHttpFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        var uri = FirstValue(fields, "uri", "requestUri", "path", "url.path", "http.url", "http.request.uri", "_source.layers.http.http.request.uri");
        var host = FirstValue(fields, "host", "hostname", "httpHost", "authority", "url.host", "http.host", "http.hostname", "http.request.headers.host", "_source.layers.http.http.host");
        var url = FirstValue(fields, "url", "http.url", "_source.layers.http.http.url");
        var absoluteUrl = string.Empty;
        if (!string.IsNullOrWhiteSpace(url) && Uri.TryCreate(url, UriKind.Absolute, out var parsedUrl))
        {
            absoluteUrl = url;
            host ??= parsedUrl.Host;
            uri ??= string.IsNullOrWhiteSpace(parsedUrl.PathAndQuery) ? "/" : parsedUrl.PathAndQuery;
        }
        else if (!string.IsNullOrWhiteSpace(url) && string.IsNullOrWhiteSpace(uri))
        {
            uri = url;
        }

        NetworkTelemetrySchema.AddIfNotEmpty(extra, "method", FirstValue(fields, "method", "httpMethod", "http.method", "http.request.method", "_source.layers.http.http.request.method"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "uri", uri);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "requestUri", uri);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "host", host);
        if (!string.IsNullOrWhiteSpace(absoluteUrl))
        {
            NetworkTelemetrySchema.AddIfNotEmpty(extra, "url", absoluteUrl);
        }
        else if (!string.IsNullOrWhiteSpace(host))
        {
            NetworkTelemetrySchema.AddIfNotEmpty(extra, "url", $"http://{host}{(string.IsNullOrWhiteSpace(uri) ? "/" : uri)}");
        }

        NetworkTelemetrySchema.AddIfNotEmpty(extra, "userAgent", FirstValue(fields, "userAgent", "user_agent", "http.user_agent", "http.user_agent.original", "_source.layers.http.http.user_agent"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "contentType", FirstValue(fields, "contentType", "http.content_type", "http.response.mime_type", "_source.layers.http.http.content_type"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "statusCode", FirstValue(fields, "statusCode", "status", "http.status", "http.response.code", "_source.layers.http.http.response.code"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "payloadMagic", FirstValue(fields, "payloadMagic", "file.magic"));
    }

    private static void AddTlsFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        var sni = FirstValue(fields, "sni", "serverName", "tls.sni", "tls.server_name", "tls.handshake.extensions_server_name", "ssl.handshake.extensions_server_name", "_source.layers.tls.tls.handshake.extensions_server_name");
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "sni", sni);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "serverName", sni);
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "tlsVersion", FirstValue(fields, "tlsVersion", "version", "tls.version", "tls.record.version", "tls.handshake.version", "_source.layers.tls.tls.record.version"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "handshakeType", FirstValue(fields, "handshakeType", "tls.handshake.type", "_source.layers.tls.tls.handshake.type"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "ja3", FirstValue(fields, "ja3", "tls.ja3.hash", "tls.handshake.ja3"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "ja3s", FirstValue(fields, "ja3s", "tls.ja3s.hash", "tls.handshake.ja3s"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "alpn", FirstValue(fields, "alpn", "tls.handshake.extensions_alpn_str"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "cipherSuite", FirstValue(fields, "cipherSuite", "tls.handshake.ciphersuite"));
    }

    private static void AddConnectionFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "state", FirstValue(fields, "state", "conn_state"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "durationSeconds", FirstValue(fields, "duration", "durationSeconds"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "packetCount", FirstValue(fields, "packetCount", "packets", "orig_pkts", "pkts", "pkts_toserver", "packet_count"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "byteCount", FirstValue(fields, "byteCount", "bytes", "orig_bytes", "bytes_toserver", "byte_count"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "uid", FirstValue(fields, "uid", "flow_id", "conn.uid"));
    }

    private static void AddSidecarProcessFields(IReadOnlyDictionary<string, string> fields, Dictionary<string, string> extra)
    {
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "processId", FirstValue(fields, "processId", "pid", "proc.pid", "process.pid", "process_id"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "parentProcessId", FirstValue(fields, "parentProcessId", "ppid", "process.parent.pid", "parent_pid"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "rootProcessId", FirstValue(fields, "rootProcessId", "rootPid", "root.pid", "process.root.pid", "process.rootProcessId", "processRootId"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "treeLineage", FirstValue(fields, "treeLineage", "lineage", "process.lineage", "process.treeLineage", "processTreeLineage"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "processName", FirstValue(fields, "processName", "imageName", "process.name", "process.executable", "proc.name", "application", "app", "image", "exe"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "imageName", FirstValue(fields, "imageName", "processName", "process.name", "process.executable", "proc.name", "image", "exe"));
        NetworkTelemetrySchema.AddIfNotEmpty(extra, "commandLine", FirstValue(fields, "commandLine", "cmdline", "process.command_line", "process.commandLine", "process.cmdline"));
    }

    private static SandboxEvent ApplySidecarProcessContext(SandboxEvent evt, IReadOnlyDictionary<string, string> fields)
    {
        var processName = FirstValue(fields, "processName", "imageName", "process.name", "process.executable", "proc.name", "application", "app", "image", "exe");
        var commandLine = FirstValue(fields, "commandLine", "cmdline", "process.command_line", "process.commandLine", "process.cmdline");
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
            AddIfMissing(fields, "src", $"{TrimBrackets(endpointMatch.Groups["src"].Value)}:{endpointMatch.Groups["srcPort"].Value}");
            AddIfMissing(fields, "dst", $"{TrimBrackets(endpointMatch.Groups["dst"].Value)}:{endpointMatch.Groups["dstPort"].Value}");
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

        var lastColon = trimmed.LastIndexOf(':');
        if (lastColon > 0 &&
            trimmed.IndexOf(':') == lastColon &&
            NetworkTelemetrySchema.ParsePort(trimmed[(lastColon + 1)..]) is { } parsedPort)
        {
            return (trimmed[..lastColon], parsedPort);
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

    private static SandboxEvent CreateParseError(string path, int lineNumber, string message, NetworkArtifactSource source)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["schema"] = NetworkTelemetrySchema.SchemaVersion,
            ["eventFamily"] = "network",
            ["eventKind"] = "parse_error",
            ["lineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["message"] = message,
            ["parser"] = "sidecar-jsonl"
        };
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
