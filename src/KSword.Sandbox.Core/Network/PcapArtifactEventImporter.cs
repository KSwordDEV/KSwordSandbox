using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Network;

/// <summary>
/// Imports a bounded subset of PCAP/PCAPNG packet captures into normalized
/// sandbox events. Inputs are existing packet-capture artifacts; processing
/// parses Ethernet/IPv4/TCP/UDP plus lightweight DNS/HTTP/TLS metadata; the
/// method returns report-ready SandboxEvent rows without requiring native
/// packet-capture dependencies.
/// </summary>
public sealed class PcapArtifactEventImporter
{
    private const int MaxPackets = 4096;
    private const int MaxPayloadBytes = 8192;
    private const int MaxFlowEvents = 256;
    private const int MaxProtocolEvents = 256;

    /// <summary>
    /// Parses one packet-capture artifact into normalized events.
    /// Inputs are a .pcap or .pcapng path; processing is best-effort and emits
    /// pcap.parse_error instead of throwing on malformed captures; return value
    /// is a bounded list of pcap.* events.
    /// </summary>
    public IReadOnlyList<SandboxEvent> Import(string path)
    {
        return string.IsNullOrWhiteSpace(path)
            ? []
            : Import(path, NetworkArtifactSource.FromPath(path), includeSidecars: true);
    }

    /// <summary>
    /// Parses one packet-capture artifact with caller-supplied artifact
    /// identity. Inputs are a .pcap/.pcapng path, source identity, and sidecar
    /// inclusion flag; processing keeps native parsing bounded and optionally
    /// imports adjacent sidecars; return value is report-ready network events.
    /// </summary>
    internal IReadOnlyList<SandboxEvent> Import(string path, NetworkArtifactSource source, bool includeSidecars)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var packets = ReadPackets(stream, path).Take(MaxPackets).ToList();
            var events = BuildEvents(path, packets, source).ToList();
            var sidecarEvents = includeSidecars ? ImportSidecarEvents(path, source).ToList() : [];
            var allImportedEvents = events.Concat(sidecarEvents).ToList();
            return
            [
                NetworkTelemetrySchema.CreateImportSummary(
                    path,
                    source,
                    allImportedEvents,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["importer"] = nameof(PcapArtifactEventImporter),
                        ["parser"] = "native-pcap",
                        ["tsharkRequired"] = "false",
                        ["tsharkAvailable"] = IsTsharkAvailable().ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                        ["tsharkStatus"] = IsTsharkAvailable() ? "available-not-required" : "not-found-native-parser-used",
                        ["pcapArtifactCount"] = "1",
                        ["sidecarArtifactCount"] = includeSidecars ? CountSidecarArtifacts(path).ToString(CultureInfo.InvariantCulture) : "0",
                        ["packetCount"] = packets.Count.ToString(CultureInfo.InvariantCulture),
                        ["pcapFormat"] = Path.GetExtension(path).Equals(".pcapng", StringComparison.OrdinalIgnoreCase) ? "pcapng" : "pcap"
                    }),
                .. events,
                .. sidecarEvents
            ];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            var parseError = CreateParseError(path, source, ex);
            return
            [
                NetworkTelemetrySchema.CreateImportSummary(
                    path,
                    source,
                    [parseError],
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["status"] = "parse_error",
                        ["importer"] = nameof(PcapArtifactEventImporter),
                        ["parser"] = "native-pcap",
                        ["tsharkRequired"] = "false",
                        ["tsharkAvailable"] = IsTsharkAvailable().ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                        ["tsharkStatus"] = IsTsharkAvailable() ? "available-not-required" : "not-found-native-parser-used",
                        ["exceptionType"] = ex.GetType().Name,
                        ["diagnosticCode"] = ValueOrEmpty(parseError.Data, "diagnosticCode"),
                        ["parserBoundary"] = ValueOrEmpty(parseError.Data, "parserBoundary"),
                        ["parseFailureStage"] = ValueOrEmpty(parseError.Data, "parseFailureStage"),
                        ["byteOffset"] = ValueOrEmpty(parseError.Data, "byteOffset"),
                        ["expectedBytes"] = ValueOrEmpty(parseError.Data, "expectedBytes"),
                        ["actualBytes"] = ValueOrEmpty(parseError.Data, "actualBytes")
                    }),
                parseError
            ];
        }
    }

    private static IEnumerable<PcapPacket> ReadPackets(Stream stream, string path)
    {
        var magic = new byte[4];
        var magicBytesRead = stream.Read(magic);
        if (magicBytesRead == 0)
        {
            yield break;
        }

        if (magicBytesRead != 4)
        {
            throw new PcapBoundaryException(
                "pcap.global_header",
                "read-magic",
                "PCAP global header is truncated.",
                0,
                4,
                magicBytesRead);
        }

        stream.Position = 0;
        var magicValue = BinaryPrimitives.ReadUInt32LittleEndian(magic.AsSpan());
        if (magicValue == 0x0A0D0D0A)
        {
            foreach (var packet in ReadPcapNgPackets(stream, path))
            {
                yield return packet;
            }

            yield break;
        }

        foreach (var packet in ReadClassicPcapPackets(stream, path))
        {
            yield return packet;
        }
    }

    private static IEnumerable<PcapPacket> ReadClassicPcapPackets(Stream stream, string path)
    {
        var header = new byte[24];
        ReadRequired(stream, header, "pcap.global_header", "read-global-header");

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0, 4));
        var bigEndian = false;
        var nano = false;
        if (magic == 0xD4C3B2A1)
        {
            bigEndian = true;
        }
        else if (magic == 0x4D3CB2A1)
        {
            bigEndian = true;
            nano = true;
        }
        else if (magic == 0xA1B2C3D4)
        {
            bigEndian = false;
        }
        else if (magic == 0xA1B23C4D)
        {
            bigEndian = false;
            nano = true;
        }
        else
        {
            throw new InvalidDataException($"Unsupported PCAP magic in {path}.");
        }

        var linkType = ReadUInt32(header.AsSpan(20, 4), bigEndian);
        var index = 0;
        var packetHeader = new byte[16];
        while (ReadRequired(stream, packetHeader, "pcap.packet_header", "read-packet-header", allowEndOfFile: true))
        {
            var tsSec = ReadUInt32(packetHeader.AsSpan(0, 4), bigEndian);
            var tsFrac = ReadUInt32(packetHeader.AsSpan(4, 4), bigEndian);
            var includedLength = ReadUInt32(packetHeader.AsSpan(8, 4), bigEndian);
            if (includedLength > 16 * 1024 * 1024)
            {
                throw new PcapBoundaryException(
                    "pcap.packet_header",
                    "validate-packet-length",
                    "PCAP packet length is unreasonably large.",
                    stream.CanSeek ? stream.Position - 8 : null,
                    16 * 1024 * 1024,
                    checked((long)includedLength));
            }

            var payload = new byte[includedLength];
            ReadRequired(stream, payload, "pcap.packet_payload", "read-packet-payload");

            index++;
            yield return new PcapPacket(index, linkType, TimestampFromClassic(tsSec, tsFrac, nano), payload);
        }
    }

    private static IEnumerable<PcapPacket> ReadPcapNgPackets(Stream stream, string path)
    {
        var bigEndian = false;
        uint linkType = 1;
        var index = 0;
        while (stream.Position < stream.Length)
        {
            var blockHeader = new byte[8];
            ReadRequired(stream, blockHeader, "pcapng.block_header", "read-block-header");

            var blockType = BinaryPrimitives.ReadUInt32LittleEndian(blockHeader.AsSpan(0, 4));
            var blockLength = BinaryPrimitives.ReadUInt32LittleEndian(blockHeader.AsSpan(4, 4));
            if (blockLength < 12 || blockLength > 64 * 1024 * 1024)
            {
                throw new PcapBoundaryException(
                    "pcapng.block_header",
                    "validate-block-length",
                    $"Unsupported PCAPNG block length in {path}.",
                    stream.CanSeek ? stream.Position - 4 : null,
                    64 * 1024 * 1024,
                    checked((long)blockLength));
            }

            var bodyLength = checked((int)blockLength - 12);
            var body = new byte[bodyLength];
            ReadRequired(stream, body, "pcapng.block_body", "read-block-body");

            var trailer = new byte[4];
            ReadRequired(stream, trailer, "pcapng.block_trailer", "read-block-trailer");
            var trailerLength = ReadUInt32(trailer, bigEndian);
            if (trailerLength != blockLength)
            {
                throw new PcapBoundaryException(
                    "pcapng.block_trailer",
                    "validate-block-trailer",
                    "PCAPNG block trailer length does not match block header length.",
                    stream.CanSeek ? stream.Position - 4 : null,
                    blockLength,
                    trailerLength);
            }

            if (blockType == 0x0A0D0D0A && body.Length >= 4)
            {
                var bom = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(0, 4));
                bigEndian = bom == 0x4D3C2B1A;
            }
            else if (blockType == 0x00000001 && body.Length >= 8)
            {
                linkType = ReadUInt16(body.AsSpan(0, 2), bigEndian);
            }
            else if (blockType == 0x00000006 && body.Length >= 20)
            {
                var timestampHigh = ReadUInt32(body.AsSpan(4, 4), bigEndian);
                var timestampLow = ReadUInt32(body.AsSpan(8, 4), bigEndian);
                var capturedLength = ReadUInt32(body.AsSpan(12, 4), bigEndian);
                if (capturedLength > body.Length - 20)
                {
                    throw new PcapBoundaryException(
                        "pcapng.enhanced_packet",
                        "validate-captured-length",
                        "PCAPNG enhanced packet captured length exceeds block body.",
                        stream.CanSeek ? stream.Position - body.Length - 4 + 12 : null,
                        body.Length - 20,
                        checked((long)capturedLength));
                }

                var packet = body.AsSpan(20, checked((int)capturedLength)).ToArray();
                var ticks = ((ulong)timestampHigh << 32) | timestampLow;
                index++;
                yield return new PcapPacket(index, linkType, DateTimeOffset.UnixEpoch.AddTicks(checked((long)(ticks * 10))), packet);
            }
        }
    }

    private static IReadOnlyList<SandboxEvent> BuildEvents(string path, IReadOnlyList<PcapPacket> packets, NetworkArtifactSource source)
    {
        var events = new List<SandboxEvent>();
        var flows = new Dictionary<string, FlowSummary>(StringComparer.OrdinalIgnoreCase);
        var protocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ipFamilies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var protocolEvents = 0;
        var parsedPackets = 0;
        var bytes = 0L;
        foreach (var packet in packets)
        {
            bytes += packet.Data.Length;
            var decoded = TryDecodePacket(packet);
            if (decoded is null)
            {
                continue;
            }

            parsedPackets++;
            protocols.Add(decoded.TransportProtocol.ToLowerInvariant());
            ipFamilies.Add(decoded.IpFamily);
            var key = decoded.FlowKey;
            if (!flows.TryGetValue(key, out var flow))
            {
                flow = new FlowSummary(decoded);
                flows[key] = flow;
            }

            flow.Observe(decoded);
            if (protocolEvents >= MaxProtocolEvents)
            {
                continue;
            }

            foreach (var protocolEvent in BuildProtocolEvents(path, decoded, source))
            {
                if (protocolEvent.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase))
                {
                    protocols.Add(protocolEvent.EventType["pcap.".Length..].ToLowerInvariant());
                }

                events.Add(protocolEvent);
                protocolEvents++;
                if (protocolEvents >= MaxProtocolEvents)
                {
                    break;
                }
            }
        }

        var summaryData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["schema"] = NetworkTelemetrySchema.SchemaVersion,
            ["eventFamily"] = "network",
            ["eventKind"] = "summary",
            ["importSource"] = "pcap-native",
            ["parser"] = "native-pcap",
            ["packetCount"] = packets.Count.ToString(CultureInfo.InvariantCulture),
            ["parsedPacketCount"] = parsedPackets.ToString(CultureInfo.InvariantCulture),
            ["flowCount"] = flows.Count.ToString(CultureInfo.InvariantCulture),
            ["byteCount"] = bytes.ToString(CultureInfo.InvariantCulture),
            ["protocol"] = string.Join(",", protocols.OrderBy(protocol => protocol, StringComparer.OrdinalIgnoreCase)),
            ["protocols"] = string.Join(",", protocols.OrderBy(protocol => protocol, StringComparer.OrdinalIgnoreCase)),
            ["ipFamilies"] = string.Join(",", ipFamilies.OrderBy(value => value, StringComparer.OrdinalIgnoreCase)),
            ["format"] = Path.GetExtension(path).Equals(".pcapng", StringComparison.OrdinalIgnoreCase) ? "pcapng" : "pcap"
        };
        NetworkTelemetrySchema.AddArtifactData(summaryData, source);
        NetworkTelemetrySchema.ApplyHealthAndLocalization(summaryData);
        events.Insert(0, new SandboxEvent
        {
            EventType = "pcap.summary",
            Source = "host",
            Path = path,
            Data = summaryData
        });

        foreach (var flow in flows.Values.OrderBy(flow => flow.FirstSeenUtc).Take(MaxFlowEvents))
        {
            events.Add(flow.ToEvent(path, "pcap.flow", source));
            events.Add(flow.ToEvent(path, "network.flow", source));
        }

        return events;
    }

    private static IEnumerable<SandboxEvent> BuildProtocolEvents(string path, DecodedPacket packet, NetworkArtifactSource source)
    {
        if ((packet.TransportProtocol is "UDP" or "TCP") && (packet.SourcePort == 53 || packet.DestinationPort == 53))
        {
            var dns = TryParseDns(packet.Payload.AsSpan());
            if (dns is not null)
            {
                var dnsData = DnsData(dns);
                yield return new SandboxEvent
                {
                    EventType = "pcap.dns",
                    Timestamp = packet.Timestamp,
                    Source = "host",
                    Path = path,
                    Data = packet.BaseData(dnsData, "dns", source)
                };
                yield return NetworkTelemetrySchema.CreateNetworkEvent(
                    "dns.query",
                    packet.Timestamp,
                    null,
                    "dns",
                    "pcap-native",
                    packet.TransportProtocol,
                    packet.SourceIp,
                    packet.SourcePort,
                    packet.DestinationIp,
                    packet.DestinationPort,
                    source,
                    dnsData);
            }
        }

        if (packet.TransportProtocol == "TCP" && packet.Payload.Length > 0)
        {
            var http = TryParseHttp(packet.Payload.AsSpan());
            if (http is not null)
            {
                var httpData = HttpData(http);
                yield return new SandboxEvent
                {
                    EventType = "pcap.http",
                    Timestamp = packet.Timestamp,
                    Source = "host",
                    Path = path,
                    Data = packet.BaseData(httpData, "http", source)
                };
                yield return NetworkTelemetrySchema.CreateNetworkEvent(
                    "http.request",
                    packet.Timestamp,
                    null,
                    "http",
                    "pcap-native",
                    packet.TransportProtocol,
                    packet.SourceIp,
                    packet.SourcePort,
                    packet.DestinationIp,
                    packet.DestinationPort,
                    source,
                    httpData);
            }

            var tls = TryParseTls(packet.Payload.AsSpan());
            if (tls is not null)
            {
                var tlsData = TlsData(tls);
                yield return new SandboxEvent
                {
                    EventType = "pcap.tls",
                    Timestamp = packet.Timestamp,
                    Source = "host",
                    Path = path,
                    Data = packet.BaseData(tlsData, "tls", source)
                };
                yield return NetworkTelemetrySchema.CreateNetworkEvent(
                    "tls.connection",
                    packet.Timestamp,
                    null,
                    "tls",
                    "pcap-native",
                    packet.TransportProtocol,
                    packet.SourceIp,
                    packet.SourcePort,
                    packet.DestinationIp,
                    packet.DestinationPort,
                    source,
                    tlsData);
            }
        }
    }

    private static Dictionary<string, string> DnsData(DnsInfo dns)
    {
        var isNxDomain = dns.RCode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase);
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["queryName"] = dns.QueryName,
            ["qname"] = dns.QueryName,
            ["domain"] = dns.QueryName,
            ["dnsQueryName"] = dns.QueryName,
            ["queryType"] = dns.QueryType,
            ["recordType"] = dns.QueryType,
            ["dnsRecordType"] = dns.QueryType,
            ["rcode"] = dns.RCode,
            ["rcodeName"] = dns.RCode,
            ["responseCode"] = dns.RCode,
            ["dnsRcode"] = dns.RCode,
            ["isResponse"] = dns.IsResponse.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
            ["answer"] = dns.Answers,
            ["answers"] = dns.Answers,
            ["resolvedIps"] = dns.Answers,
            ["dnsAnswers"] = dns.Answers,
            ["answerCount"] = dns.AnswerCount,
            ["ttl"] = dns.Ttl,
            ["classification"] = isNxDomain ? "nxdomain" : string.Empty,
            ["dnsOutcome"] = isNxDomain ? "negative" : string.IsNullOrWhiteSpace(dns.Answers) ? string.Empty : "answered",
            ["isNxDomain"] = isNxDomain ? "true" : string.Empty
        };
    }

    private static Dictionary<string, string> HttpData(HttpInfo http)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["httpMessageType"] = http.MessageType,
            ["method"] = http.Method,
            ["httpMethod"] = http.Method,
            ["uri"] = http.Uri,
            ["requestUri"] = http.Uri,
            ["path"] = http.Uri,
            ["host"] = http.Host,
            ["hostname"] = http.Host,
            ["httpHost"] = http.Host,
            ["url"] = string.IsNullOrWhiteSpace(http.Host) || string.IsNullOrWhiteSpace(http.Uri)
                ? string.Empty
                : $"http://{http.Host}{http.Uri}",
            ["userAgent"] = http.UserAgent,
            ["contentType"] = http.ContentType,
            ["statusCode"] = http.StatusCode,
            ["responseStatusCode"] = http.StatusCode,
            ["httpStatusCode"] = http.StatusCode,
            ["statusFamily"] = StatusFamily(http.StatusCode),
            ["requestBodyBytes"] = http.RequestBytes,
            ["requestBytes"] = http.RequestBytes,
            ["bytesToServer"] = http.RequestBytes,
            ["responseBodyBytes"] = http.ResponseBytes,
            ["responseBytes"] = http.ResponseBytes,
            ["bytesToClient"] = http.ResponseBytes,
            ["requestContentLength"] = string.Equals(http.MessageType, "request", StringComparison.OrdinalIgnoreCase) ? http.ContentLength : string.Empty,
            ["responseContentLength"] = string.Equals(http.MessageType, "response", StringComparison.OrdinalIgnoreCase) ? http.ContentLength : string.Empty,
            ["uploadBytes"] = http.RequestBytes,
            ["downloadBytes"] = http.ResponseBytes,
            ["payloadMagic"] = http.PayloadMagic
        };

        if (!string.IsNullOrWhiteSpace(http.RequestBytes) &&
            (string.Equals(http.Method, "POST", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(http.Method, "PUT", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(http.Method, "PATCH", StringComparison.OrdinalIgnoreCase) ||
                IsPositiveInteger(http.RequestBytes)))
        {
            data["uploadCandidate"] = "true";
            data["transferDirection"] = "upload";
        }
        else if (!string.IsNullOrWhiteSpace(http.ResponseBytes))
        {
            data["transferDirection"] = "download";
        }

        return data;
    }

    private static Dictionary<string, string> TlsData(TlsInfo tls)
    {
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sni"] = tls.Sni,
            ["serverName"] = tls.Sni,
            ["tlsServerName"] = tls.Sni,
            ["tlsVersion"] = tls.Version,
            ["handshakeType"] = tls.HandshakeType,
            ["ja3"] = tls.Ja3,
            ["ja3Hash"] = tls.Ja3,
            ["tlsJa3"] = tls.Ja3,
            ["ja3s"] = tls.Ja3s,
            ["ja3sHash"] = tls.Ja3s,
            ["tlsJa3s"] = tls.Ja3s,
            ["alpn"] = tls.Alpn,
            ["cipherSuite"] = tls.CipherSuite,
            ["tlsExtensionTypes"] = tls.ExtensionTypes,
            ["certSubject"] = tls.CertSubject,
            ["certIssuer"] = tls.CertIssuer,
            ["certSerial"] = tls.CertSerial,
            ["certSha256"] = tls.CertSha256,
            ["certificateSha256"] = tls.CertSha256,
            ["certificateFingerprintSha256"] = tls.CertSha256,
            ["certNotBefore"] = tls.CertNotBefore,
            ["certNotAfter"] = tls.CertNotAfter,
            ["certificateStatus"] = tls.CertificateStatus,
            ["validationStatus"] = tls.CertificateStatus,
            ["certSelfSigned"] = tls.CertSelfSigned,
            ["tlsCertificateRisk"] = string.Equals(tls.CertificateStatus, "self-signed", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(tls.CertificateStatus, "parse_error", StringComparison.OrdinalIgnoreCase)
                    ? "suspicious"
                    : string.Empty
        };
    }

    private static DecodedPacket? TryDecodePacket(PcapPacket packet)
    {
        if (packet.LinkType != 1 || packet.Data.Length < 14)
        {
            return null;
        }

        var frame = packet.Data.AsSpan();
        var etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2));
        var offset = 14;
        if (etherType == 0x8100 && frame.Length >= 18)
        {
            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(16, 2));
            offset = 18;
        }

        if (etherType == 0x0800 && frame.Length >= offset + 20)
        {
            return TryDecodeIpv4Packet(packet.Timestamp, frame[offset..]);
        }

        if (etherType == 0x86DD && frame.Length >= offset + 40)
        {
            return TryDecodeIpv6Packet(packet.Timestamp, frame[offset..]);
        }

        return null;
    }

    private static DecodedPacket? TryDecodeIpv4Packet(DateTimeOffset timestamp, ReadOnlySpan<byte> ip)
    {
        var version = ip[0] >> 4;
        var ihl = (ip[0] & 0x0F) * 4;
        if (version != 4 || ihl < 20 || ip.Length < ihl)
        {
            return null;
        }

        var protocol = ip[9];
        var sourceIp = new IPAddress(ip.Slice(12, 4)).ToString();
        var destinationIp = new IPAddress(ip.Slice(16, 4)).ToString();
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(ip.Slice(2, 2));
        var availableLength = Math.Min(ip.Length, totalLength <= 0 ? ip.Length : totalLength);
        if (availableLength < ihl)
        {
            return null;
        }

        return TryDecodeTransport(
            timestamp,
            sourceIp,
            destinationIp,
            protocol,
            ip.Slice(ihl, availableLength - ihl));
    }

    private static DecodedPacket? TryDecodeIpv6Packet(DateTimeOffset timestamp, ReadOnlySpan<byte> ip)
    {
        var version = ip[0] >> 4;
        if (version != 6 || ip.Length < 40)
        {
            return null;
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(ip.Slice(4, 2));
        var availableLength = Math.Min(ip.Length, 40 + payloadLength);
        if (availableLength < 40)
        {
            return null;
        }

        var protocol = ip[6];
        var transportOffset = 40;
        var payloadEnd = availableLength;
        while (transportOffset < payloadEnd && IsIpv6ExtensionHeader(protocol))
        {
            if (protocol == 44)
            {
                if (transportOffset + 8 > payloadEnd)
                {
                    return null;
                }

                protocol = ip[transportOffset];
                transportOffset += 8;
                continue;
            }

            if (transportOffset + 2 > payloadEnd)
            {
                return null;
            }

            var extensionLength = protocol == 51
                ? (ip[transportOffset + 1] + 2) * 4
                : (ip[transportOffset + 1] + 1) * 8;
            if (extensionLength <= 0 || transportOffset + extensionLength > payloadEnd)
            {
                return null;
            }

            protocol = ip[transportOffset];
            transportOffset += extensionLength;
        }

        if (transportOffset >= payloadEnd)
        {
            return null;
        }

        var sourceIp = new IPAddress(ip.Slice(8, 16)).ToString();
        var destinationIp = new IPAddress(ip.Slice(24, 16)).ToString();
        return TryDecodeTransport(
            timestamp,
            sourceIp,
            destinationIp,
            protocol,
            ip.Slice(transportOffset, payloadEnd - transportOffset));
    }

    private static bool IsIpv6ExtensionHeader(byte nextHeader)
    {
        return nextHeader is 0 or 43 or 44 or 51 or 60 or 135;
    }

    private static DecodedPacket? TryDecodeTransport(
        DateTimeOffset timestamp,
        string sourceIp,
        string destinationIp,
        byte protocol,
        ReadOnlySpan<byte> transport)
    {
        if (protocol == 6 && transport.Length >= 20)
        {
            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(0, 2));
            var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2));
            var dataOffset = (transport[12] >> 4) * 4;
            if (dataOffset < 20 || dataOffset > transport.Length)
            {
                return null;
            }

            return new DecodedPacket(
                timestamp,
                sourceIp,
                destinationIp,
                sourcePort,
                destinationPort,
                "TCP",
                transport[dataOffset..].Slice(0, Math.Min(MaxPayloadBytes, transport.Length - dataOffset)).ToArray());
        }

        if (protocol == 17 && transport.Length >= 8)
        {
            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(0, 2));
            var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(transport.Slice(2, 2));
            return new DecodedPacket(
                timestamp,
                sourceIp,
                destinationIp,
                sourcePort,
                destinationPort,
                "UDP",
                transport[8..].Slice(0, Math.Min(MaxPayloadBytes, transport.Length - 8)).ToArray());
        }

        return null;
    }

    private static DnsInfo? TryParseDns(ReadOnlySpan<byte> payload)
    {
        payload = StripDnsTcpLengthPrefix(payload);
        if (payload.Length < 12)
        {
            return null;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(6, 2));
        if (questionCount == 0)
        {
            return null;
        }

        var offset = 12;
        if (!TryReadDnsName(payload, ref offset, out var queryName) ||
            string.IsNullOrWhiteSpace(queryName) ||
            offset + 4 > payload.Length)
        {
            return null;
        }

        var qtype = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        offset += 4; // qtype + qclass
        for (var questionIndex = 1; questionIndex < questionCount; questionIndex++)
        {
            if (!TryReadDnsName(payload, ref offset, out _) || offset + 4 > payload.Length)
            {
                break;
            }

            offset += 4;
        }

        var answers = new List<string>();
        var ttl = string.Empty;
        for (var answerIndex = 0; answerIndex < answerCount && answerIndex < 32; answerIndex++)
        {
            if (!TryReadDnsName(payload, ref offset, out _) || offset + 10 > payload.Length)
            {
                break;
            }

            var answerType = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
            offset += 2;
            offset += 2; // class
            var answerTtl = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset, 4));
            offset += 4;
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
            offset += 2;
            if (offset + dataLength > payload.Length)
            {
                break;
            }

            var dataOffset = offset;
            var answer = ReadDnsAnswer(payload, answerType, dataOffset, dataLength);
            if (!string.IsNullOrWhiteSpace(answer))
            {
                answers.Add(answer);
                if (string.IsNullOrWhiteSpace(ttl))
                {
                    ttl = answerTtl.ToString(CultureInfo.InvariantCulture);
                }
            }

            offset = dataOffset + dataLength;
        }

        var rcode = flags & 0x000F;
        return new DnsInfo(
            NetworkTelemetrySchema.NormalizeDnsName(queryName),
            NetworkTelemetrySchema.NormalizeDnsRecordType(DnsTypeName(qtype)),
            NetworkTelemetrySchema.NormalizeDnsRCode(DnsRCodeName(rcode)),
            (flags & 0x8000) != 0,
            NetworkTelemetrySchema.NormalizeDnsAnswerList(string.Join(",", answers)),
            answerCount.ToString(CultureInfo.InvariantCulture),
            ttl);
    }

    private static ReadOnlySpan<byte> StripDnsTcpLengthPrefix(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 14)
        {
            return payload;
        }

        var declaredLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(0, 2));
        return declaredLength > 0 && declaredLength <= payload.Length - 2
            ? payload.Slice(2, declaredLength)
            : payload;
    }

    private static bool TryReadDnsName(ReadOnlySpan<byte> payload, ref int offset, out string name)
    {
        name = string.Empty;
        var cursor = offset;
        var jumped = false;
        var labels = new List<string>();
        var visitedPointers = new HashSet<int>();

        for (var guard = 0; guard < 128 && cursor < payload.Length; guard++)
        {
            var length = payload[cursor++];
            if (length == 0)
            {
                if (!jumped)
                {
                    offset = cursor;
                }

                name = string.Join('.', labels);
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= payload.Length)
                {
                    return false;
                }

                var pointer = ((length & 0x3F) << 8) | payload[cursor++];
                if (pointer < 0 || pointer >= payload.Length || !visitedPointers.Add(pointer))
                {
                    return false;
                }

                if (!jumped)
                {
                    offset = cursor;
                }

                cursor = pointer;
                jumped = true;
                continue;
            }

            if ((length & 0xC0) != 0 || length > 63 || cursor + length > payload.Length)
            {
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(payload.Slice(cursor, length)));
            cursor += length;
        }

        return false;
    }

    private static string ReadDnsAnswer(ReadOnlySpan<byte> payload, ushort answerType, int dataOffset, ushort dataLength)
    {
        var data = payload.Slice(dataOffset, dataLength);
        if (answerType == 1 && data.Length == 4)
        {
            return new IPAddress(data.ToArray()).ToString();
        }

        if (answerType == 28 && data.Length == 16)
        {
            return new IPAddress(data.ToArray()).ToString();
        }

        if (answerType is 2 or 5 or 12 && data.Length > 0)
        {
            var nameOffset = dataOffset;
            return TryReadDnsName(payload, ref nameOffset, out var name)
                ? NetworkTelemetrySchema.NormalizeDnsName(name)
                : string.Empty;
        }

        if (answerType == 16 && data.Length > 1)
        {
            var textLength = data[0];
            if (textLength > 0 && 1 + textLength <= data.Length)
            {
                return Encoding.ASCII.GetString(data.Slice(1, textLength));
            }
        }

        return string.Empty;
    }

    private static HttpInfo? TryParseHttp(ReadOnlySpan<byte> payload)
    {
        var length = Math.Min(payload.Length, MaxPayloadBytes);
        if (length < 8)
        {
            return null;
        }

        var text = Encoding.ASCII.GetString(payload[..length]);
        var firstLineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
        if (firstLineEnd <= 0)
        {
            return null;
        }

        var firstLine = text[..firstLineEnd];
        var parts = firstLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headerText = headerEnd >= 0
            ? text[(firstLineEnd + 2)..headerEnd]
            : text[(firstLineEnd + 2)..];
        var headers = ParseHeaders(headerText);
        var contentLength = headers.GetValueOrDefault("content-length", string.Empty);
        var bodyBytes = headerEnd >= 0 && headerEnd + 4 <= length
            ? (length - headerEnd - 4).ToString(CultureInfo.InvariantCulture)
            : string.Empty;
        var effectiveBodyBytes = FirstNonEmpty(contentLength, bodyBytes);
        var payloadMagic = text.Contains("MZ", StringComparison.Ordinal) ? "MZ" : string.Empty;

        if (parts.Length >= 2 && IsHttpMethod(parts[0]))
        {
            return new HttpInfo(
                "request",
                parts[0],
                parts[1],
                headers.GetValueOrDefault("host", string.Empty),
                headers.GetValueOrDefault("user-agent", string.Empty),
                headers.GetValueOrDefault("content-type", string.Empty),
                string.Empty,
                effectiveBodyBytes,
                string.Empty,
                contentLength,
                payloadMagic);
        }

        if (parts.Length >= 2 &&
            firstLine.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var statusCode))
        {
            return new HttpInfo(
                "response",
                string.Empty,
                string.Empty,
                headers.GetValueOrDefault("host", string.Empty),
                string.Empty,
                headers.GetValueOrDefault("content-type", string.Empty),
                statusCode.ToString(CultureInfo.InvariantCulture),
                string.Empty,
                effectiveBodyBytes,
                contentLength,
                payloadMagic);
        }

        return null;
    }

    private static TlsInfo? TryParseTls(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 9 || payload[0] != 0x16)
        {
            return null;
        }

        var recordVersion = $"0x{payload[1]:X2}{payload[2]:X2}";
        var recordLength = (int)BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
        if (recordLength <= 0 || 5 + recordLength > payload.Length)
        {
            recordLength = payload.Length - 5;
        }

        var handshake = payload.Slice(5, recordLength);
        if (handshake.Length < 4)
        {
            return new TlsInfo(string.Empty, recordVersion, "handshake", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var handshakeType = handshake[0];
        var handshakeLength = ReadUInt24(handshake.Slice(1, 3));
        var bodyLength = Math.Min(handshake.Length - 4, handshakeLength);
        if (bodyLength < 0)
        {
            return null;
        }

        var body = handshake.Slice(4, bodyLength);
        return handshakeType switch
        {
            1 => ParseTlsClientHello(body, recordVersion),
            2 => ParseTlsServerHello(body, recordVersion),
            11 => ParseTlsCertificate(body, recordVersion),
            _ => new TlsInfo(string.Empty, recordVersion, $"handshake_{handshakeType.ToString(CultureInfo.InvariantCulture)}", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty)
        };
    }

    private static TlsInfo ParseTlsClientHello(ReadOnlySpan<byte> body, string recordVersion)
    {
        if (body.Length < 34)
        {
            return new TlsInfo(string.Empty, recordVersion, "client_hello", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var clientVersion = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(0, 2));
        var offset = 34; // version + random
        if (offset >= body.Length)
        {
            return new TlsInfo(string.Empty, TlsVersionName(clientVersion, recordVersion), "client_hello", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var sessionIdLength = body[offset++];
        if (offset + sessionIdLength + 2 > body.Length)
        {
            return new TlsInfo(string.Empty, TlsVersionName(clientVersion, recordVersion), "client_hello", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        offset += sessionIdLength;
        var cipherLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
        offset += 2;
        if (cipherLength < 0 || offset + cipherLength > body.Length)
        {
            return new TlsInfo(string.Empty, TlsVersionName(clientVersion, recordVersion), "client_hello", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var cipherSuites = ReadUInt16List(body.Slice(offset, cipherLength), excludeGrease: true);
        offset += cipherLength;
        if (offset >= body.Length)
        {
            return new TlsInfo(string.Empty, TlsVersionName(clientVersion, recordVersion), "client_hello", Ja3Hash(clientVersion, cipherSuites, [], [], []), string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var compressionLength = body[offset++];
        if (offset + compressionLength > body.Length)
        {
            return new TlsInfo(string.Empty, TlsVersionName(clientVersion, recordVersion), "client_hello", Ja3Hash(clientVersion, cipherSuites, [], [], []), string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        offset += compressionLength;
        if (offset + 2 > body.Length)
        {
            return new TlsInfo(string.Empty, TlsVersionName(clientVersion, recordVersion), "client_hello", Ja3Hash(clientVersion, cipherSuites, [], [], []), string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
        offset += 2;
        var extensionsEnd = Math.Min(body.Length, offset + extensionsLength);
        var extensionTypes = new List<ushort>();
        var ellipticCurves = new List<ushort>();
        var ecPointFormats = new List<byte>();
        var sni = string.Empty;
        var alpn = string.Empty;
        while (offset + 4 <= extensionsEnd)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
            var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset + 2, 2));
            offset += 4;
            if (offset + extensionLength > extensionsEnd)
            {
                break;
            }

            var extension = body.Slice(offset, extensionLength);
            if (!IsGreaseValue(type))
            {
                extensionTypes.Add(type);
            }

            if (type == 0)
            {
                sni = ParseSniExtension(extension);
            }
            else if (type == 10)
            {
                ellipticCurves = ParseUInt16VectorExtension(extension);
            }
            else if (type == 11)
            {
                ecPointFormats = ParseByteVectorExtension(extension);
            }
            else if (type == 16)
            {
                alpn = ParseAlpnExtension(extension);
            }

            offset += extensionLength;
        }

        return new TlsInfo(
            sni,
            TlsVersionName(clientVersion, recordVersion),
            "client_hello",
            Ja3Hash(clientVersion, cipherSuites, extensionTypes, ellipticCurves, ecPointFormats),
            string.Empty,
            alpn,
            cipherSuites.Count > 0 ? UInt16Hex(cipherSuites[0]) : string.Empty,
            string.Join("-", extensionTypes.Select(value => value.ToString(CultureInfo.InvariantCulture))),
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty);
    }

    private static TlsInfo ParseTlsServerHello(ReadOnlySpan<byte> body, string recordVersion)
    {
        if (body.Length < 38)
        {
            return new TlsInfo(string.Empty, recordVersion, "server_hello", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var serverVersion = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(0, 2));
        var offset = 34; // version + random
        var sessionIdLength = body[offset++];
        if (offset + sessionIdLength + 3 > body.Length)
        {
            return new TlsInfo(string.Empty, TlsVersionName(serverVersion, recordVersion), "server_hello", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        offset += sessionIdLength;
        var cipherSuite = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
        offset += 3; // cipher + compression
        var extensionTypes = new List<ushort>();
        var alpn = string.Empty;
        if (offset + 2 <= body.Length)
        {
            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
            offset += 2;
            var extensionsEnd = Math.Min(body.Length, offset + extensionsLength);
            while (offset + 4 <= extensionsEnd)
            {
                var type = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset, 2));
                var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(offset + 2, 2));
                offset += 4;
                if (offset + extensionLength > extensionsEnd)
                {
                    break;
                }

                var extension = body.Slice(offset, extensionLength);
                if (!IsGreaseValue(type))
                {
                    extensionTypes.Add(type);
                }

                if (type == 16)
                {
                    alpn = ParseAlpnExtension(extension);
                }

                offset += extensionLength;
            }
        }

        return new TlsInfo(
            string.Empty,
            TlsVersionName(serverVersion, recordVersion),
            "server_hello",
            string.Empty,
            Ja3sHash(serverVersion, cipherSuite, extensionTypes),
            alpn,
            UInt16Hex(cipherSuite),
            string.Join("-", extensionTypes.Select(value => value.ToString(CultureInfo.InvariantCulture))),
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty);
    }

    private static TlsInfo ParseTlsCertificate(ReadOnlySpan<byte> body, string recordVersion)
    {
        if (body.Length < 6)
        {
            return new TlsInfo(string.Empty, recordVersion, "certificate", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, "parse_error");
        }

        var listOffset = 0;
        var certificateListLength = ReadUInt24(body.Slice(0, 3));
        if (certificateListLength == 0 && body.Length >= 7)
        {
            // TLS 1.3 Certificate starts with certificate_request_context before
            // certificate_list. Treat this as best-effort metadata, not failure.
            var contextLength = body[0];
            if (1 + contextLength + 3 <= body.Length)
            {
                listOffset = 1 + contextLength;
                certificateListLength = ReadUInt24(body.Slice(listOffset, 3));
            }
        }

        listOffset += 3;
        if (certificateListLength <= 0 || listOffset + 3 > body.Length)
        {
            return new TlsInfo(string.Empty, recordVersion, "certificate", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, "parse_error");
        }

        var certLength = ReadUInt24(body.Slice(listOffset, 3));
        listOffset += 3;
        if (certLength <= 0 || listOffset + certLength > body.Length)
        {
            return new TlsInfo(string.Empty, recordVersion, "certificate", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, "parse_error");
        }

        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(body.Slice(listOffset, certLength).ToArray());
            var sha256 = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
            var status = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase)
                ? "self-signed"
                : "observed";
            return new TlsInfo(
                string.Empty,
                recordVersion,
                "certificate",
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                cert.Subject,
                cert.Issuer,
                cert.SerialNumber,
                sha256,
                cert.NotBefore.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                cert.NotAfter.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                status);
        }
        catch (CryptographicException)
        {
            return new TlsInfo(string.Empty, recordVersion, "certificate", string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, "parse_error");
        }
    }

    private static int ReadUInt24(ReadOnlySpan<byte> value)
    {
        return value.Length < 3
            ? 0
            : (value[0] << 16) | (value[1] << 8) | value[2];
    }

    private static List<ushort> ReadUInt16List(ReadOnlySpan<byte> value, bool excludeGrease)
    {
        var values = new List<ushort>();
        for (var offset = 0; offset + 2 <= value.Length; offset += 2)
        {
            var parsed = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(offset, 2));
            if (!excludeGrease || !IsGreaseValue(parsed))
            {
                values.Add(parsed);
            }
        }

        return values;
    }

    private static string ParseSniExtension(ReadOnlySpan<byte> extension)
    {
        if (extension.Length < 5)
        {
            return string.Empty;
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(0, 2));
        var offset = 2;
        var end = Math.Min(extension.Length, offset + listLength);
        while (offset + 3 <= end)
        {
            var nameType = extension[offset++];
            var nameLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(offset, 2));
            offset += 2;
            if (offset + nameLength > end)
            {
                break;
            }

            if (nameType == 0)
            {
                return Encoding.ASCII.GetString(extension.Slice(offset, nameLength));
            }

            offset += nameLength;
        }

        return string.Empty;
    }

    private static string ParseAlpnExtension(ReadOnlySpan<byte> extension)
    {
        if (extension.Length < 3)
        {
            return string.Empty;
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(0, 2));
        var offset = 2;
        var end = Math.Min(extension.Length, offset + listLength);
        var values = new List<string>();
        while (offset < end)
        {
            var length = extension[offset++];
            if (length == 0 || offset + length > end)
            {
                break;
            }

            values.Add(Encoding.ASCII.GetString(extension.Slice(offset, length)));
            offset += length;
        }

        return string.Join(",", values);
    }

    private static List<ushort> ParseUInt16VectorExtension(ReadOnlySpan<byte> extension)
    {
        if (extension.Length < 2)
        {
            return [];
        }

        var vectorLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(0, 2));
        var length = Math.Min(extension.Length - 2, vectorLength);
        return ReadUInt16List(extension.Slice(2, length), excludeGrease: true);
    }

    private static List<byte> ParseByteVectorExtension(ReadOnlySpan<byte> extension)
    {
        if (extension.Length < 1)
        {
            return [];
        }

        var vectorLength = extension[0];
        var length = Math.Min(extension.Length - 1, vectorLength);
        return extension.Slice(1, length).ToArray().ToList();
    }

    private static string Ja3Hash(
        ushort version,
        IReadOnlyCollection<ushort> cipherSuites,
        IReadOnlyCollection<ushort> extensionTypes,
        IReadOnlyCollection<ushort> ellipticCurves,
        IReadOnlyCollection<byte> ecPointFormats)
    {
        var ja3String = string.Join(
            ',',
            version.ToString(CultureInfo.InvariantCulture),
            JoinUInt16(cipherSuites),
            JoinUInt16(extensionTypes),
            JoinUInt16(ellipticCurves),
            string.Join('-', ecPointFormats.Select(value => value.ToString(CultureInfo.InvariantCulture))));
        return Md5Hex(ja3String);
    }

    private static string Ja3sHash(ushort version, ushort cipherSuite, IReadOnlyCollection<ushort> extensionTypes)
    {
        var ja3sString = string.Join(
            ',',
            version.ToString(CultureInfo.InvariantCulture),
            cipherSuite.ToString(CultureInfo.InvariantCulture),
            JoinUInt16(extensionTypes));
        return Md5Hex(ja3sString);
    }

    private static string Md5Hex(string value)
    {
        return Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant();
    }

    private static string JoinUInt16(IEnumerable<ushort> values)
    {
        return string.Join('-', values.Select(value => value.ToString(CultureInfo.InvariantCulture)));
    }

    private static bool IsGreaseValue(ushort value)
    {
        return (value & 0x0F0F) == 0x0A0A &&
            ((value >> 8) & 0xFF) == (value & 0xFF);
    }

    private static string TlsVersionName(ushort version, string fallback)
    {
        return version switch
        {
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => string.IsNullOrWhiteSpace(fallback) ? UInt16Hex(version) : fallback
        };
    }

    private static string UInt16Hex(ushort value)
    {
        return $"0x{value:X4}";
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static SandboxEvent CreateParseError(string path, NetworkArtifactSource source, Exception ex)
    {
        var boundary = ex is PcapBoundaryException boundaryException
            ? boundaryException
            : null;
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["schema"] = NetworkTelemetrySchema.SchemaVersion,
            ["eventFamily"] = "network",
            ["eventKind"] = "parse_error",
            ["status"] = "parse_error",
            ["exceptionType"] = ex.GetType().Name,
            ["message"] = ex.Message,
            ["diagnosticMessage"] = ex.Message,
            ["parseErrorMessage"] = ex.Message,
            ["parser"] = "native-pcap",
            ["diagnosticCode"] = boundary?.DiagnosticCode ?? "pcap_parse_error",
            ["parserBoundary"] = boundary?.ParserBoundary ?? "pcap.container",
            ["parseFailureStage"] = boundary?.ParseFailureStage ?? "native-pcap-read",
            ["diagnosticStage"] = boundary?.ParseFailureStage ?? "native-pcap-read",
            ["zhHint"] = "PCAP 文件边界或长度校验失败；请保留源文件，优先检查抓包是否截断、复制未完成或格式不匹配。"
        };
        if (boundary is not null)
        {
            NetworkTelemetrySchema.AddIfNotEmpty(data, "byteOffset", boundary.ByteOffset?.ToString(CultureInfo.InvariantCulture));
            NetworkTelemetrySchema.AddIfNotEmpty(data, "expectedBytes", boundary.ExpectedBytes?.ToString(CultureInfo.InvariantCulture));
            NetworkTelemetrySchema.AddIfNotEmpty(data, "actualBytes", boundary.ActualBytes?.ToString(CultureInfo.InvariantCulture));
        }

        NetworkTelemetrySchema.AddArtifactData(data, source);
        NetworkTelemetrySchema.ApplyHealthAndLocalization(data);
        return new SandboxEvent
        {
            EventType = "pcap.parse_error",
            Source = "host",
            Path = path,
            Data = data
        };
    }

    private static string ValueOrEmpty(IReadOnlyDictionary<string, string> data, string key)
    {
        return data.TryGetValue(key, out var value) ? value : string.Empty;
    }

    private static string StatusFamily(string? statusCode)
    {
        return int.TryParse(statusCode, NumberStyles.Integer, CultureInfo.InvariantCulture, out var status) &&
            status is >= 100 and <= 599
                ? $"{status / 100}xx"
                : string.Empty;
    }

    private static bool IsPositiveInteger(string? value)
    {
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) &&
            parsed > 0;
    }

    private static Dictionary<string, string> ParseHeaders(string headerText)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in headerText.Split("\r\n", StringSplitOptions.None))
        {
            if (line.Length == 0)
            {
                break;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        return headers;
    }

    private static bool IsHttpMethod(string method)
    {
        return method is "GET" or "POST" or "PUT" or "DELETE" or "HEAD" or "OPTIONS" or "CONNECT" or "PATCH";
    }

    private static DateTimeOffset TimestampFromClassic(uint seconds, uint fraction, bool nano)
    {
        var ticks = nano ? fraction / 100 : fraction * 10;
        return DateTimeOffset.UnixEpoch.AddSeconds(seconds).AddTicks(ticks);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> value, bool bigEndian)
    {
        return bigEndian ? BinaryPrimitives.ReadUInt16BigEndian(value) : BinaryPrimitives.ReadUInt16LittleEndian(value);
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> value, bool bigEndian)
    {
        return bigEndian ? BinaryPrimitives.ReadUInt32BigEndian(value) : BinaryPrimitives.ReadUInt32LittleEndian(value);
    }

    private static bool ReadRequired(
        Stream stream,
        Span<byte> buffer,
        string parserBoundary,
        string parseFailureStage,
        bool allowEndOfFile = false)
    {
        var startOffset = stream.CanSeek ? stream.Position : (long?)null;
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer[total..]);
            if (read == 0)
            {
                if (allowEndOfFile && total == 0)
                {
                    return false;
                }

                throw new PcapBoundaryException(
                    parserBoundary,
                    parseFailureStage,
                    $"{parserBoundary} is truncated.",
                    startOffset.HasValue ? startOffset.Value + total : null,
                    buffer.Length,
                    total);
            }

            total += read;
        }

        return true;
    }

    private sealed class PcapBoundaryException(
        string parserBoundary,
        string parseFailureStage,
        string message,
        long? byteOffset,
        long? expectedBytes,
        long? actualBytes) : IOException(message)
    {
        public string ParserBoundary { get; } = parserBoundary;

        public string ParseFailureStage { get; } = parseFailureStage;

        public string DiagnosticCode { get; } = "pcap_boundary_truncated";

        public long? ByteOffset { get; } = byteOffset;

        public long? ExpectedBytes { get; } = expectedBytes;

        public long? ActualBytes { get; } = actualBytes;
    }

    private static string DnsTypeName(ushort qtype)
    {
        return qtype switch
        {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            _ => qtype.ToString()
        };
    }

    private static string DnsRCodeName(int rcode)
    {
        return rcode switch
        {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            9 => "NOTAUTH",
            10 => "NOTZONE",
            _ => rcode.ToString()
        };
    }

    private static IEnumerable<SandboxEvent> ImportSidecarEvents(string pcapPath, NetworkArtifactSource pcapSource)
    {
        var sidecarImporter = new NetworkSidecarEventImporter();
        var sidecarMetadata = PcapSidecarMetadata(pcapSource);
        foreach (var sidecarPath in EnumerateSidecarPaths(pcapPath))
        {
            var sidecarSource = NetworkArtifactSource.FromPath(
                sidecarPath,
                pcapSource.ImportRoot,
                artifactKind: "Log",
                collectionName: "network-sidecars",
                evidenceRole: "network-telemetry-sidecar",
                importMode: "sidecar-artifact",
                metadata: sidecarMetadata);
            foreach (var evt in sidecarImporter.ImportEvents(sidecarPath, sidecarSource))
            {
                yield return evt;
            }
        }
    }

    private static IReadOnlyDictionary<string, string> PcapSidecarMetadata(NetworkArtifactSource pcapSource)
    {
        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (pcapSource.Metadata is not null)
        {
            foreach (var pair in pcapSource.Metadata)
            {
                metadata[pair.Key] = pair.Value;
            }
        }

        metadata["pcapSourceArtifactPath"] = pcapSource.FullPath;
        metadata["pcapSourceArtifactName"] = pcapSource.Name;
        metadata["pcapSourceArtifactRelativePath"] = pcapSource.RelativePath;
        metadata["pcapArtifactRelativePath"] = pcapSource.RelativePath;
        metadata["pcapSourceArtifactSelector"] = pcapSource.RelativePath;
        metadata["pcapDownloadSelector"] = pcapSource.RelativePath;
        metadata["sourcePcapArtifactPath"] = pcapSource.FullPath;
        metadata["sourcePcapArtifactName"] = pcapSource.Name;
        metadata["sourcePcapArtifactRelativePath"] = pcapSource.RelativePath;
        metadata["sourcePcapArtifactSelector"] = pcapSource.RelativePath;
        metadata["sourcePcapDownloadSelector"] = pcapSource.RelativePath;
        try
        {
            var info = new FileInfo(pcapSource.FullPath);
            if (info.Exists)
            {
                var sizeText = info.Length.ToString(CultureInfo.InvariantCulture);
                var sha256 = ComputeFileSha256(info.FullName);
                metadata["pcapSourceArtifactSizeBytes"] = sizeText;
                metadata["sourcePcapArtifactSizeBytes"] = sizeText;
                metadata["pcapArtifactSizeBytes"] = sizeText;
                metadata["pcapSourceArtifactSha256"] = sha256;
                metadata["sourcePcapArtifactSha256"] = sha256;
                metadata["pcapArtifactSha256"] = sha256;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            metadata["pcapSourceArtifactHashSkipped"] = ex.GetType().Name;
        }

        return metadata;
    }

    private static string ComputeFileSha256(string fullPath)
    {
        using var stream = File.OpenRead(fullPath);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static int CountSidecarArtifacts(string pcapPath)
    {
        return EnumerateSidecarPaths(pcapPath).Count();
    }

    private static IEnumerable<string> EnumerateSidecarPaths(string pcapPath)
    {
        var directory = Path.GetDirectoryName(pcapPath);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            yield break;
        }

        var baseName = Path.GetFileNameWithoutExtension(pcapPath);
        foreach (var candidate in Directory.EnumerateFiles(directory)
            .Where(path => !string.Equals(path, pcapPath, StringComparison.OrdinalIgnoreCase))
            .Where(NetworkSidecarEventImporter.IsLikelyNetworkSidecarPath)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            var candidateBase = Path.GetFileNameWithoutExtension(candidate);
            if (candidateBase.StartsWith(baseName, StringComparison.OrdinalIgnoreCase) ||
                candidateBase.Contains(".dns", StringComparison.OrdinalIgnoreCase) ||
                candidateBase.Contains(".http", StringComparison.OrdinalIgnoreCase) ||
                candidateBase.Contains(".tls", StringComparison.OrdinalIgnoreCase) ||
                candidateBase.Contains(".conn", StringComparison.OrdinalIgnoreCase) ||
                candidateBase.Contains(".flow", StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(candidate).Contains("tshark", StringComparison.OrdinalIgnoreCase))
            {
                yield return candidate;
            }
        }
    }

    private static bool IsTsharkAvailable()
    {
        var executableNames = OperatingSystem.IsWindows()
            ? new[] { "tshark.exe", "tshark.cmd", "tshark.bat" }
            : ["tshark"];
        var pathValue = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var directory in pathValue.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var executableName in executableNames)
            {
                try
                {
                    if (File.Exists(Path.Combine(directory, executableName)))
                    {
                        return true;
                    }
                }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
                {
                    // Ignore malformed PATH entries; native parser remains the fallback.
                }
            }
        }

        return false;
    }

    private sealed record PcapPacket(int Index, uint LinkType, DateTimeOffset Timestamp, byte[] Data);

    private sealed record DnsInfo(
        string QueryName,
        string QueryType,
        string RCode,
        bool IsResponse,
        string Answers,
        string AnswerCount,
        string Ttl);

    private sealed record HttpInfo(
        string MessageType,
        string Method,
        string Uri,
        string Host,
        string UserAgent,
        string ContentType,
        string StatusCode,
        string RequestBytes,
        string ResponseBytes,
        string ContentLength,
        string PayloadMagic);

    private sealed record TlsInfo(
        string Sni,
        string Version,
        string HandshakeType,
        string Ja3,
        string Ja3s,
        string Alpn,
        string CipherSuite,
        string ExtensionTypes,
        string CertSubject,
        string CertIssuer,
        string CertSerial,
        string CertSha256,
        string CertNotBefore,
        string CertNotAfter,
        string CertSelfSigned,
        string CertificateStatus);

    private sealed record DecodedPacket(
        DateTimeOffset Timestamp,
        string SourceIp,
        string DestinationIp,
        int SourcePort,
        int DestinationPort,
        string TransportProtocol,
        byte[] Payload)
    {
        public string IpFamily => SourceIp.Contains(':', StringComparison.Ordinal) ||
            DestinationIp.Contains(':', StringComparison.Ordinal)
                ? "ipv6"
                : "ipv4";

        public string FlowKey => $"{TransportProtocol}|{NetworkTelemetrySchema.Endpoint(SourceIp, SourcePort)}|{NetworkTelemetrySchema.Endpoint(DestinationIp, DestinationPort)}";

        public Dictionary<string, string> BaseData(
            Dictionary<string, string>? extra = null,
            string eventKind = "packet",
            NetworkArtifactSource? source = null)
        {
            var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ipFamily"] = IpFamily,
                ["payloadBytes"] = Payload.Length.ToString()
            };
            if (extra is not null)
            {
                foreach (var pair in extra)
                {
                    merged[pair.Key] = pair.Value;
                }
            }

            return NetworkTelemetrySchema.CreateEndpointData(
                TransportProtocol,
                SourceIp,
                SourcePort,
                DestinationIp,
                DestinationPort,
                eventKind,
                "pcap-native",
                source,
                merged);
        }
    }

    private sealed class FlowSummary
    {
        public FlowSummary(DecodedPacket packet)
        {
            Protocol = packet.TransportProtocol;
            SourceIp = packet.SourceIp;
            SourcePort = packet.SourcePort;
            DestinationIp = packet.DestinationIp;
            DestinationPort = packet.DestinationPort;
            FirstSeenUtc = packet.Timestamp;
            IpFamily = packet.IpFamily;
        }

        public string Protocol { get; }

        public string IpFamily { get; }

        public string SourceIp { get; }

        public int SourcePort { get; }

        public string DestinationIp { get; }

        public int DestinationPort { get; }

        public DateTimeOffset FirstSeenUtc { get; private set; }

        public DateTimeOffset LastSeenUtc { get; private set; }

        public int PacketCount { get; private set; }

        public long PayloadBytes { get; private set; }

        public void Observe(DecodedPacket packet)
        {
            if (PacketCount == 0 || packet.Timestamp < FirstSeenUtc)
            {
                FirstSeenUtc = packet.Timestamp;
            }

            if (PacketCount == 0 || packet.Timestamp > LastSeenUtc)
            {
                LastSeenUtc = packet.Timestamp;
            }

            PacketCount++;
            PayloadBytes += packet.Payload.Length;
        }

        public SandboxEvent ToEvent(string path, string eventType, NetworkArtifactSource source)
        {
            var data = NetworkTelemetrySchema.CreateEndpointData(
                Protocol,
                SourceIp,
                SourcePort,
                DestinationIp,
                DestinationPort,
                "connection",
                "pcap-native",
                source,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ipFamily"] = IpFamily,
                    ["packetCount"] = PacketCount.ToString(CultureInfo.InvariantCulture),
                    ["byteCount"] = PayloadBytes.ToString(CultureInfo.InvariantCulture),
                    ["payloadBytes"] = PayloadBytes.ToString(CultureInfo.InvariantCulture),
                    ["payloadByteCount"] = PayloadBytes.ToString(CultureInfo.InvariantCulture),
                    ["firstSeenUtc"] = FirstSeenUtc.ToString("O"),
                    ["lastSeenUtc"] = LastSeenUtc.ToString("O")
                });
            return new SandboxEvent
            {
                EventType = eventType,
                Timestamp = FirstSeenUtc,
                Source = "host",
                Path = path,
                Data = data
            };
        }
    }
}
