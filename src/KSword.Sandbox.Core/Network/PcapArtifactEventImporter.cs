using System.Buffers.Binary;
using System.Globalization;
using System.Net;
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
            var parseError = new SandboxEvent
            {
                EventType = "pcap.parse_error",
                Source = "host",
                Path = path,
                Data =
                {
                    ["schema"] = NetworkTelemetrySchema.SchemaVersion,
                    ["eventFamily"] = "network",
                    ["eventKind"] = "parse_error",
                    ["exceptionType"] = ex.GetType().Name,
                    ["message"] = ex.Message,
                    ["parser"] = "native-pcap"
                }
            };
            NetworkTelemetrySchema.AddArtifactData(parseError.Data, source);
            NetworkTelemetrySchema.ApplyHealthAndLocalization(parseError.Data);
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
                        ["exceptionType"] = ex.GetType().Name
                    }),
                parseError
            ];
        }
    }

    private static IEnumerable<PcapPacket> ReadPackets(Stream stream, string path)
    {
        var magic = new byte[4];
        if (stream.Read(magic) != 4)
        {
            yield break;
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
        if (!ReadExactly(stream, header))
        {
            yield break;
        }

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
        while (ReadExactly(stream, packetHeader))
        {
            var tsSec = ReadUInt32(packetHeader.AsSpan(0, 4), bigEndian);
            var tsFrac = ReadUInt32(packetHeader.AsSpan(4, 4), bigEndian);
            var includedLength = ReadUInt32(packetHeader.AsSpan(8, 4), bigEndian);
            if (includedLength > 16 * 1024 * 1024)
            {
                throw new InvalidDataException("PCAP packet length is unreasonably large.");
            }

            var payload = new byte[includedLength];
            if (!ReadExactly(stream, payload))
            {
                yield break;
            }

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
            if (!ReadExactly(stream, blockHeader))
            {
                yield break;
            }

            var blockType = BinaryPrimitives.ReadUInt32LittleEndian(blockHeader.AsSpan(0, 4));
            var blockLength = BinaryPrimitives.ReadUInt32LittleEndian(blockHeader.AsSpan(4, 4));
            if (blockLength < 12 || blockLength > 64 * 1024 * 1024)
            {
                throw new InvalidDataException($"Unsupported PCAPNG block length in {path}.");
            }

            var bodyLength = checked((int)blockLength - 12);
            var body = new byte[bodyLength];
            if (!ReadExactly(stream, body))
            {
                yield break;
            }

            var trailer = new byte[4];
            if (!ReadExactly(stream, trailer))
            {
                yield break;
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
                    continue;
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
        if (packet.TransportProtocol == "UDP" && (packet.SourcePort == 53 || packet.DestinationPort == 53))
        {
            var dns = TryParseDns(packet.Payload.AsSpan());
            if (dns is not null)
            {
                yield return new SandboxEvent
                {
                    EventType = "pcap.dns",
                    Timestamp = packet.Timestamp,
                    Source = "host",
                    Path = path,
                    Data = packet.BaseData(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["queryName"] = dns.QueryName,
                        ["qname"] = dns.QueryName,
                        ["domain"] = dns.QueryName,
                        ["queryType"] = dns.QueryType,
                        ["recordType"] = dns.QueryType,
                        ["rcode"] = dns.RCode,
                        ["isResponse"] = dns.IsResponse.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                        ["classification"] = dns.RCode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ? "nxdomain" : string.Empty
                    }, "dns", source)
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
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["queryName"] = dns.QueryName,
                        ["qname"] = dns.QueryName,
                        ["domain"] = dns.QueryName,
                        ["queryType"] = dns.QueryType,
                        ["recordType"] = dns.QueryType,
                        ["rcode"] = dns.RCode,
                        ["isResponse"] = dns.IsResponse.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                        ["classification"] = dns.RCode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ? "nxdomain" : string.Empty
                    });
            }
        }

        if (packet.TransportProtocol == "TCP" && packet.Payload.Length > 0)
        {
            var http = TryParseHttp(packet.Payload.AsSpan());
            if (http is not null)
            {
                yield return new SandboxEvent
                {
                    EventType = "pcap.http",
                    Timestamp = packet.Timestamp,
                    Source = "host",
                    Path = path,
                    Data = packet.BaseData(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["method"] = http.Method,
                        ["uri"] = http.Uri,
                        ["requestUri"] = http.Uri,
                        ["host"] = http.Host,
                        ["url"] = string.IsNullOrWhiteSpace(http.Host) ? http.Uri : $"http://{http.Host}{http.Uri}",
                        ["userAgent"] = http.UserAgent,
                        ["contentType"] = http.ContentType,
                        ["payloadMagic"] = http.PayloadMagic
                    }, "http", source)
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
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["method"] = http.Method,
                        ["uri"] = http.Uri,
                        ["requestUri"] = http.Uri,
                        ["host"] = http.Host,
                        ["url"] = string.IsNullOrWhiteSpace(http.Host) ? http.Uri : $"http://{http.Host}{http.Uri}",
                        ["userAgent"] = http.UserAgent,
                        ["contentType"] = http.ContentType,
                        ["payloadMagic"] = http.PayloadMagic
                    });
            }

            var tls = TryParseTlsClientHello(packet.Payload.AsSpan());
            if (tls is not null)
            {
                yield return new SandboxEvent
                {
                    EventType = "pcap.tls",
                    Timestamp = packet.Timestamp,
                    Source = "host",
                    Path = path,
                    Data = packet.BaseData(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["sni"] = tls.Sni,
                        ["serverName"] = tls.Sni,
                        ["tlsVersion"] = tls.Version,
                        ["handshakeType"] = tls.HandshakeType,
                        ["ja3"] = string.Empty
                    }, "tls", source)
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
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["sni"] = tls.Sni,
                        ["serverName"] = tls.Sni,
                        ["tlsVersion"] = tls.Version,
                        ["handshakeType"] = tls.HandshakeType,
                        ["ja3"] = string.Empty
                    });
            }
        }
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
        if (payload.Length < 12)
        {
            return null;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        if (questionCount == 0)
        {
            return null;
        }

        var offset = 12;
        var labels = new List<string>();
        for (var guard = 0; guard < 128 && offset < payload.Length; guard++)
        {
            var length = payload[offset++];
            if (length == 0)
            {
                break;
            }

            if ((length & 0xC0) != 0 || length > 63 || offset + length > payload.Length)
            {
                return null;
            }

            labels.Add(Encoding.ASCII.GetString(payload.Slice(offset, length)));
            offset += length;
        }

        if (labels.Count == 0 || offset + 4 > payload.Length)
        {
            return null;
        }

        var qtype = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        var rcode = flags & 0x000F;
        return new DnsInfo(string.Join('.', labels), DnsTypeName(qtype), DnsRCodeName(rcode), (flags & 0x8000) != 0);
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
        if (parts.Length < 2 || !IsHttpMethod(parts[0]))
        {
            return null;
        }

        var headers = ParseHeaders(text[(firstLineEnd + 2)..]);
        var payloadMagic = text.Contains("MZ", StringComparison.Ordinal) ? "MZ" : string.Empty;
        return new HttpInfo(
            parts[0],
            parts[1],
            headers.GetValueOrDefault("host", string.Empty),
            headers.GetValueOrDefault("user-agent", string.Empty),
            headers.GetValueOrDefault("content-type", string.Empty),
            payloadMagic);
    }

    private static TlsInfo? TryParseTlsClientHello(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 9 || payload[0] != 0x16 || payload[5] != 0x01)
        {
            return null;
        }

        var recordVersion = $"0x{payload[1]:X2}{payload[2]:X2}";
        var offset = 5 + 4;
        if (payload.Length < offset + 34)
        {
            return new TlsInfo(string.Empty, recordVersion, "client_hello");
        }

        offset += 2; // client version
        offset += 32; // random
        if (offset >= payload.Length)
        {
            return new TlsInfo(string.Empty, recordVersion, "client_hello");
        }

        var sessionIdLength = payload[offset++];
        offset += sessionIdLength;
        if (offset + 2 > payload.Length)
        {
            return new TlsInfo(string.Empty, recordVersion, "client_hello");
        }

        var cipherLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        offset += 2 + cipherLength;
        if (offset >= payload.Length)
        {
            return new TlsInfo(string.Empty, recordVersion, "client_hello");
        }

        var compressionLength = payload[offset++];
        offset += compressionLength;
        if (offset + 2 > payload.Length)
        {
            return new TlsInfo(string.Empty, recordVersion, "client_hello");
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
        offset += 2;
        var extensionsEnd = Math.Min(payload.Length, offset + extensionsLength);
        while (offset + 4 <= extensionsEnd)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
            var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset + 2, 2));
            offset += 4;
            if (offset + extensionLength > extensionsEnd)
            {
                break;
            }

            if (type == 0 && extensionLength >= 5)
            {
                var ext = payload.Slice(offset, extensionLength);
                var nameLength = BinaryPrimitives.ReadUInt16BigEndian(ext.Slice(3, 2));
                if (5 + nameLength <= ext.Length)
                {
                    return new TlsInfo(Encoding.ASCII.GetString(ext.Slice(5, nameLength)), recordVersion, "client_hello");
                }
            }

            offset += extensionLength;
        }

        return new TlsInfo(string.Empty, recordVersion, "client_hello");
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

    private static bool ReadExactly(Stream stream, Span<byte> buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer[total..]);
            if (read == 0)
            {
                return false;
            }

            total += read;
        }

        return true;
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
            3 => "NXDOMAIN",
            _ => rcode.ToString()
        };
    }

    private static IEnumerable<SandboxEvent> ImportSidecarEvents(string pcapPath, NetworkArtifactSource pcapSource)
    {
        var sidecarImporter = new NetworkSidecarEventImporter();
        foreach (var sidecarPath in EnumerateSidecarPaths(pcapPath))
        {
            var sidecarSource = NetworkArtifactSource.FromPath(
                sidecarPath,
                pcapSource.ImportRoot,
                artifactKind: "Log",
                collectionName: "network-sidecars",
                evidenceRole: "network-telemetry-sidecar",
                importMode: "sidecar-artifact");
            foreach (var evt in sidecarImporter.ImportEvents(sidecarPath, sidecarSource))
            {
                yield return evt;
            }
        }
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

    private sealed record DnsInfo(string QueryName, string QueryType, string RCode, bool IsResponse);

    private sealed record HttpInfo(string Method, string Uri, string Host, string UserAgent, string ContentType, string PayloadMagic);

    private sealed record TlsInfo(string Sni, string Version, string HandshakeType);

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
