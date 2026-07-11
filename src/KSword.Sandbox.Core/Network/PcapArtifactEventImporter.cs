using System.Buffers.Binary;
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
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var packets = ReadPackets(stream, path).Take(MaxPackets).ToList();
            return BuildEvents(path, packets);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            return
            [
                new SandboxEvent
                {
                    EventType = "pcap.parse_error",
                    Source = "host",
                    Path = path,
                    Data =
                    {
                        ["exceptionType"] = ex.GetType().Name,
                        ["message"] = ex.Message
                    }
                }
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

    private static IReadOnlyList<SandboxEvent> BuildEvents(string path, IReadOnlyList<PcapPacket> packets)
    {
        var events = new List<SandboxEvent>();
        var flows = new Dictionary<string, FlowSummary>(StringComparer.OrdinalIgnoreCase);
        var protocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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

            foreach (var protocolEvent in BuildProtocolEvents(path, decoded))
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

        events.Insert(0, new SandboxEvent
        {
            EventType = "pcap.summary",
            Source = "host",
            Path = path,
            Data =
            {
                ["packetCount"] = packets.Count.ToString(),
                ["parsedPacketCount"] = parsedPackets.ToString(),
                ["flowCount"] = flows.Count.ToString(),
                ["byteCount"] = bytes.ToString(),
                ["protocol"] = string.Join(",", protocols.OrderBy(protocol => protocol, StringComparer.OrdinalIgnoreCase)),
                ["protocols"] = string.Join(",", protocols.OrderBy(protocol => protocol, StringComparer.OrdinalIgnoreCase)),
                ["format"] = Path.GetExtension(path).Equals(".pcapng", StringComparison.OrdinalIgnoreCase) ? "pcapng" : "pcap"
            }
        });

        foreach (var flow in flows.Values.OrderBy(flow => flow.FirstSeenUtc).Take(MaxFlowEvents))
        {
            events.Add(flow.ToEvent(path));
        }

        return events;
    }

    private static IEnumerable<SandboxEvent> BuildProtocolEvents(string path, DecodedPacket packet)
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
                        ["queryType"] = dns.QueryType,
                        ["rcode"] = dns.RCode,
                        ["isResponse"] = dns.IsResponse.ToString(),
                        ["classification"] = dns.RCode.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) ? "nxdomain" : string.Empty
                    })
                };
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
                        ["host"] = http.Host,
                        ["userAgent"] = http.UserAgent,
                        ["contentType"] = http.ContentType,
                        ["payloadMagic"] = http.PayloadMagic
                    })
                };
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
                        ["tlsVersion"] = tls.Version,
                        ["handshakeType"] = tls.HandshakeType,
                        ["ja3"] = string.Empty
                    })
                };
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

        if (etherType != 0x0800 || frame.Length < offset + 20)
        {
            return null;
        }

        var ip = frame[offset..];
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

        var transport = ip.Slice(ihl, availableLength - ihl);
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
                packet.Timestamp,
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
                packet.Timestamp,
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
        public string FlowKey => $"{TransportProtocol}|{SourceIp}:{SourcePort}|{DestinationIp}:{DestinationPort}";

        public Dictionary<string, string> BaseData(Dictionary<string, string>? extra = null)
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["protocol"] = TransportProtocol,
                ["sourceIp"] = SourceIp,
                ["sourcePort"] = SourcePort.ToString(),
                ["destinationIp"] = DestinationIp,
                ["destinationPort"] = DestinationPort.ToString(),
                ["payloadBytes"] = Payload.Length.ToString()
            };
            if (extra is not null)
            {
                foreach (var pair in extra)
                {
                    data[pair.Key] = pair.Value;
                }
            }

            return data;
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
        }

        public string Protocol { get; }

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

        public SandboxEvent ToEvent(string path)
        {
            return new SandboxEvent
            {
                EventType = "pcap.flow",
                Timestamp = FirstSeenUtc,
                Source = "host",
                Path = path,
                Data =
                {
                    ["protocol"] = Protocol,
                    ["sourceIp"] = SourceIp,
                    ["sourcePort"] = SourcePort.ToString(),
                    ["destinationIp"] = DestinationIp,
                    ["destinationPort"] = DestinationPort.ToString(),
                    ["packetCount"] = PacketCount.ToString(),
                    ["payloadBytes"] = PayloadBytes.ToString(),
                    ["firstSeenUtc"] = FirstSeenUtc.ToString("O"),
                    ["lastSeenUtc"] = LastSeenUtc.ToString("O")
                }
            };
        }
    }
}
