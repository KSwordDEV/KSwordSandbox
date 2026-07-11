using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Network;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that packet-capture artifacts are no longer only downloadable files:
/// host import can parse bounded PCAP rows into normalized pcap.* events, merge
/// them into report.json, and trigger behavior rules.
/// </summary>
internal sealed class PcapArtifactImportScenario : ISmokeTestScenario
{
    public string ScenarioId => "pcap.artifact.import.contract";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await AssertDirectPcapImportAsync(context, cancellationToken);
        await AssertJobImportPcapMergeAsync(context, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "PCAP artifacts parse into pcap.summary/flow/dns/http/tls events and merge into report import."
        };
    }

    private static async Task AssertDirectPcapImportAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var root = Path.Combine(context.RuntimeRoot, "pcap-import-direct", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var pcapPath = Path.Combine(root, "sample.pcap");
        await File.WriteAllBytesAsync(pcapPath, BuildSyntheticPcap(), cancellationToken);

        var events = new PcapArtifactEventImporter().Import(pcapPath);
        var summary = RequireEvent(events, "pcap.summary");
        RequireEvent(events, "pcap.flow");
        var dns = RequireEvent(events, "pcap.dns");
        var http = RequireEvent(events, "pcap.http");
        var tls = RequireEvent(events, "pcap.tls");

        SmokeAssert.True(summary.Data.TryGetValue("protocols", out var protocols) && protocols.Contains("dns", StringComparison.OrdinalIgnoreCase) && protocols.Contains("http", StringComparison.OrdinalIgnoreCase) && protocols.Contains("tls", StringComparison.OrdinalIgnoreCase), "pcap.summary should expose protocol rollup metadata.");
        RequireData(dns, "queryName", "beacon.example.test");
        RequireData(dns, "queryType", "A");
        RequireData(http, "method", "GET");
        RequireData(http, "host", "download.example.test");
        RequireData(http, "payloadMagic", "MZ");
        RequireData(tls, "sni", "secure.example.test");
    }

    private static async Task AssertJobImportPcapMergeAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "pcap-import-job", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var samplePath = Path.Combine(runtimeRoot, "sample.exe");
        await File.WriteAllTextAsync(samplePath, "pcap import sample", cancellationToken);

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json"));
        var service = new SandboxJobService(
            new SandboxConfig
            {
                Analysis = new AnalysisConfig
                {
                    DefaultDurationSeconds = 5,
                    MaxDurationSeconds = 60,
                    MaxSampleBytes = 1024 * 1024
                },
                Paths = new SandboxPaths
                {
                    RuntimeRoot = runtimeRoot,
                    RulesDirectory = context.RulesDirectory,
                    GuestPayloadRoot = Path.Combine(runtimeRoot, "payload")
                }
            },
            rules);

        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = true
        });
        var reportPath = job.JsonReportPath ?? throw new InvalidOperationException("job report path missing");
        var jobRoot = Path.GetDirectoryName(reportPath) ?? throw new InvalidOperationException("job root missing");
        var guestRoot = Path.Combine(jobRoot, "guest", job.JobId.ToString("N"));
        var packetRoot = Path.Combine(guestRoot, "packet-captures");
        Directory.CreateDirectory(packetRoot);

        var eventsPath = Path.Combine(guestRoot, "events.json");
        await File.WriteAllTextAsync(
            eventsPath,
            JsonSerializer.Serialize(new[]
            {
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "guest",
                    ProcessName = "sample.exe",
                    ProcessId = 4242,
                    Path = samplePath
                }
            }),
            cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(packetRoot, "sample.pcap"), BuildSyntheticPcap(), cancellationToken);

        var imported = service.ImportGuestEvents(job.JobId, eventsPath);
        var importedReportPath = imported.JsonReportPath ?? throw new InvalidOperationException("imported report missing");
        var report = JsonSerializer.Deserialize<AnalysisReport>(await File.ReadAllTextAsync(importedReportPath, cancellationToken), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("report should deserialize");

        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.summary", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.summary.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.flow", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.flow.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.dns", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.dns.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.http", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.http.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.tls", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.tls.");
        var importedPcapSummary = report.Events.First(evt => string.Equals(evt.EventType, "pcap.summary", StringComparison.OrdinalIgnoreCase));
        foreach (var importedPcapEvent in report.Events.Where(evt => evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase)))
        {
            SmokeAssert.True(importedPcapEvent.Data.TryGetValue("collectionName", out var eventCollection) && eventCollection == "packet-captures", $"{importedPcapEvent.EventType} should carry packet-captures collection context.");
            SmokeAssert.True(importedPcapEvent.Data.TryGetValue("importMode", out var eventImportMode) && eventImportMode == "external-artifact", $"{importedPcapEvent.EventType} should carry external artifact import mode.");
            SmokeAssert.True(importedPcapEvent.Data.TryGetValue("sourceArtifactRelativePath", out var eventRelativePath) && eventRelativePath == "packet-captures/sample.pcap", $"{importedPcapEvent.EventType} should carry source artifact relative path.");
            SmokeAssert.True(importedPcapEvent.Data.TryGetValue("sourceArtifactSha256", out var eventSha256) && eventSha256.Length == 64, $"{importedPcapEvent.EventType} should carry source artifact SHA-256.");
        }

        SmokeAssert.True(importedPcapSummary.Data.TryGetValue("collectionName", out var pcapCollection) && pcapCollection == "packet-captures", "Imported PCAP events should carry packet-captures collection context.");
        SmokeAssert.True(importedPcapSummary.Data.TryGetValue("importMode", out var pcapImportMode) && pcapImportMode == "external-artifact", "Imported PCAP events should carry external artifact import mode.");
        SmokeAssert.True(importedPcapSummary.Data.TryGetValue("sourceArtifactRelativePath", out var pcapRelativePath) && pcapRelativePath == "packet-captures/sample.pcap", "Imported PCAP events should carry source artifact relative path.");
        SmokeAssert.True(importedPcapSummary.Data.TryGetValue("sourceArtifactSizeBytes", out var pcapSize) && long.Parse(pcapSize) > 0, "Imported PCAP events should carry source artifact size.");
        SmokeAssert.True(importedPcapSummary.Data.TryGetValue("sourceArtifactSha256", out var pcapSha256) && pcapSha256.Length == 64, "Imported PCAP events should carry source artifact SHA-256.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-http-request-observed"), "PCAP HTTP rule should match imported pcap.http rows.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-dns-query-observed"), "PCAP DNS rule should match imported pcap.dns rows.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-tls-clienthello-observed"), "PCAP TLS rule should match imported pcap.tls rows.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-protocol-summary-placeholder"), "PCAP protocol summary rule should match imported pcap.summary protocol rollups.");
    }

    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Expected {eventType}.");
        return evt!;
    }

    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(evt.Data.TryGetValue(key, out var actual) && string.Equals(actual, expected, StringComparison.Ordinal), $"{evt.EventType} should include {key}={expected}; actual={actual ?? "<missing>"}.");
    }

    private static byte[] BuildSyntheticPcap()
    {
        using var stream = new MemoryStream();
        WriteUInt32Le(stream, 0xA1B2C3D4); // bytes d4 c3 b2 a1: little-endian classic PCAP
        WriteUInt16Le(stream, 2);
        WriteUInt16Le(stream, 4);
        WriteUInt32Le(stream, 0);
        WriteUInt32Le(stream, 0);
        WriteUInt32Le(stream, 65535);
        WriteUInt32Le(stream, 1); // Ethernet

        WritePacket(stream, 1, BuildUdpFrame("10.0.0.4", "8.8.8.8", 53000, 53, BuildDnsQuery("beacon.example.test")));
        WritePacket(stream, 2, BuildTcpFrame("10.0.0.4", "198.51.100.20", 50000, 80, Encoding.ASCII.GetBytes("GET /payload.exe HTTP/1.1\r\nHost: download.example.test\r\nUser-Agent: KSwordSmoke\r\nContent-Type: application/x-msdownload\r\n\r\nMZ")));
        WritePacket(stream, 3, BuildTcpFrame("10.0.0.4", "203.0.113.10", 50001, 443, BuildTlsClientHello("secure.example.test")));
        return stream.ToArray();
    }

    private static void WritePacket(Stream stream, uint seconds, byte[] packet)
    {
        WriteUInt32Le(stream, seconds);
        WriteUInt32Le(stream, 0);
        WriteUInt32Le(stream, (uint)packet.Length);
        WriteUInt32Le(stream, (uint)packet.Length);
        stream.Write(packet);
    }

    private static byte[] BuildUdpFrame(string sourceIp, string destinationIp, ushort sourcePort, ushort destinationPort, byte[] payload)
    {
        var udpLength = 8 + payload.Length;
        var packet = BuildIpv4EthernetFrame(sourceIp, destinationIp, 17, udpLength);
        var offset = 14 + 20;
        WriteUInt16Be(packet, offset, sourcePort);
        WriteUInt16Be(packet, offset + 2, destinationPort);
        WriteUInt16Be(packet, offset + 4, (ushort)udpLength);
        payload.CopyTo(packet, offset + 8);
        return packet;
    }

    private static byte[] BuildTcpFrame(string sourceIp, string destinationIp, ushort sourcePort, ushort destinationPort, byte[] payload)
    {
        var tcpLength = 20 + payload.Length;
        var packet = BuildIpv4EthernetFrame(sourceIp, destinationIp, 6, tcpLength);
        var offset = 14 + 20;
        WriteUInt16Be(packet, offset, sourcePort);
        WriteUInt16Be(packet, offset + 2, destinationPort);
        packet[offset + 12] = 0x50;
        packet[offset + 13] = 0x18;
        payload.CopyTo(packet, offset + 20);
        return packet;
    }

    private static byte[] BuildIpv4EthernetFrame(string sourceIp, string destinationIp, byte protocol, int transportLength)
    {
        var packet = new byte[14 + 20 + transportLength];
        packet[12] = 0x08;
        packet[13] = 0x00;
        var ip = 14;
        packet[ip] = 0x45;
        packet[ip + 1] = 0;
        WriteUInt16Be(packet, ip + 2, (ushort)(20 + transportLength));
        packet[ip + 8] = 64;
        packet[ip + 9] = protocol;
        IPAddress.Parse(sourceIp).GetAddressBytes().CopyTo(packet, ip + 12);
        IPAddress.Parse(destinationIp).GetAddressBytes().CopyTo(packet, ip + 16);
        return packet;
    }

    private static byte[] BuildDnsQuery(string name)
    {
        using var stream = new MemoryStream();
        WriteUInt16Be(stream, 0x1234);
        WriteUInt16Be(stream, 0x0100);
        WriteUInt16Be(stream, 1);
        WriteUInt16Be(stream, 0);
        WriteUInt16Be(stream, 0);
        WriteUInt16Be(stream, 0);
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        WriteUInt16Be(stream, 1);
        WriteUInt16Be(stream, 1);
        return stream.ToArray();
    }

    private static byte[] BuildTlsClientHello(string sni)
    {
        var host = Encoding.ASCII.GetBytes(sni);
        using var ext = new MemoryStream();
        WriteUInt16Be(ext, 0); // SNI
        WriteUInt16Be(ext, (ushort)(5 + host.Length));
        WriteUInt16Be(ext, (ushort)(3 + host.Length));
        ext.WriteByte(0);
        WriteUInt16Be(ext, (ushort)host.Length);
        ext.Write(host);
        var extensions = ext.ToArray();

        using var body = new MemoryStream();
        WriteUInt16Be(body, 0x0303);
        body.Write(new byte[32]);
        body.WriteByte(0);
        WriteUInt16Be(body, 2);
        WriteUInt16Be(body, 0x002f);
        body.WriteByte(1);
        body.WriteByte(0);
        WriteUInt16Be(body, (ushort)extensions.Length);
        body.Write(extensions);
        var helloBody = body.ToArray();

        using var handshake = new MemoryStream();
        handshake.WriteByte(1);
        WriteUInt24Be(handshake, helloBody.Length);
        handshake.Write(helloBody);
        var handshakeBytes = handshake.ToArray();

        using var record = new MemoryStream();
        record.WriteByte(0x16);
        WriteUInt16Be(record, 0x0301);
        WriteUInt16Be(record, (ushort)handshakeBytes.Length);
        record.Write(handshakeBytes);
        return record.ToArray();
    }

    private static void WriteUInt16Le(Stream stream, ushort value)
    {
        Span<byte> buffer = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteUInt32Le(Stream stream, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteUInt16Be(Stream stream, int value)
    {
        Span<byte> buffer = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)value);
        stream.Write(buffer);
    }

    private static void WriteUInt24Be(Stream stream, int value)
    {
        stream.WriteByte((byte)((value >> 16) & 0xff));
        stream.WriteByte((byte)((value >> 8) & 0xff));
        stream.WriteByte((byte)(value & 0xff));
    }

    private static void WriteUInt16Be(byte[] buffer, int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset, 2), value);
    }
}
