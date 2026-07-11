using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
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
        await AssertSidecarOnlyNetworkImportAsync(context, cancellationToken);
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
        await File.WriteAllLinesAsync(
            Path.Combine(root, "sample.dns-http-tls.jsonl"),
            BuildSyntheticSidecarJsonLines(),
            cancellationToken);
        await File.WriteAllLinesAsync(
            Path.Combine(root, "sample.conn.log"),
            BuildSyntheticSidecarLogLines(),
            cancellationToken);

        var events = new PcapArtifactEventImporter().Import(pcapPath);
        var importSummary = RequireEvent(events, "network.import.summary");
        var summary = RequireEvent(events, "pcap.summary");
        RequireEvent(events, "pcap.flow");
        var nativeFlow = RequireEvent(events, "network.flow", "importSource", "pcap-native");
        var dns = RequireEvent(events, "pcap.dns");
        var http = RequireEvent(events, "pcap.http");
        var httpResponse = RequireEvent(events, "pcap.http", "statusCode", "200");
        var tls = RequireEvent(events, "pcap.tls");
        var tlsCertificate = RequireEvent(events, "pcap.tls", "handshakeType", "certificate");
        var dnsQuery = RequireEvent(events, "dns.query", "importSource", "pcap-native");
        var httpRequest = RequireEvent(events, "http.request", "importSource", "pcap-native");
        var httpResponseEvent = RequireEvent(events, "http.request", "statusCode", "200");
        var tlsConnection = RequireEvent(events, "tls.connection", "importSource", "pcap-native");
        var tlsCertificateEvent = RequireEvent(events, "tls.connection", "handshakeType", "certificate");

        RequireData(importSummary, "schema", "network.telemetry.v1");
        RequireData(importSummary, "tsharkRequired", "false");
        RequireData(importSummary, "sidecarArtifactCount", "2");
        RequireData(importSummary, "parseErrorCount", "1");
        RequireData(importSummary, "collectionHealth", "degraded");
        RequireNonEmpty(importSummary, "zhMessage");
        RequireNonEmpty(importSummary, "zhHint");
        SmokeAssert.True(summary.Data.TryGetValue("protocols", out var protocols) && protocols.Contains("dns", StringComparison.OrdinalIgnoreCase) && protocols.Contains("http", StringComparison.OrdinalIgnoreCase) && protocols.Contains("tls", StringComparison.OrdinalIgnoreCase), "pcap.summary should expose protocol rollup metadata.");
        RequireNonEmpty(summary, "zhMessage");
        RequireData(summary, "sourceArtifactSelector", "sample.pcap");
        RequireData(summary, "pcapDownloadSelector", "sample.pcap");
        RequireData(summary, "pcapParser", "native-pcap");
        RequireData(summary, "pcapParserMode", "bounded-native");
        RequireNonEmpty(summary, "pcapSourceDiagnostic");
        RequireData(summary, "parentArtifactRelativePath", "sample.pcap");
        RequireData(summary, "parentArtifactKind", "PacketCapture");
        RequireNonEmpty(summary, "pcapSourceArtifactSha256");
        RequireNonEmpty(summary, "parentArtifactSha256");
        RequireData(dns, "schema", "network.telemetry.v1");
        RequireData(dns, "eventKind", "dns");
        RequireData(dns, "transportProtocol", "udp");
        RequireData(dns, "flowKey", "udp|10.0.0.4:53000|8.8.8.8:53");
        RequireData(dns, "queryName", "beacon.example.test");
        RequireData(dns, "queryType", "A");
        RequireData(dns, "dnsQueryName", "beacon.example.test");
        RequireData(dns, "query", "beacon.example.test");
        RequireData(dns, "dns.qry.name", "beacon.example.test");
        RequireData(dns, "rcodeName", "NOERROR");
        RequireData(dns, "dns.flags.rcode", "NOERROR");
        RequireData(dns, "pcapSourceArtifactRelativePath", "sample.pcap");
        RequireData(dns, "sourcePcapArtifactRelativePath", "sample.pcap");
        RequireNonEmpty(dns, "sourcePcapArtifactSha256");
        RequireData(http, "method", "GET");
        RequireData(http, "requestMethod", "GET");
        RequireData(http, "http.request.method", "GET");
        RequireData(http, "host", "download.example.test");
        RequireData(http, "http.host", "download.example.test");
        RequireData(http, "url.host", "download.example.test");
        RequireData(http, "http.request.uri", "/payload.exe");
        RequireData(http, "http.user_agent", "KSwordSmoke");
        RequireData(http, "payloadMagic", "MZ");
        RequireData(http, "httpMessageType", "request");
        RequireData(http, "requestBodyBytes", "2");
        RequireData(http, "bodySizeBytes", "2");
        RequireData(http, "downloadSelector", "sample.pcap");
        RequireData(http, "pcapSourceArtifactRelativePath", "sample.pcap");
        RequireData(httpResponse, "httpMessageType", "response");
        RequireData(httpResponse, "responseStatusCode", "200");
        RequireData(httpResponse, "http.response.status_code", "200");
        RequireData(httpResponse, "response.status_code", "200");
        RequireData(httpResponse, "sc-status", "200");
        RequireData(httpResponse, "statusFamily", "2xx");
        RequireData(httpResponse, "responseBodyBytes", "2");
        RequireData(httpResponse, "bodySizeBytes", "2");
        RequireData(httpResponse, "contentLength", "2");
        RequireData(tls, "sni", "secure.example.test");
        RequireData(tls, "tlsSni", "secure.example.test");
        RequireData(tls, "tls.server_name", "secure.example.test");
        RequireData(tls, "tls.sni", "secure.example.test");
        RequireData(tls, "ssl.server_name", "secure.example.test");
        RequireData(tls, "tlsVersion", "TLS 1.2");
        RequireNonEmpty(tls, "ja3");
        RequireNonEmpty(tls, "ja3Hash");
        RequireNonEmpty(tls, "ja3Fingerprint");
        RequireNonEmpty(tls, "ja3.hash");
        RequireNonEmpty(tls, "tls.ja3.hash");
        RequireData(tls, "pcapSourceArtifactRelativePath", "sample.pcap");
        RequireData(tlsCertificate, "certificateStatus", "self-signed");
        RequireData(tlsCertificate, "validationStatus", "self-signed");
        RequireData(tlsCertificate, "certSelfSigned", "true");
        RequireData(tlsCertificate, "tlsCertificateRisk", "suspicious");
        RequireNonEmpty(tlsCertificate, "certSubject");
        RequireNonEmpty(tlsCertificate, "certificateSubject");
        RequireNonEmpty(tlsCertificate, "certSha256");
        RequireNonEmpty(tlsCertificate, "certificateFingerprintSha256");
        RequireNonEmpty(tlsCertificate, "serverCertificateSha256");
        RequireNonEmpty(tlsCertificate, "tls.cert.sha256");
        AssertStandardNetworkEvent(dnsQuery, "dns", "pcap-native", "dns");
        RequireData(dnsQuery, "queryName", "beacon.example.test");
        RequireData(dnsQuery, "qname", "beacon.example.test");
        RequireData(dnsQuery, "domain", "beacon.example.test");
        RequireData(dnsQuery, "query", "beacon.example.test");
        RequireData(dnsQuery, "recordType", "A");
        RequireData(dnsQuery, "qtype", "A");
        RequireData(dnsQuery, "serviceHint", "dns");
        AssertStandardNetworkEvent(httpRequest, "http", "pcap-native", "http");
        RequireData(httpRequest, "method", "GET");
        RequireData(httpRequest, "requestMethod", "GET");
        RequireData(httpRequest, "requestUri", "/payload.exe");
        RequireData(httpRequest, "url", "http://download.example.test/payload.exe");
        RequireData(httpRequest, "contentType", "application/x-msdownload");
        RequireData(httpRequest, "httpMessageType", "request");
        RequireData(httpResponseEvent, "statusCode", "200");
        RequireData(httpResponseEvent, "httpStatusCode", "200");
        RequireData(httpResponseEvent, "http.response.status_code", "200");
        RequireData(httpResponseEvent, "responseBodyBytes", "2");
        AssertStandardNetworkEvent(tlsConnection, "tls", "pcap-native", "tls");
        RequireData(tlsConnection, "sni", "secure.example.test");
        RequireData(tlsConnection, "serverName", "secure.example.test");
        RequireData(tlsConnection, "tlsSni", "secure.example.test");
        RequireData(tlsConnection, "handshakeType", "client_hello");
        RequireData(tlsConnection, "tlsVersion", "TLS 1.2");
        RequireNonEmpty(tlsConnection, "ja3");
        RequireNonEmpty(tlsConnection, "ja3Fingerprint");
        RequireData(tlsCertificateEvent, "certificateStatus", "self-signed");
        RequireNonEmpty(tlsCertificateEvent, "certificateSha256");
        AssertStandardNetworkEvent(nativeFlow, "connection", "pcap-native", "dns");
        RequireData(nativeFlow, "packetCount", "1");
        RequireNonEmpty(nativeFlow, "payloadBytes");
        RequireNonEmpty(nativeFlow, "byteCount");
        RequireNonEmpty(nativeFlow, "firstSeenUtc");
        RequireNonEmpty(nativeFlow, "lastSeenUtc");
        var sidecarDns = RequireEvent(events, "dns.query", "queryName", "sidecar.example.test");
        RequireData(sidecarDns, "answers", "2001:db8::44");
        RequireData(sidecarDns, "dns.answers.data", "2001:db8::44");
        RequireData(sidecarDns, "answerAddress", "2001:db8::44");
        RequireData(sidecarDns, "answersNormalized", "2001:db8::44");
        SmokeAssert.True(events.Any(evt => string.Equals(evt.EventType, "http.request", StringComparison.OrdinalIgnoreCase) && evt.Data.TryGetValue("host", out var sidecarHost) && sidecarHost == "api.example.test"), "Sidecar JSONL HTTP rows should import as http.request.");
        SmokeAssert.True(events.Any(evt => string.Equals(evt.EventType, "tls.connection", StringComparison.OrdinalIgnoreCase) && evt.Data.TryGetValue("sni", out var sidecarSni) && sidecarSni == "sidecar-secure.example.test"), "Sidecar JSONL TLS rows should import as tls.connection.");
        var sidecarLogFlow = RequireEvent(events, "network.flow", "uid", "loose-flow-1");
        RequireData(sidecarLogFlow, "sidecarFormat", "log");
        RequireData(sidecarLogFlow, "sourceIp", "10.0.0.4");
        RequireData(sidecarLogFlow, "destinationIp", "198.51.100.77");
        RequireData(sidecarLogFlow, "destinationPort", "8080");
        RequireData(sidecarLogFlow, "state", "ESTABLISHED");
        RequireData(sidecarLogFlow, "durationSeconds", "1.25");
        RequireData(sidecarLogFlow, "byteCount", "512");
        RequireData(sidecarLogFlow, "collectionHealth", "ok");
        RequireData(sidecarLogFlow, "pcapSourceArtifactRelativePath", "sample.pcap");
        RequireData(sidecarLogFlow, "sourcePcapArtifactRelativePath", "sample.pcap");
        RequireData(sidecarLogFlow, "pcapDownloadSelector", "sample.pcap");
        RequireData(sidecarLogFlow, "sourceArtifactRelativePath", "sample.conn.log");
        RequireData(sidecarLogFlow, "parentArtifactRelativePath", "sample.pcap");
        RequireData(sidecarLogFlow, "parentArtifactKind", "PacketCapture");
        RequireNonEmpty(sidecarLogFlow, "sourceArtifactSha256");
        RequireNonEmpty(sidecarLogFlow, "pcapSourceArtifactSha256");
        RequireNonEmpty(sidecarLogFlow, "sourcePcapArtifactSha256");
        RequireNonEmpty(sidecarLogFlow, "zhMessage");
        RequireNonEmpty(sidecarLogFlow, "zhHint");
        var sidecarParseError = RequireEvent(events, "network.sidecar.parse_error");
        RequireData(sidecarParseError, "collectionHealth", "degraded");
        RequireData(sidecarParseError, "sidecarLineNumber", "3");
        RequireData(sidecarParseError, "sidecarFormat", "jsonl");
        RequireData(sidecarParseError, "diagnosticCode", "sidecar_json_parse_error");
        RequireData(sidecarParseError, "parserBoundary", "sidecar.line");
        RequireData(sidecarParseError, "diagnosticStage", "json-line");
        RequireData(sidecarParseError, "sourceArtifactSelector", "sample.conn.log");
        RequireData(sidecarParseError, "downloadSelector", "sample.conn.log");
        RequireNonEmpty(sidecarParseError, "linePreview");
        RequireNonEmpty(sidecarParseError, "pcapSourceArtifactSha256");
        RequireNonEmpty(sidecarParseError, "zhMessage");
        RequireNonEmpty(sidecarParseError, "zhHint");
        await AssertMalformedPcapBoundaryDiagnosticsAsync(root, cancellationToken);
        await AssertGuestManifestNetworkImportAsync(root, cancellationToken);
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
        await File.WriteAllLinesAsync(
            Path.Combine(packetRoot, "sample.conn.jsonl"),
            [
                JsonSerializer.Serialize(new
                {
                    eventType = "network.connection",
                    timestamp = "2026-07-11T00:00:04Z",
                    data = new
                    {
                        sourceIp = "10.0.0.4",
                        sourcePort = "50244",
                        destinationIp = "198.51.100.88",
                        destinationPort = "8080",
                        protocol = "tcp",
                        uid = "job-sidecar-flow-1",
                        processId = "4242",
                        processName = "sample.exe",
                        commandLine = "sample.exe --sidecar-network"
                    }
                })
            ],
            cancellationToken);

        var directNetworkEvents = new NetworkArtifactEventImporter().ImportGuestArtifacts(guestRoot, includeCanonicalDriverJsonl: false);
        var directSidecarFlow = RequireEvent(directNetworkEvents, "network.flow", "uid", "job-sidecar-flow-1");
        RequireData(directSidecarFlow, "sourceArtifactRelativePath", "packet-captures/sample.conn.jsonl");
        RequireData(directSidecarFlow, "pcapSourceArtifactRelativePath", "packet-captures/sample.pcap");
        RequireData(directSidecarFlow, "pcapDownloadSelector", "packet-captures/sample.pcap");
        RequireNonEmpty(directSidecarFlow, "sourcePcapArtifactSha256");

        var imported = service.ImportGuestEvents(job.JobId, eventsPath);
        var importedReportPath = imported.JsonReportPath ?? throw new InvalidOperationException("imported report missing");
        var report = JsonSerializer.Deserialize<AnalysisReport>(await File.ReadAllTextAsync(importedReportPath, cancellationToken), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("report should deserialize");

        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.summary", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.summary.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "network.import.summary", StringComparison.OrdinalIgnoreCase)), "Imported report should include network.import.summary.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.flow", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.flow.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "network.flow", StringComparison.OrdinalIgnoreCase)), "Imported report should include standardized network.flow.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.dns", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.dns.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.http", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.http.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "pcap.tls", StringComparison.OrdinalIgnoreCase)), "Imported report should include pcap.tls.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "dns.query", StringComparison.OrdinalIgnoreCase)), "Imported report should include standardized dns.query.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "http.request", StringComparison.OrdinalIgnoreCase)), "Imported report should include standardized http.request.");
        SmokeAssert.True(report.Events.Any(evt => string.Equals(evt.EventType, "tls.connection", StringComparison.OrdinalIgnoreCase)), "Imported report should include standardized tls.connection.");
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
        var sidecarFlows = report.Events
            .Where(evt =>
                string.Equals(evt.EventType, "network.flow", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.TryGetValue("uid", out var uid) &&
                uid == "job-sidecar-flow-1")
            .ToList();
        SmokeAssert.True(sidecarFlows.Count == 1, "Job-level network sidecar import should emit exactly one normalized flow without PCAP sidecar duplication.");
        var sidecarFlow = sidecarFlows[0];
        SmokeAssert.True(sidecarFlow.ProcessId == 4242, "Sidecar processId should be promoted to SandboxEvent.ProcessId.");
        SmokeAssert.True(string.Equals(sidecarFlow.ProcessName, "sample.exe", StringComparison.OrdinalIgnoreCase), "Sidecar processName should be promoted to SandboxEvent.ProcessName.");
        SmokeAssert.True(string.Equals(sidecarFlow.CommandLine, "sample.exe --sidecar-network", StringComparison.Ordinal), "Sidecar commandLine should be promoted to SandboxEvent.CommandLine.");
        SmokeAssert.True(sidecarFlow.Data.TryGetValue("collectionName", out var sidecarCollection) && sidecarCollection == "network-sidecars", "Sidecar network events should preserve network-sidecars collection context.");
        SmokeAssert.True(sidecarFlow.Data.TryGetValue("evidenceRole", out var sidecarRole) && sidecarRole == "network-telemetry-sidecar", "Sidecar network events should preserve sidecar evidence role.");
        SmokeAssert.True(sidecarFlow.Data.TryGetValue("sourceArtifactRelativePath", out var sidecarRelativePath) && sidecarRelativePath == "packet-captures/sample.conn.jsonl", "Sidecar network events should preserve sidecar source artifact relative path.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-http-request-observed"), "PCAP HTTP rule should match imported pcap.http rows.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-dns-query-observed"), "PCAP DNS rule should match imported pcap.dns rows.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-tls-clienthello-observed"), "PCAP TLS rule should match imported pcap.tls rows.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "pcap-protocol-summary-placeholder"), "PCAP protocol summary rule should match imported pcap.summary protocol rollups.");
    }

    private static async Task AssertSidecarOnlyNetworkImportAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var root = Path.Combine(context.RuntimeRoot, "network-sidecar-only", Guid.NewGuid().ToString("N"));
        var sidecarRoot = Path.Combine(root, "network-sidecars");
        Directory.CreateDirectory(sidecarRoot);
        var sidecarPath = Path.Combine(sidecarRoot, "events.jsonl");
        await File.WriteAllLinesAsync(
            sidecarPath,
            [
                JsonSerializer.Serialize(new
                {
                    event_type = "dns",
                    timestamp = "2026-07-11T00:00:00Z",
                    src_ip = "10.0.0.4",
                    src_port = "5353",
                    dest_ip = "8.8.8.8",
                    dest_port = "53",
                    proto = "UDP",
                    dns = new
                    {
                        rrname = "eve-sidecar.example.test",
                        rrtype = "A",
                        rcode = "3"
                    },
                    process = new
                    {
                        pid = 5150,
                        rootProcessId = 5150,
                        treeLineage = "5150:sidecar-sample.exe",
                        name = "sidecar-sample.exe",
                        command_line = "sidecar-sample.exe --dns"
                    }
                }),
                JsonSerializer.Serialize(new
                {
                    event_type = "http",
                    timestamp = "2026-07-11T00:00:01Z",
                    src_ip = "10.0.0.4",
                    src_port = "50244",
                    dest_ip = "198.51.100.90",
                    dest_port = "8080",
                    proto = "TCP",
                    http = new
                    {
                        method = "POST",
                        hostname = "api.sidecar-only.test",
                        url = "/stage",
                        user_agent = "SidecarOnlyUA",
                        content_type = "application/json",
                        requestBodyBytes = "1536",
                        responseBodyBytes = "256",
                        authorization = "Bearer redacted",
                        cookie = "sid=redacted",
                        response = new
                        {
                            status_code = "202"
                        }
                    }
                }),
                JsonSerializer.Serialize(new
                {
                    event_type = "tls",
                    timestamp = "2026-07-11T00:00:02Z",
                    src_ip = "10.0.0.4",
                    src_port = "50245",
                    dest_ip = "203.0.113.90",
                    dest_port = "443",
                    proto = "TCP",
                    tls = new
                    {
                        sni = "tls.sidecar-only.test",
                        version = "TLS 1.2",
                        ja3 = new
                        {
                            hash = "0123456789abcdef0123456789abcdef"
                        },
                        alpn = "h2",
                        cert = new
                        {
                            subject = "CN=tls.sidecar-only.test",
                            issuer = "CN=Untrusted Test CA",
                            fingerprint = new
                            {
                                sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            }
                        },
                        validationStatus = "self-signed"
                    }
                }),
                JsonSerializer.Serialize(new
                {
                    event_type = "flow",
                    timestamp = "2026-07-11T00:00:03Z",
                    src_ip = "10.0.0.4",
                    src_port = "50246",
                    dest_ip = "198.51.100.91",
                    dest_port = "4444",
                    proto = "TCP",
                    uid = "sidecar-only-flow-1",
                    state = "ESTABLISHED",
                    duration = "3.50",
                    bytes_toserver = "2048",
                    bytes_toclient = "1024",
                    pkts_toserver = "8",
                    pkts_toclient = "4",
                    community_id = "1:sidecar-community"
                })
            ],
            cancellationToken);

        var events = new NetworkArtifactEventImporter().ImportGuestArtifacts(root, includeCanonicalDriverJsonl: false);
        var summary = RequireEvent(events, "network.import.summary");
        RequireData(summary, "pcapArtifactCount", "0");
        RequireData(summary, "sidecarArtifactCount", "1");
        RequireData(summary, "dnsEventCount", "1");
        RequireData(summary, "httpEventCount", "1");
        RequireData(summary, "tlsEventCount", "1");
        RequireData(summary, "flowEventCount", "1");

        var dns = RequireEvent(events, "dns.query", "queryName", "eve-sidecar.example.test");
        RequireData(dns, "sourceIp", "10.0.0.4");
        RequireData(dns, "destinationIp", "8.8.8.8");
        RequireData(dns, "destinationPort", "53");
        RequireData(dns, "queryType", "A");
        RequireData(dns, "sourceArtifactRelativePath", "network-sidecars/events.jsonl");
        RequireData(dns, "sourceArtifactKind", ArtifactKind.Log.ToString());
        RequireData(dns, "collectionName", "network-sidecars");
        RequireData(dns, "evidenceRole", "network-telemetry-sidecar");
        RequireData(dns, "importMode", "sidecar-artifact");
        SmokeAssert.True(dns.ProcessId == 5150, "Sidecar-only DNS process.pid should be promoted to SandboxEvent.ProcessId.");
        SmokeAssert.True(string.Equals(dns.ProcessName, "sidecar-sample.exe", StringComparison.Ordinal), "Sidecar-only DNS process.name should be promoted to SandboxEvent.ProcessName.");
        SmokeAssert.True(string.Equals(dns.CommandLine, "sidecar-sample.exe --dns", StringComparison.Ordinal), "Sidecar-only DNS process.command_line should be promoted to SandboxEvent.CommandLine.");
        RequireData(dns, "rcode", "NXDOMAIN");
        RequireData(dns, "dns.flags.rcode", "NXDOMAIN");
        RequireData(dns, "dns.response_code", "NXDOMAIN");
        RequireData(dns, "query", "eve-sidecar.example.test");
        RequireData(dns, "dns.qry.name", "eve-sidecar.example.test");
        RequireData(dns, "qtype", "A");
        RequireData(dns, "classification", "nxdomain");
        RequireData(dns, "isNxDomain", "true");
        RequireData(dns, "rootProcessId", "5150");
        RequireData(dns, "treeLineage", "5150:sidecar-sample.exe");

        var http = RequireEvent(events, "http.request", "host", "api.sidecar-only.test");
        RequireData(http, "method", "POST");
        RequireData(http, "requestMethod", "POST");
        RequireData(http, "http.request.method", "POST");
        RequireData(http, "uri", "/stage");
        RequireData(http, "url.path", "/stage");
        RequireData(http, "http.request.uri", "/stage");
        RequireData(http, "url", "http://api.sidecar-only.test/stage");
        RequireData(http, "http.host", "api.sidecar-only.test");
        RequireData(http, "request.headers.host", "api.sidecar-only.test");
        RequireData(http, "destinationPort", "8080");
        RequireData(http, "userAgent", "SidecarOnlyUA");
        RequireData(http, "http.user_agent", "SidecarOnlyUA");
        RequireData(http, "http.request.headers.user-agent", "SidecarOnlyUA");
        RequireData(http, "contentType", "application/json");
        RequireData(http, "statusCode", "202");
        RequireData(http, "httpStatusCode", "202");
        RequireData(http, "http.response.status_code", "202");
        RequireData(http, "status_code", "202");
        RequireData(http, "response.status_code", "202");
        RequireData(http, "sc-status", "202");
        RequireData(http, "statusFamily", "2xx");
        RequireData(http, "uploadCandidate", "true");
        RequireData(http, "uploadBytes", "1536");
        RequireData(http, "requestBodySizeBytes", "1536");
        RequireData(http, "bodySizeBytes", "1536");
        RequireData(http, "responseBodyBytes", "256");
        RequireData(http, "httpResponseBodyBytes", "256");
        RequireData(http, "authorizationHeaderPresent", "true");
        RequireData(http, "cookiePresent", "true");

        var tls = RequireEvent(events, "tls.connection", "sni", "tls.sidecar-only.test");
        RequireData(tls, "destinationIp", "203.0.113.90");
        RequireData(tls, "destinationPort", "443");
        RequireData(tls, "tlsVersion", "TLS 1.2");
        RequireData(tls, "ja3", "0123456789abcdef0123456789abcdef");
        RequireData(tls, "ja3Hash", "0123456789abcdef0123456789abcdef");
        RequireData(tls, "ja3Fingerprint", "0123456789abcdef0123456789abcdef");
        RequireData(tls, "tlsSni", "tls.sidecar-only.test");
        RequireData(tls, "tls.sni", "tls.sidecar-only.test");
        RequireData(tls, "ssl.server_name", "tls.sidecar-only.test");
        RequireData(tls, "alpn", "h2");
        RequireData(tls, "certSubject", "CN=tls.sidecar-only.test");
        RequireData(tls, "certificateSubject", "CN=tls.sidecar-only.test");
        RequireData(tls, "certIssuer", "CN=Untrusted Test CA");
        RequireData(tls, "certSha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        RequireData(tls, "certificateFingerprintSha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        RequireData(tls, "serverCertificateSha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        RequireData(tls, "tls.cert.sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        RequireData(tls, "tlsCertificateRisk", "suspicious");

        var flow = RequireEvent(events, "network.flow", "uid", "sidecar-only-flow-1");
        RequireData(flow, "destinationIp", "198.51.100.91");
        RequireData(flow, "destinationPort", "4444");
        RequireData(flow, "state", "ESTABLISHED");
        RequireData(flow, "durationSeconds", "3.50");
        RequireData(flow, "byteCount", "3072");
        RequireData(flow, "packetCount", "12");
        RequireData(flow, "bytesToServer", "2048");
        RequireData(flow, "bytesToClient", "1024");
        RequireData(flow, "communityId", "1:sidecar-community");

        await AssertIpv6EndpointNormalizationAsync(root, cancellationToken);
    }

    private static async Task AssertIpv6EndpointNormalizationAsync(string parentRoot, CancellationToken cancellationToken)
    {
        var root = Path.Combine(parentRoot, "ipv6-sidecar", Guid.NewGuid().ToString("N"));
        var sidecarRoot = Path.Combine(root, "network-sidecars");
        Directory.CreateDirectory(sidecarRoot);
        await File.WriteAllLinesAsync(
            Path.Combine(sidecarRoot, "ipv6.jsonl"),
            [
                JsonSerializer.Serialize(new
                {
                    eventType = "network.connection",
                    timestamp = "2026-07-11T00:00:04Z",
                    sourceEndpoint = "[2001:db8::10]:5353",
                    destinationEndpoint = "[2606:4700:4700::1111]:53",
                    proto = "udp",
                    uid = "ipv6-flow-1",
                    rootProcessId = "5150",
                    treeLineage = "5150:sidecar-sample.exe>6161:child.exe"
                }),
                JsonSerializer.Serialize(new
                {
                    eventType = "network.connection",
                    timestamp = "2026-07-11T00:00:05Z",
                    sourceIp = "[2001:db8::20]:5354",
                    destinationIp = "[2606:4700:4700::8888]:853",
                    proto = "udp",
                    uid = "ipv6-ip-field-flow"
                })
            ],
            cancellationToken);

        var events = new NetworkArtifactEventImporter().ImportGuestArtifacts(root, includeCanonicalDriverJsonl: false);
        var flow = RequireEvent(events, "network.flow", "uid", "ipv6-flow-1");
        RequireData(flow, "ipFamily", "ipv6");
        RequireData(flow, "sourceIp", "2001:db8::10");
        RequireData(flow, "destinationIp", "2606:4700:4700::1111");
        RequireData(flow, "sourceEndpoint", "[2001:db8::10]:5353");
        RequireData(flow, "destinationEndpoint", "[2606:4700:4700::1111]:53");
        RequireData(flow, "flowKey", "udp|[2001:db8::10]:5353|[2606:4700:4700::1111]:53");
        RequireData(flow, "rootProcessId", "5150");
        RequireData(flow, "treeLineage", "5150:sidecar-sample.exe>6161:child.exe");

        var ipFieldFlow = RequireEvent(events, "network.flow", "uid", "ipv6-ip-field-flow");
        RequireData(ipFieldFlow, "ipFamily", "ipv6");
        RequireData(ipFieldFlow, "sourceIp", "2001:db8::20");
        RequireData(ipFieldFlow, "destinationIp", "2606:4700:4700::8888");
        RequireData(ipFieldFlow, "sourcePort", "5354");
        RequireData(ipFieldFlow, "destinationPort", "853");
        RequireData(ipFieldFlow, "sourceEndpoint", "[2001:db8::20]:5354");
        RequireData(ipFieldFlow, "destinationEndpoint", "[2606:4700:4700::8888]:853");
        RequireData(ipFieldFlow, "flowKey", "udp|[2001:db8::20]:5354|[2606:4700:4700::8888]:853");
    }

    private static async Task AssertMalformedPcapBoundaryDiagnosticsAsync(string parentRoot, CancellationToken cancellationToken)
    {
        var malformedPath = Path.Combine(parentRoot, "truncated-boundary.pcap");
        await File.WriteAllBytesAsync(malformedPath, BuildTruncatedPcap(), cancellationToken);

        var events = new PcapArtifactEventImporter().Import(malformedPath);
        var summary = RequireEvent(events, "network.import.summary");
        var parseError = RequireEvent(events, "pcap.parse_error");
        RequireData(summary, "status", "parse_error");
        RequireData(summary, "diagnosticCode", "pcap_boundary_truncated");
        RequireData(summary, "parserBoundary", "pcap.packet_payload");
        RequireData(summary, "parseFailureStage", "read-packet-payload");
        RequireNonEmpty(summary, "byteOffset");
        RequireNonEmpty(summary, "expectedBytes");
        RequireNonEmpty(summary, "actualBytes");
        RequireData(summary, "pcapParser", "native-pcap");
        RequireNonEmpty(summary, "pcapSourceDiagnostic");
        RequireData(parseError, "collectionHealth", "degraded");
        RequireData(parseError, "diagnosticCode", "pcap_boundary_truncated");
        RequireData(parseError, "parserBoundary", "pcap.packet_payload");
        RequireData(parseError, "parseFailureStage", "read-packet-payload");
        RequireData(parseError, "diagnosticStage", "read-packet-payload");
        RequireData(parseError, "sourceArtifactSelector", "truncated-boundary.pcap");
        RequireData(parseError, "downloadSelector", "truncated-boundary.pcap");
        RequireNonEmpty(parseError, "byteOffset");
        RequireNonEmpty(parseError, "expectedBytes");
        RequireNonEmpty(parseError, "actualBytes");
        RequireNonEmpty(parseError, "sourceArtifactSha256");
        RequireNonEmpty(parseError, "pcapSourceArtifactSha256");
        RequireNonEmpty(parseError, "zhMessage");
        RequireNonEmpty(parseError, "zhHint");
    }

    private static async Task AssertGuestManifestNetworkImportAsync(string parentRoot, CancellationToken cancellationToken)
    {
        var guestRoot = Path.Combine(parentRoot, "manifest-import");
        var packetRoot = Path.Combine(guestRoot, "packet-captures");
        Directory.CreateDirectory(packetRoot);
        var artifactsRoot = Path.Combine(guestRoot, "artifacts");
        Directory.CreateDirectory(artifactsRoot);
        var pcapPath = Path.Combine(packetRoot, "manifest.pcap");
        var sidecarPath = Path.Combine(packetRoot, "manifest.conn.jsonl");
        await File.WriteAllBytesAsync(pcapPath, BuildSyntheticPcap(), cancellationToken);
        await File.WriteAllLinesAsync(
            sidecarPath,
            [
                JsonSerializer.Serialize(new
                {
                    eventType = "network.connection",
                    timestamp = "2026-07-11T00:00:00Z",
                    data = new
                    {
                        sourceIp = "10.0.0.4",
                        sourcePort = "50044",
                        destinationIp = "203.0.113.44",
                        destinationPort = "4443",
                        protocol = "tcp",
                        uid = "sidecar-conn-1"
                    }
                })
            ],
            cancellationToken);
        var manifest = new ArtifactManifest
        {
            Producer = "KSword.Sandbox.Agent",
            RuntimeRoot = guestRoot,
            RootPath = artifactsRoot,
            ImportRoot = guestRoot,
            Collections =
            [
                new ArtifactCollectionDescriptor
                {
                    Name = "packet-captures",
                    Kind = ArtifactKind.PacketCapture,
                    Category = "packet-capture",
                    EvidenceRole = "packet-capture",
                    RelativePath = "packet-captures",
                    ImportPath = "packet-captures",
                    Enabled = true,
                    Implemented = true,
                    Status = "captured",
                    Metadata =
                    {
                        ["captureSource"] = "external",
                        ["importMode"] = "external-artifact"
                    }
                },
                new ArtifactCollectionDescriptor
                {
                    Name = "network-sidecars",
                    Kind = ArtifactKind.Log,
                    Category = "telemetry",
                    EvidenceRole = "network-telemetry-sidecar",
                    RelativePath = "packet-captures",
                    ImportPath = "packet-captures",
                    Enabled = true,
                    Implemented = true,
                    Status = "captured",
                    Metadata =
                    {
                        ["telemetryDomain"] = "network"
                    }
                }
            ],
            Artifacts =
            [
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.PacketCapture,
                    Category = "packet-capture",
                    Name = "manifest.pcap",
                    RelativePath = "packet-captures/manifest.pcap",
                    ImportPath = "packet-captures/manifest.pcap",
                    EvidenceRole = "packet-capture",
                    CollectionName = "packet-captures"
                },
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.Log,
                    Category = "telemetry",
                    Name = "manifest.conn.jsonl",
                    RelativePath = "packet-captures/manifest.conn.jsonl",
                    ImportPath = "packet-captures/manifest.conn.jsonl",
                    EvidenceRole = "network-telemetry-sidecar",
                    CollectionName = "network-sidecars",
                    Metadata =
                    {
                        ["telemetryDomain"] = "network"
                    }
                }
            ]
        };
        await File.WriteAllTextAsync(
            Path.Combine(artifactsRoot, "manifest.json"),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }),
            cancellationToken);

        var events = new NetworkArtifactEventImporter().ImportGuestArtifacts(guestRoot);
        var summary = RequireEvent(events, "network.import.summary");
        RequireData(summary, "manifestPresent", "true");
        RequireData(summary, "pcapArtifactCount", "1");
        RequireData(summary, "sidecarArtifactCount", "1");
        SmokeAssert.True(events.Any(evt => string.Equals(evt.EventType, "pcap.dns", StringComparison.OrdinalIgnoreCase)), "Manifest PCAP should import pcap.dns.");
        SmokeAssert.True(events.Any(evt => string.Equals(evt.EventType, "network.flow", StringComparison.OrdinalIgnoreCase) && evt.Data.TryGetValue("uid", out var uid) && uid == "sidecar-conn-1"), "Manifest sidecar JSONL should import connection rows as network.flow.");
    }

    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Expected {eventType}.");
        return evt!;
    }

    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType, string dataKey, string expectedDataValue)
    {
        var evt = events.FirstOrDefault(candidate =>
            string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase) &&
            candidate.Data.TryGetValue(dataKey, out var actual) &&
            string.Equals(actual, expectedDataValue, StringComparison.Ordinal));
        SmokeAssert.True(evt is not null, $"Expected {eventType} with {dataKey}={expectedDataValue}.");
        return evt!;
    }

    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(evt.Data.TryGetValue(key, out var actual) && string.Equals(actual, expected, StringComparison.Ordinal), $"{evt.EventType} should include {key}={expected}; actual={actual ?? "<missing>"}.");
    }

    private static void RequireNonEmpty(SandboxEvent evt, string key)
    {
        SmokeAssert.True(evt.Data.TryGetValue(key, out var actual) && !string.IsNullOrWhiteSpace(actual), $"{evt.EventType} should include non-empty {key}.");
    }

    private static void AssertStandardNetworkEvent(SandboxEvent evt, string eventKind, string importSource, string serviceHint)
    {
        RequireData(evt, "schema", "network.telemetry.v1");
        RequireData(evt, "eventFamily", "network");
        RequireData(evt, "eventKind", eventKind);
        RequireData(evt, "importSource", importSource);
        RequireData(evt, "serviceHint", serviceHint);
        RequireData(evt, "collectionHealth", "ok");
        RequireNonEmpty(evt, "sourceIp");
        RequireNonEmpty(evt, "sourcePort");
        RequireNonEmpty(evt, "destinationIp");
        RequireNonEmpty(evt, "destinationPort");
        RequireNonEmpty(evt, "sourceEndpoint");
        RequireNonEmpty(evt, "destinationEndpoint");
        RequireNonEmpty(evt, "flowKey");
        RequireNonEmpty(evt, "collectionName");
        RequireNonEmpty(evt, "evidenceRole");
        RequireNonEmpty(evt, "sourceArtifactRelativePath");
        RequireNonEmpty(evt, "sourceArtifactSha256");
        RequireNonEmpty(evt, "zhMessage");
        RequireNonEmpty(evt, "zhHint");
    }

    private static string[] BuildSyntheticSidecarJsonLines()
    {
        return
        [
            JsonSerializer.Serialize(new
            {
                eventType = "dns.query",
                timestamp = "2026-07-11T00:00:00Z",
                data = new
                {
                    sourceIp = "10.0.0.4",
                    sourcePort = "5353",
                    destinationIp = "8.8.4.4",
                    destinationPort = "53",
                    protocol = "udp",
                    queryName = "sidecar.example.test",
                    queryType = "AAAA",
                    rcode = "NOERROR",
                    answers = new[] { "2001:db8::44" }
                }
            }),
            JsonSerializer.Serialize(new
            {
                _source = new
                {
                    layers = new
                    {
                        ip = new Dictionary<string, string>
                        {
                            ["ip.src"] = "10.0.0.4",
                            ["ip.dst"] = "198.51.100.30"
                        },
                        tcp = new Dictionary<string, string>
                        {
                            ["tcp.srcport"] = "50100",
                            ["tcp.dstport"] = "80"
                        },
                        http = new Dictionary<string, string>
                        {
                            ["http.request.method"] = "POST",
                            ["http.host"] = "api.example.test",
                            ["http.request.uri"] = "/checkin",
                            ["http.user_agent"] = "SidecarUA"
                        }
                    }
                }
            }),
            JsonSerializer.Serialize(new
            {
                eventType = "tls",
                timestamp = "2026-07-11T00:00:02Z",
                data = new
                {
                    sourceIp = "10.0.0.4",
                    sourcePort = "50101",
                    destinationIp = "203.0.113.30",
                    destinationPort = "443",
                    protocol = "tcp",
                    sni = "sidecar-secure.example.test",
                    tlsVersion = "0x0303",
                    ja3 = "sidecar-ja3"
                }
            })
        ];
    }

    private static string[] BuildSyntheticSidecarLogLines()
    {
        return
        [
            "2026-07-11T00:00:03Z flow proto=tcp 10.0.0.4:50200 -> 198.51.100.77:8080 state=ESTABLISHED uid=loose-flow-1 duration=1.25 bytes=512 packets=4",
            "plain status line without network fields should be ignored",
            "{not-json"
        ];
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
        WritePacket(stream, 3, BuildTcpFrame("198.51.100.20", "10.0.0.4", 80, 50000, Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/x-msdownload\r\nContent-Length: 2\r\n\r\nMZ")));
        WritePacket(stream, 4, BuildTcpFrame("10.0.0.4", "203.0.113.10", 50001, 443, BuildTlsClientHello("secure.example.test")));
        WritePacket(stream, 5, BuildTcpFrame("203.0.113.10", "10.0.0.4", 443, 50001, BuildTlsCertificate(BuildSelfSignedCertificateDer())));
        return stream.ToArray();
    }

    private static byte[] BuildTruncatedPcap()
    {
        using var stream = new MemoryStream();
        WriteUInt32Le(stream, 0xA1B2C3D4);
        WriteUInt16Le(stream, 2);
        WriteUInt16Le(stream, 4);
        WriteUInt32Le(stream, 0);
        WriteUInt32Le(stream, 0);
        WriteUInt32Le(stream, 65535);
        WriteUInt32Le(stream, 1);
        WriteUInt32Le(stream, 1);
        WriteUInt32Le(stream, 0);
        WriteUInt32Le(stream, 64);
        WriteUInt32Le(stream, 64);
        stream.Write([0x00, 0x01, 0x02, 0x03]);
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

    private static byte[] BuildTlsCertificate(byte[] certificateDer)
    {
        using var certificateList = new MemoryStream();
        WriteUInt24Be(certificateList, certificateDer.Length + 3);
        WriteUInt24Be(certificateList, certificateDer.Length);
        certificateList.Write(certificateDer);
        var body = certificateList.ToArray();

        using var handshake = new MemoryStream();
        handshake.WriteByte(11);
        WriteUInt24Be(handshake, body.Length);
        handshake.Write(body);
        var handshakeBytes = handshake.ToArray();

        using var record = new MemoryStream();
        record.WriteByte(0x16);
        WriteUInt16Be(record, 0x0303);
        WriteUInt16Be(record, (ushort)handshakeBytes.Length);
        record.Write(handshakeBytes);
        return record.ToArray();
    }

    private static byte[] BuildSelfSignedCertificateDer()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=secure.example.test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(7));
        return certificate.RawData;
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
