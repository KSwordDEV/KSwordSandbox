using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Protects report-event slimming from dropping high-value static, probe
/// health, and R0 backpressure evidence. Inputs are synthetic events only;
/// processing samples a noisy event stream; the scenario returns pass/fail
/// metadata without rendering HTML or starting Hyper-V.
/// </summary>
internal sealed class ReportEventSamplerPriorityContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.event-sampler-priority.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var timestamp = new DateTimeOffset(2026, 7, 11, 8, 0, 0, TimeSpan.Zero);
        var events = new List<SandboxEvent>();
        for (var index = 0; index < 160; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = "registry.value.noise",
                Timestamp = timestamp.AddMilliseconds(index),
                Source = "driver",
                Path = $@"HKCU\Software\Noise\{index:D4}",
                Data =
                {
                    ["valueName"] = $"noise-{index:D4}",
                    ["unimportant"] = new string('x', 64)
                }
            });
        }

        events.Add(new SandboxEvent
        {
            EventType = "static.pe.import.module",
            Timestamp = timestamp.AddSeconds(1),
            Source = "host",
            Path = @"D:\Temp\sample.exe",
            Data =
            {
                ["moduleName"] = "wininet.dll",
                ["apiCount"] = "7",
                ["tags"] = "import_network_api,import_download_api",
                ["zhMessage"] = "静态导入网络相关 API。"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "static.pe.resource",
            Timestamp = timestamp.AddSeconds(1.1),
            Source = "host",
            Path = @"D:\Temp\sample.exe",
            Data =
            {
                ["resourceType"] = "RCDATA",
                ["resourceRole"] = "embedded-pe",
                ["isEmbeddedPe"] = "True",
                ["isPayloadCandidate"] = "True",
                ["entropy"] = "7.900",
                ["size"] = "8192",
                ["tags"] = "resource_high_entropy_data,resource_embedded_pe",
                ["zhHint"] = "资源内嵌 PE。"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "http.request",
            Timestamp = timestamp.AddSeconds(1.5),
            Source = "host",
            Data =
            {
                ["protocol"] = "tcp",
                ["collectionName"] = "network-sidecars",
                ["evidenceRole"] = "network-telemetry-sidecar",
                ["importMode"] = "sidecar-artifact",
                ["sourceArtifactRelativePath"] = "packet-captures/sample.conn.jsonl",
                ["sourceArtifactSha256"] = new string('a', 64),
                ["sourceArtifactSizeBytes"] = "512",
                ["sourceIp"] = "10.0.0.4",
                ["sourcePort"] = "50244",
                ["destinationIp"] = "198.51.100.88",
                ["destinationPort"] = "8080",
                ["flowKey"] = "tcp|10.0.0.4:50244|198.51.100.88:8080",
                ["method"] = "POST",
                ["host"] = "api.example.test",
                ["uri"] = "/checkin",
                ["userAgent"] = "KSwordSmoke",
                ["contentType"] = "application/json",
                ["payloadMagic"] = "MZ"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "artifact.host_imported",
            Timestamp = timestamp.AddSeconds(1.7),
            Source = "host",
            Data =
            {
                ["artifactKind"] = "DroppedFile",
                ["downloadSelector"] = "artifacts/drop.bin",
                ["downloadSafeLink"] = "artifacts/drop.bin",
                ["safeRelativeSelector"] = "artifacts/drop.bin",
                ["importPath"] = "artifacts/drop.bin",
                ["isDuplicate"] = "true",
                ["duplicateGroupKey"] = "sha256:abc",
                ["duplicateGroupCount"] = "2",
                ["duplicatePrimarySelector"] = "artifacts/primary.bin",
                ["artifactRejectionReasons"] = "unsafeGuestArtifactPath",
                ["lastRejectedArtifactSelector"] = "../unsafe.bin"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Timestamp = timestamp.AddSeconds(1.8),
            Source = "virustotal",
            Data =
            {
                ["vtStatus"] = "found",
                ["vtVerdict"] = "malicious",
                ["vtMalicious"] = "4",
                ["vtSuspicious"] = "1",
                ["vtEngineCount"] = "72",
                ["vtReputation"] = "-10",
                ["vtCommunityScore"] = "-2",
                ["communityScoreSource"] = "reputation",
                ["lastAnalysisDateUtc"] = "2026-07-10T00:00:00.0000000Z",
                ["permalink"] = "https://www.virustotal.com/gui/file/" + new string('b', 64)
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "probe.summary",
            Timestamp = timestamp.AddSeconds(2),
            Source = "guest",
            Data =
            {
                ["probeId"] = "packet-capture",
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true",
                ["status"] = "completed",
                ["zhHint"] = "采集通道健康摘要。"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "r0collector.driverStatus",
            Timestamp = timestamp.AddSeconds(3),
            Source = "r0collector",
            Data =
            {
                ["lostCount"] = "3",
                ["highWatermark"] = "96",
                ["lastEnqueueFailureStatusHex"] = "0xC000009A",
                ["sequence"] = "2048",
                ["sequenceMeaning"] = "last driver health sequence"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "r0collector.driverNetworkStatus",
            Timestamp = timestamp.AddSeconds(4),
            Source = "r0collector",
            Data =
            {
                ["networkStatusAvailable"] = "true",
                ["readinessState"] = "available",
                ["supportedLayerMaskHex"] = "0x0000000F",
                ["activeLayerMaskHex"] = "0x00000007",
                ["lastRegisteredCalloutMaskHex"] = "0x00000007",
                ["lastAddedFilterMaskHex"] = "0x00000007",
                ["todoMaskHex"] = "0x00000008",
                ["classifyCount"] = "12",
                ["eventCount"] = "6",
                ["queueFailureCount"] = "0",
                ["classifyPayloadFailureCount"] = "0",
                ["lastDegradeReasonName"] = "wfpAleConnectTodo",
                ["zhHint"] = "WFP/ALE 网络状态。"
            }
        });

        var result = ReportEventSampler.SampleForReport(
            events,
            new ReportEventSamplingOptions
            {
                MaxInlineEvents = 32,
                MaxEventsPerType = 5,
                MaxHighValueEventsPerType = 16,
                MaxEventDataPairs = 16
            });

        SmokeAssert.True(result.WasSampled, "Noisy input should be sampled.");
        SmokeAssert.True(result.Events.Any(evt => string.Equals(evt.EventType, "report.events.sampled", StringComparison.OrdinalIgnoreCase)), "Sampling marker should be present.");

        var staticEvent = RequireEvent(result.Events, "static.pe.import.module");
        RequireData(staticEvent, "moduleName", "wininet.dll");
        RequireData(staticEvent, "apiCount", "7");
        RequireData(staticEvent, "zhMessage", "静态导入网络相关 API。");

        var resourceEvent = RequireEvent(result.Events, "static.pe.resource");
        RequireData(resourceEvent, "resourceRole", "embedded-pe");
        RequireData(resourceEvent, "isEmbeddedPe", "True");
        RequireData(resourceEvent, "entropy", "7.900");
        RequireData(resourceEvent, "size", "8192");

        var networkEvent = RequireEvent(result.Events, "http.request");
        RequireData(networkEvent, "protocol", "tcp");
        RequireData(networkEvent, "collectionName", "network-sidecars");
        RequireData(networkEvent, "evidenceRole", "network-telemetry-sidecar");
        RequireData(networkEvent, "sourceArtifactRelativePath", "packet-captures/sample.conn.jsonl");
        RequireData(networkEvent, "sourceArtifactSha256", new string('a', 64));
        RequireData(networkEvent, "sourceIp", "10.0.0.4");
        RequireData(networkEvent, "destinationIp", "198.51.100.88");
        RequireData(networkEvent, "flowKey", "tcp|10.0.0.4:50244|198.51.100.88:8080");
        RequireData(networkEvent, "method", "POST");
        RequireData(networkEvent, "host", "api.example.test");
        RequireData(networkEvent, "uri", "/checkin");

        var artifactEvent = RequireEvent(result.Events, "artifact.host_imported");
        RequireData(artifactEvent, "downloadSelector", "artifacts/drop.bin");
        RequireData(artifactEvent, "downloadSafeLink", "artifacts/drop.bin");
        RequireData(artifactEvent, "isDuplicate", "true");
        RequireData(artifactEvent, "duplicateGroupCount", "2");
        RequireData(artifactEvent, "lastRejectedArtifactSelector", "../unsafe.bin");

        var vtEvent = RequireEvent(result.Events, "enrichment.virustotal.lookup");
        RequireData(vtEvent, "vtVerdict", "malicious");
        RequireData(vtEvent, "vtReputation", "-10");
        RequireData(vtEvent, "vtCommunityScore", "-2");
        RequireData(vtEvent, "permalink", "https://www.virustotal.com/gui/file/" + new string('b', 64));

        var probeEvent = RequireEvent(result.Events, "probe.summary");
        RequireData(probeEvent, "collectionHealth", "true");
        RequireData(probeEvent, "nonbehavior", "true");
        RequireData(probeEvent, "zhHint", "采集通道健康摘要。");

        var r0Event = RequireEvent(result.Events, "r0collector.driverStatus");
        RequireData(r0Event, "lostCount", "3");
        RequireData(r0Event, "highWatermark", "96");
        RequireData(r0Event, "lastEnqueueFailureStatusHex", "0xC000009A");
        RequireData(r0Event, "sequence", "2048");

        var r0NetworkStatusEvent = RequireEvent(result.Events, "r0collector.driverNetworkStatus");
        RequireData(r0NetworkStatusEvent, "networkStatusAvailable", "true");
        RequireData(r0NetworkStatusEvent, "activeLayerMaskHex", "0x00000007");
        RequireData(r0NetworkStatusEvent, "todoMaskHex", "0x00000008");
        RequireData(r0NetworkStatusEvent, "classifyCount", "12");
        RequireData(r0NetworkStatusEvent, "lastDegradeReasonName", "wfpAleConnectTodo");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Report sampler preserves static/network/probe/R0 priority evidence while slimming noisy rows."
        });
    }

    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Sampled events should retain {eventType}.");
        return evt!;
    }

    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(evt.Data.TryGetValue(key, out var actual), $"{evt.EventType} should retain Data[{key}].");
        SmokeAssert.True(string.Equals(actual, expected, StringComparison.Ordinal), $"{evt.EventType} Data[{key}] should be '{expected}', got '{actual}'.");
    }
}
