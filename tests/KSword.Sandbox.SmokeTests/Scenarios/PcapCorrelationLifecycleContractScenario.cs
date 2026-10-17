using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies ownerless PCAP protocol rows remain unattributed until a runtime
/// ETW/R0 source independently joins the sample process and target. Static
/// IOC strings and lifecycle overlap alone are retained as raw evidence but
/// never enter the primary behavior lane.
/// </summary>
internal sealed class PcapCorrelationLifecycleContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.pcap-lifecycle-static-ioc";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var start = DateTimeOffset.UtcNow;
        var inWindow = start.AddSeconds(1);
        var outsideWindow = start.AddMinutes(1);

        var classified = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "guest",
                    Timestamp = start,
                    ProcessName = "sample.exe",
                    ProcessId = 100,
                    Path = SamplePath,
                    CommandLine = SamplePath,
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = SamplePath
                    }
                },
                new SandboxEvent
                {
                    EventType = "process.tree.summary",
                    Source = "guest",
                    Timestamp = start.AddSeconds(5),
                    ProcessId = 100,
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["rootProcessId"] = "100",
                        ["rootImagePath"] = SamplePath
                    }
                },
                new SandboxEvent
                {
                    EventType = "static.string.indicator",
                    Source = "static",
                    Timestamp = start,
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["kind"] = "domain",
                        ["value"] = "c2.bad.test",
                        ["classification"] = "dynamic_dns",
                        ["isReference"] = "false"
                    }
                },
                SampleOwnedNetworkEvent(inWindow, "c2.bad.test", "198.51.100.8"),
                SampleOwnedNetworkEvent(inWindow.AddMilliseconds(30), "203.0.113.44", "203.0.113.44"),
                PcapEvent("dns.query", inWindow, "c2.bad.test", 53),
                PcapUncorroboratedDns(inWindow.AddMilliseconds(5), "gate.bad.test"),
                PcapEvent("tls.connection", inWindow.AddMilliseconds(10), "c2.bad.test", 443),
                PcapEvent("network.flow", inWindow.AddMilliseconds(20), "198.51.100.8", 443),
                PcapFlowByIp(inWindow.AddMilliseconds(30), "203.0.113.44", 443),
                PcapEvent("network.flow", outsideWindow, "c2.bad.test", 443),
                PcapEvent("network.flow", inWindow, "c2.bad.test", 5986, rawCompatibility: true),
                PcapEvent("network.flow", inWindow, "c2.bad.test", 5986)
            ],
            SamplePath);

        var dns = Require(classified, "dns.query", inWindow);
        SmokeAssert.True(dns.Data["sampleCorrelation"] == "probable", "An ownerless DNS row must be probable only after ETW/R0 sample-owned network corroboration.");
        SmokeAssert.True(dns.Data["pcapCorrelationStaticIocMatched"] == "true", "Probable DNS attribution must preserve static IOC match state.");
        SmokeAssert.True(dns.Data["pcapCorrelationOwnerPidAvailable"] == "false", "PCAP attribution must disclose missing owner PID.");
        SmokeAssert.True(dns.Data["pcapCorrelationCrossSourceEvidence"] == "true", "Probable DNS attribution must disclose the independent runtime source join.");
        SmokeAssert.True(dns.Data["behaviorCounted"] == "true", "Probable canonical PCAP rows must remain behavior candidates.");

        var lifecycleDns = Require(classified, "dns.query", inWindow.AddMilliseconds(5));
        SmokeAssert.True(lifecycleDns.Data["sampleCorrelation"] == "unknown", "An ownerless lifecycle DNS query without an ETW/R0 sample join must remain unattributed.");
        SmokeAssert.True(lifecycleDns.Data["pcapCorrelationStaticIocMatched"] == "false", "Unattributed lifecycle DNS must disclose that no static IOC matched.");
        SmokeAssert.True(lifecycleDns.Data["pcapCorrelationDnsLifecycleMatched"] == "true", "Unattributed lifecycle DNS must disclose the lifecycle join.");
        SmokeAssert.True(lifecycleDns.Data["pcapCorrelationCrossSourceEvidence"] == "false", "Unattributed lifecycle DNS must disclose the missing cross-source join.");
        SmokeAssert.True(lifecycleDns.Data["behaviorCounted"] == "false", "Unattributed lifecycle DNS must stay out of behavior counts.");

        var dnsAnswerFlow = classified.Single(evt => evt.EventType == "network.flow" && evt.Timestamp == inWindow.AddMilliseconds(30));
        SmokeAssert.True(dnsAnswerFlow.Data["sampleCorrelation"] == "probable", "A flow to a static-IOC DNS answer must use DNS corroboration when no owner PID is available.");
        SmokeAssert.True(dnsAnswerFlow.Data["pcapCorrelationDnsCorroborated"] == "true", "DNS-answer corroboration must be explicit in PCAP metadata.");

        var outside = Require(classified, "network.flow", outsideWindow);
        SmokeAssert.True(outside.Data["sampleCorrelation"] != "probable", "Packets outside the sample lifecycle must not be promoted.");
        SmokeAssert.True(outside.Data["pcapCorrelationWindowMatched"] == "false", "Outside-window PCAP rows must expose the failed time join.");

        var raw = classified.Single(evt => evt.Data.TryGetValue("rawPcapCompatibilityRow", out var value) && value == "true");
        SmokeAssert.True(raw.Data["sampleCorrelation"] != "probable", "Raw compatibility rows must never be promoted by static IOC matching.");

        var winrm = classified.Single(evt => evt.Data.TryGetValue("destinationPort", out var port) && port == "5986" &&
            (!evt.Data.TryGetValue("rawPcapCompatibilityRow", out var rawFlag) || rawFlag != "true"));
        SmokeAssert.True(winrm.Data["sampleCorrelation"] != "probable", "WinRM collection traffic must remain outside probable PCAP attribution.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "PCAP attribution joins lifecycle and static IOC evidence conservatively while preserving uncertainty and collection boundaries."
        });
    }

    private static SandboxEvent Require(IReadOnlyCollection<SandboxEvent> events, string eventType, DateTimeOffset timestamp)
    {
        return events.Single(evt => evt.EventType == eventType && evt.Timestamp == timestamp);
    }

    private static SandboxEvent PcapEvent(string eventType, DateTimeOffset timestamp, string target, int destinationPort, bool rawCompatibility = false)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["importSource"] = "pcap-native",
            ["eventKind"] = eventType.StartsWith("dns", StringComparison.OrdinalIgnoreCase) ? "dns" : eventType.StartsWith("tls", StringComparison.OrdinalIgnoreCase) ? "tls" : "connection",
            ["queryName"] = target,
            ["domain"] = target,
            ["sni"] = target,
            ["networkTarget"] = target,
            ["destinationIp"] = target == "c2.bad.test" ? "198.51.100.8" : target,
            ["destinationPort"] = destinationPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["behaviorCounted"] = rawCompatibility ? "false" : "true",
            ["nonbehavior"] = rawCompatibility ? "true" : "false",
            ["rawPcapCompatibilityRow"] = rawCompatibility ? "true" : "false",
            ["duplicateRole"] = rawCompatibility ? "raw-pcap-compatibility" : "normalized-canonical"
        };

        if (eventType.StartsWith("dns", StringComparison.OrdinalIgnoreCase))
        {
            data["dnsAnswerIps"] = "203.0.113.44";
            data["answersNormalized"] = "203.0.113.44";
        }

        return new SandboxEvent
        {
            EventType = eventType,
            Source = "host",
            Timestamp = timestamp,
            Data = data
        };
    }

    private static SandboxEvent PcapFlowByIp(DateTimeOffset timestamp, string destinationIp, int destinationPort)
    {
        return new SandboxEvent
        {
            EventType = "network.flow",
            Source = "host",
            Timestamp = timestamp,
            Data = new(StringComparer.OrdinalIgnoreCase)
            {
                ["importSource"] = "pcap-native",
                ["eventKind"] = "connection",
                ["destinationIp"] = destinationIp,
                ["destinationPort"] = destinationPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["behaviorCounted"] = "true",
                ["nonbehavior"] = "false",
                ["rawPcapCompatibilityRow"] = "false",
                ["duplicateRole"] = "normalized-canonical"
            }
        };
    }

    private static SandboxEvent PcapUncorroboratedDns(DateTimeOffset timestamp, string domain)
    {
        var evt = PcapEvent("dns.query", timestamp, domain, 53);
        var data = new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase);
        data.Remove("dnsAnswerIps");
        data.Remove("answersNormalized");
        data.Remove("destinationIp");
        return evt with { Data = data };
    }

    private static SandboxEvent SampleOwnedNetworkEvent(DateTimeOffset timestamp, string target, string destinationIp)
    {
        return new SandboxEvent
        {
            EventType = "network.etw",
            Source = "etwLive",
            Timestamp = timestamp,
            ProcessId = 100,
            Data = new(StringComparer.OrdinalIgnoreCase)
            {
                ["networkTarget"] = target,
                ["destinationIp"] = destinationIp,
                ["behaviorCounted"] = "true",
                ["nonbehavior"] = "false",
                ["captureSource"] = "etwLive"
            }
        };
    }

    private const string SamplePath = @"C:\KSwordSandbox\incoming\sample.exe";
}
