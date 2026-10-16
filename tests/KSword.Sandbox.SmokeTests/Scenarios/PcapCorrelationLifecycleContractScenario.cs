using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies ownerless PCAP protocol rows can become probable sample evidence
/// only when capture time overlaps the sample lifecycle and a static IOC is
/// corroborated. Compatibility rows, WinRM collection traffic, and packets
/// outside the lifecycle remain unpromoted.
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
                PcapEvent("dns.query", inWindow, "c2.bad.test", 53),
                PcapEvent("tls.connection", inWindow.AddMilliseconds(10), "c2.bad.test", 443),
                PcapEvent("network.flow", inWindow.AddMilliseconds(20), "198.51.100.8", 443),
                PcapEvent("network.flow", outsideWindow, "c2.bad.test", 443),
                PcapEvent("network.flow", inWindow, "c2.bad.test", 5986, rawCompatibility: true),
                PcapEvent("network.flow", inWindow, "c2.bad.test", 5986)
            ],
            SamplePath);

        var dns = Require(classified, "dns.query", inWindow);
        SmokeAssert.True(dns.Data["sampleCorrelation"] == "probable", "An ownerless DNS row with lifecycle/static IOC corroboration must be probable.");
        SmokeAssert.True(dns.Data["pcapCorrelationStaticIocMatched"] == "true", "Probable DNS attribution must preserve static IOC match state.");
        SmokeAssert.True(dns.Data["pcapCorrelationOwnerPidAvailable"] == "false", "PCAP attribution must disclose missing owner PID.");
        SmokeAssert.True(dns.Data["behaviorCounted"] == "true", "Probable canonical PCAP rows must remain behavior candidates.");

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

        return new SandboxEvent
        {
            EventType = eventType,
            Source = "host",
            Timestamp = timestamp,
            Data = data
        };
    }

    private const string SamplePath = @"C:\KSwordSandbox\incoming\sample.exe";
}
