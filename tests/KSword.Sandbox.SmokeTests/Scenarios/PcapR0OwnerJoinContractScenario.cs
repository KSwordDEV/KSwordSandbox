using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the cross-source network join used by live runs: R0/WFP exposes the
/// owning PID while the PCAP protocol row intentionally does not.  The PCAP
/// row must inherit the R0 owner through a stable flow key or endpoint before
/// it is downgraded to an ownerless/IOC-only observation.
/// </summary>
internal sealed class PcapR0OwnerJoinContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.pcap-r0-owner-join";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var start = DateTimeOffset.UtcNow;
        var samplePath = @"C:\KSwordSandbox\incoming\sample.exe";
        var flowKey = "tcp|192.168.172.130:51000|198.51.100.7:443";
        var classified = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "guest",
                    Timestamp = start,
                    ProcessName = "sample.exe",
                    ProcessId = 8124,
                    Path = samplePath,
                    CommandLine = samplePath,
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = samplePath
                    }
                },
                new SandboxEvent
                {
                    EventType = "driver.network",
                    Source = "driver",
                    Timestamp = start.AddMilliseconds(100),
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["schema"] = "ksword.sandbox.r0.event",
                        ["eventOrigin"] = "kernel-driver",
                        ["producerCategory"] = "network",
                        ["ownerPid"] = "8124",
                        ["ownerPidPresent"] = "true",
                        ["ownerPidSource"] = "wfp.metadata.processId",
                        ["protocol"] = "tcp",
                        ["sourceEndpoint"] = "192.168.172.130:51000",
                        ["destinationEndpoint"] = "198.51.100.7:443",
                        ["flowKey"] = flowKey,
                        ["behaviorCounted"] = "true"
                    }
                },
                new SandboxEvent
                {
                    EventType = "network.flow",
                    Source = "host",
                    Timestamp = start.AddMilliseconds(120),
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["importSource"] = "pcap-native",
                        ["eventKind"] = "connection",
                        ["protocol"] = "tcp",
                        ["sourceEndpoint"] = "192.168.172.130:51000",
                        ["destinationEndpoint"] = "198.51.100.7:443",
                        ["flowKey"] = flowKey,
                        ["destinationIp"] = "198.51.100.7",
                        ["destinationPort"] = "443",
                        ["behaviorCounted"] = "true",
                        ["nonbehavior"] = "false"
                    }
                }
            ],
            samplePath);

        var pcap = classified.Single(evt => evt.EventType == "network.flow");
        SmokeAssert.True(
            pcap.Data.TryGetValue("sampleCorrelation", out var correlation) && correlation == "confirmed",
            "PCAP flow must inherit the sample owner from the matching R0 flow key.");
        SmokeAssert.True(
            pcap.Data.TryGetValue("sampleCorrelationReason", out var reason) && reason == "network-owner-pid-joined-from-r0-and-matched-sample-process-tree",
            "PCAP owner join must disclose that the concrete R0 owner PID matched the sample process tree.");
        SmokeAssert.True(
            pcap.Data.TryGetValue("sampleCorrelationField", out var field) && field == "owningProcessId",
            "PCAP owner join must identify the owner PID correlation field.");
        SmokeAssert.True(
            pcap.Data.TryGetValue("owningProcessId", out var joinedPid) && joinedPid == "8124" &&
            pcap.Data.TryGetValue("networkOwnerJoinSource", out var joinSource) && joinSource == "r0-flow-or-endpoint",
            "PCAP row must retain the concrete joined R0 owner PID and its source contract.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Ownerless PCAP flow rows inherit a concrete sample owner from matching R0 flow evidence."
        });
    }
}
