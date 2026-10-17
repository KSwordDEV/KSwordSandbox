using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that an owner-bearing Guest TCP edge can join a PID-less PCAP
/// flow through an exact flow key. A conflicting owner must remain unknown.
/// </summary>
internal sealed class GuestTcpOwnerJoinContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.guest-tcp-owner-join";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var start = DateTimeOffset.UtcNow;
        var samplePath = @"C:\KSwordSandbox\incoming\sample.exe";
        var flowKey = "tcp|192.168.172.130:51000|198.51.100.7:443";
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "process.start",
                Source = "guest",
                Timestamp = start,
                ProcessName = "sample.exe",
                ProcessId = 8124,
                Path = samplePath,
                CommandLine = samplePath,
                Data = new(StringComparer.OrdinalIgnoreCase) { ["processImagePath"] = samplePath }
            },
            new()
            {
                EventType = "network.tcp",
                Source = "guest",
                Timestamp = start.AddMilliseconds(100),
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["protocol"] = "TCP",
                    ["local"] = "192.168.172.130:51000",
                    ["remote"] = "198.51.100.7:443",
                    ["localEndpoint"] = "192.168.172.130:51000",
                    ["remoteEndpoint"] = "198.51.100.7:443",
                    ["flowKey"] = flowKey,
                    ["ownerPid"] = "8124",
                    ["owningProcessId"] = "8124",
                    ["processId"] = "8124",
                    ["ownerPidPresent"] = "true",
                    ["ownerPidSource"] = "getextendedtcptable-owner-pid"
                }
            },
            new()
            {
                EventType = "network.flow",
                Source = "host",
                Timestamp = start.AddMilliseconds(120),
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["importSource"] = "pcap-native",
                    ["eventKind"] = "connection",
                    ["flowKey"] = flowKey,
                    ["protocol"] = "tcp",
                    ["sourceEndpoint"] = "192.168.172.130:51000",
                    ["destinationEndpoint"] = "198.51.100.7:443",
                    ["destinationIp"] = "198.51.100.7",
                    ["destinationPort"] = "443",
                    ["behaviorCounted"] = "true",
                    ["nonbehavior"] = "false"
                }
            }
        };

        var classified = SampleCorrelationClassifier.Apply(events, samplePath);
        var pcap = classified.Single(evt => evt.EventType == "network.flow");
        SmokeAssert.True(pcap.Data["sampleCorrelation"] == "confirmed", "PCAP must inherit the sample owner from exact Guest TCP flow evidence.");
        SmokeAssert.True(pcap.Data["owningProcessId"] == "8124", "PCAP must retain the joined Guest TCP owner PID.");
        SmokeAssert.True(pcap.Data["networkOwnerJoinSource"] == "r0-flow-or-endpoint", "PCAP must disclose the stable owner join source.");

        var conflictingOwner = events[1] with
        {
            Data = new Dictionary<string, string>(events[1].Data, StringComparer.OrdinalIgnoreCase)
            {
                ["ownerPid"] = "9001",
                ["owningProcessId"] = "9001",
                ["processId"] = "9001"
            }
        };
        var conflictClassified = SampleCorrelationClassifier.Apply(
            [events[0], events[1], conflictingOwner, events[2]],
            samplePath);
        var conflictPcap = conflictClassified.Single(evt => evt.EventType == "network.flow");
        SmokeAssert.True(
            conflictPcap.Data["sampleCorrelation"] == "unknown",
            "A flow observed under conflicting owner PIDs must remain unknown instead of using a time-based guess.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Guest TCP owner rows join ownerless PCAP flows by exact flow/endpoint identity."
        });
    }
}
