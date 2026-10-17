using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the network edge-capture contract. The scenario is source-level by
/// design: it runs on CI hosts without a Windows guest, while ensuring the
/// Windows owner-table path, managed fallback, and explicit unknown-owner
/// semantics cannot silently regress.
/// </summary>
internal sealed class NetworkOwnerCaptureContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest-agent.network-owner-capture.contract";

    public Task<SmokeTestResult> RunAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var source = ReadRepositoryText(
            context,
            "guest",
            "KSword.Sandbox.Agent",
            "Collection",
            "TcpConnectionDiffProbe.cs");

        RequireContains(source, "GetExtendedTcpTable", "TCP capture must use the Windows owner table for fast PID attribution.");
        RequireContains(source, "TcpTableOwnerPidAll", "TCP capture must request owner-PID rows rather than a PID-less table.");
        RequireContains(source, "getextendedtcptable-owner-pid", "TCP rows must record the source of an attributed owner PID.");
        RequireContains(source, "OwningProcessId", "TCP snapshots must retain the owner PID across an edge and its closed event.");
        RequireContains(source, "BuildFlowKey", "TCP edge rows must emit the stable directional flow key used by cross-source joins.");
        RequireContains(source, "ownerPidPresent", "TCP edge rows must disclose whether the source owner PID is present.");
        RequireContains(source, "pcapCorrelationKey", "TCP edge rows must expose the flow key as a PCAP join candidate.");
        RequireContains(source, "unavailable-managed-api", "The managed fallback must make missing ownership explicit.");
        RequireContains(source, "unavailable-pid-zero", "PID zero must remain un-attributed.");
        RequireContains(source, "TryCaptureWindowsOwnerTableV6", "TCP owner capture must cover IPv6 rows as well as IPv4.");
        RequireContains(source, "network.tcp.closed", "Closed edges must remain observable after a short-lived connection disappears.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "TCP edge capture retains owner history, covers IPv4/IPv6, and fails closed when ownership is unavailable."
        });
    }

    private static string ReadRepositoryText(SmokeTestContext context, params string[] segments)
    {
        var path = context.RepositoryRoot;
        foreach (var segment in segments)
        {
            path = Path.Combine(path, segment);
        }

        return File.ReadAllText(path);
    }

    private static void RequireContains(string text, string expected, string message)
    {
        SmokeAssert.True(text.Contains(expected, StringComparison.Ordinal), message);
    }
}
