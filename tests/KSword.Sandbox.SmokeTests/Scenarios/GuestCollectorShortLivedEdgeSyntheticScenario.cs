using KSword.Sandbox.Agent.Collection;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Exercises the guest probes with scripted snapshots and a local temporary
/// directory. It proves that short-lived child, TCP open/close, file
/// rename/delete, task-store edge, service, and Run-key rows are observable
/// without launching a sample, VM, ETW session, or native collector.
/// </summary>
internal sealed class GuestCollectorShortLivedEdgeSyntheticScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest-collector.short-lived-edges.synthetic";

    public async Task<SmokeTestResult> RunAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken = default)
    {
        var result = await GuestCollectorSyntheticDiagnostics.RunAsync(cancellationToken).ConfigureAwait(false);
        SmokeAssert.True(result.ProcessChildObservedThenMissing, "Synthetic process child must produce observed and exited/missing evidence.");
        SmokeAssert.True(result.TcpOpenedAndClosed, "Synthetic TCP edge must produce opened and closed rows plus a poll summary.");
        SmokeAssert.True(result.FileRenameAndDeleteCaptured, "Synthetic file sequence must retain rename and delete watcher edges.");
        SmokeAssert.True(result.ScheduledTaskEdgeCaptured, "Synthetic task-store sequence must retain create, rename, and delete edges.");
        SmokeAssert.True(result.ServiceAndRegistryDiffCaptured, "Synthetic service and registry snapshots must retain created/deleted diffs.");

        SmokeAssert.True(
            result.Events.Any(evt => evt.EventType == "process.edge_poll.summary" &&
                                     evt.Data.GetValueOrDefault("shortLivedProcessLossPossible") == "true"),
            "Process edge summary must disclose the bounded polling loss boundary.");
        SmokeAssert.True(
            result.Events.Any(evt => evt.EventType == "network.tcp.edge_poll.summary" &&
                                     evt.Data.GetValueOrDefault("lossMetricState") == "possible-unmeasured"),
            "TCP edge summary must disclose an unmeasured between-poll loss boundary.");

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Guest synthetic edge harness retained short-lived process, TCP, file, task, service, and registry evidence with explicit polling diagnostics."
        };
    }
}
