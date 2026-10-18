using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the evidence-recovery routing that keeps the final guest collection
/// reachable after an earlier live-run failure, without starting a VM.
/// </summary>
internal sealed class CollectionRecoveryContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "runbook.collection-recovery.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var executor = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Execution", "PowerShellRunbookExecutor.cs"));
        var builder = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Orchestration", "HyperVRunbookBuilder.cs"));

        Require(executor, "ShouldAttemptVmwareRecoveryStep", "Collection recovery must stay behind an explicit policy.");
        Require(executor, "runbook.Provider is not VirtualizationProvider.VMware", "Collection recovery must stay scoped to the VMware live path.");
        Require(
            executor,
            "if (string.Equals(primaryFailure.StepId, \"sync-live-output\", StringComparison.OrdinalIgnoreCase))",
            "A failed live sync must not cancel the authoritative collection step.");
        Require(
            executor,
            "return string.Equals(step.Id, \"collect-output\", StringComparison.OrdinalIgnoreCase);",
            "The sync-live-output failure branch must route recovery at collect-output.");
        Require(
            executor,
            "if (!string.Equals(primaryFailure.StepId, \"run-agent\", StringComparison.OrdinalIgnoreCase))",
            "The original run-agent recovery branch must survive the sync branch.");
        Require(executor, "AnnotateVmwareRecoveryFailure", "Unavailable WinRM after a sync failure must stay visible as a diagnostic.");
        Require(executor, "partial evidence was preserved before cleanup", "A failed recovery must state that partial evidence survived.");
        Require(executor, "IsCleanupStep(step)", "Cleanup steps must still run regardless of the recovery policy.");

        // The snapshot revert is what makes a skipped collection fatal: once the
        // guest is reverted the uncollected evidence is gone for good, so the
        // collect step has to be planned before cleanup in every provider.
        var collectIndex = builder.IndexOf("Step(\"collect-output\"", StringComparison.Ordinal);
        var stopIndex = builder.IndexOf("Step(\"stop-vm\"", StringComparison.Ordinal);
        SmokeAssert.True(collectIndex > 0, "The runbook must plan a final guest output collection step.");
        SmokeAssert.True(stopIndex > collectIndex, "Final collection must be planned before the snapshot revert.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "A failed live sync still attempts the final guest collection before the snapshot revert, and the recovery diagnostic stays explicit."
        });
    }

    private static string Read(SmokeTestContext context, string path)
    {
        var fullPath = Path.Combine(context.RepositoryRoot, path);
        SmokeAssert.True(File.Exists(fullPath), $"Required source file was not found: {path}");
        return File.ReadAllText(fullPath);
    }

    private static void Require(string source, string needle, string message)
    {
        SmokeAssert.True(source.Contains(needle, StringComparison.Ordinal), message);
    }
}
