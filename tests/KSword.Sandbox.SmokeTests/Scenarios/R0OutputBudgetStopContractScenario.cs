using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the cumulative R0 output-budget contract: the native collector
/// stops cleanly (exit 0 + r0-status sidecar) once total accepted JSONL bytes
/// reach the configured budget, the guest agent forwards the budget, the host
/// importer surfaces the sidecar as a non-failure health row, and collection
/// health is not degraded into an output-write failure. Also locks the
/// no-budget baseline behavior so an unconsumed budget changes nothing.
/// Source/synthetic coverage only; it never starts a VM or executes a sample.
/// </summary>
internal sealed class R0OutputBudgetStopContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.output-budget-stop.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var collectorRoot = Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.R0Collector", "src");
        var optionsHeader = File.ReadAllText(Path.Combine(collectorRoot, "Options.h"));
        var optionsImpl = File.ReadAllText(Path.Combine(collectorRoot, "Options.cpp"));
        var jsonWriter = File.ReadAllText(Path.Combine(collectorRoot, "JsonWriter.h"));
        var jsonWriterImpl = File.ReadAllText(Path.Combine(collectorRoot, "JsonWriter.cpp"));
        var runtimeLoop = File.ReadAllText(Path.Combine(collectorRoot, "RuntimeLoop.cpp"));
        var syntheticMode = File.ReadAllText(Path.Combine(collectorRoot, "SyntheticMode.cpp"));
        var abiSelfCheck = File.ReadAllText(Path.Combine(collectorRoot, "AbiSelfCheck.cpp"));
        var readinessDiagnostics = File.ReadAllText(Path.Combine(collectorRoot, "ReadinessDiagnostics.cpp"));
        var agent = File.ReadAllText(Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.Agent", "Program.cs"));
        var runbookBuilder = File.ReadAllText(Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Orchestration", "HyperVRunbookBuilder.cs"));
        var configurationModels = File.ReadAllText(Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Abstractions", "ConfigurationModels.cs"));
        var renderer = File.ReadAllText(Path.Combine(context.RepositoryRoot, "src", "KSword.Sandbox.Core", "Reporting", "HtmlReportRenderer.cs"));

        // Native collector: budget option, environment override, clean-stop
        // sidecar, and the budget-before-failure dispatch in the runtime loop.
        SmokeAssert.True(optionsImpl.Contains("--output-budget-bytes", StringComparison.Ordinal), "Native collector must accept an explicit cumulative output budget.");
        SmokeAssert.True(optionsImpl.Contains("KSWORD_R0_OUTPUT_BUDGET_BYTES", StringComparison.Ordinal), "Native collector budget must be overridable through the environment.");
        SmokeAssert.True(optionsHeader.Contains("outputBudgetBytes = 384ULL * 1024ULL * 1024ULL", StringComparison.Ordinal), "Native collector must default the cumulative budget to 384MB (six 64MB segments).");
        SmokeAssert.True(jsonWriterImpl.Contains(".r0-status.json", StringComparison.Ordinal), "Native writer must persist an independent r0-status sidecar on a budget stop.");
        SmokeAssert.True(jsonWriterImpl.Contains("ksword.sandbox.r0.status", StringComparison.Ordinal) && jsonWriterImpl.Contains("outputBudgetReached", StringComparison.Ordinal), "Native status sidecar must name the clean budget stop reason.");
        SmokeAssert.True(jsonWriterImpl.Contains("budgetBytes", StringComparison.Ordinal) && jsonWriterImpl.Contains("bytesWritten", StringComparison.Ordinal) && jsonWriterImpl.Contains("segmentsWritten", StringComparison.Ordinal), "Native status sidecar must carry budget/bytes/segments evidence.");
        SmokeAssert.True(jsonWriter.Contains("BudgetReached()", StringComparison.Ordinal) && jsonWriter.Contains("AnnotateBudgetStopStatus", StringComparison.Ordinal), "Native writer must expose the clean budget-stop state and final status annotation.");
        SmokeAssert.True(jsonWriterImpl.Contains("EnterBudgetStop", StringComparison.Ordinal), "Native writer must finalize the current segment and refuse further writes without recording a failure.");
        SmokeAssert.True(runtimeLoop.Contains("FinishBudgetStop", StringComparison.Ordinal), "Runtime loop must route a budget stop to a clean exit instead of the failure path.");
        SmokeAssert.True(runtimeLoop.Contains("kExitSuccess", StringComparison.Ordinal), "A budget stop must exit with code 0.");

        // The clean-stop routing must not be limited to the live drain path:
        // the no-device modes (mock, ABI self-check, readiness) share the same
        // budget-aware exit mapping so a small budget in those modes is also a
        // clean stop instead of a runtime-failure exit code.
        SmokeAssert.True(jsonWriter.Contains("OutputStopExitCode", StringComparison.Ordinal), "The event writer must expose the shared budget-stop exit mapping.");
        SmokeAssert.True(syntheticMode.Contains("OutputStopExitCode", StringComparison.Ordinal), "Synthetic mode must route a budget stop to a clean exit like the live path.");
        SmokeAssert.True(abiSelfCheck.Contains("OutputStopExitCode", StringComparison.Ordinal), "ABI self-check mode must route a budget stop to a clean exit like the live path.");
        SmokeAssert.True(readinessDiagnostics.Contains("OutputStopExitCode", StringComparison.Ordinal), "Readiness diagnose mode must route a budget stop to a clean exit like the live path.");

        // Guest agent and runbook plumbing: budget forwarded on the same path
        // as the rotation parameter, and configurable from host config.
        SmokeAssert.True(agent.Contains("--output-budget-bytes", StringComparison.Ordinal) && agent.Contains("R0CollectorOutputBudgetBytes", StringComparison.Ordinal), "Guest Agent must forward the cumulative budget to R0Collector.");
        SmokeAssert.True(runbookBuilder.Contains("--output-budget-bytes", StringComparison.Ordinal), "Runbook agent arguments must pass the configured cumulative budget.");
        SmokeAssert.True(configurationModels.Contains("R0CollectorOutputBudgetBytes", StringComparison.Ordinal), "Sandbox config must expose the cumulative budget knob.");
        SmokeAssert.True(new DriverConfig().R0CollectorOutputBudgetBytes == 384 * 1024 * 1024, "Driver config must default the cumulative budget to 384MB.");
        var exampleConfig = SandboxConfigLoader.Load(Path.Combine(context.RepositoryRoot, "config", "sandbox.example.json"), context.RepositoryRoot);
        SmokeAssert.True(exampleConfig.Driver.R0CollectorOutputBudgetBytes == 402653184, "Example config must bind the cumulative budget value.");

        // Host importer: the r0-status sidecar becomes one explicit non-failure
        // health row with the clean-stop semantics preserved.
        var guestRoot = Path.Combine(context.RuntimeRoot, "r0-budget-import", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(guestRoot);
        File.WriteAllText(Path.Combine(guestRoot, "driver-events.jsonl.r0-status.json"),
            JsonSerializer.Serialize(new
            {
                schema = "ksword.sandbox.r0.status",
                stopReason = "outputBudgetReached",
                budgetBytes = 402653184UL,
                bytesWritten = 402653100UL,
                segmentsWritten = 6,
                rotatedSegmentCount = 5,
                statusAnnotated = true,
                finalStatusAvailable = true,
                queueDepthAtStopKnown = true,
                queueDepthAtStop = 1234,
                captureState = "truncated",
                exitCode = 0
            }));
        var imported = GuestFailureArtifactImporter.Import(guestRoot);
        var budgetRow = imported.SingleOrDefault(evt => string.Equals(evt.EventType, "r0collector.outputBudget", StringComparison.Ordinal));
        SmokeAssert.True(budgetRow is not null, "Importer must surface the r0-status sidecar as an explicit budget-stop row.");
        SmokeAssert.True(budgetRow!.Data.TryGetValue("stopReason", out var stopReason) && stopReason == "outputBudgetReached", "Budget row must preserve the clean stopReason.");
        SmokeAssert.True(budgetRow.Data.TryGetValue("budgetBytes", out var budgetBytes) && budgetBytes == "402653184", "Budget row must preserve budgetBytes.");
        SmokeAssert.True(budgetRow.Data.TryGetValue("bytesWritten", out var bytesWritten) && bytesWritten == "402653100", "Budget row must preserve bytesWritten.");
        SmokeAssert.True(budgetRow.Data.TryGetValue("segmentsWritten", out var segments) && segments == "6", "Budget row must preserve segmentsWritten.");
        SmokeAssert.True(!budgetRow.Data.ContainsKey("remainingUnread"), "Budget row must not fabricate an undrained-queue tail.");

        // Collection health: budget reached -> clean stop, non-failure verdict.
        var startedAt = DateTimeOffset.UtcNow;
        var healthRow = new SandboxEvent
        {
            EventType = "r0collector.started",
            Source = "r0collector",
            Timestamp = startedAt,
            Data = { ["collectionHealth"] = "true", ["producer"] = "r0collector" }
        };
        var budgetEvents = new List<SandboxEvent> { healthRow, budgetRow };
        var budgetSummary = CollectionHealthSummaryBuilder.Build(budgetEvents);
        SmokeAssert.True(budgetSummary.R0OutputBudgetReached, "Collection health must recognize the budget stop explicitly.");
        SmokeAssert.True(budgetSummary.R0OutputBudgetBytes == 402653184L && budgetSummary.R0OutputBudgetBytesWritten == 402653100L && budgetSummary.R0OutputBudgetSegments == 6, "Collection health must carry budget bytes and segment counts.");
        SmokeAssert.True(budgetSummary.DriverOutputWriteFailureRows == 0, "A budget stop must never be counted as an output-write failure.");
        SmokeAssert.True(budgetSummary.FailureRows == 0, "A budget stop must not be classified as a collection failure.");
        SmokeAssert.True(string.Equals(budgetSummary.State, "complete", StringComparison.Ordinal), "A clean budget stop must not degrade the collection state to partial.");
        SmokeAssert.True(budgetSummary.StateReasons.Contains("r0-output-budget-reached", StringComparer.Ordinal), "State reasons must name the intentional budget boundary.");
        var budgetMetrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        CollectionHealthSummaryBuilder.AddMetrics(budgetMetrics, budgetSummary);
        SmokeAssert.True(budgetMetrics.TryGetValue("collectionHealth.driver.outputBudgetReached", out var reached) && reached == 1, "Metrics must expose the budget-stop marker.");

        // Semantics stay distinguishable: a real write failure still reports
        // as a failure even when a budget row exists in the same stream.
        var failureSidecarRow = GuestFailureArtifactImporter.ImportR0OutputFailure(null);
        SmokeAssert.True(failureSidecarRow is null, "Missing failure sidecar must stay a no-op.");
        var failureRow = new SandboxEvent
        {
            EventType = "r0collector.finalStatus",
            Source = "r0collector",
            Timestamp = startedAt.AddSeconds(1),
            Data =
            {
                ["collectionHealth"] = "true",
                ["failureType"] = "outputWriteFailure",
                ["win32Error"] = "1394",
                ["exitCode"] = "70",
                ["bytesAttempted"] = "433508646"
            }
        };
        var mixedSummary = CollectionHealthSummaryBuilder.Build(new List<SandboxEvent> { healthRow, budgetRow, failureRow });
        SmokeAssert.True(mixedSummary.DriverOutputWriteFailureRows == 1, "A real output-write failure must remain visible alongside a budget stop.");
        SmokeAssert.True(mixedSummary.R0OutputBudgetReached, "The budget marker must survive a mixed budget+failure stream.");
        SmokeAssert.True(string.Equals(mixedSummary.State, "partial", StringComparison.Ordinal), "A real write failure must still degrade the collection state.");

        // No budget reached -> original behavior is unchanged: an unknown
        // final queue depth still marks the run partial.
        var baselineSummary = CollectionHealthSummaryBuilder.Build(new List<SandboxEvent> { healthRow });
        SmokeAssert.True(!baselineSummary.R0OutputBudgetReached, "A run without budget evidence must not claim a budget stop.");
        SmokeAssert.True(string.Equals(baselineSummary.State, "partial", StringComparison.Ordinal), "Without a budget stop an unknown final queue must remain a partial-state gap.");
        SmokeAssert.True(baselineSummary.StateReasons.Contains("driver-final-queue-unknown", StringComparer.Ordinal), "Without a budget stop the original queue-unknown reason must be preserved.");

        // Report surface: the R0 coverage card shows the budget boundary as an
        // informational, non-failure entry.
        SmokeAssert.True(renderer.Contains("output-budget-reached", StringComparison.Ordinal), "Report renderer must surface the budget stop in the R0 coverage card.");
        SmokeAssert.True(renderer.Contains("R0 output budget reached: ", StringComparison.Ordinal), "Report renderer must name the reached budget explicitly.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Cumulative output budget stops R0 cleanly (exit 0 + r0-status sidecar) on every collector mode, the host treats it as a non-failure truncation, real write failures stay failures, and the no-budget baseline is unchanged."
        });
    }
}
