using KSword.Sandbox.Core.StaticAnalysis;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that managed PE metadata is read without loading or executing the
/// assembly and that the bounded CLR inventory is exposed as low-confidence
/// static.managed.* evidence.
/// </summary>
internal sealed class StaticManagedMetadataContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "static.managed-metadata.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var samplePath = typeof(StaticAnalyzer).Assembly.Location;
        SmokeAssert.True(File.Exists(samplePath), "The static analyzer assembly should exist for the metadata smoke input.");

        var analyzer = new StaticAnalyzer();
        var result = analyzer.Analyze(samplePath);
        var managed = result.ManagedMetadata;
        SmokeAssert.True(managed is { HasMetadata: true }, "A managed PE should expose CLR metadata.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(managed!.RuntimeVersion), "CLR metadata should include the runtime metadata version.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(managed.AssemblyName), "CLR metadata should include the assembly name.");
        SmokeAssert.True(managed.Types.Count > 0, "CLR metadata should include at least one type.");
        SmokeAssert.True(managed.Methods.Count > 0, "CLR metadata should include at least one method.");
        SmokeAssert.True(managed.References.Count > 0, "CLR metadata should include assembly or module references.");

        var events = StaticAnalyzer.CreateEvents(samplePath, result)
            .Where(evt => evt.EventType.StartsWith("static.managed.", StringComparison.OrdinalIgnoreCase))
            .ToList();
        SmokeAssert.True(events.Any(evt => evt.EventType == "static.managed.metadata"), "CLR metadata should emit a summary event.");
        SmokeAssert.True(events.Any(evt => evt.EventType == "static.managed.type"), "CLR metadata should emit type events.");
        SmokeAssert.True(events.Any(evt => evt.EventType == "static.managed.method"), "CLR metadata should emit method events.");
        SmokeAssert.True(events.Any(evt => evt.EventType == "static.managed.reference"), "CLR metadata should emit reference events.");
        foreach (var evt in events)
        {
            SmokeAssert.True(evt.Data.TryGetValue("staticOnly", out var staticOnly) && staticOnly == "True", $"{evt.EventType} must be static-only evidence.");
            SmokeAssert.True(evt.Data.TryGetValue("confidence", out var confidence) && confidence == "low", $"{evt.EventType} must remain low confidence.");
            SmokeAssert.True(evt.Data.TryGetValue("runtimeCorrelationRequired", out var correlation) && correlation == "True", $"{evt.EventType} must require runtime correlation.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"CLR metadata emitted {events.Count} bounded static.managed.* rows without executing the assembly."
        });
    }
}
