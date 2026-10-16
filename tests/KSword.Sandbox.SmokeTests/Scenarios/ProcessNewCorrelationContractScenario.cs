using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Keeps ambient process.new snapshots out of the generic process finding.
/// Inputs are uncorrelated, environmental, confirmed, and probable rows;
/// processing verifies only the latter two are promoted by RuleEngine while
/// raw telemetry remains available to the report pipeline.
/// </summary>
internal sealed class ProcessNewCorrelationContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "behavior.process-new.sample-correlation";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RepositoryRoot, "rules", "behavior-rules.json"));
        var engine = new RuleEngine(rules);

        SmokeAssert.True(
            !HasProcessNewFinding(engine.Classify([BuildEvent()])),
            "An uncorrelated process.new row must remain raw evidence and not produce process-new.");
        SmokeAssert.True(
            !HasProcessNewFinding(engine.Classify([BuildEvent(("sampleCorrelation", "environment"), ("sampleCorrelationStatus", "environment"))])),
            "An explicitly environmental process.new row must not produce process-new.");
        SmokeAssert.True(
            HasProcessNewFinding(engine.Classify([BuildEvent(("sampleCorrelation", "confirmed"), ("sampleCorrelationStatus", "confirmed"))])),
            "A confirmed process.new row should still produce process-new.");
        SmokeAssert.True(
            HasProcessNewFinding(engine.Classify([BuildEvent(("sampleCorrelation", "probable"), ("sampleCorrelationStatus", "probable"))])),
            "A probable process.new row should still produce process-new.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Generic process.new findings require confirmed or probable sample correlation."
        });
    }

    private static bool HasProcessNewFinding(IReadOnlyCollection<BehaviorFinding> findings)
    {
        return findings.Any(finding => string.Equals(finding.RuleId, "process-new", StringComparison.OrdinalIgnoreCase));
    }

    private static SandboxEvent BuildEvent(params (string Key, string Value)[] metadata)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["lineageIncludesRoot"] = "false",
            ["processName"] = "EdgeUpdate.exe"
        };
        foreach (var (key, value) in metadata)
        {
            data[key] = value;
        }

        return new SandboxEvent
        {
            EventType = "process.new",
            Source = "guest",
            ProcessName = "EdgeUpdate.exe",
            ProcessId = 4242,
            Path = @"C:\Program Files\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            Data = data
        };
    }
}
