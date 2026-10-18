using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Keeps typed driver Run-key persistence matching both registry path
/// spellings emitted by the collector: with and without a trailing slash.
/// </summary>
internal sealed class DriverRegistryRunKeyTypedPersistenceScenario : ISmokeTestScenario
{
    private const string RuleId = "driver-registry-run-key-typed-persistence";

    public string ScenarioId => "behavior.rules-driver-registry-run-key-typed-persistence";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(rulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(rulesPath);
        var rule = rules.Rules.SingleOrDefault(candidate =>
            string.Equals(candidate.Id, RuleId, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(rule is not null, $"{RuleId} rule is missing.");
        SmokeAssert.True(
            rule!.DataContains.TryGetValue("keyPath", out var keyPathFragments) &&
            keyPathFragments.Contains(@"CurrentVersion\Run", StringComparer.OrdinalIgnoreCase) &&
            keyPathFragments.Contains(@"CurrentVersion\Run\", StringComparer.OrdinalIgnoreCase),
            $"{RuleId} must accept CurrentVersion\\Run with and without a trailing slash.");

        var events = new[]
        {
            CreateTypedRegistryEvent(@"\Windows\CurrentVersion\Run", "createKey"),
            CreateTypedRegistryEvent(@"CurrentVersion\Run\", "setValue")
        };

        var finding = new RuleEngine(rules).Classify(events).SingleOrDefault(candidate =>
            string.Equals(candidate.RuleId, RuleId, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(finding is not null, $"Both typed Run-key path spellings should match {RuleId}.");
        SmokeAssert.True(
            finding!.Evidence.Count == events.Length &&
            finding.Evidence.Any(evidence => string.Equals(
                evidence.Data.GetValueOrDefault("keyPath"),
                @"\Windows\CurrentVersion\Run",
                StringComparison.OrdinalIgnoreCase)) &&
            finding.Evidence.Any(evidence => string.Equals(
                evidence.Data.GetValueOrDefault("keyPath"),
                @"CurrentVersion\Run\",
                StringComparison.OrdinalIgnoreCase)),
            $"{RuleId} evidence should retain both keyPath spellings.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Typed driver Run-key persistence matches key paths with and without a trailing slash."
        });
    }

    private static SandboxEvent CreateTypedRegistryEvent(string keyPath, string operationName)
    {
        return new SandboxEvent
        {
            EventType = "driver.registry",
            Source = "driver",
            ProcessName = "payload.exe",
            Data =
            {
                ["keyPath"] = keyPath,
                ["operationName"] = operationName,
                ["registryOperationName"] = operationName,
                ["persistenceCandidate"] = "true",
                ["behaviorCounted"] = "true"
            }
        };
    }
}
