using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Keeps the broad service-registry rule tied to structured service
/// persistence semantics. The synthetic Tcpip parameters query represents
/// native hostname.exe noise; service create/change rows remain high-signal.
/// </summary>
internal sealed class ServiceRegistryPersistenceNoiseRegressionScenario : ISmokeTestScenario
{
    public string ScenarioId => "behavior.rules-service-registry-noise-regression";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(rulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(rulesPath);
        var guardedRuleIds = new[]
        {
            "service-registry-persistence",
            "driver-registry-service-typed-persistence",
            "service-imagepath-or-dll-registry-change"
        };
        foreach (var guardedRuleId in guardedRuleIds)
        {
            var rule = rules.Rules.SingleOrDefault(candidate =>
                string.Equals(candidate.Id, guardedRuleId, StringComparison.OrdinalIgnoreCase));
            SmokeAssert.True(rule is not null, $"{guardedRuleId} rule is missing.");
            SmokeAssert.True(
                rule!.AllDataContains.TryGetValue("servicePersistenceCandidate", out var candidateValues) &&
                candidateValues.Contains("true", StringComparer.OrdinalIgnoreCase),
                $"{guardedRuleId} must require servicePersistenceCandidate=true.");
        }

        var events = new[]
        {
            new SandboxEvent
            {
                EventType = "driver.registry",
                Source = "driver",
                ProcessName = "hostname.exe",
                Path = @"\Services\Tcpip\Parameters",
                Data =
                {
                    ["persistenceCandidate"] = "false",
                    ["servicePersistenceCandidate"] = "false",
                    ["persistenceFamily"] = "none",
                    ["path"] = @"\Services\Tcpip\Parameters",
                    ["keyPath"] = @"\Services\Tcpip\Parameters",
                    ["registryOperationName"] = "openKey"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.registry",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc",
                Data =
                {
                    ["persistenceCandidate"] = "true",
                    ["servicePersistenceCandidate"] = "true",
                    ["persistenceFamily"] = "service-configuration",
                    ["path"] = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc",
                    ["keyPath"] = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc",
                    ["registryOperationName"] = "createKey"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc\ImagePath",
                Data =
                {
                    ["persistenceCandidate"] = "true",
                    ["servicePersistenceCandidate"] = "true",
                    ["persistenceFamily"] = "service-configuration",
                    ["valueName"] = "ServiceDll",
                    ["registryOperationName"] = "setValue"
                }
            }
        };

        var findings = new RuleEngine(rules).Classify(events);
        foreach (var expectedRuleId in guardedRuleIds)
        {
            var finding = findings.SingleOrDefault(candidate => string.Equals(
                candidate.RuleId,
                expectedRuleId,
                StringComparison.OrdinalIgnoreCase));
            SmokeAssert.True(finding is not null, $"A structured service create/change should match {expectedRuleId}.");
            SmokeAssert.True(
                finding!.Evidence.Count > 0 &&
                finding.Evidence.All(evidence =>
                string.Equals(evidence.Data.GetValueOrDefault("servicePersistenceCandidate"), "true", StringComparison.OrdinalIgnoreCase)),
                $"{expectedRuleId} evidence should contain only semantic service persistence candidates.");
            SmokeAssert.True(
                finding.Evidence.All(evidence => !(evidence.Path ?? string.Empty).Contains(@"\Services\Tcpip\Parameters", StringComparison.OrdinalIgnoreCase)),
                $"Tcpip Parameters access must remain out of {expectedRuleId} evidence.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Tcpip Parameters noise is suppressed while structured service create/change rows remain high-signal."
        });
    }
}
