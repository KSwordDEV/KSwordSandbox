using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the open-source-reference rule landing for constrained
/// ATT&CK/Sigma-style LOLBin and API-monitor behavior without running E2E.
/// </summary>
internal sealed class BehaviorRuleOpenSourceReferenceScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "odbcconf-regsvr-user-writable-dll-proxy-execution",
        "mmc-user-writable-msc-proxy-execution",
        "named-pipe-impersonation-api-observed"
    ];

    private static readonly string[] RequiredTechniqueIds =
    [
        "T1218.008",
        "T1218.014"
    ];

    public string ScenarioId => "behavior.rules-open-source-reference";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        var mitreMapPath = Path.Combine(context.RulesDirectory, "mitre-windows-map.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");
        SmokeAssert.True(File.Exists(mitreMapPath), "mitre-windows-map.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"Open-source reference rule '{ruleId}' is missing.");
            AssertRuleContract(rule!);
        }

        var techniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredTechniqueIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        AssertSyntheticMatches(rules);
        AssertFalsePositiveGuards(rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Open-source reference rules load, map to ATT&CK, match constrained synthetic events, and suppress common self/noise cases."
        });
    }

    private static void AssertRuleContract(BehaviorRule rule)
    {
        SmokeAssert.True(string.Equals(rule.Severity, "high", StringComparison.OrdinalIgnoreCase), $"Rule '{rule.Id}' should stay high severity.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueName), $"Rule '{rule.Id}' should include a MITRE technique name.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(rule.Tags.Contains("open-source-reference", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should carry open-source-reference tag.");
        SmokeAssert.True(rule.Tags.Contains("sigma-style", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should carry sigma-style tag.");
        SmokeAssert.True(
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.Agent.exe", StringComparer.OrdinalIgnoreCase) &&
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.R0Collector.exe", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should exclude sandbox plumbing process names.");
        SmokeAssert.True(rule.ExcludeDataContains.Count > 0, $"Rule '{rule.Id}' should exclude collection-health/VT/R0 metadata.");

        if (rule.Id.StartsWith("odbcconf-", StringComparison.OrdinalIgnoreCase) ||
            rule.Id.StartsWith("mmc-", StringComparison.OrdinalIgnoreCase))
        {
            SmokeAssert.True(rule.AllContainsCommandLine.Count >= 2, $"Rule '{rule.Id}' should require multiple command-line tokens.");
            SmokeAssert.True(rule.CommandLineRegex.Count > 0, $"Rule '{rule.Id}' should require user-writable path regex evidence.");
        }

        if (string.Equals(rule.Id, "named-pipe-impersonation-api-observed", StringComparison.OrdinalIgnoreCase))
        {
            SmokeAssert.True(rule.AllDataKeys.Contains("pipeName", StringComparer.OrdinalIgnoreCase), "Named-pipe impersonation rule should require a pipeName field.");
            SmokeAssert.True(rule.DataContains.ContainsKey("api") || rule.DataContains.ContainsKey("operation"), "Named-pipe impersonation rule should require impersonation API or operation evidence.");
        }
    }

    private static void AssertSyntheticMatches(BehaviorRuleSet rules)
    {
        var findingIds = new RuleEngine(rules)
            .Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic open-source reference event should match '{ruleId}'.");
        }
    }

    private static void AssertFalsePositiveGuards(BehaviorRuleSet rules)
    {
        var findingIds = new RuleEngine(rules)
            .Classify(CreateNoiseEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(!findingIds.Contains(ruleId), $"Noise/self event should not match open-source reference rule '{ruleId}'.");
        }
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "odbcconf.exe",
                CommandLine = @"odbcconf.exe /A {REGSVR C:\Users\Public\payload.dll}"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "mmc.exe",
                CommandLine = @"mmc.exe C:\Users\Smoke\Downloads\payload.msc"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["api"] = "ImpersonateNamedPipeClient",
                    ["pipeName"] = @"\\.\pipe\evil-service"
                }
            }
        ];
    }

    private static IReadOnlyList<SandboxEvent> CreateNoiseEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "odbcconf.exe",
                CommandLine = @"odbcconf.exe /A {CONFIGDSN SQL Server SmokeDsn}"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "mmc.exe",
                CommandLine = @"mmc.exe C:\Windows\System32\compmgmt.msc"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                ProcessName = "chrome.exe",
                Data =
                {
                    ["api"] = "ImpersonateNamedPipeClient",
                    ["pipeName"] = @"\\.\pipe\chrome.sync"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "KSword.Sandbox.Agent.exe",
                CommandLine = @"odbcconf.exe /A {REGSVR C:\Users\Public\payload.dll}"
            }
        ];
    }

    private static HashSet<string> ReadMitreTechniqueIds(string mitreMapPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(mitreMapPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("techniques", out var techniques), "MITRE map should contain a techniques array.");

        var techniqueIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var technique in techniques.EnumerateArray())
        {
            if (!technique.TryGetProperty("id", out var idElement))
            {
                continue;
            }

            var id = idElement.GetString();
            if (!string.IsNullOrWhiteSpace(id))
            {
                techniqueIds.Add(id);
            }
        }

        return techniqueIds;
    }
}
