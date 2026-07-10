using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that static-analysis behavior rules load and that key MITRE
/// mappings are present. Inputs are repository paths from SmokeTestContext;
/// processing loads JSON rules and MITRE seed data plus classifies a synthetic
/// static-analysis event; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class StaticRulesMitreScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredStaticRuleIds =
    [
        "static-pe-known-packer",
        "static-pe-high-entropy-sections",
        "static-embedded-url",
        "static-pe-imports-present",
        "static-import-suspicious-api",
        "static-import-process-injection",
        "static-import-network-api",
        "static-import-persistence-api",
        "static-import-anti-analysis-api",
        "static-pe-tls-callbacks",
        "static-pe-exports-present",
        "static-export-registration-entrypoint",
        "static-export-service-entrypoint"
    ];

    private static readonly string[] RequiredMitreTechniqueIds =
    [
        "T1027",
        "T1027.002",
        "T1055",
        "T1059",
        "T1070.004",
        "T1105",
        "T1106",
        "T1112",
        "T1218.010",
        "T1497.003",
        "T1543.003",
        "T1547.001",
        "T1622"
    ];

    public string ScenarioId => "static.rules-mitre-depth";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        var mitreMapPath = Path.Combine(context.RulesDirectory, "mitre-windows-map.json");
        var staticNotesPath = Path.Combine(context.RulesDirectory, "static-notes.yar");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");
        SmokeAssert.True(File.Exists(mitreMapPath), "mitre-windows-map.json is missing.");
        SmokeAssert.True(File.Exists(staticNotesPath), "static-notes.yar is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(rules.Rules.Count > 0, "Behavior rules should load.");
        var ruleIds = rules.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredStaticRuleIds)
        {
            SmokeAssert.True(ruleIds.Contains(ruleId), $"Static rule '{ruleId}' is missing.");
        }

        AssertSyntheticStaticRuleMatches(rules);
        AssertMitreMappings(mitreMapPath, rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Static rules load, synthetic static tags classify, and key MITRE mappings are present."
        });
    }

    /// <summary>
    /// Classifies one synthetic static-analysis event with the new tags.
    /// Inputs are loaded rules, processing runs RuleEngine over representative
    /// static tags, and the method returns no value when expected rules match.
    /// </summary>
    private static void AssertSyntheticStaticRuleMatches(BehaviorRuleSet rules)
    {
        var engine = new RuleEngine(rules);
        var findings = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "static.analysis.completed",
                Source = "host",
                Path = "synthetic-static-depth.exe",
                Data =
                {
                    ["tags"] = string.Join(
                        ",",
                        [
                            "packer_upx",
                            "high_entropy_section",
                            "url",
                            "imports_present",
                            "import_suspicious_api",
                            "import_process_injection_api",
                            "import_network_api",
                            "import_persistence_api",
                            "import_anti_analysis_api",
                            "tls_callbacks",
                            "exports_present",
                            "export_registration_entrypoint",
                            "export_service_entrypoint"
                        ])
                }
            }
        ]);

        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredStaticRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic static tags should match '{ruleId}'.");
        }
    }

    /// <summary>
    /// Verifies that the MITRE seed map contains key and rule-referenced IDs.
    /// Inputs are the MITRE map path and loaded rules, processing parses JSON
    /// and compares IDs, and the method returns no value on success.
    /// </summary>
    private static void AssertMitreMappings(string mitreMapPath, BehaviorRuleSet rules)
    {
        var techniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredMitreTechniqueIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        var mappedRuleIds = rules.Rules
            .Select(rule => rule.MitreTechniqueId)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var techniqueId in mappedRuleIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"Rule-referenced MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }
    }

    /// <summary>
    /// Reads MITRE technique IDs from the local seed map.
    /// The input is a JSON file path, processing reads `techniques[].id`, and
    /// the method returns a case-insensitive set.
    /// </summary>
    private static HashSet<string> ReadMitreTechniqueIds(string mitreMapPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(mitreMapPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("techniques", out var techniques), "MITRE map should contain a techniques array.");
        SmokeAssert.True(techniques.ValueKind == JsonValueKind.Array, "MITRE techniques should be an array.");

        var techniqueIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var technique in techniques.EnumerateArray())
        {
            if (technique.TryGetProperty("id", out var idElement))
            {
                var id = idElement.GetString();
                if (!string.IsNullOrWhiteSpace(id))
                {
                    techniqueIds.Add(id);
                }
            }
        }

        return techniqueIds;
    }
}
