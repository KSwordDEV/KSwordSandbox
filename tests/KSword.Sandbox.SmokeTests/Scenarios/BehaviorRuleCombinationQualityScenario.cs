using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies high-signal combination rules for Windows behavior coverage.
/// Inputs are repository rule files plus synthetic runtime/correlation rows;
/// processing checks metadata, MITRE map coverage, positive matches, and
/// collector/self-noise false-positive guards; the scenario returns pass/fail
/// metadata.
/// </summary>
internal sealed class BehaviorRuleCombinationQualityScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "combo-persistence-runkey-dropped-payload",
        "combo-defense-evasion-defender-exclusion-dropped-payload",
        "combo-discovery-security-tool-process-list",
        "combo-credential-file-search-user-profile",
        "combo-c2-user-writable-payload-periodic-flow",
        "combo-anti-sandbox-vm-check-long-sleep",
        "combo-dropped-file-script-download-artifact"
    ];

    private static readonly string[] RequiredTechniqueIds =
    [
        "T1518",
        "T1518.001",
        "T1552",
        "T1552.001"
    ];

    public string ScenarioId => "behavior.rules-combination-quality";

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
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"Combination rule '{ruleId}' is missing.");
            AssertCombinationRuleShape(rule!);
        }

        var techniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredTechniqueIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        var engine = new RuleEngine(rules);
        var findingIds = engine.Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic combination event should match '{ruleId}'.");
        }

        AssertCollectorSelfNoiseDoesNotMatch(engine);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} combination rules match positive evidence and ignore collector/self-noise rows."
        });
    }

    private static void AssertCombinationRuleShape(BehaviorRule rule)
    {
        SmokeAssert.True(rule.Tags.Contains("combination", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should be tagged as a combination rule.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueName), $"Rule '{rule.Id}' should include a MITRE technique name.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(rule.EventTypes.Count > 0, $"Rule '{rule.Id}' should declare event types.");
        SmokeAssert.True(
            rule.AllContainsPath.Count > 0 ||
            rule.CommandLineRegex.Count > 0 ||
            rule.DataContains.Count > 0 ||
            rule.AllDataContains.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataRegex.Count > 0 ||
            rule.DataContainsAll.Count > 0 ||
            rule.AllDataNumericRanges.Count > 0,
            $"Rule '{rule.Id}' should require combined path, command-line, data, regex, or numeric evidence.");
        SmokeAssert.True(
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.Agent.exe", StringComparer.OrdinalIgnoreCase) ||
            rule.ExcludeDataContains.Count > 0,
            $"Rule '{rule.Id}' should include collector/self-noise exclusions.");
    }

    private static void AssertCollectorSelfNoiseDoesNotMatch(RuleEngine engine)
    {
        var findings = engine.Classify(CreateCollectorSelfNoiseEvents());
        var unexpected = findings
            .Where(finding => RequiredRuleIds.Contains(finding.RuleId, StringComparer.OrdinalIgnoreCase))
            .Select(finding => finding.RuleId)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();

        SmokeAssert.True(
            unexpected.Count == 0,
            "Collector/self-noise rows should not trigger combination rules: " + string.Join(", ", unexpected));
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Smoke",
                Data =
                {
                    ["value"] = @"C:\Users\Smoke\AppData\Roaming\payload.exe",
                    ["sourceEventType"] = "artifact.dropped_file.copied",
                    ["correlation"] = "dropped payload promoted to Run key"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                Data =
                {
                    ["valueName"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                    ["sourceEventType"] = "file.created",
                    ["correlation"] = "dropped staged-payload exclusion"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "cmd.exe",
                CommandLine = "cmd.exe /c tasklist /svc | findstr /i \"MsMpEng WinDefend Sense procmon wireshark\""
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "cmd.exe",
                CommandLine = @"cmd.exe /c dir C:\Users\Smoke\Documents /s /b | findstr /i ""password secret token kdbx"""
            },
            new SandboxEvent
            {
                EventType = "network.flow",
                Source = "guest",
                Data =
                {
                    ["processPath"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                    ["destinationIp"] = "198.51.100.44",
                    ["destinationPort"] = "443",
                    ["beaconIntervalMs"] = "60000",
                    ["jitterPercent"] = "12",
                    ["classification"] = "periodic c2 beacon"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["check"] = "vm artifact check before sleep gate",
                    ["durationMs"] = "600000",
                    ["classification"] = "anti-sandbox sandbox-evasion"
                }
            },
            new SandboxEvent
            {
                EventType = "artifact.dropped_file.copied",
                Source = "guest",
                Path = @"C:\KSwordSandbox\out\artifacts\dropped-files\payload.ps1",
                Data =
                {
                    ["sourcePath"] = @"C:\Users\Smoke\Downloads\payload.ps1",
                    ["sourceProcessName"] = "powershell.exe",
                    ["sourceUrl"] = "https://example.invalid/payload.ps1",
                    ["artifactRelativePath"] = "artifacts/dropped-files/payload.ps1"
                }
            }
        ];
    }

    private static IReadOnlyList<SandboxEvent> CreateCollectorSelfNoiseEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ShouldNotMatch",
                Data =
                {
                    ["value"] = @"C:\Users\Smoke\AppData\Roaming\payload.exe",
                    ["sourceEventType"] = "artifact.dropped_file.copied",
                    ["component"] = "KSword.Sandbox.R0Collector",
                    ["message"] = "collection health"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Path = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                Data =
                {
                    ["valueName"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                    ["sourceEventType"] = "file.created",
                    ["component"] = "KSword.Sandbox.R0Collector",
                    ["message"] = "collection health"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                CommandLine = "cmd.exe /c tasklist /svc | findstr /i MsMpEng WinDefend",
                Data =
                {
                    ["component"] = "KSword.Sandbox.R0Collector"
                }
            },
            new SandboxEvent
            {
                EventType = "network.flow",
                Source = "virustotal",
                Data =
                {
                    ["processPath"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                    ["destinationIp"] = "198.51.100.44",
                    ["beaconIntervalMs"] = "60000",
                    ["jitterPercent"] = "12",
                    ["classification"] = "periodic c2 beacon",
                    ["status"] = "not_configured",
                    ["message"] = "VirusTotal not configured"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Data =
                {
                    ["check"] = "vm artifact check before sleep gate",
                    ["durationMs"] = "600000",
                    ["classification"] = "anti-sandbox sandbox-evasion",
                    ["message"] = "collection health"
                }
            },
            new SandboxEvent
            {
                EventType = "artifact.dropped_file.copied",
                Source = "guest",
                ProcessName = "KSword.Sandbox.Agent.exe",
                Data =
                {
                    ["sourcePath"] = @"C:\Users\Smoke\Downloads\payload.ps1",
                    ["sourceProcessName"] = "powershell.exe",
                    ["sourceUrl"] = "https://example.invalid/payload.ps1",
                    ["component"] = "KSword.Sandbox.Agent"
                }
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
