using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the v23 high-signal Windows behavior expansion with synthetic
/// evidence only; no live VM, signing, or heavyweight E2E paths are used.
/// </summary>
internal sealed class BehaviorRuleHighSignalWindowsV23Scenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "persistence-time-provider-user-writable-dll",
        "persistence-netsh-helper-user-writable-dll",
        "persistence-screensaver-executable-user-writable",
        "injection-process-doppelganging-transaction-sequence",
        "injection-process-ghosting-delete-pending-section",
        "lateral-dcom-excel-application-remote-launch",
        "lateral-smb-psexesvc-pipe-or-service",
        "anti-sandbox-human-interaction-gated-exit",
        "anti-sandbox-vm-service-registry-probe-gate",
        "download-execute-office-remote-template-launch"
    ];

    private static readonly HashSet<string> RequiredRuleIdSet = new(RequiredRuleIds, StringComparer.OrdinalIgnoreCase);

    public string ScenarioId => "behavior.rules-high-signal-windows-v23";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        var mitreMapPath = Path.Combine(context.RulesDirectory, "mitre-windows-map.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");
        SmokeAssert.True(File.Exists(mitreMapPath), "mitre-windows-map.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(
            string.Equals(rules.Version, "2026-07-12-v23-high-signal-behavior-expansion", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v25-r0-file-network-semantic-fields", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v26-self-noise-guard-hardening", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v27-behavior-rule-expansion", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v28-behavior-rule-expansion", StringComparison.OrdinalIgnoreCase),
            "Behavior rules should carry the v23+ high-signal behavior expansion or newer self-noise/behavior hardening version.");

        var mitreTechniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"v23 high-signal rule '{ruleId}' is missing.");
            AssertRuleShape(rule!, mitreTechniqueIds);
        }

        var engine = new RuleEngine(rules);
        var positiveRuleIds = engine.Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(positiveRuleIds.Contains(ruleId), $"Synthetic v23 event should match '{ruleId}'.");
        }

        var noiseRuleIds = engine.Classify(CreateNoiseEvents())
            .Where(finding => RequiredRuleIdSet.Contains(finding.RuleId))
            .Select(finding => finding.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        SmokeAssert.True(
            noiseRuleIds.Count == 0,
            "Collection/VT/R0/self-noise should not trigger v23 rules: " + string.Join(", ", noiseRuleIds));

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} v23 high-signal Windows behavior rules match constrained evidence and suppress collection/VT/R0 noise."
        });
    }

    private static void AssertRuleShape(BehaviorRule rule, HashSet<string> mitreTechniqueIds)
    {
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.Title), $"Rule '{rule.Id}' should include an English title.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.Summary), $"Rule '{rule.Id}' should include an English summary.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(mitreTechniqueIds.Contains(rule.MitreTechniqueId!), $"Rule '{rule.Id}' MITRE technique '{rule.MitreTechniqueId}' is missing from mitre-windows-map.json.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(rule.Tags.Contains("mitre", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should carry a mitre tag.");
        SmokeAssert.True(HasStrongPredicate(rule), $"Rule '{rule.Id}' should use constrained regex/all/exact/numeric predicates.");
        SmokeAssert.True(
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.Agent.exe", StringComparer.OrdinalIgnoreCase) &&
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.R0Collector.exe", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should exclude sandbox plumbing process names.");
        SmokeAssert.True(
            ContainsGuard(rule.ExcludeDataContains, "source", "virustotal") &&
            ContainsGuard(rule.ExcludeDataContains, "source", "r0collector") &&
            ContainsGuard(rule.ExcludeDataContains, "vtStatus", "not_configured") &&
            ContainsGuard(rule.ExcludeDataContains, "healthStatus", "collection-health") &&
            ContainsGuard(rule.ExcludeDataContains, "collectorSelfNoise", "true") &&
            ContainsGuard(rule.ExcludeDataContains, "collectorNoise", "true") &&
            ContainsGuard(rule.ExcludeDataEquals, "behaviorCounted", "false") &&
            ContainsGuard(rule.ExcludeDataEquals, "nonbehavior", "true"),
            $"Rule '{rule.Id}' should guard collection, VT, behaviorCounted/nonbehavior, and R0/self-noise data.");
    }

    private static bool HasStrongPredicate(BehaviorRule rule)
    {
        return rule.CommandLineRegex.Count > 0 ||
            rule.DataContainsAll.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataRegex.Count > 0;
    }

    private static bool ContainsGuard(IReadOnlyDictionary<string, List<string>> guards, string key, string expected)
    {
        return guards.TryGetValue(key, out var values) &&
            values.Any(value => value.Contains(expected, StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\SmokeProvider\DllName",
                Data =
                {
                    ["path"] = @"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\SmokeProvider",
                    ["valueName"] = "DllName",
                    ["value"] = @"C:\Users\Public\timeprov.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SOFTWARE\Microsoft\NetSh\SmokeHelper",
                Data =
                {
                    ["path"] = @"HKLM\SOFTWARE\Microsoft\NetSh\SmokeHelper",
                    ["valueName"] = "HelperDll",
                    ["value"] = @"C:\ProgramData\netshhelper.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Control Panel\Desktop\SCRNSAVE.EXE",
                Data =
                {
                    ["path"] = @"HKCU\Control Panel\Desktop\SCRNSAVE.EXE",
                    ["valueName"] = "SCRNSAVE.EXE",
                    ["value"] = @"C:\Users\Smoke\AppData\Roaming\screen.scr"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sequence",
                Source = "guest",
                Data =
                {
                    ["operation"] = "CreateTransaction CreateFileTransacted WriteFile CreateSection CreateProcess",
                    ["targetProcessName"] = "svchost.exe",
                    ["imagePath"] = @"C:\Users\Public\txpayload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.image",
                Source = "guest",
                Data =
                {
                    ["operation"] = "delete-pending CreateSection SEC_IMAGE NtCreateProcessEx",
                    ["imagePath"] = @"C:\Users\Public\ghost.exe",
                    ["targetProcessName"] = "ghost.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = "powershell.exe [type]::GetTypeFromProgID('Excel.Application','server01')",
                Data =
                {
                    ["remoteHost"] = "server01",
                    ["comClass"] = "Excel.Application"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.smb",
                Source = "host",
                Data =
                {
                    ["pipeName"] = @"\PIPE\PSEXESVC",
                    ["serviceName"] = "PSEXESVC",
                    ["shareName"] = "ADMIN$"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                Data =
                {
                    ["check"] = "GetCursorPos mouse click count",
                    ["action"] = "exit gate"
                }
            },
            new SandboxEvent
            {
                EventType = "anti_sandbox.check",
                Source = "guest",
                Data =
                {
                    ["check"] = "registry service vmware virtualbox",
                    ["artifact"] = @"HKLM\SYSTEM\CurrentControlSet\Services\VBoxService",
                    ["action"] = "terminate"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                ProcessName = "winword.exe",
                CommandLine = "winword.exe https://docs.example.test/template.dotm",
                Data =
                {
                    ["sourceUrl"] = "https://docs.example.test/template.dotm",
                    ["executedPath"] = @"C:\Users\Smoke\AppData\Local\Temp\upd.exe"
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
                EventType = "registry.set",
                Source = "r0collector",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\SmokeProvider",
                Data =
                {
                    ["source"] = "r0collector",
                    ["collectorSelfNoise"] = "true",
                    ["path"] = @"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\SmokeProvider",
                    ["valueName"] = "DllName",
                    ["value"] = @"C:\Users\Public\timeprov.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "KSword.Sandbox.Agent.exe",
                CommandLine = "powershell.exe [type]::GetTypeFromProgID('Excel.Application','server01')",
                Data =
                {
                    ["remoteHost"] = "server01",
                    ["comClass"] = "Excel.Application"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "virustotal",
                ProcessName = "winword.exe",
                CommandLine = "winword.exe https://docs.example.test/template.dotm",
                Data =
                {
                    ["source"] = "virustotal",
                    ["vtStatus"] = "not_configured",
                    ["sourceUrl"] = "https://docs.example.test/template.dotm",
                    ["executedPath"] = @"C:\Users\Smoke\AppData\Local\Temp\upd.exe"
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
