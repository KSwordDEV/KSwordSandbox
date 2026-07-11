using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the latest behavior-rule quality expansion: each new rule has
/// stable metadata and can be hit by events made only from current
/// SandboxEvent, guest, R0, and PCAP fields.
/// </summary>
internal sealed class BehaviorRuleMitreQualityScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "office-addin-persistence-registry",
        "office-startup-folder-persistence",
        "accessibility-features-ifeo-persistence",
        "logon-script-file-persistence",
        "mavinject-process-injection-command",
        "installutil-proxy-execution-command",
        "msbuild-inline-task-proxy-execution",
        "regasm-regsvcs-proxy-execution-command",
        "lsass-dump-file-created",
        "clipboard-collection-api-observed",
        "screenshot-file-created-by-sample",
        "anti-analysis-uptime-check-command",
        "anti-analysis-parent-process-check-api",
        "windows-credential-staging-command",
        "domain-trust-discovery-command",
        "tor-hidden-service-domain",
        "http-long-encoded-uri-c2",
        "http-domain-fronting-indicator",
        "tls-c2-indicator-fields",
        "process-tree-office-spawned-script",
        "process-tree-browser-spawned-script-or-lolbin"
    ];

    private static readonly string[] RequiredTechniqueIds =
    [
        "T1115",
        "T1127.001",
        "T1218.004",
        "T1218.009",
        "T1482"
    ];

    private static readonly HashSet<string> AllowedSeverities = new(StringComparer.OrdinalIgnoreCase)
    {
        "info",
        "low",
        "medium",
        "high",
        "critical"
    };

    private static readonly HashSet<string> AllowedConfidences = new(StringComparer.OrdinalIgnoreCase)
    {
        "low",
        "medium",
        "high"
    };

    public string ScenarioId => "behavior.rules-mitre-quality-expansion";

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
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"Behavior quality rule '{ruleId}' is missing.");
            AssertRuleMetadata(rule!);
        }

        var findings = new RuleEngine(rules).Classify(CreateSyntheticEvents());
        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic behavior-quality event should match '{ruleId}'.");
        }

        var techniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredTechniqueIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"Behavior rule quality expansion loads and matches {RequiredRuleIds.Length} new rules."
        });
    }

    private static void AssertRuleMetadata(BehaviorRule rule)
    {
        SmokeAssert.True(AllowedSeverities.Contains(rule.Severity), $"Rule '{rule.Id}' has unsupported severity '{rule.Severity}'.");
        SmokeAssert.True(AllowedConfidences.Contains(rule.Confidence), $"Rule '{rule.Id}' has unsupported confidence '{rule.Confidence}'.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueName), $"Rule '{rule.Id}' should include a MITRE technique name.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields used for triage.");
        SmokeAssert.True(
            rule.EventTypes.Count > 0 &&
            (rule.ContainsPath.Count > 0 || rule.ContainsCommandLine.Count > 0 || rule.DataKeys.Count > 0 || rule.DataContains.Count > 0),
            $"Rule '{rule.Id}' should be constrained by event type plus path, command-line, or data evidence.");
    }

    private static IReadOnlyList<SandboxEvent> CreateSyntheticEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Microsoft\Office\Word\Addins\SmokeAddin",
                Data =
                {
                    ["valueName"] = "LoadBehavior",
                    ["value"] = "3"
                }
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = @"C:\Users\Smoke\AppData\Roaming\Microsoft\Word\STARTUP\payload.dotm"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
                Data =
                {
                    ["valueName"] = "Debugger",
                    ["value"] = @"C:\Windows\System32\cmd.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "file.modified",
                Source = "guest",
                Path = @"C:\Windows\System32\GroupPolicy\User\Scripts\Logon\logon.bat"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "mavinject.exe",
                CommandLine = @"mavinject.exe 4242 /INJECTRUNNING C:\Users\Public\payload.dll"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "InstallUtil.exe",
                CommandLine = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe C:\Users\Public\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "MSBuild.exe",
                CommandLine = @"MSBuild.exe C:\Users\Public\inline.proj /p:TaskFactory=CodeTaskFactory"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "regasm.exe",
                CommandLine = @"regasm.exe C:\Users\Public\payload.dll /codebase"
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "driver",
                Path = @"C:\Users\Public\lsass.dmp"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "OpenClipboard"
                }
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = @"C:\Users\Public\screenshot.png"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "wmic os get lastbootuptime"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "NtQueryInformationProcess",
                    ["operation"] = "ProcessBasicInformation parent process check"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"cmdkey.exe /add:TARGET /user:DOMAIN\smoke /pass:Secret"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "nltest /domain_trusts"
            },
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["queryName"] = "examplehiddenservice.onion",
                    ["queryType"] = "A"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["method"] = "GET",
                    ["host"] = "example.invalid",
                    ["uri"] = "/api/%2f%3d%2b",
                    ["classification"] = "encoded-uri beacon"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.tls",
                Source = "host",
                Data =
                {
                    ["sni"] = "front.example",
                    ["classification"] = "host-sni-mismatch domain-fronting"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["sni"] = "c2.example.invalid",
                    ["ja3"] = "00000000000000000000000000000000",
                    ["classification"] = "suspicious-tls c2"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                Data =
                {
                    ["treeLineage"] = "winword.exe -> powershell.exe -> rundll32.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                Data =
                {
                    ["treeLineage"] = "chrome.exe -> mshta.exe"
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
