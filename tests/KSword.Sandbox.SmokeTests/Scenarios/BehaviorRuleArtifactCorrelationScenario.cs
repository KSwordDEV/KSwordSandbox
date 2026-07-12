using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies artifact-backed correlation rules without live Hyper-V,
/// signing, or external enrichment calls. Inputs are repository rules plus
/// synthetic artifact/PCAP/process-tree/VT rows; processing checks narrow
/// predicates and quiet-state/self-noise suppression; output is a smoke result.
/// </summary>
internal sealed class BehaviorRuleArtifactCorrelationScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "artifact-memory-dump-process-correlation",
        "artifact-dropped-file-source-correlation",
        "artifact-screenshot-capture-correlation",
        "artifact-pcap-protocol-correlation",
        "process-tree-lineage-user-writable-descendant",
        "virustotal-found-result-enrichment"
    ];

    public string ScenarioId => "behavior.rules-artifact-correlation-guards";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(
            string.Equals(rules.Version, "2026-07-12-v22-defensive-behavior-expansion", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v25-r0-file-network-semantic-fields", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v26-self-noise-guard-hardening", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v27-behavior-rule-expansion", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v28-behavior-rule-expansion", StringComparison.OrdinalIgnoreCase),
            "Behavior rules should carry the v22+ defensive behavior expansion or newer self-noise/behavior hardening version while retaining v19 artifact-correlation rules.");

        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"Artifact-correlation rule '{ruleId}' is missing.");
            AssertRuleContract(rule!);
        }

        var engine = new RuleEngine(rules);
        var positiveFindingIds = engine.Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(positiveFindingIds.Contains(ruleId), $"Synthetic artifact-correlation event should match '{ruleId}'.");
        }

        var noiseFindingIds = engine.Classify(CreateNoiseEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(!noiseFindingIds.Contains(ruleId), $"Collection/VT/R0 self-noise should not match artifact-correlation rule '{ruleId}'.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} artifact-correlation rules match concrete artifact-backed rows and suppress quiet/self-noise rows."
        });
    }

    private static void AssertRuleContract(BehaviorRule rule)
    {
        SmokeAssert.True(rule.EventTypes.Count > 0, $"Rule '{rule.Id}' should declare event types.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(rule.Tags.Count > 0, $"Rule '{rule.Id}' should include report tags.");

        if (rule.Id.StartsWith("artifact-", StringComparison.OrdinalIgnoreCase))
        {
            SmokeAssert.True(rule.Tags.Contains("artifact", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should be tagged as artifact evidence.");
            SmokeAssert.True(rule.Tags.Contains("correlation", StringComparer.OrdinalIgnoreCase), $"Rule '{rule.Id}' should be tagged as correlation evidence.");
            SmokeAssert.True(
                rule.AllDataKeys.Contains("sourceArtifactRelativePath", StringComparer.OrdinalIgnoreCase) &&
                rule.AllDataKeys.Contains("sourceArtifactSha256", StringComparer.OrdinalIgnoreCase),
                $"Rule '{rule.Id}' should require artifact path and hash fields.");
            SmokeAssert.True(rule.AllDataRegex.ContainsKey("sourceArtifactSha256"), $"Rule '{rule.Id}' should constrain sourceArtifactSha256 shape.");
            SmokeAssert.True(rule.AllDataNumericRanges.ContainsKey("sourceArtifactSizeBytes"), $"Rule '{rule.Id}' should require a positive artifact size.");
            AssertNoiseGuard(rule);
        }

        if (string.Equals(rule.Id, "process-tree-lineage-user-writable-descendant", StringComparison.OrdinalIgnoreCase))
        {
            SmokeAssert.True(rule.Tags.Contains("lineage", StringComparer.OrdinalIgnoreCase), "Process-tree rule should be tagged as lineage.");
            SmokeAssert.True(rule.AllDataKeys.Contains("treeLineage", StringComparer.OrdinalIgnoreCase), "Process-tree rule should require treeLineage.");
            SmokeAssert.True(rule.AllDataNumericRanges.ContainsKey("treeDepth"), "Process-tree rule should require numeric treeDepth.");
            SmokeAssert.True(rule.PathRegex.Count > 0, "Process-tree rule should constrain user-writable payload path.");
            AssertNoiseGuard(rule);
        }

        if (string.Equals(rule.Id, "virustotal-found-result-enrichment", StringComparison.OrdinalIgnoreCase))
        {
            SmokeAssert.True(string.Equals(rule.Severity, "info", StringComparison.OrdinalIgnoreCase), "VT found-result rule should stay info severity.");
            SmokeAssert.True(string.IsNullOrWhiteSpace(rule.MitreTechniqueId), "VT found-result rule should not invent an ATT&CK mapping.");
            SmokeAssert.True(rule.Tags.Contains("virustotal", StringComparer.OrdinalIgnoreCase), "VT found-result rule should be tagged as VirusTotal enrichment.");
            SmokeAssert.True(rule.Tags.Contains("metadata", StringComparer.OrdinalIgnoreCase), "VT found-result rule should be metadata.");
            SmokeAssert.True(
                rule.AllDataEquals.TryGetValue("vtStatus", out var values) &&
                values.Contains("found", StringComparer.OrdinalIgnoreCase),
                "VT found-result rule should require exact vtStatus=found.");
        }
    }

    private static void AssertNoiseGuard(BehaviorRule rule)
    {
        SmokeAssert.True(
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.Agent.exe", StringComparer.OrdinalIgnoreCase) &&
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.R0Collector.exe", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should exclude sandbox plumbing process names.");
        SmokeAssert.True(rule.ExcludeDataContains.Count > 0, $"Rule '{rule.Id}' should exclude collection-health/VT/R0 metadata.");
        SmokeAssert.True(
            rule.ExcludeDataContains.TryGetValue("vtStatus", out var vtStates) &&
            vtStates.Contains("not_configured", StringComparer.OrdinalIgnoreCase) &&
            vtStates.Contains("not_found", StringComparer.OrdinalIgnoreCase) &&
            vtStates.Contains("rate_limited", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should suppress quiet VirusTotal states.");
        SmokeAssert.True(
            rule.ExcludeDataContains.TryGetValue("collectorSelfNoise", out var collectorNoise) &&
            collectorNoise.Contains("true", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should suppress R0 collector self-noise.");
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            HostImportedArtifact(
                "MemoryDump",
                "memory-dumps",
                "memory-dump",
                "memory_dump.captured",
                "memory-dumps/sample-pid4242.dmp",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["processId"] = "4242",
                    ["rootProcessId"] = "4242",
                    ["treeLineage"] = "4242"
                }),
            HostImportedArtifact(
                "DroppedFile",
                "dropped-files",
                "dropped-file",
                "artifact.dropped_file.copied",
                "artifacts/dropped-files/payload.exe",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["sourceEventPath"] = @"C:\Users\Public\payload.exe",
                    ["processName"] = "payload.exe",
                    ["commandLine"] = @"C:\Users\Public\payload.exe"
                }),
            HostImportedArtifact(
                "Screenshot",
                "screenshots",
                "screenshot",
                "screenshot.captured",
                "screenshots/after-run.bmp",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["phase"] = "after-run",
                    ["widthPixels"] = "1024",
                    ["heightPixels"] = "768"
                }),
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["collectionName"] = "packet-captures",
                    ["sourceArtifactRelativePath"] = "packet-captures/future.pcapng",
                    ["sourceArtifactSha256"] = Sha256('d'),
                    ["sourceArtifactSizeBytes"] = "4096",
                    ["protocol"] = "http",
                    ["host"] = "download.example.invalid",
                    ["uri"] = "/payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                ProcessName = "payload.exe",
                ProcessId = 6000,
                ParentProcessId = 5000,
                Path = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                Data =
                {
                    ["rootProcessId"] = "4242",
                    ["parentProcessId"] = "5000",
                    ["treeDepth"] = "2",
                    ["treeLineage"] = "4242>5000>6000",
                    ["childProcessCount"] = "0"
                }
            },
            new SandboxEvent
            {
                EventType = "enrichment.virustotal.lookup",
                Source = "virustotal",
                Data =
                {
                    ["sha256"] = Sha256('e'),
                    ["vtStatus"] = "found",
                    ["status"] = "found",
                    ["vtVerdict"] = "clean",
                    ["verdict"] = "clean",
                    ["vtMalicious"] = "0",
                    ["vtSuspicious"] = "0",
                    ["permalink"] = "https://www.virustotal.com/gui/file/" + Sha256('e')
                }
            }
        ];
    }

    private static IReadOnlyList<SandboxEvent> CreateNoiseEvents()
    {
        var memoryHealth = HostImportedArtifact(
            "MemoryDump",
            "memory-dumps",
            "memory-dump",
            "memory_dump.captured",
            "memory-dumps/sample-pid4242.dmp",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["processId"] = "4242",
                ["status"] = "skipped",
                ["healthStatus"] = "collection-health"
            });

        var droppedAgentNoise = HostImportedArtifact(
            "DroppedFile",
            "dropped-files",
            "dropped-file",
            "artifact.dropped_file.copied",
            "artifacts/dropped-files/payload.exe",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["sourceEventPath"] = @"C:\Users\Public\payload.exe",
                ["processName"] = "KSword.Sandbox.Agent.exe",
                ["component"] = "KSword.Sandbox.Agent"
            }) with
        {
            ProcessName = "KSword.Sandbox.Agent.exe"
        };

        var screenshotHealth = HostImportedArtifact(
            "Screenshot",
            "screenshots",
            "screenshot",
            "screenshot.captured",
            "screenshots/after-run.bmp",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["healthStatus"] = "collection-health",
                ["message"] = "collection health"
            });

        return
        [
            memoryHealth,
            droppedAgentNoise,
            screenshotHealth,
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["collectionName"] = "packet-captures",
                    ["sourceArtifactRelativePath"] = "packet-captures/future.pcapng",
                    ["sourceArtifactSha256"] = Sha256('f'),
                    ["sourceArtifactSizeBytes"] = "4096",
                    ["protocol"] = "http",
                    ["host"] = "download.example.invalid",
                    ["vtStatus"] = "not_configured"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Path = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                Data =
                {
                    ["rootProcessId"] = "4242",
                    ["parentProcessId"] = "5000",
                    ["treeDepth"] = "2",
                    ["treeLineage"] = "4242>5000>6000",
                    ["collectorSelfNoise"] = "true"
                }
            },
            CreateVirusTotalQuietEvent("not_found"),
            CreateVirusTotalQuietEvent("rate_limited"),
            CreateVirusTotalQuietEvent("not_configured"),
            new SandboxEvent
            {
                EventType = "enrichment.virustotal.lookup",
                Source = "virustotal",
                Data =
                {
                    ["sha256"] = Sha256('a'),
                    ["vtStatus"] = "found",
                    ["vtVerdict"] = "clean"
                }
            }
        ];
    }

    private static SandboxEvent HostImportedArtifact(
        string artifactKind,
        string collectionName,
        string evidenceRole,
        string sourceEventType,
        string relativePath,
        Dictionary<string, string> extraData)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["artifactKind"] = artifactKind,
            ["sourceArtifactKind"] = artifactKind,
            ["collectionName"] = collectionName,
            ["evidenceRole"] = evidenceRole,
            ["sourceEventType"] = sourceEventType,
            ["isDownloadable"] = "true",
            ["sourceArtifactRelativePath"] = relativePath,
            ["artifactRelativePath"] = relativePath,
            ["sourceArtifactSha256"] = Sha256('a'),
            ["sourceArtifactSizeBytes"] = "8192"
        };

        foreach (var pair in extraData)
        {
            data[pair.Key] = pair.Value;
        }

        return new SandboxEvent
        {
            EventType = "artifact.host_imported",
            Source = "host",
            Path = @"C:\KSwordSandbox\jobs\synthetic\" + relativePath.Replace('/', '\\'),
            Data = data
        };
    }

    private static SandboxEvent CreateVirusTotalQuietEvent(string status)
    {
        return new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Source = "virustotal",
            Data =
            {
                ["sha256"] = Sha256(status[0]),
                ["vtStatus"] = status,
                ["status"] = status,
                ["vtVerdict"] = status,
                ["permalink"] = "https://www.virustotal.com/gui/file/" + Sha256(status[0])
            }
        };
    }

    private static string Sha256(char value)
    {
        return new string(char.ToLowerInvariant(value), 64);
    }
}
