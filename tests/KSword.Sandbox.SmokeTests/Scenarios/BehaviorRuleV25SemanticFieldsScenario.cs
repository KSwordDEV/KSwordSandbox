using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Fast repository-only guard for the v25 semantic-field rule batch. Inputs are
/// behavior-rules.json plus synthetic DNS/HTTP/TLS/artifact/R0 rows; processing
/// verifies that the new rules consume structured fields already emitted by the
/// project and keep collection-only evidence as metadata.
/// </summary>
internal sealed class BehaviorRuleV25SemanticFieldsScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "dns-answer-private-or-loopback-scope",
        "dns-answer-fastflux-public-scope-low-ttl",
        "http-transfer-executable-download-hints",
        "http-transfer-authenticated-upload-hints",
        "tls-cert-common-name-ip-or-dynamic-host",
        "tls-cert-invalid-validity-window",
        "artifact-evidence-matrix-selectors-ready",
        "r0-backpressure-or-loss-observed"
    ];

    public string ScenarioId => "behavior.rules-v25-semantic-fields";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(
            string.Equals(rules.Version, "2026-07-12-v25-r0-file-network-semantic-fields", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(rules.Version, "2026-07-12-v26-self-noise-guard-hardening", StringComparison.OrdinalIgnoreCase),
            "Behavior rules should carry the v25 R0/file/network semantic-field version or newer v26 self-noise hardening version.");

        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"v25 semantic-field rule '{ruleId}' is missing.");
            SmokeAssert.True(rule!.EvidenceFields.Count > 0, $"Rule '{ruleId}' should document evidence fields.");
            SmokeAssert.True(rule.Tags.Contains("semantic-field", StringComparer.OrdinalIgnoreCase) || rule.Tags.Contains("metadata", StringComparer.OrdinalIgnoreCase), $"Rule '{ruleId}' should identify semantic-field or metadata evidence.");
        }

        var findingIds = new RuleEngine(rules).Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic v25 semantic-field event should match '{ruleId}'.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} v25 semantic-field rules matched structured DNS/HTTP/TLS/artifact/R0 evidence."
        });
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["queryName"] = "gate.example.invalid",
                    ["answerScope"] = "private,rfc1918",
                    ["answerAddresses"] = "10.0.0.4,192.168.56.8",
                    ["answerCount"] = "2",
                    ["sourceArtifactRelativePath"] = "packet-captures/after-run.pcapng"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["queryName"] = "rotating.example.invalid",
                    ["answerScope"] = "public,multi-asn,fastflux",
                    ["answerCount"] = "6",
                    ["minimumTtlSeconds"] = "30",
                    ["answerAsns"] = "64500,64501,64502"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["method"] = "GET",
                    ["host"] = "download.example.invalid",
                    ["uri"] = "/stage/payload.exe",
                    ["responseContentType"] = "application/octet-stream",
                    ["contentDisposition"] = "attachment; filename=payload.exe",
                    ["transferHint"] = "executable download",
                    ["bodyMagic"] = "MZ"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["method"] = "POST",
                    ["host"] = "api.example.invalid",
                    ["uri"] = "/upload",
                    ["direction"] = "upload",
                    ["requestBodyBytes"] = "2097152",
                    ["transferEncoding"] = "chunked,gzip",
                    ["authorizationPresent"] = "true"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["sni"] = "203.0.113.10",
                    ["certificateCommonName"] = "203.0.113.10",
                    ["certificateIssuer"] = "CN=Self Signed",
                    ["destinationIp"] = "203.0.113.10"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.tls",
                Source = "host",
                Data =
                {
                    ["sni"] = "expired.example.invalid",
                    ["certificateCommonName"] = "expired.example.invalid",
                    ["certificateNotBefore"] = "2020-01-01T00:00:00Z",
                    ["certificateNotAfter"] = "2020-02-01T00:00:00Z",
                    ["certificateValidity"] = "expired"
                }
            },
            new SandboxEvent
            {
                EventType = "artifact.import_summary",
                Source = "host",
                Data =
                {
                    ["behaviorCounted"] = "false",
                    ["nonbehavior"] = "true",
                    ["hostImport"] = "true",
                    ["artifactEvidenceMatrix"] = "dropped-files=1:ready:4096;screenshots=1:ready:4;memory-dumps=1:ready:8192;packet-captures=1:ready:24",
                    ["primaryArtifactSelectors"] = "dropped-files:artifacts/dropped-files/payload.exe,screenshots:screenshots/after-run.bmp,memory-dumps:memory-dumps/after-run.dmp,packet-captures:packet-captures/after-run.pcapng",
                    ["screenshotArtifactCount"] = "1",
                    ["memoryDumpArtifactCount"] = "1",
                    ["packetCaptureArtifactCount"] = "1",
                    ["downloadSecurityPolicy"] = "server-indexed-relative-selector"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.driverHealth",
                Source = "r0collector",
                Data =
                {
                    ["queueDepth"] = "4096",
                    ["queueCapacity"] = "4096",
                    ["queueHighWatermark"] = "4096",
                    ["totalEventsDropped"] = "7",
                    ["lossObserved"] = "true",
                    ["backpressureObserved"] = "true",
                    ["backpressureReason"] = "events-dropped"
                }
            }
        ];
    }
}
