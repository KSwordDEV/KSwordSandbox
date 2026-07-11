using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that VirusTotal enrichment quality has rule-facing verdicts and
/// clear local failure states without requiring a real API key.
/// </summary>
internal sealed class BehaviorRuleVirusTotalQualityScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "virustotal-malicious-verdict",
        "virustotal-suspicious-verdict",
        "virustotal-not-found",
        "virustotal-rate-limited",
        "virustotal-not-configured"
    ];

    public string ScenarioId => "behavior.rules-virustotal-quality";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"VirusTotal quality rule '{ruleId}' is missing.");
            SmokeAssert.True(rule!.Tags.Contains("virustotal", StringComparer.OrdinalIgnoreCase), $"Rule '{ruleId}' should be tagged as VirusTotal enrichment.");
            SmokeAssert.True(rule.Tags.Contains("enrichment", StringComparer.OrdinalIgnoreCase), $"Rule '{ruleId}' should be tagged as enrichment metadata.");
            SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{ruleId}' should document VT evidence fields.");
            SmokeAssert.True(string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{ruleId}' should not invent an ATT&CK mapping for external reputation metadata.");
        }

        AssertBilingualRuleMetadata(behaviorRulesPath);
        AssertSyntheticVirusTotalRuleMatches(rules);
        AssertVirusTotalInfrastructureContracts(context);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "VirusTotal enrichment rules match synthetic verdict events and infrastructure exposes clear local verdict/status fields."
        });
    }

    private static void AssertSyntheticVirusTotalRuleMatches(BehaviorRuleSet rules)
    {
        var findings = new RuleEngine(rules).Classify(
        [
            CreateVirusTotalEvent("malicious", "found", malicious: "4", suspicious: "1"),
            CreateVirusTotalEvent("suspicious", "found", malicious: "0", suspicious: "2"),
            CreateVirusTotalEvent("not_found", "not_found", httpStatusCode: "404"),
            CreateVirusTotalEvent("rate_limited", "rate_limited", httpStatusCode: "429"),
            CreateVirusTotalEvent("not_configured", "not_configured", configured: "false")
        ]);

        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic VirusTotal event should match '{ruleId}'.");
        }
    }

    private static SandboxEvent CreateVirusTotalEvent(
        string verdict,
        string status,
        string malicious = "0",
        string suspicious = "0",
        string httpStatusCode = "",
        string configured = "true")
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sha256"] = new string('a', 64),
            ["vtVerdict"] = verdict,
            ["verdict"] = verdict,
            ["vtStatus"] = status,
            ["status"] = status,
            ["vtMalicious"] = malicious,
            ["vtSuspicious"] = suspicious,
            ["configured"] = configured,
            ["permalink"] = "https://www.virustotal.com/gui/file/" + new string('a', 64)
        };

        if (!string.IsNullOrWhiteSpace(httpStatusCode))
        {
            data["httpStatusCode"] = httpStatusCode;
        }

        return new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Source = "virustotal",
            Data = data
        };
    }

    private static void AssertBilingualRuleMetadata(string behaviorRulesPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(behaviorRulesPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("rules", out var rulesElement), "behavior-rules.json should contain a rules array.");
        var required = RequiredRuleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleElement in rulesElement.EnumerateArray())
        {
            if (!ruleElement.TryGetProperty("id", out var idElement))
            {
                continue;
            }

            var id = idElement.GetString();
            if (string.IsNullOrWhiteSpace(id) || !required.Contains(id))
            {
                continue;
            }

            SmokeAssert.True(HasNonEmptyString(ruleElement, "title"), $"Rule '{id}' should include an English title.");
            SmokeAssert.True(HasNonEmptyString(ruleElement, "summary"), $"Rule '{id}' should include an English summary.");
            SmokeAssert.True(HasNonEmptyString(ruleElement, "titleZh"), $"Rule '{id}' should include a Chinese title.");
            SmokeAssert.True(HasNonEmptyString(ruleElement, "summaryZh"), $"Rule '{id}' should include a Chinese summary.");
        }
    }

    private static void AssertVirusTotalInfrastructureContracts(SmokeTestContext context)
    {
        var models = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Infrastructure", "VirusTotalModels.cs");
        var lookup = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Infrastructure", "VirusTotalLookupService.cs");

        RequireContains(models, "VirusTotalLookupStatuses", "VirusTotal status constants should prevent ad-hoc verdict strings.");
        RequireContains(models, "public string Verdict", "VirusTotal result should expose a stable Verdict field.");
        RequireContains(models, "MaliciousCount", "VirusTotal result should flatten malicious engine counts for reports.");
        RequireContains(models, "SuspiciousCount", "VirusTotal result should flatten suspicious engine counts for reports.");
        RequireContains(models, "HttpStatusCode", "VirusTotal result should expose HTTP status for 404/rate-limit quality.");
        RequireContains(models, "RetryAfterUtc", "VirusTotal result should expose Retry-After timing for rate limits.");
        RequireContains(models, "RuleData", "VirusTotal result should expose rule-facing one-level string fields.");
        RequireContains(models, "ToRuleEvent", "VirusTotal result should be convertible to a rule-facing enrichment event.");

        RequireContains(lookup, "HttpStatusCode.TooManyRequests", "VirusTotal lookup should distinguish HTTP 429 rate limits.");
        RequireContains(lookup, "VirusTotalLookupStatuses.RateLimited", "VirusTotal lookup should return a rate_limited status.");
        RequireContains(lookup, "VirusTotalLookupStatuses.NotFound", "VirusTotal lookup should return a not_found status for 404.");
        RequireContains(lookup, "VirusTotalLookupStatuses.AuthenticationFailed", "VirusTotal lookup should distinguish invalid API keys.");
        RequireContains(lookup, "ResolveVerdict", "VirusTotal lookup should derive malicious/suspicious/clean verdicts from stats.");
        RequireContains(lookup, "malicious > 0", "VirusTotal verdict should treat malicious hits as malicious.");
        RequireContains(lookup, "suspicious > 0", "VirusTotal verdict should treat suspicious hits as suspicious when malicious is zero.");
        RequireContains(lookup, "ParseRetryAfterUtc", "VirusTotal lookup should parse Retry-After for rate limits.");
    }

    private static bool HasNonEmptyString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property) &&
            property.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(property.GetString());
    }

    private static string ReadRepositoryText(SmokeTestContext context, params string[] segments)
    {
        return File.ReadAllText(Path.Combine(new[] { context.RepositoryRoot }.Concat(segments).ToArray()));
    }

    private static void RequireContains(string text, string expected, string message)
    {
        SmokeAssert.True(text.Contains(expected, StringComparison.Ordinal), message);
    }
}
