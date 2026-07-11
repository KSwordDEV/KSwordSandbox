using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Jobs;
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
        AssertVirusTotalReportPersistence(context, rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "VirusTotal enrichment rules match synthetic verdict events, persist successful lookup evidence into reports, and infrastructure exposes clear local verdict/status fields."
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
        var cache = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Infrastructure", "VirusTotalLookupCache.cs");
        var settings = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Infrastructure", "VirusTotalSettingsStore.cs");
        var program = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Program.cs");
        var settingsPage = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "SettingsPage.cs");
        var liveEventsPage = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "LiveEventsPage.cs");
        var docs = ReadRepositoryText(context, "docs", "virustotal.md");

        RequireContains(models, "VirusTotalLookupStatuses", "VirusTotal status constants should prevent ad-hoc verdict strings.");
        RequireContains(models, "InvalidHash", "VirusTotal result should distinguish malformed hash inputs without calling the provider.");
        RequireContains(models, "VirusTotalLookupEventNames", "VirusTotal models should centralize rule-facing lookup event names.");
        RequireContains(models, "vt.lookup", "VirusTotal event data should expose the compact vt.lookup event name.");
        RequireContains(models, "public string Verdict", "VirusTotal result should expose a stable Verdict field.");
        RequireContains(models, "MaliciousCount", "VirusTotal result should flatten malicious engine counts for reports.");
        RequireContains(models, "SuspiciousCount", "VirusTotal result should flatten suspicious engine counts for reports.");
        RequireContains(models, "HttpStatusCode", "VirusTotal result should expose HTTP status for 404/rate-limit quality.");
        RequireContains(models, "RetryAfterUtc", "VirusTotal result should expose Retry-After timing for rate limits.");
        RequireContains(models, "QuietErrorKind", "VirusTotal result should expose normalized quiet error taxonomy.");
        RequireContains(models, "ResolveQuietErrorKind", "VirusTotal quiet taxonomy should normalize provider/local failures.");
        RequireContains(models, "\"auth\"", "VirusTotal quiet taxonomy should distinguish authentication failures as auth.");
        RequireContains(models, "\"rate_limit\"", "VirusTotal quiet taxonomy should distinguish provider rate limits.");
        RequireContains(models, "ZhStatusText", "VirusTotal result should expose Chinese status text.");
        RequireContains(models, "ZhStatusDetail", "VirusTotal result should expose a Chinese operator status explanation.");
        RequireContains(models, "VirusTotalOfficialFileObject", "VirusTotal result should expose selected official file object metadata.");
        RequireContains(models, "FileSizeBytes", "VirusTotal official file object fields should include file size.");
        RequireContains(models, "FileTypeDescription", "VirusTotal official file object fields should include type description.");
        RequireContains(models, "VirusTotalThreatClassification", "VirusTotal official file object fields should include threat classification metadata.");
        RequireContains(models, "RuleData", "VirusTotal result should expose rule-facing one-level string fields.");
        RequireContains(models, "ToRuleEvent", "VirusTotal result should be convertible to a rule-facing enrichment event.");
        RequireContains(models, "CanPersistEnrichmentEvent", "VirusTotal result should expose whether an event is report-safe to persist.");

        RequireContains(lookup, "IsSha256Hex", "VirusTotal lookup should validate SHA-256 shape before a provider call.");
        RequireContains(lookup, "HttpStatusCode.TooManyRequests", "VirusTotal lookup should distinguish HTTP 429 rate limits.");
        RequireContains(lookup, "VirusTotalLookupStatuses.RateLimited", "VirusTotal lookup should return a rate_limited status.");
        RequireContains(lookup, "VirusTotalLookupStatuses.NotFound", "VirusTotal lookup should return a not_found status for 404.");
        RequireContains(lookup, "VirusTotalLookupStatuses.AuthenticationFailed", "VirusTotal lookup should distinguish invalid API keys.");
        RequireContains(lookup, "VirusTotalLookupStatuses.Timeout", "VirusTotal lookup should expose timeouts as a first-class quiet status.");
        RequireContains(lookup, "ResolveVerdict", "VirusTotal lookup should derive malicious/suspicious/clean verdicts from stats.");
        RequireContains(lookup, "malicious > 0", "VirusTotal verdict should treat malicious hits as malicious.");
        RequireContains(lookup, "suspicious > 0", "VirusTotal verdict should treat suspicious hits as suspicious when malicious is zero.");
        RequireContains(lookup, "ParseRetryAfterUtc", "VirusTotal lookup should parse Retry-After for rate limits.");
        RequireContains(lookup, "\"not_configured\"", "VirusTotal lookup should tag missing-key skips with the stable quiet taxonomy.");
        RequireContains(lookup, "\"auth\"", "VirusTotal lookup should tag authentication failures with the auth quiet taxonomy.");
        RequireContains(lookup, "\"rate_limit\"", "VirusTotal lookup should tag rate limits with the rate_limit quiet taxonomy.");
        RequireContains(lookup, "ReadOfficialFileObject", "VirusTotal lookup should parse selected official file object metadata.");
        RequireContains(lookup, "\"popular_threat_classification\"", "VirusTotal lookup should parse official popular threat classification metadata.");
        RequireContains(lookup, "\"first_submission_date\"", "VirusTotal lookup should parse official submission timestamps.");
        RequireContains(lookup, "\"type_description\"", "VirusTotal lookup should parse official file type descriptions.");
        RequireContains(lookup, "ReadStringArray", "VirusTotal lookup should preserve official names/tags arrays.");

        RequireContains(cache, "FoundTtl = TimeSpan.FromHours(24)", "VirusTotal cache should keep found reports for a bounded TTL.");
        RequireContains(cache, "NotFoundTtl = TimeSpan.FromHours(6)", "VirusTotal cache should keep not-found reports for a shorter bounded TTL.");
        RequireContains(cache, "RateLimitedTtl = TimeSpan.FromMinutes(5)", "VirusTotal cache should throttle repeated rate-limited lookups.");
        RequireContains(cache, "AuthenticationFailureTtl = TimeSpan.FromMinutes(5)", "VirusTotal cache should avoid hammering invalid-key responses.");
        RequireContains(cache, "CreateCredentialScope", "VirusTotal cache should scope entries by a non-secret API-key fingerprint.");
        RequireContains(cache, "WithCacheMetadata", "VirusTotal cache should annotate responses with cache metadata.");

        RequireContains(settings, "Environment.SetEnvironmentVariable(EnvironmentVariableName", "VirusTotal settings endpoint should keep submitted keys process-local.");
        RequireContains(settings, "SettingsPath: null", "VirusTotal settings state should not expose a runtime key file path.");
        RequireNotContains(settings, "File.WriteAllText", "VirusTotal settings should not persist API keys to disk.");
        RequireNotContains(settings, "Convert.ToBase64String", "VirusTotal settings should not encode API keys into a file.");
        RequireNotContains(settings, "File.ReadAllText", "VirusTotal settings should not read API keys from a runtime key file.");
        RequireNotContains(settings, "virustotal.key", "VirusTotal settings should not name a runtime API-key file.");

        RequireContains(settingsPage, "current process environment variable", "Settings page should explain that WebUI key updates are process-only.");
        RequireContains(settingsPage, "WebUI 不落盘", "Settings page should show a clear no-disk-persistence state.");
        RequireContains(settingsPage, "不会写入配置文件", "Settings page should state that VT key updates do not write config.");
        RequireContains(settingsPage, "runtime settings", "Settings page should state that VT key updates do not write runtime settings.");
        RequireContains(settingsPage, "job 日志", "Settings page should state that VT key updates do not write job logs.");
        RequireContains(settingsPage, "不会提交到仓库", "Settings page should state that VT key updates are not committed to the repository.");
        RequireContains(settingsPage, "Set process environment", "Settings page action should avoid implying durable save.");
        RequireNotContains(settingsPage, "本机设置文件", "Settings page should not imply a local key settings file exists.");
        RequireNotContains(settingsPage, "保存 / 更新", "Settings page should not label process-only key updates as durable saves.");

        RequireContains(liveEventsPage, "normalizeVirusTotalStatus", "Live monitor should normalize VT status before rendering.");
        RequireContains(liveEventsPage, "rate_limited", "Live monitor should explicitly render VT rate-limit quiet state.");
        RequireContains(liveEventsPage, "authentication_failed", "Live monitor should explicitly render VT authentication quiet state.");
        RequireContains(liveEventsPage, "timeout", "Live monitor should explicitly render VT timeout quiet state.");
        RequireContains(liveEventsPage, "quiet state", "Live monitor should label non-behavior VT outcomes as quiet states.");
        RequireContains(liveEventsPage, "job/behavior logs", "Live monitor should state that quiet VT outcomes do not write job or behavior logs.");
        RequireContains(liveEventsPage, "/virustotal`, { cache: 'no-store' }", "Live monitor should use the display-only VT GET endpoint by default.");
        RequireNotContains(liveEventsPage, "persist=true", "Live monitor should not request implicit VirusTotal persistence.");

        RequireContains(program, "AddSingleton<VirusTotalLookupCache>", "Program.cs should register the in-memory VirusTotal cache.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/enrichments/virustotal\"", "Program.cs should expose a dedicated VirusTotal job enrichment endpoint.");
        RequireContains(program, "PersistedToEnrichmentEvents = true", "VirusTotal enrichment endpoint should report successful persistence.");
        RequireContains(program, "ShouldPersistVirusTotalResult", "VirusTotal endpoint should gate persistence to report-safe outcomes.");
        RequireContains(program, "persist == true && ShouldPersistVirusTotalResult(result)", "Display-only VT GET should write job logs only when found results are explicitly persisted.");
        RequireContains(program, "if (!ShouldPersistVirusTotalResult(result))", "Explicit VT enrichment should skip job-log/report writes for quiet statuses.");

        RequireContains(docs, "never", "VirusTotal docs should state that API keys are never written by the Web backend.");
        RequireContains(docs, "process-only", "VirusTotal docs should document process-only WebUI key updates.");
        RequireContains(docs, "timeout", "VirusTotal docs should document timeout as a quiet display state.");
        RequireContains(docs, "quietErrorKind=not_configured", "VirusTotal docs should document the quiet error taxonomy.");
        RequireContains(docs, "zhStatusText", "VirusTotal docs should document Chinese API status text.");
        RequireContains(docs, "officialFileObject", "VirusTotal docs should document richer official file object fields.");
        RequireContains(docs, "只有 `status=found`", "VirusTotal docs should say only found results are persistable.");
        RequireContains(docs, "POST /api/jobs/{jobId}/enrichments/virustotal", "VirusTotal docs should document the dedicated enrichment endpoint.");
        RequireContains(docs, "vt.lookup", "VirusTotal docs should document the compact vt.lookup event name.");
    }

    private static void AssertVirusTotalReportPersistence(SmokeTestContext context, BehaviorRuleSet rules)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "smoke-vt-report-persistence");
        if (Directory.Exists(runtimeRoot))
        {
            Directory.Delete(runtimeRoot, recursive: true);
        }

        var samplePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe");
        SmokeAssert.True(File.Exists(samplePath), "notepad.exe should exist for VirusTotal report persistence smoke.");
        var service = new SandboxJobService(
            new SandboxConfig
            {
                Paths = new SandboxPaths
                {
                    RuntimeRoot = runtimeRoot,
                    RulesDirectory = context.RulesDirectory,
                    GuestPayloadRoot = Path.Combine(context.RuntimeRoot, "payload", "guest-tools")
                }
            },
            rules);

        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = true,
            UseMockCollector = true
        });
        var vtEvent = CreateVirusTotalEvent("malicious", "found", malicious: "7", suspicious: "0") with
        {
            Data = new Dictionary<string, string>(CreateVirusTotalEvent("malicious", "found", malicious: "7").Data, StringComparer.OrdinalIgnoreCase)
            {
                ["sha256"] = job.Sample!.Sha256
            }
        };

        var updated = service.UpsertEnrichmentEvent(job.JobId, vtEvent, "VirusTotal lookup persisted for smoke.");
        SmokeAssert.True(File.Exists(Path.Combine(runtimeRoot, "jobs", job.JobId.ToString("N"), "enrichment-events.json")), "enrichment-events.json should be persisted beside the job report.");
        var report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(updated.JsonReportPath!), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        SmokeAssert.True(report is not null, "Updated report.json should deserialize after VT enrichment.");
        SmokeAssert.True(report!.Events.Any(evt => evt.EventType == "enrichment.virustotal.lookup" &&
            evt.Data.TryGetValue("vtVerdict", out var verdict) &&
            string.Equals(verdict, "malicious", StringComparison.OrdinalIgnoreCase)), "VT enrichment event should be present in report events.");
        SmokeAssert.True(report.Findings.Any(finding => finding.RuleId == "virustotal-malicious-verdict"), "VT malicious verdict should be classified in regenerated report findings.");

        var artifactIndex = service.BuildArtifactIndex(job.JobId);
        SmokeAssert.True(artifactIndex.Artifacts.Any(artifact =>
            artifact.RelativePath.EndsWith("enrichment-events.json", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(artifact.EvidenceRole, "enrichment-events", StringComparison.OrdinalIgnoreCase)), "enrichment-events.json should be indexed as downloadable enrichment evidence.");
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

    private static void RequireNotContains(string text, string forbidden, string message)
    {
        SmokeAssert.True(!text.Contains(forbidden, StringComparison.Ordinal), message);
    }
}
