using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Fast rules-file quality gate. Inputs are behavior-rules.json plus synthetic
/// collection-health events; processing validates schema shape and rule-engine
/// classification; the scenario guards against diagnostic/health rows becoming
/// primary malicious behavior findings.
/// </summary>
internal sealed class BehaviorRuleSchemaCollectionHealthGuardScenario : ISmokeTestScenario
{
    private static readonly HashSet<string> AllowedRuleProperties = new(StringComparer.Ordinal)
    {
        "id",
        "title",
        "titleZh",
        "severity",
        "confidence",
        "summary",
        "summaryZh",
        "mitreTechniqueId",
        "mitreTechniqueName",
        "eventTypes",
        "containsPath",
        "allContainsPath",
        "pathRegex",
        "containsCommandLine",
        "allContainsCommandLine",
        "commandLineRegex",
        "dataKeys",
        "allDataKeys",
        "absentDataKeys",
        "dataEquals",
        "allDataEquals",
        "dataContains",
        "allDataContains",
        "dataContainsAll",
        "dataRegex",
        "allDataRegex",
        "dataNumericRanges",
        "allDataNumericRanges",
        "excludeProcessNames",
        "excludePathContains",
        "excludeCommandLineContains",
        "excludeDataEquals",
        "excludeDataContains",
        "evidenceFields",
        "tags"
    };

    private static readonly HashSet<string> AllowedSeverities = new(StringComparer.OrdinalIgnoreCase)
    {
        "info",
        "low",
        "medium",
        "high",
        "critical"
    };

    private static readonly HashSet<string> RuleArrayProperties = new(StringComparer.Ordinal)
    {
        "eventTypes",
        "containsPath",
        "allContainsPath",
        "pathRegex",
        "containsCommandLine",
        "allContainsCommandLine",
        "commandLineRegex",
        "dataKeys",
        "allDataKeys",
        "absentDataKeys",
        "excludeProcessNames",
        "excludePathContains",
        "excludeCommandLineContains",
        "evidenceFields",
        "tags"
    };

    private static readonly HashSet<string> RuleMapArrayProperties = new(StringComparer.Ordinal)
    {
        "dataEquals",
        "allDataEquals",
        "dataContains",
        "allDataContains",
        "dataContainsAll",
        "dataRegex",
        "allDataRegex",
        "excludeDataEquals",
        "excludeDataContains"
    };

    private static readonly HashSet<string> RuleNumericRangeMapProperties = new(StringComparer.Ordinal)
    {
        "dataNumericRanges",
        "allDataNumericRanges"
    };

    private static readonly HashSet<string> NumericRangeProperties = new(StringComparer.Ordinal)
    {
        "min",
        "max",
        "exclusiveMin",
        "exclusiveMax"
    };

    private static readonly HashSet<string> CollectionHealthRuleIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "r0collector-device-unavailable",
        "r0collector-start-failed",
        "r0collector-mock-driver-event",
        "r0collector-ioctl-protocol-pending",
        "r0collector-driver-health",
        "r0collector-lifecycle",
        "r0collector-ioctl-failure",
        "virustotal-not-found",
        "virustotal-rate-limited",
        "virustotal-not-configured"
    };

    public string ScenarioId => "rules.schema-collection-health.guard";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(rulesPath), "behavior-rules.json is missing.");

        using var document = JsonDocument.Parse(File.ReadAllText(rulesPath));
        AssertRulesJsonSchema(document.RootElement);

        var rules = RuleEngine.LoadRuleSet(rulesPath);
        AssertCollectionHealthRuleContracts(rules);
        AssertCollectionHealthFalsePositiveGuard(rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Behavior rules schema and collection-health false-positive guards passed."
        });
    }

    private static void AssertRulesJsonSchema(JsonElement root)
    {
        SmokeAssert.True(root.ValueKind == JsonValueKind.Object, "Behavior rules document should be a JSON object.");
        RequireString(root, "version", "rules document");
        SmokeAssert.True(root.TryGetProperty("rules", out var rulesElement), "Behavior rules document should include rules array.");
        SmokeAssert.True(rulesElement.ValueKind == JsonValueKind.Array, "Behavior rules document rules property should be an array.");

        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rulesElement.EnumerateArray())
        {
            AssertRuleJsonShape(rule, seenIds);
        }
    }

    private static void AssertRuleJsonShape(JsonElement rule, HashSet<string> seenIds)
    {
        SmokeAssert.True(rule.ValueKind == JsonValueKind.Object, "Each behavior rule should be a JSON object.");
        foreach (var property in rule.EnumerateObject())
        {
            SmokeAssert.True(AllowedRuleProperties.Contains(property.Name), $"Rule contains unsupported schema property '{property.Name}'.");
            if (RuleArrayProperties.Contains(property.Name))
            {
                AssertStringArray(property.Value, $"rule.{property.Name}", allowEmpty: property.Name != "eventTypes" && property.Name != "tags");
            }

            if (RuleMapArrayProperties.Contains(property.Name))
            {
                AssertStringArrayMap(property.Value, $"rule.{property.Name}");
            }

            if (RuleNumericRangeMapProperties.Contains(property.Name))
            {
                AssertNumericRangeMap(property.Value, $"rule.{property.Name}");
            }
        }

        var id = RequireString(rule, "id", "rule");
        SmokeAssert.True(seenIds.Add(id), $"Behavior rule id '{id}' should be unique.");
        RequireString(rule, "title", $"rule '{id}'");
        RequireString(rule, "summary", $"rule '{id}'");
        var severity = RequireString(rule, "severity", $"rule '{id}'");
        SmokeAssert.True(AllowedSeverities.Contains(severity), $"Rule '{id}' has unsupported severity '{severity}'.");
        AssertStringArray(rule.GetProperty("eventTypes"), $"rule '{id}'.eventTypes", allowEmpty: false);
        AssertStringArray(rule.GetProperty("tags"), $"rule '{id}'.tags", allowEmpty: false);
    }

    private static void AssertCollectionHealthRuleContracts(BehaviorRuleSet rules)
    {
        var indexed = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in CollectionHealthRuleIds)
        {
            SmokeAssert.True(indexed.TryGetValue(ruleId, out var rule), $"Collection-health/status rule '{ruleId}' is missing.");
            SmokeAssert.True(string.Equals(rule!.Severity, "info", StringComparison.OrdinalIgnoreCase), $"Collection-health/status rule '{ruleId}' should remain info severity.");
            SmokeAssert.True(string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Collection-health/status rule '{ruleId}' should not map to ATT&CK.");
            SmokeAssert.True(
                rule.Tags.Contains("metadata", StringComparer.OrdinalIgnoreCase) ||
                rule.Tags.Contains("diagnostic", StringComparer.OrdinalIgnoreCase) ||
                rule.Tags.Contains("collection", StringComparer.OrdinalIgnoreCase),
                $"Collection-health/status rule '{ruleId}' should be tagged as metadata, diagnostic, or collection.");
        }
    }

    private static void AssertCollectionHealthFalsePositiveGuard(BehaviorRuleSet rules)
    {
        var events = BuildCollectionHealthEvents();
        var findings = new RuleEngine(rules).Classify(events);
        SmokeAssert.True(findings.Count > 0, "Synthetic collection-health events should match diagnostic/status rules.");

        var unexpected = findings
            .Where(finding => !CollectionHealthRuleIds.Contains(finding.RuleId))
            .Select(finding => finding.RuleId)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        SmokeAssert.True(unexpected.Count == 0, "Collection-health synthetic events should not trigger primary behavior rules: " + string.Join(", ", unexpected));

        foreach (var finding in findings)
        {
            SmokeAssert.True(string.Equals(finding.Severity, "info", StringComparison.OrdinalIgnoreCase), $"Collection-health finding '{finding.RuleId}' should stay info severity.");
            SmokeAssert.True(string.IsNullOrWhiteSpace(finding.MitreTechniqueId), $"Collection-health finding '{finding.RuleId}' should not carry ATT&CK technique metadata.");
        }
    }

    private static IReadOnlyList<SandboxEvent> BuildCollectionHealthEvents()
    {
        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        return
        [
            new SandboxEvent
            {
                EventType = "r0collector.started",
                Timestamp = timestamp,
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Data =
                {
                    ["collectorVersion"] = "synthetic-contract"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.deviceUnavailable",
                Timestamp = timestamp.AddSeconds(1),
                Source = "r0collector",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ShouldRemainDiagnosticOnly",
                Data =
                {
                    ["diagnosticCode"] = "open_device_not_found",
                    ["readinessState"] = "unavailable",
                    ["driverStateName"] = "DeviceUnavailable"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.driverHealth",
                Timestamp = timestamp.AddSeconds(2),
                Source = "r0collector",
                Data =
                {
                    ["driverStateName"] = "Healthy",
                    ["queueDepth"] = "0",
                    ["queueCapacity"] = "4096",
                    ["totalEventsDropped"] = "0"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.ioctlFailure",
                Timestamp = timestamp.AddSeconds(3),
                Source = "r0collector",
                Data =
                {
                    ["operation"] = "DeviceIoControl",
                    ["error"] = "ERROR_INVALID_FUNCTION",
                    ["diagnosticStage"] = "driver-health"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.mockDriverEvent",
                Timestamp = timestamp.AddSeconds(4),
                Source = "r0collector",
                Path = @"\\.\KSwordSandboxDriver",
                Data =
                {
                    ["mock"] = "true",
                    ["driverEventPath"] = "driver-events.jsonl",
                    ["noise"] = "true"
                }
            },
            CreateVirusTotalStatusEvent(timestamp.AddSeconds(5), "not_found", "404"),
            CreateVirusTotalStatusEvent(timestamp.AddSeconds(6), "rate_limited", "429"),
            CreateVirusTotalStatusEvent(timestamp.AddSeconds(7), "not_configured", "0")
        ];
    }

    private static SandboxEvent CreateVirusTotalStatusEvent(DateTimeOffset timestamp, string status, string httpStatusCode)
    {
        return new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Timestamp = timestamp,
            Source = "virustotal",
            Data =
            {
                ["sha256"] = new string('a', 64),
                ["vtStatus"] = status,
                ["status"] = status,
                ["vtVerdict"] = status,
                ["vtMalicious"] = "0",
                ["vtSuspicious"] = "0",
                ["httpStatusCode"] = httpStatusCode
            }
        };
    }

    private static string RequireString(JsonElement root, string propertyName, string label)
    {
        SmokeAssert.True(root.TryGetProperty(propertyName, out var property), $"{label} should include '{propertyName}'.");
        SmokeAssert.True(property.ValueKind == JsonValueKind.String, $"{label}.{propertyName} should be a JSON string.");
        var value = property.GetString() ?? string.Empty;
        SmokeAssert.True(!string.IsNullOrWhiteSpace(value), $"{label}.{propertyName} should not be empty.");
        return value;
    }

    private static void AssertStringArray(JsonElement element, string label, bool allowEmpty)
    {
        SmokeAssert.True(element.ValueKind == JsonValueKind.Array, $"{label} should be a JSON array.");
        var count = 0;
        foreach (var item in element.EnumerateArray())
        {
            count++;
            SmokeAssert.True(item.ValueKind == JsonValueKind.String, $"{label} entries should be strings.");
            SmokeAssert.True(!string.IsNullOrWhiteSpace(item.GetString()), $"{label} entries should not be empty.");
        }

        SmokeAssert.True(allowEmpty || count > 0, $"{label} should not be empty.");
    }

    private static void AssertStringArrayMap(JsonElement element, string label)
    {
        SmokeAssert.True(element.ValueKind == JsonValueKind.Object, $"{label} should be a JSON object.");
        foreach (var property in element.EnumerateObject())
        {
            SmokeAssert.True(!string.IsNullOrWhiteSpace(property.Name), $"{label} keys should not be empty.");
            AssertStringArray(property.Value, $"{label}.{property.Name}", allowEmpty: false);
        }
    }

    private static void AssertNumericRangeMap(JsonElement element, string label)
    {
        SmokeAssert.True(element.ValueKind == JsonValueKind.Object, $"{label} should be a JSON object.");
        foreach (var property in element.EnumerateObject())
        {
            SmokeAssert.True(!string.IsNullOrWhiteSpace(property.Name), $"{label} keys should not be empty.");
            SmokeAssert.True(property.Value.ValueKind == JsonValueKind.Array, $"{label}.{property.Name} should be a JSON array.");
            var rangeCount = 0;
            foreach (var range in property.Value.EnumerateArray())
            {
                rangeCount++;
                AssertNumericRange(range, $"{label}.{property.Name}[{rangeCount - 1}]");
            }

            SmokeAssert.True(rangeCount > 0, $"{label}.{property.Name} should not be empty.");
        }
    }

    private static void AssertNumericRange(JsonElement element, string label)
    {
        SmokeAssert.True(element.ValueKind == JsonValueKind.Object, $"{label} should be a JSON object.");
        var hasBound = false;
        foreach (var property in element.EnumerateObject())
        {
            SmokeAssert.True(NumericRangeProperties.Contains(property.Name), $"{label} contains unsupported range property '{property.Name}'.");
            if (property.Name is "min" or "max")
            {
                SmokeAssert.True(property.Value.ValueKind == JsonValueKind.Number, $"{label}.{property.Name} should be a JSON number.");
                hasBound = true;
                continue;
            }

            SmokeAssert.True(
                property.Value.ValueKind is JsonValueKind.True or JsonValueKind.False,
                $"{label}.{property.Name} should be a JSON boolean.");
        }

        SmokeAssert.True(hasBound, $"{label} should include at least min or max.");
    }
}
