using System.Text.Json;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Validates the machine-readable v1 MVP readiness checklist. Inputs are the
/// repository docs folder; processing checks schema, release guardrails, and
/// required objective component IDs; output is a lightweight smoke result.
/// </summary>
internal sealed class V1MvpReadinessChecklistScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredComponentIds =
    [
        "webui-live-progress",
        "report-evidence-story",
        "behavior-rules",
        "r0-event-quality",
        "guest-artifacts",
        "network-telemetry",
        "virustotal",
        "release-productization"
    ];

    public string ScenarioId => "release.v1-mvp-readiness-checklist.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var checklistPath = Path.Combine(context.RepositoryRoot, "docs", "v1-mvp-readiness-checklist.json");
        SmokeAssert.True(File.Exists(checklistPath), "v1 MVP readiness checklist should exist.");

        using var document = JsonDocument.Parse(File.ReadAllText(checklistPath));
        var root = document.RootElement;
        RequireString(root, "schema", "checklist");
        SmokeAssert.True(
            string.Equals(root.GetProperty("schema").GetString(), "ksword.v1.mvp.readiness.checklist.v1", StringComparison.Ordinal),
            "Checklist schema should be stable.");
        SmokeAssert.True(root.TryGetProperty("freshLiveEvidenceRequired", out var freshLive) && freshLive.GetBoolean(), "Checklist should require fresh live evidence before live claims.");
        SmokeAssert.True(
            root.TryGetProperty("freshLiveEvidenceGuardrailZh", out var guardrail) &&
            (guardrail.GetString() ?? string.Empty).Contains("真实 Notepad 5s", StringComparison.Ordinal),
            "Checklist should warn that real Notepad 5s claims require fresh evidence.");

        SmokeAssert.True(root.TryGetProperty("noisyOrUnsafeActionsExcludedByDefault", out var excluded) && excluded.ValueKind == JsonValueKind.Array, "Checklist should list unsafe actions excluded by default.");
        var excludedText = string.Join(" | ", excluded.EnumerateArray().Select(item => item.GetString()));
        SmokeAssert.True(excludedText.Contains("CSignTool.exe", StringComparison.OrdinalIgnoreCase), "Checklist should preserve the CSignTool exclusion.");
        SmokeAssert.True(excludedText.Contains("git push", StringComparison.OrdinalIgnoreCase), "Checklist should preserve the no-push default.");

        SmokeAssert.True(root.TryGetProperty("components", out var components) && components.ValueKind == JsonValueKind.Array, "Checklist should contain components array.");
        var indexed = components.EnumerateArray()
            .ToDictionary(component => component.GetProperty("id").GetString() ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        foreach (var componentId in RequiredComponentIds)
        {
            SmokeAssert.True(indexed.TryGetValue(componentId, out var component), $"Checklist should contain component '{componentId}'.");
            RequireString(component, "titleZh", componentId);
            RequireString(component, "targetZh", componentId);
            RequireString(component, "remainingRiskZh", componentId);
            RequireString(component, "releaseGate", componentId);
            SmokeAssert.True(
                component.TryGetProperty("currentEvidence", out var evidence) &&
                evidence.ValueKind == JsonValueKind.Array &&
                evidence.GetArrayLength() > 0,
                $"Checklist component '{componentId}' should list current evidence.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredComponentIds.Length} v1 MVP readiness components are represented with release guardrails."
        });
    }

    private static void RequireString(JsonElement element, string propertyName, string label)
    {
        SmokeAssert.True(
            element.TryGetProperty(propertyName, out var property) &&
            property.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(property.GetString()),
            $"{label} should contain non-empty string property '{propertyName}'.");
    }
}
