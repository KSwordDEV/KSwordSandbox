using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;
using System.Text.Json;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Regression coverage for high-volume driver JSONL imports. Inputs are a
/// planned smoke job plus a synthetic large driver-events.jsonl; processing
/// imports the guest outputs through SandboxJobService and checks that report
/// regeneration samples report.json/report.html instead of embedding all raw
/// R0 rows; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class R0JsonlReportSamplingRegressionScenario : ISmokeTestScenario
{
    private const int ImportedR0EventCount = 1_500;
    private const int R0SectionRowBudget = 250;
    private const int HtmlSizeBudgetBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public string ScenarioId => "report.r0-jsonl-sampling.regression";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var runtimeRoot = Path.Combine(context.RuntimeRoot, ScenarioId, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var samplePath = Path.Combine(runtimeRoot, "r0-volume.exe");
        File.WriteAllText(samplePath, "not a real executable; used only for high-volume R0 JSONL report sampling smoke coverage");

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RepositoryRoot, "rules", "behavior-rules.json"));
        var config = SandboxConfigLoader.Load(Path.Combine(context.RepositoryRoot, "config", "sandbox.example.json"), context.RepositoryRoot) with
        {
            Paths = new SandboxPaths
            {
                RuntimeRoot = runtimeRoot,
                RulesDirectory = Path.Combine(context.RepositoryRoot, "rules"),
                GuestPayloadRoot = Path.Combine(runtimeRoot, "payload", "guest-tools")
            }
        };

        var service = new SandboxJobService(config, rules);
        var plannedJob = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = true
        });

        var eventsPath = WriteLargeR0JsonlGuestOutput(plannedJob);
        var importedJob = service.ImportGuestEvents(plannedJob.JobId, eventsPath);
        var reportPath = importedJob.JsonReportPath ?? throw new InvalidOperationException("Imported job should have report.json.");
        var htmlPath = importedJob.HtmlReportPath ?? throw new InvalidOperationException("Imported job should have report.html.");
        var report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(reportPath), JsonOptions)
            ?? throw new InvalidOperationException("report.json should deserialize.");
        var html = File.ReadAllText(htmlPath);
        var r0Section = ExtractSection(html, "r0");
        var r0EventRows = Math.Max(0, CountOccurrences(r0Section, "<tr>") - 1);
        var samplingMarker = report.Events.FirstOrDefault(evt => string.Equals(evt.EventType, "report.events.sampled", StringComparison.OrdinalIgnoreCase));

        SmokeAssert.True(samplingMarker is not null, "Large R0 JSONL import should add a report.events.sampled marker to report.json/report.html.");
        SmokeAssert.True(
            TryGetInt(samplingMarker!.Data, "rawEventCount", out var rawEventCount) && rawEventCount >= ImportedR0EventCount,
            "Sampling marker should report the full raw event count, including the large driver-events.jsonl input.");
        SmokeAssert.True(
            TryGetInt(samplingMarker.Data, "omittedEventCount", out var omittedEventCount) && omittedEventCount > 0,
            "Sampling marker should report omitted R0 JSONL rows.");
        SmokeAssert.True(
            samplingMarker.Data.TryGetValue("driverEventsPath", out var driverEventsPath) &&
            driverEventsPath.EndsWith("driver-events.jsonl", StringComparison.OrdinalIgnoreCase),
            "Sampling marker should retain the complete driver-events.jsonl source path.");
        SmokeAssert.True(
            report.Metrics.TryGetValue("events.omittedFromReport", out var omittedMetric) && omittedMetric == omittedEventCount,
            "Report metrics should carry the omitted-from-report count.");
        SmokeAssert.True(
            report.Events.Count <= R0SectionRowBudget,
            $"report.json should embed only sampled report events. Embedded {report.Events.Count}; budget is {R0SectionRowBudget}.");
        RequireContains(
            html,
            "report.events.sampled",
            "Rendered report should surface the sampling marker.");
        RequireContains(
            html,
            "driver-events.jsonl",
            "Rendered report should still point operators to the complete R0 JSONL artifact/source.");
        RequireNotContains(
            html,
            "r0-jsonl-volume-1499.bin",
            "Rendered report should omit low-value tail R0 JSONL rows from inline HTML.");

        SmokeAssert.True(
            r0EventRows <= R0SectionRowBudget,
            $"R0 / driver events section should sample large JSONL inputs instead of rendering every row. Rendered {r0EventRows} rows for {ImportedR0EventCount} imported events; budget is {R0SectionRowBudget}.");
        SmokeAssert.True(
            new FileInfo(htmlPath).Length <= HtmlSizeBudgetBytes,
            $"Large R0 JSONL report HTML should stay bounded. Rendered {new FileInfo(htmlPath).Length:N0} bytes; budget is {HtmlSizeBudgetBytes:N0}.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Large R0 JSONL report rendering is sampled and size-bounded."
        });
    }

    /// <summary>
    /// Writes events.json and a large sibling driver-events.jsonl under one
    /// planned job's guest output folder.
    /// </summary>
    private static string WriteLargeR0JsonlGuestOutput(AnalysisJob job)
    {
        var reportPath = job.JsonReportPath ?? throw new InvalidOperationException("Planned job should have report.json.");
        var jobRoot = Path.GetDirectoryName(reportPath) ?? throw new InvalidOperationException("Job root should be discoverable.");
        var guestRoot = Path.Combine(jobRoot, "guest", job.JobId.ToString("N"));
        Directory.CreateDirectory(guestRoot);

        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var eventsPath = Path.Combine(guestRoot, "events.json");
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(new[]
        {
            new SandboxEvent
            {
                EventType = "process.start",
                Timestamp = timestamp,
                Source = "guest",
                ProcessName = "r0-volume.exe",
                ProcessId = 8400,
                Path = @"C:\KSwordSandbox\incoming\r0-volume.exe",
                CommandLine = @"C:\KSwordSandbox\incoming\r0-volume.exe"
            }
        }));

        var driverEventsPath = Path.Combine(guestRoot, "driver-events.jsonl");
        using var writer = new StreamWriter(driverEventsPath);
        for (var index = 0; index < ImportedR0EventCount; index++)
        {
            var evt = new SandboxEvent
            {
                EventType = "driver.telemetry",
                Timestamp = timestamp.AddMilliseconds(index),
                Source = "driver",
                ProcessName = "r0collector.exe",
                ProcessId = 8400,
                Path = $@"C:\KSwordSandbox\out\r0-jsonl-volume-{index:D4}.bin",
                Data =
                {
                    ["sequence"] = index.ToString(),
                    ["driverEventPath"] = "driver-events.jsonl"
                }
            };
            writer.WriteLine(JsonSerializer.Serialize(evt));
        }

        return eventsPath;
    }

    /// <summary>
    /// Reads an integer data value from a sampling marker.
    /// </summary>
    private static bool TryGetInt(IReadOnlyDictionary<string, string> data, string key, out int value)
    {
        value = 0;
        return data.TryGetValue(key, out var text) && int.TryParse(text, out value);
    }

    /// <summary>
    /// Extracts one top-level report section by anchor id.
    /// </summary>
    private static string ExtractSection(string html, string sectionId)
    {
        var start = html.IndexOf($"<section id=\"{sectionId}\"", StringComparison.Ordinal);
        SmokeAssert.True(start >= 0, $"Rendered HTML should contain section '{sectionId}'.");

        var end = html.IndexOf("</section>", start, StringComparison.Ordinal);
        SmokeAssert.True(end > start, $"Rendered HTML section '{sectionId}' should close.");
        return html[start..(end + "</section>".Length)];
    }

    /// <summary>
    /// Counts non-overlapping literal occurrences.
    /// </summary>
    private static int CountOccurrences(string text, string expected)
    {
        var count = 0;
        var index = 0;
        while (index < text.Length)
        {
            var found = text.IndexOf(expected, index, StringComparison.Ordinal);
            if (found < 0)
            {
                break;
            }

            count++;
            index = found + expected.Length;
        }

        return count;
    }

    /// <summary>
    /// Requires a literal value in rendered HTML.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Requires a literal value to be absent from rendered HTML.
    /// </summary>
    private static void RequireNotContains(string content, string forbidden, string message)
    {
        SmokeAssert.True(!content.Contains(forbidden, StringComparison.Ordinal), message);
    }
}
