using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that an un-attributed original-file deletion can be shown as
/// supporting context next to a high-severity replacement without becoming a
/// sample-attributed detection. Busy process snapshots must remain bounded.
/// </summary>
internal sealed class TimelineTrackContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.timeline-tracks.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var at = new DateTimeOffset(2026, 10, 26, 10, 0, 0, TimeSpan.Zero);
        var originalPath = @"C:\Users\SandboxUser\Documents\decoy.txt";
        var originalDeleted = new SandboxEvent
        {
            EventType = "file.deleted", Timestamp = at.AddSeconds(2), Source = "guest", Path = originalPath,
            Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["behaviorCounted"] = "false", ["notSampleBehavior"] = "true",
                ["sampleCorrelation"] = "unknown"
            }
        };
        var unrelatedDeleted = originalDeleted with
        {
            Timestamp = at.AddSeconds(3), Path = @"C:\Windows\Temp\unrelated.tmp"
        };
        var encryptedCreated = new SandboxEvent
        {
            EventType = "file.created", Timestamp = at.AddSeconds(2).AddMilliseconds(50),
            Source = "guest", Path = originalPath + ".locked",
            Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["behaviorCounted"] = "true", ["sampleCorrelation"] = "probable"
            }
        };
        var snapshots = Enumerable.Range(0, 100)
            .Select(index => new SandboxEvent
            {
                EventType = "process.snapshot", Timestamp = at.AddMilliseconds(index * 40),
                Source = "guest", ProcessName = "sample.exe", ProcessId = 1000 + index
            })
            .ToList();
        var report = new AnalysisReport
        {
            JobId = Guid.Parse("77777777-7777-7777-7777-777777777777"),
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "sample.exe", FullPath = @"C:\Sample\sample.exe",
                Sha256 = new string('a', 64), Sha1 = new string('b', 40),
                Md5 = new string('c', 32), Crc32 = "12345678", SizeBytes = 4096
            },
            Events = [.. snapshots, originalDeleted, unrelatedDeleted, encryptedCreated],
            Findings =
            [
                new BehaviorFinding
                {
                    RuleId = "file-replacement", Title = "File replacement", Severity = "high",
                    Evidence = [encryptedCreated]
                }
            ]
        };
        var html = new HtmlReportRenderer().RenderEnglish(report);
        var fileStart = html.IndexOf("<div class=\"timeline-track-row has-events\" data-family=\"file\"", StringComparison.Ordinal);
        var fileEnd = html.IndexOf("<div class=\"timeline-track-row\" data-family=\"registry\"", fileStart, StringComparison.Ordinal);
        SmokeAssert.True(fileStart >= 0 && fileEnd > fileStart, "File track should be present.");
        var fileTrack = html[fileStart..fileEnd];
        SmokeAssert.True(fileTrack.Contains("data-priority=\"high\"", StringComparison.Ordinal),
            "High-severity replacement should remain visible on the file track.");
        SmokeAssert.True(fileTrack.Contains("data-priority=\"supporting\"", StringComparison.Ordinal),
            "The matching original deletion should be visible as supporting evidence.");
        SmokeAssert.True(!fileTrack.Contains("unrelated.tmp", StringComparison.Ordinal),
            "Unrelated un-attributed file activity must stay out of the behavior track.");

        var processMatch = System.Text.RegularExpressions.Regex.Match(
            html, "<div class=\\\"timeline-track-row(?: has-events)?\\\" data-family=\\\"process\\\"");
        SmokeAssert.True(processMatch.Success && processMatch.Index < fileStart, "Process track should precede the file track.");
        var processStart = processMatch.Index;
        var processTrack = html[processStart..fileStart];
        var processMarkers = System.Text.RegularExpressions.Regex.Matches(processTrack, "class=\"timeline-track-event timeline-track-cluster\"").Count;
        SmokeAssert.True(processMarkers <= 2, "Routine process snapshots should not crowd the track.");
        SmokeAssert.True(html.Contains("data-timeline-zoom", StringComparison.Ordinal) &&
            html.Contains("showTrackTooltip", StringComparison.Ordinal) &&
            html.Contains("layoutZoomedTrackMarkers", StringComparison.Ordinal) &&
            html.Contains("data-track-inspector", StringComparison.Ordinal),
            "The self-contained report should expose zoomed individual markers, hover/focus previews, and full cluster details.");
        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId, Passed = true,
            Message = "Bounded tracks preserve high file replacement and explicitly un-attributed supporting deletion."
        });
    }
}
