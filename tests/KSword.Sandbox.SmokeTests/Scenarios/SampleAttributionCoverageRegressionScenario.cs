using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Covers two evidence-loss boundaries: imported rows whose process ID lives
/// in Data rather than the envelope, and unknown high-signal R0 mutations that
/// must stay in the dynamic evidence lane without becoming sample behavior.
/// </summary>
internal sealed class SampleAttributionCoverageRegressionScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.attribution-coverage.regression";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        const string samplePath = @"C:\samples\payload.exe";
        var timestamp = new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        var classified = SampleCorrelationClassifier.Apply(
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Timestamp = timestamp,
                Source = "guest",
                Path = @"C:\KSwordSandbox\incoming\payload.exe",
                Data =
                {
                    // Guest JSON imports can omit the typed ProcessId field.
                    ["processId"] = "4242",
                    ["processImagePath"] = @"C:\KSwordSandbox\incoming\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.new",
                Timestamp = timestamp.AddMilliseconds(5),
                Source = "guest",
                ProcessName = "child.exe",
                Path = @"C:\Users\Public\child.exe",
                Data =
                {
                    ["processId"] = "4243",
                    ["parentProcessId"] = "4242",
                    ["processImagePath"] = @"C:\Users\Public\child.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.file",
                Timestamp = timestamp.AddMilliseconds(10),
                Source = "driver",
                Path = @"C:\Users\Public\drop.dll",
                Data =
                {
                    ["processId"] = "4243",
                    ["operationName"] = "write",
                    ["writeIntent"] = "true",
                    ["droppedFileCandidate"] = "true"
                }
            }
        ], samplePath);

        SmokeAssert.True(
            classified[0].Data.TryGetValue("sampleCorrelation", out var rootCorrelation) &&
            rootCorrelation == "confirmed",
            "A process.start PID carried only in Data must seed sample attribution.");
        SmokeAssert.True(
            classified[1].Data.TryGetValue("sampleCorrelation", out var childCorrelation) &&
            childCorrelation == "confirmed",
            "A child process PID carried only in Data must inherit sample attribution.");
        SmokeAssert.True(
            classified[2].Data.TryGetValue("sampleCorrelation", out var mutationCorrelation) &&
            mutationCorrelation == "confirmed",
            "A mutation owned by a Data-only child PID must remain sample-attributed.");

        var unknownRows = Enumerable.Range(0, 24)
            .Select(index => new SandboxEvent
            {
                EventType = "driver.file",
                Timestamp = timestamp.AddSeconds(1).AddMilliseconds(index),
                Source = "driver",
                Path = $@"C:\Users\Public\unknown-{index:D2}.dll",
                Data =
                {
                    ["schema"] = "ksword.sandbox.r0.event",
                    ["eventOrigin"] = "kernel-driver",
                    ["producerCategory"] = "file",
                    ["operationName"] = "write",
                    ["writeIntent"] = "true",
                    ["droppedFileCandidate"] = "true",
                    ["sampleCorrelation"] = "unknown",
                    ["sampleCorrelationStatus"] = "unknown",
                    ["behaviorCounted"] = "false",
                    ["nonbehavior"] = "true"
                }
            })
            .ToList();
        var sampled = ReportEventSampler.SampleForReport(
            unknownRows,
            new ReportEventSamplingOptions
            {
                MaxInlineEvents = 0,
                MaxDiagnosticEvents = 1,
                MaxDynamicActionEvents = 24
            });

        SmokeAssert.True(
            sampled.DynamicActionSelectedCount == unknownRows.Count &&
            sampled.DynamicActionOmittedCount == 0,
            "Unknown high-signal R0 mutations must use the dynamic evidence budget instead of the diagnostic quota.");
        SmokeAssert.True(
            sampled.Events.Count == unknownRows.Count,
            "Unknown high-signal R0 mutation rows must remain visible when dynamic capacity is available.");
        SmokeAssert.True(
            sampled.Events.All(evt => evt.Data.TryGetValue("sampleCorrelation", out var value) && value == "unknown"),
            "Retained unknown R0 rows must preserve their explicit attribution boundary.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Data-only sample PIDs seed attribution and unknown high-signal R0 rows remain report evidence."
        });
    }
}
