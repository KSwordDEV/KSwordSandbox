using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the normalized correlation contract after host-side enrichment.
/// Guest probes can emit an early uncorrelated disposition and later receive a
/// strong PID/path join; the final row must not retain contradictory status or
/// behavior-counting flags.
/// </summary>
internal sealed class SampleCorrelationDispositionInvariantScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.disposition-invariants";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        const string samplePath = @"C:\KSwordSandbox\incoming\sample.exe";
        const string droppedPath = @"C:\Users\Public\drop.exe";
        var start = DateTimeOffset.UtcNow;
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "process.start",
                Source = "guest",
                Timestamp = start,
                ProcessName = "sample.exe",
                ProcessId = 4242,
                Path = samplePath,
                CommandLine = samplePath,
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["processImagePath"] = samplePath
                }
            },
            // Shape emitted by WindowsBehaviorEventLogProbe for a script block
            // that was initially marked uncorrelated in the guest. The host
            // can prove the PID belongs to the sample process tree.
            new()
            {
                EventType = "eventlog.powershell.script_block",
                Source = "windowsBehaviorEventLog",
                Timestamp = start.AddMilliseconds(10),
                ProcessId = 4242,
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["evidenceRole"] = "targeted-windows-eventlog-behavior",
                    ["behaviorCounted"] = "true",
                    ["sampleBehaviorCandidate"] = "true",
                    ["sampleCorrelation"] = "uncorrelated",
                    ["sampleCorrelationStatus"] = "uncorrelated",
                    ["sampleCorrelationStrength"] = "none",
                    ["strongSampleCorrelation"] = "false",
                    ["nonbehavior"] = "false"
                }
            },
            // A probable cross-source R0 mutation starts with the same stale
            // status fields and is promoted by an ETW sample-owned path join.
            new()
            {
                EventType = "driver.file",
                Source = "driver",
                Timestamp = start.AddSeconds(1),
                Path = droppedPath,
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["operationName"] = "write",
                    ["behaviorCounted"] = "true",
                    ["sampleBehaviorCandidate"] = "true",
                    ["sampleCorrelation"] = "uncorrelated",
                    ["sampleCorrelationStatus"] = "uncorrelated",
                    ["sampleCorrelationStrength"] = "none",
                    ["strongSampleCorrelation"] = "false",
                    ["nonbehavior"] = "false"
                }
            },
            new()
            {
                EventType = "file.write",
                Source = "etwLive",
                Timestamp = start.AddSeconds(1),
                ProcessId = 4242,
                Path = droppedPath,
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["captureSource"] = "etwLive",
                    ["operation"] = "write",
                    ["behaviorCounted"] = "true"
                }
            }
        };

        var classified = SampleCorrelationClassifier.Apply(events, samplePath);
        var scriptBlock = classified.Single(evt => evt.EventType == "eventlog.powershell.script_block");
        AssertInvariant(scriptBlock, "confirmed", "correlated", strong: true);

        var probableMutation = classified.Single(evt => evt.EventType == "driver.file");
        AssertInvariant(probableMutation, "probable", "probable", strong: false);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Host correlation rewrites stale Event Log/R0 status fields into a consistent label, status, and behavior-counting disposition."
        });
    }

    private static void AssertInvariant(SandboxEvent evt, string label, string status, bool strong)
    {
        SmokeAssert.True(evt.Data.GetValueOrDefault("sampleCorrelation") == label,
            $"Expected sampleCorrelation={label} for {evt.EventType}.");
        SmokeAssert.True(evt.Data.GetValueOrDefault("sampleCorrelationStatus") == status,
            $"Expected sampleCorrelationStatus={status} for {evt.EventType}.");
        SmokeAssert.True(evt.Data.GetValueOrDefault("strongSampleCorrelation") == strong.ToString().ToLowerInvariant(),
            $"Expected strongSampleCorrelation={strong} for {evt.EventType}.");
        SmokeAssert.True(evt.Data.GetValueOrDefault("behaviorCounted") == "true" &&
                         evt.Data.GetValueOrDefault("sampleBehaviorCandidate") == "true" &&
                         evt.Data.GetValueOrDefault("nonbehavior") == "false" &&
                         evt.Data.GetValueOrDefault("notSampleBehavior") == "false",
            $"{evt.EventType} must have a self-consistent behavior disposition.");
        SmokeAssert.True(evt.Data.GetValueOrDefault("sampleCorrelationStatus") != "uncorrelated",
            $"{evt.EventType} must not retain an uncorrelated status after promotion.");
    }
}
