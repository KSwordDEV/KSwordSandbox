using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the output-failure contract across native collector, guest artifact
/// staging, and host collection-health aggregation. This is source/synthetic
/// coverage only; it never starts a VM or executes a sample.
/// </summary>
internal sealed class R0OutputFailureDiagnosticsScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.output-failure-diagnostics.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var collectorRoot = Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.R0Collector", "src");
        var jsonWriter = File.ReadAllText(Path.Combine(collectorRoot, "JsonWriter.h"));
        var jsonWriterImpl = File.ReadAllText(Path.Combine(collectorRoot, "JsonWriter.cpp"));
        var runtimeLoop = File.ReadAllText(Path.Combine(collectorRoot, "RuntimeLoop.cpp"));
        var agent = File.ReadAllText(Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.Agent", "Program.cs"));
        var artifactWriter = File.ReadAllText(Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.Agent", "Output", "GuestArtifactWriter.cs"));

        SmokeAssert.True(jsonWriterImpl.Contains("outputWriteFailure", StringComparison.Ordinal), "Native writer must name output-write failures.");
        SmokeAssert.True(jsonWriterImpl.Contains("outputSpaceInsufficient", StringComparison.Ordinal), "Native writer must classify disk reserve failures separately from generic writes.");
        SmokeAssert.True(jsonWriterImpl.Contains("minFreeOutputBytes", StringComparison.Ordinal) && jsonWriterImpl.Contains("std::filesystem::space", StringComparison.Ordinal), "Native writer must preflight output free space with an explicit reserve.");
        // The native writer assembles the JSON value from a conditional
        // expression; assert the emitted field/value tokens independently
        // instead of depending on one source-level concatenation layout.
        SmokeAssert.True(jsonWriterImpl.Contains("captureState", StringComparison.Ordinal) &&
                         jsonWriterImpl.Contains("spaceFailure ? \"partial\" : \"failed\"", StringComparison.Ordinal),
            "Disk reserve failures must be reported as partial capture, not hidden as success.");
        SmokeAssert.True(jsonWriter.Contains("AnnotateFailureStatus", StringComparison.Ordinal), "Native writer must support post-failure status annotation.");
        SmokeAssert.True(jsonWriterImpl.Contains(".failure.json", StringComparison.Ordinal), "Native writer must persist an independent failure sidecar.");
        SmokeAssert.True(jsonWriterImpl.Contains("GetLastError", StringComparison.Ordinal) && jsonWriterImpl.Contains("errno", StringComparison.Ordinal), "Native failure evidence must retain OS and CRT error context.");
        SmokeAssert.True(runtimeLoop.Contains("RuntimeFailureAfterOutputWrite", StringComparison.Ordinal), "Runtime loop must attempt final status after a write failure.");
        SmokeAssert.True(runtimeLoop.Contains("queueDepthAtStop", StringComparison.Ordinal), "Runtime failure evidence must distinguish unknown final queue depth.");
        SmokeAssert.True(agent.Contains("outputFailureRelativePath", StringComparison.Ordinal), "Guest Agent must retain the output failure sidecar selector.");
        SmokeAssert.True(artifactWriter.Contains(".failure.json", StringComparison.Ordinal), "Guest artifact manifest must classify the output failure sidecar.");

        var timestamp = DateTimeOffset.UtcNow;
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "r0collector.driverStatus",
                Source = "r0collector",
                Timestamp = timestamp,
                Data = { ["collectionHealth"] = "true", ["queueDepth"] = "2375" }
            },
            new()
            {
                EventType = "r0collector.failed",
                Source = "guest",
                Timestamp = timestamp.AddSeconds(1),
                Data =
                {
                    ["collectionHealth"] = "true",
                    ["exitCode"] = "70",
                    ["reason"] = "nonZeroExit",
                    ["captureState"] = "failed",
                    ["outputFailureRelativePath"] = "driver-events.jsonl.failure.json"
                }
            },
            new()
            {
                EventType = "driver.parse_error",
                Source = "guest",
                Timestamp = timestamp.AddSeconds(2),
                Data = { ["jsonlLineCategory"] = "malformed-json", ["collectionNoise"] = "true" }
            }
        };

        var summary = CollectionHealthSummaryBuilder.Build(events);
        SmokeAssert.True(summary.DriverRemainingUnread == 0, "Initial queue depth must not be reported as remaining unread after a failed stop.");
        SmokeAssert.True(!summary.DriverQueueDepthAtStopKnown, "Missing final status must remain explicitly unknown.");
        SmokeAssert.True(summary.DriverMalformedRows == 1, "Malformed JSONL must remain visible in collection health.");
        SmokeAssert.True(summary.DriverOutputWriteFailureRows == 1, "Exit 70/output write failure must remain visible in collection health.");
        SmokeAssert.True(summary.FailureRows >= 2, "Malformed JSONL and failed collector exit must count as collection failures.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 output failures retain independent diagnostics and never turn an initial queue snapshot into final unread evidence."
        });
    }
}
