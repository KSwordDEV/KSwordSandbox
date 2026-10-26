using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Covers the njRAT-v0.6.4 report gap: the CLR/NetFx3 preflight refused to
/// launch the sample at runbook step 16 of 20, so the guest folder holds only
/// preflight/policy markers and no Agent markers at all. Two separate defects
/// hid that verdict from the report:
///   1. the sample-launch-refusal diagnostic was classified as routine noise
///      and pushed out of the inline report by 100 static.* rows, so a sample
///      that never ran was presented as a clean static-only analysis;
///   2. once present, its bounded data payload kept the generic correlation
///      envelope and dropped guestNetFx3State / sampleExecuted /
///      legacyClrDetected, so the report said "preflight failed" without saying
///      why the sample never ran.
/// </summary>
internal sealed class SampleLaunchRefusalReportContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.sample-launch-refusal.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Defect 19: the refusal must reach the inline report even when the
        // run produced nothing but static analysis. The classifier stamps the
        // generic correlation envelope onto every row it processes, which is
        // exactly the real njRAT shape.
        var classified = SampleCorrelationClassifier.Apply(
            [RefusalRow(), .. Enumerable.Range(0, 120).Select(index => StaticManagedRow(index))],
            @"C:\incoming\njRAT-v0.6.4.exe");
        var sampled = ReportEventSampler.SampleForReport(classified);
        var reported = sampled.Events.SingleOrDefault(evt => evt.EventType == "sample.runtime.preflight.failed");
        SmokeAssert.True(reported is not null, "A refused sample launch must survive report sampling ahead of static-analysis noise.");

        // Defect 20: the verdict is only actionable together with its cause.
        // The correlation envelope alone is not enough to make this pass - the
        // refill below is what forces the priority-key contract.
        AssertRefusalPayload(reported!);

        // A single refusal row carries ~15 own fields plus the ~25-key
        // correlation envelope, so the ordinary 24-pair budget evicted the
        // reason fields entirely. Reproduce that shape with enough filler to
        // exceed even the widened refusal budget: only an explicit
        // priority-key list can keep the verdict ahead of filler.
        var crowded = RefusalRow();
        foreach (var key in Enumerable.Range(0, 60))
        {
            crowded.Data[$"filler{key}"] = "x";
        }
        // Apply returns a new list; sampling the un-enriched source would not
        // reproduce the real correlation envelope.
        var crowdedClassified = SampleCorrelationClassifier.Apply([crowded], @"C:\incoming\njRAT-v0.6.4.exe");
        var crowdedSampled = ReportEventSampler.SampleForReport(crowdedClassified);
        var crowdedReported = crowdedSampled.Events.SingleOrDefault(evt => evt.EventType == "sample.runtime.preflight.failed");
        SmokeAssert.True(crowdedReported is not null, "A crowded refusal row must still be reported.");
        AssertRefusalPayload(crowdedReported!);

        // The output-space refusal shares the same treatment: a low-disk guest
        // must be reported as "sample not started", not as a clean run.
        var spaceRefusal = new SandboxEvent
        {
            EventType = "guest.output.preflight.failed",
            Timestamp = DateTimeOffset.UtcNow,
            Source = "host",
            Data =
            {
                ["collectionHealth"] = "true",
                ["status"] = "failed",
                ["failureType"] = "guestOutputInsufficientSpace",
                ["agentFailure"] = "true",
                ["outputSpacePreflightFailure"] = "true",
                ["preflightState"] = "insufficient-space",
                ["availableFreeBytes"] = "0",
                ["requiredFreeBytes"] = "134217728",
                ["volumeRoot"] = @"C:\",
                ["agentOutputRoot"] = @"C:\guest"
            }
        };
        var spaceSampled = ReportEventSampler.SampleForReport([spaceRefusal]);
        var spaceReported = spaceSampled.Events.SingleOrDefault(evt => evt.EventType == "guest.output.preflight.failed");
        SmokeAssert.True(spaceReported is not null, "An output-space refusal must stay visible as failure evidence.");
        SmokeAssert.True(DataEquals(spaceReported!, "preflightState", "insufficient-space"),
            "The output-space refusal must preserve its measured state.");
        SmokeAssert.True(DataEquals(spaceReported!, "requiredFreeBytes", "134217728"),
            "The output-space refusal must preserve the required free-space budget.");

        // A clean run must be unaffected: the extra pair budget is scoped to
        // the refusal rows and must not change ordinary static/diagnostic rows.
        var ordinary = new SandboxEvent
        {
            EventType = "collection.health",
            Timestamp = DateTimeOffset.UtcNow,
            Source = "host",
            Data = Enumerable.Range(0, 60)
                .ToDictionary(index => $"filler{index}", index => "v")
                .Append(new KeyValuePair<string, string>("healthStatus", "ready"))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase)
        };
        var ordinarySampled = ReportEventSampler.SampleForReport([ordinary]);
        var ordinaryReported = ordinarySampled.Events.Single();
        SmokeAssert.True(ordinaryReported.Data.ContainsKey("__omittedDataPairs"),
            "The wider payload budget must stay scoped to launch-refusal diagnostics.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "A preflight-refused sample launch stays visible with its cause, and ordinary rows keep the bounded data budget."
        });
    }

    private static void AssertRefusalPayload(SandboxEvent reported)
    {
        SmokeAssert.True(DataEquals(reported, "sampleRuntimeFailureCode", "sample-runtime-blocked-netfx3-disabled"),
            "The refusal reason must stay in the bounded report payload.");
        SmokeAssert.True(DataEquals(reported, "sampleExecuted", "false"),
            "A refused launch must state that the sample never executed.");
        SmokeAssert.True(DataEquals(reported, "guestNetFx3State", "DisabledWithPayloadRemoved"),
            "The refusal must preserve the guest framework state that caused it.");
        SmokeAssert.True(DataEquals(reported, "legacyClrDetected", "true"),
            "The refusal must preserve the legacy CLR detection that caused it.");
        SmokeAssert.True(DataEquals(reported, "sampleFileName", "njRAT-v0.6.4.exe"),
            "The refusal must name the sample that never ran.");

        // Presence alone is not the contract. The real row was evicted because
        // the generic correlation envelope (~25 keys) is matched first by the
        // ordinary priority list and consumes the whole pair budget, so the
        // verdict keys only survive if an explicit priority list puts them
        // ahead of that envelope. Assert that ordering directly - dropping the
        // priority list keeps every field present but reorders the payload so
        // the verdict trails the envelope.
        var keys = reported.Data.Keys.ToList();
        var verdictIndex = keys.IndexOf("sampleRuntimeFailureCode");
        var envelopeIndex = keys.IndexOf("sampleCorrelation");
        SmokeAssert.True(verdictIndex >= 0 && envelopeIndex >= 0,
            "The refusal verdict and the generic correlation envelope must both be present.");
        SmokeAssert.True(verdictIndex < envelopeIndex,
            "The refusal verdict must precede the generic correlation envelope; otherwise the bounded payload can evict the reason.");
    }

    private static SandboxEvent RefusalRow() => new()
    {
        EventType = "sample.runtime.preflight.failed",
        Timestamp = DateTimeOffset.UtcNow.AddSeconds(-5),
        Source = "host",
        Path = Path.Combine(AppContext.BaseDirectory, "sample-runtime-preflight.json"),
        Data =
        {
            ["collectionHealth"] = "true",
            ["captureState"] = "failed",
            ["status"] = "failed",
            ["failureType"] = "sampleRuntimePreflight",
            ["sampleRuntimePreflight"] = "true",
            ["sampleRuntimeState"] = "sample-runtime-blocked",
            ["sampleRuntimeFailureCode"] = "sample-runtime-blocked-netfx3-disabled",
            ["preflightPath"] = @"C:\guest\sample-runtime-preflight.json",
            ["sampleExecuted"] = "false",
            ["sampleFileName"] = "njRAT-v0.6.4.exe",
            ["managedClrDetected"] = "true",
            ["legacyClrDetected"] = "true",
            ["guestNetFx3State"] = "DisabledWithPayloadRemoved",
            ["guestSamplePresent"] = "true",
            ["stderrPreview"] = "SAMPLE_RUNTIME_BLOCKED: legacy CLR sample requires NetFx3/CLR 2.0-3.5; guest state=DisabledWithPayloadRemoved"
        }
    };

    private static bool DataEquals(SandboxEvent evt, string key, string expected) =>
        evt.Data.TryGetValue(key, out var value) && string.Equals(value, expected, StringComparison.Ordinal);

    private static SandboxEvent StaticManagedRow(int index) => new()
    {
        EventType = "static.managed.method",
        Timestamp = DateTimeOffset.UtcNow.AddMilliseconds(index),
        Source = "host",
        Data =
        {
            ["staticOnly"] = "true",
            ["evidenceOrigin"] = "static",
            ["typeName"] = "NjRAT.Client.Net",
            ["methodName"] = $"Method{index}"
        }
    };
}
