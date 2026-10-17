using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the report boundary for typed R0 network rows. Correlation can
/// correctly classify a system-owned row as environment or an unattributed row
/// as unknown, but the concrete PID/flow evidence must still be retained in the
/// report's dynamic lane rather than omitted as noise.
/// </summary>
internal sealed class R0NetworkReportRetentionScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.r0-network-retention.regression";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var timestamp = DateTimeOffset.UtcNow;
        var rows = new List<SandboxEvent>
        {
            new()
            {
                EventType = "driver.network",
                Timestamp = timestamp,
                Source = "driver",
                ProcessId = 4,
                Path = "tcp://192.168.172.130:443",
                Data =
                {
                    ["schema"] = "ksword.sandbox.r0.event",
                    ["eventOrigin"] = "kernel-driver",
                    ["producerCategory"] = "network",
                    ["sampleCorrelation"] = "environment",
                    ["nonbehavior"] = "true",
                    ["flowKey"] = "tcp|192.168.172.130:51000|192.0.2.10:443"
                }
            },
            new()
            {
                EventType = "driver.network",
                Timestamp = timestamp.AddMilliseconds(1),
                Source = "driver",
                Data =
                {
                    ["schema"] = "ksword.sandbox.r0.event",
                    ["eventOrigin"] = "kernel-driver",
                    ["producerCategory"] = "network",
                    ["sampleCorrelation"] = "unknown",
                    ["nonbehavior"] = "true",
                    ["owningProcessId"] = "8124",
                    ["flowKey"] = "tcp|192.168.172.130:51001|198.51.100.7:8443"
                }
            },
            new()
            {
                EventType = "driver.network",
                Timestamp = timestamp.AddMilliseconds(2),
                Source = "driver",
                Data =
                {
                    ["schema"] = "ksword.sandbox.r0.event",
                    ["eventOrigin"] = "kernel-driver",
                    ["producerCategory"] = "network",
                    ["nonbehavior"] = "true",
                    ["collectorNoise"] = "true"
                }
            }
        };

        var result = ReportEventSampler.SampleForReport(
            rows,
            new ReportEventSamplingOptions
            {
                MaxInlineEvents = 0,
                MaxDynamicActionEvents = 8,
                MaxDiagnosticEvents = 0
            });

        SmokeAssert.True(
            result.DynamicActionSelectedCount == 2,
            "Concrete R0 network rows must enter the dynamic report lane even when correlation marks them environment/unknown.");
        SmokeAssert.True(
            result.Events.Count(evt => string.Equals(evt.EventType, "driver.network", StringComparison.OrdinalIgnoreCase)) == 2,
            "R0 network rows with PID/flow identity must remain visible in report events.");
        SmokeAssert.True(
            result.QuotaOmittedEventCount == 1 &&
            result.OmittedEventTypeCounts.TryGetValue("driver.network", out var omitted) && omitted == 1 &&
            !result.Events.Any(evt => string.Equals(evt.EventType, "driver.network", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.TryGetValue("collectorNoise", out var noise) && noise == "true"),
            "Explicit collector noise must remain excluded from the retained network evidence lane.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Typed R0 network rows retain PID/flow evidence across environment and unknown correlation dispositions."
        });
    }
}
