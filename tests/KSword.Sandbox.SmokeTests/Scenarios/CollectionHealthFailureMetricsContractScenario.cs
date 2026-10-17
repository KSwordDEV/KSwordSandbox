using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that collection-loss and probe-failure rows become non-zero
/// report metrics while their original diagnostic event types remain intact.
/// No VM or real sample is used; all inputs are synthetic normalized events.
/// </summary>
internal sealed class CollectionHealthFailureMetricsContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "collection-health.failure-metrics.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rawEvents = BuildEvents();
        var reportEvents = rawEvents.Take(3).ToList();
        var summary = CollectionHealthSummaryBuilder.Build(rawEvents, reportEvents);
        RequireEqual(6, summary.RawRows, "All collection-health diagnostics should remain in the raw summary.");
        RequireEqual(3, summary.ReportRows, "Report row count should reflect sampled health rows.");
        RequireEqual(3, summary.OmittedRows, "Omitted health rows should remain explicit.");
        RequireEqual(6, summary.TotalRows, "Collection health total should include every failure/loss row.");
        RequireEqual(6, summary.FailureRows, "ETW/driver loss and probe failures should be failures.");
        RequireEqual(2, summary.LossRows, "ETW and driver loss should be counted as loss rows.");
        RequireEqual(1, summary.EtwEventsLostRows, "ETW EventsLost should produce one loss row.");
        RequireEqual(7, summary.EtwEventsLost, "ETW EventsLost should preserve the numeric loss counter.");
        RequireEqual(1, summary.DriverLossRows, "Driver lostCount should produce one loss row.");
        RequireEqual(4, summary.DriverLostCount, "Driver lostCount should preserve the numeric loss counter.");
        RequireEqual(9, summary.DriverQueueDepth, "Driver queue depth should preserve the peak unread queue snapshot.");
        RequireEqual(3, summary.DriverRemainingUnread, "Driver remaining unread should remain separate from lostCount.");
        RequireEqual(1, summary.DriverDrainStoppedAtDeadlineRows, "A drain deadline should remain visible as a quality marker.");
        RequireEqual(2, summary.DriverEventsSuppressed, "Collector suppression should remain separate from kernel loss.");
        RequireEqual(1, summary.DriverQualityWarningRows, "Quality warnings should remain visible even with a zero loss counter.");
        RequireEqual(1, summary.ProcessTreeUnavailable, "Missing process tree roots should count as collection failures.");
        RequireEqual(1, summary.ScheduledTaskCaptureFailed, "Scheduled task capture failures should count as collection failures.");
        RequireEqual(1, summary.PktmonStopFailed, "pktmon stop failures should count as collection failures.");
        RequireEqual(1, summary.EtwDecodeFailed, "ETW decode failures should count as collection failures.");

        var metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        CollectionHealthSummaryBuilder.AddMetrics(metrics, summary);
        RequireEqual(6, metrics["collectionHealth.failures"], "Failure metric should be non-zero.");
        RequireEqual(7, metrics["collectionHealth.etw.eventsLost"], "ETW loss metric should preserve EventsLost.");
        RequireEqual(4, metrics["collectionHealth.driver.lostCount"], "Driver loss metric should preserve lostCount.");
        RequireEqual(9, metrics["collectionHealth.driver.queueDepth"], "Driver queue depth metric should preserve the queue snapshot.");
        RequireEqual(3, metrics["collectionHealth.driver.remainingUnread"], "Driver remaining unread metric should preserve the unread count.");
        RequireEqual(1, metrics["collectionHealth.driver.drainStoppedAtDeadlineRows"], "Driver deadline metric should preserve the count.");
        RequireEqual(2, metrics["collectionHealth.driver.eventsSuppressed"], "Driver suppression metric should preserve the count.");
        RequireEqual(1, metrics["collectionHealth.driver.qualityWarningRows"], "Driver quality warning metric should remain non-zero.");
        RequireEqual(6, metrics["runtime.failures"], "Runtime failure alias should include collection failures.");

        var model = new AnalysisReport
        {
            JobId = Guid.NewGuid(),
            Sample = new SampleIdentity
            {
                FileName = "collection-health-contract.exe",
                FullPath = @"C:\samples\collection-health-contract.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "00000000",
                SizeBytes = 1
            },
            Events = reportEvents,
            CollectionHealth = summary
        };
        RequireEqual(6, model.CollectionHealth.FailureRows, "AnalysisReport should carry the collection-health model.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Collection loss and capture failures produce non-zero shared metrics with raw diagnostics preserved."
        });
    }

    private static List<SandboxEvent> BuildEvents()
    {
        var timestamp = DateTimeOffset.UtcNow;
        return
        [
            new SandboxEvent
            {
                EventType = "etw_live.captured",
                Timestamp = timestamp,
                Source = "etw",
                Data =
                {
                    ["collectionHealth"] = "true",
                    ["payload"] = "BufferSize=8192; EventsLost=7; BuffersLost=0",
                    ["captureState"] = "captured"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.driverReadEvents",
                Timestamp = timestamp.AddSeconds(1),
                Source = "r0collector",
                Data =
                {
                    ["collectionHealth"] = "true",
                    ["lostCount"] = "4",
                    ["queueDepth"] = "9",
                    ["remainingUnread"] = "3",
                    ["drainStoppedAtDeadline"] = "true",
                    ["eventsSuppressed"] = "2"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree_unavailable",
                Timestamp = timestamp.AddSeconds(2),
                Source = "guest",
                Data =
                {
                    ["collectionHealth"] = "true",
                    ["captureState"] = "missing"
                }
            },
            new SandboxEvent
            {
                EventType = "scheduled_task.capture_failed",
                Timestamp = timestamp.AddSeconds(3),
                Source = "guest",
                Data =
                {
                    ["collectionHealth"] = "true",
                    ["status"] = "failed"
                }
            },
            new SandboxEvent
            {
                EventType = "packet_capture.failed",
                Timestamp = timestamp.AddSeconds(4),
                Source = "guest",
                Data =
                {
                    ["collectionHealth"] = "true",
                    ["failureReason"] = "pktmonStopFailed"
                }
            },
            new SandboxEvent
            {
                EventType = "etw_live.decode_failed",
                Timestamp = timestamp.AddSeconds(5),
                Source = "etw",
                Data =
                {
                    ["collectionHealth"] = "true",
                    ["decodeFailureReason"] = "tracerptFailed",
                    ["status"] = "failed"
                }
            }
        ];
    }

    private static void RequireEqual(int expected, int actual, string message)
    {
        SmokeAssert.True(expected == actual, $"{message} Expected {expected}, got {actual}.");
    }
}
