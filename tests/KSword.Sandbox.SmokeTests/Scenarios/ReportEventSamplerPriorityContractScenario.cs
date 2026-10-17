using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Protects report-event slimming from dropping high-value static, probe
/// health, and R0 backpressure evidence. Inputs are synthetic events only;
/// processing samples a noisy event stream; the scenario returns pass/fail
/// metadata without rendering HTML or starting Hyper-V.
/// </summary>
internal sealed class ReportEventSamplerPriorityContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.event-sampler-priority.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var timestamp = new DateTimeOffset(2026, 7, 11, 8, 0, 0, TimeSpan.Zero);
        var events = new List<SandboxEvent>();
        for (var index = 0; index < 160; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = "registry.value.noise",
                Timestamp = timestamp.AddMilliseconds(index),
                Source = "driver",
                Path = $@"HKCU\Software\Noise\{index:D4}",
                Data =
                {
                    ["valueName"] = $"noise-{index:D4}",
                    ["unimportant"] = new string('x', 64)
                }
            });
        }

        for (var index = 0; index < 80; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = "process.snapshot",
                Timestamp = timestamp.AddMilliseconds(400 + index),
                Source = "guest",
                ProcessName = "background.exe",
                Data =
                {
                    ["baselineSnapshot"] = "true",
                    ["behaviorCounted"] = "false",
                    ["nonbehavior"] = "true"
                }
            });
        }

        // Dynamic evidence must survive the report quota even when a process
        // burst or collector noise fills the ordinary inline budget.
        const int AttributedDynamicRows = 120;
        for (var index = 0; index < AttributedDynamicRows; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = "network.tcp",
                Timestamp = timestamp.AddMilliseconds(2000 + index),
                Source = "guest",
                ProcessId = 4242,
                Data =
                {
                    ["remote"] = $"198.51.100.{index % 200}:443",
                    ["behaviorCounted"] = "true",
                    ["sampleBehaviorCandidate"] = "true",
                    ["sampleCorrelation"] = "confirmed",
                    ["sampleCorrelationStatus"] = "correlated",
                    ["strongSampleCorrelation"] = "true"
                }
            });
        }

        // Unknown/environment dynamic rows are evidence too. They must remain
        // visible with their correlation boundary instead of disappearing into
        // the small diagnostic quota.
        events.Add(new SandboxEvent
        {
            EventType = "network.tcp",
            Timestamp = timestamp.AddMilliseconds(2200 + AttributedDynamicRows),
            Source = "guest",
            ProcessId = 7777,
            Data =
            {
                ["remote"] = "203.0.113.77:443",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["sampleCorrelation"] = "unknown",
                ["sampleCorrelationStatus"] = "unknown",
                ["sampleCorrelationReason"] = "network-row-has-no-sample-owner-pid-join"
            }
        });

        events.Add(new SandboxEvent
        {
            EventType = "static.pe.import.module",
            Timestamp = timestamp.AddSeconds(1),
            Source = "host",
            Path = @"D:\Temp\sample.exe",
            Data =
            {
                ["moduleName"] = "wininet.dll",
                ["apiCount"] = "7",
                ["tags"] = "import_network_api,import_download_api",
                ["zhMessage"] = "静态导入网络相关 API。"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "static.pe.resource",
            Timestamp = timestamp.AddSeconds(1.1),
            Source = "host",
            Path = @"D:\Temp\sample.exe",
            Data =
            {
                ["resourceType"] = "RCDATA",
                ["resourceRole"] = "embedded-pe",
                ["isEmbeddedPe"] = "True",
                ["isPayloadCandidate"] = "True",
                ["entropy"] = "7.900",
                ["size"] = "8192",
                ["tags"] = "resource_high_entropy_data,resource_embedded_pe",
                ["zhHint"] = "资源内嵌 PE。"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "http.request",
            Timestamp = timestamp.AddSeconds(1.5),
            Source = "host",
            Data =
            {
                ["protocol"] = "tcp",
                ["collectionName"] = "network-sidecars",
                ["evidenceRole"] = "network-telemetry-sidecar",
                ["importMode"] = "sidecar-artifact",
                ["sourceArtifactRelativePath"] = "packet-captures/sample.conn.jsonl",
                ["sourceArtifactSha256"] = new string('a', 64),
                ["sourceArtifactSizeBytes"] = "512",
                ["sourceIp"] = "10.0.0.4",
                ["sourcePort"] = "50244",
                ["destinationIp"] = "198.51.100.88",
                ["destinationPort"] = "8080",
                ["flowKey"] = "tcp|10.0.0.4:50244|198.51.100.88:8080",
                ["method"] = "POST",
                ["host"] = "api.example.test",
                ["uri"] = "/checkin",
                ["userAgent"] = "KSwordSmoke",
                ["contentType"] = "application/json",
                ["payloadMagic"] = "MZ"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "network.import.summary",
            Timestamp = timestamp.AddSeconds(1.6),
            Source = "host",
            Data =
            {
                ["eventKind"] = "summary",
                ["behaviorScope"] = "network-import-summary",
                ["eventCount"] = "64",
                ["canonicalBehaviorEventCount"] = "0",
                ["behaviorCountedEventCount"] = "0",
                ["connectionEventCount"] = "64",
                ["nonbehaviorEventCount"] = "64",
                ["protocols"] = "TCP",
                ["sampleCorrelation"] = "environment",
                ["sampleCorrelationStatus"] = "environment",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "network.netstat.snapshot",
            Timestamp = timestamp.AddSeconds(1.65),
            Source = "guest",
            Data =
            {
                ["phase"] = "after-run",
                ["rowCount"] = "58",
                ["emittedRows"] = "58",
                ["sourceTool"] = "netstat -ano",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "startup_item.wmi.capture_failed",
            Timestamp = timestamp.AddSeconds(1.7),
            Source = "guest",
            Data =
            {
                ["phase"] = "before-start",
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "startup_item.wmi.capture_failed",
            Timestamp = timestamp.AddSeconds(1.8),
            Source = "guest",
            Data =
            {
                ["phase"] = "after-run",
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "artifact.host_imported",
            Timestamp = timestamp.AddSeconds(1.7),
            Source = "host",
            Data =
            {
                ["artifactKind"] = "DroppedFile",
                ["downloadSelector"] = "artifacts/drop.bin",
                ["downloadSafeLink"] = "artifacts/drop.bin",
                ["safeRelativeSelector"] = "artifacts/drop.bin",
                ["importPath"] = "artifacts/drop.bin",
                ["isDuplicate"] = "true",
                ["duplicateGroupKey"] = "sha256:abc",
                ["duplicateGroupCount"] = "2",
                ["duplicatePrimarySelector"] = "artifacts/primary.bin",
                ["artifactRejectionReasons"] = "unsafeGuestArtifactPath",
                ["lastRejectedArtifactSelector"] = "../unsafe.bin"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Timestamp = timestamp.AddSeconds(1.8),
            Source = "virustotal",
            Data =
            {
                ["vtStatus"] = "found",
                ["vtVerdict"] = "malicious",
                ["vtMalicious"] = "4",
                ["vtSuspicious"] = "1",
                ["vtEngineCount"] = "72",
                ["vtReputation"] = "-10",
                ["vtCommunityScore"] = "-2",
                ["communityScoreSource"] = "reputation",
                ["lastAnalysisDateUtc"] = "2026-07-10T00:00:00.0000000Z",
                ["permalink"] = "https://www.virustotal.com/gui/file/" + new string('b', 64)
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "probe.summary",
            Timestamp = timestamp.AddSeconds(2),
            Source = "guest",
            Data =
            {
                ["probeId"] = "packet-capture",
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true",
                ["status"] = "completed",
                ["zhHint"] = "采集通道健康摘要。"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "r0collector.driverStatus",
            Timestamp = timestamp.AddSeconds(3),
            Source = "r0collector",
            Data =
            {
                ["lostCount"] = "3",
                ["highWatermark"] = "96",
                ["lastEnqueueFailureStatusHex"] = "0xC000009A",
                ["sequence"] = "2048",
                ["sequenceMeaning"] = "last driver health sequence"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "r0collector.driverNetworkStatus",
            Timestamp = timestamp.AddSeconds(4),
            Source = "r0collector",
            Data =
            {
                ["networkStatusAvailable"] = "true",
                ["readinessState"] = "available",
                ["supportedLayerMaskHex"] = "0x0000000F",
                ["activeLayerMaskHex"] = "0x00000007",
                ["lastRegisteredCalloutMaskHex"] = "0x00000007",
                ["lastAddedFilterMaskHex"] = "0x00000007",
                ["todoMaskHex"] = "0x00000008",
                ["classifyCount"] = "12",
                ["eventCount"] = "6",
                ["queueFailureCount"] = "0",
                ["classifyPayloadFailureCount"] = "0",
                ["lastDegradeReasonName"] = "wfpAleConnectTodo",
                ["zhHint"] = "WFP/ALE 网络状态。"
            }
        });
        var failedRunbook = new SandboxEvent
        {
            EventType = "vmware.runbook.executed",
            Timestamp = timestamp.AddSeconds(5),
            Source = "host",
            Data =
            {
                ["success"] = "false",
                ["failedStepIndex"] = "5",
                ["failedStepId"] = "wait-guest-remoting",
                ["message"] = "Live runbook execution stopped at step 6.",
                ["failureReason"] = "PowerShell exited with code 1",
                ["totalSteps"] = "18",
                ["executedSteps"] = "6",
                ["unimportant"] = new string('x', 1024)
            }
        };
        events.Add(failedRunbook);
        events.Add(new SandboxEvent
        {
            EventType = "guest.events.imported",
            Timestamp = timestamp.AddSeconds(5.1),
            Source = "host",
            Path = @"D:\Temp\guest\events.jsonl",
            Data =
            {
                ["eventCount"] = "37",
                ["guestImportOutcome"] = "imported",
                ["guestImportMarker"] = "true",
                ["terminalStatus"] = "Completed",
                ["unimportant"] = new string('x', 1024)
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "agent.start",
            Timestamp = timestamp.AddSeconds(5.15),
            Source = "guest",
            Data =
            {
                ["message"] = "agent session started",
                ["hostGenerated"] = "true"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "agent.stop",
            Timestamp = timestamp.AddSeconds(5.16),
            Source = "guest",
            Data =
            {
                ["message"] = "agent session stopped",
                ["hostGenerated"] = "true"
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "process.start_failed",
            Timestamp = timestamp.AddSeconds(5.2),
            Source = "guest",
            ProcessName = "notepad.exe",
            Path = @"C:\KSwordSandbox\incoming\notepad.exe",
            Data =
            {
                ["nonfatal"] = "true",
                ["exceptionType"] = "System.IO.FileNotFoundException",
                ["message"] = "The sample process could not be started."
            }
        });
        events.Add(new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp.AddSeconds(5.3),
            Source = "guest",
            ProcessName = "notepad.exe",
            Path = @"C:\KSwordSandbox\incoming\notepad.exe",
            ProcessId = 4242
        });
        events.Add(new SandboxEvent
        {
            EventType = "process.exit",
            Timestamp = timestamp.AddSeconds(5.4),
            Source = "guest",
            ProcessName = "notepad.exe",
            Path = @"C:\KSwordSandbox\incoming\notepad.exe",
            ProcessId = 4242
        });

        var result = ReportEventSampler.SampleForReport(
            events,
            new ReportEventSamplingOptions
            {
                MaxInlineEvents = 32,
                MaxEventsPerType = 5,
                MaxHighValueEventsPerType = 16,
                MaxEventDataPairs = 16
            });

        SmokeAssert.True(result.WasSampled, "Noisy input should be sampled.");
        SmokeAssert.True(result.Events.Any(evt => string.Equals(evt.EventType, "report.events.sampled", StringComparison.OrdinalIgnoreCase)), "Sampling marker should be present.");
        SmokeAssert.True(result.ExcludedEventCount == 2, $"Agent lifecycle rows should be excluded from the inline report policy; got {result.ExcludedEventCount}.");
        SmokeAssert.True(!result.Events.Any(evt => evt.EventType is "agent.start" or "agent.stop"), "Agent lifecycle rows must not appear as user-facing report events.");
        var lifecycleOnly = ReportEventSampler.SampleForReport(
        [
            new SandboxEvent { EventType = "agent.start", Timestamp = timestamp },
            new SandboxEvent { EventType = "agent.stop", Timestamp = timestamp.AddSeconds(1) }
        ]);
        SmokeAssert.True(!lifecycleOnly.WasSampled && lifecycleOnly.Events.Count == 0 && lifecycleOnly.ExcludedEventCount == 2,
            "Lifecycle-only input should not create a misleading sampling marker.");

        var failurePriorityInput = Enumerable.Range(0, 80)
            .Select(index => new SandboxEvent
            {
                EventType = "collector.background_diagnostic",
                Timestamp = timestamp.AddSeconds(10).AddMilliseconds(index),
                Source = "host",
                Data = { ["diagnosticEvent"] = "true", ["message"] = $"noise-{index}" }
            })
            .Concat(new[]
            {
                new SandboxEvent { EventType = "etw_live.decode_failed", Timestamp = timestamp.AddSeconds(11), Source = "etw", Data = { ["status"] = "failed" } },
                new SandboxEvent { EventType = "packet_capture.failed", Timestamp = timestamp.AddSeconds(12), Source = "guest", Data = { ["status"] = "failed" } },
                new SandboxEvent { EventType = "scheduled_task.capture_failed", Timestamp = timestamp.AddSeconds(13), Source = "guest", Data = { ["status"] = "failed" } },
                new SandboxEvent { EventType = "process.tree_unavailable", Timestamp = timestamp.AddSeconds(14), Source = "guest", Data = { ["status"] = "missing" } }
            })
            .ToList();
        var failurePriority = ReportEventSampler.SampleForReport(
            failurePriorityInput,
            new ReportEventSamplingOptions { MaxInlineEvents = 12, MaxDiagnosticEvents = 2, MaxEventsPerType = 2 });
        foreach (var failureType in new[] { "etw_live.decode_failed", "packet_capture.failed", "scheduled_task.capture_failed", "process.tree_unavailable" })
        {
            SmokeAssert.True(failurePriority.Events.Any(evt => string.Equals(evt.EventType, failureType, StringComparison.OrdinalIgnoreCase)),
                $"Collection failure {failureType} should remain visible ahead of the diagnostics quota.");
        }

        var staticEvent = RequireEvent(result.Events, "static.pe.import.module");
        RequireData(staticEvent, "moduleName", "wininet.dll");
        RequireData(staticEvent, "apiCount", "7");
        RequireData(staticEvent, "zhMessage", "静态导入网络相关 API。");

        var resourceEvent = RequireEvent(result.Events, "static.pe.resource");
        RequireData(resourceEvent, "resourceRole", "embedded-pe");
        RequireData(resourceEvent, "isEmbeddedPe", "True");
        RequireData(resourceEvent, "entropy", "7.900");
        RequireData(resourceEvent, "size", "8192");

        var networkEvent = RequireEvent(result.Events, "http.request");
        RequireData(networkEvent, "protocol", "tcp");
        RequireData(networkEvent, "collectionName", "network-sidecars");
        RequireData(networkEvent, "evidenceRole", "network-telemetry-sidecar");
        RequireData(networkEvent, "sourceArtifactRelativePath", "packet-captures/sample.conn.jsonl");
        RequireData(networkEvent, "sourceArtifactSha256", new string('a', 64));
        RequireData(networkEvent, "sourceIp", "10.0.0.4");
        RequireData(networkEvent, "destinationIp", "198.51.100.88");
        RequireData(networkEvent, "flowKey", "tcp|10.0.0.4:50244|198.51.100.88:8080");
        RequireData(networkEvent, "method", "POST");
        RequireData(networkEvent, "host", "api.example.test");
        RequireData(networkEvent, "uri", "/checkin");

        var networkSummary = RequireEvent(result.Events, "network.import.summary");
        RequireData(networkSummary, "eventCount", "64");
        RequireData(networkSummary, "canonicalBehaviorEventCount", "0");
        RequireData(networkSummary, "connectionEventCount", "64");
        var networkSnapshot = RequireEvent(result.Events, "network.netstat.snapshot");
        RequireData(networkSnapshot, "rowCount", "58");
        RequireData(networkSnapshot, "phase", "after-run");
        var samplingMarker = RequireEvent(result.Events, "report.events.sampled");
        RequireData(samplingMarker, "wmiCaptureFailedCount", "2");
        RequireData(samplingMarker, "wmiCaptureFailedPhases", "before-start, after-run");
        RequireData(samplingMarker, "dynamicActionEventsAlwaysRetained", "true");
        RequireData(samplingMarker, "maxInlineEventsExcludesDynamicActions", "true");

        var artifactEvent = RequireEvent(result.Events, "artifact.host_imported");
        RequireData(artifactEvent, "downloadSelector", "artifacts/drop.bin");
        RequireData(artifactEvent, "downloadSafeLink", "artifacts/drop.bin");
        RequireData(artifactEvent, "isDuplicate", "true");
        RequireData(artifactEvent, "duplicateGroupCount", "2");
        RequireData(artifactEvent, "lastRejectedArtifactSelector", "../unsafe.bin");

        var vtEvent = RequireEvent(result.Events, "enrichment.virustotal.lookup");
        RequireData(vtEvent, "vtVerdict", "malicious");
        RequireData(vtEvent, "vtReputation", "-10");
        RequireData(vtEvent, "vtCommunityScore", "-2");
        RequireData(vtEvent, "permalink", "https://www.virustotal.com/gui/file/" + new string('b', 64));

        var probeEvent = RequireEvent(result.Events, "probe.summary");
        RequireData(probeEvent, "collectionHealth", "true");
        RequireData(probeEvent, "nonbehavior", "true");
        RequireData(probeEvent, "zhHint", "采集通道健康摘要。");

        var r0Event = RequireEvent(result.Events, "r0collector.driverStatus");
        RequireData(r0Event, "lostCount", "3");
        RequireData(r0Event, "highWatermark", "96");
        RequireData(r0Event, "lastEnqueueFailureStatusHex", "0xC000009A");
        RequireData(r0Event, "sequence", "2048");

        var r0NetworkStatusEvent = RequireEvent(result.Events, "r0collector.driverNetworkStatus");
        RequireData(r0NetworkStatusEvent, "networkStatusAvailable", "true");
        RequireData(r0NetworkStatusEvent, "activeLayerMaskHex", "0x00000007");
        RequireData(r0NetworkStatusEvent, "todoMaskHex", "0x00000008");
        RequireData(r0NetworkStatusEvent, "classifyCount", "12");
        RequireData(r0NetworkStatusEvent, "lastDegradeReasonName", "wfpAleConnectTodo");

        var failureEvent = RequireEvent(result.Events, "vmware.runbook.executed");
        RequireData(failureEvent, "success", "false");
        RequireData(failureEvent, "failedStepIndex", "5");
        RequireData(failureEvent, "failedStepId", "wait-guest-remoting");
        RequireData(failureEvent, "message", "Live runbook execution stopped at step 6.");
        RequireData(failureEvent, "failureReason", "PowerShell exited with code 1");

        var guestImportEvent = RequireEvent(result.Events, "guest.events.imported");
        RequireData(guestImportEvent, "eventCount", "37");
        RequireData(guestImportEvent, "guestImportOutcome", "imported");

        var sampleStartFailure = RequireEvent(result.Events, "process.start_failed");
        RequireData(sampleStartFailure, "exceptionType", "System.IO.FileNotFoundException");
        RequireEvent(result.Events, "process.start");
        RequireEvent(result.Events, "process.exit");
        SmokeAssert.True(
            result.Events.Count(evt => string.Equals(evt.EventType, "network.tcp", StringComparison.OrdinalIgnoreCase)) == AttributedDynamicRows + 1,
            "Every sample-attributed dynamic row must remain in report sampling even when it exceeds MaxInlineEvents.");
        var unknownNetwork = result.Events.Single(evt =>
            string.Equals(evt.EventType, "network.tcp", StringComparison.OrdinalIgnoreCase) &&
            evt.Data.TryGetValue("sampleCorrelation", out var correlation) &&
            string.Equals(correlation, "unknown", StringComparison.OrdinalIgnoreCase));
        RequireData(unknownNetwork, "sampleCorrelationReason", "network-row-has-no-sample-owner-pid-join");
        RequireData(guestImportEvent, "guestImportMarker", "true");
        RequireData(guestImportEvent, "terminalStatus", "Completed");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Report sampler preserves static/network/probe/R0 priority evidence while slimming noisy rows."
        });
    }

    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Sampled events should retain {eventType}.");
        return evt!;
    }

    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(evt.Data.TryGetValue(key, out var actual), $"{evt.EventType} should retain Data[{key}].");
        SmokeAssert.True(string.Equals(actual, expected, StringComparison.Ordinal), $"{evt.EventType} Data[{key}] should be '{expected}', got '{actual}'.");
    }
}
