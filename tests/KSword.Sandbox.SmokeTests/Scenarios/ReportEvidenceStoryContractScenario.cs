using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies report storytelling for newly surfaced evidence lanes without
/// reading docs or running Hyper-V. Inputs are synthetic report models;
/// processing renders English HTML and checks stable copyable evidence blocks;
/// the scenario returns pass/fail metadata.
/// </summary>
internal sealed class ReportEvidenceStoryContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.evidence-story.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var renderer = new HtmlReportRenderer();
        var html = renderer.RenderEnglish(BuildReport(), BuildArtifacts());

        RequireContains(html, "Static PE resource story", "Report should include structured static resource storytelling.");
        RequireContains(html, "resourceRole", "Static resource evidence should be copyable with resourceRole.");
        RequireContains(html, "embedded-pe", "Static resource story should highlight embedded PE resources.");
        RequireContains(html, "Artifact index evidence", "Report should include artifact index selector diagnostics.");
        RequireContains(html, "Download selector / duplicate / rejection diagnostics", "Artifact rows should expose selector diagnostics.");
        RequireContains(html, "duplicateGroupCount=2", "Artifact evidence should include duplicate group metadata.");
        RequireContains(html, "unsafeGuestArtifactPath", "Artifact evidence should include rejection diagnostics.");
        RequireNotContains(html, "Driver network status / WFP-ALE", "R0 readiness diagnostics should stay out of the main report UI.");
        RequireNotContains(html, "Network status availability", "R0 readiness diagnostics should stay out of the main report UI.");
        RequireContains(html, "VirusTotal official evidence", "VT section should summarize official file-object fields.");
        RequireContains(html, "VT reputation/community", "VT section should expose reputation/community score.");
        RequireContains(html, "vtEngineCount=71", "VT official evidence should include engine count.");
        RequireContains(html, "https://www.virustotal.com/gui/file/", "VT permalink should remain copyable evidence.");
        RequireNotContains(html, "R0 / VT / Artifact health narrative", "Long health strategy text should stay out of the main report UI.");
        RequireContains(html, "Collection coverage gaps", "Report should list disabled, missing, and partial collection channels as explicit coverage gaps.");
        RequireContains(html, "WMI startup inventory", "Collection coverage should show WMI capture_failed counts and phases.");
        RequireContains(html, "capture_failed count=2", "WMI coverage should preserve before/after failure count.");
        RequireContains(html, "before-start, after-run", "WMI coverage should preserve capture phases.");
        RequireContains(html, "ETW live capture", "Collection coverage should show that live ETW is disabled.");
        RequireContains(html, "Security audit policy", "Collection coverage should show partial audit policy readiness.");
        RequireContains(html, "disabled/missing", "Collection coverage should show disabled R0/artifact lanes explicitly.");
        RequireContains(html, "environment network observed; no sample attribution", "Network coverage should distinguish environment network from missing collection.");
        RequireContains(html, "Network collection coverage", "Network coverage status should be rendered before endpoint cards.");
        RequireContains(html, "198.51.100.40", "The event explorer should retain an unattributed dynamic network row for review.");
        RequireContains(html, "packet-captures=1:ready:8192", "A later zero-byte counter must not erase artifact matrix byte evidence.");

        // VMware reports commonly inline only network.import.summary while raw
        // netstat/sidecar rows remain in events.json. Summary counters must
        // keep the network lane honest about observed environment traffic.
        var summaryOnlyReport = BuildReport() with
        {
            Events =
            [
                new SandboxEvent
                {
                    EventType = "network.import.summary",
                    Timestamp = DateTimeOffset.UtcNow,
                    Source = "host",
                    Data =
                    {
                        ["eventKind"] = "summary",
                        ["behaviorScope"] = "network-import-summary",
                        ["eventCount"] = "64",
                        ["canonicalBehaviorEventCount"] = "0",
                        ["behaviorCountedEventCount"] = "0",
                        ["sampleCorrelation"] = "environment",
                        ["sampleCorrelationStatus"] = "environment",
                        ["behaviorCounted"] = "false",
                        ["nonbehavior"] = "true"
                    }
                }
            ]
        };
        var summaryOnlyHtml = renderer.RenderEnglish(summaryOnlyReport, []);
        RequireContains(summaryOnlyHtml, "environment network observed; no sample attribution", "Network import summary counters should expose environment network without sample attribution.");
        RequireContains(summaryOnlyHtml, "Observed rows: 64", "Network import summary eventCount should survive report coverage rendering.");

        var snapshotOnlyReport = BuildReport() with
        {
            Events =
            [
                new SandboxEvent
                {
                    EventType = "network.netstat.snapshot",
                    Timestamp = DateTimeOffset.UtcNow,
                    Source = "guest",
                    Data =
                    {
                        ["phase"] = "after-run",
                        ["rowCount"] = "58",
                        ["emittedRows"] = "58",
                        ["behaviorCounted"] = "false",
                        ["nonbehavior"] = "true",
                        ["collectionHealth"] = "true"
                    }
                }
            ]
        };
        var snapshotOnlyHtml = renderer.RenderEnglish(snapshotOnlyReport, []);
        RequireContains(snapshotOnlyHtml, "environment network observed; no sample attribution", "Netstat snapshot rows should count as observed environment network.");
        RequireContains(snapshotOnlyHtml, "Observed rows: 58", "Netstat snapshot rowCount should survive report coverage rendering.");

        // If every environment/unknown network row spills out of the inline
        // sample and there is no import summary, raw/report metrics still
        // define the populated network lane.  HTML must keep it visible as
        // unattributed evidence instead of saying the channel was uncollected.
        var metricOnlyReport = BuildReport() with
        {
            Events =
            [
                new SandboxEvent
                {
                    EventType = "report.events.sampled",
                    Timestamp = DateTimeOffset.UtcNow,
                    Source = "host",
                    Data =
                    {
                        ["rawEventCount"] = "12",
                        ["selectedRawEventCount"] = "1",
                        ["omittedEventCount"] = "11"
                    }
                }
            ],
            Metrics = new Dictionary<string, int>
            {
                ["events.network.raw"] = 12,
                ["events.network.report"] = 0,
                ["events.network.attributedRaw"] = 0,
                ["events.network.attributedReport"] = 0,
                ["events.raw"] = 12,
                ["events.report"] = 1,
                ["events.omittedFromReport"] = 11
            }
        };
        var metricOnlyHtml = renderer.RenderEnglish(metricOnlyReport, []);
        RequireContains(metricOnlyHtml, "environment network observed; no sample attribution", "Raw network metrics should preserve an omitted environment/unknown lane.");
        RequireContains(metricOnlyHtml, "Observed rows: 12", "Raw network metrics should preserve the observed network count.");

        RequireContains(html, "Stable relationship lanes", "Behavior graph should expose stable relationship lanes before dense edges.");
        RequireContains(html, "Process relation path", "Process cards should expose visible relationship paths.");
        RequireContains(html, "Artifact lane health", "Artifact status cards should expose lane health summaries.");
        RequireContains(html, "process-tree-sparkline", "Process tree should expose weak-interaction activity sparklines.");
        RequireContains(html, "Network relation path", "Network cards should expose readable process-to-endpoint relation paths.");
        RequireContains(html, "raw-page-nav", "Raw event expansion should expose native page shortcuts.");
        RequireContains(html, "data-evidence-count=", "Bounded evidence blocks should retain machine-readable counts without a verbose visible summary.");
        RequireContains(html, "Artifact evidence matrix overview", "Process story lane should surface evidence-matrix overview evidence.");
        RequireContains(html, "Dropped-file evidence matrix", "Dropped-file story lane should surface evidence-matrix state.");
        RequireContains(html, "Screenshot evidence matrix", "Screenshot story lane should surface evidence-matrix state.");
        RequireContains(html, "Memory dump evidence matrix", "Memory dump story lane should surface evidence-matrix state.");
        RequireContains(html, "PCAP evidence matrix", "PCAP story lane should surface evidence-matrix state.");
        RequireContains(html, "Artifact evidence matrix lane", "Behavior graph artifact lane should include matrix-backed evidence.");
        RequireContains(html, "Network evidence", "Network relationship evidence should retain an accessible copy target.");
        RequireContains(html, "Raw event slimming story", "Raw event section should explain visible/folded/report-only evidence before row expansion.");
        RequireContains(html, "Artifact / network / R0 anchors", "Raw event slimming cards should preserve artifact/network/R0 evidence anchors.");
        RequireContains(html, "data-copy-button=\"true\"", "Raw event slimming story should be explicitly copyable.");
        RequireContains(html, "data-copy=", "New evidence cards should remain copyable.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "HTML report renders R0 network status, static resource, artifact-index, and VT official evidence stories."
        });
    }

    private static AnalysisReport BuildReport()
    {
        var timestamp = new DateTimeOffset(2026, 7, 12, 1, 2, 3, TimeSpan.Zero);
        var r0NetworkStatus = new SandboxEvent
        {
            EventType = "r0collector.driverNetworkStatus",
            Timestamp = timestamp.AddSeconds(1),
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
                ["lastDegradeReasonName"] = "wfpAleConnectTodo"
            }
        };
        var processStart = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp.AddMilliseconds(100),
            Source = "guest",
            ProcessName = "story.exe",
            ProcessId = 5000,
            Path = @"C:\Samples\story.exe",
            CommandLine = @"C:\Samples\story.exe"
        };
        var networkFlow = new SandboxEvent
        {
            EventType = "network.tcp",
            Timestamp = timestamp.AddSeconds(4),
            Source = "guest",
            ProcessName = "story.exe",
            ProcessId = 5000,
            Data =
            {
                ["remoteAddress"] = "203.0.113.55",
                ["remotePort"] = "443",
                ["protocol"] = "tcp"
            }
        };
        var staticResource = new SandboxEvent
        {
            EventType = "static.pe.resource",
            Timestamp = timestamp.AddSeconds(2),
            Source = "host",
            Path = @"D:\Samples\story.exe",
            Data =
            {
                ["resourceType"] = "RCDATA",
                ["resourceRole"] = "embedded-pe",
                ["isEmbeddedPe"] = "True",
                ["entropy"] = "7.850",
                ["size"] = "4096"
            }
        };
        var vt = new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Timestamp = timestamp.AddSeconds(3),
            Source = "virustotal",
            Path = "https://www.virustotal.com/gui/file/" + new string('a', 64),
            Data =
            {
                ["vtStatus"] = "found",
                ["vtVerdict"] = "malicious",
                ["vtMalicious"] = "3",
                ["vtSuspicious"] = "1",
                ["vtHarmless"] = "59",
                ["vtUndetected"] = "8",
                ["vtEngineCount"] = "71",
                ["vtReputation"] = "-12",
                ["vtCommunityScore"] = "-2",
                ["communityScoreSource"] = "reputation",
                ["vtCommunityHarmlessVotes"] = "1",
                ["vtCommunityMaliciousVotes"] = "3",
                ["vtCommunityVoteCount"] = "4",
                ["lastAnalysisDateUtc"] = "2026-07-10T00:00:00.0000000Z",
                ["permalink"] = "https://www.virustotal.com/gui/file/" + new string('a', 64)
            }
        };

        var artifactImportSummary = new SandboxEvent
        {
            EventType = "host.artifact.index",
            Timestamp = timestamp.AddSeconds(5),
            Source = "host",
            Data =
            {
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["notSampleBehavior"] = "true",
                ["artifactEvidenceMatrix"] = "dropped-files=1:ready:512;screenshots=1:ready:2048;memory-dumps=1:ready:4096;packet-captures=1:ready:8192",
                ["artifactEvidenceCollectionsReady"] = "dropped-files,screenshots,memory-dumps,packet-captures",
                ["primaryArtifactSelectors"] = "artifacts/drop.bin,screenshots/desktop.png,dumps/story.dmp,captures/story.pcapng",
                ["droppedFileArtifactCount"] = "1",
                ["screenshotArtifactCount"] = "1",
                ["memoryDumpArtifactCount"] = "1",
                ["packetCaptureArtifactCount"] = "1",
                ["droppedFileBytes"] = "512",
                ["screenshotBytes"] = "2048",
                ["memoryDumpBytes"] = "4096",
                ["packetCaptureBytes"] = "8192"
            }
        };

        var screenshot = new SandboxEvent
        {
            EventType = "screenshot.captured",
            Timestamp = timestamp.AddSeconds(6),
            Source = "guest",
            ProcessName = "story.exe",
            ProcessId = 5000,
            Data =
            {
                ["screenshotRelativePath"] = "screenshots/desktop.png",
                ["collectionName"] = "screenshots",
                ["captureStatus"] = "captured"
            }
        };

        var memoryDump = new SandboxEvent
        {
            EventType = "memory_dump.captured",
            Timestamp = timestamp.AddSeconds(7),
            Source = "guest",
            ProcessName = "story.exe",
            ProcessId = 5000,
            Data =
            {
                ["memoryDumpRelativePath"] = "dumps/story.dmp",
                ["collectionName"] = "memory-dumps",
                ["childProcessDumpEnabled"] = "true"
            }
        };

        var packetCapture = new SandboxEvent
        {
            EventType = "pcap.imported",
            Timestamp = timestamp.AddSeconds(8),
            Source = "host",
            ProcessName = "story.exe",
            ProcessId = 5000,
            Data =
            {
                ["pcapngRelativePath"] = "captures/story.pcapng",
                ["collectionName"] = "packet-captures",
                ["pcapngPacketCount"] = "42"
            }
        };

        var wmiBefore = new SandboxEvent
        {
            EventType = "startup_item.wmi.capture_failed",
            Timestamp = timestamp.AddMilliseconds(50),
            Source = "guest",
            Data =
            {
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true",
                ["phase"] = "before-start",
                ["exitCode"] = "1"
            }
        };
        var wmiAfter = new SandboxEvent
        {
            EventType = "startup_item.wmi.capture_failed",
            Timestamp = timestamp.AddSeconds(9),
            Source = "guest",
            Data =
            {
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true",
                ["phase"] = "after-run",
                ["exitCode"] = "1"
            }
        };
        var etwReadiness = new SandboxEvent
        {
            EventType = "etw_security.readiness.summary",
            Timestamp = timestamp.AddSeconds(9),
            Source = "guest",
            Data =
            {
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true",
                ["etwLiveCaptureEnabled"] = "false"
            }
        };
        var auditPartial = new SandboxEvent
        {
            EventType = "security_eventlog.audit_policy.summary",
            Timestamp = timestamp.AddSeconds(9),
            Source = "guest",
            Data =
            {
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true",
                ["captureState"] = "partial",
                ["auditPolicyStatus"] = "targetPoliciesNotFullySuccessEnabled"
            }
        };
        var r0Disabled = new SandboxEvent
        {
            EventType = "r0collector.disabled",
            Timestamp = timestamp.AddSeconds(9),
            Source = "r0collector",
            Data =
            {
                ["collectionHealth"] = "true",
                ["r0Enabled"] = "false"
            }
        };
        var environmentNetwork = new SandboxEvent
        {
            EventType = "network.tcp.closed",
            Timestamp = timestamp.AddSeconds(9),
            Source = "guest",
            Data =
            {
                ["sampleCorrelation"] = "environment",
                ["sampleCorrelationStatus"] = "environment",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["remoteAddress"] = "198.51.100.40",
                ["remotePort"] = "443"
            }
        };
        var lateZeroByteMatrixCounter = new SandboxEvent
        {
            EventType = "host.artifact.collection.completed",
            Timestamp = timestamp.AddSeconds(9.5),
            Source = "host",
            Data =
            {
                ["artifactEvidenceMatrix"] = "packet-captures=1:ready:0",
                ["packetCaptureArtifactCount"] = "1",
                ["packetCaptureBytes"] = "0"
            }
        };
        var events = new List<SandboxEvent> { processStart, r0NetworkStatus, staticResource, vt, networkFlow, artifactImportSummary, screenshot, memoryDump, packetCapture, wmiBefore, wmiAfter, etwReadiness, auditPartial, r0Disabled, environmentNetwork, lateZeroByteMatrixCounter };
        for (var index = 0; index < 30; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = $"story.raw.{index:D2}",
                Timestamp = timestamp.AddSeconds(10 + index),
                Source = "guest",
                ProcessName = "story.exe",
                ProcessId = 5000,
                Data =
                {
                    ["rawSource"] = "events.json",
                    ["index"] = index.ToString()
                }
            });
        }

        return new AnalysisReport
        {
            JobId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            GeneratedAt = timestamp,
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "story.exe",
                FullPath = @"D:\Samples\story.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            StaticAnalysis = new StaticAnalysisResult
            {
                FileFormat = "PE32+",
                Magic = "MZ",
                IsPe = true,
                Architecture = "x64",
                Subsystem = "Windows GUI",
                Resources =
                [
                    new PeResourceInfo
                    {
                        ResourceType = "RCDATA",
                        DataRva = "0x00004000",
                        DataFileOffset = "0x00002000",
                        Size = 4096,
                        Entropy = 7.85,
                        EntropyLabel = "high",
                        IsPayloadCandidate = true,
                        IsEmbeddedPe = true,
                        IsLarge = true,
                        Tags = ["resource_high_entropy_data", "resource_embedded_pe"]
                    }
                ],
                Tags = ["resource_embedded_pe"],
                InterestingStrings = ["resource:RCDATA@file=0x2000"]
            },
            Events = events,
            Findings = []
        };
    }

    private static IReadOnlyList<ArtifactDescriptor> BuildArtifacts() =>
    [
        new ArtifactDescriptor
        {
            Kind = ArtifactKind.DroppedFile,
            Category = "dropped-file",
            Name = "drop.bin",
            RelativePath = "artifacts/drop.bin",
            SafeLink = "artifacts/drop.bin",
            FullPath = @"D:\Jobs\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\artifacts\drop.bin",
            ImportPath = "artifacts/drop.bin",
            SizeBytes = 512,
            Sha256 = new string('d', 64),
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["downloadSelector"] = "artifacts/drop.bin",
                ["safeRelativeSelector"] = "artifacts/drop.bin",
                ["duplicateGroupKey"] = "sha256:" + new string('d', 64),
                ["duplicateGroupId"] = "duplicate-drop",
                ["duplicateGroupCount"] = "2",
                ["duplicateOrdinal"] = "1",
                ["isDuplicate"] = "true",
                ["duplicatePrimarySelector"] = "artifacts/primary-drop.bin",
                ["duplicateOfArtifactRelativePath"] = "artifacts/primary-drop.bin",
                ["rejectionDiagnosticsAvailable"] = "true",
                ["rejectedArtifactCount"] = "1",
                ["lastRejectedArtifactSelector"] = "../unsafe.bin",
                ["artifactRejectionReasons"] = "unsafeGuestArtifactPath"
            }
        },
        new ArtifactDescriptor
        {
            Kind = ArtifactKind.Screenshot,
            Category = "screenshot",
            Name = "desktop.png",
            RelativePath = "screenshots/desktop.png",
            SafeLink = "screenshots/desktop.png",
            SizeBytes = 2048,
            Sha256 = new string('e', 64),
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["downloadSelector"] = "screenshots/desktop.png"
            }
        },
        new ArtifactDescriptor
        {
            Kind = ArtifactKind.MemoryDump,
            Category = "memory-dump",
            Name = "story.dmp",
            RelativePath = "dumps/story.dmp",
            SafeLink = "dumps/story.dmp",
            SizeBytes = 4096,
            Sha256 = new string('f', 64),
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["downloadSelector"] = "dumps/story.dmp"
            }
        },
        new ArtifactDescriptor
        {
            Kind = ArtifactKind.PacketCapture,
            Category = "packet-capture",
            Name = "story.pcapng",
            RelativePath = "captures/story.pcapng",
            SafeLink = "captures/story.pcapng",
            SizeBytes = 8192,
            Sha256 = new string('1', 64),
            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["downloadSelector"] = "captures/story.pcapng"
            }
        }
    ];

    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    private static void RequireNotContains(string content, string unexpected, string message)
    {
        SmokeAssert.True(!content.Contains(unexpected, StringComparison.Ordinal), message);
    }
}
