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
        RequireContains(html, "Driver network status / WFP-ALE", "R0 section should narrate WFP/ALE network status.");
        RequireContains(html, "Network status availability", "R0 network status should include availability card.");
        RequireContains(html, "r0collector.driverNetworkStatus", "R0 network status should be copyable by event name.");
        RequireContains(html, "activeLayerMask=0x00000007", "R0 network status copy block should include active WFP/ALE mask.");
        RequireContains(html, "VirusTotal official evidence", "VT section should summarize official file-object fields.");
        RequireContains(html, "VT reputation/community", "VT section should expose reputation/community score.");
        RequireContains(html, "vtEngineCount=71", "VT official evidence should include engine count.");
        RequireContains(html, "https://www.virustotal.com/gui/file/", "VT permalink should remain copyable evidence.");
        RequireContains(html, "Evidence health narrative", "Report should narrate evidence health before dense evidence.");
        RequireContains(html, "R0 / VT / Artifact health narrative", "Report should separate evidence health from sample behavior.");
        RequireContains(html, "Copy health narrative", "Evidence health narrative should be explicitly copyable.");
        RequireContains(html, "Stable relationship lanes", "Behavior graph should expose stable relationship lanes before dense edges.");
        RequireContains(html, "Process relation path", "Process cards should expose visible relationship paths.");
        RequireContains(html, "Artifact lane health", "Artifact status cards should expose lane health summaries.");
        RequireContains(html, "process-tree-sparkline", "Process tree should expose weak-interaction activity sparklines.");
        RequireContains(html, "Network relation path", "Network cards should expose readable process-to-endpoint relation paths.");
        RequireContains(html, "raw-page-nav", "Raw event expansion should expose native page shortcuts.");
        RequireContains(html, "Story evidence expansion summary", "Evidence expansions should show a visible summary before dense rows.");
        RequireContains(html, "artifactEvidenceMatrix overview", "Process story lane should surface artifactEvidenceMatrix overview evidence.");
        RequireContains(html, "Dropped-file artifactEvidenceMatrix", "Dropped-file story lane should surface artifactEvidenceMatrix state.");
        RequireContains(html, "Screenshot artifactEvidenceMatrix", "Screenshot story lane should surface artifactEvidenceMatrix state.");
        RequireContains(html, "Memory dump artifactEvidenceMatrix", "Memory dump story lane should surface artifactEvidenceMatrix state.");
        RequireContains(html, "PCAP artifactEvidenceMatrix", "PCAP story lane should surface artifactEvidenceMatrix state.");
        RequireContains(html, "artifactEvidenceMatrix lane", "Behavior graph artifact lane should include matrix-backed evidence.");
        RequireContains(html, "Network evidence expansion summary", "Network relationship expansions should summarize shown/hidden evidence.");
        RequireContains(html, "Raw event slimming story", "Raw event section should explain visible/folded/report-only evidence before row expansion.");
        RequireContains(html, "Artifact / network / R0 anchors", "Raw event slimming cards should preserve artifact/network/R0 evidence anchors.");
        RequireContains(html, "Copy raw slimming story", "Raw event slimming story should be explicitly copyable.");
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

        var events = new List<SandboxEvent> { processStart, r0NetworkStatus, staticResource, vt, networkFlow, artifactImportSummary, screenshot, memoryDump, packetCapture };
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
}
