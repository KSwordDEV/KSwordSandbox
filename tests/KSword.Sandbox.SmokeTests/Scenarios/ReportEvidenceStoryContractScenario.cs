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
            Events = [r0NetworkStatus, staticResource, vt],
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
        }
    ];

    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
