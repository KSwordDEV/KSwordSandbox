using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Pipeline;
using KSword.Sandbox.Core.Pipeline.Stages;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the artifact-manifest evidence-chain contract.
/// Inputs are repository/runtime paths from SmokeTestContext; processing
/// round-trips host manifests, reads a guest artifacts/manifest.json shape, and
/// checks documentation/source markers; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class ArtifactManifestContractScenario : ISmokeTestScenario
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public string ScenarioId => "artifacts.manifest.contract";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        AssertSourceContracts(context);
        await AssertHostManifestRoundTripAsync(context, cancellationToken);
        await AssertGuestManifestReaderAsync(context, cancellationToken);
        await AssertHostArtifactIndexAsync(context, cancellationToken);
        await AssertHostArtifactImportReportEventsAsync(context, cancellationToken);
        await AssertArtifactDownloadSelectorsAsync(context, cancellationToken);
        await AssertReportArtifactLinksAsync(context, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Artifact manifest schema, host index, guest reader, and report artifact links are present."
        };
    }

    /// <summary>
    /// Verifies host artifact import events and non-behavior Chinese health
    /// diagnostics produced during report regeneration.
    /// </summary>
    private static async Task AssertHostArtifactImportReportEventsAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "artifact-host-import", Guid.NewGuid().ToString("N"));
        var service = CreateArtifactImportService(context, runtimeRoot);
        var samplePath = Path.Combine(runtimeRoot, "host-import-sample.exe");
        Directory.CreateDirectory(runtimeRoot);
        await File.WriteAllTextAsync(samplePath, "host import sample", cancellationToken);

        var importedJobId = Guid.NewGuid();
        var importedJobRoot = Path.Combine(runtimeRoot, "jobs", importedJobId.ToString("N"));
        var importedGuestRoot = Path.Combine(importedJobRoot, "guest", importedJobId.ToString("N"));
        var droppedRoot = Path.Combine(importedGuestRoot, "artifacts", "dropped-files");
        var screenshotsRoot = Path.Combine(importedGuestRoot, "screenshots");
        var memoryRoot = Path.Combine(importedGuestRoot, "memory-dumps");
        var pcapRoot = Path.Combine(importedGuestRoot, "packet-captures");
        Directory.CreateDirectory(droppedRoot);
        Directory.CreateDirectory(screenshotsRoot);
        Directory.CreateDirectory(memoryRoot);
        Directory.CreateDirectory(pcapRoot);
        var droppedPath = Path.Combine(droppedRoot, "downloaded.bin");
        var screenshotPath = Path.Combine(screenshotsRoot, "after-run.bmp");
        var memoryPath = Path.Combine(memoryRoot, "after-run-pid4242.dmp");
        var pcapPath = Path.Combine(pcapRoot, "after-run.pcap");
        await File.WriteAllTextAsync(droppedPath, "drop", cancellationToken);
        await File.WriteAllBytesAsync(screenshotPath, [0x42, 0x4d, 0x00, 0x00], cancellationToken);
        await File.WriteAllBytesAsync(memoryPath, [0x4d, 0x44, 0x4d, 0x50], cancellationToken);
        await File.WriteAllBytesAsync(pcapPath, BuildMinimalPcapHeader(), cancellationToken);
        var importedEventsPath = Path.Combine(importedGuestRoot, "events.json");
        await File.WriteAllTextAsync(
            importedEventsPath,
            JsonSerializer.Serialize(new[]
            {
                new SandboxEvent
                {
                    EventType = "artifact.dropped_file.copied",
                    Source = "guest",
                    Path = droppedPath,
                    Data =
                    {
                        ["collectionName"] = "dropped-files",
                        ["evidenceRole"] = "dropped-file",
                        ["artifactRelativePath"] = "artifacts/dropped-files/downloaded.bin",
                        ["guestFullPath"] = @"C:\work\downloaded.bin"
                    }
                },
                new SandboxEvent
                {
                    EventType = "screenshot.captured",
                    Source = "guest",
                    Path = screenshotPath,
                    Data =
                    {
                        ["collectionName"] = "screenshots",
                        ["evidenceRole"] = "screenshot",
                        ["screenshotRelativePath"] = "screenshots/after-run.bmp",
                        ["capturePhase"] = "after-run"
                    }
                },
                new SandboxEvent
                {
                    EventType = "memory_dump.captured",
                    Source = "guest",
                    Path = memoryPath,
                    ProcessId = 4242,
                    Data =
                    {
                        ["collectionName"] = "memory-dumps",
                        ["evidenceRole"] = "memory-dump",
                        ["memoryDumpRelativePath"] = "memory-dumps/after-run-pid4242.dmp",
                        ["rootProcessId"] = "4242"
                    }
                },
                new SandboxEvent
                {
                    EventType = "packet_capture.captured",
                    Source = "guest",
                    Path = pcapPath,
                    Data =
                    {
                        ["collectionName"] = "packet-captures",
                        ["evidenceRole"] = "packet-capture",
                        ["pcapRelativePath"] = "packet-captures/after-run.pcap"
                    }
                }
            }, ManifestJsonOptions),
            cancellationToken);

        var importedJob = service.ImportExternalRun(
            importedJobId,
            CreateArtifactImportSubmission(samplePath),
            importedEventsPath);
        var importedReport = await ReadReportAsync(importedJob.JsonReportPath, cancellationToken);
        var hostImportedEvents = importedReport.Events
            .Where(evt => string.Equals(evt.EventType, "artifact.host_imported", StringComparison.OrdinalIgnoreCase))
            .ToList();
        AssertHostImportedArtifactEvent(hostImportedEvents, ArtifactKind.DroppedFile, "dropped-files");
        AssertHostImportedArtifactEvent(hostImportedEvents, ArtifactKind.Screenshot, "screenshots");
        AssertHostImportedArtifactEvent(hostImportedEvents, ArtifactKind.MemoryDump, "memory-dumps");
        AssertHostImportedArtifactEvent(hostImportedEvents, ArtifactKind.PacketCapture, "packet-captures");
        var importSummary = importedReport.Events.FirstOrDefault(evt =>
            string.Equals(evt.EventType, "artifact.import_summary", StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(importSummary is not null, "Imported report should include a report-ready host artifact import summary event.");
        RequireData(importSummary!, "behaviorCounted", "false");
        RequireData(importSummary!, "downloadPolicy", "relative-index-selectors-only");
        SmokeAssert.True(
            importSummary!.Data.TryGetValue("importedSensitiveArtifactCount", out var importedSensitiveArtifactCount) &&
            int.Parse(importedSensitiveArtifactCount) >= 4,
            "Artifact import summary should count downloadable dropped-file/screenshot/memory/PCAP evidence.");

        var missingJobId = Guid.NewGuid();
        var missingJobRoot = Path.Combine(runtimeRoot, "jobs", missingJobId.ToString("N"));
        var missingGuestRoot = Path.Combine(missingJobRoot, "guest", missingJobId.ToString("N"));
        Directory.CreateDirectory(missingGuestRoot);
        var missingEventsPath = Path.Combine(missingGuestRoot, "events.json");
        await File.WriteAllTextAsync(
            missingEventsPath,
            JsonSerializer.Serialize(new[]
            {
                new SandboxEvent
                {
                    EventType = "memory_dump.failed",
                    Source = "guest",
                    Data =
                    {
                        ["collectionName"] = "memory-dumps",
                        ["evidenceRole"] = "memory-dump",
                        ["captureState"] = "failed",
                        ["status"] = "failed",
                        ["reason"] = "targetProcessExited",
                        ["zhHint"] = "目标进程已退出，未生成内存转储。"
                    }
                }
            }, ManifestJsonOptions),
            cancellationToken);

        var missingJob = service.ImportExternalRun(
            missingJobId,
            CreateArtifactImportSubmission(samplePath),
            missingEventsPath);
        var missingReport = await ReadReportAsync(missingJob.JsonReportPath, cancellationToken);
        var health = missingReport.Events.Single(evt =>
            string.Equals(evt.EventType, "collection.health", StringComparison.OrdinalIgnoreCase) &&
            evt.Data.TryGetValue("collectionName", out var collectionName) &&
            collectionName == "memory-dumps");
        RequireData(health, "healthStatus", "collection-health");
        RequireData(health, "behaviorCounted", "false");
        RequireData(health, "artifactMissing", "true");
        RequireData(health, "sourceEventType", "memory_dump.failed");
        SmokeAssert.True(health.Data.TryGetValue("zhMessage", out var zhMessage) && zhMessage.Contains("不代表样本行为", StringComparison.Ordinal), "Missing artifact health should include a Chinese non-behavior diagnostic.");
        SmokeAssert.True(missingReport.Findings.SelectMany(finding => finding.Evidence).All(evt => !string.Equals(evt.EventType, "collection.health", StringComparison.OrdinalIgnoreCase)), "Collection health diagnostics should not be classified as behavior findings.");
    }

    private static SandboxJobService CreateArtifactImportService(SmokeTestContext context, string runtimeRoot)
    {
        return new SandboxJobService(
            new SandboxConfig
            {
                Analysis = new AnalysisConfig
                {
                    DefaultDurationSeconds = 5,
                    MaxDurationSeconds = 60,
                    MaxSampleBytes = 1024 * 1024
                },
                Paths = new SandboxPaths
                {
                    RuntimeRoot = runtimeRoot,
                    RulesDirectory = context.RulesDirectory,
                    GuestPayloadRoot = Path.Combine(runtimeRoot, "payload")
                },
                ArtifactCollection = new ArtifactCollectionConfig
                {
                    CollectDroppedFiles = true,
                    CaptureScreenshots = true,
                    CaptureMemoryDumps = true,
                    CapturePacketCapture = true
                }
            },
            RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json")));
    }

    private static SandboxSubmission CreateArtifactImportSubmission(string samplePath)
    {
        return new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = false,
            CollectDroppedFiles = true,
            CaptureScreenshots = true,
            CaptureMemoryDumps = true,
            CapturePacketCapture = true
        };
    }

    private static async Task<AnalysisReport> ReadReportAsync(string? reportPath, CancellationToken cancellationToken)
    {
        SmokeAssert.True(!string.IsNullOrWhiteSpace(reportPath) && File.Exists(reportPath), "Imported job should write report.json.");
        return JsonSerializer.Deserialize<AnalysisReport>(
            await File.ReadAllTextAsync(reportPath!, cancellationToken),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("Imported report should deserialize.");
    }

    private static void AssertHostImportedArtifactEvent(
        IReadOnlyCollection<SandboxEvent> events,
        ArtifactKind kind,
        string collectionName)
    {
        var evt = events.FirstOrDefault(candidate =>
            candidate.Data.TryGetValue("sourceArtifactKind", out var actualKind) &&
            actualKind == kind.ToString() &&
            candidate.Data.TryGetValue("collectionName", out var actualCollection) &&
            actualCollection == collectionName);
        SmokeAssert.True(evt is not null, $"{kind} should emit artifact.host_imported.");
        SmokeAssert.True(
            evt!.Data.TryGetValue("behaviorCounted", out var behaviorCounted) && behaviorCounted == "false" ||
            evt.Data.TryGetValue("nonbehavior", out var nonbehavior) && nonbehavior == "true",
            $"{kind} host import event should remain marked as non-behavior even after report sampling.");
        RequireData(evt!, "sourceArtifactKind", kind.ToString());
        RequireData(evt!, "collectionName", collectionName);
        SmokeAssert.True(evt!.Data.TryGetValue("sourceArtifactSizeBytes", out var size) && long.Parse(size) > 0, $"{kind} host import event should include source artifact size.");
        SmokeAssert.True(evt.Data.TryGetValue("sourceArtifactSha256", out var sha256) && sha256.Length == 64, $"{kind} host import event should include source artifact SHA-256.");
        SmokeAssert.True(
            evt.Data.TryGetValue("sourceEventType", out var sourceEventType) && !string.IsNullOrWhiteSpace(sourceEventType) ||
            evt.Data.TryGetValue("__omittedDataPairs", out var omittedPairs) && int.TryParse(omittedPairs, out var omittedCount) && omittedCount > 0,
            $"{kind} host import event should include source event type or report sampler omission diagnostics.");
        SmokeAssert.True(
            evt.Data.TryGetValue("downloadSelector", out var downloadSelector) ||
            evt.Data.TryGetValue("artifactRelativePath", out downloadSelector) ||
            evt.Data.TryGetValue("sourceArtifactRelativePath", out downloadSelector),
            $"{kind} host import event should include a guarded download selector or sampled artifact-relative selector.");
        downloadSelector ??= string.Empty;
        AssertSafeSelectorValue($"{kind} import downloadSelector", downloadSelector);
        SmokeAssert.True(
            evt.Data.TryGetValue("downloadSafeLink", out var downloadSafeLink) ||
            evt.Data.TryGetValue("safeLink", out downloadSafeLink) ||
            evt.Data.TryGetValue("artifactRelativePath", out downloadSafeLink) ||
            evt.Data.TryGetValue("sourceArtifactRelativePath", out downloadSafeLink),
            $"{kind} host import event should include a guarded safe-link selector or sampled artifact-relative selector.");
        downloadSafeLink ??= string.Empty;
        AssertSafeSelectorValue($"{kind} import downloadSafeLink", downloadSafeLink);
        SmokeAssert.True(
            !downloadSelector.Contains(':', StringComparison.Ordinal) &&
            !downloadSelector.Contains('\\', StringComparison.Ordinal),
            $"{kind} host import download selector should not be an absolute host path.");
        SmokeAssert.True(evt.Data.TryGetValue("zhMessage", out var zhMessage) && zhMessage.Contains("Host 已索引", StringComparison.Ordinal), $"{kind} host import event should include Chinese import message.");
    }

    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(evt.Data.TryGetValue(key, out var actual) && string.Equals(actual, expected, StringComparison.Ordinal), $"{evt.EventType} should include {key}={expected}; actual={actual ?? "<missing>"}.");
    }

    private static byte[] BuildMinimalPcapHeader()
    {
        return
        [
            0xd4, 0xc3, 0xb2, 0xa1,
            0x02, 0x00,
            0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00
        ];
    }

    /// <summary>
    /// Checks source and documentation for manifest contract markers.
    /// Inputs are the smoke context, processing reads allowed repository files,
    /// and the method throws when required terms are missing.
    /// </summary>
    private static void AssertSourceContracts(SmokeTestContext context)
    {
        var guestWriter = ReadRepositoryText(context, "guest", "KSword.Sandbox.Agent", "Output", "GuestArtifactWriter.cs");
        var guestDoc = ReadRepositoryText(context, "docs", "guest-agent.md");
        var reportDoc = ReadRepositoryText(context, "docs", "report-schema.md");
        var artifactDoc = ReadRepositoryText(context, "docs", "artifact-manifest.md");
        var artifactsDoc = ReadRepositoryText(context, "docs", "artifacts.md");
        var reportStage = ReadRepositoryText(context, "src", "KSword.Sandbox.Core", "Pipeline", "Stages", "ReportArtifactStage.cs");
        var webProgram = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Program.cs");

        SmokeAssert.True(guestWriter.Contains("WriteArtifactManifest", StringComparison.Ordinal), "Guest writer should expose artifact manifest output.");
        SmokeAssert.True(guestWriter.Contains("artifacts", StringComparison.Ordinal), "Guest writer should use the artifacts directory.");
        SmokeAssert.True(guestWriter.Contains("manifest.json", StringComparison.Ordinal), "Guest writer should write manifest.json.");
        SmokeAssert.True(guestWriter.Contains("MimeType", StringComparison.Ordinal), "Guest writer should include MIME metadata.");
        SmokeAssert.True(guestWriter.Contains("SafeLink", StringComparison.Ordinal), "Guest writer should include safe links.");
        SmokeAssert.True(guestWriter.Contains("Collections", StringComparison.Ordinal), "Guest writer should include artifact collection lanes.");
        SmokeAssert.True(guestWriter.Contains("PacketCapture", StringComparison.Ordinal), "Guest writer should include packet-capture manifest lanes.");
        SmokeAssert.True(guestWriter.Contains("packetCaptureNotRequested", StringComparison.Ordinal), "Guest writer should treat packet capture as an implemented opt-in collection.");
        SmokeAssert.True(guestWriter.Contains("MemoryDump", StringComparison.Ordinal), "Guest writer should include memory-dump manifest descriptors.");
        SmokeAssert.True(guestWriter.Contains("artifactRelativePath", StringComparison.Ordinal), "Guest writer should preserve artifact-relative event metadata.");
        SmokeAssert.True(guestWriter.Contains("lastReason", StringComparison.Ordinal), "Guest writer should preserve concrete collection failure reasons.");
        SmokeAssert.True(guestWriter.Contains("lastDiagnosticStage", StringComparison.Ordinal), "Guest writer should preserve collection diagnostic stages.");
        SmokeAssert.True(guestWriter.Contains("lastProcessId", StringComparison.Ordinal), "Guest writer should preserve artifact collection process identity.");
        SmokeAssert.True(guestWriter.Contains("CountProbeFailureEvents", StringComparison.Ordinal), "Guest writer should count probe failures in collection status.");
        SmokeAssert.True(guestDoc.Contains("artifacts/manifest.json", StringComparison.Ordinal), "Guest-agent doc should describe artifacts/manifest.json.");
        SmokeAssert.True(reportDoc.Contains("ArtifactManifest", StringComparison.Ordinal), "Report schema doc should describe ArtifactManifest.");
        SmokeAssert.True(reportDoc.Contains("DroppedFile", StringComparison.Ordinal), "Report schema doc should describe dropped-file artifact entries.");
        SmokeAssert.True(reportDoc.Contains("PacketCapture", StringComparison.Ordinal), "Report schema doc should describe packet-capture artifact entries.");
        SmokeAssert.True(reportDoc.Contains("artifact-index.json", StringComparison.Ordinal), "Report schema doc should describe host artifact index.");
        SmokeAssert.True(artifactDoc.Contains("safeLink", StringComparison.Ordinal), "Artifact manifest doc should describe safe links.");
        SmokeAssert.True(artifactDoc.Contains("mimeType", StringComparison.Ordinal), "Artifact manifest doc should describe MIME type.");
        SmokeAssert.True(artifactDoc.Contains("collections", StringComparison.OrdinalIgnoreCase), "Artifact manifest doc should describe collection lanes.");
        SmokeAssert.True(artifactDoc.Contains("PacketCapture", StringComparison.Ordinal), "Artifact manifest doc should describe packet-capture artifacts.");
        SmokeAssert.True(artifactDoc.Contains("external-pcap-artifacts-indexed", StringComparison.OrdinalIgnoreCase), "Artifact manifest doc should describe external PCAP consumption.");
        SmokeAssert.True(artifactsDoc.Contains("duplicateGroupId", StringComparison.Ordinal), "Artifacts doc should describe duplicate grouping metadata.");
        SmokeAssert.True(artifactsDoc.Contains("rejectionDiagnosticsAvailable", StringComparison.Ordinal), "Artifacts doc should describe manifest rejection diagnostics.");
        SmokeAssert.True(artifactsDoc.Contains("downloadSecurityPolicy=server-indexed-relative-selector", StringComparison.Ordinal), "Artifacts doc should describe Web-safe download selector policy.");
        SmokeAssert.True(reportStage.Contains("HostArtifactIndexBuilder", StringComparison.Ordinal), "Report artifact stage should write host artifact index.");
        SmokeAssert.True(webProgram.Contains("BuildWebArtifactSelectors", StringComparison.Ordinal), "Web artifact endpoint should normalize safe selector DTO fields.");
        SmokeAssert.True(webProgram.Contains("SafeSelectorPreview", StringComparison.Ordinal), "Web artifact download helper should return safe rejection diagnostics.");
        SmokeAssert.True(webProgram.Contains("RejectionDiagnostics", StringComparison.Ordinal), "Web artifact collection DTO should expose safe rejection diagnostics.");
    }

    /// <summary>
    /// Verifies host-side manifest persistence through FileSystemArtifactStore.
    /// Inputs are the smoke context and cancellation token; processing writes and
    /// reads a manifest artifact; the method throws on contract mismatch.
    /// </summary>
    private static async Task AssertHostManifestRoundTripAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "artifact-manifest-host", Guid.NewGuid().ToString("N"));
        var store = new FileSystemArtifactStore(runtimeRoot);
        var jobId = Guid.NewGuid();
        var manifest = new ArtifactManifest
        {
            Producer = "smoke",
            Collections =
            [
                new ArtifactCollectionDescriptor
                {
                    Name = "dropped-files",
                    Kind = ArtifactKind.DroppedFile,
                    Category = "dropped-file",
                    EvidenceRole = "dropped-file",
                    RelativePath = "artifacts/dropped-files",
                    Enabled = true,
                    Implemented = true,
                    Status = "captured"
                }
            ],
            Artifacts =
            [
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.DroppedFile,
                    Name = "drop.bin",
                    Category = "dropped-file",
                    RelativePath = "artifacts/dropped-files/drop.bin",
                    SafeLink = "artifacts/dropped-files/drop.bin",
                    EvidenceRole = "dropped-file",
                    CaptureState = "captured",
                    GuestPath = @"C:\work\drop.bin",
                    ImportPath = "artifacts/dropped-files/drop.bin",
                    CollectionName = "dropped-files",
                    MimeType = "application/octet-stream",
                    SizeBytes = 4,
                    Sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
                    Hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
                    },
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["evidenceRole"] = "dropped-file"
                    }
                }
            ]
        };

        var descriptor = await store.WriteManifestAsync(jobId, manifest, cancellationToken);
        SmokeAssert.True(descriptor.Kind == ArtifactKind.ArtifactManifest, "Manifest descriptor should use ArtifactManifest kind.");
        SmokeAssert.True(File.Exists(descriptor.FullPath), "Manifest file should be written.");
        AssertArtifactManifestJsonShape(descriptor.FullPath, "host artifact manifest");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(descriptor.Sha256), "Manifest descriptor should include SHA-256.");
        SmokeAssert.True(descriptor.SizeBytes > 0, "Manifest descriptor should include size.");
        SmokeAssert.True(descriptor.MimeType == "application/json", "Manifest descriptor should include MIME type.");
        SmokeAssert.True(descriptor.Category == "artifact-manifest", "Manifest descriptor should include category.");
        SmokeAssert.True(descriptor.SafeLink == "artifact-manifest.json", "Manifest descriptor should include a safe relative link.");

        var roundTrip = await store.ReadManifestAsync(descriptor, cancellationToken);
        SmokeAssert.True(roundTrip.JobId == jobId, "Round-tripped manifest should carry job ID.");
        SmokeAssert.True(roundTrip.ImportRoot == Path.Combine(runtimeRoot, "jobs", jobId.ToString("N")), "Round-tripped manifest should carry normalized import root.");
        SmokeAssert.True(roundTrip.Collections.Count == 1, "Round-tripped manifest should preserve collection entries.");
        SmokeAssert.True(roundTrip.Collections[0].SafeLink == "artifacts/dropped-files", "Round-tripped collection should expose a safe link.");
        SmokeAssert.True(roundTrip.Artifacts.Count == 1, "Round-tripped manifest should preserve artifact entries.");
        SmokeAssert.True(roundTrip.Artifacts[0].Kind == ArtifactKind.DroppedFile, "Round-tripped manifest should preserve dropped-file kind.");
        SmokeAssert.True(roundTrip.Artifacts[0].Hashes.ContainsKey("sha256"), "Round-tripped manifest entries should expose hash map.");
        SmokeAssert.True(roundTrip.Artifacts[0].SafeLink == "artifacts/dropped-files/drop.bin", "Round-tripped manifest entries should preserve safe link.");
        SmokeAssert.True(roundTrip.Artifacts[0].EvidenceRole == "dropped-file", "Round-tripped manifest entries should preserve evidence role.");
        SmokeAssert.True(roundTrip.Artifacts[0].ImportPath == "artifacts/dropped-files/drop.bin", "Round-tripped manifest entries should preserve import path.");
    }

    /// <summary>
    /// Verifies host-side loading of collected guest artifacts/manifest.json.
    /// Inputs are smoke context and cancellation token; processing writes a
    /// synthetic guest manifest and reads it through GuestArtifactManifestReader.
    /// </summary>
    private static async Task AssertGuestManifestReaderAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var guestRoot = Path.Combine(context.RuntimeRoot, "artifact-manifest-guest", Guid.NewGuid().ToString("N"));
        var artifactsRoot = Path.Combine(guestRoot, "artifacts");
        var droppedFilesRoot = Path.Combine(artifactsRoot, "dropped-files");
        var screenshotsRoot = Path.Combine(guestRoot, "screenshots");
        var memoryDumpsRoot = Path.Combine(guestRoot, "memory-dumps");
        var packetCapturesRoot = Path.Combine(guestRoot, "packet-captures");
        Directory.CreateDirectory(droppedFilesRoot);
        Directory.CreateDirectory(screenshotsRoot);
        Directory.CreateDirectory(memoryDumpsRoot);
        Directory.CreateDirectory(packetCapturesRoot);
        var droppedFilePath = Path.Combine(droppedFilesRoot, "drop.bin");
        var screenshotPath = Path.Combine(screenshotsRoot, "after-run.bmp");
        var memoryDumpPath = Path.Combine(memoryDumpsRoot, "after-start-pid123.dmp");
        var packetCapturePath = Path.Combine(packetCapturesRoot, "external.pcap");
        await File.WriteAllTextAsync(droppedFilePath, "drop", cancellationToken);
        await File.WriteAllBytesAsync(screenshotPath, [0x42, 0x4d, 0x00, 0x00], cancellationToken);
        await File.WriteAllBytesAsync(memoryDumpPath, [0x4d, 0x44, 0x4d, 0x50], cancellationToken);
        await File.WriteAllBytesAsync(packetCapturePath, [0xd4, 0xc3, 0xb2, 0xa1], cancellationToken);

        var manifestPath = Path.Combine(artifactsRoot, "manifest.json");
        var manifest = new ArtifactManifest
        {
            RuntimeRoot = @"C:\KSwordSandbox\out",
            RootPath = @"C:\KSwordSandbox\out\artifacts",
            ImportRoot = @"C:\KSwordSandbox\out",
            Producer = "KSword.Sandbox.Agent",
            Collections =
            [
                new ArtifactCollectionDescriptor
                {
                    Name = "dropped-files",
                    Kind = ArtifactKind.DroppedFile,
                    Category = "dropped-file",
                    EvidenceRole = "dropped-file",
                    RelativePath = "artifacts/dropped-files",
                    Enabled = true,
                    Implemented = true,
                    Status = "captured"
                },
                new ArtifactCollectionDescriptor
                {
                    Name = "packet-captures",
                    Kind = ArtifactKind.PacketCapture,
                    Category = "packet-capture",
                    EvidenceRole = "packet-capture",
                    RelativePath = "packet-captures",
                    Enabled = true,
                    Implemented = false,
                    Status = "captured",
                    Reason = "external-pcap-supplied",
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["captureSource"] = "external",
                        ["hostCaptureStarted"] = "false"
                    }
                }
            ],
            Artifacts =
            [
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.DroppedFile,
                    Name = "drop.bin",
                    Category = "dropped-file",
                    RelativePath = "artifacts/dropped-files/drop.bin",
                    FullPath = @"C:\KSwordSandbox\out\artifacts\dropped-files\drop.bin",
                    SafeLink = "artifacts/dropped-files/drop.bin",
                    EvidenceRole = "dropped-file",
                    CaptureState = "captured",
                    GuestPath = @"C:\work\drop.bin",
                    ImportPath = "artifacts/dropped-files/drop.bin",
                    CollectionName = "dropped-files",
                    MimeType = "application/octet-stream",
                    SizeBytes = 4,
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["origin"] = "guest",
                        ["guestRelativePath"] = "drop.bin"
                    }
                },
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.Screenshot,
                    Name = "after-run.bmp",
                    Category = "screenshot",
                    RelativePath = "screenshots/after-run.bmp",
                    FullPath = @"C:\KSwordSandbox\out\screenshots\after-run.bmp",
                    EvidenceRole = "screenshot",
                    CapturePhase = "after-run",
                    CaptureState = "captured",
                    ImportPath = "screenshots/after-run.bmp",
                    CollectionName = "screenshots",
                    MimeType = "image/bmp",
                    SizeBytes = 4
                },
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.MemoryDump,
                    Name = "after-start-pid123.dmp",
                    Category = "memory-dump",
                    RelativePath = "memory-dumps/after-start-pid123.dmp",
                    FullPath = @"C:\KSwordSandbox\out\memory-dumps\after-start-pid123.dmp",
                    EvidenceRole = "memory-dump",
                    CapturePhase = "after-start",
                    CaptureState = "captured",
                    ImportPath = "memory-dumps/after-start-pid123.dmp",
                    CollectionName = "memory-dumps",
                    MimeType = "application/vnd.microsoft.minidump",
                    SizeBytes = 4
                },
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.PacketCapture,
                    Name = "external.pcap",
                    RelativePath = "packet-captures/external.pcap",
                    FullPath = @"C:\KSwordSandbox\out\packet-captures\external.pcap",
                    ImportPath = "packet-captures/external.pcap",
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["origin"] = "guest",
                        ["captureSource"] = "external",
                        ["hostCaptureStarted"] = "false"
                    }
                },
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.DroppedFile,
                    Name = "escape.bin",
                    Category = "dropped-file",
                    RelativePath = "../escape.bin",
                    FullPath = @"C:\KSwordSandbox\out\escape.bin"
                }
            ]
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, ManifestJsonOptions), cancellationToken);
        AssertArtifactManifestJsonShape(manifestPath, "guest artifact manifest");

        var reader = new GuestArtifactManifestReader();
        var loaded = await reader.TryReadAsync(guestRoot, cancellationToken)
            ?? throw new InvalidOperationException("Guest manifest should load.");

        SmokeAssert.True(loaded.RootPath == artifactsRoot, "Loaded guest manifest should normalize root path to host artifacts directory.");
        SmokeAssert.True(loaded.ImportRoot == guestRoot, "Loaded guest manifest should normalize import root to host guest output.");
        SmokeAssert.True(loaded.Collections.Count == 2, "Loaded guest manifest should preserve collection lanes.");
        SmokeAssert.True(loaded.Collections.Any(collection => collection.Kind == ArtifactKind.PacketCapture && !collection.Implemented && collection.Status == "captured"), "Loaded guest manifest should preserve external packet-capture collection metadata without implying host capture support.");
        SmokeAssert.True(loaded.Artifacts.Count == 5, "Loaded guest manifest should preserve artifact count, including packet captures and unsafe entries as non-linkable descriptors.");
        SmokeAssert.True(loaded.Artifacts[0].FullPath == droppedFilePath, "Loaded guest artifact should resolve full host path from relative path.");
        SmokeAssert.True(loaded.Artifacts[0].Metadata.ContainsKey("guestFullPath"), "Loaded guest artifact should preserve original guest full path.");
        SmokeAssert.True(loaded.Artifacts[0].Category == "dropped-file", "Loaded guest artifact should preserve category.");
        SmokeAssert.True(loaded.Artifacts[0].MimeType == "application/octet-stream", "Loaded guest artifact should preserve MIME type.");
        SmokeAssert.True(loaded.Artifacts[0].SafeLink == "artifacts/dropped-files/drop.bin", "Loaded guest artifact should expose a safe link.");
        SmokeAssert.True(loaded.Artifacts[0].EvidenceRole == "dropped-file", "Loaded guest artifact should preserve evidence role.");
        SmokeAssert.True(loaded.Artifacts[0].ImportPath == "artifacts/dropped-files/drop.bin", "Loaded guest artifact should preserve import path.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(loaded.Artifacts[0].Sha256), "Loaded guest artifact should fill SHA-256 when file is present.");
        var loadedScreenshot = loaded.Artifacts.Single(artifact => artifact.Kind == ArtifactKind.Screenshot);
        SmokeAssert.True(loadedScreenshot.CapturePhase == "after-run", "Loaded guest manifest should preserve screenshot capture phase.");
        SmokeAssert.True(loadedScreenshot.CaptureState == "captured", "Loaded guest manifest should preserve screenshot capture state.");
        SmokeAssert.True(loadedScreenshot.CollectionName == "screenshots", "Loaded guest manifest should preserve screenshot collection names.");
        SmokeAssert.True(loadedScreenshot.ImportPath == "screenshots/after-run.bmp", "Loaded guest screenshot should preserve safe import path.");
        SmokeAssert.True(loadedScreenshot.SafeLink == "screenshots/after-run.bmp", "Loaded guest screenshot should expose a safe link.");
        var loadedMemoryDump = loaded.Artifacts.Single(artifact => artifact.Kind == ArtifactKind.MemoryDump);
        SmokeAssert.True(loadedMemoryDump.CollectionName == "memory-dumps", "Loaded guest manifest should preserve memory-dump collection names.");
        SmokeAssert.True(loadedMemoryDump.CapturePhase == "after-start", "Loaded guest memory dump should preserve capture phase.");
        SmokeAssert.True(loadedMemoryDump.CaptureState == "captured", "Loaded guest memory dump should preserve capture state.");
        SmokeAssert.True(loadedMemoryDump.ImportPath == "memory-dumps/after-start-pid123.dmp", "Loaded guest memory dump should preserve safe import path.");
        SmokeAssert.True(loadedMemoryDump.SafeLink == "memory-dumps/after-start-pid123.dmp", "Loaded guest memory dump should expose a safe link.");
        var loadedPacketCapture = loaded.Artifacts.Single(artifact => artifact.Kind == ArtifactKind.PacketCapture);
        SmokeAssert.True(loadedPacketCapture.FullPath == packetCapturePath, "Loaded guest packet capture should resolve host path from import path.");
        SmokeAssert.True(loadedPacketCapture.Category == "packet-capture", "Loaded guest packet capture should fill packet-capture category.");
        SmokeAssert.True(loadedPacketCapture.MimeType == "application/vnd.tcpdump.pcap", "Loaded guest packet capture should fill pcap MIME type.");
        SmokeAssert.True(loadedPacketCapture.SizeBytes == 4, "Loaded guest packet capture should fill byte size.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(loadedPacketCapture.Sha256), "Loaded guest packet capture should fill SHA-256 when file is present.");
        SmokeAssert.True(loadedPacketCapture.Hashes.ContainsKey("sha256"), "Loaded guest packet capture should expose hashes map.");
        SmokeAssert.True(loadedPacketCapture.CollectionName == "packet-captures", "Loaded guest packet capture should fill collection name.");
        SmokeAssert.True(loadedPacketCapture.EvidenceRole == "packet-capture", "Loaded guest packet capture should fill evidence role.");
        SmokeAssert.True(loadedPacketCapture.CaptureState == "available", "Loaded guest packet capture should be available without starting host capture.");
        SmokeAssert.True(loadedPacketCapture.ImportPath == "packet-captures/external.pcap", "Loaded guest packet capture should preserve safe import path.");
        SmokeAssert.True(loadedPacketCapture.SafeLink == "packet-captures/external.pcap", "Loaded guest packet capture should expose a safe link.");
        SmokeAssert.True(loadedPacketCapture.Metadata.TryGetValue("captureSource", out var guestPcapSource) && guestPcapSource == "external", "Loaded guest packet capture should preserve external capture metadata.");
        SmokeAssert.True(loaded.Artifacts.Any(artifact => artifact.Name == "escape.bin" && string.IsNullOrWhiteSpace(artifact.SafeLink)), "Unsafe guest artifact paths should not become safe links.");
    }

    /// <summary>
    /// Verifies host artifact index scanning and persisted artifact-index.json.
    /// Inputs are smoke context and cancellation token; processing creates
    /// synthetic report/guest artifacts and indexes them; the method throws on
    /// contract mismatch.
    /// </summary>
    private static async Task AssertHostArtifactIndexAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var jobId = Guid.NewGuid();
        var jobRoot = Path.Combine(context.RuntimeRoot, "artifact-index", "jobs", jobId.ToString("N"));
        var guestRoot = Path.Combine(jobRoot, "guest", jobId.ToString("N"));
        var screenshotsRoot = Path.Combine(guestRoot, "screenshots");
        var memoryDumpsRoot = Path.Combine(guestRoot, "memory-dumps");
        var packetCapturesRoot = Path.Combine(guestRoot, "packet-captures");
        var artifactsRoot = Path.Combine(guestRoot, "artifacts");
        var droppedFilesRoot = Path.Combine(artifactsRoot, "dropped-files");
        var legacyDroppedFilesRoot = Path.Combine(guestRoot, "dropped-files");
        var legacyDumpsRoot = Path.Combine(guestRoot, "dumps");
        Directory.CreateDirectory(screenshotsRoot);
        Directory.CreateDirectory(memoryDumpsRoot);
        Directory.CreateDirectory(packetCapturesRoot);
        Directory.CreateDirectory(artifactsRoot);
        Directory.CreateDirectory(droppedFilesRoot);
        Directory.CreateDirectory(legacyDroppedFilesRoot);
        Directory.CreateDirectory(legacyDumpsRoot);

        await File.WriteAllTextAsync(Path.Combine(jobRoot, "report.json"), "{}", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(jobRoot, "report.html"), "<html></html>", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(jobRoot, "runbook.json"), "{}", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(jobRoot, "runbook-execution.json"), "{}", cancellationToken);
        await File.WriteAllTextAsync(
            Path.Combine(guestRoot, "events.json"),
            JsonSerializer.Serialize(new[]
            {
                new SandboxEvent
                {
                    EventType = "artifact.dropped_file.copied",
                    Source = "guest",
                    Path = Path.Combine(droppedFilesRoot, "drop.bin"),
                    Data =
                    {
                        ["collectionName"] = "dropped-files",
                        ["evidenceRole"] = "dropped-file",
                        ["relativePath"] = "artifacts/dropped-files/drop.bin",
                        ["artifactRelativePath"] = "artifacts/dropped-files/drop.bin",
                        ["guestFullPath"] = @"C:\work\drop.bin",
                        ["guestRelativePath"] = "drop.bin",
                        ["sizeBytes"] = "4"
                    }
                },
                new SandboxEvent
                {
                    EventType = "screenshot.skipped",
                    Source = "guest",
                    Data =
                    {
                        ["collectionName"] = "screenshots",
                        ["evidenceRole"] = "screenshot",
                        ["reason"] = "desktopUnavailable",
                        ["diagnosticStage"] = "screen-device"
                    }
                },
                new SandboxEvent
                {
                    EventType = "memory_dump.captured",
                    Source = "guest",
                    Path = Path.Combine(memoryDumpsRoot, "after-start-pid123.dmp"),
                    ProcessName = "sample.exe",
                    ProcessId = 123,
                    ParentProcessId = 100,
                    Data =
                    {
                        ["collectionName"] = "memory-dumps",
                        ["evidenceRole"] = "memory-dump",
                        ["relativePath"] = "memory-dumps/after-start-pid123.dmp",
                        ["processId"] = "123",
                        ["rootProcessId"] = "123",
                        ["processRole"] = "root",
                        ["treeDepth"] = "0",
                        ["treeLineage"] = "123",
                        ["targetProcessName"] = "sample.exe",
                        ["targetProcessPath"] = @"C:\work\sample.exe",
                        ["snapshotKey"] = "123:sample.exe",
                        ["dumpType"] = "MiniDumpNormal"
                    }
                },
                new SandboxEvent
                {
                    EventType = "memory_dump.sweep",
                    Source = "guest",
                    ProcessId = 123,
                    Data =
                    {
                        ["collectionName"] = "memory-dumps",
                        ["evidenceRole"] = "memory-dump",
                        ["rootProcessId"] = "123",
                        ["visibleTargetCount"] = "2",
                        ["attemptedCount"] = "1",
                        ["capturedCount"] = "1",
                        ["skippedCount"] = "0",
                        ["alreadyCapturedCount"] = "1"
                    }
                },
                new SandboxEvent
                {
                    EventType = "packet_capture.failed",
                    Source = "guest",
                    Data =
                    {
                        ["collectionName"] = "packet-captures",
                        ["evidenceRole"] = "packet-capture",
                        ["reason"] = "pktmonStartFailed",
                        ["commandMessage"] = "pktmon unavailable"
                    }
                },
                new SandboxEvent
                {
                    EventType = "r0collector.exited",
                    Source = "guest",
                    Path = @"C:\KSwordSandbox\agent\KSword.Sandbox.R0Collector.exe",
                    Data =
                    {
                        ["driverEventsPath"] = Path.Combine(guestRoot, "driver-events.jsonl"),
                        ["driverEventsRelativePath"] = "driver-events.jsonl",
                        ["stdoutPath"] = Path.Combine(guestRoot, "r0collector.stdout.log"),
                        ["stdoutRelativePath"] = "r0collector.stdout.log",
                        ["stderrPath"] = Path.Combine(guestRoot, "r0collector.stderr.log"),
                        ["stderrRelativePath"] = "r0collector.stderr.log",
                        ["artifactRelativePath"] = "driver-events.jsonl",
                        ["diagnosticRelativePath"] = "r0collector.stdout.log"
                    }
                }
            }, ManifestJsonOptions),
            cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(guestRoot, "agent-summary.json"), "{}", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(guestRoot, "driver-events.jsonl"), "{}", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(guestRoot, "r0collector.stdout.log"), "collector out", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(guestRoot, "r0collector.stderr.log"), "collector err", cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(screenshotsRoot, "after-run.bmp"), [0x42, 0x4d, 0x00, 0x00], cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(guestRoot, "screen-capture.png"), [0x89, 0x50, 0x4e, 0x47], cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(memoryDumpsRoot, "after-start-pid123.dmp"), [0x4d, 0x44, 0x4d, 0x50], cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(guestRoot, "loose-pid999.dmp"), [0x4d, 0x44, 0x4d, 0x51], cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(packetCapturesRoot, "before-start.pcap"), [0xd4, 0xc3, 0xb2, 0xa1], cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(packetCapturesRoot, "future.pcapng"), [0x0a, 0x0d, 0x0d, 0x0a], cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(droppedFilesRoot, "drop.bin"), "drop", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(droppedFilesRoot, "drop-copy.bin"), "drop", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(legacyDroppedFilesRoot, "legacy-drop.bin"), "legacy-drop", cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(legacyDumpsRoot, "legacy-pid321.dmp"), [0x4d, 0x44, 0x4d, 0x50], cancellationToken);
        await File.WriteAllTextAsync(
            Path.Combine(artifactsRoot, "manifest.json"),
            JsonSerializer.Serialize(new ArtifactManifest
            {
                Producer = "KSword.Sandbox.Agent",
                Collections =
                [
                    new ArtifactCollectionDescriptor
                    {
                        Name = "dropped-files",
                        Kind = ArtifactKind.DroppedFile,
                        Category = "dropped-file",
                        EvidenceRole = "dropped-file",
                        RelativePath = "artifacts/dropped-files",
                        Enabled = true,
                        Implemented = true,
                        Status = "captured"
                    },
                    new ArtifactCollectionDescriptor
                    {
                        Name = "screenshots",
                        Kind = ArtifactKind.Screenshot,
                        Category = "screenshot",
                        EvidenceRole = "screenshot",
                        RelativePath = "screenshots",
                        Enabled = true,
                        Implemented = true,
                        Status = "skipped",
                        Reason = "desktopUnavailable"
                    },
                    new ArtifactCollectionDescriptor
                    {
                        Name = "memory-dumps",
                        Kind = ArtifactKind.MemoryDump,
                        Category = "memory-dump",
                        EvidenceRole = "memory-dump",
                        RelativePath = "memory-dumps",
                        Enabled = true,
                        Implemented = true,
                        Status = "captured"
                    },
                    new ArtifactCollectionDescriptor
                    {
                        Name = "packet-captures",
                        Kind = ArtifactKind.PacketCapture,
                        Category = "packet-capture",
                        EvidenceRole = "packet-capture",
                        RelativePath = "packet-captures",
                        Enabled = true,
                        Implemented = true,
                        Status = "failed",
                        Reason = "pktmonStartFailed"
                    }
                ],
                Artifacts =
                [
                    new ArtifactDescriptor
                    {
                        Kind = ArtifactKind.DroppedFile,
                        Category = "dropped-file",
                        Name = "drop.bin",
                        RelativePath = "artifacts/dropped-files/drop.bin",
                        GuestPath = @"C:\work\drop.bin",
                        ImportPath = "artifacts/dropped-files/drop.bin",
                        CollectionName = "dropped-files",
                        EvidenceRole = "dropped-file",
                        CaptureState = "captured",
                        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["guestRelativePath"] = "drop.bin"
                        }
                    },
                    new ArtifactDescriptor
                    {
                        Kind = ArtifactKind.MemoryDump,
                        Category = "memory-dump",
                        Name = "after-start-pid123.dmp",
                        RelativePath = "memory-dumps/after-start-pid123.dmp",
                        GuestPath = @"C:\work\sample.exe",
                        ImportPath = "memory-dumps/after-start-pid123.dmp",
                        CollectionName = "memory-dumps",
                        EvidenceRole = "memory-dump",
                        CapturePhase = "after-start",
                        CaptureState = "captured",
                        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["processId"] = "123",
                            ["processRole"] = "root",
                            ["treeLineage"] = "123"
                        }
                    },
                    new ArtifactDescriptor
                    {
                        Kind = ArtifactKind.DroppedFile,
                        Category = "dropped-file",
                        Name = "escape.bin",
                        RelativePath = "../escape.bin",
                        FullPath = @"C:\KSwordSandbox\escape.bin",
                        ImportPath = "../escape.bin",
                        CollectionName = "dropped-files",
                        EvidenceRole = "dropped-file"
                    },
                    new ArtifactDescriptor
                    {
                        Kind = ArtifactKind.PacketCapture,
                        Category = "packet-capture",
                        Name = "missing.pcapng",
                        RelativePath = "packet-captures/missing.pcapng",
                        ImportPath = "packet-captures/missing.pcapng",
                        CollectionName = "packet-captures",
                        EvidenceRole = "packet-capture"
                    }
                ]
            }, ManifestJsonOptions),
            cancellationToken);

        var builder = new HostArtifactIndexBuilder();
        var index = builder.Build(jobId, jobRoot);
        SmokeAssert.True(index.RootPathPolicy == "server-owned-not-exposed-in-web-api", "Host artifact index should advertise the root path exposure policy.");
        SmokeAssert.True(index.DownloadPolicy == "relative-index-selectors-only", "Host artifact index should advertise the guarded download-selector policy.");
        SmokeAssert.True(index.ArtifactCount == index.Artifacts.Count, "Host artifact index should expose an artifact count summary.");
        SmokeAssert.True(index.CollectionCount == index.Collections.Count, "Host artifact index should expose a collection count summary.");
        SmokeAssert.True(index.DownloadableArtifactCount == index.Artifacts.Count(artifact => artifact.Metadata.TryGetValue("isDownloadable", out var downloadable) && downloadable == "true"), "Host artifact index should expose a downloadable artifact count summary.");
        SmokeAssert.True(index.SensitiveArtifactCount >= 1, "Host artifact index should count sensitive downloadable evidence lanes.");
        SmokeAssert.True(index.RejectedArtifactCount == 2, "Host artifact index should count rejected guest manifest artifact descriptors.");
        AssertIndexedArtifact(index, ArtifactKind.ReportJson, "report.json");
        AssertIndexedArtifact(index, ArtifactKind.ReportHtml, "report.html");
        AssertIndexedArtifact(index, ArtifactKind.RunbookJson, "runbook.json");
        AssertIndexedArtifact(index, ArtifactKind.RunbookExecutionJson, "runbook-execution.json");
        AssertIndexedArtifact(index, ArtifactKind.GuestEventsJson, $"guest/{jobId:N}/events.json");
        AssertIndexedArtifact(index, ArtifactKind.GuestSummaryJson, $"guest/{jobId:N}/agent-summary.json");
        var driverEvents = AssertIndexedArtifact(index, ArtifactKind.DriverEventsJsonLines, $"guest/{jobId:N}/driver-events.jsonl");
        SmokeAssert.True(driverEvents.CollectionName == "driver-events", "Driver JSONL index entry should include driver-events collection name.");
        SmokeAssert.True(driverEvents.EvidenceRole == "driver-events", "Driver JSONL index entry should include evidence role.");
        SmokeAssert.True(driverEvents.Metadata.TryGetValue("telemetryFormat", out var telemetryFormat) && telemetryFormat == "jsonl", "Driver JSONL index entry should include stable telemetry format metadata.");
        SmokeAssert.True(driverEvents.Metadata.TryGetValue("driverEventsRelativePath", out var driverEventsRelativePath) && driverEventsRelativePath == "driver-events.jsonl", "Driver JSONL index entry should preserve event-provided relative artifact reference.");
        var r0Log = AssertIndexedArtifact(index, ArtifactKind.Log, $"guest/{jobId:N}/r0collector.stdout.log");
        SmokeAssert.True(r0Log.CollectionName == "r0-logs", "R0 stdout log should be indexed into the r0-logs collection.");
        SmokeAssert.True(r0Log.EvidenceRole == "diagnostic-log", "R0 stdout log should include diagnostic-log evidence role.");
        var screenshot = AssertIndexedArtifact(index, ArtifactKind.Screenshot, $"guest/{jobId:N}/screenshots/after-run.bmp");
        SmokeAssert.True(screenshot.CapturePhase == "after-run", "Screenshot index entry should include capture phase.");
        SmokeAssert.True(screenshot.CollectionName == "screenshots", "Screenshot index entry should include collection name.");
        SmokeAssert.True(screenshot.CaptureState == "captured", "Screenshot index entry should mark existing screenshots as captured.");
        var looseScreenshot = AssertIndexedArtifact(index, ArtifactKind.Screenshot, $"guest/{jobId:N}/screen-capture.png");
        SmokeAssert.True(looseScreenshot.CollectionName == "screenshots", "Host index should classify screenshot-named image artifacts outside the canonical screenshots folder.");
        var memoryDump = AssertIndexedArtifact(index, ArtifactKind.MemoryDump, $"guest/{jobId:N}/memory-dumps/after-start-pid123.dmp");
        SmokeAssert.True(memoryDump.Category == "memory-dump", "Memory dump index entry should include memory-dump category.");
        SmokeAssert.True(memoryDump.MimeType == "application/vnd.microsoft.minidump", "Memory dump index entry should include minidump MIME type.");
        SmokeAssert.True(memoryDump.Metadata.TryGetValue("evidenceRole", out var dumpEvidenceRole) && dumpEvidenceRole == "memory-dump", "Memory dump index entry should include evidence role.");
        SmokeAssert.True(memoryDump.CollectionName == "memory-dumps", "Memory dump index entry should include collection name.");
        SmokeAssert.True(memoryDump.Metadata.TryGetValue("processId", out var dumpProcessId) && dumpProcessId == "123", "Memory dump index entry should preserve process identity metadata from guest events/manifests.");
        SmokeAssert.True(memoryDump.Metadata.TryGetValue("processRole", out var dumpProcessRole) && dumpProcessRole == "root", "Memory dump index entry should preserve root/child process role metadata.");
        SmokeAssert.True(memoryDump.Metadata.TryGetValue("treeLineage", out var dumpLineage) && dumpLineage == "123", "Memory dump index entry should preserve child-process sweep lineage metadata.");
        var looseMemoryDump = AssertIndexedArtifact(index, ArtifactKind.MemoryDump, $"guest/{jobId:N}/loose-pid999.dmp");
        SmokeAssert.True(looseMemoryDump.CollectionName == "memory-dumps", "Host index should classify loose .dmp files as memory-dump artifacts.");
        var packetCapture = AssertIndexedArtifact(index, ArtifactKind.PacketCapture, $"guest/{jobId:N}/packet-captures/before-start.pcap");
        SmokeAssert.True(packetCapture.Category == "packet-capture", "Packet capture index entry should include packet-capture category.");
        SmokeAssert.True(packetCapture.CapturePhase == "before-start", "Packet capture index entry should include capture phase when encoded in the file name.");
        SmokeAssert.True(packetCapture.CaptureState == "available", "Packet capture index entry should mark an existing external PCAP as available.");
        SmokeAssert.True(packetCapture.MimeType == "application/vnd.tcpdump.pcap", "Packet capture index entry should include pcap MIME type.");
        SmokeAssert.True(packetCapture.SizeBytes == 4, "Packet capture index entry should include byte size.");
        SmokeAssert.True(packetCapture.Hashes.ContainsKey("sha256"), "Packet capture index entry should include hashes map.");
        SmokeAssert.True(packetCapture.CollectionName == "packet-captures", "Packet capture index entry should include collection name.");
        SmokeAssert.True(packetCapture.Metadata.TryGetValue("captureSource", out var pcapSource) && pcapSource == "external", "Packet capture index entry should mark external capture source.");
        SmokeAssert.True(packetCapture.Metadata.TryGetValue("hostCaptureStarted", out var hostCaptureStarted) && hostCaptureStarted == "false", "Packet capture index entry should not imply host packet capture was started.");
        var packetCaptureNg = AssertIndexedArtifact(index, ArtifactKind.PacketCapture, $"guest/{jobId:N}/packet-captures/future.pcapng");
        SmokeAssert.True(packetCaptureNg.MimeType == "application/x-pcapng", "Packet capture index entry should include pcapng MIME type.");
        SmokeAssert.True(packetCaptureNg.Metadata.TryGetValue("pcapFormat", out var pcapNgFormat) && pcapNgFormat == "pcapng", "Packet capture index entry should record pcapng format metadata.");
        var packetCaptureCollection = index.Collections.Single(collection => collection.Name == "packet-captures");
        SmokeAssert.True(packetCaptureCollection.Kind == ArtifactKind.PacketCapture, "Packet capture collection should be present in host index.");
        SmokeAssert.True(packetCaptureCollection.RelativePath == $"guest/{jobId:N}/packet-captures", "Packet capture collection should expose safe import path.");
        SmokeAssert.True(packetCaptureCollection.SafeLink == $"guest/{jobId:N}/packet-captures", "Packet capture collection should expose safe link.");
        SmokeAssert.True(packetCaptureCollection.Status == "captured", "Packet capture collection should indicate indexed files are present.");
        SmokeAssert.True(packetCaptureCollection.Implemented, "Packet capture collection should indicate host can consume existing files.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("artifactCount", out var pcapCount) && pcapCount == "2", "Packet capture collection should record artifact count.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("totalBytes", out var pcapBytes) && pcapBytes == "8", "Packet capture collection should record total bytes.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("mimeTypes", out var pcapMimeTypes) && pcapMimeTypes.Contains("application/vnd.tcpdump.pcap", StringComparison.Ordinal) && pcapMimeTypes.Contains("application/x-pcapng", StringComparison.Ordinal), "Packet capture collection should record MIME types.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("importMode", out var pcapImportMode) && pcapImportMode == "external-artifact", "Packet capture collection should mark external artifact import mode.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("guestManifestStatus", out var pcapGuestStatus) && pcapGuestStatus == "failed", "Packet capture collection should retain guest collection status even when files were later indexed.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("lastReason", out var pcapFailureReason) && pcapFailureReason == "pktmonStartFailed", "Packet capture collection should retain concrete failure reason from guest events.");
        var dropped = AssertIndexedArtifact(index, ArtifactKind.DroppedFile, $"guest/{jobId:N}/artifacts/dropped-files/drop.bin");
        SmokeAssert.True(dropped.SizeBytes == 4, "Dropped-file index entry should include size.");
        SmokeAssert.True(dropped.MimeType == "application/octet-stream", "Dropped-file index entry should include MIME type.");
        SmokeAssert.True(dropped.Category == "dropped-file", "Dropped-file index entry should include category.");
        SmokeAssert.True(dropped.SafeLink == $"guest/{jobId:N}/artifacts/dropped-files/drop.bin", "Dropped-file index entry should include safe relative link.");
        SmokeAssert.True(dropped.Hashes.ContainsKey("sha256"), "Dropped-file index entry should include hashes map.");
        SmokeAssert.True(dropped.GuestPath == @"C:\work\drop.bin", "Dropped-file index entry should preserve original guest path.");
        SmokeAssert.True(dropped.Metadata.TryGetValue("previewLabel", out var droppedPreview) && droppedPreview.Contains("Dropped file", StringComparison.Ordinal), "Dropped-file index entry should include an English preview label.");
        SmokeAssert.True(dropped.Metadata.TryGetValue("previewLabelZh", out var droppedPreviewZh) && droppedPreviewZh.Contains("掉落文件", StringComparison.Ordinal), "Dropped-file index entry should include a Chinese preview label.");
        SmokeAssert.True(dropped.Metadata.TryGetValue("contentType", out var droppedContentType) && droppedContentType == "application/octet-stream", "Dropped-file index entry should include content type metadata.");
        SmokeAssert.True(dropped.Metadata.TryGetValue("downloadSelector", out var droppedDownloadSelector) && droppedDownloadSelector == dropped.RelativePath, "Dropped-file index entry should include a safe download selector.");
        SmokeAssert.True(dropped.Metadata.TryGetValue("downloadResolutionState", out var downloadResolutionState) && downloadResolutionState == "available", "Dropped-file index entry should include report-ready download resolution state.");
        SmokeAssert.True(dropped.Metadata.TryGetValue("selectorSafety", out var selectorSafety) && selectorSafety == "normalized-relative-indexed", "Dropped-file index entry should describe selector safety.");
        SmokeAssert.True(dropped.Metadata.TryGetValue("sha256Short", out var droppedShaShort) && droppedShaShort.Length == 12, "Dropped-file index entry should include a short SHA-256 preview.");
        var droppedCopy = AssertIndexedArtifact(index, ArtifactKind.DroppedFile, $"guest/{jobId:N}/artifacts/dropped-files/drop-copy.bin");
        SmokeAssert.True(dropped.Metadata.TryGetValue("duplicateGroupCount", out var duplicateGroupCount) && duplicateGroupCount == "2", "Duplicate dropped files should be grouped by hash and size.");
        var duplicatePair = new[] { dropped, droppedCopy };
        SmokeAssert.True(duplicatePair.Count(artifact => artifact.Metadata.TryGetValue("duplicateRole", out var role) && role == "primary") == 1, "Duplicate group should have exactly one primary member.");
        SmokeAssert.True(duplicatePair.Count(artifact => artifact.Metadata.TryGetValue("isDuplicate", out var duplicate) && duplicate == "true") == 1, "Duplicate group should have exactly one duplicate member.");
        var primaryDuplicate = duplicatePair.Single(artifact => artifact.Metadata.TryGetValue("duplicateRole", out var role) && role == "primary");
        var secondaryDuplicate = duplicatePair.Single(artifact => artifact.Metadata.TryGetValue("isDuplicate", out var duplicate) && duplicate == "true");
        SmokeAssert.True(secondaryDuplicate.Metadata.TryGetValue("duplicatePrimarySelector", out var duplicatePrimarySelector) && duplicatePrimarySelector == primaryDuplicate.RelativePath, "Duplicate entries should point at the stable primary selector.");
        var legacyDropped = AssertIndexedArtifact(index, ArtifactKind.DroppedFile, $"guest/{jobId:N}/dropped-files/legacy-drop.bin");
        SmokeAssert.True(legacyDropped.CollectionName == "dropped-files", "Host index should cover legacy dropped-files directories outside artifacts/.");
        var legacyDump = AssertIndexedArtifact(index, ArtifactKind.MemoryDump, $"guest/{jobId:N}/dumps/legacy-pid321.dmp");
        SmokeAssert.True(legacyDump.CollectionName == "memory-dumps", "Host index should cover legacy dumps directories as memory dumps.");
        SmokeAssert.True(index.Artifacts.All(artifact => !artifact.RelativePath.Contains("escape.bin", StringComparison.OrdinalIgnoreCase)), "Unsafe guest manifest descriptors should not become downloadable host index entries.");
        var memoryDumpCollection = index.Collections.Single(collection => collection.Name == "memory-dumps");
        SmokeAssert.True(memoryDumpCollection.Metadata.TryGetValue("sweepVisibleTargetCount", out var visibleTargetCount) && visibleTargetCount == "2", "Memory dump collection should retain child-process sweep visible target count.");
        SmokeAssert.True(memoryDumpCollection.Metadata.TryGetValue("sweepAlreadyCapturedCount", out var duplicateDumpCount) && duplicateDumpCount == "1", "Memory dump collection should retain duplicate root/child dump suppression count.");
        var screenshotCollection = index.Collections.Single(collection => collection.Name == "screenshots");
        SmokeAssert.True(screenshotCollection.Metadata.TryGetValue("skippedEventCount", out var screenshotSkippedCount) && screenshotSkippedCount == "1", "Screenshot collection should retain skipped capture event count.");
        SmokeAssert.True(screenshotCollection.Metadata.TryGetValue("lastReason", out var screenshotReason) && screenshotReason == "desktopUnavailable", "Screenshot collection should retain concrete skipped reason.");
        var droppedCollection = index.Collections.Single(collection => collection.Name == "dropped-files");
        SmokeAssert.True(droppedCollection.Metadata.TryGetValue("rejectionDiagnosticsAvailable", out var droppedRejectionAvailable) && droppedRejectionAvailable == "true", "Dropped-files collection should expose manifest rejection diagnostics.");
        SmokeAssert.True(droppedCollection.Metadata.TryGetValue("rejectedArtifactCount", out var droppedRejectedCount) && droppedRejectedCount == "1", "Dropped-files collection should count unsafe guest manifest descriptors.");
        SmokeAssert.True(droppedCollection.Metadata.TryGetValue("lastRejectedArtifactReason", out var droppedRejectedReason) && droppedRejectedReason == "unsafeGuestArtifactPath", "Dropped-files collection should preserve unsafe path rejection reason.");
        SmokeAssert.True(droppedCollection.Metadata.TryGetValue("duplicateDiagnosticsAvailable", out var duplicateDiagnosticsAvailable) && duplicateDiagnosticsAvailable == "true", "Dropped-files collection should expose structured duplicate diagnostics.");
        SmokeAssert.True(droppedCollection.Metadata.TryGetValue("duplicateGroupCount", out var duplicateCollectionGroupCount) && duplicateCollectionGroupCount == "1", "Dropped-files collection should count duplicate groups.");
        SmokeAssert.True(droppedCollection.Metadata.TryGetValue("duplicateGroupSummariesJson", out var duplicateSummariesJson) && duplicateSummariesJson.Contains("drop-copy.bin", StringComparison.Ordinal), "Dropped-files collection should include duplicate group member selectors.");
        SmokeAssert.True(droppedCollection.Metadata.TryGetValue("artifactRejectionsJson", out var droppedRejectionsJson) && droppedRejectionsJson.Contains("unsafeGuestArtifactPath", StringComparison.Ordinal), "Dropped-files collection should include machine-readable rejection details.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("rejectionDiagnosticsAvailable", out var pcapRejectionAvailable) && pcapRejectionAvailable == "true", "Packet-captures collection should expose missing manifest artifact diagnostics.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("lastRejectedArtifactReason", out var pcapRejectedReason) && pcapRejectedReason == "missingGuestArtifactFile", "Packet-captures collection should preserve missing file rejection reason.");
        SmokeAssert.True(packetCaptureCollection.Metadata.TryGetValue("artifactRejectionsJson", out var pcapRejectionsJson) && pcapRejectionsJson.Contains("missing.pcapng", StringComparison.Ordinal), "Packet-captures collection should include missing artifact rejection details.");

        var indexDescriptor = builder.WriteIndex(jobId, jobRoot);
        SmokeAssert.True(indexDescriptor.Kind == ArtifactKind.ArtifactIndex, "Index descriptor should use ArtifactIndex kind.");
        SmokeAssert.True(File.Exists(indexDescriptor.FullPath), "artifact-index.json should be written.");
        AssertHostArtifactIndexJsonShape(indexDescriptor.FullPath);
        var loaded = builder.TryReadIndex(jobRoot) ?? throw new InvalidOperationException("artifact-index.json should load.");
        SmokeAssert.True(loaded.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.DriverEventsJsonLines), "Loaded index should include driver JSONL.");
        SmokeAssert.True(loaded.Collections.Any(collection => collection.Name == "packet-captures" && collection.Metadata.ContainsKey("artifactCount")), "Loaded index should preserve packet-capture collection metadata.");
    }

    /// <summary>
    /// Verifies the selectors consumed by the WebUI download endpoint through
    /// SandboxJobService.ResolveDownloadableArtifact.
    /// </summary>
    private static async Task AssertArtifactDownloadSelectorsAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "artifact-download-selectors", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var samplePath = Path.Combine(runtimeRoot, "selector-sample.exe");
        await File.WriteAllTextAsync(samplePath, "selector sample", cancellationToken);

        var service = new SandboxJobService(
            new SandboxConfig
            {
                Analysis = new AnalysisConfig
                {
                    DefaultDurationSeconds = 5,
                    MaxDurationSeconds = 60,
                    MaxSampleBytes = 1024 * 1024
                },
                Paths = new SandboxPaths
                {
                    RuntimeRoot = runtimeRoot,
                    RulesDirectory = context.RulesDirectory,
                    GuestPayloadRoot = Path.Combine(runtimeRoot, "payload")
                }
            },
            RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json")));

        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = true
        });
        var jobRoot = Path.GetDirectoryName(job.JsonReportPath) ?? throw new InvalidOperationException("job root should be discoverable");
        var guestRoot = Path.Combine(jobRoot, "guest", job.JobId.ToString("N"));
        var droppedFilesRoot = Path.Combine(guestRoot, "artifacts", "dropped-files");
        Directory.CreateDirectory(droppedFilesRoot);
        var droppedFileName = "drop space # 零.bin";
        var droppedPath = Path.Combine(droppedFilesRoot, droppedFileName);
        await File.WriteAllTextAsync(droppedPath, "drop", cancellationToken);
        await File.WriteAllTextAsync(
            Path.Combine(guestRoot, "events.json"),
            JsonSerializer.Serialize(new[]
            {
                new SandboxEvent
                {
                    EventType = "artifact.dropped_file.copied",
                    Source = "guest",
                    Path = droppedPath,
                    Data =
                    {
                        ["collectionName"] = "dropped-files",
                        ["evidenceRole"] = "dropped-file",
                        ["relativePath"] = $"artifacts/dropped-files/{droppedFileName}",
                        ["artifactRelativePath"] = $"artifacts/dropped-files/{droppedFileName}",
                        ["guestFullPath"] = $@"C:\work\{droppedFileName}"
                    }
                }
            }, ManifestJsonOptions),
            cancellationToken);

        var index = service.BuildArtifactIndex(job.JobId);
        var descriptor = index.Artifacts.Single(artifact =>
            artifact.Kind == ArtifactKind.DroppedFile &&
            string.Equals(artifact.Name, droppedFileName, StringComparison.Ordinal));
        AssertDownloadSelectorShape(descriptor);
        SmokeAssert.True(descriptor.RelativePath == $"guest/{job.JobId:N}/artifacts/dropped-files/{droppedFileName}", "Download selector test should use host-relative artifact path.");
        SmokeAssert.True(!descriptor.SafeLink.Contains(" ", StringComparison.Ordinal) && !descriptor.SafeLink.Contains("#", StringComparison.Ordinal), "SafeLink should URL-encode spaces and fragment characters.");
        SmokeAssert.True(descriptor.SafeLink.Contains("%20", StringComparison.Ordinal) && descriptor.SafeLink.Contains("%23", StringComparison.Ordinal), "SafeLink should contain encoded path characters.");

        var relativeResolved = service.ResolveDownloadableArtifact(job.JobId, descriptor.RelativePath);
        SmokeAssert.True(string.Equals(relativeResolved.FullPath, droppedPath, StringComparison.OrdinalIgnoreCase), "Download resolver should accept RelativePath selectors.");
        var safeLinkResolved = service.ResolveDownloadableArtifact(job.JobId, descriptor.SafeLink);
        SmokeAssert.True(string.Equals(safeLinkResolved.FullPath, droppedPath, StringComparison.OrdinalIgnoreCase), "Download resolver should accept SafeLink selectors.");
        var importPathResolved = service.ResolveDownloadableArtifact(job.JobId, descriptor.ImportPath);
        SmokeAssert.True(string.Equals(importPathResolved.FullPath, droppedPath, StringComparison.OrdinalIgnoreCase), "Download resolver should accept ImportPath selectors.");

        var downloadHref = $"/api/jobs/{job.JobId:D}/artifacts/download?path={Uri.EscapeDataString(descriptor.RelativePath)}";
        SmokeAssert.True(downloadHref.Contains("/artifacts/download?path=", StringComparison.Ordinal), "WebUI download href should use the guarded artifact download endpoint.");
        SmokeAssert.True(!downloadHref.Contains(droppedPath, StringComparison.OrdinalIgnoreCase), "WebUI download href should not embed absolute host paths.");

        AssertThrows<ArgumentException>(() => service.ResolveDownloadableArtifact(job.JobId, @"C:\Windows\win.ini"), "Absolute download selectors should be rejected.");
        AssertThrows<ArgumentException>(() => service.ResolveDownloadableArtifact(job.JobId, "../escape.bin"), "Traversal download selectors should be rejected.");
        AssertThrows<ArgumentException>(() => service.ResolveDownloadableArtifact(job.JobId, Uri.EscapeDataString(@"C:\Windows\win.ini")), "URL-encoded absolute download selectors should be rejected.");
        AssertThrows<ArgumentException>(() => service.ResolveDownloadableArtifact(job.JobId, "%2e%2e%2fescape.bin"), "URL-encoded traversal download selectors should be rejected.");
        AssertThrows<FileNotFoundException>(() => service.ResolveDownloadableArtifact(job.JobId, $"guest/{job.JobId:N}/artifacts/dropped-files/missing.bin"), "Unknown relative download selectors should be rejected.");
    }

    /// <summary>
    /// Verifies report artifact links in renderer output and ReportArtifactStage.
    /// Inputs are smoke context and cancellation token; processing creates a
    /// synthetic report with guest artifacts and renders/writes it; the method
    /// throws on missing links.
    /// </summary>
    private static async Task AssertReportArtifactLinksAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var jobId = Guid.NewGuid();
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "report-artifact-stage");
        var jobRoot = Path.Combine(runtimeRoot, "jobs", jobId.ToString("N"));
        var guestRoot = Path.Combine(jobRoot, "guest", jobId.ToString("N"));
        var screenshotsRoot = Path.Combine(guestRoot, "screenshots");
        var memoryDumpsRoot = Path.Combine(guestRoot, "memory-dumps");
        var packetCapturesRoot = Path.Combine(guestRoot, "packet-captures");
        var artifactsRoot = Path.Combine(guestRoot, "artifacts");
        var droppedFilesRoot = Path.Combine(artifactsRoot, "dropped-files");
        Directory.CreateDirectory(screenshotsRoot);
        Directory.CreateDirectory(memoryDumpsRoot);
        Directory.CreateDirectory(packetCapturesRoot);
        Directory.CreateDirectory(artifactsRoot);
        Directory.CreateDirectory(droppedFilesRoot);

        var eventsPath = Path.Combine(guestRoot, "events.json");
        var driverPath = Path.Combine(guestRoot, "driver-events.jsonl");
        var screenshotPath = Path.Combine(screenshotsRoot, "after-run.bmp");
        var memoryDumpPath = Path.Combine(memoryDumpsRoot, "after-start-pid123.dmp");
        var packetCapturePath = Path.Combine(packetCapturesRoot, "future.pcapng");
        var dropPath = Path.Combine(droppedFilesRoot, "drop.bin");
        var manifestPath = Path.Combine(artifactsRoot, "manifest.json");
        await File.WriteAllTextAsync(eventsPath, "[]", cancellationToken);
        await File.WriteAllTextAsync(driverPath, "{}", cancellationToken);
        await File.WriteAllBytesAsync(screenshotPath, [0x42, 0x4d, 0x00, 0x00], cancellationToken);
        await File.WriteAllBytesAsync(memoryDumpPath, [0x4d, 0x44, 0x4d, 0x50], cancellationToken);
        await File.WriteAllBytesAsync(packetCapturePath, [0x0a, 0x0d, 0x0d, 0x0a], cancellationToken);
        await File.WriteAllTextAsync(dropPath, "drop", cancellationToken);
        await File.WriteAllTextAsync(
            manifestPath,
            JsonSerializer.Serialize(new ArtifactManifest
            {
                RuntimeRoot = @"C:\KSwordSandbox\out",
                RootPath = @"C:\KSwordSandbox\out\artifacts",
                Producer = "KSword.Sandbox.Agent",
                Artifacts =
                [
                    new ArtifactDescriptor
                    {
                        Kind = ArtifactKind.DroppedFile,
                        Name = "drop.bin",
                        Category = "dropped-file",
                        RelativePath = "artifacts/dropped-files/drop.bin",
                        FullPath = @"C:\KSwordSandbox\out\artifacts\dropped-files\drop.bin",
                        SafeLink = "artifacts/dropped-files/drop.bin",
                        EvidenceRole = "dropped-file",
                        ImportPath = "artifacts/dropped-files/drop.bin",
                        CollectionName = "dropped-files",
                        MimeType = "application/octet-stream",
                        SizeBytes = 4,
                        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["evidenceRole"] = "dropped-file"
                        }
                    }
                ]
            }, ManifestJsonOptions),
            cancellationToken);

        var report = CreateReport(jobId, eventsPath, screenshotPath, dropPath, memoryDumpPath, packetCapturePath);
        var index = new HostArtifactIndexBuilder().Build(jobId, jobRoot);
        var renderer = new HtmlReportRenderer();
        var html = renderer.RenderEnglish(report, index.Artifacts);
        AssertReportHtmlContainsArtifactLinks(html, jobId);
        var zhHtml = renderer.RenderChinese(report, index.Artifacts);
        SmokeAssert.True(zhHtml.Contains("证据文件链接", StringComparison.Ordinal), "Chinese HTML report should include localized artifact links section.");

        var stage = new ReportArtifactStage();
        await stage.ExecuteAsync(new AnalysisPipelineContext
        {
            JobId = jobId,
            Config = new SandboxConfig
            {
                Paths = new SandboxPaths
                {
                    RuntimeRoot = runtimeRoot,
                    RulesDirectory = context.RepositoryRoot,
                    GuestPayloadRoot = Path.Combine(runtimeRoot, "payload")
                }
            },
            Submission = new SandboxSubmission
            {
                SamplePath = report.Sample.FullPath,
                DryRun = true
            },
            Sample = report.Sample,
            Report = report
        }, cancellationToken);

        var writtenHtml = await File.ReadAllTextAsync(Path.Combine(jobRoot, "report.html"), cancellationToken);
        AssertReportHtmlContainsArtifactLinks(writtenHtml, jobId);
        SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "artifact-index.json")), "ReportArtifactStage should write artifact-index.json.");
    }

    private static ArtifactDescriptor AssertIndexedArtifact(HostArtifactIndex index, ArtifactKind kind, string relativePath)
    {
        var artifact = index.Artifacts.FirstOrDefault(item =>
            item.Kind == kind &&
            string.Equals(item.RelativePath, relativePath, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(artifact is not null, $"{kind} artifact should be indexed at {relativePath}.");
        AssertDownloadSelectorShape(artifact!);
        return artifact!;
    }

    private static void AssertDownloadSelectorShape(ArtifactDescriptor artifact)
    {
        AssertSafeSelectorField(artifact, "relativePath", artifact.RelativePath);
        AssertSafeSelectorField(artifact, "safeLink", artifact.SafeLink);
        AssertSafeSelectorField(artifact, "importPath", artifact.ImportPath);
        SmokeAssert.True(!string.IsNullOrWhiteSpace(artifact.FullPath), $"{artifact.Kind} artifact should retain a host-local full path for guarded streaming.");
    }

    private static void AssertSafeSelectorField(ArtifactDescriptor artifact, string fieldName, string value)
    {
        AssertSafeSelectorValue($"{artifact.Kind} {fieldName}", value);
    }

    private static void AssertSafeSelectorValue(string subject, string value)
    {
        SmokeAssert.True(!string.IsNullOrWhiteSpace(value), $"{subject} should not be empty.");
        SmokeAssert.True(!value.Contains('\\', StringComparison.Ordinal), $"{subject} should use slash-separated paths.");
        SmokeAssert.True(!value.StartsWith("/", StringComparison.Ordinal), $"{subject} should not be absolute.");
        SmokeAssert.True(!Path.IsPathFullyQualified(Uri.UnescapeDataString(value)), $"{subject} should not be a fully-qualified filesystem path.");
        SmokeAssert.True(!value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(segment => string.Equals(segment, "..", StringComparison.Ordinal)), $"{subject} should not contain parent traversal.");
    }

    private static void AssertArtifactManifestJsonShape(string manifestPath, string label)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var root = RequireObject(document.RootElement, label);
        RequireInt(root, "schemaVersion", label, value => value >= 1);
        RequireGuid(root, "jobId", label);
        RequireString(root, "producer", label);
        RequireString(root, "generatedAtUtc", label);
        RequireArray(root, "collections", label, collection => AssertCollectionJsonShape(collection, label));
        RequireArray(root, "artifacts", label, artifact => AssertArtifactDescriptorJsonShape(artifact, label, safeSelectorsRequired: false));
    }

    private static void AssertHostArtifactIndexJsonShape(string indexPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(indexPath));
        var label = "host artifact index";
        var root = RequireObject(document.RootElement, label);
        RequireInt(root, "schemaVersion", label, value => value >= 1);
        RequireGuid(root, "jobId", label);
        RequireString(root, "rootPath", label);
        RequireString(root, "producer", label);
        RequireString(root, "rootPathPolicy", label);
        RequireString(root, "downloadPolicy", label);
        RequireInt(root, "collectionCount", label, value => value >= 0);
        RequireInt(root, "artifactCount", label, value => value >= 0);
        RequireInt(root, "downloadableArtifactCount", label, value => value >= 0);
        RequireInt(root, "sensitiveArtifactCount", label, value => value >= 0);
        RequireInt(root, "duplicateArtifactCount", label, value => value >= 0);
        RequireInt(root, "rejectedArtifactCount", label, value => value >= 0);
        RequireString(root, "generatedAtUtc", label);
        RequireArray(root, "collections", label, collection => AssertCollectionJsonShape(collection, label));
        RequireArray(root, "artifacts", label, artifact => AssertArtifactDescriptorJsonShape(artifact, label, safeSelectorsRequired: true));
    }

    private static void AssertCollectionJsonShape(JsonElement element, string label)
    {
        var collection = RequireObject(element, $"{label} collection");
        RequireString(collection, "name", label);
        RequireString(collection, "kind", label);
        RequireString(collection, "category", label, allowEmpty: true);
        RequireString(collection, "evidenceRole", label, allowEmpty: true);
        RequireString(collection, "relativePath", label, allowEmpty: true);
        RequireBoolean(collection, "enabled", label);
        RequireBoolean(collection, "implemented", label);
        RequireString(collection, "status", label, allowEmpty: true);
        RequireObjectProperty(collection, "metadata", label);

        if (TryGetString(collection, "safeLink", out var safeLink) && !string.IsNullOrWhiteSpace(safeLink))
        {
            AssertSafeSelectorValue($"{label} collection safeLink", safeLink);
        }

        if (TryGetString(collection, "importPath", out var importPath) && !string.IsNullOrWhiteSpace(importPath))
        {
            AssertSafeSelectorValue($"{label} collection importPath", importPath);
        }
    }

    private static void AssertArtifactDescriptorJsonShape(JsonElement element, string label, bool safeSelectorsRequired)
    {
        var artifact = RequireObject(element, $"{label} artifact");
        RequireString(artifact, "kind", label);
        RequireString(artifact, "name", label, allowEmpty: true);
        RequireString(artifact, "category", label, allowEmpty: true);
        RequireString(artifact, "relativePath", label, allowEmpty: !safeSelectorsRequired);
        RequireString(artifact, "fullPath", label, allowEmpty: true);
        RequireString(artifact, "mimeType", label, allowEmpty: true);
        RequireInt64(artifact, "sizeBytes", label, value => value >= 0);
        RequireObjectProperty(artifact, "hashes", label);
        RequireObjectProperty(artifact, "metadata", label);

        if (TryGetString(artifact, "relativePath", out var relativePath) && !string.IsNullOrWhiteSpace(relativePath))
        {
            if (safeSelectorsRequired)
            {
                AssertSafeSelectorValue($"{label} artifact relativePath", relativePath);
            }
        }

        if (TryGetString(artifact, "safeLink", out var safeLink) && !string.IsNullOrWhiteSpace(safeLink))
        {
            AssertSafeSelectorValue($"{label} artifact safeLink", safeLink);
        }
        else
        {
            SmokeAssert.True(!safeSelectorsRequired, $"{label} artifact safeLink should not be empty.");
        }

        if (TryGetString(artifact, "importPath", out var importPath) && !string.IsNullOrWhiteSpace(importPath))
        {
            AssertSafeSelectorValue($"{label} artifact importPath", importPath);
        }
        else
        {
            SmokeAssert.True(!safeSelectorsRequired, $"{label} artifact importPath should not be empty.");
        }
    }

    private static JsonElement RequireObject(JsonElement element, string label)
    {
        SmokeAssert.True(element.ValueKind == JsonValueKind.Object, $"{label} should be a JSON object.");
        return element;
    }

    private static JsonElement RequireObjectProperty(JsonElement root, string propertyName, string label)
    {
        SmokeAssert.True(root.TryGetProperty(propertyName, out var property), $"{label} should include '{propertyName}'.");
        SmokeAssert.True(property.ValueKind == JsonValueKind.Object, $"{label}.{propertyName} should be a JSON object.");
        return property;
    }

    private static void RequireString(JsonElement root, string propertyName, string label, bool allowEmpty = false)
    {
        SmokeAssert.True(root.TryGetProperty(propertyName, out var property), $"{label} should include '{propertyName}'.");
        SmokeAssert.True(property.ValueKind == JsonValueKind.String, $"{label}.{propertyName} should be a JSON string.");
        SmokeAssert.True(allowEmpty || !string.IsNullOrWhiteSpace(property.GetString()), $"{label}.{propertyName} should not be empty.");
    }

    private static void RequireBoolean(JsonElement root, string propertyName, string label)
    {
        SmokeAssert.True(root.TryGetProperty(propertyName, out var property), $"{label} should include '{propertyName}'.");
        SmokeAssert.True(property.ValueKind is JsonValueKind.True or JsonValueKind.False, $"{label}.{propertyName} should be a JSON boolean.");
    }

    private static void RequireGuid(JsonElement root, string propertyName, string label)
    {
        RequireString(root, propertyName, label);
        SmokeAssert.True(Guid.TryParse(root.GetProperty(propertyName).GetString(), out _), $"{label}.{propertyName} should be a GUID string.");
    }

    private static void RequireInt(JsonElement root, string propertyName, string label, Func<int, bool> predicate)
    {
        SmokeAssert.True(root.TryGetProperty(propertyName, out var property), $"{label} should include '{propertyName}'.");
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt32(out var value))
        {
            SmokeAssert.True(false, $"{label}.{propertyName} should be a JSON integer.");
            return;
        }

        SmokeAssert.True(predicate(value), $"{label}.{propertyName} should satisfy its contract.");
    }

    private static void RequireInt64(JsonElement root, string propertyName, string label, Func<long, bool> predicate)
    {
        SmokeAssert.True(root.TryGetProperty(propertyName, out var property), $"{label} should include '{propertyName}'.");
        if (property.ValueKind != JsonValueKind.Number || !property.TryGetInt64(out var value))
        {
            SmokeAssert.True(false, $"{label}.{propertyName} should be a JSON integer.");
            return;
        }

        SmokeAssert.True(predicate(value), $"{label}.{propertyName} should satisfy its contract.");
    }

    private static void RequireArray(JsonElement root, string propertyName, string label, Action<JsonElement> assertElement)
    {
        SmokeAssert.True(root.TryGetProperty(propertyName, out var property), $"{label} should include '{propertyName}'.");
        SmokeAssert.True(property.ValueKind == JsonValueKind.Array, $"{label}.{propertyName} should be a JSON array.");
        foreach (var item in property.EnumerateArray())
        {
            assertElement(item);
        }
    }

    private static bool TryGetString(JsonElement root, string propertyName, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString() ?? string.Empty;
        return true;
    }

    private static void AssertThrows<TException>(Action action, string message)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }

    private static AnalysisReport CreateReport(Guid jobId, string eventsPath, string screenshotPath, string dropPath, string memoryDumpPath, string packetCapturePath)
    {
        return new AnalysisReport
        {
            JobId = jobId,
            Sample = new SampleIdentity
            {
                FileName = "sample.exe",
                FullPath = Path.Combine(Path.GetTempPath(), "sample.exe"),
                Sha256 = new string('0', 64),
                Sha1 = new string('1', 40),
                Md5 = new string('2', 32),
                Crc32 = "00000000",
                SizeBytes = 4
            },
            Status = AnalysisStatus.Completed,
            Events =
            [
                new SandboxEvent
                {
                    EventType = "guest.events.imported",
                    Source = "host",
                    Path = eventsPath,
                    Data =
                    {
                        ["eventCount"] = "3"
                    }
                },
                new SandboxEvent
                {
                    EventType = "screenshot.captured",
                    Source = "guest",
                    Path = screenshotPath,
                    Data =
                    {
                        ["phase"] = "after-run"
                    }
                },
                new SandboxEvent
                {
                    EventType = "file.created",
                    Source = "guest",
                    Path = dropPath,
                    Data =
                    {
                        ["relativePath"] = "artifacts/dropped-files/drop.bin"
                    }
                },
                new SandboxEvent
                {
                    EventType = "memory_dump.captured",
                    Source = "guest",
                    Path = memoryDumpPath,
                    Data =
                    {
                        ["capturePhase"] = "after-start",
                        ["collectionName"] = "memory-dumps"
                    }
                },
                new SandboxEvent
                {
                    EventType = "pcap.summary",
                    Source = "guest",
                    Path = packetCapturePath,
                    Data =
                    {
                        ["capturePhase"] = "future",
                        ["collectionName"] = "packet-captures"
                    }
                }
            ]
        };
    }

    private static void AssertReportHtmlContainsArtifactLinks(string html, Guid jobId)
    {
        AssertContainsAny(html, ["Artifact links", "证据文件链接"], "HTML report should include artifact links section.");
        SmokeAssert.True(html.Contains("events.json", StringComparison.Ordinal), "HTML report should expose events.json.");
        SmokeAssert.True(html.Contains("driver-events.jsonl", StringComparison.Ordinal), "HTML report should expose driver-events.jsonl.");
        SmokeAssert.True(html.Contains("screenshots/after-run.bmp", StringComparison.Ordinal), "HTML report should expose screenshot path.");
        AssertContainsAny(html, ["memory-dumps/after-start-pid123.dmp", "after-start-pid123.dmp"], "HTML report should expose memory dump path.");
        SmokeAssert.True(html.Contains("packet-captures/future.pcapng", StringComparison.Ordinal), "HTML report should expose packet capture path.");
        SmokeAssert.True(html.Contains("artifacts/dropped-files/drop.bin", StringComparison.Ordinal), "HTML report should expose dropped-file path.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/events.json\"", StringComparison.Ordinal), "HTML report should use safe relative event links.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/driver-events.jsonl\"", StringComparison.Ordinal), "HTML report should link driver JSONL.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/screenshots/after-run.bmp\"", StringComparison.Ordinal), "HTML report should link screenshots.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/memory-dumps/after-start-pid123.dmp\"", StringComparison.Ordinal), "HTML report should link memory dumps.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/packet-captures/future.pcapng\"", StringComparison.Ordinal), "HTML report should link packet captures.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/artifacts/manifest.json\"", StringComparison.Ordinal), "HTML report should link artifact manifest.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/artifacts/dropped-files/drop.bin\"", StringComparison.Ordinal), "HTML report should link dropped files.");
        AssertContainsAny(html, ["Artifact evidence", "证据文件证据", "证据文件详情"], "HTML report should render collapsible artifact evidence.");
        AssertContainsAny(html, ["Related artifacts", "相关证据文件"], "HTML report event evidence should expand related artifacts.");
        AssertContainsAny(html, ["Screenshot preview", "截图预览"], "HTML report should render screenshot evidence preview.");
        AssertContainsAny(html, ["Driver JSONL preview", "驱动 JSONL 预览"], "HTML report should render driver-events evidence preview.");
        AssertContainsAny(html, ["Manifest preview", "清单预览"], "HTML report should render artifact manifest evidence preview.");
        SmokeAssert.True(html.Contains("metadata.guestFullPath", StringComparison.Ordinal), "HTML report should expand original guest artifact paths.");
    }

    private static void AssertContainsAny(string content, IReadOnlyCollection<string> expectedValues, string message)
    {
        SmokeAssert.True(expectedValues.Any(expected => content.Contains(expected, StringComparison.Ordinal)), message);
    }

    /// <summary>
    /// Reads a repository file as text.
    /// Inputs are the smoke context and path segments; processing joins them
    /// under the repository root; the method returns complete file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        return File.ReadAllText(Path.Combine(allSegments));
    }
}
