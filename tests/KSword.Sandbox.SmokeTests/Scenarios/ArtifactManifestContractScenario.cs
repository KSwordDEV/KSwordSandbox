using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Pipeline;
using KSword.Sandbox.Core.Pipeline.Stages;
using KSword.Sandbox.Core.Reporting;
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
        await AssertReportArtifactLinksAsync(context, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Artifact manifest schema, host index, guest reader, and report artifact links are present."
        };
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
        var reportStage = ReadRepositoryText(context, "src", "KSword.Sandbox.Core", "Pipeline", "Stages", "ReportArtifactStage.cs");

        SmokeAssert.True(guestWriter.Contains("WriteArtifactManifest", StringComparison.Ordinal), "Guest writer should expose artifact manifest output.");
        SmokeAssert.True(guestWriter.Contains("artifacts", StringComparison.Ordinal), "Guest writer should use the artifacts directory.");
        SmokeAssert.True(guestWriter.Contains("manifest.json", StringComparison.Ordinal), "Guest writer should write manifest.json.");
        SmokeAssert.True(guestWriter.Contains("MimeType", StringComparison.Ordinal), "Guest writer should include MIME metadata.");
        SmokeAssert.True(guestWriter.Contains("SafeLink", StringComparison.Ordinal), "Guest writer should include safe links.");
        SmokeAssert.True(guestDoc.Contains("artifacts/manifest.json", StringComparison.Ordinal), "Guest-agent doc should describe artifacts/manifest.json.");
        SmokeAssert.True(reportDoc.Contains("ArtifactManifest", StringComparison.Ordinal), "Report schema doc should describe ArtifactManifest.");
        SmokeAssert.True(reportDoc.Contains("DroppedFile", StringComparison.Ordinal), "Report schema doc should describe dropped-file artifact entries.");
        SmokeAssert.True(reportDoc.Contains("artifact-index.json", StringComparison.Ordinal), "Report schema doc should describe host artifact index.");
        SmokeAssert.True(artifactDoc.Contains("safeLink", StringComparison.Ordinal), "Artifact manifest doc should describe safe links.");
        SmokeAssert.True(artifactDoc.Contains("mimeType", StringComparison.Ordinal), "Artifact manifest doc should describe MIME type.");
        SmokeAssert.True(reportStage.Contains("HostArtifactIndexBuilder", StringComparison.Ordinal), "Report artifact stage should write host artifact index.");
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
            Artifacts =
            [
                new ArtifactDescriptor
                {
                    Kind = ArtifactKind.DroppedFile,
                    Name = "drop.bin",
                    Category = "dropped-file",
                    RelativePath = "artifacts/drop.bin",
                    SafeLink = "artifacts/drop.bin",
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
        SmokeAssert.True(!string.IsNullOrWhiteSpace(descriptor.Sha256), "Manifest descriptor should include SHA-256.");
        SmokeAssert.True(descriptor.SizeBytes > 0, "Manifest descriptor should include size.");
        SmokeAssert.True(descriptor.MimeType == "application/json", "Manifest descriptor should include MIME type.");
        SmokeAssert.True(descriptor.Category == "artifact-manifest", "Manifest descriptor should include category.");
        SmokeAssert.True(descriptor.SafeLink == "artifact-manifest.json", "Manifest descriptor should include a safe relative link.");

        var roundTrip = await store.ReadManifestAsync(descriptor, cancellationToken);
        SmokeAssert.True(roundTrip.JobId == jobId, "Round-tripped manifest should carry job ID.");
        SmokeAssert.True(roundTrip.Artifacts.Count == 1, "Round-tripped manifest should preserve artifact entries.");
        SmokeAssert.True(roundTrip.Artifacts[0].Kind == ArtifactKind.DroppedFile, "Round-tripped manifest should preserve dropped-file kind.");
        SmokeAssert.True(roundTrip.Artifacts[0].Hashes.ContainsKey("sha256"), "Round-tripped manifest entries should expose hash map.");
        SmokeAssert.True(roundTrip.Artifacts[0].SafeLink == "artifacts/drop.bin", "Round-tripped manifest entries should preserve safe link.");
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
        Directory.CreateDirectory(artifactsRoot);
        var droppedFilePath = Path.Combine(artifactsRoot, "drop.bin");
        await File.WriteAllTextAsync(droppedFilePath, "drop", cancellationToken);

        var manifestPath = Path.Combine(artifactsRoot, "manifest.json");
        var manifest = new ArtifactManifest
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
                    RelativePath = "artifacts/drop.bin",
                    FullPath = @"C:\KSwordSandbox\out\artifacts\drop.bin",
                    SafeLink = "artifacts/drop.bin",
                    MimeType = "application/octet-stream",
                    SizeBytes = 4,
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["origin"] = "guest"
                    }
                }
            ]
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, ManifestJsonOptions), cancellationToken);

        var reader = new GuestArtifactManifestReader();
        var loaded = await reader.TryReadAsync(guestRoot, cancellationToken)
            ?? throw new InvalidOperationException("Guest manifest should load.");

        SmokeAssert.True(loaded.RootPath == artifactsRoot, "Loaded guest manifest should normalize root path to host artifacts directory.");
        SmokeAssert.True(loaded.Artifacts.Count == 1, "Loaded guest manifest should preserve artifact count.");
        SmokeAssert.True(loaded.Artifacts[0].FullPath == droppedFilePath, "Loaded guest artifact should resolve full host path from relative path.");
        SmokeAssert.True(loaded.Artifacts[0].Metadata.ContainsKey("guestFullPath"), "Loaded guest artifact should preserve original guest full path.");
        SmokeAssert.True(loaded.Artifacts[0].Category == "dropped-file", "Loaded guest artifact should preserve category.");
        SmokeAssert.True(loaded.Artifacts[0].MimeType == "application/octet-stream", "Loaded guest artifact should preserve MIME type.");
        SmokeAssert.True(loaded.Artifacts[0].SafeLink == "artifacts/drop.bin", "Loaded guest artifact should expose a safe link.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(loaded.Artifacts[0].Sha256), "Loaded guest artifact should fill SHA-256 when file is present.");
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
        var artifactsRoot = Path.Combine(guestRoot, "artifacts");
        Directory.CreateDirectory(screenshotsRoot);
        Directory.CreateDirectory(artifactsRoot);

        await File.WriteAllTextAsync(Path.Combine(jobRoot, "report.json"), "{}", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(guestRoot, "events.json"), "[]", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(guestRoot, "driver-events.jsonl"), "{}", cancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(screenshotsRoot, "after-run.bmp"), [0x42, 0x4d, 0x00, 0x00], cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(artifactsRoot, "drop.bin"), "drop", cancellationToken);
        await File.WriteAllTextAsync(Path.Combine(artifactsRoot, "manifest.json"), "{}", cancellationToken);

        var builder = new HostArtifactIndexBuilder();
        var index = builder.Build(jobId, jobRoot);
        AssertIndexedArtifact(index, ArtifactKind.ReportJson, "report.json");
        AssertIndexedArtifact(index, ArtifactKind.GuestEventsJson, $"guest/{jobId:N}/events.json");
        AssertIndexedArtifact(index, ArtifactKind.DriverEventsJsonLines, $"guest/{jobId:N}/driver-events.jsonl");
        AssertIndexedArtifact(index, ArtifactKind.Screenshot, $"guest/{jobId:N}/screenshots/after-run.bmp");
        var dropped = AssertIndexedArtifact(index, ArtifactKind.DroppedFile, $"guest/{jobId:N}/artifacts/drop.bin");
        SmokeAssert.True(dropped.SizeBytes == 4, "Dropped-file index entry should include size.");
        SmokeAssert.True(dropped.MimeType == "application/octet-stream", "Dropped-file index entry should include MIME type.");
        SmokeAssert.True(dropped.Category == "dropped-file", "Dropped-file index entry should include category.");
        SmokeAssert.True(dropped.SafeLink == $"guest/{jobId:N}/artifacts/drop.bin", "Dropped-file index entry should include safe relative link.");
        SmokeAssert.True(dropped.Hashes.ContainsKey("sha256"), "Dropped-file index entry should include hashes map.");

        var indexDescriptor = builder.WriteIndex(jobId, jobRoot);
        SmokeAssert.True(indexDescriptor.Kind == ArtifactKind.ArtifactIndex, "Index descriptor should use ArtifactIndex kind.");
        SmokeAssert.True(File.Exists(indexDescriptor.FullPath), "artifact-index.json should be written.");
        var loaded = builder.TryReadIndex(jobRoot) ?? throw new InvalidOperationException("artifact-index.json should load.");
        SmokeAssert.True(loaded.Artifacts.Any(artifact => artifact.Kind == ArtifactKind.DriverEventsJsonLines), "Loaded index should include driver JSONL.");
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
        var artifactsRoot = Path.Combine(guestRoot, "artifacts");
        Directory.CreateDirectory(screenshotsRoot);
        Directory.CreateDirectory(artifactsRoot);

        var eventsPath = Path.Combine(guestRoot, "events.json");
        var driverPath = Path.Combine(guestRoot, "driver-events.jsonl");
        var screenshotPath = Path.Combine(screenshotsRoot, "after-run.bmp");
        var dropPath = Path.Combine(artifactsRoot, "drop.bin");
        var manifestPath = Path.Combine(artifactsRoot, "manifest.json");
        await File.WriteAllTextAsync(eventsPath, "[]", cancellationToken);
        await File.WriteAllTextAsync(driverPath, "{}", cancellationToken);
        await File.WriteAllBytesAsync(screenshotPath, [0x42, 0x4d, 0x00, 0x00], cancellationToken);
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
                        RelativePath = "artifacts/drop.bin",
                        FullPath = @"C:\KSwordSandbox\out\artifacts\drop.bin",
                        SafeLink = "artifacts/drop.bin",
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

        var report = CreateReport(jobId, eventsPath, screenshotPath, dropPath);
        var index = new HostArtifactIndexBuilder().Build(jobId, jobRoot);
        var html = new HtmlReportRenderer().Render(report, index.Artifacts);
        AssertReportHtmlContainsArtifactLinks(html, jobId);

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
        return artifact!;
    }

    private static AnalysisReport CreateReport(Guid jobId, string eventsPath, string screenshotPath, string dropPath)
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
                        ["relativePath"] = "artifacts/drop.bin"
                    }
                }
            ]
        };
    }

    private static void AssertReportHtmlContainsArtifactLinks(string html, Guid jobId)
    {
        SmokeAssert.True(html.Contains("Artifact links", StringComparison.Ordinal), "HTML report should include artifact links section.");
        SmokeAssert.True(html.Contains("events.json", StringComparison.Ordinal), "HTML report should expose events.json.");
        SmokeAssert.True(html.Contains("driver-events.jsonl", StringComparison.Ordinal), "HTML report should expose driver-events.jsonl.");
        SmokeAssert.True(html.Contains("screenshots/after-run.bmp", StringComparison.Ordinal), "HTML report should expose screenshot path.");
        SmokeAssert.True(html.Contains("artifacts/drop.bin", StringComparison.Ordinal), "HTML report should expose dropped-file path.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/events.json\"", StringComparison.Ordinal), "HTML report should use safe relative event links.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/driver-events.jsonl\"", StringComparison.Ordinal), "HTML report should link driver JSONL.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/screenshots/after-run.bmp\"", StringComparison.Ordinal), "HTML report should link screenshots.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/artifacts/manifest.json\"", StringComparison.Ordinal), "HTML report should link artifact manifest.");
        SmokeAssert.True(html.Contains($"href=\"guest/{jobId:N}/artifacts/drop.bin\"", StringComparison.Ordinal), "HTML report should link dropped files.");
        SmokeAssert.True(html.Contains("Artifact evidence", StringComparison.Ordinal), "HTML report should render collapsible artifact evidence.");
        SmokeAssert.True(html.Contains("Related artifacts", StringComparison.Ordinal), "HTML report event evidence should expand related artifacts.");
        SmokeAssert.True(html.Contains("Screenshot preview", StringComparison.Ordinal), "HTML report should render screenshot evidence preview.");
        SmokeAssert.True(html.Contains("Driver JSONL preview", StringComparison.Ordinal), "HTML report should render driver-events evidence preview.");
        SmokeAssert.True(html.Contains("Manifest preview", StringComparison.Ordinal), "HTML report should render artifact manifest evidence preview.");
        SmokeAssert.True(html.Contains("metadata.guestFullPath", StringComparison.Ordinal), "HTML report should expand original guest artifact paths.");
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
