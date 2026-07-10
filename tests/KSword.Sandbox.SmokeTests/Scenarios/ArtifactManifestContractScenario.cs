using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
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

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Artifact manifest model, guest writer contract, and host reader contract are present."
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

        SmokeAssert.True(guestWriter.Contains("WriteArtifactManifest", StringComparison.Ordinal), "Guest writer should expose artifact manifest output.");
        SmokeAssert.True(guestWriter.Contains("artifacts", StringComparison.Ordinal), "Guest writer should use the artifacts directory.");
        SmokeAssert.True(guestWriter.Contains("manifest.json", StringComparison.Ordinal), "Guest writer should write manifest.json.");
        SmokeAssert.True(guestDoc.Contains("artifacts/manifest.json", StringComparison.Ordinal), "Guest-agent doc should describe artifacts/manifest.json.");
        SmokeAssert.True(reportDoc.Contains("ArtifactManifest", StringComparison.Ordinal), "Report schema doc should describe ArtifactManifest.");
        SmokeAssert.True(reportDoc.Contains("DroppedFile", StringComparison.Ordinal), "Report schema doc should describe dropped-file artifact entries.");
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
                    RelativePath = Path.Combine("artifacts", "drop.bin"),
                    SizeBytes = 4,
                    Sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
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

        var roundTrip = await store.ReadManifestAsync(descriptor, cancellationToken);
        SmokeAssert.True(roundTrip.JobId == jobId, "Round-tripped manifest should carry job ID.");
        SmokeAssert.True(roundTrip.Artifacts.Count == 1, "Round-tripped manifest should preserve artifact entries.");
        SmokeAssert.True(roundTrip.Artifacts[0].Kind == ArtifactKind.DroppedFile, "Round-tripped manifest should preserve dropped-file kind.");
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
                    RelativePath = Path.Combine("artifacts", "drop.bin"),
                    FullPath = @"C:\KSwordSandbox\out\artifacts\drop.bin",
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
