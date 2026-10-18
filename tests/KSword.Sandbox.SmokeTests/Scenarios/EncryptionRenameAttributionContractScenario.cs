using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// A filesystem watcher can only observe the post-rename name of an encrypted
/// file, so a ransomware rename can never satisfy the same-target cross-source
/// join that promotes ownerless watcher rows.  Measured case: TeslaCrypt
/// renamed the Windows telemetry JSON file to *.json.ecc and all 56 *.ecc rows
/// were demoted to collector noise.  Encryption suffixes inside the sample's
/// own execution window must stay attributable, while ordinary suffix churn
/// and out-of-window renames must not.
/// </summary>
internal sealed class EncryptionRenameAttributionContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.filesystem-watcher-encryption-rename";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var start = DateTimeOffset.UtcNow;
        const string TelemetryPath = @"C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings\telemetry.ASM-WindowsDefault.json";
        const string TelemetryCiphertext = TelemetryPath + ".ecc";
        const string DocumentPath = @"C:\Users\Public\quarterly-report.docx";
        const string DocumentCiphertext = DocumentPath + ".qwerty";
        const string SettingsPath = @"C:\Users\Public\settings.json";
        const string SettingsTemp = SettingsPath + ".tmp";

        var events = new List<SandboxEvent>
        {
            SampleStart(start),
            SampleExit(start.AddSeconds(20)),
            WatcherRename(start.AddSeconds(5), TelemetryPath, TelemetryCiphertext),
            WatcherRename(start.AddSeconds(6), DocumentPath, DocumentCiphertext),
            WatcherRename(start.AddSeconds(7), SettingsPath, SettingsTemp),
            WatcherCreate(start.AddSeconds(8), @"C:\Users\Public\budget.xlsx.locked"),
            // Outside the sample lifecycle: the process already exited at
            // +20s, so this rename belongs to the guest's own activity.
            WatcherRename(start.AddSeconds(600), TelemetryPath, TelemetryCiphertext + ".late")
        };

        var correlated = SampleCorrelationClassifier.Apply(events, SamplePath);

        var telemetry = Require(correlated, "file.renamed", TelemetryCiphertext);
        SmokeAssert.True(
            telemetry.Data["sampleCorrelation"] == "probable",
            "Encrypted telemetry rename inside the sample window must be probable even though no same-target cross-source row exists.");
        SmokeAssert.True(
            telemetry.Data["behaviorCounted"] == "true",
            "Encryption rename inside the sample window must remain behavior-counted.");
        SmokeAssert.True(
            telemetry.Data["sampleCorrelationReason"].Contains("teslacrypt", StringComparison.OrdinalIgnoreCase),
            "Encryption rename reason must name the family marker it matched so the report can explain the attribution.");

        var document = Require(correlated, "file.renamed", DocumentCiphertext);
        SmokeAssert.True(
            document.Data["sampleCorrelation"] == "probable",
            "An opaque token appended to a plaintext document extension must stay attributable inside the sample window.");

        var locked = Require(correlated, "file.created", @"C:\Users\Public\budget.xlsx.locked");
        SmokeAssert.True(
            locked.Data["sampleCorrelation"] == "probable",
            "A known ransomware marker on a created file must stay attributable inside the sample window.");

        var settings = Require(correlated, "file.renamed", SettingsTemp);
        SmokeAssert.True(
            settings.Data["sampleCorrelation"] != "probable",
            "A benign temporary suffix must not be promoted to sample behavior.");

        var late = Require(correlated, "file.renamed", TelemetryCiphertext + ".late");
        SmokeAssert.True(
            late.Data["sampleCorrelation"] == "environment",
            "An encryption rename outside the sample lifecycle must stay collector noise.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Encryption renames inside the sample lifecycle are attributable by shape; late and benign-suffix renames stay noise."
        });
    }

    private static SandboxEvent SampleStart(DateTimeOffset timestamp) => new()
    {
        EventType = "process.start",
        Source = "guest",
        Timestamp = timestamp,
        ProcessName = "sample.exe",
        ProcessId = 100,
        Path = SamplePath,
        CommandLine = SamplePath,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["processImagePath"] = SamplePath
        }
    };

    private static SandboxEvent SampleExit(DateTimeOffset timestamp) => new()
    {
        EventType = "process.exit",
        Source = "guest",
        Timestamp = timestamp,
        ProcessName = "sample.exe",
        ProcessId = 100,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["processImagePath"] = SamplePath
        }
    };

    private static SandboxEvent WatcherRename(DateTimeOffset timestamp, string sourcePath, string destinationPath) => new()
    {
        EventType = "file.renamed",
        Source = "guest",
        Timestamp = timestamp,
        Path = destinationPath,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["actorPidStatus"] = "unavailable-filesystem-watcher",
            ["operation"] = "file.renamed",
            ["sourcePath"] = sourcePath,
            ["previousPath"] = sourcePath,
            ["destinationPath"] = destinationPath,
            ["behaviorCounted"] = "true"
        }
    };

    private static SandboxEvent WatcherCreate(DateTimeOffset timestamp, string path) => new()
    {
        EventType = "file.created",
        Source = "guest",
        Timestamp = timestamp,
        Path = path,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["actorPidStatus"] = "unavailable-filesystem-watcher",
            ["operation"] = "file.created",
            ["behaviorCounted"] = "true"
        }
    };

    private static SandboxEvent Require(IEnumerable<SandboxEvent> events, string eventType, string target)
    {
        return events.Single(evt => evt.EventType.Equals(eventType, StringComparison.OrdinalIgnoreCase) &&
            (string.Equals(evt.Path, target, StringComparison.OrdinalIgnoreCase) ||
             evt.Data.Values.Any(value => string.Equals(value, target, StringComparison.OrdinalIgnoreCase))));
    }

    private const string SamplePath = @"C:\KSwordSandbox\incoming\sample.exe";
}
