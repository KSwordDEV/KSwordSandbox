using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Isolated ownerless watcher rows cannot be promoted by a familiar or opaque
/// suffix. The structural batch classifier performs that promotion separately.
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
        const string LedgerPath = @"C:\Users\Public\ledger.xlsx";
        const string LedgerCiphertext = LedgerPath + ".plmn";

        var events = new List<SandboxEvent>
        {
            SampleStart(start),
            SampleExit(start.AddSeconds(20)),
            WatcherRename(start.AddSeconds(5), TelemetryPath, TelemetryCiphertext),
            WatcherRename(start.AddSeconds(6), DocumentPath, DocumentCiphertext),
            WatcherRename(start.AddSeconds(7), SettingsPath, SettingsTemp),
            WatcherCreate(start.AddSeconds(8), @"C:\Users\Public\budget.xlsx.locked"),
            // Outside the derived lifecycle window but stamped by the guest
            // probe as during-run: this is the shape the full job pipeline
            // produces once host planning rows reshape root PID resolution.
            WatcherRename(start.AddSeconds(700), LedgerPath, LedgerCiphertext, "during-run"),
            // Outside the sample lifecycle: the process already exited at
            // +20s, so this rename belongs to the guest's own activity.
            WatcherRename(start.AddSeconds(600), TelemetryPath, TelemetryCiphertext + ".late")
        };

        var correlated = SampleCorrelationClassifier.Apply(events, SamplePath);

        var telemetry = Require(correlated, "file.renamed", TelemetryCiphertext);
        SmokeAssert.True(telemetry.Data["sampleCorrelation"] != "probable",
            "A single telemetry rename cannot be promoted by its suffix.");

        var document = Require(correlated, "file.renamed", DocumentCiphertext);
        SmokeAssert.True(
            document.Data["sampleCorrelation"] != "probable",
            "An opaque appended token is insufficient alone.");

        var locked = Require(correlated, "file.created", @"C:\Users\Public\budget.xlsx.locked");
        SmokeAssert.True(
            locked.Data["sampleCorrelation"] != "probable",
            "A known marker on a created file is insufficient alone.");

        var settings = Require(correlated, "file.renamed", SettingsTemp);
        SmokeAssert.True(
            settings.Data["sampleCorrelation"] != "probable",
            "A benign temporary suffix must not be promoted to sample behavior.");

        var late = Require(correlated, "file.renamed", TelemetryCiphertext + ".late");
        SmokeAssert.True(
            late.Data["sampleCorrelation"] == "environment",
            "An encryption rename outside the sample lifecycle must stay collector noise.");

        var phaseStamped = Require(correlated, "file.renamed", LedgerCiphertext);
        SmokeAssert.True(
            phaseStamped.Data["sampleCorrelation"] != "probable",
            "A guest-stamped phase alone cannot promote an ownerless suffix rename.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Individual ownerless watcher renames remain unpromoted regardless of suffix or phase stamp."
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

    private static SandboxEvent WatcherRename(
        DateTimeOffset timestamp,
        string sourcePath,
        string destinationPath,
        string? capturePhase = null)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["actorPidStatus"] = "unavailable-filesystem-watcher",
            ["operation"] = "file.renamed",
            ["sourcePath"] = sourcePath,
            ["previousPath"] = sourcePath,
            ["destinationPath"] = destinationPath,
            ["behaviorCounted"] = "true"
        };
        if (!string.IsNullOrWhiteSpace(capturePhase))
        {
            data["capturePhase"] = capturePhase;
            data["phase"] = capturePhase;
        }

        return new SandboxEvent
        {
            EventType = "file.renamed",
            Source = "guest",
            Timestamp = timestamp,
            Path = destinationPath,
            Data = data
        };
    }

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
