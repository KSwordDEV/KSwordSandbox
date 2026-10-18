using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// A Run/RunOnce value that points at an executable the sample's own process
/// tree started is persistence evidence even when no second runtime source
/// repeats the registry key.  Measured case: TeslaCrypt set
/// HKCU\...\Run\crypto13 to %APPDATA%\sxrtqak.exe after dropping and starting
/// that copy, and the row stayed unknown because process.start rows never enter
/// the cross-source mutation index.
/// </summary>
internal sealed class PersistenceTargetImageContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.persistence-target-launched-image";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var start = DateTimeOffset.UtcNow;
        const string DroppedImage = @"C:\Users\SandboxUser\AppData\Roaming\sxrtqak.exe";
        const string UnrelatedImage = @"C:\Users\SandboxUser\AppData\Roaming\notlaunched.exe";

        var events = new List<SandboxEvent>
        {
            SampleStart(start),
            DroppedProcessStart(start.AddSeconds(1), DroppedImage),
            RunKeyWrite(start.AddSeconds(2), "crypto13", DroppedImage),
            RunKeyWrite(start.AddSeconds(3), "crypto14", UnrelatedImage),
            RunKeyWrite(start.AddSeconds(4), "crypto15", "\"" + DroppedImage + "\" --silent")
        };

        var correlated = SampleCorrelationClassifier.Apply(events, SamplePath);

        var launched = Require(correlated, "crypto13");
        SmokeAssert.True(
            launched.Data["sampleCorrelation"] == "probable",
            "A Run value pointing at an image the sample tree launched must be probable persistence evidence. actual=" +
            (launched.Data.TryGetValue("sampleCorrelation", out var actual) ? actual : "none") +
            " reason=" +
            (launched.Data.TryGetValue("sampleCorrelationReason", out var reason) ? reason : "none"));
        SmokeAssert.True(
            launched.Data["behaviorCounted"] == "true",
            "Persistence pointing at a sample-launched image must remain behavior-counted.");
        SmokeAssert.True(
            launched.Data["sampleCorrelationReason"].Contains("persistence-target-is-image-started", StringComparison.OrdinalIgnoreCase),
            "The reason must name the persistence-target rule so the report can explain the attribution.");

        var quoted = Require(correlated, "crypto15");
        SmokeAssert.True(
            quoted.Data["sampleCorrelation"] == "probable",
            "A quoted command line whose leading token is the launched image must still match.");

        var unrelated = Require(correlated, "crypto14");
        SmokeAssert.True(
            unrelated.Data["sampleCorrelation"] != "probable",
            "A Run value pointing at an image the sample never started must stay unattributed.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Run values that name a sample-launched image are attributed; unrelated user-writable targets are not."
        });
    }

    private static SandboxEvent SampleStart(DateTimeOffset timestamp) => new()
    {
        EventType = "process.start",
        Source = "guest",
        Timestamp = timestamp,
        ProcessName = "sample.exe",
        ProcessId = 9552,
        Path = SamplePath,
        CommandLine = SamplePath,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["processImagePath"] = SamplePath
        }
    };

    private static SandboxEvent DroppedProcessStart(DateTimeOffset timestamp, string imagePath) => new()
    {
        EventType = "process.start",
        Source = "guest",
        Timestamp = timestamp,
        ProcessName = "sxrtqak.exe",
        ProcessId = 9000,
        ParentProcessId = 9552,
        Path = imagePath,
        CommandLine = imagePath,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["processImagePath"] = imagePath,
            ["parentProcessId"] = "9552"
        }
    };

    private static SandboxEvent RunKeyWrite(DateTimeOffset timestamp, string valueName, string value) => new()
    {
        EventType = "registry.run.created",
        Source = "guest",
        Timestamp = timestamp,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["keyPath"] = RunKeyPath,
            ["location"] = @"HKCU\" + RunKeyPath,
            ["valueName"] = valueName,
            ["value"] = value,
            ["signature"] = value + "|String|||autorun-run-key|HKCU\\" + RunKeyPath,
            ["behaviorCounted"] = "true"
        }
    };

    private static SandboxEvent Require(IEnumerable<SandboxEvent> events, string valueName)
    {
        return events.Single(evt => evt.Data.TryGetValue("valueName", out var value) && value == valueName);
    }

    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string SamplePath = @"C:\KSwordSandbox\incoming\sample.exe";
}
