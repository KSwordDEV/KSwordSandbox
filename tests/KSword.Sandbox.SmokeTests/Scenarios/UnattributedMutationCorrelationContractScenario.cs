using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Prevents user-writable R0 file/registry rows from becoming probable solely
/// because their path looks suspicious.  A second runtime source joined to a
/// sample PID is required before the row can enter the behavior lane.
/// </summary>
internal sealed class UnattributedMutationCorrelationContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.unattributed-mutation-cross-source";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var start = DateTimeOffset.UtcNow;
        var filePath = @"C:\Users\Public\drop.exe";
        var keyPath = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater";
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "process.start",
                Source = "guest",
                Timestamp = start,
                ProcessName = "sample.exe",
                ProcessId = 100,
                Path = SamplePath,
                CommandLine = SamplePath,
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["processImagePath"] = SamplePath
                }
            },
            new()
            {
                EventType = "process.tree.summary",
                Source = "guest",
                Timestamp = start.AddMilliseconds(1),
                ProcessId = 100,
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["rootProcessId"] = "100",
                    ["rootImagePath"] = SamplePath
                }
            },
            DriverFile(start.AddSeconds(1), filePath),
            DriverRegistry(start.AddSeconds(1), keyPath),
            EtwFile(start.AddSeconds(1), filePath),
            EtwRegistry(start.AddSeconds(1), keyPath)
        };

        var withCrossSource = SampleCorrelationClassifier.Apply(events, SamplePath);
        var file = Require(withCrossSource, "driver.file", filePath);
        SmokeAssert.True(file.Data["sampleCorrelation"] == "probable", "R0 file mutation should become probable only after an ETW sample-owned path join.");
        SmokeAssert.True(file.Data["behaviorCounted"] == "true", "Cross-source R0 file evidence should remain behavior-counted.");
        var registry = Require(withCrossSource, "driver.registry", keyPath);
        SmokeAssert.True(registry.Data["sampleCorrelation"] == "probable", "R0 registry mutation should become probable only after an ETW sample-owned key join.");
        SmokeAssert.True(registry.Data["behaviorCounted"] == "true", "Cross-source R0 registry evidence should remain behavior-counted.");

        var withoutCrossSource = SampleCorrelationClassifier.Apply(
            events.Where(evt => evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase) ||
                evt.EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase)),
            SamplePath);
        var ambientFile = Require(withoutCrossSource, "driver.file", filePath);
        SmokeAssert.True(ambientFile.Data["sampleCorrelation"] == "unknown", "Ownerless R0 file mutation must remain unknown without an independent source.");
        SmokeAssert.True(ambientFile.Data["behaviorCounted"] == "false", "Ownerless R0 file mutation must stay out of primary behavior counts.");
        var ambientRegistry = Require(withoutCrossSource, "driver.registry", keyPath);
        SmokeAssert.True(ambientRegistry.Data["sampleCorrelation"] == "unknown", "Ownerless R0 registry mutation must remain unknown without an independent source.");
        SmokeAssert.True(ambientRegistry.Data["behaviorCounted"] == "false", "Ownerless R0 registry mutation must stay out of primary behavior counts.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Ownerless R0 mutations are retained as evidence and require cross-source sample attribution before promotion."
        });
    }

    private static SandboxEvent DriverFile(DateTimeOffset timestamp, string path) => new()
    {
        EventType = "driver.file",
        Source = "driver",
        Timestamp = timestamp,
        Path = path,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["operationName"] = "create",
            ["behaviorCounted"] = "true"
        }
    };

    private static SandboxEvent DriverRegistry(DateTimeOffset timestamp, string path) => new()
    {
        EventType = "driver.registry",
        Source = "driver",
        Timestamp = timestamp,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["keyPath"] = path,
            ["registryOperationName"] = "SetValue",
            ["behaviorCounted"] = "true"
        }
    };

    private static SandboxEvent EtwFile(DateTimeOffset timestamp, string path) => new()
    {
        EventType = "file.write",
        Source = "etwLive",
        Timestamp = timestamp,
        ProcessId = 100,
        Path = path,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etwLive",
            ["operation"] = "write",
            ["behaviorCounted"] = "true"
        }
    };

    private static SandboxEvent EtwRegistry(DateTimeOffset timestamp, string path) => new()
    {
        EventType = "registry.etw",
        Source = "etwLive",
        Timestamp = timestamp,
        ProcessId = 100,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etwLive",
            ["keyPath"] = path,
            ["operation"] = "set",
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
