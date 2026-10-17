using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// R0 driver rows can carry the Guest Agent PID while the top-level process
/// name is empty.  The collector/agent process must remain environment noise
/// even when the producer pre-populated behavior flags.
/// </summary>
internal sealed class CollectorDriverSelfNoiseCorrelationScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.r0-agent-self-noise";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        const int agentPid = 1924;
        var start = DateTimeOffset.UtcNow;
        var samplePath = @"C:\KSwordSandbox\incoming\hostname.exe";
        var agentPath = @"C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe";
        var classified = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "guest",
                    Timestamp = start,
                    ProcessName = "hostname.exe",
                    ProcessId = 8576,
                    Path = samplePath,
                    CommandLine = samplePath
                },
                new SandboxEvent
                {
                    EventType = "process.snapshot",
                    Source = "guest",
                    Timestamp = start.AddMilliseconds(1),
                    ProcessName = "KSword.Sandbox.Agent",
                    ProcessId = agentPid,
                    Path = agentPath,
                    CommandLine = $"\"{agentPath}\" --sample {samplePath}",
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = agentPath,
                        ["processName"] = "KSword.Sandbox.Agent"
                    }
                },
                new SandboxEvent
                {
                    EventType = "driver.file",
                    Source = "driver",
                    Timestamp = start.AddMilliseconds(2),
                    ProcessId = agentPid,
                    Path = @"\Users\SandboxUser\AppData\Local\Temp",
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["driverProcessId"] = agentPid.ToString(),
                        ["operationName"] = "create",
                        ["sampleBehaviorCandidate"] = "true",
                        ["behaviorCounted"] = "true",
                        ["nonbehavior"] = "false"
                    }
                }
            ],
            samplePath);

        var driver = classified.Single(evt => evt.EventType == "driver.file");
        SmokeAssert.True(driver.Data["sampleCorrelation"] == "environment",
            "R0 rows owned by KSword.Sandbox.Agent must be environmental self-noise.");
        SmokeAssert.True(driver.Data["behaviorCounted"] == "false" && driver.Data["sampleBehaviorCandidate"] == "false",
            "Agent self-noise must not retain producer behavior flags.");
        SmokeAssert.True(driver.Data["sampleCorrelationReason"] == "row-belongs-to-sandbox-collector-or-agent",
            "Agent self-noise should disclose the collector/agent attribution boundary.");

        var envelopeOnly = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "driver.file",
                    Source = "driver",
                    Timestamp = start.AddMilliseconds(3),
                    ProcessId = agentPid,
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = agentPath,
                        ["sampleBehaviorCandidate"] = "true",
                        ["behaviorCounted"] = "true"
                    }
                }
            ],
            samplePath).Single();
        SmokeAssert.True(envelopeOnly.Data["sampleCorrelation"] == "environment" &&
                         envelopeOnly.Data["behaviorCounted"] == "false",
            "An R0 self-noise row carrying only its process image envelope must still be demoted.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 rows owned by the Guest Agent remain environment evidence rather than sample behavior."
        });
    }
}
