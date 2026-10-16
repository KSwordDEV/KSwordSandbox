using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Keeps guest event-log rows that were conservatively marked nonbehavior
/// when the host can prove their process PID belongs to the sample tree.
/// Collection summaries and unrelated event-log PIDs remain environmental.
/// </summary>
internal sealed class SampleCorrelationEventLogChildContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.eventlog-child-pid-override";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var classified = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "guest",
                    ProcessName = "sample.exe",
                    ProcessId = 100,
                    Path = SamplePath,
                    CommandLine = SamplePath,
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = SamplePath
                    }
                },
                new SandboxEvent
                {
                    EventType = "process.new",
                    Source = "guest",
                    ProcessName = "powershell.exe",
                    ProcessId = 200,
                    ParentProcessId = 100,
                    Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["rootProcessId"] = "100",
                        ["treeLineage"] = "100>200",
                        ["processImagePath"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    }
                },
                EventLogChild(200, "eventlog.powershell.script_block", "targeted-windows-eventlog-behavior"),
                EventLogChild(200, "security.process.created", "privilege-security-audit-event"),
                EventLogChild(300, "eventlog.powershell.script_block", "targeted-windows-eventlog-behavior"),
                EventLogChild(100, "eventlog.behavior.query.summary", "targeted-windows-eventlog-behavior")
            ],
            SamplePath);

        var eventLogChild = classified.Single(evt => evt.EventType == "eventlog.powershell.script_block" && evt.ProcessId == 200);
        SmokeAssert.True(eventLogChild.Data["sampleCorrelation"] == "confirmed", "A sample descendant event-log PID must be confirmed on the host.");
        SmokeAssert.True(eventLogChild.Data["behaviorCounted"] == "true" && eventLogChild.Data["nonbehavior"] == "false", "Host promotion must clear stale guest nonbehavior flags.");

        var securityChild = classified.Single(evt => evt.EventType == "security.process.created");
        SmokeAssert.True(securityChild.Data["sampleCorrelation"] == "confirmed", "A sample descendant Security event PID must be confirmed on the host.");
        SmokeAssert.True(securityChild.Data["behaviorCounted"] == "true", "Confirmed Security evidence must be behavior-counted.");

        var unrelated = classified.Single(evt => evt.ProcessId == 300);
        SmokeAssert.True(unrelated.Data["sampleCorrelation"] == "environment", "An unrelated event-log PID must remain environmental.");

        var summary = classified.Single(evt => evt.EventType == "eventlog.behavior.query.summary");
        SmokeAssert.True(summary.Data["sampleCorrelation"] == "environment", "Event-log summaries must never be promoted by a sample root PID.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Host event-log correlation promotes sample child PIDs and preserves collection summaries/noise boundaries."
        });
    }

    private static SandboxEvent EventLogChild(int processId, string eventType, string evidenceRole)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "windowsBehaviorEventLog",
            ProcessId = processId,
            Data = new(StringComparer.OrdinalIgnoreCase)
            {
                ["evidenceRole"] = evidenceRole,
                ["behaviorCounted"] = "false",
                ["sampleBehaviorCandidate"] = "false",
                ["nonbehavior"] = "true",
                ["notSampleBehavior"] = "true",
                ["sampleCorrelation"] = "uncorrelated",
                ["sampleCorrelationStatus"] = "uncorrelated",
                ["sampleCorrelationStrength"] = "none"
            }
        };
    }

    private const string SamplePath = @"C:\KSwordSandbox\incoming\sample.exe";
}
