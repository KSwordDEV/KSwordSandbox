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
                new SandboxEvent
                {
                    EventType = "file.created",
                    Source = "guest",
                    Path = @"C:\Users\SandboxUser\AppData\Roaming\sample.exe",
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["actorPidStatus"] = "unavailable-filesystem-watcher",
                        ["operation"] = "file.created",
                        ["evidenceRole"] = "file-change"
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

        var basenameCollision = classified.Single(evt => evt.EventType == "file.created");
        SmokeAssert.True(basenameCollision.Data["sampleCorrelation"] != "confirmed", "An unattributed watcher path sharing the sample basename must not be confirmed by filename alone.");

        var guiEtw = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "guest",
                    ProcessName = "notepad.exe",
                    ProcessId = 500,
                    Path = GuiSamplePath,
                    CommandLine = GuiSamplePath,
                    Data = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = GuiSamplePath
                    }
                },
                EtwGuiLifecycle(500, "image.load", @"C:\Windows\System32\kernel32.dll"),
                EtwGuiLifecycle(500, "image.load", @"C:\Users\SandboxUser\AppData\Local\payload.dll"),
                EtwGuiLifecycle(500, "thread.start", null),
                EtwGuiLifecycle(500, "thread.start", null, remote: true)
            ],
            GuiSamplePath);

        var systemImage = guiEtw.Single(evt => evt.EventType == "image.load" && evt.Path?.EndsWith("kernel32.dll", StringComparison.OrdinalIgnoreCase) == true);
        SmokeAssert.True(systemImage.Data["normalBehaviorBoundary"] == "normal-interactive-gui-baseline" &&
                         systemImage.Data["behaviorCounted"] == "false",
            "System DLL ETW image loads for a trusted GUI sample must remain evidence without becoming suspicious behavior.");

        var userImage = guiEtw.Single(evt => evt.EventType == "image.load" && evt.Path?.EndsWith("payload.dll", StringComparison.OrdinalIgnoreCase) == true);
        SmokeAssert.True(userImage.Data["sampleCorrelationBoundary"] == "sample-attribution-boundary" &&
                         userImage.Data["behaviorCounted"] == "true",
            "User-writable ETW image loads must remain sample candidates for a trusted GUI process.");

        var normalThread = guiEtw.Single(evt => evt.EventType == "thread.start" && !evt.Data.ContainsKey("remoteThread"));
        SmokeAssert.True(normalThread.Data["normalBehaviorBoundary"] == "normal-interactive-gui-baseline" &&
                         normalThread.Data["behaviorCounted"] == "false",
            "Routine ETW GUI thread lifecycle edges must remain baseline evidence.");

        var remoteThread = guiEtw.Single(evt => evt.EventType == "thread.start" && evt.Data.ContainsKey("remoteThread"));
        SmokeAssert.True(remoteThread.Data["sampleCorrelationBoundary"] == "sample-attribution-boundary" &&
                         remoteThread.Data["behaviorCounted"] == "true",
            "Explicit remote-thread ETW evidence must remain a sample behavior candidate.");

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

    private static SandboxEvent EtwGuiLifecycle(int processId, string eventType, string? path, bool remote = false)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etw-live-tracerpt",
            ["collectorSource"] = "etwLive",
            ["rawDecoded"] = "true"
        };
        if (remote)
        {
            data["remoteThread"] = "true";
        }

        return new SandboxEvent
        {
            EventType = eventType,
            Source = "etwLive",
            ProcessName = "notepad.exe",
            ProcessId = processId,
            Path = path,
            Data = data
        };
    }

    private const string SamplePath = @"C:\KSwordSandbox\incoming\sample.exe";
    private const string GuiSamplePath = @"C:\KSwordSandbox\incoming\notepad.exe";
}
