using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

internal sealed class AgentFailureEtwFallbackScenario : ISmokeTestScenario
{
    public string ScenarioId => "agent.failure-etw-fallback.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var root = Path.Combine(context.RuntimeRoot, "agent-failure-etw", "guest");
        var etw = Path.Combine(root, "etw-traces");
        Directory.CreateDirectory(etw);
        File.WriteAllText(Path.Combine(root, "guest-agent-run-status.json"), JsonSerializer.Serialize(new
        {
            state = "agent-failed",
            exitCode = 1,
            missingArtifacts = new[] { "events.json", "agent-summary.json" },
            stderrBytes = 19
        }));
        File.WriteAllText(Path.Combine(root, "agent.stderr.log"), "disk full\r\n");
        File.WriteAllText(Path.Combine(root, "agent.exit"), "1\r\n");
        File.WriteAllText(Path.Combine(etw, "sample.xml"), """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>1</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Execution ProcessID="4242" ThreadID="11"/></System><RenderingInfo><Task>Process</Task><Opcode>Start</Opcode><EventName>ProcessStart</EventName></RenderingInfo><EventData><Data Name="ProcessId">4242</Data><Data Name="ParentProcessId">4</Data><Data Name="ImageFileName">sample.exe</Data></EventData></Event><Event><System><Provider Name="Microsoft-Windows-Kernel-Image"/><EventID>5</EventID><TimeCreated SystemTime="2026-01-01T00:00:01Z"/><Execution ProcessID="4242" ThreadID="11"/></System><RenderingInfo><Task>Image</Task><Opcode>Load</Opcode></RenderingInfo><EventData><Data Name="ProcessId">4242</Data><Data Name="ImageFileName">payload.dll</Data></EventData></Event><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>2</EventID><TimeCreated SystemTime="2026-01-01T00:00:02Z"/><Execution ProcessID="4242" ThreadID="11"/></System><RenderingInfo><Task>Process</Task><Opcode>Stop</Opcode><EventName>ProcessExit</EventName></RenderingInfo><EventData><Data Name="ProcessId">4242</Data><Data Name="ExitStatus">1</Data></EventData></Event></Events>
            """);
        // tracerpt's kernel XML commonly serializes PIDs in hexadecimal. Keep
        // that path covered, and ensure an Image UnLoad opcode is not reduced
        // to the misleading image.load type.
        File.WriteAllText(Path.Combine(etw, "hex.xml"), """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Image"/><EventID>5</EventID><TimeCreated SystemTime="2026-01-01T00:00:03Z"/><Execution ProcessID="0x10" ThreadID="0x11"/></System><RenderingInfo><Task>Image</Task><Opcode>UnLoad</Opcode><EventName>Image</EventName></RenderingInfo><EventData><Data Name="ProcessId">0x10</Data><Data Name="ImageFileName">payload.dll</Data></EventData></Event></Events>
            """);

        var failures = GuestFailureArtifactImporter.Import(root);
        SmokeAssert.True(failures.Any(evt => evt.EventType == "agent.run.failed"), "Agent status/stderr/exit must produce a structured failure row.");
        var runbookPath = Path.Combine(context.RuntimeRoot, "agent-failure-etw", "runbook-execution.json");
        File.WriteAllText(runbookPath, JsonSerializer.Serialize(new SandboxRunbookExecutionResult
        {
            JobId = Guid.NewGuid(),
            Provider = VirtualizationProvider.VMware,
            TargetVmName = "sandbox-vm",
            Mode = SandboxRunbookExecutionMode.Live,
            Success = false,
            TotalSteps = 1,
            ExecutedSteps = 1,
            FailedStepIndex = 0,
            StartedAtUtc = DateTimeOffset.UtcNow,
            Duration = TimeSpan.FromSeconds(2),
            StepResults =
            [
                new SandboxRunbookStepExecutionResult
                {
                    StepIndex = 0,
                    StepId = "run-agent",
                    Title = "Start guest collector",
                    PowerShell = "Out-File",
                    Success = false,
                    ExitCode = 1,
                    StandardError = "Out-File : The disk was full.",
                    StartedAtUtc = DateTimeOffset.UtcNow,
                    Duration = TimeSpan.FromSeconds(1)
                }
            ]
        }));
        var runbookFailures = GuestFailureArtifactImporter.ImportRunbookFailure(runbookPath);
        SmokeAssert.True(runbookFailures.Count == 1 && runbookFailures[0].EventType == "agent.run.failed", "A failed run-agent step must create an Agent failure even when no guest markers exist.");
        var etwRows = EtwTraceXmlEventImporter.Import(root);
        SmokeAssert.True(etwRows.Any(evt => evt.EventType == "process.start"), "ETW fallback must retain process.start.");
        SmokeAssert.True(etwRows.Any(evt => evt.EventType == "image.load"), "ETW fallback must retain image.load.");
        SmokeAssert.True(etwRows.Any(evt => evt.EventType == "process.exit"), "ETW fallback must retain process.exit.");
        SmokeAssert.True(etwRows.All(evt => evt.Data.TryGetValue("captureSource", out var source) && source == "etw-live-tracerpt"), "ETW fallback rows must retain source provenance.");
        var hexUnload = etwRows.Single(evt => evt.EventType == "image.unload");
        SmokeAssert.True(hexUnload.ProcessId == 16 && hexUnload.ParentProcessId is null, "ETW fallback must parse hexadecimal process IDs from tracerpt XML.");

        var r0 = new SandboxEvent
        {
            EventType = "driver.file.created",
            Source = "driver",
            Path = @"C:\Users\Public\payload.bin",
            Data = { ["operation"] = "create", ["eventOrigin"] = "kernel-driver", ["schema"] = "ksword.sandbox.r0.event", ["producerCategory"] = "file" }
        };
        var classified = SampleCorrelationClassifier.Apply([r0, ..failures], @"C:\samples\sample.exe").Single(evt => evt.EventType == r0.EventType);
        SmokeAssert.True(classified.Data.TryGetValue("sampleCorrelation", out var correlation) && correlation == "unknown", "R0 file rows without a sample PID or cross-source anchor must remain unknown.");
        SmokeAssert.True(!string.Equals(correlation, "probable", StringComparison.OrdinalIgnoreCase), "Missing Agent output must not upgrade R0 file rows to probable.");

        var summary = CollectionHealthSummaryBuilder.Build([.. failures, .. runbookFailures, .. etwRows]);
        SmokeAssert.True(summary.AgentFailureRows > 0, "Structured Agent failure must enter CollectionHealth.");
        var sampled = ReportEventSampler.SampleForReport(failures);
        SmokeAssert.True(sampled.Events.Any(evt => evt.EventType == "agent.run.failed"), "Agent failure must survive report sampling ahead of the diagnostic quota.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Agent failures remain terminal diagnostics and ETW XML is imported as attributed-safe lifecycle evidence."
        });
    }
}
