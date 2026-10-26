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
        File.WriteAllText(Path.Combine(root, "guest-output-preflight.json"), JsonSerializer.Serialize(new
        {
            schema = "ksword.guest-output-preflight.v1",
            state = "insufficient-space",
            outputRoot = root,
            volumeRoot = "C:\\",
            availableFreeBytes = 0L,
            requiredFreeBytes = 134217728L,
            reserveSource = "driver.r0CollectorMinFreeOutputBytes",
            checkedAtUtc = DateTimeOffset.UtcNow.ToString("O")
        }));
        // The CLR preflight is also written to the host job root. Verify that
        // recovery from the guest folder finds the sibling host diagnostic and
        // keeps a blocked sample out of a reassuring clean result.
        File.WriteAllText(Path.Combine(context.RuntimeRoot, "agent-failure-etw", "sample-runtime-preflight.json"), JsonSerializer.Serialize(new
        {
            schema = "ksword.sample-runtime-preflight.v1",
            state = "sample-runtime-blocked",
            failureCode = "sample-runtime-blocked-netfx3-disabled",
            sampleFileName = "legacy-sample.exe",
            managedClrDetected = true,
            legacyClrDetected = true,
            guestSamplePresent = true,
            guestNetFx3State = "Disabled",
            sampleExecuted = false
        }));
        File.WriteAllText(Path.Combine(etw, "sample.xml"), """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>1</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Execution ProcessID="4242" ThreadID="11"/></System><RenderingInfo><Task>Process</Task><Opcode>Start</Opcode><EventName>ProcessStart</EventName></RenderingInfo><EventData><Data Name="ProcessId">4242</Data><Data Name="ParentProcessId">4</Data><Data Name="ImageFileName">sample.exe</Data></EventData></Event><Event><System><Provider Name="Microsoft-Windows-Kernel-Image"/><EventID>5</EventID><TimeCreated SystemTime="2026-01-01T00:00:01Z"/><Execution ProcessID="4242" ThreadID="11"/></System><RenderingInfo><Task>Image</Task><Opcode>Load</Opcode></RenderingInfo><EventData><Data Name="ProcessId">4242</Data><Data Name="ImageFileName">payload.dll</Data></EventData></Event><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>2</EventID><TimeCreated SystemTime="2026-01-01T00:00:02Z"/><Execution ProcessID="4242" ThreadID="11"/></System><RenderingInfo><Task>Process</Task><Opcode>Stop</Opcode><EventName>ProcessExit</EventName></RenderingInfo><EventData><Data Name="ProcessId">4242</Data><Data Name="ExitStatus">1</Data></EventData></Event></Events>
            """);
        // tracerpt's kernel XML commonly serializes PIDs in hexadecimal. Keep
        // that path covered, and ensure an Image UnLoad opcode is not reduced
        // to the misleading image.load type.
        File.WriteAllText(Path.Combine(etw, "hex.xml"), """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Image"/><EventID>5</EventID><TimeCreated SystemTime="2026-01-01T00:00:03Z"/><Execution ProcessID="0x10" ThreadID="0x11"/></System><RenderingInfo><Task>Image</Task><Opcode>UnLoad</Opcode><EventName>Image</EventName></RenderingInfo><EventData><Data Name="ProcessId">0x10</Data><Data Name="ImageFileName">payload.dll</Data></EventData></Event></Events>
            """);
        // tracerpt may omit RenderingInfo for a kernel row. The fallback
        // importer must use the payload's process/lineage shape just like the
        // live decoder, otherwise this row is reduced to etw.event and lost.
        File.WriteAllText(Path.Combine(etw, "payload-only.xml"), """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>99</EventID><TimeCreated SystemTime="2026-01-01T00:00:04Z"/><Execution ProcessID="4242" ThreadID="11"/></System><EventData><Data Name="ProcessId">4242</Data><Data Name="ParentProcessId">4</Data><Data Name="ImageFileName">payload-only.exe</Data></EventData></Event></Events>
            """);

        var failures = GuestFailureArtifactImporter.Import(root);
        SmokeAssert.True(failures.Any(evt => evt.EventType == "agent.run.failed"), "Agent status/stderr/exit must produce a structured failure row.");

        // Sample-tree stderr isolation: newer guest agents redirect sample
        // stderr into sample-stderr.log. Noise that only appears in the sample
        // lane (or leaked into agent.stderr.log but is also captured in the
        // sample lane) must not fail an otherwise healthy run, while genuine
        // agent diagnostics and legacy payloads without sample-stderr.log keep
        // failing. This reproduces the thanos 1ccb3e1d live misjudgment where
        // ~40 inherited-handle "服务名无效" NET STOP lines in agent.stderr.log
        // failed a run whose agent had state=completed, exit 0, and a full
        // events.json import.
        var noiseLines = string.Concat(Enumerable.Repeat("服务名无效。\r\n", 40)) + "taskkill /F /PID 4242: 成功。\r\n";
        string CreateHealthyGuestFixture(string name, bool withSampleLane, bool withAgentDiagnostic)
        {
            var fixtureRoot = Path.Combine(context.RuntimeRoot, "agent-failure-etw", name);
            Directory.CreateDirectory(fixtureRoot);
            File.WriteAllText(Path.Combine(fixtureRoot, "guest-agent-run-status.json"), JsonSerializer.Serialize(new
            {
                state = "completed",
                exitCode = 0,
                stdoutBytes = 0,
                stderrBytes = noiseLines.Length
            }));
            File.WriteAllText(Path.Combine(fixtureRoot, "agent.exit"), "0\r\n");
            File.WriteAllText(Path.Combine(fixtureRoot, "events.json"), "[]");
            File.WriteAllText(Path.Combine(fixtureRoot, "agent-summary.json"), JsonSerializer.Serialize(new { eventCount = 0 }));
            File.WriteAllText(Path.Combine(fixtureRoot, "agent.stderr.log"), noiseLines);
            if (withSampleLane)
            {
                File.WriteAllText(Path.Combine(fixtureRoot, "sample-stderr.log"), noiseLines);
            }

            if (withAgentDiagnostic)
            {
                File.AppendAllText(Path.Combine(fixtureRoot, "agent.stderr.log"), "guest-output-failure artifact=events.json type=IOException\r\n");
            }

            return fixtureRoot;
        }

        var isolatedNoiseRoot = CreateHealthyGuestFixture("guest-noise-isolated", withSampleLane: true, withAgentDiagnostic: false);
        var isolatedNoise = GuestFailureArtifactImporter.Import(isolatedNoiseRoot);
        SmokeAssert.True(isolatedNoise.All(evt => evt.EventType != "agent.run.failed"),
            "Sample-tree stderr noise captured in sample-stderr.log must not fail a completed agent run with exit 0 and complete artifacts.");

        var leakedNoiseRoot = CreateHealthyGuestFixture("guest-noise-leaked", withSampleLane: true, withAgentDiagnostic: true);
        var leakedNoise = GuestFailureArtifactImporter.Import(leakedNoiseRoot);
        var leakedRow = leakedNoise.SingleOrDefault(evt => evt.EventType == "agent.run.failed");
        SmokeAssert.True(leakedRow is not null, "A genuine agent diagnostic alongside sample noise must still fail the run.");
        SmokeAssert.True(leakedRow!.Data["stderrSampleAttributed"] == "false" && leakedRow.Data["stderrPreview"].Contains("guest-output-failure", StringComparison.Ordinal),
            "The failure preview must attribute stderr to the agent diagnostic line, not the sample noise lines.");
        SmokeAssert.True(!leakedRow.Data["stderrPreview"].Contains("服务名无效", StringComparison.Ordinal),
            "Sample-attributable lines must be filtered out of the agent stderr preview.");

        var legacyNoiseRoot = CreateHealthyGuestFixture("guest-noise-legacy", withSampleLane: false, withAgentDiagnostic: false);
        var legacyNoise = GuestFailureArtifactImporter.Import(legacyNoiseRoot);
        SmokeAssert.True(legacyNoise.Any(evt => evt.EventType == "agent.run.failed"),
            "Legacy payloads without sample-stderr.log must keep the backward-compatible rule where non-empty agent stderr fails the run.");        var preflightFailure = failures.Single(evt => evt.EventType == "guest.output.preflight.failed");
        SmokeAssert.True(preflightFailure.Data["outputSpacePreflightFailure"] == "true", "Low guest output space must remain a distinct collection-health failure.");
        SmokeAssert.True(preflightFailure.Data["availableFreeBytes"] == "0" && preflightFailure.Data["requiredFreeBytes"] == "134217728", "Output preflight must preserve measured and required free-space diagnostics.");
        var sampleRuntimeFailure = failures.Single(evt => evt.EventType == "sample.runtime.preflight.failed");
        SmokeAssert.True(sampleRuntimeFailure.Data["sampleRuntimePreflight"] == "true" && sampleRuntimeFailure.Data["sampleRuntimeFailureCode"] == "sample-runtime-blocked-netfx3-disabled", "CLR preflight failure must remain a collection-health diagnostic.");
        SmokeAssert.True(sampleRuntimeFailure.Data["sampleExecuted"] == "false" && sampleRuntimeFailure.Data["guestNetFx3State"] == "Disabled", "CLR preflight diagnostic must preserve non-execution and guest framework state.");
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
        var payloadOnly = etwRows.Single(evt => evt.EventType == "process.event");
        SmokeAssert.True(payloadOnly.ProcessId == 4242 && payloadOnly.ParentProcessId == 4 && payloadOnly.ProcessName == "payload-only.exe",
            "ETW fallback must preserve process-shaped rows when tracerpt omits RenderingInfo.");

        // A captured ETL with parsedEventCount=0 is a collection gap even if
        // the raw XML fallback happens to contain rows. The shared import path
        // must emit one explicit health diagnostic, while a successfully
        // decoded stream must suppress XML fallback to avoid duplicate rows.
        var zeroSummary = new SandboxEvent
        {
            EventType = "etw_live.captured",
            Source = "etwLive",
            Path = Path.Combine(etw, "sample.etl"),
            Data =
            {
                ["captureSource"] = "etw-live-tracerpt",
                ["parsedEventCount"] = "0",
                ["decodedEventCount"] = "0",
                ["semanticRowsAvailable"] = "false",
                ["etlDecodeRequired"] = "true",
                ["traceArtifactPath"] = Path.Combine(etw, "sample.etl")
            }
        };
        var zeroFallback = EtwTraceXmlEventImporter.ImportFallbackAndCoverage([zeroSummary], root);
        SmokeAssert.True(zeroFallback.Any(evt =>
                evt.EventType == "etw_live.decode_failed" &&
                evt.Data.TryGetValue("failureType", out var failureType) &&
                failureType == "etwParsedEventCountZero"),
            "ETW parsedEventCount=0 must remain an explicit collection diagnostic.");

        var decodedSummary = new SandboxEvent
        {
            EventType = "etw_live.captured",
            Source = "etwLive",
            Data =
            {
                ["captureSource"] = "etw-live-tracerpt",
                ["semanticRowsAvailable"] = "true",
                ["parsedEventCount"] = "1"
            }
        };
        var decodedRow = new SandboxEvent
        {
            EventType = "process.start",
            Source = "etwLive",
            Data =
            {
                ["captureSource"] = "etw-live-tracerpt",
                ["rawDecoded"] = "true"
            }
        };
        var noDuplicateFallback = EtwTraceXmlEventImporter.ImportFallbackAndCoverage([decodedSummary, decodedRow], root);
        SmokeAssert.True(noDuplicateFallback.Count == 0,
            "ETW XML fallback must not run after decoded semantic rows already exist.");

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

        // agent.exit is normally lifecycle noise, but a nonzero exit code is
        // a terminal collection failure and must be classified before the
        // routine lifecycle filter.
        var failedExit = ReportEventSampler.SampleForReport(
        [
            new SandboxEvent
            {
                EventType = "agent.exit",
                Timestamp = DateTimeOffset.UtcNow,
                Source = "guest",
                Data = { ["exitCode"] = "1" }
            },
            new SandboxEvent
            {
                EventType = "agent.stop",
                Timestamp = DateTimeOffset.UtcNow.AddMilliseconds(1),
                Source = "guest"
            }
        ],
        new ReportEventSamplingOptions { MaxInlineEvents = 1, MaxDiagnosticEvents = 0 });
        SmokeAssert.True(failedExit.Events.Any(evt => evt.EventType == "agent.exit"),
            "Nonzero agent.exit must remain visible as failure evidence.");
        SmokeAssert.True(!failedExit.Events.Any(evt => evt.EventType == "agent.stop"),
            "Routine agent.stop should remain policy-excluded.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Agent failures remain terminal diagnostics and ETW XML is imported as attributed-safe lifecycle evidence."
        });
    }
}
