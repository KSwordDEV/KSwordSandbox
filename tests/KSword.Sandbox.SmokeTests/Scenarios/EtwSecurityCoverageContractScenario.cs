using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Locks the source boundary for the ETW/Security fallback lane. The fixture
/// mirrors tracerpt output that omits RenderingInfo and emits one unnamed,
/// whitespace-delimited payload. It must remain a typed process row instead
/// of being silently discarded by host recovery. The source checks guard the
/// Security aliases and audit-policy state carried into later summaries.
/// </summary>
internal sealed class EtwSecurityCoverageContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest.etw-security-coverage.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var root = Path.Combine(context.RuntimeRoot, "etw-security-coverage", "guest", "etw-traces");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "payload-only.xml"), """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>99</EventID><Task>Process</Task><Opcode>Info</Opcode><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Execution ProcessID="4242" ThreadID="11"/></System><EventData><Data>ProcessId=4242 ParentProcessId=4 ImageFileName=payload-only.exe CommandLine=payload-only.exe</Data></EventData></Event></Events>
            """);
        File.WriteAllText(Path.Combine(root, "image-no-rendering.xml"), """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>5</EventID><Task>ImageLoad</Task><TimeCreated SystemTime="2026-01-01T00:00:01Z"/><Execution ProcessID="4242" ThreadID="11"/></System><EventData><Data Name="ProcessId">4242</Data><Data Name="ImageFileName">payload.dll</Data></EventData></Event></Events>
            """);

        var rows = EtwTraceXmlEventImporter.Import(Path.Combine(context.RuntimeRoot, "etw-security-coverage", "guest"));
        var row = rows.Single(evt => evt.EventType == "process.event");
        SmokeAssert.True(row.ProcessId == 4242 && row.ParentProcessId == 4 && row.ProcessName == "payload-only.exe",
            "ETW fallback must parse unnamed whitespace payloads without RenderingInfo.");
        SmokeAssert.True(row.CommandLine == "payload-only.exe",
            "ETW fallback must preserve command-line fields recovered from unnamed payloads.");
        SmokeAssert.True(rows.Any(evt => evt.EventType == "image.load" && evt.ProcessId == 4242 && evt.ProcessName == "payload.dll"),
            "ETW fallback must recover Kernel-Process ImageLoad from numeric EventID when RenderingInfo is absent.");
        SmokeAssert.True(row.Data.TryGetValue("captureSource", out var source) && source == "etw-live-tracerpt",
            "Recovered ETW rows must retain tracerpt provenance.");

        var securityProbe = File.ReadAllText(Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.Agent", "Collection", "SecurityEventLogProbe.cs"));
        SmokeAssert.True(securityProbe.Contains("CallerProcessId", StringComparison.Ordinal),
            "Security fallback correlation must consume CallerProcessId for token/privilege events.");
        SmokeAssert.True(securityProbe.Contains("zeroRowInterpretation", StringComparison.Ordinal) &&
            securityProbe.Contains("auditPolicyCoverageState", StringComparison.Ordinal),
            "Security query summaries must distinguish zero rows from disabled or unknown audit coverage.");

        var readinessSummary = new SandboxEvent
        {
            EventType = "etw_security.readiness.summary",
            Source = "etwSecurityReadiness",
            Timestamp = DateTimeOffset.UtcNow,
            Data =
            {
                ["collectionHealth"] = "true",
                ["nonbehavior"] = "true",
                ["readinessKind"] = "etw-security-r0-gap-map",
                ["surfaceKey"] = "token-adjustment",
                ["r0CoverageGap"] = "R0 does not decode token adjustment semantics.",
                ["fallbackSurfaceKeys"] = "process-handle-access;token-adjustment;thread-remote-thread;module-load"
            }
        };
        var sampled = ReportEventSampler.SampleForReport(
            [readinessSummary],
            new ReportEventSamplingOptions { MaxInlineEvents = 1, MaxDiagnosticEvents = 0 });
        SmokeAssert.True(
            sampled.Events.Any(evt => evt.EventType == "etw_security.readiness.summary"),
            "ETW Security readiness summary must remain in report sampling even with no diagnostic quota.");
        var retained = sampled.Events.Single(evt => evt.EventType == "etw_security.readiness.summary");
        SmokeAssert.True(
            retained.Data.TryGetValue("surfaceKey", out var surfaceKey) && surfaceKey == "token-adjustment" &&
            retained.Data.ContainsKey("r0CoverageGap") && retained.Data.ContainsKey("fallbackSurfaceKeys"),
            "ETW Security readiness matrix fields must survive report sanitization alongside the summary row.");

        var renderer = new HtmlReportRenderer();
        var lifecycleReport = new AnalysisReport
        {
            JobId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
            Sample = new SampleIdentity
            {
                FileName = "etw-contract.exe",
                FullPath = @"C:\Samples\etw-contract.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd"
            },
            Events =
            [
                new SandboxEvent
                {
                    EventType = "etw_live.started",
                    Source = "etwLive",
                    Timestamp = DateTimeOffset.UtcNow,
                    Data =
                    {
                        ["captureState"] = "started",
                        ["etwSessionStarted"] = "true",
                        ["etwLiveCaptureEnabled"] = "true"
                    }
                },
                new SandboxEvent
                {
                    EventType = "etw_live.captured",
                    Source = "etwLive",
                    Timestamp = DateTimeOffset.UtcNow.AddSeconds(1),
                    Data =
                    {
                        ["captureState"] = "captured",
                        ["status"] = "captured",
                        ["etwSessionStarted"] = "false",
                        ["etwLiveCaptureEnabled"] = "true"
                    }
                },
                new SandboxEvent
                {
                    EventType = "etw_security.surface.readiness",
                    Source = "etwSecurityReadiness",
                    Timestamp = DateTimeOffset.UtcNow.AddSeconds(2),
                    Data =
                    {
                        ["surfaceKey"] = "process-access",
                        ["etwSessionStarted"] = "false",
                        ["etwLiveCaptureEnabled"] = "false",
                        ["collectionHealth"] = "true",
                        ["nonbehavior"] = "true"
                    }
                }
            ]
        };
        var lifecycleHtml = renderer.RenderEnglish(lifecycleReport, []);
        SmokeAssert.True(
            !lifecycleHtml.Contains("ETW live collection gap:", StringComparison.Ordinal),
            "Successful ETW started/captured rows, including captured etwSessionStarted=false after stop, must not raise a live-capture gap.");
        SmokeAssert.True(
            lifecycleHtml.Contains("ETW/Security surface subscription", StringComparison.Ordinal) &&
            lifecycleHtml.Contains("not subscribed", StringComparison.Ordinal),
            "ETW Security surface readiness must expose a compact not-subscribed coverage gap separately from live ETW capture.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "ETW host recovery preserves payload-only rows and Security fallback exposes actor PID and audit-policy coverage boundaries."
        });
    }
}
