using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the static WebUI live telemetry contract without starting a VM.
/// Inputs are repository paths from SmokeTestContext; processing reads source
/// and documentation files for required routes and fields; the scenario returns
/// pass/fail metadata.
/// </summary>
internal sealed class LiveTelemetryContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "web.live-telemetry.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var webProgram = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Program.cs");
        var executionModels = ReadRepositoryText(context, "src", "KSword.Sandbox.Abstractions", "ExecutionModels.cs");
        var liveTelemetryDoc = ReadRepositoryText(context, "docs", "live-telemetry-pipeline.md");
        var hyperVRunnerDoc = ReadRepositoryText(context, "docs", "hyperv-runner.md");

        RequireContains(webProgram, "\"/api/jobs/{jobId:guid}/events/live\"", "Web source should map the polling live-events route.");
        RequireContains(webProgram, "\"/api/jobs/{jobId:guid}/events/stream\"", "Web source should map the SSE live-events route.");
        RequireContains(webProgram, "int? offset", "Web source should accept offset for live telemetry.");
        RequireContains(webProgram, "int? take", "Web source should accept take for live telemetry.");
        RequireContains(webProgram, "int? intervalMs", "Web source should accept intervalMs for SSE telemetry.");
        RequireContains(webProgram, "text/event-stream", "SSE route should return an event-stream content type.");
        RequireContains(webProgram, "event: snapshot", "SSE route should emit snapshot frames.");

        RequireContains(executionModels, "StandardOutput", "Runbook execution model should preserve stdout.");
        RequireContains(executionModels, "StandardError", "Runbook execution model should preserve stderr.");
        RequireContains(executionModels, "ExitCode", "Runbook execution model should preserve exit code.");
        RequireContains(executionModels, "Duration", "Runbook execution model should preserve duration.");
        RequireContains(executionModels, "Message", "Runbook execution model should preserve error/message text.");

        RequireContains(liveTelemetryDoc, "/api/jobs/{jobId}/events/stream", "Live telemetry doc should describe the SSE route.");
        RequireContains(liveTelemetryDoc, "/api/jobs/{jobId}/events/live", "Live telemetry doc should describe polling fallback.");
        RequireContains(liveTelemetryDoc, "offset", "Live telemetry doc should describe offset behavior.");
        RequireContains(liveTelemetryDoc, "take", "Live telemetry doc should describe take behavior.");
        RequireContains(liveTelemetryDoc, "intervalMs", "Live telemetry doc should describe intervalMs behavior.");

        RequireContains(hyperVRunnerDoc, "stdout", "Hyper-V runner doc should describe stdout UX.");
        RequireContains(hyperVRunnerDoc, "stderr", "Hyper-V runner doc should describe stderr UX.");
        RequireContains(hyperVRunnerDoc, "exit code", "Hyper-V runner doc should describe exit code UX.");
        RequireContains(hyperVRunnerDoc, "duration", "Hyper-V runner doc should describe duration UX.");
        RequireContains(hyperVRunnerDoc, "error", "Hyper-V runner doc should describe error UX.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Live telemetry source and documentation contracts are present."
        });
    }

    /// <summary>
    /// Reads a repository file as text.
    /// Inputs are the smoke context and relative path segments; processing joins
    /// the path under RepositoryRoot and reads the file; the method returns the
    /// complete file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        var path = Path.Combine(allSegments);
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires that a text block contains a literal value.
    /// Inputs are text, expected literal, and assertion message; processing uses
    /// ordinal substring matching; the method returns no value on success.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
