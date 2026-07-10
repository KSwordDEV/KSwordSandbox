using System.Net;
using System.Text.Json;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the live telemetry SSE contract and polling fallback shape.
/// Inputs are repository paths plus optional KSWORD_SMOKE_BASE_URL and
/// KSWORD_SMOKE_JOB_ID environment variables; processing checks local contract
/// files and can probe an already-running Web API; the scenario returns
/// pass/fail metadata without creating jobs or build artifacts.
/// </summary>
internal sealed class LiveTelemetryStreamContractScenario : ISmokeTestScenario
{
    private const string BaseUrlEnvironmentVariable = "KSWORD_SMOKE_BASE_URL";
    private const string JobIdEnvironmentVariable = "KSWORD_SMOKE_JOB_ID";
    private const string ExpectedStreamRoute = "/api/jobs/{jobId}/events/stream";
    private const string PollingFallbackRoute = "/api/jobs/{jobId}/events/live";

    public string ScenarioId => "live-telemetry.stream-contract";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        AssertLocalContractFiles(context.RepositoryRoot);

        var baseUrl = Environment.GetEnvironmentVariable(BaseUrlEnvironmentVariable);
        var jobIdText = Environment.GetEnvironmentVariable(JobIdEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(baseUrl) || string.IsNullOrWhiteSpace(jobIdText))
        {
            return new SmokeTestResult
            {
                ScenarioId = ScenarioId,
                Passed = true,
                Message = "Live telemetry SSE contract files are present; HTTP probe skipped because KSWORD_SMOKE_BASE_URL or KSWORD_SMOKE_JOB_ID is not set."
            };
        }

        SmokeAssert.True(Guid.TryParse(jobIdText, out var jobId), $"Environment variable {JobIdEnvironmentVariable} is not a valid GUID.");

        using var httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        var streamProbe = await ProbeStreamHeadersAsync(httpClient, baseUrl, jobId, cancellationToken);
        if (streamProbe.Succeeded)
        {
            return new SmokeTestResult
            {
                ScenarioId = ScenarioId,
                Passed = true,
                Message = "SSE stream endpoint returned text/event-stream."
            };
        }

        SmokeAssert.True(streamProbe.FallbackEligible, streamProbe.Message);
        await ProbePollingFallbackAsync(httpClient, baseUrl, jobId, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"SSE stream probe fell back to polling successfully: {streamProbe.Message}"
        };
    }

    /// <summary>
    /// Checks that repository files describe the expected SSE and fallback
    /// routes. The input is the repository root, processing reads only the
    /// allowed docs/script plus route text, and the method returns no value.
    /// </summary>
    private static void AssertLocalContractFiles(string repositoryRoot)
    {
        var liveTelemetryDoc = Path.Combine(repositoryRoot, "docs", "live-telemetry-pipeline.md");
        var hyperVRunnerDoc = Path.Combine(repositoryRoot, "docs", "hyperv-runner.md");
        var validationScript = Path.Combine(repositoryRoot, "scripts", "Test-LiveTelemetryFramework.ps1");
        var programFile = Path.Combine(repositoryRoot, "src", "KSword.Sandbox.Web", "Program.cs");

        SmokeAssert.True(File.Exists(liveTelemetryDoc), "Live telemetry pipeline doc is missing.");
        SmokeAssert.True(File.Exists(hyperVRunnerDoc), "Hyper-V runner doc is missing.");
        SmokeAssert.True(File.Exists(validationScript), "Live telemetry validation script is missing.");
        SmokeAssert.True(File.Exists(programFile), "Web Program.cs is missing; route presence cannot be inspected.");

        var liveDocText = File.ReadAllText(liveTelemetryDoc);
        var hyperVDocText = File.ReadAllText(hyperVRunnerDoc);
        var scriptText = File.ReadAllText(validationScript);
        var programText = File.ReadAllText(programFile);

        SmokeAssert.True(liveDocText.Contains(ExpectedStreamRoute, StringComparison.Ordinal), "Live telemetry doc does not describe the expected SSE route.");
        SmokeAssert.True(liveDocText.Contains(PollingFallbackRoute, StringComparison.Ordinal), "Live telemetry doc does not describe polling fallback.");
        SmokeAssert.True(liveDocText.Contains("text/event-stream", StringComparison.Ordinal), "Live telemetry doc does not define the SSE media type.");
        SmokeAssert.True(hyperVDocText.Contains("-UsePollingFallback", StringComparison.Ordinal), "Hyper-V runner doc does not show fallback validation usage.");
        SmokeAssert.True(scriptText.Contains("/events/stream", StringComparison.Ordinal), "Validation script does not probe the SSE route.");
        SmokeAssert.True(scriptText.Contains("/events/live", StringComparison.Ordinal), "Validation script does not probe polling fallback.");
        SmokeAssert.True(programText.Contains("/events/live", StringComparison.Ordinal), "Current Web API source does not expose the polling endpoint used as fallback.");
    }

    /// <summary>
    /// Probes response headers for the expected SSE route. Inputs are an HTTP
    /// client, API base URL, job ID, and cancellation token; processing sends a
    /// header-only SSE request; the method returns whether stream validation
    /// passed or whether fallback validation is acceptable.
    /// </summary>
    private static async Task<StreamProbeResult> ProbeStreamHeadersAsync(HttpClient httpClient, string baseUrl, Guid jobId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildUri(baseUrl, $"/api/jobs/{jobId:D}/events/stream?offset=0"));
        request.Headers.Accept.ParseAdd("text/event-stream");
        request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true };

        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var statusCode = response.StatusCode;
            var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            if (response.IsSuccessStatusCode && string.Equals(contentType, "text/event-stream", StringComparison.OrdinalIgnoreCase))
            {
                return new StreamProbeResult(true, false, "SSE stream endpoint is implemented.");
            }

            var fallbackEligible = statusCode is HttpStatusCode.NotFound
                or HttpStatusCode.MethodNotAllowed
                or HttpStatusCode.NotImplemented
                || !string.Equals(contentType, "text/event-stream", StringComparison.OrdinalIgnoreCase);
            return new StreamProbeResult(false, fallbackEligible, $"SSE stream returned HTTP {(int)statusCode} with content type '{contentType}'.");
        }
        catch (HttpRequestException ex)
        {
            return new StreamProbeResult(false, true, $"SSE stream request failed before headers: {ex.Message}");
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            return new StreamProbeResult(false, true, $"SSE stream request timed out before headers: {ex.Message}");
        }
    }

    /// <summary>
    /// Probes the implemented polling fallback endpoint. Inputs are an HTTP
    /// client, API base URL, job ID, and cancellation token; processing parses
    /// one JSON snapshot and checks cursor fields; the method returns no value.
    /// </summary>
    private static async Task ProbePollingFallbackAsync(HttpClient httpClient, string baseUrl, Guid jobId, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(BuildUri(baseUrl, $"/api/jobs/{jobId:D}/events/live?offset=0&take=1"), cancellationToken);
        SmokeAssert.True(response.IsSuccessStatusCode, $"Polling fallback returned HTTP {(int)response.StatusCode}.");

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        var root = document.RootElement;

        SmokeAssert.True(root.TryGetProperty("jobId", out var responseJobId) && Guid.Parse(responseJobId.GetString() ?? string.Empty) == jobId, "Polling fallback response jobId mismatch.");
        SmokeAssert.True(root.TryGetProperty("retrievedAt", out _), "Polling fallback response is missing retrievedAt.");
        SmokeAssert.True(root.TryGetProperty("totalEvents", out _), "Polling fallback response is missing totalEvents.");
        SmokeAssert.True(root.TryGetProperty("nextOffset", out _), "Polling fallback response is missing nextOffset.");
        SmokeAssert.True(root.TryGetProperty("hasMore", out _), "Polling fallback response is missing hasMore.");
        SmokeAssert.True(root.TryGetProperty("sources", out var sources) && sources.ValueKind == JsonValueKind.Array, "Polling fallback response is missing sources array.");
        SmokeAssert.True(root.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array, "Polling fallback response is missing events array.");
    }

    /// <summary>
    /// Builds an absolute URI for one API route. Inputs are the base URL and
    /// route, processing uses System.Uri combination rules, and the method
    /// returns the absolute URI to request.
    /// </summary>
    private static Uri BuildUri(string baseUrl, string route)
    {
        return new Uri(new Uri(baseUrl), route);
    }

    /// <summary>
    /// Stores the result of probing the expected SSE route. Inputs are probe
    /// status values, processing stores immutable data, and the record returns
    /// success/fallback metadata to the scenario runner.
    /// </summary>
    private sealed record StreamProbeResult(bool Succeeded, bool FallbackEligible, string Message);
}
