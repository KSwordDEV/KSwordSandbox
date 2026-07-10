using System.Net;
using System.Text;
using System.Text.Json;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the optional runtime WebUI smoke contract. Inputs are repository
/// files plus optional KSWORD_SMOKE_BASE_URL and KSWORD_SMOKE_JOB_ID
/// environment variables; processing always checks static route/documentation
/// gates and, when both variables are set, probes an already-running Web host
/// without launching a browser; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class WebUiRuntimeSmokeContractScenario : ISmokeTestScenario
{
    private const string BaseUrlEnvironmentVariable = "KSWORD_SMOKE_BASE_URL";
    private const string JobIdEnvironmentVariable = "KSWORD_SMOKE_JOB_ID";

    public string ScenarioId => "webui.runtime-smoke.contract";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        AssertStaticRuntimeSmokeContract(context);

        if (!TryGetRuntimeTarget(out var baseUri, out var jobId, out var skipMessage))
        {
            return new SmokeTestResult
            {
                ScenarioId = ScenarioId,
                Passed = true,
                Message = skipMessage
            };
        }

        using var httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };

        await ProbeLiveEndpointAsync(httpClient, baseUri, jobId, cancellationToken);
        await ProbeServedReportLinkAsync(httpClient, baseUri, jobId, cancellationToken);
        await ProbeManualGuestImportEndpointAsync(httpClient, baseUri, jobId, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Runtime WebUI smoke checked live events, served report link, and manual guest import endpoint."
        };
    }

    /// <summary>
    /// Checks repository text for the runtime WebUI smoke surface.
    /// Inputs are the smoke context; processing reads Web source, dashboard,
    /// documentation, and validation script text; the method returns no value
    /// and throws if the static contract is incomplete.
    /// </summary>
    private static void AssertStaticRuntimeSmokeContract(SmokeTestContext context)
    {
        var program = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Program.cs");
        var dashboard = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "DashboardExperiencePage.cs");
        var doc = ReadRepositoryText(context, "docs", "webui-framework.md");
        var script = ReadRepositoryText(context, "scripts", "Test-LiveTelemetryFramework.ps1");

        RequireContains(program, "\"/api/jobs/{jobId:guid}/events/live\"", "Web source should expose the live-event polling endpoint.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/report/html\"", "Web source should expose the served HTML report endpoint.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/guest-events/import\"", "Web source should expose the manual guest import endpoint.");
        RequireContains(program, "GuestEventImportRequest", "Web source should keep a typed guest import request body.");
        RequireContains(program, "EventsPath", "Guest import request should accept an optional explicit events path.");

        RequireContains(dashboard, "Open served HTML report", "Dashboard should render the served report link.");
        RequireContains(dashboard, "Open local file:// report", "Dashboard should render the local report fallback link.");
        RequireContains(dashboard, "guestImportPath", "Dashboard should render a manual guest import path input.");
        RequireContains(dashboard, "guest-events/import", "Dashboard should call the manual guest import endpoint.");
        RequireContains(dashboard, "JSON.stringify(explicitPath ? { eventsPath: explicitPath } : {})", "Dashboard should send optional manual import path JSON.");

        RequireContains(doc, BaseUrlEnvironmentVariable, "WebUI framework doc should describe the runtime smoke base URL environment variable.");
        RequireContains(doc, JobIdEnvironmentVariable, "WebUI framework doc should describe the runtime smoke job ID environment variable.");
        RequireContains(doc, "/api/jobs/{jobId}/events/live", "WebUI framework doc should describe the live endpoint smoke probe.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html", "WebUI framework doc should describe the served report smoke probe.");
        RequireContains(doc, "/api/jobs/{jobId}/guest-events/import", "WebUI framework doc should describe the manual guest import smoke probe.");
        RequireContains(doc, "static gate", "WebUI framework doc should describe the static gate fallback.");

        RequireContains(script, BaseUrlEnvironmentVariable, "Live telemetry framework script should accept the runtime smoke base URL environment variable.");
        RequireContains(script, JobIdEnvironmentVariable, "Live telemetry framework script should accept the runtime smoke job ID environment variable.");
        RequireContains(script, "/report/html", "Live telemetry framework script should probe the served report link.");
        RequireContains(script, "/guest-events/import", "Live telemetry framework script should probe the manual guest import endpoint.");
    }

    /// <summary>
    /// Resolves optional runtime smoke inputs from environment variables.
    /// Inputs are process environment values; processing validates the base URL
    /// and job ID when either value is present; the method returns true when a
    /// runtime target is complete, otherwise false with a skip message.
    /// </summary>
    private static bool TryGetRuntimeTarget(out Uri baseUri, out Guid jobId, out string message)
    {
        baseUri = new Uri("http://localhost/");
        jobId = Guid.Empty;

        var baseUrl = Environment.GetEnvironmentVariable(BaseUrlEnvironmentVariable);
        var jobIdText = Environment.GetEnvironmentVariable(JobIdEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(baseUrl) && string.IsNullOrWhiteSpace(jobIdText))
        {
            message = $"Runtime WebUI smoke static gate passed; HTTP probe skipped because {BaseUrlEnvironmentVariable} and {JobIdEnvironmentVariable} are not set.";
            return false;
        }

        SmokeAssert.True(!string.IsNullOrWhiteSpace(baseUrl), $"Environment variable {BaseUrlEnvironmentVariable} is required when {JobIdEnvironmentVariable} is set.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(jobIdText), $"Environment variable {JobIdEnvironmentVariable} is required when {BaseUrlEnvironmentVariable} is set.");
        SmokeAssert.True(Uri.TryCreate(baseUrl!.TrimEnd('/') + "/", UriKind.Absolute, out var parsedBaseUri), $"Environment variable {BaseUrlEnvironmentVariable} is not an absolute URL.");
        SmokeAssert.True(Guid.TryParse(jobIdText, out var parsedJobId), $"Environment variable {JobIdEnvironmentVariable} is not a valid GUID.");

        baseUri = parsedBaseUri!;
        jobId = parsedJobId;
        message = string.Empty;
        return true;
    }

    /// <summary>
    /// Probes the live polling endpoint.
    /// Inputs are an HTTP client, base URI, job ID, and cancellation token;
    /// processing requests one raw-event page and validates JSON cursor fields;
    /// the method returns no value on success.
    /// </summary>
    private static async Task ProbeLiveEndpointAsync(HttpClient httpClient, Uri baseUri, Guid jobId, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(BuildUri(baseUri, $"/api/jobs/{jobId:D}/events/live?offset=0&take=1"), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        SmokeAssert.True(response.IsSuccessStatusCode, $"Live endpoint returned HTTP {(int)response.StatusCode}: {Truncate(body)}");

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        SmokeAssert.True(root.TryGetProperty("jobId", out var responseJobId) && Guid.Parse(responseJobId.GetString() ?? string.Empty) == jobId, "Live endpoint response jobId mismatch.");
        SmokeAssert.True(root.TryGetProperty("retrievedAt", out _), "Live endpoint response is missing retrievedAt.");
        SmokeAssert.True(root.TryGetProperty("totalEvents", out _), "Live endpoint response is missing totalEvents.");
        SmokeAssert.True(root.TryGetProperty("nextOffset", out _), "Live endpoint response is missing nextOffset.");
        SmokeAssert.True(root.TryGetProperty("hasMore", out _), "Live endpoint response is missing hasMore.");
        SmokeAssert.True(root.TryGetProperty("sources", out var sources) && sources.ValueKind == JsonValueKind.Array, "Live endpoint response is missing sources array.");
        SmokeAssert.True(root.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array, "Live endpoint response is missing events array.");
    }

    /// <summary>
    /// Probes the safe served report link.
    /// Inputs are an HTTP client, base URI, job ID, and cancellation token;
    /// processing requests the server-owned report.html endpoint and validates
    /// HTML response shape; the method returns no value on success.
    /// </summary>
    private static async Task ProbeServedReportLinkAsync(HttpClient httpClient, Uri baseUri, Guid jobId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildUri(baseUri, $"/api/jobs/{jobId:D}/report/html"));
        request.Headers.Accept.ParseAdd("text/html");

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;

        SmokeAssert.True(response.IsSuccessStatusCode, $"Served report link returned HTTP {(int)response.StatusCode}: {Truncate(body)}");
        SmokeAssert.True(string.Equals(mediaType, "text/html", StringComparison.OrdinalIgnoreCase), $"Served report link should return text/html, not '{mediaType}'.");
        SmokeAssert.True(body.Contains("<html", StringComparison.OrdinalIgnoreCase), "Served report link should return an HTML document.");
    }

    /// <summary>
    /// Probes the manual guest import endpoint without importing real artifacts.
    /// Inputs are an HTTP client, base URI, job ID, and cancellation token;
    /// processing posts an explicit missing events path and expects the endpoint
    /// to reject it with a validation error instead of 404/405; the method
    /// returns no value on success.
    /// </summary>
    private static async Task ProbeManualGuestImportEndpointAsync(HttpClient httpClient, Uri baseUri, Guid jobId, CancellationToken cancellationToken)
    {
        var missingEventsPath = Path.Combine(Path.GetTempPath(), $"ksword-smoke-missing-{Guid.NewGuid():N}.events.json");
        SmokeAssert.True(!File.Exists(missingEventsPath), "Manual guest import smoke path unexpectedly exists.");

        using var request = new HttpRequestMessage(HttpMethod.Post, BuildUri(baseUri, $"/api/jobs/{jobId:D}/guest-events/import"))
        {
            Content = new StringContent(JsonSerializer.Serialize(new { eventsPath = missingEventsPath }), Encoding.UTF8, "application/json")
        };
        using var response = await httpClient.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        SmokeAssert.True(response.StatusCode == HttpStatusCode.BadRequest, $"Manual guest import endpoint should reject a missing explicit path with HTTP 400; got HTTP {(int)response.StatusCode}: {Truncate(body)}");
        SmokeAssert.True(
            body.Contains("Guest event import failed", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("Guest events file was not found", StringComparison.OrdinalIgnoreCase),
            $"Manual guest import endpoint returned an unexpected validation body: {Truncate(body)}");
    }

    /// <summary>
    /// Builds an absolute URI for a Web route.
    /// Inputs are a base URI and an absolute route string; processing trims the
    /// leading slash for Uri combination; the method returns an absolute URI.
    /// </summary>
    private static Uri BuildUri(Uri baseUri, string route)
    {
        return new Uri(baseUri, route.TrimStart('/'));
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
        return File.ReadAllText(Path.Combine(allSegments));
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

    /// <summary>
    /// Truncates response bodies for assertion messages.
    /// Inputs are response text; processing limits diagnostics to a compact
    /// single string; the method returns the original or shortened text.
    /// </summary>
    private static string Truncate(string value)
    {
        return value.Length <= 300 ? value : value[..300] + "...";
    }
}
