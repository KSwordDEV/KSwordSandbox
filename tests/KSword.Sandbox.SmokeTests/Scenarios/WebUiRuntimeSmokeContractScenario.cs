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

        await ProbeLocalHostReadinessAsync(httpClient, baseUri, cancellationToken);
        await ProbeLiveEndpointAsync(httpClient, baseUri, jobId, cancellationToken);
        await ProbeLiveRawMonitorPageAsync(httpClient, baseUri, jobId, cancellationToken);
        await ProbeSettingsPageAsync(httpClient, baseUri, cancellationToken);
        await ProbeServedReportLinkAsync(httpClient, baseUri, jobId, cancellationToken);
        await ProbeServedReportLinkAsync(httpClient, baseUri, jobId, cancellationToken, "zh");
        await ProbeServedReportLinkAsync(httpClient, baseUri, jobId, cancellationToken, "en");
        await ProbeArtifactIndexEndpointAsync(httpClient, baseUri, jobId, cancellationToken);
        await ProbeInvalidArtifactDownloadSelectorAsync(httpClient, baseUri, jobId, cancellationToken);
        await ProbeManualGuestImportEndpointAsync(httpClient, baseUri, jobId, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Runtime WebUI smoke checked live events, live raw monitor/settings pages, localized report links, artifact index/download routes, and manual guest import endpoint."
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
        var liveEventsPage = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "LiveEventsPage.cs");
        var settingsPage = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Dashboard", "SettingsPage.cs");
        var artifactDownloadContract = ReadRepositoryText(context, "src", "KSword.Sandbox.Web", "Contracts", "JobArtifactDownloadContract.cs");
        var doc = ReadRepositoryText(context, "docs", "webui-framework.md");
        var script = ReadRepositoryText(context, "scripts", "Test-LiveTelemetryFramework.ps1");

        RequireContains(program, "\"/jobs/{jobId:guid}/live-events\"", "Web source should expose the live raw monitor page route.");
        RequireContains(program, "\"/api/host/readiness\"", "Web source should expose the local host readiness endpoint.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/events/live\"", "Web source should expose the live-event polling endpoint.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/report/html\"", "Web source should expose the served HTML report endpoint.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/artifacts\"", "Web source should expose the Web artifact index endpoint.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/artifacts/download\"", "Web source should expose the guarded artifact download endpoint.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/report/{**artifactPath}\"", "Web source should expose report-relative artifact download links.");
        RequireContains(program, "ToWebArtifactDescriptor", "Web artifact endpoint should map host descriptors through an explicit safe DTO.");
        RequireContains(program, "JobArtifactDownloadContract", "Web artifact endpoint should use the typed artifact download selector contract.");
        RequireContains(program, "ToJobArtifactDownloadContract", "Web artifact endpoint should centralize download selector contract mapping.");
        RequireContains(program, "ToWebArtifactCollectionDescriptor", "Web artifact endpoint should map host collections through an explicit safe DTO.");
        RequireContains(program, "ToWebArtifactMetadata", "Web artifact endpoint should sanitize path-bearing metadata.");
        RequireContains(program, "RootPathPolicy", "Web artifact endpoint should document that root paths are server-owned and not exposed.");
        RequireContains(program, "DownloadSelector", "Web artifact endpoint should expose a stable safe download selector.");
        RequireContains(program, "DownloadHref", "Web artifact endpoint should expose a guarded download href.");
        RequireContains(program, "Uri.EscapeDataString(selector)", "Web artifact endpoint should URL-encode download selectors.");
        RequireContains(program, "StreamIndexedArtifact", "Web source should centralize artifact streaming through the index resolver.");
        RequireContains(program, "ResolveDownloadableArtifact", "Web source should resolve downloads only through the job artifact index.");
        RequireContains(program, "Results.BadRequest", "Web download endpoint should reject invalid selectors with HTTP 400.");
        RequireContains(program, "enableRangeProcessing: true", "Web download endpoint should support ranged downloads for large dumps and PCAPs.");
        RequireContains(program, "string? lang", "Served report endpoint should accept a language query.");
        RequireContains(program, "ResolveLocalizedReportPath", "Web source should resolve localized report paths.");
        RequireContains(program, "HtmlReportZhPath", "Served report endpoint should know the Chinese report path.");
        RequireContains(program, "HtmlReportEnPath", "Served report endpoint should know the English report path.");
        RequireContains(program, "\"/api/jobs/{jobId:guid}/guest-events/import\"", "Web source should expose the manual guest import endpoint.");
        RequireContains(program, "GuestEventImportRequest", "Web source should keep a typed guest import request body.");
        RequireContains(program, "EventsPath", "Guest import request should accept an optional explicit events path.");

        RequireContains(artifactDownloadContract, "public sealed record JobArtifactDownloadContract", "Artifact download contract should remain a typed Web API shape.");
        RequireContains(artifactDownloadContract, "bool Available", "Artifact download contract should expose availability.");
        RequireContains(artifactDownloadContract, "string Selector", "Artifact download contract should expose the accepted relative selector.");
        RequireContains(artifactDownloadContract, "string Href", "Artifact download contract should expose the guarded href.");
        RequireContains(artifactDownloadContract, "string RejectionCode", "Artifact download contract should expose stable rejection codes.");

        RequireContains(dashboard, "/jobs/${encodeURIComponent(jobId)}/live-events", "Dashboard should link to the live raw monitor page.");
        RequireContains(dashboard, "/report/html?lang=zh", "Dashboard should build the Chinese served report endpoint.");
        RequireContains(dashboard, "/report/html?lang=en", "Dashboard should build the English served report endpoint.");
        RequireAnyContains(
            dashboard,
            ["Open served HTML report", "Open served report", "打开服务内报告", "Open planning report", "打开规划报告", "Open dynamic report", "打开动态报告"],
            "Dashboard should render the served report link.");
        RequireContains(dashboard, "data-report-current", "Dashboard should mark the current-language served report link.");
        RequireContains(dashboard, "buildReportHref", "Dashboard should build served report links instead of relying on file:// navigation.");
        RequireContains(dashboard, "guestImportPath", "Dashboard should render a manual guest import path input.");
        RequireContains(dashboard, "guest-events/import", "Dashboard should call the manual guest import endpoint.");
        RequireContains(dashboard, "JSON.stringify(explicitPath ? { eventsPath: explicitPath } : {})", "Dashboard should send optional manual import path JSON.");
        RequireContains(dashboard, "/api/host/readiness", "Dashboard should request real local host readiness before showing VM defaults.");
        RequireContains(dashboard, "NOT_FOUND", "Dashboard should render an explicit missing state instead of a fake configured value.");

        RequireContains(liveEventsPage, "Live raw event monitor", "Live raw monitor page should have a stable title.");
        RequireContains(liveEventsPage, "/events/stream", "Live raw monitor page should attempt the SSE stream endpoint.");
        RequireContains(liveEventsPage, "/events/live", "Live raw monitor page should fall back to polling.");
        RequireContains(liveEventsPage, "data-zh", "Live raw monitor page should expose Chinese text markers.");
        RequireContains(liveEventsPage, "data-en", "Live raw monitor page should expose English text markers.");
        RequireContains(liveEventsPage, "已耗时", "Live raw monitor page should expose elapsed runbook progress.");
        RequireContains(liveEventsPage, "buildProgressFailureReason", "Live raw monitor page should expose runbook failure reasons.");
        RequireContains(liveEventsPage, "progressFreshnessInfo", "Live raw monitor page should calculate progress snapshot freshness.");
        RequireContains(liveEventsPage, "快照新鲜度", "Live raw monitor page should expose snapshot freshness in Chinese.");
        RequireContains(liveEventsPage, "Snapshot freshness", "Live raw monitor page should expose snapshot freshness in English.");
        RequireContains(liveEventsPage, "progress may be stale", "Live raw monitor page should surface stale non-terminal progress snapshots.");
        RequireContains(liveEventsPage, "Open settings", "Live raw monitor page should link to settings for missing VirusTotal keys.");
        RequireContains(liveEventsPage, "result.isQuietState || result.IsQuietState", "Live raw monitor page should honor VirusTotal quiet-state metadata.");
        RequireContains(liveEventsPage, "not configured, not found, rate limits", "Live raw monitor page should explain quiet VirusTotal states in English.");

        RequireContains(settingsPage, "VirusTotal API Key", "Settings page should expose the VirusTotal API key form.");
        RequireContains(settingsPage, "does not upload samples", "Settings page should clearly state that samples are not uploaded.");
        RequireContains(settingsPage, "不会产生噪音日志", "Settings page should state that missing VirusTotal keys do not create noisy logs.");

        RequireContains(doc, BaseUrlEnvironmentVariable, "WebUI framework doc should describe the runtime smoke base URL environment variable.");
        RequireContains(doc, JobIdEnvironmentVariable, "WebUI framework doc should describe the runtime smoke job ID environment variable.");
        RequireContains(doc, "/jobs/{jobId}/live-events", "WebUI framework doc should describe the live raw page validation probe.");
        RequireContains(doc, "/api/jobs/{jobId}/events/live", "WebUI framework doc should describe the live endpoint smoke probe.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html", "WebUI framework doc should describe the served report smoke probe.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html?lang=zh", "WebUI framework doc should describe the Chinese report endpoint probe.");
        RequireContains(doc, "/api/jobs/{jobId}/report/html?lang=en", "WebUI framework doc should describe the English report endpoint probe.");
        RequireContains(doc, "/api/jobs/{jobId}/guest-events/import", "WebUI framework doc should describe the manual guest import smoke probe.");
        RequireContains(doc, "bilingual report endpoints", "WebUI framework doc should identify bilingual report endpoint validation.");
        RequireContains(doc, "static gate", "WebUI framework doc should describe the static gate fallback.");
        RequireContains(doc, "current step, elapsed time, and failure reason", "WebUI framework doc should require visible runbook progress facts.");

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
    /// Probes the read-only local host readiness endpoint. Inputs are the live
    /// Web host URI and cancellation token; processing validates the stable
    /// non-secret response shape; the method returns no value on success.
    /// </summary>
    private static async Task ProbeLocalHostReadinessAsync(HttpClient httpClient, Uri baseUri, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(BuildUri(baseUri, "/api/host/readiness?refresh=true"), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        SmokeAssert.True(response.IsSuccessStatusCode, $"Local host readiness returned HTTP {(int)response.StatusCode}: {Truncate(body)}");

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        SmokeAssert.True(root.TryGetProperty("readOnly", out var readOnly) && readOnly.GetBoolean(), "Local host readiness should declare readOnly=true.");
        SmokeAssert.True(root.TryGetProperty("detectedAtUtc", out _), "Local host readiness should include detectedAtUtc.");
        SmokeAssert.True(root.TryGetProperty("hyperV", out var hyperV) && hyperV.ValueKind == JsonValueKind.Object, "Local host readiness should include Hyper-V facts.");
        SmokeAssert.True(hyperV.TryGetProperty("querySucceeded", out _), "Hyper-V readiness should report whether inventory succeeded.");
        SmokeAssert.True(hyperV.TryGetProperty("vmExists", out _), "Hyper-V readiness should distinguish a detected VM from a configured name.");
        SmokeAssert.True(root.TryGetProperty("paths", out var paths) && paths.ValueKind == JsonValueKind.Object, "Local host readiness should include path existence facts.");
        SmokeAssert.True(paths.TryGetProperty("guestPayloadRoot", out _), "Local host readiness should include the guest payload root fact.");
        SmokeAssert.True(!body.Contains("passwordValue", StringComparison.OrdinalIgnoreCase), "Local host readiness must not expose password values.");
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
    /// Probes the dedicated live raw monitor page without launching a browser.
    /// Inputs are an HTTP client, base URI, job ID, and cancellation token;
    /// processing requests the job-scoped HTML page and validates stable page
    /// text and endpoint references; the method returns no value on success.
    /// </summary>
    private static async Task ProbeLiveRawMonitorPageAsync(HttpClient httpClient, Uri baseUri, Guid jobId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildUri(baseUri, $"/jobs/{jobId:D}/live-events"));
        request.Headers.Accept.ParseAdd("text/html");

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;

        SmokeAssert.True(response.IsSuccessStatusCode, $"Live raw monitor page returned HTTP {(int)response.StatusCode}: {Truncate(body)}");
        SmokeAssert.True(string.Equals(mediaType, "text/html", StringComparison.OrdinalIgnoreCase), $"Live raw monitor page should return text/html, not '{mediaType}'.");
        SmokeAssert.True(body.Contains("Live raw event monitor", StringComparison.OrdinalIgnoreCase), "Live raw monitor page should include its English title.");
        SmokeAssert.True(body.Contains("实时原始事件监控", StringComparison.Ordinal), "Live raw monitor page should include its Chinese title.");
        SmokeAssert.True(body.Contains("/events/live", StringComparison.Ordinal), "Live raw monitor page should reference the polling endpoint.");
        SmokeAssert.True(body.Contains("/events/stream", StringComparison.Ordinal), "Live raw monitor page should reference the SSE endpoint.");
        SmokeAssert.True(body.Contains("虚拟机分析进度", StringComparison.Ordinal), "Live raw monitor page should include the Chinese runbook progress panel.");
        SmokeAssert.True(body.Contains("Runbook progress", StringComparison.Ordinal), "Live raw monitor page should include the English runbook progress label.");
        SmokeAssert.True(body.Contains("/runbook/progress", StringComparison.Ordinal), "Live raw monitor page should poll runbook progress.");
        SmokeAssert.True(body.Contains("后台执行状态", StringComparison.Ordinal), "Live raw monitor page should include background execution status.");
        SmokeAssert.True(body.Contains("/runbook/background", StringComparison.Ordinal), "Live raw monitor page should poll background execution status.");
    }

    /// <summary>
    /// Probes the settings page without changing local settings. Inputs are an
    /// HTTP client, base URI, and cancellation token; processing requests the
    /// local settings HTML and validates VirusTotal copy; the method returns no
    /// value on success.
    /// </summary>
    private static async Task ProbeSettingsPageAsync(HttpClient httpClient, Uri baseUri, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildUri(baseUri, "/settings"));
        request.Headers.Accept.ParseAdd("text/html");

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;

        SmokeAssert.True(response.IsSuccessStatusCode, $"Settings page returned HTTP {(int)response.StatusCode}: {Truncate(body)}");
        SmokeAssert.True(string.Equals(mediaType, "text/html", StringComparison.OrdinalIgnoreCase), $"Settings page should return text/html, not '{mediaType}'.");
        SmokeAssert.True(body.Contains("VirusTotal API Key", StringComparison.Ordinal), "Settings page should include the VirusTotal API key form.");
        SmokeAssert.True(body.Contains("不会提交到仓库", StringComparison.Ordinal), "Settings page should explain local settings are not committed.");
        SmokeAssert.True(body.Contains("/api/settings/virustotal", StringComparison.Ordinal), "Settings page should save through the VirusTotal settings endpoint.");
        SmokeAssert.True(body.Contains("does not upload samples", StringComparison.Ordinal), "Settings page should state that samples are not uploaded.");
    }

    /// <summary>
    /// Probes the safe served report link.
    /// Inputs are an HTTP client, base URI, job ID, optional language, and
    /// cancellation token; processing requests the server-owned report.html
    /// endpoint and validates HTML response shape; the method returns no value
    /// on success.
    /// </summary>
    private static async Task ProbeServedReportLinkAsync(HttpClient httpClient, Uri baseUri, Guid jobId, CancellationToken cancellationToken, string? language = null)
    {
        var suffix = string.IsNullOrWhiteSpace(language) ? string.Empty : $"?lang={language}";
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildUri(baseUri, $"/api/jobs/{jobId:D}/report/html{suffix}"));
        request.Headers.Accept.ParseAdd("text/html");

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;

        var label = string.IsNullOrWhiteSpace(language) ? "Served report link" : $"Served {language} report link";
        SmokeAssert.True(response.IsSuccessStatusCode, $"{label} returned HTTP {(int)response.StatusCode}: {Truncate(body)}");
        SmokeAssert.True(string.Equals(mediaType, "text/html", StringComparison.OrdinalIgnoreCase), $"{label} should return text/html, not '{mediaType}'.");
        SmokeAssert.True(body.Contains("<html", StringComparison.OrdinalIgnoreCase), $"{label} should return an HTML document.");
    }

    /// <summary>
    /// Probes the Web artifact index endpoint. Inputs are an HTTP client, base
    /// URI, job ID, and cancellation token; processing validates that the JSON
    /// response exposes browser-safe selectors and guarded download hrefs
    /// without exposing host-local full paths; the method returns no value.
    /// </summary>
    private static async Task ProbeArtifactIndexEndpointAsync(HttpClient httpClient, Uri baseUri, Guid jobId, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(BuildUri(baseUri, $"/api/jobs/{jobId:D}/artifacts"), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        SmokeAssert.True(response.IsSuccessStatusCode, $"Artifact index endpoint returned HTTP {(int)response.StatusCode}: {Truncate(body)}");

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        SmokeAssert.True(root.TryGetProperty("jobId", out var responseJobId) && Guid.Parse(responseJobId.GetString() ?? string.Empty) == jobId, "Artifact index response jobId mismatch.");
        SmokeAssert.True(root.TryGetProperty("schemaVersion", out _), "Artifact index response is missing schemaVersion.");
        SmokeAssert.True(root.TryGetProperty("generatedAtUtc", out _), "Artifact index response is missing generatedAtUtc.");
        SmokeAssert.True(root.TryGetProperty("rootPathPolicy", out var rootPathPolicy) && rootPathPolicy.GetString() == "server-owned-not-exposed", "Artifact index response should mark root paths as server-owned.");
        if (root.TryGetProperty("rootPath", out var rootPath))
        {
            var rootPathValue = rootPath.GetString() ?? string.Empty;
            SmokeAssert.True(string.IsNullOrWhiteSpace(rootPathValue) || !LooksLikeLocalAbsolutePath(rootPathValue), "Artifact index response should not expose the host job root path.");
        }

        SmokeAssert.True(root.TryGetProperty("collections", out var collections) && collections.ValueKind == JsonValueKind.Array, "Artifact index response is missing collections array.");
        SmokeAssert.True(root.TryGetProperty("artifacts", out var artifacts) && artifacts.ValueKind == JsonValueKind.Array, "Artifact index response is missing artifacts array.");

        foreach (var artifact in artifacts.EnumerateArray())
        {
            SmokeAssert.True(!artifact.TryGetProperty("fullPath", out _), "Web artifact descriptors must not expose host-local fullPath.");
            SmokeAssert.True(artifact.TryGetProperty("downloadSelector", out var selector), "Web artifact descriptors should expose downloadSelector.");
            AssertSafeSelector("artifact downloadSelector", selector.GetString() ?? string.Empty);
            SmokeAssert.True(artifact.TryGetProperty("downloadHref", out var href), "Web artifact descriptors should expose downloadHref.");
            var hrefText = href.GetString() ?? string.Empty;
            SmokeAssert.True(hrefText.StartsWith($"/api/jobs/{jobId:D}/artifacts/download?path=", StringComparison.Ordinal), "Artifact download href should target the guarded download endpoint.");
            SmokeAssert.True(!LooksLikeLocalAbsolutePath(hrefText), "Artifact download href should not embed an absolute host path.");
            SmokeAssert.True(artifact.TryGetProperty("download", out var download) && download.ValueKind == JsonValueKind.Object, "Web artifact descriptors should expose the typed download contract.");
            SmokeAssert.True(download.TryGetProperty("available", out var available) && available.ValueKind is JsonValueKind.True or JsonValueKind.False, "Artifact download contract should expose boolean availability.");
            SmokeAssert.True(download.TryGetProperty("selector", out var contractSelector), "Artifact download contract should expose selector.");
            SmokeAssert.True(string.Equals(contractSelector.GetString(), selector.GetString(), StringComparison.Ordinal), "Artifact download contract selector should match the top-level downloadSelector.");
            SmokeAssert.True(download.TryGetProperty("href", out var contractHref), "Artifact download contract should expose href.");
            SmokeAssert.True(string.Equals(contractHref.GetString(), hrefText, StringComparison.Ordinal), "Artifact download contract href should match the top-level downloadHref.");
            SmokeAssert.True(download.TryGetProperty("rejectionCode", out _), "Artifact download contract should expose a stable rejectionCode field.");
            if (artifact.TryGetProperty("metadata", out var metadata))
            {
                AssertNoAbsolutePathMetadata(metadata, "artifact metadata");
            }
        }

        foreach (var collection in collections.EnumerateArray())
        {
            SmokeAssert.True(!collection.TryGetProperty("fullPath", out _), "Web artifact collections must not expose host-local fullPath.");
            if (collection.TryGetProperty("metadata", out var metadata))
            {
                AssertNoAbsolutePathMetadata(metadata, "collection metadata");
            }
        }
    }

    /// <summary>
    /// Probes the guarded download endpoint with a known-bad selector. Inputs
    /// are an HTTP client, base URI, job ID, and cancellation token; processing
    /// sends URL-encoded traversal and expects a validation response rather
    /// than arbitrary filesystem resolution; the method returns no value.
    /// </summary>
    private static async Task ProbeInvalidArtifactDownloadSelectorAsync(HttpClient httpClient, Uri baseUri, Guid jobId, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(BuildUri(baseUri, $"/api/jobs/{jobId:D}/artifacts/download?path=..%2Fescape.bin"), cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        SmokeAssert.True(response.StatusCode == HttpStatusCode.BadRequest, $"Invalid artifact download selector should return HTTP 400; got HTTP {(int)response.StatusCode}: {Truncate(body)}");
        SmokeAssert.True(body.Contains("selector", StringComparison.OrdinalIgnoreCase) || body.Contains("relative", StringComparison.OrdinalIgnoreCase), $"Invalid artifact download response should explain selector validation: {Truncate(body)}");
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

    private static void AssertSafeSelector(string label, string value)
    {
        SmokeAssert.True(!string.IsNullOrWhiteSpace(value), $"{label} should not be empty.");
        SmokeAssert.True(!value.Contains('\\', StringComparison.Ordinal), $"{label} should use slash-separated paths.");
        SmokeAssert.True(!value.StartsWith("/", StringComparison.Ordinal), $"{label} should be relative.");
        SmokeAssert.True(!Path.IsPathFullyQualified(Uri.UnescapeDataString(value)), $"{label} should not be a fully-qualified filesystem path.");
        SmokeAssert.True(!value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(segment => string.Equals(segment, "..", StringComparison.Ordinal)), $"{label} should not contain parent traversal.");
    }

    private static void AssertNoAbsolutePathMetadata(JsonElement metadata, string label)
    {
        SmokeAssert.True(metadata.ValueKind == JsonValueKind.Object, $"{label} should be a JSON object.");
        foreach (var property in metadata.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var value = property.Value.GetString() ?? string.Empty;
            SmokeAssert.True(!property.Name.Contains("fullPath", StringComparison.OrdinalIgnoreCase), $"{label} should not expose full-path key '{property.Name}'.");
            SmokeAssert.True(!LooksLikeLocalAbsolutePath(value), $"{label} property '{property.Name}' should not expose an absolute local path.");
        }
    }

    private static bool LooksLikeLocalAbsolutePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.StartsWith(@"\\", StringComparison.Ordinal) ||
            trimmed.StartsWith("//", StringComparison.Ordinal))
        {
            return true;
        }

        if (trimmed.Length >= 3 &&
            char.IsLetter(trimmed[0]) &&
            trimmed[1] == ':' &&
            (trimmed[2] == '\\' || trimmed[2] == '/'))
        {
            return true;
        }

        return Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) &&
            string.Equals(uri.Scheme, Uri.UriSchemeFile, StringComparison.OrdinalIgnoreCase);
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
    /// Requires that a text block contains at least one of several literals.
    /// Inputs are text, alternatives, and assertion message; processing uses
    /// ordinal substring matching; the method returns no value on success.
    /// </summary>
    private static void RequireAnyContains(string content, IReadOnlyCollection<string> expectedAny, string message)
    {
        SmokeAssert.True(expectedAny.Any(expected => content.Contains(expected, StringComparison.Ordinal)), message);
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
