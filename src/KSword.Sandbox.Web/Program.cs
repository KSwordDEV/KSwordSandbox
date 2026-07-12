using System.Text.Json;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Execution;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Web.Contracts;
using KSword.Sandbox.Web.Dashboard;
using KSword.Sandbox.Web.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
var repositoryRoot = ResolveRepositoryRoot(builder.Environment.ContentRootPath);
var configPath = builder.Configuration["Sandbox:ConfigPath"] ?? Path.Combine("config", "sandbox.example.json");
var config = SandboxConfigLoader.Load(configPath, repositoryRoot);
var rulesPath = Path.Combine(config.Paths.RulesDirectory, "behavior-rules.json");
var rules = RuleEngine.LoadRuleSet(rulesPath);
var jobService = new SandboxJobService(config, rules);
var targetScanner = new ExecutableTargetScanner();

builder.Services.AddSingleton(config);
builder.Services.AddSingleton(rules);
builder.Services.AddSingleton(jobService);
builder.Services.AddSingleton(targetScanner);
builder.Services.AddSingleton<RunbookProgressStore>();
builder.Services.AddSingleton<RunbookBackgroundExecutionStore>();
builder.Services.AddSingleton<VirusTotalSettingsStore>();
builder.Services.AddSingleton<VirusTotalLookupCache>();
builder.Services.AddSingleton<IRunbookExecutor, PowerShellRunbookExecutor>();
builder.Services.AddHttpClient<VirusTotalLookupService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(10);
});

var app = builder.Build();

app.MapGet("/", () => Results.Content(DashboardExperiencePage.Render(), "text/html"));
app.MapGet("/settings", (VirusTotalSettingsStore settingsStore) =>
    Results.Content(SettingsPage.Render(settingsStore.GetState()), "text/html; charset=utf-8"));
app.MapGet("/jobs/{jobId:guid}/execution-flow", (Guid jobId, SandboxJobService service) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
    }

    var execution = TryReadRunbookExecutionResult(job.RunbookExecutionResultPath);
    return Results.Content(RunbookExecutionFlowPage.Render(job, execution), "text/html; charset=utf-8");
});
app.MapGet("/jobs/{jobId:guid}/live-events", (Guid jobId, SandboxJobService service) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"未找到任务 {jobId:D}；请刷新任务列表或重新上传样本 / Job was not found in the Web host job list." });
    }

    return Results.Content(LiveEventsPage.Render(job), "text/html; charset=utf-8");
});
app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "KSword Sandbox Host",
    time = DateTimeOffset.UtcNow
}));
app.MapGet("/api/config", (SandboxConfig currentConfig) => Results.Ok(currentConfig));
app.MapGet("/api/settings/virustotal", (VirusTotalSettingsStore settingsStore) => Results.Ok(settingsStore.GetState()));
app.MapPost("/api/settings/virustotal", (VirusTotalSettingsUpdateRequest request, VirusTotalSettingsStore settingsStore, VirusTotalLookupCache virusTotalCache) =>
{
    try
    {
        var state = settingsStore.Save(request.ApiKey, request.Clear);
        virusTotalCache.Clear();
        return Results.Ok(state);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
    {
        return Results.BadRequest(new { error = $"VirusTotal settings could not be saved: {ex.Message}" });
    }
});
app.MapGet("/api/jobs", (SandboxJobService service) => Results.Ok(service.ListJobs()));
app.MapGet("/api/jobs/{jobId:guid}", (Guid jobId, SandboxJobService service) =>
{
    var job = service.GetJob(jobId);
    return job is null ? Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." }) : Results.Ok(job);
});
app.MapGet("/api/jobs/{jobId:guid}/virustotal", async Task<IResult> (Guid jobId, bool? persist, SandboxJobService service, VirusTotalLookupService virusTotal, CancellationToken cancellationToken) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
    }

    if (job.Sample is null || string.IsNullOrWhiteSpace(job.Sample.Sha256))
    {
        return Results.Ok(await virusTotal.LookupFileHashAsync(string.Empty, cancellationToken));
    }

    var result = await virusTotal.LookupFileHashAsync(job.Sample.Sha256, cancellationToken);
    if (persist == true && ShouldPersistVirusTotalResult(result))
    {
        service.UpsertEnrichmentEvent(
            jobId,
            result.ToRuleEvent(),
            $"VirusTotal hash lookup persisted to report: status={result.Status}, verdict={result.Verdict}.");
        result = result with { PersistedToEnrichmentEvents = true };
    }

    return Results.Ok(result);
});
// POST /api/jobs/{jobId}/enrichments/virustotal is the explicit job enrichment
// path. The live monitor GET stays display-only by default; this endpoint
// performs the same hash-only lookup and persists only rule-safe "found"
// evidence. Missing/not-found results, missing keys, auth failures, rate
// limits, and transport failures stay friendly non-persistent UI statuses.
app.MapPost("/api/jobs/{jobId:guid}/enrichments/virustotal", async Task<IResult> (Guid jobId, SandboxJobService service, VirusTotalLookupService virusTotal, CancellationToken cancellationToken) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
    }

    var result = job.Sample is null || string.IsNullOrWhiteSpace(job.Sample.Sha256)
        ? await virusTotal.LookupFileHashAsync(string.Empty, cancellationToken)
        : await virusTotal.LookupFileHashAsync(job.Sample.Sha256, cancellationToken);
    if (!ShouldPersistVirusTotalResult(result))
    {
        return Results.Ok(result with { PersistedToEnrichmentEvents = false });
    }

    try
    {
        service.UpsertEnrichmentEvent(
            jobId,
            result.ToRuleEvent(),
            $"VirusTotal job enrichment persisted: status={result.Status}, verdict={result.Verdict}.");
        return Results.Ok(result with { PersistedToEnrichmentEvents = true });
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
    {
        return Results.Problem(
            title: "VirusTotal enrichment could not be persisted.",
            detail: $"VirusTotal lookup succeeded but report enrichment for job {jobId:D} could not be updated: {ex.Message}",
            statusCode: 500);
    }
});
// GET /api/jobs/{jobId}/runbook/progress returns the latest UI-safe runbook
// progress snapshot while a long live request is still running. Inputs are only
// a job id; processing reads both the Web host's in-memory progress store and
// the durable runbook-progress.json snapshot, then returns the newest snapshot.
// A page refresh, WebHost restart, or second Web worker therefore uses durable
// progress instead of falling back to a fake pending view. The response
// intentionally excludes PowerShell commands, stdout, and stderr.
app.MapGet("/api/jobs/{jobId:guid}/runbook/progress", (Guid jobId, SandboxJobService service, RunbookProgressStore progressStore) =>
{
    return TryReadOrCreateRunbookProgressSnapshot(jobId, service, progressStore, out var snapshot, out var errorResult)
        ? Results.Ok(BuildRunbookProgressApiPayload(service, jobId, snapshot!))
        : errorResult ?? Results.NotFound(new { error = $"任务 {jobId:D} 还没有分析进度快照 / The job does not have a runbook progress snapshot yet." });
});
// GET /api/jobs/{jobId}/progress/stream is the preferred lightweight
// Server-Sent Events transport for the live monitor. It emits UI-safe runbook
// progress snapshots as executor updates arrive, includes compact background
// execution state, and closes/reconnects on a bounded lifetime instead of
// turning the monitor into an unbounded long-poll request.
app.MapGet("/api/jobs/{jobId:guid}/progress/stream", WriteRunbookProgressStreamAsync);
// GET /api/jobs/{jobId}/runbook/background returns the WebUI server-side
// background execution state. It complements the per-step progress endpoint:
// progress is live/streaming, while this endpoint carries the terminal
// execution result, imported job, and report-ready metadata after completion.
app.MapGet("/api/jobs/{jobId:guid}/runbook/background", (Guid jobId, SandboxJobService service, RunbookBackgroundExecutionStore backgroundStore) =>
{
    if (service.GetJob(jobId) is null)
    {
        return Results.NotFound(new { error = $"未找到任务 {jobId:D}；请刷新任务列表或重新上传样本 / Job was not found in the Web host job list." });
    }

    return Results.Ok(backgroundStore.Get(jobId));
});
// GET /api/jobs/{jobId}/events/live returns unclassified raw events for the
// WebUI monitor. Inputs are a job id plus optional offset/take query values;
// processing reads current host/guest artifacts without running rules, and the
// endpoint returns a LiveEventSnapshot suitable for polling.
app.MapGet("/api/jobs/{jobId:guid}/events/live", (Guid jobId, int? offset, int? take, SandboxJobService service) =>
{
    try
    {
        return Results.Ok(service.GetLiveEvents(jobId, offset ?? 0, take ?? 100));
    }
    catch (KeyNotFoundException ex)
    {
        return Results.NotFound(new { error = ex.Message });
    }
});
// GET /api/jobs/{jobId}/events/stream keeps the raw-event monitor open with
// Server-Sent Events. Inputs are a job id plus optional offset/take/intervalMs
// query values; processing repeatedly reads unclassified live events and writes
// snapshot events; the endpoint returns no body after the client disconnects.
app.MapGet("/api/jobs/{jobId:guid}/events/stream", WriteLiveEventStreamAsync);
// GET /api/jobs/{jobId}/report/html accepts only a job identifier from the
// route. It never accepts a caller-supplied filesystem path; processing looks
// up the recorded HTML report path for that job and returns the report body
// when the file still exists.
app.MapGet("/api/jobs/{jobId:guid}/report/html", async Task<IResult> (Guid jobId, string? lang, SandboxJobService service) =>
{
    if (!TryResolveHtmlReportPath(jobId, lang, service, out var reportPath, out var errorResult))
    {
        return errorResult ?? Results.NotFound(new { error = $"HTML report was not found for job {jobId:D}." });
    }

    try
    {
        var html = await File.ReadAllTextAsync(reportPath);
        return Results.Content(html, "text/html; charset=utf-8");
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        return Results.Problem(
            title: "Unable to read HTML report.",
            detail: $"The recorded report path '{reportPath}' could not be read: {ex.Message}",
            statusCode: 500);
    }
});
// GET /api/jobs/{jobId}/artifacts returns the current host-side artifact index.
// It is the WebUI-facing source for downloadable evidence such as events.json,
// driver-events.jsonl, dropped files, screenshots, memory dumps, and PCAPs.
app.MapGet("/api/jobs/{jobId:guid}/artifacts", (Guid jobId, SandboxJobService service) =>
{
    try
    {
        var index = service.BuildArtifactIndex(jobId);
        return Results.Ok(new
        {
            index.SchemaVersion,
            index.JobId,
            RootPath = string.Empty,
            RootPathPolicy = "server-owned-not-exposed",
            index.Producer,
            index.GeneratedAtUtc,
            Collections = index.Collections.Select(ToWebArtifactCollectionDescriptor).ToList(),
            Artifacts = index.Artifacts.Select(artifact => ToWebArtifactDescriptor(jobId, artifact)).ToList()
        });
    }
    catch (KeyNotFoundException ex)
    {
        return Results.NotFound(new { error = ex.Message });
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
    {
        return Results.Problem(
            title: "Unable to build artifact index.",
            detail: $"Artifact index for job {jobId:D} could not be built: {ex.Message}",
            statusCode: 500);
    }
});
// GET /api/jobs/{jobId}/artifacts/download?path=<relative> streams one indexed
// artifact. The path must match an artifact index relative path/safe link; the
// endpoint never accepts arbitrary absolute filesystem paths from the browser.
app.MapGet("/api/jobs/{jobId:guid}/artifacts/download", (Guid jobId, string path, SandboxJobService service) =>
{
    return StreamIndexedArtifact(jobId, path, service);
});
// GET /api/jobs/{jobId}/report/{artifactPath} supports relative links embedded
// inside the served HTML report. For example, a report link to
// guest/<job>/events.json resolves under this route instead of leaking a local
// filesystem path to the browser.
app.MapGet("/api/jobs/{jobId:guid}/report/{**artifactPath}", (Guid jobId, string artifactPath, SandboxJobService service) =>
{
    return StreamIndexedArtifact(jobId, artifactPath, service);
});
app.MapPost("/api/files/scan", (ExecutableScanRequest request, ExecutableTargetScanner scanner) =>
{
    try
    {
        return Results.Ok(scanner.Scan(request));
    }
    catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or IOException or UnauthorizedAccessException)
    {
        return Results.BadRequest(new { error = $"File scan request is invalid or inaccessible: {ex.Message}" });
    }
});

app.MapPost("/api/files/upload", async (HttpRequest request, SandboxConfig currentConfig) =>
{
    try
    {
        var form = await request.ReadFormAsync();
        var candidate = await SaveUploadedExecutableAsync(form, currentConfig);
        return Results.Ok(candidate);
    }
    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException)
    {
        return Results.BadRequest(new { error = $"Executable upload failed validation or storage: {ex.Message}" });
    }
});
// POST /api/files/upload/start is the WebUI one-click path: save an uploaded
// .exe, create a normal plan, and immediately submit the runbook to the
// background VM runner. The response always includes the created job when
// upload/planning succeeds, even if live-run preflight fails, so the operator
// keeps monitor/report links instead of losing context after a credential or VM
// readiness problem.
app.MapPost("/api/files/upload/start", async Task<IResult> (HttpRequest request, SandboxConfig currentConfig, SandboxJobService service, IRunbookExecutor executor, RunbookProgressStore progressStore, RunbookBackgroundExecutionStore backgroundStore) =>
{
    try
    {
        var form = await request.ReadFormAsync();
        var candidate = await SaveUploadedExecutableAsync(form, currentConfig);
        var submission = BuildSubmissionFromUploadForm(candidate, form, currentConfig);
        var job = service.Plan(submission);
        var runbookRequest = BuildRunbookExecuteRequestFromUploadForm(form);
        var runbookStart = TryStartBackgroundRunbook(job.JobId, runbookRequest, service, executor, currentConfig, progressStore, backgroundStore);
        var runbookProgress = TryReadOrCreateRunbookProgressSnapshot(job.JobId, service, progressStore, out var progressSnapshot, out _) && progressSnapshot is not null
            ? BuildRunbookProgressApiPayload(service, job.JobId, progressSnapshot)
            : null;
        return Results.Ok(new
        {
            Uploaded = candidate,
            Job = job,
            MonitorHref = $"/jobs/{job.JobId:D}/live-events",
            UploadMonitorHref = $"/jobs/{job.JobId:D}/live-events?fromUpload=1&accepted={(runbookStart.Accepted ? "1" : "0")}&state={Uri.EscapeDataString(runbookStart.State ?? RunbookBackgroundExecutionStore.NotStarted)}",
            ExecutionFlowHref = $"/jobs/{job.JobId:D}/execution-flow",
            ReportHref = $"/api/jobs/{job.JobId:D}/report/html",
            BackgroundHref = $"/api/jobs/{job.JobId:D}/runbook/background",
            RunbookProgress = runbookProgress,
            RunbookStart = runbookStart
        });
    }
    catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or InvalidOperationException or IOException or UnauthorizedAccessException)
    {
        return Results.BadRequest(new { error = $"上传并启动分析失败，任务尚未创建：{ex.Message} / Upload-and-start analysis failed before a job could be created." });
    }
});
app.MapPost("/api/jobs/plan", (SandboxSubmission submission, SandboxJobService service) =>
{
    try
    {
        var job = service.Plan(submission);
        return Results.Ok(job);
    }
    catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or InvalidOperationException)
    {
        return Results.BadRequest(new { error = $"无法创建分析计划：{ex.Message} / Dry-run plan could not be created." });
    }
});
app.MapPost("/api/jobs/{jobId:guid}/runbook/execute", async (Guid jobId, RunbookExecuteRequest request, SandboxJobService service, IRunbookExecutor executor, SandboxConfig currentConfig, RunbookProgressStore progressStore) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"未找到任务 {jobId:D}；请先上传样本并创建分析计划 / Job was not found; create a dry-run plan before running a runbook." });
    }

    if (job.Runbook is null)
    {
        return Results.BadRequest(new { error = $"任务 {jobId:D} 没有可执行流程；请重新上传或重新创建分析计划 / Job does not have a runbook; recreate the dry-run plan for the selected executable." });
    }

    var prepareError = TryPrepareRunbookExecution(job, request, service, currentConfig, progressStore, out var options);
    if (prepareError is not null)
    {
        return prepareError;
    }

    return Results.Ok(await ExecuteRunbookAndImportAsync(jobId, request, service, executor, options));
});
// POST /api/jobs/{jobId}/runbook/start starts the same runbook work on a
// server-side background task and returns immediately. This is the preferred
// WebUI path for live VM analysis because the browser tab no longer owns the
// long PowerShell/Hyper-V request lifetime.
app.MapPost("/api/jobs/{jobId:guid}/runbook/start", (Guid jobId, RunbookExecuteRequest request, SandboxJobService service, IRunbookExecutor executor, SandboxConfig currentConfig, RunbookProgressStore progressStore, RunbookBackgroundExecutionStore backgroundStore) =>
{
    var start = TryStartBackgroundRunbook(jobId, request, service, executor, currentConfig, progressStore, backgroundStore);
    if (start.StatusCode == StatusCodes.Status404NotFound)
    {
        return Results.NotFound(new { error = start.Message });
    }

    if (start.StatusCode == StatusCodes.Status400BadRequest)
    {
        return Results.BadRequest(new { error = start.Message });
    }

    return start.Accepted
        ? Results.Accepted($"/api/jobs/{jobId:D}/runbook/background", start.Snapshot)
        : Results.Ok(start.Snapshot);
});
app.MapPost("/api/jobs/{jobId:guid}/guest-events/import", (Guid jobId, GuestEventImportRequest request, SandboxJobService service) =>
{
    try
    {
        var job = service.ImportGuestEvents(jobId, request.EventsPath);
        return Results.Ok(job);
    }
    catch (KeyNotFoundException ex)
    {
        return Results.NotFound(new { error = ex.Message });
    }
    catch (Exception ex) when (ex is DirectoryNotFoundException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException)
    {
        return Results.BadRequest(new { error = $"导入来宾事件失败，任务 {jobId:D}：{ex.Message} / Guest event import failed." });
    }
});

app.Run();

/// <summary>
/// Converts an artifact descriptor into a WebUI-safe DTO with a download URL.
/// Inputs are a job ID and host-side descriptor; processing does not expose new
/// filesystem powers beyond existing descriptor metadata; the returned object
/// lets pages link to the server-side guarded artifact download endpoint.
/// </summary>
static object ToWebArtifactDescriptor(Guid jobId, ArtifactDescriptor artifact)
{
    var selectors = BuildWebArtifactSelectors(artifact);
    var selector = FirstNonEmpty(selectors.SafeLink, selectors.RelativePath, selectors.ImportPath);
    var contentType = ResolveArtifactContentType(artifact);
    var fileName = SanitizeDownloadFileName(FirstNonEmpty(artifact.Name, artifact.RelativePath, "artifact.bin"));
    var sha256 = FirstNonEmpty(artifact.Sha256, artifact.Hashes.GetValueOrDefault("sha256"));
    var safeMetadata = ToWebArtifactMetadata(artifact.Metadata);
    var download = ToJobArtifactDownloadContract(jobId, artifact, selector, fileName, contentType, sha256);
    return new
    {
        artifact.Kind,
        artifact.Category,
        artifact.Name,
        RelativePath = selectors.RelativePath,
        SafeLink = selectors.SafeLink,
        artifact.EvidenceRole,
        artifact.CapturePhase,
        artifact.CaptureState,
        artifact.GuestPath,
        ImportPath = selectors.ImportPath,
        artifact.CollectionName,
        artifact.MimeType,
        ContentType = contentType,
        artifact.SizeBytes,
        Sha256 = sha256,
        Sha256Short = ShortHash(sha256),
        artifact.Hashes,
        artifact.CreatedAtUtc,
        PreviewLabel = FirstNonEmpty(safeMetadata.GetValueOrDefault("previewLabel"), BuildPreviewLabel(artifact.Kind, fileName, english: true)),
        PreviewLabelZh = FirstNonEmpty(safeMetadata.GetValueOrDefault("previewLabelZh"), BuildPreviewLabel(artifact.Kind, fileName, english: false)),
        Selectors = new
        {
            selectors.RelativePath,
            selectors.SafeLink,
            selectors.ImportPath,
            Policy = "relative-index-selectors-only"
        },
        Duplicate = new
        {
            IsDuplicate = string.Equals(safeMetadata.GetValueOrDefault("isDuplicate"), "true", StringComparison.OrdinalIgnoreCase),
            Role = FirstNonEmpty(safeMetadata.GetValueOrDefault("duplicateRole"), "unique"),
            GroupKey = safeMetadata.GetValueOrDefault("duplicateGroupKey") ?? string.Empty,
            GroupId = safeMetadata.GetValueOrDefault("duplicateGroupId") ?? string.Empty,
            GroupCount = safeMetadata.GetValueOrDefault("duplicateGroupCount") ?? string.Empty,
            PrimarySelector = safeMetadata.GetValueOrDefault("duplicatePrimarySelector") ?? string.Empty
        },
        Download = download,
        Metadata = safeMetadata,
        DownloadSelector = selector,
        DownloadHref = download.Href
    };
}

static JobArtifactDownloadContract ToJobArtifactDownloadContract(
    Guid jobId,
    ArtifactDescriptor artifact,
    string selector,
    string fileName,
    string contentType,
    string sha256)
{
    var href = string.IsNullOrWhiteSpace(selector)
        ? string.Empty
        : $"/api/jobs/{jobId:D}/artifacts/download?path={Uri.EscapeDataString(selector)}";
    var rejectionCode = string.IsNullOrWhiteSpace(selector) ? "missing-safe-selector" : string.Empty;

    return new JobArtifactDownloadContract(
        Available: string.IsNullOrWhiteSpace(rejectionCode),
        Selector: selector,
        Href: href,
        FileName: fileName,
        ContentType: contentType,
        SizeBytes: artifact.SizeBytes,
        Sha256: sha256,
        RejectionCode: rejectionCode,
        RejectionMessage: string.IsNullOrWhiteSpace(rejectionCode)
            ? string.Empty
            : "Artifact is indexed but has no safe relative selector; server will not stream it.",
        RejectionMessageZh: string.IsNullOrWhiteSpace(rejectionCode)
            ? string.Empty
            : "产物已被索引，但缺少安全相对 selector，Web 端不会下载。");
}

static (string RelativePath, string SafeLink, string ImportPath) BuildWebArtifactSelectors(ArtifactDescriptor artifact)
{
    var relativePath = NormalizeWebArtifactSelector(artifact.RelativePath, encode: false);
    var safeLink = NormalizeWebArtifactSelector(artifact.SafeLink, encode: true);
    var importPath = NormalizeWebArtifactSelector(artifact.ImportPath, encode: false);
    if (string.IsNullOrWhiteSpace(safeLink))
    {
        safeLink = ArtifactDescriptorFactory.BuildSafeLink(FirstNonEmpty(relativePath, importPath));
    }

    return (relativePath, safeLink, importPath);
}

static string NormalizeWebArtifactSelector(string? value, bool encode)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return string.Empty;
    }

    try
    {
        var decoded = Uri.UnescapeDataString(value.Trim());
        var normalized = ArtifactDescriptorFactory.NormalizeRelativePath(decoded);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        return encode ? ArtifactDescriptorFactory.BuildSafeLink(normalized) : normalized;
    }
    catch (UriFormatException)
    {
        return string.Empty;
    }
}

static string ResolveArtifactContentType(ArtifactDescriptor artifact)
{
    return FirstNonEmpty(
        artifact.MimeType,
        artifact.Metadata.GetValueOrDefault("contentType"),
        artifact.Metadata.GetValueOrDefault("downloadContentType"),
        ArtifactDescriptorFactory.MimeTypeForPath(FirstNonEmpty(artifact.FullPath, artifact.Name, artifact.RelativePath)));
}

static string SanitizeDownloadFileName(string value)
{
    var fileName = Path.GetFileName(value.Replace('\\', '/'));
    if (string.IsNullOrWhiteSpace(fileName))
    {
        fileName = "artifact.bin";
    }

    foreach (var invalid in Path.GetInvalidFileNameChars())
    {
        fileName = fileName.Replace(invalid, '_');
    }

    return new string(fileName.Select(ch => char.IsControl(ch) ? '_' : ch).ToArray());
}

static string ShortHash(string? value)
{
    return string.IsNullOrWhiteSpace(value)
        ? string.Empty
        : value[..Math.Min(value.Length, 12)];
}

static string BuildPreviewLabel(ArtifactKind kind, string fileName, bool english)
{
    var label = english
        ? kind switch
        {
            ArtifactKind.DroppedFile => "掉落文件 / Dropped file",
            ArtifactKind.Screenshot => "截图 / Screenshot",
            ArtifactKind.MemoryDump => "内存转储 / Memory dump",
            ArtifactKind.PacketCapture => "抓包文件 / Packet capture",
            _ => "证据文件 / Artifact"
        }
        : kind switch
        {
            ArtifactKind.DroppedFile => "掉落文件",
            ArtifactKind.Screenshot => "截图",
            ArtifactKind.MemoryDump => "内存转储",
            ArtifactKind.PacketCapture => "抓包文件",
            _ => "产物"
        };

    return english ? $"{label}: {fileName}" : $"{label}：{fileName}";
}

/// <summary>
/// Converts a host collection descriptor into the Web artifact-index shape.
/// Inputs are host-side collection metadata that may contain local paths;
/// processing keeps only safe selector fields and non-local metadata; the
/// returned DTO is suitable for browser display without granting filesystem
/// selector authority.
/// </summary>
static object ToWebArtifactCollectionDescriptor(ArtifactCollectionDescriptor collection)
{
    var relativePath = NormalizeWebArtifactSelector(collection.RelativePath, encode: false);
    var safeLink = NormalizeWebArtifactSelector(collection.SafeLink, encode: true);
    var importPath = NormalizeWebArtifactSelector(collection.ImportPath, encode: false);
    var metadata = ToWebArtifactMetadata(collection.Metadata);
    return new
    {
        collection.Name,
        collection.Kind,
        collection.Category,
        collection.EvidenceRole,
        RelativePath = relativePath,
        SafeLink = safeLink,
        ImportPath = importPath,
        collection.Enabled,
        collection.Implemented,
        collection.Status,
        collection.Reason,
        RejectionDiagnostics = new
        {
            Available = string.Equals(metadata.GetValueOrDefault("rejectionDiagnosticsAvailable"), "true", StringComparison.OrdinalIgnoreCase),
            RejectedArtifactCount = metadata.GetValueOrDefault("rejectedArtifactCount") ?? string.Empty,
            LastRejectedReason = metadata.GetValueOrDefault("lastRejectedArtifactReason") ?? string.Empty,
            LastRejectedSelector = metadata.GetValueOrDefault("lastRejectedArtifactSelector") ?? string.Empty,
            ZhHint = metadata.GetValueOrDefault("zhRejectionHint") ?? string.Empty
        },
        Metadata = metadata
    };
}

/// <summary>
/// Removes local absolute paths from Web-facing artifact metadata.
/// Inputs are host/guest metadata dictionaries; processing filters explicit
/// full-path keys and values that look like absolute Windows/URI paths; the
/// method returns deterministic display metadata that still preserves counts,
/// roles, statuses, and relative selectors.
/// </summary>
static IReadOnlyDictionary<string, string> ToWebArtifactMetadata(IDictionary<string, string>? metadata)
{
    var safeMetadata = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    if (metadata is null)
    {
        return safeMetadata;
    }

    foreach (var pair in metadata)
    {
        if (IsWebSafeArtifactMetadata(pair.Key, pair.Value))
        {
            safeMetadata[pair.Key] = pair.Value;
        }
    }

    return safeMetadata;
}

static bool IsWebSafeArtifactMetadata(string key, string? value)
{
    if (string.IsNullOrWhiteSpace(key))
    {
        return false;
    }

    if (key.Contains("fullPath", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("fullPath", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("hostFullPath", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("indexRoot", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    return !LooksLikeLocalAbsolutePath(value) && !ContainsEmbeddedLocalAbsolutePath(value);
}

static bool LooksLikeLocalAbsolutePath(string? value)
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

static bool ContainsEmbeddedLocalAbsolutePath(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return false;
    }

    var text = value.Trim();
    for (var index = 0; index + 2 < text.Length; index++)
    {
        if (char.IsLetter(text[index]) &&
            text[index + 1] == ':' &&
            (text[index + 2] == '\\' || text[index + 2] == '/'))
        {
            return true;
        }
    }

    for (var index = 0; index + 1 < text.Length; index++)
    {
        var isUncMarker =
            (text[index] == '\\' && text[index + 1] == '\\') ||
            (text[index] == '/' && text[index + 1] == '/');
        if (!isUncMarker)
        {
            continue;
        }

        // Keep ordinary URL values such as https://example.test/file, but
        // reject embedded UNC-style paths in JSON metadata like
        // {"selector":"\\\\host\\share\\sample.bin"}.
        if (index == 0 || text[index - 1] != ':')
        {
            return true;
        }
    }

    return false;
}

static string FirstNonEmpty(params string?[] values)
{
    foreach (var value in values)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }
    }

    return string.Empty;
}

static IResult StreamIndexedArtifact(Guid jobId, string path, SandboxJobService service)
{
    try
    {
        var artifact = service.ResolveDownloadableArtifact(jobId, path);
        var contentType = ResolveArtifactContentType(artifact);
        var fileName = SanitizeDownloadFileName(FirstNonEmpty(artifact.Name, artifact.FullPath, artifact.RelativePath, "artifact.bin"));
        return Results.File(artifact.FullPath, contentType, fileName, enableRangeProcessing: true);
    }
    catch (KeyNotFoundException ex)
    {
        return Results.NotFound(new
        {
            error = ex.Message,
            rejectionCode = "job-not-found",
            selectorPolicy = "relative-index-selectors-only"
        });
    }
    catch (ArgumentException ex)
    {
        return Results.BadRequest(new
        {
            error = $"Artifact download selector is invalid for job {jobId:D}: {ex.Message}",
            rejectionCode = "invalid-selector",
            selectorPolicy = "reject-empty-absolute-traversal",
            selectorPreview = SafeSelectorPreview(path)
        });
    }
    catch (Exception ex) when (ex is FileNotFoundException or IOException or UnauthorizedAccessException)
    {
        return Results.NotFound(new
        {
            error = $"Artifact download failed for job {jobId:D}: {ex.Message}",
            rejectionCode = ex is FileNotFoundException ? "unindexed-or-missing-artifact" : "artifact-stream-failed",
            selectorPolicy = "must-match-artifact-index",
            selectorPreview = SafeSelectorPreview(path)
        });
    }
}

static string SafeSelectorPreview(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return string.Empty;
    }

    try
    {
        var decoded = Uri.UnescapeDataString(value.Trim()).Replace('\\', '/');
        if (LooksLikeLocalAbsolutePath(decoded))
        {
            return "<absolute-path-redacted>";
        }

        var normalized = ArtifactDescriptorFactory.NormalizeRelativePath(decoded);
        return string.IsNullOrWhiteSpace(normalized) ? "<unsafe-selector-redacted>" : normalized;
    }
    catch (UriFormatException)
    {
        return "<invalid-uri-encoding>";
    }
}

/// <summary>
/// Decides whether a VirusTotal lookup result should become durable report
/// evidence. Inputs are the operator-safe lookup result; processing persists
/// only real "found" query outcomes, preserving the requirement that
/// missing/not-found VT status, missing API keys, and failed calls stay quiet
/// and do not write report/behavior-log noise.
/// </summary>
static bool ShouldPersistVirusTotalResult(VirusTotalLookupResult result)
{
    return result.CanPersistEnrichmentEvent;
}

/// <summary>
/// Chooses the newest known runbook progress snapshot. Inputs are optional
/// in-memory and durable snapshots; processing compares UpdatedAtUtc so a
/// durable runbook-progress.json written by a prior host or worker can replace
/// stale memory, while still keeping live memory if durable writes are behind.
/// </summary>
static SandboxRunbookProgressSnapshot SelectLatestRunbookProgressSnapshot(
    SandboxRunbookProgressSnapshot? memorySnapshot,
    SandboxRunbookProgressSnapshot? durableSnapshot)
{
    if (memorySnapshot is null)
    {
        return durableSnapshot ?? throw new ArgumentNullException(nameof(durableSnapshot));
    }

    if (durableSnapshot is null)
    {
        return memorySnapshot;
    }

    return durableSnapshot.UpdatedAtUtc >= memorySnapshot.UpdatedAtUtc
        ? durableSnapshot
        : memorySnapshot;
}

/// <summary>
/// Stores a progress snapshot in memory and best-effort durable state. Inputs
/// are the job service, in-memory store, and one executor snapshot; processing
/// writes only the UI-safe snapshot and deliberately ignores persistence
/// failures so live Hyper-V execution is never aborted by report-folder locks.
/// </summary>
static void UpdateRunbookProgress(
    SandboxJobService service,
    RunbookProgressStore progressStore,
    SandboxRunbookProgressSnapshot snapshot)
{
    progressStore.Update(snapshot);
    try
    {
        service.SaveRunbookProgressSnapshot(snapshot);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
    {
        // Progress polling remains live from memory; durable progress is a
        // best-effort recovery aid and must not interrupt VM execution.
    }
}

/// <summary>
/// Reads the best current runbook progress snapshot or creates the same
/// pending snapshot used by the polling endpoint. Inputs are a job id, job
/// service, and in-memory store; processing prefers the newest memory/durable
/// state and keeps the store warm for SSE subscribers; return value indicates
/// whether a UI-safe snapshot is available.
/// </summary>
static bool TryReadOrCreateRunbookProgressSnapshot(
    Guid jobId,
    SandboxJobService service,
    RunbookProgressStore progressStore,
    out SandboxRunbookProgressSnapshot? snapshot,
    out IResult? errorResult)
{
    snapshot = null;
    errorResult = null;

    var hasMemorySnapshot = progressStore.TryGet(jobId, out var memorySnapshot);
    var hasDurableSnapshot = service.TryGetRunbookProgress(jobId, out var durableSnapshot);
    if (hasMemorySnapshot || hasDurableSnapshot)
    {
        snapshot = SelectLatestRunbookProgressSnapshot(
            hasMemorySnapshot ? memorySnapshot : null,
            hasDurableSnapshot ? durableSnapshot : null);
        progressStore.Update(snapshot);
        return true;
    }

    var job = service.GetJob(jobId);
    if (job is null)
    {
        errorResult = Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
        return false;
    }

    if (job.Runbook is null)
    {
        errorResult = Results.NotFound(new { error = $"任务 {jobId:D} 还没有分析进度快照；请先创建计划并启动分析 / The job does not have a runbook progress snapshot yet." });
        return false;
    }

    snapshot = progressStore.Begin(job.Runbook, SandboxRunbookExecutionMode.DryRun);
    UpdateRunbookProgress(service, progressStore, snapshot);
    return true;
}

/// <summary>
/// Builds the WebUI progress payload while preserving the legacy raw snapshot
/// fields. Inputs are the selected snapshot and job service; processing adds
/// RunbookProgressContract durability/freshness metadata beside the raw step
/// list so older dashboard code can keep reading steps while the live monitor
/// prefers contract fields for source path, staleness, counts, and hints.
/// </summary>
static object BuildRunbookProgressApiPayload(
    SandboxJobService service,
    Guid jobId,
    SandboxRunbookProgressSnapshot snapshot)
{
    var contract = BuildRunbookProgressContract(service, jobId, snapshot);
    return BuildRunbookProgressApiPayloadFromContract(snapshot, contract);
}

static object BuildRunbookProgressApiPayloadFromContract(
    SandboxRunbookProgressSnapshot snapshot,
    RunbookProgressContract contract)
{
    return new
    {
        snapshot.JobId,
        snapshot.TargetVmName,
        snapshot.Mode,
        snapshot.State,
        snapshot.TotalSteps,
        snapshot.CompletedSteps,
        snapshot.ExecutedSteps,
        snapshot.CurrentStepIndex,
        snapshot.CurrentStepId,
        snapshot.CurrentStepTitle,
        snapshot.CurrentPhase,
        snapshot.CurrentCategory,
        snapshot.ProgressPercent,
        snapshot.Success,
        snapshot.Message,
        snapshot.StartedAtUtc,
        snapshot.UpdatedAtUtc,
        snapshot.Duration,
        snapshot.Steps,
        contract.DurableSourcePath,
        contract.SnapshotUpdatedAtUtc,
        contract.SnapshotAge,
        contract.StaleThreshold,
        contract.IsStale,
        contract.LatestStepSummary,
        contract.CompletedStepCount,
        contract.FailedStepCount,
        contract.RunningStepCount,
        contract.OperatorHintsZh,
        ProgressContract = contract
    };
}

static RunbookProgressContract BuildRunbookProgressContract(
    SandboxJobService service,
    Guid jobId,
    SandboxRunbookProgressSnapshot snapshot)
{
    var durableSourcePath = ResolveRunbookProgressDurableSourcePath(service.GetJob(jobId));
    return RunbookProgressContract.FromSnapshot(
        snapshot,
        durableSourcePath,
        DateTimeOffset.UtcNow);
}

static string? ResolveRunbookProgressDurableSourcePath(AnalysisJob? job)
{
    if (job is null)
    {
        return null;
    }

    var progressPath = ResolveRunbookProgressPath(job);
    var executionPath = NormalizeDurableSourcePath(job.RunbookExecutionResultPath);
    if (!string.IsNullOrWhiteSpace(progressPath) && File.Exists(progressPath))
    {
        return progressPath;
    }

    if (!string.IsNullOrWhiteSpace(executionPath) && File.Exists(executionPath))
    {
        return executionPath;
    }

    return progressPath ?? executionPath;
}

static string? ResolveRunbookProgressPath(AnalysisJob job)
{
    var sibling = FirstNonEmpty(
        job.RunbookExecutionResultPath,
        job.JsonReportPath,
        job.HtmlReportPath,
        job.HtmlReportZhPath,
        job.HtmlReportEnPath);
    if (string.IsNullOrWhiteSpace(sibling))
    {
        return null;
    }

    try
    {
        var directory = Path.GetDirectoryName(sibling);
        return string.IsNullOrWhiteSpace(directory)
            ? null
            : Path.GetFullPath(Path.Combine(directory, "runbook-progress.json"));
    }
    catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
    {
        return null;
    }
}

static string? NormalizeDurableSourcePath(string? path)
{
    if (string.IsNullOrWhiteSpace(path))
    {
        return null;
    }

    try
    {
        return Path.GetFullPath(path);
    }
    catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
    {
        return path;
    }
}

/// <summary>
/// Streams UI-safe runbook/background progress with Server-Sent Events.
/// Inputs are route/query values, HTTP context, and WebUI stores; processing
/// subscribes to the bounded progress channel and uses occasional heartbeats
/// only to refresh background terminal/import state; the function writes no
/// VirusTotal data and exits on client disconnect, terminal state, or max age.
/// </summary>
static async Task WriteRunbookProgressStreamAsync(
    Guid jobId,
    int? heartbeatMs,
    int? maxSeconds,
    HttpContext context,
    SandboxJobService service,
    RunbookProgressStore progressStore,
    RunbookBackgroundExecutionStore backgroundStore)
{
    var cancellationToken = context.RequestAborted;
    if (!TryReadOrCreateRunbookProgressSnapshot(jobId, service, progressStore, out var currentProgress, out var errorResult) ||
        currentProgress is null)
    {
        await (errorResult ?? Results.NotFound(new { error = $"Job {jobId:D} was not found." })).ExecuteAsync(context);
        return;
    }

    var heartbeatInterval = TimeSpan.FromMilliseconds(Math.Clamp(heartbeatMs ?? 1500, 500, 30000));
    var maxStreamAge = TimeSpan.FromSeconds(Math.Clamp(maxSeconds ?? 1800, 30, 7200));
    var streamDeadline = DateTimeOffset.UtcNow + maxStreamAge;

    context.Response.StatusCode = StatusCodes.Status200OK;
    context.Response.ContentType = "text/event-stream; charset=utf-8";
    context.Response.Headers["Cache-Control"] = "no-cache";
    context.Response.Headers["X-Accel-Buffering"] = "no";
    await context.Response.WriteAsync("retry: 2500\n\n", cancellationToken);

    await using var subscription = progressStore.Subscribe(jobId);
    var background = backgroundStore.Get(jobId);
    var eventName = ResolveRunbookProgressStreamEventName(currentProgress, background, heartbeat: false);
    await WriteRunbookProgressStreamFrameAsync(
        context.Response,
        eventName,
        BuildRunbookProgressStreamPayload(jobId, currentProgress, background, eventName, service),
        cancellationToken);

    if (IsRunbookProgressStreamTerminal(currentProgress, background))
    {
        return;
    }

    var wroteTerminal = false;
    try
    {
        while (!cancellationToken.IsCancellationRequested && DateTimeOffset.UtcNow < streamDeadline)
        {
            using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var readTask = subscription.Reader.WaitToReadAsync(waitCancellation.Token).AsTask();
            var delayTask = Task.Delay(heartbeatInterval, cancellationToken);
            var completedTask = await Task.WhenAny(readTask, delayTask).ConfigureAwait(false);
            var heartbeat = completedTask != readTask;

            if (heartbeat)
            {
                waitCancellation.Cancel();
                try
                {
                    await readTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    // Heartbeat won the race; the next loop creates a fresh
                    // bounded wait so there are no abandoned channel waiters.
                }
            }

            if (!heartbeat && !await readTask.ConfigureAwait(false))
            {
                break;
            }

            if (!heartbeat)
            {
                while (subscription.Reader.TryRead(out var progressUpdate))
                {
                    currentProgress = SelectLatestRunbookProgressSnapshot(currentProgress, progressUpdate);
                }
            }
            else if (TryReadOrCreateRunbookProgressSnapshot(jobId, service, progressStore, out var refreshedProgress, out _) &&
                refreshedProgress is not null)
            {
                currentProgress = SelectLatestRunbookProgressSnapshot(currentProgress, refreshedProgress);
            }

            background = backgroundStore.Get(jobId);
            eventName = ResolveRunbookProgressStreamEventName(currentProgress, background, heartbeat);
            await WriteRunbookProgressStreamFrameAsync(
                context.Response,
                eventName,
                BuildRunbookProgressStreamPayload(jobId, currentProgress, background, eventName, service),
                cancellationToken);

            if (IsRunbookProgressStreamTerminal(currentProgress, background))
            {
                wroteTerminal = true;
                break;
            }
        }

        if (!wroteTerminal && !cancellationToken.IsCancellationRequested && DateTimeOffset.UtcNow >= streamDeadline)
        {
            background = backgroundStore.Get(jobId);
            await WriteRunbookProgressStreamFrameAsync(
                context.Response,
                "timeout",
                BuildRunbookProgressStreamPayload(jobId, currentProgress, background, "timeout", service),
                cancellationToken);
        }
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
    {
        // Browser navigation or EventSource.close() cancelled the request.
    }
}

/// <summary>
/// Builds the compact stream payload consumed by LiveEventsPage. The background
/// snapshot is intentionally sanitized and excludes runbook execution command
/// text, stdout, stderr, and PowerShell details.
/// </summary>
static object BuildRunbookProgressStreamPayload(
    Guid jobId,
    SandboxRunbookProgressSnapshot progress,
    RunbookBackgroundExecutionSnapshot background,
    string eventName,
    SandboxJobService service)
{
    var state = ResolveRunbookProgressStreamState(progress, background);
    var durableProgress = BuildRunbookProgressContract(service, jobId, progress);
    return new
    {
        SchemaVersion = 1,
        Transport = "sse",
        Event = eventName,
        JobId = jobId,
        GeneratedAtUtc = DateTimeOffset.UtcNow,
        State = state,
        Terminal = IsRunbookProgressStreamTerminal(progress, background),
        TerminalKind = state is "failed" or "canceled" ? "error" : state is "completed" ? "final" : null,
        Message = ResolveRunbookProgressStreamMessage(progress, background),
        ProgressPercent = ComputeRunbookProgressPercent(progress),
        CurrentStep = BuildRunbookProgressStreamCurrentStep(progress, durableProgress),
        Progress = BuildRunbookProgressApiPayloadFromContract(progress, durableProgress),
        DurableProgress = durableProgress,
        Background = BuildSafeRunbookBackgroundSnapshot(background)
    };
}

static object BuildSafeRunbookBackgroundSnapshot(RunbookBackgroundExecutionSnapshot snapshot)
{
    return new
    {
        snapshot.JobId,
        snapshot.Live,
        snapshot.ImportGuestEvents,
        snapshot.Accepted,
        snapshot.State,
        snapshot.Success,
        snapshot.Message,
        snapshot.StartedAtUtc,
        snapshot.UpdatedAtUtc,
        snapshot.Duration,
        snapshot.GuestImportSucceeded,
        snapshot.GuestImportMessage,
        snapshot.DurableSourcePath,
        snapshot.DurableProgressSourcePath,
        snapshot.DurableExecutionSourcePath,
        snapshot.SnapshotGeneratedAtUtc,
        snapshot.SnapshotAge,
        snapshot.StaleThreshold,
        snapshot.IsStale,
        snapshot.CompletedStepCount,
        snapshot.FailedStepCount,
        snapshot.RunningStepCount,
        snapshot.LatestStepSummary,
        snapshot.OperatorHintsZh,
        Job = BuildSafeRunbookBackgroundJobSnapshot(snapshot.Job)
    };
}

static object? BuildSafeRunbookBackgroundJobSnapshot(AnalysisJob? job)
{
    return job is null
        ? null
        : new
        {
            job.JobId,
            Status = job.Status.ToString(),
            job.JsonReportPath,
            job.HtmlReportPath,
            job.HtmlReportZhPath,
            job.HtmlReportEnPath,
            job.GuestEventsPath,
            job.RunbookExecutionResultPath
        };
}

static object? BuildRunbookProgressStreamCurrentStep(
    SandboxRunbookProgressSnapshot progress,
    RunbookProgressContract durableProgress)
{
    if (durableProgress.LatestStepSummary is not null)
    {
        var latest = durableProgress.LatestStepSummary;
        return new
        {
            latest.StepIndex,
            latest.StepNumber,
            latest.TotalSteps,
            latest.Ordinal,
            latest.StepId,
            latest.Title,
            DisplayText = string.IsNullOrWhiteSpace(latest.Title)
                ? $"{latest.Ordinal} {latest.StepId}"
                : $"{latest.Ordinal} {latest.Title}",
            latest.State,
            latest.Phase,
            latest.Category,
            StateMeaning = "UI-safe latest runbook step summary from RunbookProgressContract; command text/stdout/stderr are intentionally excluded.",
            Source = "runbook-progress-contract-latest-step-summary",
            ProgressState = progress.State,
            progress.CompletedSteps,
            progress.ExecutedSteps,
            latest.StartedAtUtc,
            latest.Duration,
            latest.ExitCode,
            latest.Message,
            latest.RemediationHintZh
        };
    }

    var steps = progress.Steps;
    var totalSteps = Math.Max(progress.TotalSteps, steps.Count);
    var runningStep = steps.FirstOrDefault(step => string.Equals(step.State, SandboxRunbookProgressStates.Running, StringComparison.OrdinalIgnoreCase));
    var indexedStep = progress.CurrentStepIndex is >= 0 && progress.CurrentStepIndex < steps.Count
        ? steps[progress.CurrentStepIndex.Value]
        : null;
    var source = runningStep is not null
        ? "running-step"
        : indexedStep is not null
            ? "current-step-index"
            : "first-pending-step";
    var currentStep = runningStep ?? indexedStep ?? steps.FirstOrDefault(step => string.Equals(step.State, SandboxRunbookProgressStates.Pending, StringComparison.OrdinalIgnoreCase));
    if (currentStep is null)
    {
        return null;
    }

    return new
    {
        currentStep.StepIndex,
        StepNumber = currentStep.StepIndex + 1,
        TotalSteps = totalSteps,
        Ordinal = $"{currentStep.StepIndex + 1}/{Math.Max(totalSteps, currentStep.StepIndex + 1)}",
        currentStep.StepId,
        currentStep.Title,
        DisplayText = BuildRunbookCurrentStepDisplay(currentStep, totalSteps),
        currentStep.State,
        currentStep.Phase,
        currentStep.Category,
        StateMeaning = "UI-safe real runbook step status from the progress stream; command text/stdout/stderr are intentionally excluded.",
        Source = source,
        ProgressState = progress.State,
        progress.CompletedSteps,
        progress.ExecutedSteps,
        currentStep.StartedAtUtc,
        currentStep.Duration,
        currentStep.ExitCode,
        currentStep.Message,
        currentStep.RemediationHintZh
    };
}

static string BuildRunbookCurrentStepDisplay(SandboxRunbookStepProgressSnapshot step, int totalSteps)
{
    var ordinal = $"{step.StepIndex + 1}/{Math.Max(totalSteps, step.StepIndex + 1)}";
    return string.IsNullOrWhiteSpace(step.Title)
        ? $"{ordinal} {step.StepId}"
        : $"{ordinal} {step.Title}";
}

static string ResolveRunbookProgressStreamEventName(
    SandboxRunbookProgressSnapshot progress,
    RunbookBackgroundExecutionSnapshot background,
    bool heartbeat)
{
    var state = ResolveRunbookProgressStreamState(progress, background);
    return state switch
    {
        "failed" or "canceled" => "failed",
        "completed" => "final",
        _ => heartbeat ? "heartbeat" : "snapshot"
    };
}

static string ResolveRunbookProgressStreamState(
    SandboxRunbookProgressSnapshot progress,
    RunbookBackgroundExecutionSnapshot background)
{
    var backgroundState = (background.State ?? string.Empty).Trim().ToLowerInvariant();
    var progressState = (progress.State ?? string.Empty).Trim().ToLowerInvariant();
    if (backgroundState is RunbookBackgroundExecutionStore.Failed ||
        progressState is SandboxRunbookProgressStates.Failed or SandboxRunbookProgressStates.Canceled ||
        progress.Success == false)
    {
        return progressState == SandboxRunbookProgressStates.Canceled ? "canceled" : "failed";
    }

    if (backgroundState is RunbookBackgroundExecutionStore.Completed ||
        progressState is SandboxRunbookProgressStates.Completed ||
        progress.Success == true)
    {
        return "completed";
    }

    if (backgroundState is RunbookBackgroundExecutionStore.Running or RunbookBackgroundExecutionStore.Queued)
    {
        return backgroundState;
    }

    return string.IsNullOrWhiteSpace(progressState) ? backgroundState : progressState;
}

static string? ResolveRunbookProgressStreamMessage(
    SandboxRunbookProgressSnapshot progress,
    RunbookBackgroundExecutionSnapshot background)
{
    if (string.Equals(background.State, RunbookBackgroundExecutionStore.Failed, StringComparison.OrdinalIgnoreCase) &&
        !string.IsNullOrWhiteSpace(background.Message))
    {
        return background.Message;
    }

    return !string.IsNullOrWhiteSpace(progress.Message)
        ? progress.Message
        : background.Message;
}

static bool IsRunbookProgressStreamTerminal(
    SandboxRunbookProgressSnapshot progress,
    RunbookBackgroundExecutionSnapshot background)
{
    var state = ResolveRunbookProgressStreamState(progress, background);
    return state is "completed" or "failed" or "canceled";
}

static int ComputeRunbookProgressPercent(SandboxRunbookProgressSnapshot progress)
{
    if (progress.ProgressPercent > 0)
    {
        return Math.Clamp(progress.ProgressPercent, 0, 100);
    }

    if (string.Equals(progress.State, SandboxRunbookProgressStates.Completed, StringComparison.OrdinalIgnoreCase) ||
        progress.Success == true)
    {
        return 100;
    }

    var total = Math.Max(progress.TotalSteps, progress.Steps.Count);
    if (total <= 0)
    {
        return 0;
    }

    var state = (progress.State ?? string.Empty).Trim().ToLowerInvariant();
    if (state == SandboxRunbookProgressStates.Completed || progress.Success == true)
    {
        return 100;
    }

    var hasRunning = progress.Steps.Any(step => string.Equals(step.State, SandboxRunbookProgressStates.Running, StringComparison.OrdinalIgnoreCase));
    var currentIndex = progress.CurrentStepIndex ?? -1;
    var runningCredit = hasRunning ? 0.45d : currentIndex >= 0 && progress.CompletedSteps <= currentIndex ? 0.25d : 0d;
    var numerator = Math.Max(progress.CompletedSteps, Math.Max(currentIndex, 0)) + runningCredit;
    var percent = (int)Math.Round(Math.Min(total, numerator) / total * 100d, MidpointRounding.AwayFromZero);
    var floor = state == SandboxRunbookProgressStates.Running || hasRunning ? 3 : 0;
    return Math.Clamp(Math.Max(floor, percent), 0, 100);
}

static async Task WriteRunbookProgressStreamFrameAsync(
    HttpResponse response,
    string eventName,
    object payload,
    CancellationToken cancellationToken)
{
    var data = JsonSerializer.Serialize(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    await response.WriteAsync($"event: {eventName}\n", cancellationToken);
    await response.WriteAsync($"data: {data}\n\n", cancellationToken);
    await response.Body.FlushAsync(cancellationToken);
}

/// <summary>
/// Builds validated executor options for blocking and background runbook paths.
/// Inputs are the planned job, request, config, and progress store; processing
/// performs the same live credential preflight and starts a UI-safe progress
/// snapshot; the function returns an HTTP error result when execution should
/// not start.
/// </summary>
static IResult? TryPrepareRunbookExecution(
    AnalysisJob job,
    RunbookExecuteRequest request,
    SandboxJobService service,
    SandboxConfig currentConfig,
    RunbookProgressStore progressStore,
    out SandboxRunbookExecutionOptions options)
{
    options = new SandboxRunbookExecutionOptions();
    if (job.Runbook is null)
    {
        return Results.BadRequest(new { error = $"任务 {job.JobId:D} 没有可执行流程；请重新上传或重新创建分析计划 / Job does not have a runbook; recreate the dry-run plan for the selected executable." });
    }

    var mode = request.Live ? SandboxRunbookExecutionMode.Live : SandboxRunbookExecutionMode.DryRun;
    var initialSnapshot = progressStore.Begin(job.Runbook, mode);
    UpdateRunbookProgress(service, progressStore, initialSnapshot);

    var environmentVariables = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    if (request.Live)
    {
        var secretName = string.IsNullOrWhiteSpace(currentConfig.Guest.PasswordSecretName)
            ? "KSWORDBOX_GUEST_PASSWORD"
            : currentConfig.Guest.PasswordSecretName.Trim();

        if (!TryResolveEnvironmentSecret(secretName, out var guestPassword))
        {
            var failureSnapshot = progressStore.Fail(
                job.Runbook,
                mode,
                $"实时虚拟机分析需要来宾密码环境变量 '{secretName}'，请在当前进程、用户或机器环境中设置 / Live runbook needs guest credential secret in the WebUI process, User, or Machine environment.");
            UpdateRunbookProgress(service, progressStore, failureSnapshot);
            return Results.BadRequest(new
            {
                error = $"实时虚拟机分析需要来宾密码环境变量 '{secretName}'。最省事的做法：运行 .\\install.ps1，选择重置密码，然后重启 .\\run.ps1 -Mode WebUI / Live runbook needs the guest credential secret. Run install.ps1, choose password reset, then restart run.ps1 -Mode WebUI."
            });
        }

        Environment.SetEnvironmentVariable(secretName, guestPassword, EnvironmentVariableTarget.Process);
        environmentVariables[secretName] = guestPassword;
    }

    options = new SandboxRunbookExecutionOptions
    {
        Mode = mode,
        StepTimeout = TimeSpan.FromSeconds(Math.Clamp(request.StepTimeoutSeconds, 1, 7200)),
        RequireElevatedPowerShell = true,
        WorkingDirectory = Directory.GetCurrentDirectory(),
        EnvironmentVariables = environmentVariables,
        ProgressSink = new Progress<SandboxRunbookProgressSnapshot>(snapshot => UpdateRunbookProgress(service, progressStore, snapshot))
    };
    return null;
}

/// <summary>
/// Executes a runbook and performs the existing automatic guest import policy.
/// Inputs are job id, request, job service, executor, and prepared options;
/// processing persists execution, optionally imports guest events on successful
/// live runs, and returns a compact outcome suitable for blocking or background
/// API responses.
/// </summary>
static async Task<RunbookExecutionOutcome> ExecuteRunbookAndImportAsync(
    Guid jobId,
    RunbookExecuteRequest request,
    SandboxJobService service,
    IRunbookExecutor executor,
    SandboxRunbookExecutionOptions options)
{
    var job = service.GetJob(jobId) ?? throw new KeyNotFoundException($"未找到任务 {jobId:D}，无法开始执行 / Job was not found before execution.");
    if (job.Runbook is null)
    {
        throw new InvalidOperationException($"任务 {jobId:D} 没有可执行流程 / Job does not have a runbook.");
    }

    var result = await executor.ExecuteAsync(job.Runbook, options).ConfigureAwait(false);
    var updatedJob = service.SaveRunbookExecutionResult(jobId, result);
    var guestImportSucceeded = false;
    string? guestImportMessage = null;

    if (request.ImportGuestEvents && request.Live && result.Success)
    {
        try
        {
            updatedJob = service.ImportGuestEvents(jobId);
            guestImportSucceeded = true;
            guestImportMessage = $"已导入来宾事件：{updatedJob.GuestEventsPath} / Guest events imported.";
        }
        catch (Exception ex) when (ex is DirectoryNotFoundException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            guestImportMessage = $"分析流程已结束，但未能自动导入来宾事件：{ex.Message} / Runbook completed, but guest events were not imported automatically.";
        }
    }

    return new RunbookExecutionOutcome(result, updatedJob, guestImportSucceeded, guestImportMessage);
}

/// <summary>
/// Starts one runbook in the WebUI background runner and returns a serializable
/// summary instead of an HTTP result. Inputs mirror the public start endpoint;
/// processing keeps all validation and active-run handling in one place so the
/// upload-and-start endpoint cannot drift from manual job start behavior.
/// </summary>
static RunbookBackgroundStartAttempt TryStartBackgroundRunbook(
    Guid jobId,
    RunbookExecuteRequest request,
    SandboxJobService service,
    IRunbookExecutor executor,
    SandboxConfig currentConfig,
    RunbookProgressStore progressStore,
    RunbookBackgroundExecutionStore backgroundStore)
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return new RunbookBackgroundStartAttempt
        {
            Attempted = true,
            Accepted = false,
            State = RunbookBackgroundExecutionStore.NotStarted,
            Message = $"未找到任务 {jobId:D}；请先上传样本并创建分析计划 / Job was not found; create a dry-run plan before starting a runbook.",
            StatusCode = StatusCodes.Status404NotFound
        };
    }

    if (job.Runbook is null)
    {
        return new RunbookBackgroundStartAttempt
        {
            Attempted = true,
            Accepted = false,
            State = RunbookBackgroundExecutionStore.NotStarted,
            Message = $"任务 {jobId:D} 没有可执行流程；请重新上传或重新创建分析计划 / Job does not have a runbook; recreate the dry-run plan for the selected executable.",
            StatusCode = StatusCodes.Status400BadRequest
        };
    }

    var existingBackground = backgroundStore.Get(jobId);
    if (string.Equals(existingBackground.State, RunbookBackgroundExecutionStore.Queued, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(existingBackground.State, RunbookBackgroundExecutionStore.Running, StringComparison.OrdinalIgnoreCase))
    {
        var activeSnapshot = existingBackground with
        {
            Accepted = false,
            Message = "该任务的分析流程已经在排队或运行中 / Runbook execution is already queued or running for this job."
        };
        return new RunbookBackgroundStartAttempt
        {
            Attempted = true,
            Accepted = false,
            State = activeSnapshot.State,
            Message = activeSnapshot.Message,
            StatusCode = StatusCodes.Status200OK,
            Snapshot = activeSnapshot
        };
    }

    var prepareError = TryPrepareRunbookExecution(job, request, service, currentConfig, progressStore, out var options);
    if (prepareError is not null)
    {
        var modeText = request.Live ? "实时虚拟机分析 / live VM analysis" : "计划演练 / dry-run verification";
        return new RunbookBackgroundStartAttempt
        {
            Attempted = true,
            Accepted = false,
            State = RunbookBackgroundExecutionStore.Failed,
            Message = $"分析流程预检查失败（{modeText}）。实时模式请检查来宾密码、Hyper-V 就绪状态和 VM 配置；打开执行流程页查看安全失败步骤 / Runbook preflight failed. Verify guest credential, Hyper-V readiness, and VM configuration.",
            StatusCode = StatusCodes.Status400BadRequest
        };
    }

    var accepted = backgroundStore.TryStart(
        jobId,
        request.Live,
        request.ImportGuestEvents,
        () => ExecuteRunbookAndImportAsync(jobId, request, service, executor, options),
        out var snapshot);

    return new RunbookBackgroundStartAttempt
    {
        Attempted = true,
        Accepted = accepted,
        State = snapshot.State,
        Message = snapshot.Message,
        StatusCode = accepted ? StatusCodes.Status202Accepted : StatusCodes.Status200OK,
        Snapshot = snapshot
    };
}

/// <summary>
/// Streams live raw-event snapshots to a browser with Server-Sent Events.
/// Inputs are the route job ID, optional paging/interval query values, the HTTP
/// context, and the job service; processing repeatedly reads current host and
/// guest artifacts without rule classification; the function returns no value
/// and exits when the browser cancels the request.
/// </summary>
static async Task WriteLiveEventStreamAsync(
    Guid jobId,
    int? offset,
    int? take,
    int? intervalMs,
    HttpContext context,
    SandboxJobService service)
{
    var cancellationToken = context.RequestAborted;
    var currentOffset = Math.Max(0, offset ?? 0);
    var pageSize = Math.Clamp(take ?? 100, 1, 500);
    var pollInterval = TimeSpan.FromMilliseconds(Math.Clamp(intervalMs ?? 2000, 500, 10000));

    LiveEventSnapshot initialSnapshot;
    try
    {
        initialSnapshot = service.GetLiveEvents(jobId, currentOffset, pageSize);
    }
    catch (KeyNotFoundException ex)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        await context.Response.WriteAsJsonAsync(new { error = ex.Message }, cancellationToken);
        return;
    }

    context.Response.StatusCode = StatusCodes.Status200OK;
    context.Response.ContentType = "text/event-stream; charset=utf-8";
    context.Response.Headers["Cache-Control"] = "no-cache";
    context.Response.Headers["X-Accel-Buffering"] = "no";

    var sourceSignature = BuildLiveSourceSignature(initialSnapshot.Sources);
    try
    {
        await WriteLiveEventSnapshotAsync(context.Response, initialSnapshot, cancellationToken);
        currentOffset = initialSnapshot.NextOffset;

        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(pollInterval, cancellationToken);

            var snapshot = service.GetLiveEvents(jobId, currentOffset, pageSize);
            var nextSignature = BuildLiveSourceSignature(snapshot.Sources);
            if (!string.Equals(nextSignature, sourceSignature, StringComparison.Ordinal))
            {
                snapshot = service.GetLiveEvents(jobId, 0, pageSize);
                sourceSignature = nextSignature;
            }

            await WriteLiveEventSnapshotAsync(context.Response, snapshot, cancellationToken);
            currentOffset = snapshot.NextOffset;
        }
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
    {
        // Browser navigation or EventSource.close() cancels the request. There
        // is no response body to return after an SSE client disconnects.
    }
}

/// <summary>
/// Builds a stable signature for live-event source paths.
/// Inputs are source artifact paths from a snapshot; processing sorts them
/// ordinal-ignore-case; the function returns a compact comparison key used to
/// reset live cursors when guest artifacts replace planning-only events.
/// </summary>
static string BuildLiveSourceSignature(IEnumerable<string> sources)
{
    return string.Join("\n", sources.OrderBy(source => source, StringComparer.OrdinalIgnoreCase));
}

/// <summary>
/// Writes one Server-Sent Events frame for a live snapshot.
/// Inputs are the HTTP response, snapshot payload, and cancellation token;
/// processing serializes with ASP.NET-style camelCase JSON and flushes the
/// stream; the function returns no value.
/// </summary>
static async Task WriteLiveEventSnapshotAsync(HttpResponse response, LiveEventSnapshot snapshot, CancellationToken cancellationToken)
{
    var data = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    await response.WriteAsync("event: snapshot\n", cancellationToken);
    await response.WriteAsync($"data: {data}\n\n", cancellationToken);
    await response.Body.FlushAsync(cancellationToken);
}

/// <summary>
/// Reads a persisted runbook execution record for the dedicated execution-flow
/// page. Inputs are an optional path recorded on a job; processing validates
/// the file exists and deserializes camelCase JSON; the function returns null
/// when the job has not executed yet or the record is unreadable.
/// </summary>
static SandboxRunbookExecutionResult? TryReadRunbookExecutionResult(string? resultPath)
{
    if (string.IsNullOrWhiteSpace(resultPath) || !File.Exists(resultPath))
    {
        return null;
    }

    try
    {
        var json = File.ReadAllText(resultPath);
        return JsonSerializer.Deserialize<SandboxRunbookExecutionResult>(
            json,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }
    catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
    {
        return null;
    }
}

/// <summary>
/// Resolves a named secret from process, user, or machine environment scopes.
/// Inputs are the configured secret variable name; processing checks the same
/// scopes used by runbook preflight without logging the secret; the function
/// returns true plus the secret value when available.
/// </summary>
static bool TryResolveEnvironmentSecret(string secretName, out string value)
{
    var scopes = new[]
    {
        EnvironmentVariableTarget.Process,
        EnvironmentVariableTarget.User,
        EnvironmentVariableTarget.Machine
    };

    foreach (var scope in scopes)
    {
        var candidate = Environment.GetEnvironmentVariable(secretName, scope);
        if (!string.IsNullOrWhiteSpace(candidate))
        {
            value = candidate;
            return true;
        }
    }

    value = string.Empty;
    return false;
}

/// <summary>
/// Finds the repository root by walking upward from the Web content root.
/// The input is a project directory, processing looks for the solution file,
/// and the function returns the best matching absolute path.
/// </summary>
static string ResolveRepositoryRoot(string contentRoot)
{
    var directory = new DirectoryInfo(contentRoot);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(directory.FullName, "KSwordSandbox.sln")))
        {
            return directory.FullName;
        }

        directory = directory.Parent;
    }

    return contentRoot;
}

/// <summary>
/// Resolves the HTML report file recorded for a job without accepting a path
/// from the browser. Inputs are a job ID and job service, processing validates
/// job existence, recorded path shape, extension, and file existence, and the
/// function returns true plus a full path or false plus an HTTP error result.
/// </summary>
static bool TryResolveHtmlReportPath(Guid jobId, string? lang, SandboxJobService service, out string reportPath, out IResult? errorResult)
{
    reportPath = string.Empty;
    errorResult = null;

    var job = service.GetJob(jobId);
    if (job is null)
    {
        errorResult = Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
        return false;
    }

    var requestedPath = ResolveLocalizedReportPath(job, lang);
    if (string.IsNullOrWhiteSpace(requestedPath))
    {
        errorResult = Results.NotFound(new { error = $"Job {jobId:D} does not have an HTML report path yet; create a dry-run plan first." });
        return false;
    }

    try
    {
        reportPath = Path.GetFullPath(requestedPath);
    }
    catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
    {
        errorResult = Results.BadRequest(new { error = $"Recorded HTML report path for job {jobId:D} is invalid ('{requestedPath}'): {ex.Message}" });
        reportPath = string.Empty;
        return false;
    }

    var extension = Path.GetExtension(reportPath);
    if (!string.Equals(extension, ".html", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(extension, ".htm", StringComparison.OrdinalIgnoreCase))
    {
        errorResult = Results.BadRequest(new { error = $"Recorded report path for job {jobId:D} is not an HTML file: {reportPath}" });
        reportPath = string.Empty;
        return false;
    }

    if (!File.Exists(reportPath))
    {
        errorResult = Results.NotFound(new { error = $"HTML report file was not found at the recorded path for job {jobId:D}: {reportPath}" });
        reportPath = string.Empty;
        return false;
    }

    return true;
}

/// <summary>
/// Selects the best report file for a requested language.
/// Inputs are the recorded job and optional lang query string; processing maps
/// zh/zh-CN/cn to report.zh.html, en to report.en.html, and falls back to the
/// compatibility report.html; the function returns a recorded path or null.
/// </summary>
static string? ResolveLocalizedReportPath(AnalysisJob job, string? lang)
{
    var normalized = string.IsNullOrWhiteSpace(lang) ? string.Empty : lang.Trim().ToLowerInvariant();
    if ((normalized is "zh" or "zh-cn" or "cn" or "chinese") && !string.IsNullOrWhiteSpace(job.HtmlReportZhPath))
    {
        return job.HtmlReportZhPath;
    }

    if ((normalized is "en" or "en-us" or "english") && !string.IsNullOrWhiteSpace(job.HtmlReportEnPath))
    {
        return job.HtmlReportEnPath;
    }

    return job.HtmlReportPath ?? job.HtmlReportZhPath ?? job.HtmlReportEnPath;
}

/// <summary>
/// Builds a normal sandbox submission from the one-click upload form.
/// Inputs are the saved sample plus multipart fields; processing applies the
/// same VM/artifact overrides as the JSON planning endpoint; the returned
/// submission is ready for SandboxJobService.Plan.
/// </summary>
static SandboxSubmission BuildSubmissionFromUploadForm(ExecutableCandidate candidate, IFormCollection form, SandboxConfig config)
{
    return new SandboxSubmission
    {
        SamplePath = candidate.FullPath,
        DisplayName = candidate.FileName,
        DurationSeconds = ReadFormInt(form, "durationSeconds", config.Analysis.DefaultDurationSeconds, 1, config.Analysis.MaxDurationSeconds),
        DryRun = true,
        GoldenVmName = ReadFormString(form, "goldenVmName"),
        GoldenSnapshotName = ReadFormString(form, "goldenSnapshotName"),
        GuestUserName = ReadFormString(form, "guestUserName"),
        GuestWorkingDirectory = ReadFormString(form, "guestWorkingDirectory"),
        GuestPayloadRoot = ReadFormString(form, "guestPayloadRoot"),
        UseMockCollector = ReadFormBoolNullable(form, "useMockCollector"),
        CollectDroppedFiles = ReadFormBoolNullable(form, "collectDroppedFiles"),
        CaptureScreenshots = ReadFormBoolNullable(form, "captureScreenshots"),
        CaptureMemoryDumps = ReadFormBoolNullable(form, "captureMemoryDumps"),
        CapturePacketCapture = ReadFormBoolNullable(form, "capturePacketCapture")
    };
}

/// <summary>
/// Builds the background execution request for one-click upload analysis.
/// Inputs are multipart fields from the browser; processing defaults to live
/// VM mode with guest import enabled; the returned request is shared with the
/// normal background runbook start endpoint.
/// </summary>
static RunbookExecuteRequest BuildRunbookExecuteRequestFromUploadForm(IFormCollection form)
{
    return new RunbookExecuteRequest
    {
        Live = ReadFormBool(form, "live", true),
        StepTimeoutSeconds = ReadFormInt(form, "stepTimeoutSeconds", 1800, 1, 7200),
        ImportGuestEvents = ReadFormBool(form, "importGuestEvents", true)
    };
}

static string? ReadFormString(IFormCollection form, string key)
{
    return form.TryGetValue(key, out var values) && !string.IsNullOrWhiteSpace(values.ToString())
        ? values.ToString().Trim()
        : null;
}

static int ReadFormInt(IFormCollection form, string key, int fallback, int min, int max)
{
    if (form.TryGetValue(key, out var values) &&
        int.TryParse(values.ToString(), out var parsed))
    {
        return Math.Clamp(parsed, min, max);
    }

    return Math.Clamp(fallback, min, max);
}

static bool? ReadFormBoolNullable(IFormCollection form, string key)
{
    return form.TryGetValue(key, out var values)
        ? ParseFormBool(values.ToString())
        : null;
}

static bool ReadFormBool(IFormCollection form, string key, bool fallback)
{
    return form.TryGetValue(key, out var values)
        ? ParseFormBool(values.ToString()) ?? fallback
        : fallback;
}

static bool? ParseFormBool(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    var normalized = value.Trim().ToLowerInvariant();
    return normalized switch
    {
        "1" or "true" or "yes" or "on" => true,
        "0" or "false" or "no" or "off" => false,
        _ => null
    };
}

/// <summary>
/// Saves one uploaded executable into the configured runtime upload folder.
/// Inputs are the HTTP multipart request and sandbox config, processing
/// validates extension and size limits, and the function returns candidate
/// metadata with a host-visible path suitable for job planning.
/// </summary>
static async Task<ExecutableCandidate> SaveUploadedExecutableAsync(IFormCollection form, SandboxConfig config)
{
    if (form.Files.Count == 0)
    {
        throw new ArgumentException("Upload must use multipart/form-data with an executable file field named 'sample'.");
    }

    var file = form.Files.GetFile("sample") ?? form.Files.FirstOrDefault();
    if (file is null)
    {
        throw new ArgumentException("No uploaded file was provided; choose one .exe in the 'sample' multipart field.");
    }

    if (file.Length <= 0)
    {
        throw new InvalidOperationException($"Uploaded file '{file.FileName}' is empty.");
    }

    if (file.Length > config.Analysis.MaxSampleBytes)
    {
        throw new InvalidOperationException($"Uploaded file '{file.FileName}' size {file.Length} bytes exceeds limit {config.Analysis.MaxSampleBytes} bytes.");
    }

    var originalName = Path.GetFileName(file.FileName);
    if (!string.Equals(Path.GetExtension(originalName), ".exe", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException($"Only .exe uploads are accepted in the v1 WebUI; received '{originalName}'.");
    }

    var uploadRoot = Path.Combine(config.Paths.RuntimeRoot, "uploads");
    Directory.CreateDirectory(uploadRoot);
    var storedName = $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}-{SanitizeFileName(originalName)}";
    var storedPath = Path.Combine(uploadRoot, storedName);
    await using (var target = File.Create(storedPath))
    await using (var source = file.OpenReadStream())
    {
        await source.CopyToAsync(target);
    }

    var info = new FileInfo(storedPath);
    return new ExecutableCandidate
    {
        FileName = info.Name,
        FullPath = info.FullName,
        SizeBytes = info.Length,
        LastWriteTimeUtc = info.LastWriteTimeUtc
    };
}

/// <summary>
/// Removes path separators and invalid filesystem characters from a file name.
/// The input is a browser-supplied file name, processing keeps only safe local
/// filename characters, and the function returns a storage-safe file name.
/// </summary>
static string SanitizeFileName(string fileName)
{
    var invalid = Path.GetInvalidFileNameChars();
    var sanitized = new string(fileName.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
    return string.IsNullOrWhiteSpace(sanitized) ? "sample.exe" : sanitized;
}

/// <summary>
/// Request body for running a planned Hyper-V runbook.
/// Inputs come from the WebUI, processing maps Live to dry-run or live executor
/// mode and clamps StepTimeoutSeconds, and the record is not persisted.
/// </summary>
internal sealed record RunbookExecuteRequest
{
    public bool Live { get; init; }

    public int StepTimeoutSeconds { get; init; } = 1800;

    public bool ImportGuestEvents { get; init; } = true;
}

/// <summary>
/// Compact outcome returned by helper code that starts a runbook in the WebUI
/// background runner. Inputs are produced by validation/background-store code;
/// processing serializes this into upload-and-start responses and maps it back
/// to HTTP status for the manual start endpoint.
/// </summary>
internal sealed record RunbookBackgroundStartAttempt
{
    public bool Attempted { get; init; }

    public bool Accepted { get; init; }

    public string State { get; init; } = RunbookBackgroundExecutionStore.NotStarted;

    public string? Message { get; init; }

    public int StatusCode { get; init; } = StatusCodes.Status200OK;

    public RunbookBackgroundExecutionSnapshot? Snapshot { get; init; }
}

/// <summary>
/// Request body for importing collected guest events after a runbook.
/// Inputs may specify an explicit events.json or JSONL path; processing passes
/// the path to the job service, and the record itself is not persisted.
/// </summary>
internal sealed record GuestEventImportRequest
{
    public string? EventsPath { get; init; }
}
