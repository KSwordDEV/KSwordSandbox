using System.Text.Json;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Execution;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
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
        return Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
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
app.MapPost("/api/settings/virustotal", (VirusTotalSettingsUpdateRequest request, VirusTotalSettingsStore settingsStore) =>
{
    try
    {
        return Results.Ok(settingsStore.Save(request.ApiKey, request.Clear));
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
app.MapGet("/api/jobs/{jobId:guid}/virustotal", async Task<IResult> (Guid jobId, SandboxJobService service, VirusTotalLookupService virusTotal, CancellationToken cancellationToken) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
    }

    if (job.Sample is null || string.IsNullOrWhiteSpace(job.Sample.Sha256))
    {
        return Results.Ok(new VirusTotalLookupResult
        {
            Sha256 = string.Empty,
            Configured = false,
            Queried = false,
            Found = false,
            Status = "missing_hash",
            Message = "Sample SHA-256 is not available yet."
        });
    }

    var result = await virusTotal.LookupFileHashAsync(job.Sample.Sha256, cancellationToken);
    if (ShouldPersistVirusTotalResult(result))
    {
        service.UpsertEnrichmentEvent(
            jobId,
            result.ToRuleEvent(),
            $"VirusTotal hash lookup persisted to report: status={result.Status}, verdict={result.Verdict}.");
    }

    return Results.Ok(result);
});
// GET /api/jobs/{jobId}/runbook/progress returns the latest UI-safe runbook
// progress snapshot while a long live request is still running. Inputs are only
// a job id; processing reads the Web host's in-memory progress store; the
// response intentionally excludes PowerShell commands, stdout, and stderr.
app.MapGet("/api/jobs/{jobId:guid}/runbook/progress", (Guid jobId, SandboxJobService service, RunbookProgressStore progressStore) =>
{
    if (progressStore.TryGet(jobId, out var snapshot))
    {
        return Results.Ok(snapshot);
    }

    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
    }

    if (job.Runbook is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} does not have a runbook progress snapshot yet." });
    }

    return Results.Ok(progressStore.Begin(job.Runbook, SandboxRunbookExecutionMode.DryRun));
});
// GET /api/jobs/{jobId}/runbook/background returns the WebUI server-side
// background execution state. It complements the per-step progress endpoint:
// progress is live/streaming, while this endpoint carries the terminal
// execution result, imported job, and report-ready metadata after completion.
app.MapGet("/api/jobs/{jobId:guid}/runbook/background", (Guid jobId, SandboxJobService service, RunbookBackgroundExecutionStore backgroundStore) =>
{
    if (service.GetJob(jobId) is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} was not found in the in-memory Web host job list." });
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
            index.RootPath,
            index.Producer,
            index.GeneratedAtUtc,
            index.Collections,
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
        return Results.Ok(new
        {
            Uploaded = candidate,
            Job = job,
            MonitorHref = $"/jobs/{job.JobId:D}/live-events",
            ExecutionFlowHref = $"/jobs/{job.JobId:D}/execution-flow",
            ReportHref = $"/api/jobs/{job.JobId:D}/report/html",
            BackgroundHref = $"/api/jobs/{job.JobId:D}/runbook/background",
            RunbookStart = runbookStart
        });
    }
    catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or InvalidOperationException or IOException or UnauthorizedAccessException)
    {
        return Results.BadRequest(new { error = $"Upload-and-start analysis failed before a job could be created: {ex.Message}" });
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
        return Results.BadRequest(new { error = $"Dry-run plan could not be created: {ex.Message}" });
    }
});
app.MapPost("/api/jobs/{jobId:guid}/runbook/execute", async (Guid jobId, RunbookExecuteRequest request, SandboxJobService service, IRunbookExecutor executor, SandboxConfig currentConfig, RunbookProgressStore progressStore) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = $"Job {jobId:D} was not found; create a dry-run plan before running a runbook." });
    }

    if (job.Runbook is null)
    {
        return Results.BadRequest(new { error = $"Job {jobId:D} does not have a runbook; recreate the dry-run plan for the selected executable." });
    }

    var prepareError = TryPrepareRunbookExecution(job, request, currentConfig, progressStore, out var options);
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
        return Results.BadRequest(new { error = $"Guest event import failed for job {jobId:D}: {ex.Message}" });
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
    var selector = FirstNonEmpty(artifact.RelativePath, artifact.SafeLink, artifact.ImportPath);
    var href = string.IsNullOrWhiteSpace(selector)
        ? string.Empty
        : $"/api/jobs/{jobId:D}/artifacts/download?path={Uri.EscapeDataString(selector)}";
    return new
    {
        artifact.Kind,
        artifact.Category,
        artifact.Name,
        artifact.RelativePath,
        artifact.SafeLink,
        artifact.EvidenceRole,
        artifact.CapturePhase,
        artifact.CaptureState,
        artifact.GuestPath,
        artifact.ImportPath,
        artifact.CollectionName,
        artifact.MimeType,
        artifact.SizeBytes,
        artifact.Sha256,
        artifact.Hashes,
        artifact.CreatedAtUtc,
        artifact.Metadata,
        DownloadHref = href
    };
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
        var contentType = string.IsNullOrWhiteSpace(artifact.MimeType)
            ? ArtifactDescriptorFactory.MimeTypeForPath(artifact.FullPath)
            : artifact.MimeType;
        var fileName = string.IsNullOrWhiteSpace(artifact.Name) ? Path.GetFileName(artifact.FullPath) : artifact.Name;
        return Results.File(artifact.FullPath, contentType, fileName, enableRangeProcessing: true);
    }
    catch (KeyNotFoundException ex)
    {
        return Results.NotFound(new { error = ex.Message });
    }
    catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or IOException or UnauthorizedAccessException)
    {
        return Results.NotFound(new { error = $"Artifact download failed for job {jobId:D}: {ex.Message}" });
    }
}

/// <summary>
/// Decides whether a VirusTotal lookup result should become durable report
/// evidence. Inputs are the operator-safe lookup result; processing persists
/// only real query outcomes that are not local configuration or transport
/// failures, preserving the requirement that missing API keys and failed calls
/// stay quiet and do not write report/log noise.
/// </summary>
static bool ShouldPersistVirusTotalResult(VirusTotalLookupResult result)
{
    if (!result.Configured || !result.Queried)
    {
        return false;
    }

    return string.Equals(result.Status, VirusTotalLookupStatuses.Found, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(result.Status, VirusTotalLookupStatuses.NotFound, StringComparison.OrdinalIgnoreCase);
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
    SandboxConfig currentConfig,
    RunbookProgressStore progressStore,
    out SandboxRunbookExecutionOptions options)
{
    options = new SandboxRunbookExecutionOptions();
    if (job.Runbook is null)
    {
        return Results.BadRequest(new { error = $"Job {job.JobId:D} does not have a runbook; recreate the dry-run plan for the selected executable." });
    }

    var mode = request.Live ? SandboxRunbookExecutionMode.Live : SandboxRunbookExecutionMode.DryRun;
    progressStore.Begin(job.Runbook, mode);

    var environmentVariables = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    if (request.Live)
    {
        var secretName = string.IsNullOrWhiteSpace(currentConfig.Guest.PasswordSecretName)
            ? "KSWORDBOX_GUEST_PASSWORD"
            : currentConfig.Guest.PasswordSecretName.Trim();

        if (!TryResolveEnvironmentSecret(secretName, out var guestPassword))
        {
            progressStore.Fail(
                job.Runbook,
                mode,
                $"Live runbook needs guest credential secret '{secretName}' in the WebUI process, User, or Machine environment.");
            return Results.BadRequest(new
            {
                error = $"Live runbook needs guest credential secret '{secretName}' in the WebUI process, User, or Machine environment. Run .\\install.ps1, choose the password reset option, then restart .\\run.ps1 -Mode WebUI."
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
        ProgressSink = new Progress<SandboxRunbookProgressSnapshot>(progressStore.Update)
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
    var job = service.GetJob(jobId) ?? throw new KeyNotFoundException($"Job {jobId:D} was not found before execution.");
    if (job.Runbook is null)
    {
        throw new InvalidOperationException($"Job {jobId:D} does not have a runbook.");
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
            guestImportMessage = $"Guest events imported from {updatedJob.GuestEventsPath}.";
        }
        catch (Exception ex) when (ex is DirectoryNotFoundException or FileNotFoundException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            guestImportMessage = $"Runbook completed, but guest events were not imported automatically: {ex.Message}";
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
            Message = $"Job {jobId:D} was not found; create a dry-run plan before starting a runbook.",
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
            Message = $"Job {jobId:D} does not have a runbook; recreate the dry-run plan for the selected executable.",
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
            Message = "Runbook execution is already queued or running for this job."
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

    var prepareError = TryPrepareRunbookExecution(job, request, currentConfig, progressStore, out var options);
    if (prepareError is not null)
    {
        var modeText = request.Live ? "live VM analysis" : "dry-run verification";
        return new RunbookBackgroundStartAttempt
        {
            Attempted = true,
            Accepted = false,
            State = RunbookBackgroundExecutionStore.Failed,
            Message = $"Runbook {modeText} preflight failed. For live runs, verify the guest credential secret, Hyper-V readiness, and VM configuration; open the execution-flow page for the UI-safe failed step.",
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
