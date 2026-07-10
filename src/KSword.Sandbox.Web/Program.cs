using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Execution;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Web.Dashboard;

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
builder.Services.AddSingleton<IRunbookExecutor, PowerShellRunbookExecutor>();

var app = builder.Build();

app.MapGet("/", () => Results.Content(DashboardExperiencePage.Render(), "text/html"));
app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "KSword Sandbox Host",
    time = DateTimeOffset.UtcNow
}));
app.MapGet("/api/config", (SandboxConfig currentConfig) => Results.Ok(currentConfig));
app.MapGet("/api/jobs", (SandboxJobService service) => Results.Ok(service.ListJobs()));
app.MapGet("/api/jobs/{jobId:guid}", (Guid jobId, SandboxJobService service) =>
{
    var job = service.GetJob(jobId);
    return job is null ? Results.NotFound(new { error = "Job was not found." }) : Results.Ok(job);
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
app.MapGet("/api/jobs/{jobId:guid}/report/html", async Task<IResult> (Guid jobId, SandboxJobService service) =>
{
    if (!TryResolveHtmlReportPath(jobId, service, out var reportPath, out var errorResult))
    {
        return errorResult ?? Results.NotFound(new { error = "HTML report was not found for this job." });
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
            detail: ex.Message,
            statusCode: 500);
    }
});
app.MapPost("/api/files/scan", (ExecutableScanRequest request, ExecutableTargetScanner scanner) =>
{
    try
    {
        return Results.Ok(scanner.Scan(request));
    }
    catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or IOException or UnauthorizedAccessException)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/files/upload", async (HttpRequest request, SandboxConfig currentConfig) =>
{
    try
    {
        var candidate = await SaveUploadedExecutableAsync(request, currentConfig);
        return Results.Ok(candidate);
    }
    catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException)
    {
        return Results.BadRequest(new { error = ex.Message });
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
        return Results.BadRequest(new { error = ex.Message });
    }
});
app.MapPost("/api/jobs/{jobId:guid}/runbook/execute", async (Guid jobId, RunbookExecuteRequest request, SandboxJobService service, IRunbookExecutor executor) =>
{
    var job = service.GetJob(jobId);
    if (job is null)
    {
        return Results.NotFound(new { error = "Job was not found." });
    }

    if (job.Runbook is null)
    {
        return Results.BadRequest(new { error = "Job does not have a runbook." });
    }

    var options = new SandboxRunbookExecutionOptions
    {
        Mode = request.Live ? SandboxRunbookExecutionMode.Live : SandboxRunbookExecutionMode.DryRun,
        StepTimeout = TimeSpan.FromSeconds(Math.Clamp(request.StepTimeoutSeconds, 1, 7200)),
        RequireElevatedPowerShell = true,
        WorkingDirectory = Directory.GetCurrentDirectory()
    };
    var result = await executor.ExecuteAsync(job.Runbook, options);
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

    return Results.Ok(new
    {
        execution = result,
        job = updatedJob,
        guestImportSucceeded,
        guestImportMessage
    });
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
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.Run();

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
static bool TryResolveHtmlReportPath(Guid jobId, SandboxJobService service, out string reportPath, out IResult? errorResult)
{
    reportPath = string.Empty;
    errorResult = null;

    var job = service.GetJob(jobId);
    if (job is null)
    {
        errorResult = Results.NotFound(new { error = "Job was not found." });
        return false;
    }

    if (string.IsNullOrWhiteSpace(job.HtmlReportPath))
    {
        errorResult = Results.NotFound(new { error = "Job does not have an HTML report path." });
        return false;
    }

    try
    {
        reportPath = Path.GetFullPath(job.HtmlReportPath);
    }
    catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
    {
        errorResult = Results.BadRequest(new { error = $"Recorded HTML report path is invalid: {ex.Message}" });
        reportPath = string.Empty;
        return false;
    }

    var extension = Path.GetExtension(reportPath);
    if (!string.Equals(extension, ".html", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(extension, ".htm", StringComparison.OrdinalIgnoreCase))
    {
        errorResult = Results.BadRequest(new { error = "Recorded report path is not an HTML file." });
        reportPath = string.Empty;
        return false;
    }

    if (!File.Exists(reportPath))
    {
        errorResult = Results.NotFound(new { error = "HTML report file was not found for this job." });
        reportPath = string.Empty;
        return false;
    }

    return true;
}

/// <summary>
/// Saves one uploaded executable into the configured runtime upload folder.
/// Inputs are the HTTP multipart request and sandbox config, processing
/// validates extension and size limits, and the function returns candidate
/// metadata with a host-visible path suitable for job planning.
/// </summary>
static async Task<ExecutableCandidate> SaveUploadedExecutableAsync(HttpRequest request, SandboxConfig config)
{
    if (!request.HasFormContentType)
    {
        throw new ArgumentException("Upload must use multipart/form-data.");
    }

    var form = await request.ReadFormAsync();
    var file = form.Files.GetFile("sample") ?? form.Files.FirstOrDefault();
    if (file is null)
    {
        throw new ArgumentException("No uploaded file was provided.");
    }

    if (file.Length <= 0)
    {
        throw new InvalidOperationException("Uploaded file is empty.");
    }

    if (file.Length > config.Analysis.MaxSampleBytes)
    {
        throw new InvalidOperationException($"Uploaded file size {file.Length} exceeds limit {config.Analysis.MaxSampleBytes}.");
    }

    var originalName = Path.GetFileName(file.FileName);
    if (!string.Equals(Path.GetExtension(originalName), ".exe", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException("Only .exe uploads are accepted in the v1 WebUI.");
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
/// Renders the local WebUI for selecting analysis targets and planning jobs.
/// There are no inputs; processing creates a self-contained HTML/JavaScript
/// dashboard; the function returns HTML text for the root endpoint.
/// </summary>
#pragma warning disable CS8321 // Kept temporarily as fallback while DashboardExperiencePage is finalized.
static string RenderDashboard()
{
    return """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>KSword Sandbox Host</title>
          <style>
            :root { color-scheme: light; }
            body { font-family: Segoe UI, Arial, sans-serif; margin: 0; color: #111827; background: #f8fafc; }
            header { padding: 28px 36px; color: white; background: linear-gradient(135deg, #111827, #1d4ed8); }
            main { max-width: 1180px; margin: 24px auto; padding: 0 24px 48px; }
            section { background: white; border: 1px solid #e5e7eb; border-radius: 14px; box-shadow: 0 8px 28px rgba(15, 23, 42, .06); margin-bottom: 18px; padding: 22px; }
            label { display: block; font-weight: 600; margin: 14px 0 6px; }
            input { box-sizing: border-box; width: 100%; border: 1px solid #cbd5e1; border-radius: 10px; padding: 10px 12px; font: inherit; }
            button, a.buttonlink { border: 0; border-radius: 10px; background: #1d4ed8; color: white; cursor: pointer; display: inline-block; font-weight: 700; margin-top: 14px; padding: 10px 16px; text-decoration: none; }
            button.secondary { background: #334155; }
            a.buttonlink.secondary { background: #334155; }
            button:disabled { background: #94a3b8; cursor: wait; }
            table { border-collapse: collapse; width: 100%; margin-top: 16px; }
            td, th { border-bottom: 1px solid #e5e7eb; padding: 9px; text-align: left; vertical-align: top; }
            th { color: #475569; font-size: 13px; text-transform: uppercase; }
            code, pre { background: #f1f5f9; border-radius: 8px; }
            code { padding: 2px 5px; }
            pre { overflow: auto; padding: 14px; white-space: pre-wrap; }
            .grid { display: grid; gap: 18px; grid-template-columns: repeat(3, 1fr); }
            .hint { color: #64748b; font-size: 14px; }
            .status { margin-top: 12px; min-height: 24px; }
            .error { color: #b91c1c; }
            .ok { color: #047857; }
            .pathbox { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; margin-top: 10px; padding: 12px; }
            .pill { background: #dbeafe; border-radius: 999px; color: #1e40af; display: inline-block; font-size: 12px; font-weight: 700; padding: 3px 8px; }
            .event-monitor { border: 1px solid #bfdbfe; border-radius: 12px; background: #eff6ff; margin-top: 12px; padding: 12px; }
            .event-monitor table { background: white; font-size: 13px; }
            .event-monitor td:nth-child(5), .event-monitor td:nth-child(6) { max-width: 260px; word-break: break-all; }
            .event-source-list { margin: 6px 0 0; padding-left: 18px; }
            .runbook-output details { margin: 4px 0; }
            .runbook-output summary { cursor: pointer; font-weight: 700; }
            .runbook-output pre { max-height: 180px; margin: 6px 0 0; }
            .status-failed { color: #b91c1c; font-weight: 700; }
            .status-ok { color: #047857; font-weight: 700; }
            @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
          </style>
        </head>
        <body>
          <header>
            <h1>KSword Sandbox Host</h1>
            <p>Windows Hyper-V malware behavior sandbox scaffold. v1 currently creates a safe dry-run plan, report artifacts, and a reviewable Hyper-V runbook.</p>
          </header>
          <main>
            <section>
              <h2>Plan analysis</h2>
              <p class="hint">This is a local WebUI. Use host-visible paths such as <code>D:\Temp\sample.exe</code> or scan a directory and select one discovered executable.</p>
              <div class="grid">
                <div>
                  <h3>Upload executable</h3>
                  <label for="sampleUpload">Executable file</label>
                  <input id="sampleUpload" type="file" accept=".exe,application/vnd.microsoft.portable-executable,application/octet-stream">
                  <label for="uploadDuration">Analysis duration, seconds</label>
                  <input id="uploadDuration" type="number" min="1" max="900" value="120">
                  <button onclick="uploadAndPlan()">Upload and plan</button>
                </div>
                <div>
                  <h3>Single executable</h3>
                  <label for="samplePath">Executable path</label>
                  <input id="samplePath" placeholder="D:\Temp\sample.exe">
                  <label for="duration">Analysis duration, seconds</label>
                  <input id="duration" type="number" min="1" max="900" value="120">
                  <button onclick="planPath()">Plan selected executable</button>
                </div>
                <div>
                  <h3>Directory scan</h3>
                  <label for="scanPath">Directory or executable path</label>
                  <input id="scanPath" placeholder="D:\Temp\incoming">
                  <label for="maxDepth">Max scan depth</label>
                  <input id="maxDepth" type="number" min="0" max="16" value="4">
                  <button class="secondary" onclick="scanTargets()">Scan for .exe targets</button>
                </div>
              </div>
              <div id="status" class="status"></div>
            </section>

            <section>
              <h2>Executable candidates <span id="candidateCount" class="pill">0</span></h2>
              <div id="candidates" class="hint">No scan has been run yet.</div>
            </section>

            <section>
              <h2>Last planned job</h2>
              <div id="jobResult" class="hint">No job planned yet.</div>
            </section>
          </main>
          <script>
            const liveEventOffsets = new Map();
            const liveEventSourceSignatures = new Map();
            let liveEventTimer = null;
            let liveEventStream = null;
            let liveEventJobId = null;
            let liveEventMode = 'idle';

            async function scanTargets() {
              setBusy(true);
              setStatus('Scanning host path...', false);
              try {
                const response = await fetch('/api/files/scan', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    path: document.getElementById('scanPath').value,
                    maxDepth: Number(document.getElementById('maxDepth').value || 4),
                    maxResults: 300
                  })
                });
                const payload = await response.json();
                if (!response.ok) {
                  throw new Error(payload.error || 'Scan failed');
                }

                renderCandidates(payload);
                setStatus(`Scan complete: ${payload.candidates.length} executable candidate(s).`, false);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function uploadAndPlan() {
              const input = document.getElementById('sampleUpload');
              if (!input.files || input.files.length === 0) {
                setStatus('Select one .exe file to upload.', true);
                return;
              }

              setBusy(true);
              setStatus('Uploading executable into runtime storage...', false);
              try {
                const form = new FormData();
                form.append('sample', input.files[0]);
                const uploadResponse = await fetch('/api/files/upload', {
                  method: 'POST',
                  body: form
                });
                const uploaded = await uploadResponse.json();
                if (!uploadResponse.ok) {
                  throw new Error(uploaded.error || 'Upload failed');
                }

                document.getElementById('samplePath').value = uploaded.fullPath;
                document.getElementById('duration').value = document.getElementById('uploadDuration').value || 120;
                setStatus(`Uploaded to ${uploaded.fullPath}; creating analysis plan...`, false);
                await planPath(uploaded.fullPath);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function planPath(path) {
              const samplePath = path || document.getElementById('samplePath').value;
              if (!samplePath) {
                setStatus('Enter an executable path or select one from scan results.', true);
                return;
              }

              setBusy(true);
              setStatus('Creating dry-run Hyper-V analysis plan...', false);
              try {
                const response = await fetch('/api/jobs/plan', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    samplePath,
                    durationSeconds: Number(document.getElementById('duration').value || 120),
                    dryRun: true
                  })
                });
                const payload = await response.json();
                if (!response.ok) {
                  throw new Error(payload.error || 'Planning failed');
                }

                renderJob(payload);
                setStatus('Job planned. Review the runbook before enabling privileged execution.', false);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            function renderCandidates(result) {
              document.getElementById('candidateCount').textContent = result.candidates.length;
              if (!result.candidates.length) {
                document.getElementById('candidates').innerHTML = '<p>No .exe candidates found.</p>';
                return;
              }

              const rows = result.candidates.map((candidate, index) => `
                <tr>
                  <td><input type="radio" name="candidate" ${index === 0 ? 'checked' : ''} value="${escapeHtml(candidate.fullPath)}"></td>
                  <td>${escapeHtml(candidate.fileName)}</td>
                  <td><code>${escapeHtml(candidate.fullPath)}</code></td>
                  <td>${formatBytes(candidate.sizeBytes)}</td>
                  <td><button onclick="planPath('${escapeJs(candidate.fullPath)}')">Plan</button></td>
                </tr>`).join('');
              const warnings = (result.warnings || []).map(warning => `<li>${escapeHtml(warning)}</li>`).join('');
              document.getElementById('candidates').innerHTML = `
                <table>
                  <thead><tr><th></th><th>Name</th><th>Path</th><th>Size</th><th>Action</th></tr></thead>
                  <tbody>${rows}</tbody>
                </table>
                ${warnings ? `<p class="hint">Warnings:</p><ul class="hint">${warnings}</ul>` : ''}`;
            }

            function renderJob(job) {
              // Inputs: one AnalysisJob payload returned by the API. Processing:
              // precomputes safe report links and artifact path labels. Return:
              // no value; the latest job panel is replaced in-place.
              const jobId = String(job.jobId || '');
              const htmlReportPath = job.htmlReportPath || '';
              const jsonReportPath = job.jsonReportPath || '';
              const runbookExecutionPath = job.runbookExecutionResultPath || '';
              const guestEventsPath = job.guestEventsPath || '';
              const servedReportHref = jobId ? `/api/jobs/${encodeURIComponent(jobId)}/report/html` : '';
              const fileReportHref = toFileUri(htmlReportPath);
              const steps = (job.runbook?.steps || []).map(step => `<li><strong>${escapeHtml(step.title)}</strong><br><code>${escapeHtml(step.powerShell)}</code></li>`).join('');
              const messages = (job.messages || []).map(message => `<li>${escapeHtml(message)}</li>`).join('');
              const reportLinks = htmlReportPath ? `
                  <a class="buttonlink" target="_blank" rel="noopener" href="${escapeHtml(servedReportHref)}">Open served HTML report</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(fileReportHref)}">Open local file:// report</a>` : '<span class="hint">No HTML report path is recorded yet.</span>';
              document.getElementById('jobResult').innerHTML = `
                <p><strong>Job:</strong> <code>${escapeHtml(jobId)}</code></p>
                <p><strong>Status:</strong> <span class="pill">${escapeHtml(job.status)}</span></p>
                <p><strong>Sample:</strong> <code>${escapeHtml(job.sample?.fullPath || '')}</code></p>
                <h3>Report access</h3>
                <p>
                  <button class="secondary" onclick="refreshJob('${escapeJs(jobId)}')">Refresh job</button>
                  <button class="secondary" onclick="showReportPaths('${escapeJs(htmlReportPath)}')">Show report path</button>
                  ${reportLinks}
                </p>
                <div id="jobReportPaths" class="pathbox">
                  <p><strong>HTML report path:</strong> <code>${escapeHtml(htmlReportPath || '(not recorded)')}</code></p>
                  <p><strong>JSON report path:</strong> <code>${escapeHtml(jsonReportPath || '(not recorded)')}</code></p>
                  <p><strong>Runbook execution path:</strong> <code>${escapeHtml(runbookExecutionPath || '(not recorded)')}</code></p>
                  <p><strong>Guest events path:</strong> <code>${escapeHtml(guestEventsPath || '(not recorded)')}</code></p>
                  <p class="hint">If the browser blocks the file:// link, copy the HTML report path above or use the served report link.</p>
                </div>
                <h3>Job messages</h3>
                ${messages ? `<ul>${messages}</ul>` : '<p class="hint">No job messages recorded.</p>'}
                <h3>Live raw event monitor</h3>
                <div class="event-monitor">
                  <p>
                    <span id="liveEventStatus" class="hint">Waiting for live event polling...</span>
                    <button class="secondary" onclick="refreshLiveEvents('${escapeJs(jobId)}', true)">Refresh events now</button>
                  </p>
                  <div id="liveEventSources" class="hint"></div>
                  <div id="liveEventRows" class="hint">No raw events loaded yet.</div>
                </div>
                <h3>Hyper-V runbook</h3>
                <p>
                  <button class="secondary" onclick="executeRunbook('${escapeJs(jobId)}', false)">Record dry-run execution</button>
                  <button onclick="executeRunbook('${escapeJs(jobId)}', true)">Execute live runbook</button>
                  <button class="secondary" onclick="importGuestEvents('${escapeJs(jobId)}')">Import guest events / refresh report</button>
                </p>
                <div id="executionResult" class="hint">Live execution requires an elevated host process and a prepared golden VM.</div>
                <ol>${steps}</ol>`;
              startLiveMonitor(jobId);
            }

            async function refreshJob(jobId) {
              // Inputs: jobId from the rendered job panel. Processing: fetches
              // current server-side job state and rerenders the panel. Return:
              // no value; status text reports success or failure.
              if (!jobId) {
                setStatus('No job ID is available to refresh.', true);
                return;
              }

              setBusy(true);
              setStatus('Refreshing job status...', false);
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`);
                const job = await response.json();
                if (!response.ok) {
                  throw new Error(job.error || 'Job refresh failed');
                }

                renderJob(job);
                setStatus(`Job refreshed. Status: ${job.status}.`, false);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            function startLiveMonitor(jobId) {
              // Inputs: the current job id rendered in the UI. Processing:
              // resets the visible raw-event table for that job, prefers an
              // SSE EventSource stream, and falls back to one shared polling
              // timer when streaming is unavailable. Return: no value.
              if (!jobId) {
                return;
              }

              stopLiveMonitor();
              liveEventJobId = jobId;
              liveEventOffsets.set(jobId, 0);
              liveEventSourceSignatures.delete(jobId);

              const rows = document.getElementById('liveEventRows');
              if (rows) {
                rows.innerHTML = '<p class="hint">Opening live raw-event stream...</p>';
              }

              if ('EventSource' in window) {
                startLiveEventStream(jobId);
              } else {
                startLiveEventPolling(jobId, true, 'EventSource is not available in this browser.');
              }
            }

            function stopLiveMonitor() {
              // Inputs: none. Processing: closes any active SSE stream and
              // clears the polling timer before another job is rendered.
              // Return: no value.
              if (liveEventStream) {
                liveEventStream.close();
                liveEventStream = null;
              }

              if (liveEventTimer) {
                clearInterval(liveEventTimer);
                liveEventTimer = null;
              }

              liveEventMode = 'idle';
            }

            function startLiveEventStream(jobId) {
              // Inputs: job id for the current panel. Processing: opens an
              // EventSource against the SSE endpoint and appends every snapshot;
              // on connection failure the function switches to polling. Return:
              // no value.
              liveEventMode = 'sse';
              const url = `/api/jobs/${encodeURIComponent(jobId)}/events/stream?offset=0&take=100&intervalMs=2000`;
              try {
                liveEventStream = new EventSource(url);
              } catch (error) {
                startLiveEventPolling(jobId, false, `SSE could not start: ${error.message}`);
                return;
              }

              const status = document.getElementById('liveEventStatus');
              if (status) {
                status.className = 'hint';
                status.textContent = 'Opening SSE raw-event stream...';
              }

              liveEventStream.onopen = () => {
                const openStatus = document.getElementById('liveEventStatus');
                if (openStatus && liveEventMode === 'sse') {
                  openStatus.className = 'hint';
                  openStatus.textContent = 'SSE raw-event stream connected; waiting for snapshots...';
                }
              };

              liveEventStream.addEventListener('snapshot', event => {
                if (liveEventJobId !== jobId) {
                  return;
                }

                try {
                  const snapshot = JSON.parse(event.data);
                  renderLiveEventSnapshot(jobId, snapshot, liveEventOffsets.get(jobId) === 0, 'SSE');
                } catch (error) {
                  const parseStatus = document.getElementById('liveEventStatus');
                  if (parseStatus) {
                    parseStatus.className = 'error';
                    parseStatus.textContent = `SSE snapshot parse failed: ${error.message}`;
                  }
                }
              });

              liveEventStream.onerror = () => {
                if (liveEventJobId !== jobId || liveEventMode !== 'sse') {
                  return;
                }

                if (liveEventStream) {
                  liveEventStream.close();
                  liveEventStream = null;
                }

                startLiveEventPolling(jobId, false, 'SSE stream disconnected; switched to polling fallback.');
              };
            }

            function startLiveEventPolling(jobId, reset, reason) {
              // Inputs: job id, reset flag, and optional fallback reason.
              // Processing: starts the legacy polling endpoint at the current
              // offset and keeps the raw monitor alive. Return: no value.
              liveEventMode = 'polling';
              if (reason) {
                const status = document.getElementById('liveEventStatus');
                if (status) {
                  status.className = 'hint';
                  status.textContent = reason;
                }
              }

              refreshLiveEvents(jobId, reset);
              liveEventTimer = setInterval(() => {
                if (liveEventJobId) {
                  refreshLiveEvents(liveEventJobId, false);
                }
              }, 2000);
            }

            async function refreshLiveEvents(jobId, reset) {
              // Inputs: job id and a reset flag. Processing: calls the raw
              // live-events API with the last offset, updates source labels, and
              // appends unclassified rows. Return: no value; failures are shown
              // inline without stopping the rest of the dashboard.
              if (!jobId) {
                return;
              }

              const status = document.getElementById('liveEventStatus');
              const rows = document.getElementById('liveEventRows');
              const sources = document.getElementById('liveEventSources');
              if (!status || !rows || !sources) {
                return;
              }

              if (reset) {
                liveEventOffsets.set(jobId, 0);
                rows.innerHTML = '<p class="hint">Loading raw events...</p>';
              }

              const offset = liveEventOffsets.get(jobId) || 0;
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/events/live?offset=${offset}&take=100`);
                const snapshot = await response.json();
                if (!response.ok) {
                  throw new Error(snapshot.error || 'Live event refresh failed');
                }

                renderLiveEventSnapshot(jobId, snapshot, reset || offset === 0, 'polling');
              } catch (error) {
                status.textContent = `Live event refresh failed: ${error.message}`;
                status.className = 'error';
              }
            }

            function renderLiveEventSnapshot(jobId, snapshot, replace, transport) {
              // Inputs: the active job id, one API/SSE live-event snapshot,
              // replacement flag, and transport label. Processing: advances
              // the cursor, updates source labels, and appends raw rows without
              // classification. Return: no value.
              const status = document.getElementById('liveEventStatus');
              const sources = document.getElementById('liveEventSources');
              if (!status || !sources) {
                return;
              }

              const previousOffset = liveEventOffsets.get(jobId) || 0;
              const sourceSignature = buildLiveSourceSignature(snapshot.sources || []);
              const previousSourceSignature = liveEventSourceSignatures.get(jobId);
              if (previousSourceSignature && previousSourceSignature !== sourceSignature) {
                liveEventOffsets.set(jobId, 0);
                if (transport === 'polling' && previousOffset > 0) {
                  liveEventSourceSignatures.set(jobId, sourceSignature);
                  refreshLiveEvents(jobId, true);
                  return;
                }

                replace = true;
              }

              liveEventSourceSignatures.set(jobId, sourceSignature);
              const nextOffset = snapshot.nextOffset == null ? previousOffset : Number(snapshot.nextOffset);
              liveEventOffsets.set(jobId, Number.isFinite(nextOffset) ? nextOffset : previousOffset);

              status.className = 'hint';
              status.textContent = `${transport} raw events: ${snapshot.totalEvents || 0}; next offset: ${liveEventOffsets.get(jobId) || 0}; updated ${new Date().toLocaleTimeString()}.`;
              sources.innerHTML = renderLiveEventSources(snapshot.sources || []);
              renderLiveEventRows(snapshot.events || [], replace);
            }

            function buildLiveSourceSignature(sources) {
              // Inputs: source artifact paths from one live snapshot.
              // Processing: sorts them case-insensitively and joins with a
              // delimiter. Return: a stable key used to reset polling cursors
              // when guest output files replace planning-only report events.
              return (sources || [])
                .map(source => String(source))
                .sort((left, right) => left.localeCompare(right, undefined, { sensitivity: 'accent' }))
                .join('\n');
            }

            function renderLiveEventSources(sources) {
              // Inputs: source artifact paths returned by the API. Processing:
              // escapes them and renders a compact list. Return: HTML text.
              if (!sources.length) {
                return '<span class="hint">Sources: planning report only or no guest artifacts yet.</span>';
              }

              const items = sources.map(source => `<li><code>${escapeHtml(source)}</code></li>`).join('');
              return `<span class="hint">Sources:</span><ul class="event-source-list">${items}</ul>`;
            }

            function renderLiveEventRows(events, replace) {
              // Inputs: raw SandboxEvent rows and a replacement flag. Processing:
              // creates the table on demand and appends escaped rows. Return: no
              // value; the monitor displays a no-events hint when empty.
              const container = document.getElementById('liveEventRows');
              if (!container) {
                return;
              }

              if (replace || !container.querySelector('tbody')) {
                container.innerHTML = `
                  <table>
                    <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Process</th><th>Path / command</th><th>Data</th></tr></thead>
                    <tbody></tbody>
                  </table>`;
              }

              const body = container.querySelector('tbody');
              if (!body) {
                return;
              }

              if (!events.length && body.children.length === 0) {
                body.innerHTML = '<tr><td colspan="6" class="hint">No raw events available yet.</td></tr>';
                return;
              }

              if (events.length && body.children.length === 1 && body.textContent.includes('No raw events')) {
                body.innerHTML = '';
              }

              for (const evt of events) {
                const processLabel = `${escapeHtml(evt.processName || '-') } (${escapeHtml(evt.processId == null ? '-' : String(evt.processId))})`;
                const data = Object.entries(evt.data || {})
                  .map(([key, value]) => `${escapeHtml(key)}=${escapeHtml(String(value))}`)
                  .join('<br>');
                const row = document.createElement('tr');
                row.innerHTML = `
                  <td>${escapeHtml(formatEventTime(evt.timestamp))}</td>
                  <td>${escapeHtml(evt.eventType || '-')}</td>
                  <td>${escapeHtml(evt.source || '-')}</td>
                  <td>${processLabel}</td>
                  <td><code>${escapeHtml(evt.path || '-')}</code><br><span class="hint">${escapeHtml(evt.commandLine || '')}</span></td>
                  <td>${data || '<span class="hint">-</span>'}</td>`;
                body.appendChild(row);
              }
            }

            function formatEventTime(timestamp) {
              // Inputs: timestamp from the API. Processing: attempts local time
              // formatting and falls back to the raw string. Return: display
              // text for the event table.
              if (!timestamp) {
                return '-';
              }

              const parsed = new Date(timestamp);
              return Number.isNaN(parsed.getTime()) ? String(timestamp) : parsed.toLocaleTimeString();
            }

            function showReportPaths(reportPath) {
              // Inputs: the current HTML report path string. Processing: keeps
              // the visible path box in view and mirrors the path into the
              // status line. Return: no value.
              const pathBox = document.getElementById('jobReportPaths');
              if (pathBox) {
                pathBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              }

              setStatus(reportPath ? `HTML report path: ${reportPath}` : 'No HTML report path is recorded for this job yet.', !reportPath);
            }

            async function executeRunbook(jobId, live) {
              setBusy(true);
              setStatus(live ? 'Executing live Hyper-V runbook...' : 'Recording dry-run runbook execution...', false);
              try {
                const response = await fetch(`/api/jobs/${jobId}/runbook/execute`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    live,
                    stepTimeoutSeconds: 1800,
                    importGuestEvents: true
                  })
                });
                const payload = await response.json();
                if (!response.ok) {
                  throw new Error(payload.error || 'Runbook execution failed');
                }

                const execution = payload.execution || payload;
                if (payload.job) {
                  renderJob(payload.job);
                }

                renderExecution(execution, payload);
                const suffix = payload.guestImportMessage ? ` ${payload.guestImportMessage}` : '';
                const importFailed = Boolean(payload.guestImportMessage && !payload.guestImportSucceeded);
                setStatus((execution.success ? 'Runbook execution completed.' : 'Runbook execution stopped with a failure.') + suffix, !execution.success || importFailed);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function importGuestEvents(jobId) {
              setBusy(true);
              setStatus('Importing guest events and regenerating report...', false);
              try {
                const response = await fetch(`/api/jobs/${jobId}/guest-events/import`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({})
                });
                const job = await response.json();
                if (!response.ok) {
                  throw new Error(job.error || 'Guest event import failed');
                }

                renderJob(job);
                setStatus(`Guest events imported. Report refreshed at ${job.htmlReportPath || 'report.html'}.`, false);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            function renderExecution(result, wrapper) {
              const rows = (result.stepResults || []).map(step => {
                const statusClass = step.success ? 'status-ok' : 'status-failed';
                const stepLabel = `${escapeHtml(step.title || step.stepId || 'runbook step')}<br><code>${escapeHtml(step.stepId || '')}</code>`;
                const command = step.powerShell ? `<details open><summary>PowerShell command</summary><pre>${escapeHtml(step.powerShell)}</pre></details>` : '<span class="hint">No command text.</span>';
                const message = step.message ? `<p class="${step.success ? 'hint' : 'error'}"><strong>Message:</strong> ${escapeHtml(step.message)}</p>` : '';
                const stdout = renderOutputDetails('stdout', step.standardOutput);
                const stderr = renderOutputDetails('stderr', step.standardError);
                return `
                <tr>
                  <td>${step.stepIndex}</td>
                  <td>${stepLabel}</td>
                  <td><span class="${statusClass}">${step.success ? 'ok' : 'failed'}</span><br><span class="hint">skipped: ${step.skipped ? 'yes' : 'no'}</span></td>
                  <td>
                    <strong>Exit:</strong> ${step.exitCode ?? '(none)'}<br>
                    <strong>Duration:</strong> ${escapeHtml(formatDuration(step.duration))}<br>
                    <strong>Started:</strong> ${escapeHtml(formatEventTime(step.startedAtUtc))}<br>
                    <span class="hint">elevation: ${step.requiresElevation ? 'yes' : 'no'}; mutates VM: ${step.mutatesVmState ? 'yes' : 'no'}</span>
                  </td>
                  <td class="runbook-output">${command}${message}${stdout}${stderr}</td>
                </tr>`;
              }).join('');
              const importMessage = wrapper && wrapper.guestImportMessage ? `<p class="${wrapper.guestImportSucceeded ? 'ok' : 'hint'}">${escapeHtml(wrapper.guestImportMessage)}</p>` : '';
              document.getElementById('executionResult').innerHTML = `
                <p><strong>Mode:</strong> ${escapeHtml(result.mode)} | <strong>Success:</strong> ${result.success} | <strong>Executed:</strong> ${result.executedSteps}/${result.totalSteps} | <strong>Duration:</strong> ${escapeHtml(formatDuration(result.duration))}</p>
                ${result.message ? `<p class="error">${escapeHtml(result.message)}</p>` : ''}
                ${importMessage}
                <table>
                  <thead><tr><th>#</th><th>Step</th><th>Status</th><th>Timing / exit</th><th>Command / output / error</th></tr></thead>
                  <tbody>${rows}</tbody>
                </table>`;
            }

            function renderOutputDetails(label, value) {
              // Inputs: a stream label and captured text. Processing: skips
              // empty streams and renders non-empty data behind a details
              // expander. Return: HTML text for the runbook output cell.
              if (!value) {
                return '';
              }

              return `<details ${label === 'stderr' ? 'open' : ''}><summary>${escapeHtml(label)}</summary><pre>${escapeHtml(value)}</pre></details>`;
            }

            function formatDuration(value) {
              // Inputs: .NET TimeSpan JSON text or a primitive value. Processing
              // keeps non-empty values readable without assuming a browser
              // duration parser. Return: display text.
              if (value == null || value === '') {
                return '-';
              }

              return String(value);
            }

            function setStatus(message, isError) {
              const element = document.getElementById('status');
              element.className = `status ${isError ? 'error' : 'ok'}`;
              element.textContent = message;
            }

            function setBusy(isBusy) {
              for (const button of document.querySelectorAll('button')) {
                button.disabled = isBusy;
              }
            }

            function formatBytes(bytes) {
              if (bytes < 1024) return `${bytes} B`;
              if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
              return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
            }

            function toFileUri(path) {
              // Inputs: a local Windows or POSIX path recorded in job metadata.
              // Processing: normalizes separators and URI-encodes each path
              // segment. Return: a file:/// URL best effort; browsers may still
              // block it from http:// pages by policy.
              if (!path) {
                return '';
              }

              let normalized = String(path).replace(/\\/g, '/');
              if (/^[A-Za-z]:\//.test(normalized)) {
                const drive = normalized.slice(0, 2);
                const tail = normalized.slice(2).split('/').map(encodeURIComponent).join('/');
                return `file:///${drive}${tail}`;
              }

              if (normalized.startsWith('//')) {
                return `file:${normalized.split('/').map(encodeURIComponent).join('/')}`;
              }

              if (normalized.startsWith('/')) {
                return `file://${normalized.split('/').map(encodeURIComponent).join('/')}`;
              }

              return `file:///${normalized.split('/').map(encodeURIComponent).join('/')}`;
            }

            function escapeHtml(value) {
              return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char]));
            }

            function escapeJs(value) {
              return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
            }
          </script>
        </body>
        </html>
        """;
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
/// Request body for importing collected guest events after a runbook.
/// Inputs may specify an explicit events.json or JSONL path; processing passes
/// the path to the job service, and the record itself is not persisted.
/// </summary>
internal sealed record GuestEventImportRequest
{
    public string? EventsPath { get; init; }
}
