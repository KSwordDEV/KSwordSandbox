using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Execution;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;

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

app.MapGet("/", () => Results.Content(RenderDashboard(), "text/html"));
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
    return job is null ? Results.NotFound() : Results.Ok(job);
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
    return Results.Ok(result);
});

app.Run();

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
            button { border: 0; border-radius: 10px; background: #1d4ed8; color: white; cursor: pointer; font-weight: 700; margin-top: 14px; padding: 10px 16px; }
            button.secondary { background: #334155; }
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
            .pill { background: #dbeafe; border-radius: 999px; color: #1e40af; display: inline-block; font-size: 12px; font-weight: 700; padding: 3px 8px; }
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
              const steps = (job.runbook?.steps || []).map(step => `<li><strong>${escapeHtml(step.title)}</strong><br><code>${escapeHtml(step.powerShell)}</code></li>`).join('');
              document.getElementById('jobResult').innerHTML = `
                <p><strong>Job:</strong> <code>${escapeHtml(job.jobId)}</code></p>
                <p><strong>Status:</strong> ${escapeHtml(job.status)}</p>
                <p><strong>Sample:</strong> <code>${escapeHtml(job.sample?.fullPath || '')}</code></p>
                <p><strong>JSON report:</strong> <code>${escapeHtml(job.jsonReportPath || '')}</code></p>
                <p><strong>HTML report:</strong> <code>${escapeHtml(job.htmlReportPath || '')}</code></p>
                <h3>Hyper-V runbook</h3>
                <p>
                  <button class="secondary" onclick="executeRunbook('${escapeJs(job.jobId)}', false)">Record dry-run execution</button>
                  <button onclick="executeRunbook('${escapeJs(job.jobId)}', true)">Execute live runbook</button>
                </p>
                <div id="executionResult" class="hint">Live execution requires an elevated host process and a prepared golden VM.</div>
                <ol>${steps}</ol>`;
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
                    stepTimeoutSeconds: 1800
                  })
                });
                const payload = await response.json();
                if (!response.ok) {
                  throw new Error(payload.error || 'Runbook execution failed');
                }

                renderExecution(payload);
                setStatus(payload.success ? 'Runbook execution completed.' : 'Runbook execution stopped with a failure.', !payload.success);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            function renderExecution(result) {
              const rows = (result.stepResults || []).map(step => `
                <tr>
                  <td>${step.stepIndex}</td>
                  <td>${escapeHtml(step.stepId)}</td>
                  <td>${step.success ? 'ok' : 'failed'}</td>
                  <td>${step.skipped ? 'yes' : 'no'}</td>
                  <td>${step.exitCode ?? ''}</td>
                  <td>${escapeHtml(step.message || '')}</td>
                </tr>`).join('');
              document.getElementById('executionResult').innerHTML = `
                <p><strong>Mode:</strong> ${escapeHtml(result.mode)} | <strong>Success:</strong> ${result.success} | <strong>Executed:</strong> ${result.executedSteps}/${result.totalSteps}</p>
                ${result.message ? `<p class="error">${escapeHtml(result.message)}</p>` : ''}
                <table>
                  <thead><tr><th>#</th><th>Step</th><th>Status</th><th>Skipped</th><th>Exit</th><th>Message</th></tr></thead>
                  <tbody>${rows}</tbody>
                </table>`;
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
}
