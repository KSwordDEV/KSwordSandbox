using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
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
            .grid { display: grid; gap: 18px; grid-template-columns: 1fr 1fr; }
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
                <ol>${steps}</ol>`;
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
