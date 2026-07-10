namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: no runtime input.
/// Processing: renders the interactive local WebUI for upload/path/scan planning, job status, runbook execution, live telemetry, and artifact path review.
/// Return behavior: returns a complete HTML document for the root dashboard endpoint.
/// </summary>
internal static class DashboardExperiencePage
{
    /// <summary>
    /// Inputs: none. Processing: returns a self-contained dashboard page.
    /// Return behavior: HTML text suitable for Results.Content.
    /// </summary>
    internal static string Render()
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
            button.copy-btn { background: #e2e8f0; border: 1px solid #cbd5e1; color: #334155; font-size: 12px; margin: 0 0 0 6px; padding: 5px 8px; vertical-align: middle; }
            button.copy-btn:hover { background: #cbd5e1; }
            table { border-collapse: collapse; width: 100%; margin-top: 16px; }
            td, th { border-bottom: 1px solid #e5e7eb; padding: 9px; text-align: left; vertical-align: top; }
            th { color: #475569; font-size: 13px; text-transform: uppercase; }
            code, pre { background: #f1f5f9; border-radius: 8px; }
            code { padding: 2px 5px; }
            pre { overflow: auto; padding: 14px; white-space: pre-wrap; }
            [data-copy], td, th, code, pre { cursor: copy; }
            [data-copy]:hover, td:hover, th:hover, code:hover, pre:hover { outline: 1px dashed #93c5fd; outline-offset: 2px; }
            .copy-field { align-items: center; display: inline-flex; flex-wrap: wrap; gap: 4px; max-width: 100%; }
            .copy-field code { overflow-wrap: anywhere; word-break: break-word; }
            .artifact-table td:nth-child(2) { word-break: break-word; }
            .toast { background: #0f172a; border-radius: 999px; bottom: 22px; color: white; left: 50%; opacity: 0; padding: 10px 16px; pointer-events: none; position: fixed; transform: translate(-50%, 12px); transition: opacity .15s ease, transform .15s ease; z-index: 20; }
            .toast.visible { opacity: .96; transform: translate(-50%, 0); }
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
            <p>Windows Hyper-V malware behavior sandbox scaffold. Upload, choose a path, or scan a folder to create a safe dry-run plan first; live execution remains explicit.</p>
            <p><span class="pill">Tip: right-click any highlighted path, table value, stdout/stderr block, or raw evidence cell to copy it.</span></p>
          </header>
          <main>
            <section>
              <h2>Plan analysis</h2>
              <p class="hint">This is a local WebUI. Use host-visible paths such as <code data-copy="D:\Temp\sample.exe" data-copy-label="example sample path">D:\Temp\sample.exe</code> or scan a directory and select one discovered executable. Every entry point below creates a dry-run plan and report before any live VM action.</p>
              <div class="grid">
                <div>
                  <h3>1) Upload .exe and plan</h3>
                  <p class="hint">Stores the file in the configured runtime upload folder, then creates a dry-run job. It does not execute the sample.</p>
                  <label for="sampleUpload">Executable file (.exe)</label>
                  <input id="sampleUpload" type="file" accept=".exe,application/vnd.microsoft.portable-executable,application/octet-stream">
                  <label for="uploadDuration">Analysis duration, seconds</label>
                  <input id="uploadDuration" type="number" min="1" max="900" value="120">
                  <button onclick="uploadAndPlan()">Upload .exe → create dry-run plan</button>
                </div>
                <div>
                  <h3>2) Plan existing host path</h3>
                  <p class="hint">Use when the sample is already on this host or a mounted share. The server validates the path before writing artifacts.</p>
                  <label for="samplePath">Executable path on host</label>
                  <input id="samplePath" placeholder="D:\Temp\sample.exe">
                  <label for="duration">Analysis duration, seconds</label>
                  <input id="duration" type="number" min="1" max="900" value="120">
                  <button onclick="planPath()">Create dry-run plan from path</button>
                </div>
                <div>
                  <h3>3) Scan folder, then plan</h3>
                  <p class="hint">Metadata-only .exe discovery. Review candidates or use one-click planning for the first sorted result.</p>
                  <label for="scanPath">Directory or exact .exe path</label>
                  <input id="scanPath" placeholder="D:\Temp\incoming">
                  <label for="maxDepth">Max scan depth</label>
                  <input id="maxDepth" type="number" min="0" max="16" value="4">
                  <button class="secondary" onclick="scanTargets()">Find .exe candidates</button>
                  <button class="secondary" onclick="scanAndPlanFirst()">Scan and plan first candidate</button>
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
          <div id="copyToast" class="toast" role="status" aria-live="polite"></div>
          <script>
            const liveEventOffsets = new Map();
            const liveEventSourceSignatures = new Map();
            let liveEventTimer = null;
            let liveEventStream = null;
            let liveEventJobId = null;
            let liveEventMode = 'idle';
            let copyToastTimer = null;

            document.addEventListener('click', event => {
              const button = event.target.closest ? event.target.closest('button.copy-btn[data-copy]') : null;
              if (!button) {
                return;
              }

              event.preventDefault();
              event.stopPropagation();
              copyText(button.getAttribute('data-copy') || '', button.getAttribute('data-copy-label') || 'value');
            });

            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest('[data-copy], code, pre, td, th') : null;
              if (!target) {
                return;
              }

              const value = target.getAttribute('data-copy') || target.innerText || target.textContent || '';
              if (!value.trim()) {
                return;
              }

              event.preventDefault();
              copyText(value, target.getAttribute('data-copy-label') || 'value');
            });

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
                return payload;
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function scanAndPlanFirst() {
              try {
                const result = await scanTargets();
                if (!result) { return; }
                const first = result.candidates && result.candidates[0];
                if (!first) {
                  setStatus('Scan completed, but no executable candidates were found to plan.', true);
                  return;
                }

                setStatus(`Planning first candidate: ${first.fullPath}`, false);
                await planPath(first.fullPath);
              } catch {
                // scanTargets or planPath already wrote the visible status.
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
                setStatus('Job planned. Review status, artifact paths, raw telemetry, and runbook before enabling privileged live execution.', false);
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
                  <td data-copy="${escapeAttribute(candidate.fileName)}" data-copy-label="candidate file name">${escapeHtml(candidate.fileName)}</td>
                  <td>${copyableCode(candidate.fullPath, 'candidate path')}</td>
                  <td data-copy="${escapeAttribute(String(candidate.sizeBytes))}" data-copy-label="candidate size">${formatBytes(candidate.sizeBytes)}</td>
                  <td><button onclick="planPath('${escapeJs(candidate.fullPath)}')">Plan</button></td>
                </tr>`).join('');
              const warnings = (result.warnings || []).map(warning => `<li data-copy="${escapeAttribute(warning)}" data-copy-label="scan warning">${escapeHtml(warning)} ${copyButton(warning, 'scan warning')}</li>`).join('');
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
              const artifactPaths = buildArtifactPaths(job);
              const guestImportStatus = buildGuestImportStatus(job, artifactPaths);
              const servedReportHref = jobId ? `/api/jobs/${encodeURIComponent(jobId)}/report/html` : '';
              const fileReportHref = toFileUri(htmlReportPath);
            const steps = (job.runbook?.steps || []).map(step => `<li data-copy="${escapeAttribute((step.title || '') + '\n' + (step.powerShell || ''))}" data-copy-label="planned runbook step"><strong>${escapeHtml(step.title)}</strong><br>${copyableCode(step.powerShell, 'planned runbook PowerShell')}</li>`).join('');
              const messages = (job.messages || []).map(message => `<li data-copy="${escapeAttribute(message)}" data-copy-label="job message">${escapeHtml(message)} ${copyButton(message, 'job message')}</li>`).join('');
              const reportLinks = htmlReportPath ? `
                  <a class="buttonlink" target="_blank" rel="noopener" href="${escapeHtml(servedReportHref)}">Open served HTML report</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(fileReportHref)}">Open local file:// report</a>` : '<span class="hint">No HTML report path is recorded yet.</span>';
              document.getElementById('jobResult').innerHTML = `
                <p><strong>Job:</strong> ${copyableCode(jobId, 'job id')}</p>
                <p><strong>Status:</strong> <span class="pill" data-copy="${escapeAttribute(job.status || '')}" data-copy-label="job status">${escapeHtml(job.status)}</span></p>
                <p><strong>Sample:</strong> ${copyableCode(job.sample?.fullPath || '', 'sample path')}</p>
                <h3>Report access</h3>
                <p>
                  <button class="secondary" onclick="refreshJob('${escapeJs(jobId)}')">Refresh job</button>
                  <button class="secondary" onclick="showReportPaths('${escapeJs(htmlReportPath)}')">Show report path</button>
                  ${reportLinks}
                </p>
                <div id="jobReportPaths" class="pathbox">
                  <p><strong>Guest import status:</strong> <span class="pill" data-copy="${escapeAttribute(guestImportStatus.label)}" data-copy-label="guest import status">${escapeHtml(guestImportStatus.label)}</span> <span class="hint">${escapeHtml(guestImportStatus.detail)}</span></p>
                  <table class="artifact-table">
                    <thead><tr><th>Artifact</th><th>Copyable path</th><th>Status</th></tr></thead>
                    <tbody>
                      <tr><td>report.html</td><td>${copyableCode(artifactPaths.reportHtmlPath, 'report.html path')}</td><td>${artifactStatus(artifactPaths.reportHtmlPath, 'recorded')}</td></tr>
                      <tr><td>report.json</td><td>${copyableCode(artifactPaths.reportJsonPath, 'report.json path')}</td><td>${artifactStatus(artifactPaths.reportJsonPath, 'recorded')}</td></tr>
                      <tr><td>events.json</td><td>${copyableCode(artifactPaths.eventsJsonPath, 'events.json path')}</td><td>${artifactStatus(artifactPaths.eventsJsonPath, guestEventsPath ? 'recorded/import source' : 'expected after live run')}</td></tr>
                      <tr><td>driver-events.jsonl</td><td>${copyableCode(artifactPaths.driverEventsJsonlPath, 'driver-events.jsonl path')}</td><td>${artifactStatus(artifactPaths.driverEventsJsonlPath, 'expected driver telemetry')}</td></tr>
                      <tr><td>runbook-execution.json</td><td>${copyableCode(artifactPaths.runbookExecutionPath, 'runbook execution path')}</td><td>${artifactStatus(runbookExecutionPath, runbookExecutionPath ? 'recorded' : 'expected after runbook execution')}</td></tr>
                    </tbody>
                  </table>
                  <p><strong>Imported guest events path:</strong> ${copyableCode(guestEventsPath, 'guest import source path')}</p>
                  <p class="hint">If the browser blocks the file:// link, copy report.html above or use the served report link. Expected guest paths are shown before import so live operators know where events.json and driver-events.jsonl should appear.</p>
                </div>
                <h3>Job messages</h3>
                ${messages ? `<ul>${messages}</ul>` : '<p class="hint">No job messages recorded.</p>'}
                <h3>Live raw event monitor</h3>
                <div class="event-monitor">
                  <p>
                    <span id="liveEventStatus" class="hint">Waiting for live raw telemetry...</span>
                    <button class="secondary" onclick="refreshLiveEvents('${escapeJs(jobId)}', true)">Refresh raw telemetry now</button>
                    ${copyButton(jobId, 'live telemetry job id')}
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

              const items = sources.map(source => `<li>${copyableCode(source, 'live raw telemetry source path')}</li>`).join('');
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
                const dataText = Object.entries(evt.data || {})
                  .map(([key, value]) => `${key}=${String(value)}`)
                  .join('\n');
                const data = Object.entries(evt.data || {})
                  .map(([key, value]) => `<span data-copy="${escapeAttribute(`${key}=${String(value)}`)}" data-copy-label="event data field">${escapeHtml(key)}=${escapeHtml(String(value))}</span>`)
                  .join('<br>');
                const eventJson = JSON.stringify(evt, null, 2);
                const row = document.createElement('tr');
                row.innerHTML = `
                  <td data-copy="${escapeAttribute(formatEventTime(evt.timestamp))}" data-copy-label="event time">${escapeHtml(formatEventTime(evt.timestamp))}</td>
                  <td data-copy="${escapeAttribute(evt.eventType || '-')}" data-copy-label="event type">${escapeHtml(evt.eventType || '-')}</td>
                  <td data-copy="${escapeAttribute(evt.source || '-')}" data-copy-label="event source">${escapeHtml(evt.source || '-')}</td>
                  <td data-copy="${escapeAttribute(processLabel)}" data-copy-label="event process">${processLabel}</td>
                  <td data-copy="${escapeAttribute([evt.path || '', evt.commandLine || ''].filter(Boolean).join('\n'))}" data-copy-label="event path and command">${copyableCode(evt.path || '', 'event path', '-')}<br><span class="hint">${evt.commandLine ? copyableCode(evt.commandLine, 'event command line') : ''}</span></td>
                  <td data-copy="${escapeAttribute(dataText)}" data-copy-label="event data">${data || '<span class="hint">-</span>'} ${copyButton(eventJson, 'raw telemetry event')}</td>`;
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
                const command = step.powerShell ? `<details open><summary>PowerShell command ${copyButton(step.powerShell, 'PowerShell command')}</summary><pre data-copy="${escapeAttribute(step.powerShell)}" data-copy-label="PowerShell command">${escapeHtml(step.powerShell)}</pre></details>` : '<span class="hint">No command text.</span>';
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

              return `<details ${label === 'stderr' ? 'open' : ''}><summary>${escapeHtml(label)} ${copyButton(value, label)}</summary><pre data-copy="${escapeAttribute(value)}" data-copy-label="${escapeAttribute(label)}">${escapeHtml(value)}</pre></details>`;
            }

            function buildArtifactPaths(job) {
              // Inputs: current job payload. Processing: derives recorded and
              // expected report/guest artifact paths without touching the host
              // filesystem. Return: stable labels for display and copy.
              const jobId = String(job.jobId || '');
              const jobIdNoDash = jobId.replace(/-/g, '');
              const reportJsonPath = job.jsonReportPath || '';
              const reportHtmlPath = job.htmlReportPath || '';
              const recordedRunbookPath = job.runbookExecutionResultPath || '';
              const jobRoot = getParentDirectory(reportJsonPath || reportHtmlPath || recordedRunbookPath);
              const expectedGuestDirectory = jobRoot && jobIdNoDash ? combineHostPath(jobRoot, 'guest', jobIdNoDash) : '';
              const guestEventsPath = job.guestEventsPath || '';
              const guestEventsDirectory = guestEventsPath ? getParentDirectory(guestEventsPath) : expectedGuestDirectory;
              const eventsJsonPath = fileNameEquals(guestEventsPath, 'events.json')
                ? guestEventsPath
                : (expectedGuestDirectory ? combineHostPath(expectedGuestDirectory, 'events.json') : '');
              const driverEventsJsonlPath = fileNameEquals(guestEventsPath, 'driver-events.jsonl')
                ? guestEventsPath
                : (guestEventsDirectory ? combineHostPath(guestEventsDirectory, 'driver-events.jsonl') : '');
              const runbookExecutionPath = recordedRunbookPath || (jobRoot ? combineHostPath(jobRoot, 'runbook-execution.json') : '');

              return {
                jobRoot,
                reportJsonPath,
                reportHtmlPath,
                eventsJsonPath,
                driverEventsJsonlPath,
                runbookExecutionPath
              };
            }

            function buildGuestImportStatus(job, artifactPaths) {
              // Inputs: current job and derived artifact paths. Processing:
              // turns nullable GuestEventsPath into an operator-facing status.
              // Return: label/detail text for the dashboard.
              if (job.guestEventsPath) {
                return {
                  label: 'imported',
                  detail: `Guest events are recorded from ${job.guestEventsPath}.`
                };
              }

              if (artifactPaths.eventsJsonPath || artifactPaths.driverEventsJsonlPath) {
                return {
                  label: 'waiting for import',
                  detail: 'No guest import source is recorded yet; expected events.json and driver-events.jsonl paths are shown below.'
                };
              }

              return {
                label: 'not available',
                detail: 'Plan/report paths are not available yet, so guest artifact paths cannot be inferred.'
              };
            }

            function artifactStatus(path, statusText) {
              const tone = path ? 'ok' : 'hint';
              return `<span class="${tone}" data-copy="${escapeAttribute(statusText)}" data-copy-label="artifact status">${escapeHtml(statusText)}</span>`;
            }

            function getParentDirectory(path) {
              if (!path) {
                return '';
              }

              const normalized = String(path).replace(/[\\/]+$/, '');
              const slash = Math.max(normalized.lastIndexOf('\\'), normalized.lastIndexOf('/'));
              return slash <= 0 ? '' : normalized.slice(0, slash);
            }

            function combineHostPath(root, ...segments) {
              if (!root) {
                return '';
              }

              const separator = root.includes('/') && !root.includes('\\') ? '/' : '\\';
              const cleanedRoot = String(root).replace(/[\\/]+$/, '');
              const cleanedSegments = segments
                .filter(segment => segment != null && String(segment).length > 0)
                .map(segment => String(segment).replace(/^[\\/]+|[\\/]+$/g, ''));
              return [cleanedRoot, ...cleanedSegments].join(separator);
            }

            function fileNameEquals(path, expected) {
              if (!path) {
                return false;
              }

              const normalized = String(path).replace(/\\/g, '/');
              const fileName = normalized.slice(normalized.lastIndexOf('/') + 1);
              return fileName.toLowerCase() === expected.toLowerCase();
            }

            function copyableCode(value, label, emptyText) {
              const text = value || emptyText || '(not recorded)';
              if (!value) {
                return `<span class="copy-field"><code>${escapeHtml(text)}</code></span>`;
              }

              return `<span class="copy-field"><code data-copy="${escapeAttribute(value)}" data-copy-label="${escapeAttribute(label)}" title="Right-click to copy ${escapeAttribute(label)}">${escapeHtml(text)}</code>${copyButton(value, label)}</span>`;
            }

            function copyButton(value, label) {
              if (value == null || value === '') {
                return '';
              }

              return `<button type="button" class="copy-btn" data-copy="${escapeAttribute(String(value))}" data-copy-label="${escapeAttribute(label || 'value')}" title="Copy ${escapeAttribute(label || 'value')}">Copy</button>`;
            }

            async function copyText(value, label) {
              const text = value == null ? '' : String(value);
              if (!text) {
                showCopyToast('Nothing to copy.');
                return;
              }

              try {
                if (navigator.clipboard && window.isSecureContext) {
                  await navigator.clipboard.writeText(text);
                } else {
                  fallbackCopyText(text);
                }

                showCopyToast(`Copied ${label || 'value'}.`);
              } catch (error) {
                try {
                  fallbackCopyText(text);
                  showCopyToast(`Copied ${label || 'value'}.`);
                } catch {
                  showCopyToast(`Copy failed: ${error.message}`);
                }
              }
            }

            function fallbackCopyText(text) {
              const textarea = document.createElement('textarea');
              textarea.value = text;
              textarea.setAttribute('readonly', 'readonly');
              textarea.style.position = 'fixed';
              textarea.style.left = '-9999px';
              document.body.appendChild(textarea);
              textarea.select();
              document.execCommand('copy');
              document.body.removeChild(textarea);
            }

            function showCopyToast(message) {
              const toast = document.getElementById('copyToast');
              if (!toast) {
                return;
              }

              toast.textContent = message;
              toast.classList.add('visible');
              if (copyToastTimer) {
                clearTimeout(copyToastTimer);
              }

              copyToastTimer = setTimeout(() => toast.classList.remove('visible'), 1400);
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
              for (const button of document.querySelectorAll('button:not(.copy-btn)')) {
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

            function escapeAttribute(value) {
              return escapeHtml(value).replace(/`/g, '&#096;');
            }

            function escapeJs(value) {
              return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
            }
          </script>
        </body>
        </html>
        """;
    }
}
