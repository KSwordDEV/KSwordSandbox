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
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <title>KSword Sandbox 主机控制台</title>
          <style>
            :root { color-scheme: light; }
            body { font-family: "Microsoft YaHei UI", Segoe UI, Arial, sans-serif; margin: 0; color: #111827; background: #f8fafc; }
            header { padding: 28px 36px; color: white; background: linear-gradient(135deg, #111827, #1d4ed8); }
            .header-row { align-items: flex-start; display: flex; gap: 18px; justify-content: space-between; }
            .lang-toggle { background: rgba(255,255,255,.16); border: 1px solid rgba(255,255,255,.35); white-space: nowrap; }
            .topnav { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
            .topnav a { border: 1px solid rgba(255,255,255,.35); border-radius: 999px; color: white; font-weight: 700; padding: 7px 11px; text-decoration: none; }
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
            .button-row { align-items: center; display: flex; flex-wrap: wrap; gap: 8px; }
            .button-row button, .button-row a.buttonlink { margin-top: 8px; }
            .mini-form { background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 10px; margin: 10px 0; padding: 12px; }
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
            <div class="header-row">
              <div>
                <h1 data-zh="KSword 沙箱主机" data-en="KSword Sandbox Host">KSword 沙箱主机</h1>
                <p data-zh="选择或上传 exe 后先创建 dry-run 计划；主页面只展示关键状态和报告入口，详细排障信息请从“执行流程 / Execution flow”独立视图查看。" data-en="Choose or upload an exe and create a dry-run plan first; the dashboard only shows key status and report access. Open Execution flow for troubleshooting details.">选择或上传 exe 后先创建 dry-run 计划；主页面只展示关键状态和报告入口，详细排障信息请从“执行流程 / Execution flow”独立视图查看。</p>
                <p><span class="pill" data-zh="提示：右键路径、表格值、证据字段和执行流程视图可复制。" data-en="Tip: right-click paths, table values, evidence fields, and execution-flow details to copy.">提示：右键路径、表格值、证据字段和执行流程视图可复制。</span></p>
              </div>
              <button class="secondary lang-toggle" type="button" onclick="toggleLanguage()" data-zh="English" data-en="中文">English</button>
            </div>
            <nav class="topnav" aria-label="Dashboard navigation">
              <a href="#plan" data-zh="提交样本" data-en="Submit sample">提交样本</a>
              <a href="#current-job" data-zh="当前任务" data-en="Current job">当前任务</a>
              <a href="#recent-jobs" data-zh="历史任务" data-en="Recent jobs">历史任务</a>
            </nav>
          </header>
          <main>
            <section id="plan">
              <h2 data-zh="规划分析" data-en="Plan analysis">规划分析</h2>
              <p class="hint"><span data-zh="这是本地 WebUI。可使用主机可见路径，例如" data-en="This is a local WebUI. Use host-visible paths such as">这是本地 WebUI。可使用主机可见路径，例如</span> <code data-copy="D:\Temp\sample.exe" data-copy-label="example sample path">D:\Temp\sample.exe</code> <span data-zh="，也可扫描目录并选择发现的可执行文件。以下入口都会先创建 dry-run 计划和报告，不会直接执行 VM 动作。" data-en="or scan a directory and select one discovered executable. Every entry point below creates a dry-run plan and report before any live VM action.">，也可扫描目录并选择发现的可执行文件。以下入口都会先创建 dry-run 计划和报告，不会直接执行 VM 动作。</span></p>
              <div class="grid">
                <div>
                  <h3 data-zh="1) 上传 .exe 并规划" data-en="1) Upload .exe and plan">1) 上传 .exe 并规划</h3>
                  <p class="hint" data-zh="将文件保存到配置的运行时上传目录，然后创建 dry-run 任务；不会执行样本。" data-en="Stores the file in the configured runtime upload folder, then creates a dry-run job. It does not execute the sample.">将文件保存到配置的运行时上传目录，然后创建 dry-run 任务；不会执行样本。</p>
                  <label for="sampleUpload" data-zh="可执行文件（.exe）" data-en="Executable file (.exe)">可执行文件（.exe）</label>
                  <input id="sampleUpload" type="file" accept=".exe,application/vnd.microsoft.portable-executable,application/octet-stream">
                  <label for="uploadDuration" data-zh="分析时长（秒）" data-en="Analysis duration, seconds">分析时长（秒）</label>
                  <input id="uploadDuration" type="number" min="1" max="900" value="120">
                  <button onclick="uploadAndPlan()" data-zh="上传 .exe → 创建 dry-run 计划" data-en="Upload .exe → create dry-run plan">上传 .exe → 创建 dry-run 计划</button>
                </div>
                <div>
                  <h3 data-zh="2) 规划已有主机路径" data-en="2) Plan existing host path">2) 规划已有主机路径</h3>
                  <p class="hint" data-zh="适用于样本已经位于本机或挂载共享时。服务器会先校验路径，再写入产物。" data-en="Use when the sample is already on this host or a mounted share. The server validates the path before writing artifacts.">适用于样本已经位于本机或挂载共享时。服务器会先校验路径，再写入产物。</p>
                  <label for="samplePath" data-zh="主机上的可执行文件路径" data-en="Executable path on host">主机上的可执行文件路径</label>
                  <input id="samplePath" placeholder="D:\Temp\sample.exe">
                  <label for="duration" data-zh="分析时长（秒）" data-en="Analysis duration, seconds">分析时长（秒）</label>
                  <input id="duration" type="number" min="1" max="900" value="120">
                  <button onclick="planPath()" data-zh="从路径创建 dry-run 计划" data-en="Create dry-run plan from path">从路径创建 dry-run 计划</button>
                </div>
                <div>
                  <h3 data-zh="3) 扫描文件夹后规划" data-en="3) Scan folder, then plan">3) 扫描文件夹后规划</h3>
                  <p class="hint" data-zh="仅基于元数据发现 .exe。可复核候选项，或一键规划排序后的第一个结果。" data-en="Metadata-only .exe discovery. Review candidates or use one-click planning for the first sorted result.">仅基于元数据发现 .exe。可复核候选项，或一键规划排序后的第一个结果。</p>
                  <label for="scanPath" data-zh="目录或精确 .exe 路径" data-en="Directory or exact .exe path">目录或精确 .exe 路径</label>
                  <input id="scanPath" placeholder="D:\Temp\incoming">
                  <label for="maxDepth" data-zh="最大扫描深度" data-en="Max scan depth">最大扫描深度</label>
                  <input id="maxDepth" type="number" min="0" max="16" value="4">
                  <button class="secondary" onclick="scanTargets()" data-zh="查找 .exe 候选项" data-en="Find .exe candidates">查找 .exe 候选项</button>
                  <button class="secondary" onclick="scanAndPlanFirst()" data-zh="扫描并规划第一个候选项" data-en="Scan and plan first candidate">扫描并规划第一个候选项</button>
                </div>
              </div>
              <div id="status" class="status"></div>
            </section>

            <section>
              <h2><span data-zh="可执行文件候选项" data-en="Executable candidates">可执行文件候选项</span> <span id="candidateCount" class="pill">0</span></h2>
              <div id="candidates" class="hint"><span data-zh="尚未运行扫描。" data-en="No scan has been run yet.">尚未运行扫描。</span></div>
            </section>

            <section id="current-job">
              <h2 data-zh="最近规划的任务" data-en="Last planned job">最近规划的任务</h2>
              <div id="jobResult" class="hint"><span data-zh="尚未规划任务。" data-en="No job planned yet.">尚未规划任务。</span></div>
            </section>

            <section id="recent-jobs">
              <h2 data-zh="近期任务" data-en="Recent jobs">近期任务</h2>
              <p class="hint" data-zh="规划或导入后刷新列表，以比较任务状态、样本路径和报告产物位置。" data-en="Refresh this list after planning or importing to compare job status, sample paths, and report artifact locations.">规划或导入后刷新列表，以比较任务状态、样本路径和报告产物位置。</p>
              <button class="secondary" onclick="refreshJobs(true)" data-zh="刷新任务列表" data-en="Refresh job list">刷新任务列表</button>
              <div id="jobList" class="hint"><span data-zh="尚未加载任务。" data-en="No jobs loaded yet.">尚未加载任务。</span></div>
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
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';

            function setLanguage(lang) {
              currentLanguage = lang === 'en' ? 'en' : 'zh';
              localStorage.setItem('ksword-lang', currentLanguage);
              applyLanguage();
            }

            function toggleLanguage() {
              setLanguage(currentLanguage === 'en' ? 'zh' : 'en');
            }

            function applyLanguage() {
              document.documentElement.lang = currentLanguage === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(element => {
                if (element.id === 'candidates' || element.id === 'jobResult' || element.id === 'jobList' || element.id === 'executionResult') {
                  return;
                }

                element.textContent = currentLanguage === 'en' ? element.getAttribute('data-en') : element.getAttribute('data-zh');
              });
            }

            function formatJobStatus(status) {
              const names = {
                0: 'Queued',
                1: 'Planning',
                2: 'Planned',
                3: 'Running',
                4: 'Completed',
                5: 'Failed'
              };
              if (status === null || status === undefined || status === '') {
                return '-';
              }

              if (typeof status === 'number' || /^\d+$/.test(String(status))) {
                const numeric = Number(status);
                return names[numeric] ? `${names[numeric]} (${numeric})` : `Unknown (${numeric})`;
              }

              return String(status);
            }

            document.addEventListener('click', event => {
              const button = event.target.closest ? event.target.closest('button.copy-btn[data-copy]') : null;
              if (!button) {
                return;
              }

              event.preventDefault();
              event.stopPropagation();
              copyText(button.getAttribute('data-copy') || '', button.getAttribute('data-copy-label') || 'value');
            });

            const copyableSelector = '[data-copy], code, pre, td, th, p, li, h1, h2, h3, label, span, a, button, input';

            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest(copyableSelector) : null;
              if (!target) {
                return;
              }

              const value = target.getAttribute('data-copy') || target.value || target.innerText || target.textContent || '';
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
                const payload = await requireOk(response, 'Scan executable candidates');

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
                const uploaded = await requireOk(uploadResponse, 'Upload executable');

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
                const payload = await requireOk(response, 'Create dry-run analysis plan');

                renderJob(payload);
                applyLanguage();
            refreshJobs(false);
                setStatus('Job planned. Review status, artifact paths, raw telemetry, and runbook before enabling privileged live execution.', false);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function planSelectedCandidate() {
              const selected = document.querySelector('input[name="candidate"]:checked');
              if (!selected || !selected.value) {
                setStatus('Select one executable candidate from the scan table before planning.', true);
                return;
              }

              document.getElementById('samplePath').value = selected.value;
              await planPath(selected.value);
            }

            function renderCandidates(result) {
              document.getElementById('candidateCount').textContent = result.candidates.length;
              if (!result.candidates.length) {
                document.getElementById('candidates').innerHTML = '<p>No .exe candidates found.</p>';
                return;
              }

              const rows = result.candidates.map((candidate, index) => `
                <tr>
                  <td><input type="radio" name="candidate" ${index === 0 ? 'checked' : ''} value="${escapeAttribute(candidate.fullPath)}" data-copy="${escapeAttribute(candidate.fullPath)}" data-copy-label="selected candidate path"></td>
                  <td data-copy="${escapeAttribute(candidate.fileName)}" data-copy-label="candidate file name">${escapeHtml(candidate.fileName)}</td>
                  <td>${copyableCode(candidate.fullPath, 'candidate path')}</td>
                  <td data-copy="${escapeAttribute(String(candidate.sizeBytes))}" data-copy-label="candidate size">${formatBytes(candidate.sizeBytes)}</td>
                  <td><button onclick="planPath('${escapeJs(candidate.fullPath)}')" data-zh="规划" data-en="Plan">规划</button></td>
                </tr>`).join('');
              const warnings = (result.warnings || []).map(warning => `<li data-copy="${escapeAttribute(warning)}" data-copy-label="scan warning">${escapeHtml(warning)} ${copyButton(warning, 'scan warning')}</li>`).join('');
              document.getElementById('candidates').innerHTML = `
                <table>
                  <thead><tr><th></th><th data-zh="名称" data-en="Name">名称</th><th data-zh="路径" data-en="Path">路径</th><th data-zh="大小" data-en="Size">大小</th><th data-zh="操作" data-en="Action">操作</th></tr></thead>
                  <tbody>${rows}</tbody>
                </table>
                <p><button class="secondary" onclick="planSelectedCandidate()" data-zh="规划选中的候选项" data-en="Plan selected candidate">规划选中的候选项</button></p>
                ${warnings ? `<p class="hint" data-zh="警告：" data-en="Warnings:">警告：</p><ul class="hint">${warnings}</ul>` : ''}`;
              applyLanguage();
            }

            function renderJob(job) {
              // Inputs: one AnalysisJob payload returned by the API. Processing:
              // precomputes safe report links and artifact path labels. Return:
              // no value; the latest job panel is replaced in-place.
              const jobId = String(job.jobId || '');
              const statusLabel = formatJobStatus(job.status);
              const htmlReportPath = job.htmlReportPath || '';
              const jsonReportPath = job.jsonReportPath || '';
              const runbookExecutionPath = job.runbookExecutionResultPath || '';
              const guestEventsPath = job.guestEventsPath || '';
              const artifactPaths = buildArtifactPaths(job);
              const guestImportStatus = buildGuestImportStatus(job, artifactPaths);
              const servedReportHref = jobId ? `/api/jobs/${encodeURIComponent(jobId)}/report/html` : '';
              const fileReportHref = toFileUri(htmlReportPath);
              const executionFlowHref = jobId ? `/jobs/${encodeURIComponent(jobId)}/execution-flow` : '';
              const plannedStepCount = job.runbook?.steps?.length || 0;
              const messages = (job.messages || []).map(message => `<li data-copy="${escapeAttribute(message)}" data-copy-label="job message">${escapeHtml(message)} ${copyButton(message, 'job message')}</li>`).join('');
              const reportLinks = htmlReportPath ? `
                  <a class="buttonlink" target="_blank" rel="noopener" href="${escapeHtml(servedReportHref)}">Open served HTML report</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(fileReportHref)}">Open local file:// report</a>` : '<span class="hint">No HTML report path is recorded yet.</span>';
              document.getElementById('jobResult').innerHTML = `
                <p><strong>Job:</strong> ${copyableCode(jobId, 'job id')}</p>
                <p><strong>Status:</strong> <span class="pill" data-copy="${escapeAttribute(statusLabel)}" data-copy-label="job status">${escapeHtml(statusLabel)}</span></p>
                <p><strong>Sample:</strong> ${copyableCode(job.sample?.fullPath || '', 'sample path')}</p>
                <h3>Report access</h3>
                <p class="button-row">
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
                  <div class="mini-form">
                    <label for="guestImportPath">Optional guest events path for manual import</label>
                    <input id="guestImportPath" placeholder="${escapeAttribute(artifactPaths.eventsJsonPath || 'D:\\runtime\\jobs\\<job>\\guest\\events.json')}" value="${escapeAttribute(guestEventsPath || artifactPaths.eventsJsonPath || '')}" data-copy-label="manual guest import path">
                    <p class="hint">Leave blank to let the server search the job guest folder, or paste a specific events.json / .jsonl path when collection landed elsewhere.</p>
                  </div>
                  <p class="hint">If the browser blocks the file:// link, copy report.html above or use the served report link. Expected guest paths are shown before import so live operators know where events.json and driver-events.jsonl should appear.</p>
                </div>
                <h3>Job messages</h3>
                ${messages ? `<ul>${messages}</ul>` : '<p class="hint">No job messages recorded.</p>'}
                <h3>Live raw event monitor</h3>
                <div class="event-monitor">
                  <p class="button-row">
                    <span id="liveEventStatus" class="hint">Waiting for live raw telemetry...</span>
                    <button class="secondary" onclick="refreshLiveEvents('${escapeJs(jobId)}', true)">Refresh raw telemetry now</button>
                    ${copyButton(jobId, 'live telemetry job id')}
                  </p>
                  <div id="liveEventSources" class="hint"></div>
                  <div id="liveEventRows" class="hint">No raw events loaded yet.</div>
                </div>
                <h3 data-zh="执行" data-en="Execution">执行</h3>
                <p class="button-row">
                  <button class="secondary" onclick="executeRunbook('${escapeJs(jobId)}', false)" data-zh="记录一次 dry-run" data-en="Record dry-run execution">记录一次 dry-run</button>
                  <button onclick="executeRunbook('${escapeJs(jobId)}', true)" data-zh="启动虚拟机执行" data-en="Execute live runbook">启动虚拟机执行</button>
                  <button class="secondary" onclick="importGuestEvents('${escapeJs(jobId)}')" data-zh="导入事件并刷新报告" data-en="Import events / refresh report">导入事件并刷新报告</button>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(executionFlowHref)}" data-zh="执行流程 / Execution flow" data-en="Execution flow / 执行流程">执行流程 / Execution flow</a>
                </p>
                <div id="executionResult" class="hint" data-copy="planned steps: ${plannedStepCount}" data-copy-label="planned runbook step count">已规划 ${plannedStepCount} 个步骤。主界面不展开 1~16 步；请打开“执行流程 / Execution flow”查看独立视图。</div>`;
              applyLanguage();
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
                const job = await requireOk(response, 'Refresh job status');

                renderJob(job);
                applyLanguage();
            refreshJobs(false);
                setStatus(`Job refreshed. Status: ${formatJobStatus(job.status)}.`, false);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function refreshJobs(showStatus) {
              // Inputs: optional status flag from the recent-jobs refresh
              // button. Processing: fetches the in-memory job list and renders
              // copyable status/path rows. Return: no value.
              if (showStatus) {
                setBusy(true);
                setStatus('Refreshing recent jobs...', false);
              }

              try {
                const response = await fetch('/api/jobs');
                const jobs = await requireOk(response, 'Refresh recent jobs');
                renderJobList(Array.isArray(jobs) ? jobs : []);
                if (showStatus) {
                  setStatus(`Recent jobs refreshed: ${Array.isArray(jobs) ? jobs.length : 0} job(s).`, false);
                }
              } catch (error) {
                if (showStatus) {
                  setStatus(error.message, true);
                }
              } finally {
                if (showStatus) {
                  setBusy(false);
                }
              }
            }

            function renderJobList(jobs) {
              // Inputs: job array from /api/jobs. Processing: renders a compact
              // copyable table with status, sample, and report path fields.
              // Return: no value.
              const container = document.getElementById('jobList');
              if (!container) {
                return;
              }

              if (!jobs.length) {
                container.innerHTML = '<p>No jobs are currently held by the Web host.</p>';
                return;
              }

              const rows = jobs.slice().reverse().map(job => {
                const jobId = String(job.jobId || '');
                const statusLabel = formatJobStatus(job.status);
                const samplePath = job.sample?.fullPath || job.submission?.samplePath || '';
                const reportPath = job.htmlReportPath || '';
                return `
                <tr>
                  <td>${copyableCode(jobId, 'job id')}</td>
                  <td data-copy="${escapeAttribute(statusLabel)}" data-copy-label="job status">${escapeHtml(statusLabel)}</td>
                  <td>${copyableCode(samplePath, 'job sample path', '-')}</td>
                  <td>${copyableCode(reportPath, 'job report.html path', '-')}</td>
                  <td><button class="secondary" onclick="refreshJob('${escapeJs(jobId)}')" data-zh="打开" data-en="Open">打开</button></td>
                </tr>`;
              }).join('');

              container.innerHTML = `
                <table>
                  <thead><tr><th>Job ID</th><th data-zh="状态" data-en="Status">状态</th><th data-zh="样本" data-en="Sample">样本</th><th>report.html</th><th data-zh="操作" data-en="Action">操作</th></tr></thead>
                  <tbody>${rows}</tbody>
                </table>`;
              applyLanguage();
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
                const snapshot = await requireOk(response, 'Refresh live raw telemetry');

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
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/execute`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    live,
                    stepTimeoutSeconds: 1800,
                    importGuestEvents: true
                  })
                });
                const payload = await requireOk(response, live ? 'Execute live Hyper-V runbook' : 'Record dry-run runbook execution');

                const execution = payload.execution || payload;
                if (payload.job) {
                  renderJob(payload.job);
                }

                renderExecution(execution, payload);
                applyLanguage();
            refreshJobs(false);
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
                const explicitPath = (document.getElementById('guestImportPath')?.value || '').trim();
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/guest-events/import`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(explicitPath ? { eventsPath: explicitPath } : {})
                });
                const job = await requireOk(response, 'Import guest events and refresh report');

                renderJob(job);
                applyLanguage();
            refreshJobs(false);
                setStatus(`Guest events imported. Report refreshed at ${job.htmlReportPath || 'report.html'}.`, false);
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            function renderExecution(result, wrapper) {
              // Inputs: runbook execution response and wrapper metadata.
              // Processing: renders a compact summary only. Detailed step flow
              // lives on /jobs/{jobId}/execution-flow so the main dashboard does
              // not inline the 1~16 runbook steps, PowerShell, stdout, or stderr.
              const jobId = result.jobId || (wrapper && wrapper.job && wrapper.job.jobId) || '';
              const flowHref = jobId ? `/jobs/${encodeURIComponent(jobId)}/execution-flow` : '#';
              const importMessage = wrapper && wrapper.guestImportMessage ? `<p class="${wrapper.guestImportSucceeded ? 'ok' : 'hint'}">${escapeHtml(wrapper.guestImportMessage)}</p>` : '';
              const failedStep = Array.isArray(result.stepResults) ? result.stepResults.find(step => step && step.success === false) : null;
              const failure = failedStep
                ? `<p class="error"><strong>失败步骤 / Failed step:</strong> ${escapeHtml(failedStep.title || failedStep.stepId || '')}${failedStep.message ? ` — ${escapeHtml(failedStep.message)}` : ''}</p>`
                : '';
              const successClass = result.success ? 'status-ok' : 'status-failed';
              document.getElementById('executionResult').innerHTML = `
                <div class="pathbox" data-copy="mode=${escapeAttribute(result.mode)}; success=${result.success}; executed=${result.executedSteps}/${result.totalSteps}; duration=${escapeAttribute(formatDuration(result.duration))}" data-copy-label="runbook execution summary">
                  <p><strong>模式 / Mode:</strong> ${escapeHtml(result.mode)} · <strong>结果 / Result:</strong> <span class="${successClass}">${result.success ? '成功 / success' : '失败 / failed'}</span></p>
                  <p><strong>进度 / Progress:</strong> ${result.executedSteps}/${result.totalSteps} · <strong>耗时 / Duration:</strong> ${escapeHtml(formatDuration(result.duration))}</p>
                  ${result.message ? `<p class="error">${escapeHtml(result.message)}</p>` : ''}
                  ${failure}
                  ${importMessage}
                  <p class="button-row">
                    <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(flowHref)}" data-zh="执行流程 / Execution flow" data-en="Execution flow / 执行流程">执行流程 / Execution flow</a>
                  </p>
                </div>`;
              applyLanguage();
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
              const messageText = (job.messages || []).join('\n').toLowerCase();
              if (job.guestEventsPath) {
                if (messageText.includes('found no events')) {
                  return {
                    label: 'imported empty',
                    detail: `Guest import used ${job.guestEventsPath}, but no events were found. Check guest collection logs and driver-events.jsonl.`
                  };
                }

                return {
                  label: 'imported',
                  detail: `Guest events are recorded from ${job.guestEventsPath}.`
                };
              }

              if (messageText.includes('guest') && (messageText.includes('not imported') || messageText.includes('not found') || messageText.includes('failed'))) {
                return {
                  label: 'import failed',
                  detail: 'Guest import did not complete. Review the latest job message and paste an explicit events.json or .jsonl path if needed.'
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
              element.setAttribute('data-copy', message || '');
              element.setAttribute('data-copy-label', 'status message');
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
              return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\r/g, '\\r').replace(/\n/g, '\\n');
            }

            async function requireOk(response, action) {
              const payload = await readResponsePayload(response);
              if (!response.ok) {
                throw new Error(formatHttpError(action, response, payload));
              }

              return payload;
            }

            async function readResponsePayload(response) {
              const text = await response.text();
              if (!text) {
                return {};
              }

              try {
                return JSON.parse(text);
              } catch {
                return { raw: text };
              }
            }

            function formatHttpError(action, response, payload) {
              const statusText = response.statusText ? ` ${response.statusText}` : '';
              const detail = extractErrorMessage(payload) || 'No error detail was returned by the server.';
              const traceId = payload && (payload.traceId || payload.requestId);
              return `${action} failed (HTTP ${response.status}${statusText}${traceId ? `, trace ${traceId}` : ''}): ${detail}`;
            }

            function extractErrorMessage(payload) {
              if (!payload) {
                return '';
              }

              if (typeof payload === 'string') {
                return payload;
              }

              if (payload.error) {
                if (typeof payload.error === 'string') {
                  return payload.error;
                }

                if (payload.error.message) {
                  return payload.error.message;
                }
              }

              if (payload.title || payload.detail) {
                return [payload.title, payload.detail].filter(Boolean).join(': ');
              }

              if (payload.message) {
                return payload.message;
              }

              if (payload.errors) {
                return Object.entries(payload.errors)
                  .map(([field, values]) => `${field}: ${Array.isArray(values) ? values.join('; ') : values}`)
                  .join(' | ');
              }

              if (payload.raw) {
                return payload.raw;
              }

              return '';
            }

            applyLanguage();
            refreshJobs(false);
          </script>
        </body>
        </html>
        """;
    }
}
