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
            :root { --blue:#43A0FF; --blue-dark:#0B6FCC; --ink:#0f172a; --muted:#64748b; --line:#dbeafe; --soft:#eef7ff; color-scheme: light; }
            * { box-sizing: border-box; }
            body { font-family: "Microsoft YaHei UI", Segoe UI, Arial, sans-serif; margin: 0; color: var(--ink); background: radial-gradient(circle at 8% 4%,rgba(67,160,255,.20),transparent 27%),linear-gradient(180deg,#f4f9ff,#f8fafc); }
            header { padding: 28px 36px; color: white; background: radial-gradient(circle at 85% 10%,rgba(67,160,255,.55),transparent 32%),linear-gradient(135deg,#08111f,#123d66 62%,#0d5fa8); }
            .header-row { align-items: flex-start; display: flex; gap: 18px; justify-content: space-between; }
            .lang-toggle { background: rgba(255,255,255,.16); border: 1px solid rgba(255,255,255,.35); white-space: nowrap; }
            .topnav { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
            .topnav a { border: 1px solid rgba(255,255,255,.35); border-radius: 999px; color: white; font-weight: 700; padding: 7px 11px; text-decoration: none; }
            main { max-width: 1220px; margin: 24px auto; padding: 0 24px 48px; }
            section { background: rgba(255,255,255,.96); border: 1px solid var(--line); border-radius: 18px; box-shadow: 0 14px 36px rgba(15, 23, 42, .07); margin-bottom: 18px; padding: 22px; }
            label { display: block; font-weight: 700; margin: 14px 0 6px; }
            input { box-sizing: border-box; width: 100%; border: 1px solid #c7dff7; border-radius: 11px; padding: 10px 12px; font: inherit; }
            input[type="checkbox"] { width: auto; }
            button, a.buttonlink { border: 0; border-radius: 11px; background: var(--blue); color: white; cursor: pointer; display: inline-block; font-weight: 800; margin-top: 14px; padding: 10px 16px; text-decoration: none; }
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
            .hint { color: var(--muted); font-size: 14px; }
            .status { margin-top: 12px; min-height: 24px; }
            .error { color: #b91c1c; }
            .ok { color: #047857; }
            .pathbox { background: #f8fbff; border: 1px solid var(--line); border-radius: 12px; margin-top: 10px; padding: 12px; }
            .callout { background:#eef7ff; border:1px solid #bfdbfe; border-radius:14px; margin-top:12px; padding:14px; }
            .callout strong { display:block; margin-bottom:4px; }
            .report-notice { background:#ecfdf5; border:1px solid #86efac; border-radius:14px; color:#065f46; margin:12px 0; padding:14px; }
            .report-notice[hidden] { display:none; }
            .report-notice p { margin:6px 0; }
            .pill { background: #e7f3ff; border:1px solid rgba(67,160,255,.35); border-radius: 999px; color: #075985; display: inline-block; font-size: 12px; font-weight: 800; padding: 4px 9px; }
            .pill.ready { background:#dcfce7; border-color:#86efac; color:#166534; }
            .tabs { display:flex; flex-wrap:wrap; gap:8px; margin:16px 0 10px; }
            .tab-button { background:#e7f3ff; border:1px solid rgba(67,160,255,.35); color:#075985; margin-top:0; }
            .tab-button.active { background:var(--blue); color:white; }
            .tab-panel { display:none; border:1px solid var(--line); border-radius:16px; background:#f8fbff; padding:16px; }
            .tab-panel.active { display:block; }
            .vm-grid { display:grid; gap:12px; grid-template-columns:repeat(3,minmax(0,1fr)); }
            details.vm-config { background:#f8fbff; border:1px dashed #b9d7f3; border-radius:14px; margin-top:16px; padding:12px 14px; }
            details.vm-config summary { cursor:pointer; font-weight:800; }
            .job-card { border-left:5px solid var(--blue); }
            .job-summary { display:grid; gap:12px; grid-template-columns:repeat(4,minmax(0,1fr)); margin-top:12px; }
            .metric { background:#f8fbff; border:1px solid var(--line); border-radius:14px; padding:12px; }
            .metric strong { color:var(--muted); display:block; font-size:12px; margin-bottom:6px; }
            .progress-box { background:#f8fbff; border:1px solid var(--line); border-radius:16px; margin-top:14px; padding:14px; }
            .progress-bar { background:#dbeafe; border-radius:999px; height:12px; overflow:hidden; }
            .progress-fill { background:linear-gradient(90deg,var(--blue),#7dd3fc); height:100%; width:0%; transition:width .25s ease; }
            .stages { display:grid; gap:8px; grid-template-columns:repeat(4,minmax(0,1fr)); margin-top:12px; }
            .stage { background:white; border:1px solid #e5edf6; border-radius:12px; color:#64748b; padding:9px; }
            .stage.active { border-color:var(--blue); box-shadow:0 0 0 3px rgba(67,160,255,.12); color:#075985; font-weight:800; }
            .stage.done { background:#ecfdf5; border-color:#bbf7d0; color:#047857; }
            .compact-details { margin-top:12px; }
            .compact-details summary { cursor:pointer; color:#075985; font-weight:800; }
            .empty { border:1px dashed #b9d7f3; border-radius:12px; color:var(--muted); padding:14px; }
            .status-failed { color: #b91c1c; font-weight: 700; }
            .status-ok { color: #047857; font-weight: 700; }
            @media (max-width: 980px) { .grid,.vm-grid,.job-summary,.stages { grid-template-columns: 1fr; } header { padding:24px; } }
          </style>
        </head>
        <body>
          <header>
            <div class="header-row">
              <div>
                <h1 data-zh="KSword 沙箱主机" data-en="KSword Sandbox Host">KSword 沙箱主机</h1>
                <p data-zh="提交样本后先生成安全计划；主页面只保留关键状态、报告入口和独立监控入口，排障细节放在“执行流程”。" data-en="Submit a sample to create a safe plan first. The dashboard keeps only key status, report access, and the standalone monitor; troubleshooting details live in Execution flow.">提交样本后先生成安全计划；主页面只保留关键状态、报告入口和独立监控入口，排障细节放在“执行流程”。</p>
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
              <p class="hint"><span data-zh="三种输入方式已拆成 Tab，默认选中“上传 EXE”。生成计划不会执行样本；确认后再启动虚拟机分析。" data-en="The three input methods are tabs, with Upload EXE selected by default. Creating a plan does not execute the sample; start VM analysis only after review.">三种输入方式已拆成 Tab，默认选中“上传 EXE”。生成计划不会执行样本；确认后再启动虚拟机分析。</span></p>
              <div class="tabs" role="tablist">
                <button id="tab-upload" class="tab-button active" type="button" role="tab" aria-selected="true" aria-controls="panel-upload" onclick="selectPlanTab('upload')" data-zh="上传 EXE" data-en="Upload EXE">上传 EXE</button>
                <button id="tab-path" class="tab-button" type="button" role="tab" aria-selected="false" aria-controls="panel-path" onclick="selectPlanTab('path')" data-zh="已有路径" data-en="Existing path">已有路径</button>
                <button id="tab-scan" class="tab-button" type="button" role="tab" aria-selected="false" aria-controls="panel-scan" onclick="selectPlanTab('scan')" data-zh="扫描目录" data-en="Scan folder">扫描目录</button>
              </div>
              <div id="panel-upload" class="tab-panel active" role="tabpanel" aria-labelledby="tab-upload">
                  <h3 data-zh="上传 .exe 并生成计划" data-en="Upload .exe and create plan">上传 .exe 并生成计划</h3>
                  <p class="hint" data-zh="保存文件并生成一个可检查的分析计划；此步骤不会执行样本。" data-en="Stores the file and creates a reviewable analysis plan; this step does not execute the sample.">保存文件并生成一个可检查的分析计划；此步骤不会执行样本。</p>
                  <label for="sampleUpload" data-zh="可执行文件（.exe）" data-en="Executable file (.exe)">可执行文件（.exe）</label>
                  <input id="sampleUpload" type="file" accept=".exe,application/vnd.microsoft.portable-executable,application/octet-stream">
                  <label for="uploadDuration" data-zh="分析时长（秒）" data-en="Analysis duration, seconds">分析时长（秒）</label>
                  <input id="uploadDuration" type="number" min="1" max="900" value="120">
                  <button onclick="uploadAndPlan()" data-zh="上传 .exe → 生成计划" data-en="Upload .exe → create plan">上传 .exe → 生成计划</button>
              </div>
              <div id="panel-path" class="tab-panel" role="tabpanel" aria-labelledby="tab-path" hidden>
                  <h3 data-zh="规划已有主机路径" data-en="Plan existing host path">规划已有主机路径</h3>
                  <p class="hint" data-zh="适用于样本已经位于本机或挂载共享时。服务器会先校验路径，再写入产物。" data-en="Use when the sample is already on this host or a mounted share. The server validates the path before writing artifacts.">适用于样本已经位于本机或挂载共享时。服务器会先校验路径，再写入产物。</p>
                  <label for="samplePath" data-zh="主机上的可执行文件路径" data-en="Executable path on host">主机上的可执行文件路径</label>
                  <input id="samplePath" placeholder="D:\Temp\sample.exe">
                  <label for="duration" data-zh="分析时长（秒）" data-en="Analysis duration, seconds">分析时长（秒）</label>
                  <input id="duration" type="number" min="1" max="900" value="120">
                  <button onclick="planPath()" data-zh="从路径生成计划" data-en="Create plan from path">从路径生成计划</button>
              </div>
              <div id="panel-scan" class="tab-panel" role="tabpanel" aria-labelledby="tab-scan" hidden>
                  <h3 data-zh="扫描文件夹后规划" data-en="Scan folder, then plan">扫描文件夹后规划</h3>
                  <p class="hint" data-zh="仅基于元数据发现 .exe。可复核候选项，或一键规划排序后的第一个结果。" data-en="Metadata-only .exe discovery. Review candidates or use one-click planning for the first sorted result.">仅基于元数据发现 .exe。可复核候选项，或一键规划排序后的第一个结果。</p>
                  <label for="scanPath" data-zh="目录或精确 .exe 路径" data-en="Directory or exact .exe path">目录或精确 .exe 路径</label>
                  <input id="scanPath" placeholder="D:\Temp\incoming">
                  <label for="maxDepth" data-zh="最大扫描深度" data-en="Max scan depth">最大扫描深度</label>
                  <input id="maxDepth" type="number" min="0" max="16" value="4">
                  <button class="secondary" onclick="scanTargets()" data-zh="查找 .exe 候选项" data-en="Find .exe candidates">查找 .exe 候选项</button>
                  <button class="secondary" onclick="scanAndPlanFirst()" data-zh="扫描并规划第一个候选项" data-en="Scan and plan first candidate">扫描并规划第一个候选项</button>
              </div>
              <details class="vm-config">
                <summary data-zh="高级：虚拟机配置" data-en="Advanced: VM configuration">高级：虚拟机配置</summary>
                <p class="hint" data-zh="默认从 config 读取；这里的值只覆盖当前任务，不写入配置文件。" data-en="Defaults are loaded from config; these values only override the current job and do not write config files.">默认从 config 读取；这里的值只覆盖当前任务，不写入配置文件。</p>
                <div class="vm-grid">
                  <div><label for="goldenVmName" data-zh="虚拟机名称" data-en="VM name">虚拟机名称</label><input id="goldenVmName" placeholder="KSwordSandbox-Win10-Golden"></div>
                  <div><label for="goldenSnapshotName" data-zh="还原点" data-en="Checkpoint">还原点</label><input id="goldenSnapshotName" placeholder="Clean"></div>
                  <div><label for="guestUserName" data-zh="虚拟机用户" data-en="Guest user">虚拟机用户</label><input id="guestUserName" placeholder="SandboxUser"></div>
                  <div><label for="guestWorkingDirectory" data-zh="虚拟机工作目录" data-en="Guest working folder">虚拟机工作目录</label><input id="guestWorkingDirectory" placeholder="C:\KSwordSandbox"></div>
                  <div><label for="guestPayloadRoot" data-zh="工具目录（主机）" data-en="Host tool folder">工具目录（主机）</label><input id="guestPayloadRoot" placeholder="D:\Temp\KSwordSandbox\payload\guest-tools"></div>
                  <div><label for="useMockCollector"><input id="useMockCollector" type="checkbox"> <span data-zh="使用模拟采集器" data-en="Use mock collector">使用模拟采集器</span></label></div>
                </div>
              </details>
              <div id="status" class="status"></div>
            </section>

            <section>
              <h2><span data-zh="可执行文件候选项" data-en="Executable candidates">可执行文件候选项</span> <span id="candidateCount" class="pill">0</span></h2>
              <div id="candidates" class="hint"><span data-zh="尚未运行扫描。" data-en="No scan has been run yet.">尚未运行扫描。</span></div>
            </section>

            <section id="current-job">
              <h2 data-zh="当前任务" data-en="Current job">当前任务</h2>
              <div id="jobResult" class="hint"><span data-zh="尚未规划任务。" data-en="No job planned yet.">尚未规划任务。</span></div>
            </section>

            <section id="recent-jobs">
              <h2 data-zh="近期任务" data-en="Recent jobs">近期任务</h2>
              <p class="hint" data-zh="这里仅列出关键状态和入口；详细执行流程和原始事件流在独立页面查看。" data-en="Only key status and entry points are listed here; execution flow and raw event streams live on separate pages.">这里仅列出关键状态和入口；详细执行流程和原始事件流在独立页面查看。</p>
              <button class="secondary" onclick="refreshJobs(true)" data-zh="刷新任务列表" data-en="Refresh job list">刷新任务列表</button>
              <div id="jobList" class="hint"><span data-zh="尚未加载任务。" data-en="No jobs loaded yet.">尚未加载任务。</span></div>
            </section>
          </main>
          <div id="copyToast" class="toast" role="status" aria-live="polite"></div>
          <script>
            let copyToastTimer = null;
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';
            let progressTimer = null;
            let progressStageIndex = 0;
            const liveStages = [
              ['任务已规划', 'Job planned'],
              ['检查 Hyper-V / 凭据', 'Check Hyper-V / credential'],
              ['恢复检查点', 'Restore checkpoint'],
              ['启动虚拟机', 'Start VM'],
              ['复制样本与工具', 'Stage sample and tools'],
              ['运行样本与采集器', 'Run sample and collectors'],
              ['回收事件', 'Collect events'],
              ['导入并生成报告', 'Import and report']
            ];

            function t(zh, en) {
              return currentLanguage === 'en' ? en : zh;
            }

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
                if (element.id === 'candidates' || element.id === 'jobResult' || element.id === 'jobList' || element.id === 'executionResult' || element.id === 'analysisProgress') {
                  return;
                }

                element.textContent = currentLanguage === 'en' ? element.getAttribute('data-en') : element.getAttribute('data-zh');
              });
            }

            function formatJobStatus(status) {
              const names = {
                0: '排队中 / Queued',
                1: '规划中 / Planning',
                2: '已规划 / Planned',
                3: '运行中 / Running',
                4: '已完成 / Completed',
                5: '失败 / Failed'
              };
              const namedStatuses = {
                queued: '排队中 / Queued',
                planning: '规划中 / Planning',
                planned: '已规划 / Planned',
                running: '运行中 / Running',
                completed: '已完成 / Completed',
                failed: '失败 / Failed'
              };
              if (status === null || status === undefined || status === '') {
                return '-';
              }

              if (typeof status === 'number' || /^\d+$/.test(String(status))) {
                const numeric = Number(status);
                return names[numeric] ? `${names[numeric]} (${numeric})` : `未知 / Unknown (${numeric})`;
              }

              const normalized = String(status).trim().toLowerCase();
              if (namedStatuses[normalized]) {
                return namedStatuses[normalized];
              }

              return String(status);
            }

            function selectPlanTab(name) {
              for (const candidate of ['upload', 'path', 'scan']) {
                const tab = document.getElementById(`tab-${candidate}`);
                const panel = document.getElementById(`panel-${candidate}`);
                tab.classList.toggle('active', candidate === name);
                tab.setAttribute('aria-selected', candidate === name ? 'true' : 'false');
                tab.tabIndex = candidate === name ? 0 : -1;
                panel.classList.toggle('active', candidate === name);
                panel.hidden = candidate !== name;
              }
            }

            async function loadConfigDefaults() {
              try {
                const response = await fetch('/api/config');
                const config = await requireOk(response, 'Load config');
                document.getElementById('goldenVmName').value = config.hyperV?.goldenVmName || '';
                document.getElementById('goldenSnapshotName').value = config.hyperV?.goldenSnapshotName || '';
                document.getElementById('guestUserName').value = config.guest?.userName || '';
                document.getElementById('guestWorkingDirectory').value = config.guest?.workingDirectory || '';
                document.getElementById('guestPayloadRoot').value = config.paths?.guestPayloadRoot || '';
                document.getElementById('useMockCollector').checked = Boolean(config.driver?.useMockCollector);
              } catch {
                // Keep placeholders when config loading fails; planning still works with server defaults.
              }
            }

            function getVmConfig() {
              const clean = id => {
                const value = document.getElementById(id).value.trim();
                return value ? value : undefined;
              };

              return {
                goldenVmName: clean('goldenVmName'),
                goldenSnapshotName: clean('goldenSnapshotName'),
                guestUserName: clean('guestUserName'),
                guestWorkingDirectory: clean('guestWorkingDirectory'),
                guestPayloadRoot: clean('guestPayloadRoot'),
                useMockCollector: document.getElementById('useMockCollector').checked
              };
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
              setStatus(t('正在扫描路径...', 'Scanning host path...'), false);
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
                const payload = await requireOk(response, t('扫描候选项', 'Scan executable candidates'));

                renderCandidates(payload);
                setStatus(t(`扫描完成：${payload.candidates.length} 个候选项。`, `Scan complete: ${payload.candidates.length} executable candidate(s).`), false);
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
                  setStatus(t('扫描完成，但没有可规划的 .exe 候选项。', 'Scan completed, but no executable candidates were found to plan.'), true);
                  return;
                }

                setStatus(t(`正在规划第一个候选项：${first.fullPath}`, `Planning first candidate: ${first.fullPath}`), false);
                await planPath(first.fullPath);
              } catch {
                // scanTargets or planPath already wrote the visible status.
              }
            }

            async function uploadAndPlan() {
              const input = document.getElementById('sampleUpload');
              if (!input.files || input.files.length === 0) {
                setStatus(t('请选择一个 .exe 文件上传。', 'Select one .exe file to upload.'), true);
                return;
              }

              setBusy(true);
              setStatus(t('正在上传样本并保存...', 'Uploading sample into storage...'), false);
              try {
                const form = new FormData();
                form.append('sample', input.files[0]);
                const uploadResponse = await fetch('/api/files/upload', {
                  method: 'POST',
                  body: form
                });
                const uploaded = await requireOk(uploadResponse, t('上传样本', 'Upload executable'));

                document.getElementById('samplePath').value = uploaded.fullPath;
                document.getElementById('duration').value = document.getElementById('uploadDuration').value || 120;
                setStatus(t('上传完成，正在生成分析计划...', `Uploaded to ${uploaded.fullPath}; creating analysis plan...`), false);
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
                setStatus(t('请输入可执行文件路径，或从扫描结果中选择一个。', 'Enter an executable path or select one from scan results.'), true);
                return;
              }

              setBusy(true);
              setStatus(t('正在生成分析计划...', 'Creating analysis plan...'), false);
              try {
                const response = await fetch('/api/jobs/plan', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    samplePath,
                    durationSeconds: Number(document.getElementById('duration').value || 120),
                    dryRun: true,
                    ...getVmConfig()
                  })
                });
                const payload = await requireOk(response, t('生成分析计划', 'Create analysis plan'));

                renderJob(payload);
                applyLanguage();
            refreshJobs(false);
                setStatus(t('计划已生成。确认当前任务卡片后，可启动虚拟机分析。', 'Plan created. Review the current job card, then start VM analysis when ready.'), false);
                document.getElementById('current-job').scrollIntoView({ behavior: 'smooth', block: 'start' });
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function planSelectedCandidate() {
              const selected = document.querySelector('input[name="candidate"]:checked');
              if (!selected || !selected.value) {
                setStatus(t('请先从候选项表格中选择一个可执行文件。', 'Select one executable candidate from the scan table before planning.'), true);
                return;
              }

              document.getElementById('samplePath').value = selected.value;
              await planPath(selected.value);
            }

            function renderCandidates(result) {
              document.getElementById('candidateCount').textContent = result.candidates.length;
              if (!result.candidates.length) {
                document.getElementById('candidates').innerHTML = '<p data-zh="没有找到 .exe 候选项。" data-en="No .exe candidates found.">没有找到 .exe 候选项。</p>';
                applyLanguage();
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
              const jobId = String(job.jobId || '');
              const statusLabel = formatJobStatus(job.status);
              const htmlReportPath = job.htmlReportPath || '';
              const zhReportPath = job.htmlReportZhPath || '';
              const enReportPath = job.htmlReportEnPath || '';
              const jsonReportPath = job.jsonReportPath || '';
              const runbookExecutionPath = job.runbookExecutionResultPath || '';
              const guestEventsPath = job.guestEventsPath || '';
              const artifactPaths = buildArtifactPaths(job);
              const guestImportStatus = buildGuestImportStatus(job, artifactPaths);
              const servedReportHref = jobId ? `/api/jobs/${encodeURIComponent(jobId)}/report/html` : '';
              const servedZhReportHref = jobId ? `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh` : '';
              const servedEnReportHref = jobId ? `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en` : '';
              const fileReportHref = toFileUri(htmlReportPath);
              const executionFlowHref = jobId ? `/jobs/${encodeURIComponent(jobId)}/execution-flow` : '';
              const liveEventsHref = jobId ? `/jobs/${encodeURIComponent(jobId)}/live-events` : '';
              const reportReady = Boolean(htmlReportPath || zhReportPath || enReportPath);
              const reportBadge = reportReady
                ? '<span class="pill ready" data-zh="已生成" data-en="Ready">已生成</span>'
                : '<span class="pill" data-zh="待生成" data-en="Not ready">待生成</span>';
              const plannedStepCount = job.runbook?.steps?.length || 0;
              const messages = (job.messages || []).slice(-3).map(message => `<li data-copy="${escapeAttribute(message)}" data-copy-label="job message">${escapeHtml(message)} ${copyButton(message, 'job message')}</li>`).join('');
              document.getElementById('jobResult').innerHTML = `
                <article class="job-card">
                  <h3><span data-zh="任务已创建" data-en="Job created">任务已创建</span> ${copyableCode(jobId, 'job id')}</h3>
                  <div class="job-summary">
                    <div class="metric"><strong data-zh="状态" data-en="Status">状态</strong><span class="pill" data-copy="${escapeAttribute(statusLabel)}" data-copy-label="job status">${escapeHtml(statusLabel)}</span></div>
                    <div class="metric"><strong data-zh="样本" data-en="Sample">样本</strong>${copyableCode(job.sample?.fullPath || job.submission?.samplePath || '', 'sample path')}</div>
                    <div class="metric"><strong data-zh="分析时长" data-en="Duration">分析时长</strong><span>${escapeHtml(String(job.submission?.durationSeconds || '-'))}s</span></div>
                    <div class="metric"><strong data-zh="报告" data-en="Report">报告</strong>${reportBadge}</div>
                  </div>
                  <p class="button-row">
                    <button onclick="executeRunbook('${escapeJs(jobId)}', true)" data-zh="启动虚拟机分析" data-en="Start VM analysis">启动虚拟机分析</button>
                    <a class="buttonlink" target="_blank" rel="noopener" href="${escapeHtml(servedZhReportHref)}" data-zh="打开中文报告" data-en="Open Chinese report">打开中文报告</a>
                    <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(servedEnReportHref)}" data-zh="打开英文报告" data-en="Open English report">打开英文报告</a>
                    <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(executionFlowHref)}" data-zh="执行流程" data-en="Execution flow">执行流程</a>
                  </p>
                  <div id="reportNotice" class="report-notice" hidden></div>
                  <div class="callout">
                    <strong data-zh="独立页：实时原始事件监控" data-en="Standalone page: live raw event monitor">独立页：实时原始事件监控</strong>
                    <p class="hint" data-zh="分析运行时可在新标签页查看原始事件；主页面保持简洁，最终结论以报告为准。" data-en="Open raw events in a separate tab while analysis runs; the dashboard stays simple and the final report remains the source of truth.">分析运行时可在新标签页查看原始事件；主页面保持简洁，最终结论以报告为准。</p>
                    <p class="button-row"><a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(liveEventsHref)}" data-zh="打开实时原始事件监控（独立页）" data-en="Open live raw event monitor (standalone)">打开实时原始事件监控（独立页）</a></p>
                  </div>
                  <div id="analysisProgress" class="progress-box stage-progress">
                    <strong data-zh="阶段进度" data-en="Stage progress">阶段进度</strong>
                    <div class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
                    <div id="stageList" class="stages"></div>
                    <p id="progressText" class="hint" data-zh="等待启动。虚拟机恢复/启动可能占用大部分时间。" data-en="Waiting to start. VM restore/start usually takes most of the time.">等待启动。虚拟机恢复/启动可能占用大部分时间。</p>
                  </div>
                  <details id="jobReportPaths" class="compact-details">
                    <summary data-zh="高级详情：事件导入与文件路径" data-en="Advanced details: event import and file paths">高级详情：事件导入与文件路径</summary>
                    <p class="hint"><strong data-zh="事件导入状态" data-en="Event import status">事件导入状态</strong> <span class="pill" data-copy="${escapeAttribute(guestImportStatus.label)}" data-copy-label="guest import status">${escapeHtml(guestImportStatus.label)}</span> <span>${escapeHtml(guestImportStatus.detail)}</span></p>
                    <div class="mini-form">
                      <label for="guestImportPath" data-zh="手动事件文件（可选）" data-en="Manual event file (optional)">手动事件文件（可选）</label>
                      <input id="guestImportPath" placeholder="${escapeAttribute(artifactPaths.eventsJsonPath || 'D:\\runtime\\jobs\\<job>\\guest\\events.json')}" value="${escapeAttribute(guestEventsPath || artifactPaths.eventsJsonPath || '')}" data-copy-label="manual guest import path">
                      <p class="button-row">
                        <button class="secondary" onclick="executeRunbook('${escapeJs(jobId)}', false)" data-zh="仅验证流程（不启动虚拟机）" data-en="Verify flow only (no VM start)">仅验证流程（不启动虚拟机）</button>
                        <button class="secondary" onclick="importGuestEvents('${escapeJs(jobId)}')" data-zh="手动导入事件并刷新报告" data-en="Import events manually and refresh report">手动导入事件并刷新报告</button>
                      </p>
                    </div>
                    <table class="artifact-table">
                      <thead><tr><th data-zh="文件" data-en="File">文件</th><th data-zh="可复制路径" data-en="Copyable path">可复制路径</th><th data-zh="状态" data-en="Status">状态</th></tr></thead>
                      <tbody>
                        <tr><td>report.html</td><td>${copyableCode(artifactPaths.reportHtmlPath, 'report.html path')}</td><td><a target="_blank" rel="noopener" href="${escapeHtml(servedReportHref)}" data-zh="打开服务内报告" data-en="Open served report">打开服务内报告</a> · <a target="_blank" rel="noopener" href="${escapeHtml(fileReportHref)}" data-zh="打开本地文件" data-en="Open local file">打开本地文件</a></td></tr>
                        <tr><td>report.zh.html</td><td>${copyableCode(zhReportPath, 'report.zh.html path')}</td><td><a target="_blank" rel="noopener" href="${escapeHtml(servedZhReportHref)}" data-zh="中文报告" data-en="Chinese report">中文报告</a></td></tr>
                        <tr><td>report.en.html</td><td>${copyableCode(enReportPath, 'report.en.html path')}</td><td><a target="_blank" rel="noopener" href="${escapeHtml(servedEnReportHref)}" data-zh="英文报告" data-en="English report">英文报告</a></td></tr>
                        <tr><td>report.json</td><td>${copyableCode(jsonReportPath, 'report.json path')}</td><td>${artifactStatus(jsonReportPath, t('已记录', 'recorded'))}</td></tr>
                        <tr><td>events.json</td><td>${copyableCode(artifactPaths.eventsJsonPath, 'events.json path')}</td><td>${artifactStatus(artifactPaths.eventsJsonPath, guestEventsPath ? t('已记录 / 导入来源', 'recorded / import source') : t('虚拟机分析后生成', 'expected after VM analysis'))}</td></tr>
                        <tr><td>driver-events.jsonl</td><td>${copyableCode(artifactPaths.driverEventsJsonlPath, 'driver-events.jsonl path')}</td><td>${artifactStatus(artifactPaths.driverEventsJsonlPath, t('驱动遥测文件', 'driver telemetry'))}</td></tr>
                        <tr><td>runbook-execution.json</td><td>${copyableCode(artifactPaths.runbookExecutionPath, 'runbook execution path')}</td><td>${artifactStatus(runbookExecutionPath, runbookExecutionPath ? t('已记录', 'recorded') : t('执行后生成', 'expected after execution'))}</td></tr>
                      </tbody>
                    </table>
                  </details>
                  <details class="compact-details">
                    <summary data-zh="最近消息" data-en="Recent messages">最近消息</summary>
                    ${messages ? `<ul>${messages}</ul>` : '<p class="hint" data-zh="暂无任务消息。" data-en="No job messages recorded.">暂无任务消息。</p>'}
                  </details>
                  <div id="executionResult" class="hint" data-copy="planned steps: ${plannedStepCount}" data-copy-label="planned runbook step count">${t(`已规划 ${plannedStepCount} 个步骤。主界面只显示摘要；请打开“执行流程”查看详情。`, `${plannedStepCount} steps planned. The dashboard shows a summary only; open Execution flow for details.`)}</div>
                </article>`;
              applyLanguage();
              renderStages(0, false);
            }

            async function refreshJob(jobId) {
              // Inputs: jobId from the rendered job panel. Processing: fetches
              // current server-side job state and rerenders the panel. Return:
              // no value; status text reports success or failure.
              if (!jobId) {
                setStatus(t('没有可刷新的任务 ID。', 'No job ID is available to refresh.'), true);
                return;
              }

              setBusy(true);
              setStatus(t('正在刷新任务状态...', 'Refreshing job status...'), false);
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`);
                const job = await requireOk(response, t('刷新任务状态', 'Refresh job status'));

                renderJob(job);
                applyLanguage();
            refreshJobs(false);
                setStatus(t(`任务已刷新。状态：${formatJobStatus(job.status)}。`, `Job refreshed. Status: ${formatJobStatus(job.status)}.`), false);
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
                setStatus(t('正在刷新近期任务...', 'Refreshing recent jobs...'), false);
              }

              try {
                const response = await fetch('/api/jobs');
                const jobs = await requireOk(response, t('刷新近期任务', 'Refresh recent jobs'));
                renderJobList(Array.isArray(jobs) ? jobs : []);
                if (showStatus) {
                  setStatus(t(`近期任务已刷新：${Array.isArray(jobs) ? jobs.length : 0} 个。`, `Recent jobs refreshed: ${Array.isArray(jobs) ? jobs.length : 0} job(s).`), false);
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
                container.innerHTML = '<p data-zh="当前没有任务。" data-en="No jobs are currently held by the Web host.">当前没有任务。</p>';
                applyLanguage();
                return;
              }

              const rows = jobs.slice().reverse().map(job => {
                const jobId = String(job.jobId || '');
                const statusLabel = formatJobStatus(job.status);
                const samplePath = job.sample?.fullPath || job.submission?.samplePath || '';
                const reportPath = job.htmlReportPath || '';
                const reportHref = `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${currentLanguage === 'en' ? 'en' : 'zh'}`;
                const reportCell = reportPath
                  ? `<a target="_blank" rel="noopener" href="${escapeHtml(reportHref)}" data-zh="打开报告" data-en="Open report">打开报告</a>`
                  : '<span class="hint" data-zh="待生成" data-en="Not ready">待生成</span>';
                return `
                <tr>
                  <td>${copyableCode(jobId, 'job id')}</td>
                  <td data-copy="${escapeAttribute(statusLabel)}" data-copy-label="job status">${escapeHtml(statusLabel)}</td>
                  <td>${copyableCode(samplePath, 'job sample path', '-')}</td>
                  <td>${reportCell}</td>
                  <td><button class="secondary" onclick="refreshJob('${escapeJs(jobId)}')" data-zh="打开任务" data-en="Open job">打开任务</button> <a class="buttonlink secondary" href="/jobs/${encodeURIComponent(jobId)}/live-events" target="_blank" rel="noopener" data-zh="实时监控独立页" data-en="Standalone live monitor">实时监控独立页</a></td>
                </tr>`;
              }).join('');

              container.innerHTML = `
                <table>
                  <thead><tr><th>Job ID</th><th data-zh="状态" data-en="Status">状态</th><th data-zh="样本" data-en="Sample">样本</th><th data-zh="报告" data-en="Report">报告</th><th data-zh="入口" data-en="Links">入口</th></tr></thead>
                  <tbody>${rows}</tbody>
                </table>`;
              applyLanguage();
            }

            function showReportPaths(reportPath) {
              // Inputs: the current HTML report path string. Processing: keeps
              // the visible path box in view and mirrors the path into the
              // status line. Return: no value.
              const pathBox = document.getElementById('jobReportPaths');
              if (pathBox) {
                pathBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              }

              setStatus(reportPath ? t(`报告路径：${reportPath}`, `HTML report path: ${reportPath}`) : t('当前任务还没有报告路径。', 'No HTML report path is recorded for this job yet.'), !reportPath);
            }

            function renderStages(active, completed) {
              const list = document.getElementById('stageList');
              const fill = document.getElementById('progressFill');
              if (!list || !fill) {
                return;
              }

              list.innerHTML = liveStages.map((stage, index) => {
                const css = completed || index < active ? 'done' : index === active ? 'active' : '';
                return `<div class="stage ${css}">${escapeHtml(t(stage[0], stage[1]))}</div>`;
              }).join('');
              const percent = completed ? 100 : Math.min(94, Math.round((active / (liveStages.length - 1)) * 100));
              fill.style.width = `${percent}%`;
            }

            function startEstimatedProgress(live) {
              stopEstimatedProgress();
              progressStageIndex = live ? 1 : 0;
              renderStages(progressStageIndex, false);
              const text = document.getElementById('progressText');
              if (text) {
                text.textContent = live
                  ? t('正在执行虚拟机分析；启动或还原可能需要几十秒到数分钟。', 'Executing VM analysis; start or restore may take tens of seconds to minutes.')
                  : t('正在验证流程（不启动虚拟机）。', 'Verifying flow without starting the VM.');
              }

              progressTimer = setInterval(() => {
                progressStageIndex = Math.min(liveStages.length - 2, progressStageIndex + 1);
                renderStages(progressStageIndex, false);
                const stage = liveStages[progressStageIndex];
                if (text) {
                  text.textContent = `${t('当前阶段', 'Current stage')}: ${t(stage[0], stage[1])}`;
                }
              }, live ? 9000 : 1500);
            }

            function stopEstimatedProgress() {
              if (progressTimer) {
                clearInterval(progressTimer);
                progressTimer = null;
              }
            }

            function openReport(jobId) {
              const lang = currentLanguage === 'en' ? 'en' : 'zh';
              window.location.href = `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${lang}`;
            }

            function buildReportHref(jobId, lang) {
              return `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${lang}`;
            }

            function showReportReadyNotice(jobId, autoOpen) {
              const notice = document.getElementById('reportNotice');
              if (!notice || !jobId) {
                return;
              }

              const currentHref = buildReportHref(jobId, currentLanguage === 'en' ? 'en' : 'zh');
              const zhHref = buildReportHref(jobId, 'zh');
              const enHref = buildReportHref(jobId, 'en');
              notice.hidden = false;
              notice.innerHTML = `
                <strong data-zh="报告已生成" data-en="Report is ready">报告已生成</strong>
                <p data-zh="${autoOpen ? '页面即将打开当前语言报告；如果没有跳转，请点击下方按钮。' : '报告已刷新，可直接打开查看。'}" data-en="${autoOpen ? 'The report will open in the current language shortly; if it does not, use the buttons below.' : 'The report has been refreshed and is ready to open.'}">${autoOpen ? '页面即将打开当前语言报告；如果没有跳转，请点击下方按钮。' : '报告已刷新，可直接打开查看。'}</p>
                <p class="button-row">
                  <a class="buttonlink" href="${escapeHtml(currentHref)}" data-zh="打开报告" data-en="Open report">打开报告</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(zhHref)}" data-zh="新标签打开中文报告" data-en="Open Chinese report in new tab">新标签打开中文报告</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(enHref)}" data-zh="新标签打开英文报告" data-en="Open English report in new tab">新标签打开英文报告</a>
                </p>`;
              applyLanguage();
              notice.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              setStatus(
                autoOpen
                  ? t('报告已生成，正在打开；如果没有跳转，请点击“打开报告”。', 'Report is ready and opening; if it does not navigate, click Open report.')
                  : t('报告已生成，可在当前任务卡片中打开。', 'Report is ready; open it from the current job card.'),
                false);
              if (autoOpen) {
                setTimeout(() => openReport(jobId), 1600);
              }
            }

            async function executeRunbook(jobId, live) {
              setBusy(true);
              startEstimatedProgress(live);
              setStatus(live ? t('正在启动虚拟机分析...', 'Starting VM analysis...') : t('正在验证流程（不启动虚拟机）...', 'Verifying flow without starting the VM...'), false);
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
                const payload = await requireOk(response, live ? t('执行虚拟机分析', 'Execute VM analysis') : t('验证流程', 'Verify flow'));

                const execution = payload.execution || payload;
                if (payload.job) {
                  renderJob(payload.job);
                }

                renderExecution(execution, payload);
                applyLanguage();
            refreshJobs(false);
                const suffix = payload.guestImportMessage ? ` ${payload.guestImportMessage}` : '';
                const importFailed = Boolean(payload.guestImportMessage && !payload.guestImportSucceeded);
                stopEstimatedProgress();
                renderStages(liveStages.length - 1, Boolean(execution.success));
                setStatus((execution.success ? t('分析流程已完成。', 'Analysis flow completed.') : t('分析流程失败。', 'Analysis flow stopped with a failure.')) + suffix, !execution.success || importFailed);
                if (live && execution.success) {
                  const text = document.getElementById('progressText');
                  if (text) {
                    text.textContent = t('分析完成，报告已生成，正在打开。', 'Analysis completed; report is ready and opening.');
                  }
                  showReportReadyNotice(jobId, !importFailed);
                }
              } catch (error) {
                stopEstimatedProgress();
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            async function importGuestEvents(jobId) {
              setBusy(true);
              setStatus(t('正在导入事件并刷新报告...', 'Importing events and refreshing report...'), false);
              try {
                const explicitPath = (document.getElementById('guestImportPath')?.value || '').trim();
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/guest-events/import`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(explicitPath ? { eventsPath: explicitPath } : {})
                });
                const job = await requireOk(response, t('导入事件并刷新报告', 'Import events and refresh report'));

                renderJob(job);
                applyLanguage();
            refreshJobs(false);
                showReportReadyNotice(jobId, false);
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
                    label: t('已导入（无事件）', 'imported empty'),
                    detail: t(`已从 ${job.guestEventsPath} 导入，但未发现事件。`, `Guest import used ${job.guestEventsPath}, but no events were found.`)
                  };
                }

                return {
                  label: t('已导入', 'imported'),
                  detail: t(`事件来源：${job.guestEventsPath}`, `Guest events are recorded from ${job.guestEventsPath}.`)
                };
              }

              if (messageText.includes('guest') && (messageText.includes('not imported') || messageText.includes('not found') || messageText.includes('failed'))) {
                return {
                  label: t('导入失败', 'import failed'),
                  detail: t('事件导入未完成；可查看最近消息，必要时手动填写事件文件。', 'Guest import did not complete. Review the latest message and paste an event file if needed.')
                };
              }

              if (artifactPaths.eventsJsonPath || artifactPaths.driverEventsJsonlPath) {
                return {
                  label: t('等待导入', 'waiting for import'),
                  detail: t('尚未记录事件来源；下方高级详情保留预期文件路径。', 'No event source is recorded yet; expected file paths are kept below.')
                };
              }

              return {
                label: t('暂无', 'not available'),
                detail: t('计划或报告路径尚不可用。', 'Plan or report paths are not available yet.')
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

              return `<span class="copy-field"><code data-copy="${escapeAttribute(value)}" data-copy-label="${escapeAttribute(label)}" title="${escapeAttribute(t('右键复制', 'Right-click to copy'))} ${escapeAttribute(label)}">${escapeHtml(text)}</code>${copyButton(value, label)}</span>`;
            }

            function copyButton(value, label) {
              if (value == null || value === '') {
                return '';
              }

              return `<button type="button" class="copy-btn" data-copy="${escapeAttribute(String(value))}" data-copy-label="${escapeAttribute(label || 'value')}" title="${escapeAttribute(t('复制', 'Copy'))} ${escapeAttribute(label || 'value')}">${t('复制', 'Copy')}</button>`;
            }

            async function copyText(value, label) {
              const text = value == null ? '' : String(value);
              if (!text) {
                showCopyToast(t('没有可复制的内容。', 'Nothing to copy.'));
                return;
              }

              try {
                if (navigator.clipboard && window.isSecureContext) {
                  await navigator.clipboard.writeText(text);
                } else {
                  fallbackCopyText(text);
                }

                showCopyToast(t('已复制。', `Copied ${label || 'value'}.`));
              } catch (error) {
                try {
                  fallbackCopyText(text);
                  showCopyToast(t('已复制。', `Copied ${label || 'value'}.`));
                } catch {
                  showCopyToast(t(`复制失败：${error.message}`, `Copy failed: ${error.message}`));
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
                if (button.classList.contains('lang-toggle') || button.classList.contains('tab-button')) {
                  continue;
                }

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
              const detail = extractErrorMessage(payload) || t('服务器未返回错误详情。', 'No error detail was returned by the server.');
              const traceId = payload && (payload.traceId || payload.requestId);
              return `${action} ${t('失败', 'failed')} (HTTP ${response.status}${statusText}${traceId ? `, trace ${traceId}` : ''}): ${detail}`;
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
            selectPlanTab('upload');
            loadConfigDefaults();
            refreshJobs(false);
          </script>
        </body>
        </html>
        """;
    }
}
