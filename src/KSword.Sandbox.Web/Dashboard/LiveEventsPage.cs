using System.Net;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Renders the dedicated live raw-event monitor page. Inputs are the selected
/// job metadata; processing writes a compact bilingual HTML document that polls
/// and streams unclassified events; the method returns a standalone page.
/// </summary>
internal static class LiveEventsPage
{
    internal static string Render(AnalysisJob job)
    {
        var jobId = job.JobId.ToString("D");
        var samplePath = job.Sample?.FullPath ?? job.Submission.SamplePath;
        return $$"""
        <!doctype html>
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <title>Live raw event monitor - KSword Sandbox</title>
          <style>
            :root { --blue:#43A0FF; --ink:#0f172a; --muted:#64748b; --line:#dbeafe; color-scheme: light; }
            * { box-sizing: border-box; }
            body { background: linear-gradient(180deg,#f4f9ff,#f8fafc); color: var(--ink); font-family: "Microsoft YaHei UI", Segoe UI, Arial, sans-serif; margin: 0; }
            header { background: radial-gradient(circle at 84% 12%,rgba(67,160,255,.55),transparent 30%),linear-gradient(135deg,#08111f,#0f5f9f); color:white; padding: 26px 36px; }
            main { max-width: 1280px; margin: 22px auto 54px; padding: 0 22px; }
            .topbar { align-items: flex-start; display:flex; justify-content:space-between; gap:16px; }
            .actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:14px; }
            a.button, button { background: var(--blue); border: 0; border-radius: 11px; color: white; cursor: pointer; display:inline-block; font-weight:800; padding:9px 14px; text-decoration:none; }
            a.secondary, button.secondary { background:#334155; }
            section { background: rgba(255,255,255,.96); border:1px solid var(--line); border-radius:18px; box-shadow:0 16px 42px rgba(15,23,42,.08); margin-bottom:16px; padding:18px; }
            .grid { display:grid; gap:12px; grid-template-columns: repeat(4,minmax(0,1fr)); }
            .metric { background:#f8fbff; border:1px solid var(--line); border-radius:14px; padding:12px; }
            .metric strong { color:var(--muted); display:block; font-size:12px; margin-bottom:6px; }
            .artifact-table td:nth-child(2) { min-width:280px; }
            .artifact-table td:nth-child(4) { min-width:160px; }
            .artifact-action { align-items:center; display:flex; flex-wrap:wrap; gap:8px; }
            .artifact-action .path-only { color:var(--muted); font-size:12px; font-weight:700; }
            .report-ready { background:#eff6ff; border:1px solid rgba(67,160,255,.35); border-radius:14px; margin-top:12px; padding:12px; }
            .muted { color:var(--muted); }
            code { background:#eef7ff; border-radius:7px; padding:2px 5px; word-break:break-all; }
            .table-wrap { max-height:75vh; overflow:auto; border:1px solid var(--line); border-radius:14px; }
            table { border-collapse:separate; border-spacing:0; width:100%; }
            td, th { border-bottom:1px solid #e5edf6; padding:9px; text-align:left; vertical-align:top; }
            th { background:#f7fbff; color:#475569; font-size:12px; position:sticky; top:0; text-transform:uppercase; z-index:1; }
            td:nth-child(5),td:nth-child(6) { max-width:360px; word-break:break-word; }
            .progressbar { background:#e2e8f0; border-radius:999px; height:12px; margin:12px 0; overflow:hidden; }
            .progressbar-fill { background:linear-gradient(90deg,var(--blue),#78c0ff); border-radius:999px; height:100%; transition:width .2s ease; }
            .step-list { display:grid; gap:8px; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); max-height:34vh; overflow:auto; padding:2px; }
            .step-card { background:#f8fbff; border:1px solid var(--line); border-radius:12px; padding:10px; }
            .step-card.running { border-color:var(--blue); box-shadow:0 0 0 2px rgba(67,160,255,.12); }
            .step-card.failed { border-color:#fecaca; background:#fff7f7; }
            .step-card.completed { border-color:#bbf7d0; background:#f7fff9; }
            .step-card strong { display:block; margin-bottom:5px; }
            .pill { background:#e7f3ff; border:1px solid rgba(67,160,255,.45); border-radius:999px; color:#075985; display:inline-block; font-size:12px; font-weight:800; padding:4px 9px; }
            .pill.waiting { background:#f1f5f9; border-color:#cbd5e1; color:#475569; }
            .pill.ready { background:#dcfce7; border-color:#86efac; color:#047857; }
            .pill.endpoint { background:#e0f2fe; border-color:#7dd3fc; color:#0369a1; }
            .status { min-height:24px; margin-top:10px; }
            .ok { color:#047857; }
            .error { color:#b91c1c; }
            .vt-card { border-width:2px; }
            .vt-card .vt-head { align-items:flex-start; display:flex; justify-content:space-between; gap:14px; }
            .vt-card .vt-score { font-size:30px; font-weight:900; line-height:1; }
            .vt-card .vt-stats { display:grid; gap:8px; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); margin-top:12px; }
            .vt-card .vt-stats span { background:rgba(255,255,255,.72); border:1px solid rgba(148,163,184,.28); border-radius:10px; padding:8px; }
            .vt-danger { background:#fff7f7; border-color:#fca5a5; }
            .vt-danger .vt-score { color:#b91c1c; }
            .vt-warning { background:#fff8ed; border-color:#fdba74; }
            .vt-warning .vt-score { color:#c2410c; }
            .vt-ok { background:#f2fff7; border-color:#86efac; }
            .vt-ok .vt-score { color:#047857; }
            .vt-neutral { background:#f8fbff; border-color:#bae6fd; }
            .vt-quiet { background:#f8fafc; border-color:#cbd5e1; }
            .toast { background:#0f172a; border-radius:999px; bottom:22px; color:white; left:50%; opacity:0; padding:10px 16px; pointer-events:none; position:fixed; transform:translate(-50%,12px); transition:.15s; z-index:20; }
            .toast.visible { opacity:.96; transform:translate(-50%,0); }
            [data-copy], code, td, th { cursor: copy; }
            [data-copy]:hover, code:hover, td:hover, th:hover { outline:1px dashed var(--blue); outline-offset:2px; }
            @media(max-width:900px){ .grid{grid-template-columns:1fr;} header{padding:24px;} }
          </style>
        </head>
        <body>
          <header>
            <div class="topbar">
              <div>
                <h1 data-zh="实时原始事件监控" data-en="Live raw event monitor">实时原始事件监控</h1>
                <p data-zh="这是独立动态监控页，可与主界面并行打开；这里只显示未归类原始事件，最终结论请看报告。" data-en="This standalone dynamic monitor can stay open beside the dashboard; it shows unclassified raw events only, and final conclusions stay in the report.">这是独立动态监控页，可与主界面并行打开；这里只显示未归类原始事件，最终结论请看报告。</p>
                <p data-zh="如果此页由上传流程进入，后台分析已经交给 Web Host 执行；你可以停留在这里查看真实 runbook 进度、原始事件、VirusTotal 和证据下载。" data-en="If this page was entered from upload, background analysis has already been handed to the Web host; stay here to watch real runbook progress, raw events, VirusTotal, and evidence downloads.">如果此页由上传流程进入，后台分析已经交给 Web Host 执行；你可以停留在这里查看真实 runbook 进度、原始事件、VirusTotal 和证据下载。</p>
                <p><span class="pill">Job</span> <code data-copy="{{Attr(jobId)}}">{{Html(jobId)}}</code></p>
              </div>
              <button class="secondary" id="langToggle" type="button">English</button>
            </div>
            <div class="actions">
              <a class="button secondary" href="/" data-zh="返回主界面" data-en="Back to dashboard">返回主界面</a>
              <a class="button secondary" href="/jobs/{{Attr(jobId)}}/execution-flow" data-zh="执行流程" data-en="Execution flow">执行流程</a>
              <a class="button" href="/api/jobs/{{Attr(jobId)}}/report/html?lang=zh" target="_blank" rel="noopener" data-zh="打开中文报告" data-en="Open Chinese report">打开中文报告</a>
              <a class="button secondary" href="/api/jobs/{{Attr(jobId)}}/report/html?lang=en" target="_blank" rel="noopener" data-zh="打开英文报告" data-en="Open English report">打开英文报告</a>
              <a class="button secondary" href="/settings" data-zh="设置 / VirusTotal" data-en="Settings / VirusTotal">设置 / VirusTotal</a>
              <button type="button" onclick="connectSse()" data-zh="连接实时流" data-en="Connect stream">连接实时流</button>
              <button class="secondary" type="button" onclick="refreshLiveEvents(true)" data-zh="手动刷新" data-en="Manual refresh">手动刷新</button>
            </div>
          </header>
          <main>
            <section>
              <h2 data-zh="任务概览" data-en="Job summary">任务概览</h2>
              <div class="grid">
                <div class="metric"><strong data-zh="样本" data-en="Sample">样本</strong><code data-copy="{{Attr(samplePath)}}">{{Html(samplePath)}}</code></div>
                <div class="metric"><strong data-zh="状态" data-en="Status">状态</strong><span class="pill" data-copy="{{Attr(job.Status.ToString())}}">{{Html(job.Status.ToString())}}</span></div>
                <div class="metric"><strong data-zh="事件文件" data-en="Event file">事件文件</strong><code data-copy="{{Attr(job.GuestEventsPath ?? string.Empty)}}">{{Html(string.IsNullOrWhiteSpace(job.GuestEventsPath) ? "等待回收 / waiting" : job.GuestEventsPath)}}</code></div>
                <div class="metric"><strong data-zh="报告" data-en="Report">报告</strong><code data-copy="{{Attr(job.HtmlReportPath ?? string.Empty)}}">{{Html(job.HtmlReportPath ?? "report.html")}}</code></div>
              </div>
              <div id="status" class="status muted" data-zh="等待连接实时事件流。" data-en="Waiting to connect live event stream.">等待连接实时事件流。</div>
              <div id="sources" class="muted"></div>
            </section>
            <section>
              <h2 data-zh="Artifacts / 下载" data-en="Artifacts / downloads">Artifacts / 下载</h2>
              <p class="muted" data-zh="证据文件来自真实 artifact index；可下载的文件走安全下载 endpoint，尚未回收的采集项显示等待状态。" data-en="Evidence files come from the real artifact index; downloadable files use the guarded download endpoint, and collection lanes not yet recovered show a waiting state.">证据文件来自真实 artifact index；可下载的文件走安全下载 endpoint，尚未回收的采集项显示等待状态。</p>
              <div id="reportReadyActions" class="report-ready muted" data-copy="reports pending">报告按钮会在运行结束后保持可用 / report buttons remain available after the run finishes</div>
              <div class="table-wrap">
                <table class="artifact-table">
                  <thead><tr><th data-zh="证据" data-en="Evidence">证据</th><th data-zh="路径" data-en="Path">路径</th><th data-zh="打开 / 下载" data-en="Open / download">打开 / 下载</th><th data-zh="状态" data-en="Status">状态</th></tr></thead>
                  <tbody id="artifactRows"><tr><td colspan="4" class="muted" data-zh="正在解析 artifact 路径。" data-en="Resolving artifact paths.">正在解析 artifact 路径。</td></tr></tbody>
                </table>
              </div>
            </section>
            <section>
              <h2 data-zh="虚拟机分析进度" data-en="Runbook progress">虚拟机分析进度</h2>
              <p class="muted" data-zh="这里同步主界面的真实 runbook step，只展示安全的步骤状态，不展示命令行、stdout 或 stderr。" data-en="This panel mirrors the real runbook steps from the dashboard and only shows UI-safe status, not command lines, stdout, or stderr.">这里同步主界面的真实 runbook step，只展示安全的步骤状态，不展示命令行、stdout 或 stderr。</p>
              <div id="runbookProgress" class="metric muted" data-copy="runbook progress pending">等待主界面启动分析 / waiting for dashboard analysis</div>
              <div id="backgroundStatus" class="metric muted" data-copy="background execution pending">后台执行状态：等待启动 / background execution: waiting</div>
            </section>
            <section>
              <h2 data-zh="VirusTotal 官方结果" data-en="VirusTotal official result">VirusTotal 官方结果</h2>
              <p class="muted" data-zh="只查询 SHA-256 文件报告，不上传样本；未配置或失败时不影响沙箱流程。" data-en="SHA-256 file-report lookup only; samples are not uploaded. Missing keys or failures do not affect sandbox execution.">只查询 SHA-256 文件报告，不上传样本；未配置或失败时不影响沙箱流程。</p>
              <div id="vtResult" class="metric muted" data-copy="VirusTotal: pending">VirusTotal：等待查询 / waiting</div>
              <button class="secondary" type="button" onclick="refreshVirusTotal()" data-zh="刷新 VirusTotal" data-en="Refresh VirusTotal">刷新 VirusTotal</button>
            </section>
            <section>
              <h2 data-zh="原始事件流" data-en="Raw event stream">原始事件流</h2>
              <p class="muted" data-zh="右键任意表格单元可复制。若 SSE 不可用，会自动降级为轮询。" data-en="Right-click any table cell to copy. If SSE is unavailable, the page falls back to polling.">右键任意表格单元可复制。若 SSE 不可用，会自动降级为轮询。</p>
              <div class="table-wrap">
                <table>
                  <thead><tr><th data-zh="时间" data-en="time">时间</th><th data-zh="事件类型" data-en="eventType">事件类型</th><th data-zh="来源" data-en="source">来源</th><th data-zh="进程" data-en="pid/process">进程</th><th data-zh="路径" data-en="path">路径</th><th data-zh="数据（已隐藏命令输出字段）" data-en="data (command output fields hidden)">数据（已隐藏命令输出字段）</th></tr></thead>
                  <tbody id="eventRows"><tr><td colspan="6" class="muted" data-zh="暂无事件。" data-en="No events yet.">暂无事件。</td></tr></tbody>
                </table>
              </div>
            </section>
          </main>
          <div id="copyToast" class="toast" role="status" aria-live="polite"></div>
          <script>
            const jobId = '{{Js(jobId)}}';
            const initialJob = {
              jobId,
              jsonReportPath: '{{Js(job.JsonReportPath)}}',
              htmlReportPath: '{{Js(job.HtmlReportPath)}}',
              htmlReportZhPath: '{{Js(job.HtmlReportZhPath)}}',
              htmlReportEnPath: '{{Js(job.HtmlReportEnPath)}}',
              runbookExecutionResultPath: '{{Js(job.RunbookExecutionResultPath)}}',
              guestEventsPath: '{{Js(job.GuestEventsPath)}}',
              status: '{{Js(job.Status.ToString())}}'
            };
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';
            let eventOffset = 0;
            let sourceSignature = '';
            let eventSource = null;
            let pollTimer = null;
            let progressTimer = null;
            let backgroundTimer = null;
            let jobTimer = null;
            let lastProgressSnapshot = null;
            let lastBackgroundSnapshot = null;
            let lastVirusTotalResult = null;
            let latestJobSnapshot = initialJob;
            let latestArtifactSources = [];
            let latestArtifactIndex = null;
            let latestArtifactSignals = {};
            let reportAutoOpenScheduled = false;
            const autoOpenReportFromMonitor = new URLSearchParams(window.location.search).get('fromUpload') === '1';
            const seen = new Set();

            function t(zh, en) { return currentLanguage === 'en' ? en : zh; }
            function applyLanguage() {
              document.documentElement.lang = currentLanguage === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(el => {
                if (el.id === 'status' || el.id === 'sources' || el.id === 'eventRows' || el.id === 'artifactRows' || el.id === 'reportReadyActions' || el.id === 'vtResult') { return; }
                el.textContent = t(el.getAttribute('data-zh'), el.getAttribute('data-en'));
              });
              document.getElementById('langToggle').textContent = currentLanguage === 'en' ? '中文' : 'English';
              if (lastProgressSnapshot) { renderRunbookProgress(lastProgressSnapshot); }
              if (lastBackgroundSnapshot) { renderBackgroundStatus(lastBackgroundSnapshot); }
              if (lastVirusTotalResult) { renderVirusTotal(lastVirusTotalResult); }
              renderArtifactPanel();
            }
            document.getElementById('langToggle').addEventListener('click', () => {
              currentLanguage = currentLanguage === 'en' ? 'zh' : 'en';
              localStorage.setItem('ksword-lang', currentLanguage);
              applyLanguage();
            });

            function connectSse() {
              stopLive();
              setStatus(t('正在连接 SSE 实时事件流...', 'Connecting SSE live event stream...'), false);
              try {
                eventSource = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/events/stream?offset=${eventOffset}&take=100&intervalMs=1500`);
                eventSource.addEventListener('snapshot', ev => renderSnapshot(JSON.parse(ev.data), 'SSE'));
                eventSource.onerror = () => {
                  stopLive();
                  startPolling(t('SSE 不可用，已切换为轮询。', 'SSE unavailable; switched to polling.'));
                };
              } catch {
                startPolling(t('浏览器不支持 SSE，已切换为轮询。', 'Browser SSE support unavailable; switched to polling.'));
              }
            }

            function startRunbookProgressPolling() {
              refreshRunbookProgress();
              if (progressTimer) { clearInterval(progressTimer); }
              progressTimer = setInterval(refreshRunbookProgress, 1500);
            }

            async function refreshRunbookProgress() {
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/progress`, { cache: 'no-store' });
                const payload = await requireOk(response, t('分析进度', 'runbook progress'));
                renderRunbookProgress(payload);
                if (payload && ['completed', 'failed', 'canceled'].includes(String(payload.state || '').toLowerCase()) && progressTimer) {
                  clearInterval(progressTimer);
                  progressTimer = null;
                }
              } catch {
                // Keep progress non-blocking; the raw monitor and VirusTotal
                // card must stay usable even before the dashboard starts live
                // execution or after the Web host restarts.
              }
            }

            function startBackgroundStatusPolling() {
              refreshBackgroundStatus();
              if (backgroundTimer) { clearInterval(backgroundTimer); }
              backgroundTimer = setInterval(refreshBackgroundStatus, 2000);
            }

            function startJobSnapshotPolling() {
              refreshJobSnapshot();
              if (jobTimer) { clearInterval(jobTimer); }
              jobTimer = setInterval(refreshJobSnapshot, 5000);
            }

            async function refreshJobSnapshot() {
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`, { cache: 'no-store' });
                const payload = await requireOk(response, t('任务状态', 'job status'));
                latestJobSnapshot = normalizeJobSnapshot(payload);
                await refreshArtifactIndex(false);
                renderArtifactPanel();
              } catch {
                renderArtifactPanel();
              }
            }

            async function refreshBackgroundStatus() {
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/background`, { cache: 'no-store' });
                const payload = await requireOk(response, t('后台分析状态', 'background analysis status'));
                if (payload && payload.job) {
                  latestJobSnapshot = normalizeJobSnapshot(payload.job);
                }
                await refreshArtifactIndex(false);
                renderBackgroundStatus(payload);
                renderArtifactPanel();
                const state = String(payload.state || '').toLowerCase();
                if (['completed', 'failed'].includes(state) && backgroundTimer) {
                  clearInterval(backgroundTimer);
                  backgroundTimer = null;
                }
              } catch {
                // The monitor must remain useful for raw events even when the
                // Web host has no background execution snapshot, such as after
                // a restart or when an older blocking endpoint was used.
              }
            }

            function renderBackgroundStatus(snapshot) {
              lastBackgroundSnapshot = snapshot;
              const target = document.getElementById('backgroundStatus');
              if (!target || !snapshot) { return; }
              const state = String(snapshot.state || 'not_started').toLowerCase();
              const stateLabel = formatBackgroundState(state);
              const message = snapshot.message || '';
              const job = snapshot.job || {};
              const hasReport = Boolean(job.htmlReportPath || job.htmlReportZhPath || job.htmlReportEnPath);
              const reportButtons = hasReport || state === 'completed'
                ? `<p class="actions">
                    <a class="button" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh" target="_blank" rel="noopener">${t('打开中文报告', 'Open Chinese report')}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en" target="_blank" rel="noopener">${t('打开英文报告', 'Open English report')}</a>
                  </p>`
                : '';
              const importMessage = snapshot.guestImportMessage
                ? `<p class="${snapshot.guestImportSucceeded ? 'ok' : 'muted'}">${escapeHtml(snapshot.guestImportMessage)}</p>`
                : '';
              target.innerHTML = `
                <div><span class="pill">${escapeHtml(stateLabel)}</span>
                  <strong>${escapeHtml(snapshot.live ? t('虚拟机分析', 'VM analysis') : t('流程验证', 'flow verification'))}</strong></div>
                ${message ? `<p>${escapeHtml(message)}</p>` : ''}
                ${importMessage}
                ${reportButtons}`;
              target.setAttribute('data-copy', `background ${stateLabel}: ${message}`);
              if (autoOpenReportFromMonitor && state === 'completed' && (hasReport || job.htmlReportPath !== '') && !reportAutoOpenScheduled) {
                scheduleReportAutoOpen();
              }
            }

            function scheduleReportAutoOpen() {
              reportAutoOpenScheduled = true;
              const href = `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${currentLanguage === 'en' ? 'en' : 'zh'}`;
              const target = document.getElementById('reportReadyActions');
              if (target) {
                target.className = 'report-ready ok';
                target.innerHTML = `<strong>${escapeHtml(t('报告已生成，正在自动打开。', 'Report is ready and opening automatically.'))}</strong>
                  <div class="artifact-action">
                    <a class="button" href="${escapeAttr(href)}">${escapeHtml(t('打开报告', 'Open report'))}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh" target="_blank" rel="noopener">${escapeHtml(t('中文报告', 'Chinese report'))}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en" target="_blank" rel="noopener">${escapeHtml(t('英文报告', 'English report'))}</a>
                  </div>`;
              }
              setStatus(t('报告已生成，页面即将跳转；如果没有跳转，请点击打开报告。', 'Report is ready; this page will navigate shortly. If it does not, click Open report.'), false);
              setTimeout(() => {
                window.location.href = href;
              }, 1600);
            }

            function formatBackgroundState(state) {
              const labels = {
                not_started: t('未启动', 'not started'),
                queued: t('已排队', 'queued'),
                running: t('后台运行中', 'running in background'),
                completed: t('已完成', 'completed'),
                failed: t('失败', 'failed')
              };
              return labels[state] || state;
            }

            function normalizeJobSnapshot(raw) {
              raw = raw || {};
              return {
                jobId: raw.jobId || jobId,
                jsonReportPath: raw.jsonReportPath || raw.reportJsonPath || '',
                htmlReportPath: raw.htmlReportPath || raw.reportHtmlPath || '',
                htmlReportZhPath: raw.htmlReportZhPath || raw.reportZhHtmlPath || '',
                htmlReportEnPath: raw.htmlReportEnPath || raw.reportEnHtmlPath || '',
                runbookExecutionResultPath: raw.runbookExecutionResultPath || raw.runbookExecutionPath || '',
                guestEventsPath: raw.guestEventsPath || '',
                status: raw.status == null ? '' : raw.status
              };
            }

            async function refreshArtifactIndex(showError) {
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/artifacts`, { cache: 'no-store' });
                latestArtifactIndex = await requireOk(response, t('证据索引', 'artifact index'));
                return latestArtifactIndex;
              } catch (error) {
                if (showError) {
                  setStatus(error.message || t('证据索引暂不可用。', 'Artifact index is not available yet.'), true);
                }
                return null;
              }
            }

            function renderArtifactPanel() {
              const body = document.getElementById('artifactRows');
              if (!body) { return; }
              latestJobSnapshot = normalizeJobSnapshot(latestJobSnapshot || initialJob);
              const paths = buildArtifactPaths(latestJobSnapshot, latestArtifactSources);
              const rows = buildIndexedArtifactRows(paths);
              body.innerHTML = rows.join('');
              renderReportReadyActions(paths);
            }

            function buildIndexedArtifactRows(paths) {
              const artifacts = Array.isArray(latestArtifactIndex?.artifacts) ? latestArtifactIndex.artifacts : [];
              const rows = [];
              rows.push(artifactRow(t('中文报告', 'Chinese report'), 'report.zh.html', paths.zhReportPath, `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh`, paths.hasAnyReport, t('使用报告 endpoint 打开', 'opens through report endpoint')));
              rows.push(artifactRow(t('英文报告', 'English report'), 'report.en.html', paths.enReportPath, `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en`, paths.hasAnyReport, t('使用报告 endpoint 打开', 'opens through report endpoint')));

              if (artifacts.length > 0) {
                const sorted = [...artifacts].sort((a, b) => artifactRank(a) - artifactRank(b) || artifactPath(a).localeCompare(artifactPath(b)));
                for (const artifact of sorted.slice(0, 80)) {
                  const label = artifactLabel(artifact);
                  const type = artifactTypeText(artifact);
                  const path = artifactPath(artifact);
                  const detail = [type, formatBytes(artifact.sizeBytes), artifact.sha256 ? `sha256 ${artifact.sha256.slice(0, 12)}…` : ''].filter(Boolean).join(' · ');
                  rows.push(artifactRow(label, type, path, artifact.downloadHref || '', Boolean(artifact.downloadHref || path), detail || t('已索引', 'indexed')));
                }

                appendMissingCollectionRows(rows, artifacts, paths);
                return rows;
              }

              rows.push(artifactRow(t('默认 HTML 报告', 'Default HTML report'), 'report.html', paths.reportHtmlPath, `/api/jobs/${encodeURIComponent(jobId)}/report/html`, Boolean(paths.reportHtmlPath), t('兼容报告 endpoint', 'compatibility report endpoint')));
              rows.push(artifactRow(t('JSON 报告', 'JSON report'), 'report.json', paths.reportJsonPath, '', Boolean(paths.reportJsonPath), t('等待 artifact index 下载链接', 'waiting for artifact-index download link')));
              rows.push(artifactRow('events.json', 'events.json', paths.eventsJsonPath, '', paths.eventsCollected, paths.eventsCollected ? t('已记录事件来源', 'event source recorded') : t('等待回收', 'waiting for collection')));
              rows.push(artifactRow('driver-events.jsonl', 'driver-events.jsonl', paths.driverEventsJsonlPath, '', paths.driverCollected, paths.driverCollected ? t('已发现驱动遥测', 'driver telemetry found') : t('等待回收', 'waiting for collection')));
              rows.push(artifactRow(t('落地文件', 'Dropped files'), 'artifacts/dropped-files', paths.droppedFilesPath, '', Boolean(latestArtifactSignals.droppedFiles), latestArtifactSignals.droppedFiles ? t('事件中已出现落地文件证据', 'dropped-file evidence observed in events') : t('等待回收', 'waiting for collection')));
              rows.push(artifactRow(t('截图', 'Screenshots'), 'screenshots', paths.screenshotsPath, '', Boolean(latestArtifactSignals.screenshots), latestArtifactSignals.screenshots ? t('事件中已出现截图证据', 'screenshot evidence observed in events') : t('等待回收', 'waiting for collection')));
              rows.push(artifactRow(t('内存转储', 'Memory dumps'), 'memory-dumps', paths.memoryDumpsPath, '', Boolean(latestArtifactSignals.memoryDumps), latestArtifactSignals.memoryDumps ? t('事件中已出现内存转储证据', 'memory-dump evidence observed in events') : t('等待回收', 'waiting for collection')));
              rows.push(artifactRow(t('PCAP 抓包', 'PCAP captures'), 'packet-captures', paths.packetCapturePath, '', paths.pcapCollected || Boolean(latestArtifactSignals.packetCaptures), paths.pcapCollected || latestArtifactSignals.packetCaptures ? t('已发现 PCAP/PCAPNG 证据', 'PCAP/PCAPNG evidence found') : t('等待回收', 'waiting for collection')));
              return rows;
            }

            function appendMissingCollectionRows(rows, artifacts, paths) {
              const hasDropped = artifacts.some(a => artifactMatches(a, 'dropped-file', 'dropped-files'));
              const hasScreenshot = artifacts.some(a => artifactMatches(a, 'screenshot', 'screenshots'));
              const hasDump = artifacts.some(a => artifactMatches(a, 'memory-dump', 'memory-dumps'));
              const hasPcap = artifacts.some(a => artifactMatches(a, 'packet-capture', 'packet-captures'));
              if (!hasDropped) { rows.push(artifactRow(t('落地文件', 'Dropped files'), 'artifacts/dropped-files', paths.droppedFilesPath, '', Boolean(latestArtifactSignals.droppedFiles), t('等待回收', 'waiting for collection'))); }
              if (!hasScreenshot) { rows.push(artifactRow(t('截图', 'Screenshots'), 'screenshots', paths.screenshotsPath, '', Boolean(latestArtifactSignals.screenshots), t('等待回收', 'waiting for collection'))); }
              if (!hasDump) { rows.push(artifactRow(t('内存转储', 'Memory dumps'), 'memory-dumps', paths.memoryDumpsPath, '', Boolean(latestArtifactSignals.memoryDumps), t('等待回收', 'waiting for collection'))); }
              if (!hasPcap) { rows.push(artifactRow(t('PCAP 抓包', 'PCAP captures'), 'packet-captures', paths.packetCapturePath, '', paths.pcapCollected || Boolean(latestArtifactSignals.packetCaptures), t('等待回收', 'waiting for collection'))); }
            }

            function artifactMatches(artifact, category, collectionName) {
              const text = `${artifact.category || ''} ${artifact.collectionName || ''} ${artifact.evidenceRole || ''} ${artifact.relativePath || ''}`.toLowerCase();
              return text.includes(category) || text.includes(collectionName);
            }

            function artifactRank(artifact) {
              const text = `${artifact.category || ''} ${artifact.collectionName || ''} ${artifact.relativePath || ''}`.toLowerCase();
              if (text.includes('report')) { return 10; }
              if (text.includes('telemetry') || text.includes('events.json') || text.includes('jsonl')) { return 20; }
              if (text.includes('dropped-file') || text.includes('dropped-files')) { return 30; }
              if (text.includes('screenshot')) { return 40; }
              if (text.includes('memory-dump') || text.includes('memory-dumps')) { return 50; }
              if (text.includes('packet-capture') || text.includes('packet-captures') || text.includes('.pcap')) { return 60; }
              if (text.includes('runbook')) { return 70; }
              return 100;
            }

            function artifactLabel(artifact) {
              const text = `${artifact.category || ''} ${artifact.collectionName || ''} ${artifact.relativePath || ''}`.toLowerCase();
              if (text.includes('report')) { return t('报告文件', 'Report file'); }
              if (text.includes('driver-events') || text.includes('jsonl')) { return 'driver-events.jsonl'; }
              if (text.includes('events.json')) { return 'events.json'; }
              if (text.includes('dropped-file') || text.includes('dropped-files')) { return t('落地文件', 'Dropped file'); }
              if (text.includes('screenshot')) { return t('截图', 'Screenshot'); }
              if (text.includes('memory-dump') || text.includes('memory-dumps')) { return t('内存转储', 'Memory dump'); }
              if (text.includes('packet-capture') || text.includes('packet-captures') || text.includes('.pcap')) { return t('PCAP 抓包', 'PCAP capture'); }
              if (text.includes('runbook')) { return t('执行记录', 'Runbook record'); }
              return artifact.name || artifact.category || t('证据文件', 'Evidence file');
            }

            function artifactTypeText(artifact) {
              return [artifact.category || '', artifact.collectionName || '', artifact.name || ''].filter(Boolean).join(' / ') || 'artifact';
            }

            function artifactPath(artifact) {
              return artifact.relativePath || artifact.safeLink || artifact.importPath || artifact.fullPath || artifact.name || '';
            }

            function formatBytes(value) {
              const n = Number(value || 0);
              if (!Number.isFinite(n) || n <= 0) { return ''; }
              if (n < 1024) { return `${n} B`; }
              if (n < 1024 * 1024) { return `${(n / 1024).toFixed(1)} KB`; }
              if (n < 1024 * 1024 * 1024) { return `${(n / 1024 / 1024).toFixed(1)} MB`; }
              return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
            }

            function renderReportReadyActions(paths) {
              const target = document.getElementById('reportReadyActions');
              if (!target) { return; }
              if (reportAutoOpenScheduled) {
                const href = `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${currentLanguage === 'en' ? 'en' : 'zh'}`;
                target.innerHTML = `<strong>${escapeHtml(t('报告已生成，正在自动打开。', 'Report is ready and opening automatically.'))}</strong>
                  <div class="artifact-action"><a class="button" href="${escapeAttr(href)}">${escapeHtml(t('打开报告', 'Open report'))}</a></div>`;
                target.className = 'report-ready ok';
                target.setAttribute('data-copy', href);
                return;
              }
              const terminal = isRunTerminal();
              const hasReport = paths.hasAnyReport || terminal;
              const label = terminal
                ? t('运行已结束：可打开中文或英文报告。', 'Run finished: Chinese and English reports are available to open.')
                : t('报告将在计划或运行结束后通过现有 endpoint 打开。', 'Reports open through the existing endpoint after planning or run completion.');
              const actions = hasReport
                ? `<div class="artifact-action">
                    <a class="button" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh" target="_blank" rel="noopener">${t('打开中文报告', 'Open Chinese report')}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en" target="_blank" rel="noopener">${t('打开英文报告', 'Open English report')}</a>
                  </div>`
                : '';
              target.innerHTML = `<strong>${escapeHtml(label)}</strong>${actions}`;
              target.className = `report-ready ${hasReport ? 'ok' : 'muted'}`;
              target.setAttribute('data-copy', `${label} /api/jobs/${jobId}/report/html?lang=zh /api/jobs/${jobId}/report/html?lang=en`);
            }

            function artifactRow(displayName, fileName, path, href, ready, detail) {
              const statusText = ready ? detail : t('等待回收', 'waiting for collection');
              const statusClass = ready ? (href ? 'endpoint' : 'ready') : 'waiting';
              const pathHtml = path
                ? `<code data-copy="${escapeAttr(path)}">${escapeHtml(path)}</code>`
                : `<span class="muted" data-copy="${escapeAttr(statusText)}">${escapeHtml(t('等待回收', 'waiting for collection'))}</span>`;
              const openAction = href
                ? `<a class="button secondary" href="${escapeAttr(href)}" target="_blank" rel="noopener">${escapeHtml(t('打开/下载', 'Open/download'))}</a>`
                : `<span class="path-only">${escapeHtml(t('等待下载链接', 'waiting for download link'))}</span>`;
              const copyAction = path
                ? `<button class="secondary" type="button" data-copy="${escapeAttr(path)}" onclick="copyText(this.getAttribute('data-copy'))">${escapeHtml(t('复制路径', 'Copy path'))}</button>`
                : '';
              const copy = [displayName, fileName, path || statusText, statusText].join(' | ');
              return `<tr data-copy="${escapeAttr(copy)}">
                <td><strong>${escapeHtml(displayName)}</strong><br><span class="muted">${escapeHtml(fileName)}</span></td>
                <td>${pathHtml}</td>
                <td><div class="artifact-action">${openAction}${copyAction}</div></td>
                <td><span class="pill ${statusClass}" data-copy="${escapeAttr(statusText)}">${escapeHtml(statusText)}</span></td>
              </tr>`;
            }

            function buildArtifactPaths(job, sources) {
              job = normalizeJobSnapshot(job);
              sources = Array.isArray(sources) ? sources : [];
              const jobIdNoDash = String(job.jobId || jobId).replace(/-/g, '');
              const reportJsonPath = job.jsonReportPath || '';
              const reportHtmlPath = job.htmlReportPath || '';
              const zhReportPath = job.htmlReportZhPath || '';
              const enReportPath = job.htmlReportEnPath || '';
              const runbookPath = job.runbookExecutionResultPath || '';
              const jobRoot = getParentDirectory(reportJsonPath || reportHtmlPath || zhReportPath || enReportPath || runbookPath);
              const expectedGuestDirectory = jobRoot && jobIdNoDash ? combineHostPath(jobRoot, 'guest', jobIdNoDash) : '';
              const sourceEvents = findSourcePath(sources, source => fileNameEquals(source, 'events.json'));
              const sourceDriver = findSourcePath(sources, source => fileNameEquals(source, 'driver-events.jsonl'));
              const sourcePcap = findSourcePath(sources, source => isPacketCapturePath(source));
              const recordedGuestEvents = job.guestEventsPath || '';
              const guestSourceDirectory = getParentDirectory(recordedGuestEvents || sourceEvents || sourceDriver || inferGuestRootFromCollectionPath(sourcePcap) || expectedGuestDirectory);
              const guestOutputRoot = recordedGuestEvents || sourceEvents || sourceDriver
                ? getParentDirectory(recordedGuestEvents || sourceEvents || sourceDriver)
                : (inferGuestRootFromCollectionPath(sourcePcap) || expectedGuestDirectory);
              const eventsJsonPath = fileNameEquals(recordedGuestEvents, 'events.json')
                ? recordedGuestEvents
                : (sourceEvents || (guestOutputRoot ? combineHostPath(guestOutputRoot, 'events.json') : ''));
              const driverEventsJsonlPath = fileNameEquals(recordedGuestEvents, 'driver-events.jsonl')
                ? recordedGuestEvents
                : (sourceDriver || (guestOutputRoot ? combineHostPath(guestOutputRoot, 'driver-events.jsonl') : ''));

              return {
                jobRoot,
                reportJsonPath,
                reportHtmlPath: reportHtmlPath || (jobRoot ? combineHostPath(jobRoot, 'report.html') : ''),
                zhReportPath: zhReportPath || (jobRoot ? combineHostPath(jobRoot, 'report.zh.html') : ''),
                enReportPath: enReportPath || (jobRoot ? combineHostPath(jobRoot, 'report.en.html') : ''),
                hasAnyReport: Boolean(reportHtmlPath || zhReportPath || enReportPath || reportJsonPath),
                guestSourceDirectory,
                eventsJsonPath,
                eventsCollected: Boolean(recordedGuestEvents || sourceEvents),
                driverEventsJsonlPath,
                driverCollected: Boolean(fileNameEquals(recordedGuestEvents, 'driver-events.jsonl') || sourceDriver),
                droppedFilesPath: guestOutputRoot ? combineHostPath(guestOutputRoot, 'artifacts', 'dropped-files') : '',
                screenshotsPath: guestOutputRoot ? combineHostPath(guestOutputRoot, 'screenshots') : '',
                memoryDumpsPath: guestOutputRoot ? combineHostPath(guestOutputRoot, 'memory-dumps') : '',
                packetCapturePath: sourcePcap || (guestOutputRoot ? combineHostPath(guestOutputRoot, 'packet-captures') : ''),
                pcapCollected: Boolean(sourcePcap)
              };
            }

            function isRunTerminal() {
              const backgroundState = String(lastBackgroundSnapshot?.state || '').toLowerCase();
              if (backgroundState === 'completed' || backgroundState === 'failed') { return true; }
              const status = latestJobSnapshot ? latestJobSnapshot.status : '';
              const statusText = String(status || '').toLowerCase();
              return statusText === 'completed' || statusText === 'failed' || Number(status) === 4 || Number(status) === 5;
            }

            function updateArtifactSignalsFromEvents(events) {
              for (const ev of events || []) {
                const text = JSON.stringify({
                  eventType: ev.eventType || '',
                  path: ev.path || '',
                  source: ev.source || '',
                  data: ev.data || {}
                }).toLowerCase();
                if (text.includes('dropped-file') || text.includes('dropped_files') || text.includes('artifacts/dropped-files')) {
                  latestArtifactSignals.droppedFiles = true;
                }
                if (text.includes('screenshot') || text.includes('/screenshots/') || text.includes('\\\\screenshots\\\\')) {
                  latestArtifactSignals.screenshots = true;
                }
                if (text.includes('memory-dump') || text.includes('memory_dump') || text.includes('/memory-dumps/') || text.includes('\\\\memory-dumps\\\\')) {
                  latestArtifactSignals.memoryDumps = true;
                }
                if (text.includes('packet-capture') || text.includes('packet_capture') || text.includes('.pcap')) {
                  latestArtifactSignals.packetCaptures = true;
                }
              }
            }

            function findSourcePath(sources, predicate) {
              return (sources || []).find(source => predicate(String(source || ''))) || '';
            }

            function inferGuestRootFromCollectionPath(path) {
              if (!path) { return ''; }
              const normalized = String(path).replace(/\\/g, '/');
              const markers = ['/packet-captures/', '/screenshots/', '/memory-dumps/', '/artifacts/dropped-files/'];
              for (const marker of markers) {
                const index = normalized.toLowerCase().indexOf(marker);
                if (index >= 0) {
                  return normalized.slice(0, index).replace(/\//g, path.includes('\\') ? '\\' : '/');
                }
              }
              return '';
            }

            function getParentDirectory(path) {
              if (!path) { return ''; }
              const normalized = String(path).replace(/[\\/]+$/, '');
              const slash = Math.max(normalized.lastIndexOf('\\'), normalized.lastIndexOf('/'));
              return slash <= 0 ? '' : normalized.slice(0, slash);
            }

            function combineHostPath(root, ...segments) {
              if (!root) { return ''; }
              const separator = String(root).includes('/') && !String(root).includes('\\') ? '/' : '\\';
              const cleanedRoot = String(root).replace(/[\\/]+$/, '');
              const cleanedSegments = segments
                .filter(segment => segment != null && String(segment).length > 0)
                .map(segment => String(segment).replace(/^[\\/]+|[\\/]+$/g, ''));
              return [cleanedRoot, ...cleanedSegments].join(separator);
            }

            function fileNameEquals(path, expected) {
              if (!path) { return false; }
              const normalized = String(path).replace(/\\/g, '/');
              const fileName = normalized.slice(normalized.lastIndexOf('/') + 1);
              return fileName.toLowerCase() === String(expected || '').toLowerCase();
            }

            function isPacketCapturePath(path) {
              return /\.(pcap|pcapng)$/i.test(String(path || ''));
            }

            function renderRunbookProgress(snapshot) {
              lastProgressSnapshot = snapshot;
              const target = document.getElementById('runbookProgress');
              if (!target || !snapshot) { return; }
              const total = Number(snapshot.totalSteps || 0);
              const completed = Number(snapshot.completedSteps || 0);
              const percent = progressPercent(snapshot);
              const state = formatProgressState(snapshot.state);
              const current = snapshot.currentStepTitle || t('等待下一步', 'waiting for next step');
              const elapsed = formatDuration(snapshot.duration) || '-';
              const failedStep = (snapshot.steps || []).find(step => ['failed', 'canceled'].includes(String(step.state || '').toLowerCase()));
              const failureReason = buildProgressFailureReason(snapshot, failedStep);
              const message = snapshot.message ? `<p class="muted">${escapeHtml(snapshot.message)}</p>` : '';
              const failure = failureReason ? `<p class="error">${t('失败原因：', 'Failure reason: ')}${escapeHtml(failureReason)}</p>` : '';
              const steps = (snapshot.steps || []).slice(0, 24).map(step => {
                const stepState = String(step.state || 'pending').toLowerCase();
                const line = `${Number(step.stepIndex ?? 0) + 1}. ${step.title || step.stepId || ''}`;
                const detail = [
                  formatProgressState(stepState),
                  step.exitCode == null ? '' : `exit ${step.exitCode}`,
                  step.duration ? formatDuration(step.duration) : '',
                  step.message || ''
                ].filter(Boolean).join(' · ');
                return `<div class="step-card ${escapeAttr(stepState)}" data-copy="${escapeAttr(line + ' ' + detail)}">
                  <strong>${escapeHtml(line)}</strong>
                  <span class="pill">${escapeHtml(detail || formatProgressState('pending'))}</span>
                </div>`;
              }).join('');
              target.innerHTML = `
                <div><span class="pill" data-copy="${escapeAttr(state)}">${escapeHtml(state)}</span>
                <strong>${escapeHtml(completed)} / ${escapeHtml(total)} ${t('步骤完成', 'steps completed')}</strong></div>
                <div class="progressbar" aria-label="runbook progress"><div class="progressbar-fill" style="width:${percent}%"></div></div>
                <p>${t('当前步骤', 'Current step')}：<strong>${escapeHtml(current)}</strong></p>
                <p>${t('已耗时', 'Elapsed')}：<strong>${escapeHtml(elapsed)}</strong></p>
                ${message}
                ${failure}
                <div class="step-list">${steps || `<p class="muted">${t('尚无步骤快照。', 'No step snapshot yet.')}</p>`}</div>`;
              target.setAttribute('data-copy', `runbook ${state} ${completed}/${total} ${current}; elapsed=${elapsed}; failure=${failureReason || '-'}`);
            }

            function buildProgressFailureReason(snapshot, failedStep) {
              const pieces = [];
              if (failedStep) {
                const title = failedStep.title || failedStep.stepId || '';
                if (title) { pieces.push(`${t('失败步骤', 'Failed step')}: ${title}`); }
                if (failedStep.message) { pieces.push(failedStep.message); }
                if (failedStep.exitCode != null) { pieces.push(`exit ${failedStep.exitCode}`); }
              }
              const state = String(snapshot?.state || '').toLowerCase();
              if (snapshot?.message && (pieces.length > 0 || ['failed', 'canceled'].includes(state))) {
                pieces.push(snapshot.message);
              }
              return pieces.join(' · ');
            }

            function progressPercent(snapshot) {
              const total = Number(snapshot.totalSteps || 0);
              if (total <= 0) { return 0; }
              const completed = Number(snapshot.completedSteps || 0);
              return Math.max(0, Math.min(100, Math.round((completed / total) * 100)));
            }

            function formatProgressState(state) {
              const key = String(state || 'pending').toLowerCase();
              const labels = {
                pending: t('等待中', 'pending'),
                running: t('运行中', 'running'),
                completed: t('已完成', 'completed'),
                failed: t('失败', 'failed'),
                skipped: t('已跳过', 'skipped'),
                canceled: t('已取消', 'canceled')
              };
              return labels[key] || key;
            }

            function formatDuration(value) {
              if (typeof value === 'string') { return value; }
              if (typeof value === 'number') { return `${value}ms`; }
              return '';
            }

            function startPolling(message) {
              stopLive();
              setStatus(message, false);
              refreshLiveEvents(false);
              pollTimer = setInterval(() => refreshLiveEvents(false), 2000);
            }

            function stopLive() {
              if (eventSource) { eventSource.close(); eventSource = null; }
              if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
            }

            async function refreshLiveEvents(reset) {
              if (reset) {
                eventOffset = 0;
                sourceSignature = '';
                seen.clear();
                document.getElementById('eventRows').innerHTML = '';
              }
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/events/live?offset=${eventOffset}&take=100`);
                const payload = await requireOk(response, t('实时事件', 'live events'));
                renderSnapshot(payload, 'poll');
              } catch (error) {
                setStatus(error.message, true);
              }
            }

            async function refreshVirusTotal() {
              const target = document.getElementById('vtResult');
              if (target) {
                target.textContent = t('VirusTotal：正在查询...', 'VirusTotal: querying...');
                target.setAttribute('data-copy', target.textContent);
              }
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/virustotal`, { cache: 'no-store' });
                const payload = await requireOk(response, 'VirusTotal');
                renderVirusTotal(payload);
              } catch (error) {
                // Keep VirusTotal silent and non-blocking. Operators can open
                // Settings if they need to inspect the API key.
                const detail = error && error.message ? error.message : t('VirusTotal 查询不可用。', 'VirusTotal lookup unavailable.');
                const notConfigured = /not[_ -]?configured|api key|未配置/i.test(detail);
                renderVirusTotal({ status: notConfigured ? 'not_configured' : 'lookup_failed', configured: !notConfigured, queried: false, message: detail });
              }
            }

            function renderVirusTotal(result) {
              lastVirusTotalResult = result;
              const target = document.getElementById('vtResult');
              if (!target) { return; }
              const stats = result.lastAnalysisStats || {};
              const malicious = Number(stats.malicious || 0);
              const suspicious = Number(stats.suspicious || 0);
              const harmless = Number(stats.harmless || 0);
              const undetected = Number(stats.undetected || 0);
              let label;
              let className = 'metric vt-card vt-quiet';
              let score = t('未查询', 'not queried');
              let status = result.status || '';
              if (!result.configured) {
                label = t('未配置 API Key，已跳过官方结果。', 'API key not configured; official result skipped.');
              } else if (!result.queried) {
                label = result.message || t('查询失败或被限速，沙箱流程继续。', 'Lookup failed or was rate-limited; sandbox flow continues.');
              } else if (!result.found) {
                label = t('VirusTotal 未收录该 SHA-256。', 'VirusTotal has no report for this SHA-256.');
                className = 'metric vt-card vt-neutral';
                score = t('未收录', 'not found');
              } else {
                label = t(`已收录：恶意 ${malicious} / 可疑 ${suspicious} / 无害 ${harmless} / 未检出 ${undetected}`, `Found: malicious ${malicious} / suspicious ${suspicious} / harmless ${harmless} / undetected ${undetected}`);
                score = `${malicious + suspicious}`;
                status = malicious > 0 ? t('命中恶意', 'malicious hits') : (suspicious > 0 ? t('可疑命中', 'suspicious hits') : t('未见恶意命中', 'no malicious hits'));
                className = malicious > 0 ? 'metric vt-card vt-danger' : (suspicious > 0 ? 'metric vt-card vt-warning' : 'metric vt-card vt-ok');
              }

              const link = result.permalink ? `<a class="button secondary" href="${escapeAttr(result.permalink)}" target="_blank" rel="noopener">VirusTotal</a>` : '';
              const settingsLink = !result.configured ? ` <a href="/settings">${t('打开设置', 'Open settings')}</a>` : '';
              const name = result.meaningfulName ? `<p>${escapeHtml(result.meaningfulName)}</p>` : '';
              const sha = result.sha256 ? `<p><code data-copy="${escapeAttr(result.sha256)}">${escapeHtml(result.sha256)}</code></p>` : '';
              target.className = className;
              target.innerHTML = `
                <div class="vt-head">
                  <div>
                    <strong>${escapeHtml(label)}</strong>
                    ${name}
                  </div>
                  <div class="vt-score" data-copy="${escapeAttr(score)}">${escapeHtml(score)}</div>
                </div>
                <div class="vt-stats">
                  <span data-copy="${malicious}"><strong>${t('恶意', 'Malicious')}</strong>${malicious}</span>
                  <span data-copy="${suspicious}"><strong>${t('可疑', 'Suspicious')}</strong>${suspicious}</span>
                  <span data-copy="${harmless}"><strong>${t('无害', 'Harmless')}</strong>${harmless}</span>
                  <span data-copy="${undetected}"><strong>${t('未检出', 'Undetected')}</strong>${undetected}</span>
                </div>
                ${sha}
                <p class="artifact-action"><span class="pill ${result.found ? 'ready' : 'waiting'}">${escapeHtml(status || result.status || 'VirusTotal')}</span>${link}${settingsLink}</p>`;
              target.setAttribute('data-copy', `VirusTotal ${result.status || ''}: ${label} ${result.sha256 || ''}`);
            }

            function renderSnapshot(snapshot, transport) {
              const nextSignature = (snapshot.sources || []).join('\\n');
              if (nextSignature !== sourceSignature) {
                sourceSignature = nextSignature;
                eventOffset = 0;
                seen.clear();
                document.getElementById('eventRows').innerHTML = '';
              }

              eventOffset = snapshot.nextOffset || eventOffset;
              latestArtifactSources = snapshot.sources || [];
              updateArtifactSignalsFromEvents(snapshot.events || []);
              renderSources(snapshot.sources || []);
              renderArtifactPanel();
              appendRows(snapshot.events || []);
              setStatus(t(`${transport}：${snapshot.totalEvents || 0} 条原始事件；下次位置 ${eventOffset}；${new Date().toLocaleTimeString()}。`, `${transport}: ${snapshot.totalEvents || 0} raw events; next offset ${eventOffset}; ${new Date().toLocaleTimeString()}.`), false);
            }

            function renderSources(sources) {
              const target = document.getElementById('sources');
              if (!sources.length) {
                target.textContent = t('尚未发现事件源。', 'No event sources found yet.');
                return;
              }
              target.innerHTML = `<strong>${t('事件来源', 'Sources')}</strong><ul>` + sources.map(s => `<li><code data-copy="${escapeAttr(s)}">${escapeHtml(s)}</code></li>`).join('') + '</ul>';
            }

            function appendRows(events) {
              const body = document.getElementById('eventRows');
              if (!events.length && seen.size === 0) {
                body.innerHTML = `<tr><td colspan="6" class="muted">${t('暂无事件。', 'No events yet.')}</td></tr>`;
                return;
              }
              if (seen.size === 0) { body.innerHTML = ''; }
              for (const ev of events) {
                const key = JSON.stringify([ev.timestamp, ev.eventType, ev.source, ev.processId, ev.path]);
                if (seen.has(key)) { continue; }
                seen.add(key);
                const data = ev.data ? JSON.stringify(sanitizeEventData(ev.data)) : '';
                const pid = [ev.processId || '', ev.processName || ''].filter(Boolean).join(' / ');
                body.insertAdjacentHTML('beforeend', `<tr>
                  <td>${cell(ev.timestamp)}</td>
                  <td>${cell(ev.eventType)}</td>
                  <td>${cell(ev.source)}</td>
                  <td>${cell(pid)}</td>
                  <td>${cell(ev.path)}</td>
                  <td>${cell(data)}</td>
                </tr>`);
              }
            }

            function sanitizeEventData(data) {
              const sanitized = {};
              for (const [key, value] of Object.entries(data || {})) {
                if (isHiddenTelemetryKey(key)) { continue; }
                sanitized[key] = value;
              }
              return sanitized;
            }

            function isHiddenTelemetryKey(key) {
              const normalized = String(key || '').toLowerCase();
              return normalized.includes('command') ||
                normalized.includes('stdout') ||
                normalized.includes('stderr') ||
                normalized.includes('standardoutput') ||
                normalized.includes('standarderror') ||
                normalized.includes('powershell');
            }

            function cell(value) {
              const text = value == null ? '' : String(value);
              return `<span data-copy="${escapeAttr(text)}">${escapeHtml(text)}</span>`;
            }

            async function requireOk(response, label) {
              const text = await response.text();
              let payload;
              try { payload = text ? JSON.parse(text) : {}; } catch { payload = { error: text }; }
              if (!response.ok) { throw new Error(`${label} ${t('失败', 'failed')}: ${payload.error || response.status}`); }
              return payload;
            }

            function setStatus(message, isError) {
              const status = document.getElementById('status');
              status.className = `status ${isError ? 'error' : 'ok'}`;
              status.textContent = message;
              status.setAttribute('data-copy', message || '');
            }
            function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
            function escapeAttr(value) { return escapeHtml(value).replace(/`/g, '&#96;'); }
            function fallbackCopyText(value) {
              const area = document.createElement('textarea');
              area.value = value;
              area.setAttribute('readonly', 'readonly');
              area.style.position = 'fixed';
              area.style.left = '-9999px';
              document.body.appendChild(area);
              area.select();
              document.execCommand('copy');
              document.body.removeChild(area);
            }
            function copyText(value) {
              if (!value) { return; }
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(value).then(() => showToast(t('已复制', 'Copied'))).catch(() => {
                  fallbackCopyText(value);
                  showToast(t('已复制', 'Copied'));
                });
                return;
              }
              fallbackCopyText(value);
              showToast(t('已复制', 'Copied'));
            }
            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest('[data-copy], code, td, th, p, h1, h2, h3, span, a, button') : null;
              if (!target) { return; }
              const value = target.getAttribute('data-copy') || target.innerText || target.textContent || '';
              if (!value.trim()) { return; }
              event.preventDefault();
              copyText(value);
            });
            function showToast(message) {
              const toast = document.getElementById('copyToast');
              toast.textContent = message;
              toast.classList.add('visible');
              setTimeout(() => toast.classList.remove('visible'), 1200);
            }
            applyLanguage();
            renderArtifactPanel();
            refreshVirusTotal();
            startJobSnapshotPolling();
            startRunbookProgressPolling();
            startBackgroundStatusPolling();
            connectSse();
          </script>
        </body>
        </html>
        """;
    }

    private static string Html(string? value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty);
    }

    private static string Attr(string? value)
    {
        return Html(value).Replace("\"", "&quot;", StringComparison.Ordinal);
    }

    private static string Js(string? value)
    {
        return (value ?? string.Empty)
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("'", "\\'", StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
    }
}
