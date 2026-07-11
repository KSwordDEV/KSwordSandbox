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
            .muted { color:var(--muted); }
            code { background:#eef7ff; border-radius:7px; padding:2px 5px; word-break:break-all; }
            .table-wrap { max-height:75vh; overflow:auto; border:1px solid var(--line); border-radius:14px; }
            table { border-collapse:separate; border-spacing:0; width:100%; }
            td, th { border-bottom:1px solid #e5edf6; padding:9px; text-align:left; vertical-align:top; }
            th { background:#f7fbff; color:#475569; font-size:12px; position:sticky; top:0; text-transform:uppercase; z-index:1; }
            td:nth-child(5),td:nth-child(6),td:nth-child(7) { max-width:320px; word-break:break-word; }
            .progressbar { background:#e2e8f0; border-radius:999px; height:12px; margin:12px 0; overflow:hidden; }
            .progressbar-fill { background:linear-gradient(90deg,var(--blue),#78c0ff); border-radius:999px; height:100%; transition:width .2s ease; }
            .step-list { display:grid; gap:8px; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); max-height:34vh; overflow:auto; padding:2px; }
            .step-card { background:#f8fbff; border:1px solid var(--line); border-radius:12px; padding:10px; }
            .step-card.running { border-color:var(--blue); box-shadow:0 0 0 2px rgba(67,160,255,.12); }
            .step-card.failed { border-color:#fecaca; background:#fff7f7; }
            .step-card.completed { border-color:#bbf7d0; background:#f7fff9; }
            .step-card strong { display:block; margin-bottom:5px; }
            .pill { background:#e7f3ff; border:1px solid rgba(67,160,255,.45); border-radius:999px; color:#075985; display:inline-block; font-size:12px; font-weight:800; padding:4px 9px; }
            .status { min-height:24px; margin-top:10px; }
            .ok { color:#047857; }
            .error { color:#b91c1c; }
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
                <p data-zh="如果此页由上传流程自动打开，请保持主界面标签页继续运行分析；完成后主界面会进入当前语言报告。" data-en="If this page was opened automatically by the upload flow, keep the dashboard tab running analysis; when complete, the dashboard enters the report in the current language.">如果此页由上传流程自动打开，请保持主界面标签页继续运行分析；完成后主界面会进入当前语言报告。</p>
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
                  <thead><tr><th data-zh="时间" data-en="time">时间</th><th data-zh="事件类型" data-en="eventType">事件类型</th><th data-zh="来源" data-en="source">来源</th><th data-zh="进程" data-en="pid/process">进程</th><th data-zh="路径" data-en="path">路径</th><th data-zh="命令行" data-en="commandLine">命令行</th><th data-zh="数据" data-en="data">数据</th></tr></thead>
                  <tbody id="eventRows"><tr><td colspan="7" class="muted" data-zh="暂无事件。" data-en="No events yet.">暂无事件。</td></tr></tbody>
                </table>
              </div>
            </section>
          </main>
          <div id="copyToast" class="toast" role="status" aria-live="polite"></div>
          <script>
            const jobId = '{{Js(jobId)}}';
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';
            let eventOffset = 0;
            let sourceSignature = '';
            let eventSource = null;
            let pollTimer = null;
            let progressTimer = null;
            let backgroundTimer = null;
            let lastProgressSnapshot = null;
            let lastBackgroundSnapshot = null;
            const seen = new Set();

            function t(zh, en) { return currentLanguage === 'en' ? en : zh; }
            function applyLanguage() {
              document.documentElement.lang = currentLanguage === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(el => {
                if (el.id === 'status' || el.id === 'sources' || el.id === 'eventRows') { return; }
                el.textContent = t(el.getAttribute('data-zh'), el.getAttribute('data-en'));
              });
              document.getElementById('langToggle').textContent = currentLanguage === 'en' ? '中文' : 'English';
              if (lastProgressSnapshot) { renderRunbookProgress(lastProgressSnapshot); }
              if (lastBackgroundSnapshot) { renderBackgroundStatus(lastBackgroundSnapshot); }
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

            async function refreshBackgroundStatus() {
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/background`, { cache: 'no-store' });
                const payload = await requireOk(response, t('后台分析状态', 'background analysis status'));
                renderBackgroundStatus(payload);
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

            function renderRunbookProgress(snapshot) {
              lastProgressSnapshot = snapshot;
              const target = document.getElementById('runbookProgress');
              if (!target || !snapshot) { return; }
              const total = Number(snapshot.totalSteps || 0);
              const completed = Number(snapshot.completedSteps || 0);
              const percent = progressPercent(snapshot);
              const state = formatProgressState(snapshot.state);
              const current = snapshot.currentStepTitle || t('等待下一步', 'waiting for next step');
              const message = snapshot.message ? `<p class="muted">${escapeHtml(snapshot.message)}</p>` : '';
              const steps = (snapshot.steps || []).slice(0, 24).map(step => {
                const stepState = String(step.state || 'pending').toLowerCase();
                const line = `${Number(step.stepIndex ?? 0) + 1}. ${step.title || step.stepId || ''}`;
                const detail = [
                  formatProgressState(stepState),
                  step.exitCode == null ? '' : `exit ${step.exitCode}`,
                  step.duration ? formatDuration(step.duration) : ''
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
                ${message}
                <div class="step-list">${steps || `<p class="muted">${t('尚无步骤快照。', 'No step snapshot yet.')}</p>`}</div>`;
              target.setAttribute('data-copy', `runbook ${state} ${completed}/${total} ${current}`);
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
              } catch {
                // Keep VirusTotal silent and non-blocking. Operators can open
                // Settings if they need to inspect the API key.
                renderVirusTotal({ status: 'lookup_failed', configured: true, queried: false, message: t('VirusTotal 查询不可用。', 'VirusTotal lookup unavailable.') });
              }
            }

            function renderVirusTotal(result) {
              const target = document.getElementById('vtResult');
              if (!target) { return; }
              const stats = result.lastAnalysisStats || {};
              const malicious = Number(stats.malicious || 0);
              const suspicious = Number(stats.suspicious || 0);
              const harmless = Number(stats.harmless || 0);
              const undetected = Number(stats.undetected || 0);
              let label;
              if (!result.configured) {
                label = t('未配置 API Key，已跳过官方结果。', 'API key not configured; official result skipped.');
              } else if (!result.queried) {
                label = t('查询失败或被限速，沙箱流程继续。', 'Lookup failed or was rate-limited; sandbox flow continues.');
              } else if (!result.found) {
                label = t('VirusTotal 未收录该 SHA-256。', 'VirusTotal has no report for this SHA-256.');
              } else {
                label = t(`已收录：恶意 ${malicious} / 可疑 ${suspicious} / 无害 ${harmless} / 未检出 ${undetected}`, `Found: malicious ${malicious} / suspicious ${suspicious} / harmless ${harmless} / undetected ${undetected}`);
              }

              const link = result.permalink ? `<a href="${escapeAttr(result.permalink)}" target="_blank" rel="noopener">VirusTotal</a>` : '';
              const name = result.meaningfulName ? `<br><span>${escapeHtml(result.meaningfulName)}</span>` : '';
              const sha = result.sha256 ? `<br><code data-copy="${escapeAttr(result.sha256)}">${escapeHtml(result.sha256)}</code>` : '';
              target.innerHTML = `<strong>${escapeHtml(label)}</strong> ${link}${name}${sha}`;
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
              renderSources(snapshot.sources || []);
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
                body.innerHTML = `<tr><td colspan="7" class="muted">${t('暂无事件。', 'No events yet.')}</td></tr>`;
                return;
              }
              if (seen.size === 0) { body.innerHTML = ''; }
              for (const ev of events) {
                const key = JSON.stringify([ev.timestamp, ev.eventType, ev.source, ev.processId, ev.path, ev.commandLine]);
                if (seen.has(key)) { continue; }
                seen.add(key);
                const data = ev.data ? JSON.stringify(ev.data) : '';
                const pid = [ev.processId || '', ev.processName || ''].filter(Boolean).join(' / ');
                body.insertAdjacentHTML('beforeend', `<tr>
                  <td>${cell(ev.timestamp)}</td>
                  <td>${cell(ev.eventType)}</td>
                  <td>${cell(ev.source)}</td>
                  <td>${cell(pid)}</td>
                  <td>${cell(ev.path)}</td>
                  <td>${cell(ev.commandLine)}</td>
                  <td>${cell(data)}</td>
                </tr>`);
              }
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
            refreshVirusTotal();
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
