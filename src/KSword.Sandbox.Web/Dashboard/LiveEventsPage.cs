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
                <p data-zh="这是独立页面，可与主界面并行打开；这里只显示未归类原始事件，最终结论请看报告。" data-en="This standalone page can stay open beside the dashboard; it shows unclassified raw events only, and final conclusions stay in the report.">这是独立页面，可与主界面并行打开；这里只显示未归类原始事件，最终结论请看报告。</p>
                <p><span class="pill">Job</span> <code data-copy="{{Attr(jobId)}}">{{Html(jobId)}}</code></p>
              </div>
              <button class="secondary" id="langToggle" type="button">English</button>
            </div>
            <div class="actions">
              <a class="button secondary" href="/" data-zh="返回主界面" data-en="Back to dashboard">返回主界面</a>
              <a class="button secondary" href="/jobs/{{Attr(jobId)}}/execution-flow" data-zh="执行流程" data-en="Execution flow">执行流程</a>
              <a class="button" href="/api/jobs/{{Attr(jobId)}}/report/html?lang=zh" target="_blank" rel="noopener" data-zh="打开中文报告" data-en="Open Chinese report">打开中文报告</a>
              <a class="button secondary" href="/api/jobs/{{Attr(jobId)}}/report/html?lang=en" target="_blank" rel="noopener" data-zh="打开英文报告" data-en="Open English report">打开英文报告</a>
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
            const seen = new Set();

            function t(zh, en) { return currentLanguage === 'en' ? en : zh; }
            function applyLanguage() {
              document.documentElement.lang = currentLanguage === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(el => {
                if (el.id === 'status' || el.id === 'sources' || el.id === 'eventRows') { return; }
                el.textContent = t(el.getAttribute('data-zh'), el.getAttribute('data-en'));
              });
              document.getElementById('langToggle').textContent = currentLanguage === 'en' ? '中文' : 'English';
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
            }
            function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
            function escapeAttr(value) { return escapeHtml(value).replace(/`/g, '&#96;'); }
            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest('[data-copy], code, td, th, p, h1, h2, h3, span, a, button') : null;
              if (!target) { return; }
              const value = target.getAttribute('data-copy') || target.innerText || target.textContent || '';
              if (!value.trim()) { return; }
              event.preventDefault();
              navigator.clipboard?.writeText(value).then(() => showToast(t('已复制', 'Copied')));
            });
            function showToast(message) {
              const toast = document.getElementById('copyToast');
              toast.textContent = message;
              toast.classList.add('visible');
              setTimeout(() => toast.classList.remove('visible'), 1200);
            }
            applyLanguage();
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
