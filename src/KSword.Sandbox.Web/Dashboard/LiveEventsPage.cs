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
        var submission = job.Submission;
        static string JsBool(bool? value) => value == true ? "true" : "false";
        return $$"""
        <!doctype html>
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <title>实时原始事件监控 - KSword Sandbox</title>
          <style>
            :root { --blue:#43A0FF; --ink:#0f172a; --muted:#64748b; --line:#dbeafe; color-scheme: light; }
            * { box-sizing: border-box; }
            body { background: linear-gradient(180deg,#f4f9ff,#f8fafc); color: var(--ink); font-family: "Microsoft YaHei UI", Segoe UI, Arial, sans-serif; margin: 0; }
            header { background: radial-gradient(circle at 84% 12%,rgba(67,160,255,.55),transparent 30%),linear-gradient(135deg,#08111f,#0f5f9f); color:white; padding: 26px 36px; }
            main { max-width: 1280px; margin: 22px auto 54px; padding: 0 22px; }
            .topbar { align-items: flex-start; display:flex; justify-content:space-between; gap:16px; }
            .actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:14px; }
            a.button, button { background: var(--blue); border: 0; border-radius:2px; color: white; cursor: pointer; display:inline-block; font-weight:800; padding:9px 14px; text-decoration:none; }
            a.secondary, button.secondary { background:#334155; }
            section { background: rgba(255,255,255,.96); border:1px solid var(--line); border-radius:2px; box-shadow:none; margin-bottom:16px; padding:18px; }
            .grid { display:grid; gap:12px; grid-template-columns: repeat(4,minmax(0,1fr)); }
            .metric { background:#f8fbff; border:1px solid var(--line); border-radius:2px; padding:12px; }
            .metric strong { color:var(--muted); display:block; font-size:12px; margin-bottom:6px; }
            .artifact-table td:nth-child(2) { min-width:280px; }
            .artifact-table td:nth-child(4) { min-width:160px; }
            .artifact-card-grid { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); margin-top:12px; }
            .artifact-card-grid .artifact-group { grid-column:1/-1; }
            .artifact-group { border:1px solid var(--line); border-left:3px solid var(--blue); margin-top:12px; padding:12px; }
            .artifact-group-title { align-items:center; display:flex; flex-wrap:wrap; gap:8px; justify-content:space-between; margin-bottom:6px; }
            .artifact-group-title h3 { margin:0; }
            .artifact-group .artifact-card-grid { margin-top:8px; }
            .artifact-card { background:#f8fbff; border:1px solid var(--line); border-left:3px solid var(--blue); padding:12px; }
            .artifact-card.waiting { border-left-color:#cbd5e1; }
            .artifact-card.ready { border-left-color:#22c55e; }
            .artifact-card.endpoint { border-left-color:var(--blue); }
            .artifact-card-title { align-items:flex-start; display:flex; gap:8px; justify-content:space-between; }
            .artifact-card-title strong { overflow-wrap:anywhere; }
            .artifact-card p { margin:8px 0; }
            .artifact-action { align-items:center; display:flex; flex-wrap:wrap; gap:8px; }
            .artifact-action .path-only { color:var(--muted); font-size:12px; font-weight:700; }
            .artifact-chip-row { align-items:center; display:flex; flex-wrap:wrap; gap:6px; margin:8px 0; }
            .artifact-kv-grid { display:grid; gap:6px; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); margin-top:8px; }
            .artifact-kv { background:#ffffff; border:1px dashed #bfdbfe; padding:7px; }
            .artifact-kv span { color:var(--muted); display:block; font-size:11px; font-weight:900; margin-bottom:3px; text-transform:uppercase; }
            .artifact-kv code { display:inline-block; max-width:100%; }
            .artifact-selector { border-left:3px solid var(--blue); }
            .artifact-mini, .artifact-diagnostics { border:1px dashed var(--line); margin-top:8px; padding:8px; }
            .artifact-mini summary, .artifact-diagnostics summary { color:#075985; cursor:pointer; font-weight:900; }
            .artifact-warning { background:#fff7ed; border-color:#fdba74; color:#9a3412; }
            .artifact-warning code { background:#ffedd5; }
            .report-ready { background:#eff6ff; border:1px solid rgba(67,160,255,.35); border-radius:2px; margin-top:12px; padding:12px; }
            .handoff-notice { border:1px solid rgba(67,160,255,.35); border-left:3px solid var(--blue); margin-top:12px; padding:12px; }
            .handoff-notice.accepted { background:#eff6ff; color:#075985; }
            .handoff-notice.attention { background:#fff7ed; border-color:#fdba74; color:#9a3412; }
            .handoff-notice[hidden] { display:none; }
            .muted { color:var(--muted); }
            code { background:#eef7ff; border-radius:2px; padding:2px 5px; word-break:break-all; }
            .table-wrap { max-height:75vh; overflow:auto; border:1px solid var(--line); border-radius:2px; }
            table { border-collapse:separate; border-spacing:0; width:100%; }
            td, th { border-bottom:1px solid #e5edf6; padding:9px; text-align:left; vertical-align:top; }
            th { background:#f7fbff; color:#475569; font-size:12px; position:sticky; top:0; text-transform:uppercase; z-index:1; }
            td:nth-child(6),td:nth-child(7) { max-width:360px; word-break:break-word; }
            .stream-status { background:#f8fafc; border:1px solid var(--line); border-left:3px solid #cbd5e1; color:#475569; margin:10px 0; padding:10px 12px; }
            .stream-status.ok { background:#f0fdf4; border-color:#bbf7d0; border-left-color:#22c55e; color:#047857; }
            .stream-status.fallback { background:#eff6ff; border-left-color:var(--blue); color:#075985; }
            .stream-status.error { background:#fff7ed; border-color:#fdba74; border-left-color:#f97316; color:#9a3412; }
            .event-toolbar { border:1px solid var(--line); border-left:3px solid var(--blue); display:grid; gap:10px; margin:12px 0; padding:12px; }
            .quick-filter-line { align-items:flex-start; display:flex; flex-wrap:wrap; gap:8px 10px; }
            .quick-filter-title { color:#475569; font-size:12px; font-weight:900; min-width:72px; padding-top:7px; }
            .quick-filter-group { align-items:center; display:flex; flex-wrap:wrap; gap:6px; }
            button.filter-chip { background:#f8fbff; border:1px solid var(--line); color:#075985; font-size:12px; padding:6px 9px; }
            button.filter-chip.active { background:var(--blue); border-color:var(--blue); color:white; }
            .event-page-controls { align-items:center; display:flex; flex-wrap:wrap; gap:8px; }
            .event-page-controls label { align-items:center; display:inline-flex; gap:6px; font-weight:800; }
            .event-page-controls select { border:1px solid var(--line); color:#0f172a; padding:7px 9px; }
            .event-page-status { background:#f8fafc; border:1px solid var(--line); color:#475569; font-size:12px; font-weight:800; padding:7px 9px; }
            .selected-event-summary { background:#f8fbff; border:1px dashed #bfdbfe; color:#075985; margin:10px 0; padding:10px 12px; word-break:break-word; }
            .event-row { cursor:pointer; }
            .event-row:hover { background:#f8fbff; }
            .event-row.selected { background:#eff6ff; outline:2px solid rgba(67,160,255,.45); outline-offset:-2px; }
            .event-severity { border-left:3px solid #cbd5e1; display:inline-block; padding-left:6px; }
            .event-severity.error { border-left-color:#ef4444; color:#b91c1c; font-weight:900; }
            .event-severity.warning { border-left-color:#f97316; color:#c2410c; font-weight:900; }
            .event-severity.info { border-left-color:#22c55e; color:#047857; }
            .progressbar { background:#e2e8f0; border-radius:2px; height:12px; margin:12px 0; overflow:hidden; }
            .progressbar.compact { height:8px; margin:8px 0; }
            .progressbar-fill { background:linear-gradient(90deg,var(--blue),#78c0ff); border-radius:2px; height:100%; transition:width .2s ease; }
            .progressbar-fill.failed { background:linear-gradient(90deg,#f97316,#ef4444); }
            .monitor-stage-grid { display:grid; gap:8px; grid-template-columns:repeat(5,minmax(0,1fr)); margin:12px 0; }
            .monitor-stage { background:#f8fbff; border:1px solid #e5edf6; border-left:3px solid #cbd5e1; color:#64748b; padding:9px; }
            .monitor-stage small { color:#94a3b8; display:block; font-size:11px; margin-top:3px; }
            .monitor-stage.active { border-left-color:var(--blue); color:#075985; font-weight:900; }
            .monitor-stage.done { border-left-color:#22c55e; color:#047857; }
            .monitor-stage.failed { background:#fff7ed; border-left-color:#f97316; color:#c2410c; font-weight:900; }
            .card-status { align-items:center; display:flex; flex-wrap:wrap; gap:8px; justify-content:space-between; margin-bottom:8px; }
            .card-status strong { margin-right:auto; }
            .percent-label { color:#075985; font-size:12px; font-weight:900; }
            .countdown { background:#fff7ed; border:1px solid #fdba74; color:#9a3412; font-weight:800; padding:8px 10px; }
            .cockpit-grid { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); margin-top:12px; }
            .cockpit-card { background:#f8fbff; border:1px solid var(--line); border-left:3px solid var(--blue); padding:12px; }
            .cockpit-card.ready { border-left-color:#22c55e; }
            .cockpit-card.waiting { border-left-color:#cbd5e1; }
            .cockpit-card.failed { border-left-color:#ef4444; background:#fff7f7; }
            .cockpit-card.quiet { border-left-color:#94a3b8; background:#f8fafc; }
            .cockpit-card.endpoint { border-left-color:var(--blue); }
            .cockpit-card h3 { margin:0 0 8px; }
            .cockpit-main { font-size:18px; font-weight:900; overflow-wrap:anywhere; }
            .cockpit-meta { align-items:center; display:flex; flex-wrap:wrap; gap:6px; margin-top:10px; }
            .step-list { display:grid; gap:8px; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); max-height:34vh; overflow:auto; padding:2px; }
            .step-card { background:#f8fbff; border:1px solid var(--line); border-radius:2px; padding:10px; }
            .step-card summary { cursor:pointer; list-style:none; }
            .step-card summary::-webkit-details-marker { display:none; }
            .step-card summary::after { color:var(--muted); content:"＋"; float:right; font-weight:900; }
            .step-card[open] summary::after { content:"－"; }
            .step-card.running { border-color:var(--blue); box-shadow:none; }
            .step-card.failed { border-color:#fecaca; background:#fff7f7; }
            .step-card.completed { border-color:#bbf7d0; background:#f7fff9; }
            .step-card.current { border-left-color:var(--blue); background:#eff6ff; }
            .step-card strong { display:block; margin-bottom:5px; }
            .runbook-live-summary { border:1px solid var(--line); border-left:3px solid var(--blue); display:grid; gap:8px; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); margin:10px 0 12px; padding:10px; }
            .runbook-live-summary span { color:var(--muted); display:block; font-size:12px; font-weight:800; margin-bottom:3px; }
            .step-output-details { border-top:1px solid #e5edf6; margin-top:8px; padding-top:8px; }
            .step-output-details summary, .output-details summary { color:#075985; cursor:pointer; font-weight:800; }
            .output-details { border:1px dashed var(--line); margin-top:12px; padding:10px; }
            .output-details pre { background:#0f172a; color:#e5e7eb; max-height:28vh; overflow:auto; padding:10px; white-space:pre-wrap; word-break:break-word; }
            .output-empty { color:var(--muted); font-style:italic; }
            .pill { background:#e7f3ff; border:1px solid rgba(67,160,255,.45); border-radius:2px; color:#075985; display:inline-block; font-size:12px; font-weight:800; padding:4px 9px; }
            .pill.waiting { background:#f1f5f9; border-color:#cbd5e1; color:#475569; }
            .pill.ready { background:#dcfce7; border-color:#86efac; color:#047857; }
            .pill.endpoint { background:#e0f2fe; border-color:#7dd3fc; color:#0369a1; }
            .pill.failed { background:#fee2e2; border-color:#fca5a5; color:#b91c1c; }
            .pill.quiet { background:#f8fafc; border-color:#cbd5e1; color:#475569; }
            .status { min-height:24px; margin-top:10px; }
            .ok { color:#047857; }
            .error { color:#b91c1c; }
            .vt-card { border-width:2px; }
            .vt-card .vt-head { align-items:flex-start; display:flex; justify-content:space-between; gap:14px; }
            .vt-card .vt-score { font-size:30px; font-weight:900; line-height:1; }
            .vt-card .vt-stats { display:grid; gap:8px; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); margin-top:12px; }
            .vt-card .vt-stats span { background:rgba(255,255,255,.72); border:1px solid rgba(148,163,184,.28); border-radius:2px; padding:8px; }
            .vt-card .vt-field-grid { display:grid; gap:8px; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); margin-top:10px; }
            .vt-card .vt-field { background:rgba(255,255,255,.72); border:1px solid rgba(148,163,184,.28); border-radius:2px; padding:8px; }
            .vt-card .vt-field b { color:#475569; display:block; font-size:12px; margin-bottom:4px; }
            .vt-card .vt-details { border:1px dashed rgba(67,160,255,.32); margin-top:10px; padding:9px; }
            .vt-card .vt-details summary { color:#075985; cursor:pointer; font-weight:900; }
            .vt-card .vt-quiet-explainer { background:#f8fafc; border-color:#cbd5e1; }
            .vt-state-banner { background:rgba(255,255,255,.72); border:1px solid rgba(148,163,184,.28); margin:8px 0; padding:8px; }
            .vt-state-row { display:flex; flex-wrap:wrap; gap:6px; margin:10px 0; }
            .vt-danger { background:#fff7f7; border-color:#fca5a5; }
            .vt-danger .vt-score { color:#b91c1c; }
            .vt-warning { background:#fff8ed; border-color:#fdba74; }
            .vt-warning .vt-score { color:#c2410c; }
            .vt-ok { background:#f2fff7; border-color:#86efac; }
            .vt-ok .vt-score { color:#047857; }
            .vt-neutral { background:#f8fbff; border-color:#bae6fd; }
            .vt-quiet { background:#f8fafc; border-color:#cbd5e1; }
            .toast { background:#0f172a; border-radius:2px; bottom:22px; color:white; left:50%; opacity:0; padding:10px 16px; pointer-events:none; position:fixed; transform:translate(-50%,12px); transition:.15s; z-index:20; }
            .toast.visible { opacity:.96; transform:translate(-50%,0); }
            [data-copy], code, td, th { cursor: copy; }
            [data-copy]:hover, code:hover, td:hover, th:hover { outline:1px dashed var(--blue); outline-offset:2px; }
            .metric, .step-card, .report-ready, .table-wrap, .artifact-group, .artifact-card, .vt-card .vt-stats span { box-shadow:none; border-radius:2px; }
            .metric { background:transparent; border:0; border-left:3px solid var(--blue); padding:10px 12px; }
            .step-card { background:transparent; border:0; border-left:3px solid var(--line); padding:8px 10px; }
            .step-card.running { border-left-color:var(--blue); box-shadow:none; }
            .step-card.failed { border-left-color:#ef4444; }
            .step-card.completed { border-left-color:#22c55e; }
            .table-wrap { border:0; border-top:1px solid var(--line); }
            .report-ready { background:transparent; border-color:var(--line); }

            /* Square, flat operator theme: keep visual nesting shallow. */
            section, article, .metric, .pill, button, a.button, a.buttonlink, input, code, pre, .pathbox, .callout, .report-notice, .report-entry, .workspace-tab, .tab-button, .tab-panel, details, .progress-box, .progress-bar, .progress-fill, .stage, .recent-job-card, .runbook-step, .empty, .table-wrap, .step-card, .artifact-group, .artifact-card, .cockpit-card, .vt-state-banner, .report-ready, .handoff-notice, .countdown, .toast, .num, .stream-status, .event-toolbar, .event-page-status, .selected-event-summary, select { border-radius: 0 !important; }
            section, article, .metric, .pathbox, .callout, .report-notice, .report-entry, .tab-panel, .progress-box, .stage, .recent-job-card, .runbook-step, .step-card, .artifact-group, .artifact-card, .cockpit-card, .report-ready, .handoff-notice, .stream-status, .event-toolbar { box-shadow: none !important; }
            .pill, button, a.button, a.buttonlink { box-shadow: none !important; }
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
                <p><span class="pill" data-zh="任务 / Job" data-en="Job">任务 / Job</span> <code data-copy="{{Attr(jobId)}}">{{Html(jobId)}}</code></p>
              </div>
              <button class="secondary" id="langToggle" type="button">切换到 English</button>
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
                <div class="metric"><strong data-zh="状态" data-en="Status">状态</strong><span class="pill" data-copy="{{Attr(FormatAnalysisStatus(job.Status))}}">{{Html(FormatAnalysisStatus(job.Status))}}</span></div>
                <div class="metric"><strong data-zh="事件文件" data-en="Event file">事件文件</strong><code data-copy="{{Attr(job.GuestEventsPath ?? string.Empty)}}">{{Html(string.IsNullOrWhiteSpace(job.GuestEventsPath) ? "等待回收" : job.GuestEventsPath)}}</code></div>
                <div class="metric"><strong data-zh="报告" data-en="Report">报告</strong><code data-copy="{{Attr(job.HtmlReportPath ?? string.Empty)}}">{{Html(job.HtmlReportPath ?? "report.html")}}</code></div>
              </div>
              <div id="status" class="status muted" data-zh="等待连接实时事件流。" data-en="Waiting to connect live event stream.">等待连接实时事件流。</div>
              <div id="sources" class="muted"></div>
              <div id="uploadHandoffNotice" class="handoff-notice" hidden data-copy="上传接管状态未启用 / upload handoff not active"></div>
            </section>
            <section>
              <h2 data-zh="运营态势驾驶舱" data-en="Operator cockpit">运营态势驾驶舱</h2>
              <p class="muted" data-zh="面向值守人员的一屏摘要：真实 runbook 当前步骤、VirusTotal 静默信誉状态、证据索引就绪度。所有卡片支持右键复制，不使用大表格堆信息。" data-en="One-screen operator summary: real runbook current step, quiet VirusTotal reputation state, and artifact-index readiness. Every card supports right-click copy and avoids giant tables.">面向值守人员的一屏摘要：真实 runbook 当前步骤、VirusTotal 静默信誉状态、证据索引就绪度。所有卡片支持右键复制，不使用大表格堆信息。</p>
              <div id="operatorCockpit" class="cockpit-grid" data-copy="运营态势加载中 / operator cockpit loading">
                <article class="cockpit-card waiting muted" data-copy="等待真实进度流 / waiting for real progress stream">
                  <h3>当前步骤</h3>
                  <p class="cockpit-main">等待真实进度流</p>
                </article>
              </div>
            </section>
            <section>
              <h2 data-zh="本次采集选项" data-en="This run collection options">本次采集选项</h2>
              <p class="muted" data-zh="上传/启动分析时提交的 operator 选项会固定显示在这里；内存转储语义为样本进程，Guest Agent 支持时包含已解析子进程。" data-en="Operator options submitted by upload/start are fixed here; memory-dump semantics are the sample process, including resolved child processes when supported by the Guest Agent.">上传/启动分析时提交的 operator 选项会固定显示在这里；内存转储语义为样本进程，Guest Agent 支持时包含已解析子进程。</p>
              <div id="operatorOptions" class="grid" data-copy="采集选项加载中 / collection options loading"></div>
            </section>
            <section>
              <h2 data-zh="证据 / 下载" data-en="Artifacts / downloads">证据 / 下载</h2>
              <p class="muted" data-zh="证据文件来自真实证据索引（artifact index）；可下载的文件走安全下载端点（endpoint），并明确展示安全 selector、重复组和拒绝诊断；尚未回收的采集项显示等待状态。" data-en="Evidence files come from the real artifact index; downloadable files use the guarded download endpoint and expose safe selectors, duplicate groups, and rejection diagnostics; collection lanes not yet recovered show a waiting state.">证据文件来自真实证据索引（artifact index）；可下载的文件走安全下载端点（endpoint），并明确展示安全 selector、重复组和拒绝诊断；尚未回收的采集项显示等待状态。</p>
              <p class="artifact-action">
                <button class="secondary" type="button" onclick="refreshArtifactCardsNow()" data-copy="手动刷新证据索引 / Refresh artifact index" data-zh="刷新证据/下载卡片" data-en="Refresh artifact/download cards">刷新证据/下载卡片</button>
                <span class="pill quiet" data-copy="live monitor always shows report, events, driver-events, dropped files, screenshots, memory dumps, and PCAP lanes">报告、events、驱动遥测、落地文件、截图、内存转储、PCAP 均保留卡片 lane</span>
              </p>
              <div id="reportReadyActions" class="report-ready muted" data-copy="报告待生成 / reports pending">报告按钮会在运行结束后保持可用。</div>
              <div id="artifactCards" class="artifact-card-grid">
                <article class="artifact-card waiting muted" data-copy="证据路径解析中 / artifacts pending" data-zh="正在解析证据（artifact）路径。" data-en="Resolving artifact paths.">正在解析证据（artifact）路径。</article>
              </div>
            </section>
            <section>
              <h2 data-zh="虚拟机分析进度" data-en="Runbook progress">虚拟机分析进度</h2>
              <p class="muted" data-zh="这里优先连接 /api/jobs/{jobId}/progress/stream 真实进度流，同步持久化 runbook-progress.json 中的真实执行步骤；只展示安全的步骤状态，不展示命令行、stdout 或 stderr，SSE 不可用时自动退回轮询。" data-en="This panel prefers the real /api/jobs/{jobId}/progress/stream feed and mirrors real runbook steps from durable runbook-progress.json; it shows UI-safe status only, not command lines, stdout, or stderr, and falls back to polling when SSE is unavailable.">这里优先连接 /api/jobs/{jobId}/progress/stream 真实进度流，同步持久化 runbook-progress.json 中的真实执行步骤；只展示安全的步骤状态，不展示命令行、stdout 或 stderr，SSE 不可用时自动退回轮询。</p>
              <div id="runbookProgress" class="metric muted" data-copy="等待执行进度 / runbook progress pending" data-zh="等待主界面启动分析。" data-en="Waiting for dashboard analysis.">等待主界面启动分析。</div>
              <div id="backgroundStatus" class="metric muted" data-copy="后台执行等待启动 / background execution pending" data-zh="后台执行状态：等待启动。" data-en="Background execution: waiting.">后台执行状态：等待启动。</div>
            </section>
            <section>
              <h2 data-zh="VirusTotal 官方结果" data-en="VirusTotal official result">VirusTotal 官方结果</h2>
              <p class="muted" data-zh="只查询 SHA-256 文件报告，不上传样本；未配置、未收录、限速、鉴权失败、超时或查询失败都作为静默页面状态展示，不影响沙箱流程，也不写任务/行为日志；只有已收录结果被显式要求时才允许写入信誉增强证据。" data-en="SHA-256 file-report lookup only; samples are not uploaded. Not configured, not found, rate-limited, auth-failed, timeout, or lookup-failed outcomes are quiet page statuses; they do not affect sandbox execution or write job/behavior logs. Only found results can be explicitly persisted as reputation enrichment.">只查询 SHA-256 文件报告，不上传样本；未配置、未收录、限速、鉴权失败、超时或查询失败都作为静默页面状态展示，不影响沙箱流程，也不写任务/行为日志；只有已收录结果被显式要求时才允许写入信誉增强证据。</p>
              <div id="vtResult" class="metric muted" data-copy="VirusTotal：等待查询 / pending">VirusTotal：等待查询。</div>
              <button class="secondary" type="button" onclick="refreshVirusTotal()" data-zh="刷新 VirusTotal" data-en="Refresh VirusTotal">刷新 VirusTotal</button>
            </section>
            <section>
              <h2 data-zh="原始事件流" data-en="Raw event stream">原始事件流</h2>
              <p class="muted" data-zh="实时显示不是最终判定（verdict）；这里只保留未归类原始事件。可用严重度、类型、来源快速筛选，表格按页渲染，右键任意行/单元复制，选中行后可复制一条简短事件摘要。" data-en="Live display is not the final verdict; this page keeps unclassified raw events only. Use severity, type, and source quick filters, render bounded table pages, right-click any row/cell to copy, and select a row to copy a compact event summary.">实时显示不是最终判定（verdict）；这里只保留未归类原始事件。可用严重度、类型、来源快速筛选，表格按页渲染，右键任意行/单元复制，选中行后可复制一条简短事件摘要。</p>
              <div id="streamFallbackStatus" class="stream-status" data-copy="原始事件流状态：等待连接 / raw event stream pending" data-zh="原始事件流状态：等待连接。" data-en="Raw event stream status: waiting to connect.">原始事件流状态：等待连接。</div>
              <div class="event-toolbar" aria-label="原始事件筛选与分页">
                <div class="quick-filter-line">
                  <span class="quick-filter-title" data-zh="严重度" data-en="Severity">严重度</span>
                  <div id="severityFilters" class="quick-filter-group"></div>
                </div>
                <div class="quick-filter-line">
                  <span class="quick-filter-title" data-zh="类型" data-en="Type">类型</span>
                  <div id="typeFilters" class="quick-filter-group"></div>
                </div>
                <div class="quick-filter-line">
                  <span class="quick-filter-title" data-zh="来源" data-en="Source">来源</span>
                  <div id="sourceFilters" class="quick-filter-group"></div>
                </div>
                <div class="event-page-controls">
                  <button class="secondary" type="button" onclick="goEventPage('first')" data-zh="首页" data-en="First">首页</button>
                  <button class="secondary" type="button" onclick="goEventPage('prev')" data-zh="上一页" data-en="Previous">上一页</button>
                  <span id="eventPageStatus" class="event-page-status" data-copy="原始事件分页：等待数据 / raw-event pagination pending">原始事件分页：等待数据</span>
                  <button class="secondary" type="button" onclick="goEventPage('next')" data-zh="下一页" data-en="Next">下一页</button>
                  <button class="secondary" type="button" onclick="goEventPage('latest')" data-zh="最新页" data-en="Latest">最新页</button>
                  <label><span data-zh="每页" data-en="Page size">每页</span>
                    <select id="eventPageSize" onchange="setEventPageSize(this.value)">
                      <option value="25">25</option>
                      <option value="50" selected>50</option>
                      <option value="100">100</option>
                    </select>
                  </label>
                  <button class="secondary" type="button" onclick="clearEventFilters()" data-zh="清除筛选" data-en="Clear filters">清除筛选</button>
                  <button type="button" onclick="copySelectedEventSummary()" data-zh="复制选中事件摘要" data-en="Copy selected event summary">复制选中事件摘要</button>
                </div>
              </div>
              <div id="selectedEventSummary" class="selected-event-summary muted" data-copy="未选择原始事件 / no raw event selected" data-zh="尚未选择原始事件；点击表格行后可复制摘要。" data-en="No raw event is selected yet; click a table row to copy its summary.">尚未选择原始事件；点击表格行后可复制摘要。</div>
              <div class="table-wrap">
                <table>
                  <thead><tr><th data-zh="严重度" data-en="severity">严重度</th><th data-zh="时间" data-en="time">时间</th><th data-zh="事件类型" data-en="eventType">事件类型</th><th data-zh="来源" data-en="source">来源</th><th data-zh="进程" data-en="pid/process">进程</th><th data-zh="路径" data-en="path">路径</th><th data-zh="数据（已隐藏命令输出字段）" data-en="data (command output fields hidden)">数据（已隐藏命令输出字段）</th></tr></thead>
                  <tbody id="eventRows"><tr><td colspan="7" class="muted" data-zh="暂无原始事件。" data-en="No raw events yet.">暂无原始事件。</td></tr></tbody>
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
              status: '{{Js(job.Status.ToString())}}',
              submission: {
                collectDroppedFiles: {{JsBool(submission.CollectDroppedFiles)}},
                captureScreenshots: {{JsBool(submission.CaptureScreenshots)}},
                captureMemoryDumps: {{JsBool(submission.CaptureMemoryDumps)}},
                capturePacketCapture: {{JsBool(submission.CapturePacketCapture)}}
              }
            };
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';
            let eventOffset = 0;
            let sourceSignature = '';
            let eventSource = null;
            let progressEventSource = null;
            let pollTimer = null;
            let progressTimer = null;
            let backgroundTimer = null;
            let jobTimer = null;
            let progressStreamFallbackTimer = null;
            let progressStreamTerminal = false;
            let progressStreamConnected = false;
            let lastProgressSnapshot = null;
            let lastBackgroundSnapshot = null;
            let lastProgressStreamEnvelope = null;
            let progressStreamMode = 'pending';
            let lastVirusTotalResult = null;
            let latestJobSnapshot = initialJob;
            let latestArtifactSources = [];
            let latestArtifactIndex = null;
            let latestArtifactRows = [];
            let latestArtifactSignals = {};
            let reportAutoOpenScheduled = false;
            let reportAutoOpenTimer = null;
            let reportAutoOpenDeadline = 0;
            let reportAutoOpenHref = '';
            let reportAutoOpenRemainingSeconds = 0;
            const monitorQuery = new URLSearchParams(window.location.search);
            const enteredFromUpload = monitorQuery.get('fromUpload') === '1';
            const uploadHandoffAccepted = monitorQuery.get('accepted') === '1';
            const uploadHandoffState = monitorQuery.get('state') || '';
            const autoOpenReportFromMonitor = enteredFromUpload;
            const monitorStages = [
              ['启动 VM', 'Start VM', '还原快照并等待来宾机可用', 'Restore checkpoint and wait for guest readiness'],
              ['部署 Payload', 'Deploy payload', '传入样本、Agent 与采集器', 'Copy sample, agent, and collectors'],
              ['执行样本', 'Execute sample', '运行样本并采集行为', 'Run the sample and collect behavior'],
              ['收集结果', 'Collect results', '同步事件、截图、转储与 PCAP', 'Sync events, screenshots, dumps, and PCAP'],
              ['生成报告', 'Generate report', '刷新 JSON/HTML 报告并开放入口', 'Refresh JSON/HTML reports and expose links']
            ];
            const seen = new Set();
            const liveEventRecords = [];
            const maxBufferedLiveEvents = 2000;
            const eventTypeFilters = [
              ['all', '全部', 'All'],
              ['process', '进程', 'Process'],
              ['file', '文件', 'File'],
              ['registry', '注册表', 'Registry'],
              ['network', '网络', 'Network'],
              ['driver', 'R0/驱动', 'R0/driver'],
              ['artifact', '证据', 'Artifact'],
              ['diagnostic', '诊断/状态', 'Diagnostics']
            ];
            const severityFilters = [
              ['all', '全部', 'All'],
              ['error', '错误', 'Error'],
              ['warning', '警告', 'Warning'],
              ['info', '信息', 'Info']
            ];
            let activeSeverityFilter = 'all';
            let activeTypeFilter = 'all';
            let activeSourceFilter = 'all';
            let eventPageIndex = 0;
            let eventPageSize = 50;
            let selectedEventKey = '';
            let liveFetchInFlight = false;

            function t(zh, en) { return currentLanguage === 'en' ? en : zh; }
            function applyLanguage() {
              document.documentElement.lang = currentLanguage === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(el => {
                if (el.id === 'status' || el.id === 'sources' || el.id === 'eventRows' || el.id === 'operatorCockpit' || el.id === 'artifactCards' || el.id === 'reportReadyActions' || el.id === 'vtResult' || el.id === 'uploadHandoffNotice' || el.id === 'streamFallbackStatus' || el.id === 'eventPageStatus' || el.id === 'selectedEventSummary' || el.id === 'severityFilters' || el.id === 'typeFilters' || el.id === 'sourceFilters') { return; }
                el.textContent = t(el.getAttribute('data-zh'), el.getAttribute('data-en'));
              });
              document.getElementById('langToggle').textContent = currentLanguage === 'en' ? '切换到中文' : '切换到 English';
              if (lastProgressSnapshot) { renderRunbookProgress(lastProgressSnapshot); }
              if (lastBackgroundSnapshot) { renderBackgroundStatus(lastBackgroundSnapshot); }
              if (lastVirusTotalResult) { renderVirusTotal(lastVirusTotalResult); }
              renderOperatorOptions(latestJobSnapshot || initialJob);
              if (reportAutoOpenScheduled) { updateReportAutoOpenNotice(); }
              renderUploadHandoffNotice();
              renderArtifactPanel();
              renderOperatorCockpit();
              renderEventTable();
            }
            document.getElementById('langToggle').addEventListener('click', () => {
              currentLanguage = currentLanguage === 'en' ? 'zh' : 'en';
              localStorage.setItem('ksword-lang', currentLanguage);
              applyLanguage();
            });

            function normalizeStatusToken(value) {
              return String(value ?? '').trim().toLowerCase().replace(/[\s-]+/g, '_');
            }

            function localizeServerStatus(value) {
              const raw = String(value ?? '').trim();
              if (!raw) {
                return '';
              }

              const labels = {
                not_started: t('未启动', 'not started'),
                queued: t('已排队', 'queued'),
                pending: t('等待中', 'pending'),
                waiting: t('等待中', 'waiting'),
                running: t('运行中', 'running'),
                completed: t('已完成', 'completed'),
                complete: t('已完成', 'complete'),
                succeeded: t('成功', 'succeeded'),
                success: t('成功', 'success'),
                failed: t('失败', 'failed'),
                failure: t('失败', 'failure'),
                canceled: t('已取消', 'canceled'),
                cancelled: t('已取消', 'cancelled'),
                skipped: t('已跳过', 'skipped'),
                not_configured: t('未配置', 'not configured'),
                lookup_failed: t('查询失败', 'lookup failed'),
                not_found: t('未收录', 'not found'),
                unavailable: t('不可用', 'unavailable'),
                ready: t('就绪', 'ready')
              };
              return labels[normalizeStatusToken(raw)] || raw;
            }

            function localizeServerMessage(value) {
              if (value == null || value === '') {
                return '';
              }

              return String(value)
                .replace(/\bnot configured\b/gi, t('未配置', 'not configured'))
                .replace(/\bapi key\b/gi, t('API Key', 'API key'))
                .replace(/\bnot found\b/gi, t('未找到', 'not found'))
                .replace(/\blookup failed\b/gi, t('查询失败', 'lookup failed'))
                .replace(/\bprogress stream\b/gi, t('进度流', 'progress stream'))
                .replace(/\bstream\b/gi, t('流', 'stream'))
                .replace(/\bpolling\b/gi, t('轮询', 'polling'))
                .replace(/\bfailed\b/gi, t('失败', 'failed'))
                .replace(/\bsucceeded\b/gi, t('成功', 'succeeded'))
                .replace(/\bcompleted\b/gi, t('已完成', 'completed'));
            }

            function renderUploadHandoffNotice() {
              const target = document.getElementById('uploadHandoffNotice');
              if (!target) { return; }
              if (!enteredFromUpload) {
                target.hidden = true;
                return;
              }

              const stateToken = normalizeStatusToken(uploadHandoffState || 'submitted');
              const stateLabel = localizeServerStatus(stateToken) || stateToken;
              const handoffIssue = !uploadHandoffAccepted && !['queued', 'running', 'completed', 'complete', 'succeeded', 'success'].includes(stateToken);
              const headline = handoffIssue
                ? t('上传已创建任务，但后台启动未确认', 'Upload created a job, but background start is not confirmed')
                : t('上传流程已接管到实时监控', 'Upload flow has handed off to the live monitor');
              const detail = handoffIssue
                ? t('任务上下文已保留；请查看下方后台执行状态和真实进度流，必要时打开执行流程页排查 VM 预检或凭据问题。', 'Job context is preserved; review the background status and real progress stream below, and open the execution-flow page for VM preflight or credential issues if needed.')
                : t('Web Host 已接管后台执行，本页会连接真实进度流、原始事件流、证据索引和 VirusTotal 静默状态；不需要重新上传。', 'The Web Host owns background execution; this page connects the real progress stream, raw-event stream, artifact index, and quiet VirusTotal status. Do not upload again.');
              const progressHref = `/jobs/${encodeURIComponent(jobId)}/execution-flow`;
              const copy = `${headline}; job=${jobId}; accepted=${uploadHandoffAccepted}; state=${stateToken}; ${detail}`;
              target.hidden = false;
              target.className = `handoff-notice ${handoffIssue ? 'attention' : 'accepted'}`;
              target.setAttribute('data-copy', copy);
              target.innerHTML = `
                <strong>${escapeHtml(headline)}</strong>
                <p>${escapeHtml(detail)}</p>
                <p><span class="pill ${handoffIssue ? 'failed' : 'endpoint'}" data-copy="${escapeAttr(stateToken)}">${escapeHtml(t('接管状态', 'Handoff state'))}：${escapeHtml(stateLabel)}</span>
                <a class="button secondary" target="_blank" rel="noopener" href="${escapeAttr(progressHref)}">${escapeHtml(t('打开执行流程排障', 'Open execution flow'))}</a></p>`;
            }

            function firstDefined(...values) {
              for (const value of values) {
                if (value !== undefined && value !== null) { return value; }
              }
              return undefined;
            }

            function firstTextValue(...values) {
              for (const value of values) {
                if (value !== undefined && value !== null && String(value).trim()) {
                  return String(value).trim();
                }
              }
              return '';
            }

            function objectValue(source, ...keys) {
              if (!source || typeof source !== 'object') { return undefined; }
              for (const key of keys) {
                if (Object.prototype.hasOwnProperty.call(source, key) && source[key] !== undefined && source[key] !== null) {
                  return source[key];
                }
              }
              return undefined;
            }

            function vtValue(result, camel, pascal) {
              return objectValue(result, camel, pascal || (camel ? camel.charAt(0).toUpperCase() + camel.slice(1) : camel));
            }

            function vtBoolValue(result, camel, pascal) {
              const value = vtValue(result, camel, pascal);
              if (typeof value === 'boolean') { return value; }
              if (typeof value === 'string') { return value.toLowerCase() === 'true'; }
              return Boolean(value);
            }

            function connectSse() {
              stopLive();
              setStatus(t('正在连接 SSE 原始事件流...', 'Connecting SSE raw event stream...'), false);
              setStreamFallbackStatus(
                t('原始事件流：正在连接 SSE；若浏览器、代理或端点不支持，将自动降级为轮询 fallback。', 'Raw event stream: connecting SSE; if the browser, proxy, or endpoint does not support it, the page will fall back to polling.'),
                'fallback');
              try {
                eventSource = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/events/stream?offset=${eventOffset}&take=100&intervalMs=1500`);
                eventSource.addEventListener('open', () => setStreamFallbackStatus(
                  t('原始事件流：SSE 已连接，等待 snapshot；如果长时间没有帧，可手动刷新或等待自动 fallback。', 'Raw event stream: SSE is connected and waiting for a snapshot; if frames do not arrive, refresh manually or wait for automatic fallback.'),
                  'ok'));
                eventSource.addEventListener('snapshot', ev => {
                  try {
                    renderSnapshot(JSON.parse(ev.data), 'SSE');
                  } catch {
                    setStreamFallbackStatus(
                      t('原始事件流：SSE snapshot 解析失败；已保留连接并等待下一帧，表格不会追加不可解析数据。', 'Raw event stream: failed to parse an SSE snapshot; the connection stays open and the table will not append malformed data.'),
                      'error');
                  }
                });
                eventSource.onerror = () => {
                  stopLive();
                  startPolling(t('SSE 原始事件流不可用，已切换为轮询 fallback；继续使用 nextOffset 游标补齐原始事件。', 'SSE raw event stream is unavailable; switched to polling fallback and will keep using the nextOffset cursor.'));
                };
              } catch {
                startPolling(t('浏览器不支持 SSE，已切换为轮询 fallback；继续使用 nextOffset 游标补齐原始事件。', 'Browser SSE support is unavailable; switched to polling fallback and will keep using the nextOffset cursor.'));
              }
            }

            function startRunbookProgressStream() {
              stopRunbookProgressPolling();
              stopBackgroundStatusPolling();
              stopRunbookProgressStream();
              progressStreamTerminal = false;
              progressStreamConnected = false;
              progressStreamMode = 'connecting';
              renderOperatorCockpit();
              setProgressStreamStatus(t('正在连接真实进度流；如 6 秒内没有快照将自动切换到安全轮询。', 'Connecting real progress stream; if no snapshot arrives within 6 seconds the page will switch to safe polling.'));

              if (!window.EventSource) {
                startRunbookProgressPollingFallback(t('浏览器不支持进度流，已切换为安全轮询。', 'Browser progress stream support unavailable; switched to safe polling.'));
                return;
              }

              try {
                progressEventSource = new EventSource(`/api/jobs/${encodeURIComponent(jobId)}/progress/stream?heartbeatMs=1500&maxSeconds=1800`);
                progressStreamFallbackTimer = setTimeout(() => {
                  if (!progressStreamConnected && !progressStreamTerminal) {
                    stopRunbookProgressStream();
                    startRunbookProgressPollingFallback(t('进度流暂未返回快照，已切换为安全轮询。', 'Progress stream did not return a snapshot yet; switched to safe polling.'));
                  }
                }, 6000);

                progressEventSource.onopen = () => {
                  progressStreamConnected = true;
                  progressStreamMode = 'sse';
                  clearProgressStreamFallbackTimer();
                  stopRunbookProgressPolling();
                  stopBackgroundStatusPolling();
                  renderOperatorCockpit();
                  setProgressStreamStatus(t('真实进度流已连接，等待 runbook step 快照。', 'Real progress stream connected; waiting for runbook step snapshots.'));
                };

                ['snapshot', 'heartbeat', 'final', 'failed', 'timeout'].forEach(eventName => {
                  progressEventSource.addEventListener(eventName, ev => {
                    renderProgressStreamPayload(JSON.parse(ev.data), eventName);
                  });
                });

                progressEventSource.onerror = () => {
                  if (progressStreamTerminal) { return; }
                  stopRunbookProgressStream();
                  startRunbookProgressPollingFallback(t('进度 SSE 不可用，已切换为轮询。', 'Progress SSE unavailable; switched to polling.'));
                };
              } catch {
                startRunbookProgressPollingFallback(t('进度流初始化失败，已切换为安全轮询。', 'Progress stream initialization failed; switched to safe polling.'));
              }
            }

            function renderProgressStreamPayload(payload, eventName) {
              if (!payload) { return; }
              progressStreamConnected = true;
              progressStreamMode = 'sse';
              lastProgressStreamEnvelope = normalizeProgressStreamEnvelope(payload, eventName);
              clearProgressStreamFallbackTimer();
              if (eventName === 'heartbeat' && !payload.progress && !payload.background) {
                setProgressStreamStatus(t('真实进度流心跳正常，等待下一条进度快照。', 'Real progress stream heartbeat is healthy; waiting for the next progress snapshot.'));
              }
              if (payload.progress) {
                renderRunbookProgress(payload.progress, payload.currentStep || payload.CurrentStep);
              }
              if (payload.background) {
                if (payload.background.job) {
                  latestJobSnapshot = normalizeJobSnapshot(payload.background.job);
                }
                renderBackgroundStatus(payload.background);
              }

              const terminal = Boolean(payload.terminal) || ['final', 'failed'].includes(eventName);
              if (terminal) {
                progressStreamTerminal = true;
                stopRunbookProgressStream();
                stopRunbookProgressPolling();
                stopBackgroundStatusPolling();
                setProgressStreamStatus(eventName === 'failed'
                  ? t('真实进度流已收到失败终态，正在刷新证据索引。', 'Real progress stream received a failed terminal state and is refreshing the artifact index.')
                  : t('真实进度流已结束，正在刷新证据索引。', 'Real progress stream ended and is refreshing the artifact index.'));
                refreshArtifactIndex(false).then(renderArtifactPanel).catch(() => renderArtifactPanel());
                refreshJobSnapshot();
                renderOperatorCockpit();
                return;
              }

              if (eventName === 'timeout') {
                stopRunbookProgressStream();
                setTimeout(startRunbookProgressStream, 1200);
              }
            }

            function normalizeProgressStreamEnvelope(payload, eventName) {
              const progress = payload.progress || payload.Progress || null;
              const streamStep = normalizeRunbookStepInfo(payload.currentStep || payload.CurrentStep, progress);
              return {
                eventName: eventName || payload.event || payload.Event || 'snapshot',
                transport: payload.transport || payload.Transport || 'sse',
                state: String(payload.state || payload.State || progress?.state || progress?.State || 'pending').toLowerCase(),
                terminal: Boolean(payload.terminal || payload.Terminal),
                generatedAtUtc: payload.generatedAtUtc || payload.GeneratedAtUtc || '',
                progressPercent: Number(firstDefined(payload.progressPercent, payload.ProgressPercent, progressPercent(progress || {}))),
                message: payload.message || payload.Message || '',
                currentStep: streamStep
              };
            }

            function startRunbookProgressPollingFallback(message) {
              progressStreamMode = 'poll';
              const target = document.getElementById('backgroundStatus');
              if (target && message) {
                target.className = 'metric muted';
                target.innerHTML = `<strong>${escapeHtml(t('进度流状态', 'Progress stream status'))}</strong><p>${escapeHtml(message)}</p>`;
                target.setAttribute('data-copy', message);
              }
              renderOperatorCockpit();
              startRunbookProgressPolling();
              startBackgroundStatusPolling();
            }

            function setProgressStreamStatus(message) {
              const target = document.getElementById('backgroundStatus');
              if (!target || !message || lastBackgroundSnapshot) { return; }
              target.className = 'metric muted';
              target.innerHTML = `<strong>${escapeHtml(t('进度流状态', 'Progress stream status'))}</strong><p>${escapeHtml(message)}</p>`;
              target.setAttribute('data-copy', message);
            }

            function startRunbookProgressPolling() {
              refreshRunbookProgress();
              if (progressTimer) { clearInterval(progressTimer); }
              progressTimer = setInterval(refreshRunbookProgress, 1500);
            }

            function stopRunbookProgressPolling() {
              if (progressTimer) { clearInterval(progressTimer); progressTimer = null; }
            }

            async function refreshRunbookProgress() {
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/progress`, { cache: 'no-store' });
                const payload = await requireOk(response, t('分析进度', 'runbook progress'));
                renderRunbookProgress(payload);
                renderOperatorCockpit();
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

            function stopBackgroundStatusPolling() {
              if (backgroundTimer) { clearInterval(backgroundTimer); backgroundTimer = null; }
            }

            function stopRunbookProgressStream() {
              clearProgressStreamFallbackTimer();
              if (progressEventSource) {
                progressEventSource.close();
                progressEventSource = null;
              }
            }

            function clearProgressStreamFallbackTimer() {
              if (progressStreamFallbackTimer) {
                clearTimeout(progressStreamFallbackTimer);
                progressStreamFallbackTimer = null;
              }
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
              const message = localizeServerMessage(snapshot.message || '');
              const job = snapshot.job || {};
              const hasReport = Boolean(job.htmlReportPath || job.htmlReportZhPath || job.htmlReportEnPath);
              const progress = summarizeProgressForStatus(lastProgressSnapshot, state);
              const elapsed = formatDuration(snapshot.duration || snapshot.Duration) || formatElapsedBetween(snapshot.startedAtUtc || snapshot.StartedAtUtc, snapshot.updatedAtUtc || snapshot.UpdatedAtUtc) || '-';
              const currentStep = progress.currentStep || t('等待执行器更新', 'waiting for executor update');
              const reportButtons = hasReport || state === 'completed'
                ? `<p class="actions">
                    <a class="button" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh" target="_blank" rel="noopener">${t('打开中文报告', 'Open Chinese report')}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en" target="_blank" rel="noopener">${t('打开英文报告', 'Open English report')}</a>
                  </p>`
                : '';
              const importMessage = snapshot.guestImportMessage
                ? `<p class="${snapshot.guestImportSucceeded ? 'ok' : 'muted'}" data-copy="${escapeAttr(snapshot.guestImportMessage)}">${escapeHtml(localizeServerMessage(snapshot.guestImportMessage))}</p>`
                : '';
              const outputNotice = `<p class="muted">${escapeHtml(t('实时页不展示命令行、标准输出 stdout 或标准错误 stderr；这里只显示可读进度。需要排障时请打开执行流程或复制 runbook-execution.json 路径。', 'The Live page does not show command lines, stdout, or stderr; it only shows readable progress. For troubleshooting, open Execution flow or copy the runbook-execution.json path.'))}</p>`;
              target.innerHTML = `
                <div class="card-status"><span class="pill ${backgroundStateTone(state)}">${escapeHtml(stateLabel)}</span>
                  <strong>${escapeHtml(snapshot.live ? t('虚拟机分析', 'VM analysis') : t('流程验证', 'flow verification'))}</strong>
                  <span class="percent-label" data-copy="${escapeAttr(progress.percentText)}">${escapeHtml(progress.percentText)}</span></div>
                <div class="progressbar compact" aria-label="${escapeAttr(t('后台执行进度', 'background execution progress'))}"><div class="progressbar-fill ${state === 'failed' ? 'failed' : ''}" style="width:${progress.percent}%"></div></div>
                <p>${t('当前步骤', 'Current step')}：<strong>${escapeHtml(currentStep)}</strong></p>
                <p>${t('已耗时', 'Elapsed')}：<strong>${escapeHtml(elapsed)}</strong></p>
                ${message ? `<p>${escapeHtml(message)}</p>` : ''}
                ${importMessage}
                ${reportButtons}
                ${outputNotice}`;
              target.setAttribute('data-copy', `后台分析 ${stateLabel}; 进度=${progress.percentText}; 当前=${currentStep}; 耗时=${elapsed}; 消息=${message}`);
              renderOperatorCockpit();
              if (autoOpenReportFromMonitor && state === 'completed' && !reportAutoOpenScheduled) {
                scheduleReportAutoOpen();
              }
            }

            function renderExecutionOutputDetails(snapshot) {
              // Inputs: optional terminal background snapshot. Processing:
              // renders captured step stdout/stderr only inside collapsed
              // details after execution has produced a terminal result; command
              // lines remain hidden from this live monitor. Return: HTML.
              const execution = snapshot?.execution || snapshot?.Execution;
              const stepResults = Array.isArray(execution?.stepResults)
                ? execution.stepResults
                : (Array.isArray(execution?.StepResults) ? execution.StepResults : []);
              if (!stepResults.length) { return ''; }

              const stepOutput = stepResults.slice(0, 48).map(result => renderStepOutputDetails(result)).join('');
              return `<details class="output-details">
                <summary>${escapeHtml(t('排障输出（标准输出/标准错误，默认隐藏）', 'Troubleshooting output (stdout/stderr, collapsed by default)'))}</summary>
                <p class="muted">${escapeHtml(t('这些输出来自终端 runbook-execution 结果，仅用于本机排障；命令行仍不在实时页展示。', 'These outputs come from the terminal runbook-execution result for local troubleshooting only; command lines are still not shown on the Live page.'))}</p>
                ${stepOutput}
              </details>`;
            }

            function renderStepOutputDetails(result) {
              const title = result.title || result.Title || result.stepId || result.StepId || t('未命名步骤', 'unnamed step');
              const index = Number(result.stepIndex ?? result.StepIndex ?? 0) + 1;
              const status = Boolean(result.success ?? result.Success)
                ? t('成功', 'success')
                : t('未完成或失败', 'not completed or failed');
              const stdout = String(result.standardOutput ?? result.StandardOutput ?? '');
              const stderr = String(result.standardError ?? result.StandardError ?? '');
              const exitCode = result.exitCode ?? result.ExitCode;
              const duration = formatDuration(result.duration ?? result.Duration) || '-';
              const stdoutHtml = stdout
                ? `<pre data-copy="${escapeAttr(truncateOutputForCopy(stdout))}">${escapeHtml(truncateOutputForDisplay(stdout))}</pre>`
                : `<p class="output-empty">${escapeHtml(t('标准输出 stdout 为空', 'stdout is empty'))}</p>`;
              const stderrHtml = stderr
                ? `<pre data-copy="${escapeAttr(truncateOutputForCopy(stderr))}">${escapeHtml(truncateOutputForDisplay(stderr))}</pre>`
                : `<p class="output-empty">${escapeHtml(t('标准错误 stderr 为空', 'stderr is empty'))}</p>`;
              return `<details class="step-output-details">
                <summary data-copy="${escapeAttr(`${index}. ${title} ${status}`)}">${escapeHtml(`${index}. ${title}`)} <span class="pill">${escapeHtml(status)}</span></summary>
                <p class="muted" data-copy="${escapeAttr(`退出码=${exitCode ?? '-'}; 耗时=${duration}`)}">退出码=${escapeHtml(exitCode ?? '-')} · ${escapeHtml(duration)}</p>
                <details><summary>${escapeHtml(t('标准输出 stdout', 'stdout'))}</summary>${stdoutHtml}</details>
                <details><summary>${escapeHtml(t('标准错误 stderr', 'stderr'))}</summary>${stderrHtml}</details>
              </details>`;
            }

            function truncateOutputForDisplay(value) {
              const text = String(value || '');
              const max = 12000;
              return text.length > max
                ? `${text.slice(0, max)}\n… ${t(`已隐藏 ${text.length - max} 个字符`, `${text.length - max} more characters hidden`)} …`
                : text;
            }

            function truncateOutputForCopy(value) {
              const text = String(value || '');
              const max = 12000;
              return text.length > max ? text.slice(0, max) : text;
            }

            function scheduleReportAutoOpen() {
              reportAutoOpenScheduled = true;
              const href = `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh`;
              reportAutoOpenHref = href;
              reportAutoOpenDeadline = Date.now() + 5000;
              updateReportAutoOpenNotice();
              if (reportAutoOpenTimer) { clearInterval(reportAutoOpenTimer); }
              reportAutoOpenTimer = setInterval(updateReportAutoOpenNotice, 250);
              setTimeout(() => {
                if (reportAutoOpenTimer) {
                  clearInterval(reportAutoOpenTimer);
                  reportAutoOpenTimer = null;
                }
                window.location.href = href;
              }, 5000);
            }

            function updateReportAutoOpenNotice() {
              const href = reportAutoOpenHref || `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh`;
              const remaining = Math.max(0, Math.ceil(((reportAutoOpenDeadline || Date.now()) - Date.now()) / 1000));
              reportAutoOpenRemainingSeconds = remaining;
              const countdown = t(`${remaining} 秒后自动跳转`, `auto-open in ${remaining}s`);
              const target = document.getElementById('reportReadyActions');
              if (target) {
                target.className = 'report-ready ok';
                target.innerHTML = `<strong>${escapeHtml(t('报告已生成，正在准备自动打开中文报告 report.zh.html。', 'Report is ready and preparing to open the Chinese report (report.zh.html).'))}</strong>
                  <p class="countdown" data-copy="${escapeAttr(countdown)}">${escapeHtml(countdown)}</p>
                  <div class="artifact-action">
                    <a class="button" href="${escapeAttr(href)}">${escapeHtml(t('立即打开中文报告', 'Open Chinese report now'))}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh" target="_blank" rel="noopener">${escapeHtml(t('中文报告', 'Chinese report'))}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en" target="_blank" rel="noopener">${escapeHtml(t('英文报告', 'English report'))}</a>
                  </div>`;
                target.setAttribute('data-copy', `${href} ${countdown}`);
              }
              setStatus(t(`报告已生成，页面将在 ${remaining} 秒后跳转到中文报告 report.zh.html；如果没有跳转，请点击立即打开中文报告。`, `Report is ready; this page will navigate to report.zh.html in ${remaining}s. If it does not, click Open Chinese report now.`), false);
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

            function backgroundStateTone(state) {
              switch (String(state || '').toLowerCase()) {
                case 'completed': return 'ready';
                case 'failed': return 'failed';
                case 'quiet': return 'quiet';
                case 'queued':
                case 'running': return 'endpoint';
                default: return 'waiting';
              }
            }

            function summarizeProgressForStatus(snapshot, backgroundState) {
              const state = String(backgroundState || snapshot?.state || '').toLowerCase();
              const percent = state === 'completed'
                ? 100
                : state === 'failed'
                  ? progressPercent(snapshot || {})
                  : Math.max(state === 'running' ? 5 : 0, progressPercent(snapshot || {}));
              const currentStep = snapshot?.currentStepTitle ||
                currentStepFromSnapshot(snapshot) ||
                (state === 'queued' ? t('后台任务已排队', 'background task queued') : '');
              return {
                percent,
                percentText: `${percent}%`,
                currentStep
              };
            }

            function currentStepFromSnapshot(snapshot) {
              const info = currentStepInfoFromSnapshot(snapshot);
              return info ? info.title : '';
            }

            function formatElapsedBetween(start, end) {
              const started = Date.parse(start || '');
              const updated = Date.parse(end || '');
              if (!Number.isFinite(started)) { return ''; }
              const finish = Number.isFinite(updated) ? updated : Date.now();
              const seconds = Math.max(0, Math.round((finish - started) / 1000));
              if (seconds < 60) { return `${seconds}s`; }
              const minutes = Math.floor(seconds / 60);
              const rest = seconds % 60;
              if (minutes < 60) { return `${minutes}m ${rest}s`; }
              const hours = Math.floor(minutes / 60);
              return `${hours}h ${minutes % 60}m`;
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
                status: raw.status == null ? '' : raw.status,
                submission: normalizeSubmission(raw.submission || raw.Submission || {})
              };
            }

            function normalizeSubmission(submission) {
              submission = submission || {};
              return {
                collectDroppedFiles: Boolean(submission.collectDroppedFiles ?? submission.CollectDroppedFiles),
                captureScreenshots: Boolean(submission.captureScreenshots ?? submission.CaptureScreenshots),
                captureMemoryDumps: Boolean(submission.captureMemoryDumps ?? submission.CaptureMemoryDumps),
                capturePacketCapture: Boolean(submission.capturePacketCapture ?? submission.CapturePacketCapture)
              };
            }

            function renderOperatorOptions(job) {
              const target = document.getElementById('operatorOptions');
              if (!target) { return; }
              const submission = normalizeSubmission(job?.submission || job?.Submission || {});
              const options = [
                ['collectDroppedFiles', submission.collectDroppedFiles, t('落地文件', 'Dropped files'), t('采集运行期间新增/修改的文件。', 'Collect files created/modified during execution.')],
                ['captureScreenshots', submission.captureScreenshots, t('截图', 'Screenshots'), t('采集运行窗口或桌面截图。', 'Capture run-window or desktop screenshots.')],
                ['captureMemoryDumps', submission.captureMemoryDumps, t('内存转储（含子进程，若支持）', 'Memory dumps (children if supported)'), t('转储样本进程；Guest Agent 支持时包含已解析子进程。', 'Dump the sample process; includes resolved child processes when the Guest Agent supports it.')],
                ['capturePacketCapture', submission.capturePacketCapture, t('PCAP 抓包', 'PCAP packet capture'), t('采集网络包为 PCAP/PCAPNG 证据。', 'Collect network packets as PCAP/PCAPNG evidence.')]
              ];
              const copy = options.map(option => `${option[2]}=${option[1] ? t('已启用', 'on') : t('未启用', 'off')}`).join(' | ');
              target.setAttribute('data-copy', copy);
              target.innerHTML = options.map(option => {
                const enabled = Boolean(option[1]);
                const state = enabled ? t('已启用', 'enabled') : t('未启用', 'disabled');
                return `<div class="metric" data-copy="${escapeAttr(`${option[2]}: ${state}; ${option[3]}`)}"><strong>${escapeHtml(option[2])}</strong><span class="pill ${enabled ? 'ready' : 'waiting'}">${escapeHtml(state)}</span><p class="muted">${escapeHtml(option[3])}</p></div>`;
              }).join('');
            }

            function renderOperatorCockpit() {
              const target = document.getElementById('operatorCockpit');
              if (!target) { return; }
              const cards = [
                renderRunbookCockpitCard(),
                renderVirusTotalCockpitCard(),
                renderArtifactCockpitCard(),
                renderReportCockpitCard()
              ];
              target.innerHTML = cards.map(card => card.html).join('');
              target.setAttribute('data-copy', cards.map(card => card.copy).filter(Boolean).join(' | '));
            }

            function renderRunbookCockpitCard() {
              const snapshot = lastProgressSnapshot || {};
              const streamStep = lastProgressStreamEnvelope?.currentStep || null;
              const currentInfo = normalizeRunbookStepInfo(streamStep, snapshot) || currentStepInfoFromSnapshot(snapshot);
              const rawState = lastProgressStreamEnvelope?.state || String(snapshot.state || 'pending').toLowerCase();
              const stateLabel = localizeServerStatus(rawState) || formatProgressState(rawState);
              const percent = lastProgressStreamEnvelope?.progressPercent ?? progressPercent(snapshot);
              const stepTitle = currentInfo?.title || (rawState === 'completed' ? t('所有步骤已完成', 'all steps completed') : t('等待真实步骤快照', 'waiting for real step snapshot'));
              const stepState = currentInfo?.state ? formatProgressState(currentInfo.state) : stateLabel;
              const ordinal = currentInfo?.ordinalText || t('步骤序号待定', 'step ordinal pending');
              const transport = progressStreamLabel();
              const updatedAt = lastProgressStreamEnvelope?.generatedAtUtc || snapshot.updatedAtUtc || snapshot.UpdatedAtUtc || '';
              const tone = rawState === 'completed' ? 'ready' : (rawState === 'failed' || rawState === 'canceled' ? 'failed' : (progressStreamMode === 'sse' ? 'endpoint' : 'waiting'));
              const copy = `${t('当前真实步骤', 'Current real step')}=${stepTitle}; ${t('状态', 'state')}=${stepState}; ${t('进度', 'progress')}=${percent}%; ${transport}; ${updatedAt}`;
              return {
                copy,
                html: `<article class="cockpit-card ${tone}" data-copy="${escapeAttr(copy)}">
                  <h3>${escapeHtml(t('当前真实步骤', 'Current real step'))}</h3>
                  <p class="cockpit-main">${escapeHtml(stepTitle)}</p>
                  <div class="cockpit-meta">
                    <span class="pill ${tone}" data-copy="${escapeAttr(stateLabel)}">${escapeHtml(stateLabel)}</span>
                    <span class="pill endpoint" data-copy="${escapeAttr(ordinal)}">${escapeHtml(ordinal)}</span>
                    <span class="pill quiet" data-copy="${escapeAttr(transport)}">${escapeHtml(transport)}</span>
                    <span class="pill" data-copy="${escapeAttr(String(percent))}">${escapeHtml(`${percent}%`)}</span>
                    ${cockpitCopyButton(copy)}
                  </div>
                  <p class="muted">${escapeHtml(t('优先取 progress stream 的 currentStep；退化时才用轮询快照。', 'Prefers progress stream currentStep; falls back to polling snapshots only when needed.'))}</p>
                </article>`
              };
            }

            function renderVirusTotalCockpitCard() {
              const result = lastVirusTotalResult;
              if (!result) {
                const copy = t('VirusTotal 等待查询；默认不上传样本，不写任务/行为日志噪音。', 'VirusTotal waiting; no sample upload and no job/behavior-log noise by default.');
                return {
                  copy,
                  html: `<article class="cockpit-card waiting" data-copy="${escapeAttr(copy)}">
                    <h3>VirusTotal</h3>
                    <p class="cockpit-main">${escapeHtml(t('等待 SHA-256 查询', 'waiting for SHA-256 lookup'))}</p>
                    <div class="cockpit-meta"><span class="pill quiet">${escapeHtml(t('默认不写日志噪音', 'no log noise by default'))}</span></div>
                  </article>`
                };
              }

              const status = normalizeVirusTotalStatus(result);
              const workflow = virusTotalWorkflowState(result);
              const tone = virusTotalStatusPillTone(status, result);
              const malicious = vtNumber(vtValue(result, 'maliciousCount'), vtValue(vtValue(result, 'engineCounts'), 'malicious'));
              const suspicious = vtNumber(vtValue(result, 'suspiciousCount'), vtValue(vtValue(result, 'engineCounts'), 'suspicious'));
              const communityVotes = vtValue(result, 'communityVotes') || {};
              const community = virusTotalCommunityCopy(result, communityVotes);
              const permalink = vtValue(result, 'detectionPermalink') || vtValue(result, 'permalink') || '';
              const policy = virusTotalPolicyText(vtValue(result, 'liveLogPolicy'));
              const operatorState = virusTotalOperatorStateText(status, result, malicious, suspicious);
              const headline = status === 'found'
                ? t(`命中 ${malicious + suspicious} / 官方已收录`, `${malicious + suspicious} detections / found`)
                : operatorState;
              const copy = `VirusTotal ${status}; ${headline}; ${operatorState}; ${community}; permalink=${permalink || 'n/a'}; policy=${policy}`;
              return {
                copy,
                html: `<article class="cockpit-card ${tone}" data-copy="${escapeAttr(copy)}">
                  <h3>VirusTotal</h3>
                  <p class="cockpit-main">${escapeHtml(headline)}</p>
                  <div class="cockpit-meta">
                    <span class="pill ${tone}" data-copy="${escapeAttr(status)}">${escapeHtml(virusTotalStatusLabel(status, result))}</span>
                    <span class="pill quiet" data-copy="${escapeAttr(policy)}">${escapeHtml(t('默认不写日志噪音', 'no log noise by default'))}</span>
                    <span class="pill ${permalink ? 'endpoint' : 'waiting'}" data-copy="${escapeAttr(permalink || t('官方链接未提供', 'official permalink not provided'))}">${escapeHtml(permalink ? t('官方链接就绪', 'permalink ready') : t('无官方链接', 'no permalink'))}</span>
                    ${cockpitCopyButton(copy)}
                  </div>
                  <p class="muted" data-copy="${escapeAttr(operatorState)}">${escapeHtml(operatorState)}</p>
                  <p class="muted" data-copy="${escapeAttr(community)}">${escapeHtml(community)}</p>
                </article>`
              };
            }

            function renderArtifactCockpitCard() {
              const summary = summarizeArtifactReadiness();
              const tone = summary.readyCount > 0 ? 'ready' : (summary.indexLoaded ? 'waiting' : 'quiet');
              const headline = t(`${summary.readyCount}/${summary.totalCount} 类证据就绪`, `${summary.readyCount}/${summary.totalCount} evidence lanes ready`);
              const copy = `${headline}; indexed=${summary.indexLoaded}; downloadable=${summary.downloadableCount}; rejections=${summary.rejectionCount}`;
              return {
                copy,
                html: `<article class="cockpit-card ${tone}" data-copy="${escapeAttr(copy)}">
                  <h3>${escapeHtml(t('证据就绪', 'Artifact readiness'))}</h3>
                  <p class="cockpit-main">${escapeHtml(headline)}</p>
                  <div class="cockpit-meta">
                    <span class="pill ${summary.indexLoaded ? 'ready' : 'waiting'}">${escapeHtml(summary.indexLoaded ? t('索引已返回', 'index loaded') : t('等待索引', 'waiting index'))}</span>
                    <span class="pill endpoint" data-copy="${escapeAttr(String(summary.downloadableCount))}">${escapeHtml(t(`可下载 ${summary.downloadableCount}`, `${summary.downloadableCount} downloadable`))}</span>
                    <span class="pill ${summary.rejectionCount > 0 ? 'failed' : 'ready'}" data-copy="${escapeAttr(String(summary.rejectionCount))}">${escapeHtml(t(`拒绝 ${summary.rejectionCount}`, `${summary.rejectionCount} rejected`))}</span>
                    ${cockpitCopyButton(copy)}
                  </div>
                  <p class="muted">${escapeHtml(t('摘要来自 artifact index 与采集信号；详细 selector 在下方卡片展开。', 'Summary comes from artifact index and collection signals; detailed selectors expand in cards below.'))}</p>
                </article>`
              };
            }

            function renderReportCockpitCard() {
              const terminal = isRunTerminal();
              const job = normalizeJobSnapshot(latestJobSnapshot || initialJob);
              const hasReport = terminal || Boolean(job.htmlReportPath || job.htmlReportZhPath || job.htmlReportEnPath || job.jsonReportPath);
              const tone = hasReport ? 'ready' : 'waiting';
              const headline = hasReport ? t('报告入口可用', 'report entry ready') : t('等待报告生成', 'waiting for report');
              const copy = `${headline}; zh=/api/jobs/${jobId}/report/html?lang=zh; en=/api/jobs/${jobId}/report/html?lang=en`;
              return {
                copy,
                html: `<article class="cockpit-card ${tone}" data-copy="${escapeAttr(copy)}">
                  <h3>${escapeHtml(t('报告入口', 'Report entry'))}</h3>
                  <p class="cockpit-main">${escapeHtml(headline)}</p>
                  <div class="cockpit-meta">
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh" target="_blank" rel="noopener">${escapeHtml(t('中文报告', 'Chinese report'))}</a>
                    <a class="button secondary" href="/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en" target="_blank" rel="noopener">${escapeHtml(t('英文报告', 'English report'))}</a>
                    ${cockpitCopyButton(copy)}
                  </div>
                </article>`
              };
            }

            function cockpitCopyButton(copy) {
              return `<button class="secondary" type="button" data-copy="${escapeAttr(copy)}" onclick="copyText(this.getAttribute('data-copy'))">${escapeHtml(t('复制卡片', 'Copy card'))}</button>`;
            }

            function summarizeArtifactReadiness() {
              const rows = Array.isArray(latestArtifactRows) ? latestArtifactRows : [];
              const index = latestArtifactIndex || {};
              const artifacts = artifactArray(index, 'artifacts', 'Artifacts');
              const collections = artifactArray(index, 'collections', 'Collections');
              const readyCount = rows.filter(row => row && row.ready).length;
              const totalCount = rows.length || 8;
              const downloadableCount = artifacts.filter(artifact => {
                const download = artifactDownloadInfo(artifact);
                const selectors = artifactSelectorInfo(artifact);
                return Boolean(download.available || download.href || download.selector || selectors.primary);
              }).length;
              const rejectionCount = collections.reduce((count, collection) => count + artifactCollectionRejectedCount(collection), 0);
              return {
                indexLoaded: Boolean(latestArtifactIndex),
                readyCount,
                totalCount,
                downloadableCount,
                rejectionCount
              };
            }

            function progressStreamLabel() {
              if (lastProgressStreamEnvelope?.transport) {
                const eventName = lastProgressStreamEnvelope.eventName || 'snapshot';
                return t(`SSE 真实流 / ${eventName}`, `SSE real stream / ${eventName}`);
              }

              if (progressStreamMode === 'connecting') {
                return t('正在连接真实进度流', 'connecting real progress stream');
              }

              if (progressStreamMode === 'poll') {
                return t('安全轮询兜底', 'safe polling fallback');
              }

              return t('等待进度流', 'waiting for progress stream');
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

            async function refreshArtifactCardsNow() {
              setStatus(t('正在刷新证据/下载卡片...', 'Refreshing artifact/download cards...'), false);
              await refreshArtifactIndex(true);
              renderArtifactPanel();
              const summary = summarizeArtifactReadiness();
              setStatus(
                t(`证据/下载卡片已刷新：${summary.readyCount}/${summary.totalCount} 类就绪，可下载 ${summary.downloadableCount} 项。`, `Artifact/download cards refreshed: ${summary.readyCount}/${summary.totalCount} lanes ready, ${summary.downloadableCount} downloadable.`),
                false);
            }

            function renderArtifactPanel() {
              const body = document.getElementById('artifactCards');
              if (!body) { return; }
              latestJobSnapshot = normalizeJobSnapshot(latestJobSnapshot || initialJob);
              const paths = buildArtifactPaths(latestJobSnapshot, latestArtifactSources);
              const rows = buildIndexedArtifactRows(paths);
              latestArtifactRows = rows;
              body.innerHTML = renderArtifactIndexSummary() + renderArtifactGroups(rows);
              renderReportReadyActions(paths);
              renderOperatorCockpit();
            }

            function renderArtifactIndexSummary() {
              const index = latestArtifactIndex || {};
              const artifacts = artifactArray(index, 'artifacts', 'Artifacts');
              const collections = artifactArray(index, 'collections', 'Collections');
              if (!latestArtifactIndex) {
                return `<article class="artifact-card waiting muted" data-copy="${escapeAttr(t('证据索引尚未返回；等待 Web Host 构建 artifact index。', 'Artifact index has not returned yet; waiting for the Web host to build it.'))}">
                  <div class="artifact-card-title">
                    <strong data-copy="${escapeAttr(t('证据索引状态', 'Artifact index status'))}">${escapeHtml(t('证据索引状态', 'Artifact index status'))}</strong>
                    <span class="pill waiting">${escapeHtml(t('等待索引', 'waiting for index'))}</span>
                  </div>
                  <p class="muted">${escapeHtml(t('尚未拿到 /api/jobs/{jobId}/artifacts 响应；下方仍会显示可推断的报告与采集路径。', 'No /api/jobs/{jobId}/artifacts response yet; inferred report and collection paths are still shown below.'))}</p>
                </article>`;
              }

              const generatedAt = artifactField(index, 'generatedAtUtc', 'GeneratedAtUtc');
              const producer = artifactField(index, 'producer', 'Producer');
              const rootPolicy = artifactField(index, 'rootPathPolicy', 'RootPathPolicy') || 'server-owned-not-exposed';
              const rejectionCount = collections.reduce((count, collection) => count + artifactCollectionRejectedCount(collection), 0);
              const copy = [
                t('证据索引已加载', 'Artifact index loaded'),
                `${t('文件', 'artifacts')}=${artifacts.length}`,
                `${t('采集项', 'collections')}=${collections.length}`,
                `${t('拒绝诊断', 'rejections')}=${rejectionCount}`,
                `policy=${rootPolicy}`,
                generatedAt || ''
              ].filter(Boolean).join(' | ');
              return `<article class="artifact-card ready" data-copy="${escapeAttr(copy)}">
                <div class="artifact-card-title">
                  <strong data-copy="${escapeAttr(t('证据索引已加载', 'Artifact index loaded'))}">${escapeHtml(t('证据索引已加载', 'Artifact index loaded'))}</strong>
                  <span class="pill ready" data-copy="${escapeAttr(`${artifacts.length} artifacts / ${collections.length} collections`)}">${escapeHtml(t(`${artifacts.length} 个文件`, `${artifacts.length} artifacts`))}</span>
                </div>
                <div class="artifact-chip-row">
                  <span class="pill" data-copy="${escapeAttr(rootPolicy)}">${escapeHtml(t('根路径不暴露', 'root not exposed'))}</span>
                  <span class="pill ${rejectionCount > 0 ? 'failed' : 'ready'}" data-copy="${escapeAttr(String(rejectionCount))}">${escapeHtml(t(`拒绝诊断 ${rejectionCount}`, `rejection diagnostics ${rejectionCount}`))}</span>
                  ${generatedAt ? `<span class="pill quiet" data-copy="${escapeAttr(generatedAt)}">${escapeHtml(generatedAt)}</span>` : ''}
                </div>
                <p class="muted">${escapeHtml(t('下载只接受 artifact index 中的相对 selector；本页不会复制或打开 host 绝对路径。', 'Downloads only accept relative selectors from the artifact index; this page does not copy or open host absolute paths.'))}</p>
                <div class="artifact-kv-grid">
                  ${artifactKeyValue(t('Selector 策略', 'Selector policy'), 'relative-index-selectors-only')}
                  ${artifactKeyValue(t('RootPathPolicy', 'RootPathPolicy'), rootPolicy)}
                  ${producer ? artifactKeyValue(t('索引生成器', 'Producer'), producer) : ''}
                </div>
                ${renderCollectionRejectionDiagnostics(collections)}
              </article>`;
            }

            function renderArtifactGroups(cards) {
              cards = Array.isArray(cards) ? cards : [];
              if (!cards.length) {
                return `<article class="artifact-card waiting muted" data-copy="证据路径解析中 / artifacts pending">${escapeHtml(t('正在解析证据（artifact）路径。', 'Resolving artifact paths.'))}</article>`;
              }

              const order = ['reports', 'telemetry', 'execution', 'files', 'screenshots', 'memory', 'network', 'other'];
              const groups = new Map();
              for (const card of cards) {
                const key = card.groupKey || 'other';
                if (!groups.has(key)) {
                  groups.set(key, {
                    key,
                    label: card.groupLabel || artifactGroupLabel(key),
                    cards: []
                  });
                }
                groups.get(key).cards.push(card);
              }

              return [...groups.values()]
                .sort((a, b) => groupOrderIndex(order, a.key) - groupOrderIndex(order, b.key))
                .map(group => {
                  const readyCount = group.cards.filter(card => card.ready).length;
                  const countText = t(`${readyCount}/${group.cards.length} 项就绪`, `${readyCount}/${group.cards.length} ready`);
                  return `<article class="artifact-group" data-copy="${escapeAttr(`${group.label}: ${countText}`)}">
                    <div class="artifact-group-title">
                      <h3>${escapeHtml(group.label)}</h3>
                      <span class="pill ${readyCount > 0 ? 'ready' : 'waiting'}">${escapeHtml(countText)}</span>
                    </div>
                    <div class="artifact-card-grid">${group.cards.map(card => card.html).join('')}</div>
                  </article>`;
                })
                .join('');
            }

            function groupOrderIndex(order, key) {
              const index = order.indexOf(key);
              return index < 0 ? order.length : index;
            }

            function artifactGroupLabel(key) {
              const labels = {
                reports: t('报告', 'Reports'),
                telemetry: t('事件与遥测', 'Events and telemetry'),
                execution: t('执行记录', 'Execution records'),
                files: t('文件证据', 'File evidence'),
                screenshots: t('截图', 'Screenshots'),
                memory: t('内存转储', 'Memory dumps'),
                network: t('网络抓包', 'Network captures'),
                other: t('其他证据', 'Other evidence')
              };
              return labels[key] || labels.other;
            }

            function buildIndexedArtifactRows(paths) {
              const artifacts = Array.isArray(latestArtifactIndex?.artifacts) ? latestArtifactIndex.artifacts : [];
              const rows = [];
              const seen = new Set();
              const reportReady = paths.hasAnyReport || isRunTerminal();
              const reportHtmlArtifact = findArtifact(artifacts, artifact => fileNameEquals(artifactPath(artifact), 'report.html') || fileNameEquals(artifact.name || artifact.Name, 'report.html'));
              const zhReportArtifact = findArtifact(artifacts, artifact => fileNameEquals(artifactPath(artifact), 'report.zh.html') || fileNameEquals(artifact.name || artifact.Name, 'report.zh.html'));
              const enReportArtifact = findArtifact(artifacts, artifact => fileNameEquals(artifactPath(artifact), 'report.en.html') || fileNameEquals(artifact.name || artifact.Name, 'report.en.html'));
              const jsonReportArtifact = findArtifact(artifacts, artifact => fileNameEquals(artifactPath(artifact), 'report.json') || fileNameEquals(artifact.name || artifact.Name, 'report.json'));
              const eventsArtifact = findArtifact(artifacts, artifact => fileNameEquals(artifactPath(artifact), 'events.json') || fileNameEquals(artifact.name || artifact.Name, 'events.json'));
              const driverArtifact = findArtifact(artifacts, artifact => fileNameEquals(artifactPath(artifact), 'driver-events.jsonl') || fileNameEquals(artifact.name || artifact.Name, 'driver-events.jsonl'));
              const runbookArtifact = findArtifact(artifacts, artifact => fileNameEquals(artifactPath(artifact), 'runbook-execution.json') || fileNameEquals(artifact.name || artifact.Name, 'runbook-execution.json'));
              const droppedArtifact = findArtifact(artifacts, artifact => artifactMatches(artifact, 'dropped-file', 'dropped-files'));
              const screenshotArtifact = findArtifact(artifacts, artifact => artifactMatches(artifact, 'screenshot', 'screenshots'));
              const dumpArtifact = findArtifact(artifacts, artifact => artifactMatches(artifact, 'memory-dump', 'memory-dumps'));
              const pcapArtifact = findArtifact(artifacts, artifact => artifactMatches(artifact, 'packet-capture', 'packet-captures') || isPacketCapturePath(artifactPath(artifact)));

              pushArtifactCard(rows, seen, t('默认 HTML 报告', 'Default HTML report'), 'report.html', artifactPath(reportHtmlArtifact) || paths.reportHtmlPath, `/api/jobs/${encodeURIComponent(jobId)}/report/html`, reportReady || Boolean(reportHtmlArtifact), t('兼容报告端点（endpoint）', 'compatibility report endpoint'), reportHtmlArtifact);
              pushArtifactCard(rows, seen, t('中文报告', 'Chinese report'), 'report.zh.html', artifactPath(zhReportArtifact) || paths.zhReportPath, `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=zh`, reportReady || Boolean(zhReportArtifact), t('打开 report.zh.html', 'opens report.zh.html'), zhReportArtifact);
              pushArtifactCard(rows, seen, t('英文报告', 'English report'), 'report.en.html', artifactPath(enReportArtifact) || paths.enReportPath, `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=en`, reportReady || Boolean(enReportArtifact), t('打开 report.en.html', 'opens report.en.html'), enReportArtifact);
              pushArtifactCard(rows, seen, t('JSON 报告', 'JSON report'), 'report.json', artifactPath(jsonReportArtifact) || paths.reportJsonPath, artifactDownloadHref(jsonReportArtifact), Boolean(jsonReportArtifact || paths.reportJsonPath), jsonReportArtifact ? artifactDetail(jsonReportArtifact, t('已索引，可下载', 'indexed and downloadable')) : t('等待证据索引（artifact index）下载链接', 'waiting for artifact-index download link'), jsonReportArtifact);
              pushArtifactCard(rows, seen, 'events.json', 'events.json', artifactPath(eventsArtifact) || paths.eventsJsonPath, artifactDownloadHref(eventsArtifact), Boolean(eventsArtifact || paths.eventsCollected), eventsArtifact ? artifactDetail(eventsArtifact, t('已索引，可下载', 'indexed and downloadable')) : (paths.eventsCollected ? t('已记录事件来源', 'event source recorded') : t('等待回收', 'waiting for collection')), eventsArtifact);
              pushArtifactCard(rows, seen, 'driver-events.jsonl', 'driver-events.jsonl', artifactPath(driverArtifact) || paths.driverEventsJsonlPath, artifactDownloadHref(driverArtifact), Boolean(driverArtifact || paths.driverCollected), driverArtifact ? artifactDetail(driverArtifact, t('已索引，可下载', 'indexed and downloadable')) : (paths.driverCollected ? t('已发现驱动遥测', 'driver telemetry found') : t('等待回收', 'waiting for collection')), driverArtifact);
              pushArtifactCard(rows, seen, t('执行记录', 'Runbook execution'), 'runbook-execution.json', artifactPath(runbookArtifact) || paths.runbookExecutionPath, artifactDownloadHref(runbookArtifact), Boolean(runbookArtifact || paths.runbookExecutionPath), runbookArtifact ? artifactDetail(runbookArtifact, t('已索引，可下载', 'indexed and downloadable')) : t('执行后生成', 'expected after execution'), runbookArtifact);
              pushArtifactCard(rows, seen, t('落地文件', 'Dropped files'), 'artifacts/dropped-files', artifactPath(droppedArtifact) || paths.droppedFilesPath, artifactDownloadHref(droppedArtifact), Boolean(droppedArtifact || latestArtifactSignals.droppedFiles), droppedArtifact ? artifactDetail(droppedArtifact, t('已索引，可下载', 'indexed and downloadable')) : (latestArtifactSignals.droppedFiles ? t('事件中已出现落地文件证据', 'dropped-file evidence observed in events') : t('等待回收', 'waiting for collection')), droppedArtifact);
              pushArtifactCard(rows, seen, t('截图', 'Screenshots'), 'screenshots', artifactPath(screenshotArtifact) || paths.screenshotsPath, artifactDownloadHref(screenshotArtifact), Boolean(screenshotArtifact || latestArtifactSignals.screenshots), screenshotArtifact ? artifactDetail(screenshotArtifact, t('已索引，可下载', 'indexed and downloadable')) : (latestArtifactSignals.screenshots ? t('事件中已出现截图证据', 'screenshot evidence observed in events') : t('等待回收', 'waiting for collection')), screenshotArtifact);
              pushArtifactCard(rows, seen, t('内存转储', 'Memory dumps'), 'memory-dumps', artifactPath(dumpArtifact) || paths.memoryDumpsPath, artifactDownloadHref(dumpArtifact), Boolean(dumpArtifact || latestArtifactSignals.memoryDumps), dumpArtifact ? artifactDetail(dumpArtifact, t('已索引，可下载', 'indexed and downloadable')) : (latestArtifactSignals.memoryDumps ? t('事件中已出现内存转储证据', 'memory-dump evidence observed in events') : t('等待回收', 'waiting for collection')), dumpArtifact);
              pushArtifactCard(rows, seen, t('PCAP 抓包', 'PCAP captures'), 'packet-captures', artifactPath(pcapArtifact) || paths.packetCapturePath, artifactDownloadHref(pcapArtifact), Boolean(pcapArtifact || paths.pcapCollected || latestArtifactSignals.packetCaptures), pcapArtifact ? artifactDetail(pcapArtifact, t('已索引，可下载', 'indexed and downloadable')) : (paths.pcapCollected || latestArtifactSignals.packetCaptures ? t('已发现 PCAP/PCAPNG 证据', 'PCAP/PCAPNG evidence found') : t('等待回收', 'waiting for collection')), pcapArtifact);

              if (artifacts.length > 0) {
                const sorted = [...artifacts].sort((a, b) => artifactRank(a) - artifactRank(b) || artifactPath(a).localeCompare(artifactPath(b)));
                for (const artifact of sorted.slice(0, 80)) {
                  const label = artifactLabel(artifact);
                  const type = artifactTypeText(artifact);
                  const path = artifactPath(artifact);
                  pushArtifactCard(rows, seen, label, type, path, artifactDownloadHref(artifact), Boolean(artifactDownloadHref(artifact) || path), artifactDetail(artifact, t('已索引', 'indexed')), artifact);
                }
              }

              return rows;
            }

            function pushArtifactCard(rows, seen, displayName, fileName, path, href, ready, detail, artifact) {
              const key = artifactCardKey(displayName, fileName, path);
              if (seen.has(key)) { return; }
              seen.add(key);
              const groupKey = artifactGroupKey(displayName, fileName, path);
              rows.push({
                groupKey,
                groupLabel: artifactGroupLabel(groupKey),
                ready: Boolean(ready),
                html: artifactRow(displayName, fileName, path, href, ready, detail, artifact)
              });
            }

            function artifactGroupKey(displayName, fileName, path) {
              const text = `${displayName || ''} ${fileName || ''} ${path || ''}`.toLowerCase();
              if (text.includes('report') || text.includes('报告')) { return 'reports'; }
              if (text.includes('events.json') || text.includes('driver-events') || text.includes('telemetry') || text.includes('遥测')) { return 'telemetry'; }
              if (text.includes('runbook') || text.includes('execution') || text.includes('执行')) { return 'execution'; }
              if (text.includes('dropped') || text.includes('落地')) { return 'files'; }
              if (text.includes('screenshot') || text.includes('截图')) { return 'screenshots'; }
              if (text.includes('memory-dump') || text.includes('memory dump') || text.includes('内存')) { return 'memory'; }
              if (text.includes('packet') || text.includes('pcap') || text.includes('network') || text.includes('抓包')) { return 'network'; }
              return 'other';
            }

            function artifactCardKey(displayName, fileName, path) {
              return String(path || `${displayName}|${fileName}`).replace(/\\/g, '/').toLowerCase();
            }

            function findArtifact(artifacts, predicate) {
              return (artifacts || []).find(artifact => {
                try { return predicate(artifact || {}); } catch { return false; }
              }) || null;
            }

            function artifactArray(source, ...names) {
              const value = artifactField(source, ...names);
              return Array.isArray(value) ? value : [];
            }

            function artifactField(source, ...names) {
              if (!source || typeof source !== 'object') { return ''; }
              for (const name of names) {
                if (Object.prototype.hasOwnProperty.call(source, name)) { return source[name]; }
              }

              const lookup = new Map(Object.keys(source).map(key => [key.toLowerCase(), key]));
              for (const name of names) {
                const key = lookup.get(String(name).toLowerCase());
                if (key !== undefined) { return source[key]; }
              }

              return '';
            }

            function artifactObject(source, ...names) {
              const value = artifactField(source, ...names);
              return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
            }

            function artifactString(value) {
              if (value === null || value === undefined) { return ''; }
              return String(value).trim();
            }

            function artifactBool(value) {
              if (typeof value === 'boolean') { return value; }
              if (typeof value === 'number') { return value !== 0; }
              const text = artifactString(value).toLowerCase();
              return text === 'true' || text === '1' || text === 'yes' || text === 'y';
            }

            function firstArtifactText(...values) {
              for (const value of values) {
                const text = artifactString(value);
                if (text) { return text; }
              }
              return '';
            }

            function artifactMetadata(artifact) {
              return artifactObject(artifact, 'metadata', 'Metadata');
            }

            function artifactKeyValue(label, value, extraClass) {
              const text = artifactString(value);
              if (!text) { return ''; }
              const copy = `${label}: ${text}`;
              return `<div class="artifact-kv ${extraClass || ''}" data-copy="${escapeAttr(copy)}"><span>${escapeHtml(label)}</span><code data-copy="${escapeAttr(text)}">${escapeHtml(text)}</code></div>`;
            }

            function artifactDownloadHref(artifact) {
              const download = artifactDownloadInfo(artifact);
              return download.href || firstArtifactText(artifactField(artifact, 'downloadHref', 'DownloadHref'));
            }

            function artifactDetail(artifact, fallback) {
              if (!artifact) { return fallback || ''; }
              const download = artifactDownloadInfo(artifact);
              const sha256 = firstArtifactText(download.sha256, artifactField(artifact, 'sha256', 'Sha256'));
              const selector = download.selector || artifactSelectorInfo(artifact).primary;
              return [
                artifactTypeText(artifact),
                formatBytes(download.sizeBytes || artifactField(artifact, 'sizeBytes', 'SizeBytes')),
                sha256 ? `SHA-256 ${sha256.slice(0, 12)}…` : '',
                selector ? t('安全 selector 已就绪', 'safe selector ready') : ''
              ].filter(Boolean).join(' · ') || fallback || '';
            }

            function artifactDownloadInfo(artifact) {
              const download = artifactObject(artifact, 'download', 'Download');
              const selector = firstArtifactText(
                artifactField(download, 'selector', 'Selector'),
                artifactField(artifact, 'downloadSelector', 'DownloadSelector'));
              const href = firstArtifactText(
                artifactField(download, 'href', 'Href'),
                artifactField(artifact, 'downloadHref', 'DownloadHref'));
              const availableField = artifactField(download, 'available', 'Available');
              const rejectionCode = firstArtifactText(artifactField(download, 'rejectionCode', 'RejectionCode'));
              const rejectionMessage = firstArtifactText(
                artifactField(download, currentLanguage === 'en' ? 'rejectionMessage' : 'rejectionMessageZh', currentLanguage === 'en' ? 'RejectionMessage' : 'RejectionMessageZh'),
                artifactField(download, 'rejectionMessageZh', 'RejectionMessageZh'),
                artifactField(download, 'rejectionMessage', 'RejectionMessage'));
              return {
                available: availableField === '' ? Boolean(selector || href) : artifactBool(availableField),
                selector,
                href,
                fileName: firstArtifactText(artifactField(download, 'fileName', 'FileName')),
                contentType: firstArtifactText(artifactField(download, 'contentType', 'ContentType')),
                sizeBytes: artifactField(download, 'sizeBytes', 'SizeBytes'),
                sha256: firstArtifactText(artifactField(download, 'sha256', 'Sha256')),
                sha256Short: firstArtifactText(artifactField(download, 'sha256Short', 'Sha256Short')),
                rejectionCode,
                rejectionMessage
              };
            }

            function artifactSelectorInfo(artifact) {
              const hasArtifact = artifact && typeof artifact === 'object';
              const selectors = artifactObject(artifact, 'selectors', 'Selectors');
              const relativePath = firstArtifactText(artifactField(selectors, 'relativePath', 'RelativePath'), artifactField(artifact, 'relativePath', 'RelativePath'));
              const safeLink = firstArtifactText(artifactField(selectors, 'safeLink', 'SafeLink'), artifactField(artifact, 'safeLink', 'SafeLink'));
              const importPath = firstArtifactText(artifactField(selectors, 'importPath', 'ImportPath'), artifactField(artifact, 'importPath', 'ImportPath'));
              const policy = firstArtifactText(artifactField(selectors, 'policy', 'Policy'), hasArtifact ? 'relative-index-selectors-only' : '');
              return {
                relativePath,
                safeLink,
                importPath,
                policy,
                primary: firstArtifactText(artifactDownloadInfo(artifact).selector, safeLink, relativePath, importPath)
              };
            }

            function artifactDuplicateInfo(artifact) {
              const duplicate = artifactObject(artifact, 'duplicate', 'Duplicate');
              const metadata = artifactMetadata(artifact);
              const groupCountText = firstArtifactText(artifactField(duplicate, 'groupCount', 'GroupCount'), artifactField(metadata, 'duplicateGroupCount'));
              const groupCount = Number(groupCountText || 0);
              const role = firstArtifactText(artifactField(duplicate, 'role', 'Role'), artifactField(metadata, 'duplicateRole'), 'unique');
              const isDuplicate = artifactBool(firstArtifactText(artifactField(duplicate, 'isDuplicate', 'IsDuplicate'), artifactField(metadata, 'isDuplicate')));
              const primarySelector = firstArtifactText(
                artifactField(duplicate, 'primarySelector', 'PrimarySelector'),
                artifactField(metadata, 'duplicatePrimarySelector'),
                artifactField(metadata, 'duplicatePrimarySafeLink'));
              return {
                role,
                isDuplicate,
                groupKey: firstArtifactText(artifactField(duplicate, 'groupKey', 'GroupKey'), artifactField(metadata, 'duplicateGroupKey')),
                groupId: firstArtifactText(artifactField(duplicate, 'groupId', 'GroupId'), artifactField(metadata, 'duplicateGroupId')),
                groupCountText,
                groupCount: Number.isFinite(groupCount) ? groupCount : 0,
                primarySelector
              };
            }

            function artifactCollectionRejectedCount(collection) {
              const diagnostics = artifactObject(collection, 'rejectionDiagnostics', 'RejectionDiagnostics');
              const count = Number(firstArtifactText(artifactField(diagnostics, 'rejectedArtifactCount', 'RejectedArtifactCount'), artifactField(artifactMetadata(collection), 'rejectedArtifactCount')) || 0);
              return Number.isFinite(count) ? count : 0;
            }

            function renderCollectionRejectionDiagnostics(collections) {
              const cards = [];
              for (const collection of collections || []) {
                const diagnostics = artifactObject(collection, 'rejectionDiagnostics', 'RejectionDiagnostics');
                const count = artifactCollectionRejectedCount(collection);
                const available = artifactBool(artifactField(diagnostics, 'available', 'Available')) || count > 0;
                const reason = firstArtifactText(artifactField(diagnostics, 'lastRejectedReason', 'LastRejectedReason'));
                const selector = firstArtifactText(artifactField(diagnostics, 'lastRejectedSelector', 'LastRejectedSelector'));
                const hint = firstArtifactText(
                  artifactField(diagnostics, currentLanguage === 'en' ? 'hint' : 'zhHint', currentLanguage === 'en' ? 'Hint' : 'ZhHint'),
                  artifactField(diagnostics, 'zhHint', 'ZhHint'));
                if (!available && !reason && !selector && !hint) { continue; }
                const name = firstArtifactText(artifactField(collection, 'name', 'Name'), artifactField(collection, 'category', 'Category'), t('采集项', 'collection'));
                const copy = [name, `${t('拒绝数量', 'rejected')}=${count}`, reason, selector, hint].filter(Boolean).join(' | ');
                cards.push(`<article class="artifact-card artifact-warning" data-copy="${escapeAttr(copy)}">
                  <div class="artifact-card-title">
                    <strong data-copy="${escapeAttr(name)}">${escapeHtml(name)}</strong>
                    <span class="pill failed" data-copy="${escapeAttr(String(count))}">${escapeHtml(t(`拒绝 ${count}`, `${count} rejected`))}</span>
                  </div>
                  <div class="artifact-kv-grid">
                    ${artifactKeyValue(t('最后原因', 'Last reason'), reason || t('未记录原因', 'not recorded'))}
                    ${artifactKeyValue(t('被拒 selector', 'Rejected selector'), selector)}
                    ${artifactKeyValue(t('中文提示', 'Hint'), hint)}
                  </div>
                </article>`);
              }

              if (!cards.length) { return ''; }
              return `<details class="artifact-diagnostics" open data-copy="${escapeAttr(t('存在被拒绝的证据条目；仅展示安全摘要，不暴露 host 路径。', 'Rejected artifact entries exist; only safe summaries are shown, without host paths.'))}">
                <summary>${escapeHtml(t('拒绝诊断 / 被忽略的证据条目', 'Rejection diagnostics / ignored artifacts'))}</summary>
                <div class="artifact-card-grid">${cards.join('')}</div>
              </details>`;
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
              const text = `${artifact.category || artifact.Category || ''} ${artifact.collectionName || artifact.CollectionName || ''} ${artifact.evidenceRole || artifact.EvidenceRole || ''} ${artifact.relativePath || artifact.RelativePath || ''}`.toLowerCase();
              return text.includes(category) || text.includes(collectionName);
            }

            function artifactRank(artifact) {
              const text = `${artifact.category || artifact.Category || ''} ${artifact.collectionName || artifact.CollectionName || ''} ${artifact.relativePath || artifact.RelativePath || ''}`.toLowerCase();
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
              const text = `${artifact.category || artifact.Category || ''} ${artifact.collectionName || artifact.CollectionName || ''} ${artifact.relativePath || artifact.RelativePath || ''}`.toLowerCase();
              if (text.includes('report')) { return t('报告文件', 'Report file'); }
              if (text.includes('driver-events') || text.includes('jsonl')) { return 'driver-events.jsonl'; }
              if (text.includes('events.json')) { return 'events.json'; }
              if (text.includes('dropped-file') || text.includes('dropped-files')) { return t('落地文件', 'Dropped file'); }
              if (text.includes('screenshot')) { return t('截图', 'Screenshot'); }
              if (text.includes('memory-dump') || text.includes('memory-dumps')) { return t('内存转储', 'Memory dump'); }
              if (text.includes('packet-capture') || text.includes('packet-captures') || text.includes('.pcap')) { return t('PCAP 抓包', 'PCAP capture'); }
              if (text.includes('runbook')) { return t('执行记录', 'Runbook record'); }
              return artifact.name || artifact.Name || artifact.category || artifact.Category || t('证据文件', 'Evidence file');
            }

            function localizeArtifactToken(value) {
              const raw = String(value || '').trim();
              if (!raw) { return ''; }
              const key = raw.toLowerCase().replace(/[\s_]+/g, '-');
              const labels = {
                report: t('报告', 'report'),
                reports: t('报告', 'reports'),
                telemetry: t('遥测', 'telemetry'),
                event: t('事件', 'event'),
                events: t('事件', 'events'),
                execution: t('执行', 'execution'),
                runbook: t('执行记录', 'runbook'),
                artifact: t('证据', 'artifact'),
                artifacts: t('证据', 'artifacts'),
                evidence: t('证据', 'evidence'),
                'dropped-file': t('落地文件', 'dropped file'),
                'dropped-files': t('落地文件', 'dropped files'),
                screenshot: t('截图', 'screenshot'),
                screenshots: t('截图', 'screenshots'),
                'memory-dump': t('内存转储', 'memory dump'),
                'memory-dumps': t('内存转储', 'memory dumps'),
                'packet-capture': t('抓包', 'packet capture'),
                'packet-captures': t('抓包', 'packet captures')
              };
              return labels[key] || raw;
            }

            function artifactTypeText(artifact) {
              const category = localizeArtifactToken(artifact.category || artifact.Category || '');
              const collection = localizeArtifactToken(artifact.collectionName || artifact.CollectionName || '');
              const name = artifact.name || artifact.Name || '';
              return [category, collection, name].filter(Boolean).join(' / ') || t('证据文件', 'artifact');
            }

            function artifactPath(artifact) {
              if (!artifact) { return ''; }
              return artifact.relativePath || artifact.RelativePath || artifact.safeLink || artifact.SafeLink || artifact.importPath || artifact.ImportPath || artifact.fullPath || artifact.FullPath || artifact.name || artifact.Name || '';
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
                updateReportAutoOpenNotice();
                return;
              }
              const terminal = isRunTerminal();
              const hasReport = paths.hasAnyReport || terminal;
              const label = terminal
                ? t('运行已结束：可打开中文或英文报告。', 'Run finished: Chinese and English reports are available to open.')
                : t('报告将在计划或运行结束后通过现有端点（endpoint）打开。', 'Reports open through the existing endpoint after planning or run completion.');
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

            function artifactRow(displayName, fileName, path, href, ready, detail, artifact) {
              const hasIndexedArtifact = artifact && typeof artifact === 'object';
              const download = artifactDownloadInfo(artifact);
              const selectors = artifactSelectorInfo(artifact);
              const duplicate = artifactDuplicateInfo(artifact);
              href = href || download.href || '';
              const safeSelector = download.selector || selectors.primary || '';
              const statusText = ready ? detail : t('等待回收', 'waiting for collection');
              const statusClass = ready ? (href ? 'endpoint' : 'ready') : 'waiting';
              const laneReadiness = artifactLaneReadinessText(displayName, fileName, ready, href, safeSelector, hasIndexedArtifact);
              const pathHtml = path
                ? `<code data-copy="${escapeAttr(path)}">${escapeHtml(path)}</code>`
                : `<span class="muted" data-copy="${escapeAttr(statusText)}">${escapeHtml(t('等待回收', 'waiting for collection'))}</span>`;
              const openAction = href
                ? `<a class="button secondary" href="${escapeAttr(href)}" target="_blank" rel="noopener">${escapeHtml(t('打开/下载', 'Open/download'))}</a>`
                : `<span class="path-only">${escapeHtml(t('等待下载链接', 'waiting for download link'))}</span>`;
              const copyAction = path
                ? `<button class="secondary" type="button" data-copy="${escapeAttr(path)}" onclick="copyText(this.getAttribute('data-copy'))">${escapeHtml(t('复制路径', 'Copy path'))}</button>`
                : '';
              const selectorAction = safeSelector
                ? `<button class="secondary" type="button" data-copy="${escapeAttr(safeSelector)}" onclick="copyText(this.getAttribute('data-copy'))">${escapeHtml(t('复制 selector', 'Copy selector'))}</button>`
                : '';
              const hrefCopyAction = href
                ? `<button class="secondary" type="button" data-copy="${escapeAttr(href)}" onclick="copyText(this.getAttribute('data-copy'))">${escapeHtml(t('复制下载链接', 'Copy download link'))}</button>`
                : '';
              const previewLabel = artifactPreviewLabel(artifact, displayName);
              const selectorBlock = renderArtifactSelectorBlock(download, selectors, href, hasIndexedArtifact);
              const duplicateBlock = renderArtifactDuplicateBlock(duplicate);
              const rejectionBlock = renderArtifactDownloadRejection(download, ready, safeSelector, hasIndexedArtifact);
              const chipRow = renderArtifactChipRow(download, selectors, duplicate);
              const copy = [previewLabel, fileName, path || statusText, safeSelector ? `selector=${safeSelector}` : '', `lane readiness=${laneReadiness}`, statusText].filter(Boolean).join(' | ');
              const summaryCopyAction = `<button class="secondary" type="button" data-copy="${escapeAttr(copy)}" onclick="copyText(this.getAttribute('data-copy'))">${escapeHtml(t('复制卡片摘要', 'Copy card summary'))}</button>`;
              return `<article class="artifact-card ${statusClass}" data-copy="${escapeAttr(copy)}">
                <div class="artifact-card-title">
                  <strong data-copy="${escapeAttr(previewLabel)}">${escapeHtml(displayName)}</strong>
                  <span class="pill ${statusClass}" data-copy="${escapeAttr(statusText)}">${escapeHtml(statusText)}</span>
                  <span class="pill ${statusClass}" data-copy="${escapeAttr(laneReadiness)}">${escapeHtml(laneReadiness)}</span>
                </div>
                <p class="muted">${escapeHtml(fileName)}</p>
                <p>${pathHtml}</p>
                ${chipRow}
                ${selectorBlock}
                ${duplicateBlock}
                ${rejectionBlock}
                <div class="artifact-action">${openAction}${summaryCopyAction}${copyAction}${selectorAction}${hrefCopyAction}</div>
              </article>`;
            }

            function artifactLaneReadinessText(displayName, fileName, ready, href, safeSelector, hasIndexedArtifact) {
              if (ready && (href || safeSelector)) {
                return t('证据 lane 就绪：安全端点可用', 'artifact lane readiness: safe endpoint ready');
              }

              if (ready) {
                return hasIndexedArtifact
                  ? t('证据 lane 就绪：索引已记录，可复制 selector/状态', 'artifact lane readiness: indexed, copy selector/status')
                  : t('证据 lane 就绪：可复制路径或状态', 'artifact lane readiness: copy-only path/status');
              }

              const name = [displayName, fileName].filter(Boolean).join(' / ');
              return t(`证据 lane 等待回收：${name}`, `artifact lane readiness: waiting for collection: ${name}`);
            }

            function artifactPreviewLabel(artifact, fallback) {
              return firstArtifactText(
                artifactField(artifact, currentLanguage === 'en' ? 'previewLabel' : 'previewLabelZh', currentLanguage === 'en' ? 'PreviewLabel' : 'PreviewLabelZh'),
                artifactField(artifact, 'previewLabelZh', 'PreviewLabelZh'),
                artifactField(artifact, 'previewLabel', 'PreviewLabel'),
                fallback);
            }

            function renderArtifactChipRow(download, selectors, duplicate) {
              const chips = [];
              if (download.available || download.selector) {
                chips.push(`<span class="pill ready" data-copy="${escapeAttr(download.selector || '')}">${escapeHtml(t('安全下载', 'safe download'))}</span>`);
              } else if (download.rejectionCode) {
                chips.push(`<span class="pill failed" data-copy="${escapeAttr(download.rejectionCode)}">${escapeHtml(t('不可下载', 'not downloadable'))}</span>`);
              }

              if (selectors.policy) {
                chips.push(`<span class="pill quiet" data-copy="${escapeAttr(selectors.policy)}">${escapeHtml(t('相对 selector', 'relative selector'))}</span>`);
              }

              if (duplicate.groupCount > 1 || duplicate.isDuplicate) {
                const label = duplicate.isDuplicate ? t('重复副本', 'duplicate copy') : t('重复主项', 'duplicate primary');
                chips.push(`<span class="pill ${duplicate.isDuplicate ? 'waiting' : 'ready'}" data-copy="${escapeAttr(`${duplicate.role} ${duplicate.groupCountText}`)}">${escapeHtml(`${label} ${duplicate.groupCountText || ''}`.trim())}</span>`);
              }

              return chips.length ? `<div class="artifact-chip-row">${chips.join('')}</div>` : '';
            }

            function renderArtifactSelectorBlock(download, selectors, href, hasIndexedArtifact) {
              const primary = download.selector || selectors.primary || '';
              const rows = [
                artifactKeyValue(t('安全下载 selector', 'Safe download selector'), primary, 'artifact-selector'),
                artifactKeyValue(t('RelativePath', 'RelativePath'), selectors.relativePath),
                artifactKeyValue(t('SafeLink', 'SafeLink'), selectors.safeLink),
                artifactKeyValue(t('ImportPath', 'ImportPath'), selectors.importPath),
                artifactKeyValue(t('下载端点', 'Download endpoint'), href),
                artifactKeyValue(t('文件名', 'File name'), download.fileName),
                artifactKeyValue(t('类型', 'Content type'), download.contentType),
                artifactKeyValue('SHA-256', download.sha256 || download.sha256Short)
              ].filter(Boolean);
              if (!rows.length) { return ''; }
              const summary = !hasIndexedArtifact
                ? t('服务端端点 / 下载元数据', 'Server endpoint / download metadata')
                : primary
                ? t('安全 selector / 下载元数据', 'Safe selector / download metadata')
                : t('下载元数据（缺少安全 selector）', 'Download metadata (missing safe selector)');
              return `<details class="artifact-mini" ${primary ? '' : 'open'} data-copy="${escapeAttr([summary, primary, href].filter(Boolean).join(' | '))}">
                <summary>${escapeHtml(summary)}</summary>
                <div class="artifact-kv-grid">${rows.join('')}</div>
              </details>`;
            }

            function renderArtifactDuplicateBlock(duplicate) {
              if (!(duplicate.groupCount > 1 || duplicate.isDuplicate || duplicate.groupKey || duplicate.groupId)) { return ''; }
              const roleLabel = duplicate.isDuplicate ? t('重复副本', 'duplicate copy') : (duplicate.role === 'primary' ? t('重复组主项', 'duplicate primary') : duplicate.role);
              const rows = [
                artifactKeyValue(t('重复角色', 'Duplicate role'), roleLabel),
                artifactKeyValue(t('重复组数量', 'Duplicate group count'), duplicate.groupCountText),
                artifactKeyValue(t('主项 selector', 'Primary selector'), duplicate.primarySelector),
                artifactKeyValue(t('重复组 ID', 'Duplicate group ID'), duplicate.groupId),
                artifactKeyValue(t('重复组 Key', 'Duplicate group key'), duplicate.groupKey)
              ].filter(Boolean);
              const copy = [roleLabel, duplicate.groupCountText, duplicate.primarySelector, duplicate.groupId || duplicate.groupKey].filter(Boolean).join(' | ');
              return `<details class="artifact-mini" data-copy="${escapeAttr(copy)}">
                <summary>${escapeHtml(t('重复组信息', 'Duplicate group info'))}</summary>
                <div class="artifact-kv-grid">${rows.join('')}</div>
              </details>`;
            }

            function renderArtifactDownloadRejection(download, ready, safeSelector, hasIndexedArtifact) {
              if (!hasIndexedArtifact) { return ''; }
              if (ready && (safeSelector || download.available)) { return ''; }
              if (!download.rejectionCode && !download.rejectionMessage && safeSelector) { return ''; }
              const message = download.rejectionMessage || (safeSelector ? '' : t('缺少安全相对 selector；Web 端不会直接下载。', 'Missing a safe relative selector; the Web UI will not stream it directly.'));
              const rows = [
                artifactKeyValue(t('拒绝代码', 'Rejection code'), download.rejectionCode || (safeSelector ? '' : 'missing-safe-selector')),
                artifactKeyValue(t('说明', 'Message'), message)
              ].filter(Boolean);
              if (!rows.length) { return ''; }
              return `<details class="artifact-mini artifact-warning" open data-copy="${escapeAttr(message)}">
                <summary>${escapeHtml(t('下载拒绝诊断', 'Download rejection diagnostics'))}</summary>
                <div class="artifact-kv-grid">${rows.join('')}</div>
              </details>`;
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
                runbookExecutionPath: runbookPath || (jobRoot ? combineHostPath(jobRoot, 'runbook-execution.json') : ''),
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

            function normalizeRunbookStepInfo(raw, snapshot) {
              if (!raw || typeof raw !== 'object') { return null; }
              const steps = Array.isArray(snapshot?.steps) ? snapshot.steps : [];
              const stepIndexValue = firstDefined(raw.stepIndex, raw.StepIndex);
              const stepNumberValue = firstDefined(raw.stepNumber, raw.StepNumber);
              const stepIndex = Number.isFinite(Number(stepIndexValue))
                ? Number(stepIndexValue)
                : (Number.isFinite(Number(stepNumberValue)) ? Number(stepNumberValue) - 1 : -1);
              const total = Math.max(steps.length, Number(firstDefined(raw.totalSteps, raw.TotalSteps, snapshot?.totalSteps, snapshot?.TotalSteps, 0)) || 0);
              const title = firstTextValue(raw.displayText, raw.DisplayText, raw.title, raw.Title, raw.stepId, raw.StepId);
              const state = String(firstDefined(raw.state, raw.State, snapshot?.state, snapshot?.State, 'pending')).toLowerCase();
              const ordinal = stepIndex >= 0
                ? `${stepIndex + 1}/${Math.max(total, stepIndex + 1)}`
                : (Number.isFinite(Number(stepNumberValue)) ? `${Number(stepNumberValue)}/${Math.max(total, Number(stepNumberValue))}` : '');
              return {
                raw,
                stepIndex,
                stepId: firstTextValue(raw.stepId, raw.StepId),
                title,
                state,
                message: firstTextValue(raw.message, raw.Message),
                startedAtUtc: firstTextValue(raw.startedAtUtc, raw.StartedAtUtc),
                duration: firstDefined(raw.duration, raw.Duration),
                exitCode: firstDefined(raw.exitCode, raw.ExitCode),
                totalSteps: total,
                ordinalText: ordinal || t('步骤序号待定', 'step ordinal pending')
              };
            }

            function currentStepInfoFromSnapshot(snapshot) {
              const steps = Array.isArray(snapshot?.steps) ? snapshot.steps : [];
              if (!steps.length) { return null; }
              const index = snapshot.currentStepIndex === null || snapshot.currentStepIndex === undefined ? -1 : Number(snapshot.currentStepIndex);
              const indexed = index >= 0 && index < steps.length ? steps[index] : null;
              const running = steps.find(step => String(step.state || '').toLowerCase() === 'running');
              const step = running || indexed || steps.find(step => String(step.state || '').toLowerCase() === 'pending') || steps[steps.length - 1];
              return normalizeRunbookStepInfo(step, snapshot);
            }

            function isSameRunbookStep(step, currentInfo) {
              if (!step || !currentInfo) { return false; }
              const stepIndex = Number(step.stepIndex ?? step.StepIndex);
              if (Number.isFinite(stepIndex) && Number.isFinite(currentInfo.stepIndex) && stepIndex === currentInfo.stepIndex) {
                return true;
              }

              const stepId = firstTextValue(step.stepId, step.StepId);
              return Boolean(stepId && currentInfo.stepId && stepId === currentInfo.stepId);
            }

            function renderRunbookProgress(snapshot, streamCurrentStep) {
              lastProgressSnapshot = snapshot;
              const target = document.getElementById('runbookProgress');
              if (!target || !snapshot) { return; }
              const steps = Array.isArray(snapshot.steps) ? snapshot.steps : [];
              const total = Math.max(steps.length, Number(snapshot.totalSteps || 0));
              const completed = Math.max(0, Number(snapshot.completedSteps || 0));
              const executed = Math.max(0, Number(snapshot.executedSteps || 0));
              const rawState = String(snapshot.state || 'pending').toLowerCase();
              const state = formatProgressState(rawState);
              const done = rawState === 'completed' || snapshot.success === true;
              const failed = rawState === 'failed' || rawState === 'canceled' || snapshot.success === false;
              const streamPercent = Number(lastProgressStreamEnvelope?.progressPercent);
              const percent = progressStreamMode === 'sse' && Number.isFinite(streamPercent)
                ? Math.max(0, Math.min(100, Math.round(streamPercent)))
                : progressPercent(snapshot);
              const stageIndex = estimateMonitorStageIndex(percent, done, failed);
              const streamInfo = normalizeRunbookStepInfo(streamCurrentStep || lastProgressStreamEnvelope?.currentStep, snapshot);
              const snapshotInfo = currentStepInfoFromSnapshot(snapshot);
              const currentInfo = streamInfo || snapshotInfo;
              const current = snapshot.currentStepTitle || currentInfo?.title || (done ? t('所有步骤已完成', 'all steps completed') : t('等待下一步', 'waiting for next step'));
              const currentState = currentInfo?.state ? formatProgressState(currentInfo.state) : state;
              const currentOrdinal = currentInfo?.ordinalText || t('步骤序号待定', 'step ordinal pending');
              const currentSource = streamInfo ? t('真实进度流 currentStep', 'real progress stream currentStep') : t('轮询/持久化快照', 'poll/durable snapshot');
              const elapsed = formatDuration(snapshot.duration) || '-';
              const failedStep = steps.find(step => ['failed', 'canceled'].includes(String(step.state || '').toLowerCase()));
              const failureReason = buildProgressFailureReason(snapshot, failedStep);
              const message = snapshot.message ? `<p class="muted" data-copy="${escapeAttr(localizeServerMessage(snapshot.message))}">${escapeHtml(localizeServerMessage(snapshot.message))}</p>` : '';
              const failure = failureReason ? `<p class="error" data-copy="${escapeAttr(failureReason)}">${t('失败原因：', 'Failure reason: ')}${escapeHtml(failureReason)}</p>` : '';
              const stageRail = renderMonitorStages(stageIndex, done, failed);
              const focusCopy = `${state}; ${completed}/${total}; 当前=${current}; 当前状态=${currentState}; 序号=${currentOrdinal}; 来源=${currentSource}; 已执行=${executed}; 已耗时=${elapsed}`;
              const stepCards = steps.slice(0, 32).map(step => renderRunbookStepCard(step, currentInfo, total)).join('');
              const hiddenCount = Math.max(0, steps.length - 32);
              const hiddenNotice = hiddenCount > 0 ? `<p class="muted">${escapeHtml(t(`另有 ${hiddenCount} 个步骤已折叠，执行流程页可查看完整列表。`, `${hiddenCount} additional steps are hidden; open Execution flow for the full list.`))}</p>` : '';
              target.innerHTML = `
                <div class="card-status">
                  <span class="pill ${failed ? 'failed' : done ? 'ready' : 'endpoint'}" data-copy="${escapeAttr(state)}">${escapeHtml(state)}</span>
                  <strong>${escapeHtml(completed)} / ${escapeHtml(total)} ${t('步骤完成', 'steps completed')}</strong>
                  <span class="percent-label" data-copy="${percent}%">${percent}%</span>
                </div>
                <div class="progressbar" aria-label="${escapeAttr(t('执行进度', 'runbook progress'))}"><div class="progressbar-fill ${failed ? 'failed' : ''}" style="width:${percent}%"></div></div>
                <div class="runbook-live-summary" data-copy="${escapeAttr(focusCopy)}">
                  <div><span>${escapeHtml(t('当前真实步骤', 'Current real step'))}</span><strong>${escapeHtml(current)}</strong></div>
                  <div><span>${escapeHtml(t('当前步骤状态', 'Current step status'))}</span><strong>${escapeHtml(currentState)}</strong></div>
                  <div><span>${escapeHtml(t('步骤序号', 'Step ordinal'))}</span><strong>${escapeHtml(currentOrdinal)}</strong></div>
                  <div><span>${escapeHtml(t('进度来源', 'Progress source'))}</span><strong>${escapeHtml(currentSource)}</strong></div>
                  <div><span>${escapeHtml(t('已执行步骤', 'Executed steps'))}</span><strong>${escapeHtml(executed)} / ${escapeHtml(total)}</strong></div>
                  <div><span>${escapeHtml(t('已耗时', 'Elapsed'))}</span><strong>${escapeHtml(elapsed)}</strong></div>
                </div>
                ${message}
                ${failure}
                <div class="monitor-stage-grid" aria-label="${escapeAttr(t('分析阶段进度', 'analysis stage progress'))}">${stageRail}</div>
                <div class="step-list">${stepCards || `<p class="muted">${t('尚无步骤快照。', 'No step snapshot yet.')}</p>`}</div>
                ${hiddenNotice}`;
              target.setAttribute('data-copy', `执行进度 ${focusCopy}; 失败原因=${failureReason || '-'}`);
              renderOperatorCockpit();
            }

            function renderRunbookStepCard(step, currentInfo, total) {
              const stepState = String(step.state || 'pending').toLowerCase();
              const stepNumber = Number(step.stepIndex ?? 0) + 1;
              const title = `${stepNumber}/${Math.max(1, Number(total) || 1)} ${step.title || step.stepId || ''}`;
              const stepMessage = localizeServerMessage(step.message || '');
              const duration = step.duration ? formatDuration(step.duration) : '-';
              const isCurrent = isSameRunbookStep(step, currentInfo);
              const stateClass = ['running', 'completed', 'failed', 'skipped', 'canceled'].includes(stepState) ? stepState : 'pending';
              const detail = [
                isCurrent ? t('当前', 'current') : '',
                formatProgressState(stepState),
                step.exitCode == null ? '' : `${t('退出码', 'exit')} ${step.exitCode}`,
                step.duration ? formatDuration(step.duration) : '',
                step.requiresElevation ? t('需要提权', 'elevated') : '',
                step.mutatesVmState ? t('会改变 VM 状态', 'mutates VM') : '',
                stepMessage
              ].filter(Boolean).join(' · ');
              return `<details class="step-card ${escapeAttr(stateClass)} ${isCurrent ? 'current' : ''}" ${isCurrent ? 'open' : ''} data-copy="${escapeAttr(title + ' ' + detail)}">
                <summary>
                  <strong>${escapeHtml(title)}</strong>
                  <span class="pill ${stateClass === 'failed' || stateClass === 'canceled' ? 'failed' : stateClass === 'completed' || stateClass === 'skipped' ? 'ready' : stateClass === 'running' ? 'endpoint' : 'waiting'}">${escapeHtml(detail || formatProgressState('pending'))}</span>
                </summary>
                <p>${t('步骤状态', 'Step status')}：<strong>${escapeHtml(formatProgressState(stepState))}</strong></p>
                <p>${t('已耗时', 'Elapsed')}：<strong>${escapeHtml(duration)}</strong></p>
                ${step.exitCode == null ? '' : `<p>${t('退出码', 'Exit code')}：<strong>${escapeHtml(step.exitCode)}</strong></p>`}
                ${step.requiresElevation ? `<p class="muted">${escapeHtml(t('该步骤需要提权。', 'This step requires elevation.'))}</p>` : ''}
                ${step.mutatesVmState ? `<p class="muted">${escapeHtml(t('该步骤会改变虚拟机状态。', 'This step mutates VM state.'))}</p>` : ''}
                ${stepMessage ? `<p class="muted">${escapeHtml(stepMessage)}</p>` : ''}
                <p class="muted">${escapeHtml(t('只显示界面安全状态；不展示命令、标准输出 stdout 或标准错误 stderr。', 'UI-safe status only; commands, stdout, and stderr are not shown.'))}</p>
              </details>`;
            }

            function estimateMonitorStageIndex(percent, done, failed) {
              if (done) { return monitorStages.length - 1; }
              const bounded = Math.max(0, Math.min(99, Number(percent) || 0));
              const index = Math.floor((bounded / 100) * monitorStages.length);
              return Math.max(0, Math.min(monitorStages.length - 1, failed ? Math.max(index, 1) : index));
            }

            function renderMonitorStages(activeIndex, done, failed) {
              const bounded = Math.max(0, Math.min(monitorStages.length - 1, Number(activeIndex) || 0));
              return monitorStages.map((stage, index) => {
                const css = done
                  ? 'done'
                  : failed && index === bounded
                    ? 'failed'
                    : index < bounded
                      ? 'done'
                      : index === bounded
                        ? 'active'
                        : '';
                const label = t(stage[0], stage[1]);
                const detail = t(stage[2], stage[3]);
                return `<div class="monitor-stage ${css}" data-copy="${escapeAttr(`${label} - ${detail}`)}"><strong>${escapeHtml(label)}</strong><small>${escapeHtml(detail)}</small></div>`;
              }).join('');
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
              const steps = Array.isArray(snapshot?.steps) ? snapshot.steps : [];
              const total = Math.max(steps.length, Number(snapshot?.totalSteps || 0));
              if (total <= 0) { return 0; }
              const state = String(snapshot?.state || '').toLowerCase();
              if (state === 'completed' || snapshot?.success === true) { return 100; }
              const completed = Math.max(0, Number(snapshot?.completedSteps || 0));
              const currentIndex = snapshot?.currentStepIndex === null || snapshot?.currentStepIndex === undefined ? -1 : Number(snapshot.currentStepIndex);
              const hasRunning = steps.some(step => String(step.state || '').toLowerCase() === 'running');
              const runningCredit = hasRunning ? 0.45 : (currentIndex >= 0 && completed <= currentIndex ? 0.25 : 0);
              const numerator = Math.max(completed, currentIndex >= 0 ? currentIndex : 0) + runningCredit;
              const percent = Math.round((Math.min(total, numerator) / total) * 100);
              const floor = state === 'running' || hasRunning ? 3 : 0;
              return Math.max(floor, Math.min(100, percent));
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
              setStreamFallbackStatus(message, 'fallback');
              refreshLiveEvents(false);
              pollTimer = setInterval(() => refreshLiveEvents(false), 2000);
            }

            function stopLive() {
              if (eventSource) { eventSource.close(); eventSource = null; }
              if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
            }

            async function refreshLiveEvents(reset) {
              if (liveFetchInFlight) { return; }
              if (reset) {
                resetLiveEventsBuffer();
                setStreamFallbackStatus(
                  t('原始事件流：正在从 offset=0 手动刷新；仍会隐藏命令、stdout、stderr 与 PowerShell 字段。', 'Raw event stream: manually refreshing from offset=0; command, stdout, stderr, and PowerShell fields remain hidden.'),
                  'fallback');
              }
              try {
                liveFetchInFlight = true;
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/events/live?offset=${eventOffset}&take=100`);
                const payload = await requireOk(response, t('实时事件', 'live events'));
                renderSnapshot(payload, 'poll');
              } catch (error) {
                setStatus(error.message, true);
                setStreamFallbackStatus(error.message, 'error');
              } finally {
                liveFetchInFlight = false;
              }
            }

            async function refreshVirusTotal() {
              renderVirusTotal({
                status: 'running',
                configured: true,
                queried: false,
                found: false,
                message: t('VirusTotal：正在查询 SHA-256 文件报告...', 'VirusTotal: querying SHA-256 file report...')
              });
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/virustotal`, { cache: 'no-store' });
                const payload = await requireOk(response, 'VirusTotal');
                renderVirusTotal(payload);
              } catch (error) {
                // Keep VirusTotal silent and non-blocking. Operators can open
                // Settings if they need to inspect the API key.
                const detail = error && error.message ? error.message : '';
                const notConfigured = /not[_ -]?configured|api key|未配置/i.test(detail);
                const status = notConfigured ? 'not_configured' : 'lookup_failed';
                const quietMessage = notConfigured
                  ? t('VirusTotal API Key 未配置；官方查询已静默跳过，沙箱分析继续。', 'VirusTotal API key is not configured; official lookup was skipped quietly and sandbox analysis continues.')
                  : t('VirusTotal 查询暂不可用；已作为页面静默状态处理，不写任务/行为日志，沙箱分析继续。', 'VirusTotal lookup is temporarily unavailable; it is handled as a quiet page status without job/behavior logs, and sandbox analysis continues.');
                renderVirusTotal({
                  status,
                  configured: !notConfigured,
                  queried: false,
                  found: false,
                  message: quietMessage,
                  errorKind: 'ui_endpoint_quiet_status',
                  isQuietState: true,
                  quietFailureReason: status,
                  quietFailureExplanation: quietMessage,
                  liveLogPolicy: 'display_only_no_job_log_by_default',
                  persistencePolicy: 'display_only_quiet_status_not_persisted',
                  diagnosticMessage: detail
                });
              }
            }

            function renderVirusTotal(result) {
              lastVirusTotalResult = result;
              const target = document.getElementById('vtResult');
              if (!target) { return; }
              const stats = vtValue(result, 'lastAnalysisStats') || {};
              const engineCounts = vtValue(result, 'engineCounts') || {};
              const malicious = vtNumber(stats.malicious, stats.Malicious, vtValue(result, 'maliciousCount'), vtValue(engineCounts, 'malicious'));
              const suspicious = vtNumber(stats.suspicious, stats.Suspicious, vtValue(result, 'suspiciousCount'), vtValue(engineCounts, 'suspicious'));
              const harmless = vtNumber(stats.harmless, stats.Harmless, vtValue(result, 'harmlessCount'), vtValue(engineCounts, 'harmless'));
              const undetected = vtNumber(stats.undetected, stats.Undetected, vtValue(result, 'undetectedCount'), vtValue(engineCounts, 'undetected'));
              const timeoutEngines = vtNumber(stats.timeout, stats.Timeout, vtValue(result, 'timeoutCount'), vtValue(engineCounts, 'timeout'));
              const confirmedTimeout = vtNumber(stats['confirmed-timeout'], stats.ConfirmedTimeout, vtValue(engineCounts, 'confirmedTimeout'));
              const failedEngines = vtNumber(stats.failure, stats.Failure, vtValue(engineCounts, 'failure'));
              const unsupportedEngines = vtNumber(stats['type-unsupported'], stats.TypeUnsupported, vtValue(engineCounts, 'typeUnsupported'));
              const engineTotal = vtNumber(vtValue(result, 'engineCount'), vtValue(engineCounts, 'total'), malicious + suspicious + harmless + undetected + timeoutEngines + confirmedTimeout + failedEngines + unsupportedEngines);
              const communityVotes = vtValue(result, 'communityVotes') || {};
              let label;
              let className = 'metric vt-card vt-quiet';
              let score = t('未查询', 'not queried');
              let status = vtValue(result, 'status') || '';
              const vtStatus = normalizeVirusTotalStatus(result);
              const officialFieldsHtml = virusTotalOfficialFieldsHtml(result, communityVotes, engineTotal);
              const quietExplanationHtml = virusTotalQuietExplanationHtml(result, vtStatus);
              const workflowState = virusTotalWorkflowState(result);
              const workflowLabel = virusTotalWorkflowLabel(workflowState);
              const progress = virusTotalProgressPercent(workflowState, result);
              const currentStep = virusTotalCurrentStep(workflowState, result);
              const statusLabel = virusTotalStatusLabel(vtStatus, result);
              const outcomeStatus = virusTotalOutcomeStatus(vtStatus, result, malicious, suspicious);
              const operatorState = virusTotalOperatorStateText(vtStatus, result, malicious, suspicious);
              if (workflowState === 'running') {
                label = result.message || t('正在查询 VirusTotal 官方文件报告。', 'Querying the official VirusTotal file report.');
                className = 'metric vt-card vt-neutral';
                score = t('查询中', 'querying');
              } else if (vtStatus === 'found' || vtBoolValue(result, 'found')) {
                label = t(`已收录：恶意 ${malicious} / 可疑 ${suspicious} / 无害 ${harmless} / 未检出 ${undetected}`, `Found: malicious ${malicious} / suspicious ${suspicious} / harmless ${harmless} / undetected ${undetected}`);
                score = `${malicious + suspicious}`;
                status = outcomeStatus.label;
                className = malicious > 0 ? 'metric vt-card vt-danger' : (suspicious > 0 ? 'metric vt-card vt-warning' : 'metric vt-card vt-ok');
              } else {
                const quiet = virusTotalQuietDisplay(vtStatus, result);
                label = quiet.label;
                score = quiet.score;
                status = quiet.status;
                className = quiet.className;
              }

              const vtHref = vtValue(result, 'detectionPermalink') || vtValue(result, 'permalink');
              const link = vtHref ? `<a class="button secondary" href="${escapeAttr(vtHref)}" target="_blank" rel="noopener">${escapeHtml(t('打开 VT 检测页', 'Open VT detections'))}</a>` : '';
              const overviewHref = vtValue(result, 'permalink');
              const reportLink = overviewHref && overviewHref !== vtHref ? `<a class="button secondary" href="${escapeAttr(overviewHref)}" target="_blank" rel="noopener">${escapeHtml(t('VT 文件概览', 'VT file overview'))}</a>` : '';
              const settingsLink = ['not_configured', 'authentication_failed'].includes(vtStatus) ? ` <a href="/settings">${t('打开设置', 'Open settings')}</a>` : '';
              const nameValue = vtValue(result, 'meaningfulName');
              const shaValue = vtValue(result, 'sha256');
              const name = nameValue ? `<p>${escapeHtml(nameValue)}</p>` : '';
              const sha = shaValue ? `<p><code data-copy="${escapeAttr(shaValue)}">${escapeHtml(shaValue)}</code></p>` : '';
              const cache = virusTotalCacheText(result);
              const cacheHtml = cache ? `<p class="muted" data-copy="${escapeAttr(cache)}">${escapeHtml(cache)}</p>` : '';
              const retryAt = vtValue(result, 'retryAfterUtc');
              const retry = retryAt ? `${t('重试时间', 'Retry after')}: ${retryAt}` : '';
              const configured = vtBoolValue(result, 'configured');
              const queried = vtBoolValue(result, 'queried');
              const configuredLabel = configured ? t('VirusTotal 已配置', 'VT configured') : t('VirusTotal 未配置', 'VT not configured');
              const queriedLabel = queried ? t('已查询官方 API', 'official API queried') : t('未调用官方 API', 'official API not called');
              const quietLabel = (result.isQuietState || result.IsQuietState || workflowState === 'quiet') ? t('静默状态：不阻断分析', 'quiet: non-blocking') : t('可见结果', 'visible result');
              const retryHtml = retry ? `<p class="muted" data-copy="${escapeAttr(retry)}">${escapeHtml(retry)}</p>` : '';
              const isQuiet = Boolean(result.isQuietState || result.IsQuietState || workflowState === 'quiet');
              const quietNote = isQuiet
                ? `<p class="muted">${escapeHtml(t('静默状态卡：未配置、未收录、限速、鉴权失败、超时或查询失败只在页面展示，不写任务/行为日志，也不会中断分析。', 'Quiet status card: not configured, not found, rate limits, auth failures, timeouts, or lookup failures are display-only, do not write job/behavior logs, and do not interrupt analysis.'))}</p>`
                : '';
              const logPolicy = virusTotalPolicyText(vtValue(result, 'liveLogPolicy'));
              const statusCopy = `${vtStatus}${vtValue(result, 'errorKind') ? ` / ${vtValue(result, 'errorKind')}` : ''}; ${logPolicy}`;
              target.className = className;
              target.innerHTML = `
                <div class="card-status">
                  <span class="pill ${backgroundStateTone(workflowState)}" data-copy="${escapeAttr(workflowLabel)}">${escapeHtml(workflowLabel)}</span>
                  <strong>${escapeHtml(t('官方查询状态', 'Official lookup status'))}</strong>
                  <span class="percent-label" data-copy="${progress}%">${progress}%</span>
                </div>
                <div class="progressbar compact" aria-label="${escapeAttr(t('VirusTotal 查询进度', 'VirusTotal lookup progress'))}"><div class="progressbar-fill ${workflowState === 'failed' ? 'failed' : ''}" style="width:${progress}%"></div></div>
                <p>${t('当前步骤', 'Current step')}：<strong>${escapeHtml(currentStep)}</strong></p>
                <p class="vt-state-banner" data-copy="${escapeAttr(operatorState)}"><strong>${escapeHtml(t('操作者状态', 'Operator state'))}：</strong>${escapeHtml(operatorState)}</p>
                <div class="vt-head">
                  <div>
                    <strong>${escapeHtml(label)}</strong>
                    ${name}
                  </div>
                  <div class="vt-score" data-copy="${escapeAttr(score)}">${escapeHtml(score)}</div>
                </div>
                <div class="vt-state-row">
                  <span class="pill ${configured ? 'ready' : 'quiet'}" data-copy="${escapeAttr(configuredLabel)}">${escapeHtml(configuredLabel)}</span>
                  <span class="pill ${queried ? 'endpoint' : 'quiet'}" data-copy="${escapeAttr(queriedLabel)}">${escapeHtml(queriedLabel)}</span>
                  <span class="pill ${outcomeStatus.tone}" data-copy="${escapeAttr(outcomeStatus.copy)}">${escapeHtml(outcomeStatus.label)}</span>
                  <span class="pill quiet" data-copy="${escapeAttr(quietLabel)}">${escapeHtml(quietLabel)}</span>
                  <span class="pill quiet" data-copy="${escapeAttr(logPolicy)}">${escapeHtml(t('默认不写日志噪音', 'no log noise by default'))}</span>
                </div>
                ${quietNote}
                <div class="vt-stats">
                  <span data-copy="${malicious}"><strong>${t('恶意', 'Malicious')}</strong>${malicious}</span>
                  <span data-copy="${suspicious}"><strong>${t('可疑', 'Suspicious')}</strong>${suspicious}</span>
                  <span data-copy="${harmless}"><strong>${t('无害', 'Harmless')}</strong>${harmless}</span>
                  <span data-copy="${undetected}"><strong>${t('未检出', 'Undetected')}</strong>${undetected}</span>
                  <span data-copy="${timeoutEngines}"><strong>${t('引擎超时', 'Engine timeout')}</strong>${timeoutEngines}</span>
                  <span data-copy="${engineTotal}"><strong>${t('引擎总数', 'Engine total')}</strong>${engineTotal}</span>
                </div>
                <details class="vt-details">
                  <summary data-copy="VirusTotal 官方引擎统计 / official engine stats">${escapeHtml(t('完整官方引擎统计', 'Full official engine stats'))}</summary>
                  <div class="vt-stats">
                    <span data-copy="${malicious}"><strong>${t('恶意', 'Malicious')}</strong>${malicious}</span>
                    <span data-copy="${suspicious}"><strong>${t('可疑', 'Suspicious')}</strong>${suspicious}</span>
                    <span data-copy="${harmless}"><strong>${t('无害', 'Harmless')}</strong>${harmless}</span>
                    <span data-copy="${undetected}"><strong>${t('未检出', 'Undetected')}</strong>${undetected}</span>
                    <span data-copy="${timeoutEngines}"><strong>${t('超时', 'Timeout')}</strong>${timeoutEngines}</span>
                    <span data-copy="${confirmedTimeout}"><strong>${t('确认超时', 'Confirmed timeout')}</strong>${confirmedTimeout}</span>
                    <span data-copy="${failedEngines}"><strong>${t('失败', 'Failure')}</strong>${failedEngines}</span>
                    <span data-copy="${unsupportedEngines}"><strong>${t('类型不支持', 'Type unsupported')}</strong>${unsupportedEngines}</span>
                    <span data-copy="${engineTotal}"><strong>${t('合计', 'Total')}</strong>${engineTotal}</span>
                  </div>
                </details>
                ${officialFieldsHtml}
                ${quietExplanationHtml}
                ${sha}
                ${cacheHtml}
                ${retryHtml}
                <p class="artifact-action"><span class="pill ${virusTotalStatusPillTone(vtStatus, result)}" data-copy="${escapeAttr(statusCopy)}">${escapeHtml(status || statusLabel)}</span><span class="pill quiet" data-copy="${escapeAttr(vtStatus)}">${escapeHtml(vtStatus)}</span>${link}${reportLink}${settingsLink}</p>`;
              target.setAttribute('data-copy', `VirusTotal ${workflowLabel}; 进度=${progress}%; 当前=${currentStep}; ${vtStatus}: ${label}; ${operatorState}; 引擎=${engineTotal}; 社区=${virusTotalCommunityCopy(result, communityVotes)} ${shaValue || ''}; ${logPolicy}`);
              renderOperatorCockpit();
            }

            function virusTotalOfficialFieldsHtml(result, communityVotes, engineTotal) {
              const lastAnalysis = virusTotalDateText(vtValue(result, 'lastAnalysisDateUtc'));
              const reputation = vtValue(result, 'reputation');
              const communityScore = vtValue(result, 'communityScore');
              const communityScoreSource = vtValue(result, 'communityScoreSource') || '';
              const communityText = virusTotalCommunityText(result, communityVotes);
              const cache = virusTotalCacheText(result) || t('本次请求未使用可展示缓存元数据', 'no displayable cache metadata for this request');
              const permalink = vtValue(result, 'detectionPermalink') || vtValue(result, 'permalink') || '';
              const logPolicy = virusTotalPolicyText(vtValue(result, 'liveLogPolicy'));
              const persistencePolicy = virusTotalPolicyText(vtValue(result, 'persistencePolicy'));
              const fields = [
                { label: t('最后分析时间', 'Last analysis date'), value: lastAnalysis },
                { label: t('官方信誉分', 'Official reputation'), value: reputation === null || reputation === undefined ? t('未提供', 'not provided') : String(reputation) },
                { label: t('社区分数', 'Community score'), value: communityScore === null || communityScore === undefined ? communityText : `${communityScore} · ${communityScoreSource || t('官方字段', 'official field')}` },
                { label: t('社区投票', 'Community votes'), value: communityText },
                { label: t('引擎总数', 'Engine total'), value: String(engineTotal) },
                { label: t('缓存元数据', 'Cache metadata'), value: cache },
                { label: t('官方链接', 'Official permalink'), value: permalink || t('未提供', 'not provided') },
                { label: t('日志策略', 'Log policy'), value: logPolicy },
                { label: t('持久化策略', 'Persistence policy'), value: persistencePolicy }
              ];
              const rows = fields.map(field => `<div class="vt-field" data-copy="${escapeAttr(`${field.label}: ${field.value}`)}"><b>${escapeHtml(field.label)}</b><span>${escapeHtml(field.value)}</span></div>`).join('');
              const apiSelfLink = vtValue(result, 'officialApiSelfLink');
              const apiSelf = apiSelfLink
                ? `<p class="muted" data-copy="${escapeAttr(apiSelfLink)}">${escapeHtml(t('官方 API self link 已解析（不含 API Key）：', 'Official API self link parsed (no API key):'))} <code>${escapeHtml(apiSelfLink)}</code></p>`
                : '';
              return `<details class="vt-details" open>
                <summary data-copy="VirusTotal 官方结果字段 / official fields">${escapeHtml(t('官方结果字段 / 可复制', 'Official result fields / copyable'))}</summary>
                <div class="vt-field-grid">${rows}</div>
                ${apiSelf}
              </details>`;
            }

            function virusTotalPolicyText(value) {
              const raw = String(value || '').trim();
              const key = raw.toLowerCase();
              if (!key || key === 'display_only_no_job_log_by_default' || key === 'display_only_no_job_or_behavior_log_by_default') {
                return t('仅页面状态；默认不写任务/行为日志', 'display-only; no job/behavior log by default');
              }

              if (key === 'display_only_quiet_status_not_persisted') {
                return t('静默状态仅页面展示；不会写入信誉增强、任务日志或行为日志', 'quiet status is display-only; no enrichment, job log, or behavior log is written');
              }

              if (key === 'display_only_by_default_explicit_persist_supported') {
                return t('默认仅页面展示；只有已收录结果可被显式写入信誉增强', 'display-only by default; only found results can be explicitly persisted as reputation enrichment');
              }

              return localizeServerMessage(raw);
            }

            function virusTotalQuietExplanationHtml(result, status) {
              const isQuiet = Boolean(result?.isQuietState || result?.IsQuietState || virusTotalWorkflowState(result) === 'quiet');
              if (!isQuiet) { return ''; }
              const reason = vtValue(result, 'quietFailureReason') || status || 'quiet';
              const explanation = vtValue(result, 'quietFailureExplanation') || result?.message || t('该状态只在页面展示，不写任务/行为日志，也不阻断沙箱执行。', 'This state is displayed only; it does not write job/behavior logs or block sandbox execution.');
              const httpStatusCode = vtValue(result, 'httpStatusCode');
              const errorKindValue = vtValue(result, 'errorKind');
              const http = httpStatusCode ? `HTTP ${httpStatusCode}` : '';
              const errorKind = errorKindValue ? `errorKind=${errorKindValue}` : '';
              const parts = [reason, http, errorKind].filter(Boolean).join(' · ');
              return `<details class="vt-details vt-quiet-explainer" open>
                <summary data-copy="${escapeAttr(parts || reason)}">${escapeHtml(t('静默失败/跳过解释', 'quiet failure/skip explanation'))}</summary>
                <p data-copy="${escapeAttr(explanation)}">${escapeHtml(explanation)}</p>
                ${parts ? `<p class="muted" data-copy="${escapeAttr(parts)}">${escapeHtml(parts)}</p>` : ''}
                <p class="muted">${escapeHtml(t('默认 GET 查询只在页面展示；未配置、未收录和失败类状态不会写入信誉增强或行为日志，只有已收录结果被显式要求时才允许持久化。', 'Default GET lookup is display-only; not-configured, not-found, and failure states do not write enrichment or behavior logs, and only found results can be explicitly persisted.'))}</p>
              </details>`;
            }

            function virusTotalCommunityText(result, communityVotes) {
              const harmless = communityVotes?.harmless ?? communityVotes?.Harmless;
              const malicious = communityVotes?.malicious ?? communityVotes?.Malicious;
              if (harmless === null && malicious === null) { return t('未提供', 'not provided'); }
              if (harmless === undefined && malicious === undefined) { return t('未提供', 'not provided'); }
              const safeHarmless = vtNumber(harmless);
              const safeMalicious = vtNumber(malicious);
              return t(`无害票 ${safeHarmless} / 恶意票 ${safeMalicious}`, `harmless votes ${safeHarmless} / malicious votes ${safeMalicious}`);
            }

            function virusTotalCommunityCopy(result, communityVotes) {
              const score = vtValue(result, 'communityScore');
              const reputation = vtValue(result, 'reputation');
              return `score=${score ?? 'n/a'}; reputation=${reputation ?? 'n/a'}; ${virusTotalCommunityText(result, communityVotes)}`;
            }

            function virusTotalDateText(value) {
              if (!value) { return t('未提供', 'not provided'); }
              const date = new Date(value);
              if (!Number.isFinite(date.getTime())) { return String(value); }
              return `${date.toISOString()} / ${date.toLocaleString()}`;
            }

            function virusTotalOutcomeStatus(status, result, malicious, suspicious) {
              if (status === 'found' || vtBoolValue(result, 'found')) {
                if (Number(malicious) > 0) { return { label: t('恶意命中', 'malicious'), tone: 'failed', copy: `malicious=${malicious}; suspicious=${suspicious}` }; }
                if (Number(suspicious) > 0) { return { label: t('可疑命中', 'suspicious'), tone: 'endpoint', copy: `suspicious=${suspicious}` }; }
                return { label: t('已收录：未见恶意', 'found: no malicious hits'), tone: 'ready', copy: 'found clean-or-unknown' };
              }
              if (['not_configured', 'missing_hash', 'invalid_hash'].includes(status)) {
                return { label: t('已跳过官方查询', 'official lookup skipped'), tone: 'quiet', copy: `skipped; status=${status}` };
              }
              if (status === 'not_found') { return { label: t('未收录', 'not found'), tone: 'quiet', copy: 'not_found' }; }
              if (status === 'rate_limited') { return { label: t('限速', 'rate-limited'), tone: 'quiet', copy: 'rate_limited' }; }
              if (status === 'authentication_failed') { return { label: t('鉴权失败', 'auth failed'), tone: 'quiet', copy: 'authentication_failed' }; }
              if (status === 'timeout') { return { label: t('查询超时', 'timeout'), tone: 'quiet', copy: 'timeout' }; }
              if (status === 'running' || status === 'querying') { return { label: t('查询中', 'querying'), tone: 'endpoint', copy: 'querying' }; }
              return { label: t('查询失败', 'lookup failed'), tone: 'quiet', copy: `lookup_failed; status=${status || 'unknown'}` };
            }

            function virusTotalOperatorStateText(status, result, malicious, suspicious) {
              const hits = Number(malicious || 0) + Number(suspicious || 0);
              if (status === 'found' || vtBoolValue(result, 'found')) {
                if (hits > 0) {
                  return t(`官方已收录：命中 ${hits}（恶意 ${malicious} / 可疑 ${suspicious}）；这是信誉信号，最终结论仍以本地沙箱报告为准。`, `Found in official VT: ${hits} hits (malicious ${malicious} / suspicious ${suspicious}); this is reputation signal and the local sandbox report remains authoritative.`);
                }

                return t('官方已收录：未见恶意或可疑命中；仍以本地行为和证据报告为准。', 'Found in official VT: no malicious or suspicious hits; local behavior and evidence report remain authoritative.');
              }

              if (status === 'running' || status === 'querying' || status === 'queued') {
                return t('官方查询进行中：hash-only，不上传样本，等待页面结果。', 'Official lookup in progress: hash-only, no sample upload, waiting for page result.');
              }

              return t(`静默状态：${virusTotalStatusLabel(status, result)}；不阻断分析，不写任务/行为日志。`, `Quiet state: ${virusTotalStatusLabel(status, result)}; does not block analysis and does not write job/behavior logs.`);
            }

            function vtNumber(...values) {
              for (const value of values) {
                const number = Number(value);
                if (Number.isFinite(number)) { return number; }
              }
              return 0;
            }

            function normalizeVirusTotalStatus(result) {
              const raw = String(vtValue(result, 'status') || '').toLowerCase();
              const errorKind = String(vtValue(result, 'errorKind') || '').toLowerCase();
              const httpStatus = Number(vtValue(result, 'httpStatusCode') || 0);
              if (raw === 'running' || raw === 'querying' || raw === 'queued') { return raw; }
              if (raw === 'timeout' || errorKind === 'timeout') { return 'timeout'; }
              if (raw === 'rate_limited' || httpStatus === 429) { return 'rate_limited'; }
              if (raw === 'authentication_failed' || httpStatus === 401 || httpStatus === 403) { return 'authentication_failed'; }
              if (raw === 'found' || vtBoolValue(result, 'found')) { return 'found'; }
              if (raw === 'not_found' || httpStatus === 404) { return 'not_found'; }
              if (!vtBoolValue(result, 'configured')) { return 'not_configured'; }
              return raw || 'lookup_failed';
            }

            function virusTotalQuietDisplay(status, result) {
              const displays = {
                not_configured: {
                  label: t('未配置 API Key，官方结果已静默跳过。', 'API key not configured; official result skipped quietly.'),
                  score: t('未配置', 'not configured'),
                  status: t('未配置', 'not configured')
                },
                not_found: {
                  label: t('VirusTotal 未收录该 SHA-256；这是信誉查询状态，不代表样本恶意。', 'VirusTotal has no report for this SHA-256; this is reputation status, not malicious behavior.'),
                  score: t('未收录', 'not found'),
                  status: t('未收录', 'not found')
                },
                rate_limited: {
                  label: t('VirusTotal 限速，已静默停止本次查询；沙箱流程继续。', 'VirusTotal rate-limited the lookup; this query stopped quietly and sandbox execution continues.'),
                  score: t('限速', 'rate limited'),
                  status: t('限速', 'rate limited')
                },
                authentication_failed: {
                  label: t('VirusTotal API Key 被拒绝；请检查设置，沙箱流程继续。', 'VirusTotal rejected the API key; check settings. Sandbox execution continues.'),
                  score: t('鉴权失败', 'auth failed'),
                  status: t('鉴权失败', 'auth failed')
                },
                timeout: {
                  label: t('VirusTotal 查询超时；已作为静默状态处理，不写任务/行为日志。', 'VirusTotal lookup timed out; it is handled as a quiet state and does not write job/behavior logs.'),
                  score: t('超时', 'timeout'),
                  status: t('超时', 'timeout')
                },
                missing_hash: {
                  label: t('样本 SHA-256 不可用，已跳过官方查询。', 'Sample SHA-256 is unavailable; official lookup skipped.'),
                  score: t('无哈希', 'missing hash'),
                  status: t('无哈希', 'missing hash')
                },
                invalid_hash: {
                  label: t('样本 SHA-256 格式无效，未调用 VirusTotal。', 'Sample SHA-256 is malformed; VirusTotal was not called.'),
                  score: t('哈希无效', 'invalid hash'),
                  status: t('哈希无效', 'invalid hash')
                }
              };
              const display = displays[status] || {
                label: t('VirusTotal 查询失败，已静默处理；沙箱流程继续，不写任务/行为日志。', 'VirusTotal lookup failed quietly; sandbox execution continues without job/behavior logs.'),
                score: t('静默', 'quiet'),
                status: t('静默失败', 'quiet failure')
              };
              return {
                label: display.label,
                score: display.score,
                status: display.status,
                className: 'metric vt-card vt-quiet'
              };
            }

            function virusTotalStatusPillTone(status, result) {
              if (status === 'found' && result?.found) { return 'ready'; }
              if (['not_configured', 'not_found', 'rate_limited', 'authentication_failed', 'timeout', 'missing_hash', 'invalid_hash', 'lookup_failed'].includes(status)) { return 'quiet'; }
              return 'waiting';
            }

            function virusTotalStatusLabel(status, result) {
              const labels = {
                found: vtValue(result, 'verdict') ? `${t('已收录', 'found')} / ${vtValue(result, 'verdict')}` : t('已收录', 'found'),
                not_found: t('未收录', 'not found'),
                not_configured: t('未配置', 'not configured'),
                rate_limited: t('限速', 'rate limited'),
                authentication_failed: t('鉴权失败', 'auth failed'),
                timeout: t('超时', 'timeout'),
                lookup_failed: t('查询失败', 'lookup failed'),
                missing_hash: t('无 SHA-256', 'missing SHA-256'),
                invalid_hash: t('SHA-256 无效', 'invalid SHA-256'),
                running: t('查询中', 'querying'),
                queued: t('已排队', 'queued')
              };
              return labels[status] || status || 'VirusTotal';
            }

            function virusTotalCacheText(result) {
              if (!result) { return ''; }
              const pieces = [];
              if (vtBoolValue(result, 'cacheHit')) { pieces.push(t('缓存命中', 'cache hit')); }
              const cacheAgeSeconds = vtValue(result, 'cacheAgeSeconds');
              const cacheTtlSeconds = vtValue(result, 'cacheTtlSeconds');
              const cacheExpiresAtUtc = vtValue(result, 'cacheExpiresAtUtc');
              if (cacheAgeSeconds !== null && cacheAgeSeconds !== undefined) { pieces.push(`${t('缓存年龄', 'cache age')} ${cacheAgeSeconds}s`); }
              if (cacheTtlSeconds !== null && cacheTtlSeconds !== undefined) { pieces.push(`${t('缓存 TTL', 'cache TTL')} ${cacheTtlSeconds}s`); }
              if (cacheExpiresAtUtc) { pieces.push(`${t('过期', 'expires')} ${cacheExpiresAtUtc}`); }
              return pieces.join(' · ');
            }

            function virusTotalWorkflowState(result) {
              const status = normalizeVirusTotalStatus(result);
              if (status === 'queued') { return 'queued'; }
              if (status === 'running' || status === 'querying') { return 'running'; }
              if (status === 'found') { return 'completed'; }
              if (['not_found', 'not_configured', 'rate_limited', 'authentication_failed', 'timeout', 'missing_hash', 'invalid_hash', 'lookup_failed'].includes(status)) { return 'quiet'; }
              if (status.includes('fail')) { return 'failed'; }
              return 'quiet';
            }

            function virusTotalWorkflowLabel(state) {
              const labels = {
                queued: t('已排队', 'queued'),
                running: t('运行中', 'running'),
                completed: t('已完成', 'completed'),
                quiet: t('静默状态', 'quiet state'),
                failed: t('失败', 'failed')
              };
              return labels[state] || state;
            }

            function virusTotalProgressPercent(state, result) {
              if (state === 'completed' || state === 'quiet' || state === 'failed') { return 100; }
              if (state === 'running') { return 60; }
              if (state === 'queued') { return 10; }
              if (!vtBoolValue(result, 'configured')) { return 100; }
              return 100;
            }

            function virusTotalCurrentStep(state, result) {
              const status = normalizeVirusTotalStatus(result);
              if (state === 'queued') { return t('等待查询 SHA-256 报告', 'waiting to query SHA-256 report'); }
              if (state === 'running') { return t('调用 VirusTotal 文件报告 API', 'calling VirusTotal file report API'); }
              if (state === 'completed') { return vtBoolValue(result, 'found') ? t('解析官方引擎统计', 'parsing official engine stats') : t('确认官方未收录', 'confirmed not found in official report'); }
              if (state === 'quiet') {
                const steps = {
                  not_configured: t('等待配置 API Key；未写任务/行为日志', 'waiting for API key configuration; no job/behavior log was written'),
                  not_found: t('确认未收录；默认只在页面展示不落盘', 'confirmed not found; display-only by default'),
                  rate_limited: t('收到限速响应；等待后再查', 'received rate limit; wait before retrying'),
                  authentication_failed: t('API Key 鉴权失败；请到设置页检查', 'API key authentication failed; check Settings'),
                  timeout: t('查询超时；保持低噪音', 'lookup timed out; staying low-noise'),
                  missing_hash: t('缺少 SHA-256；跳过查询', 'missing SHA-256; lookup skipped'),
                  invalid_hash: t('SHA-256 格式无效；跳过查询', 'invalid SHA-256; lookup skipped')
                };
                return steps[status] || (result?.message || t('查询状态已静默处理', 'lookup state handled quietly'));
              }
              return result?.message || t('查询失败，沙箱流程继续', 'lookup failed; sandbox flow continues');
            }

            function renderSnapshot(snapshot, transport) {
              const transportLabel = liveTransportLabel(transport);
              const nextSignature = (snapshot.sources || []).join('\\n');
              if (nextSignature !== sourceSignature) {
                resetLiveEventsBuffer(nextSignature);
              }

              const nextOffset = Number(snapshot.nextOffset);
              eventOffset = Number.isFinite(nextOffset) && nextOffset >= 0 ? nextOffset : eventOffset;
              latestArtifactSources = snapshot.sources || [];
              updateArtifactSignalsFromEvents(snapshot.events || []);
              renderSources(snapshot.sources || []);
              renderArtifactPanel();
              appendRows(snapshot.events || []);
              const visible = filteredEventRecords().length;
              const buffered = liveEventRecords.length;
              const sourceStatus = summarizeSourceStatus(snapshot.events || []);
              const hasMoreText = snapshot.hasMore
                ? t('服务端仍有更多页，正在继续按游标读取。', 'More pages remain on the server; continuing by cursor.')
                : t('当前页已读完。', 'Current page is complete.');
              const statusText = t(`${transportLabel}：${snapshot.totalEvents || 0} 条原始事件；已缓冲 ${buffered} 条，当前筛选 ${visible} 条；下次位置 ${eventOffset}；${hasMoreText} ${new Date().toLocaleTimeString()}。`, `${transportLabel}: ${snapshot.totalEvents || 0} raw events; buffered ${buffered}, current filter ${visible}; next offset ${eventOffset}; ${hasMoreText} ${new Date().toLocaleTimeString()}.`);
              setStatus(statusText, false);
              setStreamFallbackStatus(formatLiveStreamDetail(transportLabel, snapshot, buffered, visible, sourceStatus), transport === 'SSE' ? 'ok' : 'fallback');
              if (transport === 'poll' && snapshot.hasMore) {
                setTimeout(() => refreshLiveEvents(false), 80);
              }
            }

            function liveTransportLabel(transport) {
              const key = String(transport || '').toLowerCase();
              if (key === 'poll') { return t('轮询快照', 'poll snapshot'); }
              if (key === 'sse') { return t('SSE 实时流', 'SSE stream'); }
              return transport || t('实时事件', 'live events');
            }

            function renderSources(sources) {
              const target = document.getElementById('sources');
              if (!sources.length) {
                target.textContent = t('尚未发现事件来源。', 'No event sources found yet.');
                return;
              }
              target.innerHTML = `<strong>${t('事件来源', 'Sources')}</strong><ul>` + sources.map(s => `<li><code data-copy="${escapeAttr(s)}">${escapeHtml(s)}</code></li>`).join('') + '</ul>';
            }

            function appendRows(events) {
              const wasOnLatestPage = eventPageIndex >= maxEventPageIndex(filteredEventRecords().length);
              let added = 0;
              for (const ev of events) {
                const key = liveEventKey(ev);
                if (seen.has(key)) { continue; }
                seen.add(key);
                liveEventRecords.push({
                  key,
                  event: ev,
                  severity: eventSeverity(ev),
                  family: eventFamily(ev),
                  source: eventSourceValue(ev)
                });
                added++;
              }
              trimLiveEventBuffer();
              if (added > 0 && wasOnLatestPage) {
                eventPageIndex = maxEventPageIndex(filteredEventRecords().length);
              }
              renderEventTable();
            }

            function resetLiveEventsBuffer(signature) {
              eventOffset = 0;
              sourceSignature = signature || '';
              seen.clear();
              liveEventRecords.length = 0;
              eventPageIndex = 0;
              selectedEventKey = '';
              renderEventTable();
            }

            function trimLiveEventBuffer() {
              if (liveEventRecords.length <= maxBufferedLiveEvents) { return; }
              const removeCount = liveEventRecords.length - maxBufferedLiveEvents;
              liveEventRecords.splice(0, removeCount);
              seen.clear();
              for (const record of liveEventRecords) { seen.add(record.key); }
              if (selectedEventKey && !liveEventRecords.some(record => record.key === selectedEventKey)) {
                selectedEventKey = '';
              }
            }

            function liveEventKey(ev) {
              return JSON.stringify([ev.timestamp, ev.eventType, ev.source, ev.processId, ev.processName, ev.path]);
            }

            function renderEventTable() {
              renderEventFilterChips();
              const body = document.getElementById('eventRows');
              const filtered = filteredEventRecords();
              const maxPage = maxEventPageIndex(filtered.length);
              eventPageIndex = Math.min(Math.max(eventPageIndex, 0), maxPage);
              if (liveEventRecords.length === 0) {
                body.innerHTML = `<tr><td colspan="7" class="muted">${escapeHtml(t('暂无原始事件；保持页面打开，SSE 或轮询 fallback 会继续等待 events.json / driver-events.jsonl。', 'No raw events yet; keep this page open while SSE or polling fallback waits for events.json / driver-events.jsonl.'))}</td></tr>`;
                updateEventPageStatus(0, 0, 0);
                renderSelectedEventSummary(null);
                return;
              }
              if (filtered.length === 0) {
                body.innerHTML = `<tr><td colspan="7" class="muted">${escapeHtml(t('当前严重度/类型/来源筛选无匹配；清除筛选可查看已缓冲原始事件。', 'No buffered raw events match the current severity/type/source filters; clear filters to view them.'))}</td></tr>`;
                updateEventPageStatus(0, 0, liveEventRecords.length);
                renderSelectedEventSummary(selectedEventRecord());
                return;
              }
              const start = eventPageIndex * eventPageSize;
              const pageRows = filtered.slice(start, start + eventPageSize);
              body.innerHTML = pageRows.map(record => renderEventRow(record)).join('');
              updateEventPageStatus(start + 1, Math.min(start + pageRows.length, filtered.length), filtered.length);
              renderSelectedEventSummary(selectedEventRecord());
            }

            function renderEventRow(record) {
              const ev = record.event;
              const pid = [ev.processId || '', ev.processName || ''].filter(Boolean).join(' / ');
              const data = formatEventData(ev.data);
              const summary = eventSummary(record);
              const selectedClass = record.key === selectedEventKey ? ' selected' : '';
              return `<tr class="event-row${selectedClass}" data-event-key="${escapeAttr(record.key)}" data-copy="${escapeAttr(summary)}">
                <td><span class="event-severity ${escapeAttr(record.severity)}" data-copy="${escapeAttr(eventSeverityLabel(record.severity))}">${escapeHtml(eventSeverityLabel(record.severity))}</span></td>
                <td>${cell(ev.timestamp)}</td>
                <td>${cell(ev.eventType)}</td>
                <td>${cell(ev.source)}</td>
                <td>${cell(pid)}</td>
                <td>${cell(ev.path)}</td>
                <td>${cell(data)}</td>
              </tr>`;
            }

            function renderEventFilterChips() {
              renderStaticFilterGroup('severityFilters', 'severity', severityFilters, activeSeverityFilter, record => record.severity);
              renderStaticFilterGroup('typeFilters', 'type', eventTypeFilters, activeTypeFilter, record => record.family);
              renderSourceFilterGroup();
            }

            function renderStaticFilterGroup(elementId, kind, filters, activeValue, selector) {
              const target = document.getElementById(elementId);
              if (!target) { return; }
              const counts = countBy(liveEventRecords, selector);
              target.innerHTML = filters.map(([value, zh, en]) => {
                const count = value === 'all' ? liveEventRecords.length : (counts.get(value) || 0);
                const label = `${t(zh, en)} ${count}`;
                const active = value === activeValue ? ' active' : '';
                return `<button class="filter-chip${active}" type="button" data-event-filter-kind="${escapeAttr(kind)}" data-event-filter-value="${escapeAttr(value)}" data-copy="${escapeAttr(label)}">${escapeHtml(label)}</button>`;
              }).join('');
            }

            function renderSourceFilterGroup() {
              const target = document.getElementById('sourceFilters');
              if (!target) { return; }
              const counts = countBy(liveEventRecords, record => record.source || t('未知来源', 'unknown'));
              const entries = Array.from(counts.entries())
                .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
                .slice(0, 8);
              if (activeSourceFilter !== 'all' && !counts.has(activeSourceFilter)) {
                activeSourceFilter = 'all';
              }
              const allLabel = `${t('全部', 'All')} ${liveEventRecords.length}`;
              const buttons = [`<button class="filter-chip${activeSourceFilter === 'all' ? ' active' : ''}" type="button" data-event-filter-kind="source" data-event-filter-value="all" data-copy="${escapeAttr(allLabel)}">${escapeHtml(allLabel)}</button>`];
              for (const [source, count] of entries) {
                const label = `${source || t('未知来源', 'unknown')} ${count}`;
                const active = source === activeSourceFilter ? ' active' : '';
                buttons.push(`<button class="filter-chip${active}" type="button" data-event-filter-kind="source" data-event-filter-value="${escapeAttr(source)}" data-copy="${escapeAttr(label)}">${escapeHtml(label)}</button>`);
              }
              target.innerHTML = buttons.join('');
            }

            function countBy(records, selector) {
              const map = new Map();
              for (const record of records) {
                const key = selector(record) || '';
                map.set(key, (map.get(key) || 0) + 1);
              }
              return map;
            }

            function filteredEventRecords() {
              return liveEventRecords.filter(record =>
                (activeSeverityFilter === 'all' || record.severity === activeSeverityFilter) &&
                (activeTypeFilter === 'all' || record.family === activeTypeFilter) &&
                (activeSourceFilter === 'all' || record.source === activeSourceFilter));
            }

            function maxEventPageIndex(count) {
              return Math.max(0, Math.ceil(count / eventPageSize) - 1);
            }

            function updateEventPageStatus(first, last, filteredCount) {
              const maxPage = maxEventPageIndex(filteredCount);
              const text = filteredCount > 0
                ? t(`原始事件分页：第 ${eventPageIndex + 1}/${maxPage + 1} 页，显示 ${first}-${last} / ${filteredCount}；已缓冲 ${liveEventRecords.length} / 上限 ${maxBufferedLiveEvents}。`, `Raw-event pagination: page ${eventPageIndex + 1}/${maxPage + 1}, showing ${first}-${last} / ${filteredCount}; buffered ${liveEventRecords.length} / cap ${maxBufferedLiveEvents}.`)
                : t(`原始事件分页：当前筛选 0 条；已缓冲 ${liveEventRecords.length} / 上限 ${maxBufferedLiveEvents}。`, `Raw-event pagination: current filter has 0 rows; buffered ${liveEventRecords.length} / cap ${maxBufferedLiveEvents}.`);
              const target = document.getElementById('eventPageStatus');
              target.textContent = text;
              target.setAttribute('data-copy', text);
            }

            function goEventPage(action) {
              const maxPage = maxEventPageIndex(filteredEventRecords().length);
              if (action === 'first') { eventPageIndex = 0; }
              else if (action === 'prev') { eventPageIndex = Math.max(0, eventPageIndex - 1); }
              else if (action === 'next') { eventPageIndex = Math.min(maxPage, eventPageIndex + 1); }
              else if (action === 'latest') { eventPageIndex = maxPage; }
              renderEventTable();
            }

            function setEventPageSize(value) {
              const parsed = Number(value);
              eventPageSize = [25, 50, 100].includes(parsed) ? parsed : 50;
              eventPageIndex = Math.min(eventPageIndex, maxEventPageIndex(filteredEventRecords().length));
              renderEventTable();
            }

            function setEventFilter(kind, value) {
              if (kind === 'severity') { activeSeverityFilter = value || 'all'; }
              if (kind === 'type') { activeTypeFilter = value || 'all'; }
              if (kind === 'source') { activeSourceFilter = value || 'all'; }
              eventPageIndex = 0;
              renderEventTable();
            }

            function clearEventFilters() {
              activeSeverityFilter = 'all';
              activeTypeFilter = 'all';
              activeSourceFilter = 'all';
              eventPageIndex = maxEventPageIndex(liveEventRecords.length);
              renderEventTable();
            }

            function selectEvent(key) {
              selectedEventKey = key || '';
              renderEventTable();
            }

            function selectedEventRecord() {
              return selectedEventKey ? liveEventRecords.find(record => record.key === selectedEventKey) || null : null;
            }

            function renderSelectedEventSummary(record) {
              const target = document.getElementById('selectedEventSummary');
              const text = record
                ? eventSummary(record)
                : t('尚未选择原始事件；点击表格行后可复制摘要。', 'No raw event is selected yet; click a table row to copy its summary.');
              target.textContent = text;
              target.setAttribute('data-copy', text);
            }

            function copySelectedEventSummary() {
              const record = selectedEventRecord();
              if (!record) {
                showToast(t('请先选择一条原始事件', 'Select one raw event first'));
                return;
              }
              copyText(eventSummary(record));
            }

            function eventSummary(record) {
              const ev = record.event;
              const pid = [ev.processId ? `pid=${ev.processId}` : '', ev.processName ? `process=${ev.processName}` : ''].filter(Boolean).join('; ');
              const path = ev.path ? `path=${ev.path}` : '';
              const data = formatEventData(ev.data, 6, 120);
              return [
                t('原始事件摘要', 'Raw event summary'),
                `severity=${eventSeverityLabel(record.severity)}`,
                `type=${ev.eventType || '-'}`,
                `source=${ev.source || '-'}`,
                `time=${ev.timestamp || '-'}`,
                pid,
                path,
                data ? `data=${data}` : ''
              ].filter(Boolean).join(' | ');
            }

            function eventSeverity(ev) {
              const data = ev?.data || {};
              const explicit = String(firstDataValue(data, ['severity', 'healthSeverity', 'backpressureSeverity', 'level', 'risk']) || '').toLowerCase();
              if (['critical', 'high', 'error', 'fatal'].includes(explicit)) { return 'error'; }
              if (['medium', 'warning', 'warn', 'degraded'].includes(explicit)) { return 'warning'; }
              const text = `${ev?.eventType || ''} ${ev?.source || ''}`.toLowerCase();
              if (/(fail|failed|failure|error|exception|read_error|parse_error)/.test(text)) { return 'error'; }
              if (/(timeout|missing|pending|empty|degraded|backpressure|skipped|unavailable)/.test(text)) { return 'warning'; }
              return 'info';
            }

            function eventSeverityLabel(severity) {
              if (severity === 'error') { return t('错误', 'Error'); }
              if (severity === 'warning') { return t('警告', 'Warning'); }
              return t('信息', 'Info');
            }

            function eventFamily(ev) {
              const type = String(ev?.eventType || '').toLowerCase();
              const source = String(ev?.source || '').toLowerCase();
              if (type.startsWith('live.events.') || type.includes('status') || type.includes('health') || type.includes('parse_error') || type.includes('read_error')) { return 'diagnostic'; }
              if (type.startsWith('driver.') || type.startsWith('r0collector.') || source.includes('driver') || source.includes('r0')) { return 'driver'; }
              if (type.startsWith('process.') || type.startsWith('image.')) { return 'process'; }
              if (type.startsWith('file.')) { return 'file'; }
              if (type.startsWith('registry.')) { return 'registry'; }
              if (type.startsWith('network.') || type.startsWith('dns.') || type.startsWith('http.') || type.startsWith('tls.') || type.startsWith('pcap.') || type.startsWith('packet_capture.') || type.startsWith('packet-capture.')) { return 'network'; }
              if (type.startsWith('artifact.') || type.startsWith('screenshot.') || type.startsWith('memory_dump.') || type.startsWith('memory-dump.') || type.startsWith('guest.events.') || type.startsWith('collection.')) { return 'artifact'; }
              return 'diagnostic';
            }

            function eventSourceValue(ev) {
              return String(ev?.source || t('未知来源', 'unknown'));
            }

            function firstDataValue(data, keys) {
              for (const key of keys) {
                if (data && Object.prototype.hasOwnProperty.call(data, key) && data[key] !== undefined && data[key] !== null && data[key] !== '') {
                  return data[key];
                }
              }
              return '';
            }

            function formatLiveStreamDetail(transportLabel, snapshot, buffered, visible, sourceStatus) {
              const sourceText = sourceStatus || ((snapshot.sources || []).length
                ? t(`事件来源 ${(snapshot.sources || []).length} 个。`, `${(snapshot.sources || []).length} event source(s).`)
                : t('尚未发现事件来源；页面会继续等待回收 events.json / driver-events.jsonl。', 'No event sources found yet; the page will keep waiting for events.json / driver-events.jsonl collection.'));
              const modeText = String(transportLabel || '').includes('SSE')
                ? t('当前传输：SSE 原始事件流。', 'Current transport: SSE raw event stream.')
                : t('当前传输：轮询 fallback；SSE 不可用时这是预期兜底路径。', 'Current transport: polling fallback; this is expected when SSE is unavailable.');
              const cursorText = t(`服务端 totalEvents=${snapshot.totalEvents || 0}，nextOffset=${eventOffset}，hasMore=${Boolean(snapshot.hasMore)}。`, `Server totalEvents=${snapshot.totalEvents || 0}, nextOffset=${eventOffset}, hasMore=${Boolean(snapshot.hasMore)}.`);
              const viewText = t(`页面已缓冲 ${buffered}/${maxBufferedLiveEvents} 条，当前筛选显示 ${visible} 条；命令、stdout、stderr、PowerShell 字段默认隐藏。`, `Page buffered ${buffered}/${maxBufferedLiveEvents} rows and the current filter shows ${visible}; command, stdout, stderr, and PowerShell fields are hidden by default.`);
              return [modeText, cursorText, viewText, sourceText].filter(Boolean).join(' ');
            }

            function summarizeSourceStatus(events) {
              const statuses = [];
              for (const ev of events || []) {
                if (!String(ev?.eventType || '').startsWith('live.events.source_status')) { continue; }
                const data = ev.data || {};
                const name = firstDataValue(data, ['sourceFileName', 'fileName', 'path']) || ev.path || t('未知来源', 'unknown source');
                const status = firstDataValue(data, ['status', 'readinessState']) || t('未知状态', 'unknown');
                const eventCount = firstDataValue(data, ['eventCount', 'recordCount']) || '0';
                const parseErrors = firstDataValue(data, ['parseErrorCount']) || '0';
                const partialLines = firstDataValue(data, ['partialLineCount']) || '0';
                statuses.push(`${name}: status=${status}, events=${eventCount}, parseErrors=${parseErrors}, partialLines=${partialLines}`);
              }
              if (!statuses.length) { return ''; }
              return t(`事件来源诊断：${statuses.slice(0, 3).join('；')}${statuses.length > 3 ? '；…' : ''}。`, `Source diagnostics: ${statuses.slice(0, 3).join('; ')}${statuses.length > 3 ? '; ...' : ''}.`);
            }

            function sanitizeEventData(data) {
              const sanitized = {};
              for (const [key, value] of Object.entries(data || {})) {
                if (isHiddenTelemetryKey(key)) { continue; }
                sanitized[key] = value;
              }
              return sanitized;
            }

            function formatEventData(data, maxPairs = 12, maxValueLength = 180) {
              if (!data || typeof data !== 'object') { return ''; }
              const entries = Object.entries(sanitizeEventData(data));
              const hiddenTechnical = Object.keys(data).filter(isHiddenTelemetryKey).length;
              if (!entries.length && hiddenTechnical === 0) { return ''; }
              const bounded = {};
              for (const [key, value] of entries.slice(0, maxPairs)) {
                bounded[key] = boundedText(value, maxValueLength);
              }
              const omitted = Math.max(0, entries.length - maxPairs);
              if (omitted > 0) { bounded.__omittedDataPairs = String(omitted); }
              if (hiddenTechnical > 0) { bounded.__hiddenTechnicalFields = String(hiddenTechnical); }
              return JSON.stringify(bounded);
            }

            function boundedText(value, maxLength) {
              const text = value == null ? '' : String(value);
              return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
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
              if (!response.ok) { throw new Error(formatHttpError(label, response, payload)); }
              return payload;
            }

            function formatHttpError(label, response, payload) {
              const statusText = response.statusText ? ` ${response.statusText}` : '';
              const detail = localizeServerMessage(extractErrorMessage(payload) || t('服务器未返回错误详情。', 'No error detail was returned by the server.'));
              const traceId = payload && (payload.traceId || payload.requestId);
              const traceText = traceId ? (currentLanguage === 'en' ? `, trace ${traceId}` : `，跟踪 ID ${traceId}`) : '';
              return `${label} ${t('失败', 'failed')} (HTTP ${response.status}${statusText}${traceText}): ${detail} ${t('下一步：', 'Next step: ')}${suggestNextStep(label, response, payload)}`;
            }

            function extractErrorMessage(payload) {
              if (!payload) { return ''; }
              if (typeof payload === 'string') { return payload; }
              if (payload.error) {
                if (typeof payload.error === 'string') { return payload.error; }
                if (payload.error.message) { return payload.error.message; }
              }
              if (payload.title || payload.detail) { return [payload.title, payload.detail].filter(Boolean).join(': '); }
              if (payload.message) { return payload.message; }
              if (payload.errors) {
                return Object.entries(payload.errors)
                  .map(([field, values]) => `${field}: ${Array.isArray(values) ? values.join('; ') : values}`)
                  .join(' | ');
              }
              if (payload.raw) { return payload.raw; }
              return '';
            }

            function suggestNextStep(label, response, payload) {
              const labelText = String(label || '');
              const code = String(payload?.error?.code || payload?.code || payload?.title || '').toLowerCase();
              if (response.status === 404 || code.includes('not_found') || code.includes('notfound')) {
                return t('返回主界面刷新近期任务，确认此 job 仍在当前 Web Host；如任务存在，请重新打开监控页。', 'Go back to the dashboard and refresh recent jobs to confirm this job still exists in this Web host; if it exists, reopen the monitor.');
              }

              if (/VirusTotal/i.test(labelText)) {
                return t('打开设置页确认 API Key；缺失、限速或超时不会阻断沙箱分析。', 'Open Settings to confirm the API key; missing keys, rate limits, or timeouts do not block sandbox analysis.');
              }

              if (/证据|artifact/i.test(labelText)) {
                return t('等待采集回收后重试，或打开报告链接查看当前已生成的证据。', 'Wait for collection recovery and retry, or open the report link to view evidence already generated.');
              }

              if (/进度|后台|runbook|progress|background/i.test(labelText)) {
                return t('打开执行流程页查看失败阶段；本页会继续轮询安全进度快照。', 'Open the execution-flow page to inspect the failed stage; this page will keep polling UI-safe progress snapshots.');
              }

              if (/事件|events/i.test(labelText)) {
                return t('保持本页打开并稍后手动刷新；若仍无事件，请检查 events.json 或 driver-events.jsonl 是否已回收。', 'Keep this page open and refresh again shortly; if events still do not appear, check whether events.json or driver-events.jsonl has been recovered.');
              }

              return t('稍后重试；如果重复失败，请复制本状态并打开执行流程页排障。', 'Retry shortly; if it repeats, copy this status and open the execution-flow page for troubleshooting.');
            }

            function setStatus(message, isError) {
              const status = document.getElementById('status');
              status.className = `status ${isError ? 'error' : 'ok'}`;
              status.textContent = message;
              status.setAttribute('data-copy', message || '');
            }

            function setStreamFallbackStatus(message, tone) {
              const target = document.getElementById('streamFallbackStatus');
              if (!target) { return; }
              const normalizedTone = ['ok', 'fallback', 'error'].includes(tone) ? tone : '';
              target.className = `stream-status ${normalizedTone}`.trim();
              target.textContent = message || t('原始事件流状态：等待连接。', 'Raw event stream status: waiting to connect.');
              target.setAttribute('data-copy', target.textContent);
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
            document.addEventListener('click', event => {
              const filter = event.target.closest ? event.target.closest('[data-event-filter-kind]') : null;
              if (filter) {
                setEventFilter(filter.getAttribute('data-event-filter-kind'), filter.getAttribute('data-event-filter-value'));
                return;
              }
              const row = event.target.closest ? event.target.closest('tr[data-event-key]') : null;
              if (row) {
                selectEvent(row.getAttribute('data-event-key'));
              }
            });
            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest('[data-copy], tr[data-event-key], code, pre, input, p, li, h1, h2, h3, label, span, a, button, td, th, section, article, .metric, .artifact-card, .cockpit-card, .step-card, .stream-status, .selected-event-summary') : null;
              if (!target) { return; }
              const value = target.getAttribute('data-copy') || target.value || target.innerText || target.textContent || '';
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
            renderOperatorCockpit();
            refreshVirusTotal();
            startJobSnapshotPolling();
            startRunbookProgressStream();
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

    private static string FormatAnalysisStatus(AnalysisStatus status)
    {
        return status switch
        {
            AnalysisStatus.Queued => "排队中",
            AnalysisStatus.Planning => "规划中",
            AnalysisStatus.Planned => "已规划",
            AnalysisStatus.Running => "运行中",
            AnalysisStatus.Completed => "已完成",
            AnalysisStatus.Failed => "失败",
            _ => status.ToString()
        };
    }
}
