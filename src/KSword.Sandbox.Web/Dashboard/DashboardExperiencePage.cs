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
            .lang-toggle { background: rgba(255,255,255,.22); border: 2px solid rgba(255,255,255,.72); box-shadow:none; letter-spacing: .02em; white-space: nowrap; }
            .lang-toggle:hover { background: rgba(255,255,255,.32); }
            .topnav { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
            .topnav a { border: 1px solid rgba(255,255,255,.35); border-radius:2px; color: white; font-weight: 700; padding: 7px 11px; text-decoration: none; }
            main { max-width: 1220px; margin: 24px auto; padding: 0 24px 48px; }
            section { background: rgba(255,255,255,.96); border: 1px solid var(--line); border-radius:2px; box-shadow:none; margin-bottom: 18px; padding: 22px; }
            label { display: block; font-weight: 700; margin: 14px 0 6px; }
            input { box-sizing: border-box; width: 100%; border: 1px solid #c7dff7; border-radius:2px; padding: 10px 12px; font: inherit; }
            input[type="checkbox"] { width: auto; }
            button, a.buttonlink { border: 0; border-radius:2px; background: var(--blue); color: white; cursor: pointer; display: inline-block; font-weight: 800; margin-top: 14px; padding: 10px 16px; text-decoration: none; }
            button.secondary { background: #334155; }
            a.buttonlink.secondary { background: #334155; }
            button:disabled { background: #94a3b8; cursor: wait; }
            button.copy-btn { background: #e2e8f0; border: 1px solid #cbd5e1; color: #334155; font-size: 12px; margin: 0 0 0 6px; padding: 5px 8px; vertical-align: middle; }
            button.copy-btn:hover { background: #cbd5e1; }
            table { border-collapse: collapse; width: 100%; margin-top: 16px; }
            td, th { border-bottom: 1px solid #e5e7eb; padding: 9px; text-align: left; vertical-align: top; }
            th { color: #475569; font-size: 13px; text-transform: uppercase; }
            code, pre { background: #f1f5f9; border-radius:2px; }
            code { padding: 2px 5px; }
            pre { overflow: auto; padding: 14px; white-space: pre-wrap; }
            [data-copy], td, th, code, pre { cursor: copy; }
            [data-copy]:hover, td:hover, th:hover, code:hover, pre:hover { outline: 1px dashed #93c5fd; outline-offset: 2px; }
            .copy-field { align-items: center; display: inline-flex; flex-wrap: wrap; gap: 4px; max-width: 100%; }
            .copy-field code { overflow-wrap: anywhere; word-break: break-word; }
            .artifact-table td:nth-child(2) { word-break: break-word; }
            .button-row { align-items: center; display: flex; flex-wrap: wrap; gap: 8px; }
            .button-row button, .button-row a.buttonlink { margin-top: 8px; }
            .mini-form { background: #f8fafc; border: 1px dashed #cbd5e1; border-radius:2px; margin: 10px 0; padding: 12px; }
            .toast { background: #0f172a; border-radius:2px; bottom: 22px; color: white; left: 50%; opacity: 0; padding: 10px 16px; pointer-events: none; position: fixed; transform: translate(-50%, 12px); transition: opacity .15s ease, transform .15s ease; z-index: 20; }
            .toast.visible { opacity: .96; transform: translate(-50%, 0); }
            .grid { display: grid; gap: 18px; grid-template-columns: repeat(3, 1fr); }
            .hint { color: var(--muted); font-size: 14px; }
            .status { margin-top: 12px; min-height: 24px; }
            .error { color: #b91c1c; }
            .ok { color: #047857; }
            .pathbox { background: #f8fbff; border: 1px solid var(--line); border-radius:2px; margin-top: 10px; padding: 12px; }
            .callout { background:#f7fbff; border:1px solid rgba(67,160,255,.30); border-radius:2px; margin-top:12px; padding:12px 14px; }
            .callout strong { display:block; margin-bottom:4px; }
            .report-notice { background:#ecfdf5; border:1px solid #86efac; border-radius:2px; color:#065f46; margin:12px 0; padding:14px; }
            .report-notice[hidden] { display:none; }
            .report-notice p { margin:6px 0; }
            .countdown { background:#fff7ed; border:1px solid #fdba74; color:#9a3412; font-weight:800; padding:8px 10px; }
            .report-entry { align-items:center; background:#f0fdf4; border:1px solid #86efac; border-radius:2px; display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; padding:12px; }
            .report-entry a.buttonlink { margin-top:0; }
            .report-entry .hint { margin:0; }
            .progress-links { margin:6px 0 10px; }
            .pill { background: #e7f3ff; border:1px solid rgba(67,160,255,.35); border-radius:2px; color: #075985; display: inline-block; font-size: 12px; font-weight: 800; padding: 4px 9px; }
            .pill.ready { background:#dcfce7; border-color:#86efac; color:#166534; }
            .operator-hero { background:linear-gradient(135deg,#f8fbff,#eef7ff); border-left:4px solid var(--blue); }
            .operator-hero h2 { margin-top:0; }
            .operator-hero-grid { display:grid; gap:12px; grid-template-columns:1.15fr .85fr; margin-top:14px; }
            .operator-brief { background:white; border:1px solid var(--line); padding:14px; }
            .operator-brief strong { display:block; font-size:15px; margin-bottom:6px; }
            .operator-flow { display:grid; gap:8px; grid-template-columns:repeat(3,minmax(0,1fr)); }
            .operator-step { background:white; border:1px solid #dbeafe; border-left:3px solid var(--blue); padding:10px; }
            .operator-step b { display:block; margin-bottom:4px; }
            .readiness-strip { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0 4px; }
            .readiness-chip { background:#f8fafc; border:1px solid #cbd5e1; color:#334155; cursor:copy; display:inline-flex; flex-direction:column; gap:2px; max-width:260px; padding:8px 10px; }
            .readiness-chip b { font-size:12px; }
            .readiness-chip span { font-size:12px; line-height:1.35; overflow-wrap:anywhere; }
            .readiness-chip.good { background:#ecfdf5; border-color:#86efac; color:#065f46; }
            .readiness-chip.warn { background:#fff7ed; border-color:#fdba74; color:#9a3412; }
            .readiness-chip.neutral { background:#eef7ff; border-color:#93c5fd; color:#075985; }
            .readiness-chip.error { background:#fef2f2; border-color:#fecaca; color:#991b1b; }
            .upload-card { background:white; border:1px solid var(--line); border-left:4px solid var(--blue); padding:14px; }
            .upload-dropzone { background:#f8fbff; border:2px dashed #93c5fd; cursor:pointer; margin:12px 0; padding:16px; transition:background .15s ease,border-color .15s ease; }
            .upload-dropzone.dragging { background:#e7f3ff; border-color:var(--blue-dark); }
            .upload-dropzone input { background:white; cursor:pointer; margin-top:8px; }
            .selected-sample { background:#f8fbff; border:1px solid var(--line); margin:10px 0 0; min-height:44px; padding:10px; }
            .selected-sample.empty { border-style:dashed; color:var(--muted); }
            .preset-row { display:flex; flex-wrap:wrap; gap:8px; margin:10px 0; }
            .preset-row button { background:#e7f3ff; border:1px solid rgba(67,160,255,.45); color:#075985; margin-top:0; padding:8px 10px; }
            .primary-cta { align-items:center; background:linear-gradient(90deg,var(--blue-dark),var(--blue)); display:inline-flex; font-size:16px; gap:8px; justify-content:center; min-height:46px; min-width:320px; }
            .primary-cta::before { content:"▶"; font-size:13px; }
            .primary-cta:disabled::before { content:"…"; }
            .microcopy { color:#475569; font-size:13px; line-height:1.5; margin:8px 0 0; }
            .workspace-tabs { align-items:center; display:flex; flex-wrap:wrap; gap:10px; margin-bottom:18px; }
            .workspace-tab { background:#e7f3ff; border:1px solid rgba(67,160,255,.35); color:#075985; margin-top:0; }
            .workspace-tab.active { background:#0B6FCC; color:white; box-shadow:none; }
            .workspace-panel[hidden] { display:none; }
            .tabs { display:flex; flex-wrap:wrap; gap:8px; margin:16px 0 10px; }
            .tab-button { background:#e7f3ff; border:1px solid rgba(67,160,255,.35); color:#075985; margin-top:0; }
            .tab-button.active { background:var(--blue); color:white; }
            .tab-panel { display:none; border:1px solid var(--line); border-radius:2px; background:#f8fbff; padding:16px; }
            .tab-panel.active { display:block; }
            .vm-grid { display:grid; gap:12px; grid-template-columns:repeat(3,minmax(0,1fr)); }
            .config-card { background:#f8fbff; border:1px solid var(--line); border-radius:2px; padding:12px; }
            .config-card h4 { margin:0 0 8px; }
            .field-hint { color:var(--muted); font-size:12px; line-height:1.45; margin:5px 0 0; }
            .toggle-stack { display:grid; gap:8px; margin-top:8px; }
            .toggle-card { background:white; border:1px solid #e5edf6; border-radius:2px; padding:9px; }
            .toggle-card label { align-items:flex-start; display:flex; gap:8px; margin:0; }
            .toggle-card input { margin-top:3px; }
            .readonly-toggle { opacity:.82; }
            .config-summary { display:flex; flex-wrap:wrap; gap:6px; margin-top:12px; }
            .config-summary .pill { max-width:100%; overflow-wrap:anywhere; }
            .preset-actions { align-items:center; display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
            .preset-actions button { margin-top:0; }
            details.vm-config { background:#f8fbff; border:1px dashed #b9d7f3; border-radius:2px; margin-top:16px; padding:12px 14px; }
            details.vm-config summary { cursor:pointer; font-weight:800; }
            .job-card { border-left:5px solid var(--blue); }
            .job-summary { display:grid; gap:12px; grid-template-columns:repeat(4,minmax(0,1fr)); margin-top:12px; }
            .metric { background:#f8fbff; border:1px solid var(--line); border-radius:2px; padding:12px; }
            .metric strong { color:var(--muted); display:block; font-size:12px; margin-bottom:6px; }
            .progress-box { background:#f8fbff; border:1px solid var(--line); border-radius:2px; margin-top:14px; padding:14px; }
            .progress-box.running { border-color:rgba(67,160,255,.55); box-shadow:none; }
            .progress-box.completed { border-color:#86efac; }
            .progress-box.failed { border-color:#fdba74; }
            .progress-head { align-items:center; display:flex; flex-wrap:wrap; gap:8px; justify-content:space-between; margin-bottom:8px; }
            .progress-meta { color:#075985; font-size:12px; font-weight:800; }
            .progress-bar { background:#dbeafe; border-radius:2px; height:12px; overflow:hidden; }
            .progress-fill { background:linear-gradient(90deg,var(--blue),#7dd3fc); height:100%; width:0%; transition:width .25s ease; }
            .progress-fill.failed { background:linear-gradient(90deg,#f97316,#ef4444); }
            .progress-facts { display:grid; gap:10px; grid-template-columns:repeat(3,minmax(0,1fr)); margin-top:10px; }
            .progress-facts .metric { margin-top:0; }
            .stages { display:grid; gap:8px; grid-template-columns:repeat(4,minmax(0,1fr)); margin-top:12px; }
            .stage { background:white; border:1px solid #e5edf6; border-radius:2px; color:#64748b; padding:9px; }
            .stage small { color:#94a3b8; display:block; font-size:11px; margin-top:2px; }
            .stage.active { border-color:var(--blue); box-shadow:none; color:#075985; font-weight:800; position:relative; }
            .stage.active::after { animation:pulse 1.2s ease-in-out infinite; background:var(--blue); border-radius:2px; content:""; height:8px; position:absolute; right:10px; top:10px; width:8px; }
            .stage.done { background:#ecfdf5; border-color:#bbf7d0; color:#047857; }
            .stage.failed { background:#fff7ed; border-color:#fdba74; color:#c2410c; font-weight:800; }
            .recent-job-list { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); margin-top:14px; }
            .recent-job-card { background:#f8fbff; border:1px solid var(--line); border-radius:2px; padding:14px; }
            .recent-job-card h3 { margin:0 0 8px; }
            .recent-job-meta { display:flex; flex-wrap:wrap; gap:6px; margin:8px 0; }
            @keyframes pulse { 0%,100% { opacity:.35; transform:scale(.82); } 50% { opacity:1; transform:scale(1.18); } }
            .runbook-step-grid { display:grid; gap:8px; grid-template-columns:repeat(4,minmax(0,1fr)); margin-top:10px; }
            .runbook-step { background:white; border:1px solid #e5edf6; border-radius:2px; padding:8px; }
            .runbook-step b { display:block; font-size:12px; margin-bottom:3px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
            .runbook-step small { color:#64748b; display:block; font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
            .runbook-step.pending { color:#64748b; }
            .runbook-step.running { border-color:var(--blue); box-shadow:none; color:#075985; font-weight:800; }
            .runbook-step.completed, .runbook-step.skipped { background:#ecfdf5; border-color:#bbf7d0; color:#047857; }
            .runbook-step.failed, .runbook-step.canceled { background:#fff7ed; border-color:#fdba74; color:#c2410c; font-weight:800; }
            .runbook-progress-details { margin-top:10px; }
            .runbook-progress-details summary { cursor:pointer; color:#075985; font-weight:800; }
            .compact-details { margin-top:12px; }
            .compact-details summary { cursor:pointer; color:#075985; font-weight:800; }
            .empty { border:1px dashed #b9d7f3; border-radius:2px; color:var(--muted); padding:14px; }
            .status-failed { color: #b91c1c; font-weight: 700; }
            .status-ok { color: #047857; font-weight: 700; }
            .flat-inner, .tab-panel, details.vm-config, .mini-form, .pathbox, .callout, .report-notice, .report-entry, .progress-box, .metric, .stage, .runbook-step, .recent-job-card { box-shadow:none; border-radius:2px; }
            .tab-panel, details.vm-config, .mini-form, .pathbox, .callout, .report-notice, .report-entry { background:transparent; border-color:var(--line); }
            .metric { background:transparent; border:0; border-left:3px solid var(--blue); padding:10px 12px; }
            .progress-box { background:transparent; border:1px solid var(--line); border-left:3px solid var(--blue); }
            .stage, .runbook-step { background:transparent; border:0; border-left:3px solid #e5edf6; padding:8px 10px; }
            .stage.active, .runbook-step.running { border-left-color:var(--blue); box-shadow:none; }
            .stage.done, .runbook-step.completed, .runbook-step.skipped { border-left-color:#22c55e; }
            .stage.failed, .runbook-step.failed, .runbook-step.canceled { border-left-color:#f97316; }
            .recent-job-card { background:transparent; border:1px solid var(--line); border-left:3px solid var(--blue); }
            .workspace-tabs, .tabs, .button-row { gap:6px; }

            /* Square, flat operator theme: keep visual nesting shallow. */
            section, article, .metric, .pill, button, a.button, a.buttonlink, input, code, pre, .pathbox, .callout, .report-notice, .report-entry, .countdown, .workspace-tab, .tab-button, .tab-panel, details, .config-card, .toggle-card, .progress-box, .progress-bar, .progress-fill, .stage, .recent-job-card, .runbook-step, .empty, .table-wrap, .step-card, .report-ready, .toast, .num { border-radius: 0 !important; }
            section, article, .metric, .pathbox, .callout, .report-notice, .report-entry, .tab-panel, .config-card, .toggle-card, .progress-box, .stage, .recent-job-card, .runbook-step, .step-card, .report-ready { box-shadow: none !important; }
            .pill, button, a.button, a.buttonlink { box-shadow: none !important; }
            @media (max-width: 980px) { .grid,.vm-grid,.job-summary,.stages,.progress-facts,.operator-hero-grid,.operator-flow { grid-template-columns: 1fr; } header { padding:24px; } .primary-cta { min-width:0; width:100%; } }
          </style>
        </head>
        <body>
          <header>
            <div class="header-row">
              <div>
                <h1 data-zh="KSword 沙箱主机" data-en="KSword Sandbox Host">KSword 沙箱主机</h1>
              <p data-zh="上传样本后会保存到本机、创建安全计划并尝试提交 VM 动态分析；随后进入独立监控页查看启动状态、真实进度和报告入口，原始事件与下载列表集中在监控页。" data-en="After upload, the UI stores the sample locally, creates a safe plan, and attempts to submit VM dynamic analysis. It then enters the standalone monitor for start status, real progress, and report links; raw events and downloads stay on the monitor page.">上传样本后会保存到本机、创建安全计划并尝试提交 VM 动态分析；随后进入独立监控页查看启动状态、真实进度和报告入口，原始事件与下载列表集中在监控页。</p>
                <p><span class="pill" data-zh="提示：右键路径、表格值、证据字段和执行流程视图可复制。" data-en="Tip: right-click paths, table values, evidence fields, and execution-flow details to copy.">提示：右键路径、表格值、证据字段和执行流程视图可复制。</span></p>
              </div>
              <button class="secondary lang-toggle" type="button" onclick="toggleLanguage()" aria-label="语言切换 / Language switch" data-zh="语言：中文 ⇄ English" data-en="Language: English ⇄ 中文">语言：中文 ⇄ English</button>
            </div>
            <nav class="topnav" aria-label="控制台导航 / Dashboard navigation">
              <a href="#workspace-plan" onclick="selectWorkspaceTab('plan')" data-zh="上传 / 配置" data-en="Upload / config">上传 / 配置</a>
              <a href="#workspace-analysis" onclick="selectWorkspaceTab('analysis')" data-zh="进度" data-en="Progress">进度</a>
              <a href="#workspace-results" onclick="selectWorkspaceTab('results')" data-zh="报告" data-en="Reports">报告</a>
              <a href="/settings" data-zh="设置 / VM / VirusTotal" data-en="Settings / VM / VirusTotal">设置 / VM / VirusTotal</a>
            </nav>
          </header>
          <main>
            <div class="workspace-tabs" role="tablist" aria-label="上传、进度与报告 / Upload progress reports">
              <button id="workspace-tab-plan" class="workspace-tab active" type="button" role="tab" aria-selected="true" aria-controls="workspace-plan" onclick="selectWorkspaceTab('plan')" data-zh="1. 上传 / 配置" data-en="1. Upload / config">1. 上传 / 配置</button>
              <button id="workspace-tab-analysis" class="workspace-tab" type="button" role="tab" aria-selected="false" aria-controls="workspace-analysis" onclick="selectWorkspaceTab('analysis')" data-zh="2. 进度" data-en="2. Progress">2. 进度</button>
              <button id="workspace-tab-results" class="workspace-tab" type="button" role="tab" aria-selected="false" aria-controls="workspace-results" onclick="selectWorkspaceTab('results')" data-zh="3. 报告" data-en="3. Reports">3. 报告</button>
            </div>
            <div id="workspace-plan" class="workspace-panel active" role="tabpanel" aria-labelledby="workspace-tab-plan">
            <section class="operator-hero" id="operator-start">
              <h2 data-zh="从这里开始：上传后提交 VM 分析" data-en="Start here: upload and submit VM analysis">从这里开始：上传后提交 VM 分析</h2>
              <p class="hint" data-zh="首屏按云沙箱操作习惯组织：先选择样本，再看 VM / VirusTotal / 证据采集就绪状态，最后点击一个主按钮。任务创建后会打开动态监控页确认后台接管状态和真实进度，不需要再找“启动”按钮。" data-en="The first screen follows a polished cloud-sandbox flow: choose a sample, review VM / VirusTotal / evidence readiness, then press one primary button. After the job is created, the dynamic monitor opens to confirm background handoff and real progress; no extra Start button hunting.">首屏按云沙箱操作习惯组织：先选择样本，再看 VM / VirusTotal / 证据采集就绪状态，最后点击一个主按钮。任务创建后会打开动态监控页确认后台接管状态和真实进度，不需要再找“启动”按钮。</p>
              <div id="operatorReadinessChips" class="readiness-strip" data-copy="等待配置加载 / waiting for readiness" data-copy-label="operator readiness summary"></div>
              <div class="operator-hero-grid">
                <div class="operator-brief" data-copy="KSword WebUI 一键分析：上传 EXE、生成计划、提交 VM、打开动态监控；样本留在本机，VT 只做 hash-only 查询 / one-click run: upload EXE, plan, start VM, open live monitor">
                  <strong data-zh="本地安全边界" data-en="Local safety boundary">本地安全边界</strong>
                  <span data-zh="样本只保存到本机 runtime root；VirusTotal 只查 SHA-256，不上传样本字节。若 VT 未配置、未收录或调用失败，只作为页面静默状态，主流程继续。" data-en="Samples are saved only to the local runtime root; VirusTotal performs SHA-256 lookup only and never uploads sample bytes. If VT is missing, not found, or fails, it remains a quiet page status and the main flow continues.">样本只保存到本机 runtime root；VirusTotal 只查 SHA-256，不上传样本字节。若 VT 未配置、未收录或调用失败，只作为页面静默状态，主流程继续。</span>
                </div>
                <div class="operator-flow" aria-label="上传执行路径 / Upload execution path">
                  <div class="operator-step" data-copy="1. 选择本机 EXE / Choose local EXE"><b data-zh="1. 选择 EXE" data-en="1. Choose EXE">1. 选择 EXE</b><span data-zh="支持点击或拖拽到上传区域。" data-en="Click or drag into the upload zone.">支持点击或拖拽到上传区域。</span></div>
                  <div class="operator-step" data-copy="2. 复核 VM / VT / 证据就绪态 / Review VM / VT / artifact readiness"><b data-zh="2. 看就绪态" data-en="2. Review readiness">2. 看就绪态</b><span data-zh="VM、检查点、R0、VT 和产物选项都可右键复制。" data-en="VM, checkpoint, R0, VT, and artifact options are right-click copyable.">VM、检查点、R0、VT 和产物选项都可右键复制。</span></div>
                  <div class="operator-step" data-copy="3. 提交分析并打开监控 / Submit analysis and open monitor"><b data-zh="3. 提交分析" data-en="3. Submit analysis">3. 提交分析</b><span data-zh="提交后打开动态监控页查看启动状态和真实进度。" data-en="Submission opens the dynamic monitor for start status and real progress.">提交后打开动态监控页查看启动状态和真实进度。</span></div>
                </div>
              </div>
            </section>
            <section id="plan">
              <h2 data-zh="上传与配置" data-en="Upload and configuration">上传与配置</h2>
              <p class="hint"><span data-zh="请选择一种提交方式：上传 EXE 会创建任务、尝试启动动态分析并打开监控；选择已有路径或扫描目录会先生成可复核计划。" data-en="Choose one submission method: upload creates a job, attempts to start dynamic analysis, and opens the monitor; existing path and folder scan create a reviewable plan first.">请选择一种提交方式：上传 EXE 会创建任务、尝试启动动态分析并打开监控；选择已有路径或扫描目录会先生成可复核计划。</span></p>
              <input id="duration" type="hidden" value="120">
              <div class="tabs" role="tablist" aria-label="三种提交方式 / Three submission methods">
                <button id="tab-upload" class="tab-button active" type="button" role="tab" aria-selected="true" aria-controls="panel-upload" onclick="selectPlanTab('upload')" data-zh="上传 .exe → 自动分析并打开监控" data-en="Upload .exe → auto analyze and open monitor">上传 .exe → 自动分析并打开监控</button>
                <button id="tab-path" class="tab-button" type="button" role="tab" aria-selected="false" aria-controls="panel-path" onclick="selectPlanTab('path')" data-zh="选择已有路径" data-en="Existing path">选择已有路径</button>
                <button id="tab-scan" class="tab-button" type="button" role="tab" aria-selected="false" aria-controls="panel-scan" onclick="selectPlanTab('scan')" data-zh="扫描目录" data-en="Scan folder">扫描目录</button>
              </div>
              <div id="panel-upload" class="tab-panel active" role="tabpanel" aria-labelledby="tab-upload">
                  <div class="upload-card">
                    <h3 data-zh="一键动态分析" data-en="One-click dynamic analysis">一键动态分析</h3>
                    <p class="hint" data-zh="保存文件、生成可检查计划、尝试提交后台虚拟机分析，然后当前页面进入动态监控页；证据/下载（Artifacts）、原始事件和 VirusTotal 均在该独立页查看。" data-en="Stores the file, creates a reviewable plan, attempts to submit background VM analysis, then redirects this page into the dynamic monitor; artifacts/downloads, raw events, and VirusTotal live on that standalone page.">保存文件、生成可检查计划、尝试提交后台虚拟机分析，然后当前页面进入动态监控页；证据/下载（Artifacts）、原始事件和 VirusTotal 均在该独立页查看。</p>
                    <div id="uploadDropZone" class="upload-dropzone" data-copy="上传区域：点击或拖拽 .exe / Upload zone: click or drag .exe" data-copy-label="upload drop zone">
                      <label for="sampleUpload" data-zh="可执行文件（.exe）" data-en="Executable file (.exe)">可执行文件（.exe）</label>
                      <input id="sampleUpload" type="file" accept=".exe,application/vnd.microsoft.portable-executable,application/octet-stream" data-copy-label="selected sample">
                      <p class="microcopy" data-zh="当前只接受 .exe。选择后下方会显示文件名、大小、运行时长和产物采集摘要；这些可见字段均支持右键复制。" data-en="Only .exe files are accepted for now. After selection, file name, size, duration, and artifact collection summary are shown below; visible fields support right-click copy.">当前只接受 .exe。选择后下方会显示文件名、大小、运行时长和产物采集摘要；这些可见字段均支持右键复制。</p>
                    </div>
                    <div id="selectedSampleSummary" class="selected-sample empty" data-copy="尚未选择样本 / no sample selected" data-copy-label="selected sample summary"></div>
                    <label for="uploadDuration" data-zh="分析时长（秒）" data-en="Analysis duration, seconds">分析时长（秒）</label>
                    <input id="uploadDuration" type="number" min="1" max="900" value="120" data-copy-label="analysis duration">
                    <p id="durationHint" class="field-hint" data-copy="" data-copy-label="analysis duration hint" data-zh="后端会按配置限制分析时长；本次任务值会随上传一起提交；勾选“不限制运行时间”时会改用无限制语义。" data-en="The backend clamps bounded analysis duration by config; this per-job value is submitted with upload. When No runtime limit is checked, the request uses unlimited semantics.">后端会按配置限制分析时长；本次任务值会随上传一起提交；勾选“不限制运行时间”时会改用无限制语义。</p>
                    <div class="preset-row" aria-label="样本运行预设 / Sample run presets">
                      <button type="button" onclick="applySamplePreset('quick')" data-copy="快速观察：30s，关闭敏感产物采集 / Quick observe: 30s, sensitive artifact collection off" data-zh="快速观察 30s" data-en="Quick 30s">快速观察 30s</button>
                      <button type="button" onclick="applySamplePreset('standard')" data-copy="标准动态：120s，落地文件+截图+PCAP / Standard dynamic: 120s, dropped files + screenshots + PCAP" data-zh="标准动态 120s" data-en="Standard 120s">标准动态 120s</button>
                      <button type="button" onclick="applySamplePreset('evidence')" data-copy="证据优先：180s，强化落地文件、截图、PCAP / Evidence-first: 180s with dropped files, screenshots, PCAP" data-zh="证据优先" data-en="Evidence-first">证据优先</button>
                      <button type="button" onclick="applySamplePreset('memory')" data-copy="内存取证：180s，启用内存 dump（支持时含子进程） / Memory forensic: 180s, memory dumps including children when supported" data-zh="内存取证" data-en="Memory forensic">内存取证</button>
                    </div>
                    <button class="primary-cta" onclick="uploadAndPlan()" data-zh="开始分析：上传 → 提交 VM → 打开监控" data-en="Start analysis: upload → submit VM → monitor">开始分析：上传 → 提交 VM → 打开监控</button>
                    <p class="microcopy" data-copy="上传会创建任务、尝试提交 VM 分析并打开实时监控；若预检失败会保留任务上下文 / Upload creates a job, attempts VM analysis, and opens the live monitor" data-zh="点击后会显示浏览器真实上传进度；若 VM 启动预检失败，仍会保留已创建任务、错误原因和监控/近期任务入口，避免丢上下文。" data-en="After click, the browser shows real upload progress. If VM start preflight fails, the UI still preserves the created job, failure reason, and monitor/recent-job entry points so context is not lost.">点击后会显示浏览器真实上传进度；若 VM 启动预检失败，仍会保留已创建任务、错误原因和监控/近期任务入口，避免丢上下文。</p>
                    <div id="uploadAutoStartNotice" class="callout" data-copy="一键路径：接口=/api/files/upload/start；跳转=/jobs/{jobId}/live-events；当前页进入监控；无需弹窗 / One-click path: endpoint=/api/files/upload/start; redirect=/jobs/{jobId}/live-events; no popup" data-copy-label="upload auto-start live redirect affordance">
                      <strong data-zh="一键接管路径" data-en="One-click handoff path">一键接管路径</strong>
                      <p class="hint" data-zh="主按钮使用 /api/files/upload/start：保存样本、创建任务、提交后台 VM 分析，然后当前页面进入 /jobs/{jobId}/live-events；右键或点击按钮可复制这条操作路径。" data-en="The primary button uses /api/files/upload/start: save sample, create job, submit background VM analysis, then navigate the current page to /jobs/{jobId}/live-events. Right-click or use the button to copy this operation path.">主按钮使用 /api/files/upload/start：保存样本、创建任务、提交后台 VM 分析，然后当前页面进入 /jobs/{jobId}/live-events；右键或点击按钮可复制这条操作路径。</p>
                      <button class="copy-btn" type="button" data-copy="一键路径：接口=/api/files/upload/start；跳转=/jobs/{jobId}/live-events；当前页进入监控；无需弹窗 / One-click path: endpoint=/api/files/upload/start; redirect=/jobs/{jobId}/live-events; no popup" data-copy-label="one-click handoff path" data-zh="复制一键路径" data-en="Copy handoff path">复制一键路径</button>
                    </div>
                  </div>
              </div>
              <div id="panel-path" class="tab-panel" role="tabpanel" aria-labelledby="tab-path" hidden>
                  <h3 data-zh="选择已有样本路径" data-en="Select existing sample path">选择已有样本路径</h3>
                  <p class="hint" data-zh="适用于样本已经位于本机或挂载共享时。服务器会先校验路径，再生成可复核计划；需要动态分析时再点击当前任务里的启动按钮。" data-en="Use this when the sample is already on this host or a mounted share. The server validates the path and creates a reviewable plan; start dynamic analysis from the current job card when ready.">适用于样本已经位于本机或挂载共享时。服务器会先校验路径，再生成可复核计划；需要动态分析时再点击当前任务里的启动按钮。</p>
                  <label for="samplePath" data-zh="主机上的可执行文件路径" data-en="Executable path on host">主机上的可执行文件路径</label>
                  <input id="samplePath" placeholder="D:\Temp\sample.exe" data-copy-label="sample path">
                  <button onclick="planPath()" data-zh="从路径生成计划" data-en="Create plan from path">从路径生成计划</button>
              </div>
              <div id="panel-scan" class="tab-panel" role="tabpanel" aria-labelledby="tab-scan" hidden>
                  <h3 data-zh="扫描文件夹后规划" data-en="Scan folder, then plan">扫描文件夹后规划</h3>
                  <p class="hint" data-zh="仅基于元数据发现 .exe。可复核候选项，或一键规划排序后的第一个结果。" data-en="Metadata-only .exe discovery. Review candidates or one-click plan the first sorted result.">仅基于元数据发现 .exe。可复核候选项，或一键规划排序后的第一个结果。</p>
                  <label for="scanPath" data-zh="目录或精确 .exe 路径" data-en="Directory or exact .exe path">目录或精确 .exe 路径</label>
                  <input id="scanPath" placeholder="D:\Temp\incoming" data-copy-label="scan path">
                  <label for="maxDepth" data-zh="最大扫描深度" data-en="Max scan depth">最大扫描深度</label>
                  <input id="maxDepth" type="number" min="0" max="16" value="4" data-copy-label="max scan depth">
                  <p class="button-row">
                    <button class="secondary" onclick="scanTargets()" data-zh="查找 .exe 候选项" data-en="Find .exe candidates">查找 .exe 候选项</button>
                    <button class="secondary" onclick="scanAndPlanFirst()" data-zh="扫描并规划第一个候选项" data-en="Scan and plan first candidate">扫描并规划第一个候选项</button>
                  </p>
                  <p class="hint"><span data-zh="候选项：" data-en="Candidates:">候选项：</span> <span id="candidateCount" data-copy="0">0</span></p>
                  <div id="candidates" class="hint" data-copy="等待扫描 / waiting for scan" data-zh="等待扫描。" data-en="Waiting for scan.">等待扫描。</div>
              </div>
              <details class="vm-config" open>
                <summary data-zh="本次任务：虚拟机运行配置" data-en="This job: VM run configuration">本次任务：虚拟机运行配置</summary>
                <p class="hint" data-zh="默认从 config 与本机 WebUI 预设读取；这里的值只覆盖当前任务，不写入配置文件，也不展示长命令行。" data-en="Defaults are loaded from config and the local WebUI preset. Values here only override the current job, do not write config files, and do not show long command lines.">默认从 config 与本机 WebUI 预设读取；这里的值只覆盖当前任务，不写入配置文件，也不展示长命令行。</p>
                <div class="toggle-card runtime-limit-card" data-copy="不限制运行时间 / No runtime limit：未启用 / disabled" data-copy-label="runtime limit policy">
                  <label for="uploadDurationUnlimited"><input id="uploadDurationUnlimited" type="checkbox"> <span data-zh="不限制运行时间（仅传入无限制语义）" data-en="No runtime limit (send unlimited intent only)">不限制运行时间（仅传入无限制语义）</span></label>
                  <p id="durationUnlimitedHint" class="field-hint" data-copy="未启用：使用上方秒数，并按后端 config 限制 / Disabled: use bounded seconds clamped by backend config" data-copy-label="runtime limit hint" data-zh="未勾选时使用上方秒数；勾选后上传/路径规划会提交 durationUnlimited=true、durationSeconds=0，启动 runbook 时 stepTimeoutSeconds=0（不设置 Web 端单步超时）。这不是“停止 VM/杀样本”按钮；需要后端取消接口时再接入。" data-en="When unchecked, the seconds field is used. When checked, upload/path planning submits durationUnlimited=true and durationSeconds=0, and runbook start uses stepTimeoutSeconds=0 (no Web-side per-step timeout). This is not a Stop VM/Kill sample button; backend cancellation can be wired only when a safe cancel API exists.">未勾选时使用上方秒数；勾选后上传/路径规划会提交 durationUnlimited=true、durationSeconds=0，启动 runbook 时 stepTimeoutSeconds=0（不设置 Web 端单步超时）。这不是“停止 VM/杀样本”按钮；需要后端取消接口时再接入。</p>
                </div>
                <div class="vm-grid">
                  <div class="config-card">
                    <h4 data-zh="VM 与检查点" data-en="VM and checkpoint">VM 与检查点</h4>
                    <label for="goldenVmName" data-zh="VM 名称" data-en="VM name">VM 名称</label>
                    <input id="goldenVmName" placeholder="KSwordSandbox-Win10-Golden" data-copy-label="VM name">
                    <label for="goldenSnapshotName" data-zh="检查点" data-en="Checkpoint">检查点</label>
                    <input id="goldenSnapshotName" placeholder="Clean" data-copy-label="checkpoint">
                  </div>
                  <div class="config-card">
                    <h4 data-zh="Guest 用户提示" data-en="Guest user hint">Guest 用户提示</h4>
                    <label for="guestUserName" data-zh="Guest 用户" data-en="Guest user">Guest 用户</label>
                    <input id="guestUserName" placeholder="SandboxUser" data-copy-label="guest user">
                    <p id="guestCredentialHint" class="field-hint" data-copy="" data-copy-label="guest credential hint" data-zh="Guest 密码只从本机密钥环境变量读取；WebUI 不输入也不保存密码。" data-en="Guest password is read only from the local secret environment variable; the WebUI does not ask for or store it.">Guest 密码只从本机密钥环境变量读取；WebUI 不输入也不保存密码。</p>
                    <label for="guestWorkingDirectory" data-zh="Guest 工作目录" data-en="Guest working folder">Guest 工作目录</label>
                    <input id="guestWorkingDirectory" placeholder="C:\KSwordSandbox" data-copy-label="guest working folder">
                    <label for="guestPayloadRoot" data-zh="Guest 工具目录（主机）" data-en="Guest tool folder (host)">Guest 工具目录（主机）</label>
                    <input id="guestPayloadRoot" placeholder="D:\Temp\KSwordSandbox\payload\guest-tools" data-copy-label="guest payload root">
                  </div>
                  <div class="config-card">
                    <h4 data-zh="R0 采集器（collector）" data-en="R0 collector">R0 采集器（collector）</h4>
                    <div class="toggle-stack">
                      <div class="toggle-card readonly-toggle">
                        <label for="r0Enabled"><input id="r0Enabled" type="checkbox" disabled> <span data-zh="R0 总开关来自配置（config）" data-en="R0 master switch comes from config">R0 总开关来自配置（config）</span></label>
                        <p id="r0EnabledHint" class="field-hint" data-copy="" data-copy-label="R0 enabled hint" data-zh="R0 总开关仍由 config 控制；本页不改 Core 业务。" data-en="The R0 master switch still comes from config; this page does not change Core behavior.">R0 总开关仍由 config 控制；本页不改 Core 业务。</p>
                      </div>
                      <div class="toggle-card">
                        <label for="useMockCollector"><input id="useMockCollector" type="checkbox"> <span data-zh="使用 Mock 采集器（collector，覆盖本次任务）" data-en="Use mock collector (override this job)">使用 Mock 采集器（collector，覆盖本次任务）</span></label>
                        <p class="field-hint" data-zh="未勾选时使用真实 R0 采集器（collector）和配置（config）默认模式。" data-en="When unchecked, the job uses the real R0 collector/config default mode.">未勾选时使用真实 R0 采集器（collector）和配置（config）默认模式。</p>
                      </div>
                    </div>
                  </div>
                </div>
                <div id="vmConfigSummary" class="config-summary" data-copy="" data-copy-label="VM configuration summary"></div>
                <div class="preset-actions">
                  <button class="secondary" type="button" onclick="saveVmPreset()" data-zh="保存为本机 WebUI 预设" data-en="Save as local WebUI preset">保存为本机 WebUI 预设</button>
                  <button class="secondary" type="button" onclick="clearVmPreset()" data-zh="清除本机预设" data-en="Clear local preset">清除本机预设</button>
                  <a class="buttonlink secondary" href="/settings" data-zh="设置页也可管理预设" data-en="Manage preset in Settings">设置页也可管理预设</a>
                </div>
              </details>
              <details class="vm-config" open>
                <summary data-zh="高级：敏感产物采集（显式启用 / opt-in）" data-en="Advanced: sensitive artifact collection (explicit opt-in)">高级：敏感产物采集（显式启用 / opt-in）</summary>
                <p class="hint" data-zh="这些选项默认关闭；勾选后只影响当前任务，上传点击会随计划一起提交并在动态监控页显示，runbook 会把对应参数（flag）传给 Guest Agent。" data-en="These options are disabled by default. When checked, they affect only this job, upload submits them with the plan and shows them on the dynamic monitor, and the runbook forwards matching flags to the Guest Agent.">这些选项默认关闭；勾选后只影响当前任务，上传点击会随计划一起提交并在动态监控页显示，runbook 会把对应参数（flag）传给 Guest Agent。</p>
                <div class="vm-grid">
                  <div id="artifact-card-collectDroppedFiles" class="toggle-card" data-copy="采集落地文件 / Collect dropped files / --collect-dropped-files"><label for="collectDroppedFiles"><input id="collectDroppedFiles" type="checkbox"> <span data-zh="采集落地文件" data-en="Collect dropped files">采集落地文件</span></label><p id="collectDroppedFilesHint" class="field-hint" data-zh="保存样本运行期间新增或修改的落地文件证据。" data-en="Preserve dropped-file evidence created or modified during sample execution.">保存样本运行期间新增或修改的落地文件证据。</p><button class="copy-btn" type="button" data-copy="采集落地文件 / Collect dropped files / --collect-dropped-files" data-copy-label="collect dropped files option" data-zh="复制" data-en="Copy">复制</button></div>
                  <div id="artifact-card-captureScreenshots" class="toggle-card" data-copy="采集截图 / Capture screenshots / --screenshot"><label for="captureScreenshots"><input id="captureScreenshots" type="checkbox"> <span data-zh="采集截图" data-en="Capture screenshots">采集截图</span></label><p id="captureScreenshotsHint" class="field-hint" data-zh="采集运行窗口或桌面截图，帮助复核 GUI 行为。" data-en="Capture run-window or desktop screenshots for GUI behavior review.">采集运行窗口或桌面截图，帮助复核 GUI 行为。</p><button class="copy-btn" type="button" data-copy="采集截图 / Capture screenshots / --screenshot" data-copy-label="screenshot option" data-zh="复制" data-en="Copy">复制</button></div>
                  <div id="artifact-card-captureMemoryDumps" class="toggle-card" data-copy="采集内存转储：样本进程；支持时包含子进程 / Capture memory dumps: sample process; child processes when supported / --memory-dump"><label for="captureMemoryDumps"><input id="captureMemoryDumps" type="checkbox"> <span data-zh="采集内存转储（含子进程，若支持）" data-en="Capture memory dumps (children if supported)">采集内存转储（含子进程，若支持）</span></label><p id="captureMemoryDumpsHint" class="field-hint" data-zh="请求样本进程内存转储；Guest Agent 支持时也包含可解析的子进程转储。" data-en="Request sample-process memory dumps; when the Guest Agent supports it, resolved child processes are dumped too.">请求样本进程内存转储；Guest Agent 支持时也包含可解析的子进程转储。</p><button class="copy-btn" type="button" data-copy="采集内存转储 / Capture memory dumps / --memory-dump" data-copy-label="memory dump option" data-zh="复制" data-en="Copy">复制</button></div>
                  <div id="artifact-card-capturePacketCapture" class="toggle-card" data-copy="采集 PCAP 抓包 / Capture packet capture PCAP / --packet-capture"><label for="capturePacketCapture"><input id="capturePacketCapture" type="checkbox"> <span data-zh="采集 PCAP 抓包" data-en="Capture PCAP">采集 PCAP 抓包</span></label><p id="capturePacketCaptureHint" class="field-hint" data-zh="采集网络包为 PCAP/PCAPNG 证据，监控页提供下载状态。" data-en="Capture network packets as PCAP/PCAPNG evidence; the monitor shows download status.">采集网络包为 PCAP/PCAPNG 证据，监控页提供下载状态。</p><button class="copy-btn" type="button" data-copy="采集 PCAP 抓包 / Capture PCAP / --packet-capture" data-copy-label="packet capture option" data-zh="复制" data-en="Copy">复制</button></div>
                </div>
              </details>
              <div id="status" class="status" role="status" aria-live="polite"></div>
            </section>

            </div>

            <div id="workspace-analysis" class="workspace-panel" role="tabpanel" aria-labelledby="workspace-tab-analysis" hidden>
            <section id="current-job">
              <h2 data-zh="当前任务" data-en="Current job">当前任务</h2>
              <div id="jobResult" class="hint"><span data-zh="尚未规划任务。" data-en="No job planned yet.">尚未规划任务。</span></div>
            </section>
            </div>

            <div id="workspace-results" class="workspace-panel" role="tabpanel" aria-labelledby="workspace-tab-results" hidden>
            <section id="recent-jobs">
              <h2 data-zh="报告与近期任务" data-en="Reports and recent jobs">报告与近期任务</h2>
              <p class="hint" data-zh="这里仅列出关键状态、报告入口、进度页和独立监控页入口；命令行、PowerShell、stdout/stderr 与下载列表不在主页面展示。" data-en="This tab only lists key status, report access, progress-page links, and standalone monitor links; command lines, PowerShell, stdout/stderr, and download lists are not shown on the dashboard.">这里仅列出关键状态、报告入口、进度页和独立监控页入口；命令行、PowerShell、stdout/stderr 与下载列表不在主页面展示。</p>
              <div id="globalReportNotice" class="report-notice" hidden></div>
              <button class="secondary" onclick="refreshJobs(true)" data-zh="刷新任务列表" data-en="Refresh job list">刷新任务列表</button>
              <div id="jobList" class="hint"><span data-zh="尚未加载任务。" data-en="No jobs loaded yet.">尚未加载任务。</span></div>
            </section>
            </div>
          </main>
          <div id="copyToast" class="toast" role="status" aria-live="polite"></div>
          <script>
            let copyToastTimer = null;
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';
            let activeWorkspaceTab = 'plan';
            let progressTimer = null;
            let runbookProgressTimer = null;
            let backgroundExecutionTimer = null;
            let reportAutoOpenTimer = null;
            let reportAutoOpenDeadline = 0;
            let reportAutoOpenJobId = '';
            let progressStageIndex = 0;
            let progressCompleted = false;
            let progressFailed = false;
            let currentJobPayload = null;
            let currentJobListPayload = [];
            let latestRunbookProgressSnapshot = null;
            let runtimeConfigDefaults = null;
            let runtimeConfigLoadError = '';
            let virusTotalSettingsState = null;
            let virusTotalReadinessError = '';
            let artifactCollectionSupport = {
              collectDroppedFiles: true,
              captureScreenshots: true,
              captureMemoryDumps: true,
              capturePacketCapture: true
            };
            const vmPresetStorageKey = 'ksword-vm-overrides';
            const artifactOptionDefinitions = [
              {
                key: 'collectDroppedFiles',
                id: 'collectDroppedFiles',
                cardId: 'artifact-card-collectDroppedFiles',
                hintId: 'collectDroppedFilesHint',
                flag: '--collect-dropped-files',
                labelZh: '采集落地文件',
                labelEn: 'Collect dropped files',
                hintZh: '保存样本运行期间新增或修改的落地文件证据。',
                hintEn: 'Preserve dropped-file evidence created or modified during sample execution.'
              },
              {
                key: 'captureScreenshots',
                id: 'captureScreenshots',
                cardId: 'artifact-card-captureScreenshots',
                hintId: 'captureScreenshotsHint',
                flag: '--screenshot',
                labelZh: '采集截图',
                labelEn: 'Capture screenshots',
                hintZh: '采集运行窗口或桌面截图，帮助复核 GUI 行为。',
                hintEn: 'Capture run-window or desktop screenshots for GUI behavior review.'
              },
              {
                key: 'captureMemoryDumps',
                id: 'captureMemoryDumps',
                cardId: 'artifact-card-captureMemoryDumps',
                hintId: 'captureMemoryDumpsHint',
                flag: '--memory-dump',
                labelZh: '采集内存转储（含子进程，若支持）',
                labelEn: 'Capture memory dumps (children if supported)',
                hintZh: '请求样本进程内存转储；Guest Agent 支持时也包含可解析的子进程转储。',
                hintEn: 'Request sample-process memory dumps; when the Guest Agent supports it, resolved child processes are dumped too.'
              },
              {
                key: 'capturePacketCapture',
                id: 'capturePacketCapture',
                cardId: 'artifact-card-capturePacketCapture',
                hintId: 'capturePacketCaptureHint',
                flag: '--packet-capture',
                labelZh: '采集 PCAP 抓包',
                labelEn: 'Capture PCAP',
                hintZh: '采集网络包为 PCAP/PCAPNG 证据，监控页提供下载状态。',
                hintEn: 'Capture network packets as PCAP/PCAPNG evidence; the monitor shows download status.'
              }
            ];
            const liveStages = [
              ['启动 VM', 'Start VM', '还原干净环境并等待来宾机可用', 'Restore a clean VM and wait for guest readiness'],
              ['部署 Payload', 'Deploy payload', '传入样本、Agent 与采集器', 'Copy the sample, agent, and collectors'],
              ['执行样本', 'Execute sample', '运行样本并采集行为', 'Run the sample and collect behavior'],
              ['收集结果', 'Collect results', '同步事件、截图、转储与 PCAP', 'Sync events, screenshots, dumps, and PCAP'],
              ['生成报告', 'Generate report', '刷新 JSON/HTML 报告', 'Refresh JSON/HTML reports']
            ];

            function t(zh, en) {
              return currentLanguage === 'en' ? en : zh;
            }

            function setLanguage(lang) {
              currentLanguage = lang === 'en' ? 'en' : 'zh';
              localStorage.setItem('ksword-lang', currentLanguage);
              applyLanguage();
              rerenderDynamicPanelsForLanguage();
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
              refreshLocalizedReportLinks();
              renderConfigDefaultHints();
              renderVmConfigSummary();
              if (latestRunbookProgressSnapshot) {
                renderRunbookProgress(latestRunbookProgressSnapshot);
              } else {
                renderStages(progressStageIndex, progressCompleted, progressFailed);
              }
            }

            function rerenderDynamicPanelsForLanguage() {
              // Inputs: current cached job payloads plus the selected language.
              // Processing rerenders only dynamic panels that are intentionally
              // skipped by applyLanguage because they contain generated HTML.
              // Return: no value; keeps report-state labels bilingual.
              if (currentJobPayload) {
                renderJob(currentJobPayload);
              }

              if (Array.isArray(currentJobListPayload) && currentJobListPayload.length > 0) {
                renderJobList(currentJobListPayload);
              }
            }

            function formatJobStatus(status) {
              const names = {
                0: t('排队中', 'Queued'),
                1: t('规划中', 'Planning'),
                2: t('已规划', 'Planned'),
                3: t('运行中', 'Running'),
                4: t('已完成', 'Completed'),
                5: t('失败', 'Failed')
              };
              const namedStatuses = {
                queued: t('排队中', 'Queued'),
                planning: t('规划中', 'Planning'),
                planned: t('已规划', 'Planned'),
                running: t('运行中', 'Running'),
                completed: t('已完成', 'Completed'),
                failed: t('失败', 'Failed')
              };
              if (status === null || status === undefined || status === '') {
                return '-';
              }

              if (typeof status === 'number' || /^\d+$/.test(String(status))) {
                const numeric = Number(status);
                return names[numeric] ? `${names[numeric]} (${numeric})` : `${t('未知', 'Unknown')} (${numeric})`;
              }

              const normalized = String(status).trim().toLowerCase();
              if (namedStatuses[normalized]) {
                return namedStatuses[normalized];
              }

              return String(status);
            }

            function normalizeStatusToken(value) {
              return String(value ?? '').trim().toLowerCase().replace(/[\s-]+/g, '_');
            }

            function localizeServerStatus(value) {
              const raw = String(value ?? '').trim();
              if (!raw) {
                return '';
              }

              const labels = {
                queued: t('已排队', 'queued'),
                planning: t('规划中', 'planning'),
                planned: t('已规划', 'planned'),
                submitted: t('已提交', 'submitted'),
                accepted: t('已受理', 'accepted'),
                not_started: t('未启动', 'not started'),
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
                timeout: t('超时', 'timeout'),
                timed_out: t('已超时', 'timed out'),
                not_configured: t('未配置', 'not configured'),
                lookup_failed: t('查询失败', 'lookup failed'),
                unavailable: t('不可用', 'unavailable'),
                ready: t('就绪', 'ready'),
                missing: t('缺失', 'missing')
              };
              return labels[normalizeStatusToken(raw)] || raw;
            }

            function localizeServerMessage(value) {
              if (value == null || value === '') {
                return '';
              }

              return String(value)
                .replace(/\bfound no events\b/gi, t('未发现事件', 'found no events'))
                .replace(/\bnot imported\b/gi, t('未导入', 'not imported'))
                .replace(/\bnot found\b/gi, t('未找到', 'not found'))
                .replace(/\bfailed\b/gi, t('失败', 'failed'))
                .replace(/\bsucceeded\b/gi, t('成功', 'succeeded'))
                .replace(/\bcompleted\b/gi, t('已完成', 'completed'));
            }

            function selectWorkspaceTab(name) {
              const tabs = ['plan', 'analysis', 'results'];
              const selected = tabs.includes(name) ? name : 'plan';
              activeWorkspaceTab = selected;
              for (const candidate of tabs) {
                const tab = document.getElementById(`workspace-tab-${candidate}`);
                const panel = document.getElementById(`workspace-${candidate}`);
                if (!tab || !panel) {
                  continue;
                }

                const active = candidate === selected;
                tab.classList.toggle('active', active);
                tab.setAttribute('aria-selected', active ? 'true' : 'false');
                tab.tabIndex = active ? 0 : -1;
                panel.classList.toggle('active', active);
                panel.hidden = !active;
              }
            }

            function selectPlanTab(name) {
              for (const candidate of ['path', 'upload', 'scan']) {
                const tab = document.getElementById(`tab-${candidate}`);
                const panel = document.getElementById(`panel-${candidate}`);
                if (!tab || !panel) {
                  continue;
                }

                tab.classList.toggle('active', candidate === name);
                tab.setAttribute('aria-selected', candidate === name ? 'true' : 'false');
                tab.tabIndex = candidate === name ? 0 : -1;
                panel.classList.toggle('active', candidate === name);
                panel.hidden = candidate !== name;
              }
            }

            function setupTabKeyboardNavigation() {
              for (const tablist of document.querySelectorAll('[role="tablist"]')) {
                tablist.addEventListener('keydown', event => {
                  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
                    return;
                  }

                  const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
                  const current = tabs.indexOf(document.activeElement);
                  if (current < 0 || tabs.length === 0) {
                    return;
                  }

                  event.preventDefault();
                  const next = event.key === 'Home'
                    ? 0
                    : event.key === 'End'
                      ? tabs.length - 1
                      : event.key === 'ArrowRight'
                        ? (current + 1) % tabs.length
                        : (current - 1 + tabs.length) % tabs.length;
                  tabs[next].focus();
                  tabs[next].click();
                });
              }
            }

            async function loadConfigDefaults() {
              try {
                const response = await fetch('/api/config');
                const config = await requireOk(response, t('加载配置', 'Load config'));
                runtimeConfigDefaults = config;
                runtimeConfigLoadError = '';
                updateArtifactCollectionSupport(config);
                const maxDuration = normalizePositiveInt(config.analysis?.maxDurationSeconds, 900);
                const defaultDuration = clampDuration(config.analysis?.defaultDurationSeconds, maxDuration);
                document.getElementById('duration').value = String(defaultDuration);
                document.getElementById('uploadDuration').value = String(defaultDuration);
                document.getElementById('uploadDurationUnlimited').checked = false;
                document.getElementById('uploadDuration').max = String(maxDuration);
                document.getElementById('goldenVmName').value = config.hyperV?.goldenVmName || '';
                document.getElementById('goldenSnapshotName').value = config.hyperV?.goldenSnapshotName || '';
                document.getElementById('guestUserName').value = config.guest?.userName || '';
                document.getElementById('guestWorkingDirectory').value = config.guest?.workingDirectory || '';
                document.getElementById('guestPayloadRoot').value = config.paths?.guestPayloadRoot || '';
                document.getElementById('r0Enabled').checked = Boolean(config.driver?.enabled);
                document.getElementById('useMockCollector').checked = Boolean(config.driver?.useMockCollector);
                document.getElementById('collectDroppedFiles').checked = Boolean(config.artifactCollection?.collectDroppedFiles);
                document.getElementById('captureScreenshots').checked = Boolean(config.artifactCollection?.captureScreenshots);
                document.getElementById('captureMemoryDumps').checked = Boolean(config.artifactCollection?.captureMemoryDumps);
                document.getElementById('capturePacketCapture').checked = Boolean(config.artifactCollection?.capturePacketCapture);
                applyOperatorVmPreset();
                applyArtifactCollectionSupport();
                renderConfigDefaultHints();
                renderVmConfigSummary();
                renderSelectedSample();
                renderOperatorReadinessChips();
              } catch {
                // Keep placeholders when config loading fails; planning still works with server defaults.
                runtimeConfigLoadError = t('配置读取失败；上传时仍由后端做最终预检。', 'Config loading failed; backend preflight still makes the final decision during upload.');
                markArtifactCollectionSupportUnknown();
                applyArtifactCollectionSupport();
                renderConfigDefaultHints();
                renderVmConfigSummary();
                renderSelectedSample();
                renderOperatorReadinessChips();
              }
            }

            async function loadVirusTotalReadiness() {
              try {
                const response = await fetch('/api/settings/virustotal');
                virusTotalSettingsState = await requireOk(response, t('读取 VirusTotal 状态', 'Load VirusTotal status'));
                virusTotalReadinessError = '';
              } catch (error) {
                virusTotalSettingsState = null;
                virusTotalReadinessError = error && error.message ? error.message : t('VirusTotal 状态不可用。', 'VirusTotal status is unavailable.');
              } finally {
                renderOperatorReadinessChips();
              }
            }

            function normalizePositiveInt(value, fallback) {
              const parsed = Number.parseInt(String(value ?? ''), 10);
              return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
            }

            function isDurationUnlimited() {
              return document.getElementById('uploadDurationUnlimited')?.checked === true;
            }

            function formatAnalysisDuration() {
              return isDurationUnlimited()
                ? t('不限制运行时间', 'no runtime limit')
                : `${getAnalysisDuration()}s`;
            }

            function clampDuration(value, maxDuration) {
              const max = normalizePositiveInt(maxDuration, 900);
              const parsed = normalizePositiveInt(value, normalizePositiveInt(runtimeConfigDefaults?.analysis?.defaultDurationSeconds, 120));
              return Math.max(1, Math.min(max, parsed));
            }

            function getAnalysisDuration() {
              const input = document.getElementById('uploadDuration');
              const hidden = document.getElementById('duration');
              if (isDurationUnlimited()) {
                if (input) {
                  input.disabled = true;
                }

                if (hidden) {
                  hidden.value = '0';
                }

                return 0;
              }

              if (input) {
                input.disabled = false;
              }

              const max = normalizePositiveInt(input?.max || runtimeConfigDefaults?.analysis?.maxDurationSeconds, 900);
              const fallback = normalizePositiveInt(runtimeConfigDefaults?.analysis?.defaultDurationSeconds || hidden?.value, 120);
              const duration = clampDuration(input?.value || hidden?.value || fallback, max);
              if (input) {
                input.value = String(duration);
              }

              if (hidden) {
                hidden.value = String(duration);
              }

              return duration;
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

            function getArtifactCollectionConfig() {
              return {
                collectDroppedFiles: isArtifactOptionSupported('collectDroppedFiles') && document.getElementById('collectDroppedFiles').checked,
                captureScreenshots: isArtifactOptionSupported('captureScreenshots') && document.getElementById('captureScreenshots').checked,
                captureMemoryDumps: isArtifactOptionSupported('captureMemoryDumps') && document.getElementById('captureMemoryDumps').checked,
                capturePacketCapture: isArtifactOptionSupported('capturePacketCapture') && document.getElementById('capturePacketCapture').checked
              };
            }

            function updateArtifactCollectionSupport(config) {
              // Inputs: current /api/config payload. Processing checks whether
              // the Web host exposes the artifactCollection keys that the
              // runbook understands. Return: updates UI-only support flags so
              // unsupported lanes are disabled instead of submitting phantom
              // request fields.
              const artifactConfig = config && typeof config.artifactCollection === 'object' ? config.artifactCollection : {};
              artifactCollectionSupport = {};
              for (const option of artifactOptionDefinitions) {
                artifactCollectionSupport[option.key] = Object.prototype.hasOwnProperty.call(artifactConfig, option.key);
              }
            }

            function markArtifactCollectionSupportUnknown() {
              artifactCollectionSupport = Object.fromEntries(artifactOptionDefinitions.map(option => [option.key, true]));
            }

            function isArtifactOptionSupported(key) {
              return artifactCollectionSupport[key] !== false;
            }

            function applyArtifactCollectionSupport() {
              for (const option of artifactOptionDefinitions) {
                const supported = isArtifactOptionSupported(option.key);
                const input = document.getElementById(option.id);
                const card = document.getElementById(option.cardId);
                const hint = document.getElementById(option.hintId);
                const supportText = runtimeConfigLoadError
                  ? t('支持状态：等待后端配置预检；提交时由 Web Host 最终确认。', 'Support state: waiting for backend config preflight; the Web Host makes the final decision on submit.')
                  : supported
                    ? t(`支持状态：当前 config/runbook 支持 ${option.flag}。`, `Support: current config/runbook supports ${option.flag}.`)
                    : t(`支持状态：当前 config/runbook 未暴露 ${option.flag}；本次任务不会提交该字段。`, `Support: current config/runbook does not expose ${option.flag}; this job will not submit the field.`);
                const hintText = `${t(option.hintZh, option.hintEn)} ${supportText}`;
                if (input) {
                  input.disabled = !supported;
                  if (!supported) {
                    input.checked = false;
                  }
                  input.setAttribute('data-copy', `${option.labelZh} / ${option.labelEn}：${supported ? t('已支持', 'supported') : t('未支持', 'unsupported')}；参数 / flag=${option.flag}`);
                }

                if (card) {
                  card.classList.toggle('readonly-toggle', !supported);
                  card.setAttribute('data-copy', `${option.labelZh} / ${option.labelEn}; ${supportText}; ${option.flag}`);
                }

                if (hint) {
                  hint.textContent = hintText;
                  hint.setAttribute('data-copy', hintText);
                }
              }
            }

            function readOperatorVmPreset() {
              try {
                const raw = localStorage.getItem(vmPresetStorageKey);
                return raw ? JSON.parse(raw) : null;
              } catch {
                return null;
              }
            }

            function applyOperatorVmPreset() {
              const preset = readOperatorVmPreset();
              if (!preset) {
                return;
              }

              const setValue = (id, value) => {
                if (value !== undefined && value !== null) {
                  document.getElementById(id).value = String(value);
                }
              };
              const setChecked = (id, value) => {
                if (typeof value === 'boolean') {
                  document.getElementById(id).checked = value;
                }
              };

              setValue('uploadDuration', preset.durationSeconds);
              setValue('duration', preset.durationSeconds);
              setChecked('uploadDurationUnlimited', preset.durationUnlimited);
              setValue('goldenVmName', preset.goldenVmName);
              setValue('goldenSnapshotName', preset.goldenSnapshotName);
              setValue('guestUserName', preset.guestUserName);
              setValue('guestWorkingDirectory', preset.guestWorkingDirectory);
              setValue('guestPayloadRoot', preset.guestPayloadRoot);
              setChecked('useMockCollector', preset.useMockCollector);
              setChecked('collectDroppedFiles', preset.collectDroppedFiles);
              setChecked('captureScreenshots', preset.captureScreenshots);
              setChecked('captureMemoryDumps', preset.captureMemoryDumps);
              setChecked('capturePacketCapture', preset.capturePacketCapture);
              getAnalysisDuration();
            }

            function captureVmPreset() {
              return {
                durationSeconds: getAnalysisDuration(),
                durationUnlimited: isDurationUnlimited(),
                ...getVmConfig(),
                ...getArtifactCollectionConfig()
              };
            }

            function saveVmPreset() {
              const preset = captureVmPreset();
              localStorage.setItem(vmPresetStorageKey, JSON.stringify(preset));
              renderConfigDefaultHints();
              renderVmConfigSummary();
              setStatus(t('本机 WebUI 预设已保存；后续任务会默认使用这些覆盖值。', 'Local WebUI preset saved; future jobs will default to these override values.'), false);
            }

            async function clearVmPreset() {
              localStorage.removeItem(vmPresetStorageKey);
              await loadConfigDefaults();
              setStatus(t('本机 WebUI 预设已清除；已恢复 config 默认值。', 'Local WebUI preset cleared; config defaults restored.'), false);
            }

            function renderConfigDefaultHints() {
              const secretName = runtimeConfigDefaults?.guest?.passwordSecretName || 'KSWORDBOX_GUEST_PASSWORD';
              const maxDuration = normalizePositiveInt(runtimeConfigDefaults?.analysis?.maxDurationSeconds, 900);
              setElementTextAndCopy('durationHint', t(
                `后端会把有界时长限制在 1-${maxDuration} 秒；勾选“不限制运行时间”时会提交 durationUnlimited=true、durationSeconds=0，并可保存为本机 WebUI 预设。`,
                `The backend clamps bounded duration to 1-${maxDuration} seconds; when No runtime limit is checked, the UI submits durationUnlimited=true and durationSeconds=0, and this can be saved as a local WebUI preset.`));
              const unlimitedHint = isDurationUnlimited()
                ? t('已启用：本次上传/路径规划传入无限制运行语义；监控页的“停止监视/轮询”只停止浏览器刷新，不停止 VM 或样本。', 'Enabled: this upload/path plan sends no-runtime-limit semantics; the monitor Stop watching/polling button only stops browser refresh and does not stop the VM or sample.')
                : t('未启用：使用上方秒数，并由后端按 config 限制。', 'Disabled: use the seconds field above, clamped by backend config.');
              setElementTextAndCopy('durationUnlimitedHint', unlimitedHint);
              const runtimeCard = document.querySelector('.runtime-limit-card');
              if (runtimeCard) {
                runtimeCard.setAttribute('data-copy', `${t('运行时间策略', 'Runtime policy')}: ${unlimitedHint}`);
              }
              setElementTextAndCopy('guestCredentialHint', t(
                `Guest 密码只从本机密钥环境变量 ${secretName} 读取；WebUI 不输入也不保存密码。`,
                `Guest password is read only from the local secret environment variable ${secretName}; the WebUI does not ask for or store it.`));
              const r0Enabled = Boolean(runtimeConfigDefaults?.driver?.enabled);
              const r0Text = r0Enabled
                ? t('R0 已在配置（config）中启用；本页只覆盖本次任务的真实/Mock 采集器（collector）模式。', 'R0 is enabled in config; this page only overrides the real/mock collector mode for this job.')
                : t('R0 在配置（config）中关闭；本页会保留 Mock 选择，但 Core 仍以 config 总开关为准。', 'R0 is disabled in config; this page keeps the mock selection, but Core still follows the config master switch.');
              setElementTextAndCopy('r0EnabledHint', r0Text);
              applyArtifactCollectionSupport();
            }

            function renderVmConfigSummary() {
              const target = document.getElementById('vmConfigSummary');
              if (!target) {
                return;
              }

              const valueOrDefault = (id, fallback) => {
                const value = (document.getElementById(id)?.value || '').trim();
                return value || fallback || t('使用默认', 'default');
              };
              const durationLabel = formatAnalysisDuration();
              const r0Enabled = document.getElementById('r0Enabled')?.checked;
              const mock = document.getElementById('useMockCollector')?.checked;
              const r0Mode = r0Enabled
                ? (mock ? t('R0：Mock 采集器（collector）', 'R0: mock collector') : t('R0：真实采集器（collector）', 'R0: real collector'))
                : t('R0：config 已关闭', 'R0: disabled by config');
              const artifacts = buildArtifactCollectionSummary({ submission: getArtifactCollectionConfig() });
              const parts = [
                `${t('VM', 'VM')}: ${valueOrDefault('goldenVmName', runtimeConfigDefaults?.hyperV?.goldenVmName)}`,
                `${t('检查点', 'Checkpoint')}: ${valueOrDefault('goldenSnapshotName', runtimeConfigDefaults?.hyperV?.goldenSnapshotName)}`,
                `${t('运行时间', 'Runtime')}: ${durationLabel}`,
                `${t('Guest', 'Guest')}: ${valueOrDefault('guestUserName', runtimeConfigDefaults?.guest?.userName)}`,
                r0Mode,
                `${t('产物', 'Artifacts')}: ${artifacts}`
              ];
              target.setAttribute('data-copy', parts.join(' | '));
              target.innerHTML = parts.map(part => `<span class="pill" data-copy="${escapeAttribute(part)}" data-copy-label="VM configuration summary item">${escapeHtml(part)}</span>`).join('');
            }

            function renderOperatorReadinessChips() {
              const target = document.getElementById('operatorReadinessChips');
              if (!target) {
                return;
              }

              const file = document.getElementById('sampleUpload')?.files?.[0] || null;
              const vmName = (document.getElementById('goldenVmName')?.value || runtimeConfigDefaults?.hyperV?.goldenVmName || '').trim();
              const checkpoint = (document.getElementById('goldenSnapshotName')?.value || runtimeConfigDefaults?.hyperV?.goldenSnapshotName || '').trim();
              const secretName = runtimeConfigDefaults?.guest?.passwordSecretName || 'KSWORDBOX_GUEST_PASSWORD';
              const r0Enabled = document.getElementById('r0Enabled')?.checked;
              const mock = document.getElementById('useMockCollector')?.checked;
              const artifactConfig = getArtifactCollectionConfig();
              const artifacts = buildArtifactCollectionSummary({ submission: artifactConfig });
              const artifactsEnabled = Object.values(artifactConfig).some(value => Boolean(value));
              const vtConfigured = Boolean(virusTotalSettingsState?.configured ?? virusTotalSettingsState?.Configured);
              const vtSource = virusTotalSettingsState?.source || virusTotalSettingsState?.Source || (vtConfigured ? 'configured' : 'not-configured');

              const chips = [];
              chips.push({
                state: file ? 'good' : 'warn',
                label: t('样本', 'Sample'),
                value: file ? `${file.name} · ${formatBytes(file.size || 0)}` : t('等待选择 .exe', 'Waiting for .exe'),
                hint: file ? t('上传后创建任务并尝试提交 VM', 'Will create a job and attempt VM submission after upload') : t('点击或拖拽到上传区域', 'Click or drag into upload zone')
              });
              chips.push({
                state: isDurationUnlimited() ? 'warn' : 'neutral',
                label: t('运行时间', 'Runtime'),
                value: formatAnalysisDuration(),
                hint: isDurationUnlimited()
                  ? t('传入 durationUnlimited=true；停止监视不会停止 VM/样本', 'Sends durationUnlimited=true; stopping the monitor does not stop the VM/sample')
                  : t('使用有界秒数，由后端按 config 限制', 'Uses bounded seconds clamped by backend config')
              });
              chips.push({
                state: runtimeConfigLoadError ? 'warn' : (vmName ? 'good' : 'warn'),
                label: t('VM', 'VM'),
                value: runtimeConfigLoadError || (vmName ? vmName : t('未从配置读取 VM 名称', 'VM name not loaded from config')),
                hint: checkpoint ? `${t('检查点', 'Checkpoint')}: ${checkpoint}` : t('上传时后端会做最终预检', 'Backend preflight checks this during upload')
              });
              chips.push({
                state: 'neutral',
                label: t('Guest 密钥', 'Guest secret'),
                value: secretName,
                hint: t('WebUI 不输入密码；后端预检存在性', 'WebUI does not accept passwords; backend checks presence')
              });
              chips.push({
                state: r0Enabled ? (mock ? 'warn' : 'good') : 'neutral',
                label: t('R0', 'R0'),
                value: r0Enabled ? (mock ? t('Mock 采集器', 'Mock collector') : t('真实采集器', 'Real collector')) : t('config 已关闭', 'disabled by config'),
                hint: t('本页只覆盖本次任务模式', 'This page only overrides this job mode')
              });
              chips.push({
                state: virusTotalReadinessError ? 'warn' : (vtConfigured ? 'good' : 'neutral'),
                label: 'VirusTotal',
                value: virusTotalReadinessError ? t('状态读取失败', 'status load failed') : (vtConfigured ? t('已配置', 'configured') : t('未配置，静默跳过', 'not configured, quiet skip')),
                hint: virusTotalReadinessError || `${t('来源', 'Source')}: ${vtSource}`
              });
              chips.push({
                state: artifactsEnabled ? 'good' : 'neutral',
                label: t('证据采集', 'Evidence capture'),
                value: artifacts,
                hint: t('右键复制当前采集选项', 'Right-click to copy current capture options')
              });

              const copyTextValue = chips.map(chip => `${chip.label}: ${chip.value} (${chip.hint})`).join(' | ');
              target.setAttribute('data-copy', copyTextValue);
              target.innerHTML = chips.map(chip => `
                <span class="readiness-chip ${chip.state}" data-copy="${escapeAttribute(`${chip.label}: ${chip.value} (${chip.hint})`)}" data-copy-label="readiness chip">
                  <b>${escapeHtml(chip.label)}</b>
                  <span>${escapeHtml(chip.value)}</span>
                  <span>${escapeHtml(chip.hint)}</span>
                </span>`).join('');
            }

            function renderSelectedSample() {
              const input = document.getElementById('sampleUpload');
              const target = document.getElementById('selectedSampleSummary');
              if (!target) {
                return;
              }

              const file = input?.files?.[0] || null;
              if (!file) {
                const emptyText = t('尚未选择样本。请选择一个本机 .exe；上传后会创建任务、尝试提交 VM 动态分析并打开监控页。', 'No sample selected. Choose one local .exe; upload creates a job, attempts VM dynamic analysis, and opens the monitor.');
                target.className = 'selected-sample empty';
                target.textContent = emptyText;
                target.setAttribute('data-copy', emptyText);
                renderOperatorReadinessChips();
                return;
              }

              const durationLabel = formatAnalysisDuration();
              const artifacts = buildArtifactCollectionSummary({ submission: getArtifactCollectionConfig() });
              const isExe = /\.exe$/i.test(file.name || '');
              const parts = [
                `${t('文件', 'File')}: ${file.name}`,
                `${t('大小', 'Size')}: ${formatBytes(file.size || 0)}`,
                `${t('运行时间', 'Runtime')}: ${durationLabel}`,
                `${t('证据采集', 'Evidence')}: ${artifacts}`,
                isExe ? t('扩展名检查：通过', 'Extension check: pass') : t('扩展名检查：不是 .exe，后端会拒绝', 'Extension check: not .exe, backend will reject')
              ];
              target.className = `selected-sample${isExe ? '' : ' error'}`;
              target.setAttribute('data-copy', parts.join(' | '));
              target.innerHTML = parts.map(part => `<span class="pill ${isExe ? '' : 'warn'}" data-copy="${escapeAttribute(part)}">${escapeHtml(part)}</span>`).join(' ');
              renderOperatorReadinessChips();
            }

            function applySamplePreset(name) {
              const setChecked = (id, value) => {
                const element = document.getElementById(id);
                if (element) {
                  const option = artifactOptionDefinitions.find(candidate => candidate.id === id);
                  element.checked = Boolean(value) && (!option || isArtifactOptionSupported(option.key));
                }
              };
              const duration = document.getElementById('uploadDuration');
              const hiddenDuration = document.getElementById('duration');
              const presets = {
                quick: {
                  seconds: 30,
                  collectDroppedFiles: false,
                  captureScreenshots: false,
                  captureMemoryDumps: false,
                  capturePacketCapture: false,
                  message: t('已应用“快速观察”：30 秒，敏感产物采集关闭。', 'Applied Quick observe: 30 seconds, sensitive artifact collection off.')
                },
                standard: {
                  seconds: 120,
                  collectDroppedFiles: true,
                  captureScreenshots: true,
                  captureMemoryDumps: false,
                  capturePacketCapture: true,
                  message: t('已应用“标准动态”：120 秒，采集落地文件、截图和 PCAP。', 'Applied Standard dynamic: 120 seconds with dropped files, screenshots, and PCAP.')
                },
                evidence: {
                  seconds: 180,
                  collectDroppedFiles: true,
                  captureScreenshots: true,
                  captureMemoryDumps: false,
                  capturePacketCapture: true,
                  message: t('已应用“证据优先”：180 秒，强化报告可见证据。', 'Applied Evidence-first: 180 seconds with stronger report-visible evidence.')
                },
                memory: {
                  seconds: 180,
                  collectDroppedFiles: true,
                  captureScreenshots: true,
                  captureMemoryDumps: true,
                  capturePacketCapture: true,
                  message: t('已应用“内存取证”：180 秒，启用内存 dump；Guest 支持时包含子进程。', 'Applied Memory forensic: 180 seconds with memory dumps; child processes included when Guest supports it.')
                }
              };
              const preset = presets[name] || presets.standard;
              if (duration) {
                duration.value = String(preset.seconds);
              }

              if (hiddenDuration) {
                hiddenDuration.value = String(preset.seconds);
              }

              const unlimited = document.getElementById('uploadDurationUnlimited');
              if (unlimited) {
                unlimited.checked = false;
              }

              setChecked('collectDroppedFiles', preset.collectDroppedFiles);
              setChecked('captureScreenshots', preset.captureScreenshots);
              setChecked('captureMemoryDumps', preset.captureMemoryDumps);
              setChecked('capturePacketCapture', preset.capturePacketCapture);
              getAnalysisDuration();
              applyArtifactCollectionSupport();
              renderVmConfigSummary();
              renderSelectedSample();
              renderOperatorReadinessChips();
              setStatus(preset.message, false);
            }

            function setupOperatorReadinessListeners() {
              const ids = [
                'sampleUpload',
                'uploadDuration',
                'uploadDurationUnlimited',
                'goldenVmName',
                'goldenSnapshotName',
                'guestUserName',
                'guestWorkingDirectory',
                'guestPayloadRoot',
                'useMockCollector',
                'collectDroppedFiles',
                'captureScreenshots',
                'captureMemoryDumps',
                'capturePacketCapture'
              ];
              for (const id of ids) {
                const element = document.getElementById(id);
                if (!element) {
                  continue;
                }

                element.addEventListener('input', () => {
                  renderConfigDefaultHints();
                  renderSelectedSample();
                  renderOperatorReadinessChips();
                });
                element.addEventListener('change', () => {
                  renderConfigDefaultHints();
                  renderSelectedSample();
                  renderOperatorReadinessChips();
                });
              }
            }

            function setupUploadDropZone() {
              const zone = document.getElementById('uploadDropZone');
              const input = document.getElementById('sampleUpload');
              if (!zone || !input) {
                return;
              }

              zone.addEventListener('click', event => {
                if (event.target === input || event.target.closest('button')) {
                  return;
                }

                input.click();
              });
              zone.addEventListener('dragover', event => {
                event.preventDefault();
                zone.classList.add('dragging');
              });
              zone.addEventListener('dragleave', () => zone.classList.remove('dragging'));
              zone.addEventListener('drop', event => {
                event.preventDefault();
                zone.classList.remove('dragging');
                if (!event.dataTransfer || !event.dataTransfer.files || event.dataTransfer.files.length === 0) {
                  return;
                }

                try {
                  input.files = event.dataTransfer.files;
                } catch {
                  setStatus(t('浏览器不允许直接写入拖拽文件列表；请点击上传区域手动选择该 .exe。', 'The browser did not allow assigning dropped files; click the upload zone and choose the .exe manually.'), true);
                  return;
                }

                input.dispatchEvent(new Event('change', { bubbles: true }));
              });
            }

            function setElementTextAndCopy(id, text) {
              const element = document.getElementById(id);
              if (!element) {
                return;
              }

              element.textContent = text;
              element.setAttribute('data-copy', text);
            }

            function setupConfigSummaryListeners() {
              const ids = [
                'uploadDuration',
                'uploadDurationUnlimited',
                'goldenVmName',
                'goldenSnapshotName',
                'guestUserName',
                'guestWorkingDirectory',
                'guestPayloadRoot',
                'useMockCollector',
                'collectDroppedFiles',
                'captureScreenshots',
                'captureMemoryDumps',
                'capturePacketCapture'
              ];
              for (const id of ids) {
                const element = document.getElementById(id);
                if (!element) {
                  continue;
                }

                element.addEventListener('input', renderVmConfigSummary);
                element.addEventListener('change', renderVmConfigSummary);
              }
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
              const scanPath = document.getElementById('scanPath');
              const maxDepth = document.getElementById('maxDepth');
              if (!scanPath || !maxDepth) {
                setStatus(t('目录扫描入口已从主 dashboard 移除；请使用上传入口提交样本。', 'Folder scan is no longer shown on the main dashboard; use the upload entry to submit a sample.'), true);
                return null;
              }

              setBusy(true);
              setStatus(t('正在扫描路径...', 'Scanning host path...'), false);
              try {
                const response = await fetch('/api/files/scan', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    path: scanPath.value,
                    maxDepth: Number(maxDepth.value || 4),
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
                renderSelectedSample();
                return;
              }

              const file = input.files[0];
              if (!/\.exe$/i.test(file.name || '')) {
                setStatus(t('当前 WebUI 只接受 .exe 文件；请选择可执行样本后重试。', 'The current WebUI accepts only .exe files; choose an executable sample and retry.'), true);
                renderSelectedSample();
                return;
              }

              setBusy(true);
              renderSelectedSample();
              renderOperatorReadinessChips();
              setStatus(t('正在准备上传样本；浏览器会显示真实上传进度，上传完成后 Web Host 会创建任务并尝试提交后台 VM 分析。', 'Preparing to upload the sample; the browser will show real upload progress. After upload, the Web Host creates a job and attempts background VM analysis.'), false);
              setUploadAutoStartNotice(
                t('正在提交一键动态分析', 'Submitting one-click dynamic analysis'),
                t('正在调用 /api/files/upload/start；完成后当前页面会自动进入实时监控页，不会打开弹窗。', 'Calling /api/files/upload/start; when complete, the current page navigates to the live monitor without a popup.'),
                '一键路径：接口=/api/files/upload/start；状态=提交中；跳转=/jobs/{jobId}/live-events；弹窗=否 / endpoint=/api/files/upload/start; state=submitting; redirect=/jobs/{jobId}/live-events; popup=false',
                false);
              try {
                const form = new FormData();
                form.append('sample', input.files[0]);
                appendOneClickAnalysisOptions(form);
                // Keep the one-click route stable: older source gates looked for
                // fetch('/api/files/upload/start'), while production uses XHR
                // here so the browser can show real upload progress.
                const payload = await postFormWithUploadProgress(
                  '/api/files/upload/start',
                  form,
                  t('上传并启动分析', 'Upload and start analysis'),
                  progress => renderUploadTransferProgress(file, progress));
                const uploaded = payload.uploaded || payload.Uploaded || {};
                const job = payload.job || payload.Job || null;

                document.getElementById('samplePath').value = uploaded.fullPath || uploaded.FullPath || '';
                document.getElementById('duration').value = String(getAnalysisDuration());
                if (job) {
                  renderJob(job);
                  applyLanguage();
                  selectWorkspaceTab('analysis');
                  refreshJobs(false);
                }

                const jobId = job && (job.jobId || job.id || job.JobId);
                if (jobId) {
                  const runbookStart = payload.runbookStart || payload.RunbookStart || {};
                  const uploadMonitorHref = payload.uploadMonitorHref || payload.UploadMonitorHref || '';
                  startEstimatedProgress(true);
                  startRunbookProgressPolling(String(jobId));
                  startBackgroundExecutionPolling(String(jobId), true);
                  if (runbookStart.snapshot || runbookStart.Snapshot) {
                    renderBackgroundExecutionSnapshot(runbookStart.snapshot || runbookStart.Snapshot, true);
                  } else {
                    await refreshRunbookProgress(String(jobId), true);
                  }

                  const accepted = Boolean(runbookStart.accepted ?? runbookStart.Accepted);
                  const statusCode = Number(runbookStart.statusCode ?? runbookStart.StatusCode ?? 0);
                  const message = runbookStart.message || runbookStart.Message || '';
                  const startFailed = !accepted && statusCode >= 400;
                  if (startFailed) {
                    renderStages(progressStageIndex, false, true);
                    renderUploadMonitorHandoff(
                      String(jobId),
                      runbookStart,
                      uploadMonitorHref,
                      true,
                      message || t('任务已创建，但后台虚拟机分析预检失败；请打开进度页查看原因。', 'Job was created, but background VM analysis preflight failed; open the progress page for details.'),
                      4200);
                  } else {
                    renderUploadMonitorHandoff(
                      String(jobId),
                      runbookStart,
                      uploadMonitorHref,
                      false,
                      t('上传完成，后台虚拟机分析已提交；正在进入动态监控页查看真实进度。', 'Upload completed; background VM analysis has been submitted and is entering the dynamic monitor for real progress.'),
                      850);
                  }
                  redirectToLiveMonitor(String(jobId), runbookStart, uploadMonitorHref, startFailed ? 4200 : 850);
                } else {
                  setStatus(t('上传完成但未返回任务 ID；请查看近期任务列表。', 'Upload completed but no job id was returned; check the recent jobs list.'), true);
                }
              } catch (error) {
                setStatus(error.message, true);
              } finally {
                setBusy(false);
              }
            }

            function postFormWithUploadProgress(url, form, action, onProgress) {
              // Inputs: multipart form data and a progress callback. Processing
              // uses XMLHttpRequest because fetch does not expose browser upload
              // byte progress. Return: parsed JSON payload from the existing
              // upload/start endpoint.
              return new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', url);
                xhr.responseType = 'text';
                xhr.upload.onprogress = event => {
                  if (onProgress) {
                    onProgress({
                      phase: 'uploading',
                      lengthComputable: event.lengthComputable,
                      loaded: event.loaded || 0,
                      total: event.total || 0
                    });
                  }
                };
                xhr.upload.onload = () => {
                  if (onProgress) {
                    onProgress({ phase: 'processing' });
                  }
                };
                xhr.onload = () => {
                  const payload = parseXhrPayload(xhr.responseText);
                  if (xhr.status >= 200 && xhr.status < 300) {
                    resolve(payload);
                    return;
                  }

                  reject(new Error(formatHttpError(action, xhr, payload)));
                };
                xhr.onerror = () => reject(new Error(t('上传请求无法连接 Web Host；请确认服务仍在运行，任务尚未创建。', 'Upload request could not reach the Web Host; confirm the service is still running. No job was created.')));
                xhr.ontimeout = () => reject(new Error(t('上传请求超时；任务尚未创建，请稍后重试。', 'Upload request timed out; no job was created. Retry later.')));
                xhr.send(form);
              });
            }

            function parseXhrPayload(text) {
              if (!text) {
                return {};
              }

              try {
                return JSON.parse(text);
              } catch {
                return { raw: text };
              }
            }

            function renderUploadTransferProgress(file, progress) {
              if (!progress || progress.phase === 'processing') {
                const message = t('样本已上传到 Web Host；正在创建任务、生成计划并尝试提交后台 VM 分析，随后当前页面进入动态监控页。', 'Sample uploaded to the Web Host; creating the job, generating the plan, and attempting background VM analysis, then this page enters the dynamic monitor.');
                setStatus(message, false);
                setUploadAutoStartNotice(
                  t('上传已完成，等待后台接管', 'Upload complete; waiting for background handoff'),
                  message,
                  `阶段=后台接管中 / phase=processing; endpoint=/api/files/upload/start; redirect=/jobs/{jobId}/live-events; no popup or extra dashboard tab required`,
                  false,
                  '',
                  '');
                return;
              }

              const name = file?.name || t('样本', 'sample');
              const loaded = Math.max(0, Number(progress.loaded) || 0);
              const total = Math.max(0, Number(progress.total) || 0);
              if (progress.lengthComputable && total > 0) {
                const percent = Math.max(0, Math.min(100, Math.round((loaded / total) * 100)));
                const message = t(
                  `正在上传 ${name}：${percent}%（${formatBytes(loaded)} / ${formatBytes(total)}）。上传完成后会创建任务并尝试提交 VM 分析。`,
                  `Uploading ${name}: ${percent}% (${formatBytes(loaded)} / ${formatBytes(total)}). After upload, the job is created and VM analysis is attempted.`);
                setStatus(message, false);
                setUploadAutoStartNotice(
                  t('正在上传：一键接管排队中', 'Uploading: one-click handoff queued'),
                  message,
                  `阶段=上传中 / phase=uploading; 样本 / sample=${name}; 进度 / percent=${percent}; endpoint=/api/files/upload/start; redirect=/jobs/{jobId}/live-events`,
                  false,
                  '',
                  '');
                return;
              }

              const message = t(
                `正在上传 ${name}：已发送 ${formatBytes(loaded)}。上传完成后会创建任务并尝试提交 VM 分析。`,
                `Uploading ${name}: sent ${formatBytes(loaded)}. After upload, the job is created and VM analysis is attempted.`);
              setStatus(message, false);
              setUploadAutoStartNotice(
                t('正在上传：一键接管排队中', 'Uploading: one-click handoff queued'),
                message,
                `阶段=上传中 / phase=uploading; 样本 / sample=${name}; 已发送 / sent=${formatBytes(loaded)}; endpoint=/api/files/upload/start; redirect=/jobs/{jobId}/live-events`,
                false,
                '',
                '');
            }

            function renderUploadMonitorHandoff(jobId, runbookStart, monitorHref, isError, message, delayMs) {
              const target = document.getElementById('status');
              if (!target) {
                return;
              }

              const href = buildUploadMonitorHref(jobId, runbookStart, monitorHref);
              const progressHref = `/jobs/${encodeURIComponent(jobId)}/execution-flow`;
              const state = String((runbookStart && (runbookStart.state || runbookStart.State)) || 'submitted');
              const delaySeconds = Math.max(1, Math.round((Number(delayMs) || 0) / 1000));
              const headline = isError
                ? t('任务已创建，但 VM 分析启动未通过', 'Job created, but VM analysis did not start')
                : t('任务已创建，正在进入实时监控', 'Job created; entering live monitor');
              const detail = localizeServerMessage(message || (isError
                ? t('后台启动预检未通过；监控页会保留任务上下文，执行流程页可查看失败阶段。', 'Background preflight did not pass; the monitor keeps job context and the execution-flow page shows the failed stage.')
                : t('后台执行已交给 Web Host；监控页会显示真实进度流、原始事件和证据入口。', 'Background execution has been handed to the Web Host; the monitor shows the real progress stream, raw events, and evidence links.')));
              const countdown = t(`约 ${delaySeconds} 秒后自动打开监控页。`, `Opening the monitor automatically in about ${delaySeconds} seconds.`);
              const copy = `${headline}; 任务 / job=${jobId}; 状态 / state=${state}; 监控页 / monitor=${href}; 详情 / detail=${detail}`;
              target.className = `status ${isError ? 'error' : 'ok'}`;
              target.setAttribute('data-copy', copy);
              target.setAttribute('data-copy-label', 'upload monitor handoff');
              target.innerHTML = `
                <strong>${escapeHtml(headline)}</strong>
                <p>${escapeHtml(detail)}</p>
                <p class="hint">${escapeHtml(countdown)} ${escapeHtml(t('如果浏览器未跳转，请使用下方按钮；不需要重新上传。', 'If the browser does not navigate, use the buttons below; do not upload again.'))}</p>
                <p class="button-row">
                  <a class="buttonlink" href="${escapeAttribute(href)}" data-copy="${escapeAttribute(href)}">${escapeHtml(t('打开实时监控页', 'Open live monitor'))}</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeAttribute(progressHref)}" data-copy="${escapeAttribute(progressHref)}">${escapeHtml(t('打开进度页（执行流程）', 'Open progress page (execution flow)'))}</a>
                </p>`;
              setUploadAutoStartNotice(headline, `${detail} ${countdown}`, copy, isError, href, progressHref);
            }

            function setUploadAutoStartNotice(headline, detail, copy, isError, monitorHref, progressHref) {
              const notice = document.getElementById('uploadAutoStartNotice');
              if (!notice) {
                return;
              }

              const copyValue = copy || `${headline}; ${detail}`;
              notice.className = `callout ${isError ? 'error' : ''}`;
              notice.setAttribute('data-copy', copyValue);
              notice.setAttribute('data-copy-label', 'upload auto-start live redirect affordance');
              const monitor = monitorHref
                ? `<a class="buttonlink" href="${escapeAttribute(monitorHref)}" data-copy="${escapeAttribute(monitorHref)}">${escapeHtml(t('进入动态监控页', 'Enter dynamic monitor'))}</a>`
                : '';
              const progress = progressHref
                ? `<a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeAttribute(progressHref)}" data-copy="${escapeAttribute(progressHref)}">${escapeHtml(t('打开进度页', 'Open progress page'))}</a>`
                : '';
              notice.innerHTML = `
                <strong>${escapeHtml(headline)}</strong>
                <p class="hint">${escapeHtml(detail)}</p>
                <p class="button-row">
                  <button class="copy-btn" type="button" data-copy="${escapeAttribute(copyValue)}" data-copy-label="upload handoff summary">${escapeHtml(t('复制一键路径', 'Copy handoff path'))}</button>
                  ${monitor}
                  ${progress}
                </p>`;
            }

            function buildUploadMonitorHref(jobId, runbookStart, monitorHref) {
              if (monitorHref) {
                return monitorHref;
              }

              const accepted = Boolean(runbookStart && (runbookStart.accepted ?? runbookStart.Accepted));
              const state = encodeURIComponent(String((runbookStart && (runbookStart.state || runbookStart.State)) || 'submitted'));
              return `${buildLiveMonitorHref(jobId)}?fromUpload=1&accepted=${accepted ? '1' : '0'}&state=${state}`;
            }

            function redirectToLiveMonitor(jobId, runbookStart, suppliedMonitorHref, delayMs) {
              // Inputs: created job id plus the server-side background-start
              // result. Processing navigates the current page to the dedicated
              // dynamic monitor because /api/files/upload/start already handed
              // execution to the Web host background runner; return: none.
              const monitorHref = buildUploadMonitorHref(jobId, runbookStart, suppliedMonitorHref);
              setTimeout(() => {
                window.location.href = monitorHref;
              }, Math.max(0, Number(delayMs) || 850));
            }

            function appendOneClickAnalysisOptions(form) {
              // Inputs: an upload FormData object and current UI controls.
              // Processing copies the same VM/artifact options used by JSON
              // planning into multipart fields, plus the live-run defaults.
              // Return: mutates the FormData in place for /api/files/upload/start.
              form.append('durationSeconds', String(getAnalysisDuration()));
              form.append('durationUnlimited', isDurationUnlimited() ? 'true' : 'false');
              form.append('runtimeLimitMode', isDurationUnlimited() ? 'unlimited' : 'bounded');
              form.append('live', 'true');
              form.append('importGuestEvents', 'true');
              form.append('stepTimeoutSeconds', isDurationUnlimited() ? '0' : '1800');
              const vm = getVmConfig();
              for (const [key, value] of Object.entries(vm)) {
                if (value !== undefined && value !== null) {
                  form.append(key, String(value));
                }
              }

              const artifacts = getArtifactCollectionConfig();
              for (const [key, value] of Object.entries(artifacts)) {
                if (isArtifactOptionSupported(key)) {
                  form.append(key, value ? 'true' : 'false');
                }
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
                    durationSeconds: getAnalysisDuration(),
                    durationUnlimited: isDurationUnlimited(),
                    dryRun: true,
                    ...getVmConfig(),
                    ...getArtifactCollectionConfig()
                  })
                });
                const payload = await requireOk(response, t('生成分析计划', 'Create analysis plan'));

                renderJob(payload);
                applyLanguage();
                refreshJobs(false);
                selectWorkspaceTab('analysis');
                setStatus(t('计划已生成。确认当前任务卡片后，可启动虚拟机分析。', 'Plan created. Review the current job card, then start VM analysis when ready.'), false);
                document.getElementById('current-job').scrollIntoView({ behavior: 'smooth', block: 'start' });
                return payload;
              } catch (error) {
                setStatus(error.message, true);
                return null;
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
              const count = document.getElementById('candidateCount');
              const container = document.getElementById('candidates');
              if (!count || !container) {
                setStatus(t('目录扫描入口已从主 dashboard 移除；请使用上传入口提交样本。', 'Folder scan is no longer shown on the main dashboard; use the upload entry to submit a sample.'), true);
                return;
              }

              count.textContent = result.candidates.length;
              if (!result.candidates.length) {
                container.innerHTML = '<p data-zh="没有找到 .exe 候选项。" data-en="No .exe candidates found.">没有找到 .exe 候选项。</p>';
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
              container.innerHTML = `
                <table>
                  <thead><tr><th></th><th data-zh="名称" data-en="Name">名称</th><th data-zh="路径" data-en="Path">路径</th><th data-zh="大小" data-en="Size">大小</th><th data-zh="操作" data-en="Action">操作</th></tr></thead>
                  <tbody>${rows}</tbody>
                </table>
                <p><button class="secondary" onclick="planSelectedCandidate()" data-zh="规划选中的候选项" data-en="Plan selected candidate">规划选中的候选项</button></p>
                ${warnings ? `<p class="hint" data-zh="警告：" data-en="Warnings:">警告：</p><ul class="hint">${warnings}</ul>` : ''}`;
              applyLanguage();
            }

            function normalizeJobPayload(rawJob) {
              // Inputs: a job payload from current raw AnalysisJob endpoints or
              // future DTO/contract-shaped endpoints. Processing flattens the
              // fields consumed by Dashboard so UI rendering is resilient to
              // jobId/id, flat artifact paths, nested artifactPaths, or nested
              // report objects. Return: a shallow normalized job object.
              const raw = rawJob || {};
              const artifactPaths = raw.artifactPaths || raw.artifacts || {};
              const report = raw.report || {};
              const sample = raw.sample || {};
              const submission = raw.submission || {};
              return {
                ...raw,
                jobId: raw.jobId || raw.id || raw.jobID || '',
                status: raw.status ?? raw.state ?? raw.analysisStatus ?? '',
                sample: {
                  ...sample,
                  fullPath: sample.fullPath || sample.path || raw.samplePath || submission.samplePath || ''
                },
                submission: {
                  ...submission,
                  samplePath: submission.samplePath || raw.samplePath || sample.fullPath || sample.path || '',
                  durationSeconds: submission.durationSeconds ?? submission.DurationSeconds ?? raw.durationSeconds ?? raw.analysisDurationSeconds ?? '',
                  durationUnlimited: Boolean(submission.durationUnlimited ?? submission.DurationUnlimited ?? raw.durationUnlimited ?? raw.DurationUnlimited ?? false)
                },
                jsonReportPath: raw.jsonReportPath || artifactPaths.reportJsonPath || artifactPaths.jsonReportPath || report.jsonReportPath || report.reportJsonPath || '',
                htmlReportPath: raw.htmlReportPath || artifactPaths.reportHtmlPath || artifactPaths.htmlReportPath || report.htmlReportPath || report.reportHtmlPath || '',
                htmlReportZhPath: raw.htmlReportZhPath || raw.reportZhHtmlPath || artifactPaths.reportZhHtmlPath || artifactPaths.htmlReportZhPath || report.htmlReportZhPath || report.reportZhHtmlPath || '',
                htmlReportEnPath: raw.htmlReportEnPath || raw.reportEnHtmlPath || artifactPaths.reportEnHtmlPath || artifactPaths.htmlReportEnPath || report.htmlReportEnPath || report.reportEnHtmlPath || '',
                guestEventsPath: raw.guestEventsPath || artifactPaths.eventsJsonPath || artifactPaths.guestEventsPath || report.guestEventsPath || '',
                runbookExecutionResultPath: raw.runbookExecutionResultPath || artifactPaths.runbookExecutionPath || artifactPaths.runbookExecutionResultPath || '',
                messages: Array.isArray(raw.messages) ? raw.messages : []
              };
            }

            function buildReportState(job) {
              // Inputs: a normalized job. Processing distinguishes an initial
              // planning/static report from a dynamic report refreshed after VM
              // execution and guest import. Return: badge/link labels.
              const hasReport = Boolean(job.htmlReportPath || job.htmlReportZhPath || job.htmlReportEnPath);
              const hasGuestImport = Boolean(job.guestEventsPath);
              const completed = Number(job.status) === 4 || String(job.status).toLowerCase() === 'completed';
              const failed = Number(job.status) === 5 || String(job.status).toLowerCase() === 'failed';
              if (hasReport && hasGuestImport && completed) {
                return {
                  kind: 'dynamic',
                  ready: true,
                  badgeClass: 'pill ready',
                  badge: t('动态报告已生成', 'Dynamic report ready'),
                  link: t('打开动态报告', 'Open dynamic report'),
                  hint: t('虚拟机分析与事件导入已完成，当前报告包含动态行为。', 'VM analysis and event import completed; this report includes dynamic behavior.')
                };
              }

              if (hasReport && failed) {
                return {
                  kind: 'failure',
                  ready: true,
                  badgeClass: 'pill',
                  badge: t('失败报告已生成', 'Failure report ready'),
                  link: t('打开失败报告', 'Open failure report'),
                  hint: t('分析失败但报告已记录失败原因和当前证据。', 'Analysis failed, but the report records failure reasons and available evidence.')
                };
              }

              if (hasReport) {
                return {
                  kind: 'planning',
                  ready: true,
                  badgeClass: 'pill',
                  badge: t('规划报告已生成', 'Planning report ready'),
                  link: t('打开规划报告', 'Open planning report'),
                  hint: t('这是规划/静态报告；点击“启动虚拟机分析”后才会刷新为动态报告。', 'This is the planning/static report; start VM analysis to refresh it into a dynamic report.')
                };
              }

              return {
                kind: 'missing',
                ready: false,
                badgeClass: 'pill',
                badge: t('待生成', 'Not ready'),
                link: t('打开报告', 'Open report'),
                hint: t('报告尚未生成。', 'No report has been generated yet.')
              };
            }

            function buildArtifactCollectionSummary(job) {
              // Inputs: normalized job payload with submission opt-in fields.
              // Processing: builds a concise operator-facing summary of the
              // sensitive artifact lanes requested for this run. Return: a
              // string suitable for display and right-click copy.
              const submission = job.submission || {};
              const lanes = [
                [submission.collectDroppedFiles, t('落地文件', 'dropped files')],
                [submission.captureScreenshots, t('截图', 'screenshots')],
                [submission.captureMemoryDumps, t('内存转储（含子进程，若支持）', 'memory dumps (children if supported)')],
                [submission.capturePacketCapture, t('网络抓包', 'packet capture')]
              ];
              const enabled = lanes.filter(([value]) => Boolean(value)).map(([, label]) => label);
              return enabled.length > 0
                ? enabled.join(', ')
                : t('未启用敏感产物采集（动态监控页仍会显示基础报告/events 状态）', 'no sensitive artifact collection enabled; the dynamic monitor still shows basic report/events status');
            }

            function formatSubmissionRuntime(submission) {
              if (submission?.durationUnlimited) {
                return t('不限制运行时间', 'no runtime limit');
              }

              const seconds = submission?.durationSeconds;
              return seconds === undefined || seconds === null || seconds === ''
                ? '-'
                : `${seconds}s`;
            }

            function buildVmRunSummary(job) {
              // Inputs: normalized job payload plus loaded config defaults.
              // Processing: summarizes only operator-safe VM choices, avoiding
              // command-line or executor output details. Return: copyable text.
              const submission = job.submission || {};
              const r0Enabled = runtimeConfigDefaults?.driver?.enabled;
              const r0Mode = r0Enabled === false
                ? t('R0：config 关闭', 'R0: disabled by config')
                : (submission.useMockCollector ? t('R0：Mock 采集器（collector）', 'R0: mock collector') : t('R0：真实采集器（collector）', 'R0: real collector'));
              const parts = [
                `${t('VM', 'VM')}: ${submission.goldenVmName || runtimeConfigDefaults?.hyperV?.goldenVmName || t('config 默认', 'config default')}`,
                `${t('检查点', 'Checkpoint')}: ${submission.goldenSnapshotName || runtimeConfigDefaults?.hyperV?.goldenSnapshotName || t('config 默认', 'config default')}`,
                `${t('运行时间', 'Runtime')}: ${formatSubmissionRuntime(submission)}`,
                `${t('Guest', 'Guest')}: ${submission.guestUserName || runtimeConfigDefaults?.guest?.userName || t('config 默认', 'config default')}`,
                r0Mode
              ];
              return parts.join(' · ');
            }

            function renderJob(job) {
              job = normalizeJobPayload(job);
              currentJobPayload = job;
              const jobId = String(job.jobId || '');
              if (latestRunbookProgressSnapshot && String(latestRunbookProgressSnapshot.jobId || '').toLowerCase() !== jobId.toLowerCase()) {
                latestRunbookProgressSnapshot = null;
              }
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
              const currentReportHref = currentLanguage === 'en' ? servedEnReportHref : servedZhReportHref;
              const fileReportHref = toFileUri(htmlReportPath);
              const executionFlowHref = jobId ? `/jobs/${encodeURIComponent(jobId)}/execution-flow` : '';
              const liveEventsHref = jobId ? `/jobs/${encodeURIComponent(jobId)}/live-events` : '';
              const reportState = buildReportState(job);
              const reportBadge = `<span class="${reportState.badgeClass}" data-copy="${escapeAttribute(reportState.badge)}" data-copy-label="report state">${escapeHtml(reportState.badge)}</span>`;
              const primaryReportAction = reportState.ready
                ? `<a class="buttonlink" target="_blank" rel="noopener" href="${escapeHtml(currentReportHref)}" data-report-current="true" data-job-id="${escapeAttribute(jobId)}">${escapeHtml(reportState.link)}</a>`
                : `<button type="button" disabled data-copy="${escapeAttribute(reportState.hint)}" data-copy-label="report pending">${escapeHtml(reportState.link)}</button>`;
              const fallbackReportActions = reportState.ready
                ? `<a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(servedZhReportHref)}" data-zh="中文" data-en="ZH">中文</a>
                   <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(servedEnReportHref)}" data-zh="英文" data-en="EN">英文</a>`
                : `<span class="hint" data-zh="报告生成后这里会自动变为中文/英文入口。" data-en="Chinese/English report entries appear here when the report is ready.">报告生成后这里会自动变为中文/英文入口。</span>`;
              const plannedStepCount = job.runbook?.steps?.length || 0;
              const messages = (job.messages || []).slice(-3).map(message => {
                const displayMessage = localizeServerMessage(message);
                return `<li data-copy="${escapeAttribute(message)}" data-copy-label="job message">${escapeHtml(displayMessage)} ${copyButton(message, 'job message')}</li>`;
              }).join('');
              const artifactCollectionSummary = buildArtifactCollectionSummary(job);
              const vmRunSummary = buildVmRunSummary(job);
              document.getElementById('jobResult').innerHTML = `
                <article class="job-card">
                  <h3><span data-zh="任务已创建" data-en="Job created">任务已创建</span> ${copyableCode(jobId, 'job id')}</h3>
                  <div class="job-summary">
                    <div class="metric"><strong data-zh="状态" data-en="Status">状态</strong><span class="pill" data-copy="${escapeAttribute(statusLabel)}" data-copy-label="job status">${escapeHtml(statusLabel)}</span></div>
                    <div class="metric"><strong data-zh="样本" data-en="Sample">样本</strong>${copyableCode(job.sample?.fullPath || job.submission?.samplePath || '', 'sample path')}</div>
                    <div class="metric"><strong data-zh="运行时间" data-en="Runtime">运行时间</strong><span data-copy="${escapeAttribute(formatSubmissionRuntime(job.submission))}">${escapeHtml(formatSubmissionRuntime(job.submission))}</span></div>
                    <div class="metric"><strong data-zh="报告" data-en="Report">报告</strong>${reportBadge}</div>
                  </div>
                  <p class="hint"><strong>${escapeHtml(t('VM 配置', 'VM configuration'))}</strong> <span class="pill" data-copy="${escapeAttribute(vmRunSummary)}" data-copy-label="VM configuration summary">${escapeHtml(vmRunSummary)}</span></p>
                  <p class="hint"><strong data-zh="产物采集显式启用（opt-in）" data-en="Artifact collection opt-in">产物采集显式启用（opt-in）</strong> <span class="pill" data-copy="${escapeAttribute(artifactCollectionSummary)}" data-copy-label="artifact collection opt-in">${escapeHtml(artifactCollectionSummary)}</span></p>
                  <p class="button-row">
                    <button onclick="executeRunbook('${escapeJs(jobId)}', true, ${job.submission?.durationUnlimited ? 'true' : 'false'})" data-zh="启动虚拟机分析" data-en="Start VM analysis">启动虚拟机分析</button>
                    <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(executionFlowHref)}" data-zh="打开进度页（执行流程）" data-en="Open progress page (execution flow)">打开进度页（执行流程）</a>
                    <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(liveEventsHref)}" onclick="openLiveMonitor('${escapeJs(jobId)}', false); return false;" data-zh="实时原始事件监控（独立页）" data-en="Live raw event monitor (standalone)">实时原始事件监控（独立页）</a>
                  </p>
                  <div class="report-entry" data-copy="${escapeAttribute([servedReportHref, servedZhReportHref, servedEnReportHref].filter(Boolean).join('\n'))}" data-copy-label="served report links">
                    <strong data-zh="报告页" data-en="Report page">报告页</strong>
                    ${primaryReportAction}
                    ${fallbackReportActions}
                    <span class="hint">${escapeHtml(reportState.hint)} <span data-zh="主按钮始终跟随右上角语言；动态分析成功后会自动打开当前语言报告，中文/英文备用入口保留在旁边。" data-en="The primary button follows the language toggle. After successful dynamic analysis, the current-language report opens automatically, with Chinese and English fallbacks beside it.">主按钮始终跟随右上角语言；动态分析成功后会自动打开当前语言报告，中文/英文备用入口保留在旁边。</span></span>
                  </div>
                  <div id="reportNotice" class="report-notice" hidden></div>
                  <div class="callout">
                    <strong data-zh="独立页：实时原始事件监控" data-en="Standalone page: Live raw event monitor">独立页：实时原始事件监控</strong>
                    <p class="hint" data-zh="上传流程会直接跳转到该页；实时原始事件、证据/下载（Artifacts）、VirusTotal 和最终报告跳转都集中在这里。最终结论以报告为准。" data-en="The upload flow redirects directly to this page; raw events, artifacts/downloads, VirusTotal, and final report navigation are concentrated there. The final report remains the source of truth.">上传流程会直接跳转到该页；实时原始事件、证据/下载（Artifacts）、VirusTotal 和最终报告跳转都集中在这里。最终结论以报告为准。</p>
                    <p class="button-row"><a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(liveEventsHref)}" onclick="openLiveMonitor('${escapeJs(jobId)}', false); return false;" data-zh="打开实时原始事件监控" data-en="Open Live raw event monitor">打开实时原始事件监控</a></p>
                  </div>
                  <div id="liveMonitorNotice" class="report-notice" hidden></div>
                  <div id="analysisProgress" class="progress-box stage-progress">
                    <div class="progress-head">
                      <strong data-zh="进度页摘要" data-en="Progress summary">进度页摘要</strong>
                      <span id="progressMeta" class="progress-meta" data-copy-label="progress stage">1/6</span>
                    </div>
                    <p class="button-row progress-links">
                      <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(executionFlowHref)}" data-zh="打开进度页（执行流程）" data-en="Open progress page (execution flow)">打开进度页（执行流程）</a>
                      <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(liveEventsHref)}" onclick="openLiveMonitor('${escapeJs(jobId)}', false); return false;" data-zh="实时原始事件监控（独立页）" data-en="Live raw event monitor (standalone)">实时原始事件监控（独立页）</a>
                    </p>
                    <div class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
                    <div id="progressFacts" class="progress-facts"></div>
                    <div id="stageList" class="stages"></div>
                    <div id="runbookProgressDetails" class="runbook-progress-details"></div>
                    <p class="hint" data-zh="主页面只显示阶段摘要，不含命令行、stdout 或 stderr；需要排障时请打开执行流程页。" data-en="The dashboard shows stage summaries only, not command lines, stdout, or stderr; open the execution-flow page for troubleshooting.">主页面只显示阶段摘要，不含命令行、stdout 或 stderr；需要排障时请打开执行流程页。</p>
                    <p id="progressText" class="hint" data-zh="等待启动。虚拟机恢复/启动可能占用大部分时间。" data-en="Waiting to start. VM restore/start usually takes most of the time.">等待启动。虚拟机恢复/启动可能占用大部分时间。</p>
                  </div>
                  <details id="jobReportPaths" class="compact-details">
                    <summary data-zh="高级：手动事件导入（可选）" data-en="Advanced: manual event import (optional)">高级：手动事件导入（可选）</summary>
                    <p class="hint"><strong data-zh="事件导入状态" data-en="Event import status">事件导入状态</strong> <span class="pill" data-copy="${escapeAttribute(guestImportStatus.label)}" data-copy-label="guest import status">${escapeHtml(guestImportStatus.label)}</span> <span>${escapeHtml(guestImportStatus.detail)}</span></p>
                    <div class="mini-form">
                      <label for="guestImportPath" data-zh="手动事件文件（可选）" data-en="Manual event file (optional)">手动事件文件（可选）</label>
                      <input id="guestImportPath" placeholder="${escapeAttribute(artifactPaths.eventsJsonPath || 'D:\\runtime\\jobs\\<job>\\guest\\events.json')}" value="${escapeAttribute(guestEventsPath || artifactPaths.eventsJsonPath || '')}" data-copy-label="manual guest import path">
                      <p class="button-row">
                        <button class="secondary" onclick="executeRunbook('${escapeJs(jobId)}', false, ${job.submission?.durationUnlimited ? 'true' : 'false'})" data-zh="仅验证流程（不启动虚拟机）" data-en="Verify flow only (no VM start)">仅验证流程（不启动虚拟机）</button>
                        <button class="secondary" onclick="importGuestEvents('${escapeJs(jobId)}')" data-zh="手动导入事件并刷新报告" data-en="Import events manually and refresh report">手动导入事件并刷新报告</button>
                      </p>
                    </div>
                    <p class="hint" data-zh="主页面不再展示证据/下载（artifacts/downloads）路径表；请打开“实时原始事件监控”查看报告、events.json、driver-events.jsonl、截图、转储、PCAP 等下载卡片。" data-en="The dashboard no longer renders an artifacts/downloads path table; open the Live raw event monitor for report, events.json, driver-events.jsonl, screenshots, dumps, PCAP, and other download cards.">主页面不再展示证据/下载（artifacts/downloads）路径表；请打开“实时原始事件监控”查看报告、events.json、driver-events.jsonl、截图、转储、PCAP 等下载卡片。</p>
                  </details>
                  <details class="compact-details">
                    <summary data-zh="最近消息" data-en="Recent messages">最近消息</summary>
                    ${messages ? `<ul>${messages}</ul>` : '<p class="hint" data-zh="暂无任务消息。" data-en="No job messages recorded.">暂无任务消息。</p>'}
                  </details>
                  <div id="executionResult" class="hint" data-copy="计划已就绪；主界面仅显示摘要；排障请打开进度页（执行流程） / plan ready; dashboard summary only; open execution-flow for troubleshooting" data-copy-label="plan summary">${t('计划已就绪。主界面只显示摘要；如需排障，请打开“进度页（执行流程）”。', 'The plan is ready. The dashboard shows a summary only; open the progress page (execution flow) for troubleshooting.')}</div>
                </article>`;
              applyLanguage();
              if (latestRunbookProgressSnapshot) {
                renderRunbookProgress(latestRunbookProgressSnapshot);
              } else {
                renderStages(0, false, false);
              }
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
                selectWorkspaceTab('analysis');
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
              // Inputs: job array from /api/jobs. Processing: renders compact
              // copyable cards with status, report access, and an execution-flow
              // link only. Command lines and raw telemetry stay on their
              // dedicated pages/details.
              // Return: no value.
              const container = document.getElementById('jobList');
              if (!container) {
                return;
              }

              currentJobListPayload = Array.isArray(jobs) ? jobs.slice() : [];

              if (!jobs.length) {
                container.innerHTML = '<p data-zh="当前没有任务。" data-en="No jobs are currently held by the Web host.">当前没有任务。</p>';
                applyLanguage();
                return;
              }

              const cards = jobs.slice().reverse().map(rawJob => {
                const job = normalizeJobPayload(rawJob);
                const jobId = String(job.jobId || '');
                const shortJobId = jobId.length > 14 ? `${jobId.slice(0, 8)}…${jobId.slice(-4)}` : jobId;
                const statusLabel = formatJobStatus(job.status);
                const reportPath = job.htmlReportPath || '';
                const reportHref = `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${currentLanguage === 'en' ? 'en' : 'zh'}`;
                const flowHref = `/jobs/${encodeURIComponent(jobId)}/execution-flow`;
                const liveHref = `/jobs/${encodeURIComponent(jobId)}/live-events`;
                const reportState = buildReportState(job);
                const reportCell = reportPath
                  ? `<a class="buttonlink" target="_blank" rel="noopener" href="${escapeHtml(reportHref)}" data-report-current="true" data-job-id="${escapeAttribute(jobId)}">${escapeHtml(reportState.link)}</a>`
                  : `<span class="hint">${escapeHtml(t('报告待生成', 'Report not ready'))}</span>`;
                return `
                <article class="recent-job-card" data-copy="${escapeAttribute(`任务 / job=${jobId}; 状态 / status=${statusLabel}; 报告 / report=${reportState.badge}`)}" data-copy-label="recent job summary">
                  <h3><span data-zh="任务 / Job" data-en="Job">任务 / Job</span> <code data-copy="${escapeAttribute(jobId)}" data-copy-label="job id">${escapeHtml(shortJobId)}</code></h3>
                  <div class="recent-job-meta">
                    <span class="pill" data-copy="${escapeAttribute(statusLabel)}" data-copy-label="job status">${escapeHtml(statusLabel)}</span>
                    <span class="${reportState.badgeClass}" data-copy="${escapeAttribute(reportState.badge)}" data-copy-label="report state">${escapeHtml(reportState.badge)}</span>
                  </div>
                  <p class="hint">${escapeHtml(reportState.hint)}</p>
                  <p class="button-row">
                    <button class="secondary" onclick="refreshJob('${escapeJs(jobId)}')" data-zh="打开任务" data-en="Open job">打开任务</button>
                    <a class="buttonlink secondary" href="${escapeHtml(flowHref)}" target="_blank" rel="noopener" data-zh="执行流程" data-en="Execution flow">执行流程</a>
                    <a class="buttonlink secondary" href="${escapeHtml(liveHref)}" target="_blank" rel="noopener" data-zh="监控 / 下载" data-en="Monitor / downloads">监控 / 下载</a>
                    ${reportCell}
                  </p>
                </article>`;
              }).join('');

              container.innerHTML = `
                <div class="recent-job-list">${cards}</div>`;
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

            function renderStages(active, completed, failed) {
              const list = document.getElementById('stageList');
              const fill = document.getElementById('progressFill');
              const meta = document.getElementById('progressMeta');
              const box = document.getElementById('analysisProgress');
              if (!list || !fill) {
                return;
              }

              const boundedActive = Math.max(0, Math.min(liveStages.length - 1, Number(active) || 0));
              progressStageIndex = boundedActive;
              progressCompleted = Boolean(completed);
              progressFailed = Boolean(failed);
              if (box) {
                box.classList.toggle('running', !progressCompleted && !progressFailed && boundedActive > 0);
                box.classList.toggle('completed', progressCompleted);
                box.classList.toggle('failed', progressFailed);
              }
              list.innerHTML = liveStages.map((stage, index) => {
                const css = progressCompleted
                  ? 'done'
                  : progressFailed && index === boundedActive
                    ? 'failed'
                    : index < boundedActive
                      ? 'done'
                      : index === boundedActive
                        ? 'active'
                        : '';
                return `<div class="stage ${css}">${escapeHtml(t(stage[0], stage[1]))}<small>${escapeHtml(t(stage[2], stage[3]))}</small></div>`;
              }).join('');
              const percent = progressCompleted ? 100 : Math.min(94, Math.max(8, Math.round((boundedActive / (liveStages.length - 1)) * 100)));
              fill.style.width = `${percent}%`;
              fill.classList.toggle('failed', progressFailed);
              if (meta) {
                const label = progressCompleted
                  ? t(`完成 / ${liveStages.length} 阶段`, `Complete / ${liveStages.length} stages`)
                  : progressFailed
                    ? t(`停在 ${boundedActive + 1}/${liveStages.length}`, `Stopped at ${boundedActive + 1}/${liveStages.length}`)
                    : `${boundedActive + 1}/${liveStages.length}`;
                meta.textContent = label;
                meta.setAttribute('data-copy', `${label}: ${t(liveStages[boundedActive][0], liveStages[boundedActive][1])}`);
              }
              const stage = liveStages[boundedActive];
              renderProgressFacts(
                `${boundedActive + 1}/${liveStages.length} — ${t(stage[0], stage[1])}`,
                '-',
                progressFailed ? t('阶段已停止；请打开执行流程查看失败步骤。', 'Stage stopped; open Execution flow for the failed step.') : '',
                progressFailed);
            }

            function renderProgressFacts(currentLabel, elapsedLabel, failureLabel, isFailure) {
              const facts = document.getElementById('progressFacts');
              if (!facts) {
                return;
              }

              const current = currentLabel || t('等待启动', 'Waiting to start');
              const elapsed = elapsedLabel || '-';
              const failure = failureLabel || (isFailure
                ? t('未记录失败原因；请打开进度页查看技术详情。', 'No failure reason was recorded; open the progress page for technical details.')
                : t('暂无异常', 'No issues'));
              facts.innerHTML = `
                <div class="metric"><strong>${t('当前步骤', 'Current step')}</strong><span data-copy="${escapeAttribute(current)}" data-copy-label="current analysis step">${escapeHtml(current)}</span></div>
                <div class="metric"><strong>${t('已耗时', 'Elapsed')}</strong><span data-copy="${escapeAttribute(elapsed)}" data-copy-label="analysis elapsed">${escapeHtml(elapsed)}</span></div>
                <div class="metric"><strong>${t('失败原因', 'Failure reason')}</strong><span class="${isFailure ? 'error' : 'hint'}" data-copy="${escapeAttribute(failure)}" data-copy-label="analysis failure reason">${escapeHtml(failure)}</span></div>`;
              facts.setAttribute('data-copy', `当前步骤 / step=${current}; 已耗时 / elapsed=${elapsed}; 失败原因 / failure=${failure}`);
              facts.setAttribute('data-copy-label', 'analysis progress summary');
            }

            function startEstimatedProgress(live) {
              stopEstimatedProgress();
              progressStageIndex = live ? 1 : 0;
              progressCompleted = false;
              progressFailed = false;
              renderStages(progressStageIndex, false, false);
              const text = document.getElementById('progressText');
              if (text) {
                text.textContent = live
                  ? t('正在执行虚拟机分析；启动或还原可能需要几十秒到数分钟。', 'Executing VM analysis; start or restore may take tens of seconds to minutes.')
                  : t('正在验证流程（不启动虚拟机）。', 'Verifying flow without starting the VM.');
              }

              progressTimer = setInterval(() => {
                progressStageIndex = Math.min(liveStages.length - 2, progressStageIndex + 1);
                renderStages(progressStageIndex, false, false);
                const stage = liveStages[progressStageIndex];
                if (text) {
                  text.textContent = `${t('当前阶段', 'Current stage')}: ${t(stage[0], stage[1])} — ${t(stage[2], stage[3])}`;
                }
              }, live ? 9000 : 1500);
            }

            function stopEstimatedProgress() {
              if (progressTimer) {
                clearInterval(progressTimer);
                progressTimer = null;
              }
            }

            function startRunbookProgressPolling(jobId) {
              // Inputs: current job id. Processing: polls the UI-safe progress
              // endpoint after /runbook/start accepts background execution,
              // replacing the old estimated progress with real runbook step state. Return:
              // no value; polling stops on terminal executor states.
              stopRunbookProgressPolling();
              if (!jobId) {
                return;
              }

              const tick = async () => {
                const terminal = await refreshRunbookProgress(jobId, true);
                if (terminal) {
                  stopRunbookProgressPolling();
                }
              };
              tick();
              runbookProgressTimer = setInterval(tick, 1500);
            }

            function stopRunbookProgressPolling() {
              if (runbookProgressTimer) {
                clearInterval(runbookProgressTimer);
                runbookProgressTimer = null;
              }
            }

            async function refreshRunbookProgress(jobId, quiet) {
              // Inputs: job id and quiet flag. Processing: GETs the latest
              // progress snapshot, renders exact step count/current step, and
              // returns true for terminal states. It never renders PowerShell,
              // stdout, or stderr in the main dashboard.
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/progress`, { cache: 'no-store' });
                const snapshot = await requireOk(response, t('刷新执行进度', 'Refresh analysis progress'));
                renderRunbookProgress(snapshot);
                const state = normalizeProgressState(snapshot.state);
                return state === 'completed' || state === 'failed' || state === 'canceled' || snapshot.success === true || snapshot.success === false;
              } catch (error) {
                if (!quiet) {
                  setStatus(error.message, true);
                }
                return false;
              }
            }

            function normalizeProgressState(state) {
              const value = String(state || '').trim().toLowerCase();
              return value || 'pending';
            }

            function progressStateLabel(state) {
              switch (normalizeProgressState(state)) {
                case 'running': return t('运行中', 'Running');
                case 'completed': return t('已完成', 'Completed');
                case 'failed': return t('失败', 'Failed');
                case 'canceled': return t('已取消', 'Canceled');
                case 'skipped': return t('已跳过', 'Skipped');
                default: return t('等待中', 'Pending');
              }
            }

            function estimateFriendlyStageIndex(totalSteps, currentStepIndex, completedSteps, done, failed) {
              if (done) {
                return liveStages.length - 1;
              }

              const total = Math.max(1, Number(totalSteps) || 1);
              const numerator = Math.max(0, currentStepIndex >= 0 ? currentStepIndex : completedSteps);
              const ratio = Math.max(0, Math.min(1, numerator / total));
              const stageIndex = Math.round(ratio * (liveStages.length - 1));
              return Math.max(0, Math.min(liveStages.length - 1, failed ? Math.max(stageIndex, 1) : stageIndex));
            }

            function renderFriendlyProgressStages(activeIndex, completed, failed) {
              const boundedActive = Math.max(0, Math.min(liveStages.length - 1, Number(activeIndex) || 0));
              return liveStages.map((stage, index) => {
                const css = completed
                  ? 'done'
                  : failed && index === boundedActive
                    ? 'failed'
                    : index < boundedActive
                      ? 'done'
                      : index === boundedActive
                        ? 'active'
                        : '';
                return `<div class="stage ${css}" data-copy="${escapeAttribute(`${t(stage[0], stage[1])} - ${t(stage[2], stage[3])}`)}" data-copy-label="analysis stage">${escapeHtml(t(stage[0], stage[1]))}<small>${escapeHtml(t(stage[2], stage[3]))}</small></div>`;
              }).join('');
            }

            function renderRunbookProgress(snapshot) {
              const list = document.getElementById('stageList');
              const fill = document.getElementById('progressFill');
              const meta = document.getElementById('progressMeta');
              const text = document.getElementById('progressText');
              const details = document.getElementById('runbookProgressDetails');
              const box = document.getElementById('analysisProgress');
              if (!snapshot || !list || !fill) {
                return;
              }

              stopEstimatedProgress();
              latestRunbookProgressSnapshot = snapshot;
              const steps = Array.isArray(snapshot.steps) ? snapshot.steps : [];
              const total = Math.max(steps.length, Number(snapshot.totalSteps) || 0);
              const completed = Math.max(0, Number(snapshot.completedSteps) || steps.filter(step => ['completed', 'skipped'].includes(normalizeProgressState(step.state))).length);
              const executed = Math.max(0, Number(snapshot.executedSteps) || 0);
              const state = normalizeProgressState(snapshot.state);
              const failed = state === 'failed' || state === 'canceled' || snapshot.success === false;
              const done = state === 'completed' || snapshot.success === true;
              const currentIndex = snapshot.currentStepIndex === null || snapshot.currentStepIndex === undefined ? -1 : Number(snapshot.currentStepIndex);
              const currentStep = currentIndex >= 0 && currentIndex < steps.length ? steps[currentIndex] : null;
              const friendlyStageIndex = estimateFriendlyStageIndex(total, currentIndex, completed, done, failed);
              const friendlyStage = liveStages[friendlyStageIndex] || liveStages[0];
              const realPercent = total > 0 ? Math.round((Math.max(completed, currentIndex >= 0 ? currentIndex : 0) / total) * 100) : (done ? 100 : 0);
              const stagePercent = Math.round((friendlyStageIndex / Math.max(1, liveStages.length - 1)) * 100);
              const percent = done ? 100 : Math.min(99, Math.max(failed ? realPercent : 4, realPercent, stagePercent));
              const currentTitle = currentStep ? (currentStep.title || currentStep.stepId || '') : (snapshot.currentStepTitle || '');
              const currentStepLabel = t(friendlyStage[0], friendlyStage[1]);
              const elapsed = formatDuration(snapshot.duration) || '-';
              const failedStep = steps.find(step => ['failed', 'canceled'].includes(normalizeProgressState(step.state)));
              const failureReason = getRunbookFailureReason(snapshot, failedStep, failed);
              fill.style.width = `${done ? 100 : Math.min(99, Math.max(failed ? percent : 4, percent))}%`;
              fill.classList.toggle('failed', failed);
              progressCompleted = done;
              progressFailed = failed;
              progressStageIndex = friendlyStageIndex;
              if (box) {
                box.classList.toggle('running', !done && !failed);
                box.classList.toggle('completed', done);
                box.classList.toggle('failed', failed);
              }

              if (meta) {
                const label = done
                  ? t('分析完成', 'Analysis complete')
                  : failed
                    ? t('分析已停止', 'Analysis stopped')
                    : t(`分析进度约 ${percent}%`, `Analysis about ${percent}%`);
                meta.textContent = label;
                meta.setAttribute('data-copy', `${label}; 已耗时 / elapsed=${elapsed}; 已执行 / executed=${executed}; 状态 / state=${state}; 问题 / issue=${failureReason || '-'}`);
              }

              const currentPrefix = done
                ? t('分析已完成，报告入口已就绪', 'Analysis completed; report entry is ready')
                : failed
                  ? t('分析未完成，请打开进度页查看原因', 'Analysis did not complete; open the progress page for details')
                  : currentTitle
                    ? t('正在处理', 'Processing')
                    : t('等待进度更新', 'Waiting for progress updates');
              if (text) {
                text.textContent = done || failed
                  ? currentPrefix
                  : `${currentPrefix}：${currentStepLabel}`;
              }
              renderProgressFacts(currentStepLabel || currentPrefix, elapsed, failureReason, failed);

              list.className = 'stages';
              list.innerHTML = renderFriendlyProgressStages(friendlyStageIndex, done, failed);

              if (details) {
                const flowHref = snapshot.jobId ? `/jobs/${encodeURIComponent(snapshot.jobId)}/execution-flow` : '';
                details.innerHTML = flowHref
                  ? `<p class="hint">${escapeHtml(t('主页面只显示友好摘要；完整技术步骤请打开进度页。', 'The dashboard shows a friendly summary only; open the progress page for the full technical flow.'))} <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(flowHref)}">${escapeHtml(t('打开进度页', 'Open progress page'))}</a></p>`
                  : '';
              }
            }

            function buildProgressFocusSteps(steps, currentIndex, failed, done) {
              const interesting = [];
              const failedStep = steps.find(step => ['failed', 'canceled'].includes(normalizeProgressState(step.state)));
              if (failedStep) {
                interesting.push(failedStep);
              }

              const runningStep = steps.find(step => normalizeProgressState(step.state) === 'running') || (currentIndex >= 0 ? steps[currentIndex] : null);
              if (runningStep && !interesting.includes(runningStep)) {
                interesting.push(runningStep);
              }

              const completed = steps.filter(step => ['completed', 'skipped'].includes(normalizeProgressState(step.state))).slice(-2);
              for (const step of completed) {
                if (!interesting.includes(step)) {
                  interesting.unshift(step);
                }
              }

              if (done && steps.length > 0 && !interesting.includes(steps[steps.length - 1])) {
                interesting.push(steps[steps.length - 1]);
              }

              return interesting.slice(-4);
            }

            function renderProgressStageCard(step, total) {
              const state = normalizeProgressState(step.state);
              const css = state === 'completed' || state === 'skipped'
                ? 'done'
                : state === 'failed' || state === 'canceled'
                  ? 'failed'
                  : state === 'running'
                    ? 'active'
                    : '';
              const title = `${Number(step.stepIndex) + 1}/${total} ${step.title || step.stepId || ''}`;
              const subtitle = `${progressStateLabel(state)}${step.duration ? ` · ${formatDuration(step.duration)}` : ''}${step.exitCode !== null && step.exitCode !== undefined ? ` · ${t('退出码', 'exit')} ${step.exitCode}` : ''}${step.message ? ` · ${localizeServerMessage(step.message)}` : ''}`;
              return `<div class="stage ${css}" data-copy="${escapeAttribute(`${title} - ${subtitle}`)}" data-copy-label="runbook progress step">${escapeHtml(title)}<small>${escapeHtml(subtitle)}</small></div>`;
            }

            function renderRunbookStepChip(step, currentIndex) {
              const state = normalizeProgressState(step.state);
              const css = ['pending', 'running', 'completed', 'failed', 'skipped', 'canceled'].includes(state) ? state : 'pending';
              const title = `${Number(step.stepIndex) + 1}. ${step.title || step.stepId || ''}`;
              const detail = `${progressStateLabel(state)}${step.duration ? ` · ${formatDuration(step.duration)}` : ''}${step.exitCode !== null && step.exitCode !== undefined ? ` · ${t('退出码', 'exit')} ${step.exitCode}` : ''}${step.message ? ` · ${localizeServerMessage(step.message)}` : ''}`;
              return `<div class="runbook-step ${css}" data-copy="${escapeAttribute(`${title} - ${detail}`)}" data-copy-label="runbook step status"><b>${escapeHtml(title)}</b><small>${escapeHtml(detail)}</small></div>`;
            }

            function getRunbookFailureReason(snapshot, failedStep, failed) {
              if (!failed) {
                return '';
              }

              const pieces = [];
              if (failedStep) {
                const title = failedStep.title || failedStep.stepId || '';
                if (title) { pieces.push(`${t('失败步骤', 'Failed step')}: ${title}`); }
                if (failedStep.message) { pieces.push(localizeServerMessage(failedStep.message)); }
                if (failedStep.exitCode !== null && failedStep.exitCode !== undefined) { pieces.push(`${t('退出码', 'exit')} ${failedStep.exitCode}`); }
              }

              if (snapshot && snapshot.message) {
                pieces.push(localizeServerMessage(snapshot.message));
              }

              return pieces.length
                ? pieces.join(' · ')
                : t('未记录失败原因；请打开进度页查看技术详情。', 'No failure reason was recorded; open the progress page for technical details.');
            }

            function openReport(jobId, langOverride) {
              const lang = langOverride || (currentLanguage === 'en' ? 'en' : 'zh');
              window.location.href = `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${lang}`;
            }

            function buildReportHref(jobId, lang) {
              return `/api/jobs/${encodeURIComponent(jobId)}/report/html?lang=${lang}`;
            }

            function buildLiveMonitorHref(jobId) {
              return `/jobs/${encodeURIComponent(jobId)}/live-events`;
            }

            function refreshLocalizedReportLinks() {
              const lang = currentLanguage === 'en' ? 'en' : 'zh';
              document.querySelectorAll('a[data-report-current][data-job-id]').forEach(anchor => {
                const jobId = anchor.getAttribute('data-job-id');
                if (!jobId) {
                  return;
                }

                anchor.href = buildReportHref(jobId, lang);
              });
            }

            function openLiveMonitor(jobId, autoOpenedFromUpload, existingWindow) {
              // Inputs: current job id and optional existing window. Processing
              // opens the standalone dynamic monitor in a new tab for manual
              // job cards only; upload/start uses redirectToLiveMonitor because
              // the Web host background runner owns the long runbook execution.
              // Return: true when the browser provided a window handle, false
              // when it likely blocked.
              if (!jobId) {
                return false;
              }

              const href = buildLiveMonitorHref(jobId);
              let opened = existingWindow && !existingWindow.closed ? existingWindow : null;
              try {
                if (opened) {
                  opened.location.href = href;
                  opened.opener = null;
                } else {
                  opened = window.open(href, '_blank');
                  if (opened) {
                    opened.opener = null;
                  }
                }
              } catch {
                opened = null;
              }

              showLiveMonitorNotice(jobId, Boolean(opened), Boolean(autoOpenedFromUpload));
              return Boolean(opened);
            }

            function showLiveMonitorNotice(jobId, opened, autoOpenedFromUpload) {
              const notice = document.getElementById('liveMonitorNotice');
              if (!notice || !jobId) {
                return;
              }

              const href = buildLiveMonitorHref(jobId);
              const progressHref = `/jobs/${encodeURIComponent(jobId)}/execution-flow`;
              const zhMessage = opened
                ? (autoOpenedFromUpload ? '已尝试在新标签页打开实时原始事件监控；如果新标签仍是空白或被浏览器拦截，请使用下方链接。主界面会继续提交后台分析，当前任务无需重新上传。' : '已尝试打开实时原始事件监控；如果没有出现新标签，请使用下方链接。主界面仍保留进度和报告入口。')
                : '未获得新标签页句柄，浏览器可能阻止了自动打开；请点击下方“实时原始事件监控”。当前任务卡片已保留入口，无需重新上传。';
              const enMessage = opened
                ? (autoOpenedFromUpload ? 'The dashboard tried to open the Live raw event monitor in a new tab. If the new tab stays blank or the browser blocks it, use the link below. This job does not need to be uploaded again.' : 'The dashboard tried to open the Live raw event monitor. If no new tab appeared, use the link below; progress and report links remain here.')
                : 'No new-tab handle was returned, so the browser may have blocked automatic opening. Click Live raw event monitor below; this job does not need to be uploaded again.';
              notice.hidden = false;
              notice.innerHTML = `
                <strong data-zh="实时原始事件监控已准备好" data-en="Live raw event monitor is ready">实时原始事件监控已准备好</strong>
                <p data-zh="${escapeAttribute(zhMessage)}" data-en="${escapeAttribute(enMessage)}">${escapeHtml(zhMessage)}</p>
                <p class="button-row">
                  <a class="buttonlink" target="_blank" rel="noopener" href="${escapeHtml(href)}" data-zh="实时原始事件监控" data-en="Live raw event monitor">实时原始事件监控</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(progressHref)}" data-zh="打开进度页（执行流程）" data-en="Open progress page (execution flow)">打开进度页（执行流程）</a>
                </p>`;
              applyLanguage();
              notice.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }

            function showReportReadyNotice(jobId, autoOpen) {
              const notices = ['reportNotice', 'globalReportNotice']
                .map(id => document.getElementById(id))
                .filter(Boolean);
              if (!notices.length || !jobId) {
                return;
              }

              const currentHref = buildReportHref(jobId, autoOpen ? 'zh' : (currentLanguage === 'en' ? 'en' : 'zh'));
              const zhHref = buildReportHref(jobId, 'zh');
              const enHref = buildReportHref(jobId, 'en');
              const primaryReportAttributes = autoOpen
                ? ''
                : `data-report-current="true" data-job-id="${escapeAttribute(jobId)}"`;
              const html = `
                <strong data-zh="报告已生成" data-en="Report is ready">报告已生成</strong>
                <p data-zh="${autoOpen ? '页面即将打开中文报告 report.zh.html；如果没有跳转，请点击下方按钮。' : '报告已刷新，可直接打开查看。'}" data-en="${autoOpen ? 'The Chinese report (report.zh.html) will open shortly; if it does not, use the buttons below.' : 'The report has been refreshed and is ready to open.'}">${autoOpen ? '页面即将打开中文报告 report.zh.html；如果没有跳转，请点击下方按钮。' : '报告已刷新，可直接打开查看。'}</p>
                ${autoOpen ? '<p class="countdown" data-report-countdown data-copy="" data-copy-label="report auto-open countdown"></p>' : ''}
                <p class="button-row">
                  <a class="buttonlink" href="${escapeHtml(currentHref)}" ${primaryReportAttributes} data-zh="${autoOpen ? '打开中文报告' : '打开报告'}" data-en="${autoOpen ? 'Open Chinese report' : 'Open report'}">${autoOpen ? '打开中文报告' : '打开报告'}</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(zhHref)}" data-zh="新标签打开中文报告" data-en="Open Chinese report in new tab">新标签打开中文报告</a>
                  <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(enHref)}" data-zh="新标签打开英文报告" data-en="Open English report in new tab">新标签打开英文报告</a>
                </p>`;
              for (const notice of notices) {
                notice.hidden = false;
                notice.innerHTML = html;
              }
              applyLanguage();
              selectWorkspaceTab('results');
              (document.getElementById('globalReportNotice') || notices[0]).scrollIntoView({ behavior: 'smooth', block: 'nearest' });
              setStatus(
                autoOpen
                  ? t('报告已生成，正在打开中文报告 report.zh.html；如果没有跳转，请点击“打开中文报告”。', 'Report is ready and opening report.zh.html; if it does not navigate, click Open Chinese report.')
                  : t('报告已生成，可在当前任务卡片中打开。', 'Report is ready; open it from the current job card.'),
                false);
              if (autoOpen) {
                startReportAutoOpenCountdown(jobId);
              }
            }

            function startReportAutoOpenCountdown(jobId) {
              reportAutoOpenJobId = jobId;
              reportAutoOpenDeadline = Date.now() + 5000;
              updateReportAutoOpenCountdown();
              if (reportAutoOpenTimer) {
                clearInterval(reportAutoOpenTimer);
              }

              reportAutoOpenTimer = setInterval(() => {
                updateReportAutoOpenCountdown();
                if (Date.now() >= reportAutoOpenDeadline) {
                  clearInterval(reportAutoOpenTimer);
                  reportAutoOpenTimer = null;
                  openReport(reportAutoOpenJobId, 'zh');
                }
              }, 250);
            }

            function updateReportAutoOpenCountdown() {
              const remaining = Math.max(0, Math.ceil((reportAutoOpenDeadline - Date.now()) / 1000));
              const text = t(`报告就绪，${remaining} 秒后自动跳转到中文报告 report.zh.html。`, `Report ready; auto-opening the Chinese report (report.zh.html) in ${remaining}s.`);
              document.querySelectorAll('[data-report-countdown]').forEach(element => {
                element.textContent = text;
                element.setAttribute('data-copy', text);
              });
            }

            function startBackgroundExecutionPolling(jobId, live) {
              stopBackgroundExecutionPolling();
              const tick = async () => {
                const terminal = await refreshBackgroundExecution(jobId, live, true);
                if (terminal) {
                  stopBackgroundExecutionPolling();
                }
              };
              tick();
              backgroundExecutionTimer = setInterval(tick, 2000);
            }

            function stopBackgroundExecutionPolling() {
              if (backgroundExecutionTimer) {
                clearInterval(backgroundExecutionTimer);
                backgroundExecutionTimer = null;
              }
            }

            async function refreshBackgroundExecution(jobId, live, quiet) {
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/background`, { cache: 'no-store' });
                const snapshot = await requireOk(response, t('刷新后台分析状态', 'Refresh background analysis status'));
                return renderBackgroundExecutionSnapshot(snapshot, live);
              } catch (error) {
                if (!quiet) {
                  setStatus(error.message, true);
                }
                return false;
              }
            }

            function renderBackgroundExecutionSnapshot(snapshot, live) {
              const state = String(snapshot.state || 'not_started').toLowerCase();
              const terminal = state === 'completed' || state === 'failed';
              if (!terminal) {
                const text = document.getElementById('progressText');
                if (text) {
                  text.textContent = state === 'running'
                    ? t('后台分析正在运行；可以停留在此页或查看实时原始事件监控。', 'Background analysis is running; stay here or watch the Live raw event monitor.')
                    : t('后台分析已排队，等待执行器启动。', 'Background analysis is queued and waiting for the executor.');
                }
                return false;
              }

              stopEstimatedProgress();
              stopRunbookProgressPolling();
              if (snapshot.job) {
                renderJob(snapshot.job);
              }

              if (snapshot.execution) {
                renderExecution(snapshot.execution, snapshot);
              }

              applyLanguage();
              refreshJobs(false);
              const execution = snapshot.execution || {};
              const importFailed = Boolean(snapshot.guestImportMessage && !snapshot.guestImportSucceeded);
              const success = Boolean(snapshot.success ?? (execution.success && !importFailed));
              renderStages(liveStages.length - 1, success, !success);
              setStatus(
                (success ? t('后台分析流程已完成。', 'Background analysis flow completed.') : t('后台分析流程失败。', 'Background analysis flow failed.')) +
                  (snapshot.guestImportMessage ? ` ${localizeServerMessage(snapshot.guestImportMessage)}` : ''),
                !success);

              if (live && success) {
                const text = document.getElementById('progressText');
                if (text) {
                  text.textContent = t('分析完成，报告已生成，正在打开。', 'Analysis completed; report is ready and opening.');
                }
                showReportReadyNotice(jobId, true);
              } else if (live && execution.success) {
                const text = document.getElementById('progressText');
                if (text) {
                  text.textContent = t('分析完成，但事件导入未确认；请检查报告入口或手动导入。', 'Analysis completed, but event import was not confirmed; check report links or import events manually.');
                }
                showReportReadyNotice(jobId, false);
              }

              return true;
            }

            async function executeRunbook(jobId, live, durationUnlimited) {
              setBusy(true);
              latestRunbookProgressSnapshot = null;
              startEstimatedProgress(live);
              startRunbookProgressPolling(jobId);
              stopBackgroundExecutionPolling();
              setStatus(live ? t('正在提交后台虚拟机分析...', 'Submitting background VM analysis...') : t('正在提交后台流程验证...', 'Submitting background flow verification...'), false);
              try {
                const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/runbook/start`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    live,
                    stepTimeoutSeconds: durationUnlimited ? 0 : 1800,
                    durationUnlimited: Boolean(durationUnlimited),
                    importGuestEvents: true
                  })
                });
                const payload = await requireOk(response, live ? t('启动后台虚拟机分析', 'Start background VM analysis') : t('启动后台流程验证', 'Start background flow verification'));

                startBackgroundExecutionPolling(jobId, live);
                const text = document.getElementById('progressText');
                if (text) {
                  text.textContent = t('后台任务已启动；友好进度会持续更新，完成后自动打开报告。', 'Background task started; friendly progress will keep updating and the report opens when complete.');
                }
                setStatus(live ? t('虚拟机分析已在后台启动。', 'VM analysis started in the background.') : t('流程验证已在后台启动。', 'Flow verification started in the background.'), false);
                renderBackgroundExecutionSnapshot(payload, live);
              } catch (error) {
                stopEstimatedProgress();
                stopBackgroundExecutionPolling();
                await refreshRunbookProgress(jobId, true);
                if (!latestRunbookProgressSnapshot) {
                  renderStages(progressStageIndex, false, true);
                }
                const text = document.getElementById('progressText');
                if (text) {
                  text.textContent = t('执行未完成；请打开进度页查看失败阶段和诊断详情。', 'Execution did not complete; open the progress page for the failed stage and diagnostics.');
                }
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
              const importMessage = wrapper && wrapper.guestImportMessage ? `<p class="${wrapper.guestImportSucceeded ? 'ok' : 'hint'}" data-copy="${escapeAttribute(wrapper.guestImportMessage)}">${escapeHtml(localizeServerMessage(wrapper.guestImportMessage))}</p>` : '';
              const successClass = result.success ? 'status-ok' : 'status-failed';
              document.getElementById('executionResult').innerHTML = `
                <div class="pathbox" data-copy="执行模式 / mode=${escapeAttribute(result.mode)}; 是否成功 / success=${result.success}; 已执行步骤 / executed=${result.executedSteps}/${result.totalSteps}; 耗时 / duration=${escapeAttribute(formatDuration(result.duration))}" data-copy-label="runbook execution summary">
                  <p><strong>${t('分析结果', 'Analysis result')}:</strong> <span class="${successClass}">${result.success ? t('已完成', 'Completed') : t('未完成', 'Not completed')}</span></p>
                  <p><strong>${t('耗时', 'Duration')}:</strong> ${escapeHtml(formatDuration(result.duration))}</p>
                  ${result.success ? '' : `<p class="error">${escapeHtml(t('主页面不展开技术步骤；请打开进度页查看失败阶段。', 'The dashboard does not expand technical steps; open the progress page for the failed stage.'))}</p>`}
                  ${importMessage}
                  <p class="button-row">
                    <a class="buttonlink secondary" target="_blank" rel="noopener" href="${escapeHtml(flowHref)}" data-zh="打开进度页（执行流程）" data-en="Open progress page (execution flow)">打开进度页（执行流程）</a>
                  </p>
                </div>`;
              applyLanguage();
            }

            function buildArtifactPaths(job) {
              // Inputs: current job payload. Processing: derives recorded and
              // expected report/guest artifact paths without touching the host
              // filesystem. Return: stable labels for display and copy.
              job = normalizeJobPayload(job);
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
              job = normalizeJobPayload(job);
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
              const text = value || emptyText || t('未记录', '(not recorded)');
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
              const detail = localizeServerMessage(extractErrorMessage(payload) || t('服务器未返回错误详情。', 'No error detail was returned by the server.'));
              const traceId = payload && (payload.traceId || payload.requestId);
              const traceText = traceId ? (currentLanguage === 'en' ? `, trace ${traceId}` : `，跟踪 ID ${traceId}`) : '';
              return `${action} ${t('失败', 'failed')} (HTTP ${response.status}${statusText}${traceText}): ${detail} ${t('下一步：', 'Next step: ')}${suggestNextStep(action, response, payload)}`;
            }

            function suggestNextStep(action, response, payload) {
              const actionText = String(action || '');
              const code = String(payload?.error?.code || payload?.code || payload?.title || '').toLowerCase();
              if (response.status === 404 || code.includes('not_found') || code.includes('notfound')) {
                return t('刷新近期任务，确认任务仍在当前 Web Host；如果任务存在，请从任务卡片重新打开监控或报告。', 'Refresh recent jobs and confirm the job still exists in this Web host; if it exists, reopen the monitor or report from the job card.');
              }

              if (response.status === 401 || response.status === 403) {
                return t('检查本机权限、API Key 或启动用户后重试；需要 VirusTotal 时可先打开设置页确认 Key。', 'Check local permissions, API key, or the service account, then retry; for VirusTotal, open Settings to confirm the key.');
              }

              if (/上传|upload/i.test(actionText)) {
                return t('确认选择的是可访问的 .exe 文件，重新上传；如果任务已创建，请在近期任务中打开监控页。', 'Confirm the selected file is an accessible .exe and upload again; if a job was created, open its monitor from recent jobs.');
              }

              if (/计划|plan|候选|scan|扫描/i.test(actionText)) {
                return t('检查样本路径、目录权限和 VM 配置字段，然后重新生成计划。', 'Check the sample path, folder permissions, and VM configuration fields, then create the plan again.');
              }

              if (/导入|import/i.test(actionText)) {
                return t('确认 events.json 或 JSONL 路径存在且可读；路径为空时让系统从当前 job guest 目录重新搜索。', 'Confirm the events.json or JSONL path exists and is readable; leave the field empty to let the system search the current job guest folder again.');
              }

              if (/后台|进度|runbook|progress|background|执行/i.test(actionText)) {
                return t('打开进度页（执行流程）查看失败阶段，并保留本条状态文本用于排障。', 'Open the progress page (execution flow) to inspect the failed stage, and keep this status text for troubleshooting.');
              }

              if (/配置|config|settings/i.test(actionText)) {
                return t('刷新页面重新读取配置；若仍失败，请确认 Web Host 进程仍在运行。', 'Refresh the page to reload config; if it still fails, confirm the Web Host process is running.');
              }

              return t('按当前输入重试；如果重复失败，请打开进度页或监控页查看上下文，并保留跟踪 ID。', 'Retry with the current input; if it repeats, open the progress or monitor page for context and keep the trace ID.');
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

            setupTabKeyboardNavigation();
            setupConfigSummaryListeners();
            setupOperatorReadinessListeners();
            setupUploadDropZone();
            selectWorkspaceTab('plan');
            selectPlanTab('upload');
            applyLanguage();
            renderSelectedSample();
            renderOperatorReadinessChips();
            loadConfigDefaults();
            loadVirusTotalReadiness();
            refreshJobs(false);
          </script>
        </body>
        </html>
        """;
    }
}
