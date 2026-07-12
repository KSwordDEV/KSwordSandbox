using System.Net;
using KSword.Sandbox.Web.Infrastructure;

namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Renders local operator settings. Inputs are masked VirusTotal state;
/// processing writes a bilingual page with a key update form; return value is a
/// self-contained HTML document.
/// </summary>
internal static class SettingsPage
{
    internal static string Render(VirusTotalSettingsState virusTotal)
    {
        return $$"""
        <!doctype html>
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <title>设置 - KSword Sandbox</title>
          <style>
            :root { --blue:#43A0FF; --ink:#0f172a; --muted:#64748b; --line:#dbeafe; color-scheme: light; }
            * { box-sizing: border-box; }
            body { background:linear-gradient(180deg,#f4f9ff,#f8fafc); color:var(--ink); font-family:"Microsoft YaHei UI",Segoe UI,Arial,sans-serif; margin:0; }
            header { background:radial-gradient(circle at 85% 12%,rgba(67,160,255,.55),transparent 30%),linear-gradient(135deg,#08111f,#0f5f9f); color:white; padding:26px 36px; }
            main { max-width:960px; margin:24px auto 52px; padding:0 22px; }
            section { background:rgba(255,255,255,.96); border:1px solid var(--line); border-radius:2px; box-shadow:none; margin-bottom:16px; padding:20px; }
            label { display:block; font-weight:800; margin:14px 0 6px; }
            input { border:1px solid #c7dff7; border-radius:2px; font:inherit; padding:10px 12px; width:100%; }
            button,a.button { background:var(--blue); border:0; border-radius:2px; color:white; cursor:pointer; display:inline-block; font-weight:800; margin-top:12px; padding:10px 14px; text-decoration:none; }
            button.secondary,a.secondary { background:#334155; }
            button.copy-btn { background:#e2e8f0; border:1px solid #cbd5e1; color:#334155; font-size:12px; margin:8px 0 0; padding:5px 8px; }
            button.copy-btn:hover { background:#cbd5e1; }
            .row { display:flex; flex-wrap:wrap; gap:10px; }
            .grid { display:grid; gap:12px; grid-template-columns:repeat(3,minmax(0,1fr)); }
            .metric { background:#f8fbff; border:1px solid var(--line); border-radius:2px; margin-top:10px; padding:12px; }
            .metric strong { color:var(--muted); display:block; font-size:12px; margin-bottom:6px; }
            .pill { background:#e7f3ff; border:1px solid rgba(67,160,255,.45); border-radius:2px; color:#075985; display:inline-block; font-size:12px; font-weight:800; padding:4px 9px; }
            .card { background:#f8fbff; border:1px solid var(--line); border-radius:2px; padding:12px; }
            .card h3 { margin:0 0 8px; }
            .toggle-card { background:white; border:1px solid #e5edf6; border-radius:2px; margin-top:8px; padding:9px; }
            .toggle-card label { align-items:flex-start; display:flex; gap:8px; margin:0; }
            .toggle-card input { margin-top:3px; width:auto; }
            .readonly-toggle { opacity:.82; }
            .field-hint { color:var(--muted); font-size:12px; line-height:1.45; margin:5px 0 0; }
            .summary { display:flex; flex-wrap:wrap; gap:6px; margin-top:12px; }
            .ok { color:#047857; }
            .muted { color:var(--muted); }
            .error { color:#b91c1c; }
            code { background:#eef7ff; border-radius:2px; padding:2px 5px; word-break:break-all; }
            [data-copy], code, .card, .metric, .toggle-card { cursor:copy; }
            [data-copy]:hover, code:hover, input:hover, label:hover, .card:hover, .metric:hover, .toggle-card:hover { outline:1px dashed var(--blue); outline-offset:2px; }
            .toast { background:#0f172a; border-radius:2px; bottom:22px; color:white; left:50%; opacity:0; padding:10px 16px; pointer-events:none; position:fixed; transform:translate(-50%,12px); transition:opacity .15s ease,transform .15s ease; z-index:20; }
            .toast.visible { opacity:.96; transform:translate(-50%,0); }

            /* Square, flat operator theme: keep visual nesting shallow. */
            section, article, .metric, .card, .toggle-card, .pill, button, a.button, a.buttonlink, input, code, pre, .pathbox, .callout, .report-notice, .report-entry, .workspace-tab, .tab-button, .tab-panel, details, .progress-box, .progress-bar, .progress-fill, .stage, .recent-job-card, .runbook-step, .empty, .table-wrap, .step-card, .report-ready, .toast, .num { border-radius: 0 !important; }
            section, article, .metric, .card, .toggle-card, .pathbox, .callout, .report-notice, .report-entry, .tab-panel, .progress-box, .stage, .recent-job-card, .runbook-step, .step-card, .report-ready { box-shadow: none !important; }
            .pill, button, a.button, a.buttonlink { box-shadow: none !important; }
            @media (max-width: 900px) { .grid { grid-template-columns:1fr; } }
          </style>
        </head>
        <body>
          <header>
            <div class="row" style="justify-content:space-between;align-items:flex-start">
              <div>
                <h1 data-zh="设置" data-en="Settings">设置</h1>
                <p data-zh="本页的 VirusTotal API Key 操作仅修改当前 Web Host 进程环境变量；不会写入配置文件、runtime settings、报告或 job 日志，也不会提交到仓库。" data-en="VirusTotal API key actions on this page only change the current Web Host process environment variable; they do not write config files, runtime settings, reports, or job logs, and nothing is committed to the repository.">本页的 VirusTotal API Key 操作仅修改当前 Web Host 进程环境变量；不会写入配置文件、runtime settings、报告或 job 日志，也不会提交到仓库。</p>
              </div>
              <button class="secondary" type="button" onclick="toggleLanguage()" data-zh="切换到 English" data-en="切换到中文">切换到 English</button>
            </div>
            <p class="row"><a class="button secondary" href="/" data-zh="返回主界面" data-en="Back to dashboard">返回主界面</a></p>
          </header>
          <main>
            <section id="vtSettingsSection" data-copy="VirusTotal 状态={{Attr(virusTotal.Configured ? "已配置 / configured" : "未配置 / not-configured")}}；来源={{Attr(virusTotal.Source)}}；API Key=仅当前 Web Host 进程；持久化=不落盘；官方 files/{hash} 只查 SHA-256；不上传样本字节 / VirusTotal status={{Attr(virusTotal.Configured ? "configured" : "not-configured")}}; source={{Attr(virusTotal.Source)}}; process-only key; no sample upload">
              <h2 data-zh="VirusTotal 官方 hash-only 结果" data-en="VirusTotal official hash-only results">VirusTotal 官方 hash-only 结果</h2>
              <p class="muted" data-zh="当前只对样本 SHA-256 调用 VirusTotal 官方 files/{hash} 报告查询；不上传样本字节、不提交扫描 URL、不写样本内容。不配置、未收录、限速、鉴权失败、超时或查询失败时，主流程继续运行且不会产生噪音日志；状态只在动态监控页/API 中静默展示，不写任务日志或行为日志。" data-en="The integration only calls VirusTotal official files/{hash} report lookup for the sample SHA-256; it does not upload sample bytes, submit scan URLs, or write sample contents. Missing keys, not-found, rate limits, auth failures, timeouts, or lookup failures keep the main flow running without noisy logs; status is shown quietly on the live monitor/API without job or behavior logs.">当前只对样本 SHA-256 调用 VirusTotal 官方 files/{hash} 报告查询；不上传样本字节、不提交扫描 URL、不写样本内容。不配置、未收录、限速、鉴权失败、超时或查询失败时，主流程继续运行且不会产生噪音日志；状态只在动态监控页/API 中静默展示，不写任务日志或行为日志。</p>
              <button class="copy-btn" type="button" data-copy="VirusTotal：{{Attr(virusTotal.Configured ? "已配置 / configured" : "未配置 / not-configured")}}；来源={{Attr(virusTotal.Source)}}；API Key 仅写入当前 Web Host 进程；WebUI 不落盘；官方 files/{hash} 只查 hash；不上传样本字节 / process-only key, no persisted secret, official hash lookup only, no sample upload" data-copy-label="VirusTotal settings summary" data-zh="复制本卡摘要" data-en="Copy card summary">复制本卡摘要</button>
              <div class="metric">
                <strong data-zh="安全提示" data-en="Security note">安全提示</strong>
                <p class="muted" data-copy="VirusTotal API Key 仅写入当前 Web Host 进程环境变量 KSWORDBOX_VIRUSTOTAL_API_KEY；WebUI 永不落盘，也不修改 User/Machine 环境变量 / process-only current Web Host key; never persisted to disk." data-zh="在本页输入的 API Key 只写入当前 Web Host 进程环境变量 KSWORDBOX_VIRUSTOTAL_API_KEY；WebUI 不落盘，也不会修改 User/Machine 环境变量。需要重启后仍生效时，请在启动 Web Host 之前设置 User/Machine 环境变量。" data-en="Keys entered here are written only to the current Web Host process environment variable KSWORDBOX_VIRUSTOTAL_API_KEY (current process environment variable); the WebUI never persists them to disk and never modifies User/Machine environment variables. For restart-stable use, set a User/Machine environment variable before starting the Web Host.">在本页输入的 API Key 只写入当前 Web Host 进程环境变量 KSWORDBOX_VIRUSTOTAL_API_KEY；WebUI 不落盘，也不会修改 User/Machine 环境变量。需要重启后仍生效时，请在启动 Web Host 之前设置 User/Machine 环境变量。</p>
              </div>
              <div class="metric">
                <strong data-zh="动态监控页展示策略" data-en="Live monitor display policy">动态监控页展示策略</strong>
                <p class="muted" data-copy="VT 静默状态：未配置、未收录、限速、鉴权失败、超时、查询失败、缺少/无效 SHA-256；仅 /jobs/{jobId}/live-events 与 API 展示，不写 job/behavior log，不阻断分析 / display-only quiet states; no job/behavior logs." data-zh="上传 EXE 后会进入 /jobs/{jobId}/live-events；VirusTotal 的静默状态包括未配置、未收录、限速、鉴权失败、超时、查询失败、缺少/无效 SHA-256。该页只展示状态，不阻断分析、不写任务/行为日志。" data-en="After EXE upload, the UI enters /jobs/{jobId}/live-events; VirusTotal quiet states include not configured, not found, rate limited, authentication failed, timeout, lookup failed, and missing/invalid SHA-256. The page displays status only, without blocking analysis or writing job/behavior logs.">上传 EXE 后会进入 /jobs/{jobId}/live-events；VirusTotal 的静默状态包括未配置、未收录、限速、鉴权失败、超时、查询失败、缺少/无效 SHA-256。该页只展示状态，不阻断分析、不写任务/行为日志。</p>
              </div>
              <div class="metric">
                <strong data-zh="状态" data-en="Status">状态</strong>
                <span id="vtConfigured" class="pill" data-copy="{{Attr(virusTotal.Configured ? "已配置 / Configured" : "未配置 / Not configured")}}" data-zh="{{Attr(virusTotal.Configured ? "已配置" : "未配置")}}" data-en="{{Attr(virusTotal.Configured ? "Configured" : "Not configured")}}">{{Html(virusTotal.Configured ? "已配置" : "未配置")}}</span>
              </div>
              <div class="metric">
                <strong data-zh="来源" data-en="Source">来源</strong>
                <code data-copy="{{Attr(virusTotal.Source)}}">{{Html(virusTotal.Source)}}</code>
              </div>
              <div class="metric">
                <strong data-zh="掩码" data-en="Mask">掩码</strong>
                <code data-copy="{{Attr(virusTotal.ApiKeyMask ?? string.Empty)}}">{{Html(virusTotal.ApiKeyMask ?? "-")}}</code>
              </div>
              <div class="metric">
                <strong data-zh="API Key 持久化" data-en="API key persistence">API Key 持久化</strong>
                <code data-copy="仅当前 Web Host 进程；WebUI 不落盘；不修改 User/Machine 环境变量 / process-only current Web Host; no disk persistence">仅当前进程 / WebUI 不落盘</code>
              </div>
              <div class="metric">
                <strong data-zh="策略摘要" data-en="Policy summary">策略摘要</strong>
                <p class="muted" data-copy="{{Attr(virusTotal.ZhPolicySummary)}}">{{Html(virusTotal.ZhPolicySummary)}}</p>
                <p class="muted" data-copy="{{Attr(virusTotal.ZhProcessOnlySummary)}}">{{Html(virusTotal.ZhProcessOnlySummary)}}</p>
                <code data-copy="{{Attr(virusTotal.LookupMode)}}; {{Attr(virusTotal.NoSampleUploadGuarantee)}}; {{Attr(virusTotal.ApiKeyPersistenceScope)}}; {{Attr(virusTotal.PersistencePolicy)}}; {{Attr(virusTotal.QuietFailurePolicy)}}">{{Html(virusTotal.LookupMode)}} · {{Html(virusTotal.NoSampleUploadGuarantee)}} · {{Html(virusTotal.ApiKeyPersistenceScope)}} · {{Html(virusTotal.QuietFailurePolicy)}}</code>
              </div>

              <div class="metric">
                <strong data-zh="官方摘要字段" data-en="Official summary fields">官方摘要字段</strong>
                <p class="muted" data-copy="VT 官方摘要字段 / official fields：引擎统计(engineCounts)、最后分析时间(lastAnalysisDateUtc)、信誉/社区分数、officialFileObject、officialSummary/zhOfficialSummary、permalink/detectionPermalink/API self link；这些是 hash 报告元数据，不是样本行为 / hash-report metadata, not behavior." data-zh="结果 API 会返回官方引擎统计、最后分析时间、信誉/社区分数、officialFileObject、officialSummary/zhOfficialSummary 和 VirusTotal 链接；这些都是 hash 报告元数据，不是样本行为。" data-en="The result API returns official engine counts, last analysis time, reputation/community score, officialFileObject, officialSummary/zhOfficialSummary, and VirusTotal links; these are hash-report metadata, not sample behavior.">结果 API 会返回官方引擎统计、最后分析时间、信誉/社区分数、officialFileObject、officialSummary/zhOfficialSummary 和 VirusTotal 链接；这些都是 hash 报告元数据，不是样本行为。</p>
              </div>

              <label for="apiKey" data-zh="VirusTotal API Key（仅写入当前进程）" data-en="VirusTotal API key (write to current process only)">VirusTotal API Key（仅写入当前进程）</label>
              <input id="apiKey" type="password" autocomplete="off" placeholder="x-apikey" data-copy-label="VirusTotal API key input">
              <div class="row">
                <button type="button" onclick="saveKey(false)" data-zh="写入当前 Web Host 进程" data-en="Set process environment (current Web Host)">写入当前 Web Host 进程</button>
                <button class="secondary" type="button" onclick="saveKey(true)" data-zh="清除当前进程 Key" data-en="Clear process key">清除当前进程 Key</button>
              </div>
              <p id="status" class="muted" data-copy=""></p>
            </section>
            <section id="vmSettingsSection" data-copy="本机 WebUI VM 预设：只保存到当前浏览器 localStorage；作为上传页每任务覆盖值；不改 config/Core/Driver/Guest / local WebUI VM preset, browser-local only">
              <h2 data-zh="WebUI 虚拟机预设" data-en="WebUI VM preset">WebUI 虚拟机预设</h2>
              <p class="muted" data-zh="这些值保存在当前浏览器 localStorage，只作为上传页的每任务覆盖值；不会改配置（config）、Core、Driver 或 Guest 业务。产物/下载是否真正就绪，以动态监控页的 Artifacts 卡片和最终报告为准。" data-en="These values are saved in this browser's localStorage and only become per-job overrides on the upload page; they do not modify config, Core, Driver, or Guest behavior. Artifact/download readiness is confirmed on the dynamic monitor Artifacts cards and in the final report.">这些值保存在当前浏览器 localStorage，只作为上传页的每任务覆盖值；不会改配置（config）、Core、Driver 或 Guest 业务。产物/下载是否真正就绪，以动态监控页的 Artifacts 卡片和最终报告为准。</p>
              <div id="vmPresetSummary" class="summary" data-copy="" data-copy-label="VM preset summary"></div>
              <div class="grid">
                <div id="vmPresetCoreCard" class="card" data-copy="VM 与时长预设加载中 / VM and duration preset loading">
                  <h3 data-zh="VM 与时长" data-en="VM and duration">VM 与时长</h3>
                  <button id="copyVmPresetCoreCard" class="copy-btn" type="button" data-copy="VM 与时长预设加载中 / VM and duration preset loading" data-copy-label="VM and duration preset card" data-zh="复制本卡摘要" data-en="Copy card summary">复制本卡摘要</button>
                  <label for="settingsGoldenVmName" data-zh="VM 名称" data-en="VM name">VM 名称</label>
                  <input id="settingsGoldenVmName" placeholder="KSwordSandbox-Win10-Golden" data-copy-label="VM name preset">
                  <label for="settingsGoldenSnapshotName" data-zh="检查点" data-en="Checkpoint">检查点</label>
                  <input id="settingsGoldenSnapshotName" placeholder="Clean" data-copy-label="checkpoint preset">
                  <label for="settingsDurationSeconds" data-zh="分析时长（秒）" data-en="Analysis duration, seconds">分析时长（秒）</label>
                  <input id="settingsDurationSeconds" type="number" min="1" max="900" value="120" data-copy-label="analysis duration preset">
                  <p id="settingsDurationHint" class="field-hint" data-copy="" data-copy-label="duration preset hint">-</p>
                </div>
                <div id="vmPresetGuestCard" class="card" data-copy="Guest 用户预设加载中；密码仅从本机密钥环境变量读取 / Guest preset loading; password is read from local secret env only">
                  <h3 data-zh="Guest 用户提示" data-en="Guest user hint">Guest 用户提示</h3>
                  <button id="copyVmPresetGuestCard" class="copy-btn" type="button" data-copy="Guest 用户预设加载中；密码仅从本机密钥环境变量读取 / Guest preset loading; password is read from local secret env only" data-copy-label="guest preset card" data-zh="复制本卡摘要" data-en="Copy card summary">复制本卡摘要</button>
                  <label for="settingsGuestUserName" data-zh="Guest 用户" data-en="Guest user">Guest 用户</label>
                  <input id="settingsGuestUserName" placeholder="SandboxUser" data-copy-label="guest user preset">
                  <p id="settingsGuestHint" class="field-hint" data-copy="" data-copy-label="guest credential hint">-</p>
                  <label for="settingsGuestWorkingDirectory" data-zh="Guest 工作目录" data-en="Guest working folder">Guest 工作目录</label>
                  <input id="settingsGuestWorkingDirectory" placeholder="C:\KSwordSandbox" data-copy-label="guest working folder preset">
                  <label for="settingsGuestPayloadRoot" data-zh="Guest 工具目录（主机）" data-en="Guest tool folder (host)">Guest 工具目录（主机）</label>
                  <input id="settingsGuestPayloadRoot" placeholder="D:\Temp\KSwordSandbox\payload\guest-tools" data-copy-label="guest payload root preset">
                </div>
                <div id="vmPresetArtifactCard" class="card" data-copy="R0 与产物采集预设加载中；实际产物就绪以动态监控页 Artifacts 卡片和最终报告为准 / R0 and artifact preset loading">
                  <h3 data-zh="R0 与产物采集" data-en="R0 and artifacts">R0 与产物采集</h3>
                  <button id="copyVmPresetArtifactCard" class="copy-btn" type="button" data-copy="R0 与产物采集预设加载中；实际产物就绪以动态监控页 Artifacts 卡片和最终报告为准 / R0 and artifact preset loading" data-copy-label="R0 artifact preset card" data-zh="复制本卡摘要" data-en="Copy card summary">复制本卡摘要</button>
                  <div class="toggle-card readonly-toggle">
                    <label for="settingsR0Enabled"><input id="settingsR0Enabled" type="checkbox" disabled> <span data-zh="R0 总开关来自 config" data-en="R0 master switch comes from config">R0 总开关来自 config</span></label>
                    <p id="settingsR0Hint" class="field-hint" data-copy="" data-copy-label="R0 config hint">-</p>
                  </div>
                  <div class="toggle-card">
                    <label for="settingsUseMockCollector"><input id="settingsUseMockCollector" type="checkbox"> <span data-zh="使用 Mock 采集器（collector）" data-en="Use mock collector">使用 Mock 采集器（collector）</span></label>
                  </div>
                  <div class="toggle-card">
                    <label for="settingsCollectDroppedFiles"><input id="settingsCollectDroppedFiles" type="checkbox"> <span data-zh="采集落地文件" data-en="Collect dropped files">采集落地文件</span></label>
                  </div>
                  <div class="toggle-card">
                    <label for="settingsCaptureScreenshots"><input id="settingsCaptureScreenshots" type="checkbox"> <span data-zh="采集截图" data-en="Capture screenshots">采集截图</span></label>
                  </div>
                  <div class="toggle-card">
                    <label for="settingsCaptureMemoryDumps"><input id="settingsCaptureMemoryDumps" type="checkbox"> <span data-zh="采集内存转储" data-en="Capture memory dumps">采集内存转储</span></label>
                  </div>
                  <div class="toggle-card">
                    <label for="settingsCapturePacketCapture"><input id="settingsCapturePacketCapture" type="checkbox"> <span data-zh="采集 PCAP 抓包" data-en="Capture PCAP">采集 PCAP 抓包</span></label>
                  </div>
                </div>
              </div>
              <div class="row">
                <button type="button" onclick="saveVmPreset()" data-zh="保存 VM WebUI 预设" data-en="Save VM WebUI preset">保存 VM WebUI 预设</button>
                <button class="secondary" type="button" onclick="clearVmPreset()" data-zh="清除 VM WebUI 预设" data-en="Clear VM WebUI preset">清除 VM WebUI 预设</button>
                <a class="button secondary" href="/#workspace-plan" data-zh="返回上传页使用预设" data-en="Back to upload page with preset">返回上传页使用预设</a>
              </div>
              <p id="vmStatus" class="muted" data-copy=""></p>
            </section>
          </main>
          <div id="copyToast" class="toast" role="status" aria-live="polite"></div>
          <script>
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';
            let copyToastTimer = null;
            let settingsConfigDefaults = null;
            const vmPresetStorageKey = 'ksword-vm-overrides';
            function t(zh,en){ return currentLanguage === 'en' ? en : zh; }
            function applyLanguage(){
              document.documentElement.lang = currentLanguage === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(el => { if(el.id !== 'status'){ el.textContent = t(el.getAttribute('data-zh'), el.getAttribute('data-en')); } });
              renderVmSettingsHints();
              renderVmPresetSummary();
            }
            function toggleLanguage(){ currentLanguage = currentLanguage === 'en' ? 'zh' : 'en'; localStorage.setItem('ksword-lang', currentLanguage); applyLanguage(); }
            async function saveKey(clear){
              const apiKey = document.getElementById('apiKey').value;
              if(!clear && !apiKey.trim()){
                setStatus(t('请输入 API Key；该操作只写入当前 Web Host 进程。若要移除当前进程 Key，请点击“清除当前进程 Key”。', 'Enter an API key; this writes only to the current Web Host process. To remove the current process key, click Clear process key.'), true);
                return;
              }
              try {
                const response = await fetch('/api/settings/virustotal', {
                  method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({ apiKey, clear })
                });
                const payload = await readSettingsPayload(response);
                if(!response.ok){ throw new Error(formatSettingsError(t('更新 VirusTotal 设置', 'Update VirusTotal settings'), response, payload)); }
                document.getElementById('apiKey').value = '';
                const source = payload.source || 'not-configured';
                const message = clear
                  ? (payload.configured
                    ? t(`当前进程 Key 已清除；仍从 ${source} 读取。WebUI 不会修改 User/Machine 环境变量。`, `Current process key cleared; VirusTotal is still configured from ${source}. The WebUI does not modify User/Machine environment variables.`)
                    : t('当前进程 Key 已清除；VirusTotal 未配置。', 'Current process key cleared; VirusTotal is not configured.'))
                  : t(`API Key 已写入当前 Web Host 进程环境（${source}）；不会落盘，不会修改 User/Machine 环境变量，重启后需要重新输入或预先设置环境变量。`, `API key was written to the current Web Host process environment (${source}); it is not persisted to disk, does not modify User/Machine environment variables, and must be re-entered after restart unless an environment variable is set before launch.`);
                setStatus(message, false);
                setTimeout(() => location.reload(), 800);
              } catch(error) {
                setStatus(error.message, true);
              }
            }
            function setStatus(text, error){ const el = document.getElementById('status'); el.className = error ? 'error' : 'ok'; el.textContent = text; el.setAttribute('data-copy', text); }
            function setVmStatus(text, error){ const el = document.getElementById('vmStatus'); if(!el){ return; } el.className = error ? 'error' : 'ok'; el.textContent = text; el.setAttribute('data-copy', text); }
            async function loadVmDefaults(){
              try {
                const response = await fetch('/api/config');
                const config = await readSettingsPayload(response);
                if(!response.ok){ throw new Error(formatSettingsError(t('读取 WebUI 配置', 'Load WebUI config'), response, config)); }
                settingsConfigDefaults = config;
                const maxDuration = normalizePositiveInt(config.analysis?.maxDurationSeconds, 900);
                const defaultDuration = clampDuration(config.analysis?.defaultDurationSeconds, maxDuration);
                document.getElementById('settingsDurationSeconds').max = String(maxDuration);
                document.getElementById('settingsDurationSeconds').value = String(defaultDuration);
                document.getElementById('settingsGoldenVmName').value = config.hyperV?.goldenVmName || '';
                document.getElementById('settingsGoldenSnapshotName').value = config.hyperV?.goldenSnapshotName || '';
                document.getElementById('settingsGuestUserName').value = config.guest?.userName || '';
                document.getElementById('settingsGuestWorkingDirectory').value = config.guest?.workingDirectory || '';
                document.getElementById('settingsGuestPayloadRoot').value = config.paths?.guestPayloadRoot || '';
                document.getElementById('settingsR0Enabled').checked = Boolean(config.driver?.enabled);
                document.getElementById('settingsUseMockCollector').checked = Boolean(config.driver?.useMockCollector);
                document.getElementById('settingsCollectDroppedFiles').checked = Boolean(config.artifactCollection?.collectDroppedFiles);
                document.getElementById('settingsCaptureScreenshots').checked = Boolean(config.artifactCollection?.captureScreenshots);
                document.getElementById('settingsCaptureMemoryDumps').checked = Boolean(config.artifactCollection?.captureMemoryDumps);
                document.getElementById('settingsCapturePacketCapture').checked = Boolean(config.artifactCollection?.capturePacketCapture);
                applyVmPreset();
                renderVmSettingsHints();
                renderVmPresetSummary();
              } catch(error) {
                setVmStatus(error.message, true);
                renderVmSettingsHints();
                renderVmPresetSummary();
              }
            }
            async function readSettingsPayload(response){
              const text = await response.text();
              if(!text){ return {}; }
              try { return JSON.parse(text); } catch { return { raw: text }; }
            }
            function formatSettingsError(action, response, payload){
              const statusText = response.statusText ? ` ${response.statusText}` : '';
              const detail = extractSettingsErrorMessage(payload) || t('服务器未返回错误详情。', 'No error detail was returned by the server.');
              const traceId = payload && (payload.traceId || payload.requestId);
              const traceText = traceId ? (currentLanguage === 'en' ? `, trace ${traceId}` : `，跟踪 ID ${traceId}`) : '';
              return `${action} ${t('失败', 'failed')} (HTTP ${response.status}${statusText}${traceText}): ${detail} ${t('下一步：', 'Next step: ')}${settingsNextStep(action, response, payload)}`;
            }
            function extractSettingsErrorMessage(payload){
              if(!payload){ return ''; }
              if(typeof payload === 'string'){ return payload; }
              if(payload.error){
                if(typeof payload.error === 'string'){ return payload.error; }
                if(payload.error.message){ return payload.error.message; }
              }
              if(payload.title || payload.detail){ return [payload.title, payload.detail].filter(Boolean).join(': '); }
              if(payload.message){ return payload.message; }
              if(payload.errors){
                return Object.entries(payload.errors)
                  .map(([field, values]) => `${field}: ${Array.isArray(values) ? values.join('; ') : values}`)
                  .join(' | ');
              }
              return payload.raw || '';
            }
            function settingsNextStep(action, response, payload){
              const actionText = String(action || '');
              if(response.status === 401 || response.status === 403){
                return t('检查启动 Web Host 的本机权限后重试。', 'Check the local permissions of the Web Host process, then retry.');
              }
              if(/VirusTotal/i.test(actionText)){
                return t('确认 API Key 未粘贴为空；本页只写入当前 Web Host 进程。若要移除当前进程 Key，请点击“清除当前进程 Key”。', 'Confirm the API key was not pasted as empty; this page writes only to the current Web Host process. To remove the process key, click Clear process key.');
              }
              if(/配置|config/i.test(actionText)){
                return t('确认 Web Host 仍在运行并刷新页面；上传页仍会使用已保存的本地预设。', 'Confirm the Web Host is still running and refresh the page; the upload page can still use saved local presets.');
              }
              return t('保留本条错误文本并重试；如果重复失败，请回到主界面检查任务状态。', 'Keep this error text and retry; if it repeats, return to the dashboard and check job status.');
            }
            function normalizePositiveInt(value, fallback){
              const parsed = Number.parseInt(String(value ?? ''), 10);
              return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
            }
            function clampDuration(value, maxDuration){
              const max = normalizePositiveInt(maxDuration, 900);
              const parsed = normalizePositiveInt(value, normalizePositiveInt(settingsConfigDefaults?.analysis?.defaultDurationSeconds, 120));
              return Math.max(1, Math.min(max, parsed));
            }
            function getPresetDuration(){
              const input = document.getElementById('settingsDurationSeconds');
              const max = normalizePositiveInt(input?.max || settingsConfigDefaults?.analysis?.maxDurationSeconds, 900);
              const value = clampDuration(input?.value, max);
              if(input){ input.value = String(value); }
              return value;
            }
            function readVmPreset(){
              try {
                const raw = localStorage.getItem(vmPresetStorageKey);
                return raw ? JSON.parse(raw) : null;
              } catch {
                return null;
              }
            }
            function applyVmPreset(){
              const preset = readVmPreset();
              if(!preset){ return; }
              const setValue = (id, value) => { if(value !== undefined && value !== null){ document.getElementById(id).value = String(value); } };
              const setChecked = (id, value) => { if(typeof value === 'boolean'){ document.getElementById(id).checked = value; } };
              setValue('settingsDurationSeconds', preset.durationSeconds);
              setValue('settingsGoldenVmName', preset.goldenVmName);
              setValue('settingsGoldenSnapshotName', preset.goldenSnapshotName);
              setValue('settingsGuestUserName', preset.guestUserName);
              setValue('settingsGuestWorkingDirectory', preset.guestWorkingDirectory);
              setValue('settingsGuestPayloadRoot', preset.guestPayloadRoot);
              setChecked('settingsUseMockCollector', preset.useMockCollector);
              setChecked('settingsCollectDroppedFiles', preset.collectDroppedFiles);
              setChecked('settingsCaptureScreenshots', preset.captureScreenshots);
              setChecked('settingsCaptureMemoryDumps', preset.captureMemoryDumps);
              setChecked('settingsCapturePacketCapture', preset.capturePacketCapture);
              getPresetDuration();
            }
            function captureVmPreset(){
              const clean = id => {
                const value = document.getElementById(id).value.trim();
                return value ? value : undefined;
              };
              return {
                durationSeconds: getPresetDuration(),
                goldenVmName: clean('settingsGoldenVmName'),
                goldenSnapshotName: clean('settingsGoldenSnapshotName'),
                guestUserName: clean('settingsGuestUserName'),
                guestWorkingDirectory: clean('settingsGuestWorkingDirectory'),
                guestPayloadRoot: clean('settingsGuestPayloadRoot'),
                useMockCollector: document.getElementById('settingsUseMockCollector').checked,
                collectDroppedFiles: document.getElementById('settingsCollectDroppedFiles').checked,
                captureScreenshots: document.getElementById('settingsCaptureScreenshots').checked,
                captureMemoryDumps: document.getElementById('settingsCaptureMemoryDumps').checked,
                capturePacketCapture: document.getElementById('settingsCapturePacketCapture').checked
              };
            }
            function saveVmPreset(){
              const preset = captureVmPreset();
              localStorage.setItem(vmPresetStorageKey, JSON.stringify(preset));
              renderVmPresetSummary();
              setVmStatus(t('VM WebUI 预设已保存；返回上传页后会自动套用。', 'VM WebUI preset saved; the upload page will apply it automatically.'), false);
            }
            async function clearVmPreset(){
              localStorage.removeItem(vmPresetStorageKey);
              await loadVmDefaults();
              setVmStatus(t('VM WebUI 预设已清除；已恢复 config 默认值。', 'VM WebUI preset cleared; config defaults restored.'), false);
            }
            function renderVmSettingsHints(){
              const secretName = settingsConfigDefaults?.guest?.passwordSecretName || 'KSWORDBOX_GUEST_PASSWORD';
              const maxDuration = normalizePositiveInt(settingsConfigDefaults?.analysis?.maxDurationSeconds, 900);
              setTextAndCopy('settingsDurationHint', t(`后端会限制在 1-${maxDuration} 秒。`, `The backend clamps this to 1-${maxDuration} seconds.`));
              setTextAndCopy('settingsGuestHint', t(`Guest 密码只从本机密钥环境变量 ${secretName} 读取；WebUI 不输入也不保存密码。`, `Guest password is read only from local secret environment variable ${secretName}; the WebUI does not ask for or store it.`));
              const r0Enabled = Boolean(settingsConfigDefaults?.driver?.enabled);
              setTextAndCopy('settingsR0Hint', r0Enabled
                ? t('R0 已由配置（config）启用；这里只保存 Mock 采集器（collector）的每任务覆盖预设。', 'R0 is enabled by config; this only saves the per-job mock collector override preset.')
                : t('R0 在配置（config）中关闭；Core 仍以 config 总开关为准。', 'R0 is disabled in config; Core still follows the config master switch.'));
            }
            function renderVmPresetSummary(){
              const target = document.getElementById('vmPresetSummary');
              if(!target){ return; }
              const textValue = (id, fallback) => (document.getElementById(id)?.value || '').trim() || fallback || t('默认', 'default');
              const r0Enabled = document.getElementById('settingsR0Enabled')?.checked;
              const mock = document.getElementById('settingsUseMockCollector')?.checked;
              const artifacts = [
                [document.getElementById('settingsCollectDroppedFiles')?.checked, t('落地文件', 'dropped files')],
                [document.getElementById('settingsCaptureScreenshots')?.checked, t('截图', 'screenshots')],
                [document.getElementById('settingsCaptureMemoryDumps')?.checked, t('内存转储', 'memory dumps')],
                [document.getElementById('settingsCapturePacketCapture')?.checked, t('PCAP', 'PCAP')]
              ].filter(([enabled]) => enabled).map(([, label]) => label).join(', ') || t('未启用敏感产物采集', 'no sensitive artifact collection enabled');
              const parts = [
                `${t('VM', 'VM')}: ${textValue('settingsGoldenVmName', settingsConfigDefaults?.hyperV?.goldenVmName)}`,
                `${t('检查点', 'Checkpoint')}: ${textValue('settingsGoldenSnapshotName', settingsConfigDefaults?.hyperV?.goldenSnapshotName)}`,
                `${t('时长', 'Duration')}: ${getPresetDuration()}s`,
                `${t('Guest', 'Guest')}: ${textValue('settingsGuestUserName', settingsConfigDefaults?.guest?.userName)}`,
                r0Enabled ? (mock ? t('R0：Mock 采集器（collector）', 'R0: mock collector') : t('R0：真实采集器（collector）', 'R0: real collector')) : t('R0：config 已关闭', 'R0: disabled by config'),
                `${t('产物', 'Artifacts')}: ${artifacts}`
              ];
              target.setAttribute('data-copy', parts.join(' | '));
              target.innerHTML = parts.map(part => `<span class="pill" data-copy="${escapeAttribute(part)}" data-copy-label="VM preset summary item">${escapeHtml(part)}</span>`).join('');
              refreshSettingsCopyAffordances(parts);
            }
            function refreshSettingsCopyAffordances(summaryParts){
              const core = [
                `${t('VM', 'VM')}: ${(document.getElementById('settingsGoldenVmName')?.value || settingsConfigDefaults?.hyperV?.goldenVmName || t('默认', 'default')).trim()}`,
                `${t('检查点', 'Checkpoint')}: ${(document.getElementById('settingsGoldenSnapshotName')?.value || settingsConfigDefaults?.hyperV?.goldenSnapshotName || t('默认', 'default')).trim()}`,
                `${t('时长', 'Duration')}: ${getPresetDuration()}s`
              ].join(' | ');
              const guest = [
                `${t('Guest 用户', 'Guest user')}: ${(document.getElementById('settingsGuestUserName')?.value || settingsConfigDefaults?.guest?.userName || t('默认', 'default')).trim()}`,
                `${t('Guest 工作目录', 'Guest working folder')}: ${(document.getElementById('settingsGuestWorkingDirectory')?.value || settingsConfigDefaults?.guest?.workingDirectory || t('默认', 'default')).trim()}`,
                `${t('Guest 工具目录', 'Guest tool folder')}: ${(document.getElementById('settingsGuestPayloadRoot')?.value || settingsConfigDefaults?.paths?.guestPayloadRoot || t('默认', 'default')).trim()}`,
                document.getElementById('settingsGuestHint')?.textContent || ''
              ].filter(Boolean).join(' | ');
              const artifact = [
                document.getElementById('settingsR0Hint')?.textContent || '',
                `${t('Mock 采集器', 'Mock collector')}: ${document.getElementById('settingsUseMockCollector')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`,
                `${t('落地文件', 'Dropped files')}: ${document.getElementById('settingsCollectDroppedFiles')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`,
                `${t('截图', 'Screenshots')}: ${document.getElementById('settingsCaptureScreenshots')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`,
                `${t('内存转储', 'Memory dumps')}: ${document.getElementById('settingsCaptureMemoryDumps')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`,
                `${t('PCAP', 'PCAP')}: ${document.getElementById('settingsCapturePacketCapture')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`
              ].filter(Boolean).join(' | ');
              const whole = (summaryParts && summaryParts.length ? summaryParts.join(' | ') : [core, guest, artifact].join(' | '));
              setCopyTarget('vmSettingsSection', whole);
              setCopyTarget('vmPresetCoreCard', core);
              setCopyTarget('copyVmPresetCoreCard', core);
              setCopyTarget('vmPresetGuestCard', guest);
              setCopyTarget('copyVmPresetGuestCard', guest);
              setCopyTarget('vmPresetArtifactCard', artifact);
              setCopyTarget('copyVmPresetArtifactCard', artifact);
              setCopyTarget('settingsUseMockCollector', `${t('Mock 采集器', 'Mock collector')}: ${document.getElementById('settingsUseMockCollector')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`);
              setCopyTarget('settingsCollectDroppedFiles', `${t('落地文件', 'Dropped files')}: ${document.getElementById('settingsCollectDroppedFiles')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`);
              setCopyTarget('settingsCaptureScreenshots', `${t('截图', 'Screenshots')}: ${document.getElementById('settingsCaptureScreenshots')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`);
              setCopyTarget('settingsCaptureMemoryDumps', `${t('内存转储', 'Memory dumps')}: ${document.getElementById('settingsCaptureMemoryDumps')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`);
              setCopyTarget('settingsCapturePacketCapture', `${t('PCAP', 'PCAP')}: ${document.getElementById('settingsCapturePacketCapture')?.checked ? t('启用', 'enabled') : t('关闭', 'disabled')}`);
            }
            function setCopyTarget(id, text){ const el = document.getElementById(id); if(el){ el.setAttribute('data-copy', text || ''); } }
            function setTextAndCopy(id, text){ const el = document.getElementById(id); if(!el){ return; } el.textContent = text; el.setAttribute('data-copy', text); }
            function escapeHtml(value){ return String(value).replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' }[char])); }
            function escapeAttribute(value){ return escapeHtml(value).replace(/`/g, '&#096;'); }
            function fallbackCopyText(text){
              const area = document.createElement('textarea');
              area.value = text;
              area.setAttribute('readonly', 'readonly');
              area.style.position = 'fixed';
              area.style.left = '-9999px';
              document.body.appendChild(area);
              area.select();
              document.execCommand('copy');
              document.body.removeChild(area);
            }
            function showToast(message){
              const toast = document.getElementById('copyToast');
              if(!toast){ return; }
              toast.textContent = message;
              toast.classList.add('visible');
              if(copyToastTimer){ clearTimeout(copyToastTimer); }
              copyToastTimer = setTimeout(() => toast.classList.remove('visible'), 1400);
            }
            async function copyText(value){
              const text = value == null ? '' : String(value);
              if(!text.trim()){
                showToast(t('没有可复制的内容。', 'Nothing to copy.'));
                return;
              }

              try {
                if(navigator.clipboard && navigator.clipboard.writeText){
                  await navigator.clipboard.writeText(text);
                } else {
                  fallbackCopyText(text);
                }
                showToast(t('已复制。', 'Copied.'));
              } catch {
                fallbackCopyText(text);
                showToast(t('已复制。', 'Copied.'));
              }
            }
            function setupVmPresetListeners(){
              [
                'settingsGoldenVmName',
                'settingsGoldenSnapshotName',
                'settingsDurationSeconds',
                'settingsGuestUserName',
                'settingsGuestWorkingDirectory',
                'settingsGuestPayloadRoot',
                'settingsUseMockCollector',
                'settingsCollectDroppedFiles',
                'settingsCaptureScreenshots',
                'settingsCaptureMemoryDumps',
                'settingsCapturePacketCapture'
              ].forEach(id => {
                const element = document.getElementById(id);
                if(!element){ return; }
                element.addEventListener('input', renderVmPresetSummary);
                element.addEventListener('change', renderVmPresetSummary);
              });
            }
            document.addEventListener('click', event => {
              const button = event.target.closest ? event.target.closest('button.copy-btn[data-copy]') : null;
              if(!button){ return; }
              event.preventDefault();
              event.stopPropagation();
              copyText(button.getAttribute('data-copy') || '');
            });
            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest('[data-copy], code, pre, input, p, li, h1, h2, h3, span, label, button, a, td, th, section, article, .metric, .card, .toggle-card') : null;
              if(!target){ return; }
              const value = target.getAttribute('data-copy') || target.value || target.textContent || '';
              if(!value.trim()){ return; }
              event.preventDefault();
              copyText(value);
            });
            setupVmPresetListeners();
            applyLanguage();
            loadVmDefaults();
          </script>
        </body>
        </html>
        """;
    }

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private static string Attr(string? value) => Html(value).Replace("\"", "&quot;", StringComparison.Ordinal);
}
