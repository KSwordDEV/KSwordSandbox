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
          <title>KSword Sandbox Settings</title>
          <style>
            :root { --blue:#43A0FF; --ink:#0f172a; --muted:#64748b; --line:#dbeafe; color-scheme: light; }
            * { box-sizing: border-box; }
            body { background:linear-gradient(180deg,#f4f9ff,#f8fafc); color:var(--ink); font-family:"Microsoft YaHei UI",Segoe UI,Arial,sans-serif; margin:0; }
            header { background:radial-gradient(circle at 85% 12%,rgba(67,160,255,.55),transparent 30%),linear-gradient(135deg,#08111f,#0f5f9f); color:white; padding:26px 36px; }
            main { max-width:960px; margin:24px auto 52px; padding:0 22px; }
            section { background:rgba(255,255,255,.96); border:1px solid var(--line); border-radius:18px; box-shadow:0 16px 42px rgba(15,23,42,.08); margin-bottom:16px; padding:20px; }
            label { display:block; font-weight:800; margin:14px 0 6px; }
            input { border:1px solid #c7dff7; border-radius:11px; font:inherit; padding:10px 12px; width:100%; }
            button,a.button { background:var(--blue); border:0; border-radius:11px; color:white; cursor:pointer; display:inline-block; font-weight:800; margin-top:12px; padding:10px 14px; text-decoration:none; }
            button.secondary,a.secondary { background:#334155; }
            .row { display:flex; flex-wrap:wrap; gap:10px; }
            .metric { background:#f8fbff; border:1px solid var(--line); border-radius:14px; margin-top:10px; padding:12px; }
            .metric strong { color:var(--muted); display:block; font-size:12px; margin-bottom:6px; }
            .pill { background:#e7f3ff; border:1px solid rgba(67,160,255,.45); border-radius:999px; color:#075985; display:inline-block; font-size:12px; font-weight:800; padding:4px 9px; }
            .ok { color:#047857; }
            .muted { color:var(--muted); }
            .error { color:#b91c1c; }
            code { background:#eef7ff; border-radius:7px; padding:2px 5px; word-break:break-all; }
            [data-copy], code { cursor:copy; }
          </style>
        </head>
        <body>
          <header>
            <div class="row" style="justify-content:space-between;align-items:flex-start">
              <div>
                <h1 data-zh="设置" data-en="Settings">设置</h1>
                <p data-zh="本页只保存本机运行配置；不会提交到仓库。" data-en="This page stores local runtime settings only; nothing is committed to the repository.">本页只保存本机运行配置；不会提交到仓库。</p>
              </div>
              <button class="secondary" type="button" onclick="toggleLanguage()" data-zh="English" data-en="中文">English</button>
            </div>
            <p class="row"><a class="button secondary" href="/" data-zh="返回主界面" data-en="Back to dashboard">返回主界面</a></p>
          </header>
          <main>
            <section>
              <h2 data-zh="VirusTotal 官方结果" data-en="VirusTotal official results">VirusTotal 官方结果</h2>
              <p class="muted" data-zh="当前只做 hash lookup，不上传样本。不配置或调用失败时，主流程继续运行且不写 noisy 日志。" data-en="Current integration performs hash lookup only and does not upload samples. If missing or failing, the main flow continues without noisy logs.">当前只做 hash lookup，不上传样本。不配置或调用失败时，主流程继续运行且不写 noisy 日志。</p>
              <div class="metric">
                <strong data-zh="状态" data-en="Status">状态</strong>
                <span id="vtConfigured" class="pill" data-copy="{{Attr(virusTotal.Configured ? "configured" : "not-configured")}}">{{Html(virusTotal.Configured ? "已配置 / Configured" : "未配置 / Not configured")}}</span>
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
                <strong data-zh="本机设置文件" data-en="Local settings file">本机设置文件</strong>
                <code data-copy="{{Attr(virusTotal.SettingsPath ?? string.Empty)}}">{{Html(virusTotal.SettingsPath ?? "-")}}</code>
              </div>

              <label for="apiKey" data-zh="VirusTotal API Key" data-en="VirusTotal API key">VirusTotal API Key</label>
              <input id="apiKey" type="password" autocomplete="off" placeholder="x-apikey">
              <div class="row">
                <button type="button" onclick="saveKey(false)" data-zh="保存 / 更新" data-en="Save / update">保存 / 更新</button>
                <button class="secondary" type="button" onclick="saveKey(true)" data-zh="清除本机保存的 Key" data-en="Clear saved key">清除本机保存的 Key</button>
              </div>
              <p id="status" class="muted" data-copy=""></p>
            </section>
          </main>
          <script>
            let currentLanguage = localStorage.getItem('ksword-lang') === 'en' ? 'en' : 'zh';
            function t(zh,en){ return currentLanguage === 'en' ? en : zh; }
            function applyLanguage(){
              document.documentElement.lang = currentLanguage === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(el => { if(el.id !== 'status'){ el.textContent = t(el.getAttribute('data-zh'), el.getAttribute('data-en')); } });
            }
            function toggleLanguage(){ currentLanguage = currentLanguage === 'en' ? 'zh' : 'en'; localStorage.setItem('ksword-lang', currentLanguage); applyLanguage(); }
            async function saveKey(clear){
              const apiKey = document.getElementById('apiKey').value;
              try {
                const response = await fetch('/api/settings/virustotal', {
                  method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({ apiKey, clear })
                });
                const payload = await response.json();
                if(!response.ok){ throw new Error(payload.error || response.status); }
                document.getElementById('apiKey').value = '';
                setStatus(payload.configured ? t('已保存 VirusTotal API Key。', 'VirusTotal API key saved.') : t('本机保存的 VirusTotal API Key 已清除或未配置。', 'Saved VirusTotal API key cleared or not configured.'), false);
                setTimeout(() => location.reload(), 800);
              } catch(error) {
                setStatus(t('保存失败：', 'Save failed: ') + error.message, true);
              }
            }
            function setStatus(text, error){ const el = document.getElementById('status'); el.className = error ? 'error' : 'ok'; el.textContent = text; el.setAttribute('data-copy', text); }
            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest('[data-copy], code, input, p, span') : null;
              if(!target){ return; }
              const value = target.getAttribute('data-copy') || target.value || target.textContent || '';
              if(!value.trim()){ return; }
              event.preventDefault();
              navigator.clipboard?.writeText(value).catch(()=>{});
            });
            applyLanguage();
          </script>
        </body>
        </html>
        """;
    }

    private static string Html(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private static string Attr(string? value) => Html(value).Replace("\"", "&quot;", StringComparison.Ordinal);
}
