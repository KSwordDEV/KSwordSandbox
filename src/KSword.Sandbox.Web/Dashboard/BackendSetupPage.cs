using System.Net;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// First-run and backend maintenance screen. The page is deliberately self-contained so it
/// can be hosted by a tiny launch process before the rest of the dashboard is configured.
/// </summary>
internal static class BackendSetupPage
{
    internal static string Render(SandboxConfig config, string? configPath, bool preferVmware = false)
    {
        ArgumentNullException.ThrowIfNull(config);

        var virtualization = config.Virtualization;
        var vmware = config.VMware;
        var guest = vmware.GuestRemoting;
        var path = string.IsNullOrWhiteSpace(configPath) ? "config/sandbox.local.json" : configPath;
        var selectedProvider = preferVmware ? VirtualizationProvider.VMware : virtualization.Provider;
        var vmxPath = vmware.VmxPath ?? string.Empty;
        var snapshot = vmware.SnapshotName ?? string.Empty;
        var vmrun = vmware.VmrunPath ?? "vmrun.exe";
        var address = guest.Address ?? string.Empty;
        var port = guest.Port == 0 ? 5986 : guest.Port;

        return $$"""
        <!doctype html>
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>后端设置 · KSword Sandbox</title>
          <style>
            :root { --page:#f7f8fa; --surface:#fff; --subtle:#f1f3f5; --ink:#151515; --muted:#6b7280; --line:#e5e7eb; --accent:#1f78ff; --accent-soft:#e5f0ff; --success:#16704a; --warn:#946200; --danger:#a32020; color-scheme:light; }
            * { box-sizing:border-box; }
            body { margin:0; color:var(--ink); background:var(--page); font-family:"Microsoft YaHei UI","Segoe UI",Arial,sans-serif; font-size:14px; line-height:1.55; }
            header { background:var(--surface); border-bottom:1px solid var(--line); padding:30px max(20px,calc((100% - 1080px)/2)); }
            main { max-width:1080px; margin:0 auto; padding:24px 20px 64px; }
            h1,h2,h3 { color:var(--ink); line-height:1.25; margin:0 0 8px; }
            h1 { font-size:clamp(25px,3vw,34px); font-weight:500; letter-spacing:-.02em; }
            h2 { font-size:20px; font-weight:550; }
            p { margin:8px 0; }
            .topline,.actions,.choice-row,.grid,.checks { display:flex; flex-wrap:wrap; gap:12px; }
            .topline { align-items:flex-start; justify-content:space-between; }
            .subtle { color:var(--muted); max-width:760px; }
            .lang { margin:0; white-space:nowrap; }
            .steps { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); list-style:none; margin:0 0 20px; padding:0; }
            .steps li { background:var(--surface); border:1px solid var(--line); border-right:0; color:var(--muted); font-weight:600; padding:12px; }
            .steps li:last-child { border-right:1px solid var(--line); }
            .steps li.active { border-top:3px solid var(--accent); color:var(--accent); padding-top:10px; }
            .num { border:1px solid currentColor; display:inline-block; margin-right:5px; min-width:22px; text-align:center; }
            section { background:var(--surface); border:1px solid var(--line); margin:0 0 18px; padding:20px; }
            .choice { background:var(--surface); border:1px solid var(--line); cursor:pointer; flex:1 1 180px; padding:13px; }
            .choice:hover { border-color:#b8d6ff; }
            .choice:has(input:checked) { background:var(--accent-soft); border:2px solid var(--accent); padding:12px; }
            .choice input { margin-right:7px; }
            .grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); }
            label { display:block; font-weight:600; margin:12px 0 6px; }
            input,select { background:var(--surface); border:1px solid #cbd5e1; color:var(--ink); font:inherit; padding:9px 10px; width:100%; }
            input:focus,select:focus,button:focus-visible,a:focus-visible { border-color:var(--accent); outline:2px solid #b8d6ff; outline-offset:1px; }
            .hint,.footer-note { color:var(--muted); font-size:12px; margin:4px 0 0; }
            .checks label { background:var(--subtle); border:1px solid var(--line); flex:1 1 200px; padding:11px; }
            .checks input { width:auto; margin-right:7px; }
            button,.button { align-items:center; background:var(--accent); border:1px solid var(--accent); color:#fff; cursor:pointer; display:inline-flex; font:inherit; font-weight:600; justify-content:center; line-height:1.25; padding:9px 14px; text-decoration:none; }
            button:hover,.button:hover { background:#155fc9; border-color:#155fc9; }
            button.secondary,.button.secondary { background:var(--surface); border-color:#cbd5e1; color:var(--ink); }
            button.secondary:hover,.button.secondary:hover { background:var(--subtle); border-color:#9ca3af; }
            button:disabled { cursor:wait; opacity:.6; }
            .status { background:var(--subtle); border-left:3px solid var(--line); min-height:24px; padding:10px 12px; white-space:pre-wrap; }
            .status.ok { border-color:var(--success); color:var(--success); }
            .status.warn { border-color:var(--warn); color:var(--warn); }
            .status.bad { border-color:var(--danger); color:var(--danger); }
            pre { background:var(--subtle); border:1px solid var(--line); font:12px Consolas,"JetBrains Mono",monospace; margin:10px 0 0; max-height:340px; overflow:auto; padding:11px; }
            .hidden { display:none !important; }
            @media(max-width:760px) { .topline { flex-direction:column; } .steps { grid-template-columns:1fr; } .steps li { border-bottom:0; border-right:1px solid var(--line); } .steps li:last-child { border-bottom:1px solid var(--line); } .grid { grid-template-columns:1fr; } main { padding-left:14px; padding-right:14px; } header { padding-left:14px; padding-right:14px; } }
          </style>
        </head>
        <body data-config-path="{{Attr(path)}}">
          <header>
            <div class="topline">
              <div>
                <h1 data-zh="KSword Sandbox · 后端设置" data-en="KSword Sandbox · Backend setup">KSword Sandbox · 后端设置</h1>
                <p class="subtle" data-zh="首次启动时完成主机与 Windows 10 VMware 虚拟机的连接。保存后即可进入样本选择；所有检查都先以只读方式运行。" data-en="Connect the host to a Windows 10 VMware guest during first launch. Save when ready, then continue to sample selection; checks are read-only until you save.">首次启动时完成主机与 Windows 10 VMware 虚拟机的连接。保存后即可进入样本选择；所有检查都先以只读方式运行。</p>
              </div>
              <button class="lang secondary" type="button" onclick="toggleLanguage()" data-zh="切换到 English" data-en="切换到中文">切换到 English</button>
            </div>
          </header>
          <main>
            <ol class="steps" aria-label="Setup steps">
              <li class="active"><span class="num">1</span><span data-zh="选择后端" data-en="Backend">选择后端</span></li>
              <li><span class="num">2</span><span data-zh="连接虚拟机" data-en="Connect VM">连接虚拟机</span></li>
              <li><span class="num">3</span><span data-zh="只读预检" data-en="Read-only check">只读预检</span></li>
              <li><span class="num">4</span><span data-zh="保存配置" data-en="Save config">保存配置</span></li>
              <li><span class="num">5</span><span data-zh="选择样本" data-en="Choose sample">选择样本</span></li>
            </ol>

            <section>
              <h2 data-zh="1. 选择虚拟化后端" data-en="1. Choose a virtualization backend">1. 选择虚拟化后端</h2>
              <div class="choice-row">
                <label class="choice"><input type="radio" name="provider" value="VMware"{{(selectedProvider == VirtualizationProvider.VMware ? " checked" : "")}}>VMware Workstation Pro<div class="hint" data-zh="推荐：自动开机、传样本、采集、还原快照并关机。" data-en="Recommended: boot, transfer, collect, restore snapshot, and shut down automatically.">推荐：自动开机、传样本、采集、还原快照并关机。</div></label>
                <label class="choice"><input type="radio" name="provider" value="HyperV"{{(selectedProvider == VirtualizationProvider.HyperV ? " checked" : "")}}>Hyper-V<div class="hint" data-zh="保留已有 Hyper-V 配置兼容性。" data-en="Keep compatibility with existing Hyper-V configurations.">保留已有 Hyper-V 配置兼容性。</div></label>
                <label class="choice"><input type="radio" name="provider" value="Qemu"{{(selectedProvider == VirtualizationProvider.Qemu ? " checked" : "")}}>QEMU<div class="hint" data-zh="用于已有 QEMU 工作流。" data-en="For existing QEMU workflows.">用于已有 QEMU 工作流。</div></label>
              </div>
            </section>

            <section id="vmwareFields">
              <h2 data-zh="2. VMware 与 Windows 10 连接" data-en="2. VMware and Windows 10 connection">2. VMware 与 Windows 10 连接</h2>
              <div class="grid">
                <div><label for="vmxPath" data-zh="虚拟机 VMX 路径" data-en="VMX path">虚拟机 VMX 路径</label><input id="vmxPath" name="vmxPath" value="{{Attr(vmxPath)}}" placeholder="E:\\VMs\\Windows10\\Windows 10 x64.vmx"><p class="hint" data-zh="发行包可以使用浏览器选择；本机路径不会上传。" data-en="The distribution can use a file picker; this local path is never uploaded.">发行包可以使用浏览器选择；本机路径不会上传。</p></div>
                <div><label for="snapshot" data-zh="干净快照名称" data-en="Clean snapshot">干净快照名称</label><input id="snapshot" name="snapshot" value="{{Attr(snapshot)}}" placeholder="Clean"></div>
                <div><label for="vmrun" data-zh="vmrun.exe 路径" data-en="vmrun.exe path">vmrun.exe 路径</label><input id="vmrun" name="vmrun" value="{{Attr(vmrun)}}" placeholder="vmrun.exe"></div>
                <div><label for="vmName" data-zh="虚拟机显示名称" data-en="VM display name">虚拟机显示名称</label><input id="vmName" name="vmName" value="{{Attr(vmware.VmName)}}"></div>
              </div>
              <div class="checks">
                <label><input id="tools" type="checkbox" checked>VMware Tools<div class="hint" data-zh="用于发现来宾 IP 与可靠传输。" data-en="Used to discover the guest IP and transfer reliably.">用于发现来宾 IP 与可靠传输。</div></label>
                <label><input id="ssl" type="checkbox"{{(guest.UseSsl ? " checked" : "")}}>WinRM HTTPS<div class="hint" data-zh="默认端口 5986；可跳过自签名证书校验。" data-en="Port 5986 by default; self-signed certificate checks may be skipped.">默认端口 5986；可跳过自签名证书校验。</div></label>
                <label><input id="skipCert" type="checkbox"{{(guest.SkipCertificateChecks ? " checked" : "")}}>跳过证书校验 / Skip certificate checks</label>
              </div>
              <div class="grid">
                <div><label for="guestAddress" data-zh="来宾地址（可留空让 VMware Tools 发现）" data-en="Guest address (leave blank for VMware Tools)">来宾地址（可留空让 VMware Tools 发现）</label><input id="guestAddress" value="{{Attr(address)}}" placeholder="192.168.56.101"></div>
                <div><label for="guestPort" data-zh="WinRM 端口" data-en="WinRM port">WinRM 端口</label><input id="guestPort" type="number" min="1" max="65535" value="{{port}}"></div>
              </div>
              <div class="grid">
                <div><label for="guestPassword" data-zh="来宾密码（只写入本机 secret）" data-en="Guest password (local secret only)">来宾密码（只写入本机 secret）</label><input id="guestPassword" type="password" autocomplete="new-password" placeholder="SandboxUser password"><p class="hint" data-zh="不会写入 JSON、报告或 Git；保存到当前 Web Host 和当前用户环境变量。" data-en="Never written to JSON, reports, or Git; stored in the current Web Host and current-user environment.">不会写入 JSON、报告或 Git；保存到当前 Web Host 和当前用户环境变量。</p></div>
                <div class="actions" style="align-items:flex-end"><button type="button" onclick="saveGuestSecret()" data-zh="保存来宾密码" data-en="Save guest password">保存来宾密码</button><button type="button" class="secondary" onclick="clearGuestSecret()" data-zh="清除 secret" data-en="Clear secret">清除 secret</button></div>
              </div>
              <div id="secretStatus" class="status" data-zh="来宾密码状态未知。" data-en="Guest password state is unknown.">来宾密码状态未知。</div>
            </section>

            <section>
              <h2 data-zh="3. 只读预检" data-en="3. Read-only preflight">3. 只读预检</h2>
              <p data-zh="预检只读取 vmrun、VMX、快照、VMware Tools 和 WinRM 状态，不启动或修改虚拟机。" data-en="Preflight only reads vmrun, VMX, snapshot, VMware Tools, and WinRM state; it does not start or modify the VM.">预检只读取 vmrun、VMX、快照、VMware Tools 和 WinRM 状态，不启动或修改虚拟机。</p>
              <div id="preflight" class="status" data-zh="尚未检查。" data-en="Not checked yet.">尚未检查。</div>
              <div class="actions"><button type="button" class="secondary" onclick="runPreflight()" data-zh="运行只读预检" data-en="Run read-only preflight">运行只读预检</button><button type="button" class="secondary" onclick="loadProfile()" data-zh="重新读取配置" data-en="Reload profile">重新读取配置</button></div>
              <pre id="readinessDetail" class="hidden"></pre>
            </section>

            <section>
              <h2 data-zh="4. 保存配置并进入样本选择" data-en="4. Save and continue to sample selection">4. 保存配置并进入样本选择</h2>
              <p data-zh="保存会调用本机 setup profile 接口。配置文件路径仅供本机 Web Host 使用；不会推送远程仓库。保存后请重新启动 WebUI，让新配置成为运行时配置。" data-en="Save calls the local setup profile endpoint. The config path is used only by this Web Host; nothing is pushed to a remote repository. Restart the WebUI after saving so the new profile becomes active.">保存会调用本机 setup profile 接口。配置文件路径仅供本机 Web Host 使用；不会推送远程仓库。保存后请重新启动 WebUI，让新配置成为运行时配置。</p>
              <div id="saveStatus" class="status" data-zh="请先完成预检。" data-en="Run preflight first.">请先完成预检。</div>
              <div class="actions"><button type="button" onclick="saveProfile()" data-zh="保存 VMware 配置" data-en="Save VMware configuration">保存 VMware 配置</button><a class="button secondary" href="/" data-zh="进入样本选择" data-en="Continue to sample selection">进入样本选择</a></div>
              <p class="footer-note" data-zh="当前配置文件：{{Attr(path)}}" data-en="Current config file: {{Attr(path)}}">当前配置文件：{{Attr(path)}}</p>
            </section>
          </main>
          <script>
            let language = localStorage.getItem('ksword-lang') || localStorage.getItem('ksword-language') || 'zh';
            const t = (zh, en) => language === 'en' ? en : zh;
            function toggleLanguage() { language = language === 'zh' ? 'en' : 'zh'; localStorage.setItem('ksword-lang', language); applyLanguage(); }
            function applyLanguage() {
              document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(x => { x.textContent = language === 'en' ? x.dataset.en : x.dataset.zh; });
            }
            function selectedProvider() { return document.querySelector('input[name=provider]:checked')?.value || 'VMware'; }
            function formProfile() {
              return { provider: selectedProvider(), vmxPath: document.getElementById('vmxPath').value.trim(), snapshotName: document.getElementById('snapshot').value.trim(), vmrunPath: document.getElementById('vmrun').value.trim(), vmName: document.getElementById('vmName').value.trim(), addressMode: document.getElementById('guestAddress').value.trim() ? 'Configured' : 'VMwareTools', address: document.getElementById('guestAddress').value.trim() || null, authentication: 'Negotiate', useSsl: document.getElementById('ssl').checked, port: Number(document.getElementById('guestPort').value || 5986), skipCertificateChecks: document.getElementById('skipCert').checked };
            }
            async function json(url, options) { const response = await fetch(url, options); const text = await response.text(); let data = {}; try { data = text ? JSON.parse(text) : {}; } catch { data = { raw:text }; } if (!response.ok) throw new Error(`${response.status}: ${data.error || data.title || data.detail || text}`); return data; }
            async function loadProfile() { const target = document.getElementById('preflight'); target.className = 'status'; target.textContent = t('正在读取 setup profile…', 'Loading setup profile…'); try { const data = await json('/api/setup/profile'); const vmware = data.config?.vmware || data.config?.vMware || data.vmware || data.vMware; if (vmware?.vmxPath) document.getElementById('vmxPath').value = vmware.vmxPath; if (vmware?.snapshotName) document.getElementById('snapshot').value = vmware.snapshotName; if (vmware?.vmrunPath) document.getElementById('vmrun').value = vmware.vmrunPath; target.className = 'status ok'; target.textContent = t('已读取本机配置。', 'Local profile loaded.'); } catch (e) { target.className = 'status warn'; target.textContent = t(`读取失败：${e.message}`, `Load failed: ${e.message}`); } }
            async function runPreflight() { const target = document.getElementById('preflight'), detail = document.getElementById('readinessDetail'); target.className = 'status'; target.textContent = t('检查中…', 'Checking…'); try { const preview = await json('/api/setup/preview', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(formProfile()) }); const ready = preview.readiness || {}; detail.classList.remove('hidden'); detail.textContent = JSON.stringify(preview, null, 2); const vm = ready.virtualization || ready.Virtualization || {}; const configReady = vm.configurationReady ?? vm.ConfigurationReady ?? ((vm.managementAvailable ?? vm.ManagementAvailable) && (vm.vmExists ?? vm.VmExists)); const queryOk = vm.querySucceeded ?? vm.QuerySucceeded ?? false; const baselineOk = vm.baselineExists ?? vm.BaselineExists ?? false; const ok = Boolean(configReady && queryOk && baselineOk); target.className = `status ${ok ? 'ok' : 'warn'}`; target.textContent = ok ? t('当前表单配置预检通过，可以保存。', 'The values currently in this form passed preflight; ready to save.') : t('当前表单配置仍有待处理项目，请查看详情。', 'The values currently in this form have pending items; inspect details.'); } catch (e) { target.className = 'status bad'; target.textContent = t(`预检失败：${e.message}`, `Preflight failed: ${e.message}`); } }
            async function saveProfile() { const target = document.getElementById('saveStatus'); target.className = 'status'; target.textContent = t('保存中…', 'Saving…'); try { const data = await json('/api/setup/profile', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(formProfile()) }); target.className = 'status ok'; target.textContent = t('已保存。请重新启动 WebUI，再进入样本选择。', 'Saved. Restart the WebUI, then continue to sample selection.'); if (data) document.getElementById('readinessDetail').textContent = JSON.stringify(data, null, 2); } catch (e) { target.className = 'status bad'; target.textContent = t(`保存失败：${e.message}`, `Save failed: ${e.message}`); } }
            async function saveGuestSecret() { const target = document.getElementById('secretStatus'), password = document.getElementById('guestPassword').value; target.className = 'status'; target.textContent = t('保存 secret 中…', 'Saving secret…'); try { const data = await json('/api/setup/guest-secret', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ password, clear:false }) }); document.getElementById('guestPassword').value = ''; target.className = 'status ok'; target.textContent = t(`已保存到本机 secret：${data.secretName}。`, `Saved to local secret: ${data.secretName}.`); } catch (e) { target.className = 'status bad'; target.textContent = t(`保存失败：${e.message}`, `Save failed: ${e.message}`); } }
            async function clearGuestSecret() { const target = document.getElementById('secretStatus'); if (!confirm(t('清除当前用户的来宾 secret？','Clear the current-user guest secret?'))) return; try { const data = await json('/api/setup/guest-secret', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ clear:true }) }); target.className = 'status warn'; target.textContent = t(`已清除：${data.secretName}。`, `Cleared: ${data.secretName}.`); } catch (e) { target.className = 'status bad'; target.textContent = t(`清除失败：${e.message}`, `Clear failed: ${e.message}`); } }
            document.querySelectorAll('input[name=provider]').forEach(x => x.addEventListener('change', () => { document.getElementById('vmwareFields').classList.toggle('hidden', selectedProvider() !== 'VMware'); }));
            applyLanguage(); loadProfile();
          </script>
        </body>
        </html>
        """;
    }

    private static string Attr(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
