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
        var hyperV = config.HyperV;
        var qemu = config.Qemu;
        var guest = vmware.GuestRemoting;
        var path = string.IsNullOrWhiteSpace(configPath) ? "config/sandbox.local.json" : configPath;
        var selectedProvider = preferVmware ? VirtualizationProvider.VMware : virtualization.Provider;
        var vmxPath = vmware.VmxPath ?? string.Empty;
        var snapshot = vmware.SnapshotName ?? string.Empty;
        var vmrun = vmware.VmrunPath ?? "vmrun.exe";
        var address = guest.Address ?? string.Empty;
        var port = guest.Port == 0 ? 5986 : guest.Port;
        var guestUserName = config.Guest.UserName;
        var guestWorkingDirectory = config.Guest.WorkingDirectory;
        var qemuGuest = qemu.GuestRemoting;
        // First-run must not preselect real R0: the sample config enables the
        // driver but has no host .sys, so Real would immediately fail the
        // readiness gate. User-mode keeps the first sample path working.
        var collectorMode = preferVmware && string.IsNullOrWhiteSpace(config.Driver.HostDriverPath)
            ? "UserMode"
            : (!config.Driver.Enabled ? "UserMode" : config.Driver.UseMockCollector ? "Mock" : "Real");

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
            input,select,textarea { background:var(--surface); border:1px solid #cbd5e1; color:var(--ink); font:inherit; padding:9px 10px; width:100%; }
            textarea { font-family:Consolas,"JetBrains Mono",monospace; font-size:12px; margin-top:10px; resize:vertical; }
            input:focus,select:focus,button:focus-visible,a:focus-visible { border-color:var(--accent); outline:2px solid #b8d6ff; outline-offset:1px; }
            .hint,.footer-note { color:var(--muted); font-size:12px; margin:4px 0 0; }
            .checks label { background:var(--subtle); border:1px solid var(--line); flex:1 1 200px; padding:11px; }
            .checks input { width:auto; margin-right:7px; }
            .checklist { display:grid; gap:8px; grid-template-columns:repeat(2,minmax(0,1fr)); margin:14px 0 0; }
            .check-item { align-items:flex-start; background:var(--subtle); border:1px solid var(--line); display:flex; gap:9px; padding:10px 12px; }
            .check-item .mark { color:var(--success); font-weight:700; }
            .check-item strong { display:block; font-size:13px; }
            .check-item span { color:var(--muted); display:block; font-size:12px; margin-top:2px; }
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
            @media(max-width:620px) { .checklist { grid-template-columns:1fr; } }
          </style>
        </head>
        <body data-config-path="{{Attr(path)}}">
          <header>
            <div class="topline">
              <div>
                <h1 data-zh="KSword Sandbox · 后端设置" data-en="KSword Sandbox · Backend setup">KSword Sandbox · 后端设置</h1>
                <p class="subtle" data-zh="首次启动时完成主机与 Windows 10 来宾虚拟机的连接。保存后请重新启动 WebUI，再进入样本选择；所有检查都先以只读方式运行。" data-en="Connect the host to a Windows 10 guest during first launch. Restart the WebUI after saving, then continue to sample selection; checks are read-only until you save.">首次启动时完成主机与 Windows 10 来宾虚拟机的连接。保存后请重新启动 WebUI，再进入样本选择；所有检查都先以只读方式运行。</p>
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
              <h2 data-zh="开始前：准备一台可丢弃的 Windows 10" data-en="Before you start: prepare a disposable Windows 10 guest">开始前：准备一台可丢弃的 Windows 10</h2>
              <p class="subtle" data-zh="向导不会替你创建虚拟机、安装来宾工具或配置来宾通信。按下面顺序准备一次，之后每个样本都会从干净基线启动并在结束时清理；VMware 完整清单见发行包 docs/vmware-first-run.md。" data-en="The wizard does not create the VM, install guest tools, or configure guest communication for you. Complete this checklist once; each sample then starts from the clean baseline and is cleaned up afterwards. See docs/vmware-first-run.md in the package for the full VMware checklist.">向导不会替你创建虚拟机、安装来宾工具或配置来宾通信。按下面顺序准备一次，之后每个样本都会从干净基线启动并在结束时清理；VMware 完整清单见发行包 docs/vmware-first-run.md。</p>
              <div class="checklist" role="list">
                <div class="check-item" role="listitem"><span class="mark">1</span><div><strong data-zh="创建 Windows 10 x64 VM" data-en="Create a Windows 10 x64 VM">创建 Windows 10 x64 VM</strong><span data-zh="VMware 默认 Block 路线需移除虚拟网卡并关闭 HGFS、USB、剪贴板与拖放；安装 VMware Workstation Pro 和来宾 VMware Tools，不放个人数据。" data-en="For the default VMware Block route, remove virtual NICs and disable HGFS, USB, clipboard and drag-and-drop; install Workstation Pro and guest VMware Tools, and keep personal data out.">VMware 默认 Block 路线需移除虚拟网卡并关闭 HGFS、USB、剪贴板与拖放；安装 VMware Workstation Pro 和来宾 VMware Tools，不放个人数据。</span></div></div>
                <div class="check-item" role="listitem"><span class="mark">2</span><div><strong data-zh="准备来宾通信方式" data-en="Prepare guest communication">准备来宾通信方式</strong><span data-zh="VMware Block 使用 VMware Tools GuestOps，无需来宾地址或 WinRM；Hyper-V 使用 PowerShell Direct；QEMU Allow 使用 NAT 或固定地址。" data-en="VMware Block uses VMware Tools GuestOps without a guest address or WinRM; Hyper-V uses PowerShell Direct; QEMU Allow uses NAT or a configured address.">VMware Block 使用 VMware Tools GuestOps，无需来宾地址或 WinRM；Hyper-V 使用 PowerShell Direct；QEMU Allow 使用 NAT 或固定地址。</span></div></div>
                <div class="check-item" role="listitem"><span class="mark">3</span><div><strong data-zh="配置 SandboxUser 与来宾通信" data-en="Configure SandboxUser and guest communication">配置 SandboxUser 与来宾通信</strong><span data-zh="在来宾管理员 PowerShell 中运行初始化脚本，准备专用管理员账户。默认 VMware Block 通过 VIX 登录；QEMU 和显式 Allow 的 VMware 路线仍需 WinRM HTTPS。" data-en="Run the bootstrap script in an elevated guest PowerShell to prepare a dedicated administrator account. Default VMware Block logs in through VIX; QEMU and explicit VMware Allow still need WinRM HTTPS.">在来宾管理员 PowerShell 中运行初始化脚本，准备专用管理员账户。默认 VMware Block 通过 VIX 登录；QEMU 和显式 Allow 的 VMware 路线仍需 WinRM HTTPS。</span><div class="actions"><button type="button" class="secondary" onclick="copyGuestBootstrap()" data-zh="复制来宾初始化脚本" data-en="Copy guest bootstrap script">复制来宾初始化脚本</button><a class="button secondary" href="/api/setup/guest-bootstrap" download="Bootstrap-VMwareGuest.ps1" data-zh="下载脚本文件" data-en="Download script file">下载脚本文件</a></div><div id="bootstrapStatus" class="status hidden" role="status" aria-live="polite"></div><textarea id="guestBootstrapSource" class="hidden" rows="12" spellcheck="false" readonly aria-label="来宾初始化 PowerShell 脚本"></textarea></div></div>
                <div class="check-item" role="listitem"><span class="mark">4</span><div><strong data-zh="关机后创建 Clean 快照" data-en="Power off and create a Clean snapshot">关机后创建 Clean 快照</strong><span data-zh="快照必须是可回滚的干净基线，名称可在下方修改。" data-en="The snapshot must be a disposable clean baseline; its name can be changed below.">快照必须是可回滚的干净基线，名称可在下方修改。</span></div></div>
              </div>
            </section>

            <section>
              <h2 data-zh="1. 选择虚拟化后端" data-en="1. Choose a virtualization backend">1. 选择虚拟化后端</h2>
              <div class="choice-row">
                <label class="choice"><input type="radio" name="provider" value="VMware"{{(selectedProvider == VirtualizationProvider.VMware ? " checked" : "")}}>VMware Workstation Pro<div class="hint" data-zh="推荐（当前优先支持）：首次使用请选此项；自动开机、传样本、采集、还原快照并关机。" data-en="Recommended (primary supported path): choose this for first use; boots, transfers, collects, restores the snapshot, and shuts down automatically.">推荐（当前优先支持）：首次使用请选此项；自动开机、传样本、采集、还原快照并关机。</div></label>
                <label class="choice"><input type="radio" name="provider" value="HyperV"{{(selectedProvider == VirtualizationProvider.HyperV ? " checked" : "")}}>Hyper-V<div class="hint" data-zh="仅用于已有 Hyper-V 环境；首次使用不要选此项。" data-en="Only for an existing Hyper-V environment; do not choose this for first use.">仅用于已有 Hyper-V 环境；首次使用不要选此项。</div></label>
                <label class="choice"><input type="radio" name="provider" value="Qemu"{{(selectedProvider == VirtualizationProvider.Qemu ? " checked" : "")}}>QEMU<div class="hint" data-zh="仅用于已有 QEMU 环境；首次使用不要选此项。" data-en="Only for an existing QEMU environment; do not choose this for first use.">仅用于已有 QEMU 环境；首次使用不要选此项。</div></label>
              </div>
            </section>

            <section id="vmwareFields">
              <h2 data-zh="2. VMware 与 Windows 10 连接" data-en="2. VMware and Windows 10 connection">2. VMware 与 Windows 10 连接</h2>
              <div class="grid">
                <div><label for="vmxPath" data-zh="虚拟机 VMX 路径" data-en="VMX path">虚拟机 VMX 路径</label><input id="vmxPath" name="vmxPath" value="{{Attr(vmxPath)}}" placeholder="E:\\VMs\\Windows10\\Windows 10 x64.vmx"><p class="hint" data-zh="粘贴宿主机上 .vmx 文件的完整路径；该路径只保存到本机配置。" data-en="Paste the full path to the .vmx file on this host; it is saved only in local configuration.">粘贴宿主机上 .vmx 文件的完整路径；该路径只保存到本机配置。</p></div>
                <div><label for="snapshot" data-zh="干净快照名称" data-en="Clean snapshot">干净快照名称</label><input id="snapshot" name="snapshot" value="{{Attr(snapshot)}}" placeholder="Clean"></div>
                <div><label for="vmrun" data-zh="vmrun.exe 路径（Workstation 安装目录）" data-en="vmrun.exe path (Workstation install folder)">vmrun.exe 路径（Workstation 安装目录）</label><input id="vmrun" name="vmrun" value="{{Attr(vmrun)}}" placeholder="C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"></div>
                <div><label for="vmName" data-zh="虚拟机显示名称" data-en="VM display name">虚拟机显示名称</label><input id="vmName" name="vmName" value="{{Attr(vmware.VmName)}}"></div>
              </div>
            </section>
            <section id="guestTransportFields">
              <h2 data-zh="来宾通信与密码" data-en="Guest transport and password">来宾通信与密码</h2>
              <p class="hint" data-zh="默认 VMware Block 使用 VIX GuestOps，无需 WinRM 或来宾网卡；Hyper-V 使用 PowerShell Direct。仅 QEMU Allow 与 VMware Allow 使用下方 WinRM HTTPS 选项。" data-en="Default VMware Block uses VIX GuestOps without WinRM or a guest NIC; Hyper-V uses PowerShell Direct. The WinRM HTTPS options below apply to QEMU Allow and VMware Allow.">默认 VMware Block 使用 VIX GuestOps，无需 WinRM 或来宾网卡；Hyper-V 使用 PowerShell Direct。仅 QEMU Allow 与 VMware Allow 使用下方 WinRM HTTPS 选项。</p>
              <div class="checks">
                <label><input id="tools" type="checkbox" checked disabled>VMware Tools（仅 VMware）<div class="hint" data-zh="仅 VMware 的 VMwareTools 地址模式需要；Hyper-V 使用 PowerShell Direct，QEMU 使用 QemuUserNat 或固定地址。" data-en="Required only for VMwareTools address mode; Hyper-V uses PowerShell Direct and QEMU uses QemuUserNat or a configured address.">仅 VMware 的 VMwareTools 地址模式需要；Hyper-V 使用 PowerShell Direct，QEMU 使用 QemuUserNat 或固定地址。</div></label>
                <label><input id="ssl" type="checkbox"{{(guest.UseSsl ? " checked" : "")}}>WinRM HTTPS<div class="hint" data-zh="默认端口 5986；可跳过自签名证书校验。" data-en="Port 5986 by default; self-signed certificate checks may be skipped.">默认端口 5986；可跳过自签名证书校验。</div></label>
                <label><input id="skipCert" type="checkbox"{{(guest.SkipCertificateChecks ? " checked" : "")}}>跳过证书校验 / Skip certificate checks</label>
              </div>
              <div class="grid">
                <div><label for="guestAddress" data-zh="来宾地址（自动发现模式可留空）" data-en="Guest address (leave blank for automatic discovery)">来宾地址（自动发现模式可留空）</label><input id="guestAddress" value="{{Attr(address)}}" placeholder="192.168.56.101"></div>
                <div><label for="guestPort" data-zh="WinRM 端口" data-en="WinRM port">WinRM 端口</label><input id="guestPort" type="number" min="1" max="65535" value="{{port}}"></div>
              </div>
              <div class="grid">
                <div><label for="guestPassword" data-zh="来宾密码（只写入本机 secret）" data-en="Guest password (local secret only)">来宾密码（只写入本机 secret）</label><input id="guestPassword" type="password" autocomplete="new-password" placeholder="SandboxUser password"><p class="hint" data-zh="不会写入 JSON、报告或 Git；保存到当前 Web Host 和当前用户环境变量。" data-en="Never written to JSON, reports, or Git; stored in the current Web Host and current-user environment.">不会写入 JSON、报告或 Git；保存到当前 Web Host 和当前用户环境变量。</p></div>
                <div class="actions" style="align-items:flex-end"><button type="button" onclick="saveGuestSecret()" data-zh="保存来宾密码" data-en="Save guest password">保存来宾密码</button><button type="button" class="secondary" onclick="clearGuestSecret()" data-zh="清除 secret" data-en="Clear secret">清除 secret</button></div>
              </div>
              <div id="secretStatus" class="status" data-zh="来宾密码状态未知。" data-en="Guest password state is unknown.">来宾密码状态未知。</div>
            </section>

            <section>
              <h2 data-zh="来宾身份与工作目录" data-en="Guest identity and working folder">来宾身份与工作目录</h2>
              <div class="grid">
                <div><label for="guestUserName" data-zh="来宾管理员用户名" data-en="Guest administrator username">来宾管理员用户名</label><input id="guestUserName" value="{{Attr(guestUserName)}}" placeholder="SandboxUser"><p class="hint" data-zh="必须与来宾 VM 内 bootstrap 脚本创建的账户一致。" data-en="Must match the account created by the bootstrap script inside the guest VM.">必须与来宾 VM 内 bootstrap 脚本创建的账户一致。</p></div>
                <div><label for="guestWorkingDirectory" data-zh="来宾工作目录" data-en="Guest working directory">来宾工作目录</label><input id="guestWorkingDirectory" value="{{Attr(guestWorkingDirectory)}}" placeholder="C:\\KSwordSandbox"><p class="hint" data-zh="使用系统和用户目录之外的专用绝对路径；自定义目录须先在来宾运行本页初始化脚本。分析任务会清理其中的暂存内容。" data-en="Use a dedicated absolute path outside system and user folders. Run this page's guest bootstrap first for custom paths; jobs clear staged contents there.">使用系统和用户目录之外的专用绝对路径；自定义目录须先在来宾运行本页初始化脚本。分析任务会清理其中的暂存内容。</p></div>
              </div>
              <label for="collectorMode" data-zh="采集模式" data-en="Collection mode">采集模式</label>
              <select id="collectorMode"><option value="UserMode"{{(collectorMode == "UserMode" ? " selected" : "")}}>用户态行为 / User-mode behavior</option><option value="Mock"{{(collectorMode == "Mock" ? " selected" : "")}}>模拟 R0 / Mock R0</option><option value="Real"{{(collectorMode == "Real" ? " selected" : "")}}>真实 R0 / Real R0</option></select>
              <p class="hint" data-zh="初次配置可选用户态行为。Mock 仅模拟驱动事件；真实 R0 要求已签名驱动、来宾证书信任与测试签名模式。" data-en="Choose user-mode behavior for first setup. Mock simulates driver events; real R0 needs a signed driver, guest certificate trust and test signing.">初次配置可选用户态行为。Mock 仅模拟驱动事件；真实 R0 要求已签名驱动、来宾证书信任与测试签名模式。</p>
              <label for="hostDriverPath" data-zh="真实 R0 驱动宿主路径" data-en="Host path to real R0 driver">真实 R0 驱动宿主路径</label><input id="hostDriverPath" value="{{Attr(config.Driver.HostDriverPath)}}" placeholder="D:\\Drivers\\KSword.Sandbox.Driver.sys">
            </section>

            <section id="hypervFields" class="hidden">
              <h2 data-zh="2. Hyper-V 配置" data-en="2. Hyper-V configuration">2. Hyper-V 配置</h2>
              <div class="grid">
                <div><label for="hypervVmName" data-zh="黄金 VM 名称" data-en="Golden VM name">黄金 VM 名称</label><input id="hypervVmName" value="{{Attr(hyperV.GoldenVmName)}}"></div>
                <div><label for="hypervSnapshot" data-zh="干净检查点" data-en="Clean checkpoint">干净检查点</label><input id="hypervSnapshot" value="{{Attr(hyperV.GoldenSnapshotName)}}"></div>
              </div>
            </section>

            <section id="qemuFields" class="hidden">
              <h2 data-zh="2. QEMU 配置" data-en="2. QEMU configuration">2. QEMU 配置</h2>
              <div class="grid">
                <div><label for="qemuVmName" data-zh="虚拟机名称" data-en="VM name">虚拟机名称</label><input id="qemuVmName" value="{{Attr(qemu.VmName)}}"></div>
                <div><label for="qemuDisk" data-zh="基础磁盘路径" data-en="Base disk path">基础磁盘路径</label><input id="qemuDisk" value="{{Attr(qemu.DiskImagePath)}}" placeholder="D:\\VMs\\Win10\\base.qcow2"></div>
                <div><label for="qemuSystem" data-zh="qemu-system 路径" data-en="qemu-system path">qemu-system 路径</label><input id="qemuSystem" value="{{Attr(qemu.QemuSystemPath)}}"></div>
                <div><label for="qemuImg" data-zh="qemu-img 路径" data-en="qemu-img path">qemu-img 路径</label><input id="qemuImg" value="{{Attr(qemu.QemuImgPath)}}"></div>
                <div><label for="qemuFormat" data-zh="磁盘格式" data-en="Disk format">磁盘格式</label><select id="qemuFormat"><option value="qcow2"{{(string.Equals(qemu.DiskFormat, "qcow2", StringComparison.OrdinalIgnoreCase) ? " selected" : "")}}>qcow2</option><option value="raw"{{(string.Equals(qemu.DiskFormat, "raw", StringComparison.OrdinalIgnoreCase) ? " selected" : "")}}>raw</option><option value="vhdx"{{(string.Equals(qemu.DiskFormat, "vhdx", StringComparison.OrdinalIgnoreCase) ? " selected" : "")}}>vhdx</option><option value="vmdk"{{(string.Equals(qemu.DiskFormat, "vmdk", StringComparison.OrdinalIgnoreCase) ? " selected" : "")}}>vmdk</option></select></div>
                <div><label for="qemuInterface" data-zh="磁盘接口" data-en="Disk interface">磁盘接口</label><select id="qemuInterface"><option value="virtio"{{(qemu.DiskInterface == "virtio" ? " selected" : "")}}>virtio</option><option value="ide"{{(qemu.DiskInterface == "ide" ? " selected" : "")}}>ide</option><option value="scsi"{{(qemu.DiskInterface == "scsi" ? " selected" : "")}}>scsi</option></select></div>
                <div><label for="qemuMemory" data-zh="内存 MB" data-en="Memory MB">内存 MB</label><input id="qemuMemory" type="number" min="1024" max="65536" value="{{qemu.MemoryMegabytes}}"></div>
                <div><label for="qemuSnapshot" data-zh="内部快照名称（overlay 可留空）" data-en="Internal snapshot name (optional with overlay)">内部快照名称（overlay 可留空）</label><input id="qemuSnapshot" value="{{Attr(qemu.SnapshotName)}}"></div>
              </div>
              <div class="checks"><label><input id="qemuOverlay" type="checkbox"{{(qemu.UseOverlayDisk ? " checked" : "")}}>每任务 overlay / Per-job overlay<div class="hint" data-zh="推荐：不会修改基础磁盘；每个任务使用一次性隔离层。" data-en="Recommended: keeps the base disk unchanged and uses a disposable layer per job.">推荐：不会修改基础磁盘；每个任务使用一次性隔离层。</div></label><label><input id="qemuHeadless" type="checkbox"{{(qemu.Headless ? " checked" : "")}}>无窗口 / Headless</label></div>
              <div><label for="qemuAddress" data-zh="来宾地址（QemuUserNat 可留空）" data-en="Guest address (leave blank for QemuUserNat)">来宾地址（QemuUserNat 可留空）</label><input id="qemuAddress" value="{{Attr(qemuGuest.Address)}}" placeholder="192.168.122.10"></div>
              <div><label for="qemuArguments" data-zh="QEMU 额外参数（JSON 字符串数组）" data-en="Additional QEMU arguments (JSON string array)">QEMU 额外参数（JSON 字符串数组）</label><input id="qemuArguments" value="{{Attr(System.Text.Json.JsonSerializer.Serialize(qemu.AdditionalArguments))}}"><p class="hint" data-zh="默认使用 WHPX；按镜像填写 UEFI 等参数。virtio / scsi 需要来宾存储驱动，未安装时选择 IDE。" data-en="WHPX is the default; add firmware arguments required by your image. virtio / scsi need guest storage drivers; choose IDE if absent.">默认使用 WHPX；按镜像填写 UEFI 等参数。virtio / scsi 需要来宾存储驱动，未安装时选择 IDE。</p></div>
            </section>

            <section>
              <h2 data-zh="3. 只读预检" data-en="3. Read-only preflight">3. 只读预检</h2>
               <p data-zh="预检只读取所选后端的管理工具、虚拟机/磁盘、干净基线和通信配置，不启动或修改虚拟机；真实来宾登录会在 Live 前再次验证。" data-en="Preflight reads the selected backend tool, VM or disk, clean baseline, and transport configuration; it does not start or modify the VM. Live verifies the actual guest login again.">预检只读取所选后端的管理工具、虚拟机/磁盘、干净基线和通信配置，不启动或修改虚拟机；真实来宾登录会在 Live 前再次验证。</p>
              <div id="preflight" class="status" data-zh="尚未检查。" data-en="Not checked yet.">尚未检查。</div>
              <div id="preflightChecks" class="checklist hidden" aria-live="polite"></div>
              <div class="actions"><button type="button" class="secondary" onclick="runPreflight()" data-zh="运行只读预检" data-en="Run read-only preflight">运行只读预检</button><button type="button" class="secondary" onclick="loadProfile()" data-zh="重新读取配置" data-en="Reload profile">重新读取配置</button></div>
              <pre id="readinessDetail" class="hidden"></pre>
            </section>

            <section>
              <h2 data-zh="4. 保存配置并进入样本选择" data-en="4. Save and continue to sample selection">4. 保存配置并进入样本选择</h2>
              <p data-zh="保存会调用本机 setup profile 接口。配置文件路径仅供本机 Web Host 使用；不会推送远程仓库。保存后请重新启动 WebUI，让新配置成为运行时配置。" data-en="Save calls the local setup profile endpoint. The config path is used only by this Web Host; nothing is pushed to a remote repository. Restart the WebUI after saving so the new profile becomes active.">保存会调用本机 setup profile 接口。配置文件路径仅供本机 Web Host 使用；不会推送远程仓库。保存后请重新启动 WebUI，让新配置成为运行时配置。</p>
              <div id="saveStatus" class="status" data-zh="请先完成预检。" data-en="Run preflight first.">请先完成预检。</div>
              <div class="actions"><button type="button" onclick="saveProfile()" data-zh="保存后端配置" data-en="Save backend configuration">保存后端配置</button><a class="button secondary" href="/" data-zh="重启后进入样本选择" data-en="Restart, then continue">重启后进入样本选择</a></div>
              <p class="footer-note" data-zh="当前配置文件：{{Attr(path)}}" data-en="Current config file: {{Attr(path)}}">当前配置文件：{{Attr(path)}}</p>
            </section>
          </main>
          <script>
            let language = localStorage.getItem('ksword-lang') || localStorage.getItem('ksword-language') || 'zh';
            const t = (zh, en) => language === 'en' ? en : zh;
            function toggleLanguage() { language = language === 'zh' ? 'en' : 'zh'; localStorage.setItem('ksword-lang', language); applyLanguage(); }
            async function copyGuestBootstrap() {
              const status = document.getElementById('bootstrapStatus');
              const source = document.getElementById('guestBootstrapSource');
              source.value = '';
              status.className = 'status'; status.textContent = t('正在读取来宾初始化脚本…', 'Loading the guest bootstrap script…');
              try {
                const response = await fetch('/api/setup/guest-bootstrap', { cache:'no-store' });
                if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
                const script = await response.text();
                if (!script.trim()) throw new Error(t('脚本内容为空。', 'The script is empty.'));
                // A pasted script needs a script-block scope for its param block.
                const guestPath = document.getElementById('guestWorkingDirectory').value.trim();
                const guestUser = document.getElementById('guestUserName').value.trim();
                if (!guestPath || !guestUser) throw new Error(t('请先填写来宾工作目录和用户名。', 'Enter the guest working directory and username first.'));
                const psQuote = value => "'" + value.replace(/'/g, "''") + "'";
                const pasteable = '& {\n' + script.trimEnd() + '\n} -WorkingDirectory ' + psQuote(guestPath) + ' -GuestUserName ' + psQuote(guestUser);
                source.value = pasteable;
                if (!navigator.clipboard?.writeText) throw new Error(t('浏览器不支持自动复制。', 'This browser cannot copy automatically.'));
                await navigator.clipboard.writeText(pasteable);
                source.classList.add('hidden');
                status.className = 'status ok'; status.textContent = t('完整脚本已复制。请切换到虚拟机的管理员 PowerShell，粘贴并运行。', 'The complete script was copied. Paste and run it in Administrator PowerShell inside the VM.');
              } catch (error) {
                source.classList.toggle('hidden', !source.value);
                if (source.value) source.select();
                status.className = 'status warn'; status.textContent = source.value
                  ? t('自动复制不可用；可从下方手动复制完整脚本，或下载脚本文件。', 'Automatic copy is unavailable. Copy the complete script below or download the file.')
                  : t(`无法读取脚本：${error.message}。请使用下载按钮。`, `Could not load the script: ${error.message}. Use the download button.`);
              }
            }
            function applyLanguage() {
              document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(x => { x.textContent = language === 'en' ? x.dataset.en : x.dataset.zh; });
            }
            function selectedProvider() { return document.querySelector('input[name=provider]:checked')?.value || 'VMware'; }
            const val = id => (document.getElementById(id)?.value || '').trim();
            const checked = id => Boolean(document.getElementById(id)?.checked);
            function formProfile() {
              const provider = selectedProvider();
              const address = provider === 'Qemu' ? val('qemuAddress') : val('guestAddress');
              const addressMode = provider === 'VMware' ? (address ? 'Configured' : 'VMwareTools') : provider === 'Qemu' ? (address ? 'Configured' : 'QemuUserNat') : 'Configured';
              return { provider, vmxPath: val('vmxPath'), snapshotName: provider === 'HyperV' ? val('hypervSnapshot') : provider === 'Qemu' ? val('qemuSnapshot') : val('snapshot'), vmrunPath: val('vmrun'), vmName: provider === 'HyperV' ? val('hypervVmName') : provider === 'Qemu' ? val('qemuVmName') : val('vmName'), addressMode, address: address || null, authentication: 'Negotiate', useSsl: provider === 'HyperV' ? false : checked('ssl'), port: Number(val('guestPort') || 5986), skipCertificateChecks: provider === 'HyperV' ? false : checked('skipCert'), guestUserName: val('guestUserName'), guestWorkingDirectory: val('guestWorkingDirectory'), qemuSystemPath: val('qemuSystem'), qemuImgPath: val('qemuImg'), diskImagePath: val('qemuDisk'), diskFormat: val('qemuFormat') || 'qcow2', diskInterface: val('qemuInterface') || 'virtio', useOverlayDisk: checked('qemuOverlay'), memoryMegabytes: Number(val('qemuMemory') || 4096), headless: provider === 'VMware' ? true : provider === 'Qemu' ? checked('qemuHeadless') : false, additionalArguments: JSON.parse(val('qemuArguments') || '[]'), driverEnabled: val('collectorMode') !== 'UserMode', useMockCollector: val('collectorMode') === 'Mock', hostDriverPath: val('hostDriverPath') || null };
            }
            async function json(url, options) { const response = await fetch(url, options); const text = await response.text(); let data = {}; try { data = text ? JSON.parse(text) : {}; } catch { data = { raw:text }; } if (!response.ok) throw new Error(`${response.status}: ${data.error || data.title || data.detail || text}`); return data; }
            const prop = (obj, name) => obj?.[name] ?? obj?.[name[0].toLowerCase() + name.slice(1)];
            function setProviderFields() { const p = selectedProvider(); document.getElementById('vmwareFields').classList.toggle('hidden', p !== 'VMware'); document.getElementById('hypervFields').classList.toggle('hidden', p !== 'HyperV'); document.getElementById('qemuFields').classList.toggle('hidden', p !== 'Qemu'); }
            function setValue(id, value) { const input = document.getElementById(id); if (input && value !== undefined && value !== null) input.value = value; }
            function setChecked(id, value) { const input = document.getElementById(id); if (input && value !== undefined) input.checked = Boolean(value); }
            function loadTransport() { const profile = loadedConfig?.[selectedProvider() === 'Qemu' ? 'qemu' : 'vmware'] || loadedConfig?.vMware || {}; const remoting = profile.guestRemoting || {}; setChecked('ssl', remoting.useSsl); setChecked('skipCert', remoting.skipCertificateChecks); setValue('guestPort', remoting.port > 0 ? remoting.port : selectedProvider() === 'Qemu' ? 55986 : 5986); }
            let loadedConfig = null;
            async function loadProfile() {
              preflightPassed = false;
              const target = document.getElementById('preflight'); target.className = 'status'; target.textContent = t('正在读取 setup profile…', 'Loading setup profile…');
              try {
                const data = await json('/api/setup/profile'); const c = data.config || {}; loadedConfig = c;
                const vmware = c.vmware || c.vMware || {}; const hyperv = c.hyperV || c.hyperv || {}; const qemu = c.qemu || {}; const guest = c.guest || {}; const driver = c.driver || {};
                setValue('vmxPath', vmware.vmxPath); setValue('snapshot', vmware.snapshotName); setValue('vmrun', vmware.vmrunPath); setValue('vmName', vmware.vmName); setValue('guestAddress', vmware.guestRemoting?.address || '');
                setValue('hypervVmName', hyperv.goldenVmName); setValue('hypervSnapshot', hyperv.goldenSnapshotName);
                setValue('qemuVmName', qemu.vmName); setValue('qemuDisk', qemu.diskImagePath); setValue('qemuSystem', qemu.qemuSystemPath); setValue('qemuImg', qemu.qemuImgPath); setValue('qemuFormat', qemu.diskFormat); setValue('qemuInterface', qemu.diskInterface); setValue('qemuMemory', qemu.memoryMegabytes); setValue('qemuSnapshot', qemu.snapshotName); setValue('qemuAddress', qemu.guestRemoting?.address || ''); setValue('qemuArguments', JSON.stringify(qemu.additionalArguments || ['-accel','whpx'])); setChecked('qemuOverlay', qemu.useOverlayDisk); setChecked('qemuHeadless', qemu.headless);
                setValue('guestUserName', guest.userName); setValue('guestWorkingDirectory', guest.workingDirectory); setValue('collectorMode', driver.enabled ? driver.useMockCollector ? 'Mock' : 'Real' : 'UserMode'); setValue('hostDriverPath', driver.hostDriverPath || ''); loadTransport();
                target.className = 'status'; target.textContent = t('已读取当前进程配置；请运行预检。已保存的新配置需要重启才能生效。', 'Active process profile loaded; run preflight. Restart to activate a newly saved profile.');
              } catch (e) { target.className = 'status warn'; target.textContent = t(`读取失败：${e.message}`, `Load failed: ${e.message}`); }
            }
            function renderCheck(label, ok, detail) {
              const item = document.createElement('div'); item.className = 'check-item';
              const mark = document.createElement('span'); mark.className = 'mark'; mark.textContent = ok ? '✓' : '!';
              const text = document.createElement('div'); const title = document.createElement('strong'); title.textContent = label; const description = document.createElement('span'); description.textContent = detail;
              text.append(title, description); item.append(mark, text); return item;
            }
            async function runPreflight() { const target = document.getElementById('preflight'), saveStatus = document.getElementById('saveStatus'), detail = document.getElementById('readinessDetail'), checks = document.getElementById('preflightChecks'); preflightPassed = false; checks.innerHTML = ''; checks.classList.remove('hidden'); target.className = 'status'; target.textContent = t('检查中…', 'Checking…'); saveStatus.className = 'status'; saveStatus.textContent = t('预检完成后即可保存。', 'Save will be available after preflight.'); try { const preview = await json('/api/setup/preview', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(formProfile()) }); const ready = preview.readiness || {}; const vm = prop(ready, 'Virtualization') || {}; const host = prop(ready, 'HostVirtualization') || {}; const guest = prop(ready, 'Guest') || {}; const paths = prop(ready, 'Paths') || {}; const configReady = Boolean(prop(vm, 'ManagementAvailable') && prop(vm, 'VmExists')); const queryOk = Boolean(prop(vm, 'QuerySucceeded')); const baselineOk = Boolean(prop(vm, 'BaselineExists')); const endpointOk = Boolean(prop(vm, 'GuestEndpointReady') && prop(vm, 'GuestTransportSecure')); const secretOk = Boolean(prop(guest, 'PasswordSecretAvailable')); const manifest = prop(paths, 'PayloadManifest') || {}; const agent = prop(paths, 'AgentExecutable') || {}; const payloadOk = Boolean(prop(manifest, 'Exists') && prop(agent, 'Exists')); const accelerationOk = prop(host, 'HardwareAccelerationReady') === true; const hostOk = configReady && queryOk && baselineOk && endpointOk; preflightPassed = hostOk; checks.append(renderCheck(t('管理工具 / VMX / 磁盘', 'Management tool / VMX / disk'), configReady, prop(vm, 'DiagnosticMessage') || t('未检测到完整后端配置。', 'Provider configuration is incomplete.'))); checks.append(renderCheck(t('查询与干净基线', 'Inventory and clean baseline'), queryOk && baselineOk, prop(vm, 'DiagnosticCode') || 'not checked')); checks.append(renderCheck(prop(vm, 'GuestTransport') === 'VmwareGuestOps' ? t('VIX GuestOps 与隔离配置', 'VIX GuestOps and isolation') : t('来宾端点与 HTTPS', 'Guest endpoint and HTTPS'), endpointOk, endpointOk ? t('只读传输预检通过；尚未登录来宾。', 'Read-only transport preflight passed; guest login was not attempted.') : t('来宾传输或隔离配置未就绪。', 'Guest transport or isolation is not ready.'))); checks.append(renderCheck(t('来宾 secret', 'Guest secret'), secretOk, secretOk ? t('当前 Web Host 可读取 secret。', 'The current Web Host can read the secret.') : t('保存来宾密码后再运行 Live。', 'Save the guest password before Live.'))); checks.append(renderCheck(t('Guest payload', 'Guest payload'), payloadOk, payloadOk ? t('manifest 与 agent 已存在。', 'Manifest and agent are present.') : t('保存 profile 后重启 WebUI 以准备 payload。', 'Save the profile and restart WebUI to prepare payload.'))); checks.append(renderCheck(t('主机加速', 'Host acceleration'), accelerationOk, prop(host, 'DiagnosticMessage') || t('未确认；Live 可能不可用。', 'Not confirmed; Live may be unavailable.'))); detail.classList.remove('hidden'); detail.textContent = JSON.stringify(preview, null, 2); target.className = `status ${hostOk ? 'ok' : 'warn'}`; target.textContent = hostOk ? t('宿主配置预检通过，可以保存。来宾 secret、payload 和运行中登录仍需单独满足；预检不会开机或登录来宾。', 'Host configuration preflight passed; guest secret, payload and live login still need to be ready. No VM was started and no guest login was attempted.') : t('预检未通过宿主配置门槛，请先处理带 ! 的项目。', 'Host configuration preflight did not pass; fix items marked ! first.'); saveStatus.className = `status ${hostOk ? 'ok' : 'warn'}`; saveStatus.textContent = hostOk ? t('可以保存配置；这不代表 Live 已成功。保存后请重启 WebUI。', 'You can save the profile; this does not mean Live is ready. Restart WebUI after saving.') : t('宿主配置未通过，暂不能保存。', 'Host configuration is incomplete; saving is blocked.'); } catch (e) { target.className = 'status bad'; target.textContent = t(`预检失败：${e.message}`, `Preflight failed: ${e.message}`); saveStatus.className = 'status bad'; saveStatus.textContent = t('预检失败，请修复字段后重试。', 'Preflight failed; fix the fields and retry.'); } }
            let preflightPassed = false;
            async function saveProfile() { const target = document.getElementById('saveStatus'); if (!preflightPassed) { target.className = 'status warn'; target.textContent = t('请先运行并通过只读预检；保存按钮不会替代来宾通信验证。', 'Run and pass the read-only preflight first; saving does not replace guest communication validation.'); return; } target.className = 'status'; target.textContent = t('保存中…', 'Saving…'); try { const data = await json('/api/setup/profile', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(formProfile()) }); target.className = 'status ok'; target.textContent = t('已保存。请重新启动 WebUI，再进入样本选择。', 'Saved. Restart the WebUI, then continue to sample selection.'); if (data) document.getElementById('readinessDetail').textContent = JSON.stringify(data, null, 2); } catch (e) { target.className = 'status bad'; target.textContent = t(`保存失败：${e.message}`, `Save failed: ${e.message}`); } }
            async function saveGuestSecret() { const target = document.getElementById('secretStatus'), password = document.getElementById('guestPassword').value; target.className = 'status'; target.textContent = t('保存 secret 中…', 'Saving secret…'); try { const data = await json('/api/setup/guest-secret', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ password, clear:false }) }); document.getElementById('guestPassword').value = ''; target.className = 'status ok'; target.textContent = t(`已保存到本机 secret：${data.secretName}。`, `Saved to local secret: ${data.secretName}.`); } catch (e) { target.className = 'status bad'; target.textContent = t(`保存失败：${e.message}`, `Save failed: ${e.message}`); } }
            async function clearGuestSecret() { const target = document.getElementById('secretStatus'); if (!confirm(t('清除当前用户的来宾 secret？','Clear the current-user guest secret?'))) return; try { const data = await json('/api/setup/guest-secret', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ clear:true }) }); target.className = 'status warn'; target.textContent = t(`已清除：${data.secretName}。`, `Cleared: ${data.secretName}.`); } catch (e) { target.className = 'status bad'; target.textContent = t(`清除失败：${e.message}`, `Clear failed: ${e.message}`); } }
            document.querySelectorAll('input[name=provider]').forEach(x => x.addEventListener('change', () => { setProviderFields(); loadTransport(); preflightPassed = false; }));
            document.querySelectorAll('input,select').forEach(x => { x.addEventListener('input', () => { preflightPassed = false; }); x.addEventListener('change', () => { preflightPassed = false; }); });
            applyLanguage(); setProviderFields(); loadProfile();
          </script>
        </body>
        </html>
        """;
    }

    private static string Attr(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
