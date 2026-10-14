# VMware 首次运行手册 / VMware first-run runbook

本文把工作拆成**来宾层**和**宿主层**。先完成来宾层，再在主机 WebUI 保存配置；这样空白 Windows 10 VM 能按步骤产出第一份报告。全文以 VMware Workstation Pro（`vmrun.exe`、`vmType=ws`）为例。

## 交付给用户的最短步骤 / Minimum handoff

1. 关机状态把 VM 网卡设为 **NAT**；可以在 VMX 中确认 `ethernet0.connectionType = "nat"`。命令行只需检查主机网络：`vmrun -T ws listHostNetworks`，看到 `vmnet8` 类型为 `nat` 即可。
2. 启动 Windows 10，安装 VMware Tools，然后在来宾管理员 PowerShell 执行 `Bootstrap-VMwareGuest.ps1`，设置 `SandboxUser` 和 WinRM HTTPS。
3. 关机并创建一个 powered-off 快照，名称记为 `Clean`（或把实际名称填进 WebUI）。
4. 双击 `Start-KSwordSandbox.cmd`，在 `/setup` 填 VMX、快照、`vmrun.exe`、用户名和密码，运行只读预检并保存。
5. 首轮选择 Notepad、MSPaint、Calculator，关闭真实 R0 采集，策略选择“每个样本结束后停止并还原 Clean”，确认三份 HTML 报告后再启用 R0。

本项目不要求用户配置 NAT 端口转发；宿主通过 VMware Tools 获取来宾地址后直接访问 WinRM 5986。只有主机无法直达来宾时，才额外使用 `vmrun setPortForwarding vmnet8 tcp <host-port> <guest-ip> 5986`。

## 0. 先看边界 / Boundaries

- 来宾 VM 必须是可丢弃的 Windows 10，样本执行可能改变系统；不要放个人数据。
- `E:\Projects\Ksword5.1` 只是外部只读参考。发行包和运行时配置都在 Sandbox 自己的目录/仓库外。
- **Host readiness 不是 guest connectivity**：宿主可以找到 `vmrun`、VMX、快照并通过 SLAT 检查，但这不代表来宾已开机、WinRM 已监听、凭据正确或 Tools 已报告 IP。两者必须分别通过。
- 第一轮建议使用 `-NoR0Collector`（或 WebUI 中关闭真实 R0 采集）验证 VMware 开机、传输、任务编排和 HTML 报告链路。真实 R0 需要驱动文件、测试签名/测试模式和隔离环境，不能因为 WinRM 预检通过就宣称可用。

## 1. 来宾层：从空白 VM 到 Clean 基线 / Guest layer

### 1.1 创建并安装

1. 在 VMware Workstation Pro 创建 Windows 10 x64 VM，磁盘和内存按主机余量分配；使用可重装的实验 VM。
2. 安装 VMware Tools，重启一次。确认 VMware 菜单 **VM > Settings > Options > VMware Tools** 显示运行；Tools 用于宿主在每次恢复后发现来宾 IPv4。
3. 网络选 **NAT**（推荐首次运行，主机能访问来宾；无需把来宾暴露到局域网）。如果实验室策略要求桥接或 Host-only，也可以使用，但必须保证主机到来宾 TCP 5986 可达；不要把网络模式当成 WinRM 已配置的证据。
4. 建立一个本地管理员账户，或稍后让 bootstrap 创建 `SandboxUser`。完成 Windows Update/重启后，关闭不需要的共享。

### 1.2 运行一次来宾 bootstrap

以 VM 内的管理员 PowerShell 打开仓库/发行包中脚本，执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Bootstrap-VMwareGuest.ps1
```

脚本会隐藏读取 `SandboxUser` 密码，创建或更新本地账号，将其加入 Administrators，启用 WinRM 服务，复用或创建本机自签 HTTPS 证书，建立 WinRM HTTPS listener 和 TCP 5986 防火墙规则，并创建 `C:\KSwordSandbox`。脚本不额外强制长度或字符集，只要求密码非空并符合 Windows 本机策略；密码不会写入命令行、日志或配置文件。

已有正确账户而不想轮换密码时：

```powershell
.\scripts\Bootstrap-VMwareGuest.ps1 -SkipPasswordSet
```

常用参数：`-GuestUserName analyst`、`-WorkingDirectory D:\KSwordSandbox`、`-Port 5986`。脚本可重复运行；若端口改变，会重建本脚本管理的防火墙规则和 HTTPS listener。完成后记录它显示的 IPv4、端口和证书指纹，但不要记录密码。

从主机验证端口（只读）：

```powershell
Test-NetConnection <guest-ip> -Port 5986
```

端口不通时，先检查 VM 网络模式、Windows 防火墙、WinRM 服务和 Tools 报告的 IP；不要直接修改主机 TrustedHosts 来掩盖问题。自签证书在 Sandbox 配置中使用 `skipCertificateChecks=true`，生产证书则应关闭该选项并确保名称匹配。

### 1.3 做成可回滚基线

1. 在来宾中把 `C:\KSwordSandbox` 留作 payload 工作目录，确认没有个人文件。
2. 关机，不要保持暂停或挂起状态。
3. VMware 中创建 powered-off snapshot，名称固定为 `Clean`（或在 WebUI 中填入实际名称）。
4. 以后每个样本都从该快照开始；失败、超时或用户中止时，编排器应停止 VM 并回滚到该快照。若 VMware 报告锁定/consolidation，先在 VMware UI 处理完再重试。

## 2. 宿主层：WebUI 配置与只读预检 / Host layer

1. 双击发行包根目录的 `Start-KSwordSandbox.cmd`，浏览器打开本机 WebUI（默认 `http://127.0.0.1:18080`）。
2. 首次设置选择 **VMware Workstation**，填写：`vmrun.exe` 路径、VMX 路径、VM 显示名、`Clean` 快照名、来宾用户名、WinRM HTTPS 端口；通信模式选 **VMwareTools**，证书检查按上文选择。宿主密码只放进 `KSWORDBOX_GUEST_PASSWORD` 或页面支持的本地 secret 入口，不提交到 Git。
3. 先点击**只读预检**，确认每一层：`vmrun`、VMX、快照、Tools 地址发现、来宾 TCP 5986、WinRM HTTPS 登录、工作目录和 staged payload。预检不能启动、关机、还原或修改 VM。
4. 修复所有红项后保存配置；重新启动 WebUI 让运行时配置生效。保存后再次预检，确认使用的 VMX 和快照确实是可丢弃基线。

## 3. 三样本 Live 验收 / Three-sample live acceptance

选三个无害样本（例如 Notepad、MSPaint、Calculator），在样本选择页依次加入。首轮勾选 `NoR0Collector`，运行策略选“每个样本完成后停止并还原 Clean”。每个任务应观察到：

1. provider 从 Clean 快照恢复并启动 VM；
2. Tools 返回当前来宾 IP，主机通过 WinRM HTTPS 登录；
3. payload 和样本进入 `C:\KSwordSandbox`；
4. Guest Agent 执行样本，采集 JSONL/artifacts；
5. 生成 HTML report；
6. hard stop 后还原/关机，下一样本仍从 Clean 开始。

三份 HTML 报告应保存到运行时 jobs 目录，并在 WebUI 任务详情中可打开。报告若只有 DryRun/PlanOnly 标志，不能算 Live 验收；必须看到真实 provider、来宾端点和采集步骤。

## 4. 失败处理与回滚 / Failure and rollback

- **预检失败**：不启动 VM。按失败项修复来宾或路径后重新预检。
- **启动/Tools/IP 失败**：停止任务，确认 VM 没有锁，重新从 `Clean` 恢复；不要继续传样本。
- **WinRM 失败**：在来宾检查 `Get-Service WinRM`、`winrm enumerate winrm/config/Listener`、`Get-NetFirewallRule -Name KSwordSandbox-WinRM-HTTPS`，再从主机 `Test-NetConnection`。凭据失败时重新运行 bootstrap 轮换密码，避免把密码写进命令行。
- **样本或采集失败**：保存任务日志和报告路径；停止 VM 并回滚 `Clean`。必要时丢弃并重建 VM，不要把失败来宾继续当基线。
- **快照/锁失败**：退出占用 VMX 的 VMware UI/进程，等待 consolidation 完成；确认 powered-off 后再重试。WebUI 的失败状态必须保留原因。
- **真实 R0 失败**：先保持 `-NoR0Collector` 完成三样本链路；只有驱动、测试签名和隔离环境准备好后，才单独打开 R0 做验证。

完成三样本 Live 后，再将规则编辑器中的行为规则导入/保存，并重复一个样本确认规则变更出现在 HTML 报告中。
