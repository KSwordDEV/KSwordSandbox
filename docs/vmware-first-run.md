# VMware 首次运行：默认隔离路线

本页对应当前发布包的 `/setup` → 样本选择 → Live 流程。默认网络策略是
`Block`，首轮选择 **UserMode**。WebUI 在每次任务中自动恢复干净快照、通过
VMware Tools GuestOps 传输与启动、回收证据、关机并再次恢复快照。
发布包端到端无害 Live 尚需验收；只读预检和手工探针不能代替该结果。

## 1. 准备可丢弃的 Windows 10 VM

1. 使用 VMware Workstation Pro 创建 Windows 10 x64 虚拟机，安装 VMware Tools。
   来宾中不要放个人数据。
2. 在来宾管理员 PowerShell 中运行 `/setup` 提供的
   `Bootstrap-VMwareGuest.ps1`，创建专用 `SandboxUser` 管理员账户并设置密码。
   脚本还会配置 WinRM HTTPS，供显式 `Allow` 旧路线使用；默认 `Block`
   路线通过 VIX 登录，不依赖 WinRM。密码不要放入命令行、报告或 Git。
3. 关机后移除或禁用所有虚拟网卡，关闭 HGFS 共享、USB、声卡、串口、软驱、
   剪贴板复制粘贴和拖放。VMX 中至少要有
   `isolation.tools.copy.disable=TRUE`、`paste.disable=TRUE`、
   `dnd.disable=TRUE`，且 `sharedFolder.maxNum=0`。
4. 在**关机且隔离配置已经生效**后创建唯一干净快照，并记下名称。快照名称
   不能代替对当前 VMX 隔离状态的检查。建议先在独立克隆上验收，不将原始 VM
   直接用于破坏性样本。

## 2. 在 `/setup` 保存发布包配置

1. 启动 `Start-KSwordSandbox.cmd`，选择 VMware Workstation Pro，填写本机
   `.vmx` 完整路径、干净快照名称、`vmrun.exe` 路径、来宾用户名与工作目录。
2. 采集模式选 **UserMode**，保存专用来宾密码到页面的本机 secret 入口。
   VMware `Block` 的 R0 和 `disableDefenderForLab` 特殊路线目前会在 VM
   启动前被明确拒绝；它们需要单独实现与验收。
3. 点击只读预检。它检查 `vmrun`、VMX、快照、VMX 隔离键、随包的 VIX helper
   与离线脚本，并对 VIX runtime 做只读状态查询。没有启动或登录来宾，
   因此还不能证明凭据、VMware Tools 或 S4U 启动成功。
4. 修复红项后保存并重启 WebUI。发布包将 `vix_probe.exe` 与
   `Invoke-VmwareOfflineRunbook.ps1` 放在 `tools/vix-helper`；
   `vmware.vixHelperPath` 默认解析到该位置。缺少 VMware Workstation VIX
   runtime 或 Microsoft VC++ x64 runtime 时，预检会给出 GuestOps 错误。

默认 `Block` 路线**不需要 NAT、来宾 IP、WinRM 端口或宿主共享文件夹**。
显式 `Allow` 路线仍使用既有 WinRM 配置，需单独评估其网络和共享边界。

## 3. 用无害样本验收 Live

先提交本项目的 `KSword.Sandbox.HarmlessSample.exe`，确认运行记录中存在：

- `wait-guest-operations` 已通过，Agent 以 S4U 最高权限任务启动；
- 来宾 `networkPolicy.applied` 早于样本 `process.start`；
- `events.json`、`agent-summary.json`、`agent.exit` 和原始产物已逐文件回收；
- 同一 job 下生成 `report.json` 与中文 `report.zh.html`；
- VM 最终关机并恢复干净快照，VMX 仍无网卡、HGFS 和外设通道。

若 GuestOps、Tools 或 Agent 失败，报告必须显示采集不完整，原始已回收证据
应保留；不要把缺失事件解释为样本没有行为。只有无害闭环和回滚均通过，才
能进入真实样本批次。真实样本只允许在已核验隔离的虚拟机来宾中执行，
严禁在实体机执行。
