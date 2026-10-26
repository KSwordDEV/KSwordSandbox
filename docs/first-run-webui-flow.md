# 首次启动 WebUI 流程

发行包入口是根目录 `Start-KSwordSandbox.cmd`。它使用当前 Windows PowerShell 启动 `run.ps1 -Mode StartWebUI`。首次设置和只读预检不会启动或还原虚拟机。

> **首次使用优先选择 VMware Workstation Pro。** `config/sandbox.example.json` 的 `HyperV` 值只是旧 profile 的兼容默认。当前默认网络策略是 `Block`，破坏性样本只能在隔离虚拟机中执行，实体机严禁运行。final6 发布包已通过无网卡、无宿主共享的无害校准 Live；真实样本尚无动态成功记录。

## 目标路线与当前状态

目标是：用户在已安装 Windows 的 VM 中运行一次来宾 PowerShell 引导，在宿主选择 VMX，产品核验/建立干净基线，此后自动部署、运行、回收证据、生成中文报告并回滚。VMware `Block` 任务在样本运行前应没有虚拟网卡、没有 HGFS 宿主共享，宿主通过 VMware Tools/VIX GuestOps 操作来宾，不依赖 WinRM 地址。

**用户态无害闭环已经通过，首次准备仍需人工操作。** WebUI 已有复制完整 [`Bootstrap-VMwareGuest.ps1`](../scripts/Bootstrap-VMwareGuest.ps1) 的按钮、下载脚本、填写 VMX/快照/`vmrun.exe` 和只读预检；脚本创建管理员账户并配置 WinRM HTTPS，供显式 `Allow` 旧路线使用。默认 VMware `Block` 的正式 runbook 已使用 VIX GuestOps 部署、启动和回收，无需来宾 IP、WinRM 或 HGFS。WebUI 的 VMX 仍是文本框，快照仍需手工创建，保存后仍需重启 WebUI，因此“粘贴脚本、选择 VM 后全自动”还没有完成。

final6 发布包通过 WebUI 一键上传无害校准样本，作业 `6f6f6147-efa4-47b3-ba03-bdc1ad014d08` 的报告为 `Completed`、威胁等级“高风险”，GuestOps 同步 `completed`、退出码 0、`copyErrors=[]`，VM 已关机回滚。该结果证明当前配置下的用户态发布包无害闭环可用；“高风险”只描述该无害校准样本的报告结果。R0 驱动在当前 VM 中缺失，覆盖仍为部分；真实样本尚未动态成功。final3/4 的 VIX 20004 是 Windows PowerShell 5.1 解析清单根数组时把 13 个文件名拼为一个路径的发布产品缺陷，现已修复并由 final6 同步结果复验。final5 对齐 WebUI 的 30 MB 与 200 MB 上传限制，修复已包含在 final6。详见[部署路线审计](product-vs-lab-deployment-audit-2026-10-26.md)和[GuestOps 错误诊断](vix-20004-diagnosis-2026-10-26.md)。

## 当前 WebUI 用户路径

1. 双击 `Start-KSwordSandbox.cmd`。缺少仓库外 `sandbox.local.json` 时进入 `/setup`；此时不修改 VM。
2. 选择后端。VMware 表单目前要求手工填写 VMX、已有干净快照名、`vmrun.exe` 路径、显示名和来宾账号。Hyper-V 使用 PowerShell Direct；QEMU 使用配置的 NAT/WinRM 路线。仅 VMware 默认 `Block` 的目标通道是无网卡 GuestOps。
3. 点击只读预检。`/api/setup/preview` 检查宿主工具、VMX、已有快照、隔离配置、VIX helper 和配置字段；不会启动 VM、登录来宾、证明 GuestOps 或验证样本报告。预检结果只表示**宿主配置**是否可保存。
4. 另行在本机保存来宾密码 secret。当前 `/api/setup/guest-secret` 将其写入 Web Host 进程和当前用户环境；默认 `Block` 通过进程内 VIX 登录，避免 `vmrun -gp` 命令行暴露。
5. 保存 profile 到 runtime root 的 `config\sandbox.local.json`，重启 WebUI 后进入样本选择。PlanOnly 可检查计划；默认 VMware 用户态 `Block` 已在 final6 包通过一键上传无害校准样本的 Live。R0 与 Defender 特殊配置仍会在开机前拒绝，真实样本要逐个验收。
6. 规则维护从 `/rules` 进入；保存后的规则用于后续任务。规则变更要用真实执行证据校准，不能以公开沙箱情报代替本机观测。

## VMware `Block` 首次准备与验收门槛

以下列出目标发布路线以及尚需完成的验收。final6 的一次无害闭环已满足其中的用户态核心运行环节，不能推出全部首次设置和 R0 已自动完成。

1. 用户提供可丢弃的 Windows VM，安装 VMware Tools，在 VM 内以管理员身份运行产品提供的来宾引导 PowerShell。引导结果应机器可读，并与宿主保存的专用来宾凭据配对。当前脚本还会配置 WinRM；离线 `Block` 不得把 WinRM 当成样本阶段控制通道。
2. 宿主选择该 VMX 后识别 Workstation Pro、Tools 和来宾身份；产品创建或确认 powered-off 干净基线，并验证关闭 NIC、HGFS、USB、剪贴板、拖放、打印等宿主交互通道。原机若仍用于普通任务，应先制作专用克隆；不能只凭快照名含“NetIsolated”推断隔离。
3. 先以固定哈希的无害样本跑完整 Live：从基线启动、VIX 部署与来宾 SHA-256 复核、管理员权限 Agent 启动、网络阻断事件、原始证据回收、项目原生 `report.zh.html`、停机回滚以及再次启动后探针消失。final6 已完成 WebUI 一键上传后的无害作业、同步、报告和关机回滚；仍需固化原始证据与回滚后重启探针消失的记录，并在干净宿主/VM 复验。[无害离线探针](vmware-isolated-benign-probe.md)仍用于开发验证。
4. 再以不同机制的已核验样本逐个在隔离 VM 中实测。每份报告记录 job ID、样本哈希、VM/快照、实际启动证明、采集缺口和回滚结果。R0 驱动未安装或未签名时只声明用户态覆盖，不把缺失事件解释成样本没有行为。

[VMware 首次运行手册](vmware-first-run.md)现已描述默认零网卡 GuestOps 路线，但仍需要手工准备 VM 和干净快照。final6 的无害成功不能替代真实样本动态验收或证明 R0 完整覆盖。VM、样本、payload、报告、驱动和密钥均留在仓库外。
