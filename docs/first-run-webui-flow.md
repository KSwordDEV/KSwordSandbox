# 首次启动 WebUI 流程

发行包用户的入口是根目录 `Start-KSwordSandbox.cmd`。脚本固定工作目录，使用当前 Windows PowerShell 启动 `run.ps1 -Mode StartWebUI`，并只对这个子进程使用 `ExecutionPolicy Bypass`。

> **首次使用请选 VMware Workstation Pro。** `config/sandbox.example.json` 里的
> `virtualization.provider = HyperV` 只是为旧 profile 保留的兼容默认值，不代表推荐路径；
> 本项目当前记录的端到端 Live 验收证据来自 VMware。Hyper-V/QEMU 只在你已经有对应
> 环境时选择，并按同等标准自行验收。VMware 的完整来宾/宿主准备清单见
> `docs/vmware-first-run.md`。

## 用户路径

1. 双击启动脚本。没有仓库外 `sandbox.local.json` 时，`run.ps1` 直接启动首次设置 WebUI，不要求先运行控制台安装向导，也不会启动或修改虚拟机。
2. WebUI 进入 `/setup`，用户选择后端。VMware 路径填写 VMX、snapshot、`vmrun.exe` 和 VM 显示名；默认通信方式是 VMware Tools 自动发现地址，再用 WinRM HTTPS 连接来宾。Hyper-V 路径填写黄金 VM 和 checkpoint，使用 PowerShell Direct，不需要 WinRM；QEMU 路径填写基础磁盘、`qemu-system`/`qemu-img` 和磁盘格式，默认使用 per-job overlay 与 provider-managed user NAT，再通过 WinRM HTTPS 连接来宾。页面中的字段会随 provider 切换，下面的 VMware 前置条件只适用于 VMware Workstation Pro。
3. 点击只读预检。页面把当前表单提交到 `/api/setup/preview`；服务端用临时 profile 调用与 `/api/host/readiness?refresh=true&provider=<selected-provider>` 相同的只读探针，显示管理工具、虚拟机/磁盘、干净基线、主机加速、来宾端点和 payload 状态。预检不执行 `start`、`stop`、`revertToSnapshot`，也不会验证真实来宾登录；WinRM 登录会在 VMware/QEMU Live 启动前再次检查。
4. 保存后端。配置写入 runtime root 下的 `config\sandbox.local.json`，密码仍只从 `KSWORDBOX_GUEST_PASSWORD` 读取；页面提示重新启动 WebUI，使新配置成为运行时配置。
5. 重新启动后进入 `/` 样本选择界面。上传 `.exe` 使用 `/api/files/upload/start`，后台 runbook 按所选 provider 的顺序恢复或创建隔离基线、开机、部署 payload、运行样本、回收事件、生成报告并清理虚拟机。
6. 规则维护从导航进入 `/rules`。页面以卡片编辑规则，支持新增、删除、校验、导入导出和保存；保存后的规则会写回配置的规则文件，并立即用于后续任务。

## VMware 前置条件

当前产品不会替用户创建 Windows 10 VM、安装 VMware Tools、创建快照或配置 WinRM HTTPS。发行包向导负责发现和验证这些前置条件；用户需要先准备可丢弃的 Windows 10 guest、`SandboxUser`、WinRM HTTPS、防火墙和 powered-off clean snapshot。VMware 只支持 Workstation Pro 的 `vmType=ws` profile。

### 空白 VMware 主机的准备顺序 / Blank VMware host checklist

如果手上只有 VMware Workstation Pro 和安装介质，先在 VMware 中完成一次性准备；WebUI 不会替你创建或修改来宾：

1. 创建 Windows 10 x64 VM，给它分配可用磁盘、网络和至少 4 GB 内存；安装 VMware Tools，并确认 Tools 服务在 Windows 中运行。
2. 在来宾中创建本地管理员 `SandboxUser`，设置不会过期的密码。以管理员 PowerShell 执行 `Enable-PSRemoting -Force`，将 WinRM 设置为自动启动，并创建 WinRM HTTPS listener 和入站防火墙规则（默认端口 `5986`）。自动地址模式要求 HTTPS；自签名证书可在向导中保留“跳过证书校验”。
3. 把来宾工作目录 `C:\KSwordSandbox` 留给 Guest Agent。不要在该目录放入需要保留的文件，因为每次分析都会重新部署 payload，并在清理阶段移除任务目录。
4. 关机，在 VMware Workstation 中创建名为 `Clean`（或你在向导中填写的名称）的 powered-off snapshot。这个快照必须是样本运行前的干净基线；不要在样本已经运行后覆盖它。
5. 双击 `Start-KSwordSandbox.cmd`，填写 VMX、snapshot、`vmrun.exe`（Workstation Pro 安装目录中的 `vmrun.exe`）和 VM 显示名。来宾地址留空表示用 VMware Tools 自动发现；只有固定地址且确认可达时才选择 Configured。
6. 先保存来宾密码 secret，再运行只读预检。预检通过至少应看到 `VMWARE_QUERY_OK`、VMX 存在、目标 snapshot 存在和安全的 WinRM 配置；预检不会开机或恢复快照。任何 `VMWARE_*` 查询失败、缺少 snapshot、缺少 payload 或缺少 secret 都应先修复后再 Live。
7. 保存 profile 后重新启动 WebUI。首次页面保存到 runtime root 下的 `config\sandbox.local.json`（仓库外，但仍在 runtime root 内），当前进程不会热加载它；重启后才会进入样本选择并准备 guest payload。首次 Live 会按“恢复 Clean → 开机 → 传样本/采集 → 生成报告 → 停止 VM → 按策略恢复 Clean”的顺序执行。

如果没有 Workstation Pro、VMware Tools、WinRM HTTPS 或可用的 powered-off Clean snapshot，只能使用 WebUI 的配置/PlanOnly 检查，不能声称 Live 分析已经准备完成。

VM、快照、样本、payload、报告、驱动和密钥都留在仓库外。Sandbox 继续使用自身的 `KSwordSandboxDriver` ABI，不复制或替换其他项目的驱动。
