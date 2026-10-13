# 首次启动 WebUI 流程

发行包用户的入口是根目录 `Start-KSwordSandbox.cmd`。脚本固定工作目录，使用当前 Windows PowerShell 启动 `run.ps1 -Mode StartWebUI`，并只对这个子进程使用 `ExecutionPolicy Bypass`。

## 用户路径

1. 双击启动脚本。没有仓库外 `sandbox.local.json` 时，`run.ps1` 直接启动首次设置 WebUI，不要求先运行控制台安装向导，也不会启动或修改虚拟机。
2. WebUI 进入 `/setup`，用户选择后端。VMware 路径填写 VMX、snapshot、`vmrun.exe` 和 VM 显示名；默认通信方式是 VMware Tools 自动发现地址，再用 WinRM HTTPS 连接来宾。
3. 点击只读预检。页面调用 `/api/setup/status` 和 `/api/host/readiness?refresh=true&provider=VMware`，显示管理工具、VMX、快照、主机加速、来宾端点和 payload 状态。预检不执行 `start`、`stop`、`revertToSnapshot`。
4. 保存后端。配置写入 runtime root 下的 `config\sandbox.local.json`，密码仍只从 `KSWORDBOX_GUEST_PASSWORD` 读取；页面提示重新启动 WebUI，使新配置成为运行时配置。
5. 重新启动后进入 `/` 样本选择界面。上传 `.exe` 使用 `/api/files/upload/start`，后台 runbook 按 VMware 顺序恢复基线、开机、部署 payload、运行样本、回收事件、生成报告并清理虚拟机。
6. 规则维护从导航进入 `/rules`。页面以卡片编辑规则，支持新增、删除、校验、导入导出和保存；保存后的规则会写回配置的规则文件，并立即用于后续任务。

## VMware 前置条件

当前产品不会替用户创建 Windows 10 VM、安装 VMware Tools、创建快照或配置 WinRM HTTPS。发行包向导负责发现和验证这些前置条件；用户需要先准备可丢弃的 Windows 10 guest、`SandboxUser`、WinRM HTTPS、防火墙和 powered-off clean snapshot。VMware 只支持 Workstation Pro 的 `vmType=ws` profile。

VM、快照、样本、payload、报告、驱动和密钥都留在仓库外。`E:\Projects\Ksword5.1` 是外部只读参考仓库；Sandbox 继续使用自身的 `KSwordSandboxDriver` ABI，不复制或替换 KswordARK 驱动。

## 当前本机状态

本机已发现 `D:\Software\Vmware\vmrun.exe`、`E:\VMs\Windows10-20H2\Windows 10 x64.vmx` 和 `纯净系统` snapshot，VMware 只读查询返回 `VMWARE_QUERY_OK`。该 VM 当前由 VMware UI 持有锁，snapshot 还需要 consolidation，因此在人工确认前不执行 Live 样本分析；WebUI、配置和 PlanOnly 可继续验证。
