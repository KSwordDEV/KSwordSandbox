# VMware 与 QEMU 后端 / VMware and QEMU providers

KSwordSandbox 的宿主编排支持 `HyperV`、`VMware` 和 `Qemu` 三种 provider。该功能仍以
**Windows 宿主 + Windows guest** 为目标：VMware 使用 `vmrun`，QEMU 使用
`qemu-system-x86_64.exe`/`qemu-img.exe`；Guest Agent、R0Collector、artifact 同步和报告链路
在三种 provider 间共用。

默认 provider 仍是 `HyperV`，因此旧的 `sandbox.local.json` 不需要修改。VMware/QEMU
live run 必须在仓库外本机配置中显式选择，PlanOnly/dry-run 仍不会执行任何 VM 命令。

## 共用前提 / Common prerequisites

- 准备好的 Windows guest、干净快照/baseline、`SandboxUser` 和 staged guest payload。
- `KSWORDBOX_GUEST_PASSWORD` 只保存在宿主环境变量中，不写入 JSON。
- VMware/QEMU guest 必须启用 Windows PowerShell Remoting（WinRM）。新配置默认不要求手填
  IP：VMware 使用 `guestRemoting.addressMode=VMwareTools` 在每次恢复后调用
  `vmrun getGuestIPAddress` 并受统一 Guest readiness timeout 限制；QEMU 使用 `QemuUserNat` 建立 provider-owned localhost
  转发。`Configured` 模式保留固定 DNS/IP/自定义网络；旧配置仍可用共享的
  `guest.powerShellRemotingAddress` 作为回退。Hyper-V 继续使用 PowerShell Direct。
- 工作组环境可能需要把本地账号写成 `GUESTCOMPUTER\SandboxUser`；该值同时用于 WinRM
  `PSCredential` 和 Guest Agent 的交互式 Scheduled Task principal，必须与 baseline 中已登录账号一致。
- `VMwareTools` 和 `QemuUserNat` 自动端点模式固定使用 WinRM HTTPS：恢复后发现的 IP 和
  `127.0.0.1` 不应依赖宿主机全局 `TrustedHosts`。Golden baseline 必须预先配置 WinRM
  HTTPS listener 和防火墙规则；实验室自签名证书可保留默认
  `skipCertificateChecks=true`，使用受信任且名称匹配的证书时应改为 `false`。
- `Configured` 模式仍可使用 HTTP + Negotiate/CredSSP，但操作者必须自行确保域/Kerberos、
  DNS 或明确收敛的 `TrustedHosts` 信任。Microsoft 对 IP 地址 WinRM 的要求见
  [New-PSSession](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession?view=powershell-7.6)；
  `TrustedHosts` 的宿主级影响见
  [about_Remote_Troubleshooting](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-7.6)。
- 真实 R0 仍要求 guest test mode、本地 test-signed driver 和隔离 VM；provider 切换不会
  降低驱动签名要求。
- VMware/QEMU 的宿主 WinRM 调用不要求宿主 shell 提权，但用于 WinRM 的 guest 账号必须是
  来宾本地管理员，才能修改 test-signing、管理驱动服务和运行 Highest scheduled task。

在 Windows guest 内以管理员身份准备 WinRM：

```powershell
Enable-PSRemoting -Force
Set-Service WinRM -StartupType Automatic
```

以上命令只完成基础 remoting 准备；自动端点模式还需要在 baseline 中绑定证书并建立 HTTPS
listener。不要让 KSwordSandbox 在每次运行时修改宿主机 `TrustedHosts`。

## VMware Workstation Pro（Windows 宿主）

VMware provider 按以下顺序执行：校验 `vmrun`/VMX/快照，停止 VM，
`revertToSnapshot`，以 GUI 或 `nogui` 启动，等待 WinRM，运行共用 Guest Agent 流程，最后
hard stop。每次 `vmrun start`/`stop` 后都会在 60 秒内轮询目标 VMX 的实际运行状态；超时会
令步骤失败，不会在电源状态未收敛时继续恢复、执行或清理。完整适配固定使用 Workstation Pro
和 `vmType=ws`。旧版 `vmType=player` 配置会以
`VMWARE_WORKSTATION_PRO_REQUIRED` 失败准备度检查，不会进入 Live；这是为了保证 snapshot 生命周期、
隔离 full-clone 密码恢复和交互控制台契约与 Hyper-V 路径没有功能降级。本项目仍是 Windows-only，
不把 VMware Fusion/macOS 声明为受支持宿主。

本机配置示例：

```json
{
  "virtualization": { "provider": "VMware" },
  "vmware": {
    "vmName": "KSwordSandbox-Win10-VMware",
    "vmxPath": "D:\\VMs\\KSwordSandbox\\KSwordSandbox.vmx",
    "snapshotName": "Clean",
    "vmrunPath": "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe",
    "vmType": "ws",
    "headless": false,
    "guestRemoting": {
      "addressMode": "VMwareTools",
      "address": null,
      "authentication": "Negotiate",
      "useSsl": true,
      "port": 0,
      "skipCertificateChecks": true
    }
  },
  "guest": {
    "userName": "SandboxUser",
    "passwordSecretName": "KSWORDBOX_GUEST_PASSWORD",
    "workingDirectory": "C:\\KSwordSandbox"
  }
}
```

`VMwareTools` 自动模式要求 guest 内 VMware Tools 正常运行。Tools 只用于发现恢复后的 IP；
主运行、guest test-signing 和密码维护会一致排除 loopback、IPv6 link-local 和
`169.254.*` APIPA 地址，优先选择其余 IPv4，并在没有 IPv4 时回退到其他可路由地址。
实现不通过 `vmrun -gu/-gp` 传递密码，也不把密码放进命令行，guest 文件和命令仍通过带
`PSCredential` 的 PowerShell Remoting 会话处理。固定地址环境可改为
`"addressMode":"Configured"` 并填写 `address`。

## QEMU

QEMU 默认 `useOverlayDisk=true`：每个 job 用 `qemu-img create -f qcow2 -b ...` 创建仓库外
临时 overlay，运行后停止 QEMU 并删除该 job 的 overlay。设为 `false` 时，启动前通过
`qemu-img snapshot -a` 恢复 `snapshotName` 指定的内部快照；该模式要求基础镜像为 qcow2。
raw、vhdx 或 vmdk 基础镜像必须使用 per-job overlay。
`diskInterface` 支持 `virtio`、`ide`、`scsi`；Windows guest 必须预装所选控制器驱动。`none`
不会把 provider 管理的 `ksword-disk` 连接到可启动设备，因此在配置和准备度入口一致拒绝。

配置示例（WinRM HTTPS 通过 user-mode networking 转发到宿主 `55986`）：

```json
{
  "virtualization": { "provider": "Qemu" },
  "qemu": {
    "vmName": "KSwordSandbox-Win10-QEMU",
    "qemuSystemPath": "C:\\Program Files\\qemu\\qemu-system-x86_64.exe",
    "qemuImgPath": "C:\\Program Files\\qemu\\qemu-img.exe",
    "diskImagePath": "D:\\VMs\\KSwordSandbox\\base.qcow2",
    "diskFormat": "qcow2",
    "diskInterface": "virtio",
    "snapshotName": "Clean",
    "useOverlayDisk": true,
    "memoryMegabytes": 4096,
    "headless": false,
    "additionalArguments": ["-accel", "whpx", "-machine", "q35"],
    "guestRemoting": {
      "addressMode": "QemuUserNat",
      "address": null,
      "authentication": "Negotiate",
      "useSsl": true,
      "port": 0,
      "skipCertificateChecks": true
    }
  },
  "guest": {
    "userName": "SandboxUser",
    "passwordSecretName": "KSWORDBOX_GUEST_PASSWORD",
    "workingDirectory": "C:\\KSwordSandbox"
  }
}
```

`QemuUserNat` 会自动加入 `-netdev user,id=ksword-net,hostfwd=...` 和
`-device e1000,netdev=ksword-net`。自动模式要求 HTTPS；`port=0` 时使用宿主
`127.0.0.1:55986` 转发到 guest `5986`，也可把 `port` 设为其他宿主 HTTPS 端口。
QEMU 进程启动前会先试绑定该 loopback 端口；若仍被其他 listener 占用，会在创建 QEMU
进程前给出冲突端口和改用 `guestRemoting.port` 的修复建议。启动过程的 stdout/stderr 分别写入
当前 job runtime 目录，若 QEMU 立即退出，执行记录会附带有界的 provider 输出和 WHPX、磁盘、
固件及设备参数检查建议。
per-job overlay 的运行目标名最长 64 字符；名称过长时只截短配置前缀，完整 job ID 后缀始终保留，
因此并发任务不会因显示名截断而共享同一进程身份。
准备度探针会把 VMware/QEMU 管理命令的明确权限错误单独映射为 `AccessDenied`；QEMU 的
`Running` 状态还要求 PID、配置可执行文件、原生 PID 标记写入时间、job runtime 路径与当前
精确 `-name` 参数同时匹配；overlay 模式会按 Core 的同一规则从 pidfile 父目录重建“截断前缀 + 完整
32 位 job ID”目标名，而不是拿未截断配置名直接比较。旧 PID 被系统复用、长配置名或同一 runtime 中运行另一台受管 QEMU 时都不会把
无关进程当成当前 sandbox VM；Web、installer 和 `run.ps1` readiness 都会检查全部原生 pidfile 候选，多个实例同时匹配时返回
`QEMU_PROCESS_IDENTITY_AMBIGUOUS`，不会采用目录枚举中的第一个结果。同一进程实例校验也用于 runbook 的恢复前停止、交互窗口确认、
尾部清理、安装器 baseline 恢复和密码轮换；不匹配时保留磁盘并安全失败。
`QemuUserNat` readiness 还会只读探测 `127.0.0.1` 的有效 WinRM 转发端口；只有 PID 实例已识别且
进程命令行包含当前配置的精确 `hostfwd=tcp:127.0.0.1:<port>-:` 时，才把该占用视为下一次
baseline 操作可安全停止的 KSword QEMU listener。否则继续执行独占 bind 探测；若由其他监听器
占用，Web、`run.ps1` 和 installer 都在启动 VM 前返回 `QEMU_USER_NAT_PORT_UNAVAILABLE` 并提示更换端口。
Windows baseline 必须能驱动 `e1000`、启用对应 WinRM listener/firewall 规则。
`additionalArguments` 不得复用 `id=ksword-net`/`netdev=ksword-net`。需要完全自定义网卡和
转发时改用 `Configured`，自行提供网络参数、可达地址和端口。

`diskInterface=virtio` 要求 Windows guest 已安装 virtio storage driver；IDE 镜像可选 `ide`。
选择 `scsi` 时，provider 会创建 `virtio-scsi-pci,id=ksword-scsi`，并用
`scsi-hd,drive=ksword-disk,bus=ksword-scsi.0` 明确挂接受管磁盘；guest 必须预装对应的
virtio-scsi 驱动。`additionalArguments` 不能复用这些受管磁盘、控制器或总线标识。
`-drive` 内的 Windows 路径逗号会按 QEMU 规则转义为 `,,`，PID/command-line 归属检查同时
识别文件系统原路径和转义形式；因此磁盘或 runtime 路径含逗号时不会误解析或误判清理对象。
需要 AHCI/SATA 或其他显式控制器拓扑时，当前受管理 provider 契约不会自动挂接该拓扑；应先把
baseline 调整为受支持的 `virtio`、`ide` 或 `scsi` 启动盘，而不是通过 `none` 绕过准备度检查。
CPU、UEFI、TPM、显卡和其他非磁盘设备参数由 `additionalArguments` 明确提供，Core 不猜测具体
golden image 的硬件布局；`QemuUserNat` 的
e1000 网卡和 WinRM 转发是唯一由 provider 自动加入的网络设备。VM 名称、内存、PID 归属、
display backend 和 baseline 写入语义由 provider profile 管理。每次启动都会把
`RuntimeRoot\vms\<job>\qemu.pid` 作为原生 `-pidfile` 参数传给 QEMU，并用同一路径核对进程实例、
状态、窗口和清理归属；宿主 runner 不会覆写该文件。QEMU 未在有界时间内写入 marker、marker
PID 与刚启动进程不一致或 marker 时间不匹配时，只停止本次刚创建的进程并安全失败。因此
`-name`、`-m`/`-memory`、`-pidfile`、
`-display`、`-daemonize`、`-snapshot`、`-nographic`、`-curses`、`-S`，以及重复的
`id=ksword-disk` 会在保存配置或生成计划时被拒绝。推荐安装向导会以
JSON 字符串数组读取并持久化这些参数；脚本化安装可传入
  `-QemuMemoryMegabytes 4096 -QemuAdditionalArguments @('-accel','whpx')`。新配置默认保存
`-accel whpx`；旧配置未指定 accelerator 时，Core 也会在 runbook 中自动补齐 WHPX。
显式 `-accel tcg` 或其他 accelerator 会在计划阶段被拒绝，因为软件模拟不计作与 Hyper-V
等价的 Windows Live 体验。Windows 宿主还必须启用 Windows Hypervisor Platform
（功能名 `HypervisorPlatform`）；安装器、`run.ps1` 和 Web readiness 会读取该功能，
`Disabled`、`Absent` 或无法确认都会阻止 `LiveReady`，而不会悄悄回退到 TCG。安装器也会保存
`-VMwareHeadless`/`-QemuHeadless`；默认均为 `false`，因此 Live 会打开 VMware GUI 或 QEMU display。

## 使用入口 / Usage

- WebUI 的“虚拟化后端”下拉框可按 job 选择 provider；三种 provider 共用 VM/baseline
  操作体验，VMware 会额外显示实际 VMX 路径，QEMU 会显示实际基础磁盘和格式。这些值会
  进入任务提交与任务摘要，不只是浏览器标签。最终 `report.json` 和中英文 HTML 报告封面也会
  保存/显示有效 `TargetVmName`、`BaselineName`、VMware VMX 或 QEMU 基础磁盘，以及 QEMU
  磁盘格式。独立 PostProcess 重建报告时优先从该 job 的 execution/progress/metadata 恢复这些
  资源身份，不使用后来切换过的全局 provider profile 覆盖历史记录。对已有 job 显式传入不同
  provider 或不同的 VM/baseline/VMX/磁盘/格式会被拒绝；缺失字段仍可补，同一值仍可重申。
  完全没有 provider 字段的旧版持久化产物按历史 Hyper-V 格式恢复。这样不会把持久化资源用
  另一 provider 的标签重新解释。后台终态快照也会保留安全的
  runbook/submission 资源摘要，主界面不会在完成后退回当前全局 profile。
- 主界面和独立实时监控页对三个 provider 都显示同一个“取消分析并清理虚拟机”操作，调用
  `POST /api/jobs/{jobId}/runbook/cancel`。响应先保留 queued/running 并设置
  `cancelRequested=true`；共享 executor 完成不可取消的尾部 VM cleanup 后，后台状态才进入
  `canceled`。如果取消请求与自然完成同时发生，最终真实终态仍可为 `completed`。
- `/api/host/readiness` 对三种 provider 统一返回 `configuredBaselineName`、`baselineName`、
  `baselineSource`、`baselineExists` 和 `baselineGuidance`；旧 `snapshot*` 字段继续保留给兼容客户端。
- `install.ps1` 推荐向导和“更改虚拟化配置”菜单可配置三种 provider；`Status`/
  `CheckEnvironment` 会对当前 provider 执行只读工具、VM 定义和干净基线检查；顶层摘要与嵌套
  provider profile 都提供 `Baseline*` 字段，同时保留旧 `Checkpoint*` 字段。
- Operator CLI 可用 `readiness -Provider VMware|Qemu -Json` 调用同一套只读 provider
  `CheckEnvironment`；`-ProviderReadiness` 会从当前本机配置选择 provider。
  `-RunHyperVReadiness`/`-HyperVReadiness` 只保留给 Hyper-V 深度兼容检查，在当前 profile 为
  VMware/QEMU 时会明确拒绝并引导回 provider-neutral readiness。
- 安装器的 guest test-signing 查询/启用/禁用入口对 Hyper-V 使用 PowerShell Direct，对
  VMware/QEMU 自动复用所选 provider 的 WinRM profile；直接调用 helper 时传入相同的
  `-VirtualizationProvider` 和 `-GuestRemoting*` 参数；VMware Tools 模式还需传入
  VMX/vmrun profile；QEMU 默认按 overlay 身份匹配，内部快照 profile 需加 `-QemuInternalSnapshot`。该操作和 Hyper-V PowerShell Direct 一样要求目标 VM 已运行。QEMU
  `QemuUserNat` 在连接 loopback 前还会核对 `qemu.pid` 标记时间、进程启动时间、配置的 QEMU
  可执行文件、命令行中的原生 pidfile、job runtime、内部快照配置名或按完整 job ID 重建的 overlay VM 名称，以及精确 hostfwd 端口；无法唯一证明端口属于所选 KSword
  QEMU 实例时安全失败，不会向任意本机监听器发送来宾凭据。
- 正常的实际 guest 密码轮换对三个 provider 共用同一安装器入口。VMware/QEMU
  用当前 host secret 通过 WinRM 改密、验证并创建替换 baseline；QEMU 在不知道旧密码时
  还可把 clean baseline 离线 materialize 为临时 VHDX，注入一次性 LocalSystem 服务并创建
  替代基盘。QEMU 改密会先读取
  `RuntimeRoot\vms` 下的 `qemu.pid` ownership 标记，验证标记时间属于当前进程实例，并同时匹配
  配置可执行文件、命令行原生 pidfile 和 job runtime 后才有界停止进程。没有有效原生 pidfile
  归属标记的 runtime/受管磁盘占用一律安全失败并要求人工关闭，不会被强杀。密码维护自己启动的
  QEMU 也写入同一归属域，并在启动前对 user-NAT 端口做独占 bind 预检；停止失败时保留活动
  overlay/工作目录供人工恢复，不会继续删除。
- `POST /api/jobs/plan` 可在 `SandboxSubmission` 中传入 `"provider":"VMware"` 或
  `"provider":"Qemu"`；`goldenVmName`/`goldenSnapshotName` 选择逻辑 VM 与 baseline，
  `machineDefinitionPath` 对 VMware 表示 VMX、对 QEMU 表示基础磁盘，QEMU 还可传
  `qemuDiskFormat`。Core 会在 Web 表单、JSON API、pipeline 和首次离线导入入口统一拒绝跨
  provider 字段，也会拒绝给 QEMU per-job overlay 传入内部 snapshot baseline，避免静默忽略
  操作者输入；已有作业的离线恢复继续使用其持久化 runbook 身份。
  浏览器 live 默认通过 `/runbook/start` 提交后台 runner，并轮询
  `/runbook/background`；旧 `/runbook/execute` 只保留兼容调用。
- 安装器的 `RestoreCleanCheckpoint` 对 Hyper-V checkpoint、VMware snapshot 和 QEMU internal
  snapshot 执行受确认保护的真实恢复。QEMU per-job overlay 已天然保证下一次运行使用新干净层，
  因此同一入口返回 `BaselineRestoreSatisfiedWithoutMutation=true`，不要求变更确认，也不调用
  provider stop/restore 命令；状态中的 `BaselineIsolationMode` 为 `qemu-per-job-overlay`。
- 根安装器和 `scripts\install.ps1` 的交互向导都提供只读 provider 资源选择。VMware 可从当前
  VMX 与 `vmrun list` 的运行中候选选择 VMX，再用 `listSnapshots` 选择 baseline；QEMU 用
  `qemu-img info --output=json` 自动识别所选基础磁盘格式，并在 internal-snapshot 模式列出
  snapshot。per-job overlay 不展示无效的内部 snapshot 选择；查询失败时两者都保留手动输入。
  这些只读 provider 子进程启动前会临时清除 guest/VT secret 环境变量。
- JobTool 的 `execute` 默认 dry-run；只有 `execute --live` 才执行 VM 命令。`run.ps1
  -Mode Analyze` 与 `scripts/Invoke-OperatorCli.ps1 execute` 都委托同一 JobTool executor。
- `scripts/Invoke-HyperVE2E.ps1` 保留为 Hyper-V 兼容/E2E 专用入口，不再是日常 Analyze
  的唯一执行路径。

```powershell
# 三者均默认只生成 dry-run 记录，不修改 VM
.\run.ps1 -Mode Plan -SamplePath D:\Samples\sample.exe
.\scripts\Invoke-OperatorCli.ps1 execute -SamplePath D:\Samples\sample.exe -Provider VMware `
  -VmName KSword-VMware -SnapshotName Clean `
  -MachineDefinitionPath D:\VMs\KSword\KSword.vmx

# 显式 live；provider 默认来自 sandbox.local.json，也可由 JobTool/wrapper 覆写
.\run.ps1 -Mode Analyze -SamplePath D:\Samples\sample.exe -Provider VMware -Live
.\scripts\Invoke-OperatorCli.ps1 execute -SamplePath D:\Samples\sample.exe -Provider Qemu `
  -VmName KSword-QEMU `
  -MachineDefinitionPath D:\VMs\KSword\base.qcow2 -QemuDiskFormat qcow2 -Live

# Web API E2E 默认走与浏览器一致的后台 /runbook/start -> /runbook/background 主路径，
# summary 保留 executionTransport、backgroundState、guest import 三态、所选 provider 的
# 只读宿主加速/readiness 证据，并核对终态 provider、VM、基线、VMX/磁盘身份；仅兼容旧工具时使用
# -ExecutionTransport Blocking
# 发布等价声明：三条命令使用同一样本/时长，拒绝 dirty source，并分别写入 summary。
.\scripts\Invoke-WebUIApiE2E.ps1 -BaseUrl http://127.0.0.1:18082 -Provider HyperV `
  -SamplePath D:\Samples\same-sample.exe -Live -RequireCleanSource -DurationSeconds 5 `
  -SummaryPath D:\Temp\KSwordSandbox\parity\hyperv-summary.json
.\scripts\Invoke-WebUIApiE2E.ps1 -BaseUrl http://127.0.0.1:18082 -Provider VMware `
  -SamplePath D:\Samples\same-sample.exe -VmName KSword-VMware -BaselineName Clean `
  -MachineDefinitionPath D:\VMs\KSword\KSword.vmx -Live -RequireCleanSource -DurationSeconds 5 `
  -SummaryPath D:\Temp\KSwordSandbox\parity\vmware-summary.json
.\scripts\Invoke-WebUIApiE2E.ps1 -BaseUrl http://127.0.0.1:18082 -Provider Qemu `
  -SamplePath D:\Samples\same-sample.exe `
  -VmName KSword-QEMU -BaselineName per-job-overlay -MachineDefinitionPath D:\VMs\KSword\base.qcow2 `
  -QemuDiskFormat qcow2 -Live -RequireCleanSource -DurationSeconds 5 `
  -SummaryPath D:\Temp\KSwordSandbox\parity\qemu-summary.json

.\scripts\Test-ProviderParityEvidence.ps1 `
  -HyperVSummaryPath D:\Temp\KSwordSandbox\parity\hyperv-summary.json `
  -VMwareSummaryPath D:\Temp\KSwordSandbox\parity\vmware-summary.json `
  -QemuSummaryPath D:\Temp\KSwordSandbox\parity\qemu-summary.json `
  -OutputPath D:\Temp\KSwordSandbox\parity\provider-parity-validation.json

# 脚本化保存 provider profile；默认仍不创建、启动或恢复 VM
.\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider VMware `
  -VmName KSword-VMware -CheckpointName Clean -VMwareVmxPath D:\VMs\KSword\KSword.vmx `
  -GuestRemotingAddressMode VMwareTools -GuestRemotingUseSsl -GuestRemotingSkipCertificateChecks
.\install.ps1 -Mode Change -UpdateVirtualizationConfig -VirtualizationProvider Qemu `
  -VmName KSword-QEMU -QemuDiskImagePath D:\VMs\KSword\base.qcow2 `
  -QemuMemoryMegabytes 4096 -QemuUseOverlayDisk $true `
  -GuestRemotingAddressMode QemuUserNat -GuestRemotingUseSsl -GuestRemotingSkipCertificateChecks

# 查询/修改 guest test-signing；安装器复用当前 provider profile
.\install.ps1 -Mode Change -VirtualizationProvider Qemu -QueryGuestTestSigning
.\install.ps1 -Mode Change -VirtualizationProvider VMware -EnableGuestTestSigning -Force
```

每个 live runbook 都先执行 provider preflight。VMware 会校验快照清单；QEMU 两种模式都会通过
`qemu-img info --output=json` 校验 base image 可读且实际格式与 `diskFormat` 一致，内部快照模式还会
校验 snapshot。任何 preflight 失败都发生在 baseline 修改、样本复制和执行前。
非 headless Live 在 provider 启动成功后还会有界地等待可见窗口：VMware 检查
`vmware.exe` 主窗口，QEMU 检查当前 VM 进程的 display 窗口。命令返回成功但
未观察到窗口时会失败并进入通用 cleanup，不会在无操作者桌面的情况下继续执行样本。

`analysis.guestReadyTimeoutSeconds`（CLI 为 `-GuestReadyTimeoutSeconds` /
`--guest-ready-timeout-seconds`）统一控制三种 provider 建立 PowerShell Direct/WinRM 会话的等待上限。
安装器同样接受 `-GuestReadyTimeoutSeconds`；旧参数名 `-PowerShellDirectTimeoutSeconds` 为兼容
现有脚本继续可用，二者设置的是同一个三 provider 来宾就绪超时。
它与单个 runbook step 的 `StepTimeoutSeconds` 独立，后者应不小于前者。

## 来宾密码轮换 / Guest password rotation

VMware/QEMU 与 Hyper-V 使用同一个安装器命令：

```powershell
.\install.ps1 -Mode Change -ResetGuestVmPassword -PromptPassword -Force
```

VMware/QEMU 的普通轮换要求当前 host secret 能登录旧 baseline。安装器恢复旧 baseline、通过 WinRM 修改并
验证密码，然后创建带时间戳的新 snapshot 或独立 QEMU 基盘；旧 snapshot/base image 保留。
只有新 baseline 创建成功后才切换本机 provider config 和 host secret，提交失败会恢复原本机
元数据。新密码只通过临时 Process 环境变量传给子进程，不进入命令行、日志或 JSON。
子脚本在读取密码后、启动 provider 工具前会清空它自身的两个密码环境变量，并清理
`KSWORDBOX_*` 和常见 password/secret/token/API key/credential 变量，避免
`vmrun`/`qemu-system`/`qemu-img` 继承宿主 secret。
QEMU 或 VMware Workstation Pro 当前 secret 已无法登录时，可在管理员 PowerShell 使用同一个入口并显式选择离线恢复：

```powershell
.\install.ps1 -Mode Change `
  -VirtualizationProvider Qemu `
  -ResetGuestVmPassword `
  -RecoverGuestVmPasswordWithoutCurrentSecret `
  -GeneratePassword `
  -Force

.\install.ps1 -Mode Change `
  -VirtualizationProvider VMware `
  -VMwareVmType ws `
  -ResetGuestVmPassword `
  -RecoverGuestVmPasswordWithoutCurrentSecret `
  -GeneratePassword `
  -Force
```

该流程先停止通过 `RuntimeRoot\vms\**\qemu.pid` 证明归属的 QEMU 进程；overlay 模式从基础磁盘、
内部 snapshot 模式从指定 qcow2 snapshot 转换出临时 VHDX。离线注入后再转为独立替代磁盘，启动
QEMU 并用新 WinRM 凭据验证，成功后才提交磁盘/snapshot 配置和 host secret。临时 VHDX 与失败的
替代磁盘会清理，旧 baseline 不修改。状态对象将 QEMU 报告为
`offline-vhdx-and-replacement-disk`。

新凭据首次连通后，宿主还会通过 WinRM 读取本次 one-shot reset result，重复删除重置 service，
并确认含新密码的注入脚本已经不存在；这一步未确认时不会关机、创建 snapshot 或提交 replacement baseline。

VMware Workstation Pro 路径要求 `vmrun -T ws` 的 full-clone 能力和 `qemu-img`。它从关机态 clean
snapshot 创建独立 clone，拒绝携带 `checkpoint.vmState` 的内存 snapshot，并且只接受恰好一个
VMDK disk reference 的 VMX；clone VMDK 经临时 VHDX
注入后替换到 clone VMX，启动并验证新凭据，再创建新 snapshot。成功时安装器原子切换
`VMwareVmxPath`/snapshot/host secret；失败时停止并删除未提交 clone，原 VMX、原 snapshot tree
和原 VMDK 不修改。状态模式为 `offline-vhdx-full-clone-replacement-vmx`。VMware Player 的
旧配置不再作为受支持 provider profile；请安装 Workstation Pro、把 `vmware.vmType` 改为 `ws`，
再重新运行准备度检查。系统不会用文本复制 VMX 冒充安全 clone，也不会把缺少 full-clone 恢复契约
的环境报告为与 Hyper-V 等价。

实现所依赖的磁盘转换和 clone 语义见
[QEMU `qemu-img` 官方文档](https://www.qemu.org/docs/master/tools/qemu-img.html)、
[QEMU disk image formats](https://www.qemu.org/docs/master/system/images) 和
[VMware Workstation Pro `vmrun` 命令表](https://techdocs2-prod.adobecqms.net/content/dam/broadcom/techdocs/us/en/pdf/vmware/desktop-hypervisors/workstation/vmware-workstation-pro-17-0.pdf)。
Broadcom 已[弃用免费的 Player edition](https://knowledge.broadcom.com/external/article?articleNumber=315642)，
当前提供[免费的 Workstation Pro 许可与下载说明](https://knowledge.broadcom.com/external/article/368667/download-and-license-vmware-desktop-hype.html)，
旧 Player 主机可按[官方迁移说明](https://knowledge.broadcom.com/external/article/367660/migrating-from-player-edition-to-pro-edi.html)
升级后继续使用原有 VM。

三个 provider 都通过已登录 guest 用户的 `Interactive` Scheduled Task 启动 Guest Agent，
WinRM/PowerShell Direct 只负责编排和文件同步，GUI 样本由 Agent 以正常窗口启动。干净 baseline
必须已经配置该用户自动登录，或在 Live 前保持其桌面登录；否则 `run-agent` 会在 30 秒内给出
明确错误。`-NoOpenVmConsole` 只关闭宿主侧 VM 显示窗口，仍要求 guest 内存在已登录的交互会话。

## 安全边界 / Safety boundaries

- 不要把 `.vmx`、`.vmdk`、`.qcow2`、overlay、快照或样本提交到 git。
- QEMU/VMware 默认路径必须来自受控本机配置，或由本机 WebUI/API/CLI 操作者作为显式
  per-job override 提交；路径不会从样本内容、guest 输出或远端报告推断。`additionalArguments`
  视为受信任的操作者输入。
  即使如此，Core、安装器、运行状态和密码轮换 helper 仍会拒绝能绕过 QEMU 生命周期、baseline、
  PID ownership 或交互控制台契约的参数。
- VMware/QEMU 宿主生命周期 step 在启动 `vmrun`/`qemu-system`/`qemu-img` 前会从该 step
  的 Process 环境删除自定义 guest secret、`KSWORDBOX_*` 以及名称明显属于
  password/secret/token/API key/credential 的变量；后续 WinRM step 使用独立 PowerShell 进程重新读取。
- 共用 runbook executor 在每个 PowerShell step 创建前会先删除从 WebUI/CLI 继承的敏感环境
  变量，再只加回该 run 显式提供的 guest secret；JobTool 和 WebUI 使用同一契约。
- 来宾 step 读取 secret 并构造 `SecureString`/`PSCredential` 后会立即删除它自身的
  Process 环境变量，并清空明文字符串/字符临时变量；PowerShell Direct 和 WinRM 使用相同内存生命周期。
- WebUI 的只读 provider readiness 在启动 `vmrun`/`qemu-img` 或 Hyper-V inventory PowerShell
  前也会在 `ProcessStartInfo` 中删除同类 secret，不会把 Web Host 凭据交给探测工具。
- Web job list/detail、plan、upload/start、guest import、同步 execute 和 background endpoint
  统一经过显式安全投影；runbook 只返回步骤 ID/标题/状态属性，execution 只返回聚合状态、
  退出码和时间。完整 PowerShell、stdout/stderr 仅保留在宿主机本地 `runbook.json`、
  `runbook-execution.json` 和 `job-metadata.json`；artifact index 对这些文件返回 unavailable
  download contract，直接下载 selector 返回 `403 host-local-sensitive-runbook-evidence`，不会进入实时页。
- `install.ps1`/`run.ps1` 的 provider 状态查询，以及安装器显式确认后的 VMware/QEMU baseline
  恢复命令，也会在启动原生工具前暂时清空敏感 Process 环境，并在命令结束后原样恢复；
  provider 工具不会因入口不同而继承 guest/VT secret。
- WebUI、`install.ps1` 与 `run.ps1` 都用 provider-neutral 宿主能力契约只读检查 Windows、
  `VirtualizationFirmwareEnabled`、`HypervisorPresent`、SLAT/EPT/NPT 和 VM monitor extensions。
  契约同时报告 `RequiredWindowsFeature`、`RequiredWindowsFeatureState` 和
  `RequiredWindowsFeatureReady`：Hyper-V 要求 `Microsoft-Hyper-V-All`，QEMU/WHPX 要求
  `HypervisorPlatform`，VMware 不要求固定功能。只有固件虚拟化（或系统已检测到运行中的
  hypervisor）、SLAT 与 provider 功能依赖都明确满足才确认
  `HardwareAccelerationReady=true`；`false` 或未知都不会声明
  `LiveReady`。QEMU 的等价体验以 WHPX 硬件加速为目标，不把 TCG 软件模拟当作 Hyper-V 等价。
- WebUI、安装器和 `run.ps1` 统一区分 provider 管理工具存在、查询是否成功、权限是否拒绝、
  VM/baseline 是否存在。Web readiness 在 `virtualization` 下返回 `querySucceeded`、
  `accessDenied` 和 `diagnosticCode`；安装器/`run.ps1` 顶层对应
  `ProviderQueryAttempted`、`ProviderQuerySucceeded`、`ProviderAccessDenied`、`ProviderDiagnosticCode` 和
  `ProviderDiagnosticMessage`。查询失败阻断 Live，但不会伪装成 `MissingConfiguredVm` 或
  `MissingConfiguredBaseline`。
- QEMU 在 baseline 恢复前扫描受控 runtime PID 标记和配置磁盘，只有 PID、进程名、进程启动时间、
  标记写入时间、命令行与 runtime 路径或配置磁盘一致时才按标记停止；身份无法确认时中止恢复。
  尾部清理同样只允许由原生 `qemu.pid` 标记确认的同一进程实例自动停止；若标记缺失但仍发现匹配当前
  job VM 和磁盘的进程，则不会自动终止，并保留 overlay 与运行目录供操作员处理。只有确认目标进程已
  退出或不存在后才写入 `qemu.stop-confirmed`；即使主步骤已失败且 executor 继续后续 cleanup，删除步骤
  看不到该标记也会保留 overlay 与运行目录。
- `QemuUserNat` 只把 WinRM 映射到 `127.0.0.1`，不等于限制 guest 的全部出站网络；其他
  网络可达性仍由实验室网络负责。不要让恶意样本 guest 直接进入办公网络或公网。
- VMware/QEMU 的 Basic WinRM 只允许 HTTPS；Basic+HTTP 会在安装、状态、Web readiness、
  runbook 和 guest test-signing 入口一致拒绝。`skipCertificateChecks` 也只允许与 HTTPS
  同时使用；它适合受控实验室自签名证书，不应成为办公网络的默认配置。
- `VMwareTools`/`QemuUserNat` 自动端点同样只允许 HTTPS；安装器不会为这些动态 IP/loopback
  地址修改宿主机全局 `TrustedHosts`。显式自动 HTTP 配置会在安装、状态、Web readiness、
  runbook、密码轮换和 test-signing 入口一致拒绝。

## Windows 等价验收矩阵 / Windows parity acceptance matrix

以下矩阵必须分别在 Hyper-V、VMware Workstation Pro（`vmType=ws`）和 QEMU WHPX 的 Windows
宿主/guest 实验环境中通过。
每一行保存 job id、provider、时间、样本 SHA-256/字节数、请求时长、`runbook-execution.json` 和最终 `report.json` 路径；
缺少某个 provider 的 live 记录时，只能称为“实现完成、待该 provider live 验收”。

| 验收项 | 三个 provider 的共同通过标准 |
| --- | --- |
| 安装/状态 | 两个安装入口都用 provider 原生只读查询提供 VM/VMX/磁盘与 baseline 选择，失败时可手填；向导保存 provider 配置；Status 以同一契约只读发现 Windows/固件虚拟化/SLAT、管理工具、VM 定义、baseline、secret presence 和共享 live lease 路径/范围，不打印 secret、不探测性占锁；能力未知时不声明 Live-ready |
| 默认安全 | Plan/Analyze 不加 Live 时 VM 状态、磁盘和 snapshot 不变化，execution mode 为 DryRun |
| baseline | Hyper-V/VMware Workstation Pro 恢复 `Clean`；QEMU 恢复内部 snapshot 或创建独立 per-job overlay |
| 可视操作 | 默认的 `open-vm-desktop` 步骤确认 VMConnect/RDP、VMware GUI 或 QEMU display 窗口存在；`-NoOpenVmConsole` 三者均无界面 |
| guest transport | Hyper-V PowerShell Direct、VMware Tools 自动发现 + WinRM HTTPS、QEMU provider-owned user-NAT + WinRM HTTPS 分别在超时内建立，且自动模式不修改/依赖宿主 `TrustedHosts`；`Configured` 也可用，失败信息指出 transport/mode/source/address |
| provider 证据 | plan、progress、background snapshot、execution result 和 host runbook events 均记录相同 provider；事件前缀分别为 `hyperv`、`vmware`、`qemu` |
| payload/sample | Agent、可选 R0Collector/driver 和样本进入相同 guest 目录，路径校验通过 |
| 分析/同步 | Agent 有界执行；host 周期同步输出；`events.json`、`agent.pid`、`agent.exit` 完整 |
| R0 | mock/disabled 路径一致；真实 R0 均执行相同 driver service、device 和 JSONL 导入逻辑 |
| test-signing | 安装器通过 PowerShell Direct 或 provider WinRM profile 查询/启用/禁用 guest test-signing，不在命令行暴露密码；QEMU user-NAT 必须先用 PID 标记、进程启动时间、可执行文件、原生 pidfile、VM/job 身份和 hostfwd 端口证明 loopback listener 归属 |
| guest 密码 | 同一安装器入口完成实际账号改密、凭据验证、替换 baseline 和 host secret/config 同步；旧 baseline 保留，输出不含密码 |
| 报告/证据 | guest import 后状态 Completed；四份报告与 artifact index 生成，关键事件/证据数量非零；JSON 和 HTML 封面中的 provider、实际 VM、baseline、VMX/QEMU 基础磁盘与格式和 execution 记录一致 |
| 失败清理 | 任一步失败、Ctrl+C 或 Web“取消分析并清理虚拟机”后仍执行当前及后续 stop/cleanup；Web 先显示 cancelRequested，cleanup 返回后才显示 Canceled；取消终态在 CLI、Web progress 和重启恢复后保持 Canceled，cleanup 失败另行附加；QEMU 启动、状态、桌面验证和清理共同使用原生 `-pidfile` 身份，只停止由配置可执行文件、runtime pidfile、VM/磁盘与进程启动时间共同归属的旧进程，外部/歧义进程不会被终止，停止失败时保留活动 overlay/PID 目录并安全失败 |
| live 并发 | 同一 runtime root 的首个 Web/CLI live job 或 installer baseline/password/test-signing maintenance 在所有 provider 上独占 `locks\live-execution.lock` 直至 cleanup/rollback/config-secret commit 完成；竞争者在任何 restore/start/磁盘 mutation 前失败；dry-run/WhatIf 不受 lease 影响 |
| 可重复性 | 连续两次 live 都从同一 baseline 开始，不继承前一 job 的样本、输出或进程 |
| 启动诊断 | provider 启动失败时保留可操作原因；QEMU 正常 Live 与密码维护的 user-NAT 端口冲突都在创建进程前失败，立即退出时记录有界 stdout/stderr，并指向 WHPX、磁盘、固件和设备参数 |
| 隐私 | CLI 输出使用 safe step contract；基础 job、plan、upload/start、import、execute、background API 统一使用显式安全投影；UI 不读取或展示完整 runbook 命令/stdout/stderr；密码、token 和原始执行流只留在各自受控本机来源，CLI JSON 保持 `secretValuePrinted=false` |

推荐验收顺序：先为每个 provider 运行 `-NoR0Collector` 的 harmless sample，再运行 mock
R0，最后才在隔离环境中运行 test-signed 真实 R0。三者使用相同样本、时长和 artifact
选项，便于比较步骤状态、事件数、报告状态和清理结果。最终必须由
`Test-ProviderParityEvidence.ps1` 生成 `schema=ksword.provider-parity-evidence.v1`、
`validated=true` 的聚合 JSON；该脚本会回读执行记录与 `report.json`，核对 commit、样本字节、
时长、provider 资源身份、Completed 报告和三个不同 job id，并记录每份 summary 与引用证据文件的 SHA-256。

本次实现只完成源码与静态契约收口，未生成上述 Windows live 证据。VMware/QEMU 在对应
Windows 实验室完成整张矩阵前，不应在发布说明中声明已完成运行时等价验收。
