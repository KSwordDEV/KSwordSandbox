# 虚拟机网络策略（network policy）

## 语义

- 任务开始时可选择虚拟机网络策略：`Block`（阻断，默认）或 `Allow`（允许）。
- 默认值是 `Block`：未显式选择的旧 API 客户端、旧配置文件、直接命令行调用
  Guest Agent 的场景，一律按阻断处理，绝不静默放行。

## 实现边界

阻断在**客户机内**分两层实现，样本启动前应用，并一直保留到宿主机关闭和还原虚拟机：

1. **主阻断（设备层）**：Guest Agent 先 `Get-NetAdapter` 快照当前启用的网卡
   （记录 `Name` / `InterfaceGuid` / `PnPDeviceID`，恢复按 InterfaceGuid 精确匹配），
   然后 `Disable-NetAdapter` 直接禁用网卡设备；该路径失败时降级为等价的
   PnP 设备禁用（`Disable-PnpDevice -InstanceId <PnPDeviceID>`）。
   设备层阻断不依赖 Windows Firewall，样本即使修改防火墙规则（加放行规则、
   关防火墙）也无法恢复网络连通。
2. **第二层（防火墙层）**：`netsh advfirewall` 添加 KSword 前缀命名的入向/出向
   block 规则。防火墙可被样本改动，因此只作为冗余层，不承担主阻断职责。

- Guest Agent 不修改虚拟交换机、VMX 或 QEMU 网络参数；`networkPolicy.*`
  事件带 `hypervisorNetworkConfigChanged=false`。宿主 runbook 对 VMware 的
  `Block` 任务另行检查 VMX：所有虚拟网卡必须已被移除或禁用，且不得有宿主
  共享文件夹。Hyper-V 的 `Block` 任务在启动 VM 前断开所有虚拟网卡与交换机
  的连接，并再次查询确认；临时 VM 创建时也不指定交换机。
- Guest Agent 需要管理员权限执行禁用与 netsh（现有 scheduled task 以
  `RunLevel Highest` 启动，已满足）。

## 通道矩阵（policy=Block）

设备层阻断会切断客户机网络，证据回传通道必须不依赖 guest 网络：

| 虚拟化 + 通道 | 阻断时可用性 | 处理 |
| --- | --- | --- |
| VMware + VMware Tools guest operations | 不依赖 guest TCP/WinRM，也不发布宿主目录 | 用户态 `Block` runbook 已接通 VIX GuestOps 的准备、启动和回收；发布包无害 Live 仍待验证。R0/Defender 特殊配置在开机前拒绝 |
| VMware + HGFS 共享目录 | 会向潜在恶意来宾暴露宿主可写目录 | `Block` 时禁止；仅保留给明确允许联网的既有任务 |
| Hyper-V（PowerShell Direct） | PS Direct 走 VMBus，不经过 guest NIC | 启动前断开 VM 虚拟网卡，仍可使用 PS Direct 回收证据 |
| QEMU（localhost WinRM 转发） | 失联：guest remoting 依赖 guest 网络 | `VirtualizationProviderResourceValidator` 在应用阻断前拒绝，要求改选 `Allow` 或换 Hyper-V / VMware |

即：应用阻断前主机侧必须检测证据通道是否依赖 guest 网络；QEMU 拒绝该组合，
VMware 通过 VMware Tools guest operations 准备来宾、S4U 启动 Agent 并回收证据，
同时检查 VMX 隔离配置。`vmware-offline-prelaunch-gate` 在 VM 变动前核对
UserMode 配置、VIX helper、离线脚本、Agent payload 和样本哈希。
当前正式路线已通过静态计划/解析与无害传输探针，尚未完成发布包端到端无害 Live。
VMware Tools 若被样本破坏，会保留已拉取的部分证据并报告采集不完整。

## 失败关闭（fail-closed）

- 阻断申请（网卡禁用、PnP 降级禁用、防火墙开启、规则添加）任一失败时，
  Guest Agent 记录 `networkPolicy.apply_failed` 事件并以非零退出，样本**不会**
  在无保护状态下运行；runbook 相应步骤失败，任务不会被记为成功。
- Agent 即使在样本主进程退出后，也不恢复 `Block` 的客户机网卡或防火墙规则。
  后台子进程仍可能活动，阻断会覆盖最终证据回收阶段；宿主 runbook 随后强制
  停止 VM 并还原基线。若这一步失败，必须将任务视为清理失败并人工核实 VM
  已关闭，不能将仍运行的 VM 当作完成的隔离任务。

## 事件

| 事件类型 | 含义 |
| --- | --- |
| `networkPolicy.applied` | 设备层禁用 + 防火墙规则已在客户机内生效 |
| `networkPolicy.apply_failed` | 阻断失败，任务按失败关闭处理（非零退出） |
| `networkPolicy.retained_until_vm_stop` | Agent 保留 Block 状态，等待宿主关机和基线还原；此事件本身不是 VM 已停止的证明 |

`GuestNetworkPolicyGuard.RestoreAsync` 仅供明确的人工恢复流程使用，不在
恶意样本分析任务的 Agent 收尾阶段调用。

以上事件均带 `behaviorCounted=false`、`nonbehavior=true`、
`collectionNoise=true`、`mechanism=net-adapter-or-pnp-device-disable+windows-firewall`，
不会计入样本网络行为统计。`agent.start` 事件的 `networkPolicy` 字段记录本次
策略（Block/Allow）。

## 与采集通道的相互作用

- 阻断只影响真实连通性；样本的连接尝试仍由 R0 驱动、ETW、TCP 快照等
  通道记录，PCAP 中可见被丢弃的尝试包。
- Hyper-V 走 PowerShell Direct（不走 guest TCP），阻断不影响宿主↔客户机
  控制通道。
- VMware 的 `Block` 通道在样本启动后不依赖 WinRM：宿主通过 VMware Tools
  guest operations 请求来宾列出作业输出，再逐文件拉取。宿主只接收文件，不让
  来宾看到宿主路径；恶意样本仍可能篡改来宾产物或终止 VMware Tools，因此报告
  中的退出状态只是来宾提供的证据，不是独立可信的证明。
- 当前实现对单个任务限制 20,000 个文件、单文件 16 GiB、声明总量 64 GiB，
  并检查来宾清单的路径穿越与宿主重解析点。超过上限会停止复制并报告失败。
- 正式 VMware `Block` 路线与独立[无害离线探针](vmware-isolated-benign-probe.md)
  都使用 VIX 进程内登录；密码不进入 `vmrun -gp` 命令行。密码仍短暂存在于宿主
  进程环境与 helper 内存中，因此应使用专用来宾凭据并按批次轮换。

## 配置与提交面

- 配置默认值：`guest.networkPolicy`（config/sandbox.example.json 中为
  `Block`）。
- 每任务覆盖：提交体 `networkPolicy: "Block" | "Allow"`（可空，空=沿用配置
  默认）；WebUI 在「本次任务：虚拟机运行配置 → Guest 任务配置」提供选择器，
  默认阻断，选择允许时任务摘要与就绪 chips 会以 warn 态标出。
- runbook 向 Guest Agent 显式传 `--network-policy block|allow`；Guest Agent
  对无法识别的值直接报错，避免拼写错误静默降级为放行。
