# 提取结果与阐述摘要

## 用途

本文把已经提取和调研出的结论整理成一份可直接用于项目阐述的摘要。
它不替代详细设计文档，而是把“为什么这样做、当前做到了哪里、后续还
需要补什么”串成一条清晰主线。

相关详细文档：

- `docs/microstep-report-benchmark.md`：微步风格沙箱报告结构提取结果。
- `docs/research-basis.md`：外部系统、MITRE、Hyper-V、R0 回调等设计依据。
- `docs/hyperv-runner.md`：Hyper-V runbook dry-run/live 执行边界。
- `docs/guest-agent.md`：Guest Agent 当前事件覆盖范围。
- `docs/report-schema.md`：JSON/HTML 报告结构。

## 总体结论

KSwordSandbox 当前已经形成一条可演进的 Windows 沙箱主链路：

1. Host WebUI/API 接收样本路径、目录扫描结果或上传的 `.exe`。
2. Core 层生成分析 Job、样本身份、静态分析摘要和 Hyper-V runbook。
3. Hyper-V runner 默认 dry-run 记录操作步骤，live 模式显式执行。
4. Guest Agent 在虚拟机内运行样本并输出标准化事件 JSON。
5. Rule Engine 将静态和动态证据映射为行为命中和 MITRE 技术。
6. Report Renderer 生成本地 `report.json` 和 `report.html`。

这条链路已经具备“从样本到报告”的工程骨架。当前还没有把真实 Hyper-V
执行、Guest 输出导入、报告再生成、R0 事件桥接完整打通到稳定可用阶段。

## 微步报告提取结果

本地参考报告体现的是典型情报/沙箱报告组织方式，核心结构为：

1. 封面：报告编号、样本名、SHA-256、大小、类型、分析环境、最终判定。
2. 目录：行为检测、多维检测、引擎检测、静态分析、动态分析等章节。
3. 风险摘要：高危/可疑/通用行为、MITRE 命中数量、规则命中数量。
4. 静态分析：哈希、Magic 类型、PE 元数据、节区、字符串、URL、标签。
5. 动态分析：执行流程、进程详情、截图、文件行为、网络行为。
6. 失败信息：分析失败、超时、执行异常、数据缺失等原因。

对 KSwordSandbox 的直接要求是：报告不能只列原始事件，还要先给出风险
摘要，再把证据按行为类别展开，并且必须显式展示失败原因。

## 当前报告映射

当前实现已经对齐的部分：

- 样本身份：文件名、路径、大小、SHA-256。
- 静态分析：轻量 PE 元数据、节区熵、字符串和 URL 提取。
- 动态事件：进程启动/退出/超时、新进程差异、文件差异、TCP 差异。
- 行为规则：支持事件字段匹配、`dataContains`、MITRE 技术字段。
- HTML 报告：封面、目录、风险摘要、行为命中、MITRE、静态、动态、
  进程、落地文件、网络、失败原因和原始事件区块。

后续需要增强的部分：

- Guest 输出导入后自动重新生成最终报告。
- 真实 Hyper-V live 执行后的结果持久化和状态展示。
- 截图、DNS/HTTP/TLS、注册表、系统范围文件行为和进程树归因。
- Yara 扫描、导入表、导出表、TLS 回调、更多 PE 异常标签。
- 报告可视化细节，例如证据折叠、风险分组导航和执行流程图。

## 行为规则提取结果

短期可以稳定落地的规则来自三类证据。

### 静态证据

- PE 节区高熵。
- UPX 或类似加壳节名。
- 可疑 URL、IP、命令行字符串。
- 入口点、节区大小或节名异常。
- 可疑 API/导入表特征，后续扩展。

### Guest Agent 证据

- `process.start`：样本进程启动。
- `process.timeout`：样本运行超过分析时长。
- `process.new`：样本运行后新增进程。
- `file.created` / `file.modified` / `file.deleted`：样本工作目录下文件变化。
- `network.tcp`：运行前后新增 TCP 连接。

### R0/Driver 证据

- 系统范围文件创建、修改、删除、重命名。
- 注册表创建、设置、删除，尤其是启动项和服务项。
- 进程、线程、镜像加载回调。
- WFP 网络流量和连接归因。

短期规则以“可解释、可展示”为主，不追求一次覆盖全部恶意行为。先把每
条规则的证据链展示清楚，再逐步增加覆盖面。

## R0 复用边界

R0 方向的结论是复用协议、边界和少量客户端逻辑，不把旧项目整体复制进
当前仓库，也不提交驱动二进制、证书、样本或构建产物。

建议复用/参考的旧项目边界：

- `D:\Projects\Ksword5.1\shared\driver\KswordArkFileMonitorIoctl.h`
- `D:\Projects\Ksword5.1\Ksword5.1\Ksword5.1\ArkDriverClient\ArkDriverClient.*`
- `ArkDriverFile.cpp` 中的 file monitor drain 思路。
- `KswordArkNetworkIoctl.h` 中的 TCP/UDP endpoint snapshot 协议。
- process/thread/image/registry callback 相关头文件，用于后续结构化事件。

推荐下一步是新增 guest-side `R0Collector.exe`：

1. 运行在分析 VM 内。
2. 通过现有驱动 IOCTL 拉取文件、网络、注册表、进程等事件。
3. 输出 `SandboxEvent` 兼容 JSON Lines。
4. 由 Guest Agent 的 `--driver-events` 参数合并进 `events.json`。

这样可以保持当前 Core/Web/Report 不变，只把 R0 能力作为事件来源增强。

## Hyper-V 执行链路结论

当前 runbook 设计已经把危险操作和普通规划区分开：

- 默认 dry-run：只生成和记录 PowerShell 步骤，不启动 VM、不复制文件、
  不执行样本。
- 显式 live：逐步执行 Hyper-V/PowerShell Direct 命令，记录 stdout、
  stderr、退出码和耗时。
- live 需要管理员权限、已注册黄金 VM、干净检查点、可用 guest 凭据和
  可运行的 Guest Agent。

需要补齐的关键工程点：

1. 持久化 `runbook-execution.json`。
2. 从 host 收集目录导入 guest `events.json`。
3. 重新跑 Rule Engine。
4. 重新生成 `report.json` / `report.html`。
5. 在 WebUI 展示执行结果、失败步骤和最终报告入口。

## 当前项目状态

已经完成：

- 项目骨架、解决方案、Web/Core/Abstractions/Guest/SmokeTests 分层。
- 仓库策略，阻止 VM、样本、报告、二进制、证书和大文件入库。
- 样本哈希、轻量静态分析、规则引擎和 HTML 报告。
- WebUI 路径规划、目录 `.exe` 扫描和直接 `.exe` 上传。
- Hyper-V runbook 生成和 dry-run/live 执行入口。
- Guest Agent 基础动态事件采集和 driver JSONL 合并入口。
- 文档化的黄金 VM、驱动签名、报告结构和执行 runbook。

仍未完成：

- 在真实 Hyper-V VM 上完成端到端验证。
- 自动导入 Guest Agent 输出并刷新最终报告。
- R0Collector 事件桥接。
- 更完整的网络、注册表、截图、进程树和系统范围文件监控。

## 可用于阐述的主线

对外阐述时可以按以下顺序表达：

1. 目标不是提交恶意样本或 VM 镜像，而是建设本地可控的分析框架。
2. 参考成熟沙箱报告结构，把输出目标定义为“摘要优先、证据可追溯”。
3. Host 负责调度和报告，Guest 负责运行和采集，R0 驱动负责补足内核视角。
4. 先用 dry-run 保证 Hyper-V 操作可审计，再逐步打开 live 执行。
5. 所有采集结果统一进入 `SandboxEvent`，减少后续模块耦合。
6. 报告从 `SandboxEvent + StaticAnalysis + RuleFinding` 生成，便于后续扩展。
7. 下一阶段重点是打通真实 VM 执行、事件导入和 R0Collector。

## 下一阶段优先级

1. Runbook 执行结果持久化：保存每一步 stdout、stderr、退出码和失败原因。
2. Guest 输出导入：读取收集回来的 `events.json` 并刷新报告。
3. WebUI 状态闭环：展示执行结果、导入状态和最终报告链接。
4. R0Collector 骨架：先接入文件监控 drain，输出兼容 JSONL。
5. 端到端验证：在准备好的黄金 VM 上完成一次真实样本的安全测试流程。
