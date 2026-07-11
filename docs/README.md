# 文档地图与当前状态 / Documentation map and canonical status

本页是当前 MVP 文档的轻量索引，用于减少文档漂移：当两个文档覆盖同一主题时，
优先更新下方 canonical（权威）文档，其他文档只保留短指针或历史说明。

English reference: this page is the lightweight index for the current MVP documentation.

## 当前 MVP 一段话 / Current MVP in one paragraph

当前 MVP 是本地 Hyper-V 沙箱流程：操作者在 WebUI/API 中选择或本地上传 `.exe`，
宿主创建 job 计划并执行哈希/静态分析；显式 live 模式会还原/启动准备好的
Windows 10 golden VM；Guest Agent 和可选 R0Collector 采集 guest/R0 行为；
WebUI 展示实时进度和原始事件；可选 VirusTotal 只做 hash-only 查询；宿主导入
事件/证据（artifacts）并折叠为 findings；报告渲染器在 runtime root 下输出
`report.json`、`report.html`、`report.zh.html` 和 `report.en.html`。

该端到端路径的本地记录证据见 [`webui-real-r0-e2e.md`](webui-real-r0-e2e.md)。
默认安全路径仍是 PlanOnly/dry-run，不会修改 VM。

## 仓库卫生提醒 / Repository hygiene reminder

只提交源码、规则、配置模板和文档。**不要**提交样本、VM 磁盘/检查点/导出、
runtime job 目录、生成的报告、guest payload 二进制、抓包、内存转储、`bin/`、
`obj/`、`x64/`、`.sys`、`.pdb`、`.obj`、证书、私钥、API key、guest 密码，
或本地 `sandbox.local.json` / install-state 文件。

## 按任务划分的权威文档 / Canonical documents by task

| 任务 / Task | 权威文档 / Canonical document(s) | 说明 / Notes |
| --- | --- | --- |
| 项目概览与边界 / Project overview and guardrails | [`../README.md`](../README.md), [`current-architecture-and-operations.md`](current-architecture-and-operations.md) | 根 README 是入口；current architecture/operations 是 MVP 状态和操作者地图的权威说明。 |
| 安装、本地配置和密钥 / Install, local config, secrets | [`install.md`](install.md) | 集中说明 guest 密码、VT key 和 VM 配置。 |
| 日常 WebUI / CLI 入口 / Daily WebUI / CLI entry point | [`run.md`](run.md) | 覆盖 WebUI 启动、Analyze 快捷入口、PlanOnly vs Live、报告重建和 artifact 检查。 |
| Hyper-V live 操作者流程 / Hyper-V live operator flow | [`hyperv-e2e-runbook.md`](hyperv-e2e-runbook.md), [`hyperv-readiness.md`](hyperv-readiness.md) | 脚本化 PlanOnly/WhatIf/Live 流程和只读预检。 |
| Golden VM 与 payload 暂存 / Golden VM and payload staging | [`golden-vm.md`](golden-vm.md), [`guest-payload-staging.md`](guest-payload-staging.md) | VM baseline 和 guest 工具发布；输出保持在 git 仓库外。 |
| WebUI/API 验证证据 / WebUI/API validation evidence | [`webui-real-r0-e2e.md`](webui-real-r0-e2e.md), [`verification.md`](verification.md), [`testing.md`](testing.md) | `webui-real-r0-e2e.md` 是当前本地 live 证据记录；verification/testing 用于可重复门禁。 |
| 证据与报告 / Artifacts and reports | [`artifacts.md`](artifacts.md), [`artifact-manifest.md`](artifact-manifest.md), [`report-schema.md`](report-schema.md), [`report-ux.md`](report-ux.md) | Artifact 存储/索引、报告 JSON/HTML 形状、双语报告 UX 和证据链接。 |
| Guest 采集 / Guest collection | [`guest-agent.md`](guest-agent.md), [`guest-agent-framework.md`](guest-agent-framework.md) | 事件/artifact 覆盖和 probe 框架说明。 |
| R0 采集和驱动 ABI / R0 collection and driver ABI | [`r0-collector.md`](r0-collector.md), [`r0-jsonl-schema.md`](r0-jsonl-schema.md), [`r0-driver-core.md`](r0-driver-core.md), [`driver-install.md`](driver-install.md) | Collector JSONL 与 kernel/user ABI 是权威说明；driver install 是 VM-only 操作者 runbook。 |
| R0 producer 说明 / R0 producer notes | [`r0-driver.md`](r0-driver.md), [`r0-file-monitor.md`](r0-file-monitor.md), [`r0-process-registry-image.md`](r0-process-registry-image.md), [`r0-network.md`](r0-network.md) | Producer 专项说明应链接回 `r0-driver-core.md`，避免重复 ABI 细节。 |
| 行为规则与静态分析 / Behavior rules and static analysis | [`behavior-rule-matrix.md`](behavior-rule-matrix.md), [`rules-windows-sandbox.md`](rules-windows-sandbox.md), [`static-analysis.md`](static-analysis.md), [`../rules/static-analysis-notes.md`](../rules/static-analysis-notes.md) | Matrix 是完整清单；rules-windows 是可读摘要；static 文档覆盖宿主侧证据。 |
| VirusTotal | [`virustotal.md`](virustotal.md) | 可选 hash-only enrichment；不上传样本。 |
| 打包/发布 / Packaging/release | [`release.md`](release.md), [`v1-release-gap-audit.md`](v1-release-gap-audit.md) | 源码/runtime 包边界、artifact 排除、发布 readiness 门禁和当前 v1 gap audit。 |

## 历史或背景说明 / Historical or background notes

这些文件仍有参考价值，但在未核对上方 canonical 文档前，不应作为当前状态的唯一事实来源：

- [`progress.md`](progress.md): 历史进展快照和规划百分比。
- [`extracted-results-summary.md`](extracted-results-summary.md): 研究和叙事摘要；当前状态已移至 `current-architecture-and-operations.md`。
- [`hyperv-vm-current-state.md`](hyperv-vm-current-state.md): 带日期的只读 VM 观察；live 工作前请重新运行 readiness。
- [`microstep-report-benchmark.md`](microstep-report-benchmark.md),
  [`research-basis.md`](research-basis.md), and
  [`open-source-sandbox-references.md`](open-source-sandbox-references.md):
  设计/参考材料。
- [`r0-merge-review.md`](r0-merge-review.md) and
  [`r0-next-implementation-plan.md`](r0-next-implementation-plan.md): merge 或实现规划说明；执行前请与当前源码核对。

## 重叠内容策略 / Overlap policy

- 优先链接到 canonical 文档，不要把长 PowerShell 片段复制到多个文件。
- 如果 runbook 必须重复命令，请同时保留 guardrails：PlanOnly 是安全路径；Live 必须显式选择且会修改配置的 VM；`CSignTool.exe` 不属于默认路径；生成输出必须留在 git 仓库外。
- 带日期的本地证据应包含日期，并指回可重复的 readiness 或 verification 命令。
- Review 或 packaging 前，优先运行轻量发布门禁：
  `.\scripts\Test-ReleaseReadiness.ps1 -AllowDirtySource -StageSourcePackage`。
  它不会修改 Hyper-V、签名驱动或调用 `CSignTool.exe`。
