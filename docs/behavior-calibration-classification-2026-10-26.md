# 无害行为校准程序分类审查（2026-10-26）

## 结论

最初只读检查了 `rules/behavior-rules.json`、`SampleCorrelationClassifier`、`RuleEngine`、`HtmlReportRenderer` 和 Guest Agent 启动项差分；现已根据两次 VM 实测的回收报告更新。此轮文档更新未操作虚拟机。

**无需改规则或阈值，VM 内真实运行的无害行为校准程序已得到“高风险／威胁”报告。** 程序在来宾机的 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 创建了指向自身 `Environment.ProcessPath` 的值，并保留至 Agent 后快照。文件名只用于将启动项归属到当前样本；高危判断依据是实际自启动项差分，而非固定名称、哈希或程序内自报的分类字段。这是无害校准样本的行为判定，不能称其为真实病毒家族。

### 两次实测结果

| 路径 | Job ID | 状态和结论 | 关键证据 |
| --- | --- | --- | --- |
| 手工离线 `import-live` | `ea9201fe-6c38-4004-9ed9-d0aae5348dd3` | Completed；中文报告“威胁／高风险”；4 条 high finding | [报告 JSON](../artifacts/validation-20261026/offline-runtime/jobs/ea9201fe6c3840049ed9d0aae5348dd3/report.json)、[中文报告](../artifacts/validation-20261026/offline-runtime/jobs/ea9201fe6c3840049ed9d0aae5348dd3/report.zh.html)；`process.exit` 的 `exitCode=0`。 |
| final6 WebUI 发布包路线 | `6f6f6147-efa4-47b3-ba03-bdc1ad014d08` | Completed；中文报告“威胁／高风险”；4 条 high finding | [报告 JSON](E:/Temp/KSwordSandbox-Lab-20261026/release-e2e-runtime-final6/jobs/6f6f6147efa447b3ba03bdc1ad014d08/report.json)、[中文报告](E:/Temp/KSwordSandbox-Lab-20261026/release-e2e-runtime-final6/jobs/6f6f6147efa447b3ba03bdc1ad014d08/report.zh.html)；`process.exit` 的 `exitCode=0`。 |

两份报告均出现 `startup.created` 的 Registry32 与 Registry64 两条视图事件，`data.startupSurface=autorun-run-key`，`data.target` 是带引号的来宾样本路径加 `--noop`。两条事件均 `sampleCorrelation=confirmed`、`behaviorCounted=true`。两份报告的 4 个 high 规则 ID 相同：`startup-item-system-change-created`、`startup-item-executable-value`、`startup-unified-autostart-created-or-modified`、`startup-user-writable-or-script-target`。此次实际归属原因是 `path-or-command-matched-submitted-sample`，因为通用样本路径检查先于专门的 service/task 分支。

两份报告的 `CollectionHealth.State=partial`，原因是 `driver-health-missing` 和 `driver-final-queue-unknown`；本轮未启用 R0。这是采集覆盖限制，不影响已观察到的 Run 启动项差分。S4U 会话下当前用户 Startup 文件夹路径不可用，样本清单记录 `startup-skipped`，未创建 `.cmd`；不能把它计作已观察到的 Startup 文件夹持久化。样本只复制了自身到自建 Temp 目录并未执行该副本，也未修改其他可执行文件，因此不能称为“文件感染”。对影子副本删除只记录意图文本，没有运行删除命令。

首次手工尝试的 Failed 是状态 sidecar 缺失，不能用作样本恶意性结果。final4 正式路线的 VIX `20004` 是产品在 Windows PowerShell 5.1 中把清单根数组当单个对象，拼成超长文件名的解析缺陷；已修复并由 final6 WebUI 完成路线验证，见 [VIX 诊断](vix-20004-diagnosis-2026-10-26.md)。这些故障不属于病毒行为或该 VM 的样本归属问题。

## 端到端证据链

1. `guest/KSword.Sandbox.Agent/Collection/ProcessTreeProbe.cs:2400-2455` 对 Run 等启动项清单做前后比较，生成 `registry.run.created/modified` 和投影的 `startup.created/modified`。投影事件的 `source=guest`，`path` 为启动项位置，`data.startupSurface`、`data.startupCategory`、`data.location`、`data.target`、`data.value` 描述自启动项（约 2860 行）。
2. `src/KSword.Sandbox.Core/Correlation/SampleCorrelationClassifier.cs:500-555` 先通过通用 `AnyFieldMatchesSamplePath` 把 `startup.*` 的 `target/value` 与本次实际提交的样本路径关联，实测事件为 `sampleCorrelation=confirmed`，`sampleCorrelationReason=path-or-command-matched-submitted-sample`。专门的 service/task 归属分支在后面，**本次没有经过该分支**。`ApplyDisposition` 在约 2005-2090 行设置 `behaviorCounted=true`、`sampleBehaviorCandidate=true`、`evidenceDisposition=behavior-candidate`。`BuildContext` 在约 1344、1733 行从样本 `process.start` 和进程树建立 PID 归属。
3. `src/KSword.Sandbox.Core/Rules/RuleEngine.cs:73-192,480-740` 排除 unknown/environment、自噪声及 `behaviorCounted=false` 后匹配规则。`startup-unified-autostart-created-or-modified` 需要 `startup.created/modified` 且至少有 `startupSurface/startupCategory/target/value/location/serviceName/taskName` 字段，返回 `high/high`。`startup-user-writable-or-script-target` 需要同一事件的 `data.target/value` 含 `.exe` 或用户可写路径等，亦返回 `high/high`。
4. `src/KSword.Sandbox.Core/Reporting/HtmlReportRenderer.cs:12365-12440` 中，任意主行为 high finding 将详细结论设为 `High risk`；`ToTriageVerdict` 在 1481-1498 行映射为 `Threat`。中文译文分别为“高风险”和“威胁”。以上两条 startup 规则不是静态、VT、诊断或 supporting finding，可计入主行为。

## 报告核验的具体 JSON 字段

实际 JSON 属性按项目序列化约定检查，至少须能追溯下列值；不能只看 HTML 首屏：

| 证据位置 | 必须核验的字段和预期值 |
| --- | --- |
| `report.json` 的样本启动事件 | `eventType=process.start`、`path` 或 `commandLine` 为来宾实际执行路径、`processId>0`、无 `process.start_failed`；样本执行已成功。 |
| `report.json` 的原始启动项事件 | `eventType=startup.created` 或 `startup.modified`、`source=guest`、`data.startupSurface=autorun-run-key`、`data.target` 或 `data.value` 指向当前样本 EXE、`data.location` 为 HKCU Run 位置。可伴随 `registry.run.created/modified`。 |
| 同一事件的归属字段 | 实测 `data.sampleCorrelation=confirmed`、`data.sampleCorrelationReason=path-or-command-matched-submitted-sample`、`data.strongSampleCorrelation=true`、`data.behaviorCounted=true`、`data.sampleBehaviorCandidate=true`。 |
| `report.json` 的 findings | 实测 4 个 `severity=high` 的规则：`startup-item-system-change-created`、`startup-item-executable-value`、`startup-unified-autostart-created-or-modified`、`startup-user-writable-or-script-target`；每条 2 个启动项视图证据。 |
| `report.zh.html` | 首屏 `威胁` 和 `高风险`；发现卡片可对应具体启动项事件。 |
| 运行边界 | 采集健康、原始事件与回传完整；Run 值保持到后快照；VM 回滚完成。静态字符串、高危词语、VT 标签或 unknown 事件均不能代替运行证据。 |

## 辅助行为与漏采边界

- 现有 `HarmlessSample` 只写 marker 文本、运行 `cmd.exe echo`，并可选回环与 TEST-NET 连接。这适合作为冒烟样本，通常不足以保证 `Threat`。
- Startup 文件的 `file.created/modified` 可命中 `persistence-startup-folder-lnk-or-script`（high/high），但 FileSystemWatcher 事件若 `data.actorPidStatus=unavailable-filesystem-watcher` 且没有 10 秒内另一来源的同路径样本 PID 突变证据，`ClassifyFileEvidence` 会将其归为 unknown，`RuleEngine` 不会把它当作主行为。对应代码位于 `SampleCorrelationClassifier.cs:1105-1195,2547-2554`。Startup 文件只宜作为第二信号；不要因此放宽归属边界。
- 旧的 `run-key-user-writable-payload` 仅收 `registry.set/create/driver.registry`，**不收** Guest 快照产生的 `registry.run.created/modified`；`r0-semantic-runkey-persistence-family` 同样依赖 R0 语义注册表事件。这是 P1 规则覆盖缺口，不妨碍本轮通过统一 `startup.*` 规则验证。以后可增加 diff 类型，但需保持 confirmed/probable 归属限制并验证合法启动项误报。
- `ransomware-encrypted-extension-rename` 要求 `driver.file/rename/setinfo`、实际 `.locked/.enc` 等路径和 `data.operationName/operation=rename` 一类字段；`ransomware-mass-file-write-burst-numeric` 要求真实采集器的 `writeCount>=100` 摘要及分类/扩展名证据。仅凭程序自称“ransomware”或自己伪造摘要不能作为校准结果。
- 某些文件规则排除 `\KSwordSandbox\` 路径。若测试 Startup 文件，应使用真实 Windows Startup 目录，并让创建结果留到后快照；立即自清理可能让清单差分完全看不到它。Run 值也应由隔离克隆回滚清除。

## 分类边界与后续改进

本轮不建议降低 severity 或增加样本名特判。若报告未命中 high，先定位 `process.start`、启动项后快照、`startup.created`、样本归属字段、RuleEngine findings 和证据回传这六层中断点。确认是产品采集/发布路线问题，还是本机 VM 权限、Guest Agent/R0/ETW 配置问题，再修改对应层。保存 job ID、发布包版本、样本哈希（仅作身份记录）、VM 克隆/快照与回滚记录，供报告复核。
