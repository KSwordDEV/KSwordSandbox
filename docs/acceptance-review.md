# WebUI / 报告验收审查（只读）

审查日期：2026-10-15（Asia/Shanghai）  
范围：`E:\Projects\KswordSandbox` 当前工作树；未修改业务代码，也未读取或修改 `E:\Projects\Ksword5.1`。

## 执行结果

| 检查 | 结果 | 证据 |
|---|---|---|
| `scripts/Test-QualityGates.ps1` | **失败** | 编译阶段通过（0 警告、0 错误），随后 `rules.schema-collection-health.guard` 抛出 `Rule contains unsupported schema property 'includeNonBehaviorEvidence'.`；失败发生在 smoke scenario 的 schema 校验，不是运行时样本分析失败。 |
| `report.ux.contract` | 通过 | `dotnet run --project tests/KSword.Sandbox.SmokeTests/KSword.Sandbox.SmokeTests.csproj --configuration Debug --no-build -- --scenario report.ux.contract` 输出 `Scenario report.ux.contract ... passed.` |
| 最小中文报告渲染 | 结构可生成，但中文化不完整 | 用最小空事件报告渲染 `HtmlReportRenderer.RenderChinese`，扫描可见文本发现多处英文操作文案和内部字段。 |

上述 quality gate 失败应作为当前验收阻断项保留。修复规则 schema 或测试契约后，应重新运行完整 quality gate；不能把本次 `report.ux.contract` 单独通过当作发行验收通过。

## 主要发现

### 1. 中文报告仍泄漏大量内部/英文操作文案（P0）

最小报告的可见文本仍包含：`Aggregated behavior facts`、`Startup diff`、`Startup / persistence diff`、`Collection status, safe download selectors, duplicate grouping, and rejection diagnostics ...`、`Before/after startup diff.`、`This section shows aggregated startup facts ...`、`Process relationship evidence / 进程关系证据`、`Hint / 提示: artifact badges ...`、`Artifact index evidence`、`not observed`、`Dropped files`、`Memory dumps`、`Packet captures`、`Driver events` 等。

这些不是样本原始证据，而是报告壳层、空状态和内部策略说明；在简体中文报告中直接出现会让用户误以为看到了调试提示或英文 prompt。建议继续采用显式中文文案映射，但要覆盖空状态、卡片详情、状态值和 `data-copy` 文本；不要依赖短词全局替换，当前输出已出现混合句和破坏词：`行为 facts`、`否 primary behavior rule matched`、`collectorSelf否ise`、`样本d normalized report view`。

### 2. 报告存在“策略/实现说明”式提示词泄漏（P0）

可见文案包括 `Analyst focus`、`Read the verdict and high-signal evidence first`、`Behavior story counts exclude ...`、`renderer's weak-interaction policy`、`This is an evidence gap, not proof ...`、`raw ... remains the complete record` 等长段落。它们把实现策略、内部字段名、渲染器限制和审计流程暴露给普通操作者，信息密度高且夹杂英文。

保留一条短的用户可理解说明即可；字段名、路由、采样策略和“如何审计”的解释应放进可展开的“技术详情”或文档，而不是默认显示在每个报告卡片中。

### 3. `agent.start` 的噪声边界已在核心逻辑中定义，但 UI 仍把它当可见指标（P1）

`ReportEventSampler.IsLowValueOperationalInlineEvent` 与 `HtmlReportRenderer.IsAgentLifecycleEvent` 会将 `agent.start`/`agent.stop` 视为生命周期噪声并从主行为故事隐藏；这是合理的。当前报告仍在“分析重点”中显示 `Lifecycle hidden`，并写出 `agent.start/stop 行从主叙事隐藏；原始证据仍保留在下方。`agent.start` 作为事件本身不应计入样本行为、失败数或风险结论；保留在 raw evidence 供审计即可。

验收应明确检查：

- 主行为命中、图谱、时间线和事件筛选器默认不出现 `agent.start`/`agent.stop`；
- “生命周期隐藏”不作为醒目的风险指标；最多在技术详情显示计数；
- `r0collector.*`、`collection-health.*`、R0 readiness/queue/backpressure 和 VT quiet 状态同样只影响证据质量，不提升样本恶意判定。

### 4. 失败标记的当前语义需要在 UI 中区分（P1）

核心模型把 `AnalysisStatus.Failed`、运行手册失败、来宾事件导入失败和 `process.start_failed` 作为不同来源；报告也有 Failure reasons 章节。但用户界面容易把以下情况混为“样本失败”：

- 运行手册/VM/WinRM 预检失败（分析环境失败）；
- 来宾事件没有导入（证据不完整）；
- 样本进程启动失败（样本执行失败）；
- R0 不可用或降级（采集质量问题）；
- 分析超时（需显示阶段、持续时间和是否捕获到样本行为）。

失败卡片应显示“失败归因”字段（`分析环境`、`样本启动`、`证据导入`、`采集质量`、`超时`），并保留失败阶段、消息、退出码和持续时间。`Failed` 状态不能单独推导为“恶意”或“样本行为已确认”。

### 5. 证据详情表仍有布局风险（P1）

当前实现已具备事件筛选器和较宽的 Evidence 列（CSS 中 `event-explorer-table` 的详情列至少 420–460px），这是方向正确的。但代码中存在两套相互覆盖的主题 CSS：早先的方角扁平规则与后置的 `.modern-sandbox-report` 视觉层同时定义，后者重新启用圆角、阴影、圆角徽章和多层卡片（例如 `border-radius:14px`、`box-shadow`、`border-radius:999px`）。这与“色块区分、去线框化、避免嵌套卡片”的目标冲突，且会造成同一页面不同章节风格不一致。

事件详情默认应保持单层色块、可读宽度、固定最大高度和滚动；长 command/stdout/stderr/PowerShell 只在原生 details 中展开。建议删除重复主题覆盖，保留一份明确的扁平规则，并在 1000px/640px 断点检查横向滚动和详情列是否压缩成窄小框。

### 6. 空状态和 evidence-lane 文案噪声过大（P1）

即使没有事件，报告仍展示多张“证据通道健康”卡、采样策略、来源路径和完整字段转储。对普通用户，空状态只需说明“未采集到/未观察到”，以及一条下一步建议；`collectionName=...`、`artifactEvidenceMatrix=-`、`latestReason=-` 等机器字段应折叠或隐藏。完整 `report.json`/JSONL 路径应留在技术详情或下载区。

## 复核建议

1. 先修复 `includeNonBehaviorEvidence` schema 契约不一致，使 `Test-QualityGates.ps1` 全部通过。
2. 用真实生成的 `report.zh.html` 做可见文本扫描，要求默认操作界面中不出现上述英文长句和内部策略字段；原始证据值（eventType、路径、命令、hash）可保持原文。
3. 以一个包含 `agent.start`、R0 health、`process.start_failed`、WinRM failure、guest import failure 和 timeout 的合成报告验收失败归因及噪声边界。
4. 用 10 个以上样本结果检查表格筛选器、失败标记和证据详情高度；每个结果至少显示结论、失败归因/证据质量、主要证据计数和可展开原始证据入口。

## 第二轮复核结果

已落实：

- `agent.start/stop` 等生命周期行在采样器中作为策略排除，不再触发误导性的采样提示；原始事件仍可审计。
- 失败卡片增加“失败归因”，区分分析环境、证据导入、采集质量、超时和样本启动。
- 中文化保护整个 HTML 标签、`script`、CSS/JS 属性和复制字段；`zh-CN` 元数据单独设置，避免改写筛选器和机器字段。
- 事件表增加行为族筛选器、零结果空状态；桌面证据列保持宽详情，手机端折叠低优先级列后展示完整证据。
- CSS 后置视觉层已改为无阴影、无圆角、色块分组；默认隐藏实现策略说明，只保留失败说明。
- 规则 schema 允许 `includeNonBehaviorEvidence`，质量门禁已恢复通过；发行就绪静态门禁复测为 16 通过、0 失败。

