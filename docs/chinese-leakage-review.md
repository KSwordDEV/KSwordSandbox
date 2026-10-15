# `report.zh.html` 中文化与机器字段泄漏复核

审查日期：2026-10-15（Asia/Shanghai）
范围：`E:\Projects\KswordSandbox` 当前工作树；只读检查渲染器和生成结果，没有修改业务代码，也没有读取或修改 `E:\Projects\Ksword5.1`。
## 扫描方法与边界

我从当前 `HtmlReportRenderer.cs` 构造了一个包含 6 条事件的最小报告（`process.start`、`file.write`、`network.tcp`、`agent.start`、R0 状态和证据索引），生成 `report.zh.html` 后去除样式、脚本和标签，扫描剩余可见文本。临时副本只补了一行 `NormalizeEventType` 以便运行渲染器；本仓库直接构建仍被 `HtmlReportRenderer.cs:4246` 的 `CS0103: NormalizeEventType` 阻断。因此下面的渲染样本用于文案和替换边界审查，不代表当前提交已经可以发行。

扫描样本是合成报告，没有联网下载或执行真实恶意样本；它只能揭示 UI 文案和字段污染，不能证明检测准确率。

## 结果

### P0：全局替换污染脚本和机器字段

`LocalizeChineseHtml` 在完整 HTML 上调用字符串替换。样式被保护，但脚本没有被保护；短词替换也会穿过属性、`data-*`、`data-copy` 和原始证据。最小报告出现了以下结果：

| 位置 | 扫描到的结果 | 影响 | 最小修复方向 |
|---|---|---|---|
| 内联脚本 | `setTimeout` 变成 `set时间out`；`querySelectorAll` 变成 `querySelector全部`；`setActiveSidebarSection` 中的 `Section` 被改成中文 | 筛选器、复制按钮和目录高亮可能失效 | 翻译前保护整个 `<script>...</script>`，或只翻译可见文本节点；不要在脚本源码上替换短词 |
| `data-*` 与筛选值 | `network.tcp` / `r0collector.driverNetworkStatus` 被改成 `网络.tcp` / `r0collector.driverNetwork状态` | 机器标识不再稳定，筛选、复制和后续审计数据可能与原始事件不一致 | 事件类型、来源、阶段、字段键、DOM 属性值永远保留原文；只翻译对应表头和标签 |
| 复制摘要 | `collectorSelfNoise` 变成 `collectorSelf否ise`，`notSampleBehavior` 变成 `not样本行为` | 复制出来的统计无法作为 JSON/键值证据使用 | `data-copy` 负载走技术原文通道，显示文案和复制技术摘要分开 |
| 原始键值 | `behaviorCounted=false`、`remoteAddress`、`commandLine`、`artifactEvidenceMatrix` 等在普通卡片中直接出现 | 用户看到内部策略字段和实现细节，难以区分结论与原始证据 | 默认只显示“技术字段（可展开）”；完整键值放到折叠详情或下载文件 |

这是分析失败标志，而非样本行为：如果 `report.zh.html` 中出现被改写的 JavaScript 标识符或机器键，说明中文化流水线破坏了报告本身，不能把该页面的筛选结果当作可靠证据。

### P1：报告壳层仍有英文或中英拼接的策略提示

这些字符串不是样本原始值，应直接替换成短中文句子；目前最小报告仍显示：

| 当前显示 | 建议显示 | 说明 |
|---|---|---|
| `Aggregated behavior facts` | `行为事实汇总` | 目录和章节标题都要覆盖 |
| `行为 facts before raw events.` | `原始事件前的行为事实。` | 当前只替换了 `Behavior`，留下半句英文 |
| `Startup diff` | `启动项差异` | 快速导航、动态指标和证据故事统一用这个词 |
| `Startup / 持久化 diff` | `启动项 / 持久化差异` | 不要让 `diff` 单独漏出 |
| `Agent lifecycle` / `Agent 生命周期` | `采集器生命周期` | `agent.start/stop` 只作为技术详情计数，不能成为主行为事件 |
| `Collection/self-noise policy` | `采集与自噪声说明` | 普通用户不需要看到内部 policy 名称 |
| `Behavior story counts exclude ...` | `行为统计已排除采集器、健康检查和信誉查询行。` | 长策略句放到技术详情；字段键只在展开区出现 |
| `Weak-interaction graph / 弱交互图谱`、`Hint / 提示:` | `关系图`、删除提示句 | “弱交互”“提示”是实现说明，默认界面不需要 |
| `Evidence health narrative` 后接 `These health lanes explain ...` | `证据健康` + `用于说明采集质量，不代表样本恶意性。` | 删除渲染器策略和完整记录解释 |
| `Stable relationship lanes` 后接 `Process lineage lane: ...` | `关系通道`；详情中再显示各通道 | 复制摘要可以保留英文键，但默认卡片不要混用 |
| `Artifact evidence cards. Collection status, safe download selectors...` | `证据文件概览。显示采集状态和可用下载入口。` | 其余 selector/duplicate/rejection 说明折叠 |
| `Rows are split into ... native page(s)` | `事件分为 {n} 页，每页 {m} 行。` | 目前只翻译了 `rows`，英文长句仍可见 |
| `No inline evidence observed ... check Raw normalized events...` | `本通道未观察到证据；请展开技术详情或下载原始事件。` | 去掉内部文件名和审计指引 |

### P1：动态事实卡把英文模板当成用户文案

合成报告中还出现 `Observed ... actors`、`Why review`、`Network facts ...`、`No startup.* ...`、`1 indexed`、`0 captures`、`Flow/other`、`Examples:`、`no linked artifact`、`not recorded` 等。它们是 `EvidenceStoryCard`、关系卡和复制摘要产生的模板，不是事件值。建议在模板层给每个字段一个中文标签：

| 英文模板/值 | 建议中文 |
|---|---|
| `What happened` / `Why review` | `发生了什么` / `为什么需要关注` |
| `actors` / `items` / `captures` / `dumps` / `nodes` | `个主体` / `项` / `张截图` / `个转储` / `个节点` |
| `indexed` / `not recorded` / `not observed` | `已索引` / `未记录` / `未观察到` |
| `Flow/other` | `流量/其他` |
| `Examples:` | `示例：` |
| `no linked artifact` / `none` | `未关联证据文件` / `无` |
| `status` / `readiness`（作为标签时） | `状态` / `就绪度` |

路径、哈希、进程名、命令行、URL、端口和事件类型属于证据值，可以保留原文；它们应放在表格或折叠技术详情中，不能与用户提示句混在同一段中。

### P2：可接受的技术原文

`SHA-256`、`PE32+`、`Windows GUI`、`MITRE ATT&CK`、`DNS/HTTP/TLS`、`WFP/ALE`、`PCAP`、`JSONL`、`report.json`、路径、哈希、进程名和真实事件类型可以保留。保留时应有中文标签，例如“事件类型：`process.start`”“字段：`remoteAddress=...`”；不要对这些值执行汉化替换。

## 噪声与失败判定

- `agent.start` / `agent.stop` 是采集器生命周期噪声。它们可以留在原始事件和技术详情中，但不应进入主行为表、行为图、风险计数或“分析重点”。“生命周期隐藏”也不应作为醒目的用户指标。
- `r0collector.*`、采集健康、队列背压、设备不可用和 VT 安静状态是证据质量信息。它们能解释“为什么证据不完整”，但不能单独标志样本恶意。
- `AnalysisStatus.Failed` 只能说明分析流程失败。界面需继续区分分析环境、样本启动、证据导入、采集质量和超时；不能把失败状态显示成样本结论。
- `report.zh.html` 中出现英文策略句、被汉化的机器键、被改写的脚本函数名或筛选值，均标志报告分析/渲染失败；不能归因给样本噪声。

## 最小验收清单

1. 用包含 `agent.start`、R0 健康、`process.start_failed`、导入失败和超时的合成报告渲染 `report.zh.html`。
2. 去除 `<style>`、`<script>` 和 HTML 标签后扫描可见文本；默认界面不得出现上表中的英文壳层或策略长句。
3. 再扫描 `script`、`data-*`、`data-copy` 和 `<code>/<pre>`：机器键、事件类型和脚本标识符必须与原始值完全一致。
4. 手动验证事件类型、来源、行为族和样本行为筛选器；先检查脚本未被替换，再把筛选计数作为有效结果。
5. 空状态只显示“未采集到/未观察到”和一条下一步建议；`collectionName=...`、`artifactEvidenceMatrix=-`、`latestReason=-` 等放入折叠技术详情。

## 修复后复核

渲染器现已保护完整 HTML 标签、`script` 块以及复制/路径属性，并显式设置 `lang="zh-CN"`；`report.ux.contract` 和质量门禁复跑通过。行为族筛选、移动端证据表折叠和零结果空状态也已补上。
