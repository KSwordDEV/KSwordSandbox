# 报告 UI 视觉与可读性审计

审查日期：2026-10-15（Asia/Shanghai）  
范围：`src/KSword.Sandbox.Core/Reporting/HtmlReportRenderer.cs` 的 HTML、CSS、内联脚本和中文壳层。只写本审计文档，未修改渲染器，也未读取或修改 `E:\Projects\Ksword5.1`。

## 验证记录

- `dotnet build src/KSword.Sandbox.Core/KSword.Sandbox.Core.csproj --no-restore`：通过，0 警告、0 错误。
- 重建后运行 `dotnet run --project tests/KSword.Sandbox.SmokeTests/KSword.Sandbox.SmokeTests.csproj --configuration Debug -- --scenario report.ux.contract`：通过。
- 在重建前用 `--no-build` 运行同一场景时，旧 DLL 报“Default rendered HTML should use the Simplified Chinese compatibility report”；这说明审查或发布前必须先重建，不能把旧输出当作当前源码结果。
- 本次没有可复用的真实样本 HTML 和浏览器截图，因此视觉结论按当前 CSS 计算出的有效宽度、DOM 结构和契约场景判定；真实样本的窄屏截图仍应作为下一轮验收输入。

## 结论

桌面端事件表的证据列已经有足够的设计宽度：最终 CSS 将第 7 列设为 `min-width:460px;width:42%`，详情块设为 `min-width:420px`，并将命令行、stdout、stderr、PowerShell 等长字段放进原生折叠详情。这满足“详情不能挤成小框”的桌面目标。可是表格整体 `min-width:1080px`，在 1280px 视口（右侧正文约 972px）和所有手机视口都会出现横向滚动；手机只把详情列降到 340px、详情块降到 280px，用户仍要横向拖动很远才能看到证据。窄屏体验目前不合格。

主表已经基本采用色块分区：最终层把卡片、表格单元格和主要容器设为无边框、无阴影，并按严重性使用浅红/浅黄/浅绿背景。这个方向符合去线框要求。但同一 `AppendHead` 中先后存在两套大段主题 CSS，移动端最后一条规则又把卡片设回 `border-radius:10px`，导致桌面方角、手机圆角和旧规则并存，后续维护难以判断实际样式。

筛选器的字段覆盖是合理的（搜索、事件类型、来源、行为族、阶段、严重性、是否样本行为、重置），并且 `agent.start/stop` 等生命周期行在数据层被排除出主表。筛选脚本对内联的最多 120 行工作正常，但筛选到零行时没有显示“没有匹配行”的空状态；表格只剩空白，状态文字也不再显示原始内联/报告专用/生命周期计数。这个情况会被用户误认为页面加载失败。

空状态仍偏技术化。默认报告会构造大量 `section-note`、采集策略、原始来源和健康叙事；最终 CSS 全局隐藏 `.section-note`，结果是部分噪声消失，但也把“原始证据高度限制 58vh”等对导航有用的说明一并隐藏。对于没有事件的章节，筛选器仍然显示一整套不可用的控件。应保留一条短中文结论和一个下一步动作，把路径、字段键、采样策略和渲染器说明放入“技术详情”。

## 具体发现

| 优先级 | 位置/现象 | 对用户的影响 | 建议的最小修复 |
|---|---|---|---|
| P0 | `LocalizeChineseHtml` 只保护 `<style>`、`<code>/<pre>` 和部分属性，没有保护整个 `<script>`。中文替换表包含 `("Section", "章节")` 和 `("Copied", "已复制")`；内联脚本含 `setActiveSidebarSection` 和 `'Copied'`。 | 中文报告可能把脚本标识符改成 `setActiveSidebar章节`，目录高亮或复制反馈失效；筛选结果不能再视为可信分析。 | 翻译前整体保护 `<script>...</script>`，或改为只翻译可见文本节点；保留 `data-*`、事件类型、来源和脚本源码原文。 |
| P0 | 源码仍直接输出双语提示，例如 `Weak-interaction graph / 弱交互图谱`、`Process relationship evidence / 进程关系证据`、`Network category view / 网络分类视图`、`Hint / 提示` 和 `Failure attribution / 分析环境`。全局替换只替换前半句，可能生成重复的“中文 / 中文”。 | 默认中文报告出现提示词泄漏、中英拼接和重复标签，普通操作者难以区分结论、策略说明和证据值。 | 模板直接输出单一中文可见文案；机器字段和原始值只出现在折叠技术详情。不要对已含中文的双语模板做半句替换。 |
| P1 | 最终视觉层 `@media(max-width:640px)` 将 `.card, section.card` 设为 `border-radius:10px`，覆盖前面 `border-radius:0` 的方角约定。 | 手机页面风格与桌面不一致，重新出现卡片化/线框感。 | 删除该覆盖，保留 `0` 或 `2px`；将色块层级交给背景色和留白。 |
| P1 | 事件表 `min-width:1080px`；证据列桌面 460px，`<=1000px` 仍至少 320px，`<=640px` 单元格 340px、详情块 280px。 | 1280px 视口已经横向滚动；手机要拖过约 700px 才能看到第 7 列，详情在视觉上仍像窄小框。 | `<=640px` 改为每行堆叠的“标签/值”布局，或隐藏低优先级列并让证据列占满；平板保留有界横向滚动但把时间、来源等低优先级字段折叠。 |
| P1 | 事件表外层 `section.card` 最大 75vh，事件表又最大 70vh，详情块最大 52vh，raw panel 仍有独立滚动。 | 章节、表格、详情三级滚动条叠加，长报告阅读时容易丢失当前上下文。 | summary 区域让章节自然增长，只给事件表/raw panel 设置内部高度；详情保留一个最大高度。 |
| P1 | 筛选脚本将所有已生成行设置为 `display:none`，但只有初始 `rows.Count == 0` 时才输出空状态。筛选后无匹配行不会出现空状态。 | 用户看到空白表格，无法判断是筛选结果为 0、加载失败还是证据缺失。 | 在 `applyExplorerFilters` 后维护 `.event-explorer-empty` 的 `hidden` 状态，显示“没有匹配行，请调整筛选条件”；状态中保留 `匹配/内联/报告专用/生命周期`四个计数。 |
| P1 | 最终 CSS 全局 `.modern-sandbox-report .section-note{display:none}`；raw 章节的 `Raw evidence height limit: 58vh` 和部分质量说明只存在于这些节点。 | 过量提示被隐藏的同时，用户看不到证据是否有界、为何有隐藏行；技术审计和用户阅读都缺一个明确边界。 | 默认显示一条短句“原始证据最多显示 58vh，完整记录见 report.json”，其余策略说明放到折叠技术详情。 |
| P1 | 事件 explorer 无行时仍渲染搜索和 6 个下拉框；选择项只有 `All`。 | 空状态占据很多空间，控件看起来像可用但没有任何数据。 | 无行时隐藏或禁用筛选器，仅显示“未采集到面向用户的事件”和“展开原始事件”入口。 |
| P2 | 初始状态的状态栏包含 `visible rows`、`report-only rows`、`lifecycle rows`；筛选后脚本把它替换成只有 `N matching rows`。 | 用户筛选后看不到隐藏数量和噪声边界，难以判断 `agent.start` 是否被算进来。 | 状态栏固定为 `匹配 N / 内联 M / 报告专用 K / 生命周期 L`，中文状态只显示用户需要的四个数字。 |
| P2 | `.event-explorer-toolbar input/select` 使用 inset box-shadow 模拟边框，raw page、导航链接和部分折叠块仍有细线。 | 主体已去线框，但控制区和 raw 区还有不同风格，视觉层级不够统一。 | 保留控件焦点环作为可访问性反馈，普通状态使用色块底色；统一 raw page summary 的背景色和间距。 |

## 噪声与失败标志

- `agent.start`、`agent.stop`、`agent.ready`、`agent.heartbeat` 属于采集器生命周期。它们可以保留在 raw evidence，但不能进入风险摘要、行为图、主时间线或醒目的“分析重点”。当前主事件表已通过 `IsLowValueOperationalEvent` 排除它们；`lifecycle rows folded in Raw normalized events` 仍适合留在技术状态中，不应作为风险指标。
- `r0collector.*`、R0 健康/队列背压、设备不可用、采集器自噪声和 VT quiet 状态属于证据质量。它们可以解释证据不完整，但不能单独标志样本恶意。
- 页面出现被汉化的脚本标识符、`data-*` 机器键、事件类型、筛选值，或出现“中文 / 中文”重复壳层，标志报告渲染失败；不能归因于样本噪声。
- `AnalysisStatus.Failed`、样本启动失败、来宾导入失败、采集降级和超时必须在 UI 上保留失败归因。当前失败章节已经有 `Failure attribution` 字段，但双语模板仍可能重复，需按上表修正。

## 下一轮验收

1. 用一个包含 `agent.start`、R0 health、`process.start_failed`、来宾导入失败和超时的合成报告生成中英文 HTML。
2. 在 1440px、1280px、1024px、640px、390px 视口检查事件表：详情列、横向滚动、筛选器换行、空筛选结果和 raw panel 高度。
3. 对 `report.zh.html` 分别扫描可见文本、`<script>`、`data-*`、`data-copy` 与 `<code>/<pre>`；可见壳层不应有英文策略长句，机器键、事件类型、路径、命令、哈希和脚本标识符必须原样。
4. 运行构建后的 `report.ux.contract`，再把实际生成的 HTML 放入浏览器检查；不要使用 `--no-build` 的旧 DLL 作为验收结果。
5. 用至少 10 个真实或有明确行为结论的样本回填同一表格，记录每个结果的 verdict、失败归因、证据质量、主要证据计数和可展开入口；本审计不把合成报告当作真实样本校准。

