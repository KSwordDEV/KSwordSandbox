# 报告与 WebUI UX 契约 / Report and WebUI UX contract

权威范围：本页负责 report/WebUI 展示预期。JSON/HTML section 数据契约见
`docs/report-schema.md`，artifact selector/link schema 见 `docs/artifact-manifest.md`，
VirusTotal hash-only reputation 行为见 `docs/virustotal.md`。

验证这些 UX 要求时，不要提交生成报告、raw events、artifact indexes、screenshots、
dumps、packet captures、samples、payload binaries 或 VM outputs。

v1 报告必须在 live demo 中对操作者有用，而不只是技术上完整。页面应让操作者快速回答三件事：

1. 风险是什么？（What is the risk?）
2. 哪些行为证明该风险？（What behavior proves that risk?）
3. 原始 artifacts 和 original events 在哪里？（Where are the raw artifacts and original events?）

WebUI 与报告联动契约：上传流程创建 job 并进入 live monitor 后，动态分析完成时应提供
automatic current-language report navigation，按当前中/英文 dashboard 语言打开对应报告。
该报告入口应由 upload flow opened automatically by the upload flow，但 dashboard/request
仍应 leave the dashboard tab running the analysis request；操作者也必须能从监控页和
progress-page 重新进入报告，避免自动打开失败时丢失上下文。

## 报告章节 / Report sections

`report.html`、`report.zh.html` 和 `report.en.html` 必须包含以下章节。
`report.html` 是默认简体中文兼容报告；显式英文入口仍是 `report.en.html`。

- 封面 / Cover：包含 job id、生成时间、verdict、样本身份和 hashes。
- 目录 / Table of contents。
- 快速导航 / Quick navigation：面向高频章节的 sticky subnav：
  Risk、Process、Files、Network、R0、VT、Artifacts 和 Raw events。计数应代表当前嵌入证据，
  不得暗示 R0 health、collector self-noise 或 VT lookup status 是恶意行为。
- 风险摘要 / Risk summary：方形摘要面板。
- 行为命中 / Behavior detections。
  每个 finding 应显示 evidence count，并提供原生 `<details>` “Top evidence / 关键证据”块，
  其中包含可复制的高信号事件，便于分析员无需先打开完整 raw table 就理解规则命中。
  主行为 verdict 必须排除仅静态 triage、采集诊断、R0 unavailable/health rows、
  VirusTotal/reputation findings；这些信号应放在专门的质量或信誉章节。
- MITRE 映射 / MITRE mapping。
- 引擎与规则命中 / Engine/rule hits。
- 静态分析 / Static analysis：包含 PE sections、URLs、strings、warnings 和 tags。
  静态 resource 证据应消费 `static.pe.resource`：展示 resource type/name/language、
  size、RVA、entropy、embedded-PE/payload-candidate 等字段，并明确这是静态 triage，
  不是已观察到的 guest 行为。
- 动态分析 / Dynamic summary。
- VirusTotal 信誉 / VirusTotal reputation：VT 是可选 hash-only 信誉 enrichment。
  缺失 API key、限速、未收录响应或 lookup transport status 属于 enrichment 质量/状态，
  不是沙箱观察到的恶意行为。
- 行为图谱与 IOC 摘要 / Behavior graph and IOC summary：使用稳定、弱交互的图谱视图，
  从 normalized telemetry 推导 process-to-file、process-to-registry、process-to-network
  和 process-to-artifact edges。必须包含 Narrative spine、Evidence story board、Top behavior chain、
  Evidence graph edges 和 IOC summary panels，使最终报告像分析员可读的沙箱报告，
  而不是纯 raw table。Evidence story board 应在密集事件表之前，把 dropped files、
  screenshots、memory dumps、PCAP/network、process lineage 和 R0 health/noise boundary
  作为可复制、可折叠 lane 展示。
- 时间线 / Timeline：使用 timeline grouping 让突发遥测按时间顺序可读；按稳定时间桶分组，
  展示 event count 和 event-family summary，inline 时间线按设计保持有界；完整证据仍在
  raw events 和 report JSON。
- 进程详情 / Process details：包含 process tree、process relationship tree、process relationship panels
  和 process event table。树应优先使用 stable process key / 稳定 process key，缺失时回退 PID/PPID，使 parent、
  child 和 orphan relationship 无需 JavaScript 也稳定可读。Process tree overview 应展示
  node/root/edge counts 与默认展开的高信号节点，并在展开 lineage 前排除 self-noise。
  Process relationship cards 应在事件表之前提供中文优先的紧凑证据摘要，并把与该进程相关的
  dropped files、screenshots、memory dumps 和 PCAP/source artifacts 作为有界、可复制、可打开/下载的
  related artifact evidence 展示，而不是要求操作者去 raw event wall 中手工关联。
- 文件行为 / File behavior：包含 dropped files。
  落地文件行（dropped-file rows）应由 Evidence story board 和 Artifact collection status lanes 加强展示，
  确保 raw file activity 很嘈杂时，释放出来的文件仍然可见。
- 证据文件链接 / Artifact links：当 job 目录存在对应文件时，必须包含 `events.json`、
  `driver-events.jsonl`、artifact manifests、screenshots、dropped files、显式 opt-in 的
  memory dumps，以及导入的 `.pcap` / `.pcapng` packet captures。本章节还必须包含
  Artifact collection status panels，用于 dropped files、screenshots、memory dumps、
  packet captures 和 driver events。这些面板应从 indexed artifacts 与 normalized telemetry
  汇总 captured、failed、skipped、partial、observed 或 not-observed 状态，让操作者即使在
  没有 artifact 文件时也能判断证据是否实际采集。
- 注册表行为 / Registry behavior。
- 网络行为 / Network behavior：网络分类视图（Network category view）应在 raw network rows 之前汇总
  endpoint groups 以及 DNS / HTTP / TLS / flow counts，让操作者无需打开完整 raw table
  也能读懂关系。PCAP / pktmon collection metadata、packet counts、conversion status 和
  imported DNS/HTTP/TLS/flow rows 也应出现在 Evidence story board 中，并保持可折叠、可复制，
  而不是只散落在 raw rows 里。存在 `sourceArtifact*` 或 packet capture hints 时，
  Endpoint cards 还应展示中文优先的紧凑摘要和关联 PCAP/source artifacts，并提供显式复制按钮
  以及面向 report-relative artifacts 的安全 Open/Download links。
- R0 与驱动事件 / R0 and driver events：
  R0 采集健康状态（R0 collection health status）必须出现在 driver telemetry evidence 之前。Device unavailable、
  driver health、queue backpressure 和 dropped-event counters 描述的是遥测质量，不能计入样本行为。
  Health alerts 可以作为采集质量警告（collection-quality warnings）高亮。R0 availability summary 应显示
  available、unavailable/degraded、attention-needed 或 absent-health-row 等采集质量状态，而不是恶意行为。
  归因到 `KSword.Sandbox.R0Collector.exe`、sandbox agent、collector staging paths 或 KSword driver device
  的 driver rows 属于 collection-side self-noise，必须从 behavior counts、behavior graphs 以及
  file/registry/network/process behavior sections 中排除，同时保留在 R0 self-noise summary 和
  Raw normalized events 中供审计。R0 health/unavailable examples 默认折叠并限制为少量代表样例，
  完整证据留在 raw events 和 `report.json`。
  `r0collector.driverNetworkStatus` 属于 R0/WFP/ALE readiness 诊断：展示
  supported/active layer masks、producer counters、degrade reason、readinessState
  和中文提示；不得把 IOCTL 不可用、degraded 或 queue/backpressure 诊断当作样本恶意行为。
- 失败原因 / Failure reasons。
- 原始标准化事件 / Raw normalized events。
  该章节默认折叠并限制行数；折叠表格之前应展示小型 `Raw event distribution / 原始事件分布`
  摘要，列出最高频 event types、sources 和 event families。UI 必须明确 raw evidence height limit，
  让操作者知道展开后的证据仍然有界。


## 报告渲染视觉契约 / Report renderer visual contract

最终报告渲染器应采用现代沙箱报告布局，而不是普通诊断 dump。视觉契约如下：

- 主强调色（primary accent color）：`#43A0FF`。
- 主要报告区域应渲染为方角面板，保留清晰间距、可读排版和面向操作者的 summary-first 流程。
  角半径保持方正（`0` 或 `2px`），避免使用阴影。
- 视觉嵌套最多保留一层明显容器。表格内不得再放嵌套 card stacks、圆角 pills 或卡片式 evidence blocks；
  改用 inline actions 和原生扁平 `<details>`。
- 每个主要 `section.card` 面板都要把大型证据集限制在约 `75vh` 加 `overflow:auto` 内，让 risk、
  behavior、MITRE、static、dynamic、timeline、process、file、registry、network、R0、failure
  和 raw event evidence 在演示时仍可导航。
- 每个有界主面板应保留 sticky section header，操作者滚动密集证据时不会丢失当前章节。
  Section chrome 采用 Microstep 风格的亮蓝节奏：`#43A0FF` accents、紧凑方形 step markers
  和 summary-first spacing。
- 重型事件表不仅要受整页面板限制，也要在章节内部有界。Renderer 内联代表性窗口
  （普通事件表当前为 80 行）、显示 hidden-row counts，并指向 Raw normalized events 或
  `report.json` 作为完整证据。
- 大型 static strings/warnings lists 默认视图要截断（当前 200 条），显示 hidden-entry count，
  并指向 `report.json`。
- 具有可信 `safeLink` 或安全相对路径的 Artifact evidence 应渲染为显式 Open/Download
  （`打开 / Open`、`下载 / Download`）按钮。任意 host/guest 绝对文件系统路径只能作为可复制
  evidence text 展示，绝对路径不得用于 `href`。
- Raw normalized events 章节默认保持轻量：渲染原生折叠 `<details>`，限制展开后 raw event
  面板高度，并只内联前 75 条 raw events。展开后的内联行必须拆成 25 行一页的原生分页，
  让分析员打开小块证据而不是长表格。章节必须展示 total events、inline-rendered events、
  inline page count、hidden raw events、Raw evidence height limit（当前 `58vh`），以及明确的
  `report.json` 和 raw source artifact path hints 作为完整证据入口。Raw page summary 还应展示
  closed/default state、native page count、row ranges 和 folded technical field counts，让分析员在
  展开分页前就理解 pagination / fold labels。
- Raw normalized events 还应包含静态 `原始事件页索引 / Raw event page index`，覆盖每一条
  normalized event，包括未内联渲染的行。索引按 event type、source 和 event family 分组，
  展示 first row / first inline page 或 `report.json only`，并提供可复制行范围。这样无需
  JavaScript，也不会把最终报告变成 app，就能让大型报告保持可导航。
- Raw event details 中的 command/stdout/stderr/PowerShell 以及类似长技术 payload 默认隐藏在可复制的
  原生 `<details>` 后。主报告不得直接铺开完整 command lines、script blocks、stdout 或 stderr；
  它们只能在操作者主动展开后复制。
- 普通事件行也使用同一 long-field policy：command line、stdout/stderr、PowerShell/script-block
  payloads、encoded commands 和其他大型字段即使不在 Raw normalized events 章节，也默认折叠。
- Raw event 展开和布局稳定性必须依赖原生 HTML/CSS，而不是 JavaScript。复制增强可以改善静态 HTML，
  但不能成为揭示证据的前提。
- 报告必须有 print/no-JS fallback：禁用 JavaScript 时，原生 `<details>` navigation、表格滚动、
  安全 Open/Download links 和 `@media print` 布局仍应可用。复制按钮可以依赖 JavaScript，
  但可见 evidence text、`report.json` 和 raw source hints 必须仍然可选中、可打印。
- 行为图谱与 IOC 摘要（Behavior graph / IOC summary）章节保持静态 HTML/CSS，并优先使用稳定的弱交互，
  而不是脆弱的 canvas/SVG rendering：紧凑 Narrative spine、Evidence story board、process graph nodes、
  有界 Top behavior chain、Evidence graph edges，以及 network、file/path、registry、artifact indicators 的
  IOC summary panels。
- Narrative spine 应在密集 graph tables 前提供四步、从左到右的紧凑证据叙事：execution root、
  storage changes、network scope 和 artifact proof。它必须有界、可复制、弱交互，并在
  `report.html` / `report.zh.html` 中保持中文优先。它应包含一条 Narrative spine summary 和显式
  Copy narrative spine 按钮，让分析员无需打开 raw event pages 即可复制完整 analyst story。
- Evidence story board 应 summary-first 且弱交互：每条 lane 必须展示紧凑 status badge、短 analyst narrative、
  3-8 个 metric chips，以及原生折叠 evidence block。必需 lanes 包括 execution lineage、
  dropped-file evidence、screenshot evidence、memory dump evidence、network/PCAP evidence
  和 R0 health/noise boundary。
- Artifact status、process cards 和 network cards 中的紧凑 evidence summaries 应先于密集表格可见，
  在默认简体中文报告中中文优先，并可通过显式按钮和右键复制。摘要使用有界 key/value summaries
  和紧凑 artifact lines，不要把完整 raw events 或完整 descriptor payloads 内联倾倒出来。
- Evidence summary cards、raw event distribution cards 和 raw event page index cards 也应提供显式
  Copy evidence summary / Copy distribution summary / Copy raw index summary 按钮，而不只依赖右键。
- Timeline 与 process relationship 视图也应优先采用稳定弱交互：原生 HTML/CSS timeline group panels、
  有界 process relationship tree 和可复制 relationship panels，而不是外部 graph JavaScript。
  Process tree rows 应先显示紧凑 process label，再显示 depth/key/children/activity badges 和截断的
  image/path hint；完整 event evidence 保持可复制，避免树视图变成 raw path wall。
- 报告必须支持中文和英文渲染入口，或在 core renderer 中等效支持 `report.zh.html` 与
  `report.en.html`。
- 新增 report chrome 发布前必须有简体中文映射。Quick navigation、VT lookups/status、
  collection health/status rows、health alerts、event-table caps、hidden evidence counts 等
  常见操作者文案不得在 `report.zh.html` 中保留大块英文。
- 简体中文报告应本地化操作者可见 chrome，包括 table headers、buttons、hints、section notes、
  empty states、status words 和 evidence-expander summaries。Raw evidence 必须保持原样：
  `eventType`、API names、schema keys/values、hashes、paths、command lines、stdout、stderr
  以及 JSON/JSONL previews 不翻译。
- 每个生成的 HTML report 都应提供报告内双语入口栏，链接同目录的 `report.zh.html`、
  `report.en.html` 和兼容 `report.html`，使本地文件查看与 WebUI served viewing 行为一致。
  入口栏应说明：`report.html` 是默认简体中文兼容报告，`report.en.html` 保留英文 operator chrome，
  两种报告里的 evidence values 都保持原样。
- Jobs 应保留适合 WebUI 自动链接的 report path fields，让完成后的 plan 能显示默认报告和本地化报告线索，
  无需操作者粘贴 filesystem path。
- WebUI 报告入口应对普通操作者保持 path-free：一个当前语言 primary report button、紧凑中英替代入口，
  以及动态分析或手动事件导入刷新成功后的自动当前语言 report navigation。
- 验证时应请求 served bilingual endpoints
  `/api/jobs/{jobId}/report/html?lang=zh` 和
  `/api/jobs/{jobId}/report/html?lang=en`，并要求返回 `text/html`。
  默认 `/api/jobs/{jobId}/report/html` endpoint 仍是兼容现有消费者的链接，默认应提供简体中文 report chrome。

## 证据交互 / Evidence interaction

证据行（Evidence rows）是操作者可见内容。Tables、timeline entries 和 raw evidence blocks
应支持快速复制：

- 右键（right-click）可复制单元格或 timeline item 的 evidence text。
- 点击 raw evidence 上的 `复制 / Copy` 按钮，复制完整 event block。
- Raw event fields 应排序后渲染在扁平可折叠 evidence block 中；command/output/script fields
  保持在嵌套可复制 `<details>` 内，避免大型 driver payloads 淹没页面。
- Raw normalized events 默认显示关闭的 summary，只内联前 75 行，并按 25 行一页的原生分页展示；
  页面必须明确告诉操作者隐藏了多少 events。
- Raw section 应在已索引时指向 `report.json`、`events.json`、`driver-events.jsonl`
  和/或 artifact manifests，让操作者有 raw source artifact path hints，可以打开或复制完整原始来源，
  而不是依赖超大的 HTML table。
- Indexed artifacts 应通过安全相对 report links 打开或下载。若只知道绝对 host/guest path，
  则显示为可复制 text evidence，而不是 clickable link。

## Live UI 预期 / Live UI expectations

WebUI live monitor 是独立 dynamic monitor page，由 main dashboard 链接；浏览器允许时，
upload flow 会自动打开它，操作者不需要让提交分析请求的 dashboard tab 一直停留。该页优先连接
`/api/jobs/{jobId}/progress/stream` 真实 runbook step SSE，不可用时回退
`/runbook/progress` polling 和 durable `runbook-progress.json`。在 analysis 完成并导入
guest output 前，不运行 behavior classification；live UI 只展示最终分类前的 raw events。
页面应同时展示 raw events、VT quiet/reputation card 和 artifact index/download card；当页面由
upload 打开时，双语提示应告知操作者分析请求已由后台接管，可在 monitor 页查看进度、VT 状态和证据下载。
Live table 应显示：

- timestamp / 时间戳
- `eventType`
- source / 来源
- process id/name / 进程 ID/名称
- path / 路径
- data / 数据：command/output 字段隐藏在可复制 details 中

证据文件面板（Artifact panel）应展示 artifact index 总数、root path policy、safe selector policy、download selector/href、
duplicate grouping 和 rejection diagnostics。只有来自 artifact index 的 job-relative selector 可以作为
下载入口；host/guest 绝对路径只能作为可复制 evidence text。

VT 面板应明确“hash-only，不上传样本”。缺 key、not-found、rate-limit、auth failure、timeout 或 transport
failure 是 quiet state，只显示在 reputation/health 区，不写默认 job log，不进入 behavior finding。

当 job 失败时，主 dashboard 应保持 report links、artifact paths、progress stage status、
failed step title/message、exit code 和 duration 可见。它不应内联长 runbook command text、
stdout 或 stderr；操作者可打开 execution-flow page，并复制 `runbook-execution.json` 进行深度排障。

主 dashboard 的 report navigation 应保持低噪音：一个当前语言 primary report button、紧凑的
中文/英文替代入口、生成/导入成功后的稳定 automatic open notice、progress summary 旁自然的
progress-page（`execution-flow`）链接，以及作为独立页面而非 inline stream 的 live raw monitor。
