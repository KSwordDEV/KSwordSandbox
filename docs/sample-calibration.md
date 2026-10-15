# 公开样本行为校准清单

更新时间：2026-10-15  
用途：给 KswordSandbox 的报告和 WebUI 做行为归因、噪声过滤和版式验收。

## 使用边界

本清单只引用公开的 ANY.RUN 沙箱报告页面和报告中公开的 SHA-256。没有下载、解压、执行或保存任何恶意二进制文件；样本应通过哈希或报告 URL 作为身份键。报告页面可能因为重新分析、网络环境或用户操作而变化，因此本表记录的是页面在校准时可见的行为摘要，不是新的恶意判定。

建议把下表导入测试夹具时只保留 `sampleId`、家族、预期高信号行为、允许的噪声分类和来源 URL。不要把命令行、脚本、C2 内容或 payload 写入默认报告；需要追溯时再从原始报告打开。

## 样本与预期结果

| # | 样本 / 家族 | SHA-256（公开报告身份） | 已观察到的行为结论 | 应被计为高信号的事件 | 预期噪声 / 不应提升为样本结论 | 来源 |
|---:|---|---|---|---|---|---|
| 1 | Remcos (`remcos.exe`) | `ea8020c029ee419c056c1b3c078441c9e5389ec02ec28dbac371d728c1508768` | 报告标注 Remcos RAT；进程连接动态 DNS 主机和外部 IP 查询服务，命中 Remcos JA3/TLS C2。 | `remcos.exe` 外连、TLS JA3、C2 域名/DNS。 | `svchost.exe` 的 mDNS/广播、Windows 共享地址、Skype/系统网络初始化。 | [ANY.RUN 报告](https://any.run/report/ea8020c029ee419c056c1b3c078441c9e5389ec02ec28dbac371d728c1508768/138b2457-9a1e-4c93-bce5-5f614c79f832) |
| 2 | Remcos (`remcos_a.exe`) | `e429617e07aa878054f5c61228233a8f154df34320decaba12fc0690aa9fe103` | 报告命中 Remcos 网络木马和 Remcos 3.x/4.x TLS 指纹；可见 ngrok 动态 DNS。 | `remcos_a.exe` 的 TLS/C2、ngrok DNS、连接目标。 | `Skype.exe` 对 `skype.com` 的白名单连接；系统进程产生的重复 DNS 行。 | [ANY.RUN 报告](https://any.run/report/e429617e07aa878054f5c61228233a8f154df34320decaba12fc0690aa9fe103/ed1b29f5-d5bf-4570-9855-10da783e0d53) |
| 3 | Lumma Stealer（AutoIt loader） | `6e968bb42cc7d78b2df0dab652b94499ed1be732d0c18f36cd3372270ecf6596` | 报告标注 Lumma 信息窃取器；样本为 PE/NSIS 形态并带 AutoIt、loader 标签。 | Lumma 进程、浏览器/钱包/凭据读取（若采集到）、外连和落地载荷。 | AutoIt/NSIS 启动器自身的解包、临时目录文件、沙箱启动进程。 | [ANY.RUN 报告](https://any.run/report/6e968bb42cc7d78b2df0dab652b94499ed1be732d0c18f36cd3372270ecf6596/baf7a128-d3eb-4ff3-9bbf-e4b7c6cfc79b) |
| 4 | Lumma (`lumma.exe`) | `f0ae27d10fbefaa1c7c8dd286c1def26f48d0be5a412337b59615b64c5ec4968` | 报告命中 Lumma C2 检测，列出 Lumma 关联域名和 check-in。 | Lumma 进程的 TLS SNI、C2 check-in、关联域名。 | `svchost.exe` 代发 DNS、沙箱代理产生的重复网络告警、浏览器正常联网。 | [ANY.RUN 报告](https://any.run/report/f0ae27d10fbefaa1c7c8dd286c1def26f48d0be5a412337b59615b64c5ec4968/7cffc077-6d1e-4ffb-b5fd-3f4273ba9329) |
| 5 | Agent Tesla（.NET） | `24d29087cd9eeec19d7ccd087f2a7d6bb33a1c8cad5519b6e399235e7d1f39b7` | 报告标注 Agent Tesla/Stealer；说明其记录键盘和用户交互并窃取信息。 | Agent Tesla 进程、键盘/凭据读取、外传连接。 | .NET CLR/Mono 初始化、系统检查、报告页面的家族说明文本。 | [ANY.RUN 报告](https://any.run/report/24d29087cd9eeec19d7ccd087f2a7d6bb33a1c8cad5519b6e399235e7d1f39b7/4bdba5c5-b258-4f9f-92cd-4132921fcf89) |
| 6 | AgentTesla 压缩包 | `ddd91fb87bbd6fe8f521424782d1c3e7e3ec6b4496c20ada65abb874e152b139` | 解压后落地 `AgentTesla.exe`；报告命中 FTP 外传、主机名/CPU 信息泄露和 Agent Tesla C2。 | 解压出的 AgentTesla 进程、FTP 上传、主机/CPU 信息出站。 | WinRAR 解包、`updater.log`、`ip-api.com` 外部 IP 查询（单独看不算窃取）。 | [ANY.RUN 报告](https://any.run/report/ddd91fb87bbd6fe8f521424782d1c3e7e3ec6b4496c20ada65abb874e152b139/d0504716-39ed-4aca-882e-34415387fb24) |
| 7 | Agent Tesla（SMTP 外传） | `a66429ccd03b43ece44da4841bbfb0239e3bd8046d19a4663cb1d5b4cb176b94` | 报告命中 Agent Tesla 凭据窃取并通过 SMTP 外传；另有外部 IP 查询。 | SMTP/587 外传、窃取成功事件、恶意目标域名。 | `svchost.exe` 的 LLMNR/mDNS、`api.ipify.org` 本身的普通外部 IP 查询。 | [ANY.RUN 报告](https://any.run/report/a66429ccd03b43ece44da4841bbfb0239e3bd8046d19a4663cb1d5b4cb176b94/9bdfa175-9346-4835-a738-f48d35933252) |
| 8 | RedLine Stealer | `f113ba3fee099fb98aa02f415c3a594e96076adca2deed41892742f18dee3e8f` | 报告命中 RedLine/MetaStealer TCP C2，并有恶意 IP 通信。 | `Redline.exe` C2 连接、RedLine 家族规则、可疑外传。 | `SearchApp.exe` 对 Bing 的白名单访问、系统启动网络活动、重复 IDS 告警。 | [ANY.RUN 报告](https://any.run/report/f113ba3fee099fb98aa02f415c3a594e96076adca2deed41892742f18dee3e8f/21112a60-a568-400d-b2b9-1a2b1233164d) |
| 9 | FormBook / XLoader | `a1aac69e61fbf0ab4f4d04092f73857d04743117f74b0b78dddc0c382659390a` | 报告将样本标为 FormBook；PE32 .NET 组件，带 `netreactor`、`xloader` 标签。 | FormBook/XLoader 进程、浏览器/凭据/键盘访问、C2。 | .NET/NetReactor 解密和运行时初始化、正常临时文件。 | [ANY.RUN 报告](https://any.run/report/a1aac69e61fbf0ab4f4d04092f73857d04743117f74b0b78dddc0c382659390a/85429be7-2895-41a3-bdc1-54cfcdb66ed1) |
| 10 | XWorm | `ced525930c76834184b4e194077c8c4e7342b3323544365b714943519a0f92af` | 报告命中 XWorm；创建启动目录文件、修改 Run 自启动、使用任务计划，并做外部 IP/环境检查。 | Run 键、Startup 目录、Task Scheduler、XWorm 规则、C2/载荷落地。 | 读取机器 GUID、语言、安装日期、IE 设置；这些是侦察信号，但单独不应给出“窃取成功”。 | [ANY.RUN 报告](https://any.run/report/ced525930c76834184b4e194077c8c4e7342b3323544365b714943519a0f92af/e74cb38f-6823-47f7-8e36-f9aa66e9ad1f) |
| 11 | njRAT Danger Edition | `0572b75e548423c3b3feb5bfbf3a84135d4b8ec8a736f5e83951107d3d7518a2` | RAR 解包后落地并加载 njRAT；报告命中加载重写的可执行文件。 | 解包后的 njRAT 进程、落地/重写 EXE、持久化或 C2（若出现）。 | WinRAR 父进程、手工启动、读取计算机名/语言、调试版文件提示。 | [ANY.RUN 报告](https://any.run/report/0572b75e548423c3b3feb5bfbf3a84135d4b8ec8a736f5e83951107d3d7518a2/3129cd3e-9233-4605-af60-fadaa94088e4) |
| 12 | NJRat（防火墙/持久化） | `7a84dd83f4f00cf0723b76a6a56587bdce6d57bd8024cc9c55565a442806cf69` | 报告命中 NJRAT YARA；样本使用 `NETSH.EXE` 修改防火墙规则并落地可执行文件。 | NJRat YARA、NETSH 防火墙变更、可执行文件落地。 | 读取计算机名/语言、系统服务进程、沙箱启动器。 | [ANY.RUN 报告](https://any.run/report/7a84dd83f4f00cf0723b76a6a56587bdce6d57bd8024cc9c55565a442806cf69/89cfc5a0-b0bb-4afc-a031-7b323b0e95d1) |
| 13 | SmokeLoader | `b6109a6afc225dd0879bb25914b2b57d95b6fa21feab17ccf30ce11e0efc604f` | ZIP 样本在报告中启动后立即落地可执行文件；网络关闭的场景仍能观察到 drop 行为。 | 解压后的 SmokeLoader/子载荷、立即落地和后续执行链。 | WinRAR 解包、URL 快捷方式或用户手工打开行为；网络关闭导致的“无 C2”不能解释为安全。 | [ANY.RUN 报告](https://any.run/report/b6109a6afc225dd0879bb25914b2b57d95b6fa21feab17ccf30ce11e0efc604f/b2580eac-010a-401a-a3e4-b32b9f829302) |
| 14 | 恶意 PDF 初始载荷 | `499d6ca50d3e6ebbba3ee692a65a8fa40b228e93ca0ed9f267e7dae86ac9e07d` | PDF 报告标为恶意活动；Office 尝试下载 payload，另有协议处理器检查和截图能力。 | PDF/Office 触发的下载、子进程、URL/文件落地。 | Acrobat/浏览器手工打开、字体/渲染、读取 IE 设置、截图检测规则本身。 | [ANY.RUN 报告](https://any.run/report/499d6ca50d3e6ebbba3ee692a65a8fa40b228e93ca0ed9f267e7dae86ac9e07d/c89d4e20-7e47-46ae-9c3b-221fee998424) |

## 噪声分层与验收规则

### 直接保留为样本行为

- 样本进程或其明确子进程产生的 C2/TLS/DNS、凭据/键盘读取、外传、持久化、落地载荷、任务计划、Run 键和防火墙变更。
- 家族规则（例如 Remcos、RedLine、Agent Tesla、XWorm、NJRAT）只有在报告中与样本进程或样本哈希关联时才进入主结论；孤立的签名文本放到静态/信誉区域。
- “进程启动”本身只是时间线事实。`agent.start`、沙箱手工点击、WinRAR/浏览器启动等不能单独算作恶意事件。

### 只保留在证据区，不提升为主结论

- `svchost.exe`、`System`、浏览器、Office、WinRAR、Acrobat 产生的环境初始化、mDNS/LLMNR、白名单站点访问和普通外部 IP 查询。
- 采集器自身、R0/驱动健康、队列、代理、网络仿真器和沙箱准备阶段的事件。这些事件用于诊断采集质量，计数时不归因到样本。
- 只有“读取机器名、语言、GUID、DMI、安装日期、环境变量”时，显示为“环境侦察”；没有伴随样本进程、外传或持久化证据时，不显示“窃取成功”。

### 报告和 WebUI 的最小验收

1. 选择任意一行样本，默认先看到家族、风险、3--8 条代表性证据和来源链接；原始事件放在可折叠详情中。
2. 过滤器至少支持：家族、行为类别（执行/持久化/文件/网络/凭据）、信号级别（高信号/环境噪声/采集噪声）、报告来源。
3. 事件表显示“样本归因”“环境噪声”“采集质量”三个明确类别；`agent.start`、`svchost`、R0 health 和 VT 状态不能混进恶意命中数。
4. 空结果要写明“未采集到 sample-attributed evidence”，不能用空白表格暗示样本安全；网络关闭时要保留“未观察到网络行为（环境限制）”说明。
5. 表格详情使用足够宽的横向区域，长命令、脚本、stdout/stderr 默认折叠；中文优先，英文原文作为可复制字段。

## 分析失败与“没有观察到行为”的边界

第三方报告中的 `Malicious activity` 只代表提交或静态信誉结论，不代表动态采集一定成功。导入到 KswordSandbox 时建议单独显示以下失败或不完整标记：

- **格式不受支持 / 未执行**：报告写明 `unsupported file type`、`rejected`、`error` 或任务没有启动样本进程。此时只能显示静态/信誉证据，不能把空的动态事件表解释为“样本无行为”。
- **网络被关闭或代理不可用**：报告环境显示 `Network: off`、Fakenet/代理失败或只采集到本地启动。网络 lane 应显示“未观察到网络行为（环境限制）”，同时保留文件、进程和注册表证据。
- **样本未触发 / 运行时间不足**：只有手工启动、父进程初始化或沙箱超时，没有样本子进程、落地文件和后续活动。标为“证据不足/需要复测”，不要降级成“安全”。
- **只有环境或规则文本**：出现家族说明、YARA 标签、`agent.start`、VT 信誉、R0/驱动健康或报告页面元数据，却没有样本归因事件时，主结论应为“未采集到 sample-attributed evidence”。
- **采集器失败**：设备不可用、队列丢弃、collector 自身进程或 staging 路径异常只标在“采集质量”；必须保留失败原因和计数，但不计入风险行为。

UI 可以把这些状态压缩为“动态成功 / 动态部分成功 / 未执行或不支持 / 采集失败”四种筛选值。这样审查员能区分“分析失败”与“样本在该环境中确实没有继续活动”，也不会因空表或大量启动行而误判。

## 建议的本机无害对照

真实样本条目用于验证恶意行为归因；下面三个本机对照用于验证噪声边界，不应标成恶意：

- **Notepad / 记事本**：启动、窗口、短暂临时文件和正常退出；用于确认 `agent.start`、GUI 进程和收集器自噪声不会生成行为命中。
- **签名的 7-Zip 或 WinRAR 解压一个无害文本**：会有归档读取、临时目录和子进程；用于确认“解压/落地”只有在样本归因、后续执行或规则证据同时存在时才提升。
- **系统浏览器打开普通 HTTPS 页面**：会产生 DNS、TLS、缓存和多个浏览器子进程；用于确认白名单网络、代理探活、mDNS/LLMNR 和浏览器初始化不会被算作 C2。

这些对照只需保存事件摘要和哈希，不需要把任何可执行样本放进仓库；与上表 14 个公开报告组合后，可同时验收高信号召回和噪声抑制。

## 来源与复现说明

- 所有样本均来自 [ANY.RUN public malware reports](https://any.run/malware-reports/)，报告页面提供公开样本哈希、环境、Verdict、Behavior activities 和网络/文件摘要。
- 本次校准使用报告页面的静态内容，未调用样本下载接口，也未在本机或 KswordSandbox VM 中执行样本。若后续要做动态回归，应在隔离快照中按哈希拉取样本，并把“下载、执行、网络策略、快照 ID”写入单独的实验记录。
- 公开报告结果受操作系统、网络开关、沙箱手工操作和时间影响。校准重点是事件归因和噪声边界，不把第三方报告的 verdict 当作本机引擎结论。
