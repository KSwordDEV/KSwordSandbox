# 开源沙箱与行为矩阵参考

本文记录 KSwordSandbox 行为规则、报告结构、动态采集与 UI 体验的公开参考来源。目标不是整仓复制，而是把成熟沙箱的“行为语义”和“报告组织方式”落到本项目的 Windows / Hyper-V / R0 采集链路中。

## 主要参考

- CAPE Sandbox signatures：CAPE 把签名用于从分析结果中识别恶意行为模式或关注的 IOC，强调用签名为分析结果提供上下文并辅助自动化 triage。参考：<https://capev2.readthedocs.io/en/latest/customization/signatures.html>
- Cuckoo Sandbox signatures：Cuckoo 的 signatures 机制同样面向“预定义行为模式识别”，适合映射到本项目 `rules/behavior-rules.json` 的单事件和组合事件规则。参考：<https://github.com/cuckoosandbox/cuckoo/blob/master/docs/book/customization/signatures.rst>
- CAPEv2 项目：CAPE/Cuckoo 路线强调 Windows 动态行为、取证 artifacts、配置和 payload extraction，可作为 dropped files、网络、报告章节组织参考。参考：<https://github.com/kevoreilly/CAPEv2>
- DRAKVUF Sandbox：DRAKVUF Sandbox 是基于 DRAKVUF 引擎的自动化黑盒分析系统，强调不需要 guest agent 的 hypervisor-level 采集；本项目 v1 不强制实现 agentless VMI，但可借鉴其插件/行为维度和 artifact 思路。参考：<https://github.com/CERT-Polska/drakvuf-sandbox>
- DRAKVUF：DRAKVUF 定位为 virtualization-based agentless black-box binary analysis system，可作为后续 Hyper-V/VMI 路线的长期参考。参考：<https://drakvuf.com/>
- DRAKVUF Sandbox basic usage：其文档指出插件越多越影响性能，插件选择需要在覆盖率和性能间折中；本项目 R0/Guest 采集也应保持按需开关，例如截图、内存 dump、PCAP。参考：<https://drakvuf-sandbox.readthedocs.io/en/v0.19.0/usage/basic_usage.html>
- MITRE ATT&CK Windows Matrix：Windows 平台技术矩阵是规则映射基准，规则必须尽量映射到明确 technique，collection-health、VT reputation、采集失败等诊断事件不强行映射。参考：<https://attack.mitre.org/matrices/enterprise/windows/>
- MITRE ATT&CK technique pages：新增 technique 必须按官方 technique name 写入 `rules/mitre-windows-map.json`，例如 Odbcconf (`T1218.008`)、MMC (`T1218.014`)、Security Software Discovery (`T1518.001`) 和 Credentials In Files (`T1552.001`)。参考：<https://attack.mitre.org/techniques/T1218/008/>、<https://attack.mitre.org/techniques/T1218/014/>、<https://attack.mitre.org/techniques/T1518/001/>、<https://attack.mitre.org/techniques/T1552/001/>
- SigmaHQ 规则规范与公开 Windows 规则思路：Sigma 的 `detection`/`condition`/`falsepositives`/`level` 结构适合转换成本项目的 event type + path/command/data predicates + exclusion guard + severity/confidence 元数据；只吸收可泛化的检测思想，不复制规则文本。参考：<https://sigmahq.io/docs/basics/rules.html>、<https://github.com/SigmaHQ/sigma/tree/master/rules/windows>
- Elastic detection rules：Elastic 公开规则库可作为 Windows 持久化、进程注入、横向移动、PowerShell/LOLBin、网络 C2 与误报控制的参考家族；本项目只借鉴规则组织、字段约束和 ATT&CK 对齐方式，不复制查询或描述文本。参考：<https://github.com/elastic/detection-rules>、<https://www.elastic.co/guide/en/security/current/prebuilt-rules.html>
- Splunk Security Content：Splunk 的 analytic story / detection / investigation 组织方式适合参考到 release notes、行为矩阵分组和 triage 描述；本项目不复制 SPL，只保留通用行为语义和 ATT&CK 映射思路。参考：<https://github.com/splunk/security_content>、<https://research.splunk.com/>

## 已映射到本项目的方向

1. 规则机制
   - `rules/behavior-rules.json` 采用 signature-like 规则，覆盖持久化、注入、下载执行、横向移动、反沙箱、凭据访问、防御规避、C2/网络行为。
   - `RuleEngine` 已支持更多 all-of 谓词，避免 CAPE/Cuckoo 类规则常见的单字符串误报。
   - v15 将公开 Sigma/LOLBAS 风格的 Windows 代理执行与 API 监控思路落到三个高约束规则：`odbcconf-regsvr-user-writable-dll-proxy-execution`、`mmc-user-writable-msc-proxy-execution`、`named-pipe-impersonation-api-observed`。这些规则要求 event type 加命令行/API/路径上下文，并显式排除 KSword/R0Collector/VT 采集噪声。
   - 2026-07-12 的 release-facing 规则扩展把 SigmaHQ、Elastic detection rules、Splunk Security Content 与 MITRE ATT&CK 作为“灵感家族”：参考其持久化、注入、横向移动、反沙箱、下载执行、凭据/外传和网络 triage 维度，但规则 ID、谓词、字段组合、中文摘要和 false-positive guard 均按 KSwordSandbox 事件模型重新编写。

2. 报告结构
   - 报告分为风险摘要、行为命中、MITRE 映射、静态分析、动态分析、进程树、文件、注册表、网络、R0、证据文件、raw events。
   - raw events 默认折叠/分页；证据以可复制 details 展开，避免像调试日志一样把命令行/stdout/stderr 塞满页面。

3. 采集与 artifacts
   - Guest Agent/R0/Host importer 输出统一 `SandboxEvent`。
   - dropped files、screenshots、memory dumps、PCAP/PCAPNG、driver JSONL、events.json 都进入 artifact index。
   - 高成本能力按需启用，尤其是截图、全进程内存 dump、PCAP、R0 网络 producer。
   - DRAKVUF 的 `apimon`、`filetracer`、`procmon`、`socketmon`、`tlsmon`、`regmon`、`delaymon` 等插件维度，对应本项目的 `api.call`、`driver.file`/`file.*`、`process.*`、`network.*`/`pcap.*`、`registry.*` 和 `antiAnalysis.*` 事件族。新增 named-pipe impersonation 规则即预留给 API monitor / typed sidecar 行消费。


## 2026-07-12 release-facing 行为扩展说明

当前规则集通过 38 条 release-facing 行为规则和 19 条补充高信号规则覆盖以下能力：

- 持久化：LSA authentication package、AppInit/AppCert DLL、BootExecute、Time Provider、WMI event subscription、COM InprocServer hijack、print monitor、Active Setup。
- 注入：R0/driver/API monitor 风格的跨进程内存写、远程线程、QueueUserAPC、section map execute、suspended-process hollowing、LSASS handle access。
- 横向移动：admin share executable copy、PsExec service ImagePath、WinRM remote target、WMI remote process create、RDP shadow / RestrictedAdmin。
- 反沙箱：CPUID/hypervisor、VM registry key、analysis-tool process query、long sleep / time skew。
- 下载执行：Certutil URL cache、BITS transfer、PowerShell WebClient 到用户可写路径、Mshta/Regsvr32 remote scriptlet、Rundll32 URL/DLL entrypoint。
- DNS/HTTP/TLS/PCAP：DNS TXT long-label exfil、NXDOMAIN/DGA burst、HTTP executable payload magic、small periodic POST beacon、Host/SNI suspicious metadata、self-signed/invalid TLS、no-SNI rare JA3、SMB admin-share session setup。
- 补充高信号规则：scheduled-task logon/start 和 RunLevel-highest 持久化、App Paths/Netsh helper registry 持久化、direct syscall / NTDLL unhook / process doppelgänging / sensitive-process memory write、admin-share copy / remote service / svcctl named-pipe lateral movement、PowerShell/BITS download-execute、browser credential DB copy、LSASS MiniDumpWriteDump、credential archive staging、large authenticated HTTP upload、Base64-like DNS exfil 和 risky TLS JA3/new-domain 元数据。

开源参考边界：SigmaHQ、Elastic detection rules、Splunk Security Content 和 MITRE ATT&CK 只作为检测家族、字段约束、误报控制和技术映射参考；不复制规则正文、查询语句、SPL/EQL/KQL、描述文本或测试样例。落地到本项目时必须转换为 `SandboxEvent` event type、path/command/data predicates、`evidenceFields`、severity/confidence 和 KSword/R0Collector/VT 噪声排除。

## 2026-07-11 v15 落地说明

本轮只做“开源行为矩阵/规则参考”最小闭环，不引入 Core/Web/Guest/Driver 改动：

- ATT&CK map 新增 `T1218.008 Odbcconf` 与 `T1218.014 MMC`，补齐公开 LOLBin/系统二进制代理执行子技术的规则映射。
- `odbcconf-regsvr-user-writable-dll-proxy-execution`：吸收 ATT&CK Odbcconf 与 Sigma/LOLBAS 思路，只在 `odbcconf` + `REGSVR` + 用户可写 DLL 同时出现时触发，避免单独命中正常 ODBC 配置命令。
- `mmc-user-writable-msc-proxy-execution`：只在 `mmc` 加载用户可写路径 `.msc` 时触发，不把常规系统管理控制台使用提升为高危。
- `named-pipe-impersonation-api-observed`：面向 DRAKVUF/CAPE 类 API 监控输出和公开 Sigma 思路，要求命名管道名加 `ImpersonateNamedPipeClient`/`RpcImpersonateClient` 证据，并排除浏览器/KSword 常见管道噪声。
- Smoke 覆盖新增 `behavior.rules-open-source-reference`，只验证 JSON/规则/映射和合成事件，不跑 Hyper-V 或重 E2E。

4. UI/用户体验
   - 上传后立即进入 live monitor，展示真实 runbook step、VT hash-only 结果、raw event monitor、artifact downloads。
   - 最终判断仍以 HTML 报告为准；live monitor 只做实时观察，不提前归类。

## 后续扩容清单

- 增加 CAPE/Cuckoo 风格的组合行为规则：下载后执行、脚本解释器链、压缩包释放执行、Office/宏链；新增时优先用 `allContains*`、`dataContainsAll`、regex/numeric/absent-key 组合，避免单字段宽匹配。
- 增加 DRAKVUF 风格的系统行为维度：进程、模块加载、注册表、文件、网络、截图、人机交互/窗口行为；高成本插件或 sidecar 输出保持可选。
- 继续将规则映射到 MITRE Windows techniques；无法明确映射的 reputation/health/diagnostic 保持 info 或 enrichment，不计入主行为风险。
- 把 PCAP sidecar / tshark / native parser 的网络事件标准化为 `dns.query`、`http.request`、`tls.connection`、`network.flow`。
