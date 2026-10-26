# 破坏性样本行为矩阵去重（2026-10-26）

本页把[21 个候选](destructive-sample-catalog-2026-10-26.md)和已取得的密封归档按**可独立检验的破坏机制**收敛。一个机制先保留一个代表；同一份样本若实际覆盖两个机制，不为第二个机制重复运行。家族名、归档文件名和公开报告都不是本机动态证据。真实代码只能在无网卡、零宿主共享的可丢弃 VM 克隆内执行，实体机严禁执行。

## 收敛结果

| 独立机制与验证重点 | 唯一代表 | 当前可用性 | 并入/暂不单独排队的候选 |
| --- | --- | --- | --- |
| **逐文件加密/改名与勒索产物**：受控文件前后哈希、扩展名、说明文件，区分真实加密与仅有静态字符串。 | **Thanos**，内文件 SHA-256 `5D40615701C48A122E44F831E7C8643D07765629A83B15D090587F469C77693D`。 | 密封归档及来宾哈希已核；隔离 VM 完整运行，48 个诱饵中 36 个出现 `.locked`，并有勒索说明文件。修正规则并用同一份原始证据重建后，原生报告为 `Completed`、身份 `valid`，产生文件加密和勒索信两类高危发现；采集健康仍为 `partial`（当前包无 R0）。 | **Cerber** 仍保留为本组替代/对照：已在产品直传路径完成运行，但本轮 48 个诱饵无加密、无说明文件，不能由此推断该家族不加密。Jigsaw 的早期中转探针被来宾拦截；WannaCry 加密器、HermeticRansom（14）、Crucio（19）与本组信号重叠。离线单 VM 不评价 SMB 传播。 |
| **文件级覆写/删除**：受控文本和二进制的局部内容损毁、删除、强制重启前的最后证据。 | **DynoWiper A（1）**，SHA-256 `835b0d87ed2d49899ab6f9479cddb8b4e03f5aeb2365c50a51f9088dcede68d5`。 | 目前只有元数据和原始研究，**样本字节未取得**；取得并在 VM 核对哈希前不入执行队列。 | DynoWiper B（2）仅保留“无强制重启/5 秒等待”回归用途；DoubleZero（7）、IsaacWiper DLL（13）、SwiftSlicer（15）、FlockWiper（20）、WhisperGate 阶段 2（9）先不作为独立文件破坏覆盖。它们各自的 .NET、DLL 或多阶段前提应列为兼容性/前置条件，而非新破坏机制。 |
| **MBR/启动流程篡改**：原始扇区变化、异常重启、重新开机失败和 Agent/Tools 失联时间线。 | **RedBoot**，内文件 SHA-256 `1001A8C7F33185217E6E1BDBB8DBA9780D475DA944684FB4BF1FC04809525887`。 | 第三次 VM 运行已取得样本启动证明，随后来宾重置；48 个诱饵和身份均核实，但 `events.json`、`agent-summary.json`、`agent.exit` 未回收，原生报告为 `partial`。第二次运行只取得 S4U Agent PID 和 08:54:26.751Z 来宾请求硬重置的 VMware 日志，缺样本启动证据。**两次均无直接 MBR/扇区变化证据，不能计为此机制命中**。 | WhisperGate 阶段 1（8）、NotPetya（11、21）与它在本机 MBR/重启信号上重叠；NotPetya 经典文件是 DLL，入口点和加载语义不同，离线单 VM 也不能验证传播。 |
| **原始磁盘/分区直接擦除**：与普通文件 API 事件分开，需 VM 层磁盘前后只读比对。 | **CaddyWiper 原始（3）**，SHA-256 `a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea`。 | 有针对同一哈希的研究，**字节未取得**。R0 驱动在当前 VM 缺失，因此即便运行，也不得把未观察到的原始盘写入算作真阴性。 | CaddyWiper 变体（4）、HermeticWiper 两构建（5、6）、GigaWiper（18）先不重复跑。Shamoon 密封归档有两个未核身份的成员；确认其中独立擦除器后可替换本代表，但两者不同时排队。驱动加载可作这个机制的细分诊断，只有证明现有代表无法测到时才加 HermeticWiper。 |
| **整盘加密/第三方磁盘驱动部署**：DiskCryptor 组件、服务/驱动、重启后的卷可访问性，不能用逐文件高熵规则替代。 | **Mamba / HDDCryptor**，已核成员 `131.exe` 的 SHA-256 `2ECC525177ED52C74DDAAACD47AD513450E85C01F2616BF179BE5B576164BF63`。 | ZIP 已封存；7-Zip 与 Python `zipfile` 两种宿主只读流式解码均确认单一成员 `131.exe`、2,415,104 字节、MZ 文件头及同一内部哈希。**仅身份已核，未执行**；归档没有其他成员，但运行时部署依赖和参数尚未证实，需先评估前置条件。 | NotPetya 的 MFT/MBR 破坏不能代替整盘加密；不再为普通文件加密样本增加一个“磁盘加密”计数。 |
| **恢复抑制**：删除卷影/备份的命令尝试与实际系统状态变化分别记录。 | **Prestige（10）**，SHA-256 `5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57`。 | 同哈希公开分析可核，**字节未取得**。若同组已实测的具体样本直接证明此机制，则由该样本覆盖，取消 Prestige 的单独运行。 | 不能从 Cerber、Thanos 或 WannaCry 的家族描述推定特定归档成员会删除卷影；也不能把 `vssadmin` 命令行出现等同于卷影已删除。 |
| **可执行文件感染/多态改写**：无害 EXE 副本的代码段/入口点前后差异，与普通文件覆写区分。 | **Azov 新版（17）**，SHA-256 `650f0d694c0928d88aeeed649cf629fc8a7bec604563bca716b1688227e0cc7e`。 | 原始逆向研究明确同一哈希，**字节未取得**；须用无价值 EXE 副本，复核时间触发与样本角色。 | Azov 旧版（16）能力基本重叠，只留为版本回归；不能把普通自复制或改写数据文件等同于 PE 感染。 |

因此，**不是 21 个家族/哈希就要跑 21 次**。逐文件加密只保留 Thanos 一个当前代表：它已在 48 个诱饵中的 36 个留下 `.locked`，还生成勒索说明文件；作业完成且身份有效。修正规则后的报告给出高危结论。Cerber 是同机制对照：先前实验室中转路径被来宾文件防护阻断，后来产品直传路径的作业已完成，但该次没有观察到诱饵加密；不能把它记成第二份加密覆盖，也不能推断 Cerber 家族行为的普遍边界。RedBoot 已有启动证明及来宾重置，仍缺回收事件与磁盘前后比对，所以不计 MBR/擦除命中。Mamba 身份已核，只进入运行依赖和部署链评估队列；其余代表按取得字节和条件满足后逐个增加，不拿同族重复样本凑数量。

### 已审计的代表及替代样本尝试

| 样本 / job | 已证实 | 未证实及矩阵处理 |
| --- | --- | --- |
| Thanos，`24bd8e6c-1ea3-496f-9d75-85d710337027` | 来宾哈希与密封成员相同；`sampleStarted=true`，48 个诱饵中 36 个变为 `.locked`，存在 `HOW_TO_DECYPHER_FILES.txt`。作业回滚并清除宿主临时明文；修正规则后原生报告 `Completed`、身份 `valid`，给出 36 个不同文件配对与 2 处勒索信的高危证据。[原生中文报告](E:/Temp/KSwordSandbox-Lab-20261026/runs/sealed-real/imports-thanos-corrected-20261026/jobs/24bd8e6c1ea3496f9d7585d710337027/report.zh.html)。 | 最初报告漏判高危，已在同一 job 原始证据上修复并重建，无须为修正规则再次执行样本。采集健康仍为 `partial`，原因是 R0 健康数据缺失及最终队列状态未知；不把这个部署能力限制混作加密行为未发生。 |
| Cerber，`0ec32d6b-9eca-4841-969b-77f9e7cce9a1` | 产品直传到 `C:\KSwordSandbox\incoming` 的路线已测；归档与来宾哈希相符，原生报告 `Completed`、身份 `valid`，有 `process.start` PID 8392、子进程 `netsh advfirewall set allprofiles state on` 和约 1 秒后的退出码 0。48 个诱饵无变化、无勒索说明文件；回滚与明文清除完成。[原生中文报告](E:/Temp/KSwordSandbox-Lab-20261026/runs/sealed-real/jobs/0ec32d6b9eca4841969b77f9e7cce9a1/report.zh.html)。 | 只可说**这次离线 VM 运行未观察到加密**，不可推定该家族或此成员在其他触发条件下不加密；亦无恢复抑制证据。它是 Thanos 的同组对照，不增加独立机制覆盖。采集健康仍为 `partial`（无 R0），但诱饵终态是独立的文件证据。 |
| Cerber，`29b331c1-8100-4faa-b5b1-251eef846f5f` | 已校验归档及内文件 SHA-256；早期实验室探针以数据复制到隔离 VM 的 `C:\Users\Public\cerber.exe`，失败后关机回滚、宿主临时明文清除。[失败报告](E:/Temp/KSwordSandbox-Lab-20261026/runs/sealed-real/vmware-isolated-cerber-29b331c181004faab5b1251eef846f5f/report.zh.html)。 | 来宾 `setup-result.json` 在中转路径 `File.OpenRead` 返回病毒/潜在垃圾软件阻断，`sampleStarted=false`。这是实验室中转路线与来宾防护状态的问题；后续产品直传已另行完成，不能用此早期失败评价产品路线或病毒行为。 |
| RedBoot，`d8ec6732-6bb8-44fd-be8d-9afd16bdc7e2` | 哈希与固定成员相同，48 个诱饵就绪，`sampleStarted=true` 且独立的样本启动证明已回收；随后来宾重置。实验环境已回滚并清除宿主临时明文。[部分报告](E:/Temp/KSwordSandbox-Lab-20261026/runs/sealed-real/jobs/d8ec67326bb844fdbe8d9afd16bdc7e2/report.zh.html)。 | `events.json`、`agent-summary.json`、`agent.exit` 未回收，原生报告 `partial`。没有直接 MBR/原始扇区差异或完整进程事件链，不能将重置等同于启动区破坏；这是重启边界下的采集缺口。 |
| RedBoot，`34c91597-2d65-495d-a270-d5fd0dfb1c73` | 来宾 SHA-256 与固定内文件哈希相同；48 个诱饵共 196,608 字节已创建；S4U Agent 发布 PID。VMware 日志 `vmware.log` 在 2026-10-26 08:54:26.751Z 写有“guest has requested ... hard reset”；最终关机回滚、宿主临时明文清除。[失败报告](E:/Temp/KSwordSandbox-Lab-20261026/runs/sealed-real/vmware-isolated-redboot-34c915972d65495da270d5fd0dfb1c73/report.zh.html)。 | 缺 `process.start`、`events.json`、`agent-summary.json`、`agent.exit`，`sampleStarted=false`。硬重置的发起进程与磁盘变化未证实，不能把该日志直接归因 RedBoot 或计为 MBR/擦除命中；此条保留为早期审计记录。 |

### 当前问题归因边界

| 现象 | 当前归类 | 下一项可证伪检查 |
| --- | --- | --- |
| Thanos 初版报告为 0 个高危，尽管诱饵已被改写且产生说明文件。 | **产品规则问题，已修复**：在同一 job 原始证据上重建报告，确认 36 个不同文件配对和 2 处勒索信为高危；重复文件监视通知不会复用同一原文件来放大计数。 | 完整烟测与重复通知负例已通过；后续样本继续核对文件前后状态与报告证据链。 |
| Thanos、Cerber 的 `CollectionHealth=partial`，原因含 R0 健康信息缺失。 | **当前发布/部署包的采集能力限制**，不能归咎于这台 VM 的单项设置；文件终态证据仍可独立评价。 | 在发布部署路线中验证驱动是否提供、安装、加载与回报健康；报告要明确区分用户态观察和原始磁盘不可见。 |
| Cerber 首轮 `C:\Users\Public` 读取被拦，随后产品直传 `C:\KSwordSandbox\incoming` 可完整运行。 | **实验室中转路线加来宾防护异常**；首轮失败不代表产品直传失败。后一次 48 个诱饵无变化是该次样本/触发条件的观察结果。 | 将两个 job 分开保留；对后一次只陈述本机终态，不把无加密写成家族真阴性。 |
| RedBoot 启动后重置，最终缺事件、Agent 摘要和退出记录。 | **重启边界证据回收缺口**；重置发起原因和 MBR 变化仍未验证，不能先归因为 VM 配置或样本具体破坏动作。 | 在仍隔离的可丢弃克隆上做 VM 层磁盘前后只读比对，并核查重启前事件落盘与重启后回收链。 |

## 合并规则与恢复重复样本的条件

1. 只看**受控对象上的机制**：文件哈希/存在性、磁盘扇区或分区结构、VSS 状态、PE 结构，而不是家族名称、勒索字样或公开标签。同一个样本可以覆盖多列，覆盖必须由本机直接证据证明。
2. 每个代表先跑一份。若结果是“样本未启动”“需要另一个阶段”“对应采集通道缺失”或“来宾防护拦截”，这不是该机制的真阴性；可换同组备用样本，但必须记录替换原因，不能把两者均计为独立机制覆盖。
3. 同族 A/B、旧/新构建仅在修复规则后做**回归**，或验证已明确提出的时间线差异；不会计入新增破坏机制。DynoWiper A/B、CaddyWiper 两变体、HermeticWiper 两构建、Azov 旧/新尤其如此。
4. 断网单 VM 不能评价横向传播、C2 或外部共享传播。WannaCry、NotPetya 的传播标签不进入当前矩阵分母；必要时另设计可封闭的多机网络实验，而不是在本克隆上改开网卡。
5. 当前用户态包缺 R0，规则集中有文件删除、文件写入和勒索扩展名/恢复抑制信号，但没有足以独立证明原始扇区、MBR 或分区覆写的专用高置信结论。对这两列应以 VM 层只读磁盘比对和采集缺口同时报告；不能用“高风险”封面反推所有预期破坏动作都被采到。

## 状态纠偏与公开分析边界

早期[候选清单](destructive-sample-catalog-2026-10-26.md)与[归档清单](additional-sealed-samples-2026-10-26.md)保留了当时“未取得/未核内文件”的时间点，不能直接当作当前状态。随后宿主仅作**数据解码与哈希**，确认 Jigsaw、RedBoot、Cerber、Thanos 内文件 SHA-256；Mamba 的 `131.exe` 又经 7-Zip 和 Python `zipfile` 双流式核验，并在来宾确认 NotPetya DLL 的 `027cc450...`。宿主从未执行恶意样本。Jigsaw 与 Cerber 的早期实验室中转路径在来宾读取时被拦截；Cerber 后续产品直传完成且可评价本轮终态。一次性来宾准备轮次的 `MpCmdRun -ResetPlatform` 退出码为 0，重启后 `Get-MpPreference` 列出 `C:\KSwordSandbox\incoming` 排除路径，但同轮 `engineHealthy=false`；这是来宾防护健康异常，不再作为 Cerber 产品直传不可行的结论。RedBoot 第二次尝试无样本启动证据，第三次有启动证明但因重置丢失事件及 Agent 退出记录；两者均不能证明 MBR/擦除行为。Thanos 的诱饵加密已观察到，初版报告漏判高危；修正规则后已在同一份原始证据上重建并判为高危。R0 缺失及 RedBoot 重启后的证据回收则需分别作为采集/环境限制记录。每次实测的最终状态以该 job 的原始事件、任务报告与回滚记录为准。

机制选择参考原始研究：[Cerber 变体及备份差异](https://www.mcafee.com/blogs/blogs/other-blogs/mcafee-labs/unfolding-the-mystery-of-cerber-ransomwares-random-file-extension/)、[DynoWiper A/B](https://security-labs.elastic.co/security-labs/dynowiper)、[RedBoot](https://digital.nhs.uk/cyber-alerts/2017/cc-1673)、[CaddyWiper 同哈希](https://www.ibm.com/think/x-force/caddywiper-malware-targeting-ukrainian-organizations)、[Mamba/DiskCryptor](https://securelist.com/the-return-of-mamba-ransomware/79403/)、[Prestige 同哈希](https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/)、[Azov 两版本](https://research.checkpoint.com/2022/pulling-the-curtains-on-azov-ransomware-not-a-skidsware-but-polymorphic-wiper/)。公开家族行为用于确定待验观察点；**不证明此处封存成员具有相同行为，也不替代 VM 本机结果**。
