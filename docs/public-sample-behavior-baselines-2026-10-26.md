# 公开样本行为基线与本机报告对照（2026-10-26）

本页用于**校准检测覆盖**，不是本项目的动态实测报告。只引用公开分析者自己运行或逆向所得的一手资料；精确 SHA-256 相同才称为“同一文件基线”。即使字节相同，操作系统、权限、联网、运行时长、启动参数、诱饵文件和防护软件不同，也可能使行为不同。公开沙箱的“恶意”结论不能替代本机 `process.start`、原始事件和回滚证据。所有恶意样本只能在无网卡、零 HGFS 的可丢弃克隆内运行。

## 已找到的精确文件基线

| 样本 SHA-256 | 一手来源与实验条件 | 该来源**实际观察或分析**到的信号 | 本项目应对照的信号与边界 |
| --- | --- | --- | --- |
| Jigsaw `3AE96F73D805E1D3995253DB4D910300D8442EA603737A1428B613061E7F61E7` | [ANY.RUN 同哈希 60 秒报告](https://any.run/report/3ae96f73d805e1d3995253db4d910300d8442ea603737a1428b613061e7f61e7/de764616-d289-4df6-b1ae-89da4e0188e0)，Windows 7 x86，联网开启。 | 样本进程 PID 1560 将同哈希可执行文件落到用户 `AppData\Roaming\Frfx\firefox.exe` 和 `AppData\Local\Drpbx\drpbx.exe`，写入 HKCU Run `firefox.exe`，并从新位置启动；该次报告记录 0 次 HTTP/TCP/DNS。 | 对照样本启动、子进程、自复制、用户目录可执行落地、Run 项和样本归属。**不能**因为本项目短窗口没看到周期性删文件就直接判漏采：该公开运行只持续 60 秒且未给出此哈希在该次运行中发生定时删除的证据。当前本机 Jigsaw 尝试在启动前受来宾文件读取拦截，不能拿它与这些动态信号评分。 |
| RedBoot `1001A8C7F33185217E6E1BDBB8DBA9780D475DA944684FB4BF1FC04809525887` | [ANY.RUN 同哈希报告](https://any.run/report/1001a8c7f33185217e6e1bdbb8dba9780d475da944684fb4bf1fc04809525887/753993f3-5581-4be6-96ee-d1b1f22c8fa0)，Windows 10 19044 x64，60 秒，联网和自动 UAC 确认开启；[BleepingComputer 原作者对同哈希安装器的分析](https://www.bleepingcomputer.com/news/security/ransomware-or-wiper-redboot-encrypts-files-but-also-modifies-partition-table/)。 | 公开沙箱看到 `assembler.exe`、`protect.exe`、`overwrite.exe` 等子进程，`.locked` 文件，`overwrite.exe` 接触 `\Device\Harddisk0\DR0`；原作者分析指出解出 `boot.asm/main.exe/overwrite.exe/protect.exe`、编译 `boot.bin`、覆盖 MBR，之后可能重启显示勒索画面。 | 对照父子进程、落地文件、批量改写/`.locked`、物理盘写入、重启和采集终止。**本项目之前的 RedBoot 尝试只有来宾哈希与 Agent PID，缺少 `process.start` 和事件/退出文件，故动态行为仍未获证**。VM 若在覆盖 MBR 后失去 Tools，报告必须保留“采集被中断”，不能写“无行为”。公开沙箱的自动 UAC/联网与本机 Block 环境不同。 |
| Cerber `E67834D1E8B38EC5864CFA101B140AEABA8F1900A6E269E6A94C90FCBFE56678` | [分析者自己的 Flare-VM/Cuckoo 实验记录](https://ily455.github.io/writeups/cerber-ransomware-lab/)明确给出同哈希、619,008 字节的 packed `cerber.exe`；Windows 10 无互联网 Flare-VM 与 Windows 7 InetSim Cuckoo 两条环境。 | 记录运行时动态解析 DLL/API，启动 `netsh.exe` 修改防火墙，尝试 UDP 6893 通信；枚举目录，读/加密/写回文件，再重命名为**随机文件名与随机扩展名**，并生成 HTA/TXT 赎金说明。 | 对照进程树 `netsh`、防火墙/注册表变更、文件读写与高熵批量重命名、赎金文档和 `mshta`。该**具体版本不能用固定 `.cerber` 扩展名规则作为唯一及格线**；Block 设计不会产生成功外联，至多比较尝试事件。当前本机 Cerber 仅准备了固定哈希隔离脚本，尚无可评分动态报告。 |
| WannaCry `ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA` | [同哈希 Windows 10 隔离实验](https://github.com/vincenzocasano00/wannacry-malware-analysis/blob/main/README.md)及其[动态记录](https://github.com/vincenzocasano00/wannacry-malware-analysis/blob/main/dynamic-analysis.md)；[LogRhythm Labs 原分析](https://logrhythm.com/wp-content/uploads/2020/03/wannacry-ransomware-analysis-logrhythm-labs-threat-intelligence-report.pdf)将该哈希列为 encrypter。 | 第一份实验认为该**精确文件**是加密器部分，未观察到 EternalBlue/SMB 自传播；它将网络爆发流量另用历史 PCAP 测试。 | 对照加密器本身的文件修改、勒索物、启动链与退出；**不要要求这个文件在零网卡 VM 产生 SMB 蠕虫传播**。本机封存 ZIP 的内部哈希仍需来宾核实，且尚未有本项目成功启动证明。 |
| NotPetya `027CC450EF5F8C5F653329641EC1FED91F694E0D229928963B30F6B0D7D3A745` | [Carbon Black/VMware 原始技术分析](https://blogs.vmware.com/security/2017/06/carbon-black-threat-research-technical-analysis-petya-notpetya-ransomware.html)明确给出同哈希、362,360 字节、PE32 **DLL**；[Hitachi 实验网络中运行同哈希的记录](https://www.hitachi.com/en/hirt/publications/hirt-pub/hirt-pub17010/)。 | 分析指出需调用 DLL ordinal 1 才执行主逻辑，按权限切换 MBR 或用户态文件加密；涉及 `perfc.dat`、物理盘、凭据/横向移动。Hitachi 实验还记录向其他主机端口探测。 | 本项目 WebUI v1 只接收 `.exe`，普通 EXE 启动不能等价于 DLL ordinal 1；当前是**发布产品的格式/启动方式缺口**，不能据一次普通上传无行为判漏采。零网卡实验也不能期待横向移动成功。应先证明专门 DLL 启动器与来宾实际 ordinal 1 执行，再评分磁盘/文件/进程信号。 |

### 证据等级与避免误判

- **A：精确文件动态基线**：来源同时展示 SHA-256、运行环境与可核对行为。Jigsaw、RedBoot 的 ANY.RUN 记录属于这一档；Cerber 的原始实验记录也明确 packed 文件哈希及动态序列。
- **B：精确文件静态/逆向基线**：哈希相同，但某些步骤来自代码分析；它说明能力和合理预期，不保证在本机条件下必然执行。RedBoot 原作者、NotPetya 的部分路线属于这一档。
- **C：家族或近似变体**：只写家族名、归档名或不同哈希的资料。可用于设计采集器，不得作为该文件逐项“漏检”判据。Mamba、Shamoon、Thanos 的封存归档仍有未核内部成员，暂不建立精确行为评分。

## 每次本机运行的逐项对照模板

每条机制单独填写，不把家族多个变体的共同传说合并成一个测试义务。

| 字段 | 记录方式 |
| --- | --- |
| 身份 | 归档 SHA-256、来宾内文件 SHA-256、文件类型/架构、上传路径、公开来源的精确哈希是否一致。 |
| 激活 | 来宾 `process.start` 或 DLL export 调用证明、PID/父进程、提权与退出码；无此证明只记“未启动/未知”。 |
| 环境 | Windows build、运行时长、权限、Defender/过滤驱动、网卡/HGFS、R0/ETW/文件观察器、诱饵文件与快照。 |
| 公开预期 | 来源 URL、观察或逆向的区别、来源运行窗口和网络条件、具体机制及其证据。 |
| 本机观测 | 原始事件路径、时间、PID/样本归属、规则 ID/置信度、报告路径、采集健康和回滚结果。 |
| 差异结论 | `匹配`、`来源仅能力未发生`、`本机未激活`、`环境阻断`、`窗口不足`、`采集缺失`、`归因缺失`、`规则缺失`、`来源不确定`之一；每项附原始证据。 |

**目前可下的结论**：校准程序的 VM 实测已证明 Run 自启动和文件观察链可给出高风险判定；真实恶意样本的上述公开行为仍须按每个已成功启动的本机 job 独立核对，不能从公开分析反推本机已经采到。
