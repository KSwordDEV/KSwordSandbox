# VMware 动态夹具批次（无哈希裁决）

本批次使用 `E:\Temp\KswordSandbox\malware-sample\dynamic-vmware-inputs-v2` 中的 10 个本地受控 Windows 行为夹具。它们只写测试目录、HKCU 测试 Run 值、临时计划任务或 TEST-NET 地址，不访问真实凭据，也不依赖样本哈希来生成结论。报告裁决只使用运行期归因事件；哈希和静态能力簇仅作为背景线索。

| 样本 | Job ID | 动态事件数 | 已进入报告的事件族 | 中文报告 |
|---|---|---:|---|---|
| `lab-combined-behavior.exe` | `b4745a32-6d5f-42b7-8092-9fa299dd3537` | 15 | file、process、registry.run、startup_item、startup | [report.zh.html](D:/Temp/KSwordSandbox/jobs/b4745a326d5f42b780929fa299dd3537/report.zh.html) |
| `lab-registry-run.exe` | `c1ce8d1c-7931-4801-8a31-ba6e4cf826b9` | 13 | file、process、registry.run、startup_item、startup | [report.zh.html](D:/Temp/KSwordSandbox/jobs/c1ce8d1c793148018a31ba6e4cf826b9/report.zh.html) |
| `lab-mutex-signal.exe` | `72440896-b602-484e-9edd-cd2f1f981648` | 7 | file、process | [report.zh.html](D:/Temp/KSwordSandbox/jobs/72440896b602484e9eddcd2f1f981648/report.zh.html) |
| `lab-network-probe.exe` | `1feb22d0-733b-494f-b2f4-6887d083e969` | 9 | file、process；网络未归因 | [report.zh.html](D:/Temp/KSwordSandbox/jobs/1feb22d0733b494fb2f46887d083e969/report.zh.html) |
| `lab-process-discovery.exe` | `d11d3637-584a-45f8-8b82-0783571d1456` | 6 | file、process | [report.zh.html](D:/Temp/KSwordSandbox/jobs/d11d3637584a45f88b820783571d1456/report.zh.html) |
| `lab-script-launch.exe` | `5d4cdb51-a537-471e-9def-13378a3fd184` | 7 | file、process | [report.zh.html](D:/Temp/KSwordSandbox/jobs/5d4cdb51a537471e9def13378a3fd184/report.zh.html) |
| `lab-file-drop.exe` | `c5548427-2e53-4e55-9b3d-026b0a1fee82` | 9 | file、process | [report.zh.html](D:/Temp/KSwordSandbox/jobs/c55484272e534e559b3d026b0a1fee82/report.zh.html) |
| `lab-file-rename-delete.exe` | `acb5d6d0-96b2-48e4-b7e7-2ca15db4b9ec` | 8 | file、process | [report.zh.html](D:/Temp/KSwordSandbox/jobs/acb5d6d096b248e4b7e72ca15db4b9ec/report.zh.html) |
| `lab-process-tree.exe` | `0f52c540-84a7-4a15-a171-57f950d88828` | 7 | file、process | [report.zh.html](D:/Temp/KSwordSandbox/jobs/0f52c54084a74a15a17157f950d88828/report.zh.html) |
| `lab-scheduled-task.exe` | `663512a5-1d6f-4286-a738-dce78eb5417d` | 7 | file、process | [report.zh.html](D:/Temp/KSwordSandbox/jobs/663512a51d6f4286a738dce78eb5417d/report.zh.html) |

## 证据边界

10 份报告均有样本进程启动、运行中/退出和文件差异；组合夹具和注册表夹具还出现 HKCU Run 与启动项差异。当前批次使用 `-NoR0Collector`，因此 TEST-NET 连接、互斥体和部分子进程行为可能只在静态能力线索或原始 guest JSONL 中出现，不能被报告写成已观测网络/内核行为。失败的旧作业目录不在上表，也不计入批次结果。
