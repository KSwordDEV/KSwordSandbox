# 三样本动态报告门禁

`scripts/Test-ThreeSampleCoverage.ps1` 只读取已有的 `report.json`，不启动虚拟机，也不执行样本。它把“报告中没有报错”与“报告已经证明采集完整”分开：任意无法证明的指标都会标记为 `FAIL`，不会被当作未检出。

运行示例：

```powershell
pwsh -NoLogo -NoProfile -File scripts/Test-ThreeSampleCoverage.ps1 `
  -JobRoot D:\Temp\KSwordSandbox\jobs\job-a,D:\Temp\KSwordSandbox\jobs\job-b,D:\Temp\KSwordSandbox\jobs\job-c `
  -OutputPath D:\Temp\KSwordSandbox\three-sample-coverage.md
```

门禁要求每份报告同时满足：

- `CollectionHealth` 存在，且 R0 丢失、R0 丢失行、ETW `EventsLost`、ETW 丢失行、失败行、ETW 解码失败、计划任务采集失败和 pktmon 停止失败都明确为 `0`。
- `rawEventsPath` 与 `driverEventsPath` 分别存在并可读取。两个路径不能互相替代。
- 存在 `driver` 来源事件或 `events.sources.driver` 指标；R0 计数不能只由 Host 行代替。
- ETW 有大于 `0` 的 `parsedEventCount`。`etlDecodeRequired=true`、解析计数为 `0` 或计数缺失都会失败。
- `packet_capture` 的 `protocolParserNotImplemented` 不得为 `true`。
- `process.tree_unavailable` 必须为 `0`。
- 样本归因的 `process.exit` 必须返回 `0`；例如 `0x80131700` 会失败。
- 动态动作分解必须闭合：`attributedRaw + rawUnknown == raw`，`attributedReport + unattributedReport == report`，且 `attributedOmitted == 0`、`raw == report`。这能识别采集后在归因或报告采样层丢行的情况。

覆盖测试不触碰 VMware：

```powershell
pwsh -NoLogo -NoProfile -File tests/ThreeSampleCoverageGate.Tests.ps1
```

测试覆盖缺失 `CollectionHealth`、独立原始路径、ETW 解析计数为零、ETL 解码缺口、协议解析未实现、样本非零退出码和动态动作分解不闭合等失败场景。
