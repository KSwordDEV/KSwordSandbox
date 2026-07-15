# 验证指南（verification）

验证默认应保持离线、可重复、低副作用：不启动任何 provider VM，不还原 clean baseline，不加载或安装驱动，
不调用 `CSignTool.exe`，也不提交任何构建/运行产物。

## 快速离线质量门（fast synthetic gates）

优先跑目标质量门：

```powershell
.\scripts\Test-QualityGates.ps1
```

当其他 worker 正在改产品项目，而你只需要用已构建依赖重新编译 smoke-test assembly 时：

```powershell
.\scripts\Test-QualityGates.ps1 -NoDependencies
```

该脚本构建 `tests/KSword.Sandbox.SmokeTests` 并默认运行：

- `report.r0collector-self-noise.contract`
- `artifacts.manifest.contract`
- `rules.schema-collection-health.guard`

等价的直接命令：

```powershell
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj --no-build -- --scenario report.r0collector-self-noise.contract --scenario artifacts.manifest.contract --scenario rules.schema-collection-health.guard
```

列出可用 scenario ID：

```powershell
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj -- --list-scenarios
```

## VirusTotal（VT）低噪音验证

VT 相关验证重点不是“联网成功”，而是确保 hash-only、缺 key 安静、信誉状态不污染主行为告警：

```powershell
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj --no-build -- `
  --scenario behavior.rules-virustotal-quality `
  --scenario report.health-reputation.contract `
  --scenario rules.schema-collection-health.guard
```

这些 scenario 应确认：

- `not_configured`、`rate_limited`、`authentication_failed`、timeout/lookup failure 不写入主行为列表。
- VT status 属于 reputation/enrichment health，不直接映射 ATT&CK。
- 只有 `found` / `not_found` 这类真实查询结果才可持久化为 enrichment evidence。
- 缺少 `KSWORDBOX_VIRUSTOTAL_API_KEY` 时不写 job message、规则 evidence 或噪音日志。

## .NET build 与全量 smoke

常规源码验证：

```powershell
dotnet build .\KSwordSandbox.sln --nologo
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj --no-build
```

不要提交 `bin/`、`obj/`、test logs、runtime job 输出或生成报告。

## Native compile-only 验证

Native/R0 默认只做 compile-only：

```powershell
.\scripts\Invoke-NativeBuild.ps1 -Project .\KSwordSandbox.sln -Configuration Debug -Platform x64
```

注意：

- 正常验证应保持 `SignMode=Off` / compile-only。
- 不要调用 `CSignTool.exe`，不要使用旧 KSword signing wrapper。
- 不要提交 `x64/`、`.sys`、`.pdb`、`.obj`、native `.exe` 或任何签名材料。
- 真实 driver load 只属于隔离 VM test-signing 分支，不属于默认 CI/smoke。

## Provider 和 WebUI/API 验证

只读 Hyper-V readiness：

```powershell
.\scripts\Test-HyperVReadiness.ps1
```

该脚本只读：不启动 VM，不 restore checkpoint，不复制文件，不启用 integration service。自动化应读
`ReadinessSummary.LiveReady`、`FailedCheckIds`、`WarningCheckIds` 和 `ReadOnlyAssertions`。

WebUI/API safe E2E：

默认通过 WebUI 实际使用的后台 runner 执行（`/runbook/start` 后轮询
`/runbook/background`），summary 中的 `executionTransport=Background` 用于证明没有退回
legacy blocking endpoint；`backgroundState`、guest import 三态及终态 provider/VM/基线/VMX/磁盘
身份共同保留实际后台链路证据。脚本还会在 plan 前调用所选 provider 的只读
`/api/host/readiness?refresh=true&provider=...`：Live 要求 Windows 与硬件加速明确就绪，并把
Windows feature、管理工具、查询、VM/baseline、guest transport 和 diagnostic 字段写入 summary。
Live 还会在 plan 前解析完整 `gitCommit`，并记录 `gitDirty`、`gitChangedFileCount`、
`gitCommitSource`、`gitProvenancePath`、`runtimeRoot`、`generatedAtUtc` 与带时区偏移的
`generatedAtLocal`，以及 `sampleSha256`、`sampleSizeBytes`、`requestedDurationSeconds`。从不含 `.git` 的正式 runtime package 执行时会读取
`package-manifest.generated.json`；手工复制且没有 manifest 的目录必须显式传入完整的
`-GitCommit <40-or-64-hex>`，但其 dirty 状态无法证明，不能用于最终等价声明。若当前目录同时存在
checkout，其 HEAD 必须与参数一致。来源或 runtime root 无法确认时，不会进入 VM 变更阶段。
发布级三 provider 验收必须加 `-RequireCleanSource`，让 dirty、状态未知或非零变更数在 VM 变更前失败。
只有兼容旧调用链时才显式传 `-ExecutionTransport Blocking`。

```powershell
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 120
```

这个默认路径不启动、不还原、不停止 VM。Live E2E 会修改配置 VM，只能在 elevated PowerShell、guest
password 和 readiness 都满足后执行：

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<SandboxUser password>'
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -Provider HyperV `
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900
```

同一入口也可显式验收 VMware 或 QEMU：

```powershell
.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -Provider VMware `
  -VmName 'KSword-VMware' `
  -BaselineName 'Clean' `
  -MachineDefinitionPath 'D:\VMs\KSword\KSword.vmx' `
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900

.\scripts\Invoke-WebUIApiE2E.ps1 `
  -BaseUrl 'http://127.0.0.1:18082' `
  -Provider Qemu `
  -VmName 'KSword-QEMU' `
  -BaselineName 'per-job-overlay' `
  -MachineDefinitionPath 'D:\VMs\KSword\base.qcow2' `
  -QemuDiskFormat qcow2 `
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900
```

输出 summary 会记录 provider、逻辑 VM、实际运行 VM、baseline、VMX/基础磁盘和 QEMU 格式，
并校验 execution 仍使用 plan 中的 provider/VM 身份。未传资源覆盖时，Live readiness 还必须确认
配置 profile 的 provider 查询、VM 与 baseline；传入 VM/VMX/磁盘等 per-job 覆盖时，summary 会记录
`providerResourceOverrideUsed=true`，宿主加速与 guest transport 仍必须就绪，具体覆盖资源由 runbook
preflight 在任何 VM 变更前验证。

发布级三 provider 等价验收必须让三次命令使用同一份样本文件和时长，并分别写入
`hyperv-summary.json`、`vmware-summary.json`、`qemu-summary.json`。三次都成功后运行只读聚合校验；它不会启动、停止或恢复 VM：

```powershell
.\scripts\Test-ProviderParityEvidence.ps1 `
  -HyperVSummaryPath 'D:\Temp\KSwordSandbox\parity\hyperv-summary.json' `
  -VMwareSummaryPath 'D:\Temp\KSwordSandbox\parity\vmware-summary.json' `
  -QemuSummaryPath 'D:\Temp\KSwordSandbox\parity\qemu-summary.json' `
  -OutputPath 'D:\Temp\KSwordSandbox\parity\provider-parity-validation.json'
```

校验器要求相同完整 commit、clean source、相同 SHA-256/字节数/请求时长、三个不同 job id、
`Background`/`completed` 终态，并回读每个 `runbook-execution.json` 与 `report.json` 核对
provider、VM、baseline、VMX/磁盘身份、执行成功、Completed 报告和样本身份。最终交付物必须是
`schema=ksword.provider-parity-evidence.v1` 且 `validated=true` 的 JSON，并保留每份 summary 与所引用
执行/guest/report 文件的 SHA-256；三份摘要本身不能替代该聚合结果。

脚本式 Hyper-V E2E 的安全 review：

```powershell
.\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -PlanOnly

.\scripts\Invoke-HyperVE2E.ps1 `
  -SamplePath 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe' `
  -Live `
  -WhatIf
```

`PlanOnly` 和 `WhatIf` 都不修改 VM；真正 `-Live` 会 restore/start/copy/run/collect/stop/restore。

## 综合验证入口（full validation）

本地综合入口：

```powershell
.\scripts\Invoke-FullValidation.ps1
```

它覆盖 solution build、全部 smoke、live telemetry contract、local WebUI/API pipeline smoke、Hyper-V
E2E PlanOnly/WhatIf、native x64 compile-only、readiness contracts 和 repository policy。

文档/只读 worker 可按需跳过昂贵或环境相关步骤：

```powershell
.\scripts\Invoke-FullValidation.ps1 -SkipNative -SkipLocalPipelineSmoke -SkipReadiness
```

不要给综合验证传 `-SignNativeDriver` 或任何 signing 参数，除非明确进入隔离 VM 的真实驱动实验。

## 仓库策略和提交前检查

提交前至少运行：

```powershell
git status --short
git diff --check -- README.md docs
.\scripts\Test-RepositoryPolicy.ps1
```

只检查已暂存内容：

```powershell
.\scripts\Test-RepositoryPolicy.ps1 -StagedOnly
```

仓库策略会阻止 VM disks、samples、reports、binaries、DPAPI backups、`install-state.json`、secrets 和
大文件入库。文档任务不要 stage 或 commit 构建产物，也不要 push。

## 覆盖范围

- Report synthetic/golden assertions：隐藏 R0Collector 自身 file/registry self-noise，同时在 R0/raw
  evidence 中保留可审计证据。
- Artifact manifest：`artifact-manifest.json`、guest `artifacts/manifest.json`、`artifact-index.json`
  的 schema/version、collection、artifact、metadata、safe selector 形状稳定。
- Rules schema 与 collection-health guard：`behavior-rules.json` 使用受支持字段、唯一 ID、合法
  severity、typed predicates；R0/VT collection-health 行保持 info-level metadata，不带 ATT&CK 映射。
- Hyper-V readiness：用机器可读字段证明 live 前置条件和只读保证。
