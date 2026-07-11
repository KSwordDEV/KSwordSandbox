# 验证指南（verification）

验证默认应保持离线、可重复、低副作用：不启动 Hyper-V VM，不还原 checkpoint，不加载或安装驱动，
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

## Hyper-V 和 WebUI/API 验证

只读 Hyper-V readiness：

```powershell
.\scripts\Test-HyperVReadiness.ps1
```

该脚本只读：不启动 VM，不 restore checkpoint，不复制文件，不启用 integration service。自动化应读
`ReadinessSummary.LiveReady`、`FailedCheckIds`、`WarningCheckIds` 和 `ReadOnlyAssertions`。

WebUI/API safe E2E：

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
  -Live `
  -DurationSeconds 3 `
  -StepTimeoutSeconds 900
```

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
