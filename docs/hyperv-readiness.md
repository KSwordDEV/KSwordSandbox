# Hyper-V 就绪预检（readiness preflight）

`scripts/Test-HyperVReadiness.ps1` 用于在 live Hyper-V runbook 启动 VM、运行样本和导入报告前，验证
宿主机与 golden VM 的最低前置条件。脚本设计为只读：不创建 runtime probe 文件，不创建/还原 checkpoint，
不启动/停止 VM，不复制文件，也不修改 integration service 设置。

## 运行预检

在 Hyper-V host 的 elevated PowerShell 中运行：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

Windows PowerShell 也可用：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

完成 `./install.ps1` 或兼容包装器 `./scripts/install.ps1` 后，无参数命令会复用与 `run.ps1` 相同的本机
配置。配置路径解析顺序为：

1. 显式 `-ConfigPath`；
2. `Sandbox__ConfigPath`（Process/User/Machine scope）；
3. `%ProgramData%\KSwordSandbox\install-state.json` 中的 `localConfigPath`；
4. 仓库 fallback：`config/sandbox.example.json`。

读取到 config/install state 后，未显式绑定的 VM、checkpoint、guest、payload、runtime 参数会用本机状态或
配置值补齐。使用 `-IgnoreInstalledConfig` 可忽略 installed config，只使用显式参数和 repository example
fallback。

完全显式命令：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestUserName 'SandboxUser' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -GuestPayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

如果只想为本次预检输入一次 guest password，而不持久化到 User/Machine 环境：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1 `
  -PromptForMissingGuestPassword
```

该 prompt 只写当前 PowerShell Process scope，不写 `%ProgramData%`、User environment、config JSON、report 或
仓库文件。可重复部署请优先使用：

```powershell
.\install.ps1
.\install.ps1 -Mode Change -ResetPassword -PromptPassword
```

## 输出契约（output contract）

脚本输出结构化 PowerShell objects：

- 多个 `ReadinessCheck`：每项包含 `CheckId`、`Category`、`Status`、`RequiredForLive`、
  `MachineReadable`、`Details`、`Remediation`。
- 一个 `ReadinessSummary`：包含 `ContractVersion`、`Kind`、`OverallStatus`、counts、
  `FailedCheckIds`、`WarningCheckIds`、`LiveReady`、`ReadOnlyAssertions`、`RecommendedActions`、
  `RemediationHints` 和 `ExitCode`。

Exit code：

- `0`：没有 check 的 `Status = Failed`。
- `1`：至少一个 check 失败。

自动化不要解析展示文本，应优先读取：

```powershell
$results = & .\scripts\Test-HyperVReadiness.ps1
$summary = $results | Where-Object { $_.ResultType -eq 'ReadinessSummary' }
$summary | Select-Object OverallStatus, LiveReady, FailedCheckIds, WarningCheckIds, ReadOnlyAssertions
```

`ReadOnlyAssertions` 会明确记录：没有写 probe file、没有执行 VM mutation command、没有启动 VM、没有还原
checkpoint、没有启用 Guest Service Interface、没有打印 secret value。

## 只读保证

即使以 Administrator 身份运行，preflight 也只查询状态。它可能调用 Hyper-V read APIs；只有当 VM 已经是
`Running` 且当前进程可见 guest password 时，才会通过 PowerShell Direct 运行只读 probe。它不会为了预检而
启动 VM，也不会 restore checkpoint、enable service、copy files、create guest folders 或写入 probe files。

非管理员运行通常会得到 Administrator check failed，并且 VM 相关 check 因无法可靠读取状态而 warning/skipped。

## 检查项

### 输入解析（Readiness input resolution）

报告有效 VM/checkpoint/guest settings 的来源。这是 `install.ps1`、`run.ps1` 与独立 readiness script 之间的
桥：安装器写入 `Sandbox__ConfigPath` 或 install state 后，operator 不必重复输入本机 VM 名称。

### 管理员权限（Administrator privilege）

确认当前 PowerShell process 是 elevated。Live Hyper-V 操作如 `Restore-VMSnapshot`、`Start-VM`、
`Copy-VMFile` 和 PowerShell Direct 必须由 elevated host process 执行。

修复：重新以 “Run as administrator” 打开 PowerShell。

### Hyper-V PowerShell module

检查 `Hyper-V` PowerShell module 和必要 cmdlets 是否存在。preflight 只检查可用性，不调用 mutation-capable
命令如 `Copy-VMFile`。

需要的 cmdlets：

```text
Get-VM
Get-VMSnapshot
Get-VMIntegrationService
Copy-VMFile
```

### Hyper-V feature enabled

非变更地检查宿主是否启用 Hyper-V。会记录 `Get-WindowsOptionalFeature` 可见的 optional-feature state 和
`vmms` service state，但不会启用 Hyper-V、启动 service、reboot 或 start VM。

### Guest password environment variable

检查 `-GuestPasswordSecretName` 指向的环境变量是否在当前 process 中非空。默认是
`KSWORDBOX_GUEST_PASSWORD`。脚本永远不打印 secret value。

当前 session 临时设置：

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
```

部署/重复使用推荐：

```powershell
.\install.ps1
```

readiness/live 脚本读取 Process、User、Machine scope。新 elevated PowerShell 通常继承 User/Machine scope；
脚本也会直接检查这些 scope。

### Guest working directory

检查 `-GuestWorkingDirectory` 是非空绝对 Windows path，例如：

```text
C:\KSwordSandbox
```

该 check 只做语法检查，不创建 guest folder。它还会报告 live runbook 派生路径：

```text
C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe
C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe
C:\KSwordSandbox\incoming
C:\KSwordSandbox\out
```

### Host payload files

检查 host-staged payload root，不 build、不 copy。默认：

```text
D:\Temp\KSwordSandbox\payload\guest-tools
```

必需文件：

```text
agent\KSword.Sandbox.Agent.exe
r0collector\KSword.Sandbox.R0Collector.exe
payload-manifest.json
```

修复：从仓库根运行 payload 准备脚本，并保持输出在仓库外：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-GuestPayload.ps1 `
  -PayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -SelfContained
```

readiness 不判断 payload freshness。需要时查看 `payload-manifest.json` 的 `generatedAtUtc`、
`repositoryHead`、`sourceFingerprint`、`sourceLatestWriteUtc`，若 stale 再重新 prepare。

### Runtime root writable

检查 `-RuntimeRoot` 是否存在且从只读 ACL inspection 看起来可写。不会创建临时文件。默认：

```text
D:\Temp\KSwordSandbox
```

Runtime root 必须在仓库外，用于 plans、jobs、reports、collected output。

### Host shared path configuration

检查 host/guest 交换路径：

- `paths.runtimeRoot`：plans、jobs、reports、collected output；
- `paths.guestPayloadRoot`：staged Guest Agent/R0Collector payload。

路径必须是绝对路径并在仓库外。check 会记录 copy mechanisms：`Copy-VMFile` 和 PowerShell Direct 的
`Copy-Item -ToSession/-FromSession`，但不创建目录或 probe file。

### Target VM

用 `Get-VM` 只读检查 `-VmName` 是否存在。默认：

```text
KSwordSandbox-Win10-Golden
```

### Clean checkpoint

用 `Get-VMSnapshot` 检查目标 VM 是否存在 `-CheckpointName`。默认：

```text
Clean
```

### Guest Service Interface

检查目标 VM 是否存在并启用了 Hyper-V integration service：`Guest Service Interface`。中文系统可能显示为
`来宾服务接口`；脚本同时兼容稳定组件 ID：

```text
6C09BB55-D683-4DA0-8931-C9BF705F6480
```

只读查看命令：

```powershell
$guestServiceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'
Get-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' |
  Where-Object {
    ([string]$_.Id).EndsWith('\' + $guestServiceComponentId, [System.StringComparison]::OrdinalIgnoreCase) -or
    $_.Name -eq 'Guest Service Interface' -or
    $_.Name -eq '来宾服务接口'
  } |
  Select-Object Name, Enabled, PrimaryStatusDescription
```

需要修复时，在明确准备修改 VM 后才运行：

```powershell
Enable-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' -Name 'Guest Service Interface'
```

### PowerShell Direct

当 process elevated、Hyper-V 可查询、VM 存在且 state 为 `Running`、guest password 可见时，脚本运行只读
PowerShell Direct probe：

```powershell
Invoke-Command -VMName '<vm>' -Credential '<in-memory credential>' -ScriptBlock {
    $PSVersionTable.PSVersion
}
```

如果 VM 为 `Off`，check 报 `Warning` 和 `RequiresRunning=true`；preflight 不会启动 VM。缺少 password 时，
password check failed，PowerShell Direct check 会明确跳过。

### Guest deployed payload files

当 PowerShell Direct probe 通过时，脚本检查 golden VM 内是否已有：

```text
C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe
C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe
```

这是 guest 内 `Test-Path`，不执行文件。缺失是 warning，不是 hard failure，因为 live runbook 可以在运行前
从 host payload root stage tools。刷新 golden `Clean` checkpoint 时应处理该 warning。

### Repository secret hygiene

当 `KSWORDBOX_GUEST_PASSWORD` 或配置的 secret 在当前进程可见且长度至少 8 字符时，readiness 会扫描 git
tracked/untracked candidate text files 是否包含该 exact value。命中会 fail，并只列文件名，不打印 secret。

提交前也运行：

```powershell
.\scripts\Test-RepositoryPolicy.ps1 -StagedOnly
```

`Test-RepositoryPolicy.ps1` 还会阻止 VM disks、samples、reports、binaries、DPAPI backups、
`install-state.json` 和其他本地产物入库。仅当当前 shell 不应读取仓库文本文件时，才对 readiness 使用
`-SkipRepositorySecretScan`。

### Test signing status

通过只读 `bcdedit.exe /enum {current}` 记录 host boot entry 的 test-signing 值。默认 mock/no-driver 流程下
该项只是信息。Real R0 时，需要在隔离 guest VM 内单独验证 Windows test-signing；readiness 不会为了检查
而启动 VM。

当准备触碰配置的 guest VM 时才使用：

```powershell
.\install.ps1 -Mode Change -QueryGuestTestSigning
.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force
.\scripts\Set-GuestTestSigning.ps1 -Mode Query
```

Driver signing 不属于 readiness。真实 R0 需要已 test-signed `.sys`。可在隔离
lab VM 中使用 `./scripts/Sign-SandboxDriverWithTestCertificate.ps1`；该 helper
只使用普通 Windows SDK `signtool.exe`，如果找不到 `signtool.exe` 会明确输出
`SignatureAttempted=false` / `Skipped=true`，不会回退到 legacy signing tools。
readiness/install/run 默认不签名、不调用 legacy signing tools。

### Real R0 host driver path

当 `driver.enabled=true` 且 `driver.useMockCollector=false` 时，`driver.hostDriverPath` 必须指向存在的 `.sys`。
否则 live preflight 会在 VM mutation 前失败，避免后续 R0Collector 才报 `deviceUnavailable` / `win32Error=2`。

## Payload staging dependency

readiness 只验证 host/VM readiness，不 build、不复制 guest tools。Live 前准备 payload：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-GuestPayload.ps1 -SelfContained
```

然后按 `docs/guest-payload-staging.md` 将 staged files 放入 golden VM 的：

```text
C:\KSwordSandbox\agent
C:\KSwordSandbox\r0collector
```

至少配置的 guest agent path 必须存在，live runbook 才能产出 `events.json`。

## 保存机器可读输出

保留脚本 exit code 并保存 JSON：

```powershell
$results = & .\scripts\Test-HyperVReadiness.ps1
$code = $LASTEXITCODE
$results | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 D:\Temp\KSwordSandbox\hyperv-readiness.json
exit $code
```

不要把 readiness JSON、runtime job folders、VM images 或 guest output 提交到仓库。
