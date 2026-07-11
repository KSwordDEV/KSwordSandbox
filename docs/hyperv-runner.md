# Hyper-V runbook runner（Web/API 执行边界）

Runner 为 `SandboxRunbook` 增加执行边界，并注册在 WebUI/API 后面。默认模式是 dry-run，所以普通计划和
operator review 不会启动 PowerShell，也不会运行 Hyper-V 命令。

One-command Hyper-V E2E script: 脚本式入口仍是 `scripts/Invoke-HyperVE2E.ps1`。Use `-WhatIf` with
`-Live` when you need to review live intent without mutating the VM.

注意区分：Web/API runner 使用 `DryRun` 字段；脚本式 `Invoke-HyperVE2E.ps1` 使用 `PlanOnly`。二者都不
修改 VM，但入口和持久化字段不同。

## 执行模式（execution modes）

### DryRun

`SandboxRunbookExecutionOptions.Mode` 默认是 `SandboxRunbookExecutionMode.DryRun`。

Dry-run 行为：

- 记录每个 `SandboxRunbookStep.PowerShell` command。
- 将每个 step 标记为 skipped 且 successful。
- 不启动 PowerShell。
- 不修改 VM state。
- 返回 `ExecutedSteps = 0` 的 `SandboxRunbookExecutionResult`。

### Live

Live mode 必须显式选择：

```csharp
var executor = new PowerShellRunbookExecutor();
var result = await executor.ExecuteAsync(
    runbook,
    new SandboxRunbookExecutionOptions
    {
        Mode = SandboxRunbookExecutionMode.Live
    },
    cancellationToken);
```

Live 行为：

- 按顺序执行 `SandboxRunbookStep.PowerShell`。
- 每个 step 启动一个独立 non-interactive PowerShell process。
- 捕获 stdout、stderr、exit code、duration。
- 对 VM boot、PowerShell Direct readiness、live output copy 等长步骤输出低频 progress heartbeat。
- 将第一个非零 exit code、timeout、launch failure 或 cancellation 记录为 primary failure。
- primary failure 后跳过非 cleanup 工作，并尝试 trailing cleanup steps（如 VM stop/remove）。Cleanup failure
  会附加到 aggregate message 和 step results，但 primary failed step 仍保持为 failure index。

## 提权要求（elevation requirement）

`Get-VM`、`Start-VM`、`Restore-VMSnapshot`、`Copy-VMFile` 和 PowerShell Direct 需要 elevated host process。
使用 live mode 前，承载 Web/API 的进程本身必须以 Administrator 启动；否则 executor preflight 失败且不会
执行任何部分 VM 命令。

默认保护：

- `SandboxRunbookExecutionOptions.RequireElevatedPowerShell` 默认为 `true`。
- 只要 source step 中存在 `RequiresElevation = true`，且当前 process 不是 Administrator，live mode 会返回
  failed preflight result。
- elevation preflight 失败时不启动 VM 命令。

Hyper-V runbook 应保持该检查开启。

## 结果数据（result data）

`SandboxRunbookExecutionResult` 包含：

- Job ID 和 target VM name。
- Execution mode。
- Total source step count。
- 已启动 PowerShell process 数量。
- Failed step index（如有）。
- Aggregate duration 和 elevation requirement flag。
- Per-step `SandboxRunbookStepExecutionResult`。

每个 step result 包含：

- Step index、ID、title、PowerShell command。
- Skipped/success status。
- stdout/stderr。
- PowerShell exit code。
- UTC start time 和 duration。
- 从 source step 复制的 elevation 与 VM mutation flags。
- dry-run、timeout、cancellation、launch failure 或 exit failure 的 optional message。

Web/API 会把每次执行持久化到 job folder：

```text
D:\Temp\KSwordSandbox\jobs\<job-id>\runbook-execution.json
D:\Temp\KSwordSandbox\jobs\<job-id>\runbook-progress.json
```

`runbook-execution.json` 是完整执行记录，包含命令、stdout/stderr 和 phase details；`runbook-progress.json`
是 UI-safe sidecar，只包含 step state、duration、exit code、message、failure reason/remediation hints，
不包含 PowerShell command text 或 secret。脚本式 `Invoke-HyperVE2E.ps1` 也写同名 progress sidecar，
因此 WebUI/recovery 工具可以用同一读取路径展示失败进度。

Live runbook 成功后，host 会尝试从 collected guest folder 导入 guest output。synthetic events 或收集完成较晚
时，也可手动导入：

```http
POST /api/jobs/{jobId}/guest-events/import
Content-Type: application/json

{
  "eventsPath": "D:\\Temp\\KSwordSandbox\\jobs\\<job-id>\\guest\\<job-id>\\events.json"
}
```

`eventsPath` 省略时，服务会在 `D:\Temp\KSwordSandbox\jobs\<job-id>\guest\` 递归查找 `events.json`，
再查找 `*.jsonl`。导入事件会重新运行 behavior rules，并重新生成 `report.json` 和 `report.html`。

脚本式 Hyper-V failure path 会在缺少真实 guest output 时生成可导入 skeleton：

```text
D:\Temp\KSwordSandbox\jobs\<job-id>\guest\<job-id>\events.json
D:\Temp\KSwordSandbox\jobs\<job-id>\guest\<job-id>\guest-output-skeleton.json
```

该 skeleton 至少包含 `hyperv.e2e.failure_skeleton` 事件、`agent.pid=0`、`agent.exit=-1` 和 stdout/stderr
占位文件。它用于恢复报告和定位失败步骤，不代表 Guest Agent 完整运行。`Import-HyperVJobReport.ps1`
在 `events.json` 缺失但 `runbook-execution.json` 存在时也会自动补 skeleton 后再导入。

## Web API 集成

创建 job 后执行或记录 planned runbook：

```http
POST /api/jobs/{jobId}/runbook/execute
Content-Type: application/json

{
  "live": false,
  "stepTimeoutSeconds": 1800
}
```

只有在 Web/API host process 已 elevated，且 golden VM、guest credentials、guest agent path 都准备好后，
才将 `live` 设为 `true`。

最小 live API flow：

```powershell
$job = Invoke-RestMethod -Method Post -Uri 'http://localhost:5000/api/jobs/plan' `
  -ContentType 'application/json' `
  -Body (@{
      samplePath = 'D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample\KSword.Sandbox.HarmlessSample.exe'
      displayName = 'KSword.Sandbox.HarmlessSample.exe'
      durationSeconds = 30
      dryRun = $true
  } | ConvertTo-Json)

$execution = Invoke-RestMethod -Method Post -Uri "http://localhost:5000/api/jobs/$($job.jobId)/runbook/execute" `
  -ContentType 'application/json' `
  -Body (@{
      live = $true
      stepTimeoutSeconds = 1800
      importGuestEvents = $true
  } | ConvertTo-Json)

if (-not $execution.guestImportSucceeded) {
    Invoke-RestMethod -Method Post -Uri "http://localhost:5000/api/jobs/$($job.jobId)/guest-events/import" `
      -ContentType 'application/json' `
      -Body '{}'
}
```

## WebUI 集成

Job result panel 暴露：

- `Record dry-run execution`
- `Execute live runbook`
- `Import guest events / refresh report`

Live 按钮是 “start VM and report behavior” 的可用路径，但仍依赖本地 Hyper-V readiness：

- Hyper-V feature 和 module installed。
- Golden VM registered，例如 `KSwordSandbox-Win10-Golden`。
- Clean checkpoint available，例如 `Clean`。
- Guest credential secret 通过配置环境变量可见。
- Guest Service Interface / PowerShell Direct usable。
- Guest agent 已发布到配置的 guest path。

## Runbook execution UX contract

Runbook execution 是 operator diagnostics data，不是最终恶意行为 telemetry。UI 应让失败可操作，避免
operator 必须手动打开 `runbook-execution.json`。

执行摘要应显示：

- mode（`DryRun` 或 `Live`）；
- aggregate success/failure；
- executed step count / total step count；
- aggregate duration；
- failed step index（如有）；
- top-level error/message text；
- automatic import 的 guest import status 和 error text。

步骤详情应显示：

- step index、step ID、title；
- status 和 skipped state；
- PowerShell exit code；
- step duration；
- error/message text；
- captured stdout；
- captured stderr。

长 stdout/stderr 默认折叠，并提供 copy action，避免大量命令输出掩盖 failed step 或 exit code。空输出要显示为
明确 empty state。当前 persisted model 已稳定保存 `standardOutput`、`standardError`、`exitCode`、
`duration` 和 `message`。

## Live telemetry stream validation

Live Hyper-V run 中，UI-safe event source 仍然是 host-collected guest output folder。baseline validation 使用
polling endpoint：

```http
GET /api/jobs/{jobId}/events/live?offset=0&take=100
Accept: application/json
```

SSE（Server-Sent Events）endpoint 可用时：

```http
GET /api/jobs/{jobId}/events/stream?offset=0
Accept: text/event-stream
```

stream endpoint 也接受 `take=<n>` 和 `intervalMs=<milliseconds>`。当前 server 行为：`take` clamp 到 `1..500`
且默认 `100`；`intervalMs` clamp 到 `500..10000` 且默认 `2000`。

如果 running Web API 没有 `/events/stream`，QA probe 应记录 “SSE route unavailable”，然后验证 polling
fallback，而不是让整个 live telemetry check 失败。

Fallback loop：

1. client-side `offset` 初始为 `0`。
2. 调用 `/api/jobs/{jobId}/events/live?offset=<offset>&take=100`。
3. 验证 response 包含 `jobId`、`retrievedAt`、`totalEvents`、`nextOffset`、`hasMore`、`sources`、`events`。
4. 渲染或检查 raw event，不在 monitor 中做 verdict logic。
5. 将 `offset` 替换为 `nextOffset`。
6. 如果 `hasMore=true`，立即继续 poll；否则在 runbook 仍运行时短暂等待。

轻量 QA：

```powershell
# Static expected-contract check；不启动 Web API，不写 runtime artifacts。
.\scripts\Test-LiveTelemetryFramework.ps1 -ContractOnly

# Runtime probe against 已启动 Web API 和已有 job。保留 -UsePollingFallback，
# 让 stream failure 或较老 polling-only build 成为 documented fallback validation。
.\scripts\Test-LiveTelemetryFramework.ps1 `
  -BaseUrl 'http://localhost:5000' `
  -JobId '<job-guid>' `
  -UsePollingFallback
```
