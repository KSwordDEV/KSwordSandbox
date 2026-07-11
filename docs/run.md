# 运行入口 / Runtime entry point

本页中文优先。命令参数名（如 `-Mode`、`-Live`、`-SamplePath`）和机器可读
JSON key（如 `RecommendedActions`、`SecretValuePrinted`）保持英文，不翻译。

日常使用最短路径：

```powershell
.\install.ps1 -Mode Install -PromptPassword   # 首次或配置变化时运行
.\run.ps1                                     # 日常启动 WebUI；不会启动/还原 VM
```

出错时先按输出中的“下一步”处理。常见路径：

- WebUI 端口不可用：去掉 `-StrictUrl` 让脚本自动换端口，或传
  `-Url http://127.0.0.1:<free-port>`。
- 找不到配置：普通启动会显示“本机配置未就绪”，请先打开安装向导完成
  `Install / prepare local settings`，再在 `Change settings` 里确认 VM/checkpoint/driver path。
- payload 缺失/过期：运行 `.\scripts\Prepare-GuestPayload.ps1 -SelfContained`。
- `Analyze` 没有样本：使用 `-SamplePreset Notepad` / `-SamplePreset HarmlessSample`
  或传入 `-SamplePath <sample.exe>`。
- 真实 R0 缺少 driver：配置 `-DriverHostPath <test-signed .sys>`，或仅做链路验证时
  设置 `driver.useMockCollector=true`。

English summary: `.\run.ps1` defaults to WebUI/PlanOnly-safe behavior. VM
mutation requires an explicit `-Live`.

Use `run.ps1` after `install.ps1` has prepared local settings.

The intended operator flow is:

```powershell
.\install.ps1   # one-time or when VM/password/config changes
.\run.ps1       # each time you want to use the local WebUI
```

`.\run.ps1 -Mode StartWebUI` 是一键 WebUI 入口：未显式传
`-OpenBrowser:$false` 时会自动打开浏览器。默认 `.\run.ps1` 仍只启动本地
WebUI 服务，不会启动、还原或停止 VM。

Release bundles may also expose the same entry points from `scripts\`:

```powershell
.\scripts\install.ps1
.\scripts\run.ps1
```

The script-folder wrappers forward to the repository-root wrappers in the same
PowerShell process. They are aliases for packaging convenience, not a second
configuration system. Use either root or `scripts\` form consistently in a
session; both read `%ProgramData%\KSwordSandbox\install-state.json`, use the
same `Sandbox__ConfigPath`, and keep secrets out of command output.
Because the root scripts remain the implementation owner, diagnostic output and
`RecommendedActions` can still show canonical commands such as `.\run.ps1` and
`.\install.ps1`; those commands are expected and are equivalent to the wrapper
form.

## Start the WebUI

Default mode starts the local WebUI and loads the installed local config:

```powershell
.\run.ps1
.\scripts\run.ps1
```

Equivalent explicit form:

```powershell
.\run.ps1 -Mode WebUI -Url 'http://127.0.0.1:18080' -OpenBrowser
```

`StartWebUI` is an alias intended for menus and automation that prefer a verb:

```powershell
.\run.ps1 -Mode StartWebUI
.\scripts\run.ps1 -Mode StartWebUI
```

In interactive packaging use, `StartWebUI` opens the browser automatically unless
`-OpenBrowser:$false` is supplied.

If no installed local config exists and the resolver would fall back to
`config\sandbox.example.json`, ordinary `WebUI`/`StartWebUI`/`Analyze`/`Plan`
startup stops with the Chinese message `本机配置未就绪`. This avoids launching
with placeholder VM/checkpoint values. Explicit `-ConfigPath` remains supported
for developers who intentionally want the example or a custom config.

Preview startup without building payloads, starting dotnet, opening a browser,
or touching a VM:

```powershell
.\run.ps1 -Mode StartWebUI -WhatIf
```

`run.ps1` sets these process-scoped values before starting the Web project:

- `Sandbox__ConfigPath` from `%ProgramData%\KSwordSandbox\install-state.json`,
  the current environment, or `D:\Temp\KSwordSandbox\config\sandbox.local.json`;
- `ASPNETCORE_URLS` from `-Url`;
- `KSWORDBOX_GUEST_PASSWORD` in process scope by mirroring the User/Machine
  environment value if one exists.
- optional `KSWORDBOX_VIRUSTOTAL_API_KEY` in process scope by mirroring the
  User/Machine environment value if one exists.

The password value is never printed. Optional VT key values are never printed.
The WebUI startup path intentionally prints only concise status, the selected
URL, and repair hints. It does not dump a long command sequence to the operator.

If the requested localhost port is blocked by Windows/Hyper-V TCP port
exclusions or another process, `run.ps1` automatically falls back to a nearby
safe port and prints the final WebUI URL. Use `-StrictUrl` when you want port
binding failure to stop immediately instead.

## Single EXE plan or live run

For a non-mutating plan check:

```powershell
.\run.ps1 -Mode Plan -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30
```

Release shortcuts for built-in samples:

```powershell
# Analyze Notepad in PlanOnly mode; no VM mutation.
.\run.ps1 -Mode Analyze -SamplePreset Notepad

# Equivalent short alias.
.\run.ps1 -Mode Analyze -SamplePath notepad

# Publish the harmless sample outside git, then create a PlanOnly runbook.
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample

# Equivalent short alias.
.\run.ps1 -Mode Analyze -SamplePath sample
```

中文提示：上面四条命令都是“一条命令 Analyze notepad/sample”的入口；未加
`-Live` 时只生成计划，不启动、不还原、不停止 Hyper-V VM，也不会执行样本。
`HarmlessSample` 会在 `D:\Temp\KSwordSandbox\samples\...` 或已配置的
`RuntimeRoot` 下发布测试 EXE，输出位于仓库外。

`-Mode Plan` is PlanOnly and non-mutating: it does not start, restore, stop, or
copy into a VM, and it now skips guest payload preparation. The generated
Hyper-V plan records missing/stale payload files plus repair suggestions such as
running `.\scripts\Prepare-GuestPayload.ps1 -SelfContained`.

For a single live Hyper-V analysis from an elevated shell:

```powershell
.\run.ps1 -Mode Analyze -SamplePath 'D:\Temp\sample.exe' -DurationSeconds 30 -Live
```

Built-in sample live forms:

```powershell
.\run.ps1 -Mode Analyze -SamplePreset Notepad -Live
.\run.ps1 -Mode Analyze -SamplePreset HarmlessSample -Live

# Public-MVP live smoke: real Notepad for 5 seconds.
.\run.ps1 -Mode Analyze -SamplePreset Notepad -DurationSeconds 5 -Live
```

Live mode can restore/start/stop the configured VM and requires the installed
golden VM/checkpoint, guest password secret, prepared guest payload, and any
real R0 `driver.hostDriverPath`/guest test-signing setup required by your lab.
The host must have Hyper-V PowerShell tools and BIOS/UEFI hardware
virtualization enabled (Intel VT-x / AMD-V). This is unrelated to optional
VirusTotal hash-only enrichment, which is configured separately with
`.\install.ps1 -Mode ConfigureVTKey -PromptVTKey`.

If `-Live` is omitted, `Analyze` falls back to PlanOnly and does not mutate the
VM. This keeps accidental sample execution out of the default path while still
making the real live command short.

When `-Live` succeeds, `run.ps1` automatically invokes
`tools/KSword.Sandbox.PostProcess` against the collected job directory. The
single command therefore ends with:

- `runbook-execution.json`
- `guest\<job-id>\events.json`
- `postprocess-result.json`
- `report.json`
- `report.html`
- `report.zh.html`
- `report.en.html`

## Rebuild reports and inspect artifacts without rerunning the VM

Operators can rebuild reports or inspect collected artifacts after a live run
without starting, restoring, stopping, or mutating Hyper-V:

```powershell
# List runtime jobs.
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- list-jobs

# Show one job summary.
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- show-job --job-id <job-guid>

# Rebuild report.json/report.html/report.zh.html/report.en.html and artifact-index.json.
.\scripts\Rebuild-JobReport.ps1 -JobId <job-guid>

# Inspect artifacts in memory without rewriting artifact-index.json.
.\scripts\Inspect-JobArtifacts.ps1 -JobId <job-guid>

# Explicitly refresh artifact-index.json when desired.
.\scripts\Inspect-JobArtifacts.ps1 -JobId <job-guid> -WriteIndex
```

中文提示：这些命令只读取已有 job 目录、`events.json`、`driver-events.jsonl`、
`runbook-execution.json`、PCAP 和其他产物；不会重跑样本，也不会操作 VM。
`Rebuild-JobReport.ps1` 会调用 JobTool 的 `rebuild-report`，可在已有
`report.json` 中推断原始样本路径；若样本无法推断，请追加 `-SamplePath`。

JobTool also supports JSON output for automation:

```powershell
dotnet run --project .\tools\KSword.Sandbox.JobTool\KSword.Sandbox.JobTool.csproj -- inspect-artifacts --job-id <job-guid> --json
.\scripts\Rebuild-JobReport.ps1 -JobId <job-guid> -Json
```

The wrapper scripts accept `-NoBuild` when the JobTool project has already been
built and you want to avoid an implicit `dotnet run` build during triage.

All JobTool and wrapper output is designed to be operator friendly in English
and Chinese and to redact password/API-key/token-like fields before printing.
Do not commit regenerated runtime artifacts; keep job folders, reports, samples,
payload binaries, VM disks, and local secrets under `D:\Temp\KSwordSandbox` or
another ignored runtime root.

Before invoking `scripts/Invoke-HyperVE2E.ps1`, `run.ps1` checks the staged Guest
Agent/R0Collector payload under the configured `guestPayloadRoot`. If it is
missing, it calls `scripts/Prepare-GuestPayload.ps1 -SelfContained` so a fresh
machine can reach the Hyper-V path without manually building guest binaries.
Use `-SkipPayloadPreparation` only when intentionally testing planner behavior
without payload files.

`run.ps1` also reports the real R0 driver configuration before WebUI or one-shot
analysis. If `driver.enabled=true`, `driver.useMockCollector=false`, and
`driver.hostDriverPath` is empty or missing, it prints an `R0 warning` because
the live runbook cannot stage a `.sys` or generate `install-driver-service`;
R0Collector would otherwise fail later with `deviceUnavailable` /
`win32Error=2`. Fix it by setting
`.\install.ps1 -Mode Change -UpdateHyperVConfig -DriverHostPath <test-signed .sys>`,
using `driver.useMockCollector=true` for payload-only R0 validation, or setting
`driver.enabled=false`.

## Status

```powershell
.\run.ps1 -Mode Status
```

Status reports repository root, install state, local config, Web URL, runtime
root, secret presence, optional VirusTotal key presence, VM/checkpoint
presence, host Guest Agent/R0Collector payload presence, R0 driver host-path
readiness, and whether the secret value was printed (`False`). It also prints
`RecommendedActions` with
human-readable fixes for common setup gaps:

- missing VM: record the real VM with
  `.\install.ps1 -Mode Change -UpdateHyperVConfig -VmName <existing VM> -CheckpointName <checkpoint>`;
- missing checkpoint: create or record the clean checkpoint;
- missing guest payload: run
  `.\scripts\Prepare-GuestPayload.ps1 -RepoRoot . -PayloadRoot <payloadRoot> -SelfContained`;
- missing guest password secret: run `.\install.ps1 -Mode Install -PromptPassword`
  or use `.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword` for
  a process-only check;
- real R0 requested but no `driver.hostDriverPath`: set `-DriverHostPath`,
  enable `driver.useMockCollector=true`, or disable `driver.enabled`.

For a fuller non-mutating preflight summary:

```powershell
.\run.ps1 -Mode CheckEnvironment
```

`CheckEnvironment` prints the daily startup command, `ReadinessCommand`, whether
`dotnet`, the Web project, payload-preparation script, Hyper-V E2E script,
local config, guest secret, optional VirusTotal key, VM, checkpoint, and payload
files are visible from this host. `CheckEnvironmentStartsVm=False` and
`PlanOnlyStartsVm=False`; these paths are meant to be safe on another
developer's computer before they try `-Live`.

`-WhatIf` is supported on `run.ps1`. In WebUI modes it skips payload
preparation and dotnet startup. In `Plan` / `Analyze` modes it stops before
delegating to `scripts\Invoke-HyperVE2E.ps1`, so no Hyper-V child script is
launched.

## Relationship with install.ps1

- `install.ps1` is for one-time local preparation: folders, Hyper-V VM/checkpoint
  config, local config file, Web/API config env var, and guest password sync.
- `run.ps1` is for each launch: start WebUI, or run/plan one EXE with the
  installed config.
- `run.ps1` never asks you to type a password on the command line. It mirrors
  the configured secret from Process/User/Machine environment into the child
  WebUI or Hyper-V process and reports only whether a value exists.

Keep runtime outputs under `D:\Temp\KSwordSandbox`; do not commit generated
reports, samples, payload binaries, VM disks, or local secrets.

## 便携包一键 WebUI 启动

中文优先：`run.ps1` 现在会自动选择 WebUI 启动目标。源码仓库中优先使用
`src\KSword.Sandbox.Web\KSword.Sandbox.Web.csproj`；便携包中如果没有源码项目，则使用
`app\host-web\KSword.Sandbox.Web.exe`，或退回到 `app\host-web\KSword.Sandbox.Web.dll` + `dotnet`。
日常入口仍然是一条命令：

```powershell
.\run.ps1
.\run.ps1 -Mode StartWebUI -OpenBrowser
.\run.ps1 -Mode Status
```

`Status`/`CheckEnvironment` 会展示 `WebUiLaunchKind`、`WebUiLaunchPath`、`PublishedWebAppExists`、
`PortableWebUiReady`、`VmProfile`、`HostTestSigningState`、guest password presence 和 R0 driver
配置状态。缺失本机配置、payload、VM profile、driver path 或 published WebUI 时，先看
`RecommendedActions`；这些检查不会启动、还原或停止 Hyper-V VM。

便携包运行要求：

- `install.ps1`/`run.ps1` 位于包根目录，`scripts\run.ps1` 只是等价 wrapper。
- `app\host-web` 来自外部发布目录，不从仓库 `bin/`、`obj/`、`x64/` 复制。
- `packaging\runtime-package.manifest.json` 和 `packaging\README.md` 会随 runtime
  包一起进入包内，便于审阅 portable layout 与禁止项；真实发布 payload 的
  来源仍只允许是仓库外 `RuntimePublishRoot`。
- 包根的 `package-manifest.generated.json` 是本次 staging 的审计索引，包含
  文件 hash/size、git revision、runtime publish root、跳过的可选 payload
  和安全合约。排障时先看这个文件，再看 `Status`/`CheckEnvironment`。
- 本机 `sandbox.local.json`、guest password、VT key、样本、报告和 VM 输出继续保存在 runtime root
  或 Windows 环境/DPAPI 中，不进入 zip。
- 默认 WebUI 不执行 Live；Live Hyper-V 仍必须在 WebUI/API 或 CLI 中显式选择。
