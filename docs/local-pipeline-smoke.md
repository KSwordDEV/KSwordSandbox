# 本地管线 Smoke / Local pipeline smoke

`scripts/Invoke-LocalPipelineSmoke.ps1` 是快速 host-only smoke，用于在没有真实 Hyper-V VM 的情况下检查 Web/Core 管线。

English summary: this script checks the Web/Core pipeline without a real Hyper-V VM.

## 用途 / Purpose

当需要验证本地 API 与 Core job/report services 仍能形成闭环时，使用此 smoke：

English summary: use this smoke to verify that the local API and Core job/report services still form a closed loop:

1. create a harmless `.exe`-named file under
   `D:\Temp\KSwordSandbox\pipeline-smoke`;
2. start `KSword.Sandbox.Web` on a random `127.0.0.1` port;
3. call `/health`, `/api/files/scan`, and `/api/jobs/plan`;
4. call `/api/jobs/{jobId}/runbook/execute` with `live=false` and verify
   `runbook-execution.json`;
5. write synthetic guest `events.json` plus `driver-events.jsonl` into the job
   guest output folder;
6. call `/api/jobs/{jobId}/events/live` and verify the raw unclassified event
   rows and source paths;
7. call `/api/jobs/{jobId}/guest-events/import`;
8. verify that `report.html` contains the expected report sections and rule
   findings.

The smoke only executes the runbook in dry-run mode. It does not require
Hyper-V, does not start a VM, and does not require a golden VM.

## 运行 / Run

从仓库根目录运行 / From the repository root:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1
```

常用选项 / Useful options:

```powershell
# 使用 Release build output / Use Release build output.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1 -Configuration Release

# 已有成功 build 后跳过 dotnet run 内部构建 / Skip build inside dotnet run after a prior successful build.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1 -NoBuild

# 使用不同 runtime artifact root / Use a different runtime artifact root.
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Invoke-LocalPipelineSmoke.ps1 -RuntimeRoot D:\Temp\KSwordSandbox\pipeline-smoke-dev
```

## 输出 / Outputs

成功时脚本会打印 / On success the script prints:

- run root;
- benign sample path;
- temporary Web URL;
- job ID;
- synthetic guest event paths;
- `report.json`;
- `report.html`;
- Web stdout/stderr logs.

All runtime artifacts are written below the configured runtime root, not into
the repository. Do not commit generated run folders, samples, configs, reports,
or logs.

## 失败处理 / Failure handling

失败时脚本以 exit code `1` 退出，并在可用时打印 run root 和 Web stderr tail。删除 run folder 前，先检查打印出的 `report.html`、`report.json` 和 log paths。

English summary: on failure, inspect the printed report and log paths before deleting the run folder.
