# 测试 / Testing

KSwordSandbox 默认验证路径保持 VM-free。Smoke tests 使用系统临时目录中的合成文件，不应要求 Hyper-V、已签名 driver、CSignTool 或真实恶意样本。

English summary: the default validation path is VM-free and uses synthetic files outside the repository.

## 无 VM 合成 E2E smoke / VM-free synthetic E2E smoke

The primary minimum-link regression gate is:

```powershell
.\scripts\Invoke-SandboxSmokeTest.ps1 -Scenario synthetic.e2e-smoke.contract
```

It exercises this path without starting a VM:

1. Create a harmless `.exe` placeholder outside the repository and find it via
   `ExecutableTargetScanner`.
2. Simulate Web upload staging and verify the upload JSON shape.
3. Plan a dry-run job through `SandboxJobService.Plan`.
4. Persist a synthetic dry-run runbook result and UI-safe progress snapshot.
5. Write synthetic `events.json`, `driver-events.jsonl`, artifact files, and
   `artifacts/manifest.json` under the job runtime folder.
6. Verify live raw-event paging before import.
7. Import guest/driver events, classify behavior rules, and regenerate reports.
8. Verify `report.zh.html`, `report.en.html`, safe artifact links, artifact
   index/download resolution, and the live UI JSON contract.

The scenario ID is stable so it can be used as a fast regression gate:

```powershell
dotnet run --project .\tests\KSword.Sandbox.SmokeTests\KSword.Sandbox.SmokeTests.csproj -- --scenario synthetic.e2e-smoke.contract
```

## Smoke 过滤器 / Smoke harness filters

列出可用场景 / List available scenarios:

```powershell
.\scripts\Invoke-SandboxSmokeTest.ps1 -ListScenarios
```

运行聚焦场景 / Run focused scenarios:

```powershell
.\scripts\Invoke-SandboxSmokeTest.ps1 -Scenario synthetic.e2e-smoke.contract
.\scripts\Invoke-SandboxSmokeTest.ps1 -ScenarioPrefix webui.
```

仅在已有成功 build 后使用 `-NoBuild` / Use `-NoBuild` only after a successful build:

```powershell
.\scripts\Invoke-SandboxSmokeTest.ps1 -NoBuild -Scenario synthetic.e2e-smoke.contract
```

## 仓库策略门禁 / Repository policy gate

提交前运行 / Run before committing:

```powershell
.\scripts\Test-RepositoryPolicy.ps1
```

仓库策略会拒绝 build outputs、VM images、binaries、reports、captures、sample payloads、private keys/certificates、packet captures、dumps 和常见 runtime telemetry artifacts。Synthetic smoke artifacts 应保留在临时 runtime directory 下，不能提交。

English summary: the policy rejects generated/runtime artifacts and secrets; synthetic smoke outputs must stay outside git.
