# Testing

KSwordSandbox keeps the default validation path VM-free. Smoke tests use
synthetic files under the system temp directory and must not require Hyper-V,
a signed driver, CSignTool, or real malware samples.

## VM-free synthetic E2E smoke

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

## Smoke harness filters

List available scenarios:

```powershell
.\scripts\Invoke-SandboxSmokeTest.ps1 -ListScenarios
```

Run focused scenarios:

```powershell
.\scripts\Invoke-SandboxSmokeTest.ps1 -Scenario synthetic.e2e-smoke.contract
.\scripts\Invoke-SandboxSmokeTest.ps1 -ScenarioPrefix webui.
```

Use `-NoBuild` only after a successful build:

```powershell
.\scripts\Invoke-SandboxSmokeTest.ps1 -NoBuild -Scenario synthetic.e2e-smoke.contract
```

## Repository policy gate

Run before committing:

```powershell
.\scripts\Test-RepositoryPolicy.ps1
```

The policy rejects build outputs, VM images, binaries, reports, captures,
sample payloads, private keys/certificates, packet captures, dumps, and common
runtime telemetry artifacts. Synthetic smoke artifacts should stay under the
temp runtime directory and must not be committed.
