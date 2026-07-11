# Hyper-V readiness preflight

`scripts/Test-HyperVReadiness.ps1` verifies the minimum host and golden-VM
state needed before the live Hyper-V runner starts a VM and imports a behavior
report. The script is intentionally read-only: it does not create runtime probe
files, create or restore checkpoints, start or stop VMs, copy files, or change
integration-service settings.

## Run the check

Run from an elevated PowerShell session on the Hyper-V host:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

Windows PowerShell also works:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-HyperVReadiness.ps1
```

After `.\install.ps1` or its wrapper `.\scripts\install.ps1` has been run, the
no-argument command automatically tries the same local config path used by
`run.ps1`:

1. `Sandbox__ConfigPath` from Process/User/Machine scope;
2. `%ProgramData%\KSwordSandbox\install-state.json` -> `localConfigPath`;
3. repository fallback `config/sandbox.example.json`.

Use `-IgnoreInstalledConfig` when you deliberately want only explicit
parameters plus the repository example fallback.

If your release bundle starts from `scripts\`, the compatibility wrappers
`.\scripts\install.ps1` and `.\scripts\run.ps1` write/read the same install
state and local config as the repository-root `.\install.ps1` and `.\run.ps1`.
Readiness resolution is therefore identical for either entry point.

Defaults match `config/sandbox.example.json` when no installed config is found:

```powershell
.\scripts\Test-HyperVReadiness.ps1 `
  -VmName 'KSwordSandbox-Win10-Golden' `
  -CheckpointName 'Clean' `
  -GuestPasswordSecretName 'KSWORDBOX_GUEST_PASSWORD' `
  -GuestUserName 'SandboxUser' `
  -GuestPayloadRoot 'D:\Temp\KSwordSandbox\payload\guest-tools' `
  -GuestWorkingDirectory 'C:\KSwordSandbox' `
  -RuntimeRoot 'D:\Temp\KSwordSandbox'
```

If the password is missing and you only want a one-shot process-scoped value for
this readiness run, opt in to a secure prompt:

```powershell
.\scripts\Test-HyperVReadiness.ps1 -PromptForMissingGuestPassword
```

The prompt stores the value in the current PowerShell process only. It does not
write `%ProgramData%`, user environment, config JSON, reports, or any repository
file. For repeatable setup, prefer `install.ps1 -Mode Install -PromptPassword`
or `install.ps1 -Mode Change -ResetPassword -PromptPassword`.

The script writes structured PowerShell objects:

- `ReadinessCheck` objects for each check. Every check includes stable
  machine-readable fields: `CheckId`, `Category`, `Status`,
  `RequiredForLive`, `MachineReadable`, `Details`, and `Remediation`.
- One `ReadinessSummary` object with `ContractVersion`, `Kind`,
  `OverallStatus`, counts, `FailedCheckIds`, `WarningCheckIds`, `LiveReady`,
  `ReadOnlyAssertions`, `RecommendedActions`, and `ExitCode`.

Exit code behavior:

- `0`: no check has `Status = Failed`.
- `1`: at least one check has `Status = Failed`.

Warnings are still printed as objects. A non-administrator run usually emits a
failed Administrator check and warning objects for VM state that cannot be read
reliably from a non-elevated process.

The preflight is still non-destructive when it runs as Administrator. It may
query Hyper-V and, only when the VM is already running and a guest password is
visible to the current process, run read-only `Invoke-Command -VMName ...`
probes. It never starts the VM, restores a checkpoint, enables services, copies
files, creates guest folders, or writes probe files.

## Checks

### Readiness input resolution

Reports the config source used for effective VM/checkpoint/guest settings. This
is the bridge between `install.ps1`, `run.ps1`, and the standalone readiness
script: operators can run the preflight without retyping local VM names after
the installer has written `Sandbox__ConfigPath` or install state.

### Administrator privilege

Confirms that the current PowerShell process is elevated. Live Hyper-V actions
such as `Restore-VMSnapshot`, `Start-VM`, `Copy-VMFile`, and PowerShell Direct
must run from an elevated host process.

Fix: reopen PowerShell with "Run as administrator" and run the preflight again.

### Hyper-V PowerShell module

Checks that the `Hyper-V` PowerShell module is installed and that the required
cmdlets are available. The preflight checks command availability only; it does
not call mutation-capable commands such as `Copy-VMFile`.

- `Get-VM`
- `Get-VMSnapshot`
- `Get-VMIntegrationService`
- `Copy-VMFile`

Fix: enable/install Hyper-V management tools for the host OS, then open a new
PowerShell session.

### Hyper-V feature enabled

Checks whether the host appears to have Hyper-V enabled without mutating the
machine. The check records Windows optional-feature state when
`Get-WindowsOptionalFeature` is available and also records the `vmms` service
state. It does not enable Hyper-V, start services, reboot, or start a VM.

Machine-readable details include `FeatureStates`, `AnyFeatureEnabled`,
`VmmsServiceExists`, `VmmsServiceStatus`, and `ReadOnly=true`.

### Guest password environment variable

Checks that the environment variable named by `-GuestPasswordSecretName` exists
and is non-empty in the current process. The default is
`KSWORDBOX_GUEST_PASSWORD`. The script never prints the secret value.

Fix for the current session:

```powershell
$env:KSWORDBOX_GUEST_PASSWORD = '<local guest password>'
```

For deployment and repeat use, prefer the local installer:

```powershell
.\install.ps1 -Mode Install -PromptPassword
```

or generate/reset a local value:

```powershell
.\install.ps1 -Mode Change -ResetPassword -GeneratePassword
```

The readiness and live scripts read Process, User, then Machine scope. If a
value exists at User or Machine scope, a newly opened elevated PowerShell
session inherits it; the scripts also check those scopes directly.

### Guest working directory

Checks that `-GuestWorkingDirectory` is a non-empty absolute Windows path such
as:

```text
C:\KSwordSandbox
```

The check is syntax-only and does not create guest folders. It also reports the
derived guest paths expected by the live runbook:

```text
C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe
C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe
C:\KSwordSandbox\incoming
C:\KSwordSandbox\out
```

### Host payload files

Checks the host-staged payload root without building or copying anything. The
default root is:

```text
D:\Temp\KSwordSandbox\payload\guest-tools
```

Required files:

```text
agent\KSword.Sandbox.Agent.exe
r0collector\KSword.Sandbox.R0Collector.exe
payload-manifest.json
```

Fix: run `scripts/Prepare-GuestPayload.ps1` from the repository root and keep
the generated payload under `D:\Temp\KSwordSandbox` or another non-repository
runtime directory.

The readiness script is intentionally a presence and path-contract preflight;
it does not rebuild payloads and it does not decide payload freshness on its
own. For payload freshness, open `payload-manifest.json` and compare
`generatedAtUtc`, `repositoryHead`, `sourceFingerprint`, and
`sourceLatestWriteUtc` with the current repository and guest source changes. If
the manifest is stale, rerun `scripts/Prepare-GuestPayload.ps1` before live
execution or before refreshing the golden checkpoint.

### Runtime root writable

Checks that `-RuntimeRoot` exists as a directory and appears writable from
read-only ACL inspection. The check does not create a temporary file, so it is
conservative: if the directory does not exist or ACLs cannot prove write access,
the check fails.

Fix: create the runtime directory outside git and grant the account running the
host service permission to create job folders under it. The default path is:

```text
D:\Temp\KSwordSandbox
```

### Host shared path configuration

Checks the host paths used for VM exchange:

- `paths.runtimeRoot` for plans, jobs, reports, and collected output;
- `paths.guestPayloadRoot` for the staged Guest Agent/R0Collector payload.

The paths must be absolute and outside the repository. The check also records
the live copy mechanisms (`Copy-VMFile` plus PowerShell Direct
`Copy-Item -ToSession/-FromSession`) so automation can understand how host and
guest exchange files. It does not create directories or write probe files.

### Target VM

Checks that `-VmName` exists and is readable through `Get-VM`. The default is:

```text
KSwordSandbox-Win10-Golden
```

Fix: register or rename the golden VM so it matches local configuration, or pass
the correct `-VmName` value.

### Clean checkpoint

Checks that `-CheckpointName` exists on the target VM through `Get-VMSnapshot`.
The default is:

```text
Clean
```

Fix: prepare the VM, shut it down into the desired clean baseline, and create a
checkpoint with the configured name.

### Guest Service Interface

Checks that the target VM has the Hyper-V integration service named
`Guest Service Interface` and that it is enabled. This is required when the
runner uses `Copy-VMFile` to move files between host and guest.

Fix: enable the integration service in Hyper-V Manager or with an elevated
operator command such as:

```powershell
Enable-VMIntegrationService -VMName 'KSwordSandbox-Win10-Golden' -Name 'Guest Service Interface'
```

### PowerShell Direct

When the process is elevated, Hyper-V is queryable, the VM exists, the VM state
is `Running`, and the guest password is visible, the script runs a read-only
PowerShell Direct probe:

```powershell
Invoke-Command -VMName '<vm>' -Credential '<in-memory credential>' -ScriptBlock {
    $PSVersionTable.PSVersion
}
```

If the VM is `Off`, the check is reported as `Warning` with
`RequiresRunning = true`; the preflight does not start the VM just to test
PowerShell Direct. If the password is missing, the password check fails and the
PowerShell Direct check is skipped with an explicit warning.

### Guest deployed payload files

When the PowerShell Direct probe passes, the script also checks whether the
golden VM already contains the expected deployed files:

```text
C:\KSwordSandbox\agent\KSword.Sandbox.Agent.exe
C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe
```

This check uses `Test-Path` inside the guest only. Missing deployed files are a
warning, not a hard failure, because the live runbook can stage tools from the
host payload root immediately before execution. Treat the warning as actionable
when refreshing the golden `Clean` checkpoint.

### Repository secret hygiene

When `KSWORDBOX_GUEST_PASSWORD` or the configured secret is visible and at least
8 characters long, readiness scans git tracked/untracked candidate text files
for that exact value. A match fails the preflight and lists only file names; the
secret value is not printed.

Use this as a final guard before staging local changes:

```powershell
.\scripts\Test-RepositoryPolicy.ps1 -StagedOnly
```

`Test-RepositoryPolicy.ps1` also blocks VM disks, samples, reports, binaries,
DPAPI backups, `install-state.json`, and other local artifacts. Use
`-SkipRepositorySecretScan` on readiness only when the current shell should not
read repository text files.

### Test signing status

Records the host current boot entry test-signing value with a read-only
`bcdedit.exe /enum {current}` query. This is informational for the default
mock/no-driver flow. For real R0 collection, treat a warning here as a reminder
to verify Windows test-signing inside the isolated guest VM manually; the
readiness script does not start the VM just to inspect guest boot state.

Use the installer change menu or the explicit helper only when you are ready to
touch the configured guest VM:

```powershell
.\install.ps1 -Mode Change -QueryGuestTestSigning
.\install.ps1 -Mode Change -EnableGuestTestSigning -RestartGuestAfterTestSigning -Force
.\scripts\Set-GuestTestSigning.ps1 -Mode Query
```

Driver signing is outside readiness. If a real R0 driver is required, use an
already test-signed `.sys` or the documented test-certificate helper
`.\scripts\Sign-SandboxDriverWithTestCertificate.ps1`; the readiness/install/run
path does not sign drivers or invoke legacy signing tools.

## Payload staging dependency

This preflight verifies host/VM readiness only. It does not build or copy guest
tools. Before refreshing the golden `Clean` checkpoint for a live run, prepare
the payload outside the repository and deploy it into the guest:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\Prepare-GuestPayload.ps1
```

Then follow `docs/guest-payload-staging.md` to copy the staged files into:

```text
C:\KSwordSandbox\agent
C:\KSwordSandbox\r0collector
```

At minimum, the configured guest agent path must exist before a live runbook can
produce `events.json`.

## Reporting and automation

To save machine-readable output while preserving the script exit code:

```powershell
$results = & .\scripts\Test-HyperVReadiness.ps1
$code = $LASTEXITCODE
$results | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 .\hyperv-readiness.json
exit $code
```

Automation should prefer `CheckId` and `RequiredForLive` over display names.
Use `ReadinessSummary.LiveReady` for the go/no-go gate and
`ReadinessSummary.RemediationHints` / `RecommendedActions` for operator repair
text. The summary `ReadOnlyAssertions` block explicitly records that no VM was
started, no checkpoint was restored, Guest Service Interface was not enabled,
and no probe files were written.

Do not commit generated readiness JSON files, runtime job folders, VM images, or
guest output. These are local operator artifacts.
