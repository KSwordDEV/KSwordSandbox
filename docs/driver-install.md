# 驱动安装、test-signing 与加载/卸载 Runbook

Canonical scope: this page owns the VM-only driver service install/start/stop
operator runbook and `Manage-SandboxDriver.ps1` JSON contract. Signing policy
and broader R0 validation boundaries live in `docs/driver-signing.md`; ABI
details live in `docs/r0-driver-core.md`.

本页中文优先。命令参数名（如 `-Action`、`-DriverPath`、`-SkipTestSigningCheck`）
和机器可读 JSON key（如 `Kind`、`Steps`、`Hints`、`CSignToolUsed`）保持英文，
不翻译。

普通用户先记住三条：

1. 只在隔离 Windows 测试 VM 中执行安装/启动/停止/卸载 driver。
2. 所有会修改 driver service、注册表、test-signing 或重启的操作，都需要管理员
   PowerShell。
3. 本流程禁止 `CSignTool.exe`；JSON 中 `CSignToolUsed=false` 是固定护栏。

遇到失败时，先看 JSON 的 `Error.Message` 和 `Hints`：

- 提示需要管理员：以管理员身份重新打开 VM 内 PowerShell 后重试。
- 提示 test-signing 关闭：在隔离 VM 管理员 PowerShell 中运行
  `bcdedit /set testsigning on`，重启，并信任测试证书。
- 提示签名不是 `Valid`：运行
  `.\scripts\Sign-SandboxDriverWithTestCertificate.ps1` 做测试签名，并把公钥证书信任到
  Root/TrustedPublisher。
- 提示找不到 INF：脚本会使用 `sc.exe` fallback；验证正式 minifilter 包装时请使用签名
  INF/pnputil 路径。
- 提示找不到 `.sys`：先构建或复制测试签名的
  `KSword.Sandbox.Driver.sys`，再传 `-DriverPath <path>`。

English summary: this runbook is for isolated test VMs only. It produces
machine-readable JSON and tells operators the next repair step in `Hints`.

This runbook is for isolated Windows test VMs only. The default repository
validation path remains compile-only: do not install or load the R0 driver from
normal build, smoke, or unattended Hyper-V plan checks.

## Guardrails

- Do **not** call `CSignTool.exe` and do not use
  `scripts\Sign-SandboxDriverWithKswordCSignTool.ps1`.
- Keep `.sys`, `.cat`, `.pdb`, certificates, private keys, and WDK output
  outside git.
- Mutating driver actions require an elevated PowerShell session.
- A test-signed driver requires all of the following before load:
  - a trusted test certificate in the test VM;
  - Windows test-signing enabled with `bcdedit /set testsigning on`;
  - a reboot after test-signing changes.

## Test-sign the driver without CSignTool

Run inside the disposable VM, or against a VM-local driver path:

```powershell
.\scripts\Sign-SandboxDriverWithTestCertificate.ps1 `
  -DriverPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -TrustCertificateForLocalMachine `
  -EnableLocalTestSigning `
  -Json
```

The JSON result includes `CSignToolUsed=false`, the certificate thumbprint,
`SignatureStatus`, `LocalTestSigningRequested`, and `RequiresReboot`.

If toggling test-signing inside the configured Hyper-V guest from the host, use
PowerShell Direct:

```powershell
.\scripts\Set-GuestTestSigning.ps1 `
  -VmName KSwordSandbox-Win10-Golden `
  -GuestUserName SandboxUser `
  -Mode Enable `
  -RestartGuest `
  -Force `
  -Json
```

## Driver service and minifilter status

Use the dedicated JSON helper:

```powershell
.\scripts\Manage-SandboxDriver.ps1 -Action Status
```

The script emits one JSON document with stable fields:

- `Kind`: `KSwordSandbox.DriverServiceOperation`
- `Action`, `ServiceName`, `DriverPath`, `InfPath`, `DriverKind`
- `Before` / `After`: SCM service state, minifilter state, Authenticode status,
  and BCDEdit test-signing state
- `Steps`: commands that ran or were skipped by `-WhatIf`
- `RequiresReboot`, `Hints`, `CSignToolUsed=false`, `Success`, `Error`

Packaging-compatible wrapper:

```powershell
.\scripts\install.ps1 -Mode Driver -DriverAction Status
```

## Install, start, stop, and uninstall

`Manage-SandboxDriver.ps1` auto-detects a built
`KSword.Sandbox.Driver.sys` and an optional `.inf`. If an INF exists or
`-InfPath` is supplied, install uses:

```text
pnputil.exe /add-driver <inf> /install
```

If no INF exists, the script falls back to `sc.exe`. The default
`-DriverKind MiniFilter` uses `type= filesys` and writes lab-only minifilter
`Instances` registry values. Prefer a signed INF with an assigned altitude for
production packaging.

Example VM-local sequence:

```powershell
$driver = 'C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys'

.\scripts\Manage-SandboxDriver.ps1 -Action Install -DriverPath $driver
.\scripts\Manage-SandboxDriver.ps1 -Action Start
.\scripts\Manage-SandboxDriver.ps1 -Action Status | ConvertFrom-Json
.\scripts\Manage-SandboxDriver.ps1 -Action Stop
.\scripts\Manage-SandboxDriver.ps1 -Action Uninstall
```

For a non-minifilter kernel-only build, pass `-DriverKind Kernel`.

If uninstalling an INF-installed package, pass the published `oem*.inf` name
when known:

```powershell
.\scripts\Manage-SandboxDriver.ps1 `
  -Action Uninstall `
  -InfPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.inf `
  -PublishedName oem42.inf
```

Without `-PublishedName`, the script still unloads/stops/deletes the service
and reports a hint explaining how to complete pnputil package removal.

## WhatIf and status validation

Preview a load-path mutation without touching SCM, FltMgr, or registry:

```powershell
.\scripts\Manage-SandboxDriver.ps1 `
  -Action Install `
  -DriverPath C:\KSwordSandbox\driver\KSword.Sandbox.Driver.sys `
  -WhatIf | ConvertFrom-Json
```

For CI/static validation, parse the scripts and exercise JSON status:

```powershell
$null = [System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\scripts\Manage-SandboxDriver.ps1),
  [ref]$null,
  [ref]$null)

.\scripts\Manage-SandboxDriver.ps1 -Action Status | ConvertFrom-Json
.\scripts\install.ps1 -Mode Driver -DriverAction Status | ConvertFrom-Json
```

`Status` is read-only: it queries `sc.exe`, `fltmc.exe`,
`Get-AuthenticodeSignature`, and `bcdedit.exe /enum`; it does not install,
start, stop, unload, open `\\.\KSwordSandboxDriver`, or call DeviceIoControl.
