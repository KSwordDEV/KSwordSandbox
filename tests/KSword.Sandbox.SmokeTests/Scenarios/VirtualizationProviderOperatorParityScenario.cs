using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the provider-neutral operator surface without invoking PowerShell,
/// virtualization tools, or VM mutations.
/// </summary>
internal sealed class VirtualizationProviderOperatorParityScenario : ISmokeTestScenario
{
    public string ScenarioId => "virtualization.operator-parity.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var runScript = Read(context, "run.ps1");
        Require(runScript, "Get-RunVirtualizationProvider", "run.ps1 should resolve the active provider.");
        Require(runScript, "'execute'", "run.ps1 should delegate Analyze to JobTool execute.");
        Require(runScript, "--provider", "run.ps1 should pass the selected provider.");
        Require(runScript, "--guest-ready-timeout-seconds", "run.ps1 should pass the shared guest readiness timeout.");
        Require(runScript, "--machine-definition-path", "run.ps1 should expose the same VMware/QEMU resource override as Web and Operator CLI.");
        Require(runScript, "--qemu-disk-format", "run.ps1 should pair QEMU disk overrides with an explicit format when requested.");
        Require(runScript, "Assert-RunProviderResourceOverrides", "run.ps1 should reject provider-specific options that do not apply to the selected provider.");
        Require(runScript, "$hasProviderOverride -and $Mode -notin @('Status', 'CheckEnvironment', 'Plan', 'Analyze')", "run.ps1 should reject a provider override that pure WebUI startup would otherwise ignore.");
        Require(runScript, "$provider -eq 'HyperV'", "Only Hyper-V should trigger automatic UAC elevation.");
        Require(runScript, "ProviderManagementAvailable", "Run status should not label VMware/QEMU management tools as the Hyper-V module.");
        Require(runScript, "Get-RunProviderHostPrerequisiteStatus", "Run status should inspect provider-neutral host acceleration prerequisites.");
        Require(runScript, "HostHardwareVirtualizationNotReadyOrUnconfirmed", "Run status should not claim Live readiness when host acceleration is false or unknown.");
        Require(runScript, "RequiredWindowsFeatureReady", "Run status should expose the selected provider's Windows feature readiness.");
        Require(runScript, "HypervisorPlatform", "QEMU readiness should require Windows Hypervisor Platform for WHPX.");
        Require(runScript, "Invoke-RunProviderReadOnlyCommand", "Run status provider tools should receive a sanitized process environment.");
        Require(runScript, "InvalidProviderConfiguration", "Run status should block Live for unsupported provider configuration.");
        Require(runScript, "ProviderExecutionToolReady", "Run status should expose provider-neutral JobTool readiness.");
        Require(runScript, "MissingProviderExecutionTool", "Run status should block Live when JobTool cannot execute.");
        Require(runScript, "BaselineName = $checkpointName", "Run status should expose a provider-neutral baseline identity while preserving legacy checkpoint fields.");
        Require(runScript, "BaselineExists = $checkpointExists", "Run readiness should expose provider-neutral baseline readiness.");
        Require(runScript, "ExpectedBaselineName = $snapshotName", "Run provider profile should expose the expected clean baseline alongside its checkpoint compatibility field.");
        Require(runScript, "QEMU per-job overlay or internal snapshot", "Run provider profile should explain QEMU baseline semantics.");
        Require(runScript, "RestoreCleanBaseline", "Run mutation policy should describe all providers with baseline terminology.");
        Require(runScript, "Test-RunBaselineRestoreRequiresVmMutation", "Run status should distinguish provider snapshot restoration from QEMU per-job overlay isolation.");
        Require(runScript, "Get-RunOperatorModeMatrix -Provider $provider -UseQemuOverlayDisk $qemuUseOverlayDisk", "Run status should build operator guidance from the active provider profile.");
        Require(runScript, "BaselineRestoreSatisfiedWithoutMutation = -not $restoreBaselineRequiresVmMutation", "Run status should expose when QEMU overlay isolation already satisfies the clean-baseline request.");
        Require(runScript, "BaselineIsolationMode = $baselineIsolationMode", "Run status should identify provider snapshot restoration versus QEMU per-job overlay semantics.");
        Require(runScript, "RestoreBaselineWhatIfCommand = $restoreBaselineWhatIfCommand", "Run status should not require mutation approval for the QEMU overlay no-op path.");
        Require(runScript, "RestoreCleanCheckpoint -Json", "Run status should offer a direct machine-readable QEMU overlay clean-baseline result without mutation flags.");
        Require(runScript, "OperatorModeMatrix = @($runStatus.OperatorModeMatrix)", "Environment check should preserve the provider-specific operator matrix from run status.");
        Require(runScript, "RestoreCheckpointWhatIfCommand = $runStatus.RestoreCheckpointWhatIfCommand", "Environment check should preserve provider-specific restore compatibility commands.");
        Require(runScript, "LegacyAnalyzeLiveMutationOperations", "Run mutation policy should retain an explicit compatibility view for checkpoint-era consumers.");
        Require(runScript, "ProviderNeutralBlockingReasons", "Run readiness should expose provider-neutral blocker names without deleting legacy values.");
        Require(runScript, "ProviderQueryAttempted", "Run status should distinguish an unavailable resource from a provider command that failed after launch.");
        Require(runScript, "ProviderQuerySucceeded", "Run status and readiness should expose provider query success independently of resource existence.");
        Require(runScript, "ProviderAccessDenied", "Run status should expose provider management permission failures explicitly.");
        Require(runScript, "-ProviderAccessDenied $providerAccessDenied", "Run readiness verdict should retain the provider permission diagnosis.");
        Require(runScript, "ProviderQueryFailed", "Run readiness should not misreport a failed provider query as a missing baseline.");
        Require(runScript, "Test-RunProviderAccessDenied", "Run status should classify standard provider permission errors consistently.");
        Require(runScript, "VmProfileHealthy = ($providerConfigurationReady -and $providerQuerySucceeded", "Run status should not call a partially queried provider profile healthy.");
        Require(runScript, "$processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5)", "Run status should ignore a QEMU pid marker that belongs to an older process instance.");
        Require(runScript, "Get-RunExpectedQemuProcessVmName", "Run status should reconstruct QEMU's bounded per-job VM identity before matching an active process.");
        Require(runScript, "function Get-RunActiveQemuPids", "Run status should inspect every active QEMU identity instead of returning the first match.");
        Require(runScript, "$diagnosticCode = 'QEMU_PROCESS_IDENTITY_AMBIGUOUS'", "Run status should fail closed when duplicate QEMU instances match the selected profile.");
        Require(runScript, "$maximumPrefixLength = 64 - $suffix.Length", "Run status should retain the complete QEMU job suffix when the configured VM prefix is long.");
        Require(runScript, "Test-RunQemuCommandLineVmName", "Run status should match the exact QEMU -name argument rather than an arbitrary VM-name substring.");
        Require(runScript, "QEMU_USER_NAT_PORT_UNAVAILABLE", "Run status should block QEMU user-NAT before launch when its WinRM forwarding port is occupied.");
        Require(runScript, "GuestRemotingPortAvailable = $guestRemotingPortAvailable", "Run status should expose QEMU host-forward port availability.");
        Require(runScript, "Test-RunQemuProcessOwnsUserNatPort", "Run status should only exempt a running QEMU process that owns the configured host-forward port.");
        Require(runScript, "ActiveQemuOwnsGuestRemotingPort", "Run status should expose whether its active QEMU process owns the configured host-forward port.");
        Require(runScript, "MissingConfiguredBaseline", "Run readiness should not require QEMU overlay users to interpret a checkpoint-only blocker.");
        Require(runScript, "MissingGuestTransportEndpoint", "Run readiness should cover automatic VMware/QEMU guest endpoints without claiming a literal address is always required.");
        Require(runScript, "Basic WinRM over HTTP is refused", "Run status should reject insecure Basic guest remoting.");
        Require(runScript, "Automatic guest endpoint modes require WinRM HTTPS", "Run status should reject automatic endpoints that depend on host-wide TrustedHosts.");
        Require(runScript, "QEMU internal snapshot mode requires qcow2", "Run status should reject unsupported QEMU internal snapshot formats.");
        Require(runScript, "Player 配置不能进入 Live", "Run status should reject legacy VMware Player profiles before provider queries or VM mutation.");
        Require(runScript, "if=none leaves the provider-managed disk unattached", "Run status should reject QEMU profiles without an attached boot disk.");
        Require(runScript, "managed SCSI topology is provider-owned", "Run status should reserve the provider-managed QEMU SCSI topology.");

        var webApiE2E = Read(context, Path.Combine("scripts", "Invoke-WebUIApiE2E.ps1"));
        Require(webApiE2E, "[ValidateSet('', 'HyperV', 'VMware', 'Qemu')]", "Web API E2E should select the same three providers as the product UI.");
        Require(webApiE2E, "$planBody.provider = $Provider", "Web API E2E should submit its provider as job data.");
        Require(webApiE2E, "$planBody.machineDefinitionPath = $MachineDefinitionPath", "Web API E2E should support VMware VMX and QEMU base-disk overrides.");
        Require(webApiE2E, "$planBody.qemuDiskFormat = $QemuDiskFormat.ToLowerInvariant()", "Web API E2E should pair QEMU disk overrides with their format.");
        Require(webApiE2E, "Get-E2EProviderReadiness", "Web API E2E should capture selected-provider readiness before planning or live mutation.");
        Require(webApiE2E, "/api/host/readiness?refresh=true", "Web API E2E should use the product's provider-neutral read-only readiness endpoint.");
        Require(webApiE2E, "hardwareAccelerationReady -eq $true", "Live Web API E2E should require confirmed host hardware acceleration.");
        Require(webApiE2E, "providerBaselineExists = [bool]$providerReadiness.virtualization.baselineExists", "Web API E2E evidence should retain selected-provider clean-baseline readiness.");
        Require(webApiE2E, "providerGuestTransportSecure = [bool]$providerReadiness.virtualization.guestTransportSecure", "Web API E2E evidence should retain selected-provider guest transport security.");
        Require(webApiE2E, "providerResourceOverrideUsed = $hasProviderResourceOverride", "Web API E2E evidence should distinguish config-profile readiness from per-job resource overrides.");
        Require(webApiE2E, "Get-E2EGitProvenance", "Web API E2E evidence should resolve checkout provenance before live provider mutation.");
        Require(webApiE2E, "Live parity evidence requires a full Git commit", "Live Web API E2E should fail before VM mutation when source commit provenance is unavailable.");
        Require(webApiE2E, "gitCommit            = $gitProvenance.commit", "Web API E2E evidence should retain the full source commit.");
        Require(webApiE2E, "gitDirty             = $gitProvenance.dirty", "Web API E2E evidence should disclose a dirty checkout.");
        Require(webApiE2E, "package-manifest.generated.json", "Packaged Web API E2E should recover immutable source provenance without requiring a .git directory.");
        Require(webApiE2E, "Clean-source parity evidence requires gitDirty=false", "Release-grade Web API E2E should fail before VM mutation when source cleanliness is not proven.");
        Require(webApiE2E, "runtimeRoot          = [string]$providerReadiness.paths.runtimeRoot.path", "Web API E2E evidence should retain the runtime root that owns job artifacts and the live lease.");
        Require(webApiE2E, "generatedAtLocal     = $generatedAt.ToString('O')", "Web API E2E evidence should retain a local timestamp with UTC offset.");
        Require(webApiE2E, "sampleSha256         = $sampleSha256", "Web API E2E evidence should retain the exact sample bytes used by each provider.");
        Require(webApiE2E, "sampleSizeBytes      = [long]$sampleFile.Length", "Web API E2E evidence should retain sample size for cross-provider comparison.");
        Require(webApiE2E, "requestedDurationSeconds = $DurationSeconds", "Web API E2E evidence should retain the requested analysis duration.");
        Require(webApiE2E, "[string]$ExecutionTransport = 'Background'", "Web API E2E should exercise the same background runner used by the product UI by default.");
        Require(webApiE2E, "/runbook/start", "Web API E2E should cover the preferred background runbook start endpoint.");
        Require(webApiE2E, "/runbook/background", "Web API E2E should wait for the background terminal state before reading reports.");
        Require(webApiE2E, "executionTransport   = $ExecutionTransport", "Web API E2E evidence should record whether it used the background or compatibility blocking path.");
        Require(webApiE2E, "$backgroundState = if ($null -ne $background)", "Web API E2E evidence should record the terminal background-runner state.");
        Require(webApiE2E, "Background terminal VMX/base-disk identity", "Web API E2E should prove that the actual background terminal job retained the planned provider resource.");
        Require(webApiE2E, "guestImportSkipped   = [bool]$payload.guestImportSkipped", "Web API E2E evidence should distinguish skipped guest import from success and failure.");
        Require(webApiE2E, "guestImportFailed    = [bool]$payload.guestImportFailed", "Web API E2E evidence should retain guest import failure state.");
        Require(webApiE2E, "Execution provider", "Web API E2E should prove that execution retained the planned provider.");
        Require(webApiE2E, "Report provider", "Web API E2E should prove that report regeneration retained the planned provider.");
        Require(webApiE2E, "Report VMX/base-disk identity", "Web API E2E should compare report resources with the effective runbook.");
        Require(webApiE2E, "Report sample SHA-256 does not match", "Web API E2E should compare report sample identity with the bytes hashed before planning.");
        Require(webApiE2E, "Sample bytes changed between planning", "Web API E2E should detect sample mutation across the live run.");
        Require(webApiE2E, "machineDefinitionPath = $effectiveMachineDefinitionPath", "Web API E2E evidence should record the effective VMX or QEMU base disk.");

        var parityEvidenceValidator = Read(context, Path.Combine("scripts", "Test-ProviderParityEvidence.ps1"));
        Require(parityEvidenceValidator, "ksword.provider-parity-evidence.v1", "Provider parity should produce one versioned aggregate validation artifact.");
        Require(parityEvidenceValidator, "Provider summaries do not share one gitCommit", "Provider parity should reject summaries from different source commits.");
        Require(parityEvidenceValidator, "Provider summaries did not execute the same sample bytes", "Provider parity should compare both sample SHA-256 and byte size.");
        Require(parityEvidenceValidator, "Provider summaries do not share one requestedDurationSeconds value", "Provider parity should require the same requested duration.");
        Require(parityEvidenceValidator, "Each provider must retain a distinct jobId", "Provider parity should require three independent jobs.");
        Require(parityEvidenceValidator, "gitDirty' -Expected $false", "Provider parity should reject dirty-source evidence.");
        Require(parityEvidenceValidator, "providerResourceOverrideUsed", "Provider parity should distinguish profile readiness from explicit resource overrides.");
        Require(parityEvidenceValidator, "providerDiagnosticCode is empty", "Provider parity should require a selected-provider diagnostic identity.");
        Require(parityEvidenceValidator, "Microsoft-Hyper-V-All", "Provider parity should retain Hyper-V's required Windows feature identity.");
        Require(parityEvidenceValidator, "HypervisorPlatform", "Provider parity should retain QEMU WHPX's required Windows feature identity.");
        Require(parityEvidenceValidator, "guest events evidence contains no rows", "Provider parity should reject an empty imported guest event artifact.");
        Require(parityEvidenceValidator, "must retain exactly three report endpoint checks", "Provider parity should require default, Chinese, and English report endpoint evidence.");
        Require(parityEvidenceValidator, "Read-ParityJsonFile -Path $evidencePaths.runbookExecutionPath", "Provider parity should cross-check persisted runbook execution evidence.");
        Require(parityEvidenceValidator, "runbook execution targetVmName does not match its summary", "Provider parity should cross-check executed provider resource identity.");
        Require(parityEvidenceValidator, "report status must be Completed", "Provider parity should require a completed final report.");
        Require(parityEvidenceValidator, "report sample SHA-256 does not match its summary", "Provider parity should cross-check sample identity against report.json.");
        Require(parityEvidenceValidator, "summarySha256 = Get-ParityFileSha256", "Aggregate parity evidence should fingerprint every provider summary.");
        Require(parityEvidenceValidator, "evidenceSha256 = $evidenceSha256", "Aggregate parity evidence should fingerprint every referenced execution and report artifact.");
        Require(parityEvidenceValidator, "validationPath = $resolvedOutputPath", "Aggregate parity evidence should retain its durable validation path.");

        var installer = Read(context, "install.ps1");
        foreach (var expected in new[]
                 {
                     "UpdateVirtualizationConfig", "VMwareVmxPath", "QemuDiskImagePath", "QemuAdditionalArguments",
                     "qemuAdditionalArguments", "GuestRemotingAddress", "GuestRemotingAddressMode", "GuestRemotingSkipCertificateChecks",
                     "VMwareHeadless", "QemuMemoryMegabytes", "QemuHeadless",
                     "@('-accel', 'whpx')",
                     "Get-InstallProviderHostPrerequisiteStatus", "ksword.provider-host-prerequisites.v1",
                     "HostHardwareVirtualizationNotReadyOrUnconfirmed", "RequiredWindowsFeatureReady", "HypervisorPlatform",
                     "Invoke-InstallProviderCommand", "SensitiveEnvironmentCleared = $true",
                     "拒绝通过 HTTP 使用 Basic WinRM",
                     "自动端点模式固定使用 HTTPS", "宿主机全局 TrustedHosts",
                     "Get-InstallProviderProfileStatus", "Add-MissingSandboxConfigProperties",
                     "GuestTransportSecure = $guestTransportSecure", "GuestRemotingAuthentication = if",
                     "Initialize-LegacyGuestRemotingAddressModes",
                     "Import-SelectedVirtualizationProfileFromLocalConfig", "revertToSnapshot",
                     "@('snapshot', '-a'", "@('info', '--output=json'", "Stop-ConfiguredQemuProcesses",
                     "没有有效原生 qemu.pid 归属标记",
                     "vmrun listSnapshots 失败", "vmrun list 失败",
                     "Reset-RemoteGuestPassword.ps1", "ActualGuestPasswordResetSupported = $true",
                     "winrm-and-replacement-baseline", "winrm-or-offline-vhdx-and-replacement-baseline",
                     "ActualGuestPasswordUnknownOldPasswordRecoverySupported", "RecoverGuestVmPasswordWithoutCurrentSecret",
                     "ActualGuestPasswordUnknownOldPasswordRecoveryReady", "offline-vhdx-full-clone-replacement-vmx",
                     "ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady",
                     "ActualGuestPasswordUnknownOldPasswordRecoveryLayoutValidation", "deferred-to-isolated-full-clone",
                     "-not [bool]$result.OldBaselinePreserved", "-not [bool]$result.OfflineGuestServiceCleanupConfirmed", "$oldProcessWebConfigPath",
                     "本机回滚不完整", "KSWORDBOX_PASSWORD_RESET_",
                     "QEMU PID 标记", "无法确认进程归属", "尚未停止或修改 VM",
                     "尚未停止进程或修改镜像", "candidate.ExecutablePath",
                     "executable/pidfile/runtime", "未归属的外部 QEMU 进程"
                 })
        {
            Require(installer, expected, $"Installer parity contract is missing '{expected}'.");
        }
        Require(installer, "[ValidateSet('ws')]", "The installer should expose only the Workstation Pro vmrun target.");
        Require(installer, "不再支持 Player 配置", "The installer should explain how a legacy Player profile must be migrated.");
        Require(installer, "[ValidateSet('virtio', 'ide', 'scsi')]", "The installer should expose only QEMU disk interfaces that attach the managed boot disk.");
        Require(installer, "Player profile 不会调用 vmrun", "Installer readiness should reject Player before provider process invocation.");
        Require(installer, "旧 Player profile 不会调用 vmrun", "Installer snapshot restore should reject Player before provider process invocation.");
        Require(installer, "Wait-InstallVMwarePowerState", "Installer restore should wait for VMware to reach the requested power state.");
        Require(installer, "受管 SCSI 拓扑由 provider 保留", "Installer validation should reserve the provider-managed QEMU SCSI topology.");
        Require(installer, "[Alias('GuestReadyTimeoutSeconds')]", "The installer should expose a provider-neutral guest readiness timeout name while preserving its legacy parameter.");
        Require(installer, "[Alias('BaselineName', 'SnapshotName')]", "The installer should accept provider-neutral baseline naming while preserving CheckpointName.");
        Require(installer, "Enter-InstallLiveExecutionLease", "Installer VM maintenance should share the Web/CLI live execution lease.");
        Require(installer, "[System.IO.FileShare]::None", "Installer maintenance lease should provide cross-process exclusion.");
        Require(installer, "restore $VirtualizationProvider baseline", "Provider baseline restore should acquire the shared lease before mutation.");
        Require(installer, "$VirtualizationProvider guest password reset", "Provider password replacement should hold the shared lease through metadata commit.");
        Require(installer, "$VirtualizationProvider guest test-signing $TestSigningMode", "Provider test-signing maintenance should acquire the shared lease.");
        Require(installer, "不要通过删除文件绕过 lease", "Lease contention guidance should not tell operators to delete a persistent lock file.");
        Require(installer, "LiveExecutionLeasePath =", "Installer status should expose the shared provider-neutral lease path.");
        Require(installer, "LiveExecutionLeaseScope = 'web-cli-installer-provider-maintenance'", "Installer status should explain the complete live lease scope.");
        Require(installer, "LiveExecutionLeaseFilePresenceMeansHeld = $false", "Installer status should distinguish a persistent lock file from an owned lease.");
        Require(installer, "BaselineName = $CheckpointName", "Installer status should expose a provider-neutral baseline identity.");
        Require(installer, "BaselineExists = $checkpointExists", "Installer readiness should expose provider-neutral baseline readiness.");
        Require(installer, "ExpectedBaselineName = $CheckpointName", "Installer provider profiles should expose the expected clean baseline alongside checkpoint compatibility fields.");
        Require(installer, "QEMU per-job overlay or internal snapshot", "Installer provider profiles should explain QEMU baseline semantics.");
        Require(installer, "RestoreBaselineRequiresAllowVmMutation", "Installer mutation policy should expose a provider-neutral baseline restore contract.");
        Require(installer, "Test-InstallBaselineRestoreRequiresVmMutation", "Installer restore semantics should distinguish a provider snapshot restore from QEMU per-job overlay isolation.");
        Require(installer, "BaselineRestoreSatisfiedWithoutMutation", "Installer diagnostics should expose when QEMU overlay isolation already satisfies the clean-baseline request.");
        Require(installer, "RestoreCleanBaselineRequested", "Installer diagnostics should expose the provider-neutral clean-baseline intent.");
        Require(installer, "ProviderSnapshotRestoreRequested", "Installer diagnostics should distinguish an actual provider snapshot restore from overlay isolation.");
        Require(installer, "BaselineIsolationMode = if", "Installer diagnostics should identify provider snapshot restore versus QEMU per-job overlay semantics.");
        Require(installer, "QemuOverlayRestoreDoesNotMutate", "Installer safety assertions should prove that the QEMU overlay restore-equivalent path does not mutate a VM.");
        Require(installer, "无需 -AllowVmMutation/-Confirm", "QEMU overlay guidance should not require mutation approval for a no-op clean-baseline result.");
        Require(installer, "未调用任何 provider stop/restore 命令", "QEMU overlay restore-equivalent handling should state that no provider mutation command ran.");
        Require(installer, "QemuUseOverlayDisk = $VirtualizationProvider -eq 'Qemu'", "Installer status should expose the active QEMU overlay mode at the top level.");
        Require(installer, "回退/恢复已有 clean baseline（Hyper-V checkpoint / VMware snapshot / QEMU internal snapshot；overlay 只确认干净启动）", "The root installer menu should describe one provider-neutral clean-baseline workflow.");
        Require(installer, "RestoreBaselinePlanCommand = $installStatus.RestoreBaselinePlanCommand", "Installer environment check should preserve the status restore plan command.");
        Require(installer, "BaselineRestoreRequiresVmMutation = $installStatus.BaselineRestoreRequiresVmMutation", "Installer environment check should preserve provider-specific baseline mutation semantics.");
        Require(installer, "RestoreCheckpointCommand = $installStatus.RestoreCheckpointCommand", "Installer environment check should retain provider-specific compatibility restore commands.");
        Require(installer, "ProviderNeutralBlockingReasons", "Installer readiness should expose provider-neutral blocker names without deleting legacy values.");
        Require(installer, "ProviderQueryAttempted", "Installer status should distinguish an unavailable resource from a provider command that failed after launch.");
        Require(installer, "ProviderQuerySucceeded", "Installer status and readiness should expose provider query success independently of resource existence.");
        Require(installer, "ProviderAccessDenied", "Installer status should expose provider management permission failures explicitly.");
        Require(installer, "-ProviderAccessDenied $providerAccessDenied", "Installer readiness verdict should retain the provider permission diagnosis.");
        Require(installer, "ProviderQueryFailed", "Installer readiness should not misreport a failed provider query as a missing baseline.");
        Require(installer, "Test-InstallProviderAccessDenied", "Installer status should classify standard provider permission errors consistently.");
        Require(installer, "VmProfileHealthy = ([bool]$vmProfile.ConfigurationReady -and $providerQuerySucceeded", "Installer status should not call a partially queried provider profile healthy.");
        Require(installer, "进程启动时间与标记不匹配", "Installer baseline restore should refuse a reused QEMU pid before stopping a process.");
        Require(installer, "$processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5)", "Installer status should ignore stale QEMU process-instance markers.");
        Require(installer, "Get-ConfiguredQemuExpectedProcessVmName", "Installer status should reconstruct QEMU's bounded per-job VM identity before matching an active process.");
        Require(installer, "function Get-ConfiguredQemuActivePids", "Installer status should inspect every active QEMU identity instead of returning the first match.");
        Require(installer, "$profile.DiagnosticCode = 'QEMU_PROCESS_IDENTITY_AMBIGUOUS'", "Installer status should fail closed when duplicate QEMU instances match the selected profile.");
        Require(installer, "$maximumPrefixLength = 64 - $suffix.Length", "Installer status should retain the complete QEMU job suffix when the configured VM prefix is long.");
        Require(installer, "Test-ConfiguredQemuCommandLineVmName", "Installer status should bind an active QEMU pidfile to the exact -name argument.");
        Require(installer, "Test-InstallCanBindLoopbackPort", "Installer readiness should probe the QEMU user-NAT forwarding port without starting a VM.");
        Require(installer, "QEMU_USER_NAT_PORT_UNAVAILABLE", "Installer readiness should expose an actionable QEMU host-forward port conflict.");
        Require(installer, "Test-ConfiguredQemuProcessOwnsUserNatPort", "Installer readiness should only exempt a QEMU process that owns the configured host-forward port.");
        Require(installer, "ActiveQemuOwnsGuestRemotingPort", "Installer readiness should expose active QEMU host-forward ownership.");
        Require(installer, "Select-VMwareVmxAndSnapshotInteractive", "The root installer should offer read-only VMware VMX and snapshot selection.");
        Require(installer, "@('-T', 'ws', 'listSnapshots', $resolvedVmxPath)", "VMware interactive selection should use provider-native read-only snapshot discovery.");
        Require(installer, "Select-QemuDiskMetadataAndSnapshotInteractive", "The root installer should offer read-only QEMU disk metadata and internal snapshot selection.");
        Require(installer, "qemu-img info --output=json", "QEMU interactive selection should state its read-only metadata boundary.");
        Require(installer, "Per-job overlay supplies the clean baseline", "QEMU overlay setup should not ask the operator to select an unused internal snapshot.");
        Require(installer, "'-QemuSystemPath', $QemuSystemPath", "Installer test-signing maintenance should forward the configured QEMU executable.");
        Require(installer, "'-RuntimeRoot', $RuntimeRoot", "Installer test-signing maintenance should forward the runtime root used for QEMU ownership markers.");

        var guestTestSigning = Read(context, Path.Combine("scripts", "Set-GuestTestSigning.ps1"));
        Require(guestTestSigning, "Resolve-QemuUserNatOwner", "QEMU guest test-signing should bind the loopback endpoint to an owned provider process.");
        Require(guestTestSigning, "LastWriteTimeUtc", "QEMU guest test-signing should bind its pid marker to the process start time.");
        Require(guestTestSigning, "Win32_Process.ExecutablePath", "QEMU guest test-signing should verify the configured QEMU executable identity.");
        Require(guestTestSigning, "matchesProviderPidFile", "QEMU guest test-signing should require the provider-owned native pidfile identity.");
        Require(guestTestSigning, "matchesProviderRuntime", "QEMU guest test-signing should require the provider-owned runtime job identity.");
        Require(guestTestSigning, "hostfwd=tcp:127.0.0.1:$HostPort-:", "QEMU guest test-signing should verify the exact provider-owned WinRM forwarding port.");
        Require(guestTestSigning, "provider-managed-user-nat-verified", "QEMU guest test-signing should report a verified endpoint source.");
        Require(guestTestSigning, "GuestRemotingOwnerProcessId", "Guest test-signing output should retain the verified QEMU process identity.");

        var installerWrapper = Read(context, Path.Combine("scripts", "install.ps1"));
        Require(installerWrapper, "[ValidateSet('ws')]", "The packaged installer wrapper should expose only Workstation Pro.");
        Require(installerWrapper, "VMwareHeadless = 'vmwareHeadless'", "Installer wrapper should restore the VMware headless setting.");
        Require(installerWrapper, "QemuHeadless = 'qemuHeadless'", "Installer wrapper should restore the QEMU headless setting.");
        Require(installerWrapper, "QemuMemoryMegabytes = [int]$memoryProperty.Value", "Installer wrapper should restore QEMU memory from install state.");
        Require(installerWrapper, "GuestRemotingAddressMode = 'guestRemotingAddressMode'", "Installer wrapper should restore the structured guest endpoint mode.");
        Require(installerWrapper, "VMwareTools", "Installer wrapper should offer VMware Tools endpoint discovery.");
        Require(installerWrapper, "QemuUserNat", "Installer wrapper should offer provider-managed QEMU user-NAT.");
        Require(installerWrapper, "回退/恢复已有 clean baseline（Hyper-V checkpoint / VMware snapshot / QEMU internal snapshot；overlay 只确认干净启动）", "The packaged installer menu should preserve provider-neutral clean-baseline terminology.");
        Require(installerWrapper, "Automatic endpoints require HTTPS", "Installer wrapper should force HTTPS for automatic endpoint modes.");
        Require(installerWrapper, "[Alias('GuestReadyTimeoutSeconds')]", "The packaged installer wrapper should expose the provider-neutral guest readiness timeout alias.");
        Require(installerWrapper, "[Alias('BaselineName', 'SnapshotName')]", "The packaged installer wrapper should preserve provider-neutral baseline aliases.");
        Require(installerWrapper, "Select-ScriptVMwareVmxAndSnapshotInteractive", "The packaged installer should preserve VMware VMX and snapshot selection.");
        Require(installerWrapper, "Select-ScriptQemuDiskMetadataAndSnapshotInteractive", "The packaged installer should preserve QEMU disk metadata and internal snapshot selection.");
        Require(installerWrapper, "Invoke-ScriptReadOnlyProviderCommand", "Packaged provider discovery should share a secret-sanitized read-only command wrapper.");
        Require(installerWrapper, "SetEnvironmentVariable($name, $null, 'Process')", "Packaged provider discovery should not expose process secrets to vmrun or qemu-img.");

        var remotePasswordReset = Read(context, Path.Combine("scripts", "Reset-RemoteGuestPassword.ps1"));
        Require(remotePasswordReset, "[ValidateSet('ws')]", "VMware password maintenance should accept only the Workstation Pro vmrun target.");
        Require(remotePasswordReset, "Wait-VMwareVmPowerStateChecked", "VMware password maintenance should share a bounded running/stopped state wait.");
        Require(remotePasswordReset, "did not reach $expectedState state within 60 seconds", "VMware password maintenance should fail bounded waits with the expected state.");
        Require(remotePasswordReset, "vmrun failure rollback stop", "VMware password-reset rollback should wait for stop before restoring the prior snapshot.");
        Require(remotePasswordReset, "Cleanup is incomplete", "VMware password maintenance should preserve the primary failure while reporting incomplete cleanup.");
        Require(remotePasswordReset, "vmrun rollback to original snapshot", "VMware password maintenance should use checked rollback after a verified stop.");
        Require(remotePasswordReset, "qemu-img rollback to original snapshot", "QEMU password maintenance should use checked rollback after a verified stop.");
        Require(remotePasswordReset, "Secret-bearing QEMU password-reset workspace could not be removed", "QEMU password maintenance should confirm removal of temporary disks containing the replacement password.");
        Require(remotePasswordReset, "virtio-scsi-pci,id=ksword-scsi", "QEMU password maintenance should attach SCSI disks through a managed controller.");
        Require(remotePasswordReset, "managed SCSI topology", "QEMU password maintenance should reject collisions with the managed SCSI topology.");
        Require(remotePasswordReset, "CurrentPasswordSecretName", "Remote password reset should receive only the current secret name.");
        Require(remotePasswordReset, "NewPasswordSecretName", "Remote password reset should receive only the replacement secret name.");
        Require(remotePasswordReset, "OldBaselinePreserved = $true", "Remote password reset should preserve the old provider baseline.");
        Require(remotePasswordReset, "ProviderChildSecretEnvironmentCleared = $true", "Provider tools must not inherit guest password environment variables.");
        Require(remotePasswordReset, "SetEnvironmentVariable($CurrentPasswordSecretName, $null, 'Process')", "The child should clear the current password environment variable before provider tools start.");
        Require(remotePasswordReset, "StartsWith('KSWORDBOX_'", "The child should sanitize KSword process secrets before launching provider tools.");
        Require(remotePasswordReset, "Basic WinRM over HTTP is refused", "Password rotation should reject Basic authentication without TLS.");
        Require(remotePasswordReset, "automatic endpoint mode requires GuestRemotingUseSsl", "Password rotation should enforce HTTPS for provider-managed endpoints.");
        Require(remotePasswordReset, "GuestRemotingSkipCertificateChecks is valid only", "Password rotation should reject certificate-skip without TLS.");
        Require(remotePasswordReset, "Test-QemuWhpxAdditionalArguments", "Password rotation should enforce the same QEMU accelerator contract.");
        Require(remotePasswordReset, "Escape-QemuDriveOptionValue", "Password rotation should preserve QEMU disk paths containing commas.");
        Require(remotePasswordReset, "qemu-img create replacement baseline", "QEMU overlay password reset should create a replacement base image.");
        Require(remotePasswordReset, "Select-VMwareGuestAddress", "VMware password maintenance should use deterministic routable-address selection.");
        Require(remotePasswordReset, "vmrun create replacement snapshot", "VMware password reset should create a replacement snapshot.");
        Require(remotePasswordReset, "Stop-VMwareVmChecked", "VMware password reset should verify the VM is stopped before baseline operations.");
        Require(remotePasswordReset, "getGuestIPAddress", "VMware password reset should discover the restored guest address through VMware Tools.");
        Require(remotePasswordReset, "hostfwd=tcp:127.0.0.1", "QEMU password reset should own its WinRM user-NAT forwarding rule.");
        Require(remotePasswordReset, "id/netdev=ksword-net", "QEMU password reset should reject collisions with the managed network identity.");
        Require(remotePasswordReset, "-Filter 'qemu.pid'", "QEMU password reset should stop provider-owned overlay jobs through runtime PID markers before changing a baseline.");
        Require(remotePasswordReset, "executable/pidfile/runtime identity does not match", "QEMU password reset should refuse PID markers whose process ownership cannot be proved.");
        Require(remotePasswordReset, "process instance start time does not match the marker", "QEMU password reset should refuse a reused pid before changing the baseline.");
        Require(remotePasswordReset, "'-pidfile', $PidPath", "QEMU password-reset launches should publish their native PID marker for crash recovery.");
        Require(remotePasswordReset, "did not publish its native -pidfile marker", "QEMU password-reset launches should fail when QEMU does not publish its native marker.");
        Require(remotePasswordReset, "does not match newly started process", "QEMU password-reset launches should bind the native marker to the process they just created.");
        SmokeAssert.True(
            !remotePasswordReset.Contains("$process.Id | Set-Content -LiteralPath $PidPath", StringComparison.Ordinal),
            "QEMU password maintenance must not overwrite QEMU's native pidfile from PowerShell.");
        Require(remotePasswordReset, "$portProbe.ExclusiveAddressUse = $true", "QEMU password reset should perform the same exclusive user-NAT port preflight as normal live execution.");
        Require(remotePasswordReset, "no QEMU process was started", "QEMU password reset should diagnose a user-NAT port conflict before launch.");
        Require(remotePasswordReset, "found an unowned process", "QEMU password reset should refuse to terminate an external process using its managed disk.");
        Require(remotePasswordReset, "without a valid native qemu.pid ownership marker", "QEMU password reset should never auto-stop a disk-matching process without native pidfile ownership.");
        Require(remotePasswordReset, "$cleanupErrors.Count -eq 0 -and (Test-Path -LiteralPath $resetRoot", "QEMU password reset should preserve an active working directory when process cleanup fails.");
        Require(remotePasswordReset, "Invoke-QemuOfflinePasswordRecovery", "QEMU should support recovery when the current guest password is unknown.");
        Require(remotePasswordReset, "materialize clean baseline as temporary VHDX", "QEMU offline recovery should materialize the selected clean baseline without modifying it.");
        Require(remotePasswordReset, "create offline-recovery replacement baseline", "QEMU offline recovery should commit only to a replacement disk.");
        Require(remotePasswordReset, "Invoke-VMwareOfflinePasswordRecovery", "VMware Workstation Pro should support unknown-password recovery through an isolated replacement VMX.");
        Require(remotePasswordReset, "Confirm-RemoteOfflinePasswordResetCleanup", "VMware and QEMU offline recovery should confirm the one-shot guest service removed its injected script before creating a baseline.");
        Require(remotePasswordReset, "OfflineGuestServiceCleanupConfirmed", "Offline recovery should report the guest cleanup contract to the parent installer.");
        Require(remotePasswordReset, "vmrun create offline-recovery full clone", "VMware offline recovery should clone the clean snapshot instead of modifying the source VMX.");
        Require(remotePasswordReset, "exactly one VMDK disk reference", "VMware offline recovery should reject ambiguous multi-disk VMX layouts.");
        Require(remotePasswordReset, "requires a powered-off clean snapshot", "VMware offline recovery should reject memory snapshots before replacing a clone disk.");
        Require(remotePasswordReset, "NewVmxPath", "VMware offline recovery should return the verified replacement VMX for transactional config commit.");
        Require(remotePasswordReset, "NewVmName", "VMware offline recovery should transactionally switch the logical VM name with the replacement VMX.");
        Require(remotePasswordReset, "OfflineTemporaryWorkspaceRemoved", "Offline recovery should report that its secret-bearing temporary VHDX workspace was removed.");

        var offlineInjector = Read(context, Path.Combine("scripts", "Inject-OfflineGuestPasswordService.ps1"));
        Require(offlineInjector, "Mount-DiskImage", "Offline injection should use provider-neutral Windows Storage mounting rather than a Hyper-V cmdlet.");
        Require(offlineInjector, "Dismount-DiskImage", "Offline injection should always detach its temporary VHDX.");
        Require(offlineInjector, "refuses an already attached VHDX", "Offline injection should refuse to reuse an ambiguous existing disk attachment.");
        Require(offlineInjector, "stale guest password-reset artifact", "Offline injection should remove stale reset markers before the replacement VM boots.");
        Require(offlineInjector, "LocalSystem", "Offline recovery should use a one-shot LocalSystem guest service.");
        Require(offlineInjector, "ProviderChildSecretEnvironmentCleared = $true", "Offline injection should clear inherited password secrets.");

        var readinessProbe = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Infrastructure", "LocalHostReadinessProbe.cs"));
        Require(readinessProbe, "VMWARE_WORKSTATION_PRO_REQUIRED", "Web readiness should fail legacy Player profiles before invoking vmrun.");
        Require(readinessProbe, "managed disk would not be attached to a boot device", "Web readiness should reject QEMU if=none profiles consistently with Core.");
        Require(readinessProbe, "SanitizeProviderProcessEnvironment", "Provider readiness tools should receive a sanitized process environment.");
        Require(readinessProbe, "startInfo.Environment.Remove(name)", "Provider readiness should remove secret-like environment variables before process launch.");

        var executor = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Execution", "PowerShellRunbookExecutor.cs"));
        Require(executor, "SanitizeInheritedSecretEnvironment(startInfo)", "Every runbook step should sanitize inherited host secrets.");
        Require(executor, "foreach (var item in options.EnvironmentVariables)", "Explicit per-runbook secrets should be added only after inherited secrets are removed.");
        Require(executor, "currentStepIsCleanup || HasRemainingCleanupSteps", "Cancellation at the first cleanup step should still execute that cleanup step.");
        Require(executor, "CreateCancellationBeforeCleanupStepResult", "Cleanup-boundary cancellation should not consume the cleanup step result slot.");
        Require(executor, "RunbookProgressFacts.IsCanceledStepResult(stepResult)", "Canceled child steps should produce the canceled aggregate state.");
        Require(executor, "cleanupMode ? CancellationToken.None : cancellationToken", "Cleanup should continue with a non-cancelable token after mutation.");
        Require(executor, "AcquireLiveExecutionLease(runbook)", "Every provider should acquire the shared live lease before executing source steps.");
        Require(executor, "FileShare.None", "The live lease should provide cross-process exclusion.");
        Require(executor, "StepId = \"live-execution-lease\"", "Lease contention should produce an explicit provider-neutral preflight failure.");
        Require(executor, "using var ownedLiveExecutionLease", "The live lease should remain held through provider cleanup and aggregate completion.");
        Require(executor, "persisted runbook predates the live execution lease contract", "Legacy runbooks should fail closed instead of using a different fallback lease.");

        var executionModels = Read(context, Path.Combine("src", "KSword.Sandbox.Abstractions", "ExecutionModels.cs"));
        Require(executionModels, "public bool WasCanceled", "Execution results should expose one provider-neutral cancellation fact.");

        var progressFacts = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Execution", "RunbookProgressFacts.cs"));
        Require(progressFacts, "\"open-vm-desktop\" => \"virtualization-console\"", "All providers should expose the same console progress category.");
        Require(progressFacts, "\"stop-golden\" or \"stop-vm-before-restore\" or \"restore-golden\" or \"restore-vm-snapshot\"", "Hyper-V, VMware, and QEMU baseline lifecycle failures should share one remediation path.");
        Require(progressFacts, "手动关闭 VM 并恢复干净基线", "Cleanup remediation should use provider-neutral clean-baseline wording.");
        Require(progressFacts, "result.StepResults.FirstOrDefault(IsCanceledStepResult)", "Recovered progress should retain cancellation even when cleanup later succeeds.");
        Require(progressFacts, "IsPreflightFailureResult", "Durable progress should recognize synthetic lease and elevation failures without assigning them a source index.");
        Require(progressFacts, "has no execution lease path", "Preflight sanitization should preserve legacy-runbook remediation after repeated recovery.");

        var jobPersistence = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Jobs", "SandboxJobService.Persistence.cs"));
        Require(jobPersistence, "result.WasCanceled", "Durable progress should preserve the canceled terminal state.");
        Require(jobPersistence, "CurrentStepId = preflightFailure?.StepId", "Recovered progress should expose a synthetic preflight identity while source steps remain pending.");
        Require(jobPersistence, "TargetVmName = FirstPersistedIdentity(", "Metadata fallback should preserve the executed provider target instead of deriving a new VM identity from current config.");

        var backgroundStore = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Infrastructure", "RunbookBackgroundExecutionStore.cs"));
        Require(backgroundStore, "public const string Canceled = \"canceled\"", "Web background state should distinguish cancellation from failure.");
        Require(backgroundStore, "outcome.Execution.WasCanceled", "Web background state should consume the shared execution cancellation fact.");
        Require(backgroundStore, "Func<CancellationToken, Task<RunbookExecutionOutcome>>", "Web background execution should pass a provider-neutral cancellation token into the shared executor.");
        Require(backgroundStore, "public bool TryCancel", "Web background execution should expose one cancellation path for all providers.");
        Require(backgroundStore, "CancelRequested = true", "Web cancellation should distinguish a request from the terminal canceled state.");
        Require(backgroundStore, "cancellationSource.Cancel()", "Web cancellation should signal the active shared executor.");
        Require(backgroundStore, "if (!IsActive(current.State))", "A late cancel request should not overwrite an already-published terminal snapshot.");
        Require(backgroundStore, "executor returns after its mandatory VM", "Web cancellation should remain active until mandatory VM cleanup returns.");
        Require(backgroundStore, "BuildLatestStepRemediationHintZh", "Background execution summaries should provide preflight-specific remediation.");

        var cancellationWebProgram = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Program.cs"));
        Require(cancellationWebProgram, "\"/api/jobs/{jobId:guid}/runbook/cancel\"", "WebUI should expose the same cancel endpoint for Hyper-V, VMware, and QEMU jobs.");
        Require(cancellationWebProgram, "executor.ExecuteAsync(job.Runbook, options, cancellationToken)", "WebUI should forward cancellation to the shared provider-neutral executor.");
        Require(cancellationWebProgram, "job.Runbook.TargetVmName", "Safe background job snapshots should retain the effective VM target without exposing runbook commands.");
        Require(cancellationWebProgram, "job.Runbook.MachineDefinitionPath", "Safe background job snapshots should retain the effective VMware VMX or QEMU base disk.");

        var dashboard = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Dashboard", "DashboardExperiencePage.cs"));
        Require(dashboard, "取消分析并清理虚拟机", "The dashboard should expose a provider-neutral cancel-and-clean-up action.");
        Require(dashboard, "/runbook/cancel", "The dashboard cancel action should call the shared Web endpoint.");

        var cancellationLiveEventsPage = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Dashboard", "LiveEventsPage.cs"));
        Require(cancellationLiveEventsPage, "取消分析并清理虚拟机", "The standalone live monitor should expose the same cancel-and-clean-up action.");
        Require(cancellationLiveEventsPage, "['completed', 'failed', 'canceled']", "The standalone monitor should stop polling on all terminal states, including cancellation.");

        var executionContract = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Contracts", "RunbookExecutionContract.cs"));
        Require(executionContract, "public bool WasCanceled", "Web execution contracts should expose cancellation without changing the legacy success flag.");
        Require(executionContract, "State = result.Success ? \"completed\" : result.WasCanceled ? \"canceled\" : \"failed\"", "Web execution contracts should expose an explicit terminal state.");
        Require(executionContract, "State = \"skipped\"", "Skipped Web execution contracts should not be mislabeled as failed.");
        Require(executionContract, "live execution lease 获取失败", "Web execution contracts should explain lease contention without pointing to nonexistent process output.");

        var progressContract = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Contracts", "RunbookProgressContract.cs"));
        Require(progressContract, "if (preflightFailure && failedStepCount == 0)", "Web progress should count a synthetic preflight as one failure.");
        Require(progressContract, "IsLegacyLeaseRunbookFailure", "Web progress should distinguish a legacy runbook from active lease contention.");

        var executionFlow = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Dashboard", "RunbookExecutionFlowPage.cs"));
        Require(executionFlow, "execution.WasCanceled", "The execution-flow page should distinguish canceled runs from failures.");

        var jobToolCommands = Read(context, Path.Combine("tools", "KSword.Sandbox.JobTool", "JobToolCommands.cs"));
        Require(jobToolCommands, "ValidateProviderResourceOverrides(options, context.Config, provider)", "Direct JobTool plan/execute should validate provider-specific resource overrides.");
        Require(jobToolCommands, "QEMU overlay mode does not accept an internal snapshot baseline override", "Direct JobTool calls should not silently ignore a QEMU overlay baseline name.");
        Require(jobToolCommands, "Generic and provider-specific machine paths cannot disagree", "Direct JobTool calls should reject conflicting resource path aliases.");
        Require(jobToolCommands, "EnvironmentVariables = runbookEnvironment", "CLI live execution should pass only its explicit guest secret to runbook steps.");
        Require(jobToolCommands, "var effectiveVmName = job.Runbook?.TargetVmName", "CLI plans should display the effective runbook VM rather than only the submitted logical name.");
        Require(jobToolCommands, "var effectiveVmName = execution.TargetVmName", "CLI execution JSON and text should display the VM that actually ran.");
        Require(jobToolCommands, "execution.StepResults.LastOrDefault(step => !step.Success)", "CLI should summarize synthetic preflight failures that do not have a source step index.");
        Require(jobToolCommands, "Message : {Safe(execution.Message)}", "CLI human output should explain a safe aggregate preflight failure.");
        Require(jobToolCommands, "GetProviderMachineDefinitionPath", "CLI planning should map VMware VMX and QEMU disk overrides to the actual provider resource.");
        Require(jobToolCommands, "qemu-disk-format", "CLI planning should carry the format paired with a QEMU disk override.");
        Require(jobToolCommands, "config.Qemu.UseOverlayDisk ? string.Empty", "CLI planning should not submit an unused QEMU internal snapshot in overlay mode.");
        Require(jobToolCommands, "executionState = execution.Success ? \"Completed\" : execution.WasCanceled ? \"Canceled\" : \"Failed\"", "CLI output should distinguish cancellation from failure.");
        Require(jobToolCommands, "GetOption(options, \"baseline\"", "Direct JobTool calls should accept provider-neutral --baseline overrides.");
        Require(jobToolCommands, "baselineName = effectiveBaselineName", "Plan and execution JSON should expose provider-neutral baselineName.");
        Require(jobToolCommands, "var planPath = ResolvePlanOutputPath(options, context.RepositoryRoot)", "Direct JobTool plans should resolve an optional provider-neutral plan output path.");
        Require(jobToolCommands, "WriteJsonFile(planPath, result)", "Direct JobTool plans should persist the same redacted result contract when --plan-path is requested.");

        var operatorCli = Read(context, Path.Combine("scripts", "Invoke-OperatorCli.ps1"));
        Require(operatorCli, "'execute'", "Operator CLI should expose execute.");
        Require(operatorCli, "[switch]$Live", "Operator CLI live mode must be explicit.");
        Require(operatorCli, "@('--vm', $VmName)", "Operator CLI should forward the selected provider VM name.");
        Require(operatorCli, "@('--checkpoint', $SnapshotName)", "Operator CLI should forward the selected provider baseline name.");
        Require(operatorCli, "[Alias('BaselineName')]", "Operator CLI should accept -BaselineName while retaining -SnapshotName compatibility.");
        Require(operatorCli, "@('--machine-definition-path', $MachineDefinitionPath)", "Operator CLI should forward the actual VMware VMX or QEMU disk path.");
        Require(operatorCli, "@('--qemu-disk-format', $QemuDiskFormat)", "Operator CLI should forward QEMU disk format with a disk override.");
        Require(operatorCli, "@('--plan-path', $PlanPath)", "Operator CLI should forward custom plan output paths to the provider-neutral JobTool.");
        SmokeAssert.True(!operatorCli.Contains("function Invoke-OperatorPlan", StringComparison.Ordinal), "Operator CLI plan must not retain a dead Hyper-V-only implementation beside the provider-neutral JobTool path.");
        Require(operatorCli, "--no-open-vm-console", "Operator CLI should expose headless execution.");
        Require(operatorCli, "--guest-ready-timeout-seconds", "Operator CLI should expose the shared guest readiness timeout.");
        Require(operatorCli, "--machine-definition-path", "Operator CLI should forward the actual VMware VMX or QEMU disk path.");
        Require(operatorCli, "--qemu-disk-format", "Operator CLI should forward QEMU disk format overrides.");
        Require(
            operatorCli.Split("@('--machine-definition-path', $MachineDefinitionPath)", StringSplitOptions.None).Length - 1 >= 4,
            "Operator CLI should forward provider resource overrides for plan/execute, report, import, and recover.");
        Require(
            operatorCli.Split("@('--qemu-disk-format', $QemuDiskFormat)", StringSplitOptions.None).Length - 1 >= 4,
            "Operator CLI should forward QEMU format overrides for plan/execute, report, import, and recover.");
        Require(operatorCli, "[switch]$ProviderReadiness", "Operator CLI should expose provider-neutral host readiness.");
        Require(operatorCli, "'-Mode', 'CheckEnvironment'", "Provider CLI readiness should reuse run.ps1 host diagnostics.");
        Require(operatorCli, "mode = 'provider-host'", "Provider CLI readiness JSON should distinguish host readiness from artifact readiness.");
        Require(
            operatorCli.Split("@('--provider', $Provider)", StringSplitOptions.None).Length - 1 >= 5,
            "Operator CLI should forward an explicit provider for plan, execute, report, import, and recover.");

        var rebuildWrapper = Read(context, Path.Combine("scripts", "Rebuild-JobReport.ps1"));
        Require(rebuildWrapper, "[ValidateSet('', 'HyperV', 'VMware', 'Qemu')]", "The specialist report wrapper should accept all supported providers.");
        Require(rebuildWrapper, "[Alias('SnapshotName', 'CheckpointName')]", "The specialist report wrapper should expose provider-neutral baseline naming with legacy aliases.");
        Require(rebuildWrapper, "@('--machine-definition-path', $MachineDefinitionPath)", "The specialist report wrapper should forward VMware VMX and QEMU disk paths.");
        Require(rebuildWrapper, "@('--qemu-disk-format', $QemuDiskFormat.ToLowerInvariant())", "The specialist report wrapper should forward the QEMU disk format.");

        Require(jobToolCommands, "guestReadyTimeoutSeconds", "JobTool results should echo the effective guest readiness timeout.");
        Require(jobToolCommands, "provider = job.Runbook.Provider.ToString()", "JobTool execution results should expose the provider.");
        Require(jobToolCommands, "stepTimeoutSeconds < guestReadyTimeoutSeconds", "JobTool should reject a live timeout that truncates guest readiness.");
        Require(
            jobToolCommands.Split("ValidateProviderResourceOverrides(options", StringSplitOptions.None).Length - 1 >= 4,
            "Plan, execute, report, and recover-report paths should share provider resource conflict validation.");

        var jobToolHelpers = Read(context, Path.Combine("tools", "KSword.Sandbox.JobTool", "JobToolHelpers.cs"));
        Require(jobToolHelpers, "TryReadJobProvider", "JobTool list/status should recover the provider from persisted job artifacts.");
        Require(jobToolHelpers, "ResolvePersistedOrConfiguredProvider", "Offline report rebuilds should preserve the persisted provider.");
        Require(jobToolHelpers, "cannot rewrite its VM/baseline identity", "Offline report rebuilds should reject attempts to relabel an existing job as another provider.");
        Require(jobToolHelpers, "TryReadJobSamplePath", "Offline report rebuilds should recover provider-neutral sample paths from job metadata.");
        Require(jobToolHelpers, "ResolvePersistedOrConfiguredVmName", "Offline report rebuilds should preserve the provider VM override.");
        Require(jobToolHelpers, "ResolvePersistedOrConfiguredSnapshotName", "Offline report rebuilds should preserve the provider baseline override.");
        Require(jobToolHelpers, "[--baseline <name>|--checkpoint <name>]", "JobTool help should present provider-neutral baseline naming with its legacy alias.");
        Require(jobToolHelpers, "[--plan-path <json>]", "JobTool help should advertise provider-neutral plan result persistence.");
        Require(jobToolHelpers, "File.Move(temporaryPath, path, overwrite: true)", "Explicit plan result files should be atomically replaced rather than exposed as partial JSON.");
        Require(jobToolHelpers, "ResolvePersistedOrConfiguredMachineDefinitionPath", "Offline report rebuilds should preserve the provider VMX or base-disk override.");
        Require(jobToolHelpers, "ResolvePersistedOrConfiguredQemuDiskFormat", "Offline report rebuilds should preserve the QEMU base-disk format.");
        Require(jobToolHelpers, "ReadPersistedProviderResourceIdentity", "CLI list/status and rebuilds should share one persisted provider resource identity resolver.");
        Require(jobToolHelpers, "EnsurePersistedResourceIdentityMatches", "Offline report rebuilds should fill missing provider resources without rewriting an existing job identity.");
        Require(jobToolHelpers, "compareAsPath: true", "VMware VMX and QEMU disk conflicts should compare normalized Windows paths rather than raw spelling.");
        Require(jobToolHelpers, "offline report rebuild cannot rewrite that resource identity", "Provider VM, baseline, VMX/disk, and QEMU format conflicts should fail before report regeneration.");
        Require(jobToolHelpers, "targetVmName = rebuiltJob?.Runbook?.TargetVmName ?? vmName", "Report rebuild diagnostics should retain provider resource identity even when rebuilding fails.");
        Require(jobToolHelpers, "HasProviderlessLegacyJobArtifacts(jobRoot)", "CLI report recovery should not relabel provider-less historical jobs from the current profile.");

        var jobToolModels = Read(context, Path.Combine("tools", "KSword.Sandbox.JobTool", "JobToolModels.cs"));
        Require(jobToolModels, "internal sealed record ProviderResourceIdentity", "CLI operator surfaces should use one typed provider resource identity.");
        Require(jobToolModels, "public string? MachineDefinitionPath", "CLI job summaries should expose the effective VMware VMX or QEMU base disk.");

        var postProcess = Read(context, Path.Combine("tools", "KSword.Sandbox.PostProcess", "Program.cs"));
        Require(postProcess, "ResolveProvider(options.Provider, jobRoot", "Standalone post-processing should prefer the job provider over current config.");
        Require(postProcess, "cannot rewrite its persisted VM/baseline identity", "Standalone post-processing should reject provider relabeling that would mismatch persisted VMX/disk identity.");
        Require(postProcess, "HasProviderlessLegacyJobArtifacts(jobRoot)", "Standalone post-processing should not relabel provider-less historical reports from the current profile.");
        Require(postProcess, "ResolveProviderResourceIdentity(jobRoot)", "Standalone post-processing should recover the effective provider VM and baseline identity.");
        Require(postProcess, "MachineDefinitionPath = providerIdentity.MachineDefinitionPath", "Standalone reports should preserve the effective VMware VMX or QEMU base disk.");
        Require(postProcess, "provider = provider.ToString()", "Standalone post-processing results should expose the recovered provider.");

        Require(executionModels, "VirtualizationProvider Provider", "Execution and progress models should persist provider identity.");
        Require(executionModels, "MachineDefinitionPath", "Execution and progress models should persist the effective VMware VMX or QEMU base disk.");
        Require(executionModels, "BaselineName", "Execution and progress models should persist the effective provider baseline.");

        Require(executor, "HasRemainingCleanupSteps", "Provider execution failures should retain tail cleanup steps.");
        Require(executor, "cleanupMode ? CancellationToken.None : cancellationToken", "Cancellation should not cancel required VM cleanup after mutation.");
        Require(executor, "Cleanup also reported", "Cleanup failures should be reported without replacing the primary failure.");

        var analysisModels = Read(context, Path.Combine("src", "KSword.Sandbox.Abstractions", "AnalysisModels.cs"));
        Require(analysisModels, "VirtualizationProvider? Provider", "Reports should expose provider identity without mislabeling old reports.");
        Require(analysisModels, "public string? TargetVmName", "Reports should preserve the effective provider VM target.");
        Require(analysisModels, "public string? BaselineName", "Reports should preserve the effective clean provider baseline.");
        Require(analysisModels, "public string? MachineDefinitionPath", "Reports should preserve the effective VMware VMX or QEMU base disk.");
        Require(analysisModels, "public string? QemuDiskFormat", "Reports should preserve the QEMU disk format paired with the base disk.");

        var runbookModels = Read(context, Path.Combine("src", "KSword.Sandbox.Abstractions", "RunbookModels.cs"));
        Require(runbookModels, "BaselineName", "Persisted runbooks should identify the provider's effective clean baseline.");
        Require(runbookModels, "MachineDefinitionPath", "Persisted runbooks should identify the effective VMware VMX or QEMU base disk.");
        Require(runbookModels, "QemuDiskFormat", "Persisted QEMU runbooks should identify the effective disk format.");
        Require(runbookModels, "LiveExecutionLeasePath", "Persisted runbooks should carry the provider-neutral live execution lease path.");

        var jobService = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Jobs", "SandboxJobService.cs"));
        var runbookPlanningStage = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Pipeline", "Stages", "RunbookPlanningStage.cs"));
        var providerResourceValidator = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Orchestration", "VirtualizationProviderResourceValidator.cs"));
        Require(jobService, "VirtualizationProviderResourceValidator.Validate", "Web/API job planning should reject cross-provider resource fields before creating a job directory.");
        Require(
            jobService.Split("VirtualizationProviderResourceValidator.Validate", StringSplitOptions.None).Length - 1 >= 2,
            "First-time offline imports should apply the same provider resource validation as normal planning while persisted runbooks retain their historical identity.");
        Require(jobService, "if (existingJob?.Runbook is null)", "Offline imports should validate only when they are not reusing a persisted provider runbook.");
        Require(runbookPlanningStage, "VirtualizationProviderResourceValidator.Validate", "Pipeline planning should apply the same provider resource validation as the job service.");
        Require(providerResourceValidator, "QEMU overlay mode does not accept an internal snapshot baseline override", "Core provider resource validation should reject silently ignored QEMU overlay baselines.");
        Require(providerResourceValidator, "QEMU disk format overrides apply only to Qemu", "Core provider resource validation should reject QEMU-only fields on Hyper-V and VMware.");
        Require(jobService, "Provider = expectedProvider", "Persisted execution results should use the job runbook provider.");
        Require(jobService, "EnsureRunbookExecutionIdentityMatches(job.Runbook, result)", "Persisted execution results should reject cross-provider or cross-resource identity conflicts before backfilling missing fields.");
        Require(jobService, "NormalizeExternalRunbookExecutionPath(jobRoot, runbookExecutionResultPath, runbook)", "Offline report imports should validate execution artifacts against the persisted provider runbook.");
        Require(jobService, "TargetVmName = runbook.TargetVmName", "Planned and regenerated reports should use the effective runbook VM target.");
        Require(jobService, "MachineDefinitionPath = runbook.MachineDefinitionPath", "Planned and regenerated reports should use the effective provider resource path.");
        Require(jobService, "$\"{providerPrefix}.runbook.executed\"", "Execution events should use the active provider prefix.");
        Require(jobService, "$\"{providerPrefix}.runbook.execution_result_error\"", "Execution import failures should use the active provider prefix.");
        Require(jobService, "EnsureExternalImportPreservesPersistedIdentity(existingJob, normalizedSubmission)", "Offline report imports should reject attempts to rewrite an existing provider runbook identity.");
        Require(jobService, "var runbook = existingJob?.Runbook ??", "Offline report imports should always reuse an existing persisted runbook.");
        Require(jobService, "CreatedAt = existingJob?.CreatedAt", "Offline report imports should not reset the historical job creation time.");
        Require(jobService, "Submission = persistedSubmission", "Offline report imports should not replace the logical submission with an effective provider target.");

        var reportRenderer = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Reporting", "HtmlReportRenderer.cs"));
        Require(reportRenderer, "Row(html, \"Target VM\", report.TargetVmName)", "HTML reports should identify the effective provider VM target.");
        Require(reportRenderer, "VirtualizationProvider.VMware => \"VMX path\"", "VMware reports should label their effective VMX resource.");
        Require(reportRenderer, "VirtualizationProvider.Qemu => \"QEMU base disk\"", "QEMU reports should label their effective base disk.");
        Require(reportRenderer, "Row(html, \"QEMU disk format\", report.QemuDiskFormat)", "QEMU reports should show the format paired with the base disk.");

        Require(jobPersistence, "metadataJob?.Runbook?.Provider ??", "Metadata recovery should prefer persisted runbook provider identity.");
        Require(jobPersistence, "VirtualizationProvider.HyperV;", "Provider-less legacy jobs should recover as the historical Hyper-V format instead of following the current profile.");
        Require(jobPersistence, "metadataJob?.Runbook?.MachineDefinitionPath", "Metadata recovery should retain provider resource identity when compact job metadata is incomplete.");

        var eventClassifier = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Classification", "EventCategoryClassifier.cs"));
        Require(eventClassifier, "vmware.runbook.", "Event categories should recognize VMware orchestration events.");
        Require(eventClassifier, "qemu.runbook.", "Event categories should recognize QEMU orchestration events.");

        var readiness = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Infrastructure", "LocalHostReadinessProbe.cs"));
        Require(readiness, "ProbeVMwareAsync", "Web readiness should probe VMware.");
        Require(readiness, "ProbeQemuAsync", "Web readiness should probe QEMU.");
        Require(readiness, "ProbeHostVirtualizationAsync", "Web readiness should inspect the same Windows host acceleration facts for every provider.");
        Require(readiness, "HOST_VIRTUALIZATION_QUERY_OK", "Web readiness should expose a machine-readable host capability diagnostic.");
        Require(readiness, "HOST_REQUIRED_WINDOWS_FEATURE_DISABLED", "Web readiness should distinguish a disabled provider feature from BIOS capability failures.");
        Require(readiness, "Win32_OptionalFeature", "Web readiness should fall back to read-only CIM feature discovery.");
        Require(readiness, "VMWARE_SNAPSHOT_NOT_FOUND", "VMware readiness should validate snapshots.");
        Require(readiness, "VMWARE_ACCESS_DENIED", "VMware readiness should distinguish management permission failures.");
        Require(readiness, "QEMU_ACCESS_DENIED", "QEMU readiness should distinguish management permission failures.");
        Require(readiness, "ProviderAccessDeniedCode", "Provider readiness should emit the same machine-readable permission code for every query stage.");
        Require(readiness, "IsProviderAccessDenied", "Provider readiness should classify permission failures without matching unrelated access text.");
        Require(readiness, "access is denied", "Provider readiness should recognize the standard Windows access-denied wording.");
        Require(readiness, "QEMU_OVERLAY_READY", "QEMU readiness should understand overlay mode.");
        Require(readiness, "QEMU_DISK_FORMAT_MISMATCH", "QEMU readiness should validate the configured image format.");
        Require(readiness, "QEMU_INTERNAL_SNAPSHOT_FORMAT_UNSUPPORTED", "QEMU readiness should reject unsupported internal snapshot formats.");
        Require(readiness, "QEMU_CONFIGURATION_INVALID", "QEMU Web readiness should reject configuration that runbook planning would reject.");
        Require(readiness, "ValidateQemuProviderArguments", "QEMU Web readiness should reuse the Core argument contract.");
        Require(readiness, "FindActiveQemuProcesses", "QEMU readiness should enumerate controlled running state from native PID marker identities.");
        Require(readiness, "markerWrittenUtc.AddSeconds(-5)", "QEMU readiness should reject PID reuse when the process predates its ownership marker.");
        Require(readiness, "CanBindLoopbackPort", "Web readiness should probe the provider-owned QEMU WinRM forwarding port before launch.");
        Require(readiness, "QEMU_USER_NAT_PORT_UNAVAILABLE", "Web readiness should distinguish a QEMU user-NAT port conflict from an invalid guest address.");
        Require(readiness, "QemuProcessOwnsConfiguredUserNatEndpointAsync", "Web readiness should verify that an active QEMU process owns the configured host-forward endpoint before exempting it from the bind probe.");
        Require(readiness, "QemuProcessMatchesProviderIdentityAsync", "Web readiness should verify executable, pidfile, runtime, and VM identity for every QEMU guest endpoint mode.");
        Require(readiness, "foreach (var runningProcessCandidate in FindActiveQemuProcesses())", "Web readiness should inspect every live native QEMU pidfile instead of stopping at an unrelated managed process.");
        Require(readiness, "QEMU_PROCESS_IDENTITY_AMBIGUOUS", "Web readiness should fail closed when multiple active QEMU processes match the selected provider identity.");
        Require(readiness, "ResolveExpectedQemuProcessVmName", "Web readiness should reconstruct the same bounded QEMU per-job VM name used by Core planning.");
        Require(readiness, "var maximumPrefixLength = maximumLength - suffix.Length", "Web readiness should retain the complete QEMU job suffix when the configured VM prefix is long.");
        Require(readiness, "$vmNamePattern = '(?i)(?:^|\\s)-name", "Web readiness should match the exact QEMU -name argument instead of accepting a maintenance-process name prefix.");
        Require(readiness, "executableMatches -and $pidMarkerMatches -and $runtimeMatches -and $vmMatches -and $forwardMatches", "Web readiness should bind QEMU endpoint ownership to executable, pidfile, runtime, VM, and port identity.");
        Require(readiness, "ResolveGuestRemoting", "Web readiness should select each provider's WinRM profile.");
        Require(readiness, "GUEST_REMOTING_INSECURE", "Web readiness should reject insecure Basic HTTP or meaningless certificate-skip settings.");
        Require(readiness, "automatic endpoint mode requires WinRM HTTPS", "Web readiness should reject automatic endpoint modes without HTTPS.");
        Require(readiness, "GuestEndpointReady", "Web readiness should expose endpoint readiness independently of a literal address.");
        Require(readiness, "VMwareTools", "Web readiness should understand VMware Tools endpoint discovery.");
        Require(readiness, "QemuUserNat", "Web readiness should understand provider-managed QEMU user-NAT.");

        var settingsPage = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Dashboard", "SettingsPage.cs"));
        Require(settingsPage, "VMware Workstation Pro</option>", "Web settings should identify the supported VMware product precisely.");
        Require(settingsPage, "settingsVirtualizationProvider", "Web settings presets should include the virtualization provider.");
        Require(settingsPage, "selectedProviderDefaults", "Web settings should resolve VM defaults from the selected provider profile.");
        Require(settingsPage, "provider: selectedVirtualizationProvider()", "Saved Web presets should retain the selected provider.");
        Require(settingsPage, "settingsMachineDefinitionPath", "Saved Web presets should retain the actual VMware VMX or QEMU disk path.");
        Require(settingsPage, "settingsQemuDiskFormat", "Saved Web presets should retain QEMU disk format.");
        Require(settingsPage, "useOverlayDisk ? 'per-job-overlay'", "Web presets should identify QEMU overlay baseline semantics.");
        Require(settingsPage, "snapshotInput.disabled = qemuUsesOverlay", "Web presets should disable the unused QEMU internal snapshot field in overlay mode.");
        Require(settingsPage, "Clean baseline", "Web settings should use one provider-neutral baseline label.");
        Require(settingsPage, "QEMU per-job overlay or internal snapshot", "Web settings should explain how the shared baseline field maps to QEMU.");

        var dashboardPage = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Dashboard", "DashboardExperiencePage.cs"));
        Require(dashboardPage, "VMware Workstation Pro</option>", "The main provider selector should not advertise a generic or Player VMware profile.");
        Require(dashboardPage, "setValue('virtualizationProvider', preset.provider)", "Loading a Web preset should restore its provider.");
        Require(dashboardPage, "await refreshLocalHostReadiness(true, false)", "Loading a Web preset should refresh readiness for its provider.");
        Require(dashboardPage, "localHostReadinessRequestId", "Web readiness should ignore stale responses after provider switches.");
        Require(dashboardPage, "selectedProvider() !== previousProvider", "Loading a cross-provider Web preset should clear stale readiness before probing the new provider.");
        Require(dashboardPage, "readinessMatchesProvider", "Web field sources should not attribute another provider's readiness to the selected provider.");
        Require(dashboardPage, "宿主加速", "Web readiness should show host acceleration next to VM and guest transport readiness.");
        Require(dashboardPage, "requiredWindowsFeatureState", "Web readiness should show the concrete provider feature state when it blocks Live.");
        Require(dashboardPage, "const provider = job.runbook?.provider || submission.provider", "VM run summaries should prefer the persisted effective runbook provider over submission/config defaults.");
        Require(dashboardPage, "job.runbook?.targetVmName || submission.goldenVmName", "VM run summaries should prefer the persisted effective runbook VM target over submission/config defaults.");
        Require(dashboardPage, "submission: snapshot.job.submission || (sameCurrentJob ? currentJobPayload.submission : undefined)", "Terminal background updates should preserve the selected job's effective submission instead of falling back to current config.");
        Require(dashboardPage, "runbook: snapshot.job.runbook || (sameCurrentJob ? currentJobPayload.runbook : undefined)", "Terminal background updates should preserve the selected job's effective provider runbook identity.");

        Require(progressFacts, "TargetVmName = runbook?.TargetVmName ?? snapshot.TargetVmName", "Recovered progress should backfill the effective VM target from the persisted runbook.");
        Require(progressFacts, "BaselineName = runbook?.BaselineName ?? snapshot.BaselineName", "Recovered progress should backfill the effective clean baseline from the persisted runbook.");
        Require(progressFacts, "MachineDefinitionPath = runbook?.MachineDefinitionPath ?? snapshot.MachineDefinitionPath", "Recovered progress should backfill the effective VMware VMX or QEMU base disk from the persisted runbook.");
        Require(progressFacts, "QemuDiskFormat = runbook?.QemuDiskFormat ?? snapshot.QemuDiskFormat", "Recovered progress should backfill the effective QEMU disk format from the persisted runbook.");
        Require(dashboardPage, "document.getElementById('goldenVmName').value = ''", "Switching providers should clear stale VM overrides before readiness returns.");
        Require(dashboardPage, "machineDefinitionPath: selectedProvider() === 'HyperV'", "Web submissions should map VMware/QEMU resource paths into the job contract without changing Hyper-V selection semantics.");
        Require(dashboardPage, "qemuDiskFormat: selectedProvider() === 'Qemu'", "Web submissions should carry QEMU disk format with a per-job disk path.");
        Require(dashboardPage, "machineDefinitionOverride && configuredMachineMissing", "Web readiness should distinguish a per-job VMX/disk override from a missing default profile path.");
        Require(dashboardPage, "provider preflight will validate", "Web readiness should explain that manual provider paths remain subject to runbook preflight.");
        Require(dashboardPage, "QEMU_USER_NAT_PORT_UNAVAILABLE", "The dashboard should present QEMU host-forward port conflicts before live execution.");
        Require(dashboardPage, "VM and clean baseline", "The main VM configuration should use provider-neutral baseline terminology.");
        Require(dashboardPage, "Hyper-V checkpoint, VMware snapshot, or QEMU overlay/internal snapshot", "The main VM configuration should explain the provider-specific baseline mapping.");

        var executionFlowPage = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Dashboard", "RunbookExecutionFlowPage.cs"));
        Require(executionFlowPage, "job.Submission.MachineDefinitionPath", "Execution flow should identify the actual VMware VMX or QEMU base disk.");
        Require(executionFlowPage, "job.Runbook?.TargetVmName", "Execution flow should identify the concrete runtime VM target.");
        Require(executionFlowPage, "data-en=\"Clean baseline\"", "Execution flow should label the effective baseline without assuming one provider's snapshot mechanism.");

        var liveEventsPage = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Dashboard", "LiveEventsPage.cs"));
        Require(liveEventsPage, "submission.MachineDefinitionPath", "Live monitoring should retain the actual VMware VMX or QEMU base disk.");
        Require(liveEventsPage, "submission.QemuDiskFormat", "Live monitoring should retain QEMU disk format.");
        Require(liveEventsPage, "data-en=\"Clean baseline\"", "Live monitoring should label the effective baseline without assuming one provider's snapshot mechanism.");
        Require(liveEventsPage, "Restore clean baseline and wait for guest readiness", "Live monitoring should describe startup with provider-neutral baseline terminology.");

        var webProgram = Read(context, Path.Combine("src", "KSword.Sandbox.Web", "Program.cs"));
        Require(webProgram, "Provider = job.Runbook.Provider", "Web background start failures should retain the selected provider.");
        Require(webProgram, "snapshot.Provider", "Web progress/background payloads should expose provider identity.");
        Require(webProgram, "request.StepTimeoutSeconds < guestReadyTimeoutSeconds", "Web execution should reject a timeout that truncates guest readiness.");
        Require(webProgram, "MachineDefinitionPath = ReadFormString", "Multipart one-click analysis should preserve provider machine path overrides.");
        Require(webProgram, "QemuDiskFormat = ReadFormString", "Multipart one-click analysis should preserve QEMU disk format overrides.");

        var pipelineStage = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Pipeline", "Stages", "RunbookPlanningStage.cs"));
        Require(pipelineStage, "submission.Provider", "Pipeline planning should honor the selected provider.");
        Require(pipelineStage, "config.VMware with", "Pipeline planning should apply VMware VM overrides.");
        Require(pipelineStage, "config.Qemu with", "Pipeline planning should apply QEMU VM overrides.");
        Require(pipelineStage, "submission.MachineDefinitionPath", "Pipeline planning should apply VMware VMX and QEMU disk path overrides.");
        Require(pipelineStage, "submission.QemuDiskFormat", "Pipeline planning should apply QEMU disk format overrides.");

        var configurationModels = Read(context, Path.Combine("src", "KSword.Sandbox.Abstractions", "ConfigurationModels.cs"));
        Require(configurationModels, "JsonStringEnumConverter<VirtualizationProvider>", "Provider names should use one string enum contract across config, HTTP, SSE, and persisted artifacts.");
        Require(configurationModels, "JsonStringEnumConverter<GuestRemotingAddressMode>", "Guest endpoint modes should use one string enum contract across config and status surfaces.");

        var configLoader = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Configuration", "SandboxConfigLoader.cs"));
        Require(configLoader, "ApplyLegacyGuestRemotingFallback", "Config loading should preserve legacy shared WinRM endpoints when provider profiles are absent.");
        Require(configLoader, "HasGuestRemotingObject", "Config loading should distinguish an explicit provider endpoint profile from a missing legacy profile.");
        Require(configLoader, "ApplyAutomaticGuestRemotingSecurityDefaults", "Config loading should migrate automatic endpoint profiles that predate explicit HTTPS fields.");
        Require(configLoader, "HasGuestRemotingProperty", "Config migration should preserve an explicitly configured automatic HTTP value for readiness rejection.");
        Require(configLoader, "NormalizeGuestRemoting", "Config loading should normalize VMware/QEMU endpoint values once for every operator surface.");
        Require(configLoader, ".Select(argument => (argument ?? string.Empty).Trim())", "QEMU validation and launch should consume the same normalized argument tokens.");

        var exampleConfig = Read(context, Path.Combine("config", "sandbox.example.json"));
        Require(exampleConfig, "\"addressMode\": \"VMwareTools\"", "The example VMware profile should use automatic Tools discovery.");
        Require(exampleConfig, "\"addressMode\": \"QemuUserNat\"", "The example QEMU profile should use provider-managed user-NAT.");
        Require(exampleConfig, "\"useSsl\": true", "Automatic provider examples should use WinRM HTTPS.");
        Require(exampleConfig, "\"skipCertificateChecks\": true", "Automatic provider examples should support self-signed guest certificates by default.");

        var runbookBuilder = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Orchestration", "HyperVRunbookBuilder.cs"));
        Require(runbookBuilder, "VMware parity requires Workstation Pro", "Core planning should reject provider profiles that cannot meet the VMware parity contract.");
        Require(runbookBuilder, "managed disk would not be attached to a boot device", "QEMU planning should reject an unattached if=none boot disk.");
        Require(runbookBuilder, "BuildVMwarePowerStateWaitCommand", "VMware lifecycle steps should wait for stable running/stopped inventory state.");
        Require(runbookBuilder, "BuildQemuManagedDiskArguments", "QEMU lifecycle steps should attach each supported disk interface through a managed topology.");
        Require(runbookBuilder, "\"-pidfile\", pidPath", "QEMU launch should publish the provider-owned PID marker in its native command line.");
        Require(runbookBuilder, "did not publish its native -pidfile marker", "QEMU launch should fail closed when the native pidfile is absent.");
        Require(runbookBuilder, "does not match newly started process", "QEMU launch should bind the native marker to the process returned by Start-Process.");
        SmokeAssert.True(
            !runbookBuilder.Contains("$process.Id | Set-Content -LiteralPath $pidPath", StringComparison.Ordinal),
            "Core QEMU launch must not replace the native pidfile with a host-written marker.");
        Require(runbookBuilder, "virtio-scsi-pci,id=ksword-scsi", "QEMU SCSI profiles should create an explicit managed controller.");
        Require(runbookBuilder, "ValidateQemuWhpxAcceleration", "QEMU live execution should default to and enforce WHPX acceleration.");
        Require(runbookBuilder, "ValidateQemuProviderArguments", "Web and runbook planning should share the QEMU argument contract.");
        Require(runbookBuilder, "ValidateQemuManagedArguments", "QEMU profile-owned lifecycle and console arguments should not be overridable.");
        Require(runbookBuilder, "transport={transportName}; mode={addressMode}; source={addressSource}; endpoint={endpoint}", "Guest readiness failures should identify the selected transport mode, endpoint source, and endpoint without exposing credentials.");
        Require(runbookBuilder, "TCG software emulation is not treated as provider parity", "QEMU should reject software emulation as a parity result.");
        Require(runbookBuilder, "BuildPerJobVmName", "Hyper-V differencing and QEMU overlay targets should preserve a complete per-job identity suffix.");
        Require(runbookBuilder, "markerMatchesProcessInstance", "QEMU baseline restore should bind pid markers to the process instance start time.");
        Require(runbookBuilder, "QEMU cleanup refused reused pid", "QEMU cleanup should preserve the job disk when a pid was reused.");
        Require(runbookBuilder, "qemu.stop-confirmed", "QEMU cleanup should remove its job disk only after the preceding stop step records confirmed process cleanup.");
        Require(runbookBuilder, "process stop was not confirmed", "QEMU cleanup should fail closed when stop ownership or process termination could not be confirmed.");
        Require(runbookBuilder, "executable/pidfile/runtime identity", "QEMU baseline restore should stop only provider-managed processes identified by the configured executable and runtime pidfile.");
        Require(runbookBuilder, "native qemu.pid ownership marker is absent", "QEMU cleanup should never auto-stop a process discovered only by job VM and disk text.");
        Require(runbookBuilder, "ambiguous provider ownership", "QEMU cleanup should fail closed when a disk-matching process lacks native pidfile ownership.");
        Require(runbookBuilder, "found an unowned process", "QEMU baseline restore should refuse to terminate an external QEMU that uses the managed base disk.");
        Require(runbookBuilder, "without a valid native qemu.pid ownership marker", "QEMU baseline restore should never auto-stop a process discovered only by runtime or disk text.");
        Require(runbookBuilder, "QEMU display verification refused reused pid", "QEMU console verification should reject a stale process marker.");
        Require(runbookBuilder, "getGuestIPAddress", "VMware runbooks should discover the restored guest endpoint through VMware Tools.");
        Require(runbookBuilder, "BuildVMwareGuestAddressSelectionCommand", "VMware runbooks should apply one deterministic routable-address selection contract.");
        Require(runbookBuilder, "[Net.Sockets.AddressFamily]::InterNetwork", "VMware Tools discovery should prefer IPv4 while retaining a routable fallback.");
        Require(runbookBuilder, "hostfwd=tcp:127.0.0.1", "QEMU runbooks should create the provider-owned WinRM forwarding rule.");
        Require(runbookBuilder, "$portProbe.ExclusiveAddressUse = $true", "QEMU's final pre-launch port probe should use the same exclusive bind contract as readiness.");
        Require(runbookBuilder, "automatic endpoint mode requires guestRemoting.useSsl=true", "Runbook planning should reject automatic HTTP endpoints.");
        Require(runbookBuilder, "Path.Combine(config.Paths.RuntimeRoot, \"locks\", \"live-execution.lock\")", "Every provider should use one runtime-root live lease.");

        var releaseReadiness = Read(context, Path.Combine("scripts", "Test-ReleaseReadiness.ps1"));
        Require(releaseReadiness, "providerParityLiveClaim", "Release evidence should have a distinct three-provider parity claim contract.");
        Require(releaseReadiness, "requiredProviders = @('HyperV', 'VMware', 'Qemu')", "Provider parity should require independent evidence for all three providers.");
        Require(releaseReadiness, "providerParityLiveEvidenceGenerated = $false", "Non-mutating readiness should never claim that it generated provider live evidence.");
        Require(releaseReadiness, "providerParityLiveEvidence = [ordered]@{", "The release gap audit should expose provider parity as a distinct evidence gate.");
        Require(releaseReadiness, "claimAllowedWithoutAllProviders = $false", "Provider parity should fail closed when any provider evidence is absent.");
        Require(releaseReadiness, "one provider job cannot prove the other two", "Release guidance should reject single-provider evidence as proof of provider parity.");
        Require(releaseReadiness, "'hostAccelerationReady'", "Each provider parity record should retain confirmed host acceleration readiness.");
        Require(releaseReadiness, "'gitCommit'", "Each provider parity record should retain exact source provenance.");
        Require(releaseReadiness, "'gitDirty'", "Each provider parity record should disclose whether its checkout was dirty.");
        Require(releaseReadiness, "'runtimeRoot'", "Each provider parity record should retain the runtime root that owns its evidence.");
        Require(releaseReadiness, "'generatedAtLocal'", "Each provider parity record should retain a local timestamp with UTC offset.");
        Require(releaseReadiness, "crossProviderInvariants", "Release evidence should state invariants that must hold across all three provider records.");
        Require(releaseReadiness, "same full gitCommit across HyperV, VMware, and Qemu", "Provider parity should compare runs from the exact same source commit.");
        Require(releaseReadiness, "gitDirty=false for every provider record", "Provider parity should reject evidence from a dirty checkout.");
        Require(releaseReadiness, "same sampleSha256 and sampleSizeBytes across all providers", "Provider parity should require the same sample bytes for all providers.");
        Require(releaseReadiness, "same requestedDurationSeconds across all providers", "Provider parity should require the same analysis duration for all providers.");
        Require(releaseReadiness, "executionTransport=Background", "Provider parity should require the product's background execution path for every provider.");
        Require(releaseReadiness, "-Live -RequireCleanSource", "Release lab commands should reject dirty or unknown source provenance before provider mutation.");
        Require(releaseReadiness, "'requiredWindowsFeatureReady'", "Each provider parity record should retain the selected provider's required Windows feature state.");
        Require(releaseReadiness, "'providerQuerySucceeded'", "Each provider parity record should retain the selected provider inventory query result.");
        Require(releaseReadiness, "'providerGuestTransportSecure'", "Each provider parity record should retain guest transport security readiness.");
        Require(releaseReadiness, "'providerGuestEndpointReady'", "Each provider parity record should retain guest endpoint readiness.");
        Require(releaseReadiness, "'backgroundState'", "Each provider parity record should retain the background runner terminal state.");
        Require(releaseReadiness, "Invoke-WebUIApiE2E.ps1 -BaseUrl", "Release lab commands should use the evidence helper that records provider readiness and background execution state.");
        Require(releaseReadiness, "providerParityLiveEvidenceValidatorCommand", "Release metadata should provide the aggregate parity validator command.");
        Require(releaseReadiness, "schema=ksword.provider-parity-evidence.v1", "Release evidence should require a versioned aggregate parity result.");
        Require(releaseReadiness, "validated=true", "Release evidence should require a successful aggregate parity result.");
        Require(releaseReadiness, "'runbookExecutionPath'", "Each provider parity record should retain execution evidence.");
        Require(releaseReadiness, "'Reset-RemoteGuestPassword.ps1'", "Release readiness must forbid package/readiness paths from invoking VMware/QEMU guest password mutation.");
        Require(releaseReadiness, "'Inject-OfflineGuestPasswordService.ps1'", "Release readiness must forbid package/readiness paths from injecting offline guest changes.");
        Require(releaseReadiness, "'Invoke-WebUIApiE2E.ps1'", "Release readiness must forbid package/readiness paths from invoking the live parity evidence helper.");
        Require(releaseReadiness, "'Invoke-HyperVE2E.ps1'", "Release readiness must forbid package/readiness paths from invoking the legacy Hyper-V live helper.");
        Require(releaseReadiness, "$literalReferenceCount -gt $allowedDeclarationCount", "Release readiness should detect provider mutation scripts even when a checked script invokes them through a path variable.");
        Require(releaseReadiness, "nonMutatingEquivalentCommand = '.\\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -Json'", "Release metadata should advertise the QEMU overlay clean-baseline result without mutation switches.");
        Require(releaseReadiness, "mutatingProviders = @('HyperV', 'VMware', 'QemuInternalSnapshot')", "Release metadata should keep real provider snapshot restores behind the mutation gate.");
        Require(releaseReadiness, "nonMutatingProfiles = @('QemuOverlay')", "Release metadata should identify only QEMU per-job overlay as the non-mutating restore-equivalent profile.");

        var packagePortable = Read(context, Path.Combine("scripts", "package-portable.ps1"));
        Require(packagePortable, "providerParityLiveEvidenceGuardrail", "Portable package metadata should retain the three-provider parity evidence gate.");
        Require(packagePortable, "provider-parity-live-evidence", "Package component progress should expose the provider parity evidence state.");
        Require(packagePortable, "'gitCommit'", "Portable package evidence should retain exact source provenance.");
        Require(packagePortable, "'gitDirty'", "Portable package evidence should disclose whether its checkout was dirty.");
        Require(packagePortable, "'runtimeRoot'", "Portable package evidence should retain the runtime root that owns its job artifacts.");
        Require(packagePortable, "crossProviderInvariants", "Portable package metadata should retain cross-provider parity invariants.");
        Require(packagePortable, "aggregateValidation", "Portable package metadata should retain the aggregate parity result contract.");
        Require(packagePortable, "Test-ProviderParityEvidence.ps1 -HyperVSummaryPath", "Portable package metadata should provide the aggregate validator command.");
        Require(packagePortable, "'requiredWindowsFeatureReady'", "Portable package evidence should retain the selected provider's required Windows feature state.");
        Require(packagePortable, "'providerQuerySucceeded'", "Portable package evidence should retain the selected provider inventory query result.");
        Require(packagePortable, "'providerGuestEndpointReady'", "Portable package evidence should retain guest endpoint readiness.");
        Require(packagePortable, "'backgroundState'", "Portable package evidence should retain the background runner terminal state.");
        Require(packagePortable, "nonMutatingEquivalentCommand", "Portable package generation should preserve the QEMU overlay non-mutating command.");
        Require(packagePortable, "mutationCondition must distinguish provider snapshots from QEMU per-job overlay", "Portable package validation should reject ambiguous baseline restore metadata.");
        var runtimeManifest = Read(context, Path.Combine("packaging", "runtime-package.manifest.json"));
        var sourceManifest = Read(context, Path.Combine("packaging", "source-package.manifest.json"));
        Require(runtimeManifest, "providerParityLiveEvidenceGuardrail", "Runtime package handoff should require independent provider parity evidence.");
        Require(runtimeManifest, "scripts/Invoke-WebUIApiE2E.ps1", "Runtime package handoff should include the three-provider parity evidence helper named by its lab commands.");
        Require(runtimeManifest, "scripts/Test-ProviderParityEvidence.ps1", "Runtime package handoff should include the read-only aggregate parity validator.");
        Require(runtimeManifest, "ksword.provider-parity-evidence.v1", "Runtime handoff should require validated aggregate provider parity evidence.");
        Require(sourceManifest, "providerParityLiveEvidenceGuardrail", "Source package handoff should require independent provider parity evidence.");
        Require(sourceManifest, "ksword.provider-parity-evidence.v1", "Source handoff should require validated aggregate provider parity evidence.");
        Require(runtimeManifest, "\"nonMutatingEquivalentCommand\": \".\\\\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -Json\"", "Runtime handoff should expose the direct QEMU overlay baseline result.");
        Require(sourceManifest, "\"nonMutatingEquivalentCommand\": \".\\\\install.ps1 -InstallEntrypoint RestoreCleanCheckpoint -Json\"", "Source handoff should expose the direct QEMU overlay baseline result.");
        Require(runtimeManifest, "\"QemuInternalSnapshot\"", "Runtime handoff should classify QEMU internal snapshots with mutating providers.");
        Require(sourceManifest, "\"QemuOverlay\"", "Source handoff should classify QEMU per-job overlay as non-mutating.");
        Require(runtimeManifest, "\"ProviderSnapshotRestoreRequested\"", "Runtime handoff should retain provider-neutral baseline restore evidence.");
        Require(sourceManifest, "\"BaselineRestoreSatisfiedWithoutMutation\"", "Source handoff should retain QEMU overlay equivalence evidence.");

        var providerDoc = Read(context, Path.Combine("docs", "vmware-qemu.md"));
        Require(providerDoc, "官方迁移说明", "Provider documentation should direct legacy Player users to the Workstation Pro migration path.");
        Require(providerDoc, "Windows parity acceptance matrix", "Provider documentation should retain the Windows parity matrix.");
        Require(providerDoc, "secretValuePrinted=false", "Parity acceptance should retain the no-secret-output contract.");
        Require(providerDoc, "TrustedHosts", "Provider documentation should explain why automatic endpoint modes require HTTPS.");
        Require(providerDoc, "scsi-hd,drive=ksword-disk,bus=ksword-scsi.0", "Provider documentation should describe the managed QEMU SCSI attachment.");
        Require(providerDoc, "169.254.*", "Provider documentation should describe VMware Tools address filtering.");
        Require(providerDoc, "最终 `report.json` 和中英文 HTML 报告封面", "Provider documentation should require final reports to retain effective resource identity.");
        Require(providerDoc, "重启恢复后保持 Canceled", "Provider documentation should retain canceled-state persistence in the parity matrix.");
        Require(providerDoc, "live-execution.lock", "Provider parity acceptance should cover cross-job live exclusion.");
        Require(providerDoc, "Test-ProviderParityEvidence.ps1", "Provider documentation should close three live runs with the aggregate parity validator.");
        Require(providerDoc, "schema=ksword.provider-parity-evidence.v1", "Provider documentation should require the versioned aggregate parity schema.");
        Require(providerDoc, "`validated=true`", "Provider documentation should require successful aggregate parity validation.");

        var operatorDoc = Read(context, Path.Combine("docs", "operator-cli.md"));
        Require(operatorDoc, "这些字段来自任务产物，不随当前本机 profile 切换", "CLI documentation should preserve historical provider resource identity in list/status.");
        Require(operatorDoc, "--machine-definition-path", "CLI report/recovery documentation should expose provider resource overrides.");
        Require(operatorDoc, "invalid cross-provider fields cannot be", "CLI documentation should state that Core rejects invalid provider resource fields outside JobTool.");
        Require(operatorDoc, "同一 runtime root 只允许一个 live job", "CLI safety documentation should explain the cross-process live lease.");
        Require(operatorDoc, "旧 runbook 必须重新 `plan` 才能 live", "CLI documentation should explain the fail-closed legacy runbook contract.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Run, install, CLI, Web readiness, and Windows acceptance surfaces cover all three providers."
        });
    }

    private static string Read(SmokeTestContext context, string relativePath) =>
        File.ReadAllText(Path.Combine(context.RepositoryRoot, relativePath));

    private static void Require(string text, string expected, string message) =>
        SmokeAssert.True(text.Contains(expected, StringComparison.Ordinal), message);
}
