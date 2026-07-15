using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the root runtime entry point contract without starting WebUI or
/// Hyper-V. Inputs are repository text files; processing checks that run.ps1 is
/// the post-install single-launch entry point; the scenario returns pass/fail
/// metadata.
/// </summary>
internal sealed class RunScriptContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "runtime.entrypoint.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var runScriptPath = Path.Combine(context.RepositoryRoot, "run.ps1");
        var runWrapperPath = Path.Combine(context.RepositoryRoot, "scripts", "run.ps1");
        var runDocPath = Path.Combine(context.RepositoryRoot, "docs", "run.md");
        var readmePath = Path.Combine(context.RepositoryRoot, "README.md");

        SmokeAssert.True(File.Exists(runScriptPath), "run.ps1 is missing from the repository root.");
        SmokeAssert.True(File.Exists(runWrapperPath), "scripts/run.ps1 is missing.");
        SmokeAssert.True(File.Exists(runDocPath), "docs/run.md is missing.");
        SmokeAssert.True(File.Exists(readmePath), "README.md is missing.");

        var runScript = File.ReadAllText(runScriptPath);
        var runWrapper = File.ReadAllText(runWrapperPath);
        var runDoc = File.ReadAllText(runDocPath);
        var readme = File.ReadAllText(readmePath);

        RequireContains(runScript, "ValidateSet(", "run.ps1 should expose a ValidateSet for supported modes.");
        foreach (var mode in new[] { "'WebUI'", "'StartWebUI'", "'Analyze'", "'Plan'", "'Status'", "'CheckEnvironment'" })
        {
            RequireContains(runScript, mode, $"run.ps1 should expose mode {mode}.");
        }
        RequireContains(runScript, "CmdletBinding(SupportsShouldProcess = $true", "run.ps1 should support -WhatIf/-Confirm for startup/delegation paths.");
        RequireContains(runScript, "install-state.json", "run.ps1 should load install.ps1 state.");
        RequireContains(runScript, "Sandbox__ConfigPath", "run.ps1 should set the Web/API config path.");
        RequireContains(runScript, "ASPNETCORE_URLS", "run.ps1 should control the WebUI listen URL without launchSettings.");
        RequireContains(runScript, "http://127.0.0.1:18080", "run.ps1 should default to a localhost port outside common Hyper-V excluded ranges.");
        RequireContains(runScript, "Resolve-WebListenUrl", "run.ps1 should resolve or fall back from blocked localhost ports.");
        RequireContains(runScript, "StrictUrl", "run.ps1 should allow strict URL binding for operators who need it.");
        RequireContains(runScript, "Assert-RunLocalConfigReadyForInteractiveStartup", "run.ps1 should stop ordinary startup when only the repository example config is available.");
        RequireContains(runScript, "本机配置未就绪", "run.ps1 should show a Chinese actionable message for missing local config.");
        RequireContains(runScript, "StartWebUI 模式会自动打开浏览器", "StartWebUI should be the one-click browser-opening WebUI entry point.");
        RequireContains(runScript, "KSWORDBOX_GUEST_PASSWORD", "run.ps1 should default to the guest password secret name.");
        RequireContains(runScript, "KSWORDBOX_VIRUSTOTAL_API_KEY", "run.ps1 should mirror the optional VirusTotal API key into process scope.");
        RequireContains(runScript, "Import-UserOrMachineEnvironmentSecret", "run.ps1 should centralize user/machine secret import.");
        RequireContains(runScript, "Show-RunEnvironmentCheck", "run.ps1 should expose a non-mutating environment check mode.");
        RequireContains(runScript, "SecretValuePrinted = $false", "run.ps1 status should assert secrets are not printed.");
        RequireContains(runScript, "dotnet", "run.ps1 should launch the Web project through dotnet.");
        RequireContains(runScript, "--no-launch-profile", "run.ps1 should avoid launchSettings port surprises.");
        RequireContains(runScript, "Resolve-KSwordPortableTool", "run.ps1 should resolve the provider-neutral JobTool target.");
        RequireContains(runScript, "Invoke-RunJobToolCaptured", "run.ps1 should delegate one-shot analysis to JobTool.");
        RequireContains(runScript, "'--provider', $provider", "run.ps1 should forward the selected provider to JobTool.");
        RequireContains(runScript, "@('--vm', $VmName.Trim())", "run.ps1 should forward a per-job VM override.");
        RequireContains(runScript, "@('--baseline', $BaselineName.Trim())", "run.ps1 should forward the provider-neutral clean baseline override.");
        RequireContains(runScript, "@('--machine-definition-path', $MachineDefinitionPath.Trim())", "run.ps1 should forward VMware VMX or QEMU base-disk overrides.");
        RequireContains(runScript, "@('--qemu-disk-format', $QemuDiskFormat.Trim().ToLowerInvariant())", "run.ps1 should forward QEMU disk format with a disk override.");
        RequireContains(runScript, "Assert-RunProviderResourceOverrides", "run.ps1 should reject provider/resource combinations that JobTool would otherwise ignore.");
        RequireContains(runScript, "QEMU profile 使用 per-job overlay", "run.ps1 should explain why an internal baseline name is invalid in QEMU overlay mode.");
        RequireContains(runScript, "只适用于单次 Plan/Analyze", "run.ps1 should reject resource overrides in modes where they would otherwise be ignored.");
        RequireContains(runScript, "$arguments += '--live'", "run.ps1 should make provider mutation an explicit live option.");
        RequireContains(runScript, "Prepare-GuestPayload.ps1", "run.ps1 should prepare missing guest payloads.");
        RequireContains(runScript, "-SelfContained", "run.ps1 should prepare self-contained guest payloads for the VM.");
        RequireContains(runScript, "-PlanOnly", "run.ps1 should support non-mutating plans.");
        RequireContains(runScript, "WhatIf: WebUI would start", "run.ps1 should make WebUI startup previewable with -WhatIf.");
        RequireContains(runScript, "WhatIf: guest payload preparation would be checked/prepared", "run.ps1 should make payload preparation previewable with -WhatIf.");
        RequireContains(runScript, "PlanOnly: guest payload preparation skipped", "run.ps1 PlanOnly should avoid building guest payloads before writing a review plan.");
        RequireContains(runScript, "RecommendedActions", "run.ps1 status should emit human-readable setup repair actions.");
        RequireContains(runScript, "GuestAgentPayloadExists", "run.ps1 status should show Guest Agent payload readiness.");
        RequireContains(runScript, "R0CollectorPayloadExists", "run.ps1 status should show R0Collector payload readiness.");
        RequireContains(runScript, "ProviderReadinessCommand", "run.ps1 environment check should point to selected-provider readiness.");
        RequireContains(runScript, "ActualGuestPasswordUnknownOldPasswordRecoveryReady", "run.ps1 readiness should expose selected-provider unknown-password recovery readiness.");
        RequireContains(runScript, "ActualGuestPasswordUnknownOldPasswordRecoveryElevationReady", "run.ps1 readiness should distinguish capability support from the current elevation state.");
        RequireContains(runScript, "ProviderHostPrerequisites", "run.ps1 status should expose provider-neutral host acceleration prerequisites.");
        RequireContains(runScript, "RequiredWindowsFeatureReady", "run.ps1 should include provider-specific Windows feature readiness in the host contract.");
        RequireContains(runScript, "Win32_OptionalFeature", "run.ps1 should have a read-only CIM fallback for optional feature state.");
        RequireContains(runScript, "ProviderExecutionToolReady", "run.ps1 status should expose provider-neutral JobTool readiness.");
        RequireContains(runScript, "MissingProviderExecutionTool", "run.ps1 live readiness should fail when JobTool cannot execute.");
        RequireContains(runScript, "WebUiLaunchTargetReady", "run.ps1 should account for the runtime required by the selected WebUI target.");
        RequireContains(runScript, "Invoke-RunProviderReadOnlyCommand", "run.ps1 provider status commands should not inherit host secrets.");
        RequireContains(runScript, "vmrun listSnapshots failed with exit code", "VMware readiness should distinguish tool failure from a missing snapshot.");
        RequireContains(runScript, "vmrun list failed with exit code", "VMware readiness should distinguish inventory failure from a stopped VM.");
        RequireContains(runScript, "PlanOnlyStartsVm", "run.ps1 environment check should explicitly state PlanOnly does not start a VM.");
        RequireContains(runScript, "WhatIf: JobTool was not launched", "run.ps1 should avoid provider execution when -WhatIf declines ShouldProcess.");
        RequireContains(runScript, "Add -Live", "run.ps1 should tell operators how to opt into live VM execution.");
        RequireNotContains(runScript, "Write-Host $password", "run.ps1 must not print the guest password.");
        RequireNotContains(runScript, "Write-Output $password", "run.ps1 must not output the guest password.");

        RequireContains(runWrapper, "[Alias('SnapshotName', 'CheckpointName')]", "scripts/run.ps1 should expose the same provider-neutral baseline parameter and compatibility aliases.");
        RequireContains(runWrapper, "[string]$MachineDefinitionPath", "scripts/run.ps1 should expose provider machine-definition overrides.");
        RequireContains(runWrapper, "[string]$QemuDiskFormat", "scripts/run.ps1 should expose QEMU disk format overrides.");
        RequireContains(runWrapper, "& $rootRunner @PSBoundParameters", "scripts/run.ps1 should forward every bound provider resource override.");

        RequireContains(runDoc, ".\\install.ps1", "run doc should show the one-time install step.");
        RequireContains(runDoc, ".\\run.ps1", "run doc should show the per-use runtime step.");
        RequireContains(runDoc, "-Mode WebUI", "run doc should document WebUI mode.");
        RequireContains(runDoc, "-Mode StartWebUI", "run doc should document StartWebUI alias mode.");
        RequireContains(runDoc, "-Mode CheckEnvironment", "run doc should document environment check mode.");
        RequireContains(runDoc, "-WhatIf", "run doc should document safe preview mode.");
        RequireContains(runDoc, "-Mode Plan", "run doc should document non-mutating plan mode.");
        RequireContains(runDoc, "skips guest payload preparation", "run doc should state PlanOnly skips payload preparation.");
        RequireContains(runDoc, "RecommendedActions", "run doc should document status repair guidance.");
        RequireContains(runDoc, "PlanOnlyStartsVm=False", "run doc should state PlanOnly does not start VMs.");
        RequireContains(runDoc, "-Mode Analyze", "run doc should document one-shot analyze mode.");
        RequireContains(runDoc, "-Live", "run doc should document explicit live execution.");
        RequireContains(runDoc, "-BaselineName", "run doc should document provider-neutral baseline overrides.");
        RequireContains(runDoc, "-MachineDefinitionPath", "run doc should document VMware VMX and QEMU base-disk overrides.");
        RequireContains(runDoc, "Workstation Pro `vmrun`", "run doc should state VMware's actual live host prerequisite.");
        RequireContains(runDoc, "`qemu-system-x86_64`、`qemu-img` 和 WHPX", "run doc should state QEMU's actual live host prerequisites.");
        RequireContains(runDoc, "JobTool `execute`", "run doc should document the actual automatic guest import and report path.");
        RequireContains(runDoc, "不需要也不会重复执行第二次报告重建", "run doc should distinguish one-shot reporting from standalone PostProcess output.");
        RequireContains(runDoc, "report.html", "run doc should document final HTML report output.");
        RequireContains(runDoc, "The password value is never printed.", "run doc should state that secrets are not printed.");

        RequireContains(readme, ".\\run.ps1", "README quick start should show run.ps1.");
        RequireContains(runDoc, "# 运行入口", "run docs should be present for detailed runtime guidance.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "run.ps1 post-install WebUI and provider-neutral one-shot entry point contracts are present."
        });
    }

    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    private static void RequireNotContains(string content, string unexpected, string message)
    {
        SmokeAssert.True(!content.Contains(unexpected, StringComparison.Ordinal), message);
    }
}
