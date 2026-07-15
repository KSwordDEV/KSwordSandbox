using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the release-wrapper contract for the install/run path without
/// executing a provider or starting the WebUI. Inputs are repository scripts/docs;
/// processing performs static checks; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class InstallRunPackagingContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "install-run.packaging.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var installScriptPath = Path.Combine(context.RepositoryRoot, "install.ps1");
        var runScriptPath = Path.Combine(context.RepositoryRoot, "run.ps1");
        var installDocPath = Path.Combine(context.RepositoryRoot, "docs", "install.md");
        var readmePath = Path.Combine(context.RepositoryRoot, "README.md");
        var runtimeManifestPath = Path.Combine(context.RepositoryRoot, "packaging", "runtime-package.manifest.json");

        SmokeAssert.True(File.Exists(installScriptPath), "install.ps1 is missing.");
        SmokeAssert.True(File.Exists(runScriptPath), "run.ps1 is missing.");
        SmokeAssert.True(File.Exists(installDocPath), "docs/install.md is missing.");
        SmokeAssert.True(File.Exists(readmePath), "README.md is missing.");
        SmokeAssert.True(File.Exists(runtimeManifestPath), "Runtime package manifest is missing.");

        var installScript = File.ReadAllText(installScriptPath);
        var runScript = File.ReadAllText(runScriptPath);
        var installDoc = File.ReadAllText(installDocPath);
        var readme = File.ReadAllText(readmePath);
        var runtimeManifest = File.ReadAllText(runtimeManifestPath);

        RequireNotContains(installScript, "CSignTool", "install.ps1 must not call or reference CSignTool.");
        RequireNotContains(installScript, "Sign-SandboxDriverWithKswordCSignTool", "install.ps1 must not call the legacy KSword signing wrapper.");

        RequireContains(runScript, "Ensure-GuestPayloadForWebUi", "run.ps1 should have a WebUI-specific payload wrapper.");
        RequireContains(runScript, "StartWebUI", "run.ps1 should provide an explicit StartWebUI mode.");
        RequireContains(runScript, "Assert-RunLocalConfigReadyForInteractiveStartup", "run.ps1 should block ordinary startup from silently using the example config.");
        RequireContains(runScript, "本机配置未就绪", "run.ps1 should explain missing local config in Chinese.");
        RequireContains(runScript, "CheckEnvironment", "run.ps1 should provide a non-mutating environment-check mode.");
        RequireContains(runScript, "RequirePayloadForWebUI", "run.ps1 should allow strict WebUI payload enforcement.");
        RequireContains(runScript, "WebUI will still start", "WebUI mode should remain launchable when payload build prerequisites are missing.");
        RequireContains(runScript, "GuestPayloadManifestExists", "run.ps1 status should show payload readiness.");
        RequireContains(runScript, "GuestAgentPayloadExists", "run.ps1 status should show agent payload readiness.");
        RequireContains(runScript, "R0CollectorPayloadExists", "run.ps1 status should show collector payload readiness.");
        RequireContains(runScript, "GuestPasswordGuidance", "run.ps1 status should guide operators to configure the guest password.");
        RequireContains(runScript, "RecommendedActions", "run.ps1 status should provide human-readable repair suggestions.");
        RequireContains(runScript, "Provider live prerequisites", "run.ps1 should print selected-provider live prerequisite guidance at WebUI startup.");

        RequireContains(installDoc, ".\\run.ps1", "Install docs should show the post-install WebUI command.");
        RequireContains(installDoc, ".\\install.ps1 -Mode CheckEnvironment", "Install docs should show the environment-check command.");
        RequireContains(installDoc, ".\\install.ps1 -Mode ConfigureVTKey -PromptVTKey", "Install docs should show VT key configuration.");
        RequireContains(installDoc, "self-contained Guest", "Install docs should explain self-contained guest payload preparation.");
        RequireContains(installDoc, "-RequirePayloadForWebUI", "Install docs should document strict payload mode.");
        RequireContains(installDoc, "RecommendedActions", "Install docs should describe repair suggestions for fresh hosts.");
        RequireContains(installDoc, "must not call `CSignTool.exe`", "Install docs should document the no-CSignTool boundary.");

        RequireContains(readme, ".\\run.ps1", "README quick start should show the runtime wrapper.");
        RequireContains(readme, ".\\install.ps1 -Mode CheckEnvironment", "README quick start should show the environment-check wrapper.");
        RequireContains(readme, ".\\install.ps1 -Mode ConfigureVTKey -PromptVTKey", "README should document optional VT key setup.");
        RequireContains(readme, "Guest Agent/R0Collector payload", "README should explain payload preparation in the wrapper path.");
        RequireContains(readme, "RequirePayloadForWebUI", "README should document strict WebUI payload preparation.");
        RequireContains(readme, "不调用 `CSignTool.exe`", "README should preserve the no-CSignTool install/run boundary.");

        RequireContains(runtimeManifest, "docs/vmware-qemu.md", "Runtime packages should include the provider operations guide.");
        RequireContains(runtimeManifest, "scripts/Invoke-WebUIApiE2E.ps1", "Runtime packages should include the three-provider Web API parity evidence helper.");
        RequireContains(runtimeManifest, "scripts/Test-ProviderParityEvidence.ps1", "Runtime packages should include the read-only aggregate provider parity validator.");
        RequireContains(runtimeManifest, "scripts/Set-GuestTestSigning.ps1", "Runtime packages should include the shared provider guest test-signing helper.");
        RequireContains(runtimeManifest, "scripts/Reset-RemoteGuestPassword.ps1", "Runtime packages should include provider WinRM password rotation.");
        RequireContains(runtimeManifest, "scripts/Inject-OfflineGuestPasswordService.ps1", "Runtime packages should include provider-neutral offline VHDX password injection.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Install/run packaging contract covers no-CSignTool install, one-command WebUI startup, payload prep, and guest password guidance."
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
