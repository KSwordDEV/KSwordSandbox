using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the release-wrapper contract for the install/run path without
/// executing Hyper-V or starting the WebUI. Inputs are repository scripts/docs;
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

        SmokeAssert.True(File.Exists(installScriptPath), "install.ps1 is missing.");
        SmokeAssert.True(File.Exists(runScriptPath), "run.ps1 is missing.");
        SmokeAssert.True(File.Exists(installDocPath), "docs/install.md is missing.");
        SmokeAssert.True(File.Exists(readmePath), "README.md is missing.");

        var installScript = File.ReadAllText(installScriptPath);
        var runScript = File.ReadAllText(runScriptPath);
        var installDoc = File.ReadAllText(installDocPath);
        var readme = File.ReadAllText(readmePath);

        RequireNotContains(installScript, "CSignTool", "install.ps1 must not call or reference CSignTool.");
        RequireNotContains(installScript, "Sign-SandboxDriverWithKswordCSignTool", "install.ps1 must not call the legacy KSword signing wrapper.");

        RequireContains(runScript, "Ensure-GuestPayloadForWebUi", "run.ps1 should have a WebUI-specific payload wrapper.");
        RequireContains(runScript, "RequirePayloadForWebUI", "run.ps1 should allow strict WebUI payload enforcement.");
        RequireContains(runScript, "WebUI will still start", "WebUI mode should remain launchable when payload build prerequisites are missing.");
        RequireContains(runScript, "GuestPayloadManifestExists", "run.ps1 status should show payload readiness.");
        RequireContains(runScript, "GuestPasswordGuidance", "run.ps1 status should guide operators to configure the guest password.");
        RequireContains(runScript, "Hyper-V live prerequisites", "run.ps1 should print live prerequisite guidance at WebUI startup.");

        RequireContains(installDoc, ".\\run.ps1", "Install docs should show the post-install WebUI command.");
        RequireContains(installDoc, "self-contained Guest", "Install docs should explain self-contained guest payload preparation.");
        RequireContains(installDoc, "-RequirePayloadForWebUI", "Install docs should document strict payload mode.");
        RequireContains(installDoc, "must not call `CSignTool.exe`", "Install docs should document the no-CSignTool boundary.");

        RequireContains(readme, ".\\run.ps1", "README quick start should show the runtime wrapper.");
        RequireContains(readme, "self-contained guest payload", "README should explain payload preparation in the wrapper path.");
        RequireContains(readme, "RequirePayloadForWebUI", "README should document strict WebUI payload preparation.");
        RequireContains(readme, "do not call", "README should preserve the no-CSignTool install/run boundary.");

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
