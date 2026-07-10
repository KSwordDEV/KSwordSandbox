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
        var runDocPath = Path.Combine(context.RepositoryRoot, "docs", "run.md");
        var readmePath = Path.Combine(context.RepositoryRoot, "README.md");

        SmokeAssert.True(File.Exists(runScriptPath), "run.ps1 is missing from the repository root.");
        SmokeAssert.True(File.Exists(runDocPath), "docs/run.md is missing.");
        SmokeAssert.True(File.Exists(readmePath), "README.md is missing.");

        var runScript = File.ReadAllText(runScriptPath);
        var runDoc = File.ReadAllText(runDocPath);
        var readme = File.ReadAllText(readmePath);

        RequireContains(runScript, "ValidateSet('WebUI', 'Analyze', 'Plan', 'Status')", "run.ps1 should expose WebUI, Analyze, Plan, and Status modes.");
        RequireContains(runScript, "install-state.json", "run.ps1 should load install.ps1 state.");
        RequireContains(runScript, "Sandbox__ConfigPath", "run.ps1 should set the Web/API config path.");
        RequireContains(runScript, "ASPNETCORE_URLS", "run.ps1 should control the WebUI listen URL without launchSettings.");
        RequireContains(runScript, "http://127.0.0.1:18080", "run.ps1 should default to a localhost port outside common Hyper-V excluded ranges.");
        RequireContains(runScript, "Resolve-WebListenUrl", "run.ps1 should resolve or fall back from blocked localhost ports.");
        RequireContains(runScript, "StrictUrl", "run.ps1 should allow strict URL binding for operators who need it.");
        RequireContains(runScript, "KSWORDBOX_GUEST_PASSWORD", "run.ps1 should default to the guest password secret name.");
        RequireContains(runScript, "SecretValuePrinted = $false", "run.ps1 status should assert secrets are not printed.");
        RequireContains(runScript, "dotnet", "run.ps1 should launch the Web project through dotnet.");
        RequireContains(runScript, "--no-launch-profile", "run.ps1 should avoid launchSettings port surprises.");
        RequireContains(runScript, "Invoke-HyperVE2E.ps1", "run.ps1 should delegate one-shot analysis to the Hyper-V E2E script.");
        RequireContains(runScript, "Prepare-GuestPayload.ps1", "run.ps1 should prepare missing guest payloads.");
        RequireContains(runScript, "-SelfContained", "run.ps1 should prepare self-contained guest payloads for the VM.");
        RequireContains(runScript, "-PlanOnly", "run.ps1 should support non-mutating plans.");
        RequireContains(runScript, "Add -Live", "run.ps1 should tell operators how to opt into live VM execution.");
        RequireNotContains(runScript, "Write-Host $password", "run.ps1 must not print the guest password.");
        RequireNotContains(runScript, "Write-Output $password", "run.ps1 must not output the guest password.");

        RequireContains(runDoc, ".\\install.ps1", "run doc should show the one-time install step.");
        RequireContains(runDoc, ".\\run.ps1", "run doc should show the per-use runtime step.");
        RequireContains(runDoc, "-Mode WebUI", "run doc should document WebUI mode.");
        RequireContains(runDoc, "-Mode Plan", "run doc should document non-mutating plan mode.");
        RequireContains(runDoc, "-Mode Analyze", "run doc should document one-shot analyze mode.");
        RequireContains(runDoc, "-Live", "run doc should document explicit live execution.");
        RequireContains(runDoc, "The password value is never printed.", "run doc should state that secrets are not printed.");

        RequireContains(readme, ".\\run.ps1", "README quick start should show run.ps1.");
        RequireContains(readme, "docs/run.md", "README should link to run docs.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "run.ps1 post-install WebUI and one-shot Hyper-V entry point contracts are present."
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
