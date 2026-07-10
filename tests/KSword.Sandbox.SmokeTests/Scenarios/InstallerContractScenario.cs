using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the local installer contract for Hyper-V guest credential setup.
/// Inputs are repository paths; processing reads scripts/docs only; the
/// scenario returns pass/fail metadata without executing the installer.
/// </summary>
internal sealed class InstallerContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "installer.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var installerPath = Path.Combine(context.RepositoryRoot, "install.ps1");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "install.md");
        SmokeAssert.True(File.Exists(installerPath), "install.ps1 is missing from the repository root.");
        SmokeAssert.True(File.Exists(docPath), "docs/install.md is missing.");

        var installer = File.ReadAllText(installerPath);
        var doc = File.ReadAllText(docPath);

        RequireContains(installer, "ValidateSet('Interactive', 'Install', 'Change', 'Uninstall', 'Status')", "Installer should expose install/change/uninstall/status modes.");
        RequireContains(installer, "KSwordSandbox local installer", "Installer should expose an interactive menu.");
        RequireContains(installer, "Install / prepare local settings", "Interactive installer should offer install.");
        RequireContains(installer, "Change settings", "Interactive installer should offer change.");
        RequireContains(installer, "Uninstall local settings", "Interactive installer should offer uninstall.");
        RequireContains(installer, "Status", "Interactive installer should offer status.");
        RequireContains(installer, "Invoke-ChangeMenu", "Installer should include a change menu.");
        RequireContains(installer, "Change options:", "Installer should label the change menu.");
        RequireContains(installer, "Reset password secret", "Installer change menu should include password reset.");
        RequireContains(installer, "Reset actual VM guest password", "Installer change menu should include actual VM password reset.");
        RequireContains(installer, "Change Hyper-V VM/checkpoint/guest paths", "Installer change menu should include Hyper-V config.");
        RequireContains(installer, "Change recorded guest username", "Installer change menu should include more than password reset.");
        RequireContains(installer, "Recreate runtime folders and local config", "Installer change menu should include runtime folder and config refresh.");
        RequireContains(installer, "Show Hyper-V readiness/status", "Installer change menu should include Hyper-V status.");
        RequireContains(installer, "Set-GuestPasswordSecret", "Installer should centralize secret writes.");
        RequireContains(installer, "Set-HyperVConfigState", "Installer should centralize Hyper-V config writes.");
        RequireContains(installer, "Invoke-GuestVmPasswordReset", "Installer should expose actual VM password reset integration.");
        RequireContains(installer, "Reset-SandboxGuestPassword.ps1", "Installer should call the offline actual VM password reset script.");
        RequireContains(installer, "KSWORDBOX_GUEST_PASSWORD", "Installer should default to the expected Hyper-V guest password secret.");
        RequireContains(installer, "Sandbox__ConfigPath", "Installer should set the ASP.NET config path environment variable.");
        RequireContains(installer, "vmName = $Vm", "Install state should record the Hyper-V VM name.");
        RequireContains(installer, "checkpointName = $Checkpoint", "Install state should record the clean checkpoint name.");
        RequireContains(installer, "guestWorkingDirectory = $GuestWorking", "Install state should record the guest working directory.");
        RequireContains(installer, "localConfigPath = $LocalConfig", "Install state should record the generated local config path.");
        RequireContains(installer, "ConvertFrom-SecureString", "Installer should support DPAPI-protected local backup.");
        RequireContains(installer, "SecretValuePrinted = $false", "Installer should explicitly avoid printing secret values.");
        RequireContains(installer, "Value was not printed.", "Installer should tell operators the password value was not printed.");
        RequireNotContains(installer, "Write-Host $Password", "Installer should not print the password value.");
        RequireNotContains(installer, "Write-Output $Password", "Installer should not output the password value.");
        RequireNotContains(installer, "Write-InstallInfo $Password", "Installer should not log the password value.");
        RequireContains(installer, "SetEnvironmentVariable($Name, $Password, 'User')", "Installer should persist the secret to the user environment.");
        RequireContains(installer, "SetEnvironmentVariable($Name, $Password, 'Process')", "Installer should mirror the secret to the current process.");
        RequireContains(installer, "'Change'", "Installer should support non-interactive change mode.");
        RequireContains(installer, "'Uninstall'", "Installer should support non-interactive uninstall mode.");
        RequireContains(installer, "[switch]$GeneratePassword", "Installer should support generated passwords in non-interactive modes.");
        RequireContains(installer, "[switch]$PromptPassword", "Installer should support prompted passwords in non-interactive modes.");
        RequireContains(installer, "[switch]$ResetPassword", "Installer should support non-interactive password reset.");
        RequireContains(installer, "[switch]$ResetGuestVmPassword", "Installer should support non-interactive actual VM password reset.");
        RequireContains(installer, "[switch]$UpdateHyperVConfig", "Installer should support non-interactive Hyper-V config updates.");
        RequireContains(installer, "$shouldSetPassword = [bool]$GeneratePassword -or [bool]$PromptPassword -or [bool]$ResetPassword", "Non-interactive install should support prompt/generate password setup.");
        RequireContains(installer, "if ($ResetGuestVmPassword)", "Non-interactive change should prioritize actual VM password reset.");
        RequireContains(installer, "elseif ($UpdateHyperVConfig)", "Non-interactive change should support Hyper-V config updates.");
        RequireContains(installer, "if ($ResetPassword -or $GeneratePassword -or $PromptPassword)", "Non-interactive change should support reset password prompt/generate.");
        RequireNotContains(installer, "CSignTool", "Installer must not call or reference CSignTool.");
        RequireNotContains(installer, "Sign-SandboxDriverWithKswordCSignTool", "Installer must not call the legacy KSword signing wrapper.");

        RequireContains(doc, "- Install / prepare local settings", "Install doc should describe interactive install.");
        RequireContains(doc, "Change menu", "Install doc should describe the change menu.");
        RequireContains(doc, "reset password secret", "Install doc should describe password reset.");
        RequireContains(doc, "reset the actual VM guest password", "Install doc should describe actual VM password reset.");
        RequireContains(doc, "change Hyper-V VM/checkpoint/guest paths", "Install doc should describe Hyper-V config changes.");
        RequireContains(doc, "change the recorded guest username", "Install doc should describe multiple change options.");
        RequireContains(doc, "recreate runtime folders and local config", "Install doc should describe multiple change options.");
        RequireContains(doc, "DPAPI", "Install doc should describe DPAPI storage.");
        RequireContains(doc, "Sandbox__ConfigPath", "Install doc should describe Web/API local config wiring.");
        RequireContains(doc, ".\\install.ps1 -Mode Change -UpdateHyperVConfig", "Install doc should describe non-interactive Hyper-V config.");
        RequireContains(doc, ".\\install.ps1 -Mode Change -ResetGuestVmPassword -GeneratePassword -Force", "Install doc should describe non-interactive actual VM password reset.");
        RequireContains(doc, ".\\install.ps1 -Mode Install -GeneratePassword", "Install doc should describe non-interactive generated install.");
        RequireContains(doc, ".\\install.ps1 -Mode Install -PromptPassword", "Install doc should describe non-interactive prompted install.");
        RequireContains(doc, ".\\install.ps1 -Mode Change -ResetPassword -GeneratePassword", "Install doc should describe non-interactive generated reset.");
        RequireContains(doc, ".\\install.ps1 -Mode Change -ResetPassword -PromptPassword", "Install doc should describe non-interactive prompted reset.");
        RequireContains(doc, "Uninstall", "Install doc should describe uninstall.");
        RequireContains(doc, "Status", "Install doc should describe status.");
        RequireContains(doc, "The password value is never printed.", "Install doc should state that password values are never printed.");
        RequireContains(doc, ".\\run.ps1", "Install doc should show the post-install one-command WebUI launch.");
        RequireContains(doc, "self-contained Guest", "Install doc should explain self-contained guest payload preparation.");
        RequireContains(doc, "-RequirePayloadForWebUI", "Install doc should explain strict WebUI payload preparation.");
        RequireContains(doc, "does not sign drivers", "Install doc should state install does not sign drivers.");
        RequireContains(doc, "must not call `CSignTool.exe`", "Install doc should explicitly prohibit CSignTool in install packaging.");
        RequireContains(doc, ".\\scripts\\Test-HyperVReadiness.ps1", "Install doc should point operators to the one-command readiness preflight.");
        RequireContains(doc, "PromptForMissingGuestPassword", "Install doc should document the process-only readiness password prompt.");
        RequireContains(doc, "repository-policy", "Install doc should describe secret hygiene repository policy.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Installer interactive modes, change options, non-interactive password reset, DPAPI backup, and no-print secret contracts are present."
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
