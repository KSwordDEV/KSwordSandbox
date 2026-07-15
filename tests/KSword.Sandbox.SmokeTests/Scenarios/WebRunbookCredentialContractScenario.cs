using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that WebUI-generated live runbook steps are self-contained around
/// guest credentials. Inputs are an in-memory sandbox config and sample
/// identity; processing builds a runbook without invoking Hyper-V; the scenario
/// fails when any step references $guestCredential without recreating it in the
/// same PowerShell process.
/// </summary>
internal sealed class WebRunbookCredentialContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "webui.runbook-credential.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var config = new SandboxConfig
        {
            HyperV = new HyperVConfig
            {
                GoldenVmName = "KSwordSandbox-Win10-Golden",
                GoldenSnapshotName = "Clean"
            },
            Guest = new GuestConfig
            {
                UserName = "SandboxUser",
                PasswordSecretName = "KSWORDBOX_GUEST_PASSWORD",
                WorkingDirectory = @"C:\KSwordSandbox"
            },
            Paths = new SandboxPaths
            {
                RuntimeRoot = Path.Combine(Path.GetTempPath(), "KSwordSandboxRunbookContract"),
                GuestPayloadRoot = @"D:\Temp\KSwordSandbox\payload\guest-tools"
            },
            Driver = new DriverConfig
            {
                Enabled = true,
                UseMockCollector = true,
                R0CollectorPathInGuest = @"C:\KSwordSandbox\r0collector\KSword.Sandbox.R0Collector.exe",
                DevicePath = @"\\.\KSwordSandboxDriver"
            },
            Analysis = new AnalysisConfig
            {
                DefaultDurationSeconds = 30
            }
        };

        var sample = new SampleIdentity
        {
            FileName = "sample.exe",
            FullPath = Path.Combine(Path.GetTempPath(), "sample.exe"),
            Sha256 = new string('a', 64),
            Sha1 = new string('b', 40),
            Md5 = new string('c', 32),
            Crc32 = "00000000",
            SizeBytes = 1
        };

        var runbook = new HyperVRunbookBuilder().Build(config, Guid.Parse("11111111-1111-1111-1111-111111111111"), sample);
        var credentialSteps = runbook.Steps
            .Where(step => step.PowerShell.Contains("$guestCredential", StringComparison.Ordinal))
            .ToList();

        SmokeAssert.True(credentialSteps.Count > 0, "Runbook should contain PowerShell Direct steps that use guest credentials.");

        foreach (var step in credentialSteps)
        {
            SmokeAssert.True(
                step.PowerShell.Contains("[System.Environment]::GetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD', 'Process')", StringComparison.Ordinal) &&
                step.PowerShell.Contains("[System.Environment]::GetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD', 'User')", StringComparison.Ordinal) &&
                step.PowerShell.Contains("[System.Environment]::GetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD', 'Machine')", StringComparison.Ordinal) &&
                step.PowerShell.Contains("[System.Security.SecureString]::new()", StringComparison.Ordinal) &&
                step.PowerShell.Contains("$guestPassword.AppendChar($guestPasswordChar)", StringComparison.Ordinal) &&
                step.PowerShell.Contains("[pscredential]::new('SandboxUser'", StringComparison.Ordinal) &&
                step.PowerShell.Contains("$guestPasswordText = $null; $guestPasswordChar = $null;", StringComparison.Ordinal),
                $"Runbook step {step.Id} references $guestCredential but does not recreate it in the same PowerShell command.");

            SmokeAssert.True(
                !step.PowerShell.Contains("ConvertTo-SecureString", StringComparison.Ordinal),
                $"Runbook step {step.Id} should not depend on ConvertTo-SecureString module autoloading.");
        }

        SmokeAssert.True(
            runbook.Steps.Any(step => step.Id.Equals("check-guest-credential", StringComparison.OrdinalIgnoreCase)),
            "Runbook should include an explicit credential preflight step.");

        SmokeAssert.True(
            runbook.Steps.Any(step =>
                step.Id.Equals("wait-powershell-direct", StringComparison.OrdinalIgnoreCase) &&
                step.PowerShell.Contains("Guest endpoint did not become ready", StringComparison.Ordinal) &&
                step.PowerShell.Contains("transport=PowerShell Direct", StringComparison.Ordinal)),
            "Runbook should wait for PowerShell Direct after VM start before staging payload or running the sample.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "WebUI runbook credential steps are self-contained for per-step PowerShell execution."
        });
    }
}
