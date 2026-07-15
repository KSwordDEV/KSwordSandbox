using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that unattended driver validation is compile-only, legacy CSignTool
/// signing is guarded, and VM-only test-certificate helpers stay documented.
/// </summary>
internal sealed class DriverSigningContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "driver.signing.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var legacyScriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Sign-SandboxDriverWithKswordCSignTool.ps1");
        var testCertificateScriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Sign-SandboxDriverWithTestCertificate.ps1");
        var guestTestSigningScriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Set-GuestTestSigning.ps1");
        var nativeBuildScriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Invoke-NativeBuild.ps1");
        var fullValidationScriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Invoke-FullValidation.ps1");
        var driverProjectPath = Path.Combine(context.RepositoryRoot, "driver", "KSword.Sandbox.Driver", "KSword.Sandbox.Driver.vcxproj");
        var gitignorePath = Path.Combine(context.RepositoryRoot, ".gitignore");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "driver-signing.md");

        SmokeAssert.True(File.Exists(legacyScriptPath), "Legacy CSignTool script is missing.");
        SmokeAssert.True(File.Exists(testCertificateScriptPath), "Test-certificate signing helper is missing.");
        SmokeAssert.True(File.Exists(guestTestSigningScriptPath), "Guest test-signing helper is missing.");
        SmokeAssert.True(File.Exists(nativeBuildScriptPath), "Native build script is missing.");
        SmokeAssert.True(File.Exists(fullValidationScriptPath), "Full validation script is missing.");
        SmokeAssert.True(File.Exists(driverProjectPath), "Driver project is missing.");
        SmokeAssert.True(File.Exists(gitignorePath), ".gitignore is missing.");
        SmokeAssert.True(File.Exists(docPath), "driver signing doc is missing.");

        var legacyScript = File.ReadAllText(legacyScriptPath);
        SmokeAssert.True(legacyScript.Contains("AllowInteractiveCSignTool", StringComparison.Ordinal), "Legacy CSignTool script must require an explicit interactive opt-in.");
        SmokeAssert.True(legacyScript.Contains("disabled by default for unattended builds", StringComparison.Ordinal), "Legacy CSignTool script should fail closed in unattended runs.");

        var testCertificateScript = File.ReadAllText(testCertificateScriptPath);
        SmokeAssert.True(testCertificateScript.Contains("New-SelfSignedCertificate", StringComparison.Ordinal), "Test-certificate helper should create or reuse a local test cert.");
        SmokeAssert.True(testCertificateScript.Contains("signtool.exe", StringComparison.Ordinal), "Test-certificate helper should use ordinary signtool.exe when signing.");
        SmokeAssert.True(testCertificateScript.Contains("Resolve-SignTool", StringComparison.Ordinal), "Test-certificate helper should resolve Windows SDK/PATH signtool.exe.");
        SmokeAssert.True(testCertificateScript.Contains("SignatureAttempted = $false", StringComparison.Ordinal), "Test-certificate helper should clearly skip when signtool.exe is absent.");
        SmokeAssert.True(testCertificateScript.Contains("Skipped = $true", StringComparison.Ordinal), "Test-certificate helper should report skipped signing when signtool.exe is absent.");
        SmokeAssert.True(!testCertificateScript.Contains("Set-AuthenticodeSignature", StringComparison.Ordinal), "Test-certificate helper should not use PowerShell Authenticode fallback signing.");
        SmokeAssert.True(testCertificateScript.Contains("CSignToolUsed = $false", StringComparison.Ordinal), "Test-certificate helper should make the no-CSignTool path explicit.");

        var guestTestSigningScript = File.ReadAllText(guestTestSigningScriptPath);
        SmokeAssert.True(guestTestSigningScript.Contains("[ValidateSet('HyperV', 'VMware', 'Qemu')]", StringComparison.Ordinal), "Guest test-signing should support all virtualization providers.");
        SmokeAssert.True(guestTestSigningScript.Contains("$invokeParameters['VMName']", StringComparison.Ordinal), "Hyper-V guest test-signing should retain PowerShell Direct.");
        SmokeAssert.True(guestTestSigningScript.Contains("$invokeParameters['ComputerName']", StringComparison.Ordinal), "VMware/QEMU guest test-signing should use WinRM.");
        SmokeAssert.True(guestTestSigningScript.Contains("Basic WinRM over HTTP is refused", StringComparison.Ordinal), "Guest test-signing should reject Basic WinRM without HTTPS.");
        SmokeAssert.True(guestTestSigningScript.Contains("SetEnvironmentVariable($SecretName, $null, 'Process')", StringComparison.Ordinal), "Guest test-signing should clear its process guest secret after credential construction.");
        SmokeAssert.True(guestTestSigningScript.Contains("GuestRemotingSkipCertificateChecks", StringComparison.Ordinal), "Guest test-signing should honor the provider certificate policy.");
        SmokeAssert.True(guestTestSigningScript.Contains("$VirtualizationProvider -eq 'HyperV' -and -not (Test-IsAdministrator)", StringComparison.Ordinal), "Only the Hyper-V PowerShell Direct path should require an elevated host shell.");
        SmokeAssert.True(guestTestSigningScript.Contains("getGuestIPAddress", StringComparison.Ordinal), "VMware guest test-signing should support VMware Tools endpoint discovery.");
        SmokeAssert.True(guestTestSigningScript.Contains("Select-VMwareGuestAddress", StringComparison.Ordinal), "VMware guest test-signing should use the shared routable-address preference contract.");
        SmokeAssert.True(guestTestSigningScript.Contains("[Net.Sockets.AddressFamily]::InterNetwork", StringComparison.Ordinal), "VMware guest test-signing should prefer a routable IPv4 address.");
        SmokeAssert.True(guestTestSigningScript.Contains("QemuUserNat", StringComparison.Ordinal), "QEMU guest test-signing should support the managed user-NAT endpoint.");
        SmokeAssert.True(guestTestSigningScript.Contains("Get-QemuExpectedProcessVmNameFromPidFile", StringComparison.Ordinal), "QEMU guest test-signing should reconstruct bounded per-job overlay VM names before sending credentials to user-NAT.");
        SmokeAssert.True(guestTestSigningScript.Contains("[switch]$QemuInternalSnapshot", StringComparison.Ordinal), "QEMU guest test-signing should distinguish internal-snapshot and per-job-overlay VM identities without fragile command-line bool binding.");
        SmokeAssert.True(guestTestSigningScript.Contains("Test-QemuCommandLineVmName", StringComparison.Ordinal), "QEMU guest test-signing should match the exact -name argument selected by the configured disk isolation mode.");

        var installerScript = File.ReadAllText(Path.Combine(context.RepositoryRoot, "install.ps1"));
        SmokeAssert.True(installerScript.Contains("$arguments += '-QemuInternalSnapshot'", StringComparison.Ordinal), "Installer guest test-signing should pass the selected QEMU internal-snapshot mode to the shared helper.");
        SmokeAssert.True(guestTestSigningScript.Contains("automatic endpoint mode requires GuestRemotingUseSsl", StringComparison.Ordinal), "Provider-managed guest test-signing endpoints should require WinRM HTTPS.");
        SmokeAssert.True(guestTestSigningScript.Contains("StartsWith('KSWORDBOX_'", StringComparison.Ordinal), "Guest test-signing provider discovery should not inherit KSword secrets.");
        SmokeAssert.True(guestTestSigningScript.Contains("RestartAttempted", StringComparison.Ordinal), "Guest test-signing should distinguish restart dispatch from verified completion.");
        SmokeAssert.True(guestTestSigningScript.Contains("RestartCompleted", StringComparison.Ordinal), "Guest test-signing should expose verified restart completion.");
        SmokeAssert.True(guestTestSigningScript.Contains("PostRestartBootTimeUtc", StringComparison.Ordinal), "Guest test-signing should retain the post-restart boot identity.");
        SmokeAssert.True(guestTestSigningScript.Contains("$bootChanged -and $stateMatches", StringComparison.Ordinal), "Restart completion should require both a new boot and the requested test-signing state.");
        SmokeAssert.True(guestTestSigningScript.Contains("Resolve-GuestRemotingEndpoint", StringComparison.Ordinal), "Post-restart verification should rediscover provider-managed VMware/QEMU endpoints.");
        SmokeAssert.True(guestTestSigningScript.Contains("shutdown.exe /r /t 0 /f", StringComparison.Ordinal), "Guest restart should be dispatched after the change result is safely returned.");
        SmokeAssert.True(!guestTestSigningScript.Contains("Restart-Computer -Force", StringComparison.Ordinal), "The change command should not tear down its own remoting session before returning a result.");

        var nativeBuildScript = File.ReadAllText(nativeBuildScriptPath);
        SmokeAssert.True(nativeBuildScript.Contains("/p:SignMode=Off", StringComparison.Ordinal), "Native build must disable MSBuild driver signing by default.");
        SmokeAssert.True(nativeBuildScript.Contains("-not $SignDriver -and $signingParametersSupplied", StringComparison.Ordinal), "Native build must reject signing parameters without explicit -SignDriver.");
        SmokeAssert.True(!nativeBuildScript.Contains("CSignTool", StringComparison.Ordinal), "Native build must not reference CSignTool.");

        var fullValidationScript = File.ReadAllText(fullValidationScriptPath);
        SmokeAssert.True(fullValidationScript.Contains("SignNativeDriver", StringComparison.Ordinal), "Full validation should keep signing opt-in explicit.");
        SmokeAssert.True(fullValidationScript.Contains("default validation path is compile-only", StringComparison.Ordinal), "Full validation should document compile-only default.");

        foreach (var unattendedScriptName in new[]
        {
            "Invoke-NativeBuild.ps1",
            "Invoke-FullValidation.ps1",
            "Invoke-LocalPipelineSmoke.ps1",
            "Invoke-HyperVE2E.ps1",
            "Invoke-WebUIApiE2E.ps1",
            "Start-SandboxHyperVJob.ps1",
            "Set-GuestTestSigning.ps1"
        })
        {
            var unattendedScript = File.ReadAllText(Path.Combine(context.RepositoryRoot, "scripts", unattendedScriptName));
            SmokeAssert.True(!unattendedScript.Contains("Sign-SandboxDriverWithKswordCSignTool.ps1", StringComparison.Ordinal), $"{unattendedScriptName} must not call the legacy CSignTool wrapper.");
            SmokeAssert.True(!unattendedScript.Contains(".cert\\CSignTool.exe", StringComparison.Ordinal), $"{unattendedScriptName} must not call a bundled CSignTool binary.");
            SmokeAssert.True(!unattendedScript.Contains("& CSignTool", StringComparison.Ordinal), $"{unattendedScriptName} must not invoke CSignTool by command name.");
        }

        var driverProject = File.ReadAllText(driverProjectPath);
        SmokeAssert.True(driverProject.Contains("<SignMode>Off</SignMode>", StringComparison.Ordinal), "Driver project must keep SignMode=Off.");
        SmokeAssert.True(!driverProject.Contains("<DriverSign>", StringComparison.Ordinal), "Driver project must not keep a DriverSign hook.");

        var gitignore = File.ReadAllText(gitignorePath);
        SmokeAssert.True(gitignore.Contains("/.cert/", StringComparison.Ordinal), ".cert directory must be ignored.");

        var doc = File.ReadAllText(docPath);
        SmokeAssert.True(doc.Contains("compile-only", StringComparison.Ordinal), "Driver signing doc should describe compile-only default validation.");
        SmokeAssert.True(doc.Contains("Do **not** call `CSignTool.exe`", StringComparison.Ordinal), "Driver signing doc should freeze unattended CSignTool use.");
        SmokeAssert.True(doc.Contains("Sign-SandboxDriverWithTestCertificate.ps1", StringComparison.Ordinal), "Driver signing doc should mention the test-certificate helper.");
        SmokeAssert.True(doc.Contains(".cert", StringComparison.Ordinal), "Driver signing doc should explain the local ignored .cert directory.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Driver signing defaults to compile-only; legacy CSignTool is guarded and test-certificate flow is documented."
        });
    }
}
