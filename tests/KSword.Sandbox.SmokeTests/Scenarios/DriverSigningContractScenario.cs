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
        var nativeBuildScriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Invoke-NativeBuild.ps1");
        var fullValidationScriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Invoke-FullValidation.ps1");
        var driverProjectPath = Path.Combine(context.RepositoryRoot, "driver", "KSword.Sandbox.Driver", "KSword.Sandbox.Driver.vcxproj");
        var gitignorePath = Path.Combine(context.RepositoryRoot, ".gitignore");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "driver-signing.md");

        SmokeAssert.True(File.Exists(legacyScriptPath), "Legacy CSignTool script is missing.");
        SmokeAssert.True(File.Exists(testCertificateScriptPath), "Test-certificate signing helper is missing.");
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
        SmokeAssert.True(testCertificateScript.Contains("Set-AuthenticodeSignature", StringComparison.Ordinal), "Test-certificate helper should use non-CSignTool Authenticode signing.");
        SmokeAssert.True(testCertificateScript.Contains("CSignToolUsed = $false", StringComparison.Ordinal), "Test-certificate helper should make the no-CSignTool path explicit.");

        var nativeBuildScript = File.ReadAllText(nativeBuildScriptPath);
        SmokeAssert.True(nativeBuildScript.Contains("/p:SignMode=Off", StringComparison.Ordinal), "Native build must disable MSBuild driver signing by default.");
        SmokeAssert.True(nativeBuildScript.Contains("-not $SignDriver -and $signingParametersSupplied", StringComparison.Ordinal), "Native build must reject signing parameters without explicit -SignDriver.");
        SmokeAssert.True(!nativeBuildScript.Contains("CSignTool", StringComparison.Ordinal), "Native build must not reference CSignTool.");

        var fullValidationScript = File.ReadAllText(fullValidationScriptPath);
        SmokeAssert.True(fullValidationScript.Contains("SignNativeDriver", StringComparison.Ordinal), "Full validation should keep signing opt-in explicit.");
        SmokeAssert.True(fullValidationScript.Contains("default validation path is compile-only", StringComparison.Ordinal), "Full validation should document compile-only default.");

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
