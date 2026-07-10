using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the local driver signing handoff keeps the KswordARK CSignTool
/// chain available without allowing certificate/tool material into git.
/// </summary>
internal sealed class DriverSigningContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "driver.signing.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var scriptPath = Path.Combine(context.RepositoryRoot, "scripts", "Sign-SandboxDriverWithKswordCSignTool.ps1");
        var gitignorePath = Path.Combine(context.RepositoryRoot, ".gitignore");
        var docPath = Path.Combine(context.RepositoryRoot, "docs", "driver-signing.md");

        SmokeAssert.True(File.Exists(scriptPath), "Sandbox driver CSignTool signing script is missing.");
        SmokeAssert.True(File.Exists(gitignorePath), ".gitignore is missing.");
        SmokeAssert.True(File.Exists(docPath), "driver signing doc is missing.");

        var script = File.ReadAllText(scriptPath);
        SmokeAssert.True(script.Contains("CSignTool.exe", StringComparison.Ordinal), "Signing script should use CSignTool.");
        SmokeAssert.True(script.Contains("'sign', '/r', '1', '/f', $driver", StringComparison.Ordinal), "Signing script should keep the first CSignTool pass.");
        SmokeAssert.True(script.Contains("'sign', '/r', '1', '/f', $driver, '/ac'", StringComparison.Ordinal), "Signing script should keep the /ac CSignTool pass.");
        SmokeAssert.True(script.Contains("AuthenticodeVariantGUI.exe", StringComparison.Ordinal), "Signing script should support the Ksword Authenticode variant tool.");

        var gitignore = File.ReadAllText(gitignorePath);
        SmokeAssert.True(gitignore.Contains("/.cert/", StringComparison.Ordinal), ".cert directory must be ignored.");

        var doc = File.ReadAllText(docPath);
        SmokeAssert.True(doc.Contains("Sign-SandboxDriverWithKswordCSignTool.ps1", StringComparison.Ordinal), "Driver signing doc should mention the CSignTool wrapper.");
        SmokeAssert.True(doc.Contains(".cert", StringComparison.Ordinal), "Driver signing doc should explain the local ignored .cert directory.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Driver signing CSignTool contract is documented and git-ignored."
        });
    }
}
