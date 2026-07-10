using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the static Hyper-V readiness preflight contract without invoking
/// Hyper-V. Inputs are repository paths from SmokeTestContext; processing reads
/// only scripts and docs; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class HyperVReadinessContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "hyperv.readiness.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var readinessScript = ReadRepositoryText(context, "scripts", "Test-HyperVReadiness.ps1");
        var repositoryPolicyScript = ReadRepositoryText(context, "scripts", "Test-RepositoryPolicy.ps1");
        var payloadScript = ReadRepositoryText(context, "scripts", "Prepare-GuestPayload.ps1");
        var readinessDoc = ReadRepositoryText(context, "docs", "hyperv-readiness.md");
        var goldenVmDoc = ReadRepositoryText(context, "docs", "golden-vm.md");
        var runbookDoc = ReadRepositoryText(context, "docs", "hyperv-runbook.md");
        var payloadDoc = ReadRepositoryText(context, "docs", "guest-payload-staging.md");

        RequireContains(readinessScript, "Test-HostPayloadFiles", "Readiness script should check host payload files.");
        RequireContains(readinessScript, "Test-PowerShellDirectReadOnly", "Readiness script should check PowerShell Direct without mutation.");
        RequireContains(readinessScript, "Test-GuestPayloadFilesReadOnly", "Readiness script should check guest payload files when PowerShell Direct passes.");
        RequireContains(readinessScript, "Invoke-Command", "Readiness script should use PowerShell Direct for the live guest probe.");
        RequireContains(readinessScript, "read-only preflight will not start it", "Readiness script should diagnose an off VM without starting it.");
        RequireContains(readinessScript, "MutatedVm", "Readiness output should explicitly mark non-mutating probes.");
        RequireContains(readinessScript, "GuestPayloadRoot", "Readiness summary should include the host payload root.");
        RequireContains(readinessScript, "Details.Contains('State')", "Readiness script should read VM state from readiness detail dictionaries.");
        RequireContains(readinessScript, "Resolve-ReadinessInputConfiguration", "Readiness should reuse install/run local config when no explicit parameters are provided.");
        RequireContains(readinessScript, "PromptForMissingGuestPassword", "Readiness should offer an opt-in process-only password prompt.");
        RequireContains(readinessScript, "Guest working directory", "Readiness should validate the configured guest working directory.");
        RequireContains(readinessScript, "Repository secret hygiene", "Readiness should guard against committing the current guest password value.");
        RequireContains(readinessScript, "SecretValuePrinted = $false", "Readiness should explicitly avoid printing password values.");

        RequireContains(repositoryPolicyScript, "SecretEnvironmentNames", "Repository policy should scan configured environment secrets.");
        RequireContains(repositoryPolicyScript, "Secret value from environment variable", "Repository policy should reject current secret values in candidate files.");
        RequireContains(repositoryPolicyScript, "Value was not printed", "Repository policy should not print rejected secret values.");

        RequireContains(payloadScript, "payloadContractVersion", "Payload manifest should expose a contract version.");
        RequireContains(payloadScript, "payloadContractVersion = 2", "Payload manifest should expose the current freshness-aware contract version.");
        RequireContains(payloadScript, "generatedAtUtc", "Payload manifest should record when the payload was generated.");
        RequireContains(payloadScript, "repositoryHead", "Payload manifest should record the repository head used for staging.");
        RequireContains(payloadScript, "sourceFingerprint", "Payload manifest should record a source freshness fingerprint.");
        RequireContains(payloadScript, "sourceLatestWriteUtc", "Payload manifest should record the newest source input timestamp.");
        RequireContains(payloadScript, "requiredHostFiles", "Payload manifest should list readiness-required host files.");
        RequireContains(payloadScript, "expectedGuestAgentPath", "Payload manifest should record the expected guest agent path.");
        RequireContains(payloadScript, "expectedR0CollectorPath", "Payload manifest should record the expected guest R0Collector path.");
        RequireContains(payloadScript, "Assert-StagedPayloadFile", "Payload preparation should verify staged executable outputs.");

        RequireContains(readinessDoc, "Host payload files", "Readiness doc should describe host payload checks.");
        RequireContains(readinessDoc, "PowerShell Direct", "Readiness doc should describe PowerShell Direct checks.");
        RequireContains(readinessDoc, "Guest deployed payload files", "Readiness doc should describe guest payload checks.");
        RequireContains(readinessDoc, "does not start the VM", "Readiness doc should state that off VMs are not started.");
        RequireContains(readinessDoc, "Readiness input resolution", "Readiness doc should describe install/run config resolution.");
        RequireContains(readinessDoc, "Repository secret hygiene", "Readiness doc should describe no-secret-in-git checks.");
        RequireContains(goldenVmDoc, "Readiness preflight", "Golden VM doc should reference the readiness preflight.");
        RequireContains(runbookDoc, "The preflight is intentionally safer than the live runbook", "Runbook doc should distinguish preflight from live execution.");
        RequireContains(runbookDoc, "PromptForMissingGuestPassword", "Runbook doc should document the process-only password prompt.");
        RequireContains(readinessDoc, "payload freshness", "Readiness doc should explain how to evaluate payload freshness.");
        RequireContains(readinessDoc, "generatedAtUtc", "Readiness doc should mention the payload manifest generation timestamp.");
        RequireContains(readinessDoc, "sourceFingerprint", "Readiness doc should mention the payload manifest source fingerprint.");
        RequireContains(payloadDoc, "payload contract version", "Payload staging doc should mention manifest contract metadata.");
        RequireContains(payloadDoc, "Payload manifest freshness", "Payload staging doc should include freshness validation guidance.");
        RequireContains(payloadDoc, "sourceLatestWriteUtc", "Payload staging doc should explain source freshness timestamps.");
        RequireContains(payloadDoc, "repositoryHead", "Payload staging doc should explain repository-head freshness checks.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Hyper-V readiness and payload staging contracts are documented."
        });
    }

    /// <summary>
    /// Reads a repository file as text.
    /// Inputs are the smoke context and relative path segments; processing joins
    /// the path under RepositoryRoot and reads the file; the method returns the
    /// complete file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var allSegments = new string[relativeSegments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        relativeSegments.CopyTo(allSegments, 1);
        var path = Path.Combine(allSegments);
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires that a text block contains a literal value.
    /// Inputs are text, expected literal, and assertion message; processing uses
    /// ordinal substring matching; the method returns no value on success.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
