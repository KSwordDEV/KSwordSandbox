using KSword.Sandbox.Abstractions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the VMware host output share contract: when the share is enabled the
/// guest writes evidence straight into the host job folder, so a sample that
/// takes the WinRM listener down no longer discards the run.
/// </summary>
internal sealed class VmwareHostOutputShareContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "vmware.host-output-share.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var models = Read(context, Path.Combine("src", "KSword.Sandbox.Abstractions", "ConfigurationModels.cs"));
        var builder = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Orchestration", "HyperVRunbookBuilder.cs"));
        var facts = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Execution", "RunbookProgressFacts.cs"));

        Require(models, "public bool UseHostOutputShare { get; init; }", "VMware needs an explicit opt-in for the host output share.");
        Require(models, "public string OutputShareName { get; init; } = \"KSwordOutput\";", "The share needs a stable default name.");

        Require(builder, "provider is not VirtualizationProvider.VMware || !config.VMware.UseHostOutputShare", "The share must stay provider-specific and opt-in.");
        Require(builder, "$\"\\\\\\\\vmware-host\\\\Shared Folders\\\\{hostOutputShare.Value.Name}\"", "The guest output directory must point at the shared folder.");
        Require(builder, "\"enable-vmware-output-share\"", "The runbook must plan the host output share mapping.");
        Require(builder, "vmrun enableSharedFolders failed", "A failed shared-folder enable must fail the run loudly.");
        Require(builder, "vmrun addSharedFolder failed", "A failed mapping must fail the run loudly.");
        Require(builder, "No previous '$shareName' mapping had to be removed", "A stale mapping from an earlier job must be replaced, not reused.");
        Require(builder, "Shared folder mapping '$shareName' removed", "Cleanup must drop the mapping because a snapshot revert keeps the VMX.");
        Require(builder, "live remoting sync is not required", "Live sync must not open a WinRM session when the guest already writes to the host.");
        Require(builder, "run is incomplete: status=$statusState", "A killed Guest Agent must degrade the shared-folder collection instead of discarding the run.");
        Require(builder, "Write-Warning \\\"Guest output reached the host folder", "Incomplete shared-folder collection must stay a visible warning.");
        Require(builder, "collectionChannel = 'vmware-shared-folder'", "The report must be able to state which channel produced the evidence.");

        // The Agent serializes its output only after the sample window closes,
        // and its post-run probes are separately bounded. Observed on
        // Win32.Emotet: a duration+30s host budget expired 0.8s before
        // agent.exit landed, so a complete run was reported incomplete.
        Require(builder, "config.Analysis.DefaultDurationSeconds + 150", "The host wait budget must cover the Agent's post-run probe and ETW decode time, not just the sample window.");
        Require(builder, "if (-not (Test-Path -LiteralPath (Join-Path $hostOut 'agent.exit') -PathType Leaf)) { Start-Sleep -Seconds 2 }", "The artifact set must be re-read after agent.exit appears, because shared-folder writes can lag the check.");

        Require(facts, "\"enable-vmware-output-share\" => \"guest-prepare\"", "The new step needs a runbook phase.");
        Require(facts, "\"enable-vmware-output-share\" => \"guest-output-share\"", "The new step needs an operator-facing category.");
        Require(facts, "共享目录让来宾证据不再依赖 WinRM", "The new step needs a Chinese remediation hint.");

        // Opt-in must not change the default live runbook.
        var defaultConfig = new VMwareConfig();
        SmokeAssert.True(!defaultConfig.UseHostOutputShare, "The host output share must stay off by default.");
        SmokeAssert.True(defaultConfig.OutputShareName == "KSwordOutput", "The default share name must be stable.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "VMware can map the host job output folder into the guest as a shared folder, so guest evidence survives a killed WinRM listener."
        });
    }

    private static string Read(SmokeTestContext context, string path)
    {
        var fullPath = Path.Combine(context.RepositoryRoot, path);
        SmokeAssert.True(File.Exists(fullPath), $"Required source file was not found: {path}");
        return File.ReadAllText(fullPath);
    }

    private static void Require(string source, string needle, string message)
    {
        SmokeAssert.True(source.Contains(needle, StringComparison.Ordinal), message);
    }
}