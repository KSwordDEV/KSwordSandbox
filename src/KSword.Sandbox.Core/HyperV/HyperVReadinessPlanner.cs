using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.HyperV;

/// <summary>
/// Builds read-only readiness checks for the local Hyper-V host.
/// Inputs are typed sandbox configuration; processing emits non-mutating
/// runbook steps; the method returns checks for live-analysis preflight.
/// </summary>
public sealed class HyperVReadinessPlanner
{
    /// <summary>
    /// Creates read-only readiness steps for the configured golden VM.
    /// The input is sandbox config, processing creates command records, and the
    /// method returns a list of SandboxRunbookStep values.
    /// </summary>
    public IReadOnlyList<SandboxRunbookStep> BuildChecks(SandboxConfig config)
    {
        var catalog = new HyperVCommandCatalog();
        return
        [
            new SandboxRunbookStep
            {
                Id = "readiness.hyperv-module",
                Title = "Verify Hyper-V PowerShell module",
                PowerShell = "Get-Command Get-VM | Out-Null",
                MutatesVmState = false
            },
            new SandboxRunbookStep
            {
                Id = "readiness.golden-vm",
                Title = "Verify configured golden VM",
                PowerShell = catalog.GetVm(config.HyperV.GoldenVmName),
                MutatesVmState = false
            }
        ];
    }
}
