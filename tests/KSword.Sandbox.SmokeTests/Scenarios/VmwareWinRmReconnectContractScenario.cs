using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the narrow VMware WinRM reconnect contract without starting a VM.
/// </summary>
internal sealed class VmwareWinRmReconnectContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "vmware.winrm-reconnect.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var executor = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Execution", "PowerShellRunbookExecutor.cs"));
        var builder = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Orchestration", "HyperVRunbookBuilder.cs"));

        Require(executor, "ShouldRetryVmwareRunAgent", "VMware run-agent must have an explicit reconnect policy.");
        Require(executor, "runbook.Provider is not VirtualizationProvider.VMware", "Reconnect policy must be scoped to VMware.");
        Require(executor, "result.ExitCode is not 2", "Reconnect policy must reject unrelated PowerShell exit codes.");
        Require(executor, "EndRootElement", "Reconnect policy must recognize the malformed remoting XML failure.");
        Require(executor, "网络连接已中断", "Reconnect policy must recognize the localized network interruption emitted by WinRM.");
        Require(executor, "MergeTransientVmwareRetryResult", "The first failed attempt must remain in the retry diagnostic.");
        Require(executor, "Task.Delay(TimeSpan.FromSeconds(3)", "Reconnect retry must back off before creating a fresh session.");
        Require(executor, "KSWORDBOX_AGENT_MARKERS_PRESENT", "Retry must honor the guest marker-preservation handshake.");

        Require(builder, "$existingEvents = Test-Path", "Guest launch must check events.json before retrying.");
        Require(builder, "$existingExit = Test-Path", "Guest launch must check agent.exit before retrying.");
        Require(builder, "$existingPidFile = Test-Path", "Guest launch must preserve any existing agent.pid marker before retrying.");
        Require(builder, "Get-Process -Id $existingPid", "Guest launch must preserve a still-running Agent process.");
        Require(builder, "KSWORDBOX_AGENT_MARKERS_PRESENT", "Guest launch must report preserved markers to the host executor.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "VMware WinRM EndRootElement failures retry once with idempotent guest-marker preservation and retained diagnostics."
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
