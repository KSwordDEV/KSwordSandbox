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
        Require(executor, "ShouldAttemptVmwareRecoveryStep", "VMware run-agent failures must attempt post-failure evidence recovery.");
        Require(executor, "VMware evidence recovery", "Recovery progress must remain visible before cleanup.");
        Require(executor, "AnnotateVmwareRecoveryFailure", "Unavailable WinRM/guest markers must produce an explicit recovery diagnostic.");
        Require(executor, "sync-live-output", "Recovery must include live output synchronization.");
        Require(executor, "collect-output", "Recovery must include final guest output collection.");
        Require(executor, "sink.Report(snapshot)", "Progress should still be published through the configured sink.");
        Require(executor, "Progress persistence is an observer", "A progress sink failure must not strand a mutated VM before cleanup.");
        Require(executor, "MaxEncodedCommandChars", "Long VMware runbook scripts must avoid the Windows PowerShell argument limit.");
        Require(executor, "startInfo.ArgumentList.Add(\"-File\")", "Oversized PowerShell scripts must be launched from a temporary file.");

        Require(builder, "$existingEvents = Test-Path", "Guest launch must check events.json before retrying.");
        Require(builder, "$existingExit = Test-Path", "Guest launch must check agent.exit before retrying.");
        Require(builder, "$existingPidFile = Test-Path", "Guest launch must preserve any existing agent.pid marker before retrying.");
        Require(builder, "Get-Process -Id $existingPid", "Guest launch must preserve a still-running Agent process.");
        Require(builder, "$existingTaskRunning", "Guest launch must preserve a still-running scheduled fallback task before reconnecting.");
        Require(builder, "KSWORDBOX_AGENT_MARKERS_PRESENT", "Guest launch must report preserved markers to the host executor.");
        Require(builder, "$interactiveStopDeadline", "WinRM fallback must wait for an interactive task to stop before starting S4U.");
        Require(builder, "refusing to start the S4U fallback", "WinRM fallback must fail closed if the interactive task cannot be stopped safely.");
        Require(builder, "$fallbackDeadline=(Get-Date).AddSeconds(60)", "S4U marker wait must allow guest payload launch time beyond the sample collection window.");

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
