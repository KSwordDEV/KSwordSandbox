using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the script-level Hyper-V E2E contract without invoking Hyper-V.
/// Inputs are repository text files; processing checks safe defaults, live gates,
/// and collection/cleanup steps; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class HyperVE2EContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "hyperv.e2e.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var invokeScript = ReadRepositoryText(context, "scripts", "Invoke-HyperVE2E.ps1");
        var startScript = ReadRepositoryText(context, "scripts", "Start-SandboxHyperVJob.ps1");
        var collectScript = ReadRepositoryText(context, "scripts", "Collect-GuestOutputs.ps1");
        var e2eDoc = ReadRepositoryText(context, "docs", "hyperv-e2e-runbook.md");
        var goldenDoc = ReadRepositoryText(context, "docs", "golden-vm.md");

        RequireContains(invokeScript, "SupportsShouldProcess", "Top-level script should support -WhatIf/-Confirm semantics.");
        RequireContains(invokeScript, "PlanOnly", "Top-level script should expose/default to PlanOnly behavior.");
        RequireContains(invokeScript, "WhatIfPreference", "Top-level script should treat -WhatIf as non-mutating.");
        RequireContains(invokeScript, "-WhatIf:$false", "Top-level script should still write the review plan when -WhatIf is used.");
        RequireContains(invokeScript, "willMutateVm", "Plan JSON should state whether VM mutation will occur.");
        RequireContains(invokeScript, "ConvertTo-Json -Depth 12", "Top-level script should write a complete plan JSON.");
        RequireContains(invokeScript, "Start-SandboxHyperVJob.ps1", "Top-level script should delegate live start work.");
        RequireContains(invokeScript, "Collect-GuestOutputs.ps1", "Top-level script should delegate collection and cleanup.");
        RequireContains(invokeScript, "Invoke-ChildPowerShellScript", "Top-level script should run child scripts out-of-process so child exit statements cannot skip aggregate persistence.");
        RequireContains(invokeScript, "launchedOutOfProcess", "Top-level script should record child process launch evidence in runbook-execution.json.");
        RequireContains(invokeScript, "startInvocation", "Top-level script should persist start child stdout/stderr/exit metadata.");
        RequireContains(invokeScript, "collectInvocation", "Top-level script should persist collect child stdout/stderr/exit metadata.");
        RequireContains(invokeScript, "New-HyperVE2EStep", "Top-level plan should model ordered progress stages/steps.");
        RequireContains(invokeScript, "phase", "Top-level plan should tag each step with a phase for operator progress.");
        RequireContains(invokeScript, "phaseResults", "Runbook execution record should persist per-phase progress results.");
        RequireContains(invokeScript, "TotalSteps", "Runbook execution record should persist total planned steps.");
        RequireContains(invokeScript, "ExecutedSteps", "Runbook execution record should persist executed step count.");
        RequireContains(invokeScript, "StepResults", "Runbook execution record should persist per-step progress results.");
        RequireContains(invokeScript, "Convert-PhaseStepsToRunbookStepResults", "Top-level script should merge child phase steps into runbook progress.");
        SmokeAssert.True(!invokeScript.Contains("& $startScript -PlanPath", StringComparison.Ordinal), "Top-level script should not dot/call the start script in-process because exit 1 bypasses aggregate runbook persistence.");
        SmokeAssert.True(!invokeScript.Contains("& $collectScript -PlanPath", StringComparison.Ordinal), "Top-level script should not dot/call the collect script in-process because exit 1 bypasses aggregate runbook persistence.");
        RequireContains(invokeScript, "Test-IsAdministrator", "Top-level live mode should require an elevated shell.");
        RequireContains(invokeScript, "RestoreCheckpointAfterRun", "Plan should model final checkpoint restore behavior.");

        RequireContains(startScript, "SupportsShouldProcess", "Start script should support -WhatIf/-Confirm semantics.");
        RequireContains(startScript, "Restore-VMSnapshot", "Start script should restore the clean checkpoint only in live mode.");
        RequireContains(startScript, "Start-VM", "Start script should start the restored VM in live mode.");
        RequireContains(startScript, "Copy-VMFile", "Start script should copy the sample through Guest Service Interface.");
        RequireContains(startScript, "Copy-Item -ToSession", "Start script should stage payload through PowerShell Direct.");
        RequireContains(startScript, "New-PSSession -VMName", "Start script should use VM PowerShell Direct sessions.");
        RequireContains(startScript, "Start-Process", "Start script should launch Guest Agent asynchronously.");
        RequireContains(startScript, "--r0collector", "Start script should pass R0Collector sidecar arguments when enabled.");
        RequireContains(startScript, "Guest password environment variable", "Start script should load but not print the guest secret.");
        RequireContains(startScript, "No VM command was executed", "Start script should document safe failure before live mutation.");
        RequireContains(startScript, "Start phase failed after VM mutation", "Start script should attempt stop/restore cleanup after partial live mutation.");
        RequireContains(startScript, "cleanupErrors", "Start script should persist cleanup failures for operators.");
        RequireContains(startScript, "StepResults", "Start script should persist per-step progress for the parent runbook record.");
        RequireContains(startScript, "phase = 'start'", "Start script should label its result as the start phase.");

        RequireContains(collectScript, "SupportsShouldProcess", "Collect script should support -WhatIf/-Confirm semantics.");
        RequireContains(collectScript, "Copy-Item -FromSession", "Collect script should pull artifacts from the guest session.");
        RequireContains(collectScript, "agent.pid", "Collect script should wait on the guest agent pid marker.");
        RequireContains(collectScript, "agent.exit", "Collect script should validate the guest agent exit marker.");
        RequireContains(collectScript, "driver-events.jsonl", "Collect script should preserve driver/R0 JSONL artifacts.");
        RequireContains(collectScript, "Stop-VM", "Collect script should power off the VM during cleanup.");
        RequireContains(collectScript, "Restore-VMSnapshot", "Collect script should restore the clean checkpoint after cleanup.");
        RequireContains(collectScript, "finally", "Collect script should attempt cleanup after collection failures.");
        RequireContains(collectScript, "No VM command was executed", "Collect script should document safe no-live behavior.");
        RequireContains(collectScript, "StepResults", "Collect script should persist per-step progress for the parent runbook record.");
        RequireContains(collectScript, "phase = 'collect'", "Collect script should label its result as the collect phase.");

        RequireContains(e2eDoc, "default mode is `PlanOnly`", "E2E runbook should document safe default mode.");
        RequireContains(e2eDoc, "-WhatIf", "E2E runbook should document WhatIf safety.");
        RequireContains(e2eDoc, "-Live", "E2E runbook should document explicit live mode.");
        RequireContains(e2eDoc, "willMutateVm=false", "E2E runbook should tell reviewers how to confirm no mutation.");
        RequireContains(e2eDoc, "Copy-Item -FromSession", "E2E runbook should describe artifact collection.");
        RequireContains(e2eDoc, "restores the clean checkpoint again", "E2E runbook should describe final restore.");
        RequireContains(e2eDoc, "Test-HyperVReadiness.ps1", "E2E runbook should point to the standalone readiness helper.");
        RequireContains(e2eDoc, "Test-RepositoryPolicy.ps1 -StagedOnly", "E2E runbook should include a staged repository policy check.");
        RequireContains(e2eDoc, "PromptForMissingGuestPassword", "E2E runbook should document the process-only readiness password prompt.");
        RequireContains(e2eDoc, "runbook-execution.json", "E2E runbook should document the persisted progress record.");
        RequireContains(e2eDoc, "phase result paths", "E2E runbook should document per-phase progress result paths.");
        RequireContains(e2eDoc, "skipped/executed step records", "E2E runbook should document skipped/executed step records.");
        RequireContains(goldenDoc, "One-command Hyper-V E2E script", "Golden VM doc should point to the one-command E2E script.");
        RequireContains(goldenDoc, "Use `-WhatIf`", "Golden VM doc should remind operators that WhatIf is non-mutating.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Hyper-V E2E scripts are gated, plan-first, and documented."
        });
    }

    /// <summary>
    /// Reads a repository file as text. Inputs are the smoke context and relative
    /// path segments; processing checks existence and reads the full file; the
    /// method returns file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] segments)
    {
        var allSegments = new string[segments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        Array.Copy(segments, 0, allSegments, 1, segments.Length);
        var path = Path.Combine(allSegments);
        SmokeAssert.True(File.Exists(path), $"Required Hyper-V E2E contract file is missing: {path}");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires one literal to appear in a text block. Inputs are the content,
    /// expected literal, and assertion message; processing uses ordinal matching;
    /// the method returns no value when the check passes.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
