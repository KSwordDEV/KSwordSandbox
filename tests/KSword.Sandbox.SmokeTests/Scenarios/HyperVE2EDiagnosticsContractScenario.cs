using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the script-level Hyper-V E2E failure-diagnostics contract without
/// invoking Hyper-V. Inputs are repository text files; processing checks that
/// failed live attempts persist UI-safe progress and importable guest-output
/// skeleton artifacts; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class HyperVE2EDiagnosticsContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "hyperv.e2e.diagnostics.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var invokeScript = ReadRepositoryText(context, "scripts", "Invoke-HyperVE2E.ps1");
        var startScript = ReadRepositoryText(context, "scripts", "Start-SandboxHyperVJob.ps1");
        var collectScript = ReadRepositoryText(context, "scripts", "Collect-GuestOutputs.ps1");
        var importScript = ReadRepositoryText(context, "scripts", "Import-HyperVJobReport.ps1");
        var operatorScript = ReadRepositoryText(context, "scripts", "Invoke-OperatorCli.ps1");
        var jobToolCommands = ReadRepositoryText(context, "tools", "KSword.Sandbox.JobTool", "JobToolCommands.cs");
        var jobToolHelpers = ReadRepositoryText(context, "tools", "KSword.Sandbox.JobTool", "JobToolHelpers.cs");
        var e2eDoc = ReadRepositoryText(context, "docs", "hyperv-e2e-runbook.md");
        var runnerDoc = ReadRepositoryText(context, "docs", "hyperv-runner.md");

        RequireContains(invokeScript, "Save-RunbookProgressSnapshot", "Top-level E2E script should persist runbook-progress.json sidecar files.");
        RequireContains(invokeScript, "runbook-progress.json", "Top-level E2E script should write the durable UI-safe progress sidecar.");
        RequireContains(invokeScript, "Save-GuestOutputSkeleton", "Top-level E2E script should generate importable guest output skeletons on failure.");
        RequireContains(invokeScript, "guest-output-skeleton.json", "Top-level E2E script should persist skeleton metadata.");
        RequireContains(invokeScript, "hyperv.e2e.failure_skeleton", "Skeleton events should be importable SandboxEvent rows.");
        RequireContains(invokeScript, "agent.exit", "Failure skeleton should include an agent.exit marker.");
        RequireContains(invokeScript, "agent.pid", "Failure skeleton should include an agent.pid marker.");
        RequireContains(invokeScript, "Importable guest output skeleton ready", "Top-level script should print the skeleton path for operators.");
        RequireContains(invokeScript, "凭据诊断", "Top-level preflight should present credential diagnostics in Chinese first.");
        RequireContains(invokeScript, "VM 诊断", "Top-level preflight should present VM diagnostics in Chinese first.");
        RequireContains(invokeScript, "Checkpoint 诊断", "Top-level preflight should present checkpoint diagnostics in Chinese first.");
        RequireContains(invokeScript, "Guest Service Interface 诊断", "Top-level preflight should present Guest Service Interface diagnostics.");
        RequireContains(invokeScript, "PowerShell Direct 诊断", "Top-level preflight should present PowerShell Direct diagnostics.");
        RequireContains(invokeScript, "secretValuePrinted", "Diagnostics must explicitly record that secret values are not printed.");
        RequireContains(invokeScript, "standardOutputLogPath", "Top-level E2E should persist child stdout/stderr log paths.");
        RequireContains(invokeScript, "hyperv-e2e-{0}.stdout.log", "Child PowerShell phases should write full stdout logs beside the job.");
        RequireContains(invokeScript, "hyperv-e2e-failure-report-import.json", "Live failure should leave an automatic report-import diagnostic result.");
        RequireContains(invokeScript, "Invoke-FailureReportImport", "Live failure should attempt a best-effort report rebuild from the failure skeleton.");
        RequireContains(invokeScript, "report-rebuild-diagnostics.json", "Top-level failure guidance should point operators at report rebuild diagnostics.");
        RequireContains(invokeScript, "无法解析，将写入 failure skeleton", "Top-level skeleton preservation should reject corrupt events.json.");

        RequireContains(startScript, "Guest password environment variable", "Start phase should diagnose missing guest password environment variables.");
        RequireContains(startScript, "Get-PowerShellDirectDiagnosticHint", "Start phase should classify PowerShell Direct failures.");
        RequireContains(startScript, "lastVmState", "Start phase PowerShell Direct heartbeat should capture the latest VM state.");
        RequireContains(startScript, "Save-GuestOutputSkeleton", "Start phase should generate skeleton output when run directly and failing.");
        RequireContains(startScript, "guest-output-skeleton.json", "Start phase should write skeleton metadata.");
        RequireContains(startScript, "6C09BB55-D683-4DA0-8931-C9BF705F6480", "Guest Service Interface diagnostics should use the stable integration-service component id.");
        RequireContains(startScript, "ConvertFrom-Json -ErrorAction Stop", "Start skeleton preservation should validate existing events.json before preserving it.");

        RequireContains(collectScript, "Get-CollectRemediationHints", "Collect phase should persist remediation hints.");
        RequireContains(collectScript, "PowerShell Direct 诊断失败", "Collect phase should identify New-PSSession/PowerShell Direct failures.");
        RequireContains(collectScript, "failureReason", "Collect phase result should persist a failure reason.");
        RequireContains(collectScript, "remediationHints", "Collect phase result should persist remediation hints.");
        RequireContains(collectScript, "Save-GuestOutputSkeleton", "Collect phase should generate skeleton output when collection fails.");
        RequireContains(collectScript, "validJson", "Collect phase should persist events.json parse validation in required artifact diagnostics.");
        RequireContains(collectScript, "eventCount", "Collect phase should persist event counts for events.json.");

        RequireContains(importScript, "Write-ImportGuestOutputSkeleton", "Import wrapper should generate a skeleton if events.json is missing but runbook-execution exists.");
        RequireContains(importScript, "hyperv.e2e.failure_skeleton", "Import-generated skeleton should contain an importable failure event.");
        RequireContains(importScript, "runbook-execution.json", "Import wrapper should use runbook-execution.json as the recovery source.");
        RequireContains(importScript, "未找到 events.json", "Import wrapper should print a Chinese-first missing-events diagnostic.");
        RequireContains(importScript, "report-rebuild-diagnostics.json", "Import wrapper should surface report rebuild diagnostics after JobTool import.");

        RequireContains(operatorScript, "rawOutput", "Operator CLI JSON failure envelopes should retain raw JobTool/dotnet output.");
        RequireContains(operatorScript, "willMutateVm = $false", "Operator CLI JobTool commands should explicitly report no VM mutation on failure.");
        RequireContains(operatorScript, "if (-not [string]::IsNullOrWhiteSpace($JobRoot)) { $extra += @('--job-root', $JobRoot) }", "Operator CLI import should forward -JobRoot to JobTool.");
        RequireContains(jobToolCommands, "EventInputResolution", "JobTool report/recover should expose event input resolution diagnostics.");
        RequireContains(jobToolHelpers, "generated-failure-skeleton", "JobTool should generate a failure skeleton when report rebuild has runbook-execution but no events.");
        RequireContains(jobToolHelpers, "report-rebuild-diagnostics.json", "JobTool should write a stable report rebuild diagnostics sidecar.");

        RequireContains(e2eDoc, "失败诊断与可导入 skeleton", "E2E runbook should document failure skeleton recovery.");
        RequireContains(e2eDoc, "runbook-progress.json", "E2E runbook should document the progress sidecar.");
        RequireContains(e2eDoc, "hyperv.e2e.failure_skeleton", "E2E runbook should document the skeleton event.");
        RequireContains(runnerDoc, "guest-output-skeleton.json", "Runner doc should document skeleton artifact locations.");
        RequireContains(runnerDoc, "不代表 Guest Agent 完整运行", "Runner doc should state skeleton output is diagnostic only.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Hyper-V E2E failure diagnostics persist progress and importable guest-output skeletons."
        });
    }

    /// <summary>
    /// Reads a repository file as text. Inputs are the smoke context and path
    /// segments; processing validates file existence; the method returns text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] segments)
    {
        var allSegments = new string[segments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        segments.CopyTo(allSegments, 1);
        var path = Path.Combine(allSegments);
        SmokeAssert.True(File.Exists(path), $"Required Hyper-V diagnostics contract file is missing: {path}");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires a literal to be present in a text block.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
