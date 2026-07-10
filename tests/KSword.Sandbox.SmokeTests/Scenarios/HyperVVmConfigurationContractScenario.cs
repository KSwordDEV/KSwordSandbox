using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that VM and guest configuration fields are present from the public
/// config sample through WebUI job submission normalization and Hyper-V runbook
/// planning. Inputs are repository source files only; processing performs
/// static contract checks without invoking Hyper-V; the scenario returns
/// pass/fail metadata.
/// </summary>
internal sealed class HyperVVmConfigurationContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "hyperv.vm-configuration.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var configSample = ReadRepositoryText(context, "config", "sandbox.example.json");
        var configModel = ReadRepositoryText(context, "src", "KSword.Sandbox.Abstractions", "ConfigurationModels.cs");
        var submissionModel = ReadRepositoryText(context, "src", "KSword.Sandbox.Abstractions", "AnalysisModels.cs");
        var jobService = ReadRepositoryText(context, "src", "KSword.Sandbox.Core", "Jobs", "SandboxJobService.cs");
        var runbookBuilder = ReadRepositoryText(context, "src", "KSword.Sandbox.Core", "Orchestration", "HyperVRunbookBuilder.cs");

        foreach (var jsonField in new[]
        {
            "goldenVmName",
            "goldenSnapshotName",
            "tempVmPrefix",
            "switchName",
            "useDifferencingDisk",
            "baseVhdxPath",
            "memoryStartupBytes",
            "userName",
            "workingDirectory",
            "guestPayloadRoot",
            "useMockCollector"
        })
        {
            RequireContains(configSample, jsonField, $"sandbox.example.json should expose VM/guest configuration field '{jsonField}'.");
        }

        foreach (var typedField in new[]
        {
            "GoldenVmName",
            "GoldenSnapshotName",
            "TempVmPrefix",
            "SwitchName",
            "UseDifferencingDisk",
            "BaseVhdxPath",
            "MemoryStartupBytes",
            "UserName",
            "WorkingDirectory",
            "GuestPayloadRoot",
            "UseMockCollector"
        })
        {
            RequireContains(configModel, typedField, $"SandboxConfig model should expose VM/guest field '{typedField}'.");
        }

        foreach (var overrideField in new[]
        {
            "GoldenVmName",
            "GoldenSnapshotName",
            "GuestUserName",
            "GuestWorkingDirectory",
            "GuestPayloadRoot",
            "UseMockCollector"
        })
        {
            RequireContains(submissionModel, overrideField, $"SandboxSubmission should carry per-job VM override '{overrideField}'.");
            RequireContains(jobService, overrideField, $"SandboxJobService should preserve per-job VM override '{overrideField}'.");
        }

        RequireContains(jobService, "NormalizeSubmission", "Job planning should normalize optional VM fields before persistence.");
        RequireContains(jobService, "BuildJobConfig", "Job planning should build a per-job config from VM overrides.");
        RequireContains(runbookBuilder, "config.HyperV.GoldenVmName", "Runbook builder should use the configured golden VM name.");
        RequireContains(runbookBuilder, "config.HyperV.GoldenSnapshotName", "Runbook builder should use the configured golden snapshot.");
        RequireContains(runbookBuilder, "config.HyperV.UseDifferencingDisk", "Runbook builder should honor differencing-disk mode.");
        RequireContains(runbookBuilder, "config.HyperV.SwitchName", "Runbook builder should honor the configured virtual switch.");
        RequireContains(runbookBuilder, "config.HyperV.MemoryStartupBytes", "Runbook builder should honor configured memory startup bytes.");
        RequireContains(runbookBuilder, "config.Guest.UserName", "Runbook builder should use the configured guest user.");
        RequireContains(runbookBuilder, "config.Guest.WorkingDirectory", "Runbook builder should use the configured guest working directory.");
        RequireContains(runbookBuilder, "config.Paths.GuestPayloadRoot", "Runbook builder should use the configured host guest payload root.");
        RequireContains(runbookBuilder, "config.Driver.UseMockCollector", "Runbook builder should honor mock collector configuration.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Hyper-V VM/guest configuration fields are present from config through runbook planning."
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
        SmokeAssert.True(File.Exists(path), $"Required Hyper-V VM configuration contract file is missing: {path}");
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
