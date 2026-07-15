using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.Core.Pipeline;

namespace KSword.Sandbox.Core.Pipeline.Stages;

/// <summary>
/// Plans provider-specific VM work after a sample identity has been computed.
/// Inputs are pipeline context with Config and Sample; processing calls the
/// runbook builder; the stage returns after context.Runbook is populated.
/// </summary>
public sealed class RunbookPlanningStage : IAnalysisPipelineStage
{
    private readonly HyperVRunbookBuilder builder = new();

    public string StageId => "virtualization.runbook.plan";

    public string Title => "Plan virtual machine analysis runbook";

    /// <inheritdoc />
    public Task ExecuteAsync(AnalysisPipelineContext context, CancellationToken cancellationToken = default)
    {
        var provider = context.Submission.Provider ?? context.Config.Virtualization.Provider;
        VirtualizationProviderResourceValidator.Validate(
            context.Config,
            provider,
            context.Submission.GoldenSnapshotName,
            context.Submission.MachineDefinitionPath,
            context.Submission.QemuDiskFormat);
        var config = ApplySubmissionOverrides(context.Config, context.Submission);
        context.Runbook = builder.Build(
            config,
            context.JobId,
            context.Sample ?? throw new InvalidOperationException("Sample identity is required before runbook planning."));
        return Task.CompletedTask;
    }

    /// <summary>
    /// Applies provider, VM, guest, and artifact overrides to the stage config.
    /// Inputs are the pipeline defaults and submission overrides; processing
    /// mirrors the job-service planning surface; the method returns the config
    /// used by the provider runbook builder.
    /// </summary>
    private static SandboxConfig ApplySubmissionOverrides(SandboxConfig config, SandboxSubmission submission)
    {
        var provider = submission.Provider ?? config.Virtualization.Provider;
        return config with
        {
            Virtualization = config.Virtualization with { Provider = provider },
            HyperV = config.HyperV with
            {
                GoldenVmName = CleanOptional(submission.GoldenVmName) ?? config.HyperV.GoldenVmName,
                GoldenSnapshotName = CleanOptional(submission.GoldenSnapshotName) ?? config.HyperV.GoldenSnapshotName
            },
            VMware = config.VMware with
            {
                VmName = CleanOptional(submission.GoldenVmName) ?? config.VMware.VmName,
                SnapshotName = CleanOptional(submission.GoldenSnapshotName) ?? config.VMware.SnapshotName,
                VmxPath = provider is VirtualizationProvider.VMware
                    ? CleanOptional(submission.MachineDefinitionPath) ?? config.VMware.VmxPath
                    : config.VMware.VmxPath
            },
            Qemu = config.Qemu with
            {
                VmName = CleanOptional(submission.GoldenVmName) ?? config.Qemu.VmName,
                SnapshotName = CleanOptional(submission.GoldenSnapshotName) ?? config.Qemu.SnapshotName,
                DiskImagePath = provider is VirtualizationProvider.Qemu
                    ? CleanOptional(submission.MachineDefinitionPath) ?? config.Qemu.DiskImagePath
                    : config.Qemu.DiskImagePath,
                DiskFormat = provider is VirtualizationProvider.Qemu
                    ? CleanOptional(submission.QemuDiskFormat)?.ToLowerInvariant() ?? config.Qemu.DiskFormat
                    : config.Qemu.DiskFormat
            },
            Guest = config.Guest with
            {
                UserName = CleanOptional(submission.GuestUserName) ?? config.Guest.UserName,
                WorkingDirectory = CleanOptional(submission.GuestWorkingDirectory) ?? config.Guest.WorkingDirectory
            },
            Paths = config.Paths with
            {
                GuestPayloadRoot = CleanOptional(submission.GuestPayloadRoot) ?? config.Paths.GuestPayloadRoot
            },
            Driver = config.Driver with
            {
                UseMockCollector = submission.UseMockCollector ?? config.Driver.UseMockCollector
            },
            ArtifactCollection = config.ArtifactCollection with
            {
                CollectDroppedFiles = submission.CollectDroppedFiles ?? config.ArtifactCollection.CollectDroppedFiles,
                CaptureScreenshots = submission.CaptureScreenshots ?? config.ArtifactCollection.CaptureScreenshots,
                CaptureMemoryDumps = submission.CaptureMemoryDumps ?? config.ArtifactCollection.CaptureMemoryDumps,
                CapturePacketCapture = submission.CapturePacketCapture ?? config.ArtifactCollection.CapturePacketCapture
            },
            Analysis = config.Analysis with
            {
                GuestReadyTimeoutSeconds = submission.GuestReadyTimeoutSeconds is > 0
                    ? Math.Clamp(submission.GuestReadyTimeoutSeconds.Value, 1, 7200)
                    : config.Analysis.GuestReadyTimeoutSeconds
            }
        };
    }

    private static string? CleanOptional(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
