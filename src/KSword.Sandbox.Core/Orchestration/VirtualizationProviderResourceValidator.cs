using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Orchestration;

/// <summary>
/// Validates per-job provider resource overrides before a runbook is built.
/// This keeps Web/API and pipeline submissions from silently ignoring fields
/// that belong to another provider.
/// </summary>
public static class VirtualizationProviderResourceValidator
{
    public static void Validate(
        SandboxConfig config,
        VirtualizationProvider provider,
        string? baselineName,
        string? machineDefinitionPath,
        string? qemuDiskFormat)
    {
        ArgumentNullException.ThrowIfNull(config);

        var hasMachineDefinition = !string.IsNullOrWhiteSpace(machineDefinitionPath);
        var hasQemuDiskFormat = !string.IsNullOrWhiteSpace(qemuDiskFormat);
        if (provider is VirtualizationProvider.HyperV && hasMachineDefinition)
        {
            throw new ArgumentException(
                "HyperV does not accept a machine-definition path override; select the Hyper-V VM by name.",
                nameof(machineDefinitionPath));
        }

        if (provider is not VirtualizationProvider.Qemu && hasQemuDiskFormat)
        {
            throw new ArgumentException(
                $"QEMU disk format overrides apply only to Qemu, not {provider}.",
                nameof(qemuDiskFormat));
        }

        if (provider is VirtualizationProvider.Qemu &&
            config.Qemu.UseOverlayDisk &&
            !string.IsNullOrWhiteSpace(baselineName) &&
            !baselineName.Trim().Equals("per-job-overlay", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "QEMU overlay mode does not accept an internal snapshot baseline override; omit it or use 'per-job-overlay'.",
                nameof(baselineName));
        }
    }
}
