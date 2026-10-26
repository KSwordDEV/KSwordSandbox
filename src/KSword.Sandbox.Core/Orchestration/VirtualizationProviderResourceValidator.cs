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
        string? qemuDiskFormat,
        SandboxNetworkPolicy networkPolicy)
    {
        ArgumentNullException.ThrowIfNull(config);

        // Channel matrix for network policy Block (device-level guest NIC
        // disable): Hyper-V keeps PowerShell Direct over the VMBus, so guest
        // collection never rides the guest network. VMware uses VMware Tools
        // guest operations to pull evidence without a shared folder. QEMU has
        // no network-independent evidence channel because
        // guest remoting uses localhost WinRM forwarding into the guest
        // network, so Block must be refused loudly instead of silently
        // collecting nothing.
        if (provider is VirtualizationProvider.Qemu && networkPolicy is SandboxNetworkPolicy.Block)
        {
            throw new ArgumentException(
                "Network policy 'Block' disables the guest network adapters, but QEMU guest collection depends on guest network connectivity (localhost WinRM forwarding). Select network policy 'Allow' for QEMU, or use Hyper-V (PowerShell Direct) / VMware with VMware Tools guest operations, which keep a network-independent evidence channel.",
                nameof(networkPolicy));
        }

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
