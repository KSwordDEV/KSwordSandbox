using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Guest;

namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Builds a manifest for files copied into the guest VM before execution.
/// Inputs are sandbox config, job ID, and sample identity; processing computes
/// stable guest paths; the method returns a payload manifest.
/// </summary>
public sealed class GuestPayloadManifestBuilder
{
    /// <summary>
    /// Creates a manifest for sample, agent, and optional R0 collector paths.
    /// Inputs are config, job ID, and sample metadata; processing joins guest
    /// path segments; the method returns GuestPayloadManifest.
    /// </summary>
    public GuestPayloadManifest Build(SandboxConfig config, Guid jobId, SampleIdentity sample)
    {
        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        return new GuestPayloadManifest
        {
            JobId = jobId,
            SampleGuestPath = $"{guestRoot}\\incoming\\{sample.FileName}",
            AgentGuestPath = $"{guestRoot}\\agent\\{config.Guest.AgentExecutableName}",
            R0CollectorGuestPath = config.Driver.Enabled ? config.Driver.R0CollectorPathInGuest : null
        };
    }
}
