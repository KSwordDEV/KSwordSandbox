using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Guest;

namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Plans guest and host output paths for one sandbox job.
/// Inputs are sandbox configuration and job metadata; processing keeps guest
/// paths job-specific; methods return manifests consumed by runbook builders.
/// </summary>
public sealed class GuestPathPlanner
{
    /// <summary>
    /// Creates a guest output manifest for one job.
    /// Inputs are config and job ID, processing derives guest and host folders,
    /// and the method returns a GuestOutputManifest.
    /// </summary>
    public GuestOutputManifest PlanOutput(SandboxConfig config, Guid jobId)
    {
        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        var guestOut = $"{guestRoot}\\out\\{jobId:N}";
        var hostOut = Path.Combine(config.Paths.RuntimeRoot, "jobs", jobId.ToString("N"), "guest");
        return new GuestOutputManifest
        {
            JobId = jobId,
            GuestOutputDirectory = guestOut,
            HostOutputDirectory = hostOut,
            EventsJsonPath = $"{guestOut}\\events.json",
            DriverJsonLinesPath = config.Driver.Enabled ? $"{guestOut}\\driver-events.jsonl" : null
        };
    }
}
