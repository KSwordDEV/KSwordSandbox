namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: job counters and a UTC generation timestamp collected by dashboard logic.
/// Processing: groups high-level metrics that the dashboard can render without knowing service internals.
/// Return behavior: instances are serialized for dashboard bootstrap APIs or embedded in rendered HTML.
/// </summary>
/// <param name="TotalJobs">Total number of jobs visible to the dashboard.</param>
/// <param name="RunningJobs">Number of jobs currently running.</param>
/// <param name="CompletedJobs">Number of jobs completed successfully.</param>
/// <param name="FailedJobs">Number of jobs completed with failure.</param>
/// <param name="GeneratedAtUtc">UTC timestamp captured when counters were produced.</param>
public sealed record DashboardSnapshotContract(
    int TotalJobs,
    int RunningJobs,
    int CompletedJobs,
    int FailedJobs,
    DateTimeOffset GeneratedAtUtc)
{
    /// <summary>
    /// Inputs: a UTC timestamp from the caller.
    /// Processing: creates a zeroed dashboard snapshot for empty or unavailable stores.
    /// Return behavior: returns a snapshot with all counters set to zero.
    /// </summary>
    public static DashboardSnapshotContract Empty(DateTimeOffset generatedAtUtc)
    {
        return new DashboardSnapshotContract(0, 0, 0, 0, generatedAtUtc);
    }
}
