namespace KSword.Sandbox.Core.Orchestration;

/// <summary>
/// Records one host-capacity preflight outcome for a live run.
/// Inputs are computed by <see cref="HostOutputCapacityGuard"/>; processing
/// stores the byte math and a bilingual refusal reason; callers use
/// <see cref="Refused"/> to decide whether the run may start.
/// </summary>
public sealed record HostCapacityAssessment(
    long RequiredBytes,
    long? AvailableBytes,
    bool Refused,
    string? Reason);

/// <summary>
/// Refuses to start a live run when the host drive that will hold the job
/// output cannot hold the estimated evidence volume. Live failures from
/// 2026-10-19 were dominated by host disk exhaustion (7 of 8 historical R0
/// failure sidecars are outputSpaceInsufficient), so the estimate is
/// deliberately conservative:
///   required = windowSeconds * 5.9 MB/s (R0 ambient-noise upper bound, from
///              r0_diagnosis: idle ≈ 2,476 events/s ≈ 5.9 MB/s)
///            + ETW budget (windowSeconds * 0.7 MB/s when the ETW lane is on,
///              measured on e1b5a048: (4 MB ETL + 16 MB pktmon + 32 MB decode
///              XML) / 90 s ≈ 0.58 MB/s, rounded up)
///            + 100 MB fixed reserve for report.json/html and markers.
/// Validation anchor: the e1b5a048 run (90 s window, ETW on) consumed 396 MB
/// total; the formula predicts 694 MB, i.e. a safe 1.75x upper bound that
/// still fits comfortably on hosts that could run that job.
/// </summary>
public static class HostOutputCapacityGuard
{
    public const double R0StreamBytesPerSecond = 5.9 * 1024 * 1024;

    public const double EtwStreamBytesPerSecond = 0.7 * 1024 * 1024;

    public const long FixedReserveBytes = 100L * 1024 * 1024;

    /// <summary>
    /// Conservative window used when the operator requested an unlimited
    /// runtime: refuse rather than pretend an unbounded output volume fits.
    /// </summary>
    public const int UnlimitedWindowSeconds = 3600;

    /// <summary>
    /// Computes the required free bytes for one live run. Inputs are the
    /// analysis window in seconds (null = unlimited) and whether the ETW
    /// lane is enabled; processing applies the rates documented on the
    /// class; the method returns the conservative byte estimate.
    /// </summary>
    public static long EstimateRequiredBytes(int? durationSeconds, bool etwTraceEnabled)
    {
        var windowSeconds = durationSeconds.HasValue
            ? Math.Max(0, durationSeconds.Value)
            : UnlimitedWindowSeconds;
        var required = windowSeconds * R0StreamBytesPerSecond + FixedReserveBytes;
        if (etwTraceEnabled)
        {
            required += windowSeconds * EtwStreamBytesPerSecond;
        }

        return (long)Math.Ceiling(required);
    }

    /// <summary>
    /// Assesses one prospective live run without throwing. Inputs are the
    /// jobs root whose drive must absorb the evidence, the window, the ETW
    /// flag, and an optional measured-free-bytes override (smoke tests);
    /// processing reads the drive when no override is given and refuses when
    /// free space is measurable and below the estimate; the method returns
    /// the assessment. Unmeasurable space (UNC roots, missing directories)
    /// never refuses.
    /// </summary>
    public static HostCapacityAssessment Assess(
        string jobsRoot,
        int? durationSeconds,
        bool etwTraceEnabled,
        long? availableFreeBytesOverride = null)
    {
        var required = EstimateRequiredBytes(durationSeconds, etwTraceEnabled);
        long? available;
        try
        {
            available = availableFreeBytesOverride ?? TryMeasureAvailableBytes(jobsRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            available = availableFreeBytesOverride;
        }

        if (available is null)
        {
            return new HostCapacityAssessment(required, null, Refused: false, Reason: null);
        }

        if (available.Value >= required)
        {
            return new HostCapacityAssessment(required, available.Value, Refused: false, Reason: null);
        }

        return new HostCapacityAssessment(
            required,
            available.Value,
            Refused: true,
            Reason: BuildRefusalReason(jobsRoot, durationSeconds, etwTraceEnabled, required, available.Value));
    }

    /// <summary>
    /// Refuses to start a live run when measurable host free space is below
    /// the conservative estimate. Inputs match <see cref="Assess"/>; the
    /// method returns normally when capacity is sufficient or unmeasurable
    /// and throws <see cref="ArgumentException"/> with a bilingual,
    /// operator-readable reason otherwise.
    /// </summary>
    public static void EnsureCapacity(
        string jobsRoot,
        int? durationSeconds,
        bool etwTraceEnabled,
        long? availableFreeBytesOverride = null)
    {
        var assessment = Assess(jobsRoot, durationSeconds, etwTraceEnabled, availableFreeBytesOverride);
        if (assessment.Refused)
        {
            throw new ArgumentException(assessment.Reason, nameof(jobsRoot));
        }
    }

    private static long? TryMeasureAvailableBytes(string jobsRoot)
    {
        if (string.IsNullOrWhiteSpace(jobsRoot))
        {
            return null;
        }

        var fullPath = Path.GetFullPath(jobsRoot);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return null;
        }

        var drive = new DriveInfo(root);
        return drive.AvailableFreeSpace;
    }

    private static string BuildRefusalReason(
        string jobsRoot,
        int? durationSeconds,
        bool etwTraceEnabled,
        long requiredBytes,
        long availableBytes)
    {
        var windowText = durationSeconds.HasValue
            ? $"{Math.Max(0, durationSeconds.Value)}s"
            : $"unlimited(按 {UnlimitedWindowSeconds}s 保守估算 / estimated conservatively)";
        var requiredMb = requiredBytes / 1024.0 / 1024.0;
        var availableMb = availableBytes / 1024.0 / 1024.0;
        return
            $"主机磁盘剩余空间不足，已拒绝启动实时分析：任务目录 {jobsRoot} 所在驱动器可用 {availableMb:0.0} MB，" +
            $"预估需要 {requiredMb:0.0} MB（窗口 {windowText} × 5.9 MB/s R0 噪声上限{(etwTraceEnabled ? " + ETW 预算 0.7 MB/s" : string.Empty)} + 100 MB 固定余量）。" +
            $"请清理该驱动器、缩短分析窗口，或改用其他磁盘作为 runtimeRoot。/ " +
            $"Host drive free space is insufficient; the live run was refused: drive holding {jobsRoot} has {availableMb:0.0} MB available " +
            $"but the run needs about {requiredMb:0.0} MB (window {windowText} × 5.9 MB/s R0 noise upper bound{(etwTraceEnabled ? " + 0.7 MB/s ETW budget" : string.Empty)} + 100 MB reserve). " +
            $"Free space on that drive, shorten the analysis window, or point runtimeRoot at a larger disk.";
    }
}
