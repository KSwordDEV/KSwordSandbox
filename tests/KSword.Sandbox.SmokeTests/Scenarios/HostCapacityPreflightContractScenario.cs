using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Covers the host-capacity preflight that refuses to start a live run when
/// the drive holding the job output cannot absorb the conservative evidence
/// estimate (window × 5.9 MB/s R0 noise upper bound + ETW budget + 100 MB
/// reserve). The 2026-10-19 incident batch was dominated by host disk
/// exhaustion: 7 of 8 historical R0 failure sidecars are
/// outputSpaceInsufficient, and the e1b5a048 run (90 s window, ETW on)
/// consumed 396 MB on the host. The guard must refuse loudly before any VM
/// mutation, with a bilingual reason that states the byte math.
/// </summary>
internal sealed class HostCapacityPreflightContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "host.capacity-preflight.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Formula anchor, validated against the e1b5a048 replay in the
        // round-2026-10-19-live audit report: 90 s × (5.9 + 0.7) MB/s + 100 MB
        // = 694 MB, a safe 1.75x upper bound over the measured 396 MB.
        const int e1b5a048WindowSeconds = 90;
        var withEtw = HostOutputCapacityGuard.EstimateRequiredBytes(e1b5a048WindowSeconds, etwTraceEnabled: true);
        var withoutEtw = HostOutputCapacityGuard.EstimateRequiredBytes(e1b5a048WindowSeconds, etwTraceEnabled: false);
        var expectedWithEtw = (long)Math.Ceiling(e1b5a048WindowSeconds * (5.9 + 0.7) * 1024 * 1024 + 100.0 * 1024 * 1024);
        SmokeAssert.True(withEtw == expectedWithEtw,
            $"90s ETW estimate must follow the documented formula (expected {expectedWithEtw}, got {withEtw}).");
        SmokeAssert.True(withoutEtw == (long)Math.Ceiling(e1b5a048WindowSeconds * 5.9 * 1024 * 1024 + 100.0 * 1024 * 1024),
            "90s no-ETW estimate must be window × 5.9 MB/s + 100 MB reserve.");
        SmokeAssert.True(withEtw > withoutEtw, "The ETW budget must only add bytes when the ETW lane is enabled.");
        SmokeAssert.True(withEtw / 1024.0 / 1024.0 / 396.0 is > 1.0 and < 3.0,
            "The e1b5a048 anchor: the estimate must bound the measured 396 MB without being absurdly large.");

        // Unlimited windows must still produce an honest conservative number.
        var unlimited = HostOutputCapacityGuard.EstimateRequiredBytes(null, etwTraceEnabled: true);
        SmokeAssert.True(unlimited > withEtw,
            "An unlimited window must be estimated at least as large as the 90 s window.");

        // Refusal path: measurable space below the estimate refuses with a
        // reason that carries the numbers in both languages.
        var refused = HostOutputCapacityGuard.Assess(
            Path.Combine(context.RuntimeRoot, "jobs"),
            e1b5a048WindowSeconds,
            etwTraceEnabled: true,
            availableFreeBytesOverride: 1024L * 1024);
        SmokeAssert.True(refused.Refused, "1 MB of free space must refuse a 90 s live run.");
        SmokeAssert.True(refused.Reason is not null, "A refusal must carry an operator-readable reason.");
        SmokeAssert.True(
            refused.Reason!.Contains("5.9 MB/s", StringComparison.Ordinal) &&
            refused.Reason.Contains("拒绝", StringComparison.Ordinal) &&
            refused.Reason.Contains("insufficient", StringComparison.OrdinalIgnoreCase) &&
            refused.Reason.Contains("refused", StringComparison.OrdinalIgnoreCase) &&
            refused.Reason.Contains("MB", StringComparison.Ordinal),
            "The refusal reason must explain the formula and be bilingual.");

        var thrown = false;
        try
        {
            HostOutputCapacityGuard.EnsureCapacity(
                Path.Combine(context.RuntimeRoot, "jobs"),
                e1b5a048WindowSeconds,
                etwTraceEnabled: true,
                availableFreeBytesOverride: 1024L * 1024);
        }
        catch (ArgumentException)
        {
            thrown = true;
        }

        SmokeAssert.True(thrown, "EnsureCapacity must throw ArgumentException on refusal so callers abort before VM mutation.");

        // Sufficient space starts normally.
        var allowed = HostOutputCapacityGuard.Assess(
            Path.Combine(context.RuntimeRoot, "jobs"),
            e1b5a048WindowSeconds,
            etwTraceEnabled: true,
            availableFreeBytesOverride: withEtw);
        SmokeAssert.True(!allowed.Refused && allowed.Reason is null,
            "Free space exactly equal to the estimate must be allowed.");

        // Unmeasurable space (UNC/missing roots) never refuses: preflight is a
        // guardrail, not a hard dependency on a local drive letter.
        var unmeasured = HostOutputCapacityGuard.Assess(
            "\\\\nonexistent-host\\no-such-share\\jobs",
            e1b5a048WindowSeconds,
            etwTraceEnabled: true);
        SmokeAssert.True(!unmeasured.Refused,
            "An unmeasurable jobs root must not refuse the run.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"capacity preflight: 90s+ETW={withEtw / 1024 / 1024} MB, refusal reason bilingual, unmeasurable roots tolerated"
        });
    }
}
