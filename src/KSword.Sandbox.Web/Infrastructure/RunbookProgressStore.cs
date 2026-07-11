using System.Collections.Concurrent;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// In-memory Web host store for long-running runbook progress.
/// Inputs are progress snapshots emitted by the executor and route lookups by
/// job id; processing keeps only the latest UI-safe snapshot per job; callers
/// receive snapshots that never contain PowerShell commands, stdout, or stderr.
/// </summary>
internal sealed class RunbookProgressStore
{
    private readonly ConcurrentDictionary<Guid, SandboxRunbookProgressSnapshot> snapshots = new();

    /// <summary>
    /// Creates a pending snapshot before the executor starts. Inputs are the
    /// planned runbook and requested mode; processing records all source steps
    /// as pending; the snapshot is returned and stored for immediate polling.
    /// </summary>
    public SandboxRunbookProgressSnapshot Begin(SandboxRunbook runbook, SandboxRunbookExecutionMode mode)
    {
        ArgumentNullException.ThrowIfNull(runbook);

        var now = DateTimeOffset.UtcNow;
        var snapshot = new SandboxRunbookProgressSnapshot
        {
            JobId = runbook.JobId,
            TargetVmName = runbook.TargetVmName,
            Mode = mode,
            State = SandboxRunbookProgressStates.Pending,
            TotalSteps = runbook.Steps.Count,
            CompletedSteps = 0,
            ExecutedSteps = 0,
            CurrentStepIndex = null,
            CurrentStepId = null,
            CurrentStepTitle = null,
            Success = null,
            Message = "分析任务已进入 WebUI 队列 / Runbook execution has been queued by the WebUI.",
            StartedAtUtc = now,
            UpdatedAtUtc = now,
            Duration = TimeSpan.Zero,
            Steps = runbook.Steps.Select((step, index) => new SandboxRunbookStepProgressSnapshot
            {
                StepIndex = index,
                StepId = step.Id,
                Title = step.Title,
                State = SandboxRunbookProgressStates.Pending,
                RequiresElevation = step.RequiresElevation,
                MutatesVmState = step.MutatesVmState
            }).ToList()
        };

        Update(snapshot);
        return snapshot;
    }

    /// <summary>
    /// Stores the latest executor progress snapshot. Input is one immutable
    /// snapshot; processing replaces any older snapshot for the same job; the
    /// method returns no value.
    /// </summary>
    public void Update(SandboxRunbookProgressSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        snapshots.AddOrUpdate(
            snapshot.JobId,
            snapshot,
            (_, existing) => ShouldReplaceSnapshot(snapshot, existing) ? snapshot : existing);
    }

    /// <summary>
    /// Stores a terminal failure before or after executor startup. Inputs are
    /// job identity, runbook, mode, and message; processing creates a failed
    /// snapshot that WebUI polling can display; the snapshot is returned.
    /// </summary>
    public SandboxRunbookProgressSnapshot Fail(SandboxRunbook runbook, SandboxRunbookExecutionMode mode, string message)
    {
        ArgumentNullException.ThrowIfNull(runbook);

        var now = DateTimeOffset.UtcNow;
        var started = snapshots.TryGetValue(runbook.JobId, out var previous)
            ? previous.StartedAtUtc
            : now;
        var snapshot = new SandboxRunbookProgressSnapshot
        {
            JobId = runbook.JobId,
            TargetVmName = runbook.TargetVmName,
            Mode = mode,
            State = SandboxRunbookProgressStates.Failed,
            TotalSteps = runbook.Steps.Count,
            CompletedSteps = previous?.CompletedSteps ?? 0,
            ExecutedSteps = previous?.ExecutedSteps ?? 0,
            CurrentStepIndex = previous?.CurrentStepIndex,
            CurrentStepId = previous?.CurrentStepId,
            CurrentStepTitle = previous?.CurrentStepTitle,
            Success = false,
            Message = message,
            StartedAtUtc = started,
            UpdatedAtUtc = now,
            Duration = now - started,
            Steps = previous?.Steps ?? runbook.Steps.Select((step, index) => new SandboxRunbookStepProgressSnapshot
            {
                StepIndex = index,
                StepId = step.Id,
                Title = step.Title,
                State = SandboxRunbookProgressStates.Pending,
                RequiresElevation = step.RequiresElevation,
                MutatesVmState = step.MutatesVmState
            }).ToList()
        };

        Update(snapshot);
        return snapshot;
    }

    /// <summary>
    /// Attempts to read the latest snapshot. Input is job id; processing checks
    /// the in-memory dictionary; return value tells callers whether progress is
    /// currently known in this Web host process.
    /// </summary>
    public bool TryGet(Guid jobId, out SandboxRunbookProgressSnapshot snapshot)
    {
        return snapshots.TryGetValue(jobId, out snapshot!);
    }

    private static bool ShouldReplaceSnapshot(
        SandboxRunbookProgressSnapshot candidate,
        SandboxRunbookProgressSnapshot existing)
    {
        if (candidate.UpdatedAtUtc != existing.UpdatedAtUtc)
        {
            return candidate.UpdatedAtUtc > existing.UpdatedAtUtc;
        }

        if (candidate.ExecutedSteps != existing.ExecutedSteps)
        {
            return candidate.ExecutedSteps > existing.ExecutedSteps;
        }

        if (candidate.CompletedSteps != existing.CompletedSteps)
        {
            return candidate.CompletedSteps > existing.CompletedSteps;
        }

        return candidate.Success.HasValue && !existing.Success.HasValue;
    }
}
