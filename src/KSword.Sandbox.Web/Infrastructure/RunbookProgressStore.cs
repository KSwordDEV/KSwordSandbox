using System.Collections.Concurrent;
using System.Threading.Channels;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Web.Contracts;

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
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, Channel<SandboxRunbookProgressSnapshot>>> subscribers = new();

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
            Provider = runbook.Provider,
            TargetVmName = runbook.TargetVmName,
            BaselineName = runbook.BaselineName,
            MachineDefinitionPath = runbook.MachineDefinitionPath,
            QemuDiskFormat = runbook.QemuDiskFormat,
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
        var shouldPublish = false;
        snapshots.AddOrUpdate(
            snapshot.JobId,
            _ =>
            {
                shouldPublish = true;
                return snapshot;
            },
            (_, existing) =>
            {
                if (!ShouldReplaceSnapshot(snapshot, existing))
                {
                    return existing;
                }

                shouldPublish = true;
                return snapshot;
            });

        if (shouldPublish)
        {
            Publish(snapshot);
        }
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
            Provider = runbook.Provider,
            TargetVmName = runbook.TargetVmName,
            BaselineName = runbook.BaselineName,
            MachineDefinitionPath = runbook.MachineDefinitionPath,
            QemuDiskFormat = runbook.QemuDiskFormat,
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

    /// <summary>
    /// Attempts to read the latest snapshot with API-safe durability/freshness
    /// metadata. Inputs are a job id and optional durable source path;
    /// processing derives age, stale flag, latest step summary, counts, and
    /// Chinese operator hints without exposing commands/stdout/stderr; return
    /// value tells callers whether progress is known in this Web host process.
    /// </summary>
    public bool TryGetContract(
        Guid jobId,
        string? durableSourcePath,
        out RunbookProgressContract contract)
    {
        contract = null!;
        if (!TryGet(jobId, out var snapshot))
        {
            return false;
        }

        contract = RunbookProgressContract.FromSnapshot(
            snapshot,
            durableSourcePath,
            DateTimeOffset.UtcNow);
        return true;
    }

    /// <summary>
    /// Subscribes a single SSE client to bounded progress updates for one job.
    /// Inputs are the job id; processing creates a drop-oldest in-memory
    /// channel and immediately seeds it with the latest snapshot when present;
    /// callers dispose the subscription when the browser disconnects.
    /// </summary>
    public RunbookProgressSubscription Subscribe(Guid jobId)
    {
        var subscriberId = Guid.NewGuid();
        var channel = Channel.CreateBounded<SandboxRunbookProgressSnapshot>(
            new BoundedChannelOptions(16)
            {
                AllowSynchronousContinuations = false,
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });

        var jobSubscribers = subscribers.GetOrAdd(
            jobId,
            _ => new ConcurrentDictionary<Guid, Channel<SandboxRunbookProgressSnapshot>>());
        jobSubscribers[subscriberId] = channel;

        if (snapshots.TryGetValue(jobId, out var snapshot))
        {
            channel.Writer.TryWrite(snapshot);
        }

        return new RunbookProgressSubscription(
            jobId,
            subscriberId,
            channel.Reader,
            () => RemoveSubscriber(jobId, subscriberId));
    }

    private void Publish(SandboxRunbookProgressSnapshot snapshot)
    {
        if (!subscribers.TryGetValue(snapshot.JobId, out var jobSubscribers))
        {
            return;
        }

        foreach (var subscriber in jobSubscribers.ToArray())
        {
            if (!subscriber.Value.Writer.TryWrite(snapshot) &&
                subscriber.Value.Reader.Completion.IsCompleted)
            {
                jobSubscribers.TryRemove(subscriber.Key, out _);
            }
        }
    }

    private void RemoveSubscriber(Guid jobId, Guid subscriberId)
    {
        if (!subscribers.TryGetValue(jobId, out var jobSubscribers))
        {
            return;
        }

        if (jobSubscribers.TryRemove(subscriberId, out var channel))
        {
            channel.Writer.TryComplete();
        }

        if (jobSubscribers.IsEmpty)
        {
            subscribers.TryRemove(jobId, out _);
        }
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

/// <summary>
/// Disposable handle for one runbook-progress stream subscriber.
/// </summary>
internal sealed class RunbookProgressSubscription : IAsyncDisposable
{
    private readonly Action dispose;
    private int disposed;

    public RunbookProgressSubscription(
        Guid jobId,
        Guid subscriberId,
        ChannelReader<SandboxRunbookProgressSnapshot> reader,
        Action dispose)
    {
        JobId = jobId;
        SubscriberId = subscriberId;
        Reader = reader;
        this.dispose = dispose;
    }

    public Guid JobId { get; }

    public Guid SubscriberId { get; }

    public ChannelReader<SandboxRunbookProgressSnapshot> Reader { get; }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            dispose();
        }

        return ValueTask.CompletedTask;
    }
}
