using System.Threading.Channels;

namespace KSword.Sandbox.Core.Scheduling;

/// <summary>
/// Provides an in-process FIFO queue for future live analysis workers.
/// Inputs are queued jobs; processing uses a bounded channel when configured;
/// methods return when enqueue or dequeue operations complete.
/// </summary>
public sealed class SandboxJobQueue
{
    private readonly Channel<QueuedSandboxJob> channel;

    /// <summary>
    /// Creates a job queue with an optional capacity.
    /// The input is capacity, processing chooses bounded or unbounded channel,
    /// and the constructor returns no value.
    /// </summary>
    public SandboxJobQueue(int capacity = 0)
    {
        channel = capacity > 0
            ? Channel.CreateBounded<QueuedSandboxJob>(capacity)
            : Channel.CreateUnbounded<QueuedSandboxJob>();
    }

    /// <summary>
    /// Enqueues a job for worker processing.
    /// Inputs are a queued job and cancellation token; processing writes to the
    /// channel; the method returns when the job is accepted.
    /// </summary>
    public ValueTask EnqueueAsync(QueuedSandboxJob job, CancellationToken cancellationToken = default)
    {
        return channel.Writer.WriteAsync(job, cancellationToken);
    }

    /// <summary>
    /// Dequeues the next job.
    /// The input is a cancellation token, processing waits for channel data,
    /// and the method returns the next queued job.
    /// </summary>
    public ValueTask<QueuedSandboxJob> DequeueAsync(CancellationToken cancellationToken = default)
    {
        return channel.Reader.ReadAsync(cancellationToken);
    }
}
