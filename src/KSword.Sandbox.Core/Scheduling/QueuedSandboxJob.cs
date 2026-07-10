using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Scheduling;

/// <summary>
/// Represents one queued analysis request before worker execution.
/// Inputs are job ID and submission; processing is queue storage only; the
/// record returns immutable queue metadata to schedulers.
/// </summary>
public sealed record QueuedSandboxJob
{
    public required Guid JobId { get; init; }

    public required SandboxSubmission Submission { get; init; }

    public DateTimeOffset QueuedAtUtc { get; init; } = DateTimeOffset.UtcNow;
}
