using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Storage;

/// <summary>
/// Stores job metadata in memory for the local MVP host process.
/// Inputs are AnalysisJob values; processing copies references into a map;
/// methods return current in-memory job state.
/// </summary>
public sealed class InMemoryJobRepository : IJobRepository
{
    private readonly Dictionary<Guid, AnalysisJob> jobs = [];

    /// <inheritdoc />
    public AnalysisJob Save(AnalysisJob job)
    {
        jobs[job.JobId] = job;
        return job;
    }

    /// <inheritdoc />
    public AnalysisJob? Get(Guid jobId)
    {
        return jobs.TryGetValue(jobId, out var job) ? job : null;
    }

    /// <inheritdoc />
    public IReadOnlyList<AnalysisJob> List()
    {
        return jobs.Values.OrderBy(job => job.CreatedAt).ToList();
    }
}
