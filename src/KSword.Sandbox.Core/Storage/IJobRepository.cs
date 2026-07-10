using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Storage;

/// <summary>
/// Defines storage operations for analysis job metadata.
/// Inputs are AnalysisJob records and IDs; processing is adapter-specific;
/// methods return saved, listed, or retrieved job records.
/// </summary>
public interface IJobRepository
{
    /// <summary>
    /// Saves the supplied job metadata.
    /// The input is an AnalysisJob, processing stores the latest state, and the
    /// method returns the saved record.
    /// </summary>
    AnalysisJob Save(AnalysisJob job);

    /// <summary>
    /// Reads one job by ID.
    /// The input is a job ID, processing performs repository lookup, and the
    /// method returns a job or null.
    /// </summary>
    AnalysisJob? Get(Guid jobId);

    /// <summary>
    /// Lists all known jobs.
    /// There are no inputs, processing snapshots repository state, and the
    /// method returns ordered job metadata.
    /// </summary>
    IReadOnlyList<AnalysisJob> List();
}
