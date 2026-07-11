using System.Collections.Concurrent;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// In-memory background execution registry for WebUI-started runbooks.
/// Inputs are job ids and deferred runbook execution delegates; processing
/// starts work on the server side so browser requests can return immediately;
/// callers poll compact snapshots for terminal result/report navigation.
/// </summary>
internal sealed class RunbookBackgroundExecutionStore
{
    public const string NotStarted = "not_started";
    public const string Queued = "queued";
    public const string Running = "running";
    public const string Completed = "completed";
    public const string Failed = "failed";

    private readonly ConcurrentDictionary<Guid, RunbookBackgroundExecutionSnapshot> snapshots = new();

    /// <summary>
    /// Starts one background run unless the same job is already queued/running.
    /// Inputs are job id, mode flags, and a delegate that owns the real executor
    /// work; processing records queued/running/terminal snapshots; return value
    /// indicates whether a new task was accepted.
    /// </summary>
    public bool TryStart(
        Guid jobId,
        bool live,
        bool importGuestEvents,
        Func<Task<RunbookExecutionOutcome>> executeAsync,
        out RunbookBackgroundExecutionSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(executeAsync);

        if (snapshots.TryGetValue(jobId, out var existing) && IsActive(existing.State))
        {
            snapshot = existing with
            {
                Accepted = false,
                Message = "Runbook execution is already queued or running for this job.",
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        var queuedSnapshot = new RunbookBackgroundExecutionSnapshot
        {
            JobId = jobId,
            Live = live,
            ImportGuestEvents = importGuestEvents,
            Accepted = true,
            State = Queued,
            Message = "Runbook execution has been accepted by the WebUI background runner.",
            StartedAtUtc = now,
            UpdatedAtUtc = now
        };
        snapshot = queuedSnapshot;
        snapshots[jobId] = snapshot;

        _ = Task.Run(async () =>
        {
            Update(queuedSnapshot with
            {
                State = Running,
                Message = "Runbook execution is running in the WebUI background runner.",
                UpdatedAtUtc = DateTimeOffset.UtcNow
            });

            try
            {
                var outcome = await executeAsync().ConfigureAwait(false);
                var importFailed = !string.IsNullOrWhiteSpace(outcome.GuestImportMessage) &&
                    !outcome.GuestImportSucceeded;
                var success = outcome.Execution.Success && !importFailed;
                Update(new RunbookBackgroundExecutionSnapshot
                {
                    JobId = jobId,
                    Live = live,
                    ImportGuestEvents = importGuestEvents,
                    Accepted = true,
                    State = success ? Completed : Failed,
                    Success = success,
                    Execution = outcome.Execution,
                    Job = outcome.Job,
                    GuestImportSucceeded = outcome.GuestImportSucceeded,
                    GuestImportMessage = outcome.GuestImportMessage,
                    Message = success
                        ? "Runbook execution completed."
                        : outcome.Execution.Message ?? outcome.GuestImportMessage ?? "Runbook execution failed.",
                    StartedAtUtc = now,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
            }
            catch (Exception ex)
            {
                Update(new RunbookBackgroundExecutionSnapshot
                {
                    JobId = jobId,
                    Live = live,
                    ImportGuestEvents = importGuestEvents,
                    Accepted = true,
                    State = Failed,
                    Success = false,
                    Message = $"Runbook background execution failed: {ex.Message}",
                    StartedAtUtc = now,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                });
            }
        });

        return true;
    }

    /// <summary>
    /// Reads a current snapshot or returns a stable not-started marker.
    /// </summary>
    public RunbookBackgroundExecutionSnapshot Get(Guid jobId)
    {
        return snapshots.TryGetValue(jobId, out var snapshot)
            ? snapshot
            : new RunbookBackgroundExecutionSnapshot
            {
                JobId = jobId,
                State = NotStarted,
                Message = "No WebUI background runbook execution has started for this job.",
                StartedAtUtc = DateTimeOffset.UtcNow,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
    }

    private static bool IsActive(string state)
    {
        return string.Equals(state, Queued, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(state, Running, StringComparison.OrdinalIgnoreCase);
    }

    private void Update(RunbookBackgroundExecutionSnapshot snapshot)
    {
        snapshots[snapshot.JobId] = snapshot;
    }
}

/// <summary>
/// JSON-serializable background execution status for a job.
/// </summary>
internal sealed record RunbookBackgroundExecutionSnapshot
{
    public required Guid JobId { get; init; }

    public bool Live { get; init; }

    public bool ImportGuestEvents { get; init; }

    public bool Accepted { get; init; }

    public required string State { get; init; }

    public bool? Success { get; init; }

    public string? Message { get; init; }

    public DateTimeOffset StartedAtUtc { get; init; }

    public DateTimeOffset UpdatedAtUtc { get; init; }

    public SandboxRunbookExecutionResult? Execution { get; init; }

    public AnalysisJob? Job { get; init; }

    public bool GuestImportSucceeded { get; init; }

    public string? GuestImportMessage { get; init; }
}

/// <summary>
/// Terminal result from one runbook execution plus optional guest import.
/// </summary>
internal sealed record RunbookExecutionOutcome(
    SandboxRunbookExecutionResult Execution,
    AnalysisJob Job,
    bool GuestImportSucceeded,
    string? GuestImportMessage);
