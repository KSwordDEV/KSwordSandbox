using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Jobs;

public sealed partial class SandboxJobService
{
    private const string JobMetadataFileName = "job-metadata.json";
    private const string RunbookProgressFileName = "runbook-progress.json";
    private const string GuestImportStateFileName = "guest-import-state.json";
    private const long MaxCompanionJsonBytes = 4L * 1024 * 1024;

    private readonly object jobsSyncRoot = new();

    /// <summary>
    /// Attempts to read the latest persisted UI-safe runbook progress snapshot.
    /// Inputs are a job id; processing recovers the job if necessary and reads
    /// runbook-progress.json or derives a terminal snapshot from
    /// runbook-execution.json; the method returns false when no durable progress
    /// is available.
    /// </summary>
    public bool TryGetRunbookProgress(Guid jobId, out SandboxRunbookProgressSnapshot snapshot)
    {
        snapshot = null!;
        var job = GetJob(jobId);
        if (job is null)
        {
            return false;
        }

        var progressPath = GetRunbookProgressPath(jobId);
        if (TryReadCompanionJsonFile(progressPath, out SandboxRunbookProgressSnapshot? persisted) &&
            persisted is not null &&
            persisted.JobId == jobId)
        {
            snapshot = persisted;
            return true;
        }

        if (job.Runbook is not null &&
            TryReadRunbookExecutionResult(job.RunbookExecutionResultPath, out var execution) &&
            execution is not null &&
            execution.JobId == jobId)
        {
            snapshot = BuildRunbookProgressSnapshot(job.Runbook, execution);
            if (!File.Exists(progressPath))
            {
                try
                {
                    WriteJsonAtomically(progressPath, snapshot);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
                {
                    // Best-effort backfill; callers still receive the
                    // recovered snapshot derived from runbook-execution.json.
                }
            }

            return true;
        }

        return false;
    }

    /// <summary>
    /// Persists one UI-safe runbook progress snapshot while a live/background
    /// execution is still running. Inputs are the executor snapshot; processing
    /// writes runbook-progress.json atomically under the deterministic job
    /// directory without touching raw stdout/stderr or PowerShell commands; the
    /// method returns no value.
    /// </summary>
    public void SaveRunbookProgressSnapshot(SandboxRunbookProgressSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (snapshot.JobId == Guid.Empty)
        {
            throw new ArgumentException("Runbook progress snapshot must include a job id.", nameof(snapshot));
        }

        Directory.CreateDirectory(GetJobRoot(snapshot.JobId));
        WriteJsonAtomically(GetRunbookProgressPath(snapshot.JobId), snapshot);
    }

    /// <summary>
    /// Adds newly discovered on-disk jobs to the in-memory index.
    /// Inputs are the configured runtime jobs root; processing enumerates only
    /// first-level GUID-named directories and never loads guest events.json; the
    /// method returns no value.
    /// </summary>
    private void RefreshRecoveredJobs()
    {
        var jobsRoot = GetJobsRoot();
        if (!Directory.Exists(jobsRoot))
        {
            return;
        }

        foreach (var jobRoot in SafeEnumerateJobDirectories(jobsRoot)
            .OrderBy(SafeGetCreationTimeUtc)
            .ThenBy(path => Path.GetFileName(Path.TrimEndingDirectorySeparator(path)), StringComparer.OrdinalIgnoreCase))
        {
            if (!TryParseJobIdFromDirectory(jobRoot, out var jobId))
            {
                continue;
            }

            lock (jobsSyncRoot)
            {
                if (jobs.ContainsKey(jobId))
                {
                    continue;
                }
            }

            if (TryRecoverJobFromDirectory(jobId, jobRoot, out var recovered))
            {
                StoreRecoveredJob(recovered);
            }
        }
    }

    /// <summary>
    /// Recovers one job by deterministic directory name.
    /// Inputs are a job id; processing reads compact metadata/report/import
    /// state only when the in-memory cache misses; the method returns true when
    /// a usable job record was recovered.
    /// </summary>
    private bool TryRecoverJob(Guid jobId, out AnalysisJob job)
    {
        lock (jobsSyncRoot)
        {
            if (jobs.TryGetValue(jobId, out job!))
            {
                return true;
            }
        }

        var jobRoot = GetJobRoot(jobId);
        if (!Directory.Exists(jobRoot) ||
            !TryRecoverJobFromDirectory(jobId, jobRoot, out job!))
        {
            job = null!;
            return false;
        }

        StoreRecoveredJob(job);
        return true;
    }

    /// <summary>
    /// Stores one job in memory and writes compact job metadata beside reports.
    /// Inputs are an AnalysisJob; processing creates the job directory, writes
    /// job-metadata.json, and atomically updates the process-local index; the
    /// method returns no value.
    /// </summary>
    private void StoreJob(AnalysisJob job)
    {
        PersistJobMetadata(job);
        lock (jobsSyncRoot)
        {
            jobs[job.JobId] = job;
        }
    }

    private void StoreRecoveredJob(AnalysisJob job)
    {
        try
        {
            PersistJobMetadata(job);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Recovery should keep the WebHost job list available even when a
            // historical job directory is temporarily read-only or locked.
        }

        lock (jobsSyncRoot)
        {
            jobs[job.JobId] = job;
        }
    }

    private bool TryRecoverJobFromDirectory(Guid jobId, string jobRoot, out AnalysisJob job)
    {
        job = null!;
        var metadataPath = Path.Combine(jobRoot, JobMetadataFileName);
        var reportPath = Path.Combine(jobRoot, "report.json");
        var report = LoadExistingReport(reportPath);
        var importState = ReadGuestImportState(jobId) ?? BuildGuestImportStateFromReport(jobId, report);
        var execution = ReadRunbookExecutionResult(jobId);

        AnalysisJob? metadataJob = null;
        if (TryReadCompanionJsonFile(metadataPath, out AnalysisJob? loadedJob) &&
            loadedJob is not null &&
            loadedJob.JobId == jobId)
        {
            metadataJob = loadedJob;
        }

        if (metadataJob is null && report?.Sample is null)
        {
            return false;
        }

        var sample = metadataJob?.Sample ?? report?.Sample;
        if (sample is null)
        {
            return false;
        }

        var submission = metadataJob?.Submission ?? new SandboxSubmission
        {
            SamplePath = sample.FullPath,
            DisplayName = sample.FileName,
            DurationSeconds = config.Analysis.DefaultDurationSeconds,
            DryRun = true
        };
        var duration = ClampDuration(submission.DurationSeconds);
        var normalizedSubmission = NormalizeSubmission(submission, duration);
        var runbook = metadataJob?.Runbook ?? TryBuildRecoveredRunbook(jobId, sample, normalizedSubmission);
        var status = ResolveRecoveredStatus(metadataJob?.Status, report?.Status, execution, importState);
        var messages = metadataJob?.Messages.ToList() ?? [];
        AddUniqueMessage(messages, $"Recovered job metadata from {jobRoot}.");
        if (importState is not null && !string.IsNullOrWhiteSpace(importState.Message))
        {
            AddUniqueMessage(messages, importState.Message);
        }

        job = new AnalysisJob
        {
            JobId = jobId,
            CreatedAt = ResolveRecoveredCreatedAt(jobRoot, metadataJob, report),
            Submission = normalizedSubmission,
            Status = status,
            Sample = sample,
            Runbook = runbook,
            JsonReportPath = ResolveDeterministicJobFile(jobRoot, "report.json"),
            HtmlReportPath = ResolveDeterministicJobFile(jobRoot, "report.html"),
            HtmlReportZhPath = ResolveDeterministicJobFile(jobRoot, "report.zh.html"),
            HtmlReportEnPath = ResolveDeterministicJobFile(jobRoot, "report.en.html"),
            RunbookExecutionResultPath = ResolveDeterministicJobFile(jobRoot, "runbook-execution.json") ?? metadataJob?.RunbookExecutionResultPath,
            GuestEventsPath = ResolveRecoveredGuestEventsPath(metadataJob, importState, jobRoot),
            Messages = messages
        };

        PersistRecoveredCompanionState(job, execution, importState);

        return true;
    }

    private void PersistJobMetadata(AnalysisJob job)
    {
        var jobRoot = GetJobRoot(job.JobId);
        Directory.CreateDirectory(jobRoot);
        WriteJsonAtomically(Path.Combine(jobRoot, JobMetadataFileName), job);
    }

    private void PersistRunbookProgress(AnalysisJob job, SandboxRunbookExecutionResult result)
    {
        if (job.Runbook is null)
        {
            return;
        }

        var snapshot = BuildRunbookProgressSnapshot(job.Runbook, result);
        WriteJsonAtomically(GetRunbookProgressPath(job.JobId), snapshot);
    }

    private void PersistGuestImportState(AnalysisJob job, string? eventsPath, int eventCount, AnalysisStatus status, string message)
    {
        var state = new GuestImportState
        {
            JobId = job.JobId,
            EventsPath = string.IsNullOrWhiteSpace(eventsPath) ? null : Path.GetFullPath(eventsPath),
            EventCount = eventCount,
            Status = status,
            Message = message,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        WriteJsonAtomically(GetGuestImportStatePath(job.JobId), state);
    }

    private static SandboxRunbookProgressSnapshot BuildRunbookProgressSnapshot(SandboxRunbook runbook, SandboxRunbookExecutionResult result)
    {
        var startedAt = result.StartedAtUtc == default ? DateTimeOffset.UtcNow : result.StartedAtUtc;
        var updatedAt = startedAt + result.Duration;
        if (updatedAt < startedAt)
        {
            updatedAt = startedAt;
        }

        var resultByIndex = result.StepResults.ToDictionary(step => step.StepIndex);
        var failedIndex = result.FailedStepIndex;
        var steps = runbook.Steps.Select((step, index) =>
        {
            resultByIndex.TryGetValue(index, out var stepResult);
            var state = ResolveStepProgressState(index, stepResult, failedIndex);
            return new SandboxRunbookStepProgressSnapshot
            {
                StepIndex = index,
                StepId = step.Id,
                Title = step.Title,
                State = state,
                RequiresElevation = step.RequiresElevation,
                MutatesVmState = step.MutatesVmState,
                StartedAtUtc = stepResult?.StartedAtUtc,
                Duration = stepResult?.Duration,
                ExitCode = stepResult?.ExitCode,
                Message = stepResult?.Message
            };
        }).ToList();

        var completedSteps = steps.Count(step => string.Equals(step.State, SandboxRunbookProgressStates.Completed, StringComparison.OrdinalIgnoreCase));
        var currentStep = steps.LastOrDefault(step =>
            string.Equals(step.State, SandboxRunbookProgressStates.Failed, StringComparison.OrdinalIgnoreCase)) ??
            steps.LastOrDefault(step => !string.Equals(step.State, SandboxRunbookProgressStates.Pending, StringComparison.OrdinalIgnoreCase));
        var state = result.Success
            ? SandboxRunbookProgressStates.Completed
            : SandboxRunbookProgressStates.Failed;

        return new SandboxRunbookProgressSnapshot
        {
            JobId = runbook.JobId,
            TargetVmName = result.TargetVmName,
            Mode = result.Mode,
            State = state,
            TotalSteps = result.TotalSteps > 0 ? result.TotalSteps : runbook.Steps.Count,
            CompletedSteps = completedSteps,
            ExecutedSteps = result.ExecutedSteps,
            CurrentStepIndex = currentStep?.StepIndex,
            CurrentStepId = currentStep?.StepId,
            CurrentStepTitle = currentStep?.Title,
            Success = result.Success,
            Message = result.Message ?? (result.Success ? "Runbook execution completed." : "Runbook execution failed."),
            StartedAtUtc = startedAt,
            UpdatedAtUtc = updatedAt,
            Duration = result.Duration,
            Steps = steps
        };
    }

    private SandboxRunbook? TryBuildRecoveredRunbook(Guid jobId, SampleIdentity sample, SandboxSubmission submission)
    {
        try
        {
            var jobConfig = BuildJobConfig(submission, submission.DurationSeconds);
            return runbookBuilder.Build(jobConfig, jobId, sample);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private AnalysisStatus ResolveRecoveredStatus(
        AnalysisStatus? metadataStatus,
        AnalysisStatus? reportStatus,
        SandboxRunbookExecutionResult? execution,
        GuestImportState? importState)
    {
        if (importState is not null)
        {
            return importState.Status;
        }

        if (reportStatus is not null)
        {
            return reportStatus.Value;
        }

        if (execution is not null)
        {
            return execution.Mode == SandboxRunbookExecutionMode.Live
                ? execution.Success ? AnalysisStatus.Running : AnalysisStatus.Failed
                : metadataStatus ?? AnalysisStatus.Planned;
        }

        return metadataStatus ?? AnalysisStatus.Planned;
    }

    private static string ResolveStepProgressState(
        int stepIndex,
        SandboxRunbookStepExecutionResult? stepResult,
        int? failedIndex)
    {
        if (stepResult is not null)
        {
            return stepResult.Success
                ? SandboxRunbookProgressStates.Completed
                : SandboxRunbookProgressStates.Failed;
        }

        if (failedIndex.HasValue && stepIndex > failedIndex.Value)
        {
            return SandboxRunbookProgressStates.Skipped;
        }

        return SandboxRunbookProgressStates.Pending;
    }

    private static DateTimeOffset ResolveRecoveredCreatedAt(string jobRoot, AnalysisJob? metadataJob, AnalysisReport? report)
    {
        if (metadataJob is not null && metadataJob.CreatedAt != default)
        {
            return metadataJob.CreatedAt;
        }

        if (report is not null && report.GeneratedAt != default)
        {
            return report.GeneratedAt;
        }

        try
        {
            return new DateTimeOffset(Directory.GetCreationTimeUtc(jobRoot), TimeSpan.Zero);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return DateTimeOffset.UtcNow;
        }
    }

    private string? ResolveRecoveredGuestEventsPath(AnalysisJob? metadataJob, GuestImportState? importState, string jobRoot)
    {
        var candidates = new[]
        {
            importState?.EventsPath,
            metadataJob?.GuestEventsPath,
            TryDiscoverGuestEventPath(jobRoot)
        };

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            try
            {
                return Path.GetFullPath(candidate);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }
        }

        return null;
    }

    private static string? TryDiscoverGuestEventPath(string jobRoot)
    {
        var guestRoot = Path.Combine(jobRoot, "guest");
        if (!Directory.Exists(guestRoot))
        {
            return null;
        }

        return SafeEnumerateFiles(guestRoot, path => string.Equals(Path.GetFileName(path), "events.json", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(SafeGetLastWriteTimeUtc)
            .FirstOrDefault() ??
            SafeEnumerateFiles(guestRoot, path => string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(SafeGetLastWriteTimeUtc)
                .FirstOrDefault();
    }

    private GuestImportState? ReadGuestImportState(Guid jobId)
    {
        return TryReadCompanionJsonFile(GetGuestImportStatePath(jobId), out GuestImportState? state) &&
            state is not null &&
            state.JobId == jobId
            ? state
            : null;
    }

    private static GuestImportState? BuildGuestImportStateFromReport(Guid jobId, AnalysisReport? report)
    {
        var importEvent = report?.Events
            .Where(evt =>
                string.Equals(evt.EventType, "guest.events.imported", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(evt.EventType, "guest.events.empty", StringComparison.OrdinalIgnoreCase))
            .LastOrDefault();
        if (importEvent is null || string.IsNullOrWhiteSpace(importEvent.Path))
        {
            return null;
        }

        var eventCount = 0;
        if (importEvent.Data.TryGetValue("eventCount", out var countText))
        {
            _ = int.TryParse(countText, out eventCount);
        }

        var status = string.Equals(importEvent.EventType, "guest.events.empty", StringComparison.OrdinalIgnoreCase)
            ? AnalysisStatus.Failed
            : report?.Status ?? AnalysisStatus.Completed;
        return new GuestImportState
        {
            JobId = jobId,
            EventsPath = importEvent.Path,
            EventCount = eventCount,
            Status = status,
            Message = $"Recovered guest import state from report: {eventCount} event(s) from {importEvent.Path}.",
            UpdatedAtUtc = report?.GeneratedAt ?? DateTimeOffset.UtcNow
        };
    }

    private void PersistRecoveredCompanionState(
        AnalysisJob job,
        SandboxRunbookExecutionResult? execution,
        GuestImportState? importState)
    {
        if (execution is not null &&
            job.Runbook is not null &&
            !File.Exists(GetRunbookProgressPath(job.JobId)))
        {
            try
            {
                PersistRunbookProgress(job, execution);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                // Best-effort backfill; TryGetRunbookProgress can derive this
                // snapshot again from runbook-execution.json.
            }
        }

        if (importState is not null &&
            !File.Exists(GetGuestImportStatePath(job.JobId)))
        {
            try
            {
                WriteJsonAtomically(GetGuestImportStatePath(job.JobId), importState);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                // Best-effort backfill; report.json still carries the import
                // marker used for recovery.
            }
        }
    }

    private SandboxRunbookExecutionResult? ReadRunbookExecutionResult(Guid jobId)
    {
        return TryReadRunbookExecutionResult(Path.Combine(GetJobRoot(jobId), "runbook-execution.json"), out var result) &&
            result is not null &&
            result.JobId == jobId
            ? result
            : null;
    }

    private static bool TryReadRunbookExecutionResult(string? path, out SandboxRunbookExecutionResult? result)
    {
        return TryReadJsonFile(path, out result);
    }

    private string GetJobsRoot()
    {
        return Path.Combine(config.Paths.RuntimeRoot, "jobs");
    }

    private string GetRunbookProgressPath(Guid jobId)
    {
        return Path.Combine(GetJobRoot(jobId), RunbookProgressFileName);
    }

    private string GetGuestImportStatePath(Guid jobId)
    {
        return Path.Combine(GetJobRoot(jobId), GuestImportStateFileName);
    }

    private static string? ResolveDeterministicJobFile(string jobRoot, string fileName)
    {
        var path = Path.Combine(jobRoot, fileName);
        return File.Exists(path) ? path : null;
    }

    private static void AddUniqueMessage(List<string> messages, string message)
    {
        if (!messages.Contains(message, StringComparer.OrdinalIgnoreCase))
        {
            messages.Add(message);
        }
    }

    private static bool TryParseJobIdFromDirectory(string jobRoot, out Guid jobId)
    {
        var name = Path.GetFileName(Path.TrimEndingDirectorySeparator(jobRoot));
        return Guid.TryParseExact(name, "N", out jobId) || Guid.TryParse(name, out jobId);
    }

    private static IEnumerable<string> SafeEnumerateJobDirectories(string jobsRoot)
    {
        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        using var enumerator = CreateDirectoryEnumerator(jobsRoot, options);
        if (enumerator is null)
        {
            yield break;
        }

        while (TryMoveNext(enumerator, out var directory))
        {
            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(directory);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }

            if (IsSameOrUnderDirectory(jobsRoot, fullPath))
            {
                yield return fullPath;
            }
        }
    }

    private static IEnumerable<string> SafeEnumerateFiles(string root, Func<string, bool> predicate)
    {
        if (!Directory.Exists(root))
        {
            yield break;
        }

        var options = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        using var enumerator = CreateFileEnumerator(root, options);
        if (enumerator is null)
        {
            yield break;
        }

        while (TryMoveNext(enumerator, out var path))
        {
            bool include;
            try
            {
                include = predicate(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or PathTooLongException)
            {
                continue;
            }

            if (include)
            {
                yield return path;
            }
        }
    }

    private static IEnumerator<string>? CreateDirectoryEnumerator(string root, EnumerationOptions options)
    {
        try
        {
            return Directory.EnumerateDirectories(root, "*", options).GetEnumerator();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    private static IEnumerator<string>? CreateFileEnumerator(string root, EnumerationOptions options)
    {
        try
        {
            return Directory.EnumerateFiles(root, "*", options).GetEnumerator();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    private static bool TryMoveNext(IEnumerator<string> enumerator, out string current)
    {
        current = string.Empty;
        try
        {
            if (!enumerator.MoveNext())
            {
                return false;
            }

            current = enumerator.Current;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or DirectoryNotFoundException)
        {
            return false;
        }
    }

    private static DateTime SafeGetLastWriteTimeUtc(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or PathTooLongException)
        {
            return DateTime.MinValue;
        }
    }

    private static DateTime SafeGetCreationTimeUtc(string path)
    {
        try
        {
            return Directory.GetCreationTimeUtc(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or PathTooLongException)
        {
            return DateTime.MinValue;
        }
    }

    private static bool TryReadCompanionJsonFile<T>(string? path, out T? value)
    {
        return TryReadJsonFile(path, out value, quarantineBadJson: true, maxBytes: MaxCompanionJsonBytes);
    }

    private static bool TryReadJsonFile<T>(string? path, out T? value)
    {
        return TryReadJsonFile(path, out value, quarantineBadJson: false, maxBytes: null);
    }

    private static bool TryReadJsonFile<T>(string? path, out T? value, bool quarantineBadJson, long? maxBytes)
    {
        value = default;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return false;
        }

        var shouldQuarantine = false;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (maxBytes.HasValue && stream.Length > maxBytes.Value)
            {
                shouldQuarantine = quarantineBadJson;
                return false;
            }

            value = JsonSerializer.Deserialize<T>(stream, JsonOptions);
            if (value is null)
            {
                shouldQuarantine = quarantineBadJson;
                return false;
            }

            return value is not null;
        }
        catch (JsonException)
        {
            shouldQuarantine = quarantineBadJson;
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            if (shouldQuarantine)
            {
                TryQuarantineBadJsonFile(path);
            }
        }
    }

    private static void TryQuarantineBadJsonFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            File.Move(path, BuildBadJsonPath(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or PathTooLongException)
        {
            // A corrupt companion file should never prevent job recovery. If it
            // cannot be moved aside because another process holds it, future
            // reads will continue to ignore it and retry the quarantine.
        }
    }

    private static string BuildBadJsonPath(string path)
    {
        var preferred = path + ".bad";
        if (!File.Exists(preferred))
        {
            return preferred;
        }

        var directory = Path.GetDirectoryName(path) ?? ".";
        var fileName = Path.GetFileName(path);
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var candidate = Path.Combine(directory, $"{fileName}.{DateTimeOffset.UtcNow:yyyyMMddHHmmssfffffff}.{attempt}.bad");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }

        return Path.Combine(directory, $"{fileName}.{Guid.NewGuid():N}.bad");
    }

    private static void WriteJsonAtomically<T>(string path, T value)
    {
        var directory = Path.GetDirectoryName(path) ?? ".";
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 16 * 1024,
                FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, value, JsonOptions);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(path))
            {
                try
                {
                    File.Replace(temporaryPath, path, destinationBackupFileName: null, ignoreMetadataErrors: true);
                    return;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
                {
                    File.Move(temporaryPath, path, overwrite: true);
                    return;
                }
            }

            File.Move(temporaryPath, path);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                // A stale uniquely named temp file is safer than failing after
                // the durable write path has already reported its real outcome.
            }
        }
    }

    private sealed record GuestImportState
    {
        public required Guid JobId { get; init; }

        public string? EventsPath { get; init; }

        public int EventCount { get; init; }

        public AnalysisStatus Status { get; init; }

        public string? Message { get; init; }

        public DateTimeOffset UpdatedAtUtc { get; init; }
    }
}
