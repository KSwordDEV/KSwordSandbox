using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies restart recovery for compact job-persistence sidecars. Inputs are
/// synthetic job roots under the smoke runtime directory; processing corrupts
/// compact sidecar JSON, creates a huge invalid events.json, restarts the
/// service, and checks recovery without loading guest event payloads.
/// </summary>
internal sealed class JobPersistenceRecoveryScenario : ISmokeTestScenario
{
    private const string JobMetadataFileName = "job-metadata.json";
    private const string RunbookProgressFileName = "runbook-progress.json";
    private const string GuestImportStateFileName = "guest-import-state.json";
    private const long HugeEventsJsonBytes = 9L * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public string ScenarioId => "job-persistence.recovery.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var runtimeRoot = Path.Combine(context.RuntimeRoot, "job-persistence-recovery");
        Directory.CreateDirectory(runtimeRoot);
        var config = CreateConfig(runtimeRoot, context.RulesDirectory);
        var service = new SandboxJobService(config, new BehaviorRuleSet());
        var samplePath = WriteSample(runtimeRoot);

        var fallbackJob = CreateImportedJob(service, samplePath);
        var earlyJob = service.Plan(CreateSubmission(samplePath));
        var hugeEventsJob = service.Plan(CreateSubmission(samplePath));

        SetPersistedCreatedAt(earlyJob, runtimeRoot, new DateTimeOffset(2024, 01, 01, 00, 00, 00, TimeSpan.Zero));
        SetPersistedCreatedAt(hugeEventsJob, runtimeRoot, new DateTimeOffset(2024, 01, 02, 00, 00, 00, TimeSpan.Zero));
        var hugeEventsPath = WriteHugeInvalidEventsJson(runtimeRoot, hugeEventsJob.JobId);

        CorruptCompanionJson(runtimeRoot, fallbackJob.JobId, JobMetadataFileName);
        CorruptCompanionJson(runtimeRoot, fallbackJob.JobId, RunbookProgressFileName);
        CorruptCompanionJson(runtimeRoot, fallbackJob.JobId, GuestImportStateFileName);

        var recoveredService = new SandboxJobService(config, new BehaviorRuleSet());
        var recoveredJobs = recoveredService.ListJobs();
        AssertRecoveredJobList(recoveredJobs, fallbackJob.JobId, earlyJob.JobId, hugeEventsJob.JobId);

        var recoveredFallback = recoveredService.GetJob(fallbackJob.JobId);
        SmokeAssert.True(recoveredFallback is not null, "Job with corrupt compact sidecars should recover from report/runbook fallbacks.");
        SmokeAssert.True(File.Exists(JobFile(runtimeRoot, fallbackJob.JobId, JobMetadataFileName + ".bad")), "Corrupt job-metadata.json should be moved aside as job-metadata.json.bad.");
        SmokeAssert.True(File.Exists(JobFile(runtimeRoot, fallbackJob.JobId, GuestImportStateFileName + ".bad")), "Corrupt guest-import-state.json should be moved aside as guest-import-state.json.bad.");
        SmokeAssert.True(File.Exists(JobFile(runtimeRoot, fallbackJob.JobId, JobMetadataFileName)), "Recovered job metadata should be backfilled after corrupt metadata quarantine.");
        SmokeAssert.True(File.Exists(JobFile(runtimeRoot, fallbackJob.JobId, GuestImportStateFileName)), "Recovered guest import state should be backfilled after corrupt import-state quarantine.");

        SmokeAssert.True(
            recoveredService.TryGetRunbookProgress(fallbackJob.JobId, out var recoveredProgress),
            "Corrupt runbook-progress.json should fall back to runbook-execution.json.");
        SmokeAssert.True(recoveredProgress.JobId == fallbackJob.JobId, "Recovered progress snapshot should carry the requested job id.");
        SmokeAssert.True(File.Exists(JobFile(runtimeRoot, fallbackJob.JobId, RunbookProgressFileName + ".bad")), "Corrupt runbook-progress.json should be moved aside as runbook-progress.json.bad.");
        SmokeAssert.True(File.Exists(JobFile(runtimeRoot, fallbackJob.JobId, RunbookProgressFileName)), "Recovered runbook progress should be backfilled after corrupt progress quarantine.");

        var recoveredHugeJob = recoveredService.GetJob(hugeEventsJob.JobId);
        SmokeAssert.True(recoveredHugeJob is not null, "Job with a huge events.json should still recover from compact metadata.");
        SmokeAssert.True(
            string.Equals(recoveredHugeJob!.GuestEventsPath, hugeEventsPath, StringComparison.OrdinalIgnoreCase),
            "Recovery should discover the huge events.json path without parsing the payload.");
        AssertHugeEventsJsonIsSkippedByLiveMonitor(recoveredService, hugeEventsJob.JobId, hugeEventsPath);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Job persistence recovery quarantines corrupt compact sidecars, preserves ListJobs order, and skips huge events.json live parsing."
        });
    }

    private static SandboxConfig CreateConfig(string runtimeRoot, string rulesDirectory)
    {
        return new SandboxConfig
        {
            Paths = new SandboxPaths
            {
                RuntimeRoot = runtimeRoot,
                RulesDirectory = rulesDirectory,
                GuestPayloadRoot = Path.Combine(runtimeRoot, "payload", "guest-tools")
            },
            Driver = new DriverConfig
            {
                Enabled = false
            }
        };
    }

    private static string WriteSample(string runtimeRoot)
    {
        var samplePath = Path.Combine(runtimeRoot, "recovery-sample.exe");
        File.WriteAllText(samplePath, "not a real executable; used only for job persistence recovery smoke coverage");
        return samplePath;
    }

    private static SandboxSubmission CreateSubmission(string samplePath)
    {
        return new SandboxSubmission
        {
            SamplePath = samplePath,
            DisplayName = Path.GetFileName(samplePath),
            DurationSeconds = 5,
            DryRun = true
        };
    }

    private static AnalysisJob CreateImportedJob(SandboxJobService service, string samplePath)
    {
        var job = service.Plan(CreateSubmission(samplePath));
        var runbook = job.Runbook ?? throw new InvalidOperationException("Planned job should include a runbook.");
        var executed = service.SaveRunbookExecutionResult(job.JobId, new SandboxRunbookExecutionResult
        {
            JobId = job.JobId,
            TargetVmName = runbook.TargetVmName,
            Mode = SandboxRunbookExecutionMode.DryRun,
            Success = true,
            TotalSteps = runbook.Steps.Count,
            ExecutedSteps = 0,
            StartedAtUtc = DateTimeOffset.UtcNow,
            Duration = TimeSpan.Zero,
            RequiresElevation = runbook.Steps.Any(step => step.RequiresElevation)
        });

        var eventsPath = WriteSmallEventsJson(GetJobRootFromReport(executed), executed.JobId);
        return service.ImportGuestEvents(executed.JobId, eventsPath);
    }

    private static void SetPersistedCreatedAt(AnalysisJob job, string runtimeRoot, DateTimeOffset createdAt)
    {
        var metadataPath = JobFile(runtimeRoot, job.JobId, JobMetadataFileName);
        var metadata = JsonSerializer.Deserialize<AnalysisJob>(File.ReadAllText(metadataPath), JsonOptions)
            ?? throw new InvalidOperationException("Persisted job metadata should deserialize.");
        File.WriteAllText(metadataPath, JsonSerializer.Serialize(metadata with { CreatedAt = createdAt }, JsonOptions));
    }

    private static void AssertRecoveredJobList(IReadOnlyList<AnalysisJob> jobs, Guid fallbackJobId, Guid earlyJobId, Guid hugeEventsJobId)
    {
        SmokeAssert.True(jobs.Any(job => job.JobId == fallbackJobId), "ListJobs should include the job recovered through report fallback.");
        var earlyIndex = IndexOfJob(jobs, earlyJobId);
        var hugeEventsIndex = IndexOfJob(jobs, hugeEventsJobId);
        SmokeAssert.True(earlyIndex >= 0, "ListJobs should include the early metadata-backed job after restart.");
        SmokeAssert.True(hugeEventsIndex >= 0, "ListJobs should include the later metadata-backed job after restart.");
        SmokeAssert.True(earlyIndex < hugeEventsIndex, "ListJobs should preserve recovered creation-time ordering.");
    }

    private static int IndexOfJob(IReadOnlyList<AnalysisJob> jobs, Guid jobId)
    {
        for (var index = 0; index < jobs.Count; index++)
        {
            if (jobs[index].JobId == jobId)
            {
                return index;
            }
        }

        return -1;
    }

    private static void AssertHugeEventsJsonIsSkippedByLiveMonitor(SandboxJobService service, Guid jobId, string hugeEventsPath)
    {
        var snapshot = service.GetLiveEvents(jobId, offset: 0, take: 10);
        SmokeAssert.True(
            snapshot.Sources.Any(source => string.Equals(source, hugeEventsPath, StringComparison.OrdinalIgnoreCase)),
            "Live snapshot should list the huge events.json source without requiring full parsing.");
        var sourceStatus = snapshot.Events.FirstOrDefault(evt =>
            string.Equals(evt.EventType, "live.events.source_status", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(evt.Path, hugeEventsPath, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(sourceStatus is not null, "Huge events.json should produce a live source-status event.");
        SmokeAssert.True(
            sourceStatus!.Data.TryGetValue("status", out var status) &&
            string.Equals(status, "too-large", StringComparison.OrdinalIgnoreCase),
            "Huge events.json should be skipped with a too-large status instead of being parsed.");
        SmokeAssert.True(
            sourceStatus.Data.TryGetValue("sizeBytes", out var sizeText) &&
            long.TryParse(sizeText, out var sizeBytes) &&
            sizeBytes >= HugeEventsJsonBytes,
            "Huge events.json status should report the source size.");
    }

    private static string WriteSmallEventsJson(string jobRoot, Guid jobId)
    {
        var guestRoot = Path.Combine(jobRoot, "guest", jobId.ToString("N"));
        Directory.CreateDirectory(guestRoot);
        var eventsPath = Path.Combine(guestRoot, "events.json");
        var events = new[]
        {
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "recovery-smoke",
                ProcessId = 1001,
                Path = @"C:\KSwordSandbox\incoming\recovery-sample.exe"
            }
        };
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(events, JsonOptions));
        return eventsPath;
    }

    private static string WriteHugeInvalidEventsJson(string runtimeRoot, Guid jobId)
    {
        var guestRoot = Path.Combine(JobRoot(runtimeRoot, jobId), "guest", jobId.ToString("N"));
        Directory.CreateDirectory(guestRoot);
        var eventsPath = Path.Combine(guestRoot, "events.json");
        using var stream = new FileStream(eventsPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        stream.SetLength(HugeEventsJsonBytes);
        return eventsPath;
    }

    private static void CorruptCompanionJson(string runtimeRoot, Guid jobId, string fileName)
    {
        File.WriteAllText(JobFile(runtimeRoot, jobId, fileName), "{ this is not valid json");
    }

    private static string GetJobRootFromReport(AnalysisJob job)
    {
        return Path.GetDirectoryName(job.JsonReportPath ?? throw new InvalidOperationException("Job report path should be present."))
            ?? throw new InvalidOperationException("Job root should be discoverable from report path.");
    }

    private static string JobFile(string runtimeRoot, Guid jobId, string fileName)
    {
        return Path.Combine(JobRoot(runtimeRoot, jobId), fileName);
    }

    private static string JobRoot(string runtimeRoot, Guid jobId)
    {
        return Path.Combine(runtimeRoot, "jobs", jobId.ToString("N"));
    }
}
