using System.Globalization;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.Core.Network;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.Samples;
using KSword.Sandbox.Core.StaticAnalysis;
using KSword.Sandbox.Core.Telemetry;

namespace KSword.Sandbox.Core.Jobs;

/// <summary>
/// Coordinates validation, runbook planning, behavior classification, and
/// report artifact creation for v1 dry-run jobs. Inputs are submissions and
/// loaded configuration, processing creates deterministic local artifacts, and
/// methods return AnalysisJob records for the Web API.
/// </summary>
public sealed partial class SandboxJobService
{
    private const string EnrichmentEventsFileName = "enrichment-events.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private static readonly HashSet<string> EventKeyImportOnlyDataKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "artifactRelativePath",
        "artifactSafeLink",
        "artifactSelector",
        "canonicalArtifactSelector",
        "driverEventPath",
        "driverEventsPath",
        "driverEventsRelativePath",
        "importPath",
        "importRoot",
        "jsonlImportStatus",
        "jsonlPath",
        // Guest Agent annotates rows while importing the sidecar stream into
        // events.json. These fields are provenance metadata, not event
        // identity; ignoring them lets the sibling raw row deduplicate with
        // its already-imported counterpart.
        "jsonlLineNumber",
        "jsonlLineSelector",
        "jsonlLineCategory",
        "importAction",
        "eventOrigin",
        "producerCategory",
        "subjectKind",
        "actorRole",
        "subjectRole",
        "processIdSource",
        "attributionSummary",
        "noise",
        "selfNoise",
        "selfNoiseReason",
        "selfNoiseAction",
        "collectionNoise",
        "sourceArtifactKind",
        "sourceArtifactPath"
    };

    private readonly SandboxConfig config;
    private readonly RuleEngine ruleEngine;
    private readonly HyperVRunbookBuilder runbookBuilder;
    private readonly HtmlReportRenderer reportRenderer;
    private readonly StaticAnalyzer staticAnalyzer;
    private readonly HostArtifactIndexBuilder artifactIndexBuilder = new();
    private readonly LiveEventFeedService liveEventFeedService = new();
    private readonly Dictionary<Guid, AnalysisJob> jobs = [];

    /// <summary>
    /// Creates a job service from immutable runtime dependencies.
    /// Inputs are config, rules, runbook builder, and report renderer;
    /// processing stores defaults for later planning; the constructor returns
    /// no value.
    /// </summary>
    public SandboxJobService(
        SandboxConfig config,
        BehaviorRuleSet rules,
        HyperVRunbookBuilder? runbookBuilder = null,
        HtmlReportRenderer? reportRenderer = null,
        StaticAnalyzer? staticAnalyzer = null)
    {
        this.config = config;
        this.ruleEngine = new RuleEngine(rules);
        this.runbookBuilder = runbookBuilder ?? new HyperVRunbookBuilder();
        this.reportRenderer = reportRenderer ?? new HtmlReportRenderer();
        this.staticAnalyzer = staticAnalyzer ?? new StaticAnalyzer();
        RefreshRecoveredJobs();
    }

    /// <summary>
    /// Returns all known jobs in creation order.
    /// There are no inputs; processing snapshots the in-memory dictionary; the
    /// method returns a list of AnalysisJob records.
    /// </summary>
    public IReadOnlyList<AnalysisJob> ListJobs()
    {
        RefreshRecoveredJobs();
        lock (jobsSyncRoot)
        {
            return jobs.Values.OrderBy(job => job.CreatedAt).ToList();
        }
    }

    /// <summary>
    /// Replaces the behavior rules used for future planning and report
    /// rebuilds. The local WebUI calls this after persisting rules.json.
    /// </summary>
    public void ReplaceRules(BehaviorRuleSet rules)
    {
        ruleEngine.ReplaceRuleSet(rules);
    }

    /// <summary>
    /// Returns one job by ID when present.
    /// The input is a job ID, processing performs an in-memory lookup, and the
    /// method returns the job or null.
    /// </summary>
    public AnalysisJob? GetJob(Guid jobId)
    {
        lock (jobsSyncRoot)
        {
            if (jobs.TryGetValue(jobId, out var job))
            {
                return job;
            }
        }

        return TryRecoverJob(jobId, out var recovered) ? recovered : null;
    }

    /// <summary>
    /// Builds the current host-visible artifact index for one known job.
    /// Inputs are a job ID; processing scans the deterministic job directory
    /// for reports, telemetry, screenshots, memory dumps, packet captures, and
    /// dropped files; the method returns descriptors without loading payloads.
    /// </summary>
    public HostArtifactIndex BuildArtifactIndex(Guid jobId)
    {
        var job = GetJob(jobId);
        if (job is null)
        {
            throw new KeyNotFoundException($"Job {jobId:D} was not found in the in-memory job list.");
        }

        var jobConfig = BuildJobConfig(job.Submission, ResolveDuration(job.Submission));
        return artifactIndexBuilder.Build(jobId, GetJobRoot(jobId), jobConfig.ArtifactCollection);
    }

    /// <summary>
    /// Resolves a browser-supplied artifact selector to an indexed local file.
    /// Inputs are a job ID and relative/safe-link path from the artifact index;
    /// processing rejects unknown, missing, or out-of-job paths; the method
    /// returns a descriptor that is safe for the Web host to stream.
    /// </summary>
    public ArtifactDescriptor ResolveDownloadableArtifact(Guid jobId, string requestedPath)
    {
        var index = BuildArtifactIndex(jobId);
        var normalized = NormalizeArtifactSelector(requestedPath);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new ArgumentException("Artifact path is required and must be relative to the job output.", nameof(requestedPath));
        }

        var descriptor = index.Artifacts.FirstOrDefault(artifact =>
            ArtifactSelectorMatches(artifact.RelativePath, normalized) ||
            ArtifactSelectorMatches(artifact.SafeLink, normalized) ||
            ArtifactSelectorMatches(artifact.ImportPath, normalized));
        if (descriptor is null)
        {
            throw new FileNotFoundException($"Artifact '{requestedPath}' is not present in job {jobId:D} artifact index.");
        }

        var jobRoot = GetJobRoot(jobId);
        if (string.IsNullOrWhiteSpace(descriptor.FullPath) ||
            !File.Exists(descriptor.FullPath) ||
            !IsSameOrUnderDirectory(jobRoot, descriptor.FullPath))
        {
            throw new FileNotFoundException($"Artifact '{requestedPath}' is not available as a host-local file under the job output directory.");
        }

        return descriptor with { FullPath = Path.GetFullPath(descriptor.FullPath) };
    }

    /// <summary>
    /// Creates a planned job and writes JSON/HTML planning artifacts.
    /// Inputs are a SandboxSubmission, processing validates the sample, builds
    /// a provider-specific runbook, classifies seed events, and writes reports; the
    /// method returns the completed planning job.
    /// </summary>
    public AnalysisJob Plan(SandboxSubmission submission)
    {
        var duration = ResolveDuration(submission);
        var normalizedSubmission = NormalizeSubmission(submission, duration);
        var provider = normalizedSubmission.Provider ?? config.Virtualization.Provider;
        VirtualizationProviderResourceValidator.Validate(
            config,
            provider,
            normalizedSubmission.GoldenSnapshotName,
            normalizedSubmission.MachineDefinitionPath,
            normalizedSubmission.QemuDiskFormat);
        var jobId = Guid.NewGuid();
        var jobRoot = GetJobRoot(jobId);
        Directory.CreateDirectory(jobRoot);

        var sample = SampleHasher.Compute(normalizedSubmission.SamplePath, config.Analysis.MaxSampleBytes);
        var staticAnalysis = AnalyzeSample(sample);
        var jobConfig = BuildJobConfig(normalizedSubmission, duration);
        var runbook = runbookBuilder.Build(jobConfig, jobId, sample);

        var seedEvents = CreatePlanningEvents(sample, normalizedSubmission, runbook, staticAnalysis, jobConfig.ArtifactCollection);
        var findings = ruleEngine.Classify(seedEvents);
        var report = new AnalysisReport
        {
            JobId = jobId,
            Provider = runbook.Provider,
            TargetVmName = runbook.TargetVmName,
            BaselineName = runbook.BaselineName,
            MachineDefinitionPath = runbook.MachineDefinitionPath,
            QemuDiskFormat = runbook.QemuDiskFormat,
            Sample = sample,
            SampleIdentityStatus = "valid",
            Status = AnalysisStatus.Planned,
            StaticAnalysis = staticAnalysis,
            Events = seedEvents,
            Findings = findings,
            Metrics = BuildMetrics(seedEvents, findings, staticAnalysis),
            CollectionHealth = CollectionHealthSummaryBuilder.Build(seedEvents)
        };

        var jsonPath = Path.Combine(jobRoot, "report.json");
        var htmlPath = Path.Combine(jobRoot, "report.html");
        var zhHtmlPath = Path.Combine(jobRoot, "report.zh.html");
        var enHtmlPath = Path.Combine(jobRoot, "report.en.html");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, JsonOptions));
        WriteHtmlReports(jobRoot, report, jobConfig.ArtifactCollection);

        var job = new AnalysisJob
        {
            JobId = jobId,
            Submission = normalizedSubmission,
            Status = AnalysisStatus.Planned,
            Sample = sample,
            Runbook = runbook,
            JsonReportPath = jsonPath,
            HtmlReportPath = htmlPath,
            HtmlReportZhPath = zhHtmlPath,
            HtmlReportEnPath = enHtmlPath,
            Messages =
            [
                "Dry-run planning completed.",
                $"Review the runbook before enabling live {runbook.Provider} execution.",
                $"Artifacts written to {jobRoot}."
            ]
        };

        StoreJob(job);
        return job;
    }

    /// <summary>
    /// Persists one dry-run or live runbook execution result beside the job.
    /// Inputs are a job ID and executor result, processing writes
    /// runbook-execution.json and refreshes host report artifacts; the method
    /// returns the updated AnalysisJob.
    /// </summary>
    public AnalysisJob SaveRunbookExecutionResult(Guid jobId, SandboxRunbookExecutionResult result)
    {
        var job = GetJob(jobId);
        if (job is null)
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        if (job.Runbook is not null)
        {
            EnsureRunbookExecutionIdentityMatches(job.Runbook, result);
        }
        else if (result.JobId != jobId)
        {
            throw new InvalidDataException($"Runbook execution result job id {result.JobId:D} does not match target job {jobId:D}.");
        }

        var expectedProvider = job.Runbook?.Provider ?? job.Submission.Provider ?? config.Virtualization.Provider;
        result = result with
        {
            Provider = expectedProvider,
            TargetVmName = job.Runbook?.TargetVmName ?? result.TargetVmName,
            BaselineName = job.Runbook?.BaselineName ?? result.BaselineName,
            MachineDefinitionPath = job.Runbook?.MachineDefinitionPath ?? result.MachineDefinitionPath,
            QemuDiskFormat = job.Runbook?.QemuDiskFormat ?? result.QemuDiskFormat
        };

        var jobRoot = GetJobRoot(jobId);
        Directory.CreateDirectory(jobRoot);
        var resultPath = Path.Combine(jobRoot, "runbook-execution.json");
        // Readers poll this file while background execution is being reported.
        // Replace it atomically so recovery never sees a truncated JSON document
        // after a process interruption or concurrent report read.
        WriteJsonAtomically(resultPath, result);

        var status = result.Mode == SandboxRunbookExecutionMode.Live
            ? result.Success ? AnalysisStatus.Running : AnalysisStatus.Failed
            : job.Status;
        var existingGuestEvents = LoadGuestEventsIfPresent(job.GuestEventsPath);
        var submission = job.Submission with
        {
            DryRun = result.Mode != SandboxRunbookExecutionMode.Live
        };
        var messages = result.Mode == SandboxRunbookExecutionMode.Live
            ? job.Messages
                .Where(message =>
                    !message.StartsWith("Dry-run planning completed.", StringComparison.OrdinalIgnoreCase) &&
                    !message.StartsWith("Review the runbook before enabling live", StringComparison.OrdinalIgnoreCase))
                .Append($"Live runbook execution result persisted to {resultPath}.")
                .ToList()
            : AppendMessage(job.Messages, $"Runbook execution result persisted to {resultPath}.");
        var updated = RegenerateReport(job with
        {
            Status = status,
            RunbookExecutionResultPath = resultPath,
            Submission = submission,
            Messages = messages
        }, status, existingGuestEvents, job.GuestEventsPath);

        PersistRunbookProgress(updated, result);
        StoreJob(updated);
        return updated;
    }

    /// <summary>
    /// Imports guest events collected by the runbook and regenerates reports.
    /// Inputs are a job ID and optional events file path; processing locates
    /// events.json or JSONL output, merges optional driver JSONL files,
    /// re-runs rules, and returns the updated completed or failed job.
    /// </summary>
    public AnalysisJob ImportGuestEvents(Guid jobId, string? eventsPath = null)
    {
        var job = GetJob(jobId);
        if (job is null)
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        var resolvedEventsPath = ResolveGuestEventsPath(jobId, eventsPath);
        var guestEvents = LoadGuestEventsWithDriverJsonl(resolvedEventsPath, out var importSummary);
        var importedEventCount = guestEvents.Count;
        var sampleLaunchBlocked = HasTerminalSampleStartFailure(guestEvents);
        var agentFailed = guestEvents.Any(IsImportedAgentFailure) ||
            GuestFailureArtifactImporter.ImportRunbookFailure(job.RunbookExecutionResultPath).Count > 0;
        var status = importedEventCount == 0 || sampleLaunchBlocked || agentFailed
            ? AnalysisStatus.Failed
            : AnalysisStatus.Completed;
        var message = importedEventCount == 0
            ? $"来宾事件导入未发现事件，报告状态已标记为 Failed：{resolvedEventsPath} / Guest event import found no events in {resolvedEventsPath}."
            : agentFailed
                ? $"Guest Agent 运行失败或输出不完整，已导入 {guestEvents.Count} 个诊断/来宾事件；报告状态已标记为 Failed：{resolvedEventsPath} / Guest Agent failed or produced incomplete output; report status is Failed: {resolvedEventsPath}."
            : sampleLaunchBlocked
                ? $"样本启动被来宾拦截且未观察到成功启动，报告状态已标记为 Failed：{resolvedEventsPath} / The guest blocked sample launch and no successful sample start was observed; report status is Failed: {resolvedEventsPath}."
            : $"已导入 {guestEvents.Count} 个来宾事件：{resolvedEventsPath} / Imported {guestEvents.Count} guest event(s) from {resolvedEventsPath}.";
        var persistedSubmission = IsLiveRunbookExecution(job.RunbookExecutionResultPath)
            ? job.Submission with { DryRun = false }
            : job.Submission;
        if (guestEvents.Count == 0)
        {
            UpsertDurableHostEvent(jobId, CreateGuestImportOperationalMarker(
                "guest.events.import_failed",
                resolvedEventsPath,
                "guest-events-import-failed",
                "guest-event-import-failed-no-events-is-host-import-diagnostic-not-sample-behavior",
                message,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["guestImportOutcome"] = "failed",
                    ["failureKind"] = "no-events",
                    ["eventCount"] = "0",
                    ["eventsPath"] = resolvedEventsPath,
                    ["terminalStatus"] = AnalysisStatus.Failed.ToString()
                }));
        }

        var updated = RegenerateReport(job with
        {
            Status = status,
            Submission = persistedSubmission,
            GuestEventsPath = resolvedEventsPath,
            Messages = AppendMessage(job.Messages, message)
        }, status, guestEvents, resolvedEventsPath, importSummary);

        PersistGuestImportState(updated, resolvedEventsPath, importedEventCount, status, message);
        StoreJob(updated);
        return updated;
    }

    private static bool IsLiveRunbookExecution(string? resultPath)
    {
        if (string.IsNullOrWhiteSpace(resultPath) || !File.Exists(resultPath))
        {
            return false;
        }

        try
        {
            var result = JsonSerializer.Deserialize<SandboxRunbookExecutionResult>(File.ReadAllText(resultPath), JsonOptions);
            return result?.Mode == SandboxRunbookExecutionMode.Live;
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Records a successful live run where automatic guest import was disabled.
    /// Inputs are a job id and operator-facing reason; processing persists a
    /// host operational marker and regenerates reports with a terminal Completed
    /// state so the job never remains indefinitely Running.
    /// </summary>
    public AnalysisJob RecordGuestImportSkipped(Guid jobId, string? message = null)
    {
        var job = GetJob(jobId);
        if (job is null)
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        var terminalMessage = CleanOperatorMessage(
            message,
            "来宾事件自动导入已按请求跳过；live run 已成功，报告状态已收敛为 Completed / Guest event auto-import was skipped by request; live run succeeded and report status is Completed.");
        var guestEvents = LoadGuestEventsIfPresent(job.GuestEventsPath);
        var importedEventCount = guestEvents.Count;
        var markerPath = string.IsNullOrWhiteSpace(job.GuestEventsPath) ? GetJobRoot(jobId) : job.GuestEventsPath;
        UpsertDurableHostEvent(jobId, CreateGuestImportOperationalMarker(
            "guest.events.import_skipped",
            markerPath,
            "guest-events-import-skipped",
            "guest-event-import-skipped-is-host-policy-not-sample-behavior",
            terminalMessage,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["guestImportOutcome"] = "skipped",
                ["failureKind"] = string.Empty,
                ["eventCount"] = importedEventCount.ToString(),
                ["importGuestEvents"] = "false",
                ["terminalStatus"] = AnalysisStatus.Completed.ToString()
            }));

        var updated = RegenerateReport(job with
        {
            Status = AnalysisStatus.Completed,
            Submission = job.Submission with { DryRun = false },
            Messages = AppendMessage(job.Messages, terminalMessage)
        }, AnalysisStatus.Completed, guestEvents, job.GuestEventsPath);

        PersistGuestImportState(updated, job.GuestEventsPath, importedEventCount, AnalysisStatus.Completed, terminalMessage);
        StoreJob(updated);
        return updated;
    }

    /// <summary>
    /// Records an automatic guest import failure after a successful live run.
    /// Inputs are a job id, failure reason, and optional candidate events path;
    /// processing persists a nonbehavior host marker and regenerates reports as
    /// Failed so the publishing path cannot leave report/job state Running.
    /// </summary>
    public AnalysisJob RecordGuestImportFailure(Guid jobId, string? message, string? eventsPath = null)
    {
        var job = GetJob(jobId);
        if (job is null)
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        var terminalMessage = CleanOperatorMessage(
            message,
            "来宾事件自动导入失败；报告状态已收敛为 Failed / Guest event auto-import failed; report status is Failed.");
        var normalizedEventsPath = NormalizeOptionalPath(eventsPath);
        var existingGuestEvents = LoadGuestEventsIfPresent(job.GuestEventsPath);
        var markerPath = normalizedEventsPath ?? job.GuestEventsPath ?? GetJobRoot(jobId);
        UpsertDurableHostEvent(jobId, CreateGuestImportOperationalMarker(
            "guest.events.import_failed",
            markerPath,
            "guest-events-import-failed",
            "guest-event-import-failed-is-host-import-diagnostic-not-sample-behavior",
            terminalMessage,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["guestImportOutcome"] = "failed",
                ["failureKind"] = "exception",
                ["eventCount"] = "0",
                ["eventsPath"] = normalizedEventsPath ?? string.Empty,
                ["terminalStatus"] = AnalysisStatus.Failed.ToString()
            }));

        var updated = RegenerateReport(job with
        {
            Status = AnalysisStatus.Failed,
            Messages = AppendMessage(job.Messages, terminalMessage)
        }, AnalysisStatus.Failed, existingGuestEvents, job.GuestEventsPath);

        PersistGuestImportState(updated, normalizedEventsPath ?? job.GuestEventsPath, 0, AnalysisStatus.Failed, terminalMessage);
        StoreJob(updated);
        return updated;
    }

    /// <summary>
    /// Imports an already executed provider runbook that was produced outside the
    /// in-memory WebUI process. Inputs are the deterministic job id, original
    /// sample submission, collected guest events path, and optional
    /// runbook-execution record; processing reconstructs the same runbook,
    /// merges guest/driver JSONL events, classifies behavior, and writes
    /// report.json/report.html/report.zh.html/report.en.html under the job
    /// directory. The method returns the regenerated job metadata.
    /// </summary>
    public AnalysisJob ImportExternalRun(
        Guid jobId,
        SandboxSubmission submission,
        string eventsPath,
        string? runbookExecutionResultPath = null)
    {
        if (jobId == Guid.Empty)
        {
            throw new ArgumentException("Job id is required.", nameof(jobId));
        }

        if (string.IsNullOrWhiteSpace(eventsPath))
        {
            throw new ArgumentException("Guest events path is required.", nameof(eventsPath));
        }

        var duration = ResolveDuration(submission);
        var normalizedSubmission = NormalizeSubmission(submission, duration);
        var existingJob = GetJob(jobId);
        if (existingJob?.Runbook is null)
        {
            var provider = normalizedSubmission.Provider ?? config.Virtualization.Provider;
            VirtualizationProviderResourceValidator.Validate(
                config,
                provider,
                normalizedSubmission.GoldenSnapshotName,
                normalizedSubmission.MachineDefinitionPath,
                normalizedSubmission.QemuDiskFormat);
        }

        var jobRoot = GetJobRoot(jobId);
        Directory.CreateDirectory(jobRoot);

        // Capture persisted identity before replacing the in-memory job.  A
        // stale report or metadata file must be rejected rather than silently
        // becoming the identity of a newly rebuilt report.
        var persistedSample = existingJob?.Sample;
        var persistedReport = LoadExistingReport(
            existingJob?.JsonReportPath ?? Path.Combine(jobRoot, "report.json"));

        var sample = SampleHasher.Compute(normalizedSubmission.SamplePath, config.Analysis.MaxSampleBytes);
        var staticAnalysis = AnalyzeSample(sample);
        var jobConfig = BuildJobConfig(normalizedSubmission, duration);
        EnsureExternalImportPreservesPersistedIdentity(existingJob, normalizedSubmission);
        var runbook = existingJob?.Runbook ?? runbookBuilder.Build(jobConfig, jobId, sample);
        var persistedSubmission = existingJob?.Runbook is not null
            ? existingJob.Submission with { DryRun = false }
            : normalizedSubmission with { DryRun = false };
        var jsonPath = Path.Combine(jobRoot, "report.json");
        var htmlPath = Path.Combine(jobRoot, "report.html");
        var zhHtmlPath = Path.Combine(jobRoot, "report.zh.html");
        var enHtmlPath = Path.Combine(jobRoot, "report.en.html");
        var resultPath = NormalizeExternalRunbookExecutionPath(jobRoot, runbookExecutionResultPath, runbook);

        var messages = existingJob?.Messages.ToList() ?? [];
        AddUniqueMessage(messages, $"Imported external {runbook.Provider} execution.");
        AddUniqueMessage(messages, $"Guest event import source: {eventsPath}.");
        var job = new AnalysisJob
        {
            JobId = jobId,
            CreatedAt = existingJob?.CreatedAt ?? DateTimeOffset.UtcNow,
            Submission = persistedSubmission,
            Status = AnalysisStatus.Running,
            Sample = sample,
            Runbook = runbook,
            JsonReportPath = jsonPath,
            HtmlReportPath = htmlPath,
            HtmlReportZhPath = zhHtmlPath,
            HtmlReportEnPath = enHtmlPath,
            RunbookExecutionResultPath = resultPath,
            Messages = messages
        };

        StoreJob(job);
        var guestEvents = LoadGuestEventsWithDriverJsonl(eventsPath, out var importSummary);
        var importedEventCount = guestEvents.Count;
        var failureSkeleton = guestEvents.Any(evt =>
            string.Equals(evt.EventType, "hyperv.e2e.failure_skeleton", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, "vmware.e2e.failure_skeleton", StringComparison.OrdinalIgnoreCase));
        var failedRunbook = IsFailedRunbookExecution(resultPath);
        var sampleLaunchBlocked = HasTerminalSampleStartFailure(guestEvents);
        var agentFailed = guestEvents.Any(IsImportedAgentFailure) ||
            GuestFailureArtifactImporter.ImportRunbookFailure(resultPath).Count > 0;
        var status = failureSkeleton || failedRunbook || sampleLaunchBlocked || agentFailed || importedEventCount == 0
            ? AnalysisStatus.Failed
            : AnalysisStatus.Completed;
        var message = importedEventCount == 0
            ? $"External guest event import found no events in {eventsPath}."
            : agentFailed
                ? $"Imported {importedEventCount} diagnostic guest event(s) from {eventsPath}; Guest Agent failure keeps report status Failed."
            : sampleLaunchBlocked
                ? $"Imported {importedEventCount} diagnostic guest event(s) from {eventsPath}; no successful sample start was observed, so report status is Failed."
            : failedRunbook || failureSkeleton
                ? $"Imported {importedEventCount} diagnostic guest event(s) from {eventsPath}; runbook failure keeps report status Failed."
                : $"Imported {importedEventCount} external guest/driver event(s) from {eventsPath}.";
        var updated = RegenerateReport(job with
        {
            Status = status,
            GuestEventsPath = Path.GetFullPath(eventsPath),
            Messages = AppendMessage(job.Messages, message)
        }, status, guestEvents, eventsPath, importSummary, persistedSample, persistedReport?.Sample);

        PersistGuestImportState(updated, Path.GetFullPath(eventsPath), importedEventCount, status, message);
        StoreJob(updated);
        return updated;
    }

    private static bool HasTerminalSampleStartFailure(IReadOnlyCollection<SandboxEvent> guestEvents)
    {
        var launchFailures = guestEvents
            .Where(evt => string.Equals(evt.EventType, "process.start_failed", StringComparison.OrdinalIgnoreCase))
            .Where(IsIncomingSampleProcessEvent)
            .ToList();
        if (launchFailures.Count == 0)
        {
            return false;
        }

        // A transient retry may emit process.start_failed before a successful
        // retry. Only treat the launch as terminal when no matching successful
        // start was observed in the guest event stream.
        return !guestEvents.Any(evt =>
            string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase) &&
            IsIncomingSampleProcessEvent(evt));
    }

    private static bool IsImportedAgentFailure(SandboxEvent evt)
    {
        if (string.Equals(evt.EventType, "sample.runtime.preflight.failed", StringComparison.OrdinalIgnoreCase) &&
            EventDataTruthy(evt, "collectionHealth", "sampleRuntimePreflight"))
        {
            return true;
        }

        if (!evt.EventType.StartsWith("agent.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (evt.EventType.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("failure", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Contains("error", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return evt.Data.TryGetValue("exitCode", out var exit) &&
            int.TryParse(exit, out var code) && code != 0;
    }

    private static bool IsIncomingSampleProcessEvent(SandboxEvent evt)
    {
        return evt.Path?.Contains("\\incoming\\", StringComparison.OrdinalIgnoreCase) == true ||
            evt.CommandLine?.Contains("\\incoming\\", StringComparison.OrdinalIgnoreCase) == true;
    }

    private static bool IsFailedRunbookExecution(string? resultPath)
    {
        if (string.IsNullOrWhiteSpace(resultPath) || !File.Exists(resultPath))
        {
            return false;
        }

        try
        {
            var result = JsonSerializer.Deserialize<SandboxRunbookExecutionResult>(File.ReadAllText(resultPath), JsonOptions);
            return result is not null && !result.Success;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return false;
        }
    }

    private static void EnsureExternalImportPreservesPersistedIdentity(AnalysisJob? existingJob, SandboxSubmission submission)
    {
        var runbook = existingJob?.Runbook;
        if (runbook is null)
        {
            return;
        }

        var identityMatches =
            (!submission.Provider.HasValue || submission.Provider.Value == runbook.Provider) &&
            MatchesPersistedIdentity(
                submission.SamplePath,
                existingJob?.Sample?.FullPath,
                existingJob?.Submission.SamplePath) &&
            MatchesPersistedIdentity(
                submission.GoldenVmName,
                runbook.TargetVmName,
                existingJob?.Submission.GoldenVmName) &&
            MatchesPersistedIdentity(
                submission.GoldenSnapshotName,
                runbook.BaselineName,
                existingJob?.Submission.GoldenSnapshotName) &&
            MatchesPersistedIdentity(submission.MachineDefinitionPath, runbook.MachineDefinitionPath) &&
            MatchesPersistedIdentity(submission.QemuDiskFormat, runbook.QemuDiskFormat);

        if (!identityMatches)
        {
            throw new InvalidOperationException(
                $"Job {existingJob!.JobId:D} already persists its {runbook.Provider} runbook identity; external import cannot rewrite its sample, provider, VM, clean baseline, or machine definition.");
        }
    }

    private static bool MatchesPersistedIdentity(string? requested, params string?[] persistedValues)
    {
        return string.IsNullOrWhiteSpace(requested) || persistedValues.Any(value =>
            !string.IsNullOrWhiteSpace(value) &&
            string.Equals(requested.Trim(), value.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    private static void EnsureRunbookExecutionIdentityMatches(
        SandboxRunbook runbook,
        SandboxRunbookExecutionResult result)
    {
        if (result.JobId != runbook.JobId)
        {
            throw new InvalidDataException(
                $"Runbook execution result job id {result.JobId:D} does not match persisted runbook {runbook.JobId:D}.");
        }

        var identityMatches = result.Provider == runbook.Provider &&
            MatchesPersistedIdentity(result.TargetVmName, runbook.TargetVmName) &&
            MatchesPersistedIdentity(result.BaselineName, runbook.BaselineName) &&
            MatchesPersistedIdentity(result.MachineDefinitionPath, runbook.MachineDefinitionPath) &&
            MatchesPersistedIdentity(result.QemuDiskFormat, runbook.QemuDiskFormat);
        if (!identityMatches)
        {
            throw new InvalidDataException(
                $"Runbook execution result conflicts with the persisted {runbook.Provider} provider, VM, clean baseline, or machine definition identity.");
        }
    }

    /// <summary>
    /// Upserts one host-side enrichment event and regenerates the report. Inputs
    /// are a known job id, a normalized event such as a VirusTotal lookup, and
    /// an operator-safe message; processing persists the event under the job
    /// root so future report regenerations keep it, then re-runs rules and
    /// report rendering. The method returns updated job metadata.
    /// </summary>
    public AnalysisJob UpsertEnrichmentEvent(Guid jobId, SandboxEvent enrichmentEvent, string message)
    {
        var job = GetJob(jobId);
        if (job is null)
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        UpsertDurableHostEvent(jobId, enrichmentEvent);

        var guestEvents = LoadGuestEventsIfPresent(job.GuestEventsPath);
        var updated = RegenerateReport(job with
        {
            Messages = AppendMessage(job.Messages, message)
        }, job.Status, guestEvents, job.GuestEventsPath);

        StoreJob(updated);
        return updated;
    }

    /// <summary>
    /// Upserts one durable host-side event under enrichment-events.json.
    /// Inputs are a job id and normalized/normalizable event; processing uses
    /// the same source/event/path identity as enrichment updates so operational
    /// markers survive future report regeneration without accumulating copies.
    /// </summary>
    private void UpsertDurableHostEvent(Guid jobId, SandboxEvent hostEvent)
    {
        var jobRoot = GetJobRoot(jobId);
        Directory.CreateDirectory(jobRoot);
        var enrichmentPath = GetEnrichmentEventsPath(jobId);
        var existing = LoadEventsIfPresent(enrichmentPath);
        var normalized = NormalizeEvent(hostEvent);
        var nextEvents = existing
            .Where(evt => !SameEnrichmentIdentity(evt, normalized))
            .Select(NormalizeEvent)
            .ToList();
        nextEvents.Add(normalized);
        nextEvents = nextEvents
            .OrderBy(evt => evt.Timestamp)
            .ThenBy(evt => evt.EventType, StringComparer.OrdinalIgnoreCase)
            .ThenBy(evt => evt.Source, StringComparer.OrdinalIgnoreCase)
            .ToList();
        File.WriteAllText(enrichmentPath, JsonSerializer.Serialize(nextEvents, JsonOptions));
    }

    /// <summary>
    /// Returns raw events for the WebUI live monitor without rule classification.
    /// Inputs are a job ID plus offset/take paging values; processing reads any
    /// current guest JSON/JSONL artifacts and falls back to the persisted report
    /// events when guest output is not present yet; the method returns an
    /// ordered, unclassified LiveEventSnapshot for polling UI clients.
    /// </summary>
    public LiveEventSnapshot GetLiveEvents(Guid jobId, int offset = 0, int take = 100)
    {
        var job = GetJob(jobId);
        if (job is null)
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        var normalizedOffset = Math.Max(0, offset);
        var normalizedTake = Math.Clamp(take, 1, 500);

        var livePaths = EnumerateLiveEventFiles(job).ToList();
        var liveSnapshot = liveEventFeedService.Build(jobId, livePaths, normalizedOffset, normalizedTake);
        if (liveSnapshot.TotalEvents > 0 || liveSnapshot.Sources.Count > 0)
        {
            return liveSnapshot;
        }

        var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var eventKeys = new HashSet<string>(StringComparer.Ordinal);
        var events = new List<SandboxEvent>();

        if (events.Count == 0)
        {
            var existingReport = LoadExistingReport(job.JsonReportPath);
            if (existingReport is not null)
            {
                foreach (var reportEvent in existingReport.Events.Select(NormalizeEvent))
                {
                    if (eventKeys.Add(EventKey(reportEvent)))
                    {
                        events.Add(reportEvent);
                    }
                }

                if (!string.IsNullOrWhiteSpace(job.JsonReportPath))
                {
                    sources.Add(job.JsonReportPath);
                }
            }
        }

        events = events
            .OrderBy(evt => evt.Timestamp)
            .ThenBy(evt => evt.EventType, StringComparer.OrdinalIgnoreCase)
            .ThenBy(evt => evt.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var page = events.Skip(normalizedOffset).Take(normalizedTake).ToList();
        var nextOffset = Math.Min(events.Count, normalizedOffset + page.Count);
        return new LiveEventSnapshot
        {
            JobId = jobId,
            TotalEvents = events.Count,
            NextOffset = nextOffset,
            HasMore = nextOffset < events.Count,
            Sources = sources.OrderBy(source => source, StringComparer.OrdinalIgnoreCase).ToList(),
            Events = page
        };
    }

    /// <summary>
    /// Loads events for the polling live monitor without failing the request.
    /// The input is a JSON or JSONL artifact path that may still be changing;
    /// processing shares reads with writers and converts parse or IO failures
    /// into a synthetic host event; the method returns zero or more normalized
    /// events suitable for raw display only.
    /// </summary>
    private static List<SandboxEvent> TryLoadEventsForLiveMonitor(string path)
    {
        try
        {
            if (ArtifactDescriptorFactory.IsPacketCapturePath(path))
            {
                return new PcapArtifactEventImporter().Import(path).Select(NormalizeEvent).ToList();
            }

            return LoadEventsIfPresent(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return
            [
                new SandboxEvent
                {
                    EventType = "live.events.read_pending",
                    Source = "host",
                    Path = path,
                    Data = CreateHostOperationalEventData(
                        "live-events-read-pending",
                        "live-monitor-read-is-transient-not-sample-behavior",
                        "Live monitor source is still being written; this diagnostic is not sample behavior.",
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["exceptionType"] = ex.GetType().Name,
                        ["message"] = ex.Message
                    })
                }
            ];
        }
    }

    private static GuestSampleIdentity ResolveGuestSampleIdentity(
        IReadOnlyCollection<SandboxEvent> guestEvents,
        string? guestEventsPath)
    {
        string? path = null;
        string? sha256 = null;
        long? sizeBytes = null;

        // Prefer explicit samplePath fields emitted by the agent. Restricting
        // the fallback to sample lifecycle rows avoids treating an artifact
        // path as the guest input identity.
        foreach (var evt in guestEvents)
        {
            if (evt.Data.TryGetValue("samplePath", out var eventPath) &&
                !string.IsNullOrWhiteSpace(eventPath))
            {
                path ??= eventPath;
            }

            if (evt.Data.TryGetValue("sampleSha256", out var eventHash) &&
                !string.IsNullOrWhiteSpace(eventHash))
            {
                sha256 ??= eventHash;
            }

            if (evt.Data.TryGetValue("sampleSizeBytes", out var eventSize) &&
                long.TryParse(eventSize, out var parsedSize) &&
                parsedSize >= 0)
            {
                sizeBytes ??= parsedSize;
            }

            if (path is null &&
                (string.Equals(evt.EventType, "agent.start", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase)) &&
                evt.Path?.Contains("\\incoming\\", StringComparison.OrdinalIgnoreCase) == true)
            {
                path = evt.Path;
            }
        }

        // The compact summary is produced even when events are heavily
        // sampled. Older summaries contain only the guest path; newer ones
        // may carry the guest SHA-256 and size.
        if (!string.IsNullOrWhiteSpace(guestEventsPath))
        {
            var summaryPath = Path.Combine(
                Path.GetDirectoryName(Path.GetFullPath(guestEventsPath)) ?? string.Empty,
                "agent-summary.json");
            if (File.Exists(summaryPath))
            {
                try
                {
                    using var document = JsonDocument.Parse(File.ReadAllText(summaryPath));
                    var root = document.RootElement;
                    path ??= ReadJsonString(root, "sample", "samplePath");
                    sha256 ??= ReadJsonString(root, "sampleSha256", "sha256");
                    if (!sizeBytes.HasValue &&
                        root.TryGetProperty("sampleSizeBytes", out var sizeElement) &&
                        sizeElement.TryGetInt64(out var summarySize) && summarySize >= 0)
                    {
                        sizeBytes = summarySize;
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                {
                    // Legacy imports may not contain a summary. Collection
                    // health retains that fact; report rebuild remains usable.
                }
            }
        }

        return new GuestSampleIdentity(path, sha256, sizeBytes);
    }

    private static string? ReadJsonString(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (root.TryGetProperty(name, out var value) &&
                value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    return text;
                }
            }
        }

        return null;
    }

    private static SandboxEvent CreateSampleIdentityMismatchEvent(
        SampleIdentity sample,
        SampleIdentityValidationResult identity)
    {
        return new SandboxEvent
        {
            EventType = "sample.identity_mismatch",
            Source = "host",
            Path = sample.FullPath,
            ProcessName = sample.FileName,
            Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["notSampleBehavior"] = "true",
                ["sampleIdentityStatus"] = identity.Status,
                ["sampleIdentityIssues"] = string.Join(",", identity.Issues),
                ["zhHint"] = "样本身份与任务元数据、报告或来宾输入不一致；本报告不可作为有效样本结果。"
            }
        };
    }

    private sealed record GuestSampleIdentity(string? Path, string? Sha256, long? SizeBytes);

    /// <summary>
    /// Rewrites report.json and report.html from current host and guest data.
    /// Inputs are job metadata, target status, guest events, and source path;
    /// processing rebuilds deterministic host seed events, appends execution
    /// and import markers, classifies all events, and returns updated metadata.
    /// </summary>
    private AnalysisJob RegenerateReport(
        AnalysisJob job,
        AnalysisStatus status,
        List<SandboxEvent> guestEvents,
        string? guestEventsPath,
        GuestEventImportSummary? importSummary = null,
        SampleIdentity? persistedMetadataSample = null,
        SampleIdentity? persistedReportSample = null)
    {
        var sample = job.Sample ?? throw new InvalidOperationException("Job does not have sample metadata.");
        var runbook = job.Runbook ?? throw new InvalidOperationException("Job does not have a runbook.");
        var jobRoot = GetJobRoot(job.JobId);
        Directory.CreateDirectory(jobRoot);

        var previousReport = LoadExistingReport(job.JsonReportPath);
        var staticAnalysis = previousReport?.StaticAnalysis ?? AnalyzeSample(sample);
        var guestIdentity = ResolveGuestSampleIdentity(guestEvents, guestEventsPath);
        var identity = SampleIdentityValidation.Validate(
            sample,
            persistedMetadataSample ?? job.Sample,
            persistedReportSample ?? previousReport?.Sample,
            job.Submission.SamplePath,
            guestIdentity.Path,
            guestIdentity.Sha256,
            guestIdentity.SizeBytes);
        var jobConfig = BuildJobConfig(job.Submission, ResolveDuration(job.Submission));
        var events = CreatePlanningEvents(sample, job.Submission, runbook, staticAnalysis, jobConfig.ArtifactCollection);
        if (!identity.IsValid)
        {
            events.Add(CreateSampleIdentityMismatchEvent(sample, identity));
        }
        AppendRunbookExecutionEvent(events, job.RunbookExecutionResultPath, runbook.Provider);
        events.AddRange(GuestFailureArtifactImporter.ImportRunbookFailure(job.RunbookExecutionResultPath));
        events.AddRange(LoadEnrichmentEvents(job.JobId));
        events.AddRange(guestEvents.Select(NormalizeEvent));
        AppendGuestImportEvent(events, guestEventsPath, guestEvents.Count, importSummary);
        var artifactIndex = artifactIndexBuilder.Build(job.JobId, jobRoot);
        events.AddRange(BuildHostArtifactImportEvents(jobConfig.ArtifactCollection, jobRoot, guestEventsPath, artifactIndex, events));

        var fullEvents = SampleCorrelationClassifier.Apply(events.OrderBy(evt => evt.Timestamp), sample.FullPath);
        var rawFindings = ruleEngine.Classify(fullEvents);
        var findings = ReportEventSampler.SanitizeFindings(rawFindings);
        var driverEventPaths = importSummary?.DriverPaths ?? [];
        var driverEventsPath = driverEventPaths.FirstOrDefault(path =>
                string.Equals(Path.GetFileName(path), "driver-events.jsonl", StringComparison.OrdinalIgnoreCase)) ??
            driverEventPaths.FirstOrDefault() ??
            (string.IsNullOrWhiteSpace(guestEventsPath)
                ? null
                : Path.Combine(Path.GetDirectoryName(guestEventsPath) ?? string.Empty, "driver-events.jsonl"));
        var sampling = ReportEventSampler.SampleForReport(
            fullEvents,
            jobRoot: jobRoot,
            eventsPath: guestEventsPath,
            driverEventsPath: driverEventsPath,
            driverEventsPaths: driverEventPaths,
            findings: rawFindings);
        var effectiveStatus = identity.IsValid ? status : AnalysisStatus.Failed;
        var messages = identity.IsValid
            ? job.Messages
            : AppendMessage(
                job.Messages,
                $"样本身份校验失败，报告不可作为有效样本结果：{string.Join(", ", identity.Issues)} / Sample identity validation failed; report is not a valid sample result: {string.Join(", ", identity.Issues)}.");
        var report = new AnalysisReport
        {
            JobId = job.JobId,
            Provider = runbook.Provider,
            TargetVmName = runbook.TargetVmName,
            BaselineName = runbook.BaselineName,
            MachineDefinitionPath = runbook.MachineDefinitionPath,
            QemuDiskFormat = runbook.QemuDiskFormat,
            Sample = sample,
            SampleIdentityStatus = identity.Status,
            SampleIdentityIssues = identity.Issues,
            Status = effectiveStatus,
            StaticAnalysis = staticAnalysis,
            Events = sampling.Events,
            Findings = findings,
            Metrics = BuildMetrics(sampling.Events, findings, staticAnalysis, fullEvents.Count, sampling.OmittedEventCount, fullEvents, importSummary),
            CollectionHealth = CollectionHealthSummaryBuilder.Build(fullEvents, sampling.Events)
        };

        var jsonPath = Path.Combine(jobRoot, "report.json");
        var htmlPath = Path.Combine(jobRoot, "report.html");
        var zhHtmlPath = Path.Combine(jobRoot, "report.zh.html");
        var enHtmlPath = Path.Combine(jobRoot, "report.en.html");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, JsonOptions));

        // The imported guest list and the derived full event/finding lists can
        // be orders of magnitude larger than the bounded report model.  Keep
        // them alive only through report.json serialization: HTML rendering
        // needs the report model, not the raw classification graph.  Clearing
        // the owned lists here also releases the caller's large guest list
        // before the expensive bilingual renderer starts.  Callers capture
        // the imported count before entering this method for persistence.
        var transientEventCount = fullEvents.Count;
        ReleaseTransientReportBuffers(guestEvents, events, fullEvents, rawFindings);
        if (transientEventCount >= 50_000)
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: false);
            GC.WaitForPendingFinalizers();
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: false);
        }

        WriteHtmlReports(jobRoot, report, jobConfig.ArtifactCollection);

        return job with
        {
            Status = effectiveStatus,
            Messages = messages,
            JsonReportPath = jsonPath,
            HtmlReportPath = htmlPath,
            HtmlReportZhPath = zhHtmlPath,
            HtmlReportEnPath = enHtmlPath,
            GuestEventsPath = guestEventsPath ?? job.GuestEventsPath
        };
    }

    /// <summary>
    /// Drops the large mutable collections that are no longer needed after
    /// report.json has been serialized. Inputs are the imported guest rows and
    /// derived classification buffers owned by one regeneration; processing
    /// clears them in place so the caller cannot keep a second copy alive while
    /// HTML is rendered. The method returns no value.
    /// </summary>
    private static void ReleaseTransientReportBuffers(
        List<SandboxEvent> guestEvents,
        List<SandboxEvent> events,
        List<SandboxEvent> fullEvents,
        List<BehaviorFinding> rawFindings)
    {
        ClearAndRelease(guestEvents);
        ClearAndRelease(events);
        ClearAndRelease(fullEvents);
        ClearAndRelease(rawFindings);
    }

    /// <summary>
    /// Clears a mutable list and drops its oversized backing array. The input
    /// is one transient collection owned by report regeneration; processing
    /// returns no value.
    /// </summary>
    private static void ClearAndRelease<T>(List<T> values)
    {
        values.Clear();
        values.TrimExcess();
    }

    /// <summary>
    /// Writes the default compatibility report plus explicit localized report
    /// variants. Inputs are one job directory and report model; processing keeps
    /// report.html Chinese for the default compatibility report and emits
    /// report.zh.html / report.en.html for explicit bilingual WebUI links; the
    /// method returns no value.
    /// </summary>
    private void WriteHtmlReports(string jobRoot, AnalysisReport report, ArtifactCollectionConfig artifactCollection)
    {
        var artifactIndex = artifactIndexBuilder.Build(report.JobId, jobRoot, artifactCollection);
        var englishHtml = reportRenderer.RenderEnglish(report, artifactIndex.Artifacts, artifactIndex.Collections);
        // Build the expensive evidence sections once. Localizing the completed
        // English payload avoids a second full graph/timeline/event traversal
        // for large R0 reports and keeps bilingual files synchronized.
        var chineseHtml = reportRenderer.LocalizeChineseFromEnglish(englishHtml, report);
        File.WriteAllText(Path.Combine(jobRoot, "report.html"), chineseHtml);
        File.WriteAllText(Path.Combine(jobRoot, "report.zh.html"), chineseHtml);
        File.WriteAllText(Path.Combine(jobRoot, "report.en.html"), englishHtml);

        artifactIndexBuilder.WriteIndex(report.JobId, jobRoot, artifactCollection);
    }

    /// <summary>
    /// Returns the deterministic runtime folder for one job.
    /// The input is a job ID, processing combines runtime root and job ID, and
    /// the method returns an absolute or configured local path.
    /// </summary>
    private string GetJobRoot(Guid jobId)
    {
        return Path.Combine(config.Paths.RuntimeRoot, "jobs", jobId.ToString("N"));
    }

    private string GetEnrichmentEventsPath(Guid jobId)
    {
        return Path.Combine(GetJobRoot(jobId), EnrichmentEventsFileName);
    }

    private static string? NormalizeExternalRunbookExecutionPath(
        string jobRoot,
        string? runbookExecutionResultPath,
        SandboxRunbook runbook)
    {
        if (string.IsNullOrWhiteSpace(runbookExecutionResultPath))
        {
            return null;
        }

        var fullPath = Path.GetFullPath(runbookExecutionResultPath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Runbook execution record was not found.", fullPath);
        }

        SandboxRunbookExecutionResult execution;
        try
        {
            execution = JsonSerializer.Deserialize<SandboxRunbookExecutionResult>(File.ReadAllText(fullPath), JsonOptions)
                ?? throw new InvalidDataException("Runbook execution record was empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Runbook execution record is not valid JSON.", ex);
        }
        EnsureRunbookExecutionIdentityMatches(runbook, execution);

        if (IsSameOrUnderDirectory(jobRoot, fullPath))
        {
            return fullPath;
        }

        Directory.CreateDirectory(jobRoot);
        var destination = Path.Combine(jobRoot, "runbook-execution.json");
        File.Copy(fullPath, destination, overwrite: true);
        return destination;
    }

    private void EnsureJobExists(Guid jobId)
    {
        if (GetJob(jobId) is null)
        {
            throw new KeyNotFoundException($"Job {jobId:D} was not found in the in-memory job list.");
        }
    }

    private static bool ArtifactSelectorMatches(string candidate, string normalizedRequestedPath)
    {
        return string.Equals(NormalizeArtifactSelector(candidate), normalizedRequestedPath, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeArtifactSelector(string? value)
    {
        return ArtifactDescriptorFactory.NormalizeSelector(value);
    }

    private static bool IsSameOrUnderDirectory(string rootPath, string candidatePath)
    {
        var root = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(candidatePath);
        return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Loads an existing report when static-analysis data can be reused.
    /// The input is an optional JSON path, processing tolerates missing or
    /// corrupt files, and the method returns a report or null.
    /// </summary>
    private static AnalysisReport? LoadExistingReport(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(path), JsonOptions);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the guest event artifact for a WebUI job.
    /// Inputs are job ID and optional explicit path; processing only accepts
    /// explicit files under this job's runtime root, or searches jobRoot\guest
    /// recursively. This prevents the Web API from importing arbitrary host
    /// files while preserving the separate ImportExternalRun tool path for
    /// operator-controlled offline imports.
    /// </summary>
    private string ResolveGuestEventsPath(Guid jobId, string? eventsPath)
    {
        var jobRoot = Path.GetFullPath(GetJobRoot(jobId));
        if (!string.IsNullOrWhiteSpace(eventsPath))
        {
            var resolved = Path.GetFullPath(eventsPath);
            if (!IsPathUnderRoot(resolved, jobRoot))
            {
                throw new InvalidDataException(
                    $"Explicit guest events import path must stay under this job root. JobRoot={jobRoot}; EventsPath={resolved}");
            }

            if (!IsGuestEventImportFileName(resolved))
            {
                throw new InvalidDataException(
                    "Explicit guest events import path must be an events.json or .jsonl file under the job root.");
            }

            if (!File.Exists(resolved))
            {
                throw new FileNotFoundException("Guest events file was not found.", resolved);
            }

            return resolved;
        }

        var guestRoot = Path.Combine(jobRoot, "guest");
        if (!Directory.Exists(guestRoot))
        {
            throw new DirectoryNotFoundException($"Guest output folder was not found: {guestRoot}");
        }

        var eventsJson = SafeEnumerateFiles(guestRoot, path => string.Equals(Path.GetFileName(path), "events.json", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(SafeGetLastWriteTimeUtc)
            .FirstOrDefault();
        if (eventsJson is not null)
        {
            return eventsJson;
        }

        // If events.json is absent, prefer the canonical R0 stream (or its
        // numbered rotation parts) over an arbitrary scratch JSONL. The
        // importer will merge every canonical stream under this guest root,
        // including files in artifacts/.
        var jsonLines = SafeEnumerateFiles(guestRoot, path => IsCanonicalOrRotatedDriverJsonl(Path.GetFileName(path)))
            .Concat(SafeEnumerateFiles(guestRoot, path =>
                string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) &&
                !IsCanonicalOrRotatedDriverJsonl(Path.GetFileName(path))))
            .OrderByDescending(SafeGetLastWriteTimeUtc)
            .FirstOrDefault();
        if (jsonLines is not null)
        {
            return jsonLines;
        }

        // Preserve a deterministic import anchor when the Agent crashed before
        // creating events.json. The importer will still load guest-agent-run-
        // status/stderr and ETW XML diagnostics from this sibling folder.
        var failureMarker = SafeEnumerateFiles(guestRoot, path =>
                string.Equals(Path.GetFileName(path), "guest-agent-run-status.json", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(path), "agent.stderr.log", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetFileName(path), "agent.exit", StringComparison.OrdinalIgnoreCase) ||
                (string.Equals(Path.GetExtension(path), ".xml", StringComparison.OrdinalIgnoreCase) && path.Contains("etw-traces", StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(SafeGetLastWriteTimeUtc)
            .FirstOrDefault();
        if (failureMarker is not null)
        {
            return Path.Combine(Path.GetDirectoryName(failureMarker) ?? guestRoot, "events.json");
        }

        throw new FileNotFoundException($"No events.json or .jsonl artifact was found under {guestRoot}.");
    }

    private static bool IsGuestEventImportFileName(string path)
    {
        var fileName = Path.GetFileName(path);
        return string.Equals(fileName, "events.json", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPathUnderRoot(string candidatePath, string rootPath)
    {
        var candidate = Path.GetFullPath(candidatePath);
        var root = Path.GetFullPath(rootPath);
        var normalizedRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return candidate.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Enumerates raw live-monitor event artifacts for one job.
    /// The input is a job record, processing looks at the recorded import path
    /// and the deterministic job guest folder, and the method returns JSON or
    /// JSONL files that may be present while or after a live run executes.
    /// </summary>
    private IEnumerable<string> EnumerateLiveEventFiles(AnalysisJob job)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(job.GuestEventsPath) && File.Exists(job.GuestEventsPath))
        {
            var fullPath = Path.GetFullPath(job.GuestEventsPath);
            seen.Add(fullPath);
            yield return fullPath;
        }

        var guestRoot = Path.Combine(GetJobRoot(job.JobId), "guest");
        if (!Directory.Exists(guestRoot))
        {
            yield break;
        }

        foreach (var path in SafeEnumerateFiles(guestRoot, path =>
                string.Equals(Path.GetFileName(path), "events.json", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) ||
                ArtifactDescriptorFactory.IsPacketCapturePath(path))
            .OrderBy(SafeGetLastWriteTimeUtc))
        {
            var fullPath = Path.GetFullPath(path);
            if (seen.Add(fullPath))
            {
                yield return fullPath;
            }
        }
    }

    private sealed record GuestEventImportSummary(
        string PrimaryPath,
        int PrimaryEventCount,
        IReadOnlyList<string> DriverPaths,
        int DriverEventCount,
        int DriverEventCountMerged)
    {
        public int SourceCount => 1 + DriverPaths.Count;
    }

    /// <summary>
    /// Loads guest events and nearby driver JSONL events without duplicates.
    /// The input is a primary event file, processing reads JSON array or JSONL
    /// data and optional sibling driver-events.jsonl files, and the method
    /// returns normalized event records.
    /// </summary>
    private static List<SandboxEvent> LoadGuestEventsWithDriverJsonl(string eventsPath)
    {
        return LoadGuestEventsWithDriverJsonl(eventsPath, out _);
    }

    private static List<SandboxEvent> LoadGuestEventsWithDriverJsonl(string eventsPath, out GuestEventImportSummary importSummary)
    {
        var searchRoot = Path.GetDirectoryName(eventsPath);
        var primaryIsCanonicalDriverStream = string.Equals(
            Path.GetFileName(eventsPath),
            "driver-events.jsonl",
            StringComparison.OrdinalIgnoreCase);
        var events = File.Exists(eventsPath) && !primaryIsCanonicalDriverStream
            ? LoadEventsFromFile(eventsPath).Select(NormalizeEvent).ToList()
            : [];
        // Keep this count anchored to the selected events.json source. Network
        // artifact import can append normalized PCAP/sidecar rows later, but
        // those rows are not primary events and must not inflate source metrics.
        var primaryEventCount = events.Count;
        var eventKeys = events.Select(EventKey).ToHashSet(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(searchRoot))
        {
            importSummary = new GuestEventImportSummary(Path.GetFullPath(eventsPath), primaryEventCount, [], 0, 0);
            return events.Select(NormalizeEvent).ToList();
        }

        // Safe equivalent of Directory.EnumerateFiles(searchRoot, "driver-events*.jsonl", SearchOption.AllDirectories)
        // for the static import contract: only the canonical stream and its
        // collector-created numbered rotation parts are imported. Arbitrary
        // scratch JSONL remains excluded.
        var driverPaths = EnumerateCanonicalDriverJsonlPaths(
            eventsPath,
            searchRoot,
            includePrimary: primaryIsCanonicalDriverStream);
        var driverRowsRead = 0;
        var driverRowsMerged = 0;
        foreach (var jsonlPath in driverPaths)
        {
            foreach (var driverEvent in LoadEventsFromJsonLines(jsonlPath))
            {
                driverRowsRead++;
                var normalized = NormalizeEvent(driverEvent);
                if (eventKeys.Add(EventKey(normalized)))
                {
                    events.Add(normalized);
                    driverRowsMerged++;
                }
            }
        }

        foreach (var networkEvent in new NetworkArtifactEventImporter().ImportGuestArtifacts(searchRoot, includeCanonicalDriverJsonl: false))
        {
            var normalized = NormalizeEvent(networkEvent);
            var key = EventKey(normalized);
            if (eventKeys.Add(key))
            {
                events.Add(normalized);
            }
            else
            {
                // Guest events may already contain a compatibility PCAP row
                // with the same identity but without host artifact metadata.
                // Merge the host parser's source/selector/hash fields into
                // that retained row instead of silently discarding them as a
                // duplicate.
                var existingIndex = events.FindIndex(evt => string.Equals(EventKey(evt), key, StringComparison.Ordinal));
                if (existingIndex >= 0)
                {
                    events[existingIndex] = MergeMissingEventData(events[existingIndex], normalized);
                }
            }
        }

        // A crashed Agent can leave the status/stderr markers and tracerpt XML
        // while never reaching events.json serialization. Preserve those
        // diagnostics and use the XML decoder only as a fallback in that
        // case. A successful Agent already serializes the decoded ETW rows in
        // events.json; importing the same full-machine XML again would add
        // tens of thousands of duplicate ambient process/image rows (and can
        // make a report look more complete than the sample actually was).
        var agentFailures = GuestFailureArtifactImporter.Import(searchRoot);
        var etwFallbackAndCoverage = EtwTraceXmlEventImporter.ImportFallbackAndCoverage(events, searchRoot);
        foreach (var diagnostic in agentFailures.Concat(etwFallbackAndCoverage))
        {
            var normalized = NormalizeEvent(diagnostic);
            if (eventKeys.Add(EventKey(normalized)))
            {
                events.Add(normalized);
            }
        }

        importSummary = new GuestEventImportSummary(
            Path.GetFullPath(eventsPath),
            primaryEventCount,
            driverPaths,
            driverRowsRead,
            driverRowsMerged);
        return NormalizeHostParsedProtocolSummary(events.Select(NormalizeEvent).ToList());
    }

    private static IReadOnlyList<string> EnumerateCanonicalDriverJsonlPaths(
        string eventsPath,
        string searchRoot,
        bool includePrimary = false)
    {
        var primaryPath = Path.GetFullPath(eventsPath);
        // The guest output contract places events.json and the stream parts
        // beside one another. Include all parts in lexical sequence so a
        // high-volume run cannot silently lose rows after JSONL rotation.
        return SafeEnumerateFiles(searchRoot, path =>
                IsCanonicalOrRotatedDriverJsonl(Path.GetFileName(path)))
            .Where(path => includePrimary || !string.Equals(Path.GetFullPath(path), primaryPath, StringComparison.OrdinalIgnoreCase))
            .OrderBy(path => string.Equals(Path.GetFileName(path), "driver-events.jsonl", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
            .ThenBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(Path.GetFullPath)
            .ToList();
    }

    private static bool IsCanonicalOrRotatedDriverJsonl(string? fileName)
    {
        if (string.Equals(fileName, "driver-events.jsonl", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // R0Collector uses driver-events.part-000001.jsonl. Keep the
        // predicate strict so unrelated files named driver-events-backup.jsonl
        // cannot enter the behavior stream.
        if (string.IsNullOrWhiteSpace(fileName) ||
            !fileName.StartsWith("driver-events.part-", StringComparison.OrdinalIgnoreCase) ||
            !fileName.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var number = fileName["driver-events.part-".Length..^".jsonl".Length];
        return number.Length == 6 && number.All(static ch => ch is >= '0' and <= '9');
    }

    private static SandboxEvent MergeMissingEventData(SandboxEvent existing, SandboxEvent imported)
    {
        var data = new Dictionary<string, string>(existing.Data, StringComparer.OrdinalIgnoreCase);
        foreach (var pair in imported.Data)
        {
            if (!data.TryGetValue(pair.Key, out var value) || string.IsNullOrWhiteSpace(value))
            {
                data[pair.Key] = pair.Value;
            }
        }

        return existing with
        {
            Path = string.IsNullOrWhiteSpace(existing.Path) ? imported.Path : existing.Path,
            Data = data
        };
    }

    private static List<SandboxEvent> NormalizeHostParsedProtocolSummary(List<SandboxEvent> events)
    {
        var parsed = events.Where(static evt =>
                evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) &&
                !evt.EventType.EndsWith(".summary", StringComparison.OrdinalIgnoreCase) &&
                !evt.EventType.Contains("parse_error", StringComparison.OrdinalIgnoreCase))
            .ToList();

        // The guest packet rows are intentionally emitted before host import
        // (the guest has only captured an artifact at that point). Treat a
        // successful host summary as parse success even when it is parsed-empty
        // so the old capture-metadata-only boundary does not survive import.
        var successfulSummaries = events.Where(static evt =>
                evt.EventType.Equals("pcap.summary", StringComparison.OrdinalIgnoreCase) &&
                IsProtocolSummarySuccessful(evt.Data))
            .ToList();
        if (parsed.Count == 0 && successfulSummaries.Count == 0)
        {
            return events;
        }

        var rollups = BuildPcapProtocolRollups(parsed, successfulSummaries);

        return events.Select(evt =>
        {
            if (!evt.EventType.Equals("packet_capture.protocol_summary", StringComparison.OrdinalIgnoreCase) &&
                !evt.EventType.Equals("packet_capture.captured", StringComparison.OrdinalIgnoreCase))
            {
                return evt;
            }

            var rollup = rollups.FirstOrDefault(candidate => PcapEventsMatch(evt, candidate.ArtifactKeys));
            if (rollup is null)
            {
                return evt;
            }

            var protocols = string.IsNullOrWhiteSpace(rollup.Protocols) ? "unknown" : rollup.Protocols;
            var data = new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["protocolSummaryAvailable"] = rollup.Available.ToString().ToLowerInvariant(),
                ["protocolSummaryState"] = rollup.State,
                ["protocolSummaryStatus"] = "ok",
                ["protocolSummaryReason"] = "nativePcapParser",
                ["protocolSummaryFormat"] = "normalized-events",
                ["protocolSummaryParser"] = "native-pcap",
                ["protocolSummaryHostNormalized"] = "true",
                ["protocolsObserved"] = protocols,
                ["protocol"] = protocols,
                ["protocols"] = protocols,
                ["dnsSummaryState"] = rollup.Dns ? "parsed" : "empty",
                ["httpSummaryState"] = rollup.Http ? "parsed" : "empty",
                ["tlsSummaryState"] = rollup.Tls ? "parsed" : "empty",
                ["protocolSummary"] = JsonSerializer.Serialize(new { state = rollup.State, protocols })
            };

            // `reason` on the guest rows used to carry the legacy
            // protocolParserNotImplemented marker. Replace it after a
            // successful host parse while preserving capture status (`captured`)
            // on both guest evidence rows.
            data["reason"] = "nativePcapParser";

            return evt with { Data = data };
        }).ToList();
    }

    private sealed record PcapProtocolRollup(
        IReadOnlySet<string> ArtifactKeys,
        bool Available,
        string State,
        bool Dns,
        bool Http,
        bool Tls,
        string Protocols);

    private static List<PcapProtocolRollup> BuildPcapProtocolRollups(
        IReadOnlyCollection<SandboxEvent> parsed,
        IReadOnlyCollection<SandboxEvent> successfulSummaries)
    {
        var grouped = parsed
            .Concat(successfulSummaries)
            .GroupBy(GetPcapArtifactKey, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return grouped.Select(group =>
        {
            var protocolEvents = group.Where(static evt =>
                    evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) &&
                    !evt.EventType.Equals("pcap.summary", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var summary = group.FirstOrDefault(static evt => evt.EventType.Equals("pcap.summary", StringComparison.OrdinalIgnoreCase));
            var dns = protocolEvents.Any(static evt => evt.EventType.Equals("pcap.dns", StringComparison.OrdinalIgnoreCase));
            var http = protocolEvents.Any(static evt => evt.EventType.Equals("pcap.http", StringComparison.OrdinalIgnoreCase));
            var tls = protocolEvents.Any(static evt => evt.EventType.Equals("pcap.tls", StringComparison.OrdinalIgnoreCase));
            var protocols = string.Join(",", protocolEvents
                .SelectMany(static evt => new[]
                {
                    evt.EventType.StartsWith("pcap.dns", StringComparison.OrdinalIgnoreCase) ? "dns" : string.Empty,
                    evt.EventType.StartsWith("pcap.http", StringComparison.OrdinalIgnoreCase) ? "http" : string.Empty,
                    evt.EventType.StartsWith("pcap.tls", StringComparison.OrdinalIgnoreCase) ? "tls" : string.Empty,
                    evt.EventType.StartsWith("pcap.flow", StringComparison.OrdinalIgnoreCase) ? "flow" : string.Empty
                })
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Concat(summary is null ? [] : ReadProtocolValues(summary.Data))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase));

            var state = summary?.Data.TryGetValue("protocolSummaryState", out var summaryState) == true &&
                !string.IsNullOrWhiteSpace(summaryState)
                ? summaryState
                : protocolEvents.Count > 0 ? "parsed" : "parsed-empty";
            var available = true;
            if (summary is not null &&
                summary.Data.TryGetValue("protocolSummaryAvailable", out var summaryAvailable))
            {
                available = !string.Equals(summaryAvailable, "false", StringComparison.OrdinalIgnoreCase);
            }
            return new PcapProtocolRollup(
                group.SelectMany(GetPcapArtifactKeys).ToHashSet(StringComparer.OrdinalIgnoreCase),
                available,
                state,
                dns,
                http,
                tls,
                protocols);
        }).ToList();
    }

    private static IEnumerable<string> ReadProtocolValues(IReadOnlyDictionary<string, string> data)
    {
        foreach (var key in new[] { "protocols", "protocol", "protocolsObserved" })
        {
            if (data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                foreach (var protocol in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (protocol is "dns" or "http" or "tls" or "flow")
                    {
                        yield return protocol;
                    }
                }
            }
        }
    }

    private static bool IsProtocolSummarySuccessful(IReadOnlyDictionary<string, string> data)
    {
        return data.TryGetValue("protocolSummaryAvailable", out var available) &&
            !string.Equals(available, "false", StringComparison.OrdinalIgnoreCase) &&
            data.TryGetValue("protocolSummaryStatus", out var status) &&
            string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase);
    }

    private static bool PcapEventsMatch(SandboxEvent evt, IReadOnlySet<string> artifactKeys)
    {
        var keys = GetPcapArtifactKeys(evt).ToList();
        return keys.Count == 0 || keys.Any(artifactKeys.Contains);
    }

    private static string GetPcapArtifactKey(SandboxEvent evt)
    {
        return GetPcapArtifactKeys(evt).FirstOrDefault() ?? string.Empty;
    }

    private static IEnumerable<string> GetPcapArtifactKeys(SandboxEvent evt)
    {
        var values = new[]
        {
            evt.Path,
            ReadEventData(evt, "sourceArtifactPath"),
            ReadEventData(evt, "sourceArtifactRelativePath"),
            ReadEventData(evt, "sourcePcapArtifactPath"),
            ReadEventData(evt, "sourcePcapArtifactRelativePath"),
            ReadEventData(evt, "pcapSourceArtifactPath"),
            ReadEventData(evt, "pcapSourceArtifactRelativePath"),
            ReadEventData(evt, "pcapDownloadSelector"),
            ReadEventData(evt, "sourceArtifactSelector"),
            ReadEventData(evt, "artifactRelativePath"),
            ReadEventData(evt, "packetCaptureRelativePath"),
            ReadEventData(evt, "relativePath"),
            ReadEventData(evt, "pcapngRelativePath")
        };
        foreach (var value in values.Where(static value => !string.IsNullOrWhiteSpace(value)))
        {
            yield return NormalizePcapArtifactKey(value!);
        }
    }

    private static string? ReadEventData(SandboxEvent evt, string key)
    {
        return evt.Data.TryGetValue(key, out var value) ? value : null;
    }

    private static string NormalizePcapArtifactKey(string value)
    {
        try
        {
            return Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            return value.Trim();
        }
    }

    /// <summary>
    /// Adds source artifact identity to host-generated PCAP events during guest
    /// import. Inputs are one parsed PCAP event, the capture path, and import
    /// root; processing records path, size, hash, format, and collection
    /// context; the method returns a normalized event.
    /// </summary>
    private static SandboxEvent NormalizeImportedPcapEvent(SandboxEvent evt, string pcapPath, string importRoot)
    {
        var normalized = NormalizeEvent(evt);
        var data = new Dictionary<string, string>(normalized.Data, StringComparer.OrdinalIgnoreCase);
        AddDataIfMissing(data, "sourceArtifactPath", pcapPath);
        AddDataIfMissing(data, "sourceArtifactKind", ArtifactKind.PacketCapture.ToString());
        AddDataIfMissing(data, "sourceArtifactRelativePath", ArtifactDescriptorFactory.SafeRelativePath(importRoot, pcapPath));
        AddDataIfMissing(data, "sourceImportRoot", importRoot);
        AddDataIfMissing(data, "collectionName", "packet-captures");
        AddDataIfMissing(data, "evidenceRole", "packet-capture");
        AddDataIfMissing(data, "captureSource", "external");
        AddDataIfMissing(data, "hostCaptureStarted", "false");
        AddDataIfMissing(data, "importMode", "external-artifact");
        AddDataIfMissing(
            data,
            "pcapFormat",
            string.Equals(Path.GetExtension(pcapPath), ".pcapng", StringComparison.OrdinalIgnoreCase)
                ? "pcapng"
                : "pcap");

        try
        {
            var info = new FileInfo(pcapPath);
            AddDataIfMissing(data, "sourceArtifactSizeBytes", info.Length.ToString());
            AddDataIfMissing(data, "sourceArtifactSha256", ComputeSha256(info.FullName));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            data["sourceArtifactHashSkipped"] = ex.GetType().Name;
        }

        return normalized with { Data = data };
    }

    private static void AddDataIfMissing(Dictionary<string, string> data, string key, string value)
    {
        if (!data.ContainsKey(key) || string.IsNullOrWhiteSpace(data[key]))
        {
            data[key] = value;
        }
    }

    private static string ComputeSha256(string fullPath)
    {
        using var stream = File.OpenRead(fullPath);
        var hash = System.Security.Cryptography.SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Enumerates PCAP/PCAPNG artifacts near a guest import path.
    /// Inputs are the primary guest output directory; processing searches
    /// recursively for packet-capture artifacts; the method returns stable paths.
    /// </summary>
    private static IEnumerable<string> EnumeratePacketCaptures(string searchRoot)
    {
        if (!Directory.Exists(searchRoot))
        {
            yield break;
        }

        foreach (var path in SafeEnumerateFiles(searchRoot, ArtifactDescriptorFactory.IsPacketCapturePath)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            yield return path;
        }
    }

    /// <summary>
    /// Loads guest events from an existing import path, including canonical
    /// sibling driver JSONL streams when the import path is events.json.
    /// The input is an optional path; processing tolerates missing paths like
    /// LoadEventsIfPresent, and the method returns normalized event records.
    /// </summary>
    private static List<SandboxEvent> LoadGuestEventsIfPresent(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        return LoadGuestEventsWithDriverJsonl(path);
    }

    /// <summary>
    /// Loads events from a file if the path exists.
    /// The input is an optional path, processing supports JSON array and JSONL,
    /// and the method returns an empty list for missing paths.
    /// </summary>
    private static List<SandboxEvent> LoadEventsIfPresent(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        return LoadEventsFromFile(path);
    }

    /// <summary>
    /// Loads durable host-side enrichment events for report regeneration.
    /// Inputs are a job id; processing reads enrichment-events.json when it
    /// exists and tolerates corrupt/missing files by returning a diagnostic
    /// host event only for corrupt readable files; the method returns
    /// normalized events.
    /// </summary>
    private List<SandboxEvent> LoadEnrichmentEvents(Guid jobId)
    {
        var path = GetEnrichmentEventsPath(jobId);
        if (!File.Exists(path))
        {
            return [];
        }

        try
        {
            return LoadEventsFromFile(path).Select(NormalizeEvent).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return
            [
                new SandboxEvent
                {
                    EventType = "enrichment.events.read_error",
                    Source = "host",
                    Path = path,
                    Data = CreateHostOperationalEventData(
                        "enrichment-events-read-error",
                        "enrichment-read-error-is-host-diagnostic-not-sample-behavior",
                        "Host failed to read durable enrichment events; this diagnostic is not sample behavior.",
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["exceptionType"] = ex.GetType().Name,
                        ["message"] = ex.Message
                    })
                }
            ];
        }
    }

    /// <summary>
    /// Loads events from either events.json or JSON Lines.
    /// The input is a file path, processing selects the parser by extension,
    /// and the method returns normalized events.
    /// </summary>
    private static List<SandboxEvent> LoadEventsFromFile(string path)
    {
        if (ArtifactDescriptorFactory.IsPacketCapturePath(path))
        {
            return new PcapArtifactEventImporter().Import(path).Select(NormalizeEvent).ToList();
        }

        return string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase)
            ? LoadEventsFromJsonLines(path)
            : LoadEventsFromJsonArrayStreaming(path);
    }

    /// <summary>
    /// Reads a guest events.json array incrementally. Inputs are a bounded
    /// output path; processing keeps one event object at a time instead of
    /// materializing the whole UTF-8 document as a second large string before
    /// deserialization. The method returns normalized events and preserves the
    /// existing malformed-document exception contract for import diagnostics.
    /// </summary>
    private static List<SandboxEvent> LoadEventsFromJsonArrayStreaming(string path)
    {
        var events = new List<SandboxEvent>();
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 64 * 1024,
            options: FileOptions.SequentialScan);
        var sequence = JsonSerializer.DeserializeAsyncEnumerable<SandboxEvent>(stream, JsonOptions);
        var enumerator = sequence.GetAsyncEnumerator();
        try
        {
            while (enumerator.MoveNextAsync().AsTask().GetAwaiter().GetResult())
            {
                if (enumerator.Current is SandboxEvent evt)
                {
                    events.Add(NormalizeEvent(evt));
                }
            }
        }
        finally
        {
            enumerator.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        return events;
    }

    /// <summary>
    /// Loads one JSON event per line.
    /// The input is a JSONL path, processing deserializes lines independently
    /// and converts malformed lines into parse-error events; the method returns
    /// normalized events.
    /// </summary>
    private static List<SandboxEvent> LoadEventsFromJsonLines(string path)
    {
        var events = new List<SandboxEvent>();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        var lineNumber = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                var evt = JsonSerializer.Deserialize<SandboxEvent>(line, JsonOptions);
                if (evt is not null)
                {
                    events.Add(NormalizeEvent(evt));
                }
            }
            catch (JsonException)
            {
                events.Add(new SandboxEvent
                {
                    EventType = "driver.parse_error",
                    Source = "host",
                    Path = path,
                    Data = CreateHostOperationalEventData(
                        "driver-jsonl-parse-error",
                        "driver-jsonl-parse-error-is-host-diagnostic-not-sample-behavior",
                        "Host could not parse one driver JSONL row; this diagnostic is not sample behavior.",
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                            ["line"] = line,
                            ["lineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
                            ["jsonlPath"] = path,
                            ["jsonlLineNumber"] = lineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
                            ["jsonlLineSelector"] = $"{path}#L{lineNumber}"
                    })
                });
            }
        }

        return events;
    }

    /// <summary>
    /// Normalizes nullable or missing event fields after JSON import.
    /// The input is a deserialized event, processing fills source, timestamp,
    /// and data defaults, and the method returns a safe event for reports.
    /// </summary>
    private static SandboxEvent NormalizeEvent(SandboxEvent evt)
    {
        var data = evt.Data is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase);
        return evt with
        {
            Source = string.IsNullOrWhiteSpace(evt.Source) ? "guest" : evt.Source,
            Timestamp = evt.Timestamp == default ? DateTimeOffset.UtcNow : evt.Timestamp,
            Data = data
        };
    }

    /// <summary>
    /// Appends a host event that summarizes a persisted runbook attempt.
    /// Inputs are event output and optional execution-result path; processing
    /// reads the persisted result when present, and the method returns no value.
    /// </summary>
    private static void AppendRunbookExecutionEvent(
        List<SandboxEvent> events,
        string? resultPath,
        VirtualizationProvider provider)
    {
        if (string.IsNullOrWhiteSpace(resultPath) || !File.Exists(resultPath))
        {
            return;
        }

        try
        {
            var result = JsonSerializer.Deserialize<SandboxRunbookExecutionResult>(File.ReadAllText(resultPath), JsonOptions);
            if (result is null)
            {
                return;
            }

            var providerPrefix = provider.ToString().ToLowerInvariant();
            var fallbackWarning = result.FallbackWarning ?? DetectS4UFallbackWarning(result) ?? string.Empty;
            var launchContext = string.Equals(result.LaunchContext, "s4u-fallback", StringComparison.OrdinalIgnoreCase) ||
                !string.IsNullOrWhiteSpace(fallbackWarning)
                ? "s4u-fallback"
                : result.LaunchContext;
            var fallbackUsed = !string.IsNullOrWhiteSpace(fallbackWarning) ||
                string.Equals(launchContext, "s4u-fallback", StringComparison.OrdinalIgnoreCase);
            var runbookData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["provider"] = provider.ToString(),
                ["mode"] = result.Mode.ToString(),
                ["success"] = result.Success.ToString(),
                ["totalSteps"] = result.TotalSteps.ToString(),
                ["executedSteps"] = result.ExecutedSteps.ToString(),
                ["failedStepIndex"] = result.FailedStepIndex?.ToString() ?? string.Empty,
                ["duration"] = result.Duration.ToString(),
                ["resultPath"] = resultPath,
                ["message"] = result.Message ?? string.Empty,
                ["failureHint"] = BuildSafeRunbookFailureHint(result),
                ["launchContext"] = string.IsNullOrWhiteSpace(launchContext) ? "unknown" : launchContext,
                ["fallbackWarning"] = fallbackWarning ?? string.Empty,
                ["fallbackUsed"] = fallbackUsed.ToString()
            };
            if (fallbackUsed)
            {
                // Persist this as evidence-quality health so report.json and
                // CollectionHealthSummary retain the desktop-to-S4U boundary
                // after stdout/stderr are no longer in the live request.
                runbookData["collectionHealth"] = "true";
                runbookData["runbookFallbackWarning"] = "true";
                runbookData["healthSeverity"] = "warning";
            }

            events.Add(new SandboxEvent
            {
                EventType = $"{providerPrefix}.runbook.executed",
                Source = "host",
                Path = result.TargetVmName,
                Data = CreateHostOperationalEventData(
                    $"{providerPrefix}-runbook-executed",
                    "runbook-execution-summary-is-host-control-plane-not-sample-behavior",
                    $"{provider} runbook execution summary describes host orchestration, not sample behavior.",
                    runbookData)
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            var providerPrefix = provider.ToString().ToLowerInvariant();
            events.Add(new SandboxEvent
            {
                EventType = $"{providerPrefix}.runbook.execution_result_error",
                Source = "host",
                Path = resultPath,
                Data = CreateHostOperationalEventData(
                    $"{providerPrefix}-runbook-execution-result-error",
                    "runbook-result-read-error-is-host-diagnostic-not-sample-behavior",
                    "Host failed to read runbook execution result; this diagnostic is not sample behavior.",
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["provider"] = provider.ToString(),
                    ["error"] = ex.Message
                })
            });
        }
    }

    private static string? DetectS4UFallbackWarning(SandboxRunbookExecutionResult result)
    {
        var runAgentOutput = result.StepResults
            .Where(step => string.Equals(step.StepId, "run-agent", StringComparison.OrdinalIgnoreCase))
            .SelectMany(step => new[] { step.StandardOutput, step.StandardError, step.Message ?? string.Empty });
        return runAgentOutput.Any(output =>
                output.Contains("Interactive desktop is unavailable", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("S4U fallback started", StringComparison.OrdinalIgnoreCase))
            ? "Interactive desktop unavailable; Guest Agent started by S4U scheduled task fallback."
            : null;
    }

    private static string BuildSafeRunbookFailureHint(SandboxRunbookExecutionResult result)
    {
        if (result.Success)
        {
            return string.Empty;
        }

        foreach (var step in result.StepResults.Where(step => !step.Success).OrderBy(step => step.StepIndex))
        {
            var output = $"{step.StandardOutput}\n{step.StandardError}";
            if (output.Contains("拒绝访问", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("access is denied", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("access denied", StringComparison.OrdinalIgnoreCase))
            {
                return "Guest WinRM rejected the configured account (access denied). Re-run the guest bootstrap with the same username and password, then verify the account has WinRM/Administrators access.";
            }

            if (output.Contains("VMware Tools are not running", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Tools are not running", StringComparison.OrdinalIgnoreCase))
            {
                return "VMware Tools did not report a guest address after restore. Start VMware Tools in the baseline guest and retry address discovery.";
            }

            if (output.Contains("cannot connect", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("目标服务不可达", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("WinRM 无法完成", StringComparison.OrdinalIgnoreCase))
            {
                return "Guest WinRM endpoint was unreachable. Verify the guest firewall, HTTPS listener, address, and TCP 5986 before retrying.";
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Appends a host event documenting guest event import status.
    /// Inputs are event output, imported path, and imported count; processing
    /// writes one status event when a path is known; the method returns no value.
    /// </summary>
    private static void AppendGuestImportEvent(
        List<SandboxEvent> events,
        string? guestEventsPath,
        int guestEventCount,
        GuestEventImportSummary? importSummary = null)
    {
        if (string.IsNullOrWhiteSpace(guestEventsPath))
        {
            return;
        }

        events.Add(new SandboxEvent
        {
            EventType = guestEventCount == 0 ? "guest.events.empty" : "guest.events.imported",
            Source = "host",
            Path = guestEventsPath,
            Data = CreateHostOperationalEventData(
                guestEventCount == 0 ? "guest-events-empty" : "guest-events-imported",
                "guest-event-import-summary-is-host-metadata-not-sample-behavior",
                "Host import summary records how many guest events were read; it is not sample behavior.",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["eventCount"] = guestEventCount.ToString(),
                ["guestImportOutcome"] = guestEventCount == 0 ? "failed" : "imported",
                ["terminalStatus"] = (guestEventCount == 0 ? AnalysisStatus.Failed : AnalysisStatus.Completed).ToString()
            })
        });

        if (importSummary is not null)
        {
            var marker = events[^1];
            var data = new Dictionary<string, string>(marker.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["primaryEventsPath"] = importSummary.PrimaryPath,
                ["primaryEventCount"] = importSummary.PrimaryEventCount.ToString(),
                ["driverEventsPathCount"] = importSummary.DriverPaths.Count.ToString(),
                ["driverEventCount"] = importSummary.DriverEventCount.ToString(),
                ["driverEventCountMerged"] = importSummary.DriverEventCountMerged.ToString(),
                ["sourceFileCount"] = importSummary.SourceCount.ToString(),
                ["driverEventsPaths"] = string.Join(";", importSummary.DriverPaths)
            };
            events[^1] = marker with { Data = data };
        }
    }

    /// <summary>
    /// Builds a nonbehavior host operational marker for skipped/failed guest
    /// import outcomes. Inputs are stable event identity plus display reason;
    /// processing stamps behaviorCounted=false/nonbehavior=true through the
    /// shared host metadata helper and returns a durable report event.
    /// </summary>
    private static SandboxEvent CreateGuestImportOperationalMarker(
        string eventType,
        string? path,
        string evidenceKind,
        string reason,
        string hint,
        IReadOnlyDictionary<string, string>? values = null)
    {
        var data = CreateHostOperationalEventData(evidenceKind, reason, hint, values);
        data["guestImportMessage"] = hint;
        data["guestImportMarker"] = "true";

        return new SandboxEvent
        {
            EventType = eventType,
            Source = "host",
            Path = path,
            Data = data
        };
    }

    private static string CleanOperatorMessage(string? message, string fallback)
    {
        return string.IsNullOrWhiteSpace(message)
            ? fallback
            : message.Trim();
    }

    private static string? NormalizeOptionalPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path.Trim();
        }
    }

    /// <summary>
    /// Creates a stable key used to avoid duplicate driver events.
    /// The input is one event, processing combines common fields and ordered
    /// data values, and the method returns a comparison key.
    /// </summary>
    private static string EventKey(SandboxEvent evt)
    {
        if (evt.EventType.Equals("driver.parse_error", StringComparison.OrdinalIgnoreCase))
        {
            var jsonlPath = evt.Data.TryGetValue("jsonlPath", out var path) && !string.IsNullOrWhiteSpace(path)
                ? path
                : evt.Path ?? string.Empty;
            var line = evt.Data.TryGetValue("jsonlLineNumber", out var lineNumber) && !string.IsNullOrWhiteSpace(lineNumber)
                ? lineNumber
                : evt.Data.TryGetValue("lineNumber", out var fallbackLine) ? fallbackLine : string.Empty;
            return string.Join("|", "driver.parse_error", jsonlPath, line);
        }

        var data = string.Join(
            ";",
            evt.Data
                .Where(pair => !IsImportOnlyEventKeyData(evt, pair.Key))
                .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(pair => $"{pair.Key}={pair.Value}"));
        return string.Join("|", evt.EventType, evt.Source, evt.Timestamp.ToString("O"), evt.ProcessId?.ToString() ?? string.Empty, evt.Path ?? string.Empty, evt.CommandLine ?? string.Empty, data);
    }

    private static bool IsImportOnlyEventKeyData(SandboxEvent evt, string key)
    {
        if (EventKeyImportOnlyDataKeys.Contains(key))
        {
            return true;
        }

        return !evt.EventType.Equals("driver.parse_error", StringComparison.OrdinalIgnoreCase) &&
            key.Equals("jsonlLineNumber", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Compares enrichment identity for upsert semantics. Inputs are two
    /// enrichment events; processing prefers provider/hash identity and falls
    /// back to source/event/path; the method returns true when a newer result
    /// should replace an older one instead of duplicating it.
    /// </summary>
    private static bool SameEnrichmentIdentity(SandboxEvent left, SandboxEvent right)
    {
        if (!string.Equals(left.EventType, right.EventType, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(left.Source, right.Source, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var leftHash = ReadNullableEventData(left, "sha256");
        var rightHash = ReadNullableEventData(right, "sha256");
        if (!string.IsNullOrWhiteSpace(leftHash) || !string.IsNullOrWhiteSpace(rightHash))
        {
            return string.Equals(leftHash, rightHash, StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(left.Path, right.Path, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns a new message list with one appended message.
    /// Inputs are existing messages and a new message, processing copies to
    /// avoid mutating previous job records, and the method returns the list.
    /// </summary>
    private static List<string> AppendMessage(IEnumerable<string> messages, string message)
    {
        var next = messages.ToList();
        next.Add(message);
        return next;
    }

    /// <summary>
    /// Runs static analysis without making job planning depend on parser success.
    /// The input is sample identity, processing catches parser and IO failures,
    /// and the method returns a static-analysis result with warnings.
    /// </summary>
    private StaticAnalysisResult AnalyzeSample(SampleIdentity sample)
    {
        try
        {
            return staticAnalyzer.Analyze(sample.FullPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new StaticAnalysisResult
            {
                FileFormat = "unknown",
                Magic = "analysis failed",
                Warnings = [$"Static analysis failed: {ex.Message}"]
            };
        }
    }

    /// <summary>
    /// Resolves requested duration while preserving explicit unlimited intent.
    /// Inputs are the raw submission; processing returns 0 only when the
    /// operator selected no runtime limit, otherwise it applies configured safe
    /// bounds; the method returns the effective persisted seconds value.
    /// </summary>
    private int ResolveDuration(SandboxSubmission submission)
    {
        return submission.DurationUnlimited ? 0 : ClampDuration(submission.DurationSeconds);
    }

    /// <summary>
    /// Clamps requested bounded duration to configured safe bounds.
    /// The input is user-supplied seconds, processing applies defaults and max
    /// limits, and the method returns the effective duration in seconds.
    /// </summary>
    private int ClampDuration(int requestedSeconds)
    {
        var duration = requestedSeconds <= 0 ? config.Analysis.DefaultDurationSeconds : requestedSeconds;
        return Math.Clamp(duration, 1, config.Analysis.MaxDurationSeconds);
    }

    /// <summary>
    /// Normalizes optional WebUI job settings while preserving per-job VM
    /// overrides. Inputs are the raw submission and effective duration; processing
    /// trims string values, keeps explicit no-limit semantics, and forces dry-run
    /// planning mode; the method returns the persisted request snapshot.
    /// </summary>
    private static SandboxSubmission NormalizeSubmission(SandboxSubmission submission, int duration)
    {
        return submission with
        {
            DurationSeconds = submission.DurationUnlimited ? 0 : duration,
            DurationUnlimited = submission.DurationUnlimited,
            GuestReadyTimeoutSeconds = submission.GuestReadyTimeoutSeconds is > 0
                ? Math.Clamp(submission.GuestReadyTimeoutSeconds.Value, 1, 7200)
                : null,
            DryRun = true,
            GoldenVmName = CleanOptional(submission.GoldenVmName),
            GoldenSnapshotName = CleanOptional(submission.GoldenSnapshotName),
            MachineDefinitionPath = CleanOptional(submission.MachineDefinitionPath),
            QemuDiskFormat = CleanOptional(submission.QemuDiskFormat)?.ToLowerInvariant(),
            GuestUserName = CleanOptional(submission.GuestUserName),
            GuestWorkingDirectory = CleanOptional(submission.GuestWorkingDirectory),
            GuestPayloadRoot = CleanOptional(submission.GuestPayloadRoot)
        };
    }

    /// <summary>
    /// Creates a per-job sandbox configuration from optional WebUI overrides.
    /// Inputs are the normalized submission and clamped analysis duration;
    /// processing overlays safe provider/guest/path/driver fields; the method
    /// returns the config used to build the concrete runbook.
    /// </summary>
    private SandboxConfig BuildJobConfig(SandboxSubmission submission, int duration)
    {
        var provider = submission.Provider ?? config.Virtualization.Provider;
        return config with
        {
            Virtualization = config.Virtualization with { Provider = provider },
            HyperV = config.HyperV with
            {
                GoldenVmName = submission.GoldenVmName ?? config.HyperV.GoldenVmName,
                GoldenSnapshotName = submission.GoldenSnapshotName ?? config.HyperV.GoldenSnapshotName
            },
            VMware = config.VMware with
            {
                VmName = submission.GoldenVmName ?? config.VMware.VmName,
                SnapshotName = submission.GoldenSnapshotName ?? config.VMware.SnapshotName,
                VmxPath = provider is VirtualizationProvider.VMware
                    ? submission.MachineDefinitionPath ?? config.VMware.VmxPath
                    : config.VMware.VmxPath
            },
            Qemu = config.Qemu with
            {
                VmName = submission.GoldenVmName ?? config.Qemu.VmName,
                SnapshotName = submission.GoldenSnapshotName ?? config.Qemu.SnapshotName,
                DiskImagePath = provider is VirtualizationProvider.Qemu
                    ? submission.MachineDefinitionPath ?? config.Qemu.DiskImagePath
                    : config.Qemu.DiskImagePath,
                DiskFormat = provider is VirtualizationProvider.Qemu
                    ? submission.QemuDiskFormat ?? config.Qemu.DiskFormat
                    : config.Qemu.DiskFormat
            },
            Guest = config.Guest with
            {
                UserName = submission.GuestUserName ?? config.Guest.UserName,
                WorkingDirectory = submission.GuestWorkingDirectory ?? config.Guest.WorkingDirectory
            },
            Paths = config.Paths with
            {
                GuestPayloadRoot = submission.GuestPayloadRoot ?? config.Paths.GuestPayloadRoot
            },
            Driver = config.Driver with
            {
                Enabled = submission.DriverEnabled ?? config.Driver.Enabled,
                UseMockCollector = submission.UseMockCollector ?? config.Driver.UseMockCollector
            },
            ArtifactCollection = config.ArtifactCollection with
            {
                CollectDroppedFiles = submission.CollectDroppedFiles ?? config.ArtifactCollection.CollectDroppedFiles,
                CaptureScreenshots = submission.CaptureScreenshots ?? config.ArtifactCollection.CaptureScreenshots,
                CaptureMemoryDumps = submission.CaptureMemoryDumps ?? config.ArtifactCollection.CaptureMemoryDumps,
                CapturePacketCapture = submission.CapturePacketCapture ?? config.ArtifactCollection.CapturePacketCapture
            },
            Analysis = config.Analysis with
            {
                DefaultDurationSeconds = duration,
                DurationUnlimited = submission.DurationUnlimited,
                GuestReadyTimeoutSeconds = submission.GuestReadyTimeoutSeconds ?? config.Analysis.GuestReadyTimeoutSeconds
            }
        };
    }

    private static string? CleanOptional(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>
    /// Creates seed events that document the planned job before VM execution.
    /// Inputs are sample metadata, submission, and runbook; processing creates
    /// normalized host events; the method returns the event list.
    /// </summary>
    private static List<SandboxEvent> CreatePlanningEvents(SampleIdentity sample, SandboxSubmission submission, SandboxRunbook runbook, StaticAnalysisResult staticAnalysis, ArtifactCollectionConfig artifactCollection)
    {
        var events = new List<SandboxEvent>
        {
            new SandboxEvent
            {
                EventType = "submission.accepted",
                Source = "host",
                Path = sample.FullPath,
                CommandLine = submission.DisplayName ?? sample.FileName,
                Data = CreateHostOperationalEventData(
                    "submission-accepted",
                    "submission-metadata-is-host-control-plane-not-sample-behavior",
                    "Submission metadata records host job planning and must not be counted as sample behavior.",
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["sha256"] = sample.Sha256,
                    ["sha1"] = sample.Sha1,
                    ["md5"] = sample.Md5,
                    ["crc32"] = sample.Crc32,
                    ["sizeBytes"] = sample.SizeBytes.ToString(),
                    ["durationSeconds"] = submission.DurationSeconds.ToString(),
                    ["durationUnlimited"] = submission.DurationUnlimited.ToString(),
                    ["runtimeLimitPolicy"] = submission.DurationUnlimited ? "unlimited-requested" : "bounded-seconds",
                    ["collectDroppedFiles"] = artifactCollection.CollectDroppedFiles.ToString(),
                    ["captureScreenshots"] = artifactCollection.CaptureScreenshots.ToString(),
                    ["captureMemoryDumps"] = artifactCollection.CaptureMemoryDumps.ToString(),
                    ["capturePacketCapture"] = artifactCollection.CapturePacketCapture.ToString(),
                    ["collectDroppedFilesOverride"] = FormatNullableBool(submission.CollectDroppedFiles),
                    ["captureScreenshotsOverride"] = FormatNullableBool(submission.CaptureScreenshots),
                    ["captureMemoryDumpsOverride"] = FormatNullableBool(submission.CaptureMemoryDumps),
                    ["capturePacketCaptureOverride"] = FormatNullableBool(submission.CapturePacketCapture)
                })
            },
            new SandboxEvent
            {
                EventType = $"{runbook.Provider.ToString().ToLowerInvariant()}.runbook.created",
                Source = "host",
                Path = runbook.TargetVmName,
                Data = CreateHostOperationalEventData(
                    "virtualization-runbook-created",
                    "runbook-plan-is-host-control-plane-not-sample-behavior",
                    "Runbook planning describes host orchestration and must not be counted as sample behavior.",
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["provider"] = runbook.Provider.ToString(),
                    ["steps"] = runbook.Steps.Count.ToString(),
                    ["usesTemporaryVm"] = runbook.UsesTemporaryVm.ToString(),
                    ["launchContext"] = runbook.LaunchContext,
                    ["fallbackWarning"] = runbook.FallbackWarning ?? string.Empty
                })
            }
        };

        // Keep host-side static analysis as first-class normalized telemetry so
        // rules, live views, and reports can consume PE sections, imports,
        // exports, TLS callbacks, string indicators, packer hints, and
        // YARA-like matches instead of a single opaque summary row.
        events.InsertRange(1, StaticAnalyzer.CreateEvents(sample.FullPath, staticAnalysis));
        return events;
    }

    /// <summary>
    /// Builds explicit host/control-plane metadata for operational rows.
    /// Inputs are a stable evidence kind, reason, human hint, and optional
    /// event-specific values; processing stamps nonbehavior/self-noise fields
    /// first and appends caller values; the method returns a dictionary ready
    /// for SandboxEvent.Data.
    /// </summary>
    private static Dictionary<string, string> CreateHostOperationalEventData(
        string evidenceKind,
        string reason,
        string hint,
        IReadOnlyDictionary<string, string>? values = null)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["sampleBehaviorCandidate"] = "false",
            ["eventKind"] = "diagnostic",
            ["evidenceRole"] = "host-control-plane",
            ["behaviorScope"] = "host-operational",
            ["operationalEvent"] = "true",
            ["hostGenerated"] = "true",
            ["hostImportSelfNoise"] = "true",
            ["nonbehaviorReason"] = reason,
            ["hostOperationalKind"] = evidenceKind,
            ["behaviorCountingPolicy"] = "host-control-plane-events-are-not-sample-behavior",
            ["zhBehaviorHint"] = "该行由 Host 生成，用于记录任务规划、导入、富化或运行手册状态；behaviorCounted=false，不计入样本行为。",
            ["operatorHint"] = hint
        };

        if (values is not null)
        {
            foreach (var (key, value) in values)
            {
                data[key] = value;
            }
        }

        return data;
    }

    /// <summary>
    /// Formats optional per-job collection overrides for planning evidence.
    /// Inputs are nullable boolean submission values; processing preserves
    /// unset/null as "config-default"; the method returns display metadata.
    /// </summary>
    private static string FormatNullableBool(bool? value)
    {
        return value.HasValue ? value.Value.ToString() : "config-default";
    }

    /// <summary>
    /// Builds small report metrics from events and findings.
    /// Inputs are event, finding, and static-analysis data, processing counts
    /// totals and severity groups, and the method returns a metric dictionary.
    /// </summary>
    private static Dictionary<string, int> BuildMetrics(
        IReadOnlyCollection<SandboxEvent> events,
        List<BehaviorFinding> findings,
        StaticAnalysisResult staticAnalysis,
        int? rawEventCount = null,
        int omittedReportEvents = 0,
        IReadOnlyCollection<SandboxEvent>? rawEvents = null,
        GuestEventImportSummary? importSummary = null)
    {
        var totalEvents = rawEventCount ?? events.Count;
        var metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["events.total"] = totalEvents,
            ["events.raw"] = totalEvents,
            ["events.report"] = events.Count,
            ["events.omittedFromReport"] = omittedReportEvents,
            ["findings.total"] = findings.Count,
            ["static.events"] = events.Count(evt => evt.EventType.StartsWith("static.", StringComparison.OrdinalIgnoreCase)),
            ["static.tags"] = staticAnalysis.Tags.Count,
            ["static.urls"] = staticAnalysis.Urls.Count,
            ["static.interestingStrings"] = staticAnalysis.InterestingStrings.Count
        };

        // `events.report` includes the synthetic sampling marker when one is
        // present. Keep an explicit raw-inline count and account for policy
        // exclusions (for example routine agent lifecycle rows) even when no
        // quota marker was needed. This makes raw = inline + quota omitted +
        // policy excluded reconcile for small/lifecycle-only reports.
        var reportInlineRows = events.Count(evt =>
            !string.Equals(evt.EventType, "report.events.sampled", StringComparison.OrdinalIgnoreCase));
        metrics["events.reportRaw"] = reportInlineRows;
        metrics["events.policyExcludedFromReport"] = Math.Max(
            0,
            totalEvents - reportInlineRows - Math.Max(0, omittedReportEvents));

        AddDynamicCoverageMetrics(metrics, events, rawEvents ?? events, rawEventCount, omittedReportEvents);
        AddR0DriverCoverageMetrics(metrics, events, rawEvents ?? events);
        CollectionHealthSummaryBuilder.AddMetrics(
            metrics,
            CollectionHealthSummaryBuilder.Build(rawEvents ?? events, events));
        AddEtwCoverageMetrics(metrics, rawEvents ?? events);
        CollectionHealthSummaryBuilder.AddEtwSecurityCoverageMetrics(metrics, rawEvents ?? events, events);
        if (importSummary is not null)
        {
            metrics["events.sources.total"] = importSummary.SourceCount;
            metrics["events.sources.primary"] = 1;
            metrics["events.sources.driver"] = importSummary.DriverPaths.Count;
            metrics["events.sources.primaryEvents"] = importSummary.PrimaryEventCount;
            metrics["events.sources.driverEvents"] = importSummary.DriverEventCount;
            metrics["events.sources.driverEventsMerged"] = importSummary.DriverEventCountMerged;
        }

        foreach (var group in findings.GroupBy(finding => finding.Severity))
        {
            metrics[$"findings.{group.Key}"] = group.Count();
        }

        return metrics;
    }

    /// <summary>
    /// Records R0 driver-row coverage and queue quality in report metrics.
    /// Inputs are report and raw event collections; processing counts every
    /// driver producer class plus explicit loss/backpressure evidence so a
    /// report can distinguish inline sampling from collector loss.
    /// </summary>
    private static void AddR0DriverCoverageMetrics(
        Dictionary<string, int> metrics,
        IReadOnlyCollection<SandboxEvent> reportEvents,
        IReadOnlyCollection<SandboxEvent> rawEvents)
    {
        var rawDriverRows = rawEvents.Where(IsR0DriverTelemetryRow).ToList();
        var reportDriverRows = reportEvents.Where(IsR0DriverTelemetryRow).ToList();
        var rawAttributedDriverRows = rawDriverRows.Count(CollectionHealthSummaryBuilder.IsSampleAttributedR0DriverTelemetryRow);
        var reportAttributedDriverRows = reportDriverRows.Count(CollectionHealthSummaryBuilder.IsSampleAttributedR0DriverTelemetryRow);
        metrics["events.r0.driver.raw"] = rawDriverRows.Count;
        metrics["events.r0.driver.report"] = reportDriverRows.Count;
        metrics["events.r0.driver.omitted"] = Math.Max(0, rawDriverRows.Count - reportDriverRows.Count);
        metrics["events.r0.driver.rawUnknown"] = rawDriverRows.Count - rawAttributedDriverRows;
        metrics["events.r0.driver.reportUnknown"] = reportDriverRows.Count - reportAttributedDriverRows;
        // Keep unresolved attribution separate from rows the classifier has
        // explicitly identified as environment/collector noise.  A healthy
        // run commonly contains many known self-noise rows; folding them into
        // `rawUnknown` made coverage look like an attribution failure.
        var rawEnvironmentRows = rawDriverRows.Count(evt =>
            !CollectionHealthSummaryBuilder.IsSampleAttributedR0DriverTelemetryRow(evt) &&
            IsKnownEnvironmentalR0Row(evt));
        var reportEnvironmentRows = reportDriverRows.Count(evt =>
            !CollectionHealthSummaryBuilder.IsSampleAttributedR0DriverTelemetryRow(evt) &&
            IsKnownEnvironmentalR0Row(evt));
        var rawUnknownUnresolved = Math.Max(0, rawDriverRows.Count - rawAttributedDriverRows - rawEnvironmentRows);
        var reportUnknownUnresolved = Math.Max(0, reportDriverRows.Count - reportAttributedDriverRows - reportEnvironmentRows);
        metrics["events.r0.driver.rawEnvironment"] = rawEnvironmentRows;
        metrics["events.r0.driver.reportEnvironment"] = reportEnvironmentRows;
        metrics["events.r0.driver.rawUnknownUnresolved"] = rawUnknownUnresolved;
        metrics["events.r0.driver.reportUnknownUnresolved"] = reportUnknownUnresolved;
        metrics["events.r0.driver.attributedRaw"] = rawAttributedDriverRows;
        metrics["events.r0.driver.attributedReport"] = reportAttributedDriverRows;
        metrics["events.r0.driver.attributedOmitted"] = Math.Max(0, rawAttributedDriverRows - reportAttributedDriverRows);
        metrics["events.r0.driver.unknownOmitted"] = Math.Max(0, (rawDriverRows.Count - rawAttributedDriverRows) - (reportDriverRows.Count - reportAttributedDriverRows));
        metrics["events.r0.driver.unknownUnresolvedOmitted"] = Math.Max(0, rawUnknownUnresolved - reportUnknownUnresolved);
        metrics["events.r0.driver.lossObserved"] = rawEvents.Count(IsR0LossEvidenceEvent);
        metrics["events.r0.driver.backpressureObserved"] = rawEvents.Count(IsR0BackpressureEvidenceEvent);
        metrics["events.r0.driver.drainStoppedAtDeadline"] = rawEvents.Count(evt => EventDataBoolTrue(evt, "drainStoppedAtDeadline"));
        metrics["events.r0.driver.drainStoppedAtBatchLimit"] = rawEvents.Count(evt => EventDataBoolTrue(evt, "drainStoppedAtBatchLimit"));
        var readSummaries = rawEvents.Where(evt => evt.EventType.Equals("r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase)).ToList();
        var lostCount = MaxDataUnsigned(rawEvents, "lostCount", "eventsDropped", "TotalEventsDropped");
        var processed = SumDataUnsigned(readSummaries, "recordsProcessed");
        var emitted = SumDataUnsigned(readSummaries, "eventsEmitted");
        metrics["events.r0.driver.lostCount"] = ToMetricInt(lostCount);
        metrics["events.r0.driver.recordsProcessed"] = ToMetricInt(processed);
        metrics["events.r0.driver.eventsEmitted"] = ToMetricInt(emitted);
        metrics["events.r0.driver.lossRateBasisPoints"] = processed == 0
            ? 0
            : lostCount >= processed
                ? 10000
                : ToMetricInt(lostCount * 10000UL / processed);

        // Keep queue/drain quality separate from the kernel lost counter. A
        // zero lostCount does not prove a complete drain when unread records,
        // a deadline stop, or collector suppression was reported.
        var health = CollectionHealthSummaryBuilder.Build(rawEvents, reportEvents);
        metrics["events.r0.driver.queueDepth"] = health.DriverQueueDepth;
        metrics["events.r0.driver.remainingUnread"] = health.DriverRemainingUnread;
        metrics["events.r0.driver.drainStoppedAtDeadlineRows"] = health.DriverDrainStoppedAtDeadlineRows;
        metrics["events.r0.driver.eventsSuppressed"] = health.DriverEventsSuppressed;
        metrics["events.r0.driver.qualityWarningRows"] = health.DriverQualityWarningRows;

        foreach (var category in new[] { "process", "image", "file", "registry", "network", "load", "other" })
        {
            metrics[$"events.r0.driver.{category}.raw"] = rawDriverRows.Count(evt => R0DriverCategory(evt) == category);
            metrics[$"events.r0.driver.{category}.report"] = reportDriverRows.Count(evt => R0DriverCategory(evt) == category);
        }
    }

    private static void AddEtwCoverageMetrics(
        Dictionary<string, int> metrics,
        IReadOnlyCollection<SandboxEvent> rawEvents)
    {
        var captured = rawEvents.Where(evt =>
            evt.EventType.Equals("etw_live.captured", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.Equals("etw_live.decode_failed", StringComparison.OrdinalIgnoreCase));
        var parsed = MaxDataUnsigned(captured, "parsedEventCount", "decodedEventCount");
        metrics["events.etw.parsedEventCount"] = ToMetricInt(parsed);
        metrics["etw.parsedEventCount"] = ToMetricInt(parsed);
        metrics["events.etw.etlDecodeRequired"] = captured.Any(evt =>
            EventDataBoolTrue(evt, "etlDecodeRequired")) ? 1 : 0;
    }

    private static bool IsR0DriverTelemetryRow(SandboxEvent evt) =>
        CollectionHealthSummaryBuilder.IsR0DriverTelemetryRow(evt);

    private static bool IsKnownEnvironmentalR0Row(SandboxEvent evt)
    {
        if (EventDataEqualsAny(evt, "sampleCorrelation", "environment") ||
            EventDataEqualsAny(evt, "sampleCorrelationStatus", "environment"))
        {
            return true;
        }

        // Generic negative flags are also stamped on unknown rows by the
        // classifier. Treating either as environment collapses the two
        // attribution boundaries and makes unresolved R0 rows look like
        // known system noise. Only explicit collector/self-noise markers are
        // safe environment evidence here; unknown rows remain visible in the
        // unresolved counters.
        return EventDataTruthy(
            evt,
            "collectorSelfNoise",
            "collectorNoise",
            "collectionNoise",
            "selfNoise",
            "selfProcess");
    }

    private static bool IsR0LossEvidenceEvent(SandboxEvent evt)
    {
        return EventDataBoolTrue(evt, "lost", "lossObserved", "sequenceGapObserved") ||
            evt.EventType.Equals("r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase) &&
            EventDataPositive(evt, "lostCount", "sequenceGapEstimate");
    }

    private static bool IsR0BackpressureEvidenceEvent(SandboxEvent evt)
    {
        return EventDataBoolTrue(evt, "backpressure", "backpressureObserved") ||
            evt.EventType.Equals("r0collector.driverReadEvents", StringComparison.OrdinalIgnoreCase) &&
            EventDataPositive(evt, "highWatermark", "collectorSkippedEvents", "skipped");
    }

    private static bool EventDataBoolTrue(SandboxEvent evt, params string[] keys)
    {
        return keys.Any(key => evt.Data.TryGetValue(key, out var value) &&
            (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1"));
    }

    private static bool EventDataPositive(SandboxEvent evt, params string[] keys)
    {
        return keys.Any(key => evt.Data.TryGetValue(key, out var value) &&
            ulong.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var number) && number > 0);
    }

    private static ulong MaxDataUnsigned(IEnumerable<SandboxEvent> events, params string[] keys)
    {
        return events.SelectMany(evt => keys.Select(key => evt.Data.TryGetValue(key, out var value) &&
            ulong.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var number) ? number : 0UL)).DefaultIfEmpty().Max();
    }

    private static ulong SumDataUnsigned(IEnumerable<SandboxEvent> events, string key)
    {
        return events.Select(evt => evt.Data.TryGetValue(key, out var value) &&
            ulong.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var number) ? number : 0UL)
            .Aggregate(0UL, (total, value) => ulong.MaxValue - total < value ? ulong.MaxValue : total + value);
    }

    private static int ToMetricInt(ulong value) => value > int.MaxValue ? int.MaxValue : (int)value;

    private static string R0DriverCategory(SandboxEvent evt)
        => CollectionHealthSummaryBuilder.GetR0DriverCategory(evt);

    private static void AddDynamicCoverageMetrics(
        Dictionary<string, int> metrics,
        IReadOnlyCollection<SandboxEvent> reportEvents,
        IReadOnlyCollection<SandboxEvent> rawEvents,
        int? rawEventCount,
        int omittedReportEvents)
    {
        var rawDynamicActionCount = rawEvents.Count(IsDynamicActionEvent);
        var reportDynamicActionCount = reportEvents.Count(IsDynamicActionEvent);
        metrics["events.dynamicAction.raw"] = rawDynamicActionCount;
        metrics["events.dynamicAction.report"] = reportDynamicActionCount;
        metrics["events.dynamicAction.omitted"] = Math.Max(0, rawDynamicActionCount - reportDynamicActionCount);
        var rawUnattributedDynamicActionCount = rawEvents.Count(evt =>
            IsDynamicActionEvent(evt) && !IsSampleAttributedDynamicActionEvent(evt));
        var reportUnattributedDynamicActionCount = reportEvents.Count(evt =>
            IsDynamicActionEvent(evt) && !IsSampleAttributedDynamicActionEvent(evt));
        metrics["events.dynamicAction.rawUnknown"] = rawUnattributedDynamicActionCount;
        // Keep attribution and report-cap accounting separate. A large raw
        // minus report delta is often expected environment traffic, not lost
        // sample evidence. These counters make that distinction explicit in
        // report.json and allow HTML to explain it without guessing.
        metrics["events.dynamicAction.attributedRaw"] = rawDynamicActionCount - rawUnattributedDynamicActionCount;
        metrics["events.dynamicAction.attributedReport"] = reportDynamicActionCount - reportUnattributedDynamicActionCount;
        metrics["events.dynamicAction.attributedOmitted"] = Math.Max(
            0,
            metrics["events.dynamicAction.attributedRaw"] - metrics["events.dynamicAction.attributedReport"]);
        metrics["events.dynamicAction.unattributedReport"] = reportUnattributedDynamicActionCount;
        // Keep a raw/report network lane independent from the sampled event
        // list.  HTML coverage uses this when all environment/unknown rows
        // spill out of report.Events and no import summary survives inline.
        AddDynamicCategoryMetrics(metrics, "events.network", rawEvents, reportEvents, IsNetworkEvent);
        AddDynamicCategoryMetrics(metrics, "events.networkTcp", rawEvents, reportEvents, IsTcpEvent);
        AddDynamicCategoryMetrics(metrics, "events.process", rawEvents, reportEvents, IsProcessEvent);
        AddDynamicCategoryMetrics(metrics, "events.thread", rawEvents, reportEvents, IsThreadEvent);
        AddDynamicCategoryMetrics(metrics, "events.module", rawEvents, reportEvents, IsModuleEvent);
        AddDynamicCategoryMetrics(metrics, "events.security", rawEvents, reportEvents, IsSecurityEvent);
        AddDynamicCategoryMetrics(metrics, "events.persistence", rawEvents, reportEvents, IsPersistenceEvent);
        AddDynamicCategoryMetrics(metrics, "events.file", rawEvents, reportEvents, IsFileEvent);
        if (rawEventCount.HasValue)
        {
            metrics["events.rawProvided"] = rawEventCount.Value;
        }
    }

    private static void AddDynamicCategoryMetrics(
        Dictionary<string, int> metrics,
        string metricPrefix,
        IReadOnlyCollection<SandboxEvent> rawEvents,
        IReadOnlyCollection<SandboxEvent> reportEvents,
        Func<SandboxEvent, bool> predicate)
    {
        var rawCount = rawEvents.Count(predicate);
        var reportCount = reportEvents.Count(predicate);
        var rawUnattributed = rawEvents.Count(evt => predicate(evt) && !IsSampleAttributedDynamicActionEvent(evt));
        var reportUnattributed = reportEvents.Count(evt => predicate(evt) && !IsSampleAttributedDynamicActionEvent(evt));
        metrics[$"{metricPrefix}.raw"] = rawCount;
        metrics[$"{metricPrefix}.report"] = reportCount;
        metrics[$"{metricPrefix}.omitted"] = Math.Max(0, rawCount - reportCount);
        metrics[$"{metricPrefix}.rawUnknown"] = rawUnattributed;
        metrics[$"{metricPrefix}.attributedRaw"] = rawCount - rawUnattributed;
        metrics[$"{metricPrefix}.attributedReport"] = reportCount - reportUnattributed;
        metrics[$"{metricPrefix}.attributedOmitted"] = Math.Max(
            0,
            metrics[$"{metricPrefix}.attributedRaw"] - metrics[$"{metricPrefix}.attributedReport"]);
    }

    private static bool IsDynamicActionEvent(SandboxEvent evt) =>
        ReportEventSampler.IsDynamicActionEventForMetrics(evt);

    private static bool IsTcpEvent(SandboxEvent evt) =>
        evt.EventType.StartsWith("network.tcp", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("driver.network", StringComparison.OrdinalIgnoreCase);

    private static bool IsProcessEvent(SandboxEvent evt) =>
        evt.EventType.StartsWith("process.", StringComparison.OrdinalIgnoreCase);

    private static bool IsThreadEvent(SandboxEvent evt) =>
        evt.EventType.StartsWith("thread.", StringComparison.OrdinalIgnoreCase);

    private static bool IsModuleEvent(SandboxEvent evt) =>
        evt.EventType.StartsWith("image.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("module.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("load.", StringComparison.OrdinalIgnoreCase);

    private static bool IsSecurityEvent(SandboxEvent evt) =>
        evt.EventType.StartsWith("security.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("security_eventlog.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("etw_security.", StringComparison.OrdinalIgnoreCase);

    private static bool IsNetworkEvent(SandboxEvent evt) =>
        evt.EventType.StartsWith("network.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("http.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("dns.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("tls.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("pcap.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("driver.network", StringComparison.OrdinalIgnoreCase);

    private static bool IsPersistenceEvent(SandboxEvent evt) =>
        IsDynamicActionEvent(evt) &&
        (evt.EventType.StartsWith("registry.", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("driver.registry", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("registry.run.", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("startup_item.", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("startup.", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("scheduled_task.", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("wmi.", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("persistence.", StringComparison.OrdinalIgnoreCase) ||
         evt.EventType.StartsWith("service.", StringComparison.OrdinalIgnoreCase));

    private static bool IsFileEvent(SandboxEvent evt) =>
        evt.EventType.StartsWith("file.", StringComparison.OrdinalIgnoreCase) ||
        evt.EventType.StartsWith("driver.file", StringComparison.OrdinalIgnoreCase);

    private static bool IsSampleAttributedDynamicActionEvent(SandboxEvent evt)
    {
        if (EventDataTruthy(evt, "behaviorCounted", "sampleBehaviorCandidate", "strongSampleCorrelation"))
        {
            return true;
        }

        return EventDataEqualsAny(evt, "sampleCorrelation", "confirmed", "probable", "candidate") ||
            EventDataEqualsAny(evt, "sampleCorrelationStatus", "correlated", "confirmed", "probable", "candidate") ||
            EventDataEqualsAny(evt, "evidenceDisposition", "behavior-candidate", "sample-attributed");
    }

    private static bool EventDataEqualsAny(SandboxEvent evt, string key, params string[] values) =>
        evt.Data.TryGetValue(key, out var value) &&
        values.Any(expected => string.Equals(value, expected, StringComparison.OrdinalIgnoreCase));

    private static bool EventDataTruthy(SandboxEvent evt, params string[] keys) =>
        keys.Any(key => evt.Data.TryGetValue(key, out var value) &&
            value is not null && (value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1"));
}

