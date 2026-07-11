using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Network;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.Samples;
using KSword.Sandbox.Core.StaticAnalysis;

namespace KSword.Sandbox.Core.Jobs;

/// <summary>
/// Coordinates validation, runbook planning, behavior classification, and
/// report artifact creation for v1 dry-run jobs. Inputs are submissions and
/// loaded configuration, processing creates deterministic local artifacts, and
/// methods return AnalysisJob records for the Web API.
/// </summary>
public sealed class SandboxJobService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private readonly SandboxConfig config;
    private readonly RuleEngine ruleEngine;
    private readonly HyperVRunbookBuilder runbookBuilder;
    private readonly HtmlReportRenderer reportRenderer;
    private readonly StaticAnalyzer staticAnalyzer;
    private readonly HostArtifactIndexBuilder artifactIndexBuilder = new();
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
    }

    /// <summary>
    /// Returns all known jobs in creation order.
    /// There are no inputs; processing snapshots the in-memory dictionary; the
    /// method returns a list of AnalysisJob records.
    /// </summary>
    public IReadOnlyList<AnalysisJob> ListJobs()
    {
        return jobs.Values.OrderBy(job => job.CreatedAt).ToList();
    }

    /// <summary>
    /// Returns one job by ID when present.
    /// The input is a job ID, processing performs an in-memory lookup, and the
    /// method returns the job or null.
    /// </summary>
    public AnalysisJob? GetJob(Guid jobId)
    {
        return jobs.TryGetValue(jobId, out var job) ? job : null;
    }

    /// <summary>
    /// Builds the current host-visible artifact index for one known job.
    /// Inputs are a job ID; processing scans the deterministic job directory
    /// for reports, telemetry, screenshots, memory dumps, packet captures, and
    /// dropped files; the method returns descriptors without loading payloads.
    /// </summary>
    public HostArtifactIndex BuildArtifactIndex(Guid jobId)
    {
        EnsureJobExists(jobId);
        return artifactIndexBuilder.Build(jobId, GetJobRoot(jobId));
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
    /// a Hyper-V runbook, classifies seed events, and writes reports; the
    /// method returns the completed planning job.
    /// </summary>
    public AnalysisJob Plan(SandboxSubmission submission)
    {
        var duration = ClampDuration(submission.DurationSeconds);
        var normalizedSubmission = NormalizeSubmission(submission, duration);
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
            Sample = sample,
            Status = AnalysisStatus.Planned,
            StaticAnalysis = staticAnalysis,
            Events = seedEvents,
            Findings = findings,
            Metrics = BuildMetrics(seedEvents, findings, staticAnalysis)
        };

        var jsonPath = Path.Combine(jobRoot, "report.json");
        var htmlPath = Path.Combine(jobRoot, "report.html");
        var zhHtmlPath = Path.Combine(jobRoot, "report.zh.html");
        var enHtmlPath = Path.Combine(jobRoot, "report.en.html");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, JsonOptions));
        WriteHtmlReports(jobRoot, report);

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
                "Review the runbook before enabling privileged Hyper-V execution.",
                $"Artifacts written to {jobRoot}."
            ]
        };

        jobs[job.JobId] = job;
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
        if (!jobs.TryGetValue(jobId, out var job))
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        var jobRoot = GetJobRoot(jobId);
        Directory.CreateDirectory(jobRoot);
        var resultPath = Path.Combine(jobRoot, "runbook-execution.json");
        File.WriteAllText(resultPath, JsonSerializer.Serialize(result, JsonOptions));

        var status = result.Mode == SandboxRunbookExecutionMode.Live
            ? result.Success ? AnalysisStatus.Running : AnalysisStatus.Failed
            : job.Status;
        var existingGuestEvents = LoadGuestEventsIfPresent(job.GuestEventsPath);
        var updated = RegenerateReport(job with
        {
            Status = status,
            RunbookExecutionResultPath = resultPath,
            Messages = AppendMessage(job.Messages, $"Runbook execution result persisted to {resultPath}.")
        }, status, existingGuestEvents, job.GuestEventsPath);

        jobs[jobId] = updated;
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
        if (!jobs.TryGetValue(jobId, out var job))
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        var resolvedEventsPath = ResolveGuestEventsPath(jobId, eventsPath);
        var guestEvents = LoadGuestEventsWithDriverJsonl(resolvedEventsPath);
        var status = guestEvents.Count == 0 ? AnalysisStatus.Failed : AnalysisStatus.Completed;
        var message = guestEvents.Count == 0
            ? $"Guest event import found no events in {resolvedEventsPath}."
            : $"Imported {guestEvents.Count} guest event(s) from {resolvedEventsPath}.";
        var updated = RegenerateReport(job with
        {
            Status = status,
            GuestEventsPath = resolvedEventsPath,
            Messages = AppendMessage(job.Messages, message)
        }, status, guestEvents, resolvedEventsPath);

        jobs[jobId] = updated;
        return updated;
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
        if (!jobs.TryGetValue(jobId, out var job))
        {
            throw new KeyNotFoundException($"Job {jobId} was not found.");
        }

        var normalizedOffset = Math.Max(0, offset);
        var normalizedTake = Math.Clamp(take, 1, 500);
        var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var eventKeys = new HashSet<string>(StringComparer.Ordinal);
        var events = new List<SandboxEvent>();

        foreach (var path in EnumerateLiveEventFiles(job))
        {
            foreach (var liveEvent in TryLoadEventsForLiveMonitor(path))
            {
                var normalized = NormalizeEvent(liveEvent);
                if (eventKeys.Add(EventKey(normalized)))
                {
                    events.Add(normalized);
                }
            }

            sources.Add(path);
        }

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
                    Data =
                    {
                        ["exceptionType"] = ex.GetType().Name,
                        ["message"] = ex.Message
                    }
                }
            ];
        }
    }

    /// <summary>
    /// Rewrites report.json and report.html from current host and guest data.
    /// Inputs are job metadata, target status, guest events, and source path;
    /// processing rebuilds deterministic host seed events, appends execution
    /// and import markers, classifies all events, and returns updated metadata.
    /// </summary>
    private AnalysisJob RegenerateReport(AnalysisJob job, AnalysisStatus status, IReadOnlyCollection<SandboxEvent> guestEvents, string? guestEventsPath)
    {
        var sample = job.Sample ?? throw new InvalidOperationException("Job does not have sample metadata.");
        var runbook = job.Runbook ?? throw new InvalidOperationException("Job does not have a runbook.");
        var jobRoot = GetJobRoot(job.JobId);
        Directory.CreateDirectory(jobRoot);

        var staticAnalysis = LoadExistingReport(job.JsonReportPath)?.StaticAnalysis ?? AnalyzeSample(sample);
        var jobConfig = BuildJobConfig(job.Submission, job.Submission.DurationSeconds);
        var events = CreatePlanningEvents(sample, job.Submission, runbook, staticAnalysis, jobConfig.ArtifactCollection);
        AppendRunbookExecutionEvent(events, job.RunbookExecutionResultPath);
        events.AddRange(guestEvents.Select(NormalizeEvent));
        AppendGuestImportEvent(events, guestEventsPath, guestEvents.Count);

        var fullEvents = events.OrderBy(evt => evt.Timestamp).ToList();
        var findings = ReportEventSampler.SanitizeFindings(ruleEngine.Classify(fullEvents));
        var driverEventsPath = string.IsNullOrWhiteSpace(guestEventsPath)
            ? null
            : Path.Combine(Path.GetDirectoryName(guestEventsPath) ?? string.Empty, "driver-events.jsonl");
        var sampling = ReportEventSampler.SampleForReport(fullEvents, jobRoot: jobRoot, eventsPath: guestEventsPath, driverEventsPath: driverEventsPath);
        var report = new AnalysisReport
        {
            JobId = job.JobId,
            Sample = sample,
            Status = status,
            StaticAnalysis = staticAnalysis,
            Events = sampling.Events,
            Findings = findings,
            Metrics = BuildMetrics(sampling.Events, findings, staticAnalysis, fullEvents.Count, sampling.OmittedEventCount)
        };

        var jsonPath = Path.Combine(jobRoot, "report.json");
        var htmlPath = Path.Combine(jobRoot, "report.html");
        var zhHtmlPath = Path.Combine(jobRoot, "report.zh.html");
        var enHtmlPath = Path.Combine(jobRoot, "report.en.html");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, JsonOptions));
        WriteHtmlReports(jobRoot, report);

        return job with
        {
            Status = status,
            JsonReportPath = jsonPath,
            HtmlReportPath = htmlPath,
            HtmlReportZhPath = zhHtmlPath,
            HtmlReportEnPath = enHtmlPath,
            GuestEventsPath = guestEventsPath ?? job.GuestEventsPath
        };
    }

    /// <summary>
    /// Writes the default compatibility report plus explicit localized report
    /// variants. Inputs are one job directory and report model; processing keeps
    /// report.html English for existing smoke tests and emits report.zh.html /
    /// report.en.html for the bilingual WebUI; the method returns no value.
    /// </summary>
    private void WriteHtmlReports(string jobRoot, AnalysisReport report)
    {
        var artifactIndex = artifactIndexBuilder.Build(report.JobId, jobRoot);
        File.WriteAllText(Path.Combine(jobRoot, "report.html"), reportRenderer.RenderEnglish(report, artifactIndex.Artifacts));
        foreach (var document in reportRenderer.RenderBilingualReports(report, artifactIndex.Artifacts))
        {
            File.WriteAllText(Path.Combine(jobRoot, document.FileName), document.Html);
        }

        artifactIndexBuilder.WriteIndex(report.JobId, jobRoot);
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

    private void EnsureJobExists(Guid jobId)
    {
        if (!jobs.ContainsKey(jobId))
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
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var decoded = Uri.UnescapeDataString(value.Trim()).Replace('\\', '/').TrimStart('/');
        return ArtifactDescriptorFactory.NormalizeRelativePath(decoded);
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
    /// Resolves the guest event artifact for a job.
    /// Inputs are job ID and optional explicit path, processing accepts a file
    /// or searches jobRoot\guest recursively, and the method returns the file
    /// path or throws when no artifact exists.
    /// </summary>
    private string ResolveGuestEventsPath(Guid jobId, string? eventsPath)
    {
        if (!string.IsNullOrWhiteSpace(eventsPath))
        {
            if (!File.Exists(eventsPath))
            {
                throw new FileNotFoundException("Guest events file was not found.", eventsPath);
            }

            return Path.GetFullPath(eventsPath);
        }

        var guestRoot = Path.Combine(GetJobRoot(jobId), "guest");
        if (!Directory.Exists(guestRoot))
        {
            throw new DirectoryNotFoundException($"Guest output folder was not found: {guestRoot}");
        }

        var eventsJson = Directory
            .EnumerateFiles(guestRoot, "events.json", SearchOption.AllDirectories)
            .OrderByDescending(path => File.GetLastWriteTimeUtc(path))
            .FirstOrDefault();
        if (eventsJson is not null)
        {
            return eventsJson;
        }

        var jsonLines = Directory
            .EnumerateFiles(guestRoot, "*.jsonl", SearchOption.AllDirectories)
            .OrderByDescending(path => File.GetLastWriteTimeUtc(path))
            .FirstOrDefault();
        if (jsonLines is not null)
        {
            return jsonLines;
        }

        throw new FileNotFoundException($"No events.json or .jsonl artifact was found under {guestRoot}.");
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

        foreach (var path in Directory
            .EnumerateFiles(guestRoot, "*.*", SearchOption.AllDirectories)
            .Where(path =>
                string.Equals(Path.GetFileName(path), "events.json", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(Path.GetExtension(path), ".jsonl", StringComparison.OrdinalIgnoreCase) ||
                ArtifactDescriptorFactory.IsPacketCapturePath(path))
            .OrderBy(path => File.GetLastWriteTimeUtc(path)))
        {
            var fullPath = Path.GetFullPath(path);
            if (seen.Add(fullPath))
            {
                yield return fullPath;
            }
        }
    }

    /// <summary>
    /// Loads guest events and nearby driver JSONL events without duplicates.
    /// The input is a primary event file, processing reads JSON array or JSONL
    /// data and optional sibling driver-events.jsonl files, and the method
    /// returns normalized event records.
    /// </summary>
    private static List<SandboxEvent> LoadGuestEventsWithDriverJsonl(string eventsPath)
    {
        var events = LoadEventsFromFile(eventsPath);
        var eventKeys = events.Select(EventKey).ToHashSet(StringComparer.Ordinal);
        var searchRoot = Path.GetDirectoryName(eventsPath);
        if (string.IsNullOrWhiteSpace(searchRoot))
        {
            return events.Select(NormalizeEvent).ToList();
        }

        foreach (var jsonlPath in Directory
            .EnumerateFiles(searchRoot, "driver-events.jsonl", SearchOption.AllDirectories))
        {
            foreach (var driverEvent in LoadEventsFromJsonLines(jsonlPath))
            {
                var normalized = NormalizeEvent(driverEvent);
                if (eventKeys.Add(EventKey(normalized)))
                {
                    events.Add(normalized);
                }
            }
        }

        foreach (var pcapPath in EnumeratePacketCaptures(searchRoot))
        {
            foreach (var pcapEvent in new PcapArtifactEventImporter().Import(pcapPath))
            {
                var normalized = NormalizeImportedPcapEvent(pcapEvent, pcapPath, searchRoot);
                if (eventKeys.Add(EventKey(normalized)))
                {
                    events.Add(normalized);
                }
            }
        }

        return events.Select(NormalizeEvent).ToList();
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
        var data = new Dictionary<string, string>(normalized.Data, StringComparer.OrdinalIgnoreCase)
        {
            ["sourceArtifactPath"] = pcapPath,
            ["sourceArtifactKind"] = ArtifactKind.PacketCapture.ToString(),
            ["sourceArtifactRelativePath"] = ArtifactDescriptorFactory.SafeRelativePath(importRoot, pcapPath),
            ["sourceImportRoot"] = importRoot,
            ["collectionName"] = "packet-captures",
            ["evidenceRole"] = "packet-capture",
            ["captureSource"] = "external",
            ["hostCaptureStarted"] = "false",
            ["importMode"] = "external-artifact",
            ["pcapFormat"] = string.Equals(Path.GetExtension(pcapPath), ".pcapng", StringComparison.OrdinalIgnoreCase)
                ? "pcapng"
                : "pcap"
        };

        try
        {
            var info = new FileInfo(pcapPath);
            data["sourceArtifactSizeBytes"] = info.Length.ToString();
            data["sourceArtifactSha256"] = ComputeSha256(info.FullName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            data["sourceArtifactHashSkipped"] = ex.GetType().Name;
        }

        return normalized with { Data = data };
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

        foreach (var path in Directory
            .EnumerateFiles(searchRoot, "*.*", SearchOption.AllDirectories)
            .Where(ArtifactDescriptorFactory.IsPacketCapturePath)
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
            : (JsonSerializer.Deserialize<List<SandboxEvent>>(File.ReadAllText(path), JsonOptions) ?? []).Select(NormalizeEvent).ToList();
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
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
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
                    Data =
                    {
                        ["line"] = line
                    }
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
    private static void AppendRunbookExecutionEvent(List<SandboxEvent> events, string? resultPath)
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

            events.Add(new SandboxEvent
            {
                EventType = "hyperv.runbook.executed",
                Source = "host",
                Path = result.TargetVmName,
                Data =
                {
                    ["mode"] = result.Mode.ToString(),
                    ["success"] = result.Success.ToString(),
                    ["totalSteps"] = result.TotalSteps.ToString(),
                    ["executedSteps"] = result.ExecutedSteps.ToString(),
                    ["failedStepIndex"] = result.FailedStepIndex?.ToString() ?? string.Empty,
                    ["duration"] = result.Duration.ToString(),
                    ["resultPath"] = resultPath,
                    ["message"] = result.Message ?? string.Empty
                }
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            events.Add(new SandboxEvent
            {
                EventType = "hyperv.runbook.execution_result_error",
                Source = "host",
                Path = resultPath,
                Data =
                {
                    ["error"] = ex.Message
                }
            });
        }
    }

    /// <summary>
    /// Appends a host event documenting guest event import status.
    /// Inputs are event output, imported path, and imported count; processing
    /// writes one status event when a path is known; the method returns no value.
    /// </summary>
    private static void AppendGuestImportEvent(List<SandboxEvent> events, string? guestEventsPath, int guestEventCount)
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
            Data =
            {
                ["eventCount"] = guestEventCount.ToString()
            }
        });
    }

    /// <summary>
    /// Creates a stable key used to avoid duplicate driver events.
    /// The input is one event, processing combines common fields and ordered
    /// data values, and the method returns a comparison key.
    /// </summary>
    private static string EventKey(SandboxEvent evt)
    {
        var data = string.Join(";", evt.Data.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => $"{pair.Key}={pair.Value}"));
        return string.Join("|", evt.EventType, evt.Source, evt.Timestamp.ToString("O"), evt.ProcessId?.ToString() ?? string.Empty, evt.Path ?? string.Empty, evt.CommandLine ?? string.Empty, data);
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
    /// Clamps requested duration to configured safe bounds.
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
    /// overrides. Inputs are the raw submission and clamped duration; processing
    /// trims string values and forces dry-run planning mode; the method returns
    /// the persisted request snapshot.
    /// </summary>
    private static SandboxSubmission NormalizeSubmission(SandboxSubmission submission, int duration)
    {
        return submission with
        {
            DurationSeconds = duration,
            DryRun = true,
            GoldenVmName = CleanOptional(submission.GoldenVmName),
            GoldenSnapshotName = CleanOptional(submission.GoldenSnapshotName),
            GuestUserName = CleanOptional(submission.GuestUserName),
            GuestWorkingDirectory = CleanOptional(submission.GuestWorkingDirectory),
            GuestPayloadRoot = CleanOptional(submission.GuestPayloadRoot)
        };
    }

    /// <summary>
    /// Creates a per-job sandbox configuration from optional WebUI overrides.
    /// Inputs are the normalized submission and clamped analysis duration;
    /// processing overlays safe Hyper-V/guest/path/driver fields; the method
    /// returns the config used to build the concrete runbook.
    /// </summary>
    private SandboxConfig BuildJobConfig(SandboxSubmission submission, int duration)
    {
        return config with
        {
            HyperV = config.HyperV with
            {
                GoldenVmName = submission.GoldenVmName ?? config.HyperV.GoldenVmName,
                GoldenSnapshotName = submission.GoldenSnapshotName ?? config.HyperV.GoldenSnapshotName
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
                UseMockCollector = submission.UseMockCollector ?? config.Driver.UseMockCollector
            },
            ArtifactCollection = config.ArtifactCollection with
            {
                CollectDroppedFiles = submission.CollectDroppedFiles ?? config.ArtifactCollection.CollectDroppedFiles,
                CaptureScreenshots = submission.CaptureScreenshots ?? config.ArtifactCollection.CaptureScreenshots,
                CaptureMemoryDumps = submission.CaptureMemoryDumps ?? config.ArtifactCollection.CaptureMemoryDumps,
                CapturePacketCapture = submission.CapturePacketCapture ?? config.ArtifactCollection.CapturePacketCapture
            },
            Analysis = config.Analysis with { DefaultDurationSeconds = duration }
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
        return
        [
            new SandboxEvent
            {
                EventType = "submission.accepted",
                Source = "host",
                Path = sample.FullPath,
                CommandLine = submission.DisplayName ?? sample.FileName,
                Data =
                {
                    ["sha256"] = sample.Sha256,
                    ["sha1"] = sample.Sha1,
                    ["md5"] = sample.Md5,
                    ["crc32"] = sample.Crc32,
                    ["sizeBytes"] = sample.SizeBytes.ToString(),
                    ["collectDroppedFiles"] = artifactCollection.CollectDroppedFiles.ToString(),
                    ["captureScreenshots"] = artifactCollection.CaptureScreenshots.ToString(),
                    ["captureMemoryDumps"] = artifactCollection.CaptureMemoryDumps.ToString(),
                    ["capturePacketCapture"] = artifactCollection.CapturePacketCapture.ToString(),
                    ["collectDroppedFilesOverride"] = FormatNullableBool(submission.CollectDroppedFiles),
                    ["captureScreenshotsOverride"] = FormatNullableBool(submission.CaptureScreenshots),
                    ["captureMemoryDumpsOverride"] = FormatNullableBool(submission.CaptureMemoryDumps),
                    ["capturePacketCaptureOverride"] = FormatNullableBool(submission.CapturePacketCapture)
                }
            },
            new SandboxEvent
            {
                EventType = "static.analysis.completed",
                Source = "host",
                Path = sample.FullPath,
                Data =
                {
                    ["fileFormat"] = staticAnalysis.FileFormat,
                    ["isPe"] = staticAnalysis.IsPe.ToString(),
                    ["tags"] = string.Join(",", staticAnalysis.Tags),
                    ["urls"] = staticAnalysis.Urls.Count.ToString(),
                    ["interestingStrings"] = staticAnalysis.InterestingStrings.Count.ToString()
                }
            },
            new SandboxEvent
            {
                EventType = "hyperv.runbook.created",
                Source = "host",
                Path = runbook.TargetVmName,
                Data =
                {
                    ["steps"] = runbook.Steps.Count.ToString(),
                    ["usesTemporaryVm"] = runbook.UsesTemporaryVm.ToString()
                }
            }
        ];
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
        int omittedReportEvents = 0)
    {
        var totalEvents = rawEventCount ?? events.Count;
        var metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["events.total"] = totalEvents,
            ["events.raw"] = totalEvents,
            ["events.report"] = events.Count,
            ["events.omittedFromReport"] = omittedReportEvents,
            ["findings.total"] = findings.Count,
            ["static.tags"] = staticAnalysis.Tags.Count,
            ["static.urls"] = staticAnalysis.Urls.Count,
            ["static.interestingStrings"] = staticAnalysis.InterestingStrings.Count
        };

        foreach (var group in findings.GroupBy(finding => finding.Severity))
        {
            metrics[$"findings.{group.Key}"] = group.Count();
        }

        return metrics;
    }
}
