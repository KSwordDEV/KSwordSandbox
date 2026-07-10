using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.Samples;

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
        WriteIndented = true
    };

    private readonly SandboxConfig config;
    private readonly RuleEngine ruleEngine;
    private readonly HyperVRunbookBuilder runbookBuilder;
    private readonly HtmlReportRenderer reportRenderer;
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
        HtmlReportRenderer? reportRenderer = null)
    {
        this.config = config;
        this.ruleEngine = new RuleEngine(rules);
        this.runbookBuilder = runbookBuilder ?? new HyperVRunbookBuilder();
        this.reportRenderer = reportRenderer ?? new HtmlReportRenderer();
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
    /// Creates a planned job and writes JSON/HTML planning artifacts.
    /// Inputs are a SandboxSubmission, processing validates the sample, builds
    /// a Hyper-V runbook, classifies seed events, and writes reports; the
    /// method returns the completed planning job.
    /// </summary>
    public AnalysisJob Plan(SandboxSubmission submission)
    {
        var duration = ClampDuration(submission.DurationSeconds);
        var normalizedSubmission = submission with { DurationSeconds = duration, DryRun = true };
        var jobId = Guid.NewGuid();
        var jobRoot = Path.Combine(config.Paths.RuntimeRoot, "jobs", jobId.ToString("N"));
        Directory.CreateDirectory(jobRoot);

        var sample = SampleHasher.Compute(normalizedSubmission.SamplePath, config.Analysis.MaxSampleBytes);
        var runbook = runbookBuilder.Build(config with
        {
            Analysis = config.Analysis with { DefaultDurationSeconds = duration }
        }, jobId, sample);

        var seedEvents = CreatePlanningEvents(sample, normalizedSubmission, runbook);
        var findings = ruleEngine.Classify(seedEvents);
        var report = new AnalysisReport
        {
            JobId = jobId,
            Sample = sample,
            Status = AnalysisStatus.Planned,
            Events = seedEvents,
            Findings = findings,
            Metrics = BuildMetrics(seedEvents, findings)
        };

        var jsonPath = Path.Combine(jobRoot, "report.json");
        var htmlPath = Path.Combine(jobRoot, "report.html");
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, JsonOptions));
        File.WriteAllText(htmlPath, reportRenderer.Render(report));

        var job = new AnalysisJob
        {
            JobId = jobId,
            Submission = normalizedSubmission,
            Status = AnalysisStatus.Planned,
            Sample = sample,
            Runbook = runbook,
            JsonReportPath = jsonPath,
            HtmlReportPath = htmlPath,
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
    /// Creates seed events that document the planned job before VM execution.
    /// Inputs are sample metadata, submission, and runbook; processing creates
    /// normalized host events; the method returns the event list.
    /// </summary>
    private static List<SandboxEvent> CreatePlanningEvents(SampleIdentity sample, SandboxSubmission submission, SandboxRunbook runbook)
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
                    ["sizeBytes"] = sample.SizeBytes.ToString()
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
    /// Builds small report metrics from events and findings.
    /// Inputs are event and finding lists, processing counts total and severity
    /// groups, and the method returns a metric dictionary.
    /// </summary>
    private static Dictionary<string, int> BuildMetrics(List<SandboxEvent> events, List<BehaviorFinding> findings)
    {
        var metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["events.total"] = events.Count,
            ["findings.total"] = findings.Count
        };

        foreach (var group in findings.GroupBy(finding => finding.Severity))
        {
            metrics[$"findings.{group.Key}"] = group.Count();
        }

        return metrics;
    }
}
