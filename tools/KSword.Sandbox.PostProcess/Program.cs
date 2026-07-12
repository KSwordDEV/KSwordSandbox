using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.Samples;
using KSword.Sandbox.Core.StaticAnalysis;

var exitCode = PostProcessProgram.Run(args);
return exitCode;

internal static class PostProcessProgram
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public static int Run(string[] args)
    {
        try
        {
            var options = ParseOptions(args);
            if (options.ShowHelp)
            {
                PrintHelp();
                return 0;
            }

            var repoRoot = ResolveRepositoryRoot(options.RepoRoot);
            var config = SandboxConfigLoader.Load(options.ConfigPath, repoRoot);
            var jobRoot = ResolveJobRoot(options.JobRoot, config.Paths.RuntimeRoot, options.JobId);
            var jobId = ResolveJobId(options.JobId, jobRoot);
            var eventsPath = ResolveEventsPath(options.EventsPath, jobRoot, jobId);
            var samplePath = ResolveSamplePath(options.SamplePath, jobRoot);

            Directory.CreateDirectory(jobRoot);
            var sample = SampleHasher.Compute(samplePath, config.Analysis.MaxSampleBytes);
            var staticAnalyzer = new StaticAnalyzer();
            var staticAnalysis = staticAnalyzer.Analyze(samplePath);
            var staticEvents = StaticAnalyzer.CreateEvents(sample.FullPath, staticAnalysis)
                .Select(NormalizeEvent)
                .ToList();
            var guestEvents = LoadEventsWithSiblingDriverJsonl(eventsPath);
            var hostEvents = BuildHostPostProcessEvents(jobId, jobRoot, eventsPath, guestEvents.Count);
            var allEvents = hostEvents
                .Concat(staticEvents)
                .Concat(guestEvents)
                .OrderBy(evt => evt.Timestamp)
                .ToList();
            var rulesPath = Path.Combine(repoRoot, config.Paths.RulesDirectory, "behavior-rules.json");
            var findings = ReportEventSampler.SanitizeFindings(new RuleEngine(RuleEngine.LoadRuleSet(rulesPath)).Classify(allEvents));
            var driverEventsPath = Path.Combine(Path.GetDirectoryName(eventsPath) ?? string.Empty, "driver-events.jsonl");
            var sampling = ReportEventSampler.SampleForReport(allEvents, jobRoot: jobRoot, eventsPath: eventsPath, driverEventsPath: driverEventsPath);
            var reportEvents = sampling.Events;
            var omittedReportEvents = sampling.OmittedEventCount;

            var status = guestEvents.Count > 0 ? AnalysisStatus.Completed : AnalysisStatus.Failed;
            var report = new AnalysisReport
            {
                JobId = jobId,
                Sample = sample,
                Status = status,
                StaticAnalysis = staticAnalysis,
                Events = reportEvents,
                Findings = findings,
                Metrics = BuildMetrics(allEvents, reportEvents, omittedReportEvents, findings, staticAnalysis)
            };

            var jsonReportPath = Path.Combine(jobRoot, "report.json");
            var htmlReportPath = Path.Combine(jobRoot, "report.html");
            var htmlZhReportPath = Path.Combine(jobRoot, "report.zh.html");
            var htmlEnReportPath = Path.Combine(jobRoot, "report.en.html");
            var renderer = new HtmlReportRenderer();
            File.WriteAllText(jsonReportPath, JsonSerializer.Serialize(report, JsonOptions));
            File.WriteAllText(htmlReportPath, renderer.RenderChinese(report));
            foreach (var document in renderer.RenderBilingualReports(report))
            {
                File.WriteAllText(Path.Combine(jobRoot, document.FileName), document.Html);
            }

            var resultPath = Path.Combine(jobRoot, "postprocess-result.json");
            var result = new
            {
                kind = "KSwordSandbox.PostProcessResult",
                success = true,
                jobId,
                jobRoot,
                samplePath,
                eventsPath,
                importedGuestEventCount = guestEvents.Count,
                importedStaticEventCount = staticEvents.Count,
                totalEventCount = allEvents.Count,
                reportEventCount = reportEvents.Count,
                omittedReportEventCount = omittedReportEvents,
                findingCount = findings.Count,
                jsonReportPath,
                htmlReportPath,
                htmlZhReportPath,
                htmlEnReportPath,
                completedAtUtc = DateTimeOffset.UtcNow,
                secretValuePrinted = false
            };
            File.WriteAllText(resultPath, JsonSerializer.Serialize(result, JsonOptions));
            Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"KSword.Sandbox.PostProcess failed: {ex.Message}");
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static Options ParseOptions(string[] args)
    {
        var options = new Options();
        for (var index = 0; index < args.Length; index++)
        {
            var arg = args[index];
            if (arg is "-h" or "--help" or "/?")
            {
                options.ShowHelp = true;
                continue;
            }

            string Next()
            {
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for {arg}.");
                }

                return args[++index];
            }

            switch (arg.ToLowerInvariant())
            {
                case "--repo-root":
                case "-reporoot":
                    options.RepoRoot = Next();
                    break;
                case "--config":
                case "--config-path":
                case "-configpath":
                    options.ConfigPath = Next();
                    break;
                case "--job-root":
                case "-jobroot":
                    options.JobRoot = Next();
                    break;
                case "--job-id":
                case "-jobid":
                    options.JobId = Next();
                    break;
                case "--events":
                case "--events-path":
                case "-eventspath":
                    options.EventsPath = Next();
                    break;
                case "--sample":
                case "--sample-path":
                case "-samplepath":
                    options.SamplePath = Next();
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {arg}");
            }
        }

        return options;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("KSword.Sandbox.PostProcess --job-root <path> --sample-path <exe> [--events-path <events.json>] [--config-path <config>] [--repo-root <repo>]");
    }

    private static string ResolveRepositoryRoot(string? explicitRoot)
    {
        if (!string.IsNullOrWhiteSpace(explicitRoot))
        {
            return Path.GetFullPath(explicitRoot);
        }

        var current = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(current))
        {
            if (File.Exists(Path.Combine(current, "KSwordSandbox.sln")))
            {
                return current;
            }

            var parent = Directory.GetParent(current)?.FullName;
            if (string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent ?? string.Empty;
        }

        return Directory.GetCurrentDirectory();
    }

    private static string ResolveJobRoot(string? explicitJobRoot, string runtimeRoot, string? jobIdText)
    {
        if (!string.IsNullOrWhiteSpace(explicitJobRoot))
        {
            var full = Path.GetFullPath(explicitJobRoot);
            if (!Directory.Exists(full))
            {
                throw new DirectoryNotFoundException($"Job root was not found: {full}");
            }

            return full;
        }

        if (string.IsNullOrWhiteSpace(jobIdText))
        {
            throw new ArgumentException("Either --job-root or --job-id is required.");
        }

        var compact = Guid.Parse(jobIdText).ToString("N");
        var path = Path.Combine(runtimeRoot, "jobs", compact);
        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"Job root was not found: {path}");
        }

        return path;
    }

    private static Guid ResolveJobId(string? explicitJobId, string jobRoot)
    {
        if (!string.IsNullOrWhiteSpace(explicitJobId))
        {
            return Guid.Parse(explicitJobId);
        }

        var leaf = Path.GetFileName(Path.TrimEndingDirectorySeparator(jobRoot));
        if (Guid.TryParseExact(leaf, "N", out var compact))
        {
            return compact;
        }

        if (Guid.TryParse(leaf, out var dashed))
        {
            return dashed;
        }

        var runbookPath = Path.Combine(jobRoot, "runbook-execution.json");
        if (File.Exists(runbookPath))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(runbookPath));
            if (doc.RootElement.TryGetProperty("JobId", out var jobIdElement) && Guid.TryParse(jobIdElement.GetString(), out var fromRunbook))
            {
                return fromRunbook;
            }
        }

        throw new InvalidOperationException($"Could not resolve job id from job root: {jobRoot}");
    }

    private static string ResolveEventsPath(string? explicitPath, string jobRoot, Guid jobId)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            var full = Path.GetFullPath(explicitPath);
            if (!File.Exists(full))
            {
                throw new FileNotFoundException("Events file was not found.", full);
            }

            return full;
        }

        var expected = Path.Combine(jobRoot, "guest", jobId.ToString("N"), "events.json");
        if (File.Exists(expected))
        {
            return expected;
        }

        var found = Directory.EnumerateFiles(jobRoot, "events.json", SearchOption.AllDirectories)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
        if (found is not null)
        {
            return found;
        }

        throw new FileNotFoundException($"events.json was not found under {jobRoot}.", expected);
    }

    private static string ResolveSamplePath(string? explicitPath, string jobRoot)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            var full = Path.GetFullPath(explicitPath);
            if (!File.Exists(full))
            {
                throw new FileNotFoundException("Sample file was not found.", full);
            }

            return full;
        }

        var planPath = Directory.EnumerateFiles(Path.Combine(Directory.GetParent(jobRoot)?.Parent?.FullName ?? jobRoot, "plans"), "hyperv-e2e-*.json", SearchOption.TopDirectoryOnly)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
        if (planPath is not null)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(planPath));
            if (doc.RootElement.TryGetProperty("sample", out var sample) && sample.TryGetProperty("hostPath", out var hostPathElement))
            {
                var hostPath = hostPathElement.GetString();
                if (!string.IsNullOrWhiteSpace(hostPath) && File.Exists(hostPath))
                {
                    return hostPath;
                }
            }
        }

        throw new ArgumentException("--sample-path is required when the sample cannot be inferred.");
    }

    private static List<SandboxEvent> LoadEventsWithSiblingDriverJsonl(string eventsPath)
    {
        var events = LoadEvents(eventsPath);
        var driverJsonl = Path.Combine(Path.GetDirectoryName(eventsPath) ?? string.Empty, "driver-events.jsonl");
        if (File.Exists(driverJsonl) && !events.Any(IsDriverPayloadEvent))
        {
            events.AddRange(LoadJsonLines(driverJsonl));
        }

        return events.Select(NormalizeEvent).ToList();
    }

    private static List<SandboxEvent> LoadEvents(string path)
    {
        using var stream = File.OpenRead(path);
        var first = ReadFirstNonWhitespaceByte(stream);
        if (first is null)
        {
            return [];
        }

        stream.Position = 0;
        if (first == (byte)'[')
        {
            return JsonSerializer.Deserialize<List<SandboxEvent>>(stream, JsonOptions) ?? [];
        }

        if (first == (byte)'{')
        {
            using var doc = JsonDocument.Parse(stream);
            if (doc.RootElement.TryGetProperty("events", out var eventsElement) && eventsElement.ValueKind == JsonValueKind.Array)
            {
                return JsonSerializer.Deserialize<List<SandboxEvent>>(eventsElement.GetRawText(), JsonOptions) ?? [];
            }
        }

        return LoadJsonLines(path);
    }

    private static byte? ReadFirstNonWhitespaceByte(Stream stream)
    {
        int value;
        do
        {
            value = stream.ReadByte();
            if (value < 0)
            {
                return null;
            }
        } while (char.IsWhiteSpace((char)value));

        return (byte)value;
    }

    private static List<SandboxEvent> LoadJsonLines(string path)
    {
        var events = new List<SandboxEvent>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var evt = JsonSerializer.Deserialize<SandboxEvent>(line, JsonOptions);
            if (evt is not null)
            {
                events.Add(evt);
            }
        }

        return events;
    }

    private static SandboxEvent NormalizeEvent(SandboxEvent evt)
    {
        return evt with
        {
            EventType = string.IsNullOrWhiteSpace(evt.EventType) ? "unknown" : evt.EventType,
            Source = string.IsNullOrWhiteSpace(evt.Source) ? "guest" : evt.Source,
            Data = evt.Data ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };
    }

    private static bool IsDriverPayloadEvent(SandboxEvent evt)
    {
        return evt.EventType.StartsWith("driver.", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.Source, "driver", StringComparison.OrdinalIgnoreCase);
    }

    private static List<SandboxEvent> BuildHostPostProcessEvents(Guid jobId, string jobRoot, string eventsPath, int guestEventCount)
    {
        var now = DateTimeOffset.UtcNow;
        return
        [
            new SandboxEvent
            {
                EventType = "guest.events.imported",
                Timestamp = now,
                Source = "host",
                Path = eventsPath,
                Data = CreateHostOperationalEventData(
                    "guest-events-imported",
                    "postprocess-guest-import-summary-not-sample-behavior",
                    "PostProcess import summary records host-side report rebuilding, not sample behavior.",
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["jobId"] = jobId.ToString("D"),
                    ["jobRoot"] = jobRoot,
                    ["importedEventCount"] = guestEventCount.ToString()
                })
            },
            new SandboxEvent
            {
                EventType = "report.generated",
                Timestamp = now,
                Source = "host",
                Path = jobRoot,
                Data = CreateHostOperationalEventData(
                    "report-generated",
                    "postprocess-report-generated-summary-not-sample-behavior",
                    "PostProcess report generation summary is host control-plane metadata, not sample behavior.",
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["generator"] = "KSword.Sandbox.PostProcess"
                })
            }
        ];
    }

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
            ["zhBehaviorHint"] = "该行由 Host/PostProcess 生成，用于记录导入或报告生成状态；behaviorCounted=false，不计入样本行为。",
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

    private static Dictionary<string, int> BuildMetrics(
        IReadOnlyCollection<SandboxEvent> rawEvents,
        IReadOnlyCollection<SandboxEvent> reportEvents,
        int omittedReportEvents,
        IReadOnlyCollection<BehaviorFinding> findings,
        StaticAnalysisResult? staticAnalysis)
    {
        var metrics = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["events"] = rawEvents.Count,
            ["rawEvents"] = rawEvents.Count,
            ["reportEvents"] = reportEvents.Count,
            ["omittedReportEvents"] = omittedReportEvents,
            ["findings"] = findings.Count,
            ["highFindings"] = findings.Count(finding => string.Equals(finding.Severity, "high", StringComparison.OrdinalIgnoreCase)),
            ["mediumFindings"] = findings.Count(finding => string.Equals(finding.Severity, "medium", StringComparison.OrdinalIgnoreCase)),
            ["lowFindings"] = findings.Count(finding => string.Equals(finding.Severity, "low", StringComparison.OrdinalIgnoreCase)),
            ["infoFindings"] = findings.Count(finding => string.Equals(finding.Severity, "info", StringComparison.OrdinalIgnoreCase)),
            ["processEvents"] = rawEvents.Count(evt => evt.EventType.Contains("process", StringComparison.OrdinalIgnoreCase)),
            ["fileEvents"] = rawEvents.Count(evt => evt.EventType.Contains("file", StringComparison.OrdinalIgnoreCase)),
            ["registryEvents"] = rawEvents.Count(evt => evt.EventType.Contains("registry", StringComparison.OrdinalIgnoreCase)),
            ["networkEvents"] = rawEvents.Count(evt => evt.EventType.Contains("network", StringComparison.OrdinalIgnoreCase) || evt.EventType.Contains("tcp", StringComparison.OrdinalIgnoreCase)),
            ["staticTags"] = staticAnalysis?.Tags.Count ?? 0
        };
        return metrics;
    }

    private sealed class Options
    {
        public bool ShowHelp { get; set; }
        public string? RepoRoot { get; set; }
        public string? ConfigPath { get; set; }
        public string? JobRoot { get; set; }
        public string? JobId { get; set; }
        public string? EventsPath { get; set; }
        public string? SamplePath { get; set; }
    }
}
