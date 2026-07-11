using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;

internal static partial class ProgramMain
{
    private static SandboxJobService CreateService(ToolContext context)
    {
        var rulesPath = Path.Combine(context.Config.Paths.RulesDirectory, "behavior-rules.json");
        if (!File.Exists(rulesPath))
        {
            throw new FileNotFoundException("未找到行为规则文件。请使用 --repo-root/--config 让 rulesDirectory 解析到正确目录。/ Behavior rules file was not found. Use --repo-root/--config so rulesDirectory resolves correctly.", rulesPath);
        }

        var rules = RuleEngine.LoadRuleSet(rulesPath);
        return new SandboxJobService(context.Config, rules);
    }

    private static ToolContext CreateContext(JobToolOptions options, string? runtimeRootOverride = null)
    {
        var repositoryRoot = ResolveRepositoryRoot(GetOption(options, "repo-root", string.Empty));
        var configPath = ResolveConfigPath(options, repositoryRoot);
        var config = SandboxConfigLoader.Load(configPath, repositoryRoot);
        var runtimeRoot = runtimeRootOverride ?? GetOption(options, "runtime-root", string.Empty);
        if (!string.IsNullOrWhiteSpace(runtimeRoot))
        {
            config = config with { Paths = config.Paths with { RuntimeRoot = Path.GetFullPath(runtimeRoot) } };
        }

        return new ToolContext(repositoryRoot, configPath, config);
    }

    private static string ResolveRepositoryRoot(string explicitRoot)
    {
        if (!string.IsNullOrWhiteSpace(explicitRoot))
        {
            return Path.GetFullPath(explicitRoot);
        }

        var current = Directory.GetCurrentDirectory();
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

    private static string ResolveConfigPath(JobToolOptions options, string repositoryRoot)
    {
        var explicitConfig = GetOption(options, "config", GetOption(options, "config-path", string.Empty));
        if (!string.IsNullOrWhiteSpace(explicitConfig))
        {
            return Path.IsPathRooted(explicitConfig)
                ? explicitConfig
                : Path.GetFullPath(Path.Combine(repositoryRoot, explicitConfig));
        }

        var envConfig = Environment.GetEnvironmentVariable("Sandbox__ConfigPath");
        if (!string.IsNullOrWhiteSpace(envConfig))
        {
            return envConfig;
        }

        return Path.Combine(repositoryRoot, "config", "sandbox.example.json");
    }

    private static string ResolveRuntimeRoot(JobToolOptions options, SandboxConfig config)
    {
        var runtimeRoot = GetOption(options, "runtime-root", config.Paths.RuntimeRoot);
        return Path.GetFullPath(string.IsNullOrWhiteSpace(runtimeRoot) ? DefaultRuntimeRoot : runtimeRoot);
    }

    private static JobLocator ResolveJobLocator(JobToolOptions options, SandboxConfig config, bool requireExisting)
    {
        var explicitJobRoot = GetOption(options, "job-root", string.Empty);
        var explicitJobId = GetOption(options, "job-id", string.Empty);
        Guid? parsedJobId = null;
        if (!string.IsNullOrWhiteSpace(explicitJobId))
        {
            parsedJobId = ParseGuid(explicitJobId, "job-id");
        }

        if (!string.IsNullOrWhiteSpace(explicitJobRoot))
        {
            var fullJobRoot = Path.GetFullPath(explicitJobRoot);
            if (requireExisting && !Directory.Exists(fullJobRoot))
            {
                throw new DirectoryNotFoundException($"未找到任务目录: {fullJobRoot} / Job root was not found: {fullJobRoot}");
            }

            var jobId = parsedJobId ?? TryResolveJobId(fullJobRoot) ?? throw new ArgumentException("无法从 --job-root 推断任务 ID；请添加 --job-id <guid>。/ Could not infer job id from --job-root. Add --job-id <guid>.");
            return new JobLocator(jobId, fullJobRoot);
        }

        if (parsedJobId is null)
        {
            throw new ArgumentException("缺少必需参数 --job-id 或 --job-root。/ Missing required --job-id or --job-root.");
        }

        var runtimeRoot = ResolveRuntimeRoot(options, config);
        var jobRoot = Path.Combine(runtimeRoot, "jobs", parsedJobId.Value.ToString("N"));
        if (requireExisting && !Directory.Exists(jobRoot))
        {
            throw new DirectoryNotFoundException($"未找到任务目录: {jobRoot} / Job root was not found: {jobRoot}");
        }

        return new JobLocator(parsedJobId.Value, jobRoot);
    }

    private static string ResolveServiceRuntimeRoot(JobToolOptions options, SandboxConfig config, JobLocator locator)
    {
        var explicitRuntimeRoot = GetOption(options, "runtime-root", string.Empty);
        if (!string.IsNullOrWhiteSpace(explicitRuntimeRoot))
        {
            return Path.GetFullPath(explicitRuntimeRoot);
        }

        var inferred = TryInferRuntimeRootFromJobRoot(locator.JobRoot);
        if (!string.IsNullOrWhiteSpace(inferred))
        {
            return inferred;
        }

        return ResolveRuntimeRoot(options, config);
    }

    private static string? TryInferRuntimeRootFromJobRoot(string jobRoot)
    {
        var full = Path.GetFullPath(jobRoot);
        var parent = Directory.GetParent(Path.TrimEndingDirectorySeparator(full));
        if (parent is null || !string.Equals(parent.Name, "jobs", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return parent.Parent?.FullName;
    }

    private static void EnsureServiceJobRootMatchesLocator(SandboxConfig config, JobLocator locator)
    {
        var expected = Path.Combine(config.Paths.RuntimeRoot, "jobs", locator.JobId.ToString("N"));
        if (!SamePath(expected, locator.JobRoot))
        {
            throw new ArgumentException($"任务目录 {locator.JobRoot} 不是确定性的服务路径 {expected}。请使用 --runtime-root，或将 --job-root 放在 <runtimeRoot>\\jobs\\<jobId> 下。/ Job root {locator.JobRoot} is not the deterministic service path {expected}. Use --runtime-root or a --job-root under <runtimeRoot>\\jobs\\<jobId>.");
        }
    }

    private static string ResolveSamplePath(JobToolOptions options, string jobRoot)
    {
        var explicitSample = GetOption(options, "sample", GetOption(options, "sample-path", string.Empty));
        if (!string.IsNullOrWhiteSpace(explicitSample))
        {
            return RequireExistingFile(explicitSample, "sample");
        }

        var report = TryLoadReport(Path.Combine(jobRoot, "report.json"));
        var reportSamplePath = report?.Sample?.FullPath;
        if (!string.IsNullOrWhiteSpace(reportSamplePath) && File.Exists(reportSamplePath))
        {
            return Path.GetFullPath(reportSamplePath);
        }

        var planSamplePath = TryResolveSamplePathFromPlan(jobRoot, TryResolveJobId(jobRoot));
        if (!string.IsNullOrWhiteSpace(planSamplePath) && File.Exists(planSamplePath))
        {
            return Path.GetFullPath(planSamplePath);
        }

        throw new ArgumentException("缺少 --sample；无法从 report.json 或 Hyper-V plan 文件推断原始样本路径。/ Missing --sample. The original sample path could not be inferred from report.json or Hyper-V plan files.");
    }

    private static string? TryResolveSamplePathFromPlan(string jobRoot, Guid? expectedJobId)
    {
        var jobsDirectory = Directory.GetParent(Path.TrimEndingDirectorySeparator(Path.GetFullPath(jobRoot)));
        var runtimeRoot = jobsDirectory?.Parent?.FullName;
        if (string.IsNullOrWhiteSpace(runtimeRoot))
        {
            return null;
        }

        var plansRoot = Path.Combine(runtimeRoot, "plans");
        if (!Directory.Exists(plansRoot))
        {
            return null;
        }

        foreach (var planPath in Directory.EnumerateFiles(plansRoot, "hyperv-e2e-*.json", SearchOption.TopDirectoryOnly)
            .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(planPath));
                if (expectedJobId is not null &&
                    TryGetPropertyIgnoreCase(document.RootElement, "job", out var jobElement) &&
                    TryGetPropertyIgnoreCase(jobElement, "jobId", out var jobIdElement) &&
                    Guid.TryParse(jobIdElement.GetString(), out var planJobId) &&
                    planJobId != expectedJobId.Value)
                {
                    continue;
                }

                if (TryGetPropertyIgnoreCase(document.RootElement, "sample", out var sample) &&
                    TryGetPropertyIgnoreCase(sample, "hostPath", out var hostPathElement))
                {
                    var hostPath = hostPathElement.GetString();
                    if (!string.IsNullOrWhiteSpace(hostPath) && File.Exists(hostPath))
                    {
                        return hostPath;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                // Ignore stale or partial plan files and continue looking.
            }
        }

        return null;
    }

    private static string ResolveEventsPath(JobToolOptions options, string jobRoot, Guid jobId)
    {
        return ResolveEventInput(options, jobRoot, jobId, allowFailureSkeleton: false).Path;
    }

    private static EventInputResolution ResolveEventInput(JobToolOptions options, string jobRoot, Guid jobId, bool allowFailureSkeleton)
    {
        var explicitEvents = GetOption(options, "events", GetOption(options, "events-path", string.Empty));
        if (!string.IsNullOrWhiteSpace(explicitEvents))
        {
            var explicitPath = RequireExistingFile(explicitEvents, "events");
            return new EventInputResolution
            {
                Path = explicitPath,
                Source = "explicit",
                CandidateCount = 1,
                CandidatePaths = [explicitPath],
                Message = "使用显式 --events 输入。/ Using explicit --events input."
            };
        }

        var candidates = FindEventCandidatePaths(jobRoot, jobId);
        if (candidates.Count > 0)
        {
            var selected = candidates[0];
            var hints = new List<string>();
            if (candidates.Count > 1)
            {
                hints.Add("检测到多个事件候选文件；如选择不符合预期，请用 --events <path> 明确指定。/ Multiple event candidates were found; pass --events <path> if this selection is not intended.");
            }

            return new EventInputResolution
            {
                Path = selected,
                Source = "discovered",
                CandidateCount = candidates.Count,
                CandidatePaths = candidates,
                Message = candidates.Count > 1
                    ? $"选择最新/最明确的事件候选文件：{selected}。/ Selected event candidate: {selected}."
                    : $"发现事件文件：{selected}。/ Found event file: {selected}.",
                RemediationHints = hints
            };
        }

        if (allowFailureSkeleton)
        {
            var runbookExecutionPath = ResolveRunbookExecutionPath(options, jobRoot);
            if (!string.IsNullOrWhiteSpace(runbookExecutionPath) && File.Exists(runbookExecutionPath))
            {
                var skeletonPath = WriteFailureEventSkeletonFromRunbook(jobRoot, jobId, runbookExecutionPath);
                return new EventInputResolution
                {
                    Path = skeletonPath,
                    Source = "generated-failure-skeleton",
                    CreatedFailureSkeleton = true,
                    CandidateCount = 1,
                    CandidatePaths = [skeletonPath],
                    Message = "未找到 events.json；已根据 runbook-execution.json 生成可导入 failure skeleton。/ events.json was missing; generated an importable failure skeleton from runbook-execution.json.",
                    RemediationHints =
                    [
                        "该 skeleton 仅用于失败诊断报告，不代表 Guest Agent 完整运行。/ The skeleton is diagnostic only and does not prove the Guest Agent ran completely.",
                        "修复 live 失败后重新运行 E2E，或用 --events 指向真实来宾事件文件重建报告。/ After fixing live failure, rerun E2E or rebuild with --events pointing at real guest events."
                    ]
                };
            }
        }

        var expected = Path.Combine(jobRoot, "guest", jobId.ToString("N"), "events.json");
        throw new FileNotFoundException($"在 {jobRoot} 下未找到 events.json 或 .jsonl 产物；也无法从 runbook-execution.json 生成 skeleton。请添加 --events <path>，或先运行 recover/report after collect。/ No events.json or .jsonl artifact was found under {jobRoot}, and no runbook-execution.json skeleton source was available. Add --events <path> or run recover/report after collection.", expected);
    }

    private static string? ResolveRunbookExecutionPath(JobToolOptions options, string jobRoot)
    {
        var explicitRunbook = GetOption(options, "runbook-execution", GetOption(options, "runbook-execution-path", string.Empty));
        if (!string.IsNullOrWhiteSpace(explicitRunbook))
        {
            return RequireExistingFile(explicitRunbook, "runbook-execution");
        }

        var expected = Path.Combine(jobRoot, "runbook-execution.json");
        return File.Exists(expected) ? Path.GetFullPath(expected) : null;
    }

    private static List<string> FindEventCandidatePaths(string jobRoot, Guid? jobId)
    {
        var candidates = new List<string>();
        if (jobId is not null)
        {
            AddCandidatePath(candidates, Path.Combine(jobRoot, "guest", jobId.Value.ToString("N"), "events.json"));
        }

        if (!Directory.Exists(jobRoot))
        {
            return candidates;
        }

        foreach (var path in Directory.EnumerateFiles(jobRoot, "events.json", SearchOption.AllDirectories)
            .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            AddCandidatePath(candidates, path);
        }

        foreach (var path in Directory.EnumerateFiles(jobRoot, "*.jsonl", SearchOption.AllDirectories)
            .Where(path => !Path.GetFileName(path).Equals("driver-events.jsonl", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            AddCandidatePath(candidates, path);
        }

        foreach (var path in Directory.EnumerateFiles(jobRoot, "driver-events.jsonl", SearchOption.AllDirectories)
            .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            AddCandidatePath(candidates, path);
        }

        return candidates;
    }

    private static void AddCandidatePath(List<string> candidates, string path)
    {
        if (File.Exists(path))
        {
            var fullPath = Path.GetFullPath(path);
            if (!candidates.Contains(fullPath, StringComparer.OrdinalIgnoreCase))
            {
                candidates.Add(fullPath);
            }
        }
    }

    private static string WriteFailureEventSkeletonFromRunbook(string jobRoot, Guid jobId, string runbookExecutionPath)
    {
        var guestOutputDirectory = Path.Combine(jobRoot, "guest", jobId.ToString("N"));
        Directory.CreateDirectory(guestOutputDirectory);
        var eventsPath = Path.Combine(guestOutputDirectory, "events.json");
        var metadataPath = Path.Combine(guestOutputDirectory, "guest-output-skeleton.json");
        var now = DateTimeOffset.UtcNow;
        var failureReason = ReadRunbookFailureReason(runbookExecutionPath);
        if (string.IsNullOrWhiteSpace(failureReason))
        {
            failureReason = "events.json missing; generated importable failure skeleton from runbook-execution.json.";
        }

        WriteTextIfMissing(Path.Combine(guestOutputDirectory, "agent.pid"), "0");
        WriteTextIfMissing(Path.Combine(guestOutputDirectory, "agent.exit"), "-1");
        WriteTextIfMissing(Path.Combine(guestOutputDirectory, "agent.stdout.log"), string.Empty);
        WriteTextIfMissing(Path.Combine(guestOutputDirectory, "agent.stderr.log"), failureReason);

        var skeletonEvent = new[]
        {
            new Dictionary<string, object?>
            {
                ["eventType"] = "hyperv.e2e.failure_skeleton",
                ["timestamp"] = now,
                ["source"] = "host",
                ["processName"] = "KSword.Sandbox.JobTool",
                ["processId"] = Environment.ProcessId,
                ["path"] = jobRoot,
                ["commandLine"] = "JobTool generated a guest-output skeleton because events.json was missing during report rebuild.",
                ["data"] = new Dictionary<string, object?>
                {
                    ["jobId"] = jobId.ToString("D"),
                    ["jobRoot"] = jobRoot,
                    ["failureReason"] = failureReason,
                    ["runbookExecutionPath"] = runbookExecutionPath,
                    ["generatedBy"] = "KSword.Sandbox.JobTool",
                    ["importable"] = "True",
                    ["skeleton"] = "True",
                    ["secretValuePrinted"] = "False"
                }
            }
        };
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(skeletonEvent, JsonOptions));

        var metadata = new
        {
            contractVersion = 1,
            kind = "KSwordSandbox.GuestOutputSkeleton",
            generatedAtUtc = now,
            generatedBy = "KSword.Sandbox.JobTool",
            importable = true,
            jobId,
            jobRoot,
            reason = failureReason,
            secretValuePrinted = false,
            paths = new
            {
                guestOutputDirectory,
                eventsJsonPath = eventsPath,
                runbookExecutionPath
            },
            note = "该 skeleton 仅用于报告重建/失败诊断，不代表 Guest Agent 已成功运行。"
        };
        File.WriteAllText(metadataPath, JsonSerializer.Serialize(metadata, JsonOptions));
        return eventsPath;
    }

    private static void WriteTextIfMissing(string path, string value)
    {
        if (!File.Exists(path))
        {
            File.WriteAllText(path, value);
        }
    }

    private static string ReadRunbookFailureReason(string runbookExecutionPath)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(runbookExecutionPath));
            var root = document.RootElement;
            var direct = TryReadJsonString(root, "failureReason", "FailureReason", "message", "Message");
            if (!string.IsNullOrWhiteSpace(direct))
            {
                return direct;
            }

            if (TryGetPropertyIgnoreCase(root, "failure", out var failure))
            {
                return TryReadJsonString(failure, "reason", "message", "failureReason");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return ex.Message;
        }

        return string.Empty;
    }

    private static JobSummary BuildJobSummary(string jobRoot, bool buildArtifactIndex)
    {
        var fullJobRoot = Path.GetFullPath(jobRoot);
        var reportPath = Path.Combine(fullJobRoot, "report.json");
        var report = TryLoadReport(reportPath);
        var jobId = report?.JobId is { } reportJobId && reportJobId != Guid.Empty
            ? reportJobId
            : TryResolveJobId(fullJobRoot);
        var htmlPath = FirstExistingPath(
            Path.Combine(fullJobRoot, "report.html"),
            Path.Combine(fullJobRoot, "report.en.html"),
            Path.Combine(fullJobRoot, "report.zh.html"));
        var eventsPath = TryFindEventsPath(fullJobRoot, jobId);
        var runbookExecutionPath = FirstExistingPath(Path.Combine(fullJobRoot, "runbook-execution.json"));
        var runbookProgressPath = FirstExistingPath(Path.Combine(fullJobRoot, "runbook-progress.json"));
        var startResultPath = FirstExistingPath(Path.Combine(fullJobRoot, "hyperv-e2e-start-result.json"));
        var collectResultPath = FirstExistingPath(Path.Combine(fullJobRoot, "hyperv-e2e-collect-result.json"));
        var reportRebuildDiagnosticsPath = FirstExistingPath(Path.Combine(fullJobRoot, "report-rebuild-diagnostics.json"));
        var guestOutputSkeletonPath = TryFindGuestOutputSkeletonPath(fullJobRoot);
        var indexPath = Path.Combine(fullJobRoot, HostArtifactIndexBuilder.IndexFileName);
        int? artifactCount = null;
        int? collectionCount = null;
        if (buildArtifactIndex && jobId is not null && Directory.Exists(fullJobRoot))
        {
            var index = new HostArtifactIndexBuilder().Build(jobId.Value, fullJobRoot);
            artifactCount = index.Artifacts.Count;
            collectionCount = index.Collections.Count;
        }
        else if (File.Exists(indexPath))
        {
            var index = TryReadArtifactIndex(fullJobRoot);
            artifactCount = index?.Artifacts.Count;
            collectionCount = index?.Collections.Count;
        }

        var missingKeyArtifacts = new List<string>();
        if (runbookExecutionPath is null)
        {
            missingKeyArtifacts.Add("runbook-execution.json");
        }

        if (eventsPath is null)
        {
            missingKeyArtifacts.Add("guest events (events.json/jsonl)");
        }

        if (!File.Exists(reportPath))
        {
            missingKeyArtifacts.Add("report.json");
        }

        var knownPaths = new[] { reportPath, htmlPath, eventsPath, runbookExecutionPath, runbookProgressPath, guestOutputSkeletonPath, startResultPath, collectResultPath, reportRebuildDiagnosticsPath, indexPath }
            .Where(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path))
            .Cast<string>()
            .ToList();
        var lastWriteUtc = knownPaths.Count > 0
            ? knownPaths.Select(File.GetLastWriteTimeUtc).Max()
            : Directory.Exists(fullJobRoot) ? Directory.GetLastWriteTimeUtc(fullJobRoot) : (DateTime?)null;

        return new JobSummary
        {
            IsCandidate = jobId is not null || report is not null || eventsPath is not null || runbookExecutionPath is not null,
            JobId = jobId,
            JobRoot = fullJobRoot,
            Status = report?.Status.ToString() ?? (Directory.Exists(fullJobRoot) ? "unknown" : "missing"),
            SampleName = report?.Sample?.FileName ?? "unknown",
            SamplePath = report?.Sample?.FullPath,
            SampleSha256 = report?.Sample?.Sha256,
            JsonReportPath = File.Exists(reportPath) ? reportPath : null,
            HtmlReportPath = htmlPath,
            GuestEventsPath = eventsPath,
            RunbookExecutionPath = runbookExecutionPath,
            RunbookProgressPath = runbookProgressPath,
            GuestOutputSkeletonPath = guestOutputSkeletonPath,
            StartResultPath = startResultPath,
            CollectResultPath = collectResultPath,
            ReportRebuildDiagnosticsPath = reportRebuildDiagnosticsPath,
            ReportEventCount = report?.Events.Count,
            FindingCount = report?.Findings.Count,
            ArtifactCount = artifactCount,
            CollectionCount = collectionCount,
            LastWriteUtc = lastWriteUtc.HasValue ? new DateTimeOffset(DateTime.SpecifyKind(lastWriteUtc.Value, DateTimeKind.Utc)) : null,
            MissingKeyArtifacts = missingKeyArtifacts,
            Metrics = report?.Metrics ?? []
        };
    }

    private static string? TryFindGuestOutputSkeletonPath(string jobRoot)
    {
        if (!Directory.Exists(jobRoot))
        {
            return null;
        }

        return Directory.EnumerateFiles(jobRoot, "guest-output-skeleton.json", SearchOption.AllDirectories)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .Select(Path.GetFullPath)
            .FirstOrDefault();
    }

    private static AnalysisReport? TryLoadReport(string path)
    {
        if (!File.Exists(path))
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

    private static HostArtifactIndex? TryReadArtifactIndex(string jobRoot)
    {
        try
        {
            return new HostArtifactIndexBuilder().TryReadIndex(jobRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static Guid? TryResolveJobId(string jobRoot)
    {
        var leaf = Path.GetFileName(Path.TrimEndingDirectorySeparator(Path.GetFullPath(jobRoot)));
        if (Guid.TryParseExact(leaf, "N", out var compact))
        {
            return compact;
        }

        if (Guid.TryParse(leaf, out var dashed))
        {
            return dashed;
        }

        var report = TryLoadReport(Path.Combine(jobRoot, "report.json"));
        if (report?.JobId is { } reportJobId && reportJobId != Guid.Empty)
        {
            return reportJobId;
        }

        foreach (var candidate in new[] { "runbook-execution.json", "postprocess-result.json" })
        {
            var path = Path.Combine(jobRoot, candidate);
            var jobId = TryReadGuidProperty(path, "jobId", "JobId");
            if (jobId is not null)
            {
                return jobId;
            }
        }

        return null;
    }

    private static Guid? TryReadGuidProperty(string path, params string[] names)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var name in names)
            {
                if (TryGetPropertyIgnoreCase(document.RootElement, name, out var element) && Guid.TryParse(element.GetString(), out var parsed))
                {
                    return parsed;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return null;
        }

        return null;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static string? TryFindEventsPath(string jobRoot, Guid? jobId)
    {
        return FindEventCandidatePaths(jobRoot, jobId).FirstOrDefault();
    }

    private static string? FirstExistingPath(params string?[] paths)
    {
        foreach (var path in paths)
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                return Path.GetFullPath(path);
            }
        }

        return null;
    }

    private static string RequireExistingFile(string path, string optionName)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"--{optionName} 指定的必需文件不存在。/ Required file for --{optionName} was not found.", fullPath);
        }

        return fullPath;
    }

    private static JobToolOptions ParseOptions(IReadOnlyList<string> args)
    {
        var result = new JobToolOptions();
        for (var index = 0; index < args.Count; index++)
        {
            var token = args[index];
            if (string.IsNullOrWhiteSpace(token))
            {
                continue;
            }

            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"不支持的位置参数: {token} / Unexpected positional argument: {token}");
            }

            var nameAndValue = token[2..];
            if (string.IsNullOrWhiteSpace(nameAndValue))
            {
                throw new ArgumentException("选项名称不能为空。/ Empty option name is not valid.");
            }

            var equalsIndex = nameAndValue.IndexOf('=', StringComparison.Ordinal);
            if (equalsIndex >= 0)
            {
                var name = nameAndValue[..equalsIndex];
                var value = nameAndValue[(equalsIndex + 1)..];
                result.Values[name] = value;
                continue;
            }

            if (index + 1 < args.Count && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                result.Values[nameAndValue] = args[++index];
            }
            else
            {
                result.Flags.Add(nameAndValue);
                result.Values[nameAndValue] = "true";
            }
        }

        return result;
    }

    private static string GetOption(JobToolOptions options, string name, string defaultValue)
    {
        return options.Values.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : defaultValue;
    }

    private static bool GetBool(JobToolOptions options, string name)
    {
        if (!options.Values.TryGetValue(name, out var value))
        {
            return false;
        }

        if (options.Flags.Contains(name))
        {
            return true;
        }

        return value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("1", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("y", StringComparison.OrdinalIgnoreCase);
    }

    private static bool? GetNullableBool(JobToolOptions options, string name)
    {
        return options.Values.ContainsKey(name) ? GetBool(options, name) : null;
    }

    private static int ParseLimit(JobToolOptions options, int defaultValue)
    {
        var value = GetOption(options, "limit", defaultValue.ToString(CultureInfo.InvariantCulture));
        var limit = ParseNonNegativeInt(value, "limit");
        return Math.Clamp(limit, 1, 1000);
    }

    private static int ParseNonNegativeInt(string value, string name)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) || parsed < 0)
        {
            throw new ArgumentException($"--{name} 必须是非负整数；当前值: {value} / --{name} must be a non-negative integer. Value: {value}");
        }

        return parsed;
    }

    private static Guid ParseGuid(string value, string name)
    {
        if (!Guid.TryParse(value, out var parsed) || parsed == Guid.Empty)
        {
            throw new ArgumentException($"--{name} 必须是非空 GUID；当前值: {value} / --{name} must be a non-empty GUID. Value: {value}");
        }

        return parsed;
    }

    private static bool IsHelp(string value)
    {
        return value.Equals("help", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("--help", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("-h", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("/?", StringComparison.OrdinalIgnoreCase);
    }

    private static void WriteMetadata(IReadOnlyDictionary<string, string> metadata, string indent)
    {
        foreach (var pair in metadata.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            var value = IsSensitivePropertyName(pair.Key) ? "[redacted]" : Safe(pair.Value);
            Console.WriteLine($"{indent}{Safe(pair.Key)}={value}");
        }
    }

    private static void WriteJson(object value)
    {
        var serialized = JsonSerializer.Serialize(value, JsonOptions);
        var node = JsonNode.Parse(serialized);
        var redacted = RedactNode(node, propertyName: null);
        Console.WriteLine(redacted?.ToJsonString(JsonOptions) ?? "{}");
    }

    private static JsonNode? RedactNode(JsonNode? node, string? propertyName)
    {
        if (node is null)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(propertyName) && IsSensitivePropertyName(propertyName))
        {
            return JsonValue.Create("[redacted]");
        }

        if (node is JsonObject obj)
        {
            var clone = new JsonObject();
            foreach (var pair in obj)
            {
                clone[pair.Key] = RedactNode(pair.Value, pair.Key);
            }

            return clone;
        }

        if (node is JsonArray array)
        {
            var clone = new JsonArray();
            foreach (var item in array)
            {
                clone.Add(RedactNode(item, propertyName: null));
            }

            return clone;
        }

        if (node is JsonValue valueNode && valueNode.TryGetValue<string>(out var text))
        {
            return JsonValue.Create(RedactSecretText(text));
        }

        return JsonNode.Parse(node.ToJsonString(JsonOptions));
    }

    private static bool IsSensitivePropertyName(string name)
    {
        var normalized = name.Replace("_", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();
        if (normalized is "secretvalueprinted" or "passwordsecretname")
        {
            return false;
        }

        return normalized.Contains("password", StringComparison.Ordinal) ||
            normalized.Contains("passwd", StringComparison.Ordinal) ||
            normalized.Contains("apikey", StringComparison.Ordinal) ||
            normalized.Contains("token", StringComparison.Ordinal) ||
            normalized.Contains("secret", StringComparison.Ordinal) ||
            normalized.Contains("credential", StringComparison.Ordinal) ||
            normalized.Contains("authorization", StringComparison.Ordinal) ||
            normalized.Contains("bearer", StringComparison.Ordinal);
    }

    private static string Safe(string? value)
    {
        return RedactSecretText(value ?? string.Empty);
    }

    private static string RedactSecretText(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        var redacted = BearerRegex().Replace(text, "Bearer [redacted]");
        redacted = SecretAssignmentRegex().Replace(redacted, match => $"{match.Groups[1].Value}=[redacted]");
        return redacted;
    }

    private static string FormatNullable(int? value)
    {
        return value?.ToString(CultureInfo.InvariantCulture) ?? "未知 / unknown";
    }

    private static string FormatDate(DateTimeOffset? value)
    {
        return value?.ToString("u", CultureInfo.InvariantCulture) ?? "未知 / unknown";
    }

    private static string FormatNameForHuman(string? value)
    {
        return IsUnknown(value) ? "未知 / unknown" : Safe(value);
    }

    private static string FormatPathForHuman(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? "未生成 / missing" : Safe(value);
    }

    private static string FormatValueOrUnavailable(string? value)
    {
        return string.IsNullOrWhiteSpace(value) || value.Equals("n/a", StringComparison.OrdinalIgnoreCase)
            ? "无 / n/a"
            : Safe(value);
    }

    private static string ReadArtifactMetadata(ArtifactDescriptor artifact, string key)
    {
        return artifact.Metadata.TryGetValue(key, out var value) ? value : string.Empty;
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string FormatStatusForHuman(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "未知 / unknown";
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "queued" => "已排队 / queued",
            "planning" => "规划中 / planning",
            "planned" => "已规划 / planned",
            "running" => "运行中 / running",
            "completed" => "已完成 / completed",
            "failed" => "失败 / failed",
            "missing" => "缺失 / missing",
            "unknown" => "未知 / unknown",
            _ => Safe(value)
        };
    }

    private static string FormatReadinessStatusForHuman(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "未知 / unknown";
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "passed" => "通过 / passed",
            "warning" => "警告 / warning",
            "failed" => "失败 / failed",
            _ => Safe(value)
        };
    }

    private static string FormatRecoveryStateForHuman(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "未知 / unknown";
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "missing" => "缺失 / missing",
            "present" => "已存在 / present",
            "unreadable" => "不可读取 / unreadable",
            "completed" => "已完成 / completed",
            "failed" => "失败 / failed",
            "report-rebuilt" => "报告已重建 / report rebuilt",
            "failed-action-required" => "失败，需要处理 / failed, action required",
            "report-missing" => "报告缺失 / report missing",
            "recoverable" => "可恢复 / recoverable",
            _ => Safe(value)
        };
    }

    private static string FormatTextOrNone(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? "无 / none" : Safe(value);
    }

    private static string FormatArtifactKindForHuman(ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.Unknown => "未知 / unknown",
            ArtifactKind.ArtifactManifest => "产物清单 / artifact manifest",
            ArtifactKind.ReportJson => "JSON 报告 / report JSON",
            ArtifactKind.ReportHtml => "HTML 报告 / report HTML",
            ArtifactKind.RunbookJson => "运行手册 JSON / runbook JSON",
            ArtifactKind.RunbookExecutionJson => "运行记录 JSON / runbook execution JSON",
            ArtifactKind.GuestEventsJson => "来宾事件 JSON / guest events JSON",
            ArtifactKind.GuestSummaryJson => "来宾摘要 JSON / guest summary JSON",
            ArtifactKind.DroppedFile => "落地文件 / dropped file",
            ArtifactKind.DriverEventsJsonLines => "驱动事件 JSONL / driver events JSONL",
            ArtifactKind.StaticAnalysisJson => "静态分析 JSON / static analysis JSON",
            ArtifactKind.Screenshot => "截图 / screenshot",
            ArtifactKind.MemoryDump => "内存转储 / memory dump",
            ArtifactKind.PacketCapture => "抓包 / packet capture",
            ArtifactKind.Log => "日志 / log",
            ArtifactKind.Bundle => "产物包 / bundle",
            ArtifactKind.ArtifactIndex => "产物索引 / artifact index",
            _ => Safe(kind.ToString())
        };
    }

    private static string FormatCollectionStatusForHuman(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "未知 / unknown";
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "captured" => "已采集 / captured",
            "enabled" => "已启用 / enabled",
            "disabled" => "已禁用 / disabled",
            "skipped" => "已跳过 / skipped",
            "unavailable" => "不可用 / unavailable",
            "missing" => "缺失 / missing",
            "pending" => "待处理 / pending",
            "failed" => "失败 / failed",
            "unknown" => "未知 / unknown",
            _ => Safe(value)
        };
    }

    private static bool IsUnknown(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ||
            value.Equals("unknown", StringComparison.OrdinalIgnoreCase);
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{bytes} B"
            : $"{value:0.##} {units[unit]}";
    }

    private static bool SamePath(string left, string right)
    {
        return string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            StringComparison.OrdinalIgnoreCase);
    }

    private static void AddPathCheck(
        List<ReadinessCheck> checks,
        string checkId,
        string name,
        string path,
        bool required,
        bool expectDirectory)
    {
        var fullPath = string.IsNullOrWhiteSpace(path) ? string.Empty : Path.GetFullPath(path);
        var exists = !string.IsNullOrWhiteSpace(fullPath) &&
            (expectDirectory
                ? Directory.Exists(fullPath)
                : File.Exists(fullPath));
        var details = new Dictionary<string, object?>
        {
            ["path"] = fullPath,
            ["exists"] = exists,
            ["expectedKind"] = expectDirectory ? "directory" : "file"
        };

        if (exists)
        {
            checks.Add(ReadinessCheck.Passed(checkId, name, required, $"{name} 存在: {fullPath} / {name} exists: {fullPath}", details));
            return;
        }

        var hint = expectDirectory
            ? $"创建或配置所需目录: {fullPath} / Create or configure the required directory: {fullPath}"
            : $"创建、构建或配置所需文件: {fullPath} / Create, build, or configure the required file: {fullPath}";
        if (required)
        {
            checks.Add(ReadinessCheck.Failed(checkId, name, required, $"{name} 缺失: {fullPath} / {name} is missing: {fullPath}", details, [hint]));
        }
        else
        {
            checks.Add(ReadinessCheck.Warning(checkId, name, required, $"{name} 不存在: {fullPath} / {name} is not present: {fullPath}", details, [hint]));
        }
    }

    private static List<RecoveryResultFile> ReadRecoveryResultFiles(string jobRoot)
    {
        var files = new (string Name, string FileName)[]
        {
            ("runbook", "runbook-execution.json"),
            ("runbook-progress", "runbook-progress.json"),
            ("start", "hyperv-e2e-start-result.json"),
            ("collect", "hyperv-e2e-collect-result.json"),
            ("guest-import", "guest-import-state.json"),
            ("report-rebuild", "report-rebuild-diagnostics.json"),
            ("operator-recovery", "operator-recovery.json")
        };

        return files
            .Select(file => ReadRecoveryResultFile(file.Name, Path.Combine(jobRoot, file.FileName)))
            .ToList();
    }

    private static RecoveryResultFile ReadRecoveryResultFile(string name, string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return new RecoveryResultFile
            {
                Name = name,
                Path = fullPath,
                Exists = false,
                State = "missing"
            };
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(fullPath));
            var root = document.RootElement;
            var success = TryReadJsonBool(root, "success", "Success");
            var state = TryReadJsonString(root, "state", "State", "overallStatus", "OverallStatus", "status", "Status");
            var message = TryReadJsonString(root, "message", "Message", "operatorMessage", "OperatorMessage");
            var failureReason = TryReadJsonString(root, "failureReason", "FailureReason", "error", "Error");
            var remediationHints = TryReadJsonStringArray(root, "remediationHints", "RemediationHints", "recommendedActions", "RecommendedActions");
            if (string.IsNullOrWhiteSpace(state) && success is not null)
            {
                state = success.Value ? "completed" : "failed";
            }

            return new RecoveryResultFile
            {
                Name = name,
                Path = fullPath,
                Exists = true,
                Success = success,
                State = string.IsNullOrWhiteSpace(state) ? "present" : state,
                Message = message,
                FailureReason = failureReason,
                RemediationHints = remediationHints
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return new RecoveryResultFile
            {
                Name = name,
                Path = fullPath,
                Exists = true,
                State = "unreadable",
                Message = ex.Message,
                FailureReason = ex.Message
            };
        }
    }

    private static string WriteReportRebuildDiagnostics(
        JobLocator locator,
        string commandName,
        string samplePath,
        EventInputResolution eventInput,
        string? runbookExecutionPath,
        bool success,
        string message,
        AnalysisJob? rebuiltJob = null)
    {
        Directory.CreateDirectory(locator.JobRoot);
        var diagnosticsPath = Path.Combine(locator.JobRoot, "report-rebuild-diagnostics.json");
        var remediationHints = new List<string>();
        foreach (var hint in eventInput.RemediationHints)
        {
            AddUniqueAction(remediationHints, hint);
        }

        if (!success)
        {
            AddUniqueAction(remediationHints, "确认 --sample 指向仍存在的样本文件，--events 指向有效 events.json/jsonl，--runtime-root 与 jobRoot 匹配。/ Confirm --sample exists, --events points to valid events.json/jsonl, and --runtime-root matches the job root.");
            AddUniqueAction(remediationHints, "若 events.json 缺失但 runbook-execution.json 存在，可重新运行 report/recover；工具会生成 failure skeleton。/ If events.json is missing but runbook-execution.json exists, rerun report/recover so the tool can generate a failure skeleton.");
        }

        var diagnostics = new
        {
            contractVersion = 1,
            kind = "KSwordSandbox.ReportRebuildDiagnostics",
            command = commandName.Equals("import-live", StringComparison.OrdinalIgnoreCase) ? "import" : "report",
            success,
            state = success ? "completed" : "failed",
            generatedAtUtc = DateTimeOffset.UtcNow,
            message,
            failureReason = success ? string.Empty : message,
            jobId = locator.JobId,
            jobRoot = locator.JobRoot,
            samplePath,
            eventInput,
            runbookExecutionPath,
            vmAction = "none",
            willMutateVm = false,
            reportPaths = new
            {
                jsonReportPath = rebuiltJob?.JsonReportPath,
                htmlReportPath = rebuiltJob?.HtmlReportPath,
                htmlReportZhPath = rebuiltJob?.HtmlReportZhPath,
                htmlReportEnPath = rebuiltJob?.HtmlReportEnPath,
                artifactIndexPath = Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName)
            },
            remediationHints,
            secretValuePrinted = false
        };

        File.WriteAllText(diagnosticsPath, JsonSerializer.Serialize(diagnostics, JsonOptions));
        return diagnosticsPath;
    }

    private static RecoveryAssessment BuildRecoveryAssessment(
        JobSummary summary,
        IReadOnlyList<RecoveryResultFile> resultFiles,
        bool rebuiltReport)
    {
        var failedFiles = resultFiles
            .Where(file => file.Exists &&
                (file.Success == false ||
                 file.State.Equals("failed", StringComparison.OrdinalIgnoreCase) ||
                 file.State.Equals("Failed", StringComparison.OrdinalIgnoreCase)))
            .ToList();
        var actions = new List<string>();
        foreach (var hint in failedFiles.SelectMany(file => file.RemediationHints))
        {
            AddUniqueAction(actions, hint);
        }

        if (summary.GuestEventsPath is null)
        {
            AddUniqueAction(actions, "请先收集来宾输出，或使用 --events <events.json|jsonl> 重新运行 import/report/recover。/ Collect guest outputs first, or rerun import/report/recover with --events <events.json|jsonl>.");
        }

        if (summary.JsonReportPath is null)
        {
            AddUniqueAction(actions, "events 可用后运行 report --job-id <id>，或 recover --job-id <id> --rebuild-report。/ Run report --job-id <id> or recover --job-id <id> --rebuild-report after events are available.");
        }

        if (summary.ArtifactCount is null)
        {
            AddUniqueAction(actions, "其他工具需要索引时，运行 artifacts --job-id <id> --write-index 写入 artifact-index.json。/ Run artifacts --job-id <id> --write-index to persist artifact-index.json when an index is needed by other tools.");
        }

        if (rebuiltReport)
        {
            AddUniqueAction(actions, "请检查重新生成的报告和产物索引；该操作未修改 VM。/ Review the regenerated report and artifact index; no VM mutation was performed.");
        }

        if (actions.Count == 0)
        {
            AddUniqueAction(actions, "未检测到阻塞性恢复动作。可使用 status/artifacts 检查，或使用 report --json 刷新报告。/ No blocking recovery action was detected. Use status/artifacts for inspection or report --json to refresh reports.");
        }

        var failureReason = failedFiles
            .Select(file => string.IsNullOrWhiteSpace(file.FailureReason) ? file.Message : file.FailureReason)
            .FirstOrDefault(reason => !string.IsNullOrWhiteSpace(reason)) ?? string.Empty;
        var state = rebuiltReport
            ? "report-rebuilt"
            : failedFiles.Count > 0
                ? "failed-action-required"
                : summary.JsonReportPath is null
                    ? "report-missing"
                    : "recoverable";

        return new RecoveryAssessment
        {
            State = state,
            HasBlockingFailure = failedFiles.Count > 0 || summary.JsonReportPath is null,
            FailureReason = failureReason,
            RecommendedActions = actions
        };
    }

    private static void AddUniqueAction(List<string> actions, string action)
    {
        if (!string.IsNullOrWhiteSpace(action) &&
            !actions.Contains(action, StringComparer.OrdinalIgnoreCase))
        {
            actions.Add(action);
        }
    }

    private static bool? TryReadJsonBool(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryGetPropertyIgnoreCase(root, name, out var element))
            {
                continue;
            }

            if (element.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                return element.GetBoolean();
            }

            if (element.ValueKind == JsonValueKind.String &&
                bool.TryParse(element.GetString(), out var parsed))
            {
                return parsed;
            }
        }

        return null;
    }

    private static string TryReadJsonString(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryGetPropertyIgnoreCase(root, name, out var element) ||
                element.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            {
                continue;
            }

            return element.ValueKind == JsonValueKind.String
                ? element.GetString() ?? string.Empty
                : element.ToString();
        }

        return string.Empty;
    }

    private static List<string> TryReadJsonStringArray(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryGetPropertyIgnoreCase(root, name, out var element))
            {
                continue;
            }

            if (element.ValueKind == JsonValueKind.Array)
            {
                return element.EnumerateArray()
                    .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString())
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Cast<string>()
                    .ToList();
            }

            if (element.ValueKind == JsonValueKind.String)
            {
                var value = element.GetString();
                return string.IsNullOrWhiteSpace(value) ? [] : [value];
            }
        }

        return [];
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true
        };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("任务工具 / KSword Sandbox JobTool");
        Console.WriteLine("用法 / Usage:");
        Console.WriteLine("  生成干跑计划 / Create dry-run plan:");
        Console.WriteLine("    KSword.Sandbox.JobTool plan --sample <exe> [--display-name <name>] [--config <sandbox.json>] [--repo-root <path>] [--runtime-root <path>] [--duration <seconds>] [--json]");
        Console.WriteLine("  列出任务 / List jobs:");
        Console.WriteLine("    KSword.Sandbox.JobTool list [--config <sandbox.json>] [--repo-root <path>] [--runtime-root <path>] [--limit <n>] [--json]");
        Console.WriteLine("  查看任务详情 / Show job details:");
        Console.WriteLine("    KSword.Sandbox.JobTool status --job-id <guid>|--job-root <path> [--config <sandbox.json>] [--repo-root <path>] [--runtime-root <path>] [--json]");
        Console.WriteLine("  重建报告 / Rebuild report:");
        Console.WriteLine("    KSword.Sandbox.JobTool report [rebuild] --job-id <guid>|--job-root <path> [--sample <exe>] [--events <events.json|jsonl>] [--runbook-execution <runbook-execution.json>] [--config <sandbox.json>] [--repo-root <path>] [--runtime-root <path>] [--duration <seconds>] [--json]");
        Console.WriteLine("  导入已有 Live 运行 / Import live run:");
        Console.WriteLine("    KSword.Sandbox.JobTool import [live] --job-id <guid> --sample <exe> [--events <events.json|jsonl>] [--runbook-execution <runbook-execution.json>] [--config <sandbox.json>] [--repo-root <path>] [--runtime-root <path>] [--duration <seconds>]");
        Console.WriteLine("  检查产物 / Inspect artifacts:");
        Console.WriteLine("    KSword.Sandbox.JobTool artifacts [inspect] --job-id <guid>|--job-root <path> [--config <sandbox.json>] [--repo-root <path>] [--runtime-root <path>] [--write-index] [--include-metadata] [--limit <n>] [--json]");
        Console.WriteLine("  恢复检查 / Recover:");
        Console.WriteLine("    KSword.Sandbox.JobTool recover --job-id <guid>|--job-root <path> [--write-state] [--write-index] [--rebuild-report] [--sample <exe>] [--events <events.json|jsonl>] [--json]");
        Console.WriteLine("  就绪检查 / Readiness:");
        Console.WriteLine("    KSword.Sandbox.JobTool readiness [--config <sandbox.json>] [--repo-root <path>] [--runtime-root <path>] [--job-id <guid>|--job-root <path>] [--sample <exe>] [--json]");
        Console.WriteLine();
        Console.WriteLine("别名 / Aliases: list-jobs=list, show-job=status, rebuild-report=report, import-live=import, inspect-artifacts=artifacts.");
        Console.WriteLine("说明 / Notes:");
        Console.WriteLine("  plan/report/import/artifacts/recover/readiness 只复用本地文件；不会启动、还原、停止或修改 VM。/ these commands reuse local files only and do not start, restore, stop, or mutate VMs.");
        Console.WriteLine("  report/import 会在任务运行目录下写入 report.json/report.html/report.zh.html/report.en.html 和 artifact-index.json。/ report/import write report and artifact-index files under the job runtime folder.");
        Console.WriteLine("  artifacts 仅在 --write-index 时写 artifact-index.json；recover 仅在 --write-state/--write-index/--rebuild-report 时写文件。/ artifacts/recover writes are explicit opt-in.");
        Console.WriteLine("  输出前会隐藏 password/API-key/token 等敏感字段。/ output redacts password/API-key/token-like fields before printing.");
    }

    [GeneratedRegex(@"(?i)\b(password|passwd|pwd|api[-_]?key|token|secret|credential|authorization)\b\s*[:=]\s*[^;\s,]+")]
    private static partial Regex SecretAssignmentRegex();

    [GeneratedRegex(@"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")]
    private static partial Regex BearerRegex();
}
