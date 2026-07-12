using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Abstractions.Artifacts;
using KSword.Sandbox.Core.Artifacts;
using System.Text.Json;

internal static partial class ProgramMain
{
    private static int AuditJob(JobToolOptions options)
    {
        var context = CreateContext(options);
        var locator = ResolveJobLocator(options, context.Config, requireExisting: true);
        var summary = BuildJobSummary(locator.JobRoot, buildArtifactIndex: true);
        var reportPath = Path.Combine(locator.JobRoot, "report.json");
        var report = TryLoadReport(reportPath);
        var artifactIndexPath = Path.Combine(locator.JobRoot, HostArtifactIndexBuilder.IndexFileName);
        var artifactIndex = TryBuildAuditArtifactIndex(locator.JobId, locator.JobRoot);
        var reportAudit = BuildAuditReportSummary(report);
        var artifactAudit = BuildAuditArtifactSummary(artifactIndex, artifactIndexPath);
        var progressAudit = BuildAuditRunbookProgressSummary(summary.RunbookProgressPath ?? Path.Combine(locator.JobRoot, "runbook-progress.json"));
        var warnings = new List<string>();

        if (report is null)
        {
            warnings.Add("未找到 report.json；只能审计任务/产物目录，无法统计报告事件。/ report.json was not found; only job/artifact files can be audited.");
        }

        if (!progressAudit.Exists)
        {
            warnings.Add("未找到 runbook-progress.json；live progress 持久化证据缺失。/ runbook-progress.json was not found, so durable live-progress evidence is missing.");
        }

        if (artifactIndex is null)
        {
            warnings.Add("产物索引无法构建；请检查任务目录权限和 artifact-index.json。/ Artifact index could not be built; check job permissions and artifact-index.json.");
        }

        var output = new
        {
            contractVersion = 1,
            kind = "KSwordSandbox.JobSelfNoiseAudit",
            command = "self-noise-audit",
            generatedAtUtc = DateTimeOffset.UtcNow,
            jobId = locator.JobId,
            jobRoot = locator.JobRoot,
            summary,
            reportPath,
            reportExists = report is not null,
            artifactIndexPath,
            artifactIndexBuilt = artifactIndex is not null,
            reportAudit,
            artifactAudit,
            runbookProgressAudit = progressAudit,
            warnings,
            releaseReviewHints = new[]
            {
                "该命令仅读取现有 report.json、artifact-index/目录和 runbook-progress.json；不会启动、还原、停止或修改 VM。/ This command only reads existing report, artifact, and progress files; it does not start, restore, stop, or mutate a VM.",
                "该命令不运行 smoke 测试，不代表 fresh Hyper-V/live evidence。/ This command does not run smoke tests and is not fresh Hyper-V/live evidence.",
                "审阅重点：sampleBehaviorCandidateCount 应只包含样本/系统候选行为；nonbehavior/self-noise/VT/R0 健康行应进入排除统计。/ Review focus: sampleBehaviorCandidateCount should only contain sample/system behavior candidates; nonbehavior/self-noise/VT/R0 health rows should appear in excluded counts."
            },
            vmAction = "none",
            hyperVAction = "none",
            smokeTestsRun = false,
            liveVmMutatingChecksRun = false,
            willMutateVm = false,
            secretValuePrinted = false
        };

        if (GetBool(options, "json"))
        {
            WriteJson(output);
            return 0;
        }

        Console.WriteLine("离线审计 / KSword Sandbox self-noise audit");
        Console.WriteLine($"任务 ID / Job ID: {locator.JobId:D}");
        Console.WriteLine($"任务目录 / Job root: {Safe(locator.JobRoot)}");
        Console.WriteLine("VM 操作 / VM action: 无 / none");
        Console.WriteLine("Smoke/Hyper-V: 未运行 / not run");
        Console.WriteLine($"报告 / Report: {(report is null ? "缺失 / missing" : Safe(reportPath))}");
        Console.WriteLine($"事件总数 / Total events: {reportAudit.TotalEvents}");
        Console.WriteLine($"样本行为候选 / Sample behavior candidates: {reportAudit.SampleBehaviorCandidateCount}");
        Console.WriteLine($"排除的 metadata/self-noise / Excluded metadata/self-noise: {reportAudit.ExcludedNonBehaviorCandidateCount}");
        Console.WriteLine($"behaviorCounted=false: {reportAudit.BehaviorCountedFalseCount} | nonbehavior=true: {reportAudit.NonBehaviorTrueCount} | sampleBehaviorCandidate=false: {reportAudit.SampleBehaviorCandidateFalseCount}");
        Console.WriteLine($"Collector self-noise/noise: {reportAudit.CollectorSelfNoiseCount}/{reportAudit.CollectorNoiseCount} | VT quiet: {reportAudit.VirusTotalQuietStateCount} | R0 health/readiness: {reportAudit.R0HealthOrReadinessCount}");
        Console.WriteLine($"产物 / Artifacts: total={artifactAudit.TotalArtifacts}, downloadable={artifactAudit.DownloadableArtifacts}, rejected={artifactAudit.RejectedArtifacts}, dropped={artifactAudit.DroppedFiles}, screenshots={artifactAudit.Screenshots}, memory={artifactAudit.MemoryDumps}, pcap={artifactAudit.PacketCaptures}");
        Console.WriteLine($"Runbook progress: {(progressAudit.Exists ? "存在 / exists" : "缺失 / missing")} | state={FormatValueOrUnavailable(progressAudit.State)} | ageSeconds={FormatNullable(progressAudit.AgeSeconds)} | completed/failed/running={FormatNullable(progressAudit.CompletedSteps)}/{FormatNullable(progressAudit.FailedSteps)}/{FormatNullable(progressAudit.RunningSteps)}");

        if (reportAudit.TopEventTypes.Count > 0)
        {
            Console.WriteLine("Top event types:");
            foreach (var item in reportAudit.TopEventTypes.Take(8))
            {
                Console.WriteLine($"- {Safe(item.Name)}: {item.Count}");
            }
        }

        if (warnings.Count > 0)
        {
            Console.WriteLine("警告 / Warnings:");
            foreach (var warning in warnings)
            {
                Console.WriteLine($"- {Safe(warning)}");
            }
        }

        Console.WriteLine("提示 / Tip: 添加 --json 输出机器可读审计结果，便于审阅者对比 self-noise 边界。/ Add --json for a machine-readable self-noise audit.");
        return 0;
    }

    private static HostArtifactIndex? TryBuildAuditArtifactIndex(Guid jobId, string jobRoot)
    {
        try
        {
            return new HostArtifactIndexBuilder().Build(jobId, jobRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return TryReadArtifactIndex(jobRoot);
        }
    }

    private static AuditReportSummary BuildAuditReportSummary(AnalysisReport? report)
    {
        if (report is null)
        {
            return new AuditReportSummary();
        }

        var events = report.Events;
        var excluded = events.Where(IsAuditNonBehaviorOrSelfNoiseEvent).ToList();
        var topEventTypes = events
            .GroupBy(evt => string.IsNullOrWhiteSpace(evt.EventType) ? "unknown" : evt.EventType, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .Select(group => new AuditNameCount(group.Key, group.Count()))
            .ToList();
        var sourceCounts = events
            .GroupBy(evt => string.IsNullOrWhiteSpace(evt.Source) ? "unknown" : evt.Source, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group => new AuditNameCount(group.Key, group.Count()))
            .ToList();

        return new AuditReportSummary
        {
            TotalEvents = events.Count,
            SampleBehaviorCandidateCount = events.Count - excluded.Count,
            ExcludedNonBehaviorCandidateCount = excluded.Count,
            BehaviorCountedFalseCount = events.Count(evt => AuditDataBoolFalse(evt, "behaviorCounted", "behavior_counted", "countsAsBehavior", "countedAsBehavior")),
            NonBehaviorTrueCount = events.Count(evt => AuditDataBoolTrue(evt, "nonbehavior", "nonBehavior", "non_behavior", "notBehavior", "not_behavior")),
            NotSampleBehaviorTrueCount = events.Count(evt => AuditDataBoolTrue(evt, "notSampleBehavior", "not_sample_behavior")),
            SampleBehaviorCandidateFalseCount = events.Count(evt => AuditDataBoolFalse(evt, "sampleBehaviorCandidate", "sample_behavior_candidate")),
            CollectorSelfNoiseCount = events.Count(evt => AuditDataBoolTrue(evt, "collectorSelfNoise", "collector_self_noise", "selfNoise", "self_noise")),
            CollectorNoiseCount = events.Count(evt => AuditDataBoolTrue(evt, "collectorNoise", "collectionNoise", "noise")),
            HostImportSelfNoiseCount = events.Count(evt => AuditDataBoolTrue(evt, "hostImportSelfNoise")),
            CollectionHealthSourceCount = events.Count(evt => AuditTextEqualsAny(evt.Source, "collection-health")),
            VirusTotalSourceCount = events.Count(evt => AuditTextEqualsAny(evt.Source, "virustotal") || evt.EventType.Contains("virustotal", StringComparison.OrdinalIgnoreCase)),
            R0CollectorSourceCount = events.Count(evt => AuditTextEqualsAny(evt.Source, "r0collector") || evt.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase)),
            VirusTotalQuietStateCount = events.Count(IsAuditVirusTotalQuietState),
            R0HealthOrReadinessCount = events.Count(IsAuditR0HealthOrReadinessRow),
            TopEventTypes = topEventTypes,
            SourceCounts = sourceCounts
        };
    }

    private static AuditArtifactSummary BuildAuditArtifactSummary(HostArtifactIndex? index, string artifactIndexPath)
    {
        if (index is null)
        {
            return new AuditArtifactSummary
            {
                ArtifactIndexPath = artifactIndexPath
            };
        }

        return new AuditArtifactSummary
        {
            ArtifactIndexPath = artifactIndexPath,
            TotalArtifacts = index.Artifacts.Count,
            TotalCollections = index.Collections.Count,
            DownloadableArtifacts = index.DownloadableArtifactCount > 0
                ? index.DownloadableArtifactCount
                : index.Artifacts.Count(artifact => !string.IsNullOrWhiteSpace(artifact.SafeLink)),
            SensitiveArtifacts = index.SensitiveArtifactCount,
            DuplicateArtifacts = index.DuplicateArtifactCount,
            RejectedArtifacts = index.RejectedArtifactCount,
            DroppedFiles = index.Artifacts.Count(artifact => artifact.Kind == ArtifactKind.DroppedFile),
            Screenshots = index.Artifacts.Count(artifact => artifact.Kind == ArtifactKind.Screenshot),
            MemoryDumps = index.Artifacts.Count(artifact => artifact.Kind == ArtifactKind.MemoryDump),
            PacketCaptures = index.Artifacts.Count(artifact => artifact.Kind == ArtifactKind.PacketCapture)
        };
    }

    private static AuditRunbookProgressSummary BuildAuditRunbookProgressSummary(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return new AuditRunbookProgressSummary
            {
                Path = fullPath,
                Exists = false
            };
        }

        var lastWriteUtc = new DateTimeOffset(File.GetLastWriteTimeUtc(fullPath), TimeSpan.Zero);
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(fullPath));
            var root = document.RootElement;
            var steps = ReadAuditRunbookSteps(root);
            var state = TryReadJsonString(root, "state", "State", "status", "Status");
            var totalSteps = TryReadAuditInt(root, "totalSteps", "TotalSteps") ?? (steps.Count > 0 ? steps.Count : null);
            return new AuditRunbookProgressSummary
            {
                Path = fullPath,
                Exists = true,
                Readable = true,
                LastWriteUtc = lastWriteUtc,
                AgeSeconds = Math.Max(0, (int)Math.Round((DateTimeOffset.UtcNow - lastWriteUtc).TotalSeconds)),
                State = string.IsNullOrWhiteSpace(state) ? "unknown" : state,
                TotalSteps = totalSteps,
                CompletedSteps = steps.Count(step => AuditTextEqualsAny(step.State, "completed", "skipped")),
                FailedSteps = steps.Count(step => AuditTextEqualsAny(step.State, "failed", "canceled", "cancelled")),
                RunningSteps = steps.Count(step => AuditTextEqualsAny(step.State, "running")),
                PendingSteps = steps.Count(step => AuditTextEqualsAny(step.State, "pending")),
                LatestStep = steps.LastOrDefault(step => !AuditTextEqualsAny(step.State, "pending"))?.Label ?? string.Empty
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return new AuditRunbookProgressSummary
            {
                Path = fullPath,
                Exists = true,
                Readable = false,
                LastWriteUtc = lastWriteUtc,
                AgeSeconds = Math.Max(0, (int)Math.Round((DateTimeOffset.UtcNow - lastWriteUtc).TotalSeconds)),
                State = "unreadable",
                Message = ex.Message
            };
        }
    }

    private static List<AuditRunbookStep> ReadAuditRunbookSteps(JsonElement root)
    {
        if (!TryGetPropertyIgnoreCase(root, "steps", out var stepsElement) ||
            stepsElement.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var steps = new List<AuditRunbookStep>();
        foreach (var step in stepsElement.EnumerateArray())
        {
            var id = TryReadJsonString(step, "id", "Id", "stepId", "StepId");
            var title = TryReadJsonString(step, "title", "Title", "name", "Name", "label", "Label");
            var state = TryReadJsonString(step, "state", "State", "status", "Status");
            steps.Add(new AuditRunbookStep(
                FirstNonEmpty(id, title, $"step-{steps.Count + 1}"),
                string.IsNullOrWhiteSpace(state) ? "unknown" : state));
        }

        return steps;
    }

    private static int? TryReadAuditInt(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryGetPropertyIgnoreCase(root, name, out var element))
            {
                continue;
            }

            if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var number))
            {
                return number;
            }

            if (element.ValueKind == JsonValueKind.String && int.TryParse(element.GetString(), out number))
            {
                return number;
            }
        }

        return null;
    }

    private static bool IsAuditNonBehaviorOrSelfNoiseEvent(SandboxEvent evt)
    {
        if (AuditDataBoolFalse(evt, "behaviorCounted", "behavior_counted", "countsAsBehavior", "countedAsBehavior") ||
            AuditDataBoolFalse(evt, "sampleBehaviorCandidate", "sample_behavior_candidate") ||
            AuditDataBoolTrue(
                evt,
                "nonbehavior",
                "nonBehavior",
                "non_behavior",
                "notBehavior",
                "not_behavior",
                "notSampleBehavior",
                "collectionHealth",
                "collectorSelfNoise",
                "collector_self_noise",
                "collectorNoise",
                "collectionNoise",
                "selfNoise",
                "self_noise",
                "hostImportSelfNoise"))
        {
            return true;
        }

        if (AuditTextEqualsAny(evt.Source, "collection-health", "virustotal", "r0collector"))
        {
            return true;
        }

        if (evt.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("enrichment.virustotal.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("reputation.virustotal.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("collection-health.", StringComparison.OrdinalIgnoreCase) ||
            evt.EventType.StartsWith("artifact.import.", StringComparison.OrdinalIgnoreCase) ||
            AuditTextEqualsAny(evt.EventType, "guest.events.imported", "report.generated", "driver.parse_error"))
        {
            return true;
        }

        if (AuditTextContainsAny(evt.ProcessName ?? string.Empty, "KSword.Sandbox.Agent", "KSword.Sandbox.R0Collector"))
        {
            return true;
        }

        var eventKind = AuditFirstDataValue(evt, "eventKind", "eventRole", "evidenceRole", "classification");
        return AuditTextEqualsAny(eventKind, "nonbehavior", "non-behavior", "metadata", "diagnostic", "health", "status", "summary");
    }

    private static bool IsAuditVirusTotalQuietState(SandboxEvent evt)
    {
        if (!evt.EventType.Contains("virustotal", StringComparison.OrdinalIgnoreCase) &&
            !AuditTextEqualsAny(evt.Source, "virustotal"))
        {
            return false;
        }

        var state = AuditFirstDataValue(evt, "quietState", "quietErrorKind", "quietErrorCategory", "status", "verdict", "result");
        return AuditTextEqualsAny(
            state,
            "not-configured",
            "not_configured",
            "rate-limited",
            "rate_limited",
            "not-found",
            "not_found",
            "disabled",
            "skipped",
            "lookup-skipped",
            "error",
            "unavailable");
    }

    private static bool IsAuditR0HealthOrReadinessRow(SandboxEvent evt)
    {
        if (!evt.EventType.StartsWith("r0collector.", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return AuditTextContainsAny(
            evt.EventType,
            "health",
            "readiness",
            "driver",
            "heartbeat",
            "started",
            "stopped",
            "device",
            "abi",
            "capabilities",
            "status",
            "poll",
            "batch");
    }

    private static bool AuditDataBoolTrue(SandboxEvent evt, params string[] names)
    {
        return names.Any(name => AuditTryGetDataValue(evt, name, out var value) && AuditIsTruthy(value));
    }

    private static bool AuditDataBoolFalse(SandboxEvent evt, params string[] names)
    {
        return names.Any(name => AuditTryGetDataValue(evt, name, out var value) && AuditIsFalsy(value));
    }

    private static string AuditFirstDataValue(SandboxEvent evt, params string[] names)
    {
        foreach (var name in names)
        {
            if (AuditTryGetDataValue(evt, name, out var value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static bool AuditTryGetDataValue(SandboxEvent evt, string name, out string value)
    {
        if (evt.Data.TryGetValue(name, out value!))
        {
            return true;
        }

        var normalized = name.StartsWith("data.", StringComparison.OrdinalIgnoreCase) ? name[5..] : name;
        if (!string.Equals(normalized, name, StringComparison.OrdinalIgnoreCase) &&
            evt.Data.TryGetValue(normalized, out value!))
        {
            return true;
        }

        value = string.Empty;
        return false;
    }

    private static bool AuditIsTruthy(string value)
    {
        return AuditTextEqualsAny(value, "true", "1", "yes", "y");
    }

    private static bool AuditIsFalsy(string value)
    {
        return AuditTextEqualsAny(value, "false", "0", "no", "n");
    }

    private static bool AuditTextEqualsAny(string? text, params string[] candidates)
    {
        return !string.IsNullOrWhiteSpace(text) &&
            candidates.Any(candidate => string.Equals(text, candidate, StringComparison.OrdinalIgnoreCase));
    }

    private static bool AuditTextContainsAny(string? text, params string[] fragments)
    {
        return !string.IsNullOrWhiteSpace(text) &&
            fragments.Any(fragment => text.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private sealed record AuditNameCount(string Name, int Count);

    private sealed record AuditRunbookStep(string Label, string State);

    private sealed class AuditReportSummary
    {
        public int TotalEvents { get; init; }

        public int SampleBehaviorCandidateCount { get; init; }

        public int ExcludedNonBehaviorCandidateCount { get; init; }

        public int BehaviorCountedFalseCount { get; init; }

        public int NonBehaviorTrueCount { get; init; }

        public int NotSampleBehaviorTrueCount { get; init; }

        public int SampleBehaviorCandidateFalseCount { get; init; }

        public int CollectorSelfNoiseCount { get; init; }

        public int CollectorNoiseCount { get; init; }

        public int HostImportSelfNoiseCount { get; init; }

        public int CollectionHealthSourceCount { get; init; }

        public int VirusTotalSourceCount { get; init; }

        public int R0CollectorSourceCount { get; init; }

        public int VirusTotalQuietStateCount { get; init; }

        public int R0HealthOrReadinessCount { get; init; }

        public List<AuditNameCount> TopEventTypes { get; init; } = [];

        public List<AuditNameCount> SourceCounts { get; init; } = [];
    }

    private sealed class AuditArtifactSummary
    {
        public string ArtifactIndexPath { get; init; } = string.Empty;

        public int TotalArtifacts { get; init; }

        public int TotalCollections { get; init; }

        public int DownloadableArtifacts { get; init; }

        public int SensitiveArtifacts { get; init; }

        public int DuplicateArtifacts { get; init; }

        public int RejectedArtifacts { get; init; }

        public int DroppedFiles { get; init; }

        public int Screenshots { get; init; }

        public int MemoryDumps { get; init; }

        public int PacketCaptures { get; init; }
    }

    private sealed class AuditRunbookProgressSummary
    {
        public string Path { get; init; } = string.Empty;

        public bool Exists { get; init; }

        public bool Readable { get; init; }

        public DateTimeOffset? LastWriteUtc { get; init; }

        public int? AgeSeconds { get; init; }

        public string State { get; init; } = string.Empty;

        public int? TotalSteps { get; init; }

        public int? CompletedSteps { get; init; }

        public int? FailedSteps { get; init; }

        public int? RunningSteps { get; init; }

        public int? PendingSteps { get; init; }

        public string LatestStep { get; init; } = string.Empty;

        public string Message { get; init; } = string.Empty;
    }
}
