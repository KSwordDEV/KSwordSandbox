using System.Globalization;
using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Converts the durable Guest Agent exit/status artifacts into explicit
/// collection-health rows.  The importer is intentionally independent of the
/// report renderer so a missing events.json can never be mistaken for a clean
/// run during offline or live host import.
/// </summary>
public static class GuestFailureArtifactImporter
{
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip
    };

    public static IReadOnlyList<SandboxEvent> Import(string? guestOutputRoot)
    {
        if (string.IsNullOrWhiteSpace(guestOutputRoot) || !Directory.Exists(guestOutputRoot))
        {
            return [];
        }

        var root = Path.GetFullPath(guestOutputRoot);
        var statusPath = FindNewest(root, "guest-agent-run-status.json");
        var stderrPath = FindNewest(root, "agent.stderr.log");
        var sampleStderrPath = FindNewest(root, "sample-stderr.log");
        var exitPath = FindNewest(root, "agent.exit");
        var pidPath = FindNewest(root, "agent.pid");
        var eventsPath = FindNewest(root, "events.json");
        var liveJournalPath = FindNewest(root, GuestLiveEventJournalReader.JournalFileName);
        var launchProofPath = FindNewest(root, "sample-launch-proof.json");
        var summaryPath = FindNewest(root, "agent-summary.json");
        var preflightPath = FindNewest(root, "guest-output-preflight.json");
        // The CLR preflight is written to the host job root and copied into
        // guest output when the remoting session is available.  Check the
        // guest root first and its job-root parent as a fallback so a failed
        // session still leaves a reportable host-side diagnostic.
        var sampleRuntimePreflightPath = FindNewest(root, "sample-runtime-preflight.json") ??
            FindNewestParent(root, "sample-runtime-preflight.json");
        var r0FailurePath = FindNewest(root, "driver-events.jsonl.failure.json");
        var r0StatusPath = FindNewest(root, "driver-events.jsonl.r0-status.json");
        var rows = new List<SandboxEvent>();

        var status = statusPath is null ? null : ReadStatus(statusPath);
        var exitText = ReadText(exitPath);
        var parsedExit = TryParseExit(exitText, out var exitCode);
        var stderr = ReadText(stderrPath);
        // Newer guest agents redirect the sample tree's stderr into
        // sample-stderr.log. Any agent.stderr.log line that also appears in
        // the sample lane is sample-attributable noise (inherited-handle
        // leaks), not an agent diagnostic; only the remainder may fail the
        // run. Payloads without sample-stderr.log keep the legacy rule where
        // every agent.stderr.log line counts.
        var sampleStderr = sampleStderrPath is null ? null : ReadText(sampleStderrPath);
        var agentDiagnosticStderr = sampleStderrPath is null
            ? stderr
            : RemoveLinesPresentIn(stderr, sampleStderr);
        var missing = status?.MissingArtifacts ?? [];
        var hasAgentMarker = statusPath is not null || stderrPath is not null || exitPath is not null || pidPath is not null || summaryPath is not null || launchProofPath is not null || liveJournalPath is not null;
        var hasR0Failure = r0FailurePath is not null;
        var hasR0Status = r0StatusPath is not null;
        var preflight = preflightPath is null ? null : ReadOutputPreflight(preflightPath);
        var preflightFailed = preflight is not null &&
            !string.Equals(preflight.State, "ready", StringComparison.OrdinalIgnoreCase);
        var sampleRuntime = sampleRuntimePreflightPath is null ? null : ReadSampleRuntimePreflight(sampleRuntimePreflightPath);
        var sampleRuntimeFailed = sampleRuntime is not null &&
            (string.Equals(sampleRuntime.State, "sample-runtime-blocked", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(sampleRuntime.State, "preflight-error", StringComparison.OrdinalIgnoreCase) ||
             !string.IsNullOrWhiteSpace(sampleRuntime.FailureCode));
        // Offline fixtures and older externally-produced events.json files do
        // not necessarily carry the Agent marker set. Do not invent a missing
        // summary failure for those already-complete event streams.
        if (!hasAgentMarker && !hasR0Failure && !hasR0Status && !preflightFailed && !sampleRuntimeFailed)
        {
            return rows;
        }

        // A truncated but valid events.json may omit process.start. Recover
        // the durable proof unless that exact sample process is already in
        // the event stream. The proof establishes launch only, never behavior.
        if (launchProofPath is not null)
        {
            var launchProof = ImportSampleLaunchProof(launchProofPath, statusPath);
            if (launchProof is not null &&
                (eventsPath is null || !ContainsMatchingSampleStart(eventsPath, launchProof)) &&
                (liveJournalPath is null || !ContainsMatchingLiveJournalStart(liveJournalPath, launchProof)))
            {
                rows.Add(launchProof);
            }
        }

        if (sampleRuntimeFailed && sampleRuntime is not null && sampleRuntimePreflightPath is not null)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["failureType"] = "sampleRuntimePreflight",
                ["sampleRuntimePreflight"] = "true",
                ["sampleRuntimeState"] = sampleRuntime.State ?? "preflight-error",
                ["sampleRuntimeFailureCode"] = sampleRuntime.FailureCode ?? string.Empty,
                ["preflightPath"] = sampleRuntimePreflightPath,
                ["sampleExecuted"] = "false",
                ["sampleFileName"] = sampleRuntime.SampleFileName ?? string.Empty,
                ["managedClrDetected"] = sampleRuntime.ManagedClrDetected.ToString().ToLowerInvariant(),
                ["legacyClrDetected"] = sampleRuntime.LegacyClrDetected.ToString().ToLowerInvariant(),
                ["guestNetFx3State"] = sampleRuntime.GuestNetFx3State ?? "query-failed",
                ["guestSamplePresent"] = sampleRuntime.GuestSamplePresent.ToString().ToLowerInvariant(),
                ["stderrPreview"] = sampleRuntime.Error ?? string.Empty
            };
            rows.Add(CreateSampleRuntimeFailureRow(
                sampleRuntimePreflightPath,
                values,
                "样本运行环境预检失败，样本未执行；动态结果只能按失败/部分处理，不能判定为未检出。"));
        }

        if (preflightFailed && preflight is not null && preflightPath is not null)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["failureType"] = "guestOutputInsufficientSpace",
                ["agentFailure"] = "true",
                ["outputSpacePreflightFailure"] = "true",
                ["preflightState"] = preflight.State ?? string.Empty,
                ["availableFreeBytes"] = preflight.AvailableFreeBytes.ToString(CultureInfo.InvariantCulture),
                ["requiredFreeBytes"] = preflight.RequiredFreeBytes.ToString(CultureInfo.InvariantCulture),
                ["volumeRoot"] = preflight.VolumeRoot ?? string.Empty,
                ["agentOutputRoot"] = preflight.OutputRoot ?? root,
                ["preflightPath"] = preflightPath
            };
            if (!string.IsNullOrWhiteSpace(preflight.CheckedAtUtc))
            {
                values["checkedAtUtc"] = preflight.CheckedAtUtc!;
            }

            rows.Add(CreateFailureRow(
                "guest.output.preflight.failed",
                preflightPath,
                values,
                "来宾输出卷可用空间低于 Agent/R0 共享保留阈值；样本未启动，动态结果不可判定。"));
        }

        if (hasAgentMarker && missing.Count == 0)
        {
            if (eventsPath is null) missing.Add("events.json");
            if (summaryPath is null) missing.Add("agent-summary.json");
        }

        var state = status?.State;
        var failed = hasAgentMarker && (!string.Equals(state, "completed", StringComparison.OrdinalIgnoreCase) ||
            (parsedExit && exitCode != 0) ||
            (!string.IsNullOrWhiteSpace(exitText) && !parsedExit) ||
            missing.Count > 0 ||
            // Preserve any Agent stderr as a structured runtime diagnostic,
            // but only content attributable to the agent itself: sample-tree
            // noise captured in sample-stderr.log must not fail an otherwise
            // healthy run (agent state=completed, exit 0, complete events).
            !string.IsNullOrWhiteSpace(agentDiagnosticStderr));

        if (failed)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["failureType"] = "agentFailure",
                ["agentFailure"] = "true",
                ["agentOutputRoot"] = root,
                ["eventsJsonPresent"] = (eventsPath is not null).ToString().ToLowerInvariant(),
                ["agentSummaryPresent"] = (summaryPath is not null).ToString().ToLowerInvariant(),
                ["stderrPresent"] = (!string.IsNullOrWhiteSpace(stderr)).ToString().ToLowerInvariant(),
                ["missingArtifacts"] = string.Join(",", missing),
                ["exitText"] = exitText ?? string.Empty,
                ["exitCodeStatus"] = parsedExit ? "parsed" : string.IsNullOrWhiteSpace(exitText) ? "missing" : "invalid"
            };
            if (statusPath is not null) values["statusPath"] = statusPath;
            if (stderrPath is not null) values["stderrPath"] = stderrPath;
            if (sampleStderrPath is not null)
            {
                values["sampleStderrPath"] = sampleStderrPath;
                values["sampleStderrBytes"] = FileLength(sampleStderrPath).ToString(CultureInfo.InvariantCulture);
                values["stderrSampleAttributed"] = (!string.IsNullOrWhiteSpace(stderr) &&
                    string.IsNullOrWhiteSpace(agentDiagnosticStderr)).ToString().ToLowerInvariant();
            }
            if (exitPath is not null) values["exitPath"] = exitPath;
            if (pidPath is not null) values["pidPath"] = pidPath;
            if (parsedExit) values["exitCode"] = exitCode.ToString(CultureInfo.InvariantCulture);
            if (status is not null)
            {
                values["statusState"] = status.State ?? string.Empty;
                values["statusCapturedAtUtc"] = status.CapturedAtUtc ?? string.Empty;
                values["stdoutBytes"] = status.StdoutBytes.ToString(CultureInfo.InvariantCulture);
                values["stderrBytes"] = Math.Max(status.StderrBytes, FileLength(stderrPath)).ToString(CultureInfo.InvariantCulture);
            }
            else if (stderrPath is not null)
            {
                values["stderrBytes"] = FileLength(stderrPath).ToString(CultureInfo.InvariantCulture);
            }
            var agentDiagnosticPreview = string.IsNullOrWhiteSpace(agentDiagnosticStderr) ? stderr : agentDiagnosticStderr;
            if (!string.IsNullOrWhiteSpace(agentDiagnosticPreview))
            {
                values["stderrPreview"] = agentDiagnosticPreview.Length > 4096 ? agentDiagnosticPreview[..4096] : agentDiagnosticPreview;
            }
            rows.Add(CreateFailureRow(
                "agent.run.failed",
                statusPath ?? stderrPath ?? exitPath ?? root,
                values,
                "Guest Agent failed or produced incomplete output; dynamic evidence is partial and must not be reported as clean."));
        }

        if (r0FailurePath is not null)
        {
            var r0Failure = ImportR0OutputFailure(r0FailurePath);
            if (r0Failure is not null)
            {
                rows.Add(r0Failure);
            }
        }

        if (r0StatusPath is not null)
        {
            var r0BudgetStop = ImportR0OutputBudgetStop(r0StatusPath);
            if (r0BudgetStop is not null)
            {
                rows.Add(r0BudgetStop);
            }
        }

        return rows;
    }

    public static SandboxEvent? ImportSampleLaunchProof(string? proofPath, string? statusPath = null)
    {
        if (string.IsNullOrWhiteSpace(proofPath) || !File.Exists(proofPath)) return null;
        try
        {
            if (new FileInfo(proofPath).Length is <= 0 or > 4096) return null;
            using var document = JsonDocument.Parse(File.ReadAllText(proofPath), JsonOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                ReadString(root, "schema") != "ksword-sample-launch-proof-v1" ||
                ReadString(root, "state") != "started") return null;

            var samplePath = ReadString(root, "samplePath");
            var sampleSha256 = ReadString(root, "sampleSha256");
            var jobIdText = ReadString(root, "jobId");
            var startedText = ReadString(root, "startedAtUtc");
            if (string.IsNullOrWhiteSpace(samplePath) || !Path.IsPathFullyQualified(samplePath) ||
                sampleSha256 is not { Length: 64 } || !sampleSha256.All(Uri.IsHexDigit) ||
                !Guid.TryParse(jobIdText, out var jobId) ||
                !DateTimeOffset.TryParse(startedText, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out var startedAt) ||
                !root.TryGetProperty("processId", out var pidValue) || pidValue.ValueKind != JsonValueKind.Number || !pidValue.TryGetInt32(out var pid) || pid <= 0 ||
                !root.TryGetProperty("parentProcessId", out var parentValue) ||
                parentValue.ValueKind != JsonValueKind.Number || !parentValue.TryGetInt32(out var parentPid) || parentPid <= 0) return null;

            var expectedSha256 = ReadExpectedSampleSha256(statusPath);
            if (expectedSha256 is not null &&
                !string.Equals(expectedSha256, sampleSha256, StringComparison.OrdinalIgnoreCase)) return null;
            var sampleSizeBytes = root.TryGetProperty("sampleSizeBytes", out var sizeValue) &&
                sizeValue.ValueKind == JsonValueKind.Number && sizeValue.TryGetInt64(out var parsedSize) && parsedSize >= 0
                    ? parsedSize.ToString(CultureInfo.InvariantCulture)
                    : string.Empty;

            return new SandboxEvent
            {
                EventType = "sample.launch.confirmed",
                Timestamp = startedAt,
                Source = "guest-agent",
                ProcessId = pid,
                ParentProcessId = parentPid,
                Path = samplePath,
                Data =
                {
                    ["sampleSha256"] = sampleSha256.ToUpperInvariant(),
                    ["sampleSizeBytes"] = sampleSizeBytes,
                    ["hostExpectedHashMatched"] = (expectedSha256 is not null).ToString().ToLowerInvariant(),
                    ["jobId"] = jobId.ToString("D"),
                    ["processId"] = pid.ToString(CultureInfo.InvariantCulture),
                    ["parentProcessId"] = parentPid.ToString(CultureInfo.InvariantCulture),
                    ["launchProofPath"] = proofPath,
                    ["sampleExecuted"] = "true",
                    ["launchProofRecovered"] = "true",
                    ["captureState"] = "partial",
                    ["collectionHealth"] = "true",
                    ["behaviorCounted"] = "false",
                    ["nonbehavior"] = "true",
                    ["notSampleBehavior"] = "true",
                    ["sampleBehaviorCandidate"] = "false",
                    ["zhMessage"] = "来宾 Agent 的持久化启动记录确认样本进程已启动；完整行为事件尚未回收。",
                    ["zhHint"] = "此记录只证明进程启动，不证明文件、磁盘或网络行为，也不代表采集已完成。"
                }
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return null;
        }
    }

    private static bool ContainsMatchingSampleStart(string eventsPath, SandboxEvent proof)
    {
        try
        {
            using var stream = File.OpenRead(eventsPath);
            using var document = JsonDocument.Parse(stream, JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Array) return false;
            foreach (var row in document.RootElement.EnumerateArray())
            {
                if (row.ValueKind != JsonValueKind.Object) continue;
                var eventType = ReadString(row, "EventType") ?? ReadString(row, "eventType");
                var path = ReadString(row, "Path") ?? ReadString(row, "path");
                if (!string.Equals(eventType, "process.start", StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(path, proof.Path, StringComparison.OrdinalIgnoreCase)) continue;
                if (!row.TryGetProperty("ProcessId", out var pid) && !row.TryGetProperty("processId", out pid)) return true;
                if (pid.ValueKind == JsonValueKind.Number && pid.TryGetInt32(out var value) && value == proof.ProcessId) return true;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
        return false;
    }

    private static bool ContainsMatchingLiveJournalStart(string journalPath, SandboxEvent proof)
    {
        if (!proof.Data.TryGetValue("jobId", out var jobText) ||
            !Guid.TryParse(jobText, out var jobId) ||
            !proof.Data.TryGetValue("sampleSha256", out var sha256) ||
            !proof.Data.TryGetValue("sampleSizeBytes", out var sizeText) ||
            !long.TryParse(sizeText, CultureInfo.InvariantCulture, out var sizeBytes) ||
            proof.Path is null)
        {
            return false;
        }

        try
        {
            return GuestLiveEventJournalReader.ReadValidated(
                    journalPath, jobId, sha256, sizeBytes, proof.Path)
                .Any(evt => string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(evt.Path, proof.Path, StringComparison.OrdinalIgnoreCase) &&
                            evt.ProcessId == proof.ProcessId);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return false;
        }
    }

    private static string? ReadExpectedSampleSha256(string? statusPath)
    {
        if (string.IsNullOrWhiteSpace(statusPath) || !File.Exists(statusPath)) return null;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(statusPath), JsonOptions);
            var value = ReadString(document.RootElement, "sampleSha256");
            return value is { Length: 64 } && value.All(Uri.IsHexDigit) ? value : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Imports the collector's r0-status sidecar written by an intentional
    /// cumulative-output-budget stop. Unlike the failure sidecar this row is
    /// evidence of a clean stop: the collector finalized its segment, exited
    /// with code 0, and deliberately left events beyond the budget
    /// uncollected. The row therefore never carries failure markers and must
    /// not be counted as an output-write failure; it exists so the report can
    /// say "已达输出预算（N MB / M 段）" instead of degrading the job.
    /// </summary>
    public static SandboxEvent? ImportR0OutputBudgetStop(string? sidecarPath)
    {
        if (string.IsNullOrWhiteSpace(sidecarPath) || !File.Exists(sidecarPath))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(sidecarPath), JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var stopReason = ReadScalar(document.RootElement, "stopReason");
            if (!string.Equals(stopReason, "outputBudgetReached", StringComparison.Ordinal))
            {
                return null;
            }

            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["captureState"] = "truncated",
                ["status"] = "completed",
                ["stopReason"] = "outputBudgetReached",
                ["r0OutputBudgetReached"] = "true",
                ["r0OutputTruncated"] = "true",
                ["outputBudgetStop"] = "true",
                ["healthRowType"] = "driver.output.budgetStop",
                ["eventTypeAlias"] = "driver.output.budgetStop",
                ["outputBudgetStopPath"] = sidecarPath,
                ["outputBudgetStopRelativePath"] = Path.GetFileName(sidecarPath),
                ["sourceComponent"] = "ksword-r0collector",
                ["eventOrigin"] = "collector-sidecar",
                ["producerCategory"] = "r0collector",
                ["subjectKind"] = "collector-diagnostic",
                ["actorRole"] = "collector-infrastructure",
                ["subjectRole"] = "collector-diagnostic",
                ["collectionNoise"] = "true",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["notSampleBehavior"] = "true",
                ["sampleBehaviorCandidate"] = "false",
                ["eventKind"] = "diagnostic",
                ["evidenceRole"] = "collection-diagnostic",
                ["zhMessage"] = "R0 采集已达到累计输出预算并以干净方式停止（exit 0）；预算之后的事件有意未采集，这不是输出写失败。",
                ["zhHint"] = "该行来自独立 r0-status 侧车；请按预算字节数/段数评估截断位置，不要按 outputWriteFailure 处理。"
            };

            // Preserve every scalar sidecar field. Queue-depth aliases are
            // deliberately NOT mapped to remainingUnread: an intentional
            // budget boundary is not an undrained-queue failure.
            foreach (var property in document.RootElement.EnumerateObject())
            {
                var scalar = ScalarText(property.Value);
                if (!string.IsNullOrWhiteSpace(scalar))
                {
                    data[property.Name] = scalar;
                }
            }

            data["statusAnnotated"] = BoolText(data, "statusAnnotated") ? "true" : "false";
            data["finalStatusAvailable"] = BoolText(data, "finalStatusAvailable") ? "true" : "false";
            data["queueDepthAtStopKnown"] = BoolText(data, "queueDepthAtStopKnown") ? "true" : "false";

            var timestamp = File.GetLastWriteTimeUtc(sidecarPath);
            return new SandboxEvent
            {
                EventType = "r0collector.outputBudget",
                Timestamp = timestamp == default ? DateTimeOffset.UtcNow : new DateTimeOffset(timestamp, TimeSpan.Zero),
                Source = "r0collector",
                Path = sidecarPath,
                Data = data
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Imports the R0Collector output-failure sidecar independently from the
    /// broken JSONL stream.  The sidecar may contain a final GET_STATUS
    /// snapshot that was obtained after the sink failed; this row is the
    /// authoritative final unread/queue evidence when statusAnnotated=true.
    /// Inputs are a single sidecar path, processing preserves every scalar
    /// field and adds normalized health aliases, and the method returns one
    /// report-ready diagnostic row or null for invalid/unreadable JSON.
    /// </summary>
    public static SandboxEvent? ImportR0OutputFailure(string? sidecarPath)
    {
        if (string.IsNullOrWhiteSpace(sidecarPath) || !File.Exists(sidecarPath))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(sidecarPath), JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["captureState"] = ReadScalar(document.RootElement, "captureState") ?? "partial",
                ["status"] = "failed",
                ["failureType"] = ReadScalar(document.RootElement, "failureType") ?? "outputWriteFailure",
                ["outputFailureType"] = ReadScalar(document.RootElement, "failureType") ?? "outputWriteFailure",
                ["outputWriteFailure"] = "true",
                ["driverOutputFailure"] = "true",
                ["healthRowType"] = "driver.output.failure",
                ["eventTypeAlias"] = "driver.output.failure",
                ["outputFailurePath"] = sidecarPath,
                ["outputFailureRelativePath"] = Path.GetFileName(sidecarPath),
                ["sourceComponent"] = "ksword-r0collector",
                ["eventOrigin"] = "collector-sidecar",
                ["producerCategory"] = "r0collector",
                ["subjectKind"] = "collector-diagnostic",
                ["actorRole"] = "collector-infrastructure",
                ["subjectRole"] = "collector-diagnostic",
                ["collectionNoise"] = "true",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["notSampleBehavior"] = "true",
                ["sampleBehaviorCandidate"] = "false",
                ["eventKind"] = "diagnostic",
                ["evidenceRole"] = "collection-diagnostic",
                ["zhMessage"] = "R0Collector 输出失败侧车已导入；最终队列状态以 statusAnnotated 标记为准。",
                ["zhHint"] = "该行来自独立 failure.json，不代表样本行为；请同时查看原始 JSONL 分片、丢失计数和磁盘空间。"
            };

            foreach (var property in document.RootElement.EnumerateObject())
            {
                var scalar = ScalarText(property.Value);
                if (!string.IsNullOrWhiteSpace(scalar))
                {
                    data[property.Name] = scalar;
                }
            }

            var statusAnnotated = BoolText(data, "statusAnnotated");
            var finalStatusAvailable = BoolText(data, "finalStatusAvailable");
            var queueDepthKnown = BoolText(data, "queueDepthAtStopKnown");
            var finalQueueKnown = statusAnnotated && finalStatusAvailable && queueDepthKnown;
            data["statusAnnotated"] = statusAnnotated ? "true" : "false";
            data["finalStatusAvailable"] = finalStatusAvailable ? "true" : "false";
            data["queueDepthAtStopKnown"] = finalQueueKnown ? "true" : "false";
            data["queueDepthAtStopUnknown"] = finalQueueKnown ? "false" : "true";
            data["finalStatusSource"] = finalQueueKnown ? "r0-output-failure-sidecar" : "r0-output-failure-sidecar-unannotated";

            if (finalQueueKnown && TryGetUnsigned(data, "queueDepthAtStop", out var queueDepthAtStop))
            {
                // CollectionHealthSummaryBuilder consumes remainingUnread as
                // the explicit final tail.  Keep the original queueDepthAtStop
                // field too, so raw sidecar semantics remain inspectable.
                data["remainingUnread"] = queueDepthAtStop.ToString(CultureInfo.InvariantCulture);
                data["remainingUnreadEvents"] = queueDepthAtStop.ToString(CultureInfo.InvariantCulture);
                data["remainingQueueDepth"] = queueDepthAtStop.ToString(CultureInfo.InvariantCulture);
            }

            var timestamp = File.GetLastWriteTimeUtc(sidecarPath);
            return new SandboxEvent
            {
                EventType = "r0collector.finalStatus",
                Timestamp = timestamp == default ? DateTimeOffset.UtcNow : new DateTimeOffset(timestamp, TimeSpan.Zero),
                Source = "r0collector",
                Path = sidecarPath,
                Data = data
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Converts a failed persisted runbook step into an Agent collection
    /// failure when the guest output tree was never created. This closes the
    /// startup-before-markers gap (for example an Out-File disk-full error).
    /// </summary>
    public static IReadOnlyList<SandboxEvent> ImportRunbookFailure(string? resultPath)
    {
        if (string.IsNullOrWhiteSpace(resultPath) || !File.Exists(resultPath)) return [];
        try
        {
            var result = JsonSerializer.Deserialize<SandboxRunbookExecutionResult>(File.ReadAllText(resultPath), new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                PropertyNameCaseInsensitive = true
            });
            if (result is null || result.Success) return [];
            var failed = result.StepResults.Where(step => !step.Success).OrderBy(step => step.StepIndex).FirstOrDefault();
            if (failed is null) return [];
            if (result.Provider == VirtualizationProvider.VMware &&
                failed.StepId.Equals("copy-sample", StringComparison.OrdinalIgnoreCase))
            {
                var protectionBlock = ImportGuestSampleReadProtectionBlock(resultPath, failed.StepIndex);
                if (protectionBlock is not null) return [protectionBlock];
            }
            var output = $"{failed.Title}\n{failed.Message}\n{failed.StandardOutput}\n{failed.StandardError}";
            var guestAgentFailure = failed.StepId.Equals("run-agent", StringComparison.OrdinalIgnoreCase) ||
                failed.StepId.Equals("sync-live-output", StringComparison.OrdinalIgnoreCase) ||
                failed.StepId.Equals("collect-output", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Guest Agent", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("events.json", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("disk was full", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("allocation size", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Out-File", StringComparison.OrdinalIgnoreCase);
            if (!guestAgentFailure) return [];

            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["failureType"] = "guestAgentRunbookFailure",
                ["agentFailure"] = "true",
                ["runbookFailure"] = "true",
                ["runbookResultPath"] = resultPath,
                ["failedStepId"] = failed.StepId,
                ["failedStepIndex"] = failed.StepIndex.ToString(CultureInfo.InvariantCulture),
                ["exitCode"] = failed.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty,
                ["missingGuestMarkers"] = "true",
                ["failureReason"] = "guest-agent-startup-or-output-failed-before-guest-markers",
                ["stderrPreview"] = output.Length > 4096 ? output[..4096] : output,
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["notSampleBehavior"] = "true",
                ["sampleBehaviorCandidate"] = "false",
                ["eventKind"] = "diagnostic",
                ["evidenceRole"] = "collection-diagnostic",
                ["sourceComponent"] = "guest-agent",
                ["zhMessage"] = "Guest Agent 在生成来宾标记前失败，动态采集结果只能按部分/失败处理。",
                ["zhHint"] = "请查看 runbook-execution.json 失败步骤、标准错误和来宾磁盘空间；没有 events.json 不代表未检出。"
            };
            return [new SandboxEvent { EventType = "agent.run.failed", Source = "host", Path = resultPath, Data = data }];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return [];
        }
    }

    private static SandboxEvent? ImportGuestSampleReadProtectionBlock(string runbookResultPath, int failedStepIndex)
    {
        // The offline GuestOps copy-sample step writes this exact host-side
        // control artifact before it throws. The runbook's generic failure
        // message does not include the guest exception, so the artifact is
        // necessary to distinguish a protection block from a hash mismatch.
        var jobRoot = Path.GetDirectoryName(Path.GetFullPath(runbookResultPath));
        if (string.IsNullOrWhiteSpace(jobRoot)) return null;
        var hashResultPath = Path.Combine(jobRoot, "vmware-guestops", "sample-hash-result.json");
        try
        {
            var info = new FileInfo(hashResultPath);
            if (!info.Exists || info.Length is <= 0 or > 16384) return null;
            using var document = JsonDocument.Parse(File.ReadAllText(hashResultPath), JsonOptions);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !string.Equals(ReadString(root, "state"), "failed", StringComparison.OrdinalIgnoreCase)) return null;
            var guestError = ReadString(root, "error") ?? string.Empty;
            var nativeCode = ReadScalar(root, "nativeErrorCode") ?? string.Empty;
            var hresult = ReadScalar(root, "hresult") ?? string.Empty;
            if (!IsGuestProtectionReadBlock(guestError, nativeCode, hresult)) return null;

            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["collectionHealth"] = "true",
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["failureType"] = "guestSampleFileReadBlocked",
                ["sampleRuntimePreflight"] = "true",
                ["sampleRuntimeState"] = "sample-runtime-blocked",
                ["sampleRuntimeFailureCode"] = "sample-runtime-blocked-guest-file-read",
                ["sampleExecuted"] = "false",
                ["guestProtectionSource"] = "unconfirmed",
                ["preflightPath"] = hashResultPath,
                ["runbookResultPath"] = runbookResultPath,
                ["failedStepId"] = "copy-sample",
                ["failedStepIndex"] = failedStepIndex.ToString(CultureInfo.InvariantCulture),
                ["stderrPreview"] = guestError.Length > 2048 ? guestError[..2048] : guestError,
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["notSampleBehavior"] = "true",
                ["sampleBehaviorCandidate"] = "false",
                ["eventKind"] = "diagnostic",
                ["evidenceRole"] = "collection-diagnostic",
                ["sourceComponent"] = "runbook-preflight",
                ["failureReason"] = "guest-sample-file-read-blocked-by-protection",
                ["zhMessage"] = "来宾拒绝读取样本文件，样本未执行，动态结果不可判定。",
                ["zhHint"] = "检查来宾安全事件以及防病毒和文件过滤层状态；尚未确认具体拦截组件。修复来宾环境后从干净快照重跑。"
            };
            return new SandboxEvent
            {
                EventType = "sample.runtime.preflight.failed",
                Timestamp = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero),
                Source = "host",
                Path = hashResultPath,
                Data = data
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return null;
        }
    }

    private static bool IsGuestProtectionReadBlock(string message, string nativeCode, string hresult) =>
        string.Equals(nativeCode, "225", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(hresult, "0x800700e1", StringComparison.OrdinalIgnoreCase) ||
        message.Contains("ERROR_VIRUS_INFECTED", StringComparison.OrdinalIgnoreCase) ||
        message.Contains("0x800700e1", StringComparison.OrdinalIgnoreCase) ||
        message.Contains("WinError 225", StringComparison.OrdinalIgnoreCase) ||
        message.Contains("contains a virus", StringComparison.OrdinalIgnoreCase) ||
        message.Contains("potentially unwanted software", StringComparison.OrdinalIgnoreCase) ||
        message.Contains("文件包含病毒", StringComparison.OrdinalIgnoreCase) ||
        message.Contains("包含病毒或潜在的垃圾软件", StringComparison.OrdinalIgnoreCase);

    private static SandboxEvent CreateFailureRow(string eventType, string path, Dictionary<string, string> values, string hint)
    {
        values["behaviorCounted"] = "false";
        values["nonbehavior"] = "true";
        values["notSampleBehavior"] = "true";
        values["sampleBehaviorCandidate"] = "false";
        values["eventKind"] = "diagnostic";
        values["evidenceRole"] = "collection-diagnostic";
        values["sourceComponent"] = "guest-agent";
        values["failureReason"] = "guest-agent-output-incomplete-or-nonzero-exit";
        values["zhMessage"] = "Guest Agent 运行失败或输出不完整，动态采集只能按部分结果处理。";
        values["zhHint"] = hint;
        return new SandboxEvent { EventType = eventType, Source = "guest-agent", Path = path, Data = values };
    }

    private static SandboxEvent CreateSampleRuntimeFailureRow(
        string path,
        Dictionary<string, string> values,
        string hint)
    {
        values["behaviorCounted"] = "false";
        values["nonbehavior"] = "true";
        values["notSampleBehavior"] = "true";
        values["sampleBehaviorCandidate"] = "false";
        values["eventKind"] = "diagnostic";
        values["evidenceRole"] = "collection-diagnostic";
        values["sourceComponent"] = "runbook-preflight";
        values["failureReason"] = "sample-runtime-preflight-failed";
        values["zhMessage"] = "样本运行环境预检失败，样本未执行，动态结果不可判定。";
        values["zhHint"] = hint;
        return new SandboxEvent
        {
            EventType = "sample.runtime.preflight.failed",
            Source = "host",
            Path = path,
            Data = values
        };
    }

    private static StatusSnapshot? ReadStatus(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path), JsonOptions);
            var root = document.RootElement;
            return new StatusSnapshot(
                ReadString(root, "state"),
                ReadString(root, "capturedAtUtc"),
                ReadLong(root, "stdoutBytes"),
                ReadLong(root, "stderrBytes"),
                ReadStringArray(root, "missingArtifacts"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new StatusSnapshot("invalid-status-json", null, 0, 0, ["guest-agent-run-status.json"]);
        }
    }

    private static OutputPreflightSnapshot? ReadOutputPreflight(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path), JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return new OutputPreflightSnapshot(
                ReadString(document.RootElement, "state"),
                ReadString(document.RootElement, "outputRoot"),
                ReadString(document.RootElement, "volumeRoot"),
                ReadLong(document.RootElement, "availableFreeBytes"),
                ReadLong(document.RootElement, "requiredFreeBytes"),
                ReadString(document.RootElement, "checkedAtUtc"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new OutputPreflightSnapshot("invalid-preflight-json", null, null, 0, 0, null);
        }
    }

    private static SampleRuntimePreflightSnapshot? ReadSampleRuntimePreflight(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path), JsonOptions);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var root = document.RootElement;
            return new SampleRuntimePreflightSnapshot(
                ReadString(root, "state"),
                ReadString(root, "failureCode"),
                ReadString(root, "sampleFileName"),
                ReadString(root, "guestNetFx3State"),
                ReadString(root, "error"),
                ReadBool(root, "managedClrDetected"),
                ReadBool(root, "legacyClrDetected"),
                ReadBool(root, "guestSamplePresent"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new SampleRuntimePreflightSnapshot(
                "preflight-error",
                "sample-runtime-preflight-json-invalid",
                Path.GetFileName(path),
                "query-failed",
                "sample-runtime-preflight.json could not be parsed",
                false,
                false,
                false);
        }
    }

    private static string? FindNewest(string root, string fileName)
    {
        try
        {
            return Directory.EnumerateFiles(root, fileName, SearchOption.AllDirectories)
                .OrderByDescending(path => File.GetLastWriteTimeUtc(path))
                .FirstOrDefault();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    private static string? FindNewestParent(string root, string fileName)
    {
        try
        {
            var parent = Directory.GetParent(Path.GetFullPath(root))?.FullName;
            return string.IsNullOrWhiteSpace(parent) ? null : FindNewest(parent, fileName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException or ArgumentException)
        {
            return null;
        }
    }

    private static string? ReadText(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
        try
        {
            using var reader = new StreamReader(path, detectEncodingFromByteOrderMarks: true);
            var buffer = new char[4096];
            var count = reader.ReadBlock(buffer, 0, buffer.Length);
            return new string(buffer, 0, count).Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// Removes lines from <paramref name="agentStderr"/> that also appear in the
    /// sample-tree stderr lane. Matching is line-based and ordinal after
    /// trimming line endings/whitespace, so sample noise that also landed in
    /// agent.stderr.log (for example through an inherited handle) is attributed
    /// to the sample and only genuine agent diagnostics remain.
    /// </summary>
    private static string? RemoveLinesPresentIn(string? agentStderr, string? sampleStderr)
    {
        if (string.IsNullOrWhiteSpace(agentStderr))
        {
            return agentStderr;
        }

        if (string.IsNullOrWhiteSpace(sampleStderr))
        {
            return agentStderr;
        }

        var sampleLines = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in sampleStderr.Split('\n'))
        {
            var normalized = line.Trim('\r', ' ', '\t');
            if (normalized.Length > 0)
            {
                sampleLines.Add(normalized);
            }
        }

        var kept = agentStderr
            .Split('\n')
            .Where(line => !sampleLines.Contains(line.Trim('\r', ' ', '\t')))
            .ToList();
        var result = string.Join("\n", kept).Trim();
        return result.Length == 0 ? null : result;
    }

    private static long FileLength(string? path)
    {
        try { return string.IsNullOrWhiteSpace(path) ? 0 : new FileInfo(path).Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileNotFoundException) { return 0; }
    }

    private static bool TryParseExit(string? text, out int exitCode) =>
        int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out exitCode);

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool ReadBool(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;

    private static string? ReadScalar(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) ? ScalarText(value) : null;

    private static string? ScalarText(JsonElement value)
    {
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
    }

    private static bool BoolText(IReadOnlyDictionary<string, string> data, string key) =>
        data.TryGetValue(key, out var value) &&
        (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1");

    private static bool TryGetUnsigned(IReadOnlyDictionary<string, string> data, string key, out ulong value)
    {
        value = 0;
        return data.TryGetValue(key, out var text) &&
            ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static long ReadLong(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.TryGetInt64(out var number) ? number : 0;

    private static List<string> ReadStringArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array) return [];
        return value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString()).Where(item => !string.IsNullOrWhiteSpace(item)).Select(item => item!).ToList();
    }

    private sealed record StatusSnapshot(string? State, string? CapturedAtUtc, long StdoutBytes, long StderrBytes, List<string> MissingArtifacts);

    private sealed record OutputPreflightSnapshot(
        string? State,
        string? OutputRoot,
        string? VolumeRoot,
        long AvailableFreeBytes,
        long RequiredFreeBytes,
        string? CheckedAtUtc);

    private sealed record SampleRuntimePreflightSnapshot(
        string? State,
        string? FailureCode,
        string? SampleFileName,
        string? GuestNetFx3State,
        string? Error,
        bool ManagedClrDetected,
        bool LegacyClrDetected,
        bool GuestSamplePresent);
}
