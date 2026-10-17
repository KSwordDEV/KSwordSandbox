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
        var exitPath = FindNewest(root, "agent.exit");
        var pidPath = FindNewest(root, "agent.pid");
        var eventsPath = FindNewest(root, "events.json");
        var summaryPath = FindNewest(root, "agent-summary.json");
        var preflightPath = FindNewest(root, "guest-output-preflight.json");
        var r0FailurePath = FindNewest(root, "driver-events.jsonl.failure.json");
        var rows = new List<SandboxEvent>();

        var status = statusPath is null ? null : ReadStatus(statusPath);
        var exitText = ReadText(exitPath);
        var parsedExit = TryParseExit(exitText, out var exitCode);
        var stderr = ReadText(stderrPath);
        var missing = status?.MissingArtifacts ?? [];
        var hasAgentMarker = statusPath is not null || stderrPath is not null || exitPath is not null || pidPath is not null || summaryPath is not null;
        var hasR0Failure = r0FailurePath is not null;
        var preflight = preflightPath is null ? null : ReadOutputPreflight(preflightPath);
        var preflightFailed = preflight is not null &&
            !string.Equals(preflight.State, "ready", StringComparison.OrdinalIgnoreCase);
        // Offline fixtures and older externally-produced events.json files do
        // not necessarily carry the Agent marker set. Do not invent a missing
        // summary failure for those already-complete event streams.
        if (!hasAgentMarker && !hasR0Failure && !preflightFailed)
        {
            return rows;
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
            // Preserve any Agent stderr as a structured runtime diagnostic.
            // Even when the exit marker says 0, stderr means the collector
            // reported an issue that must remain visible to operators.
            !string.IsNullOrWhiteSpace(stderr));

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
            if (!string.IsNullOrWhiteSpace(stderr))
            {
                values["stderrPreview"] = stderr.Length > 4096 ? stderr[..4096] : stderr;
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

        return rows;
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

    private static long FileLength(string? path)
    {
        try { return string.IsNullOrWhiteSpace(path) ? 0 : new FileInfo(path).Length; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FileNotFoundException) { return 0; }
    }

    private static bool TryParseExit(string? text, out int exitCode) =>
        int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out exitCode);

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

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
}
