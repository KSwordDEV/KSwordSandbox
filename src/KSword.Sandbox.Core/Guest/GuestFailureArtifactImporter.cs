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
        var eventsPath = FindNewest(root, "events.json");
        var summaryPath = FindNewest(root, "agent-summary.json");
        var rows = new List<SandboxEvent>();

        var status = statusPath is null ? null : ReadStatus(statusPath);
        var exitText = ReadText(exitPath);
        var parsedExit = TryParseExit(exitText, out var exitCode);
        var stderr = ReadText(stderrPath);
        var missing = status?.MissingArtifacts ?? [];
        if (missing.Count == 0)
        {
            if (eventsPath is null) missing.Add("events.json");
            if (summaryPath is null) missing.Add("agent-summary.json");
        }

        var state = status?.State;
        var failed = !string.Equals(state, "completed", StringComparison.OrdinalIgnoreCase) ||
            (parsedExit && exitCode != 0) ||
            (!string.IsNullOrWhiteSpace(exitText) && !parsedExit) ||
            missing.Count > 0 ||
            (!string.IsNullOrWhiteSpace(stderr) && statusPath is null);
        if (!failed)
        {
            return rows;
        }

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
        if (parsedExit) values["exitCode"] = exitCode.ToString(CultureInfo.InvariantCulture);
        if (status is not null)
        {
            values["statusState"] = status.State ?? string.Empty;
            values["statusCapturedAtUtc"] = status.CapturedAtUtc ?? string.Empty;
            values["stdoutBytes"] = status.StdoutBytes.ToString(CultureInfo.InvariantCulture);
            values["stderrBytes"] = status.StderrBytes.ToString(CultureInfo.InvariantCulture);
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
        return rows;
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
        try { return File.ReadAllText(path).Trim(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static bool TryParseExit(string? text, out int exitCode) =>
        int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out exitCode);

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static long ReadLong(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.TryGetInt64(out var number) ? number : 0;

    private static List<string> ReadStringArray(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array) return [];
        return value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString()).Where(item => !string.IsNullOrWhiteSpace(item)).Select(item => item!).ToList();
    }

    private sealed record StatusSnapshot(string? State, string? CapturedAtUtc, long StdoutBytes, long StderrBytes, List<string> MissingArtifacts);
}
