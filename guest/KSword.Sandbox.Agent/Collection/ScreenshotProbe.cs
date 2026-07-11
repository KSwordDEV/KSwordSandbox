using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Optionally captures guest desktop screenshots around sample execution.
/// Inputs are probe phases, a capture-enabled flag, and screenshot stage/count
/// options from CLI parsing; processing delegates platform-specific capture to
/// IScreenshotCapture; CollectAsync returns screenshot.captured or
/// screenshot.skipped events.
/// </summary>
internal sealed class ScreenshotProbe : IGuestProbe
{
    private const string ReasonTaxonomy = "guest-artifact.screenshot.reason.v1";
    private const string PhaseSummaryVersion = "screenshot-phase-summary-v1";
    private const string ArtifactSelectorVersion = "artifact-selectors-v1";

    private readonly IScreenshotCapture screenshotCapture;
    private readonly ScreenshotProbeOptions options;

    public ScreenshotProbe()
        : this(new WindowsDesktopScreenshotCapture(), ScreenshotProbeOptions.Default)
    {
    }

    /// <summary>
    /// Creates a screenshot probe with an injectable capture implementation.
    /// The input is a screenshot capture service, processing stores it for
    /// future probe phases, and the constructor returns no value.
    /// </summary>
    public ScreenshotProbe(IScreenshotCapture screenshotCapture)
        : this(screenshotCapture, ScreenshotProbeOptions.Default)
    {
    }

    /// <summary>
    /// Creates a screenshot probe with configurable stage and count settings.
    /// The input is screenshot probe options; processing stores the capture
    /// plan and default platform capture service; the constructor returns no
    /// value.
    /// </summary>
    public ScreenshotProbe(ScreenshotProbeOptions options)
        : this(new WindowsDesktopScreenshotCapture(), options)
    {
    }

    /// <summary>
    /// Creates a screenshot probe with injectable capture and capture plan.
    /// The inputs are screenshot capture service and options; processing
    /// stores both for future probe phases; the constructor returns no value.
    /// </summary>
    public ScreenshotProbe(IScreenshotCapture screenshotCapture, ScreenshotProbeOptions? options)
    {
        this.screenshotCapture = screenshotCapture;
        this.options = options ?? ScreenshotProbeOptions.Default;
    }

    public string ProbeId => "screenshot";

    /// <summary>
    /// Captures screenshots for enabled configured phases.
    /// Inputs are phase, guest context, and cancellation token; processing skips
    /// capture when disabled or outside the selected stages, and can emit more
    /// than one event per phase when the requested count is greater than one;
    /// the method returns screenshot events for enabled attempts.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (!context.CaptureScreenshots)
        {
            return phase == ProbePhase.BeforeStart
                ? [CreateDisabledEvent(context)]
                : [];
        }

        var requests = options.GetCaptureRequests(phase);
        if (requests.Count == 0)
        {
            return [];
        }

        var events = new List<SandboxEvent>(requests.Count + 1);
        foreach (var request in requests)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await screenshotCapture.CaptureAsync(context.OutputDirectory, request.ArtifactLabel, cancellationToken);
            events.Add(CreateScreenshotEvent(phase, context, request, result));
        }

        events.Add(CreatePhaseSummaryEvent(phase, context, requests, events));
        return events;
    }

    /// <summary>
    /// Converts one capture result into a normalized screenshot event.
    /// Inputs are probe phase, run context, capture request, and result;
    /// processing copies event and manifest metadata into Data; the method
    /// returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateScreenshotEvent(
        ProbePhase phase,
        GuestProbeContext context,
        ScreenshotCaptureRequest request,
        ScreenshotCaptureResult result)
    {
        var evt = new SandboxEvent
        {
            EventType = result.Captured ? "screenshot.captured" : "screenshot.skipped",
            Source = "guest",
            Path = result.Path,
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = request.ProbePhaseLabel,
                ["capturePhase"] = request.ProbePhaseLabel,
                ["probePhase"] = ToPhaseLabel(phase),
                ["screenshotStage"] = request.StageLabel,
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-screenshot",
                ["captureState"] = result.Captured ? "captured" : "skipped",
                ["status"] = result.Captured ? "captured" : "skipped",
                ["nonfatal"] = FormatBoolean(!result.Captured),
                ["artifactEvent"] = "true",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["evidenceRole"] = "screenshot",
                ["collectionName"] = "screenshots",
                ["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["screenshotIndex"] = request.Sequence.ToString(CultureInfo.InvariantCulture),
                ["screenshotCount"] = request.TotalCount.ToString(CultureInfo.InvariantCulture),
                ["artifactLabel"] = request.ArtifactLabel,
                ["expectedRelativePath"] = "screenshots/*.bmp",
                ["imageFormat"] = "bmp",
                ["bitsPerPixel"] = "32",
                ["captureMethod"] = "windows-gdi-bitblt",
                ["captureSurface"] = "virtual-screen",
                ["userInteractive"] = Environment.UserInteractive.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["sessionName"] = Environment.GetEnvironmentVariable("SESSIONNAME") ?? string.Empty,
                ["samplePath"] = context.SamplePath
            }
        };

        if (context.RootProcessId is not null)
        {
            evt.Data["rootProcessId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["processId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["treeDepth"] = "0";
            evt.Data["treeLineage"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "processName", evt.ProcessName);

        if (result.Captured)
        {
            evt.Data["zhMessage"] = "截图已采集为可下载证据文件。";
            evt.Data["zhHint"] = "请使用 artifactRelativePath 下载截图；sizeBytes/sha256 可用于校验文件完整性。";
        }
        else if (!string.IsNullOrWhiteSpace(result.Reason))
        {
            evt.Data["reason"] = result.Reason;
            evt.Data["reasonCode"] = ScreenshotReasonCode(result);
            evt.Data["reasonCategory"] = ScreenshotReasonCategory(result);
            evt.Data["reasonTaxonomy"] = ReasonTaxonomy;
            evt.Data["reasonTaxonomyVersion"] = "v1";
            evt.Data["collectionHealth"] = "true";
            evt.Data["zhReason"] = ScreenshotReasonZhReason(result);
            evt.Data["zhMessage"] = "截图采集被跳过；该事件说明证据缺口，不会中断整体分析。";
            evt.Data["zhHint"] = ScreenshotReasonZhHint(result.Reason, result.DiagnosticStage);
        }

        if (!string.IsNullOrWhiteSpace(result.ExceptionType))
        {
            evt.Data["exceptionType"] = result.ExceptionType;
        }

        if (!string.IsNullOrWhiteSpace(result.DiagnosticStage))
        {
            evt.Data["diagnosticStage"] = result.DiagnosticStage;
        }

        if (result.Win32Error is not null)
        {
            evt.Data["win32Error"] = result.Win32Error.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (result.WidthPixels is not null)
        {
            evt.Data["widthPixels"] = result.WidthPixels.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (result.HeightPixels is not null)
        {
            evt.Data["heightPixels"] = result.HeightPixels.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(result.Path))
        {
            var relativePath = SafeRelativePath(context.OutputDirectory, result.Path);
            var artifactRelativePath = SafeArtifactRelativePath(context.OutputDirectory, result.Path);
            evt.Data["relativePath"] = relativePath;
            evt.Data["screenshotPath"] = result.Path;
            evt.Data["screenshotRelativePath"] = relativePath;
            evt.Data["artifactFullPath"] = result.Path;
            AddIfNotEmpty(evt.Data, "artifactRelativePath", artifactRelativePath);
            AddIfNotEmpty(evt.Data, "artifactSelector", artifactRelativePath);
            AddIfNotEmpty(evt.Data, "downloadSelector", artifactRelativePath);
            AddIfNotEmpty(evt.Data, "artifactSelectorKind", string.IsNullOrWhiteSpace(artifactRelativePath) ? null : "safe-output-relative-path");
            AddIfNotEmpty(evt.Data, "artifactSelectorVersion", string.IsNullOrWhiteSpace(artifactRelativePath) ? null : ArtifactSelectorVersion);
            evt.Data["artifactRelativePathStatus"] = string.IsNullOrWhiteSpace(artifactRelativePath) ? "outside-output-root" : "captured";
            AddArtifactFileEvidence(evt, result.Path);
        }
        else
        {
            evt.Data["artifactExists"] = "false";
            evt.Data["artifactIntegrityState"] = result.Captured ? "missing" : "skipped";
            evt.Data["artifactRelativePathStatus"] = result.Captured ? "missing" : "not-created";
            evt.Data["sizeBytesStatus"] = result.Captured ? "missing" : "not-created";
            evt.Data["sha256Status"] = result.Captured ? "missing" : "not-created";
            evt.Data["artifactHashStatus"] = result.Captured ? "missing" : "not-created";
        }

        return evt;
    }

    /// <summary>
    /// Creates a non-behavior summary for one configured screenshot phase.
    /// Inputs are the phase, request plan, and per-attempt events; processing
    /// aggregates captured/skipped counts, reason taxonomy counts, and
    /// first/last/largest artifact selectors; the method returns a summary row.
    /// </summary>
    private static SandboxEvent CreatePhaseSummaryEvent(
        ProbePhase phase,
        GuestProbeContext context,
        IReadOnlyList<ScreenshotCaptureRequest> requests,
        IReadOnlyList<SandboxEvent> attemptEvents)
    {
        var capturedCount = attemptEvents.Count(static evt => string.Equals(evt.EventType, "screenshot.captured", StringComparison.OrdinalIgnoreCase));
        var skippedCount = attemptEvents.Count(static evt => string.Equals(evt.EventType, "screenshot.skipped", StringComparison.OrdinalIgnoreCase));
        var phaseLabel = ToPhaseLabel(phase);
        var status = capturedCount > 0
            ? skippedCount > 0 ? "partial" : "captured"
            : skippedCount > 0 ? "skipped" : "enabled-empty";
        var evt = new SandboxEvent
        {
            EventType = "screenshot.phase.summary",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = phaseLabel,
                ["capturePhase"] = phaseLabel,
                ["probePhase"] = phaseLabel,
                ["screenshotStage"] = string.Join(",", requests.Select(static request => request.StageLabel).Distinct(StringComparer.OrdinalIgnoreCase)),
                ["screenshotPhaseSummaryVersion"] = PhaseSummaryVersion,
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-screenshot",
                ["captureState"] = status,
                ["status"] = status,
                ["summaryEvent"] = "true",
                ["artifactEvent"] = "false",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["evidenceRole"] = "screenshot",
                ["collectionName"] = "screenshots",
                ["expectedRelativePath"] = "screenshots/*.bmp",
                ["captureAttemptCount"] = attemptEvents.Count.ToString(CultureInfo.InvariantCulture),
                ["configuredCaptureCount"] = requests.Count.ToString(CultureInfo.InvariantCulture),
                ["capturedCount"] = capturedCount.ToString(CultureInfo.InvariantCulture),
                ["skippedCount"] = skippedCount.ToString(CultureInfo.InvariantCulture),
                ["artifactCount"] = capturedCount.ToString(CultureInfo.InvariantCulture),
                ["artifactSelectorVersion"] = ArtifactSelectorVersion,
                ["reasonTaxonomy"] = ReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["reason"] = ScreenshotPhaseSummaryReason(capturedCount, skippedCount),
                ["reasonCategory"] = capturedCount > 0 ? "captured" : skippedCount > 0 ? "skipped" : "empty",
                ["samplePath"] = context.SamplePath,
                ["zhMessage"] = capturedCount > 0
                    ? "截图阶段采集摘要已记录，并包含可下载截图选择器。"
                    : "截图阶段采集摘要已记录，但没有产出可下载截图。",
                ["zhHint"] = "这是截图采集阶段摘要，不代表样本行为；请使用 first/last/largestArtifactSelector 或 reasonCountsJson 审阅截图证据质量。"
            }
        };

        AddRunContext(evt, context);
        AddScreenshotReasonSummaries(evt, attemptEvents);
        AddScreenshotArtifactSelectors(evt.Data, attemptEvents);
        return evt;
    }

    /// <summary>
    /// Creates a single disabled event for the opt-in screenshot lane.
    /// </summary>
    private static SandboxEvent CreateDisabledEvent(GuestProbeContext context)
    {
        var evt = new SandboxEvent
        {
            EventType = "screenshot.disabled",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "before-start",
                ["capturePhase"] = "before-start",
                ["captureEnabled"] = "false",
                ["implemented"] = "true",
                ["capturePolicy"] = "explicit-opt-in-screenshot",
                ["reason"] = "screenshotNotRequested",
                ["reasonCode"] = "screenshotNotRequested",
                ["reasonCategory"] = "disabled",
                ["reasonTaxonomy"] = ReasonTaxonomy,
                ["reasonTaxonomyVersion"] = "v1",
                ["zhMessage"] = "截图采集未启用。",
                ["zhReason"] = "未请求截图采集。",
                ["zhHint"] = "未启用 --screenshot/--screenshots，Guest Agent 不会截取桌面内容。",
                ["captureState"] = "disabled",
                ["status"] = "disabled",
                ["nonfatal"] = "true",
                ["artifactEvent"] = "false",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["collectionHealth"] = "true",
                ["evidenceRole"] = "screenshot",
                ["collectionName"] = "screenshots",
                ["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["expectedRelativePath"] = "screenshots/*.bmp",
                ["artifactRelativePathStatus"] = "disabled",
                ["artifactExists"] = "false",
                ["artifactIntegrityState"] = "disabled",
                ["sizeBytesStatus"] = "disabled",
                ["sha256Status"] = "disabled",
                ["artifactHashStatus"] = "disabled",
                ["samplePath"] = context.SamplePath
            }
        };

        if (context.RootProcessId is not null)
        {
            evt.Data["rootProcessId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["processId"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["treeDepth"] = "0";
            evt.Data["treeLineage"] = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "processName", evt.ProcessName);
        return evt;
    }

    private static string ScreenshotPhaseSummaryReason(int capturedCount, int skippedCount)
    {
        if (capturedCount > 0)
        {
            return skippedCount > 0 ? "someScreenshotsCaptured" : "allScreenshotsCaptured";
        }

        if (skippedCount > 0)
        {
            return "allScreenshotsSkipped";
        }

        return "noScreenshotAttempts";
    }

    private static void AddRunContext(SandboxEvent evt, GuestProbeContext context)
    {
        evt.Data["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context";
        if (context.RootProcessId is not null)
        {
            var rootProcessId = context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["rootProcessId"] = rootProcessId;
            evt.Data.TryAdd("processId", rootProcessId);
            evt.Data.TryAdd("treeDepth", "0");
            evt.Data.TryAdd("treeLineage", rootProcessId);
            evt.Data.TryAdd("rootProcessIdStatus", "available");
            evt.Data.TryAdd("treeLineageStatus", "stable");
        }
        else
        {
            evt.Data.TryAdd("rootProcessIdStatus", "unavailable");
            evt.Data.TryAdd("treeLineageStatus", "unavailable");
        }

        if (context.RootParentProcessId is not null)
        {
            evt.Data["rootParentProcessId"] = context.RootParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data.TryAdd("parentProcessId", context.RootParentProcessId.Value.ToString(CultureInfo.InvariantCulture));
        }

        AddIfNotEmpty(evt.Data, "processName", context.RootProcessName ?? evt.ProcessName);
        AddIfNotEmpty(evt.Data, "rootProcessName", context.RootProcessName);
        AddIfNotEmpty(evt.Data, "processImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "commandLine", context.RootCommandLine);
        AddIfNotEmpty(evt.Data, "rootCommandLine", context.RootCommandLine);
        if (context.RootProcessStartTimeUtc is not null)
        {
            evt.Data["rootProcessStartTimeUtc"] = context.RootProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }
    }

    private static void AddScreenshotReasonSummaries(SandboxEvent evt, IReadOnlyList<SandboxEvent> attemptEvents)
    {
        AddCounts(evt.Data, "reason", CountDataValues(attemptEvents, "reason"));
        AddCounts(evt.Data, "reasonCategory", CountDataValues(attemptEvents, "reasonCategory"));
    }

    private static Dictionary<string, int> CountDataValues(IReadOnlyList<SandboxEvent> events, string key)
    {
        return events
            .Select(evt => evt.Data.TryGetValue(key, out var value) ? value : string.Empty)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .GroupBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .OrderBy(static group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.OrdinalIgnoreCase);
    }

    private static void AddCounts(Dictionary<string, string> data, string prefix, IReadOnlyDictionary<string, int> counts)
    {
        data[$"{prefix}Count"] = counts.Count.ToString(CultureInfo.InvariantCulture);
        if (counts.Count == 0)
        {
            return;
        }

        data[$"{prefix}s"] = string.Join(",", counts.Keys);
        data[$"{prefix}Counts"] = string.Join(
            ";",
            counts.Select(pair => $"{pair.Key}={pair.Value.ToString(CultureInfo.InvariantCulture)}"));
        data[$"{prefix}CountsJson"] = JsonSerializer.Serialize(counts);
    }

    private static void AddScreenshotArtifactSelectors(Dictionary<string, string> data, IReadOnlyList<SandboxEvent> attemptEvents)
    {
        var artifacts = attemptEvents
            .Where(static evt => string.Equals(evt.EventType, "screenshot.captured", StringComparison.OrdinalIgnoreCase))
            .Select(static evt => new ScreenshotArtifactSummary(
                FirstData(evt, "artifactRelativePath", "relativePath", "screenshotRelativePath"),
                ParseLong(FirstData(evt, "artifactSizeBytes", "sizeBytes")),
                FirstData(evt, "artifactSha256", "sha256")))
            .Where(static artifact => !string.IsNullOrWhiteSpace(artifact.RelativePath))
            .ToList();

        if (artifacts.Count == 0)
        {
            data["artifactSelectorState"] = "none-captured";
            return;
        }

        data["artifactSelectorState"] = "available";
        data["artifactSelectorMode"] = "phase-event-order-and-size";
        AddArtifactSelector(data, "first", artifacts.First(), "first-captured-event");
        AddArtifactSelector(data, "last", artifacts.Last(), "last-captured-event");
        AddArtifactSelector(
            data,
            "largest",
            artifacts
                .OrderByDescending(static artifact => artifact.SizeBytes)
                .ThenBy(static artifact => artifact.RelativePath, StringComparer.OrdinalIgnoreCase)
                .First(),
            "largest-size-bytes");
    }

    private static void AddArtifactSelector(
        Dictionary<string, string> data,
        string prefix,
        ScreenshotArtifactSummary artifact,
        string selectionReason)
    {
        var titlePrefix = char.ToUpperInvariant(prefix[0]) + prefix[1..];
        data[ArtifactSelectorKey(prefix)] = artifact.RelativePath;
        data[$"{prefix}ArtifactRelativePath"] = artifact.RelativePath;
        data[$"{prefix}ArtifactSafeLink"] = BuildSafeLink(artifact.RelativePath);
        data[$"{prefix}ArtifactSizeBytes"] = artifact.SizeBytes.ToString(CultureInfo.InvariantCulture);
        AddIfNotEmpty(data, $"{prefix}ArtifactSha256", artifact.Sha256);
        data[$"{prefix}ArtifactSelectionReason"] = selectionReason;
        data[$"has{titlePrefix}ArtifactSelector"] = "true";
    }

    private static string ArtifactSelectorKey(string prefix)
    {
        return prefix switch
        {
            "first" => "firstArtifactSelector",
            "last" => "lastArtifactSelector",
            "largest" => "largestArtifactSelector",
            _ => $"{prefix}ArtifactSelector"
        };
    }

    private static string FirstData(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static long ParseLong(string value)
    {
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : 0;
    }

    private static string BuildSafeLink(string relativePath)
    {
        return string.Join(
            "/",
            relativePath
                .Replace('\\', '/')
                .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(Uri.EscapeDataString));
    }

    private static string ScreenshotReasonZhHint(string reason, string? diagnosticStage)
    {
        if (reason.Contains("only implemented on Windows", StringComparison.OrdinalIgnoreCase))
        {
            return "截图采集当前仅支持 Windows guest；非 Windows 环境会记录 skipped。";
        }

        if (diagnosticStage is "GetSystemMetrics" or "GetDC" or "CreateCompatibleDC" or "CreateCompatibleBitmap" or "SelectObject" or "BitBlt" or "GetDIBits")
        {
            return "Windows 桌面/GDI 截图调用失败；请确认 guest 处于可交互桌面会话、权限足够且不是无头会话。";
        }

        return "请结合 diagnosticStage、exceptionType 和 win32Error 判断是桌面会话、权限、GDI 还是输出路径问题。";
    }

    private static string ScreenshotReasonCode(ScreenshotCaptureResult result)
    {
        if (result.Reason?.Contains("only implemented on Windows", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "notWindows";
        }

        return result.DiagnosticStage switch
        {
            "GetSystemMetrics" => "noVisibleDesktopSurface",
            "GetDC" => "desktopDeviceContextUnavailable",
            "CreateCompatibleDC" => "gdiCompatibleDcFailed",
            "CreateCompatibleBitmap" => "gdiBitmapCreateFailed",
            "SelectObject" => "gdiSelectObjectFailed",
            "BitBlt" => "gdiBitBltFailed",
            "GetDIBits" => "gdiReadPixelsFailed",
            "platform-check" => "notWindows",
            "capture" => "captureFailed",
            _ => "screenshotSkipped"
        };
    }

    private static string ScreenshotReasonCategory(ScreenshotCaptureResult result)
    {
        if (string.Equals(ScreenshotReasonCode(result), "notWindows", StringComparison.OrdinalIgnoreCase))
        {
            return "platform";
        }

        return result.DiagnosticStage switch
        {
            "GetSystemMetrics" => "desktop-session",
            "GetDC" or "CreateCompatibleDC" or "CreateCompatibleBitmap" or "SelectObject" or "BitBlt" or "GetDIBits" => "windows-gdi",
            "capture" => "capture-io",
            _ => "unknown"
        };
    }

    private static string ScreenshotReasonZhReason(ScreenshotCaptureResult result)
    {
        return ScreenshotReasonCode(result) switch
        {
            "notWindows" => "非 Windows guest。",
            "noVisibleDesktopSurface" => "没有可见桌面表面。",
            "desktopDeviceContextUnavailable" => "无法获取桌面设备上下文。",
            "gdiCompatibleDcFailed" => "GDI 兼容 DC 创建失败。",
            "gdiBitmapCreateFailed" => "GDI 位图创建失败。",
            "gdiSelectObjectFailed" => "GDI 选择位图失败。",
            "gdiBitBltFailed" => "桌面 BitBlt 复制失败。",
            "gdiReadPixelsFailed" => "截图像素读取失败。",
            "captureFailed" => "截图写入或捕获失败。",
            _ => "截图采集被跳过。"
        };
    }

    /// <summary>
    /// Adds event-level size and SHA-256 metadata for a captured screenshot.
    /// Inputs are a screenshot event and artifact path; processing reads the
    /// file best-effort with sharing flags; failures become compact diagnostics.
    /// </summary>
    private static void AddArtifactFileEvidence(SandboxEvent evt, string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                evt.Data["hashStatus"] = "missing";
                evt.Data["artifactHashStatus"] = "missing";
                evt.Data["artifactExists"] = "false";
                evt.Data["artifactIntegrityState"] = "missing";
                evt.Data["sizeBytesStatus"] = "missing";
                evt.Data["sha256Status"] = "missing";
                return;
            }

            evt.Data["artifactExists"] = "true";
            evt.Data["sizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactSizeBytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactLastWriteUtc"] = info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            evt.Data["sha256"] = sha256;
            evt.Data["artifactSha256"] = sha256;
            evt.Data["hashAlgorithm"] = "sha256";
            evt.Data["hashStatus"] = "computed";
            evt.Data["artifactHashAlgorithm"] = "sha256";
            evt.Data["artifactHashStatus"] = "computed";
            evt.Data["artifactIntegrityState"] = "verified";
            evt.Data["sizeBytesStatus"] = "computed";
            evt.Data["sha256Status"] = "computed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data["hashStatus"] = "failed";
            evt.Data["artifactHashStatus"] = "failed";
            evt.Data["artifactIntegrityState"] = "hash-failed";
            evt.Data["sha256Status"] = "failed";
            evt.Data["artifactHashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["artifactHashMessage"] = ex.Message;
        }
    }

    /// <summary>
    /// Reads a display process name for sample-scoped artifact events.
    /// Inputs are a sample path; processing extracts only the file name; the
    /// method returns null when no stable name is available.
    /// </summary>
    private static string? SampleProcessName(string samplePath)
    {
        try
        {
            return string.IsNullOrWhiteSpace(samplePath) ? null : Path.GetFileName(samplePath);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// Computes a display relative path without trusting malformed paths.
    /// Inputs are output root and artifact path; processing normalizes
    /// separators and falls back to the original path on invalid input.
    /// </summary>
    private static string SafeRelativePath(string root, string path)
    {
        try
        {
            return Path.GetRelativePath(root, path).Replace('\\', '/');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            return path;
        }
    }

    /// <summary>
    /// Computes an artifact-relative path only when the path is under --out.
    /// Inputs are output root and artifact path; processing rejects rooted or
    /// cross-root values; the method returns empty text when no safe path exists.
    /// </summary>
    private static string SafeArtifactRelativePath(string root, string path)
    {
        try
        {
            var outputRoot = Path.GetFullPath(root);
            var fullPath = Path.GetFullPath(path);
            var outputRootWithSeparator = Path.EndsInDirectorySeparator(outputRoot)
                ? outputRoot
                : outputRoot + Path.DirectorySeparatorChar;
            if (!fullPath.StartsWith(outputRootWithSeparator, StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty;
            }

            return Path.GetRelativePath(outputRoot, fullPath).Replace('\\', '/');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Adds non-empty event Data values.
    /// </summary>
    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Formats booleans as lowercase invariant strings for event Data.
    /// </summary>
    private static string FormatBoolean(bool value)
    {
        return value.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
    }

    /// <summary>
    /// Converts probe phases to stable artifact labels.
    /// Inputs are enum values; processing maps known screenshot phases; the
    /// method returns a lowercase label for filenames and event Data.
    /// </summary>
    private static string ToPhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.AfterStart => "after-start",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString()
        };
    }

    private sealed record ScreenshotArtifactSummary(string RelativePath, long SizeBytes, string Sha256);
}

/// <summary>
/// Operator-selected screenshot capture plan.
/// Inputs are parsed screenshot stages and a per-stage capture count;
/// processing maps probe phases to screenshot requests; methods return the
/// best-effort capture attempts that should run for a phase.
/// </summary>
internal sealed record ScreenshotProbeOptions
{
    public const int DefaultCaptureCount = 1;
    public const int MaximumCaptureCount = 5;

    public static readonly ScreenshotProbeOptions Default = new()
    {
        Stages = [ScreenshotStage.Before, ScreenshotStage.During, ScreenshotStage.After],
        CaptureCount = DefaultCaptureCount
    };

    public required IReadOnlyList<ScreenshotStage> Stages { get; init; }

    public int CaptureCount { get; init; } = DefaultCaptureCount;

    /// <summary>
    /// Parses user-facing screenshot phase/count switches.
    /// Inputs are optional comma-separated stages and count text; processing
    /// accepts before/during/after aliases and clamps count to a safe maximum;
    /// the method returns a normalized screenshot plan.
    /// </summary>
    public static ScreenshotProbeOptions Parse(string? rawStages, string? rawCount)
    {
        return new ScreenshotProbeOptions
        {
            Stages = ParseStages(rawStages),
            CaptureCount = ParseCaptureCount(rawCount)
        };
    }

    /// <summary>
    /// Builds capture requests for a probe phase.
    /// Inputs are the current probe phase; processing checks selected stages
    /// and expands count into sequence-aware artifact labels; the method
    /// returns zero or more requests for that phase.
    /// </summary>
    public IReadOnlyList<ScreenshotCaptureRequest> GetCaptureRequests(ProbePhase phase)
    {
        var stage = StageFromPhase(phase);
        if (stage is null || !Stages.Contains(stage.Value))
        {
            return [];
        }

        var count = Math.Clamp(CaptureCount, 1, MaximumCaptureCount);
        var stageLabel = ToStageLabel(stage.Value);
        var phaseLabel = ToProbePhaseLabel(phase);
        var requests = new List<ScreenshotCaptureRequest>(count);
        for (var sequence = 1; sequence <= count; sequence++)
        {
            var artifactLabel = count == 1
                ? phaseLabel
                : $"{phaseLabel}-{sequence:00}-of-{count:00}";
            requests.Add(new ScreenshotCaptureRequest(
                stage.Value,
                stageLabel,
                phaseLabel,
                artifactLabel,
                sequence,
                count));
        }

        return requests;
    }

    /// <summary>
    /// Formats the selected stages as stable CLI text.
    /// Inputs are none; processing joins normalized labels; the method returns
    /// a comma-separated before/during/after list.
    /// </summary>
    public string FormatStages()
    {
        return string.Join(",", Stages.Select(ToStageLabel));
    }

    private static IReadOnlyList<ScreenshotStage> ParseStages(string? rawStages)
    {
        if (string.IsNullOrWhiteSpace(rawStages))
        {
            return Default.Stages;
        }

        var stages = new List<ScreenshotStage>();
        foreach (var token in rawStages.Split([',', ';', '|', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (string.Equals(token, "all", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "default", StringComparison.OrdinalIgnoreCase))
            {
                AddDistinct(stages, ScreenshotStage.Before);
                AddDistinct(stages, ScreenshotStage.During);
                AddDistinct(stages, ScreenshotStage.After);
                continue;
            }

            AddDistinct(stages, ParseStage(token));
        }

        if (stages.Count == 0)
        {
            throw new ArgumentException("--screenshot-phases must include before, during, or after.");
        }

        return stages;
    }

    private static int ParseCaptureCount(string? rawCount)
    {
        if (string.IsNullOrWhiteSpace(rawCount))
        {
            return DefaultCaptureCount;
        }

        if (!int.TryParse(rawCount, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new ArgumentException("--screenshot-count must be an integer.");
        }

        return Math.Clamp(parsed, 1, MaximumCaptureCount);
    }

    private static ScreenshotStage ParseStage(string token)
    {
        return token.Trim().ToLowerInvariant() switch
        {
            "before" or "pre" or "before-start" or "pre-start" => ScreenshotStage.Before,
            "during" or "runtime" or "after-start" or "started" => ScreenshotStage.During,
            "after" or "post" or "after-run" or "post-run" => ScreenshotStage.After,
            _ => throw new ArgumentException($"Unsupported --screenshot-phases value '{token}'. Use before,during,after.")
        };
    }

    private static void AddDistinct(List<ScreenshotStage> stages, ScreenshotStage stage)
    {
        if (!stages.Contains(stage))
        {
            stages.Add(stage);
        }
    }

    private static ScreenshotStage? StageFromPhase(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.BeforeStart => ScreenshotStage.Before,
            ProbePhase.AfterStart => ScreenshotStage.During,
            ProbePhase.AfterRun => ScreenshotStage.After,
            _ => null
        };
    }

    private static string ToStageLabel(ScreenshotStage stage)
    {
        return stage switch
        {
            ScreenshotStage.Before => "before",
            ScreenshotStage.During => "during",
            ScreenshotStage.After => "after",
            _ => stage.ToString().ToLowerInvariant()
        };
    }

    private static string ToProbePhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.AfterStart => "after-start",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString()
        };
    }
}

/// <summary>
/// User-facing screenshot stages that map onto probe phases.
/// Inputs are CLI configuration values; processing maps them to
/// BeforeStart/AfterStart/AfterRun; values are stored in capture metadata.
/// </summary>
internal enum ScreenshotStage
{
    Before = 0,
    During,
    After
}

/// <summary>
/// Describes one screenshot attempt in a configured capture plan.
/// Inputs are stage, phase labels, artifact label, and sequence information;
/// processing is immutable storage used by ScreenshotProbe event emission.
/// </summary>
internal sealed record ScreenshotCaptureRequest(
    ScreenshotStage Stage,
    string StageLabel,
    string ProbePhaseLabel,
    string ArtifactLabel,
    int Sequence,
    int TotalCount);

/// <summary>
/// Defines a platform screenshot capture implementation.
/// Inputs are an output directory, phase label, and cancellation token;
/// processing writes or skips a screenshot artifact; CaptureAsync returns
/// capture metadata for event emission.
/// </summary>
internal interface IScreenshotCapture
{
    Task<ScreenshotCaptureResult> CaptureAsync(string outputDirectory, string phase, CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures the visible Windows desktop to an uncompressed BMP file.
/// Inputs are output directory, phase label, and cancellation token; processing
/// uses User32/GDI32 APIs and requires no administrator rights; CaptureAsync
/// returns success metadata or a skipped result when capture is unavailable.
/// </summary>
internal sealed class WindowsDesktopScreenshotCapture : IScreenshotCapture
{
    private const int SmCxScreen = 0;
    private const int SmCyScreen = 1;
    private const int SmXVirtualScreen = 76;
    private const int SmYVirtualScreen = 77;
    private const int SmCxVirtualScreen = 78;
    private const int SmCyVirtualScreen = 79;
    private const int DibRgbColors = 0;
    private const uint BiRgb = 0;
    private const uint SrcCopy = 0x00CC0020;

    /// <summary>
    /// Captures a desktop BMP if the current session exposes a screen.
    /// Inputs are output directory, phase, and cancellation token; processing
    /// creates a screenshots subdirectory and writes a BMP; the method returns
    /// capture metadata or a skipped result for unsupported sessions.
    /// </summary>
    public Task<ScreenshotCaptureResult> CaptureAsync(string outputDirectory, string phase, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(ScreenshotCaptureResult.Skipped(
                "Screenshot capture is only implemented on Windows.",
                diagnosticStage: "platform-check"));
        }

        try
        {
            var screenshotDirectory = Path.Combine(outputDirectory, "screenshots");
            Directory.CreateDirectory(screenshotDirectory);
            var safePhase = phase.Replace(' ', '-');
            var path = Path.Combine(screenshotDirectory, $"{safePhase}-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.bmp");
            var (width, height) = CaptureDesktopToBmp(path, cancellationToken);
            return Task.FromResult(ScreenshotCaptureResult.Success(path, width, height));
        }
        catch (ScreenshotCaptureException ex)
        {
            return Task.FromResult(ScreenshotCaptureResult.Skipped(
                ex.Message,
                ex.GetType().FullName ?? ex.GetType().Name,
                ex.Stage,
                ex.Win32Error));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ExternalException or InvalidOperationException)
        {
            return Task.FromResult(ScreenshotCaptureResult.Skipped(
                ex.Message,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "capture"));
        }
    }

    /// <summary>
    /// Captures the virtual screen into a BMP file.
    /// Inputs are an output path and cancellation token; processing performs the
    /// GDI BitBlt and manual BMP serialization; the method returns dimensions.
    /// </summary>
    private static (int Width, int Height) CaptureDesktopToBmp(string path, CancellationToken cancellationToken)
    {
        var x = GetSystemMetrics(SmXVirtualScreen);
        var y = GetSystemMetrics(SmYVirtualScreen);
        var width = GetSystemMetrics(SmCxVirtualScreen);
        var height = GetSystemMetrics(SmCyVirtualScreen);
        if (width <= 0 || height <= 0)
        {
            x = 0;
            y = 0;
            width = GetSystemMetrics(SmCxScreen);
            height = GetSystemMetrics(SmCyScreen);
        }

        if (width <= 0 || height <= 0)
        {
            throw ScreenshotCaptureException.ForLastPInvokeError(
                "GetSystemMetrics",
                "No visible desktop surface is available for screenshot capture.");
        }

        var screenDc = GetDC(IntPtr.Zero);
        if (screenDc == IntPtr.Zero)
        {
            throw ScreenshotCaptureException.ForLastPInvokeError("GetDC", "GetDC returned null for the desktop.");
        }

        var memoryDc = IntPtr.Zero;
        var bitmap = IntPtr.Zero;
        var previousObject = IntPtr.Zero;

        try
        {
            memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == IntPtr.Zero)
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("CreateCompatibleDC", "CreateCompatibleDC failed.");
            }

            bitmap = CreateCompatibleBitmap(screenDc, width, height);
            if (bitmap == IntPtr.Zero)
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("CreateCompatibleBitmap", "CreateCompatibleBitmap failed.");
            }

            previousObject = SelectObject(memoryDc, bitmap);
            if (previousObject == IntPtr.Zero)
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("SelectObject", "SelectObject failed for screenshot bitmap.");
            }

            if (!BitBlt(memoryDc, 0, 0, width, height, screenDc, x, y, SrcCopy))
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("BitBlt", "BitBlt failed while capturing the desktop.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            WriteBitmapPixels(path, screenDc, bitmap, width, height);
            return (width, height);
        }
        finally
        {
            if (previousObject != IntPtr.Zero && memoryDc != IntPtr.Zero)
            {
                _ = SelectObject(memoryDc, previousObject);
            }

            if (bitmap != IntPtr.Zero)
            {
                _ = DeleteObject(bitmap);
            }

            if (memoryDc != IntPtr.Zero)
            {
                _ = DeleteDC(memoryDc);
            }

            _ = ReleaseDC(IntPtr.Zero, screenDc);
        }
    }

    /// <summary>
    /// Serializes captured GDI bitmap pixels as a top-down 32-bit BMP.
    /// Inputs are output path, device context, bitmap handle, width, and height;
    /// processing calls GetDIBits and writes BMP headers and pixels; the method
    /// returns no value.
    /// </summary>
    private static void WriteBitmapPixels(string path, IntPtr deviceContext, IntPtr bitmap, int width, int height)
    {
        var stride = checked(width * 4);
        var imageSize = checked(stride * height);
        var pixels = new byte[imageSize];
        var info = new BitmapInfoHeader
        {
            BiSize = (uint)Marshal.SizeOf<BitmapInfoHeader>(),
            BiWidth = width,
            BiHeight = -height,
            BiPlanes = 1,
            BiBitCount = 32,
            BiCompression = BiRgb,
            BiSizeImage = (uint)imageSize
        };

        var scanLines = GetDIBits(deviceContext, bitmap, 0, (uint)height, pixels, ref info, DibRgbColors);
        if (scanLines == 0)
        {
            throw ScreenshotCaptureException.ForLastPInvokeError("GetDIBits", "GetDIBits failed while reading screenshot pixels.");
        }

        using var stream = File.Create(path);
        using var writer = new BinaryWriter(stream);
        var pixelOffset = 14 + Marshal.SizeOf<BitmapInfoHeader>();
        var fileSize = checked(pixelOffset + imageSize);

        writer.Write((ushort)0x4D42);
        writer.Write((uint)fileSize);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((uint)pixelOffset);
        writer.Write(info.BiSize);
        writer.Write(info.BiWidth);
        writer.Write(info.BiHeight);
        writer.Write(info.BiPlanes);
        writer.Write(info.BiBitCount);
        writer.Write(info.BiCompression);
        writer.Write(info.BiSizeImage);
        writer.Write(info.BiXPelsPerMeter);
        writer.Write(info.BiYPelsPerMeter);
        writer.Write(info.BiClrUsed);
        writer.Write(info.BiClrImportant);
        writer.Write(pixels);
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetDC(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDc);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateCompatibleDC(IntPtr hDc);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteDC(IntPtr hDc);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateCompatibleBitmap(IntPtr hDc, int cx, int cy);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr SelectObject(IntPtr hDc, IntPtr hObject);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool BitBlt(IntPtr hdcDest, int xDest, int yDest, int width, int height, IntPtr hdcSrc, int xSrc, int ySrc, uint rop);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern int GetDIBits(IntPtr hdc, IntPtr hbm, uint start, uint cLines, byte[] lpvBits, ref BitmapInfoHeader lpbmi, int usage);

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfoHeader
    {
        public uint BiSize;
        public int BiWidth;
        public int BiHeight;
        public ushort BiPlanes;
        public ushort BiBitCount;
        public uint BiCompression;
        public uint BiSizeImage;
        public int BiXPelsPerMeter;
        public int BiYPelsPerMeter;
        public uint BiClrUsed;
        public uint BiClrImportant;
    }
}

/// <summary>
/// Carries screenshot capture failure diagnostics from the platform-specific
/// implementation. Inputs are a capture stage, message, and Win32 error code;
/// processing is immutable exception storage; records are converted into
/// screenshot.skipped event Data.
/// </summary>
internal sealed class ScreenshotCaptureException : InvalidOperationException
{
    public ScreenshotCaptureException(string stage, string message, int win32Error)
        : base(message)
    {
        Stage = stage;
        Win32Error = win32Error;
    }

    public string Stage { get; }

    public int Win32Error { get; }

    /// <summary>
    /// Creates a screenshot exception using the last P/Invoke error code.
    /// Inputs are capture stage and message; processing reads the thread-local
    /// P/Invoke error; the method returns a ScreenshotCaptureException.
    /// </summary>
    public static ScreenshotCaptureException ForLastPInvokeError(string stage, string message)
    {
        return new ScreenshotCaptureException(stage, message, Marshal.GetLastPInvokeError());
    }
}

/// <summary>
/// Describes the result of one screenshot attempt.
/// Inputs are capture outcome details; processing is immutable storage; records
/// are returned by IScreenshotCapture and converted into SandboxEvent data.
/// </summary>
internal sealed record ScreenshotCaptureResult(
    bool Captured,
    string? Path,
    string? Reason,
    string? ExceptionType,
    string? DiagnosticStage,
    int? Win32Error,
    int? WidthPixels,
    int? HeightPixels)
{
    /// <summary>
    /// Creates a successful screenshot result.
    /// Inputs are artifact path and dimensions; processing stores success
    /// metadata; the method returns a ScreenshotCaptureResult.
    /// </summary>
    public static ScreenshotCaptureResult Success(string path, int widthPixels, int heightPixels)
    {
        return new ScreenshotCaptureResult(true, path, null, null, null, null, widthPixels, heightPixels);
    }

    /// <summary>
    /// Creates a skipped screenshot result.
    /// Inputs are skip reason, optional exception type, diagnostic stage, and
    /// Win32 error; processing stores diagnostic metadata; the method returns a
    /// ScreenshotCaptureResult.
    /// </summary>
    public static ScreenshotCaptureResult Skipped(
        string reason,
        string? exceptionType = null,
        string? diagnosticStage = null,
        int? win32Error = null)
    {
        return new ScreenshotCaptureResult(false, null, reason, exceptionType, diagnosticStage, win32Error, null, null);
    }
}
