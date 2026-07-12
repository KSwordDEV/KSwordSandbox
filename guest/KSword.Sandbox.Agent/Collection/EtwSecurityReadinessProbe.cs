using System.Globalization;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Emits a bounded ETW/Security readiness map for semantic gaps that are not
/// reliably covered by the R0 callback stream.
/// Inputs are the guest probe phase and run context; processing queries only
/// provider manifests with short timeouts and never starts a live ETW trace;
/// CollectAsync returns non-behavior collection-health diagnostics.
/// </summary>
internal sealed class EtwSecurityReadinessProbe : IGuestProbe
{
    private const string CollectorSource = "etwSecurityReadiness";
    private const string CollectionName = "etw-security-readiness";
    private const string EvidenceRole = "etw-security-readiness-diagnostic";
    private const int MaxManifestSnippetLength = 1024;
    private static readonly TimeSpan ProviderManifestCommandTimeout = TimeSpan.FromSeconds(2);

    private static readonly EtwProviderExpectation[] ProviderExpectations =
    [
        new(
            "security-auditing",
            "Microsoft-Windows-Security-Auditing",
            "Security Event Log audit provider",
            "token-privilege;process-access;process-lifecycle",
            "Security event IDs 4656/4663/4690/4672/4673/4674/4688/4689/4696/4703/4704/4705/4717/4718.",
            "Security 日志 provider 可用于补足 R0 难以解释的令牌、权限、进程访问和进程生命周期语义；实际事件仍取决于审核策略、SACL 和样本强关联。"),
        new(
            "kernel-process",
            "Microsoft-Windows-Kernel-Process",
            "Kernel process/thread/image ETW provider",
            "process-lifecycle;thread-lifecycle;module-load",
            "Manifest readiness for ProcessStart/Stop, ThreadStart/Stop, and ImageLoad/ImageUnload style events; no trace session is started.",
            "Kernel-Process provider 就绪度用于说明线程和模块加载等 R0 v1 未直接产出的 ETW 兜底面；这里只查询 manifest，不启动实时 ETW。"),
        new(
            "threat-intelligence",
            "Microsoft-Windows-Threat-Intelligence",
            "Optional Windows Threat Intelligence ETW provider",
            "process-access;remote-thread;module-tamper",
            "Optional provider; availability and access vary by Windows build and policy. Presence is readiness context only.",
            "Threat-Intelligence provider 若存在，可作为远程线程、进程访问或模块篡改的额外就绪度线索；缺失或拒绝访问不影响样本分析。")
    ];

    private static readonly EtwSecuritySurface[] SurfaceExpectations =
    [
        new(
            "token-privilege",
            "Token and privilege changes",
            "token,privilege",
            "Microsoft-Windows-Security-Auditing",
            "4672,4673,4674,4696,4703,4704,4705,4717,4718",
            "Security audit rows; bounded collection is handled by SecurityEventLogProbe when log access and audit policy allow it.",
            "R0 callbacks can see process/file/registry/network activity but do not reliably explain token assignment, AdjustTokenPrivileges-style state, or user-right policy changes.",
            "Security 日志可补足令牌和权限语义，但 readiness 行本身不是样本行为；只有强 PID/路径关联的实际 security.* 行才可能计数。"),
        new(
            "process-access",
            "Process object access and handle duplication",
            "process-access,handle",
            "Microsoft-Windows-Security-Auditing; Microsoft-Windows-Threat-Intelligence",
            "4656,4663,4690",
            "Security Handle Manipulation auditing plus target process SACL; optional TI provider manifest readiness for richer process access semantics.",
            "R0 v1 does not directly report every OpenProcess/DuplicateHandle/VM access right against another process.",
            "进程句柄访问依赖 Security 审核策略和对象 SACL；本 readiness 只说明兜底面，不代表样本已经访问其它进程。"),
        new(
            "thread-lifecycle",
            "Thread start/stop and remote-thread correlation readiness",
            "thread,remote-thread",
            "Microsoft-Windows-Kernel-Process; Microsoft-Windows-Threat-Intelligence",
            "Kernel-Process ThreadStart/ThreadStop (typical manifest IDs 3/4; version-dependent); TI remote-thread events when present.",
            "Provider manifest readiness only; live ETW trace/session is intentionally disabled.",
            "R0 v1 process callbacks do not provide complete per-thread lifecycle or remote-thread injection context.",
            "线程就绪度只记录 provider/事件族可见性；未开启长时间 ETW trace，因此不会产生线程行为证据。"),
        new(
            "module-load",
            "Module image load/unload readiness",
            "module,image-load,dll",
            "Microsoft-Windows-Kernel-Process",
            "Kernel-Process ImageLoad/ImageUnload (typical manifest IDs 5/6; version-dependent).",
            "Provider manifest readiness only; no image-load ETW subscription is started.",
            "R0 image callbacks may not be available or complete for all module ownership/reporting scenarios.",
            "模块加载 readiness 仅说明 ETW 兜底面存在与否；它不是 DLL 加载行为证据。"),
        new(
            "process-lifecycle",
            "Process create/exit readiness",
            "process,lifecycle",
            "Microsoft-Windows-Security-Auditing; Microsoft-Windows-Kernel-Process",
            "Security 4688/4689; Kernel-Process ProcessStart/ProcessStop (typical manifest IDs 1/2; version-dependent).",
            "SecurityEventLogProbe can read bounded Security rows; Kernel-Process is manifest-readiness only in this agent.",
            "Short-lived processes can be missed by low-rate snapshots, and R0 availability may be degraded.",
            "进程生命周期 readiness 用于解释 Security/ETW 兜底面；最终行为仍以实际 process.*、driver.* 或强关联 security.* 事件为准。")
    ];

    public string ProbeId => "etw-security-readiness";

    /// <summary>
    /// Emits readiness diagnostics during the before-start phase only.
    /// Inputs are phase/context/cancellation; processing performs bounded
    /// provider manifest inspection on Windows and no live tracing; the method
    /// returns readiness rows or a non-Windows skipped diagnostic.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (phase != ProbePhase.BeforeStart)
        {
            return [];
        }

        if (!OperatingSystem.IsWindows())
        {
            return [CreateSkippedEvent(phase, context, "nonWindowsGuest")];
        }

        var manifestTasks = ProviderExpectations
            .Select(expectation => QueryProviderManifestAsync(expectation, cancellationToken))
            .ToArray();
        var providerResults = await Task.WhenAll(manifestTasks).ConfigureAwait(false);
        var providerReadiness = providerResults
            .ToDictionary(static item => item.Provider.Key, static item => item, StringComparer.OrdinalIgnoreCase);

        var events = new List<SandboxEvent>
        {
            CreateSummaryEvent(phase, context, providerResults)
        };

        foreach (var result in providerResults.OrderBy(static item => item.Provider.Key, StringComparer.OrdinalIgnoreCase))
        {
            events.Add(CreateProviderManifestEvent(phase, context, result));
        }

        foreach (var surface in SurfaceExpectations)
        {
            events.Add(CreateSurfaceReadinessEvent(phase, context, surface, providerReadiness));
        }

        return events;
    }

    /// <summary>
    /// Runs a single provider manifest query with a hard timeout.
    /// Inputs are the expected provider and cancellation token; processing uses
    /// wevtutil provider inspection only; the method returns classified status.
    /// </summary>
    private static async Task<EtwProviderManifestResult> QueryProviderManifestAsync(
        EtwProviderExpectation provider,
        CancellationToken cancellationToken)
    {
        var wevtutilPath = ResolveWevtutilPath();
        var arguments = new[]
        {
            "gp",
            provider.ProviderName,
            "/ge:true",
            "/gm:false"
        };
        var result = await BoundedProcessRunner
            .RunAsync(wevtutilPath, arguments, ProviderManifestCommandTimeout, cancellationToken)
            .ConfigureAwait(false);
        return new EtwProviderManifestResult(provider, result, ProviderManifestStatus(result));
    }

    /// <summary>
    /// Resolves wevtutil.exe with a System32 preference and PATH fallback.
    /// </summary>
    private static string ResolveWevtutilPath()
    {
        var systemDirectory = Environment.SystemDirectory;
        if (!string.IsNullOrWhiteSpace(systemDirectory))
        {
            var candidate = Path.Combine(systemDirectory, "wevtutil.exe");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return "wevtutil.exe";
    }

    /// <summary>
    /// Creates the aggregate readiness event.
    /// Inputs are provider results; processing summarizes provider status and
    /// surface maps; the method returns one non-behavior health row.
    /// </summary>
    private static SandboxEvent CreateSummaryEvent(
        ProbePhase phase,
        GuestProbeContext context,
        IReadOnlyList<EtwProviderManifestResult> providerResults)
    {
        var evt = CreateDiagnosticEvent("etw_security.readiness.summary", phase, context, "providerManifestReadiness");
        var queryableProviders = providerResults
            .Where(static item => string.Equals(item.Status, "manifestQueryable", StringComparison.OrdinalIgnoreCase))
            .Select(static item => item.Provider.ProviderName)
            .ToList();
        var unavailableProviders = providerResults
            .Where(static item => !string.Equals(item.Status, "manifestQueryable", StringComparison.OrdinalIgnoreCase))
            .Select(static item => $"{item.Provider.ProviderName}={item.Status}")
            .ToList();

        evt.Data["collectorMode"] = "etw-provider-manifest-readiness-only";
        evt.Data["readinessKind"] = "etw-security-r0-gap-map";
        evt.Data["r0CoverageGap"] = "token/privilege/process-access/thread/module semantics are not reliably available from the R0 callback stream in v1.";
        evt.Data["targetedSemanticGaps"] = "token; privilege; process-access; process-lifecycle; thread; remote-thread; module-load";
        evt.Data["surfaceCount"] = SurfaceExpectations.Length.ToString(CultureInfo.InvariantCulture);
        evt.Data["surfaceKeys"] = JoinDistinct(SurfaceExpectations.Select(static item => item.Key));
        evt.Data["surfaceNames"] = JoinDistinct(SurfaceExpectations.Select(static item => item.Name));
        evt.Data["providerCount"] = providerResults.Count.ToString(CultureInfo.InvariantCulture);
        evt.Data["providerNames"] = JoinDistinct(providerResults.Select(static item => item.Provider.ProviderName));
        evt.Data["providerManifestStatuses"] = JoinDistinct(providerResults.Select(static item => $"{item.Provider.ProviderName}={item.Status}"));
        evt.Data["queryableProviders"] = JoinDistinct(queryableProviders);
        evt.Data["unavailableProviders"] = JoinDistinct(unavailableProviders);
        evt.Data["allProviderManifestsQueryable"] = (unavailableProviders.Count == 0).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["manifestQueryTimeoutMilliseconds"] = ProviderManifestCommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        evt.Data["securityEventIdMap"] = "processAccess=4656/4663/4690; privilege=4672/4673/4674; processLifecycle=4688/4689; token=4696/4703/4704/4705/4717/4718";
        evt.Data["kernelProcessEtwEventMap"] = "ProcessStart/Stop≈1/2; ThreadStart/Stop≈3/4; ImageLoad/Unload≈5/6; exact IDs and templates are manifest/version dependent";
        evt.Data["etwLiveCaptureEnabled"] = "false";
        evt.Data["etwSessionStarted"] = "false";
        evt.Data["etwTraceDurationMilliseconds"] = "0";
        evt.Data["etwReadinessPolicy"] = "manifest-query-only; no long trace; no provider subscription; no VM mutation";
        evt.Data["boundedCollectionSurface"] = "SecurityEventLogProbe may read bounded Security log rows; this probe emits readiness diagnostics only.";
        evt.Data["sampleBehaviorCandidateReason"] = "readiness-only-etw-security-gap-map";
        evt.Data["zhMessage"] = "已记录 ETW/Security 补充面就绪度，用于说明 R0 不可靠覆盖的令牌、权限、进程访问、线程和模块语义可由哪些低风险通道补足。";
        evt.Data["zhHint"] = unavailableProviders.Count == 0
            ? "所有目标 provider manifest 均可查询；这仍只是 readiness，不会启动实时 ETW，也不代表样本行为。实际计数只来自强关联的行为事件。"
            : "部分 provider manifest 不可查询或超时；这只表示兜底面可能降级，不会启动 ETW trace，也不会影响其它 Guest/R0 采集。";

        if (unavailableProviders.Count > 0)
        {
            evt.Data["captureState"] = "partial";
            evt.Data["status"] = "partial";
            evt.Data["reason"] = "providerManifestPartiallyUnavailable";
        }

        return evt;
    }

    /// <summary>
    /// Creates one provider-manifest readiness row.
    /// Inputs are provider query result/context; processing records command
    /// metadata and manifest snippets; the method returns a non-behavior row.
    /// </summary>
    private static SandboxEvent CreateProviderManifestEvent(
        ProbePhase phase,
        GuestProbeContext context,
        EtwProviderManifestResult providerResult)
    {
        var evt = CreateDiagnosticEvent("etw_security.provider_manifest.readiness", phase, context, "providerManifestReadiness");
        evt.Data["collectorMode"] = "etw-provider-manifest-readiness-only";
        evt.Data["providerKey"] = providerResult.Provider.Key;
        evt.Data["providerName"] = providerResult.Provider.ProviderName;
        evt.Data["providerReadinessRole"] = providerResult.Provider.Role;
        evt.Data["providerSurfaceKeys"] = providerResult.Provider.SurfaceKeys;
        evt.Data["providerEventMap"] = providerResult.Provider.EventMap;
        evt.Data["providerManifestStatus"] = providerResult.Status;
        evt.Data["providerManifestQueryable"] = string.Equals(providerResult.Status, "manifestQueryable", StringComparison.OrdinalIgnoreCase)
            .ToString(CultureInfo.InvariantCulture)
            .ToLowerInvariant();
        evt.Data["manifestQueryTimeoutMilliseconds"] = ProviderManifestCommandTimeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture);
        evt.Data["manifestSnippet"] = Truncate(providerResult.Result.StandardOutput, MaxManifestSnippetLength);
        evt.Data["command"] = providerResult.Result.FileName;
        evt.Data["arguments"] = providerResult.Result.Arguments;
        evt.Data["exitCode"] = providerResult.Result.ExitCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
        evt.Data["timedOut"] = providerResult.Result.TimedOut.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        AddIfNotEmpty(evt.Data, "exceptionType", providerResult.Result.ExceptionType);
        AddIfNotEmpty(evt.Data, "message", providerResult.Result.Message);
        AddIfNotEmpty(evt.Data, "stderr", Truncate(providerResult.Result.StandardError, MaxManifestSnippetLength));
        evt.Data["etwLiveCaptureEnabled"] = "false";
        evt.Data["etwSessionStarted"] = "false";
        evt.Data["sampleBehaviorCandidateReason"] = "provider-manifest-readiness-only";
        evt.Data["zhMessage"] = providerResult.Provider.ZhMessage;
        evt.Data["zhHint"] = string.Equals(providerResult.Status, "manifestQueryable", StringComparison.OrdinalIgnoreCase)
            ? "provider manifest 可查询只表示系统知道该 provider；Guest Agent 没有启动 ETW 会话，因此该行不是样本行为。"
            : "provider manifest 查询失败、缺失或超时属于采集就绪度降级；请结合 Security 实际事件、R0 JSONL 和其它 guest 探针判断。";

        if (!string.Equals(providerResult.Status, "manifestQueryable", StringComparison.OrdinalIgnoreCase))
        {
            evt.Data["captureState"] = "partial";
            evt.Data["status"] = "partial";
            evt.Data["reason"] = providerResult.Status;
        }

        return evt;
    }

    /// <summary>
    /// Creates a readiness row for one semantic fallback surface.
    /// Inputs are the surface map and provider statuses; processing projects a
    /// stable event-ID/provider map; the method returns a non-behavior row.
    /// </summary>
    private static SandboxEvent CreateSurfaceReadinessEvent(
        ProbePhase phase,
        GuestProbeContext context,
        EtwSecuritySurface surface,
        IReadOnlyDictionary<string, EtwProviderManifestResult> providerReadiness)
    {
        var evt = CreateDiagnosticEvent("etw_security.surface.readiness", phase, context, "surfaceReadiness");
        var providerNames = SplitList(surface.ProviderNames);
        var providerStatuses = providerNames.Select(providerName => $"{providerName}={ProviderStatusForSurface(providerName, providerReadiness)}").ToList();

        evt.Data["collectorMode"] = "etw-security-surface-readiness-only";
        evt.Data["surfaceKey"] = surface.Key;
        evt.Data["surfaceName"] = surface.Name;
        evt.Data["semanticTags"] = surface.SemanticTags;
        evt.Data["providerNames"] = surface.ProviderNames;
        evt.Data["providerManifestStatuses"] = JoinDistinct(providerStatuses);
        evt.Data["eventIdMap"] = surface.EventIdMap;
        evt.Data["boundedCollectionSurface"] = surface.BoundedCollectionSurface;
        evt.Data["r0CoverageGap"] = surface.R0CoverageGap;
        evt.Data["etwLiveCaptureEnabled"] = "false";
        evt.Data["etwSessionStarted"] = "false";
        evt.Data["sampleBehaviorCandidateReason"] = "surface-readiness-only-not-behavior";
        evt.Data["zhMessage"] = $"已记录 {surface.Name} 的 ETW/Security 兜底面就绪度。";
        evt.Data["zhHint"] = surface.ZhHint;
        return evt;
    }

    private static SandboxEvent CreateSkippedEvent(ProbePhase phase, GuestProbeContext context, string reason)
    {
        var evt = CreateDiagnosticEvent("etw_security.readiness.skipped", phase, context, reason);
        evt.Data["collectorMode"] = "etw-provider-manifest-readiness-only";
        evt.Data["etwLiveCaptureEnabled"] = "false";
        evt.Data["etwSessionStarted"] = "false";
        evt.Data["sampleBehaviorCandidateReason"] = "non-windows-readiness-skip";
        evt.Data["zhMessage"] = "ETW/Security 就绪度仅适用于 Windows guest；当前平台已跳过该通道。";
        evt.Data["zhHint"] = "该 skipped 行是采集健康信息，不代表样本行为，也不会影响其它平台的基础探针。";
        return evt;
    }

    private static SandboxEvent CreateDiagnosticEvent(
        string eventType,
        ProbePhase phase,
        GuestProbeContext context,
        string reason)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = CollectorSource,
            ["collectorSource"] = CollectorSource,
            ["phase"] = ToPhaseLabel(phase),
            ["capturePhase"] = ToPhaseLabel(phase),
            ["collectionName"] = CollectionName,
            ["evidenceRole"] = EvidenceRole,
            ["collectionHealth"] = "true",
            ["nonfatal"] = "true",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["sampleBehaviorCandidate"] = "false",
            ["behaviorCounted"] = "false",
            ["reason"] = reason
        };
        AddIfNotEmpty(data, "samplePath", context.SamplePath);
        AddIfNotEmpty(data, "rootProcessId", context.RootProcessId?.ToString(CultureInfo.InvariantCulture));
        AddIfNotEmpty(data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);

        return new SandboxEvent
        {
            EventType = eventType,
            Source = CollectorSource,
            ProcessName = SafeFileName(context.RootProcessPath ?? context.SamplePath),
            ProcessId = context.RootProcessId,
            Path = context.SamplePath,
            CommandLine = context.RootCommandLine,
            Data = data
        };
    }

    private static string ProviderManifestStatus(BoundedCommandResult result)
    {
        if (result.Succeeded)
        {
            return "manifestQueryable";
        }

        if (result.TimedOut)
        {
            return "manifestQueryTimedOut";
        }

        if (!string.IsNullOrWhiteSpace(result.ExceptionType))
        {
            return "manifestCollectorLaunchFailed";
        }

        var text = $"{result.StandardError}\n{result.StandardOutput}\n{result.Message}";
        if (ContainsAny(text, "not found", "could not find", "cannot find", "找不到指定"))
        {
            return "manifestProviderMissing";
        }

        if (ContainsAny(text, "Access is denied", "拒绝访问", "0x5"))
        {
            return "manifestAccessDenied";
        }

        return "manifestQueryFailed";
    }

    private static string ProviderStatusForSurface(
        string providerName,
        IReadOnlyDictionary<string, EtwProviderManifestResult> providerReadiness)
    {
        var trimmed = providerName.Trim();
        var match = providerReadiness.Values.FirstOrDefault(item =>
            string.Equals(item.Provider.ProviderName, trimmed, StringComparison.OrdinalIgnoreCase));
        return match is null ? "notQueried" : match.Status;
    }

    private static IReadOnlyList<string> SplitList(string value)
    {
        return value
            .Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .ToList();
    }

    private static string JoinDistinct(IEnumerable<string> values)
    {
        return string.Join(
            "; ",
            values
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    private static bool ContainsAny(string value, params string[] needles)
    {
        return needles.Any(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value[..maxLength];
    }

    private static string? SafeFileName(string path)
    {
        try
        {
            return string.IsNullOrWhiteSpace(path) ? null : Path.GetFileName(path);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static string ToPhaseLabel(ProbePhase phase)
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

    private readonly record struct EtwProviderExpectation(
        string Key,
        string ProviderName,
        string Role,
        string SurfaceKeys,
        string EventMap,
        string ZhMessage);

    private readonly record struct EtwSecuritySurface(
        string Key,
        string Name,
        string SemanticTags,
        string ProviderNames,
        string EventIdMap,
        string BoundedCollectionSurface,
        string R0CoverageGap,
        string ZhHint);

    private sealed record EtwProviderManifestResult(
        EtwProviderExpectation Provider,
        BoundedCommandResult Result,
        string Status);
}
