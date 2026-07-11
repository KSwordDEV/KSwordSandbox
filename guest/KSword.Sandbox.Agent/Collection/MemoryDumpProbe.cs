using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Optionally captures best-effort minidumps for the launched sample process
/// and its visible descendants.
/// Inputs are after-start/after-run probe phases, root process ID, and an
/// explicit CLI opt-in flag; processing delegates to a platform capture
/// implementation and reuses the low-privilege process snapshot provider;
/// CollectAsync returns memory_dump.captured, memory_dump.skipped, and
/// memory_dump.sweep events.
/// </summary>
internal sealed class MemoryDumpProbe : IGuestProbe
{
    private readonly IProcessMemoryDumpCapture dumpCapture;
    private readonly IProcessSnapshotProvider snapshotProvider;
    private readonly HashSet<int> capturedProcessIds = [];
    private int? rememberedRootProcessId;

    public MemoryDumpProbe()
        : this(new WindowsMiniDumpCapture(), new ProcessSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a memory dump probe with an injectable capture implementation.
    /// The input is a dump capture service, processing stores it for future
    /// phases, and the constructor returns no value.
    /// </summary>
    public MemoryDumpProbe(IProcessMemoryDumpCapture dumpCapture)
        : this(dumpCapture, new ProcessSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a memory dump probe with injectable capture and process snapshot
    /// providers. Inputs are services used by the probe; processing stores
    /// them for future phases; the constructor returns no value.
    /// </summary>
    public MemoryDumpProbe(
        IProcessMemoryDumpCapture dumpCapture,
        IProcessSnapshotProvider snapshotProvider)
    {
        this.dumpCapture = dumpCapture;
        this.snapshotProvider = snapshotProvider;
    }

    public string ProbeId => "memory-dump";

    /// <summary>
    /// Captures opt-in minidumps while the sample process is running and after
    /// the run has produced descendants.
    /// Inputs are phase, guest context, and cancellation token; processing skips
    /// by default, captures the root process at AfterStart as a safety net, and
    /// sweeps the visible root/child process tree at AfterRun; the method
    /// returns diagnostic events for enabled attempts.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (!context.CaptureMemoryDump)
        {
            return phase == ProbePhase.BeforeStart
                ? [CreateDisabledEvent(context)]
                : [];
        }

        var phaseLabel = ToPhaseLabel(phase);
        if (context.RootProcessId is not null)
        {
            rememberedRootProcessId = context.RootProcessId.Value;
        }

        return phase switch
        {
            ProbePhase.AfterStart => await CaptureRootSafetyNetAsync(context, phaseLabel, cancellationToken).ConfigureAwait(false),
            ProbePhase.AfterRun => await CaptureVisibleProcessTreeAsync(context, phaseLabel, cancellationToken).ConfigureAwait(false),
            _ => []
        };
    }

    /// <summary>
    /// Captures the root process once while it is most likely still alive.
    /// Inputs are context, phase label, and cancellation token; processing
    /// writes one root dump or a non-fatal skipped event; the method returns
    /// memory dump events.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> CaptureRootSafetyNetAsync(
        GuestProbeContext context,
        string phaseLabel,
        CancellationToken cancellationToken)
    {
        if (rememberedRootProcessId is null)
        {
            return
            [
                CreateSkippedEvent(
                    MemoryDumpCaptureResult.Skipped(
                        "Sample root process ID is not available for memory dump capture.",
                        processId: null,
                        diagnosticStage: "root-process"),
                    phaseLabel,
                    target: null,
                    rootProcessId: null,
                    duplicate: false)
            ];
        }

        var target = new MemoryDumpTarget(
            rememberedRootProcessId.Value,
            ParentProcessId: context.RootParentProcessId,
            ProcessName: context.RootProcessName ?? SampleProcessName(context.SamplePath) ?? "root",
            Path: context.RootProcessPath ?? context.SamplePath,
            Depth: 0,
            Lineage: rememberedRootProcessId.Value.ToString(CultureInfo.InvariantCulture),
            IsRoot: true,
            SnapshotKey: string.Empty);
        return [await CaptureTargetAsync(context, phaseLabel, target, rememberedRootProcessId.Value, cancellationToken).ConfigureAwait(false)];
    }

    /// <summary>
    /// Captures root plus visible descendants at the final AfterRun sweep.
    /// Inputs are context, phase label, and cancellation token; processing
    /// snapshots processes, walks the root child tree, skips already captured
    /// PIDs, and writes a summary event; the method returns sweep events.
    /// </summary>
    private async Task<IReadOnlyList<SandboxEvent>> CaptureVisibleProcessTreeAsync(
        GuestProbeContext context,
        string phaseLabel,
        CancellationToken cancellationToken)
    {
        var rootProcessId = context.RootProcessId ?? rememberedRootProcessId;
        if (rootProcessId is null)
        {
            return
            [
                CreateSkippedEvent(
                    MemoryDumpCaptureResult.Skipped(
                        "Sample root process ID is not available for final memory dump sweep.",
                        processId: null,
                        diagnosticStage: "root-process-final"),
                    phaseLabel,
                    target: null,
                    rootProcessId: null,
                    duplicate: false)
            ];
        }

        Dictionary<int, ProcessTreeSnapshot> snapshot;
        try
        {
            snapshot = snapshotProvider.Capture(cancellationToken);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException or UnauthorizedAccessException)
        {
            return
            [
                CreateSkippedEvent(
                    MemoryDumpCaptureResult.Skipped(
                        "Process tree snapshot failed before final memory dump sweep.",
                        rootProcessId.Value,
                        ex.GetType().FullName ?? ex.GetType().Name,
                        diagnosticStage: "process-tree-snapshot"),
                    phaseLabel,
                    target: null,
                    rootProcessId: rootProcessId.Value,
                    duplicate: false)
            ];
        }

        var targets = BuildVisibleDumpTargets(snapshot, rootProcessId.Value);
        var events = new List<SandboxEvent>();
        var alreadyCaptured = 0;
        var attempted = 0;
        var captured = 0;
        var skipped = 0;
        var rootTargetCount = targets.Count(static target => target.IsRoot);
        var childTargetCount = targets.Count(static target => !target.IsRoot);
        var rootAttempted = 0;
        var childAttempted = 0;
        var rootCaptured = 0;
        var childCaptured = 0;
        var rootSkipped = 0;
        var childSkipped = 0;
        var rootAlreadyCaptured = 0;
        var childAlreadyCaptured = 0;

        foreach (var target in targets.OrderBy(target => target.Depth).ThenBy(target => target.ProcessId))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (capturedProcessIds.Contains(target.ProcessId))
            {
                alreadyCaptured++;
                if (target.IsRoot)
                {
                    rootAlreadyCaptured++;
                }
                else
                {
                    childAlreadyCaptured++;
                }

                continue;
            }

            attempted++;
            if (target.IsRoot)
            {
                rootAttempted++;
            }
            else
            {
                childAttempted++;
            }

            var evt = await CaptureTargetAsync(context, phaseLabel, target, rootProcessId.Value, cancellationToken).ConfigureAwait(false);
            if (string.Equals(evt.EventType, "memory_dump.captured", StringComparison.OrdinalIgnoreCase))
            {
                captured++;
                if (target.IsRoot)
                {
                    rootCaptured++;
                }
                else
                {
                    childCaptured++;
                }
            }
            else
            {
                skipped++;
                if (target.IsRoot)
                {
                    rootSkipped++;
                }
                else
                {
                    childSkipped++;
                }
            }

            events.Add(evt);
        }

        if (targets.Count == 0)
        {
            events.Add(CreateSkippedEvent(
                MemoryDumpCaptureResult.Skipped(
                    "No visible root or child processes were available for final memory dump sweep.",
                    rootProcessId.Value,
                    diagnosticStage: "process-tree-empty"),
                phaseLabel,
                target: null,
                rootProcessId: rootProcessId.Value,
                duplicate: false));
        }

        events.Add(CreateSweepEvent(
            phaseLabel,
            rootProcessId.Value,
            targets.Count,
            attempted,
            captured,
            skipped,
            alreadyCaptured,
            rootTargetCount,
            childTargetCount,
            rootAttempted,
            childAttempted,
            rootCaptured,
            childCaptured,
            rootSkipped,
            childSkipped,
            rootAlreadyCaptured,
            childAlreadyCaptured));
        return events;
    }

    /// <summary>
    /// Captures one target process and converts the result into an event.
    /// Inputs are context, phase, target metadata, root PID, and cancellation;
    /// processing delegates to the dump capture service and stores tree
    /// metadata; the method returns one SandboxEvent.
    /// </summary>
    private async Task<SandboxEvent> CaptureTargetAsync(
        GuestProbeContext context,
        string phaseLabel,
        MemoryDumpTarget target,
        int rootProcessId,
        CancellationToken cancellationToken)
    {
        var duplicate = capturedProcessIds.Contains(target.ProcessId);
        var result = duplicate
            ? MemoryDumpCaptureResult.Skipped(
                "Process memory dump was already captured earlier in this run.",
                target.ProcessId,
                diagnosticStage: "duplicate")
            : await dumpCapture.CaptureAsync(context.OutputDirectory, target.ProcessId, phaseLabel, cancellationToken).ConfigureAwait(false);
        if (result.Captured && result.ProcessId is not null)
        {
            capturedProcessIds.Add(result.ProcessId.Value);
        }

        return result.Captured
            ? CreateCapturedEvent(result, phaseLabel, target, rootProcessId, context.OutputDirectory)
            : CreateSkippedEvent(result, phaseLabel, target, rootProcessId, duplicate);
    }

    /// <summary>
    /// Creates a memory_dump.captured event with process-tree metadata.
    /// </summary>
    private SandboxEvent CreateCapturedEvent(
        MemoryDumpCaptureResult result,
        string phaseLabel,
        MemoryDumpTarget? target,
        int? rootProcessId,
        string outputDirectory)
    {
        var evt = CreateBaseEvent("memory_dump.captured", result, phaseLabel, target, rootProcessId);
        evt.Data["captureState"] = "captured";
        evt.Data["status"] = "captured";
        evt.Data["childProcessDumpTarget"] = (target is not null && !target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["nonfatal"] = "false";
        evt.Data["zhMessage"] = "内存转储已采集为可下载证据文件。";
        evt.Data["zhHint"] = "内存转储可能包含敏感内容；请使用 artifactRelativePath 下载，并用 sizeBytes/sha256 校验完整性。";
        if (result.SizeBytes is not null)
        {
            evt.Data["sizeBytes"] = result.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["artifactSizeBytes"] = result.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(result.Path))
        {
            var relativePath = SafeRelativePathForEvent(outputDirectory, result.Path);
            evt.Data["relativePath"] = relativePath;
            AddOptionalData(evt, "artifactRelativePath", relativePath);
            AddArtifactFileEvidence(evt, result.Path);
        }

        return evt;
    }

    /// <summary>
    /// Creates a memory_dump.skipped event with process-tree metadata.
    /// </summary>
    private SandboxEvent CreateSkippedEvent(
        MemoryDumpCaptureResult result,
        string phaseLabel,
        MemoryDumpTarget? target,
        int? rootProcessId,
        bool duplicate)
    {
        var evt = CreateBaseEvent("memory_dump.skipped", result, phaseLabel, target, rootProcessId);
        evt.Data["captureState"] = "skipped";
        evt.Data["status"] = "skipped";
        evt.Data["nonfatal"] = "true";
        evt.Data["duplicate"] = duplicate.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        evt.Data["childProcessDumpTarget"] = (target is not null && !target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
        AddOptionalData(evt, "reason", result.Reason);
        AddOptionalData(evt, "zhMessage", "内存转储采集被跳过；该事件说明证据缺口，不会中断整体分析。");
        AddOptionalData(evt, "zhHint", MemoryDumpReasonZhHint(result.Reason, result.DiagnosticStage, duplicate));
        AddOptionalData(evt, "exceptionType", result.ExceptionType);
        AddOptionalData(evt, "diagnosticStage", result.DiagnosticStage);
        if (IsExitedBeforeDump(result.Reason, result.DiagnosticStage))
        {
            evt.Data["processExited"] = "true";
            evt.Data["exitMissing"] = "true";
            evt.Data["exitedBeforeDump"] = "true";
        }

        if (result.Win32Error is not null)
        {
            evt.Data["win32Error"] = result.Win32Error.Value.ToString(CultureInfo.InvariantCulture);
        }

        return evt;
    }

    /// <summary>
    /// Creates base event fields shared by captured/skipped dump attempts.
    /// </summary>
    private static SandboxEvent CreateBaseEvent(
        string eventType,
        MemoryDumpCaptureResult result,
        string phaseLabel,
        MemoryDumpTarget? target,
        int? rootProcessId)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = result.Path,
            ProcessId = result.ProcessId,
            ProcessName = target?.ProcessName,
            ParentProcessId = target?.ParentProcessId,
            CommandLine = target?.Path,
            Data =
            {
                ["phase"] = phaseLabel,
                ["capturePhase"] = phaseLabel,
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["childProcessDumpEnabled"] = "true",
                ["childProcessDumpMode"] = "visible-root-tree",
                ["dumpType"] = result.DumpType,
                ["evidenceRole"] = "memory-dump",
                ["collectionName"] = "memory-dumps",
                ["expectedRelativePath"] = "memory-dumps/*.dmp"
            }
        };

        if (result.ProcessId is not null)
        {
            evt.Data["processId"] = result.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (rootProcessId is not null)
        {
            evt.Data["rootProcessId"] = rootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data.TryAdd("treeLineage", rootProcessId.Value.ToString(CultureInfo.InvariantCulture));
            evt.Data.TryAdd("treeDepth", "0");
            evt.Data.TryAdd("processRole", "sample-root-context");
        }

        if (target is not null)
        {
            evt.Data["processRole"] = target.IsRoot ? "root" : "child";
            evt.Data["treeDepth"] = target.Depth.ToString(CultureInfo.InvariantCulture);
            evt.Data["treeLineage"] = target.Lineage;
            evt.Data["rootProcessDumpTarget"] = target.IsRoot.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["childProcessDumpTarget"] = (!target.IsRoot).ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            evt.Data["memoryDumpCoverageRole"] = target.IsRoot ? "root" : "child";
            evt.Data["targetProcessName"] = target.ProcessName;
            AddOptionalData(evt, "processName", target.ProcessName);
            AddOptionalData(evt, "targetProcessPath", target.Path);
            AddOptionalData(evt, "processPath", target.Path);
            AddOptionalData(evt, "snapshotKey", target.SnapshotKey);
            if (target.ParentProcessId is not null)
            {
                evt.Data["parentProcessId"] = target.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
            }
        }
        else
        {
            evt.Data["rootProcessDumpTarget"] = rootProcessId is not null ? "true" : "false";
            evt.Data["childProcessDumpTarget"] = "false";
            evt.Data["memoryDumpCoverageRole"] = rootProcessId is null ? "unknown" : "root-context";
        }

        return evt;
    }

    /// <summary>
    /// Creates a memory_dump.sweep summary event for final tree capture.
    /// </summary>
    private static SandboxEvent CreateSweepEvent(
        string phaseLabel,
        int rootProcessId,
        int visibleTargetCount,
        int attemptedCount,
        int capturedCount,
        int skippedCount,
        int alreadyCapturedCount,
        int rootTargetCount,
        int childTargetCount,
        int rootAttemptedCount,
        int childAttemptedCount,
        int rootCapturedCount,
        int childCapturedCount,
        int rootSkippedCount,
        int childSkippedCount,
        int rootAlreadyCapturedCount,
        int childAlreadyCapturedCount)
    {
        return new SandboxEvent
        {
            EventType = "memory_dump.sweep",
            Source = "guest",
            ProcessId = rootProcessId,
            Data =
            {
                ["phase"] = phaseLabel,
                ["capturePhase"] = phaseLabel,
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["childProcessDumpEnabled"] = "true",
                ["childProcessDumpMode"] = "visible-root-tree",
                ["captureState"] = "summary",
                ["status"] = "summary",
                ["summaryEvent"] = "true",
                ["nonfatal"] = "false",
                ["dumpType"] = MemoryDumpCaptureResult.MiniDumpTypeName,
                ["evidenceRole"] = "memory-dump",
                ["collectionName"] = "memory-dumps",
                ["rootProcessId"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["processId"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["processRole"] = "root",
                ["treeDepth"] = "0",
                ["treeLineage"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["visibleTargetCount"] = visibleTargetCount.ToString(CultureInfo.InvariantCulture),
                ["attemptedCount"] = attemptedCount.ToString(CultureInfo.InvariantCulture),
                ["capturedCount"] = capturedCount.ToString(CultureInfo.InvariantCulture),
                ["skippedCount"] = skippedCount.ToString(CultureInfo.InvariantCulture),
                ["alreadyCapturedCount"] = alreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["rootTargetCount"] = rootTargetCount.ToString(CultureInfo.InvariantCulture),
                ["childTargetCount"] = childTargetCount.ToString(CultureInfo.InvariantCulture),
                ["rootAttemptedCount"] = rootAttemptedCount.ToString(CultureInfo.InvariantCulture),
                ["childAttemptedCount"] = childAttemptedCount.ToString(CultureInfo.InvariantCulture),
                ["rootCapturedCount"] = rootCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["childCapturedCount"] = childCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["rootSkippedCount"] = rootSkippedCount.ToString(CultureInfo.InvariantCulture),
                ["childSkippedCount"] = childSkippedCount.ToString(CultureInfo.InvariantCulture),
                ["rootAlreadyCapturedCount"] = rootAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["childAlreadyCapturedCount"] = childAlreadyCapturedCount.ToString(CultureInfo.InvariantCulture),
                ["rootProcessCoverageState"] = DetermineDumpCoverageState(rootTargetCount, rootAttemptedCount, rootCapturedCount, rootSkippedCount, rootAlreadyCapturedCount),
                ["childProcessCoverageState"] = DetermineDumpCoverageState(childTargetCount, childAttemptedCount, childCapturedCount, childSkippedCount, childAlreadyCapturedCount),
                ["memoryDumpCoverageState"] = DetermineDumpCoverageState(visibleTargetCount, attemptedCount, capturedCount, skippedCount, alreadyCapturedCount),
                ["zhMessage"] = "内存转储 sweep 已完成并记录根/子进程覆盖情况。",
                ["zhHint"] = "内存转储为显式 opt-in；启用后会尽力覆盖可见根进程树中的子进程。请结合 rootProcessId/treeLineage、capturedCount、skippedCount 和 alreadyCapturedCount 判断覆盖面。"
            }
        };
    }

    /// <summary>
    /// Creates a single disabled event for the opt-in memory-dump lane.
    /// </summary>
    private static SandboxEvent CreateDisabledEvent(GuestProbeContext context)
    {
        var evt = new SandboxEvent
        {
            EventType = "memory_dump.disabled",
            Source = "guest",
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "before-start",
                ["capturePhase"] = "before-start",
                ["captureEnabled"] = "false",
                ["implemented"] = "true",
                ["childProcessDumpEnabled"] = "false",
                ["childProcessDumpMode"] = "disabled-until-memory-dump-requested",
                ["reason"] = "memoryDumpNotRequested",
                ["zhMessage"] = "内存转储采集未启用。",
                ["zhHint"] = "未启用 --memory-dump/--memory-dumps，Guest Agent 不会生成进程 minidump。",
                ["captureState"] = "disabled",
                ["status"] = "disabled",
                ["nonfatal"] = "true",
                ["dumpType"] = MemoryDumpCaptureResult.MiniDumpTypeName,
                ["evidenceRole"] = "memory-dump",
                ["collectionName"] = "memory-dumps",
                ["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["expectedRelativePath"] = "memory-dumps/*.dmp",
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

        AddOptionalData(evt, "processName", evt.ProcessName);
        return evt;
    }

    private static string MemoryDumpReasonZhHint(string? reason, string? diagnosticStage, bool duplicate)
    {
        if (duplicate)
        {
            return "同一进程已在本次运行中采集过转储，重复目标被跳过。";
        }

        if (string.IsNullOrWhiteSpace(reason))
        {
            return string.Empty;
        }

        if (reason.Contains("only implemented on Windows", StringComparison.OrdinalIgnoreCase))
        {
            return "内存转储当前仅支持 Windows guest；非 Windows 环境会记录 skipped。";
        }

        if (reason.Contains("root process ID is not available", StringComparison.OrdinalIgnoreCase))
        {
            return "样本根进程 ID 不可用，无法定位要转储的进程。";
        }

        if (reason.Contains("exited before memory dump", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(diagnosticStage, "process-state", StringComparison.OrdinalIgnoreCase))
        {
            return "目标进程在转储前已经退出；可尝试延长样本运行时间或更早启用 after-start 转储。";
        }

        if (reason.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(diagnosticStage, "process-lookup", StringComparison.OrdinalIgnoreCase))
        {
            return "无法通过 PID 找到目标进程；它可能已经退出或权限不可见。";
        }

        if (string.Equals(diagnosticStage, "MiniDumpWriteDump", StringComparison.OrdinalIgnoreCase))
        {
            return "MiniDumpWriteDump 调用失败；请检查进程权限、位数匹配、DbgHelp 可用性和输出路径。";
        }

        return "请结合 diagnosticStage、exceptionType/message 和 win32Error 判断是权限、进程状态、DbgHelp 还是输出路径问题。";
    }

    /// <summary>
    /// Summarizes root/child minidump coverage for report cards without
    /// requiring the host to recompute per-target attempt counters.
    /// </summary>
    private static string DetermineDumpCoverageState(
        int targetCount,
        int attemptedCount,
        int capturedCount,
        int skippedCount,
        int alreadyCapturedCount)
    {
        if (targetCount == 0)
        {
            return "no-visible-targets";
        }

        if (capturedCount + alreadyCapturedCount >= targetCount && skippedCount == 0)
        {
            return "covered";
        }

        if (capturedCount > 0 || alreadyCapturedCount > 0)
        {
            return "partial";
        }

        if (attemptedCount > 0 && skippedCount == attemptedCount)
        {
            return "all-skipped";
        }

        return "unknown";
    }

    private static bool IsExitedBeforeDump(string? reason, string? diagnosticStage)
    {
        return (!string.IsNullOrWhiteSpace(reason) &&
                reason.Contains("exited before memory dump", StringComparison.OrdinalIgnoreCase)) ||
            string.Equals(diagnosticStage, "process-state", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(diagnosticStage, "process-lookup", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Builds final dump targets from the visible root process tree.
    /// Inputs are a process snapshot and root PID; processing walks children by
    /// parent PID even when the root has already exited; the method returns
    /// deterministic root/child targets.
    /// </summary>
    private static IReadOnlyList<MemoryDumpTarget> BuildVisibleDumpTargets(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        int rootProcessId)
    {
        var childrenByParent = snapshot.Values
            .Where(process => process.ParentProcessId is not null)
            .GroupBy(process => process.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.OrderBy(process => process.ProcessId).ToList());
        var targets = new List<MemoryDumpTarget>();
        var queue = new Queue<(ProcessTreeSnapshot Process, int Depth, string Lineage, bool IsRoot)>();
        var visited = new HashSet<int>();
        if (snapshot.TryGetValue(rootProcessId, out var root))
        {
            queue.Enqueue((root, 0, root.ProcessId.ToString(CultureInfo.InvariantCulture), true));
        }
        else if (childrenByParent.TryGetValue(rootProcessId, out var orphanedChildren))
        {
            foreach (var child in orphanedChildren)
            {
                queue.Enqueue((child, 1, $"{rootProcessId.ToString(CultureInfo.InvariantCulture)}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}", false));
            }
        }

        while (queue.Count > 0)
        {
            var (process, depth, lineage, isRoot) = queue.Dequeue();
            if (!visited.Add(process.ProcessId))
            {
                continue;
            }

            targets.Add(new MemoryDumpTarget(
                process.ProcessId,
                process.ParentProcessId,
                process.ProcessName,
                process.Path,
                depth,
                lineage,
                isRoot,
                process.Key));

            if (!childrenByParent.TryGetValue(process.ProcessId, out var children))
            {
                continue;
            }

            foreach (var child in children)
            {
                queue.Enqueue((child, depth + 1, $"{lineage}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}", false));
            }
        }

        return targets;
    }

    private static void AddOptionalData(SandboxEvent evt, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evt.Data[key] = value;
        }
    }

    /// <summary>
    /// Reads a display process name for root sample dump attempts.
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
    /// Converts probe phases to stable artifact labels.
    /// Inputs are enum values; processing maps known phases; the method returns
    /// a lowercase label for filenames and event data.
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

    /// <summary>
    /// Computes a display relative path without trusting rooted input.
    /// Inputs are output root and artifact path; processing normalizes
    /// separators and falls back to the original path on malformed input.
    /// </summary>
    private static string SafeRelativePathForEvent(string outputDirectory, string path)
    {
        try
        {
            var outputRoot = Path.GetFullPath(outputDirectory);
            var fullPath = Path.GetFullPath(path);
            var outputRootWithSeparator = Path.EndsInDirectorySeparator(outputRoot)
                ? outputRoot
                : outputRoot + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(outputRootWithSeparator, StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetRelativePath(outputRoot, fullPath).Replace('\\', '/');
            }

            var directory = Path.GetDirectoryName(fullPath);
            return string.IsNullOrWhiteSpace(directory)
                ? Path.GetFileName(fullPath)
                : Path.Combine(Path.GetFileName(directory), Path.GetFileName(fullPath)).Replace('\\', '/');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return path;
        }
    }

    /// <summary>
    /// Adds event-level file size/hash metadata for captured minidumps.
    /// Inputs are an event and dump path; processing reads the file best-effort
    /// with sharing flags; failures are retained as diagnostics.
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
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data["hashStatus"] = "failed";
            evt.Data["artifactHashStatus"] = "failed";
            evt.Data["artifactHashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["artifactHashMessage"] = ex.Message;
        }
    }

    private sealed record MemoryDumpTarget(
        int ProcessId,
        int? ParentProcessId,
        string ProcessName,
        string? Path,
        int Depth,
        string Lineage,
        bool IsRoot,
        string? SnapshotKey);
}

/// <summary>
/// Defines a process memory dump capture implementation.
/// Inputs are output directory, target PID, phase label, and cancellation token;
/// processing writes or skips a dump artifact; CaptureAsync returns capture
/// metadata for event emission.
/// </summary>
internal interface IProcessMemoryDumpCapture
{
    Task<MemoryDumpCaptureResult> CaptureAsync(
        string outputDirectory,
        int processId,
        string phase,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures a Windows MiniDumpNormal file for a target process.
/// Inputs are output directory, PID, and phase; processing uses DbgHelp
/// MiniDumpWriteDump and writes memory-dumps/*.dmp; CaptureAsync returns
/// success metadata or a skipped result when capture is unavailable.
/// </summary>
internal sealed class WindowsMiniDumpCapture : IProcessMemoryDumpCapture
{
    private const string DumpDirectoryName = "memory-dumps";

    /// <summary>
    /// Captures a process minidump if the platform and access rights permit it.
    /// Inputs are output directory, target process ID, phase, and cancellation
    /// token; processing writes one .dmp file; the method returns capture
    /// metadata or a skipped diagnostic.
    /// </summary>
    public Task<MemoryDumpCaptureResult> CaptureAsync(
        string outputDirectory,
        int processId,
        string phase,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                "Memory dump capture is only implemented on Windows.",
                processId,
                diagnosticStage: "platform-check"));
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited)
            {
                return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                    "Sample process exited before memory dump capture.",
                    processId,
                    diagnosticStage: "process-state"));
            }

            var dumpDirectory = Path.Combine(outputDirectory, DumpDirectoryName);
            Directory.CreateDirectory(dumpDirectory);
            var safePhase = phase.Replace(' ', '-');
            var path = Path.Combine(dumpDirectory, $"{safePhase}-pid{processId}-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.dmp");
            var sizeBytes = WriteMiniDump(process, path, cancellationToken);
            return Task.FromResult(MemoryDumpCaptureResult.Success(path, processId, MiniDumpType.MiniDumpNormal.ToString(), sizeBytes));
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                "Sample process was not found for memory dump capture.",
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "process-lookup"));
        }
        catch (MemoryDumpCaptureException ex)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                ex.Message,
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                ex.Stage,
                ex.Win32Error));
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException or NotSupportedException or DllNotFoundException or EntryPointNotFoundException)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                ex.Message,
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "capture"));
        }
    }

    /// <summary>
    /// Writes the minidump file through DbgHelp.
    /// Inputs are a target process, output path, and cancellation token;
    /// processing creates the dump file and removes partial output on failure;
    /// the method returns the final byte length.
    /// </summary>
    private static long WriteMiniDump(Process process, string path, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 4096);
            cancellationToken.ThrowIfCancellationRequested();
            if (!MiniDumpWriteDump(
                    process.Handle,
                    process.Id,
                    stream.SafeFileHandle.DangerousGetHandle(),
                    MiniDumpType.MiniDumpNormal,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw MemoryDumpCaptureException.ForLastPInvokeError(
                    "MiniDumpWriteDump",
                    "MiniDumpWriteDump failed while capturing the sample process.");
            }

            stream.Flush(flushToDisk: true);
            return stream.Length;
        }
        catch
        {
            TryDeleteFile(path);
            throw;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Preserve the original capture failure as the diagnostic event.
        }
    }

    [DllImport("dbghelp.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int processId,
        IntPtr hFile,
        MiniDumpType dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    [Flags]
    private enum MiniDumpType
    {
        MiniDumpNormal = 0x00000000
    }
}

/// <summary>
/// Carries memory dump capture failure diagnostics from the platform-specific
/// implementation. Inputs are a capture stage, message, and Win32 error code;
/// processing is immutable exception storage; records are converted into
/// memory_dump.skipped event Data.
/// </summary>
internal sealed class MemoryDumpCaptureException : InvalidOperationException
{
    public MemoryDumpCaptureException(string stage, string message, int win32Error)
        : base(message)
    {
        Stage = stage;
        Win32Error = win32Error;
    }

    public string Stage { get; }

    public int Win32Error { get; }

    /// <summary>
    /// Creates a memory dump exception using the last P/Invoke error code.
    /// Inputs are capture stage and message; processing reads the thread-local
    /// P/Invoke error; the method returns a MemoryDumpCaptureException.
    /// </summary>
    public static MemoryDumpCaptureException ForLastPInvokeError(string stage, string message)
    {
        return new MemoryDumpCaptureException(stage, message, Marshal.GetLastPInvokeError());
    }
}

/// <summary>
/// Describes the result of one memory dump attempt.
/// Inputs are capture outcome details; processing is immutable storage; records
/// are returned by IProcessMemoryDumpCapture and converted into SandboxEvent
/// data.
/// </summary>
internal sealed record MemoryDumpCaptureResult(
    bool Captured,
    string? Path,
    int? ProcessId,
    string DumpType,
    long? SizeBytes,
    string? Reason,
    string? ExceptionType,
    string? DiagnosticStage,
    int? Win32Error)
{
    /// <summary>
    /// Creates a successful memory dump result.
    /// Inputs are artifact path, process ID, dump type, and byte length;
    /// processing stores success metadata; the method returns a result record.
    /// </summary>
    public static MemoryDumpCaptureResult Success(string path, int processId, string dumpType, long sizeBytes)
    {
        return new MemoryDumpCaptureResult(true, path, processId, dumpType, sizeBytes, null, null, null, null);
    }

    /// <summary>
    /// Creates a skipped memory dump result.
    /// Inputs are skip reason, process ID, optional exception type, diagnostic
    /// stage, and Win32 error; processing stores diagnostic metadata; the method
    /// returns a result record.
    /// </summary>
    public static MemoryDumpCaptureResult Skipped(
        string reason,
        int? processId,
        string? exceptionType = null,
        string? diagnosticStage = null,
        int? win32Error = null)
    {
        return new MemoryDumpCaptureResult(false, null, processId, MiniDumpTypeName, null, reason, exceptionType, diagnosticStage, win32Error);
    }

    public const string MiniDumpTypeName = "MiniDumpNormal";
}
