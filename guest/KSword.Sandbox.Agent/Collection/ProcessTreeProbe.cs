using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;
using Microsoft.Win32;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures process baselines, process deltas, root process tree views, and
/// low-privilege Windows persistence inventory diffs.
/// Inputs are probe phases and a root process id from sample execution;
/// processing snapshots visible processes, services, scheduled tasks, startup
/// items, and environment details; CollectAsync returns normalized events.
/// </summary>
internal sealed class ProcessTreeProbe : IGuestProbe
{
    private const int MaxSystemDiffEventsPerKind = 256;
    private const int MaxProcessTreeSummaryItems = 16;
    private const string ServiceCreatedEventType = "service.created";
    private const string ServiceModifiedEventType = "service.modified";
    private const string ServiceDeletedEventType = "service.deleted";
    private const string ScheduledTaskCreatedEventType = "scheduled_task.created";
    private const string ScheduledTaskModifiedEventType = "scheduled_task.modified";
    private const string ScheduledTaskDeletedEventType = "scheduled_task.deleted";
    private const string StartupItemCreatedEventType = "startup_item.created";
    private const string StartupItemModifiedEventType = "startup_item.modified";
    private const string StartupItemDeletedEventType = "startup_item.deleted";
    private const string RegistryRunCreatedEventType = "registry.run.created";
    private const string RegistryRunModifiedEventType = "registry.run.modified";
    private const string RegistryRunDeletedEventType = "registry.run.deleted";
    private readonly IProcessSnapshotProvider snapshotProvider;
    private readonly ISystemChangeSnapshotProvider systemChangeSnapshotProvider;
    private readonly HashSet<string> emittedNewProcessKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ProcessTreeObservation> observedSnapshots = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> monitoredProcessKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> emittedMissingProcessKeys = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<int, ProcessTreeSnapshot> baselineByPid = [];
    private SystemChangeSnapshot baselineSystemState = SystemChangeSnapshot.Empty;

    public ProcessTreeProbe()
        : this(new ProcessSnapshotProvider(), new SystemChangeSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a process tree probe with an injectable process snapshot provider.
    /// The input is a process snapshot provider, processing pairs it with the
    /// default system-change provider, and the constructor returns no value.
    /// </summary>
    public ProcessTreeProbe(IProcessSnapshotProvider snapshotProvider)
        : this(snapshotProvider, new SystemChangeSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a process tree probe with injectable providers.
    /// Inputs are process and system-change providers; processing stores them
    /// for future phases; the constructor returns no value.
    /// </summary>
    public ProcessTreeProbe(
        IProcessSnapshotProvider snapshotProvider,
        ISystemChangeSnapshotProvider systemChangeSnapshotProvider)
    {
        this.snapshotProvider = snapshotProvider;
        this.systemChangeSnapshotProvider = systemChangeSnapshotProvider;
    }

    public string ProbeId => "process-tree";

    /// <summary>
    /// Collects process, environment, service, scheduled task, and startup
    /// events for one phase.
    /// Inputs are phase, guest context, and cancellation token; processing uses
    /// Toolhelp parent process identifiers when available and bounded Windows
    /// helper commands for inventory diffs; the method returns process,
    /// environment.detail, service, scheduled_task, and startup_item events.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var capturedAtUtc = DateTimeOffset.UtcNow;
        var current = snapshotProvider.Capture(cancellationToken);
        var events = new List<SandboxEvent>();
        if (phase == ProbePhase.BeforeStart)
        {
            emittedNewProcessKeys.Clear();
            observedSnapshots.Clear();
            monitoredProcessKeys.Clear();
            emittedMissingProcessKeys.Clear();
            RememberVisibleProcesses(current, phase, capturedAtUtc);
            baselineByPid = current;
            baselineSystemState = await systemChangeSnapshotProvider.CaptureAsync(cancellationToken).ConfigureAwait(false);

            events.Add(CreateEnvironmentDetailEvent(context));
            events.AddRange(CreateSystemSnapshotEvents(baselineSystemState, phase));
            events.AddRange(WithPhase(baselineSystemState.Diagnostics, phase));
            events.AddRange(CreateCurrentProcessSnapshotEvents(current, phase, context, capturedAtUtc));

            foreach (var process in current.Values.OrderBy(process => process.ProcessId).ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                events.Add(CreateProcessSnapshotEvent(
                    "process.observed",
                    process,
                    phase,
                    rootProcessId: null,
                    depth: null,
                    snapshotLookup: current,
                    capturedAtUtc: capturedAtUtc));
            }
        }
        else if (phase is ProbePhase.AfterStart or ProbePhase.AfterRun)
        {
            TrackRootProcess(context, current, phase, capturedAtUtc);
            RememberVisibleProcesses(current, phase, capturedAtUtc);
            events.AddRange(CreateCurrentProcessSnapshotEvents(current, phase, context, capturedAtUtc));
            var rootTreeMetadata = CreateRootTreeMetadata(current, context);

            foreach (var process in current.Values.OrderBy(process => process.ProcessId).ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (baselineByPid.TryGetValue(process.ProcessId, out var baseline) &&
                    string.Equals(baseline.Key, process.Key, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!emittedNewProcessKeys.Add(process.Key))
                {
                    continue;
                }

                monitoredProcessKeys.Add(process.Key);
                rootTreeMetadata.TryGetValue(process.ProcessId, out var metadata);
                events.Add(CreateProcessSnapshotEvent(
                    "process.new",
                    process,
                    phase,
                    context.RootProcessId,
                    depth: metadata?.Depth,
                    childCount: metadata?.ChildCount,
                    lineage: metadata?.Lineage,
                    snapshotLookup: current,
                    capturedAtUtc: capturedAtUtc));
            }

            ProcessTreeEventResult? treeResult = null;
            if (context.RootProcessId is not null)
            {
                treeResult = CreateTreeEvents(current, context.RootProcessId.Value, phase, context, capturedAtUtc);
                foreach (var processKey in treeResult.ProcessKeys)
                {
                    monitoredProcessKeys.Add(processKey);
                }

                events.AddRange(treeResult.Events);
            }

            var missingSnapshotEvents = CreateMissingProcessSnapshotEvents(current, phase, context, capturedAtUtc);
            events.AddRange(missingSnapshotEvents);
            if (treeResult is not null)
            {
                events.Add(CreateProcessTreeSummaryEvent(treeResult, current, missingSnapshotEvents.Count, phase, context, capturedAtUtc));
            }

            if (phase == ProbePhase.AfterRun)
            {
                var currentSystemState = await systemChangeSnapshotProvider.CaptureAsync(cancellationToken).ConfigureAwait(false);
                events.AddRange(CreateSystemSnapshotEvents(currentSystemState, phase));
                events.AddRange(CreateSystemDiffEvents(baselineSystemState, currentSystemState, phase));
                events.AddRange(WithPhase(currentSystemState.Diagnostics, phase));
            }
        }

        return events;
    }

    /// <summary>
    /// Records visible process snapshots so later phases can mark tracked
    /// processes as missing when they exit before the final process sweep.
    /// </summary>
    private void RememberVisibleProcesses(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        ProbePhase phase,
        DateTimeOffset capturedAtUtc)
    {
        foreach (var process in snapshot.Values)
        {
            RememberProcessObservation(process, phase, capturedAtUtc, visibleInSnapshot: true);
        }
    }

    /// <summary>
    /// Records one process observation while preserving first/last seen phase
    /// and timestamps.
    /// </summary>
    private void RememberProcessObservation(
        ProcessTreeSnapshot process,
        ProbePhase phase,
        DateTimeOffset capturedAtUtc,
        bool visibleInSnapshot)
    {
        if (observedSnapshots.TryGetValue(process.Key, out var existing))
        {
            observedSnapshots[process.Key] = existing with
            {
                Snapshot = MergeProcessSnapshot(existing.Snapshot, process),
                LastSeenPhase = visibleInSnapshot ? phase : existing.LastSeenPhase,
                LastSeenAtUtc = visibleInSnapshot ? capturedAtUtc : existing.LastSeenAtUtc,
                VisibleInAnySnapshot = existing.VisibleInAnySnapshot || visibleInSnapshot
            };
            return;
        }

        observedSnapshots[process.Key] = new ProcessTreeObservation(
            process,
            FirstSeenPhase: phase,
            FirstSeenAtUtc: capturedAtUtc,
            LastSeenPhase: phase,
            LastSeenAtUtc: capturedAtUtc,
            VisibleInAnySnapshot: visibleInSnapshot);
    }

    /// <summary>
    /// Ensures the launched root process is tracked even when it exits before a
    /// probe snapshot can still see the PID.
    /// </summary>
    private void TrackRootProcess(
        GuestProbeContext context,
        Dictionary<int, ProcessTreeSnapshot> current,
        ProbePhase phase,
        DateTimeOffset capturedAtUtc)
    {
        if (context.RootProcessId is null)
        {
            return;
        }

        if (current.TryGetValue(context.RootProcessId.Value, out var visibleRoot) &&
            IsSameRootProcess(visibleRoot, context))
        {
            var enriched = MergeRootContext(visibleRoot, context);
            current[context.RootProcessId.Value] = enriched;
            monitoredProcessKeys.Add(enriched.Key);
            return;
        }

        var knownRoot = observedSnapshots.Values
            .Where(observation => observation.Snapshot.ProcessId == context.RootProcessId.Value)
            .OrderByDescending(observation => observation.LastSeenAtUtc)
            .FirstOrDefault();
        if (knownRoot is not null)
        {
            monitoredProcessKeys.Add(knownRoot.Snapshot.Key);
            return;
        }

        var fallback = CreateRootFallbackSnapshot(context);
        RememberProcessObservation(fallback, phase, capturedAtUtc, visibleInSnapshot: false);
        monitoredProcessKeys.Add(fallback.Key);
    }

    /// <summary>
    /// Creates process.snapshot rows for every currently visible process.
    /// </summary>
    private static IEnumerable<SandboxEvent> CreateCurrentProcessSnapshotEvents(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        ProbePhase phase,
        GuestProbeContext context,
        DateTimeOffset capturedAtUtc)
    {
        var treeMetadata = CreateRootTreeMetadata(snapshot, context);
        foreach (var process in snapshot.Values.OrderBy(process => process.ProcessId).ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase))
        {
            treeMetadata.TryGetValue(process.ProcessId, out var metadata);
            yield return CreateProcessSnapshotEvent(
                "process.snapshot",
                process,
                phase,
                context.RootProcessId,
                metadata?.Depth,
                metadata?.ChildCount,
                metadata?.Lineage,
                snapshot,
                snapshotState: "present",
                capturedAtUtc: capturedAtUtc,
                context: context);
        }
    }

    /// <summary>
    /// Creates process.snapshot rows for tracked root/tree/new processes that
    /// are no longer visible in the current process list.
    /// </summary>
    private IReadOnlyList<SandboxEvent> CreateMissingProcessSnapshotEvents(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> current,
        ProbePhase phase,
        GuestProbeContext context,
        DateTimeOffset capturedAtUtc)
    {
        var currentKeys = current.Values.Select(process => process.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var observedLookup = CreateLatestObservedSnapshotByPid(context);
        var events = new List<SandboxEvent>();
        foreach (var key in monitoredProcessKeys.OrderBy(key => key, StringComparer.OrdinalIgnoreCase))
        {
            if (currentKeys.Contains(key) || !observedSnapshots.TryGetValue(key, out var observation))
            {
                continue;
            }

            if (!emittedMissingProcessKeys.Add(key))
            {
                continue;
            }

            var missingLineage = TryBuildObservedLineage(observation.Snapshot, context.RootProcessId);
            var missingDepth = DepthFromLineage(missingLineage) ??
                (context.RootProcessId == observation.Snapshot.ProcessId ? 0 : (int?)null);
            var evt = CreateProcessSnapshotEvent(
                "process.snapshot",
                observation.Snapshot,
                phase,
                context.RootProcessId,
                depth: missingDepth,
                childCount: null,
                lineage: missingLineage,
                snapshotLookup: observedLookup,
                snapshotState: "missing",
                capturedAtUtc: capturedAtUtc,
                context: context);
            evt.Data["processMissing"] = "true";
            evt.Data["exitMissing"] = "true";
            evt.Data["processExited"] = "true";
            evt.Data["exitedBeforeSnapshot"] = "true";
            evt.Data["captureState"] = "missing";
            evt.Data["status"] = "missing";
            evt.Data["reason"] = "processNotVisibleInCurrentSnapshot";
            evt.Data["missingAtPhase"] = ToPhaseLabel(phase);
            evt.Data["missingAtUtc"] = capturedAtUtc.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["firstSeenPhase"] = ToPhaseLabel(observation.FirstSeenPhase);
            evt.Data["firstSeenUtc"] = observation.FirstSeenAtUtc.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["lastSeenPhase"] = ToPhaseLabel(observation.LastSeenPhase);
            evt.Data["lastSeenUtc"] = observation.LastSeenAtUtc.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["visibleInAnySnapshot"] = observation.VisibleInAnySnapshot.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
            events.Add(evt);
        }

        return events;
    }

    /// <summary>
    /// Builds the richest known pid lookup from observations plus launch
    /// context so missing/exited rows can keep parent, child, and lineage
    /// display metadata even after a process disappears.
    /// </summary>
    private Dictionary<int, ProcessTreeSnapshot> CreateLatestObservedSnapshotByPid(GuestProbeContext context)
    {
        var lookup = observedSnapshots.Values
            .GroupBy(observation => observation.Snapshot.ProcessId)
            .ToDictionary(
                group => group.Key,
                group => group
                    .OrderByDescending(observation => observation.LastSeenAtUtc)
                    .ThenByDescending(observation => observation.Snapshot.StartTimeUtc ?? DateTime.MinValue)
                    .First()
                    .Snapshot);

        if (context.RootProcessId is not null && !lookup.ContainsKey(context.RootProcessId.Value))
        {
            lookup[context.RootProcessId.Value] = CreateRootFallbackSnapshot(context);
        }

        return lookup;
    }

    /// <summary>
    /// Rebuilds a root-relative lineage for a missing process from previously
    /// observed parent links so exited child rows keep stable tree attribution.
    /// </summary>
    private string? TryBuildObservedLineage(ProcessTreeSnapshot process, int? rootProcessId)
    {
        if (rootProcessId is null)
        {
            return null;
        }

        var lineage = new Stack<int>();
        var visited = new HashSet<int>();
        var current = process;
        while (true)
        {
            if (!visited.Add(current.ProcessId))
            {
                return null;
            }

            lineage.Push(current.ProcessId);
            if (current.ProcessId == rootProcessId.Value)
            {
                return string.Join(">", lineage.Select(pid => pid.ToString(CultureInfo.InvariantCulture)));
            }

            if (current.ParentProcessId is null)
            {
                return null;
            }

            var parent = observedSnapshots.Values
                .Where(observation => observation.Snapshot.ProcessId == current.ParentProcessId.Value)
                .OrderByDescending(observation => observation.LastSeenAtUtc)
                .Select(observation => observation.Snapshot)
                .FirstOrDefault();
            if (parent is null)
            {
                return current.ParentProcessId.Value == rootProcessId.Value
                    ? $"{rootProcessId.Value.ToString(CultureInfo.InvariantCulture)}>{string.Join(">", lineage.Select(pid => pid.ToString(CultureInfo.InvariantCulture)))}"
                    : null;
            }

            current = parent;
        }
    }

    private static int? DepthFromLineage(string? lineage)
    {
        return string.IsNullOrWhiteSpace(lineage)
            ? null
            : lineage.Split('>', StringSplitOptions.RemoveEmptyEntries).Length - 1;
    }

    /// <summary>
    /// Creates process.tree rows for the root process and visible descendants.
    /// Inputs are a process snapshot, root process id, probe phase, and launch
    /// context; processing walks parent identifiers breadth-first and keeps
    /// partial child trees when the root already exited; the method returns
    /// deterministic tree rows plus summary metadata.
    /// </summary>
    private static ProcessTreeEventResult CreateTreeEvents(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        int rootProcessId,
        ProbePhase phase,
        GuestProbeContext context,
        DateTimeOffset capturedAtUtc)
    {
        var childrenByParent = snapshot.Values
            .Where(process => process.ParentProcessId is not null)
            .GroupBy(process => process.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.OrderBy(process => process.ProcessId).ToList());

        var events = new List<SandboxEvent>();
        var processKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var rootVisible = snapshot.TryGetValue(rootProcessId, out var root) && IsSameRootProcess(root, context);
        var rootProcess = rootVisible ? root : null;
        if (!rootVisible)
        {
            events.Add(CreateRootUnavailableEvent(rootProcessId, phase, context, capturedAtUtc, root));
        }

        var queue = new Queue<(ProcessTreeSnapshot Process, int Depth, string Lineage)>();
        if (rootVisible && rootProcess is not null)
        {
            queue.Enqueue((rootProcess, 0, rootProcess.ProcessId.ToString(CultureInfo.InvariantCulture)));
        }
        else if (childrenByParent.TryGetValue(rootProcessId, out var orphanedChildren))
        {
            foreach (var child in orphanedChildren)
            {
                queue.Enqueue((child, 1, $"{rootProcessId.ToString(CultureInfo.InvariantCulture)}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}"));
            }
        }

        var visited = new HashSet<int>();
        var maxDepth = 0;
        while (queue.Count != 0)
        {
            var (process, depth, lineage) = queue.Dequeue();
            if (!visited.Add(process.ProcessId))
            {
                continue;
            }

            maxDepth = Math.Max(maxDepth, depth);
            processKeys.Add(process.Key);
            var childCount = childrenByParent.TryGetValue(process.ProcessId, out var children) ? children.Count : 0;
            events.Add(CreateProcessSnapshotEvent(
                "process.tree",
                process,
                phase,
                rootProcessId,
                depth,
                childCount,
                lineage,
                snapshot,
                snapshotState: "present",
                capturedAtUtc: capturedAtUtc,
                context: context));

            if (childCount == 0 || children is null)
            {
                continue;
            }

            foreach (var child in children)
            {
                queue.Enqueue((child, depth + 1, $"{lineage}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}"));
            }
        }

        var directChildCount = childrenByParent.TryGetValue(rootProcessId, out var directChildren) ? directChildren.Count : 0;
        return new ProcessTreeEventResult(
            events,
            processKeys.ToList(),
            RootVisible: rootVisible,
            RootProcess: rootProcess,
            RootProcessId: rootProcessId,
            VisibleProcessCount: visited.Count,
            DirectChildProcessCount: directChildCount,
            MaxDepth: maxDepth,
            OrphanedChildProcessCount: rootVisible ? 0 : directChildCount);
    }

    /// <summary>
    /// Creates a normalized process event from one snapshot.
    /// Inputs are event type, snapshot data, phase, optional root process id,
    /// tree depth, child count, and lineage; processing copies stable metadata
    /// into common fields and Data; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateProcessSnapshotEvent(
        string eventType,
        ProcessTreeSnapshot process,
        ProbePhase phase,
        int? rootProcessId,
        int? depth,
        int? childCount = null,
        string? lineage = null,
        IReadOnlyDictionary<int, ProcessTreeSnapshot>? snapshotLookup = null,
        string snapshotState = "present",
        DateTimeOffset? capturedAtUtc = null,
        GuestProbeContext? context = null)
    {
        var parent = process.ParentProcessId is not null && snapshotLookup is not null && snapshotLookup.TryGetValue(process.ParentProcessId.Value, out var parentProcess)
            ? parentProcess
            : null;
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessName = process.ProcessName,
            ProcessId = process.ProcessId,
            ParentProcessId = process.ParentProcessId,
            Path = process.Path,
            CommandLine = process.CommandLine,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["snapshotKey"] = process.Key,
                ["processSnapshotKey"] = process.Key,
                ["processId"] = process.ProcessId.ToString(CultureInfo.InvariantCulture),
                ["processName"] = process.ProcessName,
                ["snapshotState"] = snapshotState,
                ["captureState"] = snapshotState,
                ["status"] = snapshotState,
                ["processMissing"] = string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["exitMissing"] = string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["processExited"] = string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["exitedBeforeSnapshot"] = string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["zhMessage"] = string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase)
                    ? "进程此前被跟踪，但当前快照中已不可见，可能已经退出。"
                    : "进程快照行已采集。",
                ["zhHint"] = "请使用 rootProcessId、parentProcessId、treeDepth 和 treeLineage 还原样本进程关系。"
            }
        };

        if (capturedAtUtc is not null)
        {
            evt.Data["snapshotTimeUtc"] = capturedAtUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["capturedAtUtc"] = capturedAtUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (process.StartTimeUtc is not null)
        {
            evt.Data["startTimeUtc"] = process.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["processStartTimeUtc"] = process.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (process.ParentProcessId is not null)
        {
            evt.Data["parentProcessId"] = process.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "imagePath", process.Path);
        AddIfNotEmpty(evt.Data, "processImagePath", process.Path);
        AddIfNotEmpty(evt.Data, "commandLine", process.CommandLine);
        AddIfNotEmpty(evt.Data, "toolhelpImageName", process.ToolhelpImageName);
        AddIfNotEmpty(evt.Data, "parentSnapshotKey", parent?.Key);
        AddIfNotEmpty(evt.Data, "parentProcessSnapshotKey", parent?.Key);
        AddIfNotEmpty(evt.Data, "parentProcessName", parent?.ProcessName);
        AddIfNotEmpty(evt.Data, "parentImagePath", parent?.Path);
        AddIfNotEmpty(evt.Data, "parentCommandLine", parent?.CommandLine);
        if (parent?.StartTimeUtc is not null)
        {
            evt.Data["parentStartTimeUtc"] = parent.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["parentProcessStartTimeUtc"] = parent.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (context is not null &&
            process.ParentProcessId == context.RootParentProcessId &&
            context.RootProcessId == process.ProcessId &&
            !string.IsNullOrWhiteSpace(context.RootCommandLine))
        {
            evt.Data["launchedByAgent"] = "true";
        }

        if (process.SessionId is not null)
        {
            evt.Data["sessionId"] = process.SessionId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (process.ThreadCount is not null)
        {
            evt.Data["threadCount"] = process.ThreadCount.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (process.BasePriority is not null)
        {
            evt.Data["basePriority"] = process.BasePriority.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (rootProcessId is not null)
        {
            evt.Data["rootProcessId"] = rootProcessId.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["processRole"] = process.ProcessId == rootProcessId.Value
                ? "root"
                : depth is not null
                    ? "child"
                    : "process-snapshot";
        }
        else
        {
            evt.Data["processRole"] = "process-snapshot";
        }

        if (depth is not null)
        {
            evt.Data["treeDepth"] = depth.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (childCount is not null)
        {
            evt.Data["childProcessCount"] = childCount.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (string.IsNullOrWhiteSpace(lineage) &&
            rootProcessId is not null &&
            process.ProcessId == rootProcessId.Value)
        {
            lineage = rootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "treeLineage", lineage);
        AddProcessTreeSemanticFields(
            evt,
            eventType,
            process,
            rootProcessId,
            depth,
            childCount,
            lineage,
            snapshotLookup,
            snapshotState,
            context);
        return evt;
    }

    /// <summary>
    /// Adds process-tree completeness fields that reports can copy without
    /// recomputing relationships: stable lineage keys, role markers, direct
    /// child summaries, descendant counts, and Chinese operator text.
    /// </summary>
    private static void AddProcessTreeSemanticFields(
        SandboxEvent evt,
        string eventType,
        ProcessTreeSnapshot process,
        int? rootProcessId,
        int? depth,
        int? childCount,
        string? lineage,
        IReadOnlyDictionary<int, ProcessTreeSnapshot>? snapshotLookup,
        string snapshotState,
        GuestProbeContext? context)
    {
        var isMissing = string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase);
        var isRoot = rootProcessId is not null && process.ProcessId == rootProcessId.Value;
        var isTreeNode = string.Equals(eventType, "process.tree", StringComparison.OrdinalIgnoreCase) ||
            depth is not null ||
            !string.IsNullOrWhiteSpace(lineage);
        var isChild = rootProcessId is not null && !isRoot && isTreeNode;

        evt.Data["isRootProcess"] = ToLowerInvariantString(isRoot);
        evt.Data["isChildProcess"] = ToLowerInvariantString(isChild);
        evt.Data["isDescendantOfRoot"] = ToLowerInvariantString(isChild);
        evt.Data["processTreeNode"] = ToLowerInvariantString(isTreeNode);
        evt.Data["treeNodeState"] = snapshotState;
        evt.Data["treeScope"] = rootProcessId is null
            ? "global-snapshot"
            : isTreeNode
                ? "sample-root-tree"
                : "sample-root-context";
        evt.Data["lineageStable"] = ToLowerInvariantString(!string.IsNullOrWhiteSpace(lineage));
        evt.Data["lineageIncludesRoot"] = ToLowerInvariantString(rootProcessId is not null &&
            !string.IsNullOrWhiteSpace(lineage) &&
            LineageContainsPid(lineage, rootProcessId.Value));

        if (snapshotLookup is not null && rootProcessId is not null)
        {
            var rootVisible = snapshotLookup.TryGetValue(rootProcessId.Value, out var visibleRoot) &&
                (context is null || IsSameRootProcess(visibleRoot, context));
            evt.Data["rootVisibleInSnapshot"] = ToLowerInvariantString(rootVisible);
        }

        AddLineagePresentationFields(evt, process, rootProcessId, lineage, snapshotLookup, context);
        AddChildSummaryFields(evt, process, childCount, snapshotLookup);

        var roleZh = isRoot ? "根进程" : isChild ? "子进程" : "进程快照";
        evt.Data["zhProcessRole"] = roleZh;
        evt.Data["zhMessage"] = ProcessSnapshotZhMessage(eventType, snapshotState, isRoot, isChild);
        evt.Data["zhHint"] = ProcessSnapshotZhHint(snapshotState, isTreeNode, isMissing);

        var copyText = CreateProcessTreeCopyText(evt, process, rootProcessId, lineage);
        evt.Data["processTreeCopyText"] = copyText;
        evt.Data["copyText"] = copyText;
    }

    /// <summary>
    /// Adds human-readable and stable-key lineage variants from a pid lineage.
    /// </summary>
    private static void AddLineagePresentationFields(
        SandboxEvent evt,
        ProcessTreeSnapshot process,
        int? rootProcessId,
        string? lineage,
        IReadOnlyDictionary<int, ProcessTreeSnapshot>? snapshotLookup,
        GuestProbeContext? context)
    {
        var lineagePids = ParseLineagePids(lineage);
        if (lineagePids.Count == 0 && rootProcessId is not null && process.ProcessId == rootProcessId.Value)
        {
            lineagePids.Add(process.ProcessId);
        }

        if (lineagePids.Count == 0)
        {
            return;
        }

        var names = new List<string>(lineagePids.Count);
        var keys = new List<string>(lineagePids.Count);
        foreach (var pid in lineagePids)
        {
            names.Add(ProcessLineageDisplayName(pid, snapshotLookup, context));
            keys.Add(ProcessLineageStableKey(pid, snapshotLookup, context));
        }

        evt.Data["treeLineageDisplay"] = string.Join(" > ", names);
        evt.Data["treeLineageNames"] = string.Join(" > ", names);
        evt.Data["treeLineageProcessKeys"] = string.Join(" > ", keys);
        evt.Data["treeLineageStableKeys"] = string.Join(" > ", keys);
        evt.Data["treeLineageCopy"] = $"{evt.Data.GetValueOrDefault("treeLineage", string.Join(">", lineagePids.Select(pid => pid.ToString(CultureInfo.InvariantCulture))))} | {string.Join(" > ", names)}";
    }

    /// <summary>
    /// Adds direct-child and descendant summaries for report process-tree cards.
    /// </summary>
    private static void AddChildSummaryFields(
        SandboxEvent evt,
        ProcessTreeSnapshot process,
        int? childCount,
        IReadOnlyDictionary<int, ProcessTreeSnapshot>? snapshotLookup)
    {
        if (snapshotLookup is null)
        {
            if (childCount is not null)
            {
                evt.Data.TryAdd("directChildProcessCount", childCount.Value.ToString(CultureInfo.InvariantCulture));
            }

            return;
        }

        var directChildren = snapshotLookup.Values
            .Where(candidate => candidate.ParentProcessId == process.ProcessId)
            .OrderBy(candidate => candidate.ProcessId)
            .ThenBy(candidate => candidate.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var directChildCount = childCount ?? directChildren.Count;
        evt.Data["directChildProcessCount"] = directChildCount.ToString(CultureInfo.InvariantCulture);
        evt.Data["childProcessCount"] = directChildCount.ToString(CultureInfo.InvariantCulture);

        if (directChildren.Count == 0)
        {
            evt.Data["childSummary"] = "none";
            evt.Data["childSummaryTruncated"] = "false";
            evt.Data["descendantProcessCount"] = "0";
            return;
        }

        var limited = directChildren.Take(MaxProcessTreeSummaryItems).ToList();
        var childNames = limited.Select(ProcessDisplayName).ToList();
        evt.Data["childProcessIds"] = string.Join(",", limited.Select(child => child.ProcessId.ToString(CultureInfo.InvariantCulture)));
        evt.Data["childProcessNames"] = string.Join(" > ", childNames);
        evt.Data["childProcessSnapshotKeys"] = string.Join(" > ", limited.Select(child => child.Key));
        evt.Data["childSummary"] = string.Join("; ", limited.Select(child => $"{child.ProcessName}({child.ProcessId.ToString(CultureInfo.InvariantCulture)})"));
        evt.Data["childSummaryTruncated"] = ToLowerInvariantString(directChildren.Count > MaxProcessTreeSummaryItems);
        evt.Data["descendantProcessCount"] = CountDescendants(process.ProcessId, snapshotLookup).ToString(CultureInfo.InvariantCulture);
    }

    private static List<int> ParseLineagePids(string? lineage)
    {
        if (string.IsNullOrWhiteSpace(lineage))
        {
            return [];
        }

        var pids = new List<int>();
        foreach (var token in lineage.Split('>', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid))
            {
                pids.Add(pid);
            }
        }

        return pids;
    }

    private static bool LineageContainsPid(string lineage, int pid)
    {
        return ParseLineagePids(lineage).Contains(pid);
    }

    private static string ProcessLineageDisplayName(
        int pid,
        IReadOnlyDictionary<int, ProcessTreeSnapshot>? snapshotLookup,
        GuestProbeContext? context)
    {
        if (snapshotLookup is not null && snapshotLookup.TryGetValue(pid, out var snapshot))
        {
            return ProcessDisplayName(snapshot);
        }

        if (context?.RootProcessId == pid)
        {
            var rootName = context.RootProcessName ??
                SafeProcessNameFromPath(context.RootProcessPath ?? context.SamplePath) ??
                "root";
            return $"{rootName}({pid.ToString(CultureInfo.InvariantCulture)})";
        }

        return $"pid:{pid.ToString(CultureInfo.InvariantCulture)}";
    }

    private static string ProcessLineageStableKey(
        int pid,
        IReadOnlyDictionary<int, ProcessTreeSnapshot>? snapshotLookup,
        GuestProbeContext? context)
    {
        if (snapshotLookup is not null && snapshotLookup.TryGetValue(pid, out var snapshot))
        {
            return snapshot.Key;
        }

        if (context?.RootProcessId == pid)
        {
            return CreateRootFallbackSnapshot(context).Key;
        }

        return $"pid:{pid.ToString(CultureInfo.InvariantCulture)}";
    }

    private static string ProcessDisplayName(ProcessTreeSnapshot process)
    {
        return $"{process.ProcessName}({process.ProcessId.ToString(CultureInfo.InvariantCulture)})";
    }

    private static int CountDescendants(
        int processId,
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshotLookup)
    {
        var childrenByParent = snapshotLookup.Values
            .Where(process => process.ParentProcessId is not null)
            .GroupBy(process => process.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.ToList());
        var visited = new HashSet<int>();
        var queue = new Queue<int>();
        if (childrenByParent.TryGetValue(processId, out var children))
        {
            foreach (var child in children)
            {
                queue.Enqueue(child.ProcessId);
            }
        }

        while (queue.Count != 0)
        {
            var childPid = queue.Dequeue();
            if (!visited.Add(childPid))
            {
                continue;
            }

            if (!childrenByParent.TryGetValue(childPid, out var grandchildren))
            {
                continue;
            }

            foreach (var grandchild in grandchildren)
            {
                queue.Enqueue(grandchild.ProcessId);
            }
        }

        return visited.Count;
    }

    private static string CreateProcessTreeCopyText(
        SandboxEvent evt,
        ProcessTreeSnapshot process,
        int? rootProcessId,
        string? lineage)
    {
        var parts = new List<string>
        {
            $"event={evt.EventType}",
            $"pid={process.ProcessId.ToString(CultureInfo.InvariantCulture)}",
            $"name={process.ProcessName}"
        };
        if (process.ParentProcessId is not null)
        {
            parts.Add($"ppid={process.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture)}");
        }

        if (rootProcessId is not null)
        {
            parts.Add($"root={rootProcessId.Value.ToString(CultureInfo.InvariantCulture)}");
        }

        AddCopyPart(parts, "role", evt.Data.GetValueOrDefault("processRole"));
        AddCopyPart(parts, "state", evt.Data.GetValueOrDefault("snapshotState"));
        AddCopyPart(parts, "depth", evt.Data.GetValueOrDefault("treeDepth"));
        AddCopyPart(parts, "lineage", lineage);
        AddCopyPart(parts, "lineageDisplay", evt.Data.GetValueOrDefault("treeLineageDisplay"));
        AddCopyPart(parts, "children", evt.Data.GetValueOrDefault("childSummary"));
        return string.Join(" | ", parts);
    }

    private static void AddCopyPart(List<string> parts, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            parts.Add($"{name}={value}");
        }
    }

    private static string ToLowerInvariantString(bool value)
    {
        return value.ToString(CultureInfo.InvariantCulture).ToLowerInvariant();
    }

    /// <summary>
    /// Creates a stable root-missing diagnostic while preserving known launch
    /// metadata so reports can still render an exited root.
    /// </summary>
    private static SandboxEvent CreateRootUnavailableEvent(
        int rootProcessId,
        ProbePhase phase,
        GuestProbeContext context,
        DateTimeOffset capturedAtUtc,
        ProcessTreeSnapshot? visiblePidReuse)
    {
        var evt = new SandboxEvent
        {
            EventType = "process.tree_unavailable",
            Source = "guest",
            ProcessName = context.RootProcessName,
            ProcessId = rootProcessId,
            ParentProcessId = context.RootParentProcessId,
            Path = context.RootProcessPath ?? context.SamplePath,
            CommandLine = context.RootCommandLine,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["processId"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["rootProcessId"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["snapshotTimeUtc"] = capturedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["capturedAtUtc"] = capturedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["rootVisible"] = "false",
                ["rootMissing"] = "true",
                ["rootExited"] = "true",
                ["processMissing"] = "true",
                ["exitMissing"] = "true",
                ["processExited"] = "true",
                ["exitedBeforeSnapshot"] = "true",
                ["snapshotState"] = "missing",
                ["captureState"] = "missing",
                ["status"] = "missing",
                ["processRole"] = "root",
                ["treeDepth"] = "0",
                ["treeLineage"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                ["reason"] = "Root process was not visible in the current process snapshot.",
                ["zhMessage"] = "样本根进程在当前进程快照中不可见，可能已经退出。",
                ["zhHint"] = "该事件保留 rootProcessId/treeLineage 和已知启动信息；请结合 process.exit、process.timeout 或 missingAtUtc 判断退出时机。"
            }
        };

        if (context.RootParentProcessId is not null)
        {
            evt.Data["parentProcessId"] = context.RootParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (context.RootProcessStartTimeUtc is not null)
        {
            evt.Data["startTimeUtc"] = context.RootProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["processStartTimeUtc"] = context.RootProcessStartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "rootProcessName", context.RootProcessName);
        AddIfNotEmpty(evt.Data, "rootImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "imagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "processImagePath", context.RootProcessPath ?? context.SamplePath);
        AddIfNotEmpty(evt.Data, "rootCommandLine", context.RootCommandLine);
        AddIfNotEmpty(evt.Data, "commandLine", context.RootCommandLine);
        if (visiblePidReuse is not null)
        {
            evt.Data["pidReuseSuspected"] = "true";
            evt.Data["visiblePidSnapshotKey"] = visiblePidReuse.Key;
            AddIfNotEmpty(evt.Data, "visiblePidProcessName", visiblePidReuse.ProcessName);
            AddIfNotEmpty(evt.Data, "visiblePidImagePath", visiblePidReuse.Path);
            if (visiblePidReuse.StartTimeUtc is not null)
            {
                evt.Data["visiblePidStartTimeUtc"] = visiblePidReuse.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            }
        }

        var rootSnapshot = CreateRootFallbackSnapshot(context);
        AddLineagePresentationFields(
            evt,
            rootSnapshot,
            rootProcessId,
            rootProcessId.ToString(CultureInfo.InvariantCulture),
            snapshotLookup: null,
            context);
        evt.Data["isRootProcess"] = "true";
        evt.Data["isChildProcess"] = "false";
        evt.Data["isDescendantOfRoot"] = "false";
        evt.Data["processTreeNode"] = "true";
        evt.Data["treeNodeState"] = "missing";
        evt.Data["treeScope"] = "sample-root-tree";
        evt.Data["lineageStable"] = "true";
        evt.Data["lineageIncludesRoot"] = "true";
        evt.Data["childSummary"] = "none";
        evt.Data["childSummaryTruncated"] = "false";
        evt.Data["directChildProcessCount"] = "0";
        evt.Data["descendantProcessCount"] = "0";
        var copyText = CreateProcessTreeCopyText(
            evt,
            rootSnapshot,
            rootProcessId,
            rootProcessId.ToString(CultureInfo.InvariantCulture));
        evt.Data["processTreeCopyText"] = copyText;
        evt.Data["copyText"] = copyText;
        return evt;
    }

    /// <summary>
    /// Creates a compact process.tree.summary event for report process-tree
    /// sections without changing the row-level process.tree contract.
    /// </summary>
    private SandboxEvent CreateProcessTreeSummaryEvent(
        ProcessTreeEventResult tree,
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        int missingProcessCount,
        ProbePhase phase,
        GuestProbeContext context,
        DateTimeOffset capturedAtUtc)
    {
        var root = tree.RootProcess ?? observedSnapshots.Values
            .Where(observation => observation.Snapshot.ProcessId == tree.RootProcessId)
            .OrderByDescending(observation => observation.LastSeenAtUtc)
            .Select(observation => observation.Snapshot)
            .FirstOrDefault();
        var evt = new SandboxEvent
        {
            EventType = "process.tree.summary",
            Source = "guest",
            ProcessName = root?.ProcessName ?? context.RootProcessName,
            ProcessId = tree.RootProcessId,
            ParentProcessId = root?.ParentProcessId ?? context.RootParentProcessId,
            Path = root?.Path ?? context.RootProcessPath ?? context.SamplePath,
            CommandLine = root?.CommandLine ?? context.RootCommandLine,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["snapshotTimeUtc"] = capturedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["capturedAtUtc"] = capturedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["rootProcessId"] = tree.RootProcessId.ToString(CultureInfo.InvariantCulture),
                ["processId"] = tree.RootProcessId.ToString(CultureInfo.InvariantCulture),
                ["processRole"] = "root",
                ["treeDepth"] = "0",
                ["treeLineage"] = tree.RootProcessId.ToString(CultureInfo.InvariantCulture),
                ["rootVisible"] = tree.RootVisible.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["rootMissing"] = (!tree.RootVisible).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["rootExited"] = (!tree.RootVisible).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["processMissing"] = (!tree.RootVisible).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["exitMissing"] = (!tree.RootVisible).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["processExited"] = (!tree.RootVisible).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["visibleProcessCount"] = tree.VisibleProcessCount.ToString(CultureInfo.InvariantCulture),
                ["treeProcessCount"] = tree.VisibleProcessCount.ToString(CultureInfo.InvariantCulture),
                ["snapshotProcessCount"] = snapshot.Count.ToString(CultureInfo.InvariantCulture),
                ["directChildProcessCount"] = tree.DirectChildProcessCount.ToString(CultureInfo.InvariantCulture),
                ["childProcessCount"] = tree.DirectChildProcessCount.ToString(CultureInfo.InvariantCulture),
                ["maxTreeDepth"] = tree.MaxDepth.ToString(CultureInfo.InvariantCulture),
                ["orphanedChildProcessCount"] = tree.OrphanedChildProcessCount.ToString(CultureInfo.InvariantCulture),
                ["missingProcessCount"] = missingProcessCount.ToString(CultureInfo.InvariantCulture),
                ["trackedProcessCount"] = monitoredProcessKeys.Count.ToString(CultureInfo.InvariantCulture),
                ["summaryEvent"] = "true",
                ["captureState"] = tree.RootVisible ? "complete" : "partial",
                ["status"] = tree.RootVisible ? "complete" : "partial",
                ["zhMessage"] = tree.RootVisible
                    ? "进程树快照已采集，根进程仍可见。"
                    : "进程树快照已采集，但根进程当前不可见，可能已经退出。",
                ["zhHint"] = "请使用 rootProcessId/treeLineage 关联 process.tree、process.snapshot missing 行和最终 process.exit 事件。"
            }
        };

        if (evt.ParentProcessId is not null)
        {
            evt.Data["parentProcessId"] = evt.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "rootProcessName", evt.ProcessName);
        AddIfNotEmpty(evt.Data, "rootImagePath", evt.Path);
        AddIfNotEmpty(evt.Data, "imagePath", evt.Path);
        AddIfNotEmpty(evt.Data, "processImagePath", evt.Path);
        AddIfNotEmpty(evt.Data, "rootCommandLine", evt.CommandLine);
        AddIfNotEmpty(evt.Data, "commandLine", evt.CommandLine);
        AddIfNotEmpty(evt.Data, "rootSnapshotKey", root?.Key);
        if (root?.StartTimeUtc is not null)
        {
            evt.Data["startTimeUtc"] = root.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
            evt.Data["processStartTimeUtc"] = root.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        var rootSnapshot = root ?? CreateRootFallbackSnapshot(context);
        AddLineagePresentationFields(
            evt,
            rootSnapshot,
            tree.RootProcessId,
            tree.RootProcessId.ToString(CultureInfo.InvariantCulture),
            snapshot,
            context);
        AddChildSummaryFields(
            evt,
            rootSnapshot,
            tree.DirectChildProcessCount,
            snapshot);
        AddObservedRootChildSummaryFields(evt, tree.RootProcessId, context);
        evt.Data["isRootProcess"] = "true";
        evt.Data["isChildProcess"] = "false";
        evt.Data["isDescendantOfRoot"] = "false";
        evt.Data["processTreeNode"] = "true";
        evt.Data["treeNodeState"] = tree.RootVisible ? "present" : "missing";
        evt.Data["treeScope"] = "sample-root-tree";
        evt.Data["lineageStable"] = "true";
        evt.Data["lineageIncludesRoot"] = "true";
        evt.Data["zhProcessRole"] = "根进程";
        var copyText = CreateProcessTreeCopyText(
            evt,
            rootSnapshot,
            tree.RootProcessId,
            tree.RootProcessId.ToString(CultureInfo.InvariantCulture));
        evt.Data["processTreeCopyText"] = copyText;
        evt.Data["copyText"] = copyText;
        return evt;
    }

    /// <summary>
    /// Adds observed child summary fields for root summaries so reports can
    /// show exited children even when the final live snapshot is empty.
    /// </summary>
    private void AddObservedRootChildSummaryFields(
        SandboxEvent evt,
        int rootProcessId,
        GuestProbeContext context)
    {
        var observedLookup = CreateLatestObservedSnapshotByPid(context);
        var children = observedLookup.Values
            .Where(process => process.ParentProcessId == rootProcessId)
            .OrderBy(process => process.ProcessId)
            .ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
        evt.Data["observedChildProcessCount"] = children.Count.ToString(CultureInfo.InvariantCulture);
        evt.Data["observedDescendantProcessCount"] = CountDescendants(rootProcessId, observedLookup).ToString(CultureInfo.InvariantCulture);
        if (children.Count == 0)
        {
            evt.Data["observedChildSummary"] = "none";
            evt.Data["observedChildSummaryTruncated"] = "false";
            return;
        }

        var limited = children.Take(MaxProcessTreeSummaryItems).ToList();
        evt.Data["observedChildProcessIds"] = string.Join(",", limited.Select(child => child.ProcessId.ToString(CultureInfo.InvariantCulture)));
        evt.Data["observedChildProcessNames"] = string.Join(" > ", limited.Select(ProcessDisplayName));
        evt.Data["observedChildProcessSnapshotKeys"] = string.Join(" > ", limited.Select(child => child.Key));
        evt.Data["observedChildSummary"] = string.Join("; ", limited.Select(child => $"{child.ProcessName}({child.ProcessId.ToString(CultureInfo.InvariantCulture)})"));
        evt.Data["observedChildSummaryTruncated"] = ToLowerInvariantString(children.Count > MaxProcessTreeSummaryItems);
    }

    /// <summary>
    /// Maps process snapshot state into short report text.
    /// </summary>
    private static string ProcessSnapshotZhMessage(
        string eventType,
        string snapshotState,
        bool isRootProcess,
        bool isChildProcess)
    {
        if (string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase))
        {
            if (isRootProcess)
            {
                return "样本根进程此前被跟踪，但当前快照中已不可见，可能已经退出。";
            }

            if (isChildProcess)
            {
                return "样本子进程此前被跟踪，但当前快照中已不可见，可能已经退出。";
            }

            return "进程此前被跟踪，但当前快照中已不可见，可能已经退出。";
        }

        if (string.Equals(eventType, "process.tree", StringComparison.OrdinalIgnoreCase))
        {
            return isRootProcess
                ? "样本根进程树节点已采集。"
                : "样本子进程树节点已采集。";
        }

        if (isRootProcess)
        {
            return "样本根进程快照行已采集。";
        }

        return isChildProcess
            ? "样本子进程快照行已采集。"
            : "进程快照行已采集。";
    }

    /// <summary>
    /// Maps process snapshot state into operator guidance.
    /// </summary>
    private static string ProcessSnapshotZhHint(
        string snapshotState,
        bool isTreeNode,
        bool isMissing)
    {
        if (isMissing || string.Equals(snapshotState, "missing", StringComparison.OrdinalIgnoreCase))
        {
            return "missing/exited 标记用于解释短生命周期进程；请结合 firstSeen/lastSeen、rootProcessId、treeLineageDisplay 和 treeLineageProcessKeys 还原时序。";
        }

        return isTreeNode
            ? "请使用 rootProcessId、parentProcessId、treeDepth、treeLineageDisplay、treeLineageProcessKeys 和 childSummary 还原样本进程关系。"
            : "请使用 parentProcessId、snapshotKey 和 childSummary 还原当前可见进程关系。";
    }

    /// <summary>
    /// Builds root-relative process tree metadata used by process.snapshot
    /// rows so each row can be consumed independently by host reports.
    /// </summary>
    private static Dictionary<int, ProcessTreeMetadata> CreateRootTreeMetadata(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        GuestProbeContext context)
    {
        var metadata = new Dictionary<int, ProcessTreeMetadata>();
        if (context.RootProcessId is null)
        {
            return metadata;
        }

        var childrenByParent = snapshot.Values
            .Where(process => process.ParentProcessId is not null)
            .GroupBy(process => process.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.OrderBy(process => process.ProcessId).ToList());
        var queue = new Queue<(ProcessTreeSnapshot Process, int Depth, string Lineage)>();
        var visited = new HashSet<int>();
        if (snapshot.TryGetValue(context.RootProcessId.Value, out var root) && IsSameRootProcess(root, context))
        {
            queue.Enqueue((root, 0, root.ProcessId.ToString(CultureInfo.InvariantCulture)));
        }
        else if (childrenByParent.TryGetValue(context.RootProcessId.Value, out var orphanedChildren))
        {
            foreach (var child in orphanedChildren)
            {
                queue.Enqueue((child, 1, $"{context.RootProcessId.Value.ToString(CultureInfo.InvariantCulture)}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}"));
            }
        }

        while (queue.Count != 0)
        {
            var (process, depth, lineage) = queue.Dequeue();
            if (!visited.Add(process.ProcessId))
            {
                continue;
            }

            var childCount = childrenByParent.TryGetValue(process.ProcessId, out var children) ? children.Count : 0;
            metadata[process.ProcessId] = new ProcessTreeMetadata(depth, childCount, lineage);
            if (childCount == 0 || children is null)
            {
                continue;
            }

            foreach (var child in children)
            {
                queue.Enqueue((child, depth + 1, $"{lineage}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}"));
            }
        }

        return metadata;
    }

    /// <summary>
    /// Merges later process data with earlier metadata so missing rows keep the
    /// richest known command line, image path, and start time.
    /// </summary>
    private static ProcessTreeSnapshot MergeProcessSnapshot(ProcessTreeSnapshot existing, ProcessTreeSnapshot current)
    {
        return current with
        {
            ParentProcessId = current.ParentProcessId ?? existing.ParentProcessId,
            ProcessName = IsUnknownProcessName(current.ProcessName) ? existing.ProcessName : current.ProcessName,
            Path = current.Path ?? existing.Path,
            StartTimeUtc = current.StartTimeUtc ?? existing.StartTimeUtc,
            SessionId = current.SessionId ?? existing.SessionId,
            ThreadCount = current.ThreadCount ?? existing.ThreadCount,
            BasePriority = current.BasePriority ?? existing.BasePriority,
            ToolhelpImageName = current.ToolhelpImageName ?? existing.ToolhelpImageName,
            CommandLine = current.CommandLine ?? existing.CommandLine
        };
    }

    private static ProcessTreeSnapshot MergeRootContext(ProcessTreeSnapshot process, GuestProbeContext context)
    {
        return process with
        {
            ParentProcessId = process.ParentProcessId ?? context.RootParentProcessId,
            ProcessName = IsUnknownProcessName(process.ProcessName)
                ? context.RootProcessName ?? SafeProcessNameFromPath(context.RootProcessPath ?? context.SamplePath) ?? process.ProcessName
                : process.ProcessName,
            Path = process.Path ?? context.RootProcessPath ?? context.SamplePath,
            StartTimeUtc = process.StartTimeUtc ?? context.RootProcessStartTimeUtc,
            ToolhelpImageName = process.ToolhelpImageName ?? SafeFileName(context.RootProcessPath ?? context.SamplePath),
            CommandLine = process.CommandLine ?? context.RootCommandLine
        };
    }

    private static ProcessTreeSnapshot CreateRootFallbackSnapshot(GuestProbeContext context)
    {
        var rootPath = context.RootProcessPath ?? context.SamplePath;
        return new ProcessTreeSnapshot(
            context.RootProcessId!.Value,
            context.RootParentProcessId,
            context.RootProcessName ?? SafeProcessNameFromPath(rootPath) ?? "unknown",
            rootPath,
            context.RootProcessStartTimeUtc,
            SessionId: null,
            ThreadCount: null,
            BasePriority: null,
            ToolhelpImageName: SafeFileName(rootPath),
            CommandLine: context.RootCommandLine);
    }

    private static bool IsSameRootProcess(ProcessTreeSnapshot process, GuestProbeContext context)
    {
        if (context.RootProcessStartTimeUtc is null || process.StartTimeUtc is null)
        {
            return true;
        }

        var delta = process.StartTimeUtc.Value - context.RootProcessStartTimeUtc.Value;
        return Math.Abs(delta.TotalSeconds) <= 1;
    }

    private static bool IsUnknownProcessName(string? processName)
    {
        return string.IsNullOrWhiteSpace(processName) ||
            string.Equals(processName, "unknown", StringComparison.OrdinalIgnoreCase);
    }

    private static string? SafeProcessNameFromPath(string? path)
    {
        var fileName = SafeFileName(path);
        return string.IsNullOrWhiteSpace(fileName)
            ? null
            : Path.GetFileNameWithoutExtension(fileName);
    }

    private static string? SafeFileName(string? path)
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

    /// <summary>
    /// Creates a single environment detail event.
    /// Inputs are guest probe context; processing reads stable runtime, user,
    /// token, time zone, and selected environment values; the method returns a
    /// SandboxEvent without dumping the full environment block.
    /// </summary>
    private static SandboxEvent CreateEnvironmentDetailEvent(GuestProbeContext context)
    {
        var evt = new SandboxEvent
        {
            EventType = "environment.detail",
            Source = "guest",
            Path = context.SamplePath,
            ProcessId = Environment.ProcessId,
            Data =
            {
                ["phase"] = ToPhaseLabel(ProbePhase.BeforeStart),
                ["samplePath"] = context.SamplePath,
                ["sampleFileName"] = Path.GetFileName(context.SamplePath),
                ["workingDirectory"] = context.WorkingDirectory,
                ["outputDirectory"] = context.OutputDirectory,
                ["frameworkDescription"] = RuntimeInformation.FrameworkDescription,
                ["runtimeIdentifier"] = RuntimeInformation.RuntimeIdentifier,
                ["osDescription"] = RuntimeInformation.OSDescription,
                ["osArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
                ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                ["is64BitProcess"] = Environment.Is64BitProcess.ToString(CultureInfo.InvariantCulture),
                ["is64BitOperatingSystem"] = Environment.Is64BitOperatingSystem.ToString(CultureInfo.InvariantCulture),
                ["userInteractive"] = Environment.UserInteractive.ToString(CultureInfo.InvariantCulture),
                ["isElevated"] = SafeIsElevated(),
                ["processorCount"] = Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture),
                ["systemPageSize"] = Environment.SystemPageSize.ToString(CultureInfo.InvariantCulture),
                ["tickCount64"] = Environment.TickCount64.ToString(CultureInfo.InvariantCulture),
                ["timeZoneId"] = TimeZoneInfo.Local.Id,
                ["utcOffsetMinutes"] = TimeZoneInfo.Local.BaseUtcOffset.TotalMinutes.ToString("0", CultureInfo.InvariantCulture),
                ["machineName"] = Environment.MachineName,
                ["userName"] = Environment.UserName,
                ["userDomainName"] = Environment.UserDomainName,
                ["currentDirectory"] = Environment.CurrentDirectory,
                ["systemDirectory"] = Environment.SystemDirectory,
                ["tempPath"] = Path.GetTempPath()
            }
        };

        AddIfNotEmpty(evt.Data, "processPath", Environment.ProcessPath);
        AddIfNotEmpty(evt.Data, "userProfile", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        AddIfNotEmpty(evt.Data, "sessionName", Environment.GetEnvironmentVariable("SESSIONNAME"));
        AddIfNotEmpty(evt.Data, "computerNameEnvironment", Environment.GetEnvironmentVariable("COMPUTERNAME"));
        var pathValue = Environment.GetEnvironmentVariable("PATH");
        if (pathValue is not null)
        {
            evt.Data["pathLength"] = pathValue.Length.ToString(CultureInfo.InvariantCulture);
        }

        return evt;
    }

    /// <summary>
    /// Creates summary events for service/task/startup inventories.
    /// Inputs are a system snapshot and phase; processing stores inventory
    /// counts without expanding all baseline items; the method yields events.
    /// </summary>
    private static IEnumerable<SandboxEvent> CreateSystemSnapshotEvents(SystemChangeSnapshot snapshot, ProbePhase phase)
    {
        yield return CreateInventorySnapshotEvent("service.snapshot", "service", snapshot.Services.Count, phase);
        yield return CreateInventorySnapshotEvent("scheduled_task.snapshot", "scheduled_task", snapshot.ScheduledTasks.Count, phase);
        yield return CreateInventorySnapshotEvent("startup_item.snapshot", "startup_item", snapshot.StartupItems.Count, phase);
        yield return CreateInventorySnapshotEvent("registry.run.snapshot", "registry.run", snapshot.RegistryRunValues.Count, phase);
    }

    /// <summary>
    /// Creates one inventory summary event.
    /// Inputs are event type, inventory kind, count, and phase; processing stores
    /// count metadata; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateInventorySnapshotEvent(string eventType, string kind, int count, ProbePhase phase)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["kind"] = kind,
                ["count"] = count.ToString(CultureInfo.InvariantCulture)
            }
        };
    }

    /// <summary>
    /// Creates service, scheduled task, and startup item diff events.
    /// Inputs are baseline and current system snapshots plus phase; processing
    /// emits created, modified, deleted events with bounded volume; the method
    /// returns a deterministic event list.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateSystemDiffEvents(
        SystemChangeSnapshot baseline,
        SystemChangeSnapshot current,
        ProbePhase phase)
    {
        var events = new List<SandboxEvent>();
        AddStateDiffEvents(
            events,
            baseline.Services,
            current.Services,
            "service",
            ServiceCreatedEventType,
            ServiceModifiedEventType,
            ServiceDeletedEventType,
            phase,
            CreateServiceEvent);
        AddStateDiffEvents(
            events,
            baseline.ScheduledTasks,
            current.ScheduledTasks,
            "scheduled_task",
            ScheduledTaskCreatedEventType,
            ScheduledTaskModifiedEventType,
            ScheduledTaskDeletedEventType,
            phase,
            CreateScheduledTaskEvent);
        AddStateDiffEvents(
            events,
            baseline.StartupItems,
            current.StartupItems,
            "startup_item",
            StartupItemCreatedEventType,
            StartupItemModifiedEventType,
            StartupItemDeletedEventType,
            phase,
            CreateStartupItemEvent);
        AddStateDiffEvents(
            events,
            baseline.RegistryRunValues,
            current.RegistryRunValues,
            "registry.run",
            RegistryRunCreatedEventType,
            RegistryRunModifiedEventType,
            RegistryRunDeletedEventType,
            phase,
            CreateRegistryRunEvent);
        return events;
    }

    /// <summary>
    /// Adds created/modified/deleted events for one system-state dictionary.
    /// Inputs are output list, baseline/current dictionaries, event prefix,
    /// phase, and event factory; processing compares keys and signatures with a
    /// per-kind cap; the method returns no value.
    /// </summary>
    private static void AddStateDiffEvents<TSnapshot>(
        List<SandboxEvent> events,
        IReadOnlyDictionary<string, TSnapshot> baseline,
        IReadOnlyDictionary<string, TSnapshot> current,
        string eventPrefix,
        string createdEventType,
        string modifiedEventType,
        string deletedEventType,
        ProbePhase phase,
        Func<string, string, TSnapshot, TSnapshot?, ProbePhase, SandboxEvent> createEvent)
        where TSnapshot : ISystemStateItemSnapshot
    {
        var emitted = 0;
        foreach (var (key, snapshot) in current.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!baseline.TryGetValue(key, out var previous))
            {
                if (!TryReserveDiffSlot(events, eventPrefix, "created", phase, current.Count, ref emitted))
                {
                    break;
                }

                events.Add(createEvent(createdEventType, "created", snapshot, default, phase));
            }
            else if (!string.Equals(previous.Signature, snapshot.Signature, StringComparison.Ordinal))
            {
                if (!TryReserveDiffSlot(events, eventPrefix, "modified", phase, current.Count, ref emitted))
                {
                    break;
                }

                events.Add(createEvent(modifiedEventType, "modified", snapshot, previous, phase));
            }
        }

        foreach (var (key, previous) in baseline.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (current.ContainsKey(key))
            {
                continue;
            }

            if (!TryReserveDiffSlot(events, eventPrefix, "deleted", phase, baseline.Count, ref emitted))
            {
                break;
            }

            events.Add(createEvent(deletedEventType, "deleted", previous, default, phase));
        }
    }

    /// <summary>
    /// Enforces the per-kind diff cap.
    /// Inputs are event output, prefix, change label, phase, total count, and
    /// emitted count; processing appends a truncation event when the cap is hit;
    /// the method returns whether a new slot was reserved.
    /// </summary>
    private static bool TryReserveDiffSlot(
        List<SandboxEvent> events,
        string eventPrefix,
        string change,
        ProbePhase phase,
        int totalCount,
        ref int emitted)
    {
        if (emitted >= MaxSystemDiffEventsPerKind)
        {
            events.Add(new SandboxEvent
            {
                EventType = $"{eventPrefix}.diff_truncated",
                Source = "guest",
                Data =
                {
                    ["phase"] = ToPhaseLabel(phase),
                    ["change"] = change,
                    ["totalCount"] = totalCount.ToString(CultureInfo.InvariantCulture),
                    ["emittedCount"] = emitted.ToString(CultureInfo.InvariantCulture)
                }
            });
            return false;
        }

        emitted++;
        return true;
    }

    /// <summary>
    /// Creates one service diff event.
    /// Inputs are event type, change label, current/previous service snapshots,
    /// and phase; processing copies service identity, state, PID, and registry
    /// configuration metadata; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateServiceEvent(
        string eventType,
        string change,
        ServiceStateSnapshot service,
        ServiceStateSnapshot? previous,
        ProbePhase phase)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessId = service.ProcessId,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["serviceName"] = service.ServiceName,
                ["state"] = service.State,
                ["signature"] = service.Signature
            }
        };

        AddIfNotEmpty(evt.Data, "displayName", service.DisplayName);
        AddIfNotEmpty(evt.Data, "stateCode", service.StateCode);
        AddIfNotEmpty(evt.Data, "rawSummary", service.RawSummary);
        AddIfNotEmpty(evt.Data, "imagePath", service.ImagePath);
        AddIfNotEmpty(evt.Data, "startType", service.StartType);
        AddIfNotEmpty(evt.Data, "serviceType", service.ServiceType);
        AddIfNotEmpty(evt.Data, "objectName", service.ObjectName);
        AddIfNotEmpty(evt.Data, "serviceDll", service.ServiceDll);
        if (service.ProcessId is not null)
        {
            evt.Data["serviceProcessId"] = service.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (previous is not null)
        {
            AddIfNotEmpty(evt.Data, "previousState", previous.State);
            AddIfNotEmpty(evt.Data, "previousImagePath", previous.ImagePath);
            AddIfNotEmpty(evt.Data, "previousStartType", previous.StartType);
            AddIfNotEmpty(evt.Data, "previousServiceType", previous.ServiceType);
            AddIfNotEmpty(evt.Data, "previousObjectName", previous.ObjectName);
            AddIfNotEmpty(evt.Data, "previousServiceDll", previous.ServiceDll);
            if (previous.ProcessId is not null)
            {
                evt.Data["previousServiceProcessId"] = previous.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
            }
        }

        return evt;
    }

    /// <summary>
    /// Creates one scheduled task diff event.
    /// Inputs are event type, change label, current/previous task snapshots,
    /// and phase; processing copies task identity, status, and command metadata;
    /// the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateScheduledTaskEvent(
        string eventType,
        string change,
        ScheduledTaskStateSnapshot task,
        ScheduledTaskStateSnapshot? previous,
        ProbePhase phase)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = task.TaskName,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["taskName"] = task.TaskName,
                ["signature"] = task.Signature
            }
        };

        AddIfNotEmpty(evt.Data, "status", task.Status);
        AddIfNotEmpty(evt.Data, "taskToRun", task.TaskToRun);
        AddIfNotEmpty(evt.Data, "nextRunTime", task.NextRunTime);
        AddIfNotEmpty(evt.Data, "lastRunTime", task.LastRunTime);
        AddIfNotEmpty(evt.Data, "author", task.Author);
        AddIfNotEmpty(evt.Data, "rawSummary", task.RawSummary);
        if (previous is not null)
        {
            AddIfNotEmpty(evt.Data, "previousStatus", previous.Status);
            AddIfNotEmpty(evt.Data, "previousTaskToRun", previous.TaskToRun);
        }

        return evt;
    }

    /// <summary>
    /// Creates one startup item diff event.
    /// Inputs are event type, change label, current/previous startup snapshots,
    /// and phase; processing copies registry/folder identity and value metadata;
    /// the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateStartupItemEvent(
        string eventType,
        string change,
        StartupItemStateSnapshot item,
        StartupItemStateSnapshot? previous,
        ProbePhase phase)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = item.Location,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["kind"] = item.Kind,
                ["location"] = item.Location,
                ["name"] = item.Name,
                ["signature"] = item.Signature
            }
        };

        AddIfNotEmpty(evt.Data, "value", item.Value);
        AddIfNotEmpty(evt.Data, "valueKind", item.ValueKind);
        if (item.LastWriteUtc is not null)
        {
            evt.Data["lastWriteUtc"] = item.LastWriteUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (item.SizeBytes is not null)
        {
            evt.Data["sizeBytes"] = item.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (previous is not null)
        {
            AddIfNotEmpty(evt.Data, "previousValue", previous.Value);
            AddIfNotEmpty(evt.Data, "previousValueKind", previous.ValueKind);
        }

        return evt;
    }

    /// <summary>
    /// Creates one registry Run/RunOnce value diff event.
    /// Inputs are event type, change label, current/previous registry snapshots,
    /// and phase; processing copies hive, view, key, value name, and payload
    /// details into string Data; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateRegistryRunEvent(
        string eventType,
        string change,
        RegistryRunValueSnapshot item,
        RegistryRunValueSnapshot? previous,
        ProbePhase phase)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = item.Location,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["hive"] = item.Hive,
                ["keyPath"] = item.KeyPath,
                ["keyName"] = item.KeyName,
                ["view"] = item.View,
                ["location"] = item.Location,
                ["valueName"] = item.ValueName,
                ["signature"] = item.Signature
            }
        };

        AddIfNotEmpty(evt.Data, "value", item.Value);
        AddIfNotEmpty(evt.Data, "expandedValue", item.ExpandedValue);
        AddIfNotEmpty(evt.Data, "valueKind", item.ValueKind);
        if (previous is not null)
        {
            AddIfNotEmpty(evt.Data, "previousValue", previous.Value);
            AddIfNotEmpty(evt.Data, "previousExpandedValue", previous.ExpandedValue);
            AddIfNotEmpty(evt.Data, "previousValueKind", previous.ValueKind);
        }

        return evt;
    }

    /// <summary>
    /// Copies diagnostic events and adds the current phase.
    /// Inputs are diagnostic events and phase; processing clones each event with
    /// a phase Data value; the method yields normalized diagnostics.
    /// </summary>
    private static IEnumerable<SandboxEvent> WithPhase(IEnumerable<SandboxEvent> diagnostics, ProbePhase phase)
    {
        foreach (var diagnostic in diagnostics)
        {
            var data = new Dictionary<string, string>(diagnostic.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["phase"] = ToPhaseLabel(phase)
            };
            yield return diagnostic with { Data = data };
        }
    }

    /// <summary>
    /// Converts probe phases to stable legacy labels.
    /// Inputs are enum values, processing maps known phases to existing strings,
    /// and the method returns a string stored in event Data.
    /// </summary>
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

    /// <summary>
    /// Adds a string Data value when it is non-empty.
    /// Inputs are Data dictionary, key, and value; processing skips empty
    /// values; the method returns no value.
    /// </summary>
    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Determines whether the current Windows token is elevated.
    /// Inputs are none; processing uses WindowsIdentity when available and
    /// returns "unknown" on unsupported platforms/errors; the method returns a
    /// string suitable for SandboxEvent Data.
    /// </summary>
    private static string SafeIsElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return "unknown";
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator).ToString(CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or InvalidOperationException)
        {
            return "unknown";
        }
    }
}

/// <summary>
/// Supplies process snapshots for process tree collection.
/// Inputs are none at call time; processing observes process identifiers,
/// parent identifiers, names, paths, start times, sessions, thread counts, and
/// base priorities; Capture returns a dictionary keyed by pid.
/// </summary>
internal interface IProcessSnapshotProvider
{
    Dictionary<int, ProcessTreeSnapshot> Capture(CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures process metadata using low-privilege Windows APIs when available.
/// Inputs are none; processing uses Toolhelp snapshots on Windows and falls
/// back to Process.GetProcesses elsewhere; Capture returns visible processes.
/// </summary>
internal sealed class ProcessSnapshotProvider : IProcessSnapshotProvider
{
    private const uint Th32CsSnapProcess = 0x00000002;
    private static readonly TimeSpan CommandLineQueryTimeout = TimeSpan.FromSeconds(4);

    /// <summary>
    /// Captures the current visible process list.
    /// Inputs are cancellation token; processing prefers parent process ids and
    /// process metadata from Toolhelp and enriches records with accessible
    /// Process properties; the method returns process snapshots keyed by pid.
    /// </summary>
    public Dictionary<int, ProcessTreeSnapshot> Capture(CancellationToken cancellationToken = default)
    {
        var toolhelpByPid = OperatingSystem.IsWindows()
            ? CaptureToolhelpProcessInfo()
            : new Dictionary<int, ToolhelpProcessInfo>();
        var commandLineMetadataByPid = OperatingSystem.IsWindows()
            ? CaptureCommandLineMetadata()
            : new Dictionary<int, ProcessCommandLineInfo>();

        return CaptureWithProcessApi(toolhelpByPid, commandLineMetadataByPid, cancellationToken);
    }

    /// <summary>
    /// Captures process parent identifiers and lightweight metadata through
    /// CreateToolhelp32Snapshot. Inputs are none; processing walks
    /// PROCESSENTRY32 records; the method returns pid-to-info mappings and
    /// tolerates snapshot failures.
    /// </summary>
    private static Dictionary<int, ToolhelpProcessInfo> CaptureToolhelpProcessInfo()
    {
        var processes = new Dictionary<int, ToolhelpProcessInfo>();
        var handle = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (handle == InvalidHandleValue)
        {
            return processes;
        }

        try
        {
            var entry = new ProcessEntry32
            {
                DwSize = (uint)Marshal.SizeOf<ProcessEntry32>()
            };

            if (!Process32First(handle, ref entry))
            {
                return processes;
            }

            do
            {
                processes[(int)entry.Th32ProcessId] = new ToolhelpProcessInfo(
                    ParentProcessId: (int)entry.Th32ParentProcessId,
                    ThreadCount: (int)entry.CntThreads,
                    BasePriority: entry.PcPriClassBase,
                    ImageName: entry.SzExeFile);
            }
            while (Process32Next(handle, ref entry));

            return processes;
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    /// <summary>
    /// Captures process command lines with a bounded PowerShell CIM helper.
    /// Inputs are none; processing reads Win32_Process rows without elevation
    /// where permitted and returns PID-command-line mappings; failures are
    /// ignored so the primary process snapshot path remains non-fatal.
    /// </summary>
    private static Dictionary<int, ProcessCommandLineInfo> CaptureCommandLineMetadata()
    {
        try
        {
            var result = BoundedProcessRunner.RunAsync(
                "powershell.exe",
                [
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress -Depth 2"
                ],
                CommandLineQueryTimeout).GetAwaiter().GetResult();
            return result.Succeeded
                ? ParseCommandLineJson(result.StandardOutput)
                : new Dictionary<int, ProcessCommandLineInfo>();
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return new Dictionary<int, ProcessCommandLineInfo>();
        }
    }

    /// <summary>
    /// Parses compact PowerShell JSON from Win32_Process into PID-command-line
    /// mappings while tolerating either a single object or an array.
    /// </summary>
    private static Dictionary<int, ProcessCommandLineInfo> ParseCommandLineJson(string json)
    {
        var values = new Dictionary<int, ProcessCommandLineInfo>();
        if (string.IsNullOrWhiteSpace(json))
        {
            return values;
        }

        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var element in document.RootElement.EnumerateArray())
            {
                AddCommandLineJsonRow(values, element);
            }
        }
        else if (document.RootElement.ValueKind == JsonValueKind.Object)
        {
            AddCommandLineJsonRow(values, document.RootElement);
        }

        return values;
    }

    private static void AddCommandLineJsonRow(Dictionary<int, ProcessCommandLineInfo> values, JsonElement element)
    {
        if (!TryGetJsonInt32(element, "ProcessId", out var processId) || processId <= 0)
        {
            return;
        }

        _ = TryGetJsonInt32(element, "ParentProcessId", out var parentProcessId);
        _ = TryGetJsonString(element, "Name", out var name);
        _ = TryGetJsonString(element, "ExecutablePath", out var executablePath);
        _ = TryGetJsonString(element, "CommandLine", out var commandLine);
        values[processId] = new ProcessCommandLineInfo(
            parentProcessId > 0 ? parentProcessId : null,
            name,
            executablePath,
            commandLine);
    }

    private static bool TryGetJsonInt32(JsonElement element, string propertyName, out int value)
    {
        value = 0;
        if (!element.TryGetProperty(propertyName, out var property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out value))
        {
            return true;
        }

        return property.ValueKind == JsonValueKind.String &&
            int.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryGetJsonString(JsonElement element, string propertyName, out string? value)
    {
        value = null;
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return false;
        }

        value = property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
        return !string.IsNullOrWhiteSpace(value);
    }

    /// <summary>
    /// Enriches process snapshots with names, executable paths, start times, and
    /// sessions. Inputs are optional Toolhelp metadata and cancellation token;
    /// processing reads each Process defensively because protected/exited
    /// targets can deny access; the method returns snapshots keyed by process id.
    /// </summary>
    private static Dictionary<int, ProcessTreeSnapshot> CaptureWithProcessApi(
        IReadOnlyDictionary<int, ToolhelpProcessInfo> toolhelpByPid,
        IReadOnlyDictionary<int, ProcessCommandLineInfo> commandLineMetadataByPid,
        CancellationToken cancellationToken)
    {
        var snapshot = new Dictionary<int, ProcessTreeSnapshot>();

        try
        {
            foreach (var process in Process.GetProcesses())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (process)
                {
                    commandLineMetadataByPid.TryGetValue(process.Id, out var commandLineMetadata);
                    var processName = TryReadProcessValue(process, static p => p.ProcessName, "unknown");
                    var cimName = commandLineMetadata?.Name;
                    if (IsUnknownProcessNameValue(processName) && !string.IsNullOrWhiteSpace(cimName))
                    {
                        processName = Path.GetFileNameWithoutExtension(cimName) ?? cimName;
                    }

                    processName ??= "unknown";
                    var path = TryReadProcessValue<string?>(process, static p => p.MainModule?.FileName, null) ?? commandLineMetadata?.ExecutablePath;
                    var startTimeUtc = TryReadProcessValue<DateTime?>(process, static p => p.StartTime.ToUniversalTime(), null);
                    var sessionId = TryReadProcessValue<int?>(process, static p => p.SessionId, null);
                    toolhelpByPid.TryGetValue(process.Id, out var toolhelp);
                    var parentProcessId = toolhelp is not null && toolhelp.ParentProcessId > 0
                        ? toolhelp.ParentProcessId
                        : commandLineMetadata?.ParentProcessId;

                    snapshot[process.Id] = new ProcessTreeSnapshot(
                        process.Id,
                        parentProcessId,
                        string.IsNullOrWhiteSpace(processName) ? "unknown" : processName,
                        path,
                        startTimeUtc,
                        sessionId,
                        toolhelp?.ThreadCount,
                        toolhelp?.BasePriority,
                        toolhelp?.ImageName,
                        commandLineMetadata?.CommandLine);
                }
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (Win32Exception)
        {
        }

        return snapshot;
    }

    /// <summary>
    /// Reads one Process property while tolerating protected or exited targets.
    /// Inputs are the Process instance, a value selector, and a fallback value;
    /// processing catches expected process-access exceptions; the method
    /// returns the selected value or fallback.
    /// </summary>
    private static T TryReadProcessValue<T>(Process process, Func<Process, T> read, T fallback)
    {
        try
        {
            return read(process);
        }
        catch (InvalidOperationException)
        {
            return fallback;
        }
        catch (Win32Exception)
        {
            return fallback;
        }
        catch (NotSupportedException)
        {
            return fallback;
        }
    }

    /// <summary>
    /// Checks whether a process name from System.Diagnostics is missing or only
    /// a placeholder. Kept local to the provider so the provider remains
    /// self-contained when used by memory-dump and process-tree probes.
    /// </summary>
    private static bool IsUnknownProcessNameValue(string? processName)
    {
        return string.IsNullOrWhiteSpace(processName) ||
            string.Equals(processName, "unknown", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly IntPtr InvalidHandleValue = new(-1);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW")]
    private static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "Process32NextW")]
    private static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private sealed record ToolhelpProcessInfo(
        int ParentProcessId,
        int ThreadCount,
        int BasePriority,
        string? ImageName);

    private sealed record ProcessCommandLineInfo(
        int? ParentProcessId,
        string? Name,
        string? ExecutablePath,
        string? CommandLine);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint DwSize;
        public uint CntUsage;
        public uint Th32ProcessId;
        public IntPtr Th32DefaultHeapId;
        public uint Th32ModuleId;
        public uint CntThreads;
        public uint Th32ParentProcessId;
        public int PcPriClassBase;
        public uint DwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string SzExeFile;
    }
}

/// <summary>
/// Supplies service, scheduled task, and startup item snapshots.
/// Inputs are cancellation tokens; processing uses low-privilege Windows
/// commands, registry reads, and folder enumeration; CaptureAsync returns
/// snapshot dictionaries plus diagnostic events.
/// </summary>
internal interface ISystemChangeSnapshotProvider
{
    Task<SystemChangeSnapshot> CaptureAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures service, scheduled task, and startup item state.
/// Inputs are cancellation token; processing bounds helper commands so
/// inventory collection cannot hang the analysis; CaptureAsync returns state
/// dictionaries and non-fatal diagnostics.
/// </summary>
internal sealed class SystemChangeSnapshotProvider : ISystemChangeSnapshotProvider
{
    private static readonly TimeSpan ServiceQueryTimeout = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan ScheduledTaskQueryTimeout = TimeSpan.FromSeconds(6);

    /// <summary>
    /// Captures all system-change inventories.
    /// Inputs are cancellation token; processing isolates each inventory source;
    /// the method returns a SystemChangeSnapshot.
    /// </summary>
    public async Task<SystemChangeSnapshot> CaptureAsync(CancellationToken cancellationToken = default)
    {
        var diagnostics = new List<SandboxEvent>();
        var services = await CaptureServicesAsync(diagnostics, cancellationToken).ConfigureAwait(false);
        var scheduledTasks = await CaptureScheduledTasksAsync(diagnostics, cancellationToken).ConfigureAwait(false);
        var registryRunValues = new Dictionary<string, RegistryRunValueSnapshot>(StringComparer.OrdinalIgnoreCase);
        var startupItems = CaptureStartupItems(registryRunValues, diagnostics, cancellationToken);
        return new SystemChangeSnapshot(services, scheduledTasks, startupItems, registryRunValues, diagnostics);
    }

    /// <summary>
    /// Captures service state through sc.exe queryex plus service registry
    /// configuration. Inputs are diagnostics and cancellation token; processing
    /// parses service names, display names, states, PIDs, ImagePath/Start/Type,
    /// ObjectName, and Parameters\ServiceDll; returns a keyed dictionary.
    /// </summary>
    private static async Task<Dictionary<string, ServiceStateSnapshot>> CaptureServicesAsync(
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            diagnostics.Add(CreateUnsupportedEvent("service.capture_skipped", "sc queryex state= all"));
            return new Dictionary<string, ServiceStateSnapshot>(StringComparer.OrdinalIgnoreCase);
        }

        var result = await BoundedProcessRunner.RunAsync(
            "sc.exe",
            ["queryex", "state=", "all"],
            ServiceQueryTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            diagnostics.Add(CreateCommandFailureEvent("service.capture_failed", result));
        }

        var services = ParseServices(result.StandardOutput);
        EnrichServiceRegistryMetadata(services, diagnostics, cancellationToken);
        return services;
    }

    /// <summary>
    /// Captures scheduled task state through schtasks.
    /// Inputs are diagnostics and cancellation token; processing parses CSV
    /// output defensively; returns a task dictionary keyed by task path/name.
    /// </summary>
    private static async Task<Dictionary<string, ScheduledTaskStateSnapshot>> CaptureScheduledTasksAsync(
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            diagnostics.Add(CreateUnsupportedEvent("scheduled_task.capture_skipped", "schtasks /query /fo csv /v"));
            return new Dictionary<string, ScheduledTaskStateSnapshot>(StringComparer.OrdinalIgnoreCase);
        }

        var result = await BoundedProcessRunner.RunAsync(
            "schtasks.exe",
            ["/query", "/fo", "csv", "/v"],
            ScheduledTaskQueryTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            diagnostics.Add(CreateCommandFailureEvent("scheduled_task.capture_failed", result));
        }

        return ParseScheduledTasks(result.StandardOutput);
    }

    /// <summary>
    /// Captures startup registry values and Startup folder entries.
    /// Inputs are diagnostics and cancellation token; processing reads common
    /// Run/RunOnce keys and startup folders defensively; returns a dictionary.
    /// </summary>
    private static Dictionary<string, StartupItemStateSnapshot> CaptureStartupItems(
        Dictionary<string, RegistryRunValueSnapshot> registryRunValues,
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        var items = new Dictionary<string, StartupItemStateSnapshot>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows())
        {
            diagnostics.Add(CreateUnsupportedEvent("startup_item.capture_skipped", "registry and Startup folders"));
            diagnostics.Add(CreateUnsupportedEvent("registry.run.capture_skipped", "Run/RunOnce registry keys"));
            return items;
        }

        CaptureRegistryStartupItems(items, registryRunValues, diagnostics, cancellationToken);
        CaptureStartupFolderItems(items, diagnostics, Environment.SpecialFolder.Startup, "user-startup-folder", cancellationToken);
        CaptureStartupFolderItems(items, diagnostics, Environment.SpecialFolder.CommonStartup, "common-startup-folder", cancellationToken);
        return items;
    }

    /// <summary>
    /// Parses sc.exe queryex output.
    /// Inputs are command output; processing groups SERVICE_NAME blocks; returns
    /// service snapshots keyed by service name.
    /// </summary>
    private static Dictionary<string, ServiceStateSnapshot> ParseServices(string text)
    {
        var services = new Dictionary<string, ServiceStateSnapshot>(StringComparer.OrdinalIgnoreCase);
        string? serviceName = null;
        string? displayName = null;
        string? state = null;
        string? stateCode = null;
        int? processId = null;
        var rawLines = new List<string>();

        foreach (var rawLine in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (rawLine.StartsWith("SERVICE_NAME:", StringComparison.OrdinalIgnoreCase))
            {
                CommitService(services, serviceName, displayName, state, stateCode, processId, rawLines);
                serviceName = ValueAfterColon(rawLine);
                displayName = null;
                state = null;
                stateCode = null;
                processId = null;
                rawLines.Clear();
            }

            rawLines.Add(rawLine);

            if (rawLine.StartsWith("DISPLAY_NAME:", StringComparison.OrdinalIgnoreCase))
            {
                displayName = ValueAfterColon(rawLine);
            }
            else if (rawLine.StartsWith("STATE", StringComparison.OrdinalIgnoreCase))
            {
                var value = ValueAfterColon(rawLine);
                var parts = value?.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [];
                stateCode = parts.Length > 0 ? parts[0] : null;
                state = parts.Length > 1 ? parts[1] : value;
            }
            else if (rawLine.StartsWith("PID", StringComparison.OrdinalIgnoreCase))
            {
                processId = int.TryParse(ValueAfterColon(rawLine), NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid)
                    ? pid
                    : null;
            }
        }

        CommitService(services, serviceName, displayName, state, stateCode, processId, rawLines);
        return services;
    }

    /// <summary>
    /// Commits one parsed service block to the dictionary.
    /// Inputs are dictionary and current block fields; processing skips empty
    /// service names; the method returns no value.
    /// </summary>
    private static void CommitService(
        Dictionary<string, ServiceStateSnapshot> services,
        string? serviceName,
        string? displayName,
        string? state,
        string? stateCode,
        int? processId,
        IReadOnlyList<string> rawLines)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return;
        }

        var service = new ServiceStateSnapshot(
            serviceName,
            displayName,
            state ?? "unknown",
            stateCode,
            processId is > 0 ? processId : null,
            Truncate(string.Join(" | ", rawLines.Take(6)), 512),
            ImagePath: null,
            StartType: null,
            ServiceType: null,
            ObjectName: null,
            ServiceDll: null);
        services[service.Key] = service;
    }

    /// <summary>
    /// Adds low-privilege service registry configuration metadata to parsed
    /// service rows. Inputs are parsed service snapshots, diagnostics, and
    /// cancellation; processing reads HKLM service keys defensively; the method
    /// returns no value and preserves sc.exe state when registry reads fail.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void EnrichServiceRegistryMetadata(
        Dictionary<string, ServiceStateSnapshot> services,
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        foreach (var serviceName in services.Keys.OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToList())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var service = services[serviceName];
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{service.ServiceName}");
                if (key is null)
                {
                    continue;
                }

                var imagePath = FormatRegistryValue(key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                var startType = FormatRegistryValue(key.GetValue("Start", null, RegistryValueOptions.None));
                var serviceType = FormatRegistryValue(key.GetValue("Type", null, RegistryValueOptions.None));
                var objectName = FormatRegistryValue(key.GetValue("ObjectName", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                string? serviceDll = null;
                using (var parameters = key.OpenSubKey("Parameters"))
                {
                    serviceDll = FormatRegistryValue(parameters?.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
                }

                services[serviceName] = service with
                {
                    ImagePath = imagePath,
                    StartType = startType,
                    ServiceType = serviceType,
                    ObjectName = objectName,
                    ServiceDll = serviceDll
                };
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException)
            {
                diagnostics.Add(CreateExceptionEvent("service.registry.capture_failed", service.ServiceName, ex));
            }
        }
    }

    /// <summary>
    /// Parses schtasks CSV output.
    /// Inputs are command output; processing accepts quoted CSV and English
    /// headers when available with index fallbacks; returns keyed task snapshots.
    /// </summary>
    private static Dictionary<string, ScheduledTaskStateSnapshot> ParseScheduledTasks(string text)
    {
        var tasks = new Dictionary<string, ScheduledTaskStateSnapshot>(StringComparer.OrdinalIgnoreCase);
        var rows = ParseCsvRows(text);
        if (rows.Count < 2)
        {
            return tasks;
        }

        var headers = rows[0];
        var taskNameIndex = FindHeader(headers, "TaskName", "Task Name");
        if (taskNameIndex < 0 && headers.Count > 1)
        {
            taskNameIndex = 1;
        }

        var statusIndex = FindHeader(headers, "Status");
        var taskToRunIndex = FindHeader(headers, "Task To Run");
        var nextRunIndex = FindHeader(headers, "Next Run Time");
        var lastRunIndex = FindHeader(headers, "Last Run Time");
        var authorIndex = FindHeader(headers, "Author");

        foreach (var row in rows.Skip(1))
        {
            var taskName = GetCsvValue(row, taskNameIndex);
            if (string.IsNullOrWhiteSpace(taskName))
            {
                continue;
            }

            var task = new ScheduledTaskStateSnapshot(
                taskName,
                GetCsvValue(row, statusIndex),
                GetCsvValue(row, taskToRunIndex),
                GetCsvValue(row, nextRunIndex),
                GetCsvValue(row, lastRunIndex),
                GetCsvValue(row, authorIndex),
                Truncate(string.Join(" | ", row.Take(8)), 512));
            tasks[task.Key] = task;
        }

        return tasks;
    }

    /// <summary>
    /// Captures common Run/RunOnce registry startup entries.
    /// Inputs are item dictionary, diagnostics, and cancellation token;
    /// processing enumerates HKCU/HKLM 32/64-bit views defensively.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CaptureRegistryStartupItems(
        Dictionary<string, StartupItemStateSnapshot> items,
        Dictionary<string, RegistryRunValueSnapshot> registryRunValues,
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        var views = Environment.Is64BitOperatingSystem
            ? [RegistryView.Registry64, RegistryView.Registry32]
            : new[] { RegistryView.Default };
        var keys = new[]
        {
            (RegistryHive.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
            (RegistryHive.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
            (RegistryHive.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
            (RegistryHive.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce")
        };

        foreach (var view in views)
        {
            foreach (var (hive, hiveLabel, subKeyPath, keyName) in keys)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    using var key = baseKey.OpenSubKey(subKeyPath);
                    if (key is null)
                    {
                        continue;
                    }

                    foreach (var valueName in key.GetValueNames())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                        var expandedValue = key.GetValue(valueName, null, RegistryValueOptions.None);
                        var valueKind = SafeGetValueKind(key, valueName);
                        var name = string.IsNullOrWhiteSpace(valueName) ? "(Default)" : valueName;
                        var location = $"{hiveLabel}\\{subKeyPath} ({view})";
                        var registryRunValue = new RegistryRunValueSnapshot(
                            hiveLabel,
                            subKeyPath,
                            keyName,
                            view.ToString(),
                            name,
                            FormatRegistryValue(value),
                            FormatRegistryValue(expandedValue),
                            valueKind);
                        registryRunValues[registryRunValue.Key] = registryRunValue;

                        var item = new StartupItemStateSnapshot(
                            "registry",
                            location,
                            name,
                            registryRunValue.Value,
                            valueKind,
                            LastWriteUtc: null,
                            SizeBytes: null);
                        items[item.Key] = item;
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException)
                {
                    diagnostics.Add(CreateExceptionEvent("registry.run.capture_failed", $"{hiveLabel}\\{subKeyPath} ({view})", ex));
                    diagnostics.Add(CreateExceptionEvent("startup_item.capture_failed", $"{hiveLabel}\\{subKeyPath} ({view})", ex));
                }
            }
        }
    }

    /// <summary>
    /// Captures files in a Startup folder.
    /// Inputs are item dictionary, diagnostics, special folder, label, and
    /// cancellation token; processing records file path, size, and timestamp.
    /// </summary>
    private static void CaptureStartupFolderItems(
        Dictionary<string, StartupItemStateSnapshot> items,
        List<SandboxEvent> diagnostics,
        Environment.SpecialFolder folder,
        string label,
        CancellationToken cancellationToken)
    {
        try
        {
            var folderPath = Environment.GetFolderPath(folder);
            if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
            {
                return;
            }

            foreach (var path in Directory.EnumerateFiles(folderPath))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var info = new FileInfo(path);
                    var item = new StartupItemStateSnapshot(
                        "folder",
                        folderPath,
                        Path.GetFileName(path),
                        path,
                        label,
                        info.LastWriteTimeUtc,
                        info.Length);
                    items[item.Key] = item;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
                {
                    diagnostics.Add(CreateExceptionEvent("startup_item.capture_failed", path, ex));
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException)
        {
            diagnostics.Add(CreateExceptionEvent("startup_item.capture_failed", label, ex));
        }
    }

    /// <summary>
    /// Parses basic CSV rows with quote escaping.
    /// Inputs are CSV text; processing handles quoted fields and CR/LF; the
    /// method returns row lists.
    /// </summary>
    private static IReadOnlyList<IReadOnlyList<string>> ParseCsvRows(string text)
    {
        var rows = new List<IReadOnlyList<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var inQuotes = false;

        for (var index = 0; index < text.Length; index++)
        {
            var ch = text[index];
            if (ch == '"')
            {
                if (inQuotes && index + 1 < text.Length && text[index + 1] == '"')
                {
                    field.Append('"');
                    index++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (ch == ',' && !inQuotes)
            {
                row.Add(field.ToString());
                field.Clear();
            }
            else if ((ch == '\r' || ch == '\n') && !inQuotes)
            {
                row.Add(field.ToString());
                field.Clear();
                if (row.Any(value => !string.IsNullOrWhiteSpace(value)))
                {
                    rows.Add(row.ToList());
                }

                row.Clear();
                if (ch == '\r' && index + 1 < text.Length && text[index + 1] == '\n')
                {
                    index++;
                }
            }
            else
            {
                field.Append(ch);
            }
        }

        if (field.Length > 0 || row.Count > 0)
        {
            row.Add(field.ToString());
            if (row.Any(value => !string.IsNullOrWhiteSpace(value)))
            {
                rows.Add(row.ToList());
            }
        }

        return rows;
    }

    /// <summary>
    /// Finds a CSV header index by case-insensitive names.
    /// Inputs are headers and candidate names; processing compares trimmed
    /// values; the method returns -1 when no header matches.
    /// </summary>
    private static int FindHeader(IReadOnlyList<string> headers, params string[] names)
    {
        for (var index = 0; index < headers.Count; index++)
        {
            if (names.Any(name => string.Equals(headers[index].Trim(), name, StringComparison.OrdinalIgnoreCase)))
            {
                return index;
            }
        }

        return -1;
    }

    /// <summary>
    /// Reads a CSV field by index.
    /// Inputs are row and index; processing handles missing indexes; returns a
    /// nullable trimmed value.
    /// </summary>
    private static string? GetCsvValue(IReadOnlyList<string> row, int index)
    {
        return index >= 0 && index < row.Count ? row[index].Trim() : null;
    }

    /// <summary>
    /// Reads a registry value kind without failing on access races.
    /// Inputs are registry key and value name; processing catches expected
    /// registry errors; the method returns a value-kind string or unknown.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string SafeGetValueKind(RegistryKey key, string valueName)
    {
        try
        {
            return key.GetValueKind(valueName).ToString();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return "unknown";
        }
    }

    /// <summary>
    /// Formats registry value payloads as strings.
    /// Inputs are a registry value object; processing handles string arrays and
    /// binary values; returns a compact display string.
    /// </summary>
    private static string? FormatRegistryValue(object? value)
    {
        return value switch
        {
            null => null,
            string[] values => string.Join(";", values),
            byte[] bytes => Convert.ToHexString(bytes),
            _ => value.ToString()
        };
    }

    /// <summary>
    /// Extracts text after the first colon.
    /// Inputs are a line; processing trims the suffix; returns null if absent.
    /// </summary>
    private static string? ValueAfterColon(string line)
    {
        var colon = line.IndexOf(':', StringComparison.Ordinal);
        return colon >= 0 && colon + 1 < line.Length ? line[(colon + 1)..].Trim() : null;
    }

    /// <summary>
    /// Creates a diagnostic event for unsupported system inventory sources.
    /// Inputs are event type and source; processing stores reason metadata; the
    /// method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateUnsupportedEvent(string eventType, string source)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["source"] = source,
                ["reason"] = "System inventory source is only available on Windows.",
                ["zhHint"] = "该系统清单来源仅在 Windows guest 中可用；在非 Windows 或受限环境中会跳过，不代表样本行为。"
            }
        };
    }

    /// <summary>
    /// Creates a diagnostic event from a helper-command result.
    /// Inputs are event type and command result; processing copies command,
    /// timeout, exit, stderr, and exception metadata; returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateCommandFailureEvent(string eventType, BoundedCommandResult result)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["command"] = Truncate(string.IsNullOrWhiteSpace(result.Arguments) ? result.FileName : $"{result.FileName} {result.Arguments}", 1200),
                ["commandFileName"] = result.FileName,
                ["commandArguments"] = Truncate(result.Arguments, 1024),
                ["timedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["timeoutMilliseconds"] = result.Timeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture)
            }
        };

        if (result.ExitCode is not null)
        {
            evt.Data["exitCode"] = result.ExitCode.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["commandExitCode"] = result.ExitCode.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "exceptionType", result.ExceptionType);
        AddIfNotEmpty(evt.Data, "commandExceptionType", result.ExceptionType);
        AddIfNotEmpty(evt.Data, "message", result.Message);
        AddIfNotEmpty(evt.Data, "commandMessage", result.Message);
        AddIfNotEmpty(evt.Data, "zhMessage", CommandFailureZhMessage(result));
        AddIfNotEmpty(evt.Data, "zhHint", "系统清单 helper 命令失败；请检查命令是否存在、权限是否足够，以及 stderr/exitCode/timeoutMilliseconds。");
        if (!string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            evt.Data["stdout"] = Truncate(result.StandardOutput.Trim(), 512);
            evt.Data["stdoutTruncated"] = (result.StandardOutput.Trim().Length > 512).ToString(CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(result.StandardError))
        {
            evt.Data["stderr"] = Truncate(result.StandardError.Trim(), 512);
            evt.Data["stderrTruncated"] = (result.StandardError.Trim().Length > 512).ToString(CultureInfo.InvariantCulture);
        }

        return evt;
    }

    /// <summary>
    /// Adds a string Data value when it is non-empty.
    /// Inputs are Data dictionary, key, and value; processing skips empty
    /// values; the method returns no value.
    /// </summary>
    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Creates a diagnostic event from an exception.
    /// Inputs are event type, path/source, and exception; processing copies
    /// exception details; returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateExceptionEvent(string eventType, string? path, Exception exception)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = path,
            Data =
            {
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message,
                ["zhMessage"] = "读取系统清单时发生异常；该诊断不会中断整体采集。",
                ["zhHint"] = "请结合 eventType、path、exceptionType/message 判断是权限、注册表、服务或文件系统访问问题。"
            }
        };
    }

    private static string CommandFailureZhMessage(BoundedCommandResult result)
    {
        if (result.TimedOut)
        {
            return "系统清单 helper 命令超时。";
        }

        if (result.ExceptionType is not null)
        {
            return "系统清单 helper 命令启动或读取输出失败。";
        }

        if (result.ExitCode is not null)
        {
            return $"系统清单 helper 命令以非零退出码 {result.ExitCode.Value.ToString(CultureInfo.InvariantCulture)} 结束。";
        }

        return string.Empty;
    }

    /// <summary>
    /// Truncates a string for compact event Data.
    /// Inputs are value and max length; processing appends an ellipsis marker
    /// when needed; the method returns a bounded string.
    /// </summary>
    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }
}

/// <summary>
/// Stores one visible process snapshot.
/// Inputs are process metadata from Toolhelp and Process APIs; processing is
/// immutable storage; records are returned to process tree and delta emitters.
/// </summary>
internal sealed record ProcessTreeSnapshot(
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    string? Path,
    DateTime? StartTimeUtc,
    int? SessionId,
    int? ThreadCount,
    int? BasePriority,
    string? ToolhelpImageName,
    string? CommandLine)
{
    public string Key => StartTimeUtc is null
        ? $"{ProcessId}:{ProcessName}"
        : $"{ProcessId}:{StartTimeUtc.Value.Ticks}:{ProcessName}";
}

/// <summary>
/// Stores the first and latest process snapshot seen by the probe so
/// short-lived or exited sample processes can still be represented in the
/// final event stream.
/// </summary>
internal sealed record ProcessTreeObservation(
    ProcessTreeSnapshot Snapshot,
    ProbePhase FirstSeenPhase,
    DateTimeOffset FirstSeenAtUtc,
    ProbePhase LastSeenPhase,
    DateTimeOffset LastSeenAtUtc,
    bool VisibleInAnySnapshot);

/// <summary>
/// Carries row-level process tree events plus counters for a single root
/// process sweep.
/// </summary>
internal sealed record ProcessTreeEventResult(
    IReadOnlyList<SandboxEvent> Events,
    IReadOnlyList<string> ProcessKeys,
    bool RootVisible,
    ProcessTreeSnapshot? RootProcess,
    int RootProcessId,
    int VisibleProcessCount,
    int DirectChildProcessCount,
    int MaxDepth,
    int OrphanedChildProcessCount);

/// <summary>
/// Root-relative process relationship metadata attached to process.snapshot
/// events for report rendering.
/// </summary>
internal sealed record ProcessTreeMetadata(
    int Depth,
    int ChildCount,
    string Lineage);

/// <summary>
/// Common contract for system-state inventory records.
/// Inputs are concrete inventory item properties; processing exposes a stable
/// key and signature for dictionary diffing.
/// </summary>
internal interface ISystemStateItemSnapshot
{
    string Key { get; }

    string Signature { get; }
}

/// <summary>
/// Stores one Windows service snapshot.
/// Inputs are sc.exe fields; processing exposes stable key/signature values for
/// diff events.
/// </summary>
internal sealed record ServiceStateSnapshot(
    string ServiceName,
    string? DisplayName,
    string State,
    string? StateCode,
    int? ProcessId,
    string RawSummary,
    string? ImagePath,
    string? StartType,
    string? ServiceType,
    string? ObjectName,
    string? ServiceDll) : ISystemStateItemSnapshot
{
    public string Key => ServiceName;

    public string Signature => string.Join(
        "|",
        DisplayName,
        State,
        StateCode,
        ProcessId?.ToString(CultureInfo.InvariantCulture),
        ImagePath,
        StartType,
        ServiceType,
        ObjectName,
        ServiceDll);
}

/// <summary>
/// Stores one scheduled task snapshot.
/// Inputs are schtasks CSV fields; processing exposes stable key/signature
/// values for task creation/deletion/modification diffs.
/// </summary>
internal sealed record ScheduledTaskStateSnapshot(
    string TaskName,
    string? Status,
    string? TaskToRun,
    string? NextRunTime,
    string? LastRunTime,
    string? Author,
    string RawSummary) : ISystemStateItemSnapshot
{
    public string Key => TaskName;

    public string Signature => string.Join("|", Status, TaskToRun, Author);
}

/// <summary>
/// Stores one registry or folder startup item snapshot.
/// Inputs are startup item location, name, value, type, and optional file
/// metadata; processing exposes stable key/signature values for diffs.
/// </summary>
internal sealed record StartupItemStateSnapshot(
    string Kind,
    string Location,
    string Name,
    string? Value,
    string? ValueKind,
    DateTime? LastWriteUtc,
    long? SizeBytes) : ISystemStateItemSnapshot
{
    public string Key => $"{Kind}:{Location}:{Name}";

    public string Signature => string.Join(
        "|",
        Value,
        ValueKind,
        LastWriteUtc?.Ticks.ToString(CultureInfo.InvariantCulture),
        SizeBytes?.ToString(CultureInfo.InvariantCulture));
}

/// <summary>
/// Stores one value from a key Windows Run/RunOnce autostart registry path.
/// Inputs are registry hive/path/view/value fields; processing exposes a stable
/// key/signature for dedicated registry.run diff events.
/// </summary>
internal sealed record RegistryRunValueSnapshot(
    string Hive,
    string KeyPath,
    string KeyName,
    string View,
    string ValueName,
    string? Value,
    string? ExpandedValue,
    string? ValueKind) : ISystemStateItemSnapshot
{
    public string Location => $"{Hive}\\{KeyPath} ({View})";

    public string Key => $"{Hive}:{KeyPath}:{View}:{ValueName}";

    public string Signature => string.Join("|", Value, ExpandedValue, ValueKind);
}

/// <summary>
/// Stores all system-change snapshots captured for one phase.
/// Inputs are services, scheduled tasks, startup items, and diagnostics;
/// processing is immutable storage returned by ISystemChangeSnapshotProvider.
/// </summary>
internal sealed record SystemChangeSnapshot(
    Dictionary<string, ServiceStateSnapshot> Services,
    Dictionary<string, ScheduledTaskStateSnapshot> ScheduledTasks,
    Dictionary<string, StartupItemStateSnapshot> StartupItems,
    Dictionary<string, RegistryRunValueSnapshot> RegistryRunValues,
    IReadOnlyList<SandboxEvent> Diagnostics)
{
    public static SystemChangeSnapshot Empty { get; } = new(
        new Dictionary<string, ServiceStateSnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, ScheduledTaskStateSnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, StartupItemStateSnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, RegistryRunValueSnapshot>(StringComparer.OrdinalIgnoreCase),
        []);
}
