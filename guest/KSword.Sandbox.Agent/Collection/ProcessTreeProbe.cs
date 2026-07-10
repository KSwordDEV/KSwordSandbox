using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using System.Text;
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
    private const string ServiceCreatedEventType = "service.created";
    private const string ServiceModifiedEventType = "service.modified";
    private const string ServiceDeletedEventType = "service.deleted";
    private const string ScheduledTaskCreatedEventType = "scheduled_task.created";
    private const string ScheduledTaskModifiedEventType = "scheduled_task.modified";
    private const string ScheduledTaskDeletedEventType = "scheduled_task.deleted";
    private const string StartupItemCreatedEventType = "startup_item.created";
    private const string StartupItemModifiedEventType = "startup_item.modified";
    private const string StartupItemDeletedEventType = "startup_item.deleted";
    private readonly IProcessSnapshotProvider snapshotProvider;
    private readonly ISystemChangeSnapshotProvider systemChangeSnapshotProvider;
    private readonly HashSet<string> emittedNewProcessKeys = new(StringComparer.OrdinalIgnoreCase);
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

        var current = snapshotProvider.Capture(cancellationToken);
        var events = new List<SandboxEvent>();
        if (phase == ProbePhase.BeforeStart)
        {
            emittedNewProcessKeys.Clear();
            baselineByPid = current;
            baselineSystemState = await systemChangeSnapshotProvider.CaptureAsync(cancellationToken).ConfigureAwait(false);

            events.Add(CreateEnvironmentDetailEvent(context));
            events.AddRange(CreateSystemSnapshotEvents(baselineSystemState, phase));
            events.AddRange(WithPhase(baselineSystemState.Diagnostics, phase));

            foreach (var process in current.Values.OrderBy(process => process.ProcessId).ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                events.Add(CreateProcessSnapshotEvent("process.observed", process, phase, rootProcessId: null, depth: null));
            }
        }
        else if (phase is ProbePhase.AfterStart or ProbePhase.AfterRun)
        {
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

                events.Add(CreateProcessSnapshotEvent("process.new", process, phase, context.RootProcessId, depth: null));
            }

            if (context.RootProcessId is not null)
            {
                events.AddRange(CreateTreeEvents(current, context.RootProcessId.Value, phase));
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
    /// Creates process.tree events for the root process and visible descendants.
    /// Inputs are a process snapshot, root process id, and probe phase;
    /// processing walks parent identifiers breadth-first and annotates lineage;
    /// the method returns deterministic tree events or an empty list.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateTreeEvents(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        int rootProcessId,
        ProbePhase phase)
    {
        if (!snapshot.TryGetValue(rootProcessId, out var root))
        {
            return
            [
                new SandboxEvent
                {
                    EventType = "process.tree_unavailable",
                    Source = "guest",
                    ProcessId = rootProcessId,
                    Data =
                    {
                        ["phase"] = ToPhaseLabel(phase),
                        ["rootProcessId"] = rootProcessId.ToString(CultureInfo.InvariantCulture),
                        ["reason"] = "Root process was not visible in the current process snapshot."
                    }
                }
            ];
        }

        var childrenByParent = snapshot.Values
            .Where(process => process.ParentProcessId is not null)
            .GroupBy(process => process.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.OrderBy(process => process.ProcessId).ToList());

        var events = new List<SandboxEvent>();
        var queue = new Queue<(ProcessTreeSnapshot Process, int Depth, string Lineage)>();
        var visited = new HashSet<int>();
        queue.Enqueue((root, 0, root.ProcessId.ToString(CultureInfo.InvariantCulture)));

        while (queue.Count != 0)
        {
            var (process, depth, lineage) = queue.Dequeue();
            if (!visited.Add(process.ProcessId))
            {
                continue;
            }

            var childCount = childrenByParent.TryGetValue(process.ProcessId, out var children) ? children.Count : 0;
            events.Add(CreateProcessSnapshotEvent("process.tree", process, phase, rootProcessId, depth, childCount, lineage));

            if (childCount == 0 || children is null)
            {
                continue;
            }

            foreach (var child in children)
            {
                queue.Enqueue((child, depth + 1, $"{lineage}>{child.ProcessId.ToString(CultureInfo.InvariantCulture)}"));
            }
        }

        return events;
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
        string? lineage = null)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessName = process.ProcessName,
            ProcessId = process.ProcessId,
            ParentProcessId = process.ParentProcessId,
            Path = process.Path,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["snapshotKey"] = process.Key
            }
        };

        if (process.StartTimeUtc is not null)
        {
            evt.Data["startTimeUtc"] = process.StartTimeUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (process.ParentProcessId is not null)
        {
            evt.Data["parentProcessId"] = process.ParentProcessId.Value.ToString(CultureInfo.InvariantCulture);
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

        AddIfNotEmpty(evt.Data, "toolhelpImageName", process.ToolhelpImageName);

        if (rootProcessId is not null)
        {
            evt.Data["rootProcessId"] = rootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (depth is not null)
        {
            evt.Data["treeDepth"] = depth.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (childCount is not null)
        {
            evt.Data["childProcessCount"] = childCount.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "treeLineage", lineage);
        return evt;
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
    /// and phase; processing copies service identity, state, and PID metadata;
    /// the method returns a SandboxEvent.
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
        if (service.ProcessId is not null)
        {
            evt.Data["serviceProcessId"] = service.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (previous is not null)
        {
            AddIfNotEmpty(evt.Data, "previousState", previous.State);
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

        return CaptureWithProcessApi(toolhelpByPid, cancellationToken);
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
    /// Enriches process snapshots with names, executable paths, start times, and
    /// sessions. Inputs are optional Toolhelp metadata and cancellation token;
    /// processing reads each Process defensively because protected/exited
    /// targets can deny access; the method returns snapshots keyed by process id.
    /// </summary>
    private static Dictionary<int, ProcessTreeSnapshot> CaptureWithProcessApi(
        IReadOnlyDictionary<int, ToolhelpProcessInfo> toolhelpByPid,
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
                    var processName = TryReadProcessValue(process, static p => p.ProcessName, "unknown");
                    var path = TryReadProcessValue<string?>(process, static p => p.MainModule?.FileName, null);
                    var startTimeUtc = TryReadProcessValue<DateTime?>(process, static p => p.StartTime.ToUniversalTime(), null);
                    var sessionId = TryReadProcessValue<int?>(process, static p => p.SessionId, null);
                    toolhelpByPid.TryGetValue(process.Id, out var toolhelp);
                    var parentProcessId = toolhelp is not null && toolhelp.ParentProcessId > 0
                        ? toolhelp.ParentProcessId
                        : (int?)null;

                    snapshot[process.Id] = new ProcessTreeSnapshot(
                        process.Id,
                        parentProcessId,
                        processName,
                        path,
                        startTimeUtc,
                        sessionId,
                        toolhelp?.ThreadCount,
                        toolhelp?.BasePriority,
                        toolhelp?.ImageName);
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

    private static readonly IntPtr InvalidHandleValue = new(-1);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private sealed record ToolhelpProcessInfo(
        int ParentProcessId,
        int ThreadCount,
        int BasePriority,
        string? ImageName);

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
        var startupItems = CaptureStartupItems(diagnostics, cancellationToken);
        return new SystemChangeSnapshot(services, scheduledTasks, startupItems, diagnostics);
    }

    /// <summary>
    /// Captures service state through sc.exe queryex.
    /// Inputs are diagnostics and cancellation token; processing parses service
    /// names, display names, states, and PIDs; returns a keyed dictionary.
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

        return ParseServices(result.StandardOutput);
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
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        var items = new Dictionary<string, StartupItemStateSnapshot>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows())
        {
            diagnostics.Add(CreateUnsupportedEvent("startup_item.capture_skipped", "registry and Startup folders"));
            return items;
        }

        CaptureRegistryStartupItems(items, diagnostics, cancellationToken);
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
            Truncate(string.Join(" | ", rawLines.Take(6)), 512));
        services[service.Key] = service;
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
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        var views = Environment.Is64BitOperatingSystem
            ? [RegistryView.Registry64, RegistryView.Registry32]
            : new[] { RegistryView.Default };
        var keys = new[]
        {
            (RegistryHive.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        };

        foreach (var view in views)
        {
            foreach (var (hive, hiveLabel, subKeyPath) in keys)
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
                        var valueKind = SafeGetValueKind(key, valueName);
                        var name = string.IsNullOrWhiteSpace(valueName) ? "(Default)" : valueName;
                        var location = $"{hiveLabel}\\{subKeyPath} ({view})";
                        var item = new StartupItemStateSnapshot(
                            "registry",
                            location,
                            name,
                            FormatRegistryValue(value),
                            valueKind,
                            LastWriteUtc: null,
                            SizeBytes: null);
                        items[item.Key] = item;
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException)
                {
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
                ["reason"] = "System inventory source is only available on Windows."
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
                ["command"] = string.IsNullOrWhiteSpace(result.Arguments) ? result.FileName : $"{result.FileName} {result.Arguments}",
                ["timedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["timeoutMilliseconds"] = result.Timeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture)
            }
        };

        if (result.ExitCode is not null)
        {
            evt.Data["exitCode"] = result.ExitCode.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfNotEmpty(evt.Data, "exceptionType", result.ExceptionType);
        AddIfNotEmpty(evt.Data, "message", result.Message);
        if (!string.IsNullOrWhiteSpace(result.StandardError))
        {
            evt.Data["stderr"] = Truncate(result.StandardError.Trim(), 512);
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
                ["message"] = exception.Message
            }
        };
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
    string? ToolhelpImageName)
{
    public string Key => StartTimeUtc is null
        ? $"{ProcessId}:{ProcessName}"
        : $"{ProcessId}:{StartTimeUtc.Value.Ticks}:{ProcessName}";
}

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
    string RawSummary) : ISystemStateItemSnapshot
{
    public string Key => ServiceName;

    public string Signature => string.Join("|", DisplayName, State, StateCode, ProcessId?.ToString(CultureInfo.InvariantCulture));
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
/// Stores all system-change snapshots captured for one phase.
/// Inputs are services, scheduled tasks, startup items, and diagnostics;
/// processing is immutable storage returned by ISystemChangeSnapshotProvider.
/// </summary>
internal sealed record SystemChangeSnapshot(
    Dictionary<string, ServiceStateSnapshot> Services,
    Dictionary<string, ScheduledTaskStateSnapshot> ScheduledTasks,
    Dictionary<string, StartupItemStateSnapshot> StartupItems,
    IReadOnlyList<SandboxEvent> Diagnostics)
{
    public static SystemChangeSnapshot Empty { get; } = new(
        new Dictionary<string, ServiceStateSnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, ScheduledTaskStateSnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, StartupItemStateSnapshot>(StringComparer.OrdinalIgnoreCase),
        []);
}
