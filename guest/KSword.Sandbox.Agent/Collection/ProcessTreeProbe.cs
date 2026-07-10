using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures process baselines, process deltas, and root process tree views.
/// Inputs are probe phases and a root process id from sample execution;
/// processing snapshots visible processes without requiring administrator
/// rights; CollectAsync returns normalized process events.
/// </summary>
internal sealed class ProcessTreeProbe : IGuestProbe
{
    private readonly IProcessSnapshotProvider snapshotProvider;
    private readonly HashSet<string> emittedNewProcessKeys = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<int, ProcessTreeSnapshot> baselineByPid = [];

    public ProcessTreeProbe()
        : this(new ProcessSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a process tree probe with an injectable snapshot provider.
    /// The input is a snapshot provider, processing stores it for future probe
    /// phases, and the constructor returns no value.
    /// </summary>
    public ProcessTreeProbe(IProcessSnapshotProvider snapshotProvider)
    {
        this.snapshotProvider = snapshotProvider;
    }

    public string ProbeId => "process-tree";

    /// <summary>
    /// Collects process baseline, delta, and tree events for one phase.
    /// Inputs are phase, guest context, and cancellation token; processing uses
    /// Toolhelp parent process identifiers when available and falls back to
    /// Process APIs; the method returns process.observed, process.new, and
    /// process.tree events.
    /// </summary>
    public Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var current = snapshotProvider.Capture();
        var events = new List<SandboxEvent>();
        if (phase == ProbePhase.BeforeStart)
        {
            baselineByPid = current;
            foreach (var process in current.Values.OrderBy(process => process.ProcessId).ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase))
            {
                events.Add(CreateProcessSnapshotEvent("process.observed", process, phase, rootProcessId: null, depth: null));
            }
        }
        else if (phase is ProbePhase.AfterStart or ProbePhase.AfterRun)
        {
            foreach (var process in current.Values.OrderBy(process => process.ProcessId).ThenBy(process => process.ProcessName, StringComparer.OrdinalIgnoreCase))
            {
                if (baselineByPid.TryGetValue(process.ProcessId, out var baseline) &&
                    string.Equals(baseline.ProcessName, process.ProcessName, StringComparison.OrdinalIgnoreCase))
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
        }

        return Task.FromResult<IReadOnlyList<SandboxEvent>>(events);
    }

    /// <summary>
    /// Creates process.tree events for the root process and visible descendants.
    /// Inputs are a process snapshot, root process id, and probe phase;
    /// processing walks parent identifiers breadth-first; the method returns
    /// deterministic tree events or an empty list when the root is unavailable.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateTreeEvents(
        IReadOnlyDictionary<int, ProcessTreeSnapshot> snapshot,
        int rootProcessId,
        ProbePhase phase)
    {
        if (!snapshot.TryGetValue(rootProcessId, out var root))
        {
            return [];
        }

        var childrenByParent = snapshot.Values
            .Where(process => process.ParentProcessId is not null)
            .GroupBy(process => process.ParentProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.OrderBy(process => process.ProcessId).ToList());

        var events = new List<SandboxEvent>();
        var queue = new Queue<(ProcessTreeSnapshot Process, int Depth)>();
        var visited = new HashSet<int>();
        queue.Enqueue((root, 0));

        while (queue.Count != 0)
        {
            var (process, depth) = queue.Dequeue();
            if (!visited.Add(process.ProcessId))
            {
                continue;
            }

            events.Add(CreateProcessSnapshotEvent("process.tree", process, phase, rootProcessId, depth));

            if (!childrenByParent.TryGetValue(process.ProcessId, out var children))
            {
                continue;
            }

            foreach (var child in children)
            {
                queue.Enqueue((child, depth + 1));
            }
        }

        return events;
    }

    /// <summary>
    /// Creates a normalized process event from one snapshot.
    /// Inputs are event type, snapshot data, phase, optional root process id,
    /// and optional tree depth; processing copies stable metadata into common
    /// fields and Data; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateProcessSnapshotEvent(
        string eventType,
        ProcessTreeSnapshot process,
        ProbePhase phase,
        int? rootProcessId,
        int? depth)
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

        if (rootProcessId is not null)
        {
            evt.Data["rootProcessId"] = rootProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (depth is not null)
        {
            evt.Data["treeDepth"] = depth.Value.ToString(CultureInfo.InvariantCulture);
        }

        return evt;
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
}

/// <summary>
/// Supplies process snapshots for process tree collection.
/// Inputs are none at call time; processing observes process identifiers,
/// parent identifiers, names, paths, and start times; Capture returns a
/// dictionary keyed by process id.
/// </summary>
internal interface IProcessSnapshotProvider
{
    Dictionary<int, ProcessTreeSnapshot> Capture();
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
    /// Inputs are none; processing prefers parent process ids from Toolhelp and
    /// enriches records with accessible Process properties; the method returns
    /// process snapshots keyed by pid.
    /// </summary>
    public Dictionary<int, ProcessTreeSnapshot> Capture()
    {
        var parentByPid = OperatingSystem.IsWindows()
            ? CaptureParentProcessIds()
            : new Dictionary<int, int>();

        return CaptureWithProcessApi(parentByPid);
    }

    /// <summary>
    /// Captures process parent identifiers through CreateToolhelp32Snapshot.
    /// Inputs are none; processing walks PROCESSENTRY32 records; the method
    /// returns pid-to-parent-pid mappings and tolerates snapshot failures.
    /// </summary>
    private static Dictionary<int, int> CaptureParentProcessIds()
    {
        var parents = new Dictionary<int, int>();
        var handle = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (handle == InvalidHandleValue)
        {
            return parents;
        }

        try
        {
            var entry = new ProcessEntry32
            {
                DwSize = (uint)Marshal.SizeOf<ProcessEntry32>()
            };

            if (!Process32First(handle, ref entry))
            {
                return parents;
            }

            do
            {
                parents[(int)entry.Th32ProcessId] = (int)entry.Th32ParentProcessId;
            }
            while (Process32Next(handle, ref entry));

            return parents;
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    /// <summary>
    /// Enriches process snapshots with names, executable paths, and start times.
    /// Inputs are optional parent pid mappings; processing reads each Process
    /// defensively because protected or exited targets can deny access; the
    /// method returns process snapshots keyed by process id.
    /// </summary>
    private static Dictionary<int, ProcessTreeSnapshot> CaptureWithProcessApi(IReadOnlyDictionary<int, int> parentByPid)
    {
        var snapshot = new Dictionary<int, ProcessTreeSnapshot>();

        try
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    var processName = TryReadProcessValue(process, static p => p.ProcessName, "unknown");
                    var path = TryReadProcessValue<string?>(process, static p => p.MainModule?.FileName, null);
                    var startTimeUtc = TryReadProcessValue<DateTime?>(process, static p => p.StartTime.ToUniversalTime(), null);
                    var parentProcessId = parentByPid.TryGetValue(process.Id, out var parent) && parent > 0
                        ? parent
                        : (int?)null;

                    snapshot[process.Id] = new ProcessTreeSnapshot(
                        process.Id,
                        parentProcessId,
                        processName,
                        path,
                        startTimeUtc);
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
/// Stores one visible process snapshot.
/// Inputs are process metadata from Toolhelp and Process APIs; processing is
/// immutable storage; records are returned to process tree and delta emitters.
/// </summary>
internal sealed record ProcessTreeSnapshot(
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    string? Path,
    DateTime? StartTimeUtc)
{
    public string Key => StartTimeUtc is null
        ? $"{ProcessId}:{ProcessName}"
        : $"{ProcessId}:{StartTimeUtc.Value.Ticks}:{ProcessName}";
}
