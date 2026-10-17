using System.Net;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Runs a deterministic, no-sample collector exercise. The harness feeds
/// scripted snapshots to the guest probes and performs one local file rename
/// sequence, so smoke tests can prove that short-lived edges become explicit
/// rows without starting a sample or a VM.
/// </summary>
public static class GuestCollectorSyntheticDiagnostics
{
    /// <summary>
    /// Exercises process, TCP, file, task, service, and registry edge lanes.
    /// The method returns every normalized row produced by the scripted probes
    /// so callers can assert both edge presence and loss diagnostics.
    /// </summary>
    public static async Task<GuestCollectorSyntheticDiagnosticsResult> RunAsync(
        CancellationToken cancellationToken = default)
    {
        var root = Path.Combine(Path.GetTempPath(), "KSwordSandboxSyntheticEdges", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var context = CreateContext(root);
            var events = new List<SandboxEvent>();

            var systemBaseline = CreateSystemSnapshot(
                service: Service("SyntheticOld", "old-image.exe"),
                task: TaskSnapshot("\\Synthetic\\Old", "old-task.exe"),
                registry: Registry("Old", "old-value.exe"));
            var systemAfter = CreateSystemSnapshot(
                service: Service("SyntheticNew", "new-image.exe"),
                task: TaskSnapshot("\\Synthetic\\New", "new-task.exe"),
                registry: Registry("New", "new-value.exe"));
            var processProbe = new ProcessTreeProbe(
                new ScriptedProcessSnapshotProvider(ProcessSnapshots()),
                new ScriptedSystemSnapshotProvider([systemBaseline, systemAfter]));
            events.AddRange(await processProbe.CollectAsync(ProbePhase.BeforeStart, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(await processProbe.CollectAsync(ProbePhase.DuringRun, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(await processProbe.CollectAsync(ProbePhase.DuringRun, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(await processProbe.CollectAsync(ProbePhase.AfterRun, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(processProbe.CollectSyntheticScheduledTaskEdgeDiagnostics(context));

            var tcpProbe = new TcpConnectionDiffProbe(
                new ScriptedTcpSnapshotProvider(TcpSnapshots()),
                new EmptyNetworkStateSnapshotProvider());
            events.AddRange(await tcpProbe.CollectAsync(ProbePhase.BeforeStart, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(await tcpProbe.CollectAsync(ProbePhase.DuringRun, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(await tcpProbe.CollectAsync(ProbePhase.DuringRun, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(await tcpProbe.CollectAsync(ProbePhase.AfterRun, context, cancellationToken).ConfigureAwait(false));

            var fileProbe = new FileDiffProbe();
            events.AddRange(await fileProbe.CollectAsync(ProbePhase.BeforeStart, context, cancellationToken).ConfigureAwait(false));
            var created = Path.Combine(root, "edge-before.txt");
            var renamed = Path.Combine(root, "edge-after.txt");
            await File.WriteAllTextAsync(created, "synthetic-edge", cancellationToken).ConfigureAwait(false);
            File.Move(created, renamed);
            File.Delete(renamed);
            // FileSystemWatcher callbacks are asynchronous. This wait is local
            // filesystem synchronization; it never launches a sample or VM.
            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            events.AddRange(await fileProbe.CollectAsync(ProbePhase.DuringRun, context, cancellationToken).ConfigureAwait(false));
            events.AddRange(await fileProbe.CollectAsync(ProbePhase.AfterRun, context, cancellationToken).ConfigureAwait(false));

            return new GuestCollectorSyntheticDiagnosticsResult(
                ProcessChildObservedThenMissing: HasProcessExitEvidence(events),
                TcpOpenedAndClosed: HasTcpOpenCloseEvidence(events),
                FileRenameAndDeleteCaptured: HasFileRenameDeleteEvidence(events),
                ScheduledTaskEdgeCaptured: HasTaskEdgeEvidence(events),
                ServiceAndRegistryDiffCaptured: HasServiceRegistryEvidence(events),
                Events: events);
        }
        finally
        {
            try
            {
                if (Directory.Exists(root))
                {
                    Directory.Delete(root, recursive: true);
                }
            }
            catch (IOException)
            {
                // Synthetic diagnostics are best effort and must not hide the
                // evidence rows produced before cleanup.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static bool HasProcessExitEvidence(IEnumerable<SandboxEvent> events)
    {
        return events.Any(evt => evt.EventType == "process.new" && evt.ProcessId == 101) &&
               events.Any(evt => evt.EventType == "process.snapshot" && evt.ProcessId == 101 &&
                                 evt.Data.TryGetValue("processExited", out var exited) && exited == "true");
    }

    private static bool HasTcpOpenCloseEvidence(IEnumerable<SandboxEvent> events)
    {
        return events.Any(evt => evt.EventType == "network.tcp" && evt.Data.GetValueOrDefault("change") == "opened") &&
               events.Any(evt => evt.EventType == "network.tcp.closed" && evt.Data.GetValueOrDefault("change") == "closed") &&
               events.Any(evt => evt.EventType == "network.tcp.edge_poll.summary" &&
                                 evt.Data.GetValueOrDefault("openedEdgeCount") == "1" &&
                                 evt.Data.GetValueOrDefault("closedEdgeCount") == "1");
    }

    private static bool HasFileRenameDeleteEvidence(IEnumerable<SandboxEvent> events)
    {
        return events.Any(evt => evt.EventType == "file.renamed" && evt.Data.GetValueOrDefault("edgeCaptured") == "true") &&
               events.Any(evt => evt.EventType == "file.deleted" && evt.Data.GetValueOrDefault("edgeCaptured") == "true");
    }

    private static bool HasTaskEdgeEvidence(IEnumerable<SandboxEvent> events)
    {
        return events.Any(evt => evt.EventType == "scheduled_task.created" && evt.Data.GetValueOrDefault("edgeCaptured") == "true") &&
               events.Any(evt => evt.EventType == "scheduled_task.modified" && evt.Data.GetValueOrDefault("oldTaskName") is not null) &&
               events.Any(evt => evt.EventType == "scheduled_task.deleted" && evt.Data.GetValueOrDefault("captureState") == "deleted");
    }

    private static bool HasServiceRegistryEvidence(IEnumerable<SandboxEvent> events)
    {
        return events.Any(evt => evt.EventType == "service.deleted") &&
               events.Any(evt => evt.EventType == "service.created" && evt.Data.GetValueOrDefault("imagePath") == "new-image.exe") &&
               events.Any(evt => evt.EventType == "registry.run.deleted") &&
               events.Any(evt => evt.EventType == "registry.run.created" && evt.Data.GetValueOrDefault("value") == "new-value.exe");
    }

    private static GuestProbeContext CreateContext(string root)
    {
        return new GuestProbeContext
        {
            SamplePath = Path.Combine(root, "synthetic-sample.exe"),
            WorkingDirectory = root,
            OutputDirectory = root,
            RootProcessId = 100,
            RootParentProcessId = 1,
            RootProcessName = "synthetic-root",
            RootProcessPath = Path.Combine(root, "synthetic-sample.exe"),
            RootCommandLine = "synthetic-root --edge-contract"
        };
    }

    private static IEnumerable<Dictionary<int, ProcessTreeSnapshot>> ProcessSnapshots()
    {
        var root = Process(100, null, "synthetic-root");
        var child = Process(101, 100, "short-lived-child");
        yield return new Dictionary<int, ProcessTreeSnapshot> { [100] = root };
        yield return new Dictionary<int, ProcessTreeSnapshot> { [100] = root, [101] = child };
        yield return new Dictionary<int, ProcessTreeSnapshot> { [100] = root };
        yield return new Dictionary<int, ProcessTreeSnapshot> { [100] = root };
    }

    private static IEnumerable<Dictionary<string, TcpConnectionSnapshot>> TcpSnapshots()
    {
        var edge = new TcpConnectionSnapshot(
            new IPEndPoint(IPAddress.Loopback, 43111),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443),
            "Established",
            101,
            "synthetic-owner");
        yield return new Dictionary<string, TcpConnectionSnapshot>(StringComparer.OrdinalIgnoreCase);
        yield return new Dictionary<string, TcpConnectionSnapshot>(StringComparer.OrdinalIgnoreCase) { [edge.Key] = edge };
        yield return new Dictionary<string, TcpConnectionSnapshot>(StringComparer.OrdinalIgnoreCase);
        yield return new Dictionary<string, TcpConnectionSnapshot>(StringComparer.OrdinalIgnoreCase);
    }

    private static ProcessTreeSnapshot Process(int pid, int? parent, string name)
    {
        return new ProcessTreeSnapshot(pid, parent, name, $"C:\\Synthetic\\{name}.exe", null, null, 1, 8, name + ".exe", name);
    }

    private static ServiceStateSnapshot Service(string name, string image)
    {
        return new ServiceStateSnapshot(name, name, "RUNNING", "4", 101, name, image, "auto", "own", "LocalSystem", null);
    }

    private static ScheduledTaskStateSnapshot TaskSnapshot(string name, string command)
    {
        return new ScheduledTaskStateSnapshot(name, "Ready", command, null, null, "synthetic", command);
    }

    private static RegistryRunValueSnapshot Registry(string name, string value)
    {
        return new RegistryRunValueSnapshot("HKCU", "Software\\Synthetic", "Synthetic", "64", name, value, value, "String");
    }

    private static SystemChangeSnapshot CreateSystemSnapshot(
        ServiceStateSnapshot service,
        ScheduledTaskStateSnapshot task,
        RegistryRunValueSnapshot registry)
    {
        return new SystemChangeSnapshot(
            new Dictionary<string, ServiceStateSnapshot>(StringComparer.OrdinalIgnoreCase) { [service.Key] = service },
            new Dictionary<string, ScheduledTaskStateSnapshot>(StringComparer.OrdinalIgnoreCase) { [task.Key] = task },
            new Dictionary<string, StartupItemStateSnapshot>(StringComparer.OrdinalIgnoreCase),
            new Dictionary<string, RegistryRunValueSnapshot>(StringComparer.OrdinalIgnoreCase) { [registry.Key] = registry },
            []);
    }

    private sealed class ScriptedProcessSnapshotProvider(IEnumerable<Dictionary<int, ProcessTreeSnapshot>> snapshots) : IProcessSnapshotProvider
    {
        private readonly Queue<Dictionary<int, ProcessTreeSnapshot>> queue = new(snapshots);
        public Dictionary<int, ProcessTreeSnapshot> Capture(CancellationToken cancellationToken = default) => Next(cancellationToken);
        public Dictionary<int, ProcessTreeSnapshot> CaptureFast(CancellationToken cancellationToken = default) => Next(cancellationToken);
        private Dictionary<int, ProcessTreeSnapshot> Next(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return queue.Count == 0 ? [] : queue.Dequeue();
        }
    }

    private sealed class ScriptedSystemSnapshotProvider(IEnumerable<SystemChangeSnapshot> snapshots) : ISystemChangeSnapshotProvider
    {
        private readonly Queue<SystemChangeSnapshot> queue = new(snapshots);
        public Task<SystemChangeSnapshot> CaptureAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(queue.Count == 0 ? SystemChangeSnapshot.Empty : queue.Dequeue());
        }
    }

    private sealed class ScriptedTcpSnapshotProvider(IEnumerable<Dictionary<string, TcpConnectionSnapshot>> snapshots) : ITcpConnectionSnapshotProvider
    {
        private readonly Queue<Dictionary<string, TcpConnectionSnapshot>> queue = new(snapshots);
        public Dictionary<string, TcpConnectionSnapshot> Capture() => queue.Count == 0 ? [] : queue.Dequeue();
    }

    private sealed class EmptyNetworkStateSnapshotProvider : INetworkStateSnapshotProvider
    {
        public Task<NetworkStateSnapshot> CaptureAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(NetworkStateSnapshot.Empty);
        }
    }
}

/// <summary>
/// Summarizes the synthetic guest edge exercise and retains its rows for smoke
/// diagnostics. All booleans describe observable evidence, not a live sample.
/// </summary>
public sealed record GuestCollectorSyntheticDiagnosticsResult(
    bool ProcessChildObservedThenMissing,
    bool TcpOpenedAndClosed,
    bool FileRenameAndDeleteCaptured,
    bool ScheduledTaskEdgeCaptured,
    bool ServiceAndRegistryDiffCaptured,
    IReadOnlyList<SandboxEvent> Events);
