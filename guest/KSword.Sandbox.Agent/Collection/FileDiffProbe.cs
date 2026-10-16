using System.Collections.Concurrent;
using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures file edges under the sample working directory and common
/// persistence roots (AppData, ProgramData, and Startup). Inputs are
/// BeforeStart and AfterRun probe phases; processing records file length and
/// write-time metadata without administrator rights; CollectAsync returns
/// file.created, file.modified, file.renamed, and file.deleted events.
/// </summary>
internal sealed class FileDiffProbe : IGuestProbe
{
    private const int MaxQueuedWatcherEvents = 2048;
    private readonly IFileSnapshotProvider snapshotProvider;
    private Dictionary<string, FileStateSnapshot> baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<FileSystemChange> watcherChanges = new();
    private readonly ConcurrentDictionary<string, byte> queuedWatcherKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<WatcherError> watcherErrors = new();
    private readonly ConcurrentDictionary<string, byte> watcherKnownPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> watchers = [];
    private readonly HashSet<string> watchedRoots = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, FileStateSnapshot> lastKnownFileState = new(StringComparer.OrdinalIgnoreCase);
    private readonly object watcherGate = new();
    private long droppedWatcherChanges;
    private string? tempRoot;
    private string? workingRoot;

    public FileDiffProbe()
        : this(new FileSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a file diff probe with an injectable snapshot provider.
    /// The input is a snapshot provider, processing stores it for future probe
    /// phases, and the constructor returns no value.
    /// </summary>
    public FileDiffProbe(IFileSnapshotProvider snapshotProvider)
    {
        this.snapshotProvider = snapshotProvider;
    }

    public string ProbeId => "file-diff";

    /// <summary>
    /// Collects file delta events for one probe phase.
    /// Inputs are phase, guest context, and cancellation token; processing
    /// snapshots the working directory at BeforeStart and compares it after the
    /// sample run; the method returns normalized file events.
    /// </summary>
    public Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (phase == ProbePhase.BeforeStart)
        {
            DisposeWatchers();
            baseline = CaptureWatchedFiles(context, cancellationToken);
            lastKnownFileState.Clear();
            watcherKnownPaths.Clear();
            Interlocked.Exchange(ref droppedWatcherChanges, 0);
            foreach (var pair in baseline)
            {
                lastKnownFileState[pair.Key] = pair.Value;
                watcherKnownPaths[pair.Key] = 0;
            }

            StartWatchers(context);
            return Task.FromResult<IReadOnlyList<SandboxEvent>>([]);
        }

        if (phase is not (ProbePhase.DuringRun or ProbePhase.AfterRun))
        {
            return Task.FromResult<IReadOnlyList<SandboxEvent>>([]);
        }

        var current = CaptureWatchedFiles(context, cancellationToken);
        var events = new List<SandboxEvent>();
        var emittedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // FileSystemWatcher can report an internal buffer overflow when a
        // process creates/removes many files quickly.  Snapshot reconciliation
        // cannot recover the missing edge history, so retain an explicit
        // collection-health event instead of silently presenting a partial
        // file stream as complete.
        foreach (var watcherError in DrainWatcherErrors())
        {
            events.Add(CreateWatcherFailureEvent(phase, context, watcherError));
        }

        var droppedChanges = Interlocked.Exchange(ref droppedWatcherChanges, 0);
        if (droppedChanges > 0)
        {
            events.Add(CreateWatcherDroppedEvent(phase, context, droppedChanges));
        }

        // FileSystemWatcher is the primary edge source during the run. A
        // snapshot still runs as a reconciliation pass, but watcher rows are
        // emitted first so create -> rename -> delete sequences survive even
        // when no file exists by the next snapshot.
        foreach (var change in DrainWatcherChanges())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var eventType = change.Kind switch
            {
                WatcherChangeKind.Created => "file.created",
                WatcherChangeKind.Changed => "file.modified",
                WatcherChangeKind.Deleted => "file.deleted",
                WatcherChangeKind.Renamed => "file.renamed",
                _ => string.Empty
            };
            if (string.IsNullOrWhiteSpace(eventType) || !IsWatchedPath(change.Path))
            {
                continue;
            }

            // A Changed notification often follows Created. The create row
            // already carries the current hash/size, so suppress this one
            // duplicate while preserving later modifications.
            var key = $"{eventType}|{change.Path}|{change.OldPath}";
            if (!emittedKeys.Add(key))
            {
                continue;
            }

            var currentState = TryReadState(change.Path);
            var previousStatePath = change.Kind == WatcherChangeKind.Renamed && !string.IsNullOrWhiteSpace(change.OldPath)
                ? change.OldPath
                : change.Path;
            lastKnownFileState.TryGetValue(previousStatePath, out var previousState);
            if (change.Kind == WatcherChangeKind.Changed && currentState is null)
            {
                // A delayed Changed callback can arrive after a file was
                // renamed/deleted. The create/rename/delete edge is already
                // retained; do not turn the stale callback into a phantom
                // modification row.
                continue;
            }
            if (currentState is not null)
            {
                lastKnownFileState[change.Path] = currentState;
            }
            if (change.Kind == WatcherChangeKind.Deleted || change.Kind == WatcherChangeKind.Renamed)
            {
                lastKnownFileState.TryRemove(previousStatePath, out _);
            }
            if (change.Kind == WatcherChangeKind.Deleted)
            {
                watcherKnownPaths.TryRemove(change.Path, out _);
            }
            else if (change.Kind == WatcherChangeKind.Renamed && !string.IsNullOrWhiteSpace(change.OldPath))
            {
                watcherKnownPaths.TryRemove(change.OldPath, out _);
                watcherKnownPaths[change.Path] = 0;
            }

            var evt = CreateFileEvent(
                eventType,
                phase,
                context,
                change.Path,
                currentState,
                previousState);
            evt.Data["captureSource"] = "filesystem-watcher";
            evt.Data["watcherChangeKind"] = change.Kind.ToString().ToLowerInvariant();
            evt.Data["edgeCaptured"] = "true";
            evt.Data["transientState"] = currentState is null ? "not-present-at-drain" : "present-at-drain";
            if (!string.IsNullOrWhiteSpace(change.OldPath))
            {
                evt.Data["oldPath"] = change.OldPath;
                evt.Data["previousPath"] = change.OldPath;
                evt.Data["sourcePath"] = change.OldPath;
                evt.Data["destinationPath"] = change.Path;
            }
            events.Add(evt);
        }

        foreach (var (path, snapshot) in current.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!baseline.TryGetValue(path, out var previous))
            {
                var key = $"file.created|{path}|";
                if (emittedKeys.Add(key))
                {
                    events.Add(CreateFileEvent("file.created", phase, context, path, snapshot, previous: null));
                }
            }
            else if (previous != snapshot)
            {
                var key = $"file.modified|{path}|";
                if (emittedKeys.Add(key))
                {
                    events.Add(CreateFileEvent("file.modified", phase, context, path, snapshot, previous));
                }
            }

            lastKnownFileState[path] = snapshot;
        }

        foreach (var (path, previous) in baseline.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!current.ContainsKey(path))
            {
                var key = $"file.deleted|{path}|";
                if (emittedKeys.Add(key))
                {
                    events.Add(CreateFileEvent("file.deleted", phase, context, path, current: null, previous));
                }
                lastKnownFileState.TryRemove(path, out _);
            }
        }

        // Advance the comparison point after every in-flight poll. This keeps
        // short-lived create/modify/delete activity visible in the event
        // stream while preventing the same delta from being emitted again by
        // the final AfterRun sweep.
        baseline = current;

        if (phase == ProbePhase.AfterRun)
        {
            DisposeWatchers();
        }

        return Task.FromResult<IReadOnlyList<SandboxEvent>>(events);
    }

    private void StartWatchers(GuestProbeContext context)
    {
        workingRoot = context.WorkingDirectory;
        tempRoot = Environment.GetEnvironmentVariable("TEMP");
        TryAddWatcher(context.WorkingDirectory, includeSubdirectories: true);
        if (!string.IsNullOrWhiteSpace(tempRoot))
        {
            // One watcher on TEMP covers both direct KSwordSandbox-*.txt
            // files and fixture directories created after BeforeStart.
            TryAddWatcher(tempRoot, includeSubdirectories: true);
        }

        // Persistence commonly lands outside the sample directory.  Watch the
        // bounded user-writable roots that malware uses most often.  These
        // roots are edge-only: snapshots remain limited to the sample and
        // KSwordSandbox TEMP fixtures so a large profile cannot stall a run.
        foreach (var root in PersistenceWatchRoots())
        {
            TryAddWatcher(root, includeSubdirectories: true);
        }
    }

    private static IEnumerable<string> PersistenceWatchRoots()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddRoot(roots, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        AddRoot(roots, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        AddRoot(roots, Environment.GetEnvironmentVariable("PROGRAMDATA"));

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        AddRoot(roots, Path.Combine(roaming, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu);
        AddRoot(roots, Path.Combine(common, "Programs", "Startup"));
        return roots;

        static void AddRoot(HashSet<string> target, string? root)
        {
            if (!string.IsNullOrWhiteSpace(root) && Directory.Exists(root))
            {
                target.Add(root);
            }
        }
    }

    private void TryAddWatcher(string root, bool includeSubdirectories)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            return;
        }

        lock (watcherGate)
        {
            if (!watchedRoots.Add(root))
            {
                return;
            }

            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = includeSubdirectories,
                    NotifyFilter = NotifyFilters.FileName |
                                   NotifyFilters.DirectoryName |
                                   NotifyFilters.LastWrite |
                                   NotifyFilters.Size,
                    Filter = "*",
                    InternalBufferSize = 64 * 1024,
                    EnableRaisingEvents = true
                };
                watcher.Created += (_, args) => EnqueueWatcherChange(WatcherChangeKind.Created, args.FullPath, null);
                watcher.Changed += (_, args) => EnqueueWatcherChange(WatcherChangeKind.Changed, args.FullPath, null);
                watcher.Deleted += (_, args) => EnqueueWatcherChange(WatcherChangeKind.Deleted, args.FullPath, null);
                watcher.Renamed += (_, args) => EnqueueWatcherChange(WatcherChangeKind.Renamed, args.FullPath, args.OldFullPath);
                watcher.Error += (_, args) => EnqueueWatcherError(args.GetException(), root);
                watchers.Add(watcher);
            }
            catch (ArgumentException ex)
            {
                watchedRoots.Remove(root);
                EnqueueWatcherError(ex, root);
            }
            catch (IOException ex)
            {
                watchedRoots.Remove(root);
                EnqueueWatcherError(ex, root);
            }
            catch (InvalidOperationException ex)
            {
                watchedRoots.Remove(root);
                EnqueueWatcherError(ex, root);
            }
        }
    }

    private void EnqueueWatcherChange(WatcherChangeKind kind, string? path, string? oldPath)
    {
        if (string.IsNullOrWhiteSpace(path) || !IsWatchedPath(path))
        {
            return;
        }

        // FileSystemWatcher also reports directory notifications. The probe
        // is a file evidence lane; ignore directory creation/rename and only
        // accept a delete when that path was previously known as a file.
        if (kind is WatcherChangeKind.Created or WatcherChangeKind.Changed or WatcherChangeKind.Renamed)
        {
            if (Directory.Exists(path))
            {
                return;
            }
        }
        else if (kind == WatcherChangeKind.Deleted &&
                 !lastKnownFileState.ContainsKey(path) &&
                 !watcherKnownPaths.ContainsKey(path) &&
                 !File.Exists(path) &&
                 !IsLikelyPersistenceFilePath(path))
        {
            return;
        }

        if (kind is WatcherChangeKind.Created or WatcherChangeKind.Changed or WatcherChangeKind.Renamed)
        {
            watcherKnownPaths[path] = 0;
            if (!string.IsNullOrWhiteSpace(oldPath))
            {
                watcherKnownPaths[oldPath] = 0;
            }
        }

        var queueKey = WatcherChangeKey(kind, path, oldPath);
        // AppData and ProgramData can produce repeated Changed callbacks for a
        // single write. Coalesce an identical edge until the next drain so a
        // noisy profile cannot consume the bounded queue before the sample's
        // create/rename/delete edge is observed.
        if (!queuedWatcherKeys.TryAdd(queueKey, 0))
        {
            return;
        }

        while (watcherChanges.Count >= MaxQueuedWatcherEvents && watcherChanges.TryDequeue(out var dropped))
        {
            queuedWatcherKeys.TryRemove(WatcherChangeKey(dropped.Kind, dropped.Path, dropped.OldPath), out _);
            Interlocked.Increment(ref droppedWatcherChanges);
        }

        watcherChanges.Enqueue(new FileSystemChange(kind, path, oldPath));
    }

    private List<FileSystemChange> DrainWatcherChanges()
    {
        var changes = new List<FileSystemChange>();
        while (watcherChanges.TryDequeue(out var change))
        {
            queuedWatcherKeys.TryRemove(WatcherChangeKey(change.Kind, change.Path, change.OldPath), out _);
            changes.Add(change);
        }

        return changes;
    }

    private List<WatcherError> DrainWatcherErrors()
    {
        var errors = new List<WatcherError>();
        while (watcherErrors.TryDequeue(out var error))
        {
            errors.Add(error);
        }

        return errors;
    }

    private bool IsWatchedPath(string path)
    {
        bool underWorkingRoot;
        bool tempRootWatched;
        lock (watcherGate)
        {
            underWorkingRoot = watchedRoots.Any(root =>
                !string.Equals(root, tempRoot, StringComparison.OrdinalIgnoreCase) && IsPathUnderRoot(root, path));
            tempRootWatched = !string.IsNullOrWhiteSpace(tempRoot) && watchedRoots.Contains(tempRoot);
        }
        if (underWorkingRoot)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(tempRoot) || !tempRootWatched || !IsPathUnderRoot(tempRoot, path))
        {
            return false;
        }

        var relative = SafeRelativePath(tempRoot, path);
        return relative.StartsWith("KSwordSandbox-", StringComparison.OrdinalIgnoreCase) ||
               relative.Contains("KSwordSandboxFixture-", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPathUnderRoot(string root, string path)
    {
        try
        {
            var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var fullPath = Path.GetFullPath(path);
            return string.Equals(fullRoot, fullPath, StringComparison.OrdinalIgnoreCase) ||
                   fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                   fullPath.StartsWith(fullRoot + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private FileStateSnapshot? TryReadState(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var info = new FileInfo(path);
            return new FileStateSnapshot(info.Length, info.LastWriteTimeUtc);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void DisposeWatchers()
    {
        lock (watcherGate)
        {
            foreach (var watcher in watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch (ObjectDisposedException)
                {
                }
            }

            watchers.Clear();
            watchedRoots.Clear();
        }
        while (watcherChanges.TryDequeue(out _))
        {
        }
        queuedWatcherKeys.Clear();
        while (watcherErrors.TryDequeue(out _))
        {
        }
        Interlocked.Exchange(ref droppedWatcherChanges, 0);
        watcherKnownPaths.Clear();
        workingRoot = null;
    }

    private void EnqueueWatcherError(Exception? exception, string? root = null)
    {
        // Keep diagnostics bounded if a broken watcher repeatedly signals the
        // same condition; the first rows retain the exception detail needed to
        // diagnose the loss without allowing the queue to become another loss
        // source.
        while (watcherErrors.Count >= 32 && watcherErrors.TryDequeue(out _))
        {
        }

        watcherErrors.Enqueue(new WatcherError(exception, root));
    }

    private static string WatcherChangeKey(WatcherChangeKind kind, string path, string? oldPath)
    {
        return string.Concat(kind.ToString(), "|", path, "|", oldPath ?? string.Empty);
    }

    private bool IsLikelyPersistenceFilePath(string path)
    {
        if (!Path.HasExtension(path))
        {
            return false;
        }

        lock (watcherGate)
        {
            return watchedRoots.Any(root =>
                !string.Equals(root, tempRoot, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(root, workingRoot, StringComparison.OrdinalIgnoreCase) &&
                IsPathUnderRoot(root, path));
        }
    }

    private static SandboxEvent CreateWatcherFailureEvent(
        ProbePhase phase,
        GuestProbeContext context,
        WatcherError watcherError)
    {
        var exception = watcherError.Exception;
        var overflow = exception is InternalBufferOverflowException;
        var evt = new SandboxEvent
        {
            EventType = "file.watcher.failed",
            Source = "guest",
            ProcessName = null,
            ProcessId = null,
            Path = context.WorkingDirectory,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["captureSource"] = "filesystem-watcher",
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["collectionHealth"] = "true",
                ["nonfatal"] = "true",
                ["nonbehavior"] = "true",
                ["behaviorCounted"] = "false",
                ["reason"] = overflow ? "watcherBufferOverflow" : "watcherError",
                ["reasonCode"] = overflow ? "watcherBufferOverflow" : "watcherError",
                ["reasonCategory"] = "file-capture",
                ["capturePolicy"] = "always-on-configured-file-diff-roots",
                ["watchScope"] = "configured-file-roots",
                ["actorPidStatus"] = "unavailable-filesystem-watcher",
                ["samplePath"] = context.SamplePath,
                ["workingDirectory"] = context.WorkingDirectory,
                ["zhMessage"] = overflow
                    ? "文件实时监视器缓冲区溢出；部分瞬时文件边沿可能无法恢复。"
                    : "文件实时监视器发生错误；部分瞬时文件边沿可能无法恢复。",
                ["zhHint"] = "请结合快照中的 file.* 行和该采集健康事件判断文件证据是否完整。"
            }
        };

        if (exception is not null)
        {
            evt.Data["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name;
            evt.Data["exceptionMessage"] = exception.Message;
        }

        if (!string.IsNullOrWhiteSpace(watcherError.Root))
        {
            evt.Data["watchRoot"] = watcherError.Root;
        }

        return evt;
    }

    private static SandboxEvent CreateWatcherDroppedEvent(
        ProbePhase phase,
        GuestProbeContext context,
        long droppedChanges)
    {
        return new SandboxEvent
        {
            EventType = "file.watcher.dropped",
            Source = "guest",
            Path = context.WorkingDirectory,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["capturePhase"] = ToPhaseLabel(phase),
                ["captureSource"] = "filesystem-watcher",
                ["captureState"] = "degraded",
                ["status"] = "degraded",
                ["collectionHealth"] = "true",
                ["nonfatal"] = "true",
                ["nonbehavior"] = "true",
                ["behaviorCounted"] = "false",
                ["reason"] = "watcherQueueDrop",
                ["reasonCode"] = "watcherQueueDrop",
                ["reasonCategory"] = "file-capture",
                ["droppedWatcherChanges"] = droppedChanges.ToString(CultureInfo.InvariantCulture),
                ["capturePolicy"] = "always-on-configured-file-diff-roots",
                ["watchScope"] = "configured-file-roots",
                ["actorPidStatus"] = "unavailable-filesystem-watcher",
                ["samplePath"] = context.SamplePath,
                ["workingDirectory"] = context.WorkingDirectory,
                ["zhMessage"] = "文件实时监视器队列丢弃了部分变更边沿；文件证据不完整。",
                ["zhHint"] = "请结合 droppedWatcherChanges 判断文件事件是否存在采集缺口。"
            }
        };
    }

    private Dictionary<string, FileStateSnapshot> CaptureWatchedFiles(
        GuestProbeContext context,
        CancellationToken cancellationToken)
    {
        var merged = snapshotProvider.Capture(context.WorkingDirectory, cancellationToken);
        var tempRoot = Environment.GetEnvironmentVariable("TEMP");
        if (string.IsNullOrWhiteSpace(tempRoot) || !Directory.Exists(tempRoot))
        {
            return merged;
        }

        IEnumerable<string> fixtureDirectories;
        try
        {
            fixtureDirectories = Directory.EnumerateDirectories(tempRoot, "KSwordSandboxFixture-*", SearchOption.TopDirectoryOnly);
        }
        catch (IOException)
        {
            fixtureDirectories = Array.Empty<string>();
        }
        catch (UnauthorizedAccessException)
        {
            fixtureDirectories = Array.Empty<string>();
        }

        // The process-discovery and script fixtures write directly below TEMP
        // rather than inside a fixture directory. Include only the sandbox
        // namespace so a host temp directory cannot flood events.json.
        try
        {
            foreach (var path in Directory.EnumerateFiles(tempRoot, "KSwordSandbox-*.txt", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var info = new FileInfo(path);
                    merged[path] = new FileStateSnapshot(info.Length, info.LastWriteTimeUtc);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        foreach (var directory in fixtureDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var pair in snapshotProvider.Capture(directory, cancellationToken))
            {
                merged[pair.Key] = pair.Value;
            }
        }

        return merged;
    }

    /// <summary>
    /// Creates one normalized file delta event.
    /// Inputs are event type, root path, absolute path, current snapshot, and
    /// previous snapshot; processing stores common path fields and string Data;
    /// the method returns a SandboxEvent.
    /// </summary>
    private SandboxEvent CreateFileEvent(
        string eventType,
        ProbePhase phase,
        GuestProbeContext context,
        string path,
        FileStateSnapshot? current,
        FileStateSnapshot? previous)
    {
        var root = ResolveWatchRoot(path, context);
        var phaseLabel = phase switch
        {
            ProbePhase.DuringRun => "during-run",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.AfterStart => "after-start",
            _ => phase.ToString().ToLowerInvariant()
        };
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = path,
            ProcessName = null,
            ProcessId = null,
            Data =
            {
                ["phase"] = phaseLabel,
                ["capturePhase"] = phaseLabel,
                ["probePhase"] = phaseLabel,
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["capturePolicy"] = "always-on-configured-file-diff-roots",
                ["evidenceRole"] = "file-change",
                ["collectionName"] = "file-diff",
                ["processRole"] = "unknown-file-actor",
                ["actorPidStatus"] = "unavailable-filesystem-watcher",
                ["watchScope"] = WatchScope(root, context),
                ["samplePath"] = context.SamplePath,
                ["expectedRelativePath"] = "artifacts/dropped-files/**",
                ["root"] = root,
                ["sourcePath"] = path,
                ["guestFullPath"] = path,
                ["relativePath"] = SafeRelativePath(root, path),
                ["guestRelativePath"] = SafeRelativePath(root, path)
            }
        };

        AddIfNotEmpty(evt.Data, "processName", evt.ProcessName);

        if (current is not null)
        {
            evt.Data["sizeBytes"] = current.SizeBytes.ToString(CultureInfo.InvariantCulture);
            evt.Data["sizeBytesStatus"] = "computed";
            evt.Data["lastWriteUtc"] = current.LastWriteUtc.ToString("O", CultureInfo.InvariantCulture);
            AddFileHashEvidence(evt, path);
        }
        else
        {
            evt.Data["sizeBytes"] = string.Empty;
            evt.Data["sizeBytesStatus"] = "not-created";
            evt.Data["sha256"] = string.Empty;
            evt.Data["sha256Status"] = "not-created";
            evt.Data["hashStatus"] = "not-created";
        }

        if (previous is not null)
        {
            evt.Data["previousSizeBytes"] = previous.SizeBytes.ToString(CultureInfo.InvariantCulture);
            evt.Data["previousLastWriteUtc"] = previous.LastWriteUtc.ToString("O", CultureInfo.InvariantCulture);
        }

        evt.Data["captureState"] = eventType.EndsWith(".deleted", StringComparison.OrdinalIgnoreCase) ? "deleted" : "observed";
        evt.Data["status"] = evt.Data["captureState"];
        evt.Data["nonfatal"] = "false";
        evt.Data["operation"] = eventType;
        evt.Data["zhMessage"] = FileEventZhMessage(eventType);
        evt.Data["zhHint"] = FileEventZhHint(eventType);

        return evt;
    }

    private string ResolveWatchRoot(string path, GuestProbeContext context)
    {
        lock (watcherGate)
        {
            var match = watchedRoots
                .Where(root => IsPathUnderRoot(root, path))
                .OrderByDescending(root => root.Length)
                .FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(match))
            {
                return match;
            }
        }

        return path.StartsWith(context.WorkingDirectory, StringComparison.OrdinalIgnoreCase)
            ? context.WorkingDirectory
            : (tempRoot ?? context.WorkingDirectory);
    }

    private bool IsPersistenceRoot(string root)
    {
        return !string.Equals(root, tempRoot, StringComparison.OrdinalIgnoreCase) &&
               !watchedRoots.Any(candidate => string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase) &&
                                              candidate.Contains("KSwordSandbox", StringComparison.OrdinalIgnoreCase));
    }

    private string WatchScope(string root, GuestProbeContext context)
    {
        if (string.Equals(root, context.WorkingDirectory, StringComparison.OrdinalIgnoreCase))
        {
            return "sample-working-root";
        }

        if (string.Equals(root, tempRoot, StringComparison.OrdinalIgnoreCase))
        {
            return "sandbox-temp-fixture-root";
        }

        return IsPersistenceRoot(root) ? "persistence-root" : "configured-file-root";
    }

    /// <summary>
    /// Adds best-effort SHA-256 metadata to created/modified file events so
    /// dropped-file copy decisions can be traced even if later copy is skipped.
    /// </summary>
    private static void AddFileHashEvidence(SandboxEvent evt, string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                evt.Data["hashStatus"] = "missing";
                evt.Data["sha256"] = string.Empty;
                evt.Data["sha256Status"] = "missing";
                return;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            evt.Data["sha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            evt.Data["hashAlgorithm"] = "sha256";
            evt.Data["hashStatus"] = "computed";
            evt.Data["sha256Status"] = "computed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data.TryAdd("sha256", string.Empty);
            evt.Data["hashStatus"] = "failed";
            evt.Data["sha256Status"] = "failed";
            evt.Data["hashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["hashMessage"] = ex.Message;
        }
    }

    private static string FileEventZhMessage(string eventType)
    {
        return eventType switch
        {
            "file.created" => "受监视目录内检测到新建文件；请结合路径和归因字段判断是否为样本行为。",
            "file.modified" => "受监视目录内检测到文件被修改。",
            "file.deleted" => "受监视目录内检测到文件被删除。",
            "file.renamed" => "受监视目录内检测到文件被重命名。",
            _ => "文件变更事件已记录。"
        };
    }

    private static string FileEventZhHint(string eventType)
    {
        return eventType switch
        {
            "file.created" => "请结合 watchScope、actorPidStatus、relativePath、sizeBytes 与 sha256 判断文件归因。",
            "file.modified" => "请结合 watchScope、actorPidStatus、relativePath、sizeBytes、sha256/hashStatus 与 previous* 字段判断文件变化。",
            "file.deleted" => "删除事件保留路径和前一状态；请结合 watchScope 与 actorPidStatus 判断是否为样本行为。",
            "file.renamed" => "请结合 sourcePath、destinationPath、oldPath、previousPath 和 watchScope 判断重命名前后的文件关系。",
            _ => "请结合 watchScope、actorPidStatus、relativePath、sizeBytes、sha256/hashStatus 和时间字段分析文件行为。"
        };
    }

    /// <summary>
    /// Reads a display process name for sample-scoped file-diff events.
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

    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Computes a relative path without failing on malformed or cross-root paths.
    /// Inputs are a root path and file path; processing attempts Path.GetRelativePath
    /// and falls back to the absolute path; the method returns a display string.
    /// </summary>
    private static string SafeRelativePath(string root, string path)
    {
        try
        {
            return Path.GetRelativePath(root, path).Replace('\\', '/');
        }
        catch (ArgumentException)
        {
            return path;
        }
        catch (NotSupportedException)
        {
            return path;
        }
    }

    private static string ToPhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.AfterStart => "after-start",
            ProbePhase.DuringRun => "during-run",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString().ToLowerInvariant()
        };
    }
}

/// <summary>
/// Supplies file snapshots for file diff collection.
/// Inputs are a root directory and cancellation token; processing enumerates
/// files defensively; Capture returns file metadata keyed by full path.
/// </summary>
internal interface IFileSnapshotProvider
{
    Dictionary<string, FileStateSnapshot> Capture(string root, CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures file metadata under one directory tree.
/// Inputs are a root directory and cancellation token; processing records file
/// size and UTC last-write time while skipping inaccessible files; Capture
/// returns a case-insensitive dictionary keyed by full path.
/// </summary>
internal sealed class FileSnapshotProvider : IFileSnapshotProvider
{
    /// <summary>
    /// Captures file metadata under a root directory.
    /// Inputs are root and cancellation token; processing recursively enumerates
    /// files and tolerates IO/access races; the method returns a path snapshot.
    /// </summary>
    public Dictionary<string, FileStateSnapshot> Capture(string root, CancellationToken cancellationToken = default)
    {
        var files = new Dictionary<string, FileStateSnapshot>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            return files;
        }

        foreach (var path in EnumerateFilesSafe(root, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var info = new FileInfo(path);
                files[path] = new FileStateSnapshot(info.Length, info.LastWriteTimeUtc);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return files;
    }

    /// <summary>
    /// Enumerates files while tolerating inaccessible subtrees.
    /// Inputs are root path and cancellation token; processing uses an explicit
    /// directory stack to skip only failing branches; the method yields file paths.
    /// </summary>
    private static IEnumerable<string> EnumerateFilesSafe(string root, CancellationToken cancellationToken)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count != 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var directory = pending.Pop();
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(directory);
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            IEnumerable<string> children;
            try
            {
                children = Directory.EnumerateDirectories(directory);
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var child in children)
            {
                pending.Push(child);
            }
        }
    }
}

/// <summary>
/// Stores one file's size and timestamp for diff comparisons.
/// Inputs are FileInfo metadata; processing is immutable value storage; records
/// are returned from file snapshot providers and compared by value.
/// </summary>
internal sealed record FileStateSnapshot(long SizeBytes, DateTime LastWriteUtc);

/// <summary>
/// Represents one edge notification from a FileSystemWatcher.
/// Inputs are change kind, full path, and optional old path; processing keeps
/// transient create/rename/delete evidence until the next probe drain.
/// </summary>
internal sealed record FileSystemChange(WatcherChangeKind Kind, string Path, string? OldPath);

/// <summary>
/// Stores one FileSystemWatcher error until the next probe drain so capture
/// loss is represented as collection-health evidence rather than discarded.
/// </summary>
internal sealed record WatcherError(Exception? Exception, string? Root);

internal enum WatcherChangeKind
{
    Created,
    Changed,
    Deleted,
    Renamed
}
