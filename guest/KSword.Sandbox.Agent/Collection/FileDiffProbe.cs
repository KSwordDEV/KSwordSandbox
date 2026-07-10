using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures and compares file state under the sample working directory.
/// Inputs are BeforeStart and AfterRun probe phases; processing records file
/// length and write-time metadata without administrator rights; CollectAsync
/// returns file.created, file.modified, and file.deleted events.
/// </summary>
internal sealed class FileDiffProbe : IGuestProbe
{
    private readonly IFileSnapshotProvider snapshotProvider;
    private Dictionary<string, FileStateSnapshot> baseline = new(StringComparer.OrdinalIgnoreCase);

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
            baseline = snapshotProvider.Capture(context.WorkingDirectory, cancellationToken);
            return Task.FromResult<IReadOnlyList<SandboxEvent>>([]);
        }

        if (phase != ProbePhase.AfterRun)
        {
            return Task.FromResult<IReadOnlyList<SandboxEvent>>([]);
        }

        var current = snapshotProvider.Capture(context.WorkingDirectory, cancellationToken);
        var events = new List<SandboxEvent>();

        foreach (var (path, snapshot) in current.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!baseline.TryGetValue(path, out var previous))
            {
                events.Add(CreateFileEvent("file.created", context.WorkingDirectory, path, snapshot, previous: null));
            }
            else if (previous != snapshot)
            {
                events.Add(CreateFileEvent("file.modified", context.WorkingDirectory, path, snapshot, previous));
            }
        }

        foreach (var (path, previous) in baseline.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!current.ContainsKey(path))
            {
                events.Add(CreateFileEvent("file.deleted", context.WorkingDirectory, path, current: null, previous));
            }
        }

        return Task.FromResult<IReadOnlyList<SandboxEvent>>(events);
    }

    /// <summary>
    /// Creates one normalized file delta event.
    /// Inputs are event type, root path, absolute path, current snapshot, and
    /// previous snapshot; processing stores common path fields and string Data;
    /// the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateFileEvent(
        string eventType,
        string root,
        string path,
        FileStateSnapshot? current,
        FileStateSnapshot? previous)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = path,
            Data =
            {
                ["root"] = root,
                ["relativePath"] = SafeRelativePath(root, path)
            }
        };

        if (current is not null)
        {
            evt.Data["sizeBytes"] = current.SizeBytes.ToString(CultureInfo.InvariantCulture);
            evt.Data["lastWriteUtc"] = current.LastWriteUtc.ToString("O", CultureInfo.InvariantCulture);
        }

        if (previous is not null)
        {
            evt.Data["previousSizeBytes"] = previous.SizeBytes.ToString(CultureInfo.InvariantCulture);
            evt.Data["previousLastWriteUtc"] = previous.LastWriteUtc.ToString("O", CultureInfo.InvariantCulture);
        }

        return evt;
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
            return Path.GetRelativePath(root, path);
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
