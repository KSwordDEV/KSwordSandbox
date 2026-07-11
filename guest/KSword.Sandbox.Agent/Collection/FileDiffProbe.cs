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
                events.Add(CreateFileEvent("file.created", context, path, snapshot, previous: null));
            }
            else if (previous != snapshot)
            {
                events.Add(CreateFileEvent("file.modified", context, path, snapshot, previous));
            }
        }

        foreach (var (path, previous) in baseline.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!current.ContainsKey(path))
            {
                events.Add(CreateFileEvent("file.deleted", context, path, current: null, previous));
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
        GuestProbeContext context,
        string path,
        FileStateSnapshot? current,
        FileStateSnapshot? previous)
    {
        var root = context.WorkingDirectory;
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = path,
            ProcessName = SampleProcessName(context.SamplePath),
            ProcessId = context.RootProcessId,
            Data =
            {
                ["phase"] = "after-run",
                ["capturePhase"] = "after-run",
                ["probePhase"] = "after-run",
                ["captureEnabled"] = "true",
                ["implemented"] = "true",
                ["capturePolicy"] = "always-on-working-directory-file-diff",
                ["droppedFileArtifactCopyPolicy"] = "explicit-opt-in-copy-after-run",
                ["artifactRelativePathStatus"] = "not-created-by-file-diff",
                ["evidenceRole"] = "dropped-file-candidate",
                ["collectionName"] = "file-diff",
                ["processRole"] = context.RootProcessId is null ? "sample-context" : "sample-root-context",
                ["samplePath"] = context.SamplePath,
                ["expectedRelativePath"] = "artifacts/dropped-files/**",
                ["root"] = root,
                ["sourcePath"] = path,
                ["guestFullPath"] = path,
                ["relativePath"] = SafeRelativePath(root, path),
                ["guestRelativePath"] = SafeRelativePath(root, path)
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
        AddIfNotEmpty(evt.Data, "rootProcessPath", context.RootProcessPath);
        AddIfNotEmpty(evt.Data, "rootCommandLine", context.RootCommandLine);

        if (current is not null)
        {
            evt.Data["sizeBytes"] = current.SizeBytes.ToString(CultureInfo.InvariantCulture);
            evt.Data["lastWriteUtc"] = current.LastWriteUtc.ToString("O", CultureInfo.InvariantCulture);
            AddFileHashEvidence(evt, path);
        }

        if (previous is not null)
        {
            evt.Data["previousSizeBytes"] = previous.SizeBytes.ToString(CultureInfo.InvariantCulture);
            evt.Data["previousLastWriteUtc"] = previous.LastWriteUtc.ToString("O", CultureInfo.InvariantCulture);
        }

        evt.Data["captureState"] = eventType.EndsWith(".deleted", StringComparison.OrdinalIgnoreCase) ? "deleted" : "observed";
        evt.Data["status"] = evt.Data["captureState"];
        evt.Data["nonfatal"] = "false";
        evt.Data["zhMessage"] = FileEventZhMessage(eventType);
        evt.Data["zhHint"] = FileEventZhHint(eventType);

        return evt;
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
                return;
            }

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            evt.Data["sha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
            evt.Data["hashAlgorithm"] = "sha256";
            evt.Data["hashStatus"] = "computed";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            evt.Data["hashStatus"] = "failed";
            evt.Data["hashExceptionType"] = ex.GetType().FullName ?? ex.GetType().Name;
            evt.Data["hashMessage"] = ex.Message;
        }
    }

    private static string FileEventZhMessage(string eventType)
    {
        return eventType switch
        {
            "file.created" => "样本工作目录内检测到新建文件；可能是掉落文件候选。",
            "file.modified" => "样本工作目录内检测到文件被修改。",
            "file.deleted" => "样本工作目录内检测到文件被删除。",
            _ => "文件变更事件已记录。"
        };
    }

    private static string FileEventZhHint(string eventType)
    {
        return eventType switch
        {
            "file.created" => "若启用 dropped-file 复制，后续 artifact.dropped_file.* 事件会给出 artifactRelativePath、sizeBytes 和 sha256。",
            "file.modified" => "请结合 relativePath、sizeBytes、sha256/hashStatus 与 previous* 字段判断文件内容变化。",
            "file.deleted" => "删除事件没有可下载文件；如复制被跳过，请查看 artifact.dropped_file.skipped 的 reason/zhHint。",
            _ => "请结合 relativePath、sizeBytes、sha256/hashStatus 和时间字段分析文件行为。"
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
