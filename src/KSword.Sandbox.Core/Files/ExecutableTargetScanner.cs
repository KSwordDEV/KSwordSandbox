using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Files;

/// <summary>
/// Scans host files and directories for executable analysis targets.
/// Inputs are local paths from the WebUI, processing performs bounded recursive
/// enumeration with access-error tolerance, and the method returns candidate
/// executable metadata for user selection.
/// </summary>
public sealed class ExecutableTargetScanner
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe"
    };

    /// <summary>
    /// Scans one file or directory for executable candidates.
    /// Inputs are a scan request, processing validates the path and enumerates
    /// up to the configured limits, and the method returns a scan result.
    /// </summary>
    public ExecutableScanResult Scan(ExecutableScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Path))
        {
            throw new ArgumentException("Path is required.", nameof(request));
        }

        var fullPath = Path.GetFullPath(request.Path);
        var maxDepth = Math.Clamp(request.MaxDepth, 0, 16);
        var maxResults = Math.Clamp(request.MaxResults, 1, 2000);
        var warnings = new List<string>();

        if (File.Exists(fullPath))
        {
            var candidate = TryCreateCandidate(fullPath, warnings);
            return new ExecutableScanResult
            {
                RootPath = fullPath,
                RootIsFile = true,
                Candidates = candidate is null ? [] : [candidate],
                Warnings = warnings
            };
        }

        if (!Directory.Exists(fullPath))
        {
            throw new DirectoryNotFoundException($"Path does not exist: {fullPath}");
        }

        var candidates = ScanDirectory(fullPath, maxDepth, maxResults, warnings)
            .OrderBy(candidate => candidate.FullPath, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ExecutableScanResult
        {
            RootPath = fullPath,
            RootIsFile = false,
            Candidates = candidates,
            Warnings = warnings
        };
    }

    /// <summary>
    /// Performs bounded breadth-first directory scanning.
    /// Inputs are a root directory and scan limits, processing tolerates access
    /// errors and stops at maxResults, and the method returns candidates.
    /// </summary>
    private static List<ExecutableCandidate> ScanDirectory(string root, int maxDepth, int maxResults, List<string> warnings)
    {
        var candidates = new List<ExecutableCandidate>();
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));

        while (queue.Count > 0 && candidates.Count < maxResults)
        {
            var (current, depth) = queue.Dequeue();
            foreach (var file in EnumerateFiles(current, warnings))
            {
                if (candidates.Count >= maxResults)
                {
                    warnings.Add($"Result limit {maxResults} reached; scan stopped early.");
                    break;
                }

                var candidate = TryCreateCandidate(file, warnings);
                if (candidate is not null)
                {
                    candidates.Add(candidate);
                }
            }

            if (depth >= maxDepth)
            {
                continue;
            }

            foreach (var directory in EnumerateDirectories(current, warnings))
            {
                queue.Enqueue((directory, depth + 1));
            }
        }

        return candidates;
    }

    /// <summary>
    /// Enumerates files in one directory without throwing access exceptions.
    /// Inputs are a directory path and warning list, processing catches expected
    /// IO failures, and the method returns zero or more file paths.
    /// </summary>
    private static IEnumerable<string> EnumerateFiles(string directory, List<string> warnings)
    {
        try
        {
            return Directory.EnumerateFiles(directory, "*.exe", SearchOption.TopDirectoryOnly).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            warnings.Add($"Cannot enumerate files in {directory}: {ex.Message}");
            return [];
        }
    }

    /// <summary>
    /// Enumerates subdirectories without throwing access exceptions.
    /// Inputs are a directory path and warning list, processing catches expected
    /// IO failures, and the method returns zero or more directory paths.
    /// </summary>
    private static IEnumerable<string> EnumerateDirectories(string directory, List<string> warnings)
    {
        try
        {
            return Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            warnings.Add($"Cannot enumerate directories in {directory}: {ex.Message}");
            return [];
        }
    }

    /// <summary>
    /// Converts one executable path to candidate metadata.
    /// Inputs are a file path and warning list, processing validates extension
    /// and reads file metadata, and the method returns a candidate or null.
    /// </summary>
    private static ExecutableCandidate? TryCreateCandidate(string path, List<string> warnings)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || !ExecutableExtensions.Contains(info.Extension))
            {
                return null;
            }

            return new ExecutableCandidate
            {
                FileName = info.Name,
                FullPath = info.FullName,
                SizeBytes = info.Length,
                LastWriteTimeUtc = info.LastWriteTimeUtc
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Cannot read file metadata for {path}: {ex.Message}");
            return null;
        }
    }
}
