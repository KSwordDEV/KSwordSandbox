using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Correlation;

/// <summary>
/// Promotes a filesystem watcher's otherwise ownerless file rows only when a
/// burst of encrypted-suffix creations is paired with deletion of the exact
/// original paths during a confirmed sample run. A suffix alone is not proof
/// of encryption, and a single create/delete pair is deliberately insufficient.
/// </summary>
public static class RansomwareFilePairClassifier
{
    private const string EncryptedSuffix = ".locked";
    private const int MinimumPairs = 5;
    private static readonly TimeSpan PairWindow = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan BurstWindow = TimeSpan.FromMinutes(2);

    public static List<SandboxEvent> Apply(IReadOnlyList<SandboxEvent> events)
    {
        var starts = events.Where(IsSampleStart).ToArray();
        if (starts.Length == 0)
        {
            return events as List<SandboxEvent> ?? events.ToList();
        }

        var deleted = events
            .Where(evt => IsWatcherFileEvent(evt, "file.deleted") && IsUserDataPath(evt.Path))
            .GroupBy(evt => Normalize(evt.Path), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);

        var pairs = new List<Pair>();
        var pairedOriginals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < events.Count; index++)
        {
            var created = events[index];
            if (!IsWatcherFileEvent(created, "file.created") ||
                !IsUserDataPath(created.Path) ||
                created.Path is null ||
                !created.Path.EndsWith(EncryptedSuffix, StringComparison.OrdinalIgnoreCase) ||
                !IsAlreadyCorrelatedSampleBehavior(created))
            {
                continue;
            }

            var original = Normalize(created.Path[..^EncryptedSuffix.Length]);
            if (pairedOriginals.Contains(original) || !deleted.TryGetValue(original, out var candidates))
            {
                continue;
            }

            var matchingDeletion = candidates.FirstOrDefault(evt =>
                AbsoluteDifference(evt.Timestamp, created.Timestamp) <= PairWindow &&
                IsInsideSampleWindow(evt.Timestamp, starts));
            if (matchingDeletion is null || !IsInsideSampleWindow(created.Timestamp, starts))
            {
                continue;
            }

            // Multiple watcher notifications for one replacement and its one
            // deletion must contribute only one pair to the burst threshold.
            pairedOriginals.Add(original);
            pairs.Add(new Pair(index, created, matchingDeletion, original));
        }

        // Choose a bounded burst, rather than adding unrelated pairs over a
        // long-running job. Diverse original extensions keep a batch of
        // ordinary .locked temp files from satisfying the high-risk signal.
        var orderedPairs = pairs.OrderBy(pair => pair.Created.Timestamp).ToArray();
        Pair[]? burst = null;
        var extensionCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var right = 0;
        for (var first = 0; first <= orderedPairs.Length - MinimumPairs; first++)
        {
            while (right < orderedPairs.Length &&
                   orderedPairs[right].Created.Timestamp - orderedPairs[first].Created.Timestamp <= BurstWindow)
            {
                var extension = Extension(orderedPairs[right].OriginalPath);
                if (extension.Length > 0)
                {
                    extensionCounts[extension] = extensionCounts.GetValueOrDefault(extension) + 1;
                }
                right++;
            }

            if (right - first >= MinimumPairs && extensionCounts.Count >= 2)
            {
                burst = orderedPairs[first..right];
                break;
            }

            var leaving = Extension(orderedPairs[first].OriginalPath);
            if (leaving.Length > 0 && --extensionCounts[leaving] == 0)
            {
                extensionCounts.Remove(leaving);
            }
        }
        if (burst is null)
        {
            return events as List<SandboxEvent> ?? events.ToList();
        }

        var result = events.ToList();
        var matchedDirectories = new HashSet<string>(
            burst.Select(pair => Directory(pair.OriginalPath)),
            StringComparer.OrdinalIgnoreCase);
        foreach (var pair in burst)
        {
            var data = new Dictionary<string, string>(pair.Created.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["classification"] = "ransomware",
                ["behavior"] = "file-encryption",
                ["pairedOriginalPath"] = pair.OriginalPath,
                ["pairedDeletionUtc"] = pair.Deleted.Timestamp.ToUniversalTime().ToString("O"),
                ["pairBurstCount"] = burst.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["pairClassificationReason"] = "multiple-encrypted-suffix-creations-paired-with-original-deletions"
            };
            result[pair.Index] = pair.Created with { Data = data };
        }

        // The same ownerless watcher can see a note beside the transformed
        // files. Promote only a concrete note in a paired directory and in
        // the same burst window; general user-writable notes stay unknown.
        for (var index = 0; index < events.Count; index++)
        {
            var note = events[index];
            if (!IsWatcherFileEvent(note, "file.created") ||
                !IsRansomNoteName(note.Path) ||
                !matchedDirectories.Contains(Directory(Normalize(note.Path))) ||
                note.Timestamp < burst[0].Created.Timestamp - PairWindow ||
                note.Timestamp > burst[^1].Created.Timestamp + PairWindow)
            {
                continue;
            }

            var data = new Dictionary<string, string>(note.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["behaviorCounted"] = "true",
                ["sampleBehaviorCandidate"] = "true",
                ["nonbehavior"] = "false",
                ["notSampleBehavior"] = "false",
                ["sampleCorrelation"] = "probable",
                ["sampleCorrelationStatus"] = "probable",
                ["sampleCorrelationReason"] = "ransom-note-created-beside-paired-encrypted-file-burst",
                ["sampleCorrelationStrength"] = "probable",
                ["sampleConclusionPromoted"] = "true",
                ["pairBurstCount"] = burst.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
            };
            result[index] = note with { Data = data };
        }

        return result;
    }

    private static bool IsSampleStart(SandboxEvent evt) =>
        string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase) &&
        evt.ProcessId is > 0 &&
        Normalize(evt.Path).Contains(@"\incoming\", StringComparison.OrdinalIgnoreCase);

    private static bool IsWatcherFileEvent(SandboxEvent evt, string eventType) =>
        string.Equals(evt.EventType, eventType, StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("captureSource", out var source) &&
        string.Equals(source, "filesystem-watcher", StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("capturePhase", out var phase) &&
        string.Equals(phase, "during-run", StringComparison.OrdinalIgnoreCase);

    private static bool IsAlreadyCorrelatedSampleBehavior(SandboxEvent evt) =>
        evt.Data.TryGetValue("behaviorCounted", out var counted) &&
        string.Equals(counted, "true", StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("sampleCorrelation", out var correlation) &&
        (string.Equals(correlation, "probable", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(correlation, "confirmed", StringComparison.OrdinalIgnoreCase));

    private static bool IsInsideSampleWindow(DateTimeOffset timestamp, IReadOnlyList<SandboxEvent> starts) =>
        starts.Any(start => timestamp >= start.Timestamp && timestamp - start.Timestamp <= BurstWindow);

    private static bool IsUserDataPath(string? path)
    {
        var normalized = Normalize(path);
        return normalized.Length >= 4 && char.IsAsciiLetter(normalized[0]) &&
               normalized[1] == ':' && normalized[2] == '\\' &&
               normalized.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) &&
               !normalized.Contains(@"\KSwordSandbox\", StringComparison.OrdinalIgnoreCase) &&
               !normalized.Split('\\').Any(segment => segment is "." or "..");
    }

    private static bool IsRansomNoteName(string? path)
    {
        var name = FileName(Normalize(path));
        return name.Contains("HOW_TO_DECYPHER", StringComparison.OrdinalIgnoreCase) ||
               name.Contains("HOW_TO_DECIPHER", StringComparison.OrdinalIgnoreCase) ||
               name.Contains("HOW_TO_DECRYPT", StringComparison.OrdinalIgnoreCase);
    }

    private static string Normalize(string? path) => (path ?? string.Empty).Replace('/', '\\');

    private static string Directory(string path)
    {
        var index = path.LastIndexOf('\\');
        return index < 0 ? string.Empty : path[..index];
    }

    private static string FileName(string path)
    {
        var index = path.LastIndexOf('\\');
        return index < 0 ? path : path[(index + 1)..];
    }

    private static string Extension(string path)
    {
        var name = FileName(path);
        var index = name.LastIndexOf('.');
        return index < 0 ? string.Empty : name[index..];
    }

    private static TimeSpan AbsoluteDifference(DateTimeOffset left, DateTimeOffset right) =>
        left >= right ? left - right : right - left;

    private sealed record Pair(int Index, SandboxEvent Created, SandboxEvent Deleted, string OriginalPath);
}
