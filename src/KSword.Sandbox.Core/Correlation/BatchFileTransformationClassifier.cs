using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Correlation;

/// <summary>
/// Corroborates ownerless watcher rows as a probable batch transformation of
/// user files. No family name, output suffix, or note filename is consulted.
/// The result describes an observed impact pattern, not a cryptographic proof
/// or a verified actor PID.
/// </summary>
public static class BatchFileTransformationClassifier
{
    private const int MinimumDistinctOriginals = 5;
    private static readonly TimeSpan PairWindow = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan BurstWindow = TimeSpan.FromMinutes(2);
    private static readonly HashSet<string> ContentDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"
    };

    public static List<SandboxEvent> Apply(IReadOnlyList<SandboxEvent> events)
    {
        // A provider or sample can supply arbitrary event metadata. Only this
        // classifier may assert the derived structural marker consumed by the
        // high-risk rule.
        var result = events.Select(ClearDerivedMarker).ToList();
        // SampleCorrelationClassifier runs before this classifier in the
        // product pipeline. Only its confirmed root launch may open a burst
        // window; an unrelated executable under incoming is insufficient.
        var starts = events.Where(IsConfirmedSampleStart)
            .OrderBy(evt => evt.Timestamp)
            .Take(1)
            .ToArray();
        if (starts.Length == 0)
        {
            return result;
        }

        var deletions = Index(events, "file.deleted");
        var modifications = Index(events, "file.modified");
        var creations = Index(events, "file.created");
        var candidates = new List<ConversionPair>();
        var seenOriginals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < events.Count; index++)
        {
            var output = events[index];
            if (!IsWatcher(output) ||
                output.EventType is not ("file.created" or "file.renamed") ||
                !IsUserContentPath(output.Path) ||
                !InsideSampleWindow(output.Timestamp, starts) ||
                !TryPayload(output, out var outputHash))
            {
                continue;
            }

            var outputPath = Normalize(output.Path);
            if (output.EventType == "file.renamed" &&
                TryDirectContentChangingRename(output, outputPath, starts[0].Timestamp, out var renamedOriginal) &&
                seenOriginals.Add(renamedOriginal))
            {
                // A pre-run baseline is the independent evidence here. The
                // watcher can drain after content has already changed, so a
                // later file.modified row may have the same post-change hash.
                candidates.Add(new ConversionPair(index, output, null, null, renamedOriginal,
                    "preexisting-original-renamed-and-content-changed"));
                continue;
            }

            var source = output.EventType == "file.created" ? deletions : modifications;
            foreach (var (originalPath, changes) in source)
            {
                if (seenOriginals.Contains(originalPath) ||
                    !IsAppendedSibling(originalPath, outputPath) ||
                    !HasOriginalExtension(originalPath))
                {
                    continue;
                }

                var originalChange = changes.FirstOrDefault(change =>
                    InsideSampleWindow(change.Timestamp, starts) &&
                    AbsoluteDifference(change.Timestamp, output.Timestamp) <= PairWindow &&
                    (output.EventType == "file.created" ||
                     TryPayload(change, out var originalHash) &&
                     !originalHash.Equals(outputHash, StringComparison.OrdinalIgnoreCase)));
                if (originalChange is null)
                {
                    continue;
                }

                string pattern;
                SandboxEvent? secondSource;
                if (output.EventType == "file.created")
                {
                    // A created sibling must be observed as a stable file and
                    // have a corroborating modification before the original
                    // disappears. A transient editor swap alone is insufficient.
                    secondSource = modifications.GetValueOrDefault(outputPath)?
                        .FirstOrDefault(change =>
                            InsideSampleWindow(change.Timestamp, starts) &&
                            AbsoluteDifference(change.Timestamp, output.Timestamp) <= PairWindow &&
                            TryPayload(change, out var modifiedHash) &&
                            modifiedHash.Equals(outputHash, StringComparison.OrdinalIgnoreCase));
                    pattern = "stable-sibling-created-and-original-deleted";
                }
                else
                {
                    // An editor normally renames its temporary file back to
                    // the original path. This pattern needs a distinct sibling
                    // destination, an observed temporary predecessor, and an
                    // independently modified original with different bytes.
                    var predecessor = output.Data.TryGetValue("previousPath", out var path)
                        ? Normalize(path)
                        : string.Empty;
                    secondSource = IsAppendedSibling(originalPath, predecessor) &&
                                   !predecessor.Equals(outputPath, StringComparison.OrdinalIgnoreCase)
                        ? creations.GetValueOrDefault(predecessor)?
                            .FirstOrDefault(change =>
                                change.Timestamp <= output.Timestamp &&
                                output.Timestamp - change.Timestamp <= PairWindow &&
                                InsideSampleWindow(change.Timestamp, starts))
                        : null;
                    pattern = "temporary-sibling-created-renamed-and-original-modified";
                }

                if (secondSource is null)
                {
                    continue;
                }

                seenOriginals.Add(originalPath);
                candidates.Add(new ConversionPair(index, output, originalChange, secondSource, originalPath, pattern));
                break;
            }
        }

        foreach (var directoryGroup in candidates.GroupBy(
                     candidate => Directory(candidate.OriginalPath), StringComparer.OrdinalIgnoreCase))
        {
            var ordered = directoryGroup.OrderBy(candidate => candidate.Output.Timestamp).ToArray();
            for (var first = 0; first <= ordered.Length - MinimumDistinctOriginals; first++)
            {
                var last = first;
                var originalExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                while (last < ordered.Length &&
                       ordered[last].Output.Timestamp - ordered[first].Output.Timestamp <= BurstWindow)
                {
                    originalExtensions.Add(Extension(ordered[last].OriginalPath));
                    last++;
                }

                if (last - first < MinimumDistinctOriginals || originalExtensions.Count < 2)
                {
                    continue;
                }

                var burst = ordered[first..last];
                foreach (var pair in burst)
                {
                    var data = new Dictionary<string, string>(pair.Output.Data, StringComparer.OrdinalIgnoreCase)
                    {
                        ["behaviorCounted"] = "true",
                        ["sampleBehaviorCandidate"] = "true",
                        ["nonbehavior"] = "false",
                        ["notSampleBehavior"] = "false",
                        ["sampleCorrelation"] = "probable",
                        ["sampleCorrelationStatus"] = "probable",
                        ["sampleCorrelationStrength"] = "probable",
                        ["sampleCorrelationReason"] = "independent-watcher-file-conversion-burst-inside-sample-window",
                        ["sampleConclusionPromoted"] = "true",
                        ["batchConversionVerified"] = "true",
                        ["classification"] = "mass-file-transformation",
                        ["behavior"] = "probable-batch-file-conversion",
                        ["pairedOriginalPath"] = pair.OriginalPath,
                        ["conversionPattern"] = pair.Pattern,
                        ["pairBurstCount"] = burst.Length.ToString(CultureInfo.InvariantCulture),
                        ["attributionLimit"] = "watcher-has-no-actor-pid; cryptographic-encryption-not-proved"
                    };
                    if (pair.OriginalChange is not null)
                    {
                        data["pairedOriginalChangeUtc"] = pair.OriginalChange.Timestamp.ToUniversalTime().ToString("O");
                    }
                    if (pair.SecondSource is not null)
                    {
                        data["pairedSupportingEventUtc"] = pair.SecondSource.Timestamp.ToUniversalTime().ToString("O");
                    }
                    result[pair.Index] = pair.Output with { Data = data };
                }
                break;
            }
        }

        return result;
    }

    private static Dictionary<string, SandboxEvent[]> Index(IReadOnlyList<SandboxEvent> events, string eventType) =>
        events.Where(evt => evt.EventType.Equals(eventType, StringComparison.OrdinalIgnoreCase) &&
                            IsWatcher(evt) && IsUserContentPath(evt.Path))
            .GroupBy(evt => Normalize(evt.Path), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);

    private static SandboxEvent ClearDerivedMarker(SandboxEvent evt)
    {
        if (!evt.Data.ContainsKey("batchConversionVerified"))
        {
            return evt;
        }

        var data = new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase);
        data.Remove("batchConversionVerified");
        return evt with { Data = data };
    }

    private static bool IsWatcher(SandboxEvent evt) =>
        evt.Data.TryGetValue("captureSource", out var source) &&
        source.Equals("filesystem-watcher", StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("capturePhase", out var phase) &&
        phase.Equals("during-run", StringComparison.OrdinalIgnoreCase);

    private static bool IsConfirmedSampleStart(SandboxEvent evt) =>
        evt.EventType.Equals("process.start", StringComparison.OrdinalIgnoreCase) &&
        evt.ProcessId is > 0 &&
        Normalize(evt.Path).Contains(@"\incoming\", StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("sampleCorrelationClassifier", out var classifier) &&
        classifier.Equals("core-sample-correlation-v1", StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("sampleCorrelation", out var correlation) &&
        correlation.Equals("confirmed", StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("strongSampleCorrelation", out var strong) &&
        bool.TryParse(strong, out var isStrong) && isStrong &&
        evt.Data.TryGetValue("actorProcessId", out var actorPid) &&
        int.TryParse(actorPid, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedPid) &&
        parsedPid == evt.ProcessId &&
        evt.Data.TryGetValue("actorProcessImagePath", out var actorPath) &&
        Normalize(actorPath).Equals(Normalize(evt.Path), StringComparison.OrdinalIgnoreCase);

    private static bool InsideSampleWindow(DateTimeOffset timestamp, IReadOnlyList<SandboxEvent> starts) =>
        starts.Any(start => timestamp >= start.Timestamp && timestamp - start.Timestamp <= BurstWindow);

    private static bool IsUserContentPath(string? path)
    {
        var normalized = Normalize(path);
        if (normalized.Length < 4 || !char.IsAsciiLetter(normalized[0]) ||
            normalized[1] != ':' || normalized[2] != '\\' ||
            normalized.Contains(@"\KSwordSandbox\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var segments = normalized.Split('\\');
        if (segments.Any(segment => segment is "" or "." or ".."))
        {
            return false;
        }

        for (var index = 0; index + 2 < segments.Length; index++)
        {
            if (segments[index].Equals("Users", StringComparison.OrdinalIgnoreCase) &&
                ContentDirectories.Contains(segments[index + 2]))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsAppendedSibling(string original, string output) =>
        output.Length > original.Length + 1 &&
        output.StartsWith(original + ".", StringComparison.OrdinalIgnoreCase) &&
        Directory(output).Equals(Directory(original), StringComparison.OrdinalIgnoreCase) &&
        output[(original.Length + 1)..] is { Length: > 0 and <= 32 } tail &&
        !tail.Contains('\\') && !tail.Contains('/');

    private static bool TryDirectContentChangingRename(
        SandboxEvent output,
        string outputPath,
        DateTimeOffset sampleStart,
        out string originalPath)
    {
        originalPath = output.Data.TryGetValue("previousPath", out var previousPath)
            ? Normalize(previousPath)
            : string.Empty;
        if (!IsUserContentPath(originalPath) || !HasOriginalExtension(originalPath) ||
            !IsAppendedSibling(originalPath, outputPath) ||
            !DataEquals(output, "contentBaselineStatus", "captured") ||
            !DataEquals(output, "baselineHashStatus", "computed") ||
            !DataEquals(output, "hashStatus", "computed") ||
            !DataEquals(output, "contentChangeComparisonState", "compared") ||
            !DataEquals(output, "contentChangedFromBaseline", "true") ||
            !DataEquals(output, "previousPathAbsentAtDrain", "true") ||
            !output.Data.TryGetValue("baselineSha256", out var baselineHash) ||
            !IsSha256(baselineHash) ||
            !output.Data.TryGetValue("sha256", out var outputHash) ||
            !IsSha256(outputHash) ||
            baselineHash.Equals(outputHash, StringComparison.OrdinalIgnoreCase) ||
            !output.Data.TryGetValue("baselineSizeBytes", out var baselineSize) ||
            !long.TryParse(baselineSize, NumberStyles.Integer, CultureInfo.InvariantCulture, out var beforeBytes) ||
            beforeBytes <= 0 ||
            !output.Data.TryGetValue("baselineCapturedAtUtc", out var capturedAt) ||
            !DateTimeOffset.TryParse(capturedAt, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out var baselineAt) ||
            baselineAt > sampleStart)
        {
            return false;
        }

        return true;
    }

    private static bool DataEquals(SandboxEvent evt, string key, string expected) =>
        evt.Data.TryGetValue(key, out var value) &&
        value.Equals(expected, StringComparison.OrdinalIgnoreCase);

    private static bool IsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static bool HasOriginalExtension(string path) => Extension(path).Length > 1;

    private static bool TryPayload(SandboxEvent evt, out string hash)
    {
        hash = evt.Data.TryGetValue("sha256", out var value) ? value : string.Empty;
        return hash.Length == 64 && hash.All(Uri.IsHexDigit) &&
               evt.Data.TryGetValue("sizeBytes", out var size) &&
               long.TryParse(size, NumberStyles.Integer, CultureInfo.InvariantCulture, out var bytes) && bytes > 0;
    }

    private static TimeSpan AbsoluteDifference(DateTimeOffset left, DateTimeOffset right) =>
        left >= right ? left - right : right - left;

    private static string Normalize(string? path) => (path ?? string.Empty).Replace('/', '\\');

    private static string Directory(string path)
    {
        var index = path.LastIndexOf('\\');
        return index < 0 ? string.Empty : path[..index];
    }

    private static string Extension(string path)
    {
        var name = path[(path.LastIndexOf('\\') + 1)..];
        var index = name.LastIndexOf('.');
        return index < 0 ? string.Empty : name[index..];
    }

    private sealed record ConversionPair(
        int Index,
        SandboxEvent Output,
        SandboxEvent? OriginalChange,
        SandboxEvent? SecondSource,
        string OriginalPath,
        string Pattern);
}
