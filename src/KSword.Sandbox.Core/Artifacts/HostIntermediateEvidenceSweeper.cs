using System.Text.Json;

namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Describes one intermediate file found by <see cref="HostIntermediateEvidenceSweeper"/>.
/// </summary>
public sealed record SweptEvidenceEntry(string RelativePath, long SizeBytes, string Reason);

/// <summary>
/// Describes the outcome of one sweep pass over a job directory.
/// </summary>
public sealed record HostEvidenceSlimmingResult(
    bool RetainedEverything,
    long FreedBytes,
    IReadOnlyList<SweptEvidenceEntry> Deleted,
    string ManifestPath);

/// <summary>
/// Records host-side evidence eligible for a future, lossless compaction pass.
/// report.json embeds a bounded sample, and later imports still read rotated
/// R0 JSONL and raw ETL inputs. Deleting those files after the first report
/// would lose evidence and change a repeated import. Until compaction can
/// preserve and replay every raw stream, this pass retains all files and
/// writes an auditable host-evidence-slimming.json manifest beside report.json.
/// </summary>
public static class HostIntermediateEvidenceSweeper
{
    public const string ManifestFileName = "host-evidence-slimming.json";

    private static readonly JsonSerializerOptions ManifestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    /// <summary>
    /// Runs one audit pass over a job directory. Inputs are the job root,
    /// the retention switch, and the job id for the manifest; processing
    /// records candidate intermediates but retains them until a verified
    /// lossless archive and replay path exists.
    /// </summary>
    public static HostEvidenceSlimmingResult Sweep(string jobRoot, bool keepRawEvidence, Guid jobId)
    {
        var fullRoot = Path.GetFullPath(jobRoot);
        Directory.CreateDirectory(fullRoot);

        var retainedCandidates = new List<SweptEvidenceEntry>();
        foreach (var file in EnumerateCandidates(fullRoot))
        {
            var relativePath = Path.GetRelativePath(fullRoot, file.FullName);
            var reason = Classify(relativePath);
            if (reason is not null)
            {
                retainedCandidates.Add(new SweptEvidenceEntry(relativePath, SafeLength(file), reason));
            }
        }

        var manifestPath = Path.Combine(fullRoot, ManifestFileName);
        var manifest = new
        {
            schema = "ksword.sandbox.host-evidence-slimming",
            contractVersion = 2,
            jobId = jobId.ToString("D"),
            sweptAtUtc = DateTimeOffset.UtcNow,
            keepRawEvidence,
            retainedEverything = true,
            retentionReason = "raw-evidence-required-for-reimport",
            freedBytes = 0L,
            deleted = Array.Empty<SweptEvidenceEntry>(),
            deleteFailures = Array.Empty<SweptEvidenceEntry>(),
            retainedCandidates,
            retainedStreams = new[]
            {
                "events.json（guest 事件流 / guest event stream）",
                "driver-events.jsonl（R0 canonical guest stream）",
                "driver-events.part-*.jsonl（R0 rotated guest streams）",
                "*.etl（ETW and pktmon raw traces）",
                "report.json / report.html（限额采样后的事件与报告 / sampled events and reports）",
                "*.failure.json（失败 sidecar / failure sidecars）"
            }
        };

        File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, ManifestJsonOptions));
        return new HostEvidenceSlimmingResult(true, 0, Array.Empty<SweptEvidenceEntry>(), manifestPath);
    }

    /// <summary>
    /// Returns the sweep reason for one relative path, or null when the file
    /// is not a known host intermediate. Inputs are the job-relative path
    /// with either separator style; processing matches segment-based
    /// patterns so only the documented directories and file shapes qualify.
    /// </summary>
    public static string? Classify(string jobRelativePath)
    {
        var normalized = jobRelativePath.Replace('\\', '/');
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var fileName = segments.Length > 0 ? segments[^1] : string.Empty;

        // Host-side tracerpt decode output may be regenerated only if its
        // source ETL and successful import are both known to be retained.
        if (segments.Contains("host-etl-decode", StringComparer.OrdinalIgnoreCase))
        {
            return "host-decode-xml";
        }

        // Raw guest ETW trace, classified before this sweep runs.
        if (segments.Contains("etw-traces", StringComparer.OrdinalIgnoreCase) &&
            fileName.EndsWith(".etl", StringComparison.OrdinalIgnoreCase))
        {
            return "etw-trace-etl";
        }

        // pktmon ETL under diagnostics; parsed packet summaries stay in
        // packet-captures and in report rows.
        if (segments.Contains("packet-capture-diagnostics", StringComparer.OrdinalIgnoreCase) &&
            fileName.EndsWith(".etl", StringComparison.OrdinalIgnoreCase))
        {
            return "pktmon-etl";
        }

        // Rotated closed segments of the R0 JSONL stream. The canonical
        // driver-events.jsonl (active segment) and *.failure.json sidecars
        // never match this shape.
        if (fileName.StartsWith("driver-events.part-", StringComparison.OrdinalIgnoreCase) &&
            fileName.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            return "r0-rotated-segment";
        }

        return null;
    }

    private static IEnumerable<FileInfo> EnumerateCandidates(string fullRoot)
    {
        return Directory.EnumerateFiles(fullRoot, "*", SearchOption.AllDirectories)
            .Select(path => new FileInfo(path));
    }

    private static long SafeLength(FileInfo file)
    {
        try
        {
            file.Refresh();
            return file.Exists ? file.Length : 0;
        }
        catch (IOException)
        {
            return 0;
        }
    }
}
