using System.Text;
using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Reads the Agent's during-run JSONL only when final events.json is absent or
/// unusable. The identity sidecar is checked against host-pinned job metadata;
/// a journal is partial evidence and never upgrades collection health.
/// </summary>
public static class GuestLiveEventJournalReader
{
    public const string JournalFileName = "live-events.jsonl";
    public const string IdentityFileName = "live-events.identity.json";
    private const long MaxJournalBytes = 64L * 1024 * 1024;
    private const int MaxIdentityBytes = 4096;
    private const int MaxLineBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static IReadOnlyList<SandboxEvent> ReadValidated(
        string journalPath,
        Guid expectedJobId,
        string expectedSampleSha256,
        long expectedSampleSizeBytes,
        string? expectedGuestSamplePath = null)
    {
        if (expectedJobId == Guid.Empty || !IsSha256(expectedSampleSha256) || expectedSampleSizeBytes < 0 ||
            !string.Equals(Path.GetFileName(journalPath), JournalFileName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Invalid live journal import identity or path.");
        }

        var fullPath = Path.GetFullPath(journalPath);
        var folder = Path.GetDirectoryName(fullPath) ?? throw new InvalidDataException("Journal has no parent folder.");
        var identityPath = Path.Combine(folder, IdentityFileName);
        RejectReparseAncestors(fullPath);
        RejectReparseAncestors(identityPath);
        var identityInfo = new FileInfo(identityPath);
        if (!identityInfo.Exists || identityInfo.Length is <= 0 or > MaxIdentityBytes)
        {
            throw new InvalidDataException("Live journal identity sidecar is missing or oversized.");
        }

        string samplePath;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(identityPath));
            var root = document.RootElement;
            var schema = root.GetProperty("schema").GetString();
            var jobId = root.GetProperty("jobId").GetString();
            var sha256 = root.GetProperty("sampleSha256").GetString();
            var sizeBytes = root.GetProperty("sampleSizeBytes").GetInt64();
            samplePath = root.GetProperty("samplePath").GetString() ?? string.Empty;
            var format = root.GetProperty("eventFormat").GetString();
            if (schema != "ksword-live-events-v1" ||
                !Guid.TryParse(jobId, out var parsedJobId) || parsedJobId != expectedJobId ||
                !IsSha256(sha256) || !sha256!.Equals(expectedSampleSha256, StringComparison.OrdinalIgnoreCase) ||
                sizeBytes != expectedSampleSizeBytes || !Path.IsPathFullyQualified(samplePath) ||
                (expectedGuestSamplePath is not null &&
                 !string.Equals(samplePath, expectedGuestSamplePath, StringComparison.OrdinalIgnoreCase)) ||
                format != "SandboxEvent-jsonl")
            {
                throw new InvalidDataException("Live journal identity does not match the pinned job/sample.");
            }
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new InvalidDataException("Live journal identity sidecar is malformed.", ex);
        }

        ValidateOptionalGuestIdentity(Path.Combine(folder, "setup-result.json"),
            samplePath, expectedSampleSha256, expectedSampleSizeBytes, "sampleLength");
        ValidateOptionalGuestIdentity(Path.Combine(folder, "sample-launch-proof.json"),
            samplePath, expectedSampleSha256, expectedSampleSizeBytes, "sampleSizeBytes");

        var info = new FileInfo(fullPath);
        if (!info.Exists || info.Length is < 0 or > MaxJournalBytes)
        {
            throw new InvalidDataException("Live journal is missing or oversized.");
        }

        // A crash may interrupt the last JSON object. Only complete newline-
        // terminated rows are accepted. The writer flushes after each batch.
        var rows = new List<SandboxEvent>();
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
        var endsWithNewline = false;
        if (stream.Length > 0)
        {
            stream.Seek(-1, SeekOrigin.End);
            endsWithNewline = stream.ReadByte() == '\n';
            stream.Seek(0, SeekOrigin.Begin);
        }
        using var reader = new StreamReader(stream);
        string? pending = null;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (pending is not null)
            {
                ParseCompleteRow(pending, samplePath, rows);
            }
            pending = line;
        }
        if (endsWithNewline && pending is not null)
        {
            ParseCompleteRow(pending, samplePath, rows);
        }
        return rows;
    }

    private static void ParseCompleteRow(string line, string samplePath, List<SandboxEvent> rows)
    {
        if (line.Length == 0) return;
        if (Encoding.UTF8.GetByteCount(line) > MaxLineBytes)
        {
            throw new InvalidDataException("Live journal row exceeds the bounded size.");
        }
        try
        {
            var evt = JsonSerializer.Deserialize<SandboxEvent>(line, JsonOptions);
            if (evt is null || string.IsNullOrWhiteSpace(evt.EventType))
            {
                throw new InvalidDataException("Live journal row is missing an event type.");
            }
            // The Agent emits the submitted root process as Source=guest.
            // ETW can also report process.start for descendants, whose image
            // paths must be allowed to differ from the submitted sample.
            if ((evt.EventType.Equals("agent.start", StringComparison.OrdinalIgnoreCase) ||
                 (evt.EventType.Equals("process.start", StringComparison.OrdinalIgnoreCase) &&
                  string.Equals(evt.Source, "guest", StringComparison.OrdinalIgnoreCase))) &&
                !string.Equals(evt.Path, samplePath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Live journal root path conflicts with pinned sample identity.");
            }
            rows.Add(evt);
        }
        catch (JsonException ex)
        {
            // A malformed complete row is corruption, not a partial tail.
            throw new InvalidDataException("Live journal contains a malformed complete row.", ex);
        }
    }

    private static void RejectReparseAncestors(string path)
    {
        for (var cursor = Path.GetFullPath(path); !string.IsNullOrWhiteSpace(cursor);)
        {
            if (File.Exists(cursor) || Directory.Exists(cursor))
            {
                if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException("Live journal path contains a reparse point.");
                }
            }
            var parent = Path.GetDirectoryName(cursor);
            if (string.IsNullOrWhiteSpace(parent) ||
                parent.Equals(cursor, StringComparison.OrdinalIgnoreCase)) break;
            cursor = parent;
        }
    }

    private static void ValidateOptionalGuestIdentity(
        string path, string samplePath, string expectedSha256, long expectedSizeBytes, string sizeField)
    {
        if (!File.Exists(path) || new FileInfo(path).Length is <= 0 or > MaxIdentityBytes) return;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("samplePath", out var pathValue) ||
                !root.TryGetProperty("sampleSha256", out var shaValue) ||
                !root.TryGetProperty(sizeField, out var sizeValue) ||
                sizeValue.ValueKind != JsonValueKind.Number ||
                !sizeValue.TryGetInt64(out var size)) return;
            if (!string.Equals(pathValue.GetString(), samplePath, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(shaValue.GetString(), expectedSha256, StringComparison.OrdinalIgnoreCase) ||
                size != expectedSizeBytes)
            {
                throw new InvalidDataException("Live journal conflicts with independent guest sample identity.");
            }
        }
        catch (JsonException)
        {
            // The guest may have reset while writing an optional sidecar.
            // A malformed sidecar is not corroboration and does not override
            // the host-pinned job/hash/size validation above.
        }
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
}
