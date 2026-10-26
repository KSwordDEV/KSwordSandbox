using System.Text.Json;
using System.Text;
using System.Globalization;
using KSword.Sandbox.Agent.Collection;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Output;

/// <summary>
/// Keeps a bounded, append-only copy of guest events while the sample runs.
/// Complete newline-terminated records survive an Agent crash or guest reset;
/// events.json remains the authoritative completed-run artifact.
/// </summary>
internal sealed class DurableEventJournal : IDisposable
{
    internal const string FileName = "live-events.jsonl";
    internal const string IdentityFileName = "live-events.identity.json";
    internal const long MaxBytes = 64L * 1024 * 1024;
    internal const int MaxRecordBytes = 1024 * 1024;

    private readonly FileStream stream;
    private readonly long maxBytes;
    private readonly int maxRecordBytes;
    private int writtenCount;
    private long writtenBytes;

    private DurableEventJournal(FileStream stream, long maxBytes, int maxRecordBytes)
    {
        this.stream = stream;
        this.maxBytes = maxBytes;
        this.maxRecordBytes = maxRecordBytes;
    }

    internal string? Failure { get; private set; }

    internal int WrittenCount => writtenCount;

    internal static DurableEventJournal Create(
        string outputDirectory,
        long maxBytes = MaxBytes,
        int maxRecordBytes = MaxRecordBytes)
    {
        if (maxBytes < 1 || maxBytes > MaxBytes || maxRecordBytes < 1 || maxRecordBytes > MaxRecordBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes), "Journal limits must be positive and no larger than production bounds.");
        }
        Directory.CreateDirectory(outputDirectory);
        var path = Path.Combine(outputDirectory, FileName);
        var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 64 * 1024,
            options: FileOptions.WriteThrough);
        return new DurableEventJournal(stream, maxBytes, maxRecordBytes);
    }

    /// <summary>
    /// Binds the stream to the exact guest bytes before CreateProcess. The
    /// host must validate this sidecar against its own pinned job identity.
    /// </summary>
    internal static void WriteIdentity(
        string outputDirectory,
        Guid jobId,
        string samplePath,
        SampleLaunchProofWriter.SampleIdentity identity)
    {
        if (jobId == Guid.Empty || !Path.IsPathFullyQualified(samplePath) ||
            identity.SizeBytes < 0 || identity.Sha256.Length != 64 ||
            !identity.Sha256.All(char.IsAsciiHexDigit))
        {
            throw new ArgumentException("Invalid live journal sample identity.");
        }

        var body = new
        {
            schema = "ksword-live-events-v1",
            jobId = jobId.ToString("D", CultureInfo.InvariantCulture),
            samplePath,
            sampleSha256 = identity.Sha256.ToUpperInvariant(),
            sampleSizeBytes = identity.SizeBytes,
            eventFormat = "SandboxEvent-jsonl",
            maxBytes = MaxBytes
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(body));
        var path = Path.Combine(outputDirectory, IdentityFileName);
        using var identityStream = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
            FileShare.Read, 4096, FileOptions.WriteThrough);
        identityStream.Write(bytes);
        identityStream.Flush(flushToDisk: true);
    }

    /// <summary>
    /// Persists the guest's prelaunch sample identity before any potentially
    /// expensive probes or journal entries. No sample process is started here.
    /// </summary>
    internal static SampleLaunchProofWriter.SampleIdentity CaptureAndWriteIdentity(
        string outputDirectory, Guid jobId, string samplePath)
    {
        var identity = SampleLaunchProofWriter.ComputeSampleIdentity(samplePath);
        WriteIdentity(outputDirectory, jobId, samplePath, identity);
        return identity;
    }

    /// <summary>
    /// Rehashes immediately before Process.Start. A changed file must not run
    /// under the durable identity already copied to the host.
    /// </summary>
    internal static SampleLaunchProofWriter.SampleIdentity VerifyUnchangedSample(
        string samplePath, SampleLaunchProofWriter.SampleIdentity pinnedIdentity)
    {
        var current = SampleLaunchProofWriter.ComputeSampleIdentity(samplePath);
        if (current.SizeBytes != pinnedIdentity.SizeBytes ||
            !current.Sha256.Equals(pinnedIdentity.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Sample bytes changed after the durable journal identity was written; execution refused.");
        }
        return current;
    }

    /// <summary>
    /// Appends exactly the new list entries and flushes them to the guest disk.
    /// A failed or over-budget journal is never represented as complete.
    /// </summary>
    internal bool AppendNew(IReadOnlyList<SandboxEvent> events)
    {
        if (Failure is not null)
        {
            return false;
        }

        try
        {
            while (writtenCount < events.Count)
            {
                // Final events.json receives these quality flags later during
                // artifact writing. Apply the same normalization now so a
                // recovered partial journal cannot promote Agent self-noise.
                GuestSelfNoiseMetadata.Apply(events[writtenCount]);
                var row = JsonSerializer.SerializeToUtf8Bytes(events[writtenCount]);
                if (row.Length > maxRecordBytes || writtenBytes + row.Length + 1 > maxBytes)
                {
                    Failure = "capacity-limit";
                    return false;
                }

                stream.Write(row);
                stream.WriteByte((byte)'\n');
                writtenBytes += row.Length + 1;
                writtenCount++;
            }

            stream.Flush(flushToDisk: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            Failure = ex.GetType().Name;
            return false;
        }
    }

    public void Dispose() => stream.Dispose();
}
