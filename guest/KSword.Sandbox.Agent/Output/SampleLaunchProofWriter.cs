using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KSword.Sandbox.Agent.Output;

/// <summary>
/// Persists the smallest useful launch fact before a destructive sample can
/// reset the guest and prevent events.json from being finalized.
/// </summary>
public static class SampleLaunchProofWriter
{
    public const string FileName = "sample-launch-proof.json";

    public readonly record struct SampleIdentity(string Sha256, long SizeBytes);

    public static SampleIdentity ComputeSampleIdentity(string samplePath)
    {
        using var stream = File.OpenRead(samplePath);
        var sizeBytes = stream.Length;
        return new SampleIdentity(Convert.ToHexString(SHA256.HashData(stream)), sizeBytes);
    }

    public static string Write(
        string outputDirectory,
        Guid jobId,
        string samplePath,
        SampleIdentity identity,
        int processId,
        int parentProcessId,
        DateTimeOffset startedAtUtc)
    {
        if (processId <= 0 || parentProcessId <= 0 ||
            !Path.IsPathFullyQualified(samplePath) ||
            identity.SizeBytes < 0 || identity.Sha256.Length != 64 ||
            !identity.Sha256.All(static c => char.IsAsciiHexDigit(c)))
        {
            throw new ArgumentException("Invalid sample launch proof fields.");
        }

        var path = Path.Combine(outputDirectory, FileName);
        var record = new
        {
            schema = "ksword-sample-launch-proof-v1",
            state = "started",
            jobId = jobId.ToString("D", CultureInfo.InvariantCulture),
            samplePath,
            sampleSha256 = identity.Sha256.ToUpperInvariant(),
            sampleSizeBytes = identity.SizeBytes,
            processId,
            parentProcessId,
            startedAtUtc = startedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
        Directory.CreateDirectory(outputDirectory);
        // An incomplete JSON file is rejected by the host importer. Flush(true)
        // requests persistence of the completed record before later probes run.
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
            FileShare.Read, 4096, FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
        return path;
    }

    public static bool TryReadIdentity(string outputDirectory, Guid jobId, string samplePath, out SampleIdentity identity)
    {
        identity = default;
        var path = Path.Combine(outputDirectory, FileName);
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length is <= 0 or > 4096) return false;
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("schema", out var schema) || schema.GetString() != "ksword-sample-launch-proof-v1" ||
                !root.TryGetProperty("state", out var state) || state.GetString() != "started" ||
                !root.TryGetProperty("jobId", out var recordedJob) ||
                !Guid.TryParse(recordedJob.GetString(), out var parsedJob) || parsedJob != jobId ||
                !root.TryGetProperty("samplePath", out var recordedPath) ||
                !string.Equals(recordedPath.GetString(), samplePath, StringComparison.OrdinalIgnoreCase) ||
                !root.TryGetProperty("sampleSha256", out var recordedSha) ||
                !root.TryGetProperty("sampleSizeBytes", out var recordedSize) ||
                recordedSize.ValueKind != JsonValueKind.Number ||
                !recordedSize.TryGetInt64(out var sizeBytes) || sizeBytes < 0) return false;
            var sha256 = recordedSha.GetString();
            if (sha256 is not { Length: 64 } || !sha256.All(static c => char.IsAsciiHexDigit(c))) return false;
            identity = new SampleIdentity(sha256, sizeBytes);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return false;
        }
    }
}
