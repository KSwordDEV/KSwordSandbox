using System.Security.Cryptography;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Samples;

/// <summary>
/// Creates stable sample metadata without loading the whole file in memory.
/// Inputs are host sample paths and size limits, processing validates and hashes
/// the file stream, and the method returns a SampleIdentity record.
/// </summary>
public static class SampleHasher
{
    /// <summary>
    /// Validates and hashes one submitted sample.
    /// The input is a local path and maximum byte count; processing checks
    /// existence, size, and SHA-256; the method returns immutable identity data.
    /// </summary>
    public static SampleIdentity Compute(string samplePath, long maxSampleBytes)
    {
        if (string.IsNullOrWhiteSpace(samplePath))
        {
            throw new ArgumentException("Sample path is required.", nameof(samplePath));
        }

        var fullPath = Path.GetFullPath(samplePath);
        var info = new FileInfo(fullPath);
        if (!info.Exists)
        {
            throw new FileNotFoundException("Sample file was not found.", fullPath);
        }

        if (info.Length <= 0)
        {
            throw new InvalidOperationException("Sample file is empty.");
        }

        if (info.Length > maxSampleBytes)
        {
            throw new InvalidOperationException($"Sample size {info.Length} exceeds limit {maxSampleBytes}.");
        }

        using var stream = File.OpenRead(fullPath);
        var hash = SHA256.HashData(stream);
        return new SampleIdentity
        {
            FileName = info.Name,
            FullPath = fullPath,
            Sha256 = Convert.ToHexString(hash).ToLowerInvariant(),
            SizeBytes = info.Length
        };
    }
}
