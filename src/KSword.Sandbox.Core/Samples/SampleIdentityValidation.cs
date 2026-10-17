using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Samples;

/// <summary>
/// Describes whether the sample identity carried by a job, its report, and
/// the execution input still refers to the same file.  A report with a
/// mismatch must never be treated as a valid sample result.
/// </summary>
public sealed record SampleIdentityValidationResult
{
    public required string Status { get; init; }

    public List<string> Issues { get; init; } = [];

    public bool IsValid => string.Equals(Status, "valid", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Provides the small identity gate shared by live imports and offline report
/// rebuilds.  Inputs are the freshly hashed sample, persisted metadata/report
/// identities, and optional guest-side input identity; processing compares
/// path, SHA-256, and size and returns stable issue codes.
/// </summary>
public static class SampleIdentityValidation
{
    public static SampleIdentityValidationResult Validate(
        SampleIdentity canonical,
        SampleIdentity? metadata,
        SampleIdentity? report,
        string? submissionPath,
        string? guestPath = null,
        string? guestSha256 = null,
        long? guestSizeBytes = null)
    {
        ArgumentNullException.ThrowIfNull(canonical);
        var issues = new List<string>();

        ComparePersisted("metadata", canonical, metadata, issues);
        ComparePersisted("report", canonical, report, issues);

        if (!string.IsNullOrWhiteSpace(submissionPath) &&
            !PathsEqual(canonical.FullPath, submissionPath))
        {
            issues.Add("submission-path-mismatch");
        }

        if (!string.IsNullOrWhiteSpace(guestPath) &&
            !FileNamesEqual(canonical.FileName, guestPath))
        {
            issues.Add("guest-path-mismatch");
        }

        if (!string.IsNullOrWhiteSpace(guestSha256) &&
            !HashesEqual(canonical.Sha256, guestSha256))
        {
            issues.Add("guest-sha256-mismatch");
        }

        if (guestSizeBytes.HasValue && guestSizeBytes.Value >= 0 &&
            canonical.SizeBytes != guestSizeBytes.Value)
        {
            issues.Add("guest-size-mismatch");
        }

        return new SampleIdentityValidationResult
        {
            Status = issues.Count == 0 ? "valid" : "mismatch",
            Issues = issues.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private static void ComparePersisted(
        string source,
        SampleIdentity canonical,
        SampleIdentity? persisted,
        ICollection<string> issues)
    {
        if (persisted is null)
        {
            return;
        }

        if (!PathsEqual(canonical.FullPath, persisted.FullPath))
        {
            issues.Add($"{source}-path-mismatch");
        }

        if (!HashesEqual(canonical.Sha256, persisted.Sha256))
        {
            issues.Add($"{source}-sha256-mismatch");
        }

        if (canonical.SizeBytes != persisted.SizeBytes)
        {
            issues.Add($"{source}-size-mismatch");
        }
    }

    public static bool PathsEqual(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
        {
            return string.Equals(left?.Trim(), right?.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(left),
                Path.GetFullPath(right),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or IOException)
        {
            return string.Equals(left.Trim(), right.Trim(), StringComparison.OrdinalIgnoreCase);
        }
    }

    private static bool FileNamesEqual(string expectedFileName, string guestPath)
    {
        var guestFileName = Path.GetFileName(guestPath.Trim().Trim('"'));
        return string.Equals(expectedFileName, guestFileName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HashesEqual(string? left, string? right) =>
        !string.IsNullOrWhiteSpace(left) &&
        !string.IsNullOrWhiteSpace(right) &&
        string.Equals(left.Trim(), right.Trim(), StringComparison.OrdinalIgnoreCase);
}
