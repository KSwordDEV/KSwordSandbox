using KSword.Sandbox.Abstractions.Artifacts;
using System.Security.Cryptography;

namespace KSword.Sandbox.Core.Artifacts;

/// <summary>
/// Creates normalized artifact descriptors from filesystem paths.
/// Inputs are paths, roots, and artifact kinds; processing fills size, hash,
/// MIME, category, relative path, and safe link fields; methods return schema
/// descriptors suitable for manifests, indexes, and reports.
/// </summary>
public static class ArtifactDescriptorFactory
{
    /// <summary>
    /// Creates a descriptor for an existing file.
    /// Inputs are a full path, root path, kind, and optional metadata;
    /// processing reads file metadata and SHA-256; the method returns a
    /// descriptor with safe relative link fields filled.
    /// </summary>
    public static ArtifactDescriptor FromExistingFile(
        string fullPath,
        string rootPath,
        ArtifactKind kind,
        IDictionary<string, string>? metadata = null,
        string? category = null)
    {
        var info = new FileInfo(fullPath);
        var relativePath = SafeRelativePath(rootPath, info.FullName);
        var sha256 = ComputeSha256(info.FullName);
        var copiedMetadata = CopyMetadata(metadata);
        ApplyKindMetadataDefaults(kind, copiedMetadata, includeAvailability: true);
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sha256"] = sha256
        };

        return new ArtifactDescriptor
        {
            Kind = kind,
            Category = string.IsNullOrWhiteSpace(category) ? CategoryForKind(kind) : category,
            Name = info.Name,
            RelativePath = relativePath,
            FullPath = info.FullName,
            SafeLink = BuildSafeLink(relativePath),
            EvidenceRole = FirstNonEmpty(MetadataValue(copiedMetadata, "evidenceRole")),
            CapturePhase = FirstNonEmpty(MetadataValue(copiedMetadata, "capturePhase", "phase")),
            CaptureState = FirstNonEmpty(MetadataValue(copiedMetadata, "captureState")),
            GuestPath = FirstNonEmpty(MetadataValue(copiedMetadata, "guestFullPath", "guestPath", "sourcePath")),
            ImportPath = FirstNonEmpty(MetadataValue(copiedMetadata, "importPath"), relativePath),
            CollectionName = FirstNonEmpty(MetadataValue(copiedMetadata, "collectionName")),
            MimeType = MimeTypeForPath(info.FullName),
            SizeBytes = info.Length,
            Sha256 = sha256,
            Hashes = hashes,
            CreatedAtUtc = info.CreationTimeUtc,
            Metadata = copiedMetadata
        };
    }

    /// <summary>
    /// Creates a descriptor for a path that may not exist on the host.
    /// Inputs are a path, optional root, kind, and metadata; processing fills
    /// link/category/MIME fields and hashes only when the file exists; the
    /// method returns a descriptor for report path exposure.
    /// </summary>
    public static ArtifactDescriptor FromKnownPath(
        string path,
        string? rootPath,
        ArtifactKind kind,
        IDictionary<string, string>? metadata = null,
        string? category = null)
    {
        if (File.Exists(path) && !string.IsNullOrWhiteSpace(rootPath))
        {
            return FromExistingFile(path, rootPath, kind, metadata, category);
        }

        var copiedMetadata = CopyMetadata(metadata);
        ApplyKindMetadataDefaults(kind, copiedMetadata, includeAvailability: false);
        var name = SafeFileName(path);
        var relativePath = string.IsNullOrWhiteSpace(rootPath)
            ? NormalizeRelativePath(path)
            : SafeRelativePath(rootPath, path);
        var safeLink = BuildSafeLink(relativePath);

        return new ArtifactDescriptor
        {
            Kind = kind,
            Category = string.IsNullOrWhiteSpace(category) ? CategoryForKind(kind) : category,
            Name = name,
            RelativePath = relativePath,
            FullPath = path,
            SafeLink = safeLink,
            EvidenceRole = FirstNonEmpty(MetadataValue(copiedMetadata, "evidenceRole")),
            CapturePhase = FirstNonEmpty(MetadataValue(copiedMetadata, "capturePhase", "phase")),
            CaptureState = FirstNonEmpty(MetadataValue(copiedMetadata, "captureState")),
            GuestPath = FirstNonEmpty(MetadataValue(copiedMetadata, "guestFullPath", "guestPath", "sourcePath")),
            ImportPath = FirstNonEmpty(MetadataValue(copiedMetadata, "importPath"), relativePath),
            CollectionName = FirstNonEmpty(MetadataValue(copiedMetadata, "collectionName")),
            MimeType = MimeTypeForPath(path),
            Metadata = copiedMetadata
        };
    }

    /// <summary>
    /// Normalizes non-file descriptor metadata without reading file contents.
    /// Inputs are an existing descriptor; processing fills empty category, MIME,
    /// hash map, and safe link fields; the method returns a descriptor copy.
    /// </summary>
    public static ArtifactDescriptor NormalizeDescriptor(ArtifactDescriptor descriptor)
    {
        var relativePath = NormalizeRelativePath(descriptor.RelativePath);
        var hashes = CopyMetadata(descriptor.Hashes);
        var metadata = CopyMetadata(descriptor.Metadata);
        ApplyKindMetadataDefaults(descriptor.Kind, metadata, includeAvailability: false);
        if (!string.IsNullOrWhiteSpace(descriptor.Sha256))
        {
            hashes["sha256"] = descriptor.Sha256;
        }

        return descriptor with
        {
            Category = string.IsNullOrWhiteSpace(descriptor.Category)
                ? CategoryForKind(descriptor.Kind)
                : descriptor.Category,
            RelativePath = relativePath,
            SafeLink = string.IsNullOrWhiteSpace(descriptor.SafeLink)
                ? BuildSafeLink(relativePath)
                : descriptor.SafeLink,
            EvidenceRole = FirstNonEmpty(descriptor.EvidenceRole, MetadataValue(metadata, "evidenceRole")),
            CapturePhase = FirstNonEmpty(descriptor.CapturePhase, MetadataValue(metadata, "capturePhase", "phase")),
            CaptureState = FirstNonEmpty(descriptor.CaptureState, MetadataValue(metadata, "captureState")),
            GuestPath = FirstNonEmpty(descriptor.GuestPath, MetadataValue(metadata, "guestFullPath", "guestPath", "sourcePath")),
            ImportPath = FirstNonEmpty(descriptor.ImportPath, MetadataValue(metadata, "importPath"), relativePath),
            CollectionName = FirstNonEmpty(descriptor.CollectionName, MetadataValue(metadata, "collectionName")),
            MimeType = string.IsNullOrWhiteSpace(descriptor.MimeType)
                ? MimeTypeForPath(!string.IsNullOrWhiteSpace(descriptor.FullPath) ? descriptor.FullPath : descriptor.Name)
                : descriptor.MimeType,
            Hashes = hashes,
            Metadata = metadata
        };
    }

    /// <summary>
    /// Builds a safe relative path from a root/path pair.
    /// Inputs are a root directory and child path; processing rejects traversal
    /// segments; the method returns a slash-separated relative path or empty
    /// text when the path is unsafe.
    /// </summary>
    public static string SafeRelativePath(string rootPath, string path)
    {
        if (string.IsNullOrWhiteSpace(rootPath) || string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        try
        {
            var fullRoot = Path.GetFullPath(rootPath);
            var fullPath = Path.IsPathFullyQualified(path) ? Path.GetFullPath(path) : Path.GetFullPath(Path.Combine(fullRoot, path));
            if (!IsUnderRoot(fullRoot, fullPath))
            {
                return string.Empty;
            }

            return NormalizeRelativePath(Path.GetRelativePath(fullRoot, fullPath));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Normalizes a relative path for manifest JSON.
    /// The input may use platform separators; processing rejects rooted paths
    /// and parent traversal; the method returns slash-separated safe text.
    /// </summary>
    public static string NormalizeRelativePath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return string.Empty;
        }

        var unified = relativePath.Replace('\\', '/').Trim();
        if (Path.IsPathFullyQualified(unified) || unified.StartsWith("/", StringComparison.Ordinal))
        {
            return string.Empty;
        }

        var segments = unified
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(segment => !string.Equals(segment, ".", StringComparison.Ordinal))
            .ToList();
        if (segments.Count == 0 ||
            segments.Any(segment =>
                string.Equals(segment, "..", StringComparison.Ordinal) ||
                segment.Contains(':', StringComparison.Ordinal)))
        {
            return string.Empty;
        }

        return string.Join("/", segments);
    }

    /// <summary>
    /// Builds a link target that is safe to place in a local report href.
    /// Inputs are a normalized relative path; processing URL-encodes each path
    /// segment; the method returns slash-separated link text or empty text.
    /// </summary>
    public static string BuildSafeLink(string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }

        return string.Join(
            "/",
            normalized.Split('/').Select(segment => Uri.EscapeDataString(segment)));
    }

    /// <summary>
    /// Maps an artifact kind to a stable report category string.
    /// The input is an artifact kind; processing uses local convention; the
    /// method returns a lower-case category.
    /// </summary>
    public static string CategoryForKind(ArtifactKind kind)
    {
        return kind switch
        {
            ArtifactKind.ArtifactIndex => "artifact-index",
            ArtifactKind.ArtifactManifest => "artifact-manifest",
            ArtifactKind.ReportJson or ArtifactKind.ReportHtml => "report",
            ArtifactKind.RunbookJson or ArtifactKind.RunbookExecutionJson => "runbook",
            ArtifactKind.GuestEventsJson or ArtifactKind.DriverEventsJsonLines or ArtifactKind.GuestSummaryJson => "telemetry",
            ArtifactKind.DroppedFile => "dropped-file",
            ArtifactKind.StaticAnalysisJson => "static-analysis",
            ArtifactKind.Screenshot => "screenshot",
            ArtifactKind.MemoryDump => "memory-dump",
            ArtifactKind.PacketCapture => "packet-capture",
            ArtifactKind.Log => "log",
            ArtifactKind.Bundle => "bundle",
            _ => "artifact"
        };
    }

    /// <summary>
    /// Maps common artifact extensions to MIME types.
    /// The input is a path or file name; processing checks the extension; the
    /// method returns a deterministic content type string.
    /// </summary>
    public static string MimeTypeForPath(string path)
    {
        return Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".json" => "application/json",
            ".jsonl" => "application/x-ndjson",
            ".html" or ".htm" => "text/html",
            ".txt" or ".log" => "text/plain",
            ".bmp" => "image/bmp",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".dmp" => "application/vnd.microsoft.minidump",
            ".pcap" => "application/vnd.tcpdump.pcap",
            ".pcapng" => "application/x-pcapng",
            ".zip" => "application/zip",
            ".exe" or ".dll" or ".sys" => "application/vnd.microsoft.portable-executable",
            _ => "application/octet-stream"
        };
    }

    /// <summary>
    /// Returns true when a path names a supported packet-capture artifact.
    /// Inputs are arbitrary paths or file names; processing checks only the
    /// extension; the method returns true for .pcap and .pcapng files.
    /// </summary>
    public static bool IsPacketCapturePath(string path)
    {
        var extension = Path.GetExtension(path);
        return string.Equals(extension, ".pcap", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(extension, ".pcapng", StringComparison.OrdinalIgnoreCase);
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string? MetadataValue(IDictionary<string, string>? metadata, params string[] keys)
    {
        if (metadata is null)
        {
            return null;
        }

        foreach (var key in keys)
        {
            if (metadata.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static Dictionary<string, string> CopyMetadata(IDictionary<string, string>? metadata)
    {
        return metadata is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(metadata, StringComparer.OrdinalIgnoreCase);
    }

    private static void ApplyKindMetadataDefaults(ArtifactKind kind, Dictionary<string, string> metadata, bool includeAvailability)
    {
        if (kind != ArtifactKind.PacketCapture)
        {
            return;
        }

        AddDefault(metadata, "evidenceRole", "packet-capture");
        AddDefault(metadata, "collectionName", "packet-captures");
        if (includeAvailability)
        {
            AddDefault(metadata, "captureState", "available");
        }
    }

    private static void AddDefault(Dictionary<string, string> metadata, string key, string value)
    {
        if (!metadata.ContainsKey(key) || string.IsNullOrWhiteSpace(metadata[key]))
        {
            metadata[key] = value;
        }
    }

    private static string ComputeSha256(string fullPath)
    {
        using var stream = File.OpenRead(fullPath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool IsUnderRoot(string rootPath, string path)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath)) + Path.DirectorySeparatorChar;
        var candidate = Path.GetFullPath(path);
        return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Path.TrimEndingDirectorySeparator(candidate), Path.TrimEndingDirectorySeparator(rootPath), StringComparison.OrdinalIgnoreCase);
    }

    private static string SafeFileName(string path)
    {
        try
        {
            var name = Path.GetFileName(path);
            return string.IsNullOrWhiteSpace(name) ? "artifact" : name;
        }
        catch (ArgumentException)
        {
            return "artifact";
        }
    }
}
