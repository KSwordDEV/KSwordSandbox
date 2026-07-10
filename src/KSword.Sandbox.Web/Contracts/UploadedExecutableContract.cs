namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: original file name, stored path, file length, and optional content hash.
/// Processing: describes an uploaded executable after validation and staging.
/// Return behavior: instances are serialized as upload endpoint responses.
/// </summary>
/// <param name="OriginalFileName">Browser-supplied file name after server-side normalization.</param>
/// <param name="StoredPath">Server-side path where the executable was staged.</param>
/// <param name="Length">Number of bytes written to storage.</param>
/// <param name="Sha256">Optional SHA-256 hash calculated during upload processing.</param>
public sealed record UploadedExecutableContract(
    string OriginalFileName,
    string StoredPath,
    long Length,
    string? Sha256);
