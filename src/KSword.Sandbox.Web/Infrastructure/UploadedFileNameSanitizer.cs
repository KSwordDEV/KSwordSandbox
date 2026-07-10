using System.Text;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: browser-supplied upload file names.
/// Processing: removes directory components, replaces invalid file-name characters, and bounds length.
/// Return behavior: returns a safe file name suitable for staging directories.
/// </summary>
internal static class UploadedFileNameSanitizer
{
    private const int MaxFileNameLength = 120;

    /// <summary>
    /// Inputs: a raw file name supplied by a multipart upload.
    /// Processing: trims whitespace, keeps only the final path component, replaces invalid characters, and applies a length limit.
    /// Return behavior: returns a non-empty file name; "upload.bin" is returned when no usable name remains.
    /// </summary>
    internal static string Sanitize(string fileName)
    {
        var leafName = Path.GetFileName((fileName ?? string.Empty).Trim());
        if (string.IsNullOrWhiteSpace(leafName))
        {
            return "upload.bin";
        }

        var invalidCharacters = Path.GetInvalidFileNameChars().ToHashSet();
        var builder = new StringBuilder(leafName.Length);
        foreach (var character in leafName)
        {
            builder.Append(invalidCharacters.Contains(character) ? '_' : character);
        }

        var sanitized = builder.ToString();
        if (sanitized.Length <= MaxFileNameLength)
        {
            return sanitized;
        }

        return sanitized[..MaxFileNameLength];
    }
}
