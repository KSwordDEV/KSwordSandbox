namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: no runtime input.
/// Processing: centralizes content type strings used by endpoint and dashboard modules.
/// Return behavior: exposes constants for response construction.
/// </summary>
internal static class WebContentTypes
{
    /// <summary>
    /// HTML response content type with UTF-8 charset.
    /// </summary>
    internal const string HtmlUtf8 = "text/html; charset=utf-8";

    /// <summary>
    /// JSON response content type with UTF-8 charset.
    /// </summary>
    internal const string JsonUtf8 = "application/json; charset=utf-8";

    /// <summary>
    /// Plain-text response content type with UTF-8 charset.
    /// </summary>
    internal const string TextUtf8 = "text/plain; charset=utf-8";
}
