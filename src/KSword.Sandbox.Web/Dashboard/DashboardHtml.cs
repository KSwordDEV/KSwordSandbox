using System.Net;

namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: raw text or HTML fragments produced by dashboard components.
/// Processing: provides common escaping and line-joining helpers for server-rendered dashboard HTML.
/// Return behavior: returns strings that can be embedded into HTML responses by dashboard composers.
/// </summary>
internal static class DashboardHtml
{
    /// <summary>
    /// Inputs: optional plain text from a dashboard model.
    /// Processing: converts null to an empty string and applies HTML encoding.
    /// Return behavior: returns encoded text safe for element bodies.
    /// </summary>
    internal static string Encode(string? value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty);
    }

    /// <summary>
    /// Inputs: optional plain text intended for an HTML attribute.
    /// Processing: applies HTML encoding and keeps null represented as an empty attribute value.
    /// Return behavior: returns encoded text safe for quoted HTML attributes.
    /// </summary>
    internal static string Attribute(string? value)
    {
        return Encode(value);
    }

    /// <summary>
    /// Inputs: an enumerable of HTML lines produced by local dashboard renderers.
    /// Processing: joins the lines with the platform newline without re-encoding owned HTML fragments.
    /// Return behavior: returns a single HTML fragment string.
    /// </summary>
    internal static string JoinLines(IEnumerable<string> lines)
    {
        return string.Join(Environment.NewLine, lines);
    }
}
