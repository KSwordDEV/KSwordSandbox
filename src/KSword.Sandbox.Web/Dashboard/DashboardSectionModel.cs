namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: section identity, title, trusted body HTML, and optional CSS class.
/// Processing: wraps locally generated dashboard content in a consistent section frame.
/// Return behavior: returns HTML that can be inserted into a DashboardDocument.
/// </summary>
/// <param name="Id">Stable HTML id used for anchors and tests.</param>
/// <param name="Title">Section heading rendered to the user.</param>
/// <param name="BodyHtml">Trusted body HTML produced by server-side dashboard components.</param>
/// <param name="CssClass">Optional additional CSS class for the section.</param>
internal sealed record DashboardSectionModel(
    string Id,
    string Title,
    string BodyHtml,
    string? CssClass = null)
{
    /// <summary>
    /// Inputs: the current section model.
    /// Processing: escapes section metadata while preserving trusted BodyHtml from local renderers.
    /// Return behavior: returns a complete section HTML fragment.
    /// </summary>
    internal string Render()
    {
        var cssClass = string.IsNullOrWhiteSpace(CssClass) ? "dashboard-section" : $"dashboard-section {DashboardHtml.Attribute(CssClass)}";
        return DashboardHtml.JoinLines(new[]
        {
            $"<section id=\"{DashboardHtml.Attribute(Id)}\" class=\"{cssClass}\">",
            $"  <h2>{DashboardHtml.Encode(Title)}</h2>",
            $"  <div class=\"section-body\">{BodyHtml}</div>",
            "</section>"
        });
    }
}
