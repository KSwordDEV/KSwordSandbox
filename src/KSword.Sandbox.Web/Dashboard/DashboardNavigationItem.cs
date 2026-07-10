namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: label, hyperlink target, and active-state flag for one navigation item.
/// Processing: renders escaped anchor text and attributes for the dashboard navigation bar.
/// Return behavior: returns an HTML anchor fragment.
/// </summary>
/// <param name="Label">Text displayed to the user.</param>
/// <param name="Href">Navigation target used by the anchor.</param>
/// <param name="IsActive">Indicates whether this item represents the current page.</param>
internal sealed record DashboardNavigationItem(
    string Label,
    string Href,
    bool IsActive)
{
    /// <summary>
    /// Inputs: the current navigation item.
    /// Processing: escapes label and href values and adds an active class when requested.
    /// Return behavior: returns a safe HTML anchor fragment.
    /// </summary>
    internal string Render()
    {
        var activeClass = IsActive ? " is-active" : string.Empty;
        return $"<a class=\"nav-item{activeClass}\" href=\"{DashboardHtml.Attribute(Href)}\">{DashboardHtml.Encode(Label)}</a>";
    }
}
