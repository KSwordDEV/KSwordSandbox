namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: document title, optional subtitle, and optional auto-refresh interval.
/// Processing: carries shell-level dashboard settings independently from page sections.
/// Return behavior: instances guide DashboardDocument rendering.
/// </summary>
/// <param name="Title">Main document title rendered in the browser and page header.</param>
/// <param name="Subtitle">Optional subtitle rendered below the page title.</param>
/// <param name="AutoRefreshSeconds">Optional refresh interval; null disables meta refresh.</param>
internal sealed record DashboardShellOptions(
    string Title,
    string? Subtitle,
    int? AutoRefreshSeconds)
{
    /// <summary>
    /// Inputs: none.
    /// Processing: creates the standard KSword Sandbox dashboard shell settings.
    /// Return behavior: returns default options for dashboard pages.
    /// </summary>
    internal static DashboardShellOptions Default()
    {
        return new DashboardShellOptions("KSword Sandbox", "Web control surface", null);
    }
}
