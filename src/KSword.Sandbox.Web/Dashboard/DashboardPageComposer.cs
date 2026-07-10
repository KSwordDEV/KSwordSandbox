namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: shell options, navigation models, and dashboard sections from endpoint code.
/// Processing: materializes enumerable inputs once and appends standard dashboard client scripts.
/// Return behavior: returns a DashboardDocument ready for rendering.
/// </summary>
internal sealed class DashboardPageComposer
{
    /// <summary>
    /// Inputs: shell options, navigation item sequence, and section sequence.
    /// Processing: materializes navigation and sections, attaches the standard context-copy script, and creates a document model.
    /// Return behavior: returns a DashboardDocument that can render a complete HTML page.
    /// </summary>
    internal DashboardDocument Compose(
        DashboardShellOptions options,
        IEnumerable<DashboardNavigationItem> navigation,
        IEnumerable<DashboardSectionModel> sections)
    {
        return new DashboardDocument(
            options,
            navigation.ToArray(),
            sections.ToArray(),
            DashboardClientScripts.ContextCopyScript());
    }
}
