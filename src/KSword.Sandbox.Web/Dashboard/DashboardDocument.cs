using System.Text;

namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: shell options, navigation items, sections, and optional script HTML.
/// Processing: composes a complete HTML document from dashboard component fragments.
/// Return behavior: returns a string suitable for Results.Content with an HTML content type.
/// </summary>
/// <param name="Options">Shell settings used for title, subtitle, and refresh behavior.</param>
/// <param name="Navigation">Navigation items rendered near the page header.</param>
/// <param name="Sections">Ordered dashboard sections rendered in the main area.</param>
/// <param name="ScriptHtml">Trusted script HTML produced by local dashboard helpers.</param>
internal sealed record DashboardDocument(
    DashboardShellOptions Options,
    IReadOnlyList<DashboardNavigationItem> Navigation,
    IReadOnlyList<DashboardSectionModel> Sections,
    string ScriptHtml)
{
    /// <summary>
    /// Inputs: the current document model.
    /// Processing: renders document head, navigation, sections, and owned scripts into one HTML string.
    /// Return behavior: returns a complete HTML document.
    /// </summary>
    internal string Render()
    {
        var builder = new StringBuilder();
        builder.AppendLine("<!doctype html>");
        builder.AppendLine("<html lang=\"en\">");
        builder.AppendLine("<head>");
        builder.AppendLine("  <meta charset=\"utf-8\">");
        builder.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        builder.AppendLine($"  <title>{DashboardHtml.Encode(Options.Title)}</title>");
        if (Options.AutoRefreshSeconds is > 0)
        {
            builder.AppendLine($"  <meta http-equiv=\"refresh\" content=\"{Options.AutoRefreshSeconds.Value}\">");
        }

        builder.AppendLine("</head>");
        builder.AppendLine("<body>");
        builder.AppendLine("  <header class=\"dashboard-header\">");
        builder.AppendLine($"    <h1>{DashboardHtml.Encode(Options.Title)}</h1>");
        if (!string.IsNullOrWhiteSpace(Options.Subtitle))
        {
            builder.AppendLine($"    <p>{DashboardHtml.Encode(Options.Subtitle)}</p>");
        }

        builder.AppendLine("    <nav>");
        builder.AppendLine(DashboardHtml.JoinLines(Navigation.Select(item => "      " + item.Render())));
        builder.AppendLine("    </nav>");
        builder.AppendLine("  </header>");
        builder.AppendLine("  <main>");
        builder.AppendLine(DashboardHtml.JoinLines(Sections.Select(section => "    " + section.Render())));
        builder.AppendLine("  </main>");
        builder.AppendLine(ScriptHtml);
        builder.AppendLine("</body>");
        builder.AppendLine("</html>");
        return builder.ToString();
    }
}
