namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: badge text and tone supplied by dashboard view models.
/// Processing: renders a compact status indicator with escaped text and CSS class.
/// Return behavior: returns an HTML span fragment for section bodies.
/// </summary>
/// <param name="Text">Status text shown to the user.</param>
/// <param name="Tone">CSS tone suffix such as neutral, success, warning, or danger.</param>
internal sealed record DashboardStatusBadge(string Text, string Tone)
{
    /// <summary>
    /// Inputs: the current badge model.
    /// Processing: escapes badge text and tone before composing a span element.
    /// Return behavior: returns a safe HTML badge fragment.
    /// </summary>
    internal string Render()
    {
        return $"<span class=\"status-badge status-{DashboardHtml.Attribute(Tone)}\">{DashboardHtml.Encode(Text)}</span>";
    }
}
