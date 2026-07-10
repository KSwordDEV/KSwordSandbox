namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: no runtime input.
/// Processing: supplies small owned JavaScript snippets used by dashboard documents.
/// Return behavior: returns script HTML fragments that can be appended to rendered pages.
/// </summary>
internal static class DashboardClientScripts
{
    /// <summary>
    /// Inputs: none.
    /// Processing: creates a right-click copy helper for elements that declare data-copy or contain copyable text.
    /// Return behavior: returns a script tag that can be embedded in server-rendered dashboard HTML.
    /// </summary>
    internal static string ContextCopyScript()
    {
        return """
<script>
document.addEventListener('contextmenu', function (event) {
  var target = event.target.closest('[data-copy]');
  if (!target || !navigator.clipboard) {
    return;
  }

  event.preventDefault();
  var value = target.getAttribute('data-copy') || target.textContent || '';
  navigator.clipboard.writeText(value);
});
</script>
""";
    }
}
