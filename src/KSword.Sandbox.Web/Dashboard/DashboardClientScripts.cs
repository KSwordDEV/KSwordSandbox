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
function kswFallbackCopyText(value) {
  var textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.setAttribute('readonly', 'readonly');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}

function kswCopyDashboardValue(value) {
  if (!value) {
    return;
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(value).catch(function () { kswFallbackCopyText(value); });
    return;
  }

  kswFallbackCopyText(value);
}

document.addEventListener('click', function (event) {
  var button = event.target.closest('button.copy-btn[data-copy]');
  if (!button) {
    return;
  }

  event.preventDefault();
  event.stopPropagation();
  kswCopyDashboardValue(button.getAttribute('data-copy') || '');
});

document.addEventListener('contextmenu', function (event) {
  var target = event.target.closest('[data-copy], code, pre, td, th, p, li, h1, h2, h3, label, span, a, button, input');
  if (!target) {
    return;
  }

  event.preventDefault();
  var value = target.getAttribute('data-copy') || target.value || target.innerText || target.textContent || '';
  kswCopyDashboardValue(value);
});
</script>
""";
    }
}
