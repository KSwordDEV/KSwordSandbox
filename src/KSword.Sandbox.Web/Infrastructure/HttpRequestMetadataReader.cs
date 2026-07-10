using Microsoft.AspNetCore.Http;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: an ASP.NET Core HttpContext and a Web clock.
/// Processing: extracts request correlation fields without binding endpoint modules to HttpContext directly.
/// Return behavior: returns immutable request metadata for diagnostics and response construction.
/// </summary>
internal static class HttpRequestMetadataReader
{
    /// <summary>
    /// Inputs: the current HttpContext and a clock implementation.
    /// Processing: reads trace identifier, method, path, and UTC receipt time.
    /// Return behavior: returns a RequestCorrelationContext containing the extracted fields.
    /// </summary>
    internal static RequestCorrelationContext Read(HttpContext httpContext, ISandboxWebClock clock)
    {
        return new RequestCorrelationContext(
            httpContext.TraceIdentifier,
            httpContext.Request.Method,
            httpContext.Request.Path.Value ?? "/",
            clock.UtcNow());
    }
}
