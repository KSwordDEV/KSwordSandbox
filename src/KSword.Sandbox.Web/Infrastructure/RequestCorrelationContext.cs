namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: trace identifier, HTTP method, request path, and UTC receipt timestamp.
/// Processing: captures request metadata once so endpoint code can pass it through logs or responses.
/// Return behavior: instances are used as immutable correlation values.
/// </summary>
/// <param name="TraceIdentifier">Trace identifier assigned by ASP.NET Core.</param>
/// <param name="Method">HTTP method used by the request.</param>
/// <param name="Path">Request path observed by ASP.NET Core.</param>
/// <param name="ReceivedAtUtc">UTC timestamp captured when metadata was read.</param>
internal sealed record RequestCorrelationContext(
    string TraceIdentifier,
    string Method,
    string Path,
    DateTimeOffset ReceivedAtUtc);
