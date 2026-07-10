namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: no runtime input for constants and route parameters for helper methods.
/// Processing: keeps route literals in one place so extracted endpoint modules can share the same surface.
/// Return behavior: returns route templates or concrete route paths for dashboard links.
/// </summary>
internal static class WebRouteCatalog
{
    /// <summary>
    /// Dashboard root route template.
    /// </summary>
    internal const string DashboardRoot = "/";

    /// <summary>
    /// Health route template.
    /// </summary>
    internal const string Health = "/health";

    /// <summary>
    /// Job collection route template.
    /// </summary>
    internal const string Jobs = "/api/jobs";

    /// <summary>
    /// File scan route template.
    /// </summary>
    internal const string FileScan = "/api/files/scan";

    /// <summary>
    /// File upload route template.
    /// </summary>
    internal const string FileUpload = "/api/files/upload";

    /// <summary>
    /// Inputs: a job identifier selected by the dashboard.
    /// Processing: formats the identifier with the invariant "D" format and appends it to the jobs route.
    /// Return behavior: returns the concrete route path for a job detail request.
    /// </summary>
    internal static string JobById(Guid jobId)
    {
        return $"{Jobs}/{jobId:D}";
    }

    /// <summary>
    /// Inputs: a job identifier selected by the dashboard.
    /// Processing: formats the identifier with the invariant "D" format and appends the live events suffix.
    /// Return behavior: returns the concrete route path for live event polling.
    /// </summary>
    internal static string LiveEvents(Guid jobId)
    {
        return $"{JobById(jobId)}/events/live";
    }

    /// <summary>
    /// Inputs: a job identifier selected by the dashboard.
    /// Processing: formats the identifier with the invariant "D" format and appends the SSE live-event suffix.
    /// Return behavior: returns the concrete route path for streaming raw live events.
    /// </summary>
    internal static string LiveEventStream(Guid jobId)
    {
        return $"{JobById(jobId)}/events/stream";
    }
}
