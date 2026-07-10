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
    /// Runbook execute route suffix under a job detail route.
    /// </summary>
    internal const string RunbookExecuteSuffix = "/runbook/execute";

    /// <summary>
    /// Guest event import route suffix under a job detail route.
    /// </summary>
    internal const string GuestEventsImportSuffix = "/guest-events/import";

    /// <summary>
    /// Served HTML report route suffix under a job detail route.
    /// </summary>
    internal const string ReportHtmlSuffix = "/report/html";

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

    /// <summary>
    /// Inputs: a job identifier selected by the dashboard.
    /// Processing: appends the served HTML report suffix to the job route.
    /// Return behavior: returns the concrete route path for report.html access.
    /// </summary>
    internal static string ReportHtml(Guid jobId)
    {
        return $"{JobById(jobId)}{ReportHtmlSuffix}";
    }

    /// <summary>
    /// Inputs: a job identifier selected by the dashboard.
    /// Processing: appends the runbook execute suffix to the job route.
    /// Return behavior: returns the concrete route path for runbook execution.
    /// </summary>
    internal static string RunbookExecute(Guid jobId)
    {
        return $"{JobById(jobId)}{RunbookExecuteSuffix}";
    }

    /// <summary>
    /// Inputs: a job identifier selected by the dashboard.
    /// Processing: appends the guest import suffix to the job route.
    /// Return behavior: returns the concrete route path for guest event import.
    /// </summary>
    internal static string GuestEventsImport(Guid jobId)
    {
        return $"{JobById(jobId)}{GuestEventsImportSuffix}";
    }
}
