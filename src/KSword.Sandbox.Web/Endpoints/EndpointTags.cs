namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: no runtime input.
/// Processing: centralizes endpoint tag names used by route modules and generated documentation.
/// Return behavior: exposes stable tag constants for route metadata.
/// </summary>
internal static class EndpointTags
{
    /// <summary>
    /// Tag for dashboard HTML and bootstrap endpoints.
    /// </summary>
    internal const string Dashboard = "Dashboard";

    /// <summary>
    /// Tag for health and readiness endpoints.
    /// </summary>
    internal const string Health = "Health";

    /// <summary>
    /// Tag for job planning, detail, and execution endpoints.
    /// </summary>
    internal const string Jobs = "Jobs";

    /// <summary>
    /// Tag for file scan and upload endpoints.
    /// </summary>
    internal const string Files = "Files";

    /// <summary>
    /// Tag for runbook execution endpoints.
    /// </summary>
    internal const string Runbooks = "Runbooks";
}
