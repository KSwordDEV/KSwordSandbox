namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: no constructor input.
/// Processing: declares the dashboard route area that will receive extracted HTML and bootstrap endpoints.
/// Return behavior: inherits mapping behavior from EndpointModuleBase.
/// </summary>
internal sealed class DashboardEndpointModule : EndpointModuleBase
{
    /// <summary>
    /// Inputs: none.
    /// Processing: initializes dashboard module metadata with the root prefix and dashboard tag.
    /// Return behavior: constructs a dashboard endpoint module instance.
    /// </summary>
    public DashboardEndpointModule()
        : base(EndpointModuleDescriptor.Create("Dashboard", "/", 0, EndpointTags.Dashboard))
    {
    }
}
