namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: no constructor input.
/// Processing: declares the health route area that will receive extracted health endpoints.
/// Return behavior: inherits mapping behavior from EndpointModuleBase.
/// </summary>
internal sealed class HealthEndpointModule : EndpointModuleBase
{
    /// <summary>
    /// Inputs: none.
    /// Processing: initializes health module metadata with the health prefix and health tag.
    /// Return behavior: constructs a health endpoint module instance.
    /// </summary>
    public HealthEndpointModule()
        : base(EndpointModuleDescriptor.Create("Health", "/health", 10, EndpointTags.Health))
    {
    }
}
