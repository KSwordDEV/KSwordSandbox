namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: no constructor input.
/// Processing: declares the runbook route area that will receive extracted runbook execution endpoints.
/// Return behavior: inherits mapping behavior from EndpointModuleBase.
/// </summary>
internal sealed class RunbookEndpointModule : EndpointModuleBase
{
    /// <summary>
    /// Inputs: none.
    /// Processing: initializes runbook module metadata with the API jobs prefix and runbooks tag.
    /// Return behavior: constructs a runbook endpoint module instance.
    /// </summary>
    public RunbookEndpointModule()
        : base(EndpointModuleDescriptor.Create("Runbooks", "/api/jobs", 40, EndpointTags.Runbooks))
    {
    }
}
