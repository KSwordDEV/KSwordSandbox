namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: no constructor input.
/// Processing: declares the job route area that will receive extracted job plan, list, detail, and event endpoints.
/// Return behavior: inherits mapping behavior from EndpointModuleBase.
/// </summary>
internal sealed class JobEndpointModule : EndpointModuleBase
{
    /// <summary>
    /// Inputs: none.
    /// Processing: initializes job module metadata with the API jobs prefix and jobs tag.
    /// Return behavior: constructs a job endpoint module instance.
    /// </summary>
    public JobEndpointModule()
        : base(EndpointModuleDescriptor.Create("Jobs", "/api/jobs", 30, EndpointTags.Jobs))
    {
    }
}
