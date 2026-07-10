namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: no runtime input.
/// Processing: creates the default endpoint module set in the same order expected by the Web host.
/// Return behavior: returns a materialized module list that can be mapped or registered with DI.
/// </summary>
internal static class EndpointModuleCatalog
{
    /// <summary>
    /// Inputs: none.
    /// Processing: instantiates the default modules that will eventually replace endpoint blocks in Program.cs.
    /// Return behavior: returns modules ordered by each descriptor's registration order.
    /// </summary>
    internal static IReadOnlyList<IWebEndpointModule> CreateDefaultModules()
    {
        return new IWebEndpointModule[]
        {
            new DashboardEndpointModule(),
            new HealthEndpointModule(),
            new FileEndpointModule(),
            new JobEndpointModule(),
            new RunbookEndpointModule()
        }
        .OrderBy(module => module.Descriptor.Order)
        .ThenBy(module => module.Descriptor.Name, StringComparer.OrdinalIgnoreCase)
        .ToArray();
    }
}
