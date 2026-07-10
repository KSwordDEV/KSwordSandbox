using Microsoft.AspNetCore.Routing;

namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: ASP.NET Core route builders and endpoint module collections.
/// Processing: maps modules in deterministic order without requiring Program.cs to know each module type.
/// Return behavior: returns the original route builder after all modules have been mapped.
/// </summary>
internal static class EndpointModuleExtensions
{
    /// <summary>
    /// Inputs: an endpoint route builder and endpoint modules.
    /// Processing: orders modules by descriptor metadata and invokes each module's Map method.
    /// Return behavior: returns the supplied builder for fluent route registration.
    /// </summary>
    internal static IEndpointRouteBuilder MapSandboxEndpointModules(
        this IEndpointRouteBuilder endpoints,
        IEnumerable<IWebEndpointModule> modules)
    {
        var collection = new EndpointModuleCollection();
        foreach (var module in modules)
        {
            collection.Add(module);
        }

        foreach (var module in collection.InRegistrationOrder())
        {
            module.Map(endpoints);
        }

        return endpoints;
    }
}
