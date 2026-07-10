using KSword.Sandbox.Web.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: the ASP.NET Core service collection.
/// Processing: registers Web endpoint module services and lightweight Web infrastructure services.
/// Return behavior: returns the same service collection for fluent host configuration.
/// </summary>
internal static class EndpointServiceCollectionExtensions
{
    /// <summary>
    /// Inputs: a service collection owned by the Web host builder.
    /// Processing: registers the default clock and endpoint module implementations as singleton services.
    /// Return behavior: returns the supplied service collection after registrations are added.
    /// </summary>
    internal static IServiceCollection AddSandboxWebEndpointModules(this IServiceCollection services)
    {
        services.AddSingleton<ISandboxWebClock, SystemSandboxWebClock>();
        services.AddSingleton<IWebEndpointModule, DashboardEndpointModule>();
        services.AddSingleton<IWebEndpointModule, HealthEndpointModule>();
        services.AddSingleton<IWebEndpointModule, FileEndpointModule>();
        services.AddSingleton<IWebEndpointModule, JobEndpointModule>();
        services.AddSingleton<IWebEndpointModule, RunbookEndpointModule>();
        return services;
    }
}
