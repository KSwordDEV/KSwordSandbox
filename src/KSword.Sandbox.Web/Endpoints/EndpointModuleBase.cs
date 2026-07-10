using KSword.Sandbox.Web.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: endpoint module descriptors supplied by concrete feature modules.
/// Processing: creates the common route group and exposes a small metadata endpoint for framework diagnostics.
/// Return behavior: returns the supplied route builder after module routes are registered.
/// </summary>
internal abstract class EndpointModuleBase : IWebEndpointModule
{
    /// <summary>
    /// Inputs: descriptor metadata for the concrete endpoint module.
    /// Processing: stores descriptor metadata for route grouping and module ordering.
    /// Return behavior: constructs a module base instance ready for Map calls.
    /// </summary>
    protected EndpointModuleBase(EndpointModuleDescriptor descriptor)
    {
        Descriptor = descriptor;
    }

    /// <summary>
    /// Gets metadata that identifies this endpoint module.
    /// </summary>
    public EndpointModuleDescriptor Descriptor { get; }

    /// <summary>
    /// Inputs: the ASP.NET Core endpoint route builder that owns route registration.
    /// Processing: creates the route group and delegates feature-specific mapping to virtual hooks.
    /// Return behavior: returns the supplied builder after the module is mapped.
    /// </summary>
    public IEndpointRouteBuilder Map(IEndpointRouteBuilder endpoints)
    {
        var group = EndpointRouteGroupFactory.MapGroup(endpoints, Descriptor);
        MapModuleEndpoints(group);
        return endpoints;
    }

    /// <summary>
    /// Inputs: a route group already created for this module.
    /// Processing: maps the default metadata endpoint; derived modules can add feature endpoints later.
    /// Return behavior: no value is returned because the route group is mutated in place.
    /// </summary>
    protected virtual void MapModuleEndpoints(RouteGroupBuilder group)
    {
        MapFrameworkMetadata(group);
    }

    /// <summary>
    /// Inputs: a route group owned by this module.
    /// Processing: registers a metadata route that reports the module descriptor through the common API envelope.
    /// Return behavior: no value is returned because ASP.NET Core stores the route on the supplied group.
    /// </summary>
    protected void MapFrameworkMetadata(RouteGroupBuilder group)
    {
        group.MapGet("/framework", () =>
        {
            var envelope = ApiEnvelopeContract<EndpointModuleDescriptor>.Success(Descriptor, DateTimeOffset.UtcNow);
            return Results.Ok(envelope);
        });
    }
}
