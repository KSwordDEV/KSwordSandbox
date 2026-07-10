using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: an endpoint route builder and endpoint module metadata.
/// Processing: creates route groups with normalized prefixes and attaches module descriptors as metadata.
/// Return behavior: returns a RouteGroupBuilder that module implementations can populate.
/// </summary>
internal static class EndpointRouteGroupFactory
{
    /// <summary>
    /// Inputs: the owning route builder and the descriptor for the module being mapped.
    /// Processing: creates a route group for the descriptor prefix and attaches the descriptor to endpoint metadata.
    /// Return behavior: returns the route group for module-specific route registration.
    /// </summary>
    internal static RouteGroupBuilder MapGroup(IEndpointRouteBuilder endpoints, EndpointModuleDescriptor descriptor)
    {
        var group = endpoints.MapGroup(descriptor.Prefix);
        group.WithMetadata(descriptor);
        return group;
    }
}
