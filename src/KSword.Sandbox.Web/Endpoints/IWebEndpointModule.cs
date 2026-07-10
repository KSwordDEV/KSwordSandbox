using Microsoft.AspNetCore.Routing;

namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: an endpoint route builder supplied by Program.cs or a future composition root.
/// Processing: describes a self-contained route module that can map one Web feature area.
/// Return behavior: implementations return the same route builder after adding their routes.
/// </summary>
internal interface IWebEndpointModule
{
    /// <summary>
    /// Gets metadata that identifies the module, route prefix, order, and tags.
    /// </summary>
    EndpointModuleDescriptor Descriptor { get; }

    /// <summary>
    /// Inputs: the ASP.NET Core endpoint route builder that owns route registration.
    /// Processing: registers all routes owned by the module onto the supplied builder.
    /// Return behavior: returns the supplied builder so callers can continue fluent mapping.
    /// </summary>
    IEndpointRouteBuilder Map(IEndpointRouteBuilder endpoints);
}
