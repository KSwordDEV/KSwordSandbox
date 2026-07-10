namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: endpoint modules created manually or resolved from dependency injection.
/// Processing: stores modules and exposes deterministic ordering by descriptor order and name.
/// Return behavior: returns ordered module sequences for route registration.
/// </summary>
internal sealed class EndpointModuleCollection
{
    private readonly List<IWebEndpointModule> _modules = new();

    /// <summary>
    /// Gets the modules in their insertion order.
    /// </summary>
    internal IReadOnlyList<IWebEndpointModule> Modules => _modules;

    /// <summary>
    /// Inputs: a module instance supplied by the composition root.
    /// Processing: appends the module after checking for null.
    /// Return behavior: returns this collection so callers can chain module additions.
    /// </summary>
    internal EndpointModuleCollection Add(IWebEndpointModule module)
    {
        ArgumentNullException.ThrowIfNull(module);
        _modules.Add(module);
        return this;
    }

    /// <summary>
    /// Inputs: modules already stored in this collection.
    /// Processing: orders modules first by descriptor order and then by descriptor name.
    /// Return behavior: returns a deterministic module sequence for endpoint mapping.
    /// </summary>
    internal IEnumerable<IWebEndpointModule> InRegistrationOrder()
    {
        return _modules
            .OrderBy(module => module.Descriptor.Order)
            .ThenBy(module => module.Descriptor.Name, StringComparer.OrdinalIgnoreCase);
    }
}
