namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: module name, route prefix, ordering value, and documentation tags.
/// Processing: captures route-module metadata separately from route mapping code.
/// Return behavior: instances are attached to route groups and used for registration ordering.
/// </summary>
/// <param name="Name">Stable module name used in diagnostics and route metadata.</param>
/// <param name="Prefix">Route prefix owned by the module.</param>
/// <param name="Order">Registration order used when modules are mapped as a collection.</param>
/// <param name="Tags">Documentation and UI tags associated with the module.</param>
internal sealed record EndpointModuleDescriptor(
    string Name,
    string Prefix,
    int Order,
    IReadOnlyList<string> Tags)
{
    /// <summary>
    /// Inputs: raw module metadata supplied by an endpoint module.
    /// Processing: validates required fields, normalizes route prefixes, and de-duplicates tags.
    /// Return behavior: returns a descriptor ready for route-group metadata.
    /// </summary>
    internal static EndpointModuleDescriptor Create(string name, string prefix, int order, params string[] tags)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var normalizedPrefix = string.IsNullOrWhiteSpace(prefix) ? "/" : prefix.Trim();
        if (!normalizedPrefix.StartsWith('/'))
        {
            normalizedPrefix = "/" + normalizedPrefix;
        }

        var normalizedTags = tags
            .Where(tag => !string.IsNullOrWhiteSpace(tag))
            .Select(tag => tag.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new EndpointModuleDescriptor(name.Trim(), normalizedPrefix, order, normalizedTags);
    }
}
