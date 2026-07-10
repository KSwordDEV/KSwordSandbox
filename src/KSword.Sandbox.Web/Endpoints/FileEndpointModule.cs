namespace KSword.Sandbox.Web.Endpoints;

/// <summary>
/// Inputs: no constructor input.
/// Processing: declares the file route area that will receive extracted scan and upload endpoints.
/// Return behavior: inherits mapping behavior from EndpointModuleBase.
/// </summary>
internal sealed class FileEndpointModule : EndpointModuleBase
{
    /// <summary>
    /// Inputs: none.
    /// Processing: initializes file module metadata with the API file prefix and files tag.
    /// Return behavior: constructs a file endpoint module instance.
    /// </summary>
    public FileEndpointModule()
        : base(EndpointModuleDescriptor.Create("Files", "/api/files", 20, EndpointTags.Files))
    {
    }
}
