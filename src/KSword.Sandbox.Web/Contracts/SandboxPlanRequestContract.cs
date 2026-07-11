namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: executable path, optional arguments, optional working directory, and optional labels from the browser.
/// Processing: carries planning intent across the Web boundary before core submission objects are created.
/// Return behavior: instances are deserialized from future plan endpoint request bodies.
/// </summary>
/// <param name="ExecutablePath">Absolute or repository-relative path selected by the user.</param>
/// <param name="Arguments">Optional command-line arguments supplied by the user.</param>
/// <param name="WorkingDirectory">Optional working directory supplied by the user.</param>
/// <param name="Labels">Optional labels used by the dashboard for grouping or filtering.</param>
/// <param name="CollectDroppedFiles">Explicit opt-in for dropped-file artifact collection.</param>
/// <param name="CaptureScreenshots">Explicit opt-in for screenshot artifact collection.</param>
/// <param name="CaptureMemoryDumps">Explicit opt-in for memory-dump artifact collection.</param>
/// <param name="CapturePacketCapture">Explicit opt-in for guest packet-capture artifact collection.</param>
public sealed record SandboxPlanRequestContract(
    string ExecutablePath,
    string? Arguments,
    string? WorkingDirectory,
    IReadOnlyList<string> Labels,
    bool? CollectDroppedFiles = null,
    bool? CaptureScreenshots = null,
    bool? CaptureMemoryDumps = null,
    bool? CapturePacketCapture = null);
