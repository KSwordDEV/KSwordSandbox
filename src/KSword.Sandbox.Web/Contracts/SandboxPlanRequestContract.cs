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
public sealed record SandboxPlanRequestContract(
    string ExecutablePath,
    string? Arguments,
    string? WorkingDirectory,
    IReadOnlyList<string> Labels);
