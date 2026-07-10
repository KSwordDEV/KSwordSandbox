namespace KSword.Sandbox.Core.Rules.Import;

/// <summary>
/// Reports non-fatal issues found while loading rule or taxonomy files.
/// Inputs are parser errors and warning details; processing stores location and
/// text, and the record is returned to callers for display.
/// </summary>
public sealed record RuleImportDiagnostic
{
    public string SourcePath { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public bool IsError { get; init; }
}
