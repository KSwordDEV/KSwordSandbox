namespace KSword.Sandbox.Core.HyperV;

/// <summary>
/// Provides small formatting helpers for PowerShell command generation.
/// Inputs are raw strings; processing escapes single-quoted literals; methods
/// return text that can be embedded in generated runbook commands.
/// </summary>
public static class PowerShellLiteral
{
    /// <summary>
    /// Quotes a string for single-quoted PowerShell syntax.
    /// The input is raw text, processing doubles embedded single quotes, and
    /// the method returns a quoted literal.
    /// </summary>
    public static string Quote(string value)
    {
        return $"'{value.Replace("'", "''")}'";
    }
}
