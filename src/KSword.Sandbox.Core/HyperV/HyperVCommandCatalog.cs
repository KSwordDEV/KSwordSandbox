namespace KSword.Sandbox.Core.HyperV;

/// <summary>
/// Centralizes frequently used Hyper-V PowerShell command templates.
/// Inputs are VM names and paths; processing delegates escaping to
/// PowerShellLiteral; methods return command strings only.
/// </summary>
public sealed class HyperVCommandCatalog
{
    /// <summary>
    /// Builds a command that verifies a VM exists.
    /// The input is a VM name, processing quotes it, and the method returns a
    /// PowerShell command string.
    /// </summary>
    public string GetVm(string vmName)
    {
        return $"Get-VM -Name {PowerShellLiteral.Quote(vmName)} | Out-Null";
    }

    /// <summary>
    /// Builds a command that starts a VM.
    /// The input is a VM name, processing quotes it, and the method returns a
    /// PowerShell command string.
    /// </summary>
    public string StartVm(string vmName)
    {
        return $"Start-VM -Name {PowerShellLiteral.Quote(vmName)}";
    }

    /// <summary>
    /// Builds a command that force-stops a VM.
    /// The input is a VM name, processing quotes it, and the method returns a
    /// PowerShell command string.
    /// </summary>
    public string StopVm(string vmName)
    {
        return $"Stop-VM -Name {PowerShellLiteral.Quote(vmName)} -TurnOff -Force";
    }
}
