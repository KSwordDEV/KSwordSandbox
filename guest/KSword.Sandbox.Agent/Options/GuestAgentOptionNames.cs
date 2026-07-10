namespace KSword.Sandbox.Agent.Options;

/// <summary>
/// Centralizes command-line switch names accepted by the guest agent.
/// Inputs are none; processing exposes constants; callers use values to avoid
/// duplicated option strings and return no runtime state.
/// </summary>
internal static class GuestAgentOptionNames
{
    public const string Sample = "sample";
    public const string Output = "out";
    public const string Duration = "duration";
    public const string DriverEvents = "driver-events";
    public const string DriverDevice = "driver-device";
    public const string R0Collector = "r0collector";
    public const string R0CollectorAlias = "r0-collector";
    public const string R0Mock = "r0-mock";
}
