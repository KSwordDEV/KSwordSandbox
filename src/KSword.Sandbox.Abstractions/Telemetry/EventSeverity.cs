namespace KSword.Sandbox.Abstractions.Telemetry;

/// <summary>
/// Normalizes event importance before rules produce final findings.
/// Inputs are set by collectors or enrichment code, processing compares enum
/// values, and the value is returned in future live telemetry payloads.
/// </summary>
public enum EventSeverity
{
    Info = 0,
    Low,
    Medium,
    High
}
