namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: service status, display name, and UTC generation timestamp.
/// Processing: captures health data in a named contract instead of an anonymous object.
/// Return behavior: instances are serialized by the health endpoint.
/// </summary>
/// <param name="Status">Machine-readable service status value.</param>
/// <param name="Service">Human-readable service name.</param>
/// <param name="GeneratedAtUtc">UTC timestamp captured when the health response was built.</param>
public sealed record HealthStatusContract(
    string Status,
    string Service,
    DateTimeOffset GeneratedAtUtc);
