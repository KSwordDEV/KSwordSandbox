namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Public settings state for the VirusTotal integration.
/// Inputs come from the local settings store; processing masks sensitive values;
/// the record returned to the browser never includes the API key.
/// </summary>
internal sealed record VirusTotalSettingsState(
    bool Configured,
    string? ApiKeyMask,
    string Source,
    string? SettingsPath);

/// <summary>
/// Request body for updating the local VirusTotal API key.
/// Inputs come from the settings page; processing stores or clears the key; the
/// key is never returned by any response.
/// </summary>
internal sealed record VirusTotalSettingsUpdateRequest(string? ApiKey, bool Clear = false);

/// <summary>
/// Operator-safe VirusTotal lookup result.
/// Inputs are local sample hash plus optional VirusTotal API response;
/// processing extracts summary fields only; the record returned to WebUI never
/// includes the API key and suppresses transport error details.
/// </summary>
internal sealed record VirusTotalLookupResult
{
    public required string Sha256 { get; init; }

    public bool Configured { get; init; }

    public bool Queried { get; init; }

    public bool Found { get; init; }

    public string Status { get; init; } = "not_configured";

    public string? Message { get; init; }

    public string? Permalink { get; init; }

    public string? MeaningfulName { get; init; }

    public DateTimeOffset? LastAnalysisDateUtc { get; init; }

    public Dictionary<string, int> LastAnalysisStats { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}
