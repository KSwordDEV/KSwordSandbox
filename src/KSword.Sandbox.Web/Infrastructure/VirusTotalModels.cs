using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Stable status/verdict tokens returned by VirusTotal lookup code. Inputs are
/// HTTP/configuration outcomes and parsed file-report stats; processing uses
/// these constants instead of ad-hoc strings so rule/report consumers can key
/// on clear values.
/// </summary>
internal static class VirusTotalLookupStatuses
{
    public const string MissingHash = "missing_hash";
    public const string NotConfigured = "not_configured";
    public const string NotFound = "not_found";
    public const string RateLimited = "rate_limited";
    public const string AuthenticationFailed = "authentication_failed";
    public const string LookupFailed = "lookup_failed";
    public const string Found = "found";
    public const string Malicious = "malicious";
    public const string Suspicious = "suspicious";
    public const string Clean = "clean";
    public const string Unknown = "unknown";
}

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
    private string? verdict;

    public required string Sha256 { get; init; }

    public bool Configured { get; init; }

    public bool Queried { get; init; }

    public bool Found { get; init; }

    public string Status { get; init; } = "not_configured";

    public string Verdict
    {
        get => string.IsNullOrWhiteSpace(verdict) ? StatusToVerdict(Status) : verdict!;
        init => verdict = value;
    }

    public string? Message { get; init; }

    public string? Permalink { get; init; }

    public string? MeaningfulName { get; init; }

    public DateTimeOffset? LastAnalysisDateUtc { get; init; }

    public int MaliciousCount { get; init; }

    public int SuspiciousCount { get; init; }

    public int HarmlessCount { get; init; }

    public int UndetectedCount { get; init; }

    public int TimeoutCount { get; init; }

    public int? HttpStatusCode { get; init; }

    public string? ErrorKind { get; init; }

    public DateTimeOffset? RetryAfterUtc { get; init; }

    public Dictionary<string, int> LastAnalysisStats { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, string> RuleData => BuildRuleData();

    /// <summary>
    /// Converts the lookup result into a normalized enrichment event that the
    /// existing rule engine can classify without numeric predicates.
    /// </summary>
    public SandboxEvent ToRuleEvent(DateTimeOffset? timestamp = null)
    {
        return new SandboxEvent
        {
            EventType = "enrichment.virustotal.lookup",
            Timestamp = timestamp ?? DateTimeOffset.UtcNow,
            Source = "virustotal",
            Path = Permalink,
            Data = new Dictionary<string, string>(RuleData, StringComparer.OrdinalIgnoreCase)
        };
    }

    private IReadOnlyDictionary<string, string> BuildRuleData()
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sha256"] = Sha256,
            ["vtStatus"] = Status,
            ["status"] = Status,
            ["vtVerdict"] = Verdict,
            ["verdict"] = Verdict,
            ["configured"] = Configured ? "true" : "false",
            ["queried"] = Queried ? "true" : "false",
            ["found"] = Found ? "true" : "false",
            ["vtMalicious"] = MaliciousCount.ToString(CultureInfo.InvariantCulture),
            ["vtSuspicious"] = SuspiciousCount.ToString(CultureInfo.InvariantCulture),
            ["vtHarmless"] = HarmlessCount.ToString(CultureInfo.InvariantCulture),
            ["vtUndetected"] = UndetectedCount.ToString(CultureInfo.InvariantCulture),
            ["vtTimeout"] = TimeoutCount.ToString(CultureInfo.InvariantCulture)
        };

        AddIfPresent(data, "message", Message);
        AddIfPresent(data, "permalink", Permalink);
        AddIfPresent(data, "meaningfulName", MeaningfulName);
        AddIfPresent(data, "errorKind", ErrorKind);
        if (HttpStatusCode is not null)
        {
            data["httpStatusCode"] = HttpStatusCode.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (RetryAfterUtc is not null)
        {
            data["retryAfterUtc"] = RetryAfterUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        if (LastAnalysisDateUtc is not null)
        {
            data["lastAnalysisDateUtc"] = LastAnalysisDateUtc.Value.ToString("O", CultureInfo.InvariantCulture);
        }

        return data;
    }

    private static void AddIfPresent(IDictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value.Trim();
        }
    }

    private static string StatusToVerdict(string? status)
    {
        return status switch
        {
            VirusTotalLookupStatuses.MissingHash => VirusTotalLookupStatuses.MissingHash,
            VirusTotalLookupStatuses.NotConfigured => VirusTotalLookupStatuses.NotConfigured,
            VirusTotalLookupStatuses.NotFound => VirusTotalLookupStatuses.NotFound,
            VirusTotalLookupStatuses.RateLimited => VirusTotalLookupStatuses.RateLimited,
            VirusTotalLookupStatuses.AuthenticationFailed => VirusTotalLookupStatuses.AuthenticationFailed,
            VirusTotalLookupStatuses.LookupFailed => VirusTotalLookupStatuses.LookupFailed,
            VirusTotalLookupStatuses.Found => VirusTotalLookupStatuses.Unknown,
            _ => VirusTotalLookupStatuses.Unknown
        };
    }
}
