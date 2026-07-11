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
    public const string InvalidHash = "invalid_hash";
    public const string NotConfigured = "not_configured";
    public const string NotFound = "not_found";
    public const string RateLimited = "rate_limited";
    public const string AuthenticationFailed = "authentication_failed";
    public const string Timeout = "timeout";
    public const string LookupFailed = "lookup_failed";
    public const string Found = "found";
    public const string Malicious = "malicious";
    public const string Suspicious = "suspicious";
    public const string Clean = "clean";
    public const string Unknown = "unknown";
}

/// <summary>
/// Stable event names used by VirusTotal enrichment. The report/rule event type
/// stays compatible with the current rule set, while vt.lookup is carried as a
/// compact provider event name for downstream enrichment consumers.
/// </summary>
internal static class VirusTotalLookupEventNames
{
    public const string RuleEngineEventType = "enrichment.virustotal.lookup";
    public const string CompactLookupName = "vt.lookup";
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
/// Flattened VirusTotal engine counts for browser display. Inputs are
/// last_analysis_stats from the official file report; processing keeps the
/// common counters as named fields while preserving the raw stats dictionary on
/// the lookup result for forward compatibility.
/// </summary>
internal sealed record VirusTotalEngineCounts
{
    public int Malicious { get; init; }

    public int Suspicious { get; init; }

    public int Harmless { get; init; }

    public int Undetected { get; init; }

    public int Timeout { get; init; }

    public int ConfirmedTimeout { get; init; }

    public int Failure { get; init; }

    public int TypeUnsupported { get; init; }

    public int Total { get; init; }
}

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

    public int Score => MaliciousCount + SuspiciousCount;

    public int DetectionCount => Score;

    public int EngineCount => EngineCounts.Total > 0
        ? EngineCounts.Total
        : Math.Max(0, MaliciousCount) +
            Math.Max(0, SuspiciousCount) +
            Math.Max(0, HarmlessCount) +
            Math.Max(0, UndetectedCount) +
            Math.Max(0, TimeoutCount);

    public VirusTotalEngineCounts EngineCounts { get; init; } = new();

    public int? HttpStatusCode { get; init; }

    public string? ErrorKind { get; init; }

    public DateTimeOffset? RetryAfterUtc { get; init; }

    public Dictionary<string, int> LastAnalysisStats { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public bool CacheHit { get; init; }

    public DateTimeOffset? CachedAtUtc { get; init; }

    public DateTimeOffset? CacheExpiresAtUtc { get; init; }

    public double? CacheAgeSeconds { get; init; }

    public double? CacheTtlSeconds { get; init; }

    public bool PersistedToEnrichmentEvents { get; init; }

    public bool IsQuietState => Status is
        VirusTotalLookupStatuses.MissingHash or
        VirusTotalLookupStatuses.InvalidHash or
        VirusTotalLookupStatuses.NotConfigured or
        VirusTotalLookupStatuses.NotFound or
        VirusTotalLookupStatuses.RateLimited or
        VirusTotalLookupStatuses.AuthenticationFailed or
        VirusTotalLookupStatuses.Timeout or
        VirusTotalLookupStatuses.LookupFailed;

    public bool CanPersistEnrichmentEvent => Configured &&
        Queried &&
        (string.Equals(Status, VirusTotalLookupStatuses.Found, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Status, VirusTotalLookupStatuses.NotFound, StringComparison.OrdinalIgnoreCase));

    public IReadOnlyDictionary<string, string> RuleData => BuildRuleData();

    /// <summary>
    /// Converts the lookup result into a normalized enrichment event that the
    /// existing rule engine can classify without numeric predicates. Only real
    /// found/not_found query outcomes are eligible; local configuration,
    /// authentication, rate-limit, and timeout states intentionally stay out of
    /// behavior rules.
    /// </summary>
    public SandboxEvent ToRuleEvent(DateTimeOffset? timestamp = null)
    {
        if (!CanPersistEnrichmentEvent)
        {
            throw new InvalidOperationException(
                $"VirusTotal status '{Status}' is not eligible for behavior-rule enrichment persistence.");
        }

        return new SandboxEvent
        {
            EventType = VirusTotalLookupEventNames.RuleEngineEventType,
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
            ["vtEventName"] = VirusTotalLookupEventNames.CompactLookupName,
            ["eventName"] = VirusTotalLookupEventNames.CompactLookupName,
            ["vtVerdict"] = Verdict,
            ["verdict"] = Verdict,
            ["configured"] = Configured ? "true" : "false",
            ["queried"] = Queried ? "true" : "false",
            ["found"] = Found ? "true" : "false",
            ["vtMalicious"] = MaliciousCount.ToString(CultureInfo.InvariantCulture),
            ["vtSuspicious"] = SuspiciousCount.ToString(CultureInfo.InvariantCulture),
            ["vtHarmless"] = HarmlessCount.ToString(CultureInfo.InvariantCulture),
            ["vtUndetected"] = UndetectedCount.ToString(CultureInfo.InvariantCulture),
            ["vtTimeout"] = TimeoutCount.ToString(CultureInfo.InvariantCulture),
            ["vtScore"] = Score.ToString(CultureInfo.InvariantCulture),
            ["score"] = Score.ToString(CultureInfo.InvariantCulture),
            ["vtDetectionCount"] = DetectionCount.ToString(CultureInfo.InvariantCulture),
            ["vtEngineCount"] = EngineCount.ToString(CultureInfo.InvariantCulture),
            ["engineCount"] = EngineCount.ToString(CultureInfo.InvariantCulture),
            ["cacheHit"] = CacheHit ? "true" : "false"
        };

        AddIfPresent(data, "message", Message);
        AddIfPresent(data, "permalink", Permalink);
        AddIfPresent(data, "meaningfulName", MeaningfulName);
        AddIfPresent(data, "errorKind", ErrorKind);
        AddIfPresent(data, "cacheAgeSeconds", FormatNullableSeconds(CacheAgeSeconds));
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

    public VirusTotalLookupResult WithCacheMetadata(
        bool cacheHit,
        DateTimeOffset? cachedAtUtc,
        DateTimeOffset? cacheExpiresAtUtc,
        TimeSpan? cacheTtl,
        DateTimeOffset? nowUtc = null)
    {
        double? ageSeconds = null;
        if (cachedAtUtc is not null)
        {
            var age = (nowUtc ?? DateTimeOffset.UtcNow) - cachedAtUtc.Value;
            ageSeconds = Math.Round(Math.Max(0, age.TotalSeconds), 3);
        }

        return this with
        {
            CacheHit = cacheHit,
            CachedAtUtc = cachedAtUtc?.ToUniversalTime(),
            CacheExpiresAtUtc = cacheExpiresAtUtc?.ToUniversalTime(),
            CacheAgeSeconds = ageSeconds,
            CacheTtlSeconds = cacheTtl is null
                ? null
                : Math.Round(Math.Max(0, cacheTtl.Value.TotalSeconds), 3)
        };
    }

    private static void AddIfPresent(IDictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value.Trim();
        }
    }

    private static string? FormatNullableSeconds(double? seconds)
    {
        return seconds is null
            ? null
            : seconds.Value.ToString("0.###", CultureInfo.InvariantCulture);
    }

    private static string StatusToVerdict(string? status)
    {
        return status switch
        {
            VirusTotalLookupStatuses.MissingHash => VirusTotalLookupStatuses.MissingHash,
            VirusTotalLookupStatuses.InvalidHash => VirusTotalLookupStatuses.InvalidHash,
            VirusTotalLookupStatuses.NotConfigured => VirusTotalLookupStatuses.NotConfigured,
            VirusTotalLookupStatuses.NotFound => VirusTotalLookupStatuses.NotFound,
            VirusTotalLookupStatuses.RateLimited => VirusTotalLookupStatuses.RateLimited,
            VirusTotalLookupStatuses.AuthenticationFailed => VirusTotalLookupStatuses.AuthenticationFailed,
            VirusTotalLookupStatuses.Timeout => VirusTotalLookupStatuses.Timeout,
            VirusTotalLookupStatuses.LookupFailed => VirusTotalLookupStatuses.LookupFailed,
            VirusTotalLookupStatuses.Found => VirusTotalLookupStatuses.Unknown,
            _ => VirusTotalLookupStatuses.Unknown
        };
    }
}
