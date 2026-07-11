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
/// Flattened VirusTotal community vote counts. Inputs are total_votes from the
/// official file object; processing keeps nullable counters so the WebUI can
/// distinguish "zero votes" from "field not present".
/// </summary>
internal sealed record VirusTotalCommunityVotes
{
    public int? Harmless { get; init; }

    public int? Malicious { get; init; }

    public bool HasVotes => Harmless is not null || Malicious is not null;

    public int Total => Math.Max(0, Harmless ?? 0) + Math.Max(0, Malicious ?? 0);

    public int Score => Math.Max(0, Harmless ?? 0) - Math.Max(0, Malicious ?? 0);
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

    public string? DetectionPermalink { get; init; }

    public string? OfficialApiSelfLink { get; init; }

    public string? MeaningfulName { get; init; }

    public DateTimeOffset? LastAnalysisDateUtc { get; init; }

    public int? Reputation { get; init; }

    public VirusTotalCommunityVotes CommunityVotes { get; init; } = new();

    public int? CommunityScore => Reputation ?? (CommunityVotes.HasVotes ? CommunityVotes.Score : null);

    public string? CommunityScoreSource => Reputation is not null
        ? "reputation"
        : CommunityVotes.HasVotes
            ? "total_votes"
            : null;

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

    public string LiveLogPolicy => "display_only_no_job_log_by_default";

    public string PersistencePolicy => CanPersistEnrichmentEvent
        ? "display_only_by_default_explicit_persist_supported"
        : "display_only_quiet_status_not_persisted";

    public bool IsQuietState => Status is
        VirusTotalLookupStatuses.MissingHash or
        VirusTotalLookupStatuses.InvalidHash or
        VirusTotalLookupStatuses.NotConfigured or
        VirusTotalLookupStatuses.NotFound or
        VirusTotalLookupStatuses.RateLimited or
        VirusTotalLookupStatuses.AuthenticationFailed or
        VirusTotalLookupStatuses.Timeout or
        VirusTotalLookupStatuses.LookupFailed;

    public string? QuietFailureReason => IsQuietState ? Status : null;

    public string? QuietFailureExplanation => IsQuietState
        ? BuildQuietFailureExplanation(Status, ErrorKind, HttpStatusCode, Message)
        : null;

    public bool CanPersistEnrichmentEvent => Configured &&
        Queried &&
        string.Equals(Status, VirusTotalLookupStatuses.Found, StringComparison.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, string> RuleData => BuildRuleData();

    /// <summary>
    /// Converts the lookup result into a normalized enrichment event that the
    /// existing rule engine can classify without numeric predicates. Only real
    /// found query outcomes are eligible; not_found, local configuration,
    /// authentication, rate-limit, timeout, and transport states intentionally
    /// stay out of behavior rules.
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
        AddIfPresent(data, "detectionPermalink", DetectionPermalink);
        AddIfPresent(data, "officialApiSelfLink", OfficialApiSelfLink);
        AddIfPresent(data, "meaningfulName", MeaningfulName);
        AddIfPresent(data, "errorKind", ErrorKind);
        AddIfPresent(data, "cacheAgeSeconds", FormatNullableSeconds(CacheAgeSeconds));
        AddIfPresent(data, "quietFailureReason", QuietFailureReason);
        AddIfPresent(data, "quietFailureExplanation", QuietFailureExplanation);
        if (Reputation is not null)
        {
            data["vtReputation"] = Reputation.Value.ToString(CultureInfo.InvariantCulture);
            data["reputation"] = data["vtReputation"];
        }

        if (CommunityScore is not null)
        {
            data["vtCommunityScore"] = CommunityScore.Value.ToString(CultureInfo.InvariantCulture);
            data["communityScore"] = data["vtCommunityScore"];
        }

        AddIfPresent(data, "communityScoreSource", CommunityScoreSource);
        if (CommunityVotes.HasVotes)
        {
            data["vtCommunityHarmlessVotes"] = Math.Max(0, CommunityVotes.Harmless ?? 0).ToString(CultureInfo.InvariantCulture);
            data["vtCommunityMaliciousVotes"] = Math.Max(0, CommunityVotes.Malicious ?? 0).ToString(CultureInfo.InvariantCulture);
            data["vtCommunityVoteCount"] = CommunityVotes.Total.ToString(CultureInfo.InvariantCulture);
        }

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

    private static string BuildQuietFailureExplanation(string? status, string? errorKind, int? httpStatusCode, string? message)
    {
        var baseMessage = string.IsNullOrWhiteSpace(message) ? null : message.Trim();
        var explanation = status switch
        {
            VirusTotalLookupStatuses.MissingHash => "样本 SHA-256 不可用，未调用 VirusTotal 官方 API；仅作为页面状态展示，不写任务/行为日志 / Sample SHA-256 is unavailable; official API was not called.",
            VirusTotalLookupStatuses.InvalidHash => "样本 SHA-256 格式无效，未调用 VirusTotal 官方 API；仅作为页面状态展示，不写任务/行为日志 / Sample SHA-256 is malformed; official API was not called.",
            VirusTotalLookupStatuses.NotConfigured => "VirusTotal API Key 未配置，已静默跳过查询；沙箱执行继续，不写任务/行为日志 / API key is not configured; lookup is skipped quietly.",
            VirusTotalLookupStatuses.NotFound => "VirusTotal 未收录该 SHA-256；这是信誉查询状态，不代表样本行为，默认不写任务/行为日志 / VirusTotal has no report for this SHA-256; this is reputation status, not sample behavior.",
            VirusTotalLookupStatuses.RateLimited => "VirusTotal 返回限速，已静默停止本次查询；可稍后重试，不写任务/行为日志 / VirusTotal returned a rate-limit response; retry later.",
            VirusTotalLookupStatuses.AuthenticationFailed => "VirusTotal 拒绝当前 API Key；请在设置页检查，沙箱执行继续，不写任务/行为日志 / VirusTotal rejected the API key; check Settings before retrying.",
            VirusTotalLookupStatuses.Timeout => "VirusTotal 查询超时；沙箱执行继续，该超时仅在页面展示，不写任务/行为日志 / VirusTotal lookup timed out; sandbox execution continues.",
            VirusTotalLookupStatuses.LookupFailed => "VirusTotal 查询在网络、HTTP 或解析阶段失败；失败仅在页面展示，不写任务/行为日志 / VirusTotal lookup failed during transport, HTTP, or response parsing.",
            _ => "VirusTotal 处于静默非阻断状态；仅页面展示，不写任务/行为日志 / VirusTotal lookup is in a quiet non-blocking state."
        };

        if (httpStatusCode is not null && !explanation.Contains(httpStatusCode.Value.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))
        {
            explanation = $"{explanation} HTTP {httpStatusCode.Value.ToString(CultureInfo.InvariantCulture)}.";
        }

        if (!string.IsNullOrWhiteSpace(errorKind))
        {
            explanation = $"{explanation} errorKind={errorKind.Trim()}.";
        }

        return baseMessage is null
            ? explanation
            : $"{explanation} Provider message: {baseMessage}";
    }
}
