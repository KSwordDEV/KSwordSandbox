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
    string? SettingsPath)
{
    public string Provider => "VirusTotal";

    public string LookupMode => "hash_only_no_sample_upload";

    public string PersistencePolicy => "process_environment_only_no_disk";

    public string ApiKeyPersistenceScope => "process_only_current_web_host_environment";

    public string NoSampleUploadGuarantee => "official_files_hash_lookup_only_no_sample_upload";

    public string QuietFailurePolicy => "missing_key_not_found_rate_limit_auth_timeout_are_display_only_no_job_log";

    public IReadOnlyList<string> QuietStateTaxonomy =>
    [
        VirusTotalLookupStatuses.NotConfigured,
        VirusTotalLookupStatuses.NotFound,
        VirusTotalLookupStatuses.RateLimited,
        VirusTotalLookupStatuses.AuthenticationFailed,
        VirusTotalLookupStatuses.Timeout,
        VirusTotalLookupStatuses.LookupFailed,
        VirusTotalLookupStatuses.MissingHash,
        VirusTotalLookupStatuses.InvalidHash
    ];

    public string ZhProcessOnlySummary => Configured
        ? $"API Key 当前来源：{Source}；设置页写入/清除只影响当前 Web Host 进程环境变量，WebUI 不落盘。"
        : "API Key 未配置；可在本页临时写入当前 Web Host 进程环境变量，WebUI 不落盘。";

    public string ZhPolicySummary => Configured
        ? "VirusTotal 已配置：仅对 SHA-256 调用官方 files/{hash} 查询，不上传样本；Key 只在进程/User/Machine 环境变量中读取，不写入报告或 job 日志。"
        : "VirusTotal 未配置：沙箱主流程继续；动态监控页/API 只显示静默状态，不写任务/行为日志。";
}

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
/// One VirusTotal popular-threat classification item. Inputs are entries from
/// the official file object's popular_threat_classification arrays; processing
/// keeps provider value/count pairs without turning them into sandbox behavior.
/// </summary>
internal sealed record VirusTotalThreatClassificationItem(string Value, int Count);

/// <summary>
/// VirusTotal's official popular_threat_classification summary. Inputs are the
/// nested official file object fields; processing preserves category/name votes
/// and suggested labels as API metadata only.
/// </summary>
internal sealed record VirusTotalThreatClassification
{
    public string? SuggestedThreatLabel { get; init; }

    public IReadOnlyList<VirusTotalThreatClassificationItem> PopularThreatCategories { get; init; } =
        Array.Empty<VirusTotalThreatClassificationItem>();

    public IReadOnlyList<VirusTotalThreatClassificationItem> PopularThreatNames { get; init; } =
        Array.Empty<VirusTotalThreatClassificationItem>();

    public string? TopThreatCategory => PopularThreatCategories.Count > 0
        ? PopularThreatCategories[0].Value
        : null;

    public string? TopThreatName => PopularThreatNames.Count > 0
        ? PopularThreatNames[0].Value
        : null;

    public string? PopularThreatCategorySummary => FormatThreatItems(PopularThreatCategories, 6);

    public string? PopularThreatNameSummary => FormatThreatItems(PopularThreatNames, 6);

    public string? ThreatClassificationSummary
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(SuggestedThreatLabel))
            {
                parts.Add($"label={SuggestedThreatLabel.Trim()}");
            }

            if (!string.IsNullOrWhiteSpace(PopularThreatCategorySummary))
            {
                parts.Add($"categories={PopularThreatCategorySummary}");
            }

            if (!string.IsNullOrWhiteSpace(PopularThreatNameSummary))
            {
                parts.Add($"names={PopularThreatNameSummary}");
            }

            return parts.Count == 0 ? null : string.Join("; ", parts);
        }
    }

    private static string? FormatThreatItems(IReadOnlyList<VirusTotalThreatClassificationItem> values, int limit)
    {
        return values.Count == 0
            ? null
            : string.Join(", ", values
                .Where(static value => !string.IsNullOrWhiteSpace(value.Value))
                .Select(static value => $"{value.Value.Trim()}:{Math.Max(0, value.Count).ToString(CultureInfo.InvariantCulture)}")
                .Take(Math.Max(1, limit)));
    }
}

/// <summary>
/// Selected official VirusTotal file object fields exposed by the lookup API.
/// Inputs are data.id/data.type plus attributes from /api/v3/files/{hash};
/// processing keeps identity, type, timing, names/tags, and threat-label
/// metadata operator-safe while never storing API keys or sample bytes.
/// </summary>
internal sealed record VirusTotalOfficialFileObject
{
    public string? Id { get; init; }

    public string? Type { get; init; }

    public string? Md5 { get; init; }

    public string? Sha1 { get; init; }

    public string? Sha256 { get; init; }

    public long? SizeBytes { get; init; }

    public string? FileTypeDescription { get; init; }

    public string? TypeTag { get; init; }

    public string? Magic { get; init; }

    public IReadOnlyList<string> Names { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();

    public DateTimeOffset? FirstSubmissionDateUtc { get; init; }

    public DateTimeOffset? LastSubmissionDateUtc { get; init; }

    public DateTimeOffset? LastAnalysisDateUtc { get; init; }

    public DateTimeOffset? LastModificationDateUtc { get; init; }

    public DateTimeOffset? FirstSeenInTheWildDateUtc { get; init; }

    public VirusTotalThreatClassification ThreatClassification { get; init; } = new();

    public string? NamesSummary => JoinValues(Names, 8);

    public string? TagsSummary => JoinValues(Tags, 12);

    public string? TypeSummary
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(FileTypeDescription))
            {
                parts.Add(FileTypeDescription.Trim());
            }

            if (!string.IsNullOrWhiteSpace(TypeTag) &&
                !parts.Contains(TypeTag.Trim(), StringComparer.OrdinalIgnoreCase))
            {
                parts.Add(TypeTag.Trim());
            }

            if (!string.IsNullOrWhiteSpace(Magic))
            {
                parts.Add(Magic.Trim());
            }

            return parts.Count == 0 ? null : string.Join(" / ", parts.Take(3));
        }
    }

    public IReadOnlyList<string> OfficialSummaryFields =>
    [
        "id",
        "type",
        "md5",
        "sha1",
        "sha256",
        "sizeBytes",
        "fileTypeDescription",
        "typeTag",
        "magic",
        "names",
        "tags",
        "firstSubmissionDateUtc",
        "lastSubmissionDateUtc",
        "lastAnalysisDateUtc",
        "lastModificationDateUtc",
        "firstSeenInTheWildDateUtc",
        "threatClassification"
    ];

    public string? OfficialSummary
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(TypeSummary))
            {
                parts.Add($"type={TypeSummary}");
            }

            if (SizeBytes is not null)
            {
                parts.Add($"sizeBytes={SizeBytes.Value.ToString(CultureInfo.InvariantCulture)}");
            }

            if (!string.IsNullOrWhiteSpace(NamesSummary))
            {
                parts.Add($"names={NamesSummary}");
            }

            if (!string.IsNullOrWhiteSpace(TagsSummary))
            {
                parts.Add($"tags={TagsSummary}");
            }

            if (!string.IsNullOrWhiteSpace(ThreatClassification.ThreatClassificationSummary))
            {
                parts.Add($"threat={ThreatClassification.ThreatClassificationSummary}");
            }

            return parts.Count == 0 ? null : string.Join("; ", parts);
        }
    }

    public string? ZhOfficialSummary
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(TypeSummary))
            {
                parts.Add($"类型={TypeSummary}");
            }

            if (SizeBytes is not null)
            {
                parts.Add($"大小={SizeBytes.Value.ToString(CultureInfo.InvariantCulture)} bytes");
            }

            if (!string.IsNullOrWhiteSpace(NamesSummary))
            {
                parts.Add($"名称={NamesSummary}");
            }

            if (!string.IsNullOrWhiteSpace(TagsSummary))
            {
                parts.Add($"标签={TagsSummary}");
            }

            if (!string.IsNullOrWhiteSpace(ThreatClassification.ThreatClassificationSummary))
            {
                parts.Add($"威胁分类={ThreatClassification.ThreatClassificationSummary}");
            }

            return parts.Count == 0 ? null : string.Join("；", parts);
        }
    }

    private static string? JoinValues(IReadOnlyList<string> values, int limit)
    {
        return values.Count == 0
            ? null
            : string.Join(", ", values
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Take(Math.Max(1, limit)));
    }
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

    public string? QuietErrorKind => IsQuietState
        ? ResolveQuietErrorKind(Status, ErrorKind, HttpStatusCode)
        : null;

    public string? QuietErrorCategory => IsQuietState
        ? ResolveQuietErrorCategory(QuietErrorKind)
        : null;

    public string ZhStatusText => BuildZhStatusText(Status, Verdict, MaliciousCount, SuspiciousCount);

    public string ZhStatusDetail => BuildZhStatusDetail(Status, Verdict, MaliciousCount, SuspiciousCount, QuietErrorKind);

    public DateTimeOffset? RetryAfterUtc { get; init; }

    public Dictionary<string, int> LastAnalysisStats { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public VirusTotalOfficialFileObject OfficialFileObject { get; init; } = new();

    public string? OfficialFileObjectId => OfficialFileObject.Id;

    public string? OfficialFileObjectType => OfficialFileObject.Type;

    public string? Md5 => OfficialFileObject.Md5;

    public string? Sha1 => OfficialFileObject.Sha1;

    public string? OfficialSha256 => OfficialFileObject.Sha256;

    public long? FileSizeBytes => OfficialFileObject.SizeBytes;

    public string? FileTypeDescription => OfficialFileObject.FileTypeDescription;

    public string? TypeTag => OfficialFileObject.TypeTag;

    public string? Magic => OfficialFileObject.Magic;

    public IReadOnlyList<string> Names => OfficialFileObject.Names;

    public IReadOnlyList<string> Tags => OfficialFileObject.Tags;

    public DateTimeOffset? FirstSubmissionDateUtc => OfficialFileObject.FirstSubmissionDateUtc;

    public DateTimeOffset? LastSubmissionDateUtc => OfficialFileObject.LastSubmissionDateUtc;

    public DateTimeOffset? LastModificationDateUtc => OfficialFileObject.LastModificationDateUtc;

    public DateTimeOffset? FirstSeenInTheWildDateUtc => OfficialFileObject.FirstSeenInTheWildDateUtc;

    public VirusTotalThreatClassification ThreatClassification => OfficialFileObject.ThreatClassification;

    public string? SuggestedThreatLabel => ThreatClassification.SuggestedThreatLabel;

    public string? TopThreatCategory => ThreatClassification.TopThreatCategory;

    public string? TopThreatName => ThreatClassification.TopThreatName;

    public string? PopularThreatCategorySummary => ThreatClassification.PopularThreatCategorySummary;

    public string? PopularThreatNameSummary => ThreatClassification.PopularThreatNameSummary;

    public string? ThreatClassificationSummary => ThreatClassification.ThreatClassificationSummary;

    public string? OfficialFileObjectSummary => OfficialFileObject.OfficialSummary;

    public string? ZhOfficialFileObjectSummary => OfficialFileObject.ZhOfficialSummary;

    public int LastAnalysisResultCount => LastAnalysisStats.Values.Where(static value => value > 0).Sum();

    public string LastAnalysisCategorySummary => BuildLastAnalysisCategorySummary();

    public bool CacheHit { get; init; }

    public DateTimeOffset? CachedAtUtc { get; init; }

    public DateTimeOffset? CacheExpiresAtUtc { get; init; }

    public double? CacheAgeSeconds { get; init; }

    public double? CacheTtlSeconds { get; init; }

    public bool PersistedToEnrichmentEvents { get; init; }

    public string LookupMode => "hash_only_no_sample_upload";

    public string NoSampleUploadGuarantee => "official_v3_files_hash_lookup_only_never_uploads_sample_bytes";

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

    public IReadOnlyList<string> QuietStateTaxonomy =>
    [
        VirusTotalLookupStatuses.NotConfigured,
        VirusTotalLookupStatuses.NotFound,
        VirusTotalLookupStatuses.RateLimited,
        VirusTotalLookupStatuses.AuthenticationFailed,
        VirusTotalLookupStatuses.Timeout,
        VirusTotalLookupStatuses.LookupFailed,
        VirusTotalLookupStatuses.MissingHash,
        VirusTotalLookupStatuses.InvalidHash
    ];

    public IReadOnlyList<string> OfficialSummaryFields => OfficialFileObject.OfficialSummaryFields;

    public string? OfficialSummary => OfficialFileObject.OfficialSummary;

    public string? ZhOfficialSummary => OfficialFileObject.ZhOfficialSummary;

    public string? QuietFailureReason => IsQuietState ? QuietErrorKind ?? Status : null;

    public string? QuietFailureExplanation => IsQuietState
        ? BuildQuietFailureExplanation(Status, QuietErrorKind, ErrorKind, HttpStatusCode, Message)
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
            ["zhStatusText"] = ZhStatusText,
            ["zhStatusDetail"] = ZhStatusDetail,
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
            ["vtLastAnalysisResultCount"] = LastAnalysisResultCount.ToString(CultureInfo.InvariantCulture),
            ["lastAnalysisResultCount"] = LastAnalysisResultCount.ToString(CultureInfo.InvariantCulture),
            ["vtLastAnalysisCategorySummary"] = LastAnalysisCategorySummary,
            ["lastAnalysisCategorySummary"] = LastAnalysisCategorySummary,
            ["cacheHit"] = CacheHit ? "true" : "false",
            ["lookupMode"] = LookupMode,
            ["noSampleUploadGuarantee"] = NoSampleUploadGuarantee
        };

        AddIfPresent(data, "message", Message);
        AddIfPresent(data, "permalink", Permalink);
        AddIfPresent(data, "detectionPermalink", DetectionPermalink);
        AddIfPresent(data, "officialApiSelfLink", OfficialApiSelfLink);
        AddIfPresent(data, "meaningfulName", MeaningfulName);
        AddIfPresent(data, "errorKind", ErrorKind);
        AddIfPresent(data, "quietErrorKind", QuietErrorKind);
        AddIfPresent(data, "quietErrorCategory", QuietErrorCategory);
        AddIfPresent(data, "cacheAgeSeconds", FormatNullableSeconds(CacheAgeSeconds));
        AddIfPresent(data, "quietFailureReason", QuietFailureReason);
        AddIfPresent(data, "quietFailureExplanation", QuietFailureExplanation);
        AddOfficialFileObjectData(data);
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

    private void AddOfficialFileObjectData(IDictionary<string, string> data)
    {
        AddIfPresent(data, "vtOfficialFileObjectId", OfficialFileObject.Id);
        AddIfPresent(data, "vtOfficialFileObjectType", OfficialFileObject.Type);
        AddIfPresent(data, "vtMd5", OfficialFileObject.Md5);
        AddIfPresent(data, "vtSha1", OfficialFileObject.Sha1);
        AddIfPresent(data, "vtOfficialSha256", OfficialFileObject.Sha256);
        AddIfPresent(data, "vtFileTypeDescription", OfficialFileObject.FileTypeDescription);
        AddIfPresent(data, "vtTypeTag", OfficialFileObject.TypeTag);
        AddIfPresent(data, "vtMagic", OfficialFileObject.Magic);
        AddIfPresent(data, "vtNames", JoinValues(OfficialFileObject.Names));
        AddIfPresent(data, "vtTags", JoinValues(OfficialFileObject.Tags));
        AddIfPresent(data, "vtNamesSummary", OfficialFileObject.NamesSummary);
        AddIfPresent(data, "vtTagsSummary", OfficialFileObject.TagsSummary);
        AddIfPresent(data, "vtTypeSummary", OfficialFileObject.TypeSummary);
        AddIfPresent(data, "vtOfficialFileObjectSummary", OfficialFileObject.OfficialSummary);
        AddIfPresent(data, "officialSummary", OfficialFileObject.OfficialSummary);
        AddIfPresent(data, "vtZhOfficialFileObjectSummary", OfficialFileObject.ZhOfficialSummary);
        AddIfPresent(data, "zhOfficialSummary", OfficialFileObject.ZhOfficialSummary);
        AddIfPresent(data, "vtOfficialSummaryFields", string.Join(",", OfficialFileObject.OfficialSummaryFields));
        AddIfPresent(data, "vtSuggestedThreatLabel", ThreatClassification.SuggestedThreatLabel);
        AddIfPresent(data, "vtTopThreatCategory", ThreatClassification.TopThreatCategory);
        AddIfPresent(data, "vtTopThreatName", ThreatClassification.TopThreatName);
        AddIfPresent(data, "vtPopularThreatCategorySummary", ThreatClassification.PopularThreatCategorySummary);
        AddIfPresent(data, "vtPopularThreatNameSummary", ThreatClassification.PopularThreatNameSummary);
        AddIfPresent(data, "vtThreatClassificationSummary", ThreatClassification.ThreatClassificationSummary);

        if (OfficialFileObject.SizeBytes is not null)
        {
            data["vtFileSizeBytes"] = OfficialFileObject.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
        }

        AddIfPresent(data, "vtFirstSubmissionDateUtc", FormatDate(OfficialFileObject.FirstSubmissionDateUtc));
        AddIfPresent(data, "vtLastSubmissionDateUtc", FormatDate(OfficialFileObject.LastSubmissionDateUtc));
        AddIfPresent(data, "vtLastModificationDateUtc", FormatDate(OfficialFileObject.LastModificationDateUtc));
        AddIfPresent(data, "vtFirstSeenInTheWildDateUtc", FormatDate(OfficialFileObject.FirstSeenInTheWildDateUtc));

        var categoryVotes = FormatThreatItems(ThreatClassification.PopularThreatCategories);
        var nameVotes = FormatThreatItems(ThreatClassification.PopularThreatNames);
        AddIfPresent(data, "vtPopularThreatCategories", categoryVotes);
        AddIfPresent(data, "vtPopularThreatNames", nameVotes);
    }

    private string BuildLastAnalysisCategorySummary()
    {
        var ordered = LastAnalysisStats
            .Where(static item => item.Value > 0)
            .OrderByDescending(static item => item.Value)
            .ThenBy(static item => item.Key, StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .Select(static item => $"{item.Key}:{item.Value.ToString(CultureInfo.InvariantCulture)}")
            .ToArray();

        return ordered.Length == 0 ? "none" : string.Join(", ", ordered);
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

    private static string? FormatDate(DateTimeOffset? value)
    {
        return value?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    }

    private static string? JoinValues(IReadOnlyList<string> values)
    {
        return values.Count == 0
            ? null
            : string.Join(", ", values
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Take(20));
    }

    private static string? FormatThreatItems(IReadOnlyList<VirusTotalThreatClassificationItem> values)
    {
        return values.Count == 0
            ? null
            : string.Join(", ", values
                .Where(static value => !string.IsNullOrWhiteSpace(value.Value))
                .Select(static value => $"{value.Value.Trim()}:{Math.Max(0, value.Count).ToString(CultureInfo.InvariantCulture)}")
                .Take(20));
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

    private static string BuildQuietFailureExplanation(string? status, string? quietErrorKind, string? errorKind, int? httpStatusCode, string? message)
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

        if (!string.IsNullOrWhiteSpace(quietErrorKind) &&
            !string.Equals(quietErrorKind, errorKind, StringComparison.OrdinalIgnoreCase))
        {
            explanation = $"{explanation} quietErrorKind={quietErrorKind.Trim()}.";
        }

        return baseMessage is null
            ? explanation
            : $"{explanation} Provider message: {baseMessage}";
    }

    private static string ResolveQuietErrorKind(string? status, string? errorKind, int? httpStatusCode)
    {
        if (httpStatusCode is 401 or 403 ||
            string.Equals(status, VirusTotalLookupStatuses.AuthenticationFailed, StringComparison.OrdinalIgnoreCase))
        {
            return "auth";
        }

        if (httpStatusCode is 429 ||
            string.Equals(status, VirusTotalLookupStatuses.RateLimited, StringComparison.OrdinalIgnoreCase))
        {
            return "rate_limit";
        }

        if (httpStatusCode is 404 ||
            string.Equals(status, VirusTotalLookupStatuses.NotFound, StringComparison.OrdinalIgnoreCase))
        {
            return "not_found";
        }

        if (string.Equals(status, VirusTotalLookupStatuses.NotConfigured, StringComparison.OrdinalIgnoreCase))
        {
            return "not_configured";
        }

        if (string.Equals(status, VirusTotalLookupStatuses.Timeout, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(errorKind, "timeout", StringComparison.OrdinalIgnoreCase))
        {
            return "timeout";
        }

        if (string.Equals(status, VirusTotalLookupStatuses.MissingHash, StringComparison.OrdinalIgnoreCase))
        {
            return "missing_hash";
        }

        if (string.Equals(status, VirusTotalLookupStatuses.InvalidHash, StringComparison.OrdinalIgnoreCase))
        {
            return "invalid_hash";
        }

        return string.IsNullOrWhiteSpace(errorKind)
            ? VirusTotalLookupStatuses.LookupFailed
            : errorKind.Trim();
    }

    private static string ResolveQuietErrorCategory(string? quietErrorKind)
    {
        return quietErrorKind switch
        {
            "not_configured" => "configuration",
            "auth" => "authentication",
            "rate_limit" => "provider_quota",
            "timeout" => "network_timeout",
            "not_found" => "provider_not_found",
            "missing_hash" or "invalid_hash" => "local_input",
            _ => "lookup_failure"
        };
    }

    private static string BuildZhStatusText(string? status, string? verdict, int malicious, int suspicious)
    {
        return status switch
        {
            VirusTotalLookupStatuses.Found when string.Equals(verdict, VirusTotalLookupStatuses.Malicious, StringComparison.OrdinalIgnoreCase) => "官方已收录：恶意",
            VirusTotalLookupStatuses.Found when string.Equals(verdict, VirusTotalLookupStatuses.Suspicious, StringComparison.OrdinalIgnoreCase) => "官方已收录：可疑",
            VirusTotalLookupStatuses.Found => "官方已收录",
            VirusTotalLookupStatuses.NotConfigured => "未配置 API Key",
            VirusTotalLookupStatuses.NotFound => "官方未收录",
            VirusTotalLookupStatuses.RateLimited => "官方限速",
            VirusTotalLookupStatuses.AuthenticationFailed => "鉴权失败",
            VirusTotalLookupStatuses.Timeout => "查询超时",
            VirusTotalLookupStatuses.MissingHash => "缺少 SHA-256",
            VirusTotalLookupStatuses.InvalidHash => "SHA-256 无效",
            VirusTotalLookupStatuses.LookupFailed => "查询失败",
            _ when malicious > 0 => "官方已收录：恶意",
            _ when suspicious > 0 => "官方已收录：可疑",
            _ => "状态未知"
        };
    }

    private static string BuildZhStatusDetail(string? status, string? verdict, int malicious, int suspicious, string? quietErrorKind)
    {
        return status switch
        {
            VirusTotalLookupStatuses.Found when malicious > 0 =>
                $"VirusTotal 官方文件报告已收录；{malicious.ToString(CultureInfo.InvariantCulture)} 个引擎判恶意，{suspicious.ToString(CultureInfo.InvariantCulture)} 个引擎判可疑。显式 persist 时可写入信誉增强。",
            VirusTotalLookupStatuses.Found when suspicious > 0 =>
                $"VirusTotal 官方文件报告已收录；0 个引擎判恶意，{suspicious.ToString(CultureInfo.InvariantCulture)} 个引擎判可疑。显式 persist 时可写入信誉增强。",
            VirusTotalLookupStatuses.Found =>
                $"VirusTotal 官方文件报告已收录；当前 verdict={verdict ?? VirusTotalLookupStatuses.Unknown}。显式 persist 时可写入信誉增强。",
            VirusTotalLookupStatuses.NotConfigured =>
                "未配置 VirusTotal API Key；未调用官方 API，仅在页面/API 中作为静默状态返回，不写任务/行为日志。",
            VirusTotalLookupStatuses.NotFound =>
                "VirusTotal 官方 API 已查询但未收录该 SHA-256；这是信誉状态，不代表样本行为，默认不写任务/行为日志。",
            VirusTotalLookupStatuses.RateLimited =>
                "VirusTotal 官方 API 返回限速；本次查询静默结束，可稍后重试，不写任务/行为日志。",
            VirusTotalLookupStatuses.AuthenticationFailed =>
                "VirusTotal 官方 API 拒绝当前 Key；请检查设置，沙箱分析继续，不写任务/行为日志。",
            VirusTotalLookupStatuses.Timeout =>
                "VirusTotal 查询超时；沙箱分析继续，该状态只通过 API/页面展示，不写任务/行为日志。",
            VirusTotalLookupStatuses.MissingHash =>
                "样本 SHA-256 不可用；未调用 VirusTotal 官方 API，不写任务/行为日志。",
            VirusTotalLookupStatuses.InvalidHash =>
                "样本 SHA-256 格式无效；未调用 VirusTotal 官方 API，不写任务/行为日志。",
            _ =>
                $"VirusTotal 查询处于静默失败状态（{quietErrorKind ?? VirusTotalLookupStatuses.LookupFailed}）；沙箱分析继续，不写任务/行为日志。"
        };
    }
}
