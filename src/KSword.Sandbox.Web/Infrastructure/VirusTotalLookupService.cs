using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Performs optional VirusTotal v3 hash lookups for already-submitted samples.
/// Inputs are local SHA-256 hashes and an optional local API key; processing
/// calls the official file-report endpoint only when configured; failures are
/// returned as quiet status values instead of being logged. This service does
/// not upload samples; it only asks VirusTotal for an existing file report.
/// </summary>
internal sealed class VirusTotalLookupService
{
    private static readonly Uri BaseUri = new("https://www.virustotal.com/api/v3/");

    private readonly HttpClient httpClient;
    private readonly VirusTotalSettingsStore settingsStore;
    private readonly VirusTotalLookupCache cache;

    public VirusTotalLookupService(
        HttpClient httpClient,
        VirusTotalSettingsStore settingsStore,
        VirusTotalLookupCache cache)
    {
        this.httpClient = httpClient;
        this.settingsStore = settingsStore;
        this.cache = cache;
    }

    /// <summary>
    /// Looks up one SHA-256 hash. Inputs are the sample hash and cancellation;
    /// processing skips if no key is configured, otherwise calls
    /// /api/v3/files/{hash}; return value is an operator-safe summary.
    /// </summary>
    public async Task<VirusTotalLookupResult> LookupFileHashAsync(string sha256, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sha256))
        {
            return NotQueried(
                string.Empty,
                configured: settingsStore.GetState().Configured,
                VirusTotalLookupStatuses.MissingHash,
                "Sample SHA-256 is not available.");
        }

        var normalizedHash = sha256.Trim().ToLowerInvariant();
        if (!IsSha256Hex(normalizedHash))
        {
            return NotQueried(
                normalizedHash,
                configured: settingsStore.GetState().Configured,
                VirusTotalLookupStatuses.InvalidHash,
                "VirusTotal lookup requires a SHA-256 hash.",
                "invalid_hash");
        }

        var apiKey = settingsStore.ResolveApiKey();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return NotQueried(
                normalizedHash,
                configured: false,
                VirusTotalLookupStatuses.NotConfigured,
                "VirusTotal API key is not configured.");
        }

        var credentialScope = VirusTotalLookupCache.CreateCredentialScope(apiKey);
        return await cache.GetOrAddAsync(
            normalizedHash,
            credentialScope,
            token => LookupFileHashCoreAsync(normalizedHash, apiKey, token),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<VirusTotalLookupResult> LookupFileHashCoreAsync(
        string normalizedHash,
        string apiKey,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(BaseUri, $"files/{Uri.EscapeDataString(normalizedHash)}"));
            request.Headers.Add("x-apikey", apiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return new VirusTotalLookupResult
                {
                    Sha256 = normalizedHash,
                    Configured = true,
                    Queried = true,
                    Found = false,
                    Status = VirusTotalLookupStatuses.NotFound,
                    Verdict = VirusTotalLookupStatuses.NotFound,
                    Message = "Hash was not found by VirusTotal.",
                    Permalink = BuildFilePermalink(normalizedHash),
                    DetectionPermalink = BuildDetectionPermalink(normalizedHash),
                    HttpStatusCode = (int)response.StatusCode
                };
            }

            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return QueriedFailure(
                    normalizedHash,
                    response.StatusCode,
                    VirusTotalLookupStatuses.RateLimited,
                    "VirusTotal lookup was rate-limited.",
                    "rate_limited",
                    ParseRetryAfterUtc(response));
            }

            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                return QueriedFailure(
                    normalizedHash,
                    response.StatusCode,
                    VirusTotalLookupStatuses.AuthenticationFailed,
                    "VirusTotal API key was rejected by the service.",
                    "authentication_failed");
            }

            if (!response.IsSuccessStatusCode)
            {
                return QueriedFailure(
                    normalizedHash,
                    response.StatusCode,
                    VirusTotalLookupStatuses.LookupFailed,
                    "VirusTotal lookup failed.",
                    "http_error");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return ParseFileReport(normalizedHash, document.RootElement);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            var timedOut = ex is TaskCanceledException;
            return NotQueried(
                normalizedHash,
                configured: true,
                timedOut ? VirusTotalLookupStatuses.Timeout : VirusTotalLookupStatuses.LookupFailed,
                timedOut
                    ? "VirusTotal lookup failed or timed out."
                    : "VirusTotal lookup failed.",
                timedOut ? "timeout" : "transport_or_parse_error");
        }
    }

    private static VirusTotalLookupResult ParseFileReport(string sha256, JsonElement root)
    {
        var attributes = root.TryGetProperty("data", out var data) && data.TryGetProperty("attributes", out var attr)
            ? attr
            : default;
        var officialApiSelfLink = data.ValueKind == JsonValueKind.Object &&
            data.TryGetProperty("links", out var links)
                ? ReadString(links, "self")
                : null;
        var stats = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (attributes.ValueKind == JsonValueKind.Object &&
            attributes.TryGetProperty("last_analysis_stats", out var statsElement) &&
            statsElement.ValueKind == JsonValueKind.Object)
        {
            foreach (var item in statsElement.EnumerateObject())
            {
                if (item.Value.TryGetInt32(out var value))
                {
                    stats[item.Name] = value;
                }
            }
        }

        var name = ReadString(attributes, "meaningful_name") ??
            ReadFirstString(attributes, "names") ??
            ReadString(attributes, "suggested_threat_label");
        DateTimeOffset? lastAnalysis = null;
        if (attributes.ValueKind == JsonValueKind.Object &&
            attributes.TryGetProperty("last_analysis_date", out var dateElement) &&
            dateElement.TryGetInt64(out var unixSeconds))
        {
            lastAnalysis = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }

        var reputation = ReadNullableInt(attributes, "reputation");
        var communityVotes = ReadCommunityVotes(attributes);
        var malicious = ReadStat(stats, "malicious");
        var suspicious = ReadStat(stats, "suspicious");
        var harmless = ReadStat(stats, "harmless");
        var undetected = ReadStat(stats, "undetected");
        var timeout = ReadStat(stats, "timeout");
        var confirmedTimeout = ReadStat(stats, "confirmed-timeout");
        var failure = ReadStat(stats, "failure");
        var typeUnsupported = ReadStat(stats, "type-unsupported");
        var engineCounts = new VirusTotalEngineCounts
        {
            Malicious = malicious,
            Suspicious = suspicious,
            Harmless = harmless,
            Undetected = undetected,
            Timeout = timeout,
            ConfirmedTimeout = confirmedTimeout,
            Failure = failure,
            TypeUnsupported = typeUnsupported,
            Total = stats.Values.Where(value => value > 0).Sum()
        };
        var verdict = ResolveVerdict(malicious, suspicious, harmless, undetected);

        return new VirusTotalLookupResult
        {
            Sha256 = sha256,
            Configured = true,
            Queried = true,
            Found = true,
            Status = VirusTotalLookupStatuses.Found,
            Verdict = verdict,
            Message = BuildFoundMessage(verdict, malicious, suspicious),
            Permalink = BuildFilePermalink(sha256),
            DetectionPermalink = BuildDetectionPermalink(sha256),
            OfficialApiSelfLink = officialApiSelfLink,
            MeaningfulName = name,
            LastAnalysisDateUtc = lastAnalysis,
            Reputation = reputation,
            CommunityVotes = communityVotes,
            MaliciousCount = malicious,
            SuspiciousCount = suspicious,
            HarmlessCount = harmless,
            UndetectedCount = undetected,
            TimeoutCount = timeout,
            EngineCounts = engineCounts,
            LastAnalysisStats = stats
        };
    }

    private static VirusTotalLookupResult NotQueried(string sha256, bool configured, string status, string message, string? errorKind = null)
    {
        var hasValidHash = IsSha256Hex(sha256);
        return new VirusTotalLookupResult
        {
            Sha256 = sha256,
            Configured = configured,
            Queried = false,
            Found = false,
            Status = status,
            Verdict = status,
            Message = message,
            Permalink = hasValidHash ? BuildFilePermalink(sha256) : null,
            DetectionPermalink = hasValidHash ? BuildDetectionPermalink(sha256) : null,
            ErrorKind = errorKind
        };
    }

    private static VirusTotalLookupResult QueriedFailure(
        string sha256,
        HttpStatusCode httpStatusCode,
        string status,
        string message,
        string errorKind,
        DateTimeOffset? retryAfterUtc = null)
    {
        return new VirusTotalLookupResult
        {
            Sha256 = sha256,
            Configured = true,
            Queried = true,
            Found = false,
            Status = status,
            Verdict = status,
            Message = message,
            Permalink = BuildFilePermalink(sha256),
            DetectionPermalink = BuildDetectionPermalink(sha256),
            HttpStatusCode = (int)httpStatusCode,
            ErrorKind = errorKind,
            RetryAfterUtc = retryAfterUtc
        };
    }

    private static int ReadStat(IReadOnlyDictionary<string, int> stats, string key)
    {
        return stats.TryGetValue(key, out var value) ? value : 0;
    }

    private static bool IsSha256Hex(string value)
    {
        return value.Length == 64 && value.All(static ch =>
            (ch >= '0' && ch <= '9') ||
            (ch >= 'a' && ch <= 'f'));
    }

    private static string ResolveVerdict(int malicious, int suspicious, int harmless, int undetected)
    {
        if (malicious > 0)
        {
            return VirusTotalLookupStatuses.Malicious;
        }

        if (suspicious > 0)
        {
            return VirusTotalLookupStatuses.Suspicious;
        }

        return harmless > 0 || undetected > 0
            ? VirusTotalLookupStatuses.Clean
            : VirusTotalLookupStatuses.Unknown;
    }

    private static string BuildFoundMessage(string verdict, int malicious, int suspicious)
    {
        return verdict switch
        {
            VirusTotalLookupStatuses.Malicious => $"VirusTotal hash report found: {malicious} malicious engine hits.",
            VirusTotalLookupStatuses.Suspicious => $"VirusTotal hash report found: {suspicious} suspicious engine hits.",
            VirusTotalLookupStatuses.Clean => "VirusTotal hash report found with no malicious or suspicious engine hits.",
            _ => "VirusTotal hash report found, but no decisive analysis verdict was available."
        };
    }

    private static DateTimeOffset? ParseRetryAfterUtc(HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter;
        if (retryAfter is null)
        {
            return null;
        }

        if (retryAfter.Date is not null)
        {
            return retryAfter.Date.Value.ToUniversalTime();
        }

        if (retryAfter.Delta is not null)
        {
            return DateTimeOffset.UtcNow.Add(retryAfter.Delta.Value);
        }

        return null;
    }

    private static string BuildFilePermalink(string sha256) => $"https://www.virustotal.com/gui/file/{sha256}";

    private static string BuildDetectionPermalink(string sha256) => $"{BuildFilePermalink(sha256)}/detection";

    private static string? ReadString(JsonElement element, string propertyName)
    {
        return element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(propertyName, out var value) &&
            value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
    }

    private static string? ReadFirstString(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                return item.GetString();
            }
        }

        return null;
    }

    private static int? ReadNullableInt(JsonElement element, string propertyName)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(propertyName, out var value))
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
        {
            return number;
        }

        if (value.ValueKind == JsonValueKind.String &&
            int.TryParse(value.GetString(), out var stringNumber))
        {
            return stringNumber;
        }

        return null;
    }

    private static VirusTotalCommunityVotes ReadCommunityVotes(JsonElement attributes)
    {
        if (attributes.ValueKind != JsonValueKind.Object ||
            !attributes.TryGetProperty("total_votes", out var votes) ||
            votes.ValueKind != JsonValueKind.Object)
        {
            return new VirusTotalCommunityVotes();
        }

        return new VirusTotalCommunityVotes
        {
            Harmless = ReadNullableInt(votes, "harmless"),
            Malicious = ReadNullableInt(votes, "malicious")
        };
    }
}
