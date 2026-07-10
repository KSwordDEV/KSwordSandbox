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

    public VirusTotalLookupService(HttpClient httpClient, VirusTotalSettingsStore settingsStore)
    {
        this.httpClient = httpClient;
        this.settingsStore = settingsStore;
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
            return NotQueried(string.Empty, configured: settingsStore.GetState().Configured, "missing_hash", "Sample SHA-256 is not available.");
        }

        var normalizedHash = sha256.Trim().ToLowerInvariant();
        var apiKey = settingsStore.ResolveApiKey();
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return NotQueried(normalizedHash, configured: false, "not_configured", "VirusTotal API key is not configured.");
        }

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
                    Status = "not_found",
                    Message = "Hash was not found by VirusTotal.",
                    Permalink = BuildFilePermalink(normalizedHash)
                };
            }

            if (!response.IsSuccessStatusCode)
            {
                return NotQueried(normalizedHash, configured: true, "lookup_failed", "VirusTotal lookup failed or was rate-limited.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return ParseFileReport(normalizedHash, document.RootElement);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            return NotQueried(normalizedHash, configured: true, "lookup_failed", "VirusTotal lookup failed or timed out.");
        }
    }

    private static VirusTotalLookupResult ParseFileReport(string sha256, JsonElement root)
    {
        var attributes = root.TryGetProperty("data", out var data) && data.TryGetProperty("attributes", out var attr)
            ? attr
            : default;
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

        return new VirusTotalLookupResult
        {
            Sha256 = sha256,
            Configured = true,
            Queried = true,
            Found = true,
            Status = "found",
            Message = "VirusTotal hash report found.",
            Permalink = BuildFilePermalink(sha256),
            MeaningfulName = name,
            LastAnalysisDateUtc = lastAnalysis,
            LastAnalysisStats = stats
        };
    }

    private static VirusTotalLookupResult NotQueried(string sha256, bool configured, string status, string message)
    {
        return new VirusTotalLookupResult
        {
            Sha256 = sha256,
            Configured = configured,
            Queried = false,
            Found = false,
            Status = status,
            Message = message,
            Permalink = string.IsNullOrWhiteSpace(sha256) ? null : BuildFilePermalink(sha256)
        };
    }

    private static string BuildFilePermalink(string sha256) => $"https://www.virustotal.com/gui/file/{sha256}";

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
}
