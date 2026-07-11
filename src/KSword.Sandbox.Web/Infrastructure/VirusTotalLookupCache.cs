using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Small in-memory cache for optional VirusTotal hash lookups. Inputs are
/// normalized SHA-256 hashes plus a non-secret credential scope; processing
/// deduplicates concurrent requests and keeps quiet terminal/transient states
/// for bounded TTLs; returned results include cache-age metadata for the live
/// monitor.
/// </summary>
internal sealed class VirusTotalLookupCache
{
    private static readonly TimeSpan FoundTtl = TimeSpan.FromHours(24);
    private static readonly TimeSpan NotFoundTtl = TimeSpan.FromHours(6);
    private static readonly TimeSpan RateLimitedTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan AuthenticationFailureTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan TimeoutTtl = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan LookupFailureTtl = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MinimumRetryAfterTtl = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaximumRetryAfterTtl = TimeSpan.FromMinutes(30);
    private const int MaximumEntries = 2048;

    private readonly ConcurrentDictionary<string, VirusTotalLookupCacheEntry> entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Lazy<Task<VirusTotalLookupCacheEntry>>> inFlight = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Returns a cached result or runs one lookup factory for the hash/scope.
    /// Inputs are a SHA-256 hash, a non-secret credential scope, a lookup
    /// delegate, and cancellation; processing reuses fresh cache entries and
    /// collapses concurrent lookups; the result carries cacheHit/cacheAge.
    /// </summary>
    public async Task<VirusTotalLookupResult> GetOrAddAsync(
        string sha256,
        string credentialScope,
        Func<CancellationToken, Task<VirusTotalLookupResult>> lookup,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lookup);

        if (string.IsNullOrWhiteSpace(sha256))
        {
            return await lookup(cancellationToken).ConfigureAwait(false);
        }

        var now = DateTimeOffset.UtcNow;
        var key = BuildEntryKey(sha256, credentialScope);
        if (TryReadFreshEntry(key, now, out var cached))
        {
            return cached.ToResult(cacheHit: true, now);
        }

        var lazy = inFlight.GetOrAdd(
            key,
            _ => new Lazy<Task<VirusTotalLookupCacheEntry>>(
                () => CreateEntryAsync(key, lookup, cancellationToken),
                LazyThreadSafetyMode.ExecutionAndPublication));

        try
        {
            var entry = await lazy.Value.ConfigureAwait(false);
            return entry.ToResult(cacheHit: false, DateTimeOffset.UtcNow);
        }
        finally
        {
            inFlight.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Clears cached VT lookups after a local API-key save/clear operation.
    /// Inputs are none; processing removes stored and in-flight cache handles;
    /// future lookups will query with the new settings.
    /// </summary>
    public void Clear()
    {
        entries.Clear();
        inFlight.Clear();
    }

    /// <summary>
    /// Builds a short non-secret scope so invalid-key/rate-limit entries do not
    /// poison another key while the raw API key never leaves the settings store
    /// and lookup service.
    /// </summary>
    public static string CreateCredentialScope(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return "none";
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey.Trim()));
        return Convert.ToHexString(hash.AsSpan(0, 8));
    }

    private async Task<VirusTotalLookupCacheEntry> CreateEntryAsync(
        string key,
        Func<CancellationToken, Task<VirusTotalLookupResult>> lookup,
        CancellationToken cancellationToken)
    {
        var cachedAtUtc = DateTimeOffset.UtcNow;
        var result = await lookup(cancellationToken).ConfigureAwait(false);
        var ttl = ResolveTtl(result, cachedAtUtc);
        if (ttl is null || ttl.Value <= TimeSpan.Zero)
        {
            return VirusTotalLookupCacheEntry.Uncached(result);
        }

        var expiresAtUtc = cachedAtUtc.Add(ttl.Value);
        var entry = new VirusTotalLookupCacheEntry(
            result.WithCacheMetadata(
                cacheHit: false,
                cachedAtUtc,
                expiresAtUtc,
                ttl.Value,
                cachedAtUtc),
            cachedAtUtc,
            expiresAtUtc,
            ttl.Value,
            Cacheable: true);
        entries[key] = entry;
        TrimIfNeeded(cachedAtUtc);
        return entry;
    }

    private bool TryReadFreshEntry(string key, DateTimeOffset now, out VirusTotalLookupCacheEntry entry)
    {
        if (entries.TryGetValue(key, out var cached))
        {
            if (cached.ExpiresAtUtc > now)
            {
                entry = cached;
                return true;
            }

            entries.TryRemove(key, out _);
        }

        entry = VirusTotalLookupCacheEntry.Uncached(new VirusTotalLookupResult
        {
            Sha256 = string.Empty,
            Status = VirusTotalLookupStatuses.LookupFailed
        });
        return false;
    }

    private void TrimIfNeeded(DateTimeOffset now)
    {
        if (entries.Count <= MaximumEntries)
        {
            return;
        }

        foreach (var pair in entries)
        {
            if (pair.Value.ExpiresAtUtc <= now)
            {
                entries.TryRemove(pair.Key, out _);
            }
        }

        if (entries.Count <= MaximumEntries)
        {
            return;
        }

        foreach (var pair in entries
            .OrderBy(pair => pair.Value.CachedAtUtc)
            .Take(Math.Max(0, entries.Count - MaximumEntries)))
        {
            entries.TryRemove(pair.Key, out _);
        }
    }

    private static TimeSpan? ResolveTtl(VirusTotalLookupResult result, DateTimeOffset now)
    {
        var isLookupFailure = string.Equals(result.Status, VirusTotalLookupStatuses.LookupFailed, StringComparison.OrdinalIgnoreCase);
        var isTimeout = string.Equals(result.Status, VirusTotalLookupStatuses.Timeout, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(result.ErrorKind, "timeout", StringComparison.OrdinalIgnoreCase);
        if (!result.Queried && !isLookupFailure && !isTimeout)
        {
            return null;
        }

        if (string.Equals(result.Status, VirusTotalLookupStatuses.Found, StringComparison.OrdinalIgnoreCase))
        {
            return FoundTtl;
        }

        if (string.Equals(result.Status, VirusTotalLookupStatuses.NotFound, StringComparison.OrdinalIgnoreCase))
        {
            return NotFoundTtl;
        }

        if (string.Equals(result.Status, VirusTotalLookupStatuses.RateLimited, StringComparison.OrdinalIgnoreCase))
        {
            if (result.RetryAfterUtc is not null && result.RetryAfterUtc.Value > now)
            {
                return Clamp(result.RetryAfterUtc.Value - now, MinimumRetryAfterTtl, MaximumRetryAfterTtl);
            }

            return RateLimitedTtl;
        }

        if (string.Equals(result.Status, VirusTotalLookupStatuses.AuthenticationFailed, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticationFailureTtl;
        }

        if (isTimeout && result.Configured)
        {
            return TimeoutTtl;
        }

        if (isLookupFailure && result.Configured)
        {
            return LookupFailureTtl;
        }

        return null;
    }

    private static TimeSpan Clamp(TimeSpan value, TimeSpan minimum, TimeSpan maximum)
    {
        if (value < minimum)
        {
            return minimum;
        }

        return value > maximum ? maximum : value;
    }

    private static string BuildEntryKey(string sha256, string credentialScope)
    {
        var scope = string.IsNullOrWhiteSpace(credentialScope) ? "none" : credentialScope.Trim();
        return $"{sha256.Trim().ToLowerInvariant()}|{scope}";
    }

    private sealed record VirusTotalLookupCacheEntry(
        VirusTotalLookupResult Result,
        DateTimeOffset CachedAtUtc,
        DateTimeOffset ExpiresAtUtc,
        TimeSpan Ttl,
        bool Cacheable)
    {
        public static VirusTotalLookupCacheEntry Uncached(VirusTotalLookupResult result)
        {
            return new VirusTotalLookupCacheEntry(
                result.WithCacheMetadata(
                    cacheHit: false,
                    cachedAtUtc: null,
                    cacheExpiresAtUtc: null,
                    cacheTtl: null),
                DateTimeOffset.MinValue,
                DateTimeOffset.MinValue,
                TimeSpan.Zero,
                Cacheable: false);
        }

        public VirusTotalLookupResult ToResult(bool cacheHit, DateTimeOffset now)
        {
            return Cacheable
                ? Result.WithCacheMetadata(cacheHit, CachedAtUtc, ExpiresAtUtc, Ttl, now)
                : Result.WithCacheMetadata(cacheHit: false, cachedAtUtc: null, cacheExpiresAtUtc: null, cacheTtl: null, now);
        }
    }
}
