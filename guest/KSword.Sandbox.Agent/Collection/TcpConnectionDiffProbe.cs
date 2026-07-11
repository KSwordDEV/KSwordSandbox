using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using KSword.Sandbox.Agent.Diagnostics;
using KSword.Sandbox.Abstractions;
using Microsoft.Win32;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures TCP connection baselines plus guest DNS/cache/hosts/proxy/netstat state.
/// Inputs are BeforeStart and AfterRun probe phases; processing queries
/// low-privilege network APIs and bounded helper commands; CollectAsync returns
/// TCP deltas, DNS cache deltas, hosts/proxy snapshots, listener deltas, and
/// netstat diagnostics.
/// </summary>
internal sealed class TcpConnectionDiffProbe : IGuestProbe
{
    private const int MaxDeltaEventsPerKind = 256;
    private const int MaxNetstatRows = 256;
    private readonly ITcpConnectionSnapshotProvider snapshotProvider;
    private readonly INetworkStateSnapshotProvider networkStateSnapshotProvider;
    private Dictionary<string, TcpConnectionSnapshot> baseline = new(StringComparer.OrdinalIgnoreCase);
    private NetworkStateSnapshot baselineNetworkState = NetworkStateSnapshot.Empty;

    public TcpConnectionDiffProbe()
        : this(new TcpConnectionSnapshotProvider(), new NetworkStateSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a TCP diff probe with an injectable TCP snapshot provider.
    /// The input is a TCP provider, processing pairs it with default DNS/netstat
    /// providers, and the constructor returns no value.
    /// </summary>
    public TcpConnectionDiffProbe(ITcpConnectionSnapshotProvider snapshotProvider)
        : this(snapshotProvider, new NetworkStateSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a network diff probe with injectable providers.
    /// Inputs are TCP and network-state providers; processing stores them for
    /// future probe phases; the constructor returns no value.
    /// </summary>
    public TcpConnectionDiffProbe(
        ITcpConnectionSnapshotProvider snapshotProvider,
        INetworkStateSnapshotProvider networkStateSnapshotProvider)
    {
        this.snapshotProvider = snapshotProvider;
        this.networkStateSnapshotProvider = networkStateSnapshotProvider;
    }

    public string ProbeId => "tcp-diff";

    /// <summary>
    /// Collects network delta events for one probe phase.
    /// Inputs are phase, guest context, and cancellation token; processing
    /// captures the baseline before launch and compares it after execution; the
    /// method returns normalized network, DNS cache, and netstat events.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (phase == ProbePhase.BeforeStart)
        {
            baseline = snapshotProvider.Capture();
            baselineNetworkState = await networkStateSnapshotProvider.CaptureAsync(cancellationToken).ConfigureAwait(false);

            var baselineEvents = new List<SandboxEvent>
            {
                CreateDnsSnapshotEvent(phase, baselineNetworkState.DnsCacheEntries),
                CreateHostsSnapshotEvent(phase, baselineNetworkState.HostsFile),
                CreateProxySnapshotEvent(phase, baselineNetworkState.ProxySettings),
                CreateNetstatSnapshotEvent(phase, baselineNetworkState.NetstatRows, emittedRows: 0, truncated: false),
                CreateListenerSnapshotEvent(phase, "tcp", baselineNetworkState.TcpListeners.Count),
                CreateListenerSnapshotEvent(phase, "udp", baselineNetworkState.UdpListeners.Count)
            };
            baselineEvents.AddRange(WithPhase(baselineNetworkState.Diagnostics, phase));
            return baselineEvents;
        }

        if (phase != ProbePhase.AfterRun)
        {
            return [];
        }

        var current = snapshotProvider.Capture();
        var currentNetworkState = await networkStateSnapshotProvider.CaptureAsync(cancellationToken).ConfigureAwait(false);
        var events = new List<SandboxEvent>();

        foreach (var (key, connection) in current.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!baseline.ContainsKey(key))
            {
                events.Add(CreateTcpEvent("network.tcp", "opened", connection));
            }
        }

        foreach (var (key, connection) in baseline.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!current.ContainsKey(key))
            {
                events.Add(CreateTcpEvent("network.tcp.closed", "closed", connection));
            }
        }

        events.Add(CreateDnsSnapshotEvent(phase, currentNetworkState.DnsCacheEntries));
        events.Add(CreateDnsDiffSummaryEvent(baselineNetworkState.DnsCacheEntries, currentNetworkState.DnsCacheEntries, phase));
        events.AddRange(CreateDnsCacheDeltaEvents(baselineNetworkState.DnsCacheEntries, currentNetworkState.DnsCacheEntries, phase));
        events.Add(CreateHostsSnapshotEvent(phase, currentNetworkState.HostsFile));
        events.Add(CreateHostsDiffSummaryEvent(baselineNetworkState.HostsFile, currentNetworkState.HostsFile, phase));
        events.AddRange(CreateHostsDeltaEvents(baselineNetworkState.HostsFile, currentNetworkState.HostsFile, phase));
        events.Add(CreateProxySnapshotEvent(phase, currentNetworkState.ProxySettings));
        events.Add(CreateProxyDiffSummaryEvent(baselineNetworkState.ProxySettings, currentNetworkState.ProxySettings, phase));
        events.AddRange(CreateProxyDeltaEvents(baselineNetworkState.ProxySettings, currentNetworkState.ProxySettings, phase));
        events.Add(CreateNetstatSnapshotEvent(
            phase,
            currentNetworkState.NetstatRows,
            Math.Min(currentNetworkState.NetstatRows.Count, MaxNetstatRows),
            currentNetworkState.NetstatRows.Count > MaxNetstatRows));
        events.AddRange(CreateNetstatRowEvents(currentNetworkState.NetstatRows, phase));
        events.Add(CreateNetstatDiffSummaryEvent(baselineNetworkState.NetstatRows, currentNetworkState.NetstatRows, phase));
        events.AddRange(CreateNetstatDeltaEvents(baselineNetworkState.NetstatRows, currentNetworkState.NetstatRows, phase));
        events.Add(CreateListenerSnapshotEvent(phase, "tcp", currentNetworkState.TcpListeners.Count));
        events.Add(CreateListenerSnapshotEvent(phase, "udp", currentNetworkState.UdpListeners.Count));
        events.AddRange(CreateListenerDeltaEvents("network.tcp.listener", baselineNetworkState.TcpListeners, currentNetworkState.TcpListeners, phase));
        events.AddRange(CreateListenerDeltaEvents("network.udp.listener", baselineNetworkState.UdpListeners, currentNetworkState.UdpListeners, phase));
        events.AddRange(WithPhase(currentNetworkState.Diagnostics, phase));

        return events;
    }

    /// <summary>
    /// Creates one normalized TCP event.
    /// Inputs are event type, change label, and connection snapshot; processing
    /// copies endpoint strings plus structured address/port fields; the method
    /// returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateTcpEvent(string eventType, string change, TcpConnectionSnapshot connection)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["change"] = change,
                ["connection"] = connection.Key,
                ["local"] = connection.Local,
                ["remote"] = connection.Remote,
                ["state"] = connection.State,
                ["localAddress"] = connection.LocalEndPoint.Address.ToString(),
                ["localPort"] = connection.LocalEndPoint.Port.ToString(CultureInfo.InvariantCulture),
                ["remoteAddress"] = connection.RemoteEndPoint.Address.ToString(),
                ["remotePort"] = connection.RemoteEndPoint.Port.ToString(CultureInfo.InvariantCulture)
            }
        };
    }

    /// <summary>
    /// Creates a DNS cache snapshot summary event.
    /// Inputs are probe phase and entry count; processing stores source-tool and
    /// count metadata; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateDnsSnapshotEvent(
        ProbePhase phase,
        IReadOnlyDictionary<string, DnsCacheEntrySnapshot> entries)
    {
        return new SandboxEvent
        {
            EventType = "dns.cache.snapshot",
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["entryCount"] = entries.Count.ToString(CultureInfo.InvariantCulture),
                ["snapshotHash"] = SnapshotHash(entries.Keys),
                ["stableKey"] = "name|recordType|data|rawSummary",
                ["sourceTool"] = "ipconfig /displaydns"
            }
        };
    }

    /// <summary>
    /// Creates a hosts-file snapshot summary event.
    /// Inputs are probe phase and hosts snapshot; processing stores stable
    /// counts and hashes without dumping the full file; the method returns an
    /// event suitable for events.json diffing.
    /// </summary>
    private static SandboxEvent CreateHostsSnapshotEvent(ProbePhase phase, HostsFileSnapshot hostsFile)
    {
        return new SandboxEvent
        {
            EventType = "network.hosts.snapshot",
            Source = "guest",
            Path = hostsFile.Path,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["sourcePath"] = hostsFile.Path,
                ["exists"] = hostsFile.Exists.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["lineCount"] = hostsFile.LineCount.ToString(CultureInfo.InvariantCulture),
                ["entryCount"] = hostsFile.Entries.Count.ToString(CultureInfo.InvariantCulture),
                ["snapshotHash"] = SnapshotHash(hostsFile.Entries.Keys),
                ["stableKey"] = "address|hostName",
                ["sourceTool"] = "hosts-file"
            }
        };
    }

    /// <summary>
    /// Creates a hosts-file diff summary between before and after snapshots.
    /// Inputs are baseline/current hosts snapshots and phase; processing stores
    /// counts and hashes; the method returns one summary event.
    /// </summary>
    private static SandboxEvent CreateHostsDiffSummaryEvent(HostsFileSnapshot before, HostsFileSnapshot after, ProbePhase phase)
    {
        return new SandboxEvent
        {
            EventType = "network.hosts.diff",
            Source = "guest",
            Path = after.Path,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["sourcePath"] = after.Path,
                ["beforeExists"] = before.Exists.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["afterExists"] = after.Exists.ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["beforeEntryCount"] = before.Entries.Count.ToString(CultureInfo.InvariantCulture),
                ["afterEntryCount"] = after.Entries.Count.ToString(CultureInfo.InvariantCulture),
                ["addedCount"] = CountMissing(before.Entries, after.Entries).ToString(CultureInfo.InvariantCulture),
                ["removedCount"] = CountMissing(after.Entries, before.Entries).ToString(CultureInfo.InvariantCulture),
                ["beforeSnapshotHash"] = SnapshotHash(before.Entries.Keys),
                ["afterSnapshotHash"] = SnapshotHash(after.Entries.Keys),
                ["contentHashChanged"] = (!string.Equals(before.ContentSha256, after.ContentSha256, StringComparison.OrdinalIgnoreCase)).ToString(CultureInfo.InvariantCulture).ToLowerInvariant(),
                ["stableKey"] = "address|hostName",
                ["sourceTool"] = "hosts-file"
            }
        };
    }

    /// <summary>
    /// Creates bounded hosts-file added/removed events.
    /// Inputs are before/after hosts snapshots and phase; processing compares
    /// stable address/host keys; the method returns row-level events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateHostsDeltaEvents(HostsFileSnapshot before, HostsFileSnapshot after, ProbePhase phase)
    {
        var events = new List<SandboxEvent>();
        AddBoundedDiffEvents(events, before.Entries, after.Entries, "network.hosts.added", "added", phase, CreateHostsEntryEvent);
        AddBoundedDiffEvents(events, after.Entries, before.Entries, "network.hosts.removed", "removed", phase, CreateHostsEntryEvent);
        return events;
    }

    /// <summary>
    /// Creates one hosts-file entry event.
    /// Inputs are event type, change label, entry, and phase; processing copies
    /// host/address fields and stable hashes; the method returns an event.
    /// </summary>
    private static SandboxEvent CreateHostsEntryEvent(string eventType, string change, HostsEntrySnapshot entry, ProbePhase phase)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = entry.SourcePath,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["sourcePath"] = entry.SourcePath,
                ["entryHash"] = entry.Key,
                ["address"] = entry.Address,
                ["hostName"] = entry.HostName,
                ["entry"] = entry.Entry,
                ["sourceTool"] = "hosts-file"
            }
        };
    }

    /// <summary>
    /// Creates a proxy settings snapshot summary event.
    /// Inputs are probe phase and proxy snapshot; processing stores stable
    /// counts, common setting values, and a hash across registry/environment/
    /// WinHTTP proxy sources; the method returns one event.
    /// </summary>
    private static SandboxEvent CreateProxySnapshotEvent(ProbePhase phase, ProxySettingsSnapshot proxySettings)
    {
        var evt = new SandboxEvent
        {
            EventType = "network.proxy.snapshot",
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["settingCount"] = proxySettings.Settings.Count.ToString(CultureInfo.InvariantCulture),
                ["registrySettingCount"] = proxySettings.Settings.Values.Count(static setting => string.Equals(setting.Source, "registry", StringComparison.OrdinalIgnoreCase)).ToString(CultureInfo.InvariantCulture),
                ["environmentSettingCount"] = proxySettings.Settings.Values.Count(static setting => string.Equals(setting.Source, "environment", StringComparison.OrdinalIgnoreCase)).ToString(CultureInfo.InvariantCulture),
                ["winHttpSettingCount"] = proxySettings.Settings.Values.Count(static setting => string.Equals(setting.Source, "winhttp", StringComparison.OrdinalIgnoreCase)).ToString(CultureInfo.InvariantCulture),
                ["snapshotHash"] = ProxySnapshotHash(proxySettings),
                ["stableKey"] = "source|scope|settingName",
                ["sourceTool"] = "HKCU Internet Settings; environment; netsh winhttp show proxy"
            }
        };

        AddIfNotEmpty(evt.Data, "internetSettingsProxyEnable", FindProxySettingValue(proxySettings, "registry", "ProxyEnable"));
        AddIfNotEmpty(evt.Data, "internetSettingsProxyServer", FindProxySettingValue(proxySettings, "registry", "ProxyServer"));
        AddIfNotEmpty(evt.Data, "internetSettingsProxyOverride", FindProxySettingValue(proxySettings, "registry", "ProxyOverride"));
        AddIfNotEmpty(evt.Data, "internetSettingsAutoConfigUrl", FindProxySettingValue(proxySettings, "registry", "AutoConfigURL"));
        AddIfNotEmpty(evt.Data, "internetSettingsAutoDetect", FindProxySettingValue(proxySettings, "registry", "AutoDetect"));
        AddIfNotEmpty(evt.Data, "winHttpProxySummary", FindProxySettingValue(proxySettings, "winhttp", "WinHttpProxy"));
        AddIfNotEmpty(evt.Data, "httpProxyEnvironment", FindProxySettingValue(proxySettings, "environment", "HTTP_PROXY"));
        AddIfNotEmpty(evt.Data, "httpsProxyEnvironment", FindProxySettingValue(proxySettings, "environment", "HTTPS_PROXY"));
        AddIfNotEmpty(evt.Data, "noProxyEnvironment", FindProxySettingValue(proxySettings, "environment", "NO_PROXY"));
        return evt;
    }

    /// <summary>
    /// Creates a proxy-settings diff summary.
    /// Inputs are before/after proxy snapshots and phase; processing compares
    /// source/scope/name keys and value signatures; the method returns one
    /// compact diff summary event.
    /// </summary>
    private static SandboxEvent CreateProxyDiffSummaryEvent(ProxySettingsSnapshot before, ProxySettingsSnapshot after, ProbePhase phase)
    {
        return new SandboxEvent
        {
            EventType = "network.proxy.diff",
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["beforeSettingCount"] = before.Settings.Count.ToString(CultureInfo.InvariantCulture),
                ["afterSettingCount"] = after.Settings.Count.ToString(CultureInfo.InvariantCulture),
                ["addedCount"] = CountMissing(before.Settings, after.Settings).ToString(CultureInfo.InvariantCulture),
                ["removedCount"] = CountMissing(after.Settings, before.Settings).ToString(CultureInfo.InvariantCulture),
                ["modifiedCount"] = CountModified(before.Settings, after.Settings).ToString(CultureInfo.InvariantCulture),
                ["beforeSnapshotHash"] = ProxySnapshotHash(before),
                ["afterSnapshotHash"] = ProxySnapshotHash(after),
                ["stableKey"] = "source|scope|settingName",
                ["sourceTool"] = "HKCU Internet Settings; environment; netsh winhttp show proxy"
            }
        };
    }

    /// <summary>
    /// Creates bounded proxy added/removed/modified events.
    /// Inputs are before/after proxy snapshots and phase; processing compares
    /// values by signature and caps row-level volume; the method returns events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateProxyDeltaEvents(ProxySettingsSnapshot before, ProxySettingsSnapshot after, ProbePhase phase)
    {
        var events = new List<SandboxEvent>();
        AddBoundedDiffEvents(events, before.Settings, after.Settings, "network.proxy.added", "added", phase, CreateProxySettingEvent);
        AddBoundedDiffEvents(events, after.Settings, before.Settings, "network.proxy.removed", "removed", phase, CreateProxySettingEvent);

        var emitted = 0;
        foreach (var (key, current) in after.Settings.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!before.Settings.TryGetValue(key, out var previous) ||
                string.Equals(previous.Signature, current.Signature, StringComparison.Ordinal))
            {
                continue;
            }

            if (emitted >= MaxDeltaEventsPerKind)
            {
                events.Add(CreateTruncatedEvent("network.proxy.modified.truncated", "modified", phase, after.Settings.Count, emitted));
                break;
            }

            events.Add(CreateProxySettingEvent("network.proxy.modified", "modified", current, phase, previous));
            emitted++;
        }

        return events;
    }

    /// <summary>
    /// Creates one proxy-setting row event without previous-value context.
    /// Inputs are event type, change label, current setting, and phase; the
    /// method delegates to the richer modified-event factory.
    /// </summary>
    private static SandboxEvent CreateProxySettingEvent(
        string eventType,
        string change,
        ProxySettingSnapshot setting,
        ProbePhase phase)
    {
        return CreateProxySettingEvent(eventType, change, setting, phase, previous: null);
    }

    /// <summary>
    /// Creates one proxy-setting row event.
    /// Inputs are event type, change label, current setting, phase, and optional
    /// previous setting; processing copies stable key/value hashes and bounded
    /// values; the method returns an event.
    /// </summary>
    private static SandboxEvent CreateProxySettingEvent(
        string eventType,
        string change,
        ProxySettingSnapshot setting,
        ProbePhase phase,
        ProxySettingSnapshot? previous = null)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["settingKey"] = setting.Key,
                ["source"] = setting.Source,
                ["scope"] = setting.Scope,
                ["settingName"] = setting.Name,
                ["settingValue"] = Truncate(setting.Value ?? string.Empty, 512),
                ["valueHash"] = setting.ValueHash,
                ["sourceTool"] = setting.SourceTool
            }
        };

        if (previous is not null)
        {
            evt.Data["previousValueHash"] = previous.ValueHash;
            evt.Data["previousSettingValue"] = Truncate(previous.Value ?? string.Empty, 512);
        }

        return evt;
    }

    /// <summary>
    /// Creates a netstat snapshot summary event.
    /// Inputs are phase, row count, emitted row count, and truncation flag;
    /// processing stores stable count metadata; the method returns an event.
    /// </summary>
    private static SandboxEvent CreateNetstatSnapshotEvent(
        ProbePhase phase,
        IReadOnlyDictionary<string, NetstatRowSnapshot> rows,
        int emittedRows,
        bool truncated)
    {
        return new SandboxEvent
        {
            EventType = "network.netstat.snapshot",
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["rowCount"] = rows.Count.ToString(CultureInfo.InvariantCulture),
                ["emittedRows"] = emittedRows.ToString(CultureInfo.InvariantCulture),
                ["truncated"] = truncated.ToString(CultureInfo.InvariantCulture),
                ["snapshotHash"] = SnapshotHash(rows.Keys),
                ["sourceTool"] = "netstat -ano"
            }
        };
    }

    /// <summary>
    /// Creates a bounded DNS diff summary event before row-level DNS deltas.
    /// Inputs are before/after dictionaries and phase; processing stores stable
    /// counts and snapshot hashes; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateDnsDiffSummaryEvent(
        IReadOnlyDictionary<string, DnsCacheEntrySnapshot> before,
        IReadOnlyDictionary<string, DnsCacheEntrySnapshot> after,
        ProbePhase phase)
    {
        return new SandboxEvent
        {
            EventType = "dns.cache.diff",
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["beforeEntryCount"] = before.Count.ToString(CultureInfo.InvariantCulture),
                ["afterEntryCount"] = after.Count.ToString(CultureInfo.InvariantCulture),
                ["addedCount"] = CountMissing(before, after).ToString(CultureInfo.InvariantCulture),
                ["removedCount"] = CountMissing(after, before).ToString(CultureInfo.InvariantCulture),
                ["beforeSnapshotHash"] = SnapshotHash(before.Keys),
                ["afterSnapshotHash"] = SnapshotHash(after.Keys),
                ["stableKey"] = "name|recordType|data|rawSummary",
                ["sourceTool"] = "ipconfig /displaydns"
            }
        };
    }

    /// <summary>
    /// Creates a bounded netstat diff summary event before row-level deltas.
    /// Inputs are before/after dictionaries and phase; processing stores counts
    /// and hashes without expanding every row; the method returns an event.
    /// </summary>
    private static SandboxEvent CreateNetstatDiffSummaryEvent(
        IReadOnlyDictionary<string, NetstatRowSnapshot> before,
        IReadOnlyDictionary<string, NetstatRowSnapshot> after,
        ProbePhase phase)
    {
        return new SandboxEvent
        {
            EventType = "network.netstat.diff",
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["beforeRowCount"] = before.Count.ToString(CultureInfo.InvariantCulture),
                ["afterRowCount"] = after.Count.ToString(CultureInfo.InvariantCulture),
                ["addedCount"] = CountMissing(before, after).ToString(CultureInfo.InvariantCulture),
                ["removedCount"] = CountMissing(after, before).ToString(CultureInfo.InvariantCulture),
                ["beforeSnapshotHash"] = SnapshotHash(before.Keys),
                ["afterSnapshotHash"] = SnapshotHash(after.Keys),
                ["sourceTool"] = "netstat -ano"
            }
        };
    }

    /// <summary>
    /// Creates a TCP/UDP listener snapshot summary event.
    /// Inputs are phase, protocol, and count; processing stores count metadata;
    /// the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateListenerSnapshotEvent(ProbePhase phase, string protocol, int listenerCount)
    {
        return new SandboxEvent
        {
            EventType = $"network.{protocol}.listener.snapshot",
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["protocol"] = protocol.ToUpperInvariant(),
                ["listenerCount"] = listenerCount.ToString(CultureInfo.InvariantCulture)
            }
        };
    }

    /// <summary>
    /// Creates DNS cache added/removed events.
    /// Inputs are baseline/current cache dictionaries and phase; processing
    /// compares hash keys and caps event volume; the method returns events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateDnsCacheDeltaEvents(
        IReadOnlyDictionary<string, DnsCacheEntrySnapshot> before,
        IReadOnlyDictionary<string, DnsCacheEntrySnapshot> after,
        ProbePhase phase)
    {
        var events = new List<SandboxEvent>();
        AddBoundedDiffEvents(
            events,
            before,
            after,
            "dns.cache.added",
            "added",
            phase,
            CreateDnsCacheEvent);
        AddBoundedDiffEvents(
            events,
            after,
            before,
            "dns.cache.removed",
            "removed",
            phase,
            CreateDnsCacheEvent);
        return events;
    }

    /// <summary>
    /// Creates one DNS cache event.
    /// Inputs are event type, change label, entry, and phase; processing copies
    /// parsed and fallback raw-summary metadata; the method returns an event.
    /// </summary>
    private static SandboxEvent CreateDnsCacheEvent(string eventType, string change, DnsCacheEntrySnapshot entry, ProbePhase phase)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["entryHash"] = entry.Key,
                ["sourceTool"] = "ipconfig /displaydns"
            }
        };

        AddIfNotEmpty(evt.Data, "name", entry.Name);
        AddIfNotEmpty(evt.Data, "recordType", entry.RecordType);
        AddIfNotEmpty(evt.Data, "data", entry.Data);
        AddIfNotEmpty(evt.Data, "timeToLive", entry.TimeToLive);
        AddIfNotEmpty(evt.Data, "rawSummary", entry.RawSummary);
        return evt;
    }

    /// <summary>
    /// Emits bounded netstat row observations for the post-run snapshot.
    /// Inputs are netstat rows and phase; processing caps volume and appends a
    /// truncation event when needed; the method returns events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateNetstatRowEvents(
        IReadOnlyDictionary<string, NetstatRowSnapshot> rows,
        ProbePhase phase)
    {
        var events = new List<SandboxEvent>();
        var emitted = 0;
        foreach (var row in rows.Values.OrderBy(row => row.Protocol, StringComparer.OrdinalIgnoreCase).ThenBy(row => row.Local, StringComparer.OrdinalIgnoreCase).ThenBy(row => row.Remote, StringComparer.OrdinalIgnoreCase))
        {
            if (emitted >= MaxNetstatRows)
            {
                events.Add(CreateTruncatedEvent("network.netstat.truncated", "observed", phase, rows.Count, emitted));
                break;
            }

            events.Add(CreateNetstatEvent("network.netstat", "observed", row, phase));
            emitted++;
        }

        return events;
    }

    /// <summary>
    /// Creates netstat added/removed events.
    /// Inputs are baseline/current netstat dictionaries and phase; processing
    /// compares row keys and caps event volume; the method returns events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateNetstatDeltaEvents(
        IReadOnlyDictionary<string, NetstatRowSnapshot> before,
        IReadOnlyDictionary<string, NetstatRowSnapshot> after,
        ProbePhase phase)
    {
        var events = new List<SandboxEvent>();
        AddBoundedDiffEvents(events, before, after, "network.netstat.added", "added", phase, CreateNetstatEvent);
        AddBoundedDiffEvents(events, after, before, "network.netstat.removed", "removed", phase, CreateNetstatEvent);
        return events;
    }

    /// <summary>
    /// Creates one netstat event.
    /// Inputs are event type, change label, row, and phase; processing copies
    /// protocol, endpoints, state, and PID; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateNetstatEvent(string eventType, string change, NetstatRowSnapshot row, ProbePhase phase)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            ProcessId = row.OwningProcessId,
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["protocol"] = row.Protocol,
                ["local"] = row.Local,
                ["remote"] = row.Remote,
                ["state"] = row.State,
                ["sourceTool"] = "netstat -ano"
            }
        };

        if (row.OwningProcessId is not null)
        {
            evt.Data["owningProcessId"] = row.OwningProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        return evt;
    }

    /// <summary>
    /// Creates listener opened/closed events.
    /// Inputs are event prefix, before/current listener dictionaries, and phase;
    /// processing compares endpoint keys and caps volume; the method returns
    /// listener delta events.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateListenerDeltaEvents(
        string eventPrefix,
        IReadOnlyDictionary<string, NetworkEndpointSnapshot> before,
        IReadOnlyDictionary<string, NetworkEndpointSnapshot> after,
        ProbePhase phase)
    {
        var events = new List<SandboxEvent>();
        AddBoundedDiffEvents(events, before, after, $"{eventPrefix}.opened", "opened", phase, CreateListenerEvent);
        AddBoundedDiffEvents(events, after, before, $"{eventPrefix}.closed", "closed", phase, CreateListenerEvent);
        return events;
    }

    /// <summary>
    /// Creates one listener event.
    /// Inputs are event type, change label, endpoint snapshot, and phase;
    /// processing copies protocol and local address fields; the method returns
    /// a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateListenerEvent(
        string eventType,
        string change,
        NetworkEndpointSnapshot endpoint,
        ProbePhase phase)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["protocol"] = endpoint.Protocol,
                ["local"] = endpoint.Local,
                ["localAddress"] = endpoint.EndPoint.Address.ToString(),
                ["localPort"] = endpoint.EndPoint.Port.ToString(CultureInfo.InvariantCulture),
                ["state"] = endpoint.State
            }
        };
    }

    /// <summary>
    /// Adds bounded dictionary-diff events using a supplied event factory.
    /// Inputs are output list, dictionaries, event metadata, and factory;
    /// processing emits items in key order up to a cap; the method returns no
    /// value.
    /// </summary>
    private static void AddBoundedDiffEvents<TSnapshot>(
        List<SandboxEvent> events,
        IReadOnlyDictionary<string, TSnapshot> existing,
        IReadOnlyDictionary<string, TSnapshot> candidate,
        string eventType,
        string change,
        ProbePhase phase,
        Func<string, string, TSnapshot, ProbePhase, SandboxEvent> createEvent)
    {
        var emitted = 0;
        foreach (var (key, snapshot) in candidate.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (existing.ContainsKey(key))
            {
                continue;
            }

            if (emitted >= MaxDeltaEventsPerKind)
            {
                events.Add(CreateTruncatedEvent($"{eventType}.truncated", change, phase, candidate.Count, emitted));
                break;
            }

            events.Add(createEvent(eventType, change, snapshot, phase));
            emitted++;
        }
    }

    /// <summary>
    /// Counts candidate keys missing from an existing dictionary.
    /// Inputs are existing and candidate dictionaries; processing performs a
    /// case-insensitive key-set comparison; the method returns a total count.
    /// </summary>
    private static int CountMissing<TSnapshot>(
        IReadOnlyDictionary<string, TSnapshot> existing,
        IReadOnlyDictionary<string, TSnapshot> candidate)
    {
        var count = 0;
        foreach (var key in candidate.Keys)
        {
            if (!existing.ContainsKey(key))
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Counts changed signatures for keys present in both snapshots.
    /// Inputs are before/after dictionaries; processing compares item
    /// signatures; the method returns modified item count.
    /// </summary>
    private static int CountModified(
        IReadOnlyDictionary<string, ProxySettingSnapshot> before,
        IReadOnlyDictionary<string, ProxySettingSnapshot> after)
    {
        var count = 0;
        foreach (var (key, current) in after)
        {
            if (before.TryGetValue(key, out var previous) &&
                !string.Equals(previous.Signature, current.Signature, StringComparison.Ordinal))
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Hashes proxy setting keys and value hashes for stable summaries.
    /// Inputs are a proxy snapshot; processing sorts source/scope/name rows;
    /// the method returns a SHA-256 snapshot hash.
    /// </summary>
    private static string ProxySnapshotHash(ProxySettingsSnapshot proxySettings)
    {
        return SnapshotHash(proxySettings.Settings.Values.Select(setting => $"{setting.Key}|{setting.ValueHash}"));
    }

    /// <summary>
    /// Reads one proxy setting value from a snapshot by source/name.
    /// Inputs are snapshot, source, and setting name; processing picks the
    /// first matching setting in stable scope order; the method returns the
    /// bounded value or null.
    /// </summary>
    private static string? FindProxySettingValue(ProxySettingsSnapshot proxySettings, string source, string name)
    {
        return proxySettings.Settings.Values
            .Where(setting =>
                string.Equals(setting.Source, source, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(setting.Name, name, StringComparison.OrdinalIgnoreCase))
            .OrderBy(setting => setting.Scope, StringComparer.OrdinalIgnoreCase)
            .Select(setting => Truncate(setting.Value ?? string.Empty, 512))
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
    }

    /// <summary>
    /// Creates a generic truncation diagnostic event.
    /// Inputs are event type, change label, phase, total count, and emitted
    /// count; processing stores cap metadata; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateTruncatedEvent(string eventType, string change, ProbePhase phase, int totalCount, int emittedCount)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["phase"] = ToPhaseLabel(phase),
                ["change"] = change,
                ["totalCount"] = totalCount.ToString(CultureInfo.InvariantCulture),
                ["emittedCount"] = emittedCount.ToString(CultureInfo.InvariantCulture)
            }
        };
    }

    /// <summary>
    /// Copies diagnostic events and adds the current phase.
    /// Inputs are diagnostic events and phase; processing clones each event with
    /// a phase Data value; the method yields normalized diagnostics.
    /// </summary>
    private static IEnumerable<SandboxEvent> WithPhase(IEnumerable<SandboxEvent> diagnostics, ProbePhase phase)
    {
        foreach (var diagnostic in diagnostics)
        {
            var data = new Dictionary<string, string>(diagnostic.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["phase"] = ToPhaseLabel(phase)
            };
            yield return diagnostic with { Data = data };
        }
    }

    /// <summary>
    /// Hashes a case-insensitive snapshot key set for compact diff summaries.
    /// Inputs are snapshot keys; processing sorts and joins keys before SHA-256;
    /// the method returns a lower-case hex digest.
    /// </summary>
    private static string SnapshotHash(IEnumerable<string> keys)
    {
        var material = string.Join("\n", keys.OrderBy(key => key, StringComparer.OrdinalIgnoreCase));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Truncates a string for compact event Data.
    /// Inputs are value and max length; processing appends an ellipsis marker
    /// when needed; the method returns a bounded string.
    /// </summary>
    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }

    /// <summary>
    /// Adds a string Data value when it is non-empty.
    /// Inputs are Data dictionary, key, and value; processing skips empty
    /// values; the method returns no value.
    /// </summary>
    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Converts probe phases to stable event labels.
    /// Inputs are enum values, processing maps known phases; the method returns
    /// a lowercase label for event Data.
    /// </summary>
    private static string ToPhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.AfterStart => "after-start",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString()
        };
    }
}

/// <summary>
/// Supplies TCP connection snapshots for network diff collection.
/// Inputs are none; processing reads active TCP connections; Capture returns
/// connection snapshots keyed by endpoint/state identity.
/// </summary>
internal interface ITcpConnectionSnapshotProvider
{
    Dictionary<string, TcpConnectionSnapshot> Capture();
}

/// <summary>
/// Captures active TCP connections visible to the guest user.
/// Inputs are none; processing queries IPGlobalProperties and tolerates network
/// API failures; Capture returns a case-insensitive connection dictionary.
/// </summary>
internal sealed class TcpConnectionSnapshotProvider : ITcpConnectionSnapshotProvider
{
    /// <summary>
    /// Captures active TCP connection snapshots.
    /// Inputs are none; processing maps endpoints and state into immutable
    /// records; the method returns an empty dictionary when the platform denies
    /// the query.
    /// </summary>
    public Dictionary<string, TcpConnectionSnapshot> Capture()
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpConnections()
                .Select(connection => new TcpConnectionSnapshot(connection.LocalEndPoint, connection.RemoteEndPoint, connection.State.ToString()))
                .ToDictionary(connection => connection.Key, StringComparer.OrdinalIgnoreCase);
        }
        catch (NetworkInformationException)
        {
            return new Dictionary<string, TcpConnectionSnapshot>(StringComparer.OrdinalIgnoreCase);
        }
    }
}

/// <summary>
/// Captures DNS cache, hosts, proxy, netstat, and listener state for
/// network-depth events.
/// Inputs are none beyond cancellation; processing combines managed network
/// APIs and bounded helper commands; CaptureAsync returns a full snapshot plus
/// diagnostic events for unavailable helpers.
/// </summary>
internal interface INetworkStateSnapshotProvider
{
    Task<NetworkStateSnapshot> CaptureAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Default network-state provider for DNS cache, hosts, proxy, and netstat
/// collection.
/// Inputs are a cancellation token; processing uses IPGlobalProperties,
/// hosts-file reads, registry/environment proxy reads, ipconfig /displaydns,
/// netsh winhttp, and netstat -ano with short timeouts; CaptureAsync returns
/// parsed snapshots and non-fatal diagnostics.
/// </summary>
internal sealed class NetworkStateSnapshotProvider : INetworkStateSnapshotProvider
{
    private static readonly TimeSpan DnsCacheTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan NetstatTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan WinHttpProxyTimeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Captures all network-state sub-snapshots.
    /// Inputs are cancellation token; processing isolates each source so one
    /// failure does not prevent other network evidence; the method returns a
    /// NetworkStateSnapshot.
    /// </summary>
    public async Task<NetworkStateSnapshot> CaptureAsync(CancellationToken cancellationToken = default)
    {
        var diagnostics = new List<SandboxEvent>();
        var tcpListeners = CaptureTcpListeners(diagnostics);
        var udpListeners = CaptureUdpListeners(diagnostics);
        var dnsEntries = await CaptureDnsCacheAsync(diagnostics, cancellationToken).ConfigureAwait(false);
        var netstatRows = await CaptureNetstatAsync(diagnostics, cancellationToken).ConfigureAwait(false);
        var hostsFile = CaptureHostsFile(diagnostics, cancellationToken);
        var proxySettings = await CaptureProxySettingsAsync(diagnostics, cancellationToken).ConfigureAwait(false);

        return new NetworkStateSnapshot(tcpListeners, udpListeners, dnsEntries, netstatRows, hostsFile, proxySettings, diagnostics);
    }

    /// <summary>
    /// Captures active TCP listeners through managed APIs.
    /// Inputs are a diagnostics list; processing tolerates NetworkInformation
    /// failures; the method returns listener snapshots keyed by endpoint.
    /// </summary>
    private static Dictionary<string, NetworkEndpointSnapshot> CaptureTcpListeners(List<SandboxEvent> diagnostics)
    {
        try
        {
            var listeners = new Dictionary<string, NetworkEndpointSnapshot>(StringComparer.OrdinalIgnoreCase);
            foreach (var endpoint in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners())
            {
                var snapshot = new NetworkEndpointSnapshot("TCP", endpoint, "LISTENING");
                listeners[snapshot.Key] = snapshot;
            }

            return listeners;
        }
        catch (NetworkInformationException ex)
        {
            diagnostics.Add(CreateCaptureFailureEvent("network.tcp.listener.capture_failed", "IPGlobalProperties.GetActiveTcpListeners", ex));
            return new Dictionary<string, NetworkEndpointSnapshot>(StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Captures active UDP listeners through managed APIs.
    /// Inputs are a diagnostics list; processing tolerates NetworkInformation
    /// failures; the method returns listener snapshots keyed by endpoint.
    /// </summary>
    private static Dictionary<string, NetworkEndpointSnapshot> CaptureUdpListeners(List<SandboxEvent> diagnostics)
    {
        try
        {
            var listeners = new Dictionary<string, NetworkEndpointSnapshot>(StringComparer.OrdinalIgnoreCase);
            foreach (var endpoint in IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners())
            {
                var snapshot = new NetworkEndpointSnapshot("UDP", endpoint, "LISTENING");
                listeners[snapshot.Key] = snapshot;
            }

            return listeners;
        }
        catch (NetworkInformationException ex)
        {
            diagnostics.Add(CreateCaptureFailureEvent("network.udp.listener.capture_failed", "IPGlobalProperties.GetActiveUdpListeners", ex));
            return new Dictionary<string, NetworkEndpointSnapshot>(StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Captures and parses the Windows DNS resolver cache.
    /// Inputs are diagnostics list and cancellation token; processing invokes
    /// ipconfig /displaydns with a timeout; the method returns parsed entries.
    /// </summary>
    private static async Task<Dictionary<string, DnsCacheEntrySnapshot>> CaptureDnsCacheAsync(
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            diagnostics.Add(CreateUnsupportedEvent("dns.cache.capture_skipped", "ipconfig /displaydns"));
            return new Dictionary<string, DnsCacheEntrySnapshot>(StringComparer.OrdinalIgnoreCase);
        }

        var result = await BoundedProcessRunner.RunAsync(
            "ipconfig.exe",
            ["/displaydns"],
            DnsCacheTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            diagnostics.Add(CreateCommandFailureEvent("dns.cache.capture_failed", result));
        }

        return ParseDnsCache(result.StandardOutput);
    }

    /// <summary>
    /// Captures and parses netstat rows with owning process IDs.
    /// Inputs are diagnostics list and cancellation token; processing invokes
    /// netstat -ano with a timeout; the method returns parsed rows.
    /// </summary>
    private static async Task<Dictionary<string, NetstatRowSnapshot>> CaptureNetstatAsync(
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            diagnostics.Add(CreateUnsupportedEvent("network.netstat.capture_skipped", "netstat -ano"));
            return new Dictionary<string, NetstatRowSnapshot>(StringComparer.OrdinalIgnoreCase);
        }

        var result = await BoundedProcessRunner.RunAsync(
            "netstat.exe",
            ["-ano"],
            NetstatTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            diagnostics.Add(CreateCommandFailureEvent("network.netstat.capture_failed", result));
        }

        return ParseNetstat(result.StandardOutput);
    }

    /// <summary>
    /// Captures the local hosts file as parsed address/host entries.
    /// Inputs are diagnostics and cancellation; processing reads the file with
    /// sharing enabled and tolerates missing/inaccessible hosts files; the
    /// method returns a compact hosts snapshot.
    /// </summary>
    private static HostsFileSnapshot CaptureHostsFile(List<SandboxEvent> diagnostics, CancellationToken cancellationToken)
    {
        var path = ResolveHostsPath();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(path))
            {
                return new HostsFileSnapshot(path, Exists: false, LineCount: 0, ContentSha256: string.Empty, new Dictionary<string, HostsEntrySnapshot>(StringComparer.OrdinalIgnoreCase));
            }

            string text;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true))
            {
                text = reader.ReadToEnd();
            }

            var lines = text.Split(['\r', '\n'], StringSplitOptions.None);
            var entries = ParseHostsEntries(path, lines);
            return new HostsFileSnapshot(
                path,
                Exists: true,
                LineCount: lines.Length,
                ContentSha256: Sha256Hex(text),
                entries);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException or NotSupportedException or PathTooLongException)
        {
            diagnostics.Add(CreateCaptureFailureEvent("network.hosts.capture_failed", path, ex));
            return new HostsFileSnapshot(path, Exists: false, LineCount: 0, ContentSha256: string.Empty, new Dictionary<string, HostsEntrySnapshot>(StringComparer.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Captures proxy settings from environment, HKCU Internet Settings, and
    /// WinHTTP. Inputs are diagnostics and cancellation; processing isolates
    /// each source; the method returns a combined proxy snapshot.
    /// </summary>
    private static async Task<ProxySettingsSnapshot> CaptureProxySettingsAsync(
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        var settings = new Dictionary<string, ProxySettingSnapshot>(StringComparer.OrdinalIgnoreCase);
        CaptureEnvironmentProxySettings(settings, cancellationToken);
        if (OperatingSystem.IsWindows())
        {
            CaptureInternetSettingsProxy(settings, diagnostics, cancellationToken);
            await CaptureWinHttpProxyAsync(settings, diagnostics, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            diagnostics.Add(CreateUnsupportedEvent("network.proxy.winhttp.capture_skipped", "netsh winhttp show proxy"));
        }

        return new ProxySettingsSnapshot(settings);
    }

    /// <summary>
    /// Resolves the platform hosts-file path.
    /// Inputs are none; processing prefers the Windows system directory when
    /// present and falls back to /etc/hosts on non-Windows platforms; returns
    /// the path used in events.
    /// </summary>
    private static string ResolveHostsPath()
    {
        if (OperatingSystem.IsWindows())
        {
            var systemDirectory = Environment.SystemDirectory;
            if (!string.IsNullOrWhiteSpace(systemDirectory))
            {
                return Path.Combine(systemDirectory, "drivers", "etc", "hosts");
            }

            var windir = Environment.GetEnvironmentVariable("WINDIR");
            if (!string.IsNullOrWhiteSpace(windir))
            {
                return Path.Combine(windir, "System32", "drivers", "etc", "hosts");
            }
        }

        return "/etc/hosts";
    }

    /// <summary>
    /// Parses hosts-file lines into per-host entries.
    /// Inputs are a source path and raw lines; processing skips comments/blank
    /// lines and expands one address with multiple names into multiple stable
    /// entries; the method returns a keyed dictionary.
    /// </summary>
    private static Dictionary<string, HostsEntrySnapshot> ParseHostsEntries(string sourcePath, IEnumerable<string> lines)
    {
        var entries = new Dictionary<string, HostsEntrySnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in lines)
        {
            var effectiveLine = rawLine;
            var commentIndex = effectiveLine.IndexOf('#', StringComparison.Ordinal);
            if (commentIndex >= 0)
            {
                effectiveLine = effectiveLine[..commentIndex];
            }

            var tokens = effectiveLine.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (tokens.Length < 2)
            {
                continue;
            }

            var address = tokens[0];
            foreach (var hostName in tokens.Skip(1))
            {
                var entry = new HostsEntrySnapshot(sourcePath, address, hostName, Truncate($"{address} {hostName}", 512));
                entries[entry.Key] = entry;
            }
        }

        return entries;
    }

    /// <summary>
    /// Captures process environment proxy variables.
    /// Inputs are output settings and cancellation; processing reads common
    /// upper/lower-case variables without expanding the full environment block.
    /// </summary>
    private static void CaptureEnvironmentProxySettings(Dictionary<string, ProxySettingSnapshot> settings, CancellationToken cancellationToken)
    {
        foreach (var name in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy" })
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            AddProxySetting(settings, "environment", "process", name.ToUpperInvariant(), value, "process environment");
        }
    }

    /// <summary>
    /// Captures HKCU Internet Settings proxy values.
    /// Inputs are output settings, diagnostics, and cancellation; processing
    /// reads common low-privilege proxy registry values; the method returns no
    /// value.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CaptureInternetSettingsProxy(
        Dictionary<string, ProxySettingSnapshot> settings,
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        const string subKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(subKeyPath);
            if (key is null)
            {
                return;
            }

            foreach (var valueName in new[] { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect" })
            {
                cancellationToken.ThrowIfCancellationRequested();
                var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (value is null)
                {
                    continue;
                }

                AddProxySetting(
                    settings,
                    "registry",
                    $@"HKCU\{subKeyPath}",
                    valueName,
                    FormatRegistryValue(value),
                    "HKCU Internet Settings");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or ArgumentException)
        {
            diagnostics.Add(CreateCaptureFailureEvent("network.proxy.capture_failed", $@"HKCU\{subKeyPath}", ex));
        }
    }

    /// <summary>
    /// Captures machine WinHTTP proxy state through netsh.
    /// Inputs are output settings, diagnostics, and cancellation; processing
    /// runs a bounded helper and records the compact output summary.
    /// </summary>
    private static async Task CaptureWinHttpProxyAsync(
        Dictionary<string, ProxySettingSnapshot> settings,
        List<SandboxEvent> diagnostics,
        CancellationToken cancellationToken)
    {
        var result = await BoundedProcessRunner.RunAsync(
            "netsh.exe",
            ["winhttp", "show", "proxy"],
            WinHttpProxyTimeout,
            cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            diagnostics.Add(CreateCommandFailureEvent("network.proxy.winhttp.capture_failed", result));
        }

        var summary = Truncate(NormalizeWhitespace(result.StandardOutput), 512);
        if (!string.IsNullOrWhiteSpace(summary))
        {
            AddProxySetting(settings, "winhttp", "machine", "WinHttpProxy", summary, "netsh winhttp show proxy");
        }
    }

    /// <summary>
    /// Adds one proxy setting to a keyed dictionary.
    /// Inputs are setting identity and value; processing normalizes empty
    /// values and stores a stable row; the method returns no value.
    /// </summary>
    private static void AddProxySetting(
        Dictionary<string, ProxySettingSnapshot> settings,
        string source,
        string scope,
        string name,
        string? value,
        string sourceTool)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var setting = new ProxySettingSnapshot(source, scope, name, value, sourceTool);
        settings[setting.Key] = setting;
    }

    /// <summary>
    /// Parses DNS cache text into stable hash-keyed entries.
    /// Inputs are ipconfig output; processing extracts English labels when
    /// available and falls back to a hash of each non-empty block; the method
    /// returns a case-insensitive dictionary.
    /// </summary>
    private static Dictionary<string, DnsCacheEntrySnapshot> ParseDnsCache(string text)
    {
        var entries = new Dictionary<string, DnsCacheEntrySnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var block in SplitBlocks(text))
        {
            var lines = block
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(line => !line.Equals("Windows IP Configuration", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (lines.Count == 0)
            {
                continue;
            }

            var rawSummary = Truncate(string.Join(" | ", lines.Take(8)), 512);
            var stableRawSummary = Truncate(
                string.Join(" | ", lines.Where(line => !line.StartsWith("Time To Live", StringComparison.OrdinalIgnoreCase)).Take(8)),
                512);
            var name = FindLabelValue(lines, "Record Name") ?? FindLikelyDnsName(lines);
            var recordType = FindLabelValue(lines, "Record Type");
            var ttl = FindLabelValue(lines, "Time To Live");
            var data = FindRecordData(lines);
            var keyMaterial = string.Join("|", name, recordType, data, stableRawSummary);
            var key = Sha256Hex(keyMaterial);
            entries[key] = new DnsCacheEntrySnapshot(key, name, recordType, data, ttl, rawSummary);
        }

        return entries;
    }

    /// <summary>
    /// Parses netstat output into keyed protocol rows.
    /// Inputs are netstat -ano output; processing accepts TCP and UDP row
    /// shapes; the method returns parsed rows keyed by protocol/endpoints/PID.
    /// </summary>
    private static Dictionary<string, NetstatRowSnapshot> ParseNetstat(string text)
    {
        var rows = new Dictionary<string, NetstatRowSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = rawLine.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length < 4)
            {
                continue;
            }

            if (parts[0].Equals("TCP", StringComparison.OrdinalIgnoreCase) && parts.Length >= 5)
            {
                var row = new NetstatRowSnapshot("TCP", parts[1], parts[2], parts[3], ParsePid(parts[4]));
                rows[row.Key] = row;
            }
            else if (parts[0].Equals("UDP", StringComparison.OrdinalIgnoreCase))
            {
                var pidToken = parts[^1];
                var remote = parts.Length >= 4 ? parts[2] : "*:*";
                var row = new NetstatRowSnapshot("UDP", parts[1], remote, "LISTENING", ParsePid(pidToken));
                rows[row.Key] = row;
            }
        }

        return rows;
    }

    /// <summary>
    /// Splits helper-command output into non-empty paragraph blocks.
    /// Inputs are raw text; processing groups lines separated by blank lines;
    /// the method yields block strings.
    /// </summary>
    private static IEnumerable<string> SplitBlocks(string text)
    {
        var block = new StringBuilder();
        foreach (var line in text.Split(['\r', '\n']))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                if (block.Length > 0)
                {
                    yield return block.ToString();
                    block.Clear();
                }

                continue;
            }

            block.AppendLine(line);
        }

        if (block.Length > 0)
        {
            yield return block.ToString();
        }
    }

    /// <summary>
    /// Finds a colon-delimited value for an English ipconfig label.
    /// Inputs are lines and label prefix; processing ignores dot padding; the
    /// method returns the trimmed value or null.
    /// </summary>
    private static string? FindLabelValue(IEnumerable<string> lines, string label)
    {
        foreach (var line in lines)
        {
            if (!line.StartsWith(label, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon >= 0 && colon + 1 < line.Length)
            {
                return line[(colon + 1)..].Trim();
            }
        }

        return null;
    }

    /// <summary>
    /// Finds DNS record data from common ipconfig record lines.
    /// Inputs are DNS cache block lines; processing excludes metadata labels;
    /// the method returns the first record payload or null.
    /// </summary>
    private static string? FindRecordData(IEnumerable<string> lines)
    {
        foreach (var line in lines)
        {
            if (!line.Contains("Record", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Record Name", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Record Type", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("Data Length", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon >= 0 && colon + 1 < line.Length)
            {
                return line[(colon + 1)..].Trim();
            }
        }

        return null;
    }

    /// <summary>
    /// Finds a likely DNS name when localized ipconfig labels cannot be parsed.
    /// Inputs are block lines; processing selects the first dotted non-metadata
    /// token; the method returns a candidate name or null.
    /// </summary>
    private static string? FindLikelyDnsName(IEnumerable<string> lines)
    {
        return lines
            .Select(line => line.Trim().TrimEnd('.'))
            .FirstOrDefault(line => line.Contains('.', StringComparison.Ordinal) && !line.Contains(':', StringComparison.Ordinal));
    }

    /// <summary>
    /// Parses a process ID token from netstat output.
    /// Inputs are a text token; processing uses invariant integer parsing; the
    /// method returns a nullable PID.
    /// </summary>
    private static int? ParsePid(string token)
    {
        return int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) ? pid : null;
    }

    /// <summary>
    /// Creates a diagnostic event for unsupported network helpers.
    /// Inputs are event type and source tool; processing stores platform
    /// metadata; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateUnsupportedEvent(string eventType, string sourceTool)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["sourceTool"] = sourceTool,
                ["reason"] = "Network helper is only available on Windows.",
                ["zhHint"] = "该网络 helper 仅在 Windows guest 中可用；在非 Windows 或受限环境中会跳过，不代表样本行为。"
            }
        };
    }

    /// <summary>
    /// Creates a diagnostic event from a helper-command result.
    /// Inputs are event type and bounded command result; processing copies
    /// command, exit, timeout, stderr, and exception metadata; returns an event.
    /// </summary>
    private static SandboxEvent CreateCommandFailureEvent(string eventType, BoundedCommandResult result)
    {
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["command"] = Truncate(string.IsNullOrWhiteSpace(result.Arguments) ? result.FileName : $"{result.FileName} {result.Arguments}", 1200),
                ["commandFileName"] = result.FileName,
                ["commandArguments"] = Truncate(result.Arguments, 1024),
                ["timedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["commandTimedOut"] = result.TimedOut.ToString(CultureInfo.InvariantCulture),
                ["timeoutMilliseconds"] = result.Timeout.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture)
            }
        };

        if (result.ExitCode is not null)
        {
            evt.Data["exitCode"] = result.ExitCode.Value.ToString(CultureInfo.InvariantCulture);
            evt.Data["commandExitCode"] = result.ExitCode.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(result.ExceptionType))
        {
            evt.Data["exceptionType"] = result.ExceptionType;
            evt.Data["commandExceptionType"] = result.ExceptionType;
        }

        if (!string.IsNullOrWhiteSpace(result.Message))
        {
            evt.Data["message"] = result.Message;
            evt.Data["commandMessage"] = result.Message;
        }

        AddIfNotEmpty(evt.Data, "zhMessage", CommandFailureZhMessage(result));
        AddIfNotEmpty(evt.Data, "zhHint", "网络 helper 命令失败；请检查命令是否存在、权限是否足够，以及 stderr/exitCode/timeoutMilliseconds。");

        if (!string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            var stdout = result.StandardOutput.Trim();
            evt.Data["stdout"] = Truncate(stdout, 512);
            evt.Data["stdoutTruncated"] = (stdout.Length > 512).ToString(CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(result.StandardError))
        {
            var stderr = result.StandardError.Trim();
            evt.Data["stderr"] = Truncate(stderr, 512);
            evt.Data["stderrTruncated"] = (stderr.Length > 512).ToString(CultureInfo.InvariantCulture);
        }

        return evt;
    }

    /// <summary>
    /// Creates a diagnostic event from a managed network API exception.
    /// Inputs are event type, source API, and exception; processing copies
    /// exception details; the method returns a SandboxEvent.
    /// </summary>
    private static SandboxEvent CreateCaptureFailureEvent(string eventType, string sourceApi, Exception exception)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Data =
            {
                ["sourceApi"] = sourceApi,
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message,
                ["zhMessage"] = "读取网络状态时发生异常；该诊断不会中断整体采集。",
                ["zhHint"] = "请结合 sourceApi、exceptionType/message 判断是权限、系统 API 还是网络栈状态问题。"
            }
        };
    }

    private static string CommandFailureZhMessage(BoundedCommandResult result)
    {
        if (result.TimedOut)
        {
            return "网络 helper 命令超时。";
        }

        if (!string.IsNullOrWhiteSpace(result.ExceptionType))
        {
            return "网络 helper 命令启动或读取输出失败。";
        }

        if (result.ExitCode is not null)
        {
            return $"网络 helper 命令以非零退出码 {result.ExitCode.Value.ToString(CultureInfo.InvariantCulture)} 结束。";
        }

        return string.Empty;
    }

    /// <summary>
    /// Adds a non-empty diagnostic field to a network-state event.
    /// Inputs are Data dictionary, key, and value; processing skips blank
    /// strings; the method returns no value.
    /// </summary>
    private static void AddIfNotEmpty(Dictionary<string, string> data, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            data[key] = value;
        }
    }

    /// <summary>
    /// Hashes DNS cache fallback material.
    /// Inputs are a string; processing computes SHA-256; the method returns a
    /// lower-case hex digest.
    /// </summary>
    private static string Sha256Hex(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Hashes a case-insensitive snapshot key set for compact diff summaries.
    /// Inputs are snapshot keys; processing sorts and joins keys before SHA-256;
    /// the method returns a lower-case hex digest.
    /// </summary>
    private static string SnapshotHash(IEnumerable<string> keys)
    {
        return Sha256Hex(string.Join("\n", keys.OrderBy(key => key, StringComparer.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Truncates a string for compact event Data.
    /// Inputs are value and max length; processing appends an ellipsis marker
    /// when needed; the method returns a bounded string.
    /// </summary>
    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }

    /// <summary>
    /// Formats registry values as compact strings.
    /// Inputs are registry payload values; processing supports arrays and
    /// binary values; the method returns a display string.
    /// </summary>
    private static string? FormatRegistryValue(object? value)
    {
        return value switch
        {
            null => null,
            string[] values => string.Join(";", values),
            byte[] bytes => Convert.ToHexString(bytes),
            _ => value.ToString()
        };
    }

    /// <summary>
    /// Normalizes helper output to a single compact line.
    /// Inputs are raw command output; processing collapses whitespace; the
    /// method returns bounded-friendly summary text.
    /// </summary>
    private static string NormalizeWhitespace(string value)
    {
        return string.Join(" ", value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }
}

/// <summary>
/// Stores one active TCP connection snapshot.
/// Inputs are local/remote endpoints and TCP state; processing exposes stable
/// string forms for event Data; records are returned by TCP snapshot providers.
/// </summary>
internal sealed record TcpConnectionSnapshot(IPEndPoint LocalEndPoint, IPEndPoint RemoteEndPoint, string State)
{
    public string Local => FormatEndPoint(LocalEndPoint);

    public string Remote => FormatEndPoint(RemoteEndPoint);

    public string Key => $"{Local}->{Remote}:{State}";

    /// <summary>
    /// Formats IPv4 and IPv6 endpoints consistently for event output.
    /// Inputs are an endpoint; processing brackets IPv6 literals; the method
    /// returns a host:port string.
    /// </summary>
    private static string FormatEndPoint(IPEndPoint endpoint)
    {
        return endpoint.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{endpoint.Address}]:{endpoint.Port}"
            : $"{endpoint.Address}:{endpoint.Port}";
    }
}

/// <summary>
/// Stores one network listener endpoint.
/// Inputs are protocol, endpoint, and state; processing exposes formatted
/// endpoint strings and stable keys for listener diffing.
/// </summary>
internal sealed record NetworkEndpointSnapshot(string Protocol, IPEndPoint EndPoint, string State)
{
    public string Local => EndPoint.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
        ? $"[{EndPoint.Address}]:{EndPoint.Port}"
        : $"{EndPoint.Address}:{EndPoint.Port}";

    public string Key => $"{Protocol}:{Local}:{State}";
}

/// <summary>
/// Stores one DNS resolver cache entry.
/// Inputs are parsed or fallback ipconfig fields; processing is immutable
/// storage for DNS cache diff events.
/// </summary>
internal sealed record DnsCacheEntrySnapshot(
    string Key,
    string? Name,
    string? RecordType,
    string? Data,
    string? TimeToLive,
    string RawSummary);

/// <summary>
/// Stores one parsed hosts-file entry.
/// Inputs are source path, IP address, and hostname; processing exposes a
/// stable key for before/after hosts diffs.
/// </summary>
internal sealed record HostsEntrySnapshot(
    string SourcePath,
    string Address,
    string HostName,
    string Entry)
{
    public string Key => StableHash($"{Address.ToLowerInvariant()}|{HostName.ToLowerInvariant()}");

    private static string StableHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>
/// Stores the parsed hosts-file snapshot for one probe phase.
/// Inputs are path, existence flag, line count, content hash, and entries;
/// processing is immutable storage for events and diffs.
/// </summary>
internal sealed record HostsFileSnapshot(
    string Path,
    bool Exists,
    int LineCount,
    string ContentSha256,
    Dictionary<string, HostsEntrySnapshot> Entries)
{
    public static HostsFileSnapshot Empty { get; } = new(
        string.Empty,
        Exists: false,
        LineCount: 0,
        ContentSha256: string.Empty,
        new Dictionary<string, HostsEntrySnapshot>(StringComparer.OrdinalIgnoreCase));
}

/// <summary>
/// Stores one parsed netstat row.
/// Inputs are protocol, local/remote endpoints, connection state, and optional
/// owning PID; processing exposes a stable diff key.
/// </summary>
internal sealed record NetstatRowSnapshot(
    string Protocol,
    string Local,
    string Remote,
    string State,
    int? OwningProcessId)
{
    public string Key => $"{Protocol}:{Local}->{Remote}:{State}:{OwningProcessId?.ToString(CultureInfo.InvariantCulture) ?? "unknown"}";
}

/// <summary>
/// Stores one proxy setting from registry, environment, or WinHTTP.
/// Inputs are source/scope/name/value/source-tool fields; processing exposes
/// stable key/signature values for proxy snapshot diffs.
/// </summary>
internal sealed record ProxySettingSnapshot(
    string Source,
    string Scope,
    string Name,
    string? Value,
    string SourceTool)
{
    public string Key => $"{Source}:{Scope}:{Name}";

    public string ValueHash => StableHash(Value ?? string.Empty);

    public string Signature => ValueHash;

    private static string StableHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>
/// Stores combined proxy settings for one probe phase.
/// Inputs are keyed proxy settings; processing is immutable storage for
/// snapshot and diff events.
/// </summary>
internal sealed record ProxySettingsSnapshot(Dictionary<string, ProxySettingSnapshot> Settings)
{
    public static ProxySettingsSnapshot Empty { get; } = new(new Dictionary<string, ProxySettingSnapshot>(StringComparer.OrdinalIgnoreCase));
}

/// <summary>
/// Stores all network-depth snapshots captured for one phase.
/// Inputs are listener, DNS cache, netstat, hosts, proxy, and diagnostic data;
/// processing is immutable storage returned from INetworkStateSnapshotProvider.
/// </summary>
internal sealed record NetworkStateSnapshot(
    Dictionary<string, NetworkEndpointSnapshot> TcpListeners,
    Dictionary<string, NetworkEndpointSnapshot> UdpListeners,
    Dictionary<string, DnsCacheEntrySnapshot> DnsCacheEntries,
    Dictionary<string, NetstatRowSnapshot> NetstatRows,
    HostsFileSnapshot HostsFile,
    ProxySettingsSnapshot ProxySettings,
    IReadOnlyList<SandboxEvent> Diagnostics)
{
    public static NetworkStateSnapshot Empty { get; } = new(
        new Dictionary<string, NetworkEndpointSnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, NetworkEndpointSnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, DnsCacheEntrySnapshot>(StringComparer.OrdinalIgnoreCase),
        new Dictionary<string, NetstatRowSnapshot>(StringComparer.OrdinalIgnoreCase),
        HostsFileSnapshot.Empty,
        ProxySettingsSnapshot.Empty,
        []);
}
