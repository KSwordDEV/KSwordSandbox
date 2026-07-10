using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Captures TCP connection baselines and emits post-run connection deltas.
/// Inputs are BeforeStart and AfterRun probe phases; processing queries
/// IPGlobalProperties without administrator rights; CollectAsync returns
/// legacy network.tcp events for opened connections and network.tcp.closed for
/// closed baseline connections.
/// </summary>
internal sealed class TcpConnectionDiffProbe : IGuestProbe
{
    private readonly ITcpConnectionSnapshotProvider snapshotProvider;
    private Dictionary<string, TcpConnectionSnapshot> baseline = new(StringComparer.OrdinalIgnoreCase);

    public TcpConnectionDiffProbe()
        : this(new TcpConnectionSnapshotProvider())
    {
    }

    /// <summary>
    /// Creates a TCP diff probe with an injectable snapshot provider.
    /// The input is a snapshot provider, processing stores it for future probe
    /// phases, and the constructor returns no value.
    /// </summary>
    public TcpConnectionDiffProbe(ITcpConnectionSnapshotProvider snapshotProvider)
    {
        this.snapshotProvider = snapshotProvider;
    }

    public string ProbeId => "tcp-diff";

    /// <summary>
    /// Collects TCP delta events for one probe phase.
    /// Inputs are phase, guest context, and cancellation token; processing
    /// captures the baseline before launch and compares it after execution; the
    /// method returns normalized network events.
    /// </summary>
    public Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (phase == ProbePhase.BeforeStart)
        {
            baseline = snapshotProvider.Capture();
            return Task.FromResult<IReadOnlyList<SandboxEvent>>([]);
        }

        if (phase != ProbePhase.AfterRun)
        {
            return Task.FromResult<IReadOnlyList<SandboxEvent>>([]);
        }

        var current = snapshotProvider.Capture();
        var events = new List<SandboxEvent>();

        foreach (var (key, connection) in current.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!baseline.ContainsKey(key))
            {
                events.Add(CreateTcpEvent("network.tcp", "opened", connection));
            }
        }

        foreach (var (key, connection) in baseline.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!current.ContainsKey(key))
            {
                events.Add(CreateTcpEvent("network.tcp.closed", "closed", connection));
            }
        }

        return Task.FromResult<IReadOnlyList<SandboxEvent>>(events);
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
