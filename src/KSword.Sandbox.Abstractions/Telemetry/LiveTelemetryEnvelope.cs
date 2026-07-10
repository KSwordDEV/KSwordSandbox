using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Abstractions.Telemetry;

/// <summary>
/// Wraps live events with cursor and source metadata for transport.
/// Inputs are raw normalized events and source files, processing applies no
/// behavior classification, and the record is returned to polling clients.
/// </summary>
public sealed record LiveTelemetryEnvelope
{
    public LiveEventCursor Cursor { get; init; } = new();

    public DateTimeOffset RetrievedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public int TotalEvents { get; init; }

    public List<string> Sources { get; init; } = [];

    public List<SandboxEvent> Events { get; init; } = [];
}
