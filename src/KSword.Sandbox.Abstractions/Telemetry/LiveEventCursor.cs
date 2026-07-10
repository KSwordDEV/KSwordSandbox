namespace KSword.Sandbox.Abstractions.Telemetry;

/// <summary>
/// Carries paging state for live raw-event polling.
/// Inputs are supplied by WebUI query values, processing clamps values in the
/// service layer, and the record is returned with event-feed responses.
/// </summary>
public sealed record LiveEventCursor
{
    public Guid JobId { get; init; }

    public int Offset { get; init; }

    public int Take { get; init; } = 100;
}
