namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: stream offset, source, event type, message, and optional observation timestamp.
/// Processing: represents live event rows in a UI-safe contract that can be paged or polled.
/// Return behavior: instances are serialized as live event response items.
/// </summary>
/// <param name="Offset">Monotonic event offset assigned by the event reader.</param>
/// <param name="Source">Event source such as host, guest, or driver.</param>
/// <param name="EventType">Source-specific event type.</param>
/// <param name="Message">Rendered event message intended for the dashboard.</param>
/// <param name="ObservedAtUtc">Optional UTC timestamp when the event was observed.</param>
public sealed record LiveEventContract(
    long Offset,
    string Source,
    string EventType,
    string Message,
    DateTimeOffset? ObservedAtUtc);
