using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Classification;

/// <summary>
/// Wraps a raw event with lightweight category metadata.
/// Inputs are normalized events and classifier results; processing stores the
/// selected category and reason; the record is returned to report builders.
/// </summary>
public sealed record ClassifiedEvent
{
    public required SandboxEvent Event { get; init; }

    public EventCategory Category { get; init; } = EventCategory.Unknown;

    public string Reason { get; init; } = string.Empty;
}
