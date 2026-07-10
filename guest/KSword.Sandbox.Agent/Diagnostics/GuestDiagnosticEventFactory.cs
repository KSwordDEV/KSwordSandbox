using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Diagnostics;

/// <summary>
/// Creates normalized guest diagnostic events for failures and milestones.
/// Inputs are event names, paths, and exception details; processing populates
/// common fields; methods return SandboxEvent records.
/// </summary>
internal static class GuestDiagnosticEventFactory
{
    /// <summary>
    /// Creates an exception event.
    /// Inputs are event type, optional path, and exception; processing copies
    /// exception type and message into Data; the method returns a SandboxEvent.
    /// </summary>
    public static SandboxEvent FromException(string eventType, string? path, Exception exception)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = path,
            Data =
            {
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message
            }
        };
    }
}
