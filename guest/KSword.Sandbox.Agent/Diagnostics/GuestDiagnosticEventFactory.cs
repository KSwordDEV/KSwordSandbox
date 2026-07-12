using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Agent.Collection;

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
        var evt = new SandboxEvent
        {
            EventType = eventType,
            Source = "guest",
            Path = path,
            Data =
            {
                ["exceptionType"] = exception.GetType().FullName ?? exception.GetType().Name,
                ["message"] = exception.Message,
                ["zhMessage"] = "Guest 诊断事件捕获到异常；请结合 eventType、path 和 exceptionType/message 判断根因。",
                ["zhHint"] = "该事件通常表示采集或环境诊断问题，不应直接归类为样本行为。"
            }
        };
        GuestSelfNoiseMetadata.Apply(evt);
        return evt;
    }
}
