namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: no external input beyond the host clock implementation.
/// Processing: abstracts UTC time reads so endpoint and dashboard code can be tested deterministically.
/// Return behavior: implementations return the current UTC timestamp.
/// </summary>
internal interface ISandboxWebClock
{
    /// <summary>
    /// Inputs: none.
    /// Processing: reads the configured clock source.
    /// Return behavior: returns a UTC timestamp for response metadata and diagnostics.
    /// </summary>
    DateTimeOffset UtcNow();
}

/// <summary>
/// Inputs: no constructor input.
/// Processing: uses DateTimeOffset.UtcNow as the production clock source.
/// Return behavior: returns the system UTC timestamp whenever UtcNow is called.
/// </summary>
internal sealed class SystemSandboxWebClock : ISandboxWebClock
{
    /// <summary>
    /// Inputs: none.
    /// Processing: reads DateTimeOffset.UtcNow directly.
    /// Return behavior: returns the current UTC timestamp.
    /// </summary>
    public DateTimeOffset UtcNow()
    {
        return DateTimeOffset.UtcNow;
    }
}
