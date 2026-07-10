namespace KSword.Sandbox.SmokeTests.Assertions;

/// <summary>
/// Provides lightweight assertions without adding a test framework dependency.
/// Inputs are boolean conditions and messages; processing throws on failure;
/// methods return no value when assertions pass.
/// </summary>
internal static class SmokeAssert
{
    /// <summary>
    /// Requires a condition to be true.
    /// Inputs are condition and message, processing throws InvalidOperationException
    /// on false, and the method returns no value on success.
    /// </summary>
    public static void True(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
