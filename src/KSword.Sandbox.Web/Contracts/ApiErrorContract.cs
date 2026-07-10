namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: a stable error code, a caller-facing message, and optional field details.
/// Processing: carries structured error data without coupling endpoint code to anonymous objects.
/// Return behavior: instances are serialized directly as API error payloads.
/// </summary>
/// <param name="Code">Stable machine-readable error code supplied by endpoint code.</param>
/// <param name="Message">Human-readable summary supplied by endpoint code.</param>
/// <param name="Details">Optional per-field validation details supplied by validators.</param>
public sealed record ApiErrorContract(
    string Code,
    string Message,
    IReadOnlyDictionary<string, string[]>? Details = null)
{
    /// <summary>
    /// Inputs: the current contract instance.
    /// Processing: checks whether validation details are present and non-empty.
    /// Return behavior: returns true when callers can render field-level details; otherwise false.
    /// </summary>
    public bool HasDetails()
    {
        return Details is { Count: > 0 };
    }
}
