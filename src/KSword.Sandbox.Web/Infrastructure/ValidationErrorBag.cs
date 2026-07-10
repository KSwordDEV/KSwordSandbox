using KSword.Sandbox.Web.Contracts;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: field names and validation messages accumulated by endpoint validators.
/// Processing: groups messages by field with case-insensitive field keys.
/// Return behavior: exposes structured API errors for bad-request responses.
/// </summary>
internal sealed class ValidationErrorBag
{
    private readonly Dictionary<string, List<string>> _errors = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets whether the bag currently contains no validation messages.
    /// </summary>
    internal bool IsEmpty => _errors.Count == 0;

    /// <summary>
    /// Inputs: a field name and a validation message.
    /// Processing: normalizes blank field names to "request" and appends the message to that field bucket.
    /// Return behavior: returns the same bag to support fluent validation code.
    /// </summary>
    internal ValidationErrorBag Add(string field, string message)
    {
        var normalizedField = string.IsNullOrWhiteSpace(field) ? "request" : field.Trim();
        if (!_errors.TryGetValue(normalizedField, out var messages))
        {
            messages = new List<string>();
            _errors.Add(normalizedField, messages);
        }

        messages.Add(message);
        return this;
    }

    /// <summary>
    /// Inputs: a stable error code and caller-facing message.
    /// Processing: materializes grouped validation messages into string arrays.
    /// Return behavior: returns an ApiErrorContract that can be embedded in an API envelope.
    /// </summary>
    internal ApiErrorContract ToApiError(string code, string message)
    {
        var details = _errors.ToDictionary(
            pair => pair.Key,
            pair => pair.Value.ToArray(),
            StringComparer.OrdinalIgnoreCase);

        return new ApiErrorContract(code, message, details);
    }
}
