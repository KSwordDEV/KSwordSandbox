namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: guest import lifecycle status, copyable source path, and
/// operator-facing detail text.
/// Processing: separates imported, waiting, failed, and unavailable states from
/// free-form job messages so the WebUI can render a clear status badge.
/// Return behavior: instances are serialized as guest import status payloads.
/// </summary>
/// <param name="State">Machine-readable state such as waiting, imported, failed, or unavailable.</param>
/// <param name="Message">Human-readable import status detail.</param>
/// <param name="SourcePath">Recorded events.json or JSONL source path when import has happened.</param>
/// <param name="ImportedEventCount">Imported event count when known.</param>
public sealed record GuestImportStatusContract(
    string State,
    string Message,
    string? SourcePath,
    int? ImportedEventCount);
