namespace KSword.Sandbox.Web.Contracts;

/// <summary>
/// Inputs: a Web-facing artifact descriptor selected from artifact-index.json.
/// Processing: carries only relative selector, sanitized download-name, and
/// localized rejection metadata for the guarded artifact download API.
/// Return behavior: serialized by artifact index/download clients without
/// exposing host-local absolute paths.
/// </summary>
/// <param name="Available">True when the indexed host file can be streamed.</param>
/// <param name="Selector">Relative selector accepted by the download endpoint.</param>
/// <param name="Href">Guarded download endpoint href using the selector.</param>
/// <param name="FileName">Sanitized Content-Disposition filename.</param>
/// <param name="ContentType">Resolved response content type.</param>
/// <param name="SizeBytes">Indexed artifact size when known.</param>
/// <param name="Sha256">Indexed artifact SHA-256 when known.</param>
/// <param name="RejectionCode">Stable unavailable/rejection code.</param>
/// <param name="RejectionMessage">English unavailable/rejection message.</param>
/// <param name="RejectionMessageZh">Chinese unavailable/rejection hint.</param>
public sealed record JobArtifactDownloadContract(
    bool Available,
    string Selector,
    string Href,
    string FileName,
    string ContentType,
    long SizeBytes,
    string Sha256,
    string RejectionCode,
    string RejectionMessage,
    string RejectionMessageZh);
