using KSword.Sandbox.Web.Contracts;
using Microsoft.AspNetCore.Http;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Inputs: endpoint validation failures, missing-resource messages, or caught exceptions.
/// Processing: converts common Web errors into consistent ASP.NET Core IResult instances.
/// Return behavior: returns result objects that endpoint modules can return directly.
/// </summary>
internal static class WebProblemResultFactory
{
    /// <summary>
    /// Inputs: a stable error code, message, and optional validation details.
    /// Processing: creates a failed API envelope and wraps it in a 400 result.
    /// Return behavior: returns an IResult that serializes a bad-request payload.
    /// </summary>
    internal static IResult BadRequest(
        string code,
        string message,
        IReadOnlyDictionary<string, string[]>? details = null)
    {
        var error = new ApiErrorContract(code, message, details);
        var envelope = ApiEnvelopeContract<object>.Failure(error, DateTimeOffset.UtcNow);
        return Results.BadRequest(envelope);
    }

    /// <summary>
    /// Inputs: a stable error code and missing-resource message.
    /// Processing: creates a failed API envelope and wraps it in a 404 result.
    /// Return behavior: returns an IResult that serializes a not-found payload.
    /// </summary>
    internal static IResult NotFound(string code, string message)
    {
        var error = new ApiErrorContract(code, message);
        var envelope = ApiEnvelopeContract<object>.Failure(error, DateTimeOffset.UtcNow);
        return Results.NotFound(envelope);
    }

    /// <summary>
    /// Inputs: an exception, caller-facing title, and HTTP status code.
    /// Processing: maps exception text into ASP.NET Core ProblemDetails without exposing stack traces.
    /// Return behavior: returns an IResult that serializes a problem response.
    /// </summary>
    internal static IResult FromException(Exception exception, string title, int statusCode)
    {
        return Results.Problem(title: title, detail: exception.Message, statusCode: statusCode);
    }
}
