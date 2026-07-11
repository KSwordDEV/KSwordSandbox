using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the R0 driver core ABI exposes capability/status negotiation,
/// producer enable bits, queue counters, and a documented error contract.
/// Inputs are repository source/docs files; processing performs textual contract
/// checks; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class R0DriverCoreContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.driver-core.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var header = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "include",
            "KSwordSandboxDriverIoctl.h");
        var dispatch = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Device",
            "ControlDevice.c");
        var queue = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Eventing",
            "EventQueue.c");
        var abiGuards = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Common",
            "AbiGuards.c");
        var contract = ReadRepositoryText(context, "docs", "r0-driver-core.md");

        RequireContains(header, "KSWORD_SANDBOX_ABI_VERSION_MAJOR", "Header must expose ABI major version.");
        RequireContains(header, "KSWORD_SANDBOX_CAPABILITY_FLAGS_CURRENT", "Header must expose current capability flags.");
        RequireContains(header, "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES", "Header must define capabilities IOCTL.");
        RequireContains(header, "IOCTL_KSWORD_SANDBOX_GET_STATUS", "Header must define status IOCTL.");
        RequireContains(header, "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK", "Header must define producer enable-mask IOCTL.");
        RequireContains(header, "KSWORD_SANDBOX_CAPABILITIES_REPLY", "Header must define capabilities reply.");
        RequireContains(header, "KSWORD_SANDBOX_STATUS_REPLY", "Header must define status reply.");
        RequireContains(header, "KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST", "Header must define enable-mask request.");
        RequireContains(header, "KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS", "Header must expose process producer bit.");
        RequireContains(header, "KSWORD_SANDBOX_PRODUCER_FLAG_FILE", "Header must expose file producer bit.");
        RequireContains(header, "KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK", "Header must expose network producer bit.");
        RequireContains(header, "QueueCapacity", "Status reply must include queue capacity.");
        RequireContains(header, "TotalEventsSuppressed", "Status reply must include suppressed-event counter.");
        RequireContains(header, "KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE", "Health flags must advertise producer-mask fields.");
        RequireContains(header, "ProducerEnableMask", "Health/status replies must include producer enable mask.");
        RequireContains(header, "ActiveProducerMask", "Health/status replies must include active producer mask.");
        RequireContains(header, "FailedProducerMask", "Health/status replies must include failed producer mask.");

        RequireContains(dispatch, "case IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES", "Dispatch must route capabilities IOCTL.");
        RequireContains(dispatch, "case IOCTL_KSWORD_SANDBOX_GET_STATUS", "Dispatch must route status IOCTL.");
        RequireContains(dispatch, "case IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK", "Dispatch must route enable-mask IOCTL.");
        RequireContains(dispatch, "KswHandleSetProducerEnableMask", "Enable-mask handler must be implemented.");
        RequireContains(dispatch, "STATUS_INVALID_PARAMETER", "Dispatch must reject malformed requests.");
        RequireContains(dispatch, "KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE", "GET_HEALTH flags must expose producer-mask availability.");
        RequireContains(dispatch, "reply->ProducerEnableMask = snapshot.ProducerEnableMask", "GET_HEALTH must return producer enable mask.");
        RequireContains(dispatch, "reply->FailedProducerMask = snapshot.FailedProducerMask", "GET_HEALTH must return failed producer mask.");

        RequireContains(queue, "KswGetProducerMaskForEventType", "Queue must map event types to producer bits.");
        RequireContains(queue, "ProducerEnableMask", "Queue must gate events by producer enable mask.");
        RequireContains(queue, "EventsSuppressed", "Queue must count suppressed producer events.");
        RequireContains(queue, "QueueHighWatermark", "Queue must track queue high watermark.");

        RequireContains(abiGuards, "sizeof(KSWORD_SANDBOX_HEALTH_REPLY) == 80U", "ABI guards must pin GET_HEALTH reply size.");
        RequireContains(abiGuards, "FIELD_OFFSET(KSWORD_SANDBOX_HEALTH_REPLY, ProducerEnableMask)", "ABI guards must pin health producer-mask offsets.");

        RequireContains(contract, "Capability negotiation flow", "Core contract doc must describe negotiation flow.");
        RequireContains(contract, "Producer enable mask", "Core contract doc must describe producer enable mask.");
        RequireContains(contract, "GET_HEALTH producer-mask snapshot", "Core contract doc must describe health producer-mask diagnostics.");
        RequireContains(contract, "Queue and status counters", "Core contract doc must describe queue/status counters.");
        RequireContains(contract, "IOCTL error contract", "Core contract doc must describe IOCTL errors.");
        RequireContains(contract, "STATUS_INVALID_DEVICE_REQUEST", "Core contract doc must document unknown/new IOCTL fallback.");
        RequireContains(contract, "STATUS_BUFFER_TOO_SMALL", "Core contract doc must document size failures.");
        RequireContains(contract, "STATUS_INVALID_PARAMETER", "Core contract doc must document request validation failures.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 core IOCTL ABI, producer mask, queue status, and docs contract are present."
        });
    }

    /// <summary>
    /// Reads a repository file by path segment.
    /// Inputs are context and path segments; processing combines them under the
    /// repository root; return value is file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] segments)
    {
        var allSegments = new string[segments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        Array.Copy(segments, 0, allSegments, 1, segments.Length);
        var path = Path.Combine(allSegments);
        SmokeAssert.True(File.Exists(path), $"Required R0 core contract file is missing: {path}");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires a text fragment to be present.
    /// Inputs are content, expected text, and failure message; processing throws
    /// on absence; return value is none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
