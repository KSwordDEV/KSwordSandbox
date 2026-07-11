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
        var processProducer = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Producers",
            "Process",
            "ProcessMonitor.c");
        var imageProducer = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Producers",
            "Image",
            "ImageMonitor.c");
        var registryProducer = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Producers",
            "Registry",
            "RegistryMonitor.c");
        var fileProducer = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Producers",
            "File",
            "FileFilter.c");
        var fileProducerHeader = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Producers",
            "File",
            "FileFilter.h");
        var networkProducer = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Producers",
            "Network",
            "NetworkMonitor.c");
        var networkProducerHeader = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "src",
            "Producers",
            "Network",
            "NetworkInternal.h");
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
        RequireContains(header, "TotalEventsBackpressured", "Status reply must include backpressure-event counter.");
        RequireContains(header, "ProducerDroppedMask", "Status reply must include producer dropped mask.");
        RequireContains(header, "ProducerSuppressedMask", "Status reply must include producer suppressed mask.");
        RequireContains(header, "ProducerBackpressureMask", "Status reply must include producer backpressure mask.");
        RequireContains(header, "KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE", "Status flags must expose queue backpressure.");
        RequireContains(header, "KSWORD_SANDBOX_STATUS_FLAG_EVENTS_DROPPED", "Status flags must expose dropped events.");
        RequireContains(header, "KSWORD_SANDBOX_STATUS_FLAG_EVENTS_SUPPRESSED", "Status flags must expose suppressed events.");
        RequireContains(header, "KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE", "Health flags must advertise producer-mask fields.");
        RequireContains(header, "KSWORD_SANDBOX_FILE_EVENT_VERSION", "Header must define file payload v1 version.");
        RequireContains(header, "KSWORD_SANDBOX_PROCESS_EVENT_VERSION", "Header must define process payload v1 version.");
        RequireContains(header, "KSWORD_SANDBOX_IMAGE_EVENT_VERSION", "Header must define image payload v1 version.");
        RequireContains(header, "KSWORD_SANDBOX_REGISTRY_EVENT_VERSION", "Header must define registry payload v1 version.");
        RequireContains(header, "KSWORD_SANDBOX_NETWORK_EVENT_VERSION", "Header must define network payload v1 version.");
        RequireContains(header, "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD", "Header must define file typed payload.");
        RequireContains(header, "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD", "Header must define process typed payload.");
        RequireContains(header, "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD", "Header must define image typed payload.");
        RequireContains(header, "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD", "Header must define registry typed payload.");
        RequireContains(header, "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD", "Header must define network typed payload.");
        RequireContains(header, "Version must equal KSWORD_SANDBOX_FILE_EVENT_VERSION", "File payload comment must pin v1 Version.");
        RequireContains(header, "Version must equal KSWORD_SANDBOX_NETWORK_EVENT_VERSION", "Network payload comment must pin v1 Version.");
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
        RequireContains(dispatch, "reply->TotalEventsBackpressured = snapshot.EventsBackpressured", "GET_STATUS must return backpressure counter.");
        RequireContains(dispatch, "reply->ProducerDroppedMask = snapshot.ProducerDroppedMask", "GET_STATUS must return producer dropped mask.");
        RequireContains(dispatch, "KSWORD_SANDBOX_STATUS_FLAG_QUEUE_BACKPRESSURE", "GET_STATUS flags must classify backpressure.");

        RequireContains(queue, "KswGetProducerMaskForEventType", "Queue must map event types to producer bits.");
        RequireContains(queue, "ProducerEnableMask", "Queue must gate events by producer enable mask.");
        RequireContains(queue, "EventsSuppressed", "Queue must count suppressed producer events.");
        RequireContains(queue, "QueueHighWatermark", "Queue must track queue high watermark.");
        RequireContains(queue, "ProducerDroppedMask", "Queue must record producer families that dropped events.");
        RequireContains(queue, "ProducerSuppressedMask", "Queue must record producer families suppressed by the enable mask.");
        RequireContains(queue, "ProducerBackpressureMask", "Queue must record producer families seen under backpressure.");

        RequireContains(processProducer, "KSWORD_SANDBOX_PROCESS_MONITOR_RUNTIME", "Process producer must keep structured runtime state.");
        RequireContains(processProducer, "KswProcessPayloadVersion", "Process producer must stamp v1 payload version through a guarded helper.");
        RequireContains(processProducer, "Uninitializing", "Process producer must guard teardown.");
        RequireContains(imageProducer, "KSWORD_SANDBOX_IMAGE_MONITOR_RUNTIME", "Image producer must keep structured runtime state.");
        RequireContains(imageProducer, "KswImagePayloadVersion", "Image producer must stamp v1 payload version through a guarded helper.");
        RequireContains(imageProducer, "Uninitializing", "Image producer must guard teardown.");
        RequireContains(registryProducer, "KSWORD_SANDBOX_REGISTRY_MONITOR_RUNTIME", "Registry producer must keep structured runtime state.");
        RequireContains(registryProducer, "KswRegistryPayloadVersion", "Registry producer must stamp v1 payload version through a guarded helper.");
        RequireContains(registryProducer, "Argument1 == NULL", "Registry callback must defensively guard missing notify-class input.");
        RequireContains(fileProducerHeader, "KSWORD_SANDBOX_FILE_FILTER_RUNTIME", "File producer must keep structured runtime state.");
        RequireContains(fileProducerHeader, "PayloadVersion", "File runtime must store payload version state.");
        RequireContains(fileProducer, "KswFilePayloadVersion", "File producer must stamp v1 payload version through a guarded helper.");
        RequireContains(fileProducer, "DeviceExtension->Signature", "File producer init must validate device-extension signature.");
        RequireContains(networkProducerHeader, "KSWORD_SANDBOX_NETWORK_WFP_RUNTIME", "Network producer must keep structured runtime state.");
        RequireContains(networkProducerHeader, "PayloadVersion", "Network runtime must store payload version state.");
        RequireContains(networkProducer, "KswNetworkPayloadVersion", "Network producer must stamp v1 payload version through a guarded helper.");
        RequireContains(networkProducer, "Uninitializing", "Network producer must guard teardown.");

        RequireContains(abiGuards, "sizeof(KSWORD_SANDBOX_HEALTH_REPLY) == 80U", "ABI guards must pin GET_HEALTH reply size.");
        RequireContains(abiGuards, "FIELD_OFFSET(KSWORD_SANDBOX_HEALTH_REPLY, ProducerEnableMask)", "ABI guards must pin health producer-mask offsets.");
        RequireContains(abiGuards, "sizeof(KSWORD_SANDBOX_FILE_EVENT_PAYLOAD) == 128U", "ABI guards must pin file payload size.");
        RequireContains(abiGuards, "sizeof(KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD) == 128U", "ABI guards must pin process payload size.");
        RequireContains(abiGuards, "sizeof(KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD) == 128U", "ABI guards must pin image payload size.");
        RequireContains(abiGuards, "sizeof(KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD) == 128U", "ABI guards must pin registry payload size.");
        RequireContains(abiGuards, "sizeof(KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD) == 112U", "ABI guards must pin network payload size.");

        RequireContains(contract, "Capability negotiation flow", "Core contract doc must describe negotiation flow.");
        RequireContains(contract, "Producer enable mask", "Core contract doc must describe producer enable mask.");
        RequireContains(contract, "GET_HEALTH producer-mask snapshot", "Core contract doc must describe health producer-mask diagnostics.");
        RequireContains(contract, "Queue and status counters", "Core contract doc must describe queue/status counters.");
        RequireContains(contract, "Producer runtime state and payload versions", "Core contract doc must describe producer runtime state and payload versions.");
        RequireContains(contract, "V1 typed payload checklist", "Core contract doc must include v1 typed payload checklist.");
        RequireContains(contract, "KSWORD_SANDBOX_NETWORK_EVENT_VERSION", "Core contract doc must name network payload version.");
        RequireContains(contract, "IOCTL error contract", "Core contract doc must describe IOCTL errors.");
        RequireContains(contract, "STATUS_INVALID_DEVICE_REQUEST", "Core contract doc must document unknown/new IOCTL fallback.");
        RequireContains(contract, "STATUS_BUFFER_TOO_SMALL", "Core contract doc must document size failures.");
        RequireContains(contract, "STATUS_INVALID_PARAMETER", "Core contract doc must document request validation failures.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 core IOCTL ABI, producer mask, queue status, producer runtime state, payload versions, and docs contract are present."
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
