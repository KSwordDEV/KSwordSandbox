using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the R0Collector source split, project membership, and operator
/// documentation stay aligned.
/// </summary>
internal sealed class R0CollectorContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.collector.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var collectorRoot = Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.R0Collector");
        var sourceRoot = Path.Combine(collectorRoot, "src");
        var project = ReadText(Path.Combine(collectorRoot, "KSword.Sandbox.R0Collector.vcxproj"));
        var filters = ReadText(Path.Combine(collectorRoot, "KSword.Sandbox.R0Collector.vcxproj.filters"));
        var collectorDoc = ReadText(Path.Combine(context.RepositoryRoot, "docs", "r0-collector.md"));
        var schemaDoc = ReadText(Path.Combine(context.RepositoryRoot, "docs", "r0-jsonl-schema.md"));

        foreach (var module in new[]
        {
            "AbiSelfCheck",
            "Options",
            "IoctlClient",
            "EventParser",
            "JsonWriter",
            "SyntheticMode",
            "RuntimeLoop"
        })
        {
            RequireFile(Path.Combine(sourceRoot, module + ".h"));
            RequireFile(Path.Combine(sourceRoot, module + ".cpp"));
            RequireContains(project, $"src\\{module}.cpp", $"{module}.cpp should be compiled by the native project.");
            RequireContains(project, $"src\\{module}.h", $"{module}.h should be included by the native project.");
            RequireContains(filters, $"src\\{module}.cpp", $"{module}.cpp should appear in Visual Studio filters.");
            RequireContains(filters, $"src\\{module}.h", $"{module}.h should appear in Visual Studio filters.");
            RequireContains(collectorDoc, module, $"{module} should be documented in the source layout.");
        }

        RequireContains(ReadText(Path.Combine(sourceRoot, "main.cpp")), "RunCollector", "main.cpp should remain a thin entry point.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--self-test", "self-test alias should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--synthetic", "synthetic alias should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--enable-mask", "enable-mask should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--max-events", "max-events should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--max-read-batches", "max-read-batches should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--heartbeat", "heartbeat should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--abi-self-check", "ABI self-check mode should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--contract-self-check", "contract self-check alias should be parsed.");
        var ioctlClient = ReadText(Path.Combine(sourceRoot, "IoctlClient.cpp"));
        var eventParser = ReadText(Path.Combine(sourceRoot, "EventParser.cpp"));
        var runtimeLoop = ReadText(Path.Combine(sourceRoot, "RuntimeLoop.cpp"));
        var abiSelfCheck = ReadText(Path.Combine(sourceRoot, "AbiSelfCheck.cpp"));
        RequireContains(runtimeLoop, "RunAbiSelfCheckMode", "Runtime loop should support no-device ABI self-check mode.");
        RequireContains(abiSelfCheck, "r0collector.abiSelfCheck", "ABI self-check should emit a dedicated JSONL row.");
        RequireContains(abiSelfCheck, "collectorAbiVersion", "ABI self-check should preserve collector ABI version.");
        RequireContains(abiSelfCheck, "capabilityFlagsCurrentHex", "ABI self-check should preserve capability flags.");
        RequireContains(abiSelfCheck, "producerMaskCurrentHex", "ABI self-check should preserve producer mask.");
        RequireContains(abiSelfCheck, "jsonlNoisePolicy", "ABI self-check should describe JSONL noise policy.");
        RequireContains(abiSelfCheck, "jsonlMalformedPolicy", "ABI self-check should describe malformed JSONL policy.");
        RequireContains(abiSelfCheck, "kernelBackpressurePolicy", "ABI self-check should describe kernel backpressure policy.");
        RequireContains(abiSelfCheck, "stableJsonlFields", "ABI self-check should name stable JSONL event-quality fields.");
        RequireContains(ioctlClient, "EmitDriverCapabilities", "R0Collector should negotiate capabilities.");
        RequireContains(ioctlClient, "EmitDriverStatus", "R0Collector should emit status snapshots.");
        RequireContains(ioctlClient, "EmitDriverSetProducerEnableMask", "R0Collector should support producer-mask IOCTL negotiation.");
        RequireContains(ioctlClient, "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES", "R0Collector should issue capabilities IOCTL.");
        RequireContains(ioctlClient, "IOCTL_KSWORD_SANDBOX_GET_STATUS", "R0Collector should issue status IOCTL.");
        RequireContains(ioctlClient, "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK", "R0Collector should issue producer-mask IOCTL.");
        RequireContains(ioctlClient, "request->EnableMask = options.enableMask", "enable-mask should flow to SET_PRODUCER_ENABLE_MASK request.");
        RequireContains(ioctlClient, "request->Flags = 0", "producer-mask request reserved flags should be zero.");
        RequireContains(ioctlClient, "r0collector.driverCapabilities", "R0Collector should emit capabilities JSONL rows.");
        RequireContains(ioctlClient, "r0collector.driverStatus", "R0Collector should emit status JSONL rows.");
        RequireContains(ioctlClient, "r0collector.driverProducerMask", "R0Collector should emit producer-mask JSONL rows.");
        RequireContains(eventParser, "capabilityFlagsHex", "Capabilities row should preserve capability flags.");
        RequireContains(eventParser, "supportedProducerMaskHex", "Capabilities/status rows should preserve supported producer mask.");
        RequireContains(eventParser, "queueCapacity", "Status row should preserve queue capacity.");
        RequireContains(eventParser, "queueDepth", "Status row should preserve queue depth.");
        RequireContains(eventParser, "producerEnableMaskHex", "Status row should preserve producer enable mask.");
        RequireContains(eventParser, "activeProducerMaskHex", "Status row should preserve active producer mask.");
        RequireContains(eventParser, "failedProducerMaskHex", "Status row should preserve failed producer mask.");
        RequireContains(eventParser, "totalEventsSuppressed", "Status row should preserve suppressed event counter.");
        RequireContains(eventParser, "requestedEnableMaskHex", "Producer-mask row should preserve requested mask.");
        RequireContains(eventParser, "effectiveEnableMaskHex", "Producer-mask row should preserve effective mask.");
        RequireContains(eventParser, "producer", "Event parser rows should preserve stable producer metadata.");
        RequireContains(eventParser, "schema", "Event parser rows should preserve stable schema metadata.");
        RequireContains(eventParser, "lost", "Event parser rows should preserve stable loss metadata.");
        RequireContains(eventParser, "backpressure", "Event parser rows should preserve stable backpressure metadata.");
        RequireContains(eventParser, "noise", "Event parser rows should preserve stable noise metadata.");
        RequireContains(runtimeLoop, "EmitDriverCapabilities", "Runtime loop should call capabilities before drain.");
        RequireContains(runtimeLoop, "EmitDriverSetProducerEnableMask", "Runtime loop should apply requested producer mask before drain.");
        RequireContains(runtimeLoop, "EmitDriverStatus", "Runtime loop should capture status before/after drain.");
        RequireContains(runtimeLoop, "r0collector.heartbeat", "heartbeat rows should be emitted by the runtime loop.");

        foreach (var option in new[] { "--self-test", "--synthetic", "--enable-mask", "--max-events", "--max-read-batches", "--heartbeat", "--duration", "--poll-ms" })
        {
            RequireContains(collectorDoc, option, $"{option} should be documented in r0-collector.md.");
            RequireContains(schemaDoc, option, $"{option} should be documented in r0-jsonl-schema.md.");
        }

        RequireContains(collectorDoc, "batch limit", "r0-collector.md should describe the batch limit option.");
        RequireContains(collectorDoc, "requestedMaxEvents", "r0-collector.md should describe the requested max-events field.");
        RequireContains(collectorDoc, "drainStoppedAtBatchLimit", "r0-collector.md should describe the batch-limit exit field.");
        RequireContains(collectorDoc, "--abi-self-check", "r0-collector.md should describe the ABI self-check mode.");
        RequireContains(collectorDoc, "r0collector.abiSelfCheck", "r0-collector.md should document ABI self-check output.");
        RequireContains(collectorDoc, "JSONL quality and noise contract", "r0-collector.md should document stable JSONL quality fields.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0Collector split, CLI aliases, and JSONL docs are in sync."
        });
    }

    /// <summary>
    /// Reads a required text file. Inputs are path; processing asserts existence
    /// and reads the file; return value is file contents.
    /// </summary>
    private static string ReadText(string path)
    {
        SmokeAssert.True(File.Exists(path), $"Required R0Collector contract file is missing: {path}");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires a repository file to exist. Inputs are path; processing throws on
    /// absence; return value is none.
    /// </summary>
    private static void RequireFile(string path)
    {
        SmokeAssert.True(File.Exists(path), $"Required R0Collector module file is missing: {path}");
    }

    /// <summary>
    /// Requires a text fragment to be present. Inputs are content, expected text,
    /// and failure message; processing throws on absence; return value is none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
