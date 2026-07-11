using KSword.Sandbox.Abstractions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that the no-device R0Collector ABI self-check contract remains
/// available for CI/operator smoke checks. Inputs are repository source/docs;
/// processing performs static contract checks only; the scenario returns
/// pass/fail metadata and never loads the kernel driver.
/// </summary>
internal sealed class R0CollectorAbiSelfCheckContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.collector.abi-self-check.contract";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var collectorRoot = Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.R0Collector");
        var sourceRoot = Path.Combine(collectorRoot, "src");
        var project = ReadText(Path.Combine(collectorRoot, "KSword.Sandbox.R0Collector.vcxproj"));
        var filters = ReadText(Path.Combine(collectorRoot, "KSword.Sandbox.R0Collector.vcxproj.filters"));
        var optionsHeader = ReadText(Path.Combine(sourceRoot, "Options.h"));
        var optionsSource = ReadText(Path.Combine(sourceRoot, "Options.cpp"));
        var runtimeLoop = ReadText(Path.Combine(sourceRoot, "RuntimeLoop.cpp"));
        var abiSelfCheck = ReadText(Path.Combine(sourceRoot, "AbiSelfCheck.cpp"));
        var collectorDoc = ReadText(Path.Combine(context.RepositoryRoot, "docs", "r0-collector.md"));

        RequireContains(project, @"src\AbiSelfCheck.cpp", "AbiSelfCheck.cpp should be compiled by the native collector project.");
        RequireContains(project, @"src\AbiSelfCheck.h", "AbiSelfCheck.h should be included by the native collector project.");
        RequireContains(filters, @"src\AbiSelfCheck.cpp", "AbiSelfCheck.cpp should appear in Visual Studio filters.");
        RequireContains(filters, @"src\AbiSelfCheck.h", "AbiSelfCheck.h should appear in Visual Studio filters.");

        RequireContains(optionsHeader, "abiSelfCheck", "Options should carry the ABI self-check mode flag.");
        RequireContains(optionsSource, "--abi-self-check", "CLI should parse --abi-self-check.");
        RequireContains(optionsSource, "--contract-self-check", "CLI should parse --contract-self-check alias.");
        RequireContains(optionsSource, "Emit ABI/event-quality contract row and exit without opening the driver", "Usage text should make no-device behavior explicit.");

        var abiSelfCheckBranch = runtimeLoop.IndexOf("if (options.abiSelfCheck)", StringComparison.Ordinal);
        var mockBranch = runtimeLoop.IndexOf("if (options.mockMode)", StringComparison.Ordinal);
        var openDevice = runtimeLoop.IndexOf("OpenDriverDevice", StringComparison.Ordinal);
        SmokeAssert.True(abiSelfCheckBranch >= 0, "RuntimeLoop should branch on options.abiSelfCheck.");
        SmokeAssert.True(mockBranch > abiSelfCheckBranch, "ABI self-check should run before mock mode to produce deterministic contract rows.");
        SmokeAssert.True(openDevice > abiSelfCheckBranch, "ABI self-check should run before OpenDriverDevice.");
        RequireContains(runtimeLoop, "RunAbiSelfCheckMode(options, writer)", "RuntimeLoop should delegate ABI self-check output to AbiSelfCheck.cpp.");

        foreach (var expected in new[]
        {
            "r0collector.abiSelfCheck",
            "selfCheckPassed",
            "opensDriverDevice",
            "ioctlIssued",
            "collectorAbiVersion",
            "collectorAbiVersionHex",
            "abiVersionMajor",
            "abiVersionMinor",
            "eventHeaderVersion",
            "eventSchemaName",
            "eventSchemaVersion",
            "stableAbiVersionFields",
            "schema",
            "producer",
            "noise",
            "collectorNoise",
            "collectorSelfNoise",
            "selfProcess",
            "collectorNoiseReason",
            "collectorNoiseAction",
            "collectorSuppressed",
            "lost",
            "lostCount",
            "lossObserved",
            "backpressure",
            "backpressureObserved",
            "highWatermark",
            "capabilityFlagsCurrentHex",
            "producerMaskCurrentHex",
            "producerMaskDefaultHex",
            "abiGuardPassed",
            "abiGuardPolicy",
            "zhAbiGuardPolicy",
            "eventHeaderSize",
            "eventHeaderSequenceOffset",
            "eventHeaderLostEventsOffset",
            "eventHeaderBackpressureEventsOffset",
            "eventHeaderOperationOffset",
            "eventHeaderStatusOffset",
            "eventHeaderProducerMetadataFlagsOffset",
            "statusQueueHighWatermarkOffset",
            "statusTotalEventsDroppedOffset",
            "statusTotalEventsBackpressuredOffset",
            "statusLastEnqueueFailureOffset",
            "readEventsEventsDroppedOffset",
            "readEventsEventsOffset",
            "networkStatusReplySize",
            "networkStatusTodoMaskOffset",
            "networkStatusPayloadVersionOffset",
            "networkStatusLastDegradeReasonOffset",
            "networkStatusClassifyCountOffset",
            "networkStatusEventCountOffset",
            "networkStatusQueueFailureCountOffset",
            "networkStatusLastQueueFailureOffset",
            "networkStatusIoctlPolicy",
            "healthReplySize",
            "healthReplyLegacyMinimumBytes",
            "healthReplyProducerMaskBytes",
            "healthProducerMasksAvailableFlag",
            "healthProducerMasksAvailableFlagHex",
            "healthProducerMasksCompatibilityPolicy",
            "capabilitiesReplySize",
            "statusReplySize",
            "readEventsRequestSize",
            "readEventsReplyHeaderSize",
            "eventMaxPayloadSize",
            "readEventsBufferBytes",
            "requestedMaxEvents",
            "maxEventsBounds",
            "maxReadBatches",
            "readEventsRequestFlagsPolicy",
            "producerSelectionPolicy",
            "jsonlNoisePolicy",
            "jsonlMalformedPolicy",
            "jsonlNoiseInjectionGuard",
            "zhJsonlNoiseInjectionGuard",
            "kernelBackpressurePolicy",
            "sequenceSemantics",
            "zhSequenceSemantics",
            "driverEventSequenceMeaning",
            "driverEventSequenceScope",
            "driverEventSequencePolicy",
            "zhDriverEventSequencePolicy",
            "networkServiceHintPolicy",
            "networkFlowKeyPolicy",
            "networkCorrelationPolicy",
            "networkCorrelationStableFields",
            "pcapCorrelationJoinFieldsPolicy",
            "selfNoiseClassificationFields",
            "selfNoiseFilterPolicy",
            "selfNoiseFilterFields",
            "typedPayloadSemanticFields",
            "stressBackpressureDiagnostics",
            "queueLossEvidence",
            "stableJsonlFields",
            "semanticStressCountPreservationPolicy",
            "noiseClassificationFieldSet",
            "noiseTaxonomyVersion",
            "noiseDecision",
            "zhNoiseClassificationHint",
            "abiSelfCheckComplete"
        })
        {
            RequireContains(abiSelfCheck, expected, $"ABI self-check source should emit {expected} evidence.");
        }

        foreach (var expected in new[]
        {
            "--abi-self-check",
            "--contract-self-check",
            "r0collector.abiSelfCheck",
            "collectorAbiVersion",
            "capabilityFlagsCurrentHex",
            "producerMaskCurrentHex",
            "jsonlNoisePolicy",
            "jsonlMalformedPolicy",
            "kernelBackpressurePolicy",
            "queueLossEvidence",
            "stableJsonlFields",
            "does not open",
            "DeviceIoControl"
        })
        {
            RequireContains(collectorDoc, expected, $"r0-collector.md should document {expected} for ABI self-check mode.");
        }

        await AssertExecutableAbiSelfCheckGoldenAsync(context, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0Collector no-device ABI self-check contract is covered by source/docs plus executable golden smoke or explicit host-policy block evidence."
        };
    }

    /// <summary>
    /// Builds and runs the collector no-device ABI self-check. Inputs are the
    /// smoke context and cancellation token; processing writes build/output
    /// artifacts only under D:\Temp\KSwordSandbox\verify; return value is none.
    /// </summary>
    private static async Task AssertExecutableAbiSelfCheckGoldenAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken)
    {
        var build = await R0CollectorExecutableSmokeHelper.BuildCollectorAsync(context, cancellationToken);
        var outputPath = R0CollectorExecutableSmokeHelper.CreateRunOutputPath(build, "r0collector-abi-self-check.jsonl");
        var result = await R0CollectorExecutableSmokeHelper.RunCollectorAsync(
            build.ExecutablePath,
            [
                "--abi-self-check",
                "--heartbeat",
                "--max-events",
                "16",
                "--max-read-batches",
                "4",
                "--enable-mask",
                "0x3f",
                "--out",
                outputPath
            ],
            context.RepositoryRoot,
            cancellationToken);
        if (R0CollectorExecutableSmokeHelper.IsExecutionBlockedByHostPolicy(result))
        {
            SmokeAssert.True(
                result.CombinedOutput.Contains("Execution blocked by host policy", StringComparison.Ordinal),
                "Blocked executable ABI smoke should report explicit host-policy evidence.");
            return;
        }

        SmokeAssert.True(result.ExitCode == 0, $"collector --abi-self-check should exit 0. Output: {result.CombinedOutput}");

        var jsonLines = R0CollectorExecutableSmokeHelper.ReadJsonLines(outputPath);
        SmokeAssert.True(jsonLines.BlankLineCount == 0, "ABI self-check output should not contain blank JSONL noise.");
        SmokeAssert.True(jsonLines.MalformedLines.Count == 0, "ABI self-check output should not contain malformed JSONL rows.");

        var started = RequireEvent(jsonLines.Events, "r0collector.started");
        RequireData(started, "abiSelfCheck", "true");
        RequireData(started, "readEventsMaxEvents", "16");
        RequireData(started, "maxReadBatches", "4");
        RequireData(started, "enableMaskHex", "0x0000003F");

        var abiSelfCheck = RequireEvent(jsonLines.Events, "r0collector.abiSelfCheck");
        RequireData(abiSelfCheck, "selfCheckPassed", "true");
        RequireData(abiSelfCheck, "opensDriverDevice", "false");
        RequireData(abiSelfCheck, "ioctlIssued", "false");
        RequireData(abiSelfCheck, "collectorAbiVersion", "65536");
        RequireData(abiSelfCheck, "collectorAbiVersionHex", "0x00010000");
        RequireData(abiSelfCheck, "abiVersionMajor", "1");
        RequireData(abiSelfCheck, "abiVersionMinor", "0");
        RequireData(abiSelfCheck, "eventHeaderVersion", "65536");
        RequireData(abiSelfCheck, "eventSchemaName", "ksword.sandbox.r0.event");
        RequireData(abiSelfCheck, "eventSchemaVersion", "65536");
        RequireContains(
            abiSelfCheck.Data["stableAbiVersionFields"],
            "collectorAbiVersion|collectorAbiVersionHex",
            "ABI self-check should publish stable ABI/version field names.");
        RequireData(abiSelfCheck, "collectorNoise", "false");
        RequireData(abiSelfCheck, "collectorSelfNoise", "false");
        RequireData(abiSelfCheck, "selfProcess", "false");
        RequireData(abiSelfCheck, "collectorNoiseReason", "none");
        RequireData(abiSelfCheck, "collectorSuppressed", "false");
        RequireData(abiSelfCheck, "lost", "false");
        RequireData(abiSelfCheck, "lostCount", "0");
        RequireData(abiSelfCheck, "lossObserved", "false");
        RequireData(abiSelfCheck, "backpressure", "false");
        RequireData(abiSelfCheck, "backpressureObserved", "false");
        RequireData(abiSelfCheck, "highWatermark", "0");
        RequireData(abiSelfCheck, "capabilityFlagsCurrentHex", "0x000000000007FFFF");
        RequireData(abiSelfCheck, "producerMaskCurrentHex", "0x0000003F");
        RequireData(abiSelfCheck, "producerMaskDefaultHex", "0x0000003F");
        RequireData(abiSelfCheck, "abiGuardPassed", "true");
        RequireData(abiSelfCheck, "eventHeaderSize", "104");
        RequireData(abiSelfCheck, "eventHeaderSequenceOffset", "16");
        RequireData(abiSelfCheck, "eventHeaderLostEventsOffset", "64");
        RequireData(abiSelfCheck, "eventHeaderBackpressureEventsOffset", "72");
        RequireData(abiSelfCheck, "eventHeaderOperationOffset", "80");
        RequireData(abiSelfCheck, "eventHeaderStatusOffset", "84");
        RequireData(abiSelfCheck, "eventHeaderProducerMetadataFlagsOffset", "92");
        RequireData(abiSelfCheck, "statusQueueHighWatermarkOffset", "24");
        RequireData(abiSelfCheck, "statusTotalEventsDroppedOffset", "56");
        RequireData(abiSelfCheck, "statusTotalEventsBackpressuredOffset", "88");
        RequireData(abiSelfCheck, "statusLastEnqueueFailureOffset", "112");
        RequireData(abiSelfCheck, "readEventsEventsDroppedOffset", "24");
        RequireData(abiSelfCheck, "readEventsEventsOffset", "40");
        RequireData(abiSelfCheck, "healthReplySize", "80");
        RequireData(abiSelfCheck, "healthReplyLegacyMinimumBytes", "44");
        RequireData(abiSelfCheck, "healthReplyProducerMaskBytes", "60");
        RequireData(abiSelfCheck, "healthProducerMasksAvailableFlag", "16");
        RequireData(abiSelfCheck, "healthProducerMasksAvailableFlagHex", "0x00000010");
        RequireData(abiSelfCheck, "capabilitiesReplySize", "104");
        RequireData(abiSelfCheck, "statusReplySize", "120");
        RequireData(abiSelfCheck, "readEventsReplyHeaderSize", "40");
        RequireData(abiSelfCheck, "networkStatusReplySize", "128");
        RequireData(abiSelfCheck, "networkStatusTodoMaskOffset", "32");
        RequireData(abiSelfCheck, "networkStatusPayloadVersionOffset", "36");
        RequireData(abiSelfCheck, "networkStatusLastDegradeReasonOffset", "40");
        RequireData(abiSelfCheck, "networkStatusClassifyCountOffset", "56");
        RequireData(abiSelfCheck, "networkStatusEventCountOffset", "64");
        RequireData(abiSelfCheck, "networkStatusQueueFailureCountOffset", "72");
        RequireData(abiSelfCheck, "networkStatusLastQueueFailureOffset", "92");
        RequireData(abiSelfCheck, "networkPayloadSize", "112");
        RequireData(abiSelfCheck, "requestedMaxEvents", "16");
        RequireData(abiSelfCheck, "maxReadBatches", "4");
        RequireData(abiSelfCheck, "readEventsRequestFlagsPolicy", "always-zero");
        RequireContains(
            abiSelfCheck.Data["capabilityFlagNames"],
            "EventSchemaNames",
            "ABI self-check should advertise event-schema-name support.");
        RequireContains(
            abiSelfCheck.Data["capabilityFlagNames"],
            "EventCommonMetadata",
            "ABI self-check should advertise common event metadata support.");
        RequireContains(
            abiSelfCheck.Data["capabilityFlagNames"],
            "SelfNoiseMetadata",
            "ABI self-check should advertise self-noise metadata support.");
        RequireContains(
            abiSelfCheck.Data["capabilityFlagNames"],
            "GetNetworkStatus",
            "ABI self-check should advertise network status diagnostics support.");
        RequireContains(
            abiSelfCheck.Data["producerMaskCurrentNames"],
            "network",
            "ABI self-check should advertise the network producer.");
        RequireContains(
            abiSelfCheck.Data["healthProducerMasksCompatibilityPolicy"],
            "legacy-sized replies",
            "ABI self-check should describe GET_HEALTH legacy compatibility.");
        RequireContains(
            abiSelfCheck.Data["jsonlNoisePolicy"],
            "malformed lines preserved",
            "ABI self-check should describe malformed JSONL preservation.");
        RequireContains(
            abiSelfCheck.Data["kernelBackpressurePolicy"],
            "nonblocking producers",
            "ABI self-check should describe non-blocking backpressure.");
        RequireContains(
            abiSelfCheck.Data["queueLossEvidence"],
            "sequenceGapObserved",
            "ABI self-check should name sequence-gap loss evidence.");
        RequireContains(
            abiSelfCheck.Data["sequenceSemantics"],
            "sequenceMeaning=nextSequence",
            "ABI self-check should explain sequence summary semantics.");
        RequireData(abiSelfCheck, "driverEventSequenceMeaning", "eventSequence");
        RequireData(abiSelfCheck, "driverEventSequenceScope", "driver-event");
        RequireContains(
            abiSelfCheck.Data["driverEventSequencePolicy"],
            "sequenceConcrete=true",
            "ABI self-check should explain concrete driver event sequence semantics.");
        RequireContains(
            abiSelfCheck.Data["networkServiceHintPolicy"],
            "53=dns",
            "ABI self-check should document DNS service-hint mapping.");
        RequireContains(
            abiSelfCheck.Data["networkServiceHintPolicy"],
            "443/8443=tls",
            "ABI self-check should document TLS service-hint mapping.");
        RequireContains(
            abiSelfCheck.Data["networkFlowKeyPolicy"],
            "flowKeyVersion=1",
            "ABI self-check should document flow-key version semantics.");
        RequireContains(
            abiSelfCheck.Data["networkCorrelationPolicy"],
            "join-candidate-not-l7-owner",
            "ABI self-check should document R0/PCAP ownership boundary.");
        RequireContains(
            abiSelfCheck.Data["networkCorrelationStableFields"],
            "pcapCorrelationJoinFields",
            "ABI self-check should list stable network correlation fields.");
        RequireContains(
            abiSelfCheck.Data["pcapCorrelationJoinFieldsPolicy"],
            "flowKey|sourceEndpoint|destinationEndpoint",
            "ABI self-check should document stable PCAP join fields.");
        RequireContains(
            abiSelfCheck.Data["selfNoiseClassificationFields"],
            "noiseClass",
            "ABI self-check should list self-noise classification fields.");
        RequireContains(
            abiSelfCheck.Data["selfNoiseClassificationFields"],
            "noiseDecision",
            "ABI self-check should list noise decision fields.");
        RequireContains(
            abiSelfCheck.Data["selfNoiseFilterPolicy"],
            "synthetic/no-device rows use kSyntheticSampleProcessId",
            "ABI self-check should document synthetic/no-device self-noise filtering.");
        RequireContains(
            abiSelfCheck.Data["selfNoiseFilterFields"],
            "selfNoiseFilterMatched",
            "ABI self-check should list stable self-noise filter evidence fields.");
        RequireData(abiSelfCheck, "noiseTaxonomyVersion", "1");
        RequireData(abiSelfCheck, "noiseDecision", "collector-diagnostic");
        RequireData(abiSelfCheck, "sampleBehaviorCandidateReason", "abi-self-check-is-collection-diagnostic");
        RequireContains(
            abiSelfCheck.Data["stressBackpressureDiagnostics"],
            "observedSequenceSpan",
            "ABI self-check should list stress/backpressure diagnostic fields.");
        RequireContains(
            abiSelfCheck.Data["semanticStressCountPreservationPolicy"],
            "semanticRowCountedInStress=false",
            "ABI self-check should preserve semantic companion/stress row-count separation.");
        RequireContains(
            abiSelfCheck.Data["jsonlNoiseInjectionGuard"],
            "rejected",
            "ABI self-check should document noise-injection guardrails.");

        var stopped = RequireEvent(jsonLines.Events, "r0collector.stopped");
        RequireData(stopped, "reason", "abiSelfCheckComplete");
        RequireData(stopped, "opensDriverDevice", "false");
        RequireData(stopped, "ioctlIssued", "false");

        SmokeAssert.True(
            jsonLines.Events.All(evt => !string.Equals(evt.EventType, "r0collector.deviceOpened", StringComparison.OrdinalIgnoreCase)),
            "ABI self-check golden smoke must not open the driver device.");
        SmokeAssert.True(
            jsonLines.Events.All(evt => !string.Equals(evt.EventType, "r0collector.driverHealth", StringComparison.OrdinalIgnoreCase)),
            "ABI self-check golden smoke must not issue driver health IOCTLs.");
    }

    /// <summary>
    /// Reads a required file. Inputs are path; processing asserts presence and
    /// returns text; return value is full file content.
    /// </summary>
    private static string ReadText(string path)
    {
        SmokeAssert.True(File.Exists(path), $"Required ABI self-check contract file is missing: {path}");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires a text fragment to be present. Inputs are content, fragment, and
    /// failure message; processing throws on absence; return value is none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }

    /// <summary>
    /// Returns the first event with an expected type. Inputs are event list and
    /// type; processing searches case-insensitively; return value is the event.
    /// </summary>
    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Executable ABI self-check JSONL should contain {eventType}.");
        return evt!;
    }

    /// <summary>
    /// Requires one data value. Inputs are an event, key, and value; processing
    /// compares ordinally; return value is none.
    /// </summary>
    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(
            evt.Data.TryGetValue(key, out var actual) &&
            string.Equals(actual, expected, StringComparison.Ordinal),
            $"{evt.EventType} should contain data.{key}={expected}.");
    }
}
