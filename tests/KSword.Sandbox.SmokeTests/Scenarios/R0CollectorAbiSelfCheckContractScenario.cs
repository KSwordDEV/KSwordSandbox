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
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
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
            "capabilityFlagsCurrentHex",
            "producerMaskCurrentHex",
            "producerMaskDefaultHex",
            "eventHeaderSize",
            "healthReplySize",
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
            "kernelBackpressurePolicy",
            "queueLossEvidence",
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
            "kernelBackpressurePolicy",
            "queueLossEvidence",
            "does not open",
            "DeviceIoControl"
        })
        {
            RequireContains(collectorDoc, expected, $"r0-collector.md should document {expected} for ABI self-check mode.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0Collector no-device ABI self-check contract is covered by source/docs smoke checks."
        });
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
}
