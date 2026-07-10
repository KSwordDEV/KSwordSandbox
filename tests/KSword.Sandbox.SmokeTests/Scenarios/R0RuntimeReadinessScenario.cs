using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that R0 runtime validation remains explicitly gated before live VM
/// driver loading. Inputs are repository files; processing inspects docs and the
/// readiness script only; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class R0RuntimeReadinessScenario : ISmokeTestScenario
{
    public string ScenarioId => "r0.runtime-readiness.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var script = ReadRepositoryText(context, "scripts", "Test-R0Readiness.ps1");
        var signingDoc = ReadRepositoryText(context, "docs", "driver-signing.md");
        var collectorDoc = ReadRepositoryText(context, "docs", "r0-collector.md");
        var networkDoc = ReadRepositoryText(context, "docs", "r0-network.md");
        var driverReadme = ReadRepositoryText(context, "driver", "KSword.Sandbox.Driver", "README.md");

        RequireContains(script, "Default mode", "Readiness script should document default safe behavior.");
        RequireContains(script, "AllowServiceMutation", "Service mutations must require an explicit gate.");
        RequireContains(script, "InstallService", "Readiness script should expose explicit install operation.");
        RequireContains(script, "StartService", "Readiness script should expose explicit start operation.");
        RequireContains(script, "StopService", "Readiness script should expose explicit stop operation.");
        RequireContains(script, "DeleteService", "Readiness script should expose explicit delete operation.");
        RequireContains(script, "CheckDeviceHealth", "Device health IOCTL must be opt-in.");
        RequireContains(script, "DrainWithCollector", "R0Collector drain must be opt-in.");
        RequireContains(script, "IOCTL_KSWORD_SANDBOX_GET_HEALTH", "Script should name the health IOCTL it probes.");
        RequireContains(script, "R0 capability/status IOCTL static contract", "Script should statically check negotiated R0 IOCTL readiness.");
        RequireContains(script, "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES", "Script should statically check capabilities IOCTL wiring.");
        RequireContains(script, "IOCTL_KSWORD_SANDBOX_GET_STATUS", "Script should statically check status IOCTL wiring.");
        RequireContains(script, "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK", "Script should statically check producer-mask IOCTL wiring.");
        RequireContains(script, "r0collector.driverCapabilities", "Script should validate collector capabilities rows in drain output.");
        RequireContains(script, "r0collector.driverStatus", "Script should validate collector status rows in drain output.");
        RequireContains(script, "r0collector.driverProducerMask", "Script should document producer-mask row coverage.");
        RequireContains(script, "DefaultModeSafe", "Script summary should identify default safe mode.");

        RequireContains(signingDoc, "bcdedit /set testsigning on", "Signing doc should describe test-signing enablement.");
        RequireContains(signingDoc, "sc.exe create", "Signing doc should document raw service install fallback.");
        RequireContains(signingDoc, "sc.exe stop", "Signing doc should document raw service unload fallback.");
        RequireContains(signingDoc, "IOCTL_KSWORD_SANDBOX_GET_HEALTH", "Signing doc should describe device health validation.");
        RequireContains(signingDoc, "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES", "Signing doc should describe capabilities readiness.");
        RequireContains(signingDoc, "IOCTL_KSWORD_SANDBOX_GET_STATUS", "Signing doc should describe status readiness.");
        RequireContains(signingDoc, "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK", "Signing doc should describe producer-mask readiness.");
        RequireContains(signingDoc, "r0collector.driverCapabilities", "Signing doc should list capabilities JSONL evidence.");
        RequireContains(signingDoc, "r0collector.driverStatus", "Signing doc should list status JSONL evidence.");
        RequireContains(signingDoc, "r0collector.driverProducerMask", "Signing doc should list producer-mask JSONL evidence.");
        RequireContains(signingDoc, "non-fatal diagnostics", "Signing doc should keep unavailable live-driver checks diagnostic.");
        RequireContains(signingDoc, "DrainWithCollector", "Signing doc should describe collector drain validation.");

        RequireContains(collectorDoc, "Capability/status/producer-mask negotiation", "Collector doc should describe negotiated IOCTL flow.");
        RequireContains(collectorDoc, "IOCTL_KSWORD_SANDBOX_GET_CAPABILITIES", "Collector doc should document capabilities IOCTL.");
        RequireContains(collectorDoc, "IOCTL_KSWORD_SANDBOX_GET_STATUS", "Collector doc should document status IOCTL.");
        RequireContains(collectorDoc, "IOCTL_KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK", "Collector doc should document producer-mask IOCTL.");
        RequireContains(collectorDoc, "KSWORD_SANDBOX_CAPABILITIES_REPLY", "Collector doc should document capabilities reply.");
        RequireContains(collectorDoc, "KSWORD_SANDBOX_STATUS_REPLY", "Collector doc should document status reply.");
        RequireContains(collectorDoc, "KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REQUEST", "Collector doc should document producer-mask request.");
        RequireContains(collectorDoc, "KSWORD_SANDBOX_SET_PRODUCER_ENABLE_MASK_REPLY", "Collector doc should document producer-mask reply.");
        RequireContains(collectorDoc, "r0collector.driverCapabilities", "Collector doc should list capabilities JSONL evidence.");
        RequireContains(collectorDoc, "r0collector.driverStatus", "Collector doc should list status JSONL evidence.");
        RequireContains(collectorDoc, "r0collector.driverProducerMask", "Collector doc should list producer-mask JSONL evidence.");
        RequireContains(collectorDoc, "non-fatal diagnostics", "Collector doc should keep unavailable live-driver checks diagnostic.");
        RequireContains(collectorDoc, "one-shot drain", "Collector doc should describe one-shot drain validation.");
        RequireContains(collectorDoc, "--duration 0", "Collector doc should show one-shot collector mode.");
        RequireContains(networkDoc, "Runtime validation gate", "Network doc should include runtime validation gate.");
        RequireContains(networkDoc, "Test-NetConnection", "Network doc should include a controlled traffic smoke.");
        RequireContains(driverReadme, "Runtime validation preflight", "Driver README should point operators at the preflight script.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 runtime readiness contract is documented and explicitly gated."
        });
    }

    /// <summary>
    /// Reads a UTF-8/Unicode repository file by path segment. Inputs are context
    /// and path segments; processing combines them under RepositoryRoot; return
    /// value is the full file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] segments)
    {
        var allSegments = new string[segments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        Array.Copy(segments, 0, allSegments, 1, segments.Length);
        var path = Path.Combine(allSegments);
        SmokeAssert.True(File.Exists(path), $"Required R0 readiness file is missing: {path}");
        return File.ReadAllText(path);
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
