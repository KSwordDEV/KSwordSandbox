using KSword.Sandbox.Abstractions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies executable R0Collector readiness diagnostics without a live driver.
/// Inputs are the native collector binary and deliberately missing service/device
/// names; processing runs no-device/health/self-test commands and parses JSONL;
/// the scenario returns pass/fail metadata without signing or loading a driver.
/// </summary>
internal sealed class R0CollectorReadinessDiagnosticsContractScenario : ISmokeTestScenario
{
    private const int DeviceUnavailableExitCode = 66;

    public string ScenarioId => "r0.collector.readiness-diagnostics.contract";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await AssertExecutableReadinessUnavailableAsync(context, cancellationToken);
        await AssertExecutableHealthUnavailableAsync(context, cancellationToken);
        await AssertExecutableSelfTestAliasAsync(context, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0Collector readiness/device-unavailable diagnostics and self-test alias JSONL contracts are executable."
        };
    }

    /// <summary>
    /// Runs --readiness against a unique missing service/device pair.
    /// Inputs are smoke context and cancellation token; processing writes JSONL
    /// under the native smoke output root; return value is none.
    /// </summary>
    private static async Task AssertExecutableReadinessUnavailableAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken)
    {
        var build = await R0CollectorExecutableSmokeHelper.BuildCollectorAsync(context, cancellationToken);
        var uniqueName = "KSwordSandboxMissing" + Guid.NewGuid().ToString("N");
        var missingDevice = @"\\.\" + uniqueName;
        var outputPath = R0CollectorExecutableSmokeHelper.CreateRunOutputPath(build, "r0collector-readiness-missing-device.jsonl");
        var result = await R0CollectorExecutableSmokeHelper.RunCollectorAsync(
            build.ExecutablePath,
            [
                "--readiness",
                "--service-name",
                uniqueName,
                "--device",
                missingDevice,
                "--read-timeout-ms",
                "50",
                "--out",
                outputPath
            ],
            context.RepositoryRoot,
            cancellationToken);
        if (R0CollectorExecutableSmokeHelper.IsExecutionBlockedByHostPolicy(result))
        {
            SmokeAssert.True(
                result.CombinedOutput.Contains("Execution blocked by host policy", StringComparison.Ordinal),
                "Blocked executable readiness smoke should report explicit host-policy evidence.");
            return;
        }

        SmokeAssert.True(
            result.ExitCode == DeviceUnavailableExitCode,
            $"collector --readiness against a missing device should exit {DeviceUnavailableExitCode}. Output: {result.CombinedOutput}");

        var jsonLines = R0CollectorExecutableSmokeHelper.ReadJsonLines(outputPath);
        SmokeAssert.True(jsonLines.BlankLineCount == 0, "Readiness unavailable output should not contain blank JSONL noise.");
        SmokeAssert.True(jsonLines.MalformedLines.Count == 0, "Readiness unavailable output should not contain malformed JSONL rows.");

        var started = RequireEvent(jsonLines.Events, "r0collector.started");
        RequireData(started, "diagnose", "true");
        RequireData(started, "serviceName", uniqueName);
        RequireData(started, "devicePath", missingDevice);
        RequireData(started, "diagnoseReadTimeoutMs", "50");

        var serviceDiagnostic = RequireDiagnostic(jsonLines.Events, "service");
        RequireDataPresent(serviceDiagnostic, "diagnosticCode");
        RequireDataPresent(serviceDiagnostic, "severity");
        RequireDataPresent(serviceDiagnostic, "readinessState");

        var unavailable = RequireEvent(jsonLines.Events, "r0collector.deviceUnavailable");
        RequireData(unavailable, "diagnosticStage", "openDevice");
        RequireData(unavailable, "severity", "error");
        RequireData(unavailable, "readinessState", "blocked");
        RequireData(unavailable, "serviceName", uniqueName);
        RequireData(unavailable, "devicePath", missingDevice);
        RequireDataPresent(unavailable, "diagnosticCode");
        RequireDataPresent(unavailable, "win32Error");
        RequireDataPresent(unavailable, "win32Message");
        RequireDataPresent(unavailable, "hint");

        var summary = RequireEvent(jsonLines.Events, "r0collector.readinessSummary");
        RequireData(summary, "ready", "false");
        RequireData(summary, "severity", "error");
        RequireData(summary, "readinessState", "blocked");
        RequireDataOneOf(summary, "failedStage", "service", "openDevice");
        RequireDataPresent(summary, "serviceDiagnosticCode");
        RequireDataPresent(summary, "openDeviceDiagnosticCode");

        RequireNoEvent(jsonLines.Events, "r0collector.deviceOpened");
        RequireNoEvent(jsonLines.Events, "r0collector.driverHealth");
        RequireNoEvent(jsonLines.Events, "r0collector.driverReadEvents");
    }

    /// <summary>
    /// Runs --health against a unique missing device and verifies the legacy
    /// device-unavailable event now carries structured severity/readiness fields.
    /// </summary>
    private static async Task AssertExecutableHealthUnavailableAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken)
    {
        var build = await R0CollectorExecutableSmokeHelper.BuildCollectorAsync(context, cancellationToken);
        var missingDevice = @"\\.\" + "KSwordSandboxHealthMissing" + Guid.NewGuid().ToString("N");
        var outputPath = R0CollectorExecutableSmokeHelper.CreateRunOutputPath(build, "r0collector-health-missing-device.jsonl");
        var result = await R0CollectorExecutableSmokeHelper.RunCollectorAsync(
            build.ExecutablePath,
            [
                "--health",
                "--device",
                missingDevice,
                "--out",
                outputPath
            ],
            context.RepositoryRoot,
            cancellationToken);
        if (R0CollectorExecutableSmokeHelper.IsExecutionBlockedByHostPolicy(result))
        {
            SmokeAssert.True(
                result.CombinedOutput.Contains("Execution blocked by host policy", StringComparison.Ordinal),
                "Blocked executable health-unavailable smoke should report explicit host-policy evidence.");
            return;
        }

        SmokeAssert.True(
            result.ExitCode == DeviceUnavailableExitCode,
            $"collector --health against a missing device should exit {DeviceUnavailableExitCode}. Output: {result.CombinedOutput}");

        var jsonLines = R0CollectorExecutableSmokeHelper.ReadJsonLines(outputPath);
        SmokeAssert.True(jsonLines.BlankLineCount == 0, "Health unavailable output should not contain blank JSONL noise.");
        SmokeAssert.True(jsonLines.MalformedLines.Count == 0, "Health unavailable output should not contain malformed JSONL rows.");

        var started = RequireEvent(jsonLines.Events, "r0collector.started");
        RequireData(started, "healthOnly", "true");
        RequireData(started, "diagnose", "false");

        var unavailable = RequireEvent(jsonLines.Events, "r0collector.deviceUnavailable");
        RequireData(unavailable, "diagnosticStage", "openDevice");
        RequireData(unavailable, "severity", "error");
        RequireData(unavailable, "readinessState", "blocked");
        RequireDataPresent(unavailable, "diagnosticCode");
        RequireDataPresent(unavailable, "win32Error");
        RequireDataPresent(unavailable, "hint");

        RequireNoEvent(jsonLines.Events, "r0collector.deviceOpened");
        RequireNoEvent(jsonLines.Events, "r0collector.driverHealth");
        RequireNoEvent(jsonLines.Events, "r0collector.driverPoll");
        RequireNoEvent(jsonLines.Events, "r0collector.driverReadEvents");
    }

    /// <summary>
    /// Runs --self-test to prove the mock alias remains executable and never
    /// opens the live driver path.
    /// </summary>
    private static async Task AssertExecutableSelfTestAliasAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken)
    {
        var build = await R0CollectorExecutableSmokeHelper.BuildCollectorAsync(context, cancellationToken);
        var outputPath = R0CollectorExecutableSmokeHelper.CreateRunOutputPath(build, "r0collector-self-test-alias.jsonl");
        var result = await R0CollectorExecutableSmokeHelper.RunCollectorAsync(
            build.ExecutablePath,
            [
                "--self-test",
                "--out",
                outputPath
            ],
            context.RepositoryRoot,
            cancellationToken);
        if (R0CollectorExecutableSmokeHelper.IsExecutionBlockedByHostPolicy(result))
        {
            SmokeAssert.True(
                result.CombinedOutput.Contains("Execution blocked by host policy", StringComparison.Ordinal),
                "Blocked executable self-test smoke should report explicit host-policy evidence.");
            return;
        }

        SmokeAssert.True(result.ExitCode == 0, $"collector --self-test should exit 0. Output: {result.CombinedOutput}");

        var jsonLines = R0CollectorExecutableSmokeHelper.ReadJsonLines(outputPath);
        SmokeAssert.True(jsonLines.BlankLineCount == 0, "Self-test output should not contain blank JSONL noise.");
        SmokeAssert.True(jsonLines.MalformedLines.Count == 0, "Self-test output should not contain malformed JSONL rows.");

        var started = RequireEvent(jsonLines.Events, "r0collector.started");
        RequireData(started, "mockMode", "true");
        RequireData(started, "syntheticMode", "true");
        RequireData(started, "diagnose", "false");

        var stopped = RequireEvent(jsonLines.Events, "r0collector.stopped");
        RequireData(stopped, "reason", "mockComplete");
        RequireData(stopped, "ioctlIssued", "false");

        RequireEvent(jsonLines.Events, "r0collector.mockDriverEvent");
        RequireNoEvent(jsonLines.Events, "r0collector.deviceOpened");
        RequireNoEvent(jsonLines.Events, "r0collector.deviceUnavailable");
        RequireNoEvent(jsonLines.Events, "r0collector.driverHealth");
    }

    private static SandboxEvent RequireDiagnostic(IEnumerable<SandboxEvent> events, string diagnosticStage)
    {
        var evt = events.FirstOrDefault(candidate =>
            string.Equals(candidate.EventType, "r0collector.readinessDiagnostic", StringComparison.OrdinalIgnoreCase) &&
            DataEquals(candidate, "diagnosticStage", diagnosticStage));
        SmokeAssert.True(evt is not null, $"Readiness JSONL should contain diagnostic stage {diagnosticStage}.");
        return evt!;
    }

    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Collector JSONL should contain {eventType}.");
        return evt!;
    }

    private static void RequireNoEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        SmokeAssert.True(
            events.All(candidate => !string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase)),
            $"Collector JSONL should not contain {eventType}.");
    }

    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(
            evt.Data.TryGetValue(key, out var actual) &&
            string.Equals(actual, expected, StringComparison.Ordinal),
            $"{evt.EventType} should contain data.{key}={expected}.");
    }

    private static void RequireDataPresent(SandboxEvent evt, string key)
    {
        SmokeAssert.True(
            evt.Data.TryGetValue(key, out var actual) &&
            !string.IsNullOrWhiteSpace(actual),
            $"{evt.EventType} should contain non-empty data.{key}.");
    }

    private static void RequireDataOneOf(SandboxEvent evt, string key, params string[] expectedValues)
    {
        SmokeAssert.True(
            evt.Data.TryGetValue(key, out var actual) &&
            expectedValues.Any(expected => string.Equals(actual, expected, StringComparison.Ordinal)),
            $"{evt.EventType} should contain data.{key} in [{string.Join(", ", expectedValues)}].");
    }

    private static bool DataEquals(SandboxEvent evt, string key, string expected)
    {
        return evt.Data.TryGetValue(key, out var actual) &&
            string.Equals(actual, expected, StringComparison.Ordinal);
    }
}
