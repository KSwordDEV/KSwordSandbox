using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards cleanup and loss-boundary contracts that are difficult to exercise
/// on a non-Windows build: an interrupted probe must still stop pktmon, a
/// PCAPNG trailer must be validated, and R0's final lifecycle row must expose
/// driver loss counters instead of claiming a clean drain.
/// </summary>
internal sealed class GuestCaptureIntegrityContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest.capture-integrity.contract";

    public Task<SmokeTestResult> RunAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var packetProbe = File.ReadAllText(Path.Combine(
            context.RepositoryRoot,
            "guest",
            "KSword.Sandbox.Agent",
            "Collection",
            "PacketCaptureProbe.cs"));
        SmokeAssert.True(
            packetProbe.Contains("[\"stop\"]", StringComparison.Ordinal) &&
            packetProbe.Contains("CancellationToken.None", StringComparison.Ordinal),
            "pktmon stop must use bounded uncancelable cleanup after a session starts.");
        SmokeAssert.True(
            packetProbe.Contains("pktmonConvertProducedEmptyArtifact", StringComparison.Ordinal),
            "An empty PCAPNG conversion result must remain an explicit failed capture.");
        SmokeAssert.True(
            packetProbe.Contains("TryReadExactly", StringComparison.Ordinal) &&
            packetProbe.Contains("blockTrailer", StringComparison.Ordinal) &&
            packetProbe.Contains("partial-or-invalid", StringComparison.Ordinal),
            "PCAPNG scanning must detect short reads and mismatched block trailers.");

        var runtimeLoop = File.ReadAllText(Path.Combine(
            context.RepositoryRoot,
            "guest",
            "KSword.Sandbox.R0Collector",
            "src",
            "RuntimeLoop.cpp"));
        SmokeAssert.True(
            runtimeLoop.Contains("finalStatusReply.TotalEventsDropped", StringComparison.Ordinal) &&
            runtimeLoop.Contains("finalStatusReply.QueueHighWatermark", StringComparison.Ordinal),
            "R0 stopped evidence must carry authoritative final loss and high-watermark counters.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Guest packet cleanup, PCAPNG integrity, and R0 final loss accounting contracts are explicit."
        });
    }
}
