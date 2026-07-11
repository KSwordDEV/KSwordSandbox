using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Reserves the packet-capture collection lane without starting a sniffer.
/// Inputs are probe phase and an explicit future PCAP flag; processing emits a
/// non-fatal placeholder event only when requested; CollectAsync never captures
/// live traffic in the current implementation.
/// </summary>
internal sealed class PacketCaptureProbe : IGuestProbe
{
    public string ProbeId => "packet-capture";

    /// <summary>
    /// Emits one explicit not-implemented event for future PCAP collection.
    /// Inputs are phase, guest context, and cancellation token; processing keeps
    /// default behavior silent and safe; the method returns placeholder events.
    /// </summary>
    public Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!context.CapturePacketCapture || phase is not ProbePhase.BeforeStart)
        {
            return Task.FromResult<IReadOnlyList<SandboxEvent>>([]);
        }

        return Task.FromResult<IReadOnlyList<SandboxEvent>>(
        [
            new SandboxEvent
            {
                EventType = "packet_capture.skipped",
                Source = "guest",
                Data =
                {
                    ["phase"] = "before-start",
                    ["captureEnabled"] = "true",
                    ["implemented"] = "false",
                    ["reason"] = "packetCaptureNotImplemented",
                    ["evidenceRole"] = "packet-capture",
                    ["collectionName"] = "packet-captures",
                    ["expectedRelativePath"] = "packet-captures/*.pcapng"
                }
            }
        ]);
    }
}
