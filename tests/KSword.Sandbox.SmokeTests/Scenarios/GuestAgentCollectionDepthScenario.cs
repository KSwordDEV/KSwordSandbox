using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the guest collection-depth framework contract without malware,
/// administrator rights, or a live VM.
/// Inputs are repository paths from SmokeTestContext; processing reads source
/// and documentation files for required probe/event contracts; the scenario
/// returns pass/fail metadata.
/// </summary>
internal sealed class GuestAgentCollectionDepthScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest-agent.collection-depth";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        var agentRoot = Path.Combine(context.RepositoryRoot, "guest", "KSword.Sandbox.Agent");
        var collectionRoot = Path.Combine(agentRoot, "Collection");
        var guestAgentDoc = ReadRepositoryText(context, "docs", "guest-agent.md");
        var frameworkDoc = ReadRepositoryText(context, "docs", "guest-agent-framework.md");
        var artifactsDoc = ReadRepositoryText(context, "docs", "artifacts.md");
        var programText = ReadRepositoryText(context, "guest", "KSword.Sandbox.Agent", "Program.cs");

        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "process.tree", "Process tree probe must emit process.tree.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "CreateToolhelp32Snapshot", "Process tree probe must use low-privilege Toolhelp snapshots.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.created", "File diff probe must emit file.created.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.modified", "File diff probe must emit file.modified.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.deleted", "File diff probe must emit file.deleted.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.tcp.closed", "TCP diff probe must emit closed connection deltas.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "dns.cache.added", "Network probe must emit DNS cache deltas.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.netstat", "Network probe must emit netstat evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "ipconfig.exe", "DNS cache collection must use a bounded ipconfig helper.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "netstat.exe", "Netstat collection must use a bounded netstat helper.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "environment.detail", "Process probe must emit extended environment details.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "service.created", "Process probe must emit service diff events.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "scheduled_task.created", "Process probe must emit scheduled task diff events.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "startup_item.created", "Process probe must emit startup item diff events.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "IScreenshotCapture", "Screenshot interface must be present.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "ScreenshotProbeOptions", "Screenshot probe must expose configurable capture options.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "MaximumCaptureCount", "Screenshot count must be capped.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshotStage", "Screenshot events must include configured stage metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshotIndex", "Screenshot events must include sequence metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshot.skipped", "Screenshot capture must be non-fatal in unsupported sessions.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "diagnosticStage", "Screenshot skipped events must include failure-stage diagnostics.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "IProcessMemoryDumpCapture", "Memory dump interface must be present.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "MiniDumpWriteDump", "Memory dump capture must use Windows minidump APIs.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "memory_dump.skipped", "Memory dump capture must be non-fatal.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "memory_dump.sweep", "Memory dump capture must summarize final root/child sweep coverage.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "MiniDumpNormal", "Memory dump capture must default to lightweight minidumps.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "ProcessSnapshotProvider", "Memory dump capture must reuse process snapshots for child-process sweeps.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "BuildVisibleDumpTargets", "Memory dump capture must build root/child process dump targets.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "processRole", "Memory dump events must identify root versus child process dumps.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "alreadyCapturedCount", "Memory dump sweep must report duplicate root/child dump suppression.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "pktmon.exe", "Packet capture probe must use Windows pktmon.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "etl2pcap", "Packet capture probe must convert ETL output to PCAPNG.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.started", "Packet capture probe must emit start evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.captured", "Packet capture probe must emit captured PCAPNG evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.failed", "Packet capture probe must emit non-fatal failure evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.skipped", "Packet capture probe must keep unavailable capture non-fatal.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet-captures", "Packet capture probe must write to the packet-captures collection lane.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "probe.timeout", "Probe runner must isolate timed-out probes.");
        AssertFileContains(Path.Combine(agentRoot, "Diagnostics", "BoundedProcessRunner.cs"), "Kill(entireProcessTree: true)", "Bounded helper commands must be terminated on timeout.");

        SmokeAssert.True(programText.Contains("new ProcessTreeProbe()", StringComparison.Ordinal), "Agent pipeline must include ProcessTreeProbe.");
        SmokeAssert.True(programText.Contains("new FileDiffProbe()", StringComparison.Ordinal), "Agent pipeline must include FileDiffProbe.");
        SmokeAssert.True(programText.Contains("new TcpConnectionDiffProbe()", StringComparison.Ordinal), "Agent pipeline must include TcpConnectionDiffProbe.");
        SmokeAssert.True(programText.Contains("new PacketCaptureProbe()", StringComparison.Ordinal), "Agent pipeline must include PacketCaptureProbe.");
        SmokeAssert.True(programText.Contains("new ScreenshotProbe(options.ScreenshotOptions)", StringComparison.Ordinal), "Agent pipeline must include configured ScreenshotProbe.");
        SmokeAssert.True(programText.Contains("new MemoryDumpProbe()", StringComparison.Ordinal), "Agent pipeline must include MemoryDumpProbe.");
        SmokeAssert.True(programText.Contains("CaptureScreenshots", StringComparison.Ordinal), "Agent options must carry screenshot enablement.");
        SmokeAssert.True(programText.Contains("ScreenshotProbeOptions.Parse", StringComparison.Ordinal), "Agent options must parse configurable screenshot phases and count.");
        SmokeAssert.True(programText.Contains("screenshot-phases", StringComparison.Ordinal), "Agent CLI must accept configurable screenshot phases.");
        SmokeAssert.True(programText.Contains("screenshot-count", StringComparison.Ordinal), "Agent CLI must accept configurable screenshot count.");
        SmokeAssert.True(programText.Contains("artifact.manifest.written", StringComparison.Ordinal), "Agent must report manifest write success.");
        SmokeAssert.True(programText.Contains("artifact.manifest.failed", StringComparison.Ordinal), "Agent must keep manifest write failures non-fatal.");
        SmokeAssert.True(programText.Contains("CaptureMemoryDump", StringComparison.Ordinal), "Agent options must carry explicit memory dump enablement.");
        SmokeAssert.True(programText.Contains("flags.Contains(\"memory-dump\")", StringComparison.Ordinal), "Memory dump capture must require an explicit flag.");
        SmokeAssert.True(programText.Contains("CapturePacketCapture", StringComparison.Ordinal), "Agent options must carry explicit packet capture enablement.");
        SmokeAssert.True(programText.Contains("flags.Contains(\"packet-capture\")", StringComparison.Ordinal), "Packet capture must require an explicit flag.");

        SmokeAssert.True(guestAgentDoc.Contains("process.tree", StringComparison.Ordinal), "Guest agent doc must document process.tree.");
        SmokeAssert.True(guestAgentDoc.Contains("network.tcp.closed", StringComparison.Ordinal), "Guest agent doc must document TCP closed deltas.");
        SmokeAssert.True(guestAgentDoc.Contains("dns.cache.added", StringComparison.Ordinal), "Guest agent doc must document DNS cache deltas.");
        SmokeAssert.True(guestAgentDoc.Contains("network.netstat", StringComparison.Ordinal), "Guest agent doc must document netstat collection.");
        SmokeAssert.True(guestAgentDoc.Contains("service.created", StringComparison.Ordinal), "Guest agent doc must document service diffs.");
        SmokeAssert.True(guestAgentDoc.Contains("scheduled_task.created", StringComparison.Ordinal), "Guest agent doc must document scheduled task diffs.");
        SmokeAssert.True(guestAgentDoc.Contains("startup_item.created", StringComparison.Ordinal), "Guest agent doc must document startup item diffs.");
        SmokeAssert.True(guestAgentDoc.Contains("probe.timeout", StringComparison.Ordinal), "Guest agent doc must document probe timeouts.");
        SmokeAssert.True(guestAgentDoc.Contains("--screenshot", StringComparison.Ordinal), "Guest agent doc must document screenshot CLI.");
        SmokeAssert.True(guestAgentDoc.Contains("--screenshot-phases", StringComparison.Ordinal), "Guest agent doc must document configurable screenshot phases.");
        SmokeAssert.True(guestAgentDoc.Contains("--screenshot-count", StringComparison.Ordinal), "Guest agent doc must document configurable screenshot count.");
        SmokeAssert.True(guestAgentDoc.Contains("--memory-dump", StringComparison.Ordinal), "Guest agent doc must document memory dump CLI.");
        SmokeAssert.True(guestAgentDoc.Contains("memory_dump.sweep", StringComparison.Ordinal), "Guest agent doc must document final memory dump sweep.");
        SmokeAssert.True(guestAgentDoc.Contains("visible root/child", StringComparison.OrdinalIgnoreCase), "Guest agent doc must document root and child memory dump coverage.");
        SmokeAssert.True(guestAgentDoc.Contains("--packet-capture", StringComparison.Ordinal), "Guest agent doc must document packet capture CLI.");
        SmokeAssert.True(guestAgentDoc.Contains("packet_capture.captured", StringComparison.Ordinal), "Guest agent doc must document captured packet events.");
        SmokeAssert.True(guestAgentDoc.Contains("pktmon", StringComparison.OrdinalIgnoreCase), "Guest agent doc must document pktmon capture.");
        SmokeAssert.True(guestAgentDoc.Contains("off by default", StringComparison.OrdinalIgnoreCase), "Guest agent doc must document memory dumps as opt-in.");
        SmokeAssert.True(artifactsDoc.Contains("memory-dumps/*.dmp", StringComparison.Ordinal), "Artifacts doc must document memory dump output.");
        SmokeAssert.True(artifactsDoc.Contains("memory_dump.sweep", StringComparison.Ordinal), "Artifacts doc must document memory dump sweep summary.");
        SmokeAssert.True(artifactsDoc.Contains("packet-captures/*.pcapng", StringComparison.Ordinal), "Artifacts doc must document packet-capture output.");
        SmokeAssert.True(artifactsDoc.Contains("packet_capture.captured", StringComparison.Ordinal), "Artifacts doc must document packet-capture event output.");
        SmokeAssert.True(artifactsDoc.Contains("dropped-files", StringComparison.Ordinal), "Artifacts doc must document dropped-file artifacts.");
        SmokeAssert.True(artifactsDoc.Contains("screenshots/", StringComparison.Ordinal), "Artifacts doc must document screenshot artifacts.");
        SmokeAssert.True(artifactsDoc.Contains("before,during,after", StringComparison.Ordinal), "Artifacts doc must document screenshot cadence metadata.");
        SmokeAssert.True(artifactsDoc.Contains("manifest.json` is always written", StringComparison.Ordinal), "Artifacts doc must document best-effort manifest output.");
        SmokeAssert.True(frameworkDoc.Contains("IGuestProbe.CollectAsync", StringComparison.Ordinal), "Framework doc must document the probe extension point.");
        SmokeAssert.True(frameworkDoc.Contains("BoundedProcessRunner", StringComparison.Ordinal), "Framework doc must document bounded helper command execution.");
        SmokeAssert.True(frameworkDoc.Contains("IScreenshotCapture", StringComparison.Ordinal), "Framework doc must document screenshot capture interface.");
        SmokeAssert.True(frameworkDoc.Contains("ScreenshotProbeOptions", StringComparison.Ordinal), "Framework doc must document configurable screenshot capture planning.");
        SmokeAssert.True(frameworkDoc.Contains("PacketCaptureProbe", StringComparison.Ordinal), "Framework doc must document packet capture probe.");
        SmokeAssert.True(frameworkDoc.Contains("pktmon", StringComparison.OrdinalIgnoreCase), "Framework doc must document pktmon usage.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Guest collection-depth probe contracts are documented and wired."
        });
    }

    /// <summary>
    /// Reads a repository file as text.
    /// Inputs are smoke context and relative path segments; processing combines
    /// and reads the path; the method returns the file text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] relativeSegments)
    {
        var segments = new string[relativeSegments.Length + 1];
        segments[0] = context.RepositoryRoot;
        Array.Copy(relativeSegments, 0, segments, 1, relativeSegments.Length);
        return File.ReadAllText(Path.Combine(segments));
    }

    /// <summary>
    /// Verifies that a source file contains expected contract text.
    /// Inputs are file path, expected text, and failure message; processing reads
    /// the file and asserts containment; the method returns no value.
    /// </summary>
    private static void AssertFileContains(string path, string expected, string message)
    {
        SmokeAssert.True(File.Exists(path), $"{Path.GetFileName(path)} is missing.");
        SmokeAssert.True(File.ReadAllText(path).Contains(expected, StringComparison.Ordinal), message);
    }
}
