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
        var guestWriterText = ReadRepositoryText(context, "guest", "KSword.Sandbox.Agent", "Output", "GuestArtifactWriter.cs");

        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "process.tree", "Process tree probe must emit process.tree.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "CreateToolhelp32Snapshot", "Process tree probe must use low-privilege Toolhelp snapshots.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "treeLineage", "Process tree events must preserve root/child lineage.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "rootLineageProcessId", "Process tree events must expose root lineage aliases.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "treeLineageDepth", "Process tree events must expose lineage depth aliases.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "eventSemanticClass", "Process tree events must expose semantic classes for report selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "semanticEventTags", "Process tree events must expose semantic tags for report filtering.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "processTreeRole", "Process tree events must preserve stable root/direct-child/descendant roles.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "rootAncestorProcessId", "Process tree events must preserve stable root ancestor metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "isDirectChildOfRoot", "Process tree events must distinguish direct children from deeper descendants.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "processExited", "Process tree missing rows must preserve exited markers.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "rootExited", "Process tree summaries must preserve root-exited markers.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "rootTreeMetadata", "New process rows should reuse root-tree metadata when lineage is available.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "zhMessage", "Process tree events must include Chinese report text.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "reasonTaxonomy", "Process tree missing/summary rows must expose stable reason taxonomy.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "behaviorCounted", "Process tree diagnostic summary rows must be explicitly marked out of behavior counts.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "nonbehavior", "Process tree diagnostic summary rows must be marked as non-behavior evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.created", "File diff probe must emit file.created.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.modified", "File diff probe must emit file.modified.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.deleted", "File diff probe must emit file.deleted.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.tcp.closed", "TCP diff probe must emit closed connection deltas.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "dns.cache.added", "Network probe must emit DNS cache deltas.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.hosts.snapshot", "Network probe must emit hosts file snapshots.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.hosts.added", "Network probe must emit hosts file deltas.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.proxy.snapshot", "Network probe must emit proxy snapshots.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.proxy.modified", "Network probe must emit proxy setting modifications.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.netstat", "Network probe must emit netstat evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "ipconfig.exe", "DNS cache collection must use a bounded ipconfig helper.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "netsh.exe", "WinHTTP proxy collection must use a bounded netsh helper.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "netstat.exe", "Netstat collection must use a bounded netstat helper.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "environment.detail", "Process probe must emit extended environment details.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "service.created", "Process probe must emit service diff events.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "imagePath", "Service diff events must preserve service ImagePath metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "serviceDll", "Service diff events must preserve service DLL metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "scheduled_task.created", "Process probe must emit scheduled task diff events.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "startup_item.created", "Process probe must emit startup item diff events.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "IScreenshotCapture", "Screenshot interface must be present.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "ScreenshotProbeOptions", "Screenshot probe must expose configurable capture options.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "MaximumCaptureCount", "Screenshot count must be capped.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshotStage", "Screenshot events must include configured stage metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshotIndex", "Screenshot events must include sequence metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshot.skipped", "Screenshot capture must be non-fatal in unsupported sessions.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "reason", "Screenshot skipped events must include concrete failure reasons.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "exceptionType", "Screenshot skipped events must include exception type diagnostics.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "diagnosticStage", "Screenshot skipped events must include failure-stage diagnostics.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "win32Error", "Screenshot skipped events must include Win32 diagnostics when available.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "capturePhase", "Screenshot events must include normalized capture phase metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "artifactRelativePath", "Screenshot events must expose artifact-relative paths.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "stableArtifactSelector", "Screenshot events must expose stable artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "canonicalArtifactSelector", "Screenshot events must expose canonical artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "artifactSemanticType", "Screenshot events must expose artifact semantic type tags.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "semanticEventTags", "Screenshot events must expose semantic event tags.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "sha256", "Screenshot captured events must expose event-level SHA-256 metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "sizeBytes", "Screenshot captured events must expose event-level size metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "artifactIntegrityState", "Screenshot events must expose artifact integrity state.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "reasonCode", "Screenshot skipped events must expose stable reason codes.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "reasonCategory", "Screenshot skipped events must expose stable reason categories.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "reasonTaxonomy", "Screenshot skipped/summary events must expose a stable reason taxonomy.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshot.phase.summary", "Screenshot probe must emit per-phase capture summaries.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshotPhaseSummaryVersion", "Screenshot phase summaries must be versioned.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "firstArtifactSelector", "Screenshot summaries must expose first artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "lastArtifactSelector", "Screenshot summaries must expose last artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "largestArtifactSelector", "Screenshot summaries must expose largest artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "behaviorCounted", "Screenshot artifact/summary events must be explicitly marked out of behavior counts.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "nonbehavior", "Screenshot artifact/summary events must be marked as non-behavior evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "processRole", "Screenshot events should identify sample-root scoped attribution.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "treeLineage", "Screenshot events should preserve root lineage when available.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "zhMessage", "Screenshot events must include Chinese report text.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "nonfatal", "Screenshot skipped events must mark non-fatal collection status.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "rootProcessId", "Screenshot events should carry sample root process identity when available.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "IProcessMemoryDumpCapture", "Memory dump interface must be present.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "MiniDumpWriteDump", "Memory dump capture must use Windows minidump APIs.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "memory_dump.skipped", "Memory dump capture must be non-fatal.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "reason", "Memory dump skipped events must include concrete failure reasons.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "exceptionType", "Memory dump skipped events must include exception type diagnostics.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "diagnosticStage", "Memory dump skipped events must include failure-stage diagnostics.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "win32Error", "Memory dump skipped events must include Win32 diagnostics when available.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "memory_dump.sweep", "Memory dump capture must summarize final root/child sweep coverage.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "MiniDumpNormal", "Memory dump capture must default to lightweight minidumps.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "ProcessSnapshotProvider", "Memory dump capture must reuse process snapshots for child-process sweeps.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "BuildVisibleDumpTargets", "Memory dump capture must build root/child process dump targets.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "processRole", "Memory dump events must identify root versus child process dumps.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "alreadyCapturedCount", "Memory dump sweep must report duplicate root/child dump suppression.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "rootTargetCount", "Memory dump sweep must report root-process coverage.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "childTargetCount", "Memory dump sweep must report child-process coverage.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "memoryDumpCoverageState", "Memory dump sweep must expose a report-ready coverage state.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "artifactRelativePath", "Memory dump captured events must expose artifact-relative paths.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "stableArtifactSelector", "Memory dump captured/reference events must expose stable artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "canonicalArtifactSelector", "Memory dump captured/reference events must expose canonical artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "artifactSemanticType", "Memory dump events must expose artifact semantic type tags.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "semanticEventTags", "Memory dump events must expose semantic event tags.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "existingArtifactSelector", "Duplicate memory dump rows must reference the already-captured artifact selector.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "artifactReferenceEvent", "Duplicate memory dump rows must be explicit artifact-reference events.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "selectorArtifactCount", "Memory dump sweep summaries must count selector-ready dump artifacts.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "firstArtifactSelector", "Memory dump sweep summaries must expose first artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "largestArtifactSelector", "Memory dump sweep summaries must expose largest artifact selectors.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "sha256", "Memory dump captured events must expose event-level SHA-256 metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "treeLineage", "Memory dump events must preserve child lineage metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "zhMessage", "Memory dump events must include Chinese report text.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "targetProcessName", "Memory dump events must preserve target process identity.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "targetProcessPath", "Memory dump events must preserve target process path metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "targetProcessRole", "Memory dump events must preserve root/direct-child/descendant target roles.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "targetTreeLineage", "Memory dump events must preserve target lineage metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "rootDescendantCoverageState", "Memory dump sweep must summarize root plus descendant coverage.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "directChildCoverageState", "Memory dump sweep must summarize direct-child coverage separately.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "deeperDescendantCoverageState", "Memory dump sweep must summarize deeper descendant coverage separately.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "descendantCoverageCompleteness", "Memory dump sweep must expose report-ready descendant coverage completeness.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "directChildProcessDumpTarget", "Memory dump events must flag direct-child dump targets.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "deeperDescendantProcessDumpTarget", "Memory dump events must flag deeper descendant dump targets.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "coverageTaxonomy", "Memory dump sweep must version coverage taxonomy.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "reasonTaxonomy", "Memory dump events must expose a stable reason taxonomy.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "reasonCode", "Memory dump skipped events must expose stable reason codes.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "reasonCategory", "Memory dump skipped events must expose stable reason categories.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "capturePhase", "Memory dump events must include normalized capture phase metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "nonfatal", "Memory dump skipped events must mark non-fatal collection status.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "behaviorCounted", "Memory dump artifact/summary events must be explicitly marked out of behavior counts.");
        AssertFileContains(Path.Combine(collectionRoot, "MemoryDumpProbe.cs"), "nonbehavior", "Memory dump artifact/summary events must be marked as non-behavior evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "pktmon.exe", "Packet capture probe must use Windows pktmon.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "etl2pcap", "Packet capture probe must convert ETL output to PCAPNG.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.started", "Packet capture probe must emit start evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.captured", "Packet capture probe must emit captured PCAPNG evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.failed", "Packet capture probe must emit non-fatal failure evidence.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet_capture.skipped", "Packet capture probe must keep unavailable capture non-fatal.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packet-captures", "Packet capture probe must write to the packet-captures collection lane.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "artifactRelativePath", "Packet capture events must expose final PCAP artifact-relative paths.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "etlRelativePath", "Packet capture diagnostics must distinguish ETL diagnostic paths.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "artifactSourceTool", "Packet capture events must identify the source tool for artifacts.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "packetCaptureSourceTool", "Packet capture events must preserve packet-capture source tool metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "sha256", "Packet capture captured events must expose event-level SHA-256 metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "sizeBytes", "Packet capture captured events must expose event-level size metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "artifactExists", "Packet capture diagnostics must preserve artifact existence/missing state.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "processRole", "Packet capture events should identify sample-root scoped attribution.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "treeLineage", "Packet capture events should preserve root lineage when available.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "zhMessage", "Packet capture events must include Chinese report text.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "capturePhase", "Packet capture events must include normalized capture phase metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "PacketCaptureProbe.cs"), "nonfatal", "Packet capture skipped/failed events must mark non-fatal collection status.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "probe.timeout", "Probe runner must isolate timed-out probes.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "probe.summary", "Probe runner must emit per-probe health summaries.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "probe.phase.summary", "Probe runner must emit phase-level probe summaries.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "collectionHealth", "Probe summaries must be explicitly marked as collection health, not behavior.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "nonbehavior", "Probe timeout/failure/summary events must be explicitly marked as non-behavior.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "treeLineage", "Probe summaries must preserve root lineage metadata.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "rootProcessId", "Probe summaries must preserve root process identity.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "collectionName", "Probe timeout/failure events must map known artifact probes to collection lanes.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "probeTimeout", "Probe timeout events must retain concrete failure reasons.");
        AssertFileContains(Path.Combine(collectionRoot, "GuestProbeRunner.cs"), "nonfatal", "Probe failure diagnostics must mark collection failures as non-fatal.");
        AssertFileContains(Path.Combine(agentRoot, "Diagnostics", "BoundedProcessRunner.cs"), "Kill(entireProcessTree: true)", "Bounded helper commands must be terminated on timeout.");

        SmokeAssert.True(guestWriterText.Contains("lastReason", StringComparison.Ordinal), "Guest artifact writer must preserve concrete collection failure reasons.");
        SmokeAssert.True(guestWriterText.Contains("lastDiagnosticStage", StringComparison.Ordinal), "Guest artifact writer must preserve diagnostic stages in collection metadata.");
        SmokeAssert.True(guestWriterText.Contains("lastArtifactRelativePath", StringComparison.Ordinal), "Guest artifact writer must preserve last artifact-relative path metadata.");
        SmokeAssert.True(guestWriterText.Contains("originalSha256", StringComparison.Ordinal), "Guest artifact writer must preserve original dropped-file SHA-256 metadata.");
        SmokeAssert.True(guestWriterText.Contains("copiedSha256", StringComparison.Ordinal), "Guest artifact writer must preserve copied dropped-file SHA-256 metadata.");
        SmokeAssert.True(guestWriterText.Contains("artifactHashStatus", StringComparison.Ordinal), "Guest artifact writer must preserve artifact hash/missing status metadata.");
        SmokeAssert.True(guestWriterText.Contains("artifactSourceTool", StringComparison.Ordinal), "Guest artifact writer must preserve packet-capture artifact source-tool metadata.");
        SmokeAssert.True(guestWriterText.Contains("CountProbeFailureEvents", StringComparison.Ordinal), "Guest artifact writer must count probe failures in collection status.");
        SmokeAssert.True(guestWriterText.Contains("lastProcessId", StringComparison.Ordinal), "Guest artifact writer must preserve process identity in artifact/collection metadata.");
        SmokeAssert.True(guestWriterText.Contains("lastTreeLineage", StringComparison.Ordinal), "Guest artifact writer must preserve child lineage metadata in collection metadata.");
        SmokeAssert.True(guestWriterText.Contains("collectionSummaryVersion", StringComparison.Ordinal), "Guest artifact writer must version collection summary metadata.");
        SmokeAssert.True(guestWriterText.Contains("artifactIntegrityState", StringComparison.Ordinal), "Guest artifact writer must preserve artifact integrity metadata.");
        SmokeAssert.True(guestWriterText.Contains("reasonCountsJson", StringComparison.Ordinal), "Guest artifact writer must summarize collection skipped/failed reasons.");
        SmokeAssert.True(guestWriterText.Contains("artifactSelectorVersion", StringComparison.Ordinal), "Guest artifact writer must version artifact selector metadata.");
        SmokeAssert.True(guestWriterText.Contains("stableArtifactSelector", StringComparison.Ordinal), "Guest artifact writer must preserve stable artifact selector metadata.");
        SmokeAssert.True(guestWriterText.Contains("canonicalArtifactSelector", StringComparison.Ordinal), "Guest artifact writer must preserve canonical artifact selector metadata.");
        SmokeAssert.True(guestWriterText.Contains("artifactSemanticType", StringComparison.Ordinal), "Guest artifact writer must preserve artifact semantic type metadata.");
        SmokeAssert.True(guestWriterText.Contains("semanticEventTags", StringComparison.Ordinal), "Guest artifact writer must preserve semantic event tags.");
        SmokeAssert.True(guestWriterText.Contains("summaryRow", StringComparison.Ordinal), "Guest artifact writer must mark collection summaries as report summary rows.");
        SmokeAssert.True(guestWriterText.Contains("firstArtifactSelector", StringComparison.Ordinal), "Guest artifact writer must expose first artifact selectors.");
        SmokeAssert.True(guestWriterText.Contains("lastArtifactSelector", StringComparison.Ordinal), "Guest artifact writer must expose last artifact selectors.");
        SmokeAssert.True(guestWriterText.Contains("largestArtifactSelector", StringComparison.Ordinal), "Guest artifact writer must expose largest artifact selectors.");
        SmokeAssert.True(guestWriterText.Contains("firstArtifactSafeLink", StringComparison.Ordinal), "Guest artifact writer must expose safe links for first artifact selectors.");
        SmokeAssert.True(guestWriterText.Contains("largestArtifactSha256", StringComparison.Ordinal), "Guest artifact writer must preserve hashes for largest artifact selectors.");
        SmokeAssert.True(guestWriterText.Contains("IsNonDiagnosticSummaryEvent", StringComparison.Ordinal), "Guest artifact writer must avoid replacing concrete diagnostics with summary reasons.");
        SmokeAssert.True(guestWriterText.Contains("directChildCoverageState", StringComparison.Ordinal), "Guest artifact writer must preserve direct-child memory dump coverage metadata.");
        SmokeAssert.True(guestWriterText.Contains("deeperDescendantCoverageState", StringComparison.Ordinal), "Guest artifact writer must preserve deeper descendant memory dump coverage metadata.");
        SmokeAssert.True(guestWriterText.Contains("descendantCoverageCompleteness", StringComparison.Ordinal), "Guest artifact writer must preserve descendant memory dump coverage completeness metadata.");
        SmokeAssert.True(guestWriterText.Contains("lastProcessExited", StringComparison.Ordinal), "Guest artifact writer must preserve process exited markers in collection metadata.");
        SmokeAssert.True(programText.Contains("artifact.dropped_file.copied", StringComparison.Ordinal), "Dropped-file copied events must be emitted for copied artifacts.");
        SmokeAssert.True(programText.Contains("artifact.dropped_file.skipped", StringComparison.Ordinal), "Dropped-file skipped events must be emitted for copy diagnostics.");
        SmokeAssert.True(programText.Contains("capturePhase", StringComparison.Ordinal), "Dropped-file events must include normalized capture phase metadata.");
        SmokeAssert.True(programText.Contains("processRole", StringComparison.Ordinal), "Dropped-file events must include sample process role attribution.");
        SmokeAssert.True(programText.Contains("rootProcessId", StringComparison.Ordinal), "Dropped-file events should carry sample root process identity when available.");
        SmokeAssert.True(programText.Contains("treeLineage", StringComparison.Ordinal), "Dropped-file events should preserve root lineage attribution.");
        SmokeAssert.True(programText.Contains("zhMessage", StringComparison.Ordinal), "Dropped-file events must include Chinese report text.");
        SmokeAssert.True(programText.Contains("sourceSha256", StringComparison.Ordinal), "Dropped-file events must include source SHA-256 metadata when readable.");
        SmokeAssert.True(programText.Contains("artifactSizeBytes", StringComparison.Ordinal), "Dropped-file copied events must include artifact size metadata.");
        SmokeAssert.True(programText.Contains("artifactExists", StringComparison.Ordinal), "Dropped-file copied events must preserve artifact existence state.");
        SmokeAssert.True(programText.Contains("sourceMissing", StringComparison.Ordinal), "Dropped-file skipped events must preserve source missing state.");
        SmokeAssert.True(programText.Contains("AddDroppedFileHashData(evt, copiedHash, prefix: \"copied\")", StringComparison.Ordinal), "Dropped-file events must include copied artifact SHA-256 metadata.");
        SmokeAssert.True(programText.Contains("sourceHashStatus", StringComparison.Ordinal), "Dropped-file events must include source hash status metadata.");
        SmokeAssert.True(programText.Contains("sourceEventSha256", StringComparison.Ordinal), "Dropped-file events must preserve source file-event hashes when available.");
        SmokeAssert.True(programText.Contains("sourceCopiedSha256Match", StringComparison.Ordinal), "Dropped-file copied events must compare source and copied hashes when available.");
        SmokeAssert.True(programText.Contains("skippedReasonCountsJson", StringComparison.Ordinal), "Dropped-file summaries must expose skipped reason counts.");
        SmokeAssert.True(programText.Contains("reasonCategory", StringComparison.Ordinal), "Dropped-file skipped events must expose stable reason categories.");
        SmokeAssert.True(programText.Contains("DroppedFileReasonTaxonomy", StringComparison.Ordinal), "Dropped-file events must expose a stable reason taxonomy.");
        SmokeAssert.True(programText.Contains("artifactSelector", StringComparison.Ordinal), "Dropped-file events must expose safe artifact selectors.");
        SmokeAssert.True(programText.Contains("firstArtifactSelector", StringComparison.Ordinal), "Dropped-file summaries must expose first copied artifact selectors.");
        SmokeAssert.True(programText.Contains("lastArtifactSelector", StringComparison.Ordinal), "Dropped-file summaries must expose last copied artifact selectors.");
        SmokeAssert.True(programText.Contains("largestArtifactSelector", StringComparison.Ordinal), "Dropped-file summaries must expose largest copied artifact selectors.");
        SmokeAssert.True(programText.Contains("reasonCountsJson", StringComparison.Ordinal), "Dropped-file summaries must expose all outcome reason counts.");
        SmokeAssert.True(programText.Contains("behaviorCounted", StringComparison.Ordinal), "Dropped-file artifact/summary/manifest events must be explicitly marked out of behavior counts.");
        SmokeAssert.True(programText.Contains("nonbehavior", StringComparison.Ordinal), "Dropped-file artifact/summary/manifest events must be marked as non-behavior evidence.");

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
        SmokeAssert.True(guestAgentDoc.Contains("network.hosts.snapshot", StringComparison.Ordinal), "Guest agent doc must document hosts file snapshots.");
        SmokeAssert.True(guestAgentDoc.Contains("network.proxy.snapshot", StringComparison.Ordinal), "Guest agent doc must document proxy snapshots.");
        SmokeAssert.True(guestAgentDoc.Contains("network.netstat", StringComparison.Ordinal), "Guest agent doc must document netstat collection.");
        SmokeAssert.True(guestAgentDoc.Contains("service.created", StringComparison.Ordinal), "Guest agent doc must document service diffs.");
        SmokeAssert.True(guestAgentDoc.Contains("serviceDll", StringComparison.Ordinal), "Guest agent doc must document service registry metadata.");
        SmokeAssert.True(guestAgentDoc.Contains("scheduled_task.created", StringComparison.Ordinal), "Guest agent doc must document scheduled task diffs.");
        SmokeAssert.True(guestAgentDoc.Contains("startup_item.created", StringComparison.Ordinal), "Guest agent doc must document startup item diffs.");
        SmokeAssert.True(guestAgentDoc.Contains("probe.timeout", StringComparison.Ordinal), "Guest agent doc must document probe timeouts.");
        SmokeAssert.True(guestAgentDoc.Contains("probe.summary", StringComparison.Ordinal), "Guest agent doc must document probe health summaries.");
        SmokeAssert.True(guestAgentDoc.Contains("probe.phase.summary", StringComparison.Ordinal), "Guest agent doc must document phase-level probe summaries.");
        SmokeAssert.True(guestAgentDoc.Contains("--screenshot", StringComparison.Ordinal), "Guest agent doc must document screenshot CLI.");
        SmokeAssert.True(guestAgentDoc.Contains("--screenshot-phases", StringComparison.Ordinal), "Guest agent doc must document configurable screenshot phases.");
        SmokeAssert.True(guestAgentDoc.Contains("--screenshot-count", StringComparison.Ordinal), "Guest agent doc must document configurable screenshot count.");
        SmokeAssert.True(guestAgentDoc.Contains("screenshot.phase.summary", StringComparison.Ordinal), "Guest agent doc must document screenshot phase summaries.");
        SmokeAssert.True(guestAgentDoc.Contains("firstArtifactSelector", StringComparison.Ordinal), "Guest agent doc must document artifact selector summaries.");
        SmokeAssert.True(guestAgentDoc.Contains("reasonTaxonomy", StringComparison.Ordinal), "Guest agent doc must document reason taxonomy fields.");
        SmokeAssert.True(guestAgentDoc.Contains("--memory-dump", StringComparison.Ordinal), "Guest agent doc must document memory dump CLI.");
        SmokeAssert.True(guestAgentDoc.Contains("memory_dump.sweep", StringComparison.Ordinal), "Guest agent doc must document final memory dump sweep.");
        SmokeAssert.True(guestAgentDoc.Contains("visible root/child", StringComparison.OrdinalIgnoreCase), "Guest agent doc must document root and child memory dump coverage.");
        SmokeAssert.True(guestAgentDoc.Contains("directChildCoverageState", StringComparison.Ordinal), "Guest agent doc must document direct-child memory dump coverage state.");
        SmokeAssert.True(guestAgentDoc.Contains("deeperDescendantCoverageState", StringComparison.Ordinal), "Guest agent doc must document deeper descendant memory dump coverage state.");
        SmokeAssert.True(guestAgentDoc.Contains("nonbehavior=true", StringComparison.Ordinal), "Guest agent doc must document non-behavior flags for semantic artifacts.");
        SmokeAssert.True(guestAgentDoc.Contains("--packet-capture", StringComparison.Ordinal), "Guest agent doc must document packet capture CLI.");
        SmokeAssert.True(guestAgentDoc.Contains("packet_capture.captured", StringComparison.Ordinal), "Guest agent doc must document captured packet events.");
        SmokeAssert.True(guestAgentDoc.Contains("pktmon", StringComparison.OrdinalIgnoreCase), "Guest agent doc must document pktmon capture.");
        SmokeAssert.True(guestAgentDoc.Contains("off by default", StringComparison.OrdinalIgnoreCase), "Guest agent doc must document memory dumps as opt-in.");
        SmokeAssert.True(artifactsDoc.Contains("memory-dumps/*.dmp", StringComparison.Ordinal), "Artifacts doc must document memory dump output.");
        SmokeAssert.True(artifactsDoc.Contains("memory_dump.sweep", StringComparison.Ordinal), "Artifacts doc must document memory dump sweep summary.");
        SmokeAssert.True(artifactsDoc.Contains("directChildCoverageState", StringComparison.Ordinal), "Artifacts doc must document direct-child memory dump coverage state.");
        SmokeAssert.True(artifactsDoc.Contains("deeperDescendantCoverageState", StringComparison.Ordinal), "Artifacts doc must document deeper descendant memory dump coverage state.");
        SmokeAssert.True(artifactsDoc.Contains("descendantCoverageCompleteness", StringComparison.Ordinal), "Artifacts doc must document descendant memory dump coverage completeness.");
        SmokeAssert.True(artifactsDoc.Contains("packet-captures/*.pcapng", StringComparison.Ordinal), "Artifacts doc must document packet-capture output.");
        SmokeAssert.True(artifactsDoc.Contains("packet_capture.captured", StringComparison.Ordinal), "Artifacts doc must document packet-capture event output.");
        SmokeAssert.True(artifactsDoc.Contains("dropped-files", StringComparison.Ordinal), "Artifacts doc must document dropped-file artifacts.");
        SmokeAssert.True(artifactsDoc.Contains("network.hosts.*", StringComparison.Ordinal), "Artifacts doc must document hosts snapshot telemetry.");
        SmokeAssert.True(artifactsDoc.Contains("network.proxy.*", StringComparison.Ordinal), "Artifacts doc must document proxy snapshot telemetry.");
        SmokeAssert.True(artifactsDoc.Contains("screenshots/", StringComparison.Ordinal), "Artifacts doc must document screenshot artifacts.");
        SmokeAssert.True(artifactsDoc.Contains("before,during,after", StringComparison.Ordinal), "Artifacts doc must document screenshot cadence metadata.");
        SmokeAssert.True(artifactsDoc.Contains("manifest.json` is always written", StringComparison.Ordinal), "Artifacts doc must document best-effort manifest output.");
        SmokeAssert.True(artifactsDoc.Contains("artifactRelativePath", StringComparison.Ordinal), "Artifacts doc must document artifact-relative event links.");
        SmokeAssert.True(artifactsDoc.Contains("artifactSelector", StringComparison.Ordinal), "Artifacts doc must document artifact selector event links.");
        SmokeAssert.True(artifactsDoc.Contains("largestArtifactSelector", StringComparison.Ordinal), "Artifacts doc must document largest artifact selectors.");
        SmokeAssert.True(artifactsDoc.Contains("reasonTaxonomy", StringComparison.Ordinal), "Artifacts doc must document artifact reason taxonomies.");
        SmokeAssert.True(artifactsDoc.Contains("behaviorCounted=false", StringComparison.Ordinal), "Artifacts doc must document behavior-count exclusion flags.");
        SmokeAssert.True(artifactsDoc.Contains("nonfatal", StringComparison.OrdinalIgnoreCase), "Artifacts doc must document nonfatal collection status.");
        SmokeAssert.True(artifactsDoc.Contains("rootProcessId", StringComparison.Ordinal), "Artifacts doc must document process identity fields.");
        SmokeAssert.True(artifactsDoc.Contains("lastReason", StringComparison.Ordinal), "Artifacts doc must document retained collection failure reasons.");
        SmokeAssert.True(frameworkDoc.Contains("IGuestProbe.CollectAsync", StringComparison.Ordinal), "Framework doc must document the probe extension point.");
        SmokeAssert.True(frameworkDoc.Contains("BoundedProcessRunner", StringComparison.Ordinal), "Framework doc must document bounded helper command execution.");
        SmokeAssert.True(frameworkDoc.Contains("collectionHealth", StringComparison.Ordinal), "Framework doc must document probe summary health events.");
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
