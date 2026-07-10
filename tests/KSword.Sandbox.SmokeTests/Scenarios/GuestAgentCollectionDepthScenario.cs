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
        var programText = ReadRepositoryText(context, "guest", "KSword.Sandbox.Agent", "Program.cs");

        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "process.tree", "Process tree probe must emit process.tree.");
        AssertFileContains(Path.Combine(collectionRoot, "ProcessTreeProbe.cs"), "CreateToolhelp32Snapshot", "Process tree probe must use low-privilege Toolhelp snapshots.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.created", "File diff probe must emit file.created.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.modified", "File diff probe must emit file.modified.");
        AssertFileContains(Path.Combine(collectionRoot, "FileDiffProbe.cs"), "file.deleted", "File diff probe must emit file.deleted.");
        AssertFileContains(Path.Combine(collectionRoot, "TcpConnectionDiffProbe.cs"), "network.tcp.closed", "TCP diff probe must emit closed connection deltas.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "IScreenshotCapture", "Screenshot interface must be present.");
        AssertFileContains(Path.Combine(collectionRoot, "ScreenshotProbe.cs"), "screenshot.skipped", "Screenshot capture must be non-fatal in unsupported sessions.");

        SmokeAssert.True(programText.Contains("new ProcessTreeProbe()", StringComparison.Ordinal), "Agent pipeline must include ProcessTreeProbe.");
        SmokeAssert.True(programText.Contains("new FileDiffProbe()", StringComparison.Ordinal), "Agent pipeline must include FileDiffProbe.");
        SmokeAssert.True(programText.Contains("new TcpConnectionDiffProbe()", StringComparison.Ordinal), "Agent pipeline must include TcpConnectionDiffProbe.");
        SmokeAssert.True(programText.Contains("new ScreenshotProbe()", StringComparison.Ordinal), "Agent pipeline must include ScreenshotProbe.");
        SmokeAssert.True(programText.Contains("CaptureScreenshots", StringComparison.Ordinal), "Agent options must carry screenshot enablement.");

        SmokeAssert.True(guestAgentDoc.Contains("process.tree", StringComparison.Ordinal), "Guest agent doc must document process.tree.");
        SmokeAssert.True(guestAgentDoc.Contains("network.tcp.closed", StringComparison.Ordinal), "Guest agent doc must document TCP closed deltas.");
        SmokeAssert.True(guestAgentDoc.Contains("--screenshot", StringComparison.Ordinal), "Guest agent doc must document screenshot CLI.");
        SmokeAssert.True(frameworkDoc.Contains("IGuestProbe.CollectAsync", StringComparison.Ordinal), "Framework doc must document the probe extension point.");
        SmokeAssert.True(frameworkDoc.Contains("IScreenshotCapture", StringComparison.Ordinal), "Framework doc must document screenshot capture interface.");

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
