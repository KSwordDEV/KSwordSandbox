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
        RequireContains(ReadText(Path.Combine(sourceRoot, "Options.cpp")), "--heartbeat", "heartbeat should be parsed.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "IoctlClient.cpp")), "request.Flags = options.enableMask", "enable-mask should flow to READ_EVENTS request flags.");
        RequireContains(ReadText(Path.Combine(sourceRoot, "RuntimeLoop.cpp")), "r0collector.heartbeat", "heartbeat rows should be emitted by the runtime loop.");

        foreach (var option in new[] { "--self-test", "--synthetic", "--enable-mask", "--heartbeat", "--duration", "--poll-ms" })
        {
            RequireContains(collectorDoc, option, $"{option} should be documented in r0-collector.md.");
            RequireContains(schemaDoc, option, $"{option} should be documented in r0-jsonl-schema.md.");
        }

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
