using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;

return SmokeTestProgram.Run(args);

/// <summary>
/// Lightweight smoke tests for the repository scaffold.
/// Inputs are optional command-line arguments, processing exercises config
/// loading, rule classification, runbook planning, and report writing, and
/// Run returns a process exit code.
/// </summary>
internal static class SmokeTestProgram
{
    /// <summary>
    /// Executes all smoke checks.
    /// Inputs are unused CLI arguments, processing throws on failed assertions,
    /// and the method returns zero when every check passes.
    /// </summary>
    public static int Run(string[] args)
    {
        try
        {
            var repositoryRoot = ResolveRepositoryRoot(AppContext.BaseDirectory);
            var rules = RuleEngine.LoadRuleSet(Path.Combine(repositoryRoot, "rules", "behavior-rules.json"));
            Assert(rules.Rules.Count > 0, "rules should load");
            AssertRuleClassification(rules);
            AssertExecutableScanning();
            AssertPlanningPipeline(repositoryRoot, rules);
            Console.WriteLine("Smoke tests passed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    /// <summary>
    /// Verifies that a synthetic process event matches the scripting rule.
    /// Inputs are loaded rules, processing classifies one event, and the method
    /// returns no value when the expected rule is present.
    /// </summary>
    private static void AssertRuleClassification(BehaviorRuleSet rules)
    {
        var engine = new RuleEngine(rules);
        var findings = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell",
                CommandLine = "powershell -NoProfile -ExecutionPolicy Bypass"
            }
        ]);

        Assert(findings.Any(finding => finding.RuleId == "script-interpreter"), "script rule should match");
    }

    /// <summary>
    /// Verifies that the WebUI backing scanner finds executable candidates.
    /// There are no inputs; processing creates a temporary directory with one
    /// benign .exe-named file; the method returns no value on success.
    /// </summary>
    private static void AssertExecutableScanning()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "KSwordSandboxScan", Guid.NewGuid().ToString("N"));
        var nested = Path.Combine(tempRoot, "nested");
        Directory.CreateDirectory(nested);
        var executablePath = Path.Combine(nested, "candidate.exe");
        File.WriteAllText(executablePath, "not a real executable; used only for scan tests");

        var scanner = new ExecutableTargetScanner();
        var result = scanner.Scan(new ExecutableScanRequest
        {
            Path = tempRoot,
            MaxDepth = 2,
            MaxResults = 10
        });

        Assert(result.Candidates.Any(candidate => candidate.FullPath == executablePath), "scanner should find nested executable candidate");
    }

    /// <summary>
    /// Verifies that a sample can be planned and report artifacts are written.
    /// Inputs are repository root and rules, processing creates a temporary
    /// benign sample file, and the method returns no value on success.
    /// </summary>
    private static void AssertPlanningPipeline(string repositoryRoot, BehaviorRuleSet rules)
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "KSwordSandboxSmoke", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        var samplePath = Path.Combine(tempRoot, "benign-sample.exe");
        File.WriteAllText(samplePath, "not a real executable; used only for host planning tests");

        var config = SandboxConfigLoader.Load(Path.Combine(repositoryRoot, "config", "sandbox.example.json"), repositoryRoot) with
        {
            Paths = new SandboxPaths
            {
                RuntimeRoot = tempRoot,
                RulesDirectory = Path.Combine(repositoryRoot, "rules")
            }
        };

        var service = new SandboxJobService(config, rules);
        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = true
        });

        Assert(job.Status == AnalysisStatus.Planned, "job should be planned");
        Assert(!string.IsNullOrWhiteSpace(job.Sample?.Md5), "md5 should be computed");
        Assert(!string.IsNullOrWhiteSpace(job.Sample?.Sha1), "sha1 should be computed");
        Assert(!string.IsNullOrWhiteSpace(job.Sample?.Crc32), "crc32 should be computed");
        Assert(job.Runbook is not null && job.Runbook.Steps.Count > 0, "runbook should contain steps");
        Assert(File.Exists(job.JsonReportPath), "json report should exist");
        Assert(File.Exists(job.HtmlReportPath), "html report should exist");

        var htmlReportPath = job.HtmlReportPath ?? throw new InvalidOperationException("html report path should be set");
        var html = File.ReadAllText(htmlReportPath);
        Assert(html.Contains("Risk summary", StringComparison.Ordinal), "html report should include risk summary");
        Assert(html.Contains("Static analysis", StringComparison.Ordinal), "html report should include static analysis");
        Assert(html.Contains("CRC32", StringComparison.Ordinal), "html report should include crc32");
    }

    /// <summary>
    /// Finds the repository root by walking upward from a start directory.
    /// The input is a directory path, processing searches for the solution file,
    /// and the method returns the root path or throws.
    /// </summary>
    private static string ResolveRepositoryRoot(string start)
    {
        var directory = new DirectoryInfo(start);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "KSwordSandbox.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not find KSwordSandbox.sln.");
    }

    /// <summary>
    /// Throws when a smoke-test condition is false.
    /// Inputs are a condition and message, processing raises an exception on
    /// failure, and the method returns no value when the condition is true.
    /// </summary>
    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}
