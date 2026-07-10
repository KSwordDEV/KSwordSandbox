using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.StaticAnalysis;

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
            AssertStaticAnalysis(rules);
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
    /// Verifies that host static analysis parses a minimal PE-like sample and
    /// feeds static tags into behavior rules.
    /// Inputs are loaded rules, processing creates a bounded synthetic PE file,
    /// and the method returns no value on success.
    /// </summary>
    private static void AssertStaticAnalysis(BehaviorRuleSet rules)
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "KSwordSandboxStatic", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        var samplePath = Path.Combine(tempRoot, "packed.exe");
        WriteMinimalPe(samplePath);

        var analyzer = new StaticAnalyzer();
        var result = analyzer.Analyze(samplePath);
        Assert(result.IsPe, "static analyzer should parse minimal PE");
        Assert(result.Tags.Contains("packer_upx"), "static analyzer should tag UPX section");

        var engine = new RuleEngine(rules);
        var findings = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "static.analysis.completed",
                Source = "host",
                Path = samplePath,
                Data =
                {
                    ["tags"] = string.Join(",", result.Tags)
                }
            }
        ]);

        Assert(findings.Any(finding => finding.RuleId == "static-pe-known-packer"), "static packer rule should match");
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
        Assert(html.Contains("PE sections", StringComparison.Ordinal), "html report should include pe sections");
    }

    /// <summary>
    /// Writes a tiny PE-shaped file for parser smoke tests.
    /// The input is an output path, processing writes DOS, PE, optional-header,
    /// and one UPX-named section, and the method returns no value.
    /// </summary>
    private static void WriteMinimalPe(string path)
    {
        var buffer = new byte[1024];
        WriteUInt16(buffer, 0x00, 0x5a4d);
        WriteUInt32(buffer, 0x3c, 0x80);
        WriteUInt32(buffer, 0x80, 0x00004550);
        WriteUInt16(buffer, 0x84, 0x8664);
        WriteUInt16(buffer, 0x86, 1);
        WriteUInt16(buffer, 0x94, 0xf0);
        WriteUInt16(buffer, 0x98, 0x20b);
        WriteUInt32(buffer, 0xa8, 0x1000);
        WriteUInt16(buffer, 0xdc, 2);
        var sectionOffset = 0x188;
        var name = "UPX0"u8;
        name.CopyTo(buffer.AsSpan(sectionOffset, name.Length));
        WriteUInt32(buffer, sectionOffset + 8, 0x1000);
        WriteUInt32(buffer, sectionOffset + 12, 0x1000);
        WriteUInt32(buffer, sectionOffset + 16, 0x200);
        WriteUInt32(buffer, sectionOffset + 20, 0x200);
        for (var index = 0x200; index < 0x400; index++)
        {
            buffer[index] = (byte)(index % 251);
        }

        File.WriteAllBytes(path, buffer);
    }

    /// <summary>
    /// Writes a little-endian UInt16 into a byte buffer.
    /// Inputs are a buffer, offset, and value; processing writes bytes in place;
    /// the method returns no value.
    /// </summary>
    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        BitConverter.GetBytes(value).CopyTo(buffer, offset);
    }

    /// <summary>
    /// Writes a little-endian UInt32 into a byte buffer.
    /// Inputs are a buffer, offset, and value; processing writes bytes in place;
    /// the method returns no value.
    /// </summary>
    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        BitConverter.GetBytes(value).CopyTo(buffer, offset);
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
