using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Files;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.StaticAnalysis;
using KSword.Sandbox.SmokeTests.Framework;
using System.Text.Json;

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
            var scenarioSelection = ScenarioSelection.Parse(args);
            var repositoryRoot = ResolveRepositoryRoot(AppContext.BaseDirectory);
            if (scenarioSelection.ListScenarios)
            {
                foreach (var scenario in CreateScenarioInstances())
                {
                    Console.WriteLine(scenario.ScenarioId);
                }

                return 0;
            }

            if (scenarioSelection.HasFilters)
            {
                AssertScenarioContracts(repositoryRoot, scenarioSelection);
                Console.WriteLine("Selected smoke scenarios passed.");
                return 0;
            }

            var rules = RuleEngine.LoadRuleSet(Path.Combine(repositoryRoot, "rules", "behavior-rules.json"));
            Assert(rules.Rules.Count > 0, "rules should load");
            AssertRuleClassification(rules);
            AssertExecutableScanning();
            AssertStaticAnalysis(rules);
            AssertPlanningPipeline(repositoryRoot, rules);
            AssertScenarioContracts(repositoryRoot);
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
    /// Runs modular smoke-test scenarios that live under Scenarios/.
    /// Inputs are the repository root; processing creates a temporary runtime
    /// root and executes source/docs contract checks; the method returns no
    /// value when every scenario passes.
    /// </summary>
    private static void AssertScenarioContracts(string repositoryRoot, ScenarioSelection? scenarioSelection = null)
    {
        var runtimeRoot = Path.Combine(Path.GetTempPath(), "KSwordSandboxScenarioSmoke", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var context = new SmokeTestContext
        {
            RepositoryRoot = repositoryRoot,
            RuntimeRoot = runtimeRoot
        };
        var scenarios = CreateScenarioInstances();
        if (scenarioSelection is { HasFilters: true })
        {
            var filtered = scenarios
                .Where(scenario => scenarioSelection.Matches(scenario.ScenarioId))
                .ToList();
            Assert(
                filtered.Count > 0,
                "No smoke scenarios matched the requested filter(s). Available scenarios: " +
                string.Join(", ", scenarios.Select(scenario => scenario.ScenarioId)));
            scenarios = filtered;
        }

        var suite = new SmokeTestSuite(scenarios);
        var results = suite.RunAsync(context).GetAwaiter().GetResult();
        foreach (var result in results)
        {
            Assert(result.Passed, $"{result.ScenarioId} failed: {result.Message}");
            Console.WriteLine($"Scenario {result.ScenarioId}: {result.Message}");
        }
    }

    /// <summary>
    /// Discovers smoke scenarios compiled into this assembly.
    /// There are no inputs; processing instantiates non-abstract scenario
    /// classes with parameterless constructors and orders them by ScenarioId;
    /// the method returns ready-to-run scenario instances.
    /// </summary>
    private static IReadOnlyList<ISmokeTestScenario> CreateScenarioInstances()
    {
        return typeof(ISmokeTestScenario)
            .Assembly
            .GetTypes()
            .Where(type =>
                typeof(ISmokeTestScenario).IsAssignableFrom(type) &&
                type is { IsAbstract: false, IsInterface: false } &&
                type.GetConstructor(Type.EmptyTypes) is not null)
            .Select(type => (ISmokeTestScenario)Activator.CreateInstance(type)!)
            .OrderBy(scenario => scenario.ScenarioId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Describes optional scenario filters for quick quality gates.
    /// Inputs are smoke-test command-line arguments; processing accepts
    /// --scenario, --scenario-prefix, and --list-scenarios; the value is used
    /// to run a targeted subset without invoking broader smoke coverage.
    /// </summary>
    private sealed record ScenarioSelection(
        IReadOnlyList<string> ScenarioIds,
        IReadOnlyList<string> ScenarioPrefixes,
        bool ListScenarios)
    {
        public bool HasFilters => ScenarioIds.Count > 0 || ScenarioPrefixes.Count > 0;

        public static ScenarioSelection Parse(IReadOnlyList<string> args)
        {
            var ids = new List<string>();
            var prefixes = new List<string>();
            var listScenarios = false;

            for (var index = 0; index < args.Count; index++)
            {
                var arg = args[index];
                if (string.Equals(arg, "--list-scenarios", StringComparison.OrdinalIgnoreCase))
                {
                    listScenarios = true;
                    continue;
                }

                if (TryReadOptionValue(args, ref index, arg, "--scenario", out var scenarioValue) ||
                    TryReadOptionValue(args, ref index, arg, "--scenario-id", out scenarioValue) ||
                    TryReadOptionValue(args, ref index, arg, "-s", out scenarioValue))
                {
                    AddValues(ids, scenarioValue);
                    continue;
                }

                if (TryReadOptionValue(args, ref index, arg, "--scenario-prefix", out var prefixValue))
                {
                    AddValues(prefixes, prefixValue);
                }
            }

            return new ScenarioSelection(ids, prefixes, listScenarios);
        }

        public bool Matches(string scenarioId)
        {
            return ScenarioIds.Any(id => string.Equals(id, scenarioId, StringComparison.OrdinalIgnoreCase)) ||
                ScenarioPrefixes.Any(prefix => scenarioId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }

        private static bool TryReadOptionValue(
            IReadOnlyList<string> args,
            ref int index,
            string arg,
            string optionName,
            out string value)
        {
            value = string.Empty;
            if (arg.StartsWith(optionName + "=", StringComparison.OrdinalIgnoreCase))
            {
                value = arg[(optionName.Length + 1)..];
                return true;
            }

            if (string.Equals(arg, optionName, StringComparison.OrdinalIgnoreCase) &&
                index + 1 < args.Count)
            {
                index++;
                value = args[index];
                return true;
            }

            return false;
        }

        private static void AddValues(List<string> values, string rawValue)
        {
            foreach (var value in rawValue.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                values.Add(value);
            }
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
                RulesDirectory = Path.Combine(repositoryRoot, "rules"),
                GuestPayloadRoot = Path.Combine(tempRoot, "payload", "guest-tools")
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
        var runbook = job.Runbook ?? throw new InvalidOperationException("runbook should be set");
        Assert(runbook.Steps.Count > 0, "runbook should contain steps");
        var stagePayloadStep = runbook.Steps.Single(step => step.Id == "stage-guest-payload");
        Assert(stagePayloadStep.PowerShell.Contains("Copy-Item -ToSession", StringComparison.Ordinal), "runbook should copy guest payload through PowerShell Direct");
        Assert(stagePayloadStep.PowerShell.Contains(config.Paths.GuestPayloadRoot, StringComparison.Ordinal), "runbook should use configured host guest payload root");
        Assert(stagePayloadStep.PowerShell.Contains("KSword.Sandbox.Agent.exe", StringComparison.Ordinal), "runbook should validate guest agent path");
        Assert(stagePayloadStep.PowerShell.Contains("KSword.Sandbox.R0Collector.exe", StringComparison.Ordinal), "runbook should validate R0Collector path when driver is enabled");
        var runAgentStep = runbook.Steps.Single(step => step.Id == "run-agent");
        Assert(runAgentStep.PowerShell.Contains("--driver-events", StringComparison.Ordinal), "runbook should pass driver events path");
        Assert(runAgentStep.PowerShell.Contains($"{job.JobId:N}\\driver-events.jsonl", StringComparison.Ordinal), "runbook should use job-specific driver events path");
        Assert(runAgentStep.PowerShell.Contains("--r0collector", StringComparison.Ordinal), "runbook should pass R0Collector path");
        Assert(runAgentStep.PowerShell.Contains("--driver-device", StringComparison.Ordinal), "runbook should pass driver device path");
        var liveSyncStep = runbook.Steps.Single(step => step.Id == "sync-live-output");
        Assert(liveSyncStep.PowerShell.Contains("Copy-Item -FromSession", StringComparison.Ordinal), "runbook should sync guest output through PowerShell Direct");
        Assert(liveSyncStep.PowerShell.Contains($"{job.JobId:N}", StringComparison.Ordinal), "live sync should target the job-specific guest output directory");
        Assert(runbook.Steps.Any(step => step.Id == "collect-output"), "runbook should keep a final guest output collection step");
        Assert(File.Exists(job.JsonReportPath), "json report should exist");
        Assert(File.Exists(job.HtmlReportPath), "html report should exist");
        var savedExecutionJob = service.SaveRunbookExecutionResult(job.JobId, new SandboxRunbookExecutionResult
        {
            JobId = job.JobId,
            TargetVmName = runbook.TargetVmName,
            Mode = SandboxRunbookExecutionMode.DryRun,
            Success = true,
            TotalSteps = runbook.Steps.Count,
            ExecutedSteps = 0,
            StartedAtUtc = DateTimeOffset.UtcNow,
            Duration = TimeSpan.Zero,
            RequiresElevation = true
        });
        Assert(File.Exists(savedExecutionJob.RunbookExecutionResultPath), "runbook execution result should be persisted");

        var eventsPath = WriteSyntheticGuestEvents(savedExecutionJob);
        AssertLiveEventSnapshotShape(service, savedExecutionJob.JobId, eventsPath);
        var importedJob = service.ImportGuestEvents(savedExecutionJob.JobId, eventsPath);
        Assert(importedJob.Status == AnalysisStatus.Completed, "imported job should be completed");
        Assert(File.Exists(importedJob.JsonReportPath), "refreshed json report should exist");
        Assert(File.Exists(importedJob.HtmlReportPath), "refreshed html report should exist");
        AssertBilingualHtmlReports(importedJob);
        AssertRefreshedReportJson(importedJob);
        var refreshedExecutionJob = service.SaveRunbookExecutionResult(importedJob.JobId, new SandboxRunbookExecutionResult
        {
            JobId = importedJob.JobId,
            TargetVmName = runbook.TargetVmName,
            Mode = SandboxRunbookExecutionMode.DryRun,
            Success = true,
            TotalSteps = runbook.Steps.Count,
            ExecutedSteps = runbook.Steps.Count,
            StartedAtUtc = DateTimeOffset.UtcNow,
            Duration = TimeSpan.FromSeconds(1),
            RequiresElevation = true
        });
        AssertRefreshedReportJson(refreshedExecutionJob);
        AssertBilingualHtmlReports(refreshedExecutionJob);

        var htmlReportPath = importedJob.HtmlReportPath ?? throw new InvalidOperationException("html report path should be set");
        var html = File.ReadAllText(htmlReportPath);
        Assert(html.Contains("Risk summary", StringComparison.Ordinal), "html report should include risk summary");
        Assert(html.Contains("Static analysis", StringComparison.Ordinal), "html report should include static analysis");
        Assert(html.Contains("CRC32", StringComparison.Ordinal), "html report should include crc32");
        Assert(html.Contains("PE sections", StringComparison.Ordinal), "html report should include pe sections");
        Assert(html.Contains("Process details", StringComparison.Ordinal), "html report should include process details");
        Assert(html.Contains("Dropped files", StringComparison.Ordinal), "html report should include dropped files");
        Assert(html.Contains("Network behavior", StringComparison.Ordinal), "html report should include network behavior");
        Assert(html.Contains("Outbound TCP activity observed", StringComparison.Ordinal), "html report should include network finding");
        Assert(html.Contains("Dropped or modified file", StringComparison.Ordinal), "html report should include file finding");
        Assert(html.Contains("Registry modification observed", StringComparison.Ordinal), "html report should include driver jsonl finding");
        Assert(html.Contains("R0 collector mock driver event", StringComparison.Ordinal), "html report should include R0 collector finding");
        Assert(html.Contains("r0collector.mockDriverEvent", StringComparison.Ordinal), "html report should include raw R0 event type");
        Assert(html.Contains("driver-events.jsonl", StringComparison.Ordinal), "html report should include the imported R0 mock JSONL source path");
        Assert(html.Contains("Raw normalized events", StringComparison.Ordinal), "html report should include raw events section");
    }

    /// <summary>
    /// Verifies that report regeneration writes explicit Chinese and English
    /// HTML variants beside the default compatibility report.
    /// </summary>
    private static void AssertBilingualHtmlReports(AnalysisJob job)
    {
        Assert(!string.IsNullOrWhiteSpace(job.HtmlReportZhPath), "job should expose report.zh.html path");
        Assert(!string.IsNullOrWhiteSpace(job.HtmlReportEnPath), "job should expose report.en.html path");
        var zhPath = job.HtmlReportZhPath ?? throw new InvalidOperationException("job should expose report.zh.html path");
        var enPath = job.HtmlReportEnPath ?? throw new InvalidOperationException("job should expose report.en.html path");
        Assert(string.Equals(Path.GetFileName(zhPath), "report.zh.html", StringComparison.OrdinalIgnoreCase), "Chinese report file name should be report.zh.html");
        Assert(string.Equals(Path.GetFileName(enPath), "report.en.html", StringComparison.OrdinalIgnoreCase), "English report file name should be report.en.html");
        Assert(File.Exists(zhPath), "refreshed Chinese html report should exist");
        Assert(File.Exists(enPath), "refreshed English html report should exist");

        var chineseHtml = File.ReadAllText(zhPath);
        var englishHtml = File.ReadAllText(enPath);
        Assert(chineseHtml.Contains("<html lang=\"zh-CN\">", StringComparison.Ordinal), "Chinese html report should set zh-CN metadata");
        Assert(englishHtml.Contains("<html lang=\"en\">", StringComparison.Ordinal), "English html report should set English language metadata");
        Assert(chineseHtml.Contains("driver-events.jsonl", StringComparison.Ordinal), "Chinese html report should include imported driver JSONL evidence");
        Assert(englishHtml.Contains("driver-events.jsonl", StringComparison.Ordinal), "English html report should include imported driver JSONL evidence");
        Assert(chineseHtml.Contains("原始事件", StringComparison.Ordinal), "Chinese html report should include localized raw events section");
        Assert(englishHtml.Contains("Raw normalized events", StringComparison.Ordinal), "English html report should include raw events section");
    }

    /// <summary>
    /// Verifies live event polling shape without requiring a real VM.
    /// Inputs are the job service, job ID, and synthetic events.json path;
    /// processing reads the same guest folder that the Web endpoint uses,
    /// checks paging metadata, and serializes with Web JSON defaults to validate
    /// the camelCase endpoint contract; the method returns no value.
    /// </summary>
    private static void AssertLiveEventSnapshotShape(SandboxJobService service, Guid jobId, string eventsPath)
    {
        var snapshot = service.GetLiveEvents(jobId, offset: 0, take: 2);
        Assert(snapshot.JobId == jobId, "live snapshot should carry the requested job id");
        Assert(snapshot.TotalEvents >= 5, "live snapshot should include events.json plus driver-events.jsonl rows");
        Assert(snapshot.Events.Count == 2, "live snapshot should honor take paging");
        Assert(snapshot.NextOffset == 2, "live snapshot should advance next offset by returned event count");
        Assert(snapshot.HasMore, "live snapshot should report more events when page is truncated");
        Assert(snapshot.Sources.Any(source => string.Equals(source, eventsPath, StringComparison.OrdinalIgnoreCase)), "live snapshot should include events.json source");
        Assert(snapshot.Sources.Any(source => string.Equals(Path.GetFileName(source), "driver-events.jsonl", StringComparison.OrdinalIgnoreCase)), "live snapshot should include driver-events.jsonl source");
        Assert(snapshot.Sources.Any(source => string.Equals(Path.GetFileName(source), "partial-driver-events.jsonl", StringComparison.OrdinalIgnoreCase)), "live snapshot should tolerate and list a partially written JSONL source");

        var fullSnapshot = service.GetLiveEvents(jobId, offset: 0, take: 100);
        Assert(fullSnapshot.Events.Any(evt => string.Equals(evt.EventType, "process.start", StringComparison.OrdinalIgnoreCase)), "live snapshot should include process event");
        Assert(fullSnapshot.Events.Any(evt => string.Equals(evt.EventType, "file.created", StringComparison.OrdinalIgnoreCase)), "live snapshot should include file event");
        Assert(fullSnapshot.Events.Any(evt => string.Equals(evt.EventType, "network.tcp", StringComparison.OrdinalIgnoreCase)), "live snapshot should include network event");
        Assert(fullSnapshot.Events.Any(evt => string.Equals(evt.EventType, "registry.set", StringComparison.OrdinalIgnoreCase)), "live snapshot should include synthetic driver registry event");
        Assert(fullSnapshot.Events.Any(evt => string.Equals(evt.EventType, "r0collector.mockDriverEvent", StringComparison.OrdinalIgnoreCase)), "live snapshot should include synthetic R0 collector event");

        var json = JsonSerializer.Serialize(fullSnapshot, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert(root.TryGetProperty("jobId", out var jsonJobId) && Guid.Parse(jsonJobId.GetString() ?? string.Empty) == jobId, "live endpoint JSON should expose camelCase jobId");
        Assert(root.TryGetProperty("retrievedAt", out _), "live endpoint JSON should expose retrievedAt");
        Assert(root.TryGetProperty("totalEvents", out var totalEvents) && totalEvents.GetInt32() == fullSnapshot.TotalEvents, "live endpoint JSON should expose totalEvents");
        Assert(root.TryGetProperty("nextOffset", out var nextOffset) && nextOffset.GetInt32() == fullSnapshot.NextOffset, "live endpoint JSON should expose nextOffset");
        Assert(root.TryGetProperty("hasMore", out var hasMore) && hasMore.ValueKind is JsonValueKind.True or JsonValueKind.False, "live endpoint JSON should expose hasMore boolean");
        Assert(root.TryGetProperty("sources", out var sources) && sources.ValueKind == JsonValueKind.Array && sources.GetArrayLength() >= 2, "live endpoint JSON should expose sources array");
        Assert(root.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array && events.GetArrayLength() >= 5, "live endpoint JSON should expose events array");

        var firstEvent = events.EnumerateArray().First();
        Assert(firstEvent.TryGetProperty("eventType", out _), "live endpoint event JSON should expose eventType");
        Assert(firstEvent.TryGetProperty("timestamp", out _), "live endpoint event JSON should expose timestamp");
        Assert(firstEvent.TryGetProperty("source", out _), "live endpoint event JSON should expose source");
        Assert(firstEvent.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object, "live endpoint event JSON should expose data object");
    }

    /// <summary>
    /// Verifies regenerated report JSON after guest event import.
    /// The input is the imported job, processing deserializes report.json and
    /// checks status, metrics, raw event merge, import counts, and R0/driver
    /// event presence; the method returns no value.
    /// </summary>
    private static void AssertRefreshedReportJson(AnalysisJob importedJob)
    {
        var reportPath = importedJob.JsonReportPath ?? throw new InvalidOperationException("json report path should be set");
        var report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(reportPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidOperationException("report.json should deserialize");
        Assert(report.Status == AnalysisStatus.Completed, "report json should be regenerated with completed status");
        var importEvent = report.Events.FirstOrDefault(evt => string.Equals(evt.EventType, "guest.events.imported", StringComparison.OrdinalIgnoreCase));
        Assert(importEvent is not null, "report json should include guest import marker");
        Assert(string.Equals(importEvent!.Path, importedJob.GuestEventsPath, StringComparison.OrdinalIgnoreCase), "guest import marker should point at the imported events.json path");
        Assert(
            importEvent.Data.TryGetValue("eventCount", out var importedCountText) &&
            int.TryParse(importedCountText, out var importedCount) &&
            importedCount == 5,
            "guest import marker should count events.json plus sibling R0 mock JSONL rows");
        Assert(report.Events.Any(evt => string.Equals(evt.EventType, "registry.set", StringComparison.OrdinalIgnoreCase)), "report json should include driver registry jsonl event");
        var r0MockEvent = report.Events.FirstOrDefault(evt => string.Equals(evt.EventType, "r0collector.mockDriverEvent", StringComparison.OrdinalIgnoreCase));
        Assert(r0MockEvent is not null, "report json should include synthetic R0 collector jsonl event");
        Assert(
            r0MockEvent!.Data.TryGetValue("mock", out var mockFlag) &&
            string.Equals(mockFlag, "true", StringComparison.OrdinalIgnoreCase),
            "synthetic R0 collector jsonl event should retain mock=true evidence");
        Assert(
            r0MockEvent.Data.TryGetValue("driverEventPath", out var driverEventPath) &&
            string.Equals(driverEventPath, "driver-events.jsonl", StringComparison.OrdinalIgnoreCase),
            "synthetic R0 collector jsonl event should retain the driver-events.jsonl source clue");
        Assert(report.Findings.Any(finding => finding.RuleId == "registry-change"), "report json should include registry rule finding");
        Assert(!report.Findings.Any(finding => finding.RuleId == "r0collector-mock-driver-event"), "R0 collector mock plumbing should not become a behavior-rule finding");
        Assert(report.Metrics.TryGetValue("events.total", out var eventCount) && eventCount == report.Events.Count, "report metrics should count all raw events");
    }

    /// <summary>
    /// Writes synthetic guest output for report-regeneration smoke coverage.
    /// The input is a planned job, processing creates events.json and driver
    /// JSONL under the expected job guest folder, and the method returns the
    /// primary events.json path.
    /// </summary>
    private static string WriteSyntheticGuestEvents(AnalysisJob job)
    {
        var reportPath = job.JsonReportPath ?? throw new InvalidOperationException("job report path should be set");
        var jobRoot = Path.GetDirectoryName(reportPath) ?? throw new InvalidOperationException("job root should be discoverable");
        var guestRoot = Path.Combine(jobRoot, "guest", job.JobId.ToString("N"));
        Directory.CreateDirectory(guestRoot);

        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell",
                ProcessId = 4242,
                Path = "C:\\KSwordSandbox\\incoming\\benign-sample.exe",
                CommandLine = "powershell -NoProfile -ExecutionPolicy Bypass"
            },
            new()
            {
                EventType = "file.created",
                Source = "guest",
                Path = "C:\\Users\\Public\\ksword-smoke-drop.bin"
            },
            new()
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["remoteAddress"] = "203.0.113.10",
                    ["remotePort"] = "443",
                    ["state"] = "Established"
                }
            }
        };

        var eventsPath = Path.Combine(guestRoot, "events.json");
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(events, new JsonSerializerOptions { WriteIndented = true }));
        var driverEvent = new SandboxEvent
        {
            EventType = "registry.set",
            Source = "driver",
            ProcessId = 4242,
            Path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SandboxSmoke",
            Data =
            {
                ["value"] = "C:\\KSwordSandbox\\incoming\\benign-sample.exe"
            }
        };
        var r0Event = new SandboxEvent
        {
            EventType = "r0collector.mockDriverEvent",
            Source = "r0collector",
            ProcessId = 4242,
            Path = @"\\.\KSwordSandboxDriver",
            Data =
            {
                ["mock"] = "true",
                ["driverEventPath"] = "driver-events.jsonl"
            }
        };
        File.WriteAllLines(
            Path.Combine(guestRoot, "driver-events.jsonl"),
            [
                JsonSerializer.Serialize(driverEvent),
                JsonSerializer.Serialize(r0Event)
            ]);
        File.WriteAllText(
            Path.Combine(guestRoot, "partial-driver-events.jsonl"),
            "{\"eventType\":\"driver.file\",\"source\":\"driver\"");
        return eventsPath;
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
