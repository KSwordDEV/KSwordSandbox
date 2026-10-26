using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// A real Thanos run created *.locked counterparts and deleted originals while
/// the filesystem watcher had no owner PID. Verify that the paired burst is
/// promoted, but isolated suffixes and unrelated notes remain raw evidence.
/// </summary>
internal sealed class RansomwareFilePairBurstScenario : ISmokeTestScenario
{
    public string ScenarioId => "rules.ransomware-file-pair-burst";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var engine = new RuleEngine(RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json")));
        var start = DateTimeOffset.UtcNow;
        var originals = new[] { "budget.xlsx", "notes.txt", "photo.jpg", "presentation.pptx", "ledger.csv" };
        var positive = CreateBatch(start, originals, includeStart: true, includeDeletes: true, includeNote: true);
        var promoted = RansomwareFilePairClassifier.Apply(positive);
        var findings = engine.Classify(promoted);
        RequireHigh(findings, "ransomware-encryption-classified-file-event");
        RequireHigh(findings, "ransomware-ransom-note-file-created");
        SmokeAssert.True(promoted.Count(evt => evt.EventType == "file.created" &&
            evt.Path?.EndsWith(".locked", StringComparison.OrdinalIgnoreCase) == true &&
            evt.Data.TryGetValue("classification", out var classification) && classification == "ransomware") == 5,
            "All five exact created/deleted file pairs must carry the derived classification.");
        var unrelatedNote = promoted.Single(evt => evt.Path?.Contains(@"\Desktop\HOW_TO_DECYPHER_FILES.txt", StringComparison.OrdinalIgnoreCase) == true);
        SmokeAssert.True(unrelatedNote.Data["behaviorCounted"] == "false",
            "A same-name note outside a paired directory must remain unattributed.");

        RequireNoBurst(engine, CreateBatch(start, originals[..4], true, true, true), "Four pairs are below threshold.");
        var duplicateNotifications = CreateBatch(start, originals[..2], true, true, true);
        var repeatedCreates = duplicateNotifications
            .Where(evt => evt.EventType == "file.created" &&
                evt.Path?.EndsWith(".locked", StringComparison.OrdinalIgnoreCase) == true)
            .ToArray();
        foreach (var created in repeatedCreates)
        {
            for (var repeat = 0; repeat < 3; repeat++)
            {
                duplicateNotifications.Add(Watcher("file.created", created.Path!, created.Timestamp.AddMilliseconds(repeat + 1), correlated: true));
            }
        }
        RequireNoBurst(engine, duplicateNotifications,
            "Repeated watcher creation notifications for two originals must not inflate the distinct-pair threshold.");
        RequireNoBurst(engine, CreateBatch(start, originals, true, false, true), "Suffix creation without original deletion is insufficient.");
        RequireNoBurst(engine, CreateBatch(start, originals, false, true, true), "A burst without a sample start is insufficient.");
        RequireNoBurst(engine, CreateBatch(start, ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"], true, true, true),
            "Single-extension temp-file churn is insufficient.");
        RequireNoBurst(engine, CreateBatch(start, originals, true, true, true, delayed: true),
            "Pairs outside the sample window are insufficient.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Five diverse same-path create/delete pairs and a colocated ransom note promote high-risk findings; weak controls remain raw."
        });
    }

    private static List<SandboxEvent> CreateBatch(
        DateTimeOffset start,
        IReadOnlyList<string> names,
        bool includeStart,
        bool includeDeletes,
        bool includeNote,
        bool delayed = false)
    {
        const string directory = @"C:\Users\Analyst\Documents\Decoys";
        var rows = new List<SandboxEvent>();
        if (includeStart)
        {
            rows.Add(new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                Timestamp = start,
                ProcessId = 912,
                Path = @"C:\KSwordSandbox\incoming\sample.exe"
            });
        }

        for (var index = 0; index < names.Count; index++)
        {
            var original = directory + "\\" + names[index];
            var when = start.AddSeconds(delayed ? 180 + index : index + 1);
            rows.Add(Watcher("file.created", original + ".locked", when, correlated: true));
            if (includeDeletes)
            {
                rows.Add(Watcher("file.deleted", original, when.AddMilliseconds(100), correlated: false));
            }
        }

        if (includeNote)
        {
            rows.Add(Watcher("file.created", directory + @"\HOW_TO_DECYPHER_FILES.txt", start.AddSeconds(7), correlated: false));
            rows.Add(Watcher("file.created", @"C:\Users\Analyst\Desktop\HOW_TO_DECYPHER_FILES.txt", start.AddSeconds(7), correlated: false));
        }

        return rows;
    }

    private static SandboxEvent Watcher(string type, string path, DateTimeOffset when, bool correlated) => new()
    {
        EventType = type,
        Source = "guest",
        Timestamp = when,
        Path = path,
        Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "filesystem-watcher",
            ["capturePhase"] = "during-run",
            ["sampleCorrelation"] = correlated ? "probable" : "unknown",
            ["behaviorCounted"] = correlated ? "true" : "false",
            ["sampleBehaviorCandidate"] = correlated ? "true" : "false",
            ["nonbehavior"] = correlated ? "false" : "true",
            ["notSampleBehavior"] = correlated ? "false" : "true"
        }
    };

    private static void RequireHigh(IEnumerable<BehaviorFinding> findings, string ruleId) =>
        SmokeAssert.True(findings.Any(finding => finding.RuleId == ruleId && finding.Severity == "high"),
            $"Expected high-risk finding {ruleId}.");

    private static void RequireNoBurst(RuleEngine engine, IReadOnlyList<SandboxEvent> rows, string message)
    {
        var findings = engine.Classify(RansomwareFilePairClassifier.Apply(rows));
        SmokeAssert.True(findings.All(finding =>
                finding.RuleId != "ransomware-encryption-classified-file-event" &&
                finding.RuleId != "ransomware-ransom-note-file-created"), message);
    }
}
