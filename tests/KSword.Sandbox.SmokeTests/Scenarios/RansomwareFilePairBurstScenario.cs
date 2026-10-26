using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>Structural file transformation signals must not depend on malware filenames or suffixes.</summary>
internal sealed class RansomwareFilePairBurstScenario : ISmokeTestScenario
{
    private const string RuleId = "mass-user-file-transformation";
    private const string Directory = @"C:\Users\Analyst\Documents\Decoys";
    private static readonly string[] Names = ["budget.xlsx", "notes.txt", "photo.jpg", "presentation.pptx", "ledger.csv"];
    public string ScenarioId => "rules.batch-file-transformation";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var engine = new RuleEngine(RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json")));
        var start = DateTimeOffset.UtcNow;
        RequireCount(engine, Build(start, Names, false), 5, "Stable sibling outputs and deleted originals");
        RequireCount(engine, Build(start, Names, true), 5, "Temporary sibling renames and modified originals");
        RequireCount(engine, DirectRenames(start, Names), 5,
            "Preexisting originals directly renamed to changed-content siblings");
        RequireCount(engine, DirectRenames(start, Names, sameHash: true), 0,
            "Pure batch renaming without content change is insufficient");
        RequireCount(engine, DirectRenames(start, Names, originalStillExists: true), 0,
            "Retained originals make the batch a copy or backup, not a destructive conversion");
        RequireCount(engine, DirectRenames(start, Names, crossDirectory: true), 0,
            "Cross-directory direct renames are not appended sibling conversions");
        var repeatedDirectRenames = DirectRenames(start, Names[..2]);
        repeatedDirectRenames.AddRange(repeatedDirectRenames.Where(row => row.EventType == "file.renamed").ToArray());
        RequireCount(engine, repeatedDirectRenames, 0,
            "Duplicate rename notifications cannot inflate distinct original files");
        RequireCount(engine, DirectRenames(start, Names, missingBaselineHash: true), 0,
            "A size change without an authenticated before hash is insufficient");
        RequireCount(engine, Build(start, Names[..4], false), 0, "Four originals are below threshold");
        var duplicates = Build(start, Names[..2], false);
        duplicates.AddRange(duplicates.Where(row => row.EventType != "process.start").ToArray());
        RequireCount(engine, duplicates, 0, "Repeated watcher notifications cannot inflate unique originals");
        RequireCount(engine, Build(start, Names, false).Where(row => row.EventType != "file.deleted").ToList(), 0,
            "A backup copy retaining originals must not count as conversion");
        RequireCount(engine, Build(start, Names, false).Where(row => row.EventType != "file.modified").ToList(), 0,
            "Created siblings without stable output payloads are insufficient");
        RequireCount(engine, Build(start, Names, false).Where(row => row.EventType != "process.start").ToList(), 0,
            "A sample start is required");
        var unrelatedIncoming = Build(start, Names, false);
        unrelatedIncoming[0] = unrelatedIncoming[0] with
        {
            Path = @"C:\KSwordSandbox\incoming\unrelated.exe",
            Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };
        RequireCount(engine, unrelatedIncoming, 0,
            "An unrelated executable under incoming must not open a sample behavior window");
        RequireCount(engine, SampleCorrelationClassifier.Apply(unrelatedIncoming, @"C:\Host\submitted.exe"), 0,
            "The product correlation pipeline must not confirm a different incoming executable");
        unrelatedIncoming.Add(Start(start.AddMinutes(5)));
        RequireCount(engine, unrelatedIncoming, 0,
            "File changes before the confirmed submitted sample launch must not be attributed to it");
        RequireCount(engine, Build(start, ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"], false), 0,
            "A single original extension is insufficient");
        RequireCount(engine, Build(start, Names, false, splitDirectories: true), 0,
            "Separate directories cannot be combined");
        RequireCount(engine, Build(start, Names, false, delayed: true), 0,
            "Events outside the sample window are insufficient");
        RequireCount(engine, Build(start, Names, true, sameHash: true), 0,
            "Unchanged original and sibling hashes are insufficient");
        RequireCount(engine, Build(start, Names, true, wrongPreviousPath: true), 0,
            "A rename without a matching temporary precursor is insufficient");
        RequireCount(engine, Build(start, Names, true).Where(row => row.EventType != "file.modified").ToList(), 0,
            "A renamed sibling without original modification is insufficient");
        RequireCount(engine, AtomicSaves(start), 0,
            "Editor atomic saves that rename temporary files back to original names are insufficient");

        var forged = new List<SandboxEvent> { Start(start), Watcher("file.created", Directory + @"\report.txt.mystery", start.AddSeconds(1), 'A') };
        forged[1].Data["batchConversionVerified"] = "true";
        RequireCount(engine, forged, 0, "Untrusted input cannot forge the derived structural marker");
        var noteOnly = new List<SandboxEvent> { Start(start), Watcher("file.created", Directory + @"\HOW_TO_DECRYPT.txt", start.AddSeconds(1), 'A') };
        RequireCount(engine, noteOnly, 0, "A note-like filename alone cannot assert a high-risk transformation");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Three suffix-independent batch patterns classify; unchanged renames, backups, editor saves, duplicates, and forged markers do not."
        });
    }

    private static List<SandboxEvent> Build(DateTimeOffset start, IReadOnlyList<string> names, bool renamePattern,
        bool splitDirectories = false, bool delayed = false, bool sameHash = false, bool wrongPreviousPath = false)
    {
        var rows = new List<SandboxEvent> { Start(start) };
        for (var index = 0; index < names.Count; index++)
        {
            var directory = splitDirectories && index >= 3 ? @"C:\Users\Analyst\Desktop\Decoys" : Directory;
            var original = directory + "\\" + names[index];
            var output = original + ".opaque";
            var when = start.AddSeconds((delayed ? 180 : 1) + index);
            if (renamePattern)
            {
                var temporary = original + ".phase1";
                rows.Add(Watcher("file.created", temporary, when, 'A'));
                var renamed = Watcher("file.renamed", output, when.AddMilliseconds(100), 'A');
                renamed.Data["previousPath"] = wrongPreviousPath ? original + ".unseen" : temporary;
                rows.Add(renamed);
                rows.Add(Watcher("file.modified", original, when.AddMilliseconds(200), sameHash ? 'A' : 'B'));
            }
            else
            {
                rows.Add(Watcher("file.created", output, when, 'A'));
                rows.Add(Watcher("file.modified", output, when.AddMilliseconds(100), 'A'));
                rows.Add(Watcher("file.deleted", original, when.AddMilliseconds(200), null));
            }
        }
        return rows;
    }

    private static List<SandboxEvent> AtomicSaves(DateTimeOffset start)
    {
        var rows = new List<SandboxEvent> { Start(start) };
        for (var index = 0; index < Names.Length; index++)
        {
            var original = Directory + "\\" + Names[index];
            var temporary = original + ".tmp";
            var when = start.AddSeconds(index + 1);
            rows.Add(Watcher("file.created", temporary, when, 'A'));
            var rename = Watcher("file.renamed", original, when.AddMilliseconds(100), 'A');
            rename.Data["previousPath"] = temporary;
            rows.Add(rename);
            rows.Add(Watcher("file.modified", original, when.AddMilliseconds(200), 'B'));
        }
        return rows;
    }

    private static List<SandboxEvent> DirectRenames(
        DateTimeOffset start,
        IReadOnlyList<string> names,
        bool sameHash = false,
        bool originalStillExists = false,
        bool crossDirectory = false,
        bool missingBaselineHash = false)
    {
        var rows = new List<SandboxEvent> { Start(start) };
        for (var index = 0; index < names.Count; index++)
        {
            var original = Directory + "\\" + names[index];
            var output = crossDirectory
                ? @"C:\Users\Analyst\Desktop\Decoys\" + names[index] + ".opaque"
                : original + ".opaque";
            var renamed = Watcher("file.renamed", output, start.AddSeconds(index + 1),
                sameHash ? 'A' : 'B');
            renamed.Data["previousPath"] = original;
            renamed.Data["sourcePath"] = original;
            renamed.Data["destinationPath"] = output;
            renamed.Data["contentBaselineStatus"] = "captured";
            renamed.Data["baselineHashStatus"] = missingBaselineHash ? "not-computed" : "computed";
            renamed.Data["baselineSha256"] = missingBaselineHash ? "" : new string('A', 64);
            renamed.Data["baselineSizeBytes"] = "4096";
            renamed.Data["baselineCapturedAtUtc"] = start.AddSeconds(-1).ToString("O");
            renamed.Data["contentChangeComparisonState"] = "compared";
            renamed.Data["contentChangedFromBaseline"] = sameHash ? "false" : "true";
            renamed.Data["previousPathAbsentAtDrain"] = originalStillExists ? "false" : "true";
            renamed.Data["hashStatus"] = "computed";
            renamed.Data["sizeBytes"] = sameHash ? "4096" : "4360";
            rows.Add(renamed);
        }
        return rows;
    }

    private static SandboxEvent Start(DateTimeOffset when) => new()
    {
        EventType = "process.start", Source = "guest", Timestamp = when,
        ProcessId = 912, Path = @"C:\KSwordSandbox\incoming\sample.exe",
        Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sampleCorrelationClassifier"] = "core-sample-correlation-v1",
            ["sampleCorrelation"] = "confirmed",
            ["strongSampleCorrelation"] = "true",
            ["actorProcessId"] = "912",
            ["actorProcessImagePath"] = @"C:\KSwordSandbox\incoming\sample.exe"
        }
    };

    private static SandboxEvent Watcher(string type, string path, DateTimeOffset when, char? hash) => new()
    {
        EventType = type, Source = "guest", Timestamp = when, Path = path,
        Data = hash is null
            ? new(StringComparer.OrdinalIgnoreCase) { ["captureSource"] = "filesystem-watcher", ["capturePhase"] = "during-run" }
            : new(StringComparer.OrdinalIgnoreCase)
            {
                ["captureSource"] = "filesystem-watcher", ["capturePhase"] = "during-run",
                ["sha256"] = new string(hash.Value, 64), ["sizeBytes"] = "4096"
            }
    };

    private static void RequireCount(RuleEngine engine, IReadOnlyList<SandboxEvent> rows, int expected, string reason)
    {
        var promoted = BatchFileTransformationClassifier.Apply(rows);
        var observed = promoted.Count(row => row.Data.TryGetValue("batchConversionVerified", out var value) && value == "true");
        SmokeAssert.True(observed == expected, $"{reason}: expected {expected} correlated outputs, got {observed}.");
        var high = engine.Classify(promoted).Where(finding => finding.RuleId == RuleId && finding.Severity == "high").ToArray();
        var expectedFindingCount = expected > 0 ? 1 : 0;
        SmokeAssert.True(high.Length == expectedFindingCount,
            $"{reason}: expected {expectedFindingCount} grouped high findings, got {high.Length}.");
    }
}
