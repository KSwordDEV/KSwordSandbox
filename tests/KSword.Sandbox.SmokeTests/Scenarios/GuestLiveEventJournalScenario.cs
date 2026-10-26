using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Agent.Output;
using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Exercises the durable guest lane without executing a submitted sample.
/// A reset after the second append must retain complete rows, and a capacity
/// failure must be explicit rather than silently claiming a complete journal.
/// </summary>
internal sealed class GuestLiveEventJournalScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest.live-event-journal.contract";

    public Task<SmokeTestResult> RunAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var root = Path.Combine(Path.GetTempPath(), "ksword-live-journal-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            VerifyPrelaunchIdentity(root, context);
            var jobId = Guid.NewGuid();
            var sampleSha256 = new string('A', 64);
            var samplePath = @"C:\incoming\benign.exe";
            var rows = new List<SandboxEvent>
            {
                new() { EventType = "agent.start", Path = samplePath },
                new() { EventType = "process.start", ProcessId = 1234, Path = samplePath }
            };
            using (var journal = DurableEventJournal.Create(root))
            {
                DurableEventJournal.WriteIdentity(root, jobId, samplePath,
                    new SampleLaunchProofWriter.SampleIdentity(sampleSha256, 1024));
                SmokeAssert.True(journal.AppendNew(rows), "First append must flush complete rows.");
                SmokeAssert.True(journal.AppendNew(rows), "Replaying the same event list must not duplicate rows.");
                rows.Add(new SandboxEvent { EventType = "file.modified", Path = @"C:\Users\SandboxUser\Documents\a.txt" });
                SmokeAssert.True(journal.AppendNew(rows), "Later events must append to the same stream.");
                SmokeAssert.True(journal.WrittenCount == 3, "Each event must appear exactly once in the journal.");
            }

            var path = Path.Combine(root, DurableEventJournal.FileName);
            var lines = File.ReadAllLines(path);
            SmokeAssert.True(lines.Length == 3, "A simulated Agent stop before events.json must leave three complete lines.");
            var eventTypes = lines.Select(line =>
            {
                using var document = JsonDocument.Parse(line);
                return document.RootElement.GetProperty("EventType").GetString();
            }).ToArray();
            SmokeAssert.True(eventTypes.SequenceEqual(new[] { "agent.start", "process.start", "file.modified" }),
                "The durable journal must preserve event order and process.start evidence.");
            var firstEvent = JsonSerializer.Deserialize<SandboxEvent>(lines[0]);
            SmokeAssert.True(firstEvent?.Data.TryGetValue("behaviorCounted", out var counted) == true && counted == "false",
                "Journal serialization must apply Agent self-noise flags before a destructive reset.");
            var recovered = GuestLiveEventJournalReader.ReadValidated(path, jobId, sampleSha256, 1024);
            SmokeAssert.True(recovered.Count == 3, "Validated import must read the three complete rows.");
            SampleLaunchProofWriter.Write(root, jobId, samplePath,
                new SampleLaunchProofWriter.SampleIdentity(sampleSha256, 1024),
                1234, 1000, DateTimeOffset.UtcNow);
            var partialDiagnostics = GuestFailureArtifactImporter.Import(root);
            SmokeAssert.True(partialDiagnostics.Any(evt => evt.EventType == "agent.run.failed"),
                "A live journal without final events.json must remain a failed collection.");
            SmokeAssert.True(!partialDiagnostics.Any(evt => evt.EventType == "sample.launch.confirmed"),
                "A matching journal process.start must suppress the redundant launch-proof row.");
            File.AppendAllText(path, "{\"EventType\":\"partial\"");
            recovered = GuestLiveEventJournalReader.ReadValidated(path, jobId, sampleSha256, 1024);
            SmokeAssert.True(recovered.Count == 3, "An unterminated crash tail must not be treated as a complete event.");
            var mismatchedIdentityRejected = false;
            try
            {
                GuestLiveEventJournalReader.ReadValidated(path, jobId, new string('B', 64), 1024);
            }
            catch (InvalidDataException)
            {
                mismatchedIdentityRejected = true;
            }
            SmokeAssert.True(mismatchedIdentityRejected, "Host-pinned sample identity must reject a foreign live journal.");
            var setupPath = Path.Combine(root, "setup-result.json");
            File.WriteAllText(setupPath, JsonSerializer.Serialize(new
            {
                samplePath = @"C:\incoming\different.exe",
                sampleSha256,
                sampleLength = 1024
            }));
            var conflictingSetupRejected = false;
            try
            {
                GuestLiveEventJournalReader.ReadValidated(path, jobId, sampleSha256, 1024);
            }
            catch (InvalidDataException)
            {
                conflictingSetupRejected = true;
            }
            SmokeAssert.True(conflictingSetupRejected,
                "A conflicting independently recovered guest setup path must reject the journal.");
            File.Delete(setupPath);
            VerifyDescendantStarts(root, jobId, samplePath, sampleSha256);
            var finalPath = Path.Combine(root, "events.json");
            File.WriteAllText(finalPath, "[]");
            var selected = new GuestOutputLocator().EnumerateEventArtifacts(root);
            SmokeAssert.True(selected.Contains(finalPath) && !selected.Contains(path),
                "A completed event artifact must suppress duplicate live-journal event import.");

            var limited = Path.Combine(root, "limited");
            using (var journal = DurableEventJournal.Create(limited, maxBytes: 1))
            {
                SmokeAssert.True(!journal.AppendNew(rows), "Over-budget appends must fail explicitly.");
                SmokeAssert.True(journal.Failure == "capacity-limit", "Capacity loss needs a stable diagnostic reason.");
                SmokeAssert.True(journal.WrittenCount == 0, "A rejected first record cannot be counted as durable.");
            }

            VerifyReportImport(context);

            return Task.FromResult(new SmokeTestResult
            {
                ScenarioId = ScenarioId,
                Passed = true,
                Message = "Live JSONL retains unique, ordered, flushed events and reports capacity loss."
            });
        }
        finally
        {
            var path = Path.Combine(root, DurableEventJournal.FileName);
            if (File.Exists(path)) File.Delete(path);
            var finalPath = Path.Combine(root, "events.json");
            if (File.Exists(finalPath)) File.Delete(finalPath);
            var identityPath = Path.Combine(root, DurableEventJournal.IdentityFileName);
            if (File.Exists(identityPath)) File.Delete(identityPath);
            var launchProofPath = Path.Combine(root, SampleLaunchProofWriter.FileName);
            if (File.Exists(launchProofPath)) File.Delete(launchProofPath);
            var setupPath = Path.Combine(root, "setup-result.json");
            if (File.Exists(setupPath)) File.Delete(setupPath);
            var prelaunch = Path.Combine(root, "prelaunch");
            var prelaunchIdentity = Path.Combine(prelaunch, DurableEventJournal.IdentityFileName);
            var prelaunchSample = Path.Combine(prelaunch, "benign-sample.bin");
            if (File.Exists(prelaunchIdentity)) File.Delete(prelaunchIdentity);
            if (File.Exists(prelaunchSample)) File.Delete(prelaunchSample);
            if (Directory.Exists(prelaunch)) Directory.Delete(prelaunch);
            var descendants = Path.Combine(root, "descendants");
            if (Directory.Exists(descendants)) Directory.Delete(descendants, recursive: true);
            var limited = Path.Combine(root, "limited");
            var limitedPath = Path.Combine(limited, DurableEventJournal.FileName);
            if (File.Exists(limitedPath)) File.Delete(limitedPath);
            if (Directory.Exists(limited)) Directory.Delete(limited);
            if (Directory.Exists(root)) Directory.Delete(root);
        }
    }

    private static void VerifyDescendantStarts(string root, Guid jobId, string samplePath, string sampleSha256)
    {
        var folder = Path.Combine(root, "descendants");
        Directory.CreateDirectory(folder);
        DurableEventJournal.WriteIdentity(folder, jobId, samplePath,
            new SampleLaunchProofWriter.SampleIdentity(sampleSha256, 1024));
        var path = Path.Combine(folder, DurableEventJournal.FileName);
        var child = new SandboxEvent
        {
            EventType = "process.start", Source = "etwLive", ProcessId = 1235,
            ParentProcessId = 1234, Path = @"C:\Windows\System32\cmd.exe"
        };
        File.WriteAllText(path, JsonSerializer.Serialize(new SandboxEvent
        {
            EventType = "agent.start", Source = "guest", Path = samplePath
        }) + "\n" + JsonSerializer.Serialize(child) + "\n");
        SmokeAssert.True(GuestLiveEventJournalReader.ReadValidated(path, jobId, sampleSha256, 1024).Count == 2,
            "A descendant process.start from ETW must not be confused with the submitted root image.");
        File.AppendAllText(path, JsonSerializer.Serialize(child with { Source = "guest" }) + "\n");
        var rootMismatchRejected = false;
        try
        {
            GuestLiveEventJournalReader.ReadValidated(path, jobId, sampleSha256, 1024);
        }
        catch (InvalidDataException)
        {
            rootMismatchRejected = true;
        }
        SmokeAssert.True(rootMismatchRejected,
            "An Agent root process.start with a different image path must still be rejected.");
    }

    private static void VerifyPrelaunchIdentity(string root, SmokeTestContext context)
    {
        var folder = Path.Combine(root, "prelaunch");
        Directory.CreateDirectory(folder);
        var samplePath = Path.Combine(folder, "benign-sample.bin");
        File.WriteAllText(samplePath, "safe-A");
        var original = DurableEventJournal.CaptureAndWriteIdentity(folder, Guid.NewGuid(), samplePath);
        SmokeAssert.True(File.Exists(Path.Combine(folder, DurableEventJournal.IdentityFileName)) &&
            !File.Exists(Path.Combine(folder, DurableEventJournal.FileName)),
            "Sample identity must be durable before the first journal append or prelaunch probe.");
        File.WriteAllText(samplePath, "safe-B");
        var changedRejected = false;
        try
        {
            DurableEventJournal.VerifyUnchangedSample(samplePath, original);
        }
        catch (InvalidDataException)
        {
            changedRejected = true;
        }
        SmokeAssert.True(changedRejected,
            "A same-size sample mutation between early identity and Process.Start must be refused.");
        File.WriteAllText(samplePath, "safe-A");
        var verified = DurableEventJournal.VerifyUnchangedSample(samplePath, original);
        SmokeAssert.True(verified == original, "Unchanged sample bytes must pass the second hash check.");

        var source = File.ReadAllText(Path.Combine(context.RepositoryRoot,
            "guest", "KSword.Sandbox.Agent", "Program.cs"));
        var identityIndex = source.IndexOf("DurableEventJournal.CaptureAndWriteIdentity(", StringComparison.Ordinal);
        var journalIndex = source.IndexOf("DurableEventJournal.Create(options.OutputDirectory)", StringComparison.Ordinal);
        var probeIndex = source.IndexOf("ProbePhase.BeforeStart", StringComparison.Ordinal);
        var rehashIndex = source.IndexOf("DurableEventJournal.VerifyUnchangedSample(", StringComparison.Ordinal);
        var processStartIndex = source.IndexOf("Process.Start(startInfo)", StringComparison.Ordinal);
        SmokeAssert.True(identityIndex >= 0 && identityIndex < journalIndex && journalIndex < probeIndex &&
            rehashIndex > probeIndex && rehashIndex < processStartIndex,
            "Agent ordering must persist identity before probes and rehash immediately before Process.Start.");
    }

    private static void VerifyReportImport(SmokeTestContext context)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "live-journal-import-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var samplePath = Path.Combine(runtimeRoot, "harmless-data.bin");
        File.WriteAllText(samplePath, "benign static bytes for journal import identity test");
        var config = new SandboxConfig
        {
            Paths = new SandboxPaths
            {
                RuntimeRoot = runtimeRoot,
                RulesDirectory = context.RulesDirectory,
                GuestPayloadRoot = Path.Combine(runtimeRoot, "payload")
            },
            Driver = new DriverConfig { Enabled = false }
        };
        var service = new SandboxJobService(config, new BehaviorRuleSet());
        var planned = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DisplayName = "harmless-data.bin",
            DurationSeconds = 5,
            DryRun = true
        });
        var sample = planned.Sample ?? throw new InvalidOperationException("Planned sample identity is required.");
        var jobRoot = Path.GetDirectoryName(planned.JsonReportPath) ?? throw new InvalidOperationException("Job root is required.");
        var guestRoot = Path.Combine(jobRoot, "guest");
        var guestSamplePath = @"C:\KSwordSandbox\incoming\harmless-data.exe";
        var rows = new List<SandboxEvent>
        {
            new() { EventType = "agent.start", Source = "guest", Path = guestSamplePath },
            new() { EventType = "process.start", Source = "guest", ProcessId = 9876, Path = guestSamplePath }
        };
        using (var journal = DurableEventJournal.Create(guestRoot))
        {
            DurableEventJournal.WriteIdentity(guestRoot, planned.JobId, guestSamplePath,
                new SampleLaunchProofWriter.SampleIdentity(sample.Sha256, sample.SizeBytes));
            SmokeAssert.True(journal.AppendNew(rows), "Integration journal must flush its benign fixture events.");
        }

        var journalPath = Path.Combine(guestRoot, DurableEventJournal.FileName);
        var partial = service.ImportGuestEvents(planned.JobId, journalPath);
        SmokeAssert.True(partial.Status == AnalysisStatus.Failed,
            "A journal-only import must remain Failed despite having a root process.start event.");
        var report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(partial.JsonReportPath!));
        SmokeAssert.True(report?.Events.Count(evt => evt.EventType == "process.start") == 1 &&
            report.Events.Any(evt => evt.EventType == "agent.live_journal.recovered_failed"),
            "Journal recovery must preserve one root start and an explicit partial-collection marker.");

        var finalPath = Path.Combine(guestRoot, "events.json");
        File.WriteAllText(finalPath, JsonSerializer.Serialize(rows));
        var interrupted = service.ImportGuestEvents(planned.JobId, finalPath);
        report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(interrupted.JsonReportPath!));
        SmokeAssert.True(interrupted.Status == AnalysisStatus.Failed &&
            report?.Events.Any(evt => evt.EventType == "agent.live_journal.recovered_failed") == true,
            "A syntactically valid but unterminated final array must use the durable partial journal.");
        File.WriteAllText(finalPath, JsonSerializer.Serialize(rows.Append(
            new SandboxEvent { EventType = "agent.stop", Source = "guest", Path = guestSamplePath })));
        var complete = service.ImportGuestEvents(planned.JobId, finalPath);
        report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(complete.JsonReportPath!));
        SmokeAssert.True(report?.Events.Count(evt => evt.EventType == "process.start") == 1 &&
            !report.Events.Any(evt => evt.EventType == "agent.live_journal.recovered_failed"),
            "Final events.json must suppress duplicate journal rows and the recovery marker.");
    }
}
