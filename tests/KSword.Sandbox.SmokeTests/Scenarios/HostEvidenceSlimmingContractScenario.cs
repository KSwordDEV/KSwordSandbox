using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Artifacts;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Covers the conservative host evidence retention policy. report.json is
/// sampled, so rotated R0 JSONL and raw ETL must survive report generation
/// and a second import. Until lossless archiving/replay is implemented, the
/// audit pass records candidates but deletes none of them.
/// </summary>
internal sealed class HostEvidenceSlimmingContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "host.evidence-slimming.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var jobRoot = Path.Combine(context.RuntimeRoot, "slimming-contract", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(jobRoot);
        try
        {
            var jobId = Guid.NewGuid();
            const int reportEventCount = 7;
            var reportBytes = SeedJobDirectory(jobRoot, reportEventCount);

            // Default policy retains all raw evidence, even when the operator
            // did not explicitly select KeepRawEvidence.
            var swept = HostIntermediateEvidenceSweeper.Sweep(jobRoot, keepRawEvidence: false, jobId);
            SmokeAssert.True(swept.RetainedEverything && swept.FreedBytes == 0 && swept.Deleted.Count == 0,
                "Default audit must retain every candidate until lossless replay exists.");

            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "driver-events.part-000001.jsonl")),
                "Rotated R0 segment must be retained for re-import.");
            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "driver-events.jsonl")),
                "Canonical R0 guest stream must be retained.");
            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "events.json")),
                "events.json guest stream must be retained.");
            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "driver-events.jsonl.failure.json")),
                "R0 failure sidecar must be retained.");
            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "packet-captures", "capture.pcap")),
                "Collected packet-capture artifact must be retained.");
            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "etw-traces", "trace.etl")) &&
                File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "packet-capture-diagnostics", "pktmon.etl")),
                "Raw ETW and pktmon traces must be retained for re-import and audit.");
            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "host-etl-decode", "trace.hostdecoded.xml")),
                "Decoded XML remains until successful lossless regeneration is guaranteed.");

            // The classified event data must be unchanged: report.json is
            // byte-identical after the sweep.
            var reportAfter = File.ReadAllBytes(Path.Combine(jobRoot, "report.json"));
            SmokeAssert.True(reportAfter.AsSpan().SequenceEqual(reportBytes),
                "report.json must be byte-identical after slimming; classified event count/data must not change.");
            using (var document = JsonDocument.Parse(reportAfter))
            {
                SmokeAssert.True(document.RootElement.GetProperty("Events").GetArrayLength() == reportEventCount,
                    "The classified event count in report.json must be unchanged by slimming.");
            }

            // The manifest makes the suspended deletion policy explicit.
            var manifestPath = Path.Combine(jobRoot, HostIntermediateEvidenceSweeper.ManifestFileName);
            SmokeAssert.True(File.Exists(manifestPath), "Retention manifest must be written beside report.json.");
            using (var manifest = JsonDocument.Parse(File.ReadAllBytes(manifestPath)))
            {
                var root = manifest.RootElement;
                SmokeAssert.True(root.GetProperty("deleted").GetArrayLength() == 0 &&
                    root.GetProperty("retentionReason").GetString() == "raw-evidence-required-for-reimport" &&
                    root.GetProperty("retainedCandidates").GetArrayLength() == 4,
                    "The manifest must explain why all four candidate intermediate files were retained.");
            }

            var index = new HostArtifactIndexBuilder().Build(jobId, jobRoot);
            SmokeAssert.True(index.Artifacts.Where(artifact => !string.IsNullOrWhiteSpace(artifact.SafeLink))
                .All(artifact => File.Exists(Path.Combine(jobRoot, artifact.RelativePath.Replace('/', Path.DirectorySeparatorChar)))),
                "The post-audit artifact index must not contain a dead local download link.");

            // Explicit retention continues to keep everything.
            var retained = HostIntermediateEvidenceSweeper.Sweep(jobRoot, keepRawEvidence: true, jobId);
            SmokeAssert.True(retained.RetainedEverything && retained.FreedBytes == 0 && retained.Deleted.Count == 0,
                "KeepRawEvidence=true must delete nothing.");
            SmokeAssert.True(File.Exists(Path.Combine(jobRoot, "guest", ".shared-folder-staging", "driver-events.part-000001.jsonl")),
                "KeepRawEvidence=true must retain rotated R0 segments.");

            AssertRepeatedImportPreservesR0(context);

            return Task.FromResult(new SmokeTestResult
            {
                ScenarioId = ScenarioId,
                Passed = true,
                Message = "Raw R0/ETL evidence and artifact links survive default retention and repeated import."
            });
        }
        finally
        {
            try
            {
                Directory.Delete(jobRoot, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static void AssertRepeatedImportPreservesR0(SmokeTestContext context)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "slimming-repeat", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var samplePath = Path.Combine(runtimeRoot, "retention-sample.exe");
        File.WriteAllText(samplePath, "synthetic smoke input; never executed");
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
        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = true,
            KeepRawEvidence = false
        });
        var jobRoot = Path.GetDirectoryName(job.JsonReportPath
            ?? throw new InvalidOperationException("Planned job must have a report path."))!;
        var guestRoot = Path.Combine(jobRoot, "guest", job.JobId.ToString("N"));
        Directory.CreateDirectory(guestRoot);

        var timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var eventsPath = Path.Combine(guestRoot, "events.json");
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(new[]
        {
            new SandboxEvent
            {
                EventType = "process.start",
                Timestamp = timestamp,
                Source = "guest",
                ProcessName = "retention-sample.exe",
                ProcessId = 8400,
                Path = @"C:\KSwordSandbox\retention-sample.exe"
            }
        }));
        foreach (var name in new[]
        {
            "driver-events.part-000001.jsonl",
            "driver-events.part-000002.jsonl",
            "driver-events.jsonl"
        })
        {
            var evt = new SandboxEvent
            {
                EventType = "driver.telemetry",
                Timestamp = timestamp.AddMilliseconds(-1),
                Source = "driver",
                ProcessName = "retention-sample.exe",
                ProcessId = 8400,
                Path = $@"C:\KSwordSandbox\{name}.bin",
                Data = new() { ["sequence"] = name, ["driverEventPath"] = name }
            };
            File.WriteAllText(Path.Combine(guestRoot, name), JsonSerializer.Serialize(evt) + Environment.NewLine);
        }

        var first = service.ImportGuestEvents(job.JobId, eventsPath);
        var firstReport = ReadReport(first);
        var firstR0 = R0Sequences(firstReport);
        SmokeAssert.True(firstR0.Count == 3, "First import must include both rotated R0 segments and the canonical stream.");
        SmokeAssert.True(File.Exists(Path.Combine(guestRoot, "driver-events.part-000001.jsonl")) &&
            File.Exists(Path.Combine(guestRoot, "driver-events.part-000002.jsonl")),
            "The report-generation retention pass must preserve both rotated R0 segments.");

        var index = new HostArtifactIndexBuilder().Build(job.JobId, jobRoot);
        SmokeAssert.True(index.Artifacts.Where(artifact => !string.IsNullOrWhiteSpace(artifact.SafeLink))
            .All(artifact => File.Exists(Path.Combine(jobRoot, artifact.RelativePath.Replace('/', Path.DirectorySeparatorChar)))),
            "Report generation must not leave dead artifact download links.");

        var second = service.ImportGuestEvents(job.JobId, eventsPath);
        var secondReport = ReadReport(second);
        SmokeAssert.True(R0Sequences(secondReport).SetEquals(firstR0),
            "Re-import must recover the same R0 rows from both rotated segments and the canonical stream.");
        SmokeAssert.True(secondReport.Metrics["events.raw"] >= firstReport.Metrics["events.raw"],
            "Re-import must not lose raw events after the retention pass.");
    }

    private static AnalysisReport ReadReport(AnalysisJob job) =>
        JsonSerializer.Deserialize<AnalysisReport>(
            File.ReadAllText(job.JsonReportPath ?? throw new InvalidOperationException("Imported job must have report.json.")),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
        ?? throw new InvalidOperationException("report.json must deserialize.");

    private static HashSet<string> R0Sequences(AnalysisReport report) =>
        report.Events
            .Where(evt => string.Equals(evt.Source, "driver", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.TryGetValue("sequence", out _))
            .Select(evt => evt.Data["sequence"])
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static byte[] SeedJobDirectory(string jobRoot, int reportEventCount)
    {
        var staging = Path.Combine(jobRoot, "guest", ".shared-folder-staging");
        var decodeDir = Path.Combine(staging, "host-etl-decode");
        var etwDir = Path.Combine(staging, "etw-traces");
        var pktDir = Path.Combine(staging, "packet-capture-diagnostics");
        var capturesDir = Path.Combine(jobRoot, "packet-captures");
        Directory.CreateDirectory(decodeDir);
        Directory.CreateDirectory(etwDir);
        Directory.CreateDirectory(pktDir);
        Directory.CreateDirectory(capturesDir);

        File.WriteAllText(Path.Combine(staging, "driver-events.part-000001.jsonl"), "{\"seq\":1}\n");
        File.WriteAllText(Path.Combine(staging, "driver-events.jsonl"), "{\"seq\":2}\n");
        File.WriteAllText(Path.Combine(staging, "events.json"), "[]");
        File.WriteAllText(Path.Combine(staging, "driver-events.jsonl.failure.json"), "{}");
        File.WriteAllText(Path.Combine(decodeDir, "trace.hostdecoded.xml"), "<events/>");
        File.WriteAllText(Path.Combine(etwDir, "trace.etl"), "etl");
        File.WriteAllText(Path.Combine(pktDir, "pktmon.etl"), "etl");
        File.WriteAllText(Path.Combine(capturesDir, "capture.pcap"), "pcap");

        var reportPath = Path.Combine(jobRoot, "report.json");
        var reportJson = JsonSerializer.Serialize(new
        {
            JobId = Guid.NewGuid(),
            Status = "Completed",
            Events = Enumerable.Range(0, reportEventCount)
                .Select(index => new { EventType = "process.start", Timestamp = DateTimeOffset.UnixEpoch.AddSeconds(index) })
                .ToArray()
        });
        File.WriteAllText(reportPath, reportJson);
        return File.ReadAllBytes(reportPath);
    }
}
