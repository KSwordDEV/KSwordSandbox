using System.Text;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Agent.Output;
using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that a durable launch proof survives missing final Agent output
/// without being counted as a complete behavior run. Uses only inert bytes.
/// </summary>
internal sealed class GuestLaunchProofRecoveryScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest.launch-proof-recovery.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var root = Path.Combine(context.RuntimeRoot, "launch-proof-recovery");
        var output = Path.Combine(root, "guest");
        Directory.CreateDirectory(output);
        var sample = Path.Combine(root, "inert-sample.bin");
        File.WriteAllBytes(sample, Encoding.UTF8.GetBytes("inert launch-proof fixture"));
        var identity = SampleLaunchProofWriter.ComputeSampleIdentity(sample);
        var sha256 = identity.Sha256;
        var jobId = Guid.NewGuid();
        var proof = SampleLaunchProofWriter.Write(output, jobId, sample, identity, 1234, 4321, DateTimeOffset.UtcNow);
        SmokeAssert.True(File.Exists(proof), "Launch proof must be persisted before final events.");

        File.Delete(sample);
        var summaryPath = new GuestArtifactWriter().WriteSummary(output, sample, 3, jobId);
        using (var summary = JsonDocument.Parse(File.ReadAllText(summaryPath)))
        {
            var json = summary.RootElement;
            SmokeAssert.True(json.GetProperty("sampleSha256").GetString() == sha256.ToLowerInvariant() &&
                json.GetProperty("sampleSizeBytes").GetInt64() == identity.SizeBytes &&
                json.GetProperty("sampleIdentitySource").GetString() == "prelaunch-verified" &&
                !json.GetProperty("samplePresentAtSummary").GetBoolean(),
                "A self-deleting sample must retain its verified prelaunch SHA-256/size in the final summary.");
        }

        var rows = GuestFailureArtifactImporter.Import(output);
        var launch = rows.Single(row => row.EventType == "sample.launch.confirmed");
        SmokeAssert.True(launch.Data["sampleSha256"] == sha256 && launch.ProcessId == 1234,
            "Recovered launch proof must preserve sample hash and PID.");
        SmokeAssert.True(launch.Data["behaviorCounted"] == "false" && launch.Data["captureState"] == "partial",
            "A launch-only proof must never be counted as completed behavior.");
        SmokeAssert.True(rows.Any(row => row.EventType == "agent.run.failed") &&
            rows.All(row => row.EventType != "process.start"),
            "Missing final events must stay a failed collection without inventing a process.start row.");

        var report = new AnalysisReport
        {
            JobId = jobId,
            Status = AnalysisStatus.Failed,
            Sample = new SampleIdentity
            {
                FileName = "inert-sample.bin",
                FullPath = sample,
                Sha256 = sha256,
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = identity.SizeBytes
            },
            Events = rows.ToList()
        };
        var renderer = new HtmlReportRenderer();
        var english = renderer.RenderEnglish(report);
        var chinese = renderer.RenderChinese(report);
        SmokeAssert.True(english.Contains("Launch confirmed / collection failed", StringComparison.Ordinal) &&
                         english.Contains("<span class=\"badge badge-medium triage-verdict\">Runtime indeterminate</span>", StringComparison.Ordinal) &&
                         english.Contains("Sample launch confirmed / behavior collection failed", StringComparison.Ordinal),
            "A launch-only failed report must show a collection failure without a suspiciousness verdict.");
        SmokeAssert.True(chinese.Contains("启动已证/采集失败", StringComparison.Ordinal) &&
                         chinese.Contains("<span class=\"badge badge-medium triage-verdict\">运行期不可判定</span>", StringComparison.Ordinal) &&
                         chinese.Contains("样本启动已证/行为采集失败", StringComparison.Ordinal),
            "Chinese launch-only cover must not turn missing behavior into a suspiciousness verdict.");

        var confirmedBehavior = report with
        {
            Status = AnalysisStatus.Completed,
            Findings =
            [
                new BehaviorFinding
                {
                    RuleId = "inert-fixture-behavior",
                    Title = "Confirmed fixture behavior",
                    Severity = "high"
                }
            ]
        };
        SmokeAssert.True(renderer.RenderEnglish(confirmedBehavior).Contains("High risk", StringComparison.Ordinal),
            "Completed reports with a high-severity behavior finding must retain the threat verdict.");

        File.WriteAllText(Path.Combine(output, "events.json"), "[]", Encoding.UTF8);
        SmokeAssert.True(GuestFailureArtifactImporter.Import(output).Any(row => row.EventType == "sample.launch.confirmed"),
            "An incomplete event stream without process.start must retain verified launch proof.");
        File.WriteAllText(Path.Combine(output, "events.json"),
            JsonSerializer.Serialize(new[] { new { EventType = "process.start", Path = sample, ProcessId = 1234 } }), Encoding.UTF8);
        SmokeAssert.True(GuestFailureArtifactImporter.Import(output).All(row => row.EventType != "sample.launch.confirmed"),
            "A matching process.start must not double count the verified launch proof.");
        File.WriteAllText(Path.Combine(output, "events.json"),
            JsonSerializer.Serialize(new[] { new { EventType = "process.start", Path = sample, ProcessId = 9999 } }), Encoding.UTF8);
        SmokeAssert.True(GuestFailureArtifactImporter.Import(output).Any(row => row.EventType == "sample.launch.confirmed"),
            "A different PID at the same path must not suppress the verified launch proof.");
        File.Delete(Path.Combine(output, "events.json"));

        File.WriteAllText(Path.Combine(output, "guest-agent-run-status.json"),
            JsonSerializer.Serialize(new { state = "incomplete-output", sampleSha256 = new string('0', 64) }), Encoding.UTF8);
        SmokeAssert.True(GuestFailureArtifactImporter.Import(output).All(row => row.EventType != "sample.launch.confirmed"),
            "Host expected hash mismatch must reject recovered launch evidence.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Flushed launch proof preserves prelaunch identity after self-delete; incomplete output and hash mismatch remain explicit."
        });
    }
}
