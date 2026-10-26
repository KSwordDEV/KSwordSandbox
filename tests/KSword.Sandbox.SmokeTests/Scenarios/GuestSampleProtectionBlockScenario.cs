using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// A guest file-filter block during VMware sample hash verification is a
/// pre-launch failure, not a clean dynamic result or proof about which
/// security component blocked the file.
/// </summary>
internal sealed class GuestSampleProtectionBlockScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest.sample-protection-block.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var root = Path.Combine(context.RuntimeRoot, "guest-protection-block");
        var control = Path.Combine(root, "vmware-guestops");
        Directory.CreateDirectory(control);
        var resultPath = Path.Combine(root, "runbook-execution.json");
        WriteFailedCopyResult(resultPath);

        var hashResultPath = Path.Combine(control, "sample-hash-result.json");
        File.WriteAllText(hashResultPath, JsonSerializer.Serialize(new
        {
            state = "failed",
            error = "无法成功完成操作，因为文件包含病毒或潜在的垃圾软件。"
        }));
        var blocked = GuestFailureArtifactImporter.ImportRunbookFailure(resultPath);
        SmokeAssert.True(blocked.Count == 1 && blocked[0].EventType == "sample.runtime.preflight.failed",
            "A guest antivirus or file-filter read block must produce one pre-launch diagnostic.");
        var diagnostic = blocked[0];
        SmokeAssert.True(DataEquals(diagnostic, "sampleExecuted", "false") &&
                         DataEquals(diagnostic, "sampleRuntimeFailureCode", "sample-runtime-blocked-guest-file-read") &&
                         DataEquals(diagnostic, "guestProtectionSource", "unconfirmed"),
            "The diagnostic must record non-execution and leave the blocking component unconfirmed.");
        SmokeAssert.True(DataEquals(diagnostic, "behaviorCounted", "false") &&
                         DataEquals(diagnostic, "collectionHealth", "true"),
            "The block is a collection diagnostic, not sample behavior.");

        var crowded = blocked.Concat(Enumerable.Range(0, 120).Select(index => new SandboxEvent
        {
            EventType = "static.import",
            Source = "static",
            Data = { ["index"] = index.ToString() }
        })).ToList();
        var sampled = ReportEventSampler.SampleForReport(crowded);
        var sampledDiagnostic = sampled.Events.SingleOrDefault(evt => evt.EventType == "sample.runtime.preflight.failed");
        SmokeAssert.True(sampledDiagnostic is not null,
            "The blocked pre-launch diagnostic must survive a crowded report.");
        SmokeAssert.True(DataEquals(sampledDiagnostic!, "guestProtectionSource", "unconfirmed") &&
                         DataEquals(sampledDiagnostic!, "sampleExecuted", "false"),
            "The bounded report payload must retain non-execution and uncertain blocker identity.");

        var report = new AnalysisReport
        {
            JobId = Guid.NewGuid(),
            Provider = VirtualizationProvider.VMware,
            Status = AnalysisStatus.Failed,
            Sample = new SampleIdentity
            {
                FileName = "blocked-sample.exe",
                FullPath = @"C:\KSwordSandbox\incoming\blocked-sample.exe",
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 4096
            },
            Events = [diagnostic]
        };
        var renderer = new HtmlReportRenderer();
        var english = renderer.RenderEnglish(report);
        var chinese = renderer.RenderChinese(report);
        SmokeAssert.True(english.Contains("Execution blocked / runtime indeterminate", StringComparison.Ordinal) &&
                         english.Contains("blocking component is unconfirmed", StringComparison.Ordinal),
            "The English report must show the execution boundary and avoid naming an unverified blocker.");
        SmokeAssert.True(chinese.Contains("执行被阻断/运行期不可判定", StringComparison.Ordinal) &&
                         chinese.Contains("来宾文件读取被阻断", StringComparison.Ordinal),
            "The Chinese report must show the guest file-read failure prominently.");

        // A checksum mismatch is not evidence of antivirus intervention.
        File.WriteAllText(hashResultPath, JsonSerializer.Serialize(new { state = "failed", error = "Copied sample hash mismatch." }));
        SmokeAssert.True(GuestFailureArtifactImporter.ImportRunbookFailure(resultPath).Count == 0,
            "An ordinary hash mismatch must not be mislabeled as a protection block.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Guest protection blocks stay visible as non-execution diagnostics without attributing an unproven filter."
        });
    }

    private static void WriteFailedCopyResult(string resultPath)
    {
        File.WriteAllText(resultPath, JsonSerializer.Serialize(new SandboxRunbookExecutionResult
        {
            JobId = Guid.NewGuid(),
            Provider = VirtualizationProvider.VMware,
            TargetVmName = "isolated-guest",
            Mode = SandboxRunbookExecutionMode.Live,
            Success = false,
            TotalSteps = 1,
            ExecutedSteps = 1,
            FailedStepIndex = 0,
            StartedAtUtc = DateTimeOffset.UtcNow,
            Duration = TimeSpan.FromSeconds(2),
            StepResults =
            [
                new SandboxRunbookStepExecutionResult
                {
                    StepIndex = 0,
                    StepId = "copy-sample",
                    Title = "Copy and verify submitted sample through VMware GuestOps",
                    PowerShell = "# synthetic smoke fixture; no guest command runs",
                    Success = false,
                    ExitCode = 1,
                    StandardError = "Guest sample copy/hash verification failed.",
                    StartedAtUtc = DateTimeOffset.UtcNow,
                    Duration = TimeSpan.FromSeconds(1)
                }
            ]
        }));
    }

    private static bool DataEquals(SandboxEvent evt, string key, string expected) =>
        evt.Data.TryGetValue(key, out var value) && string.Equals(value, expected, StringComparison.Ordinal);
}
