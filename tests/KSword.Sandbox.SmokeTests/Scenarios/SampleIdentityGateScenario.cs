using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.Samples;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;
using System.Text.Json;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that report rebuild inputs cannot silently change the sample
/// identity. This is a data-only contract test and never executes a sample.
/// </summary>
internal sealed class SampleIdentityGateScenario : ISmokeTestScenario
{
    public string ScenarioId => "sample-identity.gate.contract";

    public Task<SmokeTestResult> RunAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var canonical = CreateIdentity(
            @"E:\Samples\sample.exe",
            "a",
            12);
        var matchingMetadata = canonical with { };
        var matchingReport = canonical with { };

        var valid = SampleIdentityValidation.Validate(
            canonical,
            matchingMetadata,
            matchingReport,
            canonical.FullPath,
            @"C:\KSwordSandbox\incoming\sample.exe",
            canonical.Sha256,
            canonical.SizeBytes);
        SmokeAssert.True(valid.IsValid, "Matching metadata, report, submission, and guest input should pass the identity gate.");
        SmokeAssert.True(valid.Issues.Count == 0, "A matching identity should not produce mismatch issues.");

        var mismatched = SampleIdentityValidation.Validate(
            canonical,
            matchingMetadata,
            matchingReport with { Sha256 = new string('b', 64) },
            canonical.FullPath,
            @"C:\KSwordSandbox\incoming\other.exe",
            canonical.Sha256,
            canonical.SizeBytes);
        SmokeAssert.True(!mismatched.IsValid, "A report hash or guest filename mismatch must fail the identity gate.");
        SmokeAssert.True(mismatched.Status == "mismatch", "Identity failures must be explicitly marked mismatch.");
        SmokeAssert.True(mismatched.Issues.Contains("report-sha256-mismatch"), "Report hash mismatch must remain visible in the issue list.");
        SmokeAssert.True(mismatched.Issues.Contains("guest-path-mismatch"), "Guest input path mismatch must remain visible in the issue list.");

        AssertServiceRejectsStaleReport(context);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Sample path, SHA-256, size, and guest filename identity mismatches are rejected before a report can be treated as valid."
        });
    }

    private static void AssertServiceRejectsStaleReport(SmokeTestContext context)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "sample-identity-rebuild");
        Directory.CreateDirectory(runtimeRoot);
        var config = SandboxConfigLoader.Load(
            Path.Combine(context.RepositoryRoot, "config", "sandbox.example.json"),
            context.RepositoryRoot) with
        {
            Paths = new SandboxPaths
            {
                RuntimeRoot = runtimeRoot,
                RulesDirectory = context.RulesDirectory,
                GuestPayloadRoot = Path.Combine(runtimeRoot, "payload", "guest-tools")
            }
        };
        var samplePath = Path.Combine(runtimeRoot, "sample.exe");
        File.WriteAllText(samplePath, "data-only sample identity gate fixture");
        var service = new SandboxJobService(config, new BehaviorRuleSet());
        var planned = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 1,
            DryRun = true
        });

        var reportPath = planned.JsonReportPath ?? throw new InvalidOperationException("Smoke plan should write report.json.");
        var report = JsonSerializer.Deserialize<AnalysisReport>(File.ReadAllText(reportPath), new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }) ?? throw new InvalidOperationException("Smoke plan report should deserialize.");
        File.WriteAllText(reportPath, JsonSerializer.Serialize(report with
        {
            Sample = report.Sample with { Sha256 = new string('f', 64) }
        }));

        var eventsPath = Path.Combine(runtimeRoot, "jobs", planned.JobId.ToString("N"), "guest", "events.json");
        Directory.CreateDirectory(Path.GetDirectoryName(eventsPath)!);
        File.WriteAllText(eventsPath, JsonSerializer.Serialize(new[]
        {
            new SandboxEvent
            {
                EventType = "agent.start",
                Source = "guest",
                Path = @"C:\KSwordSandbox\incoming\sample.exe",
                Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["samplePath"] = @"C:\KSwordSandbox\incoming\sample.exe"
                }
            }
        }));

        var imported = service.ImportGuestEvents(planned.JobId, eventsPath);
        SmokeAssert.True(imported.Status == AnalysisStatus.Failed, "A stale report identity must fail the rebuilt job.");
        var rebuilt = JsonSerializer.Deserialize<AnalysisReport>(
            File.ReadAllText(imported.JsonReportPath ?? throw new InvalidOperationException("Rebuilt report path should exist.")),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        SmokeAssert.True(rebuilt?.SampleIdentityStatus == "mismatch", "Rebuilt report must explicitly mark sample identity mismatch.");
        SmokeAssert.True(rebuilt?.SampleIdentityIssues.Contains("report-sha256-mismatch") == true, "Rebuilt report must retain the stale report hash issue.");
        SmokeAssert.True(rebuilt?.Events.Any(evt => string.Equals(evt.EventType, "sample.identity_mismatch", StringComparison.OrdinalIgnoreCase)) == true, "Identity mismatch must remain visible as a diagnostic event.");
    }

    private static SampleIdentity CreateIdentity(string path, string seed, long size) => new()
    {
        FileName = Path.GetFileName(path),
        FullPath = path,
        Sha256 = seed.Length == 64 ? seed : new string(seed[0], 64),
        Sha1 = new string('c', 40),
        Md5 = new string('d', 32),
        Crc32 = "00000000",
        SizeBytes = size
    };
}
