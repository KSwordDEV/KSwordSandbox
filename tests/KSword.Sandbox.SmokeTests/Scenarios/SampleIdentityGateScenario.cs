using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Samples;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

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

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Sample path, SHA-256, size, and guest filename identity mismatches are rejected before a report can be treated as valid."
        });
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
