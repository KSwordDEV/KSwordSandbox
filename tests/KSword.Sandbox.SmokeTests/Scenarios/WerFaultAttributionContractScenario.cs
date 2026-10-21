using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Windows Error Reporting rows are OS crash-handling side effects, not
/// sample behavior. Measured case: Win32.Emotet (job 5c1762a2) crashed early,
/// WerFault.exe ran as its child with "-u -p &lt;pid&gt; -s 504", touched DPAPI
/// and Vault paths while building the crash report, and the parent-child link
/// promoted those rows to the sample — producing a false
/// credential-vault-dpapi-access High. WerFault/WerFaultSecure/WerMgr identity
/// and WER report-queue paths must stay environment even when the crashed
/// sample owns the PID lineage, while a normal child process of the sample
/// must still inherit attribution.
/// </summary>
internal sealed class WerFaultAttributionContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "correlation.werfault-attribution";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var start = DateTimeOffset.UtcNow;

        var events = new List<SandboxEvent>
        {
            SampleStart(start),
            SampleExit(start.AddSeconds(20)),
            // WerFault spawned by the OS because the sample crashed; parent is
            // the crashed sample PID, and the guest row carries the bare
            // "WerFault" name without the .exe extension.
            new()
            {
                EventType = "process.start",
                Source = "guest",
                Timestamp = start.AddSeconds(2),
                ProcessName = "WerFault",
                ProcessId = 7752,
                ParentProcessId = 4316,
                Path = @"C:\Windows\System32\WerFault.exe",
                CommandLine = "-u -p 4316 -s 504",
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["processimagepath"] = @"C:\Windows\System32\WerFault.exe"
                }
            },
            // Crash-report handling touches credential stores; the process
            // identity alone (no WER path involved) must demote the row.
            new()
            {
                EventType = "file.accessed",
                Source = "guest",
                Timestamp = start.AddSeconds(3),
                ProcessName = "WerFault.exe",
                ProcessId = 7752,
                ParentProcessId = 4316,
                Path = @"C:\Users\SANDBO~1\AppData\Roaming\Microsoft\Protect",
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["processimagepath"] = @"C:\Windows\System32\WerFault.exe"
                }
            },
            // Even the crashed sample's own process writing into the WER
            // report queue is crash-reporting noise, not sample staging.
            new()
            {
                EventType = "file.created",
                Source = "guest",
                Timestamp = start.AddSeconds(4),
                ProcessName = "sample.exe",
                ProcessId = 4316,
                Path = @"C:\ProgramData\Microsoft\Windows\WER\ReportQueue\AppCrash_sample.exe_1a2b3c4d",
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["processimagepath"] = SamplePath
                }
            },
            // Guard against over-exclusion: an ordinary child process of the
            // sample must still inherit sample attribution.
            new()
            {
                EventType = "process.start",
                Source = "guest",
                Timestamp = start.AddSeconds(5),
                ProcessName = "cmd.exe",
                ProcessId = 5000,
                ParentProcessId = 4316,
                Path = @"C:\Windows\System32\cmd.exe",
                CommandLine = @"C:\Windows\System32\cmd.exe /c whoami",
                Data = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["processimagepath"] = @"C:\Windows\System32\cmd.exe"
                }
            }
        };

        var correlated = SampleCorrelationClassifier.Apply(events, SamplePath);

        var vault = Require(correlated, "file.accessed", @"C:\Users\SANDBO~1\AppData\Roaming\Microsoft\Protect");
        SmokeAssert.True(
            vault.Data["sampleCorrelation"] == "environment",
            "WerFault accessing DPAPI/Protect paths must stay environment even though its parent is the crashed sample.");
        SmokeAssert.True(
            vault.Data["behaviorCounted"] == "false",
            "WerFault DPAPI rows must not count as sample behavior.");
        SmokeAssert.True(
            vault.Data["sampleCorrelationReason"].Contains("windows-error-reporting", StringComparison.OrdinalIgnoreCase),
            "WerFault exclusion must name the windows-error-reporting reason so the report can explain the demotion.");

        var reportQueue = Require(correlated, "file.created", @"C:\ProgramData\Microsoft\Windows\WER\ReportQueue\AppCrash_sample.exe_1a2b3c4d");
        SmokeAssert.True(
            reportQueue.Data["sampleCorrelation"] == "environment",
            "A WER ReportQueue write must stay environment even when the process is the crashed sample itself.");

        var child = Require(correlated, "process.start", @"C:\Windows\System32\cmd.exe");
        SmokeAssert.True(
            child.Data["sampleCorrelation"] != "environment",
            "A normal child process of the sample must still inherit sample attribution; the WerFault exclusion must not over-match.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "WerFault/WER rows stay environment regardless of sample lineage; ordinary children still inherit attribution."
        });
    }

    private static SandboxEvent SampleStart(DateTimeOffset timestamp) => new()
    {
        EventType = "process.start",
        Source = "guest",
        Timestamp = timestamp,
        ProcessName = "sample.exe",
        ProcessId = 4316,
        Path = SamplePath,
        CommandLine = SamplePath,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["processImagePath"] = SamplePath
        }
    };

    private static SandboxEvent SampleExit(DateTimeOffset timestamp) => new()
    {
        EventType = "process.exit",
        Source = "guest",
        Timestamp = timestamp,
        ProcessName = "sample.exe",
        ProcessId = 4316,
        Path = SamplePath,
        Data = new(StringComparer.OrdinalIgnoreCase)
        {
            ["processImagePath"] = SamplePath,
            ["exitCode"] = "0"
        }
    };

    private static SandboxEvent Require(IEnumerable<SandboxEvent> events, string eventType, string target)
    {
        var match = events.FirstOrDefault(candidate =>
            candidate.EventType == eventType &&
            string.Equals(candidate.Path, target, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(match is not null, $"Expected a {eventType} row for {target}.");
        return match!;
    }

    private const string SamplePath = @"C:\KSwordSandbox\incoming\sample.exe";
}
