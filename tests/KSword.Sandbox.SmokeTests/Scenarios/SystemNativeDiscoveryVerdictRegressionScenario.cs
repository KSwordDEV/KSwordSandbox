using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Reporting;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Keeps ordinary System32 discovery utilities out of the sample verdict while
/// retaining their normalized rows and preserving explicit high-signal rules.
/// </summary>
internal sealed class SystemNativeDiscoveryVerdictRegressionScenario : ISmokeTestScenario
{
    public string ScenarioId => "report.system-native-discovery-verdict-regression";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var timestamp = new DateTimeOffset(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        var sample = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp,
            Source = "etwLive",
            ProcessName = "sample.exe",
            ProcessId = 7000,
            Path = @"C:\Users\Public\sample.exe",
            CommandLine = @"C:\Users\Public\sample.exe"
        };
        var hostname = new SandboxEvent
        {
            EventType = "process.start",
            Timestamp = timestamp.AddMilliseconds(100),
            Source = "etwLive",
            ProcessName = "hostname.exe",
            ProcessId = 7001,
            ParentProcessId = 7000,
            Path = @"C:\Windows\System32\hostname.exe",
            CommandLine = @"C:\Windows\System32\hostname.exe",
            Data =
            {
                ["processImagePath"] = @"C:\Windows\System32\hostname.exe"
            }
        };

        var classified = SampleCorrelationClassifier.Apply([sample, hostname], sample.Path);
        var classifiedHostname = classified.Single(evt => evt.ProcessId == 7001);
        SmokeAssert.True(
            string.Equals(classifiedHostname.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "System32 hostname discovery should be retained as environment evidence.");
        SmokeAssert.True(
            string.Equals(classifiedHostname.Data.GetValueOrDefault("behaviorCounted"), "false", StringComparison.OrdinalIgnoreCase),
            "System32 hostname discovery should not count as sample behavior.");
        SmokeAssert.True(
            string.Equals(classifiedHostname.Data.GetValueOrDefault("sampleCorrelationReason"), "system32-signed-or-known-discovery-utility-without-high-signal-behavior", StringComparison.OrdinalIgnoreCase),
            "System32 discovery suppression should expose a stable reason in raw evidence.");

        var prefetch = new SandboxEvent
        {
            EventType = "driver.file",
            Timestamp = timestamp.AddMilliseconds(200),
            Source = "driver",
            ProcessName = "System",
            ProcessId = 4,
            Path = @"\Windows\Prefetch\HOSTNAME.EXE-12345678.pf",
            Data =
            {
                ["operationName"] = "write",
                ["processId"] = "4",
                ["path"] = @"\Windows\Prefetch\HOSTNAME.EXE-12345678.pf",
                ["sampleBehaviorCandidate"] = "true",
                ["behaviorCounted"] = "true"
            }
        };
        var classifiedPrefetch = SampleCorrelationClassifier.Apply([sample, hostname, prefetch], sample.Path)
            .Single(evt => evt.EventType.Equals("driver.file", StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(
            string.Equals(classifiedPrefetch.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "PID 4 Prefetch writes for a native discovery utility should remain environment evidence.");
        SmokeAssert.True(
            string.Equals(classifiedPrefetch.Data.GetValueOrDefault("behaviorCounted"), "false", StringComparison.OrdinalIgnoreCase),
            "PID 4 Prefetch writes for a native discovery utility must not count as sample behavior.");

        var utilityPrefetch = prefetch with
        {
            ProcessName = "hostname.exe",
            ProcessId = 7001,
            Data = new Dictionary<string, string>(prefetch.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["processId"] = "7001"
            }
        };
        var classifiedUtilityPrefetch = SampleCorrelationClassifier.Apply([sample, hostname, utilityPrefetch], sample.Path)
            .Single(evt => evt.EventType.Equals("driver.file", StringComparison.OrdinalIgnoreCase) && evt.ProcessId == 7001);
        SmokeAssert.True(
            string.Equals(classifiedUtilityPrefetch.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "Expected Windows Prefetch writes must remain environment evidence even when the utility PID owns the row.");

        var utilityDriverRow = new SandboxEvent
        {
            EventType = "driver.file",
            Timestamp = timestamp.AddMilliseconds(250),
            Source = "driver",
            ProcessName = "hostname.exe",
            ProcessId = 7001,
            Path = @"\Windows\System32\hostname.exe",
            Data =
            {
                ["schema"] = "ksword.sandbox.r0.event",
                ["eventOrigin"] = "kernel-driver",
                ["producerCategory"] = "file",
                ["operationName"] = "read"
            }
        };
        var classifiedUtilityDriverRow = SampleCorrelationClassifier.Apply([sample, hostname, utilityDriverRow], sample.Path)
            .Single(evt => ReferenceEquals(evt, utilityDriverRow) ||
                (evt.EventType.Equals("driver.file", StringComparison.OrdinalIgnoreCase) && evt.ProcessId == 7001));
        SmokeAssert.True(
            string.Equals(classifiedUtilityDriverRow.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "R0 file rows owned by a signed System32 discovery utility should remain environment evidence.");

        var hostStagingRow = new SandboxEvent
        {
            EventType = "driver.file",
            Timestamp = timestamp.AddMilliseconds(275),
            Source = "driver",
            ProcessName = "csrss.exe",
            ProcessId = 476,
            Path = @"\KSwordSandbox\incoming\sample.exe.Config",
            Data =
            {
                ["eventOrigin"] = "kernel-driver",
                ["operationName"] = "create",
                ["path"] = @"\KSwordSandbox\incoming\sample.exe.Config"
            }
        };
        var classifiedHostStagingRow = SampleCorrelationClassifier.Apply([sample, hostStagingRow], sample.Path)
            .Single(evt => evt.ProcessId == 476);
        SmokeAssert.True(
            string.Equals(classifiedHostStagingRow.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "System-owned incoming staging rows must not be promoted by the submitted sample path.");
        SmokeAssert.True(
            string.Equals(classifiedHostStagingRow.Data.GetValueOrDefault("behaviorCounted"), "false", StringComparison.OrdinalIgnoreCase),
            "System-owned incoming staging rows must remain non-behavior evidence.");

        var stagingRow = new SandboxEvent
        {
            EventType = "driver.file",
            Timestamp = timestamp.AddMilliseconds(50),
            Source = "driver",
            ProcessName = "MSPCManagerService.exe",
            ProcessId = 4596,
            Path = @"C:\KSwordSandbox\incoming\sample.exe",
            Data =
            {
                ["schema"] = "ksword.sandbox.r0.event",
                ["eventOrigin"] = "kernel-driver",
                ["producerCategory"] = "file",
                ["processImagePath"] = @"C:\Program Files\WindowsApps\Microsoft.MicrosoftPCManager_3.23.0.0_x64__8wekyb3d8bbwe\PCManager\MSPCManagerService.exe",
                ["operationName"] = "create"
            }
        };
        var classifiedStagingRow = SampleCorrelationClassifier.Apply([sample, stagingRow], sample.Path)
            .Single(evt => evt.ProcessId == 4596);
        SmokeAssert.True(
            string.Equals(classifiedStagingRow.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "Guest sample staging by MSPCManagerService must not be promoted by the submitted sample path.");

        // Incoming setup probes can carry a broad dropped-file bit or a
        // failed open/create intent. They remain environment evidence until a
        // successful, explicit mutation is present.
        var failedOpenStagingRow = stagingRow with
        {
            Timestamp = timestamp.AddMilliseconds(60),
            Data = new Dictionary<string, string>(stagingRow.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["operationName"] = "open",
                ["fileIntent"] = "failed-open",
                ["droppedFileCandidate"] = "true",
                ["processId"] = "7000",
                ["processImagePath"] = sample.Path
            },
            ProcessName = "sample.exe",
            ProcessId = 7000
        };
        var classifiedFailedOpen = SampleCorrelationClassifier.Apply([sample, failedOpenStagingRow], sample.Path)
            .Single(evt => evt.Timestamp == failedOpenStagingRow.Timestamp);
        SmokeAssert.True(
            string.Equals(classifiedFailedOpen.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
            "Failed-open staging probes with droppedFileCandidate must remain environment evidence.");
        SmokeAssert.True(
            string.Equals(classifiedFailedOpen.Data.GetValueOrDefault("behaviorCounted"), "false", StringComparison.OrdinalIgnoreCase),
            "Failed-open staging probes must not count as sample behavior.");

        var successfulIncomingWrite = failedOpenStagingRow with
        {
            Timestamp = timestamp.AddMilliseconds(70),
            Data = new Dictionary<string, string>(failedOpenStagingRow.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["operationName"] = "write",
                ["fileIntent"] = "write",
                ["fileWrite"] = "true",
                ["operationFailed"] = "false"
            }
        };
        var classifiedIncomingWrite = SampleCorrelationClassifier.Apply([sample, successfulIncomingWrite], sample.Path)
            .Single(evt => evt.Timestamp == successfulIncomingWrite.Timestamp);
        SmokeAssert.True(
            string.Equals(classifiedIncomingWrite.Data.GetValueOrDefault("sampleCorrelation"), "confirmed", StringComparison.OrdinalIgnoreCase),
            "A successful explicit incoming write must remain eligible for sample behavior.");

        foreach (var threadType in new[] { "thread.start", "thread.exit" })
        {
            var benignThread = new SandboxEvent
            {
                EventType = threadType,
                Timestamp = timestamp.AddMilliseconds(300),
                Source = "etwLive",
                ProcessName = "hostname.exe",
                ProcessId = 7001,
                Path = @"C:\Windows\System32\hostname.exe",
                Data =
                {
                    ["captureSource"] = "etwLive",
                    ["processImagePath"] = @"C:\Windows\System32\hostname.exe",
                    ["threadId"] = "42"
                }
            };
            var classifiedThread = SampleCorrelationClassifier.Apply([sample, hostname, benignThread], sample.Path)
                .Single(evt => evt.EventType == threadType && evt.Timestamp == benignThread.Timestamp);
            SmokeAssert.True(
                string.Equals(classifiedThread.Data.GetValueOrDefault("sampleCorrelation"), "environment", StringComparison.OrdinalIgnoreCase),
                $"ETW {threadType} from a signed System32 discovery utility should remain environment evidence.");
        }

        var remoteThread = new SandboxEvent
        {
            EventType = "thread.start",
            Timestamp = timestamp.AddMilliseconds(310),
            Source = "etwLive",
            ProcessName = "hostname.exe",
            ProcessId = 7001,
            Path = @"C:\Windows\System32\hostname.exe",
            Data =
            {
                ["captureSource"] = "etwLive",
                ["processImagePath"] = @"C:\Windows\System32\hostname.exe",
                ["remoteThread"] = "true",
                ["creatorProcessId"] = "7000"
            }
        };
        var classifiedRemoteThread = SampleCorrelationClassifier.Apply([sample, hostname, remoteThread], sample.Path)
            .Single(evt => evt.Timestamp == remoteThread.Timestamp);
        SmokeAssert.True(
            string.Equals(classifiedRemoteThread.Data.GetValueOrDefault("sampleCorrelation"), "confirmed", StringComparison.OrdinalIgnoreCase),
            "Explicit remote-thread evidence must bypass benign discovery suppression.");

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json"));
        var findings = new RuleEngine(rules).Classify(classified);
        SmokeAssert.True(
            !findings.Any(finding => string.Equals(finding.RuleId, "system-discovery-command", StringComparison.OrdinalIgnoreCase)),
            "Environment-classified hostname evidence must not create a primary discovery finding.");

        var highSignalHostname = hostname with
        {
            Data = new Dictionary<string, string>(hostname.Data, StringComparer.OrdinalIgnoreCase)
            {
                ["persistenceCandidate"] = "true",
                ["persistenceFamily"] = "service-configuration"
            }
        };
        var highSignalClassified = SampleCorrelationClassifier.Apply([sample, highSignalHostname], sample.Path)
            .Single(evt => evt.ProcessId == 7001);
        SmokeAssert.True(
            string.Equals(highSignalClassified.Data.GetValueOrDefault("sampleCorrelation"), "confirmed", StringComparison.OrdinalIgnoreCase),
            "Explicit persistence evidence must bypass the System32 discovery baseline guard.");

        // A pre-correlation/externally produced report can still contain the
        // old rule hit. Renderer routing must demote it without dropping raw
        // events or evidence.
        var legacyFinding = new BehaviorFinding
        {
            RuleId = "system-discovery-command",
            Title = "System information discovery command",
            Severity = "medium",
            Tags = ["discovery", "system", "command"],
            Summary = "A command collected host details.",
            Evidence =
            [
                hostname with
                {
                    Data = new Dictionary<string, string>(hostname.Data, StringComparer.OrdinalIgnoreCase)
                    {
                        ["sampleCorrelation"] = "confirmed",
                        ["sampleCorrelationStatus"] = "correlated",
                        ["behaviorCounted"] = "true",
                        ["sampleBehaviorCandidate"] = "true"
                    }
                }
            ]
        };
        var report = new AnalysisReport
        {
            JobId = Guid.Parse("11111111-2222-3333-4444-555555555555"),
            GeneratedAt = timestamp.AddSeconds(1),
            Status = AnalysisStatus.Completed,
            Sample = new SampleIdentity
            {
                FileName = "sample.exe",
                FullPath = sample.Path,
                Sha256 = new string('a', 64),
                Sha1 = new string('b', 40),
                Md5 = new string('c', 32),
                Crc32 = "1234abcd",
                SizeBytes = 1
            },
            Events = classified,
            Findings = [legacyFinding]
        };

        var html = new HtmlReportRenderer().RenderEnglish(report);
        var highRisk = html.Contains("class=\"focus-verdict badge badge-high\"", StringComparison.OrdinalIgnoreCase);
        var critical = html.Contains("class=\"focus-verdict badge badge-critical\"", StringComparison.OrdinalIgnoreCase);
        SmokeAssert.True(!highRisk && !critical,
            $"A discovery-only System32 finding must not raise a high/critical report verdict (high={highRisk}, critical={critical}).");
        SmokeAssert.True(
            html.Contains("<span>Primary findings</span><strong class=\"risk-low\">0</strong>", StringComparison.OrdinalIgnoreCase),
            "A discovery-only System32 finding must be absent from the primary finding count.");
        SmokeAssert.True(html.Contains("System information discovery command", StringComparison.Ordinal),
            "Demoted discovery evidence must remain visible in the report.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "System32 hostname discovery remains raw evidence and cannot drive a suspicious primary verdict."
        });
    }
}
