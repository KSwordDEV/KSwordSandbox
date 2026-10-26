using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Correlation;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the 2026-10-19 rule/attribution fixes against the real rules file.
/// Inputs are behavior-rules.json and representative normalized rows; the
/// scenario checks the new C2/child-process/egress/browser rules and the
/// path-AND, noise-exclusion, and owner-PID attribution corrections that the
/// live batch exposed.
/// </summary>
internal sealed class RuleAttributionFixContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "rules.attribution-fix.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(rulesPath), "behavior-rules.json is missing.");
        var engine = new RuleEngine(RuleEngine.LoadRuleSet(rulesPath));
        var start = DateTimeOffset.UtcNow;

        var c2 = engine.Classify(
        [
            Event("dns.query", "ravor.ac.ug", start, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["pcapCorrelationStaticIocMatched"] = "true",
                ["pcapCorrelationDnsCorroborated"] = "false",
                ["pcapCorrelationStaticIoc"] = "ravor.ac.ug",
                ["sampleCorrelation"] = "probable"
            })
        ]);
        RequireSeverity(c2, "c2-static-ioc-corroborated-egress", "high");

        var c2Environment = engine.Classify(
        [
            Event("dns.query", "ravor.ac.ug", start, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["pcapCorrelationStaticIocMatched"] = "true",
                ["sampleCorrelation"] = "environment"
            })
        ]);
        RequireAbsent(c2Environment, "c2-static-ioc-corroborated-egress");

        var dnsAnswerOnly = engine.Classify(
        [
            Event("dns.query", "c2.bad.test", start, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["pcapCorrelationStaticIocMatched"] = "true",
                ["pcapCorrelationDnsCorroborated"] = "true",
                ["sampleCorrelation"] = "probable"
            })
        ]);
        RequireAbsent(dnsAnswerOnly, "c2-static-ioc-corroborated-egress");

        var child = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start,
                ProcessName = "payload.exe",
                ProcessId = 5216,
                ParentProcessId = 8480,
                Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["sampleChildProcess"] = "true"
                }
            }
        ]);
        RequireSeverity(child, "sample-child-process-spawned", "medium");

        var unmarkedChild = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "etwLive",
                Timestamp = start,
                ProcessName = "payload.exe",
                ProcessId = 5216,
                ParentProcessId = 8480,
                Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["parentProcessId"] = "8480"
                }
            }
        ]);
        RequireAbsent(unmarkedChild, "sample-child-process-spawned");

        // The guest loader starts Fondue.exe with a Windows feature switch
        // when a submitted image cannot load its runtime.  Its parent is the
        // sample PID, but the classifier must keep the sample-child marker
        // off so the fix does not report guest repair as malicious descent.
        var repair = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "guest",
                    Timestamp = start,
                    ProcessName = "agenttesla.exe",
                    ProcessId = 8480,
                    Path = @"C:\samples\agenttesla.exe",
                    CommandLine = @"C:\samples\agenttesla.exe",
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = @"C:\samples\agenttesla.exe"
                    }
                },
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "etwLive",
                    Timestamp = start,
                    ProcessName = "Fondue.exe",
                    ProcessId = 5216,
                    ParentProcessId = 8480,
                    Path = @"C:\Windows\System32\fondue.exe",
                    CommandLine = @"C:\Windows\System32\fondue.exe /enable-feature:NetFx3 /caller-name:mscoreei.dll",
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = @"C:\Windows\System32\fondue.exe",
                        ["commandLine"] = @"C:\Windows\System32\fondue.exe /enable-feature:NetFx3 /caller-name:mscoreei.dll"
                    }
                },
                new SandboxEvent
                {
                    EventType = "process.new",
                    Source = "guest",
                    Timestamp = start,
                    ProcessName = string.Empty,
                    ProcessId = 6400,
                    ParentProcessId = 8480,
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processName"] = "Fondue.exe",
                        ["parentProcessId"] = "8480",
                        ["processRole"] = "process-snapshot"
                    }
                },
                new SandboxEvent
                {
                    EventType = "process.new",
                    Source = "guest",
                    Timestamp = start,
                    ProcessName = string.Empty,
                    ProcessId = 6600,
                    ParentProcessId = 8480,
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processName"] = "payload.exe",
                        ["parentProcessId"] = "8480",
                        ["processRole"] = "process-snapshot",
                        ["childSummary"] = "payload.exe"
                    }
                },
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "etwLive",
                    Timestamp = start,
                    ProcessName = "payload.exe",
                    ProcessId = 5300,
                    ParentProcessId = 8480,
                    Path = @"C:\Users\SandboxUser\AppData\Local\Temp\payload.exe",
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = @"C:\Users\SandboxUser\AppData\Local\Temp\payload.exe"
                    }
                }
            ],
            @"C:\samples\agenttesla.exe");
        SmokeAssert.True(
            !repair.Single(evt => evt.ProcessId == 5216).Data.TryGetValue("sampleChildProcess", out var repairMarker),
            "Fondue.exe started for a guest feature repair must not be marked as a sample child.");
        SmokeAssert.True(
            !repair.Single(evt => evt.ProcessId == 6400).Data.TryGetValue("sampleChildProcess", out var snapshotMarker),
            "A process.new snapshot row for Fondue.exe without a command line must not be marked as a sample child.");
        SmokeAssert.True(
            !repair.Single(evt => evt.ProcessId == 6600).Data.TryGetValue("sampleChildProcess", out var snapshotOnlyMarker),
            "A snapshot-only process.new row without a command line must never carry the sampleChildProcess marker.");
        SmokeAssert.True(
            repair.Single(evt => evt.ProcessId == 5300).Data.TryGetValue("sampleChildProcess", out var payloadMarker) &&
            string.Equals(payloadMarker, "true", StringComparison.OrdinalIgnoreCase),
            "A payload child started under the sample PID must keep the sample-child marker.");

        // A security-service state change with no cross-source sample evidence
        // stays probable, and the row must disclose why it is only probable by
        // carrying both the reason and the uncertainty marker in its Data so
        // the report side can render the attribution boundary.
        var serviceChange = SampleCorrelationClassifier.Apply(
            [
                new SandboxEvent
                {
                    EventType = "process.start",
                    Source = "etwLive",
                    Timestamp = start,
                    ProcessName = "agenttesla.exe",
                    ProcessId = 8480,
                    Path = @"C:\samples\agenttesla.exe",
                    CommandLine = @"C:\samples\agenttesla.exe",
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["processImagePath"] = @"C:\samples\agenttesla.exe"
                    }
                },
                new SandboxEvent
                {
                    EventType = "service.modified",
                    Source = "guest",
                    Timestamp = start,
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["serviceName"] = "WdNisSvc",
                        ["displayName"] = "Windows Defender Network Inspection Service",
                        ["imagePath"] = @"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2300.0-0\WdNisSvc.exe",
                        ["keyPath"] = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc",
                        ["startType"] = "demand",
                        ["previousState"] = "running",
                        ["state"] = "stopped"
                    }
                }
            ],
            @"C:\samples\agenttesla.exe");
        var defenderRow = serviceChange.Single(evt => evt.EventType == "service.modified").Data;
        SmokeAssert.True(
            string.Equals(defenderRow.GetValueOrDefault("sampleCorrelation"), "probable", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(defenderRow.GetValueOrDefault("sampleCorrelationReason"), "service-change-targets-security-service-without-cross-source", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(defenderRow.GetValueOrDefault("sampleCorrelationUncertainty")),
            "A Defender security-service change without cross-source evidence must stay probable with reason and uncertainty written into Data.");

        var synSent = engine.Classify(
        [
            TcpEvent(start, "SynSent", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["sampleOwnerPidMatched"] = "true",
                ["sampleCorrelation"] = "confirmed"
            })
        ]);
        RequireSeverity(synSent, "outbound-connection-attempt-blocked", "medium");
        RequireSeverity(synSent, "network-connection", "medium");

        var established = engine.Classify(
        [
            TcpEvent(start, "Established", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["sampleOwnerPidMatched"] = "true",
                ["sampleCorrelation"] = "confirmed"
            })
        ]);
        RequireAbsent(established, "outbound-connection-attempt-blocked");

        var unattributedTcp = engine.Classify(
        [
            TcpEvent(start, "Established", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["sampleCorrelation"] = "environment"
            })
        ]);
        RequireAbsent(unattributedTcp, "network-connection");

        var browser = engine.Classify(
        [
            FileEvent(@"C:\Users\SandboxUser\AppData\Local\Google\Chrome\User Data\Default\Login Data", start,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
        ]);
        RequireSeverity(browser, "browser-credential-store-path-observed", "high");

        var browserNoise = engine.Classify(
        [
            FileEvent(@"C:\Users\SandboxUser\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\Cookies", start,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
        ]);
        RequireAbsent(browserNoise, "browser-credential-store-path-observed");

        // Emotet anchor: the Run value is written by an injected explorer.exe
        // and stored with the %LOCALAPPDATA% token unexpanded.  The rule must
        // key on the autostart value path, not on the writing process, and
        // must recognize the LOCALAPPDATA token.
        var runKey = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "guest",
                Timestamp = start,
                ProcessName = "explorer.exe",
                Path = @"\Registry\User\S-1-5-21-0\Software\Microsoft\Windows\CurrentVersion\Run\{11111111-2222-4333-8444-555555555555}",
                Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["valueName"] = "{11111111-2222-4333-8444-555555555555}",
                    ["value"] = @"%LOCALAPPDATA%\{11111111-2222-4333-8444-555555555555}.exe"
                }
            }
        ]);
        RequireSeverity(runKey, "run-key-user-writable-payload", "high");

        // X1: an .exe.log under UsageLogs must not satisfy the System32 rule
        // merely because the string ends in ".log"; it also must not match the
        // Temp/AppData rule because that rule now requires the extension.
        var usageLog = engine.Classify(
        [
            FileEvent(@"C:\Users\SandboxUser\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\kpot-36dc.exe.log", start,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
        ]);
        RequireAbsent(usageLog, "system-directory-executable-write");
        RequireAbsent(usageLog, "temp-executable-drop");

        // X2: a script under Temp is still a real drop, while a PowerShell
        // self-test file is excluded by the shared noise filter.
        var tempDrop = engine.Classify(
        [
            FileEvent(@"C:\Users\SandboxUser\AppData\Local\Temp\payload.exe", start,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
        ]);
        RequireSeverity(tempDrop, "temp-executable-drop", "medium");

        var policyTest = engine.Classify(
        [
            FileEvent(@"C:\Users\SandboxUser\AppData\Local\Temp\__PSScriptPolicyTest_xtczhp0m.ofq.ps1", start,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
        ]);
        RequireAbsent(policyTest, "temp-executable-drop");
        RequireAbsent(policyTest, "script-file-drop");
        RequireAbsent(policyTest, "executable-file-write");
        RequireAbsent(policyTest, "download-archive-or-script-stage");

        // X6: fileName is not a process name. A row that names powershell.exe
        // as the dropped file must not inherit the exclusion, while an actual
        // powershell.exe actor still does.
        var fileNameOnly = engine.Classify(
        [
            FileEvent(@"C:\Users\SandboxUser\AppData\Local\Temp\payload.ps1", start,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["fileName"] = "powershell.exe"
                })
        ]);
        RequireSeverity(fileNameOnly, "temp-executable-drop", "medium");

        var powershellActor = engine.Classify(
        [
            FileEvent(@"C:\Users\SandboxUser\AppData\Local\Temp\payload.ps1", start,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["processName"] = "powershell.exe"
                })
        ]);
        RequireAbsent(powershellActor, "temp-executable-drop");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "New C2/child-process/egress/browser rules fire on measured shapes, and path-AND, noise exclusion, and owner-PID attribution no longer rely on file names or OR path fragments."
        });
    }

    private static SandboxEvent Event(
        string eventType,
        string path,
        DateTimeOffset timestamp,
        Dictionary<string, string> data)
    {
        return new SandboxEvent
        {
            EventType = eventType,
            Source = "host",
            Timestamp = timestamp,
            Path = path,
            Data = data
        };
    }

    private static SandboxEvent FileEvent(string path, DateTimeOffset timestamp, Dictionary<string, string> data)
    {
        return Event("file.created", path, timestamp, data);
    }

    private static SandboxEvent TcpEvent(DateTimeOffset timestamp, string state, Dictionary<string, string> data)
    {
        data["state"] = state;
        data["owningProcessId"] = "1216";
        data["remote"] = "31.13.85.53:443";
        return new SandboxEvent
        {
            EventType = "network.tcp",
            Source = "guest",
            Timestamp = timestamp,
            ProcessId = 1216,
            ProcessName = "kpot-36dc.exe",
            Data = data
        };
    }

    private static void RequireSeverity(IReadOnlyCollection<BehaviorFinding> findings, string ruleId, string severity)
    {
        var finding = findings.SingleOrDefault(item => string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(finding is not null, $"Expected rule {ruleId} to fire.");
        SmokeAssert.True(
            string.Equals(finding!.Severity, severity, StringComparison.OrdinalIgnoreCase),
            $"Expected rule {ruleId} severity {severity}, got {finding.Severity}.");
    }

    private static void RequireAbsent(IReadOnlyCollection<BehaviorFinding> findings, string ruleId)
    {
        SmokeAssert.True(
            findings.All(item => !string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase)),
            $"Expected rule {ruleId} not to fire.");
    }
}
