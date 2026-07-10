using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies expanded behavior-rule coverage for persistence, injection,
/// lateral movement, anti-analysis, download execution, credential access,
/// C2/DNS/HTTP/TLS, and PCAP placeholder rules.
/// </summary>
internal sealed class BehaviorRuleExpansionScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "downloaded-file-zone-identifier",
        "browser-download-cache-write",
        "execution-from-downloads-or-staging-path",
        "download-archive-or-script-stage",
        "download-execute-chain-placeholder",
        "process-injection-memory-primitive",
        "process-injection-thread-or-apc-primitive",
        "process-hollowing-signal",
        "rwx-memory-protection-change",
        "dll-injection-loadlibrary-signal",
        "wmi-event-subscription-persistence",
        "wmi-event-subscription-command",
        "com-hijack-persistence",
        "appinit-dlls-persistence",
        "lsa-security-provider-persistence",
        "psexec-or-remote-service-lateral-command",
        "winrm-powershell-remoting-lateral-command",
        "admin-share-or-remote-copy-command",
        "wmi-remote-execution-command",
        "anti-analysis-sandbox-artifact-command",
        "anti-analysis-user-activity-check",
        "anti-analysis-security-tool-termination-command",
        "lsass-memory-dump-command",
        "lsass-process-access-observed",
        "credential-store-access-observed",
        "credential-dumping-tool-command",
        "network-c2-beacon-event",
        "network-c2-indicator-fields",
        "dns-c2-tunnel-placeholder",
        "http-c2-suspicious-user-agent",
        "tls-sni-ja3-placeholder",
        "pcap-artifact-placeholder",
        "pcap-protocol-summary-placeholder"
    ];

    public string ScenarioId => "behavior.rules-expansion-coverage";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var ruleIds = rules.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(ruleIds.Contains(ruleId), $"Expanded behavior rule '{ruleId}' is missing.");
        }

        var engine = new RuleEngine(rules);
        var findings = engine.Classify(CreateSyntheticEvents());
        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic expanded behavior events should match '{ruleId}'.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Expanded behavior rules load and match representative synthetic events."
        });
    }

    /// <summary>
    /// Builds one synthetic event set that exercises every expanded rule group.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> CreateSyntheticEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = @"C:\Users\Smoke\Downloads\payload.iso",
                Data =
                {
                    ["stream"] = "Zone.Identifier",
                    ["details"] = "ZoneId=3 Mark-of-the-Web"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                Path = @"C:\Users\Smoke\Downloads\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"C:\Users\Public\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "WriteProcessMemory"
                }
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "CreateRemoteThread"
                }
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["operation"] = "CREATE_SUSPENDED NtUnmapViewOfSection SetThreadContext ResumeThread"
                }
            },
            new SandboxEvent
            {
                EventType = "memory.protect",
                Source = "guest",
                Data =
                {
                    ["newProtection"] = "PAGE_EXECUTE_READWRITE"
                }
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "LoadLibraryW"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SOFTWARE\Microsoft\WMI\root\subscription\__EventFilter\Smoke"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"wmic /namespace:\\root\subscription PATH __EventFilter CREATE Name='Smoke'"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"PsExec.exe \\TARGET -s cmd.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"powershell Invoke-Command -ComputerName TARGET -ScriptBlock { whoami }"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"cmd /c net use \\TARGET\ADMIN$ && copy payload.exe \\TARGET\ADMIN$\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"wmic /node:TARGET process call create calc.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"cmd /c tasklist | findstr /i vboxservice vmtoolsd"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "taskkill /im procmon.exe /f"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"procdump.exe -ma lsass.exe C:\Temp\lsass.dmp"
            },
            new SandboxEvent
            {
                EventType = "process.access",
                Source = "driver",
                Data =
                {
                    ["targetProcessName"] = "lsass.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "file.open",
                Source = "driver",
                Path = @"C:\Windows\System32\config\SAM"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
            },
            new SandboxEvent
            {
                EventType = "c2.beacon",
                Source = "guest"
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["behavior"] = "c2 beacon checkin",
                    ["userAgent"] = "python-requests/2.31"
                }
            },
            new SandboxEvent
            {
                EventType = "dns.query",
                Source = "guest",
                Data =
                {
                    ["recordType"] = "TXT",
                    ["classification"] = "dns tunnel c2"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["sni"] = "example.invalid",
                    ["ja3"] = "00000000000000000000000000000000"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.summary",
                Source = "host"
            },
            new SandboxEvent
            {
                EventType = "pcap.protocol.summary",
                Source = "host",
                Data =
                {
                    ["protocols"] = "dns,http,tls"
                }
            }
        ];
    }
}
