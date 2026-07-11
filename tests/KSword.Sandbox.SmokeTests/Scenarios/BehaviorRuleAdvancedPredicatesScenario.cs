using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies advanced behavior-rule predicates and the Windows behavior rules
/// that depend on them. Inputs are the repository rule file plus synthetic
/// events; processing checks regex, numeric range, absent-key, and same-field
/// AND matching; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class BehaviorRuleAdvancedPredicatesScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "powershell-encoded-command-base64-regex",
        "powershell-amsi-bypass-scriptblock-field-and",
        "wmic-shadowcopy-delete-field-and",
        "wevtutil-log-clear-command-regex",
        "bcdedit-recovery-ignoreallfailures-command",
        "network-smb-outbound-admin-port-numeric",
        "network-rdp-outbound-port-numeric",
        "network-winrm-outbound-port-numeric",
        "network-tor-socks-listener-port-numeric",
        "pcap-http-large-upload-numeric",
        "dns-very-long-nxdomain-query-numeric",
        "anti-analysis-long-sleep-duration-numeric",
        "process-tree-high-child-count-numeric",
        "ransomware-mass-file-write-burst-numeric",
        "registry-mass-runkey-change-burst-numeric",
        "http-direct-ip-missing-user-agent",
        "tls-ja3-without-sni",
        "download-execute-no-referrer-user-writable",
        "http-uri-api-gate-field-and",
        "credential-cookie-file-path-regex",
        "credential-ntds-dit-path-access-regex",
        "credential-lsass-dump-path-regex",
        "suspicious-service-imagepath-user-writable-regex",
        "suspicious-scheduled-task-payload-regex"
    ];

    private static readonly string[] PrimaryBehaviorRuleIds =
    [
        .. RequiredRuleIds,
        "powershell-encoded-command-execution",
        "ransomware-shadow-copy-deletion-command",
        "tls-ja3-without-sni",
        "http-direct-ip-missing-user-agent"
    ];

    public string ScenarioId => "behavior.rules-advanced-predicates";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        AssertInMemoryPredicateSemantics();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"Advanced-predicate rule '{ruleId}' is missing.");
            AssertAdvancedRuleShape(rule!);
        }

        var findings = new RuleEngine(rules).Classify(CreateSyntheticRuleEvents());
        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic advanced-predicate event should match '{ruleId}'.");
        }

        AssertCollectionHealthAndVirusTotalNotPrimary(rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"Advanced predicates and {RequiredRuleIds.Length} Windows behavior rules matched synthetic evidence."
        });
    }

    private static void AssertInMemoryPredicateSemantics()
    {
        var rules = new BehaviorRuleSet
        {
            Rules =
            [
                new BehaviorRule
                {
                    Id = "synthetic-regex",
                    Title = "Synthetic regex",
                    EventTypes = ["process.start"],
                    CommandLineRegex = [@"\bpowershell(?:\.exe)?\b.*\s-enc\s+[A-Za-z0-9+/]{20,}"],
                    Tags = ["test"]
                },
                new BehaviorRule
                {
                    Id = "synthetic-numeric-any",
                    Title = "Synthetic numeric any",
                    EventTypes = ["network.tcp"],
                    DataNumericRanges = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["remotePort"] = [new BehaviorRuleNumericRange { Min = 5985, Max = 5986 }]
                    },
                    Tags = ["test"]
                },
                new BehaviorRule
                {
                    Id = "synthetic-numeric-all",
                    Title = "Synthetic numeric all",
                    EventTypes = ["network.flow"],
                    AllDataNumericRanges = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["beaconIntervalMs"] = [new BehaviorRuleNumericRange { Min = 30000, Max = 120000 }],
                        ["jitterPercent"] = [new BehaviorRuleNumericRange { Min = 5, Max = 50 }]
                    },
                    Tags = ["test"]
                },
                new BehaviorRule
                {
                    Id = "synthetic-absent",
                    Title = "Synthetic absent",
                    EventTypes = ["http.request"],
                    DataRegex = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["host"] = [@"^(?:\d{1,3}\.){3}\d{1,3}$"]
                    },
                    AbsentDataKeys = ["userAgent"],
                    Tags = ["test"]
                },
                new BehaviorRule
                {
                    Id = "synthetic-field-and",
                    Title = "Synthetic field AND",
                    EventTypes = ["powershell.scriptblock"],
                    DataContainsAll = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["scriptBlockText"] = ["AmsiUtils", "amsiInitFailed"]
                    },
                    Tags = ["test"]
                },
                new BehaviorRule
                {
                    Id = "synthetic-all-regex",
                    Title = "Synthetic all regex",
                    EventTypes = ["network.tls"],
                    AllDataRegex = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ja3"] = [@"^[a-f0-9]{32}$"]
                    },
                    AbsentDataKeys = ["sni"],
                    Tags = ["test"]
                }
            ]
        };

        var findings = new RuleEngine(rules).Classify(
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "powershell.exe -enc SQBFAFgAQQBNAFAATABFAEIAQQBTAEUANgA0AA=="
            },
            new SandboxEvent
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["remotePort"] = "5985"
                }
            },
            new SandboxEvent
            {
                EventType = "network.flow",
                Source = "guest",
                Data =
                {
                    ["beaconIntervalMs"] = "60000",
                    ["jitterPercent"] = "12.5"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["host"] = "198.51.100.25"
                }
            },
            new SandboxEvent
            {
                EventType = "powershell.scriptblock",
                Source = "guest",
                Data =
                {
                    ["scriptBlockText"] = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["ja3"] = "0123456789abcdef0123456789abcdef"
                }
            }
        ]);

        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var expected in new[]
        {
            "synthetic-regex",
            "synthetic-numeric-any",
            "synthetic-numeric-all",
            "synthetic-absent",
            "synthetic-field-and",
            "synthetic-all-regex"
        })
        {
            SmokeAssert.True(findingIds.Contains(expected), $"In-memory advanced predicate '{expected}' should match.");
        }

        var absentGuardFindings = new RuleEngine(rules).Classify(
        [
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["host"] = "198.51.100.25",
                    ["userAgent"] = "Mozilla/5.0"
                }
            }
        ]);
        SmokeAssert.True(
            absentGuardFindings.All(finding => !string.Equals(finding.RuleId, "synthetic-absent", StringComparison.OrdinalIgnoreCase)),
            "Absent-key predicate should not match when the key is present.");
    }

    private static void AssertAdvancedRuleShape(BehaviorRule rule)
    {
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(rule.Tags.Count > 0, $"Rule '{rule.Id}' should include tags.");
        SmokeAssert.True(
            rule.PathRegex.Count > 0 ||
            rule.CommandLineRegex.Count > 0 ||
            rule.AbsentDataKeys.Count > 0 ||
            rule.DataContainsAll.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataRegex.Count > 0 ||
            rule.DataNumericRanges.Count > 0 ||
            rule.AllDataNumericRanges.Count > 0,
            $"Rule '{rule.Id}' should exercise at least one advanced predicate.");
    }

    private static void AssertCollectionHealthAndVirusTotalNotPrimary(BehaviorRuleSet rules)
    {
        var findings = new RuleEngine(rules).Classify(
        [
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "virustotal",
                Data =
                {
                    ["host"] = "198.51.100.20",
                    ["status"] = "not_configured",
                    ["message"] = "VirusTotal not configured"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Data =
                {
                    ["ja3"] = "0123456789abcdef0123456789abcdef",
                    ["message"] = "collection health"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                CommandLine = "powershell.exe -enc SQBFAFgAQQBNAFAATABFAEIAQQBTAEUANgA0AA==",
                Data =
                {
                    ["component"] = "KSword.Sandbox.R0Collector"
                }
            }
        ]);

        var unexpected = findings
            .Where(finding => PrimaryBehaviorRuleIds.Contains(finding.RuleId, StringComparer.OrdinalIgnoreCase))
            .Select(finding => finding.RuleId)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        SmokeAssert.True(unexpected.Count == 0, "Collection health and VT unset rows should not trigger primary advanced behavior rules: " + string.Join(", ", unexpected));
    }

    private static IReadOnlyList<SandboxEvent> CreateSyntheticRuleEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = "powershell.exe -NoProfile -EncodedCommand SQBFAFgAQQBNAFAATABFAEIAQQBTAEUANgA0AA=="
            },
            new SandboxEvent
            {
                EventType = "powershell.scriptblock",
                Source = "guest",
                ProcessName = "powershell.exe",
                Data =
                {
                    ["scriptBlockText"] = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "wmic.exe",
                CommandLine = "wmic shadowcopy delete /nointeractive",
                Data =
                {
                    ["commandLine"] = "wmic shadowcopy delete /nointeractive"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "wevtutil.exe",
                CommandLine = "wevtutil cl Security"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "bcdedit.exe",
                CommandLine = "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
            },
            new SandboxEvent
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["remoteAddress"] = "10.0.0.10",
                    ["remotePort"] = "445"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["remoteAddress"] = "10.0.0.11",
                    ["remotePort"] = "3389"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tcp",
                Source = "guest",
                Data =
                {
                    ["remoteAddress"] = "10.0.0.12",
                    ["remotePort"] = "5986"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tcp.listener.opened",
                Source = "guest",
                Data =
                {
                    ["localAddress"] = "127.0.0.1",
                    ["localPort"] = "9050",
                    ["state"] = "LISTENING"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["method"] = "POST",
                    ["host"] = "upload.example.invalid",
                    ["uri"] = "/api/upload",
                    ["uploadBytes"] = "2097152"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["queryName"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.invalid",
                    ["queryLength"] = "96",
                    ["rcode"] = "NXDOMAIN"
                }
            },
            new SandboxEvent
            {
                EventType = "api.sleep",
                Source = "guest",
                Data =
                {
                    ["durationMs"] = "600000"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                Data =
                {
                    ["childProcessCount"] = "25",
                    ["treeLineage"] = "payload.exe -> cmd.exe -> powershell.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "file.activity",
                Source = "driver",
                Data =
                {
                    ["writeCount"] = "350",
                    ["classification"] = "ransom encryption burst"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.activity",
                Source = "driver",
                Data =
                {
                    ["setCount"] = "75",
                    ["pathScope"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["host"] = "198.51.100.44",
                    ["uri"] = "/gate"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["ja3"] = "0123456789abcdef0123456789abcdef",
                    ["destinationIp"] = "198.51.100.45"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                Data =
                {
                    ["downloadPath"] = @"C:\Users\Smoke\Downloads\payload.exe",
                    ["executedPath"] = @"C:\Users\Smoke\Downloads\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["host"] = "gate.example.invalid",
                    ["uri"] = "/api/gate?bot=SMOKE1234",
                    ["method"] = "GET"
                }
            },
            new SandboxEvent
            {
                EventType = "file.open",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"C:\Users\Smoke\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
            },
            new SandboxEvent
            {
                EventType = "file.open",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"C:\Windows\NTDS\ntds.dit"
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "driver",
                ProcessName = "rundll32.exe",
                Path = @"C:\Users\Smoke\AppData\Local\Temp\lsass-4242.dmp"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc",
                Data =
                {
                    ["imagePath"] = @"C:\Users\Smoke\AppData\Local\Temp\svc.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "scheduled_task.created",
                Source = "guest",
                Path = @"\SmokeTask",
                Data =
                {
                    ["taskName"] = @"\SmokeTask",
                    ["taskToRun"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.ps1"
                }
            }
        ];
    }
}
