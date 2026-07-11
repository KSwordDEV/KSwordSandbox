using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the latest behavior-rule quality expansion: each new rule has
/// stable metadata and can be hit by events made only from current
/// SandboxEvent, guest, R0, and PCAP fields.
/// </summary>
internal sealed class BehaviorRuleMitreQualityScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "office-addin-persistence-registry",
        "office-startup-folder-persistence",
        "accessibility-features-ifeo-persistence",
        "logon-script-file-persistence",
        "mavinject-process-injection-command",
        "installutil-proxy-execution-command",
        "msbuild-inline-task-proxy-execution",
        "regasm-regsvcs-proxy-execution-command",
        "lsass-dump-file-created",
        "clipboard-collection-api-observed",
        "screenshot-file-created-by-sample",
        "anti-analysis-uptime-check-command",
        "anti-analysis-parent-process-check-api",
        "windows-credential-staging-command",
        "domain-trust-discovery-command",
        "tor-hidden-service-domain",
        "http-long-encoded-uri-c2",
        "http-domain-fronting-indicator",
        "tls-c2-indicator-fields",
        "process-tree-office-spawned-script",
        "process-tree-browser-spawned-script-or-lolbin",
        "run-key-user-writable-payload",
        "run-key-script-interpreter-payload",
        "startupapproved-run-reenabled",
        "service-binary-user-writable-path",
        "service-unquoted-imagepath-risk",
        "service-failure-command-persistence",
        "service-weak-permission-hijack-metadata",
        "scheduled-task-com-handler-persistence",
        "scheduled-task-xml-user-writable-payload",
        "kernel-driver-service-install",
        "dropped-executable-launched-from-user-writable-path",
        "archive-or-installer-spawns-user-writable-payload",
        "image-load-user-writable-dll",
        "process-access-debug-privilege",
        "token-impersonation-api-observed",
        "uac-bypass-auto-elevate-registry",
        "uac-bypass-auto-elevate-lolbin-command",
        "powershell-in-memory-reflection-loader",
        "powershell-lolbin-child-process-tree",
        "cmstp-profile-proxy-execution-command",
        "control-panel-proxy-execution-command",
        "privilege-debug-backup-restore-enabled",
        "network-periodic-beacon-metadata",
        "dns-reputation-risk-domain",
        "dns-high-entropy-subdomain-metadata",
        "http-json-tasking-or-gate-uri",
        "http-host-header-mismatch-indicator",
        "tls-certificate-reputation-risk",
        "certificate-root-store-command",
        "certificate-root-store-registry-change",
        "anti-analysis-debug-register-check-api",
        "anti-analysis-host-identity-check"
    ];

    private static readonly string[] RequiredTechniqueIds =
    [
        "T1115",
        "T1134.001",
        "T1127.001",
        "T1218.004",
        "T1218.009",
        "T1218.002",
        "T1218.003",
        "T1482",
        "T1548.002",
        "T1553.004",
        "T1574.009",
        "T1574.011"
    ];

    private static readonly string[] BilingualRuleIds =
    [
        "run-key-user-writable-payload",
        "run-key-script-interpreter-payload",
        "startupapproved-run-reenabled",
        "service-binary-user-writable-path",
        "service-unquoted-imagepath-risk",
        "service-failure-command-persistence",
        "service-weak-permission-hijack-metadata",
        "scheduled-task-com-handler-persistence",
        "scheduled-task-xml-user-writable-payload",
        "kernel-driver-service-install",
        "dropped-executable-launched-from-user-writable-path",
        "archive-or-installer-spawns-user-writable-payload",
        "image-load-user-writable-dll",
        "process-access-debug-privilege",
        "token-impersonation-api-observed",
        "uac-bypass-auto-elevate-registry",
        "uac-bypass-auto-elevate-lolbin-command",
        "powershell-in-memory-reflection-loader",
        "powershell-lolbin-child-process-tree",
        "cmstp-profile-proxy-execution-command",
        "control-panel-proxy-execution-command",
        "privilege-debug-backup-restore-enabled",
        "network-periodic-beacon-metadata",
        "dns-reputation-risk-domain",
        "dns-high-entropy-subdomain-metadata",
        "http-json-tasking-or-gate-uri",
        "http-host-header-mismatch-indicator",
        "tls-certificate-reputation-risk",
        "certificate-root-store-command",
        "certificate-root-store-registry-change",
        "anti-analysis-debug-register-check-api",
        "anti-analysis-host-identity-check"
    ];

    private static readonly HashSet<string> AllowedSeverities = new(StringComparer.OrdinalIgnoreCase)
    {
        "info",
        "low",
        "medium",
        "high",
        "critical"
    };

    private static readonly HashSet<string> AllowedConfidences = new(StringComparer.OrdinalIgnoreCase)
    {
        "low",
        "medium",
        "high"
    };

    public string ScenarioId => "behavior.rules-mitre-quality-expansion";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        var mitreMapPath = Path.Combine(context.RulesDirectory, "mitre-windows-map.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");
        SmokeAssert.True(File.Exists(mitreMapPath), "mitre-windows-map.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"Behavior quality rule '{ruleId}' is missing.");
            AssertRuleMetadata(rule!);
        }
        AssertBilingualRuleMetadata(behaviorRulesPath, BilingualRuleIds);

        var findings = new RuleEngine(rules).Classify(CreateSyntheticEvents());
        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic behavior-quality event should match '{ruleId}'.");
        }

        var techniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredTechniqueIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"Behavior rule quality expansion loads and matches {RequiredRuleIds.Length} new rules."
        });
    }

    private static void AssertRuleMetadata(BehaviorRule rule)
    {
        SmokeAssert.True(AllowedSeverities.Contains(rule.Severity), $"Rule '{rule.Id}' has unsupported severity '{rule.Severity}'.");
        SmokeAssert.True(AllowedConfidences.Contains(rule.Confidence), $"Rule '{rule.Id}' has unsupported confidence '{rule.Confidence}'.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueName), $"Rule '{rule.Id}' should include a MITRE technique name.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields used for triage.");
        SmokeAssert.True(
            rule.EventTypes.Count > 0 &&
            (rule.ContainsPath.Count > 0 ||
                rule.AllContainsPath.Count > 0 ||
                rule.PathRegex.Count > 0 ||
                rule.ContainsCommandLine.Count > 0 ||
                rule.AllContainsCommandLine.Count > 0 ||
                rule.CommandLineRegex.Count > 0 ||
                rule.DataKeys.Count > 0 ||
                rule.AllDataKeys.Count > 0 ||
                rule.AbsentDataKeys.Count > 0 ||
                rule.DataEquals.Count > 0 ||
                rule.AllDataEquals.Count > 0 ||
                rule.DataContains.Count > 0 ||
                rule.AllDataContains.Count > 0 ||
                rule.DataContainsAll.Count > 0 ||
                rule.DataRegex.Count > 0 ||
                rule.AllDataRegex.Count > 0 ||
                rule.DataNumericRanges.Count > 0 ||
                rule.AllDataNumericRanges.Count > 0),
            $"Rule '{rule.Id}' should be constrained by event type plus path, command-line, or data evidence.");
    }

    private static void AssertBilingualRuleMetadata(string behaviorRulesPath, IEnumerable<string> ruleIds)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(behaviorRulesPath));
        var required = ruleIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        SmokeAssert.True(document.RootElement.TryGetProperty("rules", out var rulesElement), "behavior-rules.json should contain a rules array.");
        foreach (var ruleElement in rulesElement.EnumerateArray())
        {
            if (!ruleElement.TryGetProperty("id", out var idElement))
            {
                continue;
            }

            var id = idElement.GetString();
            if (string.IsNullOrWhiteSpace(id) || !required.Contains(id))
            {
                continue;
            }

            SmokeAssert.True(HasNonEmptyString(ruleElement, "title"), $"Rule '{id}' should include an English title.");
            SmokeAssert.True(HasNonEmptyString(ruleElement, "summary"), $"Rule '{id}' should include an English summary.");
            SmokeAssert.True(HasNonEmptyString(ruleElement, "titleZh"), $"Rule '{id}' should include a Chinese title.");
            SmokeAssert.True(HasNonEmptyString(ruleElement, "summaryZh"), $"Rule '{id}' should include a Chinese summary.");
        }
    }

    private static bool HasNonEmptyString(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property) &&
            property.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(property.GetString());
    }

    private static IReadOnlyList<SandboxEvent> CreateSyntheticEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Microsoft\Office\Word\Addins\SmokeAddin",
                Data =
                {
                    ["valueName"] = "LoadBehavior",
                    ["value"] = "3"
                }
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = @"C:\Users\Smoke\AppData\Roaming\Microsoft\Word\STARTUP\payload.dotm"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe",
                Data =
                {
                    ["valueName"] = "Debugger",
                    ["value"] = @"C:\Windows\System32\cmd.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "file.modified",
                Source = "guest",
                Path = @"C:\Windows\System32\GroupPolicy\User\Scripts\Logon\logon.bat"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "mavinject.exe",
                CommandLine = @"mavinject.exe 4242 /INJECTRUNNING C:\Users\Public\payload.dll"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "InstallUtil.exe",
                CommandLine = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe C:\Users\Public\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "MSBuild.exe",
                CommandLine = @"MSBuild.exe C:\Users\Public\inline.proj /p:TaskFactory=CodeTaskFactory"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "regasm.exe",
                CommandLine = @"regasm.exe C:\Users\Public\payload.dll /codebase"
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "driver",
                Path = @"C:\Users\Public\lsass.dmp"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "OpenClipboard"
                }
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = @"C:\Users\Public\screenshot.png"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "wmic os get lastbootuptime"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "NtQueryInformationProcess",
                    ["operation"] = "ProcessBasicInformation parent process check"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = @"cmdkey.exe /add:TARGET /user:DOMAIN\smoke /pass:Secret"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "nltest /domain_trusts"
            },
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["queryName"] = "examplehiddenservice.onion",
                    ["queryType"] = "A"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["method"] = "GET",
                    ["host"] = "example.invalid",
                    ["uri"] = "/api/%2f%3d%2b",
                    ["classification"] = "encoded-uri beacon"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.tls",
                Source = "host",
                Data =
                {
                    ["sni"] = "front.example",
                    ["classification"] = "host-sni-mismatch domain-fronting"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["sni"] = "c2.example.invalid",
                    ["ja3"] = "00000000000000000000000000000000",
                    ["classification"] = "suspicious-tls c2"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                Data =
                {
                    ["treeLineage"] = "winword.exe -> powershell.exe -> rundll32.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                Data =
                {
                    ["treeLineage"] = "chrome.exe -> mshta.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Smoke",
                Data =
                {
                    ["value"] = @"C:\Users\Public\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\SmokeScript",
                Data =
                {
                    ["value"] = @"powershell.exe -WindowStyle Hidden -File C:\Users\Public\payload.ps1"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\Smoke",
                Data =
                {
                    ["value"] = "02,00,00,00"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc",
                Data =
                {
                    ["value"] = @"C:\Users\Public\svc.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\QuotedRiskSvc",
                Data =
                {
                    ["imagePath"] = @"C:\Program Files\Quoted Risk\svc.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\FailSvc",
                Data =
                {
                    ["valueName"] = "FailureCommand",
                    ["value"] = @"cmd.exe /c C:\Users\Public\recover.cmd"
                }
            },
            new SandboxEvent
            {
                EventType = "service.acl",
                Source = "guest",
                Data =
                {
                    ["serviceName"] = "WeakSvc",
                    ["serviceAclWeak"] = "true",
                    ["writableBy"] = "Authenticated Users"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{00000000-0000-0000-0000-000000000000}",
                Data =
                {
                    ["value"] = "ComHandler CLSID {11111111-1111-1111-1111-111111111111}"
                }
            },
            new SandboxEvent
            {
                EventType = "file.modified",
                Source = "guest",
                Path = @"C:\Windows\System32\Tasks\SmokeTask",
                Data =
                {
                    ["target"] = @"C:\Users\Public\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeDrv",
                Data =
                {
                    ["imagePath"] = @"C:\Users\Public\smokedrv.sys",
                    ["serviceType"] = "SERVICE_KERNEL_DRIVER"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "payload.exe",
                CommandLine = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                Data =
                {
                    ["treeLineage"] = @"setup.exe -> C:\Users\Public\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "image.load",
                Source = "driver",
                Data =
                {
                    ["imagePath"] = @"C:\Users\Public\payload.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "process.access",
                Source = "driver",
                Data =
                {
                    ["targetProcessName"] = "lsass.exe",
                    ["desiredAccess"] = "PROCESS_ALL_ACCESS",
                    ["privilege"] = "SeDebugPrivilege"
                }
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "DuplicateTokenEx"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKCU\Software\Classes\ms-settings\Shell\Open\command",
                Data =
                {
                    ["valueName"] = "DelegateExecute",
                    ["value"] = @"C:\Users\Public\elevate.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "fodhelper.exe",
                CommandLine = "fodhelper.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = "powershell.exe -nop -c [Reflection.Assembly]::Load([Convert]::FromBase64String('AA=='))"
            },
            new SandboxEvent
            {
                EventType = "process.tree",
                Source = "guest",
                Data =
                {
                    ["treeLineage"] = "powershell.exe -> regsvr32.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "cmstp.exe",
                CommandLine = @"cmstp.exe /s C:\Users\Public\profile.inf"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "control.exe",
                CommandLine = @"control.exe C:\Users\Public\payload.cpl"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "AdjustTokenPrivileges",
                    ["privilege"] = "SeBackupPrivilege"
                }
            },
            new SandboxEvent
            {
                EventType = "network.flow",
                Source = "guest",
                Data =
                {
                    ["beaconIntervalMs"] = "60000",
                    ["jitterPercent"] = "15",
                    ["behavior"] = "periodic beacon"
                }
            },
            new SandboxEvent
            {
                EventType = "dns.query",
                Source = "guest",
                Data =
                {
                    ["queryName"] = "new-c2.example.invalid",
                    ["domainReputation"] = "newly-registered suspicious"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["queryName"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.invalid",
                    ["labelEntropy"] = "high",
                    ["queryLength"] = "96",
                    ["classification"] = "high-entropy"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["host"] = "gate.example.invalid",
                    ["uri"] = "/api/gate",
                    ["contentType"] = "application/json"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["host"] = "front.example.invalid",
                    ["classification"] = "host-header-mismatch"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["sni"] = "c2.example.invalid",
                    ["certReputation"] = "malicious"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "certutil.exe",
                CommandLine = @"certutil.exe -addstore root C:\Users\Public\ca.cer"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\SmokeThumbprint"
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["api"] = "GetThreadContext",
                    ["operation"] = "debug register DR7 hardware breakpoint check"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                Data =
                {
                    ["check"] = "hostname username SandboxUser"
                }
            }
        ];
    }

    private static HashSet<string> ReadMitreTechniqueIds(string mitreMapPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(mitreMapPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("techniques", out var techniques), "MITRE map should contain a techniques array.");

        var techniqueIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var technique in techniques.EnumerateArray())
        {
            if (technique.TryGetProperty("id", out var idElement))
            {
                var id = idElement.GetString();
                if (!string.IsNullOrWhiteSpace(id))
                {
                    techniqueIds.Add(id);
                }
            }
        }

        return techniqueIds;
    }
}
