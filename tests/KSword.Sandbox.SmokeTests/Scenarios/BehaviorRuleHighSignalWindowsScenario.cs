using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the v20 high-signal Windows behavior rules. Inputs are repository
/// rules plus synthetic runtime/network events; processing checks constrained
/// predicates, MITRE map coverage, duplicate IDs, positive matches, and
/// collection/VT/R0 noise suppression; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class BehaviorRuleHighSignalWindowsScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "persistence-silentprocessexit-monitorprocess-user-writable",
        "persistence-print-processor-user-writable-dll",
        "persistence-winsock-provider-user-writable-dll",
        "injection-early-bird-apc-suspended-resume-sequence",
        "injection-process-herpaderping-delete-pending-image",
        "lateral-winrm-wsman-remote-shell-command",
        "lateral-smb-atsvc-named-pipe-task-registration",
        "lateral-rdp-tscon-system-session-hijack",
        "anti-sandbox-firmware-wmi-vm-gate",
        "anti-sandbox-short-uptime-exit-gate",
        "download-execute-mounted-image-lnk-payload",
        "download-execute-script-interpreter-motw",
        "c2-websocket-upgrade-nonbrowser-user-agent",
        "c2-doh-post-high-entropy-query",
        "c2-mtls-client-cert-rare-ja3"
    ];

    private static readonly HashSet<string> RequiredRuleIdSet = new(RequiredRuleIds, StringComparer.OrdinalIgnoreCase);

    public string ScenarioId => "behavior.rules-high-signal-windows-v20";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        var mitreMapPath = Path.Combine(context.RulesDirectory, "mitre-windows-map.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");
        SmokeAssert.True(File.Exists(mitreMapPath), "mitre-windows-map.json is missing.");

        AssertRulesJsonParsesWithUniqueIds(behaviorRulesPath);
        var mitreTechniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        SmokeAssert.True(mitreTechniqueIds.Contains("T1547.012"), "MITRE map should include Print Processors (T1547.012).");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"High-signal Windows rule '{ruleId}' is missing.");
            AssertHighSignalRuleShape(rule!, mitreTechniqueIds);
        }

        var engine = new RuleEngine(rules);
        var positiveFindings = engine.Classify(CreatePositiveEvents());
        var positiveRuleIds = positiveFindings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(positiveRuleIds.Contains(ruleId), $"Synthetic high-signal Windows event should match '{ruleId}'.");
        }

        var noiseFindings = engine.Classify(CreateCollectionVirusTotalR0NoiseEvents());
        var unexpectedNoiseRuleIds = noiseFindings
            .Where(finding => RequiredRuleIdSet.Contains(finding.RuleId))
            .Select(finding => finding.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        SmokeAssert.True(
            unexpectedNoiseRuleIds.Count == 0,
            "Collection/VT/R0 noise should not trigger v20 high-signal rules: " + string.Join(", ", unexpectedNoiseRuleIds));

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} v20 high-signal Windows behavior rules match positive evidence and suppress collection/VT/R0 noise."
        });
    }

    private static void AssertHighSignalRuleShape(BehaviorRule rule, HashSet<string> mitreTechniqueIds)
    {
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.Summary), $"Rule '{rule.Id}' should include an analyst summary.");
        SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.MitreTechniqueId), $"Rule '{rule.Id}' should include a MITRE technique ID.");
        SmokeAssert.True(mitreTechniqueIds.Contains(rule.MitreTechniqueId!), $"Rule '{rule.Id}' MITRE technique '{rule.MitreTechniqueId}' is missing from mitre-windows-map.json.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(HasStrongPredicate(rule), $"Rule '{rule.Id}' should use regex, all-of, exact, numeric, or same-field predicates; broad substring-only rules are not allowed.");
        SmokeAssert.True(
            rule.Tags.Contains("mitre", StringComparer.OrdinalIgnoreCase) &&
            rule.Tags.Any(tag => tag is "persistence" or "injection" or "lateral-movement" or "anti-sandbox" or "download-execute" or "network"),
            $"Rule '{rule.Id}' should carry MITRE plus behavior-family tags.");

        SmokeAssert.True(
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.Agent.exe", StringComparer.OrdinalIgnoreCase) &&
            rule.ExcludeProcessNames.Contains("KSword.Sandbox.R0Collector.exe", StringComparer.OrdinalIgnoreCase),
            $"Rule '{rule.Id}' should exclude sandbox agent and R0 collector process self-noise.");
        SmokeAssert.True(
            ContainsGuard(rule.ExcludeDataContains, "source", "r0collector") &&
            ContainsGuard(rule.ExcludeDataContains, "source", "virustotal") &&
            ContainsGuard(rule.ExcludeDataContains, "vtStatus", "not_configured") &&
            ContainsGuard(rule.ExcludeDataContains, "healthStatus", "collection-health") &&
            ContainsGuard(rule.ExcludeDataContains, "collectorSelfNoise", "true") &&
            ContainsGuard(rule.ExcludeDataContains, "collectorNoise", "true") &&
            ContainsGuard(rule.ExcludeDataEquals, "behaviorCounted", "false") &&
            ContainsGuard(rule.ExcludeDataEquals, "nonbehavior", "true"),
            $"Rule '{rule.Id}' should explicitly guard collection, VirusTotal, behaviorCounted/nonbehavior, and R0/self-noise data.");
    }

    private static bool HasStrongPredicate(BehaviorRule rule)
    {
        return rule.AllContainsPath.Count > 0 ||
            rule.PathRegex.Count > 0 ||
            rule.AllContainsCommandLine.Count > 0 ||
            rule.CommandLineRegex.Count > 0 ||
            rule.AllDataKeys.Count > 0 ||
            rule.AbsentDataKeys.Count > 0 ||
            rule.AllDataEquals.Count > 0 ||
            rule.DataContainsAll.Count > 0 ||
            rule.AllDataContains.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataRegex.Count > 0 ||
            rule.DataNumericRanges.Count > 0 ||
            rule.AllDataNumericRanges.Count > 0;
    }

    private static bool ContainsGuard(IReadOnlyDictionary<string, List<string>> guards, string key, string expected)
    {
        return guards.TryGetValue(key, out var values) &&
            values.Any(value => value.Contains(expected, StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe\MonitorProcess",
                Data =
                {
                    ["valueName"] = "MonitorProcess",
                    ["value"] = @"C:\Users\Public\mon.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\SmokePrint\Driver",
                Data =
                {
                    ["valueName"] = "Driver",
                    ["driverPath"] = @"C:\Users\Public\printproc.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\000000000001",
                Data =
                {
                    ["valueName"] = "PackedCatalogItem",
                    ["providerPath"] = @"C:\Users\Public\winsockshim.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                Data =
                {
                    ["operation"] = "CreateProcess CREATE_SUSPENDED VirtualAllocEx WriteProcessMemory QueueUserAPC ResumeThread",
                    ["targetProcessName"] = "svchost.exe",
                    ["targetThreadId"] = "8844"
                }
            },
            new SandboxEvent
            {
                EventType = "process.image",
                Source = "guest",
                Data =
                {
                    ["operation"] = "CreateFile WriteFile SetFileInformationByHandle CreateProcess",
                    ["imageMutation"] = "delete-pending image-overwrite",
                    ["imagePath"] = @"C:\Users\Public\payload.exe",
                    ["targetProcessName"] = "payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["method"] = "POST",
                    ["uri"] = "/wsman",
                    ["host"] = "target.example",
                    ["action"] = "CreateShell Command http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
                    ["destinationPort"] = "5985"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.smb",
                Source = "host",
                Data =
                {
                    ["sourceIp"] = "10.0.0.5",
                    ["destinationIp"] = "10.0.0.10",
                    ["pipeName"] = @"\PIPE\atsvc",
                    ["operation"] = "SchRpcRegisterTask remote scheduled task",
                    ["shareName"] = "IPC$"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "tscon.exe",
                CommandLine = "tscon.exe 2 /dest:rdp-tcp#5",
                Data =
                {
                    ["tokenUser"] = @"NT AUTHORITY\SYSTEM",
                    ["integrityLevel"] = "System"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = "powershell.exe Get-CimInstance Win32_BIOS | ? { $_.Manufacturer -match 'VMware|VirtualBox|QEMU' }",
                Data =
                {
                    ["action"] = "exit gate",
                    ["check"] = "firmware vendor"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                Data =
                {
                    ["check"] = "GetTickCount uptime",
                    ["action"] = "exit gate",
                    ["uptimeSeconds"] = "120",
                    ["thresholdSeconds"] = "600"
                }
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                Data =
                {
                    ["containerPath"] = @"C:\Users\Smoke\Downloads\invoice.iso",
                    ["downloadPath"] = @"C:\Users\Smoke\Downloads\invoice.iso",
                    ["executedPath"] = @"E:\invoice.lnk"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "powershell.exe",
                CommandLine = @"powershell.exe -ExecutionPolicy Bypass -File C:\Users\Smoke\Downloads\stage.ps1",
                Data =
                {
                    ["zoneIdentifier"] = "ZoneId=3 Mark-of-the-Web",
                    ["downloadPath"] = @"C:\Users\Smoke\Downloads\stage.ps1"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["method"] = "GET",
                    ["host"] = "socket.example.invalid",
                    ["uri"] = "/api/socket",
                    ["headers"] = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: abc",
                    ["userAgent"] = "python-requests/2.31"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["method"] = "POST",
                    ["host"] = "cloudflare-dns.com",
                    ["uri"] = "/dns-query",
                    ["contentType"] = "application/dns-message",
                    ["queryLength"] = "128"
                }
            },
            new SandboxEvent
            {
                EventType = "network.tls",
                Source = "guest",
                Data =
                {
                    ["sni"] = "mtls.example.invalid",
                    ["ja3"] = "0123456789abcdef0123456789abcdef",
                    ["ja3Reputation"] = "rare c2",
                    ["clientCertificatePresent"] = "true",
                    ["destinationIp"] = "203.0.113.44",
                    ["destinationPort"] = "443"
                }
            }
        ];
    }

    private static IReadOnlyList<SandboxEvent> CreateCollectionVirusTotalR0NoiseEvents()
    {
        var noiseEvents = new List<SandboxEvent>();
        foreach (var evt in CreatePositiveEvents())
        {
            noiseEvents.Add(CloneNoiseEvent(evt, "r0collector", "KSword.Sandbox.R0Collector"));
            noiseEvents.Add(CloneNoiseEvent(evt, "virustotal", "virustotal"));
            noiseEvents.Add(CloneNoiseEvent(evt, "collection-health", "collection-health"));
        }

        return noiseEvents;
    }

    private static SandboxEvent CloneNoiseEvent(SandboxEvent evt, string source, string component)
    {
        var data = new Dictionary<string, string>(evt.Data, StringComparer.OrdinalIgnoreCase)
        {
            ["source"] = source,
            ["producer"] = source,
            ["component"] = component,
            ["status"] = "not_configured collection health",
            ["vtStatus"] = "not_configured",
            ["healthStatus"] = "collection-health",
            ["noise"] = "true",
            ["selfNoise"] = "true",
            ["collectorSelfNoise"] = "true",
            ["collectorNoise"] = "true",
            ["message"] = "collection health R0Collector VirusTotal not configured"
        };

        return evt with
        {
            Source = source,
            ProcessName = string.Equals(source, "r0collector", StringComparison.OrdinalIgnoreCase)
                ? "KSword.Sandbox.R0Collector.exe"
                : evt.ProcessName,
            Data = data
        };
    }

    private static void AssertRulesJsonParsesWithUniqueIds(string behaviorRulesPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(behaviorRulesPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("rules", out var rules), "behavior-rules.json should include a rules array.");
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules.EnumerateArray())
        {
            SmokeAssert.True(rule.TryGetProperty("id", out var idElement), "Every behavior rule should include an id.");
            var id = idElement.GetString();
            SmokeAssert.True(!string.IsNullOrWhiteSpace(id), "Behavior rule IDs should not be empty.");
            SmokeAssert.True(ids.Add(id!), $"Behavior rule id '{id}' should be unique.");
        }
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
