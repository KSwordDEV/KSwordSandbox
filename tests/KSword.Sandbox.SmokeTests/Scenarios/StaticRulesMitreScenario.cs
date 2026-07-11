using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that static-analysis behavior rules load and that key MITRE
/// mappings are present. Inputs are repository paths from SmokeTestContext;
/// processing loads JSON rules and MITRE seed data plus classifies a synthetic
/// static-analysis event; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class StaticRulesMitreScenario : ISmokeTestScenario
{
    private static readonly string[] RequiredStaticRuleIds =
    [
        "static-pe-known-packer",
        "static-pe-high-entropy-sections",
        "static-embedded-url",
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
        "static-pe-tls-callbacks",
        "static-pe-exports-present",
        "static-export-registration-entrypoint",
        "static-export-service-entrypoint",
        "static-pe-resources-present",
        "static-resource-payload-candidate",
        "static-resource-embedded-pe",
        "static-resource-high-entropy",
        "static-section-writable-executable",
        "static-ip-address",
        "static-windows-path-string",
        "static-registry-path-string",
        "static-persistence-string",
        "static-script-command-string",
        "static-encoded-command-string",
        "static-lolbin-string",
        "static-anti-sandbox-string"
    ];

    private static readonly string[] RequiredBehaviorRuleIds =
    [
        "service-registry-persistence",
        "scheduled-task-persistence",
        "startup-folder-persistence",
        "temp-executable-drop",
        "script-file-executed",
        "http-network-activity",
        "dns-query-observed",
        "remote-thread-injection-observed",
        "anti-analysis-debugger-check"
    ];

    private static readonly string[] RequiredMitreTechniqueIds =
    [
        "T1027",
        "T1027.002",
        "T1027.009",
        "T1053.005",
        "T1055",
        "T1059",
        "T1059.001",
        "T1070.004",
        "T1071.001",
        "T1071.004",
        "T1105",
        "T1106",
        "T1112",
        "T1134.001",
        "T1218",
        "T1218.002",
        "T1218.003",
        "T1218.010",
        "T1497",
        "T1497.003",
        "T1548.002",
        "T1543.003",
        "T1546",
        "T1547.001",
        "T1553.004",
        "T1574.009",
        "T1574.011",
        "T1620",
        "T1622"
    ];

    private static readonly string[] PendingMitreTechniqueIds =
    [
        "T1003.001",
        "T1003.002",
        "T1021.002",
        "T1021.006",
        "T1497.001",
        "T1555",
        "T1555.003"
    ];

    public string ScenarioId => "static.rules-mitre-depth";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var behaviorRulesPath = Path.Combine(context.RulesDirectory, "behavior-rules.json");
        var mitreMapPath = Path.Combine(context.RulesDirectory, "mitre-windows-map.json");
        var staticNotesPath = Path.Combine(context.RulesDirectory, "static-notes.yar");
        SmokeAssert.True(File.Exists(behaviorRulesPath), "behavior-rules.json is missing.");
        SmokeAssert.True(File.Exists(mitreMapPath), "mitre-windows-map.json is missing.");
        SmokeAssert.True(File.Exists(staticNotesPath), "static-notes.yar is missing.");

        var rules = RuleEngine.LoadRuleSet(behaviorRulesPath);
        SmokeAssert.True(rules.Rules.Count > 0, "Behavior rules should load.");
        var ruleIds = rules.Rules.Select(rule => rule.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredStaticRuleIds)
        {
            SmokeAssert.True(ruleIds.Contains(ruleId), $"Static rule '{ruleId}' is missing.");
        }

        foreach (var ruleId in RequiredBehaviorRuleIds)
        {
            SmokeAssert.True(ruleIds.Contains(ruleId), $"Behavior rule '{ruleId}' is missing.");
        }

        AssertSyntheticStaticRuleMatches(rules);
        AssertSyntheticBehaviorRuleMatches(rules);
        AssertSyntheticStaticAnalyzerTags(context);
        AssertMitreMappings(mitreMapPath, rules);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Static rules load, synthetic static tags classify, and key MITRE mappings are present."
        });
    }

    /// <summary>
    /// Classifies one synthetic static-analysis event with the new tags.
    /// Inputs are loaded rules, processing runs RuleEngine over representative
    /// static tags, and the method returns no value when expected rules match.
    /// </summary>
    private static void AssertSyntheticStaticRuleMatches(BehaviorRuleSet rules)
    {
        var engine = new RuleEngine(rules);
        var findings = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "static.analysis.completed",
                Source = "host",
                Path = "synthetic-static-depth.exe",
                Data =
                {
                    ["tags"] = string.Join(
                        ",",
                        [
                            "packer_upx",
                            "high_entropy_section",
                            "url",
                            "imports_present",
                            "import_suspicious_api",
                            "import_process_injection_api",
                            "import_network_api",
                            "import_persistence_api",
                            "import_anti_analysis_api",
                            "import_dynamic_code_api",
                            "import_script_execution_api",
                            "import_file_drop_api",
                            "import_resource_api",
                            "import_registry_persistence_api",
                            "import_service_persistence_api",
                            "tls_callbacks",
                            "exports_present",
                            "export_registration_entrypoint",
                            "export_service_entrypoint",
                            "resources_present",
                            "resource_payload_candidate",
                            "resource_embedded_pe",
                            "resource_high_entropy_data",
                            "writable_executable_section",
                            "ip_address",
                            "windows_path_string",
                            "registry_path_string",
                            "persistence_string",
                            "script_execution_string",
                            "encoded_command_string",
                            "lolbin_string",
                            "sandbox_evasion_string"
                        ])
                }
            }
        ]);

        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredStaticRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic static tags should match '{ruleId}'.");
        }
    }

    /// <summary>
    /// Classifies representative dynamic behavior events for new rules.
    /// Inputs are loaded rules, processing runs RuleEngine over synthetic
    /// persistence, injection, network, dropper, script, and anti-analysis
    /// events, and the method returns no value when expected rules match.
    /// </summary>
    private static void AssertSyntheticBehaviorRuleMatches(BehaviorRuleSet rules)
    {
        var engine = new RuleEngine(rules);
        var findings = engine.Classify(
        [
            new SandboxEvent
            {
                EventType = "registry.set",
                Source = "driver",
                Path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\KswordSmoke"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "schtasks /create /tn KswordSmoke /tr C:\\Users\\Public\\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "file.created",
                Source = "guest",
                Path = "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.lnk"
            },
            new SandboxEvent
            {
                EventType = "file.modified",
                Source = "guest",
                Path = "C:\\Users\\Public\\AppData\\Local\\Temp\\payload.exe"
            },
            new SandboxEvent
            {
                EventType = "process.start",
                Source = "guest",
                CommandLine = "powershell.exe -File C:\\Users\\Public\\payload.ps1"
            },
            new SandboxEvent
            {
                EventType = "http.request",
                Source = "guest"
            },
            new SandboxEvent
            {
                EventType = "dns.query",
                Source = "guest"
            },
            new SandboxEvent
            {
                EventType = "process.remote_thread",
                Source = "driver",
                Data =
                {
                    ["operation"] = "CreateRemoteThread"
                }
            },
            new SandboxEvent
            {
                EventType = "antiAnalysis.debuggerCheck",
                Source = "guest"
            }
        ]);

        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var ruleId in RequiredBehaviorRuleIds)
        {
            SmokeAssert.True(findingIds.Contains(ruleId), $"Synthetic behavior events should match '{ruleId}'.");
        }
    }

    /// <summary>
    /// Exercises StaticAnalyzer string and resource extraction with local
    /// synthetic files. Inputs are smoke context paths, processing writes
    /// benign byte fixtures, and the method asserts the new static tags.
    /// </summary>
    private static void AssertSyntheticStaticAnalyzerTags(SmokeTestContext context)
    {
        var analyzer = new KSword.Sandbox.Core.StaticAnalysis.StaticAnalyzer();
        var staticRoot = Path.Combine(context.RuntimeRoot, "static-rules-mitre");
        Directory.CreateDirectory(staticRoot);

        var stringSample = Path.Combine(staticRoot, "strings.bin");
        File.WriteAllText(
            stringSample,
            string.Join(
                '\n',
                [
                    "https://example.invalid/payload.bin",
                    "connect 8.8.8.8 then run powershell -EncodedCommand SQBFAFgA",
                    "C:\\Users\\Public\\AppData\\Local\\Temp\\payload.exe",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KswordSmoke",
                    "rundll32.exe javascript:.. IsDebuggerPresent VirtualBox"
                ]));

        var stringResult = analyzer.Analyze(stringSample);
        AssertTags(
            stringResult.Tags,
            "url",
            "ip_address",
            "public_ip_address",
            "windows_path_string",
            "registry_path_string",
            "run_key_path_string",
            "persistence_string",
            "script_execution_string",
            "encoded_command_string",
            "lolbin_string",
            "anti_analysis_string",
            "sandbox_evasion_string");
        SmokeAssert.True(stringResult.Urls.Any(url => url.StartsWith("https://example.invalid/", StringComparison.OrdinalIgnoreCase)), "StaticAnalyzer should extract embedded URLs.");

        var resourceSample = Path.Combine(staticRoot, "resource-pe.exe");
        WriteResourcePe(resourceSample);
        var resourceResult = analyzer.Analyze(resourceSample);
        AssertTags(
            resourceResult.Tags,
            "resources_present",
            "resource_type_rcdata",
            "resource_payload_candidate",
            "resource_embedded_pe",
            "resource_high_entropy_data");
    }

    /// <summary>
    /// Asserts that all expected tags are present.
    /// Inputs are actual tags and expected tag names, processing uses
    /// case-insensitive membership, and the method returns no value on success.
    /// </summary>
    private static void AssertTags(IEnumerable<string> tags, params string[] expectedTags)
    {
        var tagSet = tags.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var tag in expectedTags)
        {
            SmokeAssert.True(tagSet.Contains(tag), $"StaticAnalyzer should emit tag '{tag}'.");
        }
    }

    /// <summary>
    /// Writes a minimal PE32+ file with one RCDATA resource containing
    /// high-entropy bytes and an MZ marker.
    /// </summary>
    private static void WriteResourcePe(string path)
    {
        var buffer = new byte[2048];
        WriteUInt16(buffer, 0x00, 0x5a4d);
        WriteUInt32(buffer, 0x3c, 0x80);
        WriteUInt32(buffer, 0x80, 0x00004550);
        WriteUInt16(buffer, 0x84, 0x8664);
        WriteUInt16(buffer, 0x86, 1);
        WriteUInt16(buffer, 0x94, 0xf0);

        var optionalHeaderOffset = 0x98;
        WriteUInt16(buffer, optionalHeaderOffset, 0x20b);
        WriteUInt32(buffer, optionalHeaderOffset + 16, 0x1000);
        WriteUInt64(buffer, optionalHeaderOffset + 24, 0x140000000);
        WriteUInt16(buffer, optionalHeaderOffset + 68, 2);
        WriteUInt32(buffer, optionalHeaderOffset + 108, 16);
        var dataDirectoryOffset = optionalHeaderOffset + 112;
        WriteUInt32(buffer, dataDirectoryOffset + 2 * 8, 0x1000);
        WriteUInt32(buffer, dataDirectoryOffset + 2 * 8 + 4, 0x300);

        var sectionOffset = optionalHeaderOffset + 0xf0;
        var name = ".rsrc"u8;
        name.CopyTo(buffer.AsSpan(sectionOffset, name.Length));
        WriteUInt32(buffer, sectionOffset + 8, 0x1000);
        WriteUInt32(buffer, sectionOffset + 12, 0x1000);
        WriteUInt32(buffer, sectionOffset + 16, 0x400);
        WriteUInt32(buffer, sectionOffset + 20, 0x200);
        WriteUInt32(buffer, sectionOffset + 36, 0x40000040);

        var root = 0x200;
        WriteUInt16(buffer, root + 14, 1);
        WriteUInt32(buffer, root + 16, 10);
        WriteUInt32(buffer, root + 20, 0x80000020);

        var nameDirectory = root + 0x20;
        WriteUInt16(buffer, nameDirectory + 14, 1);
        WriteUInt32(buffer, nameDirectory + 16, 1);
        WriteUInt32(buffer, nameDirectory + 20, 0x80000040);

        var languageDirectory = root + 0x40;
        WriteUInt16(buffer, languageDirectory + 14, 1);
        WriteUInt32(buffer, languageDirectory + 16, 1033);
        WriteUInt32(buffer, languageDirectory + 20, 0x60);

        var dataEntry = root + 0x60;
        WriteUInt32(buffer, dataEntry, 0x1080);
        WriteUInt32(buffer, dataEntry + 4, 0x200);

        var dataOffset = root + 0x80;
        buffer[dataOffset] = 0x4d;
        buffer[dataOffset + 1] = 0x5a;
        var state = 0x31415926u;
        for (var index = dataOffset + 2; index < dataOffset + 0x200; index++)
        {
            state = unchecked(state * 1664525 + 1013904223);
            buffer[index] = (byte)(state >> 24);
        }

        File.WriteAllBytes(path, buffer);
    }

    /// <summary>
    /// Writes a little-endian UInt16 into a byte buffer.
    /// </summary>
    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        BitConverter.GetBytes(value).CopyTo(buffer, offset);
    }

    /// <summary>
    /// Writes a little-endian UInt32 into a byte buffer.
    /// </summary>
    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        BitConverter.GetBytes(value).CopyTo(buffer, offset);
    }

    /// <summary>
    /// Writes a little-endian UInt64 into a byte buffer.
    /// </summary>
    private static void WriteUInt64(byte[] buffer, int offset, ulong value)
    {
        BitConverter.GetBytes(value).CopyTo(buffer, offset);
    }

    /// <summary>
    /// Verifies that the MITRE seed map contains key and rule-referenced IDs.
    /// Inputs are the MITRE map path and loaded rules, processing parses JSON
    /// and compares IDs, and the method returns no value on success.
    /// </summary>
    private static void AssertMitreMappings(string mitreMapPath, BehaviorRuleSet rules)
    {
        var techniqueIds = ReadMitreTechniqueIds(mitreMapPath);
        foreach (var techniqueId in RequiredMitreTechniqueIds)
        {
            SmokeAssert.True(techniqueIds.Contains(techniqueId), $"MITRE technique '{techniqueId}' is missing from mitre-windows-map.json.");
        }

        var mappedRuleIds = rules.Rules
            .Select(rule => rule.MitreTechniqueId)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        var pendingTechniqueIds = PendingMitreTechniqueIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var techniqueId in mappedRuleIds)
        {
            SmokeAssert.True(
                techniqueIds.Contains(techniqueId) || pendingTechniqueIds.Contains(techniqueId),
                $"Rule-referenced MITRE technique '{techniqueId}' is missing from mitre-windows-map.json and is not listed as pending seed-map coverage.");
        }
    }

    /// <summary>
    /// Reads MITRE technique IDs from the local seed map.
    /// The input is a JSON file path, processing reads `techniques[].id`, and
    /// the method returns a case-insensitive set.
    /// </summary>
    private static HashSet<string> ReadMitreTechniqueIds(string mitreMapPath)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(mitreMapPath));
        SmokeAssert.True(document.RootElement.TryGetProperty("techniques", out var techniques), "MITRE map should contain a techniques array.");
        SmokeAssert.True(techniques.ValueKind == JsonValueKind.Array, "MITRE techniques should be an array.");

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
