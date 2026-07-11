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
        var samplePath = Path.Combine(staticRoot, "overlay-signed.exe");
        WriteOverlaySignedPe(samplePath);

        var result = new StaticAnalyzer().Analyze(samplePath);
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
            "url",
            "ip_address",
            "public_ip_address");
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

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Static analyzer emits overlay, signature-table, URL, and IP evidence."
        });
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
        WriteUInt32(buffer, dataDirectoryOffset + 1 * 8, 0x1100);
        WriteUInt32(buffer, dataDirectoryOffset + 1 * 8 + 4, 0x3c);
        WriteUInt32(buffer, dataDirectoryOffset + 4 * 8, 0x500);
        WriteUInt32(buffer, dataDirectoryOffset + 4 * 8 + 4, 0x100);

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

        WriteSyntheticImportTable(buffer);

        var overlayText = "https://overlay.example.invalid/payload 9.9.9.9";
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
