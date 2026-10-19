using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Guest;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the host ETW recovery contract.
///
/// A sample that kills the Guest Agent (Petya overwrites the boot path, wipers
/// take the session down) leaves a raw .etl on the host and no events.json.
/// Before this path existed the report showed zero dynamic evidence even
/// though the trace still held every process/image/thread edge the sample
/// produced. The host must decode that trace as a last resort, must not decode
/// it when the Agent already succeeded, and must turn every failure into an
/// explicit collection diagnostic instead of silence.
/// </summary>
internal sealed class HostEtlDecodeFallbackContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "guest.host-etl-decode-fallback.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // 1. The recovery path must be wired into the one import entry point
        //    that both the live job and offline PostProcess already use.
        var importer = Read(context, Path.Combine("src", "KSword.Sandbox.Core", "Guest", "EtwTraceXmlEventImporter.cs"));
        SmokeAssert.True(
            importer.Contains("HostEtlTraceDecoder.ImportFallback(existingEvents, guestOutputRoot)", StringComparison.Ordinal),
            "Host ETW decode must run from ImportFallbackAndCoverage so live import and PostProcess share one recovery path.");

        // 2. A healthy Agent must never get a second full-machine trace bolted
        //    onto its own decoded rows.
        var guestRoot = Path.Combine(context.RuntimeRoot, "host-etl-decode", "guest");
        var etw = Path.Combine(guestRoot, "etw-traces");
        Directory.CreateDirectory(etw);
        // Not a real ETL: the gate must be what stops the decode, not a decode
        // failure, so this file must never be handed to tracerpt.
        File.WriteAllBytes(Path.Combine(etw, "KSEtw_already-decoded.etl"), [1, 2, 3, 4]);

        var decodedRow = new SandboxEvent
        {
            EventType = "process.start",
            Source = "etwLive",
            Data =
            {
                ["captureSource"] = "etw-live-tracerpt",
                ["rawDecoded"] = "true"
            }
        };
        var gated = HostEtlTraceDecoder.ImportFallback([decodedRow], guestRoot);
        SmokeAssert.True(gated.Count == 0,
            "Host ETW decode must not run once the Agent already produced decoded semantic rows.");

        // 3. With no decoded rows the recovery path engages. A truncated ETL
        //    cannot be decoded, and that must surface as an explicit, stable
        //    diagnostic rather than an empty result.
        var recovered = HostEtlTraceDecoder.ImportFallback([], guestRoot);
        SmokeAssert.True(recovered.Count >= 1,
            "Host ETW decode must return at least one diagnostic when a trace cannot be recovered.");
        var diagnostic = recovered[0];
        SmokeAssert.True(diagnostic.EventType == "etw.host_decode.failed",
            "An unrecoverable trace must produce an etw.host_decode.failed row.");
        SmokeAssert.True(diagnostic.Data.TryGetValue("captureSource", out var captureSource) && captureSource == "etw-host-tracerpt",
            "Host-decoded rows must carry host provenance so they are never confused with guest-decoded evidence.");
        SmokeAssert.True(diagnostic.Data.TryGetValue("failureType", out var failureType) && !string.IsNullOrWhiteSpace(failureType),
            "Every host decode failure needs a stable failure type.");
        SmokeAssert.True(diagnostic.Data.TryGetValue("traceArtifactPath", out var tracePath) &&
            tracePath!.EndsWith("KSEtw_already-decoded.etl", StringComparison.OrdinalIgnoreCase),
            "The diagnostic must name the trace it could not recover.");
        SmokeAssert.True(diagnostic.Data.TryGetValue("behaviorCounted", out var counted) && counted == "false" &&
            diagnostic.Data.TryGetValue("nonbehavior", out var nonbehavior) && nonbehavior == "true",
            "A decode diagnostic must never be counted as sample behavior.");
        SmokeAssert.True(diagnostic.Data.ContainsKey("zhMessage") && diagnostic.Data.ContainsKey("zhHint"),
            "A host decode diagnostic needs Chinese remediation text like every other collection gap.");

        // 4. Recovery output must land outside etw-traces, otherwise the next
        //    import would treat host-generated XML as captured guest evidence.
        SmokeAssert.True(HostEtlTraceDecoder.DecodeDirectoryName == "host-etl-decode",
            "The host decode scratch folder must not sit inside the etw-traces evidence folder.");

        // 5. The XML parser must be reusable one file at a time, which is what
        //    lets the host decoder reuse the guest decoder's exact row mapping.
        var xmlPath = Path.Combine(etw, "hostdecoded.xml");
        File.WriteAllText(xmlPath, """
            <Events><Event><System><Provider Name="Microsoft-Windows-Kernel-Process"/><EventID>1</EventID><TimeCreated SystemTime="2026-01-01T00:00:00Z"/><Execution ProcessID="4242" ThreadID="11"/></System><RenderingInfo><Task>Process</Task><Opcode>Start</Opcode><EventName>ProcessStart</EventName></RenderingInfo><EventData><Data Name="ProcessId">4242</Data><Data Name="ParentProcessId">4</Data><Data Name="ImageFileName">sample.exe</Data></EventData></Event></Events>
            """);
        var parsed = EtwTraceXmlEventImporter.ImportXmlFile(xmlPath);
        SmokeAssert.True(parsed.Count == 1 && parsed[0].EventType == "process.start" && parsed[0].ProcessId == 4242,
            "ImportXmlFile must expose the same row mapping the guest decoder uses.");
        SmokeAssert.True(EtwTraceXmlEventImporter.ImportXmlFile(Path.Combine(etw, "does-not-exist.xml")).Count == 0,
            "A missing decoded file must return no rows instead of throwing.");

        // 6. The host import ceiling must be published so an oversized dump is
        //    dropped before XDocument loads it.
        SmokeAssert.True(EtwTraceXmlEventImporter.XmlImportLimitBytes > 0,
            "The XML import ceiling must be readable by the host decoder.");

        // 7. Collection health must still count the gap: an unrecovered trace
        //    is a collection failure, not a clean capture.
        var health = KSword.Sandbox.Core.Reporting.CollectionHealthSummaryBuilder.Build(recovered);
        SmokeAssert.True(health.TotalRows > 0 && health.FailureRows > 0,
            "A host decode failure must enter CollectionHealth as a failure so the report cannot imply a clean run.");

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "A raw ETW trace left by a killed Guest Agent is decoded on the host as a last resort, and every failure stays an explicit collection gap."
        });
    }

    private static string Read(SmokeTestContext context, string path)
    {
        var fullPath = Path.Combine(context.RepositoryRoot, path);
        SmokeAssert.True(File.Exists(fullPath), $"Required source file was not found: {path}");
        return File.ReadAllText(fullPath);
    }
}