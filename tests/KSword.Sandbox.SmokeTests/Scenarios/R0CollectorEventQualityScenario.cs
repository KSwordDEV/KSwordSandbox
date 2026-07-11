using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Jobs;
using KSword.Sandbox.Core.Rules;
using KSword.Sandbox.Core.Telemetry;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies synthetic R0/collector event-quality contracts without loading a
/// real driver. Inputs are repository source/docs and generated JSONL rows;
/// processing checks ABI/version fields, producer masks, backpressure counters,
/// robust JSONL parsing, and stress/mock corpus shape; the scenario returns
/// pass/fail metadata.
/// </summary>
internal sealed class R0CollectorEventQualityScenario : ISmokeTestScenario
{
    private const string AbiVersion = "65536";
    private const string AbiVersionHex = "0x00010000";
    private const string CurrentProducerMaskHex = "0x0000003F";
    private const int ExpectedEventRingCapacity = 1024;
    private const int ExpectedBackpressureQueueDepth = 768;
    private const int ExpectedStressDriverRows = 32;
    private const int StressJsonlSequenceStart = 1200;
    private const int StressJsonlSequenceEnd = StressJsonlSequenceStart + ExpectedStressDriverRows - 1;
    private const int StressJsonlSequenceGapCount = 0;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private static readonly JsonSerializerOptions JsonLineOptions = new(JsonSerializerDefaults.Web);

    public string ScenarioId => "r0.collector.event-quality.synthetic";

    /// <inheritdoc />
    public async Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        AssertStaticAbiNoiseAndBackpressureContract(context);
        await AssertSyntheticJsonLinesQualityAsync(context, cancellationToken);
        await AssertExecutableStressNoiseQualityAsync(context, cancellationToken);

        return new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0 collector ABI, producer-mask, loss/backpressure, robust JSONL, and mock/stress synthetic contracts are covered."
        };
    }

    /// <summary>
    /// Checks source/docs markers for ABI structure versions, masks, queue loss,
    /// and stress/noise controls. Inputs are repository paths; processing reads
    /// allowed R0/collector and driver docs files; return value is none.
    /// </summary>
    private static void AssertStaticAbiNoiseAndBackpressureContract(SmokeTestContext context)
    {
        var header = ReadRepositoryText(
            context,
            "driver",
            "KSword.Sandbox.Driver",
            "include",
            "KSwordSandboxDriverIoctl.h");
        var eventParser = ReadRepositoryText(
            context,
            "guest",
            "KSword.Sandbox.R0Collector",
            "src",
            "EventParser.cpp");
        var ioctlClient = ReadRepositoryText(
            context,
            "guest",
            "KSword.Sandbox.R0Collector",
            "src",
            "IoctlClient.cpp");
        var options = ReadRepositoryText(
            context,
            "guest",
            "KSword.Sandbox.R0Collector",
            "src",
            "Options.cpp");
        var runtimeLoop = ReadRepositoryText(
            context,
            "guest",
            "KSword.Sandbox.R0Collector",
            "src",
            "RuntimeLoop.cpp");
        var syntheticMode = ReadRepositoryText(
            context,
            "guest",
            "KSword.Sandbox.R0Collector",
            "src",
            "SyntheticMode.cpp");
        var collectorDoc = ReadRepositoryText(context, "docs", "r0-collector.md");
        var schemaDoc = ReadRepositoryText(context, "docs", "r0-jsonl-schema.md");
        var coreDoc = ReadRepositoryText(context, "docs", "r0-driver-core.md");
        var driverReadme = ReadRepositoryText(context, "driver", "KSword.Sandbox.Driver", "README.md");
        var readinessScript = ReadRepositoryText(context, "scripts", "Test-R0Readiness.ps1");

        RequireContains(header, "KSWORD_SANDBOX_EVENT_HEADER_VERSION", "ABI header must publish event header version.");
        RequireContains(header, "KSWORD_SANDBOX_EVENT_SCHEMA_VERSION", "ABI header must publish event schema version.");
        RequireContains(header, "KSWORD_SANDBOX_CAPABILITY_FLAG_EVENT_SCHEMA_NAMES", "Capabilities must advertise schema-name support.");
        RequireContains(header, "KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE", "GET_HEALTH ABI must publish the producer-mask availability flag.");
        RequireStructFields(
            header,
            "KSWORD_SANDBOX_HEALTH_REPLY",
            "ProducerEnableMask",
            "SupportedProducerMask",
            "ActiveProducerMask",
            "FailedProducerMask");
        RequireStructFields(
            header,
            "KSWORD_SANDBOX_EVENT_HEADER",
            "Version",
            "Size",
            "Sequence",
            "PayloadSize");
        RequireStructFields(
            header,
            "KSWORD_SANDBOX_CAPABILITIES_REPLY",
            "Version",
            "Size",
            "AbiVersionMajor",
            "AbiVersionMinor",
            "CapabilityFlags",
            "SupportedProducerMask",
            "DefaultProducerMask",
            "EventHeaderVersion",
            "EventRingCapacity");
        RequireStructFields(
            header,
            "KSWORD_SANDBOX_STATUS_REPLY",
            "Version",
            "Size",
            "QueueCapacity",
            "QueueDepth",
            "QueueHighWatermark",
            "ProducerEnableMask",
            "SupportedProducerMask",
            "ActiveProducerMask",
            "FailedProducerMask",
            "TotalEventsEnqueued",
            "TotalEventsDropped",
            "TotalEventsRead",
            "TotalEventsSuppressed",
            "TotalEventsBackpressured",
            "ProducerDroppedMask",
            "ProducerSuppressedMask",
            "ProducerBackpressureMask",
            "NextSequence");
        RequireStructFields(
            header,
            "KSWORD_SANDBOX_READ_EVENTS_REPLY",
            "Version",
            "Size",
            "EventsWritten",
            "BytesWritten",
            "EventsDropped",
            "NextSequence");
        foreach (var payloadStruct in new[]
        {
            "KSWORD_SANDBOX_DRIVER_LOAD_PAYLOAD",
            "KSWORD_SANDBOX_PROCESS_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_IMAGE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_REGISTRY_EVENT_PAYLOAD",
            "KSWORD_SANDBOX_NETWORK_EVENT_PAYLOAD"
        })
        {
            RequireStructFields(header, payloadStruct, "Version", "Size");
        }

        foreach (var producer in new[]
        {
            "KSWORD_SANDBOX_PRODUCER_FLAG_DRIVER",
            "KSWORD_SANDBOX_PRODUCER_FLAG_PROCESS",
            "KSWORD_SANDBOX_PRODUCER_FLAG_IMAGE",
            "KSWORD_SANDBOX_PRODUCER_FLAG_FILE",
            "KSWORD_SANDBOX_PRODUCER_FLAG_REGISTRY",
            "KSWORD_SANDBOX_PRODUCER_FLAG_NETWORK"
        })
        {
            RequireContains(header, producer, $"ABI header must publish {producer}.");
        }

        RequireContains(ioctlClient, "header.Version != KSWORD_SANDBOX_EVENT_HEADER_VERSION", "Collector must reject incompatible event header versions.");
        RequireContains(ioctlClient, "header.Size < sizeof(header)", "Collector must validate event record size before payload parsing.");
        RequireContains(ioctlClient, "PayloadSize exceeds record Size", "Collector must reject payload sizes that overrun records.");
        RequireContains(ioctlClient, "reply.EventHeaderVersion != KSWORD_SANDBOX_EVENT_HEADER_VERSION", "Collector must compare negotiated event header versions.");
        RequireContains(ioctlClient, "reply.EventMaxPayloadSize > KSWORD_SANDBOX_EVENT_MAX_PAYLOAD_SIZE", "Collector must reject oversized negotiated payload limits.");
        RequireContains(ioctlClient, "request->Flags = 0", "Producer-mask request reserved flags must remain zero.");
        RequireContains(ioctlClient, "request.Flags = 0", "READ_EVENTS request reserved flags must remain zero.");
        RequireContains(ioctlClient, "reply.BytesWritten > availableEventBytes", "Collector must protect against malformed READ_EVENTS byte counts.");
        RequireContains(ioctlClient, "kHealthReplyLegacyMinimumBytes", "Collector must tolerate old GET_HEALTH replies that contain the stable legacy prefix.");
        RequireContains(ioctlClient, "KSWORD_SANDBOX_HEALTH_FLAG_PRODUCER_MASKS_AVAILABLE", "Collector must gate GET_HEALTH producer masks on the advertised availability flag.");
        RequireContains(ioctlClient, "advertised producer masks without returning", "Collector must reject flagged GET_HEALTH replies that omit producer mask bytes.");

        RequireContains(eventParser, "abiVersionMajor", "Capabilities JSONL must include ABI major version.");
        RequireContains(eventParser, "abiVersionMinor", "Capabilities JSONL must include ABI minor version.");
        RequireContains(eventParser, "eventHeaderVersion", "Capabilities JSONL must include event header version.");
        RequireContains(eventParser, "eventSchemaName", "Driver JSONL rows must include event schema name.");
        RequireContains(eventParser, "eventSchemaVersion", "Driver JSONL rows must include event schema version.");
        RequireContains(eventParser, "ProducerMasksAvailable", "Health JSONL flag names must print producer-mask availability.");
        RequireContains(eventParser, "producerMasksAvailable", "Health JSONL must expose whether GET_HEALTH producer masks are valid.");
        RequireContains(eventParser, "producerMaskFieldsReturned", "Health JSONL must expose old/new GET_HEALTH byte compatibility.");
        RequireContains(eventParser, "producerEnableMaskHex", "Status/health JSONL must include producer enable mask.");
        RequireContains(eventParser, "supportedProducerMaskHex", "Status/capabilities/health JSONL must include supported producer mask.");
        RequireContains(eventParser, "activeProducerMaskHex", "Status JSONL must include active producer mask.");
        RequireContains(eventParser, "failedProducerMaskHex", "Status JSONL must include failed producer mask.");
        RequireContains(eventParser, "queueHighWatermark", "Status JSONL must include queue high watermark.");
        RequireContains(eventParser, "totalEventsDropped", "Status JSONL must include dropped/lost event counter.");
        RequireContains(eventParser, "totalEventsSuppressed", "Status JSONL must include producer-suppressed event counter.");
        RequireContains(eventParser, "eventsDropped", "Poll/read-events JSONL must include batch dropped counter.");
        RequireContains(eventParser, "sequence", "Driver rows must include sequence for loss-gap diagnostics.");
        RequireContains(eventParser, "sourceEndpoint", "Network parser must include source endpoint semantics.");
        RequireContains(eventParser, "destinationEndpoint", "Network parser must include destination endpoint semantics.");
        RequireContains(eventParser, "flowKey", "Network parser must include flow-key semantics.");

        RequireContains(options, "--max-events", "Collector CLI must expose a READ_EVENTS max-events stress knob.");
        RequireContains(options, "--max-read-batches", "Collector CLI must expose a bounded drain batch knob.");
        RequireContains(options, "--abi-self-check", "Collector CLI must expose a no-device ABI self-check knob.");
        RequireContains(runtimeLoop, "drainStoppedAtBatchLimit", "Runtime loop must expose batch-limit backpressure stop evidence.");
        RequireContains(runtimeLoop, "RunAbiSelfCheckMode", "Runtime loop must expose ABI self-check mode before live driver open.");
        RequireContains(syntheticMode, "typedPayloadStatus", "Synthetic rows must mark typed payload status.");
        RequireContains(syntheticMode, "mock", "Synthetic rows must mark mock mode.");
        RequireContains(syntheticMode, "eventSchemaVersion", "Synthetic rows must include event schema version.");
        RequireContains(syntheticMode, "producer", "Synthetic rows must include stable producer metadata.");
        RequireContains(syntheticMode, "schema", "Synthetic rows must include stable schema metadata.");
        RequireContains(syntheticMode, "lost", "Synthetic rows must include stable loss/no-lost metadata.");
        RequireContains(syntheticMode, "backpressure", "Synthetic rows must include stable backpressure metadata.");
        RequireContains(syntheticMode, "noise", "Synthetic rows must include stable noise metadata.");
        RequireContains(syntheticMode, "EmitSyntheticJsonlNoiseRows", "Synthetic JSONL noise should be injectable without requiring stress rows.");
        RequireContains(syntheticMode, "sourceEndpoint", "Synthetic network rows should preserve source endpoint semantics.");
        RequireContains(syntheticMode, "destinationEndpoint", "Synthetic network rows should preserve destination endpoint semantics.");
        RequireContains(syntheticMode, "flowKey", "Synthetic network rows should preserve flow-key semantics.");
        var abiSelfCheck = ReadRepositoryText(
            context,
            "guest",
            "KSword.Sandbox.R0Collector",
            "src",
            "AbiSelfCheck.cpp");
        RequireContains(abiSelfCheck, "r0collector.abiSelfCheck", "ABI self-check must emit a dedicated JSONL event.");
        RequireContains(abiSelfCheck, "capabilityFlagsCurrentHex", "ABI self-check must include capability flags.");
        RequireContains(abiSelfCheck, "producerMaskCurrentHex", "ABI self-check must include producer mask.");
        RequireContains(abiSelfCheck, "jsonlNoisePolicy", "ABI self-check must describe JSONL noise filtering.");
        RequireContains(abiSelfCheck, "kernelBackpressurePolicy", "ABI self-check must describe non-blocking ring backpressure.");
        RequireContains(abiSelfCheck, "queueLossEvidence", "ABI self-check must name loss evidence fields.");

        foreach (var doc in new[] { collectorDoc, schemaDoc, coreDoc, driverReadme })
        {
            RequireContains(doc, "Synthetic event-quality", "Docs must define the synthetic event-quality contract.");
            RequireContains(doc, "backpressure", "Docs must describe R0 backpressure behavior.");
            RequireContains(doc, "TotalEventsDropped", "Docs must describe dropped/lost event accounting.");
            RequireContains(doc, "QueueHighWatermark", "Docs must describe queue high-watermark evidence.");
            RequireContains(doc, "driver.parse_error", "Docs must describe JSONL parse-error preservation.");
            RequireContains(doc, "--max-read-batches", "Docs must describe bounded stress-drain input.");
        }

        foreach (var doc in new[] { collectorDoc, coreDoc })
        {
            RequireContains(doc, "StressJsonlExpectedDriverRows", "Operator gate docs must name expected stress JSONL row-count evidence.");
            RequireContains(doc, "StressJsonlSequenceStart", "Operator gate docs must name stress sequence-start evidence.");
            RequireContains(doc, "StressJsonlSequenceEnd", "Operator gate docs must name stress sequence-end evidence.");
            RequireContains(doc, "StressJsonlSequenceGapCount", "Operator gate docs must name stress sequence-gap evidence.");
            RequireContains(doc, "StressJsonlLossEvidence", "Operator gate docs must name loss evidence field set.");
            RequireContains(doc, "StressJsonlBackpressureEvidence", "Operator gate docs must name backpressure evidence field set.");
            RequireContains(doc, "ReadinessNoDevicePolicy", "Operator gate docs must name the no-device readiness policy.");
            RequireContains(doc, "ReadinessNonFatalPolicy", "Operator gate docs must name non-fatal readiness policy.");
        }

        RequireContains(readinessScript, "R0Collector event-quality static contract", "Readiness script should emit a static event-quality operator-gate row.");
        RequireContains(readinessScript, "StressJsonlExpectedDriverRows", "Readiness script should surface expected stress row count evidence.");
        RequireContains(readinessScript, "StressJsonlSequenceStart", "Readiness script should surface sequence-start evidence.");
        RequireContains(readinessScript, "StressJsonlSequenceEnd", "Readiness script should surface sequence-end evidence.");
        RequireContains(readinessScript, "StressJsonlSequenceGapCount", "Readiness script should surface sequence-gap evidence.");
        RequireContains(readinessScript, "StressJsonlLossEvidence", "Readiness script should surface stress loss evidence field names.");
        RequireContains(readinessScript, "StressJsonlBackpressureEvidence", "Readiness script should surface stress backpressure evidence field names.");
        RequireContains(readinessScript, "ReadinessNoDevicePolicy", "Readiness script should surface no-device policy text.");
        RequireContains(readinessScript, "ReadinessNonFatalPolicy", "Readiness script should surface non-fatal policy text.");
        RequireContains(readinessScript, "CallsCSignTool             = $false", "Readiness event-quality static row must not call CSignTool.");
        RequireContains(readinessScript, "OpensDevice                = $false", "Readiness event-quality static row must not open the driver device.");
        RequireContains(readinessScript, "LoadsDriver                = $false", "Readiness event-quality static row must not load the driver.");
    }

    /// <summary>
    /// Exercises host JSONL readers with a generated collector-like event
    /// stream. Inputs are the smoke context and cancellation token; processing
    /// writes only temporary runtime files; return value is a completed task.
    /// </summary>
    private static async Task AssertSyntheticJsonLinesQualityAsync(SmokeTestContext context, CancellationToken cancellationToken)
    {
        var runtimeRoot = Path.Combine(context.RuntimeRoot, "r0-collector-event-quality", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(runtimeRoot);
        var samplePath = Path.Combine(runtimeRoot, "r0-event-quality-sample.exe");
        await File.WriteAllTextAsync(samplePath, "synthetic R0 collector event-quality sample", cancellationToken);

        var service = new SandboxJobService(
            new SandboxConfig
            {
                Analysis = new AnalysisConfig
                {
                    DefaultDurationSeconds = 5,
                    MaxDurationSeconds = 60,
                    MaxSampleBytes = 1024 * 1024
                },
                Paths = new SandboxPaths
                {
                    RuntimeRoot = runtimeRoot,
                    RulesDirectory = Path.Combine(context.RepositoryRoot, "rules"),
                    GuestPayloadRoot = Path.Combine(runtimeRoot, "payload", "guest-tools")
                },
                Driver = new DriverConfig
                {
                    Enabled = true,
                    UseMockCollector = true
                }
            },
            new BehaviorRuleSet());

        var job = service.Plan(new SandboxSubmission
        {
            SamplePath = samplePath,
            DurationSeconds = 5,
            DryRun = true,
            UseMockCollector = true
        });

        var jobRoot = Path.Combine(runtimeRoot, "jobs", job.JobId.ToString("N"));
        var guestRoot = Path.Combine(jobRoot, "guest", job.JobId.ToString("N"));
        Directory.CreateDirectory(guestRoot);

        var guestEventsPath = Path.Combine(guestRoot, "events.json");
        await File.WriteAllTextAsync(
            guestEventsPath,
            JsonSerializer.Serialize(
                new[]
                {
                    new SandboxEvent
                    {
                        EventType = "process.start",
                        Source = "guest",
                        ProcessId = 4242,
                        Path = samplePath,
                        CommandLine = samplePath
                    }
                },
                JsonOptions),
            cancellationToken);

        var validDriverEvents = BuildSyntheticDriverJsonLinesCorpus();
        var driverEventsPath = Path.Combine(guestRoot, "driver-events.jsonl");
        var lines = validDriverEvents
            .Select(evt => JsonSerializer.Serialize(evt, JsonLineOptions))
            .ToList();
        lines.Insert(3, "   ");
        lines.Insert(9, "{\"eventType\":\"driver.file\",\"source\":\"driver\",\"data\":{\"sequence\":\"broken\"");
        lines.Add("{\"eventType\":\"driver.network\",\"source\":\"driver\",\"extraTopLevel\":\"ignored\",\"data\":{\"sequence\":\"9999\",\"eventSchemaName\":\"ksword.sandbox.r0.event\"}}");
        SmokeAssert.True(
            lines.Count == validDriverEvents.Count + 3,
            "Synthetic stress/noise JSONL should include the valid corpus, one blank line, one malformed line, and one extra-field row.");
        await File.WriteAllLinesAsync(driverEventsPath, lines, cancellationToken);

        var liveEvents = new FileLiveEventSource().Read(driverEventsPath).ToList();
        SmokeAssert.True(
            liveEvents.Count == validDriverEvents.Count + 1,
            "Live JSONL reader should keep valid rows with extra fields and skip blank/malformed noise.");
        AssertSyntheticEventQualityRows(liveEvents);
        AssertMonotonicStressSequences(liveEvents);

        var importedJob = service.ImportGuestEvents(job.JobId, guestEventsPath);
        var reportPath = importedJob.JsonReportPath ?? throw new InvalidOperationException("report.json path should be set after import.");
        var report = JsonSerializer.Deserialize<AnalysisReport>(await File.ReadAllTextAsync(reportPath, cancellationToken), JsonOptions)
            ?? throw new InvalidOperationException("report.json should deserialize.");

        var parseError = report.Events.FirstOrDefault(evt => string.Equals(evt.EventType, "driver.parse_error", StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(parseError is not null, "Malformed collector JSONL lines must remain visible as driver.parse_error evidence.");
        SmokeAssert.True(
            parseError!.Data.TryGetValue("line", out var malformedLine) &&
            malformedLine.Contains("broken", StringComparison.Ordinal),
            "Parse-error evidence should retain the malformed JSONL line.");
        AssertSyntheticEventQualityRows(report.Events);
        AssertMonotonicStressSequences(report.Events);

        var importedMarker = report.Events.FirstOrDefault(evt => string.Equals(evt.EventType, "guest.events.imported", StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(importedMarker is not null, "Report should include guest.events.imported marker.");
        SmokeAssert.True(
            importedMarker!.Data.TryGetValue("eventCount", out var countText) &&
            int.TryParse(countText, out var importedCount) &&
            importedCount == validDriverEvents.Count + 3,
            $"Import count should include guest event, valid JSONL rows, extra-field row, and parse-error row. Actual: {countText}");
    }

    /// <summary>
    /// Creates valid synthetic JSONL rows that model R0 collector ABI,
    /// producer-mask, stress, and backpressure evidence. There are no inputs;
    /// processing builds in-memory events; return value is the event list.
    /// </summary>
    private static List<SandboxEvent> BuildSyntheticDriverJsonLinesCorpus()
    {
        var events = new List<SandboxEvent>
        {
            new()
            {
                EventType = "r0collector.started",
                Source = "r0collector",
                Path = @"\\.\KSwordSandboxDriver",
                Data =
                {
                    ["mockMode"] = "true",
                    ["syntheticMode"] = "true",
                    ["enableMaskSpecified"] = "true",
                    ["enableMaskHex"] = CurrentProducerMaskHex,
                    ["readEventsMaxEvents"] = "16",
                    ["maxReadBatches"] = "4",
                    ["StressJsonlExpectedDriverRows"] = ExpectedStressDriverRows.ToString(),
                    ["StressJsonlSequenceStart"] = StressJsonlSequenceStart.ToString(),
                    ["StressJsonlSequenceEnd"] = StressJsonlSequenceEnd.ToString(),
                    ["StressJsonlSequenceGapCount"] = StressJsonlSequenceGapCount.ToString(),
                    ["StressJsonlLossEvidence"] = "TotalEventsDropped|totalEventsDropped|EventsDropped|eventsDropped|ProducerDroppedMask|producerDroppedMask|NextSequence|nextSequence|sequence",
                    ["StressJsonlBackpressureEvidence"] = "QueueCapacity|queueCapacity|QueueHighWatermark|queueHighWatermark|TotalEventsBackpressured|totalEventsBackpressured|ProducerBackpressureMask|producerBackpressureMask|drainStoppedAtBatchLimit|requestedMaxEvents|readEventsMaxEvents|maxReadBatches",
                    ["ReadinessNoDevicePolicy"] = "no-device",
                    ["ReadinessNonFatalPolicy"] = "warning"
                }
            },
            new()
            {
                EventType = "r0collector.driverCapabilities",
                Source = "r0collector",
                Path = @"\\.\KSwordSandboxDriver",
                Data =
                {
                    ["version"] = AbiVersion,
                    ["versionHex"] = AbiVersionHex,
                    ["size"] = "104",
                    ["abiVersionMajor"] = "1",
                    ["abiVersionMinor"] = "0",
                    ["capabilityFlagsHex"] = "0x00000000000003FF",
                    ["supportedProducerMaskHex"] = CurrentProducerMaskHex,
                    ["defaultProducerMaskHex"] = CurrentProducerMaskHex,
                    ["eventSchemaName"] = "ksword.sandbox.r0.event",
                    ["eventSchemaVersion"] = AbiVersion,
                    ["eventSchemaVersionHex"] = AbiVersionHex,
                    ["eventHeaderVersion"] = AbiVersion,
                    ["eventMaxPayloadSize"] = "128",
                    ["eventRingCapacity"] = ExpectedEventRingCapacity.ToString(),
                    ["readEventsReplyHeaderSize"] = "40"
                }
            },
            new()
            {
                EventType = "r0collector.driverProducerMask",
                Source = "r0collector",
                Path = @"\\.\KSwordSandboxDriver",
                Data =
                {
                    ["requestedEnableMaskHex"] = "0x0000001B",
                    ["previousEnableMaskHex"] = CurrentProducerMaskHex,
                    ["effectiveEnableMaskHex"] = "0x0000001B",
                    ["supportedProducerMaskHex"] = CurrentProducerMaskHex,
                    ["requestedEnableMaskNames"] = "driver|process|file|registry",
                    ["effectiveEnableMaskNames"] = "driver|process|file|registry"
                }
            },
            BuildStatusRow("beforeDrain", queueDepth: ExpectedBackpressureQueueDepth, highWatermark: ExpectedEventRingCapacity, dropped: 7, suppressed: 3, nextSequence: 1200),
            new()
            {
                EventType = "r0collector.driverReadEvents",
                Source = "r0collector",
                Path = @"\\.\KSwordSandboxDriver",
                Data =
                {
                    ["version"] = AbiVersion,
                    ["versionHex"] = AbiVersionHex,
                    ["size"] = "40",
                    ["requestedMaxEvents"] = "16",
                    ["eventsWritten"] = "16",
                    ["eventsEmitted"] = "16",
                    ["bytesWritten"] = "1536",
                    ["eventsDropped"] = "9",
                    ["nextSequence"] = "1216",
                    ["backpressureObserved"] = "true"
                }
            },
            new()
            {
                EventType = "r0collector.mockDriverEvent",
                Source = "r0collector",
                ProcessId = 4242,
                Path = @"C:\Windows\System32\notepad.exe",
                Data =
                {
                    ["mock"] = "true",
                    ["stress"] = "true",
                    ["ioctlProtocol"] = "not-issued"
                }
            }
        };

        for (var index = 0; index < ExpectedStressDriverRows; index++)
        {
            events.Add(new SandboxEvent
            {
                EventType = "driver.file",
                Source = "driver",
                ProcessId = 4242,
                Path = $@"C:\KSwordSandbox\stress\file-{index:D2}.tmp",
                Data =
                {
                    ["mock"] = "true",
                    ["stress"] = "true",
                    ["eventSchemaName"] = "ksword.sandbox.r0.event",
                    ["eventSchemaVersion"] = AbiVersion,
                    ["eventSchemaVersionHex"] = AbiVersionHex,
                    ["version"] = AbiVersion,
                    ["versionHex"] = AbiVersionHex,
                    ["recordSize"] = "96",
                    ["driverEventTypeName"] = "file",
                    ["sequence"] = (StressJsonlSequenceStart + index).ToString(),
                    ["payloadSize"] = "56",
                    ["payloadSchema"] = "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD",
                    ["typedPayloadStatus"] = "mock",
                    ["typedPayloadParsed"] = "true"
                }
            });
        }

        events.Add(BuildStatusRow("afterDrain", queueDepth: 8, highWatermark: ExpectedEventRingCapacity, dropped: 9, suppressed: 5, nextSequence: 1232));
        return events;
    }

    /// <summary>
    /// Builds one status row for the synthetic corpus. Inputs are a phase and
    /// counters; processing stores all values as JSONL-compatible strings;
    /// return value is the event.
    /// </summary>
    private static SandboxEvent BuildStatusRow(
        string phase,
        int queueDepth,
        int highWatermark,
        int dropped,
        int suppressed,
        int nextSequence)
    {
        return new SandboxEvent
        {
            EventType = "r0collector.driverStatus",
            Source = "r0collector",
            Path = @"\\.\KSwordSandboxDriver",
            Data =
            {
                ["phase"] = phase,
                ["version"] = AbiVersion,
                ["versionHex"] = AbiVersionHex,
                ["size"] = "120",
                ["queueCapacity"] = ExpectedEventRingCapacity.ToString(),
                ["queueDepth"] = queueDepth.ToString(),
                ["queueHighWatermark"] = highWatermark.ToString(),
                ["producerEnableMaskHex"] = "0x0000001B",
                ["supportedProducerMaskHex"] = CurrentProducerMaskHex,
                ["activeProducerMaskHex"] = "0x0000003B",
                ["failedProducerMaskHex"] = "0x00000004",
                ["totalEventsEnqueued"] = nextSequence.ToString(),
                ["totalEventsDropped"] = dropped.ToString(),
                ["totalEventsRead"] = (nextSequence - queueDepth).ToString(),
                ["totalEventsSuppressed"] = suppressed.ToString(),
                ["nextSequence"] = nextSequence.ToString(),
                ["totalEventsBackpressured"] = highWatermark >= ExpectedBackpressureQueueDepth ? "1" : "0",
                ["producerDroppedMaskHex"] = "0x00000008",
                ["producerSuppressedMaskHex"] = "0x00000010",
                ["producerBackpressureMaskHex"] = "0x00000018",
                ["backpressureObserved"] = "true"
            }
        };
    }

    /// <summary>
    /// Asserts that parsed rows retain event-quality evidence. Inputs are parsed
    /// events; processing checks required rows and data keys; return value is none.
    /// </summary>
    private static void AssertSyntheticEventQualityRows(IReadOnlyCollection<SandboxEvent> events)
    {
        var capabilities = RequireEvent(events, "r0collector.driverCapabilities");
        RequireData(capabilities, "abiVersionMajor", "1");
        RequireData(capabilities, "abiVersionMinor", "0");
        RequireData(capabilities, "eventHeaderVersion", AbiVersion);
        RequireData(capabilities, "supportedProducerMaskHex", CurrentProducerMaskHex);
        RequireData(capabilities, "eventSchemaName", "ksword.sandbox.r0.event");

        var producerMask = RequireEvent(events, "r0collector.driverProducerMask");
        RequireData(producerMask, "requestedEnableMaskHex", "0x0000001B");
        RequireData(producerMask, "effectiveEnableMaskHex", "0x0000001B");
        RequireData(producerMask, "supportedProducerMaskHex", CurrentProducerMaskHex);

        var statusRows = events
            .Where(evt => string.Equals(evt.EventType, "r0collector.driverStatus", StringComparison.OrdinalIgnoreCase))
            .ToList();
        SmokeAssert.True(statusRows.Count >= 2, "Synthetic corpus should include pre/post driverStatus rows.");
        SmokeAssert.True(
            statusRows.All(evt =>
                evt.Data.ContainsKey("queueCapacity") &&
                evt.Data.ContainsKey("queueHighWatermark") &&
                evt.Data.ContainsKey("totalEventsDropped") &&
                evt.Data.ContainsKey("totalEventsSuppressed") &&
                evt.Data.ContainsKey("nextSequence")),
            "Every driverStatus row should preserve queue and loss/backpressure counters.");

        var before = statusRows.First(evt => DataEquals(evt, "phase", "beforeDrain"));
        var after = statusRows.First(evt => DataEquals(evt, "phase", "afterDrain"));
        SmokeAssert.True(
            new[] { before, after }.All(evt =>
                evt.Data.ContainsKey("totalEventsBackpressured") &&
                evt.Data.ContainsKey("producerDroppedMaskHex") &&
                evt.Data.ContainsKey("producerSuppressedMaskHex") &&
                evt.Data.ContainsKey("producerBackpressureMaskHex")),
            "Synthetic before/after status rows should preserve new producer loss/backpressure masks.");
        SmokeAssert.True(
            ToInt(after, "totalEventsDropped") >= ToInt(before, "totalEventsDropped"),
            "Dropped/lost event counter should be monotonic across status rows.");
        SmokeAssert.True(
            ToInt(before, "queueHighWatermark") == ToInt(before, "queueCapacity"),
            "Backpressure corpus should prove the queue reached capacity.");

        var readEvents = RequireEvent(events, "r0collector.driverReadEvents");
        RequireData(readEvents, "eventsDropped", "9");
        RequireData(readEvents, "eventsWritten", "16");
        RequireData(readEvents, "eventsEmitted", "16");

        var mockMarker = RequireEvent(events, "r0collector.mockDriverEvent");
        RequireData(mockMarker, "mock", "true");
        RequireData(mockMarker, "stress", "true");

        var stressRows = events
            .Where(evt => string.Equals(evt.EventType, "driver.file", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "stress", "true"))
            .ToList();
        SmokeAssert.True(stressRows.Count == ExpectedStressDriverRows, $"Synthetic stress corpus should preserve {ExpectedStressDriverRows} driver.file rows. Actual: {stressRows.Count}");
        SmokeAssert.True(
            stressRows.All(evt =>
                DataEquals(evt, "eventSchemaVersion", AbiVersion) &&
                evt.Data.ContainsKey("version") &&
                evt.Data.ContainsKey("recordSize") &&
                evt.Data.ContainsKey("sequence") &&
                DataEquals(evt, "payloadSchema", "KSWORD_SANDBOX_FILE_EVENT_PAYLOAD")),
            "Every stress driver row should preserve ABI version, record size, sequence, and payload schema.");

        var started = RequireEvent(events, "r0collector.started");
        RequireData(started, "StressJsonlExpectedDriverRows", ExpectedStressDriverRows.ToString());
        RequireData(started, "StressJsonlSequenceStart", StressJsonlSequenceStart.ToString());
        RequireData(started, "StressJsonlSequenceEnd", StressJsonlSequenceEnd.ToString());
        RequireData(started, "StressJsonlSequenceGapCount", StressJsonlSequenceGapCount.ToString());
        SmokeAssert.True(started.Data.ContainsKey("StressJsonlLossEvidence"), "Started row should name stress loss evidence fields.");
        SmokeAssert.True(started.Data.ContainsKey("StressJsonlBackpressureEvidence"), "Started row should name stress backpressure evidence fields.");
    }

    /// <summary>
    /// Runs the built collector stress/noise mode. Inputs are the smoke context
    /// and cancellation token; processing writes native build/run artifacts only
    /// under D:\Temp\KSwordSandbox\verify; return value is none.
    /// </summary>
    private static async Task AssertExecutableStressNoiseQualityAsync(
        SmokeTestContext context,
        CancellationToken cancellationToken)
    {
        var build = await R0CollectorExecutableSmokeHelper.BuildCollectorAsync(context, cancellationToken);
        var outputPath = R0CollectorExecutableSmokeHelper.CreateRunOutputPath(build, "r0collector-stress-noise.jsonl");
        var result = await R0CollectorExecutableSmokeHelper.RunCollectorAsync(
            build.ExecutablePath,
            [
                "--stress-count",
                ExpectedStressDriverRows.ToString(),
                "--inject-jsonl-noise",
                "--heartbeat",
                "--max-events",
                "16",
                "--max-read-batches",
                "4",
                "--out",
                outputPath
            ],
            context.RepositoryRoot,
            cancellationToken);
        if (R0CollectorExecutableSmokeHelper.IsExecutionBlockedByHostPolicy(result))
        {
            SmokeAssert.True(
                result.CombinedOutput.Contains("Execution blocked by host policy", StringComparison.Ordinal),
                "Blocked executable stress/noise smoke should report explicit host-policy evidence.");
            return;
        }

        SmokeAssert.True(result.ExitCode == 0, $"collector stress/noise smoke should exit 0. Output: {result.CombinedOutput}");

        var jsonLines = R0CollectorExecutableSmokeHelper.ReadJsonLines(outputPath);
        SmokeAssert.True(jsonLines.BlankLineCount == 1, "Executable stress/noise JSONL should include one blank noise line.");
        SmokeAssert.True(jsonLines.MalformedLines.Count == 1, "Executable stress/noise JSONL should include one malformed noise line.");
        SmokeAssert.True(
            jsonLines.MalformedLines.Single().Contains("broken", StringComparison.Ordinal),
            "Malformed executable stress/noise row should retain the broken sequence marker.");

        var stressRows = jsonLines.Events
            .Where(evt => string.Equals(evt.EventType, "driver.file", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "stress", "true"))
            .ToList();
        SmokeAssert.True(stressRows.Count == ExpectedStressDriverRows, $"Executable collector should emit {ExpectedStressDriverRows} stress rows.");
        SmokeAssert.True(
            stressRows.All(evt =>
                DataEquals(evt, "producer", "file") &&
                DataEquals(evt, "schema", "ksword.sandbox.r0.event") &&
                DataEquals(evt, "noise", "false") &&
                DataEquals(evt, "lost", "false") &&
                DataEquals(evt, "backpressure", "false") &&
                evt.Data.ContainsKey("sequence") &&
                evt.Data.ContainsKey("StressJsonlLossEvidence") &&
                evt.Data.ContainsKey("StressJsonlBackpressureEvidence")),
            "Executable stress rows should preserve stable producer/schema/noise/loss/backpressure fields.");
        AssertMonotonicStressSequences(jsonLines.Events);

        var mockNetwork = jsonLines.Events.FirstOrDefault(evt =>
            string.Equals(evt.EventType, "driver.network", StringComparison.OrdinalIgnoreCase) &&
            DataEquals(evt, "producer", "network") &&
            DataEquals(evt, "noise", "false"));
        SmokeAssert.True(mockNetwork is not null, "Executable mock corpus should include a non-noise driver.network row.");
        RequireData(mockNetwork!, "sourceEndpoint", "192.0.2.10:51515");
        RequireData(mockNetwork!, "destinationEndpoint", "203.0.113.10:443");
        RequireData(mockNetwork!, "flowKey", "tcp|192.0.2.10:51515|203.0.113.10:443");

        var validNoise = jsonLines.Events.FirstOrDefault(evt =>
            string.Equals(evt.EventType, "driver.network", StringComparison.OrdinalIgnoreCase) &&
            DataEquals(evt, "noise", "true") &&
            DataEquals(evt, "sequence", "9999"));
        SmokeAssert.True(validNoise is not null, "Executable JSONL noise corpus should keep the valid extra-field driver.network row.");
        RequireData(validNoise!, "sourceEndpoint", "192.0.2.10:51515");
        RequireData(validNoise!, "destinationEndpoint", "203.0.113.10:443");
        RequireData(validNoise!, "flowKey", "tcp|192.0.2.10:51515|203.0.113.10:443");
    }

    /// <summary>
    /// Requires stress row sequences to be contiguous. Inputs are parsed events;
    /// processing extracts integer sequence values; return value is none.
    /// </summary>
    private static void AssertMonotonicStressSequences(IReadOnlyCollection<SandboxEvent> events)
    {
        var sequences = events
            .Where(evt => string.Equals(evt.EventType, "driver.file", StringComparison.OrdinalIgnoreCase) &&
                DataEquals(evt, "stress", "true"))
            .Select(evt => ToInt(evt, "sequence"))
            .Order()
            .ToList();
        SmokeAssert.True(sequences.Count == ExpectedStressDriverRows, $"Expected {ExpectedStressDriverRows} stress sequences.");
        SmokeAssert.True(sequences.First() == StressJsonlSequenceStart, "Stress driver event sequence start should match the gate contract.");
        SmokeAssert.True(sequences.Last() == StressJsonlSequenceEnd, "Stress driver event sequence end should match the gate contract.");
        var gapCount = 0;
        for (var index = 1; index < sequences.Count; index++)
        {
            if (sequences[index] != sequences[index - 1] + 1)
            {
                gapCount++;
            }
        }

        SmokeAssert.True(
            gapCount == StressJsonlSequenceGapCount,
            "Stress driver event sequence values should remain contiguous inside the parsed JSONL corpus.");
    }

    /// <summary>
    /// Returns the first event with an expected type. Inputs are event list and
    /// type; processing searches case-insensitively; return value is the event.
    /// </summary>
    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"Synthetic corpus should contain {eventType}.");
        return evt!;
    }

    /// <summary>
    /// Requires one data value. Inputs are an event, key, and value; processing
    /// compares ordinally; return value is none.
    /// </summary>
    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(
            evt.Data.TryGetValue(key, out var actual) &&
            string.Equals(actual, expected, StringComparison.Ordinal),
            $"{evt.EventType} should contain data.{key}={expected}.");
    }

    /// <summary>
    /// Compares one event data value. Inputs are an event, key, and value;
    /// processing performs ordinal comparison; return value is true on match.
    /// </summary>
    private static bool DataEquals(SandboxEvent evt, string key, string expected)
    {
        return evt.Data.TryGetValue(key, out var actual) &&
            string.Equals(actual, expected, StringComparison.Ordinal);
    }

    /// <summary>
    /// Parses an integer data value. Inputs are an event and data key; processing
    /// asserts parse success; return value is the parsed integer.
    /// </summary>
    private static int ToInt(SandboxEvent evt, string key)
    {
        SmokeAssert.True(
            evt.Data.TryGetValue(key, out var value) &&
            int.TryParse(value, out _),
            $"{evt.EventType} should contain integer data.{key}.");
        return int.Parse(evt.Data[key]);
    }

    /// <summary>
    /// Requires fields in a C ABI struct. Inputs are header text, struct name,
    /// and field names; processing extracts the struct text; return value is none.
    /// </summary>
    private static void RequireStructFields(string header, string structName, params string[] fields)
    {
        var start = header.IndexOf($"typedef struct _{structName}", StringComparison.Ordinal);
        SmokeAssert.True(start >= 0, $"ABI header should define {structName}.");
        var end = header.IndexOf($"}} {structName}", start, StringComparison.Ordinal);
        SmokeAssert.True(end > start, $"ABI header should terminate {structName}.");
        var structText = header[start..end];
        foreach (var field in fields)
        {
            RequireContains(structText, field, $"{structName} must include {field}.");
        }
    }

    /// <summary>
    /// Reads a repository file by path segment. Inputs are context and relative
    /// segments; processing combines them under RepositoryRoot; return value is text.
    /// </summary>
    private static string ReadRepositoryText(SmokeTestContext context, params string[] segments)
    {
        var allSegments = new string[segments.Length + 1];
        allSegments[0] = context.RepositoryRoot;
        Array.Copy(segments, 0, allSegments, 1, segments.Length);
        var path = Path.Combine(allSegments);
        SmokeAssert.True(File.Exists(path), $"Required R0 event-quality file is missing: {path}");
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Requires a text fragment to be present. Inputs are content, expected
    /// text, and message; processing throws on absence; return value is none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
