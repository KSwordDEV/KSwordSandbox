using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Lightweight JSONL schema smoke for the R0Collector contract. Inputs are the
/// schema docs, public ABI header, and a tiny in-memory JSONL stream; processing
/// verifies sequence/loss/high-watermark/backpressure/noise fields remain
/// documented and parseable without running a live driver.
/// </summary>
internal sealed class R0CollectorJsonlSchemaContractScenario : ISmokeTestScenario
{
    private static readonly JsonSerializerOptions JsonLineOptions = new(JsonSerializerDefaults.Web);

    public string ScenarioId => "r0.collector.jsonl-schema.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var schemaDoc = ReadText(context, "docs", "r0-jsonl-schema.md");
        var collectorDoc = ReadText(context, "docs", "r0-collector.md");
        var header = ReadText(context, "driver", "KSword.Sandbox.Driver", "include", "KSwordSandboxDriverIoctl.h");
        var common = ReadText(context, "guest", "KSword.Sandbox.R0Collector", "src", "Common.h");
        var parser = ReadText(context, "guest", "KSword.Sandbox.R0Collector", "src", "EventParser.cpp");
        var synthetic = ReadText(context, "guest", "KSword.Sandbox.R0Collector", "src", "SyntheticMode.cpp");
        var abiSelfCheck = ReadText(context, "guest", "KSword.Sandbox.R0Collector", "src", "AbiSelfCheck.cpp");

        AssertDocumentedSchemaFields(schemaDoc, collectorDoc);
        AssertSourceSchemaFields(header, common, parser, synthetic, abiSelfCheck);
        AssertInMemoryJsonlNoiseAndSchemaParsing();

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "R0Collector JSONL schema documents and parses sequence/loss/high-watermark/backpressure/noise fields."
        });
    }

    private static void AssertDocumentedSchemaFields(string schemaDoc, string collectorDoc)
    {
        foreach (var field in StableSchemaFields())
        {
            RequireContains(schemaDoc, field, $"r0-jsonl-schema.md should document stable data.{field}.");
            RequireContains(collectorDoc, field, $"r0-collector.md should document stable data.{field}.");
        }

        foreach (var phrase in new[]
        {
            "driver.parse_error",
            "--inject-jsonl-noise",
            "malformed",
            "extra-field",
            "StressJsonlLossEvidence",
            "StressJsonlBackpressureEvidence"
        })
        {
            RequireContains(schemaDoc, phrase, $"JSONL schema doc should cover {phrase}.");
            RequireContains(collectorDoc, phrase, $"Collector doc should cover {phrase}.");
        }
    }

    private static void AssertSourceSchemaFields(
        string header,
        string common,
        string parser,
        string synthetic,
        string abiSelfCheck)
    {
        RequireContains(header, "Sequence/loss/backpressure policy", "ABI header should document stable sequence/loss/backpressure policy.");
        RequireContains(header, "QueueHighWatermark", "ABI header should document queue high-watermark evidence.");
        RequireContains(header, "EventsDropped and NextSequence", "ABI header should document READ_EVENTS batch loss/sequence evidence.");
        RequireContains(common, "kStressJsonlLossEvidence", "Common.h should define the stress loss evidence token list.");
        RequireContains(common, "kStressJsonlBackpressureEvidence", "Common.h should define the stress backpressure evidence token list.");
        RequireContains(common, "lossObserved", "Stress loss evidence should include lossObserved.");
        RequireContains(common, "backpressureObserved", "Stress backpressure evidence should include backpressureObserved.");
        RequireContains(common, "sampling", "Stress backpressure evidence should include sampling.");

        foreach (var source in new[] { parser, synthetic, abiSelfCheck })
        {
            foreach (var field in StableSchemaFields())
            {
                RequireContains(source, field, $"R0Collector source should emit or contract data.{field}.");
            }
        }
    }

    private static void AssertInMemoryJsonlNoiseAndSchemaParsing()
    {
        var lines = new[]
        {
            "   ",
            "{\"eventType\":\"driver.file\",\"source\":\"driver\",\"data\":{\"sequence\":\"broken\"",
            JsonSerializer.Serialize(BuildStressRow(), JsonLineOptions),
            JsonSerializer.Serialize(BuildReadEventsSummary(), JsonLineOptions)
        };

        var events = new List<SandboxEvent>();
        var blank = 0;
        var malformed = 0;
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                blank++;
                continue;
            }

            try
            {
                var evt = JsonSerializer.Deserialize<SandboxEvent>(line, JsonLineOptions);
                if (evt is not null)
                {
                    events.Add(evt);
                }
            }
            catch (JsonException)
            {
                malformed++;
            }
        }

        SmokeAssert.True(blank == 1, "Schema smoke should count one blank JSONL noise line.");
        SmokeAssert.True(malformed == 1, "Schema smoke should count one malformed JSONL noise line.");
        SmokeAssert.True(events.Count == 2, "Schema smoke should keep valid JSONL rows after noise.");

        var stress = RequireEvent(events, "driver.file");
        RequireData(stress, "sequence", "1200");
        RequireData(stress, "lost", "false");
        RequireData(stress, "lostCount", "0");
        RequireData(stress, "lossObserved", "false");
        RequireData(stress, "highWatermark", "0");
        RequireData(stress, "backpressure", "false");
        RequireData(stress, "backpressureObserved", "false");
        RequireData(stress, "collectorSelfNoise", "false");
        RequireData(stress, "collectorSuppressed", "false");

        var summary = RequireEvent(events, "r0collector.driverReadEvents");
        RequireData(summary, "sequence", "1232");
        RequireData(summary, "sequenceMeaning", "nextSequence");
        RequireData(summary, "head", "1200");
        RequireData(summary, "tail", "1231");
        RequireData(summary, "loss", "none");
        RequireData(summary, "backpressureReason", "none");
        RequireData(summary, "sampling", "none");
    }

    private static SandboxEvent BuildStressRow()
    {
        return new SandboxEvent
        {
            EventType = "driver.file",
            Source = "driver",
            Path = @"C:\Users\Public\ksword-r0collector-stress-0.tmp",
            Data =
            {
                ["mock"] = "true",
                ["stress"] = "true",
                ["schema"] = "ksword.sandbox.r0.event",
                ["producer"] = "file",
                ["sequence"] = "1200",
                ["noise"] = "false",
                ["collectorNoise"] = "false",
                ["collectorSelfNoise"] = "false",
                ["selfProcess"] = "false",
                ["collectorSuppressed"] = "false",
                ["selfNoise"] = "false",
                ["selfNoiseReason"] = "none",
                ["selfNoiseAction"] = "emit",
                ["lost"] = "false",
                ["lostCount"] = "0",
                ["lossObserved"] = "false",
                ["highWatermark"] = "0",
                ["backpressure"] = "false",
                ["backpressureObserved"] = "false",
                ["lastEnqueueFailureStatus"] = "0",
                ["StressJsonlLossEvidence"] = "lost|lostCount|lossObserved|sequence|sequenceGapObserved|sequenceGapEstimate|head|tail|loss",
                ["StressJsonlBackpressureEvidence"] = "backpressure|backpressureObserved|highWatermark|sampling"
            }
        };
    }

    private static SandboxEvent BuildReadEventsSummary()
    {
        return new SandboxEvent
        {
            EventType = "r0collector.driverReadEvents",
            Source = "r0collector",
            Path = @"\\.\KSwordSandboxDriver",
            Data =
            {
                ["recordsProcessed"] = "32",
                ["eventsEmitted"] = "32",
                ["collectorSuppressedEvents"] = "0",
                ["collectorSkippedEvents"] = "0",
                ["processed"] = "32",
                ["eligible"] = "32",
                ["emitted"] = "32",
                ["suppressed"] = "0",
                ["skipped"] = "0",
                ["head"] = "1200",
                ["tail"] = "1231",
                ["sampling"] = "none",
                ["loss"] = "none",
                ["lost"] = "false",
                ["lostCount"] = "0",
                ["lossObserved"] = "false",
                ["highWatermark"] = "0",
                ["backpressure"] = "false",
                ["backpressureObserved"] = "false",
                ["backpressureReason"] = "none",
                ["sequence"] = "1232",
                ["sequenceMeaning"] = "nextSequence",
                ["noise"] = "false",
                ["collectorNoise"] = "false",
                ["collectorSelfNoise"] = "false",
                ["selfProcess"] = "false",
                ["collectorSuppressed"] = "false"
            }
        };
    }

    private static IEnumerable<string> StableSchemaFields()
    {
        return new[]
        {
            "sequence",
            "sequenceMeaning",
            "lost",
            "lostCount",
            "lossObserved",
            "highWatermark",
            "backpressure",
            "backpressureObserved",
            "backpressureReason",
            "noise",
            "collectorNoise",
            "collectorSelfNoise",
            "selfProcess",
            "collectorSuppressed",
            "selfNoise",
            "selfNoiseReason",
            "selfNoiseAction",
            "processed",
            "eligible",
            "emitted",
            "suppressed",
            "skipped",
            "head",
            "tail",
            "sampling"
        };
    }

    private static SandboxEvent RequireEvent(IEnumerable<SandboxEvent> events, string eventType)
    {
        var evt = events.FirstOrDefault(candidate => string.Equals(candidate.EventType, eventType, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(evt is not null, $"JSONL schema smoke should contain {eventType}.");
        return evt!;
    }

    private static void RequireData(SandboxEvent evt, string key, string expected)
    {
        SmokeAssert.True(
            evt.Data.TryGetValue(key, out var actual) &&
            string.Equals(actual, expected, StringComparison.Ordinal),
            $"{evt.EventType} should contain data.{key}={expected}.");
    }

    private static string ReadText(SmokeTestContext context, params string[] segments)
    {
        var path = Path.Combine(new[] { context.RepositoryRoot }.Concat(segments).ToArray());
        SmokeAssert.True(File.Exists(path), $"Required R0 JSONL schema contract file is missing: {path}");
        return File.ReadAllText(path);
    }

    private static void RequireContains(string content, string expected, string message)
    {
        SmokeAssert.True(content.Contains(expected, StringComparison.Ordinal), message);
    }
}
