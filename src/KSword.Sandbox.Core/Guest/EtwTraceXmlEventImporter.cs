using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Imports tracerpt XML left in a guest output folder when the Guest Agent
/// crashed before it could serialize events.json.  It is deliberately a
/// conservative fallback: rows retain ETW provenance and are unattributed
/// unless their own payload contains a PID/lineage anchor.
/// </summary>
public static class EtwTraceXmlEventImporter
{
    private const long MaxXmlBytes = 128L * 1024 * 1024;
    private const int MaxRowsPerTrace = 100_000;
    // tracerpt versions in the field sometimes emit kernel payload as one
    // unnamed string. Keep the same bounded key vocabulary as the guest
    // decoder so a whitespace-delimited payload does not collapse into an
    // unattributed generic row during host recovery.
    private const string UnnamedPayloadKeyPattern =
        "UniqueProcessKey|ProcessId|Pid|ParentProcessId|ParentPid|ParentId|" +
        "ThreadId|TThreadId|Tid|EventName|Task|Opcode|Operation|" +
        "ImageFileName|ImageName|ProcessName|Process|FileName|Image|" +
        "CommandLine|Command|ExitStatus|ExitTime|Status|Path|ImagePath|" +
        "KeyName|KeyPath|ObjectName|ImageBase|ImageSize|ImageChecksum";
    private static readonly Regex UnnamedPayloadFieldRegex = new(
        $"(?ix)(?<![A-Za-z0-9_.-])(?<key>{UnnamedPayloadKeyPattern})\\s*=\\s*(?<value>.*?)(?=(?:\\s*[;,]\\s*|\\r?\\n|\\s+)(?:{UnnamedPayloadKeyPattern})\\s*=|$)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

    // tracerpt writes the guest's time-zone offset as +HH:MM. Some Windows
    // builds emit +07:59 instead of +08:00, which shifts every row 60 seconds
    // later and makes a child process look like it started after its parent
    // exited. Detect a non-zero minute component and calibrate from the
    // trace header FILETIME (StartTime) when it is present.
    private static readonly Regex SystemTimeOffsetRegex = new(
        "(?<sign>[+-])(?<hour>\\d{2}):(?<minute>\\d{2})$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Returns whether the guest stream already contains semantic ETW rows.
    /// The same predicate is used by live import and offline PostProcess so
    /// ETW XML is a fallback only; rebuilding a report must not append a
    /// second full-machine trace after the Agent has already decoded rows.
    /// </summary>
    public static bool HasDecodedRows(IReadOnlyCollection<SandboxEvent> events)
    {
        if (events is null || events.Count == 0)
        {
            return false;
        }

        if (events.Any(evt =>
                evt.Source.Equals("etwLive", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.TryGetValue("captureSource", out var captureSource) &&
                captureSource.Equals("etw-live-tracerpt", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.TryGetValue("rawDecoded", out var rawDecoded) &&
                rawDecoded.Equals("true", StringComparison.OrdinalIgnoreCase) &&
                !evt.EventType.StartsWith("etw_live.", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        // Older Agent builds emitted only the summary marker.  Preserve that
        // compatibility path while requiring a positive semantic row count.
        return events.Any(evt =>
        {
            if (!evt.EventType.Equals("etw_live.captured", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return evt.Data.TryGetValue("semanticRowsAvailable", out var rowsAvailable) &&
                rowsAvailable.Equals("true", StringComparison.OrdinalIgnoreCase) &&
                evt.Data.TryGetValue("parsedEventCount", out var countText) &&
                long.TryParse(countText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count) &&
                count > 0;
        });
    }

    /// <summary>
    /// Imports ETW XML only when the supplied events do not already contain
    /// decoded semantic rows, then adds one explicit diagnostic for every
    /// captured ETW summary that reports zero parsed rows. A zero parsed count
    /// is a collection gap even when an ETL file exists or XML fallback happens
    /// to yield a few rows, and must never be treated as a clean capture.
    /// </summary>
    public static IReadOnlyList<SandboxEvent> ImportFallbackAndCoverage(
        IReadOnlyCollection<SandboxEvent> existingEvents,
        string? guestOutputRoot)
    {
        var imported = new List<SandboxEvent>();
        if (!HasDecodedRows(existingEvents))
        {
            var xmlRows = Import(guestOutputRoot);
            imported.AddRange(xmlRows);
            // The XML fallback above only helps when the Agent survived long
            // enough to run its own tracerpt pass. A sample that kills the Agent
            // leaves a raw ETL and no XML at all, which used to mean the report
            // showed zero dynamic evidence even though the trace was sitting on
            // the host. Decode it there as the last recovery step.
            //
            // Only when the guest XML yielded no semantic rows of its own. The
            // Agent can write the decoded XML and then die before serializing
            // events.json; re-decoding that same trace on the host would append
            // a second copy of rows the guest already produced.
            if (!HasSemanticRows(xmlRows))
            {
                imported.AddRange(HostEtlTraceDecoder.ImportFallback(existingEvents, guestOutputRoot));
            }
        }

        var existingZeroDiagnostics = existingEvents
            .Where(IsZeroParsedDiagnostic)
            .Select(evt => DiagnosticPath(evt))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var summary in existingEvents.Where(IsCapturedSummary))
        {
            if (!TryGetZeroParsedCount(summary, out var count, out var reason))
            {
                continue;
            }

            var path = FirstValue(summary, "traceArtifactPath", "etlPath", "artifactPath") ??
                guestOutputRoot ?? string.Empty;
            if (!existingZeroDiagnostics.Add(path))
            {
                continue;
            }

            imported.Add(CreateZeroParsedDiagnostic(summary, path, count, reason));
        }

        return imported;
    }

    private static bool IsCapturedSummary(SandboxEvent evt) =>
        evt.EventType.Equals("etw_live.captured", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Returns whether a decoded XML pass produced real behavior rows. A
    /// document that only yields import-failure diagnostics carries no evidence,
    /// so a host-side ETL decode is still worth attempting for it.
    /// </summary>
    private static bool HasSemanticRows(IReadOnlyCollection<SandboxEvent> rows) =>
        rows.Any(evt => !evt.EventType.StartsWith("etw.", StringComparison.OrdinalIgnoreCase) &&
            !evt.EventType.StartsWith("etw_live.", StringComparison.OrdinalIgnoreCase));

    private static bool IsZeroParsedDiagnostic(SandboxEvent evt) =>
        evt.EventType.Equals("etw_live.decode_failed", StringComparison.OrdinalIgnoreCase) &&
        evt.Data.TryGetValue("failureType", out var failureType) &&
        failureType.Equals("etwParsedEventCountZero", StringComparison.OrdinalIgnoreCase);

    private static bool TryGetZeroParsedCount(SandboxEvent evt, out long count, out string reason)
    {
        count = 0;
        reason = "parsedEventCount=0";
        if (evt.Data.TryGetValue("parsedEventCount", out var countText) &&
            long.TryParse(countText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            count = parsed;
            return parsed <= 0;
        }

        // Some older probe builds did not write parsedEventCount when the
        // decoder failed. Their explicit decode-required marker is equivalent
        // evidence, so retain a diagnostic with a stable zero-count alias.
        if (evt.Data.TryGetValue("etlDecodeRequired", out var required) &&
            required.Equals("true", StringComparison.OrdinalIgnoreCase) &&
            evt.Data.TryGetValue("semanticRowsAvailable", out var rows) &&
            rows.Equals("false", StringComparison.OrdinalIgnoreCase))
        {
            reason = "etlDecodeRequired=true;semanticRowsAvailable=false";
            return true;
        }

        return false;
    }

    private static SandboxEvent CreateZeroParsedDiagnostic(SandboxEvent summary, string path, long count, string reason)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etw-live-tracerpt",
            ["collectionHealth"] = "true",
            ["captureState"] = "failed",
            ["status"] = "failed",
            ["failureType"] = "etwParsedEventCountZero",
            ["parsedEventCount"] = count.ToString(CultureInfo.InvariantCulture),
            ["decodedEventCount"] = count.ToString(CultureInfo.InvariantCulture),
            ["diagnosticReason"] = reason,
            ["etlDecodeRequired"] = FirstValue(summary, "etlDecodeRequired") ?? "true",
            ["semanticRowsAvailable"] = "false",
            ["sampleCorrelation"] = "unattributed",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["eventKind"] = "diagnostic",
            ["evidenceRole"] = "collection-diagnostic",
            ["sourceComponent"] = "etw-live-tracerpt",
            ["zhMessage"] = "ETW 原始 ETL 已保存，但解析行为行数量为 0；动态证据不可判定。",
            ["zhHint"] = "不能把 ETL 原始文件当作已解析行为；请修复 tracerpt 解码或解析输出。"
        };
        var decodedPath = FirstValue(summary, "decodedArtifactPath", "decodedArtifactRelativePath");
        if (!string.IsNullOrWhiteSpace(decodedPath))
        {
            data["decodedArtifactPath"] = decodedPath;
        }

        return new SandboxEvent
        {
            EventType = "etw_live.decode_failed",
            Timestamp = summary.Timestamp,
            Source = "etwLive",
            Path = path,
            Data = data
        };
    }

    private static string? DiagnosticPath(SandboxEvent evt) =>
        evt.Path ?? FirstValue(evt, "traceArtifactPath", "etlPath", "artifactPath");

    private static string? FirstValue(SandboxEvent evt, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (evt.Data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>
    /// Host import ceiling for one decoded tracerpt document. Exposed so a
    /// host-driven decode can discard an oversized XML dump before paying the
    /// XDocument load cost.
    /// </summary>
    public static long XmlImportLimitBytes => MaxXmlBytes;

    /// <summary>
    /// Parses one already-decoded tracerpt XML document. Inputs are the XML
    /// path; processing returns semantic rows, or a single structured failure
    /// row when the document cannot be read. The method never throws for
    /// ordinary IO or XML faults.
    /// </summary>
    public static IReadOnlyList<SandboxEvent> ImportXmlFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        try
        {
            return Parse(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
        {
            return [CreateFailure(path, ex)];
        }
    }

    public static IReadOnlyList<SandboxEvent> Import(string? guestOutputRoot)
    {
        if (string.IsNullOrWhiteSpace(guestOutputRoot) || !Directory.Exists(guestOutputRoot)) return [];
        var rows = new List<SandboxEvent>();
        foreach (var path in EnumerateXml(guestOutputRoot))
        {
            rows.AddRange(ImportXmlFile(path));
        }
        return rows;
    }

    private static IEnumerable<string> EnumerateXml(string root)
    {
        try
        {
            return Directory.EnumerateFiles(root, "*.xml", SearchOption.AllDirectories)
                .Where(path => path.Contains("etw-traces", StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            return [];
        }
    }

    private static IReadOnlyList<SandboxEvent> Parse(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxXmlBytes)
        {
            return [CreateFailure(path, new InvalidDataException($"ETW XML exceeds the host import limit of {MaxXmlBytes} bytes."))];
        }

        var document = XDocument.Load(path, LoadOptions.PreserveWhitespace);
        var elements = document.Descendants()
            .Where(element => element.Name.LocalName.Equals("Event", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var correction = ResolveFileTimeCorrection(elements, out var offsetAnomaly);
        var rows = new List<SandboxEvent>();
        var importedCount = 0;
        var skippedCount = 0;
        long eventsLost = 0;
        foreach (var element in elements)
        {
            var system = element.Elements().FirstOrDefault(child => child.Name.LocalName.Equals("System", StringComparison.OrdinalIgnoreCase));
            if (system is null) continue;
            var providerElement = system.Elements().FirstOrDefault(child => child.Name.LocalName.Equals("Provider", StringComparison.OrdinalIgnoreCase));
            var rendering = element.Elements().FirstOrDefault(child => child.Name.LocalName.Equals("RenderingInfo", StringComparison.OrdinalIgnoreCase));
            var provider = First(providerElement?.Attribute("Name")?.Value, Child(rendering, "Provider"), "unknown");
            var task = First(Child(rendering, "Task", "TaskName"), Child(system, "Task", "TaskName"));
            var opcode = First(Child(rendering, "Opcode", "Operation"), Child(system, "Opcode", "Operation"));
            var eventId = Child(system, "EventID", "EventId", "Id");
            var eventName = First(
                Child(rendering, "EventName", "Name"),
                Child(system, "EventName", "Name"),
                task,
                opcode,
                provider + ":" + eventId);
            var timestamp = ParseTimestamp(
                system.Elements().FirstOrDefault(child => child.Name.LocalName.Equals("TimeCreated", StringComparison.OrdinalIgnoreCase))?.Attribute("SystemTime")?.Value,
                out var rowOffsetAnomaly) ?? DateTimeOffset.UtcNow;
            offsetAnomaly |= rowOffsetAnomaly;
            if (correction.HasValue)
            {
                timestamp += correction.Value;
            }
            var execution = system.Elements().FirstOrDefault(child => child.Name.LocalName.Equals("Execution", StringComparison.OrdinalIgnoreCase));
            var processId = ParsePid(First(execution?.Attribute("ProcessID")?.Value, execution?.Attribute("ProcessId")?.Value));
            var payload = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var rawPayload = new List<string>();
            foreach (var data in element.Descendants().Where(child => child.Name.LocalName.Equals("Data", StringComparison.OrdinalIgnoreCase)))
            {
                var value = data.Value.Trim();
                if (string.IsNullOrWhiteSpace(value)) continue;
                var name = First(data.Attribute("Name")?.Value, data.Attribute("name")?.Value);
                rawPayload.Add(string.IsNullOrWhiteSpace(name) ? value : name + "=" + value);
                if (!string.IsNullOrWhiteSpace(name)) payload[Normalize(name)] = value;
                else ParseUnnamed(value, payload);
            }
            processId = ParsePid(First(Value(payload, "processid", "pid"), processId?.ToString(CultureInfo.InvariantCulture)));
            var parentPid = ParsePid(Value(payload, "parentprocessid", "parentpid", "parentid"));
            eventName = First(Value(payload, "eventname", "taskname"), eventName);
            var payloadEventsLost = ParseUnsigned(Value(payload, "eventslost", "events_lost"));
            if (payloadEventsLost > 0)
            {
                eventsLost = Math.Max(eventsLost, payloadEventsLost);
            }

            var image = Value(payload, "imagefilename", "imagename", "processname", "image", "process");
            var commandLine = Value(payload, "commandline", "command");
            var pathValue = Value(payload, "filename", "file", "path", "imagepath", "keyname", "keypath", "objectname");
            var type = MapType(eventName, provider, task, opcode, payload, eventId);
            if (!IsUsefulType(type))
            {
                skippedCount++;
                continue;
            }

            var dataValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["captureSource"] = "etw-live-tracerpt",
                ["traceArtifactPath"] = path,
                ["traceArtifactRelativePath"] = RelativeToEtwRoot(path),
                ["etwHostImported"] = "true",
                ["eventName"] = eventName,
                ["provider"] = provider,
                ["eventId"] = eventId,
                ["opcode"] = opcode,
                ["sampleCorrelation"] = "unattributed",
                ["sampleCorrelationStatus"] = "unattributed",
                ["sampleCorrelationStrength"] = "none",
                ["attributionStatus"] = processId is null ? "unattributed-no-pid" : "pid-present-unjoined",
                ["rawPayload"] = string.Join("; ", rawPayload)
            };
            if (rowOffsetAnomaly)
            {
                dataValues["etwTimestampOffsetAnomaly"] = "true";
            }

            if (correction.HasValue)
            {
                dataValues["etwTimestampCorrectionSeconds"] = correction.Value.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture);
            }

            foreach (var pair in payload) dataValues.TryAdd(pair.Key, pair.Value);
            rows.Add(new SandboxEvent
            {
                EventType = type,
                Timestamp = timestamp,
                Source = "etwLive",
                ProcessName = image,
                ProcessId = processId,
                ParentProcessId = parentPid,
                Path = pathValue,
                CommandLine = commandLine,
                Data = dataValues
            });
            importedCount++;
            if (rows.Count >= MaxRowsPerTrace)
            {
                rows.Add(CreateLimitDiagnostic(path, MaxRowsPerTrace));
                break;
            }
        }

        if (offsetAnomaly)
        {
            rows.Add(CreateTimestampAnomaly(path, correction));
        }

        rows.Add(CreateDecodeSummary(path, elements.Count, importedCount, skippedCount, eventsLost));
        return rows;
    }

    private static bool IsUsefulType(string type) =>
        type is "etw.event" or "process.start" or "process.exit" or "process.event" or "image.load" or "image.unload" or "thread.start" or "thread.exit" or "thread.event" or "registry.etw" ||
        type.StartsWith("file.", StringComparison.OrdinalIgnoreCase) ||
        type.StartsWith("network.", StringComparison.OrdinalIgnoreCase);

    private static string MapType(
        string name,
        string provider,
        string task,
        string opcode,
        IReadOnlyDictionary<string, string> payload,
        string eventId = "")
    {
        var value = (name + " " + provider + " " + task + " " + opcode).ToLowerInvariant();
        if (value.Contains("process", StringComparison.Ordinal) && (value.Contains("start", StringComparison.Ordinal) || value.Contains("create", StringComparison.Ordinal) || value.Contains("dcstart", StringComparison.Ordinal))) return "process.start";
        if (value.Contains("process", StringComparison.Ordinal) && (value.Contains("stop", StringComparison.Ordinal) || value.Contains("exit", StringComparison.Ordinal) || value.Contains("end", StringComparison.Ordinal) || value.Contains("dcexit", StringComparison.Ordinal) || value.Contains("terminate", StringComparison.Ordinal) || value.Contains("defunct", StringComparison.Ordinal))) return "process.exit";
        if (value.Contains("image", StringComparison.Ordinal) && (value.Contains("unload", StringComparison.Ordinal) || value.Contains("dcend", StringComparison.Ordinal))) return "image.unload";
        if (value.Contains("image", StringComparison.Ordinal) && (value.Contains("load", StringComparison.Ordinal) || value.Contains("start", StringComparison.Ordinal) || value.Contains("dcstart", StringComparison.Ordinal))) return "image.load";
        if (value.Contains("thread", StringComparison.Ordinal) && (value.Contains("start", StringComparison.Ordinal) || value.Contains("dcstart", StringComparison.Ordinal))) return "thread.start";
        if (value.Contains("thread", StringComparison.Ordinal) && (value.Contains("stop", StringComparison.Ordinal) || value.Contains("end", StringComparison.Ordinal) || value.Contains("exit", StringComparison.Ordinal) || value.Contains("dcexit", StringComparison.Ordinal))) return "thread.exit";
        // Older tracerpt XML can omit RenderingInfo names and leave only the
        // Kernel-Process task plus numeric EventID. Apply this fallback after
        // explicit opcode/name semantics so EventID=5 with Opcode=Unload is
        // not incorrectly rewritten as ImageLoad.
        if (provider.Contains("kernel-process", StringComparison.OrdinalIgnoreCase) ||
            provider.Contains("kernel-image", StringComparison.OrdinalIgnoreCase))
        {
            switch (eventId.Trim().ToLowerInvariant())
            {
                case "1": return "process.start";
                case "2": return "process.exit";
                case "3": return "thread.start";
                case "4": return "thread.exit";
                case "5": return "image.load";
                case "6": return "image.unload";
            }
        }
        // NT Kernel Logger rows frequently carry no rendering name and only
        // GUID providers, so EventID/Task/Opcode are all zero. Classify those
        // rows by payload shape instead of dropping the whole trace. Order
        // matters: an image-load row also has FileName, and a network row can
        // carry process identity, so the most specific shape wins.
        if (!string.IsNullOrWhiteSpace(Value(payload, "imagebase")) &&
            !string.IsNullOrWhiteSpace(Value(payload, "filename", "imagename", "imagefilename")))
        {
            return "image.load";
        }

        if (!string.IsNullOrWhiteSpace(Value(payload, "keyname", "keypath")))
        {
            return "registry.etw";
        }

        if (!string.IsNullOrWhiteSpace(Value(payload, "tcpip", "saddr", "daddr", "sport", "dport", "localaddr", "remoteaddr")))
        {
            return "network.etw";
        }

        // A process payload alone does not prove a start event: DCStart
        // bookkeeping and generic Process rows carry the same fields. The
        // explicit name/task/opcode checks above own start/stop semantics.
        if (value.Contains("file", StringComparison.Ordinal) || value.Contains("fileio", StringComparison.Ordinal)) return "file.etw";
        if (value.Contains("network", StringComparison.Ordinal) || value.Contains("tcp", StringComparison.Ordinal)) return "network.etw";
        // tracerpt can omit RenderingInfo for kernel rows. Mirror the live
        // decoder's constrained payload-shape fallback so those rows retain
        // a stable process/thread family instead of being discarded as the
        // generic etw.event type.
        var hasThreadPayload = !string.IsNullOrWhiteSpace(Value(payload, "tthreadid", "threadid", "tid"));
        var hasProcessPayload = !string.IsNullOrWhiteSpace(Value(payload, "processid", "pid")) &&
            (!string.IsNullOrWhiteSpace(Value(payload, "parentid", "parentprocessid", "parentpid")) ||
             !string.IsNullOrWhiteSpace(Value(payload, "imagename", "imagefilename", "processname")));
        if (hasThreadPayload && !hasProcessPayload)
        {
            return "thread.event";
        }

        if (hasProcessPayload)
        {
            return "process.event";
        }

        return value.Contains("registry", StringComparison.Ordinal) ? "registry.etw" : "etw.event";
    }

    private static SandboxEvent CreateFailure(string path, Exception exception) => new()
    {
        EventType = "etw.import.failed",
        Source = "etwLive",
        Path = path,
        Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etw-live-tracerpt",
            ["collectionHealth"] = "true",
            ["captureState"] = "failed",
            ["status"] = "failed",
            ["failureType"] = "etwXmlImport",
            ["exceptionType"] = exception.GetType().Name,
            ["message"] = exception.Message,
            ["sampleCorrelation"] = "unattributed",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true"
        }
    };

    private static SandboxEvent CreateLimitDiagnostic(string path, int limit) => new()
    {
        EventType = "etw.import.failed",
        Source = "etwLive",
        Path = path,
        Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etw-live-tracerpt",
            ["collectionHealth"] = "true",
            ["captureState"] = "failed",
            ["status"] = "failed",
            ["failureType"] = "etwXmlImportLimit",
            ["maxRows"] = limit.ToString(CultureInfo.InvariantCulture),
            ["sampleCorrelation"] = "unattributed",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true"
        }
    };

    private static string RelativeToEtwRoot(string path)
    {
        var marker = path.IndexOf("etw-traces", StringComparison.OrdinalIgnoreCase);
        return marker >= 0 ? path[marker..].Replace(Path.DirectorySeparatorChar, '/') : Path.GetFileName(path);
    }

    private static void ParseUnnamed(string text, Dictionary<string, string> payload)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        var matches = UnnamedPayloadFieldRegex.Matches(text);
        foreach (Match match in matches)
        {
            var key = Normalize(match.Groups["key"].Value);
            var value = match.Groups["value"].Value.Trim().TrimEnd(';', ',').Trim();
            if (!string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(value))
            {
                payload.TryAdd(key, value);
            }
        }

        if (matches.Count > 0)
        {
            return;
        }

        foreach (var chunk in text.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = chunk.IndexOf('=');
            if (separator <= 0) continue;
            payload.TryAdd(Normalize(chunk[..separator]), chunk[(separator + 1)..].Trim());
        }
    }

    private static string Normalize(string value) => value.Trim().Replace("_", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
    private static string Child(XElement? element, params string[] names) => element is null ? string.Empty : First(names.Select(name => element.Elements().FirstOrDefault(child => child.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value).ToArray());
    private static string First(params string?[] values) => values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;
    private static string Value(IReadOnlyDictionary<string, string> values, params string[] names) => First(names.Select(name => values.TryGetValue(Normalize(name), out var value) ? value : null).ToArray());
    private static int? ParsePid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(normalized[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hexPid) &&
            hexPid > 0)
        {
            return hexPid;
        }

        return int.TryParse(normalized, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) && pid > 0 ? pid : null;
    }
    /// <summary>
    /// Parses one tracerpt SystemTime value. A non-zero offset minute component
    /// is not a legal Windows time-zone offset and is normalized to the nearest
    /// whole hour; the caller records the anomaly and may apply a FILETIME
    /// correction from the trace header.
    /// </summary>
    private static DateTimeOffset? ParseTimestamp(string? value, out bool offsetAnomaly)
    {
        offsetAnomaly = false;
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        var match = SystemTimeOffsetRegex.Match(text);
        if (match.Success)
        {
            var minuteText = match.Groups["minute"].Value;
            if (!string.Equals(minuteText, "00", StringComparison.Ordinal))
            {
                offsetAnomaly = true;
                var hour = int.Parse(match.Groups["hour"].Value, CultureInfo.InvariantCulture);
                var minute = int.Parse(minuteText, CultureInfo.InvariantCulture);
                if (minute >= 30)
                {
                    hour++;
                }

                // A +23:5x anomaly rounds past the day boundary. Clamp rather
                // than throw; the header FILETIME correction still wins when
                // the trace provides one.
                hour = Math.Min(hour, 23);
                text = text[..match.Index] + match.Groups["sign"].Value + hour.ToString("00", CultureInfo.InvariantCulture) + ":00";
            }
        }

        return DateTimeOffset.TryParse(
            text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var timestamp)
            ? timestamp
            : null;
    }

    /// <summary>
    /// Derives an exact UTC correction from the EventTrace header FILETIME.
    /// Inputs are parsed XML events; processing compares the header StartTime
    /// (FILETIME) with the header SystemTime, and the method returns null when
    /// the trace has no usable anchor or the two already agree.
    /// </summary>
    private static TimeSpan? ResolveFileTimeCorrection(IReadOnlyList<XElement> events, out bool offsetAnomaly)
    {
        offsetAnomaly = false;
        DateTimeOffset? headerTimestamp = null;
        long? startFileTime = null;
        foreach (var element in events.Take(64))
        {
            var system = element.Elements().FirstOrDefault(child => child.Name.LocalName.Equals("System", StringComparison.OrdinalIgnoreCase));
            var rawTimestamp = system?.Elements()
                .FirstOrDefault(child => child.Name.LocalName.Equals("TimeCreated", StringComparison.OrdinalIgnoreCase))
                ?.Attribute("SystemTime")?.Value;
            var parsed = ParseTimestamp(rawTimestamp, out var anomaly);
            offsetAnomaly |= anomaly;
            if (parsed is null)
            {
                continue;
            }

            var startTimeText = element.Descendants()
                .Where(child => child.Name.LocalName.Equals("Data", StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault(child => string.Equals(child.Attribute("Name")?.Value, "StartTime", StringComparison.OrdinalIgnoreCase))
                ?.Value;
            if (!long.TryParse(startTimeText?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var fileTime) ||
                fileTime <= 0)
            {
                continue;
            }

            headerTimestamp = parsed;
            startFileTime = fileTime;
            break;
        }

        if (headerTimestamp is null || startFileTime is null)
        {
            return null;
        }

        try
        {
            var headerUtc = new DateTimeOffset(DateTime.FromFileTimeUtc(startFileTime.Value), TimeSpan.Zero);
            var delta = headerUtc - headerTimestamp.Value;
            return Math.Abs(delta.TotalSeconds) >= 1 ? delta : null;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static long ParseUnsigned(string? value) =>
        long.TryParse(value?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? parsed
            : 0;

    private static SandboxEvent CreateTimestampAnomaly(string path, TimeSpan? correction)
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etw-live-tracerpt",
            ["collectionHealth"] = "true",
            ["captureState"] = "degraded",
            ["status"] = "degraded",
            ["failureType"] = "etwTimestampOffsetAnomaly",
            ["diagnosticReason"] = "SystemTime offset minute component was not zero",
            ["etwTimestampCorrectionSeconds"] = correction?.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture) ?? "0",
            ["sampleCorrelation"] = "unattributed",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["eventKind"] = "diagnostic",
            ["evidenceRole"] = "collection-diagnostic",
            ["sourceComponent"] = "etw-live-tracerpt",
            ["zhMessage"] = "ETW 时间戳时区偏移的分钟位不为 0；已按文件内 FILETIME 校准，避免事件整体偏移。",
            ["zhHint"] = "检查来宾时区配置；时间戳偏移会导致父子进程时序判断错误。"
        };
        return new SandboxEvent
        {
            EventType = "etw.timestamp.offset_anomaly",
            Timestamp = DateTimeOffset.UtcNow,
            Source = "etwLive",
            Path = path,
            Data = data
        };
    }

    private static SandboxEvent CreateDecodeSummary(string path, int xmlEventCount, int importedCount, int skippedCount, long eventsLost)
    {
        var retention = xmlEventCount <= 0
            ? 0
            : (int)Math.Min(10000, importedCount * 10000L / xmlEventCount);
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["captureSource"] = "etw-live-tracerpt",
            ["collectionHealth"] = "true",
            ["captureState"] = "observed",
            ["status"] = "observed",
            ["xmlEventCount"] = xmlEventCount.ToString(CultureInfo.InvariantCulture),
            ["importedEventCount"] = importedCount.ToString(CultureInfo.InvariantCulture),
            ["skippedEventCount"] = skippedCount.ToString(CultureInfo.InvariantCulture),
            ["eventsLost"] = eventsLost.ToString(CultureInfo.InvariantCulture),
            ["decodeRetentionBasisPoints"] = retention.ToString(CultureInfo.InvariantCulture),
            ["sampleCorrelation"] = "unattributed",
            ["behaviorCounted"] = "false",
            ["nonbehavior"] = "true",
            ["notSampleBehavior"] = "true",
            ["eventKind"] = "diagnostic",
            ["evidenceRole"] = "collection-diagnostic",
            ["sourceComponent"] = "etw-live-tracerpt"
        };
        return new SandboxEvent
        {
            EventType = "etw.trace.decode_summary",
            Timestamp = DateTimeOffset.UtcNow,
            Source = "etwLive",
            Path = path,
            Data = data
        };
    }
}
