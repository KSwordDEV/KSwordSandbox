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
            imported.AddRange(Import(guestOutputRoot));
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

    public static IReadOnlyList<SandboxEvent> Import(string? guestOutputRoot)
    {
        if (string.IsNullOrWhiteSpace(guestOutputRoot) || !Directory.Exists(guestOutputRoot)) return [];
        var rows = new List<SandboxEvent>();
        foreach (var path in EnumerateXml(guestOutputRoot))
        {
            try
            {
                var parsed = Parse(path);
                rows.AddRange(parsed);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
            {
                rows.Add(CreateFailure(path, ex));
            }
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
        var rows = new List<SandboxEvent>();
        foreach (var element in document.Descendants().Where(element => element.Name.LocalName.Equals("Event", StringComparison.OrdinalIgnoreCase)))
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
            var timestamp = ParseTimestamp(system.Elements().FirstOrDefault(child => child.Name.LocalName.Equals("TimeCreated", StringComparison.OrdinalIgnoreCase))?.Attribute("SystemTime")?.Value) ?? DateTimeOffset.UtcNow;
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
            var image = Value(payload, "imagefilename", "imagename", "processname", "image", "process");
            var commandLine = Value(payload, "commandline", "command");
            var pathValue = Value(payload, "filename", "file", "path", "imagepath", "keyname", "keypath", "objectname");
            var type = MapType(eventName, provider, task, opcode, payload, eventId);
            if (!IsUsefulType(type))
            {
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
            if (rows.Count >= MaxRowsPerTrace)
            {
                rows.Add(CreateLimitDiagnostic(path, MaxRowsPerTrace));
                break;
            }
        }
        return rows;
    }

    private static bool IsUsefulType(string type) =>
        type is "process.start" or "process.exit" or "process.event" or "image.load" or "image.unload" or "thread.start" or "thread.exit" or "thread.event" or "registry.etw" ||
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
    private static DateTimeOffset? ParseTimestamp(string? value) => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var timestamp) ? timestamp : null;
}
