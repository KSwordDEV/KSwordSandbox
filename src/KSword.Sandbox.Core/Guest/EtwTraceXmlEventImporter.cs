using System.Globalization;
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
            var task = Child(rendering, "Task", "TaskName");
            var opcode = First(Child(rendering, "Opcode", "Operation"), Child(system, "Opcode", "Operation"));
            var eventId = Child(system, "EventID", "EventId", "Id");
            var eventName = First(Child(rendering, "EventName", "Name"), task, opcode, provider + ":" + eventId);
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
            var image = Value(payload, "imagefilename", "imagename", "processname", "image", "process");
            var commandLine = Value(payload, "commandline", "command");
            var pathValue = Value(payload, "filename", "file", "path", "imagepath", "keyname", "keypath", "objectname");
            var type = MapType(eventName, provider, task, opcode, payload);
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
        type is "process.start" or "process.exit" or "image.load" or "image.unload" or "thread.start" or "thread.exit" or "registry.etw" ||
        type.StartsWith("file.", StringComparison.OrdinalIgnoreCase) ||
        type.StartsWith("network.", StringComparison.OrdinalIgnoreCase);

    private static string MapType(string name, string provider, string task, string opcode, IReadOnlyDictionary<string, string> payload)
    {
        var value = (name + " " + provider + " " + task + " " + opcode).ToLowerInvariant();
        if (value.Contains("process", StringComparison.Ordinal) && (value.Contains("start", StringComparison.Ordinal) || value.Contains("create", StringComparison.Ordinal) || value.Contains("dcstart", StringComparison.Ordinal))) return "process.start";
        if (value.Contains("process", StringComparison.Ordinal) && (value.Contains("stop", StringComparison.Ordinal) || value.Contains("exit", StringComparison.Ordinal) || value.Contains("end", StringComparison.Ordinal) || value.Contains("dcexit", StringComparison.Ordinal) || value.Contains("terminate", StringComparison.Ordinal) || value.Contains("defunct", StringComparison.Ordinal))) return "process.exit";
        if (value.Contains("image", StringComparison.Ordinal) && (value.Contains("unload", StringComparison.Ordinal) || value.Contains("dcend", StringComparison.Ordinal))) return "image.unload";
        if (value.Contains("image", StringComparison.Ordinal) && (value.Contains("load", StringComparison.Ordinal) || value.Contains("start", StringComparison.Ordinal) || value.Contains("dcstart", StringComparison.Ordinal))) return "image.load";
        if (value.Contains("thread", StringComparison.Ordinal) && (value.Contains("start", StringComparison.Ordinal) || value.Contains("dcstart", StringComparison.Ordinal))) return "thread.start";
        if (value.Contains("thread", StringComparison.Ordinal) && (value.Contains("stop", StringComparison.Ordinal) || value.Contains("end", StringComparison.Ordinal) || value.Contains("exit", StringComparison.Ordinal) || value.Contains("dcexit", StringComparison.Ordinal))) return "thread.exit";
        if (value.Contains("file", StringComparison.Ordinal) || value.Contains("fileio", StringComparison.Ordinal)) return "file.etw";
        if (value.Contains("network", StringComparison.Ordinal) || value.Contains("tcp", StringComparison.Ordinal)) return "network.etw";
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
