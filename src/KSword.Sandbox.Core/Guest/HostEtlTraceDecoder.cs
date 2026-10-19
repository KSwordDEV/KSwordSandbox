using System.Diagnostics;
using System.Globalization;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Guest;

/// <summary>
/// Decodes a raw ETW kernel trace on the host when the Guest Agent was killed
/// before it could run its own tracerpt pass.
///
/// The guest decoder is the primary path: the Agent owns the ETL while it is
/// still alive and turns it into semantic rows inside events.json. When a
/// sample terminates the Agent (Petya overwrites the boot path and the machine
/// stops responding, WannaCry-style wipers take the collector down with the
/// session) that primary path never runs. The ETL still reaches the host
/// through the VMware shared-folder evidence channel, but without a host-side
/// decoder the report shows zero dynamic evidence even though the trace holds
/// every process/image/thread edge the sample produced.
///
/// This importer is deliberately a last resort:
///   - it never runs when the guest stream already contains decoded rows, so a
///     healthy Agent cannot get a second full-machine trace appended;
///   - it decodes into a host-side scratch folder rather than into the guest
///     tree, so recovery output can never be mistaken for captured evidence;
///   - every decode is bounded (size, wall-clock, process tree kill) and every
///     failure becomes an explicit collection diagnostic rather than silence.
/// </summary>
public static class HostEtlTraceDecoder
{
    /// <summary>Host scratch folder for decoded traces. Never under etw-traces.</summary>
    public const string DecodeDirectoryName = "host-etl-decode";

    private const long MaxEtlBytes = 512L * 1024 * 1024;
    private const int MaxTracesPerJob = 8;

    /// <summary>
    /// Returns host-decoded rows for any ETL under <paramref name="guestRoot"/>
    /// that the guest did not already decode, plus one explicit diagnostic per
    /// trace that could not be recovered.
    ///
    /// The same <see cref="EtwTraceXmlEventImporter.HasDecodedRows"/> gate the
    /// XML fallback uses is applied first: if the Agent already produced
    /// semantic rows there is nothing to recover.
    /// </summary>
    public static IReadOnlyList<SandboxEvent> ImportFallback(
        IReadOnlyCollection<SandboxEvent> existingEvents,
        string? guestRoot,
        string? scratchRoot = null)
    {
        if (EtwTraceXmlEventImporter.HasDecodedRows(existingEvents))
        {
            return [];
        }

        if (string.IsNullOrWhiteSpace(guestRoot) || !SafeDirectoryExists(guestRoot))
        {
            return [];
        }

        var traces = EnumerateEtl(guestRoot);
        if (traces.Count == 0)
        {
            return [];
        }

        var target = string.IsNullOrWhiteSpace(scratchRoot)
            ? Path.Combine(guestRoot, DecodeDirectoryName)
            : Path.Combine(scratchRoot, DecodeDirectoryName);

        var rows = new List<SandboxEvent>();
        foreach (var trace in traces.Take(MaxTracesPerJob))
        {
            rows.AddRange(DecodeOne(trace, target));
        }

        if (traces.Count > MaxTracesPerJob)
        {
            rows.Add(CreateDiagnostic(
                traces[MaxTracesPerJob],
                "host-etl-decode-limit",
                decodedCount: 0,
                message: $"Host ETW decode stopped after {MaxTracesPerJob} traces; {traces.Count - MaxTracesPerJob} additional trace(s) were not decoded."));
        }

        return rows;
    }

    private static IReadOnlyList<SandboxEvent> DecodeOne(string etlPath, string decodeDirectory)
    {
        // A decode already on disk from an earlier import of this job folder is
        // reused. Re-running tracerpt over the same trace would duplicate rows
        // and burn minutes of host CPU for nothing. A cache older than its
        // trace is stale (the capture was replaced) and must be redone.
        var decodedPath = Path.Combine(decodeDirectory, Path.GetFileNameWithoutExtension(etlPath) + ".hostdecoded.xml");
        if (File.Exists(decodedPath) && new FileInfo(decodedPath).Length > 0)
        {
            try
            {
                if (new FileInfo(decodedPath).LastWriteTimeUtc >= new FileInfo(etlPath).LastWriteTimeUtc)
                {
                    return EtwTraceXmlEventImporter.ImportXmlFile(decodedPath);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Fall through and re-decode from the trace itself.
            }
        }

        long etlLength;
        try
        {
            etlLength = new FileInfo(etlPath).Length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-stat-failed", 0, $"Host could not read the ETW trace: {ex.Message}")];
        }

        if (etlLength <= 0)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-empty", 0, "Host ETW decode skipped because the captured trace is empty.")];
        }

        if (etlLength > MaxEtlBytes)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-too-large", 0,
                $"Host ETW decode skipped: trace is {etlLength} bytes, above the {MaxEtlBytes}-byte host limit.")];
        }

        string tracerpt;
        try
        {
            tracerpt = ResolveTracerpt();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-unavailable", 0,
                $"Host ETW decode is unavailable: {ex.Message}")];
        }

        try
        {
            Directory.CreateDirectory(decodeDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-scratch-failed", 0,
                $"Host ETW decode could not create its scratch folder: {ex.Message}")];
        }

        (bool Succeeded, string Output) run;
        try
        {
            run = RunTracerpt(tracerpt, etlPath, decodedPath);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-launch-failed", 0,
                $"Host ETW decode could not start tracerpt: {ex.Message}")];
        }

        if (!run.Succeeded || !File.Exists(decodedPath) || new FileInfo(decodedPath).Length == 0)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-failed", 0,
                $"Host ETW decode produced no XML. tracerpt output: {run.Output}")];
        }

        // tracerpt expands a kernel ETL by roughly an order of magnitude. Drop
        // an oversized dump before XDocument tries to load it into memory.
        var decodedLength = new FileInfo(decodedPath).Length;
        if (decodedLength > EtwTraceXmlEventImporter.XmlImportLimitBytes)
        {
            TryDelete(decodedPath);
            return [CreateDiagnostic(etlPath, "host-etl-decode-xml-too-large", 0,
                $"Host ETW decode produced {decodedLength} bytes of XML, above the {EtwTraceXmlEventImporter.XmlImportLimitBytes}-byte import limit; the dump was discarded instead of being loaded.")];
        }

        var decoded = EtwTraceXmlEventImporter.ImportXmlFile(decodedPath);
        if (decoded.Count == 0)
        {
            return [CreateDiagnostic(etlPath, "host-etl-decode-no-semantic-rows", 0,
                "Host ETW decode produced XML but no process/image/thread/file/network rows could be extracted.")];
        }

        return decoded;
    }

    /// <summary>
    /// Runs tracerpt with a bounded wall clock. Inputs are the tool, trace and
    /// output paths; processing returns success plus captured output and always
    /// leaves no tracerpt process behind.
    /// </summary>
    private static (bool Succeeded, string Output) RunTracerpt(string tracerpt, string etlPath, string decodedPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = tracerpt,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        // -lr keeps rows whose payload does not match the manifest schema. The
        // guest decoder uses the same switch; without it a kernel trace loses
        // the very rows this recovery path exists to recover.
        foreach (var argument in new[] { etlPath, "-o", decodedPath, "-of", "XML", "-y", "-lr" })
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("tracerpt did not start.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();

        // A hostile sample can wedge a decoder process. Bound the wait and take
        // the whole tree down rather than letting the host accumulate orphans.
        if (!process.WaitForExit((int)TimeSpan.FromMinutes(5).TotalMilliseconds))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
            {
                // The process already exited between the timeout and the kill.
            }

            return (false, "tracerpt exceeded the 5-minute host decode budget and was terminated.");
        }

        var combined = string.Join(' ', new[] { output, error }.Where(part => !string.IsNullOrWhiteSpace(part)));
        return (process.ExitCode == 0, combined.Length > 400 ? combined[..400] : combined);
    }

    private static string ResolveTracerpt()
    {
        foreach (var candidate in new[]
                 {
                     Path.Combine(Environment.SystemDirectory, "tracerpt.exe"),
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "tracerpt.exe")
                 })
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            "tracerpt.exe was not found in the host System32 directory, so a raw ETW trace cannot be decoded on the host.");
    }

    /// <summary>
    /// Returns ETL traces under any etw-traces folder in the guest tree.
    /// Inputs are the guest root; processing returns the traces ordered by
    /// name so a decode is deterministic.
    /// </summary>
    private static IReadOnlyList<string> EnumerateEtl(string guestRoot)
    {
        try
        {
            return Directory.EnumerateFiles(guestRoot, "*.etl", SearchOption.AllDirectories)
                .Where(path => path.Contains("etw-traces", StringComparison.OrdinalIgnoreCase))
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            return [];
        }
    }

    /// <summary>
    /// Builds one explicit recovery diagnostic. Inputs are the trace, a stable
    /// failure type and a message; processing returns a non-behavior row so
    /// the report explains the gap instead of implying a clean capture.
    /// </summary>
    private static SandboxEvent CreateDiagnostic(string etlPath, string failureType, int decodedCount, string message)
    {
        long sizeBytes = 0;
        try
        {
            sizeBytes = new FileInfo(etlPath).Length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            sizeBytes = 0;
        }

        return new SandboxEvent
        {
            EventType = "etw.host_decode.failed",
            Timestamp = DateTimeOffset.UtcNow,
            Source = "host",
            Path = etlPath,
            Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["captureSource"] = "etw-host-tracerpt",
                ["collectionHealth"] = "true",
                ["captureState"] = "failed",
                ["status"] = "failed",
                ["failureType"] = failureType,
                ["traceArtifactPath"] = etlPath,
                ["traceSizeBytes"] = sizeBytes.ToString(CultureInfo.InvariantCulture),
                ["decodedRowCount"] = decodedCount.ToString(CultureInfo.InvariantCulture),
                ["etlDecodeRequired"] = "true",
                ["semanticRowsAvailable"] = "false",
                ["message"] = message,
                ["sampleCorrelation"] = "unattributed",
                ["sampleCorrelationStatus"] = "unattributed",
                ["sampleCorrelationStrength"] = "none",
                ["behaviorCounted"] = "false",
                ["nonbehavior"] = "true",
                ["notSampleBehavior"] = "true",
                ["eventKind"] = "diagnostic",
                ["evidenceRole"] = "collection-diagnostic",
                ["sourceComponent"] = "etw-host-tracerpt",
                ["zhMessage"] = "宿主未能从原始 ETW 追踪中恢复行为行。",
                ["zhHint"] = "这是明确的采集缺口：请检查宿主 tracerpt 是否可用，或改用已解码的 events.json 作为证据来源。"
            }
        };
    }

    private static bool SafeDirectoryExists(string path)
    {
        try
        {
            return Directory.Exists(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A leftover scratch file is harmless; the next import reuses it only
            // when it is non-empty and within the import limit.
        }
    }
}