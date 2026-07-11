using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Optionally captures a best-effort minidump for the launched sample process.
/// Inputs are the after-start probe phase, root process ID, and an explicit
/// CLI opt-in flag; processing delegates to a platform capture implementation;
/// CollectAsync returns memory_dump.captured or memory_dump.skipped events.
/// </summary>
internal sealed class MemoryDumpProbe : IGuestProbe
{
    private readonly IProcessMemoryDumpCapture dumpCapture;

    public MemoryDumpProbe()
        : this(new WindowsMiniDumpCapture())
    {
    }

    /// <summary>
    /// Creates a memory dump probe with an injectable capture implementation.
    /// The input is a dump capture service, processing stores it for future
    /// phases, and the constructor returns no value.
    /// </summary>
    public MemoryDumpProbe(IProcessMemoryDumpCapture dumpCapture)
    {
        this.dumpCapture = dumpCapture;
    }

    public string ProbeId => "memory-dump";

    /// <summary>
    /// Captures one opt-in minidump while the sample process is running.
    /// Inputs are phase, guest context, and cancellation token; processing skips
    /// by default and only writes a dump for AfterStart when a root PID exists;
    /// the method returns one diagnostic event for enabled attempts.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (!context.CaptureMemoryDump || phase is not ProbePhase.AfterStart)
        {
            return [];
        }

        var phaseLabel = ToPhaseLabel(phase);
        var result = context.RootProcessId is null
            ? MemoryDumpCaptureResult.Skipped(
                "Sample root process ID is not available for memory dump capture.",
                processId: null,
                diagnosticStage: "root-process")
            : await dumpCapture.CaptureAsync(context.OutputDirectory, context.RootProcessId.Value, phaseLabel, cancellationToken);

        var evt = new SandboxEvent
        {
            EventType = result.Captured ? "memory_dump.captured" : "memory_dump.skipped",
            Source = "guest",
            Path = result.Path,
            ProcessId = result.ProcessId,
            Data =
            {
                ["phase"] = phaseLabel,
                ["captureEnabled"] = "true",
                ["captureState"] = result.Captured ? "captured" : "skipped",
                ["dumpType"] = result.DumpType,
                ["evidenceRole"] = "memory-dump",
                ["collectionName"] = "memory-dumps"
            }
        };

        AddOptionalData(evt, "reason", result.Reason);
        AddOptionalData(evt, "exceptionType", result.ExceptionType);
        AddOptionalData(evt, "diagnosticStage", result.DiagnosticStage);

        if (result.ProcessId is not null)
        {
            evt.Data["processId"] = result.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (result.Win32Error is not null)
        {
            evt.Data["win32Error"] = result.Win32Error.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (result.SizeBytes is not null)
        {
            evt.Data["sizeBytes"] = result.SizeBytes.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (!string.IsNullOrWhiteSpace(result.Path))
        {
            evt.Data["relativePath"] = SafeRelativePath(context.OutputDirectory, result.Path);
        }

        return [evt];
    }

    private static void AddOptionalData(SandboxEvent evt, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            evt.Data[key] = value;
        }
    }

    /// <summary>
    /// Converts probe phases to stable artifact labels.
    /// Inputs are enum values; processing maps known phases; the method returns
    /// a lowercase label for filenames and event data.
    /// </summary>
    private static string ToPhaseLabel(ProbePhase phase)
    {
        return phase switch
        {
            ProbePhase.AfterStart => "after-start",
            ProbePhase.AfterRun => "after-run",
            ProbePhase.BeforeStart => "before-start",
            ProbePhase.Cleanup => "cleanup",
            _ => phase.ToString()
        };
    }

    /// <summary>
    /// Computes a display relative path without trusting rooted input.
    /// Inputs are output root and artifact path; processing normalizes
    /// separators and falls back to the original path on malformed input.
    /// </summary>
    private static string SafeRelativePath(string root, string path)
    {
        try
        {
            return Path.GetRelativePath(root, path).Replace('\\', '/');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            return path;
        }
    }
}

/// <summary>
/// Defines a process memory dump capture implementation.
/// Inputs are output directory, target PID, phase label, and cancellation token;
/// processing writes or skips a dump artifact; CaptureAsync returns capture
/// metadata for event emission.
/// </summary>
internal interface IProcessMemoryDumpCapture
{
    Task<MemoryDumpCaptureResult> CaptureAsync(
        string outputDirectory,
        int processId,
        string phase,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures a Windows MiniDumpNormal file for a target process.
/// Inputs are output directory, PID, and phase; processing uses DbgHelp
/// MiniDumpWriteDump and writes memory-dumps/*.dmp; CaptureAsync returns
/// success metadata or a skipped result when capture is unavailable.
/// </summary>
internal sealed class WindowsMiniDumpCapture : IProcessMemoryDumpCapture
{
    private const string DumpDirectoryName = "memory-dumps";

    /// <summary>
    /// Captures a process minidump if the platform and access rights permit it.
    /// Inputs are output directory, target process ID, phase, and cancellation
    /// token; processing writes one .dmp file; the method returns capture
    /// metadata or a skipped diagnostic.
    /// </summary>
    public Task<MemoryDumpCaptureResult> CaptureAsync(
        string outputDirectory,
        int processId,
        string phase,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                "Memory dump capture is only implemented on Windows.",
                processId,
                diagnosticStage: "platform-check"));
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited)
            {
                return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                    "Sample process exited before memory dump capture.",
                    processId,
                    diagnosticStage: "process-state"));
            }

            var dumpDirectory = Path.Combine(outputDirectory, DumpDirectoryName);
            Directory.CreateDirectory(dumpDirectory);
            var safePhase = phase.Replace(' ', '-');
            var path = Path.Combine(dumpDirectory, $"{safePhase}-pid{processId}-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.dmp");
            var sizeBytes = WriteMiniDump(process, path, cancellationToken);
            return Task.FromResult(MemoryDumpCaptureResult.Success(path, processId, MiniDumpType.MiniDumpNormal.ToString(), sizeBytes));
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                "Sample process was not found for memory dump capture.",
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "process-lookup"));
        }
        catch (MemoryDumpCaptureException ex)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                ex.Message,
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                ex.Stage,
                ex.Win32Error));
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException or NotSupportedException or DllNotFoundException or EntryPointNotFoundException)
        {
            return Task.FromResult(MemoryDumpCaptureResult.Skipped(
                ex.Message,
                processId,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "capture"));
        }
    }

    /// <summary>
    /// Writes the minidump file through DbgHelp.
    /// Inputs are a target process, output path, and cancellation token;
    /// processing creates the dump file and removes partial output on failure;
    /// the method returns the final byte length.
    /// </summary>
    private static long WriteMiniDump(Process process, string path, CancellationToken cancellationToken)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 4096);
            cancellationToken.ThrowIfCancellationRequested();
            if (!MiniDumpWriteDump(
                    process.Handle,
                    process.Id,
                    stream.SafeFileHandle.DangerousGetHandle(),
                    MiniDumpType.MiniDumpNormal,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw MemoryDumpCaptureException.ForLastPInvokeError(
                    "MiniDumpWriteDump",
                    "MiniDumpWriteDump failed while capturing the sample process.");
            }

            stream.Flush(flushToDisk: true);
            return stream.Length;
        }
        catch
        {
            TryDeleteFile(path);
            throw;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Preserve the original capture failure as the diagnostic event.
        }
    }

    [DllImport("dbghelp.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int processId,
        IntPtr hFile,
        MiniDumpType dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);

    [Flags]
    private enum MiniDumpType
    {
        MiniDumpNormal = 0x00000000
    }
}

/// <summary>
/// Carries memory dump capture failure diagnostics from the platform-specific
/// implementation. Inputs are a capture stage, message, and Win32 error code;
/// processing is immutable exception storage; records are converted into
/// memory_dump.skipped event Data.
/// </summary>
internal sealed class MemoryDumpCaptureException : InvalidOperationException
{
    public MemoryDumpCaptureException(string stage, string message, int win32Error)
        : base(message)
    {
        Stage = stage;
        Win32Error = win32Error;
    }

    public string Stage { get; }

    public int Win32Error { get; }

    /// <summary>
    /// Creates a memory dump exception using the last P/Invoke error code.
    /// Inputs are capture stage and message; processing reads the thread-local
    /// P/Invoke error; the method returns a MemoryDumpCaptureException.
    /// </summary>
    public static MemoryDumpCaptureException ForLastPInvokeError(string stage, string message)
    {
        return new MemoryDumpCaptureException(stage, message, Marshal.GetLastPInvokeError());
    }
}

/// <summary>
/// Describes the result of one memory dump attempt.
/// Inputs are capture outcome details; processing is immutable storage; records
/// are returned by IProcessMemoryDumpCapture and converted into SandboxEvent
/// data.
/// </summary>
internal sealed record MemoryDumpCaptureResult(
    bool Captured,
    string? Path,
    int? ProcessId,
    string DumpType,
    long? SizeBytes,
    string? Reason,
    string? ExceptionType,
    string? DiagnosticStage,
    int? Win32Error)
{
    /// <summary>
    /// Creates a successful memory dump result.
    /// Inputs are artifact path, process ID, dump type, and byte length;
    /// processing stores success metadata; the method returns a result record.
    /// </summary>
    public static MemoryDumpCaptureResult Success(string path, int processId, string dumpType, long sizeBytes)
    {
        return new MemoryDumpCaptureResult(true, path, processId, dumpType, sizeBytes, null, null, null, null);
    }

    /// <summary>
    /// Creates a skipped memory dump result.
    /// Inputs are skip reason, process ID, optional exception type, diagnostic
    /// stage, and Win32 error; processing stores diagnostic metadata; the method
    /// returns a result record.
    /// </summary>
    public static MemoryDumpCaptureResult Skipped(
        string reason,
        int? processId,
        string? exceptionType = null,
        string? diagnosticStage = null,
        int? win32Error = null)
    {
        return new MemoryDumpCaptureResult(false, null, processId, MiniDumpTypeName, null, reason, exceptionType, diagnosticStage, win32Error);
    }

    private const string MiniDumpTypeName = "MiniDumpNormal";
}
