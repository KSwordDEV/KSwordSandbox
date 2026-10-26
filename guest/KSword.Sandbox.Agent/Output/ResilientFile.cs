using System.Runtime.InteropServices;
using System.Text;

namespace KSword.Sandbox.Agent.Output;

/// <summary>
/// Resilient guest-side artifact writes for UNC/shared-folder output roots.
/// HGFS and similar redirected file systems can transiently fail an append or
/// create with handle-exhaustion or sharing-violation class errors (observed
/// live as win32 1394 ERROR_NO_MORE_USER_HANDLES / errno 22 on
/// \\vmware-host\Shared Folders).  Every helper here closes and reopens a fresh
/// handle per attempt, writes through a per-process temporary file, and only
/// publishes the artifact by rename once a complete write succeeded, so a
/// retried write never loses previously accepted bytes or imports a torn file.
/// </summary>
internal static class ResilientFile
{
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromMilliseconds(250),
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(3)
    ];

    /// <summary>
    /// Writes text with bounded reopen-and-retry.  Each attempt creates a new
    /// temporary file and a fresh FileStream (FileShare.Read only); the final
    /// path is replaced atomically by rename, so readers never observe a
    /// partially written artifact.
    /// </summary>
    public static void WriteAllTextWithRetry(string path, string contents)
    {
        WriteAllBytesWithRetry(path, Encoding.UTF8.GetBytes(contents));
    }

    /// <summary>
    /// Writes bytes with bounded reopen-and-retry using the same temporary
    /// file plus atomic rename contract as WriteAllTextWithRetry.
    /// </summary>
    public static void WriteAllBytesWithRetry(string path, byte[] bytes)
    {
        WriteWithRetry(path, static (stream, payload) => stream.Write(payload), bytes);
    }

    /// <summary>
    /// Streams a serialized artifact with bounded reopen-and-retry.  Inputs are
    /// the final path and a serialization callback; processing gives the
    /// callback a fresh FileStream per attempt, so a mid-stream IOException
    /// (handle exhaustion, sharing violation, short write surfaced as an
    /// exception) restarts the whole serialization from scratch instead of
    /// leaving a truncated file or dropping already buffered rows.
    /// </summary>
    public static void WriteStreamWithRetry(string path, Action<Stream> write)
    {
        WriteWithRetry(path, static (stream, callback) => callback(stream), write);
    }

    private static void WriteWithRetry<TPayload>(string path, Action<FileStream, TPayload> write, TPayload payload)
    {
        var temporaryPath = path + ".tmp." + Guid.NewGuid().ToString("N");
        try
        {
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    // The write-handle slot is held for exactly the lifetime
                    // of the destination handle, so concurrent artifact
                    // writers cannot exhaust the redirector handle budget.
                    using (GuestWriteHandlePolicy.AcquireWriteHandle())
                    using (var stream = new FileStream(
                        temporaryPath,
                        FileMode.Create,
                        FileAccess.Write,
                        FileShare.Read,
                        bufferSize: 64 * 1024,
                        FileOptions.WriteThrough))
                    {
                        write(stream, payload);
                        stream.Flush(flushToDisk: true);
                    }

                    File.Move(temporaryPath, path, overwrite: true);
                    return;
                }
                catch (Exception ex) when (IsRetryableOutputException(ex) && attempt < RetryDelays.Length)
                {
                    TryDelete(temporaryPath);
                    Thread.Sleep(RetryDelays[attempt]);
                }
            }
        }
        finally
        {
            TryDelete(temporaryPath);
        }
    }

    /// <summary>
    /// Decides whether a write failure is worth reopening the handle for.
    /// Inputs are the caught exception; processing accepts IO failures
    /// (including win32-error HResults such as 0x80070572 for 1394) and
    /// rejects argument/permission failures that a fresh handle cannot fix.
    /// </summary>
    public static bool IsRetryableOutputException(Exception exception)
    {
        return exception is IOException;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>
/// Space-availability check for guest output directories with an explicit
/// UNC/HGFS degradation path.  The legacy DriveInfo probe fails on UNC output
/// roots, which previously left failure diagnostics with spaceCheckAvailable
/// false and zeroed byte counts.  This probe first queries
/// GetDiskFreeSpaceEx (UNC-capable), then falls back to a 1 MiB write probe,
/// and always returns the method actually used so failure artifacts stay
/// interpretable.
/// </summary>
internal static class OutputSpaceProbe
{
    public const long ProbeBytes = 1024 * 1024;

    /// <summary>Method name when GetDiskFreeSpaceEx returned a real byte count.</summary>
    public const string DiskFreeMethod = "GetDiskFreeSpaceEx";

    /// <summary>Method name when only the 1 MiB write probe succeeded.</summary>
    public const string WriteProbeMethod = "write-probe-1mb";

    public sealed record Result(
        bool SpaceCheckAvailable,
        long? AvailableFreeBytes,
        string Method,
        string? Error);

    /// <summary>
    /// True only when AvailableFreeBytes is a real measured byte count; the
    /// write-probe fallback reports a verified lower bound instead, which must
    /// never be compared against a required-bytes estimate.
    /// </summary>
    public static bool HasMeasuredFreeBytes(Result result)
    {
        return result.SpaceCheckAvailable &&
            string.Equals(result.Method, DiskFreeMethod, StringComparison.Ordinal) &&
            result.AvailableFreeBytes is not null;
    }

    public static Result Query(string directory, long requiredBytes)
    {
        if (TryQueryDiskFreeSpaceEx(directory, out var available, out var getDiskError))
        {
            return new Result(true, available, DiskFreeMethod, getDiskError);
        }

        if (TryWriteProbe(directory, out var probeError))
        {
            // The probe cannot measure the true volume size, but it proves at
            // least ProbeBytes are writable right now.  Reporting the verified
            // bound plus the method keeps the failure artifact truthful.
            return new Result(true, ProbeBytes, WriteProbeMethod, null);
        }

        return new Result(false, null, "unavailable", CombineErrors(getDiskError, probeError));
    }

    private static bool TryQueryDiskFreeSpaceEx(string directory, out long availableBytes, out string? error)
    {
        availableBytes = 0;
        error = null;
        try
        {
            var fullDirectory = Path.GetFullPath(directory);
            if (!Directory.Exists(fullDirectory))
            {
                error = $"directory-not-found: {fullDirectory}";
                return false;
            }

            if (!GetDiskFreeSpaceEx(fullDirectory, out var freeToCaller, out _, out _))
            {
                error = $"GetDiskFreeSpaceEx failed: win32 {Marshal.GetLastWin32Error()}";
                return false;
            }

            availableBytes = freeToCaller;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            error = $"GetDiskFreeSpaceEx exception: {ex.Message}";
            return false;
        }
    }

    private static bool TryWriteProbe(string directory, out string? error)
    {
        error = null;
        var probePath = Path.Combine(directory, ".ksword-space-probe-" + Guid.NewGuid().ToString("N") + ".tmp");
        var buffer = new byte[64 * 1024];
        try
        {
            using (var stream = new FileStream(
                probePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 1,
                FileOptions.WriteThrough))
            {
                for (var written = 0L; written < ProbeBytes; written += buffer.Length)
                {
                    stream.Write(buffer, 0, buffer.Length);
                }

                stream.Flush(flushToDisk: true);
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error = $"write-probe failed after 1mb attempt: {ex.Message}";
            return false;
        }
        finally
        {
            try
            {
                if (File.Exists(probePath))
                {
                    File.Delete(probePath);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static string? CombineErrors(string? first, string? second)
    {
        return string.IsNullOrWhiteSpace(first) ? second : string.IsNullOrWhiteSpace(second) ? first : $"{first}; {second}";
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool GetDiskFreeSpaceEx(
        string lpDirectoryName,
        out long lpFreeBytesAvailableToCaller,
        out long lpTotalNumberOfBytes,
        out long lpTotalNumberOfFreeBytes);
}

/// <summary>
/// Marker type kept for the Win32 error annotation used by callers that embed
/// space-probe outcomes into failure sidecars (for example
/// "win32 1394 ERROR_NO_MORE_USER_HANDLES").
/// </summary>
internal static class Win32ErrorText
{
    public static string Describe(int win32Error)
    {
        return win32Error switch
        {
            1394 => $"win32 {win32Error} (ERROR_NO_MORE_USER_HANDLES)",
            _ => $"win32 {win32Error} ({new System.ComponentModel.Win32Exception(win32Error).Message})"
        };
    }
}
