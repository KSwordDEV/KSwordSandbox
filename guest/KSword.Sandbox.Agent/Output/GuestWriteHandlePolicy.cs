namespace KSword.Sandbox.Agent.Output;

/// <summary>
/// Bounds guest-side write-handle pressure for shared-folder (HGFS/UNC)
/// output roots. Observed live as win32 1394 ERROR_NO_MORE_USER_HANDLES on
/// \\vmware-host\Shared Folders: redirector-backed handles that stay open for
/// a whole collection window eventually stop being creatable, and the failure
/// surfaces in the least helpful place (the final events.json write).
/// Inputs are process-wide policy constants; processing provides (1) a gate
/// that caps concurrent write handles across all artifact writers, and (2) a
/// registry of long-lived diagnostic handles that failure paths can force-
/// close before writing the small failure sidecar that must always land.
/// </summary>
internal static class GuestWriteHandlePolicy
{
    /// <summary>
    /// Upper bound on FileStream handles opened for writing artifacts at the
    /// same time. The dropped-file copier, artifact writer, and resilient
    /// retry paths all acquire this gate, so a burst of concurrent artifact
    /// writes cannot starve the redirector of handle budget.
    /// </summary>
    public const int MaxConcurrentWriteHandles = 4;

    private static readonly SemaphoreSlim WriteHandleGate = new(MaxConcurrentWriteHandles, MaxConcurrentWriteHandles);

    private static readonly object DiagnosticHandlesSync = new();

    private static readonly List<FileStream> OpenDiagnosticHandles = new();

    /// <summary>
    /// Acquires one write-handle slot. Callers wrap the open/write/close of a
    /// destination FileStream in the returned disposable so the slot is held
    /// exactly as long as the handle exists. Inputs are none; processing
    /// blocks while more than <see cref="MaxConcurrentWriteHandles"/> writes
    /// are open; the return releases the slot on Dispose.
    /// </summary>
    public static IDisposable AcquireWriteHandle()
    {
        WriteHandleGate.Wait();
        return new WriteHandleSlot(WriteHandleGate);
    }

    /// <summary>
    /// Tracks a long-lived diagnostic handle (R0 collector stdout/stderr
    /// sidecars) so a failure path can release it without waiting for the
    /// copy task to notice. Inputs are the open stream; processing stores it
    /// in the process-wide registry; the method returns no value.
    /// </summary>
    public static void RegisterDiagnosticHandle(FileStream stream)
    {
        lock (DiagnosticHandlesSync)
        {
            OpenDiagnosticHandles.Add(stream);
        }
    }

    /// <summary>
    /// Stops tracking a diagnostic handle that closed normally. Inputs are
    /// the stream being disposed; processing removes it from the registry;
    /// the method returns no value and never throws.
    /// </summary>
    public static void UnregisterDiagnosticHandle(FileStream stream)
    {
        lock (DiagnosticHandlesSync)
        {
            OpenDiagnosticHandles.Remove(stream);
        }
    }

    /// <summary>
    /// Force-closes every tracked long-lived diagnostic handle. Inputs are
    /// none; processing disposes each registered stream (pending copy tasks
    /// fault with ObjectDisposedException and are already annotated as failed
    /// by the drain logic); the method returns the number of handles closed.
    /// Failure sidecar writers call this first so their tiny write gets the
    /// full handle budget on an exhausted system.
    /// </summary>
    public static int ForceCloseDiagnosticHandles()
    {
        FileStream[] snapshot;
        lock (DiagnosticHandlesSync)
        {
            if (OpenDiagnosticHandles.Count == 0)
            {
                return 0;
            }

            snapshot = OpenDiagnosticHandles.ToArray();
            OpenDiagnosticHandles.Clear();
        }

        var closed = 0;
        foreach (var stream in snapshot)
        {
            try
            {
                stream.Dispose();
                closed++;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
            }
        }

        return closed;
    }

    private sealed class WriteHandleSlot : IDisposable
    {
        private readonly SemaphoreSlim gate;
        private bool released;

        public WriteHandleSlot(SemaphoreSlim gate)
        {
            this.gate = gate;
        }

        public void Dispose()
        {
            if (released)
            {
                return;
            }

            released = true;
            gate.Release();
        }
    }
}
