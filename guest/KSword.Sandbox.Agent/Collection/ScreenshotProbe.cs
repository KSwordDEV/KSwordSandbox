using System.Globalization;
using System.Runtime.InteropServices;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Agent.Collection;

/// <summary>
/// Optionally captures guest desktop screenshots around sample execution.
/// Inputs are probe phases and a capture-enabled flag from CLI options;
/// processing delegates platform-specific capture to IScreenshotCapture;
/// CollectAsync returns screenshot.captured or screenshot.skipped events.
/// </summary>
internal sealed class ScreenshotProbe : IGuestProbe
{
    private readonly IScreenshotCapture screenshotCapture;

    public ScreenshotProbe()
        : this(new WindowsDesktopScreenshotCapture())
    {
    }

    /// <summary>
    /// Creates a screenshot probe with an injectable capture implementation.
    /// The input is a screenshot capture service, processing stores it for
    /// future probe phases, and the constructor returns no value.
    /// </summary>
    public ScreenshotProbe(IScreenshotCapture screenshotCapture)
    {
        this.screenshotCapture = screenshotCapture;
    }

    public string ProbeId => "screenshot";

    /// <summary>
    /// Captures screenshots for enabled after-start and after-run phases.
    /// Inputs are phase, guest context, and cancellation token; processing skips
    /// capture when disabled or outside the selected phases; the method returns
    /// screenshot events for enabled attempts.
    /// </summary>
    public async Task<IReadOnlyList<SandboxEvent>> CollectAsync(
        ProbePhase phase,
        GuestProbeContext context,
        CancellationToken cancellationToken = default)
    {
        if (!context.CaptureScreenshots || phase is not (ProbePhase.AfterStart or ProbePhase.AfterRun))
        {
            return [];
        }

        var phaseLabel = ToPhaseLabel(phase);
        var result = await screenshotCapture.CaptureAsync(context.OutputDirectory, phaseLabel, cancellationToken);
        var evt = new SandboxEvent
        {
            EventType = result.Captured ? "screenshot.captured" : "screenshot.skipped",
            Source = "guest",
            Path = result.Path,
            Data =
            {
                ["phase"] = phaseLabel,
                ["captureEnabled"] = "true"
            }
        };

        if (!string.IsNullOrWhiteSpace(result.Reason))
        {
            evt.Data["reason"] = result.Reason;
        }

        if (!string.IsNullOrWhiteSpace(result.ExceptionType))
        {
            evt.Data["exceptionType"] = result.ExceptionType;
        }

        if (!string.IsNullOrWhiteSpace(result.DiagnosticStage))
        {
            evt.Data["diagnosticStage"] = result.DiagnosticStage;
        }

        if (result.Win32Error is not null)
        {
            evt.Data["win32Error"] = result.Win32Error.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (result.WidthPixels is not null)
        {
            evt.Data["widthPixels"] = result.WidthPixels.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (result.HeightPixels is not null)
        {
            evt.Data["heightPixels"] = result.HeightPixels.Value.ToString(CultureInfo.InvariantCulture);
        }

        return [evt];
    }

    /// <summary>
    /// Converts probe phases to stable artifact labels.
    /// Inputs are enum values; processing maps known screenshot phases; the
    /// method returns a lowercase label for filenames and event Data.
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
}

/// <summary>
/// Defines a platform screenshot capture implementation.
/// Inputs are an output directory, phase label, and cancellation token;
/// processing writes or skips a screenshot artifact; CaptureAsync returns
/// capture metadata for event emission.
/// </summary>
internal interface IScreenshotCapture
{
    Task<ScreenshotCaptureResult> CaptureAsync(string outputDirectory, string phase, CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures the visible Windows desktop to an uncompressed BMP file.
/// Inputs are output directory, phase label, and cancellation token; processing
/// uses User32/GDI32 APIs and requires no administrator rights; CaptureAsync
/// returns success metadata or a skipped result when capture is unavailable.
/// </summary>
internal sealed class WindowsDesktopScreenshotCapture : IScreenshotCapture
{
    private const int SmCxScreen = 0;
    private const int SmCyScreen = 1;
    private const int SmXVirtualScreen = 76;
    private const int SmYVirtualScreen = 77;
    private const int SmCxVirtualScreen = 78;
    private const int SmCyVirtualScreen = 79;
    private const int DibRgbColors = 0;
    private const uint BiRgb = 0;
    private const uint SrcCopy = 0x00CC0020;

    /// <summary>
    /// Captures a desktop BMP if the current session exposes a screen.
    /// Inputs are output directory, phase, and cancellation token; processing
    /// creates a screenshots subdirectory and writes a BMP; the method returns
    /// capture metadata or a skipped result for unsupported sessions.
    /// </summary>
    public Task<ScreenshotCaptureResult> CaptureAsync(string outputDirectory, string phase, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(ScreenshotCaptureResult.Skipped(
                "Screenshot capture is only implemented on Windows.",
                diagnosticStage: "platform-check"));
        }

        try
        {
            var screenshotDirectory = Path.Combine(outputDirectory, "screenshots");
            Directory.CreateDirectory(screenshotDirectory);
            var safePhase = phase.Replace(' ', '-');
            var path = Path.Combine(screenshotDirectory, $"{safePhase}-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.bmp");
            var (width, height) = CaptureDesktopToBmp(path, cancellationToken);
            return Task.FromResult(ScreenshotCaptureResult.Success(path, width, height));
        }
        catch (ScreenshotCaptureException ex)
        {
            return Task.FromResult(ScreenshotCaptureResult.Skipped(
                ex.Message,
                ex.GetType().FullName ?? ex.GetType().Name,
                ex.Stage,
                ex.Win32Error));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ExternalException or InvalidOperationException)
        {
            return Task.FromResult(ScreenshotCaptureResult.Skipped(
                ex.Message,
                ex.GetType().FullName ?? ex.GetType().Name,
                diagnosticStage: "capture"));
        }
    }

    /// <summary>
    /// Captures the virtual screen into a BMP file.
    /// Inputs are an output path and cancellation token; processing performs the
    /// GDI BitBlt and manual BMP serialization; the method returns dimensions.
    /// </summary>
    private static (int Width, int Height) CaptureDesktopToBmp(string path, CancellationToken cancellationToken)
    {
        var x = GetSystemMetrics(SmXVirtualScreen);
        var y = GetSystemMetrics(SmYVirtualScreen);
        var width = GetSystemMetrics(SmCxVirtualScreen);
        var height = GetSystemMetrics(SmCyVirtualScreen);
        if (width <= 0 || height <= 0)
        {
            x = 0;
            y = 0;
            width = GetSystemMetrics(SmCxScreen);
            height = GetSystemMetrics(SmCyScreen);
        }

        if (width <= 0 || height <= 0)
        {
            throw ScreenshotCaptureException.ForLastPInvokeError(
                "GetSystemMetrics",
                "No visible desktop surface is available for screenshot capture.");
        }

        var screenDc = GetDC(IntPtr.Zero);
        if (screenDc == IntPtr.Zero)
        {
            throw ScreenshotCaptureException.ForLastPInvokeError("GetDC", "GetDC returned null for the desktop.");
        }

        var memoryDc = IntPtr.Zero;
        var bitmap = IntPtr.Zero;
        var previousObject = IntPtr.Zero;

        try
        {
            memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == IntPtr.Zero)
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("CreateCompatibleDC", "CreateCompatibleDC failed.");
            }

            bitmap = CreateCompatibleBitmap(screenDc, width, height);
            if (bitmap == IntPtr.Zero)
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("CreateCompatibleBitmap", "CreateCompatibleBitmap failed.");
            }

            previousObject = SelectObject(memoryDc, bitmap);
            if (previousObject == IntPtr.Zero)
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("SelectObject", "SelectObject failed for screenshot bitmap.");
            }

            if (!BitBlt(memoryDc, 0, 0, width, height, screenDc, x, y, SrcCopy))
            {
                throw ScreenshotCaptureException.ForLastPInvokeError("BitBlt", "BitBlt failed while capturing the desktop.");
            }

            cancellationToken.ThrowIfCancellationRequested();
            WriteBitmapPixels(path, screenDc, bitmap, width, height);
            return (width, height);
        }
        finally
        {
            if (previousObject != IntPtr.Zero && memoryDc != IntPtr.Zero)
            {
                _ = SelectObject(memoryDc, previousObject);
            }

            if (bitmap != IntPtr.Zero)
            {
                _ = DeleteObject(bitmap);
            }

            if (memoryDc != IntPtr.Zero)
            {
                _ = DeleteDC(memoryDc);
            }

            _ = ReleaseDC(IntPtr.Zero, screenDc);
        }
    }

    /// <summary>
    /// Serializes captured GDI bitmap pixels as a top-down 32-bit BMP.
    /// Inputs are output path, device context, bitmap handle, width, and height;
    /// processing calls GetDIBits and writes BMP headers and pixels; the method
    /// returns no value.
    /// </summary>
    private static void WriteBitmapPixels(string path, IntPtr deviceContext, IntPtr bitmap, int width, int height)
    {
        var stride = checked(width * 4);
        var imageSize = checked(stride * height);
        var pixels = new byte[imageSize];
        var info = new BitmapInfoHeader
        {
            BiSize = (uint)Marshal.SizeOf<BitmapInfoHeader>(),
            BiWidth = width,
            BiHeight = -height,
            BiPlanes = 1,
            BiBitCount = 32,
            BiCompression = BiRgb,
            BiSizeImage = (uint)imageSize
        };

        var scanLines = GetDIBits(deviceContext, bitmap, 0, (uint)height, pixels, ref info, DibRgbColors);
        if (scanLines == 0)
        {
            throw ScreenshotCaptureException.ForLastPInvokeError("GetDIBits", "GetDIBits failed while reading screenshot pixels.");
        }

        using var stream = File.Create(path);
        using var writer = new BinaryWriter(stream);
        var pixelOffset = 14 + Marshal.SizeOf<BitmapInfoHeader>();
        var fileSize = checked(pixelOffset + imageSize);

        writer.Write((ushort)0x4D42);
        writer.Write((uint)fileSize);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((uint)pixelOffset);
        writer.Write(info.BiSize);
        writer.Write(info.BiWidth);
        writer.Write(info.BiHeight);
        writer.Write(info.BiPlanes);
        writer.Write(info.BiBitCount);
        writer.Write(info.BiCompression);
        writer.Write(info.BiSizeImage);
        writer.Write(info.BiXPelsPerMeter);
        writer.Write(info.BiYPelsPerMeter);
        writer.Write(info.BiClrUsed);
        writer.Write(info.BiClrImportant);
        writer.Write(pixels);
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetSystemMetrics(int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetDC(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDc);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateCompatibleDC(IntPtr hDc);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteDC(IntPtr hDc);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateCompatibleBitmap(IntPtr hDc, int cx, int cy);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr SelectObject(IntPtr hDc, IntPtr hObject);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool BitBlt(IntPtr hdcDest, int xDest, int yDest, int width, int height, IntPtr hdcSrc, int xSrc, int ySrc, uint rop);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern int GetDIBits(IntPtr hdc, IntPtr hbm, uint start, uint cLines, byte[] lpvBits, ref BitmapInfoHeader lpbmi, int usage);

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfoHeader
    {
        public uint BiSize;
        public int BiWidth;
        public int BiHeight;
        public ushort BiPlanes;
        public ushort BiBitCount;
        public uint BiCompression;
        public uint BiSizeImage;
        public int BiXPelsPerMeter;
        public int BiYPelsPerMeter;
        public uint BiClrUsed;
        public uint BiClrImportant;
    }
}

/// <summary>
/// Carries screenshot capture failure diagnostics from the platform-specific
/// implementation. Inputs are a capture stage, message, and Win32 error code;
/// processing is immutable exception storage; records are converted into
/// screenshot.skipped event Data.
/// </summary>
internal sealed class ScreenshotCaptureException : InvalidOperationException
{
    public ScreenshotCaptureException(string stage, string message, int win32Error)
        : base(message)
    {
        Stage = stage;
        Win32Error = win32Error;
    }

    public string Stage { get; }

    public int Win32Error { get; }

    /// <summary>
    /// Creates a screenshot exception using the last P/Invoke error code.
    /// Inputs are capture stage and message; processing reads the thread-local
    /// P/Invoke error; the method returns a ScreenshotCaptureException.
    /// </summary>
    public static ScreenshotCaptureException ForLastPInvokeError(string stage, string message)
    {
        return new ScreenshotCaptureException(stage, message, Marshal.GetLastPInvokeError());
    }
}

/// <summary>
/// Describes the result of one screenshot attempt.
/// Inputs are capture outcome details; processing is immutable storage; records
/// are returned by IScreenshotCapture and converted into SandboxEvent data.
/// </summary>
internal sealed record ScreenshotCaptureResult(
    bool Captured,
    string? Path,
    string? Reason,
    string? ExceptionType,
    string? DiagnosticStage,
    int? Win32Error,
    int? WidthPixels,
    int? HeightPixels)
{
    /// <summary>
    /// Creates a successful screenshot result.
    /// Inputs are artifact path and dimensions; processing stores success
    /// metadata; the method returns a ScreenshotCaptureResult.
    /// </summary>
    public static ScreenshotCaptureResult Success(string path, int widthPixels, int heightPixels)
    {
        return new ScreenshotCaptureResult(true, path, null, null, null, null, widthPixels, heightPixels);
    }

    /// <summary>
    /// Creates a skipped screenshot result.
    /// Inputs are skip reason, optional exception type, diagnostic stage, and
    /// Win32 error; processing stores diagnostic metadata; the method returns a
    /// ScreenshotCaptureResult.
    /// </summary>
    public static ScreenshotCaptureResult Skipped(
        string reason,
        string? exceptionType = null,
        string? diagnosticStage = null,
        int? win32Error = null)
    {
        return new ScreenshotCaptureResult(false, null, reason, exceptionType, diagnosticStage, win32Error, null, null);
    }
}
