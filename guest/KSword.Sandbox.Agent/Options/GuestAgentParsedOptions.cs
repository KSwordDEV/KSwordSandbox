namespace KSword.Sandbox.Agent.Options;

/// <summary>
/// Stores parsed guest agent options for future Program.cs decomposition.
/// Inputs are raw command-line switches; processing validates paths elsewhere;
/// the record is returned to execution and collection services.
/// </summary>
internal sealed record GuestAgentParsedOptions
{
    public string SamplePath { get; init; } = string.Empty;

    public string OutputDirectory { get; init; } = string.Empty;

    public int DurationSeconds { get; init; } = 120;

    public string? DriverEventsPath { get; init; }

    public string? R0CollectorPath { get; init; }

    public string DriverDevicePath { get; init; } = @"\\.\KSwordSandboxDriver";

    public bool R0Mock { get; init; }

    public bool CaptureScreenshots { get; init; }

    public string ScreenshotPhases { get; init; } = "before,during,after";

    public int ScreenshotCount { get; init; } = 1;

    public bool CollectDroppedFiles { get; init; }

    public bool CaptureMemoryDump { get; init; }

    public bool CapturePacketCapture { get; init; }
}
