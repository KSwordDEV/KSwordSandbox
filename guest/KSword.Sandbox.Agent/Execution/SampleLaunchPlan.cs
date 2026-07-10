namespace KSword.Sandbox.Agent.Execution;

/// <summary>
/// Describes how the guest agent should launch one submitted sample.
/// Inputs are parsed command-line options, processing normalizes working
/// directory and timeout, and the record is returned to execution services.
/// </summary>
internal sealed record SampleLaunchPlan
{
    public required string SamplePath { get; init; }

    public string WorkingDirectory { get; init; } = Environment.CurrentDirectory;

    public TimeSpan Duration { get; init; } = TimeSpan.FromSeconds(120);
}
