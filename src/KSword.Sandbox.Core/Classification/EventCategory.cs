namespace KSword.Sandbox.Core.Classification;

/// <summary>
/// Groups normalized events into report-facing behavior domains.
/// Inputs are selected by event classifiers, processing compares enum values,
/// and the enum is returned in classified event summaries.
/// </summary>
public enum EventCategory
{
    Unknown = 0,
    Process,
    FileSystem,
    Registry,
    Network,
    Module,
    Persistence,
    Evasion,
    HostOrchestration,
    GuestAgent,
    Driver
}
