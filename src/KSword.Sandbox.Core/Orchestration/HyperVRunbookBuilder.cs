using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Orchestration;

/// <summary>
/// Builds a deterministic Hyper-V command plan for one sandbox analysis.
/// Inputs are typed configuration, job metadata, and sample identity;
/// processing emits PowerShell operations without executing them; the method
/// returns a runbook that can be reviewed or executed by a privileged runner.
/// </summary>
public sealed class HyperVRunbookBuilder
{
    /// <summary>
    /// Creates an ordered runbook for the supplied job and sample.
    /// Inputs are sandbox config, job ID, and sample metadata; processing
    /// chooses checkpoint or differencing-disk mode; the method returns steps.
    /// </summary>
    public SandboxRunbook Build(SandboxConfig config, Guid jobId, SampleIdentity sample)
    {
        var usesTemporaryVm = config.HyperV.UseDifferencingDisk && !string.IsNullOrWhiteSpace(config.HyperV.BaseVhdxPath);
        var targetVmName = usesTemporaryVm
            ? $"{config.HyperV.TempVmPrefix}-{jobId:N}"[..Math.Min($"{config.HyperV.TempVmPrefix}-{jobId:N}".Length, 64)]
            : config.HyperV.GoldenVmName;

        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        var guestSample = $"{guestRoot}\\incoming\\{sample.FileName}";
        var guestOut = $"{guestRoot}\\out\\{jobId:N}";
        var hostOut = Path.Combine(config.Paths.RuntimeRoot, "jobs", jobId.ToString("N"), "guest");
        var steps = new List<SandboxRunbookStep>();

        AddPrerequisiteSteps(steps, config);
        if (usesTemporaryVm)
        {
            AddDifferencingVmSteps(steps, config, targetVmName, jobId);
        }
        else
        {
            AddCheckpointRestoreSteps(steps, config);
        }

        AddGuestExecutionSteps(steps, config, targetVmName, sample, guestSample, guestOut, hostOut);
        AddCleanupSteps(steps, usesTemporaryVm, targetVmName);

        return new SandboxRunbook
        {
            JobId = jobId,
            TargetVmName = targetVmName,
            UsesTemporaryVm = usesTemporaryVm,
            Steps = steps
        };
    }

    /// <summary>
    /// Adds read-only validation steps for the host environment.
    /// Inputs are an output list and config, processing appends PowerShell
    /// checks, and the method returns no value.
    /// </summary>
    private static void AddPrerequisiteSteps(List<SandboxRunbookStep> steps, SandboxConfig config)
    {
        steps.Add(Step("check-hyperv", "Verify Hyper-V module", "Get-Command Get-VM | Out-Null", mutatesVmState: false));
        steps.Add(Step("check-golden-vm", "Verify golden VM exists", $"Get-VM -Name {Q(config.HyperV.GoldenVmName)} | Out-Null", mutatesVmState: false));
        steps.Add(Step("load-credential", "Load guest credential from environment secret", $"$guestPassword = ConvertTo-SecureString $env:{config.Guest.PasswordSecretName} -AsPlainText -Force; $guestCredential = [pscredential]::new({Q(config.Guest.UserName)}, $guestPassword)", mutatesVmState: false));
    }

    /// <summary>
    /// Adds steps for temporary VM creation from a differencing disk.
    /// Inputs are config, target VM name, and job ID; processing appends
    /// New-VHD/New-VM commands; the method returns no value.
    /// </summary>
    private static void AddDifferencingVmSteps(List<SandboxRunbookStep> steps, SandboxConfig config, string targetVmName, Guid jobId)
    {
        var vmRoot = Path.Combine(config.Paths.RuntimeRoot, "vms", jobId.ToString("N"));
        var diffDisk = Path.Combine(vmRoot, $"{targetVmName}.vhdx");
        var switchPart = string.IsNullOrWhiteSpace(config.HyperV.SwitchName) ? string.Empty : $" -SwitchName {Q(config.HyperV.SwitchName)}";

        steps.Add(Step("make-vm-root", "Create temporary VM folder", $"New-Item -ItemType Directory -Force -Path {Q(vmRoot)} | Out-Null"));
        steps.Add(Step("make-diff-disk", "Create differencing disk", $"New-VHD -Path {Q(diffDisk)} -ParentPath {Q(config.HyperV.BaseVhdxPath!)} -Differencing | Out-Null"));
        steps.Add(Step("create-temp-vm", "Create temporary analysis VM", $"New-VM -Name {Q(targetVmName)} -Generation 2 -MemoryStartupBytes {config.HyperV.MemoryStartupBytes} -VHDPath {Q(diffDisk)}{switchPart} | Out-Null"));
        steps.Add(Step("enable-guest-service", "Enable Guest Service Interface", $"Enable-VMIntegrationService -VMName {Q(targetVmName)} -Name 'Guest Service Interface'"));
        steps.Add(Step("start-temp-vm", "Start temporary analysis VM", $"Start-VM -Name {Q(targetVmName)}"));
    }

    /// <summary>
    /// Adds steps for restoring the configured golden VM checkpoint.
    /// Inputs are config and an output list, processing appends restore/start
    /// commands, and the method returns no value.
    /// </summary>
    private static void AddCheckpointRestoreSteps(List<SandboxRunbookStep> steps, SandboxConfig config)
    {
        steps.Add(Step("stop-golden", "Stop golden VM before restore", $"Stop-VM -Name {Q(config.HyperV.GoldenVmName)} -TurnOff -Force -ErrorAction SilentlyContinue"));
        steps.Add(Step("restore-golden", "Restore clean checkpoint", $"Restore-VMSnapshot -VMName {Q(config.HyperV.GoldenVmName)} -Name {Q(config.HyperV.GoldenSnapshotName)} -Confirm:$false"));
        steps.Add(Step("enable-guest-service", "Enable Guest Service Interface", $"Enable-VMIntegrationService -VMName {Q(config.HyperV.GoldenVmName)} -Name 'Guest Service Interface'"));
        steps.Add(Step("start-golden", "Start restored golden VM", $"Start-VM -Name {Q(config.HyperV.GoldenVmName)}"));
    }

    /// <summary>
    /// Adds steps that copy the sample, run the guest agent, and collect output.
    /// Inputs are VM names and host/guest paths, processing appends PowerShell
    /// Direct commands, and the method returns no value.
    /// </summary>
    private static void AddGuestExecutionSteps(List<SandboxRunbookStep> steps, SandboxConfig config, string targetVmName, SampleIdentity sample, string guestSample, string guestOut, string hostOut)
    {
        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        var agentPath = $"{guestRoot}\\agent\\{config.Guest.AgentExecutableName}";
        var driverArg = config.Driver.Enabled ? $" --driver-events {Q(config.Driver.EventJsonLinesPath)}" : string.Empty;

        steps.Add(Step("copy-sample", "Copy submitted sample into guest", $"Copy-VMFile -VMName {Q(targetVmName)} -SourcePath {Q(sample.FullPath)} -DestinationPath {Q(guestSample)} -FileSource Host -CreateFullPath"));
        steps.Add(Step("run-agent", "Run guest collector and sample", $"Invoke-Command -VMName {Q(targetVmName)} -Credential $guestCredential -ScriptBlock {{ & {Q(agentPath)} --sample {Q(guestSample)} --out {Q(guestOut)} --duration {config.Analysis.DefaultDurationSeconds}{driverArg} }}"));
        steps.Add(Step("make-host-output", "Create host output folder", $"New-Item -ItemType Directory -Force -Path {Q(hostOut)} | Out-Null", mutatesVmState: false));
        steps.Add(Step("collect-output", "Collect guest JSON output", $"$session = New-PSSession -VMName {Q(targetVmName)} -Credential $guestCredential; Copy-Item -FromSession $session -Path {Q(guestOut)} -Destination {Q(hostOut)} -Recurse -Force; Remove-PSSession $session"));
    }

    /// <summary>
    /// Adds VM cleanup steps after collection.
    /// Inputs are mode and target VM, processing appends stop/remove commands,
    /// and the method returns no value.
    /// </summary>
    private static void AddCleanupSteps(List<SandboxRunbookStep> steps, bool usesTemporaryVm, string targetVmName)
    {
        steps.Add(Step("stop-vm", "Stop analysis VM", $"Stop-VM -Name {Q(targetVmName)} -TurnOff -Force"));
        if (usesTemporaryVm)
        {
            steps.Add(Step("remove-temp-vm", "Remove temporary VM registration", $"Remove-VM -Name {Q(targetVmName)} -Force"));
        }
    }

    /// <summary>
    /// Creates one runbook step from primitive values.
    /// Inputs are identifiers, title, command text, and flags; processing stores
    /// them in a record; the method returns a SandboxRunbookStep.
    /// </summary>
    private static SandboxRunbookStep Step(string id, string title, string powerShell, bool requiresElevation = true, bool mutatesVmState = true)
    {
        return new SandboxRunbookStep
        {
            Id = id,
            Title = title,
            PowerShell = powerShell,
            RequiresElevation = requiresElevation,
            MutatesVmState = mutatesVmState
        };
    }

    /// <summary>
    /// Quotes text for single-quoted PowerShell strings.
    /// The input is raw text, processing doubles embedded single quotes, and
    /// the method returns a safely quoted PowerShell literal.
    /// </summary>
    private static string Q(string text)
    {
        return $"'{text.Replace("'", "''")}'";
    }
}
