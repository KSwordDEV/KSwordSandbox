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
        steps.Add(Step("check-guest-credential", "Verify guest credential environment secret", BuildGuestCredentialPreamble(config) + " Write-Host 'Guest credential secret is available for this step.'", mutatesVmState: false));
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
        steps.Add(Step("enable-guest-service", "Enable Guest Service Interface", BuildEnableGuestServiceCommand(targetVmName)));
        steps.Add(Step("start-temp-vm", "Start temporary analysis VM", $"Start-VM -Name {Q(targetVmName)}"));
        steps.Add(Step("wait-powershell-direct", "Wait for PowerShell Direct in guest", BuildWaitPowerShellDirectCommand(config, targetVmName), mutatesVmState: false));
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
        steps.Add(Step("enable-guest-service", "Enable Guest Service Interface", BuildEnableGuestServiceCommand(config.HyperV.GoldenVmName)));
        steps.Add(Step("start-golden", "Start restored golden VM", $"Start-VM -Name {Q(config.HyperV.GoldenVmName)}"));
        steps.Add(Step("wait-powershell-direct", "Wait for PowerShell Direct in guest", BuildWaitPowerShellDirectCommand(config, config.HyperV.GoldenVmName), mutatesVmState: false));
    }

    /// <summary>
    /// Builds a locale-neutral command that enables the Hyper-V Guest Service
    /// Interface. Inputs are the target VM name; processing resolves the
    /// integration component by stable GUID first so localized hosts (for
    /// example Chinese Windows showing "来宾服务接口") do not fail; the method
    /// returns a PowerShell command string.
    /// </summary>
    private static string BuildEnableGuestServiceCommand(string vmName)
    {
        return "$guestServiceComponentId = '6C09BB55-D683-4DA0-8931-C9BF705F6480'; " +
               $"$guestService = Get-VMIntegrationService -VMName {Q(vmName)} | Where-Object {{ ([string]$_.Id).EndsWith('\\' + $guestServiceComponentId, [System.StringComparison]::OrdinalIgnoreCase) -or $_.Name -eq 'Guest Service Interface' -or $_.Name -eq '来宾服务接口' }} | Select-Object -First 1; " +
               "if ($null -eq $guestService) { throw 'Guest Service Interface integration service was not found.' }; " +
               "Enable-VMIntegrationService -VMIntegrationService $guestService";
    }

    /// <summary>
    /// Adds steps that copy the sample, start the guest agent, live-sync output,
    /// and collect final artifacts. Inputs are VM names and host/guest paths;
    /// processing appends PowerShell Direct commands with job-specific output
    /// paths; the method returns no value.
    /// </summary>
    private static void AddGuestExecutionSteps(List<SandboxRunbookStep> steps, SandboxConfig config, string targetVmName, SampleIdentity sample, string guestSample, string guestOut, string hostOut)
    {
        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        var agentPath = $"{guestRoot}\\agent\\{config.Guest.AgentExecutableName}";
        var driverEventsPath = $"{guestOut}\\driver-events.jsonl";
        var agentPidPath = $"{guestOut}\\agent.pid";
        var agentExitPath = $"{guestOut}\\agent.exit";

        steps.Add(Step("stage-guest-payload", "Stage Guest Agent and R0Collector into guest", BuildStageGuestPayloadCommand(config, targetVmName)));
        steps.Add(Step("copy-sample", "Copy submitted sample into guest", $"Copy-VMFile -VMName {Q(targetVmName)} -SourcePath {Q(sample.FullPath)} -DestinationPath {Q(guestSample)} -FileSource Host -CreateFullPath"));
        steps.Add(Step("make-host-output", "Create host output folder", $"New-Item -ItemType Directory -Force -Path {Q(hostOut)} | Out-Null", mutatesVmState: false));
        steps.Add(Step("prepare-guest-output", "Prepare job-specific guest output folder", BuildPrepareGuestOutputCommand(config, targetVmName, guestOut, driverEventsPath, agentPidPath, agentExitPath)));
        steps.Add(Step("run-agent", "Start guest collector and sample asynchronously", BuildStartGuestAgentCommand(config, targetVmName, guestRoot, agentPath, guestSample, guestOut, driverEventsPath, agentPidPath, agentExitPath)));
        steps.Add(Step("sync-live-output", "Live-sync guest events while sample runs", BuildLiveOutputSyncCommand(config, targetVmName, guestOut, hostOut, agentPidPath, agentExitPath)));
        steps.Add(Step("collect-output", "Collect final guest JSON output", BuildCollectOutputCommand(config, targetVmName, guestOut, hostOut)));
    }

    /// <summary>
    /// Builds a self-contained credential preamble for one PowerShell step.
    /// Inputs are guest username and configured environment-secret name;
    /// processing validates that the secret is present and creates
    /// $guestCredential inside the current PowerShell process. The returned
    /// script is intentionally repeated in every PowerShell Direct step because
    /// the WebUI runbook executor launches a fresh PowerShell process for each
    /// step and does not preserve variables across steps.
    /// </summary>
    private static string BuildGuestCredentialPreamble(SandboxConfig config)
    {
        var secretName = config.Guest.PasswordSecretName;
        return string.Join(" ", new[]
        {
            $"$guestPasswordText = [System.Environment]::GetEnvironmentVariable({Q(secretName)});",
            $"if ([string]::IsNullOrWhiteSpace($guestPasswordText)) {{ throw 'Guest password environment variable {secretName} is not set for this PowerShell step.' }};",
            "$guestPassword = ConvertTo-SecureString $guestPasswordText -AsPlainText -Force;",
            $"$guestCredential = [pscredential]::new({Q(config.Guest.UserName)}, $guestPassword);"
        });
    }

    /// <summary>
    /// Prefixes a PowerShell Direct command with guest credential setup.
    /// Inputs are sandbox config and a command body that references
    /// $guestCredential; processing concatenates the credential preamble with
    /// the command body; the method returns a self-contained step command.
    /// </summary>
    private static string WithGuestCredential(SandboxConfig config, string command)
    {
        return BuildGuestCredentialPreamble(config) + " " + command;
    }

    /// <summary>
    /// Builds a readiness loop for PowerShell Direct after VM start. Inputs are
    /// sandbox config and VM name; processing repeatedly invokes a harmless
    /// guest script block with the configured credential until the guest is
    /// reachable or a fixed timeout expires; the returned command is
    /// self-contained for the per-step WebUI PowerShell executor.
    /// </summary>
    private static string BuildWaitPowerShellDirectCommand(SandboxConfig config, string targetVmName)
    {
        var command = string.Join(" ", new[]
        {
            "$deadline = (Get-Date).AddSeconds(300);",
            "$ready = $false;",
            "do {",
            "try {",
            $"Invoke-Command -VMName {Q(targetVmName)} -Credential $guestCredential -ScriptBlock {{ $env:COMPUTERNAME }} | Out-Null;",
            "$ready = $true;",
            "}",
            "catch {",
            "Start-Sleep -Seconds 3;",
            "}",
            "} while (-not $ready -and (Get-Date) -lt $deadline);",
            $"if (-not $ready) {{ throw 'PowerShell Direct did not become ready for VM {targetVmName} within 300 seconds.' }};",
            "Write-Host 'PowerShell Direct is ready.'"
        });

        return WithGuestCredential(config, command);
    }

    /// <summary>
    /// Builds a command that stages guest-side tools from the host payload root.
    /// Inputs are sandbox config and target VM name; processing copies prepared
    /// agent and R0Collector files through a PowerShell Direct session, creates
    /// required guest directories, optionally copies an external driver .sys,
    /// and validates guest paths; the method returns a runbook command string.
    /// </summary>
    private static string BuildStageGuestPayloadCommand(SandboxConfig config, string targetVmName)
    {
        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        var guestAgentDirectory = $"{guestRoot}\\agent";
        var guestCollectorDirectory = $"{guestRoot}\\r0collector";
        var guestDriverDirectory = Path.GetDirectoryName(config.Driver.DriverPathInGuest)?.Replace('/', '\\') ?? $"{guestRoot}\\driver";
        var requiredGuestPaths = new List<string>
        {
            $"{guestAgentDirectory}\\{config.Guest.AgentExecutableName}"
        };
        var commands = new List<string>
        {
            $"$payloadRoot = {Q(config.Paths.GuestPayloadRoot)};",
            "$agentSource = Join-Path $payloadRoot 'agent\\*';",
            "$collectorSource = Join-Path $payloadRoot 'r0collector\\*';",
            $"$driverSource = {Q(config.Driver.HostDriverPath ?? string.Empty)};",
            $"$session = New-PSSession -VMName {Q(targetVmName)} -Credential $guestCredential;",
            "try {",
            $"Invoke-Command -Session $session -ScriptBlock {{ New-Item -ItemType Directory -Force -Path {Q(guestAgentDirectory)}, {Q(guestCollectorDirectory)}, {Q(guestDriverDirectory)}, {Q($"{guestRoot}\\incoming")}, {Q($"{guestRoot}\\out")} | Out-Null }};",
            "if (-not (Test-Path -LiteralPath (Join-Path $payloadRoot 'agent'))) { throw \"Guest Agent payload folder was not found: $(Join-Path $payloadRoot 'agent')\" }",
            $"Copy-Item -ToSession $session -Path $agentSource -Destination {Q(guestAgentDirectory)} -Recurse -Force;"
        };

        if (config.Driver.Enabled)
        {
            requiredGuestPaths.Add(config.Driver.R0CollectorPathInGuest);
            commands.Add("if (-not (Test-Path -LiteralPath (Join-Path $payloadRoot 'r0collector'))) { throw \"R0Collector payload folder was not found: $(Join-Path $payloadRoot 'r0collector')\" }");
            commands.Add($"Copy-Item -ToSession $session -Path $collectorSource -Destination {Q(guestCollectorDirectory)} -Recurse -Force;");
        }

        if (!string.IsNullOrWhiteSpace(config.Driver.HostDriverPath))
        {
            requiredGuestPaths.Add(config.Driver.DriverPathInGuest);
            commands.Add("if (-not (Test-Path -LiteralPath $driverSource -PathType Leaf)) { throw \"Host driver path was not found: $driverSource\" }");
            commands.Add($"Copy-Item -ToSession $session -Path $driverSource -Destination {Q(config.Driver.DriverPathInGuest)} -Force;");
        }

        commands.Add($"Invoke-Command -Session $session -ScriptBlock {{ foreach ($path in @({string.Join(", ", requiredGuestPaths.Select(Q))})) {{ if (-not (Test-Path -LiteralPath $path)) {{ throw \"Required guest payload path is missing: $path\" }} }} }};");
        commands.Add("}");
        commands.Add("finally { if ($session) { Remove-PSSession $session } }");

        return WithGuestCredential(config, string.Join(" ", commands));
    }

    /// <summary>
    /// Builds a command that clears stale job-specific output before execution.
    /// Inputs are target VM and guest artifact paths; processing creates the
    /// guest output directory and removes stale artifacts; the method returns a
    /// PowerShell Direct command string.
    /// </summary>
    private static string BuildPrepareGuestOutputCommand(SandboxConfig config, string targetVmName, string guestOut, string driverEventsPath, string agentPidPath, string agentExitPath)
    {
        var stalePaths = string.Join(", ", new[] { $"{guestOut}\\events.json", driverEventsPath, agentPidPath, agentExitPath }.Select(Q));
        return WithGuestCredential(config, $"Invoke-Command -VMName {Q(targetVmName)} -Credential $guestCredential -ScriptBlock {{ New-Item -ItemType Directory -Force -Path {Q(guestOut)} | Out-Null; Remove-Item -LiteralPath {stalePaths} -Force -ErrorAction SilentlyContinue }}");
    }

    /// <summary>
    /// Builds a PowerShell Direct command that starts the Guest Agent through a
    /// guest-side PowerShell wrapper. Inputs are guest paths and config;
    /// processing writes PID and exit-code marker files into guestOut; the
    /// method returns a host PowerShell command for the runbook step.
    /// </summary>
    private static string BuildStartGuestAgentCommand(
        SandboxConfig config,
        string targetVmName,
        string guestRoot,
        string agentPath,
        string guestSample,
        string guestOut,
        string driverEventsPath,
        string agentPidPath,
        string agentExitPath)
    {
        var agentCommand = BuildGuestAgentInvocation(config, agentPath, guestSample, guestOut, driverEventsPath, agentExitPath);
        return WithGuestCredential(config, $"Invoke-Command -VMName {Q(targetVmName)} -Credential $guestCredential -ScriptBlock {{ $agentCommand = {Q(agentCommand)}; $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-Command',$agentCommand) -WorkingDirectory {Q(guestRoot)} -PassThru; $process.Id | Set-Content -Path {Q(agentPidPath)} -Encoding ASCII }}");
    }

    /// <summary>
    /// Builds the command executed inside the guest wrapper process.
    /// Inputs are guest file paths, duration, and driver settings; processing
    /// formats the Guest Agent CLI and records its exit code; the method returns
    /// a command string passed to guest powershell.exe -Command.
    /// </summary>
    private static string BuildGuestAgentInvocation(SandboxConfig config, string agentPath, string guestSample, string guestOut, string driverEventsPath, string agentExitPath)
    {
        var arguments = new List<string>
        {
            "--sample",
            Q(guestSample),
            "--out",
            Q(guestOut),
            "--duration",
            config.Analysis.DefaultDurationSeconds.ToString()
        };
        arguments.AddRange(BuildDriverAgentArguments(config, driverEventsPath));

        return string.Join("; ", new[]
        {
            $"& {Q(agentPath)} {string.Join(' ', arguments)}",
            "$exitCode = if ($global:LASTEXITCODE -is [int]) { $global:LASTEXITCODE } else { 0 }",
            $"Set-Content -Path {Q(agentExitPath)} -Value $exitCode -Encoding ASCII",
            "exit $exitCode"
        });
    }

    /// <summary>
    /// Builds optional Guest Agent arguments for R0Collector integration.
    /// Inputs are typed sandbox config and the job-specific driver JSONL path;
    /// processing forwards collector path, device name, and optional mock flag;
    /// the method returns PowerShell-safe CLI tokens.
    /// </summary>
    private static List<string> BuildDriverAgentArguments(SandboxConfig config, string driverEventsPath)
    {
        if (!config.Driver.Enabled)
        {
            return [];
        }

        var arguments = new List<string>
        {
            "--driver-events",
            Q(driverEventsPath),
            "--r0collector",
            Q(config.Driver.R0CollectorPathInGuest),
            "--driver-device",
            Q(config.Driver.DevicePath)
        };

        if (config.Driver.UseMockCollector)
        {
            arguments.Add("--r0-mock");
        }

        return arguments;
    }

    /// <summary>
    /// Builds a host loop that copies guest output while the guest process runs.
    /// Inputs are VM name, guest output paths, host output folder, and duration;
    /// processing opens one PSSession, copies artifacts repeatedly, checks the
    /// guest PID, validates the agent exit marker, and returns a PowerShell
    /// command string.
    /// </summary>
    private static string BuildLiveOutputSyncCommand(SandboxConfig config, string targetVmName, string guestOut, string hostOut, string agentPidPath, string agentExitPath)
    {
        var maxSyncSeconds = Math.Max(config.Analysis.DefaultDurationSeconds + 60, 90);
        var command = string.Join(" ", new[]
        {
            $"$session = New-PSSession -VMName {Q(targetVmName)} -Credential $guestCredential;",
            "try {",
            $"$guestOut = {Q(guestOut)};",
            $"$hostOut = {Q(hostOut)};",
            $"$pidPath = {Q(agentPidPath)};",
            $"$exitPath = {Q(agentExitPath)};",
            $"$deadline = (Get-Date).AddSeconds({maxSyncSeconds});",
            "New-Item -ItemType Directory -Force -Path $hostOut | Out-Null;",
            "$guestAgentPid = Invoke-Command -Session $session -ScriptBlock { param($path) if (Test-Path -LiteralPath $path) { [int](Get-Content -LiteralPath $path -Raw) } else { 0 } } -ArgumentList $pidPath;",
            "do {",
            "Copy-Item -FromSession $session -Path $guestOut -Destination $hostOut -Recurse -Force -ErrorAction SilentlyContinue;",
            "$running = Invoke-Command -Session $session -ScriptBlock { param($processId) if ($processId -le 0) { $false } else { [bool](Get-Process -Id $processId -ErrorAction SilentlyContinue) } } -ArgumentList $guestAgentPid;",
            "if ($running) { Start-Sleep -Seconds 2 }",
            "} while ($running -and (Get-Date) -lt $deadline);",
            "Copy-Item -FromSession $session -Path $guestOut -Destination $hostOut -Recurse -Force -ErrorAction SilentlyContinue;",
            "if ($running) { throw \"Guest Agent did not exit before live-sync deadline.\" }",
            "$exitText = Invoke-Command -Session $session -ScriptBlock { param($path) if (Test-Path -LiteralPath $path) { (Get-Content -LiteralPath $path -Raw).Trim() } else { '0' } } -ArgumentList $exitPath;",
            "$exitCode = [int]$exitText;",
            "if ($exitCode -ne 0) { throw \"Guest Agent exited with code $exitCode.\" }",
            "}",
            "finally { if ($session) { Remove-PSSession $session } }"
        });

        return WithGuestCredential(config, command);
    }

    /// <summary>
    /// Builds the final collection command after live sync completes.
    /// Inputs are target VM, guest output folder, and host output folder;
    /// processing copies the complete guest output tree one last time and
    /// closes the PSSession; the method returns a PowerShell command string.
    /// </summary>
    private static string BuildCollectOutputCommand(SandboxConfig config, string targetVmName, string guestOut, string hostOut)
    {
        return WithGuestCredential(config, $"$session = New-PSSession -VMName {Q(targetVmName)} -Credential $guestCredential; try {{ Copy-Item -FromSession $session -Path {Q(guestOut)} -Destination {Q(hostOut)} -Recurse -Force }} finally {{ if ($session) {{ Remove-PSSession $session }} }}");
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
