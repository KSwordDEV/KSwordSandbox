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
        if (config.Driver.Enabled && !config.Driver.UseMockCollector)
        {
            steps.Add(Step("check-r0-driver-config", "Verify real R0 driver host path", BuildR0DriverHostPathCheckCommand(config), requiresElevation: false, mutatesVmState: false));
        }

        steps.Add(Step("check-guest-credential", "Verify guest credential environment secret", BuildGuestCredentialPreamble(config) + " Write-Host 'Guest credential secret is available for this step.'", mutatesVmState: false));
    }

    /// <summary>
    /// Builds an early host-side R0 driver readiness check. Inputs are driver
    /// settings; processing fails fast when live R0 is requested without a
    /// configured/staged .sys path and warns when the file is unsigned; the
    /// method returns a PowerShell command string.
    /// </summary>
    private static string BuildR0DriverHostPathCheckCommand(SandboxConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.Driver.HostDriverPath))
        {
            return "Write-Warning 'R0 live driver collection is enabled (driver.enabled=true and driver.useMockCollector=false), but driver.hostDriverPath is empty. The runbook will not generate install-driver-service, stage-guest-payload will use an empty driverSource, and R0Collector can fail opening the device with deviceUnavailable/win32Error=2.'; throw 'R0 driver preflight failed: configure driver.hostDriverPath to a built and test-signed .sys, set driver.useMockCollector=true for mock R0 validation, or set driver.enabled=false / use -NoR0Collector before live execution.'";
        }

        return string.Join(" ", new[]
        {
            $"$driverPath = {Q(config.Driver.HostDriverPath)};",
            "if (-not (Test-Path -LiteralPath $driverPath -PathType Leaf)) { throw \"R0 driver host path was not found: $driverPath\" };",
            "$signature = Get-AuthenticodeSignature -FilePath $driverPath;",
            "Write-Host \"R0 driver host path: $driverPath\";",
            "Write-Host \"R0 driver Authenticode status: $($signature.Status)\";",
            "if ($signature.Status -eq 'NotSigned') { Write-Warning 'R0 driver file is not signed. Windows x64 guests normally require a trusted/test-signed kernel driver; sc.exe start may fail with 577/1275 until the guest is in test-signing mode and the driver is test-signed.' }"
        });
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
        steps.Add(Step("start-temp-vm", "Start temporary analysis VM and wait for Running", BuildStartVmAndWaitCommand(targetVmName)));
        AddOpenInteractiveDesktopStep(steps, config, targetVmName);
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
        steps.Add(Step("start-golden", "Start restored golden VM and wait for Running", BuildStartVmAndWaitCommand(config.HyperV.GoldenVmName)));
        AddOpenInteractiveDesktopStep(steps, config, config.HyperV.GoldenVmName);
        steps.Add(Step("wait-powershell-direct", "Wait for PowerShell Direct in guest", BuildWaitPowerShellDirectCommand(config, config.HyperV.GoldenVmName), mutatesVmState: false));
    }

    /// <summary>
    /// Adds the operator-interaction desktop step. Inputs are Hyper-V/RDP
    /// settings and target VM name; processing opens VMConnect first and falls
    /// back to mstsc/RDP when configured or discoverable; the method appends a
    /// required step before any sample copy/execution happens.
    /// </summary>
    private static void AddOpenInteractiveDesktopStep(List<SandboxRunbookStep> steps, SandboxConfig config, string targetVmName)
    {
        // Live Web/Core runbooks do not have the CLI-only -NoOpenVmConsole
        // escape hatch, so they always require an operator-visible VM desktop
        // before payload/sample staging. The config field remains for backward
        // compatibility and status display, but it must not silently make live
        // execution headless.
        steps.Add(Step(
            "open-vm-desktop",
            "Open interactive Hyper-V VM desktop for operator interaction",
            BuildOpenInteractiveDesktopCommand(config, targetVmName),
            mutatesVmState: false));
    }

    /// <summary>
    /// Builds a bounded VM start loop. Inputs are the VM name; processing starts
    /// the VM, polls Hyper-V state with sparse human-readable heartbeats, and
    /// fails with the last state when the VM never reaches Running; the method
    /// returns a PowerShell command string for one runbook step.
    /// </summary>
    private static string BuildStartVmAndWaitCommand(string targetVmName)
    {
        const int startupTimeoutSeconds = 180;
        return string.Join(" ", new[]
        {
            $"$vmName = {Q(targetVmName)};",
            $"$deadline = (Get-Date).AddSeconds({startupTimeoutSeconds});",
            "$lastState = '';",
            "$ready = $false;",
            "Write-Host \"Starting VM '$vmName' and waiting for Hyper-V to report Running.\";",
            "Start-VM -Name $vmName -ErrorAction Stop;",
            "do {",
            "$vm = Get-VM -Name $vmName -ErrorAction Stop;",
            "$state = $vm.State.ToString();",
            "if ($state -ne $lastState) { Write-Host \"VM '$vmName' state: $state\"; $lastState = $state };",
            "if ($state -eq 'Running') { $ready = $true; break };",
            "Start-Sleep -Seconds 2;",
            "} while ((Get-Date) -lt $deadline);",
            $"if (-not $ready) {{ throw \"VM '$vmName' did not reach Running state within {startupTimeoutSeconds} seconds. Last state: $lastState\" }};",
            "Write-Host \"VM '$vmName' is running.\""
        });
    }

    /// <summary>
    /// Builds a host-side desktop launch command. Inputs are VMConnect/RDP
    /// config and target VM name; processing starts vmconnect.exe or mstsc.exe
    /// and fails the runbook if neither desktop path opens, preventing the
    /// sample from running without an operator-visible VM desktop.
    /// </summary>
    private static string BuildOpenInteractiveDesktopCommand(SandboxConfig config, string targetVmName)
    {
        var rdpTarget = config.HyperV.RdpTarget ?? string.Empty;
        return string.Join(" ", new[]
        {
            $"$vmName = {Q(targetVmName)};",
            $"$serverName = {Q(config.HyperV.VmConsoleServerName)};",
            $"$rdpFallbackEnabled = {PsBool(config.HyperV.RdpFallbackEnabled)};",
            $"$configuredRdpTarget = {Q(rdpTarget)};",
            "$messages = New-Object System.Collections.Generic.List[string];",
            "function Resolve-NativeCommand([string]$Name, [string[]]$Candidates) {",
            "$cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1;",
            "if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Source)) { return [string]$cmd.Source };",
            "foreach ($candidate in $Candidates) { if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return (Resolve-Path -LiteralPath $candidate).ProviderPath } };",
            "return '';",
            "};",
            "function Test-DesktopLauncherStillPresent($Process, [string]$LauncherName) {",
            "$processName = [System.IO.Path]::GetFileNameWithoutExtension($LauncherName);",
            "if ($null -ne $Process -and -not [string]::IsNullOrWhiteSpace($Process.ProcessName)) { $processName = $Process.ProcessName };",
            "Start-Sleep -Milliseconds 1200;",
            "if ($null -ne $Process) { try { $Process.Refresh(); if (-not $Process.HasExited) { return [pscustomobject]@{ Success = $true; Message = \"$LauncherName is still running after launch check.\" } } } catch { return [pscustomobject]@{ Success = $false; Message = \"$LauncherName launch verification failed: $($_.Exception.Message)\" } } };",
            "$windowProcess = Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero } | Select-Object -First 1;",
            "if ($null -ne $windowProcess) { return [pscustomobject]@{ Success = $true; Message = \"$LauncherName desktop window is present in process '$($windowProcess.ProcessName)' (PID $($windowProcess.Id)).\" } };",
            "if ($null -eq $Process) { return [pscustomobject]@{ Success = $false; Message = \"$LauncherName did not return a process handle and no desktop window was observed.\" } };",
            "if ($Process.HasExited) { return [pscustomobject]@{ Success = $false; Message = \"$LauncherName exited immediately with code $($Process.ExitCode); no durable interactive desktop window was observed.\" } };",
            "return [pscustomobject]@{ Success = $false; Message = \"$LauncherName launch verification did not observe a running process or desktop window.\" };",
            "};",
            "$systemRoot = if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) { 'C:\\Windows' } else { $env:SystemRoot };",
            "$vmconnect = Resolve-NativeCommand 'vmconnect.exe' @((Join-Path $systemRoot 'System32\\vmconnect.exe'), (Join-Path $systemRoot 'Sysnative\\vmconnect.exe'));",
            "if (-not [string]::IsNullOrWhiteSpace($vmconnect)) {",
            "try { $p = Start-Process -FilePath $vmconnect -ArgumentList @($serverName, $vmName) -WindowStyle Normal -PassThru -ErrorAction Stop; $check = Test-DesktopLauncherStillPresent $p 'vmconnect.exe'; if ($check.Success) { Write-Host \"Opened Hyper-V VMConnect desktop for VM '$vmName' (PID $($p.Id)). / 已打开 Hyper-V VM 桌面。\"; exit 0 } else { [void]$messages.Add(\"vmconnect.exe launch verification failed: $($check.Message)\") } }",
            "catch { [void]$messages.Add(\"vmconnect.exe failed: $($_.Exception.Message)\") }",
            "} else { [void]$messages.Add('vmconnect.exe was not found.') };",
            "if ($rdpFallbackEnabled) {",
            "$rdpTarget = $configuredRdpTarget;",
            "if ([string]::IsNullOrWhiteSpace($rdpTarget)) { try {",
            "$rdpTarget = @(Get-VMNetworkAdapter -VMName $vmName -ErrorAction Stop | ForEach-Object { $_.IPAddresses } | Where-Object { $t = [string]$_; $t -match '^(\\d{1,3}\\.){3}\\d{1,3}$' -and -not $t.StartsWith('169.254.') -and $t -ne '0.0.0.0' } | Select-Object -Unique -First 1)[0]",
            "} catch { [void]$messages.Add(\"RDP target discovery failed: $($_.Exception.Message)\") } };",
            "if (-not [string]::IsNullOrWhiteSpace($rdpTarget)) {",
            "$mstsc = Resolve-NativeCommand 'mstsc.exe' @((Join-Path $systemRoot 'System32\\mstsc.exe'), (Join-Path $systemRoot 'Sysnative\\mstsc.exe'));",
            "if (-not [string]::IsNullOrWhiteSpace($mstsc)) { try { $p = Start-Process -FilePath $mstsc -ArgumentList @('/v:' + $rdpTarget) -WindowStyle Normal -PassThru -ErrorAction Stop; $check = Test-DesktopLauncherStillPresent $p 'mstsc.exe'; if ($check.Success) { Write-Host \"Opened RDP desktop for '$rdpTarget' (PID $($p.Id)). / 已通过 RDP 打开 VM 桌面。\"; exit 0 } else { [void]$messages.Add(\"mstsc.exe launch verification failed: $($check.Message)\") } } catch { [void]$messages.Add(\"mstsc.exe failed: $($_.Exception.Message)\") } } else { [void]$messages.Add('mstsc.exe was not found.') }",
            "} else { [void]$messages.Add('RDP fallback skipped: no hyperV.rdpTarget and no VM IPv4 was discoverable.') }",
            "} else { [void]$messages.Add('RDP fallback disabled.') };",
            "$detail = $messages -join ' | ';",
            "throw \"Live analysis requires an interactive VM desktop before the sample starts, but VMConnect/RDP did not open. 修复建议：安装 Hyper-V 管理工具、确认 vmconnect.exe 可用，或设置 hyperV.rdpTarget 为 RDP/反代地址。 Details: $detail\""
        });
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
        steps.Add(Step("record-artifact-policy", "Record artifact collection policy", BuildRecordArtifactCollectionPolicyCommand(config, hostOut), requiresElevation: false, mutatesVmState: false));
        steps.Add(Step("prepare-guest-output", "Prepare job-specific guest output folder", BuildPrepareGuestOutputCommand(config, targetVmName, guestOut, driverEventsPath, agentPidPath, agentExitPath)));
        if (config.Driver.Enabled && !string.IsNullOrWhiteSpace(config.Driver.HostDriverPath))
        {
            steps.Add(Step("install-driver-service", "Install and start guest R0 driver service", BuildInstallDriverServiceCommand(config, targetVmName)));
        }

        steps.Add(Step("run-agent", "Start guest collector and sample asynchronously", BuildStartGuestAgentCommand(config, targetVmName, guestRoot, agentPath, guestSample, guestOut, driverEventsPath, agentPidPath, agentExitPath)));
        steps.Add(Step("sync-live-output", "Live-sync guest events while sample runs", BuildLiveOutputSyncCommand(config, targetVmName, guestOut, hostOut, agentPidPath, agentExitPath)));
        steps.Add(Step("collect-output", "Collect final guest JSON output", BuildCollectOutputCommand(config, targetVmName, guestOut, hostOut)));
    }

    /// <summary>
    /// Builds a host-only step that writes the resolved per-job artifact policy
    /// beside live guest output. Inputs are sandbox config and host output
    /// root; processing records enabled lanes, memory-dump scope semantics, and
    /// copy/download expectations before the guest starts; the method returns a
    /// PowerShell command string.
    /// </summary>
    private static string BuildRecordArtifactCollectionPolicyCommand(SandboxConfig config, string hostOut)
    {
        return string.Join(" ", new[]
        {
            $"$hostOut = {Q(hostOut)};",
            "New-Item -ItemType Directory -Force -Path $hostOut | Out-Null;",
            "$policyPath = Join-Path $hostOut 'artifact-collection-policy.json';",
            "$policy = [ordered]@{",
            $"collectDroppedFiles = {PsBool(config.ArtifactCollection.CollectDroppedFiles)};",
            $"captureScreenshots = {PsBool(config.ArtifactCollection.CaptureScreenshots)};",
            $"captureMemoryDumps = {PsBool(config.ArtifactCollection.CaptureMemoryDumps)};",
            $"capturePacketCapture = {PsBool(config.ArtifactCollection.CapturePacketCapture)};",
            "memoryDumpScope = 'sample-process-tree-descendants-if-supported';",
            "memoryDumpScopeZh = '启用内存转储时，Guest Agent 以样本进程树为边界，尽量包含已解析子进程/后代进程。';",
            "droppedFilesScope = 'new-or-modified-files-in-guest-diff';",
            "packetCaptureScope = 'guest-pcap-or-pcapng-artifact-if-supported';",
            "downloadExpectation = 'host artifact index should expose safe relative selectors only';",
            "policySource = 'resolved-sandbox-config-and-webui-overrides';",
            "generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')",
            "};",
            "$policy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $policyPath -Encoding UTF8;",
            "Write-Host \"Artifact collection policy written: $policyPath\";"
        });
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
            $"$guestPasswordText = [System.Environment]::GetEnvironmentVariable({Q(secretName)}, 'Process');",
            $"if ([string]::IsNullOrWhiteSpace($guestPasswordText)) {{ $guestPasswordText = [System.Environment]::GetEnvironmentVariable({Q(secretName)}, 'User') }};",
            $"if ([string]::IsNullOrWhiteSpace($guestPasswordText)) {{ $guestPasswordText = [System.Environment]::GetEnvironmentVariable({Q(secretName)}, 'Machine') }};",
            $"if ([string]::IsNullOrWhiteSpace($guestPasswordText)) {{ throw 'Guest password environment variable {secretName} is not set for this PowerShell step.' }};",
            "$guestPassword = [System.Security.SecureString]::new();",
            "foreach ($guestPasswordChar in $guestPasswordText.ToCharArray()) { $guestPassword.AppendChar($guestPasswordChar) };",
            "$guestPassword.MakeReadOnly();",
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
            "$timeoutSeconds = 300;",
            "$deadline = (Get-Date).AddSeconds(300);",
            "$nextHeartbeat = (Get-Date).AddSeconds(15);",
            "$lastError = '';",
            "$ready = $false;",
            "$attempt = 0;",
            $"Write-Host 'Waiting for PowerShell Direct in VM {targetVmName}.';",
            "do {",
            "$attempt++;",
            "try {",
            $"Invoke-Command -VMName {Q(targetVmName)} -Credential $guestCredential -ScriptBlock {{ $env:COMPUTERNAME }} | Out-Null;",
            "$ready = $true;",
            "}",
            "catch {",
            "$lastError = $_.Exception.Message;",
            "if ((Get-Date) -ge $nextHeartbeat) { Write-Host \"PowerShell Direct is still not ready after $attempt attempt(s). Last error: $lastError\"; $nextHeartbeat = (Get-Date).AddSeconds(15) };",
            "Start-Sleep -Seconds 3;",
            "}",
            "} while (-not $ready -and (Get-Date) -lt $deadline);",
            $"if (-not $ready) {{ throw \"PowerShell Direct did not become ready for VM {targetVmName} within $timeoutSeconds seconds. Last error: $lastError\" }};",
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

        if (config.Driver.Enabled && !config.Driver.UseMockCollector && string.IsNullOrWhiteSpace(config.Driver.HostDriverPath))
        {
            commands.Add("Write-Warning 'R0 live driver collection is enabled but driver.hostDriverPath is empty; no driver .sys will be copied and no install-driver-service step was generated. R0Collector will likely fail opening the configured device with deviceUnavailable/win32Error=2.';");
        }

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
        commands.Add("finally { if ($session) { try { Remove-PSSession $session -ErrorAction Stop } catch { Write-Warning \"PowerShell Direct session cleanup failed after payload staging; primary step status is preserved: $($_.Exception.Message)\" } } }");

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
    /// Builds a guest command that installs and starts the staged kernel driver.
    /// Inputs are the configured service name and guest .sys path; processing
    /// removes stale service state, creates a demand-start kernel service, and
    /// starts it before R0Collector opens the device; the method returns a
    /// PowerShell Direct command string.
    /// </summary>
    private static string BuildInstallDriverServiceCommand(SandboxConfig config, string targetVmName)
    {
        var command = string.Join(" ", new[]
        {
            $"$serviceName = {Q(config.Driver.ServiceName)};",
            $"$driverPath = {Q(config.Driver.DriverPathInGuest)};",
            "Invoke-Command -VMName " + Q(targetVmName) + " -Credential $guestCredential -ScriptBlock {",
            "param($serviceName, $driverPath)",
            "if (-not (Test-Path -LiteralPath $driverPath -PathType Leaf)) { throw \"Driver .sys was not staged: $driverPath\" }",
            "$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue;",
            "if ($existing) { & sc.exe stop $serviceName | Out-Null; Start-Sleep -Milliseconds 500; & sc.exe delete $serviceName | Out-Null; Start-Sleep -Milliseconds 500 }",
            "$createOutput = @(& sc.exe create $serviceName type= kernel start= demand binPath= $driverPath 2>&1);",
            "$createExitCode = $LASTEXITCODE;",
            "$createText = $createOutput -join ' ';",
            "Write-Host $createText;",
            "if ($createExitCode -ne 0) { throw \"sc.exe create failed for $serviceName with exit code $createExitCode. $createText\" }",
            "$startOutput = @(& sc.exe start $serviceName 2>&1);",
            "$startExitCode = $LASTEXITCODE;",
            "$startText = $startOutput -join ' ';",
            "Write-Host $startText;",
            "if ($startExitCode -ne 0 -and $startExitCode -ne 1056) { throw \"sc.exe start failed for $serviceName with exit code $startExitCode. $startText. If this is 577/1275, enable guest test-signing and use a trusted test-signed driver; if it is 2/3, verify the staged guest driver path.\" }",
            "Write-Host \"Driver service $serviceName is started or already running.\"",
            "} -ArgumentList $serviceName, $driverPath"
        });

        return WithGuestCredential(config, command);
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
        arguments.AddRange(BuildArtifactCollectionAgentArguments(config));
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
    /// Builds optional Guest Agent arguments for sensitive artifact collection.
    /// Inputs are typed sandbox config values that may come from WebUI
    /// per-job overrides; processing forwards only explicitly enabled lanes;
    /// the method returns PowerShell-safe flag tokens for the Guest Agent.
    /// </summary>
    private static List<string> BuildArtifactCollectionAgentArguments(SandboxConfig config)
    {
        var arguments = new List<string>();
        if (config.ArtifactCollection.CollectDroppedFiles)
        {
            arguments.Add("--collect-dropped-files");
        }

        if (config.ArtifactCollection.CaptureScreenshots)
        {
            arguments.Add("--screenshot");
        }

        if (config.ArtifactCollection.CaptureMemoryDumps)
        {
            arguments.Add("--memory-dump");
        }

        if (config.ArtifactCollection.CapturePacketCapture)
        {
            arguments.Add("--packet-capture");
        }

        return arguments;
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
        var hasSyncDeadline = !config.Analysis.DurationUnlimited && config.Analysis.DefaultDurationSeconds > 0;
        var maxSyncSeconds = hasSyncDeadline
            ? Math.Max(config.Analysis.DefaultDurationSeconds + 60, 90)
            : 0;
        var command = string.Join(" ", new[]
        {
            $"$session = New-PSSession -VMName {Q(targetVmName)} -Credential $guestCredential -ErrorAction Stop;",
            "try {",
            $"$guestOut = {Q(guestOut)};",
            $"$hostOut = {Q(hostOut)};",
            $"$pidPath = {Q(agentPidPath)};",
            $"$exitPath = {Q(agentExitPath)};",
            $"$hasSyncDeadline = ${hasSyncDeadline.ToString().ToLowerInvariant()};",
            $"$maxSyncSeconds = {maxSyncSeconds};",
            "$deadline = if ($hasSyncDeadline) { (Get-Date).AddSeconds($maxSyncSeconds) } else { [datetime]::MaxValue };",
            "$nextHeartbeat = (Get-Date).AddSeconds(15);",
            "$copyWarningCount = 0;",
            "$firstCopyWarning = '';",
            "New-Item -ItemType Directory -Force -Path $hostOut | Out-Null;",
            "$pidText = Invoke-Command -Session $session -ScriptBlock { param($path) if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-Content -LiteralPath $path -Raw).Trim() } else { '' } } -ArgumentList $pidPath -ErrorAction Stop;",
            "if ([string]::IsNullOrWhiteSpace([string]$pidText)) { throw \"Guest Agent pid marker was not found: $pidPath. The run-agent step may not have started the guest wrapper.\" };",
            "$guestAgentPid = 0;",
            "if (-not [int]::TryParse([string]$pidText, [ref]$guestAgentPid)) { throw \"Guest Agent pid marker was not an integer: '$pidText' ($pidPath)\" };",
            "Write-Host \"Live output sync is watching Guest Agent pid $guestAgentPid.\";",
            "do {",
            "try { Copy-Item -FromSession $session -Path $guestOut -Destination $hostOut -Recurse -Force -ErrorAction Stop } catch { if ($copyWarningCount -eq 0) { $firstCopyWarning = $_.Exception.Message }; $copyWarningCount++ };",
            "$running = Invoke-Command -Session $session -ScriptBlock { param($processId) if ($processId -le 0) { $false } else { [bool](Get-Process -Id $processId -ErrorAction SilentlyContinue) } } -ArgumentList $guestAgentPid -ErrorAction Stop;",
            "if ($running -and (Get-Date) -ge $nextHeartbeat) { Write-Host \"Guest Agent pid $guestAgentPid is still running; suppressed copy warning count: $copyWarningCount\"; $nextHeartbeat = (Get-Date).AddSeconds(15) };",
            "if ($running) { Start-Sleep -Seconds 2 }",
            "} while ($running -and (Get-Date) -lt $deadline);",
            "try { Copy-Item -FromSession $session -Path $guestOut -Destination $hostOut -Recurse -Force -ErrorAction Stop } catch { $copyContext = if ([string]::IsNullOrWhiteSpace($firstCopyWarning)) { '' } else { \" First periodic copy warning: $firstCopyWarning\" }; throw \"Final live output copy failed from '$guestOut' to '$hostOut': $($_.Exception.Message).$copyContext\" };",
            "if ($running -and $hasSyncDeadline) { throw \"Guest Agent process $guestAgentPid did not exit before the live-sync deadline ($maxSyncSeconds seconds). Suppressed copy warning count: $copyWarningCount\" }",
            "$exitText = Invoke-Command -Session $session -ScriptBlock { param($path) if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-Content -LiteralPath $path -Raw).Trim() } else { throw \"Guest Agent exit marker was not found: $path\" } } -ArgumentList $exitPath -ErrorAction Stop;",
            "$exitCode = 0;",
            "if (-not [int]::TryParse([string]$exitText, [ref]$exitCode)) { throw \"Guest Agent exit marker was not an integer: '$exitText' ($exitPath)\" };",
            "if ($exitCode -ne 0) { throw \"Guest Agent exited with code $exitCode. Check collected agent stdout/stderr and events.json under $hostOut.\" };",
            "if ($copyWarningCount -gt 0) { Write-Warning \"Live output sync suppressed $copyWarningCount periodic copy warning(s); final copy succeeded. First warning: $firstCopyWarning\" }",
            "}",
            "finally { if ($session) { try { Remove-PSSession $session -ErrorAction Stop } catch { Write-Warning \"PowerShell Direct session cleanup failed after live output sync; primary step status is preserved: $($_.Exception.Message)\" } } }"
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
        var command = string.Join(" ", new[]
        {
            $"$session = New-PSSession -VMName {Q(targetVmName)} -Credential $guestCredential -ErrorAction Stop;",
            "try {",
            $"$guestOut = {Q(guestOut)};",
            $"$hostOut = {Q(hostOut)};",
            "New-Item -ItemType Directory -Force -Path $hostOut | Out-Null;",
            "$guestOutputExists = Invoke-Command -Session $session -ScriptBlock { param($path) Test-Path -LiteralPath $path -PathType Container } -ArgumentList $guestOut -ErrorAction Stop;",
            "if (-not [bool]$guestOutputExists) { throw \"Guest output directory does not exist in the VM: $guestOut\" };",
            "Copy-Item -FromSession $session -Path $guestOut -Destination $hostOut -Recurse -Force -ErrorAction Stop;",
            "$hostGuestOut = Join-Path $hostOut (Split-Path -Leaf $guestOut);",
            "if (-not (Test-Path -LiteralPath $hostGuestOut -PathType Container) -and (Test-Path -LiteralPath (Join-Path $hostOut 'events.json') -PathType Leaf)) { $hostGuestOut = $hostOut };",
            "foreach ($requiredName in @('events.json', 'agent.pid', 'agent.exit')) {",
            "$requiredPath = Join-Path $hostGuestOut $requiredName;",
            "if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw \"Final guest output copy completed but required artifact is missing: $requiredName ($requiredPath)\" }",
            "};",
            "Write-Host \"Final guest output collected under $hostGuestOut.\"",
            "}",
            "finally { if ($session) { try { Remove-PSSession $session -ErrorAction Stop } catch { Write-Warning \"PowerShell Direct session cleanup failed after final output collection; primary step status is preserved: $($_.Exception.Message)\" } } }"
        });

        return WithGuestCredential(config, command);
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

    /// <summary>
    /// Converts a managed bool to a PowerShell literal.
    /// </summary>
    private static string PsBool(bool value) => value ? "$true" : "$false";
}
