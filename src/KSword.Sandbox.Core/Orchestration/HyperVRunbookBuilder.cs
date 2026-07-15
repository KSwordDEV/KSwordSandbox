using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Orchestration;

/// <summary>
/// Builds a deterministic provider-specific VM command plan for one sandbox analysis.
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
        var provider = config.Virtualization.Provider;
        ValidateProviderConfig(config, provider);
        var (targetVmName, usesTemporaryVm) = ResolveTargetVm(config, provider, jobId);

        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        var guestSample = $"{guestRoot}\\incoming\\{sample.FileName}";
        var guestOut = $"{guestRoot}\\out\\{jobId:N}";
        var hostOut = Path.Combine(config.Paths.RuntimeRoot, "jobs", jobId.ToString("N"), "guest");
        var steps = new List<SandboxRunbookStep>();

        AddPrerequisiteSteps(steps, config, provider);
        switch (provider)
        {
            case VirtualizationProvider.HyperV:
                if (usesTemporaryVm)
                {
                    AddDifferencingVmSteps(steps, config, targetVmName, jobId);
                }
                else
                {
                    AddCheckpointRestoreSteps(steps, config);
                }

                break;
            case VirtualizationProvider.VMware:
                AddVMwareRestoreAndStartSteps(steps, config);
                break;
            case VirtualizationProvider.Qemu:
                AddQemuRestoreAndStartSteps(steps, config, targetVmName, jobId);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(config), provider, "Unsupported virtualization provider.");
        }

        AddGuestExecutionSteps(steps, config, provider, targetVmName, sample, guestSample, guestOut, hostOut);
        AddCleanupSteps(steps, config, provider, usesTemporaryVm, targetVmName, jobId);

        if (provider is not VirtualizationProvider.HyperV)
        {
            steps = steps.Select(step => step with { RequiresElevation = false }).ToList();
        }

        return new SandboxRunbook
        {
            JobId = jobId,
            Provider = provider,
            TargetVmName = targetVmName,
            BaselineName = provider switch
            {
                VirtualizationProvider.HyperV => config.HyperV.GoldenSnapshotName,
                VirtualizationProvider.VMware => config.VMware.SnapshotName,
                VirtualizationProvider.Qemu when config.Qemu.UseOverlayDisk => "per-job-overlay",
                VirtualizationProvider.Qemu => config.Qemu.SnapshotName,
                _ => null
            },
            MachineDefinitionPath = provider switch
            {
                VirtualizationProvider.VMware => config.VMware.VmxPath,
                VirtualizationProvider.Qemu => config.Qemu.DiskImagePath,
                _ => null
            },
            QemuDiskFormat = provider is VirtualizationProvider.Qemu ? config.Qemu.DiskFormat : null,
            LiveExecutionLeasePath = Path.Combine(config.Paths.RuntimeRoot, "locks", "live-execution.lock"),
            UsesTemporaryVm = usesTemporaryVm,
            Steps = steps
        };
    }

    /// <summary>
    /// Adds read-only validation steps for the host environment.
    /// Inputs are an output list and config, processing appends PowerShell
    /// checks, and the method returns no value.
    /// </summary>
    private static void AddPrerequisiteSteps(List<SandboxRunbookStep> steps, SandboxConfig config, VirtualizationProvider provider)
    {
        switch (provider)
        {
            case VirtualizationProvider.HyperV:
                steps.Add(Step("check-hyperv", "Verify Hyper-V module", "Get-Command Get-VM | Out-Null", mutatesVmState: false));
                steps.Add(Step("check-golden-vm", "Verify golden VM exists", $"Get-VM -Name {Q(config.HyperV.GoldenVmName)} | Out-Null", mutatesVmState: false));
                break;
            case VirtualizationProvider.VMware:
                steps.Add(Step("check-vmware", "Verify VMware vmrun and VMX", BuildVMwarePrerequisiteCommand(config), mutatesVmState: false));
                break;
            case VirtualizationProvider.Qemu:
                steps.Add(Step("check-qemu", "Verify QEMU tools and disk image", BuildQemuPrerequisiteCommand(config), mutatesVmState: false));
                break;
        }

        if (config.Driver.Enabled && !config.Driver.UseMockCollector)
        {
            steps.Add(Step("check-r0-driver-config", "Verify real R0 driver host path", BuildR0DriverHostPathCheckCommand(config), requiresElevation: false, mutatesVmState: false));
        }

        steps.Add(Step("check-guest-credential", "Verify guest credential environment secret", BuildGuestCredentialPreamble(config) + " Write-Host 'Guest credential secret is available for this step.'", mutatesVmState: false));
    }

    private static (string TargetVmName, bool UsesTemporaryVm) ResolveTargetVm(
        SandboxConfig config,
        VirtualizationProvider provider,
        Guid jobId)
    {
        if (provider is VirtualizationProvider.HyperV)
        {
            var usesTemporaryVm = config.HyperV.UseDifferencingDisk && !string.IsNullOrWhiteSpace(config.HyperV.BaseVhdxPath);
            return usesTemporaryVm
                ? (BuildPerJobVmName(config.HyperV.TempVmPrefix, jobId), true)
                : (config.HyperV.GoldenVmName, false);
        }

        if (provider is VirtualizationProvider.VMware)
        {
            return (config.VMware.VmName, false);
        }

        var qemuName = config.Qemu.UseOverlayDisk
            ? BuildPerJobVmName(config.Qemu.VmName, jobId)
            : config.Qemu.VmName;
        return (qemuName, config.Qemu.UseOverlayDisk);
    }

    private static string BuildPerJobVmName(string prefix, Guid jobId)
    {
        const int maximumLength = 64;
        var suffix = $"-{jobId:N}";
        var maximumPrefixLength = maximumLength - suffix.Length;
        var normalizedPrefix = prefix.Trim();
        if (normalizedPrefix.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            normalizedPrefix = normalizedPrefix[..^suffix.Length].TrimEnd('-');
        }

        var boundedPrefix = normalizedPrefix[..Math.Min(normalizedPrefix.Length, maximumPrefixLength)];
        return $"{boundedPrefix}{suffix}";
    }

    private static void ValidateProviderConfig(SandboxConfig config, VirtualizationProvider provider)
    {
        if (string.IsNullOrWhiteSpace(config.Guest.UserName) || string.IsNullOrWhiteSpace(config.Guest.WorkingDirectory))
        {
            throw new InvalidOperationException("Guest userName and workingDirectory are required for VM orchestration.");
        }

        if (config.Analysis.GuestReadyTimeoutSeconds is < 1 or > 7200)
        {
            throw new InvalidOperationException("analysis.guestReadyTimeoutSeconds must be between 1 and 7200.");
        }

        if (provider is VirtualizationProvider.VMware &&
            (string.IsNullOrWhiteSpace(config.VMware.VmName) ||
             string.IsNullOrWhiteSpace(config.VMware.VmxPath) ||
             string.IsNullOrWhiteSpace(config.VMware.VmrunPath)))
        {
            throw new InvalidOperationException("VMware provider requires vmware.vmName, vmware.vmxPath, and vmware.vmrunPath.");
        }

        if (provider is VirtualizationProvider.VMware && string.IsNullOrWhiteSpace(config.VMware.SnapshotName))
        {
            throw new InvalidOperationException("VMware provider requires vmware.snapshotName.");
        }

        if (provider is VirtualizationProvider.VMware &&
            !string.Equals(config.VMware.VmType, "ws", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("VMware parity requires Workstation Pro with vmware.vmType=ws; VMware Player is not supported because it cannot satisfy the full-clone recovery contract.");
        }

        if (provider is VirtualizationProvider.Qemu &&
            (string.IsNullOrWhiteSpace(config.Qemu.VmName) ||
             string.IsNullOrWhiteSpace(config.Qemu.DiskImagePath) ||
             string.IsNullOrWhiteSpace(config.Qemu.QemuSystemPath) ||
             string.IsNullOrWhiteSpace(config.Qemu.QemuImgPath)))
        {
            throw new InvalidOperationException("QEMU provider requires qemu.vmName, qemu.diskImagePath, qemu.qemuSystemPath, and qemu.qemuImgPath.");
        }

        if (provider is VirtualizationProvider.Qemu && !config.Qemu.UseOverlayDisk && string.IsNullOrWhiteSpace(config.Qemu.SnapshotName))
        {
            throw new InvalidOperationException("QEMU snapshot mode requires qemu.snapshotName.");
        }

        if (provider is VirtualizationProvider.Qemu &&
            !config.Qemu.UseOverlayDisk &&
            !config.Qemu.DiskFormat.Equals("qcow2", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("QEMU internal snapshot mode requires qemu.diskFormat=qcow2; use overlay mode for raw, vhdx, or vmdk base images.");
        }

        if (provider is VirtualizationProvider.Qemu &&
            config.Qemu.DiskFormat is not ("qcow2" or "raw" or "vhdx" or "vmdk"))
        {
            throw new InvalidOperationException("qemu.diskFormat must be qcow2, raw, vhdx, or vmdk.");
        }

        if (provider is VirtualizationProvider.Qemu &&
            config.Qemu.DiskInterface is not ("virtio" or "ide" or "scsi"))
        {
            throw new InvalidOperationException("qemu.diskInterface must be virtio, ide, or scsi; if=none is not accepted because the managed disk would not be attached to a boot device.");
        }

        if (provider is VirtualizationProvider.Qemu && config.Qemu.MemoryMegabytes is < 256 or > 1048576)
        {
            throw new InvalidOperationException("qemu.memoryMegabytes must be between 256 and 1048576.");
        }

        if (provider is VirtualizationProvider.Qemu && config.Qemu.AdditionalArguments.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidOperationException("qemu.additionalArguments cannot contain empty values.");
        }

        if (provider is VirtualizationProvider.Qemu)
        {
            ValidateQemuProviderArguments(config.Qemu.AdditionalArguments, config.Qemu.GuestRemoting.AddressMode);
        }

        var guestRemoting = ResolveGuestRemotingConfig(config, provider);
        if (provider is VirtualizationProvider.VMware &&
            guestRemoting.AddressMode is not (GuestRemotingAddressMode.Configured or GuestRemotingAddressMode.VMwareTools))
        {
            throw new InvalidOperationException("VMware guestRemoting.addressMode must be Configured or VMwareTools.");
        }

        if (provider is VirtualizationProvider.Qemu &&
            guestRemoting.AddressMode is not (GuestRemotingAddressMode.Configured or GuestRemotingAddressMode.QemuUserNat))
        {
            throw new InvalidOperationException("QEMU guestRemoting.addressMode must be Configured or QemuUserNat.");
        }

        if (provider is not VirtualizationProvider.HyperV &&
            guestRemoting.AddressMode is GuestRemotingAddressMode.Configured &&
            string.IsNullOrWhiteSpace(guestRemoting.Address))
        {
            throw new InvalidOperationException($"{provider} provider requires guestRemoting.address when addressMode=Configured.");
        }

        if (provider is not VirtualizationProvider.HyperV &&
            guestRemoting.AddressMode is GuestRemotingAddressMode.VMwareTools or GuestRemotingAddressMode.QemuUserNat &&
            !guestRemoting.UseSsl)
        {
            throw new InvalidOperationException(
                $"{guestRemoting.AddressMode} automatic endpoint mode requires guestRemoting.useSsl=true so IP/loopback WinRM does not depend on the host-wide TrustedHosts setting.");
        }

        if (guestRemoting.Port is < 0 or > 65535)
        {
            throw new InvalidOperationException("The selected guest remoting port must be 0 or a valid TCP port (1-65535).");
        }

        if (provider is not VirtualizationProvider.HyperV &&
            !new[] { "Negotiate", "Basic", "CredSSP" }.Contains(guestRemoting.Authentication, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The selected guest remoting authentication must be Negotiate, Basic, or CredSSP.");
        }

        if (provider is not VirtualizationProvider.HyperV &&
            string.Equals(guestRemoting.Authentication, "Basic", StringComparison.OrdinalIgnoreCase) &&
            !guestRemoting.UseSsl)
        {
            throw new InvalidOperationException("Basic WinRM over HTTP is refused; configure guestRemoting.useSsl=true or use Negotiate/CredSSP.");
        }

        if (provider is not VirtualizationProvider.HyperV && guestRemoting.SkipCertificateChecks && !guestRemoting.UseSsl)
        {
            throw new InvalidOperationException("guestRemoting.skipCertificateChecks is valid only when guestRemoting.useSsl=true.");
        }
    }

    private static GuestRemotingConfig ResolveGuestRemotingConfig(SandboxConfig config, VirtualizationProvider provider)
    {
        var providerConfig = provider switch
        {
            VirtualizationProvider.VMware => config.VMware.GuestRemoting,
            VirtualizationProvider.Qemu => config.Qemu.GuestRemoting,
            _ => new GuestRemotingConfig()
        };
        if (provider is VirtualizationProvider.Qemu &&
            providerConfig.AddressMode is GuestRemotingAddressMode.QemuUserNat)
        {
            return providerConfig with
            {
                Address = "127.0.0.1",
                Port = ResolveQemuUserNatHostPort(providerConfig)
            };
        }

        if (providerConfig.AddressMode is not GuestRemotingAddressMode.Configured ||
            !string.IsNullOrWhiteSpace(providerConfig.Address))
        {
            return providerConfig;
        }

        return new GuestRemotingConfig
        {
            AddressMode = GuestRemotingAddressMode.Configured,
            Address = config.Guest.PowerShellRemotingAddress,
            Authentication = config.Guest.PowerShellRemotingAuthentication,
            UseSsl = config.Guest.PowerShellRemotingUseSsl,
            Port = config.Guest.PowerShellRemotingPort,
            SkipCertificateChecks = config.Guest.PowerShellRemotingSkipCertificateChecks
        };
    }

    private static int ResolveQemuUserNatHostPort(GuestRemotingConfig remoting) =>
        remoting.Port > 0 ? remoting.Port : remoting.UseSsl ? 55986 : 55985;

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

    private static string BuildVMwarePrerequisiteCommand(SandboxConfig config)
    {
        return string.Join(" ", new[]
        {
            BuildClearGuestSecretEnvironment(config),
            BuildNativeToolResolution("vmrun", config.VMware.VmrunPath, "VMware vmrun"),
            $"$vmxPath = {Q(config.VMware.VmxPath)};",
            $"$snapshotName = {Q(config.VMware.SnapshotName)};",
            $"$vmType = {Q(config.VMware.VmType)};",
            "if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) { throw \"VMware VMX file was not found: $vmxPath\" };",
            "$vmxPath = (Resolve-Path -LiteralPath $vmxPath).ProviderPath;",
            "$snapshotOutput = @(& $vmrun -T $vmType listSnapshots $vmxPath 2>&1);",
            "$snapshotExitCode = $LASTEXITCODE;",
            "if ($snapshotExitCode -ne 0) { throw \"vmrun listSnapshots failed with exit code $snapshotExitCode. $($snapshotOutput -join ' ')\" };",
            "if (-not ($snapshotOutput | Where-Object { ([string]$_).Trim() -eq $snapshotName })) { throw \"VMware snapshot '$snapshotName' was not found for $vmxPath.\" };",
            "Write-Host \"VMware vmrun, VMX, and clean snapshot are ready.\";"
        });
    }

    private static void AddVMwareRestoreAndStartSteps(List<SandboxRunbookStep> steps, SandboxConfig config)
    {
        var preamble = string.Join(" ", new[]
        {
            BuildClearGuestSecretEnvironment(config),
            BuildNativeToolResolution("vmrun", config.VMware.VmrunPath, "VMware vmrun"),
            $"$vmxPath = {Q(config.VMware.VmxPath)};",
            "if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) { throw \"VMware VMX file was not found: $vmxPath\" };",
            "$vmxPath = (Resolve-Path -LiteralPath $vmxPath).ProviderPath;",
            $"$vmType = {Q(config.VMware.VmType)};"
        });
        var stopCommand = string.Join(" ", new[]
        {
            preamble,
            "$runningOutput = @(& $vmrun -T $vmType list 2>&1);",
            "$listExitCode = $LASTEXITCODE;",
            "if ($listExitCode -ne 0) { throw \"vmrun list failed with exit code $listExitCode. $($runningOutput -join ' ')\" };",
            "if ($runningOutput | Where-Object { ([string]$_).Trim() -eq $vmxPath }) {",
            "$stopOutput = @(& $vmrun -T $vmType stop $vmxPath hard 2>&1);",
            "$stopExitCode = $LASTEXITCODE;",
            "if ($stopExitCode -ne 0) { throw \"vmrun stop failed with exit code $stopExitCode. $($stopOutput -join ' ')\" };",
            BuildVMwarePowerStateWaitCommand(expectedRunning: false, operation: "stop"),
            "} else { Write-Host 'VMware VM is already stopped.' };"
        });
        var restoreCommand = string.Join(" ", new[]
        {
            preamble,
            $"$snapshotName = {Q(config.VMware.SnapshotName)};",
            "$restoreOutput = @(& $vmrun -T $vmType revertToSnapshot $vmxPath $snapshotName 2>&1);",
            "$restoreExitCode = $LASTEXITCODE;",
            "if ($restoreExitCode -ne 0) { throw \"vmrun revertToSnapshot failed with exit code $restoreExitCode. $($restoreOutput -join ' ')\" };",
            "Write-Host \"VMware snapshot '$snapshotName' restored.\";"
        });
        var startMode = config.VMware.Headless ? "nogui" : "gui";
        var startCommand = string.Join(" ", new[]
        {
            preamble,
            $"$startOutput = @(& $vmrun -T $vmType start $vmxPath {startMode} 2>&1);",
            "$startExitCode = $LASTEXITCODE;",
            "if ($startExitCode -ne 0) { throw \"vmrun start failed with exit code $startExitCode. $($startOutput -join ' ')\" };",
            BuildVMwarePowerStateWaitCommand(expectedRunning: true, operation: "start"),
            $"Write-Host 'VMware VM started in {startMode} mode.';"
        });

        steps.Add(Step("stop-vm-before-restore", "Stop VMware VM before snapshot restore", stopCommand));
        steps.Add(Step("restore-vm-snapshot", "Restore clean VMware snapshot", restoreCommand));
        steps.Add(Step("start-vm", "Start VMware analysis VM", startCommand));
        if (!config.VMware.Headless)
        {
            steps.Add(Step("open-vm-desktop", "Verify interactive VMware console window", BuildVMwareConsoleVerificationCommand(config), mutatesVmState: false));
        }
        steps.Add(Step("wait-guest-remoting", "Wait for PowerShell remoting in VMware guest", BuildWaitGuestSessionCommand(config, VirtualizationProvider.VMware, config.VMware.VmName), mutatesVmState: false));
    }

    private static string BuildVMwarePowerStateWaitCommand(bool expectedRunning, string operation)
    {
        var expectedState = expectedRunning ? "running" : "stopped";
        var statePredicate = expectedRunning ? "$vmwareStateRunning" : "-not $vmwareStateRunning";
        return string.Join(" ", new[]
        {
            "$vmwareStateDeadline = (Get-Date).AddSeconds(60);",
            "$vmwareStateConfirmed = $false; $vmwareStateExitCode = $null; $vmwareStateOutput = @();",
            "do {",
            "$vmwareStateOutput = @(& $vmrun -T $vmType list 2>&1); $vmwareStateExitCode = $LASTEXITCODE;",
            "if ($vmwareStateExitCode -eq 0) {",
            "$vmwareStateRunning = @($vmwareStateOutput | Where-Object { ([string]$_).Trim() -eq $vmxPath }).Count -gt 0;",
            $"if ({statePredicate}) {{ $vmwareStateConfirmed = $true; break }};",
            "};",
            "Start-Sleep -Seconds 1;",
            "} while ((Get-Date) -lt $vmwareStateDeadline);",
            $"if (-not $vmwareStateConfirmed) {{ throw \"VMware VM did not reach {expectedState} state after vmrun {operation} within 60 seconds. Last vmrun list exit code: $vmwareStateExitCode. $($vmwareStateOutput -join ' ')\" }};"
        });
    }

    private static string BuildVMwareConsoleVerificationCommand(SandboxConfig config)
    {
        return string.Join(" ", new[]
        {
            BuildClearGuestSecretEnvironment(config),
            $"$vmxPath = {Q(config.VMware.VmxPath)};",
            "if (Test-Path -LiteralPath $vmxPath -PathType Leaf) { $vmxPath = (Resolve-Path -LiteralPath $vmxPath).ProviderPath };",
            $"$expectedVmName = {Q(config.VMware.VmName)};",
            "$expectedVmxStem = [System.IO.Path]::GetFileNameWithoutExtension($vmxPath);",
            "$vmwareUiProcessName = 'vmware';",
            "$windowDeadline = (Get-Date).AddSeconds(15); $vmwareWindow = $null;",
            "do { $vmwareWindow = Get-Process -Name $vmwareUiProcessName -ErrorAction SilentlyContinue | Where-Object { if ($_.MainWindowHandle -eq [IntPtr]::Zero) { return $false }; $title = [string]$_.MainWindowTitle; $processInfo = Get-CimInstance Win32_Process -Filter \"ProcessId = $($_.Id)\" -ErrorAction SilentlyContinue | Select-Object -First 1; $commandLine = [string]$processInfo.CommandLine; return ($title.IndexOf($expectedVmName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or $title.IndexOf($expectedVmxStem, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or (-not [string]::IsNullOrWhiteSpace($commandLine) -and $commandLine.IndexOf($vmxPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)) } | Select-Object -First 1; if ($null -eq $vmwareWindow) { Start-Sleep -Milliseconds 250 } } while ($null -eq $vmwareWindow -and (Get-Date) -lt $windowDeadline);",
            "if ($null -eq $vmwareWindow) { throw \"vmrun started the target VM but no target-associated VMware console window was observed within 15 seconds (expected VM '$expectedVmName', VMX '$vmxPath'). Use headless mode only when an operator console is intentionally disabled.\" };",
            "Write-Host \"VMware console window verified in process $($vmwareWindow.ProcessName) (PID $($vmwareWindow.Id)).\";"
        });
    }

    private static string BuildQemuPrerequisiteCommand(SandboxConfig config)
    {
        var parts = new List<string>
        {
            BuildClearGuestSecretEnvironment(config),
            BuildNativeToolResolution("qemuSystem", config.Qemu.QemuSystemPath, "qemu-system"),
            BuildNativeToolResolution("qemuImg", config.Qemu.QemuImgPath, "qemu-img"),
            $"$diskPath = {Q(config.Qemu.DiskImagePath)};",
            $"$configuredDiskFormat = {Q(config.Qemu.DiskFormat)};",
            "if (-not (Test-Path -LiteralPath $diskPath -PathType Leaf)) { throw \"QEMU disk image was not found: $diskPath\" };",
            "$imageInfoOutput = @(& $qemuImg info --output=json $diskPath 2>&1);",
            "$imageInfoExitCode = $LASTEXITCODE;",
            "if ($imageInfoExitCode -ne 0) { throw \"qemu-img info failed with exit code $imageInfoExitCode. $($imageInfoOutput -join ' ')\" };",
            "try { $imageInfo = ($imageInfoOutput -join \"`n\") | ConvertFrom-Json -ErrorAction Stop } catch { throw \"qemu-img returned invalid image JSON: $($_.Exception.Message)\" };",
            "$actualDiskFormat = [string]$imageInfo.format;",
            "if (-not $actualDiskFormat.Equals($configuredDiskFormat, [System.StringComparison]::OrdinalIgnoreCase)) { throw \"Configured QEMU disk format '$configuredDiskFormat' does not match qemu-img format '$actualDiskFormat'.\" };"
        };

        if (!config.Qemu.UseOverlayDisk)
        {
            parts.Add($"$snapshotName = {Q(config.Qemu.SnapshotName)};");
            parts.Add("$snapshotProperty = $imageInfo.PSObject.Properties['snapshots'];");
            parts.Add("$snapshotNames = if ($null -eq $snapshotProperty) { @() } else { @($snapshotProperty.Value | ForEach-Object { $nameProperty = $_.PSObject.Properties['name']; if ($null -ne $nameProperty) { [string]$nameProperty.Value } }) };");
            parts.Add("if ($snapshotNames -cnotcontains $snapshotName) { throw \"QEMU internal snapshot '$snapshotName' was not found in $diskPath.\" };");
        }

        parts.Add("Write-Host 'QEMU tools and disk image are ready.';");
        return string.Join(" ", parts);
    }

    private static void AddQemuRestoreAndStartSteps(
        List<SandboxRunbookStep> steps,
        SandboxConfig config,
        string targetVmName,
        Guid jobId)
    {
        var vmRoot = Path.Combine(config.Paths.RuntimeRoot, "vms", jobId.ToString("N"));
        var pidPath = Path.Combine(vmRoot, "qemu.pid");
        var diskPath = config.Qemu.DiskImagePath;
        steps.Add(Step(
            "stop-vm-before-restore",
            "Stop prior KSword QEMU analysis processes before baseline restore",
            BuildQemuStopExistingProcessesCommand(config)));
        steps.Add(Step("make-vm-root", "Create QEMU job folder", $"New-Item -ItemType Directory -Force -Path {Q(vmRoot)} | Out-Null"));

        if (config.Qemu.UseOverlayDisk)
        {
            diskPath = Path.Combine(vmRoot, $"{targetVmName}.qcow2");
            var overlayCommand = string.Join(" ", new[]
            {
                BuildClearGuestSecretEnvironment(config),
                BuildNativeToolResolution("qemuImg", config.Qemu.QemuImgPath, "qemu-img"),
                $"$baseDisk = {Q(config.Qemu.DiskImagePath)};",
                $"$overlayDisk = {Q(diskPath)};",
                $"$baseFormat = {Q(config.Qemu.DiskFormat)};",
                "$createOutput = @(& $qemuImg create -f qcow2 -F $baseFormat -b $baseDisk $overlayDisk 2>&1);",
                "$createExitCode = $LASTEXITCODE;",
                "if ($createExitCode -ne 0) { throw \"qemu-img overlay creation failed with exit code $createExitCode. $($createOutput -join ' ')\" };",
                "if (-not (Test-Path -LiteralPath $overlayDisk -PathType Leaf)) { throw \"QEMU overlay was not created: $overlayDisk\" };"
            });
            steps.Add(Step("make-overlay-disk", "Create disposable QEMU overlay disk", overlayCommand));
        }
        else
        {
            var restoreCommand = string.Join(" ", new[]
            {
                BuildClearGuestSecretEnvironment(config),
                BuildNativeToolResolution("qemuImg", config.Qemu.QemuImgPath, "qemu-img"),
                $"$diskPath = {Q(diskPath)};",
                $"$snapshotName = {Q(config.Qemu.SnapshotName)};",
                "$restoreOutput = @(& $qemuImg snapshot -a $snapshotName $diskPath 2>&1);",
                "$restoreExitCode = $LASTEXITCODE;",
                "if ($restoreExitCode -ne 0) { throw \"qemu-img snapshot restore failed with exit code $restoreExitCode. $($restoreOutput -join ' ')\" };"
            });
            steps.Add(Step("restore-vm-snapshot", "Restore clean QEMU internal snapshot", restoreCommand));
        }

        steps.Add(Step("start-vm", "Start QEMU analysis VM", BuildQemuStartCommand(config, targetVmName, diskPath, pidPath)));
        if (!config.Qemu.Headless)
        {
            steps.Add(Step("open-vm-desktop", "Verify interactive QEMU display window", BuildQemuDisplayVerificationCommand(config, targetVmName, diskPath, pidPath), mutatesVmState: false));
        }
        steps.Add(Step("wait-guest-remoting", "Wait for PowerShell remoting in QEMU guest", BuildWaitGuestSessionCommand(config, VirtualizationProvider.Qemu, targetVmName), mutatesVmState: false));
    }

    /// <summary>
    /// Stops only QEMU processes proven by a native pidfile under this sandbox
    /// runtime. Disk/runtime matches without that ownership marker fail closed,
    /// preserving the stop-before-restore lifecycle without terminating unrelated VMs.
    /// </summary>
    private static string BuildQemuStopExistingProcessesCommand(SandboxConfig config)
    {
        var vmsRoot = Path.Combine(config.Paths.RuntimeRoot, "vms");
        var commandParts = new List<string>
        {
            BuildClearGuestSecretEnvironment(config),
            BuildNativeToolResolution("qemuSystem", config.Qemu.QemuSystemPath, "qemu-system"),
            $"$baseDisk = {Q(config.Qemu.DiskImagePath)};",
            $"$vmsRoot = {Q(vmsRoot)};",
            "$baseDisk = if (Test-Path -LiteralPath $baseDisk -PathType Leaf) { (Resolve-Path -LiteralPath $baseDisk).ProviderPath } else { [System.IO.Path]::GetFullPath($baseDisk) };",
            "$baseDiskArgument = $baseDisk.Replace(',', ',,');",
            "$qemuExecutableName = [System.IO.Path]::GetFileName($qemuSystem);",
            "$qemuExecutablePath = [System.IO.Path]::GetFullPath($qemuSystem);",
            "$qemuProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { ([string]$_.Name).Equals($qemuExecutableName, [System.StringComparison]::OrdinalIgnoreCase) });",
            "$stoppedPids = [System.Collections.Generic.HashSet[int]]::new();",
            "if (Test-Path -LiteralPath $vmsRoot -PathType Container) {",
            "foreach ($pidFile in @(Get-ChildItem -LiteralPath $vmsRoot -Filter 'qemu.pid' -File -Recurse -ErrorAction SilentlyContinue)) {",
            "$pidText = ([string](Get-Content -LiteralPath $pidFile.FullName -Raw -ErrorAction SilentlyContinue)).Trim();",
            "$qemuPid = 0;",
            "if (-not [int]::TryParse($pidText, [ref]$qemuPid)) { throw \"Invalid QEMU pid marker '$($pidFile.FullName)'; baseline restore was aborted because process ownership cannot be verified.\" };",
            "$jobRoot = Split-Path -Parent $pidFile.FullName;",
            "$candidate = $qemuProcesses | Where-Object { [int]$_.ProcessId -eq $qemuPid } | Select-Object -First 1;",
            "if ($null -eq $candidate) { Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue; continue };",
            "$markerWrittenUtc = (Get-Item -LiteralPath $pidFile.FullName -ErrorAction Stop).LastWriteTimeUtc;",
            "$processStartedUtc = ([datetime]$candidate.CreationDate).ToUniversalTime();",
            "$markerMatchesProcessInstance = $processStartedUtc -ge $markerWrittenUtc.AddSeconds(-5) -and $processStartedUtc -le $markerWrittenUtc.AddSeconds(5);",
            "if (-not $markerMatchesProcessInstance) { throw \"QEMU pid marker '$($pidFile.FullName)' points to reused pid $qemuPid; baseline restore was aborted because the process instance start time does not match the marker.\" };",
            "$commandLine = [string]$candidate.CommandLine;",
            "if ([string]::IsNullOrWhiteSpace($commandLine)) { throw \"Cannot inspect the command line for QEMU process $qemuPid; baseline restore was aborted. Run with permission to query Win32_Process.CommandLine.\" };",
            "$candidateExecutablePath = [string]$candidate.ExecutablePath;",
            "$owned = -not [string]::IsNullOrWhiteSpace($candidateExecutablePath) -and $candidateExecutablePath.Equals($qemuExecutablePath, [System.StringComparison]::OrdinalIgnoreCase) -and $commandLine.IndexOf($pidFile.FullName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $commandLine.IndexOf($jobRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0;",
            "if (-not $owned) { throw \"QEMU pid marker '$($pidFile.FullName)' points to process $qemuPid, but its executable/pidfile/runtime identity does not match this provider-managed job; baseline restore was aborted.\" };",
            "Stop-Process -Id $qemuPid -Force -ErrorAction Stop; $stopDeadline = (Get-Date).AddSeconds(30); while ((Get-Process -Id $qemuPid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $stopDeadline) { Start-Sleep -Milliseconds 200 }; if (Get-Process -Id $qemuPid -ErrorAction SilentlyContinue) { throw \"QEMU process $qemuPid did not exit within 30 seconds.\" }; [void]$stoppedPids.Add($qemuPid);",
            "Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue;",
            "}",
            "};",
            "foreach ($candidate in $qemuProcesses) {",
            "$candidatePid = [int]$candidate.ProcessId; if ($stoppedPids.Contains($candidatePid)) { continue };",
            "$commandLine = [string]$candidate.CommandLine;",
            "if ([string]::IsNullOrWhiteSpace($commandLine)) { throw \"Cannot inspect the command line for QEMU process $candidatePid; baseline restore was aborted. Run with permission to query Win32_Process.CommandLine.\" };",
            "$usesRuntimeRoot = $commandLine.IndexOf($vmsRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0;",
            "$usesBaseDisk = $commandLine.IndexOf($baseDisk, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or $commandLine.IndexOf($baseDiskArgument, [System.StringComparison]::OrdinalIgnoreCase) -ge 0;",
            "if (-not $usesRuntimeRoot -and -not $usesBaseDisk) { continue };",
            "throw \"QEMU baseline restore found an unowned process $candidatePid using the managed runtime/base disk without a valid native qemu.pid ownership marker and refused to stop it. Close that process manually before retrying.\";",
            "};",
            "Write-Host \"Stopped $($stoppedPids.Count) prior KSword QEMU analysis process(es).\";"
        };
        return string.Join(" ", commandParts);
    }

    private static string BuildQemuStartCommand(SandboxConfig config, string targetVmName, string diskPath, string pidPath)
    {
        var diskFormat = config.Qemu.UseOverlayDisk ? "qcow2" : config.Qemu.DiskFormat;
        var arguments = new List<string>
        {
            "-name", targetVmName,
            "-m", config.Qemu.MemoryMegabytes.ToString(),
            "-pidfile", pidPath
        };
        arguments.AddRange(BuildQemuManagedDiskArguments(diskPath, diskFormat, config.Qemu.DiskInterface));
        if (config.Qemu.Headless)
        {
            arguments.AddRange(["-display", "none"]);
        }

        var guestRemoting = ResolveGuestRemotingConfig(config, VirtualizationProvider.Qemu);
        if (guestRemoting.AddressMode is GuestRemotingAddressMode.QemuUserNat)
        {
            var hostPort = ResolveQemuUserNatHostPort(guestRemoting);
            var guestPort = guestRemoting.UseSsl ? 5986 : 5985;
            arguments.AddRange([
                "-netdev", $"user,id=ksword-net,hostfwd=tcp:127.0.0.1:{hostPort}-:{guestPort}",
                "-device", "e1000,netdev=ksword-net"
            ]);
        }

        if (!ValidateQemuWhpxAcceleration(config.Qemu.AdditionalArguments))
        {
            arguments.AddRange(["-accel", "whpx"]);
        }
        arguments.AddRange(config.Qemu.AdditionalArguments);
        var argumentArray = string.Join(", ", arguments.Select(Q));
        var commandParts = new List<string>
        {
            BuildClearGuestSecretEnvironment(config),
            BuildNativeToolResolution("qemuSystem", config.Qemu.QemuSystemPath, "qemu-system"),
            $"$pidPath = {Q(pidPath)};",
            "$qemuRuntimeRoot = Split-Path -Parent $pidPath;",
            "$qemuStdoutPath = Join-Path $qemuRuntimeRoot 'qemu.stdout.log'; $qemuStderrPath = Join-Path $qemuRuntimeRoot 'qemu.stderr.log';",
            "Remove-Item -LiteralPath @($pidPath, $qemuStdoutPath, $qemuStderrPath) -Force -ErrorAction SilentlyContinue;",
            $"$qemuArguments = @({argumentArray});",
            "function ConvertTo-NativeArgument([string]$Value) { if ($Value -notmatch '[\\s\"]') { return $Value }; return '\"' + $Value.Replace('\"', '\\\"') + '\"' };",
            "function Stop-NewQemuProcess([System.Diagnostics.Process]$StartedProcess) { if ($null -eq $StartedProcess) { return }; try { $StartedProcess.Refresh() } catch { return }; if ($StartedProcess.HasExited) { return }; Stop-Process -Id $StartedProcess.Id -Force -ErrorAction Stop; $stopDeadline = (Get-Date).AddSeconds(30); while ((Get-Process -Id $StartedProcess.Id -ErrorAction SilentlyContinue) -and (Get-Date) -lt $stopDeadline) { Start-Sleep -Milliseconds 200 }; if (Get-Process -Id $StartedProcess.Id -ErrorAction SilentlyContinue) { throw \"process $($StartedProcess.Id) did not exit within 30 seconds\" } };",
            "$argumentLine = ($qemuArguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' ';"
        };
        if (guestRemoting.AddressMode is GuestRemotingAddressMode.QemuUserNat)
        {
            var hostPort = ResolveQemuUserNatHostPort(guestRemoting);
            commandParts.Add("$portProbe = $null;");
            commandParts.Add($"try {{ $portProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, {hostPort}); $portProbe.ExclusiveAddressUse = $true; $portProbe.Start() }} catch {{ throw \"QEMU WinRM host-forward port {hostPort} on 127.0.0.1 is unavailable after managed-process cleanup. Stop the conflicting listener or configure another guestRemoting.port. No QEMU process was started. $($_.Exception.Message)\" }} finally {{ if ($null -ne $portProbe) {{ $portProbe.Stop() }} }};");
        }

        commandParts.AddRange([
            "$process = Start-Process -FilePath $qemuSystem -ArgumentList $argumentLine -RedirectStandardOutput $qemuStdoutPath -RedirectStandardError $qemuStderrPath -PassThru -ErrorAction Stop;",
            "Start-Sleep -Seconds 2;",
            "$process.Refresh();",
            "if ($process.HasExited) { $process.WaitForExit(); $qemuDiagnosticLines = @(); foreach ($diagnosticPath in @($qemuStderrPath, $qemuStdoutPath)) { if (Test-Path -LiteralPath $diagnosticPath -PathType Leaf) { $qemuDiagnosticLines += @(Get-Content -LiteralPath $diagnosticPath -Tail 20 -ErrorAction SilentlyContinue) } }; $qemuDiagnosticText = ($qemuDiagnosticLines -join ' ').Trim(); if ($qemuDiagnosticText.Length -gt 2048) { $qemuDiagnosticText = $qemuDiagnosticText.Substring(0, 2048) }; if ([string]::IsNullOrWhiteSpace($qemuDiagnosticText)) { $qemuDiagnosticText = 'No provider output was captured.' }; throw \"QEMU exited during startup with code $($process.ExitCode). Provider output: $qemuDiagnosticText Check the WinRM host-forward port, WHPX, disk interface/format, firmware, and device arguments.\" };",
            "$nativePidDeadline = (Get-Date).AddSeconds(10); while (-not (Test-Path -LiteralPath $pidPath -PathType Leaf) -and -not $process.HasExited -and (Get-Date) -lt $nativePidDeadline) { Start-Sleep -Milliseconds 100; $process.Refresh() };",
            "if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) { $markerError = \"QEMU did not publish its native -pidfile marker within 10 seconds: $pidPath\"; try { Stop-NewQemuProcess $process } catch { throw \"$markerError; the newly started process could not be stopped: $($_.Exception.Message)\" }; throw \"$markerError; the newly started process was stopped.\" };",
            "$nativePidText = (Get-Content -LiteralPath $pidPath -Raw -ErrorAction Stop).Trim(); $nativePid = 0; if (-not [int]::TryParse($nativePidText, [ref]$nativePid) -or $nativePid -le 0 -or $nativePid -ne $process.Id) { $markerError = \"QEMU native -pidfile marker '$pidPath' contains '$nativePidText', which does not match newly started process $($process.Id)\"; try { Stop-NewQemuProcess $process } catch { throw \"$markerError; the newly started process could not be stopped: $($_.Exception.Message)\" }; Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue; throw \"$markerError; the newly started process was stopped.\" };",
            "$markerWrittenUtc = (Get-Item -LiteralPath $pidPath -ErrorAction Stop).LastWriteTimeUtc; $processStartedUtc = $process.StartTime.ToUniversalTime(); if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) { $markerError = \"QEMU native -pidfile marker '$pidPath' does not match the newly started process time\"; try { Stop-NewQemuProcess $process } catch { throw \"$markerError; the newly started process could not be stopped: $($_.Exception.Message)\" }; Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue; throw \"$markerError; the newly started process was stopped.\" };",
            "Write-Host \"QEMU started with pid $($process.Id).\";"
        ]);
        return string.Join(" ", commandParts);
    }

    private static IReadOnlyList<string> BuildQemuManagedDiskArguments(
        string diskPath,
        string diskFormat,
        string diskInterface)
    {
        var drivePath = EscapeQemuDriveOptionValue(diskPath);
        if (diskInterface.Equals("scsi", StringComparison.OrdinalIgnoreCase))
        {
            return [
                "-drive", $"file={drivePath},if=none,format={diskFormat},id=ksword-disk",
                "-device", "virtio-scsi-pci,id=ksword-scsi",
                "-device", "scsi-hd,drive=ksword-disk,bus=ksword-scsi.0"
            ];
        }

        return [
            "-drive", $"file={drivePath},if={diskInterface},format={diskFormat},id=ksword-disk"
        ];
    }

    private static bool ValidateQemuWhpxAcceleration(IReadOnlyList<string> arguments)
    {
        var acceleratorConfigured = false;
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index].Trim();
            if (argument.Equals("-accel", StringComparison.OrdinalIgnoreCase))
            {
                if (++index >= arguments.Count)
                {
                    throw new InvalidOperationException("qemu.additionalArguments '-accel' requires the value 'whpx'.");
                }

                ValidateQemuAcceleratorValue(arguments[index]);
                acceleratorConfigured = true;
                continue;
            }

            if (argument.StartsWith("-accel=", StringComparison.OrdinalIgnoreCase))
            {
                ValidateQemuAcceleratorValue(argument["-accel=".Length..]);
                acceleratorConfigured = true;
                continue;
            }

            string? machineValue = null;
            if (argument.Equals("-machine", StringComparison.OrdinalIgnoreCase) ||
                argument.Equals("-M", StringComparison.Ordinal))
            {
                if (index + 1 >= arguments.Count)
                {
                    throw new InvalidOperationException($"qemu.additionalArguments '{argument}' requires a machine value.");
                }
                machineValue = arguments[index + 1];
            }
            else if (argument.StartsWith("-machine=", StringComparison.OrdinalIgnoreCase))
            {
                machineValue = argument["-machine=".Length..];
            }
            else if (argument.StartsWith("-M=", StringComparison.Ordinal))
            {
                machineValue = argument["-M=".Length..];
            }

            if (string.IsNullOrWhiteSpace(machineValue))
            {
                if (argument.StartsWith("-machine=", StringComparison.OrdinalIgnoreCase) ||
                    argument.StartsWith("-M=", StringComparison.Ordinal))
                {
                    throw new InvalidOperationException($"qemu.additionalArguments '{argument}' requires a machine value.");
                }
                continue;
            }

            var machineAccelerator = machineValue
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault(value => value.StartsWith("accel=", StringComparison.OrdinalIgnoreCase));
            if (machineAccelerator is null)
            {
                continue;
            }

            ValidateQemuAcceleratorValue(machineAccelerator["accel=".Length..]);
            acceleratorConfigured = true;
        }

        return acceleratorConfigured;
    }

    /// <summary>
    /// Validates QEMU arguments shared by runbook planning and read-only Web
    /// readiness. It performs no process launch or VM mutation.
    /// </summary>
    public static void ValidateQemuProviderArguments(
        IReadOnlyList<string> arguments,
        GuestRemotingAddressMode addressMode = GuestRemotingAddressMode.Configured)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Any(string.IsNullOrWhiteSpace))
        {
            throw new InvalidOperationException("qemu.additionalArguments cannot contain empty values.");
        }

        ValidateQemuManagedArguments(arguments, addressMode);
        ValidateQemuWhpxAcceleration(arguments);
    }

    private static void ValidateQemuManagedArguments(
        IReadOnlyList<string> arguments,
        GuestRemotingAddressMode addressMode)
    {
        for (var index = 0; index < arguments.Count; index++)
        {
            var argument = arguments[index].Trim();
            var option = argument.Split('=', 2, StringSplitOptions.TrimEntries)[0];
            if (option is "-name" or "-m" or "-memory" or "-pidfile" or "-display")
            {
                throw new InvalidOperationException(
                    $"qemu.additionalArguments cannot set '{option}'; VM identity, memory, PID ownership, and display mode are managed by the QEMU provider profile.");
            }

            if (argument is "-daemonize" or "-snapshot" or "-nographic" or "-curses" or "-S")
            {
                throw new InvalidOperationException(
                    $"qemu.additionalArguments cannot contain '{argument}' because it bypasses provider lifecycle, baseline, or interactive-console guarantees.");
            }

            string? driveValue = null;
            if (argument.Equals("-drive", StringComparison.Ordinal))
            {
                if (index + 1 >= arguments.Count || string.IsNullOrWhiteSpace(arguments[index + 1]))
                {
                    throw new InvalidOperationException("qemu.additionalArguments '-drive' requires a non-empty drive value.");
                }
                driveValue = arguments[index + 1];
            }
            else if (argument.StartsWith("-drive=", StringComparison.Ordinal))
            {
                driveValue = argument["-drive=".Length..];
            }

            if (driveValue is not null && driveValue
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Any(part => part.Equals("id=ksword-disk", StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException(
                    "qemu.additionalArguments cannot define a second drive with id=ksword-disk; that stable disk identity is managed by the provider.");
            }

            if (argument.Contains("id=ksword-scsi", StringComparison.OrdinalIgnoreCase) ||
                argument.Contains("bus=ksword-scsi.0", StringComparison.OrdinalIgnoreCase) ||
                argument.Contains("drive=ksword-disk", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "qemu.additionalArguments cannot reuse id=ksword-scsi, bus=ksword-scsi.0, or drive=ksword-disk; the managed SCSI topology is reserved by the provider.");
            }

            if (addressMode is GuestRemotingAddressMode.QemuUserNat &&
                (argument.Contains("id=ksword-net", StringComparison.OrdinalIgnoreCase) ||
                 argument.Contains("netdev=ksword-net", StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException(
                    "qemu.additionalArguments cannot reuse id/netdev=ksword-net when guestRemoting.addressMode=QemuUserNat; that user-NAT NIC and WinRM forwarding rule are managed by the provider.");
            }
        }
    }

    private static void ValidateQemuAcceleratorValue(string value)
    {
        var accelerator = value.Split(',', 2, StringSplitOptions.TrimEntries)[0];
        if (!accelerator.Equals("whpx", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"qemu accelerator '{accelerator}' is not supported for Hyper-V-equivalent Windows live execution; use '-accel whpx'. TCG software emulation is not treated as provider parity.");
        }
    }

    private static string EscapeQemuDriveOptionValue(string value) => value.Replace(",", ",,");

    private static string BuildQemuDisplayVerificationCommand(SandboxConfig config, string targetVmName, string diskPath, string pidPath)
    {
        return string.Join(" ", new[]
        {
            BuildClearGuestSecretEnvironment(config),
            BuildNativeToolResolution("qemuSystem", config.Qemu.QemuSystemPath, "qemu-system"),
            $"$pidPath = {Q(pidPath)};",
            $"$expectedVmName = {Q(targetVmName)};",
            $"$expectedDiskPath = {Q(diskPath)};",
            "$vmRoot = Split-Path -Parent $pidPath;",
            "$expectedDiskArgumentPath = $expectedDiskPath.Replace(',', ',,');",
            "if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) { throw \"QEMU display verification requires the current job pid marker: $pidPath\" };",
            "$pidText = (Get-Content -LiteralPath $pidPath -Raw -ErrorAction Stop).Trim(); $qemuPid = 0; if (-not [int]::TryParse($pidText, [ref]$qemuPid) -or $qemuPid -le 0) { throw \"Invalid QEMU pid marker '$pidPath'; display verification stopped.\" };",
            "$processInfo = Get-CimInstance Win32_Process -Filter \"ProcessId = $qemuPid\" -ErrorAction Stop | Select-Object -First 1; if ($null -eq $processInfo) { throw \"QEMU display verification could not find pid $qemuPid from marker '$pidPath'.\" }; $commandLine = [string]$processInfo.CommandLine; $processExecutablePath = [string]$processInfo.ExecutablePath; $expectedProcessName = [System.IO.Path]::GetFileName($qemuSystem); $expectedExecutablePath = [System.IO.Path]::GetFullPath($qemuSystem);",
            "$markerWrittenUtc = (Get-Item -LiteralPath $pidPath -ErrorAction Stop).LastWriteTimeUtc; $processStartedUtc = ([datetime]$processInfo.CreationDate).ToUniversalTime(); if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) { throw \"QEMU display verification refused reused pid $qemuPid because the process instance start time does not match marker '$pidPath'.\" };",
            "$owned = $null -ne $processInfo -and ([string]$processInfo.Name).Equals($expectedProcessName, [System.StringComparison]::OrdinalIgnoreCase) -and -not [string]::IsNullOrWhiteSpace($processExecutablePath) -and $processExecutablePath.Equals($expectedExecutablePath, [System.StringComparison]::OrdinalIgnoreCase) -and -not [string]::IsNullOrWhiteSpace($commandLine) -and $commandLine.IndexOf($pidPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $commandLine.IndexOf($vmRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $commandLine.IndexOf($expectedVmName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and ($commandLine.IndexOf($expectedDiskPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or $commandLine.IndexOf($expectedDiskArgumentPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0); if (-not $owned) { throw \"QEMU display verification refused pid $qemuPid because its executable/pidfile/runtime/VM/disk identity does not match this job.\" };",
            "$process = Get-Process -Id $qemuPid -ErrorAction Stop; $windowDeadline = (Get-Date).AddSeconds(15); do { $process.Refresh(); if (-not $process.HasExited -and $process.MainWindowHandle -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 250 } } while (-not $process.HasExited -and $process.MainWindowHandle -eq [IntPtr]::Zero -and (Get-Date) -lt $windowDeadline);",
            "$process.Refresh(); if ($process.HasExited) { throw \"QEMU exited while waiting for its display window with code $($process.ExitCode).\" }; if ($process.MainWindowHandle -eq [IntPtr]::Zero) { throw 'QEMU process is running but no display window was observed within 15 seconds. Check display arguments or use headless mode intentionally.' };",
            "Write-Host \"QEMU display window verified for pid $($process.Id).\";"
        });
    }

    private static string BuildNativeToolResolution(string variableName, string configuredPath, string displayName)
    {
        var configuredVariable = $"${variableName}Configured";
        var commandVariable = $"${variableName}Command";
        var resultVariable = $"${variableName}";
        return string.Join(" ", new[]
        {
            $"{configuredVariable} = {Q(configuredPath)};",
            $"{commandVariable} = Get-Command -Name {configuredVariable} -ErrorAction SilentlyContinue | Select-Object -First 1;",
            $"{resultVariable} = if ($null -ne {commandVariable} -and -not [string]::IsNullOrWhiteSpace([string]{commandVariable}.Source)) {{ [string]{commandVariable}.Source }} elseif (Test-Path -LiteralPath {configuredVariable} -PathType Leaf) {{ (Resolve-Path -LiteralPath {configuredVariable}).ProviderPath }} else {{ '' }};",
            $"if ([string]::IsNullOrWhiteSpace({resultVariable})) {{ throw {Q($"{displayName} executable was not found: {configuredPath}")} }};"
        });
    }

    private static string BuildClearGuestSecretEnvironment(SandboxConfig config)
    {
        return string.Join(" ", new[]
        {
            $"[System.Environment]::SetEnvironmentVariable({Q(config.Guest.PasswordSecretName)}, $null, 'Process');",
            "$providerEnvironment = [System.Environment]::GetEnvironmentVariables('Process');",
            "foreach ($providerEnvironmentKey in @($providerEnvironment.Keys)) {",
            "$providerEnvironmentName = [string]$providerEnvironmentKey;",
            "if ($providerEnvironmentName.StartsWith('KSWORDBOX_', [System.StringComparison]::OrdinalIgnoreCase) -or $providerEnvironmentName -match '(?i)(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)') { [System.Environment]::SetEnvironmentVariable($providerEnvironmentName, $null, 'Process') }",
            "};"
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
        steps.Add(Step("wait-powershell-direct", "Wait for PowerShell Direct in guest", BuildWaitGuestSessionCommand(config, VirtualizationProvider.HyperV, targetVmName), mutatesVmState: false));
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
        steps.Add(Step("wait-powershell-direct", "Wait for PowerShell Direct in guest", BuildWaitGuestSessionCommand(config, VirtualizationProvider.HyperV, config.HyperV.GoldenVmName), mutatesVmState: false));
    }

    /// <summary>
    /// Adds the operator-interaction desktop step. Inputs are Hyper-V/RDP
    /// settings and target VM name; processing opens VMConnect first and falls
    /// back to mstsc/RDP when configured or discoverable; the method appends a
    /// required step before any sample copy/execution happens.
    /// </summary>
    private static void AddOpenInteractiveDesktopStep(List<SandboxRunbookStep> steps, SandboxConfig config, string targetVmName)
    {
        if (!config.HyperV.OpenVmConsoleOnLiveStart)
        {
            return;
        }

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
    /// processing appends provider-neutral guest-session commands with
    /// job-specific output paths; the method returns no value.
    /// </summary>
    private static void AddGuestExecutionSteps(
        List<SandboxRunbookStep> steps,
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName,
        SampleIdentity sample,
        string guestSample,
        string guestOut,
        string hostOut)
    {
        var guestRoot = config.Guest.WorkingDirectory.TrimEnd('\\');
        var agentPath = $"{guestRoot}\\agent\\{config.Guest.AgentExecutableName}";
        var driverEventsPath = $"{guestOut}\\driver-events.jsonl";
        var agentPidPath = $"{guestOut}\\agent.pid";
        var agentExitPath = $"{guestOut}\\agent.exit";
        var agentTaskName = $"KSwordSandbox-{Path.GetFileName(guestOut)}";

        steps.Add(Step("stage-guest-payload", "Stage Guest Agent and R0Collector into guest", BuildStageGuestPayloadCommand(config, provider, targetVmName)));
        steps.Add(Step("copy-sample", "Copy submitted sample into guest", BuildCopySampleCommand(config, provider, targetVmName, sample.FullPath, guestSample)));
        steps.Add(Step("make-host-output", "Create host output folder", $"New-Item -ItemType Directory -Force -Path {Q(hostOut)} | Out-Null", mutatesVmState: false));
        steps.Add(Step("record-artifact-policy", "Record artifact collection policy", BuildRecordArtifactCollectionPolicyCommand(config, hostOut), requiresElevation: false, mutatesVmState: false));
        steps.Add(Step("prepare-guest-output", "Prepare job-specific guest output folder", BuildPrepareGuestOutputCommand(config, provider, targetVmName, guestOut, driverEventsPath, agentPidPath, agentExitPath)));
        if (config.Driver.Enabled && !string.IsNullOrWhiteSpace(config.Driver.HostDriverPath))
        {
            steps.Add(Step("install-driver-service", "Install and start guest R0 driver service", BuildInstallDriverServiceCommand(config, provider, targetVmName)));
        }

        steps.Add(Step("run-agent", "Start guest collector and sample on the interactive desktop", BuildStartGuestAgentCommand(config, provider, targetVmName, guestRoot, agentPath, guestSample, guestOut, driverEventsPath, agentPidPath, agentExitPath, agentTaskName)));
        steps.Add(Step("sync-live-output", "Live-sync guest events while sample runs", BuildLiveOutputSyncCommand(config, provider, targetVmName, guestOut, hostOut, agentPidPath, agentExitPath, agentTaskName)));
        steps.Add(Step("collect-output", "Collect final guest JSON output", BuildCollectOutputCommand(config, provider, targetVmName, guestOut, hostOut)));
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
            $"if ([string]::IsNullOrWhiteSpace($guestPasswordText)) {{ throw {Q($"Guest password environment variable {secretName} is not set for this PowerShell step.")} }};",
            $"[System.Environment]::SetEnvironmentVariable({Q(secretName)}, $null, 'Process');",
            "$guestPassword = [System.Security.SecureString]::new();",
            "foreach ($guestPasswordChar in $guestPasswordText.ToCharArray()) { $guestPassword.AppendChar($guestPasswordChar) };",
            "$guestPassword.MakeReadOnly();",
            $"$guestCredential = [pscredential]::new({Q(config.Guest.UserName)}, $guestPassword);",
            "$guestPasswordText = $null; $guestPasswordChar = $null;"
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
    /// Builds a readiness loop for the selected guest PowerShell transport.
    /// Hyper-V uses PowerShell Direct; VMware and QEMU use network remoting.
    /// </summary>
    private static string BuildWaitGuestSessionCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName)
    {
        var transportName = provider is VirtualizationProvider.HyperV ? "PowerShell Direct" : "PowerShell remoting";
        var timeoutSeconds = config.Analysis.GuestReadyTimeoutSeconds;
        var guestRemoting = ResolveGuestRemotingConfig(config, provider);
        var addressMode = provider is VirtualizationProvider.HyperV
            ? "PowerShellDirect"
            : guestRemoting.AddressMode.ToString();
        var addressSource = provider switch
        {
            VirtualizationProvider.HyperV => "vm-name",
            VirtualizationProvider.VMware when guestRemoting.AddressMode is GuestRemotingAddressMode.VMwareTools => "vmware-tools-auto-discovery",
            VirtualizationProvider.Qemu when guestRemoting.AddressMode is GuestRemotingAddressMode.QemuUserNat => "provider-managed-user-nat",
            _ => "configured"
        };
        var endpoint = provider is VirtualizationProvider.HyperV
            ? targetVmName
            : guestRemoting.AddressMode is GuestRemotingAddressMode.VMwareTools
                ? "auto-after-restore"
                : guestRemoting.Port > 0
                    ? $"{guestRemoting.Address}:{guestRemoting.Port}"
                    : guestRemoting.Address ?? string.Empty;
        var transportContext = $"transport={transportName}; mode={addressMode}; source={addressSource}; endpoint={endpoint}";
        var command = string.Join(" ", new[]
        {
            $"$timeoutSeconds = {timeoutSeconds};",
            $"$deadline = (Get-Date).AddSeconds({timeoutSeconds});",
            "$nextHeartbeat = (Get-Date).AddSeconds(15);",
            "$lastError = '';",
            "$ready = $false;",
            "$attempt = 0;",
            $"Write-Host {Q($"Waiting for guest endpoint in VM {targetVmName}. {transportContext}.")};",
            "do {",
            "$attempt++;",
            "$session = $null;",
            "try {",
            BuildGuestSessionAssignment(config, provider, targetVmName),
            "Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop | Out-Null;",
            "$ready = $true;",
            "}",
            "catch {",
            "$lastError = $_.Exception.Message;",
            $"if ((Get-Date) -ge $nextHeartbeat) {{ Write-Host \"{transportName} is still not ready after $attempt attempt(s). Last error: $lastError\"; $nextHeartbeat = (Get-Date).AddSeconds(15) }};",
            "Start-Sleep -Seconds 3;",
            "}",
            "finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }",
            "} while (-not $ready -and (Get-Date) -lt $deadline);",
            $"if (-not $ready) {{ throw ({Q($"Guest endpoint did not become ready for VM {targetVmName} within {timeoutSeconds} seconds. {transportContext}. Last error: ")} + $lastError) }};",
            $"Write-Host {Q($"{transportName} is ready.")};"
        });

        return WithGuestCredential(config, command);
    }

    private static string BuildGuestSessionAssignment(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName)
    {
        if (provider is VirtualizationProvider.HyperV)
        {
            return $"$session = New-PSSession -VMName {Q(targetVmName)} -Credential $guestCredential -ErrorAction Stop;";
        }

        var guestRemoting = ResolveGuestRemotingConfig(config, provider);
        var parts = new List<string>();
        var sessionOption = string.Empty;
        if (guestRemoting.SkipCertificateChecks)
        {
            parts.Add("$guestSessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck;");
            sessionOption = " -SessionOption $guestSessionOption";
        }

        if (provider is VirtualizationProvider.VMware &&
            guestRemoting.AddressMode is GuestRemotingAddressMode.VMwareTools)
        {
            parts.Add(BuildNativeToolResolution("vmrun", config.VMware.VmrunPath, "VMware vmrun"));
            parts.Add($"$vmxPath = {Q(config.VMware.VmxPath)};");
            parts.Add("if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) { throw \"VMware VMX file was not found while discovering the guest address: $vmxPath\" };");
            parts.Add("$vmxPath = (Resolve-Path -LiteralPath $vmxPath).ProviderPath;");
            parts.Add($"$vmType = {Q(config.VMware.VmType)};");
            parts.Add("$guestAddressOutput = @(& $vmrun -T $vmType getGuestIPAddress $vmxPath 2>&1); $guestAddressExitCode = $LASTEXITCODE;");
            parts.Add(BuildVMwareGuestAddressSelectionCommand("$guestAddressOutput", "$guestRemotingAddress"));
            parts.Add("if ($guestAddressExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$guestRemotingAddress)) { throw \"vmrun getGuestIPAddress failed with exit code $guestAddressExitCode. Confirm VMware Tools is running in the restored guest. $($guestAddressOutput -join ' ')\" };");
        }
        else
        {
            parts.Add($"$guestRemotingAddress = {Q(guestRemoting.Address ?? string.Empty)};");
        }

        var useSsl = guestRemoting.UseSsl ? " -UseSSL" : string.Empty;
        var port = guestRemoting.Port > 0
            ? $" -Port {guestRemoting.Port}"
            : string.Empty;
        parts.Add(
            "$session = New-PSSession -ComputerName $guestRemotingAddress " +
            $"-Credential $guestCredential -Authentication {Q(guestRemoting.Authentication)}" +
            $"{useSsl}{port}{sessionOption} -ErrorAction Stop;");
        return string.Join(" ", parts);
    }

    private static string BuildVMwareGuestAddressSelectionCommand(string outputVariable, string resultVariable)
    {
        return string.Join(" ", new[]
        {
            $"$vmwareGuestAddressCandidates = @({outputVariable} | ForEach-Object {{",
            "$candidateText = ([string]$_).Trim(); $candidateAddress = $null;",
            "if (-not [string]::IsNullOrWhiteSpace($candidateText) -and [Net.IPAddress]::TryParse($candidateText, [ref]$candidateAddress) -and -not [Net.IPAddress]::IsLoopback($candidateAddress) -and -not $candidateAddress.IsIPv6LinkLocal -and -not $candidateText.StartsWith('169.254.', [System.StringComparison]::Ordinal)) {",
            "[pscustomobject]@{ Text = $candidateText; Address = $candidateAddress }",
            "}",
            "});",
            $"{resultVariable} = @($vmwareGuestAddressCandidates | Where-Object {{ $_.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork }} | Select-Object -ExpandProperty Text -First 1)[0];",
            $"if ([string]::IsNullOrWhiteSpace([string]{resultVariable})) {{ {resultVariable} = @($vmwareGuestAddressCandidates | Select-Object -ExpandProperty Text -First 1)[0] }};"
        });
    }

    private static string BuildCopySampleCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName,
        string sourcePath,
        string guestPath)
    {
        var command = string.Join(" ", new[]
        {
            "$session = $null;",
            BuildGuestSessionAssignment(config, provider, targetVmName),
            "try {",
            $"Invoke-Command -Session $session -ScriptBlock {{ param($path) New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null }} -ArgumentList {Q(guestPath)} -ErrorAction Stop;",
            $"Copy-Item -ToSession $session -LiteralPath {Q(sourcePath)} -Destination {Q(guestPath)} -Force -ErrorAction Stop;",
            "}",
            "finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }"
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
    private static string BuildStageGuestPayloadCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName)
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
            "$session = $null;",
            BuildGuestSessionAssignment(config, provider, targetVmName),
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
        commands.Add("finally { if ($session) { try { Remove-PSSession $session -ErrorAction Stop } catch { Write-Warning \"Guest PowerShell session cleanup failed after payload staging; primary step status is preserved: $($_.Exception.Message)\" } } }");

        return WithGuestCredential(config, string.Join(" ", commands));
    }

    /// <summary>
    /// Builds a command that clears stale job-specific output before execution.
    /// Inputs are target VM and guest artifact paths; processing creates the
    /// guest output directory and removes stale artifacts; the method returns a
    /// PowerShell Direct command string.
    /// </summary>
    private static string BuildPrepareGuestOutputCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName,
        string guestOut,
        string driverEventsPath,
        string agentPidPath,
        string agentExitPath)
    {
        var stalePaths = string.Join(", ", new[] { $"{guestOut}\\events.json", driverEventsPath, agentPidPath, agentExitPath }.Select(Q));
        var command = string.Join(" ", new[]
        {
            "$session = $null;",
            BuildGuestSessionAssignment(config, provider, targetVmName),
            "try {",
            $"Invoke-Command -Session $session -ScriptBlock {{ New-Item -ItemType Directory -Force -Path {Q(guestOut)} | Out-Null; Remove-Item -LiteralPath {stalePaths} -Force -ErrorAction SilentlyContinue }} -ErrorAction Stop;",
            "}",
            "finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }"
        });
        return WithGuestCredential(config, command);
    }

    /// <summary>
    /// Builds a guest command that installs and starts the staged kernel driver.
    /// Inputs are the configured service name and guest .sys path; processing
    /// removes stale service state, creates a demand-start kernel service, and
    /// starts it before R0Collector opens the device; the method returns a
    /// PowerShell Direct command string.
    /// </summary>
    private static string BuildInstallDriverServiceCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName)
    {
        var command = string.Join(" ", new[]
        {
            $"$serviceName = {Q(config.Driver.ServiceName)};",
            $"$driverPath = {Q(config.Driver.DriverPathInGuest)};",
            "$session = $null;",
            BuildGuestSessionAssignment(config, provider, targetVmName),
            "try { Invoke-Command -Session $session -ScriptBlock {",
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
            "} -ArgumentList $serviceName, $driverPath -ErrorAction Stop }",
            "finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }"
        });

        return WithGuestCredential(config, command);
    }

    /// <summary>
    /// Starts the Guest Agent in the logged-on user's interactive desktop.
    /// The provider session registers an Interactive-logon scheduled task so
    /// GUI samples do not remain trapped in the remoting service session.
    /// </summary>
    private static string BuildStartGuestAgentCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName,
        string guestRoot,
        string agentPath,
        string guestSample,
        string guestOut,
        string driverEventsPath,
        string agentPidPath,
        string agentExitPath,
        string agentTaskName)
    {
        var agentCommand = BuildGuestAgentInvocation(config, agentPath, guestSample, guestOut, driverEventsPath, agentExitPath);
        var interactiveCommand = $"$PID | Set-Content -LiteralPath {Q(agentPidPath)} -Encoding ASCII; {agentCommand}";
        var encodedCommand = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(interactiveCommand));
        var command = string.Join(" ", new[]
        {
            "$session = $null;",
            BuildGuestSessionAssignment(config, provider, targetVmName),
            "try {",
            "Invoke-Command -Session $session -ScriptBlock {",
            "param($taskName, $guestUserName, $workingDirectory, $pidPath, $encodedCommand)",
            "if (-not (Get-Command New-ScheduledTaskAction -ErrorAction SilentlyContinue)) { throw 'The ScheduledTasks PowerShell module is required for interactive sample launch.' };",
            "Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue;",
            "Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue;",
            "$actionArguments = \"-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $encodedCommand\";",
            "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArguments -WorkingDirectory $workingDirectory;",
            "$principal = New-ScheduledTaskPrincipal -UserId $guestUserName -LogonType Interactive -RunLevel Highest;",
            "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 24);",
            "try {",
            "Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null;",
            "Start-ScheduledTask -TaskName $taskName -ErrorAction Stop;",
            "$deadline = (Get-Date).AddSeconds(30);",
            "do { Start-Sleep -Milliseconds 250 } while (-not (Test-Path -LiteralPath $pidPath -PathType Leaf) -and (Get-Date) -lt $deadline);",
            "if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) { $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue; throw \"Interactive Guest Agent task did not create its pid marker. LastTaskResult=$($info.LastTaskResult). Confirm that '$guestUserName' is logged on to the VM desktop.\" };",
            "}",
            "catch { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue; throw }",
            $"}} -ArgumentList {Q(agentTaskName)}, {Q(config.Guest.UserName)}, {Q(guestRoot)}, {Q(agentPidPath)}, {Q(encodedCommand)} -ErrorAction Stop;",
            "}",
            "finally { if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue } }"
        });
        return WithGuestCredential(config, command);
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
    private static string BuildLiveOutputSyncCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName,
        string guestOut,
        string hostOut,
        string agentPidPath,
        string agentExitPath,
        string agentTaskName)
    {
        var hasSyncDeadline = !config.Analysis.DurationUnlimited && config.Analysis.DefaultDurationSeconds > 0;
        var maxSyncSeconds = hasSyncDeadline
            ? Math.Max(config.Analysis.DefaultDurationSeconds + 60, 90)
            : 0;
        var command = string.Join(" ", new[]
        {
            "$session = $null;",
            BuildGuestSessionAssignment(config, provider, targetVmName),
            "try {",
            $"$guestOut = {Q(guestOut)};",
            $"$hostOut = {Q(hostOut)};",
            $"$pidPath = {Q(agentPidPath)};",
            $"$exitPath = {Q(agentExitPath)};",
            $"$taskName = {Q(agentTaskName)};",
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
            "finally {",
            "if ($session) {",
            "try { Invoke-Command -Session $session -ScriptBlock { param($name) Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue } -ArgumentList $taskName -ErrorAction Stop } catch { Write-Warning \"Guest interactive task cleanup failed; primary step status is preserved: $($_.Exception.Message)\" };",
            "try { Remove-PSSession $session -ErrorAction Stop } catch { Write-Warning \"Guest PowerShell session cleanup failed after live output sync; primary step status is preserved: $($_.Exception.Message)\" }",
            "}",
            "}"
        });

        return WithGuestCredential(config, command);
    }

    /// <summary>
    /// Builds the final collection command after live sync completes.
    /// Inputs are target VM, guest output folder, and host output folder;
    /// processing copies the complete guest output tree one last time and
    /// closes the PSSession; the method returns a PowerShell command string.
    /// </summary>
    private static string BuildCollectOutputCommand(
        SandboxConfig config,
        VirtualizationProvider provider,
        string targetVmName,
        string guestOut,
        string hostOut)
    {
        var command = string.Join(" ", new[]
        {
            "$session = $null;",
            BuildGuestSessionAssignment(config, provider, targetVmName),
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
            "finally { if ($session) { try { Remove-PSSession $session -ErrorAction Stop } catch { Write-Warning \"Guest PowerShell session cleanup failed after final output collection; primary step status is preserved: $($_.Exception.Message)\" } } }"
        });

        return WithGuestCredential(config, command);
    }

    /// <summary>
    /// Adds VM cleanup steps after collection.
    /// Inputs are mode and target VM, processing appends stop/remove commands,
    /// and the method returns no value.
    /// </summary>
    private static void AddCleanupSteps(
        List<SandboxRunbookStep> steps,
        SandboxConfig config,
        VirtualizationProvider provider,
        bool usesTemporaryVm,
        string targetVmName,
        Guid jobId)
    {
        if (provider is VirtualizationProvider.HyperV)
        {
            steps.Add(Step("stop-vm", "Stop analysis VM", $"Stop-VM -Name {Q(targetVmName)} -TurnOff -Force"));
            if (usesTemporaryVm)
            {
                steps.Add(Step("remove-temp-vm", "Remove temporary VM registration", $"Remove-VM -Name {Q(targetVmName)} -Force"));
            }

            return;
        }

        if (provider is VirtualizationProvider.VMware)
        {
            var command = string.Join(" ", new[]
            {
                BuildClearGuestSecretEnvironment(config),
                BuildNativeToolResolution("vmrun", config.VMware.VmrunPath, "VMware vmrun"),
                $"$vmxPath = {Q(config.VMware.VmxPath)};",
                "if (Test-Path -LiteralPath $vmxPath -PathType Leaf) { $vmxPath = (Resolve-Path -LiteralPath $vmxPath).ProviderPath };",
                $"$vmType = {Q(config.VMware.VmType)};",
                "$runningOutput = @(& $vmrun -T $vmType list 2>&1);",
                "$listExitCode = $LASTEXITCODE;",
                "if ($listExitCode -ne 0) { throw \"vmrun list failed with exit code $listExitCode. $($runningOutput -join ' ')\" };",
                "if ($runningOutput | Where-Object { ([string]$_).Trim() -eq $vmxPath }) {",
                "$stopOutput = @(& $vmrun -T $vmType stop $vmxPath hard 2>&1);",
                "$stopExitCode = $LASTEXITCODE;",
                "if ($stopExitCode -ne 0) { throw \"vmrun stop failed with exit code $stopExitCode. $($stopOutput -join ' ')\" };",
                BuildVMwarePowerStateWaitCommand(expectedRunning: false, operation: "cleanup stop"),
                "} else { Write-Host 'VMware VM is already stopped.' };"
            });
            steps.Add(Step("stop-vm", "Stop VMware analysis VM", command));
            return;
        }

        var vmRoot = Path.Combine(config.Paths.RuntimeRoot, "vms", jobId.ToString("N"));
        var pidPath = Path.Combine(vmRoot, "qemu.pid");
        var stopConfirmedPath = Path.Combine(vmRoot, "qemu.stop-confirmed");
        var expectedDiskPath = config.Qemu.UseOverlayDisk
            ? Path.Combine(vmRoot, $"{targetVmName}.qcow2")
            : config.Qemu.DiskImagePath;
        var stopQemu = string.Join(" ", new[]
        {
            BuildClearGuestSecretEnvironment(config),
            BuildNativeToolResolution("qemuSystem", config.Qemu.QemuSystemPath, "qemu-system"),
            $"$pidPath = {Q(pidPath)};",
            $"$vmRoot = {Q(vmRoot)};",
            $"$stopConfirmedPath = {Q(stopConfirmedPath)};",
            "Remove-Item -LiteralPath $stopConfirmedPath -Force -ErrorAction SilentlyContinue;",
            $"$expectedVmName = {Q(targetVmName)};",
            $"$expectedDiskPath = {Q(expectedDiskPath)};",
            "$expectedDiskArgumentPath = $expectedDiskPath.Replace(',', ',,');",
            "$qemuExecutableName = [System.IO.Path]::GetFileName($qemuSystem);",
            "$qemuExecutablePath = [System.IO.Path]::GetFullPath($qemuSystem);",
            "if (Test-Path -LiteralPath $pidPath -PathType Leaf) {",
            "$pidText = (Get-Content -LiteralPath $pidPath -Raw).Trim();",
            "$qemuPid = 0;",
            "if ([int]::TryParse($pidText, [ref]$qemuPid)) {",
            "$process = Get-Process -Id $qemuPid -ErrorAction SilentlyContinue;",
            "if ($process) { $processInfo = Get-CimInstance Win32_Process -Filter \"ProcessId = $qemuPid\" -ErrorAction Stop | Select-Object -First 1; $commandLine = [string]$processInfo.CommandLine; $processExecutablePath = [string]$processInfo.ExecutablePath; if ($null -eq $processInfo -or [string]::IsNullOrWhiteSpace($commandLine) -or [string]::IsNullOrWhiteSpace($processExecutablePath)) { throw \"QEMU cleanup cannot verify pid $qemuPid because Win32_Process executable/command line identity is unavailable; the job disk was preserved.\" }; $markerWrittenUtc = (Get-Item -LiteralPath $pidPath -ErrorAction Stop).LastWriteTimeUtc; $processStartedUtc = ([datetime]$processInfo.CreationDate).ToUniversalTime(); if ($processStartedUtc -lt $markerWrittenUtc.AddSeconds(-5) -or $processStartedUtc -gt $markerWrittenUtc.AddSeconds(5)) { throw \"QEMU cleanup refused reused pid $qemuPid because the process instance start time does not match marker '$pidPath'; the job disk was preserved.\" }; $owned = ([string]$processInfo.Name).Equals($qemuExecutableName, [System.StringComparison]::OrdinalIgnoreCase) -and $processExecutablePath.Equals($qemuExecutablePath, [System.StringComparison]::OrdinalIgnoreCase) -and $commandLine.IndexOf($pidPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $commandLine.IndexOf($vmRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $commandLine.IndexOf($expectedVmName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and ($commandLine.IndexOf($expectedDiskPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or $commandLine.IndexOf($expectedDiskArgumentPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0); if (-not $owned) { throw \"QEMU cleanup refused to stop pid $qemuPid because its executable/pidfile/runtime/VM/disk identity does not match this job.\" }; Stop-Process -Id $qemuPid -Force -ErrorAction Stop; $stopDeadline = (Get-Date).AddSeconds(30); while ((Get-Process -Id $qemuPid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $stopDeadline) { Start-Sleep -Milliseconds 200 }; if (Get-Process -Id $qemuPid -ErrorAction SilentlyContinue) { throw \"QEMU process $qemuPid did not exit within 30 seconds.\" } }",
            "} else { throw \"Invalid QEMU pid marker '$pidPath'; cleanup preserved the job disk because process ownership cannot be verified.\" };",
            "Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue;",
            "} else {",
            "$ownedCandidates = @();",
            "$qemuCandidates = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { ([string]$_.Name).Equals($qemuExecutableName, [System.StringComparison]::OrdinalIgnoreCase) });",
            "foreach ($candidate in $qemuCandidates) { $candidateExecutablePath = [string]$candidate.ExecutablePath; if ([string]::IsNullOrWhiteSpace($candidateExecutablePath) -or -not $candidateExecutablePath.Equals($qemuExecutablePath, [System.StringComparison]::OrdinalIgnoreCase)) { continue }; $commandLine = [string]$candidate.CommandLine; if ([string]::IsNullOrWhiteSpace($commandLine)) { throw \"QEMU pid marker is absent and process $($candidate.ProcessId) from the configured executable cannot be attributed because its command line is unavailable; the job disk was preserved.\" }; $diskMatches = $commandLine.IndexOf($expectedDiskPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or $commandLine.IndexOf($expectedDiskArgumentPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0; $identityMatches = $commandLine.IndexOf($vmRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and $commandLine.IndexOf($expectedVmName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0; if ($diskMatches -and $identityMatches) { $ownedCandidates += $candidate } };",
            "if ($ownedCandidates.Count -gt 0) { throw \"QEMU cleanup found $($ownedCandidates.Count) process(es) matching this job, but the native qemu.pid ownership marker is absent; ambiguous provider ownership means no process was stopped and the job disk was preserved.\" };",
            "Write-Host 'QEMU pid marker was absent and no matching active process was found; stop is already confirmed.';",
            "};",
            "New-Item -ItemType Directory -Force -Path $vmRoot | Out-Null; Set-Content -LiteralPath $stopConfirmedPath -Value 'stopped' -Encoding ASCII -ErrorAction Stop;"
        });
        steps.Add(Step("stop-vm", "Stop QEMU analysis VM", stopQemu));
        var removeQemuRoot = string.Join(" ", new[]
        {
            $"$pidPath = {Q(pidPath)};",
            $"$vmRoot = {Q(vmRoot)};",
            $"$stopConfirmedPath = {Q(stopConfirmedPath)};",
            "if (Test-Path -LiteralPath $pidPath -PathType Leaf) { throw \"QEMU job cleanup preserved the VM folder because its pid marker was not cleared by the stop step: $pidPath\" };",
            "if (-not (Test-Path -LiteralPath $stopConfirmedPath -PathType Leaf)) { throw \"QEMU job cleanup preserved the VM folder because process stop was not confirmed: $stopConfirmedPath\" };",
            "if (Test-Path -LiteralPath $vmRoot -PathType Container) { Remove-Item -LiteralPath $vmRoot -Recurse -Force -ErrorAction Stop } else { Write-Host 'QEMU job folder is already absent.' };"
        });
        var removeQemuTitle = config.Qemu.UseOverlayDisk
            ? "Remove QEMU job disk and process metadata"
            : "Remove QEMU job process metadata";
        steps.Add(Step("remove-temp-vm", removeQemuTitle, removeQemuRoot));
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
