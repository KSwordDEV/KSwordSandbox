using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.Web.Contracts;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Performs a bounded, read-only inventory of the local sandbox host.
/// Inputs are the active normalized config and an optional refresh request;
/// processing checks filesystem/environment facts and runs bounded read-only
/// Hyper-V, vmrun, or qemu-img inventory commands; returned data contains
/// no passwords, command text, stdout, or VM-mutating operations.
/// </summary>
internal sealed class LocalHostReadinessProbe
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan HyperVProbeTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan ProviderProbeTimeout = TimeSpan.FromSeconds(8);
    private static readonly System.Text.RegularExpressions.Regex SensitiveEnvironmentNamePattern = new(
        "(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase |
        System.Text.RegularExpressions.RegexOptions.CultureInvariant |
        System.Text.RegularExpressions.RegexOptions.Compiled);
    private readonly SandboxConfig config;
    private readonly SemaphoreSlim probeGate = new(1, 1);
    private LocalHostReadinessContract? cached;
    private VirtualizationProvider? cachedProvider;
    private DateTimeOffset cacheExpiresAtUtc;

    public LocalHostReadinessProbe(SandboxConfig config)
    {
        this.config = config ?? throw new ArgumentNullException(nameof(config));
    }

    /// <summary>
    /// Returns current host facts, using a short cache to avoid starting a
    /// PowerShell inventory process for every dashboard repaint. A forced
    /// refresh bypasses the cache. Cancellation stops the bounded child query.
    /// </summary>
    public async Task<LocalHostReadinessContract> ProbeAsync(
        bool forceRefresh,
        VirtualizationProvider? providerOverride,
        CancellationToken cancellationToken)
    {
        var provider = providerOverride ?? config.Virtualization.Provider;
        var now = DateTimeOffset.UtcNow;
        if (!forceRefresh && cached is not null && cachedProvider == provider && now < cacheExpiresAtUtc)
        {
            return cached;
        }

        await probeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            now = DateTimeOffset.UtcNow;
            if (!forceRefresh && cached is not null && cachedProvider == provider && now < cacheExpiresAtUtc)
            {
                return cached;
            }

            var hostVirtualizationTask = ProbeHostVirtualizationAsync(provider, cancellationToken);
            var hyperVProbeTask = provider is VirtualizationProvider.HyperV
                ? ProbeHyperVAsync(cancellationToken)
                : Task.FromResult(HyperVProbeResult.Failed(false, "HYPERV_NOT_SELECTED", "Hyper-V inventory was skipped because another provider is selected."));
            Task<LocalVirtualizationReadinessContract>? providerProbeTask = provider switch
            {
                VirtualizationProvider.VMware => ProbeVMwareAsync(cancellationToken),
                VirtualizationProvider.Qemu => ProbeQemuAsync(cancellationToken),
                _ => null
            };
            await Task.WhenAll(hostVirtualizationTask, hyperVProbeTask, providerProbeTask ?? Task.CompletedTask).ConfigureAwait(false);
            var hostVirtualization = await hostVirtualizationTask.ConfigureAwait(false);
            var hyperVProbe = await hyperVProbeTask.ConfigureAwait(false);
            var hyperV = BuildHyperVReadiness(hyperVProbe);
            var virtualization = providerProbeTask is null
                ? BuildHyperVProviderReadiness(hyperV)
                : await providerProbeTask.ConfigureAwait(false);
            var guest = BuildGuestReadiness();
            var paths = BuildPathReadiness();
            cached = new LocalHostReadinessContract(
                DetectedAtUtc: DateTimeOffset.UtcNow,
                MachineName: Environment.MachineName,
                OperatingSystem: RuntimeInformation.OSDescription,
                IsElevated: IsCurrentProcessElevated(),
                ReadOnly: true,
                HostVirtualization: hostVirtualization,
                Virtualization: virtualization,
                HyperV: hyperV,
                Guest: guest,
                Paths: paths);
            cacheExpiresAtUtc = DateTimeOffset.UtcNow.Add(CacheLifetime);
            cachedProvider = provider;
            return cached;
        }
        finally
        {
            probeGate.Release();
        }
    }

    private static LocalVirtualizationReadinessContract BuildHyperVProviderReadiness(LocalHyperVReadinessContract hyperV)
    {
        var managementFact = new LocalPathFactContract(
            "Get-VM",
            true,
            hyperV.ManagementAvailable,
            "powershell-command",
            hyperV.ManagementAvailable ? "command-detected" : "command-missing");
        var vmFact = new LocalPathFactContract(
            hyperV.ConfiguredVmName,
            !string.IsNullOrWhiteSpace(hyperV.ConfiguredVmName),
            hyperV.VmExists,
            "hyperv-vm",
            hyperV.VmSource);
        return new LocalVirtualizationReadinessContract(
            Provider: VirtualizationProvider.HyperV,
            ManagementAvailable: hyperV.ManagementAvailable,
            QuerySucceeded: hyperV.QuerySucceeded,
            AccessDenied: hyperV.AccessDenied,
            ConfiguredVmName: hyperV.ConfiguredVmName,
            VmName: hyperV.VmName,
            VmSource: hyperV.VmSource,
            VmState: hyperV.VmState,
            VmExists: hyperV.VmExists,
            ConfiguredSnapshotName: hyperV.ConfiguredCheckpointName,
            SnapshotName: hyperV.CheckpointName,
            SnapshotSource: hyperV.CheckpointSource,
            SnapshotExists: hyperV.CheckpointExists,
            GuestTransport: "PowerShellDirect",
            GuestAddressMode: "PowerShellDirect",
            GuestAddress: null,
            GuestAddressSource: "vm-name",
            GuestEndpointReady: true,
            GuestPort: 0,
            GuestUseSsl: false,
            GuestAuthentication: "PowerShellDirect",
            GuestSkipCertificateChecks: false,
            GuestTransportSecure: true,
            PrimaryTool: managementFact,
            SecondaryTool: managementFact with { Path = "Get-VMSnapshot" },
            MachineDefinition: vmFact,
            VmCandidates: hyperV.VmCandidates,
            DiagnosticCode: hyperV.DiagnosticCode,
            DiagnosticMessage: hyperV.DiagnosticMessage);
    }

    private LocalHyperVReadinessContract BuildHyperVReadiness(HyperVProbeResult probe)
    {
        var configuredVmName = config.HyperV.GoldenVmName?.Trim() ?? string.Empty;
        var configuredCheckpointName = config.HyperV.GoldenSnapshotName?.Trim() ?? string.Empty;
        LocalVmCandidateContract? selectedVm = null;
        var vmSource = probe.ManagementAvailable
            ? (probe.QuerySucceeded ? "not-found" : "query-failed")
            : "management-missing";

        if (probe.QuerySucceeded)
        {
            selectedVm = probe.Vms.FirstOrDefault(candidate =>
                string.Equals(candidate.Name, configuredVmName, StringComparison.OrdinalIgnoreCase));
            if (selectedVm is not null)
            {
                vmSource = "detected-config-match";
            }
            else if (probe.Vms.Count == 1)
            {
                selectedVm = probe.Vms[0];
                vmSource = "detected-single";
            }
            else if (probe.Vms.Count > 1)
            {
                vmSource = "ambiguous";
            }
        }

        string? selectedCheckpoint = null;
        var checkpointSource = selectedVm is null ? vmSource : "not-found";
        if (selectedVm is not null)
        {
            selectedCheckpoint = selectedVm.Checkpoints.FirstOrDefault(name =>
                string.Equals(name, configuredCheckpointName, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(selectedCheckpoint))
            {
                checkpointSource = "detected-config-match";
            }
            else if (selectedVm.Checkpoints.Count == 1)
            {
                selectedCheckpoint = selectedVm.Checkpoints[0];
                checkpointSource = "detected-single";
            }
            else if (selectedVm.Checkpoints.Count > 1)
            {
                checkpointSource = "ambiguous";
            }
        }

        return new LocalHyperVReadinessContract(
            ManagementAvailable: probe.ManagementAvailable,
            QuerySucceeded: probe.QuerySucceeded,
            AccessDenied: string.Equals(probe.DiagnosticCode, "HYPERV_ACCESS_DENIED", StringComparison.Ordinal),
            ConfiguredVmName: configuredVmName,
            VmName: selectedVm?.Name,
            VmSource: vmSource,
            VmState: selectedVm?.State,
            VmExists: selectedVm is not null,
            ConfiguredCheckpointName: configuredCheckpointName,
            CheckpointName: selectedCheckpoint,
            CheckpointSource: checkpointSource,
            CheckpointExists: !string.IsNullOrWhiteSpace(selectedCheckpoint),
            VmCandidates: probe.Vms,
            DiagnosticCode: probe.DiagnosticCode,
            DiagnosticMessage: probe.DiagnosticMessage);
    }

    private async Task<LocalVirtualizationReadinessContract> ProbeVMwareAsync(CancellationToken cancellationToken)
    {
        var guestRemoting = ResolveGuestRemoting(VirtualizationProvider.VMware);
        var vmrunPath = ResolveExecutable(config.VMware.VmrunPath);
        var vmxFact = FileFact(config.VMware.VmxPath);
        var toolFact = ExecutableFact(config.VMware.VmrunPath, vmrunPath);
        var unusedTool = new LocalPathFactContract(null, false, true, "not-required", "not-required");
        var snapshotName = config.VMware.SnapshotName?.Trim() ?? string.Empty;
        var vmName = config.VMware.VmName?.Trim() ?? string.Empty;

        if (!string.Equals(config.VMware.VmType?.Trim(), "ws", StringComparison.OrdinalIgnoreCase))
        {
            return ProviderFailure(
                VirtualizationProvider.VMware,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                toolFact,
                unusedTool,
                vmxFact,
                "VMWARE_WORKSTATION_PRO_REQUIRED",
                "Full VMware parity requires Workstation Pro with vmware.vmType=ws. VMware Player profiles must be migrated to Workstation Pro before Live execution.");
        }

        if (vmrunPath is null || !vmxFact.Exists)
        {
            var code = vmrunPath is null ? "VMWARE_VMRUN_MISSING" : "VMWARE_VMX_MISSING";
            var message = vmrunPath is null
                ? $"VMware vmrun was not found: {config.VMware.VmrunPath}"
                : $"Configured VMware VMX was not found: {config.VMware.VmxPath}";
            return ProviderFailure(
                VirtualizationProvider.VMware,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                toolFact,
                unusedTool,
                vmxFact,
                code,
                message);
        }
        var remotingError = GuestRemotingConfigurationError(VirtualizationProvider.VMware, guestRemoting);
        if (remotingError is not null)
        {
            return ProviderFailure(
                VirtualizationProvider.VMware,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                toolFact,
                unusedTool,
                vmxFact,
                "GUEST_REMOTING_CONFIGURATION_INVALID",
                remotingError);
        }
        if (!IsGuestRemotingSecure(guestRemoting))
        {
            return ProviderFailure(
                VirtualizationProvider.VMware,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                toolFact,
                unusedTool,
                vmxFact,
                "GUEST_REMOTING_INSECURE",
                GuestRemotingSecurityDiagnostic(guestRemoting));
        }

        var snapshots = await RunProcessAsync(
            vmrunPath,
            ["-T", "ws", "listSnapshots", config.VMware.VmxPath],
            cancellationToken).ConfigureAwait(false);
        if (!snapshots.Success)
        {
            return ProviderFailure(
                VirtualizationProvider.VMware,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                toolFact,
                unusedTool,
                vmxFact,
                snapshots.TimedOut ? "VMWARE_QUERY_TIMEOUT" : "VMWARE_SNAPSHOT_QUERY_FAILED",
                snapshots.Diagnostic);
        }

        var snapshotNames = snapshots.StandardOutput
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => !line.StartsWith("Total snapshots:", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var selectedSnapshot = snapshotNames.FirstOrDefault(candidate =>
            string.Equals(candidate, snapshotName, StringComparison.OrdinalIgnoreCase));

        var running = await RunProcessAsync(
            vmrunPath,
            ["-T", "ws", "list"],
            cancellationToken).ConfigureAwait(false);
        var runningAccessDenied = !running.Success && IsProviderAccessDenied(running.Diagnostic);
        var vmxFullPath = Path.GetFullPath(config.VMware.VmxPath);
        var isRunning = running.Success && running.StandardOutput
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(line => PathsEqual(line, vmxFullPath));
        var candidate = new LocalVmCandidateContract(
            vmName,
            isRunning ? "Running" : "Stopped",
            snapshotNames,
            null);
        var snapshotExists = selectedSnapshot is not null;
        return new LocalVirtualizationReadinessContract(
            Provider: VirtualizationProvider.VMware,
            ManagementAvailable: true,
            QuerySucceeded: running.Success,
            AccessDenied: runningAccessDenied,
            ConfiguredVmName: vmName,
            VmName: vmName,
            VmSource: "config-vmx-detected",
            VmState: candidate.State,
            VmExists: true,
            ConfiguredSnapshotName: snapshotName,
            SnapshotName: selectedSnapshot,
            SnapshotSource: snapshotExists ? "detected-config-match" : "not-found",
            SnapshotExists: snapshotExists,
            GuestTransport: "PowerShellRemoting",
            GuestAddressMode: guestRemoting.AddressMode.ToString(),
            GuestAddress: guestRemoting.Address,
            GuestAddressSource: GuestAddressSource(guestRemoting),
            GuestEndpointReady: GuestEndpointReady(VirtualizationProvider.VMware, guestRemoting),
            GuestPort: guestRemoting.Port,
            GuestUseSsl: guestRemoting.UseSsl,
            GuestAuthentication: guestRemoting.Authentication,
            GuestSkipCertificateChecks: guestRemoting.SkipCertificateChecks,
            GuestTransportSecure: true,
            PrimaryTool: toolFact,
            SecondaryTool: unusedTool,
            MachineDefinition: vmxFact,
            VmCandidates: [candidate],
            DiagnosticCode: snapshotExists && running.Success
                ? "VMWARE_QUERY_OK"
                : runningAccessDenied
                    ? "VMWARE_ACCESS_DENIED"
                    : snapshotExists
                        ? "VMWARE_LIST_FAILED"
                        : "VMWARE_SNAPSHOT_NOT_FOUND",
            DiagnosticMessage: snapshotExists
                ? running.Success ? "VMware vmrun, VMX, and configured snapshot were detected." : running.Diagnostic
                : $"Configured VMware snapshot '{snapshotName}' was not found.");
    }

    private async Task<LocalVirtualizationReadinessContract> ProbeQemuAsync(CancellationToken cancellationToken)
    {
        var guestRemoting = ResolveGuestRemoting(VirtualizationProvider.Qemu);
        var systemPath = ResolveExecutable(config.Qemu.QemuSystemPath);
        var imageToolPath = ResolveExecutable(config.Qemu.QemuImgPath);
        var systemFact = ExecutableFact(config.Qemu.QemuSystemPath, systemPath);
        var imageToolFact = ExecutableFact(config.Qemu.QemuImgPath, imageToolPath);
        var diskFact = FileFact(config.Qemu.DiskImagePath);
        var vmName = config.Qemu.VmName?.Trim() ?? string.Empty;
        var snapshotName = config.Qemu.SnapshotName?.Trim() ?? string.Empty;
        if (systemPath is null || imageToolPath is null || !diskFact.Exists)
        {
            var code = systemPath is null
                ? "QEMU_SYSTEM_MISSING"
                : imageToolPath is null
                    ? "QEMU_IMG_MISSING"
                    : "QEMU_DISK_MISSING";
            var message = code switch
            {
                "QEMU_SYSTEM_MISSING" => $"QEMU system executable was not found: {config.Qemu.QemuSystemPath}",
                "QEMU_IMG_MISSING" => $"qemu-img executable was not found: {config.Qemu.QemuImgPath}",
                _ => $"Configured QEMU disk image was not found: {config.Qemu.DiskImagePath}"
            };
            return ProviderFailure(
                VirtualizationProvider.Qemu,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                systemFact,
                imageToolFact,
                diskFact,
                code,
                message);
        }
        var configurationError = GetQemuConfigurationError();
        if (configurationError is not null)
        {
            return ProviderFailure(
                VirtualizationProvider.Qemu,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                systemFact,
                imageToolFact,
                diskFact,
                "QEMU_CONFIGURATION_INVALID",
                configurationError);
        }
        if (!IsGuestRemotingSecure(guestRemoting))
        {
            return ProviderFailure(
                VirtualizationProvider.Qemu,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                systemFact,
                imageToolFact,
                diskFact,
                "GUEST_REMOTING_INSECURE",
                GuestRemotingSecurityDiagnostic(guestRemoting));
        }

        var imageInfoResult = await RunProcessAsync(
            imageToolPath,
            ["info", "--output=json", config.Qemu.DiskImagePath],
            cancellationToken).ConfigureAwait(false);
        if (!imageInfoResult.Success)
        {
            return ProviderFailure(
                VirtualizationProvider.Qemu,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                systemFact,
                imageToolFact,
                diskFact,
                imageInfoResult.TimedOut ? "QEMU_QUERY_TIMEOUT" : "QEMU_IMAGE_QUERY_FAILED",
                imageInfoResult.Diagnostic);
        }

        QemuImageInfo imageInfo;
        try
        {
            imageInfo = ParseQemuImageInfo(imageInfoResult.StandardOutput);
        }
        catch (JsonException ex)
        {
            return ProviderFailure(
                VirtualizationProvider.Qemu,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                systemFact,
                imageToolFact,
                diskFact,
                "QEMU_INVALID_INFO_JSON",
                ex.Message);
        }

        if (!string.Equals(imageInfo.Format, config.Qemu.DiskFormat, StringComparison.OrdinalIgnoreCase))
        {
            return ProviderFailure(
                VirtualizationProvider.Qemu,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                systemFact,
                imageToolFact,
                diskFact,
                "QEMU_DISK_FORMAT_MISMATCH",
                $"Configured QEMU disk format '{config.Qemu.DiskFormat}' does not match qemu-img format '{imageInfo.Format}'.");
        }

        if (!config.Qemu.UseOverlayDisk &&
            !string.Equals(imageInfo.Format, "qcow2", StringComparison.OrdinalIgnoreCase))
        {
            return ProviderFailure(
                VirtualizationProvider.Qemu,
                vmName,
                snapshotName,
                "PowerShellRemoting",
                systemFact,
                imageToolFact,
                diskFact,
                "QEMU_INTERNAL_SNAPSHOT_FORMAT_UNSUPPORTED",
                $"QEMU internal snapshot mode requires qcow2; detected '{imageInfo.Format}'. Enable per-job overlay mode for this base image.");
        }

        var verifiedRunningProcesses = new List<QemuActiveProcessIdentity>();
        foreach (var runningProcessCandidate in FindActiveQemuProcesses())
        {
            var matches = guestRemoting.AddressMode is GuestRemotingAddressMode.QemuUserNat
                ? await QemuProcessOwnsConfiguredUserNatEndpointAsync(runningProcessCandidate, guestRemoting.Port, cancellationToken).ConfigureAwait(false)
                : await QemuProcessMatchesProviderIdentityAsync(runningProcessCandidate, null, cancellationToken).ConfigureAwait(false);
            if (matches)
            {
                verifiedRunningProcesses.Add(runningProcessCandidate);
            }
        }
        var runningProcessAmbiguous = verifiedRunningProcesses.Count > 1;
        var runningProcess = verifiedRunningProcesses.Count == 1 ? verifiedRunningProcesses[0] : null;
        var verifiedRunningProcess = runningProcess is not null;
        var runningProcessOwnsUserNatPort = guestRemoting.AddressMode is GuestRemotingAddressMode.QemuUserNat && verifiedRunningProcess;
        var userNatPortAvailable = true;
        string? userNatPortError = null;
        if (runningProcessAmbiguous)
        {
            userNatPortAvailable = false;
            userNatPortError = $"{verifiedRunningProcesses.Count} active KSword QEMU processes match the configured VM identity.";
        }
        else if (guestRemoting.AddressMode is GuestRemotingAddressMode.QemuUserNat && !runningProcessOwnsUserNatPort)
        {
            userNatPortAvailable = CanBindLoopbackPort(guestRemoting.Port, out userNatPortError);
        }
        var guestEndpointReady = GuestEndpointReady(VirtualizationProvider.Qemu, guestRemoting) && userNatPortAvailable && !runningProcessAmbiguous;
        var vmState = runningProcessAmbiguous ? "Ambiguous" : verifiedRunningProcess ? "Running" : "Configured";
        if (config.Qemu.UseOverlayDisk)
        {
            var candidate = new LocalVmCandidateContract(vmName, vmState, ["per-job-overlay"], null);
            return new LocalVirtualizationReadinessContract(
                Provider: VirtualizationProvider.Qemu,
                ManagementAvailable: true,
                QuerySucceeded: true,
                AccessDenied: false,
                ConfiguredVmName: vmName,
                VmName: vmName,
                VmSource: "config-disk-detected",
                VmState: vmState,
                VmExists: true,
                ConfiguredSnapshotName: snapshotName,
                SnapshotName: "per-job-overlay",
                SnapshotSource: "overlay-mode-not-required",
                SnapshotExists: true,
                GuestTransport: "PowerShellRemoting",
                GuestAddressMode: guestRemoting.AddressMode.ToString(),
                GuestAddress: guestRemoting.Address,
                GuestAddressSource: GuestAddressSource(guestRemoting),
                GuestEndpointReady: guestEndpointReady,
                GuestPort: guestRemoting.Port,
                GuestUseSsl: guestRemoting.UseSsl,
                GuestAuthentication: guestRemoting.Authentication,
                GuestSkipCertificateChecks: guestRemoting.SkipCertificateChecks,
                GuestTransportSecure: true,
                PrimaryTool: systemFact,
                SecondaryTool: imageToolFact,
                MachineDefinition: diskFact,
                VmCandidates: [candidate],
                DiagnosticCode: runningProcessAmbiguous
                    ? "QEMU_PROCESS_IDENTITY_AMBIGUOUS"
                    : userNatPortAvailable ? "QEMU_OVERLAY_READY" : "QEMU_USER_NAT_PORT_UNAVAILABLE",
                DiagnosticMessage: runningProcessAmbiguous
                    ? $"Multiple active KSword QEMU processes match VM '{vmName}'. Stop duplicate runs before starting another analysis."
                    : !userNatPortAvailable
                    ? $"QEMU user-NAT WinRM host-forward port {guestRemoting.Port} on 127.0.0.1 is unavailable. Stop the conflicting listener or configure another guestRemoting.port. {userNatPortError}"
                    : verifiedRunningProcess
                        ? $"QEMU tools and base disk were detected; KSword QEMU process {runningProcess!.ProcessId} is active and will be stopped before the next baseline operation."
                        : "QEMU tools and base disk were detected; each job will use a disposable overlay.");
        }

        var snapshotList = imageInfo.SnapshotNames;
        var selectedSnapshot = snapshotList.FirstOrDefault(candidate =>
            string.Equals(candidate, snapshotName, StringComparison.Ordinal));
        var snapshotExists = selectedSnapshot is not null;
        var qemuCandidate = new LocalVmCandidateContract(vmName, vmState, snapshotList, null);
        return new LocalVirtualizationReadinessContract(
            Provider: VirtualizationProvider.Qemu,
            ManagementAvailable: true,
            QuerySucceeded: true,
            AccessDenied: false,
            ConfiguredVmName: vmName,
            VmName: vmName,
            VmSource: "config-disk-detected",
            VmState: vmState,
            VmExists: true,
            ConfiguredSnapshotName: snapshotName,
            SnapshotName: selectedSnapshot,
            SnapshotSource: snapshotExists ? "detected-config-match" : "not-found",
            SnapshotExists: snapshotExists,
            GuestTransport: "PowerShellRemoting",
            GuestAddressMode: guestRemoting.AddressMode.ToString(),
            GuestAddress: guestRemoting.Address,
            GuestAddressSource: GuestAddressSource(guestRemoting),
            GuestEndpointReady: guestEndpointReady,
            GuestPort: guestRemoting.Port,
            GuestUseSsl: guestRemoting.UseSsl,
            GuestAuthentication: guestRemoting.Authentication,
            GuestSkipCertificateChecks: guestRemoting.SkipCertificateChecks,
            GuestTransportSecure: true,
            PrimaryTool: systemFact,
            SecondaryTool: imageToolFact,
            MachineDefinition: diskFact,
            VmCandidates: [qemuCandidate],
            DiagnosticCode: runningProcessAmbiguous
                ? "QEMU_PROCESS_IDENTITY_AMBIGUOUS"
                : !userNatPortAvailable
                ? "QEMU_USER_NAT_PORT_UNAVAILABLE"
                : snapshotExists
                    ? "QEMU_QUERY_OK"
                    : "QEMU_SNAPSHOT_NOT_FOUND",
            DiagnosticMessage: runningProcessAmbiguous
                ? $"Multiple active KSword QEMU processes match VM '{vmName}'. Stop duplicate runs before restoring the configured internal snapshot."
                : !userNatPortAvailable
                ? $"QEMU user-NAT WinRM host-forward port {guestRemoting.Port} on 127.0.0.1 is unavailable. Stop the conflicting listener or configure another guestRemoting.port. {userNatPortError}" +
                  (snapshotExists ? string.Empty : $" Configured QEMU internal snapshot '{snapshotName}' was also not found.")
                : snapshotExists
                    ? "QEMU tools, disk image, and configured internal snapshot were detected."
                    : $"Configured QEMU internal snapshot '{snapshotName}' was not found.");
    }

    private static bool CanBindLoopbackPort(int port, out string? error)
    {
        System.Net.Sockets.TcpListener? listener = null;
        try
        {
            listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, port)
            {
                ExclusiveAddressUse = true
            };
            listener.Start();
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = SafeDiagnostic(ex.Message);
            return false;
        }
        finally
        {
            listener?.Stop();
        }
    }

    private async Task<bool> QemuProcessOwnsConfiguredUserNatEndpointAsync(
        QemuActiveProcessIdentity activeProcess,
        int port,
        CancellationToken cancellationToken) =>
        await QemuProcessMatchesProviderIdentityAsync(activeProcess, port, cancellationToken).ConfigureAwait(false);

    private async Task<bool> QemuProcessMatchesProviderIdentityAsync(
        QemuActiveProcessIdentity activeProcess,
        int? requiredUserNatPort,
        CancellationToken cancellationToken)
    {
        static string PowerShellLiteral(string value) => value.Replace("'", "''", StringComparison.Ordinal);

        var expectedExecutable = ResolveExecutable(config.Qemu.QemuSystemPath) ?? config.Qemu.QemuSystemPath;
        var pidMarkerPath = Path.GetFullPath(activeProcess.PidMarkerPath);
        var jobRoot = Path.GetDirectoryName(activeProcess.PidMarkerPath) ?? string.Empty;
        var configuredVmName = config.Qemu.VmName?.Trim() ?? string.Empty;
        var expectedProcessVmName = ResolveExpectedQemuProcessVmName(
            configuredVmName,
            config.Qemu.UseOverlayDisk,
            activeProcess.PidMarkerPath);
        var forwardMatchExpression = requiredUserNatPort is int port
            ? $"$commandLine.IndexOf('hostfwd=tcp:127.0.0.1:{port}-:', [StringComparison]::OrdinalIgnoreCase) -ge 0"
            : "$true";
        var script = $$"""
            $result = [ordered]@{ querySucceeded = $false; ownsEndpoint = $false }
            try {
              $process = Get-CimInstance Win32_Process -Filter "ProcessId = {{activeProcess.ProcessId}}" -ErrorAction Stop | Select-Object -First 1
              if ($null -eq $process -or
                  [string]::IsNullOrWhiteSpace([string]$process.ExecutablePath) -or
                  [string]::IsNullOrWhiteSpace([string]$process.CommandLine)) {
                throw 'QEMU executable path or command line is unavailable.'
              }
              $expectedExecutable = '{{PowerShellLiteral(expectedExecutable)}}'
              $pidMarkerPath = '{{PowerShellLiteral(pidMarkerPath)}}'
              $jobRoot = '{{PowerShellLiteral(jobRoot)}}'
              $vmName = '{{PowerShellLiteral(expectedProcessVmName)}}'
              $commandLine = [string]$process.CommandLine
              $executableMatches = ([IO.Path]::GetFullPath([string]$process.ExecutablePath)).Equals([IO.Path]::GetFullPath($expectedExecutable), [StringComparison]::OrdinalIgnoreCase)
              $pidMarkerMatches = $commandLine.IndexOf($pidMarkerPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
              $runtimeMatches = $commandLine.IndexOf($jobRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
              $escapedVmName = [Text.RegularExpressions.Regex]::Escape($vmName)
              $vmNamePattern = '(?i)(?:^|\s)-name(?:\s+|=)(?:"' + $escapedVmName + '"|' + $escapedVmName + ')(?=\s|$)'
              $vmMatches = -not [string]::IsNullOrWhiteSpace($vmName) -and [Text.RegularExpressions.Regex]::IsMatch($commandLine, $vmNamePattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
              $forwardMatches = {{forwardMatchExpression}}
              $result.querySucceeded = $true
              $result.ownsEndpoint = $executableMatches -and $pidMarkerMatches -and $runtimeMatches -and $vmMatches -and $forwardMatches
            } catch {
              $result.querySucceeded = $false
            }
            [pscustomobject]$result | ConvertTo-Json -Compress
            """;
        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var result = await RunProcessAsync(
            "powershell.exe",
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedCommand],
            cancellationToken).ConfigureAwait(false);
        if (!result.Success)
        {
            return false;
        }

        try
        {
            var start = result.StandardOutput.IndexOf('{');
            var end = result.StandardOutput.LastIndexOf('}');
            if (start < 0 || end < start)
            {
                return false;
            }

            using var document = JsonDocument.Parse(result.StandardOutput[start..(end + 1)]);
            return ReadBoolean(document.RootElement, "querySucceeded") &&
                ReadBoolean(document.RootElement, "ownsEndpoint");
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string ResolveExpectedQemuProcessVmName(
        string configuredVmName,
        bool useOverlayDisk,
        string pidMarkerPath)
    {
        var normalizedPrefix = configuredVmName.Trim();
        if (!useOverlayDisk)
        {
            return normalizedPrefix;
        }

        var jobRoot = Path.GetDirectoryName(pidMarkerPath);
        var jobIdentityText = string.IsNullOrWhiteSpace(jobRoot) ? string.Empty : Path.GetFileName(jobRoot);
        if (!Guid.TryParseExact(jobIdentityText, "N", out var jobIdentity))
        {
            return string.Empty;
        }

        const int maximumLength = 64;
        var suffix = $"-{jobIdentity:N}";
        var maximumPrefixLength = maximumLength - suffix.Length;
        if (normalizedPrefix.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            normalizedPrefix = normalizedPrefix[..^suffix.Length].TrimEnd('-');
        }

        var boundedPrefix = normalizedPrefix[..Math.Min(normalizedPrefix.Length, maximumPrefixLength)];
        return $"{boundedPrefix}{suffix}";
    }

    private static QemuImageInfo ParseQemuImageInfo(string json)
    {
        using var document = JsonDocument.Parse(json);
        var format = document.RootElement.TryGetProperty("format", out var formatElement) && formatElement.ValueKind == JsonValueKind.String
            ? formatElement.GetString() ?? string.Empty
            : string.Empty;
        IReadOnlyList<string> snapshotNames = !document.RootElement.TryGetProperty("snapshots", out var snapshots) || snapshots.ValueKind != JsonValueKind.Array
            ? Array.Empty<string>()
            : snapshots.EnumerateArray()
                .Where(snapshot => snapshot.TryGetProperty("name", out var name) && name.ValueKind == JsonValueKind.String)
                .Select(snapshot => snapshot.GetProperty("name").GetString() ?? string.Empty)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
        return new QemuImageInfo(format, snapshotNames);
    }

    private string? GetQemuConfigurationError()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(config.Qemu.VmName))
            {
                throw new InvalidOperationException("qemu.vmName is required.");
            }
            if (config.Qemu.MemoryMegabytes is < 256 or > 1048576)
            {
                throw new InvalidOperationException("qemu.memoryMegabytes must be between 256 and 1048576.");
            }
            if (config.Qemu.DiskFormat is not ("qcow2" or "raw" or "vhdx" or "vmdk"))
            {
                throw new InvalidOperationException("qemu.diskFormat must be qcow2, raw, vhdx, or vmdk.");
            }
            if (config.Qemu.DiskInterface is not ("virtio" or "ide" or "scsi"))
            {
                throw new InvalidOperationException("qemu.diskInterface must be virtio, ide, or scsi; if=none is not accepted because the managed disk would not be attached to a boot device.");
            }
            if (!config.Qemu.UseOverlayDisk && string.IsNullOrWhiteSpace(config.Qemu.SnapshotName))
            {
                throw new InvalidOperationException("QEMU internal snapshot mode requires qemu.snapshotName.");
            }

            HyperVRunbookBuilder.ValidateQemuProviderArguments(
                config.Qemu.AdditionalArguments,
                config.Qemu.GuestRemoting.AddressMode);
            var remotingError = GuestRemotingConfigurationError(
                VirtualizationProvider.Qemu,
                ResolveGuestRemoting(VirtualizationProvider.Qemu));
            if (remotingError is not null)
            {
                throw new InvalidOperationException(remotingError);
            }
            return null;
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }
    }

    private IReadOnlyList<QemuActiveProcessIdentity> FindActiveQemuProcesses()
    {
        var activeProcesses = new List<QemuActiveProcessIdentity>();
        var vmsRoot = Path.Combine(config.Paths.RuntimeRoot, "vms");
        if (!Directory.Exists(vmsRoot))
        {
            return activeProcesses;
        }

        var expectedProcessName = Path.GetFileNameWithoutExtension(ResolveExecutable(config.Qemu.QemuSystemPath) ?? config.Qemu.QemuSystemPath);
        foreach (var pidPath in Directory.EnumerateFiles(vmsRoot, "qemu.pid", SearchOption.AllDirectories))
        {
            try
            {
                if (!int.TryParse(File.ReadAllText(pidPath).Trim(), out var pid) || pid <= 0)
                {
                    continue;
                }

                using var process = Process.GetProcessById(pid);
                var markerWrittenUtc = File.GetLastWriteTimeUtc(pidPath);
                var processStartedUtc = process.StartTime.ToUniversalTime();
                if (!process.HasExited &&
                    process.ProcessName.Equals(expectedProcessName, StringComparison.OrdinalIgnoreCase) &&
                    processStartedUtc >= markerWrittenUtc.AddSeconds(-5) &&
                    processStartedUtc <= markerWrittenUtc.AddSeconds(5))
                {
                    activeProcesses.Add(new QemuActiveProcessIdentity(pid, pidPath));
                }
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException or SecurityException or System.ComponentModel.Win32Exception)
            {
                // Stale or unreadable PID markers do not make the read-only probe fail.
            }
        }

        return activeProcesses;
    }

    private LocalVirtualizationReadinessContract ProviderFailure(
        VirtualizationProvider provider,
        string vmName,
        string snapshotName,
        string guestTransport,
        LocalPathFactContract primaryTool,
        LocalPathFactContract secondaryTool,
        LocalPathFactContract machineDefinition,
        string code,
        string message)
    {
        var guestRemoting = ResolveGuestRemoting(provider);
        var accessDenied = IsProviderAccessDenied(message);
        return new LocalVirtualizationReadinessContract(
            Provider: provider,
            ManagementAvailable: primaryTool.Exists && (provider is not VirtualizationProvider.Qemu || secondaryTool.Exists),
            QuerySucceeded: false,
            AccessDenied: accessDenied,
            ConfiguredVmName: vmName,
            VmName: null,
            VmSource: machineDefinition.Exists ? "config-detected" : "config-path-missing",
            VmState: null,
            VmExists: machineDefinition.Exists,
            ConfiguredSnapshotName: snapshotName,
            SnapshotName: null,
            SnapshotSource: "not-probed",
            SnapshotExists: false,
            GuestTransport: guestTransport,
            GuestAddressMode: guestRemoting.AddressMode.ToString(),
            GuestAddress: guestRemoting.Address,
            GuestAddressSource: GuestAddressSource(guestRemoting),
            GuestEndpointReady: GuestEndpointReady(provider, guestRemoting),
            GuestPort: guestRemoting.Port,
            GuestUseSsl: guestRemoting.UseSsl,
            GuestAuthentication: guestRemoting.Authentication,
            GuestSkipCertificateChecks: guestRemoting.SkipCertificateChecks,
            GuestTransportSecure: IsGuestRemotingSecure(guestRemoting),
            PrimaryTool: primaryTool,
            SecondaryTool: secondaryTool,
            MachineDefinition: machineDefinition,
            VmCandidates: [],
            DiagnosticCode: accessDenied ? ProviderAccessDeniedCode(provider) : code,
            DiagnosticMessage: SafeDiagnostic(message));
    }

    private static string ProviderAccessDeniedCode(VirtualizationProvider provider) => provider switch
    {
        VirtualizationProvider.VMware => "VMWARE_ACCESS_DENIED",
        VirtualizationProvider.Qemu => "QEMU_ACCESS_DENIED",
        _ => "PROVIDER_ACCESS_DENIED"
    };

    private static bool IsProviderAccessDenied(string message)
    {
        return message.Contains("access denied", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("access is denied", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("permission denied", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("eacces", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("0x80070005", StringComparison.OrdinalIgnoreCase) ||
               message.Contains("拒绝访问", StringComparison.Ordinal) ||
               message.Contains("访问被拒绝", StringComparison.Ordinal);
    }

    private LocalGuestReadinessContract BuildGuestReadiness()
    {
        var secretName = string.IsNullOrWhiteSpace(config.Guest.PasswordSecretName)
            ? "KSWORDBOX_GUEST_PASSWORD"
            : config.Guest.PasswordSecretName.Trim();
        var secretAvailable = TryResolveEnvironmentVariable(secretName, out var source);
        return new LocalGuestReadinessContract(
            UserName: config.Guest.UserName,
            UserNameSource: "active-config",
            WorkingDirectory: config.Guest.WorkingDirectory,
            WorkingDirectorySource: "active-config",
            PasswordSecretName: secretName,
            PasswordSecretAvailable: secretAvailable,
            PasswordSecretSource: source);
    }

    private GuestRemotingConfig ResolveGuestRemoting(VirtualizationProvider provider)
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
                Port = providerConfig.Port > 0 ? providerConfig.Port : providerConfig.UseSsl ? 55986 : 55985
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

    private static string? GuestRemotingConfigurationError(
        VirtualizationProvider provider,
        GuestRemotingConfig remoting)
    {
        if (provider is VirtualizationProvider.VMware &&
            remoting.AddressMode is not (GuestRemotingAddressMode.Configured or GuestRemotingAddressMode.VMwareTools))
        {
            return "VMware guestRemoting.addressMode must be Configured or VMwareTools.";
        }
        if (provider is VirtualizationProvider.Qemu &&
            remoting.AddressMode is not (GuestRemotingAddressMode.Configured or GuestRemotingAddressMode.QemuUserNat))
        {
            return "QEMU guestRemoting.addressMode must be Configured or QemuUserNat.";
        }
        if (remoting.AddressMode is GuestRemotingAddressMode.Configured &&
            string.IsNullOrWhiteSpace(remoting.Address))
        {
            return $"{provider} guestRemoting.address is required when addressMode=Configured.";
        }
        return null;
    }

    private static bool GuestEndpointReady(
        VirtualizationProvider provider,
        GuestRemotingConfig remoting) =>
        provider switch
        {
            VirtualizationProvider.VMware =>
                remoting.AddressMode is GuestRemotingAddressMode.VMwareTools ||
                remoting.AddressMode is GuestRemotingAddressMode.Configured &&
                !string.IsNullOrWhiteSpace(remoting.Address),
            VirtualizationProvider.Qemu =>
                remoting.AddressMode is GuestRemotingAddressMode.QemuUserNat ||
                remoting.AddressMode is GuestRemotingAddressMode.Configured &&
                !string.IsNullOrWhiteSpace(remoting.Address),
            _ => true
        };

    private static string GuestAddressSource(GuestRemotingConfig remoting) => remoting.AddressMode switch
    {
        GuestRemotingAddressMode.VMwareTools => "vmware-tools-auto-discovery",
        GuestRemotingAddressMode.QemuUserNat => "provider-managed-user-nat",
        _ => "configured"
    };

    private static bool IsGuestRemotingSecure(GuestRemotingConfig remoting) =>
        !(remoting.AddressMode is GuestRemotingAddressMode.VMwareTools or GuestRemotingAddressMode.QemuUserNat && !remoting.UseSsl) &&
        !(string.Equals(remoting.Authentication, "Basic", StringComparison.OrdinalIgnoreCase) && !remoting.UseSsl) &&
        !(remoting.SkipCertificateChecks && !remoting.UseSsl);

    private static string GuestRemotingSecurityDiagnostic(GuestRemotingConfig remoting)
    {
        if (remoting.AddressMode is GuestRemotingAddressMode.VMwareTools or GuestRemotingAddressMode.QemuUserNat &&
            !remoting.UseSsl)
        {
            return $"{remoting.AddressMode} automatic endpoint mode requires WinRM HTTPS so IP/loopback connections do not depend on host-wide TrustedHosts.";
        }

        return string.Equals(remoting.Authentication, "Basic", StringComparison.OrdinalIgnoreCase) && !remoting.UseSsl
            ? "Basic WinRM over HTTP is refused; enable HTTPS or use Negotiate/CredSSP."
            : "Guest certificate checks can be skipped only when WinRM HTTPS is enabled.";
    }

    private LocalPathReadinessContract BuildPathReadiness()
    {
        var payloadRoot = config.Paths.GuestPayloadRoot;
        return new LocalPathReadinessContract(
            RuntimeRoot: DirectoryFact(config.Paths.RuntimeRoot),
            GuestPayloadRoot: DirectoryFact(payloadRoot),
            PayloadManifest: FileFact(Path.Combine(payloadRoot, "payload-manifest.json")),
            AgentExecutable: FileFact(Path.Combine(payloadRoot, "agent", config.Guest.AgentExecutableName)),
            CollectorExecutable: FileFact(Path.Combine(payloadRoot, "r0collector", "KSword.Sandbox.R0Collector.exe")),
            BaseVhdx: FileFact(config.HyperV.BaseVhdxPath));
    }

    private static LocalPathFactContract DirectoryFact(string? path)
    {
        var configured = !string.IsNullOrWhiteSpace(path);
        var exists = configured && Directory.Exists(path);
        return new LocalPathFactContract(path, configured, exists, "directory", PathSource(configured, exists));
    }

    private static LocalPathFactContract FileFact(string? path)
    {
        var configured = !string.IsNullOrWhiteSpace(path);
        var exists = configured && File.Exists(path);
        return new LocalPathFactContract(path, configured, exists, "file", PathSource(configured, exists));
    }

    private static LocalPathFactContract ExecutableFact(string configuredPath, string? resolvedPath)
    {
        var configured = !string.IsNullOrWhiteSpace(configuredPath);
        var exists = !string.IsNullOrWhiteSpace(resolvedPath);
        return new LocalPathFactContract(
            resolvedPath ?? configuredPath,
            configured,
            exists,
            "executable",
            !configured ? "not-configured" : exists ? "command-detected" : "command-missing");
    }

    private static string? ResolveExecutable(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return null;
        }

        var value = configuredPath.Trim();
        if (Path.IsPathRooted(value) || value.Contains(Path.DirectorySeparatorChar) || value.Contains(Path.AltDirectorySeparatorChar))
        {
            return File.Exists(value) ? Path.GetFullPath(value) : null;
        }

        var extensions = OperatingSystem.IsWindows() && string.IsNullOrWhiteSpace(Path.GetExtension(value))
            ? new[] { string.Empty, ".exe", ".cmd", ".bat" }
            : new[] { string.Empty };
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var extension in extensions)
            {
                var candidate = Path.Combine(directory, value + extension);
                if (File.Exists(candidate))
                {
                    return Path.GetFullPath(candidate);
                }
            }
        }

        return null;
    }

    private static bool PathsEqual(string candidate, string expected)
    {
        try
        {
            return string.Equals(
                Path.GetFullPath(candidate.Trim()),
                Path.GetFullPath(expected),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private async Task<ProcessProbeResult> RunProcessAsync(
        string executable,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        SanitizeProviderProcessEnvironment(startInfo, config.Guest.PasswordSecretName);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return ProcessProbeResult.Failed(SafeDiagnostic(ex.Message));
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ProviderProbeTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            return ProcessProbeResult.Timeout();
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        return process.ExitCode == 0
            ? ProcessProbeResult.Passed(stdout, stderr)
            : ProcessProbeResult.Failed(SafeDiagnostic(string.IsNullOrWhiteSpace(stderr) ? stdout : stderr), process.ExitCode, stdout, stderr);
    }

    private static void SanitizeProviderProcessEnvironment(ProcessStartInfo startInfo, string? guestSecretName)
    {
        var names = startInfo.Environment.Keys.ToArray();
        foreach (var name in names)
        {
            if ((!string.IsNullOrWhiteSpace(guestSecretName) && name.Equals(guestSecretName, StringComparison.OrdinalIgnoreCase)) ||
                name.StartsWith("KSWORDBOX_", StringComparison.OrdinalIgnoreCase) ||
                SensitiveEnvironmentNamePattern.IsMatch(name))
            {
                startInfo.Environment.Remove(name);
            }
        }
    }

    private static string PathSource(bool configured, bool exists) => !configured
        ? "not-configured"
        : exists
            ? "config-path-detected"
            : "config-path-missing";

    private static bool TryResolveEnvironmentVariable(string name, out string source)
    {
        foreach (var scope in new[]
                 {
                     EnvironmentVariableTarget.Process,
                     EnvironmentVariableTarget.User,
                     EnvironmentVariableTarget.Machine
                 })
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name, scope)))
                {
                    source = scope.ToString().ToLowerInvariant();
                    return true;
                }
            }
            catch (SecurityException)
            {
                // Continue with the remaining scopes; no secret value is exposed.
            }
        }

        source = "not-found";
        return false;
    }

    private static bool IsCurrentProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private async Task<LocalHostVirtualizationCapabilitiesContract> ProbeHostVirtualizationAsync(
        VirtualizationProvider provider,
        CancellationToken cancellationToken)
    {
        var acceleratorExpectation = provider switch
        {
            VirtualizationProvider.VMware => "VMware hardware acceleration",
            VirtualizationProvider.Qemu => "QEMU WHPX hardware acceleration",
            _ => "Hyper-V hardware acceleration"
        };
        var requiredWindowsFeature = provider switch
        {
            VirtualizationProvider.HyperV => "Microsoft-Hyper-V-All",
            VirtualizationProvider.Qemu => "HypervisorPlatform",
            _ => string.Empty
        };
        if (!OperatingSystem.IsWindows())
        {
            return new LocalHostVirtualizationCapabilitiesContract(
                Provider: provider,
                OperatingSystemSupported: false,
                QuerySucceeded: false,
                HypervisorPresent: null,
                VirtualizationFirmwareEnabled: null,
                SecondLevelAddressTranslationSupported: null,
                VmMonitorModeExtensions: null,
                HardwareAccelerationReady: false,
                AcceleratorExpectation: acceleratorExpectation,
                RequiredWindowsFeature: requiredWindowsFeature,
                RequiredWindowsFeatureState: "NotApplicableOnCurrentOS",
                RequiredWindowsFeatureReady: string.IsNullOrEmpty(requiredWindowsFeature) ? true : false,
                StartsOrMutatesVm: false,
                DiagnosticCode: "WINDOWS_HOST_REQUIRED",
                DiagnosticMessage: "KSwordSandbox live virtualization requires a Windows host.");
        }

        var script = """
            $ProgressPreference = 'SilentlyContinue'
            $ErrorActionPreference = 'Stop'
            $result = [ordered]@{
              querySucceeded = $false
              hypervisorPresent = $null
              virtualizationFirmwareEnabled = $null
              secondLevelAddressTranslationSupported = $null
              vmMonitorModeExtensions = $null
              requiredWindowsFeature = '__KSWORD_REQUIRED_WINDOWS_FEATURE__'
              requiredWindowsFeatureState = if ('__KSWORD_REQUIRED_WINDOWS_FEATURE__' -eq '') { 'NotRequired' } else { 'Unknown' }
              requiredWindowsFeatureReady = if ('__KSWORD_REQUIRED_WINDOWS_FEATURE__' -eq '') { $true } else { $null }
              diagnosticCode = ''
              diagnosticMessage = ''
            }
            try {
              if ($null -eq (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
                $result.diagnosticCode = 'HOST_CIM_UNAVAILABLE'
                $result.diagnosticMessage = 'Get-CimInstance is unavailable; CPU virtualization capabilities could not be inspected.'
              } else {
                $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                $result.hypervisorPresent = [bool]$computerSystem.HypervisorPresent
                $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
                if ($null -eq $processor) {
                  $result.diagnosticCode = 'HOST_PROCESSOR_NOT_FOUND'
                  $result.diagnosticMessage = 'Win32_Processor returned no processor record.'
                } else {
                  $firmware = $processor.PSObject.Properties['VirtualizationFirmwareEnabled']
                  $slat = $processor.PSObject.Properties['SecondLevelAddressTranslationExtensions']
                  $monitor = $processor.PSObject.Properties['VMMonitorModeExtensions']
                  if ($null -ne $firmware) { $result.virtualizationFirmwareEnabled = [bool]$firmware.Value }
                  if ($null -ne $slat) { $result.secondLevelAddressTranslationSupported = [bool]$slat.Value }
                  if ($null -ne $monitor) { $result.vmMonitorModeExtensions = [bool]$monitor.Value }
                  $result.querySucceeded = $true
                  $result.diagnosticCode = 'HOST_VIRTUALIZATION_QUERY_OK'
                  $result.diagnosticMessage = 'Windows CPU virtualization capabilities were inspected read-only.'
                }
              }
            } catch {
              $result.diagnosticCode = 'HOST_VIRTUALIZATION_QUERY_FAILED'
              $result.diagnosticMessage = [string]$_.Exception.Message
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$result.requiredWindowsFeature)) {
              try {
                $featureState = ''
                $featureErrors = [System.Collections.Generic.List[string]]::new()
                if ($null -ne (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
                  try {
                    $feature = Get-WindowsOptionalFeature -Online -FeatureName $result.requiredWindowsFeature -ErrorAction Stop
                    $featureState = [string]$feature.State
                  } catch {
                    [void]$featureErrors.Add("Get-WindowsOptionalFeature: $($_.Exception.Message)")
                  }
                } else {
                  [void]$featureErrors.Add('Get-WindowsOptionalFeature is unavailable.')
                }
                if ([string]::IsNullOrWhiteSpace($featureState)) {
                  try {
                    if ($null -eq (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
                      throw 'Get-CimInstance is unavailable.'
                    }
                    $escapedFeatureName = ([string]$result.requiredWindowsFeature).Replace("'", "''")
                    $feature = Get-CimInstance -ClassName Win32_OptionalFeature -Filter "Name='$escapedFeatureName'" -ErrorAction Stop | Select-Object -First 1
                    if ($null -eq $feature) {
                      throw "Win32_OptionalFeature did not return '$($result.requiredWindowsFeature)'."
                    }
                    $featureState = switch ([int]$feature.InstallState) {
                      1 { 'Enabled' }
                      2 { 'Disabled' }
                      3 { 'Absent' }
                      default { 'Unknown' }
                    }
                  } catch {
                    [void]$featureErrors.Add("Win32_OptionalFeature: $($_.Exception.Message)")
                  }
                }
                if ($featureState -eq 'Unknown') {
                  [void]$featureErrors.Add("Windows reported an unknown state for '$($result.requiredWindowsFeature)'.")
                }
                if ([string]::IsNullOrWhiteSpace($featureState) -or $featureState -eq 'Unknown') {
                  throw ($featureErrors -join ' ')
                }
                $result.requiredWindowsFeatureState = $featureState
                $result.requiredWindowsFeatureReady = $featureState -eq 'Enabled'
              } catch {
                $result.requiredWindowsFeatureState = 'Unknown'
                $result.requiredWindowsFeatureReady = $null
                $featureMessage = "Required Windows feature '$($result.requiredWindowsFeature)' could not be confirmed: $($_.Exception.Message)"
                $result.diagnosticMessage = if ([string]::IsNullOrWhiteSpace([string]$result.diagnosticMessage)) { $featureMessage } else { "$($result.diagnosticMessage) $featureMessage" }
              }
            }
            [pscustomobject]$result | ConvertTo-Json -Depth 3 -Compress
            """.Replace("__KSWORD_REQUIRED_WINDOWS_FEATURE__", requiredWindowsFeature);

        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var result = await RunProcessAsync(
            "powershell.exe",
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedCommand],
            cancellationToken).ConfigureAwait(false);
        if (!result.Success)
        {
            return new LocalHostVirtualizationCapabilitiesContract(
                provider,
                true,
                false,
                null,
                null,
                null,
                null,
                null,
                acceleratorExpectation,
                requiredWindowsFeature,
                string.IsNullOrEmpty(requiredWindowsFeature) ? "NotRequired" : "Unknown",
                string.IsNullOrEmpty(requiredWindowsFeature) ? true : null,
                false,
                result.TimedOut ? "HOST_VIRTUALIZATION_QUERY_TIMEOUT" : "HOST_VIRTUALIZATION_PROBE_FAILED",
                result.Diagnostic);
        }

        try
        {
            var start = result.StandardOutput.IndexOf('{');
            var end = result.StandardOutput.LastIndexOf('}');
            if (start < 0 || end < start)
            {
                throw new JsonException("PowerShell output did not contain host virtualization JSON.");
            }

            using var document = JsonDocument.Parse(result.StandardOutput[start..(end + 1)]);
            var root = document.RootElement;
            var hypervisorPresent = ReadNullableBoolean(root, "hypervisorPresent");
            var firmwareEnabled = ReadNullableBoolean(root, "virtualizationFirmwareEnabled");
            var slatSupported = ReadNullableBoolean(root, "secondLevelAddressTranslationSupported");
            var vmMonitorModeExtensions = ReadNullableBoolean(root, "vmMonitorModeExtensions");
            var requiredWindowsFeatureState = ReadString(root, "requiredWindowsFeatureState");
            var requiredWindowsFeatureReady = ReadNullableBoolean(root, "requiredWindowsFeatureReady");
            var querySucceeded = ReadBoolean(root, "querySucceeded") && requiredWindowsFeatureReady is not null;
            var firmwareEffective = firmwareEnabled is true || hypervisorPresent is true;
            bool? hardwareReady = (firmwareEnabled is false && hypervisorPresent is not true) ||
                                  slatSupported is false ||
                                  requiredWindowsFeatureReady is false
                ? false
                : querySucceeded && firmwareEffective && slatSupported is true && requiredWindowsFeatureReady is true
                    ? true
                    : null;
            var diagnosticCode = requiredWindowsFeatureReady switch
            {
                false => "HOST_REQUIRED_WINDOWS_FEATURE_DISABLED",
                null => "HOST_REQUIRED_WINDOWS_FEATURE_UNCONFIRMED",
                _ => ReadString(root, "diagnosticCode")
            };
            var diagnosticMessage = requiredWindowsFeatureReady switch
            {
                false => $"Required Windows feature '{requiredWindowsFeature}' is '{requiredWindowsFeatureState}', not Enabled.",
                null => $"Required Windows feature '{requiredWindowsFeature}' could not be confirmed. {ReadString(root, "diagnosticMessage")}",
                _ => ReadString(root, "diagnosticMessage")
            };
            return new LocalHostVirtualizationCapabilitiesContract(
                provider,
                true,
                querySucceeded,
                hypervisorPresent,
                firmwareEnabled,
                slatSupported,
                vmMonitorModeExtensions,
                hardwareReady,
                acceleratorExpectation,
                requiredWindowsFeature,
                requiredWindowsFeatureState,
                requiredWindowsFeatureReady,
                false,
                diagnosticCode,
                SafeDiagnostic(diagnosticMessage));
        }
        catch (JsonException ex)
        {
            return new LocalHostVirtualizationCapabilitiesContract(
                provider,
                true,
                false,
                null,
                null,
                null,
                null,
                null,
                acceleratorExpectation,
                requiredWindowsFeature,
                string.IsNullOrEmpty(requiredWindowsFeature) ? "NotRequired" : "Unknown",
                string.IsNullOrEmpty(requiredWindowsFeature) ? true : null,
                false,
                "HOST_VIRTUALIZATION_INVALID_RESPONSE",
                SafeDiagnostic(ex.Message));
        }
    }

    private async Task<HyperVProbeResult> ProbeHyperVAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return HyperVProbeResult.Failed(false, "HYPERV_WINDOWS_REQUIRED", "Hyper-V inventory is available only on Windows hosts.");
        }

        var script = """
            $ProgressPreference = 'SilentlyContinue'
            $ErrorActionPreference = 'Stop'
            $result = [ordered]@{
              managementAvailable = $false
              querySucceeded = $false
              diagnosticCode = ''
              diagnosticMessage = ''
              vms = @()
            }
            try {
              $command = Get-Command Get-VM -ErrorAction SilentlyContinue
              if ($null -eq $command) {
                $result.diagnosticCode = 'HYPERV_CMDLET_MISSING'
                $result.diagnosticMessage = 'Hyper-V PowerShell management cmdlets were not found.'
              } else {
                $result.managementAvailable = $true
                try {
                  $items = @()
                  foreach ($vm in @(Get-VM -ErrorAction Stop | Sort-Object Name)) {
                    $checkpointNames = @()
                    $checkpointDiagnostic = ''
                    try {
                      $checkpointNames = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction Stop | Sort-Object Name | ForEach-Object { [string]$_.Name })
                    } catch {
                      $checkpointDiagnostic = [string]$_.Exception.Message
                    }
                    $items += [pscustomobject][ordered]@{
                      name = [string]$vm.Name
                      state = [string]$vm.State
                      checkpoints = @($checkpointNames)
                      checkpointDiagnostic = $checkpointDiagnostic
                    }
                  }
                  $result.vms = @($items)
                  $result.querySucceeded = $true
                  $result.diagnosticCode = if ($items.Count -eq 0) { 'HYPERV_NO_VMS' } else { 'HYPERV_QUERY_OK' }
                  $result.diagnosticMessage = if ($items.Count -eq 0) { 'No local Hyper-V virtual machines were detected.' } else { "Detected $($items.Count) local Hyper-V virtual machine(s)." }
                } catch {
                  $message = [string]$_.Exception.Message
                  $result.diagnosticCode = if ($message -match 'Access is denied|Access denied|拒绝访问') { 'HYPERV_ACCESS_DENIED' } else { 'HYPERV_QUERY_FAILED' }
                  $result.diagnosticMessage = $message
                }
              }
            } catch {
              $result.diagnosticCode = 'HYPERV_PROBE_FAILED'
              $result.diagnosticMessage = [string]$_.Exception.Message
            }
            [pscustomobject]$result | ConvertTo-Json -Depth 6 -Compress
            """;

        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encodedCommand);
        SanitizeProviderProcessEnvironment(startInfo, config.Guest.PasswordSecretName);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return HyperVProbeResult.Failed(false, "POWERSHELL_LAUNCH_FAILED", SafeDiagnostic(ex.Message));
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HyperVProbeTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            return HyperVProbeResult.Failed(true, "HYPERV_QUERY_TIMEOUT", "The read-only Hyper-V inventory query timed out.");
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(stdout))
        {
            return HyperVProbeResult.Failed(
                false,
                "HYPERV_EMPTY_RESPONSE",
                SafeDiagnostic(string.IsNullOrWhiteSpace(stderr) ? "PowerShell returned no Hyper-V inventory JSON." : stderr));
        }

        try
        {
            return ParseHyperVProbe(stdout);
        }
        catch (JsonException ex)
        {
            return HyperVProbeResult.Failed(false, "HYPERV_INVALID_RESPONSE", SafeDiagnostic(ex.Message));
        }
    }

    private static HyperVProbeResult ParseHyperVProbe(string stdout)
    {
        var start = stdout.IndexOf('{');
        var end = stdout.LastIndexOf('}');
        if (start < 0 || end < start)
        {
            throw new JsonException("PowerShell output did not contain a JSON object.");
        }

        using var document = JsonDocument.Parse(stdout[start..(end + 1)]);
        var root = document.RootElement;
        var candidates = new List<LocalVmCandidateContract>();
        if (root.TryGetProperty("vms", out var vms) && vms.ValueKind == JsonValueKind.Array)
        {
            foreach (var vm in vms.EnumerateArray())
            {
                var checkpoints = ReadStringList(vm, "checkpoints");
                candidates.Add(new LocalVmCandidateContract(
                    Name: ReadString(vm, "name"),
                    State: ReadString(vm, "state"),
                    Checkpoints: checkpoints,
                    CheckpointDiagnostic: NullIfBlank(ReadString(vm, "checkpointDiagnostic"))));
            }
        }

        return new HyperVProbeResult(
            ManagementAvailable: ReadBoolean(root, "managementAvailable"),
            QuerySucceeded: ReadBoolean(root, "querySucceeded"),
            DiagnosticCode: ReadString(root, "diagnosticCode"),
            DiagnosticMessage: SafeDiagnostic(ReadString(root, "diagnosticMessage")),
            Vms: candidates);
    }

    private static IReadOnlyList<string> ReadStringList(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value))
        {
            return Array.Empty<string>();
        }

        if (value.ValueKind == JsonValueKind.Array)
        {
            return value.EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString() ?? string.Empty)
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .ToArray();
        }

        return value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? new[] { value.GetString()! }
            : Array.Empty<string>();
    }

    private static string ReadString(JsonElement parent, string propertyName) =>
        parent.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static bool ReadBoolean(JsonElement parent, string propertyName) =>
        parent.TryGetProperty(propertyName, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False && value.GetBoolean();

    private static bool? ReadNullableBoolean(JsonElement parent, string propertyName) =>
        parent.TryGetProperty(propertyName, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : null;

    private static string SafeDiagnostic(string? value)
    {
        var normalized = string.Join(" ", (value ?? string.Empty)
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return normalized.Length <= 240 ? normalized : normalized[..240] + "…";
    }

    private static string? NullIfBlank(string value) => string.IsNullOrWhiteSpace(value) ? null : SafeDiagnostic(value);

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best effort only; the process has an independent bounded command.
        }
    }

    private sealed record HyperVProbeResult(
        bool ManagementAvailable,
        bool QuerySucceeded,
        string DiagnosticCode,
        string DiagnosticMessage,
        IReadOnlyList<LocalVmCandidateContract> Vms)
    {
        internal static HyperVProbeResult Failed(bool managementAvailable, string code, string message) =>
            new(managementAvailable, false, code, message, Array.Empty<LocalVmCandidateContract>());
    }

    private sealed record QemuImageInfo(
        string Format,
        IReadOnlyList<string> SnapshotNames);

    private sealed record QemuActiveProcessIdentity(
        int ProcessId,
        string PidMarkerPath);

    private sealed record ProcessProbeResult(
        bool Success,
        bool TimedOut,
        int? ExitCode,
        string StandardOutput,
        string StandardError,
        string Diagnostic)
    {
        internal static ProcessProbeResult Passed(string stdout, string stderr) =>
            new(true, false, 0, stdout, stderr, string.Empty);

        internal static ProcessProbeResult Failed(
            string diagnostic,
            int? exitCode = null,
            string stdout = "",
            string stderr = "") =>
            new(false, false, exitCode, stdout, stderr, diagnostic);

        internal static ProcessProbeResult Timeout() =>
            new(false, true, null, string.Empty, string.Empty, "The provider readiness command timed out.");
    }
}
