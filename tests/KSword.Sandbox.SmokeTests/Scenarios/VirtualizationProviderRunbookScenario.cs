using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Core.Configuration;
using KSword.Sandbox.Core.Orchestration;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies that each supported hypervisor produces a complete, provider-
/// specific runbook without executing host virtualization commands.
/// </summary>
internal sealed class VirtualizationProviderRunbookScenario : ISmokeTestScenario
{
    public string ScenarioId => "virtualization.provider-runbook.contract";

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var builder = new HyperVRunbookBuilder();
        var sample = CreateSample();
        var jobId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var baseConfig = CreateBaseConfig();
        var expectedLiveExecutionLeasePath = Path.Combine(baseConfig.Paths.RuntimeRoot, "locks", "live-execution.lock");

        var hyperV = builder.Build(baseConfig, jobId, sample);
        SmokeAssert.True(hyperV.Provider is VirtualizationProvider.HyperV, "Existing configs should continue to select Hyper-V by default.");
        SmokeAssert.True(hyperV.LiveExecutionLeasePath == expectedLiveExecutionLeasePath, "Hyper-V should use the runtime-root live execution lease.");
        RequireStepContains(hyperV, "restore-golden", "Restore-VMSnapshot");
        RequireAnyStepContains(hyperV, "New-PSSession -VMName");
        RequireProviderResourceFailure(
            baseConfig,
            VirtualizationProvider.HyperV,
            baselineName: null,
            machineDefinitionPath: @"D:\VMs\unexpected.vmx",
            qemuDiskFormat: null,
            expectedMessage: "does not accept a machine-definition path override");

        var vmwareConfig = CreateBaseConfig() with
        {
            Virtualization = new VirtualizationConfig { Provider = VirtualizationProvider.VMware },
            VMware = new VMwareConfig
            {
                VmName = "KSword-VMware",
                VmxPath = @"D:\VMs\KSword\KSword.vmx",
                SnapshotName = "Clean",
                VmrunPath = "vmrun.exe",
                VmType = "ws",
                GuestRemoting = new GuestRemotingConfig { Address = "192.0.2.20", Port = 5985 }
            },
            Guest = CreateRemoteGuestConfig("192.0.2.99")
        };
        var vmware = builder.Build(vmwareConfig, jobId, sample);
        SmokeAssert.True(vmware.Provider is VirtualizationProvider.VMware, "VMware config should select the VMware provider.");
        SmokeAssert.True(vmware.TargetVmName == "KSword-VMware", "VMware runbook should expose the configured VM name.");
        SmokeAssert.True(vmware.BaselineName == "Clean", "VMware runbook should expose the effective snapshot baseline.");
        SmokeAssert.True(vmware.MachineDefinitionPath == vmwareConfig.VMware.VmxPath, "VMware runbook should expose the effective VMX path.");
        SmokeAssert.True(vmware.LiveExecutionLeasePath == expectedLiveExecutionLeasePath, "VMware should share the Hyper-V live execution lease.");
        RequireStepContains(vmware, "restore-vm-snapshot", "revertToSnapshot");
        RequireStepContains(vmware, "start-vm", "start $vmxPath gui");
        RequireStepContains(vmware, "start-vm", "SetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD', $null, 'Process')");
        RequireStepContains(vmware, "open-vm-desktop", "VMware console window verified");
        RequireStepContains(vmware, "open-vm-desktop", "target-associated VMware console window");
        RequireStepContains(vmware, "stop-vm-before-restore", "did not reach stopped state after vmrun stop within 60 seconds");
        RequireStepContains(vmware, "start-vm", "did not reach running state after vmrun start within 60 seconds");
        RequireAnyStepContains(vmware, "$guestRemotingAddress = '192.0.2.20'");
        RequireAnyStepContains(vmware, "New-PSSession -ComputerName $guestRemotingAddress");
        RequireAnyStepContains(vmware, "-Port 5985");
        SmokeAssert.True(vmware.Steps.All(step => !step.RequiresElevation), "VMware runbooks should not require elevation unconditionally.");
        RequireProviderResourceFailure(
            vmwareConfig,
            VirtualizationProvider.VMware,
            baselineName: null,
            machineDefinitionPath: vmwareConfig.VMware.VmxPath,
            qemuDiskFormat: "qcow2",
            expectedMessage: "apply only to Qemu");

        var vmwareTools = builder.Build(vmwareConfig with
        {
            VMware = vmwareConfig.VMware with
            {
                GuestRemoting = new GuestRemotingConfig
                {
                    AddressMode = GuestRemotingAddressMode.VMwareTools,
                    UseSsl = true,
                    SkipCertificateChecks = true
                }
            }
        }, jobId, sample);
        RequireAnyStepContains(vmwareTools, "getGuestIPAddress $vmxPath");
        SmokeAssert.True(
            vmwareTools.Steps.All(step => !step.PowerShell.Contains("getGuestIPAddress $vmxPath -wait", StringComparison.Ordinal)),
            "VMware Tools address discovery must remain bounded by the shared guest readiness loop.");
        RequireAnyStepContains(vmwareTools, "[Net.Sockets.AddressFamily]::InterNetwork");
        RequireAnyStepContains(vmwareTools, "169.254.");
        RequireAnyStepContains(vmwareTools, "IsIPv6LinkLocal");
        RequireAnyStepContains(vmwareTools, "New-PSSession -ComputerName $guestRemotingAddress");
        RequireAnyStepContains(vmwareTools, "New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck");
        RequireAnyStepContains(vmwareTools, "-UseSSL");

        var qemuConfig = CreateBaseConfig() with
        {
            Virtualization = new VirtualizationConfig { Provider = VirtualizationProvider.Qemu },
            Qemu = new QemuConfig
            {
                VmName = "KSword-QEMU",
                QemuSystemPath = "qemu-system-x86_64.exe",
                QemuImgPath = "qemu-img.exe",
                DiskImagePath = @"D:\VMs\KSword\base.qcow2",
                DiskFormat = "qcow2",
                UseOverlayDisk = true,
                AdditionalArguments = ["-netdev", "user,id=net0"],
                GuestRemoting = new GuestRemotingConfig { Address = "192.0.2.30", Port = 55985 }
            },
            Guest = CreateRemoteGuestConfig("192.0.2.99")
        };
        var qemu = builder.Build(qemuConfig, jobId, sample);
        SmokeAssert.True(qemu.Provider is VirtualizationProvider.Qemu, "QEMU config should select the QEMU provider.");
        SmokeAssert.True(qemu.UsesTemporaryVm, "QEMU overlay mode should be represented as a temporary VM.");
        SmokeAssert.True(qemu.BaselineName == "per-job-overlay", "QEMU overlay mode should not report an unused internal snapshot as its baseline.");
        SmokeAssert.True(qemu.MachineDefinitionPath == qemuConfig.Qemu.DiskImagePath, "QEMU runbook should expose the effective base disk path.");
        SmokeAssert.True(qemu.QemuDiskFormat == "qcow2", "QEMU runbook should expose the effective base disk format.");
        SmokeAssert.True(qemu.LiveExecutionLeasePath == expectedLiveExecutionLeasePath, "QEMU should share the Hyper-V live execution lease.");
        var longNameQemu = builder.Build(qemuConfig with
        {
            Qemu = qemuConfig.Qemu with { VmName = new string('Q', 80) }
        }, jobId, sample);
        SmokeAssert.True(longNameQemu.TargetVmName.Length <= 64, "QEMU per-job target names should remain provider-safe.");
        SmokeAssert.True(
            longNameQemu.TargetVmName.EndsWith($"-{jobId:N}", StringComparison.OrdinalIgnoreCase),
            "QEMU per-job target names should preserve the complete unique job suffix when the configured prefix is long.");
        RequireStepContains(qemu, "stop-vm-before-restore", "Get-CimInstance Win32_Process");
        RequireStepContains(qemu, "stop-vm-before-restore", "baseline restore was aborted");
        RequireStepContains(qemu, "make-overlay-disk", "qemuImg create -f qcow2");
        RequireStepContains(qemu, "start-vm", "Start-Process -FilePath $qemuSystem");
        RequireStepContains(qemu, "start-vm", "'whpx'");
        RequireStepContains(qemu, "start-vm", "SetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD', $null, 'Process')");
        RequireStepContains(qemu, "open-vm-desktop", "QEMU display window verified");
        RequireStepContains(qemu, "open-vm-desktop", "display verification refused pid");
        RequireStepContains(qemu, "start-vm", "StartsWith('KSWORDBOX_'");
        RequireStepContains(qemu, "start-vm", "PASSWORD|SECRET|TOKEN|API[_-]?KEY");
        RequireStepContains(qemu, "start-vm", "did not publish its native -pidfile marker");
        RequireStepContains(qemu, "start-vm", "does not match newly started process");
        RequireStepContains(qemu, "start-vm", "the newly started process was stopped");
        SmokeAssert.True(
            !RequireStep(qemu, "start-vm").PowerShell.Contains("Set-Content -LiteralPath $pidPath", StringComparison.Ordinal),
            "QEMU launch must consume only the native -pidfile marker and must not overwrite it from the host runner.");
        RequireStepContains(qemu, "start-vm", "RedirectStandardError $qemuStderrPath");
        RequireStepContains(qemu, "start-vm", "qemu.stderr.log");
        RequireStepContains(qemu, "start-vm", "Get-Content -LiteralPath $diagnosticPath -Tail 20");
        RequireStepContains(qemu, "start-vm", "Provider output: $qemuDiagnosticText");
        SmokeAssert.True(!RequireStep(qemu, "start-vm").PowerShell.Contains("-display', 'none", StringComparison.Ordinal), "QEMU should open its display by default.");
        RequireStepContains(qemu, "remove-temp-vm", "Remove-Item");
        RequireStepContains(qemu, "remove-temp-vm", "pid marker was not cleared");
        RequireStepContains(qemu, "stop-vm", "cleanup refused to stop pid");
        RequireStepContains(qemu, "stop-vm", "native qemu.pid ownership marker is absent");
        RequireStepContains(qemu, "stop-vm", "no matching active process was found");
        RequireStepContains(qemu, "stop-vm", "cleanup preserved the job disk");
        RequireStepContains(qemu, "stop-vm", "ExecutablePath");
        RequireStepContains(qemu, "stop-vm", "executable/pidfile/runtime/VM/disk identity");
        RequireStepContains(qemu, "stop-vm", "$expectedVmName");
        RequireStepContains(qemu, "stop-vm", "ambiguous provider ownership");
        RequireStepContains(qemu, "stop-vm-before-restore", "executable/pidfile/runtime identity");
        RequireStepContains(qemu, "stop-vm-before-restore", "unowned process");
        RequireStepContains(qemu, "open-vm-desktop", "executable/pidfile/runtime/VM/disk identity");
        RequireAnyStepContains(qemu, "$guestRemotingAddress = '192.0.2.30'");
        RequireAnyStepContains(qemu, "New-PSSession -ComputerName $guestRemotingAddress");
        RequireAnyStepContains(qemu, "-Port 55985");
        SmokeAssert.True(qemu.Steps.All(step => !step.RequiresElevation), "QEMU runbooks should not require elevation unconditionally.");
        RequireProviderResourceFailure(
            qemuConfig,
            VirtualizationProvider.Qemu,
            baselineName: "Clean",
            machineDefinitionPath: qemuConfig.Qemu.DiskImagePath,
            qemuDiskFormat: "qcow2",
            expectedMessage: "does not accept an internal snapshot baseline override");

        var qemuScsi = builder.Build(qemuConfig with
        {
            Qemu = qemuConfig.Qemu with { DiskInterface = "scsi" }
        }, jobId, sample);
        RequireStepContains(qemuScsi, "start-vm", "if=none,format=qcow2,id=ksword-disk");
        RequireStepContains(qemuScsi, "start-vm", "virtio-scsi-pci,id=ksword-scsi");
        RequireStepContains(qemuScsi, "start-vm", "scsi-hd,drive=ksword-disk,bus=ksword-scsi.0");

        var qemuUserNat = builder.Build(qemuConfig with
        {
            Qemu = qemuConfig.Qemu with
            {
                AdditionalArguments = ["-accel", "whpx"],
                GuestRemoting = new GuestRemotingConfig
                {
                    AddressMode = GuestRemotingAddressMode.QemuUserNat,
                    UseSsl = true,
                    SkipCertificateChecks = true
                }
            }
        }, jobId, sample);
        RequireStepContains(qemuUserNat, "start-vm", "user,id=ksword-net,hostfwd=tcp:127.0.0.1:55986-:5986");
        RequireStepContains(qemuUserNat, "start-vm", "e1000,netdev=ksword-net");
        RequireStepContains(qemuUserNat, "start-vm", "TcpListener]::new([System.Net.IPAddress]::Loopback, 55986)");
        RequireStepContains(qemuUserNat, "start-vm", "No QEMU process was started");
        RequireStepContains(qemuUserNat, "start-vm", "configure another guestRemoting.port");
        RequireAnyStepContains(qemuUserNat, "$guestRemotingAddress = '127.0.0.1'");
        RequireAnyStepContains(qemuUserNat, "New-PSSession -ComputerName $guestRemotingAddress");
        RequireAnyStepContains(qemuUserNat, "-Port 55986");
        RequireAnyStepContains(qemuUserNat, "New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck");
        RequireAnyStepContains(qemuUserNat, "-UseSSL");

        var qemuSnapshot = builder.Build(qemuConfig with
        {
            Qemu = qemuConfig.Qemu with { UseOverlayDisk = false, SnapshotName = "Clean" }
        }, jobId, sample);
        SmokeAssert.True(!qemuSnapshot.UsesTemporaryVm, "QEMU internal snapshot mode should use the configured VM identity.");
        SmokeAssert.True(qemuSnapshot.BaselineName == "Clean", "QEMU internal snapshot mode should expose its effective snapshot baseline.");
        SmokeAssert.True(
            RequireStep(qemuSnapshot, "remove-temp-vm").Title == "Remove QEMU job process metadata",
            "QEMU internal snapshot cleanup should not claim to remove a per-job disk.");
        RequireStepContains(qemuSnapshot, "restore-vm-snapshot", "snapshot -a $snapshotName");
        RequireStepContains(qemuSnapshot, "check-qemu", "Configured QEMU disk format");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { UseOverlayDisk = false, DiskFormat = "raw", SnapshotName = "Clean" } },
            jobId,
            sample,
            "internal snapshot mode requires qemu.diskFormat=qcow2");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-accel", "tcg"] } },
            jobId,
            sample,
            "TCG software emulation is not treated as provider parity");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-M", "q35,accel=tcg"] } },
            jobId,
            sample,
            "TCG software emulation is not treated as provider parity");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-daemonize"] } },
            jobId,
            sample,
            "bypasses provider lifecycle");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-display", "none"] } },
            jobId,
            sample,
            "display mode are managed");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-drive", "file=other.qcow2,id=ksword-disk"] } },
            jobId,
            sample,
            "second drive with id=ksword-disk");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-device", "virtio-scsi-pci,id=ksword-scsi"] } },
            jobId,
            sample,
            "managed SCSI topology is reserved");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-M"] } },
            jobId,
            sample,
            "requires a machine value");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { AdditionalArguments = ["-drive"] } },
            jobId,
            sample,
            "requires a non-empty drive value");
        RequireBuildFailure(
            builder,
            qemuConfig with
            {
                Qemu = qemuConfig.Qemu with
                {
                    AdditionalArguments = ["-netdev", "user,id=ksword-net"],
                    GuestRemoting = new GuestRemotingConfig
                    {
                        AddressMode = GuestRemotingAddressMode.QemuUserNat,
                        UseSsl = true
                    }
                }
            },
            jobId,
            sample,
            "cannot reuse id/netdev=ksword-net");
        RequireBuildFailure(
            builder,
            qemuConfig with
            {
                Qemu = qemuConfig.Qemu with
                {
                    GuestRemoting = new GuestRemotingConfig
                    {
                        AddressMode = GuestRemotingAddressMode.QemuUserNat,
                        UseSsl = false
                    }
                }
            },
            jobId,
            sample,
            "requires guestRemoting.useSsl=true");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { MemoryMegabytes = 128 } },
            jobId,
            sample,
            "between 256 and 1048576");
        RequireBuildFailure(
            builder,
            qemuConfig with { Qemu = qemuConfig.Qemu with { DiskInterface = "none" } },
            jobId,
            sample,
            "managed disk would not be attached to a boot device");
        RequireBuildFailure(
            builder,
            qemuConfig with
            {
                Qemu = qemuConfig.Qemu with
                {
                    GuestRemoting = qemuConfig.Qemu.GuestRemoting with { Authentication = "Basic", UseSsl = false }
                }
            },
            jobId,
            sample,
            "Basic WinRM over HTTP is refused");
        RequireBuildFailure(
            builder,
            qemuConfig with
            {
                Qemu = qemuConfig.Qemu with
                {
                    GuestRemoting = qemuConfig.Qemu.GuestRemoting with { SkipCertificateChecks = true, UseSsl = false }
                }
            },
            jobId,
            sample,
            "skipCertificateChecks is valid only");

        var qemuCommaPath = builder.Build(qemuConfig with
        {
            Qemu = qemuConfig.Qemu with
            {
                UseOverlayDisk = false,
                SnapshotName = "Clean",
                DiskImagePath = @"D:\VMs\KSword,Lab\base,image.qcow2"
            }
        }, jobId, sample);
        RequireStepContains(qemuCommaPath, "start-vm", "KSword,,Lab\\base,,image.qcow2");
        RequireStepContains(qemuCommaPath, "open-vm-desktop", "Replace(',', ',,')");

        RequireBuildFailure(
            builder,
            vmwareConfig with { VMware = vmwareConfig.VMware with { VmType = "player" } },
            jobId,
            sample,
            "VMware parity requires Workstation Pro");

        var vmwareHeadless = builder.Build(vmwareConfig with { VMware = vmwareConfig.VMware with { Headless = true } }, jobId, sample);
        RequireStepContains(vmwareHeadless, "start-vm", "start $vmxPath nogui");
        SmokeAssert.True(vmwareHeadless.Steps.All(step => !step.Id.Equals("open-vm-desktop", StringComparison.OrdinalIgnoreCase)), "Headless VMware should not require a console window step.");
        var qemuHeadless = builder.Build(qemuConfig with { Qemu = qemuConfig.Qemu with { Headless = true } }, jobId, sample);
        RequireStepContains(qemuHeadless, "start-vm", "'-display', 'none'");
        SmokeAssert.True(qemuHeadless.Steps.All(step => !step.Id.Equals("open-vm-desktop", StringComparison.OrdinalIgnoreCase)), "Headless QEMU should not require a display window step.");

        foreach (var runbook in new[] { hyperV, vmware, qemu })
        {
            foreach (var commonStep in new[]
                     {
                         "check-guest-credential", "stage-guest-payload", "copy-sample", "prepare-guest-output",
                         "run-agent", "sync-live-output", "collect-output", "stop-vm"
                     })
            {
                RequireStep(runbook, commonStep);
            }

            RequireStepContains(runbook, "run-agent", "New-ScheduledTaskPrincipal");
            RequireStepContains(runbook, "run-agent", "-LogonType Interactive");
            RequireStep(runbook, "open-vm-desktop");
            RequireStepContains(runbook, "check-guest-credential", "SetEnvironmentVariable('KSWORDBOX_GUEST_PASSWORD', $null, 'Process')");
            var readinessStepId = runbook.Provider is VirtualizationProvider.HyperV
                ? "wait-powershell-direct"
                : "wait-guest-remoting";
            RequireStepContains(runbook, readinessStepId, "$timeoutSeconds = 321");
        }

        VerifyAutomaticGuestRemotingMigration(context);

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Hyper-V, VMware, and QEMU produce provider-specific full runbooks."
        });
    }

    private static void VerifyAutomaticGuestRemotingMigration(SmokeTestContext context)
    {
        var configRoot = Path.Combine(context.RuntimeRoot, "virtualization-provider-config-migration");
        Directory.CreateDirectory(configRoot);
        var missingSecurityFieldsPath = Path.Combine(configRoot, "automatic-missing-security-fields.json");
        File.WriteAllText(
            missingSecurityFieldsPath,
            """
            {
              "vmware": { "guestRemoting": { "addressMode": "VMwareTools" } },
              "qemu": { "guestRemoting": { "addressMode": "QemuUserNat" } }
            }
            """);
        var migrated = SandboxConfigLoader.Load(missingSecurityFieldsPath, context.RepositoryRoot);
        SmokeAssert.True(migrated.VMware.GuestRemoting.UseSsl, "VMwareTools profiles without a historical useSsl field should migrate to HTTPS.");
        SmokeAssert.True(migrated.VMware.GuestRemoting.SkipCertificateChecks, "Migrated VMwareTools profiles should support a self-signed guest listener.");
        SmokeAssert.True(migrated.Qemu.GuestRemoting.UseSsl, "QemuUserNat profiles without a historical useSsl field should migrate to HTTPS.");
        SmokeAssert.True(migrated.Qemu.GuestRemoting.SkipCertificateChecks, "Migrated QemuUserNat profiles should support a self-signed guest listener.");

        var explicitHttpPath = Path.Combine(configRoot, "automatic-explicit-http.json");
        File.WriteAllText(
            explicitHttpPath,
            """
            {
              "vmware": { "guestRemoting": { "addressMode": "VMwareTools", "useSsl": false } },
              "qemu": { "guestRemoting": { "addressMode": "QemuUserNat", "useSsl": false } }
            }
            """);
        var explicitHttp = SandboxConfigLoader.Load(explicitHttpPath, context.RepositoryRoot);
        SmokeAssert.True(!explicitHttp.VMware.GuestRemoting.UseSsl, "An explicit VMwareTools HTTP value should remain visible for readiness rejection.");
        SmokeAssert.True(!explicitHttp.VMware.GuestRemoting.SkipCertificateChecks, "Explicit VMwareTools HTTP should not imply certificate skipping.");
        SmokeAssert.True(!explicitHttp.Qemu.GuestRemoting.UseSsl, "An explicit QemuUserNat HTTP value should remain visible for readiness rejection.");
        SmokeAssert.True(!explicitHttp.Qemu.GuestRemoting.SkipCertificateChecks, "Explicit QemuUserNat HTTP should not imply certificate skipping.");
    }

    private static void RequireProviderResourceFailure(
        SandboxConfig config,
        VirtualizationProvider provider,
        string? baselineName,
        string? machineDefinitionPath,
        string? qemuDiskFormat,
        string expectedMessage)
    {
        try
        {
            VirtualizationProviderResourceValidator.Validate(
                config,
                provider,
                baselineName,
                machineDefinitionPath,
                qemuDiskFormat);
            throw new InvalidOperationException($"Expected {provider} resource validation to fail.");
        }
        catch (ArgumentException ex)
        {
            SmokeAssert.True(
                ex.Message.Contains(expectedMessage, StringComparison.OrdinalIgnoreCase),
                $"Expected {provider} resource validation failure to contain '{expectedMessage}', got '{ex.Message}'.");
        }
    }

    private static SandboxConfig CreateBaseConfig()
    {
        return new SandboxConfig
        {
            HyperV = new HyperVConfig
            {
                GoldenVmName = "KSword-HyperV",
                GoldenSnapshotName = "Clean"
            },
            Guest = new GuestConfig
            {
                UserName = "SandboxUser",
                PasswordSecretName = "KSWORDBOX_GUEST_PASSWORD",
                WorkingDirectory = @"C:\KSwordSandbox"
            },
            Paths = new SandboxPaths
            {
                RuntimeRoot = @"D:\Temp\KSwordSandbox",
                GuestPayloadRoot = @"D:\Temp\KSwordSandbox\payload\guest-tools"
            },
            Driver = new DriverConfig { Enabled = false },
            Analysis = new AnalysisConfig { DefaultDurationSeconds = 30, GuestReadyTimeoutSeconds = 321 }
        };
    }

    private static GuestConfig CreateRemoteGuestConfig(string address)
    {
        return new GuestConfig
        {
            UserName = "SandboxUser",
            PasswordSecretName = "KSWORDBOX_GUEST_PASSWORD",
            WorkingDirectory = @"C:\KSwordSandbox",
            PowerShellRemotingAddress = address,
            PowerShellRemotingAuthentication = "Negotiate"
        };
    }

    private static SampleIdentity CreateSample()
    {
        return new SampleIdentity
        {
            FileName = "sample.exe",
            FullPath = @"D:\Samples\sample.exe",
            Sha256 = new string('a', 64),
            Sha1 = new string('b', 40),
            Md5 = new string('c', 32),
            Crc32 = "00000000",
            SizeBytes = 1
        };
    }

    private static void RequireStepContains(SandboxRunbook runbook, string stepId, string expected)
    {
        var step = RequireStep(runbook, stepId);
        SmokeAssert.True(step.PowerShell.Contains(expected, StringComparison.Ordinal), $"Step '{stepId}' should contain '{expected}'.");
    }

    private static SandboxRunbookStep RequireStep(SandboxRunbook runbook, string stepId)
    {
        var step = runbook.Steps.FirstOrDefault(candidate => candidate.Id.Equals(stepId, StringComparison.OrdinalIgnoreCase));
        SmokeAssert.True(step is not null, $"{runbook.Provider} runbook is missing step '{stepId}'.");
        return step!;
    }

    private static void RequireAnyStepContains(SandboxRunbook runbook, string expected)
    {
        SmokeAssert.True(
            runbook.Steps.Any(step => step.PowerShell.Contains(expected, StringComparison.Ordinal)),
            $"{runbook.Provider} runbook should contain '{expected}'.");
    }

    private static void RequireBuildFailure(
        HyperVRunbookBuilder builder,
        SandboxConfig config,
        Guid jobId,
        SampleIdentity sample,
        string expected)
    {
        try
        {
            _ = builder.Build(config, jobId, sample);
        }
        catch (InvalidOperationException ex)
        {
            SmokeAssert.True(ex.Message.Contains(expected, StringComparison.OrdinalIgnoreCase), $"Expected failure containing '{expected}'.");
            return;
        }

        throw new InvalidOperationException($"Expected runbook construction to fail with '{expected}'.");
    }
}
