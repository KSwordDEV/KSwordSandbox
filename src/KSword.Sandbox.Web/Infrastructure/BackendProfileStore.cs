using System.Text.Json;
using System.Text.Json.Serialization;
using KSword.Sandbox.Abstractions;
using KSword.Sandbox.Web.Contracts;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Persists the small provider profile used by the local first-run page.
/// This deliberately writes outside the repository template and never accepts
/// or stores a guest password.
/// </summary>
internal sealed class BackendProfileStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string configPath;
    private readonly string packageRoot;
    private readonly object gate = new();

    public BackendProfileStore(string configPath, string packageRoot)
    {
        this.configPath = Path.GetFullPath(configPath);
        this.packageRoot = Path.GetFullPath(packageRoot);
    }

    public string ConfigPath => configPath;

    public BackendProfileResponse Read(SandboxConfig current)
    {
        ArgumentNullException.ThrowIfNull(current);
        return new BackendProfileResponse(configPath, File.Exists(configPath), current, RestartRequired: false);
    }

    public BackendProfileResponse Save(SandboxConfig current, BackendProfileUpdateRequest request)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(request);
        Validate(request);

        var updated = BuildUpdatedConfig(current, request);

        var directory = Path.GetDirectoryName(configPath);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidOperationException("The local config path has no parent directory.");
        }

        lock (gate)
        {
            Directory.CreateDirectory(directory);
            var temporaryPath = configPath + ".tmp";
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(updated, JsonOptions));
            if (File.Exists(configPath))
            {
                File.Replace(temporaryPath, configPath, null);
            }
            else
            {
                File.Move(temporaryPath, configPath);
            }
        }

        return new BackendProfileResponse(configPath, true, updated, RestartRequired: true);
    }

    public SandboxConfig BuildUpdatedConfig(SandboxConfig current, BackendProfileUpdateRequest request)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(request);
        Validate(request);

        var runtimeRoot = current.Paths.RuntimeRoot;
        var runtimeDrive = Path.GetPathRoot(runtimeRoot);
        if (string.IsNullOrWhiteSpace(runtimeDrive) || !Directory.Exists(runtimeDrive))
        {
            runtimeRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KSwordSandbox");
        }

        var payloadRoot = string.Equals(runtimeRoot, current.Paths.RuntimeRoot, StringComparison.OrdinalIgnoreCase)
            ? current.Paths.GuestPayloadRoot
            : ResolvePayloadRoot(runtimeRoot, current.Paths.GuestPayloadRoot);

        var remoting = new GuestRemotingConfig
        {
            AddressMode = request.AddressMode,
            Address = string.IsNullOrWhiteSpace(request.Address) ? null : request.Address.Trim(),
            Authentication = request.Authentication.Trim(),
            Port = request.Port,
            UseSsl = request.UseSsl,
            SkipCertificateChecks = request.SkipCertificateChecks
        };
        var updated = current with
        {
            Virtualization = current.Virtualization with { Provider = request.Provider },
            HyperV = request.Provider == VirtualizationProvider.HyperV ? current.HyperV with
            {
                GoldenVmName = request.VmName.Trim(),
                GoldenSnapshotName = request.SnapshotName.Trim(),
                UseDifferencingDisk = false,
                OpenVmConsoleOnLiveStart = !request.Headless
            } : current.HyperV,
            VMware = request.Provider == VirtualizationProvider.VMware ? current.VMware with
            {
                VmName = request.VmName.Trim(),
                VmxPath = request.VmxPath.Trim(),
                SnapshotName = request.SnapshotName.Trim(),
                VmrunPath = request.VmrunPath.Trim(),
                VmType = "ws",
                Headless = request.Headless,
                GuestRemoting = remoting
            } : current.VMware,
            Qemu = request.Provider == VirtualizationProvider.Qemu ? current.Qemu with
            {
                VmName = request.VmName.Trim(),
                SnapshotName = request.SnapshotName.Trim(),
                QemuSystemPath = request.QemuSystemPath.Trim(),
                QemuImgPath = request.QemuImgPath.Trim(),
                DiskImagePath = request.DiskImagePath.Trim(),
                DiskFormat = request.DiskFormat.Trim().ToLowerInvariant(),
                DiskInterface = request.DiskInterface.Trim().ToLowerInvariant(),
                UseOverlayDisk = request.UseOverlayDisk,
                MemoryMegabytes = request.MemoryMegabytes,
                AdditionalArguments = request.AdditionalArguments,
                Headless = request.Headless,
                GuestRemoting = remoting
            } : current.Qemu,
            Guest = current.Guest with
            {
                UserName = request.GuestUserName.Trim(),
                WorkingDirectory = request.GuestWorkingDirectory.Trim(),
                EnablePowerShellDirect = request.Provider == VirtualizationProvider.HyperV,
                PowerShellRemotingAddress = string.IsNullOrWhiteSpace(request.Address) ? null : request.Address.Trim(),
                PowerShellRemotingAuthentication = request.Authentication.Trim(),
                PowerShellRemotingUseSsl = request.UseSsl,
                PowerShellRemotingPort = request.Port,
                PowerShellRemotingSkipCertificateChecks = request.SkipCertificateChecks
            },
            Driver = current.Driver with
            {
                Enabled = request.DriverEnabled,
                UseMockCollector = request.UseMockCollector,
                // Keep an existing operator-local driver path when an older API
                // client omits the optional field; the setup page can still
                // replace it by submitting a new path.
                HostDriverPath = string.IsNullOrWhiteSpace(request.HostDriverPath)
                    ? current.Driver.HostDriverPath
                    : request.HostDriverPath.Trim()
            },
            Paths = current.Paths with
            {
                RuntimeRoot = runtimeRoot,
                GuestPayloadRoot = payloadRoot
            }
        };
        return updated;
    }

    private string ResolvePayloadRoot(string runtimeRoot, string currentPayloadRoot)
    {
        if (!string.IsNullOrWhiteSpace(currentPayloadRoot) && File.Exists(Path.Combine(currentPayloadRoot, "payload-manifest.json")))
        {
            return currentPayloadRoot;
        }

        var packagedPayloadRoot = Path.Combine(packageRoot, "payload", "guest-tools");
        if (File.Exists(Path.Combine(packagedPayloadRoot, "payload-manifest.json")))
        {
            return packagedPayloadRoot;
        }

        return Path.Combine(runtimeRoot, "payload", "guest-tools");
    }

    private static void Validate(BackendProfileUpdateRequest request)
    {
        if (!Enum.IsDefined(request.Provider)) throw new ArgumentException("Unknown backend / 未知后端。");
        if (string.IsNullOrWhiteSpace(request.VmName)) throw new ArgumentException("VM name is required / 请填写虚拟机名称。");
        if ((request.Provider != VirtualizationProvider.Qemu || !request.UseOverlayDisk) && string.IsNullOrWhiteSpace(request.SnapshotName))
            throw new ArgumentException("Clean baseline name is required / 请填写干净基线名称。");
        if (string.IsNullOrWhiteSpace(request.GuestUserName)) throw new ArgumentException("Guest username is required / 请填写来宾用户名。");
        if (!Path.IsPathFullyQualified(request.GuestWorkingDirectory) || request.GuestWorkingDirectory.TrimEnd('\\').Length <= 3)
            throw new ArgumentException("Use an absolute guest working folder such as C:\\KSwordSandbox / 请填写完整的来宾工作目录。");
        if (request.Provider == VirtualizationProvider.Qemu)
        {
            if (string.IsNullOrWhiteSpace(request.QemuSystemPath) || string.IsNullOrWhiteSpace(request.QemuImgPath) || string.IsNullOrWhiteSpace(request.DiskImagePath))
                throw new ArgumentException("QEMU tools and base disk are required / 请填写 QEMU 工具和基础磁盘路径。");
            if (request.MemoryMegabytes < 1024 || request.MemoryMegabytes > 65536) throw new ArgumentException("QEMU memory must be 1024–65536 MB.");
            if (request.AdditionalArguments is null) throw new ArgumentException("QEMU arguments must be a JSON string array.");
            if (request.AddressMode is not (GuestRemotingAddressMode.Configured or GuestRemotingAddressMode.QemuUserNat))
                throw new ArgumentException("QEMU supports Configured or QemuUserNat address mode.");
        }
        if (request.Provider == VirtualizationProvider.VMware)
        {
            if (string.IsNullOrWhiteSpace(request.VmName))
            {
                throw new ArgumentException("VMware VM name is required.", nameof(request));
            }

            if (string.IsNullOrWhiteSpace(request.VmxPath))
            {
                throw new ArgumentException("VMware VMX path is required.", nameof(request));
            }

            if (string.IsNullOrWhiteSpace(request.SnapshotName))
            {
                throw new ArgumentException("VMware snapshot name is required.", nameof(request));
            }

            if (!request.VmxPath.EndsWith(".vmx", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("VMware machine definition must be a .vmx file.", nameof(request));
            }

            if (request.AddressMode is not (GuestRemotingAddressMode.Configured or GuestRemotingAddressMode.VMwareTools))
            {
                throw new ArgumentException("VMware supports Configured or VMwareTools guest address mode.", nameof(request));
            }
        }

        if (request.Provider != VirtualizationProvider.HyperV && request.AddressMode == GuestRemotingAddressMode.Configured && string.IsNullOrWhiteSpace(request.Address))
        {
            throw new ArgumentException("Configured guest address mode requires an address.", nameof(request));
        }

        if (request.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(request.Port), "Guest remoting port must be between 1 and 65535.");
        }

        if (string.IsNullOrWhiteSpace(request.Authentication))
        {
            throw new ArgumentException("Guest remoting authentication is required.", nameof(request));
        }

        if (request.SkipCertificateChecks && !request.UseSsl)
        {
            throw new ArgumentException("Certificate checks can only be skipped when WinRM HTTPS is enabled.", nameof(request));
        }
    }
}
