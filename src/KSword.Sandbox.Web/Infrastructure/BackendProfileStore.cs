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
    private readonly object gate = new();

    public BackendProfileStore(string configPath)
    {
        this.configPath = Path.GetFullPath(configPath);
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

        var updated = current with
        {
            Virtualization = current.Virtualization with { Provider = request.Provider },
            VMware = current.VMware with
            {
                VmName = request.VmName.Trim(),
                VmxPath = request.VmxPath.Trim(),
                SnapshotName = request.SnapshotName.Trim(),
                VmrunPath = request.VmrunPath.Trim(),
                GuestRemoting = current.VMware.GuestRemoting with
                {
                    AddressMode = request.AddressMode,
                    Address = string.IsNullOrWhiteSpace(request.Address) ? null : request.Address.Trim(),
                    Authentication = request.Authentication.Trim(),
                    Port = request.Port,
                    UseSsl = request.UseSsl,
                    SkipCertificateChecks = request.SkipCertificateChecks
                }
            },
            Guest = current.Guest with
            {
                PowerShellRemotingAddress = string.IsNullOrWhiteSpace(request.Address) ? null : request.Address.Trim(),
                PowerShellRemotingAuthentication = request.Authentication.Trim(),
                PowerShellRemotingUseSsl = request.UseSsl,
                PowerShellRemotingPort = request.Port,
                PowerShellRemotingSkipCertificateChecks = request.SkipCertificateChecks
            }
        };

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

    private static void Validate(BackendProfileUpdateRequest request)
    {
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

        if (request.AddressMode == GuestRemotingAddressMode.Configured && string.IsNullOrWhiteSpace(request.Address))
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
