using System.Text.Json;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Core.Configuration;

/// <summary>
/// Loads sandbox configuration from JSON while keeping safe defaults.
/// Inputs are an optional config path and repository root, processing resolves
/// relative paths and deserializes JSON, and the methods return a typed
/// SandboxConfig instance.
/// </summary>
public static class SandboxConfigLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    /// <summary>
    /// Loads configuration from disk or returns defaults when the file is absent.
    /// The input path may be null, relative, or absolute; processing expands it
    /// against the supplied repository root; the method returns a typed config.
    /// </summary>
    public static SandboxConfig Load(string? path, string repositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return Normalize(new SandboxConfig(), repositoryRoot);
        }

        var fullPath = Path.IsPathRooted(path)
            ? path
            : Path.GetFullPath(Path.Combine(repositoryRoot, path));

        if (!File.Exists(fullPath))
        {
            return Normalize(new SandboxConfig(), repositoryRoot);
        }

        var json = File.ReadAllText(fullPath);
        var config = JsonSerializer.Deserialize<SandboxConfig>(json, JsonOptions) ?? new SandboxConfig();
        using var document = JsonDocument.Parse(json);
        config = ApplyLegacyGuestRemotingFallback(config, document.RootElement);
        config = ApplyAutomaticGuestRemotingSecurityDefaults(config, document.RootElement);
        return Normalize(config, repositoryRoot);
    }

    private static SandboxConfig ApplyAutomaticGuestRemotingSecurityDefaults(SandboxConfig config, JsonElement root)
    {
        var vmwareRemoting = config.VMware.GuestRemoting;
        var vmware = vmwareRemoting is not null && vmwareRemoting.AddressMode is GuestRemotingAddressMode.VMwareTools
            ? config.VMware with
            {
                GuestRemoting = vmwareRemoting with
                {
                    UseSsl = HasGuestRemotingProperty(root, "vmware", "useSsl") ? vmwareRemoting.UseSsl : true,
                    SkipCertificateChecks = HasGuestRemotingProperty(root, "vmware", "skipCertificateChecks")
                        ? vmwareRemoting.SkipCertificateChecks
                        : HasGuestRemotingProperty(root, "vmware", "useSsl") ? vmwareRemoting.UseSsl : true
                }
            }
            : config.VMware;
        var qemuRemoting = config.Qemu.GuestRemoting;
        var qemu = qemuRemoting is not null && qemuRemoting.AddressMode is GuestRemotingAddressMode.QemuUserNat
            ? config.Qemu with
            {
                GuestRemoting = qemuRemoting with
                {
                    UseSsl = HasGuestRemotingProperty(root, "qemu", "useSsl") ? qemuRemoting.UseSsl : true,
                    SkipCertificateChecks = HasGuestRemotingProperty(root, "qemu", "skipCertificateChecks")
                        ? qemuRemoting.SkipCertificateChecks
                        : HasGuestRemotingProperty(root, "qemu", "useSsl") ? qemuRemoting.UseSsl : true
                }
            }
            : config.Qemu;
        return config with { VMware = vmware, Qemu = qemu };
    }

    private static SandboxConfig ApplyLegacyGuestRemotingFallback(SandboxConfig config, JsonElement root)
    {
        if (string.IsNullOrWhiteSpace(config.Guest.PowerShellRemotingAddress))
        {
            return config;
        }

        var legacyRemoting = new GuestRemotingConfig
        {
            AddressMode = GuestRemotingAddressMode.Configured,
            Address = config.Guest.PowerShellRemotingAddress,
            Authentication = config.Guest.PowerShellRemotingAuthentication,
            UseSsl = config.Guest.PowerShellRemotingUseSsl,
            Port = config.Guest.PowerShellRemotingPort,
            SkipCertificateChecks = config.Guest.PowerShellRemotingSkipCertificateChecks
        };
        var vmware = HasGuestRemotingObject(root, "vmware")
            ? config.VMware
            : config.VMware with { GuestRemoting = legacyRemoting };
        var qemu = HasGuestRemotingObject(root, "qemu")
            ? config.Qemu
            : config.Qemu with { GuestRemoting = legacyRemoting };
        return config with { VMware = vmware, Qemu = qemu };
    }

    private static bool HasGuestRemotingObject(JsonElement root, string sectionName)
    {
        return root.ValueKind is JsonValueKind.Object &&
               TryGetPropertyIgnoreCase(root, sectionName, out var section) &&
               section.ValueKind is JsonValueKind.Object &&
               TryGetPropertyIgnoreCase(section, "guestRemoting", out var remoting) &&
               remoting.ValueKind is JsonValueKind.Object;
    }

    private static bool HasGuestRemotingProperty(JsonElement root, string sectionName, string propertyName) =>
        root.ValueKind is JsonValueKind.Object &&
        TryGetPropertyIgnoreCase(root, sectionName, out var section) &&
        section.ValueKind is JsonValueKind.Object &&
        TryGetPropertyIgnoreCase(section, "guestRemoting", out var remoting) &&
        remoting.ValueKind is JsonValueKind.Object &&
        TryGetPropertyIgnoreCase(remoting, propertyName, out _);

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string name, out JsonElement value)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Expands local path settings to absolute host paths.
    /// Inputs are the deserialized config and repository root; processing fixes
    /// relative runtime and rules paths; the method returns a normalized config.
    /// </summary>
    private static SandboxConfig Normalize(SandboxConfig config, string repositoryRoot)
    {
        var paths = config.Paths with
        {
            RuntimeRoot = ResolvePortableRoot(config.Paths.RuntimeRoot, repositoryRoot),
            RulesDirectory = ExpandPath(config.Paths.RulesDirectory, repositoryRoot),
            GuestPayloadRoot = ResolvePortableRoot(config.Paths.GuestPayloadRoot, repositoryRoot)
        };

        // An empty guestPayloadRoot means "derive it from the runtime root"
        // rather than "use the repository root", which would put build output
        // inside the source tree.
        if (string.IsNullOrWhiteSpace(config.Paths.GuestPayloadRoot))
        {
            paths = paths with { GuestPayloadRoot = Path.Combine(paths.RuntimeRoot, "payload", "guest-tools") };
        }

        var configuredDriverPath = ExpandOptionalPath(config.Driver.HostDriverPath, repositoryRoot);
        var driver = config.Driver with
        {
            // A development checkout often already contains the native
            // driver output. Use it when no explicit path was configured so
            // real-R0 planning can reach guest preflight without a manual
            // path edit. If no build output exists, keep null and let the
            // existing readiness check fail closed with its remediation.
            HostDriverPath = configuredDriverPath ?? FindBuiltDriver(repositoryRoot)
        };

        var vmware = config.VMware with
        {
            VmName = (config.VMware.VmName ?? string.Empty).Trim(),
            VmxPath = ExpandOptionalPath(config.VMware.VmxPath, repositoryRoot) ?? string.Empty,
            SnapshotName = (config.VMware.SnapshotName ?? string.Empty).Trim(),
            VmrunPath = ExpandCommandPath(config.VMware.VmrunPath, repositoryRoot),
            VixHelperPath = ExpandOptionalPath(config.VMware.VixHelperPath, repositoryRoot)
                ?? FindBundledVixHelper(repositoryRoot) ?? string.Empty,
            VmType = (config.VMware.VmType ?? string.Empty).Trim().ToLowerInvariant(),
            GuestRemoting = NormalizeGuestRemoting(
                config.VMware.GuestRemoting ?? new GuestRemotingConfig
                {
                    AddressMode = GuestRemotingAddressMode.VMwareTools,
                    UseSsl = true,
                    SkipCertificateChecks = true
                })
        };

        var qemu = config.Qemu with
        {
            VmName = (config.Qemu.VmName ?? string.Empty).Trim(),
            DiskImagePath = ExpandOptionalPath(config.Qemu.DiskImagePath, repositoryRoot) ?? string.Empty,
            QemuSystemPath = ExpandCommandPath(config.Qemu.QemuSystemPath, repositoryRoot),
            QemuImgPath = ExpandCommandPath(config.Qemu.QemuImgPath, repositoryRoot),
            DiskFormat = (config.Qemu.DiskFormat ?? string.Empty).Trim().ToLowerInvariant(),
            DiskInterface = (config.Qemu.DiskInterface ?? string.Empty).Trim().ToLowerInvariant(),
            SnapshotName = (config.Qemu.SnapshotName ?? string.Empty).Trim(),
            AdditionalArguments = (config.Qemu.AdditionalArguments ?? [])
                .Select(argument => (argument ?? string.Empty).Trim())
                .ToList(),
            GuestRemoting = NormalizeGuestRemoting(
                config.Qemu.GuestRemoting ?? new GuestRemotingConfig
                {
                    AddressMode = GuestRemotingAddressMode.QemuUserNat,
                    UseSsl = true,
                    SkipCertificateChecks = true
                })
        };

        return config with { Paths = paths, Driver = driver, VMware = vmware, Qemu = qemu };
    }

    private static GuestRemotingConfig NormalizeGuestRemoting(GuestRemotingConfig remoting)
    {
        return remoting with
        {
            Address = string.IsNullOrWhiteSpace(remoting.Address) ? null : remoting.Address.Trim(),
            Authentication = (remoting.Authentication ?? string.Empty).Trim()
        };
    }

    /// <summary>
    /// Resolves a configured host root that may be left empty by an operator or
    /// by the shipped example config.
    ///
    /// The shipped sandbox.example.json intentionally leaves runtimeRoot empty:
    /// it used to hardcode the authoring machine's D:\Temp\KSwordSandbox, which
    /// silently pointed a fresh operator at a drive they do not have. Resolution
    /// order matches scripts/Common-PortablePaths.ps1 so the PowerShell installer
    /// and the host agree on one location:
    ///
    ///   1. an explicit configured path;
    ///   2. the historical D:\Temp\KSwordSandbox, only when D: is present;
    ///   3. %LOCALAPPDATA%\KSwordSandbox.
    ///
    /// An empty result is never returned: falling through to the repository root
    /// would place jobs, reports, and pcaps inside the source tree.
    /// </summary>
    private static string ResolvePortableRoot(string? configured, string repositoryRoot)
    {
        var trimmed = configured?.Trim() ?? string.Empty;
        if (trimmed.Length > 0)
        {
            return Path.IsPathRooted(trimmed)
                ? Path.GetFullPath(trimmed)
                : Path.GetFullPath(Path.Combine(repositoryRoot, trimmed));
        }

        const string HistoricalDefault = @"D:\Temp\KSwordSandbox";
        var historicalRoot = Path.GetPathRoot(HistoricalDefault);
        if (!string.IsNullOrWhiteSpace(historicalRoot) && Directory.Exists(historicalRoot))
        {
            return HistoricalDefault;
        }

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            localAppData = Path.GetTempPath();
        }

        return Path.Combine(localAppData, "KSwordSandbox");
    }

    /// <summary>
    /// Converts a relative path to an absolute path.
    /// The input is one configured path; processing leaves rooted paths intact;
    /// the method returns an absolute path string.
    /// </summary>
    private static string ExpandPath(string path, string repositoryRoot)
    {
        var normalizedPath = path.Trim();
        return Path.IsPathRooted(normalizedPath)
            ? Path.GetFullPath(normalizedPath)
            : Path.GetFullPath(Path.Combine(repositoryRoot, normalizedPath));
    }

    /// <summary>
    /// Converts an optional relative path to an absolute path.
    /// The input may be null or whitespace; processing returns null for absent
    /// values and expands present relative paths; the method returns the
    /// normalized optional path.
    /// </summary>
    private static string? ExpandOptionalPath(string? path, string repositoryRoot)
    {
        return string.IsNullOrWhiteSpace(path) ? null : ExpandPath(path, repositoryRoot);
    }

    /// <summary>
    /// Finds a driver produced by this checkout when no explicit host path was
    /// configured. Release output wins over debug output; null means there is
    /// no built driver to stage.
    /// </summary>
    private static string? FindBuiltDriver(string repositoryRoot)
    {
        var candidates = new[]
        {
            Path.Combine(repositoryRoot, "driver", "KSword.Sandbox.Driver", "x64", "Release", "KSword.Sandbox.Driver.sys"),
            Path.Combine(repositoryRoot, "driver", "KSword.Sandbox.Driver", "x64", "Debug", "KSword.Sandbox.Driver.sys")
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Resolves the VIX helper from supported portable package layouts. A
    /// missing helper stays missing so VMware Block fails before VM startup.
    /// </summary>
    private static string? FindBundledVixHelper(string repositoryRoot)
    {
        var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        var candidates = new[]
        {
            Path.Combine(baseDirectory, "vix_probe.exe"),
            Path.Combine(baseDirectory, "tools", "vix-helper", "vix_probe.exe"),
            Path.GetFullPath(Path.Combine(baseDirectory, "..", "tools", "vix-helper", "vix_probe.exe")),
            Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "tools", "vix-helper", "vix_probe.exe")),
            Path.GetFullPath(Path.Combine(baseDirectory, "..", "vix-helper", "vix_probe.exe")),
            Path.Combine(repositoryRoot, "tools", "vix-helper", "vix_probe.exe")
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Expands an explicitly configured executable path while preserving bare
    /// command names that should be resolved through PATH at runbook time.
    /// </summary>
    private static string ExpandCommandPath(string? path, string repositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var normalizedPath = path.Trim();
        if (!Path.IsPathRooted(normalizedPath) && !normalizedPath.Contains('/') && !normalizedPath.Contains('\\'))
        {
            return normalizedPath;
        }

        return ExpandPath(normalizedPath, repositoryRoot);
    }
}
