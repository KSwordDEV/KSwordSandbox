using System.Text;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Stores the optional local VirusTotal API key outside the repository.
/// Inputs are the configured runtime root and settings page updates;
/// processing reads an environment variable first, then a runtime settings
/// file; returned settings always mask the key.
/// </summary>
internal sealed class VirusTotalSettingsStore
{
    internal const string EnvironmentVariableName = "KSWORDBOX_VIRUSTOTAL_API_KEY";

    private readonly string settingsPath;

    public VirusTotalSettingsStore(SandboxConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        settingsPath = Path.Combine(config.Paths.RuntimeRoot, "settings", "virustotal.key");
    }

    /// <summary>
    /// Returns masked settings state. Inputs are none; processing checks
    /// environment then file storage; the returned state never contains the key.
    /// </summary>
    public VirusTotalSettingsState GetState()
    {
        var key = ResolveApiKey(out var source);
        return new VirusTotalSettingsState(
            Configured: !string.IsNullOrWhiteSpace(key),
            ApiKeyMask: MaskApiKey(key),
            Source: source,
            SettingsPath: settingsPath);
    }

    /// <summary>
    /// Resolves the API key for outbound lookup. Inputs are none; processing
    /// prefers the process/user/machine environment and falls back to local
    /// runtime settings; the raw key is returned only to the caller service.
    /// </summary>
    public string? ResolveApiKey() => ResolveApiKey(out _);

    /// <summary>
    /// Updates local file-backed settings. Inputs are a possibly-empty key and
    /// clear flag; processing writes outside git or deletes the file; the
    /// returned state is masked.
    /// </summary>
    public VirusTotalSettingsState Save(string? apiKey, bool clear)
    {
        if (clear || string.IsNullOrWhiteSpace(apiKey))
        {
            TryDeleteSettingsFile();
            return GetState();
        }

        Directory.CreateDirectory(Path.GetDirectoryName(settingsPath) ?? ".");
        File.WriteAllText(settingsPath, Convert.ToBase64String(Encoding.UTF8.GetBytes(apiKey.Trim())));
        TryRestrictSettingsFileAcl(settingsPath);
        return GetState();
    }

    private string? ResolveApiKey(out string source)
    {
        var scopes = new[]
        {
            EnvironmentVariableTarget.Process,
            EnvironmentVariableTarget.User,
            EnvironmentVariableTarget.Machine
        };

        foreach (var scope in scopes)
        {
            var candidate = Environment.GetEnvironmentVariable(EnvironmentVariableName, scope);
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                source = $"environment:{scope}";
                return candidate.Trim();
            }
        }

        try
        {
            if (File.Exists(settingsPath))
            {
                var encoded = File.ReadAllText(settingsPath).Trim();
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                if (!string.IsNullOrWhiteSpace(decoded))
                {
                    source = "runtime-settings";
                    return decoded.Trim();
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or ArgumentException)
        {
            // Settings failures are intentionally silent for unattended runs.
        }

        source = "not-configured";
        return null;
    }

    private void TryDeleteSettingsFile()
    {
        try
        {
            if (File.Exists(settingsPath))
            {
                File.Delete(settingsPath);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Keep settings update silent; the settings page will show the
            // resulting masked state after the best-effort operation.
        }
    }

    private static string? MaskApiKey(string? apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return null;
        }

        var trimmed = apiKey.Trim();
        return trimmed.Length <= 8
            ? "********"
            : $"{trimmed[..4]}...{trimmed[^4..]}";
    }

    private static void TryRestrictSettingsFileAcl(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // ACL/attribute hardening is best-effort only.
        }
    }
}
