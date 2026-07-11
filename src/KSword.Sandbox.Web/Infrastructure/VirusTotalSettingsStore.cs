using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Infrastructure;

/// <summary>
/// Resolves the optional VirusTotal API key without persisting it to disk.
/// Inputs are the configured runtime root and settings page updates;
/// processing reads environment variables and lets the settings endpoint update
/// only the current process environment; returned settings always mask the key.
/// </summary>
internal sealed class VirusTotalSettingsStore
{
    internal const string EnvironmentVariableName = "KSWORDBOX_VIRUSTOTAL_API_KEY";
    private const string NotConfiguredSource = "未配置 / not-configured";

    public VirusTotalSettingsStore(SandboxConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
    }

    /// <summary>
    /// Returns masked settings state. Inputs are none; processing checks only
    /// process/user/machine environment variables; the returned state never
    /// contains the key and never points at a key file.
    /// </summary>
    public VirusTotalSettingsState GetState()
    {
        var key = ResolveApiKey(out var source);
        return new VirusTotalSettingsState(
            Configured: !string.IsNullOrWhiteSpace(key),
            ApiKeyMask: MaskApiKey(key),
            Source: source,
            SettingsPath: null);
    }

    /// <summary>
    /// Resolves the API key for outbound lookup. Inputs are none; processing
    /// prefers the process/user/machine environment; the raw key is returned
    /// only to the caller service and is never written to local files.
    /// </summary>
    public string? ResolveApiKey() => ResolveApiKey(out _);

    /// <summary>
    /// Updates process-local settings. Inputs are a possibly-empty key and
    /// clear flag; processing writes only the current process environment; the
    /// returned state is masked.
    /// </summary>
    public VirusTotalSettingsState Save(string? apiKey, bool clear)
    {
        if (clear || string.IsNullOrWhiteSpace(apiKey))
        {
            Environment.SetEnvironmentVariable(EnvironmentVariableName, null, EnvironmentVariableTarget.Process);
            return GetState();
        }

        Environment.SetEnvironmentVariable(EnvironmentVariableName, apiKey.Trim(), EnvironmentVariableTarget.Process);
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
                source = DescribeEnvironmentSource(scope);
                return candidate.Trim();
            }
        }

        source = NotConfiguredSource;
        return null;
    }

    private static string DescribeEnvironmentSource(EnvironmentVariableTarget scope)
    {
        return scope switch
        {
            EnvironmentVariableTarget.Process =>
                $"当前 Web Host 进程环境变量 {EnvironmentVariableName} / current process environment",
            EnvironmentVariableTarget.User =>
                $"当前 Windows 用户环境变量 {EnvironmentVariableName} / current user environment",
            EnvironmentVariableTarget.Machine =>
                $"本机系统环境变量 {EnvironmentVariableName} / local machine environment",
            _ => $"环境变量 {EnvironmentVariableName} / environment"
        };
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

}
