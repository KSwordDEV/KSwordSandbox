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
        return Normalize(config, repositoryRoot);
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
            RuntimeRoot = ExpandPath(config.Paths.RuntimeRoot, repositoryRoot),
            RulesDirectory = ExpandPath(config.Paths.RulesDirectory, repositoryRoot)
        };

        return config with { Paths = paths };
    }

    /// <summary>
    /// Converts a relative path to an absolute path.
    /// The input is one configured path; processing leaves rooted paths intact;
    /// the method returns an absolute path string.
    /// </summary>
    private static string ExpandPath(string path, string repositoryRoot)
    {
        return Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(repositoryRoot, path));
    }
}
