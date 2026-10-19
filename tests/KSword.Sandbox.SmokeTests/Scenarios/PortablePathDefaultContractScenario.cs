using System.Text.RegularExpressions;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Guards the distribution against machine-local path defaults.
///
/// Every operational PowerShell script used to default its runtime/payload/
/// publish/package roots to the authoring lab's D:\Temp\KSwordSandbox. On a
/// machine without a D: drive those scripts either failed during parameter
/// binding or silently probed a directory that does not exist, so a fresh
/// operator could not install from a freshly built package.
///
/// The fix routes resolution through scripts/Common-PortablePaths.ps1. This
/// scenario fails if any operational script reintroduces a drive-qualified
/// parameter default, or if the shared module stops being distributed.
/// </summary>
internal sealed class PortablePathDefaultContractScenario : ISmokeTestScenario
{
    public string ScenarioId => "packaging.portable-path-defaults.contract";

    /// <summary>
    /// Parameter declarations that must never carry a machine-local default.
    /// A script that needs a different fallback derives it explicitly through
    /// the shared module instead.
    /// </summary>
    private static readonly HashSet<string> PortableParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "RuntimeRoot",
        "GuestPayloadRoot",
        "OutputRoot",
        "PayloadRoot",
        "BuildRoot",
        "RuntimePublishRoot",
        "IntermediateRoot",
        "ConfigPath",
        "SummaryPath",
        "OutputPath",
        "SamplePath"
    };

    private static readonly string[] OperationalScriptRoots = ["install.ps1", "run.ps1"];

    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var repositoryRoot = ResolveRepositoryRoot(context);
        SmokeAssert.True(repositoryRoot is not null, "The scenario must run inside a KSwordSandbox checkout.");

        var scriptsRoot = Path.Combine(repositoryRoot!, "scripts");
        SmokeAssert.True(Directory.Exists(scriptsRoot), "The scripts/ directory must exist.");

        // The shared module is what makes the empty defaults resolvable; if it
        // is not shipped, every operational script silently degrades to "".
        var sharedModule = Path.Combine(scriptsRoot, "Common-PortablePaths.ps1");
        SmokeAssert.True(File.Exists(sharedModule),
            "scripts/Common-PortablePaths.ps1 must ship with the package or every portable default resolves to nothing.");
        var moduleText = File.ReadAllText(sharedModule);
        foreach (var resolver in new[]
                 {
                     "Get-PortableRuntimeRoot",
                     "Get-PortableGuestPayloadRoot",
                     "Get-PortableDerivedPath"
                 })
        {
            SmokeAssert.True(moduleText.Contains(resolver, StringComparison.Ordinal),
                $"The shared portable-path module must define {resolver}.");
        }

        var offenders = new List<string>();
        foreach (var scriptPath in EnumeratePowerShellScripts(repositoryRoot!))
        {
            var relative = Path.GetRelativePath(repositoryRoot!, scriptPath).Replace('\\', '/');
            var lines = File.ReadAllLines(scriptPath);
            for (var index = 0; index < lines.Length; index++)
            {
                var line = lines[index];
                if (line.TrimStart().StartsWith('#'))
                {
                    continue;
                }

                if (!LooksLikeParameterDeclaration(line, out var name))
                {
                    continue;
                }

                var defaultValue = ExtractDefaultValue(line);
                if (defaultValue is null || !IsDriveQualified(defaultValue))
                {
                    continue;
                }

                // Documentation examples and error-message remediation hints are
                // allowed to name the historical location: an operator reading
                // "改用 D:\Temp\KSwordSandbox" is being told where it works.
                if (!PortableParameters.Contains(name))
                {
                    continue;
                }

                offenders.Add($"{relative}:{index + 1} [string]${name} = '{defaultValue}'");
            }
        }

        SmokeAssert.True(offenders.Count == 0,
            "Operational scripts must not carry machine-local parameter defaults; " +
            $"resolve them through scripts/Common-PortablePaths.ps1 instead:{Environment.NewLine}" +
            string.Join(Environment.NewLine, offenders));

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Operational scripts resolve machine-local roots through the shared portable-path module."
        });
    }

    private static string? ResolveRepositoryRoot(SmokeTestContext context)
    {
        // The smoke runner may execute from bin/ under any project directory.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "KSwordSandbox.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        var fromContext = context.GetType().GetProperty("RepositoryRoot")?.GetValue(context) as string;
        return string.IsNullOrWhiteSpace(fromContext) ? null : fromContext;
    }

    private static IEnumerable<string> EnumeratePowerShellScripts(string repositoryRoot)
    {
        foreach (var name in OperationalScriptRoots)
        {
            var path = Path.Combine(repositoryRoot, name);
            if (File.Exists(path))
            {
                yield return path;
            }
        }

        var scriptsRoot = Path.Combine(repositoryRoot, "scripts");
        if (!Directory.Exists(scriptsRoot))
        {
            yield break;
        }

        foreach (var path in Directory.EnumerateFiles(scriptsRoot, "*.ps1", SearchOption.TopDirectoryOnly).Order())
        {
            yield return path;
        }
    }

    private static readonly Regex DeclarationPattern = new(
        @"^\s*(?:\[[^\]]*\]\s*)*\[\w+\]\s*\$(?<name>\w+)\s*=\s*(?<value>.+?)\s*,?\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static bool LooksLikeParameterDeclaration(string line, out string name)
    {
        var match = DeclarationPattern.Match(line);
        name = match.Success ? match.Groups["name"].Value : string.Empty;
        return match.Success;
    }

    private static string? ExtractDefaultValue(string line)
    {
        var match = DeclarationPattern.Match(line);
        if (!match.Success)
        {
            return null;
        }

        var value = match.Groups["value"].Value.Trim().TrimEnd(',').Trim();
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'')
        {
            return value[1..^1];
        }

        return null;
    }

    /// <summary>
    /// Matches a literal rooted Windows path such as D:\Temp\KSwordSandbox.
    /// Relative defaults and non-string defaults are intentionally excluded.
    /// </summary>
    private static bool IsDriveQualified(string value) =>
        value.Length >= 3 &&
        char.IsLetter(value[0]) &&
        value[1] == ':' &&
        (value[2] == '\\' || value[2] == '/');
}