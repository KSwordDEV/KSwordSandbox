using System.Diagnostics;
using KSword.Sandbox.SmokeTests.Assertions;
using KSword.Sandbox.SmokeTests.Framework;

namespace KSword.Sandbox.SmokeTests.Scenarios;

/// <summary>
/// Verifies the harmless behavior sample source/preparation contract without
/// building or running the sample. Inputs are repository paths from the smoke
/// context; processing checks source/script presence, tracked artifact policy,
/// and Hyper-V live documentation; the scenario returns pass/fail metadata.
/// </summary>
internal sealed class HarmlessSampleContractScenario : ISmokeTestScenario
{
    private const string SampleProjectName = "KSword.Sandbox.HarmlessSample";
    private const string PrepareScriptName = "Prepare-HarmlessSample.ps1";

    public string ScenarioId => "sample.harmless.contract";

    /// <inheritdoc />
    public Task<SmokeTestResult> RunAsync(SmokeTestContext context, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var failures = new List<string>();
        var sampleProjectPath = ResolveHarmlessSampleProject(context.RepositoryRoot);
        if (sampleProjectPath is null)
        {
            failures.Add(
                $"Missing harmless sample source contract: expected tools/{SampleProjectName}/{SampleProjectName}.csproj or a same-name {SampleProjectName}.csproj project in the repository.");
        }
        else
        {
            AssertNoPublishedArtifactsBesideSampleSource(sampleProjectPath, failures);
        }

        var prepareScriptPath = ResolvePrepareScript(context.RepositoryRoot);
        if (prepareScriptPath is null)
        {
            failures.Add(
                $"Missing harmless sample preparation script: expected {PrepareScriptName} under scripts/ or the {SampleProjectName} sample source tree.");
        }

        AssertNoCommittedBuildArtifacts(context.RepositoryRoot, failures);
        AssertHyperVLiveDocumentation(context.RepositoryRoot, failures);

        SmokeAssert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));

        return Task.FromResult(new SmokeTestResult
        {
            ScenarioId = ScenarioId,
            Passed = true,
            Message = "Harmless sample source, preparation script, artifact policy, and Hyper-V live docs are present.",
            Artifacts =
            [
                sampleProjectPath ?? string.Empty,
                prepareScriptPath ?? string.Empty
            ]
        });
    }

    /// <summary>
    /// Finds the harmless sample project. Inputs are the repository root;
    /// processing first checks the preferred tools path and then same-name
    /// projects elsewhere; the method returns the project path or null.
    /// </summary>
    private static string? ResolveHarmlessSampleProject(string repositoryRoot)
    {
        var preferredProjectPath = Path.Combine(repositoryRoot, "tools", SampleProjectName, $"{SampleProjectName}.csproj");
        if (File.Exists(preferredProjectPath))
        {
            return preferredProjectPath;
        }

        return EnumerateRepositoryFiles(repositoryRoot, $"{SampleProjectName}.csproj")
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
    }

    /// <summary>
    /// Finds the sample preparation script. Inputs are the repository root;
    /// processing checks conventional script locations before recursive search;
    /// the method returns a script path or null.
    /// </summary>
    private static string? ResolvePrepareScript(string repositoryRoot)
    {
        var preferredScriptPaths = new[]
        {
            Path.Combine(repositoryRoot, "scripts", PrepareScriptName),
            Path.Combine(repositoryRoot, "tools", SampleProjectName, PrepareScriptName)
        };

        foreach (var scriptPath in preferredScriptPaths)
        {
            if (File.Exists(scriptPath))
            {
                return scriptPath;
            }
        }

        return EnumerateRepositoryFiles(repositoryRoot, PrepareScriptName)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
    }

    /// <summary>
    /// Checks that the sample source tree does not contain published binaries
    /// beside source files. Inputs are the sample project path and failure
    /// accumulator; processing skips local bin/obj build directories because
    /// the sample is intentionally included in the main solution and normal
    /// developer builds may create ignored local outputs. Return value is none.
    /// </summary>
    private static void AssertNoPublishedArtifactsBesideSampleSource(string sampleProjectPath, List<string> failures)
    {
        var sampleRoot = Path.GetDirectoryName(sampleProjectPath);
        if (string.IsNullOrWhiteSpace(sampleRoot) || !Directory.Exists(sampleRoot))
        {
            failures.Add($"Harmless sample project directory is not readable: {sampleProjectPath}");
            return;
        }

        var forbiddenFiles = Directory.EnumerateFiles(sampleRoot, "*", SearchOption.AllDirectories)
            .Where(path => !IsUnderBinOrObjDirectory(sampleRoot, path))
            .Where(path => HasForbiddenBuildArtifactExtension(path))
            .Select(path => Path.GetRelativePath(sampleRoot, path))
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (forbiddenFiles.Count > 0)
        {
            failures.Add($"Harmless sample source tree must not contain published binaries: {string.Join(", ", forbiddenFiles)}");
        }
    }

    /// <summary>
    /// Checks git-tracked files for forbidden build artifacts. Inputs are the
    /// repository root and failure accumulator; processing uses git when
    /// available and falls back to source-tree checks above; return value is
    /// none.
    /// </summary>
    private static void AssertNoCommittedBuildArtifacts(string repositoryRoot, List<string> failures)
    {
        var trackedFiles = TryReadGitTrackedFiles(repositoryRoot);
        if (trackedFiles.Count == 0)
        {
            return;
        }

        var forbiddenTrackedFiles = trackedFiles
            .Where(IsForbiddenTrackedPath)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (forbiddenTrackedFiles.Count > 0)
        {
            failures.Add($"Repository must not track compiled sample/build artifacts: {string.Join(", ", forbiddenTrackedFiles)}");
        }
    }

    /// <summary>
    /// Checks that the operator runbook explains live Hyper-V use of the
    /// harmless sample. Inputs are repository root and failure accumulator;
    /// processing reads allowed docs only; return value is none.
    /// </summary>
    private static void AssertHyperVLiveDocumentation(string repositoryRoot, List<string> failures)
    {
        var runbookPath = Path.Combine(repositoryRoot, "docs", "hyperv-e2e-runbook.md");
        if (!File.Exists(runbookPath))
        {
            failures.Add("docs/hyperv-e2e-runbook.md is missing.");
            return;
        }

        var runbook = File.ReadAllText(runbookPath);
        RequireContains(runbook, SampleProjectName, "Hyper-V E2E runbook should name the harmless sample project.", failures);
        RequireContains(runbook, PrepareScriptName, "Hyper-V E2E runbook should name the harmless sample preparation script.", failures);
        RequireContains(runbook, @"D:\Temp\KSwordSandbox\samples\KSword.Sandbox.HarmlessSample", "Hyper-V E2E runbook should publish harmless sample output outside the repository.", failures);
        RequireContains(runbook, "Invoke-HyperVE2E.ps1", "Hyper-V E2E runbook should show the top-level E2E script.", failures);
        RequireContains(runbook, "-Live", "Hyper-V E2E runbook should show explicit live execution.", failures);
        RequireContains(runbook, "stay out of git", "Hyper-V E2E runbook should state that harmless sample binaries stay out of git.", failures);
    }

    /// <summary>
    /// Enumerates repository files while skipping heavy or generated trees.
    /// Inputs are root and filename; processing walks directories recursively;
    /// the method returns matching file paths.
    /// </summary>
    private static IEnumerable<string> EnumerateRepositoryFiles(string root, string fileName)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var file in Directory.EnumerateFiles(current, fileName, SearchOption.TopDirectoryOnly))
            {
                yield return file;
            }

            foreach (var directory in Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly))
            {
                if (!ShouldSkipDirectory(directory))
                {
                    pending.Push(directory);
                }
            }
        }
    }

    /// <summary>
    /// Reads git tracked files. Inputs are the repository root; processing runs
    /// git ls-files with a timeout; the method returns tracked relative paths or
    /// an empty list when git is unavailable.
    /// </summary>
    private static IReadOnlyList<string> TryReadGitTrackedFiles(string repositoryRoot)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = "git",
                Arguments = "ls-files -z",
                WorkingDirectory = repositoryRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();
            if (!process.WaitForExit(5000))
            {
                process.Kill(entireProcessTree: true);
                return [];
            }

            if (process.ExitCode != 0)
            {
                return [];
            }

            return output
                .Split('\0', StringSplitOptions.RemoveEmptyEntries)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    /// <summary>
    /// Records a missing text fragment. Inputs are content, expected literal,
    /// failure message, and failure accumulator; processing uses ordinal
    /// matching; return value is none.
    /// </summary>
    private static void RequireContains(string content, string expected, string message, List<string> failures)
    {
        if (!content.Contains(expected, StringComparison.Ordinal))
        {
            failures.Add(message);
        }
    }

    /// <summary>
    /// Tests whether a path is a generated directory. Inputs are a path;
    /// processing checks each path segment; returns true for skipped trees.
    /// </summary>
    private static bool ShouldSkipDirectory(string path)
    {
        var name = Path.GetFileName(path);
        return name.Equals(".git", StringComparison.OrdinalIgnoreCase) ||
            name.Equals(".vs", StringComparison.OrdinalIgnoreCase) ||
            name.Equals(".agents", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("bin", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("obj", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("x64", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Tests whether a file extension is a forbidden build artifact. Inputs are
    /// a path; processing checks extension; returns true for compiled outputs.
    /// </summary>
    private static bool HasForbiddenBuildArtifactExtension(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".bin", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Tests whether a path lives under a bin or obj directory. Inputs are a
    /// source root and descendant path; processing checks each relative path
    /// segment; returns true for generated output trees.
    /// </summary>
    private static bool IsUnderBinOrObjDirectory(string root, string path)
    {
        var relativePath = Path.GetRelativePath(root, path);
        var segments = relativePath.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);

        return segments.Any(segment =>
            segment.Equals("bin", StringComparison.OrdinalIgnoreCase) ||
            segment.Equals("obj", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Tests whether a git-tracked path is forbidden. Inputs are a git-relative
    /// path; processing checks extensions and path segments; returns true for
    /// compiled artifacts and bin/obj trees.
    /// </summary>
    private static bool IsForbiddenTrackedPath(string path)
    {
        var normalized = path.Replace('\\', '/');
        return normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("/bin/", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("/obj/", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("bin/", StringComparison.OrdinalIgnoreCase) ||
            normalized.StartsWith("obj/", StringComparison.OrdinalIgnoreCase);
    }
}
